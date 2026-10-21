import asyncio
import json

from websockets.asyncio.server import serve

from domain.interfaces.backend import ConnectionState
from infrastructure.remote.token_store import TokenStore
from infrastructure.remote.ws_client import WebSocketRealtimeChannel

from backend_fakes import FakeVault, RecordingBus, make_config


class FakeServer:
    """Minimal stand-in for the Django consumer."""

    def __init__(self, valid_token="good"):
        self.valid_token = valid_token
        self.received = []
        self.connections = 0
        self.on_auth = None  # async callback(ws) after auth.ok
        self.server = None

    async def handler(self, ws):
        self.connections += 1
        auth = json.loads(await ws.recv())
        if auth["data"].get("token") != self.valid_token:
            await ws.close(4401)
            return
        await ws.send(json.dumps({"v": 1, "type": "auth.ok", "id": auth["id"],
                                  "data": {"device_id": "dev-1", "heartbeat_interval": 0.05}}))
        if self.on_auth:
            await self.on_auth(ws)
        async for raw in ws:
            msg = json.loads(raw)
            self.received.append(msg)
            if msg["type"] == "ping":
                await ws.send(json.dumps({"v": 1, "type": "pong", "id": msg["id"], "data": {}}))

    async def __aenter__(self):
        self.server = await serve(self.handler, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


def make_channel(port, token="good"):
    store = TokenStore(FakeVault())
    if token:
        store.save(token, "dev-1")
    bus = RecordingBus()
    ch = WebSocketRealtimeChannel(make_config(f"http://127.0.0.1:{port}", ws_path="/"), store, bus)
    ch.initial_backoff = 0.05
    return ch, store, bus


async def wait_for(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        if loop.time() > end:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.01)


async def test_connects_authenticates_and_heartbeats():
    async with FakeServer() as srv:
        ch, _, bus = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.CONNECTED)
        await wait_for(lambda: any(m["type"] == "ping" for m in srv.received))
        assert bus.of("backend.auth.ok")[0]["device_id"] == "dev-1"
        assert "connected" in bus.of("backend.state")
        await ch.stop()
        assert ch.state == ConnectionState.DISCONNECTED


async def test_server_events_reach_event_bus():
    async with FakeServer() as srv:
        async def push(ws):
            await ws.send(json.dumps({"v": 1, "type": "notification", "id": "n1",
                                      "data": {"title": "Report ready"}}))
        srv.on_auth = push
        ch, _, bus = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: bus.of("backend.notification"))
        assert bus.of("backend.notification") == [{"title": "Report ready"}]
        await ch.stop()


async def test_messages_queued_while_offline_are_delivered():
    async with FakeServer() as srv:
        ch, _, _ = make_channel(srv.port)
        await ch.send("command.ack", {"command_id": "c1"})
        await ch.start()
        await wait_for(lambda: any(m["type"] == "command.ack" for m in srv.received))
        msg = next(m for m in srv.received if m["type"] == "command.ack")
        assert msg["data"] == {"command_id": "c1"} and msg["v"] == 1
        await ch.stop()


async def test_reconnects_after_server_drop():
    async with FakeServer() as srv:
        async def drop_first(ws):
            if srv.connections == 1:
                await ws.close(1011)
        srv.on_auth = drop_first
        ch, _, _ = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: srv.connections >= 2 and ch.state == ConnectionState.CONNECTED)
        await ch.stop()


async def test_bad_token_stops_without_retry_and_clears_token():
    async with FakeServer() as srv:
        ch, store, bus = make_channel(srv.port, token="bad")
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.AUTH_FAILED)
        await asyncio.sleep(0.2)
        assert srv.connections == 1
        assert store.token is None  # UI must fall back to the login form
        assert bus.of("backend.auth_lost")
        await ch.stop()
        assert ch.state == ConnectionState.AUTH_FAILED


async def test_revoked_clears_token():
    async with FakeServer() as srv:
        async def revoke(ws):
            await ws.send(json.dumps({"v": 1, "type": "device.revoked", "id": "r", "data": {}}))
            await ws.close(4403)
        srv.on_auth = revoke
        ch, store, bus = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.AUTH_FAILED)
        assert store.token is None
        assert bus.of("backend.device.revoked") == [{}]
        await ch.stop()


async def test_no_token_does_not_connect():
    async with FakeServer() as srv:
        ch, _, _ = make_channel(srv.port, token=None)
        await ch.start()
        await asyncio.sleep(0.1)
        assert srv.connections == 0
        assert ch.state == ConnectionState.DISCONNECTED


async def test_backoff_resets_after_a_working_session():
    async with FakeServer() as srv:
        async def drop(ws):
            await ws.close(1011)
        srv.on_auth = drop  # every session authenticates, then drops
        ch, _, _ = make_channel(srv.port)
        ch.initial_backoff = 0.05
        await ch.start()
        # Without the reset the delay doubles each time (0.05, 0.1, 0.2, 0.4, 0.8): 6 connects would take >1.2s.
        await wait_for(lambda: srv.connections >= 6, timeout=1.0)
        await ch.stop()


async def test_stop_discards_pending_messages():
    async with FakeServer() as srv:
        ch, _, _ = make_channel(srv.port)
        await ch.send("command.result", {"command_id": "old-session"})
        await ch.stop()
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.CONNECTED)
        await asyncio.sleep(0.1)
        assert not any(m["type"] == "command.result" for m in srv.received)
        await ch.stop()


async def test_auth_message_carries_protocol_and_version():
    async with FakeServer() as srv:
        seen = []

        async def spy(ws):
            first = await ws.recv()
            seen.append(json.loads(first))
            await ws.send(json.dumps({"v": 1, "type": "auth.ok", "id": "x", "data": {"heartbeat_interval": 10}}))
            await asyncio.sleep(0.2)

        srv.handler = spy
        srv.server.close()
        await srv.server.wait_closed()
        srv.server = await serve(srv.handler, "127.0.0.1", srv.port)
        ch, _, _ = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: seen)
        assert seen[0]["data"]["protocol"] == 1
        assert seen[0]["data"]["client_version"]
        await ch.stop()


async def test_unsupported_protocol_stops_and_keeps_token():
    async with FakeServer() as srv:
        async def reject(ws):
            await ws.recv()
            await ws.close(4426)

        srv.server.close()
        await srv.server.wait_closed()
        srv.server = await serve(reject, "127.0.0.1", srv.port)
        ch, store, bus = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.UPGRADE_REQUIRED)
        assert store.token == "good"  # login is still valid; the app needs an update
        await ch.stop()
        assert ch.state == ConnectionState.UPGRADE_REQUIRED


async def test_telemetry_is_latest_only_and_not_queued_offline():
    async with FakeServer() as srv:
        ch, _, _ = make_channel(srv.port)
        ch.send_telemetry({"cpu_percent": 999})  # offline → dropped, never replayed
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.CONNECTED)
        for i in range(50):
            ch.send_telemetry({"cpu_percent": i})
        await wait_for(lambda: any(m["type"] == "telemetry" for m in srv.received))
        await asyncio.sleep(0.1)
        samples = [m["data"]["cpu_percent"] for m in srv.received if m["type"] == "telemetry"]
        assert 999 not in samples
        assert samples[-1] == 49 and len(samples) < 50  # coalesced: latest wins
        await ch.stop()


async def test_insecure_remote_url_never_sends_token():
    from backend_fakes import make_config as cfg

    store = TokenStore(FakeVault())
    store.save("secret", "dev-1")
    bus = RecordingBus()
    ch = WebSocketRealtimeChannel(cfg("http://cybrix.example.com"), store, bus)
    await ch.start()
    await wait_for(lambda: ch.state == ConnectionState.AUTH_FAILED)
    assert store.token == "secret"  # nothing wrong with the token itself
    assert "insecure" in bus.of("backend.auth_lost")[0]["reason"]


async def test_pending_delta_is_merged_not_overwritten():
    async with FakeServer() as srv:
        ch, _, _ = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: ch.state == ConnectionState.CONNECTED)
        # Simulate both arriving before the sender task runs.
        ch._telemetry = {"cpu_percent": 50, "full": False}
        ch.send_telemetry({"ram_percent": 30, "full": False})
        assert ch._telemetry == {"cpu_percent": 50, "ram_percent": 30, "full": False}
        ch._telemetry = {"cpu_percent": 1, "ram_percent": 2, "full": True}
        ch.send_telemetry({"cpu_percent": 5, "full": False})
        assert ch._telemetry == {"cpu_percent": 5, "ram_percent": 2, "full": True}
        ch.send_telemetry({"cpu_percent": 9, "full": True})  # a keyframe replaces everything
        assert ch._telemetry == {"cpu_percent": 9, "full": True}
        await ch.stop()


async def test_client_offers_permessage_deflate():
    async with FakeServer() as srv:
        offers = []
        original = srv.handler

        async def spy(ws):
            offers.append(ws.request.headers.get("Sec-WebSocket-Extensions"))
            await original(ws)

        srv.server.close()
        await srv.server.wait_closed()
        srv.server = await serve(spy, "127.0.0.1", srv.port)
        ch, _, _ = make_channel(srv.port)
        await ch.start()
        await wait_for(lambda: offers)
        assert "permessage-deflate" in offers[0]
        await ch.stop()
