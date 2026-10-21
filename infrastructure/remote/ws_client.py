"""WebSocket client for the Cybrix server (protocol: cybrix_ai/desktop_agent/PROTOCOL.md).

Runs as one asyncio task on the qasync loop: connect → auth → (heartbeat + sender + telemetry
+ receiver), reconnecting with exponential backoff that resets after a working session.
Inbound messages go to the event bus as ``backend.<type>`` (payload = message ``data``);
state changes as ``backend.state``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import websockets
from injector import inject
from websockets.exceptions import ConnectionClosed

from core.config import AppConfig
from core.event_bus import EventBus
from domain.interfaces.backend import ConnectionState, RealtimeChannel
from infrastructure.remote import protocol as P
from infrastructure.remote.token_store import TokenStore

logger = logging.getLogger(__name__)

# Kept for older imports.
PROTOCOL_VERSION = P.PROTOCOL_VERSION
CLOSE_UNAUTHORIZED = P.CLOSE_UNAUTHORIZED
CLOSE_REVOKED = P.CLOSE_REVOKED

AUTH_REPLY_TIMEOUT = 10.0
OUTBOX_LIMIT = 500


class _StopReconnecting(Exception):
    """Retrying would not help (bad token, revoked, unsupported protocol, insecure transport)."""

    def __init__(self, reason: str, state: ConnectionState = ConnectionState.AUTH_FAILED,
                 clear_token: bool = True):
        super().__init__(reason)
        self.state = state
        self.clear_token = clear_token


def make_envelope(type_: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "v": P.PROTOCOL_VERSION,
        "type": type_,
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
    }


class WebSocketRealtimeChannel(RealtimeChannel):
    @inject
    def __init__(self, config: AppConfig, token_store: TokenStore, event_bus: EventBus):
        self._config = config.backend
        self._client_version = config.version
        self._tokens = token_store
        self._bus = event_bus
        self._state = ConnectionState.DISCONNECTED
        self._task: Optional[asyncio.Task] = None
        self._outbox: Optional[asyncio.Queue] = None
        self._telemetry: Optional[Dict[str, Any]] = None
        self._telemetry_ready: Optional[asyncio.Event] = None
        self._session: Dict[str, Any] = {}
        self._was_connected = False
        self.initial_backoff = 1.0

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def session_info(self) -> Dict[str, Any]:
        return dict(self._session)

    def _set_state(self, state: ConnectionState) -> None:
        if state != self._state:
            self._state = state
            logger.info("Realtime: state=%s", state.value)
            self._bus.emit(P.BUS_STATE, state.value)

    def _ensure_queues(self) -> None:
        if self._outbox is None:
            self._outbox = asyncio.Queue(maxsize=OUTBOX_LIMIT)
        if self._telemetry_ready is None:
            self._telemetry_ready = asyncio.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._ensure_queues()
        self._task = asyncio.create_task(self._run(), name="cybrix-realtime")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        # Pending messages belong to this session's device; never replay them after a re-login.
        if self._outbox is not None:
            while not self._outbox.empty():
                self._outbox.get_nowait()
        self._telemetry = None
        self._session = {}
        if self._state not in (ConnectionState.AUTH_FAILED, ConnectionState.UPGRADE_REQUIRED):
            self._set_state(ConnectionState.DISCONNECTED)

    async def send(self, type_: str, data: Optional[Dict[str, Any]] = None) -> None:
        self._ensure_queues()
        message = make_envelope(type_, data)
        try:
            self._outbox.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("Realtime: outbox full, dropping oldest message")
            self._outbox.get_nowait()
            self._outbox.put_nowait(message)

    def send_telemetry(self, data: Dict[str, Any]) -> None:
        if self._state != ConnectionState.CONNECTED:
            return  # stale samples are worthless; never queue them
        self._ensure_queues()
        pending = self._telemetry
        if pending is not None and data.get("full") is False:
            # A delta must not overwrite an unsent sample (its changes would be lost):
            # fold it in, keeping "full" if the pending one was a keyframe.
            data = {**pending, **data, "full": pending.get("full", True)}
        self._telemetry = data
        self._telemetry_ready.set()

    # ── Connection loop ───────────────────────────────────────────────────────

    async def _run(self) -> None:
        delay = self.initial_backoff
        while True:
            token = self._tokens.token
            if not token:
                self._set_state(ConnectionState.DISCONNECTED)
                return
            self._set_state(ConnectionState.CONNECTING)
            try:
                if not self._config.is_secure_transport and not self._config.allow_insecure:
                    raise _StopReconnecting("refusing to send the device token over an insecure "
                                            "connection (use https or set backend.allow_insecure)",
                                            clear_token=False)
                await self._session_loop(token)
            except _StopReconnecting as exc:
                logger.warning("Realtime: not reconnecting: %s", exc)
                if exc.clear_token:
                    # The stored token is useless now; drop it so the UI asks for a new login.
                    self._tokens.clear()
                self._session = {}
                self._set_state(exc.state)
                self._bus.emit(P.BUS_AUTH_LOST, {"reason": str(exc), "state": exc.state.value})
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.info("Realtime: connection lost (%s)", exc)
            self._session = {}
            if self._was_connected:
                delay = self.initial_backoff  # a working session ended → start backoff over
            self._set_state(ConnectionState.DISCONNECTED)
            logger.info("Realtime: reconnecting in ~%.1fs", delay)
            await asyncio.sleep(delay * random.uniform(0.8, 1.2))
            delay = min(delay * 2, self._config.reconnect_max_delay)

    async def _session_loop(self, token: str) -> None:
        ssl_ctx = None
        if self._config.ws_url.startswith("wss://") and not self._config.verify_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        self._was_connected = False
        async with websockets.connect(self._config.ws_url, ssl=ssl_ctx, open_timeout=10,
                                      ping_interval=None, max_size=8 * 1024 * 1024,
                                      compression="deflate") as ws:
            await ws.send(json.dumps(make_envelope(P.AUTH, {
                "token": token, "protocol": P.PROTOCOL_VERSION, "client_version": self._client_version,
            })))
            try:
                reply = json.loads(await asyncio.wait_for(ws.recv(), AUTH_REPLY_TIMEOUT))
            except ConnectionClosed as exc:
                self._raise_if_fatal(exc)
                raise
            if reply.get("type") != P.AUTH_OK:
                raise _StopReconnecting(f"unexpected auth reply: {reply.get('type')}")
            self._was_connected = True
            self._session = reply.get("data") or {}
            self._set_state(ConnectionState.CONNECTED)
            self._bus.emit(P.BUS_SESSION, dict(self._session))

            interval = float(self._session.get("heartbeat_interval") or self._config.heartbeat_interval)
            tasks = [
                asyncio.create_task(self._heartbeat(ws, interval)),
                asyncio.create_task(self._sender(ws)),
                asyncio.create_task(self._telemetry_sender(ws)),
                asyncio.create_task(self._receiver(ws)),
            ]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    exc = t.exception()
                    if isinstance(exc, ConnectionClosed):
                        self._raise_if_fatal(exc)
                    if exc:
                        raise exc
            finally:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _raise_if_fatal(exc: ConnectionClosed) -> None:
        code = exc.rcvd.code if exc.rcvd else None
        if code in (P.CLOSE_UNAUTHORIZED, P.CLOSE_REVOKED):
            raise _StopReconnecting(f"server closed with {code}") from exc
        if code == P.CLOSE_UNSUPPORTED_PROTOCOL:
            raise _StopReconnecting("server does not support this app version — please update",
                                    state=ConnectionState.UPGRADE_REQUIRED, clear_token=False) from exc

    async def _heartbeat(self, ws, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            await ws.send(json.dumps(make_envelope(P.PING)))

    async def _sender(self, ws) -> None:
        while True:
            message = await self._outbox.get()
            try:
                await ws.send(json.dumps(message))
            except Exception:
                # Re-queue so the message survives the reconnect (it may be reordered).
                await self._outbox.put(message)
                raise

    async def _telemetry_sender(self, ws) -> None:
        while True:
            await self._telemetry_ready.wait()
            self._telemetry_ready.clear()
            sample, self._telemetry = self._telemetry, None
            if sample is not None:
                await ws.send(json.dumps(make_envelope(P.TELEMETRY, sample)))

    async def _receiver(self, ws) -> None:
        async for raw in ws:
            try:
                message = json.loads(raw)
                type_ = str(message["type"])
            except (ValueError, KeyError, TypeError):
                logger.warning("Realtime: dropping malformed message")
                continue
            if type_ == P.PONG:
                continue
            if type_ == P.ERROR:
                logger.warning("Realtime: server error: %s", (message.get("data") or {}).get("detail"))
            if type_ == P.DEVICE_REVOKED:
                self._tokens.clear()
            self._bus.emit(P.bus_event(type_), message.get("data") or {})
