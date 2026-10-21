import json

import httpx
import pytest

from core.exceptions import AuthenticationError, BackendError, BackendUnavailableError
from infrastructure.remote.http_client import HttpBackendGateway
from infrastructure.remote.token_store import TokenStore

from backend_fakes import FakeVault, RecordingBus, make_config


def ok(data, status=200):
    return httpx.Response(status, json={"success": True, "message": "ok", "data": data,
                                        "errors": [], "metadata": {}})


def fail(message, status):
    return httpx.Response(status, json={"success": False, "message": message, "data": {},
                                        "errors": [], "metadata": {}})


def make_gateway(handler, token=None):
    store = TokenStore(FakeVault())
    if token:
        store.save(token, "dev-1")
    bus = RecordingBus()
    gw = HttpBackendGateway(make_config(), store, bus, transport=httpx.MockTransport(handler))
    return gw, store, bus


async def test_login_saves_token_and_sends_credentials():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("Authorization")
        return ok({"device_id": "dev-9", "token": "tok-9"}, 201)

    gw, store, _ = make_gateway(handler)
    data = await gw.login("alice", "pw", "laptop", "Linux", "0.1.0")
    assert data["token"] == "tok-9"
    assert (store.token, store.device_id) == ("tok-9", "dev-9")
    assert seen["url"] == "https://testserver/api/v1/desktop/auth/login/"
    assert seen["body"]["device_name"] == "laptop"
    assert seen["auth"] is None
    await gw.close()


async def test_requests_carry_device_token():
    def handler(request):
        assert request.headers["Authorization"] == "Device tok-1"
        return ok({"user": {"username": "alice"}})

    gw, _, _ = make_gateway(handler, token="tok-1")
    assert (await gw.me())["user"]["username"] == "alice"
    await gw.close()


async def test_401_clears_token_and_emits_auth_lost():
    gw, store, bus = make_gateway(lambda r: fail("Invalid or revoked device token.", 401), token="tok-1")
    with pytest.raises(AuthenticationError):
        await gw.me()
    assert store.token is None
    assert bus.of("backend.auth_lost") == [{"reason": "Invalid or revoked device token."}]


async def test_otp_is_sent_only_when_given_and_error_code_is_kept():
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        if "otp" not in bodies[-1]:
            return httpx.Response(401, json={"success": False, "message": "Two-factor code required", "data": {},
                                             "errors": {"code": "otp_required"}, "metadata": {}})
        return ok({"device_id": "dev-2", "token": "tok-2"}, 201)

    gw, store, bus = make_gateway(handler)
    with pytest.raises(AuthenticationError) as info:
        await gw.login("alice", "pw", "laptop")
    assert info.value.errors == {"code": "otp_required"} and bus.of("backend.auth_lost") == []
    await gw.login("alice", "pw", "laptop", otp="123456")
    assert bodies[-1]["otp"] == "123456" and store.token == "tok-2"
    await gw.close()


async def test_wrong_password_does_not_emit_auth_lost():
    gw, _, bus = make_gateway(lambda r: fail("Invalid credentials", 401))
    with pytest.raises(AuthenticationError):
        await gw.login("alice", "bad", "laptop")
    assert bus.of("backend.auth_lost") == []


async def test_error_mapping():
    gw, _, _ = make_gateway(lambda r: fail("bad tool", 400), token="t")
    with pytest.raises(BackendError) as info:
        await gw.start_scan("nope", "x")
    assert info.value.status_code == 400 and not isinstance(info.value, BackendUnavailableError)

    gw, _, _ = make_gateway(lambda r: httpx.Response(502, text="Bad gateway"), token="t")
    with pytest.raises(BackendUnavailableError):
        await gw.me()

    def boom(request):
        raise httpx.ConnectError("refused")

    gw, _, _ = make_gateway(boom, token="t")
    with pytest.raises(BackendUnavailableError):
        await gw.me()


async def test_not_logged_in():
    gw, _, _ = make_gateway(lambda r: ok({}))
    with pytest.raises(AuthenticationError):
        await gw.me()


async def test_logout_clears_token_even_if_server_unreachable():
    def boom(request):
        raise httpx.ConnectError("refused")

    gw, store, _ = make_gateway(boom, token="t")
    await gw.logout()
    assert store.token is None


async def test_non_object_json_body_is_an_error_not_a_crash():
    gw, _, _ = make_gateway(lambda r: httpx.Response(200, json=["unexpected"]), token="t")
    with pytest.raises(BackendError):
        await gw.me()


async def test_refuses_plain_http_to_remote_host():
    from core.exceptions import InsecureTransportError
    from backend_fakes import make_config as cfg

    calls = []
    store = TokenStore(FakeVault())
    gw = HttpBackendGateway(cfg("http://cybrix.example.com"), store, RecordingBus(),
                            transport=httpx.MockTransport(lambda r: calls.append(r) or ok({})))
    with pytest.raises(InsecureTransportError):
        await gw.login("alice", "pw", "laptop")
    assert calls == []  # the password never left the machine


async def test_plain_http_allowed_for_localhost_or_when_opted_in():
    from backend_fakes import make_config as cfg

    for url, extra in (("http://127.0.0.1:8000", {}), ("http://cybrix.example.com", {"allow_insecure": True})):
        store = TokenStore(FakeVault())
        gw = HttpBackendGateway(cfg(url, **extra), store, RecordingBus(),
                                transport=httpx.MockTransport(lambda r: ok({"device_id": "d", "token": "t"}, 201)))
        await gw.login("alice", "pw", "laptop")
        assert store.token == "t"


async def test_login_sends_install_id_and_refresh_rotates_token():
    seen = []

    def handler(request):
        seen.append((request.url.path, json.loads(request.content or b"{}"), request.headers.get("Authorization")))
        if request.url.path.endswith("/refresh/"):
            return ok({"device_id": "d1", "token": "tok-2", "token_expires_at": "2030-01-01T00:00:00+00:00"})
        return ok({"device_id": "d1", "token": "tok-1", "token_expires_at": "2029-01-01T00:00:00+00:00"}, 201)

    gw, store, _ = make_gateway(handler)
    await gw.login("alice", "pw", "laptop", install_id="inst-42")
    assert seen[0][1]["install_id"] == "inst-42"
    assert store.expires_at == "2029-01-01T00:00:00+00:00"
    await gw.refresh_token()
    assert seen[1][2] == "Device tok-1"
    assert (store.token, store.expires_at) == ("tok-2", "2030-01-01T00:00:00+00:00")


async def test_send_feedback_posts_with_device_token():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("Authorization")
        return ok({"id": 7}, 201)

    gw, _, _ = make_gateway(handler, token="tok-1")
    assert (await gw.send_feedback("Crash on start", "bug", "0.2.0", "desktop"))["id"] == 7
    assert seen["url"] == "https://testserver/api/v1/desktop/feedback/"
    assert seen["body"] == {"message": "Crash on start", "category": "bug", "app_version": "0.2.0", "page": "desktop"}
    assert seen["auth"] == "Device tok-1"
    await gw.close()
