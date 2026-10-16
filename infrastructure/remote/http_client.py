"""REST client for the Cybrix server (httpx, asyncio — runs on the qasync loop)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from core.config import AppConfig
from core.event_bus import EventBus
from core.exceptions import (
    AuthenticationError, BackendError, BackendUnavailableError, InsecureTransportError,
)
from domain.interfaces.backend import BackendGateway
from infrastructure.remote.token_store import TokenStore

logger = logging.getLogger(__name__)


class HttpBackendGateway(BackendGateway):
    def __init__(self, config: AppConfig, token_store: TokenStore, event_bus: EventBus,
                 transport: Optional[httpx.AsyncBaseTransport] = None):
        self._config = config.backend
        self._tokens = token_store
        self._bus = event_bus
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None

    # ── Plumbing ──────────────────────────────────────────────────────────────

    def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._config.api_url,
                timeout=self._config.request_timeout,
                verify=self._config.verify_tls,
                transport=self._transport,
                headers={"Accept": "application/json"},
            )
        return self._client

    async def _request(self, method: str, path: str, *, auth: bool = True, **kwargs) -> Dict[str, Any]:
        if not self._config.is_secure_transport and not self._config.allow_insecure:
            # Passwords and device tokens must never travel in clear text to a remote host.
            raise InsecureTransportError(
                f"Refusing to talk to {self._config.base_url} over plain HTTP. "
                "Use an https:// server URL (or set backend.allow_insecure for testing).")
        headers = kwargs.pop("headers", {})
        if auth:
            token = self._tokens.token
            if not token:
                raise AuthenticationError("Not logged in", status_code=401)
            headers["Authorization"] = f"Device {token}"
        try:
            resp = await self._http().request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise BackendUnavailableError(f"Server unreachable: {exc}") from exc

        try:
            body = resp.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        message = body.get("message") or resp.reason_phrase
        errors = body.get("errors") or []

        if resp.status_code == 401:
            if auth:
                logger.warning("HttpBackendGateway: token rejected, clearing credentials")
                self._tokens.clear()
                self._bus.emit("backend.auth_lost", {"reason": message})
            raise AuthenticationError(message, status_code=401, errors=errors)
        if resp.status_code >= 500:
            raise BackendUnavailableError(message, status_code=resp.status_code, errors=errors)
        if resp.status_code >= 400 or not body.get("success", False):
            raise BackendError(message, status_code=resp.status_code, errors=errors)
        return body.get("data") or {}

    def has_token(self) -> bool:
        return bool(self._tokens.token)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── API ───────────────────────────────────────────────────────────────────

    async def login(self, username: str, password: str, device_name: str,
                    platform: str = "", app_version: str = "", install_id: str = "") -> Dict[str, Any]:
        data = await self._request("POST", "/auth/login/", auth=False, json={
            "username": username, "password": password, "device_name": device_name,
            "platform": platform, "app_version": app_version, "install_id": install_id,
        })
        self._tokens.save(data["token"], data["device_id"], data.get("token_expires_at"))
        return data

    async def refresh_token(self) -> Dict[str, Any]:
        data = await self._request("POST", "/auth/refresh/")
        self._tokens.save(data["token"], data["device_id"], data.get("token_expires_at"))
        return data

    async def logout(self) -> None:
        try:
            if self.has_token():
                await self._request("POST", "/auth/logout/")
        except (AuthenticationError, BackendUnavailableError) as exc:
            logger.info("HttpBackendGateway.logout: server-side revoke skipped: %s", exc)
        finally:
            self._tokens.clear()

    async def me(self) -> Dict[str, Any]:
        return await self._request("GET", "/me/")

    async def start_scan(self, tool: str, text: str, target: str = "") -> Dict[str, Any]:
        return await self._request("POST", "/scans/", json={"tool": tool, "input": text, "target": target})

    async def get_scan(self, scan_id: int) -> Dict[str, Any]:
        return await self._request("GET", f"/scans/{scan_id}/")

    async def list_devices(self) -> List[Dict[str, Any]]:
        return (await self._request("GET", "/devices/")).get("devices", [])

    async def send_feedback(self, message: str, category: str = "other", app_version: str = "",
                            page: str = "") -> Dict[str, Any]:
        return await self._request("POST", "/feedback/", json={
            "message": message, "category": category, "app_version": app_version, "page": page})

    async def post_command_result(self, command_id: str, success: bool,
                                  result: Optional[Dict[str, Any]] = None, error: str = "",
                                  rejected: bool = False) -> None:
        payload: Dict[str, Any] = {"type": "command.result", "success": success, "error": error,
                                   "rejected": rejected}
        if result is not None:
            payload["result"] = result
        await self._request("POST", f"/commands/{command_id}/result/", json=payload)
