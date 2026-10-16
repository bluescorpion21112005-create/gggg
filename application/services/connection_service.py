"""Login/logout flow, token rotation and realtime lifecycle for the Cybrix server connection."""
from __future__ import annotations

import asyncio
import logging
import platform
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from injector import inject

from core.config import AppConfig
from core.event_bus import EventBus
from core.exceptions import BackendError
from domain.interfaces.backend import BackendGateway, ConnectionState, RealtimeChannel
from infrastructure.remote import protocol as P
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

logger = logging.getLogger(__name__)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ConnectionService:
    @inject
    def __init__(self, gateway: BackendGateway, realtime: RealtimeChannel, config: AppConfig,
                 event_bus: EventBus, settings: AgentSettings, audit: AgentAuditLog):
        self._gateway = gateway
        self._realtime = realtime
        self._config = config
        self._bus = event_bus
        self._settings = settings
        self._audit = audit
        self._refreshing = False
        self._bus.subscribe(P.BUS_AUTH_LOST, self._on_auth_lost)
        self._bus.subscribe(P.BUS_SESSION, self._on_session)

    @property
    def gateway(self) -> BackendGateway:
        return self._gateway

    @property
    def state(self) -> ConnectionState:
        return self._realtime.state

    @property
    def session_info(self) -> Dict[str, Any]:
        return self._realtime.session_info

    @property
    def is_logged_in(self) -> bool:
        return self._gateway.has_token()

    async def login(self, username: str, password: str) -> Dict[str, Any]:
        await self._realtime.stop()  # never keep a socket authenticated as a previous device
        data = await self._gateway.login(
            username, password,
            device_name=socket.gethostname() or "desktop",
            platform=f"{platform.system()} {platform.release()}".strip(),
            app_version=self._config.version,
            install_id=self._settings.install_id,
        )
        self._audit.record("login", server=self._config.backend.base_url, device_id=data.get("device_id"),
                           token_expires_at=data.get("token_expires_at"))
        await self._realtime.start()
        return data

    async def logout(self) -> None:
        await self._realtime.stop()
        await self._gateway.logout()
        self._audit.record("logout", server=self._config.backend.base_url)

    async def auto_connect(self) -> bool:
        """Reconnect at startup if a device token is stored."""
        if not self._gateway.has_token():
            return False
        await self._realtime.start()
        return True

    async def shutdown(self) -> None:
        await self._realtime.stop()
        await self._gateway.close()

    # ── Token rotation ────────────────────────────────────────────────────────

    def needs_refresh(self, expires_at: Optional[str]) -> bool:
        expiry = _parse_iso(expires_at)
        if expiry is None:
            return False
        return expiry - datetime.now(timezone.utc) < timedelta(days=self._config.backend.token_refresh_days)

    async def refresh_token_if_needed(self, expires_at: Optional[str]) -> bool:
        if self._refreshing or not self.needs_refresh(expires_at):
            return False
        self._refreshing = True
        try:
            data = await self._gateway.refresh_token()
            self._audit.record("token_rotated", token_expires_at=data.get("token_expires_at"))
            return True
        except BackendError as exc:
            logger.warning("ConnectionService: token refresh failed: %s", exc)
            return False
        finally:
            self._refreshing = False

    def _on_session(self, data: Dict[str, Any]) -> None:
        # The live socket stays authenticated; the rotated token is used from the next connect.
        asyncio.get_running_loop().create_task(self.refresh_token_if_needed((data or {}).get("token_expires_at")))

    def _on_auth_lost(self, data) -> None:
        self._audit.record("session_ended", reason=(data or {}).get("reason"))
        try:
            asyncio.get_running_loop().create_task(self._realtime.stop())
        except RuntimeError:
            pass
