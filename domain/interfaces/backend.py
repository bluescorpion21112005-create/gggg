"""Abstract gateways to the Cybrix server: REST (request/response) and realtime (WebSocket)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional


class ConnectionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTH_FAILED = "auth_failed"
    UPGRADE_REQUIRED = "upgrade_required"  # server rejected our protocol version


class ApprovalDecision(str, Enum):
    ALLOW_ONCE = "allow_once"
    ALLOW_ALWAYS = "allow_always"
    DENY = "deny"


class BackendGateway(ABC):
    """REST API of the server (/api/v1/desktop/)."""

    @abstractmethod
    async def login(self, username: str, password: str, device_name: str,
                    platform: str = "", app_version: str = "", install_id: str = "",
                    otp: str = "") -> Dict[str, Any]:
        """Return {"device_id", "token"}; the token is also persisted by the implementation."""
        ...

    @abstractmethod
    async def refresh_token(self) -> Dict[str, Any]:
        """Rotate the device token; the new one is persisted by the implementation."""
        ...

    @abstractmethod
    async def logout(self) -> None: ...

    @abstractmethod
    async def me(self) -> Dict[str, Any]: ...

    @abstractmethod
    async def start_scan(self, tool: str, text: str, target: str = "") -> Dict[str, Any]: ...

    @abstractmethod
    async def get_scan(self, scan_id: int) -> Dict[str, Any]: ...

    @abstractmethod
    async def list_devices(self) -> List[Dict[str, Any]]: ...

    @abstractmethod
    async def post_command_result(self, command_id: str, success: bool,
                                  result: Optional[Dict[str, Any]] = None, error: str = "",
                                  rejected: bool = False) -> None: ...

    @abstractmethod
    def has_token(self) -> bool: ...

    async def send_feedback(self, message: str, category: str = "other", app_version: str = "",
                            page: str = "") -> Dict[str, Any]:
        """POST /feedback/ — optional for gateways that do not support it."""
        raise NotImplementedError

    async def get_rules(self, have: int = 0) -> Dict[str, Any]:
        """GET /rules/latest/ — {version, bundle, signature}, or {} when `have` is current."""
        raise NotImplementedError

    async def close(self) -> None:
        """Release network resources."""


class RealtimeChannel(ABC):
    """Persistent bidirectional channel; inbound messages are published on the event bus
    as ``backend.<type>`` and state changes as ``backend.state``."""

    @property
    @abstractmethod
    def state(self) -> ConnectionState: ...

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def send(self, type_: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Queue a message; delivered once connected."""
        ...

    @abstractmethod
    def send_telemetry(self, data: Dict[str, Any]) -> None:
        """Latest-wins: only the newest sample is sent; nothing accumulates while offline."""
        ...

    @property
    @abstractmethod
    def session_info(self) -> Dict[str, Any]:
        """Data of the last ``auth.ok`` (device_id, token_expires_at, …); empty when offline."""
        ...


class CommandApprover(ABC):
    """Asks the local user whether a server-issued command may run."""

    @abstractmethod
    async def request_approval(self, command: Dict[str, Any], timeout: float) -> ApprovalDecision:
        """Must return DENY when the user does not answer within ``timeout`` seconds."""
        ...
