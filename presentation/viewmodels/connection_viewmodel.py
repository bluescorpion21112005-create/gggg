"""ViewModel for the Cybrix server connection: login, realtime state, telemetry sharing,
server commands, notifications and the local audit trail."""
import logging
from typing import Any, Dict, List

from PySide6.QtCore import Signal, Slot
from qasync import asyncSlot
from injector import inject

from application.services.connection_service import ConnectionService
from application.services.netflow_service import NetflowService
from application.services.process_hash_service import ProcessHashService
from application.services.telemetry_service import TelemetryService
from core.config import AppConfig
from core.event_bus import EventBus
from core.exceptions import AuthenticationError, BackendError, InsecureTransportError
from infrastructure.remote import protocol as P
from infrastructure.remote.agent_settings import AgentSettings, POLICIES
from infrastructure.remote.audit_log import AgentAuditLog
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class ConnectionViewModel(BaseViewModel):
    state_changed = Signal(str)          # disconnected / connecting / connected / auth_failed / upgrade_required
    logged_in_changed = Signal(bool)
    login_failed = Signal(str)
    session_changed = Signal(dict)       # auth.ok data (device_id, token_expires_at, …)
    notification = Signal(dict)          # {title, message, level}
    scan_progress = Signal(dict)
    scan_completed = Signal(dict)
    devices_changed = Signal(list)
    telemetry = Signal(dict)             # what is being shared right now
    sharing_changed = Signal(bool)
    command_updated = Signal(dict)       # local command lifecycle row
    audit_appended = Signal(dict)
    intel_hit = Signal(dict)             # server flagged one of our connections
    netflow_batch = Signal(dict)         # {"sent", "open", "flows"} last shared batch
    netflow_sharing_changed = Signal(bool)
    hash_sharing_changed = Signal(bool)

    @inject
    def __init__(self, service: ConnectionService, config: AppConfig, event_bus: EventBus,
                 telemetry: TelemetryService, settings: AgentSettings, audit: AgentAuditLog,
                 netflow: NetflowService, hashes: ProcessHashService):
        super().__init__()
        self._netflow = netflow
        self._hashes = hashes
        self._service = service
        self._config = config
        self._bus = event_bus
        self._telemetry = telemetry
        self._settings = settings
        self._audit = audit
        self._bus.subscribe(P.BUS_STATE, self._on_state)
        self._bus.subscribe(P.BUS_SESSION, self.session_changed.emit)
        self._bus.subscribe(P.bus_event(P.NOTIFICATION), self._on_notification)
        self._bus.subscribe(P.bus_event(P.SCAN_PROGRESS), self.scan_progress.emit)
        self._bus.subscribe(P.bus_event(P.SCAN_COMPLETED), self._on_scan_completed)
        self._bus.subscribe(P.BUS_AUTH_LOST, self._on_auth_lost)
        # device.revoked is always followed by close 4403 → auth_lost, which shows the toast.
        self._bus.subscribe(P.bus_event(P.DEVICE_REVOKED), lambda _d: self.logged_in_changed.emit(False))
        self._bus.subscribe(P.BUS_AGENT_TELEMETRY, self.telemetry.emit)
        self._bus.subscribe(P.BUS_AGENT_COMMAND, self._on_command)
        self._bus.subscribe(P.BUS_AGENT_AUDIT, self.audit_appended.emit)
        self._bus.subscribe(P.BUS_INTEL_HIT, self.intel_hit.emit)
        self._bus.subscribe(P.BUS_AGENT_NETFLOW, self.netflow_batch.emit)

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def server_url(self) -> str:
        return self._config.backend.base_url

    @property
    def is_secure(self) -> bool:
        return self._config.backend.is_secure_transport

    @property
    def state(self) -> str:
        return self._service.state.value

    @property
    def is_logged_in(self) -> bool:
        return self._service.is_logged_in

    @property
    def session_info(self) -> Dict[str, Any]:
        return self._service.session_info

    @property
    def sharing(self) -> bool:
        return self._telemetry.sharing

    @property
    def last_telemetry(self) -> Dict[str, Any]:
        return dict(self._telemetry.last_sample)

    @property
    def netflow_sharing(self) -> bool:
        return self._netflow.sharing

    @Slot(bool)
    def set_netflow_sharing(self, enabled: bool):
        if enabled == self._netflow.sharing:
            return
        self._netflow.set_sharing(enabled)
        self.netflow_sharing_changed.emit(enabled)
        self.status_message.emit("Network connection sharing " + ("enabled" if enabled else "disabled"))

    @property
    def hash_sharing(self) -> bool:
        return self._hashes.sharing

    @Slot(bool)
    def set_hash_sharing(self, enabled: bool):
        if enabled == self._hashes.sharing:
            return
        self._hashes.set_sharing(enabled)
        self.hash_sharing_changed.emit(enabled)
        self.status_message.emit("Malware hash check " + ("enabled" if enabled else "disabled"))

    @property
    def command_policy(self) -> str:
        return self._settings.command_policy

    @property
    def policies(self) -> tuple:
        return POLICIES

    @property
    def always_allowed(self) -> List[str]:
        return sorted(self._settings.always_allowed)

    @property
    def allowed_dirs(self) -> List[str]:
        return list(self._config.backend.command_allowed_dirs)

    @property
    def audit_path(self) -> str:
        return str(self._audit.path)

    def recent_audit(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self._audit.recent(limit)

    # ── Commands ─────────────────────────────────────────────────────────────

    @asyncSlot(str, str)
    async def login(self, username: str, password: str):
        if not username.strip() or not password:
            self.login_failed.emit("Username and password are required.")
            return
        self.is_busy = True
        try:
            await self._service.login(username.strip(), password)
            self.logged_in_changed.emit(True)
            self.status_message.emit(f"Logged in to {self.server_url}")
        except AuthenticationError:
            self.login_failed.emit("Invalid username or password.")
        except InsecureTransportError as exc:
            self.login_failed.emit(str(exc))
        except BackendError as exc:
            logger.warning("ConnectionViewModel: login failed: %s", exc)
            self.login_failed.emit(f"Login failed: {exc}")
        finally:
            self.is_busy = False

    @asyncSlot()
    async def logout(self):
        self.is_busy = True
        try:
            await self._service.logout()
        finally:
            self.is_busy = False
            self.logged_in_changed.emit(False)
            self.status_message.emit("Logged out from server")

    @asyncSlot()
    async def refresh_devices(self):
        try:
            self.devices_changed.emit(await self._service.gateway.list_devices())
        except BackendError as exc:
            self.error_occurred.emit(f"Could not load devices: {exc}")

    @asyncSlot(str, str)
    async def start_scan(self, tool: str, text: str):
        if not text.strip():
            self.error_occurred.emit("Scan input is empty.")
            return
        try:
            scan = await self._service.gateway.start_scan(tool, text)
            self.status_message.emit(f"Server scan #{scan.get('id')} queued")
        except BackendError as exc:
            self.error_occurred.emit(f"Could not start scan: {exc}")

    @Slot(bool)
    def set_sharing(self, enabled: bool):
        self._telemetry.set_sharing(enabled)
        self._audit.record("telemetry_sharing_" + ("enabled" if enabled else "disabled"))
        self.sharing_changed.emit(enabled)

    @Slot(str)
    def set_command_policy(self, policy: str):
        if policy not in POLICIES:
            self.error_occurred.emit(f"Unknown command policy: {policy}")
            return
        self._settings.command_policy = policy
        self._audit.record("command_policy_changed", policy=policy)
        self.status_message.emit(f"Server command policy: {policy}")

    @Slot()
    def clear_always_allowed(self):
        self._settings.clear_always_allowed()
        self._audit.record("always_allowed_cleared")
        self.status_message.emit("Permanent command approvals cleared")

    # ── Event bus bridges ────────────────────────────────────────────────────

    def _on_state(self, state: str) -> None:
        self.state_changed.emit(state)
        if state == "upgrade_required":
            self.notification.emit({"title": "Update required", "level": "error",
                                    "message": "The server no longer supports this app version."})

    def _on_notification(self, data: dict) -> None:
        self.notification.emit({"level": "info", **(data or {})})

    def _on_command(self, row: dict) -> None:
        self.command_updated.emit(row)

    def _on_scan_completed(self, data: dict) -> None:
        self.scan_completed.emit(data)
        ok = data.get("success", False)
        self.notification.emit({"title": f"Server scan #{data.get('scan_id')}",
                                "message": "completed" if ok else (data.get("error") or "failed"),
                                "level": "success" if ok else "error"})

    def _on_auth_lost(self, data) -> None:
        self.logged_in_changed.emit(False)
        reason = (data or {}).get("reason") or "session ended"
        self.notification.emit({"title": "Signed out from server", "message": reason, "level": "warning"})

    # ── Feedback ─────────────────────────────────────────────────────────────

    @asyncSlot(str, str)
    async def send_feedback(self, category: str, message: str):
        message = (message or "").strip()
        if len(message) < 5:
            self.error_occurred.emit("Please write a few words.")
            return
        if not self.is_logged_in:
            self.error_occurred.emit("Sign in on the Server page to send feedback.")
            return
        try:
            await self._service.gateway.send_feedback(message, category, self._config.version, "desktop")
        except BackendError as exc:
            self.error_occurred.emit(f"Feedback not sent: {exc}")
            return
        self.status_message.emit("Thank you — your feedback was sent to the team.")
