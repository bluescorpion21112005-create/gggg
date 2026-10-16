from unittest.mock import AsyncMock, MagicMock

from core.exceptions import AuthenticationError, InsecureTransportError
from domain.interfaces.backend import ConnectionState
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog
from presentation.viewmodels.connection_viewmodel import ConnectionViewModel

from backend_fakes import RecordingBus, make_config


def make_vm(tmp_path):
    config = make_config(data_dir=str(tmp_path))
    service = MagicMock()
    service.state = ConnectionState.DISCONNECTED
    service.is_logged_in = False
    service.session_info = {}
    service.login = AsyncMock(return_value={"device_id": "d"})
    bus = RecordingBus()
    telemetry = MagicMock(sharing=True, last_sample={})
    settings = AgentSettings(config)
    audit = AgentAuditLog(config, bus)
    netflow = MagicMock(sharing=False)
    rules = MagicMock()
    rules.summary.return_value = {"version": 0, "yara": 0, "sigma": 0, "skipped": 0}
    vm = ConnectionViewModel(service, config, bus, telemetry, settings, audit, netflow, MagicMock(sharing=False),
                             rules)
    return vm, service, bus, telemetry, settings


def test_event_bus_bridges_to_signals(qapp, qtbot, tmp_path):
    vm, _, bus, _, _ = make_vm(tmp_path)
    with qtbot.waitSignal(vm.state_changed) as s:
        bus.emit("backend.state", "connected")
    assert s.args == ["connected"]
    with qtbot.waitSignal(vm.notification) as n:
        bus.emit("backend.notification", {"title": "hi"})
    assert n.args == [{"level": "info", "title": "hi"}]
    with qtbot.waitSignal(vm.logged_in_changed) as l:
        bus.emit("backend.device.revoked", {})
    assert l.args == [False]
    toasts = []
    vm.notification.connect(toasts.append)
    bus.emit("backend.device.revoked", {})
    bus.emit("backend.auth_lost", {"reason": "server closed with 4403"})
    assert len(toasts) == 1  # one toast per sign-out, not two
    with qtbot.waitSignal(vm.command_updated) as c:
        bus.emit("agent.command", {"command_id": "x", "status": "done"})
    assert c.args[0]["status"] == "done"
    with qtbot.waitSignal(vm.telemetry):
        bus.emit("agent.telemetry", {"cpu_percent": 3})


def test_upgrade_required_raises_notification(qapp, qtbot, tmp_path):
    vm, _, bus, _, _ = make_vm(tmp_path)
    with qtbot.waitSignal(vm.notification) as n:
        bus.emit("backend.state", "upgrade_required")
    assert n.args[0]["level"] == "error"


async def test_login_success_and_failure(qapp, qtbot, tmp_path):
    vm, service, _, _, _ = make_vm(tmp_path)
    with qtbot.waitSignal(vm.logged_in_changed) as sig:
        await vm.login.__wrapped__(vm, "alice", "pw")  # qasync asyncSlot keeps the coroutine here
    service.login.assert_awaited_once_with("alice", "pw")
    assert sig.args == [True]

    service.login = AsyncMock(side_effect=AuthenticationError("nope", 401))
    with qtbot.waitSignal(vm.login_failed) as sig:
        await vm.login.__wrapped__(vm, "alice", "bad")
    assert "Invalid" in sig.args[0]

    service.login = AsyncMock(side_effect=InsecureTransportError("Refusing plain HTTP"))
    with qtbot.waitSignal(vm.login_failed) as sig:
        await vm.login.__wrapped__(vm, "alice", "pw")
    assert "plain HTTP" in sig.args[0]


def test_settings_slots_persist_and_audit(qapp, tmp_path):
    vm, _, _, telemetry, settings = make_vm(tmp_path)
    vm.set_command_policy("deny_all")
    assert settings.command_policy == "deny_all"
    vm.set_sharing(False)
    telemetry.set_sharing.assert_called_once_with(False)
    settings.allow_always("ioc_analysis")
    vm.clear_always_allowed()
    assert vm.always_allowed == []
    events = [e["event"] for e in vm.recent_audit()]
    assert {"command_policy_changed", "telemetry_sharing_disabled", "always_allowed_cleared"} <= set(events)
