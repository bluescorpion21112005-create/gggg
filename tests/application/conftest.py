"""Shared fixtures for application-service tests."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from application.services.command_executor import CommandExecutor
from domain.interfaces.backend import ConnectionState
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

from backend_fakes import FakeApprover, RecordingBus, make_config


@pytest.fixture
def make_executor(tmp_path):
    def factory(allowed_dirs=(), connected=True, accept=True, decision="allow_once", policy=None, rules=None):
        config = make_config(command_allowed_dirs=tuple(str(d) for d in allowed_dirs),
                             accept_remote_commands=accept, data_dir=str(tmp_path / "agent"))
        orchestrator = MagicMock()
        orchestrator.dispatch = AsyncMock(return_value="REPORT")
        realtime = MagicMock()
        realtime.send = AsyncMock()
        realtime.state = ConnectionState.CONNECTED if connected else ConnectionState.DISCONNECTED
        gateway = MagicMock()
        gateway.post_command_result = AsyncMock()
        bus = RecordingBus()
        settings = AgentSettings(config)
        if policy:
            settings.command_policy = policy
        audit = AgentAuditLog(config, bus)
        telemetry = MagicMock()
        telemetry.snapshot = AsyncMock(return_value={"process_count": 3})
        approver = FakeApprover(decision)
        if rules is None:  # no verified rule bundle
            rules = MagicMock(version=0)
            rules.summary.return_value = {"version": 0, "yara": 0, "sigma": 0, "skipped": 0}
            rules.sigma_scan.return_value = []
        ex = CommandExecutor(orchestrator, realtime, gateway, config, bus, approver, settings, audit, telemetry,
                             rules)
        ex.t = MagicMock(orch=orchestrator, rt=realtime, gw=gateway, bus=bus, approver=approver,
                         settings=settings, audit=audit, telemetry=telemetry)
        return ex
    return factory
