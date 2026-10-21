"""Executes server-issued commands (``backend.command.dispatch``) with local agents.

Pipeline per command: validate (allow-list, path sandbox) → ack → policy / user approval →
run with a timeout → report. Redelivered command IDs are never executed twice: a running one
is ignored and a finished one gets its cached result re-sent. Every step is written to the
local audit log. No shell or arbitrary code is ever executed.
"""
from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional

from injector import inject

from core.config import AppConfig
from core.event_bus import EventBus
from core.exceptions import BackendError
from application.orchestrator import Orchestrator
from application.services.rule_service import RuleService, RulesUnavailable
from application.services.telemetry_service import TelemetryService
from domain.interfaces.backend import (
    ApprovalDecision, BackendGateway, CommandApprover, ConnectionState, RealtimeChannel,
)
from infrastructure.remote import protocol as P
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

logger = logging.getLogger(__name__)

# server command type → orchestrator agent name (None = handled locally)
COMMAND_AGENTS: Dict[str, Optional[str]] = {
    "log_analysis": "log_analysis",
    "ioc_analysis": "ioc_analysis",
    "malware_analysis": "malware_analysis",
    "threat_hunting": "threat_hunting",
    "report": "generate_report",
    "system_snapshot": None,
    "yara_scan": None,            # signed YARA rules over a file or folder (RuleService)
    "rea_analysis": None,         # REA static reverse-engineering inspection (infrastructure/analyzers/rea_analyzer)
}
FILE_COMMANDS = {"log_analysis", "malware_analysis"}
DEFAULT_TIMEOUT = 900.0
MAX_TIMEOUT = 6 * 3600.0
COMPLETED_CACHE_SIZE = 500


class CommandRejected(Exception):
    pass


class CommandExecutor:
    @inject
    def __init__(self, orchestrator: Orchestrator, realtime: RealtimeChannel,
                 gateway: BackendGateway, config: AppConfig, event_bus: EventBus,
                 approver: CommandApprover, settings: AgentSettings, audit: AgentAuditLog,
                 telemetry: TelemetryService, rules: RuleService):
        self._orchestrator = orchestrator
        self._realtime = realtime
        self._gateway = gateway
        self._config = config.backend
        self._bus = event_bus
        self._approver = approver
        self._settings = settings
        self._audit = audit
        self._telemetry = telemetry
        self._rules = rules
        self._running: Dict[str, asyncio.Task] = {}
        self._completed: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._bus.subscribe(P.bus_event(P.COMMAND_DISPATCH), self._on_dispatch)

    # ── Dispatch & idempotency ────────────────────────────────────────────────

    def _on_dispatch(self, data: Dict[str, Any]) -> None:
        command_id = str((data or {}).get("command_id", ""))
        if not command_id or command_id in self._running:
            return  # duplicate redelivery while still working on it
        loop = asyncio.get_running_loop()
        if command_id in self._completed:
            # Server lost our result (e.g. socket dropped): re-send it, never re-run.
            loop.create_task(self._send_result(command_id, self._completed[command_id]))
            return
        task = loop.create_task(self.execute(data))
        self._running[command_id] = task
        task.add_done_callback(lambda _t: self._running.pop(command_id, None))

    async def execute(self, data: Dict[str, Any]) -> None:
        command_id = str(data.get("command_id", ""))
        type_ = str(data.get("type", ""))
        payload = data.get("payload") or {}
        self._audit.record("command_received", command_id=command_id, type=type_,
                           attempt=data.get("attempt"))
        self._ui(command_id, type_, "received", 0)

        try:
            agent, payload = self._validate(type_, payload)
        except CommandRejected as exc:
            logger.warning("CommandExecutor: rejected %s (%s): %s", command_id, type_, exc)
            await self._finish(command_id, type_, success=False, rejected=True, error=f"rejected: {exc}")
            return

        await self._realtime.send(P.COMMAND_ACK, {"command_id": command_id})
        decision = await self._authorize(command_id, type_, payload)
        if decision is ApprovalDecision.DENY:
            await self._finish(command_id, type_, success=False, rejected=True, error="denied on device")
            return

        await self._progress(command_id, type_, 10, P.STAGE_APPROVED)
        timeout = self._timeout(data.get("timeout_seconds"))
        try:
            if type_ == "rea_analysis":
                from infrastructure.analyzers.rea_analyzer import analyze as rea_analyze

                result = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(
                    None, lambda: rea_analyze(payload["file_path"], deep=payload["deep"])), timeout)
                if not result.get("available"):
                    raise RuntimeError("REA is not installed on this computer: " + result["hint"])
            elif type_ == "yara_scan":
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(loop.run_in_executor(
                    None, self._rules.yara_scan, Path(payload["file_path"]), self._is_allowed), timeout)
            elif agent is None:
                result = await asyncio.wait_for(self._telemetry.snapshot(), timeout)
            else:
                report = await asyncio.wait_for(self._orchestrator.dispatch(agent, payload), timeout)
                result = {"report": report}
                if type_ == "log_analysis":
                    result.update(await self._sigma(Path(payload["file_path"])))
        except asyncio.TimeoutError:
            await self._finish(command_id, type_, success=False, error=f"timed out on device after {timeout:.0f}s")
            return
        except Exception as exc:
            logger.error("CommandExecutor: %s failed: %s", command_id, exc, exc_info=True)
            await self._finish(command_id, type_, success=False, error=str(exc))
            return
        await self._finish(command_id, type_, success=True, result=result)

    # ── Policy & validation ───────────────────────────────────────────────────

    async def _authorize(self, command_id: str, type_: str, payload: Dict[str, Any]) -> ApprovalDecision:
        policy = self._settings.command_policy
        if policy == "deny_all":
            self._audit.record("command_denied_by_policy", command_id=command_id, type=type_)
            return ApprovalDecision.DENY
        if type_ in self._settings.always_allowed:
            self._audit.record("command_auto_approved", command_id=command_id, type=type_)
            return ApprovalDecision.ALLOW_ONCE
        if policy == "allow_listed":
            self._audit.record("command_denied_by_policy", command_id=command_id, type=type_)
            return ApprovalDecision.DENY

        await self._progress(command_id, type_, 0, P.STAGE_AWAITING_APPROVAL)
        try:
            decision = await self._approver.request_approval(
                {"command_id": command_id, "type": type_, "payload": payload,
                 "server": self._config.base_url},
                timeout=self._config.approval_timeout,
            )
        except Exception as exc:  # a broken UI must fail closed
            logger.error("CommandExecutor: approval failed for %s: %s", command_id, exc, exc_info=True)
            decision = ApprovalDecision.DENY
        if decision is ApprovalDecision.ALLOW_ALWAYS:
            self._settings.allow_always(type_)
        self._audit.record("command_" + ("approved" if decision is not ApprovalDecision.DENY else "denied"),
                           command_id=command_id, type=type_, decision=decision.value)
        return decision

    def _validate(self, type_: str, payload: Any) -> tuple[Optional[str], Dict[str, Any]]:
        if not self._config.accept_remote_commands:
            raise CommandRejected("remote commands are disabled in settings")
        if type_ not in COMMAND_AGENTS:
            raise CommandRejected(f"unsupported command type '{type_}'")
        if not isinstance(payload, dict):
            raise CommandRejected("payload must be an object")
        payload = dict(payload)
        if type_ in FILE_COMMANDS:
            payload["file_path"] = str(self._check_path(payload.get("file_path")))
        if type_ == "report":
            payload.pop("output_dir", None)  # the server never chooses where we write
        if type_ == "system_snapshot":
            payload = {}
        if type_ == "rea_analysis":
            deep = payload.get("deep")           # None = Ghidra when configured; true/false forces it
            payload = {"file_path": str(self._check_path(payload.get("file_path"), allow_dir=True)),
                       "deep": deep if isinstance(deep, bool) else None}
        if type_ == "yara_scan":
            if not self._rules.summary()["yara"]:
                raise CommandRejected("no verified YARA rules on this computer")
            payload = {"file_path": str(self._check_path(payload.get("file_path"), allow_dir=True))}
        return COMMAND_AGENTS[type_], payload

    async def _sigma(self, path: Path) -> Dict[str, Any]:
        """Sigma matches for a log file; never fails the log analysis itself."""
        try:
            matches = await asyncio.get_running_loop().run_in_executor(None, self._rules.sigma_scan, path)
        except (OSError, RulesUnavailable) as exc:
            logger.warning("CommandExecutor: Sigma scan of %s failed: %s", path, exc)
            return {}
        return {"rules_version": self._rules.version, "sigma_matches": matches} if self._rules.version else {}

    def _roots(self) -> list[Path]:
        return [Path(d).expanduser().resolve() for d in self._config.command_allowed_dirs]

    def _is_allowed(self, path: Path) -> bool:
        return any(Path(path).is_relative_to(root) for root in self._roots())

    def _check_path(self, raw: Optional[str], allow_dir: bool = False) -> Path:
        if not raw:
            raise CommandRejected("file_path is required")
        roots = self._roots()
        if not roots:
            raise CommandRejected("no command_allowed_dirs configured for file commands")
        path = Path(raw).expanduser().resolve()
        if not any(path.is_relative_to(root) for root in roots):
            raise CommandRejected("file_path is outside command_allowed_dirs")
        if not (path.is_file() or (allow_dir and path.is_dir())):
            raise CommandRejected("file not found")
        return path

    @staticmethod
    def _timeout(raw) -> float:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return DEFAULT_TIMEOUT
        return max(1.0, min(value, MAX_TIMEOUT))

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _ui(self, command_id: str, type_: str, status: str, progress: int, error: str = "") -> None:
        self._bus.emit(P.BUS_AGENT_COMMAND, {"command_id": command_id, "type": type_, "status": status,
                                             "progress": progress, "error": error})

    async def _progress(self, command_id: str, type_: str, progress: int, stage: str) -> None:
        await self._realtime.send(P.COMMAND_PROGRESS, {"command_id": command_id, "progress": progress,
                                                       "stage": stage})
        self._ui(command_id, type_, stage, progress)

    async def _finish(self, command_id: str, type_: str, *, success: bool, rejected: bool = False,
                      result: Optional[Dict[str, Any]] = None, error: str = "") -> None:
        outcome: Dict[str, Any] = {"command_id": command_id, "success": success, "error": error}
        if rejected:
            outcome["rejected"] = True
        if result is not None:
            outcome["result"] = result
        self._completed[command_id] = outcome
        while len(self._completed) > COMPLETED_CACHE_SIZE:
            self._completed.popitem(last=False)
        status = "done" if success else ("rejected" if rejected else "failed")
        self._audit.record(f"command_{status}", command_id=command_id, type=type_, error=error)
        self._ui(command_id, type_, status, 100, error)
        self._bus.emit("status_message", f"Server task {type_}: {status}")
        await self._send_result(command_id, outcome)

    async def _send_result(self, command_id: str, outcome: Dict[str, Any]) -> None:
        if self._realtime.state == ConnectionState.CONNECTED:
            await self._realtime.send(P.COMMAND_RESULT, outcome)
            return
        try:  # REST fallback while the socket is down
            await self._gateway.post_command_result(
                command_id, outcome["success"], outcome.get("result"), outcome.get("error", ""),
                rejected=outcome.get("rejected", False))
        except BackendError as exc:
            logger.error("CommandExecutor: could not report %s: %s", command_id, exc)
