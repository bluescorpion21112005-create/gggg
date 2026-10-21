"""Signed YARA/Sigma detection rules on this computer.

While connected, the newest bundle is fetched from the server (`GET rules/latest/?have=`) at
connect and every REFRESH_INTERVAL. It is used only if its Ed25519 signature verifies against the
key pinned in settings.yaml and it is newer than the current one (no rollback). Rules are data —
YARA rules are compiled by libyara, Sigma rules evaluated by infrastructure/detection/sigma.py.

Scanning happens only through server commands the user approves (`yara_scan`, and Sigma inside
`log_analysis`), limited to `command_allowed_dirs` by the CommandExecutor.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from injector import inject

from core.config import AppConfig
from core.event_bus import EventBus
from domain.interfaces.backend import BackendGateway, ConnectionState
from infrastructure.detection import sigma
from infrastructure.detection.rule_bundle import RuleBundleError, RuleStore
from infrastructure.remote import protocol as P
from infrastructure.remote.audit_log import AgentAuditLog

logger = logging.getLogger(__name__)

REFRESH_INTERVAL = 6 * 3600.0
MAX_SCAN_FILES = 5000
MAX_SCAN_FILE_BYTES = 100 * 1024 * 1024
MAX_LOG_BYTES = 200 * 1024 * 1024
YARA_TIMEOUT = 30            # seconds per file
MAX_MATCHES = 200


class RulesUnavailable(Exception):
    pass


class RuleService:
    @inject
    def __init__(self, config: AppConfig, gateway: BackendGateway, event_bus: EventBus, audit: AgentAuditLog):
        self._store = RuleStore(config.backend.data_path / "rules", config.rules_public_key)
        self._gateway = gateway
        self._bus = event_bus
        self._audit = audit
        self._bundle: Optional[Dict[str, Any]] = None
        self._yara = None
        self._yara_count = 0
        self._sigma: List[sigma.SigmaRule] = []
        self.skipped: Dict[str, str] = {}          # rule name → why it could not be loaded
        self._task: Optional[asyncio.Task] = None
        self._install(self._store.load())
        self._bus.subscribe(P.BUS_STATE, self._on_state)

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def version(self) -> int:
        return int((self._bundle or {}).get("version", 0))

    def summary(self) -> Dict[str, Any]:
        return {"version": self.version, "yara": self._yara_count,
                "sigma": len(self._sigma), "skipped": len(self.skipped)}

    def _install(self, bundle: Optional[Dict[str, Any]]) -> None:
        if not bundle:
            return
        skipped: Dict[str, str] = {}
        compiled = None
        sources = dict(bundle.get("yara") or {})
        if sources:
            try:
                import yara
            except ImportError:
                skipped.update({n: "yara-python is not installed" for n in sources})
            else:
                for name in list(sources):           # drop rules libyara refuses, keep the rest
                    try:
                        yara.compile(source=sources[name])
                    except yara.Error as exc:
                        skipped[name] = str(exc)[:200]
                        sources.pop(name)
                compiled = yara.compile(sources=sources) if sources else None
        rules = []
        for name, text in sorted((bundle.get("sigma") or {}).items()):
            try:
                rules.append(sigma.SigmaRule.parse(name, text))
            except (sigma.SigmaError, ValueError, TypeError) as exc:
                skipped[name] = str(exc)[:200]
        self._bundle, self._yara, self._sigma, self.skipped = bundle, compiled, rules, skipped
        self._yara_count = len(sources) if compiled is not None else 0
        if skipped:
            logger.warning("Rules v%s: %d rule(s) skipped: %s", bundle["version"], len(skipped), sorted(skipped))
        self._bus.emit(P.BUS_AGENT_RULES, self.summary())

    # ── Updates ───────────────────────────────────────────────────────────────

    def _on_state(self, state: str) -> None:
        running = self._task is not None and not self._task.done()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if state == ConnectionState.CONNECTED.value and not running:
            self._task = loop.create_task(self._loop(), name="cybrix-rules")
        elif state != ConnectionState.CONNECTED.value and running:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.refresh()
            except Exception as exc:  # network / server errors: try again next round
                logger.warning("Rules: update check failed: %s", exc)
            await asyncio.sleep(REFRESH_INTERVAL)

    async def refresh(self) -> bool:
        """Fetch, verify and install a newer bundle. True if one was installed."""
        try:
            data = await self._gateway.get_rules(self.version)
        except NotImplementedError:
            return False
        if not data or not data.get("bundle"):
            return False
        try:
            bundle = self._store.accept(str(data["bundle"]), str(data.get("signature", "")), self.version)
        except RuleBundleError as exc:
            logger.error("Rules: %s", exc)
            self._audit.record("rules_refused", version=data.get("version"), reason=str(exc)[:200])
            return False
        await asyncio.get_running_loop().run_in_executor(None, self._install, bundle)
        self._audit.record("rules_updated", version=bundle["version"], skipped=len(self.skipped))
        return True

    # ── Scanning (called from approved commands, in a worker thread) ─────────

    def yara_scan(self, root: Path, is_allowed) -> Dict[str, Any]:
        """Scan a file or folder. `is_allowed(path)` re-checks every file (symlinks must stay inside)."""
        if self._yara is None:
            raise RulesUnavailable("no verified YARA rules on this computer")
        import yara

        root = Path(root)
        files = [root] if root.is_file() else (Path(d) / f for d, _dirs, names in os.walk(root) for f in names)
        scanned, skipped, matches, truncated = 0, 0, [], False
        for path in files:
            if scanned + skipped >= MAX_SCAN_FILES:
                truncated = True
                break
            try:
                real = path.resolve()
                if not is_allowed(real) or not real.is_file() or real.stat().st_size > MAX_SCAN_FILE_BYTES:
                    skipped += 1
                    continue
                found = self._yara.match(str(real), timeout=YARA_TIMEOUT)
            except (OSError, yara.Error):
                skipped += 1
                continue
            scanned += 1
            if found:
                digest = _sha256(real)
                for m in found:
                    if len(matches) < MAX_MATCHES:
                        matches.append({"rule": m.rule, "severity": str(m.meta.get("severity", "medium")),
                                        "description": str(m.meta.get("description", ""))[:200],
                                        "tags": list(m.tags), "file": str(real), "sha256": digest})
        return {"rules_version": self.version, "scanned": scanned, "skipped": skipped,
                "truncated": truncated, "matches": matches}

    def sigma_scan(self, path: Path) -> List[Dict[str, Any]]:
        if not self._sigma:
            return []
        path = Path(path)
        if path.stat().st_size > MAX_LOG_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            hits = sigma.scan_lines(self._sigma, fh)
        return [{**h, "file": str(path)} for h in hits.values()]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
