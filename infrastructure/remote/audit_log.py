"""Local, append-only audit trail of everything the server asked this agent to do.

JSON lines in <data_dir>/agent_audit.jsonl, rotated at MAX_BYTES (keeps BACKUPS old files).
Kept independent of the server so the user can verify what happened on their machine.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from core.config import AppConfig
from core.event_bus import EventBus
from infrastructure.remote.protocol import BUS_AGENT_AUDIT

logger = logging.getLogger(__name__)

MAX_BYTES = 1024 * 1024
BACKUPS = 3


class AgentAuditLog:
    FILE_NAME = "agent_audit.jsonl"

    def __init__(self, config: AppConfig, event_bus: EventBus):
        self._path: Path = config.backend.data_path / self.FILE_NAME
        self._bus = event_bus
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event: str, **details: Any) -> Dict[str, Any]:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **details}
        line = json.dumps(entry, default=str, ensure_ascii=False)
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed()
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                logger.warning("AgentAuditLog: write failed: %s", exc)
        self._bus.emit(BUS_AGENT_AUDIT, entry)
        return entry

    def recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Newest first."""
        try:
            with self._path.open(encoding="utf-8") as fh:
                lines = deque(fh, maxlen=limit)
        except FileNotFoundError:
            return []
        entries = []
        for line in reversed(lines):
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries

    def _rotate_if_needed(self) -> None:
        if not self._path.exists() or self._path.stat().st_size < MAX_BYTES:
            return
        for i in range(BACKUPS - 1, 0, -1):
            src = self._path.with_name(f"{self.FILE_NAME}.{i}")
            if src.exists():
                src.replace(self._path.with_name(f"{self.FILE_NAME}.{i + 1}"))
        self._path.replace(self._path.with_name(f"{self.FILE_NAME}.1"))
