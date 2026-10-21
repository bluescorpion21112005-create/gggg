"""Opt-in check of running programs against known-malware hashes (MalwareBazaar on the server).

While connected *and* the user consented, the SHA-256 of each running executable is sent as
`process.hashes` — only the hash and the file's basename, never the path or contents. A file is
hashed once per (path, size, mtime) and sent only when new or changed; files over MAX_FILE_BYTES
are skipped. The server answers with a notification (`kind: hash_hit`) for a known-malware match.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import psutil
from injector import inject

from domain.interfaces.backend import ConnectionState, RealtimeChannel
from core.event_bus import EventBus
from infrastructure.remote import protocol as P
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 200 * 1024 * 1024
INTERVAL = 300.0          # seconds between scans of the process list


class ProcessHashCollector:
    def __init__(self, max_bytes: int = MAX_FILE_BYTES):
        self._max = max_bytes
        self._seen: Dict[str, Tuple[int, float]] = {}   # path → (size, mtime) already sent

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def executables(self) -> List[str]:
        paths = set()
        for proc in psutil.process_iter(["exe"]):
            exe = (proc.info or {}).get("exe")
            if exe:
                paths.add(exe)
        return sorted(paths)

    def new_files(self, paths: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """Hash executables not sent before (or changed since), up to P.MAX_PROCESS_HASHES."""
        out = []
        for path in self.executables() if paths is None else paths:
            if len(out) >= P.MAX_PROCESS_HASHES:
                break
            try:
                st = os.stat(path)
                key = (st.st_size, st.st_mtime)
                if self._seen.get(path) == key or st.st_size > self._max:
                    continue
                digest = self._sha256(path)
            except OSError:
                continue
            self._seen[path] = key
            out.append({"sha256": digest, "name": os.path.basename(path)[:128]})
        return out


class ProcessHashService:
    @inject
    def __init__(self, realtime: RealtimeChannel, settings: AgentSettings, event_bus: EventBus,
                 audit: AgentAuditLog):
        self._realtime = realtime
        self._settings = settings
        self._bus = event_bus
        self._audit = audit
        self._collector = ProcessHashCollector()
        self._task: Optional[asyncio.Task] = None
        self._bus.subscribe(P.BUS_STATE, self._on_state)
        self._bus.subscribe(P.bus_event(P.NOTIFICATION), self._on_notification)

    @property
    def sharing(self) -> bool:
        return self._settings.share_process_hashes

    def set_sharing(self, enabled: bool) -> None:
        self._settings.share_process_hashes = enabled
        self._audit.record("process_hashes_" + ("enabled" if enabled else "disabled"))
        self._on_state(self._realtime.state.value)

    def _on_state(self, state: str) -> None:
        should_run = state == ConnectionState.CONNECTED.value and self.sharing
        running = self._task is not None and not self._task.done()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if should_run and not running:
            self._task = loop.create_task(self._loop(), name="cybrix-process-hashes")
        elif not should_run and running:
            self._task.cancel()
            self._task = None
            self._collector = ProcessHashCollector()   # a later opt-in rechecks everything

    async def collect_once(self) -> int:
        files = await asyncio.get_running_loop().run_in_executor(None, self._collector.new_files)
        if files:
            await self._realtime.send(P.PROCESS_HASHES, {"files": files})
        return len(files)

    async def _loop(self) -> None:
        while True:
            try:
                await self.collect_once()
            except Exception as exc:  # unreadable files / psutil quirks must never kill the loop
                logger.warning("Process hashes: collection failed: %s", exc)
            await asyncio.sleep(INTERVAL)

    def _on_notification(self, data: Dict[str, Any]) -> None:
        if (data or {}).get("kind") != "hash_hit":
            return
        hit = dict(data.get("hit") or {})
        if data.get("url"):
            hit["url"] = data["url"]
        self._audit.record("hash_hit", sha256=hit.get("sha256"), process=hit.get("process"))
        self._bus.emit(P.BUS_INTEL_HIT, hit)
