"""Opt-in sharing of this computer's network connections for threat-intel matching.

Every `netflow_interval` seconds (while connected *and* the user consented) the current outbound
connections are collected with psutil and new ones are sent as `netflow.batch`. The server checks
the remote IPs against threat feeds and answers with a notification for any hit.
Only remote IP/port, local port, protocol, TCP state and process name are sent — never payloads.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Any, Dict, List, Optional

import psutil
from injector import inject

from core.config import AppConfig
from core.event_bus import EventBus
from domain.interfaces.backend import ConnectionState, RealtimeChannel
from infrastructure.remote import protocol as P
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

logger = logging.getLogger(__name__)

SHARED_STATES = {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT}
RESEND_AFTER = 30 * 60   # a still-open connection is reported again after this many seconds
MAX_BATCH = 500


class NetworkFlowCollector:
    def __init__(self):
        self._names: Dict[int, str] = {}
        self._sent: Dict[tuple, float] = {}

    def _process(self, pid: Optional[int]) -> Optional[str]:
        if not pid:
            return None
        if pid not in self._names:
            try:
                self._names[pid] = psutil.Process(pid).name()[:64]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self._names[pid] = None
        return self._names[pid]

    def collect(self) -> List[Dict[str, Any]]:
        """Current outbound connections worth reporting (no loopback/link-local/unconnected)."""
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []
            for proc in psutil.process_iter(["pid"]):  # fall back to what this user may see
                try:
                    conns.extend(proc.net_connections(kind="inet"))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        flows = []
        for c in conns:
            udp = c.type == socket.SOCK_DGRAM
            # TCP: established/connecting only. UDP has no state; a remote address = connected (QUIC, DNS).
            if not c.raddr or (c.status not in SHARED_STATES and not udp):
                continue
            try:
                ip = ipaddress.ip_address(c.raddr.ip.split("%")[0])
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
            flows.append({
                "remote_ip": str(ip), "remote_port": c.raddr.port,
                "local_port": c.laddr.port if c.laddr else 0,
                "proto": "udp" if udp else "tcp",
                "state": "ESTABLISHED" if udp else c.status, "process": self._process(getattr(c, "pid", None)),
            })
        return flows

    def new_flows(self, flows: List[Dict[str, Any]], now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Delta: only connections not reported within RESEND_AFTER."""
        now = time.monotonic() if now is None else now
        out = []
        for f in flows:
            key = (f["remote_ip"], f["remote_port"], f["process"])
            if now - self._sent.get(key, float("-inf")) >= RESEND_AFTER:
                self._sent[key] = now
                out.append(f)
        if len(self._sent) > 20_000:  # bound memory on very busy hosts
            self._sent = {k: t for k, t in self._sent.items() if now - t < RESEND_AFTER}
        return out[:MAX_BATCH]


class NetflowService:
    @inject
    def __init__(self, realtime: RealtimeChannel, settings: AgentSettings, config: AppConfig,
                 event_bus: EventBus, audit: AgentAuditLog):
        self._realtime = realtime
        self._settings = settings
        self._interval = max(30.0, config.backend.netflow_interval)
        self._bus = event_bus
        self._audit = audit
        self._collector = NetworkFlowCollector()
        self._task: Optional[asyncio.Task] = None
        self.last_batch: List[Dict[str, Any]] = []
        self._bus.subscribe(P.BUS_STATE, self._on_state)
        self._bus.subscribe(P.bus_event(P.NOTIFICATION), self._on_notification)

    @property
    def sharing(self) -> bool:
        return self._settings.share_network_flows

    def set_sharing(self, enabled: bool) -> None:
        self._settings.share_network_flows = enabled
        self._audit.record("netflow_sharing_" + ("enabled" if enabled else "disabled"))
        self._on_state(self._realtime.state.value)

    def _on_state(self, state: str) -> None:
        should_run = state == ConnectionState.CONNECTED.value and self.sharing
        running = self._task is not None and not self._task.done()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if should_run and not running:
            self._task = loop.create_task(self._loop(), name="cybrix-netflow")
        elif not should_run and running:
            self._task.cancel()
            self._task = None

    async def collect_once(self) -> int:
        flows = await asyncio.get_running_loop().run_in_executor(None, self._collector.collect)
        batch = self._collector.new_flows(flows)
        if batch:
            await self._realtime.send(P.NETFLOW_BATCH, {"flows": batch})
            self.last_batch = batch
        self._bus.emit(P.BUS_AGENT_NETFLOW, {"sent": len(batch), "open": len(flows), "flows": batch[:50]})
        return len(batch)

    async def _loop(self) -> None:
        while True:
            try:
                await self.collect_once()
            except Exception as exc:  # psutil quirks must never kill the loop
                logger.warning("Netflow: collection failed: %s", exc)
            await asyncio.sleep(self._interval)

    def _on_notification(self, data: Dict[str, Any]) -> None:
        if (data or {}).get("kind") == "intel_hit":
            hit = dict(data.get("hit") or {})
            if data.get("url"):
                hit["url"] = data["url"]           # the server-side alert for this hit
            self._audit.record("intel_hit", dst_ip=hit.get("dst_ip"), process=hit.get("process"),
                               score=hit.get("score"), sources=hit.get("sources"))
            self._bus.emit(P.BUS_INTEL_HIT, hit)
