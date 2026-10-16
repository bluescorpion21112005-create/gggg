"""Host telemetry for the server dashboard (and the local "what is shared" view).

Collection runs in a worker thread (psutil and rocm-smi can block); the sampling loop only
runs while the realtime channel is connected and the user allows sharing.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
import time
from typing import Any, Dict, List, Optional

import psutil
from injector import inject

from core.config import AppConfig
from core.event_bus import EventBus
from core.gpu_monitor import GPUManager
from domain.interfaces.backend import ConnectionState, RealtimeChannel
from infrastructure.remote import protocol as P
from infrastructure.remote.agent_settings import AgentSettings

logger = logging.getLogger(__name__)


class TelemetryCollector:
    """Stateful sampler (network rates need the previous counters)."""

    def __init__(self, gpu: Optional[GPUManager] = None):
        self._gpu = gpu
        self._last_net: Optional[tuple[float, int, int]] = None
        psutil.cpu_percent(interval=None)  # prime: the first non-blocking call always returns 0.0

    def collect(self) -> Dict[str, Any]:
        now = time.monotonic()
        sample: Dict[str, Any] = {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "ram_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage(self._system_root()).percent,
            "process_count": len(psutil.pids()),
            "uptime_seconds": int(time.time() - psutil.boot_time()),
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}".strip(),
        }
        net = psutil.net_io_counters()
        if net is not None:
            if self._last_net is not None:
                elapsed = max(now - self._last_net[0], 1e-3)
                sample["net_rx_bps"] = max(0.0, (net.bytes_recv - self._last_net[1]) / elapsed)
                sample["net_tx_bps"] = max(0.0, (net.bytes_sent - self._last_net[2]) / elapsed)
            self._last_net = (now, net.bytes_recv, net.bytes_sent)
        if self._gpu is not None and self._gpu.rocm_available:
            metrics = self._gpu.get_metrics()
            if metrics.rocm_available:
                sample["gpu_percent"] = metrics.gpu_utilization
                sample["temperature"] = metrics.temperature
                sample["gpu_name"] = metrics.gpu_name
                if metrics.memory_total:
                    sample["gpu_mem_percent"] = round(100 * metrics.memory_used / metrics.memory_total, 1)
        return {k: (round(v, 2) if isinstance(v, float) else v) for k, v in sample.items()}

    @staticmethod
    def _system_root() -> str:
        return os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"

    @staticmethod
    def snapshot(top: int = 10) -> Dict[str, Any]:
        """On-demand, read-only system overview for the `system_snapshot` command."""
        procs: List[Dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            info = proc.info
            procs.append({
                "pid": info["pid"], "name": info.get("name") or "?", "user": info.get("username") or "",
                "cpu_percent": round(info.get("cpu_percent") or 0.0, 1),
                "memory_percent": round(info.get("memory_percent") or 0.0, 2),
            })
        by_mem = sorted(procs, key=lambda p: p["memory_percent"], reverse=True)[:top]

        listening: List[Dict[str, Any]] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    listening.append({"address": conn.laddr.ip, "port": conn.laddr.port, "pid": conn.pid})
        except (psutil.AccessDenied, PermissionError):
            listening = [{"error": "permission denied (needs elevated privileges)"}]

        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            disks.append({"mount": part.mountpoint, "fstype": part.fstype,
                          "total_gb": round(usage.total / 2**30, 1), "percent": usage.percent})
        return {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "boot_time": int(psutil.boot_time()),
            "top_processes_by_memory": by_mem,
            "process_count": len(procs),
            "listening_ports": sorted(listening, key=lambda c: c.get("port", 0))[:100],
            "disks": disks,
        }


# Thresholds below which a metric is not worth re-sending (keyframes resend everything).
PERCENT_STEP = 1.0
RATE_MIN_STEP = 1024.0      # bytes/s
RATE_REL_STEP = 0.10        # 10 %
KEYFRAME_ONLY = {"uptime_seconds"}  # changes every sample; only sent with keyframes


class TelemetryDeltaEncoder:
    """Turns full samples into keyframes (``full: true``) and deltas (``full: false``).

    A keyframe goes out on the first sample, after reset() (every (re)connect, since the server
    may have lost state) and at least every ``keyframe_interval`` seconds. In between, only
    metrics that moved by a meaningful amount are sent; ``None`` means nothing worth sending.
    """

    def __init__(self, keyframe_interval: float = 60.0):
        self.keyframe_interval = keyframe_interval
        self._sent: Dict[str, Any] = {}
        self._last_keyframe = float("-inf")

    def reset(self) -> None:
        self._sent = {}
        self._last_keyframe = float("-inf")

    def encode(self, sample: Dict[str, Any], now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        now = time.monotonic() if now is None else now
        if not self._sent or now - self._last_keyframe >= self.keyframe_interval:
            self._sent = dict(sample)
            self._last_keyframe = now
            return {**sample, "full": True}
        changes = {k: v for k, v in sample.items()
                   if k not in KEYFRAME_ONLY and self._significant(k, self._sent.get(k), v)}
        if not changes:
            return None
        self._sent.update(changes)
        return {**changes, "full": False}

    @staticmethod
    def _significant(key: str, old: Any, new: Any) -> bool:
        numbers = all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (old, new))
        if not numbers:
            return old != new
        if key.endswith("_percent") or key == "temperature":
            return abs(new - old) >= PERCENT_STEP
        if key.endswith("_bps"):
            return abs(new - old) >= max(RATE_MIN_STEP, RATE_REL_STEP * abs(old))
        return new != old


class TelemetryService:
    @inject
    def __init__(self, realtime: RealtimeChannel, settings: AgentSettings, config: AppConfig,
                 event_bus: EventBus, gpu: GPUManager):
        self._realtime = realtime
        self._settings = settings
        self._interval = max(2.0, config.backend.telemetry_interval)
        self._bus = event_bus
        self._collector = TelemetryCollector(gpu)
        self._encoder = TelemetryDeltaEncoder(P.TELEMETRY_KEYFRAME_INTERVAL)
        self._task: Optional[asyncio.Task] = None
        self.last_sample: Dict[str, Any] = {}
        self._bus.subscribe(P.BUS_STATE, self._on_state)

    @property
    def sharing(self) -> bool:
        return self._settings.share_telemetry

    def set_sharing(self, enabled: bool) -> None:
        self._settings.share_telemetry = enabled
        self._on_state(self._realtime.state.value)

    async def collect(self) -> Dict[str, Any]:
        return await asyncio.get_running_loop().run_in_executor(None, self._collector.collect)

    async def snapshot(self) -> Dict[str, Any]:
        return await asyncio.get_running_loop().run_in_executor(None, TelemetryCollector.snapshot)

    def _on_state(self, state: str) -> None:
        if state == ConnectionState.CONNECTED.value:
            self._encoder.reset()  # a (re)connected server may have lost our state → keyframe first
        should_run = state == ConnectionState.CONNECTED.value and self.sharing
        running = self._task is not None and not self._task.done()
        if should_run and not running:
            self._task = asyncio.get_running_loop().create_task(self._loop(), name="cybrix-telemetry")
        elif not should_run and running:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                sample = await self.collect()
            except Exception as exc:  # psutil quirks must never kill the loop
                logger.warning("Telemetry: collection failed: %s", exc)
            else:
                self.last_sample = sample
                message = self._encoder.encode(sample)
                if message is not None:
                    self._realtime.send_telemetry(message)
                self._bus.emit(P.BUS_AGENT_TELEMETRY, sample)
            await asyncio.sleep(self._interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None
