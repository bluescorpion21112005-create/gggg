"""Real-time GPU/CPU monitoring for AMD GPUs (blocking reads are offloaded to an executor).

The GPU is the one core.accelerator selects (the discrete card on an APU laptop). Metrics come
from `rocm-smi --json` (ROCm-SMI 7.x keys, bytes) when it is installed, otherwise straight from
amdgpu sysfs (gpu_busy_percent, mem_info_vram_*, hwmon temp1_input) — so neither rocm-smi nor
rocminfo is required.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import psutil
from injector import inject

from core import accelerator

logger = logging.getLogger(__name__)


@dataclass
class GPUMetrics:
    gpu_name: str = "Unknown"
    gpu_utilization: float = 0.0   # percent
    memory_used: float = 0.0       # MB
    memory_total: float = 0.0      # MB
    temperature: float = 0.0       # Celsius
    cpu_usage: float = 0.0
    ram_usage: float = 0.0         # percent
    rocm_available: bool = False
    gfx: str = ""
    error: Optional[str] = None


def is_pytorch_rocm_available() -> bool:
    """PyTorch is a ROCm build that can use the GPU."""
    return accelerator.torch_rocm_ready()


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text().strip()
    except OSError:
        return None


class GPUManager:
    @inject
    def __init__(self, prefer_rocm: bool = True, root: Path = accelerator.SYS):
        self._prefer_rocm = prefer_rocm
        self._root = root
        self._device = accelerator.select(accelerator.discover(root))
        self._name = accelerator.product_name(self._device, root) if self._device else "CPU only"
        logger.info("GPU Manager initialised. AMD GPU: %s",
                    f"{self._name} ({self._device.gfx})" if self._device else "none")

    @property
    def rocm_available(self) -> bool:
        return self._device is not None and self._prefer_rocm

    @property
    def device(self) -> Optional[accelerator.GpuDevice]:
        return self._device

    async def get_metrics_async(self) -> GPUMetrics:
        """Non-blocking metrics fetch: offloads subprocess/sysfs reads to the thread pool."""
        return await asyncio.get_running_loop().run_in_executor(None, self.get_metrics)

    def get_metrics(self) -> GPUMetrics:
        """Blocking call — do NOT call from the Qt main thread; use get_metrics_async() instead."""
        metrics = GPUMetrics(cpu_usage=psutil.cpu_percent(interval=0.1), ram_usage=psutil.virtual_memory().percent)
        if not self.rocm_available:
            metrics.gpu_name = "CPU only"
            return metrics
        metrics.gpu_name, metrics.gfx = self._name, self._device.gfx
        card = self._smi_card() or self._sysfs_card()
        if not card:
            metrics.error = "No metrics from rocm-smi or amdgpu sysfs"
            return metrics
        metrics.rocm_available = True
        metrics.gpu_utilization = round(card.get("util", 0.0), 1)
        metrics.memory_used = round(card.get("vram_used", 0.0) / 1048576, 1)
        metrics.memory_total = round(card.get("vram_total", 0.0) / 1048576, 1)
        metrics.temperature = round(card.get("temp", 0.0), 1)
        return metrics

    # ── sources ──────────────────────────────────────────────────────────────

    def _smi_card(self) -> dict:
        data = self._run_rocm_smi()
        entry = data.get(self._device.card) if self._device.card else None
        return parse_smi_entry(entry) if isinstance(entry, dict) else {}

    def _sysfs_card(self) -> dict:
        if not self._device.card:
            return {}
        dev = self._root / "class" / "drm" / self._device.card / "device"
        out = {}
        for key, name in (("util", "gpu_busy_percent"), ("vram_used", "mem_info_vram_used"),
                          ("vram_total", "mem_info_vram_total")):
            value = _read(dev / name)
            if value is not None and value.isdigit():
                out[key] = float(value)
        for temp in sorted(dev.glob("hwmon/hwmon*/temp1_input")):
            value = _read(temp)
            if value and value.lstrip("-").isdigit():
                out["temp"] = int(value) / 1000
                break
        return out

    def _run_rocm_smi(self) -> dict:
        try:
            output = subprocess.check_output(
                ["rocm-smi", "--showuse", "--showmeminfo", "vram", "--showtemp", "--json"],
                text=True, timeout=5, stderr=subprocess.DEVNULL)
            return json.loads(output)
        except FileNotFoundError:
            return {}
        except (subprocess.CalledProcessError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            logger.debug("rocm-smi failed: %s", exc)
            return {}


def parse_smi_entry(entry: dict) -> dict:
    """One card of `rocm-smi --json` (ROCm-SMI 7.x: bytes; older: MB) → util %, vram bytes, °C."""
    def num(*keys, scale=1.0):
        for key in keys:
            try:
                return float(entry[key]) * scale
            except (KeyError, TypeError, ValueError):
                continue
        return None

    values = {
        "util": num("GPU use (%)"),
        "vram_used": num("VRAM Total Used Memory (B)") or num("VRAM Total Used Memory (MB)", scale=1048576),
        "vram_total": num("VRAM Total Memory (B)") or num("VRAM Total Memory (MB)", scale=1048576),
        "temp": num("Temperature (Sensor edge) (C)", "Temperature (°C)", "Temperature (Sensor junction) (C)"),
    }
    return {k: v for k, v in values.items() if v is not None}
