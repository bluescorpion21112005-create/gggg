"""Real-time GPU/CPU monitoring with ROCm support (blocking ops offloaded to executor)."""
import asyncio
import logging
import subprocess
import json
from dataclasses import dataclass
from typing import Optional

import psutil
from injector import inject

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
    error: Optional[str] = None


def is_pytorch_rocm_available() -> bool:
    """Check if PyTorch is running with ROCm support."""
    try:
        import torch
        return torch.cuda.is_available() and torch.version.hip is not None
    except ImportError:
        return False


class GPUManager:
    @inject
    def __init__(self, prefer_rocm: bool = True):
        self._prefer_rocm = prefer_rocm
        self._rocm_available = self._detect_rocm()
        logger.info("GPU Manager initialised. ROCm available: %s", self._rocm_available)

    @property
    def rocm_available(self) -> bool:
        return self._rocm_available and self._prefer_rocm

    def _detect_rocm(self) -> bool:
        """One-time synchronous check at startup — acceptable blocking."""
        try:
            result = subprocess.run(
                ["rocminfo"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.info("rocminfo not found — ROCm not available")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("rocminfo timed out")
            return False

    async def get_metrics_async(self) -> GPUMetrics:
        """Non-blocking metrics fetch: offloads subprocess to thread pool executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get_metrics)

    def get_metrics(self) -> GPUMetrics:
        """Blocking call — do NOT call from Qt main thread; use get_metrics_async() instead."""
        metrics = GPUMetrics()
        metrics.cpu_usage = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory()
        metrics.ram_usage = ram.percent

        if not (self._rocm_available and self._prefer_rocm):
            metrics.gpu_name = "CPU only"
            return metrics

        data = self._run_rocm_smi()
        if not data:
            metrics.rocm_available = False
            metrics.error = "Failed to read rocm-smi data"
            return metrics

        try:
            total_util = 0.0
            total_mem_used = 0.0
            total_mem_total = 0.0
            total_temp = 0.0
            count = 0

            for card_id, card_data in data.items():
                if not card_id.startswith("card"):
                    continue
                count += 1
                total_util += float(card_data.get("GPU use (%)", 0))

                mem_used = card_data.get("VRAM Total Used Memory (MB)", "0")
                mem_total = card_data.get("VRAM Total Memory (MB)", "0")
                total_mem_used += float(mem_used) if mem_used else 0.0
                total_mem_total += float(mem_total) if mem_total else 0.0

                temp = card_data.get("Temperature (°C)") or card_data.get(
                    "Temperature (Sensor edge) (C)", "0"
                )
                total_temp += float(temp)

            if count > 0:
                metrics.gpu_utilization = round(total_util / count, 1)
                metrics.memory_used = round(total_mem_used / count, 1)
                metrics.memory_total = round(total_mem_total / count, 1)
                metrics.temperature = round(total_temp / count, 1)
                metrics.gpu_name = f"AMD ROCm ({count} GPU)"
                metrics.rocm_available = True
            else:
                metrics.rocm_available = False
                metrics.error = "No GPU cards found in rocm-smi output"

        except Exception as exc:
            logger.error("Error parsing rocm-smi output: %s", exc, exc_info=True)
            metrics.rocm_available = False
            metrics.error = str(exc)

        return metrics

    def _run_rocm_smi(self) -> dict:
        """Blocking subprocess call to rocm-smi (run via executor from async context)."""
        try:
            output = subprocess.check_output(
                ["rocm-smi", "--showuse", "--showmemuse", "vram", "--showtemp", "--json"],
                text=True,
                timeout=5,
            )
            return json.loads(output)
        except FileNotFoundError:
            logger.debug("rocm-smi not found")
            return {}
        except (subprocess.CalledProcessError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            logger.debug("rocm-smi failed: %s", exc)
            return {}
