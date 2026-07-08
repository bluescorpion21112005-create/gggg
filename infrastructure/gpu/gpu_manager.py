"""Detect GPU capabilities (ROCm/CPU)."""
import subprocess

class GPUManager:
    @staticmethod
    def is_rocm_available() -> bool:
        try:
            result = subprocess.run(["rocminfo"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    @staticmethod
    def get_device_info() -> dict:
        return {
            "rocm_support": GPUManager.is_rocm_available(),
            "cpu_fallback": True,
        }