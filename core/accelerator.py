"""AMD ROCm / CPU accelerator: detection, environment and PyTorch device selection.

Single source of truth for "which GPU do we use". Detection reads the kernel's KFD topology
(/sys/class/kfd) and DRM sysfs, so it works without `rocminfo` — only the amdgpu driver and
/dev/kfd access are needed. PyTorch's ROCm wheels bundle the HIP runtime themselves.

Consumer RDNA cards are not on ROCm's official list; their ISA is close enough to a supported one
that `HSA_OVERRIDE_GFX_VERSION` makes them work (gfx1031/1032/1034/1035/1036 → 10.3.0). With an
APU's integrated GPU present as well, HIP is restricted to the strongest discrete GPU via
`HIP_VISIBLE_DEVICES`, since mixing an iGPU in usually crashes kernels. configure_env() sets both
**only when the user has not set them** and must run before PyTorch initialises HIP.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SYS = Path("/sys")
KFD_DEVICE = Path("/dev/kfd")
# gfx prefix → HSA_OVERRIDE_GFX_VERSION for chips ROCm does not ship kernels for.
GFX_OVERRIDES = {"gfx103": "10.3.0", "gfx110": "11.0.0", "gfx115": "11.0.0"}
_preference = "auto"          # set by configure_env() from settings.yaml → gpu.device
NATIVE_GFX = {"gfx1030", "gfx1100", "gfx1101", "gfx1102", "gfx1200", "gfx1201", "gfx900", "gfx906", "gfx908",
              "gfx90a", "gfx942", "gfx950"}


@dataclass(frozen=True)
class GpuDevice:
    hip_index: int          # position among GPU nodes = HIP/PyTorch device order
    node: int               # KFD topology node
    name: str               # KFD code name, e.g. "navy_flounder"
    gfx: str                # e.g. "gfx1031"
    simd_count: int
    vram_bytes: int
    pci: str = ""           # e.g. "0000:03:00.0"
    card: str = ""          # DRM card, e.g. "card0"

    @property
    def needs_override(self) -> Optional[str]:
        if self.gfx in NATIVE_GFX:
            return None
        return next((v for p, v in GFX_OVERRIDES.items() if self.gfx.startswith(p)), None)


def gfx_name(version: int) -> str:
    """KFD gfx_target_version (e.g. 100301, 90010) → ISA name (gfx1031, gfx90a)."""
    major, minor, step = version // 10000, (version // 100) % 100, version % 100
    return f"gfx{major}{minor}{step:x}"


def _props(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            key, _, value = line.partition(" ")
            out[key] = value.strip()
    except OSError:
        pass
    return out


def _card_for_render_minor(minor: int, root: Path) -> tuple:
    if minor < 0:
        return "", ""
    drm = root / "class" / "drm"
    try:
        pci = (drm / f"renderD{minor}" / "device").resolve().name
    except OSError:
        return "", ""
    for card in sorted(drm.glob("card[0-9]*")):
        if "-" in card.name:              # connectors such as card0-DP-1
            continue
        try:
            if (card / "device").resolve().name == pci:
                return pci, card.name
        except OSError:
            continue
    return pci, ""


def discover(root: Path = SYS) -> List[GpuDevice]:
    """AMD GPUs known to the KFD driver, in HIP enumeration order."""
    nodes_dir = root / "class" / "kfd" / "kfd" / "topology" / "nodes"
    if not nodes_dir.is_dir():
        return []
    devices: List[GpuDevice] = []
    for node_dir in sorted(nodes_dir.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 1 << 30):
        props = _props(node_dir / "properties")
        try:
            simd = int(props.get("simd_count", "0"))
            version = int(props.get("gfx_target_version", "0"))
            minor = int(props.get("drm_render_minor", "-1"))
        except ValueError:
            continue
        if simd <= 0 or version <= 0:     # CPU node
            continue
        vram = 0
        for bank in sorted((node_dir / "mem_banks").glob("*")):
            try:
                vram += int(_props(bank / "properties").get("size_in_bytes", "0"))
            except ValueError:
                pass
        try:
            name = (node_dir / "name").read_text().strip()
        except OSError:
            name = ""
        pci, card = _card_for_render_minor(minor, root)
        devices.append(GpuDevice(hip_index=len(devices), node=int(node_dir.name), name=name,
                                 gfx=gfx_name(version), simd_count=simd, vram_bytes=vram, pci=pci, card=card))
    return devices


PCI_IDS = (Path("/usr/share/misc/pci.ids"), Path("/usr/share/hwdata/pci.ids"))
# libdrm's table maps device id + PCI revision to the exact product (one chip id covers several cards).
AMDGPU_IDS = (Path("/usr/share/libdrm/amdgpu.ids"), Path("/opt/amdgpu/share/libdrm/amdgpu.ids"))


def _amdgpu_ids_name(dev_id: str, revision: str, paths) -> Optional[str]:
    for path in paths:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            parts = [p.strip() for p in line.split(",", 2)]
            if len(parts) == 3 and parts[0].lower() == dev_id and parts[1].lower() == revision:
                return parts[2]
    return None


def product_name(device: GpuDevice, root: Path = SYS, pci_ids=PCI_IDS, amdgpu_ids=AMDGPU_IDS) -> str:
    """Exact product from libdrm's amdgpu.ids (id + revision, e.g. "AMD Radeon RX 6800M"), else the
    pci.ids family ("AMD Radeon RX 6700/6700 XT/…"), else the gfx code."""
    fallback = f"AMD {device.gfx}" + (f" ({device.name})" if device.name else "")
    if not device.card:
        return fallback
    dev_dir = root / "class" / "drm" / device.card / "device"
    try:
        dev_id = (dev_dir / "device").read_text().strip().lower()
    except OSError:
        return fallback
    dev_id = dev_id.removeprefix("0x")
    try:
        revision = (dev_dir / "revision").read_text().strip().lower().removeprefix("0x")
    except OSError:
        revision = ""
    exact = _amdgpu_ids_name(dev_id, revision, amdgpu_ids) if revision else None
    if exact:
        return exact
    for path in pci_ids:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        in_amd = False
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if not line.startswith("\t"):         # a vendor line ("1002  Advanced Micro Devices…")
                in_amd = line.startswith("1002 ")
                continue
            if in_amd and not line.startswith("\t\t") and line[1:5].lower() == dev_id:
                label = line[5:].strip()
                bracket = label[label.find("[") + 1:label.rfind("]")] if "[" in label else label
                return f"AMD {bracket}"
    return fallback


def kfd_accessible(path: Path = KFD_DEVICE) -> bool:
    return path.exists() and os.access(path, os.R_OK | os.W_OK)


def select(devices: List[GpuDevice]) -> Optional[GpuDevice]:
    """The strongest GPU (most SIMDs): the discrete card on an APU laptop."""
    return max(devices, key=lambda d: (d.simd_count, d.vram_bytes), default=None)


def configure_env(device_pref: str = "auto", hsa_override: str = "", visible_devices: str = "",
                  env=None, root: Path = SYS) -> Dict[str, str]:
    """Set ROCm environment for the selected GPU; returns what was set. Never overrides the user's env."""
    global _preference
    _preference = device_pref if device_pref in ("auto", "rocm", "cpu") else "auto"
    env = os.environ if env is None else env
    applied: Dict[str, str] = {}
    if device_pref == "cpu":
        return applied
    devices = discover(root)
    chosen = select(devices)
    if chosen is None:
        return applied
    override = hsa_override if hsa_override not in ("", "auto") else chosen.needs_override
    if override and override != "off" and "HSA_OVERRIDE_GFX_VERSION" not in env:
        env["HSA_OVERRIDE_GFX_VERSION"] = applied["HSA_OVERRIDE_GFX_VERSION"] = override
    visible = visible_devices or (str(chosen.hip_index) if len(devices) > 1 else "")
    if visible and "HIP_VISIBLE_DEVICES" not in env:
        env["HIP_VISIBLE_DEVICES"] = applied["HIP_VISIBLE_DEVICES"] = visible
    if applied:
        logger.info("ROCm environment for %s (%s): %s", chosen.name or chosen.gfx, chosen.gfx, applied)
    return applied


# ── PyTorch ───────────────────────────────────────────────────────────────────

_probe_result: Optional[bool] = None


def torch_rocm_ready() -> bool:
    """PyTorch is a ROCm build, sees a GPU **and can run a kernel on it** (HIP uses the torch.cuda API).

    torch.cuda.is_available() is also True for a card HIP cannot run kernels on (e.g. an RX 6000
    without HSA_OVERRIDE_GFX_VERSION → "invalid device function"), so one tiny kernel is tried once;
    on failure everything stays on the CPU instead of crashing later."""
    global _probe_result
    if _probe_result is not None:
        return _probe_result
    try:
        import torch
    except ImportError:
        return False
    if not getattr(torch.version, "hip", None) or not torch.cuda.is_available():
        _probe_result = False
        return False
    try:
        x = torch.ones(8, device="cuda")
        _probe_result = bool(((x * 2).sum() == 16).item())
    except Exception as exc:  # torch.AcceleratorError / RuntimeError from HIP
        logger.warning("AMD GPU visible to PyTorch but kernels fail (%s) — using the CPU. Is "
                       "HSA_OVERRIDE_GFX_VERSION set before PyTorch starts?", str(exc).splitlines()[0])
        _probe_result = False
    return _probe_result


def torch_device(preference: Optional[str] = None):
    """torch.device for computation: the ROCm GPU when usable (and not forced to CPU), else CPU.
    `preference` defaults to the configured gpu.device. Returns None when PyTorch is not installed."""
    preference = preference or _preference
    try:
        import torch
    except ImportError:
        return None
    if preference != "cpu" and torch_rocm_ready():
        return torch.device("cuda")
    if preference == "rocm":
        logger.warning("ROCm requested but no ROCm GPU is usable by PyTorch — using CPU")
    return torch.device("cpu")


def info(root: Path = SYS) -> Dict[str, object]:
    devices = discover(root)
    chosen = select(devices)
    data: Dict[str, object] = {
        "kfd_accessible": kfd_accessible(),
        "devices": [asdict(d) for d in devices],
        "selected": {**asdict(chosen), "product": product_name(chosen, root)} if chosen else None,
        "env": {k: os.environ[k] for k in ("HSA_OVERRIDE_GFX_VERSION", "HIP_VISIBLE_DEVICES") if k in os.environ},
        "torch": None, "hip": None, "torch_device": None, "torch_gpu_name": None,
    }
    try:
        import torch

        data["torch"] = torch.__version__
        data["hip"] = getattr(torch.version, "hip", None)
        data["torch_device"] = str(torch_device())
        if torch_rocm_ready():
            data["torch_gpu_name"] = torch.cuda.get_device_name(0)
    except ImportError:
        pass
    return data


def benchmark(size: int = 2048, repeats: int = 10) -> Dict[str, Optional[float]]:
    """Matrix-multiply throughput in TFLOPS on GPU (if usable) and CPU; None where not measured."""
    try:
        import torch
    except ImportError:
        return {"gpu_tflops": None, "cpu_tflops": None}
    flops = 2 * size ** 3 * repeats

    def run(device) -> float:
        a = torch.randn(size, size, device=device)
        b = torch.randn(size, size, device=device)
        torch.matmul(a, b)                               # warm-up (kernel load)
        if device.type == "cuda":
            torch.cuda.synchronize()
        start = time.perf_counter()
        for _ in range(repeats):
            torch.matmul(a, b)
        if device.type == "cuda":
            torch.cuda.synchronize()
        return round(flops / (time.perf_counter() - start) / 1e12, 3)

    result: Dict[str, Optional[float]] = {"gpu_tflops": None, "cpu_tflops": run(torch.device("cpu"))}
    if torch_rocm_ready():
        result["gpu_tflops"] = run(torch.device("cuda"))
    return result
