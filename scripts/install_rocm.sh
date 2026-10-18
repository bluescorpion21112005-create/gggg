#!/usr/bin/env bash
# Install PyTorch for AMD GPUs (ROCm 6.4) into .venv and check that it really uses the GPU.
#   scripts/install_rocm.sh            # install + check
#   scripts/install_rocm.sh --check    # only check
set -euo pipefail
cd "$(dirname "$0")/.."
PY=".venv/bin/python"
[ -x "$PY" ] || { echo "no .venv — create it first: python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt"; exit 1; }

if [ ! -e /dev/kfd ]; then
  echo "!! /dev/kfd is missing: the amdgpu kernel driver (with KFD) is not loaded — PyTorch will use the CPU."
elif [ ! -r /dev/kfd ] || [ ! -w /dev/kfd ]; then
  echo "!! no access to /dev/kfd — add yourself to the render and video groups, then log in again:"
  echo "   sudo usermod -aG render,video \"$USER\""
fi

if [ "${1:-}" != "--check" ]; then
  if command -v uv >/dev/null; then
    uv pip install --python "$PY" --index-url https://pypi.org/simple \
      --extra-index-url https://download.pytorch.org/whl/rocm6.4 -r requirements-rocm.txt
  else
    "$PY" -m pip install --extra-index-url https://download.pytorch.org/whl/rocm6.4 -r requirements-rocm.txt
  fi
fi

"$PY" - <<'PYEOF'
import json
from core import accelerator
applied = accelerator.configure_env()
info = accelerator.info()
sel = info["selected"] or {}
print(f"GPU:        {sel.get('product', 'none')} ({sel.get('gfx', '-')}, {sel.get('vram_bytes', 0) / 2**30:.1f} GB)")
print(f"ROCm env:   {applied or info['env'] or '-'}")
print(f"PyTorch:    {info['torch']}  HIP {info['hip']}  → device {info['torch_device']}")
bench = accelerator.benchmark()
print(f"Benchmark:  GPU {bench['gpu_tflops']} TFLOPS · CPU {bench['cpu_tflops']} TFLOPS")
if info["torch_device"] != "cuda":
    print("!! PyTorch is NOT using the GPU — see the messages above.")
PYEOF
