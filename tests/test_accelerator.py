"""AMD ROCm detection without rocminfo (KFD/sysfs), env setup, rocm-smi 7.x parsing, ML log anomalies."""
import os
from pathlib import Path

import pytest

from core import accelerator
from core.gpu_monitor import GPUManager, parse_smi_entry

# Real `rocm-smi --showuse --showmeminfo vram --showtemp --json` (ROCm-SMI 7.6) from an RX 6700 XT laptop.
SMI_7 = {"Temperature (Sensor edge) (C)": "44.0", "Temperature (Sensor junction) (C)": "45.0",
         "GPU use (%)": "7", "VRAM Total Memory (B)": "12868124672", "VRAM Total Used Memory (B)": "285741056"}


def make_sys(root: Path, gpus):
    """Fake /sys with a CPU node and the given GPUs: (gfx_target_version, simd, vram, device_id, render)."""
    nodes = root / "class" / "kfd" / "kfd" / "topology" / "nodes"
    (nodes / "0").mkdir(parents=True)
    (nodes / "0" / "properties").write_text("cpu_cores_count 16\nsimd_count 0\ngfx_target_version 0\n")
    for i, (gfx, simd, vram, dev_id, render, name) in enumerate(gpus, start=1):
        node = nodes / str(i)
        (node / "mem_banks" / "0").mkdir(parents=True)
        (node / "properties").write_text(f"simd_count {simd}\ngfx_target_version {gfx}\ndrm_render_minor {render}\n")
        (node / "mem_banks" / "0" / "properties").write_text(f"heap_type 1\nsize_in_bytes {vram}\n")
        (node / "name").write_text(name + "\n")
        pci = root / "devices" / f"0000:0{i}:00.0"
        (pci / "hwmon" / "hwmon1").mkdir(parents=True)
        (pci / "device").write_text(dev_id + "\n")
        (pci / "gpu_busy_percent").write_text("42\n")
        (pci / "mem_info_vram_used").write_text("1073741824\n")
        (pci / "mem_info_vram_total").write_text(f"{vram}\n")
        (pci / "hwmon" / "hwmon1" / "temp1_input").write_text("51000\n")
        drm = root / "class" / "drm"
        for entry in (f"card{i - 1}", f"renderD{render}"):
            (drm / entry).mkdir(parents=True, exist_ok=True)
            (drm / entry / "device").symlink_to(pci)
    return root


@pytest.fixture
def laptop(tmp_path):
    """RX 6700 XT (gfx1031, 80 SIMD) + Radeon 680M iGPU (gfx1035, 24 SIMD)."""
    return make_sys(tmp_path, [(100301, 80, 12868124672, "0x73df", 128, "navy_flounder"),
                               (100305, 24, 4294967296, "0x1681", 129, "yellow_carp")])


def test_discovery_without_rocminfo(laptop):
    devices = accelerator.discover(laptop)
    assert [(d.hip_index, d.gfx, d.simd_count, d.card) for d in devices] == [
        (0, "gfx1031", 80, "card0"), (1, "gfx1035", 24, "card1")]
    assert accelerator.select(devices).name == "navy_flounder"
    assert [accelerator.gfx_name(v) for v in (90010, 100301, 110001, 90402)] == ["gfx90a", "gfx1031", "gfx1101",
                                                                                  "gfx942"]


def test_no_amd_gpu(tmp_path):
    assert accelerator.discover(tmp_path) == []
    assert accelerator.configure_env(env={}, root=tmp_path) == {}
    assert GPUManager(root=tmp_path).get_metrics().gpu_name == "CPU only"


def test_env_override_and_discrete_gpu_only(laptop):
    env = {}
    assert accelerator.configure_env(env=env, root=laptop) == {"HSA_OVERRIDE_GFX_VERSION": "10.3.0",
                                                               "HIP_VISIBLE_DEVICES": "0"}
    user = {"HSA_OVERRIDE_GFX_VERSION": "11.0.0"}                     # the user's own setting wins
    accelerator.configure_env(env=user, root=laptop)
    assert user["HSA_OVERRIDE_GFX_VERSION"] == "11.0.0" and user["HIP_VISIBLE_DEVICES"] == "0"
    assert accelerator.configure_env("cpu", env={}, root=laptop) == {}
    assert "HSA_OVERRIDE_GFX_VERSION" not in accelerator.configure_env(hsa_override="off", env={}, root=laptop)


def test_supported_single_gpu_needs_nothing(tmp_path):
    root = make_sys(tmp_path, [(110000, 96, 24 * 2**30, "0x744c", 128, "rx7900")])     # gfx1100, native
    assert accelerator.configure_env(env={}, root=root) == {}


def test_product_name_from_pci_ids(laptop, tmp_path):
    ids = tmp_path / "pci.ids"
    ids.write_text("# comment\n1002  Advanced Micro Devices, Inc. [AMD/ATI]\n# inner comment\n"
                   "\t1681  Rembrandt [Radeon 680M]\n\t73df  Navi 22 [Radeon RX 6700/6700 XT/6750 XT]\n"
                   "10de  NVIDIA\n\t73df  Not AMD\n")
    first, second = accelerator.discover(laptop)
    assert accelerator.product_name(first, laptop, (ids,)) == "AMD Radeon RX 6700/6700 XT/6750 XT"
    assert accelerator.product_name(second, laptop, (ids,)) == "AMD Radeon 680M"
    assert accelerator.product_name(first, laptop, (tmp_path / "missing",)) == "AMD gfx1031 (navy_flounder)"


def test_rocm_smi_7_and_legacy_parsing():
    assert parse_smi_entry(SMI_7) == {"util": 7.0, "vram_used": 285741056.0, "vram_total": 12868124672.0,
                                      "temp": 44.0}
    legacy = parse_smi_entry({"GPU use (%)": "3", "VRAM Total Memory (MB)": "8192",
                              "VRAM Total Used Memory (MB)": "1024", "Temperature (°C)": "60"})
    assert legacy == {"util": 3.0, "vram_used": 1024 * 1048576.0, "vram_total": 8192 * 1048576.0, "temp": 60.0}
    assert parse_smi_entry({"GPU use (%)": "N/A"}) == {}


def test_metrics_for_the_discrete_gpu(laptop):
    manager = GPUManager(root=laptop)
    manager._run_rocm_smi = lambda: {"card0": SMI_7, "card1": {"GPU use (%)": "99"}}
    m = manager.get_metrics()
    assert (m.rocm_available, m.gfx, m.gpu_utilization, m.memory_total, m.temperature) == (
        True, "gfx1031", 7.0, round(12868124672 / 1048576, 1), 44.0)
    manager._run_rocm_smi = lambda: {}                                  # no rocm-smi → amdgpu sysfs
    m = manager.get_metrics()
    assert (m.gpu_utilization, m.memory_used, m.temperature) == (42.0, 1024.0, 51.0)
    assert GPUManager(prefer_rocm=False, root=laptop).get_metrics().gpu_name == "CPU only"


def test_gpu_device_preference_is_saved_and_applied(tmp_path):
    from backend_fakes import make_config
    from infrastructure.remote.agent_settings import AgentSettings, apply_user_overrides

    config = make_config(data_dir=str(tmp_path))
    settings = AgentSettings(config)
    with pytest.raises(ValueError):
        settings.set_pref("gpu_device", "cuda")
    settings.set_pref("gpu_device", "cpu")
    assert apply_user_overrides(config).gpu.device == "cpu"


def test_torch_device_falls_back_cleanly(monkeypatch):
    torch = pytest.importorskip("torch")
    assert accelerator.torch_device("cpu") == torch.device("cpu")
    monkeypatch.setattr(accelerator, "torch_rocm_ready", lambda: False)
    assert accelerator.torch_device("rocm") == torch.device("cpu")


def test_log_autoencoder_finds_the_odd_line():
    pytest.importorskip("torch")
    from infrastructure.analyzers.log_anomaly_torch import find_anomalies

    normal = [f"Oct 18 10:{i % 60:02d}:01 web nginx: GET /index.html 200 {512 + i % 7}" for i in range(400)]
    odd = "Oct 18 10:31:07 web sshd: Accepted publickey for root from 185.220.101.1 port 4444 ssh2 " \
          "0x4f2a9c8e1b7d6a5f4e3d2c1b0a998877 DENIED error"
    lines = normal[:250] + [odd] + normal[250:]
    result = find_anomalies(lines, device=None)
    assert result["anomalies"] and result["anomalies"][0]["line_no"] == 251
    assert find_anomalies(normal[:10])["anomalies"] == []                # too few lines to learn "normal"


@pytest.mark.skipif(not os.path.exists("/dev/kfd"), reason="needs an AMD GPU")
def test_real_rocm_gpu_runs_pytorch():
    """Hardware check: the real AMD GPU through ROCm (skipped on CI and machines without one)."""
    pytest.importorskip("torch")
    accelerator.configure_env()
    if not accelerator.torch_rocm_ready():
        pytest.skip("PyTorch here is not a ROCm build or the GPU is not usable")
    import torch

    x = torch.randn(256, 256, device="cuda")
    assert torch.allclose((x @ torch.eye(256, device="cuda")).cpu(), x.cpu(), atol=1e-4)
