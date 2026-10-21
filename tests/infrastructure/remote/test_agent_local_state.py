import json

from application.services.connection_service import ConnectionService
from application.services.telemetry_service import TelemetryCollector
from infrastructure.remote import audit_log as audit_mod
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

from backend_fakes import RecordingBus, make_config


def test_agent_settings_persist_install_id_and_choices(tmp_path):
    config = make_config(data_dir=str(tmp_path))
    first = AgentSettings(config)
    first.allow_always("ioc_analysis")
    first.command_policy = "allow_listed"
    first.share_telemetry = False
    again = AgentSettings(config)
    assert again.install_id == first.install_id
    assert again.always_allowed == {"ioc_analysis"}
    assert (again.command_policy, again.share_telemetry) == ("allow_listed", False)


def test_agent_settings_survive_corrupt_file(tmp_path):
    (tmp_path / "agent_settings.json").write_text("{not json")
    settings = AgentSettings(make_config(data_dir=str(tmp_path)))
    assert settings.install_id and settings.command_policy == "ask"


def test_audit_log_records_reads_newest_first_and_rotates(tmp_path, monkeypatch):
    bus = RecordingBus()
    log = AgentAuditLog(make_config(data_dir=str(tmp_path)), bus)
    log.record("login", server="https://x")
    log.record("command_done", command_id="c1")
    assert [e["event"] for e in log.recent()] == ["command_done", "login"]
    assert bus.of("agent.audit")[0]["event"] == "login"
    monkeypatch.setattr(audit_mod, "MAX_BYTES", 200)
    for i in range(20):
        log.record("filler", i=i, pad="x" * 50)
    assert (tmp_path / "agent_audit.jsonl.1").exists()
    for line in (tmp_path / "agent_audit.jsonl").read_text().splitlines():
        json.loads(line)


def test_telemetry_sample_shape_matches_server_allowlist():
    server_numeric = {"cpu_percent", "ram_percent", "disk_percent", "gpu_percent", "gpu_mem_percent",
                      "net_rx_bps", "net_tx_bps", "process_count", "uptime_seconds", "temperature"}
    collector = TelemetryCollector(gpu=None)
    collector.collect()
    sample = collector.collect()  # second sample has network rates
    assert {"cpu_percent", "ram_percent", "disk_percent", "net_rx_bps", "net_tx_bps"} <= set(sample)
    for key, value in sample.items():
        if key in server_numeric:
            assert isinstance(value, (int, float)) and not isinstance(value, bool), key
        else:
            assert key in {"hostname", "os", "gpu_name"}, key


def test_system_snapshot_is_bounded():
    snap = TelemetryCollector.snapshot(top=5)
    assert len(snap["top_processes_by_memory"]) <= 5
    assert snap["process_count"] >= 1
    assert isinstance(snap["disks"], list)


def test_token_refresh_window(tmp_path):
    from datetime import datetime, timedelta, timezone

    svc = ConnectionService.__new__(ConnectionService)
    svc._config = make_config(data_dir=str(tmp_path), token_refresh_days=7)
    soon = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    later = (datetime.now(timezone.utc) + timedelta(days=20)).isoformat()
    assert svc.needs_refresh(soon) is True
    assert svc.needs_refresh(later) is False
    assert svc.needs_refresh(None) is False
    assert svc.needs_refresh("garbage") is False


def test_delta_encoder_keyframes_and_thresholds():
    from application.services.telemetry_service import TelemetryDeltaEncoder

    enc = TelemetryDeltaEncoder(keyframe_interval=60)
    base = {"cpu_percent": 10.0, "ram_percent": 40.0, "net_rx_bps": 5000.0, "uptime_seconds": 100, "hostname": "h"}
    first = enc.encode(base, now=0)
    assert first["full"] is True and first["cpu_percent"] == 10.0
    # tiny changes and uptime ticks are not worth a message
    assert enc.encode({**base, "cpu_percent": 10.4, "uptime_seconds": 105, "net_rx_bps": 5500.0}, now=5) is None
    delta = enc.encode({**base, "cpu_percent": 12.0, "net_rx_bps": 9000.0}, now=10)
    assert delta == {"cpu_percent": 12.0, "net_rx_bps": 9000.0, "full": False}
    # thresholds compare to what was last *sent*, so slow drift still gets reported
    now_state = {**base, "net_rx_bps": 9000.0}
    assert enc.encode({**now_state, "cpu_percent": 12.6}, now=15) is None
    assert enc.encode({**now_state, "cpu_percent": 13.1}, now=20) == {"cpu_percent": 13.1, "full": False}
    # periodic keyframe and reset() both force a full sample
    assert enc.encode(base, now=61)["full"] is True
    enc.reset()
    assert enc.encode(base, now=62)["full"] is True
