import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

from application.services.process_hash_service import ProcessHashCollector, ProcessHashService
from domain.interfaces.backend import ConnectionState
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

from backend_fakes import RecordingBus, make_config


def make_service(tmp_path, consent):
    config = make_config(data_dir=str(tmp_path))
    settings = AgentSettings(config)
    settings.share_process_hashes = consent
    bus = RecordingBus()
    realtime = MagicMock(send=AsyncMock(), state=ConnectionState.CONNECTED)
    return ProcessHashService(realtime, settings, bus, AgentAuditLog(config, bus)), realtime, bus


def test_collector_sends_basename_and_only_new_or_changed(tmp_path):
    exe = tmp_path / "secret-user" / "tool.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ hello")
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 2048)
    c = ProcessHashCollector(max_bytes=1024)
    files = c.new_files([str(exe), str(big), str(tmp_path / "missing.exe")])
    assert files == [{"sha256": hashlib.sha256(b"MZ hello").hexdigest(), "name": "tool.exe"}]
    assert "secret-user" not in str(files)
    assert c.new_files([str(exe)]) == []                     # unchanged → not hashed/sent again
    exe.write_bytes(b"MZ changed!")
    assert c.new_files([str(exe)])[0]["sha256"] == hashlib.sha256(b"MZ changed!").hexdigest()


def test_collector_caps_batch(tmp_path):
    paths = []
    for i in range(205):
        p = tmp_path / f"p{i}.exe"
        p.write_bytes(str(i).encode())
        paths.append(str(p))
    assert len(ProcessHashCollector().new_files(paths)) == 200


def test_consent_off_by_default(tmp_path):
    assert AgentSettings(make_config(data_dir=str(tmp_path))).share_process_hashes is False


async def test_without_consent_nothing_runs(tmp_path):
    svc, realtime, bus = make_service(tmp_path, consent=False)
    bus.emit("backend.state", "connected")
    assert svc._task is None
    realtime.send.assert_not_awaited()


async def test_with_consent_sends_and_surfaces_hash_hits(tmp_path):
    svc, realtime, bus = make_service(tmp_path, consent=True)
    exe = tmp_path / "e.exe"
    exe.write_bytes(b"X5O")
    with patch.object(ProcessHashCollector, "executables", return_value=[str(exe)]):
        assert await svc.collect_once() == 1
        assert await svc.collect_once() == 0                 # nothing new → nothing sent
    type_, data = realtime.send.await_args.args
    assert type_ == "process.hashes" and data["files"][0]["name"] == "e.exe"
    bus.emit("backend.notification", {"kind": "intel_hit", "hit": {"dst_ip": "1.2.3.4"}})
    assert bus.of("agent.intel_hit") == []                   # netflow hits are not ours
    bus.emit("backend.notification", {"kind": "hash_hit", "url": "/alerts/3/",
                                      "hit": {"sha256": "ab" * 32, "process": "e.exe"}})
    assert bus.of("agent.intel_hit") == [{"sha256": "ab" * 32, "process": "e.exe", "url": "/alerts/3/"}]
    assert any(e["event"] == "hash_hit" for e in svc._audit.recent())
