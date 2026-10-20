"""REA (github.com/morluto/rea) integration: kind detection, command plan, Evidence condensing,
malware-analysis fallback for non-PE files and the rea_analysis server command."""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from infrastructure.analyzers import rea_analyzer

FAKE_REA = """#!{python}
import json, sys
cmd, target = sys.argv[1], sys.argv[2]
if cmd == "inspect-rust-binary":
    print(json.dumps({{"code": "INVALID", "message": "not a rust binary"}})); sys.exit(1)
ev = {{"subject": {{"name": target.rsplit("/", 1)[-1], "digest": {{"sha256": "ab" * 32}}, "format": "elf",
                   "architecture": "x86_64"}},
      "provider": {{"id": "fake", "name": "Fake provider"}}, "operation": cmd.replace("-", "_"),
      "raw_result": {{"stdout": "file format elf64-x86-64\\\\n" if cmd == "inspect-with-objdump" else "",
                     "exit_code": 0}},
      "normalized_result": {{"build_info": {{"go_version": "go1.22.1"}}}} if cmd == "inspect-go-binary" else None,
      "limitations": ["Only metadata is inspected."]}}
print(json.dumps(ev))
"""


@pytest.fixture
def fake_rea(tmp_path, monkeypatch):
    exe = tmp_path / "rea"
    exe.write_text(FAKE_REA.format(python=sys.executable))
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("CYBRIX_REA_PATH", str(exe))
    return exe


def test_detect_kind_and_plan(tmp_path):
    elf = tmp_path / "a.out"
    elf.write_bytes(b"\x7fELF" + b"\0" * 60)
    js = tmp_path / "app"
    js.mkdir()
    (js / "package.json").write_text("{}")
    other = tmp_path / "x.bin"
    other.write_bytes(b"hello")
    assert [rea_analyzer.detect_kind(p) for p in (elf, js, other, tmp_path / "missing")] == [
        "elf", "js_app", "other", "other"]
    assert [c for c, _ in rea_analyzer.plan("elf")] == ["inspect-with-objdump", "inspect-with-objdump",
                                                         "inspect-go-binary", "inspect-rust-binary"]
    assert [c for c, _ in rea_analyzer.plan("elf", objdump=False)] == ["inspect-go-binary", "inspect-rust-binary"]
    assert rea_analyzer.plan("js_app") == [("analyze-javascript-application", [])]
    assert rea_analyzer.plan("other")[0][0] == "inspect-artifact"


def test_not_installed(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBRIX_REA_PATH", str(tmp_path / "nope"))
    monkeypatch.setattr(rea_analyzer, "DEFAULT_LOCATIONS", ())
    monkeypatch.setattr(rea_analyzer.shutil, "which", lambda _n: None)
    result = rea_analyzer.analyze(tmp_path)
    assert result["available"] is False and "rea-agents@" in result["hint"]
    assert rea_analyzer.to_markdown(result) == ""


def test_evidence_is_condensed(fake_rea, tmp_path, monkeypatch):
    monkeypatch.setattr(rea_analyzer.shutil, "which", lambda n: "/usr/bin/objdump" if n == "objdump" else None)
    elf = tmp_path / "sample"
    elf.write_bytes(b"\x7fELF" + b"\0" * 60)
    result = rea_analyzer.analyze(elf)
    assert result["available"] and result["ok"] and result["kind"] == "elf"
    by_cmd = {(r["command"], tuple(r["args"])): r for r in result["runs"]}
    objdump = by_cmd[("inspect-with-objdump", ("file_headers",))]
    assert objdump["output"].startswith("file format elf64") and objdump["sha256"] == "ab" * 32
    assert by_cmd[("inspect-go-binary", ())]["result"] == {"build_info": {"go_version": "go1.22.1"}}
    rust = by_cmd[("inspect-rust-binary", ())]
    assert rust["ok"] is False and "not a rust binary" in rust["error"]
    md = rea_analyzer.to_markdown(result)
    assert "## REA evidence (elf: `sample`)" in md and "go1.22.1" in md and "not a rust binary" in md


async def test_malware_analysis_falls_back_to_rea_for_non_pe(fake_rea, tmp_path):
    from application.use_cases.malware_analysis_use_case import MalwareAnalysisUseCase

    class Provider:
        prompts = []

        async def generate(self, prompt, model):
            Provider.prompts.append(prompt)
            yield "AI says: ELF sample."

    elf = tmp_path / "dropper"
    elf.write_bytes(b"\x7fELF" + b"\0" * 60)
    events = [e async for e in MalwareAnalysisUseCase(Provider()).analyze_file(str(elf), "m")]
    result = events[-1]
    assert result["features"] is None and result["rea"]["ok"]
    assert "REA evidence" in result["report"] and "Static evidence from REA" in Provider.prompts[-1]


async def test_rea_analysis_command_stays_in_allowed_dirs(make_executor, fake_rea, tmp_path):
    allowed = tmp_path / "samples"
    allowed.mkdir()
    (allowed / "bin").write_bytes(b"\x7fELF" + b"\0" * 60)
    ex = make_executor(allowed_dirs=[allowed])
    await ex.execute({"command_id": "r1", "type": "rea_analysis", "payload": {"file_path": str(allowed / "bin")}})
    result = [c.args[1] for c in ex.t.rt.send.await_args_list if c.args[0] == "command.result"][-1]
    assert result["success"] and result["result"]["kind"] == "elf"
    await ex.execute({"command_id": "r2", "type": "rea_analysis", "payload": {"file_path": "/etc/passwd"}})
    result = [c.args[1] for c in ex.t.rt.send.await_args_list if c.args[0] == "command.result"][-1]
    assert result["rejected"] and "outside" in result["error"]


@pytest.mark.skipif(not rea_analyzer.find_rea() or os.environ.get("CYBRIX_REA_PATH"), reason="REA not installed")
def test_real_rea_on_a_system_binary():
    result = rea_analyzer.analyze(Path("/usr/bin/ls"))
    assert result["kind"] == "elf" and result["ok"]
    assert any(r["ok"] and r["command"] == "inspect-go-binary" for r in result["runs"])
    json.dumps(result)                                               # serialisable for command results
