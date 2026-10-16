"""Signed YARA/Sigma bundles on the desktop: verification, rollback refusal, yara_scan, Sigma in log_analysis."""
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from application.services.rule_service import RuleService
from infrastructure.detection import sigma
from infrastructure.detection.rule_bundle import RuleBundleError, canonical, verify
from infrastructure.remote.audit_log import AgentAuditLog

from backend_fakes import RecordingBus, make_config

pytest.importorskip("yara")

KEY = Ed25519PrivateKey.generate()
PUBLIC = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)).decode()
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
YARA = {"eicar_test_file": 'rule eicar_test_file { meta: severity = "low" strings: $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" '
                           "condition: $e }",
        "broken": "rule broken { condition: nope }"}
SIGMA = {"ssh_failed": "title: SSH failure\nlevel: low\ndetection:\n  kw: ['Failed password for']\n  condition: kw\n",
         "enc_ps": ("title: Encoded PowerShell\nlevel: high\ndetection:\n  sel:\n    Image|endswith: '\\powershell.exe'\n"
                    "    CommandLine|contains: [' -enc ', ' -EncodedCommand ']\n  flt:\n    User: 'SYSTEM'\n"
                    "  condition: sel and not flt\n"),
         "agg": "title: x\ndetection:\n  a: [b]\n  condition: a | count() > 5\n"}


def signed(version, yara=YARA, sigma_rules=SIGMA, key=KEY):
    bundle = {"version": version, "created": "2026-10-16T00:00:00+00:00", "yara": yara, "sigma": sigma_rules}
    body = canonical(bundle)
    return {"version": version, "bundle": body.decode(), "signature": base64.b64encode(key.sign(body)).decode()}


def make_service(tmp_path, key=PUBLIC, served=None):
    config = make_config(data_dir=str(tmp_path / "agent"))
    object.__setattr__(config, "rules_public_key", key)
    gateway = MagicMock(get_rules=AsyncMock(return_value=served or {}))
    bus = RecordingBus()
    return RuleService(config, gateway, bus, AgentAuditLog(config, bus)), gateway, bus


def test_verify_refuses_tampering_wrong_key_and_missing_key():
    s = signed(1)
    verify(s["bundle"], s["signature"], PUBLIC)
    other = signed(1, key=Ed25519PrivateKey.generate())
    for text, sig, key in ((s["bundle"].replace("SSH", "SSh"), s["signature"], PUBLIC),
                           (s["bundle"], other["signature"], PUBLIC), (s["bundle"], s["signature"], ""),
                           (json.dumps(json.loads(s["bundle"]), indent=1), s["signature"], PUBLIC)):
        with pytest.raises(RuleBundleError):
            verify(text, sig, key)


async def test_refresh_installs_skips_bad_rules_and_refuses_rollback(tmp_path):
    svc, gateway, bus = make_service(tmp_path, served=signed(5))
    assert await svc.refresh() is True
    assert svc.summary() == {"version": 5, "yara": 1, "sigma": 2, "skipped": 2}   # broken YARA + aggregation
    assert set(svc.skipped) == {"broken", "agg"}
    assert bus.of("agent.rules")[-1]["version"] == 5
    gateway.get_rules.return_value = signed(4)
    assert await svc.refresh() is False and svc.version == 5                      # older → refused
    assert any(e["event"] == "rules_refused" for e in svc._audit.recent())
    forged = {**signed(9), "signature": signed(8)["signature"]}
    gateway.get_rules.return_value = forged
    assert await svc.refresh() is False and svc.version == 5
    again, _, _ = make_service(tmp_path)                                            # survives restart
    assert again.version == 5


async def test_stored_bundle_edited_on_disk_is_ignored(tmp_path):
    svc, _, _ = make_service(tmp_path, served=signed(3))
    await svc.refresh()
    path = tmp_path / "agent" / "rules" / "bundle.json"
    stored = json.loads(path.read_text())
    stored["bundle"] = stored["bundle"].replace("Failed password", "anything")
    path.write_text(json.dumps(stored))
    assert make_service(tmp_path)[0].version == 0


async def test_no_key_means_no_rules(tmp_path):
    svc, _, _ = make_service(tmp_path, key="", served=signed(2))
    assert await svc.refresh() is False and svc.version == 0


async def test_yara_scan_stays_inside_allowed_dirs(tmp_path):
    svc, _, _ = make_service(tmp_path, served=signed(5))
    await svc.refresh()
    root = tmp_path / "scan"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "eicar.com").write_bytes(EICAR)
    (root / "clean.txt").write_text("hello")
    outside = tmp_path / "outside.com"
    outside.write_bytes(EICAR)
    (root / "link.com").symlink_to(outside)                                         # escapes the root
    result = svc.yara_scan(root, lambda p: Path(p).is_relative_to(root.resolve()))
    assert [Path(m["file"]).name for m in result["matches"]] == ["eicar.com"]
    assert result["matches"][0]["rule"] == "eicar_test_file" and len(result["matches"][0]["sha256"]) == 64
    assert (result["scanned"], result["skipped"], result["rules_version"]) == (2, 1, 5)


def test_sigma_subset_semantics():
    rules = {n: sigma.SigmaRule.parse(n, t) for n, t in SIGMA.items() if n != "agg"}
    lines = ["Oct 16 sshd[1]: Failed password for root from 203.0.113.9",
             json.dumps({"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc SQBFAFgA", "User": "ana"}),
             json.dumps({"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc AAA", "User": "SYSTEM"}),
             json.dumps({"Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad -enc x"}), "{not json"]
    hits = sigma.scan_lines(list(rules.values()), lines)
    assert {k: v["count"] for k, v in hits.items()} == {"ssh_failed": 1, "enc_ps": 1}
    assert hits["enc_ps"]["severity"] == "high"
    for bad in ("title: x\ndetection:\n  a: [b]\n  condition: a and\n",
                "title: x\ndetection:\n  a: [b]\n  condition: zzz\n",
                "title: x\ndetection:\n  a: {F|base64offset: x}\n  condition: a\n"):
        with pytest.raises(sigma.SigmaError):
            sigma.SigmaRule.parse("bad", bad)
    one_of = sigma.SigmaRule.parse("o", "title: o\ndetection:\n  s_a: [alpha]\n  s_b: [beta]\n  condition: 1 of s_*\n")
    all_of = sigma.SigmaRule.parse("a", "title: a\ndetection:\n  s_a: [alpha]\n  s_b: [beta]\n  condition: all of them\n")
    assert one_of.match("x beta") and not all_of.match("x beta") and all_of.match("alpha beta")
    # Sigma escaping: a backslash before a wildcard is written \\* ; a lone \* is a literal asterisk
    wild = sigma.SigmaRule.parse("w", r"""title: w
detection:
  s:
    Path: 'C:\Users\\*\Temp\\*.exe'
  condition: s
""")
    assert wild.match({"Path": "c:\\users\\ana\\temp\\x.exe"}) and not wild.match({"Path": "C:\\Windows\\x.exe"})


# ── through the CommandExecutor ──────────────────────────────────────────────

async def test_yara_scan_command_end_to_end(make_executor, tmp_path):
    svc, _, _ = make_service(tmp_path, served=signed(5))
    await svc.refresh()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "e.com").write_bytes(EICAR)
    ex = make_executor(allowed_dirs=[allowed], rules=svc)
    await ex.execute({"command_id": "y1", "type": "yara_scan", "payload": {"file_path": str(allowed)}})
    result = [c.args[1] for c in ex.t.rt.send.await_args_list if c.args[0] == "command.result"][-1]
    assert result["success"] and result["result"]["matches"][0]["rule"] == "eicar_test_file"
    await ex.execute({"command_id": "y2", "type": "yara_scan", "payload": {"file_path": str(tmp_path)}})
    result = [c.args[1] for c in ex.t.rt.send.await_args_list if c.args[0] == "command.result"][-1]
    assert result["rejected"] and "outside" in result["error"]


async def test_yara_scan_rejected_without_rules(make_executor, tmp_path):
    ex = make_executor(allowed_dirs=[tmp_path])
    await ex.execute({"command_id": "y3", "type": "yara_scan", "payload": {"file_path": str(tmp_path)}})
    result = [c.args[1] for c in ex.t.rt.send.await_args_list if c.args[0] == "command.result"][-1]
    assert result["rejected"] and "no verified YARA rules" in result["error"]


async def test_log_analysis_adds_sigma_matches(make_executor, tmp_path):
    svc, _, _ = make_service(tmp_path, served=signed(5))
    await svc.refresh()
    allowed = tmp_path / "logs"
    allowed.mkdir()
    log = allowed / "auth.log"
    log.write_text("ok\nsshd: Failed password for root\nsshd: Failed password for bob\n")
    ex = make_executor(allowed_dirs=[allowed], rules=svc)
    await ex.execute({"command_id": "l1", "type": "log_analysis", "payload": {"file_path": str(log)}})
    result = [c.args[1] for c in ex.t.rt.send.await_args_list if c.args[0] == "command.result"][-1]
    assert result["result"]["report"] == "REPORT" and result["result"]["rules_version"] == 5
    assert [(m["rule"], m["count"]) for m in result["result"]["sigma_matches"]] == [("ssh_failed", 2)]
