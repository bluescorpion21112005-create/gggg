"""YARA file/directory scanner: built-in rules, custom rules, directory walk, CLI."""
from __future__ import annotations

from infrastructure.analyzers import yara_scanner

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
WEBSHELL = '<?php eval(base64_decode($_POST["x"])); system($_GET["c"]); ?>'


def _lab(tmp_path):
    (tmp_path / "eicar.txt").write_text(EICAR)
    (tmp_path / "shell.php").write_text(WEBSHELL)
    (tmp_path / "clean.txt").write_text("just a normal note")
    return tmp_path


def test_builtin_rules_match_eicar_and_webshell(tmp_path):
    result = yara_scanner.scan_path(str(_lab(tmp_path)))
    rules = {m["rule"] for m in result["matches"]}
    assert result["scanned"] == 3
    assert "EICAR_Test_File" in rules and "Suspicious_PHP_Webshell" in rules
    # the clean file must not match anything
    assert all("clean.txt" not in m["file"] for m in result["matches"])


def test_single_file_scan(tmp_path):
    f = tmp_path / "e.txt"
    f.write_text(EICAR)
    result = yara_scanner.scan_path(str(f))
    assert result["scanned"] == 1 and result["matches"][0]["rule"] == "EICAR_Test_File"


def test_custom_rules_file(tmp_path):
    rule = tmp_path / "r.yar"
    rule.write_text('rule FindsSecret { strings: $s = "TOPSECRET" condition: $s }')
    (tmp_path / "doc.txt").write_text("header TOPSECRET footer")
    (tmp_path / "other.txt").write_text("nothing here")
    result = yara_scanner.scan_path(str(tmp_path), rules_path=str(rule))
    files = {m["file"] for m in result["matches"] if m["rule"] == "FindsSecret"}
    # doc.txt matches; the clean file does not (the rule file itself matching its own string is fine)
    assert any("doc.txt" in f for f in files) and all("other.txt" not in f for f in files)


def test_cli(tmp_path, capsys):
    _lab(tmp_path)
    assert yara_scanner.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "EICAR_Test_File" in out and "match(es)" in out


def test_cli_missing_path(tmp_path):
    assert yara_scanner.main([str(tmp_path / "nope")]) == 2
