"""Standalone YARA file / directory scanner.

Scans a file or a whole directory tree against YARA rules and returns structured matches. Rules come
from a path the caller gives (a ``.yar`` file or a directory of them) or, when none is given, from a
small set of benign built-in detection rules (EICAR test string, common webshell / obfuscation
markers). This is independent of the signed rule-bundle pipeline (infrastructure/detection) so it can
be used ad-hoc on a lab machine.

Nothing here executes the scanned files; it only reads their bytes. Big files are capped and
unreadable paths are skipped so a scan of a large tree cannot hang or blow up memory.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 32 * 1024 * 1024       # skip files larger than this
SCAN_TIMEOUT = 20                       # seconds per file for the YARA engine

# Benign, detection-only built-in rules used when the caller supplies no rules path.
BUILTIN_RULES = r"""
rule EICAR_Test_File {
    meta: description = "EICAR antivirus test string (not malware)"
    strings: $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition: $e
}
rule Suspicious_PHP_Webshell {
    meta: description = "Common PHP webshell / dynamic-eval markers"
    strings:
        $a = "eval(" nocase
        $b = "base64_decode(" nocase
        $c = "system(" nocase
        $d = "shell_exec(" nocase
        $e = "<?php" nocase
    condition: $e and 2 of ($a,$b,$c,$d)
}
rule Obfuscated_PowerShell {
    meta: description = "Obfuscated / encoded PowerShell markers"
    strings:
        $a = "FromBase64String" nocase
        $b = "-EncodedCommand" nocase
        $c = "IEX(" nocase
        $d = "Invoke-Expression" nocase
    condition: 2 of them
}
"""


@dataclass
class YaraMatch:
    file: str
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "rule": self.rule, "tags": self.tags,
                "description": self.meta.get("description", ""), "strings": self.strings}


def compile_rules(rules_path: Optional[str] = None):
    """Compile YARA rules from a .yar file, a directory of .yar files, or the built-in set."""
    import yara

    if rules_path:
        p = Path(rules_path).expanduser()
        if p.is_dir():
            files = {f.stem: str(f) for f in sorted(p.rglob("*.yar")) + sorted(p.rglob("*.yara"))}
            if not files:
                raise FileNotFoundError(f"no .yar/.yara files under {p}")
            return yara.compile(filepaths=files)
        if p.is_file():
            return yara.compile(filepath=str(p))
        raise FileNotFoundError(f"rules path not found: {p}")
    return yara.compile(source=BUILTIN_RULES)


def _scan_file(rules, path: Path) -> list[YaraMatch]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return []
        hits = rules.match(str(path), timeout=SCAN_TIMEOUT)
    except Exception as exc:        # noqa: BLE001 - unreadable/odd file: skip it, don't abort the scan
        logger.debug("yara: skipped %s (%s)", path, exc)
        return []
    return [YaraMatch(file=str(path), rule=h.rule, tags=list(h.tags),
                      meta=dict(h.meta), strings=len(h.strings)) for h in hits]


def scan_path(target: str, rules_path: Optional[str] = None) -> dict[str, Any]:
    """Scan a file or directory tree. Returns {target, scanned, matches:[...], rules}."""
    rules = compile_rules(rules_path)
    root = Path(target).expanduser()
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    matches: list[YaraMatch] = []
    scanned = 0
    for f in files:
        scanned += 1
        matches.extend(_scan_file(rules, f))
    return {"target": str(root), "scanned": scanned,
            "rules": rules_path or "built-in",
            "matches": [m.to_dict() for m in matches]}


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="cybrix-yara", description="Scan a file or directory with YARA rules (local, read-only).")
    parser.add_argument("target", help="file or directory to scan")
    parser.add_argument("--rules", default="", help=".yar file or directory of rules (default: built-in)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)

    if not Path(args.target).expanduser().exists():
        print(f"[!] no such path: {args.target}", file=sys.stderr)
        return 2
    try:
        result = scan_path(args.target, args.rules or None)
    except Exception as exc:        # noqa: BLE001
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[*] scanned {result['scanned']} file(s) under {result['target']} "
              f"(rules: {result['rules']})")
        for m in result["matches"]:
            print(f"  [!] {m['rule']}  {m['file']}" + (f"  — {m['description']}" if m['description'] else ""))
        print(f"[+] {len(result['matches'])} match(es)")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
