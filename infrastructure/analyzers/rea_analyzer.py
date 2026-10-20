"""REA — "Reverse Engineer Anything" (github.com/morluto/rea, MIT) as a static analysis backend.

REA is a Node.js CLI/MCP server (npm `rea-agents`; source pinned as the git submodule
third_party/rea). Every command returns one JSON *Evidence* record: subject (name, sha256,
format, architecture), provider, operation, raw/normalized result and explicit limitations.
This module picks the static commands that fit the file, runs them with --json, and condenses
the Evidence for reports and the AI prompt. Nothing here executes the analysed file: the
commands used are read-only inspections (objdump headers, Go/Rust build metadata, .NET
metadata, JavaScript/Electron module graph, safe artifact graph).

The `rea` executable is found via CYBRIX_REA_PATH, then PATH, then ~/.local/opt/rea
(`npm install --prefix ~/.local/opt/rea rea-agents@6.7.0`). Without it the app works as before.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REA_VERSION = "6.7.0"
DEFAULT_LOCATIONS = (Path.home() / ".local" / "opt" / "rea" / "node_modules" / ".bin" / "rea",)
TIMEOUT = 180                     # seconds per command
MAX_STDOUT = 12_000               # characters of raw tool output kept per command
MAX_NORMALIZED = 6_000            # characters of normalized JSON kept per command


def find_rea() -> Optional[str]:
    env = os.getenv("CYBRIX_REA_PATH")
    if env and Path(env).is_file() and os.access(env, os.X_OK):
        return env
    found = shutil.which("rea")
    if found:
        return found
    for candidate in DEFAULT_LOCATIONS:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def detect_kind(path: Path) -> str:
    """elf | pe | dotnet | macho | js_app | other — from magic bytes / layout, without executing anything."""
    if path.is_dir():
        return "js_app" if (path / "package.json").exists() or any(path.glob("*.asar")) else "other"
    if path.suffix.lower() == ".asar":
        return "js_app"
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return "other"
    if head == b"\x7fELF":
        return "elf"
    if head in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head[:2] == b"MZ":
        try:
            import pefile

            pe = pefile.PE(str(path), fast_load=True)
            com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]          # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            pe.close()
            return "dotnet" if com.VirtualAddress and com.Size else "pe"
        except Exception:  # malformed PE: still treat as PE for objdump/artifact inspection
            return "pe"
    return "other"


def plan(kind: str, objdump: bool = True) -> List[Tuple[str, List[str]]]:
    """(command, extra args) to run for this kind of target — static, read-only inspections only."""
    native: List[Tuple[str, List[str]]] = []
    if objdump:
        native += [("inspect-with-objdump", ["file_headers"]), ("inspect-with-objdump", ["section_headers"])]
    native += [("inspect-go-binary", []), ("inspect-rust-binary", [])]
    return {
        "elf": native,
        "pe": native,
        "macho": native,
        "dotnet": [("inspect-managed-artifact", []), ("inspect-artifact", ["--detail", "summary"])],
        "js_app": [("analyze-javascript-application", [])],
    }.get(kind, [("inspect-artifact", ["--detail", "summary"])])


def _condense(evidence: Dict[str, Any]) -> Dict[str, Any]:
    subject = evidence.get("subject") or {}
    provider = evidence.get("provider") or {}
    raw = evidence.get("raw_result") if isinstance(evidence.get("raw_result"), dict) else {}
    normalized = evidence.get("normalized_result")
    out: Dict[str, Any] = {
        "provider": provider.get("name") or provider.get("id"),
        "operation": evidence.get("operation"),
        "format": subject.get("format"),
        "architecture": subject.get("architecture"),
        "sha256": (subject.get("digest") or {}).get("sha256"),
        "limitations": [str(x)[:300] for x in (evidence.get("limitations") or [])][:5],
    }
    if raw.get("stdout"):
        out["output"] = raw["stdout"][:MAX_STDOUT]
        out["output_truncated"] = len(raw["stdout"]) > MAX_STDOUT or bool(raw.get("output_truncated"))
    elif normalized is not None:
        text = json.dumps(normalized, ensure_ascii=False, default=str)
        out["result"] = normalized if len(text) <= MAX_NORMALIZED else text[:MAX_NORMALIZED] + " …"
    return out


def run_command(rea: str, command: str, target: Path, extra: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    args = [rea, command, str(target), *extra, "--json"]
    env = {**os.environ, "NO_COLOR": "1", "CI": "1"}           # no TTY prompts, plain output
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env,
                              cwd=tempfile.gettempdir())
    except subprocess.TimeoutExpired:
        return {"command": command, "args": extra, "ok": False, "error": f"timed out after {timeout}s"}
    except OSError as exc:
        return {"command": command, "args": extra, "ok": False, "error": str(exc)}
    try:
        evidence = json.loads(proc.stdout) if proc.stdout.strip() else None
    except ValueError:
        evidence = None
    if proc.returncode != 0 or not isinstance(evidence, dict):
        message = str(evidence.get("message") or evidence.get("error") or "") if isinstance(evidence, dict) else ""
        return {"command": command, "args": extra, "ok": False, "exit_code": proc.returncode,
                "error": (message or proc.stderr.strip() or "no JSON output")[:500]}
    return {"command": command, "args": extra, "ok": True, **_condense(evidence)}


def analyze(target, rea: Optional[str] = None, timeout: int = TIMEOUT) -> Dict[str, Any]:
    """Run the fitting REA inspections; {"available": False} when REA is not installed."""
    rea = rea or find_rea()
    if not rea:
        return {"available": False, "tool": "rea",
                "hint": f"npm install --prefix ~/.local/opt/rea rea-agents@{REA_VERSION}"}
    path = Path(target)
    kind = detect_kind(path)
    runs = [run_command(rea, cmd, path, extra, timeout)
            for cmd, extra in plan(kind, shutil.which("objdump") is not None)]
    return {"available": True, "tool": "rea", "kind": kind, "target": path.name, "runs": runs,
            "ok": any(r["ok"] for r in runs)}


def to_markdown(result: Dict[str, Any], max_output_lines: int = 25) -> str:
    """Report section for an analyze() result ("" when REA is unavailable)."""
    if not result.get("available"):
        return ""
    lines = [f"## REA evidence ({result['kind']}: `{result['target']}`)",
             "_Static inspection by REA (github.com/morluto/rea); the file was not executed._", ""]
    for run in result["runs"]:
        title = run["command"] + (" " + " ".join(run["args"]) if run.get("args") else "")
        if not run["ok"]:
            lines.append(f"- **{title}** — not available: {str(run.get('error', ''))[:200]}")
            continue
        facts = ", ".join(f"{k}: {run[k]}" for k in ("format", "architecture") if run.get(k))
        lines.append(f"### {title}" + (f" — {facts}" if facts else ""))
        if run.get("output"):
            lines += ["```", "\n".join(run["output"].strip().splitlines()[:max_output_lines]), "```"]
        elif run.get("result") is not None:
            text = run["result"] if isinstance(run["result"], str) else json.dumps(
                run["result"], indent=1, ensure_ascii=False, default=str)
            lines += ["```json", "\n".join(text.splitlines()[:max_output_lines]), "```"]
        if run.get("limitations"):
            lines.append("Limitations: " + "; ".join(run["limitations"][:2]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
