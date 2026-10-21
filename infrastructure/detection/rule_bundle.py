"""Verification and local storage of signed YARA/Sigma bundles (mirror of cybrix_ai desktop_agent/rules.py).

A bundle is accepted only if its Ed25519 signature verifies against the key pinned in settings.yaml
(`rules.public_key`), the bytes are canonical JSON, and its version is newer than the stored one.
The stored copy is re-verified on every load, so a file edited on disk is ignored.
"""
from __future__ import annotations

import base64
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class RuleBundleError(ValueError):
    pass


def canonical(bundle: Dict[str, Any]) -> bytes:
    body = {k: bundle[k] for k in ("version", "created", "yara", "sigma")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify(bundle_text: str, signature_b64: str, public_key_b64: str) -> Dict[str, Any]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not public_key_b64:
        raise RuleBundleError("this build has no rules key; detection rules are disabled")
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature_b64), bundle_text.encode("utf-8"))
        bundle = json.loads(bundle_text)
        if canonical(bundle).decode("utf-8") != bundle_text:
            raise RuleBundleError("bundle is not canonical")
    except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, RuleBundleError):
            raise
        raise RuleBundleError("rule bundle signature is invalid — refused") from exc
    if not isinstance(bundle.get("version"), int) or bundle["version"] <= 0:
        raise RuleBundleError("bad bundle version")
    for kind in ("yara", "sigma"):
        group = bundle.get(kind)
        if not isinstance(group, dict) or not all(NAME_RE.match(n) and isinstance(t, str) for n, t in group.items()):
            raise RuleBundleError(f"bad {kind} section")
    return bundle


class RuleStore:
    def __init__(self, directory: Path, public_key_b64: str):
        self._path = Path(directory) / "bundle.json"
        self._key = public_key_b64

    def load(self) -> Optional[Dict[str, Any]]:
        try:
            stored = json.loads(self._path.read_text(encoding="utf-8"))
            return verify(stored["bundle"], stored["signature"], self._key)
        except FileNotFoundError:
            return None
        except (RuleBundleError, ValueError, KeyError, TypeError, OSError) as exc:
            logger.warning("Rules: stored bundle ignored: %s", exc)
            return None

    def accept(self, bundle_text: str, signature: str, current_version: int = 0) -> Dict[str, Any]:
        bundle = verify(bundle_text, signature, self._key)
        if bundle["version"] <= current_version:
            raise RuleBundleError(f"bundle v{bundle['version']} is not newer than v{current_version} — refused")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"bundle": bundle_text, "signature": signature}), encoding="utf-8")
        tmp.replace(self._path)
        return bundle
