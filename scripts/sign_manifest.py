#!/usr/bin/env python
"""Sign update manifests for the installers in dist/ (Ed25519, offline / in CI).

Produces <installer>.release.json = {"manifest": <canonical json>, "signature": <base64>} — the same
format as `manage.py sign_release --output` on the server side, to be imported there with
`manage.py sign_release --import <file>`. The canonical form MUST stay identical to
cybrix_ai/desktop_agent/releases.py (sorted keys, no whitespace, these fields).

  python scripts/sign_manifest.py --key release.pem --base-url https://downloads.example.com/cybrix \\
      --version 0.2.0 --os linux --channel stable [--min-supported 0.1.0] [--notes "…"] dist
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
from pathlib import Path

FIELDS = ("version", "os", "arch", "channel", "url", "sha256", "size", "min_supported", "notes")
PATTERNS = {"linux": "*.AppImage", "windows": "Cybrix-Setup-*.exe", "macos": "*.dmg"}


def canonical(manifest: dict) -> bytes:
    return json.dumps({k: manifest[k] for k in FIELDS}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dist", type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--os", required=True, choices=sorted(PATTERNS))
    parser.add_argument("--channel", default="stable", choices=("stable", "beta"))
    parser.add_argument("--arch", default="arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64")
    parser.add_argument("--min-supported", default="")
    parser.add_argument("--notes", default="")
    args = parser.parse_args()
    if not args.base_url.startswith("https://"):
        parser.error("--base-url must be https")

    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    installers = sorted(args.dist.glob(PATTERNS[args.os]))
    if not installers:
        parser.error(f"no {PATTERNS[args.os]} in {args.dist}")
    for installer in installers:
        data = installer.read_bytes()
        manifest = {"version": args.version, "os": args.os, "arch": args.arch, "channel": args.channel,
                    "url": f"{args.base_url.rstrip('/')}/{installer.name}",
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                    "min_supported": args.min_supported, "notes": args.notes[:4000]}
        body = canonical(manifest)
        out = installer.with_name(installer.name + ".release.json")
        out.write_text(json.dumps({"manifest": body.decode("utf-8"),
                                   "signature": base64.b64encode(key.sign(body)).decode()}, indent=2))
        print(f"signed {installer.name} → {out.name}")


if __name__ == "__main__":
    main()
