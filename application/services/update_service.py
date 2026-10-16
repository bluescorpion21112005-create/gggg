"""Auto-update: signed manifest → download → sha256 check → install with the user's consent.

The server answers GET /api/v1/desktop/releases/latest/?os=&arch=&channel= with the exact bytes of a
manifest signed offline with Ed25519. This app accepts it only if the signature verifies against
the public key pinned in its own settings (updates.public_key); the server cannot forge one. The
installer must then match the manifest's sha256 and size before anything runs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from injector import inject

from core.config import AppConfig

logger = logging.getLogger(__name__)
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


class UpdateError(Exception):
    pass


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    url: str
    sha256: str
    size: int
    notes: str
    mandatory: bool       # the running version is older than min_supported
    channel: str


def parse_version(value: str) -> tuple:
    """Semver key: pre-releases sort before the release (0.2.0-beta.1 < 0.2.0)."""
    m = SEMVER_RE.match(value or "")
    if not m:
        return (0, 0, 0, 0, "")
    major, minor, patch, pre = int(m[1]), int(m[2]), int(m[3]), m[4]
    return (major, minor, patch, 0 if pre else 1, pre or "")


def current_os() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def current_arch() -> str:
    return "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"


def verify_manifest(manifest_text: str, signature_b64: str, public_key_b64: str) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not public_key_b64:
        raise UpdateError("This build has no update key; updates are disabled.")
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature_b64), manifest_text.encode("utf-8"))
    except (InvalidSignature, ValueError) as exc:
        raise UpdateError("The update manifest signature is invalid — update refused.") from exc
    data = json.loads(manifest_text)
    if not str(data.get("url", "")).startswith("https://"):
        raise UpdateError("Update URL must be https.")
    if not re.fullmatch(r"[0-9a-f]{64}", str(data.get("sha256", ""))):
        raise UpdateError("Manifest has no valid sha256.")
    return data


class UpdateService:
    @inject
    def __init__(self, config: AppConfig):
        self._config = config

    @property
    def current_version(self) -> str:
        return self._config.version

    async def check(self, channel: str = "stable", client=None) -> Optional[UpdateInfo]:
        """Newer release for this OS/arch/channel, or None. Raises UpdateError on a bad manifest."""
        import httpx

        params = {"os": current_os(), "arch": current_arch(), "channel": channel}
        url = self._config.backend.api_url + "/releases/latest/"
        own = client is None
        client = client or httpx.AsyncClient(timeout=15, verify=self._config.backend.verify_tls)
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = (resp.json() or {}).get("data") or {}
        except (httpx.HTTPError, ValueError) as exc:
            raise UpdateError(f"Could not reach the update server: {type(exc).__name__}") from exc
        finally:
            if own:
                await client.aclose()
        if not data.get("manifest"):
            return None
        manifest = verify_manifest(data["manifest"], data.get("signature", ""), self._config.update_public_key)
        if (manifest.get("os"), manifest.get("arch")) != (params["os"], params["arch"]):
            raise UpdateError("Manifest is for a different platform.")
        if parse_version(manifest["version"]) <= parse_version(self.current_version):
            return None
        minimum = manifest.get("min_supported") or ""
        return UpdateInfo(version=manifest["version"], url=manifest["url"], sha256=manifest["sha256"],
                          size=int(manifest["size"]), notes=manifest.get("notes", ""),
                          mandatory=bool(minimum) and parse_version(self.current_version) < parse_version(minimum),
                          channel=manifest.get("channel", channel))

    async def download(self, info: UpdateInfo, dest_dir: Path,
                       progress: Optional[Callable[[int, int], None]] = None, client=None) -> Path:
        """Stream the installer to dest_dir; it is only renamed into place after sha256/size match."""
        import httpx

        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9._-]", "_", info.url.rsplit("/", 1)[-1]) or f"cybrix-{info.version}"
        final, part = dest_dir / name, dest_dir / (name + ".part")
        digest, received = hashlib.sha256(), 0
        own = client is None
        client = client or httpx.AsyncClient(timeout=60, follow_redirects=True)
        try:
            async with client.stream("GET", info.url) as resp:
                resp.raise_for_status()
                with part.open("wb") as fh:
                    async for chunk in resp.aiter_bytes(1 << 16):
                        received += len(chunk)
                        if received > info.size:
                            raise UpdateError("Download is larger than the signed size — refused.")
                        digest.update(chunk)
                        fh.write(chunk)
                        if progress:
                            progress(received, info.size)
        except httpx.HTTPError as exc:
            part.unlink(missing_ok=True)
            raise UpdateError(f"Download failed: {type(exc).__name__}") from exc
        except UpdateError:
            part.unlink(missing_ok=True)
            raise
        finally:
            if own:
                await client.aclose()
        if received != info.size or digest.hexdigest() != info.sha256:
            part.unlink(missing_ok=True)
            raise UpdateError("Downloaded file does not match the signed checksum — refused.")
        os.replace(part, final)
        return final

    @staticmethod
    def install(installer: Path) -> str:
        """Hand the verified installer to the OS. Returns what happened, for the UI."""
        installer = Path(installer)
        appimage = os.environ.get("APPIMAGE")
        if current_os() == "linux" and appimage and installer.suffix.lower() == ".appimage":
            import shutil

            installer.chmod(0o755)
            tmp = Path(appimage).with_suffix(".new")
            shutil.copyfile(installer, tmp)          # copy: the download may be on another filesystem
            tmp.chmod(0o755)
            os.replace(tmp, appimage)                # atomic on the AppImage's own filesystem
            return "replaced"
        if current_os() == "windows":
            os.startfile(str(installer))  # noqa: S606 — verified installer, user consented
            return "launched"
        opener = "open" if current_os() == "macos" else "xdg-open"
        subprocess.Popen([opener, str(installer)])  # noqa: S603 — fixed argv, verified file
        return "opened"
