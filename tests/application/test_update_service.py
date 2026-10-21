"""Auto-update: only manifests signed by the pinned key are accepted; downloads must match sha256/size."""
import base64
import dataclasses
import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from application.services.update_service import (UpdateError, UpdateInfo, UpdateService, current_arch,
                                                 current_os, parse_version, verify_manifest)
from core.config import AppConfig, BackendConfig

INSTALLER = b"pretend-installer-bytes" * 100


def keypair():
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, base64.b64encode(raw).decode()


def signed(key, **overrides):
    manifest = {"version": "0.2.0", "os": current_os(), "arch": current_arch(), "channel": "stable",
                "url": "https://downloads.example.com/Cybrix-0.2.0.bin",
                "sha256": hashlib.sha256(INSTALLER).hexdigest(), "size": len(INSTALLER),
                "min_supported": "", "notes": "Better things", **overrides}
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return {"manifest": text, "signature": base64.b64encode(key.sign(text.encode())).decode(),
            "version": manifest["version"]}


def service(public_key, version="0.1.0"):
    config = AppConfig(version=version, update_public_key=public_key,
                       backend=BackendConfig(base_url="https://cybrix.example.com"))
    return UpdateService(config)


def client_returning(payload, installer=INSTALLER, status=200):
    def handler(request: httpx.Request):
        if request.url.path.endswith("/releases/latest/"):
            assert request.url.params["os"] == current_os()
            return httpx.Response(200, json={"success": True, "data": payload})
        return httpx.Response(status, content=installer)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_semver_ordering():
    assert parse_version("0.10.0") > parse_version("0.9.9")
    assert parse_version("0.2.0") > parse_version("0.2.0-beta.1")
    assert parse_version("garbage") < parse_version("0.0.1")


async def test_newer_signed_release_is_offered():
    key, public = keypair()
    info = await service(public).check(client=client_returning(signed(key)))
    assert info.version == "0.2.0" and not info.mandatory


async def test_same_or_older_version_is_not_offered():
    key, public = keypair()
    assert await service(public, version="0.2.0").check(client=client_returning(signed(key))) is None


async def test_min_supported_marks_update_mandatory():
    key, public = keypair()
    info = await service(public).check(client=client_returning(signed(key, min_supported="0.1.5")))
    assert info.mandatory


async def test_manifest_signed_by_another_key_is_refused():
    key, _ = keypair()
    _, other_public = keypair()
    with pytest.raises(UpdateError, match="signature"):
        await service(other_public).check(client=client_returning(signed(key)))


async def test_tampered_manifest_is_refused():
    key, public = keypair()
    payload = signed(key)
    payload["manifest"] = payload["manifest"].replace("downloads.example.com", "evil.example.com")
    with pytest.raises(UpdateError):
        await service(public).check(client=client_returning(payload))


async def test_build_without_pinned_key_never_updates():
    key, _ = keypair()
    with pytest.raises(UpdateError, match="no update key"):
        await service("").check(client=client_returning(signed(key)))


def test_http_installer_url_is_refused():
    key, public = keypair()
    payload = signed(key, url="http://downloads.example.com/x.bin")
    with pytest.raises(UpdateError, match="https"):
        verify_manifest(payload["manifest"], payload["signature"], public)


async def test_no_release_published():
    _, public = keypair()
    assert await service(public).check(client=client_returning({})) is None


async def test_download_verifies_checksum(tmp_path):
    key, public = keypair()
    svc = service(public)
    info = await svc.check(client=client_returning(signed(key)))
    seen = []
    path = await svc.download(info, tmp_path, progress=lambda got, total: seen.append(got),
                              client=client_returning({}, installer=INSTALLER))
    assert path.read_bytes() == INSTALLER and seen[-1] == len(INSTALLER)


async def test_download_with_wrong_bytes_is_deleted(tmp_path):
    key, public = keypair()
    svc = service(public)
    info = await svc.check(client=client_returning(signed(key)))
    swapped = b"X" * len(INSTALLER)
    with pytest.raises(UpdateError, match="checksum"):
        await svc.download(info, tmp_path, client=client_returning({}, installer=swapped))
    assert list(tmp_path.iterdir()) == []


async def test_download_larger_than_signed_size_stops(tmp_path):
    key, public = keypair()
    svc = service(public)
    info = dataclasses.replace(await svc.check(client=client_returning(signed(key))), size=10)
    with pytest.raises(UpdateError, match="larger"):
        await svc.download(info, tmp_path, client=client_returning({}, installer=INSTALLER))
    assert list(tmp_path.iterdir()) == []


def test_update_info_is_immutable():
    info = UpdateInfo("1.0.0", "https://x/y", "a" * 64, 1, "", False, "stable")
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.version = "2.0.0"
