"""Small persistent per-installation state for the desktop agent (JSON in backend.data_dir).

Holds the install_id, command types the user allowed permanently, and UI overrides of the
telemetry/command-policy defaults from settings.yaml. Never holds secrets (those are in keyring).
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

from core.config import AppConfig

logger = logging.getLogger(__name__)

POLICIES = ("ask", "allow_listed", "deny_all")


class AgentSettings:
    FILE_NAME = "agent_settings.json"

    def __init__(self, config: AppConfig):
        self._defaults = config.backend
        self._path: Path = config.backend.data_path / self.FILE_NAME
        self._data: Dict[str, Any] = self._load()
        if not self._data.get("install_id"):
            self._data["install_id"] = str(uuid.uuid4())
            self._save()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> Dict[str, Any]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            logger.warning("AgentSettings: unreadable %s (%s); starting fresh", self._path, exc)
            return {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic replace so a crash never leaves a half-written file.
            fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".agent_settings.")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
            os.replace(tmp, self._path)
        except OSError as exc:
            logger.warning("AgentSettings: could not save %s: %s", self._path, exc)

    # ── Values ────────────────────────────────────────────────────────────────

    @property
    def install_id(self) -> str:
        return self._data["install_id"]

    @property
    def command_policy(self) -> str:
        policy = self._data.get("command_policy", self._defaults.command_policy)
        return policy if policy in POLICIES else "ask"

    @command_policy.setter
    def command_policy(self, value: str) -> None:
        if value not in POLICIES:
            raise ValueError(f"Unknown command policy: {value}")
        self._data["command_policy"] = value
        self._save()

    @property
    def share_telemetry(self) -> bool:
        return bool(self._data.get("share_telemetry", self._defaults.share_telemetry))

    @share_telemetry.setter
    def share_telemetry(self, value: bool) -> None:
        self._data["share_telemetry"] = bool(value)
        self._save()

    @property
    def share_network_flows(self) -> bool:
        return bool(self._data.get("share_network_flows", self._defaults.share_network_flows))

    @share_network_flows.setter
    def share_network_flows(self, value: bool) -> None:
        self._data["share_network_flows"] = bool(value)
        self._save()

    @property
    def share_process_hashes(self) -> bool:
        return bool(self._data.get("share_process_hashes", self._defaults.share_process_hashes))

    @share_process_hashes.setter
    def share_process_hashes(self, value: bool) -> None:
        self._data["share_process_hashes"] = bool(value)
        self._save()

    @property
    def always_allowed(self) -> frozenset[str]:
        return frozenset(self._data.get("always_allowed", []))

    def allow_always(self, command_type: str) -> None:
        allowed = set(self._data.get("always_allowed", []))
        allowed.add(command_type)
        self._data["always_allowed"] = sorted(allowed)
        self._save()

    def clear_always_allowed(self) -> None:
        self._data["always_allowed"] = []
        self._save()

    # ── User preferences set from the UI (applied to the config at the next start) ──

    PREF_KEYS = ("server_url", "theme", "language", "ollama_host", "crash_reports", "update_channel",
                 "onboarding_done")

    def get_pref(self, key: str, default: Any = None) -> Any:
        if key not in self.PREF_KEYS:
            raise KeyError(key)
        return self._data.get(key, default)

    def set_pref(self, key: str, value: Any) -> None:
        if key not in self.PREF_KEYS:
            raise KeyError(key)
        if key == "server_url":
            value = validate_server_url(value)
        elif key == "theme" and value not in ("dark", "light"):
            raise ValueError(f"Unknown theme: {value}")
        elif key == "language" and value not in LANGUAGES:
            raise ValueError(f"Unsupported language: {value}")
        elif key == "update_channel" and value not in ("stable", "beta"):
            raise ValueError(f"Unknown update channel: {value}")
        elif key in ("crash_reports", "onboarding_done"):
            value = bool(value)
        self._data[key] = value
        self._save()

    @property
    def onboarding_done(self) -> bool:
        return bool(self._data.get("onboarding_done", False))

    @property
    def crash_reports(self) -> bool:
        return bool(self._data.get("crash_reports", False))  # opt-in

    @property
    def update_channel(self) -> str:
        return self._data.get("update_channel", "stable")


LANGUAGES = ("en", "ru", "uz")


def validate_server_url(value: str) -> str:
    """https:// only; plain http is allowed for this machine (development server)."""
    from urllib.parse import urlsplit

    value = (value or "").strip().rstrip("/")
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
        raise ValueError("Enter the server address, e.g. https://cybrix.example.com")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("Use only the server address, without a path")
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("The server must use https:// (http is only allowed for localhost)")
    return value


def apply_user_overrides(config: AppConfig) -> AppConfig:
    """Return *config* with the preferences saved from the UI (agent_settings.json) applied."""
    import dataclasses

    path = config.backend.data_path / AgentSettings.FILE_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return config
    if not isinstance(data, dict):
        return config
    backend, ui, providers = config.backend, config.ui, dict(config.ai_providers)
    try:
        if data.get("server_url") and not os.getenv("CYBRIX_SERVER_URL"):  # env wins (tests, CI)
            backend = dataclasses.replace(backend, base_url=validate_server_url(data["server_url"]))
    except ValueError:
        logger.warning("ignoring invalid saved server_url")
    if data.get("theme") in ("dark", "light") and not os.getenv("CYBRIX_THEME"):
        ui = dataclasses.replace(ui, theme=data["theme"])
    if data.get("language") in LANGUAGES:
        ui = dataclasses.replace(ui, language=data["language"])
    if isinstance(data.get("ollama_host"), str) and data["ollama_host"].startswith(("http://", "https://")) \
            and "ollama" in providers:
        providers["ollama"] = dataclasses.replace(providers["ollama"], host=data["ollama_host"].rstrip("/"))
    return dataclasses.replace(config, backend=backend, ui=ui, ai_providers=providers)
