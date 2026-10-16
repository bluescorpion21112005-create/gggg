"""Typed configuration management.

Loads from YAML and environment variables, merging into a frozen configuration object.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Literal, Union

import yaml



@dataclass(frozen=True)
class AIProviderConfig:
    provider: str  # "ollama" or "fireworks"
    enabled: bool
    model: str
    host: Optional[str] = None
    api_key_env: Optional[str] = None  # name of environment variable holding API key


@dataclass(frozen=True)
class UIConfig:
    theme: Literal["dark", "light"] = "dark"
    language: str = "en"


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: Optional[str] = "cybrix.log"


@dataclass(frozen=True)
class GPUConfig:
    prefer_rocm: bool = True
    fallback_to_cpu: bool = True


@dataclass(frozen=True)
class BackendConfig:
    """Connection to the Cybrix Django server (REST + WebSocket)."""
    base_url: str = "http://127.0.0.1:8000"
    ws_path: str = "/ws/desktop/"
    verify_tls: bool = True
    request_timeout: float = 15.0
    heartbeat_interval: float = 25.0
    reconnect_max_delay: float = 60.0
    accept_remote_commands: bool = True
    # File-based remote commands (log/malware analysis) may only touch files under these dirs.
    command_allowed_dirs: tuple[str, ...] = ()
    # "ask" (confirm each command), "allow_listed" (only types the user allowed permanently), "deny_all"
    command_policy: str = "ask"
    approval_timeout: float = 60.0
    share_telemetry: bool = True
    telemetry_interval: float = 5.0
    # Network connections (remote IP/port/process) for threat matching — opt-in only.
    share_network_flows: bool = False
    netflow_interval: float = 60.0
    # SHA-256 + file name of running programs for known-malware matching — opt-in only.
    share_process_hashes: bool = False
    # Rotate the device token when fewer than this many days remain.
    token_refresh_days: int = 7
    # Sending the device token over plain http/ws to a non-local host is refused unless enabled.
    allow_insecure: bool = False
    # install_id, approvals, agent settings and the agent audit log live here.
    data_dir: str = "~/.cybrix"

    @property
    def api_url(self) -> str:
        return self.base_url.rstrip("/") + "/api/v1/desktop"

    @property
    def ws_url(self) -> str:
        base = self.base_url.rstrip("/")
        if base.startswith("https://"):
            base = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            base = "ws://" + base[len("http://"):]
        return base + self.ws_path

    @property
    def is_secure_transport(self) -> bool:
        from urllib.parse import urlsplit

        parts = urlsplit(self.base_url)
        return parts.scheme == "https" or (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).expanduser()


@dataclass(frozen=True)
class AppConfig:
    name: str = "Cybrix AI"
    version: str = "0.1.0"
    default_model: str = "llama3"
    ai_providers: dict[str, AIProviderConfig] = field(default_factory=dict)
    ui: UIConfig = field(default_factory=UIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    gpu: GPUConfig = field(default_factory=GPUConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    database_url: str = "sqlite:///cybrix.db"
    plugins_dir: str = "plugins"
    # Crash reports go here only if the user opts in (Settings → Diagnostics). Baked in by the build.
    sentry_dsn: str = ""
    # Ed25519 public key (base64) that signs update manifests; pinned in the shipped settings.yaml.
    update_public_key: str = ""


class ConfigLoader:
    """Loads configuration from YAML file and environment variables."""

    @staticmethod
    def default_path() -> Path:
        """CYBRIX_CONFIG_DIR (dev/tests) or the per-user settings.yaml seeded from the bundle."""
        if os.getenv("CYBRIX_CONFIG_DIR"):
            return Path(os.environ["CYBRIX_CONFIG_DIR"]) / "settings.yaml"
        from core.paths import user_settings_path

        return user_settings_path()

    @classmethod
    def load(cls, config_path: Optional[Union[str, Path]] = None, resolve_paths: bool = True) -> AppConfig:
        if config_path is None:
            config_path = cls.default_path()
        else:
            config_path = Path(config_path)

        if not config_path.exists():
            # Use built-in defaults if no file exists
            raw = {}
        else:
            with open(config_path, "r") as f:
                raw = yaml.safe_load(f) or {}

        # Override with environment variables where applicable
        raw = cls._merge_env(raw)
        if resolve_paths:
            raw = cls._resolve_paths(raw)
        return cls._parse_config(raw)

    @staticmethod
    def _resolve_paths(raw: dict) -> dict:
        """Relative paths in settings → per-user OS directories (DB, logs) or the bundle (plugins).

        Without this a packaged app would write cybrix.db / cybrix.log into whatever directory it was
        started from (often read-only, e.g. Program Files or a mounted DMG).
        """
        from core import paths

        url = raw.get("database_url", "sqlite:///cybrix.db")
        if url.startswith("sqlite:///") and not Path(url[len("sqlite:///"):]).expanduser().is_absolute():
            name = url[len("sqlite:///"):]
            target = paths.resolve_in(paths.data_dir(), name)
            paths.migrate_legacy_file(name, target)
            raw["database_url"] = f"sqlite:///{target}"
        log = raw.setdefault("logging", {})
        if log.get("file", "cybrix.log"):
            log["file"] = str(paths.resolve_in(paths.log_dir(), log.get("file", "cybrix.log")))
        raw["plugins_dir"] = str(paths.resolve_in(paths.bundle_dir(), raw.get("plugins_dir", "plugins")))
        return raw

    @classmethod
    def _merge_env(cls, raw: dict) -> dict:
        # Database URL
        if os.getenv("DATABASE_URL"):
            raw["database_url"] = os.getenv("DATABASE_URL")

        # AI providers: allow enabling via env
        ai_providers = raw.get("ai_providers", {})
        for prov_name, prov_conf in ai_providers.items():
            if os.getenv(f"CYBRIX_{prov_name.upper()}_ENABLED"):
                prov_conf["enabled"] = os.getenv(f"CYBRIX_{prov_name.upper()}_ENABLED").lower() == "true"
            if api_key_env := prov_conf.get("api_key_env"):
                prov_conf["api_key_env"] = api_key_env  # keep as is, used later
        # Backend server URL override
        if os.getenv("CYBRIX_SERVER_URL"):
            raw.setdefault("backend", {})["base_url"] = os.getenv("CYBRIX_SERVER_URL")
        if os.getenv("CYBRIX_DATA_DIR"):
            raw.setdefault("backend", {})["data_dir"] = os.getenv("CYBRIX_DATA_DIR")
        # UI theme override
        if os.getenv("CYBRIX_THEME"):
            raw.setdefault("ui", {})["theme"] = os.getenv("CYBRIX_THEME")
        return raw

    @classmethod
    def _parse_config(cls, raw: dict) -> AppConfig:
        # Parse AI providers
        ai_providers = {}
        for prov_name, prov_dict in raw.get("ai_providers", {}).items():
            ai_providers[prov_name] = AIProviderConfig(
                provider=prov_name,
                enabled=prov_dict.get("enabled", False),
                model=prov_dict.get("model", "llama3"),
                host=prov_dict.get("host"),
                api_key_env=prov_dict.get("api_key_env"),
            )

        ui = UIConfig(
            theme=raw.get("ui", {}).get("theme", "dark"),
            language=raw.get("ui", {}).get("language", "en"),
        )

        logging_conf = LoggingConfig(
            level=raw.get("logging", {}).get("level", "INFO"),
            file=raw.get("logging", {}).get("file", "cybrix.log"),
        )

        gpu = GPUConfig(
            prefer_rocm=raw.get("gpu", {}).get("prefer_rocm", True),
            fallback_to_cpu=raw.get("gpu", {}).get("fallback_to_cpu", True),
        )

        backend_raw = raw.get("backend", {}) or {}
        backend = BackendConfig(
            base_url=backend_raw.get("base_url", BackendConfig.base_url),
            ws_path=backend_raw.get("ws_path", BackendConfig.ws_path),
            verify_tls=backend_raw.get("verify_tls", True),
            request_timeout=float(backend_raw.get("request_timeout", BackendConfig.request_timeout)),
            heartbeat_interval=float(backend_raw.get("heartbeat_interval", BackendConfig.heartbeat_interval)),
            reconnect_max_delay=float(backend_raw.get("reconnect_max_delay", BackendConfig.reconnect_max_delay)),
            accept_remote_commands=backend_raw.get("accept_remote_commands", True),
            command_allowed_dirs=tuple(backend_raw.get("command_allowed_dirs", ()) or ()),
            command_policy=str(backend_raw.get("command_policy", BackendConfig.command_policy)),
            approval_timeout=float(backend_raw.get("approval_timeout", BackendConfig.approval_timeout)),
            share_telemetry=bool(backend_raw.get("share_telemetry", True)),
            telemetry_interval=float(backend_raw.get("telemetry_interval", BackendConfig.telemetry_interval)),
            share_network_flows=bool(backend_raw.get("share_network_flows", False)),
            netflow_interval=float(backend_raw.get("netflow_interval", BackendConfig.netflow_interval)),
            share_process_hashes=bool(backend_raw.get("share_process_hashes", False)),
            token_refresh_days=int(backend_raw.get("token_refresh_days", BackendConfig.token_refresh_days)),
            allow_insecure=bool(backend_raw.get("allow_insecure", False)),
            data_dir=str(backend_raw.get("data_dir", BackendConfig.data_dir)),
        )

        app_section = raw.get("app", {})

        return AppConfig(
            name=raw.get("name", app_section.get("name", "Cybrix AI")),
            version=raw.get("version", app_section.get("version", "0.1.0")),
            default_model=raw.get("default_model", "llama3"),
            ai_providers=ai_providers,
            ui=ui,
            logging=logging_conf,
            gpu=gpu,
            backend=backend,
            database_url=raw.get("database_url", "sqlite:///cybrix.db"),
            plugins_dir=raw.get("plugins_dir", "plugins"),
            sentry_dsn=os.getenv("CYBRIX_SENTRY_DSN") or (raw.get("diagnostics") or {}).get("sentry_dsn", "") or "",
            update_public_key=(raw.get("updates") or {}).get("public_key", "") or "",
        )