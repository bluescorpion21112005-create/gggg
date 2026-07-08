"""Typed configuration management.

Loads from YAML and environment variables, merging into a frozen configuration object.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Literal, Union

import yaml

from core.exceptions import ConfigurationError


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
class AppConfig:
    name: str = "Cybrix AI"
    version: str = "0.1.0"
    default_model: str = "llama3"
    ai_providers: dict[str, AIProviderConfig] = field(default_factory=dict)
    ui: UIConfig = field(default_factory=UIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    gpu: GPUConfig = field(default_factory=GPUConfig)
    database_url: str = "sqlite:///cybrix.db"
    plugins_dir: str = "plugins"


class ConfigLoader:
    """Loads configuration from YAML file and environment variables."""

    DEFAULT_CONFIG_PATH = Path(os.getenv('CYBRIX_CONFIG_DIR', 'config')) / 'settings.yaml'

    @classmethod
    def load(cls, config_path: Optional[Union[str, Path]] = None) -> AppConfig:
        if config_path is None:
            config_path = cls.DEFAULT_CONFIG_PATH
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
        return cls._parse_config(raw)

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

        app_section = raw.get("app", {})

        return AppConfig(
            name=raw.get("name", app_section.get("name", "Cybrix AI")),
            version=raw.get("version", app_section.get("version", "0.1.0")),
            default_model=raw.get("default_model", "llama3"),
            ai_providers=ai_providers,
            ui=ui,
            logging=logging_conf,
            gpu=gpu,
            database_url=raw.get("database_url", "sqlite:///cybrix.db"),
            plugins_dir=raw.get("plugins_dir", "plugins"),
        )