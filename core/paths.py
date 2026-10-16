"""Where the desktop app keeps its files, per OS (never inside the install directory).

    Linux   ~/.config/Cybrix   ~/.local/share/Cybrix   ~/.local/state/Cybrix/log   ~/.cache/Cybrix
    macOS   ~/Library/Application Support/Cybrix (config+data)   ~/Library/Logs/Cybrix   ~/Library/Caches/Cybrix
    Windows %LOCALAPPDATA%\\Cybrix\\...   (config, data, Logs, Cache)

CYBRIX_HOME=<dir> puts everything under one directory (portable installs, tests, CI).
The read-only defaults shipped with the app (config/settings.yaml, plugins, themes) are found with
bundle_dir(): the PyInstaller _MEIPASS directory when frozen, the source tree otherwise.
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

APP_NAME = "Cybrix"
logger = logging.getLogger(__name__)


def bundle_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _home() -> Path | None:
    value = os.getenv("CYBRIX_HOME", "").strip()
    return Path(value).expanduser() if value else None


def _ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_dir() -> Path:
    if (home := _home()) is not None:
        return _ensure(home / "config")
    import platformdirs

    return _ensure(Path(platformdirs.user_config_dir(APP_NAME, appauthor=False)))


def data_dir() -> Path:
    if (home := _home()) is not None:
        return _ensure(home / "data")
    import platformdirs

    return _ensure(Path(platformdirs.user_data_dir(APP_NAME, appauthor=False)))


def log_dir() -> Path:
    if (home := _home()) is not None:
        return _ensure(home / "logs")
    import platformdirs

    return _ensure(Path(platformdirs.user_log_dir(APP_NAME, appauthor=False)))


def cache_dir() -> Path:
    if (home := _home()) is not None:
        return _ensure(home / "cache")
    import platformdirs

    return _ensure(Path(platformdirs.user_cache_dir(APP_NAME, appauthor=False)))


def user_settings_path() -> Path:
    """The editable settings.yaml; seeded from the bundled default on first run."""
    target = config_dir() / "settings.yaml"
    if not target.exists():
        default = bundle_dir() / "config" / "settings.yaml"
        if default.exists():
            shutil.copyfile(default, target)
            logger.info("seeded %s from %s", target, default)
    return target


def resolve_in(base: Path, value: str) -> Path:
    """Relative paths from settings are relative to *base*, absolute/~ paths are kept."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def migrate_legacy_file(name: str, target: Path) -> None:
    """Copy a file the old builds kept in the working directory (cybrix.db) to its new home once."""
    legacy = Path.cwd() / name
    if legacy.exists() and not target.exists() and legacy.resolve() != target.resolve():
        try:
            shutil.copy2(legacy, target)
            logger.info("migrated %s → %s (the old file is kept)", legacy, target)
        except OSError as exc:
            logger.warning("could not migrate %s: %s", legacy, exc)
