"""Crash handling for the desktop app.

* Always: uncaught exceptions (main thread and worker threads) and hard crashes (faulthandler:
  segfaults in Qt/native code) are written to <log_dir>/crash.log.
* Only with the user's consent (Settings → Diagnostics, default off) and a configured DSN:
  the same exceptions go to Sentry, with no PII, no local variables and the home path masked.
* export_diagnostics() bundles logs + system info into a ZIP the user can attach to feedback.
  Secrets are never included — the device token and API keys live in the OS keyring.
"""
from __future__ import annotations

import faulthandler
import json
import logging
import os
import platform
import re
import sys
import threading
import time
import traceback
import zipfile
from pathlib import Path

from core import paths

logger = logging.getLogger("cybrix.crash")
_fault_file = None
_HOME_RE = re.compile(re.escape(str(Path.home())), re.I)


def crash_log_path() -> Path:
    return paths.log_dir() / "crash.log"


def _write_crash(text: str) -> None:
    try:
        with crash_log_path().open("a", encoding="utf-8") as fh:
            fh.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n{text}\n")
    except OSError:
        pass


def _excepthook(exc_type, exc, tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    text = "".join(traceback.format_exception(exc_type, exc, tb))
    logger.critical("uncaught exception\n%s", text)
    _write_crash(text)
    try:
        import sentry_sdk

        if sentry_sdk.get_client().is_active():
            sentry_sdk.capture_exception(exc)
    except Exception:  # noqa: BLE001
        pass


def _thread_excepthook(args):
    if args.exc_type is SystemExit:
        return
    _excepthook(args.exc_type, args.exc_value, args.exc_traceback)


def install(version: str = "", sentry_dsn: str = "", consent: bool = False) -> bool:
    """Install the hooks; returns True when Sentry reporting was enabled."""
    global _fault_file
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
    try:
        _fault_file = crash_log_path().open("a", encoding="utf-8")
        faulthandler.enable(file=_fault_file, all_threads=True)
    except OSError as exc:
        logger.warning("faulthandler not enabled: %s", exc)
    if not (consent and sentry_dsn):
        return False
    try:
        import sentry_sdk

        sentry_sdk.init(
            dsn=sentry_dsn,
            release=f"cybrix-desktop@{version}" if version else None,
            environment="frozen" if paths.is_frozen() else "source",
            send_default_pii=False,
            include_local_variables=False,
            traces_sample_rate=0.0,
            before_send=_scrub_event,
        )
        logger.info("crash reports enabled (user consent)")
        return True
    except Exception as exc:  # noqa: BLE001 — reporting must never stop the app
        logger.warning("Sentry init failed: %s", exc)
        return False


def _mask(text: str) -> str:
    return _HOME_RE.sub("~", text)


def _scrub_event(event, hint):
    event.pop("user", None)
    event.pop("server_name", None)  # the hostname often contains the user's name
    for exc in (event.get("exception") or {}).get("values", []):
        for frame in (exc.get("stacktrace") or {}).get("frames", []):
            for key in ("abs_path", "filename"):
                if isinstance(frame.get(key), str):
                    frame[key] = _mask(frame[key])
            frame.pop("vars", None)
        if isinstance(exc.get("value"), str):
            exc["value"] = _mask(exc["value"])
    for crumb in (event.get("breadcrumbs") or {}).get("values", []):
        if isinstance(crumb.get("message"), str):
            crumb["message"] = _mask(crumb["message"])
    return event


def system_info(version: str = "") -> dict:
    return {
        "app_version": version,
        "frozen": paths.is_frozen(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "qt": _qt_version(),
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


def _qt_version() -> str:
    try:
        from PySide6 import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return "?"


MAX_FILE_BYTES = 5 * 1024 * 1024


def export_diagnostics(dest: Path, version: str = "", data_dir: Path | None = None) -> Path:
    """Write a ZIP with logs (last 5 MB each), crash log, system info and non-secret agent settings."""
    dest = Path(dest)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("system.json", json.dumps(system_info(version), indent=2))
        for log in sorted(paths.log_dir().glob("*.log*")):
            try:
                size = log.stat().st_size
                with log.open("rb") as fh:
                    if size > MAX_FILE_BYTES:
                        fh.seek(size - MAX_FILE_BYTES)
                    zf.writestr(f"logs/{log.name}", _mask(fh.read().decode("utf-8", "replace")))
            except OSError:
                continue
        settings = (data_dir or Path(os.path.expanduser("~/.cybrix"))) / "agent_settings.json"
        if settings.exists():
            try:
                data = json.loads(settings.read_text(encoding="utf-8"))
                zf.writestr("agent_settings.json", json.dumps(data, indent=2))
            except (OSError, ValueError):
                pass
    return dest
