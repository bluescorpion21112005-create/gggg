"""ViewModel for Settings window.

Communicates with infrastructure only through injected services.
No direct infrastructure imports in this file.
"""
import asyncio
import logging
from pathlib import Path

from PySide6.QtCore import Signal, Property, Slot
from PySide6.QtWidgets import QApplication
from injector import inject
from qasync import asyncSlot

from application.services.update_service import UpdateError, UpdateInfo, UpdateService
from core import crash, paths
from core.config import AppConfig
from infrastructure.remote.agent_settings import LANGUAGES, AgentSettings
from infrastructure.security.vault import Vault
from presentation.theme.theme_manager import ThemeManager
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class SettingsViewModel(BaseViewModel):
    theme_changed = Signal(str)
    config_updated = Signal()
    restart_required = Signal(str)        # what changed and only applies after a restart
    update_available = Signal(dict)       # {version, notes, mandatory, size}
    update_progress = Signal(int, int)    # received, total bytes
    update_ready = Signal(str)            # path of the verified installer
    gpu_info_ready = Signal(dict)         # core.accelerator.info()
    benchmark_ready = Signal(dict)        # {gpu_tflops, cpu_tflops}

    LANGUAGES = LANGUAGES

    @inject
    def __init__(self, app_config: AppConfig, settings: AgentSettings, updates: UpdateService):
        super().__init__()
        self._config = app_config
        self._settings = settings
        self._updates = updates
        self._pending: UpdateInfo | None = None

    @Property(str, notify=theme_changed)
    def current_theme(self) -> str:
        return self._config.ui.theme

    @Slot(str)
    def set_theme(self, theme: str):
        """Apply theme immediately; config persistence requires restart."""
        if theme not in ("dark", "light"):
            self.error_occurred.emit(f"Unknown theme: {theme}")
            return
        app = QApplication.instance()
        if app:
            ThemeManager.apply_theme(app, theme)
            self.theme_changed.emit(theme)
            logger.info("SettingsViewModel: theme changed to '%s'", theme)
        self._settings.set_pref("theme", theme)  # kept for the next start

    @Slot(str, str)
    def save_api_key(self, provider: str, key: str):
        """Store API key in OS keyring via Vault."""
        if not key.strip():
            self.error_occurred.emit("API key cannot be empty.")
            return
        try:
            Vault.store_api_key(provider, key)
            self.status_message.emit(f"API key for '{provider}' saved securely.")
            logger.info("SettingsViewModel: API key saved for provider '%s'", provider)
        except Exception as exc:
            logger.error("SettingsViewModel: failed to save API key: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Could not save key: {exc}")

    @Slot()
    def apply_settings(self):
        """Signal that settings have been applied; some changes require restart."""
        self.status_message.emit("Settings applied. Some changes require a restart.")
        self.config_updated.emit()
        logger.info("SettingsViewModel: settings applied")

    # ── Preferences persisted in agent_settings.json (applied at start: apply_user_overrides) ──

    @property
    def language(self) -> str:
        return self._settings.get_pref("language") or self._config.ui.language

    @Slot(str)
    def set_language(self, language: str):
        try:
            self._settings.set_pref("language", language)
        except ValueError as exc:
            self.error_occurred.emit(str(exc))
            return
        self.restart_required.emit("language")

    # ── GPU / ROCm ───────────────────────────────────────────────────────────

    @property
    def gpu_device(self) -> str:
        return self._settings.get_pref("gpu_device") or self._config.gpu.device

    @Slot(str)
    def set_gpu_device(self, device: str):
        try:
            self._settings.set_pref("gpu_device", device)
        except ValueError as exc:
            self.error_occurred.emit(str(exc))
            return
        self.restart_required.emit("GPU device")

    @asyncSlot()
    async def load_gpu_info(self):
        from core import accelerator

        info = await asyncio.get_running_loop().run_in_executor(None, accelerator.info)
        self.gpu_info_ready.emit(info)

    @asyncSlot()
    async def run_benchmark(self):
        from core import accelerator

        self.status_message.emit("Running GPU benchmark…")
        try:
            result = await asyncio.get_running_loop().run_in_executor(None, accelerator.benchmark)
        except Exception as exc:  # driver/HIP problems are reported, not raised
            self.error_occurred.emit(f"Benchmark failed: {exc}")
            return
        self.benchmark_ready.emit(result)
        self.status_message.emit("Benchmark finished.")

    @property
    def ollama_host(self) -> str:
        provider = self._config.ai_providers.get("ollama")
        return self._settings.get_pref("ollama_host") or (provider.host if provider else "") or ""

    @Slot(str)
    def save_ollama_host(self, host: str):
        host = host.strip().rstrip("/")
        if not host.startswith(("http://", "https://")):
            self.error_occurred.emit("Ollama host must start with http:// or https://")
            return
        self._settings.set_pref("ollama_host", host)
        self.status_message.emit("Ollama host saved.")
        self.restart_required.emit("ollama host")

    @property
    def server_url(self) -> str:
        return self._settings.get_pref("server_url") or self._config.backend.base_url

    def set_server_url(self, url: str) -> bool:
        try:
            self._settings.set_pref("server_url", url)
        except ValueError as exc:
            self.error_occurred.emit(str(exc))
            return False
        self.restart_required.emit("server address (log in again after the restart)")
        return True

    @property
    def crash_reports(self) -> bool:
        return self._settings.crash_reports

    @Slot(bool)
    def set_crash_reports(self, enabled: bool):
        self._settings.set_pref("crash_reports", enabled)
        self.restart_required.emit("crash reporting")

    @property
    def crash_reports_available(self) -> bool:
        return bool(self._config.sentry_dsn)

    @property
    def update_channel(self) -> str:
        return self._settings.update_channel

    @Slot(str)
    def set_update_channel(self, channel: str):
        try:
            self._settings.set_pref("update_channel", channel)
        except ValueError as exc:
            self.error_occurred.emit(str(exc))

    @property
    def version(self) -> str:
        return self._config.version

    # ── Updates ──────────────────────────────────────────────────────────────

    @asyncSlot()
    async def check_updates(self):
        self.status_message.emit("Checking for updates…")
        try:
            info = await self._updates.check(self.update_channel)
        except UpdateError as exc:
            self.error_occurred.emit(str(exc))
            return
        self._pending = info
        if info is None:
            self.status_message.emit(f"Cybrix {self.version} is up to date.")
            return
        self.update_available.emit({"version": info.version, "notes": info.notes,
                                    "mandatory": info.mandatory, "size": info.size})

    @asyncSlot()
    async def download_update(self):
        if self._pending is None:
            return
        try:
            path = await self._updates.download(self._pending, paths.cache_dir() / "updates",
                                                progress=self.update_progress.emit)
        except UpdateError as exc:
            self.error_occurred.emit(str(exc))
            return
        self.update_ready.emit(str(path))

    @Slot(str)
    def install_update(self, installer: str):
        try:
            outcome = self._updates.install(Path(installer))
        except OSError as exc:
            self.error_occurred.emit(f"Could not start the installer: {exc}")
            return
        self.status_message.emit("Update installed — restart Cybrix." if outcome == "replaced"
                                 else "The installer was opened — follow its steps.")

    # ── Diagnostics ──────────────────────────────────────────────────────────

    def export_diagnostics(self, dest: str) -> bool:
        try:
            crash.export_diagnostics(Path(dest), self.version, self._config.backend.data_path)
        except OSError as exc:
            self.error_occurred.emit(f"Could not write diagnostics: {exc}")
            return False
        self.status_message.emit(f"Diagnostics saved to {dest}")
        return True
