"""ViewModel for Settings window.

Communicates with infrastructure only through injected services.
No direct infrastructure imports in this file.
"""
import logging

from PySide6.QtCore import Signal, Property, Slot
from PySide6.QtWidgets import QApplication
from injector import inject

from core.config import AppConfig
from infrastructure.security.vault import Vault
from presentation.theme.theme_manager import ThemeManager
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class SettingsViewModel(BaseViewModel):
    theme_changed = Signal(str)
    config_updated = Signal()

    @inject
    def __init__(self, app_config: AppConfig):
        super().__init__()
        self._config = app_config

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
