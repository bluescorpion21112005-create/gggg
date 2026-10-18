"""Application bootstrap: initialises DI, loads plugins, sets up logging, starts UI."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import qasync
from injector import Injector
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from core.config import ConfigLoader
from core.di import CybrixModule
from core.logging_config import setup_logging
from core.plugin_manager import PluginManager
from core.event_bus import event_bus
from core.gpu_monitor import GPUManager
from presentation.main_window import MainWindow
from presentation.theme.theme_manager import ThemeManager
from application.agents.chat_agent import ChatAgent
from application.agents.log_agent import LogAgent
from application.agents.malware_agent import MalwareAgent
from application.agents.ioc_agent import IOCAgent
from application.agents.threat_hunting_agent import ThreatHuntingAgent
from application.agents.rag_agent import RAGAgent
from application.agents.report_agent import ReportAgent
from application.orchestrator import Orchestrator
from application.services.connection_service import ConnectionService
from application.services.command_executor import CommandExecutor
from application.services.netflow_service import NetflowService
from application.services.process_hash_service import ProcessHashService

logger = logging.getLogger("cybrix")


class CybrixApp:
    """Main application class that handles lifecycle."""

    def __init__(self, config_path: Path | None = None):
        # ── STEP 1: QApplication MUST be created first.
        # PySide6 requires QApplication before any QObject (including ViewModels) is created.
        self._qt_app = QApplication(sys.argv)

        # ── STEP 2: Load configuration (+ preferences saved from the UI: server, theme, language…)
        from infrastructure.remote.agent_settings import apply_user_overrides

        self.config = apply_user_overrides(ConfigLoader.load(config_path))

        # ── STEP 3: Set up logging
        setup_logging(self.config.logging)
        logger.info("Starting %s v%s", self.config.name, self.config.version)
        # ROCm environment must be in place before anything initialises PyTorch/HIP.
        from core import accelerator

        gpu = self.config.gpu
        accelerator.configure_env(gpu.device if gpu.prefer_rocm else "cpu", gpu.hsa_override, gpu.visible_devices)
        from core import crash
        from infrastructure.remote.agent_settings import AgentSettings

        self._install_translator(self.config.ui.language)
        first_run = AgentSettings(self.config)
        if not first_run.onboarding_done and os.getenv("CYBRIX_SKIP_ONBOARDING") != "1":
            # Before the DI container: the server chosen here must be the one every service uses.
            from presentation.views.onboarding_wizard import OnboardingWizard

            ThemeManager.apply_theme(self._qt_app, self.config.ui.theme)
            OnboardingWizard(self.config, first_run).exec()
            first_run = AgentSettings(self.config)
            self.config = apply_user_overrides(ConfigLoader.load(config_path))
        crash.install(self.config.version, self.config.sentry_dsn, consent=first_run.crash_reports)

        # ── STEP 4: Create DI container.
        # All QObject-based singletons (ViewModels) are now safe to instantiate.
        self.injector = Injector([CybrixModule(self.config)])

        # ── STEP 5: qasync event loop — single event loop shared by Qt and asyncio.
        self._loop = qasync.QEventLoop(self._qt_app)
        asyncio.set_event_loop(self._loop)

        # ── STEP 6: Apply theme
        ThemeManager.apply_theme(self._qt_app, self.config.ui.theme)

        # ── STEP 7: Discover plugins
        plugin_manager = self.injector.get(PluginManager)
        plugin_manager.discover_plugins()

        # ── STEP 8: Register all agents with the Orchestrator.
        # The Orchestrator coordinates agents; agents are registered here so that
        # the Orchestrator itself does not need to know about concrete agent types.
        orchestrator = self.injector.get(Orchestrator)
        orchestrator.register_agent("chat", self.injector.get(ChatAgent))
        orchestrator.register_agent("log_analysis", self.injector.get(LogAgent))
        orchestrator.register_agent("malware_analysis", self.injector.get(MalwareAgent))
        orchestrator.register_agent("ioc_analysis", self.injector.get(IOCAgent))
        orchestrator.register_agent("threat_hunting", self.injector.get(ThreatHuntingAgent))
        orchestrator.register_agent("rag_query", self.injector.get(RAGAgent))
        orchestrator.register_agent("generate_report", self.injector.get(ReportAgent))

        # ── STEP 9: Build main window via DI
        self._main_window = self.injector.get(MainWindow)

        # ── STEP 10: Server connection — executor subscribes to server commands;
        # reconnect in the background if a device token is stored.
        self.injector.get(CommandExecutor)
        self.injector.get(NetflowService)  # subscribes to connection state; runs only with consent
        self.injector.get(ProcessHashService)  # same, for the opt-in malware hash check
        self._connection = self.injector.get(ConnectionService)
        # Deferred until the qasync loop is running — qasync cannot schedule tasks before that.
        QTimer.singleShot(0, lambda: asyncio.ensure_future(self._connection.auto_connect()))

        # ── STEP 11: Wire shutdown handler
        self._qt_app.aboutToQuit.connect(self._on_shutdown)

    def _install_translator(self, language: str) -> None:
        """uz/ru UI strings from presentation/i18n/cybrix_<lang>.qm (English is the source)."""
        from PySide6.QtCore import QTranslator

        from core.paths import bundle_dir

        if language == "en":
            return
        translator = QTranslator(self._qt_app)
        qm = bundle_dir() / "presentation" / "i18n" / f"cybrix_{language}.qm"
        if translator.load(str(qm)):
            self._qt_app.installTranslator(translator)
            self._translator = translator  # keep a reference: Qt does not own it
        else:
            logger.warning("no translation for language '%s' (%s)", language, qm)

    def run(self) -> int:
        """Start the combined Qt + asyncio event loop."""
        self._main_window.show()
        # On exit the WebSocket's TCP connection drops with the process; the server's
        # disconnect handler then marks this device offline.
        with self._loop:
            return self._loop.run_forever()

    def _on_shutdown(self):
        """Clean up resources on shutdown."""
        logger.info("Shutting down Cybrix AI")
        event_bus.emit("app_shutdown")


def main():
    """Entry point: bootstrap and run the application."""
    try:
        app = CybrixApp()
        gpu_manager = app.injector.get(GPUManager)
        logger.info("ROCm available: %s", gpu_manager._rocm_available)  # no torch import at startup
        sys.exit(app.run())
    except Exception as e:
        logging.critical("Failed to start application: %s", e, exc_info=True)
        sys.exit(1)
