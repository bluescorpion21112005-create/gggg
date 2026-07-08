"""Main application window with navigation, docking, and status bar."""
from typing import Dict

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QStackedWidget,
    QDockWidget, QStatusBar, QLabel, QToolBar, QMessageBox
)
from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QAction

from injector import inject, Injector

from presentation.viewmodels.dashboard_viewmodel import DashboardViewModel
from presentation.viewmodels.chat_viewmodel import ChatViewModel
from presentation.viewmodels.settings_viewmodel import SettingsViewModel
from presentation.viewmodels.log_analysis_viewmodel import LogAnalysisViewModel
from presentation.viewmodels.malware_analysis_viewmodel import MalwareAnalysisViewModel
from presentation.viewmodels.ioc_viewmodel import IOCViewModel
from presentation.viewmodels.rag_viewmodel import RAGViewModel
from presentation.viewmodels.report_viewmodel import ReportViewModel

from presentation.views.dashboard_view import DashboardView
from presentation.views.chat_view import ChatView
from presentation.views.settings_window import SettingsWindow
from presentation.views.log_analysis_view import LogAnalysisView
from presentation.views.malware_analysis_view import MalwareAnalysisView
from presentation.views.ioc_view import IOCView
from presentation.views.rag_view import RAGView
from presentation.views.report_view import ReportView

from presentation.widgets.status_bar import StatusBarWidget
from core.event_bus import event_bus
import logging

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Central window hosting all UI panels."""

    @inject
    def __init__(
        self,
        injector: Injector,
        dashboard_vm: DashboardViewModel,
        chat_vm: ChatViewModel,
        settings_vm: SettingsViewModel,
        log_analysis_vm: LogAnalysisViewModel,
        malware_analysis_vm: MalwareAnalysisViewModel,
        ioc_vm: IOCViewModel,
        rag_vm: RAGViewModel,
        report_vm: ReportViewModel,
    ) -> None:
        super().__init__()
        self._injector = injector
        self._dashboard_vm = dashboard_vm
        self._chat_vm = chat_vm
        self._settings_vm = settings_vm
        self._log_analysis_vm = log_analysis_vm
        self._malware_analysis_vm = malware_analysis_vm
        self._ioc_vm = ioc_vm
        self._rag_vm = rag_vm
        self._report_vm = report_vm

        self._view_pages: Dict[str, QWidget] = {}

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        self.setWindowTitle("Cybrix AI - Cybersecurity Platform")
        self.resize(1400, 900)

        # Central widget with sidebar + stacked views
        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar navigation
        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(200)
        self.nav_list.setObjectName("navList")
        nav_items = [
            ("Dashboard", "dashboard"),
            ("AI Chat", "chat"),
            ("Log Analyzer", "log_analysis"),
            ("Malware Analyzer", "malware"),
            ("IOC Analyzer", "ioc"),
            ("Document RAG", "rag"),
            ("Reports", "report"),
        ]
        for label, key in nav_items:
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, key)
            self.nav_list.addItem(item)
        self.nav_list.currentItemChanged.connect(self._on_nav_changed)

        main_layout.addWidget(self.nav_list)

        # Stacked widget for views
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack, 1)

        self.setCentralWidget(central_widget)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_widget = StatusBarWidget()
        self.status_bar.addPermanentWidget(self.status_widget)

        # Toolbar actions
        toolbar = self.addToolBar("Main")
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self._open_settings)
        toolbar.addAction(settings_action)

        # Build all views (after all attributes set)
        self._create_views()

        # Show dashboard initially
        self.nav_list.setCurrentRow(0)

    def _create_views(self) -> None:
        """Create and register all feature views."""
        # Har bir view’ni yaratish
        self._view_pages["dashboard"] = DashboardView(self._dashboard_vm)
        self._view_pages["chat"] = ChatView(self._chat_vm)
        self._view_pages["log_analysis"] = LogAnalysisView(self._log_analysis_vm)
        self._view_pages["malware"] = MalwareAnalysisView(self._malware_analysis_vm)
        self._view_pages["ioc"] = IOCView(self._ioc_vm)
        self._view_pages["rag"] = RAGView(self._rag_vm)
        self._view_pages["report"] = ReportView(self._report_vm)

        # Add all to stack
        for page in self._view_pages.values():
            self.stack.addWidget(page)

    def _on_nav_changed(self, current: QListWidgetItem, previous: QListWidgetItem) -> None:
        if not current:
            return
        key = current.data(Qt.UserRole)
        if key in self._view_pages:
            self.stack.setCurrentWidget(self._view_pages[key])

    def _open_settings(self) -> None:
        dialog = SettingsWindow(self._settings_vm)
        dialog.exec()

    def _connect_signals(self) -> None:
        event_bus.subscribe("status_message", lambda msg: self.status_widget.show_message(msg))
        event_bus.subscribe("analysis_completed", lambda _: self.status_widget.show_message("Analysis completed"))
        # Wire all ViewModel signals to the status bar and error dialogs
        all_vms = [
            self._dashboard_vm,
            self._chat_vm,
            self._settings_vm,
            self._log_analysis_vm,
            self._malware_analysis_vm,
            self._ioc_vm,
            self._rag_vm,
            self._report_vm,
        ]
        for vm in all_vms:
            vm.status_message.connect(self.status_widget.show_message)
            vm.error_occurred.connect(self._show_error_dialog)

    @Slot(str)
    def _show_error_dialog(self, message: str) -> None:
        """Display a non-blocking error notification in the status bar.

        Critical errors that require user action show a QMessageBox.
        Transient errors (e.g., provider timeout) are shown in the status bar only.
        """
        logger.error("UI error: %s", message)
        self.status_widget.show_message(f"Error: {message}")
        # Show a dialog only for truly critical errors to avoid flooding the user
        if any(kw in message.lower() for kw in ("api key", "no ai provider", "database")):
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Cybrix AI — Error")
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setText(message)
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec()