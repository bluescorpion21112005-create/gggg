"""Settings dialog: appearance, AI providers, server, diagnostics & updates."""
from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton,
                               QTabWidget, QVBoxLayout, QWidget)

from presentation.viewmodels.connection_viewmodel import ConnectionViewModel
from presentation.viewmodels.settings_viewmodel import SettingsViewModel
from presentation.views.server_tab import ServerTab

LANGUAGE_NAMES = {"en": "English", "ru": "Русский", "uz": "O‘zbekcha"}


class SettingsWindow(QDialog):
    def __init__(self, viewmodel: SettingsViewModel, connection_vm: ConnectionViewModel | None = None):
        super().__init__()
        self._vm = viewmodel
        self._connection_vm = connection_vm
        self.setWindowTitle(self.tr("Settings"))
        self.resize(640, 460)
        self._setup_ui()
        self._vm.restart_required.connect(self._on_restart_required)
        self._vm.error_occurred.connect(lambda msg: QMessageBox.warning(self, self.tr("Settings"), msg))
        self._vm.status_message.connect(self.status.setText)
        self._vm.update_available.connect(self._on_update_available)
        self._vm.update_progress.connect(self._on_update_progress)
        self._vm.update_ready.connect(self._on_update_ready)

    def _setup_ui(self):
        tabs = QTabWidget()

        appear_tab = QWidget()
        layout = QFormLayout(appear_tab)
        theme_combo = QComboBox()
        theme_combo.addItems(["dark", "light"])
        theme_combo.setCurrentText(self._vm.current_theme)
        theme_combo.currentTextChanged.connect(self._vm.set_theme)
        layout.addRow(self.tr("Theme:"), theme_combo)
        self.language = QComboBox()
        for code in self._vm.LANGUAGES:
            self.language.addItem(LANGUAGE_NAMES.get(code, code), code)
        self.language.setCurrentIndex(max(0, self.language.findData(self._vm.language)))
        self.language.currentIndexChanged.connect(lambda _i: self._vm.set_language(self.language.currentData()))
        layout.addRow(self.tr("Language:"), self.language)
        tabs.addTab(appear_tab, self.tr("Appearance"))

        ai_tab = QWidget()
        ai_layout = QFormLayout(ai_tab)
        self.ollama_host = QLineEdit(self._vm.ollama_host)
        self.ollama_host.setPlaceholderText("http://localhost:11434")
        save_host = QPushButton(self.tr("Save host"))
        save_host.clicked.connect(lambda: self._vm.save_ollama_host(self.ollama_host.text()))
        row = QHBoxLayout()
        row.addWidget(self.ollama_host)
        row.addWidget(save_host)
        ai_layout.addRow(self.tr("Ollama Host:"), row)
        fw_key = QLineEdit()
        fw_key.setEchoMode(QLineEdit.Password)
        ai_layout.addRow(self.tr("Fireworks API Key:"), fw_key)
        save_btn = QPushButton(self.tr("Save key"))
        save_btn.clicked.connect(lambda: (self._vm.save_api_key("fireworks", fw_key.text()), fw_key.clear()))
        ai_layout.addRow(save_btn)
        tabs.addTab(ai_tab, self.tr("AI Providers"))

        if self._connection_vm is not None:
            tabs.addTab(ServerTab(self._connection_vm, self._vm), self.tr("Server"))

        tabs.addTab(self._diagnostics_tab(), self.tr("Diagnostics && updates"))

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(tabs)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        main_layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

    def _diagnostics_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow(self.tr("Version:"), QLabel(self._vm.version))

        self.channel = QComboBox()
        self.channel.addItem(self.tr("Stable"), "stable")
        self.channel.addItem(self.tr("Beta (earlier, less tested)"), "beta")
        self.channel.setCurrentIndex(max(0, self.channel.findData(self._vm.update_channel)))
        self.channel.currentIndexChanged.connect(lambda _i: self._vm.set_update_channel(self.channel.currentData()))
        form.addRow(self.tr("Update channel:"), self.channel)
        check = QPushButton(self.tr("Check for updates"))
        check.clicked.connect(self._vm.check_updates)
        form.addRow("", check)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        form.addRow("", self.progress)

        self.crash = QCheckBox(self.tr("Send anonymous crash reports (no personal data, no files)"))
        self.crash.setChecked(self._vm.crash_reports)
        self.crash.setEnabled(self._vm.crash_reports_available)
        if not self._vm.crash_reports_available:
            self.crash.setToolTip(self.tr("This build has no crash-report endpoint configured."))
        self.crash.toggled.connect(self._vm.set_crash_reports)
        form.addRow(self.tr("Crash reports:"), self.crash)

        export = QPushButton(self.tr("Export diagnostics…"))
        export.setToolTip(self.tr("Logs and system info as a ZIP to attach to a bug report. "
                                  "Contains no passwords or tokens."))
        export.clicked.connect(self._export)
        form.addRow(self.tr("Diagnostics:"), export)

        if self._connection_vm is not None:
            feedback = QPushButton(self.tr("Send feedback…"))
            feedback.clicked.connect(self._feedback)
            form.addRow(self.tr("Feedback:"), feedback)
            self._connection_vm.status_message.connect(self.status.setText)
            self._connection_vm.error_occurred.connect(self.status.setText)
        return tab

    def _feedback(self):
        text, ok = QInputDialog.getMultiLineText(
            self, self.tr("Send feedback"),
            self.tr("What happened, or what would you like? (goes to the Cybrix team)"))
        if ok and text.strip():
            self._connection_vm.send_feedback("other", text)

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save diagnostics"), "cybrix-diagnostics.zip",
                                              "ZIP (*.zip)")
        if path:
            self._vm.export_diagnostics(path)

    @Slot(str)
    def _on_restart_required(self, what: str):
        self.status.setText(self.tr("Saved. The new %1 is used after Cybrix restarts.").replace("%1", what))

    @Slot(dict)
    def _on_update_available(self, info: dict):
        size_mb = info.get("size", 0) / 1_048_576
        text = self.tr("Cybrix %1 is available (%2 MB).").replace("%1", info["version"]).replace("%2", f"{size_mb:.0f}")
        if info.get("mandatory"):
            text += "\n" + self.tr("This update is required to keep using the server.")
        if info.get("notes"):
            text += "\n\n" + info["notes"]
        box = QMessageBox(QMessageBox.Information, self.tr("Update available"), text,
                          QMessageBox.Yes | QMessageBox.No, self)
        box.button(QMessageBox.Yes).setText(self.tr("Download"))
        if box.exec() == QMessageBox.Yes:
            self.progress.setVisible(True)
            self._vm.download_update()

    @Slot(int, int)
    def _on_update_progress(self, received: int, total: int):
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(received)

    @Slot(str)
    def _on_update_ready(self, path: str):
        self.progress.setVisible(False)
        answer = QMessageBox.question(
            self, self.tr("Install update"),
            self.tr("The update was downloaded and its signature and checksum verified.\nInstall it now?"))
        if answer == QMessageBox.Yes:
            self._vm.install_update(path)
