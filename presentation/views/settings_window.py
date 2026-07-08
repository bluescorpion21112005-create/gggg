"""Settings dialog."""
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QTabWidget, QWidget,
                               QFormLayout, QLineEdit, QPushButton, QComboBox,
                               QDialogButtonBox, QLabel)
from PySide6.QtCore import Qt
from presentation.viewmodels.settings_viewmodel import SettingsViewModel


class SettingsWindow(QDialog):
    def __init__(self, viewmodel: SettingsViewModel):
        super().__init__()
        self._vm = viewmodel
        self.setWindowTitle("Settings")
        self.resize(600, 400)
        self._setup_ui()

    def _setup_ui(self):
        tabs = QTabWidget()
        # Appearance tab
        appear_tab = QWidget()
        layout = QFormLayout(appear_tab)
        theme_combo = QComboBox()
        theme_combo.addItems(["dark", "light"])
        theme_combo.setCurrentText(self._vm.current_theme)
        theme_combo.currentTextChanged.connect(self._vm.set_theme)
        layout.addRow("Theme:", theme_combo)
        tabs.addTab(appear_tab, "Appearance")

        # AI Providers tab
        ai_tab = QWidget()
        ai_layout = QFormLayout(ai_tab)
        # Ollama
        ollama_host = QLineEdit()
        ai_layout.addRow("Ollama Host:", ollama_host)
        # Fireworks API key
        fw_key = QLineEdit()
        fw_key.setEchoMode(QLineEdit.Password)
        ai_layout.addRow("Fireworks API Key:", fw_key)
        save_btn = QPushButton("Save Keys")
        save_btn.clicked.connect(lambda: self._vm.save_api_key("fireworks", fw_key.text()))
        ai_layout.addRow(save_btn)
        tabs.addTab(ai_tab, "AI Providers")

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)