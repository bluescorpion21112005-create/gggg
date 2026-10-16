"""Settings tab: server command policy, telemetry sharing and the devices of this account.

Logging in and live activity live on the "Server" page.
"""
from PySide6.QtCore import QT_TRANSLATE_NOOP, Qt, Slot
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QPushButton, QVBoxLayout,
    QWidget,
)

from presentation.viewmodels.connection_viewmodel import ConnectionViewModel

POLICY_LABELS = {
    "ask": QT_TRANSLATE_NOOP("ServerTab", "Ask me before running any server command"),
    "allow_listed": QT_TRANSLATE_NOOP("ServerTab", "Only run command types I allowed permanently"),
    "deny_all": QT_TRANSLATE_NOOP("ServerTab", "Never run server commands"),
}


class ServerTab(QWidget):
    def __init__(self, viewmodel: ConnectionViewModel, settings_vm=None):
        super().__init__()
        self._vm = viewmodel
        self._settings_vm = settings_vm
        layout = QVBoxLayout(self)
        form = QFormLayout()
        if settings_vm is None:
            server = QLabel(self._vm.server_url)
            server.setTextFormat(Qt.PlainText)
            form.addRow(self.tr("Server:"), server)
        else:
            self.server_url = QLineEdit(settings_vm.server_url)
            self.server_url.setPlaceholderText("https://cybrix.example.com")
            save_url = QPushButton(self.tr("Save"))
            save_url.setToolTip(self.tr("https:// only (http is allowed for localhost). Applies after a restart."))
            save_url.clicked.connect(lambda: settings_vm.set_server_url(self.server_url.text()))
            row = QHBoxLayout()
            row.addWidget(self.server_url)
            row.addWidget(save_url)
            form.addRow(self.tr("Server:"), row)

        self.policy = QComboBox()
        for key in self._vm.policies:
            self.policy.addItem(self.tr(POLICY_LABELS.get(key, key)), key)
        self.policy.setCurrentIndex(max(0, self.policy.findData(self._vm.command_policy)))
        self.policy.currentIndexChanged.connect(lambda _i: self._vm.set_command_policy(self.policy.currentData()))
        form.addRow(self.tr("Server commands:"), self.policy)

        self.allowed = QLabel()
        self.allowed.setWordWrap(True)
        form.addRow(self.tr("Always allowed:"), self.allowed)
        clear_btn = QPushButton(self.tr("Forget permanent approvals"))
        clear_btn.clicked.connect(self._clear_allowed)
        form.addRow("", clear_btn)

        dirs = QLabel(", ".join(self._vm.allowed_dirs) or self.tr("none (file commands are refused)"))
        dirs.setWordWrap(True)
        dirs.setToolTip(self.tr("Configured in settings.yaml → backend.command_allowed_dirs"))
        form.addRow(self.tr("File access:"), dirs)

        self.share = QCheckBox(self.tr("Share CPU/RAM/disk/network metrics with the server"))
        self.share.setChecked(self._vm.sharing)
        self.share.toggled.connect(self._vm.set_sharing)
        self._vm.sharing_changed.connect(self.share.setChecked)
        form.addRow(self.tr("Telemetry:"), self.share)
        self.netflows = QCheckBox(self.tr("Share network connections for threat detection (opt-in)"))
        self.netflows.setChecked(self._vm.netflow_sharing)
        self.netflows.toggled.connect(self._vm.set_netflow_sharing)
        self._vm.netflow_sharing_changed.connect(self.netflows.setChecked)
        form.addRow(self.tr("Connections:"), self.netflows)
        self.hashes = QCheckBox(self.tr("Check running programs against known malware hashes (opt-in)"))
        self.hashes.setChecked(self._vm.hash_sharing)
        self.hashes.toggled.connect(self._vm.set_hash_sharing)
        self._vm.hash_sharing_changed.connect(self.hashes.setChecked)
        form.addRow(self.tr("Programs:"), self.hashes)
        layout.addLayout(form)

        layout.addWidget(QLabel(self.tr("Devices signed in to your account:")))
        self.devices = QListWidget()
        layout.addWidget(self.devices)
        refresh_btn = QPushButton(self.tr("Refresh devices"))
        refresh_btn.clicked.connect(self._vm.refresh_devices)
        layout.addWidget(refresh_btn)
        self._vm.devices_changed.connect(self._show_devices)
        self._refresh_allowed()
        if self._vm.is_logged_in:
            self._vm.refresh_devices()

    def _clear_allowed(self):
        self._vm.clear_always_allowed()
        self._refresh_allowed()

    def _refresh_allowed(self):
        self.allowed.setText(", ".join(self._vm.always_allowed) or self.tr("none"))

    @Slot(list)
    def _show_devices(self, devices: list):
        self.devices.clear()
        for d in devices:
            status = "online" if d.get("is_online") else "offline"
            self.devices.addItem(f"{d.get('name')} — {d.get('platform') or '?'} ({status})")
