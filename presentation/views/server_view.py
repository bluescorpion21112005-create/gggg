""""Server" page: connection, what is shared, server commands, server scans and the audit trail."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from PySide6.QtCore import QT_TRANSLATE_NOOP, QAbstractTableModel, QModelIndex, Qt, QUrl, Slot
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QTableView, QVBoxLayout,
    QWidget,
)

from presentation.viewmodels.connection_viewmodel import ConnectionViewModel

STATE_TEXT = {
    "connected": (QT_TRANSLATE_NOOP("ServerView", "Online"), "#22c55e"),
    "connecting": (QT_TRANSLATE_NOOP("ServerView", "Connecting…"), "#f59e0b"),
    "disconnected": (QT_TRANSLATE_NOOP("ServerView", "Offline"), "#9ca3af"),
    "auth_failed": (QT_TRANSLATE_NOOP("ServerView", "Login required"), "#ef4444"),
    "upgrade_required": (QT_TRANSLATE_NOOP("ServerView", "Update required"), "#ef4444"),
}
STATUS_COLORS = {
    "done": "#22c55e", "failed": "#ef4444", "rejected": "#ef4444",
    "awaiting_approval": "#f59e0b", "approved": "#2d9cdb", "received": "#9ca3af",
}
SCAN_TOOLS = ["sql_classifier", "threat_prediction", "vuln_explain", "url_risk", "malware"]


def _fmt_bytes(bps) -> str:
    if bps is None:
        return "–"
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024 or unit == "GB/s":
            return f"{bps:.1f} {unit}"
        bps /= 1024
    return "–"


def _fmt_pct(v) -> str:
    return "–" if v is None else f"{v:.0f}%"


class CommandTableModel(QAbstractTableModel):
    HEADERS = [QT_TRANSLATE_NOOP("CommandTableModel", "Time"), QT_TRANSLATE_NOOP("CommandTableModel", "Command"),
               QT_TRANSLATE_NOOP("CommandTableModel", "Status"), QT_TRANSLATE_NOOP("CommandTableModel", "Progress"),
               QT_TRANSLATE_NOOP("CommandTableModel", "Details")]

    def __init__(self):
        super().__init__()
        self._rows: List[Dict[str, Any]] = []
        self._index: Dict[str, int] = {}

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.tr(self.HEADERS[section])
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            return [row["time"], row["type"], row["status"].replace("_", " "),
                    f"{row['progress']}%", row.get("error") or row["command_id"][:8]][col]
        if role == Qt.ForegroundRole and col == 2:
            return QColor(STATUS_COLORS.get(row["status"], "#d1d5db"))
        if role == Qt.ToolTipRole:
            return row.get("error") or row["command_id"]
        return None

    def upsert(self, update: Dict[str, Any]) -> None:
        cid = update["command_id"]
        if cid in self._index:
            i = self._index[cid]
            self._rows[i].update({k: v for k, v in update.items() if k != "time"})
            self.dataChanged.emit(self.index(i, 0), self.index(i, len(self.HEADERS) - 1))
            return
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._rows.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), **update})
        self._index = {r["command_id"]: i for i, r in enumerate(self._rows)}
        self.endInsertRows()


class ServerView(QWidget):
    def __init__(self, viewmodel: ConnectionViewModel):
        super().__init__()
        self._vm = viewmodel
        self._commands = CommandTableModel()
        self._build()
        self._wire()
        self._apply_logged_in(self._vm.is_logged_in)
        self._apply_state(self._vm.state)
        self._apply_session(self._vm.session_info)
        self._apply_telemetry(self._vm.last_telemetry)
        for entry in reversed(self._vm.recent_audit(200)):
            self._append_audit(entry)

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        grid = QGridLayout(body)
        grid.setContentsMargins(16, 16, 16, 16)
        grid.setSpacing(14)

        title = QLabel(self.tr("Cybrix Server"))
        title.setObjectName("pageTitle")
        grid.addWidget(title, 0, 0, 1, 2)
        grid.addWidget(self._build_connection(), 1, 0, 1, 2)
        grid.addWidget(self._build_telemetry(), 2, 0)
        grid.addWidget(self._build_scan(), 2, 1)
        grid.addWidget(self._build_netflows(), 3, 0, 1, 2)
        grid.addWidget(self._build_commands(), 5, 0, 1, 2)
        grid.addWidget(self._build_audit(), 6, 0, 1, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

    def _build_connection(self) -> QGroupBox:
        box = QGroupBox(self.tr("Connection"))
        box.setObjectName("card")
        layout = QHBoxLayout(box)

        info = QFormLayout()
        self.state_label = QLabel()
        self.state_label.setObjectName("stateBadge")
        info.addRow(self.tr("Status:"), self.state_label)
        server = QLabel(("🔒 " if self._vm.is_secure else "⚠ ") + self._vm.server_url)
        server.setTextFormat(Qt.PlainText)
        server.setToolTip(self.tr("Encrypted connection") if self._vm.is_secure
                          else self.tr("Not encrypted — tokens are only sent to localhost or with allow_insecure"))
        info.addRow(self.tr("Server:"), server)
        self.device_label = QLabel("–")
        self.device_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info.addRow(self.tr("Device:"), self.device_label)
        self.expiry_label = QLabel("–")
        info.addRow(self.tr("Token expires:"), self.expiry_label)
        layout.addLayout(info, 2)

        # Login form / logged-in actions (one of them is visible)
        self.login_box = QWidget()
        form = QFormLayout(self.login_box)
        self.username = QLineEdit()
        self.username.setPlaceholderText(self.tr("username"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText(self.tr("password"))
        self.login_btn = QPushButton(self.tr("Log in"))
        self.login_btn.setObjectName("primaryButton")
        self.login_error = QLabel()
        self.login_error.setObjectName("errorText")
        self.login_error.setWordWrap(True)
        form.addRow(self.tr("Username:"), self.username)
        form.addRow(self.tr("Password:"), self.password)
        form.addRow(self.login_btn)
        form.addRow(self.login_error)
        layout.addWidget(self.login_box, 2)

        self.session_box = QWidget()
        actions = QVBoxLayout(self.session_box)
        self.logout_btn = QPushButton(self.tr("Log out this device"))
        actions.addWidget(self.logout_btn)
        actions.addStretch()
        layout.addWidget(self.session_box, 1)
        return box

    def _build_telemetry(self) -> QGroupBox:
        box = QGroupBox(self.tr("Shared with the server"))
        box.setObjectName("card")
        layout = QVBoxLayout(box)
        hint = QLabel(self.tr("Exactly these values are sent every few seconds while connected. "
                              "Nothing else leaves this computer unless you approve a command."))
        hint.setWordWrap(True)
        hint.setObjectName("mutedText")
        hint.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        layout.addWidget(hint)
        form = QFormLayout()
        self.metric_labels: Dict[str, QLabel] = {}
        for key, label in (("cpu_percent", "CPU"), ("ram_percent", "RAM"), ("disk_percent", "Disk"),
                           ("gpu_percent", "GPU"), ("net_rx_bps", "Network ↓"), ("net_tx_bps", "Network ↑"),
                           ("process_count", "Processes"), ("hostname", "Hostname"), ("os", "OS")):
            value = QLabel("–")
            value.setObjectName("metricValue")
            form.addRow(f"{label}:", value)
            self.metric_labels[key] = value
        layout.addLayout(form)
        self.share_box = QCheckBox(self.tr("Share telemetry with the server"))
        self.share_box.setChecked(self._vm.sharing)
        layout.addWidget(self.share_box)
        return box

    def _build_scan(self) -> QGroupBox:
        box = QGroupBox(self.tr("Server scan"))
        box.setObjectName("card")
        layout = QVBoxLayout(box)
        self.scan_tool = QComboBox()
        self.scan_tool.addItems(SCAN_TOOLS)
        layout.addWidget(self.scan_tool)
        self.scan_input = QPlainTextEdit()
        self.scan_input.setPlaceholderText(self.tr("Text, URL or payload to analyse on the server…"))
        self.scan_input.setMaximumHeight(110)
        layout.addWidget(self.scan_input)
        self.scan_btn = QPushButton(self.tr("Run on server"))
        self.scan_btn.setObjectName("primaryButton")
        layout.addWidget(self.scan_btn)
        self.scan_log = QListWidget()
        self.scan_log.setMaximumHeight(140)
        layout.addWidget(self.scan_log)
        return box

    def _build_netflows(self) -> QGroupBox:
        box = QGroupBox(self.tr("Suspicious connections"))
        box.setObjectName("card")
        layout = QVBoxLayout(box)
        hint = QLabel(self.tr("When enabled, this computer's open connections (remote IP/port, local port and process "
                              "name — never contents) are checked against threat-intelligence feeds on the server."))
        hint.setWordWrap(True)
        hint.setObjectName("mutedText")
        hint.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        layout.addWidget(hint)
        self.netflow_box = QCheckBox(self.tr("Share network connections for threat detection"))
        self.netflow_box.setChecked(self._vm.netflow_sharing)
        layout.addWidget(self.netflow_box)
        self.netflow_status = QLabel(self.tr("Not sharing") if not self._vm.netflow_sharing else self.tr("Waiting for first batch…"))
        self.netflow_status.setObjectName("mutedText")
        layout.addWidget(self.netflow_status)
        self.hash_box = QCheckBox(self.tr("Check running programs against known malware hashes"))
        self.hash_box.setToolTip(self.tr("Sends only the SHA-256 and file name of each running program, never the file"))
        self.hash_box.setChecked(self._vm.hash_sharing)
        layout.addWidget(self.hash_box)
        self.hits_list = QListWidget()
        self.hits_list.setMinimumHeight(110)
        self.hits_list.setToolTip(self.tr("Double-click to open the alert in the web app"))
        self.hits_list.itemDoubleClicked.connect(self._open_hit_alert)
        layout.addWidget(self.hits_list)
        return box

    def _build_commands(self) -> QGroupBox:
        box = QGroupBox(self.tr("Commands from the server"))
        box.setObjectName("card")
        layout = QVBoxLayout(box)
        self.policy_label = QLabel()
        self.policy_label.setObjectName("mutedText")
        layout.addWidget(self.policy_label)
        table = QTableView()
        table.setModel(self._commands)
        table.setSelectionBehavior(QTableView.SelectRows)
        table.setEditTriggers(QTableView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        for col, width in enumerate((90, 160, 150, 80)):
            header.setSectionResizeMode(col, QHeaderView.Interactive)
            table.setColumnWidth(col, width)
        header.setStretchLastSection(True)
        table.setMinimumHeight(180)
        layout.addWidget(table)
        self._refresh_policy_label()
        return box

    def _build_audit(self) -> QGroupBox:
        box = QGroupBox(self.tr("Local audit trail"))
        box.setObjectName("card")
        layout = QVBoxLayout(box)
        path = QLabel(self._vm.audit_path)
        path.setObjectName("mutedText")
        path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(path)
        self.audit_list = QListWidget()
        self.audit_list.setMinimumHeight(160)
        layout.addWidget(self.audit_list)
        return box

    # ── Wiring ────────────────────────────────────────────────────────────────

    def _wire(self) -> None:
        vm = self._vm
        self.login_btn.clicked.connect(self._login)
        self.password.returnPressed.connect(self._login)
        self.logout_btn.clicked.connect(vm.logout)
        self.share_box.toggled.connect(vm.set_sharing)
        self.scan_btn.clicked.connect(self._start_scan)
        vm.busy_changed.connect(lambda busy: (self.login_btn.setEnabled(not busy),
                                              self.logout_btn.setEnabled(not busy)))
        vm.logged_in_changed.connect(self._apply_logged_in)
        vm.login_failed.connect(self.login_error.setText)
        vm.state_changed.connect(self._apply_state)
        vm.session_changed.connect(self._apply_session)
        vm.telemetry.connect(self._apply_telemetry)
        vm.command_updated.connect(self._commands.upsert)
        vm.audit_appended.connect(self._append_audit)
        self.netflow_box.toggled.connect(vm.set_netflow_sharing)
        vm.netflow_sharing_changed.connect(self._apply_netflow_sharing)
        self.hash_box.toggled.connect(vm.set_hash_sharing)
        vm.hash_sharing_changed.connect(self.hash_box.setChecked)
        vm.netflow_batch.connect(lambda b: self.netflow_status.setText(
            f"Last check {datetime.now():%H:%M:%S}: {b.get('open', 0)} open, {b.get('sent', 0)} new shared"))
        vm.intel_hit.connect(self._add_hit)
        vm.scan_progress.connect(lambda d: self._scan_line(f"#{d.get('scan_id')} {d.get('stage')} {d.get('progress')}%"))
        vm.scan_completed.connect(self._scan_completed)

    def _login(self) -> None:
        self.login_error.clear()
        self._vm.login(self.username.text(), self.password.text())

    def _start_scan(self) -> None:
        self._vm.start_scan(self.scan_tool.currentText(), self.scan_input.toPlainText())

    def showEvent(self, event) -> None:
        self._refresh_policy_label()  # settings may have changed while hidden
        super().showEvent(event)

    def _refresh_policy_label(self) -> None:
        allowed = ", ".join(self._vm.always_allowed) or "none"
        self.policy_label.setText(f"Policy: {self._vm.command_policy} · always allowed: {allowed} · "
                                  f"file access limited to: {', '.join(self._vm.allowed_dirs) or 'nothing'}")

    # ── Slots ─────────────────────────────────────────────────────────────────

    @Slot(bool)
    def _apply_logged_in(self, logged_in: bool) -> None:
        self.login_box.setVisible(not logged_in)
        self.session_box.setVisible(logged_in)
        if logged_in:
            self.password.clear()
        else:
            self.device_label.setText("–")
            self.expiry_label.setText("–")

    @Slot(str)
    def _apply_state(self, state: str) -> None:
        text, color = STATE_TEXT.get(state, (state, "#9ca3af"))
        text = self.tr(text)
        self.state_label.setText(f"● {text}")
        self.state_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    @Slot(dict)
    def _apply_session(self, info: dict) -> None:
        if not info:
            return
        self.device_label.setText(str(info.get("device_id", "–")))
        expires = info.get("token_expires_at")
        if expires:
            try:
                self.expiry_label.setText(datetime.fromisoformat(expires).astimezone().strftime("%Y-%m-%d %H:%M"))
            except ValueError:
                self.expiry_label.setText(expires)

    @Slot(dict)
    def _apply_telemetry(self, sample: dict) -> None:
        for key, label in self.metric_labels.items():
            value = sample.get(key)
            if key.startswith("net_"):
                label.setText(_fmt_bytes(value))
            elif key.endswith("_percent"):
                label.setText(_fmt_pct(value))
            else:
                label.setText("–" if value is None else str(value))

    @Slot(bool)
    def _apply_netflow_sharing(self, enabled: bool) -> None:
        if self.netflow_box.isChecked() != enabled:
            self.netflow_box.setChecked(enabled)
        self.netflow_status.setText(self.tr("Waiting for first batch…") if enabled else self.tr("Not sharing"))

    @Slot(dict)
    def _add_hit(self, hit: dict) -> None:
        if hit.get("sha256"):                 # known-malware program (process.hashes)
            text = (f"{datetime.now():%H:%M:%S}  {hit.get('process') or '?'}  sha256 {hit['sha256'][:16]}…  "
                    f"({', '.join(hit.get('categories') or [])})")
        else:
            text = (f"{datetime.now():%H:%M:%S}  {hit.get('process') or '?'} → "
                    f"{hit.get('dst_ip')}:{hit.get('dst_port')}  score {hit.get('score')}  "
                    f"({', '.join(hit.get('sources') or [])})")
        self.hits_list.insertItem(0, text)
        url = str(hit.get("url") or "")
        if url.startswith("/alerts/"):        # only server-relative alert links are opened
            self.hits_list.item(0).setData(Qt.UserRole, url)

    def _open_hit_alert(self, item) -> None:
        url = item.data(Qt.UserRole)
        if url:
            QDesktopServices.openUrl(QUrl(self._vm.server_url.rstrip("/") + url))

    @Slot(dict)
    def _append_audit(self, entry: dict) -> None:
        ts = entry.get("ts", "")[11:19]
        extra = ", ".join(f"{k}={v}" for k, v in entry.items() if k not in ("ts", "event") and v not in (None, ""))
        self.audit_list.insertItem(0, f"{ts}  {entry.get('event')}" + (f"  ({extra})" if extra else ""))
        while self.audit_list.count() > 500:
            self.audit_list.takeItem(self.audit_list.count() - 1)

    def _scan_line(self, text: str) -> None:
        self.scan_log.insertItem(0, f"{datetime.now():%H:%M:%S}  {text}")

    @Slot(dict)
    def _scan_completed(self, data: dict) -> None:
        if data.get("success"):
            result = data.get("result") or {}
            summary = result.get("label") or result.get("risk_level") or "done"
            self._scan_line(f"#{data.get('scan_id')} completed: {summary}")
        else:
            self._scan_line(f"#{data.get('scan_id')} failed: {data.get('error')}")
