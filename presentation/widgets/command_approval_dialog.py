"""Asks the local user to approve a server-issued command (with an auto-deny countdown)."""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from domain.interfaces.backend import ApprovalDecision, CommandApprover

COMMAND_DESCRIPTIONS = {
    "log_analysis": "Analyse a log file on this computer with the local AI agent",
    "ioc_analysis": "Look up an indicator of compromise",
    "malware_analysis": "Statically analyse a file on this computer",
    "threat_hunting": "Run a threat-hunting query with the local AI agent",
    "report": "Generate a report from a stored analysis",
    "system_snapshot": "Share running processes, listening ports and disks",
    "yara_scan": "Scan a file or folder with the signed YARA rules (only inside your allowed folders)",
}


class CommandApprovalDialog(QDialog):
    decided = Signal(str)  # ApprovalDecision value

    def __init__(self, command: Dict[str, Any], timeout: float, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("approvalDialog")
        self.setWindowTitle(self.tr("Server command — approval required"))
        self.setWindowModality(Qt.NonModal)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setMinimumWidth(460)
        self._remaining = int(timeout)
        self._decision: Optional[ApprovalDecision] = None

        type_ = command.get("type", "?")
        layout = QVBoxLayout(self)
        title = QLabel(f"<b>{type_.replace('_', ' ').title()}</b>")
        title.setObjectName("sectionTitle")
        title.setTextFormat(Qt.RichText)
        layout.addWidget(title)
        desc = QLabel(COMMAND_DESCRIPTIONS.get(type_, "Unknown command"))
        desc.setWordWrap(True)
        layout.addWidget(desc)
        origin = QLabel(f"Requested by: {command.get('server', '?')}")
        origin.setTextFormat(Qt.PlainText)  # never render server-controlled text as HTML
        layout.addWidget(origin)

        details = QPlainTextEdit(json.dumps(command.get("payload") or {}, indent=2, ensure_ascii=False))
        details.setReadOnly(True)
        details.setMaximumHeight(140)
        layout.addWidget(details)

        self._countdown = QLabel()
        self._countdown.setObjectName("approvalCountdown")
        layout.addWidget(self._countdown)

        buttons = QHBoxLayout()
        self._deny_btn = QPushButton(self.tr("Deny"))
        self._deny_btn.setObjectName("dangerButton")
        self._always_btn = QPushButton(f"Always allow “{type_}”")
        self._once_btn = QPushButton(self.tr("Allow once"))
        self._once_btn.setObjectName("primaryButton")
        self._deny_btn.setDefault(True)  # Enter must never approve by accident
        for btn in (self._deny_btn, self._always_btn, self._once_btn):
            buttons.addWidget(btn)
        layout.addLayout(buttons)

        self._deny_btn.clicked.connect(lambda: self._decide(ApprovalDecision.DENY))
        self._always_btn.clicked.connect(lambda: self._decide(ApprovalDecision.ALLOW_ALWAYS))
        self._once_btn.clicked.connect(lambda: self._decide(ApprovalDecision.ALLOW_ONCE))

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._update_countdown()

    def _tick(self) -> None:
        self._remaining -= 1
        if self._remaining <= 0:
            self._decide(ApprovalDecision.DENY)
        else:
            self._update_countdown()

    def _update_countdown(self) -> None:
        self._countdown.setText(f"Automatically denied in {self._remaining}s")

    def _decide(self, decision: ApprovalDecision) -> None:
        if self._decision is not None:
            return
        self._decision = decision
        self._timer.stop()
        self.decided.emit(decision.value)
        self.close()

    def closeEvent(self, event) -> None:  # window closed = deny
        if self._decision is None:
            self._decide(ApprovalDecision.DENY)
        super().closeEvent(event)


class QtCommandApprover(CommandApprover):
    """Shows a non-blocking dialog per command and awaits the user's choice."""

    def __init__(self):
        self.parent_widget: Optional[QWidget] = None  # set by MainWindow so dialogs are centred on it

    async def request_approval(self, command: Dict[str, Any], timeout: float) -> ApprovalDecision:
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        dialog = CommandApprovalDialog(command, timeout, self.parent_widget)
        dialog.decided.connect(lambda value: future.done() or future.set_result(ApprovalDecision(value)))
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        try:
            # Safety net in case the dialog's own timer never fires.
            return await asyncio.wait_for(future, timeout + 5)
        except asyncio.TimeoutError:
            dialog.close()
            return ApprovalDecision.DENY
