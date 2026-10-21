"""Status-bar indicator for the Cybrix server connection."""
from PySide6.QtCore import Slot
from PySide6.QtWidgets import QLabel

_STATES = {
    "connected": ("●  Server: online", "#22c55e"),
    "connecting": ("●  Server: connecting…", "#f59e0b"),
    "disconnected": ("●  Server: offline", "#9ca3af"),
    "auth_failed": ("●  Server: login required", "#ef4444"),
}


class ConnectionIndicator(QLabel):
    def __init__(self, state: str = "disconnected"):
        super().__init__()
        self.set_state(state)

    @Slot(str)
    def set_state(self, state: str) -> None:
        text, color = _STATES.get(state, _STATES["disconnected"])
        self.setText(text)
        self.setStyleSheet(f"color: {color}; padding: 0 8px;")
        self.setToolTip(f"Realtime connection: {state}")
