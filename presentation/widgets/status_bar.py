from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PySide6.QtCore import Slot

class StatusBarWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0,0,0,0)
        self.label = QLabel("Ready")
        layout.addWidget(self.label)

    @Slot(str)
    def show_message(self, message: str):
        self.label.setText(message)