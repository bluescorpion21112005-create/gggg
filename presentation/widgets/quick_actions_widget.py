"""Quick action buttons for the dashboard."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel
from PySide6.QtCore import Signal

class QuickActionsWidget(QWidget):
    action_triggered = Signal(str)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        title = QLabel(self.tr("Quick Actions"))
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        actions = ["New Malware Scan", "Analyze Log File", "Threat Hunting", "Generate Report"]
        for action in actions:
            btn = QPushButton(action)
            btn.clicked.connect(lambda _, a=action: self.action_triggered.emit(a))
            layout.addWidget(btn)