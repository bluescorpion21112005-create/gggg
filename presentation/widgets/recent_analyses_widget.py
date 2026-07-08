"""List of recent analysis results."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel
from PySide6.QtCore import Slot
from domain.entities import AnalysisResult

class RecentAnalysesWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        title = QLabel("Recent Analyses")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

    @Slot(list)
    def update_analyses(self, analyses: list):
        self.list_widget.clear()
        for analysis in analyses:
            item = QListWidgetItem(f"{analysis.title} - {analysis.severity.value}")
            self.list_widget.addItem(item)