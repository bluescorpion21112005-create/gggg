"""IOC analysis UI with type selector, input, and report."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QLabel, QComboBox, QLineEdit, QProgressBar)
from PySide6.QtCore import Slot
from presentation.viewmodels.ioc_viewmodel import IOCViewModel
from presentation.widgets.markdown_viewer import MarkdownViewer

class IOCView(QWidget):
    def __init__(self, viewmodel: IOCViewModel):
        super().__init__()
        self._vm = viewmodel
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Input area
        input_layout = QHBoxLayout()
        self.type_combo = QComboBox()
        self.type_combo.addItems(["IP", "Domain", "URL", "Hash", "Email", "Filename"])
        input_layout.addWidget(QLabel(self.tr("IOC Type:")))
        input_layout.addWidget(self.type_combo)

        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText(self.tr("Enter IOC value..."))
        input_layout.addWidget(self.value_edit, 1)

        self.analyze_btn = QPushButton(self.tr("Analyze"))
        self.analyze_btn.clicked.connect(self._start_analysis)
        input_layout.addWidget(self.analyze_btn)
        layout.addLayout(input_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Report only
        self.report_viewer = MarkdownViewer()
        layout.addWidget(self.report_viewer, 1)

    def _connect_signals(self):
        self._vm.report_changed.connect(self._update_report)
        self._vm.busy_changed.connect(self._on_busy)
        self._vm.progress_message.connect(lambda msg: self.progress_bar.setFormat(msg))

    def _start_analysis(self):
        ioc_type = self.type_combo.currentText().lower()
        value = self.value_edit.text().strip()
        self._vm.analyze_ioc(ioc_type, value)

    @Slot(str)
    def _update_report(self, md: str):
        self.report_viewer.setMarkdown(md)

    @Slot(bool)
    def _on_busy(self, busy: bool):
        self.progress_bar.setVisible(busy)
        self.analyze_btn.setEnabled(not busy)