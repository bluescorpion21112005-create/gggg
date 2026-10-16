"""Log Analysis view with drag-drop, table, and report."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QLabel, QFileDialog, QSplitter, QTableWidget,
                               QTableWidgetItem, QHeaderView, QProgressBar)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from presentation.viewmodels.log_analysis_viewmodel import LogAnalysisViewModel
from presentation.widgets.markdown_viewer import MarkdownViewer
import os

class LogAnalysisView(QWidget):
    def __init__(self, viewmodel: LogAnalysisViewModel):
        super().__init__()
        self._vm = viewmodel
        self._setup_ui()
        self._connect_signals()
        self.setAcceptDrops(True)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Toolbar
        toolbar = QHBoxLayout()
        self.file_label = QLabel(self.tr("No file selected"))
        toolbar.addWidget(self.file_label)
        browse_btn = QPushButton(self.tr("Browse..."))
        browse_btn.clicked.connect(self._browse_file)
        toolbar.addWidget(browse_btn)
        self.analyze_btn = QPushButton(self.tr("Analyze"))
        self.analyze_btn.clicked.connect(self._start_analysis)
        self.analyze_btn.setEnabled(False)
        toolbar.addWidget(self.analyze_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # indeterminate
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Splitter: table on top, report below
        splitter = QSplitter(Qt.Vertical)

        # Entries table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels([self.tr("Timestamp"), self.tr("Level"), self.tr("Source"), self.tr("Message")])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        splitter.addWidget(self.table)

        # Report markdown viewer
        self.report_viewer = MarkdownViewer()
        splitter.addWidget(self.report_viewer)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

    def _connect_signals(self):
        self._vm.report_changed.connect(self._update_report)
        self._vm.entries_changed.connect(self._populate_table)
        self._vm.progress_message.connect(self._update_progress)
        self._vm.busy_changed.connect(self._on_busy)

    def _browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Log File", "", "Log Files (*.log *.evtx *.txt *.json *.csv);;All Files (*)")
        if file_path:
            self._select_file(file_path)

    def _select_file(self, path: str):
        self._selected_file = path
        self.file_label.setText(os.path.basename(path))
        self.analyze_btn.setEnabled(True)

    def _start_analysis(self):
        if hasattr(self, '_selected_file'):
            self._vm.analyze_file(self._selected_file)

    @Slot(str)
    def _update_report(self, report_md: str):
        self.report_viewer.setMarkdown(report_md)

    @Slot(list)
    def _populate_table(self, entries: list):
        self.table.setRowCount(0)
        for row, entry in enumerate(entries):
            self.table.insertRow(row)
            # Extract common fields
            ts = entry.get('timestamp', '')
            level = entry.get('level', '')
            source = entry.get('hostname', entry.get('computer', ''))
            message = entry.get('message', entry.get('raw', str(entry)[:200]))
            self.table.setItem(row, 0, QTableWidgetItem(str(ts)))
            self.table.setItem(row, 1, QTableWidgetItem(str(level)))
            self.table.setItem(row, 2, QTableWidgetItem(str(source)))
            self.table.setItem(row, 3, QTableWidgetItem(str(message)))

    @Slot(str)
    def _update_progress(self, msg: str):
        self.progress_bar.setVisible(True)
        self.progress_bar.setFormat(msg)

    @Slot(bool)
    def _on_busy(self, busy: bool):
        self.progress_bar.setVisible(busy)
        self.analyze_btn.setEnabled(not busy)

    # Drag-and-drop support
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isfile(file_path):
                self._select_file(file_path)
                break