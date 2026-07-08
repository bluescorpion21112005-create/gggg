"""Report generation view."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QLabel, QComboBox, QFileDialog, QTextEdit, QListWidget,
                               QListWidgetItem, QGroupBox, QFormLayout)
from PySide6.QtCore import Slot
from presentation.viewmodels.report_viewmodel import ReportViewModel

class ReportView(QWidget):
    def __init__(self, viewmodel: ReportViewModel):
        super().__init__()
        self._vm = viewmodel
        self._setup_ui()
        self._connect_signals()
        # initial load
        self._vm.refresh_analyses()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Analysis selection
        group = QGroupBox("Select Analysis")
        form = QFormLayout()
        self.analysis_combo = QComboBox()
        form.addRow("Analysis:", self.analysis_combo)
        group.setLayout(form)
        layout.addWidget(group)

        # Format selection
        format_group = QGroupBox("Output Format")
        format_layout = QHBoxLayout()
        self.format_combo = QComboBox()
        self.format_combo.addItems(["pdf", "markdown", "html"])
        format_layout.addWidget(QLabel("Format:"))
        format_layout.addWidget(self.format_combo)
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # Output directory
        dir_layout = QHBoxLayout()
        self.dir_label = QLabel("./reports")
        dir_layout.addWidget(QLabel("Output Directory:"))
        dir_layout.addWidget(self.dir_label)
        browse_dir_btn = QPushButton("Browse...")
        browse_dir_btn.clicked.connect(self._browse_dir)
        dir_layout.addWidget(browse_dir_btn)
        layout.addLayout(dir_layout)

        # Extra notes (optional)
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Additional analyst notes (will be expanded by AI)...")
        self.notes_edit.setMaximumHeight(80)
        layout.addWidget(self.notes_edit)

        # Generate button
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self._generate)
        layout.addWidget(self.generate_btn)

        # Result path
        self.result_label = QLabel("")
        layout.addWidget(self.result_label)
        layout.addStretch()

    def _connect_signals(self):
        self._vm.analyses_list_changed.connect(self._populate_analyses)
        self._vm.report_path.connect(self._on_report_generated)

    @Slot(list)
    def _populate_analyses(self, analyses):
        self.analysis_combo.clear()
        for a in analyses:
            self.analysis_combo.addItem(f"{a['title']} ({a['date']})", a['id'])

    def _browse_dir(self):
        dir = QFileDialog.getExistingDirectory(self, "Choose Output Directory")
        if dir:
            self.dir_label.setText(dir)

    def _generate(self):
        analysis_id = self.analysis_combo.currentData()
        format = self.format_combo.currentText()
        output_dir = self.dir_label.text()
        notes = self.notes_edit.toPlainText()
        self._vm.generate_report(analysis_id, format, output_dir, notes)

    @Slot(str)
    def _on_report_generated(self, path: str):
        self.result_label.setText(f"Saved to: {path}")