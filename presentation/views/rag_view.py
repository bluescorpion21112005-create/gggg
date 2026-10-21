"""RAG view: file loader, question input, answer with citations."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QLabel, QTextEdit, QFileDialog, QListWidget,
                               QListWidgetItem, QProgressBar)
from PySide6.QtCore import Slot
from presentation.viewmodels.rag_viewmodel import RAGViewModel
from presentation.widgets.markdown_viewer import MarkdownViewer

class RAGView(QWidget):
    def __init__(self, viewmodel: RAGViewModel):
        super().__init__()
        self._vm = viewmodel
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Document management
        doc_layout = QHBoxLayout()
        self.doc_label = QLabel(self.tr("Knowledge Base Documents:"))
        doc_layout.addWidget(self.doc_label)
        load_btn = QPushButton(self.tr("Add Documents..."))
        load_btn.clicked.connect(self._browse_documents)
        doc_layout.addWidget(load_btn)
        layout.addLayout(doc_layout)

        self.doc_list = QListWidget()
        layout.addWidget(self.doc_list)

        # Progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Question area
        q_layout = QHBoxLayout()
        self.question_edit = QTextEdit()
        self.question_edit.setPlaceholderText(self.tr("Ask a question about your documents..."))
        self.question_edit.setMaximumHeight(80)
        q_layout.addWidget(self.question_edit)
        self.ask_btn = QPushButton(self.tr("Ask"))
        self.ask_btn.clicked.connect(self._ask_question)
        q_layout.addWidget(self.ask_btn)
        layout.addLayout(q_layout)

        # Answer
        self.answer_viewer = MarkdownViewer()
        layout.addWidget(self.answer_viewer, 1)

    def _connect_signals(self):
        self._vm.answer_changed.connect(self._update_answer)
        self._vm.documents_loaded.connect(self._populate_documents)
        self._vm.busy_changed.connect(self._on_busy)
        self._vm.progress_message.connect(lambda msg: self.progress.setFormat(msg))

    def _browse_documents(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select documents",
                                                "", "Documents (*.pdf *.docx *.txt *.md);;All Files (*)")
        if files:
            self._vm.load_documents(';'.join(files))

    def _ask_question(self):
        question = self.question_edit.toPlainText().strip()
        if question:
            self._vm.ask_question(question)
            self.question_edit.clear()

    @Slot(str)
    def _update_answer(self, md: str):
        self.answer_viewer.setMarkdown(md)

    @Slot(list)
    def _populate_documents(self, docs):
        self.doc_list.clear()
        for doc in docs:
            self.doc_list.addItem(QListWidgetItem(doc.get('metadata', {}).get('source', doc['id'])))

    @Slot(bool)
    def _on_busy(self, busy: bool):
        self.progress.setVisible(busy)
        self.ask_btn.setEnabled(not busy)