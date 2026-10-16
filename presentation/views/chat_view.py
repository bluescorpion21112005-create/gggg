"""Chat interface similar to ChatGPT."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QScrollArea, QTextEdit,
                               QPushButton, QHBoxLayout)
from PySide6.QtCore import Qt, Signal, Slot
from presentation.viewmodels.chat_viewmodel import ChatViewModel
from presentation.widgets.chat_bubble import ChatBubble


class ChatView(QWidget):
    """View for AI chat."""
    message_sent = Signal(str)

    def __init__(self, viewmodel: ChatViewModel):
        super().__init__()
        self._vm = viewmodel
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Messages scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; }")
        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.messages_container)
        layout.addWidget(self.scroll_area, 1)

        # Input area
        input_layout = QHBoxLayout()
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText(self.tr("Type your cybersecurity question..."))
        self.message_input.setMaximumHeight(100)
        input_layout.addWidget(self.message_input)

        self.send_button = QPushButton(self.tr("Send"))
        self.send_button.setObjectName("sendButton")
        self.send_button.clicked.connect(self._send_message)
        input_layout.addWidget(self.send_button)
        layout.addLayout(input_layout)

    def _connect_signals(self):
        self._vm.messages_changed.connect(self._render_messages)
        self._vm.busy_changed.connect(self._set_busy_state)

    def _send_message(self):
        text = self.message_input.toPlainText().strip()
        if text:
            self.message_input.clear()
            self._vm.send_message(text)

    @Slot(list)
    def _render_messages(self, messages):
        # Clear and rebuild (simple approach; could be optimized)
        while self.messages_layout.count():
            child = self.messages_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        for msg in messages:
            bubble = ChatBubble(msg["role"], msg["content"])
            self.messages_layout.addWidget(bubble)

        # Scroll to bottom
        from PySide6.QtCore import QTimer
        QTimer.singleShot(10, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        scrollbar = self.scroll_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _set_busy_state(self, busy: bool):
        self.send_button.setEnabled(not busy)
        if busy:
            self.message_input.setPlaceholderText(self.tr("Cybrix is thinking..."))
        else:
            self.message_input.setPlaceholderText(self.tr("Type your cybersecurity question..."))