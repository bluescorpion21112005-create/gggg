"""Chat message bubble with Markdown rendering."""
from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt
from presentation.widgets.markdown_viewer import MarkdownViewer


class ChatBubble(QFrame):
    def __init__(self, role: str, content: str):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setObjectName("chatBubble")
        if role == "user":
            self.setProperty("role", "user")
        else:
            self.setProperty("role", "assistant")

        layout = QVBoxLayout(self)
        self.viewer = MarkdownViewer()
        self.viewer.setMarkdown(content)
        layout.addWidget(self.viewer)