"""A QTextEdit subclass that renders Markdown with syntax highlighting."""
from PySide6.QtWidgets import QTextEdit
from PySide6.QtGui import QFont
import markdown
from PySide6.QtCore import Qt


class MarkdownViewer(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        # Bundled techy monospace (falls back to a system mono when absent)
        self.setFont(QFont("Share Tech Mono", 10))

    def setMarkdown(self, text: str):
        html = markdown.markdown(text, extensions=["fenced_code", "codehilite", "tables"])
        # Apply Pygments highlighting to code blocks
        # Simple approach: replace <pre><code> blocks with highlighted HTML
        # For full implementation, use a library like markdown2 with codehilite.
        # Here we'll just set the HTML as is for now.
        self.setHtml(html)