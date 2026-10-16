"""Toast notifications: small cards stacked in the top-right corner that fade out."""
from __future__ import annotations

from typing import List

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
from PySide6.QtWidgets import QFrame, QGraphicsOpacityEffect, QLabel, QVBoxLayout, QWidget

LEVELS = ("info", "success", "warning", "error")


class Toast(QFrame):
    def __init__(self, parent: QWidget, title: str, message: str, level: str, duration_ms: int):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setProperty("level", level if level in LEVELS else "info")
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setFixedWidth(340)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        head = QLabel(title)
        head.setObjectName("toastTitle")
        head.setTextFormat(Qt.PlainText)  # server-controlled text is never rendered as HTML
        layout.addWidget(head)
        if message:
            body = QLabel(message)
            body.setObjectName("toastBody")
            body.setTextFormat(Qt.PlainText)
            body.setWordWrap(True)
            layout.addWidget(body)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(400)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        QTimer.singleShot(duration_ms, self.dismiss)

    def mousePressEvent(self, event) -> None:
        self.dismiss()

    def dismiss(self) -> None:
        if self._fade.state() == QPropertyAnimation.Running:
            return
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self.close)
        self._fade.start()


class ToastManager:
    """Owns the toasts of one window and keeps them stacked under its top-right corner."""

    MARGIN = 16
    SPACING = 8
    MAX_VISIBLE = 4

    def __init__(self, host: QWidget):
        self._host = host
        self._toasts: List[Toast] = []

    def show(self, title: str, message: str = "", level: str = "info", duration_ms: int = 5000) -> Toast:
        toast = Toast(self._host, title, message, level, duration_ms)
        toast.destroyed.connect(lambda *_: self._forget(toast))
        self._toasts.append(toast)
        while len(self._toasts) > self.MAX_VISIBLE:
            self._toasts.pop(0).close()
        toast.adjustSize()
        toast.show()
        toast.raise_()
        self.reposition()
        return toast

    def _forget(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        self.reposition()

    def reposition(self) -> None:
        y = self.MARGIN + 40  # below the toolbar
        for toast in list(self._toasts):
            try:
                toast.move(self._host.width() - toast.width() - self.MARGIN, y)
                y += toast.height() + self.SPACING
            except RuntimeError:  # already deleted on the C++ side
                self._toasts.remove(toast)
