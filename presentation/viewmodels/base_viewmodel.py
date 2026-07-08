"""Base ViewModel class providing common signals."""
from PySide6.QtCore import QObject, Signal


class BaseViewModel(QObject):
    """Base class for all ViewModels. Provides error and status reporting."""

    error_occurred = Signal(str)
    status_message = Signal(str)
    busy_changed = Signal(bool)
    progress_message = Signal(str)

    def __init__(self):
        super().__init__()
        self._is_busy = False

    @property
    def is_busy(self) -> bool:
        return self._is_busy

    @is_busy.setter
    def is_busy(self, value: bool):
        if self._is_busy != value:
            self._is_busy = value
            self.busy_changed.emit(value)