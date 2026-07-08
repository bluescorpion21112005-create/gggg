"""ViewModel for IOC Analysis."""
import logging

from PySide6.QtCore import Signal
from qasync import asyncSlot
from injector import inject

from application.orchestrator import Orchestrator
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class IOCViewModel(BaseViewModel):
    report_changed = Signal(str)
    local_checks_changed = Signal(dict)

    @inject
    def __init__(self, orchestrator: Orchestrator):
        super().__init__()
        self._orchestrator = orchestrator
        self._report = ""

    @asyncSlot(str, str)
    async def analyze_ioc(self, ioc_type: str, value: str):
        """Stream IOC analysis results from the agent."""
        if not value.strip():
            self.error_occurred.emit("Please enter an IOC value.")
            return

        self.is_busy = True
        self._report = ""
        self.report_changed.emit("")
        logger.info("IOCViewModel: starting analysis type=%s value=%s", ioc_type, value)

        try:
            async for token in self._orchestrator.dispatch_stream(
                "ioc_analysis", {"type": ioc_type, "value": value}
            ):
                self._report += token
                self.report_changed.emit(self._report)
        except Exception as exc:
            logger.error(
                "IOCViewModel: analysis failed type=%s value=%s: %s",
                ioc_type, value, exc, exc_info=True
            )
            self.error_occurred.emit(f"IOC analysis failed: {exc}")
        finally:
            self.is_busy = False
            logger.info(
                "IOCViewModel: complete type=%s value=%s (%d chars)",
                ioc_type, value, len(self._report)
            )
