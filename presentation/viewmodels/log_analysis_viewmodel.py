"""ViewModel for Log Analysis."""
import logging

from PySide6.QtCore import Signal
from qasync import asyncSlot
from injector import inject

from application.orchestrator import Orchestrator
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class LogAnalysisViewModel(BaseViewModel):
    report_changed = Signal(str)
    entries_changed = Signal(list)
    threats_detected = Signal(dict)

    @inject
    def __init__(self, orchestrator: Orchestrator):
        super().__init__()
        self._orchestrator = orchestrator
        self._report = ""

    @asyncSlot(str)
    async def analyze_file(self, file_path: str):
        """Stream log analysis results from the agent."""
        if not file_path.strip():
            self.error_occurred.emit("No file path provided.")
            return

        self.is_busy = True
        self._report = ""
        self.report_changed.emit("")
        self.entries_changed.emit([])
        self.threats_detected.emit({})
        logger.info("LogAnalysisViewModel: starting analysis for '%s'", file_path)

        try:
            async for token in self._orchestrator.dispatch_stream(
                "log_analysis", {"file_path": file_path}
            ):
                self._report += token
                self.report_changed.emit(self._report)
        except Exception as exc:
            logger.error(
                "LogAnalysisViewModel: analysis failed for '%s': %s", file_path, exc, exc_info=True
            )
            self.error_occurred.emit(f"Log analysis failed: {exc}")
        finally:
            self.is_busy = False
            logger.info(
                "LogAnalysisViewModel: analysis complete for '%s' (%d chars)",
                file_path,
                len(self._report),
            )
