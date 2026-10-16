"""ViewModel for report generation.

Communicates exclusively through the Orchestrator — no direct repository access.
"""
import logging

from PySide6.QtCore import Signal
from qasync import asyncSlot
from injector import inject

from application.orchestrator import Orchestrator
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class ReportViewModel(BaseViewModel):
    analyses_list_changed = Signal(list)
    report_path = Signal(str)

    @inject
    def __init__(self, orchestrator: Orchestrator):
        super().__init__()
        self._orchestrator = orchestrator

    @asyncSlot()
    async def refresh_analyses(self):
        """Fetch recent analyses via the Orchestrator's repository."""
        try:
            analyses = await self._orchestrator.list_recent_analyses()
            summaries = [
                {
                    "id": str(a.id),
                    "title": a.title,
                    "date": a.created_at.isoformat(),
                }
                for a in analyses
            ]
            self.analyses_list_changed.emit(summaries)
            logger.debug("ReportViewModel.refresh_analyses: %d analyses", len(summaries))
        except Exception as exc:
            logger.error("ReportViewModel.refresh_analyses failed: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Failed to load analyses: {exc}")

    @asyncSlot(str, str, str, str)
    async def generate_report(
        self,
        analysis_id: str,
        fmt: str,
        output_dir: str,
        extra_notes: str = "",
    ):
        if not analysis_id:
            self.error_occurred.emit("No analysis selected.")
            return
        self.is_busy = True
        logger.info(
            "ReportViewModel.generate_report: id=%s fmt=%s", analysis_id, fmt
        )
        try:
            result = await self._orchestrator.dispatch(
                "generate_report",
                {
                    "analysis_id": analysis_id,
                    "format": fmt,
                    "output_dir": output_dir,
                    "extra_notes": extra_notes,
                },
            )
            path = result.replace("Report generated: ", "")
            self.report_path.emit(path)
            self.status_message.emit(f"Report saved: {path}")
            logger.info("ReportViewModel.generate_report: saved to '%s'", path)
        except Exception as exc:
            logger.error("ReportViewModel.generate_report failed: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Report generation failed: {exc}")
        finally:
            self.is_busy = False
