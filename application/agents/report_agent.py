"""Report generation agent."""
from __future__ import annotations

import logging
from typing import Any
from injector import inject

from application.agents.base_agent import BaseAgent
from application.use_cases.report_use_case import ReportUseCase
from domain.context import AnalysisContext
from uuid import UUID

logger = logging.getLogger(__name__)


class ReportAgent(BaseAgent):
    @inject
    def __init__(self, use_case: ReportUseCase):
        self._use_case = use_case

    async def execute(self, payload: Any, model: str = "default") -> str:
        analysis_id = UUID(payload["analysis_id"])
        fmt = payload.get("format", "pdf")
        output_dir = payload.get("output_dir", "./reports")
        extra_notes = payload.get("extra_notes")
        logger.info("ReportAgent: generating %s report for analysis %s", fmt, analysis_id)
        path = await self._use_case.generate_from_analysis(
            analysis_id, fmt, output_dir, extra_notes
        )
        logger.info("ReportAgent: report saved to %s", path)
        return f"Report generated: {path}"

    async def execute_in_pipeline(self, context: AnalysisContext, model: str = "default") -> AnalysisContext:
        # Report generation inside a pipeline is a post-step requiring a persisted analysis ID.
        # Context passes through; callers should invoke execute() directly after saving.
        return context
