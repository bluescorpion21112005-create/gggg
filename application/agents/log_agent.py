"""Log analysis agent with repository persistence and production logging."""
from __future__ import annotations

import logging
from typing import Any, AsyncGenerator

from injector import inject

from application.agents.base_agent import BaseAgent
from application.use_cases.log_analysis_use_case import LogAnalysisUseCase
from domain.context import AnalysisContext
from domain.entities import AnalysisResult, Severity
from domain.interfaces.repository import Repository

logger = logging.getLogger(__name__)


class LogAgent(BaseAgent):
    @inject
    def __init__(self, use_case: LogAnalysisUseCase, repository: Repository):
        self._use_case = use_case
        self._repo = repository

    async def execute(self, payload: Any, model: str = "default") -> str:
        file_path = payload["file_path"]
        logger.info("LogAgent.execute: file='%s', model=%s", file_path, model)
        report = ""
        threats = {}
        try:
            async for event in self._use_case.analyze_log_file(file_path, model):
                if event["type"] == "result":
                    report = event["report"]
                    threats = event.get("threats", {})
                    break
        except Exception as exc:
            logger.error("LogAgent.execute failed for '%s': %s", file_path, exc, exc_info=True)
            raise

        await self._save_result(file_path, report, threats)
        logger.info("LogAgent.execute: complete for '%s'", file_path)
        return report

    async def stream_execute(self, payload: Any, model: str = "default") -> AsyncGenerator[str, None]:
        file_path = payload["file_path"]
        logger.info("LogAgent.stream_execute: file='%s', model=%s", file_path, model)
        report = ""
        threats = {}
        try:
            async for event in self._use_case.analyze_log_file(file_path, model):
                if event["type"] == "stream":
                    report += event["token"]
                    yield event["token"]
                elif event["type"] == "result":
                    threats = event.get("threats", {})
        except Exception as exc:
            logger.error(
                "LogAgent.stream_execute failed for '%s': %s", file_path, exc, exc_info=True
            )
            raise

        await self._save_result(file_path, report, threats)
        logger.info("LogAgent.stream_execute: complete for '%s'", file_path)

    async def execute_in_pipeline(self, context: AnalysisContext, model: str = "default") -> AnalysisContext:
        if not context.log_file_path:
            return context
        logger.info("LogAgent.execute_in_pipeline: file='%s'", context.log_file_path)
        report = ""
        context.log_threats = {}
        try:
            async for event in self._use_case.analyze_log_file(context.log_file_path, model):
                if event["type"] == "stream":
                    report += event["token"]
                elif event["type"] == "result":
                    context.log_threats = event.get("threats", {})
        except Exception as exc:
            logger.error("LogAgent pipeline failed: %s", exc, exc_info=True)
            context.error = str(exc)
        context.messages.append("Log analysis complete")
        return context

    async def _save_result(self, file_path: str, report: str, threats: dict) -> None:
        try:
            severity = Severity.HIGH if threats else Severity.LOW
            result = AnalysisResult(
                title=f"Log Analysis: {file_path.split('/')[-1].split(chr(92))[-1]}",
                description=report[:500],
                severity=severity,
                metadata={"file_path": file_path, "threats_detected": threats},
            )
            await self._repo.save_analysis(result)
            logger.debug("LogAgent: analysis saved (id=%s)", result.id)
        except Exception as exc:
            logger.warning("LogAgent: could not save analysis result: %s", exc)
