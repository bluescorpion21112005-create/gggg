"""IOC analysis agent with repository persistence and production logging."""
from __future__ import annotations

import logging
from typing import Any, AsyncGenerator

from injector import inject

from application.agents.base_agent import BaseAgent
from application.use_cases.ioc_analysis_use_case import IOCAnalysisUseCase
from domain.context import AnalysisContext
from domain.entities import AnalysisResult, Severity
from domain.interfaces.repository import Repository

logger = logging.getLogger(__name__)


class IOCAgent(BaseAgent):
    @inject
    def __init__(self, use_case: IOCAnalysisUseCase, repository: Repository):
        self._use_case = use_case
        self._repo = repository

    async def execute(self, payload: Any, model: str = "default") -> str:
        ioc_type = payload["type"]
        value = payload["value"]
        logger.info("IOCAgent.execute: type=%s value=%s model=%s", ioc_type, value, model)
        report = ""
        local_checks = {}
        try:
            async for event in self._use_case.analyze_ioc(ioc_type, value, model):
                if event["type"] == "result":
                    report = event["report"]
                    local_checks = event.get("local_checks", {})
        except Exception as exc:
            logger.error("IOCAgent.execute failed: %s", exc, exc_info=True)
            raise

        await self._save_result(ioc_type, value, report, local_checks)
        logger.info("IOCAgent.execute: complete for %s:%s", ioc_type, value)
        return report

    async def stream_execute(self, payload: Any, model: str = "default") -> AsyncGenerator[str, None]:
        ioc_type = payload["type"]
        value = payload["value"]
        logger.info("IOCAgent.stream_execute: type=%s value=%s model=%s", ioc_type, value, model)
        report = ""
        local_checks = {}
        try:
            async for event in self._use_case.analyze_ioc(ioc_type, value, model):
                if event["type"] == "stream":
                    report += event["token"]
                    yield event["token"]
                elif event["type"] == "result":
                    local_checks = event.get("local_checks", {})
        except Exception as exc:
            logger.error("IOCAgent.stream_execute failed: %s", exc, exc_info=True)
            raise

        await self._save_result(ioc_type, value, report, local_checks)
        logger.info("IOCAgent.stream_execute: complete for %s:%s", ioc_type, value)

    async def execute_in_pipeline(self, context: AnalysisContext, model: str = "default") -> AnalysisContext:
        if not (context.ioc_type and context.ioc_value):
            return context
        logger.info("IOCAgent.execute_in_pipeline: %s:%s", context.ioc_type, context.ioc_value)
        report = ""
        try:
            async for event in self._use_case.analyze_ioc(context.ioc_type, context.ioc_value, model):
                if event["type"] == "stream":
                    report += event["token"]
                elif event["type"] == "result":
                    context.ioc_result = event.get("local_checks", {})
                    context.ioc_result["report"] = report
        except Exception as exc:
            logger.error("IOCAgent pipeline failed: %s", exc, exc_info=True)
            context.error = str(exc)
        context.messages.append(f"IOC analysis complete: {context.ioc_value}")
        return context

    async def _save_result(
        self, ioc_type: str, value: str, report: str, local_checks: dict
    ) -> None:
        try:
            risk = local_checks.get("risk_score", 0)
            severity = Severity.HIGH if risk >= 7 else (Severity.MEDIUM if risk >= 4 else Severity.LOW)
            result = AnalysisResult(
                title=f"IOC Analysis: {ioc_type.upper()} — {value[:60]}",
                description=report[:500],
                severity=severity,
                metadata={"ioc_type": ioc_type, "ioc_value": value, **local_checks},
            )
            await self._repo.save_analysis(result)
            logger.debug("IOCAgent: analysis saved (id=%s)", result.id)
        except Exception as exc:
            logger.warning("IOCAgent: could not save analysis result: %s", exc)
