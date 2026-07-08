"""Threat hunting agent with repository persistence and production logging."""
from __future__ import annotations

import logging
from typing import Any, AsyncGenerator

from injector import inject

from application.agents.base_agent import BaseAgent
from application.use_cases.threat_hunting_use_case import ThreatHuntingUseCase
from domain.context import AnalysisContext
from domain.entities import AnalysisResult, Severity
from domain.interfaces.repository import Repository

logger = logging.getLogger(__name__)


class ThreatHuntingAgent(BaseAgent):
    @inject
    def __init__(self, use_case: ThreatHuntingUseCase, repository: Repository):
        self._use_case = use_case
        self._repo = repository

    async def execute(self, payload: Any, model: str = "default") -> str:
        query = payload.get("query", "") if isinstance(payload, dict) else str(payload)
        logger.info("ThreatHuntingAgent.execute: query='%s', model=%s", query[:80], model)
        report = ""
        try:
            async for event in self._use_case.hunt(query, model):
                if event["type"] == "result":
                    report = event["report"]
        except Exception as exc:
            logger.error("ThreatHuntingAgent.execute failed: %s", exc, exc_info=True)
            raise

        await self._save_result(query, report)
        logger.info("ThreatHuntingAgent.execute: complete (%d chars)", len(report))
        return report

    async def stream_execute(self, payload: Any, model: str = "default") -> AsyncGenerator[str, None]:
        query = payload.get("query", "") if isinstance(payload, dict) else str(payload)
        logger.info("ThreatHuntingAgent.stream_execute: query='%s', model=%s", query[:80], model)
        report = ""
        try:
            async for event in self._use_case.hunt(query, model):
                if event["type"] == "stream":
                    report += event["token"]
                    yield event["token"]
        except Exception as exc:
            logger.error("ThreatHuntingAgent.stream_execute failed: %s", exc, exc_info=True)
            raise

        await self._save_result(query, report)
        logger.info("ThreatHuntingAgent.stream_execute: complete (%d chars)", len(report))

    async def execute_in_pipeline(self, context: AnalysisContext, model: str = "default") -> AnalysisContext:
        if not context.ioc_result:
            return context
        query = (
            f"Find activity related to IOC '{context.ioc_value}' "
            f"(type: {context.ioc_type}, risk score: {context.ioc_result.get('risk_score', 'N/A')})"
        )
        logger.info("ThreatHuntingAgent.execute_in_pipeline: '%s'", query[:80])
        report = ""
        try:
            async for event in self._use_case.hunt(query, model):
                if event["type"] == "stream":
                    report += event["token"]
                elif event["type"] == "result":
                    context.hunting_result = report
        except Exception as exc:
            logger.error("ThreatHuntingAgent pipeline failed: %s", exc, exc_info=True)
            context.error = str(exc)
        context.messages.append("Threat hunting complete")
        return context

    async def _save_result(self, query: str, report: str) -> None:
        try:
            result = AnalysisResult(
                title=f"Threat Hunt: {query[:80]}",
                description=report[:500],
                severity=Severity.MEDIUM,
                metadata={"query": query},
            )
            await self._repo.save_analysis(result)
            logger.debug("ThreatHuntingAgent: analysis saved (id=%s)", result.id)
        except Exception as exc:
            logger.warning("ThreatHuntingAgent: could not save analysis result: %s", exc)
