"""Orchestrator: coordinates agents and exposes provider / repository operations to ViewModels.

The Orchestrator is the single point of contact between the presentation layer and the
application/infrastructure layers. ViewModels never import agents, repositories, or
providers directly.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional

from injector import inject

from domain.interfaces.ai_provider import AIProvider
from domain.interfaces.repository import Repository
from domain.entities import AnalysisResult
from application.agents.base_agent import BaseAgent
from domain.context import AnalysisContext

logger = logging.getLogger(__name__)


class Orchestrator:
    @inject
    def __init__(
        self,
        ai_provider: AIProvider,
        repository: Repository,
        default_model: str = "llama3",
    ):
        self._provider = ai_provider
        self._repository = repository
        self._agents: Dict[str, BaseAgent] = {}
        self.default_model = default_model

    # ── Agent registry ────────────────────────────────────────────────────────

    def register_agent(self, name: str, agent: BaseAgent) -> None:
        self._agents[name] = agent
        logger.debug("Orchestrator: registered agent '%s'", name)

    # ── Dispatch ─────────────────────────────────────────────────────────────

    async def dispatch(self, command: str, payload: Any, model: str = None) -> str:
        """Execute an agent and return the complete result."""
        resolved_model = model or self.default_model
        agent = self._get_agent(command)
        logger.info("Orchestrator.dispatch: command='%s', model=%s", command, resolved_model)
        try:
            result = await agent.execute(payload, model=resolved_model)
            logger.info("Orchestrator.dispatch: '%s' complete", command)
            return result
        except Exception as exc:
            logger.error(
                "Orchestrator.dispatch: '%s' failed: %s", command, exc, exc_info=True
            )
            raise

    async def dispatch_stream(
        self, command: str, payload: Any, model: str = None
    ) -> AsyncGenerator[str, None]:
        """Execute an agent and stream tokens."""
        resolved_model = model or self.default_model
        agent = self._get_agent(command)
        logger.info(
            "Orchestrator.dispatch_stream: command='%s', model=%s", command, resolved_model
        )
        token_count = 0
        try:
            if hasattr(agent, "stream_execute"):
                async for token in agent.stream_execute(payload, resolved_model):
                    token_count += 1
                    yield token
            else:
                result = await agent.execute(payload, resolved_model)
                yield result
        except Exception as exc:
            logger.error(
                "Orchestrator.dispatch_stream: '%s' failed after %d tokens: %s",
                command,
                token_count,
                exc,
                exc_info=True,
            )
            raise
        logger.info(
            "Orchestrator.dispatch_stream: '%s' complete (%d tokens)", command, token_count
        )

    # ── Pipeline ──────────────────────────────────────────────────────────────

    async def run_pipeline(
        self, agent_names: List[str], initial_context: AnalysisContext, model: str = None
    ) -> AnalysisContext:
        """Run a sequence of agents, passing context through each."""
        resolved_model = model or self.default_model
        context = initial_context
        for name in agent_names:
            agent = self._get_agent(name)
            logger.info("Orchestrator.run_pipeline: running '%s'", name)
            try:
                context = await agent.execute_in_pipeline(context, resolved_model)
            except Exception as exc:
                logger.error(
                    "Orchestrator.run_pipeline: agent '%s' failed: %s", name, exc, exc_info=True
                )
                context.error = str(exc)
                break
        return context

    # ── Repository pass-through ───────────────────────────────────────────────

    async def list_recent_analyses(self, limit: int = 50) -> List[AnalysisResult]:
        """Expose repository query to ViewModels without direct infrastructure coupling."""
        return await self._repository.list_analyses(limit=limit)

    # ── Provider observability ────────────────────────────────────────────────

    async def provider_health(self) -> dict:
        """Return provider health without leaking provider internals to the UI."""
        try:
            if hasattr(self._provider, "health_check"):
                return await self._provider.health_check()
        except Exception as exc:
            logger.warning("Orchestrator.provider_health failed: %s", exc)
            return {"healthy": False, "provider": type(self._provider).__name__, "error": str(exc)}
        return {"healthy": True, "provider": type(self._provider).__name__}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_agent(self, command: str) -> BaseAgent:
        agent = self._agents.get(command)
        if not agent:
            raise ValueError(
                f"No agent registered for command '{command}'. "
                f"Available: {list(self._agents.keys())}"
            )
        return agent
