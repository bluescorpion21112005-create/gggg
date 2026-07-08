"""Chat agent with streaming support and production logging."""
import logging
from typing import Any, AsyncGenerator

from injector import inject

from application.agents.base_agent import BaseAgent
from domain.interfaces.ai_provider import AIProvider

logger = logging.getLogger(__name__)


class ChatAgent(BaseAgent):
    """Streams AI responses for chat interactions.

    Does not persist results — chat sessions are managed by SessionManager.
    """

    @inject
    def __init__(self, ai_provider: AIProvider) -> None:
        if ai_provider is None:
            raise ValueError("AIProvider must not be None")
        self._provider = ai_provider

    async def execute(self, payload: Any, model: str = "default") -> str:
        prompt = self._extract_prompt(payload)
        logger.info("ChatAgent.execute: model=%s, prompt_len=%d", model, len(prompt))
        response = ""
        try:
            async for token in self._provider.generate(prompt, model):
                response += token
        except Exception as exc:
            logger.error("ChatAgent.execute failed: %s", exc, exc_info=True)
            raise
        logger.debug("ChatAgent.execute: response_len=%d", len(response))
        return response

    async def stream_execute(self, payload: Any, model: str = "default") -> AsyncGenerator[str, None]:
        prompt = self._extract_prompt(payload)
        logger.info("ChatAgent.stream_execute: model=%s, prompt_len=%d", model, len(prompt))
        token_count = 0
        try:
            async for token in self._provider.generate(prompt, model):
                token_count += 1
                yield token
        except Exception as exc:
            logger.error("ChatAgent.stream_execute failed after %d tokens: %s", token_count, exc, exc_info=True)
            raise
        logger.debug("ChatAgent.stream_execute: complete, %d tokens", token_count)

    @staticmethod
    def _extract_prompt(payload: Any) -> str:
        """Safely extract a text prompt from various payload shapes."""
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            if "message" in payload:
                msg = payload["message"]
                if isinstance(msg, str):
                    return msg
                if isinstance(msg, list):
                    for m in msg:
                        if isinstance(m, dict) and m.get("role") == "user":
                            return m.get("content", "")
            if "content" in payload:
                return str(payload["content"])
        raise ValueError(f"Unable to extract prompt from payload type: {type(payload).__name__}")
