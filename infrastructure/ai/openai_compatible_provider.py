"""Reusable OpenAI-compatible provider adapter."""
from __future__ import annotations

import logging
from typing import AsyncGenerator

from openai import AsyncOpenAI

from core.exceptions import AIProviderError
from domain.interfaces.ai_provider import AIProvider
from infrastructure.security.vault import Vault

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(AIProvider):
    """Adapter for providers exposing OpenAI-compatible chat API."""

    def __init__(
        self,
        provider_name: str,
        model: str,
        api_key_env: str | None = None,
        base_url: str | None = None,
        default_timeout: float = 60.0,
    ) -> None:
        self._provider_name = provider_name
        self._model = model
        self._api_key_env = api_key_env
        api_key = Vault.get_api_key(provider_name, api_key_env) if api_key_env else "not-required"
        if api_key_env and not api_key:
            raise AIProviderError(
                f"{provider_name} API key not found. Configure keyring or env var '{api_key_env}'."
            )

        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=default_timeout)

    async def generate(self, prompt: str, model: str = None, **kwargs) -> AsyncGenerator[str, None]:
        try:
            stream = await self._client.chat.completions.create(
                model=model or self._model,
                messages=[{"role": "user", "content": prompt}],
                stream=True,
                temperature=kwargs.get("temperature", 0.2),
                max_tokens=kwargs.get("max_tokens"),
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                content = getattr(delta, "content", None) if delta else None
                if content:
                    yield content
        except Exception as exc:
            logger.exception("Provider %s streaming failed", self._provider_name)
            raise AIProviderError(f"{self._provider_name} provider error: {exc}") from exc

    async def list_models(self) -> list[str]:
        try:
            models = await self._client.models.list()
            return [m.id for m in models.data]
        except Exception:
            # Some compatible backends do not expose /models reliably.
            return [self._model]

    async def health_check(self) -> dict:
        try:
            models = await self.list_models()
            return {
                "healthy": True,
                "provider": self._provider_name,
                "models": len(models),
                "model": self._model,
            }
        except Exception as exc:
            return {"healthy": False, "provider": self._provider_name, "error": str(exc)}
