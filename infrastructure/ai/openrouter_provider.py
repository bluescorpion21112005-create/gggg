"""OpenRouter provider adapter."""
from __future__ import annotations

from infrastructure.ai.openai_compatible_provider import OpenAICompatibleProvider


class OpenRouterProvider(OpenAICompatibleProvider):
    def __init__(self, model: str, api_key_env: str = "OPENROUTER_API_KEY"):
        super().__init__(
            provider_name="openrouter",
            model=model,
            api_key_env=api_key_env,
            base_url="https://openrouter.ai/api/v1",
        )
