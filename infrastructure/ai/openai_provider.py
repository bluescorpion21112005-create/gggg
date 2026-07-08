"""OpenAI provider adapter."""
from __future__ import annotations

from infrastructure.ai.openai_compatible_provider import OpenAICompatibleProvider


class OpenAIProvider(OpenAICompatibleProvider):
    def __init__(self, model: str, api_key_env: str = "OPENAI_API_KEY"):
        super().__init__(
            provider_name="openai",
            model=model,
            api_key_env=api_key_env,
            base_url="https://api.openai.com/v1",
        )
