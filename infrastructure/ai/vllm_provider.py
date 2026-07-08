"""vLLM local/remote provider (OpenAI-compatible endpoint)."""
from __future__ import annotations

from infrastructure.ai.openai_compatible_provider import OpenAICompatibleProvider


class VllmProvider(OpenAICompatibleProvider):
    def __init__(self, model: str, host: str = "http://localhost:8000/v1"):
        super().__init__(
            provider_name="vllm",
            model=model,
            api_key_env=None,
            base_url=host,
        )
