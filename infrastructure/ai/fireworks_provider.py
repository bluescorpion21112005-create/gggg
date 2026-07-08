"""Fireworks AI provider — extends OpenAICompatibleProvider."""
from __future__ import annotations

from infrastructure.ai.openai_compatible_provider import OpenAICompatibleProvider


class FireworksProvider(OpenAICompatibleProvider):
    """Fireworks AI uses an OpenAI-compatible chat endpoint."""

    def __init__(
        self,
        model: str = "accounts/fireworks/models/llama-v3-70b-instruct",
        api_key_env: str = "FIREWORKS_API_KEY",
    ):
        super().__init__(
            provider_name="fireworks",
            model=model,
            api_key_env=api_key_env,
            base_url="https://api.fireworks.ai/inference/v1",
            default_timeout=30.0,
        )
