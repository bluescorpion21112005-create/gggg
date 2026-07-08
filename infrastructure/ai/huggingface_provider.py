"""HuggingFace Inference provider via OpenAI-compatible router."""
from __future__ import annotations

from infrastructure.ai.openai_compatible_provider import OpenAICompatibleProvider


class HuggingFaceProvider(OpenAICompatibleProvider):
    """Uses HF router OpenAI-compatible endpoint for chat-like models."""

    def __init__(self, model: str, api_key_env: str = "HF_TOKEN"):
        super().__init__(
            provider_name="huggingface",
            model=model,
            api_key_env=api_key_env,
            base_url="https://router.huggingface.co/v1",
        )
