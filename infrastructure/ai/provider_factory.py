"""Config-driven provider factory and provider adapters."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from core.config import AIProviderConfig
from core.exceptions import AIProviderError
from domain.interfaces.ai_provider import AIProvider
from infrastructure.ai.fireworks_provider import FireworksProvider
from infrastructure.ai.huggingface_provider import HuggingFaceProvider
from infrastructure.ai.lmstudio_provider import LMStudioProvider
from infrastructure.ai.ollama_provider import OllamaProvider
from infrastructure.ai.openai_provider import OpenAIProvider
from infrastructure.ai.openrouter_provider import OpenRouterProvider
from infrastructure.ai.vllm_provider import VllmProvider

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProviderCapabilities:
    streaming: bool = True
    chat: bool = True
    embeddings: bool = False
    local_runtime: bool = False


class ProviderFactory:
    """Creates providers from config and keeps provider selection out of UI."""

    _builders: dict[str, Callable[[AIProviderConfig], AIProvider]]
    _capabilities: dict[str, ProviderCapabilities]

    def __init__(self) -> None:
        self._builders = {
            "ollama": self._build_ollama,
            "openai": self._build_openai,
            "huggingface": self._build_huggingface,
            "openrouter": self._build_openrouter,
            "lm_studio": self._build_lmstudio,
            "lmstudio": self._build_lmstudio,
            "vllm": self._build_vllm,
            "fireworks": self._build_fireworks,
        }
        self._capabilities = {
            "ollama": ProviderCapabilities(local_runtime=True),
            "openai": ProviderCapabilities(),
            "huggingface": ProviderCapabilities(),
            "openrouter": ProviderCapabilities(),
            "lm_studio": ProviderCapabilities(local_runtime=True),
            "lmstudio": ProviderCapabilities(local_runtime=True),
            "vllm": ProviderCapabilities(local_runtime=True),
            "fireworks": ProviderCapabilities(),
        }

    def create(self, provider_name: str, config: AIProviderConfig) -> AIProvider:
        key = provider_name.lower().strip()
        builder = self._builders.get(key)
        if not builder:
            raise AIProviderError(f"Unsupported provider '{provider_name}'")

        provider = builder(config)
        logger.info("Provider selected: %s model=%s", key, config.model)
        return provider

    def capabilities(self, provider_name: str) -> ProviderCapabilities:
        return self._capabilities.get(provider_name.lower().strip(), ProviderCapabilities())

    @staticmethod
    def _build_ollama(config: AIProviderConfig) -> AIProvider:
        return OllamaProvider(host=config.host or "http://localhost:11434", model=config.model)

    @staticmethod
    def _build_openai(config: AIProviderConfig) -> AIProvider:
        return OpenAIProvider(model=config.model, api_key_env=config.api_key_env or "OPENAI_API_KEY")

    @staticmethod
    def _build_huggingface(config: AIProviderConfig) -> AIProvider:
        return HuggingFaceProvider(model=config.model, api_key_env=config.api_key_env or "HF_TOKEN")

    @staticmethod
    def _build_openrouter(config: AIProviderConfig) -> AIProvider:
        return OpenRouterProvider(model=config.model, api_key_env=config.api_key_env or "OPENROUTER_API_KEY")

    @staticmethod
    def _build_lmstudio(config: AIProviderConfig) -> AIProvider:
        return LMStudioProvider(model=config.model, host=config.host or "http://localhost:1234/v1")

    @staticmethod
    def _build_vllm(config: AIProviderConfig) -> AIProvider:
        return VllmProvider(model=config.model, host=config.host or "http://localhost:8000/v1")

    @staticmethod
    def _build_fireworks(config: AIProviderConfig) -> AIProvider:
        return FireworksProvider(api_key_env=config.api_key_env or "FIREWORKS_API_KEY", model=config.model)
