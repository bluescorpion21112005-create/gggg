"""Ollama local LLM provider — async streaming only, no blocking fallbacks."""
from __future__ import annotations

import logging
from typing import AsyncGenerator

import aiohttp
from injector import inject

from core.exceptions import AIProviderError
from domain.interfaces.ai_provider import AIProvider

logger = logging.getLogger(__name__)


try:
    from ollama import AsyncClient as OllamaAsyncClient

    _HAS_ASYNC_CLIENT = True
except ImportError:  # pragma: no cover
    _HAS_ASYNC_CLIENT = False
    OllamaAsyncClient = None  # type: ignore[assignment, misc]


class OllamaProvider(AIProvider):
    """Async Ollama provider.

    Requires `ollama >= 0.1.0` with AsyncClient support.
    The sync fallback has been removed because it blocks the asyncio event loop.
    """

    @inject
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3"):
        if not _HAS_ASYNC_CLIENT:
            raise AIProviderError(
                "ollama package with AsyncClient support is required. "
                "Install or upgrade: pip install ollama>=0.1.0"
            )
        self._host = host
        self._model = model
        self._client = OllamaAsyncClient(host=host)
        logger.info("OllamaProvider initialised: host=%s model=%s", host, model)

    async def generate(
        self, prompt: str, model: str = None, **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream tokens from the Ollama model."""
        active_model = model or self._model
        # Strip provider-specific prefixes if passed from config (e.g. "ollama/llama3")
        if "/" in active_model and not active_model.startswith("accounts/"):
            active_model = active_model.split("/", 1)[1]

        options = {
            k: v
            for k, v in kwargs.items()
            if k not in ("temperature", "max_tokens")
        }
        if "temperature" in kwargs:
            options["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            options["num_predict"] = kwargs["max_tokens"]

        logger.debug("OllamaProvider.generate: model=%s, prompt_len=%d", active_model, len(prompt))
        try:
            stream = await self._client.generate(
                model=active_model,
                prompt=prompt,
                stream=True,
                options=options or None,
            )
            async for response in stream:
                token = response.get("response", "")
                if token:
                    yield token
        except Exception as exc:
            logger.error("OllamaProvider.generate failed: %s", exc, exc_info=True)
            raise AIProviderError(f"Ollama generation error: {exc}") from exc

    async def list_models(self) -> list[str]:
        """Return available model names from the local Ollama instance."""
        try:
            models_info = await self._client.list()
            return [m["name"] for m in models_info.get("models", [])]
        except Exception as exc:
            logger.warning("OllamaProvider.list_models failed: %s", exc)
            return [self._model]

    async def _loaded_models(self, session_timeout) -> list:
        """Models in memory with the share held in GPU VRAM (Ollama /api/ps: size, size_vram)."""
        try:
            async with aiohttp.ClientSession(timeout=session_timeout) as session:
                async with session.get(f"{self._host.rstrip('/')}/api/ps") as resp:
                    if resp.status != 200:
                        return []
                    payload = await resp.json()
        except Exception:  # older Ollama without /api/ps, or a transient error
            return []
        out = []
        for m in payload.get("models", []):
            size, vram = m.get("size") or 0, m.get("size_vram") or 0
            out.append({"name": m.get("name", "?"), "gpu_percent": round(100 * vram / size) if size else 0})
        return out

    async def health_check(self) -> dict:
        """Ping the Ollama /api/tags endpoint to verify server is reachable."""
        tags_url = f"{self._host.rstrip('/')}/api/tags"
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(tags_url) as resp:
                    if resp.status != 200:
                        return {
                            "healthy": False,
                            "provider": "ollama",
                            "error": f"HTTP {resp.status}",
                        }
                    payload = await resp.json()
            models = [m["name"] for m in payload.get("models", [])]
            return {
                "healthy": True,
                "provider": "ollama",
                "host": self._host,
                "models": len(models),
                "model_list": models,
                "loaded": await self._loaded_models(session_timeout=timeout),
            }
        except Exception as exc:
            logger.debug("OllamaProvider.health_check failed: %s", exc)
            return {"healthy": False, "provider": "ollama", "error": str(exc)}
