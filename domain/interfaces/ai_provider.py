"""Abstract interface for AI model providers."""
from abc import ABC, abstractmethod
from typing import AsyncGenerator


class AIProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, model: str, **kwargs) -> AsyncGenerator[str, None]:
        """Stream tokens from the AI model."""
        ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        """Return available model identifiers."""
        ...

    async def health_check(self) -> dict:
        """Optional runtime health check for observability."""
        return {"healthy": True, "provider": type(self).__name__}