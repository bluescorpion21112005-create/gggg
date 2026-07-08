from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator

from domain.context import AnalysisContext

class BaseAgent(ABC):
    @abstractmethod
    async def execute(self, payload: Any, model: str = "default") -> str:
        ...

    async def stream_execute(self, payload: Any, model: str = "default") -> AsyncGenerator[str, None]:
        """Override to provide streaming output."""
        result = await self.execute(payload, model)
        yield result

    async def execute_in_pipeline(self, context: AnalysisContext, model: str = "default") -> AnalysisContext:
        """Zanjirda ishlash uchun – sukut bo‘yicha kontekstni o‘zgartirmasdan qaytaradi."""
        return context