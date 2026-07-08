"""Repository interface for persisting analysis results and chat history."""
from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID
from domain.entities import AnalysisResult


class Repository(ABC):
    @abstractmethod
    async def save_analysis(self, result: AnalysisResult) -> None:
        ...

    @abstractmethod
    async def get_analysis(self, analysis_id: UUID) -> Optional[AnalysisResult]:
        ...

    @abstractmethod
    async def list_analyses(self, limit: int = 50) -> list[AnalysisResult]:
        ...