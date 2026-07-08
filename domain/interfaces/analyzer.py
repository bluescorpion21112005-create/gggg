"""Abstract base for all analyzers (plugin interface)."""
from abc import ABC, abstractmethod
from typing import Any


class BaseAnalyzer(ABC):
    @abstractmethod
    def can_handle(self, data: Any) -> bool:
        """Check if this analyzer can process the given data."""
        ...

    @abstractmethod
    async def analyze(self, data: Any) -> dict:
        """Run the analysis and return a structured result."""
        ...