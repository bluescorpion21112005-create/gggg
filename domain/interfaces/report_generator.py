"""Interface for report generators (PDF, Markdown, HTML)."""
from abc import ABC, abstractmethod
from pathlib import Path


class ReportGenerator(ABC):
    @abstractmethod
    def generate(self, data: dict, output_path: Path) -> None:
        """Produce a report file at the given path."""
        ...