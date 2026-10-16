"""Interface for log parsers."""
from abc import ABC, abstractmethod
from typing import Iterator


class LogParser(ABC):
    @abstractmethod
    def parse(self, file_path: str) -> Iterator[dict]:
        """Parse a log file and yield normalized log entries."""
        ...

    @abstractmethod
    def detect_format(self, file_path: str) -> bool:
        """Return True if the file appears to be this format."""
        ...