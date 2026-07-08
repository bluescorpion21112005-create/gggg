"""Domain interfaces (abstract base classes)."""
from .ai_provider import AIProvider
from .analyzer import BaseAnalyzer
from .log_parser import LogParser
from .report_generator import ReportGenerator
from .repository import Repository

__all__ = ["AIProvider", "BaseAnalyzer", "LogParser", "ReportGenerator", "Repository"]