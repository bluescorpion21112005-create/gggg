"""Auto-detect log format by querying each parser."""
from typing import List, Optional
from domain.interfaces.log_parser import LogParser

class AutoDetector:
    def __init__(self, parsers: List[LogParser]):
        self._parsers = parsers

    def detect(self, file_path: str) -> Optional[LogParser]:
        for parser in self._parsers:
            try:
                if parser.detect_format(file_path):
                    return parser
            except Exception:
                continue
        return None