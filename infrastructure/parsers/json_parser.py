"""Parser for JSON log files (array of objects or newline-delimited JSON)."""
import json
import logging
from typing import Iterator
from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

class JSONParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        if file_path.lower().endswith('.json'):
            return True
        try:
            with open(file_path, 'r') as f:
                first_char = f.read(1)
                if first_char == '[' or first_char == '{':
                    return True
        except:
            pass
        return False

    def parse(self, file_path: str) -> Iterator[dict]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
        # Try to parse as a JSON array
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    yield {'format': 'json', 'data': item}
                return
        except json.JSONDecodeError:
            pass
        # Try newline-delimited JSON (NDJSON)
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield {'format': 'json', 'data': obj}
            except json.JSONDecodeError:
                yield {'format': 'json_error', 'raw': line}