"""Nginx access log parser (similar to Apache combined)."""
import re
import logging
from typing import Iterator
from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

# Nginx default combined format
NGINX_RE = re.compile(
    r'(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+\"([^\"]+)\"\s+(\d{3})\s+(\d+)\s+\"([^\"]+)\"\s+\"([^\"]+)\"'
)

class NginxParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        if 'nginx' in file_path.lower() or file_path.lower().endswith('.access.log'):
            return True
        try:
            with open(file_path, 'r') as f:
                for _ in range(5):
                    line = f.readline()
                    if NGINX_RE.match(line):
                        return True
        except:
            pass
        return False

    def parse(self, file_path: str) -> Iterator[dict]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = NGINX_RE.match(line)
                if m:
                    yield {
                        'format': 'nginx',
                        'remote_addr': m.group(1),
                        'remote_user': m.group(2),
                        'timestamp': m.group(3),
                        'request': m.group(4),
                        'status': m.group(5),
                        'body_bytes_sent': m.group(6),
                        'http_referer': m.group(7),
                        'http_user_agent': m.group(8),
                        'raw': line
                    }