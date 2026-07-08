"""Apache access log parser (Common and Combined formats)."""
import re
import logging
from typing import Iterator
from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

# Combined Log Format: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
APACHE_COMBINED_RE = re.compile(
    r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+\"([^\"]+)\"\s+(\d{3})\s+(\S+)\s+\"([^\"]+)\"\s+\"([^\"]+)\"'
)
# Common Log Format: %h %l %u %t \"%r\" %>s %b
APACHE_COMMON_RE = re.compile(
    r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+\"([^\"]+)\"\s+(\d{3})\s+(\S+)'
)

class ApacheParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        if 'apache' in file_path.lower() or file_path.lower().endswith('.access.log'):
            return True
        try:
            with open(file_path, 'r') as f:
                for _ in range(5):
                    line = f.readline()
                    if APACHE_COMBINED_RE.match(line) or APACHE_COMMON_RE.match(line):
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
                entry = self._parse_line(line)
                if entry:
                    yield entry

    def _parse_line(self, line: str) -> dict | None:
        m = APACHE_COMBINED_RE.match(line)
        if m:
            return {
                'format': 'apache_combined',
                'remote_host': m.group(1),
                'logname': m.group(2),
                'user': m.group(3),
                'timestamp': m.group(4),
                'request': m.group(5),
                'status': m.group(6),
                'response_size': m.group(7),
                'referer': m.group(8),
                'user_agent': m.group(9),
                'raw': line
            }
        m = APACHE_COMMON_RE.match(line)
        if m:
            return {
                'format': 'apache_common',
                'remote_host': m.group(1),
                'logname': m.group(2),
                'user': m.group(3),
                'timestamp': m.group(4),
                'request': m.group(5),
                'status': m.group(6),
                'response_size': m.group(7),
                'raw': line
            }
        return None