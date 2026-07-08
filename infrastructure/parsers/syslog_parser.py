"""Syslog parser (RFC 3164 and RFC 5424)."""
import re
import logging
from typing import Iterator
from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

# RFC 5424 pattern: PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
SYSLOG_5424_RE = re.compile(
    r'<(\d+)>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)'
)
# RFC 3164 pattern: TIMESTAMP HOSTNAME MESSAGE
SYSLOG_3164_RE = re.compile(
    r'(\S{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)'
)

class SyslogParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        # Check extension and try a few lines
        if file_path.lower().endswith(('.log', '.syslog', '.txt')):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for _ in range(5):
                        line = f.readline()
                        if not line:
                            break
                        if self._looks_like_syslog(line):
                            return True
            except:
                pass
        return False

    def _looks_like_syslog(self, line: str) -> bool:
        return bool(SYSLOG_5424_RE.match(line) or SYSLOG_3164_RE.match(line))

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
        m = SYSLOG_5424_RE.match(line)
        if m:
            return {
                'format': 'syslog_5424',
                'pri': m.group(1),
                'version': m.group(2),
                'timestamp': m.group(3),
                'hostname': m.group(4),
                'app_name': m.group(5),
                'procid': m.group(6),
                'msgid': m.group(7),
                'structured_data': m.group(8),
                'message': m.group(9),
                'raw': line
            }
        m = SYSLOG_3164_RE.match(line)
        if m:
            return {
                'format': 'syslog_3164',
                'timestamp': m.group(1),
                'hostname': m.group(2),
                'message': m.group(3),
                'raw': line
            }
        return {'format': 'syslog_unknown', 'raw': line}