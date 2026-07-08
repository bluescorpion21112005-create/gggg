"""Generic firewall log parser (iptables, Windows Firewall)."""
import re
import logging
from typing import Iterator
from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

# iptables log example: IN=eth0 OUT= MAC=... SRC=... DST=... LEN=...
IPTABLES_RE = re.compile(r'IN=(\S+)\s+OUT=(\S+)\s+(?:MAC=\S+\s+)?SRC=(\S+)\s+DST=(\S+)\s+LEN=(\d+)')
# Windows Firewall (simplified)
WINFIRE_RE = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(ALLOW|DROP)\s+(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)')

class FirewallParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(5):
                line = f.readline()
                if IPTABLES_RE.search(line) or WINFIRE_RE.search(line):
                    return True
        return False

    def parse(self, file_path: str) -> Iterator[dict]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Try iptables
                m = IPTABLES_RE.search(line)
                if m:
                    yield {
                        'format': 'iptables',
                        'in_iface': m.group(1),
                        'out_iface': m.group(2),
                        'src': m.group(3),
                        'dst': m.group(4),
                        'length': m.group(5),
                        'raw': line
                    }
                    continue
                # Try Windows Firewall
                m = WINFIRE_RE.search(line)
                if m:
                    yield {
                        'format': 'windows_firewall',
                        'timestamp': m.group(1),
                        'action': m.group(2),
                        'protocol': m.group(3),
                        'src': m.group(4),
                        'dst': m.group(5),
                        'src_port': m.group(6),
                        'dst_port': m.group(7),
                        'raw': line
                    }