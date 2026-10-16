"""Integration tests for log parsers with sample data."""
import tempfile
import os
from infrastructure.parsers.syslog_parser import SyslogParser
from infrastructure.parsers.apache_parser import ApacheParser

def test_syslog_parser():
    parser = SyslogParser()
    sample = "<34>1 2024-01-01T00:00:00.000Z myhost app 1234 - - Hello world"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(sample)
        f.flush()
        path = f.name
    try:
        entries = list(parser.parse(path))
    finally:
        os.unlink(path)
    assert len(entries) == 1
    assert entries[0]['hostname'] == 'myhost'
    assert entries[0]['message'] == 'Hello world'

def test_apache_parser():
    parser = ApacheParser()
    sample = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(sample)
        f.flush()
        entries = list(parser.parse(f.name))
    assert len(entries) == 1
    assert entries[0]['status'] == '200'

def test_parser_auto_detection():
    from infrastructure.parsers.auto_detector import AutoDetector
    from infrastructure.parsers.syslog_parser import SyslogParser
    from infrastructure.parsers.apache_parser import ApacheParser
    detector = AutoDetector([SyslogParser(), ApacheParser()])
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write("<34>1 2024-01-01T00:00:00.000Z host app 1 - - test")
        f.flush()
        path = f.name
    try:
        parser = detector.detect(path)
    finally:
        os.unlink(path)
    assert isinstance(parser, SyslogParser)