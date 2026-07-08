"""Parser for CSV log files."""
import csv
import logging
from typing import Iterator
from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

class CSVParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        return file_path.lower().endswith('.csv')

    def parse(self, file_path: str) -> Iterator[dict]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                # fallback to reading as list
                f.seek(0)
                reader = csv.reader(f)
                headers = next(reader, None)
                for row in reader:
                    yield {'format': 'csv', 'data': dict(zip(headers, row)) if headers else row}
                return
            for row in reader:
                yield {'format': 'csv', 'data': row}