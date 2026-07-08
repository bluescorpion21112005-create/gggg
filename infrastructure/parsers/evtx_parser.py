"""Parser for Windows Event Log files (.evtx)."""
import logging
from typing import Iterator

from domain.interfaces.log_parser import LogParser

logger = logging.getLogger(__name__)

# python-evtx modulini bir necha variantda topishga harakat qilamiz
HAS_EVTX = False
evtx_parser_class = None

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    HAS_EVTX = True
except ImportError:
    try:
        from evtx import PyEvtxParser
        HAS_EVTX = True
        evtx_parser_class = PyEvtxParser
    except ImportError:
        logger.warning("python-evtx library not found. EVTX parsing disabled.")


class EVTXParser(LogParser):
    def detect_format(self, file_path: str) -> bool:
        return file_path.lower().endswith('.evtx') if HAS_EVTX else False

    def parse(self, file_path: str) -> Iterator[dict]:
        if not HAS_EVTX:
            raise RuntimeError("EVTX parser is disabled because python-evtx is not installed.")
        # Ikkita API variantini qo'llab-quvvatlash
        if evtx_parser_class is not None:  # yangi API (PyEvtxParser)
            return self._parse_with_pyevtx(file_path)
        else:
            return self._parse_with_evtx(file_path)

    def _parse_with_evtx(self, file_path: str) -> Iterator[dict]:
        from Evtx.Evtx import Evtx
        import lxml.etree as ET
        try:
            with Evtx(file_path) as evtx:
                for record in evtx.records():
                    try:
                        xml = record.xml()
                        root = ET.fromstring(xml)
                        system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
                        event_id = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text
                        level = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Level').text
                        channel = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Channel').text
                        computer = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Computer').text
                        time_created = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated').attrib['SystemTime']
                        data_dict = {}
                        event_data = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
                        if event_data is not None:
                            for data in event_data.findall('{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                                name = data.attrib.get('Name', '')
                                data_dict[name] = data.text
                        yield {
                            'format': 'evtx',
                            'event_id': event_id,
                            'level': level,
                            'channel': channel,
                            'computer': computer,
                            'timestamp': time_created,
                            'data': data_dict,
                            'raw_xml': xml
                        }
                    except Exception as e:
                        logger.warning(f"Failed to parse EVTX record: {e}")
                        yield {'format': 'evtx', 'error': str(e)}
        except Exception as e:
            logger.error(f"Error reading EVTX file {file_path}: {e}")
            raise

    def _parse_with_pyevtx(self, file_path: str) -> Iterator[dict]:
        import lxml.etree as ET
        try:
            parser = evtx_parser_class(file_path)
            for record in parser.records():
                try:
                    xml = record.get('data')
                    if not xml:
                        continue
                    root = ET.fromstring(xml)
                    system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
                    event_id = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text
                    level = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Level').text
                    channel = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Channel').text
                    computer = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Computer').text
                    time_created = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated').attrib['SystemTime']
                    data_dict = {}
                    event_data = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
                    if event_data is not None:
                        for data in event_data.findall('{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                            name = data.attrib.get('Name', '')
                            data_dict[name] = data.text
                    yield {
                        'format': 'evtx',
                        'event_id': event_id,
                        'level': level,
                        'channel': channel,
                        'computer': computer,
                        'timestamp': time_created,
                        'data': data_dict,
                        'raw_xml': xml
                    }
                except Exception as e:
                    logger.warning(f"Failed to parse EVTX record: {e}")
                    yield {'format': 'evtx', 'error': str(e)}
        except Exception as e:
            logger.error(f"Error reading EVTX file {file_path}: {e}")
            raise