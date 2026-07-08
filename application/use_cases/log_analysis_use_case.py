"""Log analysis use case: parsing, threat detection, AI report generation."""
import logging
import re
from injector import inject
from typing import Dict, List, AsyncGenerator
from domain.interfaces.log_parser import LogParser
from domain.interfaces.ai_provider import AIProvider
from infrastructure.parsers.auto_detector import AutoDetector

logger = logging.getLogger(__name__)

# Predefined threat patterns (compiled regexes)
THREAT_PATTERNS = {
    "Brute Force": re.compile(r'(failed|invalid|incorrect)\s+(login|password|authentication)', re.IGNORECASE),
    "Privilege Escalation": re.compile(r'(sudo|su\s-|RunAs|Administrator|privilege\s+escalation)', re.IGNORECASE),
    "Suspicious PowerShell": re.compile(r'(powershell\.exe|cmdlet|Invoke-|IEX\(|FromBase64String)', re.IGNORECASE),
    "Encoded Command": re.compile(r'(-enc|-EncodedCommand|base64)', re.IGNORECASE),
    "Lateral Movement": re.compile(r'(psexec|wmi|winrm|schtasks\s+/create|remote\s+desktop)', re.IGNORECASE),
    "Persistence": re.compile(r'(Registry|Run\s+Key|Startup|Scheduled\s+Task|service\s+create)', re.IGNORECASE),
    "Living off the Land": re.compile(r'(certutil|bitsadmin|mshta|regsvr32|rundll32|wmic)', re.IGNORECASE),
}

class LogAnalysisUseCase:
    @inject
    def __init__(self, parsers: List[LogParser], ai_provider: AIProvider):
        self._detector = AutoDetector(parsers)
        self._provider = ai_provider

    async def analyze_log_file(self, file_path: str, model: str) -> AsyncGenerator[Dict, None]:
        """Yield progress dictionaries: {'type': 'progress', 'status': str} 
        or {'type': 'result', 'report': str}. Final yield is the report."""
        yield {'type': 'progress', 'status': 'Detecting log format...'}
        parser = self._detector.detect(file_path)
        if not parser:
            raise ValueError(f"Unable to detect log format for {file_path}")

        yield {'type': 'progress', 'status': 'Parsing log entries...'}
        entries = []
        detection_results = {}
        for entry in parser.parse(file_path):
            entries.append(entry)
            # Run threat patterns on relevant fields
            raw = entry.get('raw', str(entry))
            for threat_name, pattern in THREAT_PATTERNS.items():
                if pattern.search(raw):
                    detection_results.setdefault(threat_name, 0)
                    detection_results[threat_name] += 1

        yield {'type': 'progress', 'status': f'Parsed {len(entries)} entries. Detecting threats...'}

        if not entries:
            yield {
                'type': 'result',
                'report': "No log entries were parsed from the provided file.",
                'threats': {},
                'entries_count': 0,
            }
            return

        # Build a summary of threats
        threat_summary = ""
        if detection_results:
            threat_summary = "## Detected Threats\n"
            for threat, count in detection_results.items():
                threat_summary += f"- **{threat}**: {count} occurrences\n"
        else:
            threat_summary = "No predefined threats detected by pattern matching."

        # Prepare prompt for AI
        # Limit entries sent to AI to avoid token overflow
        sample_entries = entries[:20]  # first 20 for context
        prompt = f"""You are a senior cybersecurity analyst. Analyze the following log file summary and detected threats.

Log format: {entries[0].get('format', 'unknown')} (first few entries sample)
{chr(10).join([str(e) for e in sample_entries])}

{threat_summary}

Provide:
1. Executive Summary
2. Detailed Technical Findings (including MITRE ATT&CK techniques if applicable)
3. Risk Score (0-10)
4. Concrete Recommendations for remediation
Use markdown formatting."""

        yield {'type': 'progress', 'status': 'Generating AI analysis...'}
        report = ""
        try:
            async for token in self._provider.generate(prompt, model):
                report += token
                yield {'type': 'stream', 'token': token}
        except Exception as e:
            logger.error(f"AI generation failed: {e}")
            report += f"\n\n**AI analysis failed**: {e}"

        yield {'type': 'result', 'report': report, 'threats': detection_results, 'entries_count': len(entries)}