"""IOC analysis use case: local validation + AI explanation."""
import logging
from injector import inject
from typing import AsyncGenerator, Dict
from domain.interfaces.ai_provider import AIProvider
from infrastructure.analyzers.ioc.ioc_validator import IOCValidator

logger = logging.getLogger(__name__)

class IOCAnalysisUseCase:
    @inject
    def __init__(self, ai_provider: AIProvider):
        self._provider = ai_provider

    async def analyze_ioc(self, ioc_type: str, value: str, model: str) -> AsyncGenerator[Dict, None]:
        yield {'type': 'progress', 'status': 'Validating IOC...'}
        local = IOCValidator.validate(ioc_type, value)

        yield {'type': 'progress', 'status': 'Generating AI explanation...'}

        prompt = f"""You are a senior cyber threat intelligence analyst. Analyze the following Indicator of Compromise (IOC).

**IOC Type:** {ioc_type}
**Value:** {value}

**Local checks performed:**
- Risk score (0-10): {local['risk_score']}
- Notes: {'; '.join(local['notes']) if local['notes'] else 'No suspicious indicators from local checks.'}

Provide a thorough threat analysis:
1. Is this IOC likely malicious? Confidence level.
2. What type of threat (phishing, C2, malware delivery, exfiltration) could this indicate?
3. MITRE ATT&CK techniques potentially involved (e.g., T1071 Application Layer Protocol, T1566 Phishing).
4. Recommended actions for the security team (block, investigate, etc.).
5. Any additional context (campaigns, known associations).

Use markdown formatting with clear headings."""

        report = ""
        try:
            async for token in self._provider.generate(prompt, model):
                report += token
                yield {'type': 'stream', 'token': token}
        except Exception as e:
            logger.error(f"AI generation failed: {e}")
            report += f"\n\n**AI analysis failed**: {e}"
        yield {'type': 'result', 'report': report, 'local_checks': local}