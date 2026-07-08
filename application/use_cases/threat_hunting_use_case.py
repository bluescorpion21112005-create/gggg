"""Threat Hunting use case — AI-powered query analysis."""
import logging
from typing import AsyncGenerator, Dict

from injector import inject

from domain.interfaces.ai_provider import AIProvider

logger = logging.getLogger(__name__)


class ThreatHuntingUseCase:
    @inject
    def __init__(self, ai_provider: AIProvider):
        self._provider = ai_provider

    async def hunt(self, query: str, model: str) -> AsyncGenerator[Dict, None]:
        """Submit a threat hunting query to the AI and stream results."""
        prompt = f"""You are a senior threat hunter with expertise in MITRE ATT&CK, SIEM analysis,
and adversary tradecraft. Perform a threat hunt based on the following query.

**Threat Hunt Query:** {query}

Provide a structured analysis:
1. **Hypothesis** — What threat actor behaviour or technique are we hunting for?
2. **Data Sources** — Which logs/telemetry should be collected (EDR, SIEM, DNS, proxy)?
3. **Detection Logic** — Specific queries, patterns, or rules (Sigma, KQL, SPL examples).
4. **MITRE ATT&CK Mapping** — Relevant techniques and sub-techniques.
5. **Expected Findings** — What would a positive hunt look like?
6. **False Positive Mitigation** — How to reduce noise.
7. **Recommended Response** — Actions if the threat is confirmed.

Use markdown formatting with clear headings."""

        logger.info("ThreatHuntingUseCase: starting hunt for query='%s'", query[:80])
        yield {"type": "progress", "status": "Threat hunting in progress..."}

        report = ""
        try:
            async for token in self._provider.generate(prompt, model):
                report += token
                yield {"type": "stream", "token": token}
        except Exception as exc:
            logger.error("AI generation failed during threat hunt: %s", exc, exc_info=True)
            report += f"\n\n**AI analysis failed**: {exc}"

        logger.info("ThreatHuntingUseCase: hunt complete (%d chars)", len(report))
        yield {"type": "result", "report": report}
