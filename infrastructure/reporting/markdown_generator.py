"""Markdown report generator."""
import logging
from pathlib import Path
from datetime import datetime
from domain.interfaces.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class MarkdownReportGenerator(ReportGenerator):
    def generate(self, data: dict, output_path: Path) -> None:
        md = f"# {data.get('title', 'Cybrix AI Analysis Report')}\n\n"
        md += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n"
        md += f"**Risk Score:** {data.get('risk_score', 'N/A')}\n\n"

        md += "## Executive Summary\n\n"
        md += data.get('executive_summary', 'No summary provided.') + "\n\n"

        md += "## Technical Findings\n\n"
        findings = data.get('findings', [])
        if findings:
            for f in findings:
                md += f"- {f}\n"
        else:
            md += "No findings.\n"
        md += "\n"

        md += "## MITRE ATT&CK Mapping\n\n"
        for tech in data.get('mitre_techniques', []):
            md += f"- {tech}\n"
        md += "\n"

        md += "## Recommendations\n\n"
        for rec in data.get('recommendations', []):
            md += f"- {rec}\n"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)
        logger.info(f"Markdown report saved to {output_path}")