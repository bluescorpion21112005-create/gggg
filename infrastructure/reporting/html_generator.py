"""HTML report generator using Markdown to HTML conversion."""
import logging
from pathlib import Path
from datetime import datetime
import markdown
from domain.interfaces.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class HtmlReportGenerator(ReportGenerator):
    def generate(self, data: dict, output_path: Path) -> None:
        md = f"# {data.get('title', 'Cybrix AI Analysis Report')}\n\n"
        md += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n"
        md += f"**Risk Score:** {data.get('risk_score', 'N/A')}\n\n"

        md += "## Executive Summary\n\n"
        md += data.get('executive_summary', 'No summary provided.') + "\n\n"

        md += "## Technical Findings\n\n"
        for f in data.get('findings', []):
            md += f"- {f}\n"
        md += "\n## MITRE ATT&CK Mapping\n\n"
        for tech in data.get('mitre_techniques', []):
            md += f"- {tech}\n"
        md += "\n## Recommendations\n\n"
        for rec in data.get('recommendations', []):
            md += f"- {rec}\n"

        html_body = markdown.markdown(md, extensions=['tables'])
        full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{data.get('title', 'Report')}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 2em; color: #333; }}
h1 {{ color: #1a5276; }}
h2 {{ color: #2c3e50; border-bottom: 1px solid #ccc; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_html)
        logger.info(f"HTML report saved to {output_path}")