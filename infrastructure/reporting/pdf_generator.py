"""PDF report generator using reportlab."""
import logging
from pathlib import Path
from datetime import datetime
from domain.interfaces.report_generator import ReportGenerator
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)

class PdfReportGenerator(ReportGenerator):
    def generate(self, data: dict, output_path: Path) -> None:
        doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        # Custom styles
        title_style = styles['Title']
        heading_style = styles['Heading2']
        normal_style = styles['Normal']

        story = []

        # Title
        story.append(Paragraph(data.get('title', 'Cybrix AI Analysis Report'), title_style))
        story.append(Spacer(1, 12))

        # Metadata
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", normal_style))
        story.append(Paragraph(f"Risk Score: {data.get('risk_score', 'N/A')}", normal_style))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(data.get('executive_summary', 'No summary provided.'), normal_style))
        story.append(Spacer(1, 12))

        # Technical Findings
        story.append(Paragraph("Technical Findings", heading_style))
        findings = data.get('findings', [])
        if findings:
            for finding in findings:
                story.append(Paragraph(f"• {finding}", normal_style))
        else:
            story.append(Paragraph("No findings.", normal_style))
        story.append(Spacer(1, 12))

        # MITRE ATT&CK Mapping
        story.append(Paragraph("MITRE ATT&CK Mapping", heading_style))
        mitre_list = data.get('mitre_techniques', [])
        if mitre_list:
            for tech in mitre_list:
                story.append(Paragraph(f"• {tech}", normal_style))
        else:
            story.append(Paragraph("No MITRE techniques mapped.", normal_style))
        story.append(Spacer(1, 12))

        # Recommendations
        story.append(Paragraph("Recommendations", heading_style))
        recs = data.get('recommendations', [])
        if recs:
            for rec in recs:
                story.append(Paragraph(f"• {rec}", normal_style))
        else:
            story.append(Paragraph("No recommendations.", normal_style))

        # Build PDF
        doc.build(story)
        logger.info(f"PDF report saved to {output_path}")