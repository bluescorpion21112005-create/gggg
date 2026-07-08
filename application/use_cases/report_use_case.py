"""Report generation use case: selects generator, prepares data, saves."""
import logging
from pathlib import Path
from typing import Optional
from uuid import UUID

from injector import inject

from core.config import AppConfig
from domain.interfaces.repository import Repository
from domain.interfaces.ai_provider import AIProvider
from domain.interfaces.report_generator import ReportGenerator
from infrastructure.reporting.pdf_generator import PdfReportGenerator
from infrastructure.reporting.markdown_generator import MarkdownReportGenerator
from infrastructure.reporting.html_generator import HtmlReportGenerator

logger = logging.getLogger(__name__)


class ReportUseCase:
    @inject
    def __init__(
        self,
        pdf_gen: PdfReportGenerator,
        md_gen: MarkdownReportGenerator,
        html_gen: HtmlReportGenerator,
        repository: Repository,
        ai_provider: AIProvider,
        app_config: AppConfig,
    ):
        self._generators: dict[str, ReportGenerator] = {
            "pdf": pdf_gen,
            "markdown": md_gen,
            "html": html_gen,
        }
        self._repo = repository
        self._provider = ai_provider
        self._default_model = app_config.default_model

    async def generate_from_analysis(
        self,
        analysis_id: UUID,
        fmt: str,
        output_dir: str,
        extra_notes: Optional[str] = None,
    ) -> Path:
        """Load analysis from repo, optionally enrich with AI, generate report."""
        analysis = await self._repo.get_analysis(analysis_id)
        if not analysis:
            raise ValueError(f"Analysis {analysis_id} not found.")

        logger.info("ReportUseCase: generating '%s' report for analysis '%s'", fmt, analysis_id)

        data = {
            "title": analysis.title,
            "risk_score": analysis.metadata.get("risk_score", "N/A"),
            "executive_summary": analysis.description,
            "findings": analysis.metadata.get("findings", []),
            "mitre_techniques": analysis.metadata.get("mitre_techniques", []),
            "recommendations": analysis.metadata.get("recommendations", []),
        }

        # Optionally expand recommendations with AI using configured default model
        if extra_notes and extra_notes.strip():
            prompt = (
                f"Given this cybersecurity analysis summary, and the following analyst notes, "
                f"generate a refined list of recommendations:\n"
                f"Analysis: {analysis.description}\n"
                f"Notes: {extra_notes}"
            )
            recs_text = ""
            try:
                async for token in self._provider.generate(prompt, self._default_model):
                    recs_text += token
                data["recommendations"] = [recs_text]
            except Exception as exc:
                logger.error("AI recommendation expansion failed: %s", exc, exc_info=True)

        # Determine output path
        ext_map = {"pdf": ".pdf", "markdown": ".md", "html": ".html"}
        file_name = f"report_{analysis_id}_{fmt}{ext_map.get(fmt, '.txt')}"
        output_path = Path(output_dir) / file_name
        output_path.parent.mkdir(parents=True, exist_ok=True)

        generator = self._generators.get(fmt)
        if not generator:
            raise ValueError(f"Unsupported report format: '{fmt}'. Use: pdf, markdown, html.")

        generator.generate(data, output_path)
        logger.info("ReportUseCase: report saved to '%s'", output_path)
        return output_path
