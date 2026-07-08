"""Load text content from various document formats."""
import logging
from pathlib import Path
from typing import List
import pypdf
import docx
import markdown

logger = logging.getLogger(__name__)

class DocumentLoader:
    @staticmethod
    def load(file_path: str) -> str:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        suffix = path.suffix.lower()
        if suffix == '.pdf':
            return DocumentLoader._load_pdf(file_path)
        elif suffix in ('.docx', '.doc'):
            return DocumentLoader._load_docx(file_path)
        elif suffix == '.md':
            return DocumentLoader._load_markdown(file_path)
        else:
            # Assume text files (txt, log, csv, etc.)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()

    @staticmethod
    def _load_pdf(path: str) -> str:
        text_parts = []
        try:
            with open(path, 'rb') as f:
                reader = pypdf.PdfReader(f)
                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
        except Exception as e:
            logger.error(f"PDF read error: {e}")
            raise
        return '\n\n'.join(text_parts)

    @staticmethod
    def _load_docx(path: str) -> str:
        try:
            doc = docx.Document(path)
            return '\n'.join([para.text for para in doc.paragraphs])
        except Exception as e:
            logger.error(f"DOCX read error: {e}")
            raise

    @staticmethod
    def _load_markdown(path: str) -> str:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            md_text = f.read()
        # Convert to plain text (strip most formatting), then use text
        html = markdown.markdown(md_text)
        # Simple HTML to text (strip tags)
        import re
        text = re.sub(r'<[^>]+>', '', html)
        return text