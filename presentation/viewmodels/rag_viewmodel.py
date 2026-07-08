"""ViewModel for RAG document Q&A.

The ViewModel communicates exclusively through the Orchestrator — it never
touches the infrastructure layer (VectorStore, Embedder) directly.
"""
import os
import logging
from PySide6.QtCore import Signal, Slot
from qasync import asyncSlot
from injector import inject

from application.orchestrator import Orchestrator
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class RAGViewModel(BaseViewModel):
    answer_changed = Signal(str)
    documents_loaded = Signal(list)  # list of {"source": str} summaries

    @inject
    def __init__(self, orchestrator: Orchestrator):
        super().__init__()
        self._orchestrator = orchestrator

    @asyncSlot(str)
    async def load_documents(self, file_paths_str: str):
        """Ingest one or more documents (semicolon-separated paths)."""
        if not file_paths_str.strip():
            return
        paths = [p.strip() for p in file_paths_str.split(";") if p.strip()]
        self.is_busy = True
        ingested: list[dict] = []
        try:
            for path in paths:
                if os.path.isfile(path):
                    status = await self._orchestrator.dispatch(
                        "rag_query",
                        {"action": "ingest", "file_path": path},
                    )
                    ingested.append({"source": os.path.basename(path), "status": status})
                    logger.info("RAGViewModel: ingested '%s'", path)
                else:
                    msg = f"Path not found: {path}"
                    logger.warning("RAGViewModel: %s", msg)
                    self.error_occurred.emit(msg)
            if ingested:
                self.documents_loaded.emit(ingested)
                self.status_message.emit(f"Loaded {len(ingested)} document(s).")
        except Exception as exc:
            logger.error("RAGViewModel.load_documents failed: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Document loading failed: {exc}")
        finally:
            self.is_busy = False

    @asyncSlot(str)
    async def ask_question(self, question: str):
        """Stream an answer to the given question from the knowledge base."""
        if not question.strip():
            return
        self.is_busy = True
        answer = ""
        self.answer_changed.emit("")
        try:
            async for token in self._orchestrator.dispatch_stream(
                "rag_query", {"action": "query", "query": question}
            ):
                answer += token
                self.answer_changed.emit(answer)
            logger.info("RAGViewModel.ask_question: complete (%d chars)", len(answer))
        except Exception as exc:
            logger.error("RAGViewModel.ask_question failed: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Question failed: {exc}")
        finally:
            self.is_busy = False
