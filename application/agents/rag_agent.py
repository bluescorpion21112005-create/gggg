"""RAG agent for document Q&A with production logging."""
import logging
from typing import Any, AsyncGenerator

from injector import inject

from application.agents.base_agent import BaseAgent
from application.use_cases.rag_use_case import RAGUseCase

logger = logging.getLogger(__name__)


class RAGAgent(BaseAgent):
    """Handles document ingestion and question-answering via RAG pipeline."""

    @inject
    def __init__(self, use_case: RAGUseCase):
        self._use_case = use_case

    async def execute(self, payload: Any, model: str = "default") -> str:
        action = payload.get("action", "query")
        if action == "ingest":
            file_path = payload["file_path"]
            logger.info("RAGAgent.execute: ingesting '%s'", file_path)
            result = await self._use_case.ingest_document(
                file_path, payload.get("metadata")
            )
            logger.info(
                "RAGAgent.execute: ingested %d chunks from '%s'",
                result["chunks"],
                result["source"],
            )
            return f"Ingested {result['chunks']} chunks from {result['source']}."
        else:
            question = payload["query"]
            logger.info("RAGAgent.execute: answering question='%s'", question[:80])
            answer = ""
            async for event in self._use_case.answer_question(question, model):
                if event["type"] == "result":
                    answer = event["answer"]
            logger.info("RAGAgent.execute: answer complete (%d chars)", len(answer))
            return answer

    async def stream_execute(self, payload: Any, model: str = "default") -> AsyncGenerator[str, None]:
        action = payload.get("action", "query")
        if action == "ingest":
            file_path = payload["file_path"]
            logger.info("RAGAgent.stream_execute: ingesting '%s'", file_path)
            result = await self._use_case.ingest_document(file_path, payload.get("metadata"))
            logger.info(
                "RAGAgent.stream_execute: ingested %d chunks from '%s'",
                result["chunks"],
                result["source"],
            )
            yield f"Ingested {result['chunks']} chunks from {result['source']}."
        else:
            question = payload["query"]
            logger.info("RAGAgent.stream_execute: answering question='%s'", question[:80])
            token_count = 0
            async for event in self._use_case.answer_question(question, model):
                if event["type"] == "stream":
                    token_count += 1
                    yield event["token"]
            logger.info("RAGAgent.stream_execute: complete (%d tokens)", token_count)
