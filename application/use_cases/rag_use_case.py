"""RAG use case: ingest documents and answer questions with citations."""
import os
import logging
from injector import inject
from typing import List, Dict, AsyncGenerator
from domain.interfaces.ai_provider import AIProvider
from infrastructure.rag.document_loader import DocumentLoader
from infrastructure.rag.chunker import Chunker
from infrastructure.rag.embedder import Embedder
from infrastructure.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)

class RAGUseCase:
    @inject
    def __init__(self, ai_provider: AIProvider, embedder: Embedder, vector_store: VectorStore):
        self._provider = ai_provider
        self._embedder = embedder
        self._vector_store = vector_store
        self._chunker = Chunker()

    async def ingest_document(self, file_path: str, metadata: Dict = None) -> Dict:
        """Load, chunk, embed, and store a single document."""
        text = DocumentLoader.load(file_path)
        chunks = self._chunker.split(text)
        if not chunks:
            raise ValueError("No content extracted.")
        embeddings = await self._embedder.embed(chunks)
        chunk_metadata = []
        for i, chunk in enumerate(chunks):
            chunk_metadata.append({
                "source": os.path.basename(file_path),
                "chunk_index": i,
                **(metadata or {})
            })
        self._vector_store.add_chunks(chunks, embeddings, metadatas=chunk_metadata)
        return {"status": "success", "chunks": len(chunks), "source": os.path.basename(file_path)}

    async def answer_question(self, question: str, model: str, top_k: int = 5) -> AsyncGenerator[Dict, None]:
        """Generate an answer using RAG."""
        yield {'type': 'progress', 'status': 'Embedding question...'}
        query_embedding = await self._embedder.embed([question])
        query_emb = query_embedding[0]

        yield {'type': 'progress', 'status': 'Searching knowledge base...'}
        results = self._vector_store.query(query_emb, n_results=top_k)
        retrieved_docs = results['documents'][0] if results['documents'] else []
        metadatas = results['metadatas'][0] if results['metadatas'] else []
        distances = results['distances'][0] if results['distances'] else []

        if not retrieved_docs:
            yield {'type': 'result', 'answer': "No relevant documents found in the knowledge base."}
            return

        # Build context for LLM
        context = ""
        citations = []
        for i, (doc, meta, dist) in enumerate(zip(retrieved_docs, metadatas, distances)):
            source = meta.get('source', 'unknown')
            citations.append(f"[{i+1}] {source} (relevance: {1-dist:.2f})")
            context += f"--- Document {i+1} (Source: {source}) ---\n{doc}\n"

        prompt = f"""You are a cybersecurity expert assistant. Answer the user's question using ONLY the provided context.
If the context doesn't contain the answer, say "I don't have enough information."

Context:
{context}

Question: {question}

Provide a clear, concise answer. At the end, list the citations you used."""

        yield {'type': 'progress', 'status': 'Generating answer...'}
        answer = ""
        try:
            async for token in self._provider.generate(prompt, model):
                answer += token
                yield {'type': 'stream', 'token': token}
        except Exception as e:
            logger.error(f"AI generation failed: {e}")
            answer += f"\n\n**Error**: {e}"

        yield {'type': 'result', 'answer': answer, 'citations': citations}