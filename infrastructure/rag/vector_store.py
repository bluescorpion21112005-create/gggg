"""ChromaDB vector store for document chunks (chromadb >= 0.4 API)."""
import logging
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import chromadb
from injector import inject

logger = logging.getLogger(__name__)


class VectorStore:
    """Persistent vector store backed by ChromaDB.

    Uses the PersistentClient API introduced in chromadb 0.4.0.
    The old chromadb.Client(Settings(...)) API is deprecated and removed.
    """

    @inject
    def __init__(
        self,
        persist_directory: str = "./cache/chroma",
        collection_name: str = "cybrix_documents",
    ):
        Path(persist_directory).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=persist_directory)
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "VectorStore initialised: collection='%s', path='%s'",
            collection_name,
            persist_directory,
        )

    def add_chunks(
        self,
        chunks: List[str],
        embeddings: List[List[float]],
        metadatas: Optional[List[Dict]] = None,
        ids: Optional[List[str]] = None,
    ) -> None:
        if not chunks:
            return
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in chunks]
        if metadatas is None:
            metadatas = [{} for _ in chunks]
        self._collection.add(
            embeddings=embeddings,
            documents=chunks,
            metadatas=metadatas,
            ids=ids,
        )
        logger.info("VectorStore: added %d chunks.", len(chunks))

    def query(self, query_embedding: List[float], n_results: int = 5) -> Dict:
        return self._collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )

    def list_documents(self) -> List[Dict]:
        """Return all document metadata entries."""
        results = self._collection.get(include=["metadatas"])
        return [
            {"id": doc_id, "metadata": meta}
            for doc_id, meta in zip(results["ids"], results["metadatas"])
        ]

    def clear(self) -> None:
        """Remove all documents from the collection."""
        self._client.delete_collection(self._collection.name)
        self._collection = self._client.get_or_create_collection(
            name=self._collection.name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("VectorStore: collection cleared.")
