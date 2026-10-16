"""ChromaDB vector store for document chunks (chromadb >= 0.4 API)."""
import logging
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from injector import inject

from core.exceptions import RagUnavailableError

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
        # Saqlash papkasini yaratish (agar mavjud bo‘lmasa)
        Path(persist_directory).mkdir(parents=True, exist_ok=True)

        # Standart nom bo‘sh yoki noto‘g‘ri bo‘lsa, tuzatish
        if not collection_name or not collection_name.strip():
            collection_name = "cybrix_documents"
            logger.warning("Collection name bo‘sh, standart 'cybrix_documents' ishlatiladi")
        # ChromaDB nom formatini tekshirish (3-512 belgi, faqat ruxsat etilgan belgilar)
        import re
        if not re.match(r'^[a-zA-Z0-9._-]{3,512}$', collection_name):
            logger.warning("Collection name '%s' noto‘g‘ri format, standartga almashtirildi", collection_name)
            collection_name = "cybrix_documents"

        # chromadb is an optional extra (pip install -r requirements-rag.txt): imported here so the app
        # starts without it, and only RAG features report that it is missing.
        try:
            from chromadb import EphemeralClient, PersistentClient
        except ImportError as exc:
            raise RagUnavailableError(
                "Knowledge base (RAG) is not installed. Install the optional RAG components "
                "(requirements-rag.txt) to enable it.") from exc

        # PersistentClient ishlamasa, vaqtinchalik xotiraga o‘tish
        try:
            self._client = PersistentClient(path=persist_directory)
            logger.info("ChromaDB PersistentClient yaratildi (%s)", persist_directory)
        except Exception as e:
            logger.warning("Doimiy ombor yaratilmadi: %s. Vaqtinchalik rejimga o‘tilmoqda.", e)
            self._client = EphemeralClient()
            logger.info("ChromaDB EphemeralClient yaratildi")

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


class LazyVectorStore:
    """Builds the real VectorStore on first use.

    The RAG agent is registered at startup; building the store there would import chromadb (slow,
    hundreds of MB) on every launch and crash the app when the optional RAG extra is missing.
    """

    def __init__(self, persist_directory: Optional[str] = None, collection_name: str = "cybrix_documents"):
        if persist_directory is None:
            from core.paths import data_dir

            persist_directory = str(data_dir() / "chroma")
        self._args = (persist_directory, collection_name)
        self._store: Optional[VectorStore] = None

    def _real(self) -> VectorStore:
        if self._store is None:
            self._store = VectorStore(*self._args)
        return self._store

    def add_chunks(self, *args, **kwargs):
        return self._real().add_chunks(*args, **kwargs)

    def query(self, *args, **kwargs):
        return self._real().query(*args, **kwargs)

    def list_documents(self):
        return self._real().list_documents()

    def clear(self):
        return self._real().clear()
