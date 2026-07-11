"""ChromaDB vector store for document chunks (chromadb >= 0.4 API)."""
import logging
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from chromadb import PersistentClient, EphemeralClient
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

    # ... qolgan metodlar o‘zgarishsiz