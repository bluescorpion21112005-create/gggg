"""Sentence-transformer embedder with lazy model loading.

The model is NOT loaded during DI container construction — it is loaded on first
use in a thread pool executor, so it never blocks the Qt main thread or startup.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import List

from injector import inject

logger = logging.getLogger(__name__)


class Embedder:
    """Async embedding wrapper around sentence-transformers.

    Model loading is deferred to the first call to ``embed()`` and executed in a
    thread pool so the asyncio event loop and Qt UI remain responsive.
    """

    @inject
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._model_name = model_name
        self._model = None          # loaded lazily
        self._load_lock = threading.Lock()
        logger.info("Embedder created (model='%s', loading deferred)", model_name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def embed(self, texts: List[str]) -> List[List[float]]:
        """Embed a list of texts, loading the model on first call."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._embed_sync, texts)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_model_loaded(self) -> None:
        """Thread-safe lazy model loader."""
        if self._model is not None:
            return
        with self._load_lock:
            if self._model is not None:  # double-checked locking
                return
            logger.info("Embedder: loading model '%s' (first use)...", self._model_name)
            try:
                from sentence_transformers import SentenceTransformer  # optional extra, import deferred
            except ImportError as exc:
                from core.exceptions import RagUnavailableError

                raise RagUnavailableError(
                    "Knowledge base (RAG) is not installed. Install the optional RAG components "
                    "(requirements-rag.txt) to enable it.") from exc
            self._model = SentenceTransformer(self._model_name)
            logger.info("Embedder: model '%s' loaded OK", self._model_name)

    def _embed_sync(self, texts: List[str]) -> List[List[float]]:
        """Synchronous embedding — called from thread pool executor."""
        self._ensure_model_loaded()
        return self._model.encode(texts, show_progress_bar=False).tolist()
