"""Test RAG components."""
import pytest
from infrastructure.rag.chunker import Chunker
from infrastructure.rag.embedder import Embedder

def test_chunker():
    chunker = Chunker(chunk_size=100, chunk_overlap=20)
    text = "Hello. This is a test. We are testing chunking. The sentence must be split properly."
    chunks = chunker.split(text)
    assert len(chunks) > 1
    # Check that no chunk exceeds size much
    for c in chunks:
        assert len(c) <= 120  # some margin

@pytest.mark.asyncio
async def test_embedder():
    pytest.importorskip("sentence_transformers", reason="optional RAG extra (requirements-rag.txt) not installed")
    embedder = Embedder(model_name="all-MiniLM-L6-v2")
    embeddings = await embedder.embed(["Test sentence"])
    assert len(embeddings) == 1
    assert len(embeddings[0]) == 384  # MiniLM dimension


def test_rag_is_optional_and_lazy(tmp_path):
    """Without chromadb the app still starts: the store is only built (and fails clearly) on first use."""
    import builtins
    from unittest import mock

    from core.exceptions import RagUnavailableError
    from infrastructure.rag.vector_store import LazyVectorStore

    real_import = builtins.__import__

    def no_chromadb(name, *args, **kwargs):
        if name == "chromadb" or name.startswith("chromadb."):
            raise ImportError("No module named 'chromadb'")
        return real_import(name, *args, **kwargs)

    store = LazyVectorStore(persist_directory=str(tmp_path / "chroma"))  # construction never imports
    with mock.patch("builtins.__import__", side_effect=no_chromadb):
        with pytest.raises(RagUnavailableError):
            store.query([0.1, 0.2])
