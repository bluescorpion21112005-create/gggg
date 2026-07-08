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
    embedder = Embedder(model_name="all-MiniLM-L6-v2")
    embeddings = await embedder.embed(["Test sentence"])
    assert len(embeddings) == 1
    assert len(embeddings[0]) == 384  # MiniLM dimension