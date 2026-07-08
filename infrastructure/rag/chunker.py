"""Split text into overlapping chunks with configurable size."""
import re
import logging
from typing import List

logger = logging.getLogger(__name__)

class Chunker:
    def __init__(self, chunk_size: int = 500, chunk_overlap: int = 50):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def split(self, text: str) -> List[str]:
        """Split text into chunks, trying to keep sentences intact."""
        # Basic sentence splitting
        sentences = re.split(r'(?<=[.!?])\s+', text)
        chunks = []
        current_chunk = []
        current_length = 0
        for sentence in sentences:
            sent_len = len(sentence)
            if current_length + sent_len > self.chunk_size and current_chunk:
                chunks.append(' '.join(current_chunk))
                # Keep overlap: remove first sentences until under overlap
                overlap_len = 0
                while current_chunk and overlap_len < self.chunk_overlap:
                    removed = current_chunk.pop(0)
                    overlap_len += len(removed)
                current_length = sum(len(s) for s in current_chunk)
            current_chunk.append(sentence)
            current_length += sent_len
        if current_chunk:
            chunks.append(' '.join(current_chunk))

        # Agar matn bir nechta gapdan iborat bo'lsa, lekin bitta chunk bo'lsa — qayta bo'lish
        if len(chunks) == 1 and len(sentences) > 1 and len(text) > self.chunk_size // 2:
            return self._split_with_size(sentences, max(self.chunk_size // 2, 1))

        return chunks

    def _split_with_size(self, sentences: List[str], size: int) -> List[str]:
        """Matnni kichikroq chunk_size bilan qayta bo'lish."""
        chunks: List[str] = []
        current_chunk: List[str] = []
        current_length = 0
        for sentence in sentences:
            sent_len = len(sentence)
            if current_length + sent_len > size and current_chunk:
                chunks.append(' '.join(current_chunk))
                overlap_len = 0
                while current_chunk and overlap_len < self.chunk_overlap:
                    removed = current_chunk.pop(0)
                    overlap_len += len(removed)
                current_length = sum(len(s) for s in current_chunk)
            current_chunk.append(sentence)
            current_length += sent_len
        if current_chunk:
            chunks.append(' '.join(current_chunk))
        return chunks