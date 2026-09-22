"""
Singleton sentence-transformers embedding wrapper.

Model: all-MiniLM-L6-v2
  Dimensions : 384
  Size       : ~90 MB (baked into the Docker image at build time)
  Quality    : Good for semantic similarity; no API key required.
"""

from __future__ import annotations

import os
from functools import lru_cache

from sentence_transformers import SentenceTransformer

MODEL_NAME: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
MODEL_CACHE_DIR: str = os.getenv("MODEL_CACHE_DIR", "/models")
EMBEDDING_DIM: int = 384


@lru_cache(maxsize=1)
def _load_model() -> SentenceTransformer:
    """Load (or return cached) the sentence-transformers model."""
    return SentenceTransformer(MODEL_NAME, cache_folder=MODEL_CACHE_DIR)


def embed(text: str) -> list[float]:
    """Return a normalised 384-dimensional float embedding for text."""
    vector = _load_model().encode(text, normalize_embeddings=True)
    return vector.tolist()


def embed_batch(texts: list[str]) -> list[list[float]]:
    """Embed a list of texts as a single efficient batch."""
    if not texts:
        return []
    vectors = _load_model().encode(
        texts,
        normalize_embeddings=True,
        batch_size=32,
        show_progress_bar=False,
    )
    return [v.tolist() for v in vectors]
