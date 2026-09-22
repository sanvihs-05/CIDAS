"""Sentence-transformer embedding utilities.

The model is loaded lazily on first call and cached for the process lifetime.
All public functions are synchronous wrappers suitable for use with
``asyncio.to_thread`` from async callers.

Usage::

    from daemon.utils.embeddings import embed_text, embed_batch, cosine_similarity
    vec = embed_text("lodash")
    sim = cosine_similarity(vec, embed_text("underscore"))
"""
from __future__ import annotations

import time
from functools import lru_cache

import numpy as np

from .logger import get_logger

log = get_logger(__name__)


@lru_cache(maxsize=1)
def _load_model():  # type: ignore[return]
    """Load the SentenceTransformer model; cached after first call."""
    from sentence_transformers import SentenceTransformer

    from ..config import get_settings

    model_name = get_settings().embedding_model
    t0 = time.perf_counter()
    log.info("Loading embedding model: %s", model_name)
    model = SentenceTransformer(model_name)
    log.info("Model loaded in %.1f s", time.perf_counter() - t0)
    return model


def embed_text(text: str) -> list[float]:
    """Embed a single string and return a plain Python float list."""
    model = _load_model()
    vec: np.ndarray = model.encode(text, show_progress_bar=False)
    return vec.tolist()


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two embedding vectors."""
    va = np.array(a, dtype=np.float32)
    vb = np.array(b, dtype=np.float32)
    norm_a = float(np.linalg.norm(va))
    norm_b = float(np.linalg.norm(vb))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return float(np.dot(va, vb) / (norm_a * norm_b))
