"""CIDAS daemon utility package.

Provides logging, embedding helpers, and an npm registry client used by the
analysis pillars.  All utilities are designed to be importable without
triggering heavy side effects (model loading, network calls).
"""
from .logger import get_logger
from .npm_registry import get_package_metadata, get_download_count, get_package_tarball_info
from .embeddings import embed_text, cosine_similarity

__all__ = [
    "get_logger",
    "get_package_metadata",
    "get_download_count",
    "get_package_tarball_info",
    "embed_text",
    "cosine_similarity",
]
