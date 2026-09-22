"""Tests for daemon.utils.embeddings.

Covers cosine_similarity (pure math, no mocks), embed_text (model mocked),
and the lru_cache behaviour of _load_model.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_st_module(dim: int = 384) -> tuple[MagicMock, MagicMock]:
    """Return (fake_sentence_transformers_module, fake_model_instance)."""
    instance = MagicMock()
    instance.encode.return_value = np.ones(dim, dtype=np.float32)
    module = MagicMock()
    module.SentenceTransformer.return_value = instance
    return module, instance


def _make_settings(model_name: str = "all-MiniLM-L6-v2") -> MagicMock:
    s = MagicMock()
    s.embedding_model = model_name
    return s


# ── cosine_similarity (pure math) ─────────────────────────────────────────────

def test_cosine_similarity_identical_vectors_returns_one() -> None:
    from daemon.utils.embeddings import cosine_similarity
    v = [1.0, 2.0, 3.0]
    assert cosine_similarity(v, v) == pytest.approx(1.0, abs=1e-6)


def test_cosine_similarity_orthogonal_vectors_returns_zero() -> None:
    from daemon.utils.embeddings import cosine_similarity
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0, abs=1e-6)


def test_cosine_similarity_known_values() -> None:
    from daemon.utils.embeddings import cosine_similarity
    # [1,1,0] vs [1,0,0] → cos(45°) ≈ 0.7071
    assert cosine_similarity([1.0, 1.0, 0.0], [1.0, 0.0, 0.0]) == pytest.approx(0.7071, abs=0.001)


def test_cosine_similarity_zero_norm_returns_zero() -> None:
    from daemon.utils.embeddings import cosine_similarity
    assert cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0
    assert cosine_similarity([1.0, 0.0], [0.0, 0.0]) == 0.0


def test_cosine_similarity_antiparallel_returns_minus_one() -> None:
    from daemon.utils.embeddings import cosine_similarity
    assert cosine_similarity([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0, abs=1e-6)


def test_cosine_similarity_partial_overlap() -> None:
    from daemon.utils.embeddings import cosine_similarity
    # [3,4] and [4,3]: dot=24, norms=5*5=25 → 0.96
    assert cosine_similarity([3.0, 4.0], [4.0, 3.0]) == pytest.approx(0.96, abs=0.001)


# ── embed_text ────────────────────────────────────────────────────────────────

def test_embed_text_returns_list_of_floats() -> None:
    from daemon.utils.embeddings import embed_text

    mock_model = MagicMock()
    mock_model.encode.return_value = np.ones(384, dtype=np.float32)
    with patch("daemon.utils.embeddings._load_model", return_value=mock_model):
        result = embed_text("hello world")

    assert isinstance(result, list)
    assert len(result) == 384
    assert all(isinstance(x, float) for x in result)


def test_embed_text_calls_encode_with_correct_args() -> None:
    from daemon.utils.embeddings import embed_text

    mock_model = MagicMock()
    mock_model.encode.return_value = np.zeros(384, dtype=np.float32)
    with patch("daemon.utils.embeddings._load_model", return_value=mock_model):
        embed_text("test input")

    mock_model.encode.assert_called_once_with("test input", show_progress_bar=False)


def test_embed_text_passes_arbitrary_string() -> None:
    from daemon.utils.embeddings import embed_text

    mock_model = MagicMock()
    mock_model.encode.return_value = np.zeros(64, dtype=np.float32)
    inputs = ["", "  spaces  ", "lodash@4.17.21", "a" * 1000]
    with patch("daemon.utils.embeddings._load_model", return_value=mock_model):
        for text in inputs:
            embed_text(text)

    assert mock_model.encode.call_count == len(inputs)
    for call, text in zip(mock_model.encode.call_args_list, inputs):
        assert call.args[0] == text


# ── _load_model — lru_cache behaviour ────────────────────────────────────────

def test_model_loaded_only_once() -> None:
    """SentenceTransformer constructor should be called exactly once across multiple embed_text calls."""
    from daemon.utils import embeddings as emb_mod
    from daemon.utils.embeddings import embed_text

    emb_mod._load_model.cache_clear()
    try:
        st_module, st_instance = _make_st_module(384)
        st_instance.encode.return_value = np.zeros(384, dtype=np.float32)

        with (
            patch.dict(sys.modules, {"sentence_transformers": st_module}),
            patch("daemon.config.get_settings", return_value=_make_settings()),
        ):
            embed_text("first call")
            embed_text("second call")
            embed_text("third call")

        st_module.SentenceTransformer.assert_called_once()
    finally:
        emb_mod._load_model.cache_clear()


def test_load_model_uses_embedding_model_from_settings() -> None:
    """_load_model should pass settings.embedding_model to SentenceTransformer."""
    from daemon.utils import embeddings as emb_mod

    emb_mod._load_model.cache_clear()
    try:
        model_name = "paraphrase-MiniLM-L3-v2"
        st_module, _ = _make_st_module()

        with (
            patch.dict(sys.modules, {"sentence_transformers": st_module}),
            patch("daemon.config.get_settings", return_value=_make_settings(model_name)),
        ):
            emb_mod._load_model()

        st_module.SentenceTransformer.assert_called_once_with(model_name)
    finally:
        emb_mod._load_model.cache_clear()


def test_load_model_returns_same_object_on_repeated_calls() -> None:
    """Cached calls must return the identical model object."""
    from daemon.utils import embeddings as emb_mod

    emb_mod._load_model.cache_clear()
    try:
        st_module, st_instance = _make_st_module()

        with (
            patch.dict(sys.modules, {"sentence_transformers": st_module}),
            patch("daemon.config.get_settings", return_value=_make_settings()),
        ):
            model_a = emb_mod._load_model()
            model_b = emb_mod._load_model()

        assert model_a is model_b
    finally:
        emb_mod._load_model.cache_clear()
