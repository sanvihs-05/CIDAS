"""Tests for the Contextify pillar.

Uses mock embeddings (fixed unit vectors) to avoid loading the sentence-transformer
model during CI, keeping the suite fast and reproducible.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from daemon.models import PillarScore
from daemon.pillars.contextify import Contextify
from daemon.utils.npm_registry import RegistryLookup, RegistryResult


@pytest.fixture
def contextify() -> Contextify:
    return Contextify()


# ── Unit tests (no I/O) ───────────────────────────────────────────────────────

def test_score_returns_pillar_score(contextify: Contextify) -> None:
    """load_project_fingerprint + compute_score must always return a PillarScore."""
    score = contextify.compute_score(similarity=0.8, domain_count=5)
    assert isinstance(score, tuple)
    risk, flags = score
    assert 0.0 <= risk <= 100.0
    assert isinstance(flags, list)


def test_unfamiliar_package_scores_high(contextify: Contextify, sample_project_path) -> None:
    """A package with very low similarity to the project should score highly."""
    # Fingerprint has >10 domains after reading a real package.json
    domains = contextify.load_project_fingerprint(str(sample_project_path))
    assert len(domains) >= 3

    # Patch embed functions to return orthogonal vectors
    import numpy as np
    project_vec = [1.0, 0.0, 0.0]
    pkg_vec = [0.0, 1.0, 0.0]  # orthogonal → similarity ≈ 0

    with (
        patch("daemon.pillars.contextify.embed_text", return_value=pkg_vec),
        patch("daemon.pillars.contextify.cosine_similarity", return_value=0.02),
        patch("daemon.pillars.contextify.get_package_metadata",
              return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT)),
    ):
        risk, flags = contextify.compute_score(similarity=0.02, domain_count=len(domains))

    assert risk >= 15.0
    assert len(flags) > 0


def test_familiar_package_scores_low(contextify: Contextify, sample_project_path) -> None:
    """A package whose embedding closely matches the project should score near zero."""
    risk, flags = contextify.compute_score(similarity=0.92, domain_count=5)
    assert risk == 0.0
    assert flags == []


@pytest.mark.asyncio
async def test_missing_project_path_handled_gracefully(contextify: Contextify) -> None:
    """An empty project_path must not raise; should return a PillarScore with low-risk default."""
    result = await contextify.score("some-package", project_path="")
    assert isinstance(result, PillarScore)
    assert 0.0 <= result.score <= 100.0
    assert "no_project_path" in result.flags


@pytest.mark.asyncio
async def test_score_with_mock_embeddings(contextify: Contextify, sample_project_path) -> None:
    """Full async score() should use mocked embeddings and return a valid PillarScore."""
    with (
        patch("daemon.pillars.contextify.embed_text", return_value=[0.5, 0.5, 0.5]),
        patch("daemon.pillars.contextify.cosine_similarity", return_value=0.75),
        patch("daemon.pillars.contextify.get_package_metadata",
              return_value=RegistryResult(RegistryLookup.EXISTS, {"description": "utility library"})),
    ):
        result = await contextify.score("lodash", str(sample_project_path))

    assert isinstance(result, PillarScore)
    assert result.score == 0.0  # similarity 0.75 >= 0.65 → no risk
    assert result.confidence > 0


# ── Line 84: non-existent project_path in load_project_fingerprint ────────────

def test_load_fingerprint_nonexistent_path_returns_empty(
    contextify: Contextify, tmp_path
) -> None:
    """load_project_fingerprint must return [] when the path is not an existing directory."""
    result = contextify.load_project_fingerprint(str(tmp_path / "does_not_exist"))
    assert result == []


# ── Lines 52-58 (line 53): empty directory triggers empty_project score ────────

@pytest.mark.asyncio
async def test_score_empty_directory_returns_empty_project_score(
    contextify: Contextify, tmp_path
) -> None:
    """An existing but empty directory (no JS files, no package.json) must return
    score=5.0 with the 'empty_project' flag and not call any embedding or registry code."""
    result = await contextify.score("lodash", str(tmp_path))
    assert isinstance(result, PillarScore)
    assert result.score == 5.0
    assert result.confidence == 0.3
    assert "empty_project" in result.flags


# ── Lines 95-96: invalid package.json silently skipped ────────────────────────

def test_load_fingerprint_invalid_package_json_skipped(
    contextify: Contextify, tmp_path
) -> None:
    """JSONDecodeError from a malformed package.json is caught; JS file imports still collected."""
    (tmp_path / "package.json").write_text("not-valid-json{{", encoding="utf-8")
    (tmp_path / "index.js").write_text("import react from 'react';", encoding="utf-8")
    domains = contextify.load_project_fingerprint(str(tmp_path))
    assert "react" in domains


# ── Lines 117-118: OSError on JS file read is silently skipped ────────────────

def test_load_fingerprint_oserror_on_js_file_skipped(
    contextify: Contextify, tmp_path, monkeypatch
) -> None:
    """OSError when reading a JS file is caught; the file is skipped without crashing."""
    from pathlib import Path as _Path

    boom = tmp_path / "boom.js"
    boom.write_text("import react from 'react';", encoding="utf-8")

    _orig = _Path.read_text

    def _explode(self, *args, **kwargs):
        if self.name == "boom.js":
            raise OSError("permission denied")
        return _orig(self, *args, **kwargs)

    monkeypatch.setattr(_Path, "read_text", _explode)
    domains = contextify.load_project_fingerprint(str(tmp_path))
    assert "react" not in domains
    assert isinstance(domains, list)


# ── Lines 106-107 and 120: _MAX_FILES cap stops the walk ──────────────────────

def test_load_fingerprint_stops_at_max_files(
    contextify: Contextify, tmp_path, monkeypatch
) -> None:
    """Scanning stops after exactly _MAX_FILES JS files; done flag breaks outer walk loop."""
    import daemon.pillars.contextify as ctx_mod

    monkeypatch.setattr(ctx_mod, "_MAX_FILES", 3)

    for i in range(5):
        (tmp_path / f"pkg{i}.js").write_text(
            f"import dep{i} from 'dep{i}';", encoding="utf-8"
        )

    domains = contextify.load_project_fingerprint(str(tmp_path))
    assert len(domains) == 3


# ── Lines 135-137: fetch_package_description swallows exceptions ──────────────

@pytest.mark.asyncio
async def test_fetch_package_description_exception_returns_none(
    contextify: Contextify,
) -> None:
    """Exception from get_package_metadata is caught; fetch_package_description returns None."""
    with patch(
        "daemon.pillars.contextify.get_package_metadata",
        side_effect=RuntimeError("network error"),
    ):
        result = await contextify.fetch_package_description("some-pkg")
    assert result is None


# ── Lines 145-146: loosely_related band (0.35 ≤ similarity < 0.65) ────────────

def test_compute_score_loosely_related(contextify: Contextify) -> None:
    """Similarity in the 0.35–0.64 band returns risk=10.0 with loosely_related flag."""
    risk, flags = contextify.compute_score(similarity=0.5, domain_count=5)
    assert risk == 10.0
    assert "loosely_related" in flags


# ── Lines 148-149: unfamiliar_in_mature_project (similarity < 0.35, domains > 10) ─

def test_compute_score_unfamiliar_in_mature_project(contextify: Contextify) -> None:
    """Very low similarity in a mature project (>10 domains) returns risk=25.0."""
    risk, flags = contextify.compute_score(similarity=0.1, domain_count=15)
    assert risk == 25.0
    assert "unfamiliar_in_mature_project" in flags
