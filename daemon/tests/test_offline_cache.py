"""Tests for daemon/utils/offline_cache.py.

The cache writer is intentionally tolerant: missing files, malformed JSON,
and write failures must never raise into the scan path.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from daemon.utils import offline_cache


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Redirect offline_cache to a temp file for isolation."""
    cache_file = tmp_path / "offline-cache.json"
    monkeypatch.setattr(offline_cache, "_path", lambda: cache_file)
    return cache_file


# ── record_allow ──────────────────────────────────────────────────────────────

async def test_record_allow_creates_file_when_missing(tmp_cache):
    await offline_cache.record_allow("lodash")
    assert tmp_cache.exists()
    data = json.loads(tmp_cache.read_text())
    assert "lodash@latest" in data
    entry = data["lodash@latest"]
    assert entry["verdict"] == "ALLOW"
    assert entry["package_name"] == "lodash"
    assert entry["version"] == "latest"
    assert entry["ttl_hours"] == offline_cache.DEFAULT_TTL_HOURS


async def test_record_allow_with_explicit_version(tmp_cache):
    await offline_cache.record_allow("lodash", version="4.17.21")
    data = json.loads(tmp_cache.read_text())
    assert "lodash@4.17.21" in data
    assert data["lodash@4.17.21"]["version"] == "4.17.21"


async def test_record_allow_different_versions_are_distinct_keys(tmp_cache):
    """Two different versions of the same package must be separate cache entries."""
    await offline_cache.record_allow("axios", version="0.27.0")
    await offline_cache.record_allow("axios", version="1.6.0")
    data = json.loads(tmp_cache.read_text())
    assert "axios@0.27.0" in data
    assert "axios@1.6.0" in data
    assert len(data) == 2


async def test_record_allow_appends_to_existing_cache(tmp_cache):
    await offline_cache.record_allow("react")
    await offline_cache.record_allow("axios")
    data = json.loads(tmp_cache.read_text())
    assert set(data.keys()) == {"react@latest", "axios@latest"}


async def test_record_allow_overwrites_same_package(tmp_cache):
    await offline_cache.record_allow("react", ttl_hours=12)
    await offline_cache.record_allow("react", ttl_hours=48)
    data = json.loads(tmp_cache.read_text())
    assert data["react@latest"]["ttl_hours"] == 48
    assert len(data) == 1


async def test_record_allow_writes_iso8601_timestamp(tmp_cache):
    from datetime import datetime
    await offline_cache.record_allow("lodash")
    data = json.loads(tmp_cache.read_text())
    ts = data["lodash@latest"]["timestamp"]
    # Must round-trip through fromisoformat
    parsed = datetime.fromisoformat(ts)
    assert parsed.tzinfo is not None  # tz-aware


async def test_record_allow_tolerates_malformed_existing_file(tmp_cache):
    tmp_cache.write_text("this is not json{{")
    await offline_cache.record_allow("lodash")
    data = json.loads(tmp_cache.read_text())
    # Existing junk replaced; new entry written cleanly.
    assert data == {"lodash@latest": data["lodash@latest"]}
    assert data["lodash@latest"]["verdict"] == "ALLOW"


async def test_record_allow_swallows_write_errors(tmp_path, monkeypatch, caplog):
    """A write failure must not propagate into the scan path."""
    bad_path = tmp_path / "no-such-dir" / "subdir" / "cache.json"
    monkeypatch.setattr(offline_cache, "_path", lambda: bad_path)

    def _explode(*_a, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(offline_cache, "_write_sync", _explode)
    # Must not raise.
    await offline_cache.record_allow("lodash")


async def test_record_allow_atomic_write_no_partial_file(tmp_cache, monkeypatch):
    """If the write fails mid-way the original file is preserved."""
    # Pre-populate with a known good entry
    tmp_cache.write_text(json.dumps({"react@latest": {
        "package_name": "react", "version": "latest", "verdict": "ALLOW",
        "timestamp": "2026-05-10T00:00:00+00:00", "ttl_hours": 24,
    }}))

    original = tmp_cache.read_text()

    real_replace = offline_cache.os.replace
    monkeypatch.setattr(offline_cache.os, "replace",
                        lambda *a, **kw: (_ for _ in ()).throw(OSError("rename failed")))

    await offline_cache.record_allow("lodash")
    # The original file should be unchanged (the new attempt failed).
    assert tmp_cache.read_text() == original
    # Restore the real implementation explicitly so subsequent tests are clean
    monkeypatch.setattr(offline_cache.os, "replace", real_replace)
