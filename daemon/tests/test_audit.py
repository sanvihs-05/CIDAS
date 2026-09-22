"""Tests for audit logging: write, rotation, query filters, and endpoints.

Covers:
- audit_log.append writes a JSONL record
- audit_log.read_records filters by verdict, package, since
- Rotation triggers when the file exceeds _MAX_BYTES
- Rotated files cap at _MAX_ROTATED; the oldest is dropped
- POST /scan appends an audit record
- POST /audit/override appends an override event
- GET /audit returns records and honours query filters
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

import daemon.utils.audit_log as audit_log_mod
from daemon.utils.audit_log import (
    _MAX_BYTES,
    _MAX_ROTATED,
    _rotated,
    _rotate_sync,
    append,
    read_records,
)
from daemon.database import TrustCheckResult, TRUST_STATUS_UNKNOWN
from daemon.models import PillarScore, ScanResponse


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ps(score: float = 0.0) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=[], metadata={})


def _scan_record(**kwargs) -> dict:
    base = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "package": "lodash@4.17.21",
        "verdict": "ALLOW",
        "score": 5.0,
        "signals": [],
        "ai_suggested": False,
        "project_path": "/tmp/project",
        "cached": False,
    }
    base.update(kwargs)
    return base


@pytest.fixture(autouse=True)
def redirect_audit_path(tmp_path, monkeypatch):
    """Send all audit I/O to a temp directory so tests do not touch ~/.cidas."""
    p = tmp_path / "audit.log"
    monkeypatch.setattr(audit_log_mod, "_DEFAULT_PATH", p)
    return p


# ── append / read_records ─────────────────────────────────────────────────────

async def test_append_creates_file_and_writes_jsonl(redirect_audit_path):
    record = _scan_record(verdict="ALLOW")
    await append(record)
    assert redirect_audit_path.exists()
    lines = redirect_audit_path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == record


async def test_multiple_appends_produce_multiple_lines(redirect_audit_path):
    for verdict in ("ALLOW", "WARN", "BLOCK"):
        await append(_scan_record(verdict=verdict))
    lines = redirect_audit_path.read_text().splitlines()
    assert len(lines) == 3
    verdicts = [json.loads(l)["verdict"] for l in lines]
    assert verdicts == ["ALLOW", "WARN", "BLOCK"]


async def test_read_records_returns_all_when_no_filters(redirect_audit_path):
    for v in ("ALLOW", "WARN", "BLOCK"):
        await append(_scan_record(verdict=v))
    records = await read_records(last=100)
    assert len(records) == 3


async def test_read_records_filter_by_verdict(redirect_audit_path):
    await append(_scan_record(verdict="ALLOW", package="lodash@4"))
    await append(_scan_record(verdict="WARN",  package="evil@1"))
    await append(_scan_record(verdict="BLOCK", package="bad@2"))
    records = await read_records(verdict="WARN")
    assert len(records) == 1
    assert records[0]["verdict"] == "WARN"


async def test_read_records_filter_by_package(redirect_audit_path):
    await append(_scan_record(package="lodash@4.17.21"))
    await append(_scan_record(package="axios@1.0.0"))
    await append(_scan_record(package="lodash@4.17.20"))
    records = await read_records(package="lodash")
    assert len(records) == 2
    assert all(r["package"].startswith("lodash@") for r in records)


async def test_read_records_filter_by_since(redirect_audit_path):
    await append(_scan_record(ts="2026-01-01T00:00:00+00:00", verdict="ALLOW"))
    await append(_scan_record(ts="2026-06-01T00:00:00+00:00", verdict="WARN"))
    records = await read_records(since="2026-03-01T00:00:00+00:00")
    assert len(records) == 1
    assert records[0]["verdict"] == "WARN"


async def test_read_records_last_caps_results(redirect_audit_path):
    for i in range(10):
        await append(_scan_record(package=f"pkg-{i}@1.0.0"))
    records = await read_records(last=3)
    assert len(records) == 3
    # last N means the tail (most recent)
    assert records[-1]["package"] == "pkg-9@1.0.0"


async def test_read_records_last_capped_at_1000(redirect_audit_path):
    for _ in range(5):
        await append(_scan_record())
    records = await read_records(last=9999)
    assert len(records) == 5


async def test_read_records_missing_file_returns_empty():
    records = await read_records()
    assert records == []


async def test_combined_filters(redirect_audit_path):
    await append(_scan_record(package="lodash@4", verdict="BLOCK", ts="2026-04-01T00:00:00+00:00"))
    await append(_scan_record(package="lodash@4", verdict="ALLOW", ts="2026-05-01T00:00:00+00:00"))
    await append(_scan_record(package="axios@1",  verdict="BLOCK", ts="2026-05-01T00:00:00+00:00"))
    records = await read_records(verdict="BLOCK", package="lodash", since="2026-03-01T00:00:00+00:00")
    assert len(records) == 1
    assert records[0]["package"] == "lodash@4"


# ── Rotation ──────────────────────────────────────────────────────────────────

def test_rotate_sync_renames_log_to_dot1(redirect_audit_path):
    redirect_audit_path.write_text("line\n")
    _rotate_sync(redirect_audit_path)
    assert not redirect_audit_path.exists()
    assert _rotated(redirect_audit_path, 1).exists()


def test_rotate_sync_shifts_existing_rotated_files(redirect_audit_path):
    redirect_audit_path.write_text("current\n")
    _rotated(redirect_audit_path, 1).write_text("old-1\n")
    _rotated(redirect_audit_path, 2).write_text("old-2\n")
    _rotate_sync(redirect_audit_path)
    assert _rotated(redirect_audit_path, 1).read_text() == "current\n"
    assert _rotated(redirect_audit_path, 2).read_text() == "old-1\n"
    assert _rotated(redirect_audit_path, 3).read_text() == "old-2\n"


def test_rotate_sync_drops_oldest_when_at_max(redirect_audit_path):
    redirect_audit_path.write_text("current\n")
    for i in range(1, _MAX_ROTATED + 1):
        _rotated(redirect_audit_path, i).write_text(f"rotated-{i}\n")
    _rotate_sync(redirect_audit_path)
    # .3 (the old .MAX_ROTATED) was dropped; new .3 is what was .2
    assert not redirect_audit_path.exists()
    assert _rotated(redirect_audit_path, 1).read_text() == "current\n"
    assert _rotated(redirect_audit_path, _MAX_ROTATED).exists()
    # There should be no .4 file
    assert not (redirect_audit_path.parent / f"{redirect_audit_path.name}.{_MAX_ROTATED + 1}").exists()


async def test_append_triggers_rotation_when_file_exceeds_max_bytes(redirect_audit_path, monkeypatch):
    """When the file is at or above _MAX_BYTES, append must rotate before writing."""
    monkeypatch.setattr(audit_log_mod, "_MAX_BYTES", 10)  # rotate after 10 bytes
    await append(_scan_record())  # first write — creates file, < 10 bytes trigger
    first_content = redirect_audit_path.read_text()
    # Force the file to appear large enough to trigger rotation on next write.
    redirect_audit_path.write_text("x" * 11)
    await append(_scan_record(verdict="WARN"))
    assert _rotated(redirect_audit_path, 1).exists()
    assert redirect_audit_path.exists()
    # The new audit.log should contain only the second record
    new_lines = redirect_audit_path.read_text().splitlines()
    assert len(new_lines) == 1
    assert json.loads(new_lines[0])["verdict"] == "WARN"


# ── Router integration: scan appends audit record ─────────────────────────────

_UNKNOWN_TRUST = TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name="")


@pytest.fixture
def mock_db_and_pillars():
    low = _ps(0.0)
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",      new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=low)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=low)),
    ):
        yield


async def test_scan_appends_audit_record(async_client, mock_db_and_pillars, redirect_audit_path):
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "version": "4.17.21",
        "project_path": "/tmp/test",
        "ai_suggested": False,
    })
    assert resp.status_code == 200
    lines = redirect_audit_path.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["package"] == "lodash@4.17.21"
    assert record["verdict"] == "ALLOW"
    assert record["ai_suggested"] is False
    assert record["project_path"] == "/tmp/test"
    assert record["cached"] is False
    assert "ts" in record
    assert "score" in record


async def test_scan_cached_result_sets_cached_true(async_client, redirect_audit_path):
    cached_resp = ScanResponse(
        package_name="lodash", version="4.17.21", decision="ALLOW",
        risk_score=3.0, contextify=_ps(), sentinel=_ps(), shield=_ps(),
        explanation="Cached.",
    )
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=cached_resp)),
    ):
        resp = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash", "version": "4.17.21", "project_path": "/tmp",
        })
    assert resp.status_code == 200
    record = json.loads(redirect_audit_path.read_text().strip())
    assert record["cached"] is True


# ── Router integration: override endpoint ─────────────────────────────────────

async def test_override_endpoint_appends_event(async_client, redirect_audit_path):
    resp = await async_client.post("/api/v1/audit/override", json={
        "package_name": "lodash",
        "version": "4.17.21",
        "verdict_was": "WARN",
    })
    assert resp.status_code == 200
    assert resp.json()["logged"] is True
    record = json.loads(redirect_audit_path.read_text().strip())
    assert record["event"] == "user_override"
    assert record["package"] == "lodash@4.17.21"
    assert record["verdict_was"] == "WARN"
    assert "ts" in record


async def test_override_defaults_version_to_latest(async_client, redirect_audit_path):
    resp = await async_client.post("/api/v1/audit/override", json={
        "package_name": "express",
    })
    assert resp.status_code == 200
    record = json.loads(redirect_audit_path.read_text().strip())
    assert record["package"] == "express@latest"


async def test_override_without_package_name_returns_422(async_client, redirect_audit_path):
    resp = await async_client.post("/api/v1/audit/override", json={})
    assert resp.status_code == 422


# ── Router integration: GET /audit filters ────────────────────────────────────

async def test_get_audit_returns_records(async_client, redirect_audit_path):
    for v in ("ALLOW", "WARN", "BLOCK"):
        await append(_scan_record(verdict=v))
    resp = await async_client.get("/api/v1/audit")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert len(body["events"]) == 3


async def test_get_audit_filter_verdict(async_client, redirect_audit_path):
    await append(_scan_record(verdict="ALLOW"))
    await append(_scan_record(verdict="BLOCK"))
    resp = await async_client.get("/api/v1/audit?verdict=BLOCK")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["events"][0]["verdict"] == "BLOCK"


async def test_get_audit_filter_package(async_client, redirect_audit_path):
    await append(_scan_record(package="lodash@4.17.21"))
    await append(_scan_record(package="axios@1.0.0"))
    resp = await async_client.get("/api/v1/audit?package=lodash")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["events"][0]["package"] == "lodash@4.17.21"


async def test_get_audit_filter_since(async_client, redirect_audit_path):
    await append(_scan_record(ts="2026-01-01T00:00:00+00:00"))
    await append(_scan_record(ts="2026-06-01T00:00:00+00:00"))
    resp = await async_client.get("/api/v1/audit?since=2026-03-01T00:00:00%2B00:00")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


async def test_get_audit_invalid_verdict_returns_422(async_client):
    resp = await async_client.get("/api/v1/audit?verdict=MAYBE")
    assert resp.status_code == 422


async def test_get_audit_last_param(async_client, redirect_audit_path):
    for i in range(5):
        await append(_scan_record(package=f"pkg-{i}@1.0.0"))
    resp = await async_client.get("/api/v1/audit?last=2")
    assert resp.status_code == 200
    assert resp.json()["total"] == 2
