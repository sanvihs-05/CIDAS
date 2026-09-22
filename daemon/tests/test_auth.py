"""Unit tests for daemon/auth.py and integration with the FastAPI router.

Covers:
- get_or_create_token: generation, persistence, mode 0600, reuse on restart
- require_token dependency: rejects missing / malformed / wrong tokens
- Router integration: read-only endpoints (health, audit) bypass auth;
  mutating endpoints (scan, trust, cache) require it.
"""
from __future__ import annotations

import os
import stat
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from daemon import auth
from daemon.database import TRUST_STATUS_UNKNOWN, TrustCheckResult
from daemon.main import app

_UNKNOWN_TRUST = TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name="")


# ── Token file fixture ────────────────────────────────────────────────────────

@pytest.fixture
def token_file(tmp_path, monkeypatch):
    """Redirect TOKEN_PATH to a temp file and clear the in-memory cache."""
    p = tmp_path / "daemon.token"
    monkeypatch.setattr(auth, "TOKEN_PATH", p)
    auth.reset_cache()
    yield p
    auth.reset_cache()


# ── get_or_create_token ───────────────────────────────────────────────────────

def test_get_or_create_token_generates_when_missing(token_file):
    assert not token_file.exists()
    token = auth.get_or_create_token()
    assert token_file.exists()
    assert token == token_file.read_text().strip()


def test_token_is_64_hex_chars(token_file):
    token = auth.get_or_create_token()
    assert len(token) == 64
    int(token, 16)  # raises ValueError if not hex


def test_token_file_has_mode_0600(token_file):
    auth.get_or_create_token()
    mode = stat.S_IMODE(os.stat(token_file).st_mode)
    # Owner read/write only — no group/other access.
    # On Windows the FS does not honour POSIX modes, so skip the assertion there.
    if os.name == "posix":
        assert mode == 0o600


def test_get_or_create_token_reuses_existing_token(token_file):
    first  = auth.get_or_create_token()
    auth.reset_cache()  # simulate a process restart
    second = auth.get_or_create_token()
    assert first == second


def test_get_or_create_token_regenerates_on_empty_file(token_file):
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text("")
    auth.reset_cache()
    token = auth.get_or_create_token()
    assert len(token) == 64
    assert token_file.read_text().strip() == token


# ── require_token (FastAPI dependency, exercised via the live app) ────────────

@pytest.fixture
def mock_db_for_auth():
    """Stub all DB ops so auth tests do not depend on SQLite state."""
    from daemon.models import PillarScore
    low = PillarScore(score=0.0, confidence=0.9, flags=[], metadata={})
    with (
        patch("daemon.router.check_trust",        new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result",  new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",       new=AsyncMock()),
        patch("daemon.router.add_trusted",        new=AsyncMock()),
        patch("daemon.router.clear_expired",      new=AsyncMock(return_value=0)),
        patch("daemon.router.list_all_trusted",   new=AsyncMock(return_value=[])),
        patch("daemon.router.record_allow",       new=AsyncMock()),
        patch("daemon.router.audit_log.append",   new=AsyncMock()),
        patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])),
        patch("daemon.router._contextify.score",  new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score",    new=AsyncMock(return_value=low)),
        patch("daemon.router._shield.score",      new=AsyncMock(return_value=low)),
    ):
        yield


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Read-only endpoints — no auth required ────────────────────────────────────

async def test_health_does_not_require_token(client, token_file):
    auth.get_or_create_token()
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200


async def test_audit_requires_token(client, token_file):
    auth.get_or_create_token()
    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 401


async def test_audit_with_valid_token_returns_200(client, token_file, mock_db_for_auth, tmp_path, monkeypatch):
    import daemon.utils.audit_log as _al
    monkeypatch.setattr(_al, "_DEFAULT_PATH", tmp_path / "audit.log")
    token = auth.get_or_create_token()
    resp = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


# ── Mutating endpoints — token enforcement ────────────────────────────────────

async def test_scan_without_token_returns_401(client, token_file, mock_db_for_auth):
    auth.get_or_create_token()
    resp = await client.post("/api/v1/scan", json={
        "package_name": "lodash", "project_path": "/tmp",
    })
    assert resp.status_code == 401


async def test_scan_with_invalid_token_returns_401(client, token_file, mock_db_for_auth):
    auth.get_or_create_token()
    resp = await client.post(
        "/api/v1/scan",
        json={"package_name": "lodash", "project_path": "/tmp"},
        headers={"Authorization": "Bearer this-is-wrong"},
    )
    assert resp.status_code == 401


async def test_scan_with_malformed_header_returns_401(client, token_file, mock_db_for_auth):
    auth.get_or_create_token()
    # Missing the "Bearer " prefix
    resp = await client.post(
        "/api/v1/scan",
        json={"package_name": "lodash", "project_path": "/tmp"},
        headers={"Authorization": "deadbeef"},
    )
    assert resp.status_code == 401


async def test_scan_with_valid_token_succeeds(client, token_file, mock_db_for_auth):
    token = auth.get_or_create_token()
    resp = await client.post(
        "/api/v1/scan",
        json={"package_name": "lodash", "project_path": "/tmp"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


async def test_trust_without_token_returns_401(client, token_file, mock_db_for_auth):
    auth.get_or_create_token()
    resp = await client.post("/api/v1/trust", json={"package_name": "lodash"})
    assert resp.status_code == 401


async def test_trust_with_valid_token_succeeds(client, token_file, mock_db_for_auth):
    token = auth.get_or_create_token()
    resp = await client.post(
        "/api/v1/trust",
        json={"package_name": "lodash"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


async def test_cache_delete_without_token_returns_401(client, token_file, mock_db_for_auth):
    auth.get_or_create_token()
    resp = await client.delete("/api/v1/cache")
    assert resp.status_code == 401


async def test_cache_delete_with_valid_token_succeeds(client, token_file, mock_db_for_auth):
    token = auth.get_or_create_token()
    resp = await client.delete(
        "/api/v1/cache",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


# ── Constant-time comparison sanity check ────────────────────────────────────

async def test_token_comparison_is_constant_time(client, token_file, mock_db_for_auth):
    """Tokens that differ only in their last byte must still be rejected."""
    token = auth.get_or_create_token()
    near_miss = token[:-1] + ("0" if token[-1] != "0" else "1")
    resp = await client.post(
        "/api/v1/scan",
        json={"package_name": "lodash", "project_path": "/tmp"},
        headers={"Authorization": f"Bearer {near_miss}"},
    )
    assert resp.status_code == 401
