"""Integration tests for the FastAPI router endpoints.

Uses the async_client fixture (httpx ASGITransport) — no real network or SQLite I/O.
Pillar scores and database operations are mocked to keep tests fast and deterministic.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from daemon.database import TrustCheckResult, TRUST_STATUS_UNKNOWN, TRUST_STATUS_VERIFIED
from daemon.models import PillarScore, ScanResponse


def _ps(score: float = 0.0, flags: list[str] | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata={})


def _cached_response(name: str = "cached-pkg", decision: str = "ALLOW") -> ScanResponse:
    ps = _ps(0.0)
    return ScanResponse(
        package_name=name,
        version=None,
        decision=decision,  # type: ignore[arg-type]
        risk_score=0.0,
        contextify=ps,
        sentinel=ps,
        shield=ps,
        explanation="Cached result.",
    )


_UNKNOWN_TRUST = TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name="")
_VERIFIED_TRUST = TrustCheckResult(status=TRUST_STATUS_VERIFIED, package_name="")


_DISK_UNAVAILABLE = {
    "estimated_install_bytes": 0,
    "estimated_install_mb": 0.0,
    "available_disk_bytes": 0,
    "available_disk_mb": 0.0,
    "node_modules_bytes": 0,
    "dep_count": 0,
    "will_fit": True,
    "flags": ["disk_check_unavailable"],
    "disk_risk_score": 0.0,
}


@pytest.fixture
def mock_db():
    """Patch all database references in daemon.router to avoid SQLite I/O.

    Also stubs check_disk_footprint so existing tests do not make real npm
    registry calls for package size lookups.
    """
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result", new=AsyncMock()),
        patch("daemon.router.add_trusted", new=AsyncMock()),
        patch("daemon.router.clear_expired", new=AsyncMock(return_value=3)),
        patch("daemon.router.invalidate_package", new=AsyncMock(return_value=1)),
        patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=[])),
        patch("daemon.router.record_allow", new=AsyncMock()),
        patch("daemon.router.audit_log.append", new=AsyncMock()),
        patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])),
        patch(
            "daemon.utils.disk_checker.check_disk_footprint",
            new=AsyncMock(return_value=_DISK_UNAVAILABLE),
        ),
    ):
        yield


@pytest.fixture
def mock_pillars_low():
    """Patch all three pillar score() methods to return zero risk."""
    low = _ps(0.0)
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=low)),
    ):
        yield


# ── GET /health ───────────────────────────────────────────────────────────────

async def test_health_returns_ok(async_client):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


async def test_health_includes_drift_field(async_client):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert "drift" in body
    assert "status" in body["drift"]
    assert body["drift"]["status"] in (
        "ok", "warn", "alert", "insufficient_data", "unavailable"
    )


async def test_health_drift_has_required_fields(async_client):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    drift = response.json()["drift"]
    for key in ("status", "overall_kl", "drifted_pillars", "sufficient_data", "baseline_loaded"):
        assert key in drift, f"missing key: {key}"


async def test_health_still_returns_200_when_drift_raises(async_client):
    with patch("daemon.router.check_drift", side_effect=RuntimeError("test error")):
        response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["drift"]["status"] == "unavailable"


# ── POST /scan — decision paths ───────────────────────────────────────────────

async def test_scan_allow(async_client, mock_db, mock_pillars_low):
    """All-zero pillar scores must produce ALLOW with risk_score == 0."""
    response = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": "/tmp/project",
        "ai_suggested": False,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] == 0.0
    assert body["package_name"] == "lodash"
    assert "latency_ms" in body


async def test_scan_warn(async_client, mock_db):
    """Pillar scores that land in the WARN band (40–79) must produce WARN."""
    # 0.30×0 + 0.35×80 + 0.35×40 = 0 + 28 + 14 = 42 → WARN
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=_ps(80.0))),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=_ps(40.0))),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "suspicious-pkg",
            "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "WARN"
    assert 40.0 <= body["risk_score"] < 80.0


async def test_scan_block(async_client, mock_db):
    """High pillar scores must produce BLOCK with risk_score >= 80."""
    # ctx=100 + sentinel=100 + shield=100 → 100 → BLOCK.
    high = _ps(100.0, flags=["package_not_found", "eval_usage"])
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(100.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=high)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=high)),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "malicious-pkg",
            "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["risk_score"] >= 80.0


# ── POST /scan — cache and trust paths ────────────────────────────────────────

async def test_scan_cache_hit_skips_pillars(async_client, mock_db):
    """A cache hit must return immediately without invoking any pillar."""
    cached = _cached_response("lodash", "ALLOW")
    with (
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=cached)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
        patch("daemon.router._sentinel.score", new=AsyncMock()) as sen,
        patch("daemon.router._shield.score", new=AsyncMock()) as shi,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    ctx.assert_not_called()
    sen.assert_not_called()
    shi.assert_not_called()


async def test_scan_trust_bypass_skips_pillars(async_client, mock_db):
    """A VERIFIED trusted package must return ALLOW immediately without calling pillars."""
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_VERIFIED_TRUST)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
        patch("daemon.router._sentinel.score", new=AsyncMock()) as sen,
        patch("daemon.router._shield.score", new=AsyncMock()) as shi,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "react",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] == 0.0
    ctx.assert_not_called()
    sen.assert_not_called()
    shi.assert_not_called()


async def test_scan_response_includes_pillar_breakdown(async_client, mock_db, mock_pillars_low):
    """ScanResponse must expose contextify, sentinel, and shield sub-objects."""
    response = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": "/tmp/project",
    })
    assert response.status_code == 200
    body = response.json()
    for pillar in ("contextify", "sentinel", "shield"):
        assert pillar in body
        assert "score" in body[pillar]
        assert "flags" in body[pillar]


async def test_scan_result_is_stored(async_client, mock_db, mock_pillars_low):
    """After a full scan (cache miss), store_result must be called once."""
    with patch("daemon.router.store_result", new=AsyncMock()) as store_mock:
        await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    store_mock.assert_called_once()


# ── Offline cache mirroring ──────────────────────────────────────────────────

async def test_allow_verdict_writes_offline_cache(async_client, mock_db, mock_pillars_low):
    """An ALLOW verdict must mirror to the offline cache for shim use."""
    with patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock:
        await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    rec_mock.assert_called_once_with("lodash", None)


async def test_warn_verdict_does_NOT_write_offline_cache(async_client, mock_db):
    """WARN must not enter the offline cache — silent install would be unsafe."""
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(80.0))),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(40.0))),
        patch("daemon.router.record_allow",      new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "suspicious-pkg", "project_path": "/tmp/project",
        })
    rec_mock.assert_not_called()


async def test_block_verdict_does_NOT_write_offline_cache(async_client, mock_db):
    """BLOCK must not enter the offline cache."""
    high = _ps(100.0, flags=["package_not_found"])
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=high)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=high)),
        patch("daemon.router.record_allow",      new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "evil-pkg", "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    rec_mock.assert_not_called()


async def test_trust_bypass_writes_offline_cache(async_client, mock_db):
    """A verified-trusted ALLOW must also persist to the offline cache."""
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=_VERIFIED_TRUST)),
        patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock,
    ):
        await async_client.post("/api/v1/scan", json={
            "package_name": "internal-lib", "project_path": "/tmp/project",
        })
    rec_mock.assert_called_once_with("internal-lib", None)


# ── POST /trust ───────────────────────────────────────────────────────────────

async def test_trust_endpoint_returns_trusted_name(async_client, mock_db):
    response = await async_client.post("/api/v1/trust", json={"package_name": "lodash"})
    assert response.status_code == 200
    assert response.json()["trusted"] == "lodash"


async def test_trust_endpoint_missing_name_returns_422(async_client, mock_db):
    response = await async_client.post("/api/v1/trust", json={})
    assert response.status_code == 422


# ── DELETE /cache ─────────────────────────────────────────────────────────────

async def test_cache_delete_returns_purge_count(async_client, mock_db):
    response = await async_client.delete("/api/v1/cache")
    assert response.status_code == 200
    body = response.json()
    assert "purged" in body
    assert isinstance(body["purged"], int)


# ── GET /audit ────────────────────────────────────────────────────────────────

async def test_audit_returns_empty_when_log_absent(async_client):
    """Endpoint returns empty list when no records match."""
    with patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])):
        response = await async_client.get("/api/v1/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["events"] == []
    assert body["total"] == 0


async def test_audit_returns_parsed_events(async_client):
    """Endpoint returns records from audit_log.read_records."""
    events = [
        {"ts": "2026-05-10T10:00:00+00:00", "package": "lodash@4", "verdict": "ALLOW",
         "score": 5.0, "signals": [], "ai_suggested": False, "project_path": "/p", "cached": False},
        {"ts": "2026-05-10T10:05:00+00:00", "package": "axios@1", "verdict": "WARN",
         "score": 45.0, "signals": [], "ai_suggested": False, "project_path": "/p", "cached": False},
    ]
    with patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=events)):
        response = await async_client.get("/api/v1/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["events"][0]["package"] == "lodash@4"
    assert body["events"][1]["verdict"] == "WARN"


async def test_audit_passes_query_params_to_read_records(async_client):
    """Query parameters are forwarded to audit_log.read_records correctly."""
    with patch("daemon.router.audit_log.read_records", new=AsyncMock(return_value=[])) as mock_rr:
        await async_client.get("/api/v1/audit?verdict=BLOCK&package=lodash&last=50")
    mock_rr.assert_awaited_once_with(last=50, verdict="BLOCK", package="lodash", since=None)


async def test_audit_invalid_verdict_returns_422(async_client):
    """An unrecognised verdict value must be rejected with 422."""
    response = await async_client.get("/api/v1/audit?verdict=MAYBE")
    assert response.status_code == 422


# ── POST /cache/invalidate ────────────────────────────────────────────────────

async def test_cache_invalidate_specific_version(async_client, mock_db):
    """Invalidating a specific version removes exactly that entry."""
    with patch("daemon.router.invalidate_package", new=AsyncMock(return_value=1)) as inv_mock:
        response = await async_client.post(
            "/api/v1/cache/invalidate",
            json={"package_name": "lodash", "version": "4.17.21"},
            headers={"Authorization": "Bearer ignored-in-test"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["invalidated"] == 1
    assert body["package_name"] == "lodash"
    assert body["version"] == "4.17.21"
    inv_mock.assert_called_once_with("lodash", "4.17.21")


async def test_cache_invalidate_wildcard_all_versions(async_client, mock_db):
    """version='*' must be forwarded verbatim to invalidate_package."""
    with patch("daemon.router.invalidate_package", new=AsyncMock(return_value=3)) as inv_mock:
        response = await async_client.post(
            "/api/v1/cache/invalidate",
            json={"package_name": "lodash", "version": "*"},
        )
    assert response.status_code == 200
    assert response.json()["invalidated"] == 3
    inv_mock.assert_called_once_with("lodash", "*")


async def test_cache_invalidate_missing_package_name_returns_422(async_client, mock_db):
    response = await async_client.post(
        "/api/v1/cache/invalidate", json={"version": "1.0.0"}
    )
    assert response.status_code == 422


async def test_cache_invalidate_missing_version_returns_422(async_client, mock_db):
    response = await async_client.post(
        "/api/v1/cache/invalidate", json={"package_name": "lodash"}
    )
    assert response.status_code == 422


# ── Version propagation in scan ───────────────────────────────────────────────

async def test_scan_with_explicit_version_mirrors_to_offline_cache(
    async_client, mock_db, mock_pillars_low
):
    """An ALLOW for name@version must record the version in the offline-cache call."""
    with patch("daemon.router.record_allow", new=AsyncMock()) as rec_mock:
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "version": "4.17.21",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    rec_mock.assert_called_once_with("lodash", "4.17.21")


# ── Trust integrity — router behavior ─────────────────────────────────────────

async def test_legacy_trust_returns_warn(async_client, mock_db):
    """A legacy trust row (no MAC) must return WARN and not skip the scan."""
    from daemon.database import TrustCheckResult, TRUST_STATUS_LEGACY
    legacy = TrustCheckResult(
        status=TRUST_STATUS_LEGACY, package_name="old-pkg", flags=["trust_legacy_no_mac"]
    )
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=legacy)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "old-pkg", "project_path": "/tmp",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "WARN"
    assert "trust_legacy_no_mac" in body["trust_flags"]
    # Legacy trust still short-circuits the pillar scan.
    ctx.assert_not_called()


async def test_tampered_trust_runs_full_scan_with_flag(async_client, mock_db, mock_pillars_low):
    """A tampered trust row must NOT short-circuit; the flag appears in the response."""
    from daemon.database import TrustCheckResult, TRUST_STATUS_TAMPERED
    tampered = TrustCheckResult(
        status=TRUST_STATUS_TAMPERED,
        package_name="tampered-pkg",
        flags=["trust_tamper_detected"],
    )
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=tampered)),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))) as ctx,
        patch("daemon.router._sentinel.score",  new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._shield.score",    new=AsyncMock(return_value=_ps(0.0))),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "tampered-pkg", "project_path": "/tmp",
        })
    assert response.status_code == 200
    body = response.json()
    assert "trust_tamper_detected" in body["trust_flags"]
    ctx.assert_called_once()  # full pillar scan ran


# ── GET /trust/verify ─────────────────────────────────────────────────────────

async def test_trust_verify_empty_list(async_client, mock_db):
    """Verify endpoint returns empty report when no packages are trusted."""
    with patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=[])):
        response = await async_client.get("/api/v1/trust/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["tampered"] == 0
    assert body["tampered_packages"] == []


async def test_trust_verify_reports_tampered_rows(async_client, mock_db):
    """Verify endpoint must surface tampered rows in tampered_packages."""
    from daemon.database import TRUST_STATUS_TAMPERED, TRUST_STATUS_VERIFIED
    fake_rows = [
        {"package_name": "react",  "added_at": 1.0, "source": "api",
         "mac_status": "ok", "verification": TRUST_STATUS_VERIFIED},
        {"package_name": "evil",   "added_at": 2.0, "source": "api",
         "mac_status": "ok", "verification": TRUST_STATUS_TAMPERED},
    ]
    with patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=fake_rows)):
        response = await async_client.get("/api/v1/trust/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["verified"] == 1
    assert body["tampered"] == 1
    assert body["tampered_packages"][0]["package_name"] == "evil"


async def test_trust_verify_reports_legacy_rows(async_client, mock_db):
    """Verify endpoint must count legacy rows separately from tampered ones."""
    from daemon.database import TRUST_STATUS_LEGACY, TRUST_STATUS_VERIFIED
    fake_rows = [
        {"package_name": "old-pkg", "added_at": 1.0, "source": "api",
         "mac_status": "legacy_no_mac", "verification": TRUST_STATUS_LEGACY},
        {"package_name": "new-pkg", "added_at": 2.0, "source": "api",
         "mac_status": "ok", "verification": TRUST_STATUS_VERIFIED},
    ]
    with patch("daemon.router.list_all_trusted", new=AsyncMock(return_value=fake_rows)):
        response = await async_client.get("/api/v1/trust/verify")
    body = response.json()
    assert body["legacy_no_mac"] == 1
    assert body["tampered"] == 0
    assert body["verified"] == 1


# ── _append_direct_deps — exception handler (lines 77-78) ────────────────────

async def test_direct_deps_exception_logged_and_swallowed(async_client, mock_db, mock_pillars_low):
    """RuntimeError from get_direct_dependencies is caught; scan still returns 200 with no deps."""
    with patch("daemon.router.get_direct_dependencies", new=AsyncMock(side_effect=RuntimeError("registry down"))):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    assert response.json()["direct_dependencies"] == []


# ── Policy block_list / trust_list (lines 182-228) ───────────────────────────

async def test_scan_policy_block_list_returns_block(async_client, mock_db):
    """Package on project block_list must return BLOCK without calling any pillar."""
    from pathlib import Path
    policy_src = Path("/tmp/project/.cidas/policy.json")
    with (
        patch("daemon.router.policy.resolve", return_value=({"block_list": ["bad-pkg"]}, policy_src)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "bad-pkg",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["risk_score"] == 100.0
    assert "policy_block" in body["contextify"]["flags"]
    ctx.assert_not_called()


async def test_scan_policy_trust_list_returns_allow(async_client, mock_db):
    """Package on project trust_list must return ALLOW without calling any pillar."""
    with (
        patch("daemon.router.policy.resolve", return_value=({"trust_list": ["good-pkg"]}, None)),
        patch("daemon.router._contextify.score", new=AsyncMock()) as ctx,
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "good-pkg",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] == 0.0
    assert "policy_trust" in body["contextify"]["flags"]
    ctx.assert_not_called()


# ── Cache hit — tamper flag injection (line 291) ──────────────────────────────

async def test_cache_hit_with_tamper_flag_attached(async_client, mock_db):
    """TAMPERED trust + cache hit: tamper_flags are injected into the cached response."""
    from daemon.database import TrustCheckResult, TRUST_STATUS_TAMPERED
    cached = _cached_response("some-pkg", "ALLOW")
    tampered = TrustCheckResult(
        status=TRUST_STATUS_TAMPERED,
        package_name="some-pkg",
        flags=["trust_tamper_detected"],
    )
    with (
        patch("daemon.router.check_trust", new=AsyncMock(return_value=tampered)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=cached)),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "some-pkg",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    assert "trust_tamper_detected" in response.json()["trust_flags"]


# ── Cache hit + scan_transitive (line 296) ───────────────────────────────────

async def test_cache_hit_runs_transitive_when_requested(async_client, mock_db):
    """Cache hit with scan_transitive=True still runs _append_transitive on the cached result."""
    cached = _cached_response("cached-pkg", "ALLOW")
    fake_deps = [{"name": "trans-dep", "version": "1.0.0", "depth": 1}]
    low = _ps(0.0)
    with (
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=cached)),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
        patch("daemon.router.resolve_transitive", new=AsyncMock(return_value=fake_deps)),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=low)),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "cached-pkg",
            "project_path": "/tmp/project",
            "scan_transitive": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert len(body["transitive_risks"]) == 1
    assert body["transitive_risks"][0]["name"] == "trans-dep"


# ── _append_transitive full path (lines 84-123) ───────────────────────────────

async def test_scan_transitive_deps_scored_and_returned(async_client, mock_db):
    """scan_transitive=True triggers full transitive scan; risky dep detected in response."""
    low = _ps(0.0)
    risky = _ps(70.0, flags=["package_not_found"])
    fake_deps = [
        {"name": "evil-dep", "version": "1.0.0", "depth": 1},
        {"name": "safe-dep", "version": "2.0.0", "depth": 2},
    ]

    async def _route_sentinel(name, *args, **kwargs):
        return risky if name == "evil-dep" else low

    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score", new=AsyncMock(side_effect=_route_sentinel)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=low)),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
        patch("daemon.router.resolve_transitive", new=AsyncMock(return_value=fake_deps)),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "some-pkg",
            "project_path": "/tmp/project",
            "scan_transitive": True,
        })

    assert response.status_code == 200
    body = response.json()
    assert body["transitive_risk_detected"] is True
    evil = next(r for r in body["transitive_risks"] if r["name"] == "evil-dep")
    assert evil["sentinel_score"] == 70.0


async def test_transitive_resolve_exception_swallowed(async_client, mock_db, mock_pillars_low):
    """RuntimeError from resolve_transitive is caught; scan still returns 200."""
    with (
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
        patch("daemon.router.resolve_transitive", new=AsyncMock(side_effect=RuntimeError("timeout"))),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "some-pkg",
            "project_path": "/tmp/project",
            "scan_transitive": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert body["transitive_risks"] is None or body["transitive_risks"] == []


async def test_transitive_sentinel_exception_excludes_dep(async_client, mock_db):
    """Sentinel raising for a transitive dep returns None from _score_one; dep excluded from risks."""
    low = _ps(0.0)
    fake_deps = [{"name": "broken-dep", "version": "1.0.0", "depth": 1}]

    async def _route_sentinel(name, *args, **kwargs):
        if name == "broken-dep":
            raise RuntimeError("sentinel crash")
        return low

    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score", new=AsyncMock(side_effect=_route_sentinel)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=low)),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
        patch("daemon.router.resolve_transitive", new=AsyncMock(return_value=fake_deps)),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "some-pkg",
            "project_path": "/tmp/project",
            "scan_transitive": True,
        })

    assert response.status_code == 200
    body = response.json()
    assert body["transitive_risks"] == []
    assert body["transitive_risk_detected"] is False


# ── Policy penalties (lines 324-331) ─────────────────────────────────────────

async def test_policy_low_downloads_penalty_applied(async_client, mock_db):
    """min_monthly_downloads policy penalty adds 15 pts for AI-suggested with low DLs."""
    sen = PillarScore(score=0.0, confidence=0.9, flags=[], metadata={"monthly_downloads": 50})
    with (
        patch("daemon.router.policy.resolve", return_value=({"min_monthly_downloads": 1000}, None)),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=sen)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "new-ai-pkg",
            "project_path": "/tmp/project",
            "ai_suggested": True,
        })
    assert response.status_code == 200
    body = response.json()
    assert "policy_low_downloads" in body["sentinel"]["flags"]
    assert body["risk_score"] >= 15.0


async def test_policy_no_repository_penalty_applied(async_client, mock_db):
    """require_repository_link policy penalty adds 10 pts when sentinel reports no repo."""
    sen = PillarScore(score=0.0, confidence=0.9, flags=[], metadata={"has_repository": False})
    with (
        patch("daemon.router.policy.resolve", return_value=({"require_repository_link": True}, None)),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=sen)),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "no-repo-pkg",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert "policy_no_repository" in body["sentinel"]["flags"]
    assert body["risk_score"] >= 10.0


# ── GET /policy (lines 478-479) ───────────────────────────────────────────────

async def test_policy_endpoint_returns_resolved_policy(async_client):
    """GET /api/v1/policy returns merged policy dict and source file path."""
    from pathlib import Path
    merged = {"warn_requires_confirmation": True, "block_list": ["evil-dep"]}
    source = Path("/tmp/project/.cidas/policy.json")
    with patch("daemon.router.policy.resolve", return_value=(merged, source)):
        response = await async_client.get("/api/v1/policy?project_path=/tmp/project")
    assert response.status_code == 200
    body = response.json()
    assert body["project_path"] == "/tmp/project"
    assert body["policy_file"] == str(source)
    assert body["resolved"]["warn_requires_confirmation"] is True


async def test_policy_endpoint_null_file_when_no_policy_found(async_client):
    """GET /api/v1/policy returns policy_file=null when no .cidas/policy.json found."""
    with patch("daemon.router.policy.resolve", return_value=({}, None)):
        response = await async_client.get("/api/v1/policy?project_path=/tmp/noproject")
    assert response.status_code == 200
    body = response.json()
    assert body["policy_file"] is None
    assert body["resolved"] == {}


# ── POST /audit/override (lines 500-514) ─────────────────────────────────────

async def test_audit_override_logs_and_returns_success(async_client, mock_db):
    """POST /api/v1/audit/override records the override event and returns logged=True."""
    response = await async_client.post("/api/v1/audit/override", json={
        "package_name": "evil-pkg",
        "version": "1.0.0",
        "verdict_was": "BLOCK",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["logged"] is True
    assert body["package"] == "evil-pkg@1.0.0"
    assert body["event"] == "user_override"


async def test_audit_override_missing_package_name_returns_422(async_client, mock_db):
    """POST /api/v1/audit/override without package_name must return 422."""
    response = await async_client.post("/api/v1/audit/override", json={
        "verdict_was": "WARN",
    })
    assert response.status_code == 422


# ── Disk footprint integration ────────────────────────────────────────────────

async def test_scan_response_includes_disk_footprint(async_client, mock_db, mock_pillars_low):
    """When disk_check_enabled=True, ScanResponse must include a populated disk_footprint."""
    fake_disk = {
        "estimated_install_bytes": 1024 * 1024,
        "estimated_install_mb": 1.0,
        "available_disk_bytes": 10 * 1024 * 1024 * 1024,
        "available_disk_mb": 10240.0,
        "node_modules_bytes": 0,
        "dep_count": 2,
        "will_fit": True,
        "flags": [],
        "disk_risk_score": 0.0,
    }
    with patch(
        "daemon.utils.disk_checker.check_disk_footprint",
        new=AsyncMock(return_value=fake_disk),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert "disk_footprint" in body
    assert body["disk_footprint"] is not None
    assert "estimated_install_mb" in body["disk_footprint"]
    assert "will_fit" in body["disk_footprint"]


async def test_disk_check_disabled_omits_disk_footprint(async_client, mock_db, mock_pillars_low):
    """When disk_check_enabled=False, disk_footprint must be absent (null) in the response."""
    from daemon.config import Settings
    disabled_settings = Settings(disk_check_enabled=False)
    with patch("daemon.router.get_settings", return_value=disabled_settings):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "lodash",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    assert response.json()["disk_footprint"] is None


async def test_exceeds_disk_adds_flag_to_response(async_client, mock_db, mock_pillars_low):
    """'exceeds_available_disk' from the disk checker must surface as 'insufficient_disk_space'
    in the top-level response flags."""
    exceeds_disk = {
        "estimated_install_bytes": 20 * 1024 * 1024 * 1024,
        "estimated_install_mb": 20480.0,
        "available_disk_bytes": 1 * 1024 * 1024 * 1024,
        "available_disk_mb": 1024.0,
        "node_modules_bytes": 0,
        "dep_count": 1,
        "will_fit": False,
        "flags": ["exceeds_available_disk", "very_large_install", "large_install"],
        "disk_risk_score": 100.0,
    }
    with patch(
        "daemon.utils.disk_checker.check_disk_footprint",
        new=AsyncMock(return_value=exceeds_disk),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "massive-pkg",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert "insufficient_disk_space" in body["flags"]


async def test_cache_hit_includes_disk_footprint(async_client, mock_db):
    """Cache hits must also receive a disk_footprint — the old cached ScanResponse
    never had the field, so _append_disk_footprint must run on the cache-hit path."""
    cached = _cached_response("express", "WARN")
    fake_disk = {
        "estimated_install_bytes": 5 * 1024 * 1024,
        "estimated_install_mb": 5.0,
        "available_disk_bytes": 10 * 1024 * 1024 * 1024,
        "available_disk_mb": 10240.0,
        "node_modules_bytes": 0,
        "dep_count": 0,
        "will_fit": True,
        "flags": [],
        "disk_risk_score": 0.0,
    }
    with (
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=cached)),
        patch("daemon.router.get_direct_dependencies", new=AsyncMock(return_value={})),
        patch(
            "daemon.utils.disk_checker.check_disk_footprint",
            new=AsyncMock(return_value=fake_disk),
        ),
    ):
        response = await async_client.post("/api/v1/scan", json={
            "package_name": "express",
            "project_path": "/tmp/project",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["disk_footprint"] is not None
    assert body["disk_footprint"]["estimated_install_mb"] == 5.0
    assert body["disk_footprint"]["will_fit"] is True
