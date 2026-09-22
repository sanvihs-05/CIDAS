"""test_performance.py — latency budget and parallelism tests for the CIDAS daemon.

All tests use the ASGI test client (no real network or SQLite I/O).
Pillar and database operations are mocked so timings measure routing
overhead and asyncio scheduling, not external service latency.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from unittest.mock import AsyncMock, patch

import pytest

from daemon.database import TrustCheckResult, TRUST_STATUS_UNKNOWN, TRUST_STATUS_VERIFIED
from daemon.models import PillarScore, ScanResponse


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ps(score: float = 0.0, flags: list[str] | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata={})


def _cached(name: str = "sample-pkg", decision: str = "ALLOW") -> ScanResponse:
    ps = _ps(0.0)
    return ScanResponse(
        package_name=name,
        version=None,
        decision=decision,  # type: ignore[arg-type]
        risk_score=0.0,
        contextify=ps,
        sentinel=ps,
        shield=ps,
        explanation="Cached.",
    )


_UNKNOWN_TRUST  = TrustCheckResult(status=TRUST_STATUS_UNKNOWN,  package_name="sample-pkg")
_VERIFIED_TRUST = TrustCheckResult(status=TRUST_STATUS_VERIFIED, package_name="sample-pkg")

_SCAN_BODY = {
    "package_name": "sample-pkg",
    "version": "1.0.0",
    "project_path": "/tmp/cidas-perf-test",
    "ai_suggested": False,
    "requesting_tool": "cidas-perf",
}


def _percentile(sorted_vals: list[float], p: float) -> float:
    """Closest-rank percentile on a pre-sorted list."""
    if not sorted_vals:
        return 0.0
    idx = max(0, min(len(sorted_vals) - 1, int(round(p * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_real_network(mock_npm_registry):
    """Every test in this module measures routing/scheduling overhead, not
    real npm-registry latency. Without this, disk_checker's get_package_size
    call (invoked on every /scan, cache-hit or not — see router.py's
    _append_disk_footprint) makes a real HTTPS request to registry.npmjs.org,
    which is what actually blew the latency budgets here, not a regression
    in the routing code."""
    yield


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Bearer token header; the test client already bypasses auth, but real requests need it."""
    return {"Authorization": "Bearer test-token"}


@pytest.fixture
def mock_embeddings():
    """Return deterministic vectors from the embedding utility so no model loads."""
    with (
        patch("daemon.utils.embeddings.embed_text", return_value=[1.0, 0.0, 0.0]),
        patch("daemon.utils.embeddings.cosine_similarity", return_value=0.9),
    ):
        yield


@pytest.fixture
def mock_db():
    """Patch all database operations in daemon.router to avoid SQLite I/O."""
    with (
        patch("daemon.router.check_trust",              new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result",        new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",             new=AsyncMock()),
        patch("daemon.router.add_trusted",              new=AsyncMock()),
        patch("daemon.router.clear_expired",            new=AsyncMock(return_value=0)),
        patch("daemon.router.invalidate_package",       new=AsyncMock(return_value=0)),
        patch("daemon.router.list_all_trusted",         new=AsyncMock(return_value=[])),
        patch("daemon.router.record_allow",             new=AsyncMock()),
        patch("daemon.router.audit_log.append",         new=AsyncMock()),
        patch("daemon.router.audit_log.read_records",   new=AsyncMock(return_value=[])),
        patch("daemon.router.get_direct_dependencies",  new=AsyncMock(return_value={})),
    ):
        yield


@pytest.fixture
def mock_pillars_low():
    """All three pillars return zero risk instantly → ALLOW."""
    low = _ps(0.0)
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=low)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=low)),
    ):
        yield


@pytest.fixture
def mock_pillars_warn():
    """Pillar scores that produce a weighted score of ~46 → WARN (threshold 40)."""
    # score = 0.30*0 + 0.35*100 + 0.35*30 = 0 + 35 + 10.5 = 45.5
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(100.0, ["typosquat_detected"]))),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(30.0))),
    ):
        yield


@pytest.fixture
def mock_pillars_block():
    """Pillar scores that produce a weighted score of ~94 → BLOCK (threshold 80)."""
    # score = 0.30*80 + 0.35*100 + 0.35*100 = 24 + 35 + 35 = 94
    with (
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(80.0, ["alien_to_project"]))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(100.0, ["package_not_found"]))),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(100.0, ["malicious_install_script"]))),
    ):
        yield


# ── TestLatencyBudget ─────────────────────────────────────────────────────────

class TestLatencyBudget:
    LATENCY_BUDGET_MS = 1000

    async def test_cache_hit_latency(self, async_client, auth_headers, mock_db):
        """Cache-hit responses should complete with median < 50ms (over 10 reps)."""
        with patch("daemon.router.get_cached_result", new=AsyncMock(return_value=_cached())):
            # Pre-warm: pay any first-request initialisation cost before measuring.
            await async_client.post("/api/v1/scan", json=_SCAN_BODY, headers=auth_headers)
            latencies: list[float] = []
            for _ in range(10):
                t0 = time.perf_counter()
                resp = await async_client.post(
                    "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
                )
                latencies.append((time.perf_counter() - t0) * 1000)

        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
        median_ms = statistics.median(latencies)
        assert median_ms < 50, (
            f"Cache-hit median {median_ms:.1f}ms exceeded 50ms budget"
        )

    async def test_trust_bypass_latency(self, async_client, auth_headers, mock_db):
        """Trust-bypass (HMAC-verified) responses should complete with median < 50ms (over 10 reps)."""
        with patch("daemon.router.check_trust", new=AsyncMock(return_value=_VERIFIED_TRUST)):
            latencies: list[float] = []
            for _ in range(10):
                t0 = time.perf_counter()
                resp = await async_client.post(
                    "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
                )
                latencies.append((time.perf_counter() - t0) * 1000)

        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
        median_ms = statistics.median(latencies)
        assert median_ms < 50, (
            f"Trust-bypass median {median_ms:.1f}ms exceeded 50ms budget"
        )

    async def test_full_scan_latency_allow(
        self, async_client, auth_headers, mock_db, mock_pillars_low,
    ):
        """Full ALLOW scan: median < 1000ms, p95 < 1500ms (5 reps)."""
        latencies: list[float] = []
        for _ in range(5):
            t0 = time.perf_counter()
            resp = await async_client.post(
                "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
            )
            latencies.append((time.perf_counter() - t0) * 1000)

        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
        latencies.sort()
        median_ms = statistics.median(latencies)
        p95_ms    = _percentile(latencies, 0.95)
        assert median_ms < self.LATENCY_BUDGET_MS, (
            f"ALLOW scan median {median_ms:.1f}ms exceeded {self.LATENCY_BUDGET_MS}ms"
        )
        assert p95_ms < self.LATENCY_BUDGET_MS * 1.5, (
            f"ALLOW scan p95 {p95_ms:.1f}ms exceeded {self.LATENCY_BUDGET_MS * 1.5:.0f}ms"
        )

    async def test_full_scan_latency_warn(
        self, async_client, auth_headers, mock_db, mock_pillars_warn,
    ):
        """Full WARN scan: median < 1000ms, p95 < 1500ms (5 reps)."""
        latencies: list[float] = []
        for _ in range(5):
            t0 = time.perf_counter()
            resp = await async_client.post(
                "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
            )
            latencies.append((time.perf_counter() - t0) * 1000)

        assert resp.status_code == 200
        assert resp.json()["decision"] == "WARN"
        latencies.sort()
        median_ms = statistics.median(latencies)
        p95_ms    = _percentile(latencies, 0.95)
        assert median_ms < self.LATENCY_BUDGET_MS
        assert p95_ms < self.LATENCY_BUDGET_MS * 1.5

    async def test_full_scan_latency_block(
        self, async_client, auth_headers, mock_db, mock_pillars_block,
    ):
        """Full BLOCK scan: median < 1000ms, p95 < 1500ms (5 reps)."""
        latencies: list[float] = []
        for _ in range(5):
            t0 = time.perf_counter()
            resp = await async_client.post(
                "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
            )
            latencies.append((time.perf_counter() - t0) * 1000)

        assert resp.status_code == 200
        assert resp.json()["decision"] == "BLOCK"
        latencies.sort()
        median_ms = statistics.median(latencies)
        p95_ms    = _percentile(latencies, 0.95)
        assert median_ms < self.LATENCY_BUDGET_MS
        assert p95_ms < self.LATENCY_BUDGET_MS * 1.5

    async def test_pillars_run_in_parallel_not_sequential(
        self, async_client, auth_headers, mock_db,
    ):
        """Each pillar takes 200ms; asyncio.gather should complete in ~200ms, not ~600ms."""
        low = _ps(0.0)

        async def _slow_score(*args, **kwargs) -> PillarScore:
            await asyncio.sleep(0.2)
            return low

        with (
            patch("daemon.router._contextify.score", side_effect=_slow_score),
            patch("daemon.router._sentinel.score",   side_effect=_slow_score),
            patch("daemon.router._shield.score",     side_effect=_slow_score),
        ):
            t0 = time.perf_counter()
            resp = await async_client.post(
                "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000

        assert resp.status_code == 200
        assert elapsed_ms < 450, (
            f"Three 200ms pillar delays took {elapsed_ms:.1f}ms total — "
            "expected ~200ms (parallel via asyncio.gather), not ~600ms (sequential)"
        )

    async def test_x_cidas_latency_header_present(
        self, async_client, auth_headers, mock_db, mock_pillars_low,
    ):
        """Every scan response must carry X-CIDAS-Latency-Ms with a positive float value."""
        resp = await async_client.post(
            "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
        )
        assert resp.status_code == 200
        header = resp.headers.get("x-cidas-latency-ms")
        assert header is not None, "X-CIDAS-Latency-Ms response header is missing"
        latency_ms = float(header)
        assert latency_ms > 0, f"X-CIDAS-Latency-Ms should be > 0, got {latency_ms}"


# ── TestLatencyDistribution ───────────────────────────────────────────────────

class TestLatencyDistribution:

    async def test_latency_report(
        self, async_client, auth_headers, mock_db, mock_pillars_low,
    ):
        """Run 20 full scans, print a distribution report, and assert p95 < 1000ms."""
        latencies: list[float] = []
        for _ in range(20):
            t0 = time.perf_counter()
            resp = await async_client.post(
                "/api/v1/scan", json=_SCAN_BODY, headers=auth_headers,
            )
            latencies.append((time.perf_counter() - t0) * 1000)

        assert resp.status_code == 200

        latencies.sort()
        min_ms    = latencies[0]
        median_ms = statistics.median(latencies)
        p95_ms    = _percentile(latencies, 0.95)
        max_ms    = latencies[-1]

        print(
            f"\n=== Latency Distribution (n=20) ===\n"
            f"  min:    {min_ms:7.2f} ms\n"
            f"  median: {median_ms:7.2f} ms\n"
            f"  p95:    {p95_ms:7.2f} ms\n"
            f"  max:    {max_ms:7.2f} ms\n"
        )

        assert p95_ms < 1000, (
            f"p95 latency {p95_ms:.1f}ms exceeded 1000ms budget"
        )
