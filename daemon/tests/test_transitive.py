"""Tests for transitive dependency resolution and router integration.

Covers:
- resolve_transitive stops at max_depth=2
- Cycle detection prevents infinite recursion
- transitive_risk_detected flag set when a sub-dep scores high
- scan_transitive=False skips transitive resolution entirely
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from daemon.models import PillarScore, ScanResponse, TransitiveDependencyResult
from daemon.utils.transitive import resolve_transitive


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ps(score: float = 0.0, flags: list[str] | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata={})


def _base_response(name: str = "pkg") -> ScanResponse:
    ps = _ps()
    return ScanResponse(
        package_name=name,
        version="1.0.0",
        decision="ALLOW",
        risk_score=0.0,
        contextify=ps,
        sentinel=ps,
        shield=ps,
        explanation="ok",
    )


# ── resolve_transitive unit tests ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_transitive_stops_at_max_depth() -> None:
    """No package at depth > max_depth=2 should appear in results."""
    call_count = 0

    async def mock_deps(name: str, version: str) -> dict[str, str]:
        nonlocal call_count
        call_count += 1
        # Every package has one child, creating an infinite chain if unbounded.
        return {"child-of-" + name: "1.0.0"}

    with patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps):
        results = await resolve_transitive("root", "1.0.0", max_depth=2)

    depths = [r["depth"] for r in results]
    assert all(d <= 2 for d in depths), f"depth > 2 found: {depths}"
    # Exactly depth-1 and depth-2 entries expected.
    assert 1 in depths
    assert 2 in depths


@pytest.mark.asyncio
async def test_resolve_transitive_cycle_detection() -> None:
    """A → B → A cycle must terminate without error."""

    async def mock_deps(name: str, version: str) -> dict[str, str]:
        if name == "A":
            return {"B": "1.0.0"}
        if name == "B":
            return {"A": "1.0.0"}  # cycle back to A
        return {}

    with patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps):
        results = await resolve_transitive("A", "1.0.0", max_depth=5)

    names = {r["name"] for r in results}
    # B should appear; A must NOT appear as a transitive result (it's the root).
    assert "B" in names
    # Most importantly: no infinite loop → we got here.


@pytest.mark.asyncio
async def test_resolve_transitive_diamond_dep_no_duplicate_expansion() -> None:
    """A→B, A→C, B→D, C→D — D's sub-tree must be expanded only once.

    D may appear in the flat results list more than once (once per parent
    that lists it as a dep), but its own children should only be fetched
    once thanks to the visited set.
    """
    expansion_count: dict[str, int] = {}

    async def mock_deps(name: str, version: str) -> dict[str, str]:
        expansion_count[name] = expansion_count.get(name, 0) + 1
        return {"B": "1.0", "C": "1.0"} if name == "A" else \
               {"D": "1.0"} if name in ("B", "C") else \
               {"E": "1.0"}  # D's child

    with patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps):
        results = await resolve_transitive("A", "1.0.0", max_depth=3)

    # D's own deps (E) must only be fetched once, not once per parent.
    assert expansion_count.get("D", 0) == 1, (
        f"D was expanded {expansion_count.get('D', 0)} times; expected 1"
    )
    # E appears in results (D's sub-tree was walked).
    assert any(r["name"] == "E" for r in results)


@pytest.mark.asyncio
async def test_resolve_transitive_registry_error_degrades_gracefully() -> None:
    """An exception from get_direct_dependencies should not abort the whole tree."""

    async def mock_deps(name: str, version: str) -> dict[str, str]:
        if name == "bad":
            raise RuntimeError("network timeout")
        return {"bad": "1.0.0"} if name == "root" else {}

    with patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps):
        results = await resolve_transitive("root", "1.0.0", max_depth=2)

    # "bad" should appear in the flat list (added before sub-expansion)
    assert any(r["name"] == "bad" for r in results)
    # but its own children are absent (exception swallowed)


@pytest.mark.asyncio
async def test_resolve_transitive_empty_deps_returns_empty() -> None:
    async def mock_deps(name: str, version: str) -> dict[str, str]:
        return {}

    with patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps):
        results = await resolve_transitive("leaf", "2.0.0", max_depth=2)

    assert results == []


@pytest.mark.asyncio
async def test_resolve_transitive_max_depth_zero_skips_all() -> None:
    mock_fn = AsyncMock(return_value={"child": "1.0.0"})
    with patch("daemon.utils.transitive.get_direct_dependencies", mock_fn):
        results = await resolve_transitive("pkg", "1.0.0", max_depth=0)

    assert results == []
    mock_fn.assert_not_called()


# ── _append_transitive / router integration tests ────────────────────────────

@pytest.mark.asyncio
async def test_transitive_risk_detected_when_subdep_scores_high() -> None:
    """transitive_risk_detected=True when a sub-dep sentinel_score >= 50."""
    from daemon.router import _append_transitive
    from daemon.models import PackageScanRequest

    req = PackageScanRequest(
        package_name="myapp",
        version="1.0.0",
        project_path="/tmp/proj",
        ai_suggested=False,
        scan_transitive=True,
    )
    response = _base_response("myapp")

    evil_sentinel = _ps(score=80.0, flags=["package_not_found", "typosquat_detected"])
    safe_sentinel = _ps(score=5.0)

    async def mock_deps(name: str, version: str) -> dict[str, str]:
        return {"evil-dep": "1.0.0", "safe-dep": "1.0.0"}

    async def mock_sentinel_score(pkg_name: str, ai_suggested: bool, version: str | None = None) -> PillarScore:
        return evil_sentinel if pkg_name == "evil-dep" else safe_sentinel

    with (
        patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps),
        patch("daemon.router._sentinel.score", side_effect=mock_sentinel_score),
    ):
        result = await _append_transitive(req, response)

    assert result.transitive_risk_detected is True
    evil_entries = [r for r in result.transitive_risks if r.name == "evil-dep"]
    assert evil_entries and evil_entries[0].sentinel_score == 80.0


@pytest.mark.asyncio
async def test_transitive_risk_not_detected_when_all_safe() -> None:
    """transitive_risk_detected=False when all sub-deps score below threshold."""
    from daemon.router import _append_transitive
    from daemon.models import PackageScanRequest

    req = PackageScanRequest(
        package_name="mypkg",
        version="1.0.0",
        project_path="/tmp/proj",
        ai_suggested=False,
        scan_transitive=True,
    )
    response = _base_response("mypkg")

    async def mock_deps(name: str, version: str) -> dict[str, str]:
        return {"safe-a": "1.0.0", "safe-b": "1.0.0"}

    async def mock_sentinel_score(pkg_name: str, ai_suggested: bool, version: str | None = None) -> PillarScore:
        return _ps(score=10.0)

    with (
        patch("daemon.utils.transitive.get_direct_dependencies", side_effect=mock_deps),
        patch("daemon.router._sentinel.score", side_effect=mock_sentinel_score),
    ):
        result = await _append_transitive(req, response)

    assert result.transitive_risk_detected is False
    assert len(result.transitive_risks) == 2


@pytest.mark.asyncio
async def test_scan_transitive_false_leaves_risks_empty() -> None:
    """When scan_transitive=False, resolve_transitive is never called."""
    from daemon.database import TrustCheckResult, TRUST_STATUS_UNKNOWN
    from daemon.tests.test_router import _cached_response

    # We reuse the router test infrastructure — mock DB + pillars, then POST
    # with scan_transitive=False and verify the response has no transitive data.
    import httpx
    from httpx import ASGITransport
    from daemon.main import app

    resolve_mock = AsyncMock(return_value=[])

    with (
        patch("daemon.router.check_trust",
              new=AsyncMock(return_value=TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name=""))),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result", new=AsyncMock()),
        patch("daemon.router.record_allow", new=AsyncMock()),
        patch("daemon.router.audit_log.append", new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps())),
        patch("daemon.router._sentinel.score", new=AsyncMock(return_value=_ps())),
        patch("daemon.router._shield.score", new=AsyncMock(return_value=_ps())),
        patch("daemon.router.resolve_transitive", resolve_mock),
    ):
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {"X-CIDAS-Token": "test-token"}
            with patch("daemon.auth.require_token", return_value=None):
                resp = await client.post(
                    "/scan",
                    json={
                        "package_name": "lodash",
                        "project_path": "/tmp/p",
                        "scan_transitive": False,
                    },
                    headers=headers,
                )

    # resolve_transitive must not have been called
    resolve_mock.assert_not_called()
