"""Tests for the Sentinel pillar.

Covers the hallucination-risk path (ai_suggested=True) and the fast-path
(ai_suggested=False) separately.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from daemon.models import PillarScore
from daemon.pillars import sentinel as sentinel_module
from daemon.pillars.sentinel import Sentinel, _levenshtein, _normalize_confusables
from daemon.utils.npm_registry import RegistryLookup, RegistryResult


@pytest.fixture(autouse=True)
def _no_admin_config(monkeypatch):
    """Disable ~/.cidas/config.json influence so unit tests stay deterministic
    regardless of what's on the machine running them (matches test_aggregator.py)."""
    monkeypatch.setattr(sentinel_module, "get_admin_config", lambda: {})


@pytest.fixture
def sentinel() -> Sentinel:
    return Sentinel()


# ── Unit tests ────────────────────────────────────────────────────────────────

def test_typosquatted_name_detected(sentinel: Sentinel) -> None:
    """Names one edit away from a popular package must be flagged."""
    is_typo, similar_to = sentinel.check_name_similarity("lodahs")
    assert is_typo is True
    assert similar_to == "lodash"

    is_typo2, _ = sentinel.check_name_similarity("reakt")
    assert is_typo2 is True


def test_exact_name_not_flagged_as_typosquat(sentinel: Sentinel) -> None:
    """An exact match to a popular package should NOT be flagged as a typosquat."""
    is_typo, _ = sentinel.check_name_similarity("react")
    assert is_typo is False


# ── Integration tests (async with mocked network) ─────────────────────────────

_NO_OSV = {"vuln_count": 0, "has_malware": False, "vuln_ids": []}


@pytest.mark.asyncio
async def test_ai_suggested_nonexistent_package_scores_high(sentinel: Sentinel) -> None:
    """An AI-suggested package that does not exist in the registry should score high."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_absent())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("totally-made-up-pkg-xyz123", ai_suggested=True)

    assert isinstance(result, PillarScore)
    assert result.score >= 60.0
    assert "package_not_found" in result.flags


@pytest.mark.asyncio
async def test_human_typed_package_skips_hallucination_check(sentinel: Sentinel) -> None:
    """Human-typed installs skip the *hallucination* risk analysis (age/OSV/etc.)

    Registry existence is still checked unconditionally regardless of
    ai_suggested (that's what catches fake/typosquatted names for human-typed
    installs too) — only compute_hallucination_risk and the OSV lookup are
    skipped. 'webpack' is an exact match in TOP_PACKAGES (distance == 0) so
    the typosquat check does not fire either, giving a clean score of 0.
    """
    good_meta = {
        "time": {"created": "2016-01-01T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "repository": {"url": "https://github.com/webpack/webpack"},
        "versions": {"5.0.0": {}},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(good_meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock()) as mock_osv,
    ):
        result = await sentinel.score("webpack", ai_suggested=False)

    assert isinstance(result, PillarScore)
    assert result.score == 0.0
    assert result.metadata.get("hallucination_check") == "skipped"
    mock_osv.assert_not_called()


@pytest.mark.asyncio
async def test_real_package_scores_low(sentinel: Sentinel) -> None:
    """A well-established AI-suggested package with downloads should score low."""
    good_meta = {
        "time": {"created": "2016-01-01T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "repository": {"url": "https://github.com/lodash/lodash"},
        "versions": {"4.17.21": {}},
        "dist-tags": {"latest": "4.17.21"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(good_meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("lodash", ai_suggested=True)

    assert isinstance(result, PillarScore)
    assert result.score < 30.0


@pytest.mark.asyncio
async def test_new_ai_suggested_package_scores_higher(sentinel: Sentinel) -> None:
    """A brand-new package with zero downloads should receive a higher risk score."""
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_meta = {
        "time": {"created": recent},
        "maintainers": [{"name": "anon"}],
        "repository": None,
        "versions": {"0.0.1": {}},
        "dist-tags": {"latest": "0.0.1"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(new_meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("brand-new-package", ai_suggested=True)

    assert result.score >= 40.0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_meta(
    created: str = "2020-01-01T00:00:00Z",
    has_repo: bool = True,
    maintainers: int = 2,
) -> dict:
    meta: dict = {
        "time": {"created": created},
        "maintainers": [{"name": f"m{i}"} for i in range(maintainers)],
    }
    meta["repository"] = {"url": "https://github.com/example/pkg"} if has_repo else None
    return meta


def _exists(data: dict) -> RegistryResult:
    return RegistryResult(RegistryLookup.EXISTS, data)


def _absent() -> RegistryResult:
    return RegistryResult(RegistryLookup.CONFIRMED_ABSENT)


# ── Non-AI suggested download / repository flags (lines 95-102) ──────────────

@pytest.mark.asyncio
async def test_zero_downloads_flag_set(sentinel: Sentinel) -> None:
    """Non-AI package with zero downloads sets zero_downloads flag and score > 0."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(_make_meta()))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "zero_downloads" in result.flags
    assert result.score > 0.0


@pytest.mark.asyncio
async def test_very_low_downloads_flag_set(sentinel: Sentinel) -> None:
    """Non-AI package with 50 downloads (< 100) sets very_low_downloads flag."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(_make_meta()))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=50)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "very_low_downloads" in result.flags
    assert "zero_downloads" not in result.flags


@pytest.mark.asyncio
async def test_no_repository_flag_set(sentinel: Sentinel) -> None:
    """Non-AI package with no repository field sets no_repository flag."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(_make_meta(has_repo=False)))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "no_repository" in result.flags


# ── Existing typosquat path (lines 81-87) ─────────────────────────────────────

@pytest.mark.asyncio
async def test_existing_typosquat_scores_100(sentinel: Sentinel) -> None:
    """Package that exists and is a typosquat (dist=1 from 'lodash') scores 100.

    Reputation-corroboration requires the candidate to actually look
    disparate from the matched target — mocks are keyed by name so "lodahs"
    (candidate: near-zero downloads, brand new) looks nothing like "lodash"
    (target: huge downloads, long-established), confirming the disparity.
    """
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    async def _meta(name: str, *args, **kwargs) -> RegistryResult:
        return _exists(_make_meta(created=recent) if name == "lodahs" else _make_meta(created="2015-01-01T00:00:00Z"))

    async def _downloads(name: str) -> int:
        return 3 if name == "lodahs" else 5_000_000

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(side_effect=_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(side_effect=_downloads)),
    ):
        result = await sentinel.score("lodahs", ai_suggested=False)

    assert result.score == 100.0
    assert "typosquat_detected" in result.flags
    assert "reputation_disparity_confirmed" in result.flags


# ── Non-existent + typosquat path (lines 71-72) ───────────────────────────────

@pytest.mark.asyncio
async def test_typosquat_also_nonexistent_scores_95_plus(sentinel: Sentinel) -> None:
    """Package that does not exist and is a typosquat scores >= 95.

    The candidate's own lookup returns None (registry miss); the target
    ("lodash") lookup succeeds, so corroboration confirms genuinely (0
    candidate downloads vs. lodash's real popularity), not via the
    lookup-failure fallback path.
    """
    async def _meta(name: str, *args, **kwargs) -> RegistryResult:
        return _absent() if name == "lodahs" else _exists(_make_meta(created="2015-01-01T00:00:00Z"))

    async def _downloads(name: str) -> int:
        return 0 if name == "lodahs" else 5_000_000

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(side_effect=_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(side_effect=_downloads)),
    ):
        result = await sentinel.score("lodahs", ai_suggested=False)

    assert result.score >= 95.0
    assert "typosquat_detected" in result.flags
    assert "package_not_found" in result.flags
    assert "reputation_disparity_confirmed" in result.flags


# ── AI-suggested: very_new_package (lines 193-194) ───────────────────────────

@pytest.mark.asyncio
async def test_very_new_package_flag_set(sentinel: Sentinel) -> None:
    """AI-suggested package created 3 days ago triggers very_new_package flag."""
    three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = _make_meta(created=three_days_ago)
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=True)

    assert "very_new_package" in result.flags
    assert result.score > 0.0


# ── AI-suggested: new_package (lines 195-197, already covered; explicit test) ──

@pytest.mark.asyncio
async def test_new_package_flag_set(sentinel: Sentinel) -> None:
    """AI-suggested package created 15 days ago triggers new_package (7≤age<30) flag."""
    fifteen_days_ago = (datetime.now(timezone.utc) - timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = _make_meta(created=fifteen_days_ago)
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=True)

    assert "new_package" in result.flags


# ── AI-suggested: very_low_downloads via compute_hallucination_risk (lines 204-205) ──

@pytest.mark.asyncio
async def test_ai_very_low_downloads_flag_set(sentinel: Sentinel) -> None:
    """AI-suggested package with 50 downloads hits very_low_downloads in compute_hallucination_risk."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=50)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=_NO_OSV)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=True)

    assert "very_low_downloads" in result.flags


# ── check_registry_existence error paths (lines 143-144, 150-151) ─────────────

@pytest.mark.asyncio
async def test_invalid_created_date_sets_age_none(sentinel: Sentinel) -> None:
    """Malformed created date triggers except ValueError; age_days=None, no crash."""
    meta = {
        "time": {"created": "not-a-valid-date"},
        "maintainers": [{"name": "a"}],
        "repository": {"url": "https://github.com/example/pkg"},
    }
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=1000)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert result is not None
    assert result.metadata.get("age_days") is None


@pytest.mark.asyncio
async def test_download_count_exception_handled(sentinel: Sentinel) -> None:
    """Exception from get_download_count is caught; monthly_downloads defaults to 0."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(_make_meta()))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(side_effect=RuntimeError("network error"))),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert "zero_downloads" in result.flags


# ── compute_hallucination_risk direct unit tests (lines 179-184, 187-188) ─────

def test_compute_hallucination_risk_nonexistent_no_typo(sentinel: Sentinel) -> None:
    """compute_hallucination_risk: not exists, no typo → package_not_found, score 70."""
    score, flags = sentinel.compute_hallucination_risk(
        exists=False, signals={}, is_typo=False, similar_to=""
    )
    assert "package_not_found" in flags
    assert score == 70.0


def test_compute_hallucination_risk_nonexistent_with_typo(sentinel: Sentinel) -> None:
    """compute_hallucination_risk: not exists + typo → both flags, score 85."""
    score, flags = sentinel.compute_hallucination_risk(
        exists=False, signals={}, is_typo=True, similar_to="lodash"
    )
    assert "package_not_found" in flags
    assert "typosquat_detected" in flags
    assert score == 85.0


def test_compute_hallucination_risk_existing_typosquat(sentinel: Sentinel) -> None:
    """compute_hallucination_risk: exists + is_typo → typosquat_detected, score += 40."""
    score, flags = sentinel.compute_hallucination_risk(
        exists=True,
        signals={"age_days": 365, "monthly_downloads": 5000, "has_repository": True},
        is_typo=True,
        similar_to="react",
    )
    assert "typosquat_detected" in flags
    assert score >= 40.0


# ── Maintainer count captured in metadata ────────────────────────────────────

@pytest.mark.asyncio
async def test_maintainer_count_signal(sentinel: Sentinel) -> None:
    """maintainer_count is stored in registry signals regardless of value."""
    single_meta = _make_meta(maintainers=1)
    multi_meta  = _make_meta(maintainers=5)

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(single_meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
    ):
        single_result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(multi_meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
    ):
        multi_result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert single_result.metadata.get("maintainer_count") == 1
    assert multi_result.metadata.get("maintainer_count") == 5


# ── Non-AI path: no age or download-risk flags for healthy package ────────────

@pytest.mark.asyncio
async def test_non_ai_package_skips_age_and_download_checks(sentinel: Sentinel) -> None:
    """Non-AI path with healthy signals has no age or download risk flags."""
    meta = _make_meta(created="2015-01-01T00:00:00Z", has_repo=True)
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=500_000)),
    ):
        result = await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    assert result.metadata.get("hallucination_check") == "skipped"
    for flag in ("very_new_package", "new_package", "zero_downloads", "very_low_downloads"):
        assert flag not in result.flags


# ── Known-incident blocklist ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_known_compromised_package_blocked(sentinel: Sentinel) -> None:
    """flatmap-stream must return known_supply_chain_incident without any network call."""
    result = await sentinel.score("flatmap-stream", ai_suggested=False)

    assert result.score == 95.0
    assert "known_supply_chain_incident" in result.flags
    assert "incident" in result.metadata


@pytest.mark.asyncio
async def test_node_ipc_blocked_as_known_incident(sentinel: Sentinel) -> None:
    """node-ipc (peacenotwar, 2022) must be caught by the blocklist."""
    result = await sentinel.score("node-ipc", ai_suggested=False)

    assert result.score == 95.0
    assert "known_supply_chain_incident" in result.flags


@pytest.mark.asyncio
async def test_known_incident_applies_regardless_of_ai_suggested(sentinel: Sentinel) -> None:
    """Blocklist check fires for both human-typed and AI-suggested installs."""
    result_human = await sentinel.score("event-stream", ai_suggested=False)
    result_ai    = await sentinel.score("event-stream", ai_suggested=True)

    assert result_human.score == 95.0
    assert result_ai.score == 95.0
    assert "known_supply_chain_incident" in result_human.flags
    assert "known_supply_chain_incident" in result_ai.flags


# ── OSV vulnerability lookup ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_osv_advisory_boosts_score(sentinel: Sentinel) -> None:
    """An AI-suggested package with OSV advisories should receive a score boost."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    osv_result = {"vuln_count": 2, "has_malware": False, "vuln_ids": ["GHSA-abc-123"]}
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=osv_result)),
    ):
        result = await sentinel.score("some-vuln-pkg", ai_suggested=True)

    assert "osv_advisory_found" in result.flags
    assert result.metadata.get("osv_vuln_count") == 2


@pytest.mark.asyncio
async def test_osv_malware_confirmed_flag(sentinel: Sentinel) -> None:
    """has_malware=True from OSV should add osv_malware_confirmed flag and max out score."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    osv_result = {"vuln_count": 1, "has_malware": True, "vuln_ids": ["MAL-2022-1"]}
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=500_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock(return_value=osv_result)),
    ):
        result = await sentinel.score("some-malware-pkg", ai_suggested=True)

    assert "osv_malware_confirmed" in result.flags
    assert result.score == 100.0


@pytest.mark.asyncio
async def test_osv_not_called_for_human_typed(sentinel: Sentinel) -> None:
    """check_osv must not be called for human-typed (non-AI) installs."""
    meta = _make_meta(created="2020-01-01T00:00:00Z")
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=500_000)),
        patch("daemon.pillars.sentinel.check_osv", new=AsyncMock()) as mock_osv,
    ):
        await sentinel.score("unique-package-xyz-123", ai_suggested=False)

    mock_osv.assert_not_called()


# ── Affix canonicalization ─────────────────────────────────────────────────────

def test_check_affix_similarity_detects_node_prefix(sentinel: Sentinel) -> None:
    is_match, target = sentinel.check_affix_similarity("node-react")
    assert is_match is True
    assert target == "react"


def test_check_affix_similarity_detects_util_suffix(sentinel: Sentinel) -> None:
    is_match, target = sentinel.check_affix_similarity("lodash-util")
    assert is_match is True
    assert target == "lodash"


def test_check_affix_similarity_no_match_for_unrelated_name(sentinel: Sentinel) -> None:
    is_match, target = sentinel.check_affix_similarity("node-some-other-tool")
    assert is_match is False
    assert target == ""


def test_check_affix_similarity_ignores_exact_name_with_no_affix(sentinel: Sentinel) -> None:
    """"react" itself has no affix to strip, so this must not match despite
    being trivially "equal to itself" after a no-op strip."""
    is_match, target = sentinel.check_affix_similarity("react")
    assert is_match is False
    assert target == ""


# ── Reputation-disparity corroboration ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_reputation_disparity_confirmed_for_low_download_new_candidate(sentinel: Sentinel) -> None:
    with (
        patch("daemon.pillars.sentinel.get_package_metadata",
              new=AsyncMock(return_value=_exists(_make_meta(created="2013-01-01T00:00:00Z")))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=10_000_000)),
    ):
        confirmed, info = await sentinel.check_reputation_disparity(
            "vue-clone", "vue", {"monthly_downloads": 5, "age_days": 2},
        )
    assert confirmed is True
    assert info["fallback"] is False


@pytest.mark.asyncio
async def test_reputation_disparity_not_confirmed_for_comparable_packages(sentinel: Sentinel) -> None:
    """Two long-established, similarly-popular packages (the "vue" vs "vite"
    case) must not be treated as disparate."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata",
              new=AsyncMock(return_value=_exists(_make_meta(created="2016-01-01T00:00:00Z")))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=8_000_000)),
    ):
        confirmed, info = await sentinel.check_reputation_disparity(
            "vue", "vite", {"monthly_downloads": 7_500_000, "age_days": 3000},
        )
    assert confirmed is False
    assert info["fallback"] is False


@pytest.mark.asyncio
async def test_reputation_disparity_fails_open_on_target_lookup_failure(sentinel: Sentinel) -> None:
    """A target-lookup outage must fail toward flagging (confirmed=True), not
    silently suppress the pre-existing force-to-100 behavior."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_absent())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        confirmed, info = await sentinel.check_reputation_disparity(
            "some-candidate", "some-target", {"monthly_downloads": 5, "age_days": 2},
        )
    assert confirmed is True
    assert info["fallback"] is True


# ── Reputation-corroborated score() integration ────────────────────────────────

@pytest.mark.asyncio
async def test_score_vue_vs_vite_not_forced_to_typosquat(sentinel: Sentinel) -> None:
    """The motivating false-positive case: "vue" (candidate) is Levenshtein
    distance 2 from "vite" (target) but both are huge, long-established,
    unrelated packages — corroboration must suppress the force-to-100."""
    async def _meta(name: str, *args, **kwargs) -> RegistryResult:
        return _exists(_make_meta(created="2016-01-01T00:00:00Z"))

    async def _downloads(name: str) -> int:
        return 7_500_000 if name == "vue" else 8_000_000

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(side_effect=_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(side_effect=_downloads)),
    ):
        result = await sentinel.score("vue", ai_suggested=False)

    assert "typosquat_detected" not in result.flags
    assert result.score < 100.0
    assert "typosquat_name_similarity_uncorroborated" in result.flags


@pytest.mark.asyncio
async def test_score_node_react_affix_typosquat_detected(sentinel: Sentinel) -> None:
    """The motivating false-negative case: "node-react" isn't caught by raw
    Levenshitein distance but is caught by affix-stripping, and (being
    unregistered / low-reputation) is corroborated."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_absent())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("node-react", ai_suggested=False)

    assert "typosquat_affix_match" in result.flags
    assert "typosquat_detected" in result.flags
    assert result.score == 100.0


@pytest.mark.asyncio
async def test_corroboration_disabled_reverts_to_legacy_behavior(sentinel: Sentinel, monkeypatch) -> None:
    """typosquat_reputation_corroboration=False restores the pre-Feature-1
    behavior: any raw-distance hit forces score=100 unconditionally, even for
    the comparable-downloads "vue"/"vite" case."""
    monkeypatch.setattr(sentinel_module, "get_admin_config",
                         lambda: {"typosquat_reputation_corroboration": False})

    async def _meta(name: str, *args, **kwargs) -> RegistryResult:
        return _exists(_make_meta(created="2016-01-01T00:00:00Z"))

    async def _downloads(name: str) -> int:
        return 7_500_000 if name == "vue" else 8_000_000

    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(side_effect=_meta)),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(side_effect=_downloads)),
    ):
        result = await sentinel.score("vue", ai_suggested=False)

    assert "typosquat_detected" in result.flags
    assert result.score == 100.0


# ── Tri-state registry verification ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_confirmed_absent_sets_package_not_found(sentinel: Sentinel) -> None:
    """A confirmed-absent (404) registry lookup sets package_not_found and
    floors risk high, as before."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_absent())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("totally-made-up-pkg-xyz123", ai_suggested=False)

    assert "package_not_found" in result.flags
    assert result.score == 85.0


@pytest.mark.asyncio
async def test_undetermined_registry_lookup_does_not_set_package_not_found(sentinel: Sentinel) -> None:
    """A registry timeout/transport/5xx failure (UNDETERMINED) must NOT be
    treated as confirmed absence — this is the redux-thunk/nodemailer
    false-positive regression case: a transient registry blip must never
    force-block a real, popular package."""
    with (
        patch(
            "daemon.pillars.sentinel.get_package_metadata",
            new=AsyncMock(return_value=RegistryResult(RegistryLookup.UNDETERMINED)),
        ),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("redux-thunk", ai_suggested=False)

    assert "package_not_found" not in result.flags
    assert "registry_lookup_undetermined" in result.flags
    assert result.score < 50.0


@pytest.mark.asyncio
async def test_undetermined_registry_lookup_fails_open_for_aggregator_gate() -> None:
    """The flag Sentinel sets for an undetermined lookup must be distinct from
    'package_not_found' so the aggregator's Stage-1 gate does not force-BLOCK
    a transient outage."""
    from daemon.pillars.aggregator import Aggregator
    from daemon.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    sen = PillarScore(score=15.0, confidence=0.3, flags=["registry_lookup_undetermined"], metadata={})
    shi = PillarScore(score=0.0, confidence=0.8, flags=[], metadata={})
    assert Aggregator._stage1_gates(sen, shi, settings) is None


# ── npm security-placeholder version detection ─────────────────────────────────

async def test_is_security_placeholder_version_matches() -> None:
    from daemon.utils.npm_registry import is_security_placeholder_version

    assert is_security_placeholder_version("0.0.1-security.0") is True
    assert is_security_placeholder_version("1.0.0-security.10") is True
    assert is_security_placeholder_version("4.2.1") is False


@pytest.mark.asyncio
async def test_security_placeholder_version_forces_flag_and_score(sentinel: Sentinel) -> None:
    """A resolved 'latest' dist-tag matching npm's security-placeholder
    convention must set npm_security_placeholder_version and floor the score,
    regardless of typosquat status — the plain-crypto-js root-cause fix."""
    meta = _make_meta(created="2026-04-01T00:00:00Z")
    meta["dist-tags"] = {"latest": "0.0.1-security.0"}
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("plain-crypto-js", ai_suggested=False)

    assert "npm_security_placeholder_version" in result.flags
    assert result.score >= 90.0


@pytest.mark.asyncio
async def test_security_placeholder_check_uses_requested_version_when_given(sentinel: Sentinel) -> None:
    """When a specific pinned version is requested, the placeholder check
    must key off that version rather than dist-tags.latest."""
    meta = _make_meta(created="2026-04-01T00:00:00Z")
    meta["dist-tags"] = {"latest": "4.2.2"}
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("plain-crypto-js", ai_suggested=False, version="0.0.1-security.0")

    assert "npm_security_placeholder_version" in result.flags


@pytest.mark.asyncio
async def test_security_placeholder_detected_when_requested_version_wiped(sentinel: Sentinel) -> None:
    """Real-world case: npm wipes the ENTIRE versions map down to a single
    placeholder when it pulls a malicious release — a pinned request for the
    original malicious version string (e.g. "4.2.1") no longer resolves in
    the registry at all, and the only remaining signal is dist-tags.latest
    itself being the placeholder. The check must still catch this even
    though the *requested* version string ("4.2.1") doesn't match the
    placeholder pattern — this is the actual plain-crypto-js regression."""
    meta = _make_meta(created="2026-04-01T00:00:00Z")
    meta["dist-tags"] = {"latest": "0.0.1-security.0"}
    meta["versions"] = {"0.0.1-security.0": {}}  # the original "4.2.1" no longer resolves
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(meta))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("plain-crypto-js", ai_suggested=False, version="4.2.1")

    assert "npm_security_placeholder_version" in result.flags
    assert result.score >= 90.0


# ── Homoglyph/confusable normalization ─────────────────────────────────────────

def test_normalize_confusables_cyrillic_a() -> None:
    assert _normalize_confusables("reаct") == "react"


def test_normalize_confusables_greek_omicron() -> None:
    assert _normalize_confusables("axiοs") == "axios"


def test_normalize_confusables_passthrough_for_unmapped_script() -> None:
    """A script not in the small hardcoded table passes through unchanged
    (beyond NFKC), documenting the deliberate narrow scope of this pass."""
    assert _normalize_confusables("lodash") == "lodash"


@pytest.mark.asyncio
async def test_score_detects_cyrillic_homoglyph_typosquat(sentinel: Sentinel) -> None:
    """A Cyrillic-substituted homoglyph of 'react' must be caught by
    check_name_similarity once normalized, and corroborated as a typosquat
    given it's an unregistered, unfamiliar name."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_absent())),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=0)),
    ):
        result = await sentinel.score("reаct", ai_suggested=False)

    assert "typosquat_detected" in result.flags
    assert "typosquat_homoglyph_match" in result.flags
    assert result.score == 100.0


@pytest.mark.asyncio
async def test_score_legitimate_package_unaffected_by_normalization(sentinel: Sentinel) -> None:
    """An ordinary ASCII legitimate package name must be unaffected by the
    confusable-normalization step."""
    with (
        patch("daemon.pillars.sentinel.get_package_metadata", new=AsyncMock(return_value=_exists(_make_meta()))),
        patch("daemon.pillars.sentinel.get_download_count", new=AsyncMock(return_value=5_000_000)),
    ):
        result = await sentinel.score("lodash", ai_suggested=False)

    assert "typosquat_detected" not in result.flags
    assert "typosquat_name_similarity_uncorroborated" not in result.flags
