"""Tests for the Aggregator pillar.

Verifies weighted scoring, decision mapping, and explanation generation without
any I/O calls.
"""
from __future__ import annotations

import pytest

from daemon.config import get_settings
from daemon.models import PillarScore
from daemon.pillars import aggregator as aggregator_module
from daemon.pillars.aggregator import Aggregator


@pytest.fixture(autouse=True)
def _no_admin_config(monkeypatch):
    """Disable ~/.cidas/config.json influence so unit tests stay deterministic."""
    monkeypatch.setattr(aggregator_module, "get_admin_config", lambda: {})


@pytest.fixture
def aggregator() -> Aggregator:
    return Aggregator()


@pytest.fixture
def settings():
    get_settings.cache_clear()
    return get_settings()


def _ps(score: float, flags: list[str] | None = None, metadata: dict | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata=metadata or {})


# ── Score computation tests ───────────────────────────────────────────────────

def test_all_low_scores_allow(aggregator: Aggregator, settings) -> None:
    """All-zero pillar scores must result in ALLOW with risk_score == 0."""
    risk, explanation = aggregator.aggregate(_ps(0), _ps(0), _ps(0), settings)
    assert risk == 0.0
    assert aggregator.get_decision(risk, settings) == "ALLOW"
    assert "passed" in explanation.lower() or "allow" in explanation.lower()


def test_high_contextify_warns(aggregator: Aggregator, settings) -> None:
    """Pillar combination that produces a score in [warn_threshold, block_threshold) → WARN."""
    # 0.30*0 + 0.35*80 + 0.35*40 = 0 + 28 + 14 = 42 → WARN (with default 0.30/0.35/0.35)
    risk, explanation = aggregator.aggregate(_ps(0), _ps(80), _ps(40), settings)
    assert settings.warn_threshold <= risk < settings.block_threshold
    assert aggregator.get_decision(risk, settings) == "WARN"
    assert explanation  # not empty


def test_any_pillar_above_block_threshold_blocks(aggregator: Aggregator, settings) -> None:
    """When the weighted score reaches block_threshold the decision must be BLOCK."""
    # All pillars at 100 → score 100 → BLOCK regardless of weight redistribution.
    risk, explanation = aggregator.aggregate(_ps(100), _ps(100), _ps(100), settings)
    assert risk >= settings.block_threshold
    assert aggregator.get_decision(risk, settings) == "BLOCK"


def test_hallucinated_package_overrides_to_block(aggregator: Aggregator, settings) -> None:
    """A nonexistent AI-suggested package must always resolve to BLOCK."""
    sen = PillarScore(
        score=70.0, confidence=0.85,
        flags=["package_not_found"],
        metadata={"ai_suggested": True},
    )
    risk, _ = aggregator.aggregate(_ps(15), sen, _ps(0), settings)
    assert aggregator.get_decision(risk, settings) == "BLOCK"
    assert risk >= settings.block_threshold


def test_explanation_contains_flags(aggregator: Aggregator, settings) -> None:
    """The explanation string must mention signal flags when they are present."""
    ctx = _ps(20, flags=["unfamiliar_in_mature_project"])
    sen = _ps(50, flags=["typosquat_detected", "very_new_package"])
    shi = _ps(0, flags=[])
    _, explanation = aggregator.aggregate(ctx, sen, shi, settings)
    assert "typosquat_detected" in explanation or "unfamiliar_in_mature_project" in explanation


def test_score_capped_at_100(aggregator: Aggregator, settings) -> None:
    """Weighted sum must never exceed 100 even if pillar scores are at maximum."""
    risk, _ = aggregator.aggregate(_ps(100), _ps(100), _ps(100), settings)
    assert risk == 100.0


def test_get_decision_boundaries(aggregator: Aggregator, settings) -> None:
    """Decision boundaries must be respected exactly at the threshold values."""
    assert aggregator.get_decision(settings.warn_threshold - 1, settings) == "ALLOW"
    assert aggregator.get_decision(settings.warn_threshold, settings) == "WARN"
    assert aggregator.get_decision(settings.block_threshold - 1, settings) == "WARN"
    assert aggregator.get_decision(settings.block_threshold, settings) == "BLOCK"


# ── Contextify floor rule ─────────────────────────────────────────────────────

def test_alien_package_pushed_to_warn_by_floor(aggregator: Aggregator, settings) -> None:
    """A package wholly unrelated to the project (similarity ~ 0) must reach WARN
    even when Sentinel and Shield report only modest signals."""
    # Realistic shape: Contextify returns 25 for "unfamiliar in mature project",
    # similarity ~ 0 triggers the +20 floor; modest Sentinel/Shield baseline.
    ctx = _ps(25, flags=["unfamiliar_in_mature_project"], metadata={"similarity": 0.01})
    sen = _ps(20)
    shi = _ps(10)
    # 0.30*25 + 0.35*20 + 0.35*10 + 20 (floor) = 7.5 + 7.0 + 3.5 + 20 = 38.0
    # → still ALLOW; bump Sentinel slightly to land in WARN.
    sen = _ps(30)
    risk, _ = aggregator.aggregate(ctx, sen, shi, settings)
    assert risk >= settings.warn_threshold
    assert aggregator.get_decision(risk, settings) == "WARN"
    assert "alien_to_project" in ctx.flags


def test_floor_not_applied_when_similarity_above_threshold(aggregator: Aggregator, settings) -> None:
    """Floor must not fire for packages with even modest similarity to the project."""
    ctx = _ps(15, metadata={"similarity": 0.10})
    sen = _ps(10)
    shi = _ps(10)
    # Without floor: 0.30*15 + 0.35*10 + 0.35*10 = 4.5 + 3.5 + 3.5 = 11.5
    risk, _ = aggregator.aggregate(ctx, sen, shi, settings)
    assert risk < 15  # nowhere near the +20 the floor would have added
    assert "alien_to_project" not in ctx.flags


def test_floor_skipped_when_metadata_missing(aggregator: Aggregator, settings) -> None:
    """If Contextify did not record a similarity (e.g. empty project) the floor
    must NOT fire — there is no evidence the package is alien."""
    ctx = _ps(5, metadata={})
    risk, _ = aggregator.aggregate(ctx, _ps(0), _ps(0), settings)
    assert risk < 10
    assert "alien_to_project" not in ctx.flags


def test_high_contextify_similarity_lowers_final_score(aggregator: Aggregator, settings) -> None:
    """A high-similarity (well-fitting) package must produce a lower final
    score than a low-similarity one with the same Sentinel/Shield signals."""
    sen, shi = _ps(20), _ps(10)
    aligned = _ps(0,  metadata={"similarity": 0.80})  # great fit
    alien   = _ps(25, metadata={"similarity": 0.02})  # alien → triggers floor

    risk_aligned, _ = aggregator.aggregate(aligned, sen, shi, settings)
    risk_alien,   _ = aggregator.aggregate(alien,   sen, shi, settings)
    assert risk_aligned < risk_alien
    # And the gap is meaningful: at minimum the floor penalty.
    assert risk_alien - risk_aligned >= aggregator_module.CONTEXTIFY_FLOOR_PENALTY - 1


# ── Admin-config override (~/.cidas/config.json: contextify_weight) ───────────

def test_admin_config_overrides_contextify_weight(aggregator, settings, monkeypatch) -> None:
    """Setting contextify_weight in the admin config replaces the env-derived
    weight; Sentinel/Shield split the remainder proportionally."""
    monkeypatch.setattr(aggregator_module, "get_admin_config",
                        lambda: {"contextify_weight": 0.5})
    # ctx=80 with weight 0.5 → 40; sentinel=0, shield=0 → final 40 → WARN.
    risk, _ = aggregator.aggregate(_ps(80), _ps(0), _ps(0), settings)
    assert risk == pytest.approx(40.0, abs=0.5)
    assert aggregator.get_decision(risk, settings) == "WARN"


def test_admin_config_zero_weight_disables_contextify(aggregator, settings, monkeypatch) -> None:
    """Mixed-domain projects can set contextify_weight=0 to silence the pillar."""
    monkeypatch.setattr(aggregator_module, "get_admin_config",
                        lambda: {"contextify_weight": 0.0})
    # Even a maximum Contextify score must contribute zero to the final score.
    # Use empty metadata so the alien-floor doesn't fire.
    risk, _ = aggregator.aggregate(_ps(100), _ps(0), _ps(0), settings)
    assert risk == pytest.approx(0.0, abs=0.5)


def test_admin_config_clamps_out_of_range_weight(aggregator, settings, monkeypatch) -> None:
    """Values above the 0.5 ceiling must be clamped, not accepted blindly."""
    monkeypatch.setattr(aggregator_module, "get_admin_config",
                        lambda: {"contextify_weight": 0.95})
    # ctx=100 weight clamped to 0.5 → contributes 50, not 95.
    risk, _ = aggregator.aggregate(_ps(100), _ps(0), _ps(0), settings)
    assert risk == pytest.approx(50.0, abs=0.5)


def test_admin_config_invalid_value_falls_back_to_default(aggregator, settings, monkeypatch) -> None:
    """Non-numeric admin-config values must not crash the aggregator."""
    monkeypatch.setattr(aggregator_module, "get_admin_config",
                        lambda: {"contextify_weight": "not-a-number"})
    risk, _ = aggregator.aggregate(_ps(100), _ps(0), _ps(0), settings)
    # Falls back to env default (0.30) → 30.
    assert risk == pytest.approx(30.0, abs=0.5)


# ── Signal amplification ──────────────────────────────────────────────────────

def test_base64_plus_unfamiliar_adds_penalty(aggregator: Aggregator, settings) -> None:
    """base64_decode co-occurring with unfamiliar_in_mature_project adds +15 and
    covert_dropper_signals flag — simulates a covert dropper that evades single-signal
    detection."""
    ctx = _ps(10, flags=["unfamiliar_in_mature_project"])
    sen = _ps(5)
    shi = _ps(10, flags=["base64_decode"])

    risk_with, _ = aggregator.aggregate(ctx, sen, shi, settings)

    # Without amplification: 0.30*10 + 0.35*5 + 0.35*10 = 3 + 1.75 + 3.5 = 8.25
    # With +15 amplification: 23.25
    assert risk_with >= 20.0
    assert "covert_dropper_signals" in shi.flags


def test_base64_alone_does_not_amplify(aggregator: Aggregator, settings) -> None:
    """base64_decode without unfamiliar_in_mature_project must not trigger amplification."""
    ctx = _ps(10)  # no unfamiliar flag
    sen = _ps(5)
    shi = _ps(10, flags=["base64_decode"])

    risk, _ = aggregator.aggregate(ctx, sen, shi, settings)
    assert "covert_dropper_signals" not in shi.flags
    assert risk == pytest.approx(8.25, abs=0.5)


def test_known_supply_chain_incident_always_blocks(aggregator: Aggregator, settings) -> None:
    """known_supply_chain_incident in sentinel flags must force the score to block_threshold."""
    sen = PillarScore(
        score=95.0, confidence=0.99,
        flags=["known_supply_chain_incident"],
        metadata={"incident": "test incident"},
    )
    risk, _ = aggregator.aggregate(_ps(0), sen, _ps(0), settings)
    assert aggregator.get_decision(risk, settings) == "BLOCK"
    assert risk >= settings.block_threshold


# ── Two-stage refactor: _stage1_gates / _stage2_score unit tests ─────────────

def test_stage1_gates_returns_block_threshold_for_package_not_found(settings) -> None:
    sen = _ps(0, flags=["package_not_found"])
    assert Aggregator._stage1_gates(sen, _ps(0), settings) == float(settings.block_threshold)


def test_stage1_gates_returns_block_threshold_for_known_incident(settings) -> None:
    sen = _ps(0, flags=["known_supply_chain_incident"])
    assert Aggregator._stage1_gates(sen, _ps(0), settings) == float(settings.block_threshold)


def test_stage1_gates_returns_block_threshold_for_npm_security_placeholder(settings) -> None:
    """A resolved version matching npm's '-security.N' placeholder convention
    (npm's security team pulled and replaced this exact version) must always
    block, regardless of typosquat/reputation status."""
    sen = _ps(0, flags=["npm_security_placeholder_version"])
    assert Aggregator._stage1_gates(sen, _ps(0), settings) == float(settings.block_threshold)


def test_stage1_gates_returns_warn_threshold_for_typosquat_only(settings) -> None:
    sen = _ps(0, flags=["typosquat_detected"])
    assert Aggregator._stage1_gates(sen, _ps(0), settings) == float(settings.warn_threshold)


def test_stage1_gates_prioritizes_block_over_warn_when_both_conditions_present(settings) -> None:
    sen = _ps(0, flags=["package_not_found", "typosquat_detected"])
    assert Aggregator._stage1_gates(sen, _ps(0), settings) == float(settings.block_threshold)


def test_stage1_gates_returns_none_when_no_gate_fires(settings) -> None:
    sen = _ps(50, flags=["zero_downloads"])
    assert Aggregator._stage1_gates(sen, _ps(0), settings) is None


def test_stage1_gates_returns_warn_threshold_for_shield_version_unresolved(settings) -> None:
    """Shield couldn't examine the actual requested version (e.g. npm purged
    it after a compromise) — meaningful enough to warrant a WARN floor, but
    not confirmed malicious on its own, so not a BLOCK."""
    sen = _ps(0)
    shi = _ps(0, flags=["requested_version_unresolved"])
    assert Aggregator._stage1_gates(sen, shi, settings) == float(settings.warn_threshold)


def test_stage2_score_matches_aggregate_when_no_gate_fires(aggregator: Aggregator, settings) -> None:
    """When Stage 1 fires no gate, aggregate()'s result must equal _stage2_score's
    result directly — the composition adds nothing beyond Stage 2 in that case."""
    ctx = _ps(20, flags=["unfamiliar_in_mature_project"])
    sen = _ps(30, flags=["zero_downloads"])
    shi = _ps(10)

    stage2 = aggregator._stage2_score(ctx, sen, shi, settings, None)
    risk, _ = aggregator.aggregate(ctx, sen, shi, settings)
    assert risk == stage2
