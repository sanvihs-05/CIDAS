"""Tests for daemon.eval.ablation's local aggregator reimplementation.

`_recompute_decision` hand-duplicates `daemon/pillars/aggregator.py`'s
Stage-1 gates so ablation.py can recompute a verdict per weight
configuration without an extra daemon round-trip. That duplication has
already drifted out of sync with the real aggregator once (missing the
npm_security_placeholder_version gate silently produced 2 misclassified
records under diluted-Sentinel-weight configs) — these tests exist so any
future new Stage-1 gate added to aggregator.py is forced to be mirrored
here too, not discovered by a confusing ablation-table F1 discrepancy.
"""
from __future__ import annotations

from daemon.eval.ablation import _BLOCK_THRESHOLD, _WARN_THRESHOLD, _recompute_decision

# Any weight combo with all three pillars weighted low enough that only a
# Stage-1 gate (not the weighted sum) can push the score past ALLOW.
_DILUTE_WEIGHTS = (0.30, 0.35, 0.35)


def _result(ctx_score=5.0, sen_score=5.0, shi_score=5.0, sen_flags=None, shi_flags=None, ctx_flags=None):
    return {
        "contextify": {"score": ctx_score, "flags": ctx_flags or [], "metadata": {}},
        "sentinel": {"score": sen_score, "flags": sen_flags or []},
        "shield": {"score": shi_score, "flags": shi_flags or []},
    }


def test_returns_none_on_error_result():
    assert _recompute_decision({"error": "http 500"}, 7, *_DILUTE_WEIGHTS) is None


def test_combo_zero_always_allow():
    assert _recompute_decision(_result(), 0, *_DILUTE_WEIGHTS) == "ALLOW"


def test_package_not_found_forces_block():
    result = _result(sen_flags=["package_not_found"])
    assert _recompute_decision(result, 7, *_DILUTE_WEIGHTS) == "BLOCK"


def test_known_supply_chain_incident_forces_block():
    result = _result(sen_flags=["known_supply_chain_incident"])
    assert _recompute_decision(result, 7, *_DILUTE_WEIGHTS) == "BLOCK"


def test_npm_security_placeholder_version_forces_block_even_diluted():
    """Regression test for the exact bug found in this session: a corroborated
    security-placeholder signal (Sentinel score 95) must still floor at BLOCK
    even when Sentinel's weight alone (0.35 * 95 = 33.25) wouldn't reach it."""
    result = _result(ctx_score=5.0, sen_score=95.0, shi_score=0.0, sen_flags=["npm_security_placeholder_version"])
    assert _recompute_decision(result, 7, *_DILUTE_WEIGHTS) == "BLOCK"


def test_typosquat_detected_forces_warn_floor():
    result = _result(sen_flags=["typosquat_detected"])
    assert _recompute_decision(result, 7, *_DILUTE_WEIGHTS) == "WARN"


def test_requested_version_unresolved_forces_warn_floor():
    result = _result(shi_flags=["requested_version_unresolved"])
    assert _recompute_decision(result, 7, *_DILUTE_WEIGHTS) == "WARN"


def test_no_gate_fires_uses_weighted_sum_only():
    result = _result(ctx_score=0.0, sen_score=0.0, shi_score=0.0)
    assert _recompute_decision(result, 7, *_DILUTE_WEIGHTS) == "ALLOW"


def test_contextify_floor_penalty_applied_below_similarity_threshold():
    result = _result(ctx_score=0.0, sen_score=0.0, shi_score=0.0)
    result["contextify"]["metadata"]["similarity"] = 0.01
    decision = _recompute_decision(result, 7, *_DILUTE_WEIGHTS)
    # +20 floor penalty alone isn't enough to cross WARN (40) at these weights.
    assert decision == "ALLOW"
