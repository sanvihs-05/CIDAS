"""Tests for daemon/utils/drift_monitor.py.

All tests are synchronous — drift_monitor.py has no async code.
Only imports from daemon/utils/drift_monitor and the standard library / pytest.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

import daemon.utils.drift_monitor as dm
from daemon.utils.drift_monitor import (
    KL_ALERT_THRESHOLD,
    KL_WARN_THRESHOLD,
    MIN_WINDOW_SCANS,
    NUM_BINS,
    WINDOW_SIZE,
    BaselineProfile,
    DriftReport,
    PillarDistribution,
    build_baseline_from_scores,
    build_score_histogram,
    check_drift,
    extract_scores_from_audit_log,
    kl_divergence,
    load_baseline,
    population_stability_index,
    save_baseline,
)

_PILLARS = ("contextify", "sentinel", "shield")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_scores(n: int = 50) -> dict[str, list[float]]:
    return {p: [float(i % 100) for i in range(n)] for p in _PILLARS}


def _simple_profile(n: int = 50) -> BaselineProfile:
    return build_baseline_from_scores(_make_scores(n), n)


def _write_audit_log(path: Path, records: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


# ── build_score_histogram ─────────────────────────────────────────────────────

def test_build_score_histogram_correct_bin_count():
    random.seed(0)
    scores = [random.uniform(0, 100) for _ in range(50)]
    edges, counts = build_score_histogram(scores)
    assert len(edges) == NUM_BINS + 1
    assert len(counts) == NUM_BINS
    assert sum(counts) == 50


def test_build_score_histogram_empty_input():
    edges, counts = build_score_histogram([])
    assert len(edges) == NUM_BINS + 1
    assert len(counts) == NUM_BINS
    assert sum(counts) == 0


def test_build_score_histogram_all_same_value():
    # 50.0 → idx = int(50.0 * 10 / 100) = 5
    edges, counts = build_score_histogram([50.0] * 20)
    assert sum(counts) == 20
    nonzero = [c for c in counts if c > 0]
    assert len(nonzero) == 1
    assert nonzero[0] == 20


def test_build_score_histogram_boundary_100():
    # 100.0 must land in the last bin (clamped, not out-of-bounds)
    edges, counts = build_score_histogram([100.0] * 5)
    assert sum(counts) == 5
    assert counts[-1] == 5


def test_build_score_histogram_boundary_zero():
    edges, counts = build_score_histogram([0.0] * 5)
    assert sum(counts) == 5
    assert counts[0] == 5


# ── kl_divergence ─────────────────────────────────────────────────────────────

def test_kl_divergence_identical_distributions_returns_zero():
    p = [10, 20, 30, 40]
    q = [10, 20, 30, 40]
    result = kl_divergence(p, q)
    assert result < 0.001


def test_kl_divergence_very_different_distributions():
    # All mass in bin 0 vs all mass in bin 3 → huge KL
    p = [100, 0, 0, 0]
    q = [0, 0, 0, 100]
    result = kl_divergence(p, q)
    assert result > 1.0


def test_kl_divergence_handles_zeros_without_raising():
    p = [0, 0, 0, 0]
    q = [0, 0, 0, 0]
    result = kl_divergence(p, q)
    assert result == 0.0


def test_kl_divergence_asymmetric():
    # KL(P||Q) != KL(Q||P) in general.
    # Use a concentrated P=[90,10] against a flat Q=[50,50] — these are not
    # mirror images, so the two KL values differ by construction.
    p = [90, 10]
    q = [50, 50]
    kl_pq = kl_divergence(p, q)
    kl_qp = kl_divergence(q, p)
    assert abs(kl_pq - kl_qp) > 0.01


def test_kl_divergence_empty_inputs_return_zero():
    assert kl_divergence([], [1, 2]) == 0.0
    assert kl_divergence([1, 2], []) == 0.0
    assert kl_divergence([], []) == 0.0


# ── population_stability_index ──────────────────────────────────────────────

def test_psi_identical_distributions_returns_zero():
    p = [10, 20, 30, 40]
    q = [10, 20, 30, 40]
    result = population_stability_index(p, q)
    assert result < 0.001


def test_psi_very_different_distributions():
    p = [100, 0, 0, 0]
    q = [0, 0, 0, 100]
    result = population_stability_index(p, q)
    assert result > 0.25  # standard PSI "significant shift" threshold


def test_psi_handles_zeros_without_raising():
    p = [0, 0, 0, 0]
    q = [0, 0, 0, 0]
    result = population_stability_index(p, q)
    assert result == 0.0


def test_psi_is_symmetric():
    # Unlike KL, PSI(P,Q) == PSI(Q,P) by construction (the (P-Q) term flips
    # sign but log(P/Q) also flips, so the product is invariant).
    p = [90, 10]
    q = [50, 50]
    psi_pq = population_stability_index(p, q)
    psi_qp = population_stability_index(q, p)
    assert psi_pq == pytest.approx(psi_qp, abs=1e-9)


def test_psi_empty_inputs_return_zero():
    assert population_stability_index([], [1, 2]) == 0.0
    assert population_stability_index([1, 2], []) == 0.0
    assert population_stability_index([], []) == 0.0


# ── build_baseline_from_scores ────────────────────────────────────────────────

def test_build_baseline_contains_all_pillars():
    profile = _simple_profile()
    for p in _PILLARS:
        assert p in profile.distributions


def test_build_baseline_sets_sample_count_correctly():
    scores = {
        "contextify": [float(i) for i in range(50)],
        "sentinel":   [float(i) for i in range(30)],
        "shield":     [],
    }
    profile = build_baseline_from_scores(scores, 80)
    assert profile.distributions["contextify"].sample_count == 50
    assert profile.distributions["sentinel"].sample_count == 30
    assert profile.distributions["shield"].sample_count == 0


def test_build_baseline_corpus_record_count_stored():
    profile = build_baseline_from_scores(_make_scores(), 162)
    assert profile.corpus_record_count == 162


def test_build_baseline_single_score_per_pillar():
    # Exercises the n==1 branch inside _stats (std should be 0.0)
    scores = {p: [42.0] for p in _PILLARS}
    profile = build_baseline_from_scores(scores, 1)
    for p in _PILLARS:
        dist = profile.distributions[p]
        assert dist.sample_count == 1
        assert dist.mean == pytest.approx(42.0, abs=0.01)
        assert dist.std == pytest.approx(0.0, abs=0.01)


def test_build_baseline_created_at_is_set():
    profile = _simple_profile()
    assert profile.created_at != ""
    assert "T" in profile.created_at  # ISO format sanity check


# ── save_baseline / load_baseline ─────────────────────────────────────────────

def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    original = _simple_profile()
    assert save_baseline(original) is True
    loaded = load_baseline()
    assert loaded is not None
    assert set(loaded.distributions.keys()) == set(_PILLARS)
    for p in _PILLARS:
        assert loaded.distributions[p].bin_counts == original.distributions[p].bin_counts


def test_load_baseline_returns_none_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "nonexistent.json")
    assert load_baseline() is None


def test_load_baseline_returns_none_on_malformed_json(tmp_path, monkeypatch):
    bad_file = tmp_path / "baseline.json"
    bad_file.write_text("not valid json", encoding="utf-8")
    monkeypatch.setattr(dm, "BASELINE_PATH", bad_file)
    result = load_baseline()
    assert result is None


def test_save_baseline_creates_directory_if_missing(tmp_path, monkeypatch):
    target = tmp_path / "newdir" / "baseline.json"
    monkeypatch.setattr(dm, "BASELINE_PATH", target)
    assert save_baseline(_simple_profile()) is True
    assert target.exists()


def test_load_baseline_roundtrip_preserves_stats(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    original = build_baseline_from_scores(
        {p: [float(i) for i in range(50)] for p in _PILLARS}, 50
    )
    save_baseline(original)
    loaded = load_baseline()
    assert loaded is not None
    for p in _PILLARS:
        assert loaded.distributions[p].mean == pytest.approx(
            original.distributions[p].mean, abs=0.001
        )
        assert loaded.distributions[p].sample_count == original.distributions[p].sample_count


# ── check_drift ───────────────────────────────────────────────────────────────

def test_check_drift_returns_insufficient_when_no_baseline(monkeypatch):
    monkeypatch.setattr(dm, "load_baseline", lambda: None)
    report = check_drift()
    assert report.baseline_loaded is False
    assert report.status == "insufficient_data"


def test_check_drift_returns_insufficient_when_too_few_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    monkeypatch.setattr(
        dm,
        "extract_scores_from_audit_log",
        lambda *_: {"contextify": [50.0] * 5, "sentinel": [50.0] * 5, "shield": [50.0] * 5},
    )
    report = check_drift()
    assert report.sufficient_data is False
    assert report.status == "insufficient_data"


def test_check_drift_ok_when_distributions_match(tmp_path, monkeypatch):
    # Baseline: all scores at 15.0 — all mass lands in bin 1 [10, 20).
    baseline_scores = {p: [15.0] * 50 for p in _PILLARS}
    profile = build_baseline_from_scores(baseline_scores, 50)
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(profile)
    # Window from same distribution — KL(same_bin || same_bin) ≈ 0.
    window = {p: [15.0] * MIN_WINDOW_SCANS for p in _PILLARS}
    monkeypatch.setattr(dm, "extract_scores_from_audit_log", lambda *_: window)
    report = check_drift()
    assert report.status == "ok"
    assert report.overall_kl < KL_WARN_THRESHOLD


def test_check_drift_alert_when_distributions_very_different(tmp_path, monkeypatch):
    # Baseline: all mass in bin 0 (scores at 5.0).
    baseline_scores = {p: [5.0] * 50 for p in _PILLARS}
    profile = build_baseline_from_scores(baseline_scores, 50)
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(profile)
    # Window: all mass in bin 9 (scores at 95.0) — completely opposite.
    window = {p: [95.0] * MIN_WINDOW_SCANS for p in _PILLARS}
    monkeypatch.setattr(dm, "extract_scores_from_audit_log", lambda *_: window)
    report = check_drift()
    assert report.status in ("warn", "alert")
    assert len(report.drifted_pillars) > 0


def test_check_drift_never_raises_on_any_exception(monkeypatch):
    def _raise():
        raise RuntimeError("simulated failure inside check_drift")
    monkeypatch.setattr(dm, "load_baseline", _raise)
    report = check_drift()
    assert report is not None
    assert isinstance(report, DriftReport)


def test_check_drift_report_has_all_pillar_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    window = {p: [50.0] * MIN_WINDOW_SCANS for p in _PILLARS}
    monkeypatch.setattr(dm, "extract_scores_from_audit_log", lambda *_: window)
    report = check_drift()
    if report.sufficient_data:
        for p in _PILLARS:
            assert p in report.pillar_kl_divergences


def test_check_drift_report_includes_psi_without_changing_status(tmp_path, monkeypatch):
    """PSI is additive: present in the report, but status/overall_kl/
    drifted_pillars are computed exactly as before (KL-driven only) —
    verified by checking the KL-based fields match a baseline run with
    PSI computation stubbed out entirely."""
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    window = {p: [50.0] * MIN_WINDOW_SCANS for p in _PILLARS}
    monkeypatch.setattr(dm, "extract_scores_from_audit_log", lambda *_: window)

    report = check_drift()
    assert report.sufficient_data is True
    for p in _PILLARS:
        assert p in report.pillar_psi
        assert isinstance(report.pillar_psi[p], float)
    assert isinstance(report.overall_psi, float)

    # Status/overall_kl/drifted_pillars must be unaffected by PSI's presence:
    # stub population_stability_index to a dummy value and confirm the
    # KL-driven fields are identical to the run above.
    monkeypatch.setattr(dm, "population_stability_index", lambda *_: 999.0)
    report_stubbed_psi = check_drift()
    assert report_stubbed_psi.status == report.status
    assert report_stubbed_psi.overall_kl == report.overall_kl
    assert report_stubbed_psi.drifted_pillars == report.drifted_pillars
    assert report_stubbed_psi.overall_psi == 999.0


def test_check_drift_baseline_loaded_true_when_baseline_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    # Return fewer than MIN_WINDOW_SCANS so we hit the early-return path,
    # but baseline_loaded should still be True.
    monkeypatch.setattr(
        dm,
        "extract_scores_from_audit_log",
        lambda *_: {p: [] for p in _PILLARS},
    )
    report = check_drift()
    assert report.baseline_loaded is True


# ── extract_scores_from_audit_log ─────────────────────────────────────────────

def test_extract_scores_returns_empty_on_missing_file(tmp_path):
    result = extract_scores_from_audit_log(tmp_path / "missing.jsonl")
    assert result == {"contextify": [], "sentinel": [], "shield": []}


def test_extract_scores_returns_empty_on_malformed_jsonl(tmp_path):
    bad = tmp_path / "bad.log"
    bad.write_text("not json\nnot json\n", encoding="utf-8")
    result = extract_scores_from_audit_log(bad)
    for lst in result.values():
        assert lst == []


def test_extract_scores_respects_window_size(tmp_path):
    log_file = tmp_path / "audit.log"
    records = [
        {
            "ts": f"2026-01-{i:02d}",
            "contextify_score": float(i),
            "sentinel_score": float(i),
            "shield_score": float(i),
        }
        for i in range(1, 51)  # 50 records
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file, window_size=10)
    for pillar in _PILLARS:
        assert len(result[pillar]) <= 10


def test_extract_scores_flat_format(tmp_path):
    # Primary format: {pillar}_score flat keys.
    log_file = tmp_path / "audit.log"
    records = [
        {"contextify_score": 25.0, "sentinel_score": 60.0, "shield_score": 40.0}
        for _ in range(5)
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file)
    assert result["contextify"] == [25.0] * 5
    assert result["sentinel"] == [60.0] * 5
    assert result["shield"] == [40.0] * 5


def test_extract_scores_pillars_nested_format(tmp_path):
    # Nested under "pillars": {"contextify": {"score": ...}, ...}
    log_file = tmp_path / "audit.log"
    records = [
        {
            "pillars": {
                "contextify": {"score": 30.0},
                "sentinel":   {"score": 70.0},
                "shield":     {"score": 50.0},
            }
        }
        for _ in range(5)
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file)
    assert result["contextify"] == [30.0] * 5
    assert result["sentinel"] == [70.0] * 5
    assert result["shield"] == [50.0] * 5


def test_extract_scores_pillars_scalar_nested(tmp_path):
    # Nested under "pillars" but value is a scalar, not a dict.
    log_file = tmp_path / "audit.log"
    records = [
        {"pillars": {"contextify": 35.0, "sentinel": 65.0, "shield": 45.0}}
        for _ in range(3)
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file)
    assert result["contextify"] == [35.0] * 3
    assert result["sentinel"] == [65.0] * 3
    assert result["shield"] == [45.0] * 3


def test_extract_scores_direct_pillar_dict_format(tmp_path):
    # Direct: record[pillar] = {"score": value}
    log_file = tmp_path / "audit.log"
    records = [
        {
            "contextify": {"score": 20.0},
            "sentinel":   {"score": 80.0},
            "shield":     {"score": 55.0},
        }
        for _ in range(4)
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file)
    assert result["contextify"] == [20.0] * 4
    assert result["sentinel"] == [80.0] * 4
    assert result["shield"] == [55.0] * 4


def test_extract_scores_skips_records_missing_pillar(tmp_path):
    # Records that don't have a given pillar's score are simply skipped
    # for that pillar — other pillars are unaffected.
    log_file = tmp_path / "audit.log"
    records = [
        {"contextify_score": 10.0},               # only contextify
        {"sentinel_score": 50.0, "shield_score": 30.0},  # only sentinel + shield
        {"contextify_score": 15.0, "sentinel_score": 55.0, "shield_score": 35.0},
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file)
    assert len(result["contextify"]) == 2  # records 0 and 2
    assert len(result["sentinel"]) == 2    # records 1 and 2
    assert len(result["shield"]) == 2      # records 1 and 2


def test_extract_scores_ignores_blank_lines(tmp_path):
    log_file = tmp_path / "audit.log"
    log_file.write_text(
        '\n{"contextify_score": 10.0, "sentinel_score": 20.0, "shield_score": 5.0}\n\n'
        '{"contextify_score": 11.0, "sentinel_score": 21.0, "shield_score": 6.0}\n',
        encoding="utf-8",
    )
    result = extract_scores_from_audit_log(log_file)
    assert len(result["contextify"]) == 2
    assert len(result["sentinel"]) == 2


def test_extract_scores_window_size_zero_returns_empty(tmp_path):
    log_file = tmp_path / "audit.log"
    records = [{"contextify_score": float(i), "sentinel_score": float(i), "shield_score": float(i)} for i in range(10)]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file, window_size=0)
    assert result == {"contextify": [], "sentinel": [], "shield": []}


# ── Exception / error branches ────────────────────────────────────────────────

def test_build_score_histogram_skips_non_numeric():
    # Covers the except (TypeError, ValueError): continue branch.
    edges, counts = build_score_histogram(["not-a-number", 50.0, None])
    assert sum(counts) == 1  # only the float 50.0 was counted


def test_extract_scores_skips_non_numeric_flat_score(tmp_path):
    # Covers the _coerce_score exception path.
    log_file = tmp_path / "audit.log"
    records = [
        {"contextify_score": "bad", "sentinel_score": 50.0, "shield_score": 30.0},
        {"contextify_score": 25.0,  "sentinel_score": 55.0, "shield_score": 35.0},
    ]
    _write_audit_log(log_file, records)
    result = extract_scores_from_audit_log(log_file)
    assert len(result["contextify"]) == 1   # first record's score was invalid
    assert len(result["sentinel"]) == 2
    assert len(result["shield"]) == 2


def test_extract_scores_handles_oserror(tmp_path):
    # Passing a directory triggers IsADirectoryError (subclass of OSError).
    # Covers the `except OSError: return out` branch.
    result = extract_scores_from_audit_log(tmp_path)  # tmp_path is a directory
    assert result == {"contextify": [], "sentinel": [], "shield": []}


def test_save_baseline_returns_false_on_error(tmp_path, monkeypatch):
    # A file where the parent dir should be makes mkdir fail → save returns False.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file", encoding="utf-8")
    monkeypatch.setattr(dm, "BASELINE_PATH", blocker / "baseline.json")
    assert save_baseline(_simple_profile()) is False


def test_load_baseline_returns_none_for_non_dict_json(tmp_path, monkeypatch):
    # Covers `if not isinstance(raw, dict): return None`.
    f = tmp_path / "baseline.json"
    f.write_text("true", encoding="utf-8")  # valid JSON, but not a dict
    monkeypatch.setattr(dm, "BASELINE_PATH", f)
    assert load_baseline() is None


def test_load_baseline_returns_none_when_distributions_not_dict(tmp_path, monkeypatch):
    # Covers `if not isinstance(dist_raw, dict): return None` when distributions
    # is a truthy non-dict (the `or {}` fallback does not apply).
    f = tmp_path / "baseline.json"
    f.write_text('{"distributions": [1, 2, 3]}', encoding="utf-8")
    monkeypatch.setattr(dm, "BASELINE_PATH", f)
    assert load_baseline() is None


def test_load_baseline_skips_non_dict_dist_entry(tmp_path, monkeypatch):
    # Covers `if not isinstance(entry, dict): continue`.
    f = tmp_path / "baseline.json"
    data = {
        "created_at": "2026-01-01T00:00:00+00:00",
        "corpus_record_count": 10,
        "distributions": {
            "contextify": "not-a-dict",   # will be skipped
            "sentinel": {
                "pillar": "sentinel",
                "bin_edges": [float(i * 10) for i in range(11)],
                "bin_counts": [5] * 10,
                "mean": 50.0,
                "std": 10.0,
                "sample_count": 50,
            },
        },
    }
    f.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(dm, "BASELINE_PATH", f)
    result = load_baseline()
    assert result is not None
    assert "sentinel" in result.distributions
    assert "contextify" not in result.distributions


def test_check_drift_warn_status(tmp_path, monkeypatch):
    # Covers `status = "warn"` branch (0.15 <= overall_kl < 0.30).
    # Monkeypatch kl_divergence to return a value in the warn zone.
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    window = {p: [50.0] * MIN_WINDOW_SCANS for p in _PILLARS}
    monkeypatch.setattr(dm, "extract_scores_from_audit_log", lambda *_: window)
    monkeypatch.setattr(dm, "kl_divergence", lambda p, q: 0.20)
    report = check_drift()
    assert report.status == "warn"
    assert report.sufficient_data is True


# ── CLI functions ─────────────────────────────────────────────────────────────

def test_cmd_build_creates_baseline(tmp_path, monkeypatch, capsys):
    # Covers _load_corpus_records, _synthesise_scores, _cmd_build.
    # Corpus files exist at daemon/eval/corpus/ relative to the repo root (CWD).
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    result = dm._cmd_build()
    assert result == 0
    assert (tmp_path / "baseline.json").exists()
    captured = capsys.readouterr()
    assert "wrote baseline" in captured.out


def test_cmd_check_runs(tmp_path, monkeypatch, capsys):
    # Covers _cmd_check.
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    result = dm._cmd_check()
    assert result == 0
    captured = capsys.readouterr()
    assert "status" in captured.out


def test_main_build_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    result = dm._main(["script", "build"])
    assert result == 0


def test_main_check_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dm, "BASELINE_PATH", tmp_path / "baseline.json")
    save_baseline(_simple_profile())
    result = dm._main(["script", "check"])
    assert result == 0


def test_main_unknown_command(capsys):
    result = dm._main(["script", "unknown"])
    assert result == 2


def test_main_no_args(capsys):
    result = dm._main(["script"])
    assert result == 2
