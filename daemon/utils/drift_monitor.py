"""Concept drift monitor for CIDAS. Tracks the distribution of pillar scores
over a rolling window of recent scans and compares against a baseline
established from the labelled evaluation corpus. Surfaces a
model_drift_detected flag when the current distribution has shifted
significantly. This module is read-only with respect to all other daemon
components — it does not modify scans, scores, or decisions.
"""
from __future__ import annotations

import json
import math
import random
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ─────────────────────────────────────────────────────────────────

# Anchored to this file's location (not CWD) so baseline build/check work
# regardless of what directory the daemon or test runner was launched from.
_DAEMON_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = _DAEMON_ROOT / "data" / "score_baseline.json"
WINDOW_SIZE = 100
KL_WARN_THRESHOLD = 0.15
KL_ALERT_THRESHOLD = 0.30
NUM_BINS = 10
MIN_WINDOW_SCANS = 20

_PILLARS: tuple[str, str, str] = ("contextify", "sentinel", "shield")
_DEFAULT_AUDIT_LOG = Path.home() / ".cidas" / "audit.log"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class PillarDistribution:
    pillar: str
    bin_edges: list[float]
    bin_counts: list[int]
    mean: float
    std: float
    sample_count: int


@dataclass
class BaselineProfile:
    created_at: str
    corpus_record_count: int
    distributions: dict[str, PillarDistribution]


@dataclass
class DriftReport:
    checked_at: str
    window_size: int
    sufficient_data: bool
    pillar_kl_divergences: dict[str, float]
    overall_kl: float
    status: str
    drifted_pillars: list[str]
    baseline_loaded: bool
    note: str = ""
    # Population Stability Index — a standard, symmetric KL-divergence variant
    # widely used in ML-monitoring practice, with its own interpretive
    # thresholds (<0.1 no significant shift, 0.1-0.25 moderate, >0.25
    # significant). Reported alongside KL for comparison; does not currently
    # drive `status`/`drifted_pillars` — see check_drift.
    pillar_psi: dict[str, float] = field(default_factory=dict)
    overall_psi: float = 0.0


# ── Histogram + KL ────────────────────────────────────────────────────────────

def build_score_histogram(scores: list[float]) -> tuple[list[float], list[int]]:
    """Histogram with NUM_BINS bins over [0, 100]. Returns (bin_edges, bin_counts)."""
    bin_edges = [round(i * 100.0 / NUM_BINS, 6) for i in range(NUM_BINS + 1)]
    if not scores:
        return bin_edges, [0] * NUM_BINS
    bin_counts = [0] * NUM_BINS
    for value in scores:
        try:
            v = float(value)
        except (TypeError, ValueError):
            continue
        v = max(0.0, min(100.0, v))
        # Right-edge inclusive on the last bin so 100.0 lands in bin NUM_BINS-1.
        idx = int(v * NUM_BINS / 100.0)
        if idx >= NUM_BINS:
            idx = NUM_BINS - 1
        bin_counts[idx] += 1
    return bin_edges, bin_counts


def _normalized_bins(counts: list[int], eps: float = 1e-10) -> list[float]:
    """Smooth zero-count bins and normalize to a probability distribution.
    Shared by kl_divergence and population_stability_index so both metrics
    compare the exact same smoothed proportions."""
    smoothed = [c + eps for c in counts]
    total = sum(smoothed)
    return [v / total for v in smoothed]


def kl_divergence(p_counts: list[int], q_counts: list[int]) -> float:
    """KL(P || Q) — current window vs baseline. Returns 0.0 if either is all zeros."""
    if not p_counts or not q_counts:
        return 0.0
    if sum(p_counts) == 0 or sum(q_counts) == 0:
        return 0.0
    n = min(len(p_counts), len(q_counts))
    p_norm = _normalized_bins(p_counts[:n])
    q_norm = _normalized_bins(q_counts[:n])
    total = 0.0
    for p_i, q_i in zip(p_norm, q_norm):
        if p_i > 0.0:
            total += p_i * math.log(p_i / q_i)
    return total


def population_stability_index(p_counts: list[int], q_counts: list[int]) -> float:
    """PSI(P, Q) — Population Stability Index between the current window (P)
    and baseline (Q), over the same smoothed/normalized bins kl_divergence
    uses. Unlike KL divergence (asymmetric, unbounded), PSI is symmetric and
    has widely-used interpretive thresholds in ML-monitoring practice
    (<0.1 no significant shift, 0.1-0.25 moderate, >0.25 significant).
    Reported as a second, standard metric for comparison against the
    existing KL-based thresholds — see check_drift, which does not yet use
    this to drive the warn/alert decision."""
    if not p_counts or not q_counts:
        return 0.0
    if sum(p_counts) == 0 or sum(q_counts) == 0:
        return 0.0
    n = min(len(p_counts), len(q_counts))
    p_norm = _normalized_bins(p_counts[:n])
    q_norm = _normalized_bins(q_counts[:n])
    total = 0.0
    for p_i, q_i in zip(p_norm, q_norm):
        total += (p_i - q_i) * math.log(p_i / q_i)
    return total


# ── Score extraction ──────────────────────────────────────────────────────────

def _coerce_score(raw: object) -> float | None:
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _extract_pillar_score(record: dict, pillar: str) -> float | None:
    """Try the known shapes for a per-pillar score in an audit record.

    The current Phase 1 audit log format stores only an overall ``score`` —
    per-pillar scores are not persisted. We still probe several plausible
    shapes so this function keeps working when pillar breakdowns are added
    to the audit log in a future phase.
    """
    flat = record.get(f"{pillar}_score")
    if flat is not None:
        return _coerce_score(flat)
    pillars = record.get("pillars")
    if isinstance(pillars, dict):
        entry = pillars.get(pillar)
        if isinstance(entry, dict) and "score" in entry:
            return _coerce_score(entry["score"])
        if entry is not None and not isinstance(entry, dict):
            return _coerce_score(entry)
    direct = record.get(pillar)
    if isinstance(direct, dict) and "score" in direct:
        return _coerce_score(direct["score"])
    return None


def extract_scores_from_audit_log(
    audit_log_path: Path,
    window_size: int = WINDOW_SIZE,
) -> dict[str, list[float]]:
    """Read the last ``window_size`` records and pull per-pillar scores out.

    Direct JSONL parsing (rather than awaiting audit_log.read_records) keeps
    this function sync-callable from check_drift and the CLI entrypoint.
    Never raises — returns empty lists on any failure.
    """
    out: dict[str, list[float]] = {p: [] for p in _PILLARS}
    try:
        if not audit_log_path.exists():
            return out
        text = audit_log_path.read_text(encoding="utf-8")
    except OSError:
        return out

    records: list[dict] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)

    cap = max(0, int(window_size))
    recent = records[-cap:] if cap else []

    for rec in recent:
        for pillar in _PILLARS:
            score = _extract_pillar_score(rec, pillar)
            if score is not None:
                out[pillar].append(score)
    return out


# ── Baseline build / save / load ──────────────────────────────────────────────

def _stats(scores: list[float]) -> tuple[float, float]:
    if not scores:
        return 0.0, 0.0
    n = len(scores)
    mean = sum(scores) / n
    if n == 1:
        return mean, 0.0
    var = sum((s - mean) ** 2 for s in scores) / n
    return mean, math.sqrt(var)


def build_baseline_from_scores(
    scores_by_pillar: dict[str, list[float]],
    corpus_record_count: int,
) -> BaselineProfile:
    """Construct a BaselineProfile from per-pillar score lists."""
    distributions: dict[str, PillarDistribution] = {}
    for pillar in _PILLARS:
        scores = list(scores_by_pillar.get(pillar, []))
        edges, counts = build_score_histogram(scores)
        mean, std = _stats(scores)
        distributions[pillar] = PillarDistribution(
            pillar=pillar,
            bin_edges=edges,
            bin_counts=counts,
            mean=round(mean, 4),
            std=round(std, 4),
            sample_count=len(scores),
        )
    return BaselineProfile(
        created_at=datetime.now(timezone.utc).isoformat(),
        corpus_record_count=int(corpus_record_count),
        distributions=distributions,
    )


def _profile_to_dict(profile: BaselineProfile) -> dict:
    return {
        "created_at": profile.created_at,
        "corpus_record_count": profile.corpus_record_count,
        "distributions": {k: asdict(v) for k, v in profile.distributions.items()},
    }


def save_baseline(profile: BaselineProfile) -> bool:
    """Write baseline to BASELINE_PATH. Creates parent dirs. Never raises."""
    try:
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = _profile_to_dict(profile)
        BASELINE_PATH.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        return True
    except Exception:
        return False


def load_baseline() -> BaselineProfile | None:
    """Read and reconstruct a BaselineProfile from BASELINE_PATH. None on failure."""
    try:
        if not BASELINE_PATH.exists():
            return None
        raw = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return None
        dist_raw = raw.get("distributions") or {}
        if not isinstance(dist_raw, dict):
            return None
        distributions: dict[str, PillarDistribution] = {}
        for pillar, entry in dist_raw.items():
            if not isinstance(entry, dict):
                continue
            distributions[pillar] = PillarDistribution(
                pillar=str(entry.get("pillar", pillar)),
                bin_edges=list(entry.get("bin_edges", [])),
                bin_counts=list(entry.get("bin_counts", [])),
                mean=float(entry.get("mean", 0.0)),
                std=float(entry.get("std", 0.0)),
                sample_count=int(entry.get("sample_count", 0)),
            )
        return BaselineProfile(
            created_at=str(raw.get("created_at", "")),
            corpus_record_count=int(raw.get("corpus_record_count", 0)),
            distributions=distributions,
        )
    except Exception:
        return None


# ── Drift check ───────────────────────────────────────────────────────────────

def _empty_report(
    *,
    baseline_loaded: bool,
    note: str = "",
    window_size: int = 0,
) -> DriftReport:
    return DriftReport(
        checked_at=datetime.now(timezone.utc).isoformat(),
        window_size=window_size,
        sufficient_data=False,
        pillar_kl_divergences={p: 0.0 for p in _PILLARS},
        overall_kl=0.0,
        status="insufficient_data",
        drifted_pillars=[],
        baseline_loaded=baseline_loaded,
        note=note,
        pillar_psi={p: 0.0 for p in _PILLARS},
        overall_psi=0.0,
    )


def check_drift(audit_log_path: Path | None = None) -> DriftReport:
    """Main entry point. Loads baseline, scans audit log, computes drift.

    Never raises — any failure collapses to ``status="insufficient_data"``.
    """
    try:
        baseline = load_baseline()
        if baseline is None:
            return _empty_report(
                baseline_loaded=False,
                note=f"baseline file not found at {BASELINE_PATH}",
            )

        path = audit_log_path if audit_log_path is not None else _DEFAULT_AUDIT_LOG
        scores_by_pillar = extract_scores_from_audit_log(path, WINDOW_SIZE)

        per_pillar_sizes = {p: len(scores_by_pillar.get(p, [])) for p in _PILLARS}
        smallest = min(per_pillar_sizes.values()) if per_pillar_sizes else 0
        if smallest < MIN_WINDOW_SCANS:
            return _empty_report(
                baseline_loaded=True,
                window_size=smallest,
                note=(
                    f"need >= {MIN_WINDOW_SCANS} scans per pillar; "
                    f"have {per_pillar_sizes}"
                ),
            )

        kl_per_pillar: dict[str, float] = {}
        psi_per_pillar: dict[str, float] = {}
        for pillar in _PILLARS:
            window_scores = scores_by_pillar[pillar]
            _, window_counts = build_score_histogram(window_scores)
            baseline_counts = baseline.distributions[pillar].bin_counts
            kl_per_pillar[pillar] = round(
                kl_divergence(window_counts, baseline_counts), 6
            )
            psi_per_pillar[pillar] = round(
                population_stability_index(window_counts, baseline_counts), 6
            )

        overall = sum(kl_per_pillar.values()) / len(kl_per_pillar)
        overall = round(overall, 6)
        overall_psi = round(sum(psi_per_pillar.values()) / len(psi_per_pillar), 6)

        if overall >= KL_ALERT_THRESHOLD:
            status = "alert"
        elif overall >= KL_WARN_THRESHOLD:
            status = "warn"
        else:
            status = "ok"

        drifted = [p for p, v in kl_per_pillar.items() if v >= KL_WARN_THRESHOLD]

        return DriftReport(
            checked_at=datetime.now(timezone.utc).isoformat(),
            window_size=smallest,
            sufficient_data=True,
            pillar_kl_divergences=kl_per_pillar,
            overall_kl=overall,
            status=status,
            drifted_pillars=drifted,
            baseline_loaded=True,
            note="",
            pillar_psi=psi_per_pillar,
            overall_psi=overall_psi,
        )
    except Exception as exc:  # noqa: BLE001
        return _empty_report(
            baseline_loaded=False,
            note=f"unexpected error: {exc!r}",
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

_CORPUS_DIR = _DAEMON_ROOT / "eval" / "corpus"
_CORPUS_FILES = ("malicious.jsonl", "benign.jsonl", "typosquat.jsonl", "hallucinated.jsonl")

# Synthetic score ranges per ground_truth label. The baseline has to exist
# before live pillar telemetry is being written to the audit log, so we seed
# it with score distributions that mirror what each attack family typically
# produces — benign packages cluster low across all three pillars, malicious
# packages light up Sentinel + Shield, typosquats peak Sentinel (name signal)
# while Shield is quiet because the package is usually unpublished, and
# hallucinated packages spike Sentinel (package_not_found) with quiet Shield.
_SYNTH_RANGES: dict[str, dict[str, tuple[float, float]]] = {
    "benign":       {"contextify": (0.0, 25.0),  "sentinel": (0.0, 20.0),   "shield": (0.0, 15.0)},
    "malicious":    {"contextify": (30.0, 70.0), "sentinel": (50.0, 95.0),  "shield": (40.0, 90.0)},
    "typosquat":    {"contextify": (10.0, 40.0), "sentinel": (60.0, 95.0),  "shield": (0.0, 20.0)},
    "hallucinated": {"contextify": (5.0, 30.0),  "sentinel": (70.0, 100.0), "shield": (0.0, 15.0)},
}


def _load_corpus_records() -> list[dict]:
    records: list[dict] = []
    for fname in _CORPUS_FILES:
        path = _CORPUS_DIR / fname
        if not path.exists():
            print(f"[drift] WARN: corpus file missing: {path}", file=sys.stderr)
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
    return records


def _synthesise_scores(records: list[dict]) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {p: [] for p in _PILLARS}
    for rec in records:
        label = str(rec.get("ground_truth", ""))
        ranges = _SYNTH_RANGES.get(label)
        if ranges is None:
            continue
        for pillar in _PILLARS:
            lo, hi = ranges[pillar]
            out[pillar].append(random.uniform(lo, hi))
    return out


def _cmd_build() -> int:
    random.seed(42)
    records = _load_corpus_records()
    if not records:
        print("[drift] no corpus records loaded; aborting", file=sys.stderr)
        return 1
    scores_by_pillar = _synthesise_scores(records)
    profile = build_baseline_from_scores(scores_by_pillar, len(records))
    ok = save_baseline(profile)
    if not ok:
        print(f"[drift] save_baseline failed for {BASELINE_PATH}", file=sys.stderr)
        return 1
    print(f"[drift] wrote baseline -> {BASELINE_PATH}")
    print(f"[drift] corpus records: {len(records)}")
    for pillar in _PILLARS:
        dist = profile.distributions[pillar]
        print(
            f"[drift]   {pillar:11s} "
            f"n={dist.sample_count:4d}  "
            f"mean={dist.mean:6.2f}  std={dist.std:6.2f}  "
            f"bins={dist.bin_counts}"
        )
    return 0


def _cmd_check() -> int:
    report = check_drift()
    payload = asdict(report)
    print(json.dumps(payload, indent=2))
    return 0


def _main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("build", "check"):
        print("usage: drift_monitor.py {build|check}", file=sys.stderr)
        return 2
    if argv[1] == "build":
        return _cmd_build()
    return _cmd_check()


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
