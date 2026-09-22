"""ablation.py — pillar ablation study across 8 weight configurations.

The daemon is queried **once per record** to obtain all three pillar scores.
The final decision is then recomputed locally for each of the 8 weight
combinations, making the study cheap to run on large corpora and requiring
zero changes to the daemon code.

Weight combinations
-------------------
  0  No pillars          ctx=0.00 sen=0.00 shi=0.00  — always ALLOW baseline
  1  Contextify only     ctx=1.00 sen=0.00 shi=0.00
  2  Sentinel only       ctx=0.00 sen=1.00 shi=0.00
  3  Shield only         ctx=0.00 sen=0.00 shi=1.00
  4  Contextify+Sentinel ctx=0.50 sen=0.50 shi=0.00
  5  Contextify+Shield   ctx=0.50 sen=0.00 shi=0.50
  6  Sentinel+Shield     ctx=0.00 sen=0.50 shi=0.50
  7  All three           ctx=0.30 sen=0.35 shi=0.35

Recomputation mirrors daemon/pillars/aggregator.py exactly, including:
  • the Contextify floor penalty (similarity < 0.05 → +20 pts)
  • the force-block for AI-hallucinated packages not found in the registry

Usage
-----
    python daemon/eval/ablation.py
    python daemon/eval/ablation.py --corpus malicious
    python daemon/eval/ablation.py --output daemon/eval/results/ablation_run1.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

CORPUS_DIR = Path(__file__).parent / "corpus"
RESULTS_DIR = Path(__file__).parent / "results"
DAEMON_URL = "http://127.0.0.1:7355/api/v1/scan"
TOKEN_PATH = Path.home() / ".cidas" / "daemon.token"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")
_EVAL_PROJECT_PATH = "/tmp/cidas-eval"

# Mirror aggregator constants — kept here so ablation.py is self-contained.
_BLOCK_THRESHOLD:   float = 80.0
_WARN_THRESHOLD:    float = 40.0
_FLOOR_SIMILARITY:  float = 0.05
_FLOOR_PENALTY:     float = 20.0

# (id, label, contextify_w, sentinel_w, shield_w)
COMBINATIONS: list[tuple[int, str, float, float, float]] = [
    (0, "No pillars",             0.00, 0.00, 0.00),
    (1, "Contextify only",        1.00, 0.00, 0.00),
    (2, "Sentinel only",          0.00, 1.00, 0.00),
    (3, "Shield only",            0.00, 0.00, 1.00),
    (4, "Contextify + Sentinel",  0.50, 0.50, 0.00),
    (5, "Contextify + Shield",    0.50, 0.00, 0.50),
    (6, "Sentinel + Shield",      0.00, 0.50, 0.50),
    (7, "All three",              0.30, 0.35, 0.35),
]


# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_token() -> str:
    if not TOKEN_PATH.exists():
        raise SystemExit(
            f"daemon token not found at {TOKEN_PATH}. "
            "Start the daemon first (scripts/start-daemon.sh)."
        )
    return TOKEN_PATH.read_text(encoding="utf-8").strip()


def _load_corpus(name: str) -> list[dict]:
    path = CORPUS_DIR / f"{name}.jsonl"
    if not path.exists():
        raise SystemExit(f"corpus file not found: {path}. Run build_corpus.py first.")
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


# ── Daemon I/O ────────────────────────────────────────────────────────────────

async def _scan_one_full(
    client: httpx.AsyncClient, token: str, record: dict,
) -> dict:
    """POST one record; return full response body including all pillar scores."""
    version = record["version"]
    payload = {
        "package_name": record["package_name"],
        "version": None if version == "latest" else version,
        "project_path": _EVAL_PROJECT_PATH,
        "ai_suggested": bool(record.get("ai_suggested", False)),
        "requesting_tool": "cidas-ablation",
    }
    try:
        resp = await client.post(
            DAEMON_URL,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=90.0,
        )
        try:
            latency_ms = float(resp.headers.get("X-CIDAS-Latency-Ms") or 0)
        except ValueError:
            latency_ms = 0.0
        if resp.status_code != 200:
            return {"error": f"http {resp.status_code}", "latency_ms": latency_ms}
        body = resp.json()
        return {
            "latency_ms":  latency_ms,
            "contextify":  body.get("contextify") or {},
            "sentinel":    body.get("sentinel")   or {},
            "shield":      body.get("shield")     or {},
        }
    except httpx.HTTPError as exc:
        return {"error": str(exc), "latency_ms": 0.0}


# ── Local score recomputation ─────────────────────────────────────────────────

def _recompute_decision(
    result: dict,
    combo_id: int,
    ctx_w: float,
    sen_w: float,
    shi_w: float,
) -> str | None:
    """Derive a verdict for one weight configuration from stored pillar scores.

    Returns None when *result* carries a daemon error (caller records ERROR).

    Replication of daemon/pillars/aggregator.py::Aggregator.aggregate() — kept
    in lockstep with that module by hand since this script recomputes locally
    rather than calling it. Mirrors, in order:
      1. Weighted sum of the three pillar scores.
      2. Contextify floor penalty when similarity < 0.05.
      3. Covert-dropper amplification (Shield base64_decode + Contextify
         unfamiliar_in_mature_project → +15).
      4. Force-block for packages not found in the registry (regardless of
         ai_suggested — the real aggregator does not gate this on it).
      5. Force-block for a known supply-chain incident.
      6. Force-block for a resolved version matching npm's security-
         placeholder convention ("-security.N" — npm pulled this exact
         version as malicious/reserved).
      7. Force-WARN floor for a detected typosquat (Sentinel's 0.35 weight
         alone caps at 35 points, below the 40-point WARN threshold).
      8. Force-WARN floor when Shield couldn't examine the actual requested
         version (its manifest/tarball is gone from the registry, e.g. a
         purged compromise) — not confirmed malicious on its own, but
         meaningful enough to warrant caution.
      9. Threshold comparison → ALLOW / WARN / BLOCK.
    """
    if "error" in result:
        return None

    # Combination 0: pure baseline — always ALLOW, weight sum would be 0 anyway.
    if combo_id == 0:
        return "ALLOW"

    ctx  = result.get("contextify") or {}
    sent = result.get("sentinel")   or {}
    shi  = result.get("shield")     or {}

    ctx_score  = float(ctx.get("score")  or 0.0)
    sent_score = float(sent.get("score") or 0.0)
    shi_score  = float(shi.get("score")  or 0.0)

    score = ctx_w * ctx_score + sen_w * sent_score + shi_w * shi_score

    # Contextify floor: hard additive rule in the aggregator, weight-independent.
    similarity = (ctx.get("metadata") or {}).get("similarity")
    if isinstance(similarity, (int, float)) and similarity < _FLOOR_SIMILARITY:
        score += _FLOOR_PENALTY

    score = min(score, 100.0)

    ctx_flags  = ctx.get("flags")  or []
    shi_flags  = shi.get("flags")  or []
    sent_flags = sent.get("flags") or []

    if "base64_decode" in shi_flags and "unfamiliar_in_mature_project" in ctx_flags:
        score = min(score + 15.0, 100.0)

    # Force-block for confirmed registry misses (any install, not just AI-suggested).
    if "package_not_found" in sent_flags:
        score = max(score, _BLOCK_THRESHOLD)

    # Force-block for a known, documented supply-chain incident.
    if "known_supply_chain_incident" in sent_flags:
        score = max(score, _BLOCK_THRESHOLD)

    # Force-block for npm's security-placeholder version convention.
    if "npm_security_placeholder_version" in sent_flags:
        score = max(score, _BLOCK_THRESHOLD)

    # Force-WARN floor for a detected typosquat.
    if "typosquat_detected" in sent_flags:
        score = max(score, _WARN_THRESHOLD)

    # Force-WARN floor when Shield couldn't examine the requested version.
    if "requested_version_unresolved" in shi_flags:
        score = max(score, _WARN_THRESHOLD)

    if score >= _BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= _WARN_THRESHOLD:
        return "WARN"
    return "ALLOW"


# ── Metric helpers ────────────────────────────────────────────────────────────

def _classify(ground_truth: str, decision: str | None) -> str:
    if decision not in ("ALLOW", "WARN", "BLOCK"):
        return "ERROR"
    positive = ground_truth in ("malicious", "typosquat", "hallucinated")
    flagged  = decision in ("WARN", "BLOCK")
    if positive and flagged:      return "TP"
    if positive and not flagged:  return "FN"
    if not positive and flagged:  return "FP"
    return "TN"


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _combo_metrics(
    records: list[dict],
    scan_results: list[dict],
    combo_id: int,
    ctx_w: float,
    sen_w: float,
    shi_w: float,
) -> dict[str, Any]:
    """Compute all metrics for one weight combination."""
    tp = fp = tn = fn = errors = 0
    latencies: list[float] = []

    for rec, res in zip(records, scan_results):
        decision = _recompute_decision(res, combo_id, ctx_w, sen_w, shi_w)
        outcome  = _classify(rec["ground_truth"], decision)
        if outcome == "TP":   tp += 1
        elif outcome == "FP": fp += 1
        elif outcome == "TN": tn += 1
        elif outcome == "FN": fn += 1
        else:                 errors += 1
        lm = float(res.get("latency_ms") or 0)
        if lm > 0:
            latencies.append(lm)

    precision = _safe_div(tp, tp + fp)
    recall    = _safe_div(tp, tp + fn)
    f1        = _safe_div(2 * precision * recall, precision + recall)
    fpr       = _safe_div(fp, fp + tn)

    latencies.sort()
    median_latency = round(statistics.median(latencies), 2) if latencies else 0.0

    return {
        "precision":           round(precision, 4),
        "recall":              round(recall,    4),
        "f1":                  round(f1,        4),
        "false_positive_rate": round(fpr,       4),
        "median_latency_ms":   median_latency,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn, "errors": errors,
    }


# ── Formatters ────────────────────────────────────────────────────────────────

_COL_NAMES = ["#", "Configuration",        "Precision", "Recall", "F1",    "FPR",   "Med ms", "TP", "FP", "TN", "FN"]
_COL_W     = [ 2,  24,                     9,           9,        9,       9,       8,         5,    5,    5,    5]
_COL_FLOAT = {2, 3, 4, 5}   # column indices to format as 4-decimal float
_COL_MS    = {6}             # column index to format as 1-decimal float


def _hr(char: str = "-") -> str:
    return "+" + "+".join(char * (w + 2) for w in _COL_W) + "+"


def _fmt_row(vals: list) -> str:
    cells: list[str] = []
    for i, (v, w) in enumerate(zip(vals, _COL_W)):
        if i in _COL_FLOAT and isinstance(v, (int, float)):
            s = f"{float(v):.4f}".rjust(w)
        elif i in _COL_MS and isinstance(v, (int, float)):
            s = f"{float(v):.1f}".rjust(w)
        elif isinstance(v, int):
            s = str(v).rjust(w)
        elif isinstance(v, float):
            s = f"{v:.4f}".rjust(w)
        else:
            s = str(v).ljust(w)
        cells.append(s)
    return "| " + " | ".join(cells) + " |"


def _ascii_table(
    combinations: list[tuple[int, str, float, float, float]],
    combo_results: list[dict[str, Any]],
) -> str:
    lines = [_hr("="), _fmt_row(_COL_NAMES), _hr("=")]
    for (cid, label, _c, _s, _h), m in zip(combinations, combo_results):
        lines.append(_fmt_row([
            cid, label,
            m["precision"], m["recall"], m["f1"], m["false_positive_rate"],
            m["median_latency_ms"],
            m["TP"], m["FP"], m["TN"], m["FN"],
        ]))
        lines.append(_hr("-"))
    return "\n".join(lines)


def _markdown_table(
    combinations: list[tuple[int, str, float, float, float]],
    combo_results: list[dict[str, Any]],
) -> str:
    lines = [
        "| Configuration | Precision | Recall | F1 | FPR | Median Latency (ms) |",
        "|---|---|---|---|---|---|",
    ]
    for (_id, label, _c, _s, _h), m in zip(combinations, combo_results):
        lines.append(
            f"| {label} "
            f"| {m['precision']:.4f} "
            f"| {m['recall']:.4f} "
            f"| {m['f1']:.4f} "
            f"| {m['false_positive_rate']:.4f} "
            f"| {m['median_latency_ms']:.1f} |"
        )
    return "\n".join(lines)


# ── Driver ────────────────────────────────────────────────────────────────────

async def _run(
    corpora: list[str],
    concurrency: int,
    output_json: Path,
    output_md: Path,
) -> None:
    token = _load_token()

    all_records: list[dict] = []
    for name in corpora:
        recs = _load_corpus(name)
        for r in recs:
            r["_corpus"] = name
        all_records.extend(recs)

    n = len(all_records)
    print(f"[ablation] {n} records across {len(corpora)} corpora")
    print(f"[ablation] fetching pillar scores from {DAEMON_URL} (once per record) ...")

    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient() as client:
        async def _bounded(r: dict) -> dict:
            async with sem:
                return await _scan_one_full(client, token, r)
        scan_results: list[dict] = await asyncio.gather(*[_bounded(r) for r in all_records])

    fetch_errors = sum(1 for r in scan_results if "error" in r)
    if fetch_errors:
        print(
            f"[ablation] WARNING: {fetch_errors}/{n} records errored on fetch",
            file=sys.stderr,
        )

    print(f"[ablation] recomputing decisions for {len(COMBINATIONS)} combinations ...")
    combo_results: list[dict[str, Any]] = []
    for combo_id, label, ctx_w, sen_w, shi_w in COMBINATIONS:
        m = _combo_metrics(all_records, scan_results, combo_id, ctx_w, sen_w, shi_w)
        combo_results.append({
            "combination_id":    combo_id,
            "label":             label,
            "contextify_weight": ctx_w,
            "sentinel_weight":   sen_w,
            "shield_weight":     shi_w,
            **m,
        })

    # Print ASCII table
    table = _ascii_table(COMBINATIONS, combo_results)
    print("\n" + table)

    # Warn when all-three is not the best F1
    best_subset_f1 = max(r["f1"] for r in combo_results[:7])
    all_three_f1   = combo_results[7]["f1"]
    if all_three_f1 < best_subset_f1:
        best_subset = next(r for r in combo_results[:7] if r["f1"] == best_subset_f1)
        print(
            f"\n[ablation] NOTE: All three (F1={all_three_f1:.4f}) is outperformed by "
            f"'{best_subset['label']}' (F1={best_subset_f1:.4f}). "
            "This suggests a weight-tuning or pillar-synergy issue — see README for guidance.",
            file=sys.stderr,
        )

    # Print Markdown
    md = _markdown_table(COMBINATIONS, combo_results)
    print("\n=== Markdown table (paste into paper) ===\n")
    print(md)

    # Write output files
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)

    doc: dict[str, Any] = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "corpora":       corpora,
        "total_records": n,
        "fetch_errors":  fetch_errors,
        "combinations":  combo_results,
    }
    output_json.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    output_md.write_text(md + "\n", encoding="utf-8")

    print(f"\n[ablation] wrote JSON -> {output_json}")
    print(f"[ablation] wrote MD   -> {output_md}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python daemon/eval/ablation.py",
        description="Pillar ablation study across 8 weight configurations.",
    )
    parser.add_argument(
        "--corpus",
        choices=ALL_CORPORA,
        help="Restrict to one corpus (default: all four).",
    )
    parser.add_argument(
        "--output",
        default=str(RESULTS_DIR / "ablation.json"),
        help="Path for the JSON results file (default: results/ablation.json). "
             "A .md file is written alongside it automatically.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrent daemon requests (default: 4).",
    )
    args = parser.parse_args()

    corpora     = [args.corpus] if args.corpus else list(ALL_CORPORA)
    output_json = Path(args.output)
    output_md   = output_json.with_suffix(".md")

    asyncio.run(_run(corpora, args.concurrency, output_json, output_md))


if __name__ == "__main__":
    main()
