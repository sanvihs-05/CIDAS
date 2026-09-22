"""evaluate.py — run the benchmark corpora against a live CIDAS daemon.

Reads every record from daemon/eval/corpus/*.jsonl, POSTs each to the
running daemon's /api/v1/scan endpoint, then computes precision / recall /
F1 per attack_type, an overall confusion matrix, and median + p95 latency
extracted from the ``X-CIDAS-Latency-Ms`` response header.

Usage
-----
    # full run, write to results/latest.json
    python daemon/eval/evaluate.py

    # single corpus
    python daemon/eval/evaluate.py --corpus malicious

    # custom output path
    python daemon/eval/evaluate.py --output daemon/eval/results/run1.json

    # tune concurrency (default 4)
    python daemon/eval/evaluate.py --concurrency 8

The daemon must be running at http://127.0.0.1:7355 with an existing
``~/.cidas/daemon.token``. The script will raise SystemExit if either is
missing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

CORPUS_DIR = Path(__file__).parent / "corpus"
RESULTS_DIR = Path(__file__).parent / "results"
DAEMON_URL = "http://127.0.0.1:7355/api/v1/scan"
TOKEN_PATH = Path.home() / ".cidas" / "daemon.token"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")

# A scan still requires a project_path; the daemon's contextify pillar will
# emit "no_project_path" / "empty_project" flags when the path is missing or
# unreadable. That's fine for evaluation — we want the other pillars to
# carry the signal.
_EVAL_PROJECT_PATH = "/tmp/cidas-eval"


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

async def _scan_one(client: httpx.AsyncClient, token: str, record: dict) -> dict:
    """POST one record; return {decision, risk_score, latency_ms} or {error}."""
    version = record["version"]
    payload = {
        "package_name": record["package_name"],
        "version": None if version == "latest" else version,
        "project_path": _EVAL_PROJECT_PATH,
        "ai_suggested": bool(record.get("ai_suggested", False)),
        "requesting_tool": "cidas-eval",
    }
    try:
        resp = await client.post(
            DAEMON_URL,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=90.0,
        )
        latency_hdr = resp.headers.get("X-CIDAS-Latency-Ms")
        try:
            latency_ms = float(latency_hdr) if latency_hdr else 0.0
        except ValueError:
            latency_ms = 0.0
        if resp.status_code != 200:
            return {"error": f"http {resp.status_code}", "latency_ms": latency_ms}
        body = resp.json()
        return {
            "decision": body.get("decision"),
            "risk_score": body.get("risk_score"),
            "latency_ms": latency_ms,
        }
    except httpx.HTTPError as exc:
        return {"error": str(exc), "latency_ms": 0.0}


# ── Metric computation ────────────────────────────────────────────────────────

def _classify(ground_truth: str, decision: str | None) -> str:
    """Return TP / FP / TN / FN / ERROR for one record.

    Anything in {malicious, typosquat, hallucinated} is treated as
    actually-positive; WARN or BLOCK is treated as a positive prediction.
    """
    if decision is None or decision not in ("ALLOW", "WARN", "BLOCK"):
        return "ERROR"
    is_actually_positive = ground_truth in ("malicious", "typosquat", "hallucinated")
    is_predicted_positive = decision in ("WARN", "BLOCK")
    if is_actually_positive and is_predicted_positive:
        return "TP"
    if is_actually_positive and not is_predicted_positive:
        return "FN"
    if not is_actually_positive and is_predicted_positive:
        return "FP"
    return "TN"


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _percentile(sorted_values: list[float], p: float) -> float:
    """Closest-rank percentile on a pre-sorted list."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    idx = max(0, min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1)))))
    return float(sorted_values[idx])


def _metrics_block(counts: dict[str, int]) -> dict[str, Any]:
    tp = counts.get("TP", 0)
    fp = counts.get("FP", 0)
    fn = counts.get("FN", 0)
    tn = counts.get("TN", 0)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        **counts,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _compute_metrics(records: list[dict]) -> dict[str, Any]:
    per_attack: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    )
    overall: dict[str, int] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    confusion: dict[str, dict[str, int]] = defaultdict(
        lambda: {"ALLOW": 0, "WARN": 0, "BLOCK": 0, "ERROR": 0}
    )
    latencies: list[float] = []

    for r in records:
        outcome = r["_outcome"]
        attack = r.get("attack_type", "none")
        per_attack[attack][outcome] += 1
        overall[outcome] += 1
        decision = r["_result"].get("decision") or "ERROR"
        if decision not in ("ALLOW", "WARN", "BLOCK"):
            decision = "ERROR"
        confusion[r["ground_truth"]][decision] += 1
        latency_ms = float(r["_result"].get("latency_ms", 0) or 0)
        if latency_ms > 0:
            latencies.append(latency_ms)

    latencies.sort()
    latency_stats: dict[str, Any] = {"n_samples": len(latencies)}
    if latencies:
        latency_stats["median_ms"] = round(statistics.median(latencies), 2)
        latency_stats["p95_ms"] = round(_percentile(latencies, 0.95), 2)

    overall_block = _metrics_block(overall)
    overall_block["false_positive_rate"] = round(
        _safe_div(overall["FP"], overall["FP"] + overall["TN"]), 4
    )

    return {
        "per_attack_type": {k: _metrics_block(v) for k, v in per_attack.items()},
        "overall": overall_block,
        "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
        "latency": latency_stats,
    }


# ── Driver ────────────────────────────────────────────────────────────────────

async def _run(corpora: list[str], concurrency: int, output: Path) -> None:
    token = _load_token()

    all_records: list[dict] = []
    for name in corpora:
        recs = _load_corpus(name)
        for r in recs:
            r["_corpus"] = name
        all_records.extend(recs)
    print(f"[eval] loaded {len(all_records)} records across {len(corpora)} corpora")
    print(f"[eval] targeting {DAEMON_URL} with concurrency={concurrency}")

    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient() as client:
        async def _bounded(r: dict) -> dict:
            async with sem:
                return await _scan_one(client, token, r)

        results = await asyncio.gather(*[_bounded(r) for r in all_records])

    errors = 0
    for r, res in zip(all_records, results):
        r["_result"] = res
        r["_outcome"] = _classify(r["ground_truth"], res.get("decision"))
        if "error" in res:
            errors += 1

    if errors:
        print(f"[eval] WARNING: {errors}/{len(all_records)} records errored", file=sys.stderr)

    metrics = _compute_metrics(all_records)
    output_doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpora": corpora,
        "total_records": len(all_records),
        "errors": errors,
        "metrics": metrics,
    }

    print("\n=== Metrics ===")
    print(json.dumps(metrics, indent=2))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_doc, indent=2), encoding="utf-8")
    print(f"\n[eval] wrote results -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m daemon.eval.evaluate",
        description="Run benchmark corpora against a running CIDAS daemon.",
    )
    parser.add_argument(
        "--corpus",
        choices=ALL_CORPORA,
        help="Run only one corpus (default: all four).",
    )
    parser.add_argument(
        "--output",
        default=str(RESULTS_DIR / "latest.json"),
        help="Where to write the JSON results document.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Number of concurrent scan requests (default: 4).",
    )
    args = parser.parse_args()

    corpora = [args.corpus] if args.corpus else list(ALL_CORPORA)
    asyncio.run(_run(corpora, args.concurrency, Path(args.output)))


if __name__ == "__main__":
    main()
