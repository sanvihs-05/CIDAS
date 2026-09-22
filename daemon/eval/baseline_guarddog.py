"""baseline_guarddog.py — run the CIDAS eval corpus through GuardDog as a baseline
comparison (Datadog/OpenSSF's Semgrep+YARA+metadata-heuristic npm scanner).

Setup (one-time)
-----------------
GuardDog needs its own Python 3.11 venv: its native dependency chain (pulled in via
semgrep) has no pre-built wheels for this project's daemon venv's Python version in
this environment (confirmed: wheels-only install fails on Python 3.13, succeeds on
3.11). This does NOT affect the daemon itself — this venv is eval-tooling-only.

    python3.11 -m venv daemon/eval/.guarddog-venv
    daemon/eval/.guarddog-venv/Scripts/pip install --only-binary :all: guarddog

GuardDog's code-analysis rules also need semgrep's compiled binary on PATH — pip
installs it into the same venv's Scripts/ dir, but guarddog's own subprocess call
doesn't find it there automatically, so this script prepends that directory to PATH
for the child process explicitly (see _scan_one). Confirmed via a spike: without
this, every scan silently loses the semgrep-based rule categories (the ones most
comparable to CIDAS's Shield pillar), while still reporting 0 issues — i.e. a
silent under-count, not a visible error, so this fix is required for a fair result,
not just a nice-to-have. Also needs PYTHONUTF8=1: guarddog's bundled rule YAML files
contain non-ASCII characters and are opened without an explicit encoding, so on
Windows (default locale cp1252) loading them raises UnicodeDecodeError otherwise.

Usage
-----
    python daemon/eval/baseline_guarddog.py
    python daemon/eval/baseline_guarddog.py --corpus malicious
    python daemon/eval/baseline_guarddog.py --concurrency 4

Known, confirmed scope limits — both counted as ERROR, not FN, per an explicit
scoping decision:
- GuardDog cannot evaluate a package name that doesn't exist on the registry at
  all — every hallucinated-corpus record will fail to download, not because
  GuardDog is weak at hallucination detection, but because "this name doesn't
  exist" isn't a signal its content-scanning model addresses at all (a different
  threat scope from Sentinel's registry-existence check, not a worse one).
- Many malicious-corpus records reference the version that was actually
  compromised, which npm has since removed from the registry; GuardDog's tarball
  download has no fallback for a missing specific version and errors out.
  Confirmed via a spike: this reproduces on every tested historical malicious
  version (ua-parser-js@0.7.29, event-stream@3.3.6, coa@2.0.3, eslint-scope@3.7.2,
  node-ipc@10.1.1) while an explicit -v flag on a currently-published version
  (lodash@4.17.21) works fine — so this is specific to unpublished-version
  lookups, not a general flag bug.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_THIS_DIR = Path(__file__).parent
sys.path.insert(0, str(_THIS_DIR))
from evaluate import _metrics_block, _safe_div  # noqa: E402  (reuse, don't reimplement)

CORPUS_DIR = _THIS_DIR / "corpus"
RESULTS_DIR = _THIS_DIR / "results"
GUARDDOG_VENV = _THIS_DIR / ".guarddog-venv"
GUARDDOG_PYTHON = GUARDDOG_VENV / "Scripts" / "python.exe"
GUARDDOG_SCRIPTS = GUARDDOG_VENV / "Scripts"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")
_SCAN_TIMEOUT_SECONDS = 180


def _load_corpus(name: str) -> list[dict]:
    path = CORPUS_DIR / f"{name}.jsonl"
    if not path.exists():
        raise SystemExit(f"corpus file not found: {path}")
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _extract_json(stdout: str) -> dict:
    """GuardDog prints one JSON object to stdout; be defensive about any
    leading log noise by taking the last brace-balanced object present."""
    stdout = stdout.strip()
    if not stdout:
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass
    start = stdout.rfind("{")
    if start == -1:
        return {}
    depth = 0
    for i in range(start, len(stdout)):
        if stdout[i] == "{":
            depth += 1
        elif stdout[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(stdout[start : i + 1])
                except json.JSONDecodeError:
                    return {}
    return {}


def _scan_one(record: dict) -> dict:
    """Run `guarddog npm scan` for one record (blocking; call via asyncio.to_thread).

    Returns {"flagged": bool, "issues": int} on success, or {"error": str} when
    GuardDog itself could not evaluate the package (see module docstring for the
    two confirmed, structural reasons this happens on this corpus).
    """
    package = record["package_name"]
    version = record.get("version")
    args = [
        str(GUARDDOG_PYTHON), "-m", "guarddog", "npm", "scan", package,
        "--output-format", "json",
    ]
    if version and version != "latest":
        args += ["-v", version]

    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PATH"] = str(GUARDDOG_SCRIPTS) + os.pathsep + env.get("PATH", "")

    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=_SCAN_TIMEOUT_SECONDS, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {_SCAN_TIMEOUT_SECONDS}s"}

    payload = _extract_json(proc.stdout)
    if not payload:
        return {"error": f"no parseable output (exit {proc.returncode}): {proc.stderr[:200]}"}

    errors = payload.get("errors") or {}
    if errors:
        return {"error": "; ".join(f"{k}: {v}" for k, v in errors.items())}
    issues = int(payload.get("issues", 0) or 0)
    return {"flagged": issues > 0, "issues": issues}


def _classify_binary(ground_truth: str, result: dict) -> str:
    """GuardDog's verdict model is binary (flagged / clean), not
    ALLOW/WARN/BLOCK — mirrors evaluate.py's _classify but for that shape."""
    if "error" in result:
        return "ERROR"
    is_actually_positive = ground_truth in ("malicious", "typosquat", "hallucinated")
    is_predicted_positive = bool(result.get("flagged"))
    if is_actually_positive and is_predicted_positive:
        return "TP"
    if is_actually_positive and not is_predicted_positive:
        return "FN"
    if not is_actually_positive and is_predicted_positive:
        return "FP"
    return "TN"


async def _run(corpora: list[str], concurrency: int, output: Path) -> None:
    if not GUARDDOG_PYTHON.exists():
        raise SystemExit(
            f"GuardDog venv not found at {GUARDDOG_VENV}. Set up with:\n"
            f"  python3.11 -m venv {GUARDDOG_VENV}\n"
            f"  {GUARDDOG_VENV}/Scripts/pip install --only-binary :all: guarddog"
        )

    all_records: list[dict] = []
    for name in corpora:
        for r in _load_corpus(name):
            r["_corpus"] = name
            all_records.append(r)
    print(f"[baseline-guarddog] loaded {len(all_records)} records across {len(corpora)} corpora")
    print(f"[baseline-guarddog] concurrency={concurrency} (each scan downloads a tarball + runs semgrep, expect this to take a while)")

    sem = asyncio.Semaphore(concurrency)

    async def _bounded(r: dict) -> dict:
        async with sem:
            return await asyncio.to_thread(_scan_one, r)

    results = await asyncio.gather(*[_bounded(r) for r in all_records])

    per_ground_truth: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    )
    overall: dict[str, int] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    error_reasons: dict[str, int] = defaultdict(int)

    for r, res in zip(all_records, results):
        outcome = _classify_binary(r["ground_truth"], res)
        per_ground_truth[r["ground_truth"]][outcome] += 1
        overall[outcome] += 1
        if "error" in res:
            reason = "download-package" if "download-package" in res["error"] else "other"
            error_reasons[reason] += 1

    per_ground_truth_metrics = {k: _metrics_block(v) for k, v in per_ground_truth.items()}
    overall_metrics = _metrics_block(overall)
    overall_metrics["false_positive_rate"] = round(
        _safe_div(overall["FP"], overall["FP"] + overall["TN"]), 4
    )
    completion_rate = round(_safe_div(len(all_records) - overall["ERROR"], len(all_records)), 4)

    output_doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "guarddog",
        "corpora": corpora,
        "total_records": len(all_records),
        "completion_rate": completion_rate,
        "error_reasons": dict(error_reasons),
        "metrics": {
            "per_ground_truth": per_ground_truth_metrics,
            "overall": overall_metrics,
        },
    }

    print("\n=== Metrics ===")
    print(json.dumps(output_doc, indent=2))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_doc, indent=2), encoding="utf-8")
    print(f"\n[baseline-guarddog] wrote results -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python daemon/eval/baseline_guarddog.py",
        description="Run the CIDAS eval corpora through GuardDog for a baseline comparison.",
    )
    parser.add_argument("--corpus", choices=ALL_CORPORA, help="Run only one corpus (default: all four).")
    parser.add_argument("--output", default=str(RESULTS_DIR / "baseline_guarddog.json"))
    parser.add_argument("--concurrency", type=int, default=3, help="Concurrent scans (default: 3).")
    args = parser.parse_args()

    corpora = [args.corpus] if args.corpus else list(ALL_CORPORA)
    asyncio.run(_run(corpora, args.concurrency, Path(args.output)))


if __name__ == "__main__":
    main()
