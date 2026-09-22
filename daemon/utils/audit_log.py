"""Structured audit log — append-only JSONL with size-based rotation.

Every completed scan appends one line to ~/.cidas/audit.log.
When the file reaches 10 MB it is renamed audit.log.1 (shifting existing
rotated files up to a maximum of three), and a fresh audit.log is started.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .logger import get_logger

log = get_logger(__name__)

_DEFAULT_PATH = Path.home() / ".cidas" / "audit.log"
_MAX_BYTES   = 10 * 1024 * 1024  # 10 MB per file before rotation
_MAX_ROTATED = 3                  # keep audit.log.1 … audit.log.3

# One lock prevents interleaved writes when concurrent scans complete together.
_lock = asyncio.Lock()


def _audit_path() -> Path:
    """Return the active log path; isolated so tests can monkeypatch it."""
    return _DEFAULT_PATH


def _rotated(base: Path, n: int) -> Path:
    return base.parent / f"{base.name}.{n}"


def _rotate_sync(path: Path) -> None:
    """Rotate: drop .3 if present, shift .2→.3 / .1→.2, move log→.1."""
    oldest = _rotated(path, _MAX_ROTATED)
    if oldest.exists():
        oldest.unlink()
    for i in range(_MAX_ROTATED - 1, 0, -1):
        src = _rotated(path, i)
        if src.exists():
            src.replace(_rotated(path, i + 1))
    if path.exists():
        path.replace(_rotated(path, 1))


def _append_sync(record: dict) -> None:
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, separators=(",", ":")) + "\n"
    try:
        size = path.stat().st_size if path.exists() else 0
    except OSError:
        size = 0
    if size >= _MAX_BYTES:
        _rotate_sync(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)


async def append(record: dict) -> None:
    """Append *record* to the audit log, rotating if the file hits 10 MB.

    Failures are logged but never raised — a write error must not interrupt
    the scan response path.
    """
    try:
        async with _lock:
            await asyncio.to_thread(_append_sync, record)
    except Exception as exc:
        log.warning("audit: write failed: %s", exc)


def _read_sync(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    records: list[dict] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            records.append(json.loads(raw))
        except json.JSONDecodeError:
            log.warning("audit: skipping malformed line: %.80s", raw)
    return records


async def read_records(
    last: int = 100,
    verdict: str | None = None,
    package: str | None = None,
    since: str | None = None,
) -> list[dict]:
    """Return filtered records from the current audit log, newest last.

    Filters are ANDed together.  *verdict* matches the ``"verdict"`` field
    (scan records only — override events have no ``"verdict"`` and are
    excluded when this filter is active).  *package* matches the name part
    before the ``@`` version suffix.  *since* is an ISO-8601 string compared
    lexicographically against ``"ts"``.  *last* is capped at 1 000.
    """
    records: list[dict] = await asyncio.to_thread(_read_sync, _audit_path())
    if verdict is not None:
        records = [r for r in records if r.get("verdict") == verdict]
    if package is not None:
        records = [r for r in records if r.get("package", "").split("@")[0] == package]
    if since is not None:
        records = [r for r in records if r.get("ts", "") >= since]
    cap = min(last, 1_000)
    return records[-cap:]
