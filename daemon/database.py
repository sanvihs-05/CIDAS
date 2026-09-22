"""Async SQLite cache for scan results.

The ``scan_cache`` table stores completed ScanResponse objects keyed by
``package_name@version``.  Each row carries a ``ttl_seconds`` field; entries
are considered valid as long as ``scanned_at + ttl_seconds > now()``.

Call ``init_db()`` once at daemon startup before any reads or writes.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import time
from dataclasses import dataclass, field

import aiosqlite

from .config import get_settings
from .models import PillarScore, ScanResponse
from .utils.logger import get_logger

log = get_logger(__name__)

_DEFAULT_TTL = 3600  # 1 hour

# Bump this whenever the cache key format or table schema changes.
# init_db() runs any pending migrations automatically.
_SCHEMA_VERSION = 3

# Trust-check outcome constants — used by router to decide how to respond.
TRUST_STATUS_VERIFIED = "verified"      # HMAC matches → ALLOW
TRUST_STATUS_LEGACY   = "legacy_no_mac" # pre-MAC row  → WARN
TRUST_STATUS_TAMPERED = "tampered"      # HMAC mismatch → log CRITICAL, treat as UNKNOWN
TRUST_STATUS_UNKNOWN  = "unknown"       # not in trust list


@dataclass
class TrustCheckResult:
    """Outcome of checking one package against the trust list."""
    status: str
    package_name: str
    flags: list[str] = field(default_factory=list)

_CREATE_SCAN_CACHE = """
CREATE TABLE IF NOT EXISTS scan_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_key  TEXT    NOT NULL UNIQUE,
    decision     TEXT    NOT NULL,
    risk_score   REAL    NOT NULL,
    context_json TEXT    NOT NULL,
    sentinel_json TEXT   NOT NULL,
    shield_json  TEXT    NOT NULL,
    explanation  TEXT    NOT NULL,
    scanned_at   REAL    NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);
"""

_CREATE_TRUST_CACHE = """
CREATE TABLE IF NOT EXISTS trust_cache (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name   TEXT    NOT NULL UNIQUE,
    added_at       REAL    NOT NULL,
    source         TEXT    NOT NULL DEFAULT 'api',
    trust_list_mac TEXT,
    mac_status     TEXT    NOT NULL DEFAULT 'ok'
);
"""

# ── HMAC helpers ──────────────────────────────────────────────────────────────
#
# The HMAC key is the daemon's bearer token (64-char hex, 256-bit entropy).
# Message: "name|seconds|source" — int(added_at) avoids SQLite REAL round-trip
# ambiguity while preserving second-level uniqueness.

def _trust_mac_message(package_name: str, added_at: float, source: str) -> bytes:
    return f"{package_name}|{int(added_at)}|{source}".encode()


def _compute_trust_mac(package_name: str, added_at: float, source: str, token: str) -> str:
    """Return the HMAC-SHA256 hex digest for a trust-list row."""
    return _hmac.new(
        token.encode(), _trust_mac_message(package_name, added_at, source), hashlib.sha256
    ).hexdigest()

_CREATE_SCHEMA_VERSION = """
CREATE TABLE IF NOT EXISTS schema_version (
    id         INTEGER PRIMARY KEY,
    version    INTEGER NOT NULL,
    applied_at REAL    NOT NULL
);
"""


def _pkg_key(name: str, version: str | None) -> str:
    return f"{name}@{version or 'latest'}"


async def _get_schema_version(db: aiosqlite.Connection) -> int:
    async with db.execute("SELECT MAX(version) FROM schema_version") as cur:
        row = await cur.fetchone()
    return row[0] if (row and row[0] is not None) else 0


async def init_db() -> None:
    """Create tables and run pending schema migrations.

    Migration history
    -----------------
    v1 → v2:  scan_cache keys changed from bare ``package_name`` to
        ``name@version``.  Pre-v2 rows are purged.
    v2 → v3:  trust_cache gained ``source``, ``trust_list_mac``, and
        ``mac_status`` columns.  Existing rows receive mac_status
        ``'legacy_no_mac'`` so the router treats them as WARN rather
        than ALLOW until they are re-added via the API.
    """
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(_CREATE_SCAN_CACHE)
        await db.execute(_CREATE_TRUST_CACHE)
        await db.execute(_CREATE_SCHEMA_VERSION)
        await db.commit()

        current = await _get_schema_version(db)

        if current < 2:
            cursor = await db.execute(
                "DELETE FROM scan_cache WHERE package_key NOT LIKE '%@%'"
            )
            purged = cursor.rowcount
            await db.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (2, time.time()),
            )
            await db.commit()
            if purged:
                log.info("schema migration v2: purged %d stale scan_cache rows", purged)

        if current < 3:
            # ADD COLUMN is idempotent if already present (wrapped in try/except
            # because SQLite raises OperationalError on duplicate column names).
            for ddl in (
                "ALTER TABLE trust_cache ADD COLUMN source TEXT NOT NULL DEFAULT 'api'",
                "ALTER TABLE trust_cache ADD COLUMN trust_list_mac TEXT",
                # Default 'legacy_no_mac' so existing rows are treated as unverified.
                "ALTER TABLE trust_cache ADD COLUMN mac_status TEXT NOT NULL DEFAULT 'legacy_no_mac'",
            ):
                try:
                    await db.execute(ddl)
                except Exception:
                    pass  # column already exists (re-entrant migration)
            await db.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (3, time.time()),
            )
            await db.commit()
            log.info("schema migration v3: trust_list_mac added to trust_cache")

    log.info("SQLite cache ready (schema v%d) at %s", _SCHEMA_VERSION, settings.sqlite_db_path)


async def get_cached_result(name: str, version: str | None) -> ScanResponse | None:
    """Return a cached ScanResponse or None if missing/expired."""
    settings = get_settings()
    key = _pkg_key(name, version)
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            """
            SELECT decision, risk_score, context_json, sentinel_json, shield_json,
                   explanation, scanned_at, ttl_seconds
            FROM scan_cache
            WHERE package_key = ? AND (scanned_at + ttl_seconds) > ?
            """,
            (key, now),
        ) as cursor:
            row = await cursor.fetchone()

    if row is None:
        return None

    decision, risk_score, ctx_j, sen_j, shi_j, explanation, _, _ = row
    return ScanResponse(
        package_name=name,
        version=version,
        decision=decision,  # type: ignore[arg-type]
        risk_score=risk_score,
        contextify=PillarScore(**json.loads(ctx_j)),
        sentinel=PillarScore(**json.loads(sen_j)),
        shield=PillarScore(**json.loads(shi_j)),
        explanation=explanation,
    )


async def store_result(response: ScanResponse, ttl_seconds: int = _DEFAULT_TTL) -> None:
    """Persist a ScanResponse; upserts on conflict."""
    settings = get_settings()
    key = _pkg_key(response.package_name, response.version)
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(
            """
            INSERT INTO scan_cache
                (package_key, decision, risk_score, context_json, sentinel_json,
                 shield_json, explanation, scanned_at, ttl_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_key) DO UPDATE SET
                decision      = excluded.decision,
                risk_score    = excluded.risk_score,
                context_json  = excluded.context_json,
                sentinel_json = excluded.sentinel_json,
                shield_json   = excluded.shield_json,
                explanation   = excluded.explanation,
                scanned_at    = excluded.scanned_at,
                ttl_seconds   = excluded.ttl_seconds
            """,
            (
                key,
                response.decision,
                response.risk_score,
                json.dumps(response.contextify.model_dump()),
                json.dumps(response.sentinel.model_dump()),
                json.dumps(response.shield.model_dump()),
                response.explanation,
                now,
                ttl_seconds,
            ),
        )
        await db.commit()


async def clear_expired() -> int:
    """Delete expired rows; returns the count removed."""
    settings = get_settings()
    now = time.time()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        cursor = await db.execute(
            "DELETE FROM scan_cache WHERE (scanned_at + ttl_seconds) <= ?", (now,)
        )
        await db.commit()
        return cursor.rowcount


async def add_trusted(package_name: str, token: str, source: str = "api") -> None:
    """Mark a package as locally trusted with an HMAC integrity tag.

    The HMAC is computed over ``(package_name, added_at, source)`` using the
    daemon's bearer token as the key, so a direct SQLite INSERT by an attacker
    cannot forge a valid MAC without reading the token file.
    """
    settings = get_settings()
    now = time.time()
    mac = _compute_trust_mac(package_name, now, source, token)
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        await db.execute(
            """
            INSERT INTO trust_cache (package_name, added_at, source, trust_list_mac, mac_status)
            VALUES (?, ?, ?, ?, 'ok')
            ON CONFLICT(package_name) DO UPDATE SET
                added_at       = excluded.added_at,
                source         = excluded.source,
                trust_list_mac = excluded.trust_list_mac,
                mac_status     = 'ok'
            """,
            (package_name, now, source, mac),
        )
        await db.commit()


async def is_trusted(package_name: str) -> bool:
    """Legacy presence check — returns True if the package is in the trust list.

    Does not verify the HMAC.  Use ``check_trust()`` for full integrity checks.
    Kept for backward compatibility with code that only needs a yes/no answer.
    """
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            "SELECT 1 FROM trust_cache WHERE package_name = ?", (package_name,)
        ) as cursor:
            return await cursor.fetchone() is not None


async def check_trust(package_name: str, token: str) -> TrustCheckResult:
    """Verify the HMAC on the trust-list row for *package_name*.

    Returns a ``TrustCheckResult`` whose ``status`` is one of:
    - ``TRUST_STATUS_VERIFIED``  — HMAC matches, safe to ALLOW.
    - ``TRUST_STATUS_LEGACY``    — row predates MAC column, treat as WARN.
    - ``TRUST_STATUS_TAMPERED``  — HMAC mismatch; logs CRITICAL.
    - ``TRUST_STATUS_UNKNOWN``   — package not in the trust list at all.
    """
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            "SELECT added_at, source, trust_list_mac, mac_status "
            "FROM trust_cache WHERE package_name = ?",
            (package_name,),
        ) as cur:
            row = await cur.fetchone()

    if row is None:
        return TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name=package_name)

    added_at, source, stored_mac, mac_status = row
    source = source or "api"

    if mac_status == TRUST_STATUS_LEGACY or stored_mac is None:
        return TrustCheckResult(
            status=TRUST_STATUS_LEGACY,
            package_name=package_name,
            flags=["trust_legacy_no_mac"],
        )

    expected = _compute_trust_mac(package_name, added_at, source, token)
    if _hmac.compare_digest(stored_mac, expected):
        return TrustCheckResult(status=TRUST_STATUS_VERIFIED, package_name=package_name)

    # HMAC mismatch — trust record has been tampered with.
    log.critical(
        "TRUST TAMPER DETECTED: package=%s added_at=%s source=%s — "
        "trust_cache row HMAC does not match; treating package as UNTRUSTED.",
        package_name, added_at, source,
    )
    return TrustCheckResult(
        status=TRUST_STATUS_TAMPERED,
        package_name=package_name,
        flags=["trust_tamper_detected"],
    )


async def list_all_trusted(token: str) -> list[dict]:
    """Return every trust_cache row with its live HMAC verification status.

    Used by the GET /trust/verify endpoint so security teams can audit the
    full trust list without reading the SQLite file directly.
    """
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        async with db.execute(
            "SELECT package_name, added_at, source, trust_list_mac, mac_status "
            "FROM trust_cache ORDER BY added_at DESC"
        ) as cur:
            rows = await cur.fetchall()

    results = []
    for pkg, added_at, source, stored_mac, mac_status in rows:
        source = source or "api"
        if mac_status == TRUST_STATUS_LEGACY or stored_mac is None:
            verification = TRUST_STATUS_LEGACY
        else:
            expected = _compute_trust_mac(pkg, added_at, source, token)
            verification = (
                TRUST_STATUS_VERIFIED
                if _hmac.compare_digest(stored_mac, expected)
                else TRUST_STATUS_TAMPERED
            )
        results.append({
            "package_name": pkg,
            "added_at": added_at,
            "source": source,
            "mac_status": mac_status,
            "verification": verification,
        })
    return results


async def invalidate_package(name: str, version: str) -> int:
    """Remove scan-cache entries for *name* at *version*.

    Pass ``version="*"`` to purge every cached version of the package —
    useful for emergency security-team invalidations where the exact
    affected version is unknown.

    Returns the number of rows deleted.
    """
    settings = get_settings()
    async with aiosqlite.connect(settings.sqlite_db_path) as db:
        if version == "*":
            # Match any key that starts with "name@" (exact prefix, not GLOB
            # expansion) so "evil-pkg" doesn't accidentally match "evil-pkg-lite".
            cursor = await db.execute(
                "DELETE FROM scan_cache WHERE package_key LIKE ?",
                (f"{name}@%",),
            )
        else:
            cursor = await db.execute(
                "DELETE FROM scan_cache WHERE package_key = ?",
                (_pkg_key(name, version),),
            )
        await db.commit()
        return cursor.rowcount
