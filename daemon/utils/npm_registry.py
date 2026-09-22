"""Async npm registry client.

All functions are module-level coroutines (not methods) so they can be
imported and mocked individually in tests without instantiating any class.

Registry lookups return a tri-state ``RegistryResult`` rather than a plain
``dict | None``: a confirmed HTTP 404 is distinguished from an undetermined
outcome (timeout, transport error, or a non-404 HTTP error status after
retries are exhausted). Conflating the two used to mean a transient registry
blip was treated identically to "this package does not exist," which forced
a BLOCK-level score for real, popular packages during registry hiccups.
"""
from __future__ import annotations

import asyncio
import io
import re
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import httpx

from ..config import get_settings
from .logger import get_logger

log = get_logger(__name__)

_TIMEOUT = httpx.Timeout(5.0)
_DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-month"

_SECURITY_PLACEHOLDER_VERSION_RE = re.compile(r"-security\.\d+$")


class _TokenBucketLimiter:
    """Shared token-bucket rate limiter for outbound npm HTTP calls.

    Retry-with-backoff (see _get's 429 handling) is reactive: it only helps
    once a request has already been rejected, and cannot prevent a burst of
    concurrent requests from tripping a hard rate limit in the first place.
    Observed in practice: api.npmjs.org's downloads endpoint 429s heavily
    when Sentinel's reputation-corroboration check fires many concurrent,
    distinct (uncached) download-count lookups within the same few seconds
    — e.g. scanning the typosquat corpus, where every candidate/target pair
    is looked up for the first time in a tight burst. This limiter paces
    every _get() call proactively so that burst never happens, independent
    of whether any individual name benefits from the result cache.
    """

    def __init__(self, rate_per_sec: float, capacity: float) -> None:
        self._rate = rate_per_sec
        self._capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._last_refill = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)


# 2 req/s sustained, burst of 2 — conservative relative to the bursts
# (dozens of concurrent distinct requests within ~1s) observed to trip
# api.npmjs.org's rate limit during a full-corpus evaluation run.
_NPM_RATE_LIMITER = _TokenBucketLimiter(rate_per_sec=2.0, capacity=2.0)


class RegistryLookup(Enum):
    """Outcome of a registry lookup, distinguishing absence from ambiguity."""

    EXISTS = "exists"
    CONFIRMED_ABSENT = "confirmed_absent"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True)
class RegistryResult:
    """Result of a registry document fetch.

    ``data`` is populated only when ``status is RegistryLookup.EXISTS``.
    """

    status: RegistryLookup
    data: dict[str, Any] | None = None


def is_security_placeholder_version(version: str) -> bool:
    """True if *version* matches npm's security-placeholder convention.

    When npm's security team pulls a malicious or reserved release, it
    republishes a stub under a version like ``"0.0.1-security.0"`` in its
    place — the tarball resolves (HTTP 200) but its contents are an inert
    placeholder, not the original package. See
    https://docs.npmjs.com/policies/security.
    """
    return bool(_SECURITY_PLACEHOLDER_VERSION_RE.search(version or ""))

# ── Per-package metadata single-flight cache ──────────────────────────────────
#
# A single /scan request fans out to several call sites that each need the
# same package's full registry document: Contextify (description), Sentinel
# (existence/age/repo signals), Shield (tarball info, when router doesn't pass
# pre-fetched metadata), disk_checker (unpacked size), get_direct_dependencies,
# and get_version_history (used by the cross-version diff analyzer). Every one
# of them hits the exact same URL (`{registry_url}/{name}` — version-specific
# lookups just slice the same full document locally), so without this cache
# one scan of an existing package makes 5+ redundant round-trips to
# registry.npmjs.org, which measured in the tens of seconds per scan in a live
# evaluation run. The TTL is short — just long enough to span one request's
# concurrent pillar fan-out — so it never serves meaningfully stale data
# across genuinely separate scans.
_METADATA_CACHE_TTL = 10.0
_metadata_cache: dict[str, tuple[float, "asyncio.Future[RegistryResult]"]] = {}
_metadata_cache_lock = asyncio.Lock()


async def _fetch_registry_doc_cached(name: str) -> RegistryResult:
    """Single-flight, short-TTL cache around the full-document registry fetch."""
    now = time.monotonic()
    async with _metadata_cache_lock:
        cached = _metadata_cache.get(name)
        if cached is not None and now - cached[0] < _METADATA_CACHE_TTL:
            future = cached[1]
        else:
            url = f"{get_settings().npm_registry_url}/{name}"
            future = asyncio.ensure_future(_get(url))
            _metadata_cache[name] = (now, future)
    try:
        result = await future
    except Exception:
        # A failed fetch must not poison the cache for the TTL window —
        # drop the entry so the next caller gets a fresh attempt.
        async with _metadata_cache_lock:
            if _metadata_cache.get(name) == (now, future):
                _metadata_cache.pop(name, None)
        raise
    if result.status is RegistryLookup.UNDETERMINED:
        # A transient timeout/transport/non-404-error outcome must not be
        # cached — caching it would mean a single network blip is treated
        # as authoritative by every fan-out caller for the rest of the TTL
        # window. EXISTS and CONFIRMED_ABSENT are both stable facts and are
        # safe (and desirable) to share across pillars via the cache.
        async with _metadata_cache_lock:
            if _metadata_cache.get(name) == (now, future):
                _metadata_cache.pop(name, None)
    return result


def _clear_metadata_cache() -> None:
    """Test-only helper: reset the single-flight cache between test cases."""
    _metadata_cache.clear()


_MAX_RATE_LIMIT_RETRIES = 3
_RATE_LIMIT_BACKOFF_BASE = 0.5  # seconds; linear backoff (base * attempt#)


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a numeric-seconds Retry-After header value. Returns None for
    missing/non-numeric values (e.g. an HTTP-date) rather than raising —
    callers fall back to a fixed backoff in that case."""
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


async def _get(url: str) -> RegistryResult:
    """Make a single GET request; returns a tri-state RegistryResult.

    HTTP 429 (rate limited) is retried with backoff — up to
    _MAX_RATE_LIMIT_RETRIES times, honoring Retry-After when present —
    since a 429 is by definition transient, unlike other non-404 HTTP
    errors. npm's downloads API (used by get_download_count) rate-limits
    aggressively under sustained request volume; without this, a single
    burst of 429s could cascade into spurious UNDETERMINED results across
    an entire evaluation run.
    """
    rate_limit_attempts = 0
    for attempt in (1, 2):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                while True:
                    await _NPM_RATE_LIMITER.acquire()
                    resp = await client.get(url, headers={"Accept": "application/json"})
                    if resp.status_code == 429 and rate_limit_attempts < _MAX_RATE_LIMIT_RETRIES:
                        rate_limit_attempts += 1
                        delay = _parse_retry_after(resp.headers.get("Retry-After"))
                        if delay is None:
                            delay = _RATE_LIMIT_BACKOFF_BASE * rate_limit_attempts
                        log.debug(
                            "GET %s rate-limited (429), retrying in %.1fs (attempt %d/%d)",
                            url, delay, rate_limit_attempts, _MAX_RATE_LIMIT_RETRIES,
                        )
                        await asyncio.sleep(delay)
                        continue
                    break
                if resp.status_code == 404:
                    return RegistryResult(RegistryLookup.CONFIRMED_ABSENT)
                if resp.status_code == 429:
                    log.warning("GET %s still rate-limited after %d retries", url, rate_limit_attempts)
                    return RegistryResult(RegistryLookup.UNDETERMINED)
                resp.raise_for_status()
                return RegistryResult(RegistryLookup.EXISTS, resp.json())
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            # TransportError covers NetworkError plus RemoteProtocolError
            # ("server disconnected without sending a response") and other
            # connection-level failures — under real concurrent load the
            # registry occasionally drops a connection without a clean error,
            # which used to propagate uncaught and 500 the whole /scan request.
            if attempt == 2:
                log.warning("GET %s failed after 2 attempts: %s", url, exc)
                return RegistryResult(RegistryLookup.UNDETERMINED)
            log.debug("GET %s attempt %d failed, retrying: %s", url, attempt, exc)
        except httpx.HTTPStatusError as exc:
            # A non-404 error status (5xx, etc.) is ambiguous, not a confirmed
            # absence — the package may well exist; the registry just failed
            # to serve it this time.
            log.warning("HTTP %s from %s", exc.response.status_code, url)
            return RegistryResult(RegistryLookup.UNDETERMINED)
    return RegistryResult(RegistryLookup.UNDETERMINED)  # unreachable, but satisfies mypy


async def get_package_metadata(
    name: str,
    version: str | None = None,
    *,
    confirm_absence: bool = False,
) -> RegistryResult:
    """Return full package metadata from the registry as a RegistryResult.

    If *version* is given, ``data`` is the version-specific package.json dict;
    otherwise ``data`` is the full registry document for *name*. Only
    populated when ``status is RegistryLookup.EXISTS``.

    In both cases a top-level ``unpackedSize`` key (int, bytes) is injected
    into ``data`` from ``dist.unpackedSize`` of the resolved version.
    Defaults to 0 when the field is absent or the registry omits it.

    If *confirm_absence* is True and the first lookup comes back
    CONFIRMED_ABSENT, one extra confirmatory re-fetch (bypassing the cache)
    is made before returning — for callers where treating "not found" as a
    high-consequence signal (e.g. Sentinel's BLOCK-floor gate) justifies the
    extra latency. Callers that don't need that guarantee should leave this
    False.
    """
    result = await _fetch_registry_doc_cached(name)
    if confirm_absence and result.status is RegistryLookup.CONFIRMED_ABSENT:
        async with _metadata_cache_lock:
            _metadata_cache.pop(name, None)
        result = await _fetch_registry_doc_cached(name)
    if result.status is not RegistryLookup.EXISTS:
        return result
    meta = result.data
    assert meta is not None
    if version:
        manifest = meta.get("versions", {}).get(version)
        if manifest is None:
            return RegistryResult(RegistryLookup.CONFIRMED_ABSENT)
        dist = manifest.get("dist") or {}
        manifest["unpackedSize"] = int(dist.get("unpackedSize") or 0)
        return RegistryResult(RegistryLookup.EXISTS, manifest)
    # Full registry document: inject unpackedSize and deprecation info from the latest version.
    latest = (meta.get("dist-tags") or {}).get("latest")
    if latest:
        latest_ver = (meta.get("versions") or {}).get(latest) or {}
        dist = latest_ver.get("dist") or {}
        meta["unpackedSize"] = int(dist.get("unpackedSize") or 0)
        dep_msg = latest_ver.get("deprecated")
        meta["deprecated"] = bool(dep_msg)
        meta["deprecation_message"] = str(dep_msg) if dep_msg else ""
    else:
        meta["unpackedSize"] = 0
        meta["deprecated"] = False
        meta["deprecation_message"] = ""
    return RegistryResult(RegistryLookup.EXISTS, meta)


async def get_package_size(name: str, version: str = "latest") -> int:
    """Return ``dist.unpackedSize`` (bytes) for *name* at *version*.

    *version* may be an exact semver, a semver range, or ``"latest"``.
    Ranges and ``"latest"`` resolve to ``dist-tags.latest``.
    Returns 0 on any error — 404, timeout, or missing field.
    """
    try:
        result = await get_package_metadata(name)
        if result.status is not RegistryLookup.EXISTS:
            return 0
        meta = result.data or {}
        dist_tags: dict = meta.get("dist-tags") or {}
        versions: dict = meta.get("versions") or {}
        cleaned = (version or "").lstrip("v=^~")
        if _EXACT_VERSION_RE.match(cleaned) and cleaned in versions:
            resolved = cleaned
        else:
            resolved = dist_tags.get("latest") or ""
        if not resolved or resolved not in versions:
            return 0
        dist = (versions[resolved].get("dist") or {})
        return int(dist.get("unpackedSize") or 0)
    except Exception:  # noqa: BLE001
        return 0


# ── Download-count single-flight cache ────────────────────────────────────────
#
# Reputation-disparity corroboration (Sentinel) looks up the *target*
# package's download count for every raw-distance/affix typosquat hit — and
# a large fraction of a real corpus's typosquat candidates target the same
# small set of popular packages (react, lodash, express, uuid, ...). Without
# caching, that's hundreds of redundant identical calls to npm's downloads
# API across one evaluation run, which measurably trips its rate limiting
# (observed: sustained 429s under a live corpus run). A 5-minute TTL is safe
# since monthly download counts don't meaningfully change on that timescale,
# and long enough to cover an entire scan session's repeated lookups of the
# same hot targets.
_DOWNLOAD_CACHE_TTL = 300.0
_download_cache: dict[str, tuple[float, "asyncio.Future[int]"]] = {}
_download_cache_lock = asyncio.Lock()


def _clear_download_cache() -> None:
    """Test-only helper: reset the download-count cache between test cases."""
    _download_cache.clear()


async def _fetch_download_count(name: str) -> int:
    result = await _get(f"{_DOWNLOADS_BASE}/{name}")
    if result.status is not RegistryLookup.EXISTS or result.data is None:
        return 0
    return int(result.data.get("downloads", 0))


async def get_download_count(name: str) -> int:
    """Return last-month download count from the npm downloads API.

    Single-flight cached per *name* for _DOWNLOAD_CACHE_TTL seconds — see
    the cache docstring above for why this matters for corroboration.
    """
    now = time.monotonic()
    async with _download_cache_lock:
        cached = _download_cache.get(name)
        if cached is not None and now - cached[0] < _DOWNLOAD_CACHE_TTL:
            future = cached[1]
        else:
            future = asyncio.ensure_future(_fetch_download_count(name))
            _download_cache[name] = (now, future)
    try:
        return await future
    except Exception:
        async with _download_cache_lock:
            if _download_cache.get(name) == (now, future):
                _download_cache.pop(name, None)
        raise


async def download_tarball(url: str, dest_path: str) -> bool:
    """Stream a tarball from *url* to *dest_path*. Returns True on success.

    Capped at 25 MiB to avoid pathological packages exhausting disk; npm's
    own per-tarball limit is well below this. Network failures return False
    so callers can degrade gracefully (skip the file scan).
    """
    max_bytes = 25 * 1024 * 1024
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=True) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    log.warning("tarball GET %s returned HTTP %s", url, resp.status_code)
                    return False
                written = 0
                with open(dest_path, "wb") as f:
                    async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                        written += len(chunk)
                        if written > max_bytes:
                            log.warning("tarball %s exceeded %d-byte cap", url, max_bytes)
                            return False
                        f.write(chunk)
        return True
    except (httpx.TimeoutException, httpx.NetworkError, OSError) as exc:
        log.warning("tarball download failed for %s: %s", url, exc)
        return False


async def tarball_has_member(
    tarball_url: str,
    member_basenames: frozenset[str],
    *,
    max_bytes: int = 2 * 1024 * 1024,
) -> bool | None:
    """Check whether *tarball_url* contains a tar entry whose basename is in
    *member_basenames*, without extracting file contents or downloading the
    whole archive.

    Streams up to *max_bytes* into memory and iterates the tar's member
    list (tolerating npm's ``package/`` path prefix). Returns:

    - ``True``  — a matching member was found before the cap.
    - ``False`` — the archive was read to a clean EOF within the cap with no
      matching member (confirmed absent).
    - ``None``  — undetermined: non-200 response, timeout/transport error,
      the *max_bytes* cap was hit, or the buffered data couldn't be parsed
      as a complete archive. A truncated/ambiguous read must never be
      reported as ``False`` — callers should treat ``None`` as "could not
      verify" and fail closed (e.g. force a fuller check) rather than
      trusting an absence they can't actually confirm.
    """
    buf = io.BytesIO()
    hit_cap = False
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=True) as client:
            async with client.stream("GET", tarball_url) as resp:
                if resp.status_code != 200:
                    log.warning("tarball listing GET %s returned HTTP %s", tarball_url, resp.status_code)
                    return None
                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    buf.write(chunk)
                    if buf.tell() > max_bytes:
                        hit_cap = True
                        break
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        log.warning("tarball listing failed for %s: %s", tarball_url, exc)
        return None

    buf.seek(0)
    found = False
    reached_clean_eof = False
    try:
        with tarfile.open(fileobj=buf, mode="r|gz") as tf:
            for member in tf:
                basename = member.name.rsplit("/", 1)[-1]
                if basename in member_basenames:
                    found = True
                    break
            else:
                reached_clean_eof = True
    except (tarfile.TarError, OSError) as exc:
        log.debug("tarball listing parse failed for %s: %s", tarball_url, exc)

    if found:
        return True
    if hit_cap or not reached_clean_eof:
        return None
    return False


_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")


async def get_direct_dependencies(name: str, version: str | None) -> dict[str, str]:
    """Return the direct dependencies declared in name@version's package manifest.

    *version* may be an exact semver (``"1.2.3"``) or a semver range
    (``"^1.0.0"``).  Ranges and ``None`` are resolved to the package's current
    ``dist-tags.latest`` version.  Returns an empty dict on any error so callers
    can degrade gracefully without special-casing failures.
    """
    result = await get_package_metadata(name)
    if result.status is not RegistryLookup.EXISTS or result.data is None:
        return {}
    meta = result.data
    dist_tags: dict = meta.get("dist-tags", {})
    versions: dict = meta.get("versions", {})

    # Use the requested version only when it's an exact semver present in the registry.
    cleaned = (version or "").lstrip("v=")
    if _EXACT_VERSION_RE.match(cleaned) and cleaned in versions:
        resolved = cleaned
    else:
        resolved = dist_tags.get("latest") or ""
    if not resolved or resolved not in versions:
        return {}

    manifest = versions[resolved]
    return dict(manifest.get("dependencies", {}) or {})


# Maximum number of recent versions returned by get_version_history.
# Cap exists because some packages have hundreds of versions (e.g. react),
# and diff analysis only ever needs the immediately-preceding entry.
_MAX_HISTORY = 10

# How far get_previous_version will walk backward past purged/unresolvable
# versions before giving up. npm's security team typically purges only the
# 1-2 malicious releases themselves, but a large batch compromise could in
# principle wipe a longer run — this bounds the worst case so the walk
# never silently diffs against a version many releases older than intended.
_MAX_PREDECESSOR_WALKBACK = 20


async def get_full_version_timeline(name: str) -> list[dict[str, Any]]:
    """Return every version npm has recorded a publish timestamp for,
    oldest-first, each tagged with whether its manifest is still resolvable
    today: ``[{"version": str, "published": datetime, "resolvable": bool}]``.

    Unlike ``get_version_history``, this is neither filtered to resolvable
    versions nor capped — callers that need to locate a since-purged
    version's position in publish order (e.g. ``get_previous_version``) need
    the *unfiltered* timeline, since npm's ``time`` object typically still
    records a purged version's original publish timestamp even after its
    manifest has been removed from ``versions``. Returns ``[]`` on registry
    miss or when no parseable timestamps are present.
    """
    result = await get_package_metadata(name)
    if result.status is not RegistryLookup.EXISTS or result.data is None:
        return []
    meta = result.data

    times: dict = meta.get("time", {}) or {}
    versions: dict = meta.get("versions", {}) or {}

    timeline: list[dict[str, Any]] = []
    for version, published_str in times.items():
        # 'created'/'modified' are document-level meta-keys, not real versions.
        if version in ("created", "modified"):
            continue
        try:
            published = datetime.fromisoformat(str(published_str).replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            continue
        timeline.append({"version": version, "published": published, "resolvable": version in versions})

    timeline.sort(key=lambda d: d["published"])
    return timeline


async def get_version_history(name: str) -> list[dict[str, Any]]:
    """Return ``[{"version": str, "published": datetime}]`` oldest-first,
    restricted to versions still resolvable today and capped at the **10
    most recent** to keep diff analysis bounded. Returns ``[]`` on registry
    miss or when no parseable timestamps are present.
    """
    timeline = await get_full_version_timeline(name)
    history = [{"version": e["version"], "published": e["published"]} for e in timeline if e["resolvable"]]
    return history[-_MAX_HISTORY:]


async def get_previous_version(name: str, current_version: str) -> str | None:
    """Return the nearest resolvable version published before *current_version*.

    Walks backward from *current_version*'s position in the full publish
    timeline (not the resolvable-only history), so a since-purged version —
    e.g. a malicious release npm's security team removed — can still be
    located by publish order even though its own manifest is gone. The
    search for a predecessor then skips over any *other* purged versions in
    between to find the nearest one that still resolves, bounded to
    ``_MAX_PREDECESSOR_WALKBACK`` steps back.

    Returns ``None`` if *current_version* has no recorded publish timestamp
    at all, is the first release, or no resolvable predecessor is found
    within the walkback bound.
    """
    if not current_version:
        return None
    timeline = await get_full_version_timeline(name)
    idx = next((i for i, e in enumerate(timeline) if e["version"] == current_version), None)
    if idx is None or idx == 0:
        return None
    lo = max(0, idx - _MAX_PREDECESSOR_WALKBACK)
    for j in range(idx - 1, lo - 1, -1):
        if timeline[j]["resolvable"]:
            return timeline[j]["version"]
    return None


async def get_package_tarball_info(name: str, version: str | None) -> dict[str, Any] | None:
    """Return the dist/tarball metadata for a specific package version."""
    result = await get_package_metadata(name)
    if result.status is not RegistryLookup.EXISTS or result.data is None:
        return None
    meta = result.data
    dist_tags: dict = meta.get("dist-tags", {})
    resolved_version = version or dist_tags.get("latest")
    if not resolved_version:
        return None
    versions: dict = meta.get("versions", {})
    pkg = versions.get(resolved_version)
    if pkg is None:
        return None
    return pkg.get("dist")
