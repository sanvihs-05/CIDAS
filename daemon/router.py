"""FastAPI router — all HTTP endpoints for the CIDAS daemon.

Endpoints
---------
GET  /health                — liveness probe, no auth
POST /scan                  — screen an npm package (main entry point)
POST /trust                 — add a package to the local trust bypass list
GET  /trust/verify          — audit all trust-list HMACs (auth required)
DELETE /cache               — purge expired cache entries
POST /cache/invalidate      — emergency per-package cache invalidation (auth required)
GET  /audit                 — query structured scan audit log (auth required)
POST /audit/override        — record a user "Proceed Anyway" override event
GET  /policy                — return resolved project policy for a path
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from .auth import get_or_create_token, require_token
from .config import get_settings
from .database import (
    TRUST_STATUS_LEGACY,
    TRUST_STATUS_TAMPERED,
    TRUST_STATUS_VERIFIED,
    add_trusted,
    check_trust,
    clear_expired,
    get_cached_result,
    invalidate_package,
    list_all_trusted,
    store_result,
)
from .models import (
    DirectDependency,
    DiskFootprint,
    HealthResponse,
    PackageScanRequest,
    PillarScore,
    ScanResponse,
    TransitiveDependencyResult,
)
from .pillars.aggregator import Aggregator
from .pillars.contextify import Contextify
from .pillars.sentinel import Sentinel
from .pillars.shield import Shield
from .utils import audit_log, policy
from .utils.npm_registry import get_direct_dependencies
from .utils.transitive import resolve_transitive
from .utils.logger import get_logger
from .utils.offline_cache import record_allow
from .utils.drift_monitor import check_drift, BASELINE_PATH

log = get_logger(__name__)
router = APIRouter()

_contextify = Contextify()
_sentinel   = Sentinel()
_shield     = Shield()
_aggregator = Aggregator()

# Sentinel score at or above this value in a transitive dep triggers
# transitive_risk_detected on the parent scan response.
_TRANSITIVE_WARN_THRESHOLD = 50.0


async def _append_direct_deps(req: PackageScanRequest, response: ScanResponse) -> ScanResponse:
    """Fetch direct dependencies from the registry and attach to *response*."""
    try:
        raw = await get_direct_dependencies(req.package_name, req.version)
        response.direct_dependencies = [
            DirectDependency(name=n, version_range=v) for n, v in raw.items()
        ]
    except Exception as exc:  # noqa: BLE001
        log.warning("direct dep fetch failed for %s: %s", req.package_name, exc)
    return response


async def _append_disk_footprint(req: PackageScanRequest, response: ScanResponse) -> ScanResponse:
    """Fetch and attach disk install footprint to *response*.

    No-op when disk_check_enabled is False.  Runs on both fresh scans and
    cache-hit paths so the footprint is always fresh (sizes change between
    package versions).  Never raises — disk_checker itself is fault-tolerant.
    """
    settings = get_settings()
    if not settings.disk_check_enabled:
        return response
    from daemon.utils.disk_checker import check_disk_footprint
    transitive_list = [
        {"name": r.name, "version": r.version}
        for r in response.transitive_risks
    ] if req.scan_transitive else []
    disk_result = await check_disk_footprint(
        package_name=req.package_name,
        version=req.version or "latest",
        transitive_deps=transitive_list,
        project_path=req.project_path,
    )
    response.disk_footprint = DiskFootprint(**disk_result)
    if "exceeds_available_disk" in disk_result["flags"]:
        response.flags.append("insufficient_disk_space")
    return response


async def _append_transitive(req: PackageScanRequest, response: ScanResponse) -> ScanResponse:
    """Resolve transitive deps and run Sentinel on each; mutates *response* in place."""
    try:
        deps = await resolve_transitive(req.package_name, req.version or "latest")
    except Exception as exc:  # noqa: BLE001
        log.warning("transitive resolution failed for %s: %s", req.package_name, exc)
        return response

    # Dedup by name before hitting the registry — same package at different depths
    # gets one Sentinel call, recorded at its shallowest depth.
    # Cap at 30 unique packages so large trees (e.g. express ~200 deps) don't
    # blow past the shim timeout; prioritise shallow (direct) deps first.
    _TRANSITIVE_CAP = 30
    seen_names: dict[str, dict] = {}
    for dep in sorted(deps, key=lambda d: d["depth"]):
        if dep["name"] not in seen_names:
            seen_names[dep["name"]] = dep
        if len(seen_names) >= _TRANSITIVE_CAP:
            break

    async def _score_one(dep: dict) -> TransitiveDependencyResult | None:
        try:
            sen = await _sentinel.score(dep["name"], req.ai_suggested, dep.get("version"))
            return TransitiveDependencyResult(
                name=dep["name"],
                version=dep["version"],
                depth=dep["depth"],
                sentinel_score=sen.score,
                flags=sen.flags,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("sentinel failed for transitive dep %s: %s", dep["name"], exc)
            return None

    results_raw = await asyncio.gather(*[_score_one(d) for d in seen_names.values()])
    risks = [r for r in results_raw if r is not None]

    response.transitive_risks = risks
    response.transitive_risk_detected = any(
        r.sentinel_score >= _TRANSITIVE_WARN_THRESHOLD for r in risks
    )
    return response


def _collect_signals(response: ScanResponse) -> list[str]:
    """Deduplicated list of all flags across all pillars + trust_flags."""
    seen: set[str] = set()
    out: list[str] = []
    for flag in (
        response.contextify.flags
        + response.sentinel.flags
        + response.shield.flags
        + response.trust_flags
    ):
        if flag not in seen:
            seen.add(flag)
            out.append(flag)
    return out


async def _audit_scan(
    req: PackageScanRequest,
    response: ScanResponse,
    *,
    cached: bool,
) -> None:
    """Append a structured scan record to the audit log (fire-and-forget)."""
    record = {
        "ts":               datetime.now(timezone.utc).isoformat(),
        "package":          f"{req.package_name}@{req.version or 'latest'}",
        "verdict":          response.decision,
        "score":            response.risk_score,
        # Per-pillar scores, persisted so the concept-drift monitor
        # (utils/drift_monitor.py) can build real per-pillar histograms from
        # live traffic instead of only the composite score.
        "contextify_score": response.contextify.score,
        "sentinel_score":   response.sentinel.score,
        "shield_score":     response.shield.score,
        "signals":          _collect_signals(response),
        "ai_suggested":     req.ai_suggested,
        "project_path":     req.project_path,
        "cached":           cached,
    }
    await audit_log.append(record)


@router.get("/health")
async def health() -> dict:
    settings = get_settings()
    if settings.drift_monitoring_enabled:
        try:
            report = check_drift()
            drift_data: dict = {
                "status": report.status,
                "overall_kl": round(report.overall_kl, 4),
                "drifted_pillars": report.drifted_pillars,
                "sufficient_data": report.sufficient_data,
                "baseline_loaded": report.baseline_loaded,
                # PSI is reported alongside KL for comparison; it does not
                # currently drive `status`/`drifted_pillars` (see
                # utils/drift_monitor.py's check_drift docstring).
                "overall_psi": round(report.overall_psi, 4),
                "pillar_psi": report.pillar_psi,
            }
        except Exception as e:  # noqa: BLE001
            drift_data = {"status": "unavailable", "error": str(e)}
    else:
        drift_data = {"status": "disabled"}
    return {
        "status": "ok",
        "version": "0.1.0",
        "drift": drift_data,
    }


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_token)])
async def scan(req: PackageScanRequest) -> ScanResponse:
    """Screen an npm package; returns a cached result when available."""
    t0 = time.perf_counter()
    log.info("scan: %s@%s (ai_suggested=%s)", req.package_name, req.version or "latest", req.ai_suggested)

    # ── Project policy resolution ─────────────────────────────────────────
    # Discovered before any other check so block_list / trust_list rules
    # decided by the security lead in .cidas/policy.json take precedence over
    # both the local trust DB and the per-machine cache.
    policy_dict, policy_path = policy.resolve(req.project_path)
    policy_file_str = str(policy_path) if policy_path else None
    requires_confirmation = bool(policy_dict.get("warn_requires_confirmation"))

    if req.package_name in policy_dict.get("block_list", []):
        log.warning("policy block_list match: %s", req.package_name)
        blocked_score = PillarScore(
            score=100.0, confidence=1.0, flags=["policy_block"], metadata={},
        )
        response = ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="BLOCK",
            risk_score=100.0,
            contextify=blocked_score,
            sentinel=blocked_score,
            shield=blocked_score,
            explanation=(
                f"'{req.package_name}' is on the project block_list "
                f"({policy_file_str}). Installation refused."
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
            policy_file=policy_file_str,
            requires_confirmation=requires_confirmation,
        )
        await _audit_scan(req, response, cached=False)
        return response

    if req.package_name in policy_dict.get("trust_list", []):
        log.info("policy trust_list match: %s", req.package_name)
        trusted_score = PillarScore(
            score=0.0, confidence=1.0, flags=["policy_trust"], metadata={},
        )
        response = ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="ALLOW",
            risk_score=0.0,
            contextify=trusted_score,
            sentinel=trusted_score,
            shield=trusted_score,
            explanation=(
                f"'{req.package_name}' is on the project trust_list "
                f"({policy_file_str})."
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
            policy_file=policy_file_str,
            requires_confirmation=requires_confirmation,
        )
        await record_allow(req.package_name, req.version)
        await _audit_scan(req, response, cached=False)
        return response

    # Trust bypass — check HMAC integrity before honoring the trust list.
    token = get_or_create_token()
    trust_result = await check_trust(req.package_name, token)

    if trust_result.status == TRUST_STATUS_VERIFIED:
        log.info("trust bypass (verified) for %s", req.package_name)
        trusted_score = PillarScore(score=0.0, confidence=1.0, flags=["trusted"], metadata={})
        await record_allow(req.package_name, req.version)
        response = ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="ALLOW",
            risk_score=0.0,
            contextify=trusted_score,
            sentinel=trusted_score,
            shield=trusted_score,
            explanation=f"'{req.package_name}' is in the local trust list (HMAC verified).",
            latency_ms=(time.perf_counter() - t0) * 1000,
            policy_file=policy_file_str,
            requires_confirmation=requires_confirmation,
        )
        await _audit_scan(req, response, cached=False)
        return response

    if trust_result.status == TRUST_STATUS_LEGACY:
        # Pre-MAC rows: trusted but unverified — return WARN so users know
        # re-adding via /trust will give them full integrity protection.
        log.warning("trust bypass (legacy, no MAC) for %s", req.package_name)
        legacy_score = PillarScore(
            score=0.0, confidence=0.5, flags=["trust_legacy_no_mac"], metadata={}
        )
        response = ScanResponse(
            package_name=req.package_name,
            version=req.version,
            decision="WARN",
            risk_score=40.0,
            contextify=legacy_score,
            sentinel=legacy_score,
            shield=legacy_score,
            explanation=(
                f"'{req.package_name}' is in the local trust list but was added before "
                "integrity protection was enabled. Re-add via POST /trust to upgrade."
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
            trust_flags=trust_result.flags,
            policy_file=policy_file_str,
            requires_confirmation=requires_confirmation,
        )
        await _audit_scan(req, response, cached=False)
        return response

    # TAMPERED: log.critical was emitted inside check_trust; fall through to
    # a full pillar scan and attach the flag so the VS Code panel can alert.
    tamper_flags = trust_result.flags if trust_result.status == TRUST_STATUS_TAMPERED else []

    # Cache lookup
    cached = await get_cached_result(req.package_name, req.version)
    if cached:
        log.debug("cache hit: %s", req.package_name)
        cached.latency_ms = (time.perf_counter() - t0) * 1000
        if tamper_flags:
            cached.trust_flags = tamper_flags
        cached.policy_file = policy_file_str
        cached.requires_confirmation = requires_confirmation
        cached = await _append_direct_deps(req, cached)
        if req.scan_transitive:
            cached = await _append_transitive(req, cached)
        cached = await _append_disk_footprint(req, cached)
        await _audit_scan(req, cached, cached=True)
        return cached

    # Run all three pillars concurrently
    ctx_score, sen_score, shi_score = await asyncio.gather(
        _contextify.score(req.package_name, req.project_path),
        _sentinel.score(req.package_name, req.ai_suggested, req.version),
        _shield.score(req.package_name, None, req.version),
    )

    settings = get_settings()
    risk_score, explanation = _aggregator.aggregate(
        ctx_score, sen_score, shi_score, settings, policy_overrides=policy_dict,
    )

    # ── Policy penalties (apply on top of the weighted score) ─────────────
    # These rules are project-policy ceilings on what can pass: a low download
    # count for an AI-suggested package, or a missing repo link, are not
    # malware tells on their own — but a security lead may want them treated
    # as risk multipliers in their codebase.
    policy_flags: list[str] = []
    min_dl = policy_dict.get("min_monthly_downloads")
    if (
        isinstance(min_dl, int)
        and req.ai_suggested
        and (sen_score.metadata.get("monthly_downloads") or 0) < min_dl
    ):
        risk_score = min(risk_score + 15.0, 100.0)
        policy_flags.append("policy_low_downloads")
    if policy_dict.get("require_repository_link") and not sen_score.metadata.get("has_repository", True):
        risk_score = min(risk_score + 10.0, 100.0)
        policy_flags.append("policy_no_repository")

    if policy_flags:
        sen_score.flags.extend(policy_flags)
    decision = _aggregator.get_decision(risk_score, settings)

    response = ScanResponse(
        package_name=req.package_name,
        version=req.version,
        decision=decision,  # type: ignore[arg-type]
        risk_score=risk_score,
        contextify=ctx_score,
        sentinel=sen_score,
        shield=shi_score,
        explanation=explanation,
        latency_ms=(time.perf_counter() - t0) * 1000,
        tarball_url=shi_score.metadata.get("tarball_url"),
        file_scan_summary=shi_score.metadata.get("file_scan_summary"),
        trust_flags=tamper_flags,
        policy_file=policy_file_str,
        requires_confirmation=requires_confirmation,
    )

    await store_result(response)
    if decision == "ALLOW":
        # Mirror to offline-cache.json so the npm shim can serve known-good
        # packages silently when the daemon is unreachable.
        await record_allow(req.package_name, req.version)

    # Direct deps, transitive scan, and disk footprint run after store_result
    # so the cache always holds the base pillar result; all three are computed
    # fresh per request (disk sizes change with new package versions).
    response = await _append_direct_deps(req, response)
    if req.scan_transitive:
        response = await _append_transitive(req, response)
    response = await _append_disk_footprint(req, response)

    await _audit_scan(req, response, cached=False)
    log.info("result: decision=%s score=%.1f package=%s", decision, risk_score, req.package_name)
    return response


@router.post("/trust", dependencies=[Depends(require_token)])
async def trust(body: dict) -> dict:
    """Add a package to the local trust bypass list with an HMAC integrity tag."""
    package_name = body.get("package_name", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    token = get_or_create_token()
    await add_trusted(package_name, token)
    log.info("trusted: %s", package_name)
    return {"trusted": package_name}


@router.get("/trust/verify", dependencies=[Depends(require_token)])
async def trust_verify() -> dict:
    """Audit every trust-list row and report HMAC verification results.

    Returns a summary count and the full list, including any rows that appear
    to have been tampered with directly in the SQLite file.
    Auth required so an attacker cannot probe which packages are trusted.
    """
    token = get_or_create_token()
    rows = await list_all_trusted(token)
    tampered = [r for r in rows if r["verification"] == TRUST_STATUS_TAMPERED]
    legacy   = [r for r in rows if r["verification"] == TRUST_STATUS_LEGACY]
    verified = len(rows) - len(tampered) - len(legacy)
    if tampered:
        log.critical(
            "trust/verify: %d tampered rows detected: %s",
            len(tampered),
            [r["package_name"] for r in tampered],
        )
    return {
        "total":            len(rows),
        "verified":         verified,
        "legacy_no_mac":    len(legacy),
        "tampered":         len(tampered),
        "tampered_packages": tampered,
        "entries":          rows,
    }


@router.delete("/cache", dependencies=[Depends(require_token)])
async def cache_delete() -> dict:
    """Purge all expired scan cache entries."""
    removed = await clear_expired()
    log.info("cache purge: removed %d expired entries", removed)
    return {"purged": removed}


@router.post("/cache/invalidate", dependencies=[Depends(require_token)])
async def cache_invalidate(body: dict) -> dict:
    """Emergency per-package cache invalidation.

    Body fields
    -----------
    package_name : str  — the npm package name (required)
    version      : str  — the specific version to evict, or ``"*"`` to evict
                          every cached version of the package (required)

    Returns ``{"invalidated": <count>}`` with the number of rows removed.
    A security team can call this immediately after a malicious-package
    disclosure to force a fresh scan on the next install attempt.
    """
    package_name = body.get("package_name", "")
    version = body.get("version", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    if not version:
        raise HTTPException(
            status_code=422,
            detail='version is required; use "*" to invalidate all versions',
        )
    removed = await invalidate_package(package_name, version)
    log.info(
        "cache invalidate: package=%s version=%s removed=%d",
        package_name, version, removed,
    )
    return {"invalidated": removed, "package_name": package_name, "version": version}


@router.get("/audit", dependencies=[Depends(require_token)])
async def audit_query(
    last:    int            = Query(default=100, ge=1, le=1000, description="Maximum records to return"),
    verdict: Optional[str]  = Query(default=None, description="Filter by verdict: ALLOW, WARN, or BLOCK"),
    package: Optional[str]  = Query(default=None, description="Filter by package name (without version)"),
    since:   Optional[str]  = Query(default=None, description="Return only records newer than this ISO-8601 timestamp"),
) -> dict:
    """Return structured scan records from the audit log.

    Supports filtering by verdict, package name, and timestamp.  The newest
    matching records (up to *last*, max 1 000) are returned, oldest first.
    Auth required — the log contains project paths and package names.
    """
    if verdict and verdict not in ("ALLOW", "WARN", "BLOCK"):
        raise HTTPException(status_code=422, detail="verdict must be ALLOW, WARN, or BLOCK")
    events = await audit_log.read_records(last=last, verdict=verdict, package=package, since=since)
    log.debug("audit: returned %d records (filters: verdict=%s package=%s since=%s)", len(events), verdict, package, since)
    return {"events": events, "total": len(events)}


@router.get("/policy", dependencies=[Depends(require_token)])
async def policy_resolved(
    project_path: str = Query(..., description="Absolute path of the project to resolve policy for"),
) -> dict:
    """Return the merged policy for *project_path* and the source file path.

    Walks up from *project_path* looking for ``.cidas/policy.json`` (capped
    at ten levels), validates it, and merges its values over the per-user
    admin config.  ``policy_file`` is null when no project policy was found.
    """
    merged, source = policy.resolve(project_path)
    return {
        "project_path": project_path,
        "policy_file":  str(source) if source else None,
        "resolved":     merged,
    }


@router.post("/audit/override", dependencies=[Depends(require_token)])
async def audit_override(body: dict) -> dict:
    """Record a user 'Proceed Anyway' override event in the audit log.

    Called by the VS Code extension when the user proceeds past a WARN
    or BLOCK dialog.  The package name and version are required so the
    event can be correlated with the preceding scan record.

    Body fields
    -----------
    package_name : str            — npm package name (required)
    version      : str | null     — specific version, or null/absent for latest
    verdict_was  : str            — the verdict the user overrode (default "WARN")
    """
    package_name = body.get("package_name", "")
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required")
    version     = body.get("version") or None
    verdict_was = body.get("verdict_was", "WARN")
    event       = body.get("event", "user_override")
    record = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "event":       event,
        "package":     f"{package_name}@{version or 'latest'}",
        "verdict_was": verdict_was,
    }
    await audit_log.append(record)
    log.info("audit: %s for %s (verdict_was=%s)", event, record["package"], verdict_was)
    return {"logged": True, "package": record["package"], "event": event}
