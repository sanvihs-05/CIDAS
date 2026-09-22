"""Pydantic models shared between the router, pillars, and database layers.

Keeping all external-facing request/response shapes in one module ensures
pillar implementations and the router stay in sync automatically.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


# ── Request ───────────────────────────────────────────────────────────────────

class PackageScanRequest(BaseModel):
    """Payload sent by the npm shim or VS Code extension to POST /scan."""

    package_name: str = Field(..., description="npm package name (no version suffix)")
    version: Optional[str] = Field(None, description="Specific version; None = latest")
    project_path: str = Field(..., description="Absolute path of the project root")
    ai_suggested: bool = Field(
        default=False,
        description="True when the package was suggested by an LLM/Copilot",
    )
    requesting_tool: Optional[str] = Field(
        None,
        description="Identifier of the calling tool, e.g. 'npm-shim' or 'vscode-extension'",
    )
    scan_transitive: bool = Field(
        default=False,
        description="When True, resolve and screen transitive dependencies (Sentinel only)",
    )


# ── Pillar output ─────────────────────────────────────────────────────────────

class PillarScore(BaseModel):
    """Risk contribution from a single analysis pillar."""

    score: float = Field(..., ge=0.0, le=100.0, description="Risk 0–100 (higher = riskier)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the score")
    flags: list[str] = Field(default_factory=list, description="Human-readable signal labels")
    metadata: dict = Field(default_factory=dict, description="Raw signals for debugging")


# ── Transitive dep result ─────────────────────────────────────────────────────

class DirectDependency(BaseModel):
    """A single direct dependency declared in the package's package.json."""

    name: str
    version_range: str = Field(..., description="Version range as declared (e.g. '^1.2.3')")


class TransitiveDependencyResult(BaseModel):
    """Sentinel screening result for a single transitive dependency."""

    name: str
    version: str
    depth: int = Field(..., ge=1, description="How many hops from the root package")
    sentinel_score: float = Field(..., ge=0.0, le=100.0)
    flags: list[str] = Field(default_factory=list)


# ── Disk footprint ────────────────────────────────────────────────────────────

class DiskFootprint(BaseModel):
    """Estimated disk cost for installing a package plus its transitive deps."""

    estimated_install_bytes: int = 0
    estimated_install_mb: float = 0.0
    available_disk_bytes: int = 0
    available_disk_mb: float = 0.0
    node_modules_bytes: int = 0
    dep_count: int = 0
    will_fit: bool = True
    flags: list[str] = []
    disk_risk_score: float = 0.0


# ── Scan response ─────────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """Complete screening result returned to the caller."""

    package_name: str
    version: Optional[str]
    decision: Literal["ALLOW", "WARN", "BLOCK"]
    risk_score: float = Field(..., ge=0.0, le=100.0)
    contextify: PillarScore
    sentinel: PillarScore
    shield: PillarScore
    direct_dependencies: list[DirectDependency] = Field(
        default_factory=list,
        description="Direct dependencies declared in the package's package.json",
    )
    alternatives: list[str] = Field(default_factory=list, description="Safer package suggestions")
    explanation: str = Field(default="", description="Human-readable summary of the decision")
    latency_ms: float = Field(default=0.0, description="Total scan duration in milliseconds")
    tarball_url: Optional[str] = Field(
        default=None, description="The dist.tarball URL that Shield's file scan downloaded",
    )
    file_scan_summary: Optional[dict] = Field(
        default=None,
        description="Shield file-scan stats: files_scanned, flags, skipped (or None when no scan ran)",
    )
    trust_flags: list[str] = Field(
        default_factory=list,
        description=(
            "Trust-integrity signals: 'trust_tamper_detected' when a trust-list row HMAC "
            "mismatches, 'trust_legacy_no_mac' when the row predates integrity protection."
        ),
    )
    policy_file: Optional[str] = Field(
        default=None,
        description=(
            "Absolute path of the .cidas/policy.json file that was applied to this scan, "
            "or null when no project policy was discovered."
        ),
    )
    requires_confirmation: bool = Field(
        default=False,
        description=(
            "When true, the npm shim must prompt the developer to type 'proceed' "
            "before a WARN install continues.  Set by the daemon when the resolved "
            "policy has warn_requires_confirmation: true."
        ),
    )
    transitive_risks: list[TransitiveDependencyResult] = Field(
        default_factory=list,
        description="Sentinel results for transitive dependencies (populated when scan_transitive=True)",
    )
    transitive_risk_detected: bool = Field(
        default=False,
        description="True when any transitive dependency sentinel_score >= WARN_THRESHOLD",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Top-level scan flags (e.g. 'insufficient_disk_space').",
    )
    disk_footprint: Optional[DiskFootprint] = Field(
        default=None,
        description="Estimated disk cost for this installation, or null when disk check is disabled.",
    )


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
