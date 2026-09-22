"""Configuration module for the CIDAS daemon.

Reads all settings from environment variables / .env file using pydantic-settings.
Import the singleton via ``get_settings()`` rather than instantiating Settings directly
to avoid re-loading the .env file on every access.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration for the CIDAS daemon.

    Each field maps directly to an environment variable of the same name
    (case-insensitive).  Defaults match the values in .env.example.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Daemon ────────────────────────────────────────────────────────────
    daemon_host: str = "127.0.0.1"
    daemon_port: int = 7355
    log_level: str = Field(default="info", description="debug | info | warning | error")

    # ── Scoring thresholds ────────────────────────────────────────────────
    block_threshold: int = Field(default=80, ge=1, le=100)
    warn_threshold: int = Field(default=40, ge=1, le=100)

    # ── Pillar weights (must sum to ~1.0) ─────────────────────────────────
    # Rebalanced from 0.15/0.40/0.45: the old Contextify weight was too low to
    # catch a clean-scripted, unique-named, off-topic package — see
    # daemon/pillars/aggregator.py for the full rationale. Admins can override
    # context_weight per-machine via ~/.cidas/config.json (key "contextify_weight").
    context_weight: float = Field(default=0.30, ge=0.0, le=1.0)
    sentinel_weight: float = Field(default=0.35, ge=0.0, le=1.0)
    shield_weight: float = Field(default=0.35, ge=0.0, le=1.0)

    # ── Embeddings ────────────────────────────────────────────────────────
    embedding_model: str = "all-MiniLM-L6-v2"
    chroma_persist_dir: str = ".cidas_chroma"

    # ── SQLite cache ──────────────────────────────────────────────────────
    sqlite_db_path: str = ".cidas_cache.db"

    # ── NPM registry ──────────────────────────────────────────────────────
    npm_registry_url: str = "https://registry.npmjs.org"

    # ── Disk space checking ───────────────────────────────────────────────
    # When True the daemon estimates the on-disk cost of a requested install
    # (top-level package + transitive deps) and surfaces the result in the
    # ScanResponse.disk_footprint field.  Disable on constrained CI runners
    # that should not make extra npm-registry size lookups.
    disk_check_enabled: bool = True

    # ── LLM secondary verification ────────────────────────────────────────
    # Optional second-pass check that asks a local Ollama model to evaluate
    # README text the regex flagged as possibly adversarial. Off by default
    # because it requires Ollama to be installed and running on the host.
    # No API key needed — calls are local. The Shield pillar reads these
    # via get_settings() at score() time, so changing the env vars and
    # restarting the daemon is enough — no code change required to enable.
    llm_verification_enabled: bool = False
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "phi3:mini"

    # ── Concept drift monitoring ──────────────────────────────────────────────
    drift_monitoring_enabled: bool = True
    drift_kl_warn_threshold: float = 0.15
    drift_kl_alert_threshold: float = 0.30


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton Settings instance.

    The instance is created once on first call and reused for the lifetime of
    the process.  Call ``get_settings.cache_clear()`` in tests to reset.
    """
    return Settings()


def get_admin_config() -> dict:
    """Read ~/.cidas/config.json and return the parsed object.

    Returns an empty dict when the file does not exist or contains invalid JSON.
    This file is controlled by the system administrator (not env vars) and is
    used for settings that must survive across dev-environment resets, such as
    ``bypass_disabled: true`` for CI enforcement.

    Supported keys
    --------------
    bypass_disabled : bool
        When true the npm shim refuses CIDAS_BYPASS=1 and exits with code 1.
    package_file_scan : bool (default true)
        When false, Shield skips downloading and extracting the package
        tarball — useful on slow connections or air-gapped CI runners.
        Lifecycle-script and README scans still run.
    contextify_weight : float (0.0–0.5)
        Per-machine override for the Contextify pillar weight. Useful for
        projects that legitimately mix domains (e.g. ML + web + tooling) where
        a low Contextify weight reduces nuisance "alien_to_project" hits.
        Out-of-range values are clamped; non-numeric values are ignored.
    shield_manifest_gating : bool (default true)
        When true, Shield skips the cross-version tarball diff whenever the
        current and immediately-preceding version's `scripts` and
        `dependencies` fields are identical — this is the dominant source of
        Shield's tail latency (two full tarball downloads per scan). Set to
        false to force every version-having package through the full diff
        regardless of manifest equality, e.g. while validating that gating
        isn't suppressing a real detection.
    typosquat_affix_canonicalization : bool (default true)
        When true, Sentinel additionally strips common squat affixes
        (node-, js- prefixes; -js, -util(s), -helper, -async, -core, -lib
        suffixes) before comparing against TOP_PACKAGES, catching names like
        "node-react" that raw Levenshtein distance misses entirely. Surfaces
        as the "typosquat_affix_match" flag, independent of the raw-distance
        "typosquat_detected" signal. When false, only raw Levenshtein
        distance is checked (pre-Feature-1 behavior).
    typosquat_reputation_corroboration : bool (default true)
        When true, a raw-Levenshtein or affix-canonicalization typosquat hit
        only escalates to a forced score=100 ("typosquat_detected") if the
        candidate also shows a reputation disparity vs. the matched popular
        package (far fewer downloads, or new where the target is mature).
        Prevents false positives between short, legitimately-unrelated names
        (e.g. "vue" vs "vite"). When false, reverts to the pre-corroboration
        behavior: any name-similarity hit forces score=100 unconditionally.
        If the target package's own registry/download lookup fails, the
        corroboration check fails toward flagging (treats it as corroborated)
        rather than silently suppressing — see Sentinel.check_reputation_disparity.
    """
    config_path = Path.home() / ".cidas" / "config.json"
    try:
        return json.loads(config_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
