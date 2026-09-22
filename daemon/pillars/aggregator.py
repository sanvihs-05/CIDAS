"""Aggregator pillar — weighted combination of pillar scores into a final verdict.

The ``aggregate`` method is intentionally a pure function of its inputs so
that it can be unit-tested without mocking any external services.

Weights are read from ``Settings`` at call time so that changing them in
``.env`` takes effect without restarting the daemon (call
``get_settings.cache_clear()`` to invalidate the cache).
"""
from __future__ import annotations

from ..config import Settings, get_admin_config
from ..models import PillarScore
from ..utils.logger import get_logger

log = get_logger(__name__)

# ── Contextify floor rule ─────────────────────────────────────────────────────
#
# A package whose embedding similarity to the project fingerprint is below this
# threshold is treated as "alien" — completely unrelated to anything the
# project already imports. Even with the rebalanced weights below, Contextify's
# compute_score caps at 25, which only contributes ~7.5 points at weight 0.30 —
# nowhere near the 40-point WARN threshold. The floor adds a flat additive
# penalty so a sufficiently alien package, combined with even modest Sentinel
# or Shield signals, lands in WARN territory rather than ALLOW. This closes the
# "clean-scripted, unique-named, off-topic dropper" hole where every other
# pillar is silent because the package has no obvious malware tells.
CONTEXTIFY_FLOOR_SIMILARITY: float = 0.05
CONTEXTIFY_FLOOR_PENALTY: float    = 20.0

# Admin override: per-machine Contextify weight clamp (read from
# ~/.cidas/config.json, key "contextify_weight"). Range is bounded so a
# misconfigured value cannot drown out Sentinel/Shield, which carry the
# concrete malware signals.
_CONTEXTIFY_WEIGHT_MIN: float = 0.0
_CONTEXTIFY_WEIGHT_MAX: float = 0.5


def _resolved_weights(
    settings: Settings,
    policy_overrides: dict | None = None,
) -> tuple[float, float, float]:
    """Return ``(context_w, sentinel_w, shield_w)`` after policy / admin override.

    Default weights have been rebalanced from 0.15/0.40/0.45 to 0.30/0.35/0.35
    (set in config.py): the old split made Contextify nearly inert — even at
    its max of 25 it contributed only 3.75 points, so a malicious package with
    a unique name (Sentinel quiet) and no install scripts (Shield quiet) would
    sail through as ALLOW regardless of how out-of-place it was. The new split
    keeps Sentinel+Shield collectively dominant (0.70) because they detect the
    most concrete signals, but lets Contextify actually move the needle.

    Override layers (highest priority first)
    ----------------------------------------
    1. ``policy_overrides`` — a project's ``.cidas/policy.json`` (already
       merged with admin config by ``utils.policy.resolve``).
    2. ``~/.cidas/config.json`` (admin per-machine config) — used when the
       caller passes ``policy_overrides=None``.
    3. Env-derived ``settings.context_weight`` etc.

    When ``contextify_weight`` is overridden, the remainder is split between
    Sentinel and Shield in the same ratio as their env-derived weights.
    """
    overrides = policy_overrides if policy_overrides is not None else get_admin_config()
    cfg_weight = overrides.get("contextify_weight")
    if cfg_weight is None:
        return settings.context_weight, settings.sentinel_weight, settings.shield_weight

    try:
        ctx_w = float(cfg_weight)
    except (TypeError, ValueError):
        log.warning("invalid contextify_weight in admin config: %r — ignoring", cfg_weight)
        return settings.context_weight, settings.sentinel_weight, settings.shield_weight

    if not _CONTEXTIFY_WEIGHT_MIN <= ctx_w <= _CONTEXTIFY_WEIGHT_MAX:
        log.warning(
            "contextify_weight=%s outside allowed range [%s, %s] — clamping",
            ctx_w, _CONTEXTIFY_WEIGHT_MIN, _CONTEXTIFY_WEIGHT_MAX,
        )
        ctx_w = max(_CONTEXTIFY_WEIGHT_MIN, min(_CONTEXTIFY_WEIGHT_MAX, ctx_w))

    remaining = 1.0 - ctx_w
    s_plus_h  = settings.sentinel_weight + settings.shield_weight
    if s_plus_h <= 0:
        # Defensive: split remainder evenly when env weights are degenerate.
        return ctx_w, remaining / 2.0, remaining / 2.0
    sen_w = remaining * (settings.sentinel_weight / s_plus_h)
    shi_w = remaining * (settings.shield_weight   / s_plus_h)
    return ctx_w, sen_w, shi_w


class Aggregator:
    """Pillar 4: compute the final weighted risk score and human-readable explanation."""

    def aggregate(
        self,
        contextify: PillarScore,
        sentinel: PillarScore,
        shield: PillarScore,
        settings: Settings,
        policy_overrides: dict | None = None,
    ) -> tuple[float, str]:
        """Return ``(risk_score, explanation)`` from the three pillar scores.

        risk_score is 0–100 (weighted sum capped at 100).
        explanation is a plain-English summary listing the top signal flags.
        ``policy_overrides`` is the merged project policy from
        ``utils.policy.resolve`` and takes precedence over admin config.

        Two-stage structure: Stage 2 (``_stage2_score``, the weighted pillar
        sum plus additive modifiers) always runs; Stage 1 (``_stage1_gates``,
        deterministic flag-driven force-floors) supplies an optional floor
        that Stage 2's result is combined with via ``max()``. This is the
        same behavior as a single sequential pass of ``max()`` calls — it's
        organized into named stages for clarity and so future signals (a
        learned classifier, homoglyph detection) have a clean place to plug
        into Stage 2 without diluting into a sum that force-rules already
        dominate (per the ablation study in the eval results).
        """
        stage2_score = self._stage2_score(contextify, sentinel, shield, settings, policy_overrides)
        gate_floor = self._stage1_gates(sentinel, shield, settings)
        score = stage2_score if gate_floor is None else max(stage2_score, gate_floor)

        explanation = self._build_explanation(score, contextify, sentinel, shield, settings)
        return score, explanation

    def _stage2_score(
        self,
        contextify: PillarScore,
        sentinel: PillarScore,
        shield: PillarScore,
        settings: Settings,
        policy_overrides: dict | None,
    ) -> float:
        """Weighted pillar sum plus the Contextify-floor and covert-dropper
        modifiers. Does not consider Stage 1's force-conditions."""
        ctx_w, sen_w, shi_w = _resolved_weights(settings, policy_overrides)
        score = (
            ctx_w * contextify.score
            + sen_w * sentinel.score
            + shi_w * shield.score
        )

        # Contextify floor: additive penalty for packages that are wholly
        # unrelated to the project, regardless of weight configuration.
        similarity = contextify.metadata.get("similarity") if contextify.metadata else None
        if isinstance(similarity, (int, float)) and similarity < CONTEXTIFY_FLOOR_SIMILARITY:
            score += CONTEXTIFY_FLOOR_PENALTY
            if "alien_to_project" not in contextify.flags:
                contextify.flags.append("alien_to_project")

        score = round(min(score, 100.0), 2)

        # Signal amplification: base64_decode co-occurring with unfamiliar_in_mature_project
        # is a strong indicator of a covert dropper — legitimate minified bundles don't also
        # look alien to the project's dependency graph. Add a flat penalty so the combination
        # escapes ALLOW even when each signal is individually weak.
        if (
            "base64_decode" in shield.flags
            and "unfamiliar_in_mature_project" in contextify.flags
        ):
            score = min(score + 15.0, 100.0)
            if "covert_dropper_signals" not in shield.flags:
                shield.flags.append("covert_dropper_signals")

        return score

    @staticmethod
    def _stage1_gates(sentinel: PillarScore, shield: PillarScore, settings: Settings) -> float | None:
        """Deterministic, flag-driven force-floors. Returns the threshold to
        floor the score at, or ``None`` if no gate fires.

        Priority (block-level checked before warn-level) mirrors the
        pre-refactor sequential ``max()`` calls; since
        ``block_threshold > warn_threshold`` the ordering is immaterial to
        the final composed score, but is kept for readability.
        """
        # A nonexistent package should always be blocked — it's either hallucinated or malicious.
        if "package_not_found" in sentinel.flags:
            return float(settings.block_threshold)

        # A known supply-chain incident should always be blocked.
        if "known_supply_chain_incident" in sentinel.flags:
            return float(settings.block_threshold)

        # A resolved version matching npm's "-security.N" placeholder
        # convention means npm's security team pulled this exact version as
        # malicious/reserved and republished an inert stub in its place —
        # installing it is pointless at best and dangerous at worst if any
        # tooling still has the original tarball cached. Always block.
        if "npm_security_placeholder_version" in sentinel.flags:
            return float(settings.block_threshold)

        # A detected typosquat must never silently ALLOW: Sentinel's weight
        # (0.35) alone caps its contribution at 35 points, below the WARN
        # threshold (40), so a typosquat with a quiet Contextify/Shield
        # signal (e.g. an evaluation harness with no real project_path)
        # would otherwise pass straight through. Floor at WARN rather than
        # forcing BLOCK, since name-similarity alone can still legitimately
        # false-positive on a similarly-named but unrelated real package.
        if "typosquat_detected" in sentinel.flags:
            return float(settings.warn_threshold)

        # Shield couldn't examine the actual requested version — its own
        # manifest/tarball is gone from the registry (e.g. npm purged it
        # after a compromise). That's not confirmed malicious on its own
        # (unlike a known incident or security placeholder), but "the exact
        # pinned version cannot be examined at all" is itself meaningful
        # enough to warrant caution rather than silently passing through
        # on whatever Contextify/Sentinel alone conclude.
        if "requested_version_unresolved" in shield.flags:
            return float(settings.warn_threshold)

        return None

    @staticmethod
    def get_decision(score: float, settings: Settings) -> str:
        """Map a numeric risk score to a decision string."""
        if score >= settings.block_threshold:
            return "BLOCK"
        if score >= settings.warn_threshold:
            return "WARN"
        return "ALLOW"

    def _build_explanation(
        self,
        score: float,
        contextify: PillarScore,
        sentinel: PillarScore,
        shield: PillarScore,
        settings: Settings,
    ) -> str:
        decision = self.get_decision(score, settings)
        all_flags = contextify.flags + sentinel.flags + shield.flags

        if not all_flags:
            if decision == "ALLOW":
                return f"Package passed all checks (risk score {score:.0f}/100)."
            return f"Package has a moderate risk score ({score:.0f}/100) but no specific flags were raised."

        top_flags = ", ".join(all_flags[:5])
        if decision == "BLOCK":
            return (
                f"Installation blocked (risk score {score:.0f}/100). "
                f"Top signals: {top_flags}."
            )
        if decision == "WARN":
            return (
                f"Proceed with caution (risk score {score:.0f}/100). "
                f"Signals detected: {top_flags}."
            )
        return (
            f"Package passed screening (risk score {score:.0f}/100). "
            f"Minor signals noted: {top_flags}."
        )
