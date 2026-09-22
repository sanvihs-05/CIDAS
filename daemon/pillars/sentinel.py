"""Sentinel pillar — registry reputation & AI hallucination detection.

When a package is ``ai_suggested`` the pillar runs a full hallucination-risk
check: does the package actually exist, how many downloads does it have, and
does its name suspiciously resemble a popular package?

When the package was typed by a human the hallucination check is skipped and
only basic typosquat detection is performed.

Steps
-----
1. If not ai_suggested → return low-risk PillarScore immediately.
2. ``check_registry_existence`` — download count, created date, repository.
3. ``check_name_similarity`` — edit distance against top-500 npm packages
   (bundled list).
4. ``compute_hallucination_risk`` — combine signals into a score.

TODO(phase-2): expand TOP_PACKAGES to a full top-500 list loaded from JSON.
TODO(phase-2): tune similarity thresholds based on false-positive data.
"""
from __future__ import annotations

import asyncio
import unicodedata
from datetime import datetime, timezone

from ..config import get_admin_config
from ..models import PillarScore
from ..utils.logger import get_logger
from ..utils.npm_registry import (
    RegistryLookup,
    get_download_count,
    get_package_metadata,
    is_security_placeholder_version,
)
from ..utils.osv_client import check_osv

log = get_logger(__name__)

# Packages with documented, public supply-chain compromise incidents.
# A hit here returns an immediate BLOCK-level score without further analysis.
# Only include packages where malware was *injected* (not just sabotaged or
# yanked) so the signal stays high-precision.
_KNOWN_COMPROMISED: dict[str, str] = {
    "flatmap-stream": "2018: backdoor via event-stream dependency (Bitcoin wallet theft)",
    "event-stream":   "2018: compromised via malicious flatmap-stream dependency",
    "node-ipc":       "2022: peacenotwar module (destructive file wipe on RU/BY IPs)",
    "ua-parser-js":   "2021: malware injection (cryptominer + password stealer)",
    "coa":            "2021: malware injection (cryptominer + password stealer)",
    "rc":             "2021: malware injection (cryptominer + password stealer)",
    "eslint-scope":   "2018: npm credentials theft via malicious postinstall",
}

# TODO(phase-2): replace with full top-500 list loaded from a bundled JSON file
TOP_PACKAGES: list[str] = [
    "react", "react-dom", "lodash", "express", "axios", "webpack", "babel-core",
    "typescript", "eslint", "prettier", "jest", "mocha", "chai", "chalk",
    "commander", "moment", "dayjs", "uuid", "dotenv", "cors", "body-parser",
    "mongoose", "sequelize", "socket.io", "next", "nuxt", "vue", "angular",
    "svelte", "tailwindcss", "postcss", "sass", "less", "nodemon", "ts-node",
    "cross-env", "rimraf", "concurrently", "husky", "lint-staged", "rollup",
    "vite", "esbuild", "turbopack", "jest-dom", "testing-library", "cypress",
    "playwright", "puppeteer", "cheerio", "got", "node-fetch", "undici",
]
_TYPO_THRESHOLD = 2

# ── Affix canonicalization ────────────────────────────────────────────────────
#
# Raw Levenshtein distance cannot catch affix squats ("node-react" is distance
# 5 from "react", far past any workable threshold) — this is a structurally
# separate signal: strip a known squat affix, then look for an *exact* match
# against TOP_PACKAGES. Affix hits still require reputation corroboration
# before escalating (see check_reputation_disparity) since some legitimate
# packages also carry these affixes (e.g. "node-sass" is a real, long-standing
# package, not a typosquat of "sass").
_AFFIX_PREFIXES: tuple[str, ...] = ("node-", "js-")
_AFFIX_SUFFIXES: tuple[str, ...] = ("-js", "-utils", "-util", "-helper", "-async", "-core", "-lib")

# ── Reputation-disparity thresholds ───────────────────────────────────────────
_REPUTATION_RATIO_THRESHOLD: float = 0.05  # candidate has <5% of target's downloads
_MATURE_AGE_DAYS: int = 365
_NEW_AGE_DAYS: int = 30

# ── Confusable-character normalization ─────────────────────────────────────────
#
# Scope is deliberately narrow: a small, hardcoded table of Cyrillic and Greek
# code points documented as used in real-world homoglyph package-name squats,
# not a full Unicode confusables.txt import — this keeps the mapping small and
# auditable at the cost of not covering every script. Anything outside this
# table (fullwidth Latin, other scripts) is an explicit out-of-scope gap for
# this pass, not a silent claim of full Unicode coverage.
_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
    # Greek -> Latin
    "ο": "o", "α": "a", "ρ": "p", "υ": "u",
    "Ο": "O", "Α": "A", "Ρ": "P", "Υ": "U",
}


def _normalize_confusables(name: str) -> str:
    """Map known Cyrillic/Greek confusable characters in *name* to their
    ASCII-skeleton Latin equivalent, then apply NFKC normalization for
    compatibility-equivalent forms. Characters outside _CONFUSABLE_MAP pass
    through unchanged. Must run before affix stripping / edit-distance
    comparison so a homoglyph-substituted name is compared on equal footing
    with its ASCII target.
    """
    mapped = "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in name)
    return unicodedata.normalize("NFKC", mapped)


def _strip_affixes(name: str) -> str:
    """Strip one leading squat prefix and one trailing squat suffix (lowercased)."""
    n = name.lower()
    for p in _AFFIX_PREFIXES:
        if n.startswith(p) and len(n) > len(p):
            n = n[len(p):]
            break
    for s in _AFFIX_SUFFIXES:
        if n.endswith(s) and len(n) > len(s):
            n = n[: -len(s)]
            break
    return n


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), curr[j] + 1, prev[j + 1] + 1))
        prev = curr
    return prev[-1]


class Sentinel:
    """Pillar 2: detect AI hallucinations and typosquats via registry signals."""

    async def score(
        self, package_name: str, ai_suggested: bool, version: str | None = None,
    ) -> PillarScore:
        """Return a PillarScore; always checks registry existence."""
        # Known-incident blocklist: synchronous dict lookup, no network call.
        # Applies to all installs (human or AI-suggested) because historical
        # supply-chain attacks are equally dangerous regardless of install origin.
        if package_name in _KNOWN_COMPROMISED:
            return PillarScore(
                score=95.0,
                confidence=0.99,
                flags=["known_supply_chain_incident"],
                metadata={
                    "incident": _KNOWN_COMPROMISED[package_name],
                    "ai_suggested": ai_suggested,
                },
            )

        # Always check if package exists - this catches hallucinated/fake packages
        exists, registry_signals = await self.check_registry_existence(package_name, version)

        # A resolved version matching npm's "-security.N" placeholder convention
        # means npm's security team pulled a malicious/reserved release and
        # republished an inert stub in its place — the tarball resolves (200 OK)
        # but installing it is either pointless or, if any tooling still has the
        # original malicious tarball cached, dangerous. Force a floor regardless
        # of typosquat status; this is root-caused separately from the general
        # tri-state registry fix (see plain-crypto-js investigation).
        if exists and registry_signals.get("npm_security_placeholder"):
            return PillarScore(
                score=95.0,
                confidence=0.9,
                flags=["npm_security_placeholder_version"],
                metadata={"ai_suggested": ai_suggested, "exists": True, **registry_signals},
            )

        normalized_name = _normalize_confusables(package_name)
        is_typo, similar_to = self.check_name_similarity(normalized_name)

        # A homoglyph-substituted name that normalizes to an *exact* skeleton
        # match of a popular package (e.g. Cyrillic "reаct" -> "react") is not
        # caught by check_name_similarity, which deliberately excludes
        # dist==0 (exact matches are legitimate re-installs, not typos) — but
        # here the *raw* string differs from the popular package while its
        # normalized skeleton is identical, which is itself the homoglyph
        # attack signal.
        is_homoglyph_typo = False
        homoglyph_similar_to = ""
        if normalized_name.lower() != package_name.lower():
            for popular in TOP_PACKAGES:
                if normalized_name.lower() == popular.lower():
                    is_homoglyph_typo = True
                    homoglyph_similar_to = popular
                    break

        admin_cfg = get_admin_config()
        affix_on = admin_cfg.get("typosquat_affix_canonicalization", True) is not False
        is_affix_typo, affix_similar_to = self.check_affix_similarity(normalized_name) if affix_on else (False, "")
        raw_hit = is_typo or is_affix_typo or is_homoglyph_typo
        matched_target = similar_to or affix_similar_to or homoglyph_similar_to

        # A raw-distance or affix name-similarity hit only escalates to a
        # forced BLOCK-level score once corroborated by a reputation
        # disparity vs. the matched target — otherwise short/legitimate
        # names collide by coincidence (e.g. "vue" vs "vite"). Disabling
        # typosquat_reputation_corroboration reverts to the pre-corroboration
        # behavior: any raw-distance hit forces score=100 unconditionally.
        corroboration_on = admin_cfg.get("typosquat_reputation_corroboration", True) is not False

        corroborated = False
        corr_info: dict = {}
        if raw_hit:
            if not corroboration_on:
                corroborated, corr_info = True, {"fallback": True}
            else:
                candidate_signals = registry_signals if exists else {"monthly_downloads": 0, "age_days": None}
                corroborated, corr_info = await self.check_reputation_disparity(
                    package_name, matched_target, candidate_signals,
                )

        # If package doesn't exist, always flag it regardless of ai_suggested
        if not exists:
            if registry_signals.get("registry_status") == "undetermined":
                # Fail open: a registry timeout/transport/non-404 error is not
                # evidence the package doesn't exist — it must NOT set
                # "package_not_found" (the flag the aggregator's Stage-1 gate
                # keys off to floor risk at BLOCK), or a transient outage would
                # force-block real, popular packages (the redux-thunk/
                # nodemailer false-positive pattern this fixes).
                flags = ["registry_lookup_undetermined"]
                if is_affix_typo:
                    flags.append("typosquat_affix_match")
                if is_homoglyph_typo:
                    flags.append("typosquat_homoglyph_match")
                if raw_hit and corroborated:
                    flags.append("typosquat_detected")
                    if not corr_info.get("fallback"):
                        flags.append("reputation_disparity_confirmed")
                elif raw_hit:
                    flags.append("typosquat_name_similarity_uncorroborated")
                return PillarScore(
                    score=15.0,
                    confidence=0.3,
                    flags=flags,
                    metadata={
                        "similar_to": similar_to, "affix_similar_to": affix_similar_to,
                        "ai_suggested": ai_suggested, "exists": False,
                        **{k: v for k, v in corr_info.items() if k != "fallback"},
                        **registry_signals,
                    },
                )
            score = 85.0  # High risk for confirmed non-existent packages
            flags = ["package_not_found"]
            if is_affix_typo:
                flags.append("typosquat_affix_match")
            if is_homoglyph_typo:
                flags.append("typosquat_homoglyph_match")
            if raw_hit and corroborated:
                flags.append("typosquat_detected")
                if not corr_info.get("fallback"):
                    flags.append("reputation_disparity_confirmed")
                # A typosquat name that isn't even registered yet is at least as
                # dangerous as one that already exists (score=100 below) — the
                # attacker has staged the name but not yet published, or the
                # target simply doesn't exist. Never score this lower than an
                # existing typosquat.
                score = 100.0
            elif raw_hit:
                flags.append("typosquat_name_similarity_uncorroborated")
            return PillarScore(
                score=score,
                confidence=0.95,
                flags=flags,
                metadata={
                    "similar_to": similar_to, "affix_similar_to": affix_similar_to,
                    "ai_suggested": ai_suggested, "exists": False,
                    **{k: v for k, v in corr_info.items() if k != "fallback"},
                },
            )

        # Package exists - a corroborated typosquat hit forces the max score.
        if raw_hit and corroborated:
            flags = ["typosquat_detected"]
            if is_affix_typo:
                flags.append("typosquat_affix_match")
            if is_homoglyph_typo:
                flags.append("typosquat_homoglyph_match")
            if not corr_info.get("fallback"):
                flags.append("reputation_disparity_confirmed")
            return PillarScore(
                score=100.0,
                confidence=0.8,
                flags=flags,
                metadata={
                    "similar_to": similar_to, "affix_similar_to": affix_similar_to,
                    "ai_suggested": ai_suggested, "exists": True,
                    **{k: v for k, v in corr_info.items() if k != "fallback"},
                },
            )

        # A name-similarity hit that failed corroboration still surfaces as a
        # (non-forcing) flag through whichever scoring path runs below.
        uncorroborated_flags = ["typosquat_name_similarity_uncorroborated"] if raw_hit else []

        # For non-AI suggested packages that exist and aren't a corroborated typosquat, do basic checks
        if not ai_suggested:
            flags = list(uncorroborated_flags)
            score = 0.0
            monthly_dl = registry_signals.get("monthly_downloads", 0)
            if monthly_dl == 0:
                flags.append("zero_downloads")
                score += 20.0
            elif monthly_dl < 100:
                flags.append("very_low_downloads")
                score += 10.0
            if not registry_signals.get("has_repository"):
                flags.append("no_repository")
                score += 10.0
            return PillarScore(
                score=score,
                confidence=0.9,
                flags=flags,
                metadata={"ai_suggested": False, "exists": True, "hallucination_check": "skipped", **registry_signals},
            )

        # Full hallucination-risk analysis for AI-suggested packages
        exists, registry_signals = await self.check_registry_existence(package_name, version)
        is_typo, similar_to = self.check_name_similarity(normalized_name)
        final_score, flags = self.compute_hallucination_risk(
            exists, registry_signals, is_typo, similar_to
        )
        flags = uncorroborated_flags + flags

        # OSV vulnerability check — only for AI-suggested packages to avoid
        # adding a live network call to the human-typed fast path.
        osv = await check_osv(package_name)
        if osv["has_malware"]:
            # Confirmed malware (MAL- entry or unambiguous keyword) overrides all
            # other signals — the package is definitively dangerous.
            flags.append("osv_advisory_found")
            flags.append("osv_malware_confirmed")
            final_score = 100.0
        elif osv["vuln_count"] > 0:
            flags.append("osv_advisory_found")
            final_score = min(final_score + 20.0, 100.0)

        return PillarScore(
            score=final_score,
            confidence=0.85,
            flags=flags,
            metadata={
                "ai_suggested": True,
                "exists": exists,
                "similar_to": similar_to,
                "osv_vuln_count": osv["vuln_count"],
                "osv_vuln_ids": osv["vuln_ids"],
                **registry_signals,
            },
        )

    async def check_registry_existence(
        self, package_name: str, version: str | None = None,
    ) -> tuple[bool, dict]:
        """Check NPM registry for package existence, age, and download count.

        Distinguishes a confirmed-absent package (a real HTTP 404 — the
        appropriate trigger for the "package_not_found" BLOCK-floor gate)
        from an undetermined lookup (registry timeout/transport/non-404
        error) — the latter must fail open rather than being treated as
        equivalent to confirmed absence. This distinction, and the
        confirmatory-retry-before-declaring-absent policy, now live in
        ``npm_registry.get_package_metadata(..., confirm_absence=True)``.
        """
        signals: dict = {}
        result = await get_package_metadata(package_name, confirm_absence=True)
        if result.status is RegistryLookup.CONFIRMED_ABSENT:
            return False, {"registry_status": "confirmed_absent"}
        if result.status is RegistryLookup.UNDETERMINED:
            return False, {"registry_status": "undetermined", "registry_miss": True}
        meta = result.data or {}

        # npm security-placeholder version check (see score()'s consumption
        # of this signal for the rationale). When npm's security team pulls
        # a malicious release, it can wipe the *entire* versions map down to
        # a single placeholder (e.g. "0.0.1-security.0") — so a pinned
        # install request for the original malicious version (e.g. "4.2.1")
        # no longer resolves in `meta["versions"]` at all, and the only
        # signal left is dist-tags.latest itself being the placeholder.
        # Checking only the resolved/requested version string (as this used
        # to) misses exactly that case — the requested version is real
        # ("4.2.1"), it's the registry's *current* state that flags it.
        latest_tag = (meta.get("dist-tags") or {}).get("latest") or ""
        resolved_version = version or latest_tag
        if (
            (resolved_version and is_security_placeholder_version(resolved_version))
            or (latest_tag and is_security_placeholder_version(latest_tag))
        ):
            signals["npm_security_placeholder"] = True

        # Age signal
        created_str = meta.get("time", {}).get("created", "")
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                signals["age_days"] = age_days
            except ValueError:
                signals["age_days"] = None

        # Download count signal
        try:
            downloads = await get_download_count(package_name)
            signals["monthly_downloads"] = downloads
        except Exception:
            signals["monthly_downloads"] = 0

        # Repository presence
        signals["has_repository"] = bool(meta.get("repository"))
        signals["maintainer_count"] = len(meta.get("maintainers", []))
        signals["registry_status"] = "exists"

        return True, signals

    def check_name_similarity(self, package_name: str) -> tuple[bool, str]:
        """Return (is_typosquat, similar_to) using edit distance against TOP_PACKAGES."""
        for popular in TOP_PACKAGES:
            dist = _levenshtein(package_name.lower(), popular.lower())
            if 0 < dist <= _TYPO_THRESHOLD:
                return True, popular
        return False, ""

    def check_affix_similarity(self, package_name: str) -> tuple[bool, str]:
        """Return (is_affix_typosquat, similar_to) — exact match against
        TOP_PACKAGES after stripping a known squat affix (e.g. "node-react"
        -> "react"). Distinct from check_name_similarity's raw edit-distance
        signal, since affix squats are often far past any workable
        Levenshtein threshold. Still requires reputation corroboration
        before escalating — some legitimate packages carry these affixes
        too (e.g. "node-sass").
        """
        canonical = _strip_affixes(package_name)
        if canonical == package_name.lower():
            return False, ""  # no affix was actually stripped
        for popular in TOP_PACKAGES:
            if canonical == popular.lower():
                return True, popular
        return False, ""

    async def check_reputation_disparity(
        self, candidate_name: str, target_name: str, candidate_signals: dict,
    ) -> tuple[bool, dict]:
        """Return (disparity_confirmed, info) for a name-similarity hit.

        A raw or affix name-similarity match alone isn't enough to force a
        BLOCK-level score — short/legitimate names collide by coincidence
        (e.g. "vue" vs "vite"). Disparity is confirmed when the candidate
        shows a large download-count gap vs. the matched target, or is very
        new while the target is long-established.

        Fails toward flagging, not suppression: if the target lookup itself
        fails (network error, confirmed-absent target), returns
        ``(True, {"fallback": True})`` so a corroboration-check outage never
        silently downgrades the pre-existing force-to-100 behavior.
        """
        try:
            target_result, target_downloads = await asyncio.gather(
                get_package_metadata(target_name), get_download_count(target_name),
            )
        except Exception as exc:
            log.debug("reputation lookup failed for target %r (candidate %r): %s",
                      target_name, candidate_name, exc)
            return True, {"fallback": True}
        if target_result.status is not RegistryLookup.EXISTS or target_result.data is None:
            log.debug("target %r not found while corroborating candidate %r",
                      target_name, candidate_name)
            return True, {"fallback": True}
        target_meta = target_result.data

        candidate_downloads = candidate_signals.get("monthly_downloads", 0) or 0
        ratio = candidate_downloads / target_downloads if target_downloads > 0 else 0.0
        disparity_by_downloads = target_downloads > 0 and ratio < _REPUTATION_RATIO_THRESHOLD

        candidate_age = candidate_signals.get("age_days")
        target_created = target_meta.get("time", {}).get("created", "")
        target_age: int | None = None
        if target_created:
            try:
                target_age = (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(target_created.replace("Z", "+00:00"))
                ).days
            except ValueError:
                target_age = None
        disparity_by_age = (
            isinstance(candidate_age, int) and candidate_age < _NEW_AGE_DAYS
            and isinstance(target_age, int) and target_age > _MATURE_AGE_DAYS
        )

        confirmed = disparity_by_downloads or disparity_by_age
        return confirmed, {
            "target_downloads": target_downloads,
            "download_ratio": round(ratio, 4),
            "target_age_days": target_age,
            "fallback": False,
        }

    def compute_hallucination_risk(
        self,
        exists: bool,
        signals: dict,
        is_typo: bool,
        similar_to: str,
    ) -> tuple[float, list[str]]:
        """Combine registry signals into a risk score."""
        score = 0.0
        flags: list[str] = []

        if not exists:
            flags.append("package_not_found")
            score += 70.0
            if is_typo:
                flags.append("typosquat_detected")
                score += 15.0
            return min(score, 100.0), flags

        if is_typo:
            flags.append("typosquat_detected")
            score += 40.0

        age_days = signals.get("age_days")
        if isinstance(age_days, int):
            if age_days < 7:
                flags.append("very_new_package")
                score += 35.0
            elif age_days < 30:
                flags.append("new_package")
                score += 15.0

        monthly_dl = signals.get("monthly_downloads", 0)
        if monthly_dl == 0:
            flags.append("zero_downloads")
            score += 20.0
        elif monthly_dl < 100:
            flags.append("very_low_downloads")
            score += 10.0

        if not signals.get("has_repository"):
            flags.append("no_repository")
            score += 10.0

        return min(score, 100.0), flags
