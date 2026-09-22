"""Shield pillar — malicious-pattern detection and vulnerability scanning.

Steps
-----
1. ``fetch_install_scripts`` — retrieve lifecycle scripts from the npm
   registry tarball metadata.
2. ``primary_scan`` — pattern-based detection: obfuscation, network calls in
   install scripts, env variable exfiltration patterns.
3. ``secondary_verification`` — TODO: second LLM call for adversarial prompt
   injection detection in package description/README.
4. ``detect_injection_patterns`` — regex scan for known prompt injection phrases.

TODO(phase-2): integrate secondary_verification with a local LLM model for
adversarial README/description scanning.
TODO(phase-2): pull tarball and scan extracted JS for obfuscated payloads.
"""
from __future__ import annotations

import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from ..config import get_admin_config, get_settings
from ..models import PillarScore
from ..utils.llm_verifier import verify_with_llm
from ..utils.logger import get_logger
from ..utils.npm_registry import (
    RegistryLookup,
    download_tarball,
    get_package_metadata,
    get_package_tarball_info,
    tarball_has_member,
)

log = get_logger(__name__)

# ── Lifecycle script patterns ─────────────────────────────────────────────────
_SCRIPT_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("network_in_install",  re.compile(r"\b(?:curl|wget|fetch|http\.get|axios\.get)\b"),   25.0),
    ("eval_usage",          re.compile(r"\beval\s*\("),                                      30.0),
    ("base64_decode",       re.compile(r"(?:Buffer\.from|atob|base64_decode)\s*\("),         20.0),
    ("env_exfil",           re.compile(r"process\.env\b.*(?:TOKEN|SECRET|KEY|PASS)",
                                        re.IGNORECASE),                                      35.0),
    ("child_process_exec",  re.compile(r"(?:exec|execSync|spawn)\s*\("),                     15.0),
    ("crypto_miner",        re.compile(r"(?:coinhive|cryptonight|stratum\+tcp)",
                                        re.IGNORECASE),                                      50.0),
    ("obfuscation",         re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:0x[0-9a-fA-F]+,){5,}"), 30.0),
]

_LIFECYCLE_HOOKS = {"preinstall", "install", "postinstall", "prepare"}


def _scripts_and_deps_equal(current_manifest: dict, prev_manifest: dict) -> bool:
    """True when two version manifests declare identical scripts and dependencies.

    Used to gate the cross-version tarball diff: if neither field changed
    between the current and immediately-preceding version, there is no
    lifecycle-script or declared-dependency change to explain, so the
    (expensive) capability diff can be skipped for this pair.
    """
    return (
        (current_manifest.get("scripts") or {}) == (prev_manifest.get("scripts") or {})
        and (current_manifest.get("dependencies") or {}) == (prev_manifest.get("dependencies") or {})
    )


# ── Native-build auto-execution trigger files ─────────────────────────────────
#
# npm's install step auto-runs `node-gyp rebuild` whenever a `binding.gyp` is
# present, independent of any `scripts` entry in package.json — the "Phantom
# Gyp" campaign (StepSecurity/Wiz/Endor Labs, June 2026) added exactly this
# file with no package.json change at all, evading manifest-first gating
# entirely since that gate only compares scripts/dependencies. Treated as
# equivalent to a lifecycle-script change: any presence transition forces the
# full historical diff.
#
# Explicitly OUT OF SCOPE for this check (see docs/threat-model.md):
#   - .node-gyp build-cache poisoning — no file-presence signal to check for.
#   - prebuild-install / node-pre-gyp fetching prebuilt binaries from an
#     arbitrary URL at install time — a content-level check, not a
#     presence-level one; named as future work rather than silently uncovered.
#   - Custom install.js-driven native builds — already covered, since those
#     are invoked via a `scripts` entry and so already trip
#     _scripts_and_deps_equal.
_NATIVE_BUILD_TRIGGER_FILES: frozenset[str] = frozenset({"binding.gyp"})


async def _native_trigger_transition(
    cur_manifest: dict, prev_manifest: dict,
) -> bool:
    """True if a native-build auto-exec trigger file's presence differs
    between *cur_manifest* and *prev_manifest*'s tarballs (added, removed, or
    undeterminable). Fail-closed: any undetermined listing check (network
    hiccup, cap exceeded, missing dist.tarball) is treated as "changed" so
    this optimization never silently trusts an ambiguous read.
    """
    cur_url = (cur_manifest.get("dist") or {}).get("tarball")
    prev_url = (prev_manifest.get("dist") or {}).get("tarball")
    if not cur_url or not prev_url:
        return True
    cur_has = await tarball_has_member(cur_url, _NATIVE_BUILD_TRIGGER_FILES)
    if cur_has is None:
        return True
    prev_has = await tarball_has_member(prev_url, _NATIVE_BUILD_TRIGGER_FILES)
    if prev_has is None:
        return True
    return cur_has != prev_has


# ── File-scan parameters ──────────────────────────────────────────────────────
#
# File-scan findings are weighted lower than lifecycle-script findings because:
#   1. Legitimate minified/bundled JS contains many of the same regex hits
#      (eval, Buffer.from, hex escapes) without being malicious.
#   2. Lifecycle scripts execute unconditionally on install, while a flagged
#      pattern in a .js file only runs if the package is actually required.
# 0.6 keeps the signal meaningful (a real malware payload still trips multiple
# patterns and clears the WARN threshold) while halving the false-positive
# weight on minified bundles.
FILE_SCAN_WEIGHT: float = 0.6
_FILE_SCAN_MAX_FILES: int = 50
_FILE_SCAN_MAX_BYTES: int = 200 * 1024  # 200 KB per file

# Require()-time patterns — checked in addition to _SCRIPT_PATTERNS for any
# .js file inside the tarball. These target code that runs at import time
# rather than at install time.
_DNS_REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]dns['"]\s*\)""")
# Subdomain longer than 12 chars built from the alphabet attackers use for
# encoded payloads (lower/upper alnum). Excludes hyphens to skip benign
# hostnames like "long-but-readable-name.example.com".
_LONG_SUBDOMAIN_RE = re.compile(r"\b[A-Za-z0-9]{13,}\.[A-Za-z0-9.-]+\.[a-z]{2,}\b")
_PROCESS_ENV_RE   = re.compile(r"process\.env\.[A-Z_]{4,}")
_HTTP_FETCH_RE    = re.compile(r"\b(?:fetch|https?\.(?:get|request)|axios\.(?:get|post))\s*\(")
# Hex escape density — separate from the lifecycle-script "obfuscation" rule
# which fires only on contiguous runs. A file-wide >5 per 100 chars density
# catches payloads that interleave hex escapes with normal code.
_HEX_ESCAPE_RE    = re.compile(r"\\x[0-9a-fA-F]{2}")
_HEX_DENSITY_THRESHOLD: float = 5.0 / 100.0  # >5 hex escapes per 100 chars

# Per-finding scores for the require()-time pattern set. Tuned so that any
# single hit alone cannot push the file-scan total past ~30 (well below
# WARN), but two or three hits together cross the threshold.
_REQUIRE_TIME_SCORES: dict[str, float] = {
    "env_exfil_near_http":   30.0,
    "dns_long_subdomain":    35.0,
    "hex_density":           25.0,
}

# ── AST analysis ──────────────────────────────────────────────────────────────
#
# Regex catches the easy cases; the AST pass catches obfuscation that's
# trivial to write but expensive to encode as regex: bracket-notation
# property access, computed keys, destructuring, `const e = eval`, and so
# on. The parser is lazy-loaded so the module still imports when the
# tree-sitter-javascript wheel isn't installed in the local environment.
_AST_PATTERN_SCORES: dict[str, float] = {
    "ast_process_env":        35.0,
    "ast_network_call":       20.0,
    "ast_eval_or_function":   25.0,
    "ast_dangerous_require":  25.0,
    "ast_base64_decode":      15.0,
    "parse_failed":            0.0,
}

_AST_NETWORK_NAMES = {"fetch", "XMLHttpRequest"}
_AST_NETWORK_METHODS = {"request"}  # http.request / https.request
_AST_DANGEROUS_MODULES = {"dns", "child_process", "http", "https", "node-fetch"}
_AST_NETWORK_MODULES = {"http", "https", "node-fetch"}

_ts_parser = None         # lazy singleton tree_sitter.Parser
_ts_load_failed = False   # set True once we've decided the binding is unusable


def _get_js_parser():
    """Return a cached tree-sitter JS Parser, or None if unavailable."""
    global _ts_parser, _ts_load_failed
    if _ts_parser is not None or _ts_load_failed:
        return _ts_parser
    try:
        import tree_sitter_javascript  # type: ignore[import-not-found]
        from tree_sitter import Language, Parser  # type: ignore[import-not-found]
        _ts_parser = Parser(Language(tree_sitter_javascript.language()))
    except Exception as exc:  # ImportError or binding mismatch
        log.debug("tree-sitter-javascript unavailable: %s", exc)
        _ts_load_failed = True
        _ts_parser = None
    return _ts_parser


def _walk_ts(node):
    """Pre-order generator over every node in a tree-sitter tree."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _node_text(node) -> str:
    """Decode a node's source slice. Returns '' on decode failure."""
    if node is None:
        return ""
    try:
        return node.text.decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return ""


def _is_identifier_named(node, name: str) -> bool:
    return node is not None and node.type == "identifier" and _node_text(node) == name


_JS_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_JS_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decode_js_escapes(s: str) -> str:
    """Best-effort decode of \\x.. and \\u.... escapes used to hide 'env' etc."""
    s = _JS_HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = _JS_UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), s)
    return s


def _is_process_env(node) -> bool:
    """True if *node* evaluates to process.env (dot or bracket form)."""
    if node is None:
        return False
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        return _is_identifier_named(obj, "process") and prop is not None \
            and prop.type == "property_identifier" and _node_text(prop) == "env"
    if node.type == "subscript_expression":
        obj = node.child_by_field_name("object")
        idx = node.child_by_field_name("index")
        if not _is_identifier_named(obj, "process") or idx is None:
            return False
        raw = _node_text(idx).strip("\"'`")
        return raw == "env" or _decode_js_escapes(raw) == "env"
    return False


def _require_argument_module(node) -> str | None:
    """If *node* is ``require('x')``, return ``'x'`` (escapes decoded). Else None."""
    if node is None or node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if not _is_identifier_named(fn, "require"):
        return None
    args = node.child_by_field_name("arguments")
    if args is None:
        return None
    for child in args.children:
        if child.type == "string":
            return _decode_js_escapes(_node_text(child).strip("\"'`"))
        if child.type == "template_string":
            inner = _node_text(child).strip("`")
            if "${" in inner:
                return None
            return _decode_js_escapes(inner)
    return None


def _classify_node(node) -> str | None:  # noqa: PLR0911
    """Return an AST-pattern label for *node*, or None if it matches nothing."""
    t = node.type

    # (a) process.env access — dot, bracket, computed key
    if t in ("member_expression", "subscript_expression"):
        obj = node.child_by_field_name("object")
        if _is_process_env(obj) or _is_process_env(node):
            return "ast_process_env"

    # destructuring: const { env } = process / const { X } = process.env
    if t == "variable_declarator":
        init = node.child_by_field_name("value")
        name = node.child_by_field_name("name")
        if name is not None and name.type == "object_pattern" and init is not None:
            if _is_identifier_named(init, "process"):
                if "env" in _node_text(name):
                    return "ast_process_env"
            if _is_process_env(init):
                return "ast_process_env"

    # (b) network calls, (c) eval/new Function, (d) dangerous require, (e) base64
    if t == "call_expression":
        fn = node.child_by_field_name("function")
        if _is_identifier_named(fn, "eval"):
            return "ast_eval_or_function"
        if _is_identifier_named(fn, "atob"):
            return "ast_base64_decode"
        if fn is not None and fn.type == "identifier" and _node_text(fn) in _AST_NETWORK_NAMES:
            return "ast_network_call"
        mod = _require_argument_module(node)
        if mod is not None:
            if mod in _AST_NETWORK_MODULES:
                return "ast_network_call"
            if mod in _AST_DANGEROUS_MODULES:
                return "ast_dangerous_require"
        if fn is not None and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            prop_name = _node_text(prop)
            obj_name = _node_text(obj)
            if obj_name in ("http", "https") and prop_name in _AST_NETWORK_METHODS:
                return "ast_network_call"
            if obj_name == "Buffer" and prop_name == "from":
                args = node.child_by_field_name("arguments")
                if args is not None:
                    str_args = [c for c in args.children if c.type == "string"]
                    if str_args and "base64" in _node_text(str_args[-1]):
                        return "ast_base64_decode"

    if t == "new_expression":
        ctor = node.child_by_field_name("constructor")
        ctor_name = _node_text(ctor)
        if ctor_name == "Function":
            return "ast_eval_or_function"
        if ctor_name == "XMLHttpRequest":
            return "ast_network_call"

    return None

# ── LLM secondary verification ────────────────────────────────────────────────
#
# When the primary regex scan turns up *some* signal in the README, optionally
# ask an Anthropic model whether the content is genuinely adversarial. The
# threshold is chosen so a single 20-point regex hit alone is not enough —
# the LLM only fires when there are at least two regex hits, keeping API
# spend low and avoiding burning the budget on obviously-clean READMEs.
_LLM_INVOKE_MIN_PRIMARY_SCORE: float = 20.0
# Final injection score is a 40/60 weighted blend of the primary regex score
# and the LLM-assessed score. The LLM is given the larger weight because the
# regex is high-precision/low-recall (catches canonical phrasings, misses
# paraphrases), while the LLM is the opposite — blending recovers both.
_PRIMARY_INJECTION_WEIGHT: float = 0.4
_LLM_INJECTION_WEIGHT:     float = 0.6


# ── Prompt injection patterns in README/description ───────────────────────────
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore (?:previous|all prior) instructions", re.IGNORECASE),
    re.compile(r"disregard (?:your|the) (?:system|previous) (?:prompt|instructions)", re.IGNORECASE),
    re.compile(r"you are now (?:a|an|in)", re.IGNORECASE),
    re.compile(r"act as (?:a|an) (?:different|malicious)", re.IGNORECASE),
    re.compile(r"new persona[:\s]", re.IGNORECASE),
    re.compile(r"system:\s*you must", re.IGNORECASE),
]


class Shield:
    """Pillar 3: detect malicious scripts and prompt injection in package metadata."""

    async def score(
        self, package_name: str, package_metadata: dict | None, version: str | None = None,
    ) -> PillarScore:
        """Return a PillarScore for the candidate package.

        *version* is the exact version actually being installed/evaluated
        (e.g. from a pinned ``npm install pkg@1.2.3``). When given and present
        in the registry's ``versions`` map, every check below (scripts,
        tarball file-scan, diff baseline) resolves against *that* version
        instead of ``dist-tags.latest`` — a compromised release that has
        since been unpublished or superseded by a clean fix would otherwise
        be invisible to Shield, since it would silently scan whatever is
        currently latest instead of the version actually requested.

        If *version* is given but the package's registry document has a
        real (non-empty) ``versions`` map that doesn't include it — e.g. the
        exact version npm's security team purged after a compromise — Shield
        cannot examine what was actually asked. It returns an explicit
        ``requested_version_unresolved`` state instead of silently
        substituting ``dist-tags.latest`` and scoring that: a scanner that
        can't examine the thing it was asked to examine must say so, not
        quietly examine something else and report as if it succeeded. This
        mirrors the tri-state (exists / confirmed-absent / undetermined)
        discipline already applied to registry-existence checks elsewhere.
        """
        if package_metadata is None:
            meta_result = await get_package_metadata(package_name)
            package_metadata = meta_result.data if meta_result.status is RegistryLookup.EXISTS else {}
            package_metadata = package_metadata or {}

        versions_map = package_metadata.get("versions") or {}
        if version and versions_map and version not in versions_map:
            return PillarScore(
                score=0.0,
                confidence=0.0,
                flags=["requested_version_unresolved"],
                metadata={
                    "requested_version": version,
                    "tarball_url": None,
                    "file_scan_summary": {"files_scanned": 0, "flags": 0, "skipped": "requested_version_unresolved"},
                    "diff_score": 0.0,
                    "new_imports": [],
                    "new_network_calls": False,
                },
            )

        scripts = await self.fetch_install_scripts(package_name, package_metadata, version)
        readme = package_metadata.get("readme", "") or ""
        description = package_metadata.get("description", "") or ""

        script_score, script_flags = self.primary_scan(scripts, readme)

        # Injection detection in description and README
        primary_injection_score, injection_flags = self._scan_injection(description + "\n" + readme)

        # File scan — downloads the tarball and statically inspects .js files.
        tarball_url = self._tarball_url_from_metadata(package_metadata, version)
        file_score, file_flags, file_summary = await self.scan_package_files(tarball_url)

        # Secondary LLM verification: only fires when (a) admin enabled it via
        # llm_verification_enabled AND (b) the primary regex scan already
        # produced enough signal to be worth the API call. The threshold of
        # >20 means "at least two regex hits" — a single match is high-precision
        # enough on its own and doesn't justify a second-pass network call.
        settings = get_settings()
        llm_flags: list[str] = []
        llm_reasoning: str = ""
        if settings.llm_verification_enabled and primary_injection_score > _LLM_INVOKE_MIN_PRIMARY_SCORE:
            llm_result = await verify_with_llm(
                package_name, readme, primary_injection_score, injection_flags,
            )
            llm_flags = list(llm_result.get("llm_flags") or [])
            llm_reasoning = str(llm_result.get("reasoning") or "")
            llm_score = float(llm_result.get("llm_score") or 0.0)
            injection_score = min(
                primary_injection_score * _PRIMARY_INJECTION_WEIGHT
                + llm_score * _LLM_INJECTION_WEIGHT,
                100.0,
            )
        else:
            injection_score = primary_injection_score

        combined = min(
            script_score * 0.7
            + injection_score * 0.3
            + file_score * FILE_SCAN_WEIGHT,
            100.0,
        )

        # Differential analysis vs. the immediately preceding published version.
        # Gated on having a current-version tarball URL: without it we can't
        # scan the current release either, so a diff is meaningless. The
        # diff_analyzer is lazy-imported to avoid the import cycle (it imports
        # this module at load time to reuse the AST helpers).
        diff_ran = False
        diff_score = 0.0
        diff_flags: list[str] = []
        diff_new_imports: list[str] = []
        diff_new_network: bool = False
        if tarball_url:
            versions_for_current = package_metadata.get("versions") or {}
            if version and version in versions_for_current:
                current_v = version
            else:
                current_v = (package_metadata.get("dist-tags") or {}).get("latest")
            if current_v:
                try:
                    from ..utils.diff_analyzer import diff_package_versions
                    from ..utils.npm_registry import get_previous_version
                    prev_v = await get_previous_version(package_name, current_v)
                    if prev_v:
                        # Manifest-first gate: scripts/dependencies for every
                        # published version are already present in
                        # package_metadata (the same document already in
                        # hand) — if they're identical between versions,
                        # there's no lifecycle-script or declared-dependency
                        # change to explain, so skip the expensive
                        # double-tarball-download diff entirely. Leaves
                        # diff_ran=False and diff_flags=[] at their pre-block
                        # defaults — NOT diff_analyzer's own "diff_unavailable"
                        # fallback shape, which means "errored", not
                        # "correctly skipped as unnecessary".
                        admin_cfg = get_admin_config()
                        gating_on = admin_cfg.get("shield_manifest_gating", True) is not False
                        versions_map = package_metadata.get("versions") or {}
                        cur_manifest = versions_map.get(current_v)
                        prev_manifest = versions_map.get(prev_v)
                        # If either manifest isn't present in the already-fetched
                        # document (shouldn't normally happen, since prev_v was
                        # resolved from this same document's version history —
                        # but package_metadata may be a partial/synthetic dict in
                        # some callers), we can't confirm equality, so don't gate
                        # rather than risk a fresh network fetch on this hot path.
                        manifest_unchanged = (
                            gating_on
                            and cur_manifest is not None
                            and prev_manifest is not None
                            and _scripts_and_deps_equal(cur_manifest, prev_manifest)
                        )
                        # Manifest equality alone isn't sufficient: the
                        # "Phantom Gyp" pattern adds a binding.gyp with no
                        # package.json change at all, relying on npm's
                        # automatic node-gyp rebuild to execute a payload
                        # outside this gate's view. Only pay this extra
                        # network check in the branch that would otherwise
                        # skip real work — packages whose manifests already
                        # differ never reach here, since they already force
                        # the full diff.
                        if manifest_unchanged:
                            native_check_on = admin_cfg.get(
                                "shield_native_trigger_check", True,
                            ) is not False
                            if native_check_on and await _native_trigger_transition(
                                cur_manifest, prev_manifest,
                            ):
                                manifest_unchanged = False
                        if not manifest_unchanged:
                            diff_result = await diff_package_versions(
                                package_name, current_v, prev_v,
                            )
                            diff_ran = True
                            diff_score = float(diff_result.get("diff_score") or 0.0)
                            diff_flags = list(diff_result.get("diff_flags") or [])
                            diff_new_imports = list(diff_result.get("new_imports") or [])
                            diff_new_network = bool(diff_result.get("new_network_calls"))
                except Exception as exc:  # noqa: BLE001 — diff is advisory only
                    log.debug("diff analysis skipped for %s: %s", package_name, exc)

        # Blend: existing shield carries 0.75, diff carries 0.25 — but only
        # when we actually ran a diff. First releases and registry misses
        # leave the score unchanged; we don't penalise packages for the
        # diff being unavailable. A clean successful diff (diff_score=0)
        # *does* trim the score by 25%, which is intentional: it discounts
        # the file-scan signal slightly when capability-stable across
        # versions, on the principle that "no behavioural change since the
        # last release" is itself weak evidence of benign-ness.
        if diff_ran:
            combined = min(combined * 0.75 + diff_score * 0.25, 100.0)
        all_flags = script_flags + injection_flags + file_flags + llm_flags + diff_flags

        return PillarScore(
            score=combined,
            confidence=0.8,
            flags=all_flags,
            metadata={
                "script_score": script_score,
                "injection_score": injection_score,
                "primary_injection_score": primary_injection_score,
                "file_score": file_score,
                "hooks_found": list(scripts.keys()),
                "tarball_url": tarball_url,
                "file_scan_summary": file_summary,
                "llm_reasoning": llm_reasoning,
                "diff_score": diff_score,
                "new_imports": diff_new_imports,
                "new_network_calls": diff_new_network,
            },
        )

    @staticmethod
    def _tarball_url_from_metadata(metadata: dict, version: str | None = None) -> str | None:
        """Pull dist.tarball for *version* (or latest, if unset/unresolvable) out of registry metadata."""
        versions = metadata.get("versions") or {}
        resolved = version if version and version in versions else None
        if resolved is None:
            resolved = (metadata.get("dist-tags") or {}).get("latest")
        pkg = versions.get(resolved) if resolved else None
        if not pkg and versions:
            pkg = next(iter(versions.values()))
        dist = (pkg or {}).get("dist") or {}
        return dist.get("tarball") or None

    async def scan_package_files(
        self, tarball_url: str | None,
    ) -> tuple[float, list[str], dict]:
        """Download *tarball_url*, extract, and statically scan .js files.

        Returns ``(score, flags, summary)``. Score is the un-weighted total —
        the caller multiplies by ``FILE_SCAN_WEIGHT``. Summary is suitable
        for the VS Code "Show Details" panel: ``{"files_scanned", "flags",
        "skipped"}``.
        """
        admin_cfg = get_admin_config()
        # Default-on: only an explicit `false` disables file scanning.
        if admin_cfg.get("package_file_scan", True) is False:
            return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "disabled_by_admin"}

        if not tarball_url:
            return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "no_tarball_url"}

        tmp_dir = tempfile.mkdtemp(prefix="cidas-shield-")
        try:
            tar_path = os.path.join(tmp_dir, "package.tgz")
            ok = await download_tarball(tarball_url, tar_path)
            if not ok:
                return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "download_failed"}

            extract_dir = os.path.join(tmp_dir, "unpacked")
            os.mkdir(extract_dir)
            try:
                self._safe_extract(tar_path, extract_dir)
            except (tarfile.TarError, OSError) as exc:
                log.warning("tarball extract failed: %s", exc)
                return 0.0, [], {"files_scanned": 0, "flags": 0, "skipped": "extract_failed"}

            score, flags, n = self._scan_extracted_dir(extract_dir)
            summary = {"files_scanned": n, "flags": len(flags), "skipped": None}
            return score, flags, summary
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _safe_extract(tar_path: str, dest: str) -> None:
        """Extract *tar_path* into *dest*, refusing path-traversal entries."""
        dest_abs = os.path.realpath(dest)
        with tarfile.open(tar_path, "r:*") as tf:
            for member in tf.getmembers():
                # Skip anything that's not a regular file or directory.
                if not (member.isfile() or member.isdir()):
                    continue
                target = os.path.realpath(os.path.join(dest, member.name))
                if not target.startswith(dest_abs + os.sep) and target != dest_abs:
                    raise tarfile.TarError(f"refusing path traversal entry: {member.name}")
            tf.extractall(dest)  # noqa: S202 — guarded above

    def _scan_extracted_dir(self, root: str) -> tuple[float, list[str], int]:
        """Walk *root*, scan up to _FILE_SCAN_MAX_FILES .js files."""
        regex_total = 0.0
        ast_total = 0.0
        # Use a set so a pattern hitting in three different files only adds
        # its weight once — otherwise legitimate vendored bundles dominate.
        regex_seen: set[str] = set()
        ast_seen: set[str] = set()
        scanned = 0
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if scanned >= _FILE_SCAN_MAX_FILES:
                    break
                if not name.endswith(".js"):
                    continue
                fpath = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(fpath) > _FILE_SCAN_MAX_BYTES:
                        continue
                    text = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                for label, score in self._scan_one_file(text):
                    if label not in regex_seen:
                        regex_seen.add(label)
                        regex_total += score

                for label, score in self.ast_scan_one_file(text):
                    if label not in ast_seen:
                        ast_seen.add(label)
                        ast_total += score
                scanned += 1
            if scanned >= _FILE_SCAN_MAX_FILES:
                break

        regex_score = min(regex_total, 100.0)
        ast_score = min(ast_total, 100.0)
        # final_shield_file_score = (regex_score * 0.5) + (ast_score * 0.5)
        combined = min(regex_score * 0.5 + ast_score * 0.5, 100.0)
        flags = sorted(regex_seen | ast_seen)
        return combined, flags, scanned

    @staticmethod
    def _scan_one_file(text: str) -> list[tuple[str, float]]:
        """Apply lifecycle patterns + require()-time patterns to *text*."""
        hits: list[tuple[str, float]] = []

        # 1. Reuse the lifecycle-script pattern table on the file body.
        for label, pattern, weight in _SCRIPT_PATTERNS:
            if pattern.search(text):
                hits.append((label, weight))

        # 2. process.env.<UPPER> within 5 lines of an http/https/fetch call.
        lines = text.splitlines()
        env_lines  = {i for i, ln in enumerate(lines) if _PROCESS_ENV_RE.search(ln)}
        http_lines = {i for i, ln in enumerate(lines) if _HTTP_FETCH_RE.search(ln)}
        if any(abs(e - h) <= 5 for e in env_lines for h in http_lines):
            hits.append(("env_exfil_near_http", _REQUIRE_TIME_SCORES["env_exfil_near_http"]))

        # 3. require('dns') near a domain string with a long random subdomain.
        if _DNS_REQUIRE_RE.search(text) and _LONG_SUBDOMAIN_RE.search(text):
            hits.append(("dns_long_subdomain", _REQUIRE_TIME_SCORES["dns_long_subdomain"]))

        # 4. High density of \x hex escapes (file-wide, not just contiguous).
        if text:
            density = len(_HEX_ESCAPE_RE.findall(text)) / max(len(text), 1)
            if density > _HEX_DENSITY_THRESHOLD:
                hits.append(("hex_density", _REQUIRE_TIME_SCORES["hex_density"]))

        return hits

    @staticmethod
    def ast_scan_one_file(text: str) -> list[tuple[str, float]]:
        """Parse *text* as JavaScript and return (label, weight) AST findings.

        Returns ``[("parse_failed", 0.0)]`` if the parser is unavailable or
        the source can't be parsed at all — the caller treats this as a
        fall-back-to-regex signal. A zero-weight flag still surfaces in the
        flag list so downstream consumers know AST coverage was lost.
        """
        parser = _get_js_parser()
        if parser is None:
            return [("parse_failed", _AST_PATTERN_SCORES["parse_failed"])]

        try:
            tree = parser.parse(bytes(text, "utf-8"))
        except Exception as exc:  # noqa: BLE001 — defensive: parser is C-backed
            log.debug("tree-sitter parse raised: %s", exc)
            return [("parse_failed", _AST_PATTERN_SCORES["parse_failed"])]

        root = tree.root_node
        # tree-sitter still produces a (partial) tree with `ERROR` nodes for
        # minified-beyond-parseable input. If the root itself is an error
        # node, treat the file as unparseable.
        if root is None or root.type == "ERROR":
            return [("parse_failed", _AST_PATTERN_SCORES["parse_failed"])]

        hits: dict[str, float] = {}
        for node in _walk_ts(root):
            label = _classify_node(node)
            if label is not None and label not in hits:
                hits[label] = _AST_PATTERN_SCORES[label]
        return list(hits.items())

    async def fetch_install_scripts(
        self, package_name: str, metadata: dict, version: str | None = None,
    ) -> dict[str, str]:
        """Extract lifecycle scripts from the package metadata or tarball info.

        Resolves *version*'s own manifest when given and present in the
        registry document; otherwise falls back to dist-tags.latest (prior
        behavior).
        """
        dist_tags: dict = metadata.get("dist-tags", {})
        latest = dist_tags.get("latest")
        versions: dict = metadata.get("versions", {})

        pkg_json: dict = {}
        if version and version in versions:
            pkg_json = versions[version]
        elif latest and latest in versions:
            pkg_json = versions[latest]
        elif versions:
            pkg_json = next(iter(versions.values()))

        all_scripts: dict[str, str] = pkg_json.get("scripts", {})

        # TODO(phase-2): also fetch tarball and scan extracted install scripts
        return {k: v for k, v in all_scripts.items() if k in _LIFECYCLE_HOOKS}

    def primary_scan(self, scripts: dict[str, str], readme: str) -> tuple[float, list[str]]:
        """Run pattern-based scan over lifecycle scripts and README."""
        if not scripts:
            return 0.0, []

        combined = "\n".join(scripts.values())
        total = 0.0
        flags: list[str] = []
        for label, pattern, weight in _SCRIPT_PATTERNS:
            if pattern.search(combined):
                flags.append(label)
                total += weight

        return min(total, 100.0), flags

    async def secondary_verification(
        self,
        primary_result: tuple[float, list[str]],
        metadata: dict,
    ) -> tuple[float, list[str]]:
        """TODO(phase-2): call a local LLM to detect adversarial prompt injection.

        This method is reserved for a second-pass analysis using a small local
        language model that has been fine-tuned to detect prompt injection
        patterns in package metadata.  For now it returns a zero-risk score.
        """
        return 0.0, []

    def detect_injection_patterns(self, text: str) -> list[str]:
        """Return a list of matched injection pattern labels."""
        matched: list[str] = []
        for i, pattern in enumerate(_INJECTION_PATTERNS):
            if pattern.search(text):
                matched.append(f"injection_pattern_{i + 1}")
        return matched

    def _scan_injection(self, text: str) -> tuple[float, list[str]]:
        matched = self.detect_injection_patterns(text)
        score = min(len(matched) * 20.0, 60.0)
        return score, matched
