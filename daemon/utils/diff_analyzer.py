"""Differential analysis between two published versions of an npm package.

The classic malicious-update pattern (event-stream, ua-parser-js, …) is a
benign package that *suddenly grows a new capability* in a fresh release:
a `require('dns')`, a `process.env.X` read, or a `fetch()` it never had
before. Comparing the AST-derived capability sets between version N and
version N-1 surfaces exactly that signal — and at very low false-positive
cost, because most legitimate releases don't gain new dangerous imports.

Implementation reuses Shield's tarball download/extract pipeline plus its
tree-sitter helpers (``_get_js_parser``, ``_walk_ts``, ``_require_argument_module``,
``_classify_node``). That keeps the new feature thin: this module owns the
diff and scoring logic, not the parsing logic.

Failure policy: on **any** error — unknown previous version, tarball miss,
extract failure, parser unavailable — return the canonical fallback dict
``{diff_score: 0, diff_flags: ["diff_unavailable"], …}`` so the caller can
blend safely without special-casing. Never raise.
"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Import shield at module-load time. shield.py does NOT import this module at
# load time — its import is lazy inside Shield.score() — so this is acyclic.
from ..pillars import shield as _shield_mod
from .logger import get_logger
from .npm_registry import download_tarball, get_package_tarball_info

log = get_logger(__name__)

# File-scan limits — match shield.py so a diff doesn't behave differently
# from the primary file scan it complements.
_MAX_FILES = 50
_MAX_BYTES = 200 * 1024

# Per-finding score weights (see module docstring). Each new dangerous import
# adds +20, capped at +60 so an attacker who adds dns+child_process+http+net
# doesn't pin the score on imports alone. Network and env-access flips add
# their own fixed weights; total clamped to 100.
_PER_DANGEROUS_IMPORT = 20.0
_DANGEROUS_IMPORT_CAP = 60.0
_NEW_NETWORK_WEIGHT   = 25.0
_NEW_ENV_WEIGHT       = 30.0


def _fallback() -> dict[str, Any]:
    """A fresh copy of the canonical "diff couldn't run" result."""
    return {
        "new_imports":       [],
        "removed_imports":   [],
        "new_network_calls": False,
        "new_env_access":    False,
        "diff_score":        0.0,
        "diff_flags":        ["diff_unavailable"],
    }


@dataclass
class _Features:
    """Capability set extracted from one extracted-tarball directory."""
    imports: set[str] = field(default_factory=set)
    has_network: bool = False
    has_env: bool = False


async def diff_package_versions(
    name: str,
    current_version: str,
    previous_version: str,
) -> dict[str, Any]:
    """Diff the capability set of *current_version* against *previous_version*.

    Returns a dict with keys ``new_imports``, ``removed_imports``,
    ``new_network_calls`` (bool), ``new_env_access`` (bool), ``diff_score``
    (0–100), and ``diff_flags`` (list[str]).

    See the module docstring for the failure policy — on any unrecoverable
    issue this returns the fallback dict rather than raising.
    """
    if not previous_version or not current_version:
        return _fallback()

    cur_info = await get_package_tarball_info(name, current_version)
    prev_info = await get_package_tarball_info(name, previous_version)
    if not cur_info or not prev_info:
        return _fallback()
    cur_url = cur_info.get("tarball")
    prev_url = prev_info.get("tarball")
    if not cur_url or not prev_url:
        return _fallback()

    tmp = tempfile.mkdtemp(prefix="cidas-diff-")
    try:
        cur_tgz = os.path.join(tmp, "current.tgz")
        prev_tgz = os.path.join(tmp, "previous.tgz")
        ok_cur = await download_tarball(cur_url, cur_tgz)
        ok_prev = await download_tarball(prev_url, prev_tgz)
        if not (ok_cur and ok_prev):
            return _fallback()

        cur_dir = os.path.join(tmp, "current")
        prev_dir = os.path.join(tmp, "previous")
        os.mkdir(cur_dir)
        os.mkdir(prev_dir)
        try:
            _shield_mod.Shield._safe_extract(cur_tgz, cur_dir)
            _shield_mod.Shield._safe_extract(prev_tgz, prev_dir)
        except (tarfile.TarError, OSError) as exc:
            log.warning("diff extract failed for %s: %s", name, exc)
            return _fallback()

        cur_feat = _extract_features(cur_dir)
        prev_feat = _extract_features(prev_dir)
    except Exception as exc:  # noqa: BLE001 — never let diff abort the scan
        log.warning("diff_package_versions failed for %s: %s", name, exc)
        return _fallback()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    new_imports = sorted(cur_feat.imports - prev_feat.imports)
    removed_imports = sorted(prev_feat.imports - cur_feat.imports)
    new_network = cur_feat.has_network and not prev_feat.has_network
    new_env = cur_feat.has_env and not prev_feat.has_env

    dangerous_new = [m for m in new_imports if m in _shield_mod._AST_DANGEROUS_MODULES]
    import_component = min(len(dangerous_new) * _PER_DANGEROUS_IMPORT, _DANGEROUS_IMPORT_CAP)
    score = import_component
    if new_network:
        score += _NEW_NETWORK_WEIGHT
    if new_env:
        score += _NEW_ENV_WEIGHT
    score = min(score, 100.0)

    flags: list[str] = []
    if dangerous_new:
        flags.append("diff_new_dangerous_import")
    if new_network:
        flags.append("diff_new_network_call")
    if new_env:
        flags.append("diff_new_env_access")

    return {
        "new_imports":       new_imports,
        "removed_imports":   removed_imports,
        "new_network_calls": new_network,
        "new_env_access":    new_env,
        "diff_score":        score,
        "diff_flags":        flags,
    }


def _extract_features(root: str) -> _Features:
    """Walk *root* and collect (imports, has_network, has_env) for diffing.

    Mirrors Shield's file-scan limits — same _MAX_FILES / _MAX_BYTES caps —
    so a package that was too big to scan in the current version is also
    too big to diff. Files the parser rejects are silently skipped; their
    capabilities simply won't contribute to either side of the diff (which
    is the right behaviour — we can't know what we can't parse).
    """
    feats = _Features()
    parser = _shield_mod._get_js_parser()
    scanned = 0

    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if scanned >= _MAX_FILES:
                break
            if not fname.endswith(".js"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) > _MAX_BYTES:
                    continue
                text = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned += 1

            if parser is None:
                continue
            try:
                tree = parser.parse(bytes(text, "utf-8"))
            except Exception:  # noqa: BLE001
                continue
            root_node = tree.root_node
            if root_node is None or root_node.type == "ERROR":
                continue

            for node in _shield_mod._walk_ts(root_node):
                mod = _shield_mod._require_argument_module(node)
                if mod:
                    feats.imports.add(mod)
                label = _shield_mod._classify_node(node)
                if label == "ast_network_call":
                    feats.has_network = True
                elif label == "ast_process_env":
                    feats.has_env = True

        if scanned >= _MAX_FILES:
            break

    return feats
