"""Transitive dependency resolver for npm packages.

Resolves the dependency tree of a package up to *max_depth* levels deep.
Registry calls at each level are made concurrently via asyncio.gather to keep
latency acceptable.

Cycle protection: *visited* is keyed by ``"name@version"`` and checked at
the top of each recursive call before any I/O, so the check-then-add is
atomic under asyncio's cooperative scheduler.
"""
from __future__ import annotations

import asyncio

from .logger import get_logger
from .npm_registry import get_direct_dependencies

log = get_logger(__name__)


async def resolve_transitive(
    name: str,
    version: str,
    depth: int = 0,
    max_depth: int = 2,
    visited: set[str] | None = None,
) -> list[dict]:
    """Recursively resolve the dependency tree up to *max_depth* levels.

    Returns a flat list of ``{"name": str, "version": str, "depth": int}``
    dicts.  A package that appears as a dependency of multiple parents is
    emitted once per occurrence (different depths), but its own sub-tree is
    only expanded once (via *visited*).

    Parameters
    ----------
    name:      Root package name for this call.
    version:   Exact semver or range; ranges resolve to ``dist-tags.latest``.
    depth:     Current recursion depth (callers should leave this at 0).
    max_depth: Stop expanding dependencies at this depth.
    visited:   Shared set of ``"name@version"`` keys already processed.
               Pass ``None`` on the initial call — a fresh set is created.
    """
    if visited is None:
        visited = set()

    key = f"{name}@{version}"
    # Both cycle guard and depth guard must be checked before any await so the
    # visited.add() below is atomic with the check (no yield between them).
    if key in visited:
        return []
    visited.add(key)

    if depth >= max_depth:
        return []

    try:
        deps = await get_direct_dependencies(name, version)
    except Exception as exc:  # noqa: BLE001 — registry errors must not abort the scan
        log.debug("get_direct_dependencies failed for %s@%s: %s", name, version, exc)
        return []

    results: list[dict] = []
    sub_coros: list = []

    for dep_name, dep_ver in deps.items():
        dep_key = f"{dep_name}@{dep_ver}"
        if dep_key in visited:
            continue
        results.append({"name": dep_name, "version": dep_ver, "depth": depth + 1})
        sub_coros.append(
            resolve_transitive(dep_name, dep_ver, depth + 1, max_depth, visited)
        )

    if sub_coros:
        sub_lists = await asyncio.gather(*sub_coros, return_exceptions=True)
        for sub in sub_lists:
            if isinstance(sub, list):
                results.extend(sub)
            # Exceptions from individual branches are swallowed — a single
            # unreachable registry endpoint should not abort the whole tree.

    return results
