"""Disk footprint analysis for npm package installations."""
from __future__ import annotations

import asyncio
import os
import shutil

from .npm_registry import get_package_size

_MB = 1024 * 1024
_SEMAPHORE_LIMIT = 10


async def check_disk_footprint(
    package_name: str,
    version: str,
    transitive_deps: list[dict],
    project_path: str,
) -> dict:
    """Estimate the disk cost of installing *package_name* plus *transitive_deps*.

    All registry fetches are concurrent, capped at _SEMAPHORE_LIMIT simultaneous
    requests.  Falls back to cwd for disk_usage when *project_path* is absent.
    Never raises — returns a "disk_check_unavailable" sentinel dict on failure.
    """
    try:
        sem = asyncio.Semaphore(_SEMAPHORE_LIMIT)

        async def _fetch(name: str, ver: str) -> int:
            async with sem:
                return await get_package_size(name, ver)

        tasks = [_fetch(package_name, version)]
        for dep in transitive_deps:
            tasks.append(_fetch(dep.get("name", ""), dep.get("version", "latest")))

        sizes: tuple[int, ...] = await asyncio.gather(*tasks)
        estimated_install_bytes = sum(sizes)

        try:
            available_disk_bytes = shutil.disk_usage(project_path).free
        except (FileNotFoundError, OSError):
            available_disk_bytes = shutil.disk_usage(".").free

        node_modules_bytes = 0
        node_modules_path = os.path.join(project_path, "node_modules")
        if os.path.isdir(node_modules_path):
            try:
                for dirpath, _dirnames, filenames in os.walk(
                    node_modules_path, followlinks=False
                ):
                    for fname in filenames:
                        try:
                            node_modules_bytes += os.path.getsize(
                                os.path.join(dirpath, fname)
                            )
                        except OSError:
                            pass
            except OSError:
                node_modules_bytes = 0

        dep_count = len(transitive_deps)
        estimated_install_mb = round(estimated_install_bytes / _MB, 2)
        available_disk_mb = round(available_disk_bytes / _MB, 2)
        will_fit = estimated_install_bytes <= available_disk_bytes

        flags: list[str] = []
        if not will_fit:
            flags.append("exceeds_available_disk")
        if estimated_install_mb > 50:
            flags.append("large_install")
        if estimated_install_mb > 200:
            flags.append("very_large_install")
        if dep_count > 100:
            flags.append("high_dep_count")
        if estimated_install_bytes == 0:
            flags.append("size_unknown")

        if not will_fit:
            disk_risk_score = 100.0
        elif estimated_install_mb > 200:
            disk_risk_score = 50.0
        elif estimated_install_mb > 50:
            disk_risk_score = 30.0
        else:
            disk_risk_score = 0.0

        return {
            "estimated_install_bytes": estimated_install_bytes,
            "estimated_install_mb": estimated_install_mb,
            "available_disk_bytes": available_disk_bytes,
            "available_disk_mb": available_disk_mb,
            "node_modules_bytes": node_modules_bytes,
            "dep_count": dep_count,
            "will_fit": will_fit,
            "flags": flags,
            "disk_risk_score": disk_risk_score,
        }

    except Exception:  # noqa: BLE001
        return {
            "estimated_install_bytes": 0,
            "estimated_install_mb": 0.0,
            "available_disk_bytes": 0,
            "available_disk_mb": 0.0,
            "node_modules_bytes": 0,
            "dep_count": 0,
            "will_fit": True,
            "flags": ["disk_check_unavailable"],
            "disk_risk_score": 0.0,
        }
