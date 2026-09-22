"""Tests for daemon.utils.disk_checker.check_disk_footprint."""
from __future__ import annotations

import asyncio

import pytest

from daemon.utils.disk_checker import check_disk_footprint

_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024

# ── helpers ───────────────────────────────────────────────────────────────────

def _fake_disk(free_bytes: int):
    class _DU:
        free = free_bytes
    return lambda _path: _DU()


# ── tests ─────────────────────────────────────────────────────────────────────

async def test_small_package_fits_returns_will_fit_true(monkeypatch):
    async def mock_size(name, version="latest"):
        return _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    deps = [{"name": "dep1", "version": "1.0.0"}, {"name": "dep2", "version": "1.0.0"}]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert result["will_fit"] is True
    assert result["disk_risk_score"] == 0
    assert result["flags"] == []


async def test_exceeds_disk_returns_will_fit_false_and_score_100(monkeypatch):
    async def mock_size(name, version="latest"):
        return 2 * _GB  # 2 GB per package — two packages exceed 1 GB free

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(1 * _GB))

    deps = [{"name": "dep1", "version": "1.0.0"}]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert result["will_fit"] is False
    assert "exceeds_available_disk" in result["flags"]
    assert result["disk_risk_score"] == 100


async def test_large_install_flagged(monkeypatch):
    # 1 top-level + 4 deps = 5 packages × 20 MB = 100 MB  (> 50, < 200)
    async def mock_size(name, version="latest"):
        return 20 * _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    deps = [{"name": f"dep{i}", "version": "1.0.0"} for i in range(4)]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert "large_install" in result["flags"]
    assert result["disk_risk_score"] == 30


async def test_very_large_install_flagged(monkeypatch):
    # 1 top-level + 5 deps = 6 packages × 50 MB = 300 MB  (> 200)
    async def mock_size(name, version="latest"):
        return 50 * _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    deps = [{"name": f"dep{i}", "version": "1.0.0"} for i in range(5)]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert "very_large_install" in result["flags"]
    assert result["disk_risk_score"] == 50


async def test_high_dep_count_flagged(monkeypatch):
    async def mock_size(name, version="latest"):
        return _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    deps = [{"name": f"dep{i}", "version": "1.0.0"} for i in range(150)]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert "high_dep_count" in result["flags"]


async def test_size_unknown_when_all_zero(monkeypatch):
    async def mock_size(name, version="latest"):
        return 0

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    deps = [{"name": "dep1", "version": "1.0.0"}]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert "size_unknown" in result["flags"]


async def test_missing_project_path_uses_cwd(monkeypatch):
    async def mock_size(name, version="latest"):
        return _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    # shutil.disk_usage is NOT mocked — the real fallback to "." must fire

    deps = [{"name": "dep1", "version": "1.0.0"}]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, "/nonexistent/path/xyz")

    assert result["available_disk_bytes"] > 0


async def test_node_modules_counted(monkeypatch, tmp_path):
    async def mock_size(name, version="latest"):
        return _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "fake_pkg.js").write_bytes(b"x" * 1024)

    deps = [{"name": "dep1", "version": "1.0.0"}]
    result = await check_disk_footprint("test-pkg", "1.0.0", deps, str(tmp_path))

    assert result["node_modules_bytes"] > 0


async def test_concurrent_fetches_capped_at_10(monkeypatch):
    sem_calls: list[int] = []
    _real_semaphore = asyncio.Semaphore

    def spy_semaphore(n: int):
        sem_calls.append(n)
        return _real_semaphore(n)

    monkeypatch.setattr(asyncio, "Semaphore", spy_semaphore)

    async def mock_size(name, version="latest"):
        return _MB

    monkeypatch.setattr("daemon.utils.disk_checker.get_package_size", mock_size)
    monkeypatch.setattr("shutil.disk_usage", _fake_disk(10 * _GB))

    deps = [{"name": f"dep{i}", "version": "1.0.0"} for i in range(25)]
    await check_disk_footprint("test-pkg", "1.0.0", deps, "/tmp")

    assert sem_calls == [10]
