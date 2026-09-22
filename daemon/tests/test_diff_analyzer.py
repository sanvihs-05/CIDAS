"""Tests for daemon.utils.diff_analyzer.diff_package_versions.

Fixture tarballs are built inline in tmp_path rather than committed under
tests/fixtures/, because the diff feature only ever needs ephemeral
two-version pairs — committing one pair per test scenario would balloon
the repo for no portability win.
"""
from __future__ import annotations

import io
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest

from daemon.utils.diff_analyzer import diff_package_versions


# ── Fixture builders ──────────────────────────────────────────────────────────

def _write_tarball(path: Path, files: dict[str, str]) -> None:
    """Write a gzipped tar at *path* containing *files* (name → content)."""
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))


def _pkg_files(version: str, index_js: str) -> dict[str, str]:
    return {
        f"package/package.json": f'{{"name":"diff-pkg","version":"{version}","main":"index.js"}}\n',
        f"package/index.js": index_js,
    }


@pytest.fixture
def two_version_pair(tmp_path):
    """Build (current_tgz, previous_tgz) for a given source pair.

    Returns a callable so individual tests can construct the version pair
    they need; the fixture itself just owns the temp dir.
    """
    def _build(current_src: str, previous_src: str) -> tuple[Path, Path]:
        cur = tmp_path / "current-1.1.0.tgz"
        prev = tmp_path / "previous-1.0.0.tgz"
        _write_tarball(cur, _pkg_files("1.1.0", current_src))
        _write_tarball(prev, _pkg_files("1.0.0", previous_src))
        return cur, prev
    return _build


def _patch_io(monkeypatch, cur_path: Path, prev_path: Path) -> None:
    """Patch tarball-info + download to serve our local fixtures.

    The url returned by ``get_package_tarball_info`` is just a marker the
    download stub recognises; we route ``1.1.0`` URLs to *cur_path* and
    everything else to *prev_path*.
    """
    async def fake_info(name: str, version: str) -> dict[str, Any]:
        return {"tarball": f"https://example.test/{name}-{version}.tgz"}

    async def fake_download(url: str, dest: str) -> bool:
        src = cur_path if "1.1.0" in url else prev_path
        shutil.copyfile(src, dest)
        return True

    monkeypatch.setattr("daemon.utils.diff_analyzer.get_package_tarball_info", fake_info)
    monkeypatch.setattr("daemon.utils.diff_analyzer.download_tarball", fake_download)


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_previous_version_returns_unavailable() -> None:
    """Empty previous_version → fallback fast-path, no IO."""
    result = await diff_package_versions("diff-pkg", "1.0.0", "")
    assert result["diff_score"] == 0
    assert result["diff_flags"] == ["diff_unavailable"]
    assert result["new_imports"] == []
    assert result["new_network_calls"] is False
    assert result["new_env_access"] is False


@pytest.mark.asyncio
async def test_new_dns_import_scores_above_zero(
    two_version_pair, monkeypatch,
) -> None:
    """current adds require('dns'); previous didn't → dangerous-import flag fires."""
    cur_src = (
        "'use strict';\n"
        "const dns = require('dns');\n"
        "module.exports = { run: () => dns.lookup('example.com', () => {}) };\n"
    )
    prev_src = (
        "'use strict';\n"
        "module.exports = { run: () => 'ok' };\n"
    )
    cur_path, prev_path = two_version_pair(cur_src, prev_src)
    _patch_io(monkeypatch, cur_path, prev_path)

    result = await diff_package_versions("diff-pkg", "1.1.0", "1.0.0")
    assert "dns" in result["new_imports"]
    assert result["diff_score"] >= 20.0
    assert "diff_new_dangerous_import" in result["diff_flags"]
    assert "diff_unavailable" not in result["diff_flags"]


@pytest.mark.asyncio
async def test_new_env_access_detected_across_versions(
    two_version_pair, monkeypatch,
) -> None:
    """current reads process.env.X; previous didn't → new_env_access flips True."""
    cur_src = (
        "'use strict';\n"
        "const token = process.env.SECRET_TOKEN;\n"
        "module.exports = { token };\n"
    )
    prev_src = (
        "'use strict';\n"
        "module.exports = { token: 'static' };\n"
    )
    cur_path, prev_path = two_version_pair(cur_src, prev_src)
    _patch_io(monkeypatch, cur_path, prev_path)

    result = await diff_package_versions("diff-pkg", "1.1.0", "1.0.0")
    assert result["new_env_access"] is True
    assert result["diff_score"] >= 30.0  # _NEW_ENV_WEIGHT
    assert "diff_new_env_access" in result["diff_flags"]


@pytest.mark.asyncio
async def test_new_network_call_detected(two_version_pair, monkeypatch) -> None:
    """fetch() appears in current but not previous → new_network_calls fires."""
    cur_src = (
        "'use strict';\n"
        "module.exports = { run: () => fetch('https://example.test/x') };\n"
    )
    prev_src = "'use strict';\nmodule.exports = { run: () => 'ok' };\n"
    cur_path, prev_path = two_version_pair(cur_src, prev_src)
    _patch_io(monkeypatch, cur_path, prev_path)

    result = await diff_package_versions("diff-pkg", "1.1.0", "1.0.0")
    assert result["new_network_calls"] is True
    assert result["diff_score"] >= 25.0  # _NEW_NETWORK_WEIGHT
    assert "diff_new_network_call" in result["diff_flags"]


@pytest.mark.asyncio
async def test_tarball_download_failure_returns_zero(monkeypatch) -> None:
    """download_tarball returning False → fallback, never raises."""
    async def fake_info(name: str, version: str) -> dict[str, Any]:
        return {"tarball": f"https://example.test/{name}-{version}.tgz"}

    async def failing_download(url: str, dest: str) -> bool:
        return False

    monkeypatch.setattr("daemon.utils.diff_analyzer.get_package_tarball_info", fake_info)
    monkeypatch.setattr("daemon.utils.diff_analyzer.download_tarball", failing_download)

    result = await diff_package_versions("diff-pkg", "1.1.0", "1.0.0")
    assert result["diff_score"] == 0
    assert result["diff_flags"] == ["diff_unavailable"]


@pytest.mark.asyncio
async def test_missing_tarball_info_returns_fallback(monkeypatch) -> None:
    """get_package_tarball_info returning None for either side → fallback."""
    async def info_none(name: str, version: str) -> dict[str, Any] | None:
        return None

    monkeypatch.setattr("daemon.utils.diff_analyzer.get_package_tarball_info", info_none)
    # download_tarball must never be reached in this path; assert it isn't by
    # leaving it patched with a function that fails the test loudly.
    async def must_not_call(*_a, **_kw):  # pragma: no cover — failure path
        raise AssertionError("download_tarball should not run when info is None")
    monkeypatch.setattr("daemon.utils.diff_analyzer.download_tarball", must_not_call)

    result = await diff_package_versions("diff-pkg", "1.1.0", "1.0.0")
    assert result["diff_flags"] == ["diff_unavailable"]


@pytest.mark.asyncio
async def test_identical_versions_score_zero(two_version_pair, monkeypatch) -> None:
    """Same source on both sides → no new capability → diff_score=0, no flags."""
    src = (
        "'use strict';\n"
        "const path = require('path');\n"
        "module.exports = { join: path.join };\n"
    )
    cur_path, prev_path = two_version_pair(src, src)
    _patch_io(monkeypatch, cur_path, prev_path)

    result = await diff_package_versions("diff-pkg", "1.1.0", "1.0.0")
    assert result["diff_score"] == 0
    assert result["new_imports"] == []
    assert result["new_network_calls"] is False
    assert result["new_env_access"] is False
    # No diff flags raised, and the fallback flag was not introduced either.
    assert result["diff_flags"] == []
