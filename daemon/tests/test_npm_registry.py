"""Tests for daemon.utils.npm_registry.

HTTP calls are mocked at the httpx.AsyncClient level for _get / download_tarball,
and via patch on _get itself for the higher-level public functions.
asyncio_mode = "auto" is set in pyproject.toml so no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

import asyncio
import io
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from daemon.utils.npm_registry import RegistryLookup, RegistryResult


# ── helpers ───────────────────────────────────────────────────────────────────

def _mock_client(status: int = 200, json_data: dict | None = None) -> MagicMock:
    """Return an async-context-manager mock for httpx.AsyncClient."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()

    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _mock_resp(status: int, json_data: dict | None = None, retry_after: str | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()
    resp.headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return resp


def _mock_client_sequence(responses: list[MagicMock]) -> MagicMock:
    """Return an async-context-manager mock whose .get() yields *responses*
    in order across successive calls (for retry-then-succeed scenarios)."""
    client = MagicMock()
    client.get = AsyncMock(side_effect=responses)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _mock_client_raising(exc: Exception) -> MagicMock:
    """Return a mock client whose .get() raises *exc*."""
    client = MagicMock()
    client.get = AsyncMock(side_effect=exc)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


_SAMPLE_REGISTRY_META: dict = {
    "name": "lodash",
    "description": "Lodash modular utilities.",
    "dist-tags": {"latest": "4.17.21"},
    "time": {
        "created": "2012-04-20T00:00:00Z",
        "modified": "2022-01-01T00:00:00Z",
        "4.17.20": "2021-01-01T00:00:00Z",
        "4.17.21": "2021-10-01T00:00:00Z",
    },
    "maintainers": [{"name": "jdalton"}],
    "repository": {"url": "https://github.com/lodash/lodash"},
    "versions": {
        "4.17.20": {
            "name": "lodash",
            "version": "4.17.20",
            "dependencies": {"semver": "^7.0.0"},
            "dist": {"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
        },
        "4.17.21": {
            "name": "lodash",
            "version": "4.17.21",
            "dependencies": {"semver": "^7.0.0"},
            "dist": {"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
        },
    },
}


# ── _get — unit tests ─────────────────────────────────────────────────────────

async def test_get_returns_exists_with_parsed_json_on_200() -> None:
    from daemon.utils.npm_registry import _get

    client = _mock_client(200, {"foo": "bar"})
    with patch("httpx.AsyncClient", return_value=client):
        result = await _get("https://example.com/pkg")

    assert result.status is RegistryLookup.EXISTS
    assert result.data == {"foo": "bar"}


async def test_get_returns_confirmed_absent_on_404() -> None:
    from daemon.utils.npm_registry import _get

    client = _mock_client(404)
    with patch("httpx.AsyncClient", return_value=client):
        result = await _get("https://example.com/missing")

    assert result.status is RegistryLookup.CONFIRMED_ABSENT
    assert result.data is None


async def test_get_returns_undetermined_after_two_timeout_attempts() -> None:
    from daemon.utils.npm_registry import _get

    failing = _mock_client_raising(httpx.TimeoutException("timeout"))
    with patch("httpx.AsyncClient", return_value=failing):
        result = await _get("https://example.com/slow")

    assert result.status is RegistryLookup.UNDETERMINED
    # Two attempts, each creates a new AsyncClient context
    assert failing.get.call_count == 2


async def test_get_retries_once_on_network_error_then_succeeds() -> None:
    from daemon.utils.npm_registry import _get

    failing = _mock_client_raising(httpx.NetworkError("reset"))
    success = _mock_client(200, {"ok": True})
    with patch("httpx.AsyncClient", side_effect=[failing, success]):
        result = await _get("https://example.com/flaky")

    assert result.status is RegistryLookup.EXISTS
    assert result.data == {"ok": True}


async def test_get_returns_undetermined_on_http_5xx_status_error() -> None:
    """A non-404 HTTP error status is ambiguous, not confirmed-absent — the
    package may exist; the registry just failed to serve it this time."""
    from daemon.utils.npm_registry import _get

    resp = MagicMock()
    resp.status_code = 500
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=MagicMock(), response=resp
    )
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=client):
        result = await _get("https://example.com/error")

    assert result.status is RegistryLookup.UNDETERMINED
    assert result.data is None


async def test_get_retries_on_429_then_succeeds() -> None:
    from daemon.utils.npm_registry import _get

    client = _mock_client_sequence([
        _mock_resp(429),
        _mock_resp(200, {"downloads": 100}),
    ])
    with patch("httpx.AsyncClient", return_value=client), \
         patch("asyncio.sleep", new=AsyncMock()):
        result = await _get("https://example.com/pkg")

    assert result.status is RegistryLookup.EXISTS
    assert result.data == {"downloads": 100}
    assert client.get.call_count == 2


async def test_get_returns_undetermined_after_exhausting_429_retries() -> None:
    from daemon.utils.npm_registry import _get, _MAX_RATE_LIMIT_RETRIES

    client = _mock_client_sequence([_mock_resp(429)] * (_MAX_RATE_LIMIT_RETRIES + 1))
    with patch("httpx.AsyncClient", return_value=client), \
         patch("asyncio.sleep", new=AsyncMock()):
        result = await _get("https://example.com/pkg")

    assert result.status is RegistryLookup.UNDETERMINED
    assert client.get.call_count == _MAX_RATE_LIMIT_RETRIES + 1


async def test_get_honors_retry_after_header_on_429() -> None:
    from daemon.utils.npm_registry import _get

    client = _mock_client_sequence([
        _mock_resp(429, retry_after="2"),
        _mock_resp(200, {"ok": True}),
    ])
    with patch("httpx.AsyncClient", return_value=client), \
         patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        result = await _get("https://example.com/pkg")

    assert result.status is RegistryLookup.EXISTS
    mock_sleep.assert_awaited_once_with(2.0)


def test_timeout_constant_is_5_seconds() -> None:
    """The module-level _TIMEOUT must be a 5-second httpx.Timeout."""
    from daemon.utils import npm_registry

    assert isinstance(npm_registry._TIMEOUT, httpx.Timeout)
    assert npm_registry._TIMEOUT.read == 5.0


async def test_get_passes_timeout_to_async_client() -> None:
    from daemon.utils.npm_registry import _get, _TIMEOUT

    client = _mock_client(200, {})
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = client
        await _get("https://example.com/check")

    _, kwargs = mock_cls.call_args
    assert kwargs.get("timeout") is _TIMEOUT


# ── get_package_metadata ──────────────────────────────────────────────────────

def _exists(data: dict) -> RegistryResult:
    return RegistryResult(RegistryLookup.EXISTS, data)


async def test_get_package_metadata_success() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        result = await get_package_metadata("lodash")

    assert result.status is RegistryLookup.EXISTS
    assert result.data["name"] == "lodash"
    assert "versions" in result.data


async def test_get_package_metadata_with_version_returns_version_dict() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        result = await get_package_metadata("lodash", version="4.17.21")

    assert result.status is RegistryLookup.EXISTS
    assert result.data["version"] == "4.17.21"


async def test_get_package_metadata_unknown_version_returns_confirmed_absent() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        result = await get_package_metadata("lodash", version="0.0.0")

    assert result.status is RegistryLookup.CONFIRMED_ABSENT


async def test_get_package_metadata_404_returns_confirmed_absent() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch(
        "daemon.utils.npm_registry._get",
        new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT)),
    ):
        result = await get_package_metadata("no-such-package-xyz")

    assert result.status is RegistryLookup.CONFIRMED_ABSENT
    assert result.data is None


async def test_get_package_metadata_undetermined_propagates() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch(
        "daemon.utils.npm_registry._get",
        new=AsyncMock(return_value=RegistryResult(RegistryLookup.UNDETERMINED)),
    ):
        result = await get_package_metadata("flaky-pkg")

    assert result.status is RegistryLookup.UNDETERMINED


async def test_get_package_metadata_confirm_absence_retries_and_recovers() -> None:
    """confirm_absence=True should retry once on CONFIRMED_ABSENT and use the
    fresh result if the retry succeeds."""
    from daemon.utils.npm_registry import get_package_metadata

    side_effects = [
        RegistryResult(RegistryLookup.CONFIRMED_ABSENT),
        _exists(_SAMPLE_REGISTRY_META),
    ]
    with patch("daemon.utils.npm_registry._get", new=AsyncMock(side_effect=side_effects)):
        result = await get_package_metadata("lodash", confirm_absence=True)

    assert result.status is RegistryLookup.EXISTS


async def test_get_package_metadata_confirm_absence_stays_absent() -> None:
    from daemon.utils.npm_registry import get_package_metadata

    with patch(
        "daemon.utils.npm_registry._get",
        new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT)),
    ):
        result = await get_package_metadata("ghost-pkg", confirm_absence=True)

    assert result.status is RegistryLookup.CONFIRMED_ABSENT


async def test_is_security_placeholder_version_matches() -> None:
    from daemon.utils.npm_registry import is_security_placeholder_version

    assert is_security_placeholder_version("0.0.1-security.0") is True
    assert is_security_placeholder_version("1.0.0-security.10") is True


async def test_is_security_placeholder_version_does_not_match() -> None:
    from daemon.utils.npm_registry import is_security_placeholder_version

    assert is_security_placeholder_version("4.2.1") is False
    assert is_security_placeholder_version("") is False
    assert is_security_placeholder_version("1.0.0-beta.1") is False


# ── get_download_count ────────────────────────────────────────────────────────

async def test_get_download_count_success() -> None:
    from daemon.utils.npm_registry import get_download_count

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_exists({"downloads": 50_000_000}))):
        count = await get_download_count("lodash")

    assert count == 50_000_000


async def test_get_download_count_zero_on_404() -> None:
    from daemon.utils.npm_registry import get_download_count

    with patch(
        "daemon.utils.npm_registry._get",
        new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT)),
    ):
        count = await get_download_count("no-such-pkg")

    assert count == 0


async def test_get_download_count_zero_when_field_missing() -> None:
    from daemon.utils.npm_registry import get_download_count

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(return_value=_exists({"period": "last-month"}))):
        count = await get_download_count("weird-pkg")

    assert count == 0


async def test_get_download_count_is_cached_across_repeated_lookups() -> None:
    """Repeated lookups of the same name within the TTL window must not
    re-hit the network — this is what prevents corroboration checks from
    tripping npm's downloads-API rate limit on hot targets (react, lodash,
    etc.) repeated across many typosquat candidates in one scan session."""
    from daemon.utils.npm_registry import get_download_count

    mock_get = AsyncMock(return_value=_exists({"downloads": 42}))
    with patch("daemon.utils.npm_registry._get", new=mock_get):
        first = await get_download_count("react")
        second = await get_download_count("react")

    assert first == 42
    assert second == 42
    mock_get.assert_called_once()


async def test_get_download_count_cache_is_per_name() -> None:
    from daemon.utils.npm_registry import get_download_count

    async def _get_side_effect(url: str):
        if url.endswith("/react"):
            return _exists({"downloads": 100})
        return _exists({"downloads": 200})

    with patch("daemon.utils.npm_registry._get", new=AsyncMock(side_effect=_get_side_effect)):
        react_count = await get_download_count("react")
        lodash_count = await get_download_count("lodash")

    assert react_count == 100
    assert lodash_count == 200


# ── get_direct_dependencies ───────────────────────────────────────────────────

async def test_get_direct_dependencies_exact_version() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        deps = await get_direct_dependencies("lodash", "4.17.21")

    assert deps == {"semver": "^7.0.0"}


async def test_get_direct_dependencies_falls_back_to_latest() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        deps = await get_direct_dependencies("lodash", None)

    assert deps == {"semver": "^7.0.0"}


async def test_get_direct_dependencies_range_version_resolves_to_latest() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        deps = await get_direct_dependencies("lodash", "^4.0.0")

    assert deps == {"semver": "^7.0.0"}


async def test_get_direct_dependencies_returns_empty_on_registry_miss() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT))):
        deps = await get_direct_dependencies("ghost-pkg", "1.0.0")

    assert deps == {}


async def test_get_direct_dependencies_no_deps_field_returns_empty() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"name": "nodeps", "version": "1.0.0"}},
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        deps = await get_direct_dependencies("nodeps", "1.0.0")

    assert deps == {}


async def test_get_direct_dependencies_no_dist_tags_returns_empty() -> None:
    from daemon.utils.npm_registry import get_direct_dependencies

    meta = {
        "dist-tags": {},
        "versions": {"1.0.0": {"dependencies": {"x": "1"}}},
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        deps = await get_direct_dependencies("bad-meta", "^1.0.0")

    assert deps == {}


# ── get_version_history ───────────────────────────────────────────────────────

async def test_get_version_history_returns_sorted_list() -> None:
    from daemon.utils.npm_registry import get_version_history

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        history = await get_version_history("lodash")

    assert len(history) == 2
    assert history[0]["version"] == "4.17.20"
    assert history[1]["version"] == "4.17.21"
    assert isinstance(history[0]["published"], datetime)


async def test_get_version_history_skips_created_modified_keys() -> None:
    from daemon.utils.npm_registry import get_version_history

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        history = await get_version_history("lodash")

    versions = [e["version"] for e in history]
    assert "created" not in versions
    assert "modified" not in versions


async def test_get_version_history_caps_at_max_history() -> None:
    from daemon.utils.npm_registry import get_version_history, _MAX_HISTORY

    many_versions = {str(i): {"name": "x", "version": str(i)} for i in range(20)}
    many_times = {str(i): f"2020-{i % 12 + 1:02d}-01T00:00:00Z" for i in range(20)}
    many_times["created"] = "2019-01-01T00:00:00Z"
    meta = {
        "dist-tags": {"latest": "19"},
        "versions": many_versions,
        "time": many_times,
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        history = await get_version_history("x")

    assert len(history) <= _MAX_HISTORY


async def test_get_version_history_returns_empty_on_registry_miss() -> None:
    from daemon.utils.npm_registry import get_version_history

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT))):
        history = await get_version_history("ghost")

    assert history == []


async def test_get_version_history_skips_bad_timestamps() -> None:
    from daemon.utils.npm_registry import get_version_history

    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {}, "0.9.0": {}},
        "time": {
            "1.0.0": "2021-06-01T00:00:00Z",
            "0.9.0": "NOT-A-DATE",
        },
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        history = await get_version_history("partial")

    assert len(history) == 1
    assert history[0]["version"] == "1.0.0"


async def test_get_version_history_skips_orphaned_time_entries() -> None:
    """Versions in time dict but not in versions dict should be skipped."""
    from daemon.utils.npm_registry import get_version_history

    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {}},
        "time": {
            "1.0.0": "2021-01-01T00:00:00Z",
            "0.5.0": "2020-01-01T00:00:00Z",  # not in versions
        },
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        history = await get_version_history("orphan-test")

    assert len(history) == 1
    assert history[0]["version"] == "1.0.0"


# ── get_previous_version ──────────────────────────────────────────────────────

async def test_get_previous_version_returns_preceding_entry() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        prev = await get_previous_version("lodash", "4.17.21")

    assert prev == "4.17.20"


async def test_get_previous_version_returns_none_for_first_version() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        prev = await get_previous_version("lodash", "4.17.20")

    assert prev is None


async def test_get_previous_version_returns_none_for_missing_version() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        prev = await get_previous_version("lodash", "9.9.9")

    assert prev is None


async def test_get_previous_version_returns_none_for_empty_string() -> None:
    from daemon.utils.npm_registry import get_previous_version

    prev = await get_previous_version("lodash", "")
    assert prev is None


async def test_get_previous_version_returns_none_on_registry_miss() -> None:
    from daemon.utils.npm_registry import get_previous_version

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT))):
        prev = await get_previous_version("ghost", "1.0.0")

    assert prev is None


# ── get_previous_version: purged/unresolvable version walk-back ──────────────
#
# Real-world case: npm's security team purges a malicious version's manifest
# from `versions` but its publish timestamp typically remains in `time`. The
# old exact-match-only lookup could never find such a version's position at
# all, so it always returned None even when a perfectly good predecessor was
# sitting right next to the gap.

def _meta_with_purged_version(purged: str, times: dict, resolvable: set[str]) -> dict:
    return {
        "dist-tags": {"latest": max(resolvable, default="1.0.0")},
        "versions": {v: {} for v in resolvable},
        "time": {"created": "2019-01-01T00:00:00Z", "modified": "2022-01-01T00:00:00Z", **times},
    }


async def test_get_previous_version_walks_past_single_purged_version() -> None:
    from daemon.utils.npm_registry import get_previous_version

    meta = _meta_with_purged_version(
        "2.0.0",
        times={
            "1.0.0": "2020-01-01T00:00:00Z",
            "2.0.0": "2020-02-01T00:00:00Z",  # purged malicious version
            "3.0.0": "2020-03-01T00:00:00Z",
        },
        resolvable={"1.0.0", "3.0.0"},  # 2.0.0 removed from versions
    )
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        prev = await get_previous_version("pkg", "2.0.0")

    assert prev == "1.0.0"


async def test_get_previous_version_walks_past_multiple_purged_versions() -> None:
    """A batch compromise purging several consecutive versions must still
    resolve to the nearest surviving predecessor, not just one step back."""
    from daemon.utils.npm_registry import get_previous_version

    meta = _meta_with_purged_version(
        "3.0.0",
        times={
            "1.0.0": "2020-01-01T00:00:00Z",
            "2.0.0": "2020-02-01T00:00:00Z",  # also purged
            "3.0.0": "2020-03-01T00:00:00Z",  # requested (purged, malicious)
            "4.0.0": "2020-04-01T00:00:00Z",
        },
        resolvable={"1.0.0", "4.0.0"},  # 2.0.0 and 3.0.0 both removed
    )
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        prev = await get_previous_version("pkg", "3.0.0")

    assert prev == "1.0.0"


async def test_get_previous_version_respects_walkback_bound() -> None:
    from daemon.utils.npm_registry import get_previous_version, _MAX_PREDECESSOR_WALKBACK

    # A run of purged versions longer than the walkback bound, with the
    # only resolvable predecessor sitting just past the boundary.
    times = {"0.0.1": "2019-06-01T00:00:00Z"}
    resolvable = {"0.0.1"}
    for i in range(1, _MAX_PREDECESSOR_WALKBACK + 2):
        times[f"1.0.{i}"] = f"2020-01-{i:02d}T00:00:00Z"
    times["9.9.9"] = "2020-02-01T00:00:00Z"  # requested, purged
    meta = _meta_with_purged_version("9.9.9", times=times, resolvable=resolvable)
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        prev = await get_previous_version("pkg", "9.9.9")

    assert prev is None  # only resolvable predecessor is beyond the bound


async def test_get_previous_version_returns_none_when_no_resolvable_predecessor_in_window() -> None:
    from daemon.utils.npm_registry import get_previous_version

    meta = _meta_with_purged_version(
        "2.0.0",
        times={"2.0.0": "2020-02-01T00:00:00Z", "3.0.0": "2020-03-01T00:00:00Z"},
        resolvable={"3.0.0"},  # nothing resolvable before 2.0.0 at all
    )
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        prev = await get_previous_version("pkg", "2.0.0")

    assert prev is None


async def test_get_full_version_timeline_marks_resolvability() -> None:
    from daemon.utils.npm_registry import get_full_version_timeline

    meta = _meta_with_purged_version(
        "2.0.0",
        times={"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2020-02-01T00:00:00Z"},
        resolvable={"1.0.0"},
    )
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        timeline = await get_full_version_timeline("pkg")

    by_version = {e["version"]: e["resolvable"] for e in timeline}
    assert by_version == {"1.0.0": True, "2.0.0": False}


# ── get_package_tarball_info ──────────────────────────────────────────────────

async def test_get_package_tarball_info_success() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        info = await get_package_tarball_info("lodash", "4.17.21")

    assert info is not None
    assert "tarball" in info


async def test_get_package_tarball_info_uses_latest_when_no_version() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        info = await get_package_tarball_info("lodash", None)

    assert info is not None


async def test_get_package_tarball_info_returns_none_on_404() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=RegistryResult(RegistryLookup.CONFIRMED_ABSENT))):
        info = await get_package_tarball_info("ghost", "1.0.0")

    assert info is None


async def test_get_package_tarball_info_returns_none_when_version_not_in_registry() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(_SAMPLE_REGISTRY_META))):
        info = await get_package_tarball_info("lodash", "0.0.0")

    assert info is None


async def test_get_package_tarball_info_returns_none_when_no_dist_tags() -> None:
    from daemon.utils.npm_registry import get_package_tarball_info

    meta = {
        "dist-tags": {},
        "versions": {},
    }
    with patch("daemon.utils.npm_registry.get_package_metadata", new=AsyncMock(return_value=_exists(meta))):
        info = await get_package_tarball_info("nodist", None)

    assert info is None


# ── download_tarball ──────────────────────────────────────────────────────────

def _streaming_client(status: int = 200, chunks: list[bytes] | None = None) -> MagicMock:
    """Return a mock AsyncClient that streams *chunks* as a response body."""
    chunks = chunks or [b"fake tarball data"]

    async def _aiter_bytes(chunk_size: int = 65536):
        for chunk in chunks:
            yield chunk

    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.aiter_bytes = _aiter_bytes
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)

    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


async def test_download_tarball_success_writes_file(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "pkg.tgz")
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [b"hello", b" world"])):
        ok = await download_tarball("https://example.com/pkg.tgz", dest)

    assert ok is True
    assert (tmp_path / "pkg.tgz").read_bytes() == b"hello world"


async def test_download_tarball_non_200_returns_false(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "pkg.tgz")
    with patch("httpx.AsyncClient", return_value=_streaming_client(404)):
        ok = await download_tarball("https://example.com/missing.tgz", dest)

    assert ok is False


async def test_download_tarball_timeout_returns_false(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "pkg.tgz")
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client):
        ok = await download_tarball("https://example.com/slow.tgz", dest)

    assert ok is False


async def test_download_tarball_exceeds_size_cap_returns_false(tmp_path) -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = str(tmp_path / "huge.tgz")
    huge_chunk = b"x" * (26 * 1024 * 1024)  # 26 MiB — over the 25 MiB cap
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [huge_chunk])):
        ok = await download_tarball("https://example.com/huge.tgz", dest)

    assert ok is False


async def test_download_tarball_uses_15_second_timeout() -> None:
    from daemon.utils.npm_registry import download_tarball

    dest = "/dev/null"
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = _streaming_client()
        await download_tarball("https://example.com/pkg.tgz", dest)

    _, kwargs = mock_cls.call_args
    timeout = kwargs.get("timeout")
    assert timeout is not None
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.read == 15.0


# ── Token-bucket rate limiter ──────────────────────────────────────────────────
#
# Tested against a fresh instance, not the module-level singleton (which is
# monkeypatched to a no-op for the rest of the suite — see conftest.py's
# _bypass_npm_rate_limiter).

async def test_token_bucket_allows_burst_up_to_capacity() -> None:
    from daemon.utils.npm_registry import _TokenBucketLimiter

    limiter = _TokenBucketLimiter(rate_per_sec=1.0, capacity=2.0)
    start = time.monotonic()
    await limiter.acquire()
    await limiter.acquire()
    elapsed = time.monotonic() - start

    assert elapsed < 0.05  # two immediate acquires within capacity: no wait


async def test_token_bucket_paces_beyond_capacity() -> None:
    from daemon.utils.npm_registry import _TokenBucketLimiter

    limiter = _TokenBucketLimiter(rate_per_sec=10.0, capacity=1.0)
    start = time.monotonic()
    await limiter.acquire()  # consumes the sole token immediately
    await limiter.acquire()  # must wait ~1/10.0 s for a refill
    elapsed = time.monotonic() - start

    assert elapsed >= 0.08  # allow small scheduling slack below the 0.1s ideal


async def test_token_bucket_refills_over_time() -> None:
    from daemon.utils.npm_registry import _TokenBucketLimiter

    limiter = _TokenBucketLimiter(rate_per_sec=100.0, capacity=1.0)
    await limiter.acquire()
    await asyncio.sleep(0.02)  # ~2 tokens' worth of refill time at 100/s
    start = time.monotonic()
    await limiter.acquire()
    elapsed = time.monotonic() - start

    assert elapsed < 0.01  # token was already available; no additional wait


# ── tarball_has_member ────────────────────────────────────────────────────────

import tarfile as _tarfile_module


def _make_tar_gz(names: list[str], padding_bytes: int = 0) -> bytes:
    """Build an in-memory gzip'd tar containing one small file per name in
    *names*, optionally with an extra padded member to inflate total size."""
    buf = io.BytesIO()
    with _tarfile_module.open(fileobj=buf, mode="w:gz") as tf:
        for name in names:
            data = b"x"
            info = _tarfile_module.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if padding_bytes:
            import os
            data = os.urandom(padding_bytes)  # incompressible, so gzip can't shrink it under the cap
            info = _tarfile_module.TarInfo(name="package/padding.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def test_tarball_has_member_true_when_present() -> None:
    from daemon.utils.npm_registry import tarball_has_member

    tar_bytes = _make_tar_gz(["package/package.json", "package/binding.gyp"])
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [tar_bytes])):
        result = await tarball_has_member("https://example.com/pkg.tgz", frozenset({"binding.gyp"}))

    assert result is True


async def test_tarball_has_member_false_when_absent_clean_eof() -> None:
    from daemon.utils.npm_registry import tarball_has_member

    tar_bytes = _make_tar_gz(["package/package.json", "package/index.js"])
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [tar_bytes])):
        result = await tarball_has_member("https://example.com/pkg.tgz", frozenset({"binding.gyp"}))

    assert result is False


async def test_tarball_has_member_undetermined_on_cap_exceeded() -> None:
    from daemon.utils.npm_registry import tarball_has_member

    tar_bytes = _make_tar_gz(["package/package.json"], padding_bytes=4096)
    with patch("httpx.AsyncClient", return_value=_streaming_client(200, [tar_bytes])):
        result = await tarball_has_member(
            "https://example.com/pkg.tgz", frozenset({"binding.gyp"}), max_bytes=256,
        )

    assert result is None


async def test_tarball_has_member_undetermined_on_non_200() -> None:
    from daemon.utils.npm_registry import tarball_has_member

    with patch("httpx.AsyncClient", return_value=_streaming_client(404)):
        result = await tarball_has_member("https://example.com/missing.tgz", frozenset({"binding.gyp"}))

    assert result is None


async def test_tarball_has_member_undetermined_on_timeout() -> None:
    from daemon.utils.npm_registry import tarball_has_member

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await tarball_has_member("https://example.com/slow.tgz", frozenset({"binding.gyp"}))

    assert result is None
