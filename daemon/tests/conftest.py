"""Shared pytest fixtures for the CIDAS daemon test suite.

Fixtures
--------
async_client         — httpx AsyncClient wired to the FastAPI test app
mock_npm_registry    — patches npm_registry module functions to return canned data
sample_project_path  — tmp_path containing a package.json and a JS file
"""
from __future__ import annotations

import json
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from daemon.main import app
from daemon.utils.npm_registry import RegistryLookup, RegistryResult

# ── Sample registry metadata ──────────────────────────────────────────────────
_SAMPLE_META: dict = {
    "name": "sample-pkg",
    "description": "A sample npm package for testing",
    "dist-tags": {"latest": "1.0.0"},
    "time": {"created": "2020-01-01T00:00:00Z", "modified": "2023-01-01T00:00:00Z"},
    "maintainers": [{"name": "alice"}, {"name": "bob"}],
    "readme": "# sample-pkg\n\nA safe utility package with good documentation.\n" * 10,
    "repository": {"type": "git", "url": "https://github.com/alice/sample-pkg"},
    "versions": {
        "1.0.0": {
            "name": "sample-pkg",
            "version": "1.0.0",
            "description": "A sample npm package for testing",
            "scripts": {"test": "jest"},
            "dist": {"tarball": "https://registry.npmjs.org/sample-pkg/-/sample-pkg-1.0.0.tgz"},
        }
    },
}


@pytest.fixture(autouse=True)
def _reset_npm_metadata_cache():
    """Clear npm_registry's per-package single-flight cache before each test.

    Without this, tests that patch ``_get`` directly (rather than the whole
    ``get_package_metadata``) and reuse a package name like "lodash" across
    test functions could observe a cached result left over from another
    test's mock, since the cache is process-global for the daemon's actual
    request-deduplication purpose.
    """
    from daemon.utils.npm_registry import _clear_download_cache, _clear_metadata_cache
    _clear_metadata_cache()
    _clear_download_cache()
    yield
    _clear_metadata_cache()
    _clear_download_cache()


@pytest.fixture(autouse=True)
def _bypass_npm_rate_limiter(monkeypatch):
    """Disable the real token-bucket pacing around _get() during tests.

    The production limiter deliberately introduces real wall-clock delay to
    stay under npm's rate limit — exactly what we don't want in a fast,
    deterministic test suite that calls the real _get() body (with mocked
    HTTP) dozens of times in a row. Rate-limiter *behavior* itself is
    covered by dedicated unit tests against a fresh _TokenBucketLimiter
    instance, not the shared module-level singleton.
    """
    from daemon.utils import npm_registry

    async def _noop() -> None:
        return None

    monkeypatch.setattr(npm_registry._NPM_RATE_LIMITER, "acquire", _noop)


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """FastAPI test client using ASGI transport (no real network).

    The bearer-token auth dependency is overridden to a no-op for these
    tests — auth itself is exercised in test_auth.py, and forcing every
    router test to manage tokens would obscure the routing assertions.
    """
    from daemon.auth import require_token
    app.dependency_overrides[require_token] = lambda: None
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(require_token, None)


@pytest.fixture
def mock_npm_registry():
    """Patch all npm registry functions to return deterministic test data."""
    with (
        patch(
            "daemon.utils.npm_registry.get_package_metadata",
            new=AsyncMock(return_value=RegistryResult(RegistryLookup.EXISTS, _SAMPLE_META)),
        ),
        patch("daemon.utils.npm_registry.get_download_count", new=AsyncMock(return_value=50_000)),
        patch("daemon.utils.npm_registry.get_package_tarball_info", new=AsyncMock(return_value={"tarball": "https://example.com"})),
        patch("daemon.utils.npm_registry.get_package_size", new=AsyncMock(return_value=12_345)),
        # disk_checker imports get_package_size via `from .npm_registry import
        # get_package_size`, binding its own module-level name — patching
        # npm_registry's attribute above does not affect that binding, so it
        # must be patched separately here.
        patch("daemon.utils.disk_checker.get_package_size", new=AsyncMock(return_value=12_345)),
    ):
        yield _SAMPLE_META


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Authorization header for endpoints that require a bearer token.

    The async_client fixture already bypasses token validation for most tests,
    but passing this header keeps request shapes realistic and lets auth-specific
    tests (test_auth.py) use the same fixture without hardcoding strings.
    """
    return {"Authorization": "Bearer test-token"}


@pytest.fixture
def sample_project_path(tmp_path):
    """A minimal project with package.json and one JS file with imports."""
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps({
            "name": "test-project",
            "dependencies": {
                "react": "^18.0.0",
                "lodash": "^4.17.21",
                "axios": "^1.6.0",
            },
        })
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "index.js").write_text(
        "import React from 'react';\n"
        "import _ from 'lodash';\n"
        "import axios from 'axios';\n"
        "\nexport default function App() { return null; }\n"
    )
    return tmp_path
