"""Tests for the project policy layer.

Covers:
- Policy validator: accepts canonical schema, rejects unknown fields,
  rejects bad types and out-of-range values
- discover() walks up the directory tree
- discover() respects the depth cap
- resolve() merges admin config + project policy with project winning
- Missing policy file falls back to admin config
- Malformed / invalid policy is logged and ignored
- Router integration: block_list → BLOCK, trust_list → ALLOW,
  min_monthly_downloads / require_repository_link penalties
- GET /policy endpoint returns merged values
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from daemon.database import TrustCheckResult, TRUST_STATUS_UNKNOWN
from daemon.models import PillarScore
from daemon.utils import policy as pol


# ── Validator ─────────────────────────────────────────────────────────────────

def test_validator_accepts_canonical_schema():
    data = {
        "version": 1,
        "block_list": ["evil-pkg"],
        "trust_list": ["our-internal-lib"],
        "min_monthly_downloads": 1000,
        "max_sentinel_distance": 1,
        "require_repository_link": True,
        "contextify_weight": 0.20,
    }
    out = pol.validate(data)
    assert out["block_list"] == ["evil-pkg"]
    assert out["trust_list"] == ["our-internal-lib"]
    assert out["contextify_weight"] == 0.20


def test_validator_rejects_unknown_fields():
    data = {"version": 1, "blocklist": ["typo-key"]}  # wrong key
    with pytest.raises(ValidationError):
        pol.validate(data)


def test_validator_rejects_unknown_top_level_keys():
    with pytest.raises(ValidationError):
        pol.validate({"version": 1, "extra_setting": "hi"})


def test_validator_rejects_unsupported_version():
    with pytest.raises(ValidationError):
        pol.validate({"version": 2, "block_list": []})


def test_validator_rejects_bad_contextify_weight_range():
    with pytest.raises(ValidationError):
        pol.validate({"version": 1, "contextify_weight": 0.9})  # > 0.5


def test_validator_rejects_negative_min_downloads():
    with pytest.raises(ValidationError):
        pol.validate({"version": 1, "min_monthly_downloads": -5})


def test_validator_accepts_minimal_policy():
    out = pol.validate({"version": 1})
    assert out["block_list"] == []
    assert out["trust_list"] == []
    assert out["contextify_weight"] is None


def test_get_json_schema_returns_dict():
    schema = pol.get_json_schema()
    assert isinstance(schema, dict)
    assert "properties" in schema
    assert "block_list" in schema["properties"]


# ── discover() ────────────────────────────────────────────────────────────────

def _write_policy(dir_: Path, **overrides) -> Path:
    cidas = dir_ / ".cidas"
    cidas.mkdir(parents=True, exist_ok=True)
    p = cidas / "policy.json"
    p.write_text(json.dumps({"version": 1, **overrides}))
    return p


def test_discover_finds_policy_in_same_directory(tmp_path):
    expected = _write_policy(tmp_path, block_list=["x"])
    found = pol.discover(tmp_path)
    assert found == expected


def test_discover_walks_up_one_level(tmp_path):
    expected = _write_policy(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    found = pol.discover(src)
    assert found == expected


def test_discover_walks_up_multiple_levels(tmp_path):
    expected = _write_policy(tmp_path)
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    found = pol.discover(deep)
    assert found == expected


def test_discover_returns_none_when_no_policy(tmp_path):
    assert pol.discover(tmp_path) is None


def test_discover_returns_none_for_empty_path():
    assert pol.discover("") is None
    assert pol.discover(None) is None


def test_discover_respects_depth_cap(tmp_path, monkeypatch):
    """A policy more than _MAX_WALK_DEPTH levels above must not be found."""
    monkeypatch.setattr(pol, "_MAX_WALK_DEPTH", 2)
    _write_policy(tmp_path)
    deep = tmp_path / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    assert pol.discover(deep) is None


def test_discover_picks_closest_ancestor(tmp_path):
    """When two ancestors have policies, the closest one wins."""
    _write_policy(tmp_path, block_list=["far"])
    inner = tmp_path / "child"
    inner.mkdir()
    expected = _write_policy(inner, block_list=["close"])
    src = inner / "src"
    src.mkdir()
    assert pol.discover(src) == expected


# ── resolve() ─────────────────────────────────────────────────────────────────

def test_resolve_returns_admin_config_when_no_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "get_admin_config", lambda: {"contextify_weight": 0.4})
    merged, source = pol.resolve(tmp_path)
    assert merged == {"contextify_weight": 0.4}
    assert source is None


def test_resolve_project_policy_overrides_admin_config(tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "get_admin_config", lambda: {"contextify_weight": 0.4})
    policy_path = _write_policy(tmp_path, contextify_weight=0.20)
    merged, source = pol.resolve(tmp_path)
    assert merged["contextify_weight"] == 0.20  # project wins
    assert source == policy_path


def test_resolve_admin_keys_survive_when_policy_silent_on_them(tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "get_admin_config", lambda: {
        "bypass_disabled": True,
        "package_file_scan": False,
    })
    _write_policy(tmp_path, block_list=["x"])
    merged, _ = pol.resolve(tmp_path)
    assert merged["bypass_disabled"] is True
    assert merged["package_file_scan"] is False
    assert merged["block_list"] == ["x"]


def test_resolve_invalid_policy_falls_back_gracefully(tmp_path, monkeypatch):
    """A policy that fails validation must be logged and ignored, not raised."""
    monkeypatch.setattr(pol, "get_admin_config", lambda: {})
    cidas = tmp_path / ".cidas"
    cidas.mkdir()
    (cidas / "policy.json").write_text(json.dumps({"version": 1, "blocklist": ["typo"]}))
    merged, source = pol.resolve(tmp_path)
    assert merged == {}
    assert source is None  # invalid → treated as missing


def test_resolve_malformed_json_falls_back_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "get_admin_config", lambda: {})
    cidas = tmp_path / ".cidas"
    cidas.mkdir()
    (cidas / "policy.json").write_text("{not json")
    merged, source = pol.resolve(tmp_path)
    assert merged == {}
    assert source is None


# ── Router integration ───────────────────────────────────────────────────────

_UNKNOWN_TRUST = TrustCheckResult(status=TRUST_STATUS_UNKNOWN, package_name="")


def _ps(score: float = 0.0, flags: list[str] | None = None, metadata: dict | None = None) -> PillarScore:
    return PillarScore(score=score, confidence=0.9, flags=flags or [], metadata=metadata or {})


@pytest.fixture
def mock_db_pillars_audit():
    low = _ps(0.0)
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",      new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router.audit_log.append",  new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=low)),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=low)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=low)),
    ):
        yield


async def test_block_list_overrides_all_pillars(async_client, mock_db_pillars_audit, tmp_path):
    """A package on the block_list is BLOCKed even if every pillar would say ALLOW."""
    _write_policy(tmp_path, block_list=["evil-pkg"])
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "evil-pkg",
        "project_path": str(tmp_path),
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "BLOCK"
    assert body["risk_score"] == 100.0
    assert body["policy_file"] == str(tmp_path / ".cidas" / "policy.json")
    assert "policy_block" in body["contextify"]["flags"]


async def test_block_list_match_does_not_run_pillars(async_client, tmp_path):
    """The pillars must not be invoked when block_list short-circuits."""
    _write_policy(tmp_path, block_list=["evil-pkg"])
    ctx_mock = AsyncMock(return_value=_ps(0.0))
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.audit_log.append",  new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router._contextify.score", new=ctx_mock),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(0.0))),
    ):
        resp = await async_client.post("/api/v1/scan", json={
            "package_name": "evil-pkg", "project_path": str(tmp_path),
        })
    assert resp.status_code == 200
    ctx_mock.assert_not_called()


async def test_trust_list_overrides_all_pillars(async_client, mock_db_pillars_audit, tmp_path):
    """A package on the policy trust_list is ALLOWed without scanning."""
    _write_policy(tmp_path, trust_list=["our-internal-lib"])
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "our-internal-lib",
        "project_path": str(tmp_path),
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] == 0.0
    assert body["policy_file"] == str(tmp_path / ".cidas" / "policy.json")
    assert "policy_trust" in body["contextify"]["flags"]


async def test_no_policy_file_falls_back_gracefully(async_client, mock_db_pillars_audit, tmp_path):
    """When no policy is found, scan proceeds normally and policy_file is null."""
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": str(tmp_path),
    })
    assert resp.status_code == 200
    assert resp.json()["policy_file"] is None


async def test_min_monthly_downloads_adds_penalty_for_ai_suggested(async_client, tmp_path):
    """When ai_suggested=true and downloads < threshold, +15 penalty applies."""
    _write_policy(tmp_path, min_monthly_downloads=10_000)
    sen_meta = {"ai_suggested": True, "monthly_downloads": 50, "has_repository": True}
    sen = _ps(0.0, metadata=sen_meta)
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",      new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router.audit_log.append",  new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=sen)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(0.0))),
    ):
        resp = await async_client.post("/api/v1/scan", json={
            "package_name": "obscure-lib",
            "project_path": str(tmp_path),
            "ai_suggested": True,
        })
    body = resp.json()
    assert body["risk_score"] == 15.0
    assert "policy_low_downloads" in body["sentinel"]["flags"]


async def test_min_monthly_downloads_skipped_when_not_ai_suggested(async_client, tmp_path):
    """The download penalty applies only to AI-suggested packages."""
    _write_policy(tmp_path, min_monthly_downloads=10_000)
    sen_meta = {"ai_suggested": False, "monthly_downloads": 50, "has_repository": True}
    sen = _ps(0.0, metadata=sen_meta)
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",      new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router.audit_log.append",  new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=sen)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(0.0))),
    ):
        resp = await async_client.post("/api/v1/scan", json={
            "package_name": "obscure-lib",
            "project_path": str(tmp_path),
            "ai_suggested": False,
        })
    body = resp.json()
    assert body["risk_score"] == 0.0
    assert "policy_low_downloads" not in body["sentinel"]["flags"]


async def test_require_repository_link_adds_penalty(async_client, tmp_path):
    """A missing repo link adds +10 when the policy requires one."""
    _write_policy(tmp_path, require_repository_link=True)
    sen_meta = {"ai_suggested": False, "monthly_downloads": 100_000, "has_repository": False}
    sen = _ps(0.0, metadata=sen_meta)
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",      new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router.audit_log.append",  new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=sen)),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(0.0))),
    ):
        resp = await async_client.post("/api/v1/scan", json={
            "package_name": "no-repo-pkg",
            "project_path": str(tmp_path),
        })
    body = resp.json()
    assert body["risk_score"] == 10.0
    assert "policy_no_repository" in body["sentinel"]["flags"]


async def test_policy_contextify_weight_overrides_admin(async_client, tmp_path, monkeypatch):
    """Policy's contextify_weight wins over the user's ~/.cidas/config.json."""
    # Admin sets 0.40; policy sets 0.20 — policy must win.
    monkeypatch.setattr(
        "daemon.utils.policy.get_admin_config",
        lambda: {"contextify_weight": 0.40},
    )
    monkeypatch.setattr(
        "daemon.pillars.aggregator.get_admin_config",
        lambda: {"contextify_weight": 0.40},
    )
    _write_policy(tmp_path, contextify_weight=0.20)
    # ctx=100 — with policy weight 0.20 the contribution is 20 (WARN floor),
    # with admin weight 0.40 it would be 40 (above WARN). Verify it's 20.
    with (
        patch("daemon.router.check_trust",       new=AsyncMock(return_value=_UNKNOWN_TRUST)),
        patch("daemon.router.get_cached_result", new=AsyncMock(return_value=None)),
        patch("daemon.router.store_result",      new=AsyncMock()),
        patch("daemon.router.record_allow",      new=AsyncMock()),
        patch("daemon.router.audit_log.append",  new=AsyncMock()),
        patch("daemon.router._contextify.score", new=AsyncMock(return_value=_ps(100.0))),
        patch("daemon.router._sentinel.score",   new=AsyncMock(return_value=_ps(0.0))),
        patch("daemon.router._shield.score",     new=AsyncMock(return_value=_ps(0.0))),
    ):
        resp = await async_client.post("/api/v1/scan", json={
            "package_name": "alien-pkg",
            "project_path": str(tmp_path),
        })
    body = resp.json()
    assert body["risk_score"] == pytest.approx(20.0, rel=0.01)


# ── GET /policy ──────────────────────────────────────────────────────────────

async def test_get_policy_returns_resolved_merged(async_client, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "daemon.utils.policy.get_admin_config",
        lambda: {"bypass_disabled": True},
    )
    _write_policy(tmp_path, block_list=["x"], contextify_weight=0.30)
    resp = await async_client.get(f"/api/v1/policy?project_path={tmp_path}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy_file"] == str(tmp_path / ".cidas" / "policy.json")
    assert body["resolved"]["bypass_disabled"] is True
    assert body["resolved"]["block_list"] == ["x"]
    assert body["resolved"]["contextify_weight"] == 0.30


async def test_get_policy_no_file_returns_null(async_client, tmp_path, monkeypatch):
    monkeypatch.setattr("daemon.utils.policy.get_admin_config", lambda: {})
    resp = await async_client.get(f"/api/v1/policy?project_path={tmp_path}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy_file"] is None
    assert body["resolved"] == {}


async def test_get_policy_missing_query_param_returns_422(async_client):
    resp = await async_client.get("/api/v1/policy")
    assert resp.status_code == 422


# ── warn_requires_confirmation flag propagation ──────────────────────────────

def test_validator_accepts_warn_requires_confirmation():
    out = pol.validate({"version": 1, "warn_requires_confirmation": False})
    assert out["warn_requires_confirmation"] is False


def test_validator_rejects_non_boolean_warn_requires_confirmation():
    with pytest.raises(ValidationError):
        pol.validate({"version": 1, "warn_requires_confirmation": ["maybe"]})


async def test_scan_response_carries_requires_confirmation_when_policy_sets_it(
    async_client, mock_db_pillars_audit, tmp_path,
):
    """A policy with warn_requires_confirmation: true must surface as
    requires_confirmation: true on the ScanResponse."""
    _write_policy(tmp_path, warn_requires_confirmation=True)
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": str(tmp_path),
    })
    assert resp.status_code == 200
    assert resp.json()["requires_confirmation"] is True


async def test_scan_response_requires_confirmation_defaults_to_false(
    async_client, mock_db_pillars_audit, tmp_path,
):
    """No policy / policy silent on the field → requires_confirmation: false."""
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "lodash",
        "project_path": str(tmp_path),
    })
    assert resp.status_code == 200
    assert resp.json()["requires_confirmation"] is False


async def test_block_list_response_also_carries_requires_confirmation(
    async_client, mock_db_pillars_audit, tmp_path,
):
    """The fast-path BLOCK / TRUST short-circuits must still propagate the flag."""
    _write_policy(
        tmp_path,
        block_list=["evil"],
        warn_requires_confirmation=True,
    )
    resp = await async_client.post("/api/v1/scan", json={
        "package_name": "evil",
        "project_path": str(tmp_path),
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "BLOCK"
    assert body["requires_confirmation"] is True


# ── /audit/override accepts an event override ─────────────────────────────────

async def test_audit_override_accepts_user_cancel_event(async_client, tmp_path, monkeypatch):
    """The shim/UX layer can record cancel intent via event=user_cancel_intent."""
    import daemon.utils.audit_log as _al
    monkeypatch.setattr(_al, "_DEFAULT_PATH", tmp_path / "audit.log")
    resp = await async_client.post("/api/v1/audit/override", json={
        "package_name": "lodash",
        "version": "4.17.21",
        "verdict_was": "WARN",
        "event": "user_cancel_intent",
    })
    assert resp.status_code == 200
    assert resp.json()["event"] == "user_cancel_intent"
    import json as _json
    record = _json.loads((tmp_path / "audit.log").read_text().strip())
    assert record["event"] == "user_cancel_intent"


async def test_audit_override_default_event_is_user_override(async_client, tmp_path, monkeypatch):
    import daemon.utils.audit_log as _al
    monkeypatch.setattr(_al, "_DEFAULT_PATH", tmp_path / "audit.log")
    resp = await async_client.post("/api/v1/audit/override", json={
        "package_name": "lodash",
    })
    assert resp.status_code == 200
    assert resp.json()["event"] == "user_override"
