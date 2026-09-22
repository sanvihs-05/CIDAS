"""Tests for daemon.utils.llm_verifier — secondary prompt-injection verification.

Coverage targets
----------------
101-105  non-200 HTTP status
110-112  ValueError from resp.json() (malformed HTTP body)
122      TypeError when Ollama content is not a string
125-129  inner JSONDecodeError → _extract_json_object; outer except handler
143-144  else branch: low-confidence / no injection → llm_score=0
162-173  _extract_json_object() helper (all three branches)
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from daemon.utils.llm_verifier import (
    _MAX_README_CHARS,
    _extract_json_object,
    verify_with_llm,
)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _make_settings(
    *,
    ollama_host: str = "http://localhost:11434",
    ollama_model: str = "phi3:mini",
) -> MagicMock:
    """Return a minimal Settings stand-in with only the fields llm_verifier reads."""
    s = MagicMock()
    s.ollama_host = ollama_host
    s.ollama_model = ollama_model
    return s


class _FakeResponse:
    """Minimal httpx.Response stand-in."""

    def __init__(
        self,
        status_code: int = 200,
        body: object = None,
        *,
        raise_on_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self.text = ""
        self._body = body
        self._raise_on_json = raise_on_json

    def json(self) -> object:
        if self._raise_on_json:
            raise ValueError("not valid json")
        return self._body


def _ollama_body(
    contains_injection: bool,
    confidence: float,
    patterns: list[str] | None = None,
    reasoning: str = "test reasoning",
) -> dict:
    """Build a dict mimicking Ollama /api/chat JSON response."""
    inner = json.dumps({
        "contains_injection": contains_injection,
        "confidence": confidence,
        "detected_patterns": patterns or [],
        "reasoning": reasoning,
    })
    return {"message": {"role": "assistant", "content": inner}}


def _client_class(response: object):
    """Return a fake AsyncClient class whose post() always returns *response*."""
    class _Client:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **kw): return response
    return _Client


# ── Network / HTTP-level failures (lines 101-112) ────────────────────────────

@pytest.mark.asyncio
async def test_returns_fallback_when_ollama_not_running() -> None:
    """ConnectError → fallback dict with llm_unavailable, no exception raised."""
    class _BoomClient:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **kw):
            raise httpx.ConnectError("connection refused")

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _BoomClient),
    ):
        result = await verify_with_llm("test-pkg", "some readme", 30.0, [])

    assert result["llm_score"] == 0.0
    assert "llm_unavailable" in result["llm_flags"]


@pytest.mark.asyncio
async def test_returns_fallback_on_non_200_status() -> None:
    """HTTP 503 from Ollama → log warning and return standard fallback dict."""
    resp = _FakeResponse(status_code=503, body={})

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "some readme", 30.0, [])

    assert result["llm_score"] == 0.0
    assert "llm_unavailable" in result["llm_flags"]
    assert result["confirmed"] is False


@pytest.mark.asyncio
async def test_returns_fallback_on_malformed_json() -> None:
    """resp.json() raises ValueError → fallback returned, no exception propagated."""
    resp = _FakeResponse(status_code=200, raise_on_json=True)

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "some readme", 30.0, [])

    assert result["llm_score"] == 0.0
    assert "llm_unavailable" in result["llm_flags"]


# ── Scoring threshold paths (lines 137-144) ───────────────────────────────────

@pytest.mark.asyncio
async def test_low_confidence_sets_score_zero() -> None:
    """contains_injection=True but confidence=0.5 ≤ threshold (0.7) → llm_score==0."""
    resp = _FakeResponse(status_code=200, body=_ollama_body(True, 0.5))

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "bad readme", 30.0, [])

    # Confidence too low → else branch: llm_score=0, flags=[]
    assert result["llm_score"] == 0.0
    assert result["llm_flags"] == []
    assert result["confirmed"] is False


@pytest.mark.asyncio
async def test_high_confidence_sets_correct_score() -> None:
    """contains_injection=True, confidence=0.9 > threshold → llm_score==90.0."""
    resp = _FakeResponse(status_code=200, body=_ollama_body(True, 0.9))

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "bad readme", 30.0, [])

    assert result["llm_score"] == pytest.approx(90.0)
    assert "llm_injection_confirmed" in result["llm_flags"]
    assert result["confirmed"] is True


# ── Input handling ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_readme_truncated_to_8kb() -> None:
    """README longer than _MAX_README_CHARS is truncated before sending to Ollama."""
    long_readme = "X" * 20_000
    captured: dict = {}

    class _CapturingClient:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, _url, *, json: dict, **kw):
            captured.update(json)
            return _FakeResponse(status_code=200, body=_ollama_body(False, 0.0))

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _CapturingClient),
    ):
        await verify_with_llm("test-pkg", long_readme, 30.0, [])

    user_content: str = captured["messages"][1]["content"]
    # 20 000 X's truncated to _MAX_README_CHARS; next char would be another X
    assert "X" * (_MAX_README_CHARS + 1) not in user_content, (
        "README was not truncated to _MAX_README_CHARS"
    )
    assert "X" * _MAX_README_CHARS in user_content, (
        "README excerpt shorter than _MAX_README_CHARS — truncated too aggressively"
    )


@pytest.mark.asyncio
async def test_detected_patterns_become_flags() -> None:
    """Each entry in detected_patterns becomes an 'llm_pattern:<name>' flag."""
    patterns = ["ignore_instructions", "persona_shift"]
    resp = _FakeResponse(
        status_code=200,
        body=_ollama_body(True, 0.9, patterns=patterns),
    )

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "bad readme", 30.0, [])

    assert "llm_pattern:ignore_instructions" in result["llm_flags"]
    assert "llm_pattern:persona_shift" in result["llm_flags"]
    assert "llm_injection_confirmed" in result["llm_flags"]


@pytest.mark.asyncio
async def test_readme_in_user_message_not_system() -> None:
    """README text must appear in the user role message, never in the system prompt."""
    readme = "UNIQUE_CANARY_TEXT_98765"
    captured_messages: list = []

    class _CapturingClient:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, _url, *, json: dict, **kw):
            captured_messages.extend(json["messages"])
            return _FakeResponse(status_code=200, body=_ollama_body(False, 0.0))

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _CapturingClient),
    ):
        await verify_with_llm("test-pkg", readme, 30.0, [])

    system_msg = next(m for m in captured_messages if m["role"] == "system")
    user_msg   = next(m for m in captured_messages if m["role"] == "user")

    assert readme not in system_msg["content"], "README leaked into system prompt"
    assert readme in user_msg["content"],       "README missing from user message"


# ── Model-reply parse paths (lines 118-129) ──────────────────────────────────

@pytest.mark.asyncio
async def test_content_not_string_returns_fallback() -> None:
    """content field is a dict (not str) → TypeError at line 122 → fallback returned."""
    bad_body = {"message": {"role": "assistant", "content": {"not": "a string"}}}
    resp = _FakeResponse(status_code=200, body=bad_body)

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "readme", 30.0, [])

    assert result["llm_score"] == 0.0
    assert "llm_unavailable" in result["llm_flags"]


@pytest.mark.asyncio
async def test_content_not_json_returns_fallback() -> None:
    """Content string with no JSON at all → inner JSONDecodeError, extraction fails,
    outer except handler at line 127 returns fallback."""
    bad_body = {"message": {"role": "assistant", "content": "not json at all"}}
    resp = _FakeResponse(status_code=200, body=bad_body)

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "readme", 30.0, [])

    assert result["llm_score"] == 0.0
    assert "llm_unavailable" in result["llm_flags"]


@pytest.mark.asyncio
async def test_model_wraps_json_in_prose() -> None:
    """Content wraps valid JSON in prose → inner JSONDecodeError at line 125 triggers
    _extract_json_object() fallback at line 126 which succeeds; result parsed normally."""
    inner = json.dumps({
        "contains_injection": True,
        "confidence": 0.85,
        "detected_patterns": [],
        "reasoning": "found adversarial content",
    })
    # Model wraps the JSON in markdown code fences
    prose_content = f"Here is my analysis:\n```json\n{inner}\n```"
    prose_body = {"message": {"role": "assistant", "content": prose_content}}
    resp = _FakeResponse(status_code=200, body=prose_body)

    with (
        patch("daemon.utils.llm_verifier.get_settings", return_value=_make_settings()),
        patch("daemon.utils.llm_verifier.httpx.AsyncClient", _client_class(resp)),
    ):
        result = await verify_with_llm("test-pkg", "readme", 30.0, [])

    assert result["llm_score"] == pytest.approx(85.0)
    assert "llm_injection_confirmed" in result["llm_flags"]


# ── _extract_json_object unit tests (lines 162-173) ──────────────────────────

def test_extract_json_object_balanced() -> None:
    """Prose surrounding a balanced JSON object → object is extracted correctly."""
    text = 'Some prefix text. {"key": "value", "n": 42} Some suffix.'
    assert _extract_json_object(text) == '{"key": "value", "n": 42}'


def test_extract_json_object_nested_braces() -> None:
    """Nested objects are handled correctly by the depth counter."""
    text = 'Result: {"outer": {"inner": 1}}'
    assert _extract_json_object(text) == '{"outer": {"inner": 1}}'


def test_extract_json_object_no_braces() -> None:
    """No curly braces at all → original text returned unchanged (line 163-164)."""
    text = "no braces here whatsoever"
    assert _extract_json_object(text) == text


def test_extract_json_object_unbalanced() -> None:
    """Opening brace with no matching close → text from first brace onward (line 173)."""
    text = 'prefix {"unclosed object'
    result = _extract_json_object(text)
    assert result == '{"unclosed object'
