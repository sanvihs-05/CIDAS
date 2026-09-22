"""Tests for daemon.cli — the `audit` subcommand.

The CLI calls asyncio.run() internally, so every test here is sync (no async
def). The underlying read_records coroutine is mocked at the module level so
no real filesystem access or event-loop nesting occurs.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from daemon.cli import _cmd_audit, main

# ── sample data ───────────────────────────────────────────────────────────────

_RECORDS = [
    {
        "ts": "2026-05-01T10:00:00Z",
        "package": "lodash@4.17.21",
        "verdict": "ALLOW",
        "score": 5.0,
    },
    {
        "ts": "2026-05-02T10:00:00Z",
        "package": "evil-pkg@1.0.0",
        "verdict": "BLOCK",
        "score": 95.0,
    },
    {
        "ts": "2026-05-03T10:00:00Z",
        "package": "axios@1.6.0",
        "verdict": "WARN",
        "score": 45.0,
    },
]


def _run(*argv: str, records: list | None = None) -> None:
    """Invoke main() with mocked sys.argv and mocked read_records."""
    if records is None:
        records = list(_RECORDS)
    with (
        patch("sys.argv", ["daemon.cli", *argv]),
        patch(
            "daemon.utils.audit_log.read_records",
            new=AsyncMock(return_value=records),
        ),
    ):
        main()


# ── no subcommand ─────────────────────────────────────────────────────────────

def test_no_subcommand_exits_with_code_1(capsys) -> None:
    with patch("sys.argv", ["daemon.cli"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == 1


def test_no_subcommand_prints_help(capsys) -> None:
    with patch("sys.argv", ["daemon.cli"]):
        with pytest.raises(SystemExit):
            main()
    captured = capsys.readouterr()
    assert "audit" in captured.out


# ── audit — success paths ─────────────────────────────────────────────────────

def test_audit_prints_all_records_as_json(capsys) -> None:
    _run("audit")
    captured = capsys.readouterr()
    # Each record is pretty-printed with indent=2; count "package" occurrences.
    assert captured.out.count('"package"') == len(_RECORDS)


def test_audit_output_is_valid_json_objects(capsys) -> None:
    """Each record must deserialise to a dict with expected keys."""
    _run("audit")
    captured = capsys.readouterr()
    # json.dumps with indent=2 emits multi-line objects; reconstruct with a
    # streaming decoder to handle multiple top-level objects in one string.
    decoder = json.JSONDecoder()
    output = captured.out.strip()
    pos = 0
    objects: list[dict] = []
    while pos < len(output):
        # Skip whitespace between objects
        while pos < len(output) and output[pos] in " \n\r\t":
            pos += 1
        if pos >= len(output):
            break
        obj, end = decoder.raw_decode(output, pos)
        objects.append(obj)
        pos = end
    assert len(objects) == len(_RECORDS)
    for obj in objects:
        assert "package" in obj
        assert "verdict" in obj


def test_audit_last_default_is_passed_to_read_records(capsys) -> None:
    """--last defaults to 100 and is forwarded to read_records."""
    mock_rr = AsyncMock(return_value=list(_RECORDS))
    with (
        patch("sys.argv", ["daemon.cli", "audit"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    mock_rr.assert_awaited_once()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("last") == 100


def test_audit_custom_last_is_forwarded(capsys) -> None:
    mock_rr = AsyncMock(return_value=list(_RECORDS))
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--last", "5"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("last") == 5


def test_audit_verdict_filter_is_forwarded(capsys) -> None:
    mock_rr = AsyncMock(return_value=[_RECORDS[1]])
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--verdict", "BLOCK"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("verdict") == "BLOCK"


def test_audit_package_filter_is_forwarded(capsys) -> None:
    mock_rr = AsyncMock(return_value=[_RECORDS[0]])
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--package", "lodash"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("package") == "lodash"


def test_audit_since_filter_is_forwarded(capsys) -> None:
    ts = "2026-05-02T00:00:00+00:00"
    mock_rr = AsyncMock(return_value=_RECORDS[1:])
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--since", ts]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("since") == ts


def test_audit_verdict_allow_is_a_valid_choice(capsys) -> None:
    mock_rr = AsyncMock(return_value=[_RECORDS[0]])
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--verdict", "ALLOW"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("verdict") == "ALLOW"


def test_audit_verdict_warn_is_a_valid_choice(capsys) -> None:
    mock_rr = AsyncMock(return_value=[_RECORDS[2]])
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--verdict", "WARN"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    _, kwargs = mock_rr.call_args
    assert kwargs.get("verdict") == "WARN"


def test_audit_invalid_verdict_exits_nonzero(capsys) -> None:
    """argparse should reject an unknown verdict value."""
    with (
        patch("sys.argv", ["daemon.cli", "audit", "--verdict", "UNKNOWN"]),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code != 0


# ── audit — empty result ──────────────────────────────────────────────────────

def test_audit_empty_records_prints_to_stderr(capsys) -> None:
    mock_rr = AsyncMock(return_value=[])
    with (
        patch("sys.argv", ["daemon.cli", "audit"]),
        patch("daemon.utils.audit_log.read_records", new=mock_rr),
    ):
        main()
    captured = capsys.readouterr()
    assert "No matching audit records" in captured.err
    assert captured.out == ""


# ── _cmd_audit directly ───────────────────────────────────────────────────────

def test_cmd_audit_direct_call(capsys) -> None:
    """Test _cmd_audit() by constructing a Namespace directly."""
    import argparse

    args = argparse.Namespace(last=10, verdict="BLOCK", package=None, since=None)
    with patch(
        "daemon.utils.audit_log.read_records",
        new=AsyncMock(return_value=[_RECORDS[1]]),
    ):
        _cmd_audit(args)
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["verdict"] == "BLOCK"
    assert data["package"] == "evil-pkg@1.0.0"


def test_cmd_audit_all_filters_combined(capsys) -> None:
    import argparse

    args = argparse.Namespace(
        last=50,
        verdict="ALLOW",
        package="lodash",
        since="2026-05-01T00:00:00Z",
    )
    with patch(
        "daemon.utils.audit_log.read_records",
        new=AsyncMock(return_value=[_RECORDS[0]]),
    ) as mock_rr:
        _cmd_audit(args)
    _, kwargs = mock_rr.call_args
    assert kwargs["last"] == 50
    assert kwargs["verdict"] == "ALLOW"
    assert kwargs["package"] == "lodash"
    assert kwargs["since"] == "2026-05-01T00:00:00Z"
