"""Local bearer-token authentication for mutating endpoints.

The daemon listens on 127.0.0.1, but any process running as the same user can
still reach it. This module gates mutating routes behind a per-user token so a
random local process cannot whitelist a malicious package via /trust.

Threat model
------------
- The token lives at ~/.cidas/daemon.token with mode 0600 (owner read/write).
- Any code that can read that file is already running as the user and could
  forge the request anyway — auth raises the bar from "read a port" to
  "read a file the OS keeps from other users".
- We compare with secrets.compare_digest to avoid timing side-channels.

Public API
----------
get_or_create_token() — generate (or reuse) the on-disk token; called at startup.
require_token        — FastAPI dependency; reject when Authorization header
                       is missing or does not match the expected token.
TOKEN_PATH           — module-level path constant (overridable via monkeypatch
                       in tests or the CIDAS_TOKEN_FILE env var).
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Header, HTTPException, status

from .utils.logger import get_logger

log = get_logger(__name__)

# Resolved at import time so tests can monkeypatch this attribute directly.
TOKEN_PATH: Path = Path(
    os.environ.get("CIDAS_TOKEN_FILE")
    or (Path.home() / ".cidas" / "daemon.token")
)

# Cached after first read so each request does not hit the filesystem.
_cached_token: str | None = None


def get_or_create_token() -> str:
    """Return the on-disk token, generating it on first run.

    The file is written atomically with mode 0600 so other local users cannot
    read it. Subsequent calls reuse the cached value to avoid repeated I/O.
    """
    global _cached_token

    path = TOKEN_PATH
    if path.exists():
        token = path.read_text().strip()
        if token:
            _cached_token = token
            return token
        # Empty file → regenerate. Falls through to write path below.

    token = secrets.token_hex(32)  # 64 hex chars = 256 bits of entropy
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write via a temp file + os.replace for atomicity, with mode 0600 set
    # before any data is written so the secret is never world-readable.
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(token)
    except Exception:
        try: tmp.unlink()
        except OSError: pass
        raise
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)  # belt-and-braces in case of umask quirks
    except OSError:
        pass

    _cached_token = token
    log.info("auth: generated new daemon token at %s", path)
    return token


def reset_cache() -> None:
    """Clear the in-memory token cache. Used by tests."""
    global _cached_token
    _cached_token = None


def _expected_token() -> str:
    """Return the active token, loading from disk on first access."""
    if _cached_token is not None:
        return _cached_token
    return get_or_create_token()


async def require_token(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: reject requests without a valid bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header (expected 'Bearer <token>').",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[len("Bearer "):].strip()
    expected = _expected_token()
    if not secrets.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid daemon token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
