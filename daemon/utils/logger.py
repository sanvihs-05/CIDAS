"""Structured logger factory for the CIDAS daemon.

In production (LOG_LEVEL != "debug") emits JSON-formatted log lines suitable
for log aggregators.  In development (LOG_LEVEL == "debug") emits a
human-readable format with colour-coded levels.

Usage::

    from daemon.utils.logger import get_logger
    log = get_logger(__name__)
    log.info("daemon started on port %d", port)
"""
from __future__ import annotations

import json
import logging
import os
import sys

_HUMAN_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class _JsonFormatter(logging.Formatter):
    """Newline-delimited JSON log formatter for production."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _configure_root(log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    root = logging.getLogger()
    if root.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    if log_level.lower() == "debug":
        handler.setFormatter(logging.Formatter(_HUMAN_FORMAT, datefmt=_DATE_FMT))
    else:
        handler.setFormatter(_JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)


# Read LOG_LEVEL directly from env so this module can be imported without
# triggering the full pydantic-settings machinery.
_configure_root(os.environ.get("LOG_LEVEL", "info"))


def get_logger(name: str) -> logging.Logger:
    """Return a named logger; the root handler is configured on first import."""
    return logging.getLogger(name)
