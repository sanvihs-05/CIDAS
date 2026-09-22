"""Project-scoped policy file: ``.cidas/policy.json`` committed in the repo.

Distribution model
------------------
Every developer's daemon is otherwise fully independent (per-user trust list,
per-user admin config, per-machine token).  A security lead has no way to push
team-wide rules.  Rather than running a central policy server, this module
discovers a JSON file inside the project tree — distributed via the same
mechanism the team already uses (git) — and merges its values over the
per-user defaults loaded from ``~/.cidas/config.json``.

Resolution
----------
* For a scan with ``project_path = /path/to/project/src``, walk up the
  directory tree looking for ``.cidas/policy.json``; stop after 10 levels or
  at the filesystem root.
* The first file found wins (closest ancestor); validation errors are logged
  and the file is ignored, so a malformed policy never breaks scans.
* The merged policy is ``{**admin_config, **project_policy}`` — project keys
  override per-user defaults for the scan's contextify weight, and add
  block/trust/quality rules that admin config does not have.

Schema
------
See ``Policy`` (Pydantic model) for the canonical shape.  Unknown fields are
rejected (``extra="forbid"``) so a typo in ``block_list`` is loud rather than
silent.  ``get_json_schema()`` returns the JSON Schema for distribution.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..config import get_admin_config
from .logger import get_logger

log = get_logger(__name__)

POLICY_FILENAME = ".cidas/policy.json"
_MAX_WALK_DEPTH = 10


class Policy(BaseModel):
    """Project policy schema — version 1.

    Unknown fields raise ``ValidationError`` so a misspelled key (``trustList``
    instead of ``trust_list``, ``blocklist`` instead of ``block_list``) fails
    loudly at load time rather than silently doing nothing.
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    block_list: list[str] = Field(default_factory=list)
    trust_list: list[str] = Field(default_factory=list)
    min_monthly_downloads: Optional[int] = Field(default=None, ge=0)
    max_sentinel_distance: Optional[int] = Field(default=None, ge=0)
    require_repository_link: Optional[bool] = None
    contextify_weight: Optional[float] = Field(default=None, ge=0.0, le=0.5)
    warn_requires_confirmation: Optional[bool] = Field(
        default=None,
        description=(
            "When true, the npm shim must prompt the developer to type 'proceed' "
            "before any WARN install proceeds (interactive TTY only).  Surfaced "
            "to the shim via ScanResponse.requires_confirmation."
        ),
    )


def get_json_schema() -> dict:
    """Return the canonical JSON Schema for ``.cidas/policy.json``.

    Useful for editor integrations (VS Code's ``json.schemas`` setting) and
    for ``GET /api/v1/policy/schema`` if added later.
    """
    return Policy.model_json_schema()


def validate(data: dict) -> dict:
    """Validate *data* against the Policy schema; return the canonical dict.

    Raises ``ValidationError`` on unknown fields, wrong types, or
    out-of-range values.
    """
    return Policy.model_validate(data).model_dump(exclude_none=False)


def discover(project_path: str | Path | None) -> Optional[Path]:
    """Walk up from *project_path* looking for ``.cidas/policy.json``.

    Returns the first match found, or ``None`` if no file is reachable within
    ``_MAX_WALK_DEPTH`` levels.  Symlink loops are bounded by the depth cap.
    """
    if not project_path:
        return None
    try:
        start = Path(project_path).resolve()
    except (OSError, ValueError):
        return None

    current = start if start.is_dir() else start.parent
    for _ in range(_MAX_WALK_DEPTH + 1):
        candidate = current / POLICY_FILENAME
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break  # reached filesystem root
        current = current.parent
    return None


def load(path: Path) -> dict:
    """Read *path*, parse JSON, validate against the Policy schema."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return validate(raw)


def resolve(project_path: str | Path | None) -> tuple[dict, Optional[Path]]:
    """Return ``(merged_policy, source_path)`` for the given project.

    The merged dict starts from ``~/.cidas/config.json`` (admin defaults) and
    is overlaid with the discovered project policy — project values win.
    *source_path* is the path of the policy file applied, or ``None`` when
    no file was found (or when it failed to parse).

    Failures are logged and downgraded to "no policy" so a broken file never
    blocks a scan.
    """
    merged: dict = dict(get_admin_config())
    source: Optional[Path] = None

    policy_path = discover(project_path)
    if policy_path is None:
        return merged, None

    try:
        project_policy = load(policy_path)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("policy: cannot read %s: %s — falling back to admin config", policy_path, exc)
        return merged, None
    except ValidationError as exc:
        log.warning("policy: %s failed schema validation: %s — ignoring", policy_path, exc)
        return merged, None

    # Drop None values so they don't blank-out admin defaults.
    overrides = {k: v for k, v in project_policy.items() if v is not None}
    merged.update(overrides)
    source = policy_path
    log.info("policy: applied %s for project %s", policy_path, project_path)
    return merged, source
