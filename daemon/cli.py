"""CIDAS command-line tools.

Usage
-----
    python -m daemon.cli audit [--last N] [--verdict ALLOW|WARN|BLOCK]
                               [--package NAME] [--since ISO8601]

Examples
--------
    python -m daemon.cli audit --last 50 --verdict BLOCK
    python -m daemon.cli audit --package lodash
    python -m daemon.cli audit --since 2026-05-01T00:00:00+00:00
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


def _cmd_audit(args: argparse.Namespace) -> None:
    from daemon.utils.audit_log import read_records

    records = asyncio.run(
        read_records(
            last=args.last,
            verdict=args.verdict,
            package=args.package,
            since=args.since,
        )
    )
    if not records:
        print("No matching audit records.", file=sys.stderr)
        return
    for record in records:
        print(json.dumps(record, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m daemon.cli",
        description="CIDAS command-line tools",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    audit_p = sub.add_parser("audit", help="Query the structured audit log")
    audit_p.add_argument(
        "--last",
        type=int,
        default=100,
        metavar="N",
        help="Return the last N records (default: 100, max: 1000)",
    )
    audit_p.add_argument(
        "--verdict",
        choices=["ALLOW", "WARN", "BLOCK"],
        metavar="VERDICT",
        help="Filter by verdict",
    )
    audit_p.add_argument(
        "--package",
        metavar="NAME",
        help="Filter by package name (without version)",
    )
    audit_p.add_argument(
        "--since",
        metavar="ISO8601",
        help="Return only records newer than this ISO-8601 timestamp",
    )

    args = parser.parse_args()
    if args.command == "audit":
        _cmd_audit(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
