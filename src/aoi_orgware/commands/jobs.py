"""Parser registration for job-start and job-update commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the job
state-machine handlers.  ``JOB_STATUSES`` is a stable constant owned by
``harnesslib`` (imported by ``cli.py`` too, never reassigned there), so it is
imported directly here rather than routed through ``vocab``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any

from ..harnesslib import JOB_STATUSES


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"job_start", "job_update"})


def register_job_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the job command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "job command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("job-start")
    parser.add_argument("--task", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--status", choices=["queued"], default="queued")
    parser.add_argument("--log", required=True)
    parser.add_argument("--pid")
    parser.add_argument("--tmux")
    parser.add_argument("--stop-condition", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-manifest", required=True)
    parser.add_argument("--tool-path", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--success-exit-code", type=int, default=0)
    parser.add_argument("--observed-start-at")
    parser.add_argument("--retroactive-reason")
    parser.add_argument("--lane-id")
    parser.add_argument("--execution-selection-id")
    parser.add_argument("--owner-packet-id")
    parser.add_argument("--skill-release-id")
    parser.add_argument("--skill-canary-event-id")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["job_start"])

    parser = subparsers.add_parser("job-update")
    parser.add_argument("--task", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--status", choices=sorted(JOB_STATUSES), required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--pid")
    parser.add_argument("--tmux")
    parser.add_argument("--terminal-log-artifact")
    parser.add_argument("--terminal-log-sha256")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["job_update"])


__all__ = ["register_job_commands"]
