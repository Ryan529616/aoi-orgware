"""Parser registration for repo bootstrap, task lifecycle, Chief lease, and
pilot-kit commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or task/claim
state-machine handlers.  ``chief-*`` and ``pilot-*`` sit in their own
registrar functions (mirroring ``commands/coordination.py``'s split between
lane-coordination and cross-lane registrars) purely because the CLI's
original ``add_parser`` order interleaves them with a foreign
(codebase-memory) block; callers must invoke all four functions at the exact
positions their original blocks occupied.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any

from ..harnesslib import (
    CHIEF_DEFAULT_TTL_SECONDS,
    RESERVING_CLAIM_STATUSES,
    TASK_PHASES,
    TERMINAL_CLAIM_STATUSES,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_BOOTSTRAP_HANDLER_NAMES = frozenset({"init", "config_check"})

_CHIEF_HANDLER_NAMES = frozenset(
    {
        "chief_acquire",
        "chief_renew",
        "chief_release",
        "chief_takeover",
        "chief_status",
    }
)

_PILOT_HANDLER_NAMES = frozenset({"pilot_init", "pilot_validate", "pilot_summary"})

_HANDLER_NAMES = frozenset(
    {
        "init_task",
        "start_mini",
        "approve_plan",
        "bind_session",
        "unbind_session",
        "import_legacy",
        "check_locks",
        "inspect_legacy",
        "claim",
        "set_claim_status",
        "release_claim",
        "audit_legacy",
        "set_phase",
        "adopt_current_branch",
        "checkpoint",
    }
)


def _check_handlers(names: frozenset[str], handlers: Mapping[str, Handler], label: str) -> None:
    missing = sorted(names - handlers.keys())
    unexpected = sorted(handlers.keys() - names)
    if missing or unexpected:
        raise ValueError(
            f"{label} command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )


def register_bootstrap_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``init`` and ``config-check``."""

    _check_handlers(_BOOTSTRAP_HANDLER_NAMES, handlers, "bootstrap")

    parser = subparsers.add_parser(
        "init", help="initialize AOI in the current Git repository"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--project-name")
    source.add_argument(
        "--config",
        help="initialize from one strictly validated candidate aoi.toml",
    )
    parser.add_argument(
        "--expected-config-sha256",
        help=(
            "required with --config; fail unless it still matches this "
            "approved full SHA-256"
        ),
    )
    parser.add_argument(
        "--replace-policy-sha256",
        help=(
            "replace a reviewed non-packaged managed policy only if its current "
            "full SHA-256 still matches"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["init"])

    parser = subparsers.add_parser(
        "config-check",
        help="validate and summarize a candidate aoi.toml without applying it",
    )
    parser.add_argument("--file", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["config_check"])


def register_chief_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the ``chief-*`` Chief-lease command family."""

    _check_handlers(_CHIEF_HANDLER_NAMES, handlers, "chief")

    parser = subparsers.add_parser(
        "chief-acquire", help="acquire the project Chief lease"
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    parser.add_argument(
        "--credential-home",
        help="optional absolute repo-external credential store root",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_acquire"])

    parser = subparsers.add_parser(
        "chief-renew", help="renew the current Chief lease"
    )
    parser.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_renew"])

    parser = subparsers.add_parser(
        "chief-release", help="release the current Chief lease"
    )
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_release"])

    parser = subparsers.add_parser(
        "chief-takeover",
        help="replace an expired lease or explicitly force replacement of a live lease",
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--expected-epoch", type=int, required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--force-live", action="store_true")
    parser.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    parser.add_argument(
        "--credential-home",
        help="optional absolute repo-external credential store root",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_takeover"])

    parser = subparsers.add_parser(
        "chief-status", help="show non-secret Chief lease status"
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_status"])


def register_pilot_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the ``pilot-*`` closed-alpha tester-kit command family."""

    _check_handlers(_PILOT_HANDLER_NAMES, handlers, "pilot")

    parser = subparsers.add_parser(
        "pilot-init",
        help="create a self-contained closed-alpha tester kit",
        description="create a self-contained closed-alpha tester kit",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--allow-unverified-windows-acl",
        action="store_true",
        help="acknowledge that AOI cannot verify private file ACLs on native Windows",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["pilot_init"])

    parser = subparsers.add_parser(
        "pilot-validate",
        help="strictly validate one sanitized closed-alpha run record",
        description="strictly validate one sanitized closed-alpha run record",
    )
    parser.add_argument("--record", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["pilot_validate"])

    parser = subparsers.add_parser(
        "pilot-summary",
        help="produce a deterministic, de-identified descriptive summary",
        description="produce a deterministic, de-identified descriptive summary",
    )
    parser.add_argument("--record", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--force", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["pilot_summary"])


def register_task_lifecycle_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register task/claim lifecycle commands (init-task through checkpoint)."""

    _check_handlers(_HANDLER_NAMES, handlers, "task lifecycle")

    parser = subparsers.add_parser("init-task")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--completion-boundary", required=True)
    parser.add_argument("--next-action")
    parser.add_argument("--session-id")
    parser.add_argument("--worktree")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["init_task"])

    parser = subparsers.add_parser("start-mini")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--completion-boundary", required=True)
    parser.add_argument("--next-action")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--worktree")
    parser.add_argument("--token", required=True)
    parser.add_argument("--lock", action="append", required=True)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--expires-at", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["start_mini"])

    parser = subparsers.add_parser("approve-plan")
    parser.add_argument("--task", required=True)
    parser.add_argument("--note", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["approve_plan"])

    parser = subparsers.add_parser("bind-session")
    parser.add_argument("--task", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--force", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["bind_session"])

    parser = subparsers.add_parser("unbind-session")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--task")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["unbind_session"])

    parser = subparsers.add_parser("import-legacy")
    parser.add_argument("--source")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["import_legacy"])

    parser = subparsers.add_parser("check-locks")
    parser.add_argument("--lock", action="append", required=True)
    parser.add_argument("--ignore-token")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["check_locks"])

    parser = subparsers.add_parser("inspect-legacy")
    parser.add_argument("--token", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["inspect_legacy"])

    parser = subparsers.add_parser("claim")
    parser.add_argument("--task", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--lock", action="append", default=[], required=True)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--adopt-legacy", action="store_true")
    parser.add_argument("--adoption-evidence")
    parser.add_argument("--ack-legacy-ambiguity", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["claim"])

    parser = subparsers.add_parser("set-claim-status")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--status", choices=sorted(RESERVING_CLAIM_STATUSES), required=True
    )
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["set_claim_status"])

    parser = subparsers.add_parser("release-claim")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--status", choices=sorted(TERMINAL_CLAIM_STATUSES), required=True
    )
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["release_claim"])

    parser = subparsers.add_parser("audit-legacy")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--decision", choices=["still-active", "released", "stale"], required=True
    )
    parser.add_argument("--detail", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["audit_legacy"])

    parser = subparsers.add_parser("set-phase")
    parser.add_argument("--task", required=True)
    parser.add_argument("--phase", choices=sorted(TASK_PHASES), required=True)
    parser.add_argument("--task-status", choices=sorted({"active", "blocked"}))
    parser.add_argument("--summary")
    parser.add_argument("--next-action")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["set_phase"])

    parser = subparsers.add_parser("adopt-current-branch")
    parser.add_argument("--task", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--next-action")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["adopt_current_branch"])

    parser = subparsers.add_parser("checkpoint")
    parser.add_argument("--task", required=True)
    parser.add_argument("--fact", action="append", default=[])
    parser.add_argument("--decision", action="append", default=[])
    parser.add_argument("--rejected", action="append", default=[])
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--blocker", action="append", default=[])
    parser.add_argument("--risk", action="append", default=[])
    parser.add_argument("--next-action")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["checkpoint"])


__all__ = [
    "register_bootstrap_commands",
    "register_chief_commands",
    "register_pilot_commands",
    "register_task_lifecycle_commands",
]
