"""Parser registration for User/Chief overrides and Codex resource control.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or domain state
transitions.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any

from ..resource_config import (
    AOI_MAX_DELEGATION_DEPTH,
    ARISE_MAX_THREADS_CEILING,
    OVERRIDE_TARGET_KINDS,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "override_request",
        "override_arbitrate",
        "override_revoke",
        "codex_config_plan",
        "codex_config_apply",
        "codex_config_rollback",
    }
)


def register_resource_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the resource command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "resource command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("override-request")
    parser.add_argument("--task", required=True)
    parser.add_argument("--override-id", required=True)
    parser.add_argument(
        "--target-kind", choices=sorted(OVERRIDE_TARGET_KINDS), required=True
    )
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--target-contract-sha256", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--setting", action="append", default=[], required=True)
    parser.add_argument("--user-rationale", required=True)
    parser.add_argument("--user-evidence", required=True)
    parser.add_argument("--chief-assessment", required=True)
    parser.add_argument("--alternative", action="append", default=[], required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["override_request"])

    parser = subparsers.add_parser("override-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--override-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument("--approved-setting", action="append", default=[])
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--risk-boundary", required=True)
    parser.add_argument("--rollback-condition", required=True)
    parser.add_argument(
        "--compensating-control", action="append", default=[], required=True
    )
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["override_arbitrate"])

    parser = subparsers.add_parser("override-revoke")
    parser.add_argument("--task", required=True)
    parser.add_argument("--override-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["override_revoke"])

    def add_plan_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--task", required=True)
        parser.add_argument("--event-id", required=True)
        parser.add_argument("--override-id", default="")
        parser.add_argument("--execution-selection-id", default="")
        parser.add_argument("--codex-home")
        parser.add_argument("--role", action="append", default=[])
        parser.add_argument(
            "--max-threads",
            type=int,
            default=ARISE_MAX_THREADS_CEILING,
            help="static project ceiling",
        )
        parser.add_argument(
            "--max-depth",
            type=int,
            default=AOI_MAX_DELEGATION_DEPTH,
            help="static project ceiling",
        )

    parser = subparsers.add_parser("codex-config-plan")
    add_plan_arguments(parser)
    parser.add_argument("--proposed-setting", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_config_plan"])

    parser = subparsers.add_parser("codex-config-apply")
    add_plan_arguments(parser)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_config_apply"])

    parser = subparsers.add_parser("codex-config-rollback")
    parser.add_argument("--task", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_config_rollback"])


__all__ = ["register_resource_commands"]
