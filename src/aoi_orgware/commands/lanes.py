"""Parser registration for lane lifecycle and lane-dependency commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the lane
state-machine handlers.  Choice vocabularies arrive as an immutable
``ParserVocabulary`` snapshot (built in ``cli.build_parser``) so no mutable CLI
global is imported or re-declared here.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "lane_set_status",
        "lane_create",
        "lane_revise",
        "lane_dependency_add",
        "lane_dependency_update",
    }
)


def register_lane_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the lane command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "lane command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("lane-set-status")
    parser.add_argument("--task", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument(
        "--expected-status", choices=sorted(vocab.lane_statuses), required=True
    )
    parser.add_argument("--status", choices=sorted(vocab.lane_statuses), required=True)
    parser.add_argument("--next-action", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_set_status"])

    parser = subparsers.add_parser("lane-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--kind", choices=sorted(vocab.lane_kinds), required=True)
    parser.add_argument("--status", choices=sorted(vocab.lane_statuses), default="active")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--role", choices=sorted(vocab.role_tier_map), required=True)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--contract-version", required=True)
    parser.add_argument("--generator-version", default="not_applicable")
    parser.add_argument("--adapter-version", default="not_applicable")
    parser.add_argument("--next-action", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_create"])

    parser = subparsers.add_parser("lane-revise")
    parser.add_argument("--task", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument(
        "--change-class",
        choices=sorted(vocab.change_classes - {"genesis"}),
        required=True,
    )
    parser.add_argument("--contract-version", required=True)
    parser.add_argument("--generator-version", required=True)
    parser.add_argument("--adapter-version", required=True)
    parser.add_argument("--next-action", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--coord", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_revise"])

    parser = subparsers.add_parser("lane-dependency-add")
    parser.add_argument("--task", required=True)
    parser.add_argument("--dependency-id", required=True)
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--target-lane", required=True)
    parser.add_argument("--kind", choices=sorted(vocab.dependency_kinds), required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--needed-by-gate")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_dependency_add"])

    parser = subparsers.add_parser("lane-dependency-update")
    parser.add_argument("--task", required=True)
    parser.add_argument("--dependency-id", required=True)
    parser.add_argument(
        "--status", choices=["satisfied", "waived", "superseded"], required=True
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_dependency_update"])


__all__ = ["register_lane_commands"]
