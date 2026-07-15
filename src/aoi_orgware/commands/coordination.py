"""Parser registration for cross-lane sessions, user escalations, coordination
requests, and baseline freezes.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the domain
state-machine handlers.  Choice vocabularies arrive as an immutable
``ParserVocabulary`` snapshot (built in ``cli.build_parser``) so no mutable CLI
global is imported or re-declared here.

This domain is registered through TWO public functions rather than one,
because its original ``add_parser`` blocks are not contiguous in ``cli.py``:
the resource-override and lane registrar calls sit between the
cross-lane/needs-user block and the coordination-request/baseline-freeze
block.  ``build_parser`` calls both functions at the exact positions their
source blocks originally occupied, preserving top-level ``aoi --help``
registration order.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_CROSS_LANE_HANDLER_NAMES = frozenset(
    {
        "cross_lane_open",
        "cross_lane_close",
        "cross_lane_cancel",
        "needs_user_create",
        "needs_user_resolve",
    }
)

_COORDINATION_HANDLER_NAMES = frozenset(
    {
        "coordination_create",
        "coordination_update",
        "coordination_arbitrate",
        "coordination_directive_ack",
        "coordination_resolve",
        "coordination_implementation_submit",
        "coordination_verify",
        "baseline_freeze",
    }
)


def register_cross_lane_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register cross-lane session and needs-user escalation commands."""

    missing = sorted(_CROSS_LANE_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _CROSS_LANE_HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "cross-lane command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("cross-lane-open")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cross-lane-session-id", required=True)
    parser.add_argument("--execution-selection-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument(
        "--participant-lane", action="append", default=[], required=True
    )
    parser.add_argument("--topic", required=True)
    parser.add_argument("--evidence-boundary", required=True)
    parser.add_argument("--expires-at", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["cross_lane_open"])

    parser = subparsers.add_parser("cross-lane-close")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cross-lane-session-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--conclusion", required=True)
    parser.add_argument("--dissent", required=True)
    parser.add_argument("--blocker", required=True)
    parser.add_argument("--evidence", action="append", default=[], required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["cross_lane_close"])

    parser = subparsers.add_parser("cross-lane-cancel")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cross-lane-session-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["cross_lane_cancel"])

    parser = subparsers.add_parser("needs-user-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--escalation-id", required=True)
    parser.add_argument(
        "--category", choices=sorted(vocab.needs_user_categories), required=True
    )
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--problem", required=True)
    parser.add_argument("--option", action="append", default=[], required=True)
    parser.add_argument("--evidence", action="append", default=[], required=True)
    parser.add_argument("--chief-recommendation", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["needs_user_create"])

    parser = subparsers.add_parser("needs-user-resolve")
    parser.add_argument("--task", required=True)
    parser.add_argument("--escalation-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--user-decision", required=True)
    parser.add_argument("--user-evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["needs_user_resolve"])


def register_coordination_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register coordination-request and baseline-freeze commands."""

    missing = sorted(_COORDINATION_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _COORDINATION_HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "coordination command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("coordination-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--target-lane", required=True)
    parser.add_argument(
        "--severity", choices=sorted(vocab.dependency_kinds), required=True
    )
    parser.add_argument("--request", required=True)
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--evidence", action="append", default=[], required=True)
    parser.add_argument("--option", action="append", default=[])
    parser.add_argument("--needed-by-gate")
    parser.add_argument(
        "--change-class",
        choices=sorted(vocab.change_classes - {"genesis"}),
        default="same_contract_implementation",
    )
    parser.add_argument(
        "--closure-category",
        choices=sorted(vocab.close_qualifying_categories),
        default="integration_test",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_create"])

    parser = subparsers.add_parser("coordination-update")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument(
        "--status", choices=["acknowledged", "countered"], required=True
    )
    parser.add_argument("--response", required=True)
    parser.add_argument("--evidence", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_update"])

    parser = subparsers.add_parser("coordination-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--selected-option")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_arbitrate"])

    parser = subparsers.add_parser("coordination-directive-ack")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--directive-id", required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_directive_ack"])

    parser = subparsers.add_parser("coordination-resolve")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_resolve"])

    parser = subparsers.add_parser("coordination-implementation-submit")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--claim-token", required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument(
        "--evidence-category",
        choices=sorted(vocab.close_qualifying_categories),
        required=True,
    )
    parser.add_argument("--command", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument("--evidence-artifact", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_implementation_submit"])

    parser = subparsers.add_parser("coordination-verify")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--verifier-lane", required=True)
    parser.add_argument(
        "--category", choices=sorted(vocab.close_qualifying_categories), required=True
    )
    parser.add_argument("--status", choices=["pass", "fail"], required=True)
    parser.add_argument("--test-oracle", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument("--evidence-artifact", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_verify"])

    parser = subparsers.add_parser("baseline-freeze")
    parser.add_argument("--task", required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--contract-version", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--lane", action="append", default=[])
    parser.add_argument("--coord", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["baseline_freeze"])


__all__ = ["register_cross_lane_commands", "register_coordination_commands"]
