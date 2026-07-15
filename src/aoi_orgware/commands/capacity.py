"""Parser registration for the capacity review command family.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the capacity
review state-machine handlers.  Choice vocabularies arrive as an immutable
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
        "capacity_snapshot",
        "capacity_recommend",
        "capacity_arbitrate",
        "capacity_distribute",
        "capacity_ack",
    }
)


def register_capacity_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the capacity command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "capacity command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("capacity-snapshot")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--capacity-lane-id", required=True)
    parser.add_argument("--target-lane-id", required=True)
    parser.add_argument("--task-type", required=True)
    parser.add_argument(
        "--leaf-role", choices=sorted(vocab.depth_two_roles), required=True
    )
    parser.add_argument("--expected-lane-revision", type=int, required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_snapshot"])

    parser = subparsers.add_parser("capacity-recommend")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--source-packet-id", required=True)
    parser.add_argument(
        "--capability-tier", choices=sorted(vocab.capability_tier_map), required=True
    )
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--risk", required=True)
    parser.add_argument("--confidence-boundary", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_recommend"])

    parser = subparsers.add_parser("capacity-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument("--rationale", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_arbitrate"])

    parser = subparsers.add_parser("capacity-distribute")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_distribute"])

    parser = subparsers.add_parser("capacity-ack")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_ack"])


__all__ = ["register_capacity_commands"]
