"""Parser registration for work-packet lifecycle and subagent-incident commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the packet
state-machine handlers.  ``PACKET_STATUSES`` is a stable constant owned by
``harnesslib`` (imported by ``cli.py`` too, never reassigned there), so it is
imported directly here rather than routed through ``vocab``.  Choice
vocabularies sourced from mutable CLI-local globals (capability tiers, role
tiers) arrive as an immutable ``ParserVocabulary`` snapshot (built in
``cli.build_parser``) so no mutable CLI global is imported or re-declared here.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any

from ..harnesslib import PACKET_STATUSES, PACKET_TYPED_OUTCOMES


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "create_packet",
        "packet_arm",
        "packet_disarm",
        "packet_update",
        "packet_attest_result",
        "subagent_incident_account",
    }
)


def register_packet_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the packet command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "packet command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("create-packet")
    parser.add_argument("--task", required=True)
    parser.add_argument("--packet-id", required=True)
    parser.add_argument("--agent-role", required=True)
    parser.add_argument("--model-tier", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--lock", action="append", default=[])
    parser.add_argument("--deliverable", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--read-first", action="append", default=[])
    parser.add_argument("--lane-id")
    parser.add_argument("--execution-selection-id")
    parser.add_argument("--steward-synthesis-for-selection-id")
    parser.add_argument("--skill-release-id")
    parser.add_argument("--skill-canary-event-id")
    parser.add_argument("--task-type", default="general")
    parser.add_argument("--delegation-depth", type=int, choices=[1, 2], default=1)
    parser.add_argument(
        "--helper-spawn-budget",
        type=int,
        default=0,
        help=(
            "Chief-granted budget (0..8) of depth-two read-only helper spawns this "
            "depth-one packet may make without a per-helper arm"
        ),
    )
    parser.add_argument("--parent-packet-id")
    parser.add_argument(
        "--capability-tier", choices=sorted(vocab.capability_tier_map)
    )
    parser.add_argument("--capacity-decision-id")
    parser.add_argument("--retry-of-packet-id")
    parser.add_argument("--capacity-review-source-id")
    parser.add_argument("--input-artifact", action="append", default=[])
    parser.add_argument(
        "--packet-mode",
        choices=["read_only", "bounded_mutation", "exact_command"],
        default="read_only",
    )
    parser.add_argument("--command-artifact")
    parser.add_argument("--command-sha256")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["create_packet"])

    parser = subparsers.add_parser("packet-arm")
    parser.add_argument("--task", required=True)
    parser.add_argument("--packet-id", required=True)
    agent_type_group = parser.add_mutually_exclusive_group(required=True)
    agent_type_group.add_argument(
        "--expected-agent-type",
        help=(
            "Codex transport agent_type expected from SubagentStart; independent "
            "of the packet's AOI technical role"
        ),
    )
    agent_type_group.add_argument(
        "--any-agent-type",
        action="store_true",
        help=(
            "Arm a wildcard that matches any observed transport agent_type for "
            "this parent session; it owns the whole parent slot"
        ),
    )
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--parent-session-id")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["packet_arm"])

    parser = subparsers.add_parser("packet-disarm")
    parser.add_argument("--task", required=True)
    parser.add_argument("--packet-id", required=True)
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["packet_disarm"])

    parser = subparsers.add_parser("packet-update")
    parser.add_argument("--task", required=True)
    parser.add_argument("--packet-id", required=True)
    parser.add_argument(
        "--status",
        choices=sorted(PACKET_STATUSES - {"ready", "armed"}),
        required=True,
    )
    parser.add_argument("--agent-id")
    parser.add_argument("--actual-role", choices=sorted(vocab.role_tier_map))
    parser.add_argument(
        "--actual-model-tier", choices=sorted(vocab.role_tier_values)
    )
    parser.add_argument("--routing-evidence")
    parser.add_argument("--manual-unverified-reason")
    parser.add_argument("--summary")
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument(
        "--typed-outcome",
        choices=sorted(PACKET_TYPED_OUTCOMES),
        help=(
            "typed technical outcome of a terminal transition; transport "
            "status alone never enters model-quality accounting"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["packet_update"])

    parser = subparsers.add_parser("packet-attest-result")
    parser.add_argument("--task", required=True)
    parser.add_argument("--packet-id", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["packet_attest_result"])

    parser = subparsers.add_parser("subagent-incident-account")
    parser.add_argument("--task", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument(
        "--disposition",
        choices=["no_material_work", "work_discarded", "manual_unverified"],
        required=True,
    )
    parser.add_argument(
        "--disposition-kind",
        choices=[
            "true_positive",
            "false_positive_guard",
            "benign_no_work",
            "unverified",
        ],
        help=(
            "Machine-readable guard-outcome tag recorded alongside the free-text "
            "disposition"
        ),
    )
    parser.add_argument("--reason", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["subagent_incident_account"])


__all__ = ["register_packet_commands"]
