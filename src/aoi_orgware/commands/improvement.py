"""Parser registration for improvement requests and skill release/adoption.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the
improvement/skill state-machine handlers.  Choice vocabularies arrive as an
immutable ``ParserVocabulary`` snapshot (built in ``cli.build_parser``) so no
mutable CLI global is imported or re-declared here.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "improvement_create",
        "improvement_brief",
        "improvement_arbitrate",
        "improvement_link_project",
        "skill_release_record",
        "skill_adoption_record",
    }
)


def register_improvement_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the improvement and skill command family on one subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "improvement command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("improvement-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--task-type", required=True)
    parser.add_argument(
        "--trigger-class",
        choices=sorted(vocab.improvement_trigger_classes),
        required=True,
    )
    parser.add_argument("--pain-statement", required=True)
    parser.add_argument("--desired-outcome", required=True)
    parser.add_argument("--occurrence", action="append", default=[], required=True)
    parser.add_argument("--release-blocking", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_create"])

    parser = subparsers.add_parser("improvement-brief")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--option", action="append", default=[], required=True)
    parser.add_argument("--capacity-review-id")
    parser.add_argument("--recommendation", required=True)
    parser.add_argument("--evidence-boundary", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_brief"])

    parser = subparsers.add_parser("improvement-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument(
        "--selected-option", choices=sorted(vocab.improvement_option_ids)
    )
    parser.add_argument("--rationale", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_arbitrate"])

    parser = subparsers.add_parser("improvement-link-project")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--project-task-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_link_project"])

    parser = subparsers.add_parser("skill-release-record")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--skill-id", required=True)
    parser.add_argument("--skill-version", required=True)
    parser.add_argument("--maintenance-owner", required=True)
    parser.add_argument("--rollback-plan", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--validation-receipt", required=True)
    parser.add_argument("--validation-receipt-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["skill_release_record"])

    parser = subparsers.add_parser("skill-adoption-record")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument(
        "--action", choices=sorted(vocab.skill_adoption_actions), required=True
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--evidence-artifact", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    parser.add_argument("--rationale", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["skill_adoption_record"])


__all__ = ["register_improvement_commands"]
