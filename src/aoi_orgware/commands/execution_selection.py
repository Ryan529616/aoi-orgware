"""Parser registration for execution-selection and execution-brief commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the execution
selection state-machine handlers.  Choice vocabularies arrive as an immutable
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
        "execution_select_plan",
        "execution_select",
        "execution_brief_record",
    }
)


def _add_execution_selection_arguments(
    parser: argparse.ArgumentParser, *, vocab: Any, override_required: bool
) -> None:
    parser.add_argument("--task", required=True)
    parser.add_argument("--selection-id", required=True)
    parser.add_argument("--work-unit-id", required=True)
    parser.add_argument("--supersedes-selection-id")
    parser.add_argument(
        "--mode", choices=sorted(vocab.execution_modes), required=True
    )
    parser.add_argument("--lane", action="append", default=[], required=True)
    parser.add_argument("--steward-lane-id")
    parser.add_argument("--scope", required=True)
    parser.add_argument(
        "--sequential-dependency",
        choices=sorted(vocab.dependency_levels),
        required=True,
    )
    parser.add_argument(
        "--tool-density", choices=sorted(vocab.tool_densities), required=True
    )
    parser.add_argument(
        "--shared-context", choices=sorted(vocab.dependency_levels), required=True
    )
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--falsification-condition", required=True)
    parser.add_argument("--escalation-condition", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--override-id", required=override_required, default="")


def register_execution_selection_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the execution-selection command family on one subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "execution selection command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("execution-select-plan")
    _add_execution_selection_arguments(parser, vocab=vocab, override_required=True)
    parser.add_argument("--proposed-setting", action="append", default=[], required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["execution_select_plan"])

    parser = subparsers.add_parser("execution-select")
    _add_execution_selection_arguments(parser, vocab=vocab, override_required=False)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["execution_select"])

    parser = subparsers.add_parser("execution-brief-record")
    parser.add_argument("--task", required=True)
    parser.add_argument("--brief-id", required=True)
    parser.add_argument("--execution-selection-id", required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--steward-packet-id")
    parser.add_argument("--packet-id", action="append", default=[], required=True)
    parser.add_argument("--cross-lane-session-id", action="append", default=[])
    parser.add_argument("--summary", required=True)
    parser.add_argument("--dissent", required=True)
    parser.add_argument("--blocker", required=True)
    parser.add_argument("--recommendation", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["execution_brief_record"])


__all__ = ["register_execution_selection_commands"]
