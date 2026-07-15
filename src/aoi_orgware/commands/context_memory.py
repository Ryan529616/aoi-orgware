"""Parser registration for codebase-memory context-receipt and benchmark
commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or the
codebase-memory receipt/benchmark implementation.  ``context-receipt-record``
is grouped here (despite its command name not starting with
``codebase-memory-``) because it is the receipt-provider entry point for the
same codebase-memory subsystem as the two ``codebase-memory-benchmark-*``
commands, and the three are a contiguous block in the original CLI.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any

from ..codebase_memory import FRESHNESS_PROFILES as CODEBASE_MEMORY_FRESHNESS_PROFILES


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "context_receipt_record",
        "codebase_memory_benchmark_validate",
        "codebase_memory_benchmark_record",
    }
)


def register_context_memory_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the codebase-memory context-receipt/benchmark command family."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "context memory command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser(
        "context-receipt-record",
        help="record an immutable optional context-provider receipt",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--provider", choices=["codebase-memory"], required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument(
        "--requirement", choices=["optional", "required"], default="optional"
    )
    parser.add_argument(
        "--freshness-profile",
        choices=sorted(CODEBASE_MEMORY_FRESHNESS_PROFILES),
        default="receipt-only",
    )
    parser.add_argument("--supersedes-receipt-id")
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["context_receipt_record"])

    parser = subparsers.add_parser(
        "codebase-memory-benchmark-validate",
        help="validate one navigation-only codebase-memory A/B record",
    )
    parser.add_argument("--record", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codebase_memory_benchmark_validate"])

    parser = subparsers.add_parser(
        "codebase-memory-benchmark-record",
        help="snapshot and summarize paired navigation-only A/B records",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--benchmark-id", required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--record", action="append", default=[], required=True)
    parser.add_argument("--record-sha256", action="append", default=[], required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codebase_memory_benchmark_record"])


__all__ = ["register_context_memory_commands"]
