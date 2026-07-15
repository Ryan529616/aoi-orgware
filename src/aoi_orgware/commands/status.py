"""Parser registration for read-oriented status/resume/index commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or its status
rendering logic.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"resume", "status", "render_index"})


def register_status_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``resume``, ``status``, and ``render-index``."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "status command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("resume")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--task")
    group.add_argument("--session-id")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["resume"])

    parser = subparsers.add_parser("status")
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--task")
    parser.add_argument("--critical", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["status"])

    parser = subparsers.add_parser("render-index")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["render_index"])


__all__ = ["register_status_commands"]
