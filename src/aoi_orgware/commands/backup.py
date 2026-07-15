"""Parser registration for state-backup commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or its backup
implementation.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"backup_state", "verify_backup"})


def register_backup_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``backup-state`` and ``verify-backup``."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "backup command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("backup-state")
    parser.add_argument("--destination")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["backup_state"])

    parser = subparsers.add_parser("verify-backup")
    parser.add_argument("--manifest", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["verify_backup"])


__all__ = ["register_backup_commands"]
