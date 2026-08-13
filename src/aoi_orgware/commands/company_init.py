"""CLI leaf for creating a read-only legacy company bridge genesis."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aoi_orgware.company.legacy_bridge_init import initialize_legacy_bridge_company

from .company_runtime import CompanyRuntimeCommandError, register_company_runtime_commands


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]
RuntimeHandlers = tuple[Handler, Handler, Handler, Handler, Handler]
_RUNTIME_HANDLER_NAMES = (
    "supervisor_ensure",
    "supervisor_status",
    "supervisor_stop",
    "dashboard_url",
    "dashboard_open",
)


class CompanyInitCommandError(CompanyRuntimeCommandError):
    """The repo-bound company init command was not admitted."""


def cmd_company_init(
    args: argparse.Namespace,
    paths: Any,
    *,
    initializer: Callable[[Path], Any] = initialize_legacy_bridge_company,
) -> int:
    """Run the one supported company init mode and render a secret-free result."""

    if getattr(args, "mode", None) != "legacy-bridge":
        raise CompanyInitCommandError("company init requires --mode legacy-bridge")
    root = getattr(paths, "root", None)
    if not isinstance(root, Path):
        raise CompanyInitCommandError("company init requires one repository root")
    try:
        result = initializer(root)
        payload = result.public_dict()
    except (MemoryError, SystemExit, KeyboardInterrupt, CompanyInitCommandError):
        raise
    except Exception as exc:
        raise CompanyInitCommandError("legacy bridge company init failed") from exc
    if getattr(args, "json", False):
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"company_id: {payload['company_id']}")
        print(f"action: {payload['action']}")
        print("chief_carrier: unknown")
    return 0


def register_company_init_commands(
    subparsers: argparse._SubParsersAction[Any],
    *,
    handlers: dict[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the project-fenced ``company init`` command family."""

    if set(handlers) != {"company_init"}:
        raise CompanyInitCommandError("company init handler registry is invalid")
    company = subparsers.add_parser("company", help="initialize a repo-bound company")
    actions = company.add_subparsers(dest="company_command", required=True)
    init = actions.add_parser("init", help="create or reopen a legacy bridge company")
    init.add_argument("--mode", choices=("legacy-bridge",), required=True)
    add_json_argument(init)
    init.set_defaults(handler=handlers["company_init"])


def register_company_commands(
    subparsers: argparse._SubParsersAction[Any],
    *,
    runtime_handlers: RuntimeHandlers,
    init_handler: Handler,
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Compose runtime and init registrars without hiding CLI handler seams."""

    register_company_runtime_commands(
        subparsers,
        handlers=dict(zip(_RUNTIME_HANDLER_NAMES, runtime_handlers, strict=True)),
        add_json_argument=add_json_argument,
    )
    register_company_init_commands(
        subparsers,
        handlers={"company_init": init_handler},
        add_json_argument=add_json_argument,
    )
