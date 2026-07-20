"""CLI boundary for local-files one-shot external-export permits."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .. import external_exports
from .. import harnesslib as h


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        import json

        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
        return
    print(payload)


def cmd_external_export_permit_issue(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    authority = getattr(args, "_aoi_chief_authority", None)
    if not isinstance(authority, dict):
        raise h.HarnessError(
            "external export permit issuance requires validated Chief authority"
        )
    result = external_exports.issue_external_export_permit(
        paths,
        task_id=args.task,
        export_id=args.export_id,
        source_file=Path(args.source_file),
        expected_content_sha256=args.expected_content_sha256,
        destination=args.destination,
        purpose=args.purpose,
        expires_at=args.expires_at,
        chief_authority=authority,
        current_time=datetime.now(timezone.utc),
    )
    _emit(result, args.json)
    return 0


def cmd_external_export_permit_consume(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    with h.state_lock(paths, create_layout=False):
        if not paths.config.is_file():
            raise h.HarnessError(
                "aoi.toml disappeared while acquiring the external-export state lock"
            )
        current = h.get_paths(paths.root)
        if (
            current.project.sha256 != paths.project.sha256
            or current.harness != paths.harness
            or current.lock != paths.lock
        ):
            raise h.HarnessError(
                "aoi.toml changed while acquiring the external-export state lock"
            )
        result = external_exports.consume_external_export_permit(
            current,
            task_id=args.task,
            permit_sha256=args.permit_sha256,
            source_file=Path(args.source_file),
            destination=args.destination,
            purpose=args.purpose,
            current_time=datetime.now(timezone.utc),
        )
    _emit(result, args.json)
    return 0


def register_confidentiality_commands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    handlers: dict[str, Callable[..., int]],
    add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    issue = sub.add_parser(
        "external-export-permit-issue",
        help=(
            "Chief-issue one local-only permit for an exact file, destination, "
            "purpose, and expiry"
        ),
    )
    issue.add_argument("--task", required=True)
    issue.add_argument("--export-id", required=True)
    issue.add_argument("--source-file", required=True)
    issue.add_argument("--expected-content-sha256", required=True)
    issue.add_argument("--destination", required=True)
    issue.add_argument("--purpose", required=True)
    issue.add_argument("--expires-at", required=True)
    add_json_argument(issue)
    issue.set_defaults(handler=handlers["external_export_permit_issue"])

    consume = sub.add_parser(
        "external-export-permit-consume",
        help=(
            "spend one exact permit before export; only fresh_consumption=true "
            "authorizes the caller to act"
        ),
    )
    consume.add_argument("--task", required=True)
    consume.add_argument("--permit-sha256", required=True)
    consume.add_argument("--source-file", required=True)
    consume.add_argument("--destination", required=True)
    consume.add_argument("--purpose", required=True)
    add_json_argument(consume)
    consume.set_defaults(handler=handlers["external_export_permit_consume"])


__all__ = [
    "cmd_external_export_permit_consume",
    "cmd_external_export_permit_issue",
    "register_confidentiality_commands",
]
