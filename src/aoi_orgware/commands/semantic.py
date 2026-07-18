"""Explicit semantic-v2 authority, migration, and rollback commands."""

from __future__ import annotations

import argparse
import json
from typing import Any, Callable

from .. import harnesslib as h
from .. import semantic_store as store


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def _authority_ref(args: argparse.Namespace) -> str:
    value = str(getattr(args, "_aoi_authority_ref", "") or "")
    if not value:
        raise h.HarnessError("semantic mutation requires validated Chief authority")
    return value


def cmd_semantic_head(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        head = store.semantic_head(paths, task_id)
        integrity_errors = store.semantic_integrity_errors(paths, task_id)
        if integrity_errors:
            raise h.HarnessError(
                "semantic authority is invalid: " + "; ".join(integrity_errors)
            )
        receipt = None
        try:
            receipt = store.validate_semantic_migration(paths, task_id)
        except store.SemanticStoreError as exc:
            if "does not have a legacy migration genesis" not in str(exc):
                raise
            receipt = None
        rolled_back = store.semantic_migration_rolled_back(paths, task_id)
    payload = {
        "task_id": task_id,
        **head,
        "semantic_authority_status": (
            "inert_rollback_archive" if rolled_back else "active"
        ),
        "migration_receipt_sha256": (
            receipt["migration_receipt_sha256"] if receipt else ""
        ),
    }
    _emit(payload, args.json)
    return 0


def cmd_semantic_migrate(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    command_id = h.validate_id(args.command_id, "semantic command id")
    with h.state_lock(paths, create_layout=False):
        result = store.migrate_legacy_task(
            paths,
            task_id,
            command_id=command_id,
            expected_legacy_sha256=args.expected_legacy_state_sha256,
            recorded_at=h.now_iso(),
            authority_ref=_authority_ref(args),
        )
        receipt = store.validate_semantic_migration(paths, task_id)
        h.write_index(paths)
    _emit(
        {
            "task_id": task_id,
            "head_event_sha256": result.event["event_sha256"],
            "migration_receipt_sha256": receipt["migration_receipt_sha256"],
            "legacy_snapshot_sha256": receipt["legacy_snapshot_sha256"],
            "idempotent_replay": result.idempotent_replay,
        },
        args.json,
    )
    return 0


def cmd_semantic_migration_rollback(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    task_id = h.validate_id(args.task, "task id")
    command_id = h.validate_id(args.command_id, "semantic rollback command id")
    with h.state_lock(paths, create_layout=False):
        marker, replay = store.rollback_semantic_migration(
            paths,
            task_id,
            command_id=command_id,
            expected_head_sha256=args.expected_head_sha256,
            expected_migration_receipt_sha256=(
                args.expected_migration_receipt_sha256
            ),
            recorded_at=h.now_iso(),
            authority_ref=_authority_ref(args),
        )
        h.write_index(paths)
    _emit(
        {
            "task_id": task_id,
            "rollback_sha256": marker["rollback_sha256"],
            "legacy_snapshot_sha256": marker["legacy_snapshot_sha256"],
            "idempotent_replay": replay,
            "semantic_history": "inert_preserved_archive",
        },
        args.json,
    )
    return 0


def register_semantic_commands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    handlers: dict[str, Callable[..., int]],
    add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    head = sub.add_parser("semantic-head", help="show the authenticated semantic head")
    head.add_argument("--task", required=True)
    add_json_argument(head)
    head.set_defaults(handler=handlers["semantic_head"])

    migrate = sub.add_parser(
        "semantic-migrate", help="migrate one quiescent legacy task to semantic-v2"
    )
    migrate.add_argument("--task", required=True)
    migrate.add_argument("--command-id", required=True)
    migrate.add_argument("--expected-legacy-state-sha256", required=True)
    add_json_argument(migrate)
    migrate.set_defaults(handler=handlers["semantic_migrate"])

    rollback = sub.add_parser(
        "semantic-migration-rollback",
        help="restore exact legacy bytes before any post-genesis transition",
    )
    rollback.add_argument("--task", required=True)
    rollback.add_argument("--command-id", required=True)
    rollback.add_argument("--expected-head-sha256", required=True)
    rollback.add_argument("--expected-migration-receipt-sha256", required=True)
    add_json_argument(rollback)
    rollback.set_defaults(handler=handlers["semantic_migration_rollback"])
