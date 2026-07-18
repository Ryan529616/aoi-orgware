"""Explicit semantic-v2 authority, migration, and rollback commands."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable

from .. import harnesslib as h
from .. import permit_runtime as permit_runtime
from .. import semantic_events as semantic
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


def _load_permit_transaction(raw_path: str) -> dict[str, Any]:
    """Read one exact bounded canonical detached permit transaction artifact."""

    if not isinstance(raw_path, str) or not raw_path:
        raise h.HarnessError("permit transaction file is required")
    requested = Path(raw_path)
    path = requested if requested.is_absolute() else Path.cwd() / requested
    try:
        canonical = h.canonicalize_no_link_traversal(path, "permit transaction file")
        if canonical != path:
            raise h.HarnessError("permit transaction file path is non-canonical")
        h.validate_existing_regular_file(path, "permit transaction file")
        before = path.lstat()
        if (
            h._path_is_link_like(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise h.HarnessError(
                "permit transaction file must be one regular non-linked file"
            )
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise h.HarnessError(
                    "permit transaction file changed while being opened"
                )
            raw = handle.read(permit_runtime.MAX_PERMIT_TRANSACTION_BYTES + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise h.HarnessError("permit transaction file is missing") from exc
    except OSError as exc:
        raise h.HarnessError(f"cannot read permit transaction file: {exc}") from exc
    if len(raw) > permit_runtime.MAX_PERMIT_TRANSACTION_BYTES:
        raise h.HarnessError("permit transaction file exceeds its byte bound")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity
        != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(raw) != finished.st_size
        or h.canonicalize_no_link_traversal(path, "permit transaction file") != path
    ):
        raise h.HarnessError("permit transaction file changed while being read")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise h.HarnessError(
                    f"permit transaction has duplicate JSON key {key!r}"
                )
            result[key] = item
        return result

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        transaction = permit_runtime.validate_permitted_arm_transaction(decoded)
        canonical_bytes = semantic.canonical_json_bytes(
            transaction, max_bytes=permit_runtime.MAX_PERMIT_TRANSACTION_BYTES
        )
    except h.HarnessError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise h.HarnessError(f"permit transaction file is invalid: {exc}") from exc
    if raw != canonical_bytes:
        raise h.HarnessError(
            "permit transaction file must contain exact canonical JSON bytes"
        )
    return transaction


def _require_transaction_task(
    args: argparse.Namespace, transaction: dict[str, Any]
) -> str:
    task_id = h.validate_id(args.task, "task id")
    if transaction["task_id"] != task_id:
        raise h.HarnessError("permit transaction belongs to another task")
    return task_id


def _permit_issue_secret(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> tuple[str, int, str]:
    authority = getattr(args, "_aoi_chief_authority", None)
    if not isinstance(authority, dict):
        raise h.HarnessError("permit issue requires validated Chief authority")
    session_id = h.validate_id(
        authority.get("session_id"), "permit issuer Chief session"
    )
    epoch = authority.get("epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise h.HarnessError("permit issuer Chief epoch is invalid")
    explicit_token = getattr(args, "chief_token", None)
    raw_file = getattr(args, "chief_credential_file", None)
    if explicit_token and raw_file:
        raise h.HarnessError(
            "use either a Chief credential file or explicit token, not both"
        )
    if explicit_token:
        token = explicit_token
    else:
        token, _credential_path = h.load_chief_credential(
            paths,
            session_id=session_id,
            epoch=epoch,
            credential_file=Path(raw_file) if raw_file else None,
        )
    if not isinstance(token, str) or not token:
        raise h.HarnessError("permit issuer Chief token is unavailable")
    return session_id, epoch, token


def _reload_permit_paths(paths: h.HarnessPaths) -> h.HarnessPaths:
    if not paths.config.is_file():
        raise h.HarnessError(
            "aoi.toml disappeared while acquiring the permit state lock"
        )
    current = h.get_paths(paths.root)
    if (
        current.project.sha256 != paths.project.sha256
        or current.harness != paths.harness
        or current.lock != paths.lock
    ):
        raise h.HarnessError("aoi.toml changed while acquiring the permit state lock")
    return current


def cmd_permit_issue(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    transaction = _load_permit_transaction(args.transaction_file)
    task_id = _require_transaction_task(args, transaction)
    session_id, epoch, token = _permit_issue_secret(args, paths)
    result = permit_runtime.issue_permitted_arm_transaction(
        paths,
        transaction,
        store.load_semantic_events(paths, task_id),
        chief_session_id=session_id,
        chief_epoch=epoch,
        chief_token=token,
        current_time=datetime.now(timezone.utc),
    )
    _emit(result, args.json)
    return 0


def cmd_permit_consume(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    transaction = _load_permit_transaction(args.transaction_file)
    task_id = _require_transaction_task(args, transaction)
    with h.state_lock(paths, create_layout=False):
        paths = _reload_permit_paths(paths)
        result = permit_runtime.commit_permitted_arm_transaction(
            paths,
            transaction,
            store.load_semantic_events(paths, task_id),
            current_time=datetime.now(timezone.utc),
        )
        head = store.semantic_head(paths, task_id)
    event = result["event"]
    binding = result["binding"]
    permit_object = next(
        wrapped
        for wrapped in transaction["objects"]
        if wrapped["object_type"] == "transition_permit"
    )
    _emit(
        {
            "task_id": task_id,
            "permit_sha256": permit_object["payload"]["permit_sha256"],
            "binding_sha256": binding["binding_sha256"],
            "consumption_identity": binding["binding_key"],
            "event_sha256": event["event_sha256"],
            "result_projection_sha256": event["result_projection_sha256"],
            "semantic_head_sha256": head["event_sha256"],
            "idempotent_replay": result["idempotent_replay"],
        },
        args.json,
    )
    return 0


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

    issue = sub.add_parser(
        "permit-issue",
        help="Chief-issue one exact detached semantic-v2 transition permit",
    )
    issue.add_argument("--task", required=True)
    issue.add_argument("--transaction-file", required=True)
    add_json_argument(issue)
    issue.set_defaults(handler=handlers["permit_issue"])

    consume = sub.add_parser(
        "permit-consume",
        help="consume one Chief-issued detached semantic-v2 transition permit",
    )
    consume.add_argument("--task", required=True)
    consume.add_argument("--transaction-file", required=True)
    add_json_argument(consume)
    consume.set_defaults(handler=handlers["permit_consume"])
