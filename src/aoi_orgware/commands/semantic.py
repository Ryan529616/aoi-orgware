"""Explicit semantic-v2 authority, migration, and rollback commands."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable

from .. import cohort_runtime
from .. import cohorts
from .. import harnesslib as h
from .. import permit_runtime as permit_runtime
from .. import semantic_events as semantic
from .. import semantic_store as store


COHORT_ROUND_REQUEST_SCHEMA_VERSION = 1
MAX_COHORT_ROUND_REQUEST_BYTES = 2 * 1024 * 1024
PACKET_ARM_REQUEST_SCHEMA_VERSION = 1
MAX_PACKET_ARM_REQUEST_BYTES = permit_runtime.MAX_PERMIT_TRANSACTION_BYTES


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


def _load_canonical_json_artifact(
    raw_path: str,
    *,
    label: str,
    maximum: int,
) -> Any:
    """Read one exact bounded canonical JSON artifact without link traversal."""

    if not isinstance(raw_path, str) or not raw_path:
        raise h.HarnessError(f"{label} is required")
    requested = Path(raw_path)
    path = requested if requested.is_absolute() else Path.cwd() / requested
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        if canonical != path:
            raise h.HarnessError(f"{label} path is non-canonical")
        h.validate_existing_regular_file(path, label)
        before = path.lstat()
        if (
            h._path_is_link_like(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise h.HarnessError(f"{label} must be one regular non-linked file")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise h.HarnessError(f"{label} changed while being opened")
            raw = handle.read(maximum + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise h.HarnessError(f"{label} is missing") from exc
    except OSError as exc:
        raise h.HarnessError(f"cannot read {label}: {exc}") from exc
    if len(raw) > maximum:
        raise h.HarnessError(f"{label} exceeds its byte bound")
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
        or h.canonicalize_no_link_traversal(path, label) != path
    ):
        raise h.HarnessError(f"{label} changed while being read")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise h.HarnessError(f"{label} has duplicate JSON key {key!r}")
            result[key] = item
        return result

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        canonical_bytes = semantic.canonical_json_bytes(decoded, max_bytes=maximum)
    except h.HarnessError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise h.HarnessError(f"{label} is invalid: {exc}") from exc
    if raw != canonical_bytes:
        raise h.HarnessError(f"{label} must contain exact canonical JSON bytes")
    return decoded


def _load_cohort_round_request(
    raw_path: str, *, require_permit: bool
) -> dict[str, Any]:
    label = "cohort round request"
    decoded = _load_canonical_json_artifact(
        raw_path,
        label=label,
        maximum=MAX_COHORT_ROUND_REQUEST_BYTES,
    )
    common = {"schema_version", "cohort_plan", "wave_index", "arms"}
    expected = common | ({"decision", "permit"} if require_permit else set())
    if not isinstance(decoded, dict) or set(decoded) != expected:
        raise h.HarnessError(f"{label} schema is invalid")
    version = decoded["schema_version"]
    wave_index = decoded["wave_index"]
    arms = decoded["arms"]
    if (
        version != COHORT_ROUND_REQUEST_SCHEMA_VERSION
        or isinstance(version, bool)
        or not isinstance(wave_index, int)
        or isinstance(wave_index, bool)
        or wave_index < 0
        or not isinstance(arms, list)
        or not arms
        or len(arms) > cohorts.MAX_CONCURRENCY
    ):
        raise h.HarnessError(f"{label} values are invalid")
    return decoded


def _load_packet_arm_request(raw_path: str) -> dict[str, Any]:
    label = "packet arm request"
    decoded = _load_canonical_json_artifact(
        raw_path,
        label=label,
        maximum=MAX_PACKET_ARM_REQUEST_BYTES,
    )
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"schema_version", "decision", "permit", "arm"}
        or not isinstance(decoded.get("schema_version"), int)
        or isinstance(decoded.get("schema_version"), bool)
        or decoded.get("schema_version") != PACKET_ARM_REQUEST_SCHEMA_VERSION
    ):
        raise h.HarnessError(f"{label} schema is invalid")
    return decoded


def _write_canonical_stdout(value: Any, *, maximum: int) -> None:
    raw = semantic.canonical_json_bytes(value, max_bytes=maximum)
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(raw.decode("utf-8"))
        sys.stdout.flush()
        return
    stream.write(raw)
    stream.flush()


def _load_permit_transaction(raw_path: str) -> dict[str, Any]:
    """Read one exact bounded canonical detached permit transaction artifact."""

    maximum = max(
        permit_runtime.MAX_PERMIT_TRANSACTION_BYTES,
        permit_runtime.MAX_COHORT_PERMIT_TRANSACTION_BYTES,
    )

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
            raw = handle.read(maximum + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise h.HarnessError("permit transaction file is missing") from exc
    except OSError as exc:
        raise h.HarnessError(f"cannot read permit transaction file: {exc}") from exc
    if len(raw) > maximum:
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
        version = decoded.get("schema_version") if isinstance(decoded, dict) else None
        if version == permit_runtime.PERMIT_TRANSACTION_SCHEMA_VERSION:
            transaction = permit_runtime.validate_permitted_arm_transaction(decoded)
            transaction_maximum = permit_runtime.MAX_PERMIT_TRANSACTION_BYTES
        elif version == permit_runtime.COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION:
            transaction = permit_runtime.validate_permitted_cohort_transaction(
                decoded
            )
            transaction_maximum = (
                permit_runtime.MAX_COHORT_PERMIT_TRANSACTION_BYTES
            )
        else:
            raise h.HarnessError(
                "permit transaction schema version is unsupported"
            )
        canonical_bytes = semantic.canonical_json_bytes(
            transaction, max_bytes=transaction_maximum
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
    raw_session_id = authority.get("session_id")
    if not isinstance(raw_session_id, str):
        raise h.HarnessError("permit issuer Chief session is invalid")
    session_id = h.validate_id(
        raw_session_id, "permit issuer Chief session"
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
    issue = (
        permit_runtime.issue_permitted_cohort_transaction
        if transaction["schema_version"]
        == permit_runtime.COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION
        else permit_runtime.issue_permitted_arm_transaction
    )
    kwargs: dict[str, Any] = {}
    if issue is permit_runtime.issue_permitted_arm_transaction:
        from .. import cli as core_cli

        kwargs["validate_packet_arm_preimage"] = (
            core_cli._validate_packet_arm_preimage
        )
    result = issue(
        paths,
        transaction,
        store.load_semantic_events(paths, task_id),
        chief_session_id=session_id,
        chief_epoch=epoch,
        chief_token=token,
        current_time=datetime.now(timezone.utc),
        **kwargs,
    )
    _emit(result, args.json)
    return 0


def cmd_permit_consume(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    transaction = _load_permit_transaction(args.transaction_file)
    task_id = _require_transaction_task(args, transaction)
    with h.state_lock(paths, create_layout=False):
        paths = _reload_permit_paths(paths)
        commit = (
            permit_runtime.commit_permitted_cohort_transaction
            if transaction["schema_version"]
            == permit_runtime.COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION
            else permit_runtime.commit_permitted_arm_transaction
        )
        kwargs: dict[str, Any] = {}
        if commit is permit_runtime.commit_permitted_arm_transaction:
            from .. import cli as core_cli

            kwargs["validate_packet_arm_preimage"] = (
                core_cli._validate_packet_arm_preimage
            )
        result = commit(
            paths,
            transaction,
            store.load_semantic_events(paths, task_id),
            current_time=datetime.now(timezone.utc),
            **kwargs,
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


def cmd_cohort_round_preview(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    task_id = h.validate_id(args.task, "task id")
    request = _load_cohort_round_request(args.request_file, require_permit=False)
    result = cohort_runtime.preview_cohort_round(
        paths,
        task_id,
        store.load_semantic_events(paths, task_id),
        request["cohort_plan"],
        wave_index=request["wave_index"],
        arms=request["arms"],
    )
    _emit(result, args.json)
    return 0


def cmd_packet_arm_prepare(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    """Emit one detached packet-owning semantic-v2 arm transaction."""

    task_id = h.validate_id(args.task, "task id")
    request = _load_packet_arm_request(args.request_file)
    transaction = permit_runtime.prepare_permitted_arm_transaction(
        task_id=task_id,
        event_chain=store.load_semantic_events(paths, task_id),
        decision=request["decision"],
        permit=request["permit"],
        arm=request["arm"],
        command_id=args.command_id,
        recorded_at=args.recorded_at,
    )
    _write_canonical_stdout(
        transaction,
        maximum=permit_runtime.MAX_PERMIT_TRANSACTION_BYTES,
    )
    return 0


def cmd_cohort_round_prepare(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    task_id = h.validate_id(args.task, "task id")
    request = _load_cohort_round_request(args.request_file, require_permit=True)
    decision_parameters = (
        request["decision"].get("parameters")
        if isinstance(request["decision"], dict)
        else None
    )
    permit_parameters = (
        request["permit"].get("parameters")
        if isinstance(request["permit"], dict)
        else None
    )
    if (
        not isinstance(decision_parameters, dict)
        or not isinstance(permit_parameters, dict)
        or decision_parameters.get("wave_index") != request["wave_index"]
        or permit_parameters.get("wave_index") != request["wave_index"]
    ):
        raise h.HarnessError(
            "cohort round request wave_index differs from its decision or permit"
        )
    transaction = permit_runtime.prepare_permitted_cohort_transaction(
        paths,
        task_id=task_id,
        event_chain=store.load_semantic_events(paths, task_id),
        decision=request["decision"],
        permit=request["permit"],
        cohort_plan=request["cohort_plan"],
        arms=request["arms"],
        command_id=args.command_id,
        recorded_at=args.recorded_at,
    )
    _write_canonical_stdout(
        transaction,
        maximum=permit_runtime.MAX_COHORT_PERMIT_TRANSACTION_BYTES,
    )
    return 0


def cmd_cohort_show(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    decoded = _load_canonical_json_artifact(
        args.cohort_file,
        label="cohort plan file",
        maximum=MAX_COHORT_ROUND_REQUEST_BYTES,
    )
    try:
        plan = cohorts.validate_cohort(decoded)
    except cohorts.CohortError as exc:
        raise h.HarnessError(f"cohort plan file is invalid: {exc}") from exc
    result = cohort_runtime.derive_cohort_status(
        paths,
        task_id,
        store.load_semantic_events(paths, task_id),
        plan,
    )
    _emit(result, args.json)
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

    arm_prepare = sub.add_parser(
        "packet-arm-prepare",
        help="emit one canonical detached packet-owning arm transaction",
    )
    arm_prepare.add_argument("--task", required=True)
    arm_prepare.add_argument("--request-file", required=True)
    arm_prepare.add_argument("--command-id", required=True)
    arm_prepare.add_argument("--recorded-at", required=True)
    arm_prepare.set_defaults(handler=handlers["packet_arm_prepare"])

    preview = sub.add_parser(
        "cohort-round-preview",
        help="preview one exact eligible cohort wave without launching it",
    )
    preview.add_argument("--task", required=True)
    preview.add_argument("--request-file", required=True)
    add_json_argument(preview)
    preview.set_defaults(handler=handlers["cohort_round_preview"])

    prepare = sub.add_parser(
        "cohort-round-prepare",
        help="emit one canonical detached permitted cohort transaction",
    )
    prepare.add_argument("--task", required=True)
    prepare.add_argument("--request-file", required=True)
    prepare.add_argument("--command-id", required=True)
    prepare.add_argument("--recorded-at", required=True)
    prepare.set_defaults(handler=handlers["cohort_round_prepare"])

    show = sub.add_parser(
        "cohort-show",
        help="derive cohort status from the authenticated routing ledger",
    )
    show.add_argument("--task", required=True)
    show.add_argument("--cohort-file", required=True)
    add_json_argument(show)
    show.set_defaults(handler=handlers["cohort_show"])
