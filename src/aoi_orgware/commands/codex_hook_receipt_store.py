"""Governed preview, application, and CLI for receipt generation rotation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .. import codex_hook_receipts as receipts
from .. import harnesslib as h
from .codex_hook_receipt_store_contract import (
    CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION,
    MAX_CODEX_HOOK_RECEIPT_GENERATIONS,
    CodexHookReceiptError,
    codex_hook_receipts_v2_dir,
    _ROTATION_MODES,
    _canonical_metadata_bytes,
    _require_sha256,
    _require_operation_id,
    _validate_authority_ref,
    _read_private_json,
    _ensure_private_directory,
    _create_or_verify_metadata,
    _v2_control_path,
    _v2_operations_dir,
    _v2_generations_dir,
    _generation_dir,
    _adoption_marker_path,
    _validate_directory,
    _legacy_inventory_locked,
    _inventory_summary,
    _ensure_store_directory,
    _validate_control,
    _validate_intent,
    _validate_marker,
    _validate_generation,
    _validate_seal,
    _successor_generation_id,
    _rotation_preview_record,
    _validate_preview,
    _build_control,
    _build_intent,
    _build_marker,
    _build_generation,
    _build_seal,
    _load_control_locked,
    _load_intents_locked,
    _read_generation_metadata_locked,
    _scan_generation_locked,
    _validate_committed_v2_locked,
    _pending_operation_locked,
)

JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]
READ_ONLY_COMMANDS = receipts.READ_ONLY_COMMANDS


def _same_logical_chief(
    stored: Mapping[str, Any], current: Mapping[str, Any]
) -> bool:
    """Compare the stable authority identity, not renewable lease metadata."""

    return (
        stored["session_id"] == current["session_id"]
        and stored["epoch"] == current["epoch"]
    )


def _uncommitted_adoption_intent_locked(
    paths: h.HarnessPaths,
    *,
    operation_id: str,
) -> dict[str, Any] | None:
    """Validate the only benign pre-intent/adoption staging prefixes."""

    root = _validate_directory(
        codex_hook_receipts_v2_dir(paths), "receipt store v2 directory"
    )
    members = sorted(item.name for item in root.iterdir())
    if members not in ([], ["operations"], ["generations", "operations"]):
        raise CodexHookReceiptError(
            "receipt_rotation_pending: v2 adoption staging is not an exact prefix"
        )
    intents: dict[str, dict[str, Any]] = {}
    if "operations" in members:
        intents = _load_intents_locked(
            paths, allow_empty_operation_id=operation_id
        )
        if set(intents) - {operation_id}:
            raise CodexHookReceiptError(
                "receipt_rotation_pending: another adoption operation owns staging"
            )
    intent = intents.get(operation_id)
    if intent is not None and intent["mode"] != "adopt-v1":
        raise CodexHookReceiptError("uncommitted v2 staging is not an adoption")
    if "generations" in members:
        generation_root = _validate_directory(
            _v2_generations_dir(paths), "receipt generations directory"
        )
        generation_ids = sorted(item.name for item in generation_root.iterdir())
        if intent is None:
            if generation_ids:
                raise CodexHookReceiptError(
                    "receipt_rotation_pending: generation staging precedes its intent"
                )
        else:
            allowed = {
                CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION,
                str(intent["successor_generation_id"]),
            }
            if not set(generation_ids).issubset(allowed):
                raise CodexHookReceiptError(
                    "receipt rotation staging contains an unrelated generation"
                )
            for generation_id in generation_ids:
                generation_dir = _validate_directory(
                    _generation_dir(paths, generation_id),
                    "receipt generation directory",
                )
                generation_members = sorted(
                    item.name for item in generation_dir.iterdir()
                )
                allowed_members = (
                    {"generation.json", "seal.json"}
                    if generation_id == CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION
                    else {"generation.json", "receipts"}
                )
                if not set(generation_members).issubset(allowed_members):
                    raise CodexHookReceiptError(
                        "receipt rotation staging has unexpected generation entries"
                    )
                receipts_dir = generation_dir / "receipts"
                if receipts_dir.exists() or h._path_is_link_like(receipts_dir):
                    _records, total, entries = _scan_generation_locked(
                        paths, generation_id
                    )
                    if entries or total:
                        raise CodexHookReceiptError(
                            "uncommitted successor generation is not empty"
                        )
    marker_path = _adoption_marker_path(paths)
    if marker_path.exists() or h._path_is_link_like(marker_path):
        if intent is None:
            raise CodexHookReceiptError(
                "receipt store adoption marker exists without its operation intent"
            )
        marker = _validate_marker(
            _read_private_json(marker_path, "receipt store adoption marker")
        )
        if (
            marker["operation_id"] != operation_id
            or marker["legacy_inventory"] != intent["source_inventory"]
            or marker["successor_generation_id"]
            != intent["successor_generation_id"]
            or marker["preview_sha256"] != intent["preview_sha256"]
            or marker["expected_control_sha256"]
            != intent["expected_control_sha256"]
        ):
            raise CodexHookReceiptError(
                "receipt store adoption marker conflicts with its operation intent"
            )
    return intent


def _preview_rotation_locked(
    paths: h.HarnessPaths, *, mode: str, operation_id: str
) -> dict[str, Any]:
    if mode not in _ROTATION_MODES:
        raise CodexHookReceiptError("receipt rotation mode is invalid")
    operation_id = _require_operation_id(operation_id)
    control = _load_control_locked(paths)
    root = codex_hook_receipts_v2_dir(paths)
    if control is None:
        if mode != "adopt-v1":
            raise CodexHookReceiptError("rotate-v2 requires an adopted v2 receipt store")
        if root.exists() or h._path_is_link_like(root):
            intent = _uncommitted_adoption_intent_locked(
                paths, operation_id=operation_id
            )
            if intent is not None:
                return _validate_preview(
                    _rotation_preview_record(
                        mode=intent["mode"],
                        operation_id=intent["operation_id"],
                        source_control_sha256=intent["source_control_sha256"],
                        source_control_revision=intent["source_control_revision"],
                        source_generation_id=intent["source_generation_id"],
                        source_inventory=intent["source_inventory"],
                        successor_generation_id=intent["successor_generation_id"],
                    )
                )
        marker_path = _adoption_marker_path(paths)
        if marker_path.exists() or h._path_is_link_like(marker_path):
            marker = _validate_marker(
                _read_private_json(marker_path, "receipt store adoption marker")
            )
            if marker["operation_id"] != operation_id:
                raise CodexHookReceiptError(
                    "receipt_rotation_pending: exact adoption resume is required"
                )
        _records, source_inventory, _entries = _legacy_inventory_locked(
            paths, allow_adoption_marker=marker_path.exists()
        )
        source_revision = 0
        source_control_sha256 = None
        source_generation_id = CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION
    else:
        control, intents, generations = _validate_committed_v2_locked(
            paths,
            full_inventory=True,
            allow_pending_operation=operation_id,
            allow_staging_operation=operation_id,
        )
        if operation_id in control["applied_operations"]:
            intent = intents[operation_id]
            if intent["mode"] != mode:
                raise CodexHookReceiptError(
                    "receipt rotation replay mode conflicts with durable truth"
                )
            return _validate_preview(
                _rotation_preview_record(
                    mode=intent["mode"],
                    operation_id=intent["operation_id"],
                    source_control_sha256=intent["source_control_sha256"],
                    source_control_revision=intent["source_control_revision"],
                    source_generation_id=intent["source_generation_id"],
                    source_inventory=intent["source_inventory"],
                    successor_generation_id=intent["successor_generation_id"],
                )
            )
        if mode != "rotate-v2":
            raise CodexHookReceiptError("adopt-v1 is valid only before v2 adoption")
        if len(control["generation_ids"]) >= MAX_CODEX_HOOK_RECEIPT_GENERATIONS:
            raise CodexHookReceiptError("receipt generation retention limit is exhausted")
        pending = _pending_operation_locked(control, intents)
        if pending is not None and pending != operation_id:
            raise CodexHookReceiptError(
                "receipt_rotation_pending: exact operation resume is required"
            )
        source_generation_id = control["active_generation_id"]
        _records, total, entries = _scan_generation_locked(paths, source_generation_id)
        source_inventory = _inventory_summary(entries, total)
        if pending is not None:
            intent = intents[pending]
            if intent["source_inventory"] != source_inventory:
                raise CodexHookReceiptError("pending rotation source inventory drifted")
            return _validate_preview(
                _rotation_preview_record(
                    mode=intent["mode"],
                    operation_id=intent["operation_id"],
                    source_control_sha256=intent["source_control_sha256"],
                    source_control_revision=intent["source_control_revision"],
                    source_generation_id=intent["source_generation_id"],
                    source_inventory=intent["source_inventory"],
                    successor_generation_id=intent["successor_generation_id"],
                )
            )
        source_revision = control["control_revision"]
        source_control_sha256 = control["control_sha256"]
        if generations[source_generation_id]["metadata"]["generation_id"] != source_generation_id:
            raise CodexHookReceiptError("active generation metadata is inconsistent")
    successor = _successor_generation_id(
        mode=mode,
        operation_id=operation_id,
        source_control_sha256=source_control_sha256,
        source_control_revision=source_revision,
        source_generation_id=source_generation_id,
        source_inventory=source_inventory,
    )
    return _validate_preview(
        _rotation_preview_record(
            mode=mode,
            operation_id=operation_id,
            source_control_sha256=source_control_sha256,
            source_control_revision=source_revision,
            source_generation_id=source_generation_id,
            source_inventory=source_inventory,
            successor_generation_id=successor,
        )
    )


def preview_codex_hook_receipt_rotation(
    paths: h.HarnessPaths, *, mode: str, operation_id: str
) -> dict[str, Any]:
    with h.state_lock(paths, create_layout=False):
        return _preview_rotation_locked(paths, mode=mode, operation_id=operation_id)


def _stage_generation_locked(
    paths: h.HarnessPaths,
    *,
    generation_id: str,
    predecessor_generation_id: str | None,
    location_kind: str,
    operation_id: str,
) -> None:
    generation_dir = _ensure_private_directory(
        _generation_dir(paths, generation_id), "receipt generation directory"
    )
    generation = _build_generation(
        generation_id=generation_id,
        predecessor_generation_id=predecessor_generation_id,
        location_kind=location_kind,
        operation_id=operation_id,
    )
    _validate_generation(generation)
    _create_or_verify_metadata(
        generation_dir / "generation.json", generation, "receipt generation metadata"
    )
    if location_kind == "v2":
        _ensure_private_directory(
            generation_dir / "receipts", "Codex hook receipt generation directory"
        )


def _stage_seal_locked(
    paths: h.HarnessPaths,
    *,
    generation_id: str,
    operation_id: str,
    inventory: list[dict[str, Any]],
    summary: Mapping[str, Any],
) -> None:
    seal = _build_seal(
        generation_id=generation_id,
        operation_id=operation_id,
        inventory=inventory,
        summary=summary,
    )
    _validate_seal(seal)
    _create_or_verify_metadata(
        _generation_dir(paths, generation_id) / "seal.json",
        seal,
        "receipt generation seal",
    )


def _validate_staged_rotation_locked(
    paths: h.HarnessPaths,
    *,
    previous: Mapping[str, Any] | None,
    expected_control: Mapping[str, Any],
    expected_intent: Mapping[str, Any],
) -> None:
    """Prove the complete staged topology before the sole control commit."""

    if _load_control_locked(paths) != previous:
        raise CodexHookReceiptError("receipt store control changed during rotation")
    root = _validate_directory(
        codex_hook_receipts_v2_dir(paths), "receipt store v2 directory"
    )
    expected_root_members = ["generations", "operations"]
    if previous is not None:
        expected_root_members.append("control.json")
    if sorted(item.name for item in root.iterdir()) != sorted(expected_root_members):
        raise CodexHookReceiptError("staged receipt store has unexpected root entries")

    operations_root = _validate_directory(
        _v2_operations_dir(paths), "receipt rotation operations directory"
    )
    operation_ids = sorted(item.name for item in operations_root.iterdir())
    if operation_ids != sorted(expected_control["applied_operations"]):
        raise CodexHookReceiptError("staged receipt operations differ from control")
    for operation_id in operation_ids:
        operation_dir = _validate_directory(
            operations_root / operation_id, "receipt rotation operation directory"
        )
        if sorted(item.name for item in operation_dir.iterdir()) != ["intent.json"]:
            raise CodexHookReceiptError(
                "staged receipt operation has unexpected entries"
            )
        stored_intent = _validate_intent(
            _read_private_json(
                operation_dir / "intent.json", "receipt rotation intent"
            )
        )
        if stored_intent["operation_id"] != operation_id:
            raise CodexHookReceiptError("staged receipt operation identity mismatches")
        if operation_id == expected_intent["operation_id"] and stored_intent != dict(
            expected_intent
        ):
            raise CodexHookReceiptError(
                "staged receipt operation conflicts with current intent"
            )

    marker = _validate_marker(
        _read_private_json(_adoption_marker_path(paths), "receipt store adoption marker")
    )
    first_operation_id = expected_control["applied_operations"][0]
    first_intent = _validate_intent(
        _read_private_json(
            _v2_operations_dir(paths) / first_operation_id / "intent.json",
            "receipt rotation intent",
        )
    )
    if (
        marker["operation_id"] != first_operation_id
        or marker["legacy_inventory"] != expected_control["legacy_inventory"]
        or marker["successor_generation_id"]
        != expected_control["generation_ids"][1]
        or marker["preview_sha256"] != first_intent["preview_sha256"]
        or marker["expected_control_sha256"]
        != first_intent["expected_control_sha256"]
    ):
        raise CodexHookReceiptError("staged adoption marker does not bind control")

    generation_root = _validate_directory(
        _v2_generations_dir(paths), "receipt generations directory"
    )
    generation_ids = sorted(item.name for item in generation_root.iterdir())
    if generation_ids != sorted(expected_control["generation_ids"]):
        raise CodexHookReceiptError("staged generations differ from control")
    legacy_records, legacy_summary, legacy_inventory = _legacy_inventory_locked(
        paths, allow_adoption_marker=True
    )
    if legacy_summary != expected_control["legacy_inventory"]:
        raise CodexHookReceiptError("legacy inventory drifted during staging")
    seen: set[str] = set()
    previous_generation_id: str | None = None
    for index, generation_id in enumerate(expected_control["generation_ids"]):
        generation_dir = _validate_directory(
            _generation_dir(paths, generation_id), "receipt generation directory"
        )
        metadata = _read_generation_metadata_locked(paths, generation_id)
        expected_creator = (
            expected_control["applied_operations"][0]
            if index <= 1
            else expected_control["applied_operations"][index - 1]
        )
        if (
            metadata["predecessor_generation_id"] != previous_generation_id
            or metadata["created_by_operation_id"] != expected_creator
        ):
            raise CodexHookReceiptError("staged generation topology is invalid")
        if generation_id == CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION:
            current_records = legacy_records
            inventory = legacy_inventory
            summary = legacy_summary
            expected_members = ["generation.json", "seal.json"]
        else:
            current_records, total, inventory = _scan_generation_locked(
                paths, generation_id
            )
            summary = _inventory_summary(inventory, total)
            expected_members = ["generation.json", "receipts"]
            if generation_id != expected_control["active_generation_id"]:
                expected_members.append("seal.json")
        if sorted(item.name for item in generation_dir.iterdir()) != sorted(
            expected_members
        ):
            raise CodexHookReceiptError(
                "staged receipt generation has unexpected entries"
            )
        for receipt, _payload in current_records:
            key = receipts.codex_hook_receipt_key(receipt)
            if key in seen:
                raise CodexHookReceiptError(
                    "duplicate receipt identity across staged generations"
                )
            seen.add(key)
        if generation_id == expected_control["active_generation_id"]:
            if inventory or summary["entry_count"] or summary["aggregate_bytes"]:
                raise CodexHookReceiptError(
                    "staged successor generation must be empty before commit"
                )
        else:
            seal = _validate_seal(
                _read_private_json(
                    generation_dir / "seal.json", "receipt generation seal"
                )
            )
            expected_sealer = expected_control["applied_operations"][index]
            if (
                seal["generation_id"] != generation_id
                or seal["sealed_by_operation_id"] != expected_sealer
                or seal["inventory"] != inventory
                or seal["inventory_summary"] != summary
            ):
                raise CodexHookReceiptError(
                    "staged generation seal does not match receipt bytes"
                )
        previous_generation_id = generation_id


def _apply_rotation_locked(
    paths: h.HarnessPaths,
    *,
    mode: str,
    operation_id: str,
    expected_preview_sha256: str,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    if not h._chief_lock_is_held(paths):
        raise CodexHookReceiptError("receipt rotation apply requires the AOI state lock")
    authority = _validate_authority_ref(dict(authority))
    preview = _preview_rotation_locked(paths, mode=mode, operation_id=operation_id)
    if preview["preview_sha256"] != _require_sha256(
        expected_preview_sha256, "expected rotation preview SHA-256"
    ):
        raise CodexHookReceiptError("receipt rotation preview changed before apply")
    prior = _load_control_locked(paths)
    if prior is not None and operation_id in prior["applied_operations"]:
        intents = _load_intents_locked(paths)
        intent = intents[operation_id]
        if (
            intent["mode"] != mode
            or intent["preview_sha256"] != expected_preview_sha256
            or not _same_logical_chief(intent["authority"], authority)
        ):
            raise CodexHookReceiptError("receipt rotation replay conflicts with durable truth")
        committed: dict[str, Any] | None = None
        for applied_operation_id in prior["applied_operations"]:
            applied_intent = intents[applied_operation_id]
            committed = _build_control(
                previous=committed,
                legacy_inventory=prior["legacy_inventory"],
                operation_id=applied_operation_id,
                mode=applied_intent["mode"],
                preview_sha256=applied_intent["preview_sha256"],
                successor_generation_id=applied_intent["successor_generation_id"],
            )
            if committed["control_sha256"] != applied_intent["expected_control_sha256"]:
                raise CodexHookReceiptError(
                    "receipt rotation operation does not bind its committed control"
                )
            if applied_operation_id == operation_id:
                break
        if committed is None or committed["last_operation_id"] != operation_id:
            raise CodexHookReceiptError(
                "receipt rotation replay operation is absent from durable control"
            )
        return {
            "status": "replayed",
            "mode": intent["mode"],
            "operation_id": operation_id,
            "preview_sha256": intent["preview_sha256"],
            "control_revision": committed["control_revision"],
            "control_sha256": committed["control_sha256"],
            "active_generation_id": committed["active_generation_id"],
            "legacy_inventory": committed["legacy_inventory"],
        }
    if prior is None:
        _legacy_records, legacy_summary, legacy_inventory = _legacy_inventory_locked(
            paths, allow_adoption_marker=_adoption_marker_path(paths).exists()
        )
        if legacy_summary != preview["source_inventory"]:
            raise CodexHookReceiptError("legacy receipt inventory changed before adoption")
    else:
        _records, total, source_inventory = _scan_generation_locked(
            paths, prior["active_generation_id"]
        )
        source_summary = _inventory_summary(source_inventory, total)
        if source_summary != preview["source_inventory"]:
            raise CodexHookReceiptError("active receipt inventory changed before rotation")
        legacy_summary = prior["legacy_inventory"]
        legacy_inventory = []
    expected_control = _build_control(
        previous=prior,
        legacy_inventory=legacy_summary,
        operation_id=operation_id,
        mode=mode,
        preview_sha256=expected_preview_sha256,
        successor_generation_id=preview["successor_generation_id"],
    )
    _validate_control(expected_control)
    existing_intent = _load_intents_locked(
        paths, allow_empty_operation_id=operation_id
    ).get(operation_id)
    if existing_intent is None:
        intent = _build_intent(
            preview,
            authority=authority,
            expected_control_sha256=expected_control["control_sha256"],
        )
    else:
        expected_intent = _build_intent(
            preview,
            authority=existing_intent["authority"],
            expected_control_sha256=expected_control["control_sha256"],
        )
        if (
            existing_intent != expected_intent
            or not _same_logical_chief(existing_intent["authority"], authority)
        ):
            raise CodexHookReceiptError(
                "receipt rotation resume conflicts with durable truth"
            )
        intent = existing_intent
    _validate_intent(intent)
    root = _ensure_private_directory(
        codex_hook_receipts_v2_dir(paths), "receipt store v2 directory"
    )
    _ensure_private_directory(_v2_operations_dir(paths), "receipt rotation operations directory")
    _ensure_private_directory(_v2_generations_dir(paths), "receipt generations directory")
    operation_dir = _ensure_private_directory(
        _v2_operations_dir(paths) / operation_id, "receipt rotation operation directory"
    )
    _create_or_verify_metadata(
        operation_dir / "intent.json", intent, "receipt rotation intent"
    )
    if prior is None:
        marker = _build_marker(
            preview, expected_control_sha256=expected_control["control_sha256"]
        )
        _validate_marker(marker)
        _ensure_store_directory(paths)
        _create_or_verify_metadata(
            _adoption_marker_path(paths), marker, "receipt store adoption marker"
        )
        _stage_generation_locked(
            paths,
            generation_id=CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION,
            predecessor_generation_id=None,
            location_kind="legacy_v1",
            operation_id=operation_id,
        )
        _stage_seal_locked(
            paths,
            generation_id=CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION,
            operation_id=operation_id,
            inventory=legacy_inventory,
            summary=legacy_summary,
        )
        predecessor = CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION
    else:
        predecessor = prior["active_generation_id"]
        _stage_seal_locked(
            paths,
            generation_id=predecessor,
            operation_id=operation_id,
            inventory=source_inventory,
            summary=source_summary,
        )
    _stage_generation_locked(
        paths,
        generation_id=preview["successor_generation_id"],
        predecessor_generation_id=predecessor,
        location_kind="v2",
        operation_id=operation_id,
    )
    _validate_staged_rotation_locked(
        paths,
        previous=prior,
        expected_control=expected_control,
        expected_intent=intent,
    )
    try:
        h.atomic_write_bytes(_v2_control_path(paths), _canonical_metadata_bytes(expected_control))
    except h.HarnessError as exc:
        raise CodexHookReceiptError(f"cannot commit receipt store control: {exc}") from exc
    committed, _intents, _generations = _validate_committed_v2_locked(
        paths, full_inventory=True
    )
    if committed != expected_control:
        raise CodexHookReceiptError("receipt store control readback differs after commit")
    return {
        "status": "committed",
        "mode": mode,
        "operation_id": operation_id,
        "preview_sha256": expected_preview_sha256,
        "control_revision": committed["control_revision"],
        "control_sha256": committed["control_sha256"],
        "active_generation_id": committed["active_generation_id"],
        "legacy_inventory": committed["legacy_inventory"],
    }


def apply_codex_hook_receipt_rotation(
    paths: h.HarnessPaths,
    *,
    mode: str,
    operation_id: str,
    expected_preview_sha256: str,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    with h.state_lock(paths, create_layout=False):
        return _apply_rotation_locked(
            paths,
            mode=mode,
            operation_id=operation_id,
            expected_preview_sha256=expected_preview_sha256,
            authority=authority,
        )



def _emit(value: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        for key, item in value.items():
            print(f"{key}: {item}")


def _translate(action: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return action()
    except (OSError, receipts.CodexHookReceiptError) as exc:
        raise h.HarnessError(str(exc)) from exc


def cmd_codex_hook_receipts_status(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    value = _translate(lambda: receipts.inspect_codex_hook_receipt_store(paths))
    _emit(value, as_json=args.json)
    return 0


def cmd_codex_hook_receipts_verify(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    value = _translate(lambda: receipts.inspect_codex_hook_receipt_store(paths))
    result = {
        "status": "verified",
        "receipt_store": value,
    }
    _emit(result, as_json=args.json)
    return 0


def cmd_codex_hook_receipts_rotation_preview(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    value = _translate(
        lambda: receipts.preview_codex_hook_receipt_rotation(
            paths,
            mode=args.mode,
            operation_id=args.operation_id,
        )
    )
    _emit(value, as_json=args.json)
    return 0


def cmd_codex_hook_receipts_rotate(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    authority = getattr(args, "_aoi_chief_authority", None)
    if not isinstance(authority, dict):
        raise h.HarnessError("receipt rotation requires current Chief authority")
    value = _translate(
        lambda: _apply_rotation_locked(
            paths,
            mode=args.mode,
            operation_id=args.operation_id,
            expected_preview_sha256=args.expected_preview_sha256,
            authority=authority,
        )
    )
    _emit(value, as_json=args.json)
    return 0


def _add_mode(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=("adopt-v1", "rotate-v2"), required=True)
    parser.add_argument("--operation-id", required=True)


def register_codex_hook_receipt_store_commands(
    subparsers: Any,
    *,
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    parser = subparsers.add_parser("codex-hook-receipts-status")
    add_json_argument(parser)
    parser.set_defaults(handler=cmd_codex_hook_receipts_status)

    parser = subparsers.add_parser("codex-hook-receipts-verify")
    add_json_argument(parser)
    parser.set_defaults(handler=cmd_codex_hook_receipts_verify)

    parser = subparsers.add_parser("codex-hook-receipts-rotation-preview")
    _add_mode(parser)
    add_json_argument(parser)
    parser.set_defaults(handler=cmd_codex_hook_receipts_rotation_preview)

    parser = subparsers.add_parser("codex-hook-receipts-rotate")
    _add_mode(parser)
    parser.add_argument("--expected-preview-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=cmd_codex_hook_receipts_rotate)



__all__ = [
    "READ_ONLY_COMMANDS",
    'preview_codex_hook_receipt_rotation',
    'apply_codex_hook_receipt_rotation',
    'cmd_codex_hook_receipts_status',
    'cmd_codex_hook_receipts_verify',
    'cmd_codex_hook_receipts_rotation_preview',
    'cmd_codex_hook_receipts_rotate',
    'register_codex_hook_receipt_store_commands',
]
