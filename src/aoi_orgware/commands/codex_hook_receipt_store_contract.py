"""Strict metadata and committed-state validation for receipt generations."""
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

CODEX_HOOK_RECEIPTS_V2_SCHEMA = receipts.CODEX_HOOK_RECEIPTS_V2_SCHEMA
CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION = (
    receipts.CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION
)
MAX_CODEX_HOOK_RECEIPT_GENERATIONS = receipts.MAX_CODEX_HOOK_RECEIPT_GENERATIONS
MAX_CODEX_HOOK_RECEIPT_ENTRIES = receipts.MAX_CODEX_HOOK_RECEIPT_ENTRIES
MAX_CODEX_HOOK_RECEIPT_STORE_BYTES = receipts.MAX_CODEX_HOOK_RECEIPT_STORE_BYTES
CodexHookReceiptError = receipts.CodexHookReceiptError
codex_hook_receipts_v2_dir = receipts.codex_hook_receipts_v2_dir
_RECEIPT_NAME = receipts._RECEIPT_NAME
_ROTATION_MODES = receipts._ROTATION_MODES
_canonical_metadata_bytes = receipts._canonical_metadata_bytes
_sealed_metadata = receipts._sealed_metadata
_require_exact_fields = receipts._require_exact_fields
_require_int = receipts._require_int
_require_sha256 = receipts._require_sha256
_require_operation_id = receipts._require_operation_id
_require_generation_id = receipts._require_generation_id
_validate_inventory_summary = receipts._validate_inventory_summary
_validate_authority_ref = receipts._validate_authority_ref
_validate_sealed_metadata = receipts._validate_sealed_metadata
_read_private_json = receipts._read_private_json
_ensure_private_directory = receipts._ensure_private_directory
_create_or_verify_metadata = receipts._create_or_verify_metadata
_scan_receipt_directory_locked = receipts._scan_receipt_directory_locked
_v2_control_path = receipts._v2_control_path
_v2_operations_dir = receipts._v2_operations_dir
_v2_generations_dir = receipts._v2_generations_dir
_generation_dir = receipts._generation_dir
_generation_receipts_dir = receipts._generation_receipts_dir
_adoption_marker_path = receipts._adoption_marker_path
_validate_directory = receipts._validate_directory
_legacy_inventory_locked = receipts._legacy_inventory_locked
_inventory_summary = receipts._inventory_summary
_ensure_store_directory = receipts._ensure_store_directory


JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]
READ_ONLY_COMMANDS = receipts.READ_ONLY_COMMANDS


_CONTROL_FIELDS = {
    "schema_version",
    "store_schema",
    "control_revision",
    "legacy_inventory",
    "generation_ids",
    "active_generation_id",
    "applied_operations",
    "last_operation_id",
    "last_mode",
    "last_preview_sha256",
}
_INTENT_FIELDS = {
    "schema_version",
    "store_schema",
    "operation_id",
    "mode",
    "source_control_sha256",
    "source_control_revision",
    "source_generation_id",
    "source_inventory",
    "successor_generation_id",
    "authority",
    "preview_sha256",
    "expected_control_sha256",
}
_MARKER_FIELDS = {
    "schema_version",
    "store_schema",
    "operation_id",
    "legacy_inventory",
    "successor_generation_id",
    "preview_sha256",
    "expected_control_sha256",
}
_GENERATION_FIELDS = {
    "schema_version",
    "store_schema",
    "generation_id",
    "predecessor_generation_id",
    "location_kind",
    "created_by_operation_id",
    "entry_capacity",
    "aggregate_byte_capacity",
}
_SEAL_FIELDS = {
    "schema_version",
    "store_schema",
    "generation_id",
    "sealed_by_operation_id",
    "inventory",
    "inventory_summary",
}


def _validate_control(value: Any) -> dict[str, Any]:
    item = _validate_sealed_metadata(
        value,
        fields=_CONTROL_FIELDS,
        digest_field="control_sha256",
        label="receipt store control",
    )
    if item["schema_version"] != 1 or item["store_schema"] != CODEX_HOOK_RECEIPTS_V2_SCHEMA:
        raise CodexHookReceiptError("receipt store control schema is unsupported")
    revision = _require_int(item["control_revision"], "control revision", minimum=1)
    _validate_inventory_summary(item["legacy_inventory"], "control legacy inventory")
    generation_ids = item["generation_ids"]
    operations = item["applied_operations"]
    if (
        not isinstance(generation_ids, list)
        or not isinstance(operations, list)
        or len(generation_ids) != revision + 1
        or len(operations) != revision
        or len(generation_ids) > MAX_CODEX_HOOK_RECEIPT_GENERATIONS
        or len(set(generation_ids)) != len(generation_ids)
        or len(set(operations)) != len(operations)
    ):
        raise CodexHookReceiptError("receipt store control topology is invalid")
    for generation_id in generation_ids:
        _require_generation_id(generation_id)
    for operation_id in operations:
        _require_operation_id(operation_id)
    if (
        generation_ids[0] != CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION
        or item["active_generation_id"] != generation_ids[-1]
        or item["last_operation_id"] != operations[-1]
        or item["last_mode"] not in _ROTATION_MODES
        or (revision == 1 and item["last_mode"] != "adopt-v1")
        or (revision > 1 and item["last_mode"] != "rotate-v2")
    ):
        raise CodexHookReceiptError("receipt store control head is invalid")
    _require_sha256(item["last_preview_sha256"], "control preview SHA-256")
    return item


def _validate_intent(value: Any) -> dict[str, Any]:
    item = _validate_sealed_metadata(
        value,
        fields=_INTENT_FIELDS,
        digest_field="intent_sha256",
        label="receipt rotation intent",
    )
    if item["schema_version"] != 1 or item["store_schema"] != CODEX_HOOK_RECEIPTS_V2_SCHEMA:
        raise CodexHookReceiptError("receipt rotation intent schema is unsupported")
    operation_id = _require_operation_id(item["operation_id"])
    mode = item["mode"]
    if mode not in _ROTATION_MODES:
        raise CodexHookReceiptError("receipt rotation intent mode is invalid")
    revision = _require_int(
        item["source_control_revision"], "intent source control revision"
    )
    if mode == "adopt-v1":
        if revision != 0 or item["source_control_sha256"] is not None:
            raise CodexHookReceiptError("adoption intent has a source control")
        if item["source_generation_id"] != CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION:
            raise CodexHookReceiptError("adoption intent source generation is invalid")
    else:
        _require_sha256(item["source_control_sha256"], "intent source control SHA-256")
        if revision < 1:
            raise CodexHookReceiptError("rotation intent source revision is invalid")
        _require_generation_id(item["source_generation_id"], "intent source generation")
    _validate_inventory_summary(item["source_inventory"], "intent source inventory")
    _require_generation_id(item["successor_generation_id"], "intent successor generation")
    if item["successor_generation_id"] == item["source_generation_id"]:
        raise CodexHookReceiptError("receipt rotation successor equals its source")
    _validate_authority_ref(item["authority"])
    _require_sha256(item["preview_sha256"], "intent preview SHA-256")
    _require_sha256(item["expected_control_sha256"], "intent expected control SHA-256")
    if operation_id != item["operation_id"]:
        raise CodexHookReceiptError("receipt rotation operation id is non-canonical")
    return item


def _validate_marker(value: Any) -> dict[str, Any]:
    item = _validate_sealed_metadata(
        value,
        fields=_MARKER_FIELDS,
        digest_field="marker_sha256",
        label="receipt store adoption marker",
    )
    if item["schema_version"] != 1 or item["store_schema"] != CODEX_HOOK_RECEIPTS_V2_SCHEMA:
        raise CodexHookReceiptError("receipt store adoption marker schema is unsupported")
    _require_operation_id(item["operation_id"])
    _validate_inventory_summary(item["legacy_inventory"], "marker legacy inventory")
    _require_generation_id(item["successor_generation_id"], "marker successor generation")
    _require_sha256(item["preview_sha256"], "marker preview SHA-256")
    _require_sha256(item["expected_control_sha256"], "marker control SHA-256")
    return item


def _validate_generation(value: Any) -> dict[str, Any]:
    item = _validate_sealed_metadata(
        value,
        fields=_GENERATION_FIELDS,
        digest_field="generation_sha256",
        label="receipt generation metadata",
    )
    if item["schema_version"] != 1 or item["store_schema"] != CODEX_HOOK_RECEIPTS_V2_SCHEMA:
        raise CodexHookReceiptError("receipt generation schema is unsupported")
    generation_id = _require_generation_id(item["generation_id"])
    predecessor = item["predecessor_generation_id"]
    if predecessor is not None:
        _require_generation_id(predecessor, "generation predecessor")
    if item["location_kind"] not in {"legacy_v1", "v2"}:
        raise CodexHookReceiptError("receipt generation location kind is invalid")
    if (generation_id == CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION) != (
        item["location_kind"] == "legacy_v1"
    ):
        raise CodexHookReceiptError("receipt generation location does not match its id")
    _require_operation_id(item["created_by_operation_id"])
    if (
        _require_int(item["entry_capacity"], "generation entry capacity", minimum=1)
        != MAX_CODEX_HOOK_RECEIPT_ENTRIES
        or _require_int(
            item["aggregate_byte_capacity"],
            "generation aggregate byte capacity",
            minimum=1,
        )
        != MAX_CODEX_HOOK_RECEIPT_STORE_BYTES
    ):
        raise CodexHookReceiptError("receipt generation capacity contract is invalid")
    return item


def _validate_inventory_entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_CODEX_HOOK_RECEIPT_ENTRIES:
        raise CodexHookReceiptError("receipt generation inventory is invalid")
    result: list[dict[str, Any]] = []
    previous = ""
    for raw in value:
        item = _require_exact_fields(
            raw, {"name", "size_bytes", "sha256"}, "receipt inventory entry"
        )
        name = item["name"]
        if (
            not isinstance(name, str)
            or _RECEIPT_NAME.fullmatch(name) is None
            or name <= previous
        ):
            raise CodexHookReceiptError("receipt inventory names are not canonical")
        previous = name
        _require_int(item["size_bytes"], "receipt inventory size", minimum=1)
        _require_sha256(item["sha256"], "receipt inventory SHA-256")
        result.append(item)
    return result


def _validate_seal(value: Any) -> dict[str, Any]:
    item = _validate_sealed_metadata(
        value,
        fields=_SEAL_FIELDS,
        digest_field="seal_sha256",
        label="receipt generation seal",
    )
    if item["schema_version"] != 1 or item["store_schema"] != CODEX_HOOK_RECEIPTS_V2_SCHEMA:
        raise CodexHookReceiptError("receipt generation seal schema is unsupported")
    _require_generation_id(item["generation_id"])
    _require_operation_id(item["sealed_by_operation_id"])
    inventory = _validate_inventory_entries(item["inventory"])
    summary = _validate_inventory_summary(
        item["inventory_summary"], "seal inventory summary"
    )
    expected = _inventory_summary(
        inventory, sum(int(entry["size_bytes"]) for entry in inventory)
    )
    if summary != expected:
        raise CodexHookReceiptError("receipt generation seal inventory summary is invalid")
    return item


def _successor_generation_id(
    *,
    mode: str,
    operation_id: str,
    source_control_sha256: str | None,
    source_control_revision: int,
    source_generation_id: str,
    source_inventory: Mapping[str, Any],
) -> str:
    basis = {
        "domain": "aoi.codex-hook-receipt-generation.v2",
        "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
        "mode": mode,
        "operation_id": operation_id,
        "source_control_sha256": source_control_sha256,
        "source_control_revision": source_control_revision,
        "source_generation_id": source_generation_id,
        "source_inventory": dict(source_inventory),
    }
    return "g-" + hashlib.sha256(_canonical_metadata_bytes(basis)).hexdigest()


def _rotation_preview_record(
    *,
    mode: str,
    operation_id: str,
    source_control_sha256: str | None,
    source_control_revision: int,
    source_generation_id: str,
    source_inventory: Mapping[str, Any],
    successor_generation_id: str,
) -> dict[str, Any]:
    preimage = {
        "schema_version": 1,
        "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
        "operation_id": operation_id,
        "mode": mode,
        "source_control_sha256": source_control_sha256,
        "source_control_revision": source_control_revision,
        "source_generation_id": source_generation_id,
        "source_inventory": dict(source_inventory),
        "successor_generation_id": successor_generation_id,
        "generation_limit": MAX_CODEX_HOOK_RECEIPT_GENERATIONS,
        "entry_capacity": MAX_CODEX_HOOK_RECEIPT_ENTRIES,
        "aggregate_byte_capacity": MAX_CODEX_HOOK_RECEIPT_STORE_BYTES,
    }
    return {
        **preimage,
        "preview_sha256": hashlib.sha256(
            _canonical_metadata_bytes(preimage)
        ).hexdigest(),
    }


def _validate_preview(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "store_schema",
        "operation_id",
        "mode",
        "source_control_sha256",
        "source_control_revision",
        "source_generation_id",
        "source_inventory",
        "successor_generation_id",
        "generation_limit",
        "entry_capacity",
        "aggregate_byte_capacity",
        "preview_sha256",
    }
    item = _require_exact_fields(value, fields, "receipt rotation preview")
    if item["schema_version"] != 1 or item["store_schema"] != CODEX_HOOK_RECEIPTS_V2_SCHEMA:
        raise CodexHookReceiptError("receipt rotation preview schema is unsupported")
    _require_operation_id(item["operation_id"])
    if item["mode"] not in _ROTATION_MODES:
        raise CodexHookReceiptError("receipt rotation preview mode is invalid")
    _require_int(item["source_control_revision"], "preview source control revision")
    if item["source_control_sha256"] is not None:
        _require_sha256(item["source_control_sha256"], "preview source control SHA-256")
    _require_generation_id(item["source_generation_id"], "preview source generation")
    _validate_inventory_summary(item["source_inventory"], "preview source inventory")
    _require_generation_id(item["successor_generation_id"], "preview successor generation")
    if (
        item["generation_limit"] != MAX_CODEX_HOOK_RECEIPT_GENERATIONS
        or item["entry_capacity"] != MAX_CODEX_HOOK_RECEIPT_ENTRIES
        or item["aggregate_byte_capacity"] != MAX_CODEX_HOOK_RECEIPT_STORE_BYTES
    ):
        raise CodexHookReceiptError("receipt rotation preview capacity contract is invalid")
    digest = _require_sha256(item["preview_sha256"], "rotation preview SHA-256")
    preimage = {key: item[key] for key in fields - {"preview_sha256"}}
    if hashlib.sha256(_canonical_metadata_bytes(preimage)).hexdigest() != digest:
        raise CodexHookReceiptError("receipt rotation preview digest is invalid")
    return item


def _build_control(
    *,
    previous: Mapping[str, Any] | None,
    legacy_inventory: Mapping[str, Any],
    operation_id: str,
    mode: str,
    preview_sha256: str,
    successor_generation_id: str,
) -> dict[str, Any]:
    if previous is None:
        generation_ids = [
            CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION,
            successor_generation_id,
        ]
        operations = [operation_id]
        revision = 1
    else:
        generation_ids = [*previous["generation_ids"], successor_generation_id]
        operations = [*previous["applied_operations"], operation_id]
        revision = int(previous["control_revision"]) + 1
    return _sealed_metadata(
        {
            "schema_version": 1,
            "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
            "control_revision": revision,
            "legacy_inventory": dict(legacy_inventory),
            "generation_ids": generation_ids,
            "active_generation_id": successor_generation_id,
            "applied_operations": operations,
            "last_operation_id": operation_id,
            "last_mode": mode,
            "last_preview_sha256": preview_sha256,
        },
        digest_field="control_sha256",
    )


def _build_intent(
    preview: Mapping[str, Any],
    *,
    authority: Mapping[str, Any],
    expected_control_sha256: str,
) -> dict[str, Any]:
    return _sealed_metadata(
        {
            "schema_version": 1,
            "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
            "operation_id": preview["operation_id"],
            "mode": preview["mode"],
            "source_control_sha256": preview["source_control_sha256"],
            "source_control_revision": preview["source_control_revision"],
            "source_generation_id": preview["source_generation_id"],
            "source_inventory": dict(preview["source_inventory"]),
            "successor_generation_id": preview["successor_generation_id"],
            "authority": dict(authority),
            "preview_sha256": preview["preview_sha256"],
            "expected_control_sha256": expected_control_sha256,
        },
        digest_field="intent_sha256",
    )


def _build_marker(
    preview: Mapping[str, Any], *, expected_control_sha256: str
) -> dict[str, Any]:
    return _sealed_metadata(
        {
            "schema_version": 1,
            "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
            "operation_id": preview["operation_id"],
            "legacy_inventory": dict(preview["source_inventory"]),
            "successor_generation_id": preview["successor_generation_id"],
            "preview_sha256": preview["preview_sha256"],
            "expected_control_sha256": expected_control_sha256,
        },
        digest_field="marker_sha256",
    )


def _build_generation(
    *,
    generation_id: str,
    predecessor_generation_id: str | None,
    location_kind: str,
    operation_id: str,
) -> dict[str, Any]:
    return _sealed_metadata(
        {
            "schema_version": 1,
            "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
            "generation_id": generation_id,
            "predecessor_generation_id": predecessor_generation_id,
            "location_kind": location_kind,
            "created_by_operation_id": operation_id,
            "entry_capacity": MAX_CODEX_HOOK_RECEIPT_ENTRIES,
            "aggregate_byte_capacity": MAX_CODEX_HOOK_RECEIPT_STORE_BYTES,
        },
        digest_field="generation_sha256",
    )


def _build_seal(
    *,
    generation_id: str,
    operation_id: str,
    inventory: list[dict[str, Any]],
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    return _sealed_metadata(
        {
            "schema_version": 1,
            "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
            "generation_id": generation_id,
            "sealed_by_operation_id": operation_id,
            "inventory": inventory,
            "inventory_summary": dict(summary),
        },
        digest_field="seal_sha256",
    )


def _load_control_locked(paths: h.HarnessPaths) -> dict[str, Any] | None:
    path = _v2_control_path(paths)
    if not path.exists() and not h._path_is_link_like(path):
        return None
    return _validate_control(_read_private_json(path, "receipt store control"))


def _load_intents_locked(
    paths: h.HarnessPaths,
    *,
    allow_empty_operation_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    directory = _v2_operations_dir(paths)
    if not directory.exists() and not h._path_is_link_like(directory):
        return {}
    _validate_directory(directory, "receipt rotation operations directory")
    result: dict[str, dict[str, Any]] = {}
    try:
        entries = sorted(Path(entry.path) for entry in os.scandir(directory))
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot scan receipt rotation operations: {exc}") from exc
    if len(entries) > MAX_CODEX_HOOK_RECEIPT_GENERATIONS:
        raise CodexHookReceiptError("receipt rotation operation retention is exhausted")
    for operation_dir in entries:
        _validate_directory(operation_dir, "receipt rotation operation directory")
        _require_operation_id(operation_dir.name)
        members = sorted(item.name for item in operation_dir.iterdir())
        if not members:
            if operation_dir.name == allow_empty_operation_id:
                # Directory creation is only scaffolding.  A crash before the
                # append-once intent remains resumable by that exact operation.
                continue
            raise CodexHookReceiptError(
                "receipt_rotation_pending: exact operation resume is required"
            )
        if members != ["intent.json"]:
            raise CodexHookReceiptError("receipt rotation operation has unexpected entries")
        intent = _validate_intent(
            _read_private_json(operation_dir / "intent.json", "receipt rotation intent")
        )
        if intent["operation_id"] != operation_dir.name:
            raise CodexHookReceiptError("receipt rotation intent path identity mismatch")
        result[operation_dir.name] = intent
    return result


def _read_generation_metadata_locked(
    paths: h.HarnessPaths, generation_id: str
) -> dict[str, Any]:
    _require_generation_id(generation_id)
    metadata = _validate_generation(
        _read_private_json(
            _generation_dir(paths, generation_id) / "generation.json",
            "receipt generation metadata",
        )
    )
    if metadata["generation_id"] != generation_id:
        raise CodexHookReceiptError("receipt generation path identity mismatch")
    return metadata


def _scan_generation_locked(
    paths: h.HarnessPaths, generation_id: str
) -> tuple[list[tuple[dict[str, Any], bytes]], int, list[dict[str, Any]]]:
    return _scan_receipt_directory_locked(
        _generation_receipts_dir(paths, generation_id),
        label="Codex hook receipt generation directory",
    )


def _validate_committed_v2_locked(
    paths: h.HarnessPaths,
    *,
    full_inventory: bool,
    allow_pending_operation: str | None = None,
    allow_staging_operation: str | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    control = _load_control_locked(paths)
    if control is None:
        raise CodexHookReceiptError("receipt store v2 control is missing")
    root = _validate_directory(codex_hook_receipts_v2_dir(paths), "receipt store v2 directory")
    members = sorted(item.name for item in root.iterdir())
    if members != ["control.json", "generations", "operations"]:
        raise CodexHookReceiptError("receipt store v2 directory has unexpected entries")
    intents = _load_intents_locked(
        paths, allow_empty_operation_id=allow_staging_operation
    )
    applied = list(control["applied_operations"])
    if sorted(intents) != sorted(applied):
        pending = sorted(set(intents) - set(applied))
        missing = sorted(set(applied) - set(intents))
        if pending and pending != [allow_pending_operation]:
            raise CodexHookReceiptError("receipt_rotation_pending: exact operation resume is required")
        if missing:
            raise CodexHookReceiptError(f"receipt store control references missing operation intent: {missing}")
    staging_intent = None
    if allow_staging_operation is not None and allow_staging_operation not in applied:
        staging_intent = intents.get(allow_staging_operation)
    if staging_intent is not None and (
        allow_pending_operation != allow_staging_operation
        or staging_intent["mode"] != "rotate-v2"
        or staging_intent["source_control_sha256"] != control["control_sha256"]
        or staging_intent["source_control_revision"] != control["control_revision"]
        or staging_intent["source_generation_id"] != control["active_generation_id"]
        or staging_intent["successor_generation_id"] in control["generation_ids"]
    ):
        raise CodexHookReceiptError("pending receipt rotation does not bind control")
    marker = _validate_marker(_read_private_json(
        _adoption_marker_path(paths), "receipt store adoption marker"
    ))
    first_intent = intents[applied[0]]
    if (
        marker["operation_id"] != applied[0]
        or marker["legacy_inventory"] != control["legacy_inventory"]
        or marker["successor_generation_id"] != control["generation_ids"][1]
        or marker["preview_sha256"] != first_intent["preview_sha256"]
        or marker["expected_control_sha256"] != first_intent["expected_control_sha256"]
    ):
        raise CodexHookReceiptError("receipt store adoption marker does not bind control")
    legacy_records, legacy_summary, legacy_entries = _legacy_inventory_locked(paths, allow_adoption_marker=True)
    if legacy_summary != control["legacy_inventory"]:
        raise CodexHookReceiptError("receipt store legacy inventory drifted after adoption")
    seen_receipt_keys: set[str] = set()
    for receipt, _payload in legacy_records:
        key = receipts.codex_hook_receipt_key(receipt)
        if key in seen_receipt_keys:
            raise CodexHookReceiptError("duplicate receipt identity across retained generations")
        seen_receipt_keys.add(key)
    generations: dict[str, dict[str, Any]] = {}
    generation_root = _validate_directory(_v2_generations_dir(paths), "receipt generations directory")
    disk_generation_ids = sorted(item.name for item in generation_root.iterdir())
    allowed_generation_sets = {tuple(sorted(control["generation_ids"]))}
    if staging_intent is not None:
        staged_ids = [*control["generation_ids"], staging_intent["successor_generation_id"]]
        allowed_generation_sets.add(tuple(sorted(staged_ids)))
    if tuple(disk_generation_ids) not in allowed_generation_sets:
        raise CodexHookReceiptError("receipt store generation inventory differs from control")
    previous: str | None = None
    for index, generation_id in enumerate(control["generation_ids"]):
        generation_dir = _validate_directory(_generation_dir(paths, generation_id), "receipt generation directory")
        metadata = _read_generation_metadata_locked(paths, generation_id)
        expected_predecessor = previous
        if metadata["predecessor_generation_id"] != expected_predecessor:
            raise CodexHookReceiptError("receipt generation predecessor topology is invalid")
        expected_creator = applied[0] if index <= 1 else applied[index - 1]
        if metadata["created_by_operation_id"] != expected_creator:
            raise CodexHookReceiptError("receipt generation creator does not match control")
        if generation_id == CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION:
            members = sorted(item.name for item in generation_dir.iterdir())
            if members != ["generation.json", "seal.json"]:
                raise CodexHookReceiptError("legacy generation has unexpected entries")
            inventory = legacy_entries
            summary = legacy_summary
        else:
            members = sorted(item.name for item in generation_dir.iterdir())
            expected_members = ["generation.json", "receipts"]
            is_active = generation_id == control["active_generation_id"]
            staged_active_seal = staging_intent is not None and is_active and "seal.json" in members
            if generation_id != control["active_generation_id"] or staged_active_seal:
                expected_members.append("seal.json")
            if members != sorted(expected_members):
                raise CodexHookReceiptError("receipt generation has unexpected entries")
            current_records, total, inventory = _scan_generation_locked(paths, generation_id)
            summary = _inventory_summary(inventory, total)
            for receipt, _payload in current_records:
                key = receipts.codex_hook_receipt_key(receipt)
                if key in seen_receipt_keys:
                    raise CodexHookReceiptError("duplicate receipt identity across retained generations")
                seen_receipt_keys.add(key)
            if (
                staging_intent is not None and is_active
                and summary != staging_intent["source_inventory"]
            ):
                raise CodexHookReceiptError("pending rotation source inventory drifted")
        if generation_id != control["active_generation_id"] or (
            staging_intent is not None and generation_id == control["active_generation_id"]
            and "seal.json" in members
        ):
            seal = _validate_seal(_read_private_json(
                generation_dir / "seal.json", "receipt generation seal"
            ))
            expected_sealer = (
                staging_intent["operation_id"]
                if generation_id == control["active_generation_id"] and staging_intent is not None
                else applied[index]
            )
            if (
                seal["generation_id"] != generation_id
                or seal["sealed_by_operation_id"] != expected_sealer
                or seal["inventory_summary"] != summary
                or ((full_inventory or generation_id == control["active_generation_id"])
                    and seal["inventory"] != inventory)
            ):
                raise CodexHookReceiptError("receipt generation seal does not match bytes")
        generations[generation_id] = {
            "metadata": metadata,
            "inventory_summary": summary,
        }
        previous = generation_id
    if (staging_intent is not None
            and staging_intent["successor_generation_id"] in disk_generation_ids):
        successor_id = staging_intent["successor_generation_id"]
        successor_dir = _validate_directory(_generation_dir(paths, successor_id),
                                            "receipt generation directory")
        successor_members = sorted(item.name for item in successor_dir.iterdir())
        allowed_prefixes: tuple[list[str], ...] = ([], ["generation.json"], ["generation.json", "receipts"])
        if successor_members not in allowed_prefixes:
            raise CodexHookReceiptError("receipt rotation successor is not an exact staging prefix")
        if "generation.json" in successor_members:
            expected_generation = _build_generation(
                generation_id=successor_id,
                predecessor_generation_id=control["active_generation_id"],
                location_kind="v2",
                operation_id=staging_intent["operation_id"],
            )
            if _read_generation_metadata_locked(paths, successor_id) != expected_generation:
                raise CodexHookReceiptError("receipt rotation successor metadata conflicts with intent")
        if "receipts" in successor_members:
            records, total, inventory = _scan_generation_locked(paths, successor_id)
            if records or total or inventory:
                raise CodexHookReceiptError("uncommitted successor generation is not empty")
    for index, operation_id in enumerate(applied):
        intent = intents[operation_id]
        if (
            intent["successor_generation_id"] != control["generation_ids"][index + 1]
            or intent["expected_control_sha256"]
            != (
                control["control_sha256"]
                if index == len(applied) - 1
                else _read_prior_control_digest_from_intents(intents, applied, index)
            )
        ):
            raise CodexHookReceiptError("receipt rotation intent does not bind generation topology")
    return control, intents, generations


def _read_prior_control_digest_from_intents(
    intents: Mapping[str, Mapping[str, Any]], operations: list[str], index: int
) -> str:
    next_intent = intents[operations[index + 1]]
    return _require_sha256(
        next_intent["source_control_sha256"], "next intent source control SHA-256"
    )


def _pending_operation_locked(
    control: Mapping[str, Any] | None,
    intents: Mapping[str, Mapping[str, Any]],
) -> str | None:
    applied = set(control["applied_operations"]) if control is not None else set()
    pending = sorted(set(intents) - applied)
    if len(pending) > 1:
        raise CodexHookReceiptError("multiple pending receipt rotations are ambiguous")
    return pending[0] if pending else None



__all__ = [
    'CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION',
    'MAX_CODEX_HOOK_RECEIPT_GENERATIONS',
    'CodexHookReceiptError',
    'codex_hook_receipts_v2_dir',
    '_ROTATION_MODES',
    '_canonical_metadata_bytes',
    '_require_sha256',
    '_require_operation_id',
    '_validate_authority_ref',
    '_read_private_json',
    '_ensure_private_directory',
    '_create_or_verify_metadata',
    '_v2_control_path',
    '_v2_operations_dir',
    '_v2_generations_dir',
    '_generation_dir',
    '_adoption_marker_path',
    '_validate_directory',
    '_legacy_inventory_locked',
    '_inventory_summary',
    '_ensure_store_directory',
    '_validate_control',
    '_validate_intent',
    '_validate_marker',
    '_validate_generation',
    '_validate_seal',
    '_successor_generation_id',
    '_rotation_preview_record',
    '_validate_preview',
    '_build_control',
    '_build_intent',
    '_build_marker',
    '_build_generation',
    '_build_seal',
    '_load_control_locked',
    '_load_intents_locked',
    '_read_generation_metadata_locked',
    '_scan_generation_locked',
    '_validate_committed_v2_locked',
    '_pending_operation_locked',
]
