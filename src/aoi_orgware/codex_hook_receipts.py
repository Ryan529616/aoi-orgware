"""Bounded create-only storage for sealed Codex hook adapter receipts.

The adapter contract owns receipt schemas and sealing.  This module only
accepts the result of its validator, binds a filename to the stable event
identity, and makes replay/collision behaviour durable under AOI's cooperative
state lock.  Receipt content digests deliberately never select a filename:
two divergent receipts for the same hook event must collide.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from . import harnesslib as h
from .agent_identity import AgentIdentityError, validate_agent_id
from .semantic_events import SemanticEventError, canonical_json_bytes


CODEX_HOOK_RECEIPTS_DIRECTORY = "codex-hook-receipts-v1"
CODEX_HOOK_RECEIPTS_V2_DIRECTORY = "codex-hook-receipts-v2"
CODEX_HOOK_RECEIPTS_V2_SCHEMA = "codex_hook_receipt_generations_v2"
CODEX_HOOK_RECEIPTS_V2_ADOPTION_MARKER = "v2-adoption.json"
CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION = "legacy-v1"
MAX_CODEX_HOOK_RECEIPT_BYTES = 64 * 1024
# A normal tool turn emits a correlated PreToolUse/PostToolUse pair.  Keep a
# bounded session store large enough for ordinary work rather than exhausting
# it after 32 calls; no eviction or partial-accounting path is introduced.
MAX_CODEX_HOOK_RECEIPT_ENTRIES = 1024
MAX_CODEX_HOOK_RECEIPT_STORE_BYTES = 16 * 1024 * 1024
MAX_CODEX_HOOK_RECEIPT_GENERATIONS = 16
READ_ONLY_COMMANDS = frozenset(
    {
        "codex-hook-receipts-status",
        "codex-hook-receipts-verify",
        "codex-hook-receipts-rotation-preview",
    }
)
MAX_CODEX_HOOK_RECEIPT_CONTROL_BYTES = 4 * 1024 * 1024
_NEAR_CAPACITY_PERCENT = 90

_RECEIPT_NAME = re.compile(r"[0-9a-f]{64}\.json")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GENERATION_ID = re.compile(r"(?:legacy-v1|g-[0-9a-f]{64})")
_ROTATION_MODES = frozenset({"adopt-v1", "rotate-v2"})


class CodexHookReceiptError(h.HarnessError):
    """A Codex hook receipt store cannot safely accept a record."""


def _adapter_validator(value: Any) -> dict[str, Any]:
    """Use the adapter-owned sealed-record validator, never a local schema."""

    # Keep this import lazy: ordinary AOI operation does not load Codex adapter
    # contracts, and it prevents this filesystem boundary from becoming a
    # second source of truth for those schemas.
    from .codex_adapter_contracts import validate_codex_adapter_receipt

    validated = validate_codex_adapter_receipt(value)
    if not isinstance(validated, dict):
        raise CodexHookReceiptError("adapter receipt validator returned a non-object")
    return validated


def _canonical_validated_receipt(value: Any) -> tuple[dict[str, Any], bytes]:
    try:
        receipt = _adapter_validator(value)
        payload = canonical_json_bytes(receipt, max_bytes=MAX_CODEX_HOOK_RECEIPT_BYTES)
    except CodexHookReceiptError:
        raise
    except (ImportError, SemanticEventError, TypeError, ValueError) as exc:
        raise CodexHookReceiptError(f"sealed Codex adapter receipt is invalid: {exc}") from exc
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover - canonical JSON is UTF-8
        raise CodexHookReceiptError("sealed Codex adapter receipt is not JSON") from exc
    if decoded != receipt:
        raise CodexHookReceiptError("adapter validator returned a non-canonical receipt")
    return receipt, payload


def _require_current_store_identity(receipt: Mapping[str, Any]) -> None:
    """Keep v1 reads compatible without admitting legacy IDs as new entries."""

    event_identity = receipt.get("event_identity")
    if not isinstance(event_identity, Mapping) or "agent_id" not in event_identity:
        return
    try:
        validate_agent_id(event_identity.get("agent_id"), "stored receipt agent id")
    except AgentIdentityError as exc:
        raise CodexHookReceiptError(
            "new Codex receipt store entries require a canonical agent identity"
        ) from exc


def _event_identity_preimage(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Return only the adapter-validated identity used for path selection."""

    receipt_type = receipt.get("receipt_type")
    event_identity = receipt.get("event_identity")
    if (
        not isinstance(receipt_type, str)
        or not receipt_type
        or len(receipt_type) > 128
        or "\x00" in receipt_type
        or not isinstance(event_identity, dict)
    ):
        raise CodexHookReceiptError("validated receipt has no usable event identity")
    # The validator owns the exact identity field set (session/turn/tool-use/
    # agent/event as applicable).  Canonical JSON makes that complete map,
    # rather than a receipt digest or incidental observation, the filename key.
    try:
        canonical_json_bytes(event_identity, max_bytes=MAX_CODEX_HOOK_RECEIPT_BYTES)
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise CodexHookReceiptError("validated receipt event identity is invalid") from exc
    return {"receipt_type": receipt_type, "event_identity": event_identity}


def codex_hook_receipt_key(receipt: Mapping[str, Any]) -> str:
    """Return the deterministic event-identity key for one validated receipt."""

    preimage = _event_identity_preimage(receipt)
    return hashlib.sha256(
        canonical_json_bytes(preimage, max_bytes=MAX_CODEX_HOOK_RECEIPT_BYTES)
    ).hexdigest()


def codex_hook_receipts_dir(paths: h.HarnessPaths) -> Path:
    return paths.harness / CODEX_HOOK_RECEIPTS_DIRECTORY


def codex_hook_receipt_path(paths: h.HarnessPaths, receipt: Mapping[str, Any]) -> Path:
    return codex_hook_receipts_dir(paths) / f"{codex_hook_receipt_key(receipt)}.json"


def _private_posix(metadata: os.stat_result) -> bool:
    return (
        metadata.st_uid == os.geteuid()  # type: ignore[attr-defined]
        and not stat.S_IMODE(metadata.st_mode) & 0o077
    )


def _validate_directory(path: Path, label: str) -> Path:
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CodexHookReceiptError(f"{label} is missing: {path}") from exc
    except h.HarnessError:
        raise
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot inspect {label}: {exc}") from exc
    if canonical != path:
        raise CodexHookReceiptError(f"{label} path is not canonical: {path}")
    if h._path_is_link_like(path) or not stat.S_ISDIR(metadata.st_mode):
        raise CodexHookReceiptError(f"{label} must be a non-linked directory: {path}")
    if os.name != "nt" and not _private_posix(metadata):
        raise CodexHookReceiptError(f"{label} must be current-user private")
    return path


def _ensure_store_directory(paths: h.HarnessPaths) -> Path:
    state_root = _validate_directory(paths.harness, "AOI state directory")
    directory = codex_hook_receipts_dir(paths)
    if directory.exists() or h._path_is_link_like(directory):
        return _validate_directory(directory, "Codex hook receipt directory")
    try:
        directory.mkdir(mode=0o700)
        if os.name != "nt":
            directory.chmod(0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot create Codex hook receipt directory: {exc}") from exc
    if h.canonicalize_no_link_traversal(paths.harness, "AOI state directory") != state_root:
        raise CodexHookReceiptError("AOI state directory changed during receipt store creation")
    return _validate_directory(directory, "Codex hook receipt directory")


def _validated_path(paths: h.HarnessPaths, receipt: Mapping[str, Any]) -> Path:
    directory = _validate_directory(codex_hook_receipts_dir(paths), "Codex hook receipt directory")
    path = codex_hook_receipt_path(paths, receipt)
    if path.parent != directory or not _RECEIPT_NAME.fullmatch(path.name):
        raise CodexHookReceiptError("Codex hook receipt path escapes its managed store")
    if h.canonicalize_no_link_traversal(path, "Codex hook receipt") != path:
        raise CodexHookReceiptError("Codex hook receipt path is not canonical")
    return path


def _read_path(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        if h.canonicalize_no_link_traversal(path, "Codex hook receipt") != path:
            raise CodexHookReceiptError("Codex hook receipt path is not canonical")
        before = path.lstat()
        if h._path_is_link_like(path) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CodexHookReceiptError("Codex hook receipt must be one regular non-linked file")
        if os.name != "nt" and not _private_posix(before):
            raise CodexHookReceiptError("Codex hook receipt must be current-user private")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise CodexHookReceiptError("Codex hook receipt changed while opening")
            payload = handle.read(MAX_CODEX_HOOK_RECEIPT_BYTES + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise CodexHookReceiptError(f"Codex hook receipt is missing: {path}") from exc
    except CodexHookReceiptError:
        raise
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot read Codex hook receipt: {exc}") from exc
    if len(payload) > MAX_CODEX_HOOK_RECEIPT_BYTES:
        raise CodexHookReceiptError("Codex hook receipt exceeds 64KiB bound")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(payload) != finished.st_size
        or (os.name != "nt" and not _private_posix(after))
        or h.canonicalize_no_link_traversal(path, "Codex hook receipt") != path
    ):
        raise CodexHookReceiptError("Codex hook receipt changed while reading")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexHookReceiptError("Codex hook receipt is corrupt JSON") from exc
    receipt, canonical = _canonical_validated_receipt(decoded)
    if payload != canonical:
        raise CodexHookReceiptError("Codex hook receipt is not exact canonical sealed JSON")
    return receipt, payload


def _canonical_metadata_bytes(value: Any) -> bytes:
    try:
        return canonical_json_bytes(
            value, max_bytes=MAX_CODEX_HOOK_RECEIPT_CONTROL_BYTES
        )
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise CodexHookReceiptError(f"receipt store metadata is invalid: {exc}") from exc


def _sealed_metadata(
    preimage: Mapping[str, Any], *, digest_field: str
) -> dict[str, Any]:
    value = dict(preimage)
    value[digest_field] = hashlib.sha256(_canonical_metadata_bytes(value)).hexdigest()
    return value


def _require_exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CodexHookReceiptError(f"{label} field set is invalid")
    return value


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CodexHookReceiptError(f"{label} must be an integer >= {minimum}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise CodexHookReceiptError(f"{label} must be lowercase SHA-256")
    return value


def _require_operation_id(value: Any) -> str:
    if not isinstance(value, str):
        raise CodexHookReceiptError("receipt rotation operation id must be text")
    try:
        return h.validate_id(value, "receipt rotation operation id")
    except h.HarnessError as exc:
        raise CodexHookReceiptError(str(exc)) from exc


def _require_generation_id(value: Any, label: str = "generation id") -> str:
    if not isinstance(value, str) or _GENERATION_ID.fullmatch(value) is None:
        raise CodexHookReceiptError(f"{label} is invalid")
    return value


def _validate_inventory_summary(value: Any, label: str) -> dict[str, Any]:
    item = _require_exact_fields(
        value,
        {"entry_count", "aggregate_bytes", "inventory_sha256"},
        label,
    )
    _require_int(item["entry_count"], f"{label} entry_count")
    _require_int(item["aggregate_bytes"], f"{label} aggregate_bytes")
    _require_sha256(item["inventory_sha256"], f"{label} inventory_sha256")
    return item


def _validate_authority_ref(value: Any) -> dict[str, Any]:
    item = _require_exact_fields(
        value,
        {"session_id", "epoch", "authority_record_sha256"},
        "receipt rotation authority",
    )
    if not isinstance(item["session_id"], str) or not item["session_id"]:
        raise CodexHookReceiptError("receipt rotation authority session id is invalid")
    _require_int(item["epoch"], "receipt rotation authority epoch", minimum=1)
    _require_sha256(
        item["authority_record_sha256"],
        "receipt rotation authority record SHA-256",
    )
    return item


def _validate_sealed_metadata(
    value: Any,
    *,
    fields: set[str],
    digest_field: str,
    label: str,
) -> dict[str, Any]:
    item = _require_exact_fields(value, fields | {digest_field}, label)
    digest = _require_sha256(item[digest_field], f"{label} digest")
    preimage = {key: item[key] for key in fields}
    if hashlib.sha256(_canonical_metadata_bytes(preimage)).hexdigest() != digest:
        raise CodexHookReceiptError(f"{label} digest is invalid")
    return item


def _read_private_payload(path: Path, label: str, *, max_bytes: int) -> bytes:
    try:
        if h.canonicalize_no_link_traversal(path, label) != path:
            raise CodexHookReceiptError(f"{label} path is not canonical")
        before = path.lstat()
        if h._path_is_link_like(path) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CodexHookReceiptError(f"{label} must be one regular non-linked file")
        if os.name != "nt" and not _private_posix(before):
            raise CodexHookReceiptError(f"{label} must be current-user private")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise CodexHookReceiptError(f"{label} changed while opening")
            payload = handle.read(max_bytes + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise CodexHookReceiptError(f"{label} is missing: {path}") from exc
    except CodexHookReceiptError:
        raise
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot read {label}: {exc}") from exc
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if len(payload) > max_bytes:
        raise CodexHookReceiptError(f"{label} exceeds its byte bound")
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(payload) != finished.st_size
        or (os.name != "nt" and not _private_posix(after))
        or h.canonicalize_no_link_traversal(path, label) != path
    ):
        raise CodexHookReceiptError(f"{label} changed while reading")
    return payload


def _read_private_json(path: Path, label: str) -> dict[str, Any]:
    payload = _read_private_payload(
        path, label, max_bytes=MAX_CODEX_HOOK_RECEIPT_CONTROL_BYTES
    )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexHookReceiptError(f"{label} is corrupt JSON") from exc
    if not isinstance(value, dict) or payload != _canonical_metadata_bytes(value):
        raise CodexHookReceiptError(f"{label} is not exact canonical JSON")
    return value


def _ensure_private_directory(path: Path, label: str) -> Path:
    parent = path.parent
    _validate_directory(parent, f"{label} parent")
    if path.exists() or h._path_is_link_like(path):
        return _validate_directory(path, label)
    try:
        path.mkdir(mode=0o700)
        if os.name != "nt":
            path.chmod(0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot create {label}: {exc}") from exc
    return _validate_directory(path, label)


def _create_or_verify_metadata(path: Path, value: Mapping[str, Any], label: str) -> None:
    payload = _canonical_metadata_bytes(value)
    if path.exists() or h._path_is_link_like(path):
        if _read_private_json(path, label) != dict(value):
            raise CodexHookReceiptError(f"{label} conflicts with durable truth")
        return
    try:
        h.atomic_create_bytes(path, payload)
    except h.HarnessError:
        if not path.exists() and not h._path_is_link_like(path):
            raise
    if _read_private_json(path, label) != dict(value):
        raise CodexHookReceiptError(f"{label} readback differs from requested bytes")


def codex_hook_receipts_v2_dir(paths: h.HarnessPaths) -> Path:
    return paths.harness / CODEX_HOOK_RECEIPTS_V2_DIRECTORY


def _v2_control_path(paths: h.HarnessPaths) -> Path:
    return codex_hook_receipts_v2_dir(paths) / "control.json"


def _v2_operations_dir(paths: h.HarnessPaths) -> Path:
    return codex_hook_receipts_v2_dir(paths) / "operations"


def _v2_generations_dir(paths: h.HarnessPaths) -> Path:
    return codex_hook_receipts_v2_dir(paths) / "generations"


def _generation_dir(paths: h.HarnessPaths, generation_id: str) -> Path:
    return _v2_generations_dir(paths) / generation_id


def _generation_receipts_dir(paths: h.HarnessPaths, generation_id: str) -> Path:
    return _generation_dir(paths, generation_id) / "receipts"


def _adoption_marker_path(paths: h.HarnessPaths) -> Path:
    return codex_hook_receipts_dir(paths) / CODEX_HOOK_RECEIPTS_V2_ADOPTION_MARKER


def _scan_receipt_directory_locked(
    directory: Path,
    *,
    label: str,
    allow_missing: bool = False,
    allow_adoption_marker: bool = False,
) -> tuple[list[tuple[dict[str, Any], bytes]], int, list[dict[str, Any]]]:
    if not directory.exists():
        if allow_missing:
            return [], 0, []
        raise CodexHookReceiptError(f"{label} is missing: {directory}")
    _validate_directory(directory, label)
    entries: list[Path] = []
    try:
        with os.scandir(directory) as scan:
            for entry in scan:
                path = Path(entry.path)
                if allow_adoption_marker and path.name == CODEX_HOOK_RECEIPTS_V2_ADOPTION_MARKER:
                    continue
                entries.append(path)
                if len(entries) > MAX_CODEX_HOOK_RECEIPT_ENTRIES:
                    raise CodexHookReceiptError("receipt_store_full: entry cap is exhausted")
    except CodexHookReceiptError:
        raise
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot scan Codex hook receipt store: {exc}") from exc
    entries.sort(key=lambda item: item.name)
    total_bytes = 0
    records: list[tuple[dict[str, Any], bytes]] = []
    inventory: list[dict[str, Any]] = []
    for path in entries:
        if not _RECEIPT_NAME.fullmatch(path.name):
            raise CodexHookReceiptError(f"Codex hook receipt store has unexpected entry: {path.name}")
        receipt, payload = _read_path(path)
        if path.name != f"{codex_hook_receipt_key(receipt)}.json":
            raise CodexHookReceiptError("Codex hook receipt filename does not match event identity")
        total_bytes += len(payload)
        if total_bytes > MAX_CODEX_HOOK_RECEIPT_STORE_BYTES:
            raise CodexHookReceiptError("receipt_store_full: aggregate byte cap is exhausted")
        records.append((receipt, payload))
        inventory.append(
            {
                "name": path.name,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return records, total_bytes, inventory


def _inventory_summary(
    inventory: list[dict[str, Any]], total_bytes: int
) -> dict[str, Any]:
    return {
        "entry_count": len(inventory),
        "aggregate_bytes": total_bytes,
        "inventory_sha256": hashlib.sha256(
            _canonical_metadata_bytes(inventory)
        ).hexdigest(),
    }


def _scan_store_locked(
    paths: h.HarnessPaths,
    *,
    allow_adoption_marker: bool = False,
) -> tuple[list[tuple[dict[str, Any], bytes]], int]:
    records, total_bytes, _inventory = _scan_receipt_directory_locked(
        codex_hook_receipts_dir(paths),
        label="Codex hook receipt directory",
        allow_missing=True,
        allow_adoption_marker=allow_adoption_marker,
    )
    return records, total_bytes


def _legacy_inventory_locked(
    paths: h.HarnessPaths, *, allow_adoption_marker: bool
) -> tuple[list[tuple[dict[str, Any], bytes]], dict[str, Any], list[dict[str, Any]]]:
    records, total_bytes, inventory = _scan_receipt_directory_locked(
        codex_hook_receipts_dir(paths),
        label="Codex hook receipt directory",
        allow_missing=True,
        allow_adoption_marker=allow_adoption_marker,
    )
    return records, _inventory_summary(inventory, total_bytes), inventory


def _load_control_locked(paths: h.HarnessPaths) -> dict[str, Any] | None:
    from .commands.codex_hook_receipt_store import _load_control_locked as load

    return load(paths)


def _scan_generation_locked(
    paths: h.HarnessPaths, generation_id: str
) -> tuple[list[tuple[dict[str, Any], bytes]], int, list[dict[str, Any]]]:
    from .commands.codex_hook_receipt_store import _scan_generation_locked as scan

    return scan(paths, generation_id)


def _validate_committed_v2_locked(
    paths: h.HarnessPaths,
    *,
    full_inventory: bool,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    from .commands.codex_hook_receipt_store import (
        _validate_committed_v2_locked as validate,
    )

    return validate(
        paths, full_inventory=full_inventory
    )


def preview_codex_hook_receipt_rotation(
    paths: h.HarnessPaths, *, mode: str, operation_id: str
) -> dict[str, Any]:
    from .commands.codex_hook_receipt_store import (
        preview_codex_hook_receipt_rotation as preview,
    )

    return preview(
        paths, mode=mode, operation_id=operation_id
    )


def apply_codex_hook_receipt_rotation(
    paths: h.HarnessPaths,
    *,
    mode: str,
    operation_id: str,
    expected_preview_sha256: str,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    from .commands.codex_hook_receipt_store import (
        apply_codex_hook_receipt_rotation as apply,
    )

    return apply(
        paths,
        mode=mode,
        operation_id=operation_id,
        expected_preview_sha256=expected_preview_sha256,
        authority=authority,
    )


def _receipt_locations_locked(
    paths: h.HarnessPaths, *, key: str, control: Mapping[str, Any] | None
) -> list[tuple[str, Path]]:
    locations: list[tuple[str, Path]] = []
    legacy = codex_hook_receipts_dir(paths) / f"{key}.json"
    if legacy.exists() or h._path_is_link_like(legacy):
        locations.append((CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION, legacy))
    if control is not None:
        for generation_id in control["generation_ids"][1:]:
            path = _generation_receipts_dir(paths, generation_id) / f"{key}.json"
            if path.exists() or h._path_is_link_like(path):
                locations.append((generation_id, path))
    return locations


def _load_unique_receipt_locked(
    paths: h.HarnessPaths,
    *,
    key: str,
    control: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bytes] | None:
    locations = _receipt_locations_locked(paths, key=key, control=control)
    if len(locations) > 1:
        raise CodexHookReceiptError(
            "Codex hook receipt identity is duplicated across generations"
        )
    if not locations:
        return None
    stored, payload = _read_path(locations[0][1])
    if codex_hook_receipt_key(stored) != key:
        raise CodexHookReceiptError("Codex hook receipt path identity mismatch")
    return stored, payload


def _validated_runtime_control_locked(paths: h.HarnessPaths) -> dict[str, Any] | None:
    control = _load_control_locked(paths)
    if control is None:
        root = codex_hook_receipts_v2_dir(paths)
        marker = _adoption_marker_path(paths)
        if (
            root.exists()
            or h._path_is_link_like(root)
            or marker.exists()
            or h._path_is_link_like(marker)
        ):
            raise CodexHookReceiptError(
                "receipt_rotation_pending: exact operation resume is required"
            )
        return None
    control, _intents, _generations = _validate_committed_v2_locked(
        paths, full_inventory=False
    )
    return control


def load_codex_hook_receipt(
    paths: h.HarnessPaths, sealed_receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Load the exact sealed receipt selected by its validated event identity."""

    receipt, _payload = _canonical_validated_receipt(sealed_receipt)
    with h.state_lock(paths, create_layout=False):
        control = _validated_runtime_control_locked(paths)
        found = _load_unique_receipt_locked(
            paths,
            key=codex_hook_receipt_key(receipt),
            control=control,
        )
        if found is None:
            raise CodexHookReceiptError("Codex hook receipt is missing")
        stored, _stored_payload = found
        return stored


def load_codex_hook_receipt_by_identity(
    paths: h.HarnessPaths,
    *,
    receipt_type: str,
    event_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Load one immutable record using only its adapter event identity.

    PostToolUse receives the same platform tool identity as PreToolUse but not
    the earlier claim snapshot.  Reconstructing the entire pre receipt after a
    tool ran would race claim changes, so correlation selects the create-only
    record by the identity that already names its path and then validates the
    complete stored receipt.
    """

    selector = {
        "receipt_type": receipt_type,
        "event_identity": dict(event_identity),
    }
    key = hashlib.sha256(
        canonical_json_bytes(
            _event_identity_preimage(selector),
            max_bytes=MAX_CODEX_HOOK_RECEIPT_BYTES,
        )
    ).hexdigest()
    with h.state_lock(paths, create_layout=False):
        control = _validated_runtime_control_locked(paths)
        found = _load_unique_receipt_locked(paths, key=key, control=control)
        if found is None:
            raise CodexHookReceiptError("Codex hook receipt is missing")
        stored, _stored_payload = found
        if (
            stored.get("receipt_type") != receipt_type
            or stored.get("event_identity") != dict(event_identity)
            or codex_hook_receipt_key(stored) != key
        ):
            raise CodexHookReceiptError(
                "Codex hook receipt does not match requested event identity"
            )
        return stored


def store_codex_hook_receipt(
    paths: h.HarnessPaths, sealed_receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Create one receipt, accept only byte-exact replay, or reject collision.

    The full capacity scan and create are held by the same cooperative state
    lock.  A full store stays full; no eviction or partial-accounting shortcut
    is available.
    """

    receipt, payload = _canonical_validated_receipt(sealed_receipt)
    with h.state_lock(paths, create_layout=False):
        control = _validated_runtime_control_locked(paths)
        key = codex_hook_receipt_key(receipt)
        found = _load_unique_receipt_locked(paths, key=key, control=control)
        if found is not None:
            stored, stored_payload = found
            if stored_payload != payload:
                raise CodexHookReceiptError(
                    "Codex hook receipt collision: same event identity has divergent sealed bytes"
                )
            return stored
        # Legacy v1 receipts remain readable and their exact bytes remain
        # idempotently replayable.  Only a newly created store entry adopts the
        # current canonical agent-identity contract.
        _require_current_store_identity(receipt)
        if control is None:
            _ensure_store_directory(paths)
            path = _validated_path(paths, receipt)
            records, total_bytes = _scan_store_locked(paths)
        else:
            active = control["active_generation_id"]
            directory = _validate_directory(
                _generation_receipts_dir(paths, active),
                "Codex hook receipt generation directory",
            )
            path = directory / f"{key}.json"
            if path.parent != directory or _RECEIPT_NAME.fullmatch(path.name) is None:
                raise CodexHookReceiptError("Codex hook receipt path escapes active generation")
            records, total_bytes, _inventory = _scan_generation_locked(paths, active)
        if len(records) >= MAX_CODEX_HOOK_RECEIPT_ENTRIES:
            raise CodexHookReceiptError("receipt_store_full: entry cap is exhausted")
        if total_bytes + len(payload) > MAX_CODEX_HOOK_RECEIPT_STORE_BYTES:
            raise CodexHookReceiptError("receipt_store_full: aggregate byte cap is exhausted")
        try:
            h.atomic_create_bytes(path, payload)
        except h.HarnessError:
            # A native or non-cooperating writer may win a create race.  It is
            # safe to continue only by validating that exact immutable record.
            if not path.exists() and not h._path_is_link_like(path):
                raise
        stored, stored_payload = _read_path(path)
        if stored_payload != payload:
            raise CodexHookReceiptError(
                "Codex hook receipt collision: same event identity has divergent sealed bytes"
            )
        return stored


def inspect_codex_hook_receipt_store(paths: h.HarnessPaths) -> dict[str, Any]:
    """Return deterministic complete accounting, or fail closed on corruption."""

    with h.state_lock(paths, create_layout=False):
        control = _load_control_locked(paths)
        if control is None:
            root = codex_hook_receipts_v2_dir(paths)
            marker = _adoption_marker_path(paths)
            if (
                root.exists()
                or h._path_is_link_like(root)
                or marker.exists()
                or h._path_is_link_like(marker)
            ):
                raise CodexHookReceiptError(
                    "receipt_rotation_pending: exact operation resume is required"
                )
            records, total_bytes = _scan_store_locked(paths)
            retained_records = records
            generation_report = None
        else:
            control, intents, generations = _validate_committed_v2_locked(
                paths, full_inventory=True
            )
            all_records: list[tuple[dict[str, Any], bytes]] = []
            legacy_records, legacy_total = _scan_store_locked(
                paths, allow_adoption_marker=True
            )
            all_records.extend(legacy_records)
            total_retained = legacy_total
            seen: set[str] = set()
            for receipt, _payload in legacy_records:
                key = codex_hook_receipt_key(receipt)
                if key in seen:
                    raise CodexHookReceiptError("duplicate receipt identity in retained store")
                seen.add(key)
            active_records: list[tuple[dict[str, Any], bytes]] = []
            active_total = 0
            for generation_id in control["generation_ids"][1:]:
                current, current_total, _inventory = _scan_generation_locked(
                    paths, generation_id
                )
                for receipt, _payload in current:
                    key = codex_hook_receipt_key(receipt)
                    if key in seen:
                        raise CodexHookReceiptError(
                            "duplicate receipt identity across retained generations"
                        )
                    seen.add(key)
                all_records.extend(current)
                total_retained += current_total
                if generation_id == control["active_generation_id"]:
                    active_records = current
                    active_total = current_total
            records = active_records
            total_bytes = active_total
            retained_records = all_records
            generation_report = {
                "store_schema": CODEX_HOOK_RECEIPTS_V2_SCHEMA,
                "control_revision": control["control_revision"],
                "control_sha256": control["control_sha256"],
                "active_generation_id": control["active_generation_id"],
                "generation_count": len(control["generation_ids"]),
                "generation_limit": MAX_CODEX_HOOK_RECEIPT_GENERATIONS,
                "retained_entry_count": len(all_records),
                "retained_aggregate_bytes": total_retained,
                "legacy_inventory": control["legacy_inventory"],
                "pending_operation_count": len(set(intents) - set(control["applied_operations"])),
                "archive_integrity": "verified",
                "generation_summaries": {
                    key: value["inventory_summary"] for key, value in generations.items()
                },
            }
    type_counts = Counter(str(item["receipt_type"]) for item, _payload in records)
    retained_type_counts = Counter(
        str(item["receipt_type"]) for item, _payload in retained_records
    )
    capacity_status = "available"
    if len(records) >= MAX_CODEX_HOOK_RECEIPT_ENTRIES or total_bytes >= MAX_CODEX_HOOK_RECEIPT_STORE_BYTES:
        capacity_status = "full"
    elif (
        len(records) * 100 >= MAX_CODEX_HOOK_RECEIPT_ENTRIES * _NEAR_CAPACITY_PERCENT
        or total_bytes * 100 >= MAX_CODEX_HOOK_RECEIPT_STORE_BYTES * _NEAR_CAPACITY_PERCENT
    ):
        capacity_status = "near_full"
    result = {
        "entry_count": len(records),
        "retained_entry_count": len(retained_records),
        "aggregate_bytes": total_bytes,
        "entry_capacity": MAX_CODEX_HOOK_RECEIPT_ENTRIES,
        "aggregate_byte_capacity": MAX_CODEX_HOOK_RECEIPT_STORE_BYTES,
        "capacity_status": capacity_status,
        "receipt_type_counts": {name: type_counts[name] for name in sorted(type_counts)},
        "corruption": [],
    }
    if generation_report is not None:
        generation_report["active_entry_count"] = len(records)
        generation_report["active_aggregate_bytes"] = total_bytes
        generation_report["retained_receipt_type_counts"] = {
            name: retained_type_counts[name] for name in sorted(retained_type_counts)
        }
        result["generations"] = generation_report
    return result


def register_commands(subparsers: Any, *, add_json_argument: Any) -> None:
    from .commands.codex_hook_receipt_store import (
        register_codex_hook_receipt_store_commands,
    )

    register_codex_hook_receipt_store_commands(
        subparsers, add_json_argument=add_json_argument
    )


__all__ = [
    "CODEX_HOOK_RECEIPTS_DIRECTORY",
    "CODEX_HOOK_RECEIPTS_V2_DIRECTORY",
    "CODEX_HOOK_RECEIPTS_V2_SCHEMA",
    "MAX_CODEX_HOOK_RECEIPT_BYTES",
    "MAX_CODEX_HOOK_RECEIPT_ENTRIES",
    "MAX_CODEX_HOOK_RECEIPT_STORE_BYTES",
    "READ_ONLY_COMMANDS",
    "MAX_CODEX_HOOK_RECEIPT_GENERATIONS",
    "CodexHookReceiptError",
    "apply_codex_hook_receipt_rotation",
    "codex_hook_receipt_key",
    "codex_hook_receipt_path",
    "codex_hook_receipts_dir",
    "codex_hook_receipts_v2_dir",
    "inspect_codex_hook_receipt_store",
    "load_codex_hook_receipt",
    "load_codex_hook_receipt_by_identity",
    "preview_codex_hook_receipt_rotation",
    "register_commands",
    "store_codex_hook_receipt",
]
