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
from .semantic_events import SemanticEventError, canonical_json_bytes


CODEX_HOOK_RECEIPTS_DIRECTORY = "codex-hook-receipts-v1"
MAX_CODEX_HOOK_RECEIPT_BYTES = 64 * 1024
# A normal tool turn emits a correlated PreToolUse/PostToolUse pair.  Keep a
# bounded session store large enough for ordinary work rather than exhausting
# it after 32 calls; no eviction or partial-accounting path is introduced.
MAX_CODEX_HOOK_RECEIPT_ENTRIES = 1024
MAX_CODEX_HOOK_RECEIPT_STORE_BYTES = 16 * 1024 * 1024
_NEAR_CAPACITY_PERCENT = 90

_RECEIPT_NAME = re.compile(r"[0-9a-f]{64}\.json")


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


def _scan_store_locked(paths: h.HarnessPaths) -> tuple[list[tuple[dict[str, Any], bytes]], int]:
    directory = codex_hook_receipts_dir(paths)
    if not directory.exists():
        return [], 0
    _validate_directory(directory, "Codex hook receipt directory")
    entries: list[Path] = []
    try:
        with os.scandir(directory) as scan:
            for entry in scan:
                entries.append(Path(entry.path))
                if len(entries) > MAX_CODEX_HOOK_RECEIPT_ENTRIES:
                    raise CodexHookReceiptError("receipt_store_full: entry cap is exhausted")
    except CodexHookReceiptError:
        raise
    except OSError as exc:
        raise CodexHookReceiptError(f"cannot scan Codex hook receipt store: {exc}") from exc
    entries.sort(key=lambda item: item.name)
    total_bytes = 0
    records: list[tuple[dict[str, Any], bytes]] = []
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
    return records, total_bytes


def load_codex_hook_receipt(
    paths: h.HarnessPaths, sealed_receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Load the exact sealed receipt selected by its validated event identity."""

    receipt, _payload = _canonical_validated_receipt(sealed_receipt)
    with h.state_lock(paths, create_layout=False):
        path = _validated_path(paths, receipt)
        stored, _stored_payload = _read_path(path)
        if codex_hook_receipt_key(stored) != codex_hook_receipt_key(receipt):
            raise CodexHookReceiptError("Codex hook receipt path identity mismatch")
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
        directory = _validate_directory(
            codex_hook_receipts_dir(paths), "Codex hook receipt directory"
        )
        path = directory / f"{key}.json"
        if path.parent != directory or not _RECEIPT_NAME.fullmatch(path.name):
            raise CodexHookReceiptError(
                "Codex hook receipt identity escapes its managed store"
            )
        stored, _stored_payload = _read_path(path)
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
        _ensure_store_directory(paths)
        path = _validated_path(paths, receipt)
        if path.exists() or h._path_is_link_like(path):
            stored, stored_payload = _read_path(path)
            if stored_payload != payload:
                raise CodexHookReceiptError(
                    "Codex hook receipt collision: same event identity has divergent sealed bytes"
                )
            return stored
        records, total_bytes = _scan_store_locked(paths)
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
        records, total_bytes = _scan_store_locked(paths)
    type_counts = Counter(str(item["receipt_type"]) for item, _payload in records)
    capacity_status = "available"
    if len(records) >= MAX_CODEX_HOOK_RECEIPT_ENTRIES or total_bytes >= MAX_CODEX_HOOK_RECEIPT_STORE_BYTES:
        capacity_status = "full"
    elif (
        len(records) * 100 >= MAX_CODEX_HOOK_RECEIPT_ENTRIES * _NEAR_CAPACITY_PERCENT
        or total_bytes * 100 >= MAX_CODEX_HOOK_RECEIPT_STORE_BYTES * _NEAR_CAPACITY_PERCENT
    ):
        capacity_status = "near_full"
    return {
        "entry_count": len(records),
        "aggregate_bytes": total_bytes,
        "entry_capacity": MAX_CODEX_HOOK_RECEIPT_ENTRIES,
        "aggregate_byte_capacity": MAX_CODEX_HOOK_RECEIPT_STORE_BYTES,
        "capacity_status": capacity_status,
        "receipt_type_counts": {name: type_counts[name] for name in sorted(type_counts)},
        "corruption": [],
    }


__all__ = [
    "CODEX_HOOK_RECEIPTS_DIRECTORY",
    "MAX_CODEX_HOOK_RECEIPT_BYTES",
    "MAX_CODEX_HOOK_RECEIPT_ENTRIES",
    "MAX_CODEX_HOOK_RECEIPT_STORE_BYTES",
    "CodexHookReceiptError",
    "codex_hook_receipt_key",
    "codex_hook_receipt_path",
    "codex_hook_receipts_dir",
    "inspect_codex_hook_receipt_store",
    "load_codex_hook_receipt",
    "load_codex_hook_receipt_by_identity",
    "store_codex_hook_receipt",
]
