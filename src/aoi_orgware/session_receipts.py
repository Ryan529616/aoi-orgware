"""Startup-only persistence for dispatch-v6 SessionStart receipts.

This is deliberately a narrow filesystem boundary.  It neither reads hook
input nor mutates task/Chief state.  A caller supplies the already-observed
startup fields and receives the sealed receipt that was durably published (or
the matching earlier receipt for an idempotent replay).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from . import harnesslib as h
from .resource_config import snapshot_managed_resource_files
from .routing_authority import seal_startup_receipt, validate_stored_startup_receipt
from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


STARTUP_RECEIPTS_DIRECTORY = "startup-receipts"
MAX_STARTUP_RECEIPT_BYTES = 512 * 1024
# Windows stores the bounded canonical receipt in a DPAPI/base64 envelope.
# Keep a separate bounded file limit so a decoded receipt at its exact limit is
# not rejected just because that representation expands it.
MAX_STARTUP_RECEIPT_FILE_BYTES = 1024 * 1024
MAX_STARTUP_RECEIPT_SCAN_ENTRIES = 256
MAX_STARTUP_RECEIPT_SCAN_BYTES = 4 * 1024 * 1024

_WINDOWS_ENVELOPE_VERSION = 1
_WINDOWS_ENVELOPE_PROTECTION = "windows-dpapi-current-user-v1"
_WINDOWS_ENVELOPE_FIELDS = frozenset(
    {"schema_version", "storage_protection", "sealed_receipt_dpapi_base64"}
)

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}")
_RECEIPT_NAME = re.compile(r"[0-9a-f]{64}\.json")


class SessionReceiptError(h.HarnessError):
    """A startup receipt cannot be safely persisted or loaded."""


def _session_id(value: Any) -> str:
    if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
        raise SessionReceiptError("startup session id is invalid")
    return value


def startup_receipt_key(session_id: str) -> str:
    """Return the full SHA-256 filename key; never expose the raw session ID."""

    return hashlib.sha256(_session_id(session_id).encode("utf-8")).hexdigest()


def startup_receipts_dir(paths: h.HarnessPaths) -> Path:
    """Return the fixed receipt directory below the configured AOI state root."""

    return paths.harness / STARTUP_RECEIPTS_DIRECTORY


def startup_receipt_path(paths: h.HarnessPaths, session_id: str) -> Path:
    """Return the canonical intended path without creating or probing it."""

    return startup_receipts_dir(paths) / f"{startup_receipt_key(session_id)}.json"


def startup_receipt_storage_protection() -> dict[str, str]:
    """Report content protection separately from filesystem-access evidence."""

    if os.name == "nt":
        return {
            "content_protection": _WINDOWS_ENVELOPE_PROTECTION,
            "acl_status": "windows-acl-unverified",
        }
    return {
        "content_protection": "posix-canonical-plaintext-v1",
        "acl_status": "not-applicable",
        "mode_status": "posix-current-user-owner-private-mode",
    }


def _posix_current_user_owner_private_mode(metadata: os.stat_result) -> bool:
    return (
        metadata.st_uid == os.geteuid()  # type: ignore[attr-defined]
        and not stat.S_IMODE(metadata.st_mode) & 0o077
    )


def _validate_receipt_directory(path: Path, label: str) -> Path:
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        if canonical != path:
            raise SessionReceiptError(f"{label} path is not canonical: {path}")
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SessionReceiptError(f"{label} is missing: {path}") from exc
    except h.HarnessError:
        raise
    except OSError as exc:
        raise SessionReceiptError(f"cannot inspect {label} {path}: {exc}") from exc
    if h._path_is_link_like(path) or not stat.S_ISDIR(metadata.st_mode):
        raise SessionReceiptError(f"{label} must be a non-linked directory: {path}")
    if os.name != "nt" and not _posix_current_user_owner_private_mode(metadata):
        raise SessionReceiptError(
            f"{label} must be current-user-owned with private POSIX mode: {path}"
        )
    return path


def _ensure_receipt_directory(paths: h.HarnessPaths) -> Path:
    """Create only the dedicated managed leaf, after the startup gate and lock."""

    state_root = _validate_receipt_directory(paths.harness, "AOI state directory")
    directory = startup_receipts_dir(paths)
    if directory.exists() or h._path_is_link_like(directory):
        return _validate_receipt_directory(directory, "startup receipt directory")
    try:
        directory.mkdir(mode=0o700)
        if os.name != "nt":
            directory.chmod(0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise SessionReceiptError(
            f"cannot create startup receipt directory {directory}: {exc}"
        ) from exc
    if h.canonicalize_no_link_traversal(paths.harness, "AOI state directory") != state_root:
        raise SessionReceiptError("AOI state directory changed during receipt directory creation")
    return _validate_receipt_directory(directory, "startup receipt directory")


def _validate_receipt_path(paths: h.HarnessPaths, path: Path) -> Path:
    directory = startup_receipts_dir(paths)
    _validate_receipt_directory(directory, "startup receipt directory")
    if path.parent != directory or not _RECEIPT_NAME.fullmatch(path.name):
        raise SessionReceiptError("startup receipt path is outside the managed receipt store")
    try:
        canonical = h.canonicalize_no_link_traversal(path, "startup receipt")
    except h.HarnessError:
        raise
    if canonical != path:
        raise SessionReceiptError(f"startup receipt path is not canonical: {path}")
    return path


def _read_receipt(path: Path, expected_session_id: str | None) -> dict[str, Any]:
    try:
        if h.canonicalize_no_link_traversal(path, "startup receipt") != path:
            raise SessionReceiptError(f"startup receipt path is not canonical: {path}")
        before = path.lstat()
        if (
            h._path_is_link_like(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise SessionReceiptError(
                f"startup receipt must be one regular non-linked file: {path}"
            )
        if os.name != "nt" and not _posix_current_user_owner_private_mode(before):
            raise SessionReceiptError(
                f"startup receipt must have owner-private POSIX mode: {path}"
            )
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise SessionReceiptError(f"startup receipt changed while being opened: {path}")
            payload = handle.read(MAX_STARTUP_RECEIPT_FILE_BYTES + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise SessionReceiptError(f"startup receipt is missing: {path}") from exc
    except SessionReceiptError:
        raise
    except OSError as exc:
        raise SessionReceiptError(f"cannot read startup receipt {path}: {exc}") from exc
    if len(payload) > MAX_STARTUP_RECEIPT_FILE_BYTES:
        raise SessionReceiptError(f"startup receipt file exceeds byte bound: {path}")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(payload) != finished.st_size
        or (
            os.name != "nt"
            and not _posix_current_user_owner_private_mode(after)
        )
        or h.canonicalize_no_link_traversal(path, "startup receipt") != path
    ):
        raise SessionReceiptError(f"startup receipt changed while being read: {path}")
    canonical_payload = _decode_storage_payload(payload, path)
    try:
        decoded = json.loads(canonical_payload.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise SessionReceiptError("startup receipt must contain a JSON object")
        if "startup_receipt_sha256" not in decoded:
            raise SessionReceiptError("startup receipt sealing field is missing")
        sealed = validate_stored_startup_receipt(decoded)
        canonical = canonical_json_bytes(sealed, max_bytes=MAX_STARTUP_RECEIPT_BYTES)
    except SessionReceiptError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, SemanticEventError, ValueError) as exc:
        raise SessionReceiptError(f"startup receipt is invalid: {path}: {exc}") from exc
    if canonical_payload != canonical:
        raise SessionReceiptError(f"startup receipt is not exact canonical sealed JSON: {path}")
    if expected_session_id is not None and sealed["session_id"] != expected_session_id:
        raise SessionReceiptError("startup receipt session identity does not match its path")
    if startup_receipt_key(sealed["session_id"]) + ".json" != path.name:
        raise SessionReceiptError("startup receipt filename key does not match its session")
    return sealed


def _windows_dpapi_receipt_transform(data: bytes, *, protect: bool) -> bytes:
    operation = "protect" if protect else "unprotect"
    try:
        return h._windows_dpapi_transform(data, protect=protect)
    except h.HarnessError as exc:
        # harnesslib's helper is shared with Chief credentials; do not expose
        # that misleading domain name at this startup-receipt boundary.
        raise SessionReceiptError(
            f"Windows DPAPI could not {operation} startup receipt contents"
        ) from exc


def _encode_storage_payload(sealed: Mapping[str, Any]) -> bytes:
    """Return the exact bounded on-disk representation for one sealed receipt."""

    canonical = canonical_json_bytes(sealed, max_bytes=MAX_STARTUP_RECEIPT_BYTES)
    if os.name != "nt":
        return canonical
    protected = _windows_dpapi_receipt_transform(canonical, protect=True)
    envelope = {
        "schema_version": _WINDOWS_ENVELOPE_VERSION,
        "storage_protection": _WINDOWS_ENVELOPE_PROTECTION,
        "sealed_receipt_dpapi_base64": base64.b64encode(protected).decode("ascii"),
    }
    try:
        return canonical_json_bytes(envelope, max_bytes=MAX_STARTUP_RECEIPT_FILE_BYTES)
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise SessionReceiptError(
            f"Windows startup receipt envelope cannot be canonicalized: {exc}"
        ) from exc


def _decode_storage_payload(payload: bytes, path: Path) -> bytes:
    """Validate the platform envelope and return canonical sealed receipt bytes."""

    if os.name != "nt":
        return payload
    try:
        envelope = json.loads(payload.decode("utf-8"))
        if not isinstance(envelope, dict) or set(envelope) != _WINDOWS_ENVELOPE_FIELDS:
            raise SessionReceiptError("Windows startup receipt envelope has an invalid schema")
        if envelope.get("schema_version") != _WINDOWS_ENVELOPE_VERSION:
            raise SessionReceiptError("Windows startup receipt envelope version is unsupported")
        if envelope.get("storage_protection") != _WINDOWS_ENVELOPE_PROTECTION:
            raise SessionReceiptError("Windows startup receipt envelope protection is unsupported")
        encoded = envelope.get("sealed_receipt_dpapi_base64")
        if not isinstance(encoded, str):
            raise SessionReceiptError("Windows startup receipt envelope payload is malformed")
        protected = base64.b64decode(encoded.encode("ascii"), validate=True)
        if base64.b64encode(protected).decode("ascii") != encoded:
            raise SessionReceiptError("Windows startup receipt envelope payload is non-canonical")
        if payload != canonical_json_bytes(envelope, max_bytes=MAX_STARTUP_RECEIPT_FILE_BYTES):
            raise SessionReceiptError("Windows startup receipt envelope is not exact canonical JSON")
    except SessionReceiptError:
        raise
    except (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError, ValueError, SemanticEventError) as exc:
        raise SessionReceiptError(f"Windows startup receipt envelope is invalid: {path}: {exc}") from exc
    canonical = _windows_dpapi_receipt_transform(protected, protect=False)
    if len(canonical) > MAX_STARTUP_RECEIPT_BYTES:
        raise SessionReceiptError(f"startup receipt exceeds byte bound after DPAPI unprotect: {path}")
    return canonical


def _scan_startup_receipt_usage_locked(
    paths: h.HarnessPaths,
) -> tuple[list[dict[str, Any]], int]:
    """Validate every store member while the state lock excludes recovery/writers."""

    directory = startup_receipts_dir(paths)
    if not directory.exists():
        return [], 0
    _validate_receipt_directory(directory, "startup receipt directory")
    entries: list[Path] = []
    try:
        with os.scandir(directory) as scan:
            for entry in scan:
                if len(entries) >= MAX_STARTUP_RECEIPT_SCAN_ENTRIES:
                    raise SessionReceiptError("startup receipt scan reached its entry bound")
                entries.append(Path(entry.path))
    except SessionReceiptError:
        raise
    except OSError as exc:
        raise SessionReceiptError(f"cannot scan startup receipt directory {directory}: {exc}") from exc
    entries.sort(key=lambda item: item.name)
    total_bytes = 0
    receipts: list[dict[str, Any]] = []
    for path in entries:
        if not _RECEIPT_NAME.fullmatch(path.name):
            raise SessionReceiptError(f"startup receipt store has an unexpected entry: {path}")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SessionReceiptError(f"cannot inspect startup receipt {path}: {exc}") from exc
        total_bytes += int(metadata.st_size)
        if total_bytes > MAX_STARTUP_RECEIPT_SCAN_BYTES:
            raise SessionReceiptError("startup receipt scan reached its byte bound")
        receipts.append(_read_receipt(path, None))
    return receipts, total_bytes


def _scan_startup_receipts_locked(paths: h.HarnessPaths) -> list[dict[str, Any]]:
    return _scan_startup_receipt_usage_locked(paths)[0]


def _load_startup_receipt_locked(paths: h.HarnessPaths, session_id: str) -> dict[str, Any]:
    path = _validate_receipt_path(paths, startup_receipt_path(paths, session_id))
    return _read_receipt(path, session_id)


def load_startup_receipt_locked(
    paths: h.HarnessPaths, session_id: str
) -> dict[str, Any]:
    """Load one receipt while the caller already owns the project state lock.

    Chief registration needs the receipt, task state, resource receipt, and
    live config files to share one serialization boundary.  This explicit API
    avoids a nested lock while retaining the exact same path and content
    validation as :func:`load_startup_receipt`.
    """

    return _load_startup_receipt_locked(paths, _session_id(session_id))


def scan_startup_receipts_locked(paths: h.HarnessPaths) -> list[dict[str, Any]]:
    """Validate all receipts while the caller already owns the state lock."""

    return _scan_startup_receipts_locked(paths)


def load_startup_receipt(paths: h.HarnessPaths, session_id: str) -> dict[str, Any]:
    """Load one exact startup receipt under the project lock, failing closed."""

    normalized = _session_id(session_id)
    with h.state_lock(paths, create_layout=False):
        return load_startup_receipt_locked(paths, normalized)


def scan_startup_receipts(paths: h.HarnessPaths) -> list[dict[str, Any]]:
    """Return every valid canonical receipt, or fail before accepting ambiguity."""

    with h.state_lock(paths, create_layout=False):
        return scan_startup_receipts_locked(paths)


def _same_startup_identity(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return left.get("schema_version") == right.get("schema_version") == 2 and all(
        left.get(field) == right.get(field)
        for field in ("session_id", "aoi_config_sha256", "project_root", "cwd")
    )


def _fresh_write_paths(
    paths: h.HarnessPaths, sealed: Mapping[str, Any]
) -> h.HarnessPaths:
    """Reload and bind all write authority before touching receipt directories."""

    try:
        fresh = h.get_paths(paths.root)
    except h.HarnessError as exc:
        raise SessionReceiptError(f"cannot reload startup receipt project binding: {exc}") from exc
    if (
        fresh.root != paths.root
        or fresh.config != paths.config
        or fresh.harness != paths.harness
        or fresh.lock != paths.lock
    ):
        raise SessionReceiptError(
            "startup receipt paths do not match the freshly reloaded AOI configuration"
        )
    if sealed["project_root"] != str(fresh.root):
        raise SessionReceiptError("startup receipt project root is not the exact canonical AOI root")
    if sealed["aoi_config_sha256"] != fresh.project.sha256:
        raise SessionReceiptError("startup receipt configuration SHA does not match current aoi.toml")
    try:
        cwd = h.canonicalize_no_link_traversal(Path(sealed["cwd"]), "startup receipt cwd")
        cwd.relative_to(fresh.root)
    except (h.HarnessError, TypeError, ValueError) as exc:
        raise SessionReceiptError(
            "startup receipt cwd must be an existing canonical path inside its project root"
        ) from exc
    if str(cwd) != sealed["cwd"]:
        raise SessionReceiptError("startup receipt cwd is not an exact canonical path")
    if not cwd.is_dir():
        raise SessionReceiptError("startup receipt cwd must name an existing directory")
    return fresh


def store_startup_receipt(
    paths: h.HarnessPaths, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Atomically create a startup receipt or return the same-identity prior one.

    ``seal_startup_receipt`` is deliberately called before acquiring/creating
    anything.  Therefore resume/clear/compact inputs cannot create even the
    receipt directory.  The complete create/read/identity sequence is held by
    the normal project state lock so atomic-temporary recovery cannot race it.
    """

    sealed = seal_startup_receipt(receipt)
    write_paths = _fresh_write_paths(paths, sealed)
    with h.state_lock(write_paths, create_layout=False):
        # Reload once more under the selected state lock.  A config/root/path
        # drift cannot redirect the first receipt-directory creation.
        write_paths = _fresh_write_paths(paths, sealed)
        return _store_startup_receipt_locked(write_paths, sealed)


def _store_startup_receipt_locked(
    write_paths: h.HarnessPaths, sealed: Mapping[str, Any]
) -> dict[str, Any]:
    """Publish one sealed receipt while the caller owns the project lock."""

    session_id = sealed["session_id"]
    _ensure_receipt_directory(write_paths)
    path = _validate_receipt_path(
        write_paths, startup_receipt_path(write_paths, session_id)
    )
    # Existing paths are only validated and loaded below; replay must not open
    # an atomic-create attempt.  A new filename reserves its exact canonical
    # bytes before publication, so a successful create can never push a valid
    # store beyond either scan bound.
    if path.exists():
        stored = _load_startup_receipt_locked(write_paths, session_id)
    else:
        try:
            payload = _encode_storage_payload(sealed)
        except (SemanticEventError, TypeError, ValueError) as exc:
            raise SessionReceiptError(
                f"startup receipt cannot be canonicalized: {exc}"
            ) from exc
        scanned, stored_bytes = _scan_startup_receipt_usage_locked(write_paths)
        if len(scanned) >= MAX_STARTUP_RECEIPT_SCAN_ENTRIES:
            raise SessionReceiptError("startup receipt store entry bound is exhausted")
        if stored_bytes + len(payload) > MAX_STARTUP_RECEIPT_SCAN_BYTES:
            raise SessionReceiptError("startup receipt store byte bound is exhausted")
        try:
            h.atomic_create_bytes(path, payload)
        except h.HarnessError:
            # A create may report after its destination became visible; only
            # that exact collision/publication race may fall through.
            if not path.exists():
                raise
        stored = _load_startup_receipt_locked(write_paths, session_id)
    if not _same_startup_identity(stored, sealed):
        raise SessionReceiptError(
            "startup receipt conflict: session id is already bound to different "
            "schema/config/root/cwd identity"
        )
    return stored


def persist_startup_receipt(
    paths: h.HarnessPaths, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Capture managed resource bytes and publish one schema-v2 receipt.

    File observation and receipt publication share the project state lock, so
    registration can prove that every reviewed after-image existed at the
    SessionStart boundary without comparing independent host wall clocks.
    """

    base = dict(receipt)
    expected_fields = {
        "schema_version",
        "hook_protocol_version",
        "session_id",
        "source",
        "observed_at",
        "cwd",
        "project_root",
        "aoi_config_sha256",
    }
    if set(base) != expected_fields or base.get("schema_version") != 2:
        raise SessionReceiptError("unobserved startup receipt schema is invalid")
    preflight = seal_startup_receipt(
        {
            **base,
            "observed_resource_files": [],
            "observed_resource_files_sha256": canonical_sha256([]),
        }
    )
    write_paths = _fresh_write_paths(paths, preflight)
    with h.state_lock(write_paths, create_layout=False):
        write_paths = _fresh_write_paths(paths, preflight)
        existing_path = startup_receipt_path(write_paths, preflight["session_id"])
        if existing_path.exists() or h._path_is_link_like(existing_path):
            stored = _load_startup_receipt_locked(
                write_paths, preflight["session_id"]
            )
            if not _same_startup_identity(stored, preflight):
                raise SessionReceiptError(
                    "startup receipt conflict: session id is already bound to "
                    "different schema/config/root/cwd identity"
                )
            return stored
        observed = snapshot_managed_resource_files(write_paths.root)
        sealed = seal_startup_receipt(
            {
                **base,
                "observed_resource_files": observed,
                "observed_resource_files_sha256": canonical_sha256(observed),
            }
        )
        return _store_startup_receipt_locked(write_paths, sealed)
