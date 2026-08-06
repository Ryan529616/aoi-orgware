"""Immutable, compact receipt storage for the observational legacy client.

The on-disk names are deliberately short enough for ordinary Windows paths.
Full scope and attempt identities remain inside exact immutable marker files and
sealed receipts; a truncated-name collision therefore fails closed instead of
aliasing another ingest attempt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, NamedTuple, NoReturn, cast

from .contracts import canonical_company_json_bytes, company_contract_sha256
from .legacy_bridge import LegacyBridgeProjectionV1, normalize_legacy_bridge_snapshot
from .legacy_bridge_client_capacity import (
    ATTEMPT_LIMIT,
    MAX_CAPACITY_RECEIPT_BYTES,
    CapacityAttemptV1,
    CapacityContractError,
    build_capacity_receipt,
    capacity_source_sha256,
    validate_capacity_receipt,
)
from .legacy_bridge_client_receipt_contract import (
    PREPARED_SCHEMA,
    RECONCILIATION_SCHEMA,
    TERMINAL_SCHEMA,
    ReceiptContractError,
    validate_prepared as _validate_prepared_contract,
    validate_reconciliation as _validate_reconciliation_contract,
    validate_terminal as _validate_terminal_contract,
)
from .legacy_bridge_health import MAX_SOURCE_DOCUMENT_BYTES
from .native_filesystem import (
    NativeFilesystemIdentityError,
    native_filesystem_path as _native_filesystem_path,
    unlink_identity_checked,
)


_RECEIPT_ROOT = ("cv1", "lb")
_PATH_ID_LENGTH = 32
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_ATTEMPTS = ATTEMPT_LIMIT
_SHA = re.compile(r"[0-9a-f]{64}")
_PATH_ID = re.compile(r"[0-9a-f]{32}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_RECEIPT_MEMBER_NAMES = frozenset({
    "scope.id", "attempt.id", "source.json", "prepared.json",
    "terminal.json", "reconciled.json", "capacity.json",
})
_TEMPORARY = re.compile(
    r"\.aoi-cv1-(scope\.id|attempt\.id|source\.json|prepared\.json|"
    r"terminal\.json|reconciled\.json|capacity\.json)-([0-9a-f]{32})\.tmp",
)
_MAX_TEMPORARIES_PER_DIRECTORY = 8


class LegacyBridgeClientError(RuntimeError):
    """One stable, secret-free client failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LegacyBridgeCapacityPublicationError(LegacyBridgeClientError):
    """Capacity sealing failed before any company ingest mutation."""


class ReceiptAttempt(NamedTuple):
    source: bytes
    projection: LegacyBridgeProjectionV1
    prepared: dict[str, Any]
    terminal: dict[str, Any] | None
    reconciliation: dict[str, Any] | None


class ReceiptInventory(NamedTuple):
    attempts: tuple[ReceiptAttempt, ...]
    attempt_ids: tuple[str, ...]
    capacity_attempts: tuple[CapacityAttemptV1, ...]
    capacity_receipt: dict[str, Any] | None


def fail(code: str) -> NoReturn:
    raise LegacyBridgeClientError(code)


def sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        fail(f"invalid_{label}")
    return value


def identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        fail(f"invalid_{label}")
    return value


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or isinstance(value, bool) or value < minimum:
        fail(f"invalid_{label}")
    return value


def timestamp(value: Any, label: str) -> str:
    if type(value) is not str or len(value) > 64:
        fail(f"invalid_{label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        raise LegacyBridgeClientError(f"invalid_{label}") from exc
    if parsed.tzinfo is None:
        fail(f"invalid_{label}")
    return value


def seal(schema: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    base = {"schema_version": schema, **dict(payload)}
    digest = company_contract_sha256(
        {"domain": f"{schema}.receipt", "receipt": base},
    )
    sealed = {**base, "receipt_sha256": digest}
    canonical_company_json_bytes(sealed, max_bytes=_MAX_RECEIPT_BYTES)
    return sealed


def _regular_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink


def _link_like(path: Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    return os.name == "nt" and bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
    )


def _lstat(path: Path) -> os.stat_result:
    return os.lstat(_native_filesystem_path(path))


def _exists(path: Path) -> bool:
    try:
        _lstat(path)
    except FileNotFoundError:
        return False
    return True


def _entries(path: Path) -> list[Path]:
    with os.scandir(_native_filesystem_path(path)) as entries:
        return [path / entry.name for entry in entries]


def safe_directory(path: Path, *, create: bool) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        fail("unsafe_client_receipt_path")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        created = False
        try:
            metadata = _lstat(current)
        except FileNotFoundError:
            if not create:
                raise LegacyBridgeClientError(
                    "client_receipt_path_unavailable"
                ) from None
            try:
                os.mkdir(_native_filesystem_path(current), mode=0o700)
                created = True
            except FileExistsError:
                pass
            metadata = _lstat(current)
        except OSError as exc:
            raise LegacyBridgeClientError("client_receipt_path_unavailable") from exc
        if _link_like(current, metadata) or not stat.S_ISDIR(metadata.st_mode):
            fail("unsafe_client_receipt_path")
        if created:
            try:
                _sync_created_directory_parent(current)
            except OSError as exc:
                raise LegacyBridgeClientError("client_directory_sync_failed") from exc
    return path


def read_regular(path: Path, *, max_bytes: int = _MAX_RECEIPT_BYTES) -> bytes:
    try:
        before = _lstat(path)
        if _link_like(path, before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail("unsafe_client_receipt_file")
        descriptor = os.open(
            _native_filesystem_path(path),
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _regular_identity(opened) != _regular_identity(before):
                fail("client_receipt_file_changed")
            raw = handle.read(max_bytes + 1)
        after = _lstat(path)
    except LegacyBridgeClientError:
        raise
    except OSError as exc:
        raise LegacyBridgeClientError("client_receipt_read_failed") from exc
    if _regular_identity(after) != _regular_identity(before):
        fail("client_receipt_file_changed")
    if len(raw) > max_bytes:
        fail("client_receipt_file_overbound")
    return raw


def _member_max_bytes(name: str) -> int:
    return MAX_SOURCE_DOCUMENT_BYTES if name == "source.json" else _MAX_RECEIPT_BYTES


def _read_recovery_file(path: Path, *, max_bytes: int) -> tuple[bytes, os.stat_result]:
    try:
        before = _lstat(path)
        if (
            _link_like(path, before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink not in {1, 2}
        ):
            fail("unsafe_client_temporary_file")
        descriptor = os.open(
            _native_filesystem_path(path),
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _regular_identity(opened) != _regular_identity(before):
                fail("client_temporary_file_changed")
            raw = handle.read(max_bytes + 1)
        after = _lstat(path)
    except LegacyBridgeClientError:
        raise
    except OSError as exc:
        raise LegacyBridgeClientError("client_temporary_read_failed") from exc
    if _regular_identity(after) != _regular_identity(before):
        fail("client_temporary_file_changed")
    if len(raw) > max_bytes:
        fail("client_temporary_file_overbound")
    return raw, after


def _sync_parent_directory(path: Path) -> None:
    descriptor = os.open(
        _native_filesystem_path(path),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_created_directory_parent(path: Path) -> None:
    if os.name != "nt":
        _sync_parent_directory(path.parent)


def _unlink_recovered_temporary(path: Path, expected: os.stat_result) -> None:
    try:
        unlink_identity_checked(path, expected)
        if os.name != "nt":
            _sync_parent_directory(path.parent)
    except NativeFilesystemIdentityError:
        fail("client_temporary_file_changed")
    except LegacyBridgeClientError:
        raise
    except OSError as exc:
        raise LegacyBridgeClientError("client_temporary_cleanup_failed") from exc


def _recover_temporary(path: Path, destination: Path) -> None:
    max_bytes = _member_max_bytes(destination.name)
    temporary_bytes, temporary_stat = _read_recovery_file(path, max_bytes=max_bytes)
    try:
        destination_stat = _lstat(destination)
    except FileNotFoundError:
        if temporary_stat.st_nlink != 1:
            fail("orphan_client_temporary_has_links")
        _unlink_recovered_temporary(path, temporary_stat)
        return
    if (
        _link_like(destination, destination_stat)
        or not stat.S_ISREG(destination_stat.st_mode)
        or destination_stat.st_nlink not in {1, 2}
    ):
        fail("unsafe_client_receipt_file")
    destination_bytes, stable_destination = _read_recovery_file(
        destination,
        max_bytes=max_bytes,
    )
    same_member = (
        temporary_stat.st_dev == stable_destination.st_dev
        and temporary_stat.st_ino == stable_destination.st_ino
    )
    if same_member:
        if temporary_stat.st_nlink != 2 or stable_destination.st_nlink != 2:
            fail("invalid_linked_client_temporary")
    elif temporary_stat.st_nlink != 1 or stable_destination.st_nlink != 1:
        fail("invalid_client_temporary_identity")
    if temporary_bytes != destination_bytes:
        fail("divergent_client_temporary")
    _unlink_recovered_temporary(path, temporary_stat)


def recover_temporaries(directory: Path, allowed_destinations: frozenset[str]) -> None:
    if not allowed_destinations or not allowed_destinations <= _RECEIPT_MEMBER_NAMES:
        fail("invalid_client_temporary_recovery_scope")
    temporaries: list[tuple[Path, str]] = []
    for entry in _entries(directory):
        if not entry.name.startswith(".aoi-cv1-"):
            continue
        matched = _TEMPORARY.fullmatch(entry.name)
        if matched is None or matched.group(1) not in allowed_destinations:
            fail("invalid_client_temporary_member")
        temporaries.append((entry, matched.group(1)))
    if len(temporaries) > _MAX_TEMPORARIES_PER_DIRECTORY:
        fail("client_temporary_inventory_overbound")
    for temporary, destination_name in sorted(
        temporaries,
        key=lambda item: item[0].name,
    ):
        _recover_temporary(temporary, directory / destination_name)


def _windows_move_no_replace_write_through(source: Path, destination: Path) -> bool:
    import ctypes
    from ctypes import wintypes

    win_dll = getattr(ctypes, "WinDLL", None)
    get_last_error = getattr(ctypes, "get_last_error", None)
    if not callable(win_dll) or not callable(get_last_error):
        fail("windows_publication_api_unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)
    move_file = kernel32.MoveFileExW
    move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file.restype = wintypes.BOOL
    if move_file(
        os.fspath(_native_filesystem_path(source)),
        os.fspath(_native_filesystem_path(destination)),
        0x00000008,
    ):
        return True
    error = get_last_error()
    if error in {80, 183}:
        return False
    raise OSError(error, "MoveFileExW write-through publication failed", str(destination))


def publish_exact(
    path: Path,
    payload: bytes,
    *,
    max_bytes: int = _MAX_RECEIPT_BYTES,
) -> bool:
    if type(payload) is not bytes or len(payload) > max_bytes:
        fail("invalid_client_receipt_payload")
    safe_directory(path.parent, create=True)
    recover_temporaries(path.parent, frozenset({path.name}))
    if _exists(path):
        if read_regular(path, max_bytes=max_bytes) != payload:
            fail("divergent_client_receipt")
        return False
    temporary = path.parent / f".aoi-cv1-{path.name}-{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            _native_filesystem_path(temporary),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if os.name == "nt":
                published = _windows_move_no_replace_write_through(temporary, path)
                if not published:
                    if read_regular(path, max_bytes=max_bytes) != payload:
                        fail("divergent_client_receipt")
                    return False
            else:
                os.link(
                    _native_filesystem_path(temporary),
                    _native_filesystem_path(path),
                    follow_symlinks=False,
                )
                os.unlink(_native_filesystem_path(temporary))
        except FileExistsError:
            if read_regular(path, max_bytes=max_bytes) != payload:
                fail("divergent_client_receipt")
            return False
        if read_regular(path, max_bytes=max_bytes) != payload:
            fail("client_receipt_publication_mismatch")
        if os.name != "nt":
            _sync_parent_directory(path.parent)
        return True
    except LegacyBridgeClientError:
        raise
    except OSError as exc:
        raise LegacyBridgeClientError("client_receipt_publication_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary_stat = _lstat(temporary)
        except FileNotFoundError:
            pass
        else:
            _unlink_recovered_temporary(temporary, temporary_stat)


def _parse_json(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail("duplicate_client_receipt_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: fail("nonfinite_client_receipt_value"),
        )
    except LegacyBridgeClientError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise LegacyBridgeClientError("invalid_client_receipt_json") from exc
    if type(value) is not dict:
        fail("invalid_client_receipt_json")
    return cast(dict[str, Any], value)


def _receipt_contract(call: Any, *args: Any) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], call(*args))
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ReceiptContractError as exc:
        raise LegacyBridgeClientError(exc.code) from exc


def _marker(path: Path, full_id: str, label: str, *, create: bool) -> None:
    sha(full_id, label)
    marker = path / f"{label}.id"
    if _exists(marker):
        if read_regular(marker, max_bytes=64) != full_id.encode("ascii"):
            fail(f"{label}_path_collision")
    elif create:
        publish_exact(marker, full_id.encode("ascii"), max_bytes=64)
    else:
        fail(f"missing_{label}_marker")
    observed = read_regular(marker, max_bytes=64)
    if observed != full_id.encode("ascii"):
        fail(f"{label}_path_collision")


def ensure_scope_root(slot_root: Path, scope_id: str) -> Path:
    full_id = sha(scope_id, "bridge_scope_id")
    root = slot_root.joinpath(*_RECEIPT_ROOT, full_id[:_PATH_ID_LENGTH])
    safe_directory(root, create=True)
    _marker(root, full_id, "scope", create=True)
    return root


def attempt_root(scope_root: Path, attempt_id: str, *, create: bool) -> Path:
    full_id = sha(attempt_id, "attempt_id")
    root = scope_root / full_id[:_PATH_ID_LENGTH]
    safe_directory(root, create=create)
    _marker(root, full_id, "attempt", create=create)
    return root


def _load_attempt(path: Path, *, expected_scope_id: str, expected_attempt_id: str) -> ReceiptAttempt | None:
    allowed = {
        "attempt.id", "source.json", "prepared.json", "terminal.json",
        "reconciled.json",
    }
    recover_temporaries(path, frozenset(allowed))
    entries = _entries(path)
    if len(entries) > len(allowed) or any(entry.name not in allowed for entry in entries):
        fail("unexpected_client_receipt_member")
    _marker(path, expected_attempt_id, "attempt", create=False)
    source_path = path / "source.json"
    prepared_path = path / "prepared.json"
    if not _exists(prepared_path):
        if any(entry.name in {"terminal.json", "reconciled.json"} for entry in entries):
            fail("incomplete_client_receipt_attempt")
        if _exists(source_path):
            read_regular(source_path, max_bytes=MAX_SOURCE_DOCUMENT_BYTES)
        return None
    if not _exists(source_path):
        fail("prepared_source_missing")
    source = read_regular(source_path, max_bytes=MAX_SOURCE_DOCUMENT_BYTES)
    prepared = _receipt_contract(
        _validate_prepared_contract,
        _parse_json(read_regular(prepared_path)),
        source,
    )
    if prepared["bridge_scope_id"] != expected_scope_id:
        fail("scope_path_collision")
    if prepared["attempt_id"] != expected_attempt_id:
        fail("attempt_path_collision")
    try:
        projection = normalize_legacy_bridge_snapshot(source)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise LegacyBridgeClientError("invalid_client_receipt_source") from exc
    if prepared["legacy_state_sha256"] != projection.legacy_state_sha256:
        fail("prepared_projection_mismatch")
    terminal_path = path / "terminal.json"
    terminal = (
        None
        if not _exists(terminal_path)
        else _receipt_contract(
            _validate_terminal_contract,
            _parse_json(read_regular(terminal_path)),
            prepared,
            source,
        )
    )
    reconciliation_path = path / "reconciled.json"
    if _exists(reconciliation_path) and terminal is None:
        fail("reconciliation_without_terminal")
    reconciliation = (
        None
        if not _exists(reconciliation_path)
        else _receipt_contract(
            _validate_reconciliation_contract,
            _parse_json(read_regular(reconciliation_path)),
            prepared,
            cast(dict[str, Any], terminal),
            source,
        )
    )
    return ReceiptAttempt(source, projection, prepared, terminal, reconciliation)


def _capacity_attempt(
    path: Path,
    attempt_id: str,
    attempt: ReceiptAttempt | None,
    expected_scope_id: str,
) -> CapacityAttemptV1:
    source_path = path / "source.json"
    source_sha256 = None
    if _exists(source_path):
        source = (
            attempt.source
            if attempt is not None
            else read_regular(source_path, max_bytes=MAX_SOURCE_DOCUMENT_BYTES)
        )
        source_sha256 = hashlib.sha256(source).hexdigest()
        if attempt is None:
            try:
                source_sha256 = capacity_source_sha256(
                    source,
                    expected_scope_id=expected_scope_id,
                    expected_attempt_id=attempt_id,
                )
            except CapacityContractError as exc:
                raise LegacyBridgeClientError(exc.code) from exc
    prepared_sha256 = None if attempt is None else cast(
        str,
        attempt.prepared["receipt_sha256"],
    )
    terminal_sha256 = (
        None
        if attempt is None or attempt.terminal is None
        else cast(str, attempt.terminal["receipt_sha256"])
    )
    reconciliation_sha256 = (
        None
        if attempt is None or attempt.reconciliation is None
        else cast(str, attempt.reconciliation["receipt_sha256"])
    )
    if attempt is None:
        state = "source_only" if source_sha256 is not None else "marker_only"
    elif attempt.reconciliation is not None:
        state = "reconciled_committed"
    elif attempt.terminal is None:
        state = "prepared_effect_unknown"
    else:
        state = {
            "none": "terminal_none",
            "committed": "terminal_committed",
            "effect_unknown": "terminal_effect_unknown",
        }[cast(str, attempt.terminal["effect"])]
    return CapacityAttemptV1(
        attempt_id=attempt_id,
        attempt_marker_sha256=hashlib.sha256(attempt_id.encode("ascii")).hexdigest(),
        source_sha256=source_sha256,
        prepared_receipt_sha256=prepared_sha256,
        terminal_receipt_sha256=terminal_sha256,
        reconciliation_receipt_sha256=reconciliation_sha256,
        effective_state=state,
    )


def inventory(scope_root: Path, expected_scope_id: str) -> ReceiptInventory:
    full_scope = sha(expected_scope_id, "bridge_scope_id")
    safe_directory(scope_root, create=False)
    _marker(scope_root, full_scope, "scope", create=False)
    recover_temporaries(scope_root, frozenset({"scope.id", "capacity.json"}))
    result: list[ReceiptAttempt] = []
    attempt_ids: list[str] = []
    capacity_attempts: list[CapacityAttemptV1] = []
    entries = _entries(scope_root)
    if len(entries) > _MAX_ATTEMPTS + 3:
        fail("client_attempt_inventory_overbound")
    for entry in sorted(entries, key=lambda member: member.name):
        if entry.name in {"capacity.json", "client.lock", "scope.id"}:
            continue
        if _PATH_ID.fullmatch(entry.name) is None:
            fail("invalid_client_attempt_member")
        safe = safe_directory(entry, create=False)
        marker_path = safe / "attempt.id"
        try:
            full_attempt = read_regular(marker_path, max_bytes=64).decode("ascii", "strict")
        except (UnicodeDecodeError, FileNotFoundError) as exc:
            raise LegacyBridgeClientError("invalid_attempt_marker") from exc
        sha(full_attempt, "attempt_id")
        if full_attempt[:_PATH_ID_LENGTH] != entry.name:
            fail("attempt_path_collision")
        attempt_ids.append(full_attempt)
        attempt = _load_attempt(
            safe,
            expected_scope_id=full_scope,
            expected_attempt_id=full_attempt,
        )
        if attempt is not None:
            result.append(attempt)
        capacity_attempts.append(_capacity_attempt(safe, full_attempt, attempt, full_scope))
    normalized_capacity_attempts = tuple(capacity_attempts)
    capacity_path = scope_root / "capacity.json"
    capacity_receipt = None
    if _exists(capacity_path):
        try:
            capacity_receipt = validate_capacity_receipt(
                _parse_json(read_regular(
                    capacity_path,
                    max_bytes=MAX_CAPACITY_RECEIPT_BYTES,
                )),
                expected_scope_id=full_scope,
                current_attempts=normalized_capacity_attempts,
            )
        except CapacityContractError as exc:
            raise LegacyBridgeClientError(exc.code) from exc
    return ReceiptInventory(
        tuple(result),
        tuple(attempt_ids),
        normalized_capacity_attempts,
        capacity_receipt,
    )


def require_attempt_capacity(
    scope_root: Path,
    value: ReceiptInventory,
    attempt_id: str,
    *,
    sealed_at: str,
) -> dict[str, Any] | None:
    full_id = sha(attempt_id, "attempt_id")
    if full_id in value.attempt_ids:
        return None
    if len(value.attempt_ids) < _MAX_ATTEMPTS:
        if value.capacity_receipt is not None:
            fail("capacity_receipt_before_saturation")
        return None
    if len(value.attempt_ids) != _MAX_ATTEMPTS:
        fail("client_attempt_inventory_overbound")
    if value.capacity_receipt is not None:
        return value.capacity_receipt
    try:
        scope_id = read_regular(scope_root / "scope.id", max_bytes=64).decode(
            "ascii",
            "strict",
        )
        sha(scope_id, "bridge_scope_id")
        receipt = build_capacity_receipt(
            scope_id,
            value.capacity_attempts,
            sealed_at=sealed_at,
        )
        capacity_path = scope_root / "capacity.json"
        try:
            publish_exact(
                capacity_path,
                canonical_company_json_bytes(
                    receipt,
                    max_bytes=MAX_CAPACITY_RECEIPT_BYTES,
                ),
                max_bytes=MAX_CAPACITY_RECEIPT_BYTES,
            )
            return validate_capacity_receipt(
                _parse_json(read_regular(
                    capacity_path,
                    max_bytes=MAX_CAPACITY_RECEIPT_BYTES,
                )),
                expected_scope_id=scope_id,
                current_attempts=value.capacity_attempts,
            )
        except (MemoryError, SystemExit, KeyboardInterrupt):
            raise
        except Exception as exc:
            raise LegacyBridgeCapacityPublicationError(
                "capacity_receipt_publication_failed",
            ) from exc
    except (UnicodeDecodeError, FileNotFoundError) as exc:
        raise LegacyBridgeClientError("invalid_scope_marker") from exc
    except CapacityContractError as exc:
        raise LegacyBridgeClientError(exc.code) from exc
