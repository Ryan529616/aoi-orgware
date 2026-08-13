"""Append-only SQLite persistence for the v0.5 company transaction contract.

This module is deliberately a storage primitive: callers supply an already
formed ``CompanyTransactionRequest`` and receive its immutable receipt.  It
does not create authority, projections, blobs, or a Supervisor.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
from typing import Any, NoReturn
from types import MappingProxyType

from .contracts import (
    COMPANY_TRANSACTION_RECEIPT_V1,
    EXPECTED_HEAD_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    ZERO_SHA256,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_transaction_receipt,
    validate_company_transaction_request,
    validate_takeover_capability,
    validate_takeover_consumption_receipt,
)
from .native_filesystem import native_filesystem_path as _native


class LedgerError(RuntimeError):
    """The local ledger cannot safely accept or read a transaction."""


class LedgerConflictError(LedgerError):
    """A global or logical-stream compare-and-swap head did not match."""


class LedgerOwnershipError(LedgerConflictError):
    """Another writer advanced the durable cursor owned by this instance."""


class LedgerRecoveryRequiredError(LedgerError):
    """The writer must complete an explicit full recovery before appending."""


class LedgerCommitEffectUnknownError(LedgerRecoveryRequiredError):
    """A COMMIT completed, but its authoritative pathname could not be fenced.

    The immutable receipt describes the transaction written through the bound
    SQLite connection.  Callers must not treat it as an acknowledgement that
    the company pathname contains that transaction; the company requires
    reconciliation before another mutation.
    """

    def __init__(self, receipt: Mapping[str, Any]) -> None:
        super().__init__(
            "ledger COMMIT completed but authoritative path fencing failed; "
            "mutation effect is unknown and reconciliation is required",
        )
        self.receipt = _immutable(dict(receipt))


class LedgerBusyError(LedgerError):
    """SQLite could not acquire the configured writer lock in time."""


class LedgerCorruptionError(LedgerError):
    """Persisted bytes or a reused identifier are inconsistent."""


class LedgerCrashInjected(LedgerError):
    """Test-only interruption at a named durable transaction boundary."""


class LedgerSnapshotError(LedgerError):
    """A requested plain ledger checkpoint could not be safely published."""


@dataclass(frozen=True)
class LedgerAppendResult:
    receipt: dict[str, Any]
    idempotent_replay: bool
    record: LedgerTransactionRecord


@dataclass(frozen=True)
class LedgerEventRecord:
    """One verified committed event, including its ledger-owned stream link."""

    event: Mapping[str, Any]
    stream_sequence: int
    previous_event_sha256: str
    event_sha256: str


@dataclass(frozen=True)
class LedgerReservationRecord:
    """One verified non-committed event-ID reservation."""

    event: Mapping[str, Any]


@dataclass(frozen=True)
class LedgerTransactionRecord:
    """One immutable, contract-normalized, chain-verified transaction record."""

    global_sequence: int
    request: Mapping[str, Any]
    receipt: Mapping[str, Any]
    events: tuple[LedgerEventRecord, ...]
    reservations: tuple[LedgerReservationRecord, ...]


@dataclass(frozen=True)
class LedgerHead:
    global_sequence: int
    transaction_sha256: str


@dataclass(frozen=True)
class LedgerHeadsSnapshot:
    """One bounded, immutable view of the sole writer's verified heads."""

    identity: tuple[str, int, int] | None
    global_head: LedgerHead
    stream_heads: Mapping[str, tuple[int, str]]


@dataclass(frozen=True)
class _VerifiedLedgerState:
    """One immutable, fully verified view of a SQLite transaction snapshot."""

    records: tuple[LedgerTransactionRecord, ...]
    identity: tuple[str, int, int] | None
    global_head: LedgerHead
    stream_heads: Mapping[str, tuple[int, str]]
    transactions_by_id: Mapping[str, LedgerTransactionRecord]
    transaction_id_by_command: Mapping[str, str]
    event_ids: frozenset[str]


@dataclass
class _RuntimeLedgerState:
    """Bounded hot-path state owned by one long-lived Supervisor writer."""

    identity: tuple[str, int, int] | None
    global_head: LedgerHead
    stream_heads: dict[str, tuple[int, str]]


@dataclass(frozen=True)
class _SnapshotTargetGuard:
    """One private staging leaf bound to its final pathname and parent chain."""

    path: Path
    final_path: Path
    parent_chain: tuple[tuple[Path, tuple[int, int]], ...]
    descriptor: int
    identity: tuple[int, int]


_SCHEMA_OBJECTS = {
"table:ledger_identity": """CREATE TABLE ledger_identity (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  company_id TEXT NOT NULL,
  company_incarnation INTEGER NOT NULL,
  lock_domain_generation INTEGER NOT NULL
) STRICT""",
"table:transactions": """CREATE TABLE transactions (
  global_sequence INTEGER PRIMARY KEY CHECK(global_sequence > 0),
  transaction_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  request_sha256 TEXT NOT NULL,
  request_bytes BLOB NOT NULL,
  receipt_sha256 TEXT NOT NULL UNIQUE,
  receipt_bytes BLOB NOT NULL,
  state TEXT NOT NULL
) STRICT""",
"table:events": """CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
  stream TEXT NOT NULL,
  stream_sequence INTEGER NOT NULL CHECK(stream_sequence > 0),
  previous_event_sha256 TEXT NOT NULL,
  event_sha256 TEXT NOT NULL UNIQUE,
  event_bytes BLOB NOT NULL,
  UNIQUE(stream, stream_sequence)
) STRICT""",
"table:event_reservations": """CREATE TABLE event_reservations (
  event_id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
  event_bytes BLOB NOT NULL
) STRICT""",
"table:takeover_consumptions": """CREATE TABLE takeover_consumptions (
  capability_id TEXT PRIMARY KEY,
  consumption_id TEXT NOT NULL UNIQUE,
  transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(transaction_id),
  command_id TEXT NOT NULL UNIQUE,
  capability_sha256 TEXT NOT NULL,
  receipt_sha256 TEXT NOT NULL,
  outcome TEXT NOT NULL,
  receipt_state TEXT NOT NULL
) STRICT""",
"index:events_transaction_id": """CREATE INDEX events_transaction_id ON events(transaction_id)""",
"index:event_reservations_transaction_id": """CREATE INDEX event_reservations_transaction_id ON event_reservations(transaction_id)""",
"trigger:ledger_identity_no_update": """CREATE TRIGGER ledger_identity_no_update BEFORE UPDATE ON ledger_identity
BEGIN SELECT RAISE(ABORT, 'ledger identity is immutable'); END""",
"trigger:ledger_identity_no_delete": """CREATE TRIGGER ledger_identity_no_delete BEFORE DELETE ON ledger_identity
BEGIN SELECT RAISE(ABORT, 'ledger identity is immutable'); END""",
"trigger:transactions_no_update": """CREATE TRIGGER transactions_no_update BEFORE UPDATE ON transactions
BEGIN SELECT RAISE(ABORT, 'transactions are append-only'); END""",
"trigger:transactions_no_delete": """CREATE TRIGGER transactions_no_delete BEFORE DELETE ON transactions
BEGIN SELECT RAISE(ABORT, 'transactions are append-only'); END""",
"trigger:events_no_update": """CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END""",
"trigger:events_no_delete": """CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END""",
"trigger:event_reservations_no_update": """CREATE TRIGGER event_reservations_no_update BEFORE UPDATE ON event_reservations
BEGIN SELECT RAISE(ABORT, 'event reservations are append-only'); END""",
"trigger:event_reservations_no_delete": """CREATE TRIGGER event_reservations_no_delete BEFORE DELETE ON event_reservations
BEGIN SELECT RAISE(ABORT, 'event reservations are append-only'); END""",
"trigger:takeover_consumptions_no_update": """CREATE TRIGGER takeover_consumptions_no_update BEFORE UPDATE ON takeover_consumptions
BEGIN SELECT RAISE(ABORT, 'takeover consumptions are append-only'); END""",
"trigger:takeover_consumptions_no_delete": """CREATE TRIGGER takeover_consumptions_no_delete BEFORE DELETE ON takeover_consumptions
BEGIN SELECT RAISE(ABORT, 'takeover consumptions are append-only'); END""",
}

_TABLES = frozenset({
    "ledger_identity", "transactions", "events", "event_reservations",
    "takeover_consumptions",
})
_LEDGER_STREAMS = ("alert", "evidence", "execution", "org", "usage")
_TERMINAL_STATES = frozenset({"committed", "failed_known", "effect_unknown", "reconcile_required", "aborted"})


def _normalized_ddl(sql: str) -> str:
    return " ".join(sql.split()).lower()


def _immutable(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _immutable(member) for key, member in value.items()})
    if isinstance(value, list):
        return tuple(_immutable(member) for member in value)
    return value


def _decode_canonical(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerCorruptionError(f"{label} is not UTF-8 JSON") from exc
    if not isinstance(value, dict) or canonical_company_json_bytes(value) != data:
        raise LedgerCorruptionError(f"{label} is not canonical JSON")
    return value


def _event_digest(event: Mapping[str, Any], stream_sequence: int, previous: str) -> str:
    return company_contract_sha256({
        "event": dict(event), "stream_sequence": stream_sequence,
        "previous_event_sha256": previous,
    })


def _takeover_consumption(
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return the one capability/receipt pair bound to this request.

    A capability is never persisted as a free-standing lifecycle object.  The
    sole durable use is a request containing one top-level issuance and its
    one embedded consumption receipt.  This storage-layer check is repeated
    even when a caller bypasses the higher-level transaction builder.
    """

    capabilities: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    for event in request["events"]:
        payload = event["payload"]
        if not isinstance(payload, Mapping):
            continue
        contract_type = payload.get("contract_type")
        try:
            if contract_type == TAKEOVER_CAPABILITY_V1:
                capabilities.append(validate_takeover_capability(payload))
            elif contract_type == TAKEOVER_CONSUMPTION_RECEIPT_V1:
                receipts.append(validate_takeover_consumption_receipt(payload))
        except CompanyContractError as exc:
            raise LedgerCorruptionError(
                "takeover request contains an invalid capability or receipt",
            ) from exc
    if not capabilities and not receipts:
        return None
    if len(capabilities) != 1 or len(receipts) != 1:
        raise LedgerCorruptionError(
            "takeover request requires exactly one capability and receipt",
        )
    capability, receipt = capabilities[0], receipts[0]
    if (
        receipt["capability"] != capability
        or receipt["capability_sha256"] != capability["capability_sha256"]
        or capability["consumption_id"] != receipt["consumption_id"]
        or capability["consumption_transaction_id"]
        != request["transaction_id"]
        or capability["consumption_command_id"] != request["command_id"]
        or receipt["transaction_id"] != request["transaction_id"]
        or receipt["command_id"] != request["command_id"]
    ):
        raise LedgerCorruptionError(
            "takeover capability and receipt do not bind the outer request",
        )
    return capability, receipt


class CompanyLedger:
    """WAL ledger with one SQLite writer and atomic global/stream heads."""

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5000) -> None:
        if not isinstance(busy_timeout_ms, int) or isinstance(busy_timeout_ms, bool) or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        self.path = Path(path)
        self._native_path = _native(self.path)
        self._busy_timeout_ms = busy_timeout_ms
        self._writer_lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._database_guard_fd: int | None = None
        self._database_identity: tuple[str, int, int] | None = None
        self._health = "opening"
        os.makedirs(_native(self.path.parent), exist_ok=True)
        connection: sqlite3.Connection | None = None
        try:
            (
                self._database_guard_fd,
                self._database_identity,
            ) = self._open_database_guard()
            connection = self._connect()
            self._assert_database_guard()
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'index', 'view', 'trigger') "
                "AND name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
            if existing is None:
                for ddl in _SCHEMA_OBJECTS.values():
                    connection.execute(ddl)
            connection.execute("COMMIT")
            connection.execute("BEGIN")
            verified = self._verified_state(connection)
            connection.execute("COMMIT")
            self._runtime = _RuntimeLedgerState(
                identity=verified.identity,
                global_head=verified.global_head,
                stream_heads=dict(verified.stream_heads),
            )
            self._data_version = int(
                connection.execute("PRAGMA data_version").fetchone()[0],
            )
            self._schema_version = int(
                connection.execute("PRAGMA schema_version").fetchone()[0],
            )
            self._assert_database_guard()
            self._connection = connection
            connection = None
            self._health = "ready"
        except sqlite3.DatabaseError as exc:
            self._rollback_safely(connection)
            self._health = "quarantined"
            self._raise_database_error(exc)
        except BaseException:
            self._rollback_safely(connection)
            self._health = "quarantined"
            raise
        finally:
            if connection is not None:
                self._close_safely(connection)
            if self._health != "ready":
                self._close_database_guard()

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._native_path,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1000,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            self._assert_pragmas(connection)
            return connection
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                self._close_safely(connection)
            self._raise_database_error(exc)
        except BaseException:
            if connection is not None:
                self._close_safely(connection)
            raise

    @property
    def health(self) -> str:
        """Return the local writer lifecycle state."""

        return self._health

    def _database_file_identity(self) -> tuple[str, int, int]:
        try:
            resolved = Path(self._native_path).resolve(strict=True)
            stat = resolved.stat()
        except OSError as exc:
            raise LedgerOwnershipError(
                "ledger database path is unavailable or was replaced",
            ) from exc
        return (str(resolved), int(stat.st_dev), int(stat.st_ino))

    def _open_database_guard(self) -> tuple[int, tuple[str, int, int]]:
        """Bind this writer to the database inode before SQLite opens it.

        The descriptor remains open for the entire writer lifetime.  On POSIX
        that makes pathname replacement observable even though the SQLite
        connection continues to reference the unlinked inode.  On Windows it
        normally prevents replacement while the writer is alive.
        """

        flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    self._native_path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                descriptor = os.open(self._native_path, flags)
            opened = os.fstat(descriptor)
            pathname_identity = self._database_file_identity()
            identity = (
                pathname_identity[0],
                int(opened.st_dev),
                int(opened.st_ino),
            )
            if pathname_identity != identity:
                raise LedgerOwnershipError(
                    "ledger database path changed while its writer guard opened",
                )
            return descriptor, identity
        except LedgerError:
            if descriptor is not None:
                self._close_guard_safely(descriptor)
            raise
        except OSError as exc:
            if descriptor is not None:
                self._close_guard_safely(descriptor)
            raise LedgerOwnershipError(
                "ledger database path cannot be bound to a writer guard",
            ) from exc

    def _assert_database_guard(self) -> None:
        descriptor = self._database_guard_fd
        identity = self._database_identity
        if descriptor is None or identity is None:
            raise LedgerOwnershipError("ledger database writer guard is unavailable")
        try:
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise LedgerOwnershipError(
                "ledger database writer guard is unavailable",
            ) from exc
        if (int(opened.st_dev), int(opened.st_ino)) != identity[1:]:
            raise LedgerOwnershipError(
                "ledger database writer guard identity changed",
            )
        if self._database_file_identity() != identity:
            raise LedgerOwnershipError(
                "ledger database path identity changed outside this writer",
            )

    @staticmethod
    def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
        """Fail closed if native Windows cannot classify a reparse point."""

        if os.name != "nt":
            return False
        attributes = getattr(metadata, "st_file_attributes", None)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
        if not isinstance(attributes, int) or not isinstance(reparse, int):
            raise LedgerSnapshotError(
                "Windows reparse-point inspection is unavailable",
            )
        return bool(attributes & reparse)

    @classmethod
    def _snapshot_directory_chain(
        cls,
        parent: Path,
    ) -> tuple[tuple[Path, tuple[int, int]], ...]:
        """Bind every extant directory component without resolving links."""

        if not parent.is_absolute() or any(
            part in {".", ".."} for part in parent.parts
        ):
            raise LedgerSnapshotError(
                "snapshot destination must be an absolute traversal-free path",
            )
        anchor = Path(parent.anchor)
        if not anchor.anchor:
            raise LedgerSnapshotError("snapshot destination has no filesystem anchor")
        try:
            parts = parent.relative_to(anchor).parts
        except ValueError as exc:  # pragma: no cover - Path contract guard
            raise LedgerSnapshotError("snapshot destination has an invalid anchor") from exc
        chain: list[tuple[Path, tuple[int, int]]] = []
        current = anchor
        for part in ("", *parts):
            if part:
                current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise LedgerSnapshotError(
                    f"snapshot destination parent is unavailable: {current}",
                ) from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or cls._is_windows_reparse_point(metadata)
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise LedgerSnapshotError(
                    "snapshot destination parent may not traverse a link or "
                    f"non-directory: {current}",
                )
            chain.append((current, (int(metadata.st_dev), int(metadata.st_ino))))
        return tuple(chain)

    @staticmethod
    def _assert_snapshot_parent_chain(guard: _SnapshotTargetGuard) -> None:
        """Ensure every destination parent component still has its identity."""

        for directory, expected_identity in guard.parent_chain:
            try:
                metadata = directory.lstat()
            except OSError as exc:
                raise LedgerSnapshotError(
                    f"snapshot destination parent changed: {directory}",
                ) from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or CompanyLedger._is_windows_reparse_point(metadata)
                or not stat.S_ISDIR(metadata.st_mode)
                or (int(metadata.st_dev), int(metadata.st_ino))
                != expected_identity
            ):
                raise LedgerSnapshotError(
                    f"snapshot destination parent changed: {directory}",
                )

    @classmethod
    def _assert_snapshot_final_absent(cls, guard: _SnapshotTargetGuard) -> None:
        """Reserve the complete final namespace without creating a public leaf."""

        cls._assert_snapshot_parent_chain(guard)
        for candidate in (
            guard.final_path,
            guard.final_path.with_name(f"{guard.final_path.name}-wal"),
            guard.final_path.with_name(f"{guard.final_path.name}-shm"),
            guard.final_path.with_name(f"{guard.final_path.name}-journal"),
        ):
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LedgerSnapshotError(
                    f"snapshot final namespace cannot be inspected: {candidate}",
                ) from exc
            raise LedgerSnapshotError(
                f"snapshot final namespace already exists: {candidate}",
            )

    @classmethod
    def _assert_snapshot_final_published(cls, guard: _SnapshotTargetGuard) -> None:
        """Verify that no-replace publication named precisely the staging inode."""

        cls._assert_snapshot_parent_chain(guard)
        try:
            pathname = guard.final_path.lstat()
        except OSError as exc:
            raise LedgerSnapshotError("snapshot final pathname changed") from exc
        if (
            stat.S_ISLNK(pathname.st_mode)
            or CompanyLedger._is_windows_reparse_point(pathname)
            or not stat.S_ISREG(pathname.st_mode)
            or (int(pathname.st_dev), int(pathname.st_ino)) != guard.identity
        ):
            raise LedgerSnapshotError("snapshot final pathname changed")

        for suffix in ("-wal", "-shm", "-journal"):
            candidate = guard.final_path.with_name(f"{guard.final_path.name}{suffix}")
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LedgerSnapshotError(
                    f"snapshot final sidecar cannot be inspected: {candidate}",
                ) from exc
            raise LedgerSnapshotError(
                f"snapshot final sidecar appeared during publication: {candidate}",
            )

    @classmethod
    def _assert_snapshot_target_path(cls, guard: _SnapshotTargetGuard) -> None:
        """Ensure the private staging leaf still names its guarded inode."""

        cls._assert_snapshot_parent_chain(guard)
        try:
            pathname = guard.path.lstat()
        except OSError as exc:
            raise LedgerSnapshotError("snapshot staging pathname changed") from exc
        if (
            stat.S_ISLNK(pathname.st_mode)
            or cls._is_windows_reparse_point(pathname)
            or not stat.S_ISREG(pathname.st_mode)
            or int(pathname.st_nlink) != 1
            or (int(pathname.st_dev), int(pathname.st_ino)) != guard.identity
        ):
            raise LedgerSnapshotError("snapshot staging pathname changed")

    @classmethod
    def _assert_snapshot_target_guard(cls, guard: _SnapshotTargetGuard) -> None:
        """Ensure the still-open leaf and every parent name the same objects."""

        try:
            opened = os.fstat(guard.descriptor)
        except OSError as exc:
            raise LedgerSnapshotError("snapshot destination guard is unavailable") from exc
        if (int(opened.st_dev), int(opened.st_ino)) != guard.identity:
            raise LedgerSnapshotError("snapshot destination guard identity changed")
        cls._assert_snapshot_target_path(guard)

    @classmethod
    def _open_snapshot_target(cls, destination: str | Path) -> _SnapshotTargetGuard:
        """Create an unpredictable private same-directory staging file only."""

        candidate = Path(destination)
        if (
            not candidate.is_absolute()
            or not candidate.name
            or any(part in {".", ".."} for part in candidate.parts)
        ):
            raise LedgerSnapshotError(
                "snapshot destination must be an absolute traversal-free file path",
            )
        parent_chain = cls._snapshot_directory_chain(candidate.parent)
        namespace_guard = _SnapshotTargetGuard(
            path=candidate,
            final_path=candidate,
            parent_chain=parent_chain,
            descriptor=-1,
            identity=(-1, -1),
        )
        cls._assert_snapshot_final_absent(namespace_guard)
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(16):
            staging = candidate.with_name(
                f".aoi-{secrets.token_urlsafe(8)}.db",
            )
            descriptor: int | None = None
            guard: _SnapshotTargetGuard | None = None
            try:
                descriptor = os.open(staging, flags, 0o600)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or int(metadata.st_nlink) != 1
                ):
                    raise LedgerSnapshotError(
                        "snapshot staging file is not one regular new file",
                    )
                guard = _SnapshotTargetGuard(
                    path=staging,
                    final_path=candidate,
                    parent_chain=parent_chain,
                    descriptor=descriptor,
                    identity=(int(metadata.st_dev), int(metadata.st_ino)),
                )
                cls._assert_snapshot_target_guard(guard)
                cls._assert_snapshot_final_absent(guard)
                return guard
            except FileExistsError:
                if descriptor is not None:
                    cls._close_guard_safely(descriptor)
                continue
            except BaseException:
                if guard is not None:
                    cls._cleanup_snapshot_target(guard)
                elif descriptor is not None:
                    cls._close_guard_safely(descriptor)
                raise
        raise LedgerSnapshotError("could not allocate unique snapshot staging path")

    @staticmethod
    def _fsync_snapshot_parent(path: Path) -> None:
        """Flush an already-fsynced leaf's parent; Windows remains best-effort."""

        if os.name != "nt":
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return
        # Python's os.open cannot open a Windows directory.  Use the native
        # directory handle form so this checkpoint does not silently lose its
        # parent-directory durability boundary on the primary platform.
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            3,  # OPEN_EXISTING
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            raise OSError(
                ctypes.get_last_error(),  # type: ignore[attr-defined]
                "CreateFileW failed",
                str(path),
            )
        try:
            if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
                error = ctypes.get_last_error()  # type: ignore[attr-defined]
                # Windows documents directory handles for metadata inspection,
                # but NTFS/ReFS reject FlushFileBuffers on them with ACCESS_DENIED.
                # The leaf is fsynced; this is a best-effort parent boundary,
                # never a Windows power-loss durability claim.
                if error != 5:  # ERROR_ACCESS_DENIED
                    raise OSError(error, "FlushFileBuffers failed", str(path))
        finally:
            kernel32.CloseHandle(wintypes.HANDLE(handle))

    @classmethod
    def _cleanup_snapshot_target(cls, guard: _SnapshotTargetGuard) -> None:
        """Remove only the still-guarded private staging leaf and its sidecars."""

        try:
            cls._assert_snapshot_target_guard(guard)
        except LedgerSnapshotError:
            return
        if os.name == "nt":
            # The Python-created descriptor denies DeleteFile sharing on
            # Windows.  Validate while it is still held, then release only
            # this known new leaf and revalidate its pathname before removal.
            cls._close_guard_safely(guard.descriptor)
            try:
                cls._assert_snapshot_target_path(guard)
            except LedgerSnapshotError:
                return
        for candidate in (
            guard.path.with_name(f"{guard.path.name}-wal"),
            guard.path.with_name(f"{guard.path.name}-shm"),
            guard.path.with_name(f"{guard.path.name}-journal"),
            guard.path,
        ):
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                return
            if (
                stat.S_ISLNK(metadata.st_mode)
                or cls._is_windows_reparse_point(metadata)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                return
            if candidate == guard.path:
                try:
                    cls._assert_snapshot_target_path(guard)
                except LedgerSnapshotError:
                    return
            try:
                candidate.unlink()
            except OSError:
                return
        try:
            cls._fsync_snapshot_parent(guard.path.parent)
        except OSError:
            pass

    @classmethod
    def _publish_snapshot_target(cls, guard: _SnapshotTargetGuard) -> None:
        """Atomically publish the verified staging inode without replacement.

        ``os.link`` maps to the native no-replace hard-link primitive on both
        supported platforms.  It either names the exact staging inode at the
        previously absent final path or fails without overwriting a concurrent
        creator.  The private staging name is then unlinked; it is never a
        public checkpoint name.
        """

        cls._assert_snapshot_target_guard(guard)
        cls._assert_snapshot_final_absent(guard)
        try:
            os.link(guard.path, guard.final_path)
        except FileExistsError as exc:
            raise LedgerSnapshotError(
                "snapshot final destination was created concurrently",
            ) from exc
        except OSError as exc:
            raise LedgerSnapshotError(
                f"snapshot no-replace publication failed: {exc}",
            ) from exc
        cls._assert_snapshot_final_published(guard)
        if os.name == "nt":
            # The stdlib descriptor used to guard the staging leaf prevents
            # deleting that private name on Windows.  Publication already
            # bound the final pathname to the verified inode; release only
            # the staging handle before removing that private alias.
            cls._close_guard_safely(guard.descriptor)
        try:
            guard.path.unlink()
        except OSError as exc:
            raise LedgerSnapshotError(
                f"snapshot staging cleanup after publication failed: {exc}",
            ) from exc
        cls._assert_snapshot_final_published(guard)
        try:
            cls._fsync_snapshot_parent(guard.final_path.parent)
        except OSError as exc:
            raise LedgerSnapshotError(
                f"snapshot publication flush failed: {exc}",
            ) from exc

    def _close_database_guard(self) -> None:
        descriptor = self._database_guard_fd
        self._database_guard_fd = None
        if descriptor is not None:
            self._close_guard_safely(descriptor)

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None or self._health == "closed":
            raise LedgerRecoveryRequiredError("company ledger writer is closed")
        return self._connection

    def _require_ready(self) -> sqlite3.Connection:
        connection = self._require_connection()
        if self._health != "ready":
            raise LedgerRecoveryRequiredError(
                f"company ledger writer is {self._health}; explicit recovery is required",
            )
        return connection

    def close(self) -> None:
        """Close the long-lived writer connection idempotently."""

        with self._writer_lock:
            connection = self._connection
            self._connection = None
            self._health = "closed"
            if connection is not None:
                self._rollback_safely(connection)
                self._close_safely(connection)
            self._close_database_guard()

    def __enter__(self) -> CompanyLedger:
        self._require_connection()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            self._connection = None
            self._close_safely(connection)
        descriptor = getattr(self, "_database_guard_fd", None)
        if descriptor is not None:
            self._database_guard_fd = None
            self._close_guard_safely(descriptor)

    def recover(self) -> None:
        """Explicitly scrub all history and republish a verified hot cursor."""

        with self._writer_lock:
            connection = self._require_connection()
            try:
                self._assert_database_guard()
                connection.execute("BEGIN IMMEDIATE")
                verified = self._verified_state(connection)
                connection.execute("COMMIT")
                self._assert_database_guard()
                self._runtime = _RuntimeLedgerState(
                    identity=verified.identity,
                    global_head=verified.global_head,
                    stream_heads=dict(verified.stream_heads),
                )
                self._data_version = int(
                    connection.execute("PRAGMA data_version").fetchone()[0],
                )
                self._schema_version = int(
                    connection.execute("PRAGMA schema_version").fetchone()[0],
                )
                self._assert_hot_environment(connection)
                self._health = "ready"
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._health = "quarantined"
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                self._health = "quarantined"
                raise

    @staticmethod
    def _close_safely(connection: sqlite3.Connection) -> None:
        try:
            connection.close()
        except sqlite3.DatabaseError:
            pass

    @staticmethod
    def _close_guard_safely(descriptor: int) -> None:
        try:
            os.close(descriptor)
        except OSError:
            pass

    @staticmethod
    def _rollback_safely(connection: sqlite3.Connection | None) -> None:
        if connection is None:
            return
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        except sqlite3.DatabaseError:
            pass

    @staticmethod
    def _raise_database_error(exc: sqlite3.DatabaseError) -> NoReturn:
        detail = str(exc)
        if "locked" in detail.lower() or "busy" in detail.lower():
            raise LedgerBusyError(f"SQLite ledger unavailable: {detail}") from exc
        raise LedgerCorruptionError(f"SQLite ledger failure: {detail}") from exc

    def _assert_pragmas(self, connection: sqlite3.Connection) -> None:
        values = {
            "journal_mode": str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
            "synchronous": int(connection.execute("PRAGMA synchronous").fetchone()[0]),
            "foreign_keys": int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
            "trusted_schema": int(connection.execute("PRAGMA trusted_schema").fetchone()[0]),
            "busy_timeout": int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
        }
        if values != {"journal_mode": "wal", "synchronous": 2, "foreign_keys": 1, "trusted_schema": 0, "busy_timeout": self._busy_timeout_ms}:
            raise LedgerCorruptionError("company ledger connection pragmas are not durable/safe")

    @staticmethod
    def _assert_schema(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA table_list").fetchall()
        strict = {row[1]: row[5] for row in rows}
        if any(strict.get(name) != 1 for name in _TABLES):
            raise LedgerCorruptionError("company ledger requires STRICT tables")
        actual = {
            f"{row['type']}:{row['name']}": _normalized_ddl(str(row["sql"]))
            for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'view', 'trigger') "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
        expected = {key: _normalized_ddl(sql) for key, sql in _SCHEMA_OBJECTS.items()}
        if actual != expected:
            raise LedgerCorruptionError("company ledger schema fingerprint differs")

    @staticmethod
    def _assert_or_bind_identity(connection: sqlite3.Connection, request: Mapping[str, Any]) -> None:
        binding = (
            request["company_id"], request["company_incarnation"], request["lock_domain_generation"],
        )
        row = connection.execute(
            "SELECT company_id, company_incarnation, lock_domain_generation FROM ledger_identity WHERE singleton=1"
        ).fetchone()
        if row is None:
            connection.execute("INSERT INTO ledger_identity VALUES (1, ?, ?, ?)", binding)
        elif tuple(row) != binding:
            raise LedgerCorruptionError("request company binding differs from this ledger identity")

    @staticmethod
    def _validated_transaction_row(
        row: sqlite3.Row,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        raw_request = _decode_canonical(
            bytes(row["request_bytes"]), "stored request",
        )
        raw_receipt = _decode_canonical(
            bytes(row["receipt_bytes"]), "stored receipt",
        )
        try:
            request = validate_company_transaction_request(raw_request)
            receipt = validate_company_transaction_receipt(raw_receipt)
        except CompanyContractError as exc:
            raise LedgerCorruptionError(
                "stored contract validation failed",
            ) from exc
        request_binding = (
            request["company_id"], request["company_incarnation"],
            request["lock_domain_generation"],
        )
        receipt_binding = (
            receipt["company_id"], receipt["company_incarnation"],
            receipt["lock_domain_generation"],
        )
        expected_global = request["expected_transaction_head"]
        if (
            request_binding != receipt_binding
            or receipt["request_sha256"] != request["request_sha256"]
            or row["request_sha256"] != request["request_sha256"]
            or receipt["transaction_id"] != row["transaction_id"]
            or receipt["command_id"] != row["command_id"]
            or request["transaction_id"] != row["transaction_id"]
            or request["command_id"] != row["command_id"]
            or row["state"] != receipt["state"]
            or row["receipt_sha256"] != receipt["receipt_sha256"]
            or receipt["global_sequence"] != int(row["global_sequence"])
            or expected_global["global_sequence"] + 1
            != receipt["global_sequence"]
            or expected_global["transaction_sha256"]
            != receipt["previous_transaction_sha256"]
        ):
            raise LedgerCorruptionError(
                "stored transaction row does not bind canonical request, "
                "receipt, and self-declared pre-head",
            )
        return request, receipt

    def _assert_writer_cursor(self, connection: sqlite3.Connection) -> None:
        """Fence a stale writer using bounded reads of append-only heads.

        Full historical verification is deliberately an open/recovery/read
        slow path.  This hot guard is sound only under the documented
        cooperative single-Supervisor writer boundary; it detects any cursor
        movement by another valid writer and fails closed.
        """

        self._assert_schema(connection)
        tail = connection.execute(
            "SELECT * FROM transactions ORDER BY global_sequence DESC LIMIT 1",
        ).fetchone()
        durable_identity_rows = connection.execute(
            "SELECT company_id, company_incarnation, lock_domain_generation "
            "FROM ledger_identity",
        ).fetchall()
        durable_identity: tuple[str, int, int] | None = None
        if tail is None:
            durable_head = LedgerHead(0, ZERO_SHA256)
            if durable_identity_rows:
                raise LedgerCorruptionError(
                    "empty ledger has a durable company identity",
                )
        else:
            if len(durable_identity_rows) != 1:
                raise LedgerCorruptionError(
                    "non-empty ledger lacks exactly one company identity",
                )
            tail_request, tail_receipt = self._validated_transaction_row(tail)
            durable_head = LedgerHead(
                int(tail["global_sequence"]),
                str(tail_receipt["transaction_sha256"]),
            )
            durable_identity = (
                str(durable_identity_rows[0]["company_id"]),
                int(durable_identity_rows[0]["company_incarnation"]),
                int(durable_identity_rows[0]["lock_domain_generation"]),
            )
            if durable_identity != (
                tail_request["company_id"],
                tail_request["company_incarnation"],
                tail_request["lock_domain_generation"],
            ):
                raise LedgerCorruptionError(
                    "ledger identity differs from transaction tail",
                )
        durable_stream_heads: dict[str, tuple[int, str]] = {}
        for stream in _LEDGER_STREAMS:
            row = connection.execute(
                "SELECT stream_sequence, event_sha256 FROM events "
                "WHERE stream=? ORDER BY stream_sequence DESC LIMIT 1",
                (stream,),
            ).fetchone()
            if row is not None:
                durable_stream_heads[stream] = (
                    int(row["stream_sequence"]), str(row["event_sha256"]),
                )
        if durable_head != self._runtime.global_head:
            if (
                durable_head.global_sequence
                > self._runtime.global_head.global_sequence
            ):
                raise LedgerOwnershipError(
                    "durable ledger cursor advanced outside this writer instance",
                )
            raise LedgerCorruptionError(
                "durable transaction tail changed without a forward append",
            )
        if (
            durable_identity != self._runtime.identity
            or durable_stream_heads != self._runtime.stream_heads
        ):
            raise LedgerCorruptionError(
                "durable ledger heads changed without advancing the global cursor",
            )

    def _assert_hot_environment(self, connection: sqlite3.Connection) -> None:
        """Detect another connection, schema change, or path replacement."""

        self._assert_database_guard()
        data_version = int(
            connection.execute("PRAGMA data_version").fetchone()[0],
        )
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0],
        )
        self._assert_writer_cursor(connection)
        if schema_version != self._schema_version:
            raise LedgerCorruptionError(
                "ledger schema version changed outside this writer",
            )
        if data_version != self._data_version:
            raise LedgerCorruptionError(
                "ledger content changed through another SQLite connection",
            )

    def _advance_writer_cursor(
        self, request: Mapping[str, Any], receipt: Mapping[str, Any],
    ) -> None:
        """Publish the just-committed cursor into bounded in-memory state."""

        binding = (
            str(request["company_id"]), int(request["company_incarnation"]),
            int(request["lock_domain_generation"]),
        )
        if self._runtime.identity not in {None, binding}:
            raise LedgerCorruptionError(
                "committed request differs from the writer identity",
            )
        self._runtime.identity = binding
        self._runtime.global_head = LedgerHead(
            int(receipt["global_sequence"]),
            str(receipt["transaction_sha256"]),
        )
        for head in receipt["result_heads"]:
            self._runtime.stream_heads[str(head["stream"])] = (
                int(head["cursor"]), str(head["event_sha256"]),
            )

    def append(
        self, request: Mapping[str, Any], *, state: str = "committed",
        evidence: Sequence[Mapping[str, Any]] = (), recorded_at: str | None = None,
        crash_at: str | None = None,
    ) -> LedgerAppendResult:
        """Atomically append one terminal receipt, or return its exact replay.

        ``crash_at`` is an intentionally narrow test hook: soft variants raise
        in-process while hard variants terminate a subprocess immediately
        before or after COMMIT.  Production callers must leave it ``None``.
        """
        if state not in _TERMINAL_STATES:
            raise ValueError("state must be a terminal mutation state")
        if crash_at not in {
            None, "before_commit", "after_commit",
            "hard_before_commit", "hard_after_commit",
        }:
            raise ValueError("unknown crash injection point")
        try:
            normalized = validate_company_transaction_request(request)
        except CompanyContractError as exc:
            raise LedgerCorruptionError(f"invalid transaction request: {exc}") from exc
        request_bytes = canonical_company_json_bytes(normalized)
        if company_contract_sha256({key: value for key, value in normalized.items() if key != "request_sha256"}) != normalized["request_sha256"]:
            raise LedgerCorruptionError("request hash does not bind canonical request bytes")
        takeover = _takeover_consumption(normalized)
        when = recorded_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

        self._writer_lock.acquire()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._require_ready()
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._assert_hot_environment(connection)
            except (LedgerOwnershipError, LedgerCorruptionError):
                self._health = "quarantined"
                raise
            self._assert_or_bind_identity(connection, normalized)
            replay = self._find_replay(
                connection, normalized, request_bytes, state, evidence, recorded_at,
            )
            if replay is not None:
                try:
                    replay_record = self._record_by_transaction(
                        connection,
                        str(normalized["transaction_id"]),
                    )
                except LedgerCorruptionError:
                    self._health = "quarantined"
                    raise
                connection.execute("COMMIT")
                try:
                    self._assert_hot_environment(connection)
                except (LedgerOwnershipError, LedgerCorruptionError):
                    self._health = "quarantined"
                    raise
                return LedgerAppendResult(replay, True, replay_record)
            self._reject_reused_takeover(
                connection,
                normalized,
                state,
                takeover,
            )
            self._reject_reused_event_ids(connection, normalized)
            sequence = self._runtime.global_head.global_sequence
            previous = self._runtime.global_head.transaction_sha256
            expected_global = normalized["expected_transaction_head"]
            if (expected_global["global_sequence"], expected_global["transaction_sha256"]) != (sequence, previous):
                raise LedgerConflictError("global transaction head compare-and-swap failed")
            heads = {head["stream"]: head for head in normalized["expected_heads"]}
            for stream, expected in heads.items():
                actual = self._runtime.stream_heads.get(stream, (0, ZERO_SHA256))
                if (expected["cursor"], expected["event_sha256"]) != actual:
                    raise LedgerConflictError(f"stream head compare-and-swap failed: {stream}")

            result_heads: list[dict[str, Any]] = []
            pending_events: list[tuple[dict[str, Any], int, str, str, bytes]] = []
            if state == "committed":
                pending_heads = {
                    stream: self._runtime.stream_heads.get(stream, (0, ZERO_SHA256))
                    for stream in heads
                }
                for event in normalized["events"]:
                    cursor, prior = pending_heads[event["stream"]]
                    event_bytes = canonical_company_json_bytes(event)
                    next_cursor = cursor + 1
                    digest = _event_digest(event, next_cursor, prior)
                    pending_events.append((event, next_cursor, prior, digest, event_bytes))
                    pending_heads[event["stream"]] = (next_cursor, digest)
                for stream in heads:
                    cursor, digest = pending_heads[stream]
                    result_heads.append({
                        "contract_type": EXPECTED_HEAD_V1, "schema_version": 1,
                        "company_id": normalized["company_id"], "company_incarnation": normalized["company_incarnation"],
                        "lock_domain_generation": normalized["lock_domain_generation"],
                        "transaction_id": normalized["transaction_id"], "command_id": normalized["command_id"],
                        "stream": stream, "cursor": cursor, "event_sha256": digest,
                    })
            receipt = self._receipt(normalized, state, when, sequence + 1, previous, result_heads, list(evidence))
            receipt_bytes = canonical_company_json_bytes(receipt)
            connection.execute(
                "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sequence + 1, normalized["transaction_id"], normalized["command_id"], normalized["request_sha256"], request_bytes, receipt["receipt_sha256"], receipt_bytes, state),
            )
            if takeover is not None:
                capability, takeover_receipt = takeover
                connection.execute(
                    "INSERT INTO takeover_consumptions VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        capability["capability_id"],
                        capability["consumption_id"],
                        normalized["transaction_id"],
                        normalized["command_id"],
                        capability["capability_sha256"],
                        takeover_receipt["receipt_sha256"],
                        takeover_receipt["outcome"],
                        state,
                    ),
                )
            if state == "committed":
                for event, cursor, prior, digest, event_bytes in pending_events:
                    connection.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", (event["event_id"], normalized["transaction_id"], event["stream"], cursor, prior, digest, event_bytes))
            else:
                for event in normalized["events"]:
                    connection.execute("INSERT INTO event_reservations VALUES (?, ?, ?)", (event["event_id"], normalized["transaction_id"], canonical_company_json_bytes(event)))
            if crash_at == "before_commit":
                raise LedgerCrashInjected("injected crash before COMMIT")
            if crash_at == "hard_before_commit":
                os._exit(91)
            # Close the window between the initial environment check and
            # COMMIT.  A replacement detected here is still safely
            # rollback-able and must never become an acknowledged mutation.
            self._assert_database_guard()
            connection.execute("COMMIT")
            if crash_at == "hard_after_commit":
                os._exit(92)
            try:
                # COMMIT is not an acknowledgement boundary.  Revalidate the
                # guarded pathname before publishing the receipt or advancing
                # the in-memory cursor.  If this fails, the bound inode may
                # contain the transaction while the authoritative pathname
                # does not, so the only honest result is effect_unknown.
                self._assert_database_guard()
                self._advance_writer_cursor(normalized, receipt)
                self._assert_hot_environment(connection)
                committed_record = self._record_by_transaction(
                    connection,
                    str(normalized["transaction_id"]),
                )
            except (LedgerOwnershipError, LedgerCorruptionError) as exc:
                self._health = "quarantined"
                raise LedgerCommitEffectUnknownError(receipt) from exc
            if crash_at == "after_commit":
                self._health = "recovery_required"
                raise LedgerCrashInjected("injected crash after COMMIT")
            return LedgerAppendResult(receipt, False, committed_record)
        except LedgerOwnershipError:
            self._rollback_safely(connection)
            self._health = "quarantined"
            raise
        except LedgerCorruptionError:
            self._rollback_safely(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_safely(connection)
            detail = str(exc).lower()
            if "locked" not in detail and "busy" not in detail:
                self._health = "quarantined"
            self._raise_database_error(exc)
        except BaseException:
            self._rollback_safely(connection)
            raise
        finally:
            self._writer_lock.release()

    @staticmethod
    def _receipt(request: Mapping[str, Any], state: str, recorded_at: str, sequence: int, previous: str, heads: list[dict[str, Any]], evidence: list[Mapping[str, Any]]) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "contract_type": COMPANY_TRANSACTION_RECEIPT_V1, "schema_version": 1,
            "company_id": request["company_id"], "company_incarnation": request["company_incarnation"],
            "lock_domain_generation": request["lock_domain_generation"], "transaction_id": request["transaction_id"],
            "command_id": request["command_id"], "request_sha256": request["request_sha256"], "state": state,
            "recorded_at": recorded_at, "global_sequence": sequence,
            "previous_transaction_sha256": previous, "result_heads": heads, "evidence": evidence,
        }
        receipt["transaction_sha256"] = company_contract_sha256(receipt)
        receipt["receipt_sha256"] = company_contract_sha256(receipt)
        try:
            return validate_company_transaction_receipt(receipt)
        except CompanyContractError as exc:
            raise LedgerCorruptionError(f"generated receipt violates v11 contract: {exc}") from exc

    @staticmethod
    def _record_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> LedgerTransactionRecord:
        """Validate and materialize one transaction without scanning history."""

        request, receipt = CompanyLedger._validated_transaction_row(row)
        transaction_id = str(request["transaction_id"])
        CompanyLedger._assert_takeover_registry_for_request(
            connection,
            request,
            str(receipt["state"]),
        )
        committed_rows = {
            str(member["event_id"]): member
            for member in connection.execute(
                "SELECT * FROM events WHERE transaction_id=?",
                (transaction_id,),
            )
        }
        reservation_rows = {
            str(member["event_id"]): member
            for member in connection.execute(
                "SELECT * FROM event_reservations WHERE transaction_id=?",
                (transaction_id,),
            )
        }
        requested_events = list(request["events"])
        requested_ids = {str(event["event_id"]) for event in requested_events}
        event_records: list[LedgerEventRecord] = []
        reservation_records: list[LedgerReservationRecord] = []

        if receipt["state"] == "committed":
            if reservation_rows or set(committed_rows) != requested_ids:
                raise LedgerCorruptionError(
                    "committed transaction event membership is broken",
                )
            pending_heads = {
                str(head["stream"]): (
                    int(head["cursor"]),
                    str(head["event_sha256"]),
                )
                for head in request["expected_heads"]
            }
            for requested in requested_events:
                event_id = str(requested["event_id"])
                event_row = committed_rows[event_id]
                event = _decode_canonical(
                    bytes(event_row["event_bytes"]),
                    "stored event",
                )
                stream = str(requested["stream"])
                prior_cursor, prior_hash = pending_heads[stream]
                next_cursor = prior_cursor + 1
                digest = _event_digest(event, next_cursor, prior_hash)
                if (
                    event != requested
                    or str(event_row["transaction_id"]) != transaction_id
                    or str(event_row["stream"]) != stream
                    or int(event_row["stream_sequence"]) != next_cursor
                    or str(event_row["previous_event_sha256"]) != prior_hash
                    or str(event_row["event_sha256"]) != digest
                ):
                    raise LedgerCorruptionError(
                        "committed event row does not bind canonical event bytes",
                    )
                event_records.append(
                    LedgerEventRecord(
                        _immutable(event),
                        next_cursor,
                        prior_hash,
                        digest,
                    )
                )
                pending_heads[stream] = (next_cursor, digest)
            receipt_heads = sorted(
                (
                    str(head["stream"]),
                    int(head["cursor"]),
                    str(head["event_sha256"]),
                )
                for head in receipt["result_heads"]
            )
            observed_heads = sorted(
                (stream, cursor, digest)
                for stream, (cursor, digest) in pending_heads.items()
            )
            if receipt_heads != observed_heads:
                raise LedgerCorruptionError(
                    "receipt result heads do not match persisted events",
                )
        else:
            if committed_rows or set(reservation_rows) != requested_ids:
                raise LedgerCorruptionError(
                    "non-committed reservation membership is broken",
                )
            for requested in requested_events:
                reservation = reservation_rows[str(requested["event_id"])]
                event = _decode_canonical(
                    bytes(reservation["event_bytes"]),
                    "stored reservation event",
                )
                if (
                    event != requested
                    or str(reservation["transaction_id"]) != transaction_id
                ):
                    raise LedgerCorruptionError(
                        "reservation row does not bind canonical event bytes",
                    )
                reservation_records.append(
                    LedgerReservationRecord(_immutable(event)),
                )

        return LedgerTransactionRecord(
            int(row["global_sequence"]),
            _immutable(request),
            _immutable(receipt),
            tuple(event_records),
            tuple(reservation_records),
        )

    @staticmethod
    def _record_by_transaction(
        connection: sqlite3.Connection,
        transaction_id: str,
    ) -> LedgerTransactionRecord:
        row = connection.execute(
            "SELECT * FROM transactions WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        if row is None:
            raise LedgerCorruptionError(
                "durable transaction disappeared after lookup",
            )
        return CompanyLedger._record_from_row(connection, row)

    @staticmethod
    def _find_replay(
        connection: sqlite3.Connection, request: Mapping[str, Any],
        request_bytes: bytes,
        state: str, evidence: Sequence[Mapping[str, Any]], recorded_at: str | None,
    ) -> dict[str, Any] | None:
        rows = connection.execute(
            "SELECT * FROM transactions WHERE transaction_id=? OR command_id=?",
            (request["transaction_id"], request["command_id"]),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise LedgerCorruptionError(
                "transaction_id and command_id have divergent prior bindings",
            )
        durable_request, durable_receipt = (
            CompanyLedger._validated_transaction_row(rows[0])
        )
        if (
            durable_request["transaction_id"] != request["transaction_id"]
            or durable_request["command_id"] != request["command_id"]
        ):
            raise LedgerCorruptionError("transaction_id and command_id have divergent prior bindings")
        if (
            canonical_company_json_bytes(durable_request) != request_bytes
            or durable_request["request_sha256"] != request["request_sha256"]
        ):
            raise LedgerCorruptionError("transaction_id or command_id was replayed with divergent bytes")
        # A request is necessary but not sufficient for an idempotent outcome:
        # a retry may not silently assert a different terminal state/evidence.
        # ``recorded_at=None`` deliberately means "reuse the durable receipt".
        if (
            durable_receipt["state"] != state
            or durable_receipt["evidence"] != list(evidence)
            or (
                recorded_at is not None
                and durable_receipt["recorded_at"] != recorded_at
            )
        ):
            raise LedgerCorruptionError("retry outcome differs from durable receipt")
        return durable_receipt

    @staticmethod
    def _reject_reused_event_ids(
        connection: sqlite3.Connection, request: Mapping[str, Any],
    ) -> None:
        event_ids = [str(event["event_id"]) for event in request["events"]]
        placeholders = ",".join("?" for _ in event_ids)
        row = connection.execute(
            f"SELECT event_id FROM events WHERE event_id IN ({placeholders}) "
            f"UNION ALL SELECT event_id FROM event_reservations "
            f"WHERE event_id IN ({placeholders}) LIMIT 1",
            (*event_ids, *event_ids),
        ).fetchone()
        if row is not None:
            raise LedgerCorruptionError(
                f"event_id was already reserved or committed: {row['event_id']}",
            )

    @staticmethod
    def _takeover_registry_expected(
        request: Mapping[str, Any],
        receipt_state: str,
        takeover: tuple[dict[str, Any], dict[str, Any]] | None = None,
    ) -> dict[str, str] | None:
        pair = _takeover_consumption(request) if takeover is None else takeover
        if pair is None:
            return None
        capability, receipt = pair
        return {
            "capability_id": str(capability["capability_id"]),
            "consumption_id": str(capability["consumption_id"]),
            "transaction_id": str(request["transaction_id"]),
            "command_id": str(request["command_id"]),
            "capability_sha256": str(capability["capability_sha256"]),
            "receipt_sha256": str(receipt["receipt_sha256"]),
            "outcome": str(receipt["outcome"]),
            "receipt_state": receipt_state,
        }

    @staticmethod
    def _reject_reused_takeover(
        connection: sqlite3.Connection,
        request: Mapping[str, Any],
        receipt_state: str,
        takeover: tuple[dict[str, Any], dict[str, Any]] | None,
    ) -> None:
        expected = CompanyLedger._takeover_registry_expected(
            request,
            receipt_state,
            takeover,
        )
        if expected is None:
            return
        rows = connection.execute(
            "SELECT * FROM takeover_consumptions "
            "WHERE capability_id=? OR consumption_id=? "
            "OR transaction_id=? OR command_id=?",
            (
                expected["capability_id"],
                expected["consumption_id"],
                expected["transaction_id"],
                expected["command_id"],
            ),
        ).fetchall()
        if rows:
            # Whole-request exact replay was handled before this point.  Any
            # remaining match is therefore a divergent one-shot binding.
            raise LedgerCorruptionError(
                "takeover capability or consumption identity was already used",
            )

    @staticmethod
    def _assert_takeover_registry_for_request(
        connection: sqlite3.Connection,
        request: Mapping[str, Any],
        receipt_state: str,
    ) -> None:
        expected = CompanyLedger._takeover_registry_expected(
            request,
            receipt_state,
        )
        if expected is None:
            row = connection.execute(
                "SELECT capability_id FROM takeover_consumptions "
                "WHERE transaction_id=?",
                (request["transaction_id"],),
            ).fetchone()
            if row is not None:
                raise LedgerCorruptionError(
                    "non-takeover transaction owns a takeover registry row",
                )
            return
        rows = connection.execute(
            "SELECT * FROM takeover_consumptions "
            "WHERE capability_id=? OR consumption_id=? "
            "OR transaction_id=? OR command_id=?",
            (
                expected["capability_id"],
                expected["consumption_id"],
                expected["transaction_id"],
                expected["command_id"],
            ),
        ).fetchall()
        if len(rows) != 1 or any(
            str(rows[0][field]) != value
            for field, value in expected.items()
        ):
            raise LedgerCorruptionError(
                "takeover consumption registry differs from durable request",
            )

    def _verified_records(self, connection: sqlite3.Connection) -> tuple[LedgerTransactionRecord, ...]:
        self._assert_schema(connection)
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise LedgerCorruptionError("SQLite integrity or foreign-key check failed")
        if connection.execute("SELECT event_id FROM events INTERSECT SELECT event_id FROM event_reservations").fetchone() is not None:
            raise LedgerCorruptionError("event_id occurs in committed and reserved tables")
        events_by_transaction: dict[str, dict[str, sqlite3.Row]] = {}
        for event_row in connection.execute(
            "SELECT * FROM events ORDER BY transaction_id, stream, stream_sequence, event_id"
        ):
            events_by_transaction.setdefault(
                str(event_row["transaction_id"]), {},
            )[str(event_row["event_id"])] = event_row
        reservations_by_transaction: dict[str, dict[str, sqlite3.Row]] = {}
        for reservation_row in connection.execute(
            "SELECT * FROM event_reservations ORDER BY transaction_id, event_id"
        ):
            reservations_by_transaction.setdefault(
                str(reservation_row["transaction_id"]), {},
            )[str(reservation_row["event_id"])] = reservation_row
        identity_rows = connection.execute("SELECT * FROM ledger_identity").fetchall()
        if len(identity_rows) > 1:
            raise LedgerCorruptionError("ledger identity cardinality is invalid")
        global_previous = ZERO_SHA256
        heads: dict[str, tuple[int, str]] = {}
        rows = connection.execute("SELECT * FROM transactions ORDER BY global_sequence").fetchall()
        if bool(rows) != bool(identity_rows):
            raise LedgerCorruptionError("ledger identity and transaction history disagree")
        identity = None if not identity_rows else (identity_rows[0]["company_id"], identity_rows[0]["company_incarnation"], identity_rows[0]["lock_domain_generation"])
        records: list[LedgerTransactionRecord] = []
        expected_takeovers: dict[str, dict[str, str]] = {}
        for expected_sequence, row in enumerate(rows, 1):
            raw_request = _decode_canonical(bytes(row["request_bytes"]), "stored request")
            raw_receipt = _decode_canonical(bytes(row["receipt_bytes"]), "stored receipt")
            try:
                request = validate_company_transaction_request(raw_request)
                receipt = validate_company_transaction_receipt(raw_receipt)
            except CompanyContractError as exc:
                raise LedgerCorruptionError("stored contract validation failed") from exc
            expected_takeover = self._takeover_registry_expected(
                request,
                str(receipt["state"]),
            )
            if expected_takeover is not None:
                capability_id = expected_takeover["capability_id"]
                if capability_id in expected_takeovers:
                    raise LedgerCorruptionError(
                        "takeover capability occurs in multiple transactions",
                    )
                expected_takeovers[capability_id] = expected_takeover
            if (identity is None or (request["company_id"], request["company_incarnation"], request["lock_domain_generation"]) != identity or (receipt["company_id"], receipt["company_incarnation"], receipt["lock_domain_generation"]) != identity):
                raise LedgerCorruptionError("stored company binding differs from ledger identity")
            if int(row["global_sequence"]) != expected_sequence or receipt["global_sequence"] != expected_sequence or receipt["previous_transaction_sha256"] != global_previous:
                raise LedgerCorruptionError("global transaction sequence or adjacency is broken")
            if (receipt["request_sha256"] != request["request_sha256"] or row["request_sha256"] != request["request_sha256"] or receipt["transaction_id"] != row["transaction_id"] or receipt["command_id"] != row["command_id"] or request["transaction_id"] != row["transaction_id"] or request["command_id"] != row["command_id"] or row["state"] != receipt["state"] or row["receipt_sha256"] != receipt["receipt_sha256"]):
                raise LedgerCorruptionError("stored transaction row does not bind canonical request and receipt bytes")
            expected_global = request["expected_transaction_head"]
            if (
                expected_global["global_sequence"],
                expected_global["transaction_sha256"],
            ) != (expected_sequence - 1, global_previous):
                raise LedgerCorruptionError(
                    "request expected global head does not match its actual pre-transaction head"
                )
            for expected_head in request["expected_heads"]:
                if (
                    expected_head["cursor"],
                    expected_head["event_sha256"],
                ) != heads.get(expected_head["stream"], (0, ZERO_SHA256)):
                    raise LedgerCorruptionError(
                        "request expected stream head does not match its actual pre-transaction head"
                    )
            transaction_id = str(row["transaction_id"])
            events = events_by_transaction.get(transaction_id, {})
            reserved = reservations_by_transaction.get(transaction_id, {})
            requested_events = {item["event_id"]: item for item in request["events"]}
            event_records: list[LedgerEventRecord] = []
            reservation_records: list[LedgerReservationRecord] = []
            if receipt["state"] == "committed":
                if reserved or set(events) != set(requested_events):
                    raise LedgerCorruptionError("committed transaction event membership is broken")
                observed_heads: dict[str, tuple[int, str]] = {}
                for requested in request["events"]:
                    event_row = events[requested["event_id"]]
                    event = _decode_canonical(bytes(event_row["event_bytes"]), "stored event")
                    if event != requested or event_row["event_id"] != event["event_id"] or event_row["transaction_id"] != event["transaction_id"] or event_row["stream"] != event["stream"]:
                        raise LedgerCorruptionError("committed event row does not bind canonical event bytes")
                    prior_cursor, prior_hash = heads.get(event_row["stream"], (0, ZERO_SHA256))
                    if int(event_row["stream_sequence"]) != prior_cursor + 1 or event_row["previous_event_sha256"] != prior_hash or event_row["event_sha256"] != _event_digest(event, prior_cursor + 1, prior_hash):
                        raise LedgerCorruptionError("stream event sequence or adjacency is broken")
                    heads[event_row["stream"]] = (prior_cursor + 1, event_row["event_sha256"])
                    observed_heads[event_row["stream"]] = (prior_cursor + 1, event_row["event_sha256"])
                    event_records.append(LedgerEventRecord(_immutable(event), prior_cursor + 1, event_row["previous_event_sha256"], event_row["event_sha256"]))
                receipt_heads = sorted((head["stream"], head["cursor"], head["event_sha256"]) for head in receipt["result_heads"])
                if sorted((stream, cursor, digest) for stream, (cursor, digest) in observed_heads.items()) != receipt_heads:
                    raise LedgerCorruptionError("receipt result heads do not match persisted events")
            else:
                if events or set(reserved) != set(requested_events):
                    raise LedgerCorruptionError("non-committed reservation membership is broken")
                for requested in request["events"]:
                    reservation = reserved[requested["event_id"]]
                    event = _decode_canonical(bytes(reservation["event_bytes"]), "stored reservation event")
                    if event != requested or reservation["event_id"] != event["event_id"] or reservation["transaction_id"] != event["transaction_id"]:
                        raise LedgerCorruptionError("reservation row does not bind canonical event bytes")
                    reservation_records.append(LedgerReservationRecord(_immutable(event)))
            records.append(LedgerTransactionRecord(expected_sequence, _immutable(request), _immutable(receipt), tuple(event_records), tuple(reservation_records)))
            global_previous = receipt["transaction_sha256"]
        durable_takeovers = {
            str(row["capability_id"]): row
            for row in connection.execute(
                "SELECT * FROM takeover_consumptions ORDER BY capability_id",
            )
        }
        if set(durable_takeovers) != set(expected_takeovers):
            raise LedgerCorruptionError(
                "takeover consumption registry membership differs",
            )
        for capability_id, expected in expected_takeovers.items():
            row = durable_takeovers[capability_id]
            if any(
                str(row[field]) != value
                for field, value in expected.items()
            ):
                raise LedgerCorruptionError(
                    "takeover consumption registry differs from history",
                )
        return tuple(records)

    def _verified_state(self, connection: sqlite3.Connection) -> _VerifiedLedgerState:
        records = self._verified_records(connection)
        stream_heads: dict[str, tuple[int, str]] = {}
        transactions_by_id: dict[str, LedgerTransactionRecord] = {}
        transaction_id_by_command: dict[str, str] = {}
        event_ids: set[str] = set()
        for record in records:
            transaction_id = str(record.request["transaction_id"])
            command_id = str(record.request["command_id"])
            transactions_by_id[transaction_id] = record
            transaction_id_by_command[command_id] = transaction_id
            for event in record.events:
                stream = str(event.event["stream"])
                stream_heads[stream] = (event.stream_sequence, event.event_sha256)
                event_ids.add(str(event.event["event_id"]))
            for reservation in record.reservations:
                event_ids.add(str(reservation.event["event_id"]))
        global_head = (
            LedgerHead(0, ZERO_SHA256)
            if not records
            else LedgerHead(
                records[-1].global_sequence,
                str(records[-1].receipt["transaction_sha256"]),
            )
        )
        return _VerifiedLedgerState(
            records=records,
            identity=(
                None
                if not records
                else (
                    str(records[0].request["company_id"]),
                    int(records[0].request["company_incarnation"]),
                    int(records[0].request["lock_domain_generation"]),
                )
            ),
            global_head=global_head,
            stream_heads=MappingProxyType(stream_heads),
            transactions_by_id=MappingProxyType(transactions_by_id),
            transaction_id_by_command=MappingProxyType(transaction_id_by_command),
            event_ids=frozenset(event_ids),
        )

    def load_records(self) -> tuple[LedgerTransactionRecord, ...]:
        """Return only a fully verified immutable snapshot in ledger order."""
        with self._writer_lock:
            connection = self._require_connection()
            try:
                self._assert_database_guard()
                connection.execute("BEGIN")
                records = self._verified_state(connection).records
                connection.execute("COMMIT")
                self._assert_database_guard()
                return records
            except (LedgerCorruptionError, LedgerOwnershipError):
                self._rollback_safely(connection)
                self._health = "quarantined"
                raise
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    @staticmethod
    def _lookup_identifier(value: object, label: str) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(f"{label} must be a non-empty identifier")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{label} must be valid UTF-8") from exc
        if len(encoded) > 256:
            raise ValueError(f"{label} must be at most 256 UTF-8 bytes")
        return value

    def _record_by_lookup(
        self,
        *,
        column: str,
        identifier: str,
    ) -> LedgerTransactionRecord | None:
        """Return one bounded, row-verified transaction lookup.

        The column name is selected only by the two public wrappers below.
        This hot path intentionally avoids a full-history scan: constructor
        recovery established the canonical prefix, the runtime cursor fences
        other writers, and ``_record_from_row`` revalidates the exact durable
        request, receipt, event or reservation membership before publication.
        """

        if column not in {"transaction_id", "command_id"}:
            raise AssertionError("unsupported ledger lookup column")
        with self._writer_lock:
            connection = self._require_ready()
            try:
                self._assert_hot_environment(connection)
                connection.execute("BEGIN")
                row = connection.execute(
                    f"SELECT * FROM transactions WHERE {column}=?",
                    (identifier,),
                ).fetchone()
                record = (
                    None
                    if row is None
                    else self._record_from_row(connection, row)
                )
                connection.execute("COMMIT")
                self._assert_hot_environment(connection)
                return record
            except (LedgerCorruptionError, LedgerOwnershipError):
                self._rollback_safely(connection)
                self._health = "quarantined"
                raise
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    def record_by_transaction_id(
        self,
        transaction_id: str,
    ) -> LedgerTransactionRecord | None:
        """Find one durable transaction without rebuilding it at a newer head."""

        identifier = self._lookup_identifier(
            transaction_id,
            "transaction_id",
        )
        return self._record_by_lookup(
            column="transaction_id",
            identifier=identifier,
        )

    def record_by_command_id(
        self,
        command_id: str,
    ) -> LedgerTransactionRecord | None:
        """Find the one transaction durably bound to a control command ID."""

        identifier = self._lookup_identifier(command_id, "command_id")
        return self._record_by_lookup(
            column="command_id",
            identifier=identifier,
        )

    def snapshot_heads(self) -> LedgerHeadsSnapshot:
        """Return bounded verified global and logical-stream heads.

        This is the hot Supervisor API used to build compare-and-swap
        transaction requests.  Full-history verification remains an explicit
        open/recovery/scrub operation.
        """

        with self._writer_lock:
            connection = self._require_ready()
            try:
                self._assert_hot_environment(connection)
                return LedgerHeadsSnapshot(
                    identity=self._runtime.identity,
                    global_head=self._runtime.global_head,
                    stream_heads=MappingProxyType(
                        dict(self._runtime.stream_heads),
                    ),
                )
            except (LedgerCorruptionError, LedgerOwnershipError):
                self._health = "quarantined"
                raise
            except sqlite3.DatabaseError as exc:
                self._raise_database_error(exc)

    def _verify_snapshot_database(
        self,
        guard: _SnapshotTargetGuard,
    ) -> _VerifiedLedgerState:
        """Independently reopen the new database read-only and verify all rows."""

        connection: sqlite3.Connection | None = None
        try:
            self._assert_snapshot_target_guard(guard)
            connection = sqlite3.connect(
                f"{guard.path.as_uri()}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            verified = self._verified_state(connection)
            connection.execute("COMMIT")
            self._assert_snapshot_target_guard(guard)
            return verified
        except LedgerCorruptionError as exc:
            self._rollback_safely(connection)
            raise LedgerSnapshotError(
                "snapshot verification detected invalid ledger history",
            ) from exc
        except sqlite3.DatabaseError as exc:
            self._rollback_safely(connection)
            raise LedgerSnapshotError(
                f"snapshot verification failed: {exc}",
            ) from exc
        finally:
            if connection is not None:
                self._close_safely(connection)

    @staticmethod
    def _snapshot_heads_from_verified(
        verified: _VerifiedLedgerState,
    ) -> LedgerHeadsSnapshot:
        return LedgerHeadsSnapshot(
            identity=verified.identity,
            global_head=verified.global_head,
            stream_heads=MappingProxyType(dict(verified.stream_heads)),
        )

    @staticmethod
    def _assert_snapshot_sidecars_absent(guard: _SnapshotTargetGuard) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            candidate = guard.path.with_name(f"{guard.path.name}{suffix}")
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LedgerSnapshotError(
                    f"snapshot sidecar cannot be inspected: {candidate}",
                ) from exc
            raise LedgerSnapshotError(
                f"snapshot leaves an unpublished SQLite sidecar: {candidate}",
            )

    def snapshot_to(self, destination: str | Path) -> LedgerHeadsSnapshot:
        """Publish one verified plain SQLite checkpoint at a new safe pathname.

        The source connection first fixes a read transaction, so SQLite's
        backup API receives one consistent prefix even if another cooperative
        writer starts only after that point.  The returned heads are exactly
        those independently verified from the new file; a later source append
        is deliberately outside this checkpoint's boundary.
        """

        guard: _SnapshotTargetGuard | None = None
        destination_connection: sqlite3.Connection | None = None
        published = False
        with self._writer_lock:
            connection = self._require_ready()
            try:
                candidate = Path(destination)
                if candidate.is_absolute() and self._database_identity is not None:
                    if os.path.normcase(os.path.abspath(candidate)) == os.path.normcase(
                        self._database_identity[0],
                    ):
                        raise LedgerSnapshotError(
                            "snapshot destination must differ from the source ledger",
                        )
                self._assert_hot_environment(connection)
                guard = self._open_snapshot_target(destination)
                self._assert_database_guard()
                connection.execute("BEGIN")
                source_verified = self._verified_state(connection)
                source_heads = self._snapshot_heads_from_verified(source_verified)
                if source_heads != self.snapshot_heads():
                    raise LedgerCorruptionError(
                        "verified source snapshot differs from writer heads",
                    )
                self._assert_snapshot_target_guard(guard)
                try:
                    destination_connection = sqlite3.connect(
                        guard.path,
                        isolation_level=None,
                        timeout=self._busy_timeout_ms / 1000,
                    )
                    connection.backup(destination_connection)
                    # ``backup`` copies the source's WAL-mode header, which
                    # can leave an empty destination WAL/SHM pair after close.
                    # A plain checkpoint intentionally folds that
                    # destination-local journal state into the new main
                    # database before publication.
                    destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    destination_connection.execute("PRAGMA journal_mode=DELETE")
                    self._close_safely(destination_connection)
                    destination_connection = None
                except sqlite3.DatabaseError as exc:
                    raise LedgerSnapshotError(
                        f"SQLite snapshot backup failed: {exc}",
                    ) from exc
                self._assert_snapshot_target_guard(guard)
                try:
                    os.fsync(guard.descriptor)
                    self._fsync_snapshot_parent(guard.path.parent)
                except OSError as exc:
                    raise LedgerSnapshotError(
                        f"snapshot durability flush failed: {exc}",
                    ) from exc
                copied_verified = self._verify_snapshot_database(guard)
                copied_heads = self._snapshot_heads_from_verified(copied_verified)
                if copied_heads != source_heads:
                    raise LedgerSnapshotError(
                        "snapshot verification heads differ from the source prefix",
                    )
                self._assert_snapshot_sidecars_absent(guard)
                self._assert_snapshot_target_guard(guard)
                self._assert_snapshot_final_absent(guard)
                connection.execute("COMMIT")
                self._assert_database_guard()
                self._publish_snapshot_target(guard)
                published = True
                return copied_heads
            except (LedgerCorruptionError, LedgerOwnershipError):
                self._rollback_safely(connection)
                self._health = "quarantined"
                raise
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise
            finally:
                if destination_connection is not None:
                    self._close_safely(destination_connection)
                if guard is not None:
                    if not published:
                        self._cleanup_snapshot_target(guard)
                    self._close_guard_safely(guard.descriptor)

    def records_after(
        self,
        global_sequence: int,
        *,
        limit: int = 1024,
    ) -> tuple[LedgerTransactionRecord, ...]:
        """Return a bounded, chain-checked ledger slice after ``global_sequence``."""

        if (
            not isinstance(global_sequence, int)
            or isinstance(global_sequence, bool)
            or global_sequence < 0
        ):
            raise ValueError("global_sequence must be a non-negative integer")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > 4096
        ):
            raise ValueError("limit must be an integer between 1 and 4096")

        with self._writer_lock:
            connection = self._require_ready()
            try:
                self._assert_hot_environment(connection)
                durable_tail = self._runtime.global_head.global_sequence
                if global_sequence > durable_tail:
                    raise LedgerConflictError(
                        "requested ledger cursor is ahead of the durable head",
                    )
                if global_sequence == durable_tail:
                    return ()

                connection.execute("BEGIN")
                if global_sequence == 0:
                    previous_transaction_sha256 = ZERO_SHA256
                else:
                    prior_row = connection.execute(
                        "SELECT * FROM transactions WHERE global_sequence=?",
                        (global_sequence,),
                    ).fetchone()
                    if prior_row is None:
                        raise LedgerCorruptionError(
                            "requested ledger prefix transaction is missing",
                        )
                    _prior_request, prior_receipt = (
                        self._validated_transaction_row(prior_row)
                    )
                    previous_transaction_sha256 = str(
                        prior_receipt["transaction_sha256"],
                    )

                stream_heads: dict[str, tuple[int, str]] = {}
                for stream in _LEDGER_STREAMS:
                    stream_row = connection.execute(
                        "SELECT e.stream_sequence, e.event_sha256 "
                        "FROM events AS e "
                        "JOIN transactions AS t "
                        "ON t.transaction_id=e.transaction_id "
                        "WHERE e.stream=? AND t.global_sequence<=? "
                        "ORDER BY e.stream_sequence DESC LIMIT 1",
                        (stream, global_sequence),
                    ).fetchone()
                    if stream_row is not None:
                        stream_heads[stream] = (
                            int(stream_row["stream_sequence"]),
                            str(stream_row["event_sha256"]),
                        )

                rows = connection.execute(
                    "SELECT * FROM transactions WHERE global_sequence>? "
                    "ORDER BY global_sequence LIMIT ?",
                    (global_sequence, limit),
                ).fetchall()
                records: list[LedgerTransactionRecord] = []
                expected_sequence = global_sequence + 1
                for row in rows:
                    record = self._record_from_row(connection, row)
                    expected_global = record.request[
                        "expected_transaction_head"
                    ]
                    if (
                        record.global_sequence != expected_sequence
                        or int(expected_global["global_sequence"])
                        != expected_sequence - 1
                        or str(expected_global["transaction_sha256"])
                        != previous_transaction_sha256
                        or str(
                            record.receipt[
                                "previous_transaction_sha256"
                            ]
                        )
                        != previous_transaction_sha256
                    ):
                        raise LedgerCorruptionError(
                            "bounded ledger slice global adjacency is broken",
                        )
                    for expected_head in record.request["expected_heads"]:
                        stream = str(expected_head["stream"])
                        if (
                            int(expected_head["cursor"]),
                            str(expected_head["event_sha256"]),
                        ) != stream_heads.get(stream, (0, ZERO_SHA256)):
                            raise LedgerCorruptionError(
                                "bounded ledger slice stream adjacency is broken",
                            )
                    for event_record in record.events:
                        stream = str(event_record.event["stream"])
                        stream_heads[stream] = (
                            event_record.stream_sequence,
                            event_record.event_sha256,
                        )
                    records.append(record)
                    previous_transaction_sha256 = str(
                        record.receipt["transaction_sha256"],
                    )
                    expected_sequence += 1

                connection.execute("COMMIT")
                self._assert_hot_environment(connection)
                return tuple(records)
            except (LedgerCorruptionError, LedgerOwnershipError):
                self._rollback_safely(connection)
                self._health = "quarantined"
                raise
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    def current_head(self) -> LedgerHead:
        """Return the bounded verified global head."""

        return self.snapshot_heads().global_head

    def verify_integrity(self) -> None:
        """Revalidate all stored canonical bytes, chains, and bindings."""
        self.load_records()
