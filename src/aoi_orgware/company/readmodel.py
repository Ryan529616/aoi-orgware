"""Replaceable SQLite projection for the AOI v0.5 company ledger.

The ledger remains authoritative.  This module accepts only immutable,
chain-verified ``LedgerTransactionRecord`` instances and maintains a query
projection that may be discarded and rebuilt at any time.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import threading
from types import MappingProxyType
from typing import Any, NoReturn
import uuid
from itertools import groupby

from .contracts import (
    ALERT_V1,
    ARTIFACT_EDGE_V1,
    AUTHORITY_GRANT_V1,
    BACKUP_ENVELOPE_V1,
    CANARY_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    CONTROL_INTENT_V1,
    CRYPTO_VERIFICATION_RECEIPT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    NEEDS_USER_REVISION_V1,
    NEEDS_USER_V1,
    OPTIMIZER_PROPOSAL_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    PROVIDER_CODEX_HOME_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    RATE_CARD_V1,
    ROUTE_POLICY_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    TASK_REVISION_V1,
    USAGE_BURN_REVISION_V1,
    USAGE_EVENT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    ZERO_SHA256,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_contract,
    validate_company_transaction_receipt,
    validate_company_transaction_request,
)
from .ledger import (
    LedgerEventRecord,
    LedgerReservationRecord,
    LedgerTransactionRecord,
)
from .invariants import (
    CompanyInvariantError,
    InvariantObject,
    InvariantTransition,
    UncertainDispatch,
    reduce_company_invariants,
)
from .projection_registry import (
    APPEND_ONCE_WRITE_ADMISSION_TYPES as _APPEND_ONCE_WRITE_ADMISSION_TYPES,
    PROJECTION_SPECS as _PROJECTION_SPECS,
    ProjectionSpec as _ProjectionSpec,
)


READMODEL_SCHEMA_VERSION = 2


class ReadModelError(RuntimeError):
    """The replaceable projection cannot safely serve or apply state."""


class ReadModelBusyError(ReadModelError):
    """SQLite could not acquire the projection writer lock in time."""


class ReadModelGapError(ReadModelError):
    """An incoming ledger record is not the next exact prefix member."""


class ReadModelCorruptionError(ReadModelError):
    """Projection bytes, schema, or an incoming record are inconsistent."""


class ReadModelClosedError(ReadModelError):
    """The projection connection has already been closed."""


@dataclass(frozen=True)
class ReadModelHead:
    company_id: str | None
    company_incarnation: int | None
    lock_domain_generation: int | None
    global_sequence: int
    transaction_sha256: str


@dataclass(frozen=True)
class ProjectedObject:
    contract_type: str
    object_key: str
    record_id: str
    global_sequence: int
    event_id: str
    stream: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class DispatchRevisionRecord:
    """One append-only durable DispatchRequest revision reservation."""

    dispatch_revision_id: str
    dispatch_request_id: str
    event_id: str
    global_sequence: int
    transaction_id: str
    command_id: str
    receipt_state: str
    payload_sha256: str


_SCHEMA_OBJECTS = {
    "table:projection_meta": """CREATE TABLE projection_meta (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      schema_version INTEGER NOT NULL,
      company_id TEXT,
      company_incarnation INTEGER,
      lock_domain_generation INTEGER,
      global_sequence INTEGER NOT NULL CHECK(global_sequence >= 0),
      transaction_sha256 TEXT NOT NULL
    ) STRICT""",
    "table:projected_transactions": """CREATE TABLE projected_transactions (
      global_sequence INTEGER PRIMARY KEY CHECK(global_sequence > 0),
      transaction_id TEXT NOT NULL UNIQUE,
      command_id TEXT NOT NULL UNIQUE,
      transaction_sha256 TEXT NOT NULL UNIQUE,
      request_bytes BLOB NOT NULL,
      receipt_bytes BLOB NOT NULL
    ) STRICT""",
    "table:projected_events": """CREATE TABLE projected_events (
      event_id TEXT PRIMARY KEY,
      global_sequence INTEGER NOT NULL REFERENCES projected_transactions(global_sequence),
      stream TEXT NOT NULL,
      stream_sequence INTEGER NOT NULL CHECK(stream_sequence > 0),
      previous_event_sha256 TEXT NOT NULL,
      event_sha256 TEXT NOT NULL UNIQUE,
      event_type TEXT NOT NULL,
      contract_type TEXT NOT NULL,
      object_key TEXT NOT NULL,
      record_id TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      payload_bytes BLOB NOT NULL,
      UNIQUE(stream, stream_sequence)
    ) STRICT""",
    "table:projected_reservations": """CREATE TABLE projected_reservations (
      event_id TEXT PRIMARY KEY,
      global_sequence INTEGER NOT NULL REFERENCES projected_transactions(global_sequence),
      event_bytes BLOB NOT NULL
    ) STRICT""",
    "table:projected_dispatch_revisions": """CREATE TABLE projected_dispatch_revisions (
      event_id TEXT PRIMARY KEY,
      dispatch_revision_id TEXT NOT NULL UNIQUE,
      dispatch_request_id TEXT NOT NULL,
      global_sequence INTEGER NOT NULL REFERENCES projected_transactions(global_sequence),
      transaction_id TEXT NOT NULL,
      command_id TEXT NOT NULL,
      receipt_state TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      payload_bytes BLOB NOT NULL
    ) STRICT""",
    "table:current_objects": """CREATE TABLE current_objects (
      contract_type TEXT NOT NULL,
      object_key TEXT NOT NULL,
      record_id TEXT NOT NULL,
      global_sequence INTEGER NOT NULL,
      event_id TEXT NOT NULL REFERENCES projected_events(event_id),
      stream TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      payload_bytes BLOB NOT NULL,
      PRIMARY KEY(contract_type, object_key)
    ) STRICT""",
    "table:current_uncertain_dispatch_reservations": """CREATE TABLE current_uncertain_dispatch_reservations (
      reservation_id TEXT PRIMARY KEY,
      dispatch_request_id TEXT NOT NULL,
      source_event_id TEXT NOT NULL UNIQUE REFERENCES projected_reservations(event_id),
      source_global_sequence INTEGER NOT NULL CHECK(source_global_sequence > 0),
      source_transaction_id TEXT NOT NULL,
      source_command_id TEXT NOT NULL,
      receipt_state TEXT NOT NULL CHECK(receipt_state IN ('effect_unknown', 'reconcile_required')),
      requested_state TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      payload_bytes BLOB NOT NULL
    ) STRICT""",
    "index:projected_events_object": """CREATE INDEX projected_events_object
      ON projected_events(contract_type, object_key, global_sequence)""",
    "index:projected_events_global": """CREATE INDEX projected_events_global
      ON projected_events(global_sequence, event_id)""",
    "index:projected_reservations_global": """CREATE INDEX projected_reservations_global
      ON projected_reservations(global_sequence, event_id)""",
    "index:projected_dispatch_revisions_global": """CREATE INDEX projected_dispatch_revisions_global
      ON projected_dispatch_revisions(global_sequence, event_id)""",
    "trigger:projected_transactions_no_update": """CREATE TRIGGER projected_transactions_no_update
      BEFORE UPDATE ON projected_transactions
      BEGIN SELECT RAISE(ABORT, 'projected transactions are immutable'); END""",
    "trigger:projected_transactions_no_delete": """CREATE TRIGGER projected_transactions_no_delete
      BEFORE DELETE ON projected_transactions
      BEGIN SELECT RAISE(ABORT, 'projected transactions are immutable'); END""",
    "trigger:projected_events_no_update": """CREATE TRIGGER projected_events_no_update
      BEFORE UPDATE ON projected_events
      BEGIN SELECT RAISE(ABORT, 'projected events are immutable'); END""",
    "trigger:projected_events_no_delete": """CREATE TRIGGER projected_events_no_delete
      BEFORE DELETE ON projected_events
      BEGIN SELECT RAISE(ABORT, 'projected events are immutable'); END""",
    "trigger:projected_reservations_no_update": """CREATE TRIGGER projected_reservations_no_update
      BEFORE UPDATE ON projected_reservations
      BEGIN SELECT RAISE(ABORT, 'projected reservations are immutable'); END""",
    "trigger:projected_reservations_no_delete": """CREATE TRIGGER projected_reservations_no_delete
      BEFORE DELETE ON projected_reservations
      BEGIN SELECT RAISE(ABORT, 'projected reservations are immutable'); END""",
    "trigger:projected_dispatch_revisions_no_update": """CREATE TRIGGER projected_dispatch_revisions_no_update
      BEFORE UPDATE ON projected_dispatch_revisions
      BEGIN SELECT RAISE(ABORT, 'projected dispatch revisions are immutable'); END""",
    "trigger:projected_dispatch_revisions_no_delete": """CREATE TRIGGER projected_dispatch_revisions_no_delete
      BEFORE DELETE ON projected_dispatch_revisions
      BEGIN SELECT RAISE(ABORT, 'projected dispatch revisions are immutable'); END""",
}

_TABLES = frozenset({
    "projection_meta", "projected_transactions", "projected_events",
    "projected_reservations", "projected_dispatch_revisions", "current_objects",
    "current_uncertain_dispatch_reservations",
})


def _normalized_ddl(sql: str) -> str:
    return " ".join(sql.split()).lower()


def _immutable(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({
            key: _immutable(member) for key, member in value.items()
        })
    if isinstance(value, list):
        return tuple(_immutable(member) for member in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(member) for key, member in value.items()}
    if isinstance(value, tuple):
        return [_plain(member) for member in value]
    return value


def _decode_canonical(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadModelCorruptionError(
            f"{label} is not UTF-8 JSON",
        ) from exc
    if (
        not isinstance(value, dict)
        or canonical_company_json_bytes(value) != data
    ):
        raise ReadModelCorruptionError(f"{label} is not canonical JSON")
    return value


def _event_digest(
    event: Mapping[str, Any],
    stream_sequence: int,
    previous_event_sha256: str,
) -> str:
    return company_contract_sha256({
        "event": dict(event),
        "stream_sequence": stream_sequence,
        "previous_event_sha256": previous_event_sha256,
    })


class CompanyReadModel:
    """One replaceable query projection owned by the Supervisor."""

    def __init__(
        self, path: str | Path, *, busy_timeout_ms: int = 5000,
    ) -> None:
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or busy_timeout_ms < 0
        ):
            raise ValueError(
                "busy_timeout_ms must be a non-negative integer",
            )
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._database_guard_fd: int | None = None
        self._database_identity: tuple[str, int, int] | None = None
        self._quarantined = False
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
                "SELECT 1 FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'view', 'trigger') "
                "AND name NOT LIKE 'sqlite_%' LIMIT 1",
            ).fetchone()
            if existing is None:
                for ddl in _SCHEMA_OBJECTS.values():
                    connection.execute(ddl)
                connection.execute(
                    "INSERT INTO projection_meta VALUES "
                    "(1, ?, NULL, NULL, NULL, 0, ?)",
                    (READMODEL_SCHEMA_VERSION, ZERO_SHA256),
                )
            self._verified_projection(connection)
            connection.execute("COMMIT")
            self._data_version = int(
                connection.execute("PRAGMA data_version").fetchone()[0],
            )
            self._schema_version = int(
                connection.execute("PRAGMA schema_version").fetchone()[0],
            )
            self._assert_environment(connection)
            self._connection = connection
            connection = None
        except sqlite3.DatabaseError as exc:
            self._rollback_safely(connection)
            self._raise_database_error(exc)
        except BaseException:
            self._rollback_safely(connection)
            raise
        finally:
            if connection is not None:
                connection.close()
            if self._connection is None:
                self._close_database_guard()

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1000,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            # The read model is replaced as one database file during rebuild;
            # authoritative concurrency is served by the Supervisor API, not
            # direct browser connections, so WAL sidecars are intentionally
            # avoided here.
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(
                f"PRAGMA busy_timeout={self._busy_timeout_ms}",
            )
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    @staticmethod
    def _rollback_safely(
        connection: sqlite3.Connection | None,
    ) -> None:
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
            raise ReadModelBusyError(
                f"SQLite read model unavailable: {detail}",
            ) from exc
        raise ReadModelCorruptionError(
            f"SQLite read model failure: {detail}",
        ) from exc

    @staticmethod
    def _assert_schema(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA table_list").fetchall()
        strict = {row[1]: row[5] for row in rows}
        if any(strict.get(name) != 1 for name in _TABLES):
            raise ReadModelCorruptionError(
                "read model requires STRICT tables",
            )
        actual = {
            f"{row['type']}:{row['name']}": _normalized_ddl(str(row["sql"]))
            for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'view', 'trigger') "
                "AND name NOT LIKE 'sqlite_%'",
            )
        }
        expected = {
            key: _normalized_ddl(sql)
            for key, sql in _SCHEMA_OBJECTS.items()
        }
        if actual != expected:
            raise ReadModelCorruptionError(
                "read model schema fingerprint differs",
            )

    @staticmethod
    def _verified_head(connection: sqlite3.Connection) -> ReadModelHead:
        rows = connection.execute(
            "SELECT * FROM projection_meta",
        ).fetchall()
        if len(rows) != 1 or int(rows[0]["singleton"]) != 1:
            raise ReadModelCorruptionError(
                "projection meta cardinality is invalid",
            )
        row = rows[0]
        if int(row["schema_version"]) != READMODEL_SCHEMA_VERSION:
            raise ReadModelCorruptionError(
                "projection schema version is unsupported",
            )
        sequence = int(row["global_sequence"])
        digest = str(row["transaction_sha256"])
        tail = connection.execute(
            "SELECT global_sequence, transaction_sha256 "
            "FROM projected_transactions "
            "ORDER BY global_sequence DESC LIMIT 1",
        ).fetchone()
        if sequence == 0:
            if (
                digest != ZERO_SHA256
                or tail is not None
                or any(
                    row[name] is not None
                    for name in (
                        "company_id", "company_incarnation",
                        "lock_domain_generation",
                    )
                )
            ):
                raise ReadModelCorruptionError(
                    "empty projection metadata is inconsistent",
                )
            return ReadModelHead(None, None, None, 0, ZERO_SHA256)
        if (
            tail is None
            or int(tail["global_sequence"]) != sequence
            or str(tail["transaction_sha256"]) != digest
            or row["company_id"] is None
            or row["company_incarnation"] is None
            or row["lock_domain_generation"] is None
        ):
            raise ReadModelCorruptionError(
                "projection cursor differs from projected transaction tail",
            )
        return ReadModelHead(
            str(row["company_id"]),
            int(row["company_incarnation"]),
            int(row["lock_domain_generation"]),
            sequence,
            digest,
        )

    def _verified_projection(
        self,
        connection: sqlite3.Connection,
    ) -> ReadModelHead:
        """Fully verify the replaceable projection from canonical rows."""

        self._assert_schema(connection)
        if (
            connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            or connection.execute("PRAGMA foreign_key_check").fetchone()
            is not None
        ):
            raise ReadModelCorruptionError(
                "read model SQLite integrity or foreign-key check failed",
            )
        if connection.execute(
            "SELECT event_id FROM projected_events INTERSECT "
            "SELECT event_id FROM projected_reservations LIMIT 1",
        ).fetchone() is not None:
            raise ReadModelCorruptionError(
                "read model event ID is both projected and reserved",
            )

        head = self._verified_head(connection)
        event_groups = iter(groupby(
            connection.execute(
                "SELECT * FROM projected_events "
                "ORDER BY global_sequence, event_id",
            ),
            key=lambda row: int(row["global_sequence"]),
        ))
        reservation_groups = iter(groupby(
            connection.execute(
                "SELECT * FROM projected_reservations "
                "ORDER BY global_sequence, event_id",
            ),
            key=lambda row: int(row["global_sequence"]),
        ))
        event_group = next(event_groups, None)
        reservation_group = next(reservation_groups, None)
        stream_heads: dict[str, tuple[int, str]] = {}
        global_previous = ZERO_SHA256
        binding: tuple[str, int, int] | None = None
        expected_current: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
        expected_shadows: tuple[UncertainDispatch, ...] = ()
        transaction_count = 0

        for expected_sequence, row in enumerate(
            connection.execute(
                "SELECT * FROM projected_transactions ORDER BY global_sequence",
            ),
            1,
        ):
            transaction_count = expected_sequence
            request_bytes = bytes(row["request_bytes"])
            receipt_bytes = bytes(row["receipt_bytes"])
            raw_request = _decode_canonical(
                request_bytes,
                "projected transaction request",
            )
            raw_receipt = _decode_canonical(
                receipt_bytes,
                "projected transaction receipt",
            )
            try:
                request = validate_company_transaction_request(raw_request)
                receipt = validate_company_transaction_receipt(raw_receipt)
            except CompanyContractError as exc:
                raise ReadModelCorruptionError(
                    "projected transaction contract is invalid",
                ) from exc
            if (
                canonical_company_json_bytes(request) != request_bytes
                or canonical_company_json_bytes(receipt) != receipt_bytes
                or int(row["global_sequence"]) != expected_sequence
                or request["transaction_id"] != row["transaction_id"]
                or receipt["transaction_id"] != row["transaction_id"]
                or request["command_id"] != row["command_id"]
                or receipt["command_id"] != row["command_id"]
                or receipt["request_sha256"] != request["request_sha256"]
                or receipt["transaction_sha256"]
                != row["transaction_sha256"]
                or receipt["global_sequence"] != expected_sequence
                or receipt["previous_transaction_sha256"] != global_previous
            ):
                raise ReadModelCorruptionError(
                    "projected transaction row does not bind canonical bytes",
                )
            row_binding = (
                str(request["company_id"]),
                int(request["company_incarnation"]),
                int(request["lock_domain_generation"]),
            )
            if binding is None:
                binding = row_binding
            if (
                row_binding != binding
                or (
                    receipt["company_id"],
                    receipt["company_incarnation"],
                    receipt["lock_domain_generation"],
                )
                != binding
            ):
                raise ReadModelCorruptionError(
                    "projected transaction company binding differs",
                )
            expected_global = request["expected_transaction_head"]
            if (
                expected_global["global_sequence"] != expected_sequence - 1
                or expected_global["transaction_sha256"] != global_previous
            ):
                raise ReadModelCorruptionError(
                    "projected transaction global prefix is broken",
                )
            for expected_stream in request["expected_heads"]:
                actual_stream = stream_heads.get(
                    str(expected_stream["stream"]),
                    (0, ZERO_SHA256),
                )
                if actual_stream != (
                    int(expected_stream["cursor"]),
                    str(expected_stream["event_sha256"]),
                ):
                    raise ReadModelCorruptionError(
                        "projected transaction stream prefix is broken",
                    )

            event_rows: dict[str, sqlite3.Row] = {}
            if event_group is not None:
                group_sequence, members = event_group
                if group_sequence < expected_sequence:
                    raise ReadModelCorruptionError(
                        "projected event references an invalid prefix member",
                    )
                if group_sequence == expected_sequence:
                    for member in members:
                        if len(event_rows) >= len(request["events"]):
                            raise ReadModelCorruptionError(
                                "projected transaction has excess events",
                            )
                        event_rows[str(member["event_id"])] = member
                    event_group = next(event_groups, None)
            reservation_rows: dict[str, sqlite3.Row] = {}
            if reservation_group is not None:
                group_sequence, members = reservation_group
                if group_sequence < expected_sequence:
                    raise ReadModelCorruptionError(
                        "projected reservation references an invalid prefix member",
                    )
                if group_sequence == expected_sequence:
                    for member in members:
                        if len(reservation_rows) >= len(request["events"]):
                            raise ReadModelCorruptionError(
                                "projected transaction has excess reservations",
                            )
                        reservation_rows[str(member["event_id"])] = member
                    reservation_group = next(reservation_groups, None)

            ledger_events: list[LedgerEventRecord] = []
            ledger_reservations: list[LedgerReservationRecord] = []
            if receipt["state"] == "committed":
                if set(event_rows) != {
                    str(event["event_id"]) for event in request["events"]
                } or reservation_rows:
                    raise ReadModelCorruptionError(
                        "projected committed event membership differs",
                    )
                for requested in request["events"]:
                    projected_event_row = event_rows[
                        str(requested["event_id"])
                    ]
                    ledger_events.append(LedgerEventRecord(
                        event=_immutable(requested),
                        stream_sequence=int(
                            projected_event_row["stream_sequence"],
                        ),
                        previous_event_sha256=str(
                            projected_event_row["previous_event_sha256"],
                        ),
                        event_sha256=str(projected_event_row["event_sha256"]),
                    ))
            else:
                if event_rows or set(reservation_rows) != {
                    str(event["event_id"]) for event in request["events"]
                }:
                    raise ReadModelCorruptionError(
                        "projected reservation membership differs",
                    )
                for requested in request["events"]:
                    projected_reservation_row = reservation_rows[
                        str(requested["event_id"])
                    ]
                    event = _decode_canonical(
                        bytes(projected_reservation_row["event_bytes"]),
                        "projected reservation event",
                    )
                    ledger_reservations.append(
                        LedgerReservationRecord(_immutable(event)),
                    )
            record = LedgerTransactionRecord(
                global_sequence=expected_sequence,
                request=_immutable(request),
                receipt=_immutable(receipt),
                events=tuple(ledger_events),
                reservations=tuple(ledger_reservations),
            )
            normalized_events, normalized_reservations = (
                self._validated_membership(record, request, receipt)
            )
            self._assert_membership_rows(
                expected_sequence,
                event_rows,
                reservation_rows,
                normalized_events,
                normalized_reservations,
            )
            expected_revisions = self._dispatch_revision_rows(
                request, receipt, expected_sequence,
            )
            stored_revisions = {
                str(member["event_id"]): member
                for member in connection.execute(
                    "SELECT * FROM projected_dispatch_revisions "
                    "WHERE global_sequence=?",
                    (expected_sequence,),
                )
            }
            self._assert_dispatch_revision_rows(
                stored_revisions, expected_revisions,
            )
            prior_current = tuple(
                InvariantObject(
                    contract_type=key[0],
                    object_key=key[1],
                    event_id=str(normalized["event"]["event_id"]),
                    global_sequence=sequence,
                    payload_sha256=str(
                        normalized["event"]["payload_sha256"],
                    ),
                    payload=normalized["payload"],
                )
                for key, (sequence, normalized) in expected_current.items()
            )
            try:
                invariant_projection = reduce_company_invariants(
                    prior_current,
                    expected_shadows,
                    InvariantTransition(request, str(receipt["state"])),
                )
            except CompanyInvariantError as exc:
                raise ReadModelCorruptionError(
                    "projected history violates company invariants",
                ) from exc
            for normalized_event in normalized_events:
                event = normalized_event["event"]
                stream_heads[str(event["stream"])] = (
                    int(normalized_event["stream_sequence"]),
                    str(normalized_event["event_sha256"]),
                )
                expected_current[(
                    str(normalized_event["contract_type"]),
                    str(normalized_event["object_key"]),
                )] = (expected_sequence, normalized_event)
            self._assert_invariant_current(
                expected_current, invariant_projection.objects,
            )
            expected_shadows = invariant_projection.unresolved_shadows
            global_previous = str(receipt["transaction_sha256"])

        if event_group is not None or reservation_group is not None:
            raise ReadModelCorruptionError(
                "projected event references a missing transaction",
            )
        derived_head = (
            ReadModelHead(None, None, None, 0, ZERO_SHA256)
            if binding is None
            else ReadModelHead(
                binding[0],
                binding[1],
                binding[2],
                transaction_count,
                global_previous,
            )
        )
        if head != derived_head:
            raise ReadModelCorruptionError(
                "projection metadata differs from verified history",
            )

        current_rows = {
            (str(row["contract_type"]), str(row["object_key"])): row
            for row in connection.execute(
                "SELECT * FROM current_objects "
                "ORDER BY contract_type, object_key",
            )
        }
        if set(current_rows) != set(expected_current):
            raise ReadModelCorruptionError(
                "current object membership differs from projected history",
            )
        for key, (
            global_sequence,
            current_projection,
        ) in expected_current.items():
            row = current_rows[key]
            event = current_projection["event"]
            if (
                str(row["record_id"]) != current_projection["record_id"]
                or int(row["global_sequence"]) != global_sequence
                or str(row["event_id"]) != event["event_id"]
                or str(row["stream"]) != event["stream"]
                or str(row["payload_sha256"]) != event["payload_sha256"]
                or bytes(row["payload_bytes"])
                != current_projection["payload_bytes"]
            ):
                raise ReadModelCorruptionError(
                    "current object differs from projected history",
                )
        if self._stored_uncertain_dispatches(connection) != expected_shadows:
            raise ReadModelCorruptionError(
                "uncertain dispatch reservations differ from projected history",
            )
        return head

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise ReadModelClosedError("company read model is closed")
        if self._quarantined:
            raise ReadModelCorruptionError(
                "company read model is quarantined; rebuild is required",
            )
        return self._connection

    def _database_file_identity(self) -> tuple[str, int, int]:
        try:
            resolved = self.path.resolve(strict=True)
            stat = resolved.stat()
        except OSError as exc:
            raise ReadModelCorruptionError(
                "read model database path is unavailable or replaced",
            ) from exc
        return (str(resolved), int(stat.st_dev), int(stat.st_ino))

    def _open_database_guard(self) -> tuple[int, tuple[str, int, int]]:
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    self.path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
            pathname_identity = self._database_file_identity()
            identity = (
                pathname_identity[0],
                int(opened.st_dev),
                int(opened.st_ino),
            )
            if pathname_identity != identity:
                raise ReadModelCorruptionError(
                    "read model path changed while its writer guard opened",
                )
            return descriptor, identity
        except ReadModelError:
            if descriptor is not None:
                self._close_guard_safely(descriptor)
            raise
        except OSError as exc:
            if descriptor is not None:
                self._close_guard_safely(descriptor)
            raise ReadModelCorruptionError(
                "read model database path cannot be bound to a writer guard",
            ) from exc

    def _assert_database_guard(self) -> None:
        if self._quarantined:
            raise ReadModelCorruptionError(
                "company read model is quarantined; rebuild is required",
            )
        try:
            self._assert_database_guard_unchecked()
        except ReadModelCorruptionError:
            self._quarantined = True
            raise

    def _assert_database_guard_unchecked(self) -> None:
        descriptor = self._database_guard_fd
        identity = self._database_identity
        if descriptor is None or identity is None:
            raise ReadModelCorruptionError(
                "read model database writer guard is unavailable",
            )
        try:
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise ReadModelCorruptionError(
                "read model database writer guard is unavailable",
            ) from exc
        if (int(opened.st_dev), int(opened.st_ino)) != identity[1:]:
            raise ReadModelCorruptionError(
                "read model database writer guard identity changed",
            )
        if self._database_file_identity() != identity:
            raise ReadModelCorruptionError(
                "read model database path identity changed",
            )

    @staticmethod
    def _close_guard_safely(descriptor: int) -> None:
        try:
            os.close(descriptor)
        except OSError:
            pass

    def _close_database_guard(self) -> None:
        descriptor = self._database_guard_fd
        self._database_guard_fd = None
        if descriptor is not None:
            self._close_guard_safely(descriptor)

    def _assert_environment(
        self, connection: sqlite3.Connection,
    ) -> None:
        try:
            self._assert_database_guard()
            if int(
                connection.execute("PRAGMA schema_version").fetchone()[0],
            ) != self._schema_version:
                raise ReadModelCorruptionError(
                    "read model schema changed outside the Supervisor",
                )
            if int(
                connection.execute("PRAGMA data_version").fetchone()[0],
            ) != self._data_version:
                raise ReadModelCorruptionError(
                    "read model content changed outside the Supervisor",
                )
        except ReadModelCorruptionError:
            self._quarantined = True
            raise

    def close(self) -> None:
        with self._lock:
            connection = self._connection
            self._connection = None
            if connection is not None:
                self._rollback_safely(connection)
                connection.close()
            self._close_database_guard()

    def __enter__(self) -> CompanyReadModel:
        self._require_connection()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            self._connection = None
            connection.close()
        descriptor = getattr(self, "_database_guard_fd", None)
        if descriptor is not None:
            self._database_guard_fd = None
            self._close_guard_safely(descriptor)

    def head(self) -> ReadModelHead:
        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN")
                self._assert_environment(connection)
                head = self._verified_head(connection)
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return head
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    @staticmethod
    def _normalized_record(
        record: LedgerTransactionRecord,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            request = validate_company_transaction_request(
                _plain(record.request),
            )
            receipt = validate_company_transaction_receipt(
                _plain(record.receipt),
            )
        except CompanyContractError as exc:
            raise ReadModelCorruptionError(
                "incoming ledger record contract is invalid",
            ) from exc
        if (
            receipt["global_sequence"] != record.global_sequence
            or receipt["request_sha256"] != request["request_sha256"]
            or receipt["transaction_id"] != request["transaction_id"]
            or receipt["command_id"] != request["command_id"]
        ):
            raise ReadModelCorruptionError(
                "incoming ledger record request and receipt differ",
            )
        return request, receipt

    @staticmethod
    def _payload_identity(
        stream: str, payload: Mapping[str, Any],
    ) -> tuple[str, str, str]:
        contract_type = str(payload["contract_type"])
        spec = _PROJECTION_SPECS.get(contract_type)
        if spec is None:
            raise ReadModelCorruptionError(
                f"contract is not projectable as a top-level event: {contract_type}",
            )
        if stream != spec.stream:
            raise ReadModelCorruptionError(
                f"{contract_type} belongs to {spec.stream}, not {stream}",
            )
        return (
            contract_type,
            str(payload[spec.object_key_field]),
            str(payload[spec.record_id_field]),
        )

    def _current_invariant_objects(
        self, connection: sqlite3.Connection,
    ) -> tuple[InvariantObject, ...]:
        """Load the canonical current-object prefix for the pure reducer."""

        result: list[InvariantObject] = []
        for row in connection.execute(
            "SELECT * FROM current_objects ORDER BY contract_type, object_key",
        ):
            payload = _decode_canonical(
                bytes(row["payload_bytes"]), "current invariant payload",
            )
            try:
                canonical = validate_company_contract(payload)
            except CompanyContractError as exc:
                raise ReadModelCorruptionError(
                    "current invariant payload contract is invalid",
                ) from exc
            contract_type, object_key, record_id = self._payload_identity(
                str(row["stream"]), canonical,
            )
            if (
                contract_type != str(row["contract_type"])
                or object_key != str(row["object_key"])
                or record_id != str(row["record_id"])
                or company_contract_sha256(canonical)
                != str(row["payload_sha256"])
            ):
                raise ReadModelCorruptionError(
                    "current invariant object differs from canonical payload",
                )
            result.append(InvariantObject(
                contract_type=contract_type,
                object_key=object_key,
                event_id=str(row["event_id"]),
                global_sequence=int(row["global_sequence"]),
                payload_sha256=str(row["payload_sha256"]),
                payload=canonical,
            ))
        return tuple(result)

    def _stored_uncertain_dispatches(
        self, connection: sqlite3.Connection,
    ) -> tuple[UncertainDispatch, ...]:
        return tuple(
            self._uncertain_dispatch_from_row(row)
            for row in connection.execute(
                "SELECT * FROM current_uncertain_dispatch_reservations "
                "ORDER BY reservation_id, source_event_id",
            )
        )

    @staticmethod
    def _replace_uncertain_dispatches(
        connection: sqlite3.Connection,
        shadows: tuple[UncertainDispatch, ...],
    ) -> None:
        """Replace the derived reservation view in the enclosing transaction."""

        connection.execute("DELETE FROM current_uncertain_dispatch_reservations")
        for shadow in shadows:
            connection.execute(
                "INSERT INTO current_uncertain_dispatch_reservations VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    shadow.reservation_id,
                    shadow.dispatch_request_id,
                    shadow.source_event_id,
                    shadow.source_global_sequence,
                    shadow.source_transaction_id,
                    shadow.source_command_id,
                    shadow.receipt_state,
                    shadow.requested_state,
                    shadow.payload_sha256,
                    canonical_company_json_bytes(_plain(shadow.payload)),
                ),
            )

    @staticmethod
    def _dispatch_revision_rows(
        request: Mapping[str, Any],
        receipt: Mapping[str, Any],
        global_sequence: int,
    ) -> list[dict[str, Any]]:
        """Extract every requested DispatchRequest, even on terminal receipt."""

        result: list[dict[str, Any]] = []
        for event in request["events"]:
            payload = event["payload"]
            if payload.get("contract_type") != DISPATCH_REQUEST_V1:
                continue
            try:
                canonical = validate_company_contract(payload)
            except CompanyContractError as exc:
                raise ReadModelCorruptionError(
                    "DispatchRequest revision payload is invalid",
                ) from exc
            if (
                canonical["command_id"] != request["command_id"]
                or event["payload_sha256"]
                != company_contract_sha256(canonical)
            ):
                raise ReadModelCorruptionError(
                    "DispatchRequest revision does not bind its transaction",
                )
            result.append({
                "event_id": str(event["event_id"]),
                "dispatch_revision_id": str(canonical["dispatch_revision_id"]),
                "dispatch_request_id": str(canonical["dispatch_request_id"]),
                "global_sequence": global_sequence,
                "transaction_id": str(request["transaction_id"]),
                "command_id": str(request["command_id"]),
                "receipt_state": str(receipt["state"]),
                "payload_sha256": str(event["payload_sha256"]),
                "payload_bytes": canonical_company_json_bytes(canonical),
            })
        return result

    @staticmethod
    def _assert_dispatch_revision_rows(
        rows: Mapping[str, sqlite3.Row],
        expected: list[dict[str, Any]],
    ) -> None:
        if set(rows) != {item["event_id"] for item in expected}:
            raise ReadModelCorruptionError(
                "DispatchRequest revision registry membership differs",
            )
        for item in expected:
            row = rows[item["event_id"]]
            for field in (
                "dispatch_revision_id", "dispatch_request_id",
                "global_sequence", "transaction_id", "command_id",
                "receipt_state", "payload_sha256",
            ):
                if str(row[field]) != str(item[field]):
                    raise ReadModelCorruptionError(
                        "DispatchRequest revision registry differs",
                    )
            if bytes(row["payload_bytes"]) != item["payload_bytes"]:
                raise ReadModelCorruptionError(
                    "DispatchRequest revision payload bytes differ",
                )

    @staticmethod
    def _assert_invariant_current(
        expected_current: Mapping[
            tuple[str, str], tuple[int, dict[str, Any]],
        ],
        projection_objects: tuple[InvariantObject, ...],
    ) -> None:
        """Bind reducer-owned logical records to the exact ledger projection."""

        reducer_types = {
            AUTHORITY_GRANT_V1,
            CONTROL_INTENT_V1,
            TAKEOVER_CAPABILITY_V1,
            TAKEOVER_CONSUMPTION_RECEIPT_V1,
            ORGANIZATION_NODE_V1,
            DEPARTMENT_IDENTITY_V1,
            DEPARTMENT_SNAPSHOT_V1,
            CHIEF_TERM_V1,
            CARRIER_BINDING_V1,
            TASK_REVISION_V1,
            WORK_DEFINITION_ENFORCEMENT_V1,
            EXECUTION_NODE_V1,
            DISPATCH_REQUEST_V1,
            WORK_PACKET_V1,
            WORK_DISPATCH_BINDING_V1,
            PROVIDER_CODEX_HOME_V1,
            PROVIDER_LAUNCH_BINDING_V1,
            PROVIDER_WORKER_IO_RECEIPT_V1,
            PROVIDER_WORKER_OPERATION_V1,
            PROVIDER_TURN_RESULT_RECEIPT_V1,
            EXTERNAL_JOB_V1,
            MUTATION_INTENT_V1,
            WORK_RESULT_RECEIPT_V1,
        }
        reducer_types.update(_APPEND_ONCE_WRITE_ADMISSION_TYPES)
        expected = {
            key: value for key, value in expected_current.items()
            if key[0] in reducer_types
        }
        actual = {
            (item.contract_type, item.object_key): item
            for item in projection_objects
            if item.contract_type in reducer_types
        }
        if set(actual) != set(expected):
            raise ReadModelCorruptionError(
                "invariant current membership differs from projected history",
            )
        for key, (sequence, normalized) in expected.items():
            item = actual[key]
            event = normalized["event"]
            if (
                item.global_sequence != sequence
                or item.event_id != event["event_id"]
                or item.payload_sha256 != event["payload_sha256"]
                or canonical_company_json_bytes(_plain(item.payload))
                != normalized["payload_bytes"]
            ):
                raise ReadModelCorruptionError(
                    "invariant current differs from projected history",
                )

    def _validated_membership(
        self,
        record: LedgerTransactionRecord,
        request: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        expected_heads = {
            str(head["stream"]): (
                int(head["cursor"]),
                str(head["event_sha256"]),
            )
            for head in request["expected_heads"]
        }
        pending_heads = dict(expected_heads)
        normalized_events: list[dict[str, Any]] = []
        normalized_reservations: list[dict[str, Any]] = []
        requested_events = list(request["events"])
        binding = (
            str(request["company_id"]),
            int(request["company_incarnation"]),
            int(request["lock_domain_generation"]),
        )
        if receipt["state"] == "committed":
            if record.reservations or len(record.events) != len(requested_events):
                raise ReadModelCorruptionError(
                    "incoming committed record event membership differs",
                )
            for requested, ledger_event in zip(
                requested_events,
                record.events,
                strict=True,
            ):
                event = validate_company_contract(
                    _plain(ledger_event.event),
                )
                if event != requested:
                    raise ReadModelCorruptionError(
                        "incoming ledger event differs from transaction request",
                    )
                stream = str(event["stream"])
                if stream not in pending_heads:
                    raise ReadModelCorruptionError(
                        "incoming event stream lacks an expected head",
                    )
                prior_cursor, prior_digest = pending_heads[stream]
                sequence = prior_cursor + 1
                digest = _event_digest(event, sequence, prior_digest)
                if (
                    ledger_event.stream_sequence != sequence
                    or ledger_event.previous_event_sha256 != prior_digest
                    or ledger_event.event_sha256 != digest
                ):
                    raise ReadModelCorruptionError(
                        "incoming ledger event chain metadata differs",
                    )
                payload = validate_company_contract(event["payload"])
                if (
                    payload["company_id"],
                    payload["company_incarnation"],
                    payload["lock_domain_generation"],
                ) != binding:
                    raise ReadModelCorruptionError(
                        "projected payload company binding differs",
                    )
                contract_type, object_key, record_id = (
                    self._payload_identity(stream, payload)
                )
                normalized_events.append({
                    "event": event,
                    "payload": payload,
                    "payload_bytes": canonical_company_json_bytes(payload),
                    "contract_type": contract_type,
                    "object_key": object_key,
                    "record_id": record_id,
                    "stream_sequence": sequence,
                    "previous_event_sha256": prior_digest,
                    "event_sha256": digest,
                })
                pending_heads[stream] = (sequence, digest)
            observed_heads = sorted(
                (stream, cursor, digest)
                for stream, (cursor, digest) in pending_heads.items()
            )
            receipt_heads = sorted(
                (
                    str(head["stream"]),
                    int(head["cursor"]),
                    str(head["event_sha256"]),
                )
                for head in receipt["result_heads"]
            )
            if observed_heads != receipt_heads:
                raise ReadModelCorruptionError(
                    "incoming receipt result heads differ from its events",
                )
        else:
            if record.events or len(record.reservations) != len(requested_events):
                raise ReadModelCorruptionError(
                    "incoming terminal record reservation membership differs",
                )
            if receipt["result_heads"]:
                raise ReadModelCorruptionError(
                    "non-committed receipt must not advance stream heads",
                )
            for requested, reservation in zip(
                requested_events,
                record.reservations,
                strict=True,
            ):
                event = validate_company_contract(
                    _plain(reservation.event),
                )
                if event != requested:
                    raise ReadModelCorruptionError(
                        "incoming reservation differs from transaction request",
                    )
                normalized_reservations.append(event)
        return normalized_events, normalized_reservations

    @staticmethod
    def _actual_stream_head(
        connection: sqlite3.Connection,
        stream: str,
    ) -> tuple[int, str]:
        row = connection.execute(
            "SELECT stream_sequence, event_sha256 FROM projected_events "
            "WHERE stream=? ORDER BY stream_sequence DESC LIMIT 1",
            (stream,),
        ).fetchone()
        if row is None:
            return (0, ZERO_SHA256)
        return (int(row["stream_sequence"]), str(row["event_sha256"]))

    def _assert_expected_stream_heads(
        self,
        connection: sqlite3.Connection,
        request: Mapping[str, Any],
    ) -> None:
        for expected in request["expected_heads"]:
            actual = self._actual_stream_head(
                connection,
                str(expected["stream"]),
            )
            if actual != (
                int(expected["cursor"]),
                str(expected["event_sha256"]),
            ):
                raise ReadModelGapError(
                    "incoming record expected stream head differs from projection",
                )

    @staticmethod
    def _assert_membership_rows(
        global_sequence: int,
        stored_events: Mapping[str, sqlite3.Row],
        stored_reservations: Mapping[str, sqlite3.Row],
        events: list[dict[str, Any]],
        reservations: list[dict[str, Any]],
    ) -> None:
        if set(stored_events) != {
            str(item["event"]["event_id"]) for item in events
        }:
            raise ReadModelCorruptionError(
                "projection replay event membership differs",
            )
        for item in events:
            event = item["event"]
            row = stored_events[str(event["event_id"])]
            if (
                int(row["global_sequence"]) != global_sequence
                or str(row["stream"]) != event["stream"]
                or int(row["stream_sequence"]) != item["stream_sequence"]
                or str(row["previous_event_sha256"])
                != item["previous_event_sha256"]
                or str(row["event_sha256"]) != item["event_sha256"]
                or str(row["event_type"]) != event["event_type"]
                or str(row["contract_type"]) != item["contract_type"]
                or str(row["object_key"]) != item["object_key"]
                or str(row["record_id"]) != item["record_id"]
                or str(row["payload_sha256"]) != event["payload_sha256"]
                or bytes(row["payload_bytes"]) != item["payload_bytes"]
            ):
                raise ReadModelCorruptionError(
                    "projection replay event bytes differ",
                )
        if set(stored_reservations) != {
            str(event["event_id"]) for event in reservations
        }:
            raise ReadModelCorruptionError(
                "projection replay reservation membership differs",
            )
        for event in reservations:
            row = stored_reservations[str(event["event_id"])]
            if (
                int(row["global_sequence"]) != global_sequence
                or bytes(row["event_bytes"])
                != canonical_company_json_bytes(event)
            ):
                raise ReadModelCorruptionError(
                    "projection replay reservation bytes differ",
                )

    @classmethod
    def _assert_replay_membership(
        cls,
        connection: sqlite3.Connection,
        global_sequence: int,
        events: list[dict[str, Any]],
        reservations: list[dict[str, Any]],
        dispatch_revisions: list[dict[str, Any]],
    ) -> None:
        stored_events = {
            str(row["event_id"]): row
            for row in connection.execute(
                "SELECT * FROM projected_events WHERE global_sequence=?",
                (global_sequence,),
            )
        }
        stored_reservations = {
            str(row["event_id"]): row
            for row in connection.execute(
                "SELECT * FROM projected_reservations WHERE global_sequence=?",
                (global_sequence,),
            )
        }
        cls._assert_membership_rows(
            global_sequence,
            stored_events,
            stored_reservations,
            events,
            reservations,
        )
        stored_revisions = {
            str(row["event_id"]): row
            for row in connection.execute(
                "SELECT * FROM projected_dispatch_revisions "
                "WHERE global_sequence=?",
                (global_sequence,),
            )
        }
        cls._assert_dispatch_revision_rows(
            stored_revisions, dispatch_revisions,
        )

    def apply(self, record: LedgerTransactionRecord) -> bool:
        """Apply one exact next ledger record; return False for exact replay."""

        request, receipt = self._normalized_record(record)
        projected_events, projected_reservations = self._validated_membership(
            record,
            request,
            receipt,
        )
        dispatch_revisions = self._dispatch_revision_rows(
            request, receipt, record.global_sequence,
        )
        request_bytes = canonical_company_json_bytes(request)
        receipt_bytes = canonical_company_json_bytes(receipt)
        binding = (
            str(request["company_id"]), int(request["company_incarnation"]),
            int(request["lock_domain_generation"]),
        )
        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._assert_environment(connection)
                self._assert_schema(connection)
                head = self._verified_head(connection)
                if record.global_sequence <= head.global_sequence:
                    prior = connection.execute(
                        "SELECT transaction_id, command_id, transaction_sha256, "
                        "request_bytes, receipt_bytes "
                        "FROM projected_transactions WHERE global_sequence=?",
                        (record.global_sequence,),
                    ).fetchone()
                    if (
                        prior is None
                        or prior["transaction_id"] != request["transaction_id"]
                        or prior["command_id"] != request["command_id"]
                        or prior["transaction_sha256"]
                        != receipt["transaction_sha256"]
                        or bytes(prior["request_bytes"]) != request_bytes
                        or bytes(prior["receipt_bytes"]) != receipt_bytes
                    ):
                        raise ReadModelCorruptionError(
                            "projection replay differs from durable prefix",
                        )
                    self._assert_replay_membership(
                        connection,
                        record.global_sequence,
                        projected_events,
                        projected_reservations,
                        dispatch_revisions,
                    )
                    self._verified_projection(connection)
                    connection.execute("COMMIT")
                    self._assert_environment(connection)
                    return False
                expected = request["expected_transaction_head"]
                if (
                    record.global_sequence != head.global_sequence + 1
                    or expected["global_sequence"] != head.global_sequence
                    or expected["transaction_sha256"]
                    != head.transaction_sha256
                    or receipt["previous_transaction_sha256"]
                    != head.transaction_sha256
                    or (
                        head.company_id is not None
                        and binding
                        != (
                            head.company_id, head.company_incarnation,
                            head.lock_domain_generation,
                        )
                    )
                ):
                    raise ReadModelGapError(
                        "incoming ledger record is not the next exact prefix member",
                    )
                self._assert_expected_stream_heads(connection, request)
                try:
                    invariant_projection = reduce_company_invariants(
                        self._current_invariant_objects(connection),
                        self._stored_uncertain_dispatches(connection),
                        InvariantTransition(request, str(receipt["state"])),
                    )
                except CompanyInvariantError as exc:
                    raise ReadModelCorruptionError(
                        "incoming record violates company invariants",
                    ) from exc
                connection.execute(
                    "INSERT INTO projected_transactions VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        record.global_sequence, request["transaction_id"],
                        request["command_id"], receipt["transaction_sha256"],
                        request_bytes, receipt_bytes,
                    ),
                )
                for revision in dispatch_revisions:
                    connection.execute(
                        "INSERT INTO projected_dispatch_revisions VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            revision["event_id"],
                            revision["dispatch_revision_id"],
                            revision["dispatch_request_id"],
                            revision["global_sequence"],
                            revision["transaction_id"],
                            revision["command_id"],
                            revision["receipt_state"],
                            revision["payload_sha256"],
                            revision["payload_bytes"],
                        ),
                    )
                if receipt["state"] == "committed":
                    for projected in projected_events:
                        wrapper = projected["event"]
                        connection.execute(
                            "INSERT INTO projected_events VALUES "
                            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                wrapper["event_id"], record.global_sequence,
                                wrapper["stream"],
                                projected["stream_sequence"],
                                projected["previous_event_sha256"],
                                projected["event_sha256"],
                                wrapper["event_type"],
                                projected["contract_type"],
                                projected["object_key"],
                                projected["record_id"],
                                wrapper["payload_sha256"],
                                projected["payload_bytes"],
                            ),
                        )
                        connection.execute(
                            "INSERT INTO current_objects VALUES "
                            "(?, ?, ?, ?, ?, ?, ?, ?) "
                            "ON CONFLICT(contract_type, object_key) DO UPDATE SET "
                            "record_id=excluded.record_id, "
                            "global_sequence=excluded.global_sequence, "
                            "event_id=excluded.event_id, stream=excluded.stream, "
                            "payload_sha256=excluded.payload_sha256, "
                            "payload_bytes=excluded.payload_bytes",
                            (
                                projected["contract_type"],
                                projected["object_key"],
                                projected["record_id"],
                                record.global_sequence, wrapper["event_id"],
                                wrapper["stream"], wrapper["payload_sha256"],
                                projected["payload_bytes"],
                            ),
                        )
                else:
                    for event in projected_reservations:
                        connection.execute(
                            "INSERT INTO projected_reservations VALUES (?, ?, ?)",
                            (
                                event["event_id"], record.global_sequence,
                                canonical_company_json_bytes(event),
                            ),
                        )
                self._replace_uncertain_dispatches(
                    connection, invariant_projection.unresolved_shadows,
                )
                connection.execute(
                    "UPDATE projection_meta SET company_id=?, "
                    "company_incarnation=?, lock_domain_generation=?, "
                    "global_sequence=?, transaction_sha256=? WHERE singleton=1",
                    (
                        binding[0], binding[1], binding[2],
                        record.global_sequence, receipt["transaction_sha256"],
                    ),
                )
                # A pathname replacement detected before COMMIT is still
                # rollback-able.  Revalidate again after COMMIT so a detached
                # projection is never published as current to the API.
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return True
            except CompanyContractError as exc:
                self._rollback_safely(connection)
                raise ReadModelCorruptionError(
                    "projected event payload contract is invalid",
                ) from exc
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    def apply_many(
        self, records: Iterable[LedgerTransactionRecord],
    ) -> int:
        applied = 0
        for record in records:
            applied += int(self.apply(record))
        return applied

    def objects(
        self, *, contract_type: str | None = None,
    ) -> tuple[ProjectedObject, ...]:
        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN")
                self._assert_environment(connection)
                sql = (
                    "SELECT contract_type, object_key, record_id, "
                    "global_sequence, event_id, stream, payload_sha256, "
                    "payload_bytes FROM current_objects"
                )
                parameters: tuple[object, ...] = ()
                if contract_type is not None:
                    sql += " WHERE contract_type=?"
                    parameters = (contract_type,)
                sql += " ORDER BY contract_type, object_key"
                result: list[ProjectedObject] = []
                for row in connection.execute(sql, parameters):
                    payload = _decode_canonical(
                        bytes(row["payload_bytes"]), "projected payload",
                    )
                    if (
                        company_contract_sha256(payload)
                        != str(row["payload_sha256"])
                    ):
                        raise ReadModelCorruptionError(
                            "projected payload digest differs",
                        )
                    result.append(ProjectedObject(
                        contract_type=str(row["contract_type"]),
                        object_key=str(row["object_key"]),
                        record_id=str(row["record_id"]),
                        global_sequence=int(row["global_sequence"]),
                        event_id=str(row["event_id"]),
                        stream=str(row["stream"]),
                        payload=_immutable(payload),
                    ))
                objects = tuple(result)
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return objects
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    def object(
        self,
        contract_type: str,
        object_key: str,
    ) -> ProjectedObject | None:
        """Return one exact current object without scanning immutable history."""

        if contract_type not in _PROJECTION_SPECS:
            raise ValueError("contract_type is not projectable")
        if (
            not isinstance(object_key, str)
            or not object_key
            or len(object_key) > 256
        ):
            raise ValueError("object_key must be a bounded non-empty string")
        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN")
                self._assert_environment(connection)
                row = connection.execute(
                    "SELECT contract_type, object_key, record_id, "
                    "global_sequence, event_id, stream, payload_sha256, "
                    "payload_bytes FROM current_objects "
                    "WHERE contract_type=? AND object_key=?",
                    (contract_type, object_key),
                ).fetchone()
                result: ProjectedObject | None = None
                if row is not None:
                    payload = _decode_canonical(
                        bytes(row["payload_bytes"]),
                        "projected payload",
                    )
                    if (
                        company_contract_sha256(payload)
                        != str(row["payload_sha256"])
                    ):
                        raise ReadModelCorruptionError(
                            "projected payload digest differs",
                        )
                    result = ProjectedObject(
                        contract_type=str(row["contract_type"]),
                        object_key=str(row["object_key"]),
                        record_id=str(row["record_id"]),
                        global_sequence=int(row["global_sequence"]),
                        event_id=str(row["event_id"]),
                        stream=str(row["stream"]),
                        payload=_immutable(payload),
                    )
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return result
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    @staticmethod
    def _uncertain_dispatch_from_row(row: sqlite3.Row) -> UncertainDispatch:
        """Decode one derived uncertainty row without trusting its bytes."""

        payload = _decode_canonical(
            bytes(row["payload_bytes"]), "uncertain dispatch payload",
        )
        try:
            canonical = validate_company_contract(payload)
        except CompanyContractError as exc:
            raise ReadModelCorruptionError(
                "uncertain dispatch payload contract is invalid",
            ) from exc
        if (
            canonical["contract_type"] != DISPATCH_REQUEST_V1
            or company_contract_sha256(canonical)
            != str(row["payload_sha256"])
            or canonical["reservation_id"] != str(row["reservation_id"])
            or canonical["dispatch_request_id"]
            != str(row["dispatch_request_id"])
            or canonical["state"] != str(row["requested_state"])
            or canonical["state"] != "effect_unknown"
            or str(row["receipt_state"])
            not in {"effect_unknown", "reconcile_required"}
            or int(row["source_global_sequence"]) <= 0
        ):
            raise ReadModelCorruptionError(
                "uncertain dispatch row differs from canonical payload",
            )
        return UncertainDispatch(
            reservation_id=str(row["reservation_id"]),
            dispatch_request_id=str(row["dispatch_request_id"]),
            source_event_id=str(row["source_event_id"]),
            source_global_sequence=int(row["source_global_sequence"]),
            source_transaction_id=str(row["source_transaction_id"]),
            source_command_id=str(row["source_command_id"]),
            receipt_state=str(row["receipt_state"]),
            requested_state=str(row["requested_state"]),
            payload_sha256=str(row["payload_sha256"]),
            payload=canonical,
        )

    def uncertain_dispatches(self) -> tuple[UncertainDispatch, ...]:
        """Return canonical unresolved dispatch reservations, never a default."""

        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN")
                self._assert_environment(connection)
                rows = connection.execute(
                    "SELECT * FROM current_uncertain_dispatch_reservations "
                    "ORDER BY reservation_id, source_event_id",
                )
                result = tuple(
                    self._uncertain_dispatch_from_row(row) for row in rows
                )
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return result
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    def dispatch_revision(
        self, dispatch_revision_id: str,
    ) -> DispatchRevisionRecord | None:
        """Look up a durable revision binding for pre-append admission checks."""

        if (
            not isinstance(dispatch_revision_id, str)
            or not dispatch_revision_id
            or len(dispatch_revision_id) > 256
        ):
            raise ValueError("dispatch_revision_id must be a bounded non-empty string")
        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN")
                self._assert_environment(connection)
                row = connection.execute(
                    "SELECT revision.*, transaction_row.transaction_id "
                    "AS bound_transaction_id, transaction_row.command_id "
                    "AS bound_command_id, transaction_row.receipt_bytes "
                    "FROM projected_dispatch_revisions AS revision "
                    "JOIN projected_transactions AS transaction_row "
                    "ON transaction_row.global_sequence=revision.global_sequence "
                    "WHERE dispatch_revision_id=?",
                    (dispatch_revision_id,),
                ).fetchone()
                if row is None:
                    result = None
                else:
                    payload = _decode_canonical(
                        bytes(row["payload_bytes"]),
                        "DispatchRequest revision payload",
                    )
                    receipt = _decode_canonical(
                        bytes(row["receipt_bytes"]),
                        "DispatchRequest revision receipt",
                    )
                    try:
                        canonical = validate_company_contract(payload)
                        checked_receipt = validate_company_transaction_receipt(
                            receipt,
                        )
                    except CompanyContractError as exc:
                        raise ReadModelCorruptionError(
                            "DispatchRequest revision binding is invalid",
                        ) from exc
                    if (
                        canonical["contract_type"] != DISPATCH_REQUEST_V1
                        or canonical["dispatch_revision_id"]
                        != dispatch_revision_id
                        or canonical["dispatch_request_id"]
                        != str(row["dispatch_request_id"])
                        or canonical["command_id"] != str(row["command_id"])
                        or company_contract_sha256(canonical)
                        != str(row["payload_sha256"])
                        or str(row["transaction_id"])
                        != str(row["bound_transaction_id"])
                        or str(row["command_id"])
                        != str(row["bound_command_id"])
                        or str(row["receipt_state"])
                        != checked_receipt["state"]
                    ):
                        raise ReadModelCorruptionError(
                            "DispatchRequest revision binding differs",
                        )
                    result = DispatchRevisionRecord(
                        dispatch_revision_id=dispatch_revision_id,
                        dispatch_request_id=str(row["dispatch_request_id"]),
                        event_id=str(row["event_id"]),
                        global_sequence=int(row["global_sequence"]),
                        transaction_id=str(row["transaction_id"]),
                        command_id=str(row["command_id"]),
                        receipt_state=str(row["receipt_state"]),
                        payload_sha256=str(row["payload_sha256"]),
                    )
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return result
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    def verify_integrity(self) -> ReadModelHead:
        """Revalidate the complete replaceable projection in one snapshot."""

        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN")
                self._assert_environment(connection)
                head = self._verified_projection(connection)
                self._assert_database_guard()
                connection.execute("COMMIT")
                self._assert_environment(connection)
                return head
            except sqlite3.DatabaseError as exc:
                self._rollback_safely(connection)
                self._raise_database_error(exc)
            except BaseException:
                self._rollback_safely(connection)
                raise

    @classmethod
    def rebuild(
        cls, path: str | Path, records: Iterable[LedgerTransactionRecord],
    ) -> ReadModelHead:
        """Build a fresh sibling database and atomically replace ``path``."""

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(
            f".{target.name}.aoi-readmodel-v1.{uuid.uuid4().hex}.tmp",
        )
        model: CompanyReadModel | None = None
        try:
            model = cls(temporary)
            model.apply_many(records)
            head = model.head()
            model.close()
            model = None
            os.replace(temporary, target)
            return head
        finally:
            if model is not None:
                model.close()
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
