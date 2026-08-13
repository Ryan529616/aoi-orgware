"""Read-only company-state values and detached record-chain validation.

Caller-built replay values prove bounded self-consistency only.  The state
owner path first uses ``CompanyLedger.load_records()``, which also verifies
the SQLite schema and auxiliary takeover registry, before detaching records.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, NamedTuple, cast

from .contracts import (
    ZERO_SHA256,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_transaction_receipt,
    validate_company_transaction_request,
)
from .invariants import UncertainDispatch
from .ledger import (
    LedgerCorruptionError,
    LedgerEventRecord,
    LedgerHead,
    LedgerHeadsSnapshot,
    LedgerReservationRecord,
    LedgerTransactionRecord,
    _takeover_consumption,
)
from .readmodel import ProjectedObject, ReadModelHead


class CompanyStateReaderError(RuntimeError):
    """A detached company-state read value is malformed or inconsistent."""


@dataclass(frozen=True)
class CompanyStateHealth:
    status: str
    ledger_status: str
    projection_status: str
    pointer_sha256: str
    ledger_heads: LedgerHeadsSnapshot
    readmodel_head: ReadModelHead
    blob_status: str = "ready"
    degradation_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompanyCheckpointDelivery:
    """One fully verified plain checkpoint and its currentness boundary."""

    state: str
    reason: str | None
    checkpoint_id: str | None
    cursor: int | None
    head_sha256: str | None
    manifest_sha256: str | None
    generated_at: str | None
    verified_at: str | None
    current: bool


@dataclass(frozen=True)
class CompanySanitizedExportDelivery:
    """One fully verified, checkpoint-bound sanitized export."""

    state: str
    reason: str | None
    export_id: str | None
    export_sha256: str | None
    generated_at: str | None
    verified_at: str | None
    source_checkpoint_id: str | None
    source_checkpoint_manifest_sha256: str | None
    cursor: int | None
    head_sha256: str | None
    current: bool
    canonical_bundle_json: bytes | None


@dataclass(frozen=True)
class CompanyDeliverySnapshot:
    """Read-only checkpoint/export delivery truth, including discovery warnings."""

    checkpoint: CompanyCheckpointDelivery
    sanitized_export: CompanySanitizedExportDelivery
    warnings: tuple[str, ...] = ()


def _unavailable_checkpoint(reason: str) -> CompanyCheckpointDelivery:
    return CompanyCheckpointDelivery(
        state="unavailable", reason=reason, checkpoint_id=None, cursor=None,
        head_sha256=None, manifest_sha256=None, generated_at=None,
        verified_at=None, current=False,
    )


def _unavailable_sanitized_export(reason: str) -> CompanySanitizedExportDelivery:
    return CompanySanitizedExportDelivery(
        state="unavailable", reason=reason, export_id=None, export_sha256=None,
        generated_at=None, verified_at=None, source_checkpoint_id=None,
        source_checkpoint_manifest_sha256=None, cursor=None, head_sha256=None,
        current=False, canonical_bundle_json=None,
    )


_DEFAULT_DELIVERY_SNAPSHOT = CompanyDeliverySnapshot(
    checkpoint=_unavailable_checkpoint("no_verified_checkpoint"),
    sanitized_export=_unavailable_sanitized_export("no_verified_sanitized_export"),
)


@dataclass(frozen=True)
class CompanyQuerySnapshot:
    """One cursor-consistent read-only projection served under the owner lock."""

    health: CompanyStateHealth
    objects: tuple[ProjectedObject, ...]
    uncertain_dispatches: tuple[UncertainDispatch, ...]
    delivery: CompanyDeliverySnapshot = _DEFAULT_DELIVERY_SNAPSHOT


class CompanyHistoricalLedgerHeads(NamedTuple):
    """Deep-immutable identity/global/stream witness for historical replay."""

    identity: tuple[str, int, int] | None
    global_head: tuple[int, str]
    stream_heads: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True, slots=True)
class CompanyHistoricalReplayInput:
    """Record-chain-consistent immutable inputs for detached projection."""

    records: tuple[LedgerTransactionRecord, ...]
    heads: CompanyHistoricalLedgerHeads
    state_root: Path
    pointer_sha256: str
    ledger_status: str
    projection_status: str
    blob_status: str
    degradation_reasons: tuple[str, ...]


def _fail(message: str) -> None:
    raise CompanyStateReaderError(message)


def _mapping_items(
    value: Mapping[Any, Any],
    label: str,
) -> tuple[tuple[Any, Any], ...]:
    """Materialize caller mappings through one typed failure boundary."""

    try:
        raw_items = tuple(value.items())
    except CompanyStateReaderError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise CompanyStateReaderError(f"{label} cannot be traversed") from exc
    items: list[tuple[Any, Any]] = []
    keys: set[str] = set()
    for item in raw_items:
        if type(item) is not tuple or len(item) != 2:
            _fail(f"{label} items must be exact pairs")
        key = item[0]
        if type(key) is not str:
            _fail(f"{label} keys must be exact strings")
        if key in keys:
            _fail(f"{label} contains a duplicate key")
        keys.add(key)
        items.append((key, item[1]))
    return tuple(items)


def _plain(value: Any) -> Any:
    """Detach ledger-owned immutable mappings into contract-validator inputs."""

    if isinstance(value, Mapping):
        return {
            key: _plain(member)
            for key, member in _mapping_items(value, "contract mapping")
        }
    if type(value) is tuple:
        return [_plain(member) for member in value]
    if type(value) is list:
        return [_plain(member) for member in value]
    return value


def _immutable_json(value: Any) -> Any:
    """Deep-copy contract JSON into tuple/mapping-proxy containers."""

    if isinstance(value, Mapping):
        return MappingProxyType({
            key: _immutable_json(member)
            for key, member in _mapping_items(value, "contract mapping")
        })
    if type(value) in {tuple, list}:
        return tuple(_immutable_json(member) for member in value)
    return value


def _immutable_records(value: object) -> tuple[LedgerTransactionRecord, ...]:
    """Detach caller records before validation can authorize later reuse."""

    if type(value) is not tuple:
        _fail("historical ledger records must be an exact tuple")
    records: list[LedgerTransactionRecord] = []
    for record in cast(tuple[object, ...], value):
        if type(record) is not LedgerTransactionRecord:
            _fail(
                "historical ledger record must be the exact "
                "LedgerTransactionRecord type"
            )
        current = cast(LedgerTransactionRecord, record)
        if type(current.events) is not tuple or type(current.reservations) is not tuple:
            _fail("historical ledger record membership must be exact tuples")
        events: list[LedgerEventRecord] = []
        for event in current.events:
            if type(event) is not LedgerEventRecord:
                _fail("historical ledger event must be the exact record type")
            events.append(LedgerEventRecord(
                _immutable_json(event.event),
                event.stream_sequence,
                event.previous_event_sha256,
                event.event_sha256,
            ))
        reservations: list[LedgerReservationRecord] = []
        for reservation in current.reservations:
            if type(reservation) is not LedgerReservationRecord:
                _fail("historical ledger reservation must be the exact record type")
            reservations.append(LedgerReservationRecord(
                _immutable_json(reservation.event),
            ))
        records.append(LedgerTransactionRecord(
            current.global_sequence,
            _immutable_json(current.request),
            _immutable_json(current.receipt),
            tuple(events),
            tuple(reservations),
        ))
    return tuple(records)


def _exact_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{label} must be a non-negative exact integer")
    return cast(int, value)


def _exact_positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(f"{label} must be a positive exact integer")
    return cast(int, value)


def _sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return cast(str, value)


def _identity(value: object, label: str) -> tuple[str, int, int] | None:
    if value is None:
        return None
    if type(value) is not tuple or len(value) != 3:
        _fail(f"{label} must be an exact identity tuple or None")
    company_id, incarnation, generation = cast(
        tuple[object, object, object],
        value,
    )
    if type(company_id) is not str or not company_id:
        _fail(f"{label} company ID is invalid")
    return (
        cast(str, company_id),
        _exact_positive_int(incarnation, f"{label} incarnation"),
        _exact_positive_int(generation, f"{label} lock-domain generation"),
    )


def _historical_heads(value: object) -> CompanyHistoricalLedgerHeads:
    if type(value) is not CompanyHistoricalLedgerHeads:
        _fail("historical ledger heads must be the exact immutable witness type")
    witness = cast(CompanyHistoricalLedgerHeads, value)
    identity = _identity(witness.identity, "historical ledger identity")
    if type(witness.global_head) is not tuple or len(witness.global_head) != 2:
        _fail("historical global head must be an exact pair")
    sequence = _exact_nonnegative_int(
        witness.global_head[0],
        "historical global sequence",
    )
    digest = _sha256(witness.global_head[1], "historical global digest")
    if (sequence == 0) != (digest == ZERO_SHA256):
        _fail("historical zero global head must use the exact zero digest")
    if type(witness.stream_heads) is not tuple:
        _fail("historical stream heads must be an exact tuple")
    normalized: list[tuple[str, int, str]] = []
    previous_stream: str | None = None
    for entry in witness.stream_heads:
        if type(entry) is not tuple or len(entry) != 3:
            _fail("historical stream head must be an exact triple")
        stream, cursor, stream_digest = entry
        if type(stream) is not str or not stream:
            _fail("historical stream name is invalid")
        if previous_stream is not None and stream <= previous_stream:
            _fail("historical stream heads must be strictly sorted")
        normalized.append((
            stream,
            _exact_positive_int(cursor, "historical stream cursor"),
            _sha256(stream_digest, "historical stream digest"),
        ))
        previous_stream = stream
    if sequence == 0 and (identity is not None or normalized):
        _fail("empty historical ledger must have no identity or stream heads")
    if sequence > 0 and identity is None:
        _fail("non-empty historical ledger must have an identity")
    return CompanyHistoricalLedgerHeads(identity, (sequence, digest), tuple(normalized))


def immutable_ledger_heads(heads: LedgerHeadsSnapshot) -> CompanyHistoricalLedgerHeads:
    """Normalize one exact live ledger snapshot into an immutable sorted witness."""

    if type(heads) is not LedgerHeadsSnapshot:
        _fail("ledger heads must be the exact LedgerHeadsSnapshot type")
    identity = _identity(heads.identity, "ledger identity")
    if type(heads.global_head) is not LedgerHead:
        _fail("ledger global head must be the exact LedgerHead type")
    sequence = _exact_nonnegative_int(heads.global_head.global_sequence, "ledger global sequence")
    digest = _sha256(heads.global_head.transaction_sha256, "ledger global digest")
    if (sequence == 0) != (digest == ZERO_SHA256):
        _fail("ledger zero global head must use the exact zero digest")
    if not isinstance(heads.stream_heads, Mapping):
        _fail("ledger stream heads must be a mapping")
    normalized: list[tuple[str, int, str]] = []
    for stream, head in _mapping_items(
        heads.stream_heads,
        "ledger stream heads",
    ):
        if type(stream) is not str or not stream:
            _fail("ledger stream name is invalid")
        if type(head) is not tuple or len(head) != 2:
            _fail("ledger stream head must be an exact pair")
        normalized.append((
            stream,
            _exact_positive_int(head[0], "ledger stream cursor"),
            _sha256(head[1], "ledger stream digest"),
        ))
    result = CompanyHistoricalLedgerHeads(
        identity, (sequence, digest), tuple(sorted(normalized)),
    )
    return _historical_heads(result)


def _validated_record(
    record: object,
    expected_sequence: int,
    identity: tuple[str, int, int] | None,
    global_digest: str,
    stream_heads: dict[str, tuple[int, str]],
    transaction_ids: set[str],
    command_ids: set[str],
    event_ids: set[str],
    takeover_capability_ids: set[str],
    takeover_consumption_ids: set[str],
) -> tuple[tuple[str, int, int], str]:
    if type(record) is not LedgerTransactionRecord:
        _fail("historical ledger record must be the exact LedgerTransactionRecord type")
    current = cast(LedgerTransactionRecord, record)
    if _exact_positive_int(current.global_sequence, "historical record sequence") != expected_sequence:
        _fail("historical ledger global sequence is not contiguous")
    if not isinstance(current.request, Mapping) or not isinstance(current.receipt, Mapping):
        _fail("historical ledger request and receipt must be mappings")
    try:
        request = validate_company_transaction_request(_plain(current.request))
        receipt = validate_company_transaction_receipt(_plain(current.receipt))
    except CompanyContractError as exc:
        raise CompanyStateReaderError("historical ledger contract validation failed") from exc
    transaction_id = request["transaction_id"]
    command_id = request["command_id"]
    if transaction_id in transaction_ids or command_id in command_ids:
        _fail("historical transaction or command identity is reused")
    transaction_ids.add(transaction_id)
    command_ids.add(command_id)
    try:
        takeover = _takeover_consumption(request)
    except LedgerCorruptionError as exc:
        raise CompanyStateReaderError(
            "historical takeover binding is invalid",
        ) from exc
    if takeover is not None:
        capability, consumption = takeover
        capability_id = capability["capability_id"]
        consumption_id = consumption["consumption_id"]
        if (
            capability_id in takeover_capability_ids
            or consumption_id in takeover_consumption_ids
        ):
            _fail("historical takeover identity is reused")
        takeover_capability_ids.add(capability_id)
        takeover_consumption_ids.add(consumption_id)
    current_identity = (
        request["company_id"], request["company_incarnation"],
        request["lock_domain_generation"],
    )
    if identity is not None and current_identity != identity:
        _fail("historical ledger request identity drifts")
    if (
        (receipt["company_id"], receipt["company_incarnation"], receipt["lock_domain_generation"])
        != current_identity
        or receipt["global_sequence"] != expected_sequence
        or receipt["previous_transaction_sha256"] != global_digest
        or receipt["request_sha256"] != request["request_sha256"]
        or receipt["transaction_id"] != request["transaction_id"]
        or receipt["command_id"] != request["command_id"]
    ):
        _fail("historical ledger transaction chain is inconsistent")
    expected_global = request["expected_transaction_head"]
    if (
        expected_global["global_sequence"] != expected_sequence - 1
        or expected_global["transaction_sha256"] != global_digest
    ):
        _fail("historical request expected global head differs")
    expected_streams = {
        head["stream"]: (head["cursor"], head["event_sha256"])
        for head in request["expected_heads"]
    }
    if any(expected_streams.get(stream) != stream_heads.get(stream, (0, ZERO_SHA256)) for stream in expected_streams):
        _fail("historical request expected stream head differs")
    requested_events = request["events"]
    if receipt["state"] == "committed":
        if (
            type(current.events) is not tuple
            or type(current.reservations) is not tuple
            or current.reservations != ()
        ):
            _fail("committed historical record event membership is invalid")
        if len(current.events) != len(requested_events):
            _fail("committed historical record event count differs")
        observed: dict[str, tuple[int, str]] = {}
        for requested, event_record in zip(
            requested_events,
            current.events,
            strict=True,
        ):
            event_id = requested["event_id"]
            if event_id in event_ids:
                _fail("historical event identity is reused")
            event_ids.add(event_id)
            if type(event_record) is not LedgerEventRecord:
                _fail("committed historical event record is invalid")
            current_event = event_record
            if not isinstance(current_event.event, Mapping):
                _fail("committed historical event record is invalid")
            event = _plain(current_event.event)
            if (
                canonical_company_json_bytes(event)
                != canonical_company_json_bytes(requested)
            ):
                _fail("committed historical event differs from its request")
            stream = requested["stream"]
            cursor, previous = stream_heads.get(stream, (0, ZERO_SHA256))
            if (
                _exact_positive_int(current_event.stream_sequence, "historical event stream sequence") != cursor + 1
                or _sha256(current_event.previous_event_sha256, "historical event previous digest") != previous
                or _sha256(current_event.event_sha256, "historical event digest")
                != company_contract_sha256({
                    "event": event, "stream_sequence": cursor + 1,
                    "previous_event_sha256": previous,
                })
            ):
                _fail("historical committed event stream adjacency is broken")
            stream_heads[stream] = (cursor + 1, current_event.event_sha256)
            observed[stream] = (cursor + 1, current_event.event_sha256)
        receipt_heads = {
            head["stream"]: (head["cursor"], head["event_sha256"])
            for head in receipt["result_heads"]
        }
        if observed != receipt_heads:
            _fail("historical receipt result stream heads differ")
    else:
        if (
            type(current.events) is not tuple
            or current.events != ()
            or type(current.reservations) is not tuple
        ):
            _fail("non-committed historical record membership is invalid")
        if len(current.reservations) != len(requested_events):
            _fail("historical reservation count differs")
        for requested, reservation in zip(
            requested_events,
            current.reservations,
            strict=True,
        ):
            event_id = requested["event_id"]
            if event_id in event_ids:
                _fail("historical event identity is reused")
            event_ids.add(event_id)
            if type(reservation) is not LedgerReservationRecord:
                _fail("historical reservation record is invalid")
            current_reservation = reservation
            if not isinstance(current_reservation.event, Mapping):
                _fail("historical reservation record is invalid")
            if (
                canonical_company_json_bytes(_plain(current_reservation.event))
                != canonical_company_json_bytes(requested)
            ):
                _fail("historical reservation differs from its request")
    return current_identity, receipt["transaction_sha256"]


def _validate_historical_ledger_snapshot(
    records: tuple[LedgerTransactionRecord, ...],
    heads: CompanyHistoricalLedgerHeads,
) -> CompanyHistoricalLedgerHeads:
    """Reconstruct and exactly compare detached ledger records with their witness."""

    expected_heads = _historical_heads(heads)
    if type(records) is not tuple:
        _fail("historical ledger records must be an exact tuple")
    identity: tuple[str, int, int] | None = None
    global_digest = ZERO_SHA256
    stream_heads: dict[str, tuple[int, str]] = {}
    transaction_ids: set[str] = set()
    command_ids: set[str] = set()
    event_ids: set[str] = set()
    takeover_capability_ids: set[str] = set()
    takeover_consumption_ids: set[str] = set()
    for sequence, record in enumerate(records, 1):
        current_identity, global_digest = _validated_record(
            record,
            sequence,
            identity,
            global_digest,
            stream_heads,
            transaction_ids,
            command_ids,
            event_ids,
            takeover_capability_ids,
            takeover_consumption_ids,
        )
        if identity is None:
            identity = current_identity
    actual = CompanyHistoricalLedgerHeads(
        identity,
        (len(records), global_digest),
        tuple(sorted((stream, cursor, digest) for stream, (cursor, digest) in stream_heads.items())),
    )
    actual = _historical_heads(actual)
    if actual != expected_heads:
        _fail("historical ledger records differ from their immutable heads")
    return actual


def validate_historical_ledger_snapshot(
    records: tuple[LedgerTransactionRecord, ...],
    heads: CompanyHistoricalLedgerHeads,
) -> CompanyHistoricalLedgerHeads:
    """Deep-copy and validate one exact detached record-chain snapshot."""

    try:
        return _validate_historical_ledger_snapshot(
            _immutable_records(records),
            heads,
        )
    except CompanyStateReaderError:
        raise
    except (
        AttributeError,
        CompanyContractError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise CompanyStateReaderError(
            "historical ledger snapshot cannot be validated",
        ) from exc


def immutable_historical_replay_input(
    replay: CompanyHistoricalReplayInput,
) -> CompanyHistoricalReplayInput:
    """Return a deeply detached replay only after full record validation."""

    try:
        if type(replay) is not CompanyHistoricalReplayInput:
            _fail("historical replay input must be the exact value type")
        if (
            not isinstance(replay.state_root, Path)
            or not replay.state_root.is_absolute()
        ):
            _fail("historical replay state root must be an absolute Path")
        for value, label in (
            (replay.pointer_sha256, "historical replay pointer digest"),
            (replay.ledger_status, "historical replay ledger status"),
            (replay.projection_status, "historical replay projection status"),
            (replay.blob_status, "historical replay blob status"),
        ):
            if type(value) is not str or not value:
                _fail(f"{label} must be a non-empty exact string")
        _sha256(replay.pointer_sha256, "historical replay pointer digest")
        if (
            type(replay.degradation_reasons) is not tuple
            or any(
                type(reason) is not str or not reason
                for reason in replay.degradation_reasons
            )
        ):
            _fail(
                "historical replay degradation reasons must be an exact "
                "tuple of strings"
            )
        records = _immutable_records(replay.records)
        heads = _validate_historical_ledger_snapshot(records, replay.heads)
        return CompanyHistoricalReplayInput(
            records=records,
            heads=heads,
            state_root=replay.state_root,
            pointer_sha256=replay.pointer_sha256,
            ledger_status=replay.ledger_status,
            projection_status=replay.projection_status,
            blob_status=replay.blob_status,
            degradation_reasons=replay.degradation_reasons,
        )
    except CompanyStateReaderError:
        raise
    except (
        AttributeError,
        CompanyContractError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise CompanyStateReaderError(
            "historical replay input cannot be validated",
        ) from exc


__all__ = [
    "CompanyCheckpointDelivery",
    "CompanyDeliverySnapshot",
    "CompanyHistoricalLedgerHeads",
    "CompanyHistoricalReplayInput",
    "CompanyQuerySnapshot",
    "CompanySanitizedExportDelivery",
    "CompanyStateHealth",
    "CompanyStateReaderError",
    "_DEFAULT_DELIVERY_SNAPSHOT",
    "_unavailable_checkpoint",
    "_unavailable_sanitized_export",
    "immutable_ledger_heads",
    "validate_historical_ledger_snapshot",
    "immutable_historical_replay_input",
]
