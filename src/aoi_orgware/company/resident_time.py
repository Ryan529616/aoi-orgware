"""Resident-only logical event time over a cooperative wall clock.

The returned value is a nondecreasing ledger event time, not proof of the
host's current wall-clock instant.  Exact transaction replay keeps the
original durable spelling; new transactions are floored by the durable tail,
active authority epochs, and this service incarnation's high-water mark.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .ledger import LedgerHeadsSnapshot, LedgerTransactionRecord
from .readmodel import ProjectedObject


class ResidentLogicalTimeError(RuntimeError):
    """Durable state cannot provide one trustworthy logical time floor."""


class ResidentTimeState(Protocol):
    """Read-only Supervisor surface needed by the logical clock."""

    def heads(self) -> LedgerHeadsSnapshot: ...

    def records_after(
        self,
        global_sequence: int,
        *,
        limit: int = 1024,
    ) -> tuple[LedgerTransactionRecord, ...]: ...

    def record_by_transaction_id(
        self,
        transaction_id: str,
    ) -> LedgerTransactionRecord | None: ...

    def objects(
        self,
        *,
        contract_type: str | None = None,
    ) -> tuple[ProjectedObject, ...]: ...


def _parsed_time(value: str, label: str) -> datetime:
    if type(value) is not str:
        raise ResidentLogicalTimeError(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value,
        )
    except ValueError as exc:
        raise ResidentLogicalTimeError(f"{label} is not a timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ResidentLogicalTimeError(f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _canonical_time(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _recorded_values(record: LedgerTransactionRecord) -> tuple[str, ...]:
    values: list[str] = []
    receipt_time = record.receipt.get("recorded_at")
    if type(receipt_time) is not str:
        raise ResidentLogicalTimeError(
            "durable transaction receipt lacks recorded_at",
        )
    values.append(receipt_time)
    for member in record.events:
        event_time = member.event.get("recorded_at")
        if type(event_time) is not str:
            raise ResidentLogicalTimeError(
                "durable transaction member lacks recorded_at",
            )
        values.append(event_time)
    for reservation in record.reservations:
        event_time = reservation.event.get("recorded_at")
        if type(event_time) is not str:
            raise ResidentLogicalTimeError(
                "durable reservation lacks recorded_at",
            )
        values.append(event_time)
    for index, value in enumerate(values):
        _parsed_time(value, f"durable transaction time {index}")
    return tuple(values)


def _exact_replay_time(record: LedgerTransactionRecord) -> str:
    values = _recorded_values(record)
    instants = {_parsed_time(value, "durable replay time") for value in values}
    if len(instants) != 1:
        raise ResidentLogicalTimeError(
            "durable transaction has more than one replay time",
        )
    return values[0]


def _tail_floor(state: ResidentTimeState) -> str | None:
    head = state.heads().global_head.global_sequence
    if head == 0:
        return None
    records = state.records_after(head - 1, limit=1)
    if len(records) != 1 or records[0].global_sequence != head:
        raise ResidentLogicalTimeError("durable ledger tail is unavailable")
    values = _recorded_values(records[0])
    return _canonical_time(
        max(_parsed_time(value, "durable tail time") for value in values),
    )


def _authority_floors(state: ResidentTimeState) -> tuple[str, ...]:
    floors: list[str] = []
    authority_types = (
        ("authority_grant_v1", "authority_state"),
        ("chief_term_v1", "state"),
    )
    for contract_type, state_field in authority_types:
        for item in state.objects(contract_type=contract_type):
            payload: Mapping[str, object] = item.payload
            if payload.get(state_field) != "active":
                continue
            value = payload.get("issued_at")
            if type(value) is not str:
                raise ResidentLogicalTimeError(
                    "active authority object lacks issued_at",
                )
            _parsed_time(value, "active authority time")
            floors.append(value)
    return tuple(floors)


@dataclass(slots=True)
class ResidentLogicalEventClock:
    """Allocate nondecreasing times for new resident-owned transactions."""

    _high_water: datetime | None = None

    def _observe(self, value: str) -> datetime:
        observed = _parsed_time(value, "resident event time")
        if self._high_water is None or observed > self._high_water:
            self._high_water = observed
        return observed

    def recorded_at(
        self,
        state: ResidentTimeState,
        transaction_id: str,
        wall_recorded_at: str,
    ) -> str:
        """Return exact replay time or allocate a new logical event time."""

        durable = state.record_by_transaction_id(transaction_id)
        if durable is not None:
            exact = _exact_replay_time(durable)
            self._observe(exact)
            return exact
        candidates = [wall_recorded_at, *_authority_floors(state)]
        tail = _tail_floor(state)
        if tail is not None:
            candidates.append(tail)
        if self._high_water is not None:
            candidates.append(_canonical_time(self._high_water))
        selected = max(
            _parsed_time(value, "resident time candidate")
            for value in candidates
        )
        self._high_water = selected
        return _canonical_time(selected)
