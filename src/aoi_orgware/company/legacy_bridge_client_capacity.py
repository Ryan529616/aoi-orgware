"""Bounded, immutable capacity receipts for legacy bridge client scopes.

Capacity receipts are observation-only evidence.  They authorize neither a
successor scope nor another ingest attempt.  A Chief or user must create the
successor task explicitly and bind its archive to this receipt.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping, NamedTuple, NoReturn, cast

from .contracts import canonical_company_json_bytes, company_contract_sha256
from .legacy_bridge import normalize_legacy_bridge_snapshot
from .legacy_bridge_contract import legacy_bridge_scope_id
from .legacy_bridge_health import legacy_bridge_attempt_id


CAPACITY_SCHEMA = "aoi.company.legacy-bridge-client-capacity.v1"
ATTEMPT_LIMIT = 256
MAX_CAPACITY_RECEIPT_BYTES = 256 * 1024

_SHA_LENGTH = 64
_DIGEST_FIELDS = (
    "attempt_marker_sha256",
    "source_sha256",
    "prepared_receipt_sha256",
    "terminal_receipt_sha256",
    "reconciliation_receipt_sha256",
)
_STATES = frozenset({
    "marker_only",
    "source_only",
    "prepared_effect_unknown",
    "terminal_none",
    "terminal_committed",
    "terminal_effect_unknown",
    "reconciled_committed",
})
_STATE_SUCCESSORS = {
    "marker_only": _STATES,
    "source_only": _STATES - {"marker_only"},
    "prepared_effect_unknown": frozenset({
        "prepared_effect_unknown",
        "terminal_none",
        "terminal_committed",
        "terminal_effect_unknown",
        "reconciled_committed",
    }),
    "terminal_none": frozenset({"terminal_none"}),
    "terminal_committed": frozenset({"terminal_committed"}),
    "terminal_effect_unknown": frozenset({
        "terminal_effect_unknown",
        "reconciled_committed",
    }),
    "reconciled_committed": frozenset({"reconciled_committed"}),
}


class CapacityContractError(RuntimeError):
    """One stable, secret-free capacity contract failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CapacityAttemptV1(NamedTuple):
    attempt_id: str
    attempt_marker_sha256: str
    source_sha256: str | None
    prepared_receipt_sha256: str | None
    terminal_receipt_sha256: str | None
    reconciliation_receipt_sha256: str | None
    effective_state: str

    def as_dict(self) -> dict[str, Any]:
        return self._asdict()


def _fail(code: str) -> NoReturn:
    raise CapacityContractError(code)


def _sha(value: Any, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if (
        type(value) is not str
        or len(value) != _SHA_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"invalid_{label}")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        _fail(f"invalid_{label}")
    return value


def _timestamp(value: Any) -> str:
    if type(value) is not str or len(value) > 64:
        _fail("invalid_capacity_sealed_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        raise CapacityContractError("invalid_capacity_sealed_at") from exc
    if parsed.tzinfo is None:
        _fail("invalid_capacity_sealed_at")
    return value


def _validate_attempt(value: Any) -> CapacityAttemptV1:
    if type(value) is not dict or set(value) != {
        "attempt_id",
        *_DIGEST_FIELDS,
        "effective_state",
    }:
        _fail("invalid_capacity_attempt")
    item = cast(dict[str, Any], value)
    attempt_id = cast(str, _sha(item["attempt_id"], "capacity_attempt_id"))
    marker = cast(str, _sha(
        item["attempt_marker_sha256"],
        "capacity_attempt_marker_sha256",
    ))
    optional = tuple(
        _sha(item[name], f"capacity_{name}", optional=True)
        for name in _DIGEST_FIELDS[1:]
    )
    state = item["effective_state"]
    if type(state) is not str or state not in _STATES:
        _fail("invalid_capacity_effective_state")
    source, prepared, terminal, reconciliation = optional
    if (
        (state == "marker_only" and any(optional))
        or (state == "source_only" and (source is None or any(optional[1:])))
        or (state == "prepared_effect_unknown" and (
            source is None or prepared is None or terminal is not None
            or reconciliation is not None
        ))
        or (state.startswith("terminal_") and (
            source is None or prepared is None or terminal is None
            or reconciliation is not None
        ))
        or (state == "reconciled_committed" and (
            source is None or prepared is None or terminal is None
            or reconciliation is None
        ))
    ):
        _fail("capacity_attempt_state_mismatch")
    return CapacityAttemptV1(
        attempt_id,
        marker,
        source,
        prepared,
        terminal,
        reconciliation,
        state,
    )


def normalize_attempts(values: tuple[CapacityAttemptV1, ...]) -> tuple[CapacityAttemptV1, ...]:
    if type(values) is not tuple or len(values) > ATTEMPT_LIMIT:
        _fail("invalid_capacity_attempts")
    result: list[CapacityAttemptV1] = []
    seen: set[str] = set()
    for value in values:
        if type(value) is not CapacityAttemptV1:
            _fail("invalid_capacity_attempt")
        validated = _validate_attempt(value.as_dict())
        if validated.attempt_id in seen:
            _fail("duplicate_capacity_attempt")
        seen.add(validated.attempt_id)
        result.append(validated)
    return tuple(sorted(result, key=lambda item: item.attempt_id))


def inventory_digest(values: tuple[CapacityAttemptV1, ...]) -> str:
    attempts = normalize_attempts(values)
    return company_contract_sha256({
        "domain": "aoi.company.legacy-bridge-client-capacity-inventory.v1",
        "attempts": [item.as_dict() for item in attempts],
    })


def capacity_source_sha256(
    source: bytes,
    *,
    expected_scope_id: str,
    expected_attempt_id: str,
) -> str:
    """Validate one source-only crash artifact against its path identities."""

    if type(source) is not bytes:
        _fail("invalid_capacity_source")
    try:
        projection = normalize_legacy_bridge_snapshot(source)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise CapacityContractError("invalid_client_receipt_source") from exc
    source_sha256 = hashlib.sha256(source).hexdigest()
    observed_scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=projection.legacy_archive_sha256,
        task_identity_digest=projection.task_identity_digest,
    )
    observed_attempt = legacy_bridge_attempt_id(
        observed_scope,
        source_document_sha256=source_sha256,
        source_document_size_bytes=len(source),
    )
    if observed_scope != expected_scope_id or observed_attempt != expected_attempt_id:
        _fail("source_only_attempt_binding_mismatch")
    return source_sha256


def build_capacity_receipt(
    bridge_scope_id: str,
    attempts: tuple[CapacityAttemptV1, ...],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    scope = cast(str, _sha(bridge_scope_id, "capacity_bridge_scope_id"))
    normalized = normalize_attempts(attempts)
    if len(normalized) != ATTEMPT_LIMIT:
        _fail("capacity_not_saturated")
    payload = {
        "schema_version": CAPACITY_SCHEMA,
        "bridge_scope_id": scope,
        "attempt_limit": ATTEMPT_LIMIT,
        "attempt_count": len(normalized),
        "attempts": [item.as_dict() for item in normalized],
        "sealed_inventory_sha256": inventory_digest(normalized),
        "decision": "successor_rollover_required",
        "sealed_at": _timestamp(sealed_at),
    }
    receipt = {
        **payload,
        "receipt_sha256": company_contract_sha256({
            "domain": f"{CAPACITY_SCHEMA}.receipt",
            "receipt": payload,
        }),
    }
    canonical_company_json_bytes(receipt, max_bytes=MAX_CAPACITY_RECEIPT_BYTES)
    return receipt


def _parse_receipt(value: Any) -> tuple[dict[str, Any], tuple[CapacityAttemptV1, ...]]:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "bridge_scope_id",
        "attempt_limit",
        "attempt_count",
        "attempts",
        "sealed_inventory_sha256",
        "decision",
        "sealed_at",
        "receipt_sha256",
    }:
        _fail("invalid_capacity_receipt")
    item = cast(dict[str, Any], value)
    if (
        item["schema_version"] != CAPACITY_SCHEMA
        or item["attempt_limit"] != ATTEMPT_LIMIT
        or item["decision"] != "successor_rollover_required"
    ):
        _fail("invalid_capacity_receipt")
    _sha(item["bridge_scope_id"], "capacity_bridge_scope_id")
    count = _integer(item["attempt_count"], "capacity_attempt_count")
    raw_attempts = item["attempts"]
    if type(raw_attempts) is not list:
        _fail("invalid_capacity_attempts")
    attempts = normalize_attempts(tuple(_validate_attempt(value) for value in raw_attempts))
    if count != ATTEMPT_LIMIT or count != len(attempts):
        _fail("capacity_attempt_count_mismatch")
    if item["sealed_inventory_sha256"] != inventory_digest(attempts):
        _fail("capacity_inventory_digest_mismatch")
    _timestamp(item["sealed_at"])
    supplied = _sha(item["receipt_sha256"], "capacity_receipt_sha256")
    payload = {name: item[name] for name in item if name != "receipt_sha256"}
    expected = company_contract_sha256({
        "domain": f"{CAPACITY_SCHEMA}.receipt",
        "receipt": payload,
    })
    if supplied != expected:
        _fail("capacity_receipt_digest_mismatch")
    canonical_company_json_bytes(item, max_bytes=MAX_CAPACITY_RECEIPT_BYTES)
    return dict(item), attempts


def validate_capacity_receipt(
    value: Any,
    *,
    expected_scope_id: str,
    current_attempts: tuple[CapacityAttemptV1, ...],
) -> dict[str, Any]:
    receipt, sealed_attempts = _parse_receipt(value)
    if receipt["bridge_scope_id"] != expected_scope_id:
        _fail("capacity_scope_mismatch")
    current = normalize_attempts(current_attempts)
    if tuple(item.attempt_id for item in current) != tuple(
        item.attempt_id for item in sealed_attempts
    ):
        _fail("capacity_attempt_identity_drift")
    for sealed, observed in zip(sealed_attempts, current, strict=True):
        for name in _DIGEST_FIELDS:
            before = getattr(sealed, name)
            after = getattr(observed, name)
            if before is not None and before != after:
                _fail("capacity_attempt_digest_drift")
        if observed.effective_state not in _STATE_SUCCESSORS[sealed.effective_state]:
            _fail("capacity_attempt_state_regression")
    return receipt


__all__ = [
    "ATTEMPT_LIMIT",
    "CAPACITY_SCHEMA",
    "MAX_CAPACITY_RECEIPT_BYTES",
    "CapacityAttemptV1",
    "CapacityContractError",
    "build_capacity_receipt",
    "capacity_source_sha256",
    "inventory_digest",
    "normalize_attempts",
    "validate_capacity_receipt",
]
