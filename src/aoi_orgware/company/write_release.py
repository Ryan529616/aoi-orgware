"""Pure, observation-only W3 derivation from one reducer-validated snapshot.

This module intentionally has no release event or admission/Supervisor wiring.
It cannot make a write available: it only records whether the immutable W2
scope is not acquired, must remain held, or is not sufficiently observable.
``release_proven`` remains a future ABI value only: this alpha has no typed
ledger/snapshot closure-proof contract.  In particular, App Server process
exit is not process-tree or execution-pool quiescence proof.

The public replay boundary rejects caller-supplied snapshots and ordinary
same-process instance-method shadows on an exact state owner/ledger.  It is
not an adversarial same-process integrity boundary against class monkeypatch,
``ctypes``, or direct replacement of private owner state.
"""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping
from dataclasses import dataclass
from typing import Any, Literal, Mapping, NamedTuple, Never, Sequence

from .contracts import (
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    CompanyContractError,
    company_contract_sha256,
)
from .invariants import (
    CompanyInvariantError,
    InvariantObject,
    reduce_company_invariants,
)
from .ledger import CompanyLedger, LedgerError
from .readmodel import ReadModelError
from .state import CompanyQuerySnapshot, CompanyStateError, CompanyStateOwner
from .write_admission import WORK_WRITE_INTENT_V1, WriteAdmissionError, validate_work_write_intent


ReleaseDisposition = Literal["not_acquired", "held", "release_proven", "coverage_unknown"]


class WriteReleaseError(ValueError):
    """Owner-verified ledger replay could not produce one trusted cursor view."""


class WriteReleaseObservation(NamedTuple):
    """Immutable observation receipt; nested JSON containers are frozen too."""

    intent_id: str
    owner_kind: str
    owner_id: str
    disposition: ReleaseDisposition
    reason_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence_digest: str
    cursor: int
    head_sha256: str
    refs: tuple[Mapping[str, Any], ...]
    runtime_ownership_only: bool = True


@dataclass(frozen=True, slots=True)
class _ObservationContext:
    cursor: int
    head_sha256: str


class _FrozenMapping(tuple[tuple[str, Any], ...]):
    """Tuple-backed Mapping with no mutable backing container or instance dict."""

    __slots__ = ()

    def __new__(cls, items: Sequence[tuple[str, Any]]) -> _FrozenMapping:
        return tuple.__new__(cls, tuple((str(key), value) for key, value in items))

    def __iter__(self):  # type: ignore[no-untyped-def]
        return (key for key, _value in tuple.__iter__(self))

    def __len__(self) -> int:
        return tuple.__len__(self)

    def __getitem__(self, key: str) -> Any:  # type: ignore[override]
        if not isinstance(key, str):
            raise TypeError("frozen mapping keys must be strings")
        for candidate, value in tuple.__iter__(self):
            if candidate == key:
                return value
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and any(
            candidate == key for candidate, _value in tuple.__iter__(self)
        )

    def items(self) -> tuple[tuple[str, Any], ...]:
        return tuple(tuple.__iter__(self))

    def keys(self) -> tuple[str, ...]:
        return tuple(key for key, _value in tuple.__iter__(self))

    def values(self) -> tuple[Any, ...]:
        return tuple(value for _key, value in tuple.__iter__(self))

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ABCMapping):
            return len(self) == len(other) and all(
                key in other and other[key] == value
                for key, value in tuple.__iter__(self)
            )
        if isinstance(other, tuple):
            return self.items() == other
        return tuple.__eq__(self, other)


ABCMapping.register(_FrozenMapping)


def _fail(message: str) -> Never:
    raise WriteReleaseError(message)


def _plain(value: Any) -> Any:
    """Thaw read-model frozen JSON before canonical validation."""
    if isinstance(value, Mapping):
        return {str(key): _plain(member) for key, member in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(member) for member in value]
    return value


def _freeze(value: Any) -> Any:
    """Detach W3 output from mutable read-model-compatible JSON containers."""
    if isinstance(value, Mapping):
        return _FrozenMapping(tuple(
            (str(key), _freeze(member)) for key, member in value.items()
        ))
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(member) for member in value)
    return value


def _snapshot_objects(snapshot: CompanyQuerySnapshot) -> tuple[InvariantObject, ...]:
    if not isinstance(snapshot, CompanyQuerySnapshot):
        _fail("write release requires CompanyQuerySnapshot")
    health = snapshot.health
    if (
        health.status != "ready"
        or health.ledger_status != "ready"
        or health.projection_status not in {"ready", "historical_prefix_replay"}
        or health.blob_status != "ready"
        or not isinstance(health.readmodel_head.global_sequence, int)
        or isinstance(health.readmodel_head.global_sequence, bool)
        or health.readmodel_head.global_sequence < 0
    ):
        _fail("snapshot health is not authoritative")
    ledger_head = health.ledger_heads.global_head
    readmodel_head = health.readmodel_head
    identity = health.ledger_heads.identity
    if (
        identity != (
            readmodel_head.company_id,
            readmodel_head.company_incarnation,
            readmodel_head.lock_domain_generation,
        )
        or ledger_head.global_sequence != readmodel_head.global_sequence
        or ledger_head.transaction_sha256 != readmodel_head.transaction_sha256
    ):
        _fail("snapshot ledger and read-model heads differ")
    values: list[InvariantObject] = []
    seen_logical: set[tuple[str, str]] = set()
    seen_events: set[str] = set()
    for item in snapshot.objects:
        if (
            not isinstance(item.contract_type, str)
            or not isinstance(item.object_key, str)
            or not isinstance(item.event_id, str)
            or not isinstance(item.global_sequence, int)
            or isinstance(item.global_sequence, bool)
            or item.global_sequence < 0
            or item.global_sequence > readmodel_head.global_sequence
            or not isinstance(item.payload, Mapping)
        ):
            _fail("snapshot projected object is malformed")
        logical = (item.contract_type, item.object_key)
        if logical in seen_logical or item.event_id in seen_events:
            _fail("snapshot current object identity is duplicated")
        seen_logical.add(logical)
        seen_events.add(item.event_id)
        try:
            payload = _plain(item.payload)
            payload_sha256 = company_contract_sha256(payload)
        except (CompanyContractError, TypeError, ValueError) as exc:
            raise WriteReleaseError("snapshot payload cannot be canonicalized") from exc
        values.append(InvariantObject(
            item.contract_type, item.object_key, item.event_id,
            item.global_sequence, payload_sha256, payload,
        ))
    try:
        projection = reduce_company_invariants(values, snapshot.uncertain_dispatches)
    except (CompanyInvariantError, KeyError, TypeError, ValueError) as exc:
        raise WriteReleaseError(f"snapshot reducer validation failed: {exc}") from exc
    return projection.objects


def _verified_snapshot(
    state: CompanyStateOwner,
    cursor: int | None,
) -> CompanyQuerySnapshot:
    """Rebuild a detached prefix from owner-frozen, chain-verified records.

    This is deliberately O(history) observation-only work.  The public API
    never accepts caller-supplied snapshot objects, heads, or replay inputs.
    """
    if type(state) is not CompanyStateOwner:
        _fail("write release requires exact CompanyStateOwner")
    try:
        # Bind the trusted implementation on the exact public owner class.
        # Calling through ``state`` would let a caller shadow this instance
        # attribute and select an older or forged replay input.
        replay = CompanyStateOwner.historical_replay_input(state)
        # ``historical_replay_input`` is class-bound above, but its existing
        # implementation delegates to ``ledger.load_records()``.  Re-read via
        # the exact ledger class and require the frozen replay to bind that
        # verified current record vector and head before projecting it.
        ledger = CompanyStateOwner.ledger.__get__(state, CompanyStateOwner)
        if type(ledger) is not CompanyLedger:
            _fail("write release requires exact CompanyLedger")
        verified_records = CompanyLedger.load_records(ledger)
        verified_heads = CompanyLedger.snapshot_heads(ledger)
        if (
            not isinstance(replay.records, tuple)
            or replay.records != verified_records
            or verified_heads.global_head.global_sequence != len(verified_records)
            or not verified_records
            or verified_heads.global_head.transaction_sha256
            != verified_records[-1].receipt["transaction_sha256"]
        ):
            _fail("write release replay does not bind the verified ledger head")
        head_cursor = len(verified_records)
        requested = head_cursor if cursor is None else cursor
        if (
            not isinstance(requested, int)
            or isinstance(requested, bool)
            or requested < 1
            or requested > head_cursor
        ):
            _fail("write release cursor is unavailable")
        snapshot = CompanyStateOwner.project_historical_replay(replay, requested)
        expected_head_sha256 = verified_records[requested - 1].receipt[
            "transaction_sha256"
        ]
        if (
            snapshot.health.readmodel_head.global_sequence != requested
            or snapshot.health.readmodel_head.transaction_sha256
            != expected_head_sha256
        ):
            _fail("write release projection does not bind the requested cursor")
        return snapshot
    except WriteReleaseError:
        raise
    except (
        AttributeError, CompanyStateError, LedgerError, ReadModelError, OSError, KeyError,
        TypeError, ValueError,
    ) as exc:
        raise WriteReleaseError("write release verified replay is unavailable") from exc


def _of_type(
    objects: Sequence[InvariantObject], contract_type: str,
) -> tuple[InvariantObject, ...]:
    return tuple(item for item in objects if item.contract_type == contract_type)


def _exact(
    objects: Sequence[InvariantObject], contract_type: str, field: str, value: str,
) -> InvariantObject | None:
    matches = [item for item in _of_type(objects, contract_type) if item.payload.get(field) == value]
    if len(matches) > 1:
        _fail(f"snapshot has ambiguous {contract_type} {field}")
    return None if not matches else matches[0]


def _evidence(
    *, intent: Mapping[str, Any], intent_item: InvariantObject, context: _ObservationContext, disposition: ReleaseDisposition,
    reasons: Sequence[str], items: Sequence[InvariantObject],
) -> WriteReleaseObservation:
    refs_value = intent["refs"]
    if not isinstance(refs_value, Sequence) or isinstance(refs_value, (str, bytes, bytearray)):
        _fail("validated WorkWriteIntent refs are unavailable")
    refs = tuple(_freeze(ref) for ref in refs_value if isinstance(ref, Mapping))
    if len(refs) != len(refs_value):
        _fail("validated WorkWriteIntent has malformed refs")
    if not all(isinstance(ref, Mapping) for ref in refs):
        _fail("validated WorkWriteIntent refs cannot be frozen")
    identity = sorted({
        (item.contract_type, item.object_key, item.event_id,
         item.global_sequence, item.payload_sha256)
        for item in (intent_item, *items)
    })
    evidence_ids = tuple(
        f"{kind}:{key}:{event}:{sequence}:{digest}"
        for kind, key, event, sequence, digest in identity
    )
    reason_codes = tuple(sorted(set(reasons)))
    evidence_digest = company_contract_sha256({
        "intent_id": intent["intent_id"], "cursor": context.cursor,
        "head_sha256": context.head_sha256,
        "disposition": disposition, "reasons": list(reason_codes),
        "evidence": [list(entry) for entry in identity],
        "refs_sha256": intent["refs_sha256"],
    })
    return WriteReleaseObservation(
        intent_id=intent["intent_id"], owner_kind=intent["owner_kind"], owner_id=intent["owner_id"],
        disposition=disposition, reason_codes=reason_codes, evidence_ids=evidence_ids,
        evidence_digest=evidence_digest, cursor=context.cursor, head_sha256=context.head_sha256, refs=refs,
    )


def _observation(
    intent: Mapping[str, Any], intent_item: InvariantObject, context: _ObservationContext, disposition: ReleaseDisposition,
    reason: str, *items: InvariantObject,
) -> WriteReleaseObservation:
    return _evidence(intent=intent, intent_item=intent_item, context=context, disposition=disposition,
                     reasons=(reason,), items=items)


def _dispatch(
    intent: Mapping[str, Any], intent_item: InvariantObject, objects: Sequence[InvariantObject],
    snapshot: CompanyQuerySnapshot, context: _ObservationContext,
) -> WriteReleaseObservation:
    owner = _exact(objects, DISPATCH_REQUEST_V1, "dispatch_request_id", intent["owner_id"])
    if owner is None:
        return _observation(intent, intent_item, context, "coverage_unknown", "dispatch_owner_missing")
    dispatch_id = intent["owner_id"]
    shadowed = any(shadow.dispatch_request_id == dispatch_id for shadow in snapshot.uncertain_dispatches)
    operations = [
        item for item in _of_type(objects, PROVIDER_WORKER_OPERATION_V1)
        if item.payload.get("dispatch_request_id") == dispatch_id
        and item.payload.get("state") in {
            "prepared", "effect_pending", "effect_observed", "effect_unknown", "reconcile_required",
        }
    ]
    if shadowed:
        return _observation(intent, intent_item, context, "held", "unresolved_dispatch_shadow", owner)
    if operations:
        return _observation(intent, intent_item, context, "held", "provider_worker_operation_unresolved", owner, *operations)
    state = owner.payload["state"]
    if state == "queued":
        return _observation(intent, intent_item, context, "not_acquired", "dispatch_not_acquired", owner)
    if state in {"admitted", "in_flight", "effect_unknown", "dispatched", "reconcile_required"}:
        return _observation(intent, intent_item, context, "held", "dispatch_may_still_launch", owner)
    if state == "failed_known":
        return _observation(intent, intent_item, context, "coverage_unknown", "failed_dispatch_quiescence_unproven", owner)
    if state == "cancelled":
        # The current projection retains the current revision, not the
        # predecessor.  A cancelled revision alone cannot prove it was never
        # admitted, so W3 deliberately does not infer the requested
        # queued->cancelled special case.
        return _observation(intent, intent_item, context, "coverage_unknown", "cancelled_dispatch_prelaunch_unproven", owner)
    return _observation(intent, intent_item, context, "coverage_unknown", "dispatch_state_unclassified", owner)


def _external_job(
    intent: Mapping[str, Any], intent_item: InvariantObject, objects: Sequence[InvariantObject], context: _ObservationContext,
) -> WriteReleaseObservation:
    job = _exact(objects, EXTERNAL_JOB_V1, "job_id", intent["owner_id"])
    if job is None:
        return _observation(intent, intent_item, context, "coverage_unknown", "external_job_owner_missing")
    state = job.payload["state"]
    if state in {"queued", "running", "unknown", "effect_unknown", "reconcile_required"}:
        return _observation(intent, intent_item, context, "held", "external_job_may_still_write", job)
    if state in {"completed", "failed_known"}:
        return _observation(intent, intent_item, context, "coverage_unknown", "external_job_process_tree_quiescence_unproven", job)
    if state != "aborted":
        return _observation(intent, intent_item, context, "coverage_unknown", "external_job_state_unclassified", job)
    mutation = _exact(objects, MUTATION_INTENT_V1, "intent_id", job.payload["mutation_intent_id"])
    executions = [item for item in _of_type(objects, EXECUTION_NODE_V1)
                  if item.payload.get("job_id") == job.payload["job_id"]]
    receipts = [item for item in _of_type(objects, EXTERNAL_JOB_EFFECT_RECEIPT_V1)
                if item.payload.get("job_id") == job.payload["job_id"]]
    if (
        mutation is None or mutation.payload.get("state") != "aborted"
        or len(executions) != 1 or len(receipts) != 1
        or executions[0].payload.get("engineering_status") != "cancelled"
        or executions[0].payload.get("runtime_status") != "stopped"
        or receipts[0].payload.get("previous_job_state") != "queued"
        or receipts[0].payload.get("observed_job_state") != "aborted"
        or receipts[0].payload.get("reconciliation_id") is not None
        or job.payload.get("external_handle") is not None
        or job.payload.get("process_fingerprint_sha256") is not None
    ):
        return _observation(intent, intent_item, context, "coverage_unknown", "aborted_job_not_proven_unlaunched", job)
    # Even the complete current aborted graph only records a negative outcome.
    # W3 has no typed immutable closure receipt proving that every writer was
    # never launched or is now quiescent, so it is not a release authorization.
    return _observation(intent, intent_item, context, "coverage_unknown", "release_proof_contract_unavailable",
                        job, mutation, executions[0], receipts[0])


def derive_write_release(
    state: CompanyStateOwner,
    intent_id: str,
    *,
    cursor: int | None = None,
) -> WriteReleaseObservation:
    """Derive one result from an owner-verified current or historical cursor."""
    if not isinstance(intent_id, str) or not intent_id:
        _fail("write intent identity is invalid")
    snapshot = _verified_snapshot(state, cursor)
    objects = _snapshot_objects(snapshot)
    context = _ObservationContext(
        cursor=snapshot.health.readmodel_head.global_sequence,
        head_sha256=snapshot.health.readmodel_head.transaction_sha256,
    )
    intent_object = _exact(objects, WORK_WRITE_INTENT_V1, "intent_id", intent_id)
    if intent_object is None:
        _fail("WorkWriteIntent is unavailable")
    try:
        intent = validate_work_write_intent(intent_object.payload)
    except (WriteAdmissionError, KeyError, TypeError, ValueError) as exc:
        raise WriteReleaseError(f"WorkWriteIntent is invalid: {exc}") from exc
    if intent["owner_kind"] == "dispatch_request":
        return _dispatch(intent, intent_object, objects, snapshot, context)
    if intent["owner_kind"] == "external_job":
        return _external_job(intent, intent_object, objects, context)
    return _observation(intent, intent_object, context, "coverage_unknown", "write_owner_kind_unclassified")


__all__ = ["ReleaseDisposition", "WriteReleaseError", "WriteReleaseObservation", "derive_write_release"]
