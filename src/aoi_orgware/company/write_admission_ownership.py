"""Bounded owner classification for the W2 write-admission reducer.

This module answers only three questions:

* which owner transitions are potential write acquisitions;
* whether an intent-less dispatch is provably read-only from its exact packet;
* which prior owner claims remain held or have incomplete coverage.

It does not validate capabilities, mutate projections, or activate a gate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, NoReturn, Protocol

from .contracts import (
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    WORK_PACKET_V1,
    company_contract_sha256,
)
from .write_admission import (
    WORK_WRITE_INTENT_V1,
    WriteAdmissionError,
    WriteCoverageGapV1,
    validate_work_write_intent,
)
from .write_reservation import WORK_WRITE_CAPABILITY_V1


class ProjectedWriteObject(Protocol):
    """The structural projection surface required by W2."""

    contract_type: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str
    payload: Mapping[str, Any]


class UncertainDispatchShadow(Protocol):
    """The unresolved-dispatch surface retained outside the read model."""

    dispatch_request_id: str


class WriteOwnershipError(ValueError):
    """Owner write scope, lineage, or claim cardinality is not trustworthy."""


def _fail(message: str) -> NoReturn:
    raise WriteOwnershipError(message)


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        _fail(f"{label} is invalid")
    try:
        return datetime.fromisoformat(
            value[:-1] + "+00:00"
            if value.endswith("Z")
            else value
        )
    except ValueError as exc:
        raise WriteOwnershipError(f"{label} is invalid") from exc


def _latest(
    items: Sequence[ProjectedWriteObject],
    contract_type: str,
    id_field: str,
) -> dict[str, ProjectedWriteObject]:
    result: dict[str, ProjectedWriteObject] = {}
    for item in items:
        if item.contract_type != contract_type:
            continue
        identity = item.payload.get(id_field)
        if not isinstance(identity, str):
            _fail(f"{contract_type} identity is invalid")
        previous = result.get(identity)
        if (
            previous is not None
            and previous.global_sequence == item.global_sequence
        ):
            _fail(f"{contract_type} identity is ambiguous")
        if (
            previous is None
            or previous.global_sequence < item.global_sequence
        ):
            result[identity] = item
    return result


def _exact_one(
    items: Sequence[ProjectedWriteObject],
    label: str,
) -> ProjectedWriteObject:
    if len(items) != 1:
        _fail(f"{label} is unavailable or ambiguous")
    return items[0]


def dispatch_packet_has_write_refs(
    old: Sequence[ProjectedWriteObject],
    owner: Mapping[str, Any],
    *,
    admission_at: str | None = None,
) -> bool:
    """Classify a dispatch only from its exact prior durable WorkPacket."""
    packet_id = owner.get("packet_id")
    if not isinstance(packet_id, str):
        _fail("dispatch no-write packet identity is unavailable")
    packet_item = _exact_one([
        item
        for item in old
        if (
            item.contract_type == WORK_PACKET_V1
            and item.payload.get("packet_id") == packet_id
        )
    ], "durable no-write WorkPacket")
    packet = packet_item.payload
    authority_scope = packet.get("authority_scope")
    if not isinstance(authority_scope, Mapping):
        _fail("dispatch no-write authority scope is invalid")
    write_refs = authority_scope.get("write_refs")
    if (
        not isinstance(write_refs, Sequence)
        or isinstance(write_refs, (str, bytes, bytearray))
        or packet.get("task_id") != owner.get("task_id")
        or company_contract_sha256(authority_scope)
        != owner.get("scope_sha256")
    ):
        _fail("dispatch no-write WorkPacket relation differs")
    if admission_at is not None:
        fence = _time(admission_at, "dispatch admission fence")
        if fence < _time(packet.get("created_at"), "WorkPacket.created_at"):
            _fail("dispatch no-write WorkPacket is not yet valid at admission")
        if _time(packet.get("expires_at"), "WorkPacket.expires_at") <= fence:
            _fail("dispatch no-write WorkPacket expired at admission")
    return bool(write_refs)


def packet_allows_intent_file_refs(
    intent: Mapping[str, Any],
    packet: Mapping[str, Any],
) -> bool:
    """Check typed intent file/tree refs against one packet write scope."""
    scope = packet.get("authority_scope")
    refs = intent.get("refs")
    if not isinstance(scope, Mapping):
        _fail("WorkPacket.authority_scope is invalid")
    allowed = scope.get("write_refs")
    if (
        not isinstance(allowed, Sequence)
        or isinstance(allowed, (str, bytes, bytearray))
        or not isinstance(refs, Sequence)
        or isinstance(refs, (str, bytes, bytearray))
    ):
        _fail("write intent or packet refs are invalid")
    for reference in refs:
        if not isinstance(reference, Mapping):
            _fail("write intent ref is invalid")
        kind = reference.get("kind")
        if kind not in {"file", "tree"}:
            continue
        identity = reference.get("canonical_identity")
        semantics = reference.get("filesystem_semantics")
        if not isinstance(identity, str) or not isinstance(semantics, str):
            _fail("write intent file ref is invalid")
        candidate = identity if semantics == "posix-v1" else identity.casefold()
        covered = False
        for ceiling in allowed:
            if (
                not isinstance(ceiling, Mapping)
                or ceiling.get("kind") not in {"file", "tree"}
                or not isinstance(ceiling.get("path"), str)
            ):
                _fail("WorkPacket write ref is invalid")
            path = str(ceiling["path"])
            if semantics != "posix-v1":
                path = path.casefold()
            covered = (
                kind == "file" and ceiling["kind"] == "file"
                and candidate == path
            ) or (
                ceiling["kind"] == "tree"
                and (candidate == path or candidate.startswith(path + "/"))
            )
            if covered:
                break
        if not covered:
            return False
    return True


def require_external_job_packet_lineage(
    intent: Mapping[str, Any],
    job: Mapping[str, Any],
    old: Sequence[ProjectedWriteObject],
) -> None:
    """Bind an effectful job to the exact packet of its prior owner execution.

    V1 has no typed Chief-management exception.  A carrier/Chief execution
    whose task or packet is null therefore fails closed until a later contract
    introduces explicit management authority.
    """
    owner_execution_id = job.get("owner_execution_id")
    if not isinstance(owner_execution_id, str):
        _fail("ExternalJob owner execution identity is unavailable")
    execution = _exact_one([
        item
        for item in old
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload.get("execution_id") == owner_execution_id
        )
    ], "prior ExternalJob owner ExecutionNode")
    if (
        execution.payload.get("task_id") != intent.get("task_id")
        or execution.payload.get("packet_id") != intent.get("packet_id")
        or intent.get("authority_scope_sha256") != job.get("scope_sha256")
    ):
        _fail("ExternalJob owner packet lineage differs")


def acquisition_candidates(
    old: Sequence[ProjectedWriteObject],
    batch: Sequence[ProjectedWriteObject],
) -> list[tuple[str, ProjectedWriteObject]]:
    """Return owner transitions that cross the write-admission fence."""
    result: list[tuple[str, ProjectedWriteObject]] = []
    old_dispatches = _latest(
        old,
        DISPATCH_REQUEST_V1,
        "dispatch_request_id",
    )
    for current in batch:
        if (
            current.contract_type != DISPATCH_REQUEST_V1
            or current.payload.get("state") != "admitted"
        ):
            continue
        dispatch_request_id = current.payload.get("dispatch_request_id")
        if not isinstance(dispatch_request_id, str):
            _fail("write acquisition DispatchRequest identity is invalid")
        previous = old_dispatches.get(dispatch_request_id)
        if (
            previous is not None
            and previous.payload.get("state") == "queued"
        ):
            result.append(("dispatch_request", current))
    for job in batch:
        if (
            job.contract_type != EXTERNAL_JOB_V1
            or job.payload.get("state") != "queued"
        ):
            continue
        mutation = next((
            item
            for item in batch
            if (
                item.contract_type == MUTATION_INTENT_V1
                and item.payload.get("intent_id")
                == job.payload.get("mutation_intent_id")
            )
        ), None)
        if (
            mutation is not None
            and mutation.payload.get("state") == "admitted"
        ):
            result.append(("external_job", job))
    return result


def has_current_active_repo_write(
    batch: Sequence[ProjectedWriteObject],
) -> bool:
    """Return whether the transaction introduces an uncovered direct write."""
    return any(
        item.contract_type == MUTATION_INTENT_V1
        and item.payload.get("mutation_kind") == "repo.write"
        and item.payload.get("state") in {
            "prepared",
            "admitted",
            "in_flight",
            "effect_unknown",
            "reconcile_required",
            "unknown",
        }
        for item in batch
    )


def classify_acquisition_intent(
    old: Sequence[ProjectedWriteObject],
    current: Sequence[ProjectedWriteObject],
    kind: str,
    owner: ProjectedWriteObject,
    *,
    admission_at: str,
) -> ProjectedWriteObject | None:
    """Return the prior write intent, or ``None`` for a proven read-only dispatch."""
    owner_id = (
        owner.payload.get("dispatch_request_id")
        if kind == "dispatch_request"
        else owner.payload.get("job_id")
    )
    if not isinstance(owner_id, str):
        _fail("write acquisition owner is invalid")
    prior_intents = [
        item
        for item in old
        if (
            item.contract_type == WORK_WRITE_INTENT_V1
            and item.payload.get("owner_kind") == kind
            and item.payload.get("owner_id") == owner_id
        )
    ]
    current_intents = [
        item
        for item in current
        if (
            item.contract_type == WORK_WRITE_INTENT_V1
            and item.payload.get("owner_kind") == kind
            and item.payload.get("owner_id") == owner_id
        )
    ]
    current_capabilities = [
        item
        for item in current
        if (
            item.contract_type == WORK_WRITE_CAPABILITY_V1
            and item.payload.get("owner_kind") == kind
            and item.payload.get("owner_id") == owner_id
        )
    ]
    if current_intents or current_capabilities:
        _fail("write acquisition intent and capability must be prior durable")
    if len(prior_intents) > 1:
        _fail("prior WorkWriteIntent for acquisition is ambiguous")
    if prior_intents:
        return prior_intents[0]
    if kind == "dispatch_request":
        if dispatch_packet_has_write_refs(
            old,
            owner.payload,
            admission_at=admission_at,
        ):
            _fail("write-scoped DispatchRequest lacks prior WorkWriteIntent")
        return None
    # ExternalJob is an effectful launch and V1 has no typed no-write proof.
    _fail("ExternalJob acquisition requires prior WorkWriteIntent")


def validate_claim_cardinality(
    old: Sequence[ProjectedWriteObject],
    current: Sequence[ProjectedWriteObject],
) -> None:
    """Enforce alpha's immutable one-intent/one-capability owner relation."""
    intent_owners: set[tuple[str, str]] = set()
    capability_intents: set[str] = set()
    capability_owners: set[tuple[str, str]] = set()
    for item in (*old, *current):
        if item.contract_type == WORK_WRITE_INTENT_V1:
            owner_kind = item.payload.get("owner_kind")
            owner_id = item.payload.get("owner_id")
            if not isinstance(owner_kind, str) or not isinstance(owner_id, str):
                _fail("WorkWriteIntent owner identity is invalid")
            owner = (owner_kind, owner_id)
            if owner in intent_owners:
                _fail("WorkWriteIntent owner already has an immutable claim")
            intent_owners.add(owner)
        elif item.contract_type == WORK_WRITE_CAPABILITY_V1:
            intent_id = item.payload.get("intent_id")
            owner_kind = item.payload.get("owner_kind")
            owner_id = item.payload.get("owner_id")
            if (
                not isinstance(intent_id, str)
                or not isinstance(owner_kind, str)
                or not isinstance(owner_id, str)
            ):
                _fail("WorkWriteCapability claim identity is invalid")
            owner = (owner_kind, owner_id)
            if intent_id in capability_intents:
                _fail(
                    "WorkWriteCapability intent already has an immutable "
                    "capability"
                )
            if owner in capability_owners:
                _fail(
                    "WorkWriteCapability owner already has an immutable "
                    "capability"
                )
            capability_intents.add(intent_id)
            capability_owners.add(owner)


def active_write_coverage(
    old: Sequence[ProjectedWriteObject],
    shadows: Sequence[UncertainDispatchShadow],
) -> tuple[list[Mapping[str, Any]], list[WriteCoverageGapV1]]:
    """Return held write claims and fail-closed active-owner coverage gaps."""
    dispatches = _latest(
        old,
        DISPATCH_REQUEST_V1,
        "dispatch_request_id",
    )
    jobs = _latest(old, EXTERNAL_JOB_V1, "job_id")
    held: list[Mapping[str, Any]] = []
    gaps: list[WriteCoverageGapV1] = []
    claims: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for item in old:
        if item.contract_type != WORK_WRITE_INTENT_V1:
            continue
        try:
            intent = validate_work_write_intent(item.payload)
        except WriteAdmissionError as exc:
            raise WriteOwnershipError(
                f"durable WorkWriteIntent is invalid: {exc}"
            ) from exc
        claims.setdefault(
            (intent["owner_kind"], intent["owner_id"]),
            [],
        ).append(intent)
    for owner_id, owner in dispatches.items():
        if owner.payload.get("state") not in {
            "admitted",
            "in_flight",
            "effect_unknown",
            "dispatched",
        }:
            continue
        owner_claims = claims.get(("dispatch_request", owner_id), [])
        if not owner_claims:
            try:
                has_write_scope = dispatch_packet_has_write_refs(
                    old,
                    owner.payload,
                )
            except WriteOwnershipError:
                gaps.append(WriteCoverageGapV1(
                    "dispatch_request",
                    owner_id,
                    "active_owner_state_unknown",
                ))
                continue
            if not has_write_scope:
                continue
            gaps.append(WriteCoverageGapV1(
                "dispatch_request",
                owner_id,
                "legacy_active_owner_missing_intent",
            ))
            continue
        if len(owner_claims) != 1:
            gaps.append(WriteCoverageGapV1(
                "dispatch_request",
                owner_id,
                "active_owner_state_unknown",
            ))
            continue
        held.append(owner_claims[0])
    for owner_id, owner in jobs.items():
        if owner.payload.get("state") not in {
            "queued",
            "running",
            "effect_unknown",
            "reconcile_required",
            "unknown",
        }:
            continue
        owner_claims = claims.get(("external_job", owner_id), [])
        if len(owner_claims) != 1:
            gaps.append(WriteCoverageGapV1(
                "external_job",
                owner_id,
                (
                    "legacy_active_owner_missing_intent"
                    if not owner_claims
                    else "active_owner_state_unknown"
                ),
            ))
            continue
        try:
            require_external_job_packet_lineage(
                owner_claims[0],
                owner.payload,
                old,
            )
        except WriteOwnershipError:
            gaps.append(WriteCoverageGapV1(
                "external_job",
                owner_id,
                "active_owner_state_unknown",
            ))
            continue
        held.append(owner_claims[0])
    for shadow in shadows:
        gaps.append(WriteCoverageGapV1(
            "dispatch_request",
            shadow.dispatch_request_id,
            "active_owner_state_unknown",
        ))
    for item in old:
        if (
            item.contract_type == MUTATION_INTENT_V1
            and item.payload.get("mutation_kind") == "repo.write"
            and item.payload.get("state") in {
                "prepared",
                "admitted",
                "in_flight",
                "effect_unknown",
                "reconcile_required",
                "unknown",
            }
        ):
            gaps.append(WriteCoverageGapV1(
                "external_job",
                str(item.payload.get(
                    "intent_id",
                    "unknown-write-owner",
                )),
                "active_owner_state_unknown",
            ))
    return held, gaps


__all__ = [
    "ProjectedWriteObject",
    "UncertainDispatchShadow",
    "WriteOwnershipError",
    "acquisition_candidates",
    "active_write_coverage",
    "classify_acquisition_intent",
    "dispatch_packet_has_write_refs",
    "has_current_active_repo_write",
    "packet_allows_intent_file_refs",
    "require_external_job_packet_lineage",
    "validate_claim_cardinality",
]
