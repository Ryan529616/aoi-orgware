"""Pure, bounded W2b reducer checks for durable write admission.

This module deliberately does not change a dispatch or activate an admission
gate.  It only joins already-projected records and rejects an attempted
acquisition whose prior durable authority, packet, owner, or held coverage is
ambiguous.  ``invariants.py`` owns the surrounding transaction reduction.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, NoReturn, cast

from .contracts import (
    AUTHORITY_GRANT_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    TASK_REVISION_V1,
    WORK_PACKET_V1,
    authority_from_grant,
    company_contract_sha256,
    validate_company_transaction_request,
)
from .write_admission import (
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
    WriteAdmissionError,
    evaluate_write_overlap,
    validate_intent_domain_binding,
    validate_work_write_intent,
    validate_write_domain_binding,
)
from .write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
    WriteReservationError,
    validate_work_write_capability,
    validate_write_admission_enforcement,
)
from .write_admission_ownership import (
    ProjectedWriteObject,
    UncertainDispatchShadow,
    WriteOwnershipError,
    acquisition_candidates,
    active_write_coverage,
    classify_acquisition_intent,
    has_current_active_repo_write,
    packet_allows_intent_file_refs,
    require_external_job_packet_lineage,
    validate_claim_cardinality,
)


# Company projections may contain many unrelated durable records.  This bound
# remains finite while accepting the documented 100k-record reducer window.
MAX_OLD_OBJECTS = 100_000
MAX_BATCH_OBJECTS = 256
MAX_SHADOWS = 256
WRITE_ADMISSION_REDUCER_TYPES = frozenset({
    AUTHORITY_GRANT_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    TASK_REVISION_V1,
    WORK_PACKET_V1,
    WRITE_DOMAIN_BINDING_V1,
    WORK_WRITE_INTENT_V1,
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
})


class WriteAdmissionInvariantError(ValueError):
    """A durable write-admission relation is missing, stale, or ambiguous."""


def external_job_reservation_id(job_id: str, mutation_intent_id: str) -> str:
    """Return the bounded stable reservation identity for one future job launch."""
    return "external-job-" + company_contract_sha256({
        "job_id": job_id,
        "mutation_intent_id": mutation_intent_id,
    })


def external_job_write_owner_anchor(job: Mapping[str, Any]) -> str:
    """Hash immutable queue identity without predicting a future transaction head."""
    fields = (
        "job_id", "owner_execution_id", "mutation_intent_id", "command_id",
        "command_blob", "scope_sha256", "actor_authority",
    )
    if any(field not in job for field in fields):
        _fail("ExternalJob immutable write owner identity is incomplete")
    return company_contract_sha256({field: job[field] for field in fields})


def _fail(message: str) -> NoReturn:
    raise WriteAdmissionInvariantError(message)


def _items(value: Any, *, maximum: int, label: str) -> tuple[ProjectedWriteObject, ...]:
    if isinstance(value, Mapping):
        raw: Iterable[Any] = value.values()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        raw = value
    else:
        _fail(f"{label} is invalid")
    result = tuple(raw)
    if len(result) > maximum:
        _fail(f"{label} is too large")
    for item in result:
        if not all(hasattr(item, field) for field in (
            "contract_type", "object_key", "event_id", "global_sequence",
            "payload_sha256", "payload",
        )) or not isinstance(item.contract_type, str) or not isinstance(item.payload, Mapping):
            _fail(f"{label} has an invalid projected object")
    return result


def _shadow_items(value: Any) -> tuple[UncertainDispatchShadow, ...]:
    if isinstance(value, Mapping):
        raw: Iterable[Any] = value.values()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        raw = value
    else:
        _fail("unresolved dispatch shadows are invalid")
    result = tuple(raw)
    if len(result) > MAX_SHADOWS:
        _fail("unresolved dispatch shadows are too large")
    if any(not isinstance(getattr(item, "dispatch_request_id", None), str) for item in result):
        _fail("unresolved dispatch shadow identity is invalid")
    return result


def _time(value: str, label: str) -> datetime:
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise WriteAdmissionInvariantError(f"{label} is invalid") from exc


def _at_or_before(left: str, right: str) -> bool:
    return _time(left, "timestamp") <= _time(right, "timestamp")


def _strictly_before(left: str, right: str) -> bool:
    return _time(left, "timestamp") < _time(right, "timestamp")


def _required_time(
    payload: Mapping[str, Any], field: str, label: str,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        _fail(f"{label}.{field} is invalid")
    _time(value, f"{label}.{field}")
    return value


def _binding_matches(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left.get(field) == right.get(field) for field in (
        "company_id", "company_incarnation", "lock_domain_generation",
    ))


def _exact_one(items: Iterable[ProjectedWriteObject], label: str) -> ProjectedWriteObject:
    values = tuple(items)
    if len(values) != 1:
        _fail(f"{label} is unavailable or ambiguous")
    return values[0]


def _validated_payload(item: ProjectedWriteObject, validator: Any, label: str) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], validator(item.payload))
    except (WriteAdmissionError, WriteReservationError, ValueError) as exc:
        raise WriteAdmissionInvariantError(f"{label} is invalid: {exc}") from exc


def _require_prior_packet_and_task(
    intent: Mapping[str, Any],
    old: Sequence[ProjectedWriteObject],
) -> Mapping[str, Any]:
    packet = _exact_one((item for item in old if item.contract_type == WORK_PACKET_V1
                         and item.payload.get("packet_id") == intent["packet_id"]), "durable WorkPacket")
    task = _exact_one((item for item in old if item.contract_type == TASK_REVISION_V1
                       and item.payload.get("task_id") == intent["task_id"]
                       and item.payload.get("task_sha256") == packet.payload.get("task_sha256")), "durable TaskRevision")
    payload = packet.payload
    scope = payload.get("authority_scope")
    if not isinstance(scope, Mapping):
        _fail("WorkPacket.authority_scope is invalid")
    try:
        file_refs_allowed = packet_allows_intent_file_refs(intent, payload)
    except WriteOwnershipError as exc:
        raise WriteAdmissionInvariantError(
            f"write intent WorkPacket scope is invalid: {exc}"
        ) from exc
    if (
        not _binding_matches(intent, payload)
        or not _binding_matches(task.payload, payload)
        or payload.get("task_id") != intent["task_id"]
        or task.payload.get("task_revision_id") != payload.get("task_revision_id")
        or payload.get("packet_sha256") != intent["packet_sha256"]
        or payload.get("task_sha256") != task.payload.get("task_sha256")
        or intent["authority_scope_sha256"] != company_contract_sha256(scope)
        or not file_refs_allowed
    ):
        _fail("write intent WorkPacket/task/scope relation differs")
    packet_created_at = _required_time(payload, "created_at", "WorkPacket")
    packet_expires_at = _required_time(payload, "expires_at", "WorkPacket")
    intent_created_at = _required_time(
        intent,
        "created_at",
        "WorkWriteIntent",
    )
    if (
        not _at_or_before(packet_created_at, intent_created_at)
        or not _strictly_before(intent_created_at, packet_expires_at)
    ):
        _fail("write intent WorkPacket is unavailable at publication fence")
    return payload


def _require_dispatch_intent_owner(intent: Mapping[str, Any], old: Sequence[ProjectedWriteObject]) -> Mapping[str, Any]:
    owner = _exact_one((item for item in old if item.contract_type == DISPATCH_REQUEST_V1
                        and item.payload.get("dispatch_request_id") == intent["owner_id"]), "prior queued DispatchRequest")
    payload = owner.payload
    if (
        payload.get("state") != "queued"
        or payload.get("dispatch_revision_id") != intent["owner_generation_id"]
        or owner.payload_sha256 != intent["owner_anchor_sha256"]
        or payload.get("reservation_id") != intent["reservation_id"]
        or payload.get("task_id") != intent["task_id"]
        or payload.get("packet_id") != intent["packet_id"]
        or payload.get("scope_sha256") != intent["authority_scope_sha256"]
    ):
        _fail("write intent DispatchRequest owner relation differs")
    return payload


def _require_external_intent_owner(intent: Mapping[str, Any]) -> Mapping[str, Any]:
    # The existing queue genesis creates its job.start MutationIntent atomically.
    # A prospective W2 intent therefore cannot bind that future payload or head.
    if (
        intent["reservation_id"] != external_job_reservation_id(intent["owner_id"], intent["owner_generation_id"])
    ):
        _fail("prospective ExternalJob write intent reservation differs")
    return {}


def _require_intent(
    intent_item: ProjectedWriteObject,
    domain: Mapping[str, Any],
    old: Sequence[ProjectedWriteObject],
    *,
    verify_owner_predecessor: bool = True,
) -> dict[str, Any]:
    intent = _validated_payload(intent_item, validate_work_write_intent, "WorkWriteIntent")
    try:
        normalized, _ = validate_intent_domain_binding(intent, domain)
    except WriteAdmissionError as exc:
        raise WriteAdmissionInvariantError(f"write intent domain relation differs: {exc}") from exc
    if not _at_or_before(
        _required_time(domain, "created_at", "WriteDomainBinding"),
        _required_time(normalized, "created_at", "WorkWriteIntent"),
    ):
        _fail("write intent predates its durable write domain")
    _require_prior_packet_and_task(normalized, old)
    if not verify_owner_predecessor:
        return normalized
    if normalized["owner_kind"] == "dispatch_request":
        _require_dispatch_intent_owner(normalized, old)
    else:
        _require_external_intent_owner(normalized)
    return normalized


def _validate_durable_intents(old: Sequence[ProjectedWriteObject]) -> None:
    for item in old:
        if item.contract_type != WORK_WRITE_INTENT_V1:
            continue
        intent = _validated_payload(
            item, validate_work_write_intent, "durable WorkWriteIntent",
        )
        domain_item = _exact_one((
            candidate for candidate in old
            if candidate.contract_type == WRITE_DOMAIN_BINDING_V1
            and candidate.payload.get("binding_id")
            == intent["domain_binding_id"]
        ), "durable write intent domain")
        _require_intent(
            item,
            _validated_payload(
                domain_item, validate_write_domain_binding,
                "durable WriteDomainBinding",
            ),
            old,
            verify_owner_predecessor=False,
        )


def _opaque_refs(intent: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [ref for ref in intent["refs"] if ref["kind"] in {"output_namespace", "serialization_key"}]


def _request_fence(request: Mapping[str, Any], event_id: str) -> str:
    events = request["events"]
    wrapper = next((event for event in events if event["event_id"] == event_id), None)
    if wrapper is None:
        _fail("write admission projection lacks its event envelope")
    return str(wrapper["recorded_at"])


def _require_capability(
    item: ProjectedWriteObject,
    domain: Mapping[str, Any],
    old: Sequence[ProjectedWriteObject],
    request: Mapping[str, Any] | None,
    *,
    verify_intent_owner_predecessor: bool = True,
) -> dict[str, Any]:
    capability = _validated_payload(item, validate_work_write_capability, "WorkWriteCapability")
    intent_item = _exact_one((candidate for candidate in old
                              if candidate.contract_type == WORK_WRITE_INTENT_V1
                              and candidate.payload.get("intent_id") == capability["intent_id"]), "prior WorkWriteIntent")
    if intent_item.payload.get("intent_sha256") != capability["intent_sha256"]:
        _fail("write capability durable intent differs")
    joined_intent = _require_intent(
        intent_item, domain, old,
        verify_owner_predecessor=verify_intent_owner_predecessor,
    )
    packet_item = _exact_one(
        (
            candidate
            for candidate in old
            if (
                candidate.contract_type == WORK_PACKET_V1
                and candidate.payload.get("packet_id")
                == capability["packet_id"]
            )
        ),
        "durable WorkPacket",
    )
    exact_fields = (
        "company_id", "company_incarnation", "lock_domain_generation", "domain_binding_id",
        "domain_binding_sha256", "task_id", "packet_id", "packet_sha256",
        "authority_scope_sha256", "intent_id", "intent_sha256", "owner_kind", "owner_id",
        "owner_generation_id", "owner_anchor_sha256",
    )
    if (
        any(capability[field] != joined_intent[field] for field in exact_fields)
        or capability["owner_reservation_id"] != joined_intent["reservation_id"]
        or capability["opaque_refs"] != _opaque_refs(joined_intent)
    ):
        _fail("write capability intent relation differs")
    grant_item = _exact_one((candidate for candidate in old
                             if candidate.contract_type == AUTHORITY_GRANT_V1
                             and candidate.payload.get("grant_id") == capability["issuer_grant_id"]), "prior supervisor AuthorityGrant")
    grant = grant_item.payload
    try:
        request_authority = None if request is None else request["actor_authority"]
        derived = authority_from_grant(grant)
    except ValueError as exc:
        raise WriteAdmissionInvariantError(f"write capability grant is invalid: {exc}") from exc
    if (
        grant.get("grant_sha256") != capability["issuer_grant_sha256"]
        or grant.get("actor_kind") != "supervisor"
        or grant.get("authority_state") != "active"
        or grant.get("provenance") != "AOI_verified"
        # Alpha compatibility: existing company genesis grants expose only
        # ``company.mutate``.  ``issuer_action`` remains an exact audit label;
        # W2 does not silently manufacture a new durable permission.
        or "company.mutate" not in set(grant.get("permissions", []))
        or not _binding_matches(grant, capability)
        or request_authority is not None and request_authority != derived
    ):
        _fail("write capability issuer authority differs")
    fence = capability["issued_at"] if request is None else _request_fence(request, item.event_id)
    if (
        request is not None and fence != capability["issued_at"]
        or not _at_or_before(joined_intent["created_at"], fence)
        or not _at_or_before(
            _required_time(packet_item.payload, "created_at", "WorkPacket"),
            fence,
        )
        or not _strictly_before(
            fence,
            _required_time(packet_item.payload, "expires_at", "WorkPacket"),
        )
        or not _at_or_before(grant["issued_at"], fence)
        or grant.get("expires_at") is None
        or not _strictly_before(fence, grant["expires_at"])
        or not _at_or_before(capability["issued_at"], capability["expires_at"])
        or not _at_or_before(capability["expires_at"], grant["expires_at"])
        or not _strictly_before(fence, capability["expires_at"])
    ):
        _fail("write capability fence time differs")
    return capability


def _require_capability_grant_at_fence(
    capability: Mapping[str, Any], old: Sequence[ProjectedWriteObject], fence: str,
) -> None:
    """Ensure the capability's immutable issuing authority remains valid at launch."""
    grant_item = _exact_one((candidate for candidate in old
                             if candidate.contract_type == AUTHORITY_GRANT_V1
                             and candidate.payload.get("grant_id") == capability["issuer_grant_id"]),
                            "prior supervisor AuthorityGrant")
    grant = grant_item.payload
    if (
        grant.get("grant_sha256") != capability["issuer_grant_sha256"]
        or grant.get("actor_kind") != "supervisor"
        or grant.get("authority_state") != "active"
        or grant.get("provenance") != "AOI_verified"
        or "company.mutate" not in set(grant.get("permissions", []))
        or not _binding_matches(grant, capability)
        or grant.get("expires_at") is None
        or not _at_or_before(str(grant["issued_at"]), fence)
        or not _strictly_before(fence, str(grant["expires_at"]))
    ):
        _fail("write acquisition issuer authority is unavailable at fence")


def _request_supervisor_grant(
    request: Mapping[str, Any], old: Sequence[ProjectedWriteObject], fence: str,
) -> Mapping[str, Any]:
    matching: list[Mapping[str, Any]] = []
    for item in old:
        if item.contract_type != AUTHORITY_GRANT_V1:
            continue
        try:
            grant_authority = authority_from_grant(item.payload)
        except ValueError as exc:
            raise WriteAdmissionInvariantError(f"durable supervisor grant is invalid: {exc}") from exc
        if grant_authority == request["actor_authority"]:
            matching.append(item.payload)
    if len(matching) != 1:
        _fail("prior supervisor AuthorityGrant is unavailable or ambiguous")
    grant = matching[0]
    if (
        grant.get("actor_kind") != "supervisor"
        or grant.get("authority_state") != "active"
        or grant.get("provenance") != "AOI_verified"
        or "company.mutate" not in set(grant.get("permissions", []))
        or grant.get("expires_at") is None
        or not _at_or_before(str(grant["issued_at"]), fence)
        or not _strictly_before(fence, str(grant["expires_at"]))
    ):
        _fail("request supervisor authority is unavailable at fence")
    return grant


def _gate_for_domain(old: Sequence[ProjectedWriteObject], domain: Mapping[str, Any]) -> ProjectedWriteObject | None:
    gates = [item for item in old if item.contract_type == WRITE_ADMISSION_ENFORCEMENT_V1
             and item.payload.get("domain_binding_id") == domain["binding_id"]]
    if len(gates) > 1:
        _fail("write admission enforcement is duplicated")
    if not gates:
        return None
    gate = _validated_payload(gates[0], validate_write_admission_enforcement, "durable WriteAdmissionEnforcement")
    if (
        not _binding_matches(gate, domain)
        or gate["domain_binding_sha256"] != domain["binding_sha256"]
        or not _at_or_before(
            _required_time(domain, "created_at", "WriteDomainBinding"),
            _required_time(gate, "activated_at", "WriteAdmissionEnforcement"),
        )
    ):
        _fail("write admission enforcement domain differs")
    return gates[0]


def _validate_new_enforcement(
    old: Sequence[ProjectedWriteObject], batch: Sequence[ProjectedWriteObject],
    shadows: Sequence[UncertainDispatchShadow], request: Mapping[str, Any] | None,
    receipt_state: str | None,
) -> None:
    new = [item for item in batch if item.contract_type == WRITE_ADMISSION_ENFORCEMENT_V1]
    if not new:
        return
    if len(new) != 1 or len(batch) != 1 or request is None or len(request["events"]) != 1 or receipt_state != "committed":
        _fail("write admission enforcement must be one clean committed event")
    gate = _validated_payload(new[0], validate_write_admission_enforcement, "WriteAdmissionEnforcement")
    domain_item = _exact_one((item for item in old if item.contract_type == WRITE_DOMAIN_BINDING_V1
                              and item.payload.get("binding_id") == gate["domain_binding_id"]), "prior durable write domain")
    domain = _validated_payload(domain_item, validate_write_domain_binding, "durable WriteDomainBinding")
    if (
        gate["domain_binding_sha256"] != domain["binding_sha256"]
        or gate["previous_transaction_sha256"] != request["expected_transaction_head"]["transaction_sha256"]
        or gate["activated_at"] != _request_fence(request, new[0].event_id)
        or not _at_or_before(domain["created_at"], gate["activated_at"])
        or _gate_for_domain(old, domain) is not None
    ):
        _fail("write admission enforcement predecessor differs")
    _request_supervisor_grant(request, old, gate["activated_at"])
    try:
        held, gaps = active_write_coverage(old, shadows)
    except WriteOwnershipError as exc:
        raise WriteAdmissionInvariantError(
            f"write admission owner coverage is invalid: {exc}"
        ) from exc
    if held or gaps:
        _fail("write admission enforcement requires no active or uncertain owners")


def validate_write_admission_invariants(
    old_objects: Sequence[ProjectedWriteObject] | Mapping[Any, ProjectedWriteObject],
    batch: Sequence[ProjectedWriteObject] | Mapping[Any, ProjectedWriteObject],
    shadows: Sequence[UncertainDispatchShadow] | Mapping[Any, UncertainDispatchShadow],
    request: Mapping[str, Any] | None,
    receipt_state: str | None,
) -> None:
    """Validate bounded W2b durable write-admission joins without side effects."""
    old = _items(old_objects, maximum=MAX_OLD_OBJECTS, label="old write projection")
    current = _items(batch, maximum=MAX_BATCH_OBJECTS, label="write transaction batch")
    unresolved = _shadow_items(shadows)
    if receipt_state is not None and receipt_state not in {
        "committed", "effect_unknown", "reconcile_required", "failed_known", "aborted",
    }:
        _fail("write admission receipt state is invalid")
    normalized_request: Mapping[str, Any] | None = None
    if request is not None:
        try:
            normalized_request = validate_company_transaction_request(request)
        except ValueError as exc:
            raise WriteAdmissionInvariantError(f"write admission request is invalid: {exc}") from exc

    all_records = (*old, *current)
    domains: dict[str, Mapping[str, Any]] = {}
    domain: Mapping[str, Any]
    for item in all_records:
        if item.contract_type != WRITE_DOMAIN_BINDING_V1:
            continue
        domain = _validated_payload(item, validate_write_domain_binding, "WriteDomainBinding")
        previous = domains.setdefault(domain["binding_id"], domain)
        if previous != domain:
            _fail("write domain binding identity is divergent")
    if len(domains) > 1:
        _fail("alpha write admission supports exactly one write domain")
    try:
        validate_claim_cardinality(old, current)
    except WriteOwnershipError as exc:
        raise WriteAdmissionInvariantError(
            f"write claim cardinality is invalid: {exc}"
        ) from exc

    # A newly published intent cannot borrow a same-transaction domain or owner.
    for item in current:
        if item.contract_type != WORK_WRITE_INTENT_V1:
            continue
        if normalized_request is None or receipt_state != "committed":
            _fail("WorkWriteIntent publication must commit with a transaction request")
        intent = _validated_payload(item, validate_work_write_intent, "WorkWriteIntent")
        if intent["created_at"] != _request_fence(normalized_request, item.event_id):
            _fail("WorkWriteIntent publication fence differs")
        domain_item = _exact_one((candidate for candidate in old if candidate.contract_type == WRITE_DOMAIN_BINDING_V1
                                  and candidate.payload.get("binding_id") == intent["domain_binding_id"]), "prior durable write domain")
        domain = _validated_payload(domain_item, validate_write_domain_binding, "durable WriteDomainBinding")
        _require_intent(item, domain, old)

    for item in current:
        if item.contract_type != WRITE_DOMAIN_BINDING_V1:
            continue
        if normalized_request is None or receipt_state != "committed":
            _fail("write domain registration must commit with a transaction request")
        registered_domain = _validated_payload(item, validate_write_domain_binding, "WriteDomainBinding")
        fence = _request_fence(normalized_request, item.event_id)
        if registered_domain["created_at"] != fence:
            _fail("write domain registration fence differs")
        _request_supervisor_grant(normalized_request, old, fence)

    _validate_durable_intents(old)

    for records, issuance_request, verify_predecessor in (
        (old, None, False),
        (current, normalized_request, True),
    ):
        for item in records:
            if item.contract_type != WORK_WRITE_CAPABILITY_V1:
                continue
            publication_fence: str | None = None
            if verify_predecessor:
                if normalized_request is None or receipt_state != "committed":
                    _fail("WorkWriteCapability publication must commit with a transaction request")
                publication_fence = _request_fence(normalized_request, item.event_id)
            capability = _validated_payload(item, validate_work_write_capability, "WorkWriteCapability")
            if publication_fence is not None and capability["issued_at"] != publication_fence:
                _fail("WorkWriteCapability publication fence differs")
            domain_item = _exact_one((candidate for candidate in old if candidate.contract_type == WRITE_DOMAIN_BINDING_V1
                                      and candidate.payload.get("binding_id") == capability["domain_binding_id"]), "prior durable write domain")
            domain = _validated_payload(domain_item, validate_write_domain_binding, "durable WriteDomainBinding")
            _require_capability(
                item, domain, old, issuance_request,
                verify_intent_owner_predecessor=verify_predecessor,
            )

    _validate_new_enforcement(old, current, unresolved, normalized_request, receipt_state)

    for item in old:
        if item.contract_type != WRITE_ADMISSION_ENFORCEMENT_V1:
            continue
        gate = _validated_payload(item, validate_write_admission_enforcement, "durable WriteAdmissionEnforcement")
        domain_item = _exact_one((candidate for candidate in old if candidate.contract_type == WRITE_DOMAIN_BINDING_V1
                                  and candidate.payload.get("binding_id") == gate["domain_binding_id"]), "durable gate write domain")
        _gate_for_domain(old, _validated_payload(domain_item, validate_write_domain_binding, "durable WriteDomainBinding"))

    # Existing gates turn a queued->admitted owner transition into one exact
    # acquisition.  Both intent and capability must have committed earlier.
    has_enforced_domain = any(
        _gate_for_domain(old, domain) is not None
        for domain in domains.values()
    )
    # W2 does not yet define a direct repo.write capability path.  Once any
    # durable gate is active, a standalone active MutationIntent must fail
    # before append even when no dispatch/job acquisition shares its batch.
    if has_enforced_domain and has_current_active_repo_write(current):
        _fail("write admission has uncovered current repo.write intent")
    try:
        candidates = (
            acquisition_candidates(old, current)
            if has_enforced_domain
            else []
        )
    except WriteOwnershipError as exc:
        raise WriteAdmissionInvariantError(
            f"write acquisition ownership is invalid: {exc}"
        ) from exc
    if candidates and (
        normalized_request is None
        or receipt_state not in {
            "committed",
            "effect_unknown",
            "reconcile_required",
        }
    ):
        _fail("write acquisition receipt state is invalid")
    acquisitions: list[
        tuple[str, ProjectedWriteObject, ProjectedWriteObject]
    ] = []
    for kind, current_owner in candidates:
        if normalized_request is None:
            _fail("write acquisition request is unavailable")
        try:
            intent_item = classify_acquisition_intent(
                old,
                current,
                kind,
                current_owner,
                admission_at=_request_fence(
                    normalized_request,
                    current_owner.event_id,
                ),
            )
        except WriteOwnershipError as exc:
            raise WriteAdmissionInvariantError(
                f"write acquisition ownership is invalid: {exc}"
            ) from exc
        if intent_item is not None:
            acquisitions.append((kind, current_owner, intent_item))
    if len(acquisitions) > 1:
        _fail("write admission transaction has more than one acquisition")
    if not acquisitions:
        return
    if normalized_request is None or receipt_state not in {
        "committed", "effect_unknown", "reconcile_required",
    }:
        _fail("write acquisition receipt state is invalid")
    kind, current_owner, intent_item = acquisitions[0]
    if kind == "external_job" and receipt_state != "committed":
        _fail("ambiguous ExternalJob acquisition has no durable shadow coverage")
    intent = _validated_payload(intent_item, validate_work_write_intent, "prior WorkWriteIntent")
    domain_item = _exact_one((item for item in old if item.contract_type == WRITE_DOMAIN_BINDING_V1
                              and item.payload.get("binding_id") == intent["domain_binding_id"]), "prior durable write domain")
    domain = _validated_payload(domain_item, validate_write_domain_binding, "durable WriteDomainBinding")
    _require_intent(intent_item, domain, old)
    if _gate_for_domain(old, domain) is None:
        _fail("write acquisition domain is not the active enforced domain")
    if kind == "dispatch_request":
        if (
            current_owner.payload.get("reservation_id") != intent["reservation_id"]
            or current_owner.payload.get("task_id") != intent["task_id"]
            or current_owner.payload.get("packet_id") != intent["packet_id"]
            or current_owner.payload.get("scope_sha256") != intent["authority_scope_sha256"]
        ):
            _fail("write acquisition DispatchRequest owner differs")
    else:
        mutation = _exact_one((item for item in current if item.contract_type == MUTATION_INTENT_V1
                               and item.payload.get("intent_id") == current_owner.payload.get("mutation_intent_id")),
                              "queued ExternalJob MutationIntent")
        if (
            mutation.payload.get("state") != "admitted"
            or intent["owner_generation_id"] != mutation.payload.get("intent_id")
            or intent["owner_anchor_sha256"] != external_job_write_owner_anchor(current_owner.payload)
            or intent["reservation_id"] != external_job_reservation_id(
                str(current_owner.payload.get("job_id")), str(mutation.payload.get("intent_id")),
            )
            or intent["authority_scope_sha256"] != current_owner.payload.get("scope_sha256")
        ):
            _fail("write acquisition ExternalJob owner differs")
        try:
            require_external_job_packet_lineage(
                intent,
                current_owner.payload,
                old,
            )
        except WriteOwnershipError as exc:
            raise WriteAdmissionInvariantError(
                f"write acquisition ExternalJob lineage is invalid: {exc}"
            ) from exc
    capability_item = _exact_one((item for item in old if item.contract_type == WORK_WRITE_CAPABILITY_V1
                                  and item.payload.get("intent_id") == intent["intent_id"]), "prior WorkWriteCapability")
    capability = _require_capability(capability_item, domain, old, None)
    fence = _request_fence(normalized_request, current_owner.event_id)
    packet = _require_prior_packet_and_task(intent, old)
    if (
        not _at_or_before(
            _required_time(packet, "created_at", "WorkPacket"),
            fence,
        )
        or not _strictly_before(
            fence,
            _required_time(packet, "expires_at", "WorkPacket"),
        )
        or not _at_or_before(capability["issued_at"], fence)
        or not _strictly_before(fence, capability["expires_at"])
    ):
        _fail("write acquisition fence exceeds packet or capability")
    _require_capability_grant_at_fence(capability, old, fence)
    try:
        held, gaps = active_write_coverage(old, unresolved)
    except WriteOwnershipError as exc:
        raise WriteAdmissionInvariantError(
            f"write acquisition owner coverage is invalid: {exc}"
        ) from exc
    try:
        evaluation = evaluate_write_overlap(intent, held, domain=domain, coverage_gaps=gaps)
    except WriteAdmissionError as exc:
        raise WriteAdmissionInvariantError(f"write acquisition overlap is invalid: {exc}") from exc
    if evaluation.overlap_status != "overlap_clear" or evaluation.idempotent_replay:
        _fail("write acquisition overlaps held or uncertain write coverage")


def validate_relevant_write_admission_invariants(
    old_objects: Sequence[Any],
    batch: Sequence[Any],
    shadows: Sequence[Any],
    request: Mapping[str, Any] | None,
    receipt_state: str | None,
) -> None:
    """Filter unrelated company facts before applying the bounded W2 reducer."""
    validate_write_admission_invariants(
        cast(Sequence[ProjectedWriteObject], tuple(
            item
            for item in old_objects
            if item.contract_type in WRITE_ADMISSION_REDUCER_TYPES
        )),
        cast(Sequence[ProjectedWriteObject], tuple(
            item
            for item in batch
            if item.contract_type in WRITE_ADMISSION_REDUCER_TYPES
        )),
        cast(Sequence[UncertainDispatchShadow], shadows),
        request,
        receipt_state,
    )


__all__ = [
    "MAX_BATCH_OBJECTS",
    "MAX_OLD_OBJECTS",
    "MAX_SHADOWS",
    "WRITE_ADMISSION_REDUCER_TYPES",
    "ProjectedWriteObject",
    "UncertainDispatchShadow",
    "WriteAdmissionInvariantError",
    "external_job_reservation_id",
    "external_job_write_owner_anchor",
    "validate_relevant_write_admission_invariants",
    "validate_write_admission_invariants",
]
