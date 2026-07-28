"""Adversarial W2b admission reducer tests.

The reducer is intentionally called directly: these are protocol-compatible
objects, not an integration test for ledger append or projection plumbing.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable

import pytest

from aoi_orgware.company.invariants import (
    InvariantObject,
    reduce_company_invariants,
)
from aoi_orgware.company.contracts import (
    ALERT_V1,
    AUTHORITY_GRANT_V1,
    COMPANY_EVENT_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    DISPATCH_REQUEST_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    TASK_REVISION_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    ZERO_SHA256,
    authority_from_grant,
    company_contract_sha256,
)
from aoi_orgware.company.write_admission import (
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
    seal_work_write_intent,
    seal_write_domain_binding,
)
from aoi_orgware.company.write_admission_invariants import (
    external_job_reservation_id,
    external_job_write_owner_anchor,
    validate_write_admission_invariants,
)
from aoi_orgware.company.write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
    seal_work_write_capability,
    seal_write_admission_enforcement,
)
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256


H = "a" * 64
H2 = "b" * 64
T0 = "2026-07-29T00:00:00Z"
T1 = "2026-07-29T01:00:00Z"
T2 = "2026-07-29T02:00:00Z"
BINDING = {
    "company_id": "company-1",
    "company_incarnation": 1,
    "lock_domain_generation": 1,
}
OBSERVED = {"state": "known", "reason": "observed"}


@dataclass(frozen=True)
class _Shadow:
    dispatch_request_id: str


def _obj(
    contract_type: str, key: str, payload: dict[str, Any], *, sequence: int = 1,
) -> InvariantObject:
    return InvariantObject(
        contract_type, key, f"{contract_type}-{key}-event", sequence,
        canonical_sha256(payload), payload,
    )


def _ref(kind: str, identity: str, namespace: str = "repo-root") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": kind,
        "namespace": namespace,
        "canonical_identity": identity,
        "filesystem_semantics": (
            "opaque-v1" if kind in {"output_namespace", "serialization_key"}
            else "posix-v1"
        ),
    }


def _domain() -> dict[str, Any]:
    return seal_write_domain_binding({
        "contract_type": WRITE_DOMAIN_BINDING_V1,
        "schema_version": 1,
        **BINDING,
        "binding_id": "write-domain-1",
        "root_namespace": "repo-root",
        "filesystem_family": "posix-v1",
        "opaque_namespaces": [
            {"kind": "output_namespace", "namespace": "outputs"},
            {"kind": "serialization_key", "namespace": "serial"},
        ],
        "created_at": T0,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _second_domain(*, created_at: str = T0) -> dict[str, Any]:
    value = _domain()
    value.pop("binding_sha256")
    value["binding_id"] = "write-domain-2"
    value["created_at"] = created_at
    return seal_write_domain_binding(value)


def _packet(
    *,
    expires_at: str = T2,
    write_refs: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    scope = {
        "write_refs": (
            [
                {"kind": "file", "path": "rtl/a.sv"},
                {"kind": "tree", "path": "docs"},
            ]
            if write_refs is None
            else write_refs
        ),
    }
    return {
        "contract_type": WORK_PACKET_V1,
        **BINDING,
        "packet_id": "packet-1",
        "packet_sha256": H2,
        "task_id": "task-1",
        "task_sha256": "d" * 64,
        "authority_scope": scope,
        "authority_scope_sha256": company_contract_sha256(scope),
        "created_at": T0,
        "expires_at": expires_at,
    }


def _grant(*, expires_at: str = T2) -> dict[str, Any]:
    value = {
        "contract_type": AUTHORITY_GRANT_V1,
        "schema_version": 1,
        **BINDING,
        "grant_id": "grant-1",
        "actor_id": "supervisor-1",
        "actor_kind": "supervisor",
        "carrier_id": None,
        "chief_epoch": None,
        "term": 1,
        "authority_state": "active",
        "permissions": ["company.mutate"],
        "scope_sha256": H,
        "issued_at": T0,
        "expires_at": expires_at,
        "provenance": "AOI_verified",
    }
    return {**value, "grant_sha256": company_contract_sha256(value)}


def _task() -> dict[str, Any]:
    return {"contract_type": TASK_REVISION_V1, **BINDING, "task_id": "task-1", "task_sha256": "d" * 64}


def _dispatch(
    *, state: str = "queued", request_id: str = "dispatch-1", reservation: str = "reservation-1",
    revision: int = 1, packet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected_packet = _packet() if packet is None else packet
    return {
        "contract_type": DISPATCH_REQUEST_V1,
        "dispatch_request_id": request_id,
        "dispatch_revision_id": f"{request_id}-revision-{revision}",
        "reservation_id": reservation,
        "state": state,
        "revision": revision,
        "execution_id": "execution-1",
        "task_id": selected_packet["task_id"],
        "packet_id": selected_packet["packet_id"],
        "packet_sha256": selected_packet["packet_sha256"],
        "scope_sha256": selected_packet["authority_scope_sha256"],
    }


def _external_job(*, state: str = "queued", packet: dict[str, Any] | None = None) -> dict[str, Any]:
    selected_packet = _packet() if packet is None else packet
    return {
        "contract_type": EXTERNAL_JOB_V1,
        "job_id": "job-1",
        "state": state,
        "owner_execution_id": "execution-1",
        "mutation_intent_id": "mutation-1",
        "command_id": "command-1",
        "command_blob": "blob-1",
        "scope_sha256": selected_packet["authority_scope_sha256"],
        "actor_authority": authority_from_grant(_grant()),
    }


def _execution(
    *,
    packet: dict[str, Any] | None = None,
    bound: bool = True,
    task_id: str | None = None,
    packet_id: str | None = None,
) -> dict[str, Any]:
    selected_packet = _packet() if packet is None else packet
    return {
        "contract_type": EXECUTION_NODE_V1,
        "execution_id": "execution-1",
        "task_id": (
            None
            if not bound
            else selected_packet["task_id"]
            if task_id is None
            else task_id
        ),
        "packet_id": (
            None
            if not bound
            else selected_packet["packet_id"]
            if packet_id is None
            else packet_id
        ),
    }


def _mutation(
    *,
    state: str = "prepared",
    mutation_kind: str = "job.start",
) -> dict[str, Any]:
    return {
        "contract_type": MUTATION_INTENT_V1,
        "intent_id": "mutation-1",
        "state": state,
        "mutation_kind": mutation_kind,
        "packet_id": "packet-1",
        "packet_sha256": H2,
        "authority_scope_sha256": "c" * 64,
    }


def _intent(
    domain: dict[str, Any], *, owner_kind: str = "dispatch_request", owner_id: str = "dispatch-1",
    owner_generation: str = "dispatch-1-revision-1", reservation: str = "reservation-1",
    refs: Iterable[dict[str, Any]] | None = None, anchor: str = H, packet: dict[str, Any] | None = None,
    intent_id: str = "write-intent-1", created_at: str = T0,
) -> dict[str, Any]:
    selected_packet = _packet() if packet is None else packet
    selected_refs = sorted(list(refs or [
        _ref("file", "rtl/a.sv"), _ref("output_namespace", "run-1", "outputs"),
    ]), key=canonical_json_bytes)
    return seal_work_write_intent({
        "contract_type": WORK_WRITE_INTENT_V1,
        "schema_version": 1,
        **BINDING,
        "intent_id": intent_id,
        "domain_binding_id": domain["binding_id"],
        "domain_binding_sha256": domain["binding_sha256"],
        "owner_kind": owner_kind,
        "owner_id": owner_id,
        "owner_generation_id": owner_generation,
        "owner_anchor_sha256": anchor,
        "reservation_id": reservation,
        "task_id": "task-1",
        "packet_id": selected_packet["packet_id"],
        "packet_sha256": selected_packet["packet_sha256"],
        "authority_scope_sha256": selected_packet["authority_scope_sha256"],
        "refs": selected_refs,
        "refs_sha256": canonical_sha256(selected_refs),
        "created_at": created_at,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _capability(
    domain: dict[str, Any], intent: dict[str, Any], grant: dict[str, Any], *, expires_at: str = T2,
    opaque_refs: Iterable[dict[str, Any]] | None = None, capability_id: str = "write-capability-1",
) -> dict[str, Any]:
    selected_opaque = sorted(list(
        [_ref("output_namespace", "run-1", "outputs")] if opaque_refs is None else opaque_refs,
    ), key=canonical_json_bytes)
    return seal_work_write_capability({
        "contract_type": WORK_WRITE_CAPABILITY_V1,
        "schema_version": 1,
        **BINDING,
        "capability_id": capability_id,
        "domain_binding_id": domain["binding_id"],
        "domain_binding_sha256": domain["binding_sha256"],
        "task_id": intent["task_id"],
        "packet_id": intent["packet_id"],
        "packet_sha256": intent["packet_sha256"],
        "authority_scope_sha256": intent["authority_scope_sha256"],
        "intent_id": intent["intent_id"],
        "intent_sha256": intent["intent_sha256"],
        "issuer_grant_id": "grant-1",
        "issuer_grant_sha256": grant["grant_sha256"],
        "issuer_action": "write_capability.issue",
        "owner_kind": intent["owner_kind"],
        "owner_id": intent["owner_id"],
        "owner_generation_id": intent["owner_generation_id"],
        "owner_anchor_sha256": intent["owner_anchor_sha256"],
        "owner_reservation_id": intent["reservation_id"],
        "opaque_refs": selected_opaque,
        "opaque_refs_sha256": canonical_sha256(selected_opaque),
        "issued_at": T0,
        "expires_at": expires_at,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _gate(domain: dict[str, Any], *, previous: str = H) -> dict[str, Any]:
    return seal_write_admission_enforcement({
        "contract_type": WRITE_ADMISSION_ENFORCEMENT_V1,
        "schema_version": 1,
        **BINDING,
        "gate_id": "write-admission-v1",
        "mode": "enforced",
        "domain_binding_id": domain["binding_id"],
        "domain_binding_sha256": domain["binding_sha256"],
        "previous_transaction_sha256": previous,
        "activated_at": T0,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _result(dispatch: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract_type": WORK_RESULT_RECEIPT_V1,
        "result_receipt_id": "result-1",
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "dispatch_revision_id": dispatch["dispatch_revision_id"],
        "reservation_id": dispatch["reservation_id"],
        "producer_execution_id": dispatch["execution_id"],
        "packet_id": dispatch["packet_id"],
        "packet_sha256": dispatch["packet_sha256"],
    }


def _request(items: tuple[InvariantObject, ...], *, head: str = H, at: str = T1) -> dict[str, Any]:
    """Build a valid envelope; W2b intentionally sees the projected batch too."""
    grant = _grant()
    authority = authority_from_grant(grant)
    events = [{
        "contract_type": COMPANY_EVENT_V1, "schema_version": 1, **BINDING,
        "transaction_id": "admission-transaction-1", "command_id": "command-1",
        "event_id": item.event_id, "stream": "org", "event_type": "record.upserted",
        "recorded_at": at, "actor_authority": deepcopy(authority), "provenance": "AOI_verified",
        "payload": dict(item.payload), "payload_sha256": company_contract_sha256(item.payload, max_bytes=64 * 1024),
    } for item in items]
    expected = {
        "contract_type": EXPECTED_HEAD_V1, "schema_version": 1, **BINDING,
        "transaction_id": "admission-transaction-1", "command_id": "command-1",
        "stream": "org", "cursor": 0, "event_sha256": ZERO_SHA256,
    }
    transaction_head = {
        "contract_type": EXPECTED_TRANSACTION_HEAD_V1, "schema_version": 1, **BINDING,
        "transaction_id": "admission-transaction-1", "global_sequence": 0 if head == ZERO_SHA256 else 1,
        "transaction_sha256": ZERO_SHA256 if head == ZERO_SHA256 else head, "command_id": "command-1",
    }
    value = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1, "schema_version": 1, **BINDING,
        "transaction_id": "admission-transaction-1", "command_id": "command-1",
        "actor_authority": deepcopy(authority), "expected_transaction_head": transaction_head,
        "expected_heads": [expected], "events": events,
    }
    return {**value, "request_sha256": company_contract_sha256(value)}


def _records(*payloads: dict[str, Any]) -> tuple[InvariantObject, ...]:
    keys = {
        WRITE_DOMAIN_BINDING_V1: "binding_id", WORK_WRITE_INTENT_V1: "intent_id",
        WORK_WRITE_CAPABILITY_V1: "capability_id", WRITE_ADMISSION_ENFORCEMENT_V1: "gate_id",
        AUTHORITY_GRANT_V1: "grant_id", WORK_PACKET_V1: "packet_id",
        DISPATCH_REQUEST_V1: "dispatch_request_id", EXTERNAL_JOB_V1: "job_id",
        MUTATION_INTENT_V1: "intent_id", WORK_RESULT_RECEIPT_V1: "result_receipt_id",
        TASK_REVISION_V1: "task_id", EXECUTION_NODE_V1: "execution_id",
    }
    return tuple(_obj(item["contract_type"], str(item[keys[item["contract_type"]]]), item) for item in payloads)


def _valid_old(*, owner_state: str = "queued", include_gate: bool = True,
               owner_kind: str = "dispatch_request") -> tuple[InvariantObject, ...]:
    domain = _domain()
    packet = _packet()
    grant = _grant()
    if owner_kind == "dispatch_request":
        owner = _dispatch(state=owner_state, packet=packet)
        intent = _intent(domain, anchor=canonical_sha256(owner), packet=packet)
    else:
        owner = _external_job(state=owner_state, packet=packet)
        intent = _intent(domain, owner_kind="external_job", owner_id="job-1",
                         owner_generation="mutation-1",
                         reservation=external_job_reservation_id("job-1", "mutation-1"),
                         anchor=external_job_write_owner_anchor(owner), packet=packet)
    values = [domain, _task(), packet, grant, intent, _capability(domain, intent, grant)]
    if owner_kind == "dispatch_request":
        values.append(owner)
    else:
        values.append(_execution(packet=packet))
    if include_gate:
        values.append(_gate(domain))
    return _records(*values)


def _admit(old: tuple[InvariantObject, ...], *batch: dict[str, Any],
           request: dict[str, Any] | None = None, shadows: tuple[Any, ...] = (),
           receipt_state: str | None = "committed") -> None:
    current = _records(*batch)
    default_request = None if not current else _request(
        current, at=T0 if len(current) == 1
        and current[0].contract_type == WRITE_ADMISSION_ENFORCEMENT_V1 else T1,
    )
    validate_write_admission_invariants(old, current, shadows,
                                        default_request if request is None else request,
                                        receipt_state)


def _raises(old: tuple[InvariantObject, ...], *batch: dict[str, Any],
            request: dict[str, Any] | None = None, shadows: tuple[Any, ...] = (),
            receipt_state: str | None = "committed") -> None:
    with pytest.raises(ValueError):
        _admit(old, *batch, request=request, shadows=shadows, receipt_state=receipt_state)


def test_orphan_capability_and_missing_prior_intent_or_domain_are_rejected() -> None:
    domain = _domain()
    intent = _intent(domain)
    grant = _grant()
    cap = _capability(domain, intent, grant)
    admitted = _dispatch(state="admitted", revision=2)
    _raises(_records(_gate(domain), _packet(), grant, admitted), cap)
    _raises(_records(_gate(domain), _packet(), grant, _dispatch(), intent, cap), admitted)


def test_capability_needs_prior_intent_and_prior_grant_but_domain_alone_is_not_authority() -> None:
    domain = _domain()
    intent = _intent(domain)
    grant = _grant()
    cap = _capability(domain, intent, grant)
    admitted = _dispatch(state="admitted", revision=2)
    _raises(_records(domain, _packet(), grant, _dispatch(), cap, _gate(domain)), admitted)
    _raises(_records(domain, _packet(), _dispatch(), intent, cap, _gate(domain)), admitted)
    _admit(_records(domain))
    _raises(_records(domain, _gate(domain), _packet(), _dispatch()), admitted)


def test_gate_allows_only_packet_proven_read_only_dispatch_without_w2_claim() -> None:
    domain = _domain()
    packet = _packet(write_refs=[])
    queued = _dispatch(packet=packet)
    old = _records(domain, _task(), packet, queued, _gate(domain))

    _admit(
        old,
        _dispatch(
            state="admitted",
            revision=2,
            packet=packet,
        ),
    )


def test_read_only_dispatch_cannot_attach_w2_claim_during_acquisition() -> None:
    domain = _domain()
    packet = _packet(write_refs=[])
    queued = _dispatch(packet=packet)
    intent = _intent(
        domain,
        packet=packet,
        anchor=canonical_sha256(queued),
        refs=[_ref("output_namespace", "run-1", "outputs")],
        created_at=T1,
    )
    admitted = _dispatch(
        state="admitted",
        revision=2,
        packet=packet,
    )
    current = _records(intent, admitted)

    _raises(
        _records(domain, _task(), packet, queued, _gate(domain)),
        intent,
        admitted,
        request=_request(current, at=T1),
    )


def test_external_job_without_prior_intent_is_not_inferred_read_only() -> None:
    domain = _domain()
    packet = _packet(write_refs=[])
    _raises(
        _records(domain, _task(), packet, _gate(domain)),
        _external_job(packet=packet),
        _mutation(state="admitted"),
    )


def test_enforcement_requires_prior_domain_correct_head_and_clean_activation_boundary() -> None:
    domain = _domain()
    _raises(_records(domain), _gate(domain, previous=H2))
    _raises(_records(), _gate(domain))
    _raises(_records(), domain, _gate(domain))
    _admit(_records(domain, _grant()), _gate(domain))


def test_alpha_rejects_second_write_domain_registration() -> None:
    _raises(
        _records(_domain(), _grant()),
        _second_domain(created_at=T1),
    )


@pytest.mark.parametrize("state", [
    "prepared",
    "admitted",
    "in_flight",
    "effect_unknown",
    "reconcile_required",
    "unknown",
])
def test_gate_or_admission_rejects_standalone_repo_write_mutation_as_coverage(state: str) -> None:
    """A scope digest or MutationIntent never replaces the exact W2 chain."""
    domain = _domain()
    mutation = _mutation(state=state, mutation_kind="repo.write")
    _raises(_records(domain), _gate(domain), mutation)
    _raises(_records(domain, _gate(domain)), mutation)
    _raises(
        _records(domain, _gate(domain), _packet(), _dispatch(), mutation),
        _dispatch(state="admitted", revision=2),
    )


def test_exact_prior_chain_is_accepted_but_intent_or_capability_cannot_arrive_with_acquisition() -> None:
    old = _valid_old()
    _admit(old, _dispatch(state="admitted"))
    domain = _domain()
    intent = _intent(domain)
    cap = _capability(domain, intent, _grant())
    base = _records(domain, _task(), _packet(), _grant(), _dispatch(), _gate(domain))
    _raises(base, intent, _dispatch(state="admitted", revision=2))
    _raises(_records(*[deepcopy(item.payload) for item in base], intent), cap,
            _dispatch(state="admitted", revision=2))


def test_native_dispatch_must_match_exact_reservation_and_prior_owner_anchor() -> None:
    old = _valid_old()
    candidate = _dispatch(state="admitted", revision=2)
    candidate["reservation_id"] = "other-reservation"
    _raises(old, candidate)

    # The intent binds the prior queued revision.  A legal adjacent admission
    # necessarily creates a different current revision identity.
    adjacent = _dispatch(state="admitted", revision=2)
    assert (
        adjacent["dispatch_revision_id"]
        != _intent(_domain())["owner_generation_id"]
    )
    _admit(old, adjacent)
    wrong_anchor = list(old)
    intent_index = next(i for i, item in enumerate(wrong_anchor) if item.contract_type == WORK_WRITE_INTENT_V1)
    altered = deepcopy(wrong_anchor[intent_index].payload)
    altered["owner_anchor_sha256"] = H2
    # Keep the test adversarial at the reducer layer: it must not accept an
    # otherwise canonical intent/capability chain with a divergent owner anchor.
    wrong_anchor[intent_index] = _obj(WORK_WRITE_INTENT_V1, "write-intent-1", altered)
    _raises(tuple(wrong_anchor), _dispatch(state="admitted", revision=2))


def test_external_job_uses_derived_reservation_and_immutable_job_anchor() -> None:
    """The prospective intent binds immutable job identity, never a future MI hash."""
    old = _valid_old(owner_kind="external_job")
    job = _external_job()
    _admit(old, job, _mutation(state="admitted"))
    divergent_job = _external_job()
    divergent_job["command_blob"] = "other-blob"
    _raises(old, divergent_job, _mutation(state="admitted"))
    wrong_reservation = list(old)
    intent_index = next(i for i, item in enumerate(wrong_reservation)
                        if item.contract_type == WORK_WRITE_INTENT_V1)
    altered = deepcopy(wrong_reservation[intent_index].payload)
    altered["reservation_id"] = "external-job-not-derived"
    wrong_reservation[intent_index] = _obj(WORK_WRITE_INTENT_V1, "write-intent-1", altered)
    _raises(tuple(wrong_reservation), job, _mutation(state="admitted"))


@pytest.mark.parametrize("owner_execution", [
    _execution(bound=False),
    _execution(task_id="other-task"),
    _execution(packet_id="other-packet"),
])
def test_external_job_requires_exact_owner_execution_packet_lineage(
    owner_execution: dict[str, Any],
) -> None:
    old = list(_valid_old(owner_kind="external_job"))
    execution_index = next(
        index
        for index, item in enumerate(old)
        if item.contract_type == EXECUTION_NODE_V1
    )
    old[execution_index] = _obj(
        EXECUTION_NODE_V1,
        "execution-1",
        owner_execution,
    )
    _raises(
        tuple(old),
        _external_job(),
        _mutation(state="admitted"),
    )


@pytest.mark.parametrize("receipt_state", ["effect_unknown", "reconcile_required"])
def test_uncertain_native_dispatch_is_admitted_only_with_reducer_shadow_coverage(
    receipt_state: str,
) -> None:
    _admit(_valid_old(), _dispatch(state="admitted"), receipt_state=receipt_state)
    domain = _domain()
    _raises(
        _records(domain, _packet(), _dispatch(), _gate(domain)), _dispatch(state="admitted"),
        receipt_state=receipt_state,
    )
    _raises(
        _valid_old(owner_kind="external_job"), _external_job(), _mutation(state="admitted"),
        receipt_state=receipt_state,
    )


def test_capability_grant_and_packet_expiry_are_checked_at_acquisition() -> None:
    domain = _domain()
    packet = _packet(expires_at=T1)
    grant = _grant(expires_at=T1)
    intent = _intent(domain, packet=packet)
    cap = _capability(domain, intent, grant, expires_at=T1)
    old = _records(domain, _task(), packet, grant, _dispatch(packet=packet), intent, cap, _gate(domain))
    current = _records(_dispatch(state="admitted", packet=packet))
    _raises(old, current[0].payload, request=_request(current, at=T1))


def test_opaque_refs_need_exact_capability_and_file_tree_refs_need_packet_subset() -> None:
    domain = _domain()
    intent = _intent(domain, refs=[_ref("file", "rtl/b.sv")])
    cap = _capability(domain, intent, _grant(), opaque_refs=[_ref("output_namespace", "other", "outputs")])
    old = _records(domain, _task(), _packet(), _grant(), _dispatch(), intent, cap, _gate(domain))
    _raises(old, _dispatch(state="admitted", revision=2))


def test_file_only_intent_with_empty_opaque_capability_is_accepted() -> None:
    domain = _domain()
    packet = _packet()
    grant = _grant()
    queued = _dispatch(packet=packet)
    intent = _intent(
        domain, packet=packet, anchor=canonical_sha256(queued), refs=[_ref("file", "rtl/a.sv")],
    )
    capability = _capability(domain, intent, grant, opaque_refs=[])
    old = _records(domain, _task(), packet, grant, queued, intent, capability, _gate(domain))
    _admit(old, _dispatch(state="admitted", revision=2, packet=packet))


def test_one_transaction_cannot_acquire_two_reservations() -> None:
    domain = _domain()
    packet = _packet()
    grant = _grant()
    first_queued = _dispatch(packet=packet)
    first_intent = _intent(domain, packet=packet, anchor=canonical_sha256(first_queued))
    second_queued = _dispatch(request_id="dispatch-2", reservation="reservation-2", packet=packet)
    second_intent = _intent(
        domain, owner_id="dispatch-2", owner_generation="dispatch-2-revision-1",
        reservation="reservation-2", packet=packet, anchor=canonical_sha256(second_queued),
        intent_id="write-intent-2",
    )
    old = _records(
        domain, _task(), packet, grant, first_queued, first_intent,
        _capability(domain, first_intent, grant), second_queued, second_intent,
        _capability(domain, second_intent, grant, capability_id="write-capability-2"), _gate(domain),
    )
    first = _dispatch(state="admitted", request_id="dispatch-1", reservation="reservation-1", revision=2)
    second = _dispatch(state="admitted", request_id="dispatch-2", reservation="reservation-2", revision=1)
    _raises(old, first, second)


def test_candidate_in_unenforced_domain_cannot_piggyback_another_domain_gate() -> None:
    first = _valid_old()
    domain = _second_domain()
    packet = _packet()
    grant = _grant()
    queued = _dispatch(request_id="dispatch-2", reservation="reservation-2", packet=packet)
    intent = _intent(
        domain, owner_id="dispatch-2", owner_generation="dispatch-2-revision-1",
        reservation="reservation-2", packet=packet, anchor=canonical_sha256(queued),
        intent_id="write-intent-2",
    )
    old = first + _records(
        domain, queued, intent, _capability(domain, intent, grant, capability_id="write-capability-2"),
    )
    _raises(old, _dispatch(
        state="admitted", request_id="dispatch-2", reservation="reservation-2", revision=2, packet=packet,
    ))


@pytest.mark.parametrize("held_state", ["admitted", "in_flight", "effect_unknown"])
def test_overlapping_held_dispatches_and_unknown_shadow_block_acquisition(held_state: str) -> None:
    domain = _domain()
    held_owner = _dispatch(state=held_state, request_id="held-dispatch", reservation="held-reservation")
    held_intent = _intent(
        domain, owner_id="held-dispatch", owner_generation="held-dispatch-revision-1",
        reservation="held-reservation", anchor=canonical_sha256(held_owner), intent_id="held-intent",
    )
    held = _valid_old() + _records(held_owner, held_intent)
    _raises(held, _dispatch(state="admitted"))
    queued = _valid_old(owner_state="queued")
    _raises(queued, _dispatch(state="admitted"), shadows=(_Shadow("unresolved-dispatch"),))


def test_dispatched_owner_stays_held_without_exact_runtime_terminal_and_queued_is_desired_only() -> None:
    domain = _domain()
    dispatched = _dispatch(state="dispatched", request_id="dispatched-owner", reservation="dispatched-reservation")
    dispatched_intent = _intent(
        domain, owner_id="dispatched-owner", owner_generation="dispatched-owner-revision-1",
        reservation="dispatched-reservation", anchor=canonical_sha256(dispatched), intent_id="dispatched-intent",
    )
    old = _valid_old() + _records(dispatched, dispatched_intent)
    _raises(old, _dispatch(state="admitted"))
    _raises(old + _records(_result(dispatched)), _dispatch(state="admitted"))
    _admit(
        _valid_old(owner_state="queued"),
        _dispatch(state="admitted", revision=2),
    )


def test_no_gate_preserves_old_behavior() -> None:
    _admit(_records(_dispatch()), _dispatch(state="admitted", revision=2))


@pytest.mark.parametrize("owner", [
    _dispatch(state="in_flight", request_id="uncovered-dispatch"),
    _external_job(state="running"),
])
def test_active_owner_without_durable_intent_is_a_coverage_gap(owner: dict[str, Any]) -> None:
    _raises(_valid_old() + _records(owner), _dispatch(state="admitted", revision=2))


def test_more_than_100k_unrelated_facts_do_not_consume_w2_bound() -> None:
    unrelated: list[InvariantObject] = []
    for index in range(100_001):
        payload = {
            "contract_type": ALERT_V1,
            "schema_version": 1,
            **BINDING,
            "alert_id": f"unrelated-alert-{index}",
            "execution_id": None,
            "severity": "info",
            "state": "open",
            "category": "unrelated-projection-fact",
            "created_at": T0,
            "resolved_at": None,
            "detail_sha256": H,
            "observation": OBSERVED,
        }
        unrelated.append(InvariantObject(
            ALERT_V1,
            payload["alert_id"],
            f"unrelated-alert-event-{index}",
            index + 1,
            company_contract_sha256(payload),
            payload,
        ))
    relevant = _records(_domain())

    projection = reduce_company_invariants(
        (*unrelated, *relevant),
        (),
    )

    assert len(projection.objects) == 100_002
    assert sum(
        item.contract_type == WRITE_DOMAIN_BINDING_V1
        for item in projection.objects
    ) == 1
