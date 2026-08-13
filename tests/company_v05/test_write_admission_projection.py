"""W2 staged authority, projection, replay, rebuild, and reopen coverage."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    DISPATCH_REQUEST_V1,
    ZERO_SHA256,
    authority_from_grant,
    company_contract_sha256,
    validate_company_contract,
)
from aoi_orgware.company.readmodel import (
    CompanyReadModel,
    ProjectedObject,
    ReadModelCorruptionError,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)
from aoi_orgware.company.write_admission import (
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
    seal_work_write_intent,
    seal_write_domain_binding,
)
from aoi_orgware.company.write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
    seal_work_write_capability,
    seal_write_admission_enforcement,
)
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_work_definition_registration as registration  # type: ignore[import-not-found]


BINDING = {
    "company_id": "company-1",
    "company_incarnation": 1,
    "lock_domain_generation": 1,
}
OBSERVED = {"state": "known", "reason": "observed"}
ENQUEUED_AT = "2026-07-27T00:02:00Z"
T2 = "2026-07-27T00:04:00Z"
T3 = "2026-07-27T00:05:00Z"
T4 = "2026-07-27T00:06:00Z"
T5 = "2026-07-27T00:07:00Z"
T6 = "2026-07-27T00:08:00Z"
EXPIRY = "2026-07-27T00:30:00Z"


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(member) for key, member in value.items()}
    if isinstance(value, tuple):
        return [_plain(member) for member in value]
    return value


def _canonical(value: Any) -> bytes:
    return canonical_json_bytes(_plain(value))


def _objects(
    supervisor: CompanySupervisor,
    contract_type: str,
) -> tuple[ProjectedObject, ...]:
    return supervisor.objects(contract_type=contract_type)


def _one_object(
    supervisor: CompanySupervisor,
    contract_type: str,
    object_key: str,
) -> ProjectedObject:
    matches = [
        item
        for item in _objects(supervisor, contract_type)
        if item.object_key == object_key
    ]
    assert len(matches) == 1
    return matches[0]


def _supervisor_grant(supervisor: CompanySupervisor) -> dict[str, Any]:
    matches = [
        _plain(item.payload)
        for item in _objects(supervisor, AUTHORITY_GRANT_V1)
        if (
            item.payload["actor_kind"] == "supervisor"
            and item.payload["authority_state"] == "active"
        )
    ]
    assert len(matches) == 1
    # Compatibility contract: deployed v0.5 bootstrap companies have this
    # existing grant.  W2 must not rewrite genesis or require a second grant.
    assert matches[0]["permissions"] == ["company.mutate"]
    return matches[0]


def _request(
    supervisor: CompanySupervisor,
    payloads: list[dict[str, Any]],
    *,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    actor_grant: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return build_company_transaction_request(
        supervisor.heads(),
        authority_from_grant(
            _supervisor_grant(supervisor)
            if actor_grant is None
            else actor_grant
        ),
        transaction_id=transaction_id,
        command_id=command_id,
        events=[
            CompanyEventDraft(
                event_id=f"{transaction_id}-event-{index}",
                event_type="record.upserted",
                recorded_at=recorded_at,
                payload=payload,
                provenance="AOI_verified",
            )
            for index, payload in enumerate(payloads, start=1)
        ],
    )


def _opaque_ref(kind: str, identity: str, namespace: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": kind,
        "namespace": namespace,
        "canonical_identity": identity,
        "filesystem_semantics": "opaque-v1",
    }


def _file_ref() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "file",
        "namespace": "repo",
        "canonical_identity": "src/a.py",
        "filesystem_semantics": "posix-v1",
    }


def _domain(*, created_at: str = T2) -> dict[str, Any]:
    return seal_write_domain_binding({
        "contract_type": WRITE_DOMAIN_BINDING_V1,
        "schema_version": 1,
        **BINDING,
        "binding_id": "write-domain-1",
        "root_namespace": "repo",
        "filesystem_family": "posix-v1",
        "opaque_namespaces": [
            {"kind": "output_namespace", "namespace": "outputs"},
            {"kind": "serialization_key", "namespace": "serial"},
        ],
        "created_at": created_at,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _intent(
    domain: Mapping[str, Any],
    queued: ProjectedObject,
    packet: Mapping[str, Any],
    *,
    intent_id: str = "write-intent-1",
    created_at: str = T3,
) -> dict[str, Any]:
    refs = sorted([
        _file_ref(),
        _opaque_ref("output_namespace", "run-output-1", "outputs"),
        _opaque_ref("serialization_key", "index-update-1", "serial"),
    ], key=canonical_json_bytes)
    queued_payload = _plain(queued.payload)
    return seal_work_write_intent({
        "contract_type": WORK_WRITE_INTENT_V1,
        "schema_version": 1,
        **BINDING,
        "intent_id": intent_id,
        "domain_binding_id": domain["binding_id"],
        "domain_binding_sha256": domain["binding_sha256"],
        "owner_kind": "dispatch_request",
        "owner_id": queued_payload["dispatch_request_id"],
        "owner_generation_id": queued_payload["dispatch_revision_id"],
        "owner_anchor_sha256": company_contract_sha256(queued_payload),
        "reservation_id": queued_payload["reservation_id"],
        "task_id": packet["task_id"],
        "packet_id": packet["packet_id"],
        "packet_sha256": packet["packet_sha256"],
        "authority_scope_sha256": company_contract_sha256(
            packet["authority_scope"],
        ),
        "refs": refs,
        "refs_sha256": canonical_sha256(refs),
        "created_at": created_at,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _capability(
    domain: Mapping[str, Any],
    intent: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    capability_id: str = "write-capability-1",
    issued_at: str = T4,
) -> dict[str, Any]:
    opaque_refs = [
        reference
        for reference in intent["refs"]
        if reference["kind"] in {"output_namespace", "serialization_key"}
    ]
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
        "issuer_grant_id": grant["grant_id"],
        "issuer_grant_sha256": grant["grant_sha256"],
        "issuer_action": "write_capability.issue",
        "owner_kind": intent["owner_kind"],
        "owner_id": intent["owner_id"],
        "owner_generation_id": intent["owner_generation_id"],
        "owner_anchor_sha256": intent["owner_anchor_sha256"],
        "owner_reservation_id": intent["reservation_id"],
        "opaque_refs": opaque_refs,
        "opaque_refs_sha256": canonical_sha256(opaque_refs),
        "issued_at": issued_at,
        "expires_at": EXPIRY,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _gate(
    domain: Mapping[str, Any],
    previous_transaction_sha256: str,
    *,
    activated_at: str = T5,
) -> dict[str, Any]:
    return seal_write_admission_enforcement({
        "contract_type": WRITE_ADMISSION_ENFORCEMENT_V1,
        "schema_version": 1,
        **BINDING,
        "gate_id": "write-admission-v1",
        "mode": "enforced",
        "domain_binding_id": domain["binding_id"],
        "domain_binding_sha256": domain["binding_sha256"],
        "previous_transaction_sha256": previous_transaction_sha256,
        "activated_at": activated_at,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def _registered_queued_dispatch(
    supervisor: CompanySupervisor,
) -> tuple[dict[str, Any], ProjectedObject]:
    task, packet, context, prompt = registration._work_bundle(supervisor)
    registration._register(supervisor, task, packet, context, prompt)
    identity, _, _ = lifecycle._rtl(supervisor)
    supervisor.enqueue_department_dispatch(
        identity["department_id"],
        transaction_id="write-enqueue-transaction-1",
        command_id="write-enqueue-command-1",
        dispatch_request_id="dispatch-1",
        reservation_id="reservation-1",
        task_id=task["task_id"],
        packet_id=packet["packet_id"],
        route_policy_id="route-1",
        requested_role="rtl_lead",
        requested_capability_tier="standard",
        requested_at="2026-07-27T00:01:00Z",
        recorded_at=ENQUEUED_AT,
    )
    return packet, _one_object(
        supervisor,
        DISPATCH_REQUEST_V1,
        "dispatch-1",
    )


def test_w2_contracts_stage_prior_authority_and_survive_replay_reopen(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        packet, queued = _registered_queued_dispatch(supervisor)
        grant = _supervisor_grant(supervisor)
        domain = _domain()
        intent = _intent(domain, queued, packet)
        capability = _capability(domain, intent, grant)

        # Same-transaction publication would let records authorize each other.
        # It must fail before any event is appended.
        invalid_domain = _domain(created_at=T2)
        invalid_intent = _intent(
            invalid_domain,
            queued,
            packet,
            created_at=T2,
        )
        invalid_capability = _capability(
            invalid_domain,
            invalid_intent,
            grant,
            issued_at=T2,
        )
        invalid_gate = _gate(
            invalid_domain,
            supervisor.heads().global_head.transaction_sha256,
            activated_at=T2,
        )
        invalid_bundle = [
            invalid_domain,
            invalid_intent,
            invalid_capability,
            invalid_gate,
        ]
        invalid_before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="prior durable write domain",
        ):
            supervisor.commit(
                _request(
                    supervisor,
                    invalid_bundle,
                    transaction_id="write-self-authorizing-transaction-1",
                    command_id="write-self-authorizing-command-1",
                    recorded_at=T2,
                ),
                recorded_at=T2,
            )
        assert supervisor.heads().global_head.global_sequence == invalid_before

        domain_request = _request(
            supervisor,
            [domain],
            transaction_id="write-domain-transaction-1",
            command_id="write-domain-command-1",
            recorded_at=T2,
        )
        domain_result = supervisor.commit(domain_request, recorded_at=T2)

        intent_request = _request(
            supervisor,
            [intent],
            transaction_id="write-intent-transaction-1",
            command_id="write-intent-command-1",
            recorded_at=T3,
        )
        intent_result = supervisor.commit(intent_request, recorded_at=T3)

        capability_request = _request(
            supervisor,
            [capability],
            transaction_id="write-capability-transaction-1",
            command_id="write-capability-command-1",
            recorded_at=T4,
        )
        capability_result = supervisor.commit(
            capability_request,
            recorded_at=T4,
        )
        capability_replay = supervisor.commit(
            capability_request,
            recorded_at=T4,
        )
        assert not capability_result.idempotent_replay
        assert capability_replay.idempotent_replay
        assert capability_replay.record == capability_result.record

        gate = _gate(
            domain,
            supervisor.heads().global_head.transaction_sha256,
        )
        gate_request = _request(
            supervisor,
            [gate],
            transaction_id="write-gate-transaction-1",
            command_id="write-gate-command-1",
            recorded_at=T5,
        )
        gate_result = supervisor.commit(gate_request, recorded_at=T5)

        streams = {
            event["payload"]["contract_type"]: event["stream"]
            for request in (
                domain_request,
                intent_request,
                capability_request,
                gate_request,
            )
            for event in request["events"]
        }
        assert streams == {
            WRITE_DOMAIN_BINDING_V1: "org",
            WORK_WRITE_INTENT_V1: "execution",
            WORK_WRITE_CAPABILITY_V1: "execution",
            WRITE_ADMISSION_ENFORCEMENT_V1: "org",
        }
        assert [
            result.record.global_sequence
            for result in (
                domain_result,
                intent_result,
                capability_result,
                gate_result,
            )
        ] == sorted({
            domain_result.record.global_sequence,
            intent_result.record.global_sequence,
            capability_result.record.global_sequence,
            gate_result.record.global_sequence,
        })

        supervisor.admit_department_dispatch(
            "dispatch-1",
            transaction_id="write-admit-transaction-1",
            command_id="write-admit-command-1",
            recorded_at=T6,
        )
        admitted = _one_object(
            supervisor,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        )
        admitted_payload = _plain(admitted.payload)
        queued_payload = _plain(queued.payload)
        assert admitted_payload["state"] == "admitted"
        assert admitted_payload["revision"] == 2
        assert intent["owner_generation_id"] == queued_payload[
            "dispatch_revision_id"
        ]
        assert admitted_payload["dispatch_revision_id"] != intent[
            "owner_generation_id"
        ]
        assert admitted_payload["previous_event_id"] == queued.event_id
        assert admitted_payload["previous_payload_sha256"] == (
            company_contract_sha256(queued_payload)
        )

        expected = {
            WRITE_DOMAIN_BINDING_V1: ("write-domain-1", domain),
            WORK_WRITE_INTENT_V1: ("write-intent-1", intent),
            WORK_WRITE_CAPABILITY_V1: ("write-capability-1", capability),
            WRITE_ADMISSION_ENFORCEMENT_V1: ("write-admission-v1", gate),
        }
        for contract_type, (object_key, payload) in expected.items():
            assert _canonical(_one_object(
                supervisor,
                contract_type,
                object_key,
            ).payload) == _canonical(payload)

        expected_sequence = supervisor.heads().global_head.global_sequence
        rebuilt = supervisor._state.rebuild_projection()
        assert rebuilt.global_sequence == expected_sequence
        assert supervisor._state.health().readmodel_head == rebuilt
    finally:
        supervisor.close()

    with CompanySupervisor.open(slot_root) as reopened:
        assert reopened.heads().global_head.global_sequence == expected_sequence
        reopened_dispatch = _one_object(
            reopened,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        )
        assert reopened_dispatch.payload["state"] == "admitted"
        assert reopened_dispatch.payload["revision"] == 2
        for contract_type, (object_key, payload) in expected.items():
            assert _canonical(_one_object(
                reopened,
                contract_type,
                object_key,
            ).payload) == _canonical(payload)


def test_w2_distinct_event_cannot_repeat_or_diverge_append_once_id(
    tmp_path: Path,
) -> None:
    with lifecycle._initialize(tmp_path) as supervisor:
        original = _domain()
        supervisor.commit(
            _request(
                supervisor,
                [original],
                transaction_id="write-domain-transaction-1",
                command_id="write-domain-command-1",
                recorded_at=T2,
            ),
            recorded_at=T2,
        )
        before = supervisor.heads().global_head.global_sequence

        with pytest.raises(
            CompanyStateInvariantError,
            match="immutable write-admission logical ID",
        ):
            supervisor.commit(
                _request(
                    supervisor,
                    [original],
                    transaction_id="write-domain-transaction-reencoded",
                    command_id="write-domain-command-reencoded",
                    recorded_at=T2,
                ),
                recorded_at=T2,
            )
        assert supervisor.heads().global_head.global_sequence == before

        divergent_unsigned = copy.deepcopy(original)
        divergent_unsigned.pop("binding_sha256")
        divergent_unsigned["root_namespace"] = "different-repo-root"
        divergent = seal_write_domain_binding(divergent_unsigned)
        with pytest.raises(
            CompanyStateInvariantError,
            match="immutable write-admission logical ID",
        ):
            supervisor.commit(
                _request(
                    supervisor,
                    [divergent],
                    transaction_id="write-domain-transaction-2",
                    command_id="write-domain-command-2",
                    recorded_at=T2,
                ),
                recorded_at=T2,
            )
        assert supervisor.heads().global_head.global_sequence == before


def test_w2_projection_rejects_a_valid_payload_on_the_wrong_stream() -> None:
    domain = _domain()
    assert validate_company_contract(domain) == domain
    assert ZERO_SHA256 != domain["binding_sha256"]
    with pytest.raises(
        ReadModelCorruptionError,
        match="belongs to org, not execution",
    ):
        CompanyReadModel._payload_identity("execution", domain)
