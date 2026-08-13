"""Real-ledger regressions for W2 write-admission promotion blockers."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    BLOB_REF_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    MUTATION_INTENT_V1,
    authority_from_grant,
    company_contract_sha256,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.write_admission import (
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
    seal_work_write_intent,
    seal_write_domain_binding,
)
from aoi_orgware.company.write_admission_invariants import (
    external_job_reservation_id,
    external_job_write_owner_anchor,
)
from aoi_orgware.company.write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
)
from aoi_orgware.semantic_events import (
    canonical_json_bytes,
    canonical_sha256,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_work_definition_registration as registration  # type: ignore[import-not-found]
import test_write_admission_projection as support  # type: ignore[import-not-found]


def _write_worker_grant(*, issued_at: str) -> dict[str, Any]:
    unsigned = {
        "contract_type": AUTHORITY_GRANT_V1,
        "schema_version": 1,
        **support.BINDING,
        "grant_id": "write-worker-grant-1",
        "actor_id": "write-worker-1",
        "actor_kind": "worker",
        "carrier_id": "carrier-1",
        "chief_epoch": None,
        "term": 1,
        "authority_state": "active",
        "permissions": [
            "company.mutate",
            "policy.change",
            "repo.write",
        ],
        "scope_sha256": company_contract_sha256({
            "scope": "test-direct-write-gate",
        }),
        "issued_at": issued_at,
        "expires_at": support.EXPIRY,
        "provenance": "AOI_verified",
    }
    return {
        **unsigned,
        "grant_sha256": company_contract_sha256(unsigned),
    }


def _chief_job_grant(
    supervisor: CompanySupervisor,
    *,
    scope_sha256: str,
    issued_at: str,
) -> dict[str, Any]:
    term, carrier, _chief_node_id = supervisor._current_chief_context()
    unsigned = {
        "contract_type": AUTHORITY_GRANT_V1,
        "schema_version": 1,
        **support.BINDING,
        "grant_id": "chief-job-grant-1",
        "actor_id": carrier["actor_id"],
        "actor_kind": "chief",
        "carrier_id": carrier["carrier_id"],
        "chief_epoch": term["epoch"],
        "term": term["term"],
        "authority_state": "active",
        "permissions": ["job.start"],
        "scope_sha256": scope_sha256,
        "issued_at": issued_at,
        "expires_at": support.EXPIRY,
        "provenance": "AOI_verified",
    }
    return {
        **unsigned,
        "grant_sha256": company_contract_sha256(unsigned),
    }


def _available_blob(
    supervisor: CompanySupervisor,
    payload: bytes,
    *,
    media_type: str = "application/octet-stream",
) -> dict[str, Any]:
    metadata = supervisor._state.blobs.put(payload)
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": media_type,
        "availability": "available",
    }


def _direct_mutation(
    supervisor: CompanySupervisor,
    grant: Mapping[str, Any],
    command_blob: Mapping[str, Any],
    *,
    intent_id: str,
    mutation_kind: str,
    state: str,
    at: str,
) -> dict[str, Any]:
    uncertain = state in {"effect_unknown", "reconcile_required"}
    unknown = state == "unknown"
    return {
        "contract_type": MUTATION_INTENT_V1,
        "schema_version": 1,
        **support.BINDING,
        "intent_id": intent_id,
        "execution_id": None,
        "mutation_kind": mutation_kind,
        "command_id": f"{intent_id}-command",
        "command_blob": support._plain(command_blob),
        "scope_sha256": grant["scope_sha256"],
        "actor_authority": authority_from_grant(grant),
        "state": state,
        "expected_head_sha256":
            supervisor.heads().global_head.transaction_sha256,
        "created_at": at,
        "updated_at": at,
        "effect_evidence": (
            [support._plain(command_blob)]
            if uncertain
            else []
        ),
        "reconcile_ref": (
            f"reconcile-{intent_id}"
            if uncertain
            else None
        ),
        "observation": (
            {"state": "unknown", "reason": "effect_unreconciled"}
            if uncertain or unknown
            else support.OBSERVED
        ),
    }


def _commit_write_chain(
    supervisor: CompanySupervisor,
    *,
    activate_gate: bool,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    packet, queued = support._registered_queued_dispatch(supervisor)
    grant = support._supervisor_grant(supervisor)
    domain = support._domain()
    intent = support._intent(domain, queued, packet)
    capability = support._capability(domain, intent, grant)
    for payload, label, at in (
        (domain, "domain", support.T2),
        (intent, "intent", support.T3),
        (capability, "capability", support.T4),
    ):
        supervisor.commit(
            support._request(
                supervisor,
                [payload],
                transaction_id=f"regression-{label}-transaction-1",
                command_id=f"regression-{label}-command-1",
                recorded_at=at,
            ),
            recorded_at=at,
        )
    if activate_gate:
        gate = support._gate(
            domain,
            supervisor.heads().global_head.transaction_sha256,
        )
        supervisor.commit(
            support._request(
                supervisor,
                [gate],
                transaction_id="regression-gate-transaction-1",
                command_id="regression-gate-command-1",
                recorded_at=support.T5,
            ),
            recorded_at=support.T5,
        )
    return domain, intent, capability, grant


def _register_dispatch(
    supervisor: CompanySupervisor,
    *,
    read_only: bool,
    created_at: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    task, packet, context, prompt = registration._work_bundle(supervisor)
    if read_only or created_at is not None or expires_at is not None:
        packet = copy.deepcopy(packet)
        if read_only:
            packet["authority_scope"]["write_refs"] = []
        if created_at is not None:
            packet["created_at"] = created_at
        if expires_at is not None:
            packet["expires_at"] = expires_at
        registration._rehash(packet, "packet_sha256")
    registration._register(supervisor, task, packet, context, prompt)
    identity, _, _ = lifecycle._rtl(supervisor)
    supervisor.enqueue_department_dispatch(
        identity["department_id"],
        transaction_id="readonly-enqueue-transaction-1",
        command_id="readonly-enqueue-command-1",
        dispatch_request_id="dispatch-1",
        reservation_id="reservation-1",
        task_id=task["task_id"],
        packet_id=packet["packet_id"],
        route_policy_id="route-1",
        requested_role="rtl_lead",
        requested_capability_tier="standard",
        requested_at="2026-07-27T00:01:00Z",
        recorded_at=support.ENQUEUED_AT,
    )
    return packet


def _activate_empty_gate(
    supervisor: CompanySupervisor,
) -> dict[str, Any]:
    domain = support._domain()
    supervisor.commit(
        support._request(
            supervisor,
            [domain],
            transaction_id="empty-domain-transaction-1",
            command_id="empty-domain-command-1",
            recorded_at=support.T2,
        ),
        recorded_at=support.T2,
    )
    gate = support._gate(
        domain,
        supervisor.heads().global_head.transaction_sha256,
    )
    supervisor.commit(
        support._request(
            supervisor,
            [gate],
            transaction_id="empty-gate-transaction-1",
            command_id="empty-gate-command-1",
            recorded_at=support.T5,
        ),
        recorded_at=support.T5,
    )
    return domain


def test_authority_grant_rewrite_is_zero_append_and_reopen_safe(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        domain, _intent, capability, grant = _commit_write_chain(
            supervisor,
            activate_gate=False,
        )
        before = supervisor.heads().global_head.global_sequence
        for label, candidate in (
            ("exact", grant),
            ("divergent", {
                **{
                    key: value
                    for key, value in grant.items()
                    if key != "grant_sha256"
                },
                "expires_at": "2026-07-28T01:00:00Z",
            }),
        ):
            if label == "divergent":
                candidate = {
                    **candidate,
                    "grant_sha256": company_contract_sha256(candidate),
                }
            with pytest.raises(
                CompanyStateInvariantError,
                match="immutable authority grant logical ID",
            ):
                supervisor.commit(
                    support._request(
                        supervisor,
                        [candidate],
                        transaction_id=f"grant-{label}-transaction-1",
                        command_id=f"grant-{label}-command-1",
                        recorded_at=support.T4,
                    ),
                    recorded_at=support.T4,
                )
            assert supervisor.heads().global_head.global_sequence == before
        gate = support._gate(
            domain,
            supervisor.heads().global_head.transaction_sha256,
        )
        supervisor.commit(
            support._request(
                supervisor,
                [gate],
                transaction_id="grant-next-valid-transaction-1",
                command_id="grant-next-valid-command-1",
                recorded_at=support.T5,
            ),
            recorded_at=support.T5,
        )
        expected_sequence = (
            supervisor.heads().global_head.global_sequence
        )
        assert supervisor._state.rebuild_projection().global_sequence == (
            expected_sequence
        )
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert reopened.heads().global_head.global_sequence == (
            expected_sequence
        )
        assert support._one_object(
            reopened,
            WORK_WRITE_CAPABILITY_V1,
            capability["capability_id"],
        ).payload["issuer_grant_sha256"] == grant["grant_sha256"]


def test_existing_gate_blocks_all_active_direct_repo_write_states(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        _commit_write_chain(supervisor, activate_gate=True)
        write_grant = _write_worker_grant(
            issued_at="2026-07-27T00:07:05Z",
        )
        supervisor.commit(
            support._request(
                supervisor,
                [write_grant],
                transaction_id="direct-write-grant-transaction-1",
                command_id="direct-write-grant-command-1",
                recorded_at="2026-07-27T00:07:05Z",
            ),
            recorded_at="2026-07-27T00:07:05Z",
        )
        command_blob = _available_blob(
            supervisor,
            b'{"operation":"direct-write-probe"}',
        )
        for index, state in enumerate((
            "prepared",
            "admitted",
            "in_flight",
            "effect_unknown",
            "reconcile_required",
            "unknown",
        )):
            mutation = _direct_mutation(
                supervisor,
                write_grant,
                command_blob,
                intent_id=f"blocked-direct-write-{index}",
                mutation_kind="repo.write",
                state=state,
                at="2026-07-27T00:07:10Z",
            )
            before = supervisor.heads().global_head.global_sequence
            with pytest.raises(
                CompanyStateInvariantError,
                match="uncovered current repo.write intent",
            ):
                supervisor.commit(
                    support._request(
                        supervisor,
                        [mutation],
                        transaction_id=(
                            f"blocked-direct-write-transaction-{index}"
                        ),
                        command_id=mutation["command_id"],
                        recorded_at="2026-07-27T00:07:10Z",
                        actor_grant=write_grant,
                    ),
                    recorded_at="2026-07-27T00:07:10Z",
                )
            assert supervisor.heads().global_head.global_sequence == before
        for mutation in (
            _direct_mutation(
                supervisor,
                write_grant,
                command_blob,
                intent_id="terminal-direct-write-1",
                mutation_kind="repo.write",
                state="aborted",
                at="2026-07-27T00:07:20Z",
            ),
            _direct_mutation(
                supervisor,
                write_grant,
                command_blob,
                intent_id="non-write-policy-change-1",
                mutation_kind="policy.change",
                state="prepared",
                at="2026-07-27T00:07:30Z",
            ),
        ):
            supervisor.commit(
                support._request(
                    supervisor,
                    [mutation],
                    transaction_id=f"{mutation['intent_id']}-transaction",
                    command_id=mutation["command_id"],
                    recorded_at=mutation["created_at"],
                    actor_grant=write_grant,
                ),
                recorded_at=mutation["created_at"],
            )
        expected_sequence = (
            supervisor.heads().global_head.global_sequence
        )
        assert supervisor._state.rebuild_projection().global_sequence == (
            expected_sequence
        )
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert reopened.heads().global_head.global_sequence == (
            expected_sequence
        )


@pytest.mark.parametrize("case", [
    "read_only",
    "write_scoped",
    "expired_read_only",
])
def test_gate_classifies_dispatch_from_exact_durable_packet(
    tmp_path: Path,
    case: str,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        _register_dispatch(
            supervisor,
            read_only=case != "write_scoped",
            expires_at=(
                "2026-07-27T00:07:30Z"
                if case == "expired_read_only"
                else None
            ),
        )
        _activate_empty_gate(supervisor)
        before = supervisor.heads().global_head.global_sequence
        if case == "read_only":
            supervisor.admit_department_dispatch(
                "dispatch-1",
                transaction_id="readonly-admit-transaction-1",
                command_id="readonly-admit-command-1",
                recorded_at=support.T6,
            )
            expected_state = "admitted"
        else:
            with pytest.raises(
                CompanyStateInvariantError,
                match=(
                    "expired at admission"
                    if case == "expired_read_only"
                    else "write-scoped DispatchRequest lacks prior"
                ),
            ):
                supervisor.admit_department_dispatch(
                    "dispatch-1",
                    transaction_id="write-missing-intent-transaction-1",
                    command_id="write-missing-intent-command-1",
                    recorded_at=support.T6,
                )
            assert supervisor.heads().global_head.global_sequence == before
            expected_state = "queued"
        current = support._one_object(
            supervisor,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        )
        assert current.payload["state"] == expected_state
        expected_sequence = (
            supervisor.heads().global_head.global_sequence
        )
        assert supervisor._state.rebuild_projection().global_sequence == (
            expected_sequence
        )
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert support._one_object(
            reopened,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        ).payload["state"] == expected_state


def test_second_write_domain_registration_is_zero_append(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        first = support._domain()
        supervisor.commit(
            support._request(
                supervisor,
                [first],
                transaction_id="first-domain-transaction-1",
                command_id="first-domain-command-1",
                recorded_at=support.T2,
            ),
            recorded_at=support.T2,
        )
        second_raw = support._domain(created_at=support.T3)
        second_raw.pop("binding_sha256")
        second_raw["binding_id"] = "write-domain-2"
        second = seal_write_domain_binding(second_raw)
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="exactly one write domain",
        ):
            supervisor.commit(
                support._request(
                    supervisor,
                    [second],
                    transaction_id="second-domain-transaction-1",
                    command_id="second-domain-command-1",
                    recorded_at=support.T3,
                ),
                recorded_at=support.T3,
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.rebuild_projection().global_sequence == before
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert len(reopened.objects(
            contract_type=WRITE_DOMAIN_BINDING_V1,
        )) == 1


def test_external_job_chief_owner_cannot_borrow_an_unrelated_packet(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    try:
        task, packet, context, prompt = registration._work_bundle(
            supervisor,
        )
        registration._register(
            supervisor,
            task,
            packet,
            context,
            prompt,
        )
        owner = next(
            item.payload
            for item in supervisor.objects(
                contract_type=EXECUTION_NODE_V1,
            )
            if (
                item.payload["execution_kind"] == "carrier"
                and item.payload["role"] == "chief"
            )
        )
        assert owner["task_id"] is None
        assert owner["packet_id"] is None
        scope_sha256 = company_contract_sha256(
            packet["authority_scope"],
        )
        job_grant = _chief_job_grant(
            supervisor,
            scope_sha256=scope_sha256,
            issued_at="2026-07-27T00:03:00Z",
        )
        supervisor.commit(
            support._request(
                supervisor,
                [job_grant],
                transaction_id="chief-job-grant-transaction-1",
                command_id="chief-job-grant-command-1",
                recorded_at="2026-07-27T00:03:00Z",
            ),
            recorded_at="2026-07-27T00:03:00Z",
        )
        command_bytes = b'{"tool":"vcs"}'
        command_blob = _available_blob(
            supervisor,
            command_bytes,
            media_type="application/json",
        )
        job_identity = {
            "job_id": "job-chief-lineage-1",
            "owner_execution_id": owner["execution_id"],
            "mutation_intent_id": "job-chief-intent-1",
            "command_id": "job-chief-command-1",
            "command_blob": support._plain(command_blob),
            "scope_sha256": scope_sha256,
            "actor_authority": authority_from_grant(job_grant),
        }
        domain = support._domain()
        refs = sorted([
            support._opaque_ref(
                "output_namespace",
                "chief-job-output-1",
                "outputs",
            ),
        ], key=canonical_json_bytes)
        write_intent = seal_work_write_intent({
            "contract_type": WORK_WRITE_INTENT_V1,
            "schema_version": 1,
            **support.BINDING,
            "intent_id": "chief-job-write-intent-1",
            "domain_binding_id": domain["binding_id"],
            "domain_binding_sha256": domain["binding_sha256"],
            "owner_kind": "external_job",
            "owner_id": job_identity["job_id"],
            "owner_generation_id": job_identity["mutation_intent_id"],
            "owner_anchor_sha256":
                external_job_write_owner_anchor(job_identity),
            "reservation_id": external_job_reservation_id(
                str(job_identity["job_id"]),
                str(job_identity["mutation_intent_id"]),
            ),
            "task_id": packet["task_id"],
            "packet_id": packet["packet_id"],
            "packet_sha256": packet["packet_sha256"],
            "authority_scope_sha256": scope_sha256,
            "refs": refs,
            "refs_sha256": canonical_sha256(refs),
            "created_at": support.T3,
            "provenance": "AOI_verified",
            "observation": support.OBSERVED,
        })
        capability = support._capability(
            domain,
            write_intent,
            support._supervisor_grant(supervisor),
        )
        for payload, label, at in (
            (domain, "chief-domain", support.T2),
            (write_intent, "chief-intent", support.T3),
            (capability, "chief-capability", support.T4),
        ):
            supervisor.commit(
                support._request(
                    supervisor,
                    [payload],
                    transaction_id=f"{label}-transaction-1",
                    command_id=f"{label}-command-1",
                    recorded_at=at,
                ),
                recorded_at=at,
            )
        gate = support._gate(
            domain,
            supervisor.heads().global_head.transaction_sha256,
        )
        supervisor.commit(
            support._request(
                supervisor,
                [gate],
                transaction_id="chief-gate-transaction-1",
                command_id="chief-gate-command-1",
                recorded_at=support.T5,
            ),
            recorded_at=support.T5,
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="ExternalJob lineage",
        ):
            supervisor.queue_external_job(
                str(owner["execution_id"]),
                job_id=str(job_identity["job_id"]),
                job_execution_id="job-chief-execution-1",
                mutation_intent_id=str(
                    job_identity["mutation_intent_id"],
                ),
                command_bytes=command_bytes,
                command_media_type="application/json",
                scope_sha256=scope_sha256,
                display_name="Rejected Chief job",
                objective="Prove packet lineage is fail closed.",
                authority_grant_id=job_grant["grant_id"],
                grant_expires_at=job_grant["expires_at"],
                transaction_id="chief-job-queue-transaction-1",
                command_id=str(job_identity["command_id"]),
                recorded_at=support.T6,
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.rebuild_projection().global_sequence == before
    finally:
        supervisor.close()
