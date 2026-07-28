"""Public-ledger regressions for W2 publication cardinality and time fences."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    DISPATCH_REQUEST_V1,
    WORK_PACKET_V1,
    authority_from_grant,
    company_contract_sha256,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.write_admission import WORK_WRITE_INTENT_V1
from aoi_orgware.company.write_admission_invariants import (
    WriteAdmissionInvariantError,
    validate_write_admission_invariants,
)
from aoi_orgware.company.write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
)
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_write_admission_gate_regressions as gates  # type: ignore[import-not-found]
import test_write_admission_invariants as unit  # type: ignore[import-not-found]
import test_write_admission_projection as support  # type: ignore[import-not-found]


GRANT_EXPIRY = "2026-07-27T00:07:30Z"


def _initialize(
    tmp_path: Path,
    *,
    grant_expires_at: str = lifecycle.EXPIRY,
) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        lifecycle._manifest(),
        bootstrap_at=lifecycle.T,
        grant_expires_at=grant_expires_at,
        known_carrier=lifecycle._known_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )


def _actor_grant(
    supervisor: CompanySupervisor,
    actor_kind: str,
) -> dict[str, Any]:
    matches = [
        support._plain(item.payload)
        for item in supervisor.objects(contract_type=AUTHORITY_GRANT_V1)
        if (
            item.payload["actor_kind"] == actor_kind
            and item.payload["authority_state"] == "active"
        )
    ]
    assert len(matches) == 1
    return matches[0]


def _commit(
    supervisor: CompanySupervisor,
    payloads: list[dict[str, Any]],
    *,
    label: str,
    at: str,
    actor_grant: Mapping[str, Any] | None = None,
) -> None:
    supervisor.commit(
        support._request(
            supervisor,
            payloads,
            transaction_id=f"{label}-transaction-1",
            command_id=f"{label}-command-1",
            recorded_at=at,
            actor_grant=actor_grant,
        ),
        recorded_at=at,
    )


def test_distinct_write_claims_are_zero_append_and_original_chain_admits(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        domain, intent, capability, grant = gates._commit_write_chain(
            supervisor,
            activate_gate=False,
        )
        packet = support._plain(support._one_object(
            supervisor,
            WORK_PACKET_V1,
            intent["packet_id"],
        ).payload)
        queued = support._one_object(
            supervisor,
            DISPATCH_REQUEST_V1,
            intent["owner_id"],
        )
        intents = [
            support._intent(
                domain,
                queued,
                packet,
                intent_id=f"write-intent-{index}",
                created_at=support.T5,
            )
            for index in (2, 3)
        ]
        capabilities = [
            support._capability(
                domain,
                intent,
                grant,
                capability_id=f"write-capability-{index}",
                issued_at=support.T5,
            )
            for index in (2, 3)
        ]
        attempts = (
            ("second-intent", intents[:1]),
            ("batch-intent", intents),
            ("second-capability", capabilities[:1]),
            ("batch-capability", capabilities),
        )
        for label, payloads in attempts:
            before = supervisor.heads().global_head.global_sequence
            with pytest.raises(
                CompanyStateInvariantError,
                match="write claim cardinality",
            ):
                _commit(
                    supervisor,
                    payloads,
                    label=label,
                    at=support.T5,
                )
            assert supervisor.heads().global_head.global_sequence == before

        gate = support._gate(
            domain,
            supervisor.heads().global_head.transaction_sha256,
        )
        _commit(supervisor, [gate], label="original-gate", at=support.T5)
        supervisor.admit_department_dispatch(
            intent["owner_id"],
            transaction_id="original-admit-transaction-1",
            command_id="original-admit-command-1",
            recorded_at=support.T6,
        )
        expected = supervisor.heads().global_head.global_sequence
        assert supervisor._state.rebuild_projection().global_sequence == expected
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert support._one_object(
            reopened,
            DISPATCH_REQUEST_V1,
            intent["owner_id"],
        ).payload["state"] == "admitted"
        assert len(reopened.objects(contract_type=WORK_WRITE_INTENT_V1)) == 1
        assert len(reopened.objects(
            contract_type=WORK_WRITE_CAPABILITY_V1,
        )) == 1


@pytest.mark.parametrize("actor_kind", ["supervisor", "chief"])
@pytest.mark.parametrize(
    ("fence", "accepted"),
    [
        (lifecycle.T, True),
        ("2026-07-27T00:07:29Z", True),
        (GRANT_EXPIRY, False),
    ],
)
def test_transaction_authority_uses_half_open_event_fence(
    tmp_path: Path,
    actor_kind: str,
    fence: str,
    accepted: bool,
) -> None:
    supervisor = _initialize(tmp_path, grant_expires_at=GRANT_EXPIRY)
    slot_root = supervisor.slot_root
    actor_grant = _actor_grant(supervisor, actor_kind)
    assert actor_grant["issued_at"] == lifecycle.T
    assert actor_grant["expires_at"] == GRANT_EXPIRY
    worker_grant = gates._write_worker_grant(issued_at=fence)
    before = supervisor.heads().global_head.global_sequence
    try:
        if accepted:
            _commit(
                supervisor,
                [worker_grant],
                label=f"{actor_kind}-valid-grant-fence",
                at=fence,
                actor_grant=actor_grant,
            )
            assert supervisor.heads().global_head.global_sequence == before + 1
        else:
            with pytest.raises(
                CompanyStateInvariantError,
                match="grant is unavailable at event fence",
            ):
                _commit(
                    supervisor,
                    [worker_grant],
                    label=f"{actor_kind}-expired-grant-fence",
                    at=fence,
                    actor_grant=actor_grant,
                )
            assert supervisor.heads().global_head.global_sequence == before
        expected = supervisor.heads().global_head.global_sequence
        assert supervisor._state.rebuild_projection().global_sequence == expected
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert len([
            item
            for item in reopened.objects(contract_type=AUTHORITY_GRANT_V1)
            if item.object_key == worker_grant["grant_id"]
        ]) == int(accepted)


def test_every_transaction_event_must_fit_the_authority_window(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path, grant_expires_at=GRANT_EXPIRY)
    slot_root = supervisor.slot_root
    actor_grant = _actor_grant(supervisor, "supervisor")
    first = gates._write_worker_grant(
        issued_at="2026-07-27T00:07:29Z",
    )
    second_unsigned = {
        **{
            key: value
            for key, value in first.items()
            if key != "grant_sha256"
        },
        "grant_id": "write-worker-grant-2",
        "issued_at": GRANT_EXPIRY,
    }
    second = {
        **second_unsigned,
        "grant_sha256": company_contract_sha256(second_unsigned),
    }
    request = build_company_transaction_request(
        supervisor.heads(),
        authority_from_grant(actor_grant),
        transaction_id="mixed-authority-window-transaction-1",
        command_id="mixed-authority-window-command-1",
        events=[
            CompanyEventDraft(
                event_id="mixed-authority-window-event-1",
                event_type="record.upserted",
                recorded_at="2026-07-27T00:07:29Z",
                payload=first,
            ),
            CompanyEventDraft(
                event_id="mixed-authority-window-event-2",
                event_type="record.upserted",
                recorded_at=GRANT_EXPIRY,
                payload=second,
            ),
        ],
    )
    before = supervisor.heads().global_head.global_sequence
    try:
        with pytest.raises(
            CompanyStateInvariantError,
            match="grant is unavailable at event fence",
        ):
            supervisor.commit(request, recorded_at=GRANT_EXPIRY)
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.rebuild_projection().global_sequence == before
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert not [
            item
            for item in reopened.objects(contract_type=AUTHORITY_GRANT_V1)
            if item.object_key in {
                first["grant_id"],
                second["grant_id"],
            }
        ]


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("created_at", "WorkPacket.created_at is invalid"),
        ("authority_scope", "dispatch no-write authority scope is invalid"),
    ],
)
def test_missing_packet_fields_are_typed_fail_closed(
    missing: str,
    message: str,
) -> None:
    domain = unit._domain()
    packet = unit._packet(write_refs=[])
    packet.pop(missing)
    queued = unit._dispatch(packet=packet)
    old = unit._records(
        domain,
        unit._task(),
        packet,
        queued,
        unit._gate(domain),
    )
    with pytest.raises(
        WriteAdmissionInvariantError,
        match=message,
    ):
        unit._admit(
            old,
            unit._dispatch(
                state="admitted",
                revision=2,
                packet=packet,
            ),
        )


def test_replay_revalidates_durable_intent_and_gate_chronology() -> None:
    domain = unit._domain()
    packet = unit._packet(expires_at=unit.T1)
    intent = unit._intent(domain, packet=packet, created_at=unit.T2)
    with pytest.raises(
        WriteAdmissionInvariantError,
        match="WorkPacket is unavailable at publication fence",
    ):
        validate_write_admission_invariants(
            unit._records(
                domain,
                unit._task(),
                packet,
                unit._dispatch(packet=packet),
                intent,
            ),
            (),
            (),
            None,
            None,
        )

    future_domain = unit._second_domain(created_at=unit.T1)
    with pytest.raises(
        WriteAdmissionInvariantError,
        match="enforcement domain differs",
    ):
        validate_write_admission_invariants(
            unit._records(future_domain, unit._gate(future_domain)),
            (),
            (),
            None,
            None,
        )


@pytest.mark.parametrize(
    ("created_at", "packet_created_at", "packet_expires_at", "message"),
    [
        (
            "2026-07-27T00:03:00Z",
            None,
            None,
            "predates its durable write domain",
        ),
        (
            support.T3,
            None,
            "2026-07-27T00:04:30Z",
            "WorkPacket is unavailable at publication fence",
        ),
        (
            support.T3,
            "2026-07-27T00:10:00Z",
            None,
            "WorkPacket is unavailable at publication fence",
        ),
    ],
)
def test_intent_publication_rejects_backdated_or_unavailable_lineage(
    tmp_path: Path,
    created_at: str,
    packet_created_at: str | None,
    packet_expires_at: str | None,
    message: str,
) -> None:
    supervisor = _initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        packet = gates._register_dispatch(
            supervisor,
            read_only=False,
            created_at=packet_created_at,
            expires_at=packet_expires_at,
        )
        queued = support._one_object(
            supervisor,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        )
        domain = support._domain()
        _commit(supervisor, [domain], label="intent-domain", at=support.T2)
        intent = support._intent(
            domain,
            queued,
            packet,
            created_at=created_at,
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanyStateInvariantError, match=message):
            _commit(
                supervisor,
                [intent],
                label="invalid-intent-time",
                at=created_at,
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.rebuild_projection().global_sequence == before
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert not reopened.objects(contract_type=WORK_WRITE_INTENT_V1)


@pytest.mark.parametrize(
    ("issued_at", "packet_expires_at"),
    [
        ("2026-07-27T00:04:30Z", None),
        (support.T4, "2026-07-27T00:05:30Z"),
    ],
)
def test_capability_publication_rechecks_intent_and_packet_time(
    tmp_path: Path,
    issued_at: str,
    packet_expires_at: str | None,
) -> None:
    supervisor = _initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        packet = gates._register_dispatch(
            supervisor,
            read_only=False,
            expires_at=packet_expires_at,
        )
        queued = support._one_object(
            supervisor,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        )
        domain = support._domain()
        _commit(supervisor, [domain], label="capability-domain", at=support.T2)
        intent = support._intent(domain, queued, packet)
        _commit(supervisor, [intent], label="capability-intent", at=support.T3)
        capability = support._capability(
            domain,
            intent,
            support._supervisor_grant(supervisor),
            issued_at=issued_at,
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="write capability fence time differs",
        ):
            _commit(
                supervisor,
                [capability],
                label="invalid-capability-time",
                at=issued_at,
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.rebuild_projection().global_sequence == before
    finally:
        supervisor.close()
    with CompanySupervisor.open(slot_root) as reopened:
        assert len(reopened.objects(contract_type=WORK_WRITE_INTENT_V1)) == 1
        assert not reopened.objects(contract_type=WORK_WRITE_CAPABILITY_V1)


def test_gate_and_read_only_admission_reject_backdated_or_future_state(
    tmp_path: Path,
) -> None:
    gate_supervisor = _initialize(tmp_path / "gate")
    gate_slot = gate_supervisor.slot_root
    try:
        domain = support._domain()
        _commit(gate_supervisor, [domain], label="gate-domain", at=support.T2)
        gate = support._gate(
            domain,
            gate_supervisor.heads().global_head.transaction_sha256,
            activated_at="2026-07-27T00:03:00Z",
        )
        before = gate_supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="enforcement predecessor differs",
        ):
            _commit(
                gate_supervisor,
                [gate],
                label="backdated-gate",
                at="2026-07-27T00:03:00Z",
            )
        assert gate_supervisor.heads().global_head.global_sequence == before
    finally:
        gate_supervisor.close()
    with CompanySupervisor.open(gate_slot) as reopened:
        assert not reopened.objects(
            contract_type=WRITE_ADMISSION_ENFORCEMENT_V1,
        )

    dispatch_supervisor = _initialize(tmp_path / "dispatch")
    dispatch_slot = dispatch_supervisor.slot_root
    try:
        gates._register_dispatch(
            dispatch_supervisor,
            read_only=True,
            created_at="2026-07-27T00:10:00Z",
        )
        gates._activate_empty_gate(dispatch_supervisor)
        before = dispatch_supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="not yet valid at admission",
        ):
            dispatch_supervisor.admit_department_dispatch(
                "dispatch-1",
                transaction_id="future-readonly-admit-transaction-1",
                command_id="future-readonly-admit-command-1",
                recorded_at=support.T6,
            )
        assert dispatch_supervisor.heads().global_head.global_sequence == before
        assert (
            dispatch_supervisor._state.rebuild_projection().global_sequence
            == before
        )
    finally:
        dispatch_supervisor.close()
    with CompanySupervisor.open(dispatch_slot) as reopened:
        assert support._one_object(
            reopened,
            DISPATCH_REQUEST_V1,
            "dispatch-1",
        ).payload["state"] == "queued"
