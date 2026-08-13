from __future__ import annotations

import copy
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    BLOB_REF_V1,
    COMPANY_EVENT_V1,
    COMPANY_MANIFEST_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    DISPATCH_REQUEST_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    ORGANIZATION_NODE_V1,
    ZERO_SHA256,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import LedgerConflictError
from aoi_orgware.company.process_lock import (
    CompanyProcessLockBusyError,
    CompanyProcessLockOwnershipError,
)
from aoi_orgware.company.readmodel import ReadModelCorruptionError
from aoi_orgware.company.state import (
    CompanyStateClosedError,
    CompanyStateInvariantError,
    CompanyStateOwner,
)
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)


H = "a" * 64
T = "2026-07-27T00:00:00Z"


def manifest() -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": H,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def authority() -> dict[str, Any]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "actor_id": "supervisor-1",
        "actor_kind": "supervisor",
        "carrier_id": None,
        "chief_epoch": None,
        "term": 1,
        "authority_state": "active",
        "permissions": ["company.mutate"],
        "scope_sha256": H,
        "authority_record_sha256": H,
        "provenance": "AOI_verified",
    }


def transaction(
    owner: CompanyStateOwner,
    payload: dict[str, Any],
    *,
    transaction_id: str,
    command_id: str,
) -> dict[str, Any]:
    heads = owner.heads()
    binding = {
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
    }
    actor = authority()
    stream = "org"
    cursor, event_sha256 = heads.stream_heads.get(
        stream,
        (0, ZERO_SHA256),
    )
    event = {
        "contract_type": COMPANY_EVENT_V1,
        "schema_version": 1,
        **binding,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "event_id": f"event-{transaction_id}",
        "stream": stream,
        "event_type": "manifest.recorded",
        "recorded_at": T,
        "actor_authority": copy.deepcopy(actor),
        "provenance": "AOI_verified",
        "payload": payload,
        "payload_sha256": company_contract_sha256(payload),
    }
    expected = {
        "contract_type": EXPECTED_HEAD_V1,
        "schema_version": 1,
        **binding,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "stream": stream,
        "cursor": cursor,
        "event_sha256": event_sha256,
    }
    global_expected = {
        "contract_type": EXPECTED_TRANSACTION_HEAD_V1,
        "schema_version": 1,
        **binding,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "global_sequence": heads.global_head.global_sequence,
        "transaction_sha256": heads.global_head.transaction_sha256,
    }
    request = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1,
        "schema_version": 1,
        **binding,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "actor_authority": actor,
        "expected_transaction_head": global_expected,
        "expected_heads": [expected],
        "events": [event],
    }
    request["request_sha256"] = company_contract_sha256(request)
    return request


def initialized(tmp_path: Path) -> CompanyStateOwner:
    return CompanyStateOwner.initialize(
        tmp_path / "state" / "companies" / "company-1",
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )


def bootstrap(owner: CompanyStateOwner) -> None:
    owner.commit(
        transaction(
            owner,
            manifest(),
            transaction_id="tx-bootstrap",
            command_id="cmd-bootstrap",
        ),
        recorded_at=T,
    )


def organization_node(
    node_id: str,
    *,
    parent_node_id: str | None,
    depth: int,
    can_delegate: bool,
) -> dict[str, Any]:
    return {
        "contract_type": ORGANIZATION_NODE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "node_id": node_id,
        "department_id": None,
        "parent_node_id": parent_node_id,
        "role": "chief" if parent_node_id is None else "worker",
        "reports_to_node_id": parent_node_id,
        "can_delegate": can_delegate,
        "delegation_depth": depth,
        "status": "active",
        "visibility": "company",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def dispatch_payload(
    *,
    request_id: str,
    revision_id: str,
    command_id: str,
    target_node_id: str,
    depth: int = 1,
    revision: int = 1,
    previous_event_id: str | None = None,
    previous_payload_sha256: str | None = None,
    state: str = "queued",
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract_type": DISPATCH_REQUEST_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "dispatch_request_id": request_id,
        "dispatch_revision_id": revision_id,
        "revision": revision,
        "previous_event_id": previous_event_id,
        "previous_payload_sha256": previous_payload_sha256,
        "command_id": command_id,
        "reservation_id": f"reservation-{request_id}",
        "task_id": None,
        "packet_id": None,
        "manager_node_id": "chief-1",
        "target_node_id": target_node_id,
        "department_id": None,
        "parent_execution_id": "execution-chief-1",
        "requested_role": "worker",
        "requested_capability_tier": "standard",
        "route_policy_id": "policy-1",
        "scope_sha256": H,
        "delegation_depth": depth,
        "state": state,
        "attempt": 0 if state in {"queued", "admitted", "cancelled"} else 1,
        "provider_dispatch_id": None,
        "execution_id": None,
        "effect_evidence": [],
        "reconcile_ref": None,
        "resolves_event_ids": [],
        "created_at": T,
        "updated_at": T,
        "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    }
    if state == "effect_unknown":
        value.update({
            "effect_evidence": [{
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": H,
                "size_bytes": 1,
                "media_type": "text/plain",
                "availability": "available",
            }],
            "reconcile_ref": "reconcile-1",
            "observation": {"state": "partial", "reason": "collector_lag"},
        })
    return value


def drafted_request(
    owner: CompanyStateOwner,
    payloads: list[dict[str, Any]],
    *,
    transaction_id: str,
    command_id: str,
    event_prefix: str,
) -> dict[str, Any]:
    return build_company_transaction_request(
        owner.heads(),
        authority(),
        transaction_id=transaction_id,
        command_id=command_id,
        events=[
            CompanyEventDraft(
                event_id=f"{event_prefix}-{index}",
                event_type="record.upserted",
                recorded_at=T,
                payload=payload,
            )
            for index, payload in enumerate(payloads, start=1)
        ],
    )


def dispatch_ready_owner(tmp_path: Path, *, targets: int = 1) -> CompanyStateOwner:
    owner = initialized(tmp_path)
    bootstrap(owner)
    payloads = [organization_node(
        "chief-1", parent_node_id=None, depth=0, can_delegate=True,
    )]
    payloads.extend(
        organization_node(
            f"target-{index}", parent_node_id="chief-1", depth=1,
            can_delegate=False,
        )
        for index in range(1, targets + 1)
    )
    owner.commit(drafted_request(
        owner, payloads, transaction_id="tx-nodes", command_id="cmd-nodes",
        event_prefix="event-node",
    ), recorded_at=T)
    return owner


def test_initialize_commit_close_and_reopen(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    try:
        assert owner.health().ledger_heads.global_head.global_sequence == 0
        bootstrap(owner)
        health = owner.health()
        assert health.status == "ready"
        assert health.ledger_heads.global_head.global_sequence == 1
        assert health.readmodel_head.global_sequence == 1
        projected = owner.objects(contract_type=COMPANY_MANIFEST_V1)
        assert len(projected) == 1
        query = owner.query_snapshot()
        assert query.health.ledger_heads.global_head.global_sequence == 1
        assert query.health.readmodel_head.global_sequence == 1
        assert query.objects == projected
        by_transaction = owner.record_by_transaction_id("tx-bootstrap")
        by_command = owner.record_by_command_id("cmd-bootstrap")
        assert by_transaction is not None
        assert by_transaction == by_command
        assert by_transaction.request["command_id"] == "cmd-bootstrap"
        assert owner.record_by_transaction_id("missing") is None
        assert owner.record_by_command_id("missing") is None
        slot = owner.registry.paths.root
    finally:
        owner.close()

    reopened = CompanyStateOwner.open(slot)
    try:
        assert reopened.health().status == "ready"
        assert reopened.heads().global_head.global_sequence == 1
        assert len(reopened.objects(contract_type=COMPANY_MANIFEST_V1)) == 1
        assert (
            reopened.record_by_command_id("cmd-bootstrap")
            == by_transaction
        )
    finally:
        reopened.close()
    with pytest.raises(CompanyStateClosedError):
        reopened.heads()


def test_second_state_owner_cannot_open_while_lifetime_lock_is_held(
    tmp_path: Path,
) -> None:
    owner = initialized(tmp_path)
    try:
        with pytest.raises(CompanyProcessLockBusyError):
            CompanyStateOwner.open(
                owner.registry.paths.root,
                lock_timeout_seconds=0.1,
            )
    finally:
        owner.close()


def test_missing_projection_is_rebuilt_from_ledger(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    bootstrap(owner)
    slot = owner.registry.paths.root
    projection = owner.resolved.incarnation.readmodel
    owner.close()
    projection.unlink()

    reopened = CompanyStateOwner.open(slot)
    try:
        assert reopened.health().readmodel_head.global_sequence == 1
        assert len(reopened.objects(contract_type=COMPANY_MANIFEST_V1)) == 1
    finally:
        reopened.close()


def test_corrupt_projection_is_discarded_and_rebuilt(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    bootstrap(owner)
    slot = owner.registry.paths.root
    projection = owner.resolved.incarnation.readmodel
    owner.close()
    connection = sqlite3.connect(projection)
    try:
        connection.execute("CREATE TABLE injected (value TEXT) STRICT")
        connection.commit()
    finally:
        connection.close()

    reopened = CompanyStateOwner.open(slot)
    try:
        assert reopened.health().readmodel_head.global_sequence == 1
        check = sqlite3.connect(projection)
        try:
            assert check.execute(
                "SELECT 1 FROM sqlite_master WHERE name='injected'",
            ).fetchone() is None
        finally:
            check.close()
    finally:
        reopened.close()


def test_post_commit_projection_failure_recovers_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = initialized(tmp_path)
    try:
        bootstrap(owner)

        def fail_apply(_record: object) -> bool:
            raise ReadModelCorruptionError("injected projection failure")

        monkeypatch.setattr(owner.readmodel, "apply", fail_apply)
        result = owner.commit(
            transaction(
                owner,
                manifest(),
                transaction_id="tx-2",
                command_id="cmd-2",
            ),
            recorded_at="2026-07-27T00:00:01Z",
        )
        assert result.receipt["state"] == "committed"
        assert owner.health().status == "ready"
        assert owner.heads().global_head.global_sequence == 2
        assert owner.readmodel.head().global_sequence == 2
    finally:
        owner.close()


def _cursor(owner: CompanyStateOwner) -> int:
    return owner.heads().global_head.global_sequence


def admitted_successors(
    queued: list[dict[str, Any]],
    *,
    event_ids: list[str],
    command_id: str,
) -> list[dict[str, Any]]:
    return [
        dispatch_payload(
            request_id=str(payload["dispatch_request_id"]),
            revision_id=f"{payload['dispatch_revision_id']}-admitted",
            command_id=command_id,
            target_node_id=str(payload["target_node_id"]),
            depth=int(payload["delegation_depth"]),
            revision=2,
            previous_event_id=event_id,
            previous_payload_sha256=company_contract_sha256(payload),
            state="admitted",
        )
        for payload, event_id in zip(queued, event_ids, strict=True)
    ]


def test_dispatch_preflight_rejects_depth_seven_without_advancing_cursor(
    tmp_path: Path,
) -> None:
    owner = dispatch_ready_owner(tmp_path)
    try:
        before = _cursor(owner)
        payload = dispatch_payload(
            request_id="request-depth-7", revision_id="revision-depth-7",
            command_id="cmd-depth-7", target_node_id="target-1",
        )
        request = drafted_request(
            owner, [payload], transaction_id="tx-depth-7",
            command_id="cmd-depth-7", event_prefix="event-depth-7",
        )
        event = request["events"][0]
        event["payload"]["delegation_depth"] = 7
        event["payload_sha256"] = company_contract_sha256(event["payload"])
        request["request_sha256"] = company_contract_sha256(
            {key: value for key, value in request.items() if key != "request_sha256"},
        )
        with pytest.raises(CompanyStateInvariantError, match="invalid"):
            owner.commit(request, recorded_at=T)
        assert _cursor(owner) == before
    finally:
        owner.close()


def test_dispatch_preflight_rejects_capacity_seventeen_without_cursor_change(
    tmp_path: Path,
) -> None:
    owner = dispatch_ready_owner(tmp_path, targets=17)
    try:
        command = "cmd-capacity-17"
        queued = [
            dispatch_payload(
                request_id=f"request-capacity-{index}",
                revision_id=f"revision-capacity-{index}", command_id=command,
                target_node_id=f"target-{index}",
            )
            for index in range(1, 18)
        ]
        queued_result = owner.commit(drafted_request(
            owner, queued, transaction_id="tx-capacity-queued", command_id=command,
            event_prefix="event-capacity-queued",
        ), recorded_at=T)
        before = _cursor(owner)
        admitted = admitted_successors(
            queued,
            event_ids=[str(item.event["event_id"]) for item in queued_result.record.events],
            command_id="cmd-capacity-17-admitted",
        )
        request = drafted_request(
            owner, admitted, transaction_id="tx-capacity-17", command_id="cmd-capacity-17-admitted",
            event_prefix="event-capacity-admitted",
        )
        with pytest.raises(CompanyStateInvariantError, match="capacity"):
            owner.commit(request, recorded_at=T)
        assert _cursor(owner) == before
    finally:
        owner.close()


def test_dispatch_preflight_rejects_manager_fanout_five_without_cursor_change(
    tmp_path: Path,
) -> None:
    owner = dispatch_ready_owner(tmp_path, targets=5)
    try:
        command = "cmd-fanout-5"
        queued = [
            dispatch_payload(
                request_id=f"request-fanout-{index}",
                revision_id=f"revision-fanout-{index}", command_id=command,
                target_node_id=f"target-{index}",
            )
            for index in range(1, 6)
        ]
        queued_result = owner.commit(drafted_request(
            owner,
            queued, transaction_id="tx-fanout-queued", command_id=command,
            event_prefix="event-fanout-queued",
        ), recorded_at=T)
        before = _cursor(owner)
        request = drafted_request(
            owner,
            admitted_successors(
                queued,
                event_ids=[str(item.event["event_id"]) for item in queued_result.record.events],
                command_id="cmd-fanout-5-admitted",
            ),
            transaction_id="tx-fanout-5", command_id="cmd-fanout-5-admitted",
            event_prefix="event-fanout-admitted",
        )
        with pytest.raises(CompanyStateInvariantError, match="fanout"):
            owner.commit(request, recorded_at=T)
        assert _cursor(owner) == before
    finally:
        owner.close()


def test_effect_unknown_dispatch_shadow_survives_query_and_rebuild(
    tmp_path: Path,
) -> None:
    owner = dispatch_ready_owner(tmp_path)
    try:
        queued = dispatch_payload(
            request_id="request-shadow", revision_id="revision-shadow-1",
            command_id="cmd-shadow-1", target_node_id="target-1",
        )
        queued_request = drafted_request(
            owner, [queued], transaction_id="tx-shadow-1", command_id="cmd-shadow-1",
            event_prefix="event-shadow-1",
        )
        queued_result = owner.commit(queued_request, recorded_at=T)
        queued_event_id = queued_result.record.events[0].event["event_id"]

        admitted = dispatch_payload(
            request_id="request-shadow", revision_id="revision-shadow-2",
            command_id="cmd-shadow-2", target_node_id="target-1", revision=2,
            previous_event_id=str(queued_event_id),
            previous_payload_sha256=company_contract_sha256(queued), state="admitted",
        )
        admitted_result = owner.commit(drafted_request(
            owner, [admitted], transaction_id="tx-shadow-2", command_id="cmd-shadow-2",
            event_prefix="event-shadow-2",
        ), recorded_at=T)
        admitted_event_id = admitted_result.record.events[0].event["event_id"]

        inflight = dispatch_payload(
            request_id="request-shadow", revision_id="revision-shadow-3",
            command_id="cmd-shadow-3", target_node_id="target-1", revision=3,
            previous_event_id=str(admitted_event_id),
            previous_payload_sha256=company_contract_sha256(admitted), state="in_flight",
        )
        inflight_result = owner.commit(drafted_request(
            owner, [inflight], transaction_id="tx-shadow-3", command_id="cmd-shadow-3",
            event_prefix="event-shadow-3",
        ), recorded_at=T)
        inflight_event_id = inflight_result.record.events[0].event["event_id"]

        uncertain = dispatch_payload(
            request_id="request-shadow", revision_id="revision-shadow-4",
            command_id="cmd-shadow-4", target_node_id="target-1", revision=4,
            previous_event_id=str(inflight_event_id),
            previous_payload_sha256=company_contract_sha256(inflight),
            state="effect_unknown",
        )
        evidence = owner.blobs.put(b"x")
        uncertain["effect_evidence"][0].update({
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
        })
        owner.commit(drafted_request(
            owner, [uncertain], transaction_id="tx-shadow-4", command_id="cmd-shadow-4",
            event_prefix="event-shadow-4",
        ), state="effect_unknown", recorded_at=T)

        snapshot = owner.query_snapshot()
        assert len(snapshot.uncertain_dispatches) == 1
        assert snapshot.uncertain_dispatches[0].reservation_id == "reservation-request-shadow"
        assert snapshot.uncertain_dispatches[0].requested_state == "effect_unknown"
        owner.rebuild_projection()
        rebuilt = owner.query_snapshot()
        assert rebuilt.uncertain_dispatches == snapshot.uncertain_dispatches
        assert (
            rebuilt.health.readmodel_head.global_sequence,
            rebuilt.health.readmodel_head.transaction_sha256,
        ) == (
            rebuilt.health.ledger_heads.global_head.global_sequence,
            rebuilt.health.ledger_heads.global_head.transaction_sha256,
        )
    finally:
        owner.close()


def test_dispatch_revision_divergence_rejects_before_append_and_exact_replay_is_allowed(
    tmp_path: Path,
) -> None:
    owner = dispatch_ready_owner(tmp_path)
    try:
        payload = dispatch_payload(
            request_id="request-replay", revision_id="revision-replay-1",
            command_id="cmd-replay-1", target_node_id="target-1",
        )
        original = drafted_request(
            owner, [payload], transaction_id="tx-replay-1", command_id="cmd-replay-1",
            event_prefix="event-replay-1",
        )
        result = owner.commit(original, recorded_at=T)

        progressed = dispatch_payload(
            request_id="request-replay", revision_id="revision-replay-2",
            command_id="cmd-replay-2", target_node_id="target-1", revision=2,
            previous_event_id=str(result.record.events[0].event["event_id"]),
            previous_payload_sha256=company_contract_sha256(payload), state="admitted",
        )
        owner.commit(drafted_request(
            owner, [progressed], transaction_id="tx-replay-2",
            command_id="cmd-replay-2", event_prefix="event-replay-2",
        ), recorded_at=T)

        replay = owner.commit(original, recorded_at=T)
        assert replay.idempotent_replay
        assert replay.record == result.record
        before = _cursor(owner)

        divergent_payload = dispatch_payload(
            request_id="request-replay", revision_id="revision-replay-1",
            command_id="cmd-replay-3", target_node_id="target-1",
        )
        divergent = drafted_request(
            owner, [divergent_payload], transaction_id="tx-replay-3",
            command_id="cmd-replay-3", event_prefix="event-replay-3",
        )
        with pytest.raises(CompanyStateInvariantError, match="divergent durable binding"):
            owner.commit(divergent, recorded_at=T)
        assert _cursor(owner) == before
    finally:
        owner.close()


def test_owner_thread_confinement_and_global_cas_dispatch_requests(
    tmp_path: Path,
) -> None:
    owner = dispatch_ready_owner(tmp_path, targets=2)
    try:
        request_a = drafted_request(
            owner,
            [dispatch_payload(
                request_id="request-race-a", revision_id="revision-race-a",
                command_id="cmd-race-a", target_node_id="target-1",
            )],
            transaction_id="tx-race-a", command_id="cmd-race-a",
            event_prefix="event-race-a",
        )
        request_b = drafted_request(
            owner,
            [dispatch_payload(
                request_id="request-race-b", revision_id="revision-race-b",
                command_id="cmd-race-b", target_node_id="target-2",
            )],
            transaction_id="tx-race-b", command_id="cmd-race-b",
            event_prefix="event-race-b",
        )
        barrier = threading.Barrier(3)
        outcomes: list[object] = []

        def writer(value: dict[str, Any]) -> None:
            barrier.wait()
            try:
                outcomes.append(owner.commit(value, recorded_at=T))
            except BaseException as exc:  # asserted below; never swallow silently
                outcomes.append(exc)

        first = threading.Thread(target=writer, args=(request_a,))
        second = threading.Thread(target=writer, args=(request_b,))
        first.start()
        second.start()
        barrier.wait()
        first.join(timeout=10)
        second.join(timeout=10)
        assert not first.is_alive() and not second.is_alive()
        assert len(outcomes) == 2
        assert all(
            isinstance(item, CompanyProcessLockOwnershipError)
            for item in outcomes
        )
        assert _cursor(owner) == 2

        owner.commit(request_a, recorded_at=T)
        with pytest.raises(LedgerConflictError):
            owner.commit(request_b, recorded_at=T)
        assert _cursor(owner) == 3
    finally:
        owner.close()
