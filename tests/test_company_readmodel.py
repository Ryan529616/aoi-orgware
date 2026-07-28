from __future__ import annotations

import copy
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    COMPANY_EVENT_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    DEPARTMENT_IDENTITY_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    ORGANIZATION_NODE_V1,
    ZERO_SHA256,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import (
    CompanyLedger,
    LedgerEventRecord,
    LedgerTransactionRecord,
)
from aoi_orgware.company.readmodel import (
    CompanyReadModel,
    ReadModelCorruptionError,
    ReadModelGapError,
)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_company_contracts import dispatch_request  # type: ignore[import-not-found]


B = {
    "company_id": "company-1",
    "company_incarnation": 1,
    "lock_domain_generation": 1,
}
T0 = "2026-07-26T00:00:00Z"


def observed() -> dict[str, str]:
    return {"state": "known", "reason": "observed"}


def authority() -> dict[str, Any]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1,
        "schema_version": 1,
        **B,
        "actor_id": "chief-1",
        "actor_kind": "chief",
        "carrier_id": "carrier-1",
        "chief_epoch": 1,
        "term": 1,
        "authority_state": "active",
        "permissions": ["company.mutate"],
        "scope_sha256": "a" * 64,
        "authority_record_sha256": "b" * 64,
        "provenance": "AOI_verified",
    }


def chief_node() -> dict[str, Any]:
    return {
        "contract_type": ORGANIZATION_NODE_V1,
        "schema_version": 1,
        **B,
        "node_id": "chief-1",
        "department_id": None,
        "parent_node_id": None,
        "role": "chief",
        "reports_to_node_id": None,
        "can_delegate": True,
        "delegation_depth": 0,
        "status": "active",
        "visibility": "company",
        "created_at": T0,
        "observation": observed(),
    }


def department(*, status: str = "active") -> dict[str, Any]:
    return {
        "contract_type": DEPARTMENT_IDENTITY_V1,
        "schema_version": 1,
        **B,
        "department_id": "rtl",
        "name": "RTL",
        "charter_sha256": "c" * 64,
        "scope_sha256": "d" * 64,
        "lead_node_id": None,
        "created_at": T0,
        "status": status,
        "observation": observed(),
    }


def target_node() -> dict[str, Any]:
    value = chief_node()
    value.update({
        "node_id": "target-1",
        "parent_node_id": "chief-1",
        "reports_to_node_id": "chief-1",
        "role": "worker",
        "can_delegate": False,
        "delegation_depth": 1,
    })
    return value


def append_payload(
    ledger: CompanyLedger,
    payload: dict[str, Any],
    *,
    tx: str,
    command: str,
    event_id: str,
    stream: str,
    state: str = "committed",
) -> LedgerTransactionRecord:
    records = ledger.load_records()
    sequence = len(records)
    previous = records[-1].receipt["transaction_sha256"] if records else ZERO_SHA256
    stream_cursor, stream_hash = 0, ZERO_SHA256
    for record in records:
        for member in record.events:
            if member.event["stream"] == stream:
                stream_cursor, stream_hash = (
                    member.stream_sequence, member.event_sha256,
                )
    value = request(
        payload, tx=tx, command=command, event_id=event_id, stream=stream,
        global_sequence=sequence, global_hash=previous,
        stream_cursor=stream_cursor, stream_hash=stream_hash,
    )
    return ledger.append(value, state=state).record


def dispatch_revision(
    *,
    state: str,
    command: str,
    revision: int,
    revision_id: str,
    previous_event_id: str | None,
    previous_sha256: str | None,
    resolves: list[str] | None = None,
) -> dict[str, Any]:
    value = copy.deepcopy(dispatch_request(state=state))
    value.update(B)
    value.update({
        "dispatch_request_id": "dispatch-request-1",
        "dispatch_revision_id": revision_id,
        "command_id": command,
        "manager_node_id": "chief-1",
        "target_node_id": "target-1",
        "revision": revision,
        "previous_event_id": previous_event_id,
        "previous_payload_sha256": previous_sha256,
        "resolves_event_ids": resolves or [],
    })
    return value


def request(
    payload: dict[str, Any],
    *,
    tx: str,
    command: str,
    event_id: str,
    stream: str = "org",
    global_sequence: int = 0,
    global_hash: str = ZERO_SHA256,
    stream_cursor: int = 0,
    stream_hash: str = ZERO_SHA256,
) -> dict[str, Any]:
    actor = authority()
    event = {
        "contract_type": COMPANY_EVENT_V1,
        "schema_version": 1,
        **B,
        "transaction_id": tx,
        "command_id": command,
        "event_id": event_id,
        "stream": stream,
        "event_type": "record.upserted",
        "recorded_at": T0,
        "actor_authority": copy.deepcopy(actor),
        "provenance": "AOI_verified",
        "payload": payload,
        "payload_sha256": company_contract_sha256(payload),
    }
    expected_head = {
        "contract_type": EXPECTED_HEAD_V1,
        "schema_version": 1,
        **B,
        "transaction_id": tx,
        "command_id": command,
        "stream": stream,
        "cursor": stream_cursor,
        "event_sha256": stream_hash,
    }
    global_head = {
        "contract_type": EXPECTED_TRANSACTION_HEAD_V1,
        "schema_version": 1,
        **B,
        "transaction_id": tx,
        "command_id": command,
        "global_sequence": global_sequence,
        "transaction_sha256": global_hash,
    }
    value = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1,
        "schema_version": 1,
        **B,
        "transaction_id": tx,
        "command_id": command,
        "actor_authority": actor,
        "expected_transaction_head": global_head,
        "expected_heads": [expected_head],
        "events": [event],
    }
    value["request_sha256"] = company_contract_sha256(value)
    return value


def two_record_ledger(path: Path) -> tuple[
    CompanyLedger, tuple[LedgerTransactionRecord, ...],
]:
    ledger = CompanyLedger(path)
    first = ledger.append(request(
        chief_node(), tx="tx-1", command="cmd-1", event_id="event-1",
    ))
    first_stream = first.receipt["result_heads"][0]
    ledger.append(request(
        department(), tx="tx-2", command="cmd-2", event_id="event-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        stream_cursor=first_stream["cursor"],
        stream_hash=first_stream["event_sha256"],
    ))
    return ledger, ledger.load_records()


def test_apply_exact_prefix_replay_and_current_objects(tmp_path: Path) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")

    assert model.apply(records[0])
    assert not model.apply(records[0])
    assert model.apply(records[1])
    head = model.head()
    assert head.global_sequence == 2
    assert head.transaction_sha256 == records[-1].receipt["transaction_sha256"]
    objects = model.objects()
    assert [
        (item.contract_type, item.object_key)
        for item in objects
    ] == [
        (DEPARTMENT_IDENTITY_V1, "rtl"),
        (ORGANIZATION_NODE_V1, "chief-1"),
    ]
    assert objects[0].payload["status"] == "active"
    exact = model.object(DEPARTMENT_IDENTITY_V1, "rtl")
    assert exact == objects[0]
    assert model.object(DEPARTMENT_IDENTITY_V1, "missing") is None
    with pytest.raises(ValueError, match="projectable"):
        model.object("not-a-contract", "rtl")
    with pytest.raises(ValueError, match="object_key"):
        model.object(DEPARTMENT_IDENTITY_V1, "")
    ledger.close()
    model.close()


def test_gap_stream_mismatch_and_divergent_replay_fail_closed(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    gap = CompanyReadModel(tmp_path / "gap.sqlite3")
    with pytest.raises(ReadModelGapError):
        gap.apply(records[1])
    assert gap.head().global_sequence == 0

    wrong_ledger = CompanyLedger(tmp_path / "wrong-ledger.sqlite3")
    wrong_ledger.append(request(
        department(), tx="tx-x", command="cmd-x", event_id="event-x",
        stream="execution",
    ))
    wrong_record = wrong_ledger.load_records()[0]
    with pytest.raises(ReadModelCorruptionError):
        gap.apply(wrong_record)
    assert gap.head().global_sequence == 0

    assert gap.apply(records[0])
    divergent_receipt = dict(records[0].receipt)
    divergent_receipt["recorded_at"] = "2026-07-26T00:00:01Z"
    altered = LedgerTransactionRecord(
        records[0].global_sequence,
        records[0].request,
        divergent_receipt,
        records[0].events,
        records[0].reservations,
    )
    with pytest.raises(ReadModelCorruptionError):
        gap.apply(altered)
    ledger.close()
    wrong_ledger.close()
    gap.close()


def test_terminal_reservation_advances_cursor_without_current_object(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    ledger.append(
        request(
            department(), tx="tx-1", command="cmd-1",
            event_id="event-reserved",
        ),
        state="failed_known",
    )
    record = ledger.load_records()[0]
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    assert model.apply(record)
    assert model.head().global_sequence == 1
    assert model.objects() == ()
    with sqlite3.connect(model.path) as connection:
        assert connection.execute(
            "SELECT event_id FROM projected_reservations",
        ).fetchall() == [("event-reserved",)]
    ledger.close()
    model.close()


def test_dispatch_effect_unknown_shadow_and_explicit_resolution_replay(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    records = [
        append_payload(
            ledger, chief_node(), tx="tx-1", command="cmd-1",
            event_id="event-chief", stream="org",
        ),
        append_payload(
            ledger, target_node(), tx="tx-2", command="cmd-2",
            event_id="event-target", stream="org",
        ),
    ]
    queued = dispatch_revision(
        state="queued", command="cmd-3", revision=1,
        revision_id="dispatch-revision-1", previous_event_id=None,
        previous_sha256=None,
    )
    records.append(append_payload(
        ledger, queued, tx="tx-3", command="cmd-3",
        event_id="event-queued", stream="execution",
    ))
    admitted = dispatch_revision(
        state="admitted", command="cmd-4", revision=2,
        revision_id="dispatch-revision-2", previous_event_id="event-queued",
        previous_sha256=company_contract_sha256(queued),
    )
    records.append(append_payload(
        ledger, admitted, tx="tx-4", command="cmd-4",
        event_id="event-admitted", stream="execution",
    ))
    inflight = dispatch_revision(
        state="in_flight", command="cmd-5", revision=3,
        revision_id="dispatch-revision-3", previous_event_id="event-admitted",
        previous_sha256=company_contract_sha256(admitted),
    )
    records.append(append_payload(
        ledger, inflight, tx="tx-5", command="cmd-5",
        event_id="event-inflight", stream="execution",
    ))
    unknown = dispatch_revision(
        state="effect_unknown", command="cmd-6", revision=4,
        revision_id="dispatch-revision-4", previous_event_id="event-inflight",
        previous_sha256=company_contract_sha256(inflight),
    )
    records.append(append_payload(
        ledger, unknown, tx="tx-6", command="cmd-6",
        event_id="event-unknown", stream="execution", state="effect_unknown",
    ))
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    assert model.apply_many(records) == len(records)
    shadows = model.uncertain_dispatches()
    assert [item.source_event_id for item in shadows] == ["event-unknown"]
    revision = model.dispatch_revision("dispatch-revision-4")
    assert revision is not None
    assert (revision.event_id, revision.receipt_state) == (
        "event-unknown", "effect_unknown",
    )
    assert model.verify_integrity().global_sequence == 6

    resolved = dispatch_revision(
        state="failed_known", command="cmd-7", revision=4,
        revision_id="dispatch-revision-5", previous_event_id="event-inflight",
        previous_sha256=company_contract_sha256(inflight),
        resolves=["event-unknown"],
    )
    resolved_record = append_payload(
        ledger, resolved, tx="tx-7", command="cmd-7",
        event_id="event-resolved", stream="execution",
    )
    assert model.apply(resolved_record)
    assert model.uncertain_dispatches() == ()
    assert not model.apply(resolved_record)
    assert model.verify_integrity().global_sequence == 7

    rebuilt_path = tmp_path / "rebuilt.sqlite3"
    CompanyReadModel.rebuild(rebuilt_path, ledger.load_records())
    rebuilt = CompanyReadModel(rebuilt_path)
    assert rebuilt.objects() == model.objects()
    assert rebuilt.uncertain_dispatches() == ()
    rebuilt.close()
    ledger.close()
    model.close()


def test_dispatch_registry_and_derived_shadow_tampering_fail_closed(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    records = [
        append_payload(ledger, chief_node(), tx="tx-1", command="cmd-1", event_id="event-chief", stream="org"),
        append_payload(ledger, target_node(), tx="tx-2", command="cmd-2", event_id="event-target", stream="org"),
    ]
    queued = dispatch_revision(state="queued", command="cmd-3", revision=1, revision_id="dispatch-revision-1", previous_event_id=None, previous_sha256=None)
    records.append(append_payload(ledger, queued, tx="tx-3", command="cmd-3", event_id="event-queued", stream="execution"))
    admitted = dispatch_revision(state="admitted", command="cmd-4", revision=2, revision_id="dispatch-revision-2", previous_event_id="event-queued", previous_sha256=company_contract_sha256(queued))
    records.append(append_payload(ledger, admitted, tx="tx-4", command="cmd-4", event_id="event-admitted", stream="execution"))
    inflight = dispatch_revision(state="in_flight", command="cmd-5", revision=3, revision_id="dispatch-revision-3", previous_event_id="event-admitted", previous_sha256=company_contract_sha256(admitted))
    records.append(append_payload(ledger, inflight, tx="tx-5", command="cmd-5", event_id="event-inflight", stream="execution"))
    unknown = dispatch_revision(state="effect_unknown", command="cmd-6", revision=4, revision_id="dispatch-revision-4", previous_event_id="event-inflight", previous_sha256=company_contract_sha256(inflight))
    records.append(append_payload(ledger, unknown, tx="tx-6", command="cmd-6", event_id="event-unknown", stream="execution", state="effect_unknown"))
    model_path = tmp_path / "readmodel.sqlite3"
    model = CompanyReadModel(model_path)
    model.apply_many(records)
    model.close()
    with sqlite3.connect(model_path) as connection:
        connection.execute(
            "UPDATE current_uncertain_dispatch_reservations "
            "SET source_command_id='tampered'",
        )
        connection.commit()
    with pytest.raises(ReadModelCorruptionError):
        CompanyReadModel(model_path)
    ledger.close()


def test_projection_catches_up_after_ledger_commit_and_reopen(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    path = tmp_path / "readmodel.sqlite3"
    model = CompanyReadModel(path)
    model.apply(records[0])
    model.close()

    reopened = CompanyReadModel(path)
    assert reopened.head().global_sequence == 1
    assert reopened.apply(records[1])
    assert reopened.head().global_sequence == 2
    ledger.close()
    reopened.close()


def test_atomic_rebuild_replaces_only_complete_projection(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    path = tmp_path / "readmodel.sqlite3"
    existing = CompanyReadModel(path)
    existing.apply(records[0])
    existing.close()

    with pytest.raises(ReadModelGapError):
        CompanyReadModel.rebuild(path, records[1:])
    preserved = CompanyReadModel(path)
    assert preserved.head().global_sequence == 1
    preserved.close()

    head = CompanyReadModel.rebuild(path, records)
    assert head.global_sequence == 2
    rebuilt = CompanyReadModel(path)
    assert rebuilt.head().global_sequence == 2
    assert len(rebuilt.objects()) == 2
    assert not list(tmp_path.glob(".readmodel.sqlite3.aoi-readmodel-v1.*.tmp"))
    ledger.close()
    rebuilt.close()


def test_payload_tamper_and_unexpected_schema_object_are_detected(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    path = tmp_path / "readmodel.sqlite3"
    model = CompanyReadModel(path)
    model.apply_many(records)
    tampered = department(status="parked")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE current_objects SET payload_bytes=? "
            "WHERE contract_type=? AND object_key='rtl'",
            (
                canonical_company_json_bytes(tampered),
                DEPARTMENT_IDENTITY_V1,
            ),
        )
    with pytest.raises(ReadModelCorruptionError):
        model.objects()
    model.close()

    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unexpected(value TEXT) STRICT")
    with pytest.raises(ReadModelCorruptionError):
        CompanyReadModel(path)
    ledger.close()


def test_readmodel_guard_blocks_or_detects_path_replacement(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    path = tmp_path / "guarded-readmodel.sqlite3"
    model = CompanyReadModel(path)
    model.apply(records[0])
    replacement_path = tmp_path / "replacement-readmodel.sqlite3"
    replacement = CompanyReadModel(replacement_path)
    replacement.apply_many(records)
    replacement.close()

    if os.name == "nt":
        with pytest.raises(OSError):
            os.replace(replacement_path, path)
        assert model.head().global_sequence == 1
    else:
        os.replace(replacement_path, path)
        with pytest.raises(
            ReadModelCorruptionError,
            match="path identity changed",
        ):
            model.head()
    model.close()
    ledger.close()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows guard prevents the replacement itself",
)
@pytest.mark.parametrize(
    "operation",
    ("head", "objects", "verify_integrity"),
)
def test_public_read_rechecks_path_guard_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    path = tmp_path / f"{operation}-post-check.sqlite3"
    model = CompanyReadModel(path)
    model.apply_many(records)
    replacement_path = tmp_path / f"{operation}-replacement.sqlite3"
    replacement = CompanyReadModel(replacement_path)
    replacement.apply(records[0])
    replacement.close()

    original_environment = model._assert_environment

    def replace_after_environment(connection: sqlite3.Connection) -> None:
        original_environment(connection)
        os.replace(replacement_path, path)

    monkeypatch.setattr(model, "_assert_environment", replace_after_environment)
    with pytest.raises(
        ReadModelCorruptionError,
        match="path identity changed",
    ):
        getattr(model, operation)()
    with pytest.raises(ReadModelCorruptionError, match="quarantined"):
        model.head()
    model.close()
    ledger.close()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows guard prevents the replacement itself",
)
def test_apply_post_commit_path_swap_never_returns_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    path = tmp_path / "apply-post-commit.sqlite3"
    model = CompanyReadModel(path)
    model.apply(records[0])
    replacement_path = tmp_path / "apply-post-commit-replacement.sqlite3"
    replacement = CompanyReadModel(replacement_path)
    replacement.apply(records[0])
    replacement.close()

    original_guard = model._assert_database_guard
    guard_calls = 0

    def replace_immediately_before_post_commit_guard() -> None:
        nonlocal guard_calls
        guard_calls += 1
        # apply checks through _assert_environment, immediately before COMMIT,
        # and finally after COMMIT but before publishing success.
        if guard_calls == 3:
            os.replace(replacement_path, path)
        original_guard()

    monkeypatch.setattr(
        model,
        "_assert_database_guard",
        replace_immediately_before_post_commit_guard,
    )
    with pytest.raises(
        ReadModelCorruptionError,
        match="path identity changed",
    ):
        model.apply(records[1])
    assert guard_calls == 3
    with pytest.raises(ReadModelCorruptionError, match="quarantined"):
        model.head()
    model.close()
    ledger.close()


@pytest.mark.skipif(os.name == "nt", reason="Windows guard prevents the replacement itself")
def test_readmodel_constructor_rejects_swap_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "constructor-readmodel.sqlite3"
    original = CompanyReadModel(path)
    original.close()
    replacement_path = tmp_path / "constructor-replacement.sqlite3"
    replacement = CompanyReadModel(replacement_path)
    replacement.close()
    original_verifier = CompanyReadModel._verified_head
    swapped = False

    def verify_then_swap(
        connection: sqlite3.Connection,
    ) -> object:
        nonlocal swapped
        verified = original_verifier(connection)
        if not swapped:
            os.replace(replacement_path, path)
            swapped = True
        return verified

    monkeypatch.setattr(
        CompanyReadModel,
        "_verified_head",
        staticmethod(verify_then_swap),
    )
    with pytest.raises(
        ReadModelCorruptionError,
        match="path identity changed",
    ):
        CompanyReadModel(path)
    assert swapped


def test_forged_ledger_event_chain_metadata_is_rejected(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    original = records[0].events[0]
    forged_event = LedgerEventRecord(
        event=original.event,
        stream_sequence=original.stream_sequence,
        previous_event_sha256=original.previous_event_sha256,
        event_sha256="e" * 64,
    )
    forged = LedgerTransactionRecord(
        global_sequence=records[0].global_sequence,
        request=records[0].request,
        receipt=records[0].receipt,
        events=(forged_event,),
        reservations=(),
    )
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    with pytest.raises(
        ReadModelCorruptionError,
        match="event chain metadata differs",
    ):
        model.apply(forged)
    assert model.head().global_sequence == 0
    model.close()
    ledger.close()


def test_reopen_fully_verifies_old_event_and_current_object_rows(
    tmp_path: Path,
) -> None:
    ledger, records = two_record_ledger(tmp_path / "ledger.sqlite3")
    event_path = tmp_path / "event-tamper.sqlite3"
    event_model = CompanyReadModel(event_path)
    event_model.apply_many(records)
    event_model.close()
    with sqlite3.connect(event_path) as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='trigger' AND name='projected_events_no_update'",
        ).fetchone()[0]
        connection.execute("DROP TRIGGER projected_events_no_update")
        connection.execute(
            "UPDATE projected_events SET event_sha256=? "
            "WHERE event_id='event-1'",
            ("e" * 64,),
        )
        connection.execute(trigger_sql)
    with pytest.raises(
        ReadModelCorruptionError,
        match="event chain metadata differs",
    ):
        CompanyReadModel(event_path)

    object_path = tmp_path / "object-tamper.sqlite3"
    object_model = CompanyReadModel(object_path)
    object_model.apply_many(records)
    object_model.close()
    tampered = department(status="parked")
    with sqlite3.connect(object_path) as connection:
        connection.execute(
            "UPDATE current_objects SET payload_sha256=?, payload_bytes=? "
            "WHERE contract_type=? AND object_key='rtl'",
            (
                company_contract_sha256(tampered),
                canonical_company_json_bytes(tampered),
                DEPARTMENT_IDENTITY_V1,
            ),
        )
    with pytest.raises(
        ReadModelCorruptionError,
        match="current object differs",
    ):
        CompanyReadModel(object_path)
    ledger.close()
