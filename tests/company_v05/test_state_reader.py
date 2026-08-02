from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
import sys
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    COMPANY_EVENT_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    ZERO_SHA256,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import (
    CompanyLedger,
    LedgerHead,
    LedgerHeadsSnapshot,
    LedgerOwnershipError,
    LedgerReservationRecord,
    LedgerTransactionRecord,
)
from aoi_orgware.company.state_reader import (
    CompanyHistoricalLedgerHeads,
    CompanyHistoricalReplayInput,
    CompanyStateReaderError,
    immutable_historical_replay_input,
    immutable_ledger_heads,
    validate_historical_ledger_snapshot,
)
from aoi_orgware.company.state import CompanyStateError

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_checkpoint as checkpoint_support  # type: ignore[import-not-found]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_company_ledger as ledger_support  # type: ignore[import-not-found]


H = "a" * 64
T = "2026-08-02T00:00:00Z"
B = {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1}


def _authority() -> dict[str, Any]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1, "schema_version": 1, **B,
        "actor_id": "chief-1", "actor_kind": "chief", "carrier_id": "carrier-1",
        "chief_epoch": 1, "term": 1, "authority_state": "active",
        "permissions": ["company.mutate"], "scope_sha256": H,
        "authority_record_sha256": H, "provenance": "AOI_verified",
    }


def _request(
    transaction_id: str,
    command_id: str,
    *,
    global_sequence: int,
    global_digest: str,
    stream: str,
    stream_cursor: int,
    stream_digest: str,
) -> dict[str, Any]:
    authority = _authority()
    payload = {"transaction_id": transaction_id}
    event = {
        "contract_type": COMPANY_EVENT_V1, "schema_version": 1, **B,
        "transaction_id": transaction_id, "command_id": command_id,
        "event_id": f"event-{transaction_id}", "stream": stream,
        "event_type": "recorded", "recorded_at": T,
        "actor_authority": copy.deepcopy(authority), "provenance": "AOI_verified",
        "payload": payload, "payload_sha256": company_contract_sha256(payload),
    }
    expected_stream = {
        "contract_type": EXPECTED_HEAD_V1, "schema_version": 1, **B,
        "transaction_id": transaction_id, "command_id": command_id,
        "stream": stream, "cursor": stream_cursor, "event_sha256": stream_digest,
    }
    expected_global = {
        "contract_type": EXPECTED_TRANSACTION_HEAD_V1, "schema_version": 1, **B,
        "transaction_id": transaction_id, "command_id": command_id,
        "global_sequence": global_sequence, "transaction_sha256": global_digest,
    }
    request = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1, "schema_version": 1, **B,
        "transaction_id": transaction_id, "command_id": command_id,
        "actor_authority": authority, "expected_transaction_head": expected_global,
        "expected_heads": [expected_stream], "events": [event],
    }
    request["request_sha256"] = company_contract_sha256(request)
    return request


def _history(tmp_path: Path) -> tuple[tuple[LedgerTransactionRecord, ...], CompanyHistoricalLedgerHeads]:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(_request(
        "tx-1", "cmd-1", global_sequence=0, global_digest=ZERO_SHA256,
        stream="org", stream_cursor=0, stream_digest=ZERO_SHA256,
    ))
    failed = ledger.append(_request(
        "tx-2", "cmd-2", global_sequence=1,
        global_digest=first.receipt["transaction_sha256"], stream="usage",
        stream_cursor=0, stream_digest=ZERO_SHA256,
    ), state="failed_known")
    ledger.append(_request(
        "tx-3", "cmd-3", global_sequence=2,
        global_digest=failed.receipt["transaction_sha256"], stream="usage",
        stream_cursor=0, stream_digest=ZERO_SHA256,
    ))
    records = ledger.load_records()
    heads = immutable_ledger_heads(ledger.snapshot_heads())
    ledger.close()
    return records, heads


def _invalid(records: tuple[LedgerTransactionRecord, ...], heads: CompanyHistoricalLedgerHeads) -> None:
    with pytest.raises(CompanyStateReaderError):
        validate_historical_ledger_snapshot(records, heads)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(member) for key, member in value.items()}
    if type(value) in {tuple, list}:
        return [_thaw(member) for member in value]
    return value


def _failed_record(
    previous: LedgerTransactionRecord,
    transaction_id: str,
    command_id: str,
    event_id: str,
) -> LedgerTransactionRecord:
    request = _request(
        transaction_id,
        command_id,
        global_sequence=previous.global_sequence,
        global_digest=str(previous.receipt["transaction_sha256"]),
        stream="usage",
        stream_cursor=0,
        stream_digest=ZERO_SHA256,
    )
    request["events"][0]["event_id"] = event_id
    del request["request_sha256"]
    request["request_sha256"] = company_contract_sha256(request)
    receipt = CompanyLedger._receipt(
        request,
        "failed_known",
        T,
        previous.global_sequence + 1,
        str(previous.receipt["transaction_sha256"]),
        [],
        [],
    )
    return LedgerTransactionRecord(
        previous.global_sequence + 1,
        request,
        receipt,
        (),
        (LedgerReservationRecord(request["events"][0]),),
    )


def test_exact_nonempty_reconstruction_and_deterministic_sorting(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)

    assert validate_historical_ledger_snapshot(records, heads) == heads
    assert heads.stream_heads == tuple(sorted(heads.stream_heads))
    assert heads.stream_heads == (
        ("org", 1, records[0].events[0].event_sha256),
        ("usage", 1, records[2].events[0].event_sha256),
    )


@pytest.mark.parametrize("alter", [
    lambda heads: CompanyHistoricalLedgerHeads(heads.identity, heads.global_head, heads.stream_heads[:-1]),
    lambda heads: CompanyHistoricalLedgerHeads(heads.identity, heads.global_head, (*heads.stream_heads, ("z", 1, H))),
    lambda heads: CompanyHistoricalLedgerHeads(heads.identity, heads.global_head, (("org", 1, H), *heads.stream_heads[1:])),
])
def test_every_missing_extra_or_changed_stream_head_fails(
    tmp_path: Path,
    alter: Any,
) -> None:
    records, heads = _history(tmp_path)
    _invalid(records, alter(heads))


def test_global_and_identity_drift_fail(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)

    _invalid(records, CompanyHistoricalLedgerHeads(
        heads.identity, (heads.global_head[0], H), heads.stream_heads,
    ))
    _invalid(records, CompanyHistoricalLedgerHeads(
        ("other-company", 1, 1), heads.global_head, heads.stream_heads,
    ))


def test_empty_ledger_requires_exact_zero_witness() -> None:
    zero = CompanyHistoricalLedgerHeads(None, (0, ZERO_SHA256), ())

    assert validate_historical_ledger_snapshot((), zero) == zero
    _invalid((), CompanyHistoricalLedgerHeads(None, (0, H), ()))
    _invalid((), CompanyHistoricalLedgerHeads(("company-1", 1, 1), (0, ZERO_SHA256), ()))


def test_reservations_do_not_advance_stream_heads(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)

    assert records[1].reservations and records[1].events == ()
    assert heads.stream_heads == (
        ("org", 1, records[0].events[0].event_sha256),
        ("usage", 1, records[2].events[0].event_sha256),
    )
    assert validate_historical_ledger_snapshot(records, heads) == heads


@pytest.mark.parametrize(
    ("field_path", "replacement"),
    (
        (("schema_version",), True),
        (("company_incarnation",), 1.0),
        (("actor_authority", "chief_epoch"), True),
    ),
)
def test_reservation_parity_is_exact_across_json_scalar_types(
    tmp_path: Path,
    field_path: tuple[str, ...],
    replacement: object,
) -> None:
    records, heads = _history(tmp_path)
    event = _thaw(records[1].reservations[0].event)
    target = event
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = replacement
    malformed = replace(
        records[1],
        reservations=(LedgerReservationRecord(event),),
    )

    _invalid((records[0], malformed, records[2]), heads)


@pytest.mark.parametrize(
    ("field_path", "replacement"),
    (
        (("schema_version",), True),
        (("company_incarnation",), 1.0),
        (("actor_authority", "chief_epoch"), True),
    ),
)
def test_committed_event_parity_is_exact_across_json_scalar_types(
    tmp_path: Path,
    field_path: tuple[str, ...],
    replacement: object,
) -> None:
    records, heads = _history(tmp_path)
    event = _thaw(records[0].events[0].event)
    target = event
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = replacement
    malformed = replace(
        records[0],
        events=(replace(records[0].events[0], event=event),),
    )

    with pytest.raises(
        CompanyStateReaderError,
        match="committed historical event differs",
    ):
        validate_historical_ledger_snapshot(
            (malformed, records[1], records[2]),
            heads,
        )


@pytest.mark.parametrize("identity_kind", ["transaction", "command", "event"])
def test_cross_transaction_identity_reuse_fails_at_reader_boundary(
    tmp_path: Path,
    identity_kind: str,
) -> None:
    records, _heads = _history(tmp_path)
    first = records[0]
    transaction_id = "tx-unique"
    command_id = "cmd-unique"
    event_id = "event-unique"
    if identity_kind == "transaction":
        transaction_id = str(first.request["transaction_id"])
    elif identity_kind == "command":
        command_id = str(first.request["command_id"])
    else:
        event_id = str(first.events[0].event["event_id"])
    second = _failed_record(first, transaction_id, command_id, event_id)
    heads = CompanyHistoricalLedgerHeads(
        (B["company_id"], B["company_incarnation"], B["lock_domain_generation"]),
        (2, str(second.receipt["transaction_sha256"])),
        (("org", 1, first.events[0].event_sha256),),
    )
    _invalid((first, second), heads)


def test_takeover_capability_identity_reuse_fails_at_reader_boundary(
    tmp_path: Path,
) -> None:
    with CompanyLedger(tmp_path / "takeover-ledger.sqlite3") as ledger:
        first = ledger.append(
            ledger_support.takeover_request("takeover-tx-1", "takeover-cmd-1"),
            recorded_at=ledger_support.T,
        ).record
    request = ledger_support.takeover_request(
        "takeover-tx-2",
        "takeover-cmd-2",
        global_sequence=1,
        global_hash=str(first.receipt["transaction_sha256"]),
        cursor=2,
        event_hash=first.events[-1].event_sha256,
    )
    receipt = CompanyLedger._receipt(
        request,
        "failed_known",
        ledger_support.T,
        2,
        str(first.receipt["transaction_sha256"]),
        [],
        [],
    )
    second = LedgerTransactionRecord(
        2,
        request,
        receipt,
        (),
        tuple(LedgerReservationRecord(event) for event in request["events"]),
    )
    heads = CompanyHistoricalLedgerHeads(
        ("company-1", 1, 1),
        (2, str(receipt["transaction_sha256"])),
        (("org", 2, first.events[-1].event_sha256),),
    )
    _invalid((first, second), heads)


def test_malformed_subclass_and_bool_inputs_fail_closed(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)

    class DerivedHeads(LedgerHeadsSnapshot):
        pass

    class DerivedRecord(LedgerTransactionRecord):
        pass

    with pytest.raises(CompanyStateReaderError):
        immutable_ledger_heads(DerivedHeads(None, LedgerHead(0, ZERO_SHA256), {}))
    with pytest.raises(CompanyStateReaderError):
        immutable_ledger_heads(LedgerHeadsSnapshot(None, LedgerHead(True, ZERO_SHA256), {}))
    _invalid((DerivedRecord(
        records[0].global_sequence, records[0].request, records[0].receipt,
        records[0].events, records[0].reservations,
    ), *records[1:]), heads)
    _invalid(records, CompanyHistoricalLedgerHeads(
        heads.identity, (True, heads.global_head[1]), heads.stream_heads,
    ))


def test_replay_witness_is_deep_immutable_and_has_no_dict(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)
    replay = CompanyHistoricalReplayInput(
        records=records, heads=heads, state_root=tmp_path.resolve(),
        pointer_sha256=H, ledger_status="ready", projection_status="ready",
        blob_status="ready", degradation_reasons=(),
    )

    assert not hasattr(heads, "__dict__")
    assert not hasattr(replay, "__dict__")
    assert type(heads.stream_heads) is tuple
    with pytest.raises(AttributeError):
        heads.global_head = (0, ZERO_SHA256)  # type: ignore[misc]
    assert immutable_historical_replay_input(replay).heads == heads

    class DerivedReplay(CompanyHistoricalReplayInput):
        pass

    with pytest.raises(CompanyStateReaderError):
        immutable_historical_replay_input(DerivedReplay(
            records=replay.records,
            heads=replay.heads,
            state_root=replay.state_root,
            pointer_sha256=replay.pointer_sha256,
            ledger_status=replay.ledger_status,
            projection_status=replay.projection_status,
            blob_status=replay.blob_status,
            degradation_reasons=replay.degradation_reasons,
        ))
    with pytest.raises(CompanyStateReaderError):
        immutable_historical_replay_input(
            replace(replay, degradation_reasons=(True,)),
        )


def test_caller_mutation_after_validation_cannot_change_replay(
    tmp_path: Path,
) -> None:
    records, heads = _history(tmp_path)
    mutable_request = _thaw(records[0].request)
    caller_records = (
        replace(records[0], request=mutable_request),
        *records[1:],
    )
    caller = CompanyHistoricalReplayInput(
        records=caller_records,
        heads=heads,
        state_root=tmp_path.resolve(),
        pointer_sha256=H,
        ledger_status="ready",
        projection_status="ready",
        blob_status="ready",
        degradation_reasons=(),
    )

    frozen = immutable_historical_replay_input(caller)
    mutable_request["events"][0]["event_type"] = "mutated-after-validation"

    assert frozen.records[0].request["events"][0]["event_type"] == "recorded"
    with pytest.raises(TypeError):
        frozen.records[0].request["events"][0]["event_type"] = "mutate"  # type: ignore[index]
    assert immutable_historical_replay_input(frozen) == frozen


def test_recursive_caller_record_is_a_typed_error(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)
    recursive: dict[str, Any] = {}
    recursive["self"] = recursive
    malformed = replace(records[0], request=recursive)

    with pytest.raises(CompanyStateReaderError):
        validate_historical_ledger_snapshot((malformed, *records[1:]), heads)


def test_mapping_traversal_failure_is_a_typed_error(tmp_path: Path) -> None:
    records, heads = _history(tmp_path)

    class RaisingItems(dict[Any, Any]):
        def items(self) -> Any:
            raise RuntimeError("caller mapping traversal failed")

    class MalformedItems(dict[Any, Any]):
        def items(self) -> Any:
            return (("not-a-pair",),)

    class DuplicateItems(dict[Any, Any]):
        def items(self) -> Any:
            pairs = tuple(dict.items(self))
            return (*pairs, pairs[0])

    malformed = replace(
        records[0],
        request=RaisingItems(dict(records[0].request)),
    )
    with pytest.raises(CompanyStateReaderError, match="cannot be traversed"):
        validate_historical_ledger_snapshot((malformed, *records[1:]), heads)
    malformed_pair = replace(
        records[0],
        request=MalformedItems(dict(records[0].request)),
    )
    with pytest.raises(CompanyStateReaderError, match="exact pairs"):
        validate_historical_ledger_snapshot(
            (malformed_pair, *records[1:]),
            heads,
        )
    duplicate_key = replace(
        records[0],
        request=DuplicateItems(dict(records[0].request)),
    )
    with pytest.raises(CompanyStateReaderError, match="duplicate key"):
        validate_historical_ledger_snapshot(
            (duplicate_key, *records[1:]),
            heads,
        )

    live_heads = LedgerHeadsSnapshot(
        identity=heads.identity,
        global_head=LedgerHead(*heads.global_head),
        stream_heads=RaisingItems({
            stream: (cursor, digest)
            for stream, cursor, digest in heads.stream_heads
        }),
    )
    with pytest.raises(CompanyStateReaderError, match="cannot be traversed"):
        immutable_ledger_heads(live_heads)
    with pytest.raises(CompanyStateReaderError, match="exact pairs"):
        immutable_ledger_heads(replace(
            live_heads,
            stream_heads=MalformedItems(),
        ))
    with pytest.raises(CompanyStateReaderError, match="duplicate key"):
        immutable_ledger_heads(replace(
            live_heads,
            stream_heads=DuplicateItems({
                "org": (1, H),
            }),
        ))


@pytest.mark.parametrize(
    "failure",
    (MemoryError("memory"), SystemExit("exit"), KeyboardInterrupt("interrupt")),
)
def test_mapping_traversal_does_not_swallow_process_failures(
    failure: BaseException,
) -> None:
    class FatalItems(dict[Any, Any]):
        def items(self) -> Any:
            raise failure

    heads = LedgerHeadsSnapshot(
        identity=None,
        global_head=LedgerHead(0, ZERO_SHA256),
        stream_heads=FatalItems(),
    )
    with pytest.raises(type(failure)):
        immutable_ledger_heads(heads)


def test_public_raw_ledger_is_a_non_mutating_tombstone(tmp_path: Path) -> None:
    owner = checkpoint_support.initialized(tmp_path)
    try:
        before = owner.heads().global_head
        with pytest.raises(CompanyStateError, match="raw company ledger access"):
            _ = owner.ledger
        with pytest.raises(AttributeError):
            owner.ledger = object()  # type: ignore[misc]
        with pytest.raises(AttributeError):
            _ = owner._ledger  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            _ = owner._ledger_store  # type: ignore[attr-defined]
        owner.__dict__["ledger"] = object()
        with pytest.raises(CompanyStateError, match="use heads.*commit"):
            _ = owner.ledger
        assert owner.heads().global_head == before
    finally:
        owner.close()
    with pytest.raises(CompanyStateError, match="raw company ledger access"):
        _ = owner.ledger


def test_out_of_band_database_append_fails_closed(tmp_path: Path) -> None:
    owner = checkpoint_support.initialized(tmp_path)
    blob = {
        "contract_type": "blob_ref_v1",
        "schema_version": 1,
        "sha256": "e" * 64,
        "size_bytes": 1,
        "media_type": "text/plain",
        "availability": "unavailable",
    }
    try:
        request = checkpoint_support.request(owner, blob, 2)
        with CompanyLedger(owner.resolved.incarnation.ledger) as raw:
            raw.append(request, recorded_at=T)
        with pytest.raises(
            LedgerOwnershipError,
            match="cursor advanced outside this writer instance",
        ):
            owner.health()
    finally:
        owner.close()


def test_public_owner_reads_and_commit_preserve_verified_history(
    tmp_path: Path,
) -> None:
    owner = checkpoint_support.initialized(tmp_path)
    first_records = owner.records_after(0)
    try:
        replay = owner.historical_replay_input()
        assert replay.records == first_records
        assert replay.heads.global_head[0] == 1
        blob = {
            "contract_type": "blob_ref_v1",
            "schema_version": 1,
            "sha256": "e" * 64,
            "size_bytes": 1,
            "media_type": "text/plain",
            "availability": "unavailable",
        }
        owner.commit(checkpoint_support.request(owner, blob, 2), recorded_at=T)
        assert owner.heads().global_head.global_sequence == 2
        assert len(owner.records_after(0)) == 2
        assert owner.record_by_transaction_id("tx-2") is not None
        assert owner.record_by_command_id("cmd-2") is not None
    finally:
        owner.close()
