from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1, BLOB_REF_V1, COMPANY_EVENT_V1,
    COMPANY_TRANSACTION_REQUEST_V1, EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1, TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1, ZERO_SHA256,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import (
    CompanyLedger, LedgerBusyError, LedgerConflictError, LedgerCorruptionError,
    LedgerCommitEffectUnknownError, LedgerCrashInjected,
    LedgerOwnershipError, LedgerRecoveryRequiredError, LedgerSnapshotError,
)


B = {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1}
T = "2026-07-26T00:00:00Z"
H = "a" * 64
TRANSACTIONS_NO_UPDATE_DDL = """CREATE TRIGGER transactions_no_update BEFORE UPDATE ON transactions
BEGIN SELECT RAISE(ABORT, 'transactions are append-only'); END"""
TAKEOVER_CONSUMPTIONS_NO_UPDATE_DDL = """CREATE TRIGGER takeover_consumptions_no_update BEFORE UPDATE ON takeover_consumptions
BEGIN SELECT RAISE(ABORT, 'takeover consumptions are append-only'); END"""


def blob() -> dict[str, Any]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": H,
            "size_bytes": 1, "media_type": "text/plain", "availability": "available"}


def authority(binding: dict[str, Any] = B) -> dict[str, Any]:
    return {"contract_type": ACTOR_AUTHORITY_V1, "schema_version": 1, **binding, "actor_id": "chief-1", "actor_kind": "chief", "carrier_id": "carrier-1", "chief_epoch": 1, "term": 1, "authority_state": "active", "permissions": ["company.mutate"], "scope_sha256": H, "authority_record_sha256": H, "provenance": "AOI_verified"}


def request(
    tx: str = "tx-1", command: str = "cmd-1", *, stream: str = "org",
    streams: tuple[str, ...] | None = None, event_id: str | None = None,
    global_sequence: int = 0, global_hash: str = ZERO_SHA256, cursor: int = 0,
    event_hash: str = ZERO_SHA256, binding: dict[str, Any] = B,
) -> dict[str, Any]:
    auth = authority(binding)
    # Canonical JSON deliberately rejects shared mutable containers, so the
    # independently embedded authority record must also have independent bytes.
    event_streams = streams or (stream,)
    events = []
    for index, event_stream in enumerate(event_streams):
        payload = {"tx": tx, "index": index}
        events.append({"contract_type": COMPANY_EVENT_V1, "schema_version": 1, **binding, "transaction_id": tx, "command_id": command, "event_id": event_id if index == 0 and event_id is not None else f"event-{tx}-{index}", "stream": event_stream, "event_type": "recorded", "recorded_at": T, "actor_authority": copy.deepcopy(auth), "provenance": "AOI_verified", "payload": payload, "payload_sha256": company_contract_sha256(payload)})
    heads = []
    for event_stream in dict.fromkeys(event_streams):
        heads.append({"contract_type": EXPECTED_HEAD_V1, "schema_version": 1, **binding, "transaction_id": tx, "command_id": command, "stream": event_stream, "cursor": cursor, "event_sha256": event_hash})
    global_head = {"contract_type": EXPECTED_TRANSACTION_HEAD_V1, "schema_version": 1, **binding, "transaction_id": tx, "command_id": command, "global_sequence": global_sequence, "transaction_sha256": global_hash}
    value = {"contract_type": COMPANY_TRANSACTION_REQUEST_V1, "schema_version": 1, **binding, "transaction_id": tx, "command_id": command, "actor_authority": auth, "expected_transaction_head": global_head, "expected_heads": heads, "events": events}
    value["request_sha256"] = company_contract_sha256(value)
    return value


def takeover_request(
    tx: str,
    command: str,
    *,
    capability_id: str = "capability-1",
    global_sequence: int = 0,
    global_hash: str = ZERO_SHA256,
    cursor: int = 0,
    event_hash: str = ZERO_SHA256,
) -> dict[str, Any]:
    capability_unsigned = {
        "contract_type": TAKEOVER_CAPABILITY_V1,
        "schema_version": 1,
        **B,
        "capability_id": capability_id,
        "contender_carrier_id": f"carrier-{tx}",
        "expected_chief_id": "chief-1",
        "expected_term": 1,
        "expected_epoch": 1,
        "expected_head_sha256": global_hash,
        "consumption_id": f"consumption-{tx}",
        "consumption_transaction_id": tx,
        "consumption_command_id": command,
        "resulting_chief_id": "chief-1",
        "resulting_term": 2,
        "resulting_epoch": 2,
        "objective_sha256": "b" * 64,
        "scope_sha256": "c" * 64,
        "nonce_sha256": "d" * 64,
        "issued_at": "2026-07-26T00:00:00Z",
        "expires_at": "2026-07-27T00:00:00Z",
        "user_action_ref": f"user-action-{tx}",
    }
    capability = {
        **capability_unsigned,
        "capability_sha256": company_contract_sha256(
            capability_unsigned,
        ),
    }
    receipt_unsigned = {
        "contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1,
        "schema_version": 1,
        **B,
        "consumption_id": capability["consumption_id"],
        "transaction_id": tx,
        "command_id": command,
        "capability": copy.deepcopy(capability),
        "capability_sha256": capability["capability_sha256"],
        "outcome": "fenced",
        "resulting_chief_term": None,
        "consumed_at": "2026-07-26T00:00:01Z",
    }
    receipt = {
        **receipt_unsigned,
        "receipt_sha256": company_contract_sha256(receipt_unsigned),
    }
    auth = authority()
    events = []
    for suffix, payload in (
        ("capability", capability),
        ("receipt", receipt),
    ):
        events.append({
            "contract_type": COMPANY_EVENT_V1,
            "schema_version": 1,
            **B,
            "transaction_id": tx,
            "command_id": command,
            "event_id": f"event-{tx}-{suffix}",
            "stream": "org",
            "event_type": f"takeover.{suffix}",
            "recorded_at": "2026-07-26T00:00:01Z",
            "actor_authority": copy.deepcopy(auth),
            "provenance": "AOI_verified",
            "payload": copy.deepcopy(payload),
            "payload_sha256": company_contract_sha256(payload),
        })
    value = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1,
        "schema_version": 1,
        **B,
        "transaction_id": tx,
        "command_id": command,
        "actor_authority": auth,
        "expected_transaction_head": {
            "contract_type": EXPECTED_TRANSACTION_HEAD_V1,
            "schema_version": 1,
            **B,
            "transaction_id": tx,
            "command_id": command,
            "global_sequence": global_sequence,
            "transaction_sha256": global_hash,
        },
        "expected_heads": [{
            "contract_type": EXPECTED_HEAD_V1,
            "schema_version": 1,
            **B,
            "transaction_id": tx,
            "command_id": command,
            "stream": "org",
            "cursor": cursor,
            "event_sha256": event_hash,
        }],
        "events": events,
    }
    value["request_sha256"] = company_contract_sha256(value)
    return value


def rewrite_second_request_to_forged_genesis(
    ledger: CompanyLedger,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Canonicalize a forged tx2 request/receipt while preserving row shape."""
    with sqlite3.connect(ledger.path) as connection:
        row = connection.execute(
            "SELECT request_bytes, receipt_bytes FROM transactions "
            "WHERE transaction_id='tx-2'"
        ).fetchone()
        assert row is not None
        forged_request = json.loads(bytes(row[0]))
        forged_request["expected_transaction_head"]["global_sequence"] = 0
        forged_request["expected_transaction_head"]["transaction_sha256"] = ZERO_SHA256
        for expected_head in forged_request["expected_heads"]:
            expected_head["cursor"] = 0
            expected_head["event_sha256"] = ZERO_SHA256
        forged_request["request_sha256"] = company_contract_sha256({
            key: value for key, value in forged_request.items()
            if key != "request_sha256"
        })

        forged_receipt = json.loads(bytes(row[1]))
        forged_receipt["request_sha256"] = forged_request["request_sha256"]
        forged_receipt.pop("transaction_sha256")
        forged_receipt.pop("receipt_sha256")
        forged_receipt["transaction_sha256"] = company_contract_sha256(
            forged_receipt
        )
        forged_receipt["receipt_sha256"] = company_contract_sha256(
            forged_receipt
        )

        connection.execute("DROP TRIGGER transactions_no_update")
        connection.execute(
            "UPDATE transactions SET request_sha256=?, request_bytes=?, "
            "receipt_sha256=?, receipt_bytes=? WHERE transaction_id='tx-2'",
            (
                forged_request["request_sha256"],
                canonical_company_json_bytes(forged_request),
                forged_receipt["receipt_sha256"],
                canonical_company_json_bytes(forged_receipt),
            ),
        )
        connection.execute(TRANSACTIONS_NO_UPDATE_DDL)
    return forged_request, forged_receipt


def test_strict_wal_append_and_exact_retry(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    replay = ledger.append(request())
    assert first.receipt == replay.receipt and replay.idempotent_replay
    assert first.record == replay.record
    assert first.record.global_sequence == 1
    assert first.record.request["request_sha256"] == request()["request_sha256"]
    assert first.record.receipt["receipt_sha256"] == first.receipt["receipt_sha256"]
    assert first.record.receipt["transaction_id"] == first.receipt["transaction_id"]
    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM transactions")
    ledger.verify_integrity()


def test_takeover_consumption_is_atomic_single_use_and_exactly_replayable(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "takeover.sqlite3")
    first_request = takeover_request("takeover-tx-1", "takeover-cmd-1")
    first = ledger.append(first_request)
    replay = ledger.append(first_request)
    assert replay.idempotent_replay
    assert replay.receipt == first.receipt
    with sqlite3.connect(ledger.path) as connection:
        row = connection.execute(
            "SELECT * FROM takeover_consumptions",
        ).fetchone()
        assert row is not None
        assert row[0] == "capability-1"
        assert row[1] == "consumption-takeover-tx-1"
        assert row[2] == "takeover-tx-1"
        assert row[6] == "fenced"
        assert row[7] == "committed"

    org_head = first.receipt["result_heads"][0]
    divergent = takeover_request(
        "takeover-tx-2",
        "takeover-cmd-2",
        capability_id="capability-1",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=org_head["cursor"],
        event_hash=org_head["event_sha256"],
    )
    with pytest.raises(LedgerCorruptionError, match="already used"):
        ledger.append(divergent)
    assert ledger.current_head().global_sequence == 1
    ledger.verify_integrity()


def test_takeover_registry_crash_atomicity_and_tamper_detection(
    tmp_path: Path,
) -> None:
    before = CompanyLedger(tmp_path / "takeover-before.sqlite3")
    with pytest.raises(LedgerCrashInjected, match="before"):
        before.append(
            takeover_request("takeover-before", "takeover-before-command"),
            crash_at="before_commit",
        )
    with sqlite3.connect(before.path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM transactions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM takeover_consumptions",
        ).fetchone()[0] == 0
    before.close()

    path = tmp_path / "takeover-after.sqlite3"
    after = CompanyLedger(path)
    with pytest.raises(LedgerCrashInjected, match="after"):
        after.append(
            takeover_request("takeover-after", "takeover-after-command"),
            crash_at="after_commit",
        )
    after.close()
    reopened = CompanyLedger(path)
    assert reopened.current_head().global_sequence == 1
    reopened.verify_integrity()
    reopened.close()

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER takeover_consumptions_no_update")
        connection.execute(
            "UPDATE takeover_consumptions SET outcome='consumed'",
        )
        connection.execute(TAKEOVER_CONSUMPTIONS_NO_UPDATE_DDL)
    with pytest.raises(LedgerCorruptionError, match="takeover"):
        CompanyLedger(path)


def test_bounded_head_snapshot_does_not_scan_full_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    expected_event = first.record.events[0]

    def reject_full_scan() -> tuple[Any, ...]:
        raise AssertionError("hot head API must not scan full history")

    monkeypatch.setattr(ledger, "load_records", reject_full_scan)
    snapshot = ledger.snapshot_heads()
    assert snapshot.identity == ("company-1", 1, 1)
    assert snapshot.global_head.global_sequence == 1
    assert (
        snapshot.global_head.transaction_sha256
        == first.receipt["transaction_sha256"]
    )
    assert snapshot.stream_heads == {
        "org": (
            expected_event.stream_sequence,
            expected_event.event_sha256,
        ),
    }
    with pytest.raises(TypeError):
        snapshot.stream_heads["org"] = (0, ZERO_SHA256)  # type: ignore[index]
    assert ledger.current_head() == snapshot.global_head


def test_records_after_returns_bounded_chain_checked_slices(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    second_request = request(
        "tx-2",
        "cmd-2",
        streams=("execution", "evidence"),
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
    )
    second = ledger.append(second_request)
    first_org_head = first.receipt["result_heads"][0]
    terminal_request = request(
        "tx-3",
        "cmd-3",
        global_sequence=2,
        global_hash=second.receipt["transaction_sha256"],
        cursor=first_org_head["cursor"],
        event_hash=first_org_head["event_sha256"],
    )
    terminal = ledger.append(terminal_request, state="effect_unknown")

    first_page = ledger.records_after(0, limit=2)
    second_page = ledger.records_after(2, limit=2)
    assert [record.global_sequence for record in first_page] == [1, 2]
    assert [record.global_sequence for record in second_page] == [3]
    assert second_page[0] == terminal.record
    assert second_page[0].events == ()
    assert len(second_page[0].reservations) == 1
    assert ledger.records_after(3) == ()
    assert (*first_page, *second_page) == ledger.load_records()

    with pytest.raises(LedgerConflictError):
        ledger.records_after(4)
    for invalid in (-1, True, 1.5):
        with pytest.raises(ValueError):
            ledger.records_after(invalid)  # type: ignore[arg-type]
    for invalid_limit in (0, 4097, True):
        with pytest.raises(ValueError):
            ledger.records_after(0, limit=invalid_limit)


def test_bounded_transaction_and_command_lookup_survive_head_advance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = CompanyLedger(tmp_path / "lookup.sqlite3")
    first = ledger.append(request())
    first_head = first.receipt["result_heads"][0]
    ledger.append(
        request(
            "tx-2",
            "cmd-2",
            global_sequence=1,
            global_hash=first.receipt["transaction_sha256"],
            cursor=1,
            event_hash=first_head["event_sha256"],
        ),
    )

    def reject_full_scan() -> tuple[Any, ...]:
        raise AssertionError("bounded lookup must not scan full history")

    monkeypatch.setattr(ledger, "load_records", reject_full_scan)
    assert ledger.record_by_transaction_id("tx-1") == first.record
    assert ledger.record_by_command_id("cmd-1") == first.record
    assert ledger.record_by_transaction_id("missing") is None
    assert ledger.record_by_command_id("missing") is None


@pytest.mark.parametrize("lookup", ("transaction", "command"))
@pytest.mark.parametrize("invalid", ("", "\x00", "x" * 257, 7, None))
def test_bounded_lookup_rejects_malformed_identifiers(
    tmp_path: Path,
    lookup: str,
    invalid: object,
) -> None:
    ledger = CompanyLedger(tmp_path / f"lookup-{lookup}.sqlite3")
    method = (
        ledger.record_by_transaction_id
        if lookup == "transaction"
        else ledger.record_by_command_id
    )
    with pytest.raises(ValueError):
        method(invalid)  # type: ignore[arg-type]


def test_canonical_cas_history_rewrite_blocks_load_replay_and_extension(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    first_head = first.receipt["result_heads"][0]
    second_request = request(
        "tx-2", "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=1,
        event_hash=first_head["event_sha256"],
    )
    second = ledger.append(second_request)
    forged_request, forged_receipt = rewrite_second_request_to_forged_genesis(
        ledger
    )
    extension = request(
        "tx-3", "cmd-3",
        global_sequence=2,
        global_hash=forged_receipt["transaction_sha256"],
        cursor=2,
        event_hash=second.receipt["result_heads"][0]["event_sha256"],
    )

    with pytest.raises(LedgerCorruptionError):
        ledger.load_records()
    assert ledger.health == "quarantined"
    with pytest.raises(LedgerRecoveryRequiredError):
        ledger.append(forged_request)
    with pytest.raises(LedgerRecoveryRequiredError):
        ledger.append(extension)
    with pytest.raises(LedgerCorruptionError):
        ledger.recover()
    with pytest.raises(LedgerCorruptionError):
        CompanyLedger(ledger.path)


def test_row_state_tamper_blocks_replay_extension_and_reopen(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER transactions_no_update")
        connection.execute(
            "UPDATE transactions SET state='failed_known' "
            "WHERE transaction_id='tx-1'"
        )
        connection.execute(TRANSACTIONS_NO_UPDATE_DDL)
    extension = request(
        "tx-2", "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=1,
        event_hash=first.receipt["result_heads"][0]["event_sha256"],
    )

    with pytest.raises(LedgerCorruptionError):
        ledger.append(request())
    assert ledger.health == "quarantined"
    with pytest.raises(LedgerRecoveryRequiredError):
        ledger.append(extension)
    with pytest.raises(LedgerCorruptionError):
        ledger.load_records()
    with pytest.raises(LedgerCorruptionError):
        CompanyLedger(ledger.path)


@pytest.mark.parametrize(
    "unexpected_ddl",
    (
        "CREATE INDEX unexpected_transactions_state ON transactions(state)",
        "CREATE VIEW unexpected_transaction_ids AS SELECT transaction_id FROM transactions",
        "CREATE TABLE unexpected_metadata (value TEXT) STRICT",
        "CREATE TRIGGER unexpected_insert AFTER INSERT ON transactions BEGIN SELECT 1; END",
    ),
)
def test_unexpected_application_schema_objects_fail_closed(
    tmp_path: Path, unexpected_ddl: str,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    with sqlite3.connect(ledger.path) as connection:
        connection.execute(unexpected_ddl)
    with pytest.raises(LedgerCorruptionError):
        ledger.load_records()
    with pytest.raises(LedgerCorruptionError):
        CompanyLedger(ledger.path)


def test_global_and_stream_cas_and_multistream_atomicity(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    stale = request("tx-2", "cmd-2")
    with pytest.raises(LedgerConflictError):
        ledger.append(stale)
    second = request("tx-2", "cmd-2", global_sequence=1, global_hash=first.receipt["transaction_sha256"], cursor=1, event_hash=first.receipt["result_heads"][0]["event_sha256"])
    assert ledger.append(second).receipt["global_sequence"] == 2
    ledger.verify_integrity()


def test_divergent_identifiers_and_terminal_reservation_fail_closed(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    terminal = ledger.append(request(), state="effect_unknown")
    assert terminal.receipt["result_heads"] == []
    assert ledger.append(request(), state="effect_unknown").idempotent_replay
    changed = copy.deepcopy(request()); changed["events"][0]["payload"] = {"tx": "changed"}; changed["events"][0]["payload_sha256"] = company_contract_sha256({"tx": "changed"}); changed["request_sha256"] = company_contract_sha256({k: v for k, v in changed.items() if k != "request_sha256"})
    with pytest.raises(LedgerCorruptionError):
        ledger.append(changed, state="effect_unknown")
    reserved_id = request()["events"][0]["event_id"]
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-next", "cmd-next", global_sequence=1, global_hash=terminal.receipt["transaction_sha256"], event_id=reserved_id))
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-next", "cmd-next", global_sequence=1, global_hash=terminal.receipt["transaction_sha256"], event_id=reserved_id), state="failed_known")
    ledger.verify_integrity()


def test_divergent_transaction_command_and_committed_event_ids_fail_closed(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request())
    kwargs = {"global_sequence": 1, "global_hash": first.receipt["transaction_sha256"], "cursor": 1, "event_hash": first.receipt["result_heads"][0]["event_sha256"]}
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-other", "cmd-1", **kwargs))
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-1", "cmd-other", **kwargs))
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-other", "cmd-other", event_id=request()["events"][0]["event_id"], **kwargs))
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-other", "cmd-other", event_id=request()["events"][0]["event_id"], **kwargs), state="failed_known")
    ledger.verify_integrity()


def test_retry_outcome_is_immutable_and_company_identity_is_fixed(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request(), state="failed_known")
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request())
    other = {**B, "company_id": "company-2"}
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request("tx-2", "cmd-2", binding=other, global_sequence=1, global_hash=first.receipt["transaction_sha256"]))
    ledger.verify_integrity()


def test_retry_cannot_silently_change_evidence_or_explicit_recorded_at(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    ledger.append(request(), evidence=[blob()], recorded_at=T)
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request(), recorded_at=T)
    with pytest.raises(LedgerCorruptionError):
        ledger.append(request(), evidence=[blob()], recorded_at="2026-07-26T00:00:01Z")


def test_same_stream_events_chain_in_request_order_and_receipt_keeps_final_head(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    result = ledger.append(request(streams=("org", "org")))
    assert len(result.receipt["result_heads"]) == 1
    assert result.receipt["result_heads"][0]["cursor"] == 2
    with sqlite3.connect(ledger.path) as connection:
        rows = connection.execute("SELECT stream_sequence FROM events ORDER BY stream_sequence").fetchall()
    assert rows == [(1,), (2,)]
    ledger.verify_integrity()


def test_authoritative_read_api_is_immutable_ordered_and_fails_closed(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    first = ledger.append(request(streams=("org", "org")))
    terminal = ledger.append(request("tx-2", "cmd-2", global_sequence=1, global_hash=first.receipt["transaction_sha256"], cursor=2, event_hash=first.receipt["result_heads"][0]["event_sha256"]), state="failed_known")
    records = ledger.load_records()
    assert [record.global_sequence for record in records] == [1, 2]
    assert [event.stream_sequence for event in records[0].events] == [1, 2]
    assert not records[0].reservations and len(records[1].reservations) == 1
    assert ledger.current_head().transaction_sha256 == terminal.receipt["transaction_sha256"]
    with pytest.raises(TypeError):
        records[0].request["company_id"] = "mutated"  # type: ignore[index]
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER events_no_update")
        connection.execute("UPDATE events SET event_sha256=? WHERE stream_sequence=1", ("b" * 64,))
    with pytest.raises(LedgerCorruptionError):
        ledger.load_records()


def test_crash_boundaries_have_exact_retry_semantics(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    with pytest.raises(LedgerCrashInjected):
        ledger.append(request(), crash_at="before_commit")
    assert not ledger.append(request()).idempotent_replay
    second = request("tx-2", "cmd-2", global_sequence=1, global_hash=ledger.append(request()).receipt["transaction_sha256"], cursor=1, event_hash=ledger.append(request()).receipt["result_heads"][0]["event_sha256"])
    # The preceding exact retries intentionally do not advance the ledger.
    with pytest.raises(LedgerCrashInjected):
        ledger.append(second, crash_at="after_commit")
    assert ledger.health == "recovery_required"
    with pytest.raises(LedgerRecoveryRequiredError):
        ledger.append(second)
    ledger.recover()
    assert ledger.append(second).idempotent_replay
    ledger.verify_integrity()


def test_hard_process_exit_before_and_after_commit_has_exact_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "hard-crash.sqlite3"
    test_source = Path(__file__).resolve()
    child = r"""
import runpy
import sys
from pathlib import Path
from aoi_orgware.company.ledger import CompanyLedger

database = Path(sys.argv[1])
mode = sys.argv[2]
namespace = runpy.run_path(sys.argv[3])
make_request = namespace["request"]
ledger = CompanyLedger(database)
if mode == "before":
    candidate = make_request()
    ledger.append(candidate, crash_at="hard_before_commit")
records = ledger.load_records()
first = records[-1]
head = first.receipt["result_heads"][0]
candidate = make_request(
    "tx-2", "cmd-2",
    global_sequence=first.global_sequence,
    global_hash=first.receipt["transaction_sha256"],
    cursor=head["cursor"],
    event_hash=head["event_sha256"],
)
ledger.append(candidate, crash_at="hard_after_commit")
"""
    environment = os.environ.copy()

    before = subprocess.run(
        [sys.executable, "-c", child, str(path), "before", str(test_source)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert before.returncode == 91, before.stderr
    ledger = CompanyLedger(path)
    assert ledger.load_records() == ()
    first = ledger.append(request())
    ledger.close()

    after = subprocess.run(
        [sys.executable, "-c", child, str(path), "after", str(test_source)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert after.returncode == 92, after.stderr
    recovered = CompanyLedger(path)
    records = recovered.load_records()
    assert len(records) == 2
    head = first.receipt["result_heads"][0]
    second_request = request(
        "tx-2", "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=head["cursor"],
        event_hash=head["event_sha256"],
    )
    assert recovered.append(second_request).idempotent_replay


def test_tampered_bytes_are_detected(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    ledger.append(request())
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER events_no_update")
        connection.execute("UPDATE events SET event_sha256=?", ("b" * 64,))
    with pytest.raises(LedgerCorruptionError):
        ledger.verify_integrity()
    with pytest.raises(LedgerCorruptionError):
        CompanyLedger(ledger.path)


def test_same_name_weakened_trigger_and_reopen_are_rejected(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER events_no_update")
        connection.execute("CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT 1; END")
    with pytest.raises(LedgerCorruptionError):
        CompanyLedger(ledger.path)


def test_busy_writer_is_not_misclassified_as_corruption(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3", busy_timeout_ms=1)
    with sqlite3.connect(ledger.path, isolation_level=None) as holder:
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(LedgerBusyError):
            ledger.append(request())
        holder.execute("ROLLBACK")


def test_busy_constructor_is_typed_and_closes_its_partial_handle(
    tmp_path: Path,
) -> None:
    path = tmp_path / "busy-constructor.sqlite3"
    holder = sqlite3.connect(path, isolation_level=None, timeout=0)
    captured: LedgerBusyError | None = None
    try:
        holder.execute("BEGIN EXCLUSIVE")
        with pytest.raises(LedgerBusyError) as error:
            CompanyLedger(path, busy_timeout_ms=1)
        captured = error.value
    finally:
        if holder.in_transaction:
            holder.execute("ROLLBACK")
        holder.close()

    assert captured is not None
    moved = tmp_path / "busy-constructor-moved.sqlite3"
    path.replace(moved)
    assert moved.exists()


def test_constructor_verification_uses_one_sqlite_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "constructor-snapshot.sqlite3"
    writer = CompanyLedger(path)
    snapshot_established = threading.Event()
    allow_verification = threading.Event()
    outcomes: list[object] = []
    original = CompanyLedger._verified_state

    def interleaved_verification(
        self: CompanyLedger, connection: sqlite3.Connection,
    ) -> Any:
        if threading.current_thread().name == "constructor-race":
            # This first read fixes the deferred transaction's WAL snapshot.
            connection.execute("SELECT COUNT(*) FROM events").fetchone()
            snapshot_established.set()
            assert allow_verification.wait(5)
        return original(self, connection)

    monkeypatch.setattr(
        CompanyLedger, "_verified_state", interleaved_verification,
    )

    def reopen() -> None:
        try:
            outcomes.append(CompanyLedger(path))
        except BaseException as exc:  # pragma: no cover - assertion reports it
            outcomes.append(exc)

    constructor = threading.Thread(target=reopen, name="constructor-race")
    constructor.start()
    assert snapshot_established.wait(5)
    try:
        writer.append(request())
    finally:
        allow_verification.set()
    constructor.join(10)

    assert len(outcomes) == 1
    assert isinstance(outcomes[0], CompanyLedger), outcomes[0]
    assert len(outcomes[0].load_records()) == 1


def test_two_concurrent_fresh_constructors_publish_one_complete_schema(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fresh-race.sqlite3"
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def construct() -> None:
        barrier.wait(timeout=5)
        try:
            outcomes.append(CompanyLedger(path))
        except BaseException as exc:  # pragma: no cover - assertion reports it
            outcomes.append(exc)

    left = threading.Thread(target=construct)
    right = threading.Thread(target=construct)
    left.start()
    right.start()
    left.join(10)
    right.join(10)

    assert len(outcomes) == 2
    assert all(
        isinstance(item, (CompanyLedger, LedgerBusyError))
        for item in outcomes
    ), outcomes
    assert any(isinstance(item, CompanyLedger) for item in outcomes)
    for item in outcomes:
        if isinstance(item, CompanyLedger):
            item.verify_integrity()
            item.close()
    reopened = CompanyLedger(path)
    reopened.verify_integrity()
    reopened.close()


def test_stale_writer_is_fenced_after_another_instance_advances(
    tmp_path: Path,
) -> None:
    path = tmp_path / "single-writer.sqlite3"
    winner = CompanyLedger(path)
    stale = CompanyLedger(path)
    first = winner.append(request())
    head = first.receipt["result_heads"][0]
    successor_request = request(
        "tx-2", "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=1,
        event_hash=head["event_sha256"],
    )

    with pytest.raises(LedgerOwnershipError):
        stale.append(successor_request)
    assert len(stale.load_records()) == 1


def test_external_sqlite_commit_without_head_change_quarantines_writer(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "external-commit.sqlite3")
    first = ledger.append(request())
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("PRAGMA user_version=7")
    with pytest.raises(LedgerCorruptionError):
        ledger.append(
            request(
                "tx-2", "cmd-2",
                global_sequence=1,
                global_hash=first.receipt["transaction_sha256"],
                cursor=1,
                event_hash=first.receipt["result_heads"][0]["event_sha256"],
            ),
        )
    assert ledger.health == "quarantined"


def test_close_releases_persistent_connection_and_fences_future_writes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "close.sqlite3"
    ledger = CompanyLedger(path)
    ledger.append(request())
    ledger.close()
    ledger.close()
    assert ledger.health == "closed"
    with pytest.raises(LedgerRecoveryRequiredError):
        ledger.append(request())
    moved = tmp_path / "closed-moved.sqlite3"
    path.replace(moved)
    assert moved.exists()


def test_database_guard_blocks_or_detects_path_replacement_during_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guarded.sqlite3"
    writer = CompanyLedger(path)
    writer.append(request())
    replacement_path = tmp_path / "replacement.sqlite3"
    replacement_binding = {
        "company_id": "company-2",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
    }
    replacement = CompanyLedger(replacement_path)
    replacement.append(request(binding=replacement_binding))
    replacement.close()

    if os.name == "nt":
        with pytest.raises(OSError):
            os.replace(replacement_path, path)
        writer.verify_integrity()
        writer.close()
        return

    os.replace(replacement_path, path)
    with pytest.raises(
        LedgerOwnershipError,
        match="path identity changed",
    ):
        writer.load_records()
    assert writer.health == "quarantined"
    with pytest.raises(LedgerOwnershipError, match="path identity changed"):
        writer.recover()
    assert writer.health == "quarantined"
    for read in (
        writer.load_records,
        writer.verify_integrity,
    ):
        with pytest.raises(
            LedgerOwnershipError,
            match="path identity changed",
        ):
            read()
    with pytest.raises(LedgerRecoveryRequiredError):
        writer.current_head()
    with pytest.raises(LedgerRecoveryRequiredError):
        writer.append(request())
    writer.close()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows guard prevents the replacement itself",
)
@pytest.mark.parametrize(
    "operation",
    (
        "load_records",
        "current_head",
        "verify_integrity",
        "recover",
        "record_by_transaction_id",
        "record_by_command_id",
    ),
)
def test_each_authoritative_read_detects_first_path_replacement(
    tmp_path: Path,
    operation: str,
) -> None:
    path = tmp_path / f"{operation}.sqlite3"
    writer = CompanyLedger(path)
    writer.append(request())
    replacement_path = tmp_path / f"{operation}-replacement.sqlite3"
    replacement = CompanyLedger(replacement_path)
    replacement.append(
        request(
            binding={
                "company_id": "company-2",
                "company_incarnation": 1,
                "lock_domain_generation": 1,
            },
        ),
    )
    replacement.close()
    os.replace(replacement_path, path)

    with pytest.raises(LedgerOwnershipError, match="path identity changed"):
        if operation == "record_by_transaction_id":
            writer.record_by_transaction_id("tx-1")
        elif operation == "record_by_command_id":
            writer.record_by_command_id("cmd-1")
        else:
            getattr(writer, operation)()
    assert writer.health == "quarantined"
    writer.close()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows guard prevents the replacement itself",
)
def test_append_post_commit_path_swap_is_effect_unknown_and_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "append-post-commit-swap.sqlite3"
    writer = CompanyLedger(path)
    first = writer.append(request())
    first_stream = first.receipt["result_heads"][0]
    candidate = request(
        "tx-2",
        "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=1,
        event_hash=first_stream["event_sha256"],
    )

    replacement_path = tmp_path / "append-post-commit-replacement.sqlite3"
    replacement = CompanyLedger(replacement_path)
    replacement.append(request())
    replacement.close()

    original_guard = writer._assert_database_guard
    guard_calls = 0

    def replace_immediately_before_post_commit_guard() -> None:
        nonlocal guard_calls
        guard_calls += 1
        # append calls the guard from _assert_hot_environment, immediately
        # before COMMIT, and finally after COMMIT but before acknowledgement.
        if guard_calls == 3:
            os.replace(replacement_path, path)
        original_guard()

    monkeypatch.setattr(
        writer,
        "_assert_database_guard",
        replace_immediately_before_post_commit_guard,
    )
    with pytest.raises(LedgerCommitEffectUnknownError) as raised:
        writer.append(candidate)
    assert raised.value.receipt["global_sequence"] == 2
    assert guard_calls == 3
    assert writer.health == "quarantined"
    with pytest.raises(LedgerRecoveryRequiredError):
        writer.append(candidate)
    writer.close()


@pytest.mark.skipif(os.name == "nt", reason="Windows guard prevents the replacement itself")
def test_constructor_rejects_path_swap_between_verification_and_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "constructor-swap.sqlite3"
    original = CompanyLedger(path)
    original.append(request())
    original.close()
    replacement_path = tmp_path / "constructor-replacement.sqlite3"
    replacement_binding = {
        "company_id": "company-2",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
    }
    replacement = CompanyLedger(replacement_path)
    replacement.append(request(binding=replacement_binding))
    replacement.close()

    original_verifier = CompanyLedger._verified_state
    swapped = False

    def verify_then_swap(
        ledger: CompanyLedger,
        connection: sqlite3.Connection,
    ) -> Any:
        nonlocal swapped
        verified = original_verifier(ledger, connection)
        if not swapped:
            os.replace(replacement_path, path)
            swapped = True
        return verified

    monkeypatch.setattr(CompanyLedger, "_verified_state", verify_then_swap)
    with pytest.raises(LedgerOwnershipError, match="path identity changed"):
        CompanyLedger(path)
    assert swapped


def test_external_old_row_and_stream_head_tamper_fail_closed(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "old-row-tamper.sqlite3")
    first = ledger.append(request())
    first_head = first.receipt["result_heads"][0]
    second = ledger.append(request(
        "tx-2", "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=1,
        event_hash=first_head["event_sha256"],
    ))
    second_head = second.receipt["result_heads"][0]
    next_request = request(
        "tx-3", "cmd-3",
        global_sequence=2,
        global_hash=second.receipt["transaction_sha256"],
        cursor=2,
        event_hash=second_head["event_sha256"],
    )
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER transactions_no_update")
        connection.execute(
            "UPDATE transactions SET state='failed_known' "
            "WHERE transaction_id='tx-1'",
        )
        connection.execute(TRANSACTIONS_NO_UPDATE_DDL)
    with pytest.raises(LedgerCorruptionError):
        ledger.append(next_request)
    with pytest.raises(LedgerCorruptionError):
        ledger.verify_integrity()
    with pytest.raises(LedgerCorruptionError):
        CompanyLedger(ledger.path)

    other = CompanyLedger(tmp_path / "stream-tamper.sqlite3")
    first = other.append(request())
    with sqlite3.connect(other.path) as connection:
        connection.execute("DROP TRIGGER events_no_update")
        connection.execute(
            "UPDATE events SET event_sha256=? WHERE stream='org'",
            ("c" * 64,),
        )
    with pytest.raises(LedgerCorruptionError):
        other.append(
            request(
                "tx-2", "cmd-2",
                global_sequence=1,
                global_hash=first.receipt["transaction_sha256"],
                cursor=1,
                event_hash=first.receipt["result_heads"][0]["event_sha256"],
            ),
        )


def test_hot_append_avoids_full_history_queries_and_sustains_20_per_second(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "hot-append.sqlite3")
    global_head = (0, ZERO_SHA256)
    stream_head = (0, ZERO_SHA256)
    started = time.perf_counter()
    for index in range(200):
        result = ledger.append(
            request(
                f"tx-{index}", f"cmd-{index}",
                global_sequence=global_head[0],
                global_hash=global_head[1],
                cursor=stream_head[0],
                event_hash=stream_head[1],
            ),
        )
        global_head = (
            result.receipt["global_sequence"],
            result.receipt["transaction_sha256"],
        )
        result_head = result.receipt["result_heads"][0]
        stream_head = (
            result_head["cursor"], result_head["event_sha256"],
        )
    elapsed = time.perf_counter() - started
    assert elapsed < 10.0, f"200 durable appends took {elapsed:.3f}s"

    statements: list[str] = []
    connection = ledger._require_connection()
    connection.set_trace_callback(statements.append)
    try:
        ledger.append(
            request(
                "tx-profile", "cmd-profile",
                global_sequence=global_head[0],
                global_hash=global_head[1],
                cursor=stream_head[0],
                event_hash=stream_head[1],
            ),
        )
    finally:
        connection.set_trace_callback(None)
    lowered = [statement.lower() for statement in statements]
    assert not any("integrity_check" in statement for statement in lowered)
    assert not any(
        "select * from events order by transaction_id" in statement
        or "select * from event_reservations order by transaction_id" in statement
        or "select * from transactions order by global_sequence" in statement
        and "limit 1" not in statement
        for statement in lowered
    )


def test_verified_state_tracks_global_and_independent_stream_preheads(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    global_head = (0, ZERO_SHA256)
    stream_heads = {stream: (0, ZERO_SHA256) for stream in ("org", "execution", "usage")}
    expected_preheads: list[tuple[tuple[int, str], str, tuple[int, str]]] = []
    for index in range(1, 25):
        stream = ("org", "execution", "usage")[index % 3]
        expected_preheads.append((global_head, stream, stream_heads[stream]))
        item = request(
            f"tx-{index}", f"cmd-{index}", stream=stream,
            global_sequence=global_head[0], global_hash=global_head[1],
            cursor=stream_heads[stream][0], event_hash=stream_heads[stream][1],
        )
        state = "failed_known" if index % 7 == 0 else "committed"
        result = ledger.append(item, state=state)
        global_head = (index, result.receipt["transaction_sha256"])
        if state == "committed":
            result_head = result.receipt["result_heads"][0]
            stream_heads[stream] = (
                result_head["cursor"], result_head["event_sha256"],
            )

    records = ledger.load_records()
    assert len(records) == len(expected_preheads)
    for record, (expected_global, stream, expected_stream) in zip(
        records, expected_preheads, strict=True,
    ):
        request_global = record.request["expected_transaction_head"]
        request_stream = record.request["expected_heads"][0]
        assert (
            request_global["global_sequence"],
            request_global["transaction_sha256"],
        ) == expected_global
        assert request_stream["stream"] == stream
        assert (
            request_stream["cursor"], request_stream["event_sha256"],
        ) == expected_stream


def test_concurrent_exact_retry_is_one_commit_and_one_replay(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def append() -> None:
        barrier.wait(timeout=5)
        outcomes.append(ledger.append(request()))

    left = threading.Thread(target=append)
    right = threading.Thread(target=append)
    left.start(); right.start(); left.join(10); right.join(10)
    assert len(outcomes) == 2
    assert sum(result.idempotent_replay for result in outcomes if hasattr(result, "idempotent_replay")) == 1
    ledger.verify_integrity()


def test_concurrent_same_cas_has_one_winner_and_one_typed_conflict(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def append(tx: str) -> None:
        barrier.wait(timeout=5)
        try:
            outcomes.append(ledger.append(request(tx, f"cmd-{tx}")))
        except LedgerConflictError as exc:
            outcomes.append(exc)

    left = threading.Thread(target=append, args=("tx-left",))
    right = threading.Thread(target=append, args=("tx-right",))
    left.start(); right.start(); left.join(10); right.join(10)
    assert sum(isinstance(item, LedgerConflictError) for item in outcomes) == 1
    assert sum(not isinstance(item, LedgerConflictError) for item in outcomes) == 1
    ledger.verify_integrity()


def test_snapshot_to_is_verified_prefix_without_wal_and_source_stays_writable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "checkpoints" / "plain.sqlite3"
    destination.parent.mkdir()
    ledger = CompanyLedger(source)
    first = ledger.append(request())
    first_head = first.receipt["result_heads"][0]
    second = ledger.append(request(
        "tx-2", "cmd-2",
        global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
        cursor=1,
        event_hash=first_head["event_sha256"],
    ))

    copied_heads = ledger.snapshot_to(destination)
    assert copied_heads == ledger.snapshot_heads()
    assert copied_heads.global_head.global_sequence == 2
    assert not destination.with_name(f"{destination.name}-wal").exists()
    assert not destination.with_name(f"{destination.name}-shm").exists()
    copied = CompanyLedger(destination)
    copied.verify_integrity()
    assert copied.snapshot_heads() == copied_heads
    copied.close()
    assert not destination.with_name(f"{destination.name}-wal").exists()
    assert not destination.with_name(f"{destination.name}-shm").exists()

    second_head = second.receipt["result_heads"][0]
    ledger.append(request(
        "tx-3", "cmd-3",
        global_sequence=2,
        global_hash=second.receipt["transaction_sha256"],
        cursor=2,
        event_hash=second_head["event_sha256"],
    ))
    reopened = CompanyLedger(destination)
    assert reopened.current_head() == copied_heads.global_head
    reopened.close()
    ledger.verify_integrity()


def test_snapshot_to_uses_a_bounded_staging_name_on_long_windows_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    ledger.append(request())
    parent = tmp_path / "checkpoints"
    pad = 229 - len(str(parent)) - 1
    assert 1 <= pad <= 255
    parent /= "p" * pad
    assert len(str(parent)) == 229
    parent.mkdir(parents=True)
    dst = parent / "plain.sqlite3"
    old = dst.with_name(f".{dst.name}.aoi-staging-{'0' * 32}.sqlite3")
    new = dst.with_name(f".aoi-{'0' * 11}.db")
    assert len(str(dst)) < 260
    assert len(str(old)) > 260
    assert len(f"{new}-journal") < 260
    monkeypatch.setattr(
        "secrets.token_urlsafe",
        lambda size: "0" * 11 if size == 8 else pytest.fail("nonce size"),
    )
    heads = ledger.snapshot_to(dst)
    assert heads == ledger.snapshot_heads()
    copied = CompanyLedger(dst)
    copied.verify_integrity()
    assert copied.snapshot_heads() == heads
    copied.close()
    assert not list(parent.glob(".aoi-*.db"))


def test_snapshot_to_concurrent_append_is_one_exact_verified_prefix(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    destination = tmp_path / "checkpoint.sqlite3"
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def snapshot() -> None:
        barrier.wait(timeout=5)
        try:
            outcomes.append(ledger.snapshot_to(destination))
        except BaseException as exc:  # pragma: no cover - assertion reports it
            outcomes.append(exc)

    def append() -> None:
        barrier.wait(timeout=5)
        try:
            outcomes.append(ledger.append(request()))
        except BaseException as exc:  # pragma: no cover - assertion reports it
            outcomes.append(exc)

    left = threading.Thread(target=snapshot)
    right = threading.Thread(target=append)
    left.start(); right.start(); left.join(10); right.join(10)
    assert len(outcomes) == 2
    assert not any(isinstance(item, BaseException) for item in outcomes), outcomes
    copied_heads = next(
        item for item in outcomes if isinstance(item, type(ledger.snapshot_heads()))
    )
    assert copied_heads.global_head.global_sequence in {0, 1}
    copied = CompanyLedger(destination)
    copied.verify_integrity()
    assert copied.snapshot_heads() == copied_heads
    copied.close()
    ledger.verify_integrity()


def test_snapshot_to_rejects_existing_same_traversal_and_unsafe_parent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sqlite3"
    ledger = CompanyLedger(source)
    existing = tmp_path / "existing.sqlite3"
    existing.write_bytes(b"not a ledger")
    unsafe_parent = tmp_path / "not-a-directory"
    unsafe_parent.write_text("x", encoding="utf-8")
    traversal = tmp_path / "safe" / ".." / "traversal.sqlite3"
    traversal.parent.parent.mkdir(exist_ok=True)

    for destination in (
        source,
        existing,
        traversal,
        unsafe_parent / "checkpoint.sqlite3",
    ):
        with pytest.raises(LedgerSnapshotError):
            ledger.snapshot_to(destination)
    assert existing.read_bytes() == b"not a ledger"
    assert not (tmp_path / "traversal.sqlite3").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink setup requires platform privilege")
def test_snapshot_to_rejects_linked_parent_without_writing_through_it(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(LedgerSnapshotError, match="link"):
        ledger.snapshot_to(linked / "checkpoint.sqlite3")
    assert not (actual / "checkpoint.sqlite3").exists()


def test_snapshot_to_source_tamper_fails_closed_without_false_checkpoint(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    ledger.append(request())
    destination = tmp_path / "tampered.sqlite3"
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER transactions_no_update")
        connection.execute(
            "UPDATE transactions SET state='failed_known' WHERE transaction_id='tx-1'",
        )
        connection.execute(TRANSACTIONS_NO_UPDATE_DDL)

    with pytest.raises(LedgerCorruptionError):
        ledger.snapshot_to(destination)
    assert ledger.health == "quarantined"
    assert not destination.exists()


def test_snapshot_to_verification_failure_cleans_only_new_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    ledger.append(request())
    destination = tmp_path / "failed.sqlite3"

    def fail_verification(_guard: Any) -> Any:
        assert _guard.path != destination
        assert _guard.path.exists()
        assert not destination.exists()
        assert not destination.with_name(f"{destination.name}-wal").exists()
        raise LedgerSnapshotError("injected destination verification failure")

    monkeypatch.setattr(ledger, "_verify_snapshot_database", fail_verification)
    with pytest.raises(LedgerSnapshotError, match="injected"):
        ledger.snapshot_to(destination)
    assert not destination.exists()
    assert not destination.with_name(f"{destination.name}-wal").exists()
    assert not destination.with_name(f"{destination.name}-shm").exists()
    assert not list(tmp_path.glob(".aoi-*.db"))
    assert ledger.current_head().global_sequence == 1


def test_snapshot_to_rejects_each_preexisting_final_sidecar_without_touching_it(
    tmp_path: Path,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    destination = tmp_path / "reserved.sqlite3"
    for suffix in ("-wal", "-shm", "-journal"):
        sentinel = destination.with_name(f"{destination.name}{suffix}")
        payload = f"unrelated-{suffix}".encode("ascii")
        sentinel.write_bytes(payload)
        with pytest.raises(LedgerSnapshotError, match="namespace"):
            ledger.snapshot_to(destination)
        assert sentinel.read_bytes() == payload
        assert not destination.exists()
        sentinel.unlink()
    assert not list(tmp_path.glob(".aoi-*.db"))


def test_snapshot_to_final_creation_race_never_overwrites_or_cleans_racer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = CompanyLedger(tmp_path / "source.sqlite3")
    ledger.append(request())
    destination = tmp_path / "raced.sqlite3"
    original_link = os.link

    def race_then_link(
        source: str | os.PathLike[str],
        destination_arg: str | os.PathLike[str],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        Path(destination_arg).write_bytes(b"racer-final")
        original_link(source, destination_arg, *args, **kwargs)

    monkeypatch.setattr(os, "link", race_then_link)
    with pytest.raises(LedgerSnapshotError, match="concurrently"):
        ledger.snapshot_to(destination)
    assert destination.read_bytes() == b"racer-final"
    assert not destination.with_name(f"{destination.name}-wal").exists()
    assert not destination.with_name(f"{destination.name}-shm").exists()
    assert not list(tmp_path.glob(".aoi-*.db"))


def test_snapshot_to_hard_exit_after_staging_never_creates_final(
    tmp_path: Path,
) -> None:
    source = tmp_path / "hard-source.sqlite3"
    destination = tmp_path / "hard-final.sqlite3"
    test_source = Path(__file__).resolve()
    child = r"""
import os
import runpy
import sys
from pathlib import Path
from aoi_orgware.company.ledger import CompanyLedger

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
namespace = runpy.run_path(sys.argv[3])
ledger = CompanyLedger(source)
ledger.append(namespace["request"]())
def hard_exit_after_staging(guard):
    assert guard.path.exists()
    assert not destination.exists()
    os._exit(93)
ledger._verify_snapshot_database = hard_exit_after_staging
ledger.snapshot_to(destination)
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(source), str(destination), str(test_source)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=os.environ.copy(),
    )
    assert result.returncode == 93, result.stderr
    assert not destination.exists()
    assert not destination.with_name(f"{destination.name}-wal").exists()
    assert not destination.with_name(f"{destination.name}-shm").exists()
