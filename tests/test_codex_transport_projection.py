from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware import codex_transport_projection as projection


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def correlation(
    thread: str | None = None,
    turn: str | None = None,
    item: str | None = None,
) -> dict[str, str | None]:
    return {"thread_id": thread, "turn_id": turn, "item_id": item}


def runtime_pin() -> dict[str, Any]:
    return {
        **contracts.pinned_runtime_binding(),
        "executable_path": "C:/AOI/codex-app-server.exe",
    }


def intent() -> dict[str, Any]:
    return {
        "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V1,
        "task_id": "task-1",
        "packet_id": "packet-1",
        "routing_binding": {
            "kind": "cohort",
            "cohort_id": "cohort-1",
            "cohort_sha256": SHA_A,
            "wave_index": 0,
            "transport_slot_sha256": SHA_B,
            "routing_authority_sha256": SHA_C,
            "transport": "codex",
            "parent_session_id": "chief-1",
            "expected_agent_type": "worker",
        },
        "expected_semantic_head_sha256": SHA_A,
        "prompt_sha256": SHA_B,
        "prompt_size_bytes": 42,
        "cwd": "C:/scratch/aoi",
        "requested_model": "gpt-5.6",
        "requested_effort": "high",
        "sandbox": "readOnly",
        "approval": "never",
        "runtime_pin": runtime_pin(),
        "pre_git_binding": {
            "git_head_sha256": SHA_A,
            "git_tree_sha256": SHA_B,
            "git_status_sha256": SHA_C,
            "claim_coverage_sha256": SHA_D,
        },
    }


def material() -> tuple[dict[str, Any], dict[str, Any]]:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(
        {
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1,
            "reservation_id": "reservation-1",
            "launch_intent_sha256": sealed_intent["intent_sha256"],
            "permit_sha256": SHA_C,
            "runtime_pin": runtime_pin(),
            "state": "reserved",
            "correlation": correlation(),
        }
    )
    return sealed_intent, sealed_reservation


def sealed_event(
    sealed_intent: dict[str, Any],
    sealed_reservation: dict[str, Any],
    journal: list[dict[str, Any]],
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
    *,
    request_id: str | None = None,
    request_bytes_sha256: str | None = None,
) -> dict[str, Any]:
    sequence = len(journal) + 1
    pending = event_type.endswith("_pending")
    unknown = event_type == "launch_unknown"
    observed = event_type != "reserved" and not pending and not unknown
    return contracts.seal_journal_event(
        {
            "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
            "event_id": f"event-{sequence}",
            "sequence": sequence,
            "prev_event_sha256": (
                contracts.ZERO_SHA256 if not journal else journal[-1]["event_sha256"]
            ),
            "launch_intent_sha256": sealed_intent["intent_sha256"],
            "reservation_sha256": sealed_reservation["reservation_sha256"],
            "event_type": event_type,
            "state": state,
            "wire_method": contracts._EVENT_WIRE_METHOD[event_type],
            "wire_event_sha256": SHA_A if observed else None,
            "payload_size_bytes": 0 if event_type == "reserved" else 42,
            "item_type": (
                "agent_message"
                if event_type in {"item_started", "item_completed"}
                else None
            ),
            "status": contracts._EVENT_WIRE_STATUS[event_type],
            "request_id": (
                request_id or f"request-{sequence}" if pending or unknown else None
            ),
            "request_bytes_sha256": (
                request_bytes_sha256 or SHA_B if pending or unknown else None
            ),
            "response_sha256": SHA_C if observed else None,
            "correlation": runtime,
        }
    )


def advance(
    base: dict[str, Any],
    sealed_intent: dict[str, Any],
    sealed_reservation: dict[str, Any],
    journal: list[dict[str, Any]],
    *,
    receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return projection.advance_codex_transport_projection(
        base,
        launch_id="launch-1",
        intent=sealed_intent,
        reservation=sealed_reservation,
        journal=journal,
        terminal_receipt=receipt,
    )


def append_and_advance(
    domain: dict[str, Any],
    sealed_intent: dict[str, Any],
    sealed_reservation: dict[str, Any],
    journal: list[dict[str, Any]],
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    candidate = sealed_event(
        sealed_intent, sealed_reservation, journal, event_type, state, runtime
    )
    extended = contracts.append_transport_journal_event(journal, candidate)
    return advance(domain, sealed_intent, sealed_reservation, extended), extended


def reserved_projection() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]
]:
    sealed_intent, sealed_reservation = material()
    reserved = sealed_event(
        sealed_intent, sealed_reservation, [], "reserved", "reserved", correlation()
    )
    journal = [reserved]
    domain = advance({}, sealed_intent, sealed_reservation, journal)
    return domain, sealed_intent, sealed_reservation, journal


def turn_started_projection() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]
]:
    domain, sealed_intent, sealed_reservation, journal = reserved_projection()
    for event_type, state, runtime in (
        ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()),
        ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()),
        ("thread_start_send_pending", "reserved", correlation()),
        ("thread_started", "thread_started", correlation("thread-1")),
        ("turn_start_send_pending", "thread_started", correlation("thread-1")),
        ("turn_started", "turn_started", correlation("thread-1", "turn-1")),
    ):
        domain, journal = append_and_advance(
            domain,
            sealed_intent,
            sealed_reservation,
            journal,
            event_type,
            state,
            runtime,
        )
    return domain, sealed_intent, sealed_reservation, journal


def test_full_projection_is_content_addressed_and_detached() -> None:
    domain, _intent, _reservation, _journal = turn_started_projection()
    row = projection.codex_transport_namespace_from_projection(domain)["launches"]["launch-1"]
    assert (row["state"], row["thread_id"], row["turn_id"]) == (
        "turn_started",
        "thread-1",
        "turn-1",
    )
    assert projection.launch_row_sha256(row) == row["launch_row_sha256"]
    assert row["terminal_receipt_sha256"] is None
    assert "verified_mutation" not in row
    assert "task_completion" not in row


def test_advance_requires_one_exact_journal_milestone_and_preserves_head() -> None:
    domain, sealed_intent, sealed_reservation, journal = reserved_projection()
    first = sealed_event(
        sealed_intent,
        sealed_reservation,
        journal,
        "process_start_pending",
        "reserved",
        correlation(),
    )
    one_more = contracts.append_transport_journal_event(journal, first)
    second = sealed_event(
        sealed_intent,
        sealed_reservation,
        one_more,
        "process_started",
        "reserved",
        correlation(),
    )
    two_more = contracts.append_transport_journal_event(one_more, second)
    with pytest.raises(projection.CodexTransportProjectionError, match="exactly one"):
        advance(domain, sealed_intent, sealed_reservation, two_more)
    advanced = advance(domain, sealed_intent, sealed_reservation, one_more)
    with pytest.raises(projection.CodexTransportProjectionError, match="behind"):
        advance(advanced, sealed_intent, sealed_reservation, journal)


def test_launch_unknown_preserves_known_prefix_and_cannot_be_relaunched() -> None:
    domain, sealed_intent, sealed_reservation, journal = reserved_projection()
    for event_type in (
        "process_start_pending",
        "process_started",
        "initialize_send_pending",
        "initialized",
        "thread_start_send_pending",
    ):
        domain, journal = append_and_advance(
            domain,
            sealed_intent,
            sealed_reservation,
            journal,
            event_type,
            "reserved",
            correlation(),
        )
    pending = journal[-1]
    unknown = sealed_event(
        sealed_intent,
        sealed_reservation,
        journal,
        "launch_unknown",
        "launch_unknown",
        correlation(),
        request_id=pending["request_id"],
        request_bytes_sha256=pending["request_bytes_sha256"],
    )
    journal = contracts.append_transport_journal_event(journal, unknown)
    terminal = advance(domain, sealed_intent, sealed_reservation, journal)
    retry = sealed_event(
        sealed_intent,
        sealed_reservation,
        journal,
        "thread_started",
        "thread_started",
        correlation("thread-2"),
    )
    with pytest.raises((projection.CodexTransportProjectionError, contracts.CodexTransportContractError)):
        advance(
            terminal,
            sealed_intent,
            sealed_reservation,
            contracts.append_transport_journal_event(journal, retry),
        )


def test_terminal_receipt_is_separate_monotonic_publication_step() -> None:
    domain, sealed_intent, sealed_reservation, journal = turn_started_projection()
    completed = sealed_event(
        sealed_intent,
        sealed_reservation,
        journal,
        "completed",
        "completed",
        correlation("thread-1", "turn-1"),
    )
    journal = contracts.append_transport_journal_event(journal, completed)
    with pytest.raises(projection.CodexTransportProjectionError, match="separate"):
        advance(domain, sealed_intent, sealed_reservation, journal, receipt={})
    terminal = advance(domain, sealed_intent, sealed_reservation, journal)
    receipt = contracts.seal_terminal_receipt(
        {
            "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
            "reservation_sha256": sealed_reservation["reservation_sha256"],
            "journal_head_sha256": completed["event_sha256"],
            "terminal_state": "completed",
            "correlation": correlation("thread-1", "turn-1"),
            "evidence_level": "codex_runtime_observed",
            "mutation_verification": {"status": "unavailable", "object_sha256": None},
        }
    )
    published = advance(
        terminal, sealed_intent, sealed_reservation, journal, receipt=receipt
    )
    row = projection.codex_transport_namespace_from_projection(published)["launches"]["launch-1"]
    assert row["terminal_receipt_sha256"] == receipt["receipt_sha256"]
    with pytest.raises(projection.CodexTransportProjectionError, match="already"):
        advance(published, sealed_intent, sealed_reservation, journal, receipt=receipt)


def test_namespace_rejects_identity_tamper_and_bound_overflow() -> None:
    domain, _intent, _reservation, _journal = reserved_projection()
    namespace = projection.codex_transport_namespace_from_projection(domain)
    tampered = copy.deepcopy(namespace)
    tampered["launches"]["launch-1"]["launch_id"] = "other"
    with pytest.raises(projection.CodexTransportProjectionError, match="digest"):
        projection.validate_codex_transport_namespace(tampered)
    too_many = {
        "schema_version": projection.CODEX_TRANSPORT_PROJECTION_VERSION,
        "launches": {
            str(index): {}
            for index in range(projection.MAX_CODEX_TRANSPORT_LAUNCHES + 1)
        },
    }
    with pytest.raises(projection.CodexTransportProjectionError, match="over bound"):
        projection.validate_codex_transport_namespace(too_many)
