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


def runtime_pin_v2() -> dict[str, Any]:
    return {
        **contracts.pinned_runtime_binding_v2(),
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
        "requested_model": "gpt-5.6-terra",
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
    response_observed = event_type in {
        "initialized",
        "thread_started",
        "turn_started",
        "interrupt_observed",
    }
    wire_observed = response_observed or event_type in {
        "process_started",
        "item_started",
        "item_completed",
        "completed",
        "interrupted",
    }
    fault_observed = event_type in {"launch_unknown", "runtime_unknown", "failed"}
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
            "wire_event_sha256": SHA_A if wire_observed else None,
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
            "response_sha256": SHA_A if response_observed else None,
            "fault_kind": "RuntimeDisconnected" if fault_observed else None,
            "fault_evidence_sha256": SHA_C if fault_observed else None,
            "fault_evidence_size_bytes": 42 if fault_observed else None,
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


def test_frozen_v1_terminal_and_projection_hashes_remain_stage_readable() -> None:
    sealed_intent, sealed_reservation = material()
    journal: list[dict[str, Any]] = []
    domain: dict[str, Any] = {}
    lifecycle = (
        ("reserved", "reserved", correlation()),
        ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()),
        ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()),
        ("thread_start_send_pending", "reserved", correlation()),
        ("thread_started", "thread_started", correlation("thread-1")),
        ("turn_start_send_pending", "thread_started", correlation("thread-1")),
        ("turn_started", "turn_started", correlation("thread-1", "turn-1")),
        ("completed", "completed", correlation("thread-1", "turn-1")),
    )
    for event_type, state, runtime in lifecycle:
        row = sealed_event(
            sealed_intent,
            sealed_reservation,
            journal,
            event_type,
            state,
            runtime,
        )
        journal = contracts.append_transport_journal_event(journal, row)
        domain = advance(domain, sealed_intent, sealed_reservation, journal)
    assert sealed_intent["intent_sha256"] == "40649722e5443a972fd36fdcabe42d7e2da0dcdc87eddc563b1ef9be6108e59d"
    assert sealed_reservation["reservation_sha256"] == "8a22dd149643d093e0743a8a2a76651dac2bcc7b349236ce46970e9238268a15"
    assert [row["event_sha256"] for row in journal] == [
        "b2e957e5e8ff16974c0daf15dff09fb48fca0777e5e55d2e18b61e925707741a",
        "474eabe245006b78faf2f782fc41704cb84d03d564ba4d86f8906069b3f3d00c",
        "59af78fc64f2af6b619ee5ad6fc5923ea2a73948a749bf27f7b08ae8106d7a2c",
        "174a1436934443cb7b314d1ffe4b2525626756453c3a9dea4657e0a8fcc444d7",
        "4fe09f16f4bb1d1f0c1a58607fc6ac566a33173b25449b867631ea028b6a8292",
        "ab211c8360fc9a85aeff18e0afab7c9e29dc4e6bced9992d30fb09fcbaed995c",
        "91ff95415986d6d9da5b2e22197ea31a1bbcb7c85d1796fd8983f16669a6e3bd",
        "9dd876244de3d5a7d117291a698268e31dc23370e3079e8b536d59e587cf7c94",
        "c12f17c6ba730f8f8ea2487b3ee9e089259ec175df141a8ae9188e73c3d0afda",
        "5103b868e9758ed1dffc15f0af207b9f946e6e686fef1c4c2582c633b0bbe64a",
    ]
    terminal_row = domain[projection.CODEX_TRANSPORT_NAMESPACE_KEY]["launches"]["launch-1"]
    assert terminal_row["schema_version"] == 1
    assert terminal_row["launch_row_sha256"] == "cff685ed6291a77ab3a558f86eef1d285098904326701550b092c11b7fb5082b"
    receipt = contracts.seal_terminal_receipt(
        {
            "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
            "reservation_sha256": sealed_reservation["reservation_sha256"],
            "journal_head_sha256": journal[-1]["event_sha256"],
            "terminal_state": "completed",
            "correlation": correlation("thread-1", "turn-1"),
            "evidence_level": "codex_runtime_observed",
            "mutation_verification": {"status": "unavailable", "object_sha256": None},
        }
    )
    assert receipt["receipt_sha256"] == "bfa5b79b7a4ac42cc21eb755db5d6820628e621d2a83598059a4c3c42258607f"
    published = advance(domain, sealed_intent, sealed_reservation, journal, receipt=receipt)
    published_row = published[projection.CODEX_TRANSPORT_NAMESPACE_KEY]["launches"]["launch-1"]
    assert published_row["launch_row_sha256"] == "cd8d8b3c317164bacf3dcd5deab38534dea780f7a69f0e592f4e2ca6cb6e3612"
    assert projection.validate_codex_transport_namespace(
        published[projection.CODEX_TRANSPORT_NAMESPACE_KEY]
    )["launches"]["launch-1"] == published_row


def test_namespace_may_hold_frozen_v1_and_new_v2_rows() -> None:
    v1_intent, v1_reservation = material()
    v1_reserved = sealed_event(
        v1_intent, v1_reservation, [], "reserved", "reserved", correlation()
    )
    domain = advance({}, v1_intent, v1_reservation, [v1_reserved])
    v2_intent = contracts.seal_launch_intent(
        {
            **intent(),
            "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V2,
            "network_access": False,
            "packet_id": "packet-2",
            "runtime_pin": runtime_pin_v2(),
        }
    )
    v2_reservation = contracts.seal_reservation(
        {
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V2,
            "reservation_id": "reservation-2",
            "launch_intent_sha256": v2_intent["intent_sha256"],
            "permit_sha256": SHA_D,
            "runtime_pin": runtime_pin_v2(),
            "state": "reserved",
            "correlation": correlation(),
            "evidence_level": "transport_reserved",
        }
    )
    raw_reserved = {
        key: value
        for key, value in sealed_event(
            v1_intent, v1_reservation, [], "reserved", "reserved", correlation()
        ).items()
        if key != "event_sha256"
    }
    raw_reserved.update(
        {
            "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V2,
            "event_id": "v2-reserved",
            "launch_intent_sha256": v2_intent["intent_sha256"],
            "reservation_sha256": v2_reservation["reservation_sha256"],
            "request_witness": None,
        }
    )
    v2_reserved = contracts.seal_journal_event(raw_reserved)
    mixed_namespace = projection.advance_codex_transport_projection(
        domain,
        launch_id="launch-2",
        intent=v2_intent,
        reservation=v2_reservation,
        journal=[v2_reserved],
    )
    rows = mixed_namespace[projection.CODEX_TRANSPORT_NAMESPACE_KEY]["launches"]
    assert rows["launch-1"]["schema_version"] == 1
    assert rows["launch-2"]["schema_version"] == 2
    assert rows["launch-2"]["launch_row_sha256"] == (
        "1cd7942d735f98edcbc63d42ee3ea24b99a681aa3d047d2768e652af321b5357"
    )
