from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import cast

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def correlation(thread: str | None = None, turn: str | None = None, item: str | None = None) -> dict[str, str | None]:
    return {"thread_id": thread, "turn_id": turn, "item_id": item}


def runtime_pin(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        **contracts.pinned_runtime_binding(),
        "executable_path": "C:/tools/codex-app-server.exe",
    }
    value.update(changes)
    return value


def intent(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
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
        "prompt_size_bytes": 41,
        "cwd": "C:/scratch/repo",
        "requested_model": "gpt-5.6-terra",
        "requested_effort": "high",
        "sandbox": "workspaceWrite",
        "approval": "never",
        "runtime_pin": runtime_pin(),
        "pre_git_binding": {
            "git_head_sha256": SHA_A,
            "git_tree_sha256": SHA_B,
            "git_status_sha256": SHA_C,
            "claim_coverage_sha256": SHA_D,
        },
    }
    value.update(changes)
    return value


def reservation(intent_sha: str, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1,
        "reservation_id": "reservation-1",
        "launch_intent_sha256": intent_sha,
        "permit_sha256": SHA_C,
        "runtime_pin": runtime_pin(),
        "state": "reserved",
        "correlation": correlation(),
    }
    value.update(changes)
    return value


def event(
    intent_sha: str,
    reservation_sha: str,
    *,
    event_id: str,
    sequence: int,
    prev: str,
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
    **changes: object,
) -> dict[str, object]:
    pending = event_type.endswith("_pending")
    unknown = event_type == "launch_unknown"
    method = str(changes.get("wire_method", contracts._EVENT_WIRE_METHOD[event_type]))
    response_observed = event_type in {
        "initialized",
        "model_list_observed",
        "thread_started",
        "turn_started",
        "interrupt_observed",
    } or (event_type == "failed" and method not in {"process/exited", "turn/completed"})
    wire_observed = response_observed or event_type in {
        "process_started",
        "item_started",
        "item_completed",
        "completed",
        "interrupted",
    } or (event_type == "failed" and method == "turn/completed")
    fault_observed = event_type in {"launch_unknown", "runtime_unknown"} or (
        event_type == "failed" and method == "process/exited"
    )
    value: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
        "event_id": event_id,
        "sequence": sequence,
        "prev_event_sha256": prev,
        "launch_intent_sha256": intent_sha,
        "reservation_sha256": reservation_sha,
        "event_type": event_type,
        "state": state,
        "wire_method": method,
        "wire_event_sha256": SHA_A if wire_observed else None,
        "payload_size_bytes": 0 if event_type == "reserved" else 42,
        "item_type": "agent_message" if event_type in {"item_started", "item_completed"} else None,
        "status": contracts._EVENT_WIRE_STATUS[event_type],
        "request_id": f"request-{sequence}" if pending or unknown else None,
        "request_bytes_sha256": SHA_B if pending or unknown else None,
        "response_sha256": SHA_A if response_observed else None,
        "fault_kind": "RuntimeDisconnected" if fault_observed else None,
        "fault_evidence_sha256": SHA_D if fault_observed else None,
        "fault_evidence_size_bytes": 42 if fault_observed else None,
        "correlation": runtime,
    }
    value.update(changes)
    return value


def append(
    records: list[dict[str, object]],
    intent_sha: str,
    reservation_sha: str,
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
    **changes: object,
) -> list[dict[str, object]]:
    sequence = len(records) + 1
    raw = event(
        intent_sha,
        reservation_sha,
        event_id=f"event-{sequence}",
        sequence=sequence,
        prev=contracts.ZERO_SHA256 if not records else records[-1]["event_sha256"],
        event_type=event_type,
        state=state,
        runtime=runtime,
        **changes,
    )
    return contracts.append_transport_journal_event(records, contracts.seal_journal_event(raw))


def to_turn_started() -> tuple[str, str, list[dict[str, object]]]:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(reservation(sealed_intent["intent_sha256"]))
    records: list[dict[str, object]] = []
    for event_type, state, runtime in (
        ("reserved", "reserved", correlation()),
        ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()),
        ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()),
        ("thread_start_send_pending", "reserved", correlation()),
        ("thread_started", "thread_started", correlation("thread-1")),
        ("turn_start_send_pending", "thread_started", correlation("thread-1")),
        ("turn_started", "turn_started", correlation("thread-1", "turn-1")),
    ):
        records = append(records, sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], event_type, state, runtime)
    return sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], records


def test_packaged_runtime_pin_and_strict_manifest_guards() -> None:
    pin = contracts.pinned_runtime_binding()
    assert pin["app_server_executable_sha256"] == "94884f0f00d4e1b9fdd2d70670169c4dd3d6533ef93002cea963ced863101e57"
    assert pin["executable_size_bytes"] == 283340080
    root = Path(contracts.__file__).resolve().parent / "resources" / "codex_app_server" / "0.144.6"
    pin_bytes = (root / "runtime-pin.json").read_bytes()
    manifest = json.loads((root / "schema-manifest.json").read_bytes())
    combined = (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    bad = copy.deepcopy(manifest)
    bad[0]["path"] = "../schema.json"
    with pytest.raises(contracts.CodexTransportContractError):
        contracts._validate_packaged_runtime_payload(pin_bytes, contracts.canonical_json_bytes(bad), combined)
    reordered = list(reversed(manifest))
    with pytest.raises(contracts.CodexTransportContractError):
        contracts._validate_packaged_runtime_payload(pin_bytes, contracts.canonical_json_bytes(reordered), combined)


@pytest.mark.parametrize(
    "change",
    (
        {"cwd": "C:\\\\scratch\\repo"},
        {"approval": "on-request"},
        {"sandbox": "workspace-write"},
        {"requested_model": "unbounded-model"},
        {"prompt_size_bytes": 0},
        {"runtime_pin": runtime_pin(executable_path="relative/path")},
        {"routing_binding": {"kind": "cohort", "cohort_id": "c"}},
    ),
)
def test_launch_intent_falsification_guards(change: dict[str, object]) -> None:
    with pytest.raises(contracts.CodexTransportContractError):
        contracts.seal_launch_intent(intent(**change))


def test_launch_intent_accepts_standalone_and_zero_based_cohort_routing() -> None:
    cohort = contracts.seal_launch_intent(intent())
    assert cohort["routing_binding"]["wave_index"] == 0
    standalone_binding = {
        "kind": "standalone",
        "routing_authority_sha256": SHA_C,
        "transport": "codex",
        "parent_session_id": "chief-1",
        "expected_agent_type": "worker",
    }
    standalone = contracts.seal_launch_intent(
        intent(routing_binding=standalone_binding)
    )
    assert standalone["routing_binding"] == standalone_binding


def test_launch_intent_rejects_legacy_fallback_model_name() -> None:
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="requested_model is not an approved bounded model",
    ):
        contracts.seal_launch_intent(intent(requested_model="gpt-5.6"))


def test_model_list_preflight_is_ordered_and_failure_is_known_before_thread_start() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(
        reservation(sealed_intent["intent_sha256"])
    )
    intent_sha = str(sealed_intent["intent_sha256"])
    reservation_sha = str(sealed_reservation["reservation_sha256"])
    records: list[dict[str, object]] = []
    for event_type in (
        "reserved",
        "process_start_pending",
        "process_started",
        "initialize_send_pending",
        "initialized",
        "model_list_send_pending",
        "model_list_observed",
    ):
        records = append(
            records,
            intent_sha,
            reservation_sha,
            event_type,
            "reserved",
            correlation(),
        )
    state = contracts.validate_transport_journal(records)
    assert state.state == "reserved"
    assert state.last_event_type == "model_list_observed"
    assert append(
        records,
        intent_sha,
        reservation_sha,
        "thread_start_send_pending",
        "reserved",
        correlation(),
    )[-1]["wire_method"] == "thread/start"

    pending = records[:-1]
    assert pending[-1]["event_type"] == "model_list_send_pending"
    failed = append(
        pending,
        intent_sha,
        reservation_sha,
        "failed",
        "failed",
        correlation(),
        wire_method="model/list",
        wire_event_sha256=None,
        response_sha256=None,
        fault_kind="ModelCatalogViolation",
        fault_evidence_sha256=SHA_D,
        fault_evidence_size_bytes=42,
    )
    assert contracts.validate_transport_journal(failed).state == "failed"
    with pytest.raises(contracts.CodexTransportContractError):
        append(
            pending,
            intent_sha,
            reservation_sha,
            "launch_unknown",
            "launch_unknown",
            correlation(),
            wire_method="model/list",
        )


def test_launch_reservation_is_exactly_bound_to_intent_and_pin() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed = contracts.seal_reservation(reservation(sealed_intent["intent_sha256"]))
    assert contracts.validate_reservation_against_intent(sealed, sealed_intent) == sealed
    mismatched = contracts.seal_reservation(reservation(SHA_A))
    with pytest.raises(contracts.CodexTransportContractError, match="does not bind"):
        contracts.validate_reservation_against_intent(mismatched, sealed_intent)
    with pytest.raises(contracts.CodexTransportContractError):
        contracts.seal_reservation(reservation(sealed_intent["intent_sha256"], runtime_pin=runtime_pin(executable_size_bytes=1)))


def test_full_crash_safe_milestone_journal_and_wire_falsification() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    assert contracts.validate_transport_journal(records).state == "turn_started"
    raw = event(intent_sha, reservation_sha, event_id="raw", sequence=10, prev=records[-1]["event_sha256"], event_type="item_started", state="turn_started", runtime=correlation("thread-1", "turn-1", "item-1"))
    raw["assistant_text"] = "must never be a receipt field"
    with pytest.raises(contracts.CodexTransportContractError, match="schema"):
        contracts.seal_journal_event(raw)
    bad_pending = event(intent_sha, reservation_sha, event_id="bad", sequence=10, prev=records[-1]["event_sha256"], event_type="interrupt_send_pending", state="turn_started", runtime=correlation("thread-1", "turn-1"), response_sha256=SHA_A)
    with pytest.raises(contracts.CodexTransportContractError, match="send-pending"):
        contracts.seal_journal_event(bad_pending)
    bad_wire = event(intent_sha, reservation_sha, event_id="bad-2", sequence=10, prev=records[-1]["event_sha256"], event_type="completed", state="completed", runtime=correlation("thread-1", "turn-1"), wire_method="thread/start")
    with pytest.raises(contracts.CodexTransportContractError, match="wire metadata"):
        contracts.seal_journal_event(bad_wire)
    mislabeled_fault = event(
        intent_sha,
        reservation_sha,
        event_id="bad-3",
        sequence=10,
        prev=records[-1]["event_sha256"],
        event_type="failed",
        state="failed",
        runtime=correlation("thread-1", "turn-1"),
        fault_kind=None,
        fault_evidence_sha256=None,
        fault_evidence_size_bytes=None,
        wire_event_sha256=SHA_A,
        response_sha256=SHA_A,
    )
    with pytest.raises(contracts.CodexTransportContractError, match="evidence"):
        contracts.seal_journal_event(mislabeled_fault)


def test_thread_and_turn_start_response_loss_are_terminal_and_non_retryable() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(reservation(sealed_intent["intent_sha256"]))
    records: list[dict[str, object]] = []
    for event_type, state, runtime in (
        ("reserved", "reserved", correlation()), ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()), ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()), ("thread_start_send_pending", "reserved", correlation()),
    ):
        records = append(records, sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], event_type, state, runtime)
    pending = records[-1]
    unknown = event(sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], event_id="unknown", sequence=7, prev=pending["event_sha256"], event_type="launch_unknown", state="launch_unknown", runtime=correlation(), request_id=pending["request_id"], request_bytes_sha256=pending["request_bytes_sha256"])
    records = contracts.append_transport_journal_event(records, contracts.seal_journal_event(unknown))
    assert contracts.validate_transport_journal(records).state == "launch_unknown"
    with pytest.raises(contracts.CodexTransportContractError, match="terminal"):
        append(records, sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], "thread_started", "thread_started", correlation("retry"))

    intent_sha, reservation_sha, active = to_turn_started()
    # A lost turn/start response is represented by rebuilding only through its pending request.
    active = active[:-1]
    pending = active[-1]
    unknown = event(intent_sha, reservation_sha, event_id="turn-unknown", sequence=9, prev=pending["event_sha256"], event_type="launch_unknown", state="launch_unknown", runtime=correlation("thread-1"), request_id=pending["request_id"], request_bytes_sha256=pending["request_bytes_sha256"], wire_method="turn/start")
    active = contracts.append_transport_journal_event(active, contracts.seal_journal_event(unknown))
    assert contracts.validate_transport_journal(active).correlation == correlation("thread-1")
    turn_unknown_receipt = contracts.seal_terminal_receipt(
        terminal(
            reservation_sha,
            active[-1]["event_sha256"],
            terminal_state="launch_unknown",
            correlation=correlation("thread-1"),
        )
    )
    assert contracts.validate_terminal_receipt_against_journal(
        turn_unknown_receipt, active
    )["correlation"] == correlation("thread-1")


def test_interrupt_response_remains_nonterminal_until_turn_completed() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupt_send_pending",
        "turn_started",
        correlation("thread-1", "turn-1"),
    )
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupt_observed",
        "turn_started",
        correlation("thread-1", "turn-1"),
    )
    observed = contracts.validate_transport_journal(records)
    assert observed.state == "turn_started"
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupted",
        "interrupted",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(records).state == "interrupted"


def test_process_start_crash_is_launch_unknown_not_a_known_failure() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(
        reservation(sealed_intent["intent_sha256"])
    )
    records: list[dict[str, object]] = []
    records = append(
        records,
        sealed_intent["intent_sha256"],
        sealed_reservation["reservation_sha256"],
        "reserved",
        "reserved",
        correlation(),
    )
    records = append(
        records,
        sealed_intent["intent_sha256"],
        sealed_reservation["reservation_sha256"],
        "process_start_pending",
        "reserved",
        correlation(),
    )
    pending = records[-1]
    unknown = event(
        sealed_intent["intent_sha256"],
        sealed_reservation["reservation_sha256"],
        event_id="process-unknown",
        sequence=3,
        prev=pending["event_sha256"],
        event_type="launch_unknown",
        state="launch_unknown",
        runtime=correlation(),
        request_id=pending["request_id"],
        request_bytes_sha256=pending["request_bytes_sha256"],
        wire_method="process/start",
    )
    records = contracts.append_transport_journal_event(
        records, contracts.seal_journal_event(unknown)
    )
    receipt = contracts.seal_terminal_receipt(
        terminal(
            sealed_reservation["reservation_sha256"],
            records[-1]["event_sha256"],
            terminal_state="launch_unknown",
            correlation=correlation(),
        )
    )
    assert contracts.validate_terminal_receipt_against_journal(
        receipt, records
    )["terminal_state"] == "launch_unknown"


def test_failures_and_disconnect_preserve_only_known_correlation() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    disconnected = append(records, intent_sha, reservation_sha, "runtime_unknown", "runtime_unknown", correlation("thread-1", "turn-1"))
    assert contracts.validate_transport_journal(disconnected).state == "runtime_unknown"
    with pytest.raises(contracts.CodexTransportContractError, match="preserve"):
        append(records, intent_sha, reservation_sha, "runtime_unknown", "runtime_unknown", correlation("thread-1"))
    before_thread = records[:2]
    failed = append(before_thread, intent_sha, reservation_sha, "failed", "failed", correlation())
    assert contracts.validate_transport_journal(failed).state == "failed"
    before_turn = records[:-1]
    failed = append(before_turn, intent_sha, reservation_sha, "failed", "failed", correlation("thread-1"))
    assert contracts.validate_transport_journal(failed).correlation == correlation("thread-1")
    turn_failed = append(
        records,
        intent_sha,
        reservation_sha,
        "failed",
        "failed",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(turn_failed).state == "failed"
    turn_interrupted = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupted",
        "interrupted",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(turn_interrupted).state == "interrupted"


def test_item_interrupt_and_correlation_falsification() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    with pytest.raises(contracts.CodexTransportContractError, match="correlation changed"):
        append(records, intent_sha, reservation_sha, "item_started", "turn_started", correlation("other", "turn-1", "item-1"))
    records = append(records, intent_sha, reservation_sha, "item_started", "turn_started", correlation("thread-1", "turn-1", "item-1"))
    with pytest.raises(contracts.CodexTransportContractError, match="duplicates item_id"):
        append(records, intent_sha, reservation_sha, "item_started", "turn_started", correlation("thread-1", "turn-1", "item-1"))
    records = append(records, intent_sha, reservation_sha, "item_completed", "turn_started", correlation("thread-1", "turn-1", "item-1"))
    records = append(records, intent_sha, reservation_sha, "interrupt_send_pending", "turn_started", correlation("thread-1", "turn-1"))
    records = append(records, intent_sha, reservation_sha, "interrupt_observed", "turn_started", correlation("thread-1", "turn-1"))
    assert contracts.validate_transport_journal(records).state == "turn_started"
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupted",
        "interrupted",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(records).state == "interrupted"


@pytest.mark.parametrize("terminal_state", ("completed", "failed", "interrupted"))
def test_terminal_states_reject_outstanding_lifecycle_items(
    terminal_state: str,
) -> None:
    intent_sha, reservation_sha, journal = to_turn_started()
    journal = append(
        journal,
        intent_sha,
        reservation_sha,
        "item_started",
        "turn_started",
        correlation("thread-1", "turn-1", "item-1"),
    )
    terminal_correlation = (
        correlation("thread-1", "turn-1", "item-1")
        if terminal_state == "failed"
        else correlation("thread-1", "turn-1")
    )
    raw_terminal = event(
        intent_sha,
        reservation_sha,
        event_id="outstanding-terminal",
        sequence=len(journal) + 1,
        prev=cast(str, journal[-1]["event_sha256"]),
        event_type=terminal_state,
        state=terminal_state,
        runtime=terminal_correlation,
    )
    invalid_journal = [*journal, contracts.seal_journal_event(raw_terminal)]
    with pytest.raises(contracts.CodexTransportContractError, match="lifecycle item started"):
        contracts.validate_transport_journal(invalid_journal)
    receipt = contracts.seal_terminal_receipt(
        terminal(
            reservation_sha,
            cast(str, invalid_journal[-1]["event_sha256"]),
            terminal_state=terminal_state,
            correlation=terminal_correlation,
        )
    )
    with pytest.raises(contracts.CodexTransportContractError, match="lifecycle item started"):
        contracts.validate_terminal_receipt_against_journal(receipt, invalid_journal)


def test_runtime_unknown_preserves_an_outstanding_lifecycle_item_as_evidence() -> None:
    intent_sha, reservation_sha, journal = to_turn_started()
    outstanding = correlation("thread-1", "turn-1", "item-1")
    journal = append(
        journal,
        intent_sha,
        reservation_sha,
        "item_started",
        "turn_started",
        outstanding,
    )
    journal = append(
        journal,
        intent_sha,
        reservation_sha,
        "runtime_unknown",
        "runtime_unknown",
        outstanding,
    )
    assert contracts.validate_transport_journal(journal).correlation == outstanding
    receipt = contracts.seal_terminal_receipt(
        terminal(
            reservation_sha,
            cast(str, journal[-1]["event_sha256"]),
            terminal_state="runtime_unknown",
            correlation=outstanding,
        )
    )
    assert contracts.validate_terminal_receipt_against_journal(receipt, journal) == receipt


def terminal(reservation_sha: str, head_sha: str, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
        "reservation_sha256": reservation_sha,
        "journal_head_sha256": head_sha,
        "terminal_state": "completed",
        "correlation": correlation("thread-1", "turn-1"),
        "evidence_level": "codex_runtime_observed",
        "mutation_verification": {"status": "unavailable", "object_sha256": None},
    }
    value.update(changes)
    return value


def test_terminal_and_mutation_evidence_are_structural_not_promotion() -> None:
    intent_sha, reservation_sha, journal = to_turn_started()
    journal = append(journal, intent_sha, reservation_sha, "completed", "completed", correlation("thread-1", "turn-1"))
    observed = contracts.seal_terminal_receipt(terminal(reservation_sha, journal[-1]["event_sha256"]))
    assert contracts.validate_terminal_receipt_against_journal(observed, journal) == observed
    payload = {
        "contract_type": "codex_mutation_verification_v1",
        "launch_intent_sha256": intent_sha,
        "reservation_sha256": reservation_sha,
        "journal_head_sha256": journal[-1]["event_sha256"],
        "pre_git_snapshot": {"cas_sha256": SHA_A, "content_type": "git_snapshot"},
        "post_git_snapshot": {"cas_sha256": SHA_B, "content_type": "git_snapshot"},
        "claim_coverage": {"cas_sha256": SHA_C, "content_type": "claim_coverage"},
        "pre_git_tree": {"cas_sha256": SHA_D, "content_type": "git_tree"},
        "post_git_tree": {"cas_sha256": SHA_D, "content_type": "git_tree"},
    }
    assert contracts.validate_mutation_verification_payload(payload)["pre_git_tree"] == payload["post_git_tree"]
    verified = contracts.seal_terminal_receipt(terminal(reservation_sha, journal[-1]["event_sha256"], evidence_level="verified_mutation", mutation_verification={"status": "referenced", "object_sha256": SHA_A}))
    assert verified["evidence_level"] == "verified_mutation"
    with pytest.raises(contracts.CodexTransportContractError, match="cannot assert"):
        contracts.seal_terminal_receipt(terminal(reservation_sha, journal[-1]["event_sha256"], mutation_verification={"status": "referenced", "object_sha256": SHA_A}))
