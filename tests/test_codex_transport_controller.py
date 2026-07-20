from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware.codex_app_server_stdio import (
    AppServerError,
    ProcessJournalEntry,
    ProtocolViolation,
    RequestJournalEntry,
    RequestPhase,
    RuntimeDisconnected,
    RuntimeEvent,
    TurnObservation,
)
from aoi_orgware.codex_transport_controller import (
    CodexTransportController,
    CodexTransportControllerError,
)


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


def launch_material() -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    prompt = b"hello"
    pin = {
        **contracts.pinned_runtime_binding(),
        "executable_path": "C:/AOI/codex-app-server.exe",
    }
    intent = contracts.seal_launch_intent(
        {
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
            "expected_semantic_head_sha256": SHA_D,
            "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
            "prompt_size_bytes": len(prompt),
            "cwd": "C:/scratch/aoi",
            "requested_model": "gpt-5.6",
            "requested_effort": "high",
            "sandbox": "readOnly",
            "approval": "never",
            "runtime_pin": pin,
            "pre_git_binding": {
                "git_head_sha256": SHA_A,
                "git_tree_sha256": SHA_B,
                "git_status_sha256": SHA_C,
                "claim_coverage_sha256": SHA_D,
            },
        }
    )
    reservation = contracts.seal_reservation(
        {
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1,
            "reservation_id": "launch-1",
            "launch_intent_sha256": intent["intent_sha256"],
            "permit_sha256": SHA_C,
            "runtime_pin": pin,
            "state": "reserved",
            "correlation": correlation(),
        }
    )
    reserved = contracts.seal_journal_event(
        {
            "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
            "event_id": "launch-1:1:reserved",
            "sequence": 1,
            "prev_event_sha256": contracts.ZERO_SHA256,
            "launch_intent_sha256": intent["intent_sha256"],
            "reservation_sha256": reservation["reservation_sha256"],
            "event_type": "reserved",
            "state": "reserved",
            "wire_method": "aoi/reservation",
            "wire_event_sha256": None,
            "payload_size_bytes": 0,
            "item_type": None,
            "status": "observed",
            "request_id": None,
            "request_bytes_sha256": None,
            "response_sha256": None,
            "correlation": correlation(),
        }
    )
    return intent, reservation, [reserved]


def runtime_event(method: str, params: Mapping[str, Any]) -> RuntimeEvent:
    raw = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": dict(params)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return RuntimeEvent(method, dict(params), hashlib.sha256(raw).hexdigest())


class Sink:
    def __init__(self, journal: list[dict[str, Any]], *, fail_publications: int = 0) -> None:
        self.journal = list(journal)
        self.fail_publications = fail_publications
        self.published: list[dict[str, Any]] = []

    def persist(self, event: Mapping[str, Any]) -> list[dict[str, Any]]:
        self.journal = contracts.append_transport_journal_event(self.journal, event)
        return list(self.journal)

    def publish(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        if self.fail_publications:
            self.fail_publications -= 1
            raise RuntimeError("publication crash")
        checked = contracts.validate_terminal_receipt_against_journal(
            receipt, self.journal
        )
        self.published.append(checked)
        return checked


class FakeAdapter:
    def __init__(self, mode: str = "completed") -> None:
        self.mode = mode
        self.on_process_start_pending: Any = None
        self.on_process_started: Any = None
        self.on_send_pending: Any = None
        self.on_response: Any = None
        self.request_count: dict[str, int] = {}
        self.closed = False
        self._next_id = 1

    @staticmethod
    def _process_entry(phase: str, pid: int | None) -> ProcessJournalEntry:
        raw = json.dumps(
            {"phase": phase, "pid": pid}, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return ProcessJournalEntry(phase, raw, hashlib.sha256(raw).hexdigest(), pid)

    def start(self) -> None:
        self.on_process_start_pending(
            self._process_entry("process_start_pending", None)
        )
        if self.mode == "process_loss":
            raise AppServerError("Popen outcome lost")
        self.on_process_started(self._process_entry("process_started", 42))

    def _request(self, method: str, result: Mapping[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self.request_count[method] = self.request_count.get(method, 0) + 1
        request_raw = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}},
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        self.on_send_pending(
            RequestJournalEntry(
                request_id,
                method,
                RequestPhase.SEND_PENDING,
                request_raw,
                hashlib.sha256(request_raw).hexdigest(),
            )
        )
        if self.mode == method.replace("/", "_") + "_loss":
            raise RuntimeDisconnected(f"{method} response lost")
        error = self.mode == method.replace("/", "_") + "_error"
        response = (
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": -1, "message": "no"}}
            if error
            else {"jsonrpc": "2.0", "id": request_id, "result": dict(result)}
        )
        response_raw = json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
        self.on_response(
            RequestJournalEntry(
                request_id,
                method,
                RequestPhase.RESPONSE_RECEIVED,
                response_raw,
                hashlib.sha256(response_raw).hexdigest(),
            )
        )
        if error:
            raise AppServerError(f"{method} error response")
        return dict(result)

    def initialize(self) -> dict[str, Any]:
        return self._request("initialize", {"capabilities": {}})

    def start_thread_from_intent(self, *, intent: object) -> str:
        result = self._request("thread/start", {"thread": {"id": "thread-1"}})
        return str(result["thread"]["id"])

    def start_turn_from_intent(
        self, *, thread_id: str, prompt: str, intent: object
    ) -> str:
        result = self._request(
            "turn/start", {"turn": {"id": "turn-1", "status": "inProgress"}}
        )
        return str(result["turn"]["id"])

    def interrupt_turn(self, *, thread_id: str, turn_id: str) -> dict[str, Any]:
        return self._request("turn/interrupt", {})

    def observe_turn(
        self, *, thread_id: str, turn_id: str, timeout_seconds: float
    ) -> TurnObservation:
        if self.mode == "midstream_loss":
            raise RuntimeDisconnected("stream lost")
        if self.mode == "wrong_correlation":
            raise ProtocolViolation("wrong turn correlation")
        item = {"id": "item-1", "type": "agentMessage", "text": "not persisted"}
        status = (
            "interrupted"
            if self.request_count.get("turn/interrupt")
            else self.mode if self.mode in {"completed", "failed", "interrupted"}
            else "completed"
        )
        events = (
            runtime_event(
                "item/started",
                {"threadId": thread_id, "turnId": turn_id, "item": item},
            ),
            runtime_event(
                "item/completed",
                {"threadId": thread_id, "turnId": turn_id, "item": item},
            ),
            runtime_event(
                "turn/completed",
                {"threadId": thread_id, "turn": {"id": turn_id, "status": status}},
            ),
        )
        return TurnObservation(thread_id, turn_id, status, events)

    def close(self) -> None:
        self.closed = True


def controller(mode: str = "completed", *, fail_publications: int = 0) -> tuple[CodexTransportController, Sink, FakeAdapter]:
    intent, reservation, journal = launch_material()
    sink = Sink(journal, fail_publications=fail_publications)
    value = CodexTransportController(
        intent=intent,
        reservation=reservation,
        journal=journal,
        persist_milestone=sink.persist,
        publish_terminal=sink.publish,
    )
    return value, sink, FakeAdapter(mode)


def test_success_is_runtime_observed_and_never_task_completion() -> None:
    value, sink, adapter = controller()
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]
    assert result.terminal_state == "completed"
    assert result.runtime_completed is True
    assert result.task_completion == "not_inferred"
    assert result.terminal_receipt["evidence_level"] == "codex_runtime_observed"
    assert result.terminal_receipt["mutation_verification"] == {
        "status": "unavailable",
        "object_sha256": None,
    }
    assert [row["event_type"] for row in result.journal] == [
        "reserved",
        "process_start_pending",
        "process_started",
        "initialize_send_pending",
        "initialized",
        "thread_start_send_pending",
        "thread_started",
        "turn_start_send_pending",
        "turn_started",
        "item_started",
        "item_completed",
        "completed",
    ]
    assert sink.published == [result.terminal_receipt]
    assert adapter.closed is True


@pytest.mark.parametrize(
    ("mode", "terminal", "thread_id"),
    [
        ("process_loss", "launch_unknown", None),
        ("thread_start_loss", "launch_unknown", None),
        ("turn_start_loss", "launch_unknown", "thread-1"),
        ("midstream_loss", "runtime_unknown", "thread-1"),
        ("thread_start_error", "failed", None),
        ("wrong_correlation", "runtime_unknown", "thread-1"),
    ],
)
def test_crash_and_protocol_faults_terminalize_without_resend(
    mode: str, terminal: str, thread_id: str | None
) -> None:
    value, _sink, adapter = controller(mode)
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]
    assert result.terminal_state == terminal
    assert result.terminal_receipt["correlation"]["thread_id"] == thread_id
    assert all(count == 1 for count in adapter.request_count.values())
    assert adapter.closed is True


def test_terminal_publication_crash_retries_receipt_only() -> None:
    value, sink, adapter = controller(fail_publications=1)
    with pytest.raises(
        CodexTransportControllerError, match="retry publication only"
    ):
        value.run(adapter, prompt="hello")  # type: ignore[arg-type]
    counts = dict(adapter.request_count)
    result = value.republish_terminal_receipt()
    assert result.terminal_state == "completed"
    assert adapter.request_count == counts
    assert len(sink.published) == 1


def test_interrupt_response_is_observed_before_turn_completed() -> None:
    value, _sink, adapter = controller()
    result = value.run(
        adapter,  # type: ignore[arg-type]
        prompt="hello",
        interrupt_after_start=True,
    )
    assert result.terminal_state == "interrupted"
    assert adapter.request_count["turn/interrupt"] == 1
    assert [row["event_type"] for row in result.journal][-3:] == [
        "item_started",
        "item_completed",
        "interrupted",
    ]
    interrupt_index = next(
        index
        for index, row in enumerate(result.journal)
        if row["event_type"] == "interrupt_observed"
    )
    assert result.journal[interrupt_index]["state"] == "turn_started"
    assert result.journal[interrupt_index]["status"] == "observed"


def test_restart_reconciliation_never_calls_an_adapter() -> None:
    value, sink, adapter = controller("turn_start_loss")
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]
    assert result.terminal_state == "launch_unknown"

    pending_journal = list(result.journal[:-1])
    assert pending_journal[-1]["event_type"] == "turn_start_send_pending"
    recovered_sink = Sink(pending_journal)
    recovered = CodexTransportController(
        intent=value.intent,
        reservation=value.reservation,
        journal=pending_journal,
        persist_milestone=recovered_sink.persist,
        publish_terminal=recovered_sink.publish,
    )
    recovered_result = recovered.reconcile_after_crash()
    assert recovered_result.terminal_state == "launch_unknown"
    assert recovered_result.journal == result.journal
    assert len(recovered_sink.published) == 1
