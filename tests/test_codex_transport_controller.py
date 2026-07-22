from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import threading
from typing import Any, Mapping

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware.codex_app_server_stdio import (
    AppServerError,
    AppServerResponseError,
    CodexAppServerStdio,
    ModelReroutedViolation,
    ProcessJournalEntry,
    ProtocolViolation,
    RequestJournalEntry,
    RequestPhase,
    ResponseSchemaViolation,
    RuntimeDisconnected,
    RuntimeEvent,
    TurnObservation,
)
from aoi_orgware.codex_transport_controller import (
    CodexTransportController,
    CodexTransportControllerError,
    _runtime_event_bytes,
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
            "requested_model": "gpt-5.6-terra",
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
            "fault_kind": None,
            "fault_evidence_sha256": None,
            "fault_evidence_size_bytes": None,
            "correlation": correlation(),
        }
    )
    return intent, reservation, [reserved]


def runtime_event(method: str, params: Mapping[str, Any]) -> RuntimeEvent:
    raw = json.dumps(
        {"method": method, "params": dict(params)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return RuntimeEvent(method, dict(params), hashlib.sha256(raw).hexdigest(), raw)


def test_controller_rejects_unpinned_or_divergent_runtime_event_bytes() -> None:
    params = {"threadId": "thread-1"}
    tagged = json.dumps(
        {"jsonrpc": "2.0", "method": "warning", "params": params},
        separators=(",", ":"),
    ).encode("utf-8")
    with pytest.raises(CodexTransportControllerError, match="unpinned jsonrpc"):
        _runtime_event_bytes(
            RuntimeEvent(
                "warning", params, hashlib.sha256(tagged).hexdigest(), tagged
            )
        )
    exact = json.dumps(
        {"method": "warning", "params": params}, separators=(",", ":")
    ).encode("utf-8")
    with pytest.raises(CodexTransportControllerError, match="fields differ"):
        _runtime_event_bytes(
            RuntimeEvent("warning", {"threadId": "other"}, hashlib.sha256(exact).hexdigest(), exact)
        )


class Sink:
    def __init__(self, journal: list[dict[str, Any]], *, fail_publications: int = 0) -> None:
        self.journal = list(journal)
        self.fail_publications = fail_publications
        self.published: list[dict[str, Any]] = []
        self.fault_evidence: list[tuple[str, bytes]] = []

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

    def persist_fault(self, data: bytes, label: str) -> dict[str, Any]:
        self.fault_evidence.append((label, data))
        return {
            "path": "local-cas",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }


class FakeAdapter:
    def __init__(self, mode: str = "completed") -> None:
        self.mode = mode
        self.on_process_start_pending: Any = None
        self.on_process_started: Any = None
        self.on_send_pending: Any = None
        self.on_response: Any = None
        self.on_rejected_response: Any = None
        self.on_rejected_notification: Any = None
        self.request_count: dict[str, int] = {}
        self.closed = False
        self.seal_called = False
        self.terminal_sealed = False
        self.reroute_event: RuntimeEvent | None = None
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
            {"id": request_id, "method": method, "params": {}},
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
        if self.mode == method.replace("/", "_") + "_schema_error":
            rejected = json.dumps(
                {"id": request_id, "result": {"invalid": True}},
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            rejected_entry = RequestJournalEntry(
                request_id,
                method,
                RequestPhase.RESPONSE_RECEIVED,
                rejected,
                hashlib.sha256(rejected).hexdigest(),
            )
            self.on_rejected_response(rejected_entry)
            raise ResponseSchemaViolation(
                f"pinned {method} response schema validation failed",
                method=method,
                evidence_sha256=hashlib.sha256(rejected).hexdigest(),
                evidence_size_bytes=len(rejected),
            )
        error = self.mode == method.replace("/", "_") + "_error"
        response = (
            {"id": request_id, "error": {"code": -1, "message": "no"}}
            if error
            else {"id": request_id, "result": dict(result)}
        )
        response_raw = json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
        response_entry = RequestJournalEntry(
            request_id,
            method,
            RequestPhase.RESPONSE_RECEIVED,
            response_raw,
            hashlib.sha256(response_raw).hexdigest(),
        )
        if error:
            self.on_rejected_response(response_entry)
            raise AppServerResponseError(
                f"App Server returned a correlated error response during {method}",
                method=method,
                evidence_sha256=response_entry.sha256,
                evidence_size_bytes=len(response_raw),
            )
        self.on_response(response_entry)
        return dict(result)

    def initialize(self) -> dict[str, Any]:
        return self._request("initialize", {"capabilities": {}})

    def verify_model_from_intent(self, *, intent: object) -> dict[str, Any]:
        return self._request(
            "model/list",
            {
                "data": [
                    {
                        "model": "gpt-5.6-terra",
                        "supportedReasoningEfforts": [
                            {"reasoningEffort": "high"}
                        ],
                    }
                ],
                "nextCursor": None,
            },
        )

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
        if self.mode == "model_rerouted_early":
            self.reroute_event = runtime_event(
                "model/rerouted",
                {
                    "fromModel": "gpt-5.6-terra",
                    "reason": "highRiskCyberActivity",
                    "threadId": thread_id,
                    "toModel": "reroute-secret-model",
                    "turnId": turn_id,
                },
            )
            reference = self.on_rejected_notification(self.reroute_event)
            raise ModelReroutedViolation(
                evidence_sha256=str(reference["sha256"]),
                evidence_size_bytes=int(reference["size_bytes"]),
            )
        if self.mode in {"model_rerouted", "model_rerouted_mismatch"}:
            params = {
                "fromModel": "gpt-5.6-terra",
                "reason": "highRiskCyberActivity",
                "threadId": thread_id,
                "toModel": "reroute-secret-model",
                "turnId": turn_id,
            }
            if self.mode == "model_rerouted_mismatch":
                raw = b'{"method":"model/rerouted","params":"payload-secret"}\n'
                self.reroute_event = RuntimeEvent(
                    "model/rerouted", params, "0" * 64, raw
                )
            else:
                self.reroute_event = runtime_event("model/rerouted", params)
            completed = runtime_event(
                "turn/completed",
                {
                    "threadId": thread_id,
                    "turn": {"id": turn_id, "status": "completed"},
                },
            )
            return TurnObservation(
                thread_id, turn_id, "completed", (self.reroute_event, completed)
            )
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

    def synchronize_reader_boundary(self, *, timeout_seconds: float) -> None:
        return None

    def seal_reader_for_terminal_commit(self, *, timeout_seconds: float) -> None:
        self.seal_called = True
        if self.mode != "boundary_rerouted":
            self.terminal_sealed = True
            return
        params = {
            "fromModel": "gpt-5.6-terra",
            "reason": "highRiskCyberActivity",
            "threadId": "thread-1",
            "toModel": "reroute-secret-model",
            "turnId": "turn-1",
        }
        self.reroute_event = runtime_event("model/rerouted", params)
        reference = self.on_rejected_notification(self.reroute_event)
        raise ModelReroutedViolation(
            evidence_sha256=str(reference["sha256"]),
            evidence_size_bytes=int(reference["size_bytes"]),
        )

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
        persist_fault_evidence=sink.persist_fault,
    )
    return value, sink, FakeAdapter(mode)


def test_success_is_runtime_observed_and_never_task_completion() -> None:
    value, sink, adapter = controller()
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]
    assert result.terminal_state == "completed"
    assert result.runtime_completed is True
    assert adapter.terminal_sealed is True
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
        "model_list_send_pending",
        "model_list_observed",
        "thread_start_send_pending",
        "thread_started",
        "turn_start_send_pending",
        "turn_started",
        "item_started",
        "item_completed",
        "completed",
    ]
    response_methods = {
        row["event_type"]: row["wire_method"]
        for row in result.journal
        if row["event_type"]
        in {"initialized", "model_list_observed", "thread_started", "turn_started"}
    }
    assert response_methods == {
        "initialized": "initialize",
        "model_list_observed": "model/list",
        "thread_started": "thread/start",
        "turn_started": "turn/start",
    }
    assert sink.published == [result.terminal_receipt]
    assert adapter.closed is True


@pytest.mark.parametrize(
    "mode", ["model_rerouted", "model_rerouted_mismatch"]
)
def test_controller_model_reroute_preempts_completed_terminal(mode: str) -> None:
    value, sink, adapter = controller(mode)
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]

    assert result.terminal_state == "failed"
    assert result.runtime_completed is False
    assert adapter.closed is True
    assert adapter.reroute_event is not None
    assert "completed" not in [row["event_type"] for row in result.journal]
    terminal = result.journal[-1]
    assert terminal["event_type"] == "failed"
    assert terminal["wire_method"] == "model/rerouted"
    assert terminal["fault_kind"] == "ModelReroutedViolation"
    assert terminal["wire_event_sha256"] is None
    assert terminal["response_sha256"] is None
    assert terminal["correlation"] == correlation("thread-1", "turn-1")
    assert sink.fault_evidence == [
        (
            "Codex App Server model/rerouted rejected notification",
            adapter.reroute_event.wire_bytes,
        )
    ]
    assert terminal["fault_evidence_sha256"] == hashlib.sha256(
        adapter.reroute_event.wire_bytes
    ).hexdigest()
    assert terminal["fault_evidence_size_bytes"] == len(
        adapter.reroute_event.wire_bytes
    )
    assert "payload-secret" not in json.dumps(result.terminal_receipt)
    assert "payload-secret" not in json.dumps(result.journal)
    with pytest.raises(CodexTransportControllerError, match="terminal"):
        value._persist(
            value._event(
                "completed",
                wire_method="turn/completed",
                correlation=value.state.correlation,
                payload_size_bytes=1,
                wire_event_sha256=SHA_A,
            )
        )


def test_controller_early_model_reroute_fault_does_not_claim_clean_seal() -> None:
    value, sink, adapter = controller("model_rerouted_early")
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]

    assert result.terminal_state == "failed"
    assert result.runtime_completed is False
    assert adapter.seal_called is False
    assert adapter.terminal_sealed is False
    assert adapter.closed is True
    assert adapter.reroute_event is not None
    assert "completed" not in [row["event_type"] for row in result.journal]
    assert sink.fault_evidence == [
        (
            "Codex App Server model/rerouted rejected notification",
            adapter.reroute_event.wire_bytes,
        )
    ]
    terminal = result.journal[-1]
    assert terminal["event_type"] == "failed"
    assert terminal["wire_method"] == "model/rerouted"
    assert terminal["fault_kind"] == "ModelReroutedViolation"
    assert terminal["fault_evidence_sha256"] == hashlib.sha256(
        adapter.reroute_event.wire_bytes
    ).hexdigest()
    assert terminal["fault_evidence_size_bytes"] == len(
        adapter.reroute_event.wire_bytes
    )
    assert sink.published == [result.terminal_receipt]


@pytest.mark.parametrize("sink_mode", ["raises", "diverges"])
def test_controller_model_reroute_cas_failure_never_completes(
    sink_mode: str,
) -> None:
    value, _sink, adapter = controller("model_rerouted")

    def broken_fault_sink(data: bytes, _label: str) -> dict[str, Any]:
        if sink_mode == "raises":
            raise RuntimeError("payload-secret")
        return {
            "path": "local-cas",
            "sha256": "0" * 64,
            "size_bytes": len(data),
        }

    value._persist_fault_evidence = broken_fault_sink
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]

    assert result.terminal_state == "runtime_unknown"
    assert result.runtime_completed is False
    assert "completed" not in [row["event_type"] for row in result.journal]
    terminal = result.journal[-1]
    assert terminal["fault_kind"] == "CodexTransportControllerError"
    assert "payload-secret" not in json.dumps(result.journal)
    assert "payload-secret" not in json.dumps(result.terminal_receipt)


@pytest.mark.parametrize(
    ("cas_fault", "expected_terminal"),
    [
        ("none", "failed"),
        ("raise", "runtime_unknown"),
        ("diverge", "runtime_unknown"),
    ],
)
def test_controller_seals_reader_before_post_observe_completion_commit(
    cas_fault: str, expected_terminal: str
) -> None:
    value, sink, adapter = controller("boundary_rerouted")
    if cas_fault == "raise":
        def raise_fault(_data: bytes, _label: str) -> dict[str, Any]:
            raise OSError("local CAS unavailable")

        value._persist_fault_evidence = raise_fault
    elif cas_fault == "diverge":
        value._persist_fault_evidence = lambda data, _label: {
            "path": "local-cas",
            "sha256": "0" * 64,
            "size_bytes": len(data),
        }
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]

    assert result.terminal_state == expected_terminal
    assert result.runtime_completed is False
    assert "completed" not in [row["event_type"] for row in result.journal]
    assert adapter.seal_called is True
    assert adapter.terminal_sealed is False
    assert adapter.reroute_event is not None
    if cas_fault == "none":
        assert sink.fault_evidence == [
            (
                "Codex App Server model/rerouted rejected notification",
                adapter.reroute_event.wire_bytes,
            )
        ]
        assert result.journal[-1]["fault_kind"] == "ModelReroutedViolation"
    assert sink.published[-1]["terminal_state"] == expected_terminal


@pytest.mark.parametrize(
    ("fault_mode", "expected_terminal"),
    [
        ("none", "failed"),
        ("raise", "runtime_unknown"),
        ("diverge", "runtime_unknown"),
        ("stderr", "runtime_unknown"),
        ("wait_oserror", "runtime_unknown"),
        ("poll_oserror", "runtime_unknown"),
        ("stdin_close_exit0", "runtime_unknown"),
        ("stdin_none", "runtime_unknown"),
        ("typed_wait_oserror", "failed"),
        ("cleanup_poll_oserror_live", "runtime_unknown"),
        ("cleanup_terminate_wait_oserror", "runtime_unknown"),
        ("cleanup_unconfirmed", "runtime_unknown"),
        ("join_oserror", "runtime_unknown"),
        ("typed_join_oserror", "failed"),
        ("stderr_reader_live", "runtime_unknown"),
    ],
)
def test_production_stream_seal_blocks_actual_controller_terminal_publication(
    tmp_path: Path, fault_mode: str, expected_terminal: str
) -> None:
    """Reproduce v68 with the production reader/condition/seal implementation."""

    value, sink, delegate = controller()
    # A POSIX venv launcher may be a symlink; this synthetic process test needs
    # a regular executable placeholder without weakening the production check.
    adapter = CodexAppServerStdio(Path(sys.executable).resolve(), cwd=tmp_path)
    release_stdout = threading.Event()
    process_exited = threading.Event()
    callback_entered = threading.Event()
    release_callback = threading.Event()
    release_stderr = threading.Event()
    process_killed = threading.Event()
    process_calls: list[str] = []
    emits_reroute = fault_mode in {
        "none",
        "raise",
        "diverge",
        "typed_wait_oserror",
        "typed_join_oserror",
    }
    reroute = runtime_event(
        "model/rerouted",
        {
            "fromModel": "gpt-5.6-terra",
            "reason": "highRiskCyberActivity",
            "threadId": "thread-1",
            "toModel": "reroute-secret-model",
            "turnId": "turn-1",
        },
    )

    class DeferredStdin:
        def close(self) -> None:
            process_calls.append("stdin.close")
            release_stdout.set()
            if fault_mode not in {
                "cleanup_poll_oserror_live",
                "cleanup_terminate_wait_oserror",
                "cleanup_unconfirmed",
            }:
                process_exited.set()
            if fault_mode in {
                "poll_oserror",
                "stdin_close_exit0",
                "cleanup_poll_oserror_live",
                "cleanup_terminate_wait_oserror",
                "cleanup_unconfirmed",
            }:
                raise OSError("synthetic stdin close failure")

    class DeferredStdout:
        def __init__(self) -> None:
            self.sent = False

        def readline(self, _limit: int) -> bytes:
            release_stdout.wait(timeout=5)
            if not emits_reroute:
                return b""
            if not self.sent:
                self.sent = True
                return reroute.wire_bytes + b"\n"
            return b""

    class DeferredStderr:
        def read(self, _limit: int) -> bytes:
            if fault_mode == "stderr":
                raise OSError("synthetic stderr read failure")
            if fault_mode == "stderr_reader_live":
                release_stderr.wait(timeout=10)
            return b""

    class DeferredProcess:
        def __init__(self) -> None:
            self.stdin = None if fault_mode == "stdin_none" else DeferredStdin()
            self.stdout = DeferredStdout()
            self.stderr = DeferredStderr()
            self.pid = 42

        def poll(self) -> int | None:
            process_calls.append("poll")
            if fault_mode in {"poll_oserror", "cleanup_poll_oserror_live", "cleanup_unconfirmed"}:
                raise OSError("synthetic process poll failure")
            return 0 if process_exited.is_set() else None

        def wait(self, timeout: float | None = None) -> int:
            process_calls.append("wait")
            if fault_mode in {"wait_oserror", "typed_wait_oserror"}:
                raise OSError("synthetic process wait failure")
            if fault_mode == "cleanup_terminate_wait_oserror" and not process_killed.is_set():
                raise OSError("synthetic process wait failure before kill")
            if fault_mode == "cleanup_unconfirmed":
                raise OSError("synthetic process wait failure")
            if not process_exited.wait(timeout=timeout):
                raise RuntimeError("synthetic process wait unexpectedly timed out")
            return 0

        def terminate(self) -> None:
            process_calls.append("terminate")
            if fault_mode in {"cleanup_terminate_wait_oserror", "cleanup_unconfirmed"}:
                raise OSError("synthetic process terminate failure")
            release_stdout.set()
            process_exited.set()

        def kill(self) -> None:
            process_calls.append("kill")
            if fault_mode == "cleanup_unconfirmed":
                raise OSError("synthetic process kill failure")
            release_stdout.set()
            process_killed.set()
            process_exited.set()

    process = DeferredProcess()

    def start() -> None:
        for name in (
            "on_process_start_pending",
            "on_process_started",
            "on_send_pending",
            "on_response",
            "on_rejected_response",
            "on_rejected_notification",
        ):
            setattr(delegate, name, getattr(adapter, name))
        adapter._process = process  # type: ignore[assignment]
        adapter._stdout_thread = threading.Thread(
            target=adapter._stdout_reader, daemon=True
        )
        adapter._stderr_thread = threading.Thread(
            target=adapter._stderr_reader, daemon=True
        )
        adapter._stdout_thread.start()
        adapter._stderr_thread.start()
        if fault_mode in {"join_oserror", "typed_join_oserror"}:
            real_stdout_thread = adapter._stdout_thread

            class JoinFaultThread:
                def join(self, timeout: float | None = None) -> None:
                    real_stdout_thread.join(timeout=timeout)
                    raise OSError("synthetic reader join failure")

                def is_alive(self) -> bool:
                    return real_stdout_thread.is_alive()

            adapter._stdout_thread = JoinFaultThread()  # type: ignore[assignment]
        delegate.start()

    def observe_turn(
        *, thread_id: str, turn_id: str, timeout_seconds: float
    ) -> TurnObservation:
        observation = delegate.observe_turn(
            thread_id=thread_id,
            turn_id=turn_id,
            timeout_seconds=timeout_seconds,
        )
        adapter._turn_terminal = True
        return observation

    adapter.start = start  # type: ignore[method-assign]
    adapter.initialize = delegate.initialize  # type: ignore[method-assign]
    adapter.verify_model_from_intent = delegate.verify_model_from_intent  # type: ignore[method-assign]
    adapter.start_thread_from_intent = delegate.start_thread_from_intent  # type: ignore[method-assign]
    adapter.start_turn_from_intent = delegate.start_turn_from_intent  # type: ignore[method-assign]
    adapter.interrupt_turn = delegate.interrupt_turn  # type: ignore[method-assign]
    adapter.observe_turn = observe_turn  # type: ignore[method-assign]

    def persist_fault(data: bytes, label: str) -> dict[str, Any]:
        callback_entered.set()
        assert release_callback.wait(timeout=5)
        if fault_mode == "raise":
            raise OSError("local CAS unavailable")
        if fault_mode == "diverge":
            return {
                "path": "local-cas",
                "sha256": "0" * 64,
                "size_bytes": len(data),
            }
        return sink.persist_fault(data, label)

    value._persist_fault_evidence = persist_fault
    results: list[Any] = []
    worker = threading.Thread(
        target=lambda: results.append(
            value.run(
                adapter,
                prompt="hello",
                timeout_seconds=0.2 if fault_mode == "stderr_reader_live" else 3,
            )
        ),
        daemon=True,
    )
    worker.start()
    if emits_reroute:
        assert callback_entered.wait(timeout=3)
        assert sink.published == []
        assert "completed" not in [row["event_type"] for row in value.journal]
        release_callback.set()
    worker.join(timeout=6)

    assert worker.is_alive() is False
    assert len(results) == 1
    result = results[0]
    assert result.terminal_state == expected_terminal, (
        result.journal,
        adapter._reader_error,
    )
    assert result.runtime_completed is False
    assert "completed" not in [row["event_type"] for row in result.journal]
    assert sink.published[-1]["terminal_state"] == expected_terminal
    if fault_mode == "stderr":
        assert adapter._stderr_reader_done is True
        assert isinstance(adapter._reader_error, RuntimeDisconnected)
    if fault_mode == "typed_wait_oserror":
        assert isinstance(adapter._reader_error, ModelReroutedViolation)
        assert result.journal[-1]["wire_method"] == "model/rerouted"
    if fault_mode == "cleanup_poll_oserror_live":
        assert "terminate" in process_calls
        assert process_exited.is_set()
        assert adapter._process is None
    if fault_mode == "cleanup_terminate_wait_oserror":
        assert "kill" in process_calls
        assert process_exited.is_set()
        assert adapter._process is None
    if fault_mode == "cleanup_unconfirmed":
        assert "terminate" in process_calls
        assert "kill" in process_calls
        assert process_exited.is_set() is False
        assert adapter._process is process
    if fault_mode in {"join_oserror", "typed_join_oserror"}:
        assert isinstance(adapter._reader_error, RuntimeDisconnected if fault_mode == "join_oserror" else ModelReroutedViolation)
    if fault_mode == "stderr_reader_live":
        assert adapter._stderr_thread is not None
        assert adapter._stderr_thread.is_alive()
        assert isinstance(adapter._reader_error, RuntimeDisconnected)
        release_stderr.set()
        adapter._stderr_thread.join(timeout=2)
        assert adapter._stderr_thread.is_alive() is False


def test_error_envelope_cannot_enter_success_response_callback() -> None:
    value, _sink, adapter = controller()
    value._on_process_start_pending(
        adapter._process_entry("process_start_pending", None)
    )
    value._on_process_started(adapter._process_entry("process_started", 42))
    request_raw = b'{"id":1,"method":"initialize","params":{}}\n'
    value._on_send_pending(
        RequestJournalEntry(
            1,
            "initialize",
            RequestPhase.SEND_PENDING,
            request_raw,
            hashlib.sha256(request_raw).hexdigest(),
        )
    )
    before = tuple(value.journal)
    error_raw = b'{"id":1,"error":{"code":-1,"message":"redacted"}}\n'
    with pytest.raises(
        CodexTransportControllerError, match="cannot enter the success callback"
    ):
        value._on_response(
            RequestJournalEntry(
                1,
                "initialize",
                RequestPhase.RESPONSE_RECEIVED,
                error_raw,
                hashlib.sha256(error_raw).hexdigest(),
            )
        )
    assert tuple(value.journal) == before
    assert value.state.last_event_type == "initialize_send_pending"


@pytest.mark.parametrize(
    ("mode", "terminal", "thread_id"),
    [
        ("process_loss", "launch_unknown", None),
        ("model_list_loss", "failed", None),
        ("model_list_schema_error", "failed", None),
        ("thread_start_loss", "launch_unknown", None),
        ("thread_start_schema_error", "launch_unknown", None),
        ("turn_start_loss", "launch_unknown", "thread-1"),
        ("midstream_loss", "runtime_unknown", "thread-1"),
        ("thread_start_error", "failed", None),
        ("wrong_correlation", "runtime_unknown", "thread-1"),
    ],
)
def test_crash_and_protocol_faults_terminalize_without_resend(
    mode: str, terminal: str, thread_id: str | None
) -> None:
    value, sink, adapter = controller(mode)
    result = value.run(adapter, prompt="hello")  # type: ignore[arg-type]
    assert result.terminal_state == terminal
    assert result.terminal_receipt["correlation"]["thread_id"] == thread_id
    terminal_event = result.journal[-1]
    assert terminal_event["wire_event_sha256"] is None
    assert terminal_event["response_sha256"] is None
    assert terminal_event["fault_kind"] in {
        "AppServerError",
        "AppServerResponseError",
        "ProtocolViolation",
        "ResponseSchemaViolation",
        "RuntimeDisconnected",
    }
    assert terminal_event["fault_evidence_sha256"] is not None
    assert terminal_event["fault_evidence_size_bytes"] > 0
    if mode == "thread_start_error":
        assert len(sink.fault_evidence) == 1
        assert hashlib.sha256(sink.fault_evidence[0][1]).hexdigest() == terminal_event[
            "fault_evidence_sha256"
        ]
    assert all(count == 1 for count in adapter.request_count.values())
    assert adapter.closed is True


def test_synthetic_fault_digest_distinguishes_redacted_reason_codes() -> None:
    value, _sink, _adapter = controller()
    timeout = value._fault_digest(RuntimeDisconnected("timed out waiting for data"))
    eof = value._fault_digest(RuntimeDisconnected("stdout reached EOF"))
    other_timeout = value._fault_digest(
        RuntimeDisconnected("timed out with sensitive path C:/secret")
    )
    assert timeout[1] != eof[1]
    assert timeout == other_timeout


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
        persist_fault_evidence=recovered_sink.persist_fault,
    )
    recovered_result = recovered.reconcile_after_crash()
    assert recovered_result.terminal_state == "launch_unknown"
    assert recovered_result.journal == result.journal
    assert len(recovered_sink.published) == 1
