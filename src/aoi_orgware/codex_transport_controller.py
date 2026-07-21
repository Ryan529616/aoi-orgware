"""Finite one-process/one-thread/one-turn Codex transport controller.

This module composes the pure contracts with the bounded stdio adapter.  It
owns no AOI Chief credential and performs no state I/O itself: every journal
event and terminal receipt must be synchronously accepted by caller-supplied
durable sinks.  A persisted start request without a persisted response is
terminal ``launch_unknown`` and is never resent by this controller.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from typing import Any

from . import codex_transport_contracts as contracts
from .codex_app_server_stdio import (
    AppServerError,
    AppServerResponseError,
    CodexAppServerStdio,
    ProcessJournalEntry,
    RequestJournalEntry,
    RequestPhase,
    RuntimeDisconnected,
    RuntimeEvent,
    SealedLaunchIntent,
    TurnObservation,
)


PersistMilestone = Callable[[Mapping[str, Any]], Sequence[Mapping[str, Any]]]
PublishTerminal = Callable[[Mapping[str, Any]], Mapping[str, Any]]
PersistFaultEvidence = Callable[[bytes, str], Mapping[str, Any]]


class CodexTransportControllerError(RuntimeError):
    """The controller could not durably advance or terminalize one launch."""


@dataclass(frozen=True)
class ControllerResult:
    launch_id: str
    terminal_state: str
    terminal_receipt: dict[str, Any]
    journal: tuple[dict[str, Any], ...]
    runtime_completed: bool
    task_completion: str = "not_inferred"


_EVENT_STATE = {
    "process_start_pending": "reserved",
    "process_started": "reserved",
    "initialize_send_pending": "reserved",
    "initialized": "reserved",
    "model_list_send_pending": "reserved",
    "model_list_observed": "reserved",
    "thread_start_send_pending": "reserved",
    "thread_started": "thread_started",
    "turn_start_send_pending": "thread_started",
    "turn_started": "turn_started",
    "interrupt_send_pending": "turn_started",
    "interrupt_observed": "turn_started",
    "item_started": "turn_started",
    "item_completed": "turn_started",
    "completed": "completed",
    "failed": "failed",
    "interrupted": "interrupted",
    "launch_unknown": "launch_unknown",
    "runtime_unknown": "runtime_unknown",
}
_EVENT_STATUS = {
    **{name: "observed" for name in _EVENT_STATE},
    "item_completed": "completed",
    "completed": "completed",
    "failed": "failed",
    "interrupt_observed": "observed",
    "interrupted": "interrupted",
    "launch_unknown": "unknown",
    "runtime_unknown": "unknown",
}
_PENDING_BY_METHOD = {
    "initialize": "initialize_send_pending",
    "model/list": "model_list_send_pending",
    "thread/start": "thread_start_send_pending",
    "turn/start": "turn_start_send_pending",
    "turn/interrupt": "interrupt_send_pending",
}
_OBSERVED_BY_METHOD = {
    # These milestones are derived from correlated request responses.  Their
    # exact bytes are not the similarly named lifecycle notifications, which
    # remain buffered runtime events until observation.
    "initialize": ("initialized", "initialize"),
    "model/list": ("model_list_observed", "model/list"),
    "thread/start": ("thread_started", "thread/start"),
    "turn/start": ("turn_started", "turn/start"),
    "turn/interrupt": ("interrupt_observed", "turn/interrupt"),
}
_TERMINAL_STATES = {
    "completed",
    "failed",
    "interrupted",
    "launch_unknown",
    "runtime_unknown",
}


def _strict_object(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CodexTransportControllerError(
                    f"duplicate response object key: {key!r}"
                )
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexTransportControllerError(
            "durable App Server response bytes are malformed"
        ) from exc
    if not isinstance(value, dict):
        raise CodexTransportControllerError("App Server response is not an object")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CodexTransportControllerError(f"{label} is not an object")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CodexTransportControllerError(f"{label} is not non-empty text")
    return value


def _correlation(
    thread_id: str | None = None,
    turn_id: str | None = None,
    item_id: str | None = None,
) -> dict[str, str | None]:
    return {"thread_id": thread_id, "turn_id": turn_id, "item_id": item_id}


def _runtime_event_bytes(event: RuntimeEvent) -> bytes:
    raw = event.wire_bytes
    message = _strict_object(raw)
    if "jsonrpc" in message:
        raise CodexTransportControllerError(
            "App Server event wire bytes use an unpinned jsonrpc envelope"
        )
    if message.get("method") != event.method or message.get("params") != event.params:
        raise CodexTransportControllerError(
            "App Server event fields differ from its exact wire bytes"
        )
    if hashlib.sha256(raw).hexdigest() != event.sha256:
        raise CodexTransportControllerError(
            "App Server event digest differs from its exact wire bytes"
        )
    return raw


class CodexTransportController:
    """Run one already-reserved launch through one finite App Server process."""

    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        reservation: Mapping[str, Any],
        journal: Sequence[Mapping[str, Any]],
        persist_milestone: PersistMilestone,
        publish_terminal: PublishTerminal,
        persist_fault_evidence: PersistFaultEvidence,
    ) -> None:
        try:
            self.intent = contracts.validate_launch_intent(intent)
            self.reservation = contracts.validate_reservation_against_intent(
                reservation, self.intent
            )
            self.journal = [contracts.validate_journal_event(row) for row in journal]
            state = contracts.validate_transport_journal(self.journal)
        except contracts.CodexTransportContractError as exc:
            raise CodexTransportControllerError(
                f"controller launch material is invalid: {exc}"
            ) from exc
        first = self.journal[0]
        if (
            first["launch_intent_sha256"] != self.intent["intent_sha256"]
            or first["reservation_sha256"] != self.reservation["reservation_sha256"]
        ):
            raise CodexTransportControllerError(
                "reserved journal does not bind controller launch material"
            )
        self.launch_id = self.reservation["reservation_id"]
        self._persist_milestone = persist_milestone
        self._publish_terminal = publish_terminal
        self._persist_fault_evidence = persist_fault_evidence
        self._terminal_receipt: dict[str, Any] | None = None

    @property
    def state(self) -> contracts.JournalState:
        return contracts.validate_transport_journal(self.journal)

    def _event(
        self,
        event_type: str,
        *,
        wire_method: str,
        correlation: Mapping[str, Any],
        payload_size_bytes: int,
        wire_event_sha256: str | None = None,
        response_sha256: str | None = None,
        request_id: str | None = None,
        request_bytes_sha256: str | None = None,
        item_type: str | None = None,
        fault_kind: str | None = None,
        fault_evidence_sha256: str | None = None,
        fault_evidence_size_bytes: int | None = None,
    ) -> dict[str, Any]:
        sequence = len(self.journal) + 1
        raw = {
            "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
            "event_id": f"{self.launch_id}:{sequence}:{event_type}",
            "sequence": sequence,
            "prev_event_sha256": self.journal[-1]["event_sha256"],
            "launch_intent_sha256": self.intent["intent_sha256"],
            "reservation_sha256": self.reservation["reservation_sha256"],
            "event_type": event_type,
            "state": _EVENT_STATE[event_type],
            "wire_method": wire_method,
            "wire_event_sha256": wire_event_sha256,
            "payload_size_bytes": payload_size_bytes,
            "item_type": item_type,
            "status": _EVENT_STATUS[event_type],
            "request_id": request_id,
            "request_bytes_sha256": request_bytes_sha256,
            "response_sha256": response_sha256,
            "fault_kind": fault_kind,
            "fault_evidence_sha256": fault_evidence_sha256,
            "fault_evidence_size_bytes": fault_evidence_size_bytes,
            "correlation": dict(correlation),
        }
        try:
            return contracts.seal_journal_event(raw)
        except (KeyError, contracts.CodexTransportContractError) as exc:
            raise CodexTransportControllerError(
                f"controller milestone is invalid: {exc}"
            ) from exc

    def _persist(self, event: Mapping[str, Any]) -> None:
        try:
            candidate = contracts.validate_journal_event(event)
            expected = contracts.append_transport_journal_event(
                self.journal, candidate
            )
            persisted = [
                contracts.validate_journal_event(row)
                for row in self._persist_milestone(candidate)
            ]
            if persisted != expected:
                raise CodexTransportControllerError(
                    "durable milestone sink returned a divergent journal"
                )
            self.journal = persisted
        except CodexTransportControllerError:
            raise
        except (contracts.CodexTransportContractError, TypeError, ValueError) as exc:
            raise CodexTransportControllerError(
                f"durable milestone persistence failed: {exc}"
            ) from exc

    def _on_process_start_pending(self, entry: ProcessJournalEntry) -> None:
        if entry.phase != "process_start_pending" or entry.pid is not None:
            raise CodexTransportControllerError(
                "process pending callback has invalid phase/PID"
            )
        self._persist(
            self._event(
                "process_start_pending",
                wire_method="process/start",
                correlation=_correlation(),
                payload_size_bytes=len(entry.payload_bytes),
                request_id=f"process:{self.launch_id}",
                request_bytes_sha256=entry.sha256,
            )
        )

    def _on_process_started(self, entry: ProcessJournalEntry) -> None:
        if entry.phase != "process_started" or not isinstance(entry.pid, int):
            raise CodexTransportControllerError(
                "process started callback has invalid phase/PID"
            )
        self._persist(
            self._event(
                "process_started",
                wire_method="process/started",
                correlation=_correlation(),
                payload_size_bytes=len(entry.payload_bytes),
                wire_event_sha256=entry.sha256,
            )
        )

    def _on_send_pending(self, entry: RequestJournalEntry) -> None:
        if entry.phase is not RequestPhase.SEND_PENDING:
            raise CodexTransportControllerError(
                "request callback is not SEND_PENDING"
            )
        try:
            event_type = _PENDING_BY_METHOD[entry.method]
        except KeyError as exc:
            raise CodexTransportControllerError(
                f"unsupported pending request method: {entry.method}"
            ) from exc
        correlation = self.state.correlation
        self._persist(
            self._event(
                event_type,
                wire_method=entry.method,
                correlation=correlation,
                payload_size_bytes=len(entry.wire_bytes),
                request_id=str(entry.request_id),
                request_bytes_sha256=entry.sha256,
            )
        )

    def _on_response(self, entry: RequestJournalEntry) -> None:
        if entry.phase is not RequestPhase.RESPONSE_RECEIVED:
            raise CodexTransportControllerError(
                "response callback is not RESPONSE_RECEIVED"
            )
        message = _strict_object(entry.wire_bytes)
        correlation = self.state.correlation
        if "error" in message:
            raise CodexTransportControllerError(
                "App Server error response cannot enter the success callback"
            )
        result = _object(message.get("result"), "App Server response result")
        event_type, wire_method = _OBSERVED_BY_METHOD[entry.method]
        if entry.method == "thread/start":
            thread = _object(result.get("thread"), "thread/start result thread")
            correlation = _correlation(
                _text(thread.get("id"), "thread/start result thread.id")
            )
        elif entry.method == "turn/start":
            turn = _object(result.get("turn"), "turn/start result turn")
            correlation = _correlation(
                correlation["thread_id"],
                _text(turn.get("id"), "turn/start result turn.id"),
            )
        self._persist(
            self._event(
                event_type,
                wire_method=wire_method,
                correlation=correlation,
                payload_size_bytes=len(entry.wire_bytes),
                wire_event_sha256=entry.sha256,
                response_sha256=entry.sha256,
            )
        )

    def _on_rejected_response(
        self, entry: RequestJournalEntry
    ) -> Mapping[str, Any]:
        if entry.phase is not RequestPhase.RESPONSE_RECEIVED:
            raise CodexTransportControllerError(
                "rejected response callback is not RESPONSE_RECEIVED"
            )
        try:
            reference = dict(
                self._persist_fault_evidence(
                    entry.wire_bytes,
                    f"Codex App Server {entry.method} rejected response",
                )
            )
        except CodexTransportControllerError:
            raise
        except Exception as exc:
            raise CodexTransportControllerError(
                "rejected response local CAS persistence failed"
            ) from exc
        if (
            reference.get("sha256") != entry.sha256
            or reference.get("size_bytes") != len(entry.wire_bytes)
        ):
            raise CodexTransportControllerError(
                "rejected response local CAS reference differs from exact wire bytes"
            )
        return reference

    def _record_observation(self, observation: TurnObservation) -> None:
        for event in observation.events:
            if event.method not in {"item/started", "item/completed", "turn/completed"}:
                continue
            raw = _runtime_event_bytes(event)
            params = event.params
            if event.method in {"item/started", "item/completed"}:
                item = _object(params.get("item"), f"{event.method} item")
                event_type = "item_started" if event.method.endswith("started") else "item_completed"
                correlation = _correlation(
                    _text(params.get("threadId"), f"{event.method} threadId"),
                    _text(params.get("turnId"), f"{event.method} turnId"),
                    _text(item.get("id"), f"{event.method} item.id"),
                )
                item_type = _text(item.get("type"), f"{event.method} item.type")
            else:
                turn = _object(params.get("turn"), "turn/completed turn")
                correlation = _correlation(
                    _text(params.get("threadId"), "turn/completed threadId"),
                    _text(turn.get("id"), "turn/completed turn.id"),
                )
                status = _text(turn.get("status"), "turn/completed turn.status")
                event_type = {
                    "completed": "completed",
                    "failed": "failed",
                    "interrupted": "interrupted",
                }.get(status, "")
                if not event_type:
                    raise CodexTransportControllerError(
                        f"unsupported turn/completed terminal status: {status!r}"
                    )
                item_type = None
            self._persist(
                self._event(
                    event_type,
                    wire_method=event.method,
                    correlation=correlation,
                    payload_size_bytes=len(raw),
                    wire_event_sha256=event.sha256,
                    item_type=item_type,
                )
            )

    def _fault_digest(self, exc: BaseException) -> tuple[str, str, int]:
        evidence_sha256 = getattr(exc, "evidence_sha256", None)
        evidence_size_bytes = getattr(exc, "evidence_size_bytes", None)
        if (
            isinstance(evidence_sha256, str)
            and len(evidence_sha256) == 64
            and isinstance(evidence_size_bytes, int)
            and not isinstance(evidence_size_bytes, bool)
            and evidence_size_bytes > 0
        ):
            return type(exc).__name__, evidence_sha256, evidence_size_bytes
        reason_code = self._fault_reason_code(exc)
        payload = json.dumps(
            {
                "exception_type": type(exc).__name__,
                "last_event_type": self.state.last_event_type,
                "reason_code": reason_code,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return type(exc).__name__, hashlib.sha256(payload).hexdigest(), len(payload)

    @staticmethod
    def _fault_reason_code(exc: BaseException) -> str:
        """Return a finite redacted reason code without hashing exception text."""

        supplied = getattr(exc, "reason_code", None)
        if isinstance(supplied, str) and supplied in {
            "app_server_error",
            "pinned_response_schema",
            "model_catalog_policy",
            "sealed_response_policy",
        }:
            return supplied
        message = str(exc).lower()
        if isinstance(exc, RuntimeDisconnected):
            if "timed out" in message:
                return "timeout"
            if "eof" in message:
                return "eof"
            if "write failed" in message or "stdin" in message:
                return "write_channel"
            return "runtime_disconnected"
        if isinstance(exc, AppServerError):
            if "correlation" in message:
                return "correlation"
            if "duplicate" in message:
                return "duplicate_event"
            if "unsupported" in message:
                return "unsupported_protocol"
            if "journal" in message or "persist" in message:
                return "durable_callback"
            return "app_server_fault"
        if isinstance(exc, CodexTransportControllerError):
            return "controller_contract"
        return "unexpected_fault"

    def _terminalize_fault(self, exc: BaseException) -> None:
        state = self.state
        if state.state in _TERMINAL_STATES:
            return
        last = self.journal[-1]
        fault_kind, digest, size = self._fault_digest(exc)
        known_rejected_start = isinstance(exc, AppServerResponseError) and (
            state.last_event_type
            in {"thread_start_send_pending", "turn_start_send_pending"}
        )
        if state.last_event_type in {
            "process_start_pending",
            "thread_start_send_pending",
            "turn_start_send_pending",
        } and not known_rejected_start:
            self._persist(
                self._event(
                    "launch_unknown",
                    wire_method=last["wire_method"],
                    correlation=state.correlation,
                    payload_size_bytes=size,
                    request_id=state.last_request_id,
                    request_bytes_sha256=state.last_request_bytes_sha256,
                    fault_kind=fault_kind,
                    fault_evidence_sha256=digest,
                    fault_evidence_size_bytes=size,
                )
            )
            return
        if state.state == "turn_started" or state.last_event_type == "interrupt_send_pending":
            event_type = "runtime_unknown"
            method = "runtime/disconnected"
        else:
            event_type = "failed"
            method = last["wire_method"] if state.last_event_type.endswith("_pending") else "process/exited"
        self._persist(
            self._event(
                event_type,
                wire_method=method,
                correlation=state.correlation,
                payload_size_bytes=size,
                fault_kind=fault_kind,
                fault_evidence_sha256=digest,
                fault_evidence_size_bytes=size,
            )
        )

    def _publish_runtime_terminal(self) -> dict[str, Any]:
        state = self.state
        if state.state not in _TERMINAL_STATES:
            raise CodexTransportControllerError(
                "cannot publish a non-terminal runtime receipt"
            )
        receipt = contracts.seal_terminal_receipt(
            {
                "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
                "reservation_sha256": self.reservation["reservation_sha256"],
                "journal_head_sha256": state.head_sha256,
                "terminal_state": state.state,
                "correlation": state.correlation,
                "evidence_level": "codex_runtime_observed",
                "mutation_verification": {
                    "status": "unavailable",
                    "object_sha256": None,
                },
            }
        )
        try:
            published = dict(self._publish_terminal(receipt))
        except Exception as exc:
            raise CodexTransportControllerError(
                "terminal receipt publication failed; retry publication only"
            ) from exc
        if published != receipt:
            raise CodexTransportControllerError(
                "terminal sink returned divergent receipt bytes"
            )
        self._terminal_receipt = receipt
        return receipt

    def run(
        self,
        adapter: CodexAppServerStdio,
        *,
        prompt: str,
        timeout_seconds: float = 60.0,
        interrupt_after_start: bool = False,
    ) -> ControllerResult:
        """Execute the fresh MVP launch once; never retry a start request."""

        if self.state.state != "reserved" or self.state.last_event_type != "reserved":
            raise CodexTransportControllerError(
                "controller run is not fresh; reconcile persisted state without launching"
            )
        callbacks = (
            adapter.on_process_start_pending,
            adapter.on_process_started,
            adapter.on_send_pending,
            adapter.on_response,
            adapter.on_rejected_response,
        )
        if any(callback is not None for callback in callbacks):
            raise CodexTransportControllerError(
                "adapter callbacks are already owned by another controller"
            )
        intent_view = SealedLaunchIntent.from_sealed_mapping(self.intent)
        adapter.on_process_start_pending = self._on_process_start_pending
        adapter.on_process_started = self._on_process_started
        adapter.on_send_pending = self._on_send_pending
        adapter.on_response = self._on_response
        adapter.on_rejected_response = self._on_rejected_response
        try:
            adapter.start()
            adapter.initialize()
            adapter.verify_model_from_intent(intent=intent_view)
            thread_id = adapter.start_thread_from_intent(intent=intent_view)
            turn_id = adapter.start_turn_from_intent(
                thread_id=thread_id, prompt=prompt, intent=intent_view
            )
            if interrupt_after_start:
                adapter.interrupt_turn(thread_id=thread_id, turn_id=turn_id)
            observation = adapter.observe_turn(
                thread_id=thread_id,
                turn_id=turn_id,
                timeout_seconds=timeout_seconds,
            )
            self._record_observation(observation)
        except (AppServerError, CodexTransportControllerError) as exc:
            self._terminalize_fault(exc)
        finally:
            adapter.close()
        receipt = self._publish_runtime_terminal()
        return ControllerResult(
            launch_id=self.launch_id,
            terminal_state=receipt["terminal_state"],
            terminal_receipt=receipt,
            journal=tuple(dict(row) for row in self.journal),
            runtime_completed=receipt["terminal_state"] == "completed",
        )

    def reconcile_after_crash(self) -> ControllerResult:
        """Terminalize persisted state without starting a process or resending.

        A start-pending journal becomes ``launch_unknown``.  A known active turn
        becomes ``runtime_unknown``.  Other pre-turn phases become a known
        controller failure.  An already-terminal journal only republishes its
        receipt, which makes publication-after-crash recovery explicit.
        """

        if self.state.state not in _TERMINAL_STATES:
            self._terminalize_fault(
                RuntimeDisconnected("controller restarted with persisted runtime state")
            )
        return self.republish_terminal_receipt()

    def republish_terminal_receipt(self) -> ControllerResult:
        """Retry only terminal receipt publication; no process/request is sent."""

        receipt = self._publish_runtime_terminal()
        return ControllerResult(
            launch_id=self.launch_id,
            terminal_state=receipt["terminal_state"],
            terminal_receipt=receipt,
            journal=tuple(dict(row) for row in self.journal),
            runtime_completed=receipt["terminal_state"] == "completed",
        )


__all__ = [
    "CodexTransportController",
    "CodexTransportControllerError",
    "ControllerResult",
    "PersistMilestone",
    "PersistFaultEvidence",
    "PublishTerminal",
]
