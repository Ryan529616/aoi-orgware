"""Fail-closed stdio client for the pinned Codex App Server protocol.

This is deliberately a transport primitive, not an AOI state writer.  Callers
must persist the returned phase markers and observations before assigning any
semantic meaning to them.  In particular, a request that reaches
``SEND_PENDING`` but has no durable response is ambiguous and must never be
retried automatically.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

from . import codex_transport_contracts as contracts
from .confidentiality import is_publish_credential_environment_name


DEFAULT_MAX_LINE_BYTES: Final = 1_048_576
DEFAULT_MAX_EVENTS: Final = 10_000
DEFAULT_MAX_STDERR_BYTES: Final = 1_048_576
DEFAULT_MAX_QUEUE_MESSAGES: Final = 1_024

_REQUEST_METHODS: Final = frozenset(
    {"initialize", "thread/start", "turn/start", "turn/interrupt"}
)
_NOTIFICATION_METHODS: Final = frozenset(
    {
        "account/login/completed",
        "account/rateLimits/updated",
        "account/updated",
        "app/list/updated",
        "command/exec/outputDelta",
        "configWarning",
        "deprecationNotice",
        "error",
        "externalAgentConfig/import/completed",
        "externalAgentConfig/import/progress",
        "fs/changed",
        "fuzzyFileSearch/sessionCompleted",
        "fuzzyFileSearch/sessionUpdated",
        "guardianWarning",
        "hook/completed",
        "hook/started",
        "item/agentMessage/delta",
        "item/autoApprovalReview/completed",
        "item/autoApprovalReview/started",
        "item/commandExecution/outputDelta",
        "item/commandExecution/terminalInteraction",
        "thread/started",
        "item/fileChange/outputDelta",
        "item/fileChange/patchUpdated",
        "item/mcpToolCall/progress",
        "item/completed",
        "item/plan/delta",
        "item/reasoning/summaryPartAdded",
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "item/started",
        "mcpServer/oauthLogin/completed",
        "mcpServer/startupStatus/updated",
        "model/rerouted",
        "model/safetyBuffering/updated",
        "model/verification",
        "process/exited",
        "process/outputDelta",
        "remoteControl/status/changed",
        "serverRequest/resolved",
        "skills/changed",
        "thread/archived",
        "thread/closed",
        "thread/compacted",
        "thread/deleted",
        "thread/goal/cleared",
        "thread/goal/updated",
        "thread/name/updated",
        "thread/realtime/closed",
        "thread/realtime/error",
        "thread/realtime/itemAdded",
        "thread/realtime/outputAudio/delta",
        "thread/realtime/sdp",
        "thread/realtime/started",
        "thread/realtime/transcript/delta",
        "thread/realtime/transcript/done",
        "thread/settings/updated",
        "thread/status/changed",
        "thread/tokenUsage/updated",
        "thread/unarchived",
        "turn/completed",
        "turn/diff/updated",
        "turn/moderationMetadata",
        "turn/plan/updated",
        "turn/started",
        "warning",
        "windows/worldWritableWarning",
        "windowsSandbox/setupCompleted",
    }
)
_LIFECYCLE_NOTIFICATION_METHODS: Final = frozenset(
    {"thread/started", "turn/started", "item/started", "item/completed", "turn/completed"}
)
_AUXILIARY_NOTIFICATION_METHODS: Final = (
    _NOTIFICATION_METHODS - _LIFECYCLE_NOTIFICATION_METHODS
)
_ITEM_TYPES: Final = frozenset(
    {
        "userMessage",
        "hookPrompt",
        "agentMessage",
        "plan",
        "reasoning",
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "dynamicToolCall",
        "collabAgentToolCall",
        "subAgentActivity",
        "webSearch",
        "imageView",
        "sleep",
        "imageGeneration",
        "enteredReviewMode",
        "exitedReviewMode",
        "contextCompaction",
    }
)
_AOI_SECRET_ENV_PREFIXES: Final = ("AOI_CHIEF_", "AOI_ROOT_", "AOI_CREDENTIAL_")
_AOI_SECRET_ENV_NAMES: Final = frozenset(
    {"AOI_CHIEF_SESSION_ID", "AOI_CHIEF_EPOCH", "AOI_CHIEF_CREDENTIAL_FILE"}
)


class AppServerError(RuntimeError):
    """Base class for failures that callers must record as runtime evidence."""


class ProtocolViolation(AppServerError):
    """The peer sent data outside the explicitly supported protocol subset."""


class RuntimeDisconnected(AppServerError):
    """The App Server stream ended before a required response or terminal event."""


class ServerRequestDenied(ProtocolViolation):
    """The server requested approval, user input, or any other client action."""


class RequestPhase(str, Enum):
    """Durable crash markers for a single non-idempotent JSON-RPC request."""

    BEFORE_SEND = "before_send"
    SEND_PENDING = "send_pending"
    RESPONSE_RECEIVED = "response_received"


@dataclass(frozen=True)
class RequestReceipt:
    request_id: int
    method: str
    phase: RequestPhase
    response: dict[str, Any] | None = None


@dataclass(frozen=True)
class RequestJournalEntry:
    """Exact wire bytes offered to an upper-layer durable journal.

    This adapter invokes observers synchronously but does not itself make any
    persistence claim.  A controller must fail the launch when its journal
    observer fails.
    """

    request_id: int
    method: str
    phase: RequestPhase
    wire_bytes: bytes
    sha256: str


@dataclass(frozen=True)
class ProcessJournalEntry:
    """Exact bounded process-start observation offered to the controller."""

    phase: str
    payload_bytes: bytes
    sha256: str
    pid: int | None


@dataclass(frozen=True)
class RuntimePin:
    codex_cli_version: str
    executable_sha256: str
    executable_size_bytes: int
    app_server_version: str
    schema_manifest_sha256: str
    combined_v2_schema_sha256: str


@dataclass(frozen=True)
class SealedLaunchIntent:
    """Validated view of the canonical transport launch-intent contract."""

    sha256: str
    cwd: str
    model: str
    effort: str
    sandbox: str
    prompt_sha256: str
    prompt_size_bytes: int
    executable_path: str

    @classmethod
    def from_sealed_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        expected_sha256: str | None = None,
    ) -> "SealedLaunchIntent":
        try:
            checked = contracts.validate_launch_intent(payload)
        except contracts.CodexTransportContractError as exc:
            raise ProtocolViolation(f"sealed launch intent is invalid: {exc}") from exc
        actual = checked["intent_sha256"]
        if expected_sha256 is not None and actual != expected_sha256:
            raise ProtocolViolation("sealed launch intent SHA-256 differs from expected digest")
        runtime_pin = checked["runtime_pin"]
        return cls(
            sha256=actual,
            cwd=checked["cwd"],
            model=checked["requested_model"],
            effort=checked["requested_effort"],
            sandbox=checked["sandbox"],
            prompt_sha256=checked["prompt_sha256"],
            prompt_size_bytes=checked["prompt_size_bytes"],
            executable_path=runtime_pin["executable_path"],
        )


@dataclass(frozen=True)
class RuntimeEvent:
    method: str
    params: dict[str, Any]
    sha256: str


@dataclass(frozen=True)
class TurnObservation:
    thread_id: str
    turn_id: str
    terminal_status: str
    events: tuple[RuntimeEvent, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolViolation(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolViolation("protocol line is not strict UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ProtocolViolation("malformed JSON-RPC line") from exc
    if not isinstance(value, dict):
        raise ProtocolViolation("JSON-RPC message must be an object")
    return value


def scrub_aoi_secret_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Copy an environment without known reusable AOI/publication authority.

    The finite bridge never needs Git-host, package-registry, artifact-store,
    or connector upload credentials.  Model-service authentication is not
    removed: ``local_files`` permits model context and is not an offline mode.
    """

    result = dict(os.environ if source is None else source)
    for name in tuple(result):
        upper_name = name.upper()
        if (
            upper_name in _AOI_SECRET_ENV_NAMES
            or upper_name.startswith(_AOI_SECRET_ENV_PREFIXES)
            or is_publish_credential_environment_name(name)
        ):
            result.pop(name, None)
    return result


class CodexAppServerStdio:
    """One local standalone ``codex-app-server --listen stdio://`` process.

    The client permits exactly one outstanding request.  That restriction makes
    response correlation and the request crash markers unambiguous, and is the
    intended single-packet/single-turn MVP shape.
    """

    def __init__(
        self,
        executable: str | Path,
        *,
        cwd: str | Path,
        environment: Mapping[str, str] | None = None,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
        max_queue_messages: int = DEFAULT_MAX_QUEUE_MESSAGES,
        runtime_pin: RuntimePin | None = None,
        on_process_start_pending: Callable[[ProcessJournalEntry], None] | None = None,
        on_process_started: Callable[[ProcessJournalEntry], None] | None = None,
        on_send_pending: Callable[[RequestJournalEntry], None] | None = None,
        on_response: Callable[[RequestJournalEntry], None] | None = None,
        _test_launch_args: tuple[str, ...] | None = None,
        _test_version_args: tuple[str, ...] | None = None,
    ) -> None:
        executable_path = Path(executable)
        if not executable_path.is_absolute():
            raise ValueError("Codex App Server executable must be an absolute path")
        if max_line_bytes < 128 or max_events < 1 or max_stderr_bytes < 1 or max_queue_messages < 1:
            raise ValueError("stdio bounds must be positive and line bound at least 128")
        if executable_path.is_symlink():
            raise ValueError("Codex App Server executable must not be a symlink")
        if runtime_pin is not None and (
            _test_launch_args is None or _test_version_args is None
        ):
            raise ValueError("runtime pin override is available only to an explicit test peer")
        self.executable = executable_path
        self.cwd = Path(cwd)
        self.environment = scrub_aoi_secret_env(environment)
        self.max_line_bytes = max_line_bytes
        self.max_events = max_events
        self.max_stderr_bytes = max_stderr_bytes
        self.max_queue_messages = max_queue_messages
        self.runtime_pin = runtime_pin or _load_packaged_runtime_pin()
        self.on_process_start_pending = on_process_start_pending
        self.on_process_started = on_process_started
        self.on_send_pending = on_send_pending
        self.on_response = on_response
        # This narrow injection point lets tests run a scripted Python peer.
        # Production callers must use the standalone App Server default below.
        self._launch_args = _test_launch_args or ("--listen", "stdio://")
        self._version_args = _test_version_args or ("--version",)
        self._process: subprocess.Popen[bytes] | None = None
        self._incoming: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=max_queue_messages)
        self._notifications: list[RuntimeEvent] = []
        self._seen_events: dict[tuple[str, str], str] = {}
        self._request_lock = threading.Lock()
        self._next_request_id = 1
        self.last_receipt: RequestReceipt | None = None
        self._initialized = False
        self._thread_id: str | None = None
        self._turn_id: str | None = None
        self._turn_terminal = False
        self._intent: SealedLaunchIntent | None = None
        self._reader_error: AppServerError | None = None
        self._stdout_message_count = 0
        self._stdout_total_bytes = 0
        self._stderr = b""
        self._stderr_total_bytes = 0
        self._stderr_truncated = False
        self._stderr_hasher = hashlib.sha256()
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

    @property
    def argv(self) -> tuple[str, ...]:
        return (str(self.executable), *self._launch_args)

    @property
    def runtime_metadata(self) -> dict[str, Any]:
        return {
            "executable": str(self.executable),
            "codex_cli_version": self.runtime_pin.codex_cli_version,
            "executable_sha256": self.runtime_pin.executable_sha256,
            "executable_size_bytes": self.runtime_pin.executable_size_bytes,
            "app_server_version": self.runtime_pin.app_server_version,
            "schema_manifest_sha256": self.runtime_pin.schema_manifest_sha256,
            "combined_v2_schema_sha256": self.runtime_pin.combined_v2_schema_sha256,
            "stderr_sha256": self.stderr_digest,
            "stderr_total_bytes": self._stderr_total_bytes,
            "stderr_truncated": self._stderr_truncated,
            "event_count": self.event_count,
            "event_sha256": self.event_digest,
            "stdout_message_count": self._stdout_message_count,
            "stdout_total_bytes": self._stdout_total_bytes,
        }

    @property
    def stderr_digest(self) -> str:
        return self._stderr_hasher.hexdigest()

    @property
    def event_count(self) -> int:
        return len(self._seen_events)

    @property
    def event_digest(self) -> str:
        aggregate = "".join(
            f"{identity[0]}:{identity[1]}:{digest}\n"
            for identity, digest in sorted(self._seen_events.items())
        ).encode("utf-8")
        return hashlib.sha256(aggregate).hexdigest()

    @property
    def stderr_bytes(self) -> bytes:
        return self._stderr

    def start(self) -> None:
        if self._process is not None:
            raise AppServerError("App Server process already started")
        if not self.executable.is_file():
            raise AppServerError(f"App Server executable does not exist: {self.executable}")
        if not self.cwd.is_dir():
            raise AppServerError(f"App Server cwd does not exist: {self.cwd}")
        self._verify_runtime_pin()
        # This durable boundary authorizes every process execution that follows
        # in the exact pinned-runtime start sequence: the bounded ``--version``
        # probe and then the long-lived App Server Popen.  No child process may
        # execute before the callback succeeds.
        pending_entry = self._process_journal_entry("process_start_pending")
        if self.on_process_start_pending is not None:
            try:
                self.on_process_start_pending(pending_entry)
            except Exception as exc:
                raise AppServerError(
                    "process_start_pending journal callback failed; process was not started"
                ) from exc
        self._verify_runtime_version()
        # Rehash after version probing and immediately before App Server exec
        # to narrow the executable replacement window.  The process image is
        # then opened by CreateProcess/exec without a shell or PATH lookup.
        self._verify_runtime_pin()
        self._stderr = b""
        self._stderr_total_bytes = 0
        self._stderr_truncated = False
        self._stderr_hasher = hashlib.sha256()
        try:
            self._process = subprocess.Popen(
                list(self.argv),
                cwd=self.cwd,
                env=self.environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError as exc:
            raise AppServerError("could not start Codex App Server") from exc
        assert self._process.stdout is not None and self._process.stderr is not None
        self._stdout_thread = threading.Thread(target=self._stdout_reader, daemon=True, name="aoi-app-server-stdout")
        self._stderr_thread = threading.Thread(target=self._stderr_reader, daemon=True, name="aoi-app-server-stderr")
        self._stdout_thread.start()
        self._stderr_thread.start()
        started_entry = self._process_journal_entry(
            "process_started", pid=self._process.pid
        )
        if self.on_process_started is not None:
            try:
                self.on_process_started(started_entry)
            except Exception as exc:
                self.close()
                raise AppServerError(
                    "process_started journal callback failed; process was terminated"
                ) from exc

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        self._process = None
        for reader in (self._stdout_thread, self._stderr_thread):
            if reader is not None:
                reader.join(timeout=2)

    def __enter__(self) -> "CodexAppServerStdio":
        self.start()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def initialize(self, *, client_name: str = "aoi-orgware", client_version: str = "0.4") -> dict[str, Any]:
        if self._initialized:
            raise AppServerError("initialize may be called only once")
        response = self.request(
            "initialize",
            {
                "clientInfo": {"name": client_name, "version": client_version},
                "capabilities": {"experimentalApi": False, "requestAttestation": False},
            },
        )
        self._send_notification("initialized", {})
        self._initialized = True
        return response

    def start_thread_from_intent(
        self,
        *,
        intent: SealedLaunchIntent,
    ) -> str:
        self._require_initialized()
        if self._thread_id is not None:
            raise AppServerError("MVP permits exactly one thread/start")
        self._validate_intent_context(intent)
        params: dict[str, Any] = {
            "cwd": intent.cwd,
            "approvalPolicy": "never",
            "sandbox": {
                "readOnly": "read-only",
                "workspaceWrite": "workspace-write",
            }[intent.sandbox],
            "serviceName": "aoi-orgware",
            "ephemeral": True,
            "model": intent.model,
        }
        response = self.request("thread/start", params)
        thread = _require_object(response.get("thread"), "thread/start response thread")
        thread_id = _require_string(thread.get("id"), "thread/start response thread.id")
        self._validate_buffered_events(thread_id=thread_id, turn_id=None)
        self._thread_id = thread_id
        self._intent = intent
        return thread_id

    def start_turn_from_intent(
        self,
        *,
        thread_id: str,
        prompt: str,
        intent: SealedLaunchIntent,
    ) -> str:
        self._require_initialized()
        if self._thread_id != thread_id or self._intent != intent:
            raise ProtocolViolation("turn/start must bind to the validated thread launch intent")
        if self._turn_id is not None:
            raise AppServerError("MVP permits exactly one turn/start")
        self._validate_intent_context(intent)
        prompt_text = _require_string(prompt, "prompt")
        prompt_bytes = prompt_text.encode("utf-8")
        if (
            len(prompt_bytes) != intent.prompt_size_bytes
            or hashlib.sha256(prompt_bytes).hexdigest() != intent.prompt_sha256
        ):
            raise ProtocolViolation("turn/start prompt bytes do not match sealed launch intent")
        if intent.sandbox == "readOnly":
            sandbox_policy: dict[str, Any] = {
                "type": "readOnly",
                "networkAccess": False,
            }
        else:
            sandbox_policy = {
                "type": "workspaceWrite",
                "networkAccess": False,
                "writableRoots": [intent.cwd],
                "excludeSlashTmp": True,
                "excludeTmpdirEnvVar": True,
            }
        params: dict[str, Any] = {
            "threadId": _require_string(thread_id, "thread_id"),
            "input": [{"type": "text", "text": prompt_text}],
            "approvalPolicy": "never",
            "sandboxPolicy": sandbox_policy,
            "cwd": intent.cwd,
            "model": intent.model,
            "effort": intent.effort,
        }
        response = self.request("turn/start", params)
        turn = _require_object(response.get("turn"), "turn/start response turn")
        turn_id = _require_string(turn.get("id"), "turn/start response turn.id")
        self._validate_buffered_events(thread_id=thread_id, turn_id=turn_id)
        self._turn_id = turn_id
        return turn_id

    def interrupt_turn(self, *, thread_id: str, turn_id: str) -> dict[str, Any]:
        self._require_initialized()
        if self._thread_id != thread_id or self._turn_id != turn_id or self._turn_terminal:
            raise AppServerError("turn/interrupt is allowed only for the active MVP turn")
        return self.request(
            "turn/interrupt",
            {"threadId": _require_string(thread_id, "thread_id"), "turnId": _require_string(turn_id, "turn_id")},
        )

    def observe_turn(self, *, thread_id: str, turn_id: str, timeout_seconds: float = 60.0) -> TurnObservation:
        """Consume buffered/live lifecycle notifications through ``turn/completed``."""

        deadline = time.monotonic() + timeout_seconds
        observed: list[RuntimeEvent] = []
        while True:
            event = self._next_notification(deadline)
            self._validate_event(event, thread_id=thread_id, turn_id=turn_id)
            observed.append(event)
            if event.method == "turn/completed":
                turn = _require_object(event.params.get("turn"), "turn/completed turn")
                status = _require_string(turn.get("status"), "turn/completed turn.status")
                if status not in {"completed", "failed", "interrupted"}:
                    raise ProtocolViolation(f"turn/completed has non-terminal status: {status!r}")
                self._turn_terminal = True
                return TurnObservation(thread_id, turn_id, status, tuple(observed))

    def request(self, method: str, params: Mapping[str, Any], *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        if method not in _REQUEST_METHODS:
            raise ValueError(f"unsupported client request method: {method}")
        process = self._require_process()
        if process.stdin is None:
            raise RuntimeDisconnected("App Server stdin is unavailable")
        with self._request_lock:
            request_id = self._next_request_id
            self._next_request_id += 1
            message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
            encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(encoded) > self.max_line_bytes:
                raise ValueError("outgoing JSON-RPC request exceeds line limit")
            self.last_receipt = RequestReceipt(request_id, method, RequestPhase.BEFORE_SEND)
            pending_entry = RequestJournalEntry(
                request_id,
                method,
                RequestPhase.SEND_PENDING,
                encoded,
                hashlib.sha256(encoded).hexdigest(),
            )
            if self.on_send_pending is not None:
                try:
                    self.on_send_pending(pending_entry)
                except Exception as exc:
                    raise AppServerError("send_pending journal callback failed; request was not written") from exc
            try:
                process.stdin.write(encoded)
                process.stdin.flush()
            except OSError as exc:
                raise RuntimeDisconnected(f"App Server write failed during {method}") from exc
            self.last_receipt = RequestReceipt(request_id, method, RequestPhase.SEND_PENDING)
            response = self._wait_response(request_id, deadline=time.monotonic() + timeout_seconds)
            self.last_receipt = RequestReceipt(request_id, method, RequestPhase.RESPONSE_RECEIVED, response)
            return response

    def _send_notification(self, method: str, params: Mapping[str, Any]) -> None:
        process = self._require_process()
        if process.stdin is None:
            raise RuntimeDisconnected("App Server stdin is unavailable")
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": dict(params)}, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(payload) > self.max_line_bytes:
            raise ValueError("outgoing JSON-RPC notification exceeds line limit")
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except OSError as exc:
            raise RuntimeDisconnected(f"App Server write failed during {method}") from exc

    def _wait_response(self, request_id: int, *, deadline: float) -> dict[str, Any]:
        while True:
            kind, payload = self._next_incoming(deadline)
            if kind == "notification":
                self._record_notification(payload, buffer=True)
                continue
            if kind == "server_request":
                raise ServerRequestDenied(_server_request_message(payload))
            if kind == "response":
                message, raw = payload
                if message["id"] != request_id:
                    raise ProtocolViolation(
                        f"response id {message['id']!r} does not match outstanding request {request_id}"
                    )
                entry = RequestJournalEntry(
                    request_id,
                    str(self.last_receipt.method if self.last_receipt else "unknown"),
                    RequestPhase.RESPONSE_RECEIVED,
                    raw,
                    hashlib.sha256(raw).hexdigest(),
                )
                if self.on_response is not None:
                    try:
                        self.on_response(entry)
                    except Exception as exc:
                        raise AppServerError("response journal callback failed") from exc
                if "error" in message:
                    raise AppServerError(f"App Server error response to request {request_id}: {message['error']!r}")
                return _require_object(message.get("result"), "JSON-RPC response result")
            raise ProtocolViolation(f"internal reader emitted unknown kind: {kind}")

    def _next_notification(self, deadline: float) -> RuntimeEvent:
        if self._notifications:
            return self._notifications.pop(0)
        while True:
            kind, payload = self._next_incoming(deadline)
            if kind == "notification":
                event = self._record_notification(payload, buffer=False)
                if event is not None:
                    return event
                continue
            if kind == "server_request":
                raise ServerRequestDenied(_server_request_message(payload))
            if kind == "response":
                raise ProtocolViolation("unexpected response without an outstanding request")
            raise ProtocolViolation(f"internal reader emitted unknown kind: {kind}")

    def _next_incoming(self, deadline: float) -> tuple[str, Any]:
        if self._reader_error is not None:
            raise self._reader_error
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeDisconnected("timed out waiting for App Server protocol data")
        try:
            kind, payload = self._incoming.get(timeout=remaining)
        except queue.Empty as exc:
            raise RuntimeDisconnected("timed out waiting for App Server protocol data") from exc
        if kind == "eof":
            raise RuntimeDisconnected("App Server stdout reached EOF")
        if self._reader_error is not None:
            raise self._reader_error
        if kind == "error":
            if isinstance(payload, AppServerError):
                raise payload
            raise ProtocolViolation("App Server reader failed") from payload
        return kind, payload

    def _stdout_reader(self) -> None:
        process = self._require_process()
        assert process.stdout is not None
        try:
            while True:
                raw = process.stdout.readline(self.max_line_bytes + 1)
                if not raw:
                    self._enqueue(("eof", None))
                    return
                if len(raw) > self.max_line_bytes or not raw.endswith(b"\n"):
                    raise ProtocolViolation("protocol line exceeds configured byte bound")
                self._stdout_message_count += 1
                self._stdout_total_bytes += len(raw)
                if self._stdout_message_count > self.max_events or self._stdout_total_bytes > self.max_line_bytes * self.max_events:
                    raise ProtocolViolation("App Server stdout aggregate limit exceeded")
                message = _strict_json_object(raw[:-1])
                self._enqueue(self._classify_incoming(message, raw))
        except BaseException as exc:  # reader must surface a deterministic protocol fault
            error = exc if isinstance(exc, AppServerError) else ProtocolViolation("App Server stdout reader failed")
            self._reader_error = error
            self._enqueue(("error", error))

    def _stderr_reader(self) -> None:
        process = self._require_process()
        assert process.stderr is not None
        chunks: list[bytes] = []
        captured = 0
        while True:
            chunk = process.stderr.read(65_536)
            if not chunk:
                break
            self._stderr_total_bytes += len(chunk)
            self._stderr_hasher.update(chunk)
            remaining = self.max_stderr_bytes - captured
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                captured += len(kept)
            if len(chunk) > max(remaining, 0):
                self._stderr_truncated = True
        self._stderr = b"".join(chunks)

    def _enqueue(self, item: tuple[str, Any]) -> None:
        try:
            self._incoming.put_nowait(item)
        except queue.Full:
            self._reader_error = ProtocolViolation("App Server reader queue/backpressure limit exceeded")

    def _classify_incoming(self, message: dict[str, Any], raw: bytes) -> tuple[str, Any]:
        if message.get("jsonrpc") != "2.0":
            raise ProtocolViolation("JSON-RPC version must be exactly '2.0'")
        if "method" in message:
            method = _require_string(message["method"], "incoming method")
            params = message.get("params", {})
            _require_object(params, "incoming notification/request params")
            if "id" in message:
                return ("server_request", message)
            if method not in _NOTIFICATION_METHODS:
                raise ProtocolViolation(f"unsupported App Server notification method: {method}")
            return ("notification", message)
        if "id" not in message:
            raise ProtocolViolation("JSON-RPC message is neither request, notification, nor response")
        if not isinstance(message["id"], int) or isinstance(message["id"], bool):
            raise ProtocolViolation("response id must be an integer")
        if "result" not in message and "error" not in message:
            raise ProtocolViolation("JSON-RPC response has neither result nor error")
        if "result" in message and "error" in message:
            raise ProtocolViolation("JSON-RPC response contains both result and error")
        return ("response", (message, raw))

    def _record_notification(self, message: dict[str, Any], *, buffer: bool) -> RuntimeEvent | None:
        method = _require_string(message.get("method"), "notification method")
        params = _require_object(message.get("params"), "notification params")
        canonical = json.dumps(message, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        event = RuntimeEvent(method, params, hashlib.sha256(canonical).hexdigest())
        identity = _event_identity(event)
        previous = self._seen_events.get(identity)
        if previous is not None:
            if previous != event.sha256:
                raise ProtocolViolation(f"conflicting duplicate App Server event: {identity!r}")
            return None
        if len(self._seen_events) >= self.max_events:
            raise ProtocolViolation("App Server event limit exceeded")
        self._seen_events[identity] = event.sha256
        if buffer:
            self._notifications.append(event)
        return event

    def _validate_buffered_events(self, *, thread_id: str, turn_id: str | None) -> None:
        for event in self._notifications:
            self._validate_event(event, thread_id=thread_id, turn_id=turn_id, allow_future_turn=turn_id is None)

    @staticmethod
    def _validate_event(
        event: RuntimeEvent,
        *,
        thread_id: str,
        turn_id: str | None,
        allow_future_turn: bool = False,
    ) -> None:
        params = event.params
        if event.method in _AUXILIARY_NOTIFICATION_METHODS:
            _validate_auxiliary_correlation(
                event,
                thread_id=thread_id,
                turn_id=turn_id,
                allow_future_turn=allow_future_turn,
            )
            return
        if event.method == "thread/started":
            thread = _require_object(params.get("thread"), "thread/started thread")
            if _require_string(thread.get("id"), "thread/started thread.id") != thread_id:
                raise ProtocolViolation("thread/started correlation mismatch")
            return
        observed_thread = _require_string(params.get("threadId"), f"{event.method} threadId")
        if observed_thread != thread_id:
            raise ProtocolViolation(f"{event.method} thread correlation mismatch")
        if event.method == "turn/started":
            turn = _require_object(params.get("turn"), "turn/started turn")
            observed_turn = _require_string(turn.get("id"), "turn/started turn.id")
        elif event.method == "turn/completed":
            turn = _require_object(params.get("turn"), "turn/completed turn")
            observed_turn = _require_string(turn.get("id"), "turn/completed turn.id")
        else:
            observed_turn = _require_string(params.get("turnId"), f"{event.method} turnId")
            item = _require_object(params.get("item"), f"{event.method} item")
            item_type = _require_string(item.get("type"), f"{event.method} item.type")
            _require_string(item.get("id"), f"{event.method} item.id")
            if item_type not in _ITEM_TYPES:
                raise ProtocolViolation(f"unsupported App Server item type: {item_type}")
        if turn_id is not None and observed_turn != turn_id:
            raise ProtocolViolation(f"{event.method} turn correlation mismatch")
        if turn_id is None and not allow_future_turn:
            raise ProtocolViolation(f"{event.method} arrived before a turn was established")

    def _require_process(self) -> subprocess.Popen[bytes]:
        if self._process is None:
            raise AppServerError("App Server process is not started")
        return self._process

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise AppServerError("initialize/initialized handshake has not completed")

    def _validate_intent_context(self, intent: SealedLaunchIntent) -> None:
        try:
            executable = self.executable.resolve(strict=True).as_posix()
            cwd = self.cwd.resolve(strict=True).as_posix()
        except OSError as exc:
            raise AppServerError("could not resolve launch intent executable/cwd") from exc
        if intent.executable_path != executable:
            raise ProtocolViolation("sealed launch intent executable path differs from active App Server")
        if intent.cwd != cwd:
            raise ProtocolViolation("sealed launch intent cwd differs from active App Server cwd")

    def _process_journal_entry(
        self, phase: str, *, pid: int | None = None
    ) -> ProcessJournalEntry:
        payload = {
            "phase": phase,
            "argv": list(self.argv),
            "cwd": self.cwd.resolve(strict=True).as_posix(),
            "executable_sha256": self.runtime_pin.executable_sha256,
            "executable_size_bytes": self.runtime_pin.executable_size_bytes,
            "pid": pid,
        }
        raw = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(raw) > self.max_line_bytes:
            raise AppServerError("process journal entry exceeds configured byte bound")
        return ProcessJournalEntry(
            phase=phase,
            payload_bytes=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
            pid=pid,
        )

    def _verify_runtime_pin(self) -> None:
        if self.executable.is_symlink() or not self.executable.is_file():
            raise AppServerError("pinned App Server executable is missing or is a symlink")
        try:
            if self.executable.resolve(strict=True) != self.executable:
                raise AppServerError("pinned App Server executable resolves through a symlink")
        except OSError as exc:
            raise AppServerError("could not resolve pinned App Server executable") from exc
        if self.executable.stat().st_size != self.runtime_pin.executable_size_bytes:
            raise AppServerError("App Server executable size does not match packaged runtime pin")
        digest = _sha256_file(self.executable)
        if digest != self.runtime_pin.executable_sha256:
            raise AppServerError("App Server executable SHA-256 does not match packaged runtime pin")

    def _verify_runtime_version(self) -> None:
        try:
            completed = subprocess.run(
                [str(self.executable), *self._version_args],
                cwd=self.cwd,
                env=self.environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AppServerError("could not execute pinned App Server --version") from exc
        try:
            version = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise AppServerError("pinned App Server --version is not strict UTF-8") from exc
        if completed.returncode != 0 or version != self.runtime_pin.app_server_version:
            raise AppServerError("App Server --version does not match packaged runtime pin")


def _event_identity(event: RuntimeEvent) -> tuple[str, str]:
    params = event.params
    if event.method in {"item/started", "item/completed"}:
        item = _require_object(params.get("item"), f"{event.method} item")
        return (event.method, ":".join((_require_string(params.get("threadId"), "item threadId"), _require_string(params.get("turnId"), "item turnId"), _require_string(item.get("id"), "item id"))))
    if event.method in {"turn/started", "turn/completed"}:
        turn = _require_object(params.get("turn"), f"{event.method} turn")
        return (event.method, ":".join((_require_string(params.get("threadId"), "turn threadId"), _require_string(turn.get("id"), "turn id"))))
    if event.method == "thread/started":
        thread = _require_object(params.get("thread"), "thread/started thread")
        return (event.method, _require_string(thread.get("id"), "thread id"))
    if event.method in _AUXILIARY_NOTIFICATION_METHODS:
        correlation = _auxiliary_correlation(event)
        if correlation is not None:
            thread_id, turn_id, item_id = correlation
            # Auxiliary streams such as deltas can legitimately emit multiple
            # payloads for one item.  Bind their explicit correlation IDs *and*
            # retain a payload component so distinct progress updates are not
            # falsely collapsed as duplicate events.
            payload_sha256 = hashlib.sha256(
                json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            return (
                event.method,
                "thread="
                + thread_id
                + ";turn="
                + (turn_id or "")
                + ";item="
                + (item_id or "")
                + ";payload="
                + payload_sha256,
            )
    return (event.method, hashlib.sha256(json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest())


def _auxiliary_correlation(event: RuntimeEvent) -> tuple[str, str | None, str | None] | None:
    """Extract an auxiliary event's IDs without treating global events as scoped.

    The generated App Server protocol has global notifications mixed with
    thread-, turn-, and item-scoped notifications.  An ID-bearing notification
    must be structurally correlated: an item belongs to a turn, and a turn
    belongs to a thread.  This helper deliberately does not infer identity
    from free-form payload fields.
    """

    params = event.params
    has_thread_id = "threadId" in params
    has_thread = "thread" in params
    has_turn_id = "turnId" in params
    has_turn = "turn" in params
    has_item_id = "itemId" in params
    has_item = "item" in params
    if not (
        has_thread_id
        or has_thread
        or has_turn_id
        or has_turn
        or has_item_id
        or has_item
    ):
        return None
    if not (has_thread_id or has_thread):
        raise ProtocolViolation(
            f"{event.method} auxiliary notification carries scoped data without thread identity"
        )
    thread_id = (
        _require_string(params.get("threadId"), f"{event.method} threadId")
        if has_thread_id
        else None
    )
    if has_thread:
        thread = _require_object(params.get("thread"), f"{event.method} thread")
        nested_thread_id = _require_string(
            thread.get("id"), f"{event.method} thread.id"
        )
        if thread_id is not None and thread_id != nested_thread_id:
            raise ProtocolViolation(
                f"{event.method} auxiliary thread identifiers disagree"
            )
        thread_id = nested_thread_id
    if thread_id is None:
        raise ProtocolViolation(
            f"{event.method} auxiliary notification has no usable thread identity"
        )
    turn_id = (
        _require_string(
            params.get("turnId"), f"{event.method} turnId"
        )
        if has_turn_id
        else None
    )
    if has_turn:
        turn = _require_object(params.get("turn"), f"{event.method} turn")
        nested_turn_id = _require_string(turn.get("id"), f"{event.method} turn.id")
        if turn_id is not None and turn_id != nested_turn_id:
            raise ProtocolViolation(
                f"{event.method} auxiliary turn identifiers disagree"
            )
        turn_id = nested_turn_id
    item_id: str | None = None
    if has_item_id:
        item_id = _require_string(params.get("itemId"), f"{event.method} itemId")
    if has_item:
        item = _require_object(params.get("item"), f"{event.method} item")
        nested_item_id = _require_string(item.get("id"), f"{event.method} item.id")
        if item_id is not None and item_id != nested_item_id:
            raise ProtocolViolation(
                f"{event.method} auxiliary item identifiers disagree"
            )
        item_id = nested_item_id
    if item_id is not None and turn_id is None:
        raise ProtocolViolation(
            f"{event.method} auxiliary item data arrived without turnId"
        )
    return thread_id, turn_id, item_id


def _validate_auxiliary_correlation(
    event: RuntimeEvent,
    *,
    thread_id: str,
    turn_id: str | None,
    allow_future_turn: bool,
) -> None:
    correlation = _auxiliary_correlation(event)
    if correlation is None:
        return
    observed_thread, observed_turn, _item_id = correlation
    if observed_thread != thread_id:
        raise ProtocolViolation(f"{event.method} auxiliary thread correlation mismatch")
    if observed_turn is None:
        return
    if turn_id is not None and observed_turn != turn_id:
        raise ProtocolViolation(f"{event.method} auxiliary turn correlation mismatch")
    if turn_id is None and not allow_future_turn:
        raise ProtocolViolation(
            f"{event.method} auxiliary turn data arrived before a turn was established"
        )


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolViolation(f"{label} must be an object")
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolViolation(f"{label} must be a non-empty string")
    return value


def _server_request_message(message: Mapping[str, Any]) -> str:
    method = str(message.get("method", "unknown"))
    return f"App Server initiated unsupported request {method!r}; approvals, user input, and elicitations are fail-closed"


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _load_packaged_runtime_pin() -> RuntimePin:
    try:
        binding = contracts.pinned_runtime_binding()
        return RuntimePin(
            codex_cli_version=str(binding["codex_cli_version"]),
            executable_sha256=str(binding["app_server_executable_sha256"]),
            executable_size_bytes=int(binding["executable_size_bytes"]),
            app_server_version=str(binding["codex_app_server_version"]),
            schema_manifest_sha256=str(binding["schema_manifest_sha256"]),
            combined_v2_schema_sha256=str(binding["combined_v2_schema_sha256"]),
        )
    except (KeyError, TypeError, ValueError, contracts.CodexTransportContractError) as exc:
        raise AppServerError("packaged Codex App Server runtime pin is invalid") from exc
