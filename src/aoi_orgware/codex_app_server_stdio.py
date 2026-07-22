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
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final, NoReturn

from . import codex_transport_contracts as contracts
from .confidentiality import is_publish_credential_environment_name


DEFAULT_MAX_LINE_BYTES: Final = 1_048_576
DEFAULT_MAX_EVENTS: Final = 10_000
DEFAULT_MAX_STDERR_BYTES: Final = 1_048_576
DEFAULT_MAX_QUEUE_MESSAGES: Final = 1_024

_REQUEST_METHODS: Final = frozenset(
    {"initialize", "model/list", "thread/start", "turn/start", "turn/interrupt"}
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
_MODEL_REROUTE_REQUIRED_FIELDS: Final = frozenset(
    {"fromModel", "reason", "threadId", "toModel", "turnId"}
)
_MODEL_REROUTE_REASONS: Final = frozenset({"highRiskCyberActivity"})
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
_INITIALIZE_RESPONSE_REQUIRED: Final = frozenset(
    {"codexHome", "platformFamily", "platformOs", "userAgent"}
)
_THREAD_START_RESPONSE_REQUIRED: Final = frozenset(
    {
        "approvalPolicy",
        "approvalsReviewer",
        "cwd",
        "model",
        "modelProvider",
        "sandbox",
        "thread",
    }
)
_THREAD_REQUIRED: Final = frozenset(
    {
        "cliVersion",
        "createdAt",
        "cwd",
        "ephemeral",
        "id",
        "modelProvider",
        "preview",
        "sessionId",
        "source",
        "status",
        "turns",
        "updatedAt",
    }
)
_TURN_REQUIRED: Final = frozenset({"id", "items", "status"})
_MODEL_LIST_RESPONSE_REQUIRED: Final = frozenset({"data"})
_MODEL_REQUIRED: Final = frozenset(
    {
        "defaultReasoningEffort",
        "description",
        "displayName",
        "hidden",
        "id",
        "isDefault",
        "model",
        "supportedReasoningEfforts",
    }
)
_REASONING_EFFORT_OPTION_REQUIRED: Final = frozenset(
    {"description", "reasoningEffort"}
)
_THREAD_ITEM_REQUIRED_FIELDS: Final = {
    "userMessage": frozenset({"content", "id", "type"}),
    "hookPrompt": frozenset({"fragments", "id", "type"}),
    "agentMessage": frozenset({"id", "text", "type"}),
    "plan": frozenset({"id", "text", "type"}),
    "reasoning": frozenset({"id", "type"}),
    "commandExecution": frozenset(
        {"command", "commandActions", "cwd", "id", "status", "type"}
    ),
    "fileChange": frozenset({"changes", "id", "status", "type"}),
    "mcpToolCall": frozenset(
        {"arguments", "id", "server", "status", "tool", "type"}
    ),
    "dynamicToolCall": frozenset(
        {"arguments", "id", "status", "tool", "type"}
    ),
    "collabAgentToolCall": frozenset(
        {
            "agentsStates",
            "id",
            "receiverThreadIds",
            "senderThreadId",
            "status",
            "tool",
            "type",
        }
    ),
    "subAgentActivity": frozenset(
        {"agentPath", "agentThreadId", "id", "kind", "type"}
    ),
    "webSearch": frozenset({"id", "query", "type"}),
    "imageView": frozenset({"id", "path", "type"}),
    "sleep": frozenset({"durationMs", "id", "type"}),
    "imageGeneration": frozenset({"id", "result", "status", "type"}),
    "enteredReviewMode": frozenset({"id", "review", "type"}),
    "exitedReviewMode": frozenset({"id", "review", "type"}),
    "contextCompaction": frozenset({"id", "type"}),
}
_AOI_SECRET_ENV_PREFIXES: Final = ("AOI_CHIEF_", "AOI_ROOT_", "AOI_CREDENTIAL_")
_AOI_SECRET_ENV_NAMES: Final = frozenset(
    {"AOI_CHIEF_SESSION_ID", "AOI_CHIEF_EPOCH", "AOI_CHIEF_CREDENTIAL_FILE"}
)
_LOCAL_FILES_HOME_NAMES: Final = frozenset(
    {"auth.json", "config.toml", "managed_config.toml"}
)
_LOCAL_FILES_CONFIG: Final = {
    "web_search": "disabled",
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
    "apps": {"_default": {"enabled": False}},
}
_LOCAL_FILES_MANAGED_CONFIG: Final = {
    "allow_remote_control": False,
    # An empty requirements allowlist permits only the implicit disabled mode.
    # A plain ``web_search = \"disabled\"`` here would be a default-like
    # setting, not the same managed constraint.
    "allowed_web_search_modes": [],
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
}
_LOCAL_FILES_THREAD_CONFIG: Final = {
    "web_search": "disabled",
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
    "apps": {"_default": {"enabled": False}},
}
_PRODUCTION_LAUNCH_ARGS: Final = (
    "--strict-config",
    "--config",
    'web_search="disabled"',
    "--config",
    "features.apps=false",
    "--config",
    "features.remote_plugin=false",
    "--config",
    "features.multi_agent=false",
    "--config",
    "apps._default.enabled=false",
    "--listen",
    "stdio://",
)


class AppServerError(RuntimeError):
    """Base class for failures that callers must record as runtime evidence."""


class AppServerResponseError(AppServerError):
    """The peer returned one correlated, schema-valid error response.

    Production controllers retain the exact bounded envelope in task-local CAS
    before this typed fault is raised.  The error payload is deliberately not
    copied into the exception message or semantic journal.
    """

    def __init__(
        self,
        message: str,
        *,
        method: str,
        evidence_sha256: str,
        evidence_size_bytes: int,
    ) -> None:
        super().__init__(message)
        self.method = method
        self.evidence_sha256 = evidence_sha256
        self.evidence_size_bytes = evidence_size_bytes
        self.reason_code = "app_server_error"


class ProtocolViolation(AppServerError):
    """The peer sent data outside the explicitly supported protocol subset."""


class ModelReroutedViolation(ProtocolViolation):
    """The runtime attempted to leave the exact model sealed by AOI."""

    def __init__(self, *, evidence_sha256: str, evidence_size_bytes: int) -> None:
        super().__init__("App Server model reroute violates sealed AOI policy")
        self.method = "model/rerouted"
        self.evidence_sha256 = evidence_sha256
        self.evidence_size_bytes = evidence_size_bytes
        self.reason_code = "model_rerouted"


class RuntimeDisconnected(AppServerError):
    """The App Server stream ended before a required response or terminal event."""


class ServerRequestDenied(ProtocolViolation):
    """The server requested approval, user input, or any other client action."""


class ResponsePolicyDrift(ProtocolViolation):
    """A schema-valid response conflicts with sealed AOI runtime policy."""


class ModelCatalogDrift(ResponsePolicyDrift):
    """The live model catalog cannot honor the exact sealed model/effort."""


class ResponseSchemaViolation(ProtocolViolation):
    """A correlated success response did not satisfy the pinned method schema.

    The rejected response is not a successful response observation.  Its exact
    bounded wire bytes are offered synchronously to a controller-owned local
    CAS sink before this exception is raised; only the verified digest and size
    enter the transport journal.
    """

    def __init__(
        self,
        message: str,
        *,
        method: str,
        evidence_sha256: str,
        evidence_size_bytes: int,
        reason_code: str = "pinned_response_schema",
    ) -> None:
        super().__init__(message)
        self.method = method
        self.evidence_sha256 = evidence_sha256
        self.evidence_size_bytes = evidence_size_bytes
        self.reason_code = reason_code


class ResponsePolicyViolation(ResponseSchemaViolation):
    """A correlated response violated sealed AOI intent or policy."""


class ModelCatalogViolation(ResponsePolicyViolation):
    """The live App Server catalog lacks the exact requested model/effort."""


class RequestPhase(str, Enum):
    """Durable crash markers for one non-idempotent App Server request."""

    BEFORE_SEND = "before_send"
    SEND_PENDING = "send_pending"
    RESPONSE_RECEIVED = "response_received"


class _TerminalStreamPhase(str, Enum):
    """One-way ownership state for the MVP stdout terminal cut."""

    OPEN = "open"
    DRAINING = "draining"
    SEALED = "sealed"
    ABORTED = "aborted"


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
    wire_bytes: bytes


@dataclass(frozen=True)
class RejectedNotificationWire:
    """Raw-only carrier offered to durable evidence before payload parsing."""

    method: str
    sha256: str
    wire_bytes: bytes
    evidence_sha256: str | None = None
    evidence_size_bytes: int | None = None


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
        raise ProtocolViolation("malformed App Server protocol line") from exc
    if not isinstance(value, dict):
        raise ProtocolViolation("App Server protocol message must be an object")
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
        on_rejected_response: Callable[
            [RequestJournalEntry], Mapping[str, Any]
        ]
        | None = None,
        on_rejected_notification: Callable[
            [RuntimeEvent | RejectedNotificationWire], Mapping[str, Any]
        ]
        | None = None,
        require_local_files_policy: bool = False,
        _test_launch_args: tuple[str, ...] | None = None,
        _test_version_args: tuple[str, ...] | None = None,
    ) -> None:
        executable_path = Path(executable)
        if not executable_path.is_absolute():
            raise ValueError("Codex App Server executable must be an absolute path")
        if max_line_bytes < 128 or max_events < 1 or max_stderr_bytes < 1 or max_queue_messages < 1:
            raise ValueError("stdio bounds must be positive and line bound at least 128")
        if not isinstance(require_local_files_policy, bool):
            raise ValueError("require_local_files_policy must be a boolean")
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
        self.on_rejected_response = on_rejected_response
        self.on_rejected_notification = on_rejected_notification
        self.require_local_files_policy = require_local_files_policy
        # This narrow injection point lets tests run a scripted Python peer.
        # Production callers must use the standalone App Server default below.
        self._launch_args = _test_launch_args or _PRODUCTION_LAUNCH_ARGS
        self._version_args = _test_version_args or ("--version",)
        self._local_files_policy_binding: dict[str, Any] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._incoming: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=max_queue_messages)
        self._notifications: list[RuntimeEvent] = []
        self._seen_events: dict[tuple[str, str], str] = {}
        self._request_lock = threading.Lock()
        self._next_request_id = 1
        self.last_receipt: RequestReceipt | None = None
        self._initialized = False
        self._model_intent: SealedLaunchIntent | None = None
        self._model_catalog_response: dict[str, Any] | None = None
        self._thread_id: str | None = None
        self._turn_id: str | None = None
        self._turn_terminal = False
        self._intent: SealedLaunchIntent | None = None
        self._reader_error: AppServerError | None = None
        self._reader_condition = threading.Condition()
        self._reroute_persistence_inflight = 0
        self._terminal_stream_phase = _TerminalStreamPhase.OPEN
        self._stdout_reader_done = False
        self._stderr_reader_done = False
        self._forced_shutdown = False
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
            "local_files_policy": self._local_files_policy_binding,
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
        if self.require_local_files_policy:
            self._local_files_policy_binding = _validate_local_files_codex_home(
                self.environment
            )
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
        if self.require_local_files_policy:
            refreshed_policy = _validate_local_files_codex_home(self.environment)
            if refreshed_policy != self._local_files_policy_binding:
                raise AppServerError(
                    "local_files CODEX_HOME policy changed after process authorization"
                )
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
        with self._reader_condition:
            self._stdout_reader_done = False
            self._stderr_reader_done = False
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
        """Best-effort bounded cleanup; never confers a clean terminal seal."""

        process = self._process
        cleanup_failed = False
        if process is not None:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except Exception:
                    cleanup_failed = True
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._force_terminal_cleanup(process)
            except Exception:
                self._force_terminal_cleanup(process)
            else:
                if self._process is process:
                    self._process = None
        if cleanup_failed:
            self._abort_terminal_stream()
            self._retain_reader_error(
                RuntimeDisconnected(
                    "App Server process cleanup encountered an owned stream fault"
                )
            )
        self._join_readers_for_cleanup(timeout_seconds=2)

    def seal_reader_for_terminal_commit(self, *, timeout_seconds: float) -> None:
        """Create the permanent stdout cut required before terminal journaling.

        ``turn/completed`` is only a candidate until the one-shot App Server
        accepts stdin EOF, exits naturally with status zero, and its stdout and
        stderr readers drain and join without error.  No forced cleanup or
        instantaneous barrier check can authorize ``completed``.
        """

        if timeout_seconds <= 0:
            raise ValueError("terminal stream seal timeout must be positive")
        if not self._turn_terminal:
            raise AppServerError(
                "terminal stream seal requires an observed terminal turn"
            )
        deadline = time.monotonic() + timeout_seconds
        with self._reader_condition:
            if self._terminal_stream_phase is _TerminalStreamPhase.SEALED:
                return
            if self._terminal_stream_phase is not _TerminalStreamPhase.OPEN:
                raise RuntimeDisconnected(
                    "App Server terminal stream is not eligible for a clean seal"
                )
            self._terminal_stream_phase = _TerminalStreamPhase.DRAINING
            self._reader_condition.notify_all()

        try:
            process = self._require_process()
        except AppServerError:
            self._abort_terminal_stream()
            raise
        if process.stdin is None:
            self._force_terminal_cleanup(process)
            self._raise_terminal_stream_failure(
                "App Server stdin is unavailable for terminal stream seal",
                deadline=deadline,
            )
        try:
            process.stdin.close()
        except Exception as exc:
            self._force_terminal_cleanup(process)
            self._raise_terminal_stream_failure(
                "could not close App Server stdin for terminal stream seal",
                cause=exc,
                deadline=deadline,
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self._force_terminal_cleanup(process)
            self._raise_terminal_stream_failure(
                "timed out before App Server terminal stream shutdown",
                deadline=deadline,
            )
        try:
            exit_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            self._force_terminal_cleanup(process)
            self._raise_terminal_stream_failure(
                "App Server did not exit naturally for terminal stream seal",
                cause=exc,
                deadline=deadline,
            )
        except Exception as exc:
            self._force_terminal_cleanup(process)
            self._raise_terminal_stream_failure(
                "could not wait for App Server terminal stream shutdown",
                cause=exc,
                deadline=deadline,
            )

        self._process = None
        if exit_code != 0:
            self._abort_terminal_stream()
            self._join_readers_until(deadline)
            self._raise_terminal_stream_failure(
                "App Server exited nonzero before terminal stream seal",
                deadline=deadline,
            )

        if not self._join_readers_until(deadline):
            self._abort_terminal_stream()
            self._raise_terminal_stream_failure(
                "App Server readers did not quiesce before terminal stream seal",
                deadline=deadline,
            )

        try:
            self._wait_rejected_notification_barrier(deadline)
        except AppServerError:
            self._abort_terminal_stream()
            raise
        with self._reader_condition:
            if (
                not self._stdout_reader_done
                or not self._stderr_reader_done
                or self._reroute_persistence_inflight != 0
                or self._reader_error is not None
            ):
                self._terminal_stream_phase = _TerminalStreamPhase.ABORTED
                self._reader_condition.notify_all()
                raise RuntimeDisconnected(
                    "App Server terminal stream did not reach a clean reader boundary"
                )
            self._terminal_stream_phase = _TerminalStreamPhase.SEALED
            self._reader_condition.notify_all()

    def _join_readers_until(self, deadline: float) -> bool:
        for reader in (self._stdout_thread, self._stderr_thread):
            if reader is None:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                reader.join(timeout=remaining)
            except Exception:
                return False
            try:
                alive = reader.is_alive()
            except Exception:
                return False
            if alive:
                return False
        return True

    def _join_readers_for_cleanup(self, *, timeout_seconds: float) -> bool:
        """Best-effort symmetric reader cleanup without leaking raw faults."""

        cleanup_failed = False
        for reader in (self._stdout_thread, self._stderr_thread):
            if reader is None:
                continue
            try:
                reader.join(timeout=timeout_seconds)
            except Exception:
                cleanup_failed = True
            try:
                alive = reader.is_alive()
            except Exception:
                cleanup_failed = True
                alive = True
            if alive:
                cleanup_failed = True
        if cleanup_failed:
            self._abort_terminal_stream()
            self._retain_reader_error(
                RuntimeDisconnected(
                    "App Server readers did not stop during bounded cleanup"
                )
            )
        return not cleanup_failed

    def _abort_terminal_stream(self, *, forced: bool = False) -> None:
        with self._reader_condition:
            if self._terminal_stream_phase is not _TerminalStreamPhase.SEALED:
                self._terminal_stream_phase = _TerminalStreamPhase.ABORTED
            if forced:
                self._forced_shutdown = True
            self._reader_condition.notify_all()

    def _raise_terminal_stream_failure(
        self,
        message: str,
        *,
        cause: BaseException | None = None,
        deadline: float | None = None,
    ) -> NoReturn:
        """Raise the retained reader fault before any later stream fault."""

        self._abort_terminal_stream()
        if deadline is not None:
            try:
                self._wait_rejected_notification_barrier(deadline)
            except AppServerError:
                pass
        with self._reader_condition:
            retained = self._reader_error
        failure: AppServerError = retained or RuntimeDisconnected(message)
        if cause is None:
            raise failure
        raise failure from cause

    def _force_terminal_cleanup(
        self, process: subprocess.Popen[bytes]
    ) -> None:
        self._abort_terminal_stream(forced=True)
        cleanup_failed = False

        # Treat each child-process operation as an independent cleanup step.
        # A broken status query must not skip terminate/kill, and an exit that
        # cannot be confirmed must not erase the only process handle.
        exit_confirmed = False
        try:
            exit_confirmed = process.poll() is not None
        except Exception:
            cleanup_failed = True

        if not exit_confirmed:
            try:
                process.terminate()
            except Exception:
                cleanup_failed = True
            try:
                process.wait(timeout=2)
            except Exception:
                cleanup_failed = True
            else:
                exit_confirmed = True

        if not exit_confirmed:
            try:
                process.kill()
            except Exception:
                cleanup_failed = True
            try:
                process.wait(timeout=2)
            except Exception:
                cleanup_failed = True
            else:
                exit_confirmed = True

        if exit_confirmed:
            if self._process is process:
                self._process = None
        else:
            cleanup_failed = True
            if self._process is None or self._process is process:
                self._process = process

        if not self._join_readers_for_cleanup(timeout_seconds=2):
            cleanup_failed = True
        if cleanup_failed:
            self._retain_reader_error(
                RuntimeDisconnected(
                    "App Server forced terminal cleanup did not fully quiesce"
                )
            )

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
            validate_result=lambda result: _validate_initialize_response(
                result,
                expected_codex_home=(
                    str(self._local_files_policy_binding["codex_home"])
                    if self._local_files_policy_binding is not None
                    else None
                ),
            ),
        )
        self._send_notification("initialized")
        self._initialized = True
        return response

    def verify_model_from_intent(self, *, intent: SealedLaunchIntent) -> dict[str, Any]:
        """Bind the sealed model/effort to the live visible App Server catalog."""

        self._require_initialized()
        if self._thread_id is not None:
            raise AppServerError("model/list preflight must precede thread/start")
        if self._model_intent is not None:
            if self._model_intent != intent or self._model_catalog_response is None:
                raise ProtocolViolation(
                    "model/list preflight intent differs from the established catalog binding"
                )
            return self._model_catalog_response
        self._validate_intent_context(intent)
        response = self.request(
            "model/list",
            {"includeHidden": True, "limit": 100},
            validate_result=lambda result: _validate_model_list_response(
                result, intent=intent
            ),
        )
        self._model_intent = intent
        self._model_catalog_response = response
        return response

    def start_thread_from_intent(
        self,
        *,
        intent: SealedLaunchIntent,
    ) -> str:
        self._require_initialized()
        if self._thread_id is not None:
            raise AppServerError("MVP permits exactly one thread/start")
        self.verify_model_from_intent(intent=intent)
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
            "config": _copy_local_files_thread_config(),
        }
        response = self.request(
            "thread/start",
            params,
            validate_result=lambda result: _validate_thread_start_response(
                result, intent=intent
            ),
        )
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
        response = self.request(
            "turn/start",
            params,
            validate_result=_validate_turn_start_response,
        )
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
            validate_result=_validate_turn_interrupt_response,
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
                self._wait_rejected_notification_barrier(deadline)
                self._turn_terminal = True
                return TurnObservation(thread_id, turn_id, status, tuple(observed))

    def synchronize_reader_boundary(self, *, timeout_seconds: float) -> None:
        """Wait for callbacks already recognized at the instant of this call.

        This is a diagnostic/consumer barrier only.  It is not a permanent
        terminal cut and must never authorize a terminal journal entry; use
        :meth:`seal_reader_for_terminal_commit` for that boundary.
        """

        if timeout_seconds <= 0:
            raise ValueError("reader boundary timeout must be positive")
        self._wait_rejected_notification_barrier(
            time.monotonic() + timeout_seconds
        )

    def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout_seconds: float = 30.0,
        validate_result: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if method not in _REQUEST_METHODS:
            raise ValueError(f"unsupported client request method: {method}")
        process = self._require_process()
        if process.stdin is None:
            raise RuntimeDisconnected("App Server stdin is unavailable")
        with self._request_lock:
            request_id = self._next_request_id
            self._next_request_id += 1
            # The pinned 0.144.6 generated ClientRequest schema and live
            # runtime use the App Server's line-delimited RPC envelope.  It
            # deliberately has no JSON-RPC ``jsonrpc`` member.
            message = {"id": request_id, "method": method, "params": dict(params)}
            encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(encoded) > self.max_line_bytes:
                raise ValueError("outgoing App Server request exceeds line limit")
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
            response = self._wait_response(
                request_id,
                method=method,
                deadline=time.monotonic() + timeout_seconds,
                validate_result=validate_result,
            )
            self.last_receipt = RequestReceipt(request_id, method, RequestPhase.RESPONSE_RECEIVED, response)
            return response

    def _send_notification(self, method: str) -> None:
        if method != "initialized":
            raise ValueError(f"unsupported client notification method: {method}")
        process = self._require_process()
        if process.stdin is None:
            raise RuntimeDisconnected("App Server stdin is unavailable")
        # ClientNotification.json for the pinned runtime defines initialized
        # as the exact method-only notification shape.
        payload = json.dumps({"method": method}, separators=(",", ":")).encode(
            "utf-8"
        ) + b"\n"
        if len(payload) > self.max_line_bytes:
            raise ValueError("outgoing App Server notification exceeds line limit")
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except OSError as exc:
            raise RuntimeDisconnected(f"App Server write failed during {method}") from exc

    def _wait_response(
        self,
        request_id: int,
        *,
        method: str,
        deadline: float,
        validate_result: Callable[[dict[str, Any]], dict[str, Any]] | None,
    ) -> dict[str, Any]:
        while True:
            kind, payload = self._next_incoming(deadline)
            if kind == "rejected_notification":
                self._reject_model_rerouted_wire(payload)
            if kind == "notification":
                message, raw = payload
                self._record_notification(message, raw, buffer=True)
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
                    method,
                    RequestPhase.RESPONSE_RECEIVED,
                    raw,
                    hashlib.sha256(raw).hexdigest(),
                )
                if "error" in message:
                    self._persist_rejected_response(entry)
                    raise AppServerResponseError(
                        f"App Server returned a correlated error response during {method}",
                        method=method,
                        evidence_sha256=entry.sha256,
                        evidence_size_bytes=len(raw),
                    )
                result = _require_object(
                    message.get("result"), "App Server response result"
                )
                if validate_result is not None:
                    try:
                        result = validate_result(result)
                    except ModelCatalogDrift as exc:
                        self._persist_rejected_response(entry)
                        raise ModelCatalogViolation(
                            f"pinned {method} response conflicts with the sealed model catalog requirement",
                            method=method,
                            evidence_sha256=entry.sha256,
                            evidence_size_bytes=len(raw),
                            reason_code="model_catalog_policy",
                        ) from exc
                    except ResponsePolicyDrift as exc:
                        self._persist_rejected_response(entry)
                        raise ResponsePolicyViolation(
                            f"pinned {method} response conflicts with sealed AOI policy",
                            method=method,
                            evidence_sha256=entry.sha256,
                            evidence_size_bytes=len(raw),
                            reason_code="sealed_response_policy",
                        ) from exc
                    except ProtocolViolation as exc:
                        self._persist_rejected_response(entry)
                        raise ResponseSchemaViolation(
                            f"pinned {method} response schema validation failed",
                            method=method,
                            evidence_sha256=entry.sha256,
                            evidence_size_bytes=len(raw),
                        ) from exc
                if self.on_response is not None:
                    try:
                        self.on_response(entry)
                    except Exception as exc:
                        raise AppServerError("response journal callback failed") from exc
                return result
            raise ProtocolViolation(f"internal reader emitted unknown kind: {kind}")

    def _persist_rejected_response(self, entry: RequestJournalEntry) -> None:
        """Synchronously bind exact rejected bytes to a controller-owned CAS."""

        if self.on_rejected_response is None:
            return
        try:
            reference = dict(self.on_rejected_response(entry))
        except Exception as exc:
            raise AppServerError(
                "rejected response evidence callback failed"
            ) from exc
        if (
            reference.get("sha256") != entry.sha256
            or reference.get("size_bytes") != len(entry.wire_bytes)
        ):
            raise AppServerError(
                "rejected response evidence callback returned divergent bytes"
            )

    def _persist_rejected_notification(
        self, event: RuntimeEvent | RejectedNotificationWire
    ) -> Mapping[str, Any]:
        """Synchronously bind exact rejected notification bytes to local CAS."""

        if self.on_rejected_notification is None:
            raise AppServerError(
                "rejected notification evidence callback is required"
            )
        actual_sha256 = hashlib.sha256(event.wire_bytes).hexdigest()
        try:
            reference = dict(self.on_rejected_notification(event))
        except Exception as exc:
            raise AppServerError(
                "rejected notification evidence callback failed"
            ) from exc
        if (
            reference.get("sha256") != actual_sha256
            or reference.get("size_bytes") != len(event.wire_bytes)
        ):
            raise AppServerError(
                "rejected notification evidence callback returned divergent bytes"
            )
        return reference

    def _reject_model_rerouted_wire(
        self, entry: RejectedNotificationWire
    ) -> NoReturn:
        """Raise the typed fault for a reader-persisted raw reroute line."""

        actual_sha256 = hashlib.sha256(entry.wire_bytes).hexdigest()
        if (
            entry.evidence_sha256 != actual_sha256
            or entry.evidence_size_bytes != len(entry.wire_bytes)
        ):
            raise AppServerError(
                "rejected notification lacks verified reader-boundary evidence"
            )
        try:
            message = _strict_json_object(entry.wire_bytes)
            if message.get("method") != "model/rerouted" or "id" in message:
                raise ProtocolViolation(
                    "rejected model/rerouted wire envelope is inconsistent"
                )
            params = _require_object(
                message.get("params"), "model/rerouted params"
            )
            _require_fields(
                params, _MODEL_REROUTE_REQUIRED_FIELDS, "model/rerouted params"
            )
            observed_thread = _require_string(
                params.get("threadId"), "model/rerouted threadId"
            )
            observed_turn = _require_string(
                params.get("turnId"), "model/rerouted turnId"
            )
            observed_from = _require_string(
                params.get("fromModel"), "model/rerouted fromModel"
            )
            _require_string(params.get("toModel"), "model/rerouted toModel")
            reason = _require_string(params.get("reason"), "model/rerouted reason")
            if reason not in _MODEL_REROUTE_REASONS:
                raise ProtocolViolation("model/rerouted reason is outside pinned schema")
            if self._thread_id is not None and observed_thread != self._thread_id:
                raise ProtocolViolation("model/rerouted thread correlation mismatch")
            if self._turn_id is not None and observed_turn != self._turn_id:
                raise ProtocolViolation("model/rerouted turn correlation mismatch")
            if self._model_intent is None:
                raise ProtocolViolation(
                    "model/rerouted arrived without a sealed model binding"
                )
            if observed_from != self._model_intent.model:
                raise ProtocolViolation(
                    "model/rerouted fromModel differs from sealed launch intent"
                )
        except ProtocolViolation:
            # Persistence already succeeded.  Classification details are
            # deliberately not exposed through the fixed typed fault.
            pass
        raise ModelReroutedViolation(
            evidence_sha256=actual_sha256,
            evidence_size_bytes=len(entry.wire_bytes),
        )

    def _next_notification(self, deadline: float) -> RuntimeEvent:
        if self._notifications:
            return self._notifications.pop(0)
        while True:
            kind, payload = self._next_incoming(deadline)
            if kind == "rejected_notification":
                self._reject_model_rerouted_wire(payload)
            if kind == "notification":
                message, raw = payload
                event = self._record_notification(message, raw, buffer=False)
                if event is not None:
                    return event
                continue
            if kind == "server_request":
                raise ServerRequestDenied(_server_request_message(payload))
            if kind == "response":
                raise ProtocolViolation("unexpected response without an outstanding request")
            raise ProtocolViolation(f"internal reader emitted unknown kind: {kind}")

    def _next_incoming(self, deadline: float) -> tuple[str, Any]:
        self._wait_rejected_notification_barrier(deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeDisconnected("timed out waiting for App Server protocol data")
        try:
            kind, payload = self._incoming.get(timeout=remaining)
        except queue.Empty as exc:
            raise RuntimeDisconnected("timed out waiting for App Server protocol data") from exc
        self._wait_rejected_notification_barrier(deadline)
        if kind == "eof":
            raise RuntimeDisconnected("App Server stdout reached EOF")
        if kind == "error":
            if isinstance(payload, AppServerError):
                raise payload
            raise ProtocolViolation("App Server reader failed") from payload
        return kind, payload

    def _stdout_reader(self) -> None:
        try:
            process = self._require_process()
            assert process.stdout is not None
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
            retained = self._retain_reader_error(error)
            self._enqueue(("error", retained))
        finally:
            with self._reader_condition:
                self._stdout_reader_done = True
                self._reader_condition.notify_all()

    def _stderr_reader(self) -> None:
        chunks: list[bytes] = []
        captured = 0
        try:
            process = self._require_process()
            assert process.stderr is not None
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
        except BaseException as exc:
            error = (
                exc
                if isinstance(exc, AppServerError)
                else RuntimeDisconnected("App Server stderr reader failed")
            )
            self._retain_reader_error(error)
        finally:
            self._stderr = b"".join(chunks)
            with self._reader_condition:
                self._stderr_reader_done = True
                self._reader_condition.notify_all()

    def _enqueue(self, item: tuple[str, Any]) -> None:
        try:
            self._incoming.put_nowait(item)
        except queue.Full:
            self._retain_reader_error(
                ProtocolViolation(
                    "App Server reader queue/backpressure limit exceeded"
                )
            )

    def _retain_reader_error(self, error: AppServerError) -> AppServerError:
        """Keep the first fault, except that an exact reroute outranks generic faults."""

        with self._reader_condition:
            current = self._reader_error
            if current is None or (
                isinstance(error, ModelReroutedViolation)
                and not isinstance(current, ModelReroutedViolation)
            ):
                self._reader_error = error
            retained = self._reader_error
            assert retained is not None
            self._reader_condition.notify_all()
            return retained

    def _begin_rejected_notification_persistence(self) -> None:
        with self._reader_condition:
            if (
                self._terminal_stream_phase is _TerminalStreamPhase.SEALED
                or self._stdout_reader_done
            ):
                raise AssertionError(
                    "reroute persistence cannot begin after terminal stream seal"
                )
            self._reroute_persistence_inflight += 1
            self._reader_condition.notify_all()

    def _finish_rejected_notification_persistence(self) -> None:
        with self._reader_condition:
            if self._reroute_persistence_inflight < 1:
                raise AssertionError("reroute persistence barrier underflow")
            self._reroute_persistence_inflight -= 1
            self._reader_condition.notify_all()

    def _wait_rejected_notification_barrier(self, deadline: float) -> None:
        with self._reader_condition:
            while self._reroute_persistence_inflight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timeout = RuntimeDisconnected(
                        "timed out waiting for rejected notification evidence"
                    )
                    if self._reader_error is None:
                        self._reader_error = timeout
                    raise self._reader_error
                self._reader_condition.wait(timeout=remaining)
            if self._reader_error is not None:
                raise self._reader_error

    def _classify_incoming(self, message: dict[str, Any], raw: bytes) -> tuple[str, Any]:
        if "jsonrpc" in message:
            raise ProtocolViolation(
                "pinned App Server 0.144.6 framing must not contain jsonrpc"
        )
        if "method" in message:
            method = _require_string(message["method"], "incoming method")
            if "id" not in message and method == "model/rerouted":
                self._begin_rejected_notification_persistence()
                try:
                    raw_entry = RejectedNotificationWire(
                        method,
                        hashlib.sha256(raw).hexdigest(),
                        raw,
                    )
                    reference = self._persist_rejected_notification(raw_entry)
                    evidence_sha256 = str(reference["sha256"])
                    evidence_size_bytes = int(reference["size_bytes"])
                    persisted_entry = RejectedNotificationWire(
                        method,
                        raw_entry.sha256,
                        raw,
                        evidence_sha256=evidence_sha256,
                        evidence_size_bytes=evidence_size_bytes,
                    )
                    self._retain_reader_error(
                        ModelReroutedViolation(
                            evidence_sha256=evidence_sha256,
                            evidence_size_bytes=evidence_size_bytes,
                        )
                    )
                    return (
                        "rejected_notification",
                        persisted_entry,
                    )
                except AppServerError as exc:
                    self._retain_reader_error(exc)
                    raise
                except BaseException as exc:
                    boundary_error = ProtocolViolation(
                        "rejected notification persistence boundary failed"
                    )
                    self._retain_reader_error(boundary_error)
                    raise boundary_error from exc
                finally:
                    self._finish_rejected_notification_persistence()
            params = message.get("params", {})
            _require_object(params, "incoming notification/request params")
            if "id" in message:
                return ("server_request", message)
            if method not in _NOTIFICATION_METHODS:
                raise ProtocolViolation(f"unsupported App Server notification method: {method}")
            return ("notification", (message, raw))
        if "id" not in message:
            raise ProtocolViolation(
                "App Server message is neither request, notification, nor response"
            )
        if not isinstance(message["id"], int) or isinstance(message["id"], bool):
            raise ProtocolViolation("response id must be an integer")
        if "result" not in message and "error" not in message:
            raise ProtocolViolation("App Server response has neither result nor error")
        if "result" in message and "error" in message:
            raise ProtocolViolation("App Server response contains both result and error")
        if "error" in message:
            error = _require_object(message["error"], "App Server response error")
            code = error.get("code")
            if not isinstance(code, int) or isinstance(code, bool):
                raise ProtocolViolation("App Server response error.code must be an integer")
            if not isinstance(error.get("message"), str):
                raise ProtocolViolation("App Server response error.message must be text")
        return ("response", (message, raw))

    def _record_notification(
        self,
        message: dict[str, Any],
        raw: bytes,
        *,
        buffer: bool,
    ) -> RuntimeEvent | None:
        method = _require_string(message.get("method"), "notification method")
        params = _require_object(message.get("params"), "notification params")
        event = RuntimeEvent(method, params, hashlib.sha256(raw).hexdigest(), raw)
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

    def _validate_event(
        self,
        event: RuntimeEvent,
        *,
        thread_id: str,
        turn_id: str | None,
        allow_future_turn: bool = False,
    ) -> None:
        params = event.params
        if event.method == "model/rerouted":
            self._reject_model_rerouted(
                event,
                thread_id=thread_id,
                turn_id=turn_id,
                allow_future_turn=allow_future_turn,
            )
        if event.method in _AUXILIARY_NOTIFICATION_METHODS:
            _validate_auxiliary_correlation(
                event,
                thread_id=thread_id,
                turn_id=turn_id,
                allow_future_turn=allow_future_turn,
            )
            return
        if event.method == "thread/started":
            thread = _validate_thread_object(
                params.get("thread"), "thread/started thread"
            )
            if _require_string(thread.get("id"), "thread/started thread.id") != thread_id:
                raise ProtocolViolation("thread/started correlation mismatch")
            return
        observed_thread = _require_string(params.get("threadId"), f"{event.method} threadId")
        if observed_thread != thread_id:
            raise ProtocolViolation(f"{event.method} thread correlation mismatch")
        if event.method == "turn/started":
            turn = _validate_turn_object(
                params.get("turn"),
                "turn/started turn",
                allowed_statuses=frozenset({"inProgress"}),
            )
            observed_turn = _require_string(turn.get("id"), "turn/started turn.id")
        elif event.method == "turn/completed":
            turn = _validate_turn_object(
                params.get("turn"),
                "turn/completed turn",
                allowed_statuses=frozenset(
                    {"completed", "failed", "interrupted"}
                ),
            )
            observed_turn = _require_string(turn.get("id"), "turn/completed turn.id")
        else:
            observed_turn = _require_string(params.get("turnId"), f"{event.method} turnId")
            _validate_thread_item(params.get("item"), f"{event.method} item")
            timestamp_field = (
                "startedAtMs" if event.method == "item/started" else "completedAtMs"
            )
            _require_integer(
                params.get(timestamp_field), f"{event.method} {timestamp_field}"
            )
        if turn_id is not None and observed_turn != turn_id:
            raise ProtocolViolation(f"{event.method} turn correlation mismatch")
        if turn_id is None and not allow_future_turn:
            raise ProtocolViolation(f"{event.method} arrived before a turn was established")

    def _reject_model_rerouted(
        self,
        event: RuntimeEvent,
        *,
        thread_id: str,
        turn_id: str | None,
        allow_future_turn: bool,
    ) -> NoReturn:
        """Persist first, then classify, and reject every model reroute."""

        reference = self._persist_rejected_notification(event)
        try:
            params = event.params
            _require_fields(
                params, _MODEL_REROUTE_REQUIRED_FIELDS, "model/rerouted params"
            )
            observed_thread = _require_string(
                params.get("threadId"), "model/rerouted threadId"
            )
            observed_turn = _require_string(
                params.get("turnId"), "model/rerouted turnId"
            )
            observed_from = _require_string(
                params.get("fromModel"), "model/rerouted fromModel"
            )
            _require_string(params.get("toModel"), "model/rerouted toModel")
            reason = _require_string(params.get("reason"), "model/rerouted reason")
            if reason not in _MODEL_REROUTE_REASONS:
                raise ProtocolViolation("model/rerouted reason is outside pinned schema")
            if observed_thread != thread_id:
                raise ProtocolViolation("model/rerouted thread correlation mismatch")
            if turn_id is not None and observed_turn != turn_id:
                raise ProtocolViolation("model/rerouted turn correlation mismatch")
            if turn_id is None and not allow_future_turn:
                raise ProtocolViolation(
                    "model/rerouted arrived before a turn was established"
                )
            if self._model_intent is None:
                raise ProtocolViolation(
                    "model/rerouted arrived without a sealed model binding"
                )
            if observed_from != self._model_intent.model:
                raise ProtocolViolation(
                    "model/rerouted fromModel differs from sealed launch intent"
                )
        except ProtocolViolation:
            # The payload is untrusted classification input.  Every shape has
            # the same fixed, redacted terminal fault after exact persistence.
            pass
        raise ModelReroutedViolation(
            evidence_sha256=str(reference["sha256"]),
            evidence_size_bytes=int(reference["size_bytes"]),
        )

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
            "local_files_policy": self._local_files_policy_binding,
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


def _copy_local_files_thread_config() -> dict[str, Any]:
    return {
        "web_search": "disabled",
        "features": {
            "apps": False,
            "remote_plugin": False,
            "multi_agent": False,
        },
        "apps": {"_default": {"enabled": False}},
    }


def _environment_value(environment: Mapping[str, str], name: str) -> str:
    matches = [value for key, value in environment.items() if key.upper() == name]
    if len(matches) != 1 or not matches[0]:
        raise AppServerError(f"local_files requires exactly one non-empty {name}")
    return matches[0]


def _same_physical_path(path: Path, resolved: Path) -> bool:
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(resolved))


def _bounded_regular_bytes(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AppServerError(f"{label} must be a regular non-symlink file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"could not resolve {label}") from exc
    if not _same_physical_path(path, resolved):
        raise AppServerError(f"{label} resolves through a link or reparse boundary")
    size = path.stat().st_size
    if size < 1 or size > DEFAULT_MAX_LINE_BYTES:
        raise AppServerError(
            f"{label} must contain 1..{DEFAULT_MAX_LINE_BYTES} bytes"
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AppServerError(f"could not read {label}") from exc
    if len(data) != size:
        raise AppServerError(f"{label} changed while being bound")
    return data


def _strict_toml(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AppServerError(f"{label} is not strict UTF-8 TOML") from exc
    if not isinstance(value, dict):
        raise AppServerError(f"{label} must decode to a TOML table")
    return value


def _validate_local_files_codex_home(
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Fail closed unless CODEX_HOME is an exact isolated policy directory."""

    home = Path(_environment_value(environment, "CODEX_HOME"))
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        raise AppServerError(
            "local_files CODEX_HOME must be an absolute regular directory"
        )
    try:
        resolved_home = home.resolve(strict=True)
    except OSError as exc:
        raise AppServerError("could not resolve local_files CODEX_HOME") from exc
    if not _same_physical_path(home, resolved_home):
        raise AppServerError(
            "local_files CODEX_HOME resolves through a link or reparse boundary"
        )
    try:
        children = sorted(home.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise AppServerError("could not enumerate local_files CODEX_HOME") from exc
    names = {item.name for item in children}
    if names != _LOCAL_FILES_HOME_NAMES or len(children) != len(
        _LOCAL_FILES_HOME_NAMES
    ):
        raise AppServerError(
            "local_files CODEX_HOME initial inventory must contain only auth.json, config.toml, and managed_config.toml"
        )

    inventory: list[dict[str, Any]] = []
    policy_files: dict[str, dict[str, Any]] = {}
    policy_bytes: dict[str, bytes] = {}
    for child in children:
        data = _bounded_regular_bytes(
            child, label=f"local_files CODEX_HOME/{child.name}"
        )
        row: dict[str, Any] = {
            "name": child.name,
            "path": child.resolve(strict=True).as_posix(),
            "size_bytes": len(data),
            "type": "file",
        }
        if child.name != "auth.json":
            row["sha256"] = hashlib.sha256(data).hexdigest()
            policy_files[child.name] = row
            policy_bytes[child.name] = data
        inventory.append(row)

    config_data = policy_bytes["config.toml"]
    managed_data = policy_bytes["managed_config.toml"]
    if _strict_toml(config_data, label="local_files config.toml") != _LOCAL_FILES_CONFIG:
        raise AppServerError("local_files config.toml policy differs from the exact profile")
    if (
        _strict_toml(managed_data, label="local_files managed_config.toml")
        != _LOCAL_FILES_MANAGED_CONFIG
    ):
        raise AppServerError(
            "local_files managed_config.toml policy differs from the exact profile"
        )

    inventory_bytes = json.dumps(
        inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    thread_config_bytes = json.dumps(
        _LOCAL_FILES_THREAD_CONFIG,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return {
        "mode": "local_files",
        "codex_home": resolved_home.as_posix(),
        "initial_inventory": inventory,
        "initial_inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "config_path": policy_files["config.toml"]["path"],
        "config_sha256": policy_files["config.toml"]["sha256"],
        "managed_config_path": policy_files["managed_config.toml"]["path"],
        "managed_config_sha256": policy_files["managed_config.toml"]["sha256"],
        "thread_config_sha256": hashlib.sha256(thread_config_bytes).hexdigest(),
    }


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
    if event.method == "model/rerouted":
        # Do not parse untrusted reroute fields before the exact raw line has
        # reached the rejected-notification evidence callback.
        return (event.method, event.sha256)
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


def _require_fields(
    value: Mapping[str, Any], required: frozenset[str], label: str
) -> None:
    missing = sorted(required - set(value))
    if missing:
        raise ProtocolViolation(
            f"{label} is missing pinned required fields: {', '.join(missing)}"
        )


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ProtocolViolation(f"{label} must be a string")
    return value


def _require_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProtocolViolation(f"{label} must be an integer")
    return value


def _require_boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolViolation(f"{label} must be a boolean")
    return value


def _require_array(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProtocolViolation(f"{label} must be an array")
    return value


def _absolute_path(value: object, label: str) -> Path:
    text = _require_string(value, label)
    path = Path(text)
    if not path.is_absolute():
        raise ProtocolViolation(f"{label} must be an absolute path")
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise ProtocolViolation(f"{label} could not be normalized") from exc


def _require_same_path(value: object, expected: str, label: str) -> None:
    observed_path = _absolute_path(value, label)
    expected_path = _absolute_path(expected, f"expected {label}")
    if os.path.normcase(str(observed_path)) != os.path.normcase(str(expected_path)):
        raise ResponsePolicyDrift(f"{label} differs from the sealed launch intent")


def _validate_thread_status(value: object, label: str) -> None:
    status = _require_object(value, label)
    status_type = _require_string(status.get("type"), f"{label}.type")
    if status_type not in {"notLoaded", "idle", "systemError", "active"}:
        raise ProtocolViolation(f"{label}.type is outside the pinned schema")
    if status_type == "active":
        flags = _require_array(status.get("activeFlags"), f"{label}.activeFlags")
        if any(
            flag not in {"waitingOnApproval", "waitingOnUserInput"}
            for flag in flags
        ):
            raise ProtocolViolation(f"{label}.activeFlags is outside the pinned schema")


def _validate_thread_item(value: object, label: str) -> dict[str, Any]:
    item = _require_object(value, label)
    item_type = _require_string(item.get("type"), f"{label}.type")
    try:
        required = _THREAD_ITEM_REQUIRED_FIELDS[item_type]
    except KeyError as exc:
        raise ProtocolViolation(f"unsupported App Server item type: {item_type}") from exc
    _require_fields(item, required, label)
    _require_string(item.get("id"), f"{label}.id")
    if "text" in required:
        _require_text(item.get("text"), f"{label}.text")
    return item


def _validate_turn_object(
    value: object,
    label: str,
    *,
    allowed_statuses: frozenset[str],
) -> dict[str, Any]:
    turn = _require_object(value, label)
    _require_fields(turn, _TURN_REQUIRED, label)
    _require_string(turn.get("id"), f"{label}.id")
    status = _require_string(turn.get("status"), f"{label}.status")
    if status not in allowed_statuses:
        raise ProtocolViolation(f"{label}.status is outside the expected pinned state")
    items = _require_array(turn.get("items"), f"{label}.items")
    for index, item in enumerate(items):
        _validate_thread_item(item, f"{label}.items[{index}]")
    for field in ("startedAt", "completedAt", "durationMs"):
        if field in turn and turn[field] is not None:
            _require_integer(turn[field], f"{label}.{field}")
    if "itemsView" in turn and turn["itemsView"] not in {
        "notLoaded",
        "summary",
        "full",
    }:
        raise ProtocolViolation(f"{label}.itemsView is outside the pinned schema")
    if status == "inProgress" and turn.get("error") is not None:
        raise ProtocolViolation(f"{label}.error must be null while in progress")
    return turn


def _validate_thread_object(
    value: object,
    label: str,
    *,
    expected_cwd: str | None = None,
) -> dict[str, Any]:
    thread = _require_object(value, label)
    _require_fields(thread, _THREAD_REQUIRED, label)
    _require_string(thread.get("id"), f"{label}.id")
    _require_string(thread.get("cliVersion"), f"{label}.cliVersion")
    _require_integer(thread.get("createdAt"), f"{label}.createdAt")
    _require_integer(thread.get("updatedAt"), f"{label}.updatedAt")
    _absolute_path(thread.get("cwd"), f"{label}.cwd")
    if expected_cwd is not None:
        _require_same_path(thread.get("cwd"), expected_cwd, f"{label}.cwd")
    _require_boolean(thread.get("ephemeral"), f"{label}.ephemeral")
    _require_string(thread.get("modelProvider"), f"{label}.modelProvider")
    _require_text(thread.get("preview"), f"{label}.preview")
    _require_string(thread.get("sessionId"), f"{label}.sessionId")
    if thread.get("source") != "appServer":
        raise ProtocolViolation(f"{label}.source is not the pinned appServer source")
    _validate_thread_status(thread.get("status"), f"{label}.status")
    turns = _require_array(thread.get("turns"), f"{label}.turns")
    if turns:
        raise ProtocolViolation(f"{label}.turns must be empty for thread/start")
    return thread


def _validate_initialize_response(
    value: dict[str, Any], *, expected_codex_home: str | None = None
) -> dict[str, Any]:
    _require_fields(value, _INITIALIZE_RESPONSE_REQUIRED, "initialize response")
    _absolute_path(value.get("codexHome"), "initialize response codexHome")
    if expected_codex_home is not None:
        _require_same_path(
            value.get("codexHome"),
            expected_codex_home,
            "initialize response codexHome",
        )
    _require_string(value.get("platformFamily"), "initialize response platformFamily")
    _require_string(value.get("platformOs"), "initialize response platformOs")
    _require_string(value.get("userAgent"), "initialize response userAgent")
    return value


def _validate_model_list_response(
    value: dict[str, Any], *, intent: SealedLaunchIntent
) -> dict[str, Any]:
    _require_fields(value, _MODEL_LIST_RESPONSE_REQUIRED, "model/list response")
    if value.get("nextCursor") is not None:
        _require_text(value.get("nextCursor"), "model/list response nextCursor")
        raise ModelCatalogDrift(
            "model/list response is paginated beyond the bounded preflight page"
        )
    rows = _require_array(value.get("data"), "model/list response data")
    candidates: list[dict[str, Any]] = []
    for index, raw_row in enumerate(rows):
        label = f"model/list response data[{index}]"
        row = _require_object(raw_row, label)
        _require_fields(row, _MODEL_REQUIRED, label)
        _require_string(
            row.get("defaultReasoningEffort"), f"{label}.defaultReasoningEffort"
        )
        _require_text(row.get("description"), f"{label}.description")
        _require_text(row.get("displayName"), f"{label}.displayName")
        hidden = _require_boolean(row.get("hidden"), f"{label}.hidden")
        _require_text(row.get("id"), f"{label}.id")
        _require_boolean(row.get("isDefault"), f"{label}.isDefault")
        model = _require_text(row.get("model"), f"{label}.model")
        effort_rows = _require_array(
            row.get("supportedReasoningEfforts"),
            f"{label}.supportedReasoningEfforts",
        )
        for effort_index, raw_effort in enumerate(effort_rows):
            effort_label = f"{label}.supportedReasoningEfforts[{effort_index}]"
            effort = _require_object(raw_effort, effort_label)
            _require_fields(effort, _REASONING_EFFORT_OPTION_REQUIRED, effort_label)
            _require_text(effort.get("description"), f"{effort_label}.description")
            _require_string(
                effort.get("reasoningEffort"),
                f"{effort_label}.reasoningEffort",
            )
        if model == intent.model and hidden is False:
            candidates.append(row)
    if len(candidates) != 1:
        raise ModelCatalogDrift(
            "model/list must contain exactly one visible exact requested model"
        )
    supported = {
        str(item["reasoningEffort"])
        for item in candidates[0]["supportedReasoningEfforts"]
    }
    if intent.effort not in supported:
        raise ModelCatalogDrift(
            "model/list exact requested model does not support the sealed effort"
        )
    return value


def _validate_thread_start_response(
    value: dict[str, Any], *, intent: SealedLaunchIntent
) -> dict[str, Any]:
    _require_fields(
        value, _THREAD_START_RESPONSE_REQUIRED, "thread/start response"
    )
    if value.get("approvalPolicy") != "never":
        raise ResponsePolicyDrift(
            "thread/start response approvalPolicy differs from sealed approval"
        )
    if value.get("approvalsReviewer") not in {
        "user",
        "auto_review",
        "guardian_subagent",
    }:
        raise ProtocolViolation(
            "thread/start response approvalsReviewer is outside the pinned schema"
        )
    _require_same_path(
        value.get("cwd"), intent.cwd, "thread/start response cwd"
    )
    if value.get("model") != intent.model:
        raise ResponsePolicyDrift(
            "thread/start response model differs from sealed launch intent"
        )
    model_provider = _require_string(
        value.get("modelProvider"), "thread/start response modelProvider"
    )
    sandbox = _require_object(value.get("sandbox"), "thread/start response sandbox")
    expected_type = {
        "readOnly": "readOnly",
        "workspaceWrite": "workspaceWrite",
    }[intent.sandbox]
    if sandbox.get("type") != expected_type:
        raise ResponsePolicyDrift(
            "thread/start response sandbox differs from sealed launch intent"
        )
    if sandbox.get("networkAccess", False) is not False:
        raise ResponsePolicyDrift(
            "thread/start response sandbox grants network access"
        )
    if expected_type == "workspaceWrite" and "writableRoots" in sandbox:
        roots = _require_array(
            sandbox["writableRoots"],
            "thread/start response sandbox.writableRoots",
        )
        if len(roots) != 1:
            raise ResponsePolicyDrift(
                "thread/start response sandbox has unexpected writable roots"
            )
        _require_same_path(
            roots[0],
            intent.cwd,
            "thread/start response sandbox.writableRoots[0]",
        )
    thread = _validate_thread_object(
        value.get("thread"),
        "thread/start response thread",
        expected_cwd=intent.cwd,
    )
    if thread["ephemeral"] is not True:
        raise ResponsePolicyDrift("thread/start response thread is not ephemeral")
    if thread["modelProvider"] != model_provider:
        raise ProtocolViolation(
            "thread/start response modelProvider disagrees with thread"
        )
    return value


def _validate_turn_start_response(value: dict[str, Any]) -> dict[str, Any]:
    _require_fields(value, frozenset({"turn"}), "turn/start response")
    _validate_turn_object(
        value.get("turn"),
        "turn/start response turn",
        allowed_statuses=frozenset({"inProgress"}),
    )
    return value


def _validate_turn_interrupt_response(value: dict[str, Any]) -> dict[str, Any]:
    # Pinned TurnInterruptResponse is an unconstrained object.  The envelope
    # validator has already established that exact top-level type.
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
