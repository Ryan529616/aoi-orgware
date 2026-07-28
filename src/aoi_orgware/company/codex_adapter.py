"""Pure, fail-closed parser for pinned Codex app-server telemetry.

This module deliberately has no Supervisor, ledger, registry, clock, or I/O
dependency.  It preserves one provider notification as one raw fact; later
layers own persistence, idempotency, AOI-dispatch joins, and any usage
attribution.  The supported wire shapes are pinned to the repository's
``codex-app-server 0.145.0`` schema resource.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Literal, TypeAlias


# These are parser admission limits, not assertions about provider limits.
MAX_RAW_NOTIFICATION_BYTES = 1 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 16 * 1024
MAX_CONTAINER_MEMBERS = 4 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_ITEMS_PER_TURN = 1024
MAX_RECEIVER_THREAD_IDS = 1024
MAX_TOKEN_VALUE = (1 << 63) - 1
MIN_INT64 = -(1 << 63)

_METHODS = frozenset(
    {
        "thread/started",
        "thread/status/changed",
        "turn/started",
        "turn/completed",
        "item/started",
        "item/completed",
        "model/rerouted",
        "thread/tokenUsage/updated",
    }
)
_THREAD_STATUS_TYPES = frozenset({"notLoaded", "idle", "systemError", "active"})
_TURN_STATUS_TYPES = frozenset({"completed", "interrupted", "failed", "inProgress"})
_COLLAB_TOOLS = frozenset({"spawnAgent", "sendInput", "resumeAgent", "wait", "closeAgent"})
_COLLAB_STATUSES = frozenset({"inProgress", "completed", "failed"})
_SUBAGENT_KINDS = frozenset({"started", "interacted", "interrupted"})
_SUPPORTED_THREAD_ITEM_TYPES = frozenset({"collabAgentToolCall", "subAgentActivity"})


class CodexAdapterError(ValueError):
    """The raw notification is malformed or outside this parser's bounds."""


class UnsupportedCodexNotification(CodexAdapterError):
    """A validly framed notification whose method is not in the allowlist."""

    def __init__(self, method: str, *, raw_sha256: str, raw_size_bytes: int) -> None:
        super().__init__(f"unsupported Codex app-server notification: {method}")
        self.method = method
        self.raw_sha256 = raw_sha256
        self.raw_size_bytes = raw_size_bytes


@dataclass(frozen=True)
class RawCodexNotification:
    """Digest identity for the exact raw UTF-8 JSON input, not a semantic ID."""

    method: str
    raw_sha256: str
    raw_size_bytes: int


@dataclass(frozen=True)
class TokenVector:
    """One provider-reported vector; no derived arithmetic is performed."""

    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int
    total_tokens: int
    cache_write_input_tokens: int | None


@dataclass(frozen=True)
class CollabAgentToolCall:
    """Native collaboration fields, without AOI parentage or prompt content.

    Non-empty ``agentsStates`` is rejected because this focused parser does
    not expose its nested provider status map as an AOI-ready fact.
    """

    sender_thread_id: str
    receiver_thread_ids: tuple[str, ...]
    tool: str
    status: str
    requested_model: str | None
    requested_effort: str | None


@dataclass(frozen=True)
class NativeThreadSpawnSource:
    """Provider-native thread-spawn metadata; it is not AOI lineage."""

    parent_thread_id: str
    depth: int
    agent_nickname: str | None
    agent_path: str | None
    agent_role: str | None


@dataclass(frozen=True)
class NativeSessionSource:
    """Schema-proven SessionSource details without deriving parentage."""

    kind: str
    custom: str | None
    subagent_kind: str | None
    subagent_other: str | None
    thread_spawn: NativeThreadSpawnSource | None


@dataclass(frozen=True)
class SubAgentActivity:
    """Native subagent activity fields; ``agent_path`` is not AOI lineage."""

    agent_thread_id: str
    agent_path: str
    kind: str


@dataclass(frozen=True)
class ThreadStarted(RawCodexNotification):
    thread_id: str
    thread_status: str
    active_flags: tuple[str, ...] | None
    model_provider: str
    created_at: int
    updated_at: int
    native_parent_thread_id: str | None
    native_forked_from_id: str | None
    native_thread_source: str | None
    native_session_id: str
    native_agent_nickname: str | None
    native_agent_role: str | None
    native_source: NativeSessionSource


@dataclass(frozen=True)
class ThreadStatusChanged(RawCodexNotification):
    thread_id: str
    thread_status: str
    active_flags: tuple[str, ...] | None


@dataclass(frozen=True)
class TurnStarted(RawCodexNotification):
    thread_id: str
    turn_id: str
    turn_status: str
    started_at: int | None
    completed_at: int | None
    duration_ms: int | None


@dataclass(frozen=True)
class TurnCompleted(RawCodexNotification):
    thread_id: str
    turn_id: str
    turn_status: str
    started_at: int | None
    completed_at: int | None
    duration_ms: int | None


@dataclass(frozen=True)
class ItemStarted(RawCodexNotification):
    thread_id: str
    turn_id: str
    item_id: str
    item_type: str
    started_at_ms: int
    collab_agent_tool_call: CollabAgentToolCall | None
    subagent_activity: SubAgentActivity | None


@dataclass(frozen=True)
class ItemCompleted(RawCodexNotification):
    thread_id: str
    turn_id: str
    item_id: str
    item_type: str
    completed_at_ms: int
    collab_agent_tool_call: CollabAgentToolCall | None
    subagent_activity: SubAgentActivity | None


@dataclass(frozen=True)
class ModelRerouted(RawCodexNotification):
    thread_id: str
    turn_id: str
    from_model: str
    to_model: str
    reason: Literal["highRiskCyberActivity"]


@dataclass(frozen=True)
class ThreadTokenUsageUpdated(RawCodexNotification):
    thread_id: str
    turn_id: str
    total: TokenVector
    last: TokenVector
    model_context_window: int | None


CodexTelemetryObservation: TypeAlias = (
    ThreadStarted
    | ThreadStatusChanged
    | TurnStarted
    | TurnCompleted
    | ItemStarted
    | ItemCompleted
    | ModelRerouted
    | ThreadTokenUsageUpdated
)


def parse_codex_notification(raw: bytes) -> CodexTelemetryObservation:
    """Parse one exact UTF-8 JSON notification into a frozen raw observation.

    Unknown methods are deliberately typed as unsupported rather than coerced
    into an event.  Repeated or unchanged cumulative token updates remain
    independent raw facts; this function has no state with which to sum them.
    """

    if type(raw) is not bytes or not raw or len(raw) > MAX_RAW_NOTIFICATION_BYTES:
        raise CodexAdapterError("raw notification must be non-empty bounded bytes")
    digest = hashlib.sha256(raw).hexdigest()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CodexAdapterError("raw notification must not have a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise CodexAdapterError("raw notification is not strict UTF-8") from exc
    try:
        decoder = json.JSONDecoder(object_pairs_hook=_no_duplicate_object)
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise CodexAdapterError("raw notification is not strict JSON") from exc
    if end != len(text):
        raise CodexAdapterError("raw notification has trailing bytes")
    _validate_json_bounds(value)
    envelope = _object(value, "notification envelope")
    if set(envelope) != {"method", "params"}:
        raise CodexAdapterError("notification envelope fields are invalid")
    method = _text(envelope["method"], "notification method")
    if method not in _METHODS:
        raise UnsupportedCodexNotification(
            method, raw_sha256=digest, raw_size_bytes=len(raw)
        )
    params = _object(envelope["params"], f"{method} params")
    base = RawCodexNotification(method, digest, len(raw))
    if method == "thread/started":
        _required(params, {"thread"}, method)
        thread = _object(params["thread"], "thread/started thread")
        return _thread_started(base, thread)
    if method == "thread/status/changed":
        _required(params, {"threadId", "status"}, method)
        status, flags = _thread_status(params["status"])
        return ThreadStatusChanged(
            **_raw_fields(base),
            thread_id=_identifier(params["threadId"], "thread/status/changed threadId"),
            thread_status=status,
            active_flags=flags,
        )
    if method in {"turn/started", "turn/completed"}:
        _required(params, {"threadId", "turn"}, method)
        thread_id = _identifier(params["threadId"], f"{method} threadId")
        turn_id, status, started_at, completed_at, duration_ms = _turn(params["turn"], method)
        cls = TurnStarted if method == "turn/started" else TurnCompleted
        return cls(
            **_raw_fields(base),
            thread_id=thread_id,
            turn_id=turn_id,
            turn_status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )
    if method in {"item/started", "item/completed"}:
        clock = "startedAtMs" if method == "item/started" else "completedAtMs"
        _required(params, {"threadId", "turnId", "item", clock}, method)
        item_id, item_type, collab, activity = _item(params["item"], method)
        common = dict(
            **_raw_fields(base),
            thread_id=_identifier(params["threadId"], f"{method} threadId"),
            turn_id=_identifier(params["turnId"], f"{method} turnId"),
            item_id=item_id,
            item_type=item_type,
            collab_agent_tool_call=collab,
            subagent_activity=activity,
        )
        timestamp = _nonnegative_int64(params[clock], f"{method} {clock}")
        if method == "item/started":
            return ItemStarted(**common, started_at_ms=timestamp)
        return ItemCompleted(**common, completed_at_ms=timestamp)
    if method == "model/rerouted":
        _required(params, {"threadId", "turnId", "fromModel", "toModel", "reason"}, method)
        reason = _text(params["reason"], "model/rerouted reason")
        if reason != "highRiskCyberActivity":
            raise CodexAdapterError("model/rerouted reason is outside pinned schema")
        pinned_reason: Literal["highRiskCyberActivity"] = "highRiskCyberActivity"
        return ModelRerouted(
            **_raw_fields(base),
            thread_id=_identifier(params["threadId"], "model/rerouted threadId"),
            turn_id=_identifier(params["turnId"], "model/rerouted turnId"),
            from_model=_text(params["fromModel"], "model/rerouted fromModel"),
            to_model=_text(params["toModel"], "model/rerouted toModel"),
            reason=pinned_reason,
        )
    _required(params, {"threadId", "turnId", "tokenUsage"}, method)
    usage = _object(params["tokenUsage"], "thread/tokenUsage/updated tokenUsage")
    _required(usage, {"total", "last"}, "thread/tokenUsage/updated tokenUsage")
    context = usage.get("modelContextWindow")
    return ThreadTokenUsageUpdated(
        **_raw_fields(base),
        thread_id=_identifier(params["threadId"], "thread/tokenUsage/updated threadId"),
        turn_id=_identifier(params["turnId"], "thread/tokenUsage/updated turnId"),
        total=_token_vector(usage["total"], "thread/tokenUsage/updated total"),
        last=_token_vector(usage["last"], "thread/tokenUsage/updated last"),
        model_context_window=(
            None
            if context is None
            else _nonnegative_int64(context, "thread/tokenUsage/updated modelContextWindow")
        ),
    )


def _thread_started(base: RawCodexNotification, thread: dict[str, Any]) -> ThreadStarted:
    _required(
        thread,
        {
            "cliVersion", "createdAt", "cwd", "ephemeral", "id", "modelProvider",
            "preview", "sessionId", "source", "status", "turns", "updatedAt",
        },
        "thread/started thread",
    )
    _text(thread["cliVersion"], "thread/started cliVersion")
    _text(thread["cwd"], "thread/started cwd")
    model_provider = _text(thread["modelProvider"], "thread/started modelProvider")
    _text(thread["preview"], "thread/started preview")
    source = _session_source(thread["source"], "thread/started source")
    created_at = _int64(thread["createdAt"], "thread/started createdAt")
    updated_at = _int64(thread["updatedAt"], "thread/started updatedAt")
    if type(thread["ephemeral"]) is not bool:
        raise CodexAdapterError("thread/started ephemeral must be boolean")
    _object(thread["status"], "thread/started status")
    status, active_flags = _thread_status(thread["status"])
    turns = _array(thread["turns"], "thread/started turns", MAX_ITEMS_PER_TURN)
    for turn in turns:
        _turn(turn, "thread/started turn")
    parent = _optional_identifier(thread, "parentThreadId", "thread/started parentThreadId")
    forked_from = _optional_identifier(
        thread, "forkedFromId", "thread/started forkedFromId"
    )
    thread_source = _optional_text(
        thread, "threadSource", "thread/started threadSource"
    )
    nickname = _optional_text(thread, "agentNickname", "thread/started agentNickname")
    role = _optional_text(thread, "agentRole", "thread/started agentRole")
    source_parent = (
        None if source.thread_spawn is None else source.thread_spawn.parent_thread_id
    )
    if parent is not None and source_parent is not None and parent != source_parent:
        raise CodexAdapterError("thread/started native parent sources diverge")
    return ThreadStarted(
        **_raw_fields(base),
        thread_id=_identifier(thread["id"], "thread/started threadId"),
        thread_status=status,
        active_flags=active_flags,
        model_provider=model_provider,
        created_at=created_at,
        updated_at=updated_at,
        native_parent_thread_id=parent,
        native_forked_from_id=forked_from,
        native_thread_source=thread_source,
        native_session_id=_identifier(thread["sessionId"], "thread/started sessionId"),
        native_agent_nickname=nickname,
        native_agent_role=role,
        native_source=source,
    )


def _turn(value: Any, label: str) -> tuple[str, str, int | None, int | None, int | None]:
    turn = _object(value, f"{label} turn")
    _required(turn, {"id", "items", "status"}, f"{label} turn")
    status = _text(turn["status"], f"{label} turn status")
    if status not in _TURN_STATUS_TYPES:
        raise CodexAdapterError(f"{label} turn status is outside pinned schema")
    items = _array(turn["items"], f"{label} turn items", MAX_ITEMS_PER_TURN)
    for item in items:
        _item(item, f"{label} turn item")
    started_at = _optional_int64(turn, "startedAt", f"{label} turn startedAt")
    completed_at = _optional_int64(turn, "completedAt", f"{label} turn completedAt")
    duration_ms = _optional_int64(turn, "durationMs", f"{label} turn durationMs")
    return (
        _identifier(turn["id"], f"{label} turn id"),
        status,
        started_at,
        completed_at,
        duration_ms,
    )


def _thread_status(value: Any) -> tuple[str, tuple[str, ...] | None]:
    status = _object(value, "thread status")
    _required(status, {"type"}, "thread status")
    kind = _text(status["type"], "thread status type")
    if kind not in _THREAD_STATUS_TYPES:
        raise CodexAdapterError("thread status type is outside pinned schema")
    if kind != "active":
        return kind, None
    _required(status, {"activeFlags"}, "active thread status")
    flags = _array(status["activeFlags"], "active thread flags", MAX_CONTAINER_MEMBERS)
    parsed = tuple(_text(item, "active thread flag") for item in flags)
    if any(flag not in {"waitingOnApproval", "waitingOnUserInput"} for flag in parsed):
        raise CodexAdapterError("active thread flag is outside pinned schema")
    return kind, parsed


def _item(
    value: Any, label: str
) -> tuple[str, str, CollabAgentToolCall | None, SubAgentActivity | None]:
    item = _object(value, f"{label} item")
    _required(item, {"id", "type"}, f"{label} item")
    item_id = _identifier(item["id"], f"{label} item id")
    item_type = _text(item["type"], f"{label} item type")
    if item_type not in _SUPPORTED_THREAD_ITEM_TYPES:
        raise CodexAdapterError(f"{label} item type is outside pinned parser subset")
    if item_type == "collabAgentToolCall":
        _required(
            item,
            {"agentsStates", "id", "receiverThreadIds", "senderThreadId", "status", "tool", "type"},
            "collabAgentToolCall item",
        )
        agents_states = _object(item["agentsStates"], "collabAgentToolCall agentsStates")
        if agents_states:
            raise CodexAdapterError("non-empty collabAgentToolCall agentsStates are unsupported")
        # ``prompt`` remains redacted but is still schema-shape validated.
        _optional_text(item, "prompt", "collabAgentToolCall prompt")
        receivers = _array(item["receiverThreadIds"], "collabAgentToolCall receiverThreadIds", MAX_RECEIVER_THREAD_IDS)
        tool = _text(item["tool"], "collabAgentToolCall tool")
        status = _text(item["status"], "collabAgentToolCall status")
        if tool not in _COLLAB_TOOLS or status not in _COLLAB_STATUSES:
            raise CodexAdapterError("collabAgentToolCall value is outside pinned schema")
        return (
            item_id,
            item_type,
            CollabAgentToolCall(
                sender_thread_id=_identifier(item["senderThreadId"], "collabAgentToolCall senderThreadId"),
                receiver_thread_ids=tuple(
                    _identifier(receiver, "collabAgentToolCall receiverThreadId")
                    for receiver in receivers
                ),
                tool=tool,
                status=status,
                requested_model=_optional_text(
                    item, "model", "collabAgentToolCall model"
                ),
                requested_effort=_optional_nonempty_text(
                    item, "reasoningEffort", "collabAgentToolCall reasoningEffort"
                ),
            ),
            None,
        )
    if item_type == "subAgentActivity":
        _required(item, {"agentPath", "agentThreadId", "id", "kind", "type"}, "subAgentActivity item")
        kind = _text(item["kind"], "subAgentActivity kind")
        if kind not in _SUBAGENT_KINDS:
            raise CodexAdapterError("subAgentActivity kind is outside pinned schema")
        return (
            item_id,
            item_type,
            None,
            SubAgentActivity(
                agent_thread_id=_identifier(item["agentThreadId"], "subAgentActivity agentThreadId"),
                agent_path=_text(item["agentPath"], "subAgentActivity agentPath"),
                kind=kind,
            ),
        )
    raise AssertionError("supported ThreadItem type was not handled")


def _token_vector(value: Any, label: str) -> TokenVector:
    vector = _object(value, label)
    _required(
        vector,
        {"inputTokens", "cachedInputTokens", "outputTokens", "reasoningOutputTokens", "totalTokens"},
        label,
    )
    cache_write = vector.get("cacheWriteInputTokens")
    return TokenVector(
        input_tokens=_counter(vector["inputTokens"], f"{label} inputTokens"),
        cached_input_tokens=_counter(vector["cachedInputTokens"], f"{label} cachedInputTokens"),
        output_tokens=_counter(vector["outputTokens"], f"{label} outputTokens"),
        reasoning_output_tokens=_counter(vector["reasoningOutputTokens"], f"{label} reasoningOutputTokens"),
        total_tokens=_counter(vector["totalTokens"], f"{label} totalTokens"),
        cache_write_input_tokens=(
            None if cache_write is None else _counter(cache_write, f"{label} cacheWriteInputTokens")
        ),
    )


def _session_source(value: Any, label: str) -> NativeSessionSource:
    """Parse SessionSource without treating its native fields as AOI lineage."""

    if type(value) is str:
        kind = _text(value, label)
        if kind not in {"cli", "vscode", "exec", "appServer", "unknown"}:
            raise CodexAdapterError(f"{label} is outside pinned schema")
        return NativeSessionSource(kind, None, None, None, None)
    source = _object(value, label)
    if set(source) == {"custom"}:
        return NativeSessionSource(
            "custom", _text(source["custom"], f"{label} custom"), None, None, None
        )
    if set(source) == {"subAgent"}:
        return _subagent_source(source["subAgent"], f"{label} subAgent")
    raise CodexAdapterError(f"{label} is outside pinned schema")


def _subagent_source(value: Any, label: str) -> NativeSessionSource:
    if type(value) is str:
        kind = _text(value, label)
        if kind not in {"review", "compact", "memory_consolidation"}:
            raise CodexAdapterError(f"{label} is outside pinned schema")
        return NativeSessionSource("subAgent", None, kind, None, None)
    source = _object(value, label)
    if set(source) == {"other"}:
        return NativeSessionSource(
            "subAgent", None, "other", _text(source["other"], f"{label} other"), None
        )
    if set(source) != {"thread_spawn"}:
        raise CodexAdapterError(f"{label} is outside pinned schema")
    spawn = _object(source["thread_spawn"], f"{label} thread_spawn")
    _required(spawn, {"depth", "parent_thread_id"}, f"{label} thread_spawn")
    if type(spawn["depth"]) is not int or not -(1 << 31) <= spawn["depth"] < (1 << 31):
        raise CodexAdapterError(f"{label} thread_spawn depth must be int32")
    return NativeSessionSource(
        "subAgent",
        None,
        "thread_spawn",
        None,
        NativeThreadSpawnSource(
            parent_thread_id=_identifier(
                spawn["parent_thread_id"], f"{label} thread_spawn parent_thread_id"
            ),
            depth=spawn["depth"],
            agent_nickname=_optional_text(
                spawn, "agent_nickname", f"{label} thread_spawn agent_nickname"
            ),
            agent_path=_optional_text(
                spawn, "agent_path", f"{label} thread_spawn agent_path"
            ),
            agent_role=_optional_text(
                spawn, "agent_role", f"{label} thread_spawn agent_role"
            ),
        ),
    )


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise CodexAdapterError("JSON object has duplicate key")
        value[key] = member
    return value


def _validate_json_bounds(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise CodexAdapterError("JSON structure exceeds parser bounds")
        if isinstance(current, dict):
            if len(current) > MAX_CONTAINER_MEMBERS:
                raise CodexAdapterError("JSON object exceeds parser bounds")
            for key, member in current.items():
                _text(key, "JSON object key")
                stack.append((member, depth + 1))
        elif isinstance(current, list):
            if len(current) > MAX_CONTAINER_MEMBERS:
                raise CodexAdapterError("JSON array exceeds parser bounds")
            stack.extend((member, depth + 1) for member in current)
        elif isinstance(current, float):
            raise CodexAdapterError("JSON floating-point values are unsupported")
        elif type(current) is int and not MIN_INT64 <= current <= MAX_TOKEN_VALUE:
            raise CodexAdapterError("JSON integer is outside int64 bounds")
        elif not isinstance(current, (str, int, bool)) and current is not None:
            raise CodexAdapterError("JSON value is invalid")
        elif isinstance(current, str):
            _text(current, "JSON string")


def _object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CodexAdapterError(f"{label} must be an object")
    return value


def _array(value: Any, label: str, maximum: int) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise CodexAdapterError(f"{label} must be a bounded array")
    return value


def _required(value: dict[str, Any], fields: set[str], label: str) -> None:
    missing = fields.difference(value)
    if missing:
        raise CodexAdapterError(f"{label} is missing required fields: {','.join(sorted(missing))}")


def _text(value: Any, label: str) -> str:
    if type(value) is not str:
        raise CodexAdapterError(f"{label} must be bounded text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise CodexAdapterError(f"{label} is not valid UTF-8 text") from exc
    if len(encoded) > MAX_TEXT_BYTES:
        raise CodexAdapterError(f"{label} must be bounded text")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label)
    if not text or "\x00" in text:
        raise CodexAdapterError(f"{label} must be non-empty")
    return text


def _optional_text(value: dict[str, Any], field: str, label: str) -> str | None:
    member = value.get(field)
    return None if member is None else _text(member, label)


def _optional_identifier(value: dict[str, Any], field: str, label: str) -> str | None:
    member = value.get(field)
    return None if member is None else _identifier(member, label)


def _optional_nonempty_text(value: dict[str, Any], field: str, label: str) -> str | None:
    member = value.get(field)
    if member is None:
        return None
    text = _text(member, label)
    if not text:
        raise CodexAdapterError(f"{label} must be non-empty")
    return text


def _int64(value: Any, label: str) -> int:
    if type(value) is not int or not MIN_INT64 <= value <= MAX_TOKEN_VALUE:
        raise CodexAdapterError(f"{label} must be an int64")
    return value


def _optional_int64(value: dict[str, Any], field: str, label: str) -> int | None:
    member = value.get(field)
    return None if member is None else _int64(member, label)


def _nonnegative_int64(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_TOKEN_VALUE:
        raise CodexAdapterError(f"{label} must be a non-negative int64")
    return value


def _counter(value: Any, label: str) -> int:
    return _nonnegative_int64(value, label)


def _raw_fields(value: RawCodexNotification) -> dict[str, Any]:
    return {
        "method": value.method,
        "raw_sha256": value.raw_sha256,
        "raw_size_bytes": value.raw_size_bytes,
    }


__all__ = [
    "CodexAdapterError",
    "CodexTelemetryObservation",
    "CollabAgentToolCall",
    "ItemCompleted",
    "ItemStarted",
    "MAX_JSON_DEPTH",
    "MAX_RAW_NOTIFICATION_BYTES",
    "ModelRerouted",
    "NativeSessionSource",
    "NativeThreadSpawnSource",
    "RawCodexNotification",
    "SubAgentActivity",
    "ThreadStarted",
    "ThreadStatusChanged",
    "ThreadTokenUsageUpdated",
    "TokenVector",
    "TurnCompleted",
    "TurnStarted",
    "UnsupportedCodexNotification",
    "parse_codex_notification",
]
