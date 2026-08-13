"""Authority-free normalization of bounded provider telemetry facts.

This module deliberately stops before AOI dispatch joins, persistence, token
deltas, cost, completion, or lineage.  It makes the adapter output suitable for
a later append-only receipt without promoting a provider-native relationship to
an AOI relationship.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from types import MappingProxyType
from typing import Any, Literal, Mapping

from aoi_orgware.company.contracts import (
    MAX_EXECUTION_DEPTH,
    MAX_PROVIDER_TELEMETRY_RAW_BYTES,
    MAX_SHORT_TEXT_BYTES,
)
from aoi_orgware.company.claude_adapter import (
    ClaudeTelemetryEvent,
    ClaudeTelemetryParseError,
    TelemetryFact as ClaudeFact,
    parse_claude_telemetry,
)
from aoi_orgware.company.codex_adapter import (
    CodexAdapterError,
    CollabAgentToolCall,
    ItemCompleted,
    ItemStarted,
    ModelRerouted,
    SubAgentActivity,
    ThreadStarted,
    ThreadStatusChanged,
    ThreadTokenUsageUpdated,
    TokenVector,
    TurnCompleted,
    TurnStarted,
    UnsupportedCodexNotification,
    parse_codex_notification,
)


FactSource = Literal["provider_payload", "adapter_route", "none"]
FactQuality = Literal["observed", "missing", "unavailable"]
ParseOutcome = Literal["normalized", "unsupported_valid", "malformed"]
TelemetrySourceClass = Literal["codex_app_server", "claude_hook", "otel"]
FactName = Literal[
    "actual_provider",
    "actual_model",
    "actual_effort",
    "actual_role",
    "routing",
    "session_id",
    "thread_id",
    "turn_id",
    "agent_id",
    "parent_thread_id",
    "event_time",
    "engineering_completion",
]

_FACT_NAMES: tuple[FactName, ...] = (
    "actual_provider",
    "actual_model",
    "actual_effort",
    "actual_role",
    "routing",
    "session_id",
    "thread_id",
    "turn_id",
    "agent_id",
    "parent_thread_id",
    "event_time",
    "engineering_completion",
)


@dataclass(frozen=True)
class TelemetryFact:
    """One explicit fact or absence with a bounded reason code."""

    value: object | None
    source: FactSource
    quality: FactQuality
    reason: str


@dataclass(frozen=True)
class RoutingObservation:
    """Provider-requested routing metadata, never an actual-route assertion."""

    kind: Literal["collab_request", "model_reroute"]
    requested_model: str | None
    requested_effort: str | None
    tool: str | None
    status: str | None
    from_model: str | None
    to_model: str | None


@dataclass(frozen=True)
class ProviderNativeRelation:
    """Provider-native relation facts which are never AOI execution lineage."""

    kind: Literal[
        "none",
        "thread_spawn",
        "collab_request",
        "subagent_activity",
    ]
    sender_thread_id: str | None
    receiver_thread_ids: tuple[str, ...]
    child_thread_id: str | None
    agent_path: str | None
    activity_kind: str | None
    native_depth: int | None
    reason: str


@dataclass(frozen=True)
class RawTokenVector:
    """A provider vector exactly as reported; ``None`` is not converted to zero."""

    input: int
    cache_read: int
    cache_creation: int | None
    output: int
    reasoning_output: int
    total: int


@dataclass(frozen=True)
class RawCumulativeTokenSample:
    """A raw cumulative sample plus its raw ``last`` vector, not a delta."""

    total: RawTokenVector
    last: RawTokenVector
    model_context_window: int | None


@dataclass(frozen=True)
class NormalizedTelemetry:
    """Frozen persistence-ready facts with no authority or stateful interpretation."""

    provider: Literal["codex", "claude"]
    source_class: TelemetrySourceClass
    parser_id: Literal["codex_adapter", "claude_adapter"]
    parser_version: Literal["v1"]
    parse_outcome: ParseOutcome
    normalized_kind: str
    raw_sha256: str
    raw_size_bytes: int
    facts: Mapping[FactName, TelemetryFact]
    provider_native_relation: ProviderNativeRelation
    raw_cumulative_tokens: RawCumulativeTokenSample | None


class TelemetryIntakeRejected(ValueError):
    """Raw bytes exceed the bounded persistence intake contract."""


def _unavailable(reason: str, *, source: FactSource = "none") -> TelemetryFact:
    return TelemetryFact(None, source, "unavailable", reason)


def _missing(reason: str) -> TelemetryFact:
    return TelemetryFact(None, "provider_payload", "missing", reason)


def _observed(value: object, reason: str) -> TelemetryFact:
    return TelemetryFact(value, "provider_payload", "observed", reason)


def _facts(**values: TelemetryFact) -> Mapping[FactName, TelemetryFact]:
    missing = set(_FACT_NAMES).difference(values)
    extra = set(values).difference(_FACT_NAMES)
    if missing or extra:
        raise AssertionError("telemetry fact map must have exactly the pinned keys")
    return MappingProxyType({name: values[name] for name in _FACT_NAMES})


def _base_facts(reason: str) -> dict[str, TelemetryFact]:
    return {
        name: _unavailable(reason)
        for name in _FACT_NAMES
    }


def _complete_facts(values: dict[str, TelemetryFact]) -> Mapping[FactName, TelemetryFact]:
    # Runtime finish signals are never engineering completion evidence.
    values["engineering_completion"] = _unavailable("engineering_completion_unavailable")
    return _facts(**values)


def _raw_identity(raw: bytes) -> tuple[str, int]:
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _no_native_relation(reason: str) -> ProviderNativeRelation:
    return ProviderNativeRelation(
        kind="none",
        sender_thread_id=None,
        receiver_thread_ids=(),
        child_thread_id=None,
        agent_path=None,
        activity_kind=None,
        native_depth=None,
        reason=reason,
    )


def _bounded_raw(raw: bytes) -> None:
    if len(raw) > MAX_PROVIDER_TELEMETRY_RAW_BYTES:
        raise TelemetryIntakeRejected("provider telemetry exceeds the intake bound")


def _malformed(
    *, provider: Literal["codex", "claude"], source_class: TelemetrySourceClass,
    parser_id: Literal["codex_adapter", "claude_adapter"], raw: bytes,
) -> NormalizedTelemetry:
    digest, size = _raw_identity(raw)
    return NormalizedTelemetry(
        provider=provider,
        source_class=source_class,
        parser_id=parser_id,
        parser_version="v1",
        parse_outcome="malformed",
        normalized_kind="malformed",
        raw_sha256=digest,
        raw_size_bytes=size,
        facts=_complete_facts(_base_facts("parser_malformed")),
        provider_native_relation=_no_native_relation("parser_malformed"),
        raw_cumulative_tokens=None,
    )


def _unsupported(
    *, provider: Literal["codex", "claude"], source_class: TelemetrySourceClass,
    parser_id: Literal["codex_adapter", "claude_adapter"], raw: bytes,
    reason: str = "parser_unsupported_valid",
) -> NormalizedTelemetry:
    digest, size = _raw_identity(raw)
    return NormalizedTelemetry(
        provider=provider,
        source_class=source_class,
        parser_id=parser_id,
        parser_version="v1",
        parse_outcome="unsupported_valid",
        normalized_kind="unsupported",
        raw_sha256=digest,
        raw_size_bytes=size,
        facts=_complete_facts(_base_facts(reason)),
        provider_native_relation=_no_native_relation(
            reason,
        ),
        raw_cumulative_tokens=None,
    )


def _set_thread(values: dict[str, TelemetryFact], thread_id: str) -> None:
    values["thread_id"] = _observed(thread_id, "provider_thread_id")


def _set_turn(values: dict[str, TelemetryFact], turn_id: str) -> None:
    values["turn_id"] = _observed(turn_id, "provider_turn_id")


def _set_item_routing(
    values: dict[str, TelemetryFact], collab: CollabAgentToolCall | None,
    activity: SubAgentActivity | None, *, sender_thread_id: str,
) -> ProviderNativeRelation:
    if collab is not None:
        values["routing"] = _observed(
            RoutingObservation(
                kind="collab_request",
                requested_model=collab.requested_model,
                requested_effort=collab.requested_effort,
                tool=collab.tool,
                status=collab.status,
                from_model=None,
                to_model=None,
            ),
            "provider_requested_routing",
        )
        return ProviderNativeRelation(
            kind="collab_request",
            sender_thread_id=collab.sender_thread_id,
            receiver_thread_ids=tuple(sorted(collab.receiver_thread_ids)),
            child_thread_id=None,
            agent_path=None,
            activity_kind=None,
            native_depth=None,
            reason="provider_native_collab_relation_not_aoi_lineage",
        )
    if activity is not None:
        # Preserve the provider child identity without promoting it to AOI
        # parentage.  The Supervisor may only bind it by exact registry ID.
        values["agent_id"] = _unavailable(
            "native_subagent_activity_not_aoi_agent_id",
        )
        return ProviderNativeRelation(
            kind="subagent_activity",
            sender_thread_id=sender_thread_id,
            receiver_thread_ids=(activity.agent_thread_id,),
            child_thread_id=activity.agent_thread_id,
            agent_path=activity.agent_path,
            activity_kind=activity.kind,
            native_depth=None,
            reason="provider_native_subagent_activity_not_aoi_lineage",
        )
    return _no_native_relation("provider_relation_not_present")


def _native_parent(event: ThreadStarted) -> str | None:
    if event.native_parent_thread_id is not None:
        return event.native_parent_thread_id
    source = event.native_source.thread_spawn
    return None if source is None else source.parent_thread_id


def _token_vector(value: TokenVector) -> RawTokenVector:
    return RawTokenVector(
        input=value.input_tokens,
        cache_read=value.cached_input_tokens,
        cache_creation=value.cache_write_input_tokens,
        output=value.output_tokens,
        reasoning_output=value.reasoning_output_tokens,
        total=value.total_tokens,
    )


def _normalize_codex_observation(raw: bytes) -> NormalizedTelemetry:
    event = parse_codex_notification(raw)
    values = _base_facts("provider_field_not_present")
    kind = "unknown_codex_event"
    sample: RawCumulativeTokenSample | None = None
    relation = _no_native_relation("provider_relation_not_present")
    if isinstance(event, ThreadStarted):
        kind = "thread_waiting_on_user_input" if event.active_flags is not None and "waitingOnUserInput" in event.active_flags else "thread_started"
        _set_thread(values, event.thread_id)
        values["session_id"] = _observed(event.native_session_id, "provider_session_id")
        values["actual_provider"] = _observed(event.model_provider, "provider_model_provider")
        if event.native_agent_role is not None:
            values["actual_role"] = _observed(event.native_agent_role, "native_agent_role_not_aoi_role")
        parent = _native_parent(event)
        if parent is not None:
            values["parent_thread_id"] = _observed(parent, "native_parent_not_aoi_lineage")
            spawn = event.native_source.thread_spawn
            relation = ProviderNativeRelation(
                kind="thread_spawn",
                sender_thread_id=parent,
                receiver_thread_ids=(event.thread_id,),
                child_thread_id=event.thread_id,
                agent_path=None if spawn is None else spawn.agent_path,
                activity_kind=None,
                native_depth=None if spawn is None else spawn.depth,
                reason="provider_native_thread_spawn_not_aoi_lineage",
            )
        values["event_time"] = _observed(event.updated_at, "provider_thread_updated_at")
    elif isinstance(event, ThreadStatusChanged):
        kind = "thread_waiting_on_user_input" if event.active_flags is not None and "waitingOnUserInput" in event.active_flags else "thread_status_changed"
        _set_thread(values, event.thread_id)
    elif isinstance(event, TurnStarted):
        kind = "turn_started_runtime_observed"
        _set_thread(values, event.thread_id)
        _set_turn(values, event.turn_id)
        if event.started_at is not None:
            values["event_time"] = _observed(event.started_at, "provider_turn_started_at")
    elif isinstance(event, TurnCompleted):
        kind = "turn_completed_runtime_observed"
        _set_thread(values, event.thread_id)
        _set_turn(values, event.turn_id)
        if event.completed_at is not None:
            values["event_time"] = _observed(event.completed_at, "provider_turn_completed_at")
    elif isinstance(event, ItemStarted):
        kind = "item_started_runtime_observed"
        _set_thread(values, event.thread_id)
        _set_turn(values, event.turn_id)
        values["event_time"] = _observed(event.started_at_ms, "provider_item_started_at_ms")
        relation = _set_item_routing(
            values,
            event.collab_agent_tool_call,
            event.subagent_activity,
            sender_thread_id=event.thread_id,
        )
    elif isinstance(event, ItemCompleted):
        kind = "item_completed_runtime_observed"
        _set_thread(values, event.thread_id)
        _set_turn(values, event.turn_id)
        values["event_time"] = _observed(event.completed_at_ms, "provider_item_completed_at_ms")
        relation = _set_item_routing(
            values,
            event.collab_agent_tool_call,
            event.subagent_activity,
            sender_thread_id=event.thread_id,
        )
    elif isinstance(event, ModelRerouted):
        kind = "model_rerouted_runtime_observed"
        _set_thread(values, event.thread_id)
        _set_turn(values, event.turn_id)
        values["actual_model"] = _observed(event.to_model, "provider_rerouted_to_model")
        values["routing"] = _observed(
            RoutingObservation(
                kind="model_reroute",
                requested_model=None,
                requested_effort=None,
                tool=None,
                status=None,
                from_model=event.from_model,
                to_model=event.to_model,
            ),
            "provider_model_reroute",
        )
    elif isinstance(event, ThreadTokenUsageUpdated):
        kind = "thread_token_usage_updated"
        _set_thread(values, event.thread_id)
        _set_turn(values, event.turn_id)
        sample = RawCumulativeTokenSample(
            total=_token_vector(event.total),
            last=_token_vector(event.last),
            model_context_window=event.model_context_window,
        )
    else:
        raise AssertionError("pinned Codex event was not normalized")
    return NormalizedTelemetry(
        provider="codex",
        source_class="codex_app_server",
        parser_id="codex_adapter",
        parser_version="v1",
        parse_outcome="normalized",
        normalized_kind=kind,
        raw_sha256=event.raw_sha256,
        raw_size_bytes=event.raw_size_bytes,
        facts=_complete_facts(values),
        provider_native_relation=relation,
        raw_cumulative_tokens=sample,
    )


def _persistence_text(value: str | None) -> bool:
    if value is None:
        return True
    if not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8", "strict")) <= MAX_SHORT_TEXT_BYTES
    except UnicodeEncodeError:
        return False


def _persistence_compatible(normalized: NormalizedTelemetry) -> bool:
    """Return whether normalized facts fit the strict immutable receipt wire."""

    for fact in normalized.facts.values():
        value = fact.value
        if isinstance(value, str) and not _persistence_text(value):
            return False
        if isinstance(value, RoutingObservation):
            routing_values = (
                value.requested_model,
                value.requested_effort,
                value.tool,
                value.status,
                value.from_model,
                value.to_model,
            )
            if not all(_persistence_text(member) for member in routing_values):
                return False

    relation = normalized.provider_native_relation
    relation_text = (
        relation.sender_thread_id,
        relation.child_thread_id,
        relation.agent_path,
        relation.activity_kind,
        *relation.receiver_thread_ids,
    )
    if not all(_persistence_text(member) for member in relation_text):
        return False
    if len(relation.receiver_thread_ids) > 64:
        return False
    if (
        relation.kind == "collab_request"
        and not relation.receiver_thread_ids
    ):
        return False
    if len(relation.receiver_thread_ids) != len(set(relation.receiver_thread_ids)):
        return False
    if relation.receiver_thread_ids != tuple(sorted(relation.receiver_thread_ids)):
        return False
    if (
        relation.native_depth is not None
        and not 0 <= relation.native_depth <= MAX_EXECUTION_DEPTH
    ):
        return False
    sample = normalized.raw_cumulative_tokens
    if (
        sample is not None
        and sample.model_context_window is not None
        and sample.model_context_window > 999_999_999_999
    ):
        return False
    return True


def _persistence_ready_or_unsupported(
    normalized: NormalizedTelemetry,
    raw: bytes,
) -> NormalizedTelemetry:
    if _persistence_compatible(normalized):
        return normalized
    return _unsupported(
        provider=normalized.provider,
        source_class=normalized.source_class,
        parser_id=normalized.parser_id,
        raw=raw,
        reason="persistence_bounds_exceeded",
    )


def normalize_codex_telemetry(raw: bytes) -> NormalizedTelemetry:
    """Normalize one Codex notification without persistence or AOI joins."""

    if type(raw) is not bytes:
        raise TypeError("raw must be bytes")
    _bounded_raw(raw)
    try:
        return _persistence_ready_or_unsupported(
            _normalize_codex_observation(raw),
            raw,
        )
    except UnsupportedCodexNotification:
        return _unsupported(
            provider="codex", source_class="codex_app_server",
            parser_id="codex_adapter", raw=raw,
        )
    except CodexAdapterError:
        return _malformed(
            provider="codex", source_class="codex_app_server",
            parser_id="codex_adapter", raw=raw,
        )


def _translate_claude_fact(value: ClaudeFact[Any], *, reason: str) -> TelemetryFact:
    if value.quality == "observed":
        if value.value is None:
            raise AssertionError("observed Claude fact lacks a value")
        return _observed(value.value, reason)
    if value.quality == "missing":
        return _missing(reason)
    return _unavailable(reason)


def _normalize_claude_event(event: ClaudeTelemetryEvent) -> NormalizedTelemetry:
    values = _base_facts("provider_field_not_present")
    if event.event_kind == "unsupported":
        raise AssertionError("unsupported Claude event must bypass semantic normalization")
    values["session_id"] = _translate_claude_fact(event.session_id, reason="provider_session_id")
    values["agent_id"] = _translate_claude_fact(event.agent_id, reason="provider_agent_id")
    values["actual_role"] = _translate_claude_fact(
        event.agent_type, reason="provider_agent_type_not_aoi_role",
    )
    kind = "subagent_start_runtime_observed" if event.event_kind == "subagent_start" else "stop_runtime_observed"
    return NormalizedTelemetry(
        provider="claude",
        source_class=event.source_class,
        parser_id="claude_adapter",
        parser_version="v1",
        parse_outcome="normalized",
        normalized_kind=kind,
        raw_sha256=event.raw_sha256,
        raw_size_bytes=event.raw_size_bytes,
        facts=_complete_facts(values),
        provider_native_relation=_no_native_relation(
            "provider_relation_not_present",
        ),
        raw_cumulative_tokens=None,
    )


def normalize_claude_telemetry(
    raw: bytes, source_class: Literal["claude_hook", "otel"],
) -> NormalizedTelemetry:
    """Normalize one Claude payload without inventing OTel or hook semantics."""

    if type(raw) is not bytes:
        raise TypeError("raw must be bytes")
    _bounded_raw(raw)
    if source_class not in {"claude_hook", "otel"}:
        raise ValueError("source_class must be 'claude_hook' or 'otel'")
    try:
        event = parse_claude_telemetry(raw, source_class=source_class)
    except ClaudeTelemetryParseError:
        return _malformed(
            provider="claude", source_class=source_class,
            parser_id="claude_adapter", raw=raw,
        )
    if event.event_kind == "unsupported":
        return _unsupported(
            provider="claude", source_class=source_class,
            parser_id="claude_adapter", raw=raw,
        )
    return _persistence_ready_or_unsupported(
        _normalize_claude_event(event),
        raw,
    )


def _routing_payload(value: RoutingObservation) -> dict[str, object | None]:
    return {
        "kind": value.kind,
        "requested_model": value.requested_model,
        "requested_effort": value.requested_effort,
        "tool": value.tool,
        "status": value.status,
        "from_model": value.from_model,
        "to_model": value.to_model,
    }


def telemetry_facts_payload(
    normalized: NormalizedTelemetry,
) -> dict[str, dict[str, object | None]]:
    """Convert frozen normalized facts to the strict persistence wire shape."""

    result: dict[str, dict[str, object | None]] = {}
    for name, fact in normalized.facts.items():
        value = fact.value
        if isinstance(value, RoutingObservation):
            value = _routing_payload(value)
        result[name] = {
            "value": value,
            "source": fact.source,
            "quality": fact.quality,
            "reason": fact.reason,
        }
    return result


def provider_native_relation_payload(
    normalized: NormalizedTelemetry,
) -> dict[str, object | None]:
    """Return a JSON-compatible provider-native relation without AOI authority."""

    relation = normalized.provider_native_relation
    return {
        "kind": relation.kind,
        "sender_thread_id": relation.sender_thread_id,
        "receiver_thread_ids": list(relation.receiver_thread_ids),
        "child_thread_id": relation.child_thread_id,
        "agent_path": relation.agent_path,
        "activity_kind": relation.activity_kind,
        "native_depth": relation.native_depth,
        "reason": relation.reason,
    }


__all__ = [
    "FactName",
    "FactQuality",
    "FactSource",
    "NormalizedTelemetry",
    "ParseOutcome",
    "ProviderNativeRelation",
    "RawCumulativeTokenSample",
    "RawTokenVector",
    "RoutingObservation",
    "TelemetryFact",
    "TelemetryIntakeRejected",
    "TelemetrySourceClass",
    "normalize_claude_telemetry",
    "normalize_codex_telemetry",
    "provider_native_relation_payload",
    "telemetry_facts_payload",
]
