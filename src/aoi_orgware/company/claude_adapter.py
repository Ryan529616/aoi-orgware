"""Pure, bounded parsing of Claude lifecycle telemetry for AOI v0.5.

This is deliberately an intake-only adapter.  It neither writes state nor
attributes cost, deltas, parentage, completion, or time windows.  The local
matcher registers several hooks, but this parser currently maps only
``SubagentStart`` and ``Stop``.  Other registered hooks are returned as typed
unsupported observations rather than guessed.  In particular,
``SubagentStop`` and ``StopFailure`` are not registered by that matcher.

No local OpenTelemetry schema was available when this module was added.  OTel
JSON is therefore bounded and decoded, but deliberately returned as typed
``unsupported`` rather than guessed from attribute names.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Generic, Literal, TypeVar


MAX_RAW_BYTES = 64 * 1024
MAX_JSON_DEPTH = 16
MAX_COLLECTION_ENTRIES = 128
MAX_STRING_BYTES = 8 * 1024
_NATIVE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_REGISTERED_BUT_UNMAPPED = frozenset({
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
})

SourceClass = Literal["claude_hook", "otel"]
EventKind = Literal["subagent_start", "stop_observed", "unsupported"]
FactQuality = Literal["observed", "missing", "unavailable"]
_T = TypeVar("_T")


class ClaudeTelemetryParseError(ValueError):
    """Raw telemetry bytes are not within this adapter's bounded JSON contract."""


@dataclass(frozen=True)
class TelemetryFact(Generic[_T]):
    """A fact and why it is present, absent, or intentionally unavailable."""

    value: _T | None
    quality: FactQuality
    reason: str


@dataclass(frozen=True)
class ClaudeTelemetryEvent:
    """One immutable, non-attributing observation of raw provider telemetry."""

    raw_sha256: str
    raw_size_bytes: int
    source_class: SourceClass
    provenance: str
    source_detail: str
    event_kind: EventKind
    lifecycle: TelemetryFact[str]
    provider: TelemetryFact[str]
    session_id: TelemetryFact[str]
    parent_session_id: TelemetryFact[str]
    prompt_id: TelemetryFact[str]
    turn_id: TelemetryFact[str]
    agent_id: TelemetryFact[str]
    agent_type: TelemetryFact[str]
    tool_name: TelemetryFact[str]
    timestamp: TelemetryFact[str]
    usage_input_tokens: TelemetryFact[int]
    usage_output_tokens: TelemetryFact[int]
    usage_total_tokens: TelemetryFact[int]
    engineering_completion: TelemetryFact[bool]

    @property
    def raw_identity(self) -> str:
        """Stable duplicate identity: the source class and exact raw bytes."""

        return f"{self.source_class}:{self.raw_sha256}"


def _missing(reason: str) -> TelemetryFact[Any]:
    return TelemetryFact(value=None, quality="missing", reason=reason)


def _unavailable(reason: str) -> TelemetryFact[Any]:
    return TelemetryFact(value=None, quality="unavailable", reason=reason)


def _observed(value: _T, reason: str) -> TelemetryFact[_T]:
    return TelemetryFact(value=value, quality="observed", reason=reason)


def _bounded_raw(raw: bytes | bytearray | memoryview) -> bytes:
    if isinstance(raw, bytes):
        value = raw
    elif isinstance(raw, bytearray):
        value = bytes(raw)
    elif isinstance(raw, memoryview):
        value = raw.tobytes()
    else:
        raise TypeError("Claude telemetry input must be raw bytes")
    if len(value) > MAX_RAW_BYTES:
        raise ClaudeTelemetryParseError("Claude telemetry payload exceeds byte bound")
    return value


def _validate_json(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ClaudeTelemetryParseError("Claude telemetry JSON exceeds depth bound")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ClaudeTelemetryParseError(
                "Claude telemetry JSON contains a non-finite number",
            )
        return
    if isinstance(value, str):
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ClaudeTelemetryParseError(
                "Claude telemetry string contains invalid Unicode",
            ) from exc
        if size > MAX_STRING_BYTES:
            raise ClaudeTelemetryParseError("Claude telemetry string exceeds byte bound")
        return
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ENTRIES:
            raise ClaudeTelemetryParseError("Claude telemetry object exceeds entry bound")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ClaudeTelemetryParseError("Claude telemetry object key is invalid")
            try:
                key_size = len(key.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ClaudeTelemetryParseError(
                    "Claude telemetry object key contains invalid Unicode",
                ) from exc
            if key_size > MAX_STRING_BYTES:
                raise ClaudeTelemetryParseError("Claude telemetry object key exceeds byte bound")
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ENTRIES:
            raise ClaudeTelemetryParseError("Claude telemetry array exceeds entry bound")
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    raise ClaudeTelemetryParseError("Claude telemetry JSON contains an unsupported value")


def _unique_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClaudeTelemetryParseError(
                "Claude telemetry object contains a duplicate key",
            )
        result[key] = value
    return result


def _bounded_integer(text: str) -> int:
    digits = text.removeprefix("-")
    if len(digits) > 19:
        raise ClaudeTelemetryParseError(
            "Claude telemetry integer exceeds int64 range",
        )
    try:
        value = int(text)
    except ValueError as exc:
        raise ClaudeTelemetryParseError(
            "Claude telemetry integer is invalid",
        ) from exc
    if value < -(2**63) or value > 2**63 - 1:
        raise ClaudeTelemetryParseError(
            "Claude telemetry integer exceeds int64 range",
        )
    return value


def _reject_constant(value: str) -> float:
    raise ClaudeTelemetryParseError(
        f"Claude telemetry contains invalid numeric constant {value}",
    )


def _decode_object(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ClaudeTelemetryParseError("Claude telemetry is not UTF-8") from exc
    try:
        value, end = json.JSONDecoder(
            object_pairs_hook=_unique_object,
            parse_int=_bounded_integer,
            parse_constant=_reject_constant,
        ).raw_decode(text)
    except ClaudeTelemetryParseError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ClaudeTelemetryParseError("Claude telemetry is not one JSON value") from exc
    if end != len(text):
        raise ClaudeTelemetryParseError("Claude telemetry has trailing data")
    if not isinstance(value, dict):
        raise ClaudeTelemetryParseError("Claude telemetry root must be a JSON object")
    _validate_json(value)
    return value


def _optional_string(payload: dict[str, Any], key: str) -> TelemetryFact[str]:
    if key not in payload:
        return _missing(f"hook payload does not contain {key}")
    value = payload[key]
    if not isinstance(value, str):
        raise ClaudeTelemetryParseError(f"hook payload field {key} must be a string")
    if not value.strip():
        raise ClaudeTelemetryParseError(
            f"hook payload field {key} must not be empty",
        )
    if any(ord(character) < 0x20 for character in value):
        raise ClaudeTelemetryParseError(
            f"hook payload field {key} contains a control character",
        )
    return _observed(value, f"hook payload {key}")


def _optional_id(payload: dict[str, Any], key: str) -> TelemetryFact[str]:
    result = _optional_string(payload, key)
    if result.value is not None and _NATIVE_ID.fullmatch(result.value) is None:
        raise ClaudeTelemetryParseError(
            f"hook payload field {key} is not a canonical identifier",
        )
    return result


def _base_event(raw: bytes, source_class: SourceClass, event_kind: EventKind) -> dict[str, Any]:
    return {
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_size_bytes": len(raw),
        "source_class": source_class,
        "provenance": "unknown",
        "source_detail": (
            "claude_hook_raw_observed"
            if source_class == "claude_hook"
            else "otel_raw_schema_unproven"
        ),
        "event_kind": event_kind,
        "provider": TelemetryFact(
            value="claude",
            quality="unavailable",
            reason=(
                "adapter route is a caller hint, not independently proven "
                "provider origin"
            ),
        ),
        "tool_name": _unavailable("current lifecycle payload matcher exposes no tool name"),
        "timestamp": _unavailable("current lifecycle payload matcher exposes no timestamp"),
        "usage_input_tokens": _unavailable("current lifecycle payload matcher exposes no input-token field"),
        "usage_output_tokens": _unavailable("current lifecycle payload matcher exposes no output-token field"),
        "usage_total_tokens": _unavailable("current lifecycle payload matcher exposes no total-token field"),
        "engineering_completion": _unavailable("runtime lifecycle observation is not engineering completion evidence"),
    }


def _unsupported(raw: bytes, source_class: SourceClass, reason: str) -> ClaudeTelemetryEvent:
    values = _base_event(raw, source_class, "unsupported")
    unavailable = _unavailable(reason)
    return ClaudeTelemetryEvent(
        **values,
        lifecycle=unavailable,
        session_id=unavailable,
        parent_session_id=unavailable,
        prompt_id=unavailable,
        turn_id=unavailable,
        agent_id=unavailable,
        agent_type=unavailable,
    )


def parse_claude_telemetry(
    raw: bytes | bytearray | memoryview, *, source_class: SourceClass
) -> ClaudeTelemetryEvent:
    """Parse exact raw JSON bytes without filesystem, network, or state writes."""

    value = _bounded_raw(raw)
    payload = _decode_object(value)
    if source_class == "otel":
        return _unsupported(
            value,
            source_class,
            "no local OTel schema proves a Claude lifecycle/name/parent/token mapping",
        )
    if source_class != "claude_hook":
        raise ValueError("source_class must be 'claude_hook' or 'otel'")
    event = payload.get("hook_event_name")
    if not isinstance(event, str):
        raise ClaudeTelemetryParseError("hook payload hook_event_name must be a string")
    if event not in {"SubagentStart", "Stop"}:
        reason = (
            f"hook event {event!r} is registered but not mapped by "
            "the current parser"
            if event in _REGISTERED_BUT_UNMAPPED
            else (
                f"hook event {event!r} is not registered by the current "
                "Claude matcher"
            )
        )
        return _unsupported(
            value,
            source_class,
            reason,
        )
    values = _base_event(value, source_class, "subagent_start" if event == "SubagentStart" else "stop_observed")
    session = _optional_id(payload, "session_id")
    if event == "SubagentStart":
        return ClaudeTelemetryEvent(
            **values,
            lifecycle=_observed("runtime_subagent_start_observed", "hook event SubagentStart"),
            session_id=session,
            parent_session_id=_unavailable(
                "SubagentStart payload does not declare a parent session",
            ),
            prompt_id=_optional_id(payload, "prompt_id"),
            turn_id=_unavailable(
                "prompt_id is not evidence of a provider turn identifier",
            ),
            agent_id=_optional_id(payload, "agent_id"),
            agent_type=_optional_string(payload, "agent_type"),
        )
    return ClaudeTelemetryEvent(
        **values,
        lifecycle=_observed("runtime_stop_observed", "hook event Stop"),
        session_id=session,
        parent_session_id=_unavailable("Stop payload does not declare a parent session"),
        prompt_id=_unavailable("Stop payload matcher exposes no prompt identifier"),
        turn_id=_unavailable("Stop payload matcher exposes no turn identifier"),
        agent_id=_unavailable("Stop payload matcher exposes no agent identifier"),
        agent_type=_unavailable("Stop payload matcher exposes no agent type"),
    )
