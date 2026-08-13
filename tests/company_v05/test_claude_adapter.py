"""Contract tests for the v0.5 pure Claude telemetry parser."""

from __future__ import annotations

import hashlib
import json

from aoi_orgware.company.claude_adapter import (
    ClaudeTelemetryParseError,
    MAX_RAW_BYTES,
    parse_claude_telemetry,
)


def raw(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def test_subagent_start_retains_exact_native_facts_and_raw_identity() -> None:
    payload = raw(
        {
            "hook_event_name": "SubagentStart",
            "session_id": "parent-session",
            "prompt_id": "prompt-7",
            "agent_id": "native-child",
            "agent_type": "general-purpose",
            "permission_mode": "default",
        }
    )
    event = parse_claude_telemetry(payload, source_class="claude_hook")

    assert event.event_kind == "subagent_start"
    assert event.raw_sha256 == hashlib.sha256(payload).hexdigest()
    assert event.raw_size_bytes == len(payload)
    assert event.raw_identity == f"claude_hook:{event.raw_sha256}"
    assert event.provenance == "unknown"
    assert event.source_detail == "claude_hook_raw_observed"
    assert event.provider.value == "claude"
    assert event.provider.quality == "unavailable"
    assert event.session_id.value == "parent-session"
    assert event.parent_session_id.value is None
    assert event.parent_session_id.quality == "unavailable"
    assert event.prompt_id.value == "prompt-7"
    assert event.turn_id.value is None
    assert event.turn_id.quality == "unavailable"
    assert event.agent_id.value == "native-child"
    assert event.agent_type.value == "general-purpose"
    assert event.tool_name.quality == "unavailable"
    assert event.timestamp.quality == "unavailable"
    assert event.usage_total_tokens.quality == "unavailable"


def test_missing_native_fields_are_not_zero_or_inferred() -> None:
    event = parse_claude_telemetry(
        raw({"hook_event_name": "SubagentStart", "session_id": "parent"}),
        source_class="claude_hook",
    )

    assert event.prompt_id.value is None and event.prompt_id.quality == "missing"
    assert event.turn_id.value is None and event.turn_id.quality == "unavailable"
    assert event.agent_id.value is None and event.agent_id.quality == "missing"
    assert event.usage_input_tokens.value is None
    assert event.usage_input_tokens.quality == "unavailable"
    assert event.parent_session_id.value is None
    assert event.parent_session_id.quality == "unavailable"


def test_stop_is_runtime_observation_not_engineering_completion() -> None:
    event = parse_claude_telemetry(
        raw({"hook_event_name": "Stop", "session_id": "chief", "stop_hook_active": False}),
        source_class="claude_hook",
    )

    assert event.event_kind == "stop_observed"
    assert event.lifecycle.value == "runtime_stop_observed"
    assert event.engineering_completion.value is None
    assert event.engineering_completion.quality == "unavailable"
    assert event.parent_session_id.quality == "unavailable"


def test_unregistered_events_are_typed_unsupported() -> None:
    for name in ("SubagentStop", "StopFailure", "FutureEvent"):
        event = parse_claude_telemetry(
            raw({"hook_event_name": name, "session_id": "ignored"}),
            source_class="claude_hook",
        )

        assert event.event_kind == "unsupported"
        assert event.lifecycle.quality == "unavailable"
        assert "not registered" in event.lifecycle.reason


def test_registered_but_unmapped_events_are_not_misreported() -> None:
    for name in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        event = parse_claude_telemetry(
            raw({"hook_event_name": name}),
            source_class="claude_hook",
        )
        assert event.event_kind == "unsupported"
        assert "registered but not mapped" in event.lifecycle.reason


def test_otel_is_bounded_but_custom_mapping_remains_unavailable() -> None:
    event = parse_claude_telemetry(
        raw(
            {
                "resourceSpans": [
                    {"scopeSpans": [{"spans": [{"name": "SubagentStart", "attributes": []}]}]}
                ]
            }
        ),
        source_class="otel",
    )

    assert event.event_kind == "unsupported"
    assert event.session_id.quality == "unavailable"
    assert event.usage_total_tokens.quality == "unavailable"
    assert "no local OTel schema" in event.lifecycle.reason


def test_duplicate_raw_bytes_have_identical_digest_identity() -> None:
    payload = raw({"hook_event_name": "Stop", "session_id": "same"})
    first = parse_claude_telemetry(payload, source_class="claude_hook")
    second = parse_claude_telemetry(payload, source_class="claude_hook")

    assert first.raw_sha256 == second.raw_sha256
    assert first.raw_identity == second.raw_identity


def test_malformed_or_deep_payloads_fail_closed() -> None:
    payloads = (
        b"{",  # malformed
        b'{"hook_event_name":"Stop"} trailing',  # trailing
        b"\xff",  # non-UTF-8
        b'{"hook_event_name":"Stop","bad":NaN}',
        b'{"hook_event_name":"Stop","bad":Infinity}',
        b'{"hook_event_name":"Stop","hook_event_name":"SubagentStart"}',
        b'{"hook_event_name":"\\ud800"}',
        (
            b'{"hook_event_name":"Stop","bad":'
            + b"9" * 4301
            + b"}"
        ),
        raw({"hook_event_name": "Stop", "session_id": ["wrong-type"]}),
        b'{"hook_event_name":"Stop","nested":' + b'{"x":' * 17 + b"0" + b"}" * 17 + b"}",
    )
    for payload in payloads:
        try:
            parse_claude_telemetry(payload, source_class="claude_hook")
        except ClaudeTelemetryParseError:
            continue
        raise AssertionError("malformed telemetry payload was accepted")


def test_oversized_payload_fails_closed() -> None:
    try:
        parse_claude_telemetry(b"x" * (MAX_RAW_BYTES + 1), source_class="claude_hook")
    except ClaudeTelemetryParseError:
        return
    raise AssertionError("oversized telemetry payload was accepted")


def test_native_identity_hygiene_fails_closed() -> None:
    for key in ("session_id", "prompt_id", "agent_id"):
        for value in ("\x00bad", "\tbad", "   ", "bad id"):
            try:
                parse_claude_telemetry(
                    raw({
                        "hook_event_name": "SubagentStart",
                        key: value,
                    }),
                    source_class="claude_hook",
                )
            except ClaudeTelemetryParseError:
                continue
            raise AssertionError(
                f"invalid native identity was accepted: {key}",
            )
