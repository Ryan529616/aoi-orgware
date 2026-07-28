"""Focused contract tests for authority-free telemetry normalization."""

from __future__ import annotations

import hashlib
import json

import pytest

from aoi_orgware.company.telemetry import (
    NormalizedTelemetry,
    RawCumulativeTokenSample,
    RoutingObservation,
    normalize_claude_telemetry,
    normalize_codex_telemetry,
)


def _codex(method: str, params: object) -> bytes:
    return json.dumps({"method": method, "params": params}, separators=(",", ":")).encode()


def _thread(*, waiting: bool = False, source: object = "cli") -> dict[str, object]:
    return {
        "cliVersion": "0.145.0",
        "createdAt": 1,
        "cwd": "C:/work",
        "ephemeral": False,
        "id": "thread-1",
        "modelProvider": "openai",
        "preview": "redacted",
        "sessionId": "session-1",
        "source": source,
        "status": {
            "type": "active",
            "activeFlags": ["waitingOnUserInput"] if waiting else [],
        },
        "turns": [],
        "updatedAt": 2,
    }


def _turn(status: str = "inProgress") -> dict[str, object]:
    return {"id": "turn-1", "items": [], "status": status}


def _tokens() -> dict[str, object]:
    return {
        "total": {
            "inputTokens": 20,
            "cachedInputTokens": 4,
            "cacheWriteInputTokens": 3,
            "outputTokens": 10,
            "reasoningOutputTokens": 8,
            "totalTokens": 42,
        },
        "last": {
            "inputTokens": 2,
            "cachedInputTokens": 1,
            "outputTokens": 1,
            "reasoningOutputTokens": 0,
            "totalTokens": 4,
        },
        "modelContextWindow": 128000,
    }


def _all_facts_uncompleted(result: NormalizedTelemetry) -> None:
    assert result.facts["engineering_completion"].value is None
    assert result.facts["engineering_completion"].quality == "unavailable"
    assert result.facts["engineering_completion"].reason == "engineering_completion_unavailable"


def test_codex_all_supported_classes_normalize_without_authority() -> None:
    thread_raw = _codex("thread/started", {"thread": _thread()})
    thread = normalize_codex_telemetry(thread_raw)
    assert thread.parse_outcome == "normalized"
    assert thread.normalized_kind == "thread_started"
    assert thread.raw_sha256 == hashlib.sha256(thread_raw).hexdigest()
    assert set(thread.facts) == {
        "actual_provider", "actual_model", "actual_effort", "actual_role", "routing",
        "session_id", "thread_id", "turn_id", "agent_id", "parent_thread_id",
        "event_time", "engineering_completion",
    }
    assert thread.facts["actual_provider"].value == "openai"
    assert thread.facts["session_id"].value == "session-1"
    assert thread.facts["thread_id"].value == "thread-1"
    assert thread.facts["event_time"].value == 2

    status = normalize_codex_telemetry(
        _codex("thread/status/changed", {"threadId": "thread-1", "status": {"type": "idle"}})
    )
    assert status.normalized_kind == "thread_status_changed"

    started_turn = _turn()
    started_turn["startedAt"] = 10
    turn_started = normalize_codex_telemetry(
        _codex("turn/started", {"threadId": "thread-1", "turn": started_turn})
    )
    assert turn_started.normalized_kind == "turn_started_runtime_observed"
    assert turn_started.facts["turn_id"].value == "turn-1"
    assert turn_started.facts["event_time"].value == 10

    completed_turn = _turn("completed")
    completed_turn["completedAt"] = 11
    turn_completed = normalize_codex_telemetry(
        _codex("turn/completed", {"threadId": "thread-1", "turn": completed_turn})
    )
    assert turn_completed.normalized_kind == "turn_completed_runtime_observed"
    assert turn_completed.facts["event_time"].value == 11

    collab = {
        "agentsStates": {}, "id": "item-1", "receiverThreadIds": ["child"],
        "senderThreadId": "thread-1", "status": "completed", "tool": "spawnAgent",
        "type": "collabAgentToolCall", "model": "gpt-5", "reasoningEffort": "high",
    }
    item_started = normalize_codex_telemetry(
        _codex("item/started", {"threadId": "thread-1", "turnId": "turn-1", "startedAtMs": 12, "item": collab})
    )
    assert item_started.normalized_kind == "item_started_runtime_observed"
    assert isinstance(item_started.facts["routing"].value, RoutingObservation)
    assert item_started.facts["routing"].value.requested_model == "gpt-5"

    activity = {"agentPath": "native/path", "agentThreadId": "child", "id": "item-2", "kind": "started", "type": "subAgentActivity"}
    item_completed = normalize_codex_telemetry(
        _codex("item/completed", {"threadId": "thread-1", "turnId": "turn-1", "completedAtMs": 13, "item": activity})
    )
    assert item_completed.normalized_kind == "item_completed_runtime_observed"
    assert item_completed.facts["agent_id"].value is None
    assert item_completed.facts["agent_id"].quality == "unavailable"
    assert (
        item_completed.facts["agent_id"].reason
        == "native_subagent_activity_not_aoi_agent_id"
    )
    assert item_completed.facts["parent_thread_id"].value is None
    assert item_completed.provider_native_relation.kind == "subagent_activity"
    assert item_completed.provider_native_relation.child_thread_id == "child"

    rerouted = normalize_codex_telemetry(
        _codex("model/rerouted", {"threadId": "thread-1", "turnId": "turn-1", "fromModel": "gpt-5", "toModel": "gpt-5-safe", "reason": "highRiskCyberActivity"})
    )
    assert rerouted.normalized_kind == "model_rerouted_runtime_observed"
    assert rerouted.facts["actual_model"].value == "gpt-5-safe"
    assert rerouted.facts["actual_effort"].value is None

    usage = normalize_codex_telemetry(
        _codex("thread/tokenUsage/updated", {"threadId": "thread-1", "turnId": "turn-1", "tokenUsage": _tokens()})
    )
    assert usage.normalized_kind == "thread_token_usage_updated"
    assert isinstance(usage.raw_cumulative_tokens, RawCumulativeTokenSample)
    assert usage.raw_cumulative_tokens.total.cache_creation == 3
    assert usage.raw_cumulative_tokens.last.cache_creation is None
    assert usage.raw_cumulative_tokens.last.total == 4
    assert usage.raw_cumulative_tokens.model_context_window == 128000
    for result in (thread, status, turn_started, turn_completed, item_started, item_completed, rerouted, usage):
        _all_facts_uncompleted(result)


def test_waiting_and_native_parent_are_explicitly_not_aoi_lineage() -> None:
    source = {"subAgent": {"thread_spawn": {"parent_thread_id": "native-parent", "depth": 2}}}
    result = normalize_codex_telemetry(_codex("thread/started", {"thread": _thread(waiting=True, source=source)}))
    assert result.normalized_kind == "thread_waiting_on_user_input"
    assert result.facts["parent_thread_id"].value == "native-parent"
    assert result.facts["parent_thread_id"].source == "provider_payload"
    assert result.facts["parent_thread_id"].reason == "native_parent_not_aoi_lineage"
    assert result.facts["agent_id"].value is None
    assert result.provider_native_relation.kind == "thread_spawn"
    assert result.provider_native_relation.sender_thread_id == "native-parent"
    assert result.provider_native_relation.child_thread_id == "thread-1"


def test_codex_unsupported_and_malformed_are_preserved_without_error_text() -> None:
    unsupported_raw = _codex("future/event", {"x": 1})
    unsupported = normalize_codex_telemetry(unsupported_raw)
    assert unsupported.parse_outcome == "unsupported_valid"
    assert unsupported.normalized_kind == "unsupported"
    assert unsupported.raw_sha256 == hashlib.sha256(unsupported_raw).hexdigest()
    assert unsupported.facts["thread_id"].reason == "parser_unsupported_valid"
    assert unsupported.facts["thread_id"].source == "none"

    malformed = normalize_codex_telemetry(b"{")
    assert malformed.parse_outcome == "malformed"
    assert malformed.normalized_kind == "malformed"
    assert malformed.facts["thread_id"].reason == "parser_malformed"
    with pytest.raises(TypeError):
        normalize_codex_telemetry(bytearray(b"{}"))  # type: ignore[arg-type]


def test_claude_start_stop_unsupported_otel_and_malformed_are_honest() -> None:
    start_raw = json.dumps({"hook_event_name": "SubagentStart", "session_id": "session-1", "agent_id": "child-1", "agent_type": "reviewer"}, separators=(",", ":")).encode()
    start = normalize_claude_telemetry(start_raw, "claude_hook")
    assert start.parse_outcome == "normalized"
    assert start.normalized_kind == "subagent_start_runtime_observed"
    assert start.facts["session_id"].value == "session-1"
    assert start.facts["agent_id"].value == "child-1"
    assert start.facts["actual_role"].value == "reviewer"
    assert start.raw_cumulative_tokens is None

    stop = normalize_claude_telemetry(
        json.dumps({"hook_event_name": "Stop", "session_id": "session-1"}).encode(), "claude_hook"
    )
    assert stop.normalized_kind == "stop_runtime_observed"
    _all_facts_uncompleted(stop)

    unsupported = normalize_claude_telemetry(
        json.dumps({"hook_event_name": "SubagentStop"}).encode(), "claude_hook"
    )
    assert unsupported.parse_outcome == "unsupported_valid"
    assert unsupported.facts["actual_model"].reason == "parser_unsupported_valid"

    otel_raw = json.dumps({"resourceSpans": []}).encode()
    otel = normalize_claude_telemetry(otel_raw, "otel")
    assert otel.parse_outcome == "unsupported_valid"
    assert otel.source_class == "otel"
    assert otel.raw_sha256 == hashlib.sha256(otel_raw).hexdigest()

    malformed = normalize_claude_telemetry(b"{", "claude_hook")
    assert malformed.parse_outcome == "malformed"
    assert malformed.facts["actual_provider"].value is None
    assert malformed.raw_cumulative_tokens is None
    with pytest.raises(TypeError):
        normalize_claude_telemetry(bytearray(b"{}"), "claude_hook")  # type: ignore[arg-type]
