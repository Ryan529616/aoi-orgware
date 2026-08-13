from __future__ import annotations

import hashlib
import json

import pytest

from aoi_orgware.company.codex_adapter import (
    CodexAdapterError,
    ItemCompleted,
    ItemStarted,
    MAX_RAW_NOTIFICATION_BYTES,
    ModelRerouted,
    ThreadStarted,
    ThreadTokenUsageUpdated,
    TurnCompleted,
    TurnStarted,
    UnsupportedCodexNotification,
    parse_codex_notification,
)


def _raw(method: str, params: object) -> bytes:
    return json.dumps({"method": method, "params": params}, separators=(",", ":")).encode("utf-8")


def _thread() -> dict[str, object]:
    return {
        "cliVersion": "0.145.0",
        "createdAt": 1,
        "cwd": "C:/work",
        "ephemeral": False,
        "id": "thread-1",
        "modelProvider": "openai",
        "forkedFromId": "fork-thread",
        "preview": "fixture",
        "sessionId": "session-1",
        "source": "cli",
        "status": {"type": "active", "activeFlags": ["waitingOnUserInput"]},
        "threadSource": "provider-analytics-source",
        "turns": [],
        "updatedAt": 2,
    }


def _turn(status: str = "inProgress") -> dict[str, object]:
    return {"id": "turn-1", "items": [], "status": status}


def _token_usage(total: int = 42) -> dict[str, object]:
    vector = {
        "inputTokens": 20,
        "cachedInputTokens": 4,
        "outputTokens": 10,
        "reasoningOutputTokens": 8,
        "totalTokens": total,
    }
    return {"last": dict(vector), "total": dict(vector), "modelContextWindow": 128000}


def test_schema_complete_lifecycle_and_native_collaboration_ids_are_preserved() -> None:
    raw = _raw("thread/started", {"thread": _thread()})
    started = parse_codex_notification(raw)
    assert isinstance(started, ThreadStarted)
    assert started.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert started.raw_size_bytes == len(raw)
    assert started.native_parent_thread_id is None
    assert started.native_forked_from_id == "fork-thread"
    assert started.native_thread_source == "provider-analytics-source"
    assert started.native_agent_role is None
    assert started.thread_status == "active"
    assert started.active_flags == ("waitingOnUserInput",)
    assert started.model_provider == "openai"
    assert started.created_at == 1
    assert started.updated_at == 2
    assert started.native_source.kind == "cli"

    started_turn = _turn()
    started_turn.update({"startedAt": 10, "completedAt": None, "durationMs": None})
    turn_started = parse_codex_notification(
        _raw("turn/started", {"threadId": "thread-1", "turn": started_turn})
    )
    completed_turn = _turn("inProgress")
    completed_turn.update({"startedAt": 10, "completedAt": 12, "durationMs": 2000})
    turn_completed = parse_codex_notification(
        _raw("turn/completed", {"threadId": "thread-1", "turn": completed_turn})
    )
    assert isinstance(turn_started, TurnStarted)
    assert isinstance(turn_completed, TurnCompleted)
    assert turn_started.started_at == 10
    assert turn_started.completed_at is None
    assert turn_completed.turn_status == "inProgress"
    assert turn_completed.completed_at == 12
    assert turn_completed.duration_ms == 2000

    collab = {
        "agentsStates": {},
        "id": "item-collab",
        "receiverThreadIds": ["thread-child"],
        "senderThreadId": "thread-1",
        "status": "completed",
        "tool": "spawnAgent",
        "type": "collabAgentToolCall",
        "model": "gpt-5",
        "reasoningEffort": "high",
    }
    item_started = parse_codex_notification(
        _raw("item/started", {"threadId": "thread-1", "turnId": "turn-1", "startedAtMs": 3, "item": collab})
    )
    assert isinstance(item_started, ItemStarted)
    assert item_started.collab_agent_tool_call is not None
    assert item_started.collab_agent_tool_call.receiver_thread_ids == ("thread-child",)
    assert item_started.collab_agent_tool_call.requested_model == "gpt-5"
    assert item_started.collab_agent_tool_call.requested_effort == "high"
    assert item_started.subagent_activity is None

    activity = {"agentPath": "agent-1", "agentThreadId": "thread-child", "id": "item-activity", "kind": "started", "type": "subAgentActivity"}
    item_completed = parse_codex_notification(
        _raw("item/completed", {"threadId": "thread-1", "turnId": "turn-1", "completedAtMs": 4, "item": activity})
    )
    assert isinstance(item_completed, ItemCompleted)
    assert item_completed.subagent_activity is not None
    assert item_completed.subagent_activity.agent_thread_id == "thread-child"


def test_thread_spawn_source_is_native_metadata_not_inferred_parentage() -> None:
    thread = _thread()
    thread["source"] = {
        "subAgent": {
            "thread_spawn": {
                "parent_thread_id": "source-parent",
                "depth": 2,
                "agent_nickname": "spruce",
                "agent_path": "root/spawn",
                "agent_role": "reviewer",
            }
        }
    }
    parsed = parse_codex_notification(_raw("thread/started", {"thread": thread}))
    assert isinstance(parsed, ThreadStarted)
    assert parsed.native_parent_thread_id is None
    assert parsed.native_source.kind == "subAgent"
    assert parsed.native_source.thread_spawn is not None
    assert parsed.native_source.thread_spawn.parent_thread_id == "source-parent"
    assert parsed.native_source.thread_spawn.depth == 2
    assert parsed.native_source.thread_spawn.agent_nickname == "spruce"
    assert parsed.native_source.thread_spawn.agent_path == "root/spawn"
    assert parsed.native_source.thread_spawn.agent_role == "reviewer"

    thread["parentThreadId"] = "conflicting-parent"
    with pytest.raises(CodexAdapterError, match="parent sources diverge"):
        parse_codex_notification(_raw("thread/started", {"thread": thread}))


def test_schema_proven_model_reroute_and_complete_cumulative_token_vector() -> None:
    reroute = parse_codex_notification(
        _raw("model/rerouted", {"threadId": "thread-1", "turnId": "turn-1", "fromModel": "gpt-5", "toModel": "gpt-5-safe", "reason": "highRiskCyberActivity"})
    )
    assert isinstance(reroute, ModelRerouted)
    assert reroute.to_model == "gpt-5-safe"

    raw = _raw("thread/tokenUsage/updated", {"threadId": "thread-1", "turnId": "turn-1", "tokenUsage": _token_usage()})
    update = parse_codex_notification(raw)
    assert isinstance(update, ThreadTokenUsageUpdated)
    assert update.total.input_tokens == 20
    assert update.total.cached_input_tokens == 4
    assert update.total.output_tokens == 10
    assert update.total.reasoning_output_tokens == 8
    assert update.total.total_tokens == 42
    assert update.total.cache_write_input_tokens is None


def test_repeated_cumulative_token_updates_are_raw_facts_not_summed() -> None:
    raw = _raw("thread/tokenUsage/updated", {"threadId": "thread-1", "turnId": "turn-1", "tokenUsage": _token_usage(42)})
    first = parse_codex_notification(raw)
    second = parse_codex_notification(raw)
    assert isinstance(first, ThreadTokenUsageUpdated)
    assert isinstance(second, ThreadTokenUsageUpdated)
    assert first.total == second.total
    assert first.total.total_tokens == 42
    assert first.raw_sha256 == second.raw_sha256


@pytest.mark.parametrize(
    "raw",
    [
        b'{"method":"thread/started","params":{"thread":{}}} trailing',
        _raw("thread/started", {"thread": _thread()}) + b"\n",
        b'\xff',
        b'{"method":"thread/started","method":"turn/started","params":{}}',
        b'{"method":"thread/started","params":' + b"[" * 33 + b"]" * 33 + b"}",
        # Exact intentionally incomplete notification currently used by the
        # legacy app-server stdio fake; it is not a v0.145.0 token schema.
        b'{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":{"totalTokens":1}}}',
    ],
)
def test_malformed_or_old_incomplete_token_fixtures_fail_closed(raw: bytes) -> None:
    with pytest.raises(CodexAdapterError):
        parse_codex_notification(raw)


def test_oversized_and_unknown_notifications_are_not_fabricated_events() -> None:
    with pytest.raises(CodexAdapterError):
        parse_codex_notification(b" " * (MAX_RAW_NOTIFICATION_BYTES + 1))
    raw = _raw("item/agentMessage/delta", {"threadId": "thread-1"})
    with pytest.raises(UnsupportedCodexNotification) as raised:
        parse_codex_notification(raw)
    assert raised.value.method == "item/agentMessage/delta"
    assert raised.value.raw_sha256 == hashlib.sha256(raw).hexdigest()


def test_identifiers_reject_nul() -> None:
    with pytest.raises(CodexAdapterError):
        parse_codex_notification(
            _raw("turn/started", {"threadId": "thread-\x00", "turn": _turn()})
        )


@pytest.mark.parametrize(
    "item",
    [
        {"id": "item-unknown", "type": "notInPinnedSubset"},
        {
            "agentsStates": {"thread-child": {"status": "running"}},
            "id": "item-collab",
            "receiverThreadIds": ["thread-child"],
            "senderThreadId": "thread-1",
            "status": "completed",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        },
        {
            "agentsStates": {},
            "id": "item-collab",
            "receiverThreadIds": ["thread-child"],
            "senderThreadId": "thread-1",
            "status": "completed",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
            "prompt": 1,
        },
    ],
)
def test_thread_items_outside_pinned_subset_or_shape_fail_closed(item: object) -> None:
    with pytest.raises(CodexAdapterError):
        parse_codex_notification(
            _raw(
                "item/started",
                {"threadId": "thread-1", "turnId": "turn-1", "startedAtMs": 3, "item": item},
            )
        )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"method":"turn/started","params":{"threadId":"\\ud800","turn":{"id":"turn-1","items":[],"status":"inProgress"}}}',
        b'{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-1","items":[],"status":"inProgress","startedAt":9223372036854775808}}}',
    ],
)
def test_lone_surrogate_and_out_of_range_json_integer_fail_closed(raw: bytes) -> None:
    with pytest.raises(CodexAdapterError):
        parse_codex_notification(raw)
