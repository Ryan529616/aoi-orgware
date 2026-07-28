from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    MAX_PROVIDER_TELEMETRY_RAW_BYTES,
    NEEDS_USER_ANSWER_MEDIA_TYPE,
    NEEDS_USER_QUESTION_MEDIA_TYPE,
    NEEDS_USER_REVISION_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RAW_MEDIA_TYPE,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    ZERO_SHA256,
    CompanyContractError,
    company_contract_sha256,
    validate_company_contract,
    validate_needs_user_revision,
    validate_provider_coverage_revision,
    validate_provider_telemetry_receipt,
    validate_usage_counter_sample,
)
from aoi_orgware.company.telemetry import (
    TelemetryIntakeRejected,
    normalize_claude_telemetry,
    normalize_codex_telemetry,
    provider_native_relation_payload,
    telemetry_facts_payload,
)


T = "2026-07-27T00:00:00Z"
T2 = "2026-07-27T00:00:01Z"
H = "a" * 64


def _blob(media_type: str, *, size: int = 12, sha256: str = H) -> dict[str, Any]:
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": sha256,
        "size_bytes": size,
        "media_type": media_type,
        "availability": "available",
    }


def _fact(*, value: object | None = None, source: str = "none", quality: str = "unavailable", reason: str = "not_exposed") -> dict[str, Any]:
    return {"value": value, "source": source, "quality": quality, "reason": reason}


def _facts() -> dict[str, dict[str, Any]]:
    names = (
        "actual_provider", "actual_model", "actual_effort", "actual_role", "routing",
        "session_id", "thread_id", "turn_id", "agent_id", "parent_thread_id",
        "event_time", "engineering_completion",
    )
    result = {name: _fact() for name in names}
    result["actual_provider"] = _fact(
        value="openai", source="provider_payload", quality="observed",
        reason="provider_model_provider",
    )
    result["session_id"] = _fact(
        value="session-1", source="provider_payload", quality="observed",
        reason="provider_session_id",
    )
    result["thread_id"] = _fact(
        value="thread-1", source="provider_payload", quality="observed",
        reason="provider_thread_id",
    )
    result["event_time"] = _fact(
        value=1_785_000_000_000, source="provider_payload",
        quality="observed", reason="provider_thread_updated_at",
    )
    return result


def _no_relation() -> dict[str, Any]:
    return {
        "kind": "none",
        "sender_thread_id": None,
        "receiver_thread_ids": [],
        "child_thread_id": None,
        "agent_path": None,
        "activity_kind": None,
        "native_depth": None,
        "reason": "provider_relation_not_present",
    }


def _join(*, state: str = "none") -> dict[str, Any]:
    if state == "exact":
        return {
            "state": "exact", "binding_kind": "dispatch", "registry_cursor": 2,
            "dispatch_request_id": "dispatch-1", "dispatch_revision_id": "dispatch-revision-1",
            "registration_id": None, "execution_id": "execution-1", "carrier_id": "carrier-1",
            "candidate_count": 1, "candidates_sha256": "b" * 64, "reason": "registry_exact",
        }
    if state == "ambiguous":
        return {
            "state": "ambiguous", "binding_kind": "none", "registry_cursor": 2,
            "dispatch_request_id": None, "dispatch_revision_id": None, "registration_id": None,
            "execution_id": None, "carrier_id": None, "candidate_count": 2,
            "candidates_sha256": "b" * 64, "reason": "multiple_candidates",
        }
    return {
        "state": "none", "binding_kind": "none", "registry_cursor": 2,
        "dispatch_request_id": None, "dispatch_revision_id": None, "registration_id": None,
        "execution_id": None, "carrier_id": None, "candidate_count": 0,
        "candidates_sha256": ZERO_SHA256, "reason": "no_registered_match",
    }


def _rehash(value: dict[str, Any], field: str) -> None:
    value[field] = company_contract_sha256({key: member for key, member in value.items() if key != field})


def _receipt() -> dict[str, Any]:
    value = {
        "contract_type": PROVIDER_TELEMETRY_RECEIPT_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1,
        "transaction_id": "transaction-1", "command_id": "command-1", "receipt_id": "receipt-1",
        "adapter_instance_id": "adapter-1", "adapter_event_id": "event-occurrence-1", "intake_sequence": 1,
        "provider": "codex", "source_class": "codex_app_server",
        "parser_id": "codex_adapter",
        "parser_version": "v1", "parse_outcome": "normalized", "normalized_kind": "thread_started",
        "facts": _facts(), "provider_native_relation": _no_relation(),
        "dispatch_join": _join(), "received_at": T,
        "raw_artifact": _blob(PROVIDER_TELEMETRY_RAW_MEDIA_TYPE),
        "provenance": "adapter_receipt_persisted", "observation": {"state": "known", "reason": "observed"},
        "receipt_sha256": ZERO_SHA256,
    }
    _rehash(value, "receipt_sha256")
    return value


def _receipt_from_normalized(
    raw: bytes,
    normalized: Any,
) -> dict[str, Any]:
    value = _receipt()
    value.update({
        "provider": normalized.provider,
        "source_class": normalized.source_class,
        "parser_id": normalized.parser_id,
        "parser_version": normalized.parser_version,
        "parse_outcome": normalized.parse_outcome,
        "normalized_kind": normalized.normalized_kind,
        "facts": telemetry_facts_payload(normalized),
        "provider_native_relation":
            provider_native_relation_payload(normalized),
        "raw_artifact": _blob(
            PROVIDER_TELEMETRY_RAW_MEDIA_TYPE,
            size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        ),
    })
    _rehash(value, "receipt_sha256")
    return value


def _dropped(*, value: int | None = 0, quality: str = "observed", reason: str = "observed") -> dict[str, Any]:
    return {"value": value, "source": "collector" if quality == "observed" else "none", "quality": quality, "reason": reason}


def _coverage() -> dict[str, Any]:
    value = {
        "contract_type": PROVIDER_COVERAGE_REVISION_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1,
        "coverage_scope_id": "codex-lifecycle", "coverage_surface": "lifecycle", "revision_id": "coverage-rev-1",
        "revision": 1, "previous_revision_sha256": ZERO_SHA256, "provider": "codex",
        "adapter_instance_id": "adapter-1", "source_class": "codex_app_server",
        "declared_event_kinds": ["thread_started", "token_usage"], "state": "observed", "reason": "observed",
        "assessment_source": "receipt", "last_receipt_id": "receipt-1", "last_received_at": T,
        "gap_started_at": None, "dropped_event_count": _dropped(), "assessed_at": T,
        "observation": {"state": "known", "reason": "observed"}, "coverage_sha256": ZERO_SHA256,
    }
    _rehash(value, "coverage_sha256")
    return value


def _vector() -> dict[str, dict[str, Any]]:
    return {
        "input": {"present": True, "tokens": 10},
        "cache_read": {"present": True, "tokens": 0},
        "cache_creation": {"present": True, "tokens": 0},
        "output": {"present": True, "tokens": 2},
        "reasoning_output": {"present": True, "tokens": 0},
        "total": {"present": True, "tokens": 12},
    }


def _provenance_facts() -> dict[str, dict[str, Any]]:
    result = {name: _fact() for name in ("actual_provider", "actual_model", "actual_effort", "actual_role", "routing")}
    result["actual_provider"] = _fact(value="codex", source="provider_payload", quality="observed", reason="observed")
    return result


def _sample() -> dict[str, Any]:
    value = {
        "contract_type": USAGE_COUNTER_SAMPLE_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1,
        "sample_id": "sample-1", "telemetry_receipt_id": "receipt-1", "telemetry_receipt_sha256": "b" * 64,
        "adapter_instance_id": "adapter-1", "adapter_event_id": "event-occurrence-1", "intake_sequence": 1,
        "provider": "codex", "thread_id": "thread-1", "turn_id": "turn-1", "counter_scope_id": "thread-1",
        "provider_sequence": None, "counting_semantics": "non_additive_cumulative",
        "total_token_vector": _vector(), "last_token_vector": _vector(),
        "model_context_window": {"present": False, "value": None}, "provenance_facts": _provenance_facts(),
        "received_at": T, "raw_artifact": _blob(PROVIDER_TELEMETRY_RAW_MEDIA_TYPE),
        "provenance": "adapter_receipt_persisted", "observation": {"state": "known", "reason": "observed"},
        "sample_sha256": ZERO_SHA256,
    }
    _rehash(value, "sample_sha256")
    return value


def _needs_user(*, state: str = "pending") -> dict[str, Any]:
    question = _blob(NEEDS_USER_QUESTION_MEDIA_TYPE, sha256="c" * 64)
    value: dict[str, Any] = {
        "contract_type": NEEDS_USER_REVISION_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1,
        "item_id": "needs-user-1", "revision_id": "needs-user-1-r1", "revision": 1,
        "previous_revision_sha256": ZERO_SHA256, "origin_execution_id": "execution-1", "opened_chief_term": 1,
        "state": state, "question_sha256": question["sha256"], "question_blob": question,
        "answer_sha256": None, "answer_blob": None, "created_at": T, "updated_at": T,
        "answered_at": None, "answered_by_chief_term": None, "answer_control_intent_id": None,
        "observation": {"state": "known", "reason": "observed"}, "revision_sha256": ZERO_SHA256,
    }
    if state == "answered":
        answer = _blob(NEEDS_USER_ANSWER_MEDIA_TYPE, sha256="d" * 64)
        value.update({"revision_id": "needs-user-1-r2", "revision": 2, "previous_revision_sha256": "b" * 64,
                      "answer_sha256": answer["sha256"], "answer_blob": answer,
                      "updated_at": T2, "answered_at": T2,
                      "answered_by_chief_term": 2, "answer_control_intent_id": "control-answer-1"})
    _rehash(value, "revision_sha256")
    return value


def test_telemetry_contracts_round_trip_and_dispatcher_registration() -> None:
    receipt = _receipt()
    coverage = _coverage()
    sample = _sample()
    needs_user = _needs_user()
    assert validate_provider_telemetry_receipt(receipt) == receipt
    assert validate_provider_coverage_revision(coverage) == coverage
    assert validate_usage_counter_sample(sample) == sample
    assert validate_needs_user_revision(needs_user) == needs_user
    for value in (receipt, coverage, sample, needs_user):
        assert validate_company_contract(value) == value


def test_telemetry_receipt_rejects_unknown_fields_raw_bounds_and_fact_forgery() -> None:
    unknown = _receipt()
    unknown["parent_execution_id"] = "guessed-parent"
    with pytest.raises(CompanyContractError, match="schema"):
        validate_provider_telemetry_receipt(unknown)

    oversized = _receipt()
    oversized["raw_artifact"]["size_bytes"] = MAX_PROVIDER_TELEMETRY_RAW_BYTES + 1
    _rehash(oversized, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="bounded available"):
        validate_provider_telemetry_receipt(oversized)

    wrong_media = _receipt()
    wrong_media["raw_artifact"]["media_type"] = "application/json"
    _rehash(wrong_media, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="bounded available"):
        validate_provider_telemetry_receipt(wrong_media)

    fake = _receipt()
    fake["facts"]["actual_model"] = _fact(value=None, source="provider_payload", quality="observed", reason="observed")
    _rehash(fake, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="observed value"):
        validate_provider_telemetry_receipt(fake)

    completion = _receipt()
    completion["facts"]["engineering_completion"] = _fact(value="completed", source="provider_payload", quality="observed", reason="observed")
    _rehash(completion, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="engineering completion"):
        validate_provider_telemetry_receipt(completion)


@pytest.mark.parametrize(
    ("outcome", "kind", "valid"),
    [("normalized", "thread_started", True), ("normalized", "unsupported", False),
     ("unsupported_valid", "unsupported", True), ("unsupported_valid", "malformed", False),
     ("malformed", "malformed", True), ("malformed", "thread_started", False)],
)
def test_telemetry_parse_outcome_matrix(outcome: str, kind: str, valid: bool) -> None:
    value = _receipt()
    value["parse_outcome"] = outcome
    value["normalized_kind"] = kind
    if outcome != "normalized":
        value["facts"] = {
            name: _fact(reason=f"parser_{kind}")
            for name in value["facts"]
        }
    _rehash(value, "receipt_sha256")
    if valid:
        assert validate_provider_telemetry_receipt(value) == value
    else:
        with pytest.raises(CompanyContractError, match="parse outcome"):
            validate_provider_telemetry_receipt(value)


@pytest.mark.parametrize("state", ["none", "exact", "ambiguous"])
def test_dispatch_join_matrices(state: str) -> None:
    value = _receipt()
    value["dispatch_join"] = _join(state=state)
    _rehash(value, "receipt_sha256")
    assert validate_provider_telemetry_receipt(value)["dispatch_join"]["state"] == state


def test_dispatch_join_rejects_mixed_or_fake_candidates() -> None:
    value = _receipt()
    value["dispatch_join"] = _join(state="none")
    value["dispatch_join"]["execution_id"] = "guessed-execution"
    _rehash(value, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="none binding"):
        validate_provider_telemetry_receipt(value)

    value = _receipt()
    value["dispatch_join"] = _join(state="ambiguous")
    value["dispatch_join"]["candidate_count"] = 1
    _rehash(value, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="ambiguous binding"):
        validate_provider_telemetry_receipt(value)


def test_coverage_rejects_fake_zero_gap_and_bad_genesis() -> None:
    fake_zero = _coverage()
    fake_zero["state"] = "unknown"
    fake_zero["reason"] = "collector_unavailable"
    fake_zero["observation"] = {"state": "unknown", "reason": "collector_unavailable"}
    _rehash(fake_zero, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="unknown coverage matrix"):
        validate_provider_coverage_revision(fake_zero)

    gap = _coverage()
    gap["state"] = "observed"
    gap["gap_started_at"] = T
    _rehash(gap, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="observed matrix"):
        validate_provider_coverage_revision(gap)

    bad_genesis = _coverage()
    bad_genesis["previous_revision_sha256"] = "b" * 64
    _rehash(bad_genesis, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="genesis predecessor"):
        validate_provider_coverage_revision(bad_genesis)


def test_usage_counter_sample_is_raw_non_additive_and_bounded() -> None:
    sample = _sample()
    sample["provider_sequence"] = None
    assert validate_usage_counter_sample(sample) == sample

    invalid_context = _sample()
    invalid_context["model_context_window"] = {"present": False, "value": 0}
    _rehash(invalid_context, "sample_sha256")
    with pytest.raises(CompanyContractError, match="must be null"):
        validate_usage_counter_sample(invalid_context)

    additive = _sample()
    additive["aggregation"] = {"burn": 1}
    with pytest.raises(CompanyContractError, match="schema"):
        validate_usage_counter_sample(additive)

    non_codex = _sample()
    non_codex["provider"] = "claude"
    _rehash(non_codex, "sample_sha256")
    with pytest.raises(CompanyContractError, match="limited to Codex"):
        validate_usage_counter_sample(non_codex)

    absent_vector = _sample()
    absent_vector["total_token_vector"]["total"] = {"present": False, "tokens": 0}
    _rehash(absent_vector, "sample_sha256")
    with pytest.raises(CompanyContractError, match="must be null"):
        validate_usage_counter_sample(absent_vector)


def test_needs_user_revision_terminal_digest_and_media_matrices() -> None:
    assert validate_needs_user_revision(_needs_user(state="answered"))["state"] == "answered"

    pending_answer = _needs_user()
    pending_answer["answer_sha256"] = "d" * 64
    _rehash(pending_answer, "revision_sha256")
    with pytest.raises(CompanyContractError, match="non-answered"):
        validate_needs_user_revision(pending_answer)

    wrong_question_media = _needs_user()
    wrong_question_media["question_blob"]["media_type"] = "application/json"
    _rehash(wrong_question_media, "revision_sha256")
    with pytest.raises(CompanyContractError, match="bounded available"):
        validate_needs_user_revision(wrong_question_media)

    digest_drift = _needs_user()
    digest_drift["question_sha256"] = "e" * 64
    _rehash(digest_drift, "revision_sha256")
    with pytest.raises(CompanyContractError, match="question digest"):
        validate_needs_user_revision(digest_drift)

    terminal_genesis = _needs_user(state="expired")
    with pytest.raises(CompanyContractError, match="genesis must be pending"):
        validate_needs_user_revision(terminal_genesis)

    wrong_answer_media = _needs_user(state="answered")
    assert wrong_answer_media["answer_blob"] is not None
    wrong_answer_media["answer_blob"]["media_type"] = NEEDS_USER_QUESTION_MEDIA_TYPE
    _rehash(wrong_answer_media, "revision_sha256")
    with pytest.raises(CompanyContractError, match="bounded available"):
        validate_needs_user_revision(wrong_answer_media)

    pending_successor = _needs_user(state="answered")
    pending_successor.update({
        "state": "pending",
        "answer_sha256": None,
        "answer_blob": None,
        "answered_at": None,
        "answered_by_chief_term": None,
        "answer_control_intent_id": None,
    })
    _rehash(pending_successor, "revision_sha256")
    with pytest.raises(CompanyContractError, match="successor must be terminal"):
        validate_needs_user_revision(pending_successor)

    late_answer = _needs_user(state="answered")
    late_answer["answered_at"] = "2026-07-27T00:00:02Z"
    _rehash(late_answer, "revision_sha256")
    with pytest.raises(CompanyContractError, match="differs from updated"):
        validate_needs_user_revision(late_answer)

    empty_question = _needs_user()
    empty_question["question_blob"]["size_bytes"] = 0
    _rehash(empty_question, "revision_sha256")
    with pytest.raises(CompanyContractError, match="bounded available"):
        validate_needs_user_revision(empty_question)


def _codex(method: str, params: object) -> bytes:
    return json.dumps(
        {"method": method, "params": params},
        separators=(",", ":"),
    ).encode()


def _codex_thread() -> dict[str, object]:
    return {
        "cliVersion": "0.145.0",
        "createdAt": 1_785_000_000_000,
        "cwd": "C:/work",
        "ephemeral": False,
        "id": "thread-1",
        "modelProvider": "openai",
        "preview": "redacted",
        "sessionId": "session-1",
        "source": "cli",
        "status": {"type": "active", "activeFlags": []},
        "turns": [],
        "updatedAt": 1_785_000_000_001,
    }


def test_normalizer_output_composes_with_strict_receipt_contract() -> None:
    thread_raw = _codex("thread/started", {"thread": _codex_thread()})
    collab_raw = _codex(
        "item/started",
        {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "startedAtMs": 1_785_000_000_002,
            "item": {
                "agentsStates": {},
                "id": "item-1",
                "receiverThreadIds": ["child-2", "child-1"],
                "senderThreadId": "thread-1",
                "status": "inProgress",
                "tool": "spawnAgent",
                "type": "collabAgentToolCall",
                "model": "gpt-5",
                "reasoningEffort": "high",
            },
        },
    )
    activity_raw = _codex(
        "item/completed",
        {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "completedAtMs": 1_785_000_000_003,
            "item": {
                "agentPath": "root/child",
                "agentThreadId": "child-1",
                "id": "item-2",
                "kind": "started",
                "type": "subAgentActivity",
            },
        },
    )
    usage_raw = _codex(
        "thread/tokenUsage/updated",
        {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "tokenUsage": {
                "total": {
                    "inputTokens": 20,
                    "cachedInputTokens": 4,
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
            },
        },
    )
    unsupported_raw = _codex("future/event", {"x": 1})
    claude_raw = json.dumps(
        {
            "hook_event_name": "SubagentStart",
            "session_id": "session-1",
            "agent_id": "child-1",
            "agent_type": "reviewer",
        },
        separators=(",", ":"),
    ).encode()
    samples = [
        (thread_raw, normalize_codex_telemetry(thread_raw)),
        (collab_raw, normalize_codex_telemetry(collab_raw)),
        (activity_raw, normalize_codex_telemetry(activity_raw)),
        (usage_raw, normalize_codex_telemetry(usage_raw)),
        (unsupported_raw, normalize_codex_telemetry(unsupported_raw)),
        (b"{", normalize_codex_telemetry(b"{")),
        (
            claude_raw,
            normalize_claude_telemetry(claude_raw, "claude_hook"),
        ),
    ]
    for raw, normalized in samples:
        receipt = _receipt_from_normalized(raw, normalized)
        assert validate_provider_telemetry_receipt(receipt) == receipt

    collab = provider_native_relation_payload(samples[1][1])
    assert collab["kind"] == "collab_request"
    assert collab["receiver_thread_ids"] == ["child-1", "child-2"]
    activity = provider_native_relation_payload(samples[2][1])
    assert activity["kind"] == "subagent_activity"
    assert activity["child_thread_id"] == "child-1"


def test_provider_matrix_and_coverage_counterexamples_fail_closed() -> None:
    mixed = _receipt()
    mixed.update({
        "provider": "claude",
        "source_class": "codex_app_server",
        "parser_id": "claude_adapter",
    })
    _rehash(mixed, "receipt_sha256")
    with pytest.raises(CompanyContractError, match="source matrix"):
        validate_provider_telemetry_receipt(mixed)

    for provider, source_class in (
        ("bogus", "bogus_source"),
        ("codex", "claude_hook"),
        ("claude", "codex_app_server"),
    ):
        invalid_coverage = _coverage()
        invalid_coverage.update({
            "provider": provider,
            "source_class": source_class,
        })
        _rehash(invalid_coverage, "coverage_sha256")
        with pytest.raises(
            CompanyContractError,
            match="provider|source",
        ):
            validate_provider_coverage_revision(invalid_coverage)

    configured = _coverage()
    configured["assessment_source"] = "configuration"
    _rehash(configured, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="observed matrix"):
        validate_provider_coverage_revision(configured)

    missing_receipt = _coverage()
    missing_receipt["last_receipt_id"] = None
    missing_receipt["last_received_at"] = None
    _rehash(missing_receipt, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="lacks a receipt"):
        validate_provider_coverage_revision(missing_receipt)

    future_receipt = _coverage()
    future_receipt["last_received_at"] = T2
    _rehash(future_receipt, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="follows assessment"):
        validate_provider_coverage_revision(future_receipt)

    unknown_known = _coverage()
    unknown_known.update({
        "state": "unknown",
        "reason": "collector_unknown",
        "assessment_source": "configuration",
        "last_receipt_id": None,
        "last_received_at": None,
        "dropped_event_count": _dropped(
            value=None,
            quality="unavailable",
            reason="collector_unknown",
        ),
    })
    _rehash(unknown_known, "coverage_sha256")
    with pytest.raises(CompanyContractError, match="unknown coverage matrix"):
        validate_provider_coverage_revision(unknown_known)


def test_usage_required_dimensions_and_oversize_intake_fail_closed() -> None:
    missing_input = _sample()
    missing_input["total_token_vector"]["input"] = {
        "present": False,
        "tokens": None,
    }
    _rehash(missing_input, "sample_sha256")
    with pytest.raises(CompanyContractError, match="required Codex"):
        validate_usage_counter_sample(missing_input)

    with pytest.raises(TelemetryIntakeRejected, match="intake bound"):
        normalize_codex_telemetry(
            b"x" * (MAX_PROVIDER_TELEMETRY_RAW_BYTES + 1),
        )


def test_parser_valid_values_outside_receipt_bounds_are_typed_unsupported() -> None:
    long_thread = _codex_thread()
    long_thread["id"] = "t" * 513
    cases = [
        _codex("thread/started", {"thread": long_thread}),
        _codex(
            "item/started",
            {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "startedAtMs": 12,
                "item": {
                    "agentsStates": {},
                    "id": "item-1",
                    "receiverThreadIds": [
                        f"child-{index:03d}"
                        for index in range(65)
                    ],
                    "senderThreadId": "thread-1",
                    "status": "completed",
                    "tool": "spawnAgent",
                    "type": "collabAgentToolCall",
                },
            },
        ),
        _codex(
            "item/started",
            {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "startedAtMs": 12,
                "item": {
                    "agentsStates": {},
                    "id": "item-1",
                    "receiverThreadIds": [],
                    "senderThreadId": "thread-1",
                    "status": "completed",
                    "tool": "spawnAgent",
                    "type": "collabAgentToolCall",
                },
            },
        ),
        _codex(
            "item/started",
            {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "startedAtMs": 12,
                "item": {
                    "agentsStates": {},
                    "id": "item-1",
                    "receiverThreadIds": ["child", "child"],
                    "senderThreadId": "thread-1",
                    "status": "completed",
                    "tool": "spawnAgent",
                    "type": "collabAgentToolCall",
                },
            },
        ),
    ]
    for raw in cases:
        normalized = normalize_codex_telemetry(raw)
        assert normalized.parse_outcome == "unsupported_valid"
        assert normalized.normalized_kind == "unsupported"
        assert (
            normalized.facts["thread_id"].reason
            == "persistence_bounds_exceeded"
        )
        receipt = _receipt_from_normalized(raw, normalized)
        assert validate_provider_telemetry_receipt(receipt) == receipt


def test_signed_provider_event_time_is_persistence_ready() -> None:
    thread = _codex_thread()
    thread["updatedAt"] = -1
    raw = _codex("thread/started", {"thread": thread})
    normalized = normalize_codex_telemetry(raw)
    assert normalized.parse_outcome == "normalized"
    assert normalized.facts["event_time"].value == -1
    receipt = _receipt_from_normalized(raw, normalized)
    assert validate_provider_telemetry_receipt(receipt) == receipt


def test_usage_sample_preserves_bounded_provider_native_ids() -> None:
    sample = _sample()
    native_id = "t" * 300
    sample.update({
        "thread_id": native_id,
        "turn_id": native_id,
        "counter_scope_id": native_id,
    })
    _rehash(sample, "sample_sha256")
    assert validate_usage_counter_sample(sample) == sample


def test_native_parent_without_provider_depth_is_persistence_ready() -> None:
    thread = _codex_thread()
    thread["parentThreadId"] = "native-parent"
    raw = _codex("thread/started", {"thread": thread})
    normalized = normalize_codex_telemetry(raw)
    assert normalized.parse_outcome == "normalized"
    relation = provider_native_relation_payload(normalized)
    assert relation["kind"] == "thread_spawn"
    assert relation["native_depth"] is None
    receipt = _receipt_from_normalized(raw, normalized)
    assert validate_provider_telemetry_receipt(receipt) == receipt
