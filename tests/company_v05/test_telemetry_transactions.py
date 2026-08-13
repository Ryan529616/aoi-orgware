from __future__ import annotations

import copy
from types import MappingProxyType
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    BLOB_REF_V1,
    NEEDS_USER_QUESTION_MEDIA_TYPE,
    NEEDS_USER_REVISION_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RAW_MEDIA_TYPE,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    ZERO_SHA256,
    CompanyContractError,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import LedgerHead, LedgerHeadsSnapshot
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    CompanyTransactionBuildError,
    build_company_transaction_request,
)


H = "a" * 64
T = "2026-07-27T00:00:00Z"
BINDING = {
    "company_id": "company-1",
    "company_incarnation": 1,
    "lock_domain_generation": 1,
}


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    value[field] = company_contract_sha256(
        {key: member for key, member in value.items() if key != field},
    )
    return value


def _authority() -> dict[str, Any]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1,
        "schema_version": 1,
        **BINDING,
        "actor_id": "supervisor-1",
        "actor_kind": "supervisor",
        "carrier_id": None,
        "chief_epoch": None,
        "term": 1,
        "authority_state": "active",
        "permissions": ["company.mutate"],
        "scope_sha256": H,
        "authority_record_sha256": H,
        "provenance": "AOI_verified",
    }


def _blob(media_type: str, *, sha256: str = H) -> dict[str, Any]:
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": sha256,
        "size_bytes": 12,
        "media_type": media_type,
        "availability": "available",
    }


def _fact(*, value: object | None = None, source: str = "none", quality: str = "unavailable", reason: str = "not_exposed") -> dict[str, Any]:
    return {"value": value, "source": source, "quality": quality, "reason": reason}


def _telemetry_facts() -> dict[str, dict[str, Any]]:
    result = {
        key: _fact()
        for key in (
            "actual_provider", "actual_model", "actual_effort", "actual_role", "routing",
            "session_id", "thread_id", "turn_id", "agent_id", "parent_thread_id",
            "event_time", "engineering_completion",
        )
    }
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
        value=1, source="provider_payload", quality="observed",
        reason="provider_thread_updated_at",
    )
    return result


def _receipt(*, transaction_id: str = "transaction-1", command_id: str = "command-1") -> dict[str, Any]:
    value = {
        "contract_type": PROVIDER_TELEMETRY_RECEIPT_V1,
        "schema_version": 1,
        **BINDING,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "receipt_id": "receipt-1",
        "adapter_instance_id": "adapter-1",
        "adapter_event_id": "event-occurrence-1",
        "intake_sequence": 1,
        "provider": "codex",
        "source_class": "codex_app_server",
        "parser_id": "codex_adapter",
        "parser_version": "v1",
        "parse_outcome": "normalized",
        "normalized_kind": "thread_started",
        "facts": _telemetry_facts(),
        "provider_native_relation": {
            "kind": "none",
            "sender_thread_id": None,
            "receiver_thread_ids": [],
            "child_thread_id": None,
            "agent_path": None,
            "activity_kind": None,
            "native_depth": None,
            "reason": "provider_relation_not_present",
        },
        "dispatch_join": {
            "state": "none", "binding_kind": "none", "registry_cursor": 0,
            "dispatch_request_id": None, "dispatch_revision_id": None,
            "registration_id": None, "execution_id": None, "carrier_id": None,
            "candidate_count": 0, "candidates_sha256": ZERO_SHA256,
            "reason": "no_registered_match",
        },
        "received_at": T,
        "raw_artifact": _blob(PROVIDER_TELEMETRY_RAW_MEDIA_TYPE),
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
        "receipt_sha256": ZERO_SHA256,
    }
    return _seal(value, "receipt_sha256")


def _coverage() -> dict[str, Any]:
    value = {
        "contract_type": PROVIDER_COVERAGE_REVISION_V1,
        "schema_version": 1,
        **BINDING,
        "coverage_scope_id": "codex-lifecycle",
        "coverage_surface": "lifecycle",
        "revision_id": "coverage-revision-1",
        "revision": 1,
        "previous_revision_sha256": ZERO_SHA256,
        "provider": "codex",
        "adapter_instance_id": "adapter-1",
        "source_class": "codex_app_server",
        "declared_event_kinds": ["thread_started"],
        "state": "observed",
        "reason": "observed",
        "assessment_source": "receipt",
        "last_receipt_id": "receipt-1",
        "last_received_at": T,
        "gap_started_at": None,
        "dropped_event_count": {
            "value": 0, "source": "collector", "quality": "observed", "reason": "observed",
        },
        "assessed_at": T,
        "observation": {"state": "known", "reason": "observed"},
        "coverage_sha256": ZERO_SHA256,
    }
    return _seal(value, "coverage_sha256")


def _vector() -> dict[str, dict[str, Any]]:
    return {
        key: {"present": True, "tokens": tokens}
        for key, tokens in (
            ("input", 10), ("cache_read", 0), ("cache_creation", 0),
            ("output", 2), ("reasoning_output", 0), ("total", 12),
        )
    }


def _sample() -> dict[str, Any]:
    provenance_facts = {
        key: _fact()
        for key in ("actual_provider", "actual_model", "actual_effort", "actual_role", "routing")
    }
    provenance_facts["actual_provider"] = _fact(
        value="codex", source="provider_payload", quality="observed", reason="observed",
    )
    value = {
        "contract_type": USAGE_COUNTER_SAMPLE_V1,
        "schema_version": 1,
        **BINDING,
        "sample_id": "sample-1",
        "telemetry_receipt_id": "receipt-1",
        "telemetry_receipt_sha256": _receipt()["receipt_sha256"],
        "adapter_instance_id": "adapter-1",
        "adapter_event_id": "event-occurrence-1",
        "intake_sequence": 1,
        "provider": "codex",
        "thread_id": "thread-1",
        "turn_id": "turn-1",
        "counter_scope_id": "thread-1",
        "provider_sequence": None,
        "counting_semantics": "non_additive_cumulative",
        "total_token_vector": _vector(),
        "last_token_vector": _vector(),
        "model_context_window": {"present": False, "value": None},
        "provenance_facts": provenance_facts,
        "received_at": T,
        "raw_artifact": _blob(PROVIDER_TELEMETRY_RAW_MEDIA_TYPE),
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
        "sample_sha256": ZERO_SHA256,
    }
    return _seal(value, "sample_sha256")


def _needs_user() -> dict[str, Any]:
    question = _blob(NEEDS_USER_QUESTION_MEDIA_TYPE, sha256="b" * 64)
    value = {
        "contract_type": NEEDS_USER_REVISION_V1,
        "schema_version": 1,
        **BINDING,
        "item_id": "needs-user-1",
        "revision_id": "needs-user-1-r1",
        "revision": 1,
        "previous_revision_sha256": ZERO_SHA256,
        "origin_execution_id": "execution-1",
        "opened_chief_term": 1,
        "state": "pending",
        "question_sha256": question["sha256"],
        "question_blob": question,
        "answer_sha256": None,
        "answer_blob": None,
        "created_at": T,
        "updated_at": T,
        "answered_at": None,
        "answered_by_chief_term": None,
        "answer_control_intent_id": None,
        "observation": {"state": "known", "reason": "observed"},
        "revision_sha256": ZERO_SHA256,
    }
    return _seal(value, "revision_sha256")


def _heads() -> LedgerHeadsSnapshot:
    return LedgerHeadsSnapshot(
        identity=("company-1", 1, 1),
        global_head=LedgerHead(7, "f" * 64),
        stream_heads=MappingProxyType({
            "evidence": (3, "e" * 64),
            "usage": (4, "d" * 64),
            "alert": (5, "c" * 64),
        }),
    )


def test_builds_one_atomic_multistream_telemetry_transaction() -> None:
    request = build_company_transaction_request(
        _heads(),
        _authority(),
        transaction_id="transaction-1",
        command_id="command-1",
        events=[
            CompanyEventDraft("event-receipt", "provider.telemetry.received", T, _receipt()),
            CompanyEventDraft("event-coverage", "provider.coverage.assessed", T, _coverage()),
            CompanyEventDraft("event-sample", "usage.counter.observed", T, _sample()),
            CompanyEventDraft("event-needs-user", "needs_user.opened", T, _needs_user()),
        ],
    )

    assert request["expected_transaction_head"] == {
        "contract_type": "expected_transaction_head_v1",
        "schema_version": 1,
        **BINDING,
        "transaction_id": "transaction-1",
        "command_id": "command-1",
        "global_sequence": 7,
        "transaction_sha256": "f" * 64,
    }
    assert [
        (item["stream"], item["cursor"], item["event_sha256"])
        for item in request["expected_heads"]
    ] == [
        ("evidence", 3, "e" * 64),
        ("usage", 4, "d" * 64),
        ("alert", 5, "c" * 64),
    ]
    assert [item["stream"] for item in request["events"]] == [
        "evidence", "evidence", "usage", "alert",
    ]
    assert [item["payload"]["contract_type"] for item in request["events"]] == [
        PROVIDER_TELEMETRY_RECEIPT_V1,
        PROVIDER_COVERAGE_REVISION_V1,
        USAGE_COUNTER_SAMPLE_V1,
        NEEDS_USER_REVISION_V1,
    ]


def test_rejects_telemetry_receipt_outer_binding_and_invalid_payload() -> None:
    divergent = _receipt(transaction_id="other-transaction")
    with pytest.raises(CompanyTransactionBuildError, match="ProviderTelemetryReceipt differs"):
        build_company_transaction_request(
            _heads(), _authority(), transaction_id="transaction-1", command_id="command-1",
            events=[CompanyEventDraft("event-receipt", "provider.telemetry.received", T, divergent)],
        )

    wrong_command = _receipt(command_id="other-command")
    with pytest.raises(CompanyTransactionBuildError, match="ProviderTelemetryReceipt differs"):
        build_company_transaction_request(
            _heads(), _authority(), transaction_id="transaction-1", command_id="command-1",
            events=[CompanyEventDraft("event-receipt", "provider.telemetry.received", T, wrong_command)],
        )

    invalid = copy.deepcopy(_coverage())
    invalid["unbounded_metric"] = 1
    with pytest.raises(CompanyContractError, match="schema"):
        build_company_transaction_request(
            _heads(), _authority(), transaction_id="transaction-1", command_id="command-1",
            events=[CompanyEventDraft("event-coverage", "provider.coverage.assessed", T, invalid)],
        )
