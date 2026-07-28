from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import (
    COMPANY_MANIFEST_V1,
    EXECUTION_NODE_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    company_contract_sha256,
)
from aoi_orgware.company.supervisor import (
    CompanySupervisor,
    CompanyTelemetryIngestError,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)
from aoi_orgware.company.views import CompanyViewService


T = "2026-07-27T00:00:00Z"


def _manifest() -> dict[str, object]:
    return {
        "contract_type": COMPANY_MANIFEST_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1,
        "lock_domain_generation": 1, "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64, "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T, "observation": {"state": "known", "reason": "observed"},
    }


def _carrier() -> dict[str, object]:
    return {
        "carrier_id": "carrier-1", "provider": "codex", "model": "gpt-5",
        "session_id": "session-1", "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _raw(method: str, params: dict[str, object]) -> bytes:
    return json.dumps({"method": method, "params": params}, separators=(",", ":")).encode()


def _usage() -> dict[str, object]:
    vector = {
        "inputTokens": 20, "cachedInputTokens": 4, "outputTokens": 10,
        "reasoningOutputTokens": 8, "totalTokens": 42,
    }
    return {"total": vector, "last": vector}


def _capture_ingest_request(
    supervisor: CompanySupervisor,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    *,
    transaction_id: str,
    command_id: str,
    received_at: str,
) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def capture(
        request: dict[str, Any],
        **_kwargs: Any,
    ) -> Any:
        captured["request"] = request
        raise RuntimeError("captured telemetry request")

    with monkeypatch.context() as context:
        context.setattr(supervisor, "commit", capture)
        with pytest.raises(RuntimeError, match="captured telemetry request"):
            supervisor.ingest_codex_telemetry(
                raw,
                adapter_instance_id="capture-adapter",
                adapter_event_id="capture-event",
                intake_sequence=1,
                transaction_id=transaction_id,
                command_id=command_id,
                received_at=received_at,
            )
    return cast(dict[str, Any], captured["request"])


def _telemetry_supervisor(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )


def test_exact_telemetry_transaction_replay_preserves_cursor(tmp_path: Path) -> None:
    supervisor = _telemetry_supervisor(tmp_path)
    try:
        raw = _raw(
            "thread/status/changed",
            {"threadId": "thread-1", "status": {"type": "idle"}},
        )
        first = supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-exact-replay",
            adapter_event_id="event-exact-replay",
            intake_sequence=1,
            transaction_id="tx-exact-replay",
            command_id="cmd-exact-replay",
            received_at="2026-07-27T00:01:00Z",
        )
        replay = supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-exact-replay",
            adapter_event_id="event-exact-replay",
            intake_sequence=1,
            transaction_id="tx-exact-replay",
            command_id="cmd-exact-replay",
            received_at="2026-07-27T00:01:00Z",
        )
        assert replay.idempotent_replay
        assert replay.receipt_id == first.receipt_id
        assert replay.global_sequence == first.global_sequence
    finally:
        supervisor.close()


def test_telemetry_transaction_replay_rejects_received_at_drift(
    tmp_path: Path,
) -> None:
    supervisor = _telemetry_supervisor(tmp_path)
    try:
        raw = _raw(
            "thread/status/changed",
            {"threadId": "thread-1", "status": {"type": "idle"}},
        )
        supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-received-at",
            adapter_event_id="event-received-at",
            intake_sequence=1,
            transaction_id="tx-received-at",
            command_id="cmd-received-at",
            received_at="2026-07-27T00:01:00Z",
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyTelemetryIngestError,
            match="transaction replay differs from durable telemetry",
        ):
            supervisor.ingest_codex_telemetry(
                raw,
                adapter_instance_id="adapter-received-at",
                adapter_event_id="event-received-at",
                intake_sequence=1,
                transaction_id="tx-received-at",
                command_id="cmd-received-at",
                received_at="2026-07-27T00:01:01Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def test_claude_telemetry_transaction_replay_rejects_source_class_drift(
    tmp_path: Path,
) -> None:
    supervisor = _telemetry_supervisor(tmp_path)
    try:
        raw = json.dumps(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "claude-session-1",
                "agent_id": "claude-agent-1",
            },
            separators=(",", ":"),
        ).encode()
        supervisor.ingest_claude_telemetry(
            raw,
            source_class="claude_hook",
            adapter_instance_id="adapter-claude-source",
            adapter_event_id="event-claude-source",
            intake_sequence=1,
            transaction_id="tx-claude-source",
            command_id="cmd-claude-source",
            received_at="2026-07-27T00:01:00Z",
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyTelemetryIngestError,
            match="transaction replay differs from durable telemetry",
        ):
            supervisor.ingest_claude_telemetry(
                raw,
                source_class="otel",
                adapter_instance_id="adapter-claude-source",
                adapter_event_id="event-claude-source",
                intake_sequence=1,
                transaction_id="tx-claude-source",
                command_id="cmd-claude-source",
                received_at="2026-07-27T00:01:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def test_telemetry_occurrence_rejects_different_transaction_and_command(
    tmp_path: Path,
) -> None:
    supervisor = _telemetry_supervisor(tmp_path)
    try:
        raw = _raw(
            "thread/status/changed",
            {"threadId": "thread-1", "status": {"type": "idle"}},
        )
        supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-occurrence",
            adapter_event_id="event-occurrence",
            intake_sequence=1,
            transaction_id="tx-occurrence-1",
            command_id="cmd-occurrence-1",
            received_at="2026-07-27T00:01:00Z",
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyTelemetryIngestError,
            match="telemetry occurrence differs from durable bytes",
        ):
            supervisor.ingest_codex_telemetry(
                raw,
                adapter_instance_id="adapter-occurrence",
                adapter_event_id="event-occurrence",
                intake_sequence=1,
                transaction_id="tx-occurrence-2",
                command_id="cmd-occurrence-2",
                received_at="2026-07-27T00:01:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def test_codex_non_token_event_does_not_downgrade_usage_coverage(tmp_path: Path) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state", _manifest(), bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z", known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        token = supervisor.ingest_codex_telemetry(
            _raw("thread/tokenUsage/updated", {
                "threadId": "thread-1", "turnId": "turn-1", "tokenUsage": _usage(),
            }), adapter_instance_id="adapter-1", adapter_event_id="event-1",
            intake_sequence=1, transaction_id="tx-1", command_id="cmd-1",
            received_at="2026-07-27T00:01:00Z",
        )
        status = supervisor.ingest_codex_telemetry(
            _raw("thread/status/changed", {"threadId": "thread-1", "status": {"type": "idle"}}),
            adapter_instance_id="adapter-1", adapter_event_id="event-2",
            intake_sequence=2, transaction_id="tx-2", command_id="cmd-2",
            received_at="2026-07-27T00:02:00Z",
        )
        assert token.usage_sample_id is not None
        assert token.usage_coverage_revision_id
        assert token.dispatch_join_state == "exact"
        assert status.usage_sample_id is None
        assert status.usage_coverage_revision_id == ""
        usage = [dict(item.payload) for item in supervisor.objects(
            contract_type=PROVIDER_COVERAGE_REVISION_V1,
        ) if item.payload["coverage_surface"] == "usage"]
        assert len(usage) == 1
        assert usage[0]["state"] == "observed"
    finally:
        supervisor.close()


def test_unregistered_provider_thread_is_degraded_not_false_healthy(
    tmp_path: Path,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state", _manifest(), bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z", known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        result = supervisor.ingest_codex_telemetry(
            _raw(
                "thread/status/changed",
                {
                    "threadId": "foreign-thread",
                    "status": {"type": "idle"},
                },
            ),
            adapter_instance_id="adapter-foreign",
            adapter_event_id="foreign-event-1",
            intake_sequence=1,
            transaction_id="tx-foreign",
            command_id="cmd-foreign",
            received_at="2026-07-27T00:01:00Z",
        )
        assert result.dispatch_join_state == "none"
        lifecycle = [
            dict(item.payload)
            for item in supervisor.objects(
                contract_type=PROVIDER_COVERAGE_REVISION_V1,
            )
            if item.payload["coverage_surface"] == "lifecycle"
        ]
        assert lifecycle[-1]["state"] == "degraded"
        assert (
            lifecycle[-1]["reason"]
            == "provider_telemetry_unattributed"
        )
        assert lifecycle[-1]["dropped_event_count"]["value"] is None
    finally:
        supervisor.close()


def test_codex_initial_and_reordered_sequences_degrade_without_dropping_raw(tmp_path: Path) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state", _manifest(), bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z", known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        first = supervisor.ingest_codex_telemetry(
            _raw("thread/status/changed", {"threadId": "thread-1", "status": {"type": "idle"}}),
            adapter_instance_id="adapter-1", adapter_event_id="gap-4", intake_sequence=4,
            transaction_id="tx-gap", command_id="cmd-gap", received_at="2026-07-27T00:01:00Z",
        )
        assert first.parse_outcome == "normalized"
        lifecycle = [dict(item.payload) for item in supervisor.objects(
            contract_type=PROVIDER_COVERAGE_REVISION_V1,
        ) if item.payload["coverage_surface"] == "lifecycle"]
        assert lifecycle[-1]["state"] == "degraded"
        assert lifecycle[-1]["dropped_event_count"]["value"] == 3
        supervisor.ingest_codex_telemetry(
            _raw("thread/status/changed", {"threadId": "thread-1", "status": {"type": "idle"}}),
            adapter_instance_id="adapter-2", adapter_event_id="ordered-1", intake_sequence=1,
            transaction_id="tx-ordered", command_id="cmd-ordered", received_at="2026-07-27T00:02:00Z",
        )
        second = supervisor.ingest_codex_telemetry(
            _raw("thread/status/changed", {"threadId": "thread-1", "status": "active"}),
            adapter_instance_id="adapter-2", adapter_event_id="reordered-1", intake_sequence=1,
            transaction_id="tx-reordered", command_id="cmd-reordered", received_at="2026-07-27T00:03:00Z",
        )
        assert second.receipt_id
        lifecycle = [dict(item.payload) for item in supervisor.objects(
            contract_type=PROVIDER_COVERAGE_REVISION_V1,
        ) if item.payload["coverage_surface"] == "lifecycle" and item.payload["adapter_instance_id"] == "adapter-2"]
        assert lifecycle[-1]["state"] == "degraded"
        assert lifecycle[-1]["dropped_event_count"]["value"] is None
    finally:
        supervisor.close()


def test_current_needs_user_has_bounded_summary_but_history_does_not_read_blob(
    tmp_path: Path,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        chief = next(
            dict(item.payload)
            for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_kind"] == "carrier"
        )
        supervisor.open_needs_user(
            "Should RTL continue?\n  Confirm the source owner first.",
            item_id="needs-user-summary",
            origin_execution_id=str(chief["execution_id"]),
            expected_chief_term=1,
            expected_carrier_id="carrier-1",
            transaction_id="tx-needs-user-summary",
            command_id="cmd-needs-user-summary",
            created_at="2026-07-27T00:01:00Z",
        )
        view = CompanyViewService(supervisor._state, clock=lambda: T)
        live = view.section("alerts")["data"]["needs_user"][0]
        assert live["question_summary"] == (
            "Should RTL continue? Confirm the source owner first."
        )
        assert live["question_summary_quality"] == "derived"
        assert live["question_summary_reason"] == (
            "bounded_local_question_content"
        )

        historical = view.snapshot_from_replay(
            view.historical_replay_input(),
            supervisor.heads().global_head.global_sequence,
        )
        historical_item = historical["data"]["alerts"]["needs_user"][0]
        assert historical_item["question_summary"] is None
        assert historical_item["question_summary_quality"] == "unavailable"
        assert historical_item["question_summary_reason"] == (
            "historical_raw_content_not_replayed"
        )
    finally:
        supervisor.close()


def test_raw_cumulative_telemetry_cannot_omit_same_transaction_sample(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        transaction_id = "tx-captured-usage"
        command_id = "cmd-captured-usage"
        received_at = "2026-07-27T00:01:00Z"
        captured = _capture_ingest_request(
            supervisor,
            monkeypatch,
            _raw(
                "thread/tokenUsage/updated",
                {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "tokenUsage": _usage(),
                },
            ),
            transaction_id=transaction_id,
            command_id=command_id,
            received_at=received_at,
        )
        receipt_and_lifecycle_only = [
            CompanyEventDraft(
                str(event["event_id"]),
                str(event["event_type"]),
                str(event["recorded_at"]),
                event["payload"],
                str(event["provenance"]),
            )
            for event in captured["events"][:2]
        ]
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=receipt_and_lifecycle_only,
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="usage sample cardinality differs",
        ):
            supervisor.commit(request, recorded_at=received_at)
        assert supervisor.heads().global_head.global_sequence == 1
    finally:
        supervisor.close()


def test_provider_telemetry_event_envelope_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        transaction_id = "tx-captured-envelope"
        command_id = "cmd-captured-envelope"
        received_at = "2026-07-27T00:01:00Z"
        captured = _capture_ingest_request(
            supervisor,
            monkeypatch,
            _raw(
                "thread/status/changed",
                {
                    "threadId": "thread-1",
                    "status": {"type": "idle"},
                },
            ),
            transaction_id=transaction_id,
            command_id=command_id,
            received_at=received_at,
        )
        drafts = [
            CompanyEventDraft(
                str(event["event_id"]),
                (
                    "provider.coverage.usage"
                    if index == 1
                    else str(event["event_type"])
                ),
                str(event["recorded_at"]),
                event["payload"],
                str(event["provenance"]),
            )
            for index, event in enumerate(captured["events"])
        ]
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="event envelope",
        ):
            supervisor.commit(request, recorded_at=received_at)
        assert supervisor.heads().global_head.global_sequence == 1
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    "mutation",
    (
        "thread_id",
        "turn_id",
        "counter_scope_id",
        "provider_sequence",
        "provenance_facts",
    ),
)
def test_raw_usage_identity_is_rederived_before_low_level_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        transaction_id = f"tx-usage-attribution-{mutation}"
        command_id = f"cmd-usage-attribution-{mutation}"
        received_at = "2026-07-27T00:01:00Z"
        captured = _capture_ingest_request(
            supervisor,
            monkeypatch,
            _raw(
                "thread/tokenUsage/updated",
                {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "tokenUsage": _usage(),
                },
            ),
            transaction_id=transaction_id,
            command_id=command_id,
            received_at=received_at,
        )
        drafts: list[CompanyEventDraft] = []
        for event in captured["events"]:
            payload = copy.deepcopy(event["payload"])
            if payload["contract_type"] == USAGE_COUNTER_SAMPLE_V1:
                if mutation == "provider_sequence":
                    payload[mutation] = 7
                elif mutation == "provenance_facts":
                    payload[mutation]["actual_model"]["reason"] = (
                        "forged_usage_provenance"
                    )
                else:
                    payload[mutation] = f"misattributed-{mutation}"
                payload["sample_sha256"] = company_contract_sha256({
                    key: member
                    for key, member in payload.items()
                    if key != "sample_sha256"
                })
            drafts.append(CompanyEventDraft(
                str(event["event_id"]),
                str(event["event_type"]),
                str(event["recorded_at"]),
                payload,
                str(event["provenance"]),
            ))
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="usage sample differs from raw cumulative telemetry",
        ):
            supervisor.commit(request, recorded_at=received_at)
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def _capture_explicit_coverage_request(
    supervisor: CompanySupervisor,
    monkeypatch: pytest.MonkeyPatch,
    *,
    transaction_id: str,
    command_id: str,
    assessed_at: str,
) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def capture(request: dict[str, Any], **_kwargs: Any) -> Any:
        captured["request"] = request
        raise RuntimeError("captured coverage request")

    with monkeypatch.context() as context:
        context.setattr(supervisor, "commit", capture)
        with pytest.raises(RuntimeError, match="captured coverage request"):
            supervisor.record_provider_coverage(
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-explicit",
                coverage_surface="lifecycle",
                declared_event_kinds=["thread_started"],
                state="unknown",
                reason="adapter_health_still_unknown",
                assessment_source="adapter_health",
                dropped_event_count={
                    "value": None,
                    "source": "none",
                    "quality": "unavailable",
                    "reason": "adapter_health_still_unknown",
                },
                assessed_at=assessed_at,
                transaction_id=transaction_id,
                command_id=command_id,
            )
    return cast(dict[str, Any], captured["request"])


def _record_initial_explicit_coverage(
    supervisor: CompanySupervisor,
) -> None:
    supervisor.record_provider_coverage(
        provider="codex",
        source_class="codex_app_server",
        adapter_instance_id="adapter-explicit",
        coverage_surface="lifecycle",
        declared_event_kinds=["thread_started"],
        state="unknown",
        reason="adapter_health_unknown",
        assessment_source="adapter_health",
        dropped_event_count={
            "value": None,
            "source": "none",
            "quality": "unavailable",
            "reason": "adapter_health_unknown",
        },
        assessed_at="2026-07-27T00:01:00Z",
        transaction_id="tx-explicit-1",
        command_id="cmd-explicit-1",
    )


@pytest.mark.parametrize(
    "mutation",
    ("revision", "previous_revision_sha256", "revision_id"),
)
def test_explicit_coverage_revision_poison_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        _record_initial_explicit_coverage(supervisor)
        transaction_id = f"tx-explicit-poison-{mutation}"
        command_id = f"cmd-explicit-poison-{mutation}"
        captured = _capture_explicit_coverage_request(
            supervisor,
            monkeypatch,
            transaction_id=transaction_id,
            command_id=command_id,
            assessed_at="2026-07-27T00:02:00Z",
        )
        event = captured["events"][0]
        payload = copy.deepcopy(event["payload"])
        if mutation == "revision":
            payload[mutation] = 99
        elif mutation == "previous_revision_sha256":
            payload[mutation] = "f" * 64
        else:
            payload[mutation] = "coverage-revision-forged"
        payload["coverage_sha256"] = company_contract_sha256({
            key: member
            for key, member in payload.items()
            if key != "coverage_sha256"
        })
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[CompanyEventDraft(
                str(event["event_id"]),
                str(event["event_type"]),
                str(event["recorded_at"]),
                payload,
                str(event["provenance"]),
            )],
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="explicit provider coverage revision chain differs",
        ):
            supervisor.commit(
                request,
                recorded_at="2026-07-27T00:02:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    "mutation",
    ("event_id", "event_type", "provenance", "recorded_at"),
)
def test_explicit_coverage_envelope_poison_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        _record_initial_explicit_coverage(supervisor)
        transaction_id = f"tx-explicit-envelope-{mutation}"
        command_id = f"cmd-explicit-envelope-{mutation}"
        captured = _capture_explicit_coverage_request(
            supervisor,
            monkeypatch,
            transaction_id=transaction_id,
            command_id=command_id,
            assessed_at="2026-07-27T00:02:00Z",
        )
        event = captured["events"][0]
        values = {
            "event_id": str(event["event_id"]),
            "event_type": str(event["event_type"]),
            "recorded_at": str(event["recorded_at"]),
            "provenance": str(event["provenance"]),
        }
        replacements = {
            "event_id": "coverage-event-forged",
            "event_type": "provider.coverage.forged",
            "recorded_at": "2026-07-27T00:02:01Z",
            "provenance": "agent_reported",
        }
        values[mutation] = replacements[mutation]
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[CompanyEventDraft(
                values["event_id"],
                values["event_type"],
                values["recorded_at"],
                event["payload"],
                values["provenance"],
            )],
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match=(
                "explicit provider coverage"
                "|provider_coverage_revision_v1"
            ),
        ):
            supervisor.commit(
                request,
                recorded_at="2026-07-27T00:02:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def test_explicit_observed_coverage_must_reference_latest_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        for sequence in (1, 2):
            supervisor.ingest_codex_telemetry(
                _raw(
                    "thread/status/changed",
                    {
                        "threadId": "thread-1",
                        "status": {"type": "idle"},
                    },
                ),
                adapter_instance_id="adapter-observed",
                adapter_event_id=f"event-observed-{sequence}",
                intake_sequence=sequence,
                transaction_id=f"tx-observed-{sequence}",
                command_id=f"cmd-observed-{sequence}",
                received_at=f"2026-07-27T00:0{sequence}:00Z",
            )
        receipts = sorted(
            (
                dict(item.payload)
                for item in supervisor.objects(
                    contract_type=PROVIDER_TELEMETRY_RECEIPT_V1,
                )
                if item.payload["adapter_instance_id"]
                == "adapter-observed"
            ),
            key=lambda value: str(value["received_at"]),
        )
        assert len(receipts) == 2
        captured: dict[str, Any] = {}

        def capture(request: dict[str, Any], **_kwargs: Any) -> Any:
            captured["request"] = request
            raise RuntimeError("captured observed coverage request")

        with monkeypatch.context() as context:
            context.setattr(supervisor, "commit", capture)
            with pytest.raises(
                RuntimeError,
                match="captured observed coverage request",
            ):
                supervisor.record_provider_coverage(
                    provider="codex",
                    source_class="codex_app_server",
                    adapter_instance_id="adapter-observed",
                    coverage_surface="lifecycle",
                    declared_event_kinds=["thread_started"],
                    state="observed",
                    reason="observed",
                    assessment_source="adapter_health",
                    dropped_event_count={
                        "value": 0,
                        "source": "adapter_route",
                        "quality": "observed",
                        "reason": "observed",
                    },
                    assessed_at="2026-07-27T00:03:00Z",
                    transaction_id="tx-observed-explicit",
                    command_id="cmd-observed-explicit",
                )
        canonical = cast(dict[str, Any], captured["request"])
        event = canonical["events"][0]
        payload = copy.deepcopy(event["payload"])
        payload["last_receipt_id"] = receipts[0]["receipt_id"]
        payload["last_received_at"] = receipts[0]["received_at"]
        payload["coverage_sha256"] = company_contract_sha256({
            key: member
            for key, member in payload.items()
            if key != "coverage_sha256"
        })
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="tx-observed-explicit",
            command_id="cmd-observed-explicit",
            events=[CompanyEventDraft(
                str(event["event_id"]),
                str(event["event_type"]),
                str(event["recorded_at"]),
                payload,
                str(event["provenance"]),
            )],
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="explicit provider coverage receipt is not latest",
        ):
            supervisor.commit(
                request,
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()
