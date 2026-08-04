from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.frozen_json import thaw_json_payload
from aoi_orgware.company.contracts import (
    MAX_CONTRACT_BYTES,
    MAX_EVENT_PAYLOAD_BYTES,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import LedgerCommitEffectUnknownError
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.company.legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    build_legacy_bridge_observation,
    validate_legacy_bridge_observation,
)
from aoi_orgware.company.legacy_bridge_health import (
    LEGACY_BRIDGE_COVERAGE_V1,
    LegacyBridgeHealthError,
    legacy_bridge_attempt_id,
    validate_legacy_bridge_coverage,
)
from aoi_orgware.company.legacy_bridge_publisher import (
    LegacyBridgePublicationError,
    publish_legacy_bridge_snapshot,
)
from aoi_orgware.company.state import CompanyStateOwner
from aoi_orgware.company.supervisor import (
    CompanySupervisor,
    CompanySupervisorDashboardRefreshError,
)
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)
from tests.company_v05.test_legacy_bridge import (
    H,
    _entry,
    _identity_digest,
    _raw,
    _snapshot,
)
from tests.company_v05.test_supervisor import manifest


TASK_DIGEST = _identity_digest("task", "task-1")
R1 = "2026-08-04T01:00:00Z"
R2 = "2026-08-04T02:00:00Z"
R3 = "2026-08-04T03:00:00Z"


def _initialized(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "company",
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    )


def _publish(
    supervisor: CompanySupervisor,
    raw: bytes | None = None,
    *,
    received_at: str = R1,
):
    return publish_legacy_bridge_snapshot(
        supervisor,
        _raw(_snapshot()) if raw is None else raw,
        task_identity_digest=TASK_DIGEST,
        legacy_archive_sha256=H,
        received_at=received_at,
    )


def _payloads(supervisor: CompanySupervisor, contract_type: str) -> list[dict[str, Any]]:
    return [
        cast(dict[str, Any], thaw_json_payload(item.payload))
        for item in supervisor.objects(contract_type=contract_type)
    ]


def _event_contracts(supervisor: CompanySupervisor) -> list[str]:
    return [
        str(event.event["payload"]["contract_type"])
        for record in supervisor.records_after(0)
        for event in record.events
        if str(event.event["event_type"]).startswith("legacy.bridge.")
    ]


def test_valid_snapshot_is_one_durable_observation_and_degraded_coverage(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        before = supervisor.heads().global_head.global_sequence
        result = _publish(supervisor, raw)
        assert result.ingest_state == "observed"
        assert result.coverage_state == "degraded"
        assert result.effect == "none"
        assert result.global_sequence == before + 1
        assert result.idempotent_replay is False
        observations = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)
        coverage = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)
        assert len(observations) == len(coverage) == 1
        assert validate_legacy_bridge_observation(observations[0]) == observations[0]
        assert validate_legacy_bridge_coverage(coverage[0]) == coverage[0]
        assert observations[0]["observation_id"] == result.observation_id
        assert coverage[0]["observation_id"] == result.observation_id
        assert coverage[0]["reason"] == "provider_runtime_unavailable"
        assert coverage[0]["source_document_sha256"] == hashlib.sha256(raw).hexdigest()
        assert coverage[0]["source_document_size_bytes"] == len(raw)
        assert coverage[0]["legacy_spawn_job_preflight"] == (
            "not_enforced_by_observation_bridge"
        )
        assert set(_event_contracts(supervisor)) == {
            LEGACY_BRIDGE_OBSERVATION_V1,
            LEGACY_BRIDGE_COVERAGE_V1,
        }
    finally:
        supervisor.close()


def test_exact_retry_ignores_later_receive_time_and_adds_no_history(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        first = _publish(supervisor)
        head = supervisor.heads().global_head
        event_count = len(_event_contracts(supervisor))
        replay = _publish(supervisor, received_at=R2)
        assert replay == first._replace(idempotent_replay=True)
        assert supervisor.heads().global_head == head
        assert len(_event_contracts(supervisor)) == event_count
    finally:
        supervisor.close()


def test_malformed_snapshot_records_degraded_health_without_observation(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        result = _publish(supervisor, b"{}")
        assert result.ingest_state == "degraded"
        assert result.coverage_state == "degraded"
        assert result.observation_id is None
        assert not _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)
        coverage = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)
        assert len(coverage) == 1
        assert coverage[0]["reason"] == "snapshot_invalid"
        assert coverage[0]["observation_id"] is None
        assert _event_contracts(supervisor) == [LEGACY_BRIDGE_COVERAGE_V1]
    finally:
        supervisor.close()


def test_binding_mismatch_is_durable_degraded_truth_not_a_foreign_projection(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    foreign = _snapshot()
    foreign["company_id"] = "other-company"
    try:
        result = _publish(supervisor, _raw(foreign))
        assert result.ingest_state == "degraded"
        assert result.observation_id is None
        coverage = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)[0]
        assert coverage["company_id"] == "company-1"
        assert coverage["reason"] == "binding_mismatch"
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    ("agent_count", "expected_state", "expected_reason"),
    [
        (109, "observed", "provider_runtime_unavailable"),
        (110, "degraded", "projection_unpublishable"),
    ],
)
def test_projection_event_boundary_is_durable_without_truncation(
    tmp_path: Path,
    agent_count: int,
    expected_state: str,
    expected_reason: str,
) -> None:
    entries = [
        _entry("task", "task-1", "active"),
        _entry(
            "packet",
            "packet-1",
            "dispatched",
            parent=("task", "task-1"),
        ),
        *(
            _entry(
                "agent",
                f"agent-{index:03d}",
                "unknown",
                parent=("packet", "packet-1"),
            )
            for index in range(agent_count)
        ),
    ]
    raw = _raw(_snapshot(entries))
    projected = build_legacy_bridge_observation(
        normalize_legacy_bridge_snapshot(raw),
        ingested_at=R1,
    )
    projected_size = len(canonical_company_json_bytes(projected))
    supervisor = _initialized(tmp_path)
    try:
        before = supervisor.heads().global_head.global_sequence
        result = _publish(supervisor, raw)
        assert len(raw) < MAX_CONTRACT_BYTES
        assert (projected_size <= MAX_EVENT_PAYLOAD_BYTES) == (
            expected_state == "observed"
        )
        assert result.ingest_state == expected_state
        assert result.global_sequence == before + 1
        observations = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)
        assert bool(observations) == (expected_state == "observed")
        assert (result.observation_id is not None) == (expected_state == "observed")
        coverage = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)
        assert len(coverage) == 1
        assert coverage[0]["reason"] == expected_reason
        assert coverage[0]["source_document_sha256"] == hashlib.sha256(raw).hexdigest()
        assert coverage[0]["source_document_size_bytes"] == len(raw)
    finally:
        supervisor.close()


def test_new_snapshot_requires_monotonic_assessment_time(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    changed = _snapshot()
    changed["legacy_state_sha256"] = "c" * 64
    try:
        _publish(supervisor, received_at=R2)
        head = supervisor.heads().global_head
        with pytest.raises(
            LegacyBridgePublicationError,
            match="assessment time does not advance",
        ):
            _publish(supervisor, _raw(changed), received_at=R1)
        assert supervisor.heads().global_head == head
    finally:
        supervisor.close()


def test_failure_and_recovery_replace_health_without_erasing_last_observation(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    changed = _snapshot()
    changed["legacy_state_sha256"] = "c" * 64
    try:
        first = _publish(supervisor, received_at=R1)
        failed = _publish(supervisor, b"{}", received_at=R2)
        assert failed.observation_id is None
        assert _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)[0][
            "observation_id"
        ] == first.observation_id
        assert _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)[0][
            "reason"
        ] == "snapshot_invalid"
        recovered = _publish(supervisor, _raw(changed), received_at=R3)
        assert recovered.observation_id != first.observation_id
        assert _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)[0][
            "observation_id"
        ] == recovered.observation_id
        bridge_events = [
            event
            for record in supervisor.records_after(0)
            for event in record.events
            if str(event.event["event_type"]).startswith("legacy.bridge.")
        ]
        assert len(bridge_events) == 5
    finally:
        supervisor.close()


def test_restart_rebuild_and_exact_replay_preserve_current_and_history(
    tmp_path: Path,
) -> None:
    root = tmp_path / "company"
    supervisor = _initialized(tmp_path)
    owner = supervisor._state
    first = _publish(supervisor)
    expected_observation = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)
    expected_coverage = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)
    expected_records = supervisor.records_after(0)
    owner.rebuild_projection()
    assert _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1) == expected_observation
    assert _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1) == expected_coverage
    supervisor.close()

    reopened = CompanySupervisor(CompanyStateOwner.open(root))
    try:
        assert _payloads(reopened, LEGACY_BRIDGE_OBSERVATION_V1) == expected_observation
        assert _payloads(reopened, LEGACY_BRIDGE_COVERAGE_V1) == expected_coverage
        assert reopened.records_after(0) == expected_records
        assert _publish(reopened, received_at=R2) == first._replace(
            idempotent_replay=True,
        )
    finally:
        reopened.close()


def test_effect_unknown_returns_once_without_retry_or_false_durable_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    before = supervisor.heads().global_head
    calls = 0

    def uncertain(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise LedgerCommitEffectUnknownError({"effect": "unknown"})

    monkeypatch.setattr(CompanySupervisor, "commit", uncertain)
    try:
        result = _publish(supervisor)
        assert calls == 1
        assert result.effect == "effect_unknown"
        assert result.ingest_state == "unknown"
        assert result.coverage_state == "unknown"
        assert result.global_sequence is None
        assert result.observation_id is None
        assert supervisor.heads().global_head == before
    finally:
        supervisor.close()


def test_dashboard_refresh_failure_is_not_swallowed_and_exact_retry_replays(
    tmp_path: Path,
) -> None:
    class TransientFailingCache:
        calls = 0

        def refresh(self) -> int:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("synthetic Dashboard refresh failure")
            return self.calls

    supervisor = _initialized(tmp_path)
    cache = TransientFailingCache()
    supervisor._dashboard_cache = cast(Any, cache)
    try:
        with pytest.raises(CompanySupervisorDashboardRefreshError) as caught:
            _publish(supervisor)
        assert cache.calls == 1
        assert caught.value.result.record.global_sequence == (
            supervisor.heads().global_head.global_sequence
        )
        replay = _publish(supervisor, received_at=R2)
        assert cache.calls == 2
        assert replay.idempotent_replay is True
        assert replay.effect == "none"
        assert replay.observation_id is not None
    finally:
        supervisor.close()


def test_deterministic_transaction_collision_is_zero_append_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aoi_orgware.company.legacy_bridge_publisher as publisher

    supervisor = _initialized(tmp_path)
    first_raw = _raw(_snapshot())
    changed = _snapshot()
    changed["legacy_state_sha256"] = "c" * 64
    changed_raw = _raw(changed)
    try:
        first = _publish(supervisor, first_raw)
        head = supervisor.heads().global_head
        first_attempt = first.transaction_id.removeprefix(
            "legacy-bridge-transaction-",
        )
        monkeypatch.setattr(
            publisher,
            "legacy_bridge_attempt_id",
            lambda *args, **kwargs: first_attempt,
        )
        with pytest.raises(
            LegacyBridgePublicationError,
            match=r"durable (observation|coverage) differs from source",
        ):
            _publish(supervisor, changed_raw, received_at=R2)
        assert supervisor.heads().global_head == head
    finally:
        supervisor.close()


def test_canonical_preseed_with_crossed_event_payloads_is_not_replay(
    tmp_path: Path,
) -> None:
    source = _initialized(tmp_path / "source")
    try:
        published = _publish(source)
        record = source.record_by_transaction_id(published.transaction_id)
        assert record is not None
        events = [cast(dict[str, Any], thaw_json_payload(item.event)) for item in record.events]
    finally:
        source.close()

    target = _initialized(tmp_path / "target")
    try:
        crossed = [
            CompanyEventDraft(
                event_id=str(event["event_id"]),
                event_type=str(event["event_type"]),
                recorded_at=str(event["recorded_at"]),
                payload=cast(dict[str, Any], events[1 - index]["payload"]),
                provenance=str(event["provenance"]),
            )
            for index, event in enumerate(events)
        ]
        request = build_company_transaction_request(
            target.heads(),
            target._supervisor_authority(),
            transaction_id=published.transaction_id,
            command_id=published.command_id,
            events=crossed,
        )
        target.commit(request, recorded_at=R1)
        head = target.heads().global_head
        with pytest.raises(
            LegacyBridgePublicationError,
            match="durable event payload contract differs",
        ):
            _publish(target, received_at=R2)
        assert target.heads().global_head == head
    finally:
        target.close()


def test_task_terminal_does_not_become_provider_runtime_stopped(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    done = _snapshot()
    done["entries"][0]["stated_status"] = "done"
    done["entries"][0]["source_record_sha256"] = hashlib.sha256(
        b"task:task-1:done",
    ).hexdigest()
    try:
        _publish(supervisor, _raw(done))
        observation = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)[0]
        task = next(
            entity for entity in observation["projection"]["entities"]
            if entity["kind"] == "task"
        )
        assert task["engineering_status"] == "completed"
        assert task["runtime_status"] == "unknown"
        assert task["coverage_status"] == "degraded"
    finally:
        supervisor.close()


def test_exact_supervisor_and_bounded_source_are_fail_closed(tmp_path: Path) -> None:
    class DerivedSupervisor(CompanySupervisor):
        pass

    derived = DerivedSupervisor.initialize(
        tmp_path / "company",
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        with pytest.raises(LegacyBridgePublicationError, match="exact CompanySupervisor"):
            _publish(cast(CompanySupervisor, derived))
    finally:
        derived.close()
    exact = _initialized(tmp_path / "exact")
    try:
        head = exact.heads().global_head
        with pytest.raises(LegacyBridgePublicationError, match="bounded API"):
            _publish(exact, b"x" * (MAX_CONTRACT_BYTES + 2))
        assert exact.heads().global_head == head
    finally:
        exact.close()


def test_coverage_contract_rejects_authority_and_digest_forgery(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        _publish(supervisor)
        health = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)[0]
        for field, forged in (
            ("authority", "supervisor"),
            ("repo_write_capability", "present"),
            ("legacy_spawn_job_preflight", "enforced"),
            ("coverage_sha256", "0" * 64),
        ):
            changed = copy.deepcopy(health)
            changed[field] = forged
            with pytest.raises(LegacyBridgeHealthError):
                validate_legacy_bridge_coverage(changed)
        attempt = legacy_bridge_attempt_id(
            str(health["bridge_scope_id"]),
            source_document_sha256=str(health["source_document_sha256"]),
            source_document_size_bytes=int(health["source_document_size_bytes"]),
        )
        assert health["assessment_id"] == company_contract_sha256(
            {"domain": "aoi.legacy-bridge.coverage.v1", "attempt_id": attempt}
        )
    finally:
        supervisor.close()
