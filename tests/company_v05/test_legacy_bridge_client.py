from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company import legacy_bridge_client as client
from aoi_orgware.company import legacy_bridge_client_receipts as receipt_store
from aoi_orgware.company.contracts import (
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.discovery import BoundCompanyTarget
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.company.legacy_bridge_contract import legacy_bridge_scope_id
from aoi_orgware.company.legacy_bridge_control_protocol import (
    LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
    LegacyBridgePrestartQueryCommand,
)
from aoi_orgware.company.legacy_bridge_health import legacy_bridge_attempt_id
from aoi_orgware.company.legacy_bridge_ingest_protocol import LegacyBridgeIngestCommand
from aoi_orgware.company.legacy_bridge_publisher import LegacyBridgeIngestResult
from aoi_orgware.company.legacy_bridge_ingest_protocol import (
    build_legacy_bridge_ingest_wire_result,
)
from aoi_orgware.company.legacy_bridge_contract import build_legacy_bridge_observation
from aoi_orgware.company.service import CompanyServiceOperationError


ARCHIVE = "a" * 64
MANIFEST = "b" * 64
POINTER = "c" * 64
HEAD = "d" * 64
STATE = "e" * 64
T0 = "2026-08-05T08:00:00Z"


def _source(
    observed_at: str,
    *,
    state_sha256: str = STATE,
    source_version: str = "0.4.0a4",
) -> bytes:
    record = {
        "kind": "task",
        "legacy_id": "task-1",
        "parent_kind": None,
        "parent_legacy_id": None,
        "stated_status": "active",
        "source_record_sha256": hashlib.sha256(b"task-1").hexdigest(),
        "receipt_refs": [],
    }
    return canonical_company_json_bytes({
        "document_type": "legacy_bridge_snapshot_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_kind": "aoi_legacy_v04",
        "source_version": source_version,
        "legacy_archive_sha256": ARCHIVE,
        "legacy_state_sha256": state_sha256,
        "legacy_receipt_set_sha256": None,
        "legacy_receipt_quality": "unavailable",
        "observed_at": observed_at,
        "task_id": "task-1",
        "entries": [record],
    })


def _target(slot: Path, *, state: str = "running") -> BoundCompanyTarget:
    return BoundCompanyTarget(
        slot_root=slot,
        company_id="company-1",
        manifest_sha256=MANIFEST,
        manifest={
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
        },
        service_state=state,
        dashboard_url="http://127.0.0.1:32100/",
        warnings=(),
    )


def _descriptor(service_id: str = "resident-1") -> dict[str, Any]:
    return {
        "schema_version": "synthetic",
        "service_instance_id": service_id,
        "company": {
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "manifest_sha256": MANIFEST,
            "pointer_sha256": POINTER,
        },
        "control_url": "http://127.0.0.1:32101",
        "bearer_token": "f" * 64,
        "telemetry_capabilities": {},
    }


def _ingest_result(command: LegacyBridgeIngestCommand) -> dict[str, Any]:
    projection = normalize_legacy_bridge_snapshot(command.source_document)
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=command.legacy_archive_sha256,
        task_identity_digest=command.task_identity_digest,
    )
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=command.source_document_sha256,
        source_document_size_bytes=len(command.source_document),
    )
    observation = build_legacy_bridge_observation(
        projection,
        ingested_at=command.received_at,
    )
    result = LegacyBridgeIngestResult(
        transaction_id=f"legacy-bridge-transaction-{attempt}",
        command_id=f"legacy-bridge-command-{attempt}",
        bridge_scope_id=scope,
        assessment_id=company_contract_sha256({
            "domain": "aoi.legacy-bridge.coverage.v1",
            "attempt_id": attempt,
        }),
        observation_id=observation["observation_id"],
        ingest_state="observed",
        coverage_state="degraded",
        effect="none",
        global_sequence=7,
        idempotent_replay=False,
    )
    return build_legacy_bridge_ingest_wire_result(command, result).as_dict()


def _query_result(
    command: LegacyBridgePrestartQueryCommand,
    *,
    reason: str,
) -> dict[str, Any]:
    satisfied = reason == "current_structural_ingest_observed"
    degraded = reason == "current_ingest_degraded"
    evidence = satisfied or degraded
    attempt = legacy_bridge_attempt_id(
        command.bridge_scope_id,
        source_document_sha256=command.source_document_sha256,
        source_document_size_bytes=len(command.source_document),
    )
    observation = build_legacy_bridge_observation(
        normalize_legacy_bridge_snapshot(command.source_document),
        ingested_at=normalize_legacy_bridge_snapshot(command.source_document).observed_at,
    )
    gate: dict[str, Any] = {
        "schema_version": 1,
        "company_id": command.company_id,
        "company_incarnation": command.company_incarnation,
        "lock_domain_generation": command.lock_domain_generation,
        "bridge_scope_id": command.bridge_scope_id,
        "decision": "satisfied" if satisfied else "blocked",
        "reason": reason,
        "ingest_state": "observed" if satisfied else "degraded",
        "provider_coverage_state": "degraded",
        "source_currentness": "exact" if evidence else "stale",
        "source_document_sha256": command.source_document_sha256,
        "source_document_size_bytes": len(command.source_document),
        "ledger_cursor": 7,
        "ledger_head_sha256": HEAD,
        "readmodel_cursor": 7,
        "readmodel_head_sha256": HEAD,
        "pointer_sha256": POINTER,
        "transaction_id": f"legacy-bridge-transaction-{attempt}" if evidence else None,
        "command_id": f"legacy-bridge-command-{attempt}" if evidence else None,
        "transaction_sha256": "1" * 64 if evidence else None,
        "coverage_record_id": "coverage-1" if evidence else None,
        "coverage_event_id": "coverage-event-1" if evidence else None,
        "coverage_global_sequence": 7 if evidence else None,
        "coverage_payload_sha256": "2" * 64 if evidence else None,
        "observation_record_id": "observation-1" if satisfied else None,
        "observation_event_id": "observation-event-1" if satisfied else None,
        "observation_global_sequence": 7 if satisfied else None,
        "observation_payload_sha256": "3" * 64 if satisfied else None,
        "assessment_id": "assessment-1" if evidence else None,
        "observation_id": observation["observation_id"] if satisfied else None,
        "publication_effect": "durable_readback" if evidence else "unknown",
        "authority": "none",
        "repo_write_capability": "absent",
        "dispatch_capability": "absent",
        "job_launch_capability": "absent",
    }
    unsigned = dict(gate)
    gate["gate_sha256"] = company_contract_sha256({
        "domain": "aoi.legacy-bridge.prestart-gate.v1",
        **unsigned,
    })
    return {
        "schema_version": LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
        "service_instance_id": command.service_instance_id,
        "company_id": command.company_id,
        "company_incarnation": command.company_incarnation,
        "lock_domain_generation": command.lock_domain_generation,
        "manifest_sha256": command.manifest_sha256,
        "bridge_scope_id": command.bridge_scope_id,
        "cursor": 7,
        "gate": gate,
    }


class Services:
    def __init__(self, slot: Path) -> None:
        self.target = _target(slot)
        self.descriptors = [_descriptor()]
        self.times = [T0, "2026-08-05T08:00:01Z", "2026-08-05T08:00:02Z"]
        self.ingest_calls = 0
        self.query_calls = 0
        self.query_reason = "current_structural_ingest_observed"
        self.ingest_error: Exception | None = None
        self.query_error: Exception | None = None

    def resolve(self, _repo_root: Path, _company_id: str | None) -> BoundCompanyTarget:
        return self.target

    def descriptor(self, _slot: Path) -> dict[str, Any]:
        return dict(self.descriptors[min(len(self.descriptors) - 1, 0)])

    def ingest(
        self,
        _descriptor_value: dict[str, Any],
        command: LegacyBridgeIngestCommand,
        _timeout_seconds: float,
    ) -> dict[str, Any]:
        self.ingest_calls += 1
        if self.ingest_error is not None:
            raise self.ingest_error
        return _ingest_result(command)

    def query(
        self,
        _descriptor_value: dict[str, Any],
        command: LegacyBridgePrestartQueryCommand,
        _timeout_seconds: float,
    ) -> dict[str, Any]:
        self.query_calls += 1
        if self.query_error is not None:
            raise self.query_error
        return _query_result(command, reason=self.query_reason)

    def now(self) -> str:
        return self.times.pop(0) if self.times else "2026-08-05T08:00:09Z"


def _run(
    tmp_path: Path,
    services: Services,
    source_calls: list[str],
    *,
    source_version: str = "0.4.0a4",
):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)

    def source_loader(
        _company_id: str,
        _incarnation: int,
        _generation: int,
        observed_at: str,
    ) -> bytes:
        source_calls.append(observed_at)
        return _source(observed_at, source_version=source_version)

    return client.run_legacy_bridge_ingest_v04(
        repo,
        task_id="task-1",
        legacy_archive_sha256=ARCHIVE,
        source_version=source_version,
        source_loader=source_loader,
        services=services,
    )


def _fill_attempt_markers(
    scope_root: Path,
    *,
    count: int,
    excluded: set[str] | None = None,
) -> None:
    observed = set() if excluded is None else set(excluded)
    index = 0
    while len(observed) < count:
        attempt = hashlib.sha256(f"AOI-SYNTHETIC-CAPACITY-{index}".encode()).hexdigest()
        index += 1
        if attempt in observed:
            continue
        receipt_store.attempt_root(scope_root, attempt, create=True)
        observed.add(attempt)


def test_committed_ingest_is_received_once_and_replayed_from_receipts(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    source_calls: list[str] = []

    first = _run(tmp_path, services, source_calls)
    services.query_error = RuntimeError("synthetic query outage")
    outage = _run(tmp_path, services, source_calls)
    services.query_error = None
    second = _run(tmp_path, services, source_calls)

    assert first.exit_code == second.exit_code == 0
    assert first.effect == second.effect == "committed"
    assert (outage.effect, outage.exit_code) == ("committed", 4)
    assert first.terminal_receipt_sha256 is not None
    assert outage.terminal_receipt_sha256 is None
    assert second.terminal_receipt_sha256 == first.terminal_receipt_sha256
    assert first.attempt_id == second.attempt_id
    assert services.ingest_calls == 1
    assert services.query_calls == len(source_calls) == 3
    assert first.source_matches_current_legacy_state
    assert first.public_dict()["dispatch_capability"] == "absent"


def test_semantic_replay_never_crosses_explicit_source_version(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)

    first = _run(tmp_path, services, [], source_version="0.4.0a4")
    second = _run(tmp_path, services, [], source_version="0.4.0a3")

    assert first.attempt_id != second.attempt_id
    assert first.source_document_sha256 != second.source_document_sha256
    assert services.ingest_calls == services.query_calls == 2


def test_source_observed_at_must_match_client_fence(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(client.LegacyBridgeClientError, match="source_binding_mismatch"):
        client.run_legacy_bridge_ingest_v04(
            repo,
            task_id="task-1",
            legacy_archive_sha256=ARCHIVE,
            source_version="0.4.0a4",
            source_loader=lambda *_args: _source("2026-08-05T09:00:00Z"),
            services=services,
        )
    assert services.ingest_calls == services.query_calls == 0


def test_terminal_none_replays_exact_durable_result_without_query_or_post(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.times = [T0, T0, T0, T0]
    services.ingest_error = CompanyServiceOperationError(
        409, "service_binding_mismatch", effect=None,
    )
    services.query_reason = "current_source_not_observed"

    first = _run(tmp_path, services, [])
    second = _run(tmp_path, services, [])

    assert first.exit_code == second.exit_code == 2
    assert first.effect == second.effect == "none"
    assert first.terminal_receipt_sha256 == second.terminal_receipt_sha256
    assert services.ingest_calls == services.query_calls == 1


def test_effect_unknown_is_never_resent_and_can_only_reconcile_by_readback(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.ingest_error = CompanyServiceOperationError(
        504,
        "effect_unknown",
        effect="effect_unknown",
    )
    services.query_reason = "current_source_not_observed"
    source_calls: list[str] = []

    first = _run(tmp_path, services, source_calls)
    second = _run(tmp_path, services, source_calls)
    services.query_reason = "current_structural_ingest_observed"
    third = _run(tmp_path, services, source_calls)
    services.query_error = RuntimeError("synthetic query outage")
    fourth = _run(tmp_path, services, source_calls)

    assert (first.exit_code, second.exit_code) == (3, 3)
    assert third.exit_code == 0
    assert (fourth.effect, fourth.exit_code) == ("committed", 4)
    assert third.reconciliation_receipt_sha256 is not None
    assert fourth.reconciliation_receipt_sha256 is None
    assert services.ingest_calls == 1
    assert services.query_calls == 4


def test_success_without_durable_readback_stays_unknown_until_reconciled(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.query_error = RuntimeError("synthetic query unavailable")

    first = _run(tmp_path, services, [])
    services.query_error = None
    second = _run(tmp_path, services, [])

    assert (first.effect, first.exit_code) == ("effect_unknown", 3)
    assert (second.effect, second.exit_code) == ("committed", 0)
    assert second.reconciliation_receipt_sha256 is not None
    assert services.ingest_calls == 1
    assert services.query_calls == 2


def test_committed_but_blocked_gate_returns_four(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.query_reason = "current_ingest_degraded"

    result = _run(tmp_path, services, [])

    assert result.effect == "committed"
    assert result.exit_code == 4
    assert result.gate_decision == "blocked"


def test_descriptor_drift_fails_before_mutating_request(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    descriptors = [_descriptor("resident-1"), _descriptor("resident-2")]
    calls = 0

    def descriptor(_slot: Path) -> dict[str, Any]:
        nonlocal calls
        value = descriptors[min(calls, 1)]
        calls += 1
        return value

    services.descriptor = descriptor  # type: ignore[method-assign]
    with pytest.raises(client.LegacyBridgeClientError, match="descriptor_changed"):
        _run(tmp_path, services, [])
    assert services.ingest_calls == services.query_calls == 0


def test_stopped_supervisor_fails_before_source_or_request(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.target = _target(slot, state="stopped")
    calls: list[str] = []

    with pytest.raises(client.LegacyBridgeClientError, match="not_running"):
        _run(tmp_path, services, calls)
    assert calls == []
    assert services.ingest_calls == services.query_calls == 0


def test_post_send_terminal_publication_failure_returns_three_without_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    original = client._publish_exact

    def fail_terminal(path: Path, payload: bytes, **kwargs: Any) -> bool:
        if path.name == "terminal.json":
            raise OSError("AOI-SYNTHETIC-FIXTURE-V1")
        return original(path, payload, **kwargs)

    monkeypatch.setattr(client, "_publish_exact", fail_terminal)
    first = _run(tmp_path, services, [])
    monkeypatch.setattr(client, "_publish_exact", original)
    services.query_reason = "current_source_not_observed"
    second = _run(tmp_path, services, [])

    assert first.exit_code == second.exit_code == 3
    assert first.terminal_receipt_sha256 is None
    assert second.terminal_receipt_sha256 is not None
    assert services.ingest_calls == 1
    assert services.query_calls == 2


def test_terminal_publication_recovery_requires_durable_terminal_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    original = client._publish_exact

    def fail_terminal(path: Path, payload: bytes, **kwargs: Any) -> bool:
        if path.name == "terminal.json":
            raise OSError("AOI-SYNTHETIC-FIXTURE-V1")
        return original(path, payload, **kwargs)

    monkeypatch.setattr(client, "_publish_exact", fail_terminal)
    first = _run(tmp_path, services, [])
    monkeypatch.setattr(client, "_publish_exact", original)
    second = _run(tmp_path, services, [])

    assert first.exit_code == 3
    assert first.terminal_receipt_sha256 is None
    assert second.exit_code == 0
    assert second.terminal_receipt_sha256 is not None
    assert services.ingest_calls == 1
    assert services.query_calls == 2


def test_compact_receipt_path_preserves_full_scope_and_attempt_ids(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)

    result = _run(tmp_path, services, [])

    scope_root = slot / "cv1" / "lb" / result.bridge_scope_id[:32]
    attempt_root = scope_root / result.attempt_id[:32]
    prepared = json.loads((attempt_root / "prepared.json").read_text(encoding="utf-8"))
    assert (scope_root / "scope.id").read_text(encoding="ascii") == result.bridge_scope_id
    assert (attempt_root / "attempt.id").read_text(encoding="ascii") == result.attempt_id
    assert prepared["bridge_scope_id"] == result.bridge_scope_id
    assert prepared["attempt_id"] == result.attempt_id
    assert len(result.bridge_scope_id) == len(result.attempt_id) == 64


def test_compact_scope_and_attempt_prefix_collisions_fail_closed(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    first_scope = "a" * 64
    other_scope = "a" * 32 + "b" * 32
    scope_root = receipt_store.ensure_scope_root(slot, first_scope)

    with pytest.raises(client.LegacyBridgeClientError, match="scope_path_collision"):
        receipt_store.ensure_scope_root(slot, other_scope)

    first_attempt = "c" * 64
    other_attempt = "c" * 32 + "d" * 32
    receipt_store.attempt_root(scope_root, first_attempt, create=True)
    with pytest.raises(client.LegacyBridgeClientError, match="attempt_path_collision"):
        receipt_store.attempt_root(scope_root, other_attempt, create=True)


def test_source_only_crash_resumes_same_attempt_without_duplicate_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.times = [T0, T0, T0, T0]
    original = client._publish_exact
    failed = False

    def fail_first_prepared(path: Path, payload: bytes, **kwargs: Any) -> bool:
        nonlocal failed
        if path.name == "prepared.json" and not failed:
            failed = True
            raise client.LegacyBridgeClientError("synthetic_prepared_publication_failure")
        return original(path, payload, **kwargs)

    monkeypatch.setattr(client, "_publish_exact", fail_first_prepared)
    with pytest.raises(client.LegacyBridgeClientError, match="synthetic_prepared"):
        _run(tmp_path, services, [])
    monkeypatch.setattr(client, "_publish_exact", original)

    result = _run(tmp_path, services, [])

    assert result.exit_code == 0
    assert services.ingest_calls == 1
    assert services.query_calls == 1
    scope_root = slot / "cv1" / "lb" / result.bridge_scope_id[:32]
    assert len([path for path in scope_root.iterdir() if path.is_dir()]) == 1


def test_attempt_capacity_seals_before_new_receipt_or_post(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    source = _source(T0)
    projection = normalize_legacy_bridge_snapshot(source)
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=ARCHIVE,
        task_identity_digest=projection.task_identity_digest,
    )
    scope_root = receipt_store.ensure_scope_root(slot, scope)
    for index in range(receipt_store.ATTEMPT_LIMIT):
        attempt = hashlib.sha256(f"AOI-SYNTHETIC-ATTEMPT-{index}".encode()).hexdigest()
        receipt_store.attempt_root(scope_root, attempt, create=True)

    result = _run(tmp_path, services, [])

    assert result.exit_code == 4
    assert result.effect == "none"
    assert result.gate_reason == "successor_rollover_required"
    assert result.prepared_receipt_sha256 is None
    assert result.capacity_receipt_sha256 is not None
    assert services.ingest_calls == 0
    assert services.query_calls == 0


def test_attempt_256_is_admitted_once_before_scope_becomes_saturated(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    projection = normalize_legacy_bridge_snapshot(_source(T0))
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=ARCHIVE,
        task_identity_digest=projection.task_identity_digest,
    )
    scope_root = receipt_store.ensure_scope_root(slot, scope)
    _fill_attempt_markers(scope_root, count=receipt_store.ATTEMPT_LIMIT - 1)

    result = _run(tmp_path, services, [])

    observed = receipt_store.inventory(scope_root, scope)
    assert result.exit_code == 0
    assert services.ingest_calls == services.query_calls == 1
    assert len(observed.attempt_ids) == receipt_store.ATTEMPT_LIMIT
    assert observed.capacity_receipt is None


def test_saturation_does_not_block_matching_committed_readback(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    first = _run(tmp_path, services, [])
    scope_root = slot / "cv1" / "lb" / first.bridge_scope_id[:32]
    _fill_attempt_markers(
        scope_root,
        count=receipt_store.ATTEMPT_LIMIT,
        excluded={first.attempt_id},
    )

    second = _run(tmp_path, services, [])

    assert second.exit_code == 0
    assert second.attempt_id == first.attempt_id
    assert services.ingest_calls == 1
    assert services.query_calls == 2
    assert not (scope_root / "capacity.json").exists()


def test_saturation_does_not_retry_effect_unknown_attempt(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.ingest_error = CompanyServiceOperationError(
        504,
        "effect_unknown",
        effect="effect_unknown",
    )
    services.query_reason = "current_source_not_observed"
    first = _run(tmp_path, services, [])
    scope_root = slot / "cv1" / "lb" / first.bridge_scope_id[:32]
    _fill_attempt_markers(
        scope_root,
        count=receipt_store.ATTEMPT_LIMIT,
        excluded={first.attempt_id},
    )

    second = _run(tmp_path, services, [])

    assert first.exit_code == second.exit_code == 3
    assert services.ingest_calls == 1
    assert services.query_calls == 2
    assert not (scope_root / "capacity.json").exists()


def test_capacity_publication_failure_is_none_before_query_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    projection = normalize_legacy_bridge_snapshot(_source(T0))
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=ARCHIVE,
        task_identity_digest=projection.task_identity_digest,
    )
    scope_root = receipt_store.ensure_scope_root(slot, scope)
    _fill_attempt_markers(scope_root, count=receipt_store.ATTEMPT_LIMIT)
    original = receipt_store.publish_exact

    def fail_capacity(path: Path, payload: bytes, **kwargs: Any) -> bool:
        if path.name == "capacity.json":
            raise OSError("AOI-SYNTHETIC-FIXTURE-V1")
        return original(path, payload, **kwargs)

    monkeypatch.setattr(receipt_store, "publish_exact", fail_capacity)
    result = _run(tmp_path, services, [])

    assert result.exit_code == 4
    assert result.effect == "none"
    assert result.gate_reason == "capacity_receipt_publication_failed"
    assert result.capacity_receipt_sha256 is None
    assert services.ingest_calls == services.query_calls == 0


def test_parent_directory_sync_flushes_and_closes_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, Any]] = []

    def open_directory(path: Path, flags: int) -> int:
        calls.append(("open", (path, flags)))
        return 41

    monkeypatch.setattr(receipt_store.os, "open", open_directory)
    monkeypatch.setattr(
        receipt_store.os,
        "fsync",
        lambda descriptor: calls.append(("fsync", descriptor)),
    )
    monkeypatch.setattr(
        receipt_store.os,
        "close",
        lambda descriptor: calls.append(("close", descriptor)),
    )

    receipt_store._sync_parent_directory(tmp_path)

    assert calls[0][0] == "open"
    assert calls[1:] == [("fsync", 41), ("close", 41)]


def test_inventory_recovers_unpublished_and_linked_private_temporaries(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    source = _source(T0)
    projection = normalize_legacy_bridge_snapshot(source)
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=ARCHIVE,
        task_identity_digest=projection.task_identity_digest,
    )
    scope_root = receipt_store.ensure_scope_root(slot, scope)

    unpublished_root = receipt_store.attempt_root(scope_root, "b" * 64, create=True)
    unpublished = unpublished_root / f".aoi-cv1-source.json-{'1' * 32}.tmp"
    unpublished.write_bytes(b"AOI-SYNTHETIC-FIXTURE-V1")

    linked_attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=hashlib.sha256(source).hexdigest(),
        source_document_size_bytes=len(source),
    )
    linked_root = receipt_store.attempt_root(scope_root, linked_attempt, create=True)
    linked = linked_root / f".aoi-cv1-source.json-{'2' * 32}.tmp"
    linked.write_bytes(source)
    os.link(linked, linked_root / "source.json")

    observed = receipt_store.inventory(scope_root, scope)

    assert observed.attempts == ()
    assert not unpublished.exists()
    assert not linked.exists()
    assert (linked_root / "source.json").read_bytes() == source


def test_inventory_rejects_divergent_private_temporary(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    scope = "a" * 64
    scope_root = receipt_store.ensure_scope_root(slot, scope)
    attempt_root = receipt_store.attempt_root(scope_root, "b" * 64, create=True)
    (attempt_root / "source.json").write_bytes(b"published")
    temporary = attempt_root / f".aoi-cv1-source.json-{'3' * 32}.tmp"
    temporary.write_bytes(b"divergent")

    with pytest.raises(client.LegacyBridgeClientError, match="divergent_client_temporary"):
        receipt_store.inventory(scope_root, scope)

    assert temporary.exists()
