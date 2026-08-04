"""Exact-current, non-authoritative legacy bridge pre-start gate tests."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import MAX_CONTRACT_BYTES, company_contract_sha256
from aoi_orgware.company.legacy_bridge_gate import (
    LegacyBridgeGateError,
    LegacyBridgePrestartGateV1,
    derive_legacy_bridge_prestart_gate,
)
from aoi_orgware.company.legacy_bridge import LegacyBridgeCompanyKey
from aoi_orgware.company.legacy_bridge_health import build_legacy_bridge_coverage
from aoi_orgware.company.state import CompanyQuerySnapshot, CompanyStateOwner
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_legacy_bridge import H, _identity_digest, _raw, _snapshot
from tests.company_v05.test_legacy_bridge_supervisor import _initialized, _publish


def _scope(supervisor: CompanySupervisor, raw: bytes) -> str:
    return _publish(supervisor, raw).bridge_scope_id


def test_exact_current_observation_satisfies_only_structural_preflight(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        scope = _scope(supervisor, raw)
        before = supervisor.heads()
        gate = derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
        assert type(gate) is LegacyBridgePrestartGateV1
        assert gate.decision == "satisfied"
        assert gate.reason == "current_structural_ingest_observed"
        assert gate.ingest_state == "observed"
        assert gate.provider_coverage_state == "degraded"
        assert gate.source_currentness == "exact"
        assert gate.publication_effect == "durable_readback"
        assert gate.authority == "none"
        assert gate.repo_write_capability == "absent"
        assert gate.dispatch_capability == "absent"
        assert gate.job_launch_capability == "absent"
        assert gate.coverage_event_id is not None
        assert gate.coverage_payload_sha256 is not None
        assert gate.observation_event_id is not None
        assert gate.observation_payload_sha256 is not None
        assert gate.observation_global_sequence == gate.coverage_global_sequence
        assert supervisor.heads() == before
        unsigned = gate.to_dict()
        unsigned.pop("gate_sha256")
        assert gate.gate_sha256 == company_contract_sha256(
            {"domain": "aoi.legacy-bridge.prestart-gate.v1", **unsigned}
        )
        assert not hasattr(gate, "__dict__")
    finally:
        supervisor.close()


def test_missing_degraded_and_stale_source_are_fail_closed(tmp_path: Path) -> None:
    raw = _raw(_snapshot())
    supervisor = _initialized(tmp_path)
    try:
        published = _publish(supervisor, raw)
        missing_scope = "0" * 64
        missing = derive_legacy_bridge_prestart_gate(
            supervisor._state,
            missing_scope,
            raw,
        )
        assert (missing.decision, missing.reason, missing.source_currentness) == (
            "unknown", "current_health_missing", "missing",
        )

        changed = _snapshot()
        changed["legacy_state_sha256"] = "c" * 64
        stale = derive_legacy_bridge_prestart_gate(
            supervisor._state,
            published.bridge_scope_id,
            _raw(changed),
        )
        assert (stale.decision, stale.reason, stale.source_currentness) == (
            "blocked", "current_source_not_observed", "stale",
        )
        assert stale.publication_effect == "unknown"
    finally:
        supervisor.close()

    degraded_supervisor = _initialized(tmp_path / "degraded")
    try:
        degraded_result = _publish(degraded_supervisor, b"{}")
        degraded = derive_legacy_bridge_prestart_gate(
            degraded_supervisor._state,
            degraded_result.bridge_scope_id,
            b"{}",
        )
        assert (degraded.decision, degraded.reason, degraded.ingest_state) == (
            "blocked", "current_ingest_degraded", "degraded",
        )
        assert degraded.source_currentness == "exact"
        assert degraded.provider_coverage_state == "degraded"
    finally:
        degraded_supervisor.close()


def test_company_health_degradation_is_unknown_even_with_matching_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        scope = _scope(supervisor, raw)
        original = CompanyStateOwner.query_snapshot

        def degraded(state: CompanyStateOwner) -> CompanyQuerySnapshot:
            snapshot = original(state)
            return replace(
                snapshot,
                health=replace(
                    snapshot.health,
                    status="degraded",
                    projection_status="degraded",
                    degradation_reasons=("synthetic_projection_degraded",),
                ),
            )

        monkeypatch.setattr(CompanyStateOwner, "query_snapshot", degraded)
        gate = derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
        assert (gate.decision, gate.reason) == (
            "unknown", "company_state_degraded",
        )
        assert gate.publication_effect == "unknown"
    finally:
        supervisor.close()


def test_instance_method_shadow_cannot_select_a_stale_snapshot(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    changed = _snapshot()
    changed["legacy_state_sha256"] = "c" * 64
    changed_raw = _raw(changed)
    try:
        first = _publish(supervisor, raw)
        stale = CompanyStateOwner.query_snapshot(supervisor._state)
        second = _publish(
            supervisor,
            changed_raw,
            received_at="2026-08-04T02:00:00Z",
        )
        supervisor._state.query_snapshot = lambda: stale  # type: ignore[method-assign]
        gate = derive_legacy_bridge_prestart_gate(
            supervisor._state,
            second.bridge_scope_id,
            changed_raw,
        )
        assert gate.decision == "satisfied"
        assert gate.ledger_cursor > stale.health.ledger_heads.global_head.global_sequence
        assert first.bridge_scope_id == second.bridge_scope_id
    finally:
        supervisor.close()


def test_reopen_rederives_byte_identical_gate_without_mutation(tmp_path: Path) -> None:
    raw = _raw(_snapshot())
    supervisor = _initialized(tmp_path)
    root = supervisor.slot_root
    scope = _scope(supervisor, raw)
    first = derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
    head = supervisor.heads()
    supervisor.close()

    with CompanySupervisor.open(root) as reopened:
        second = derive_legacy_bridge_prestart_gate(reopened._state, scope, raw)
        assert second == first
        assert reopened.heads() == head


def test_exact_owner_bounded_bytes_and_scope_fail_typed(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    try:
        scope = _publish(supervisor).bridge_scope_id
        invalid_calls: tuple[tuple[Any, Any, Any], ...] = (
            (object(), scope, b"{}"),
            (supervisor._state.query_snapshot(), scope, b"{}"),
            (supervisor._state, "A" * 64, b"{}"),
            (supervisor._state, scope, bytearray(b"{}")),
            (supervisor._state, scope, b"x" * (MAX_CONTRACT_BYTES + 2)),
        )
        for state, candidate_scope, raw in invalid_calls:
            with pytest.raises(LegacyBridgeGateError):
                derive_legacy_bridge_prestart_gate(
                    cast(CompanyStateOwner, state),
                    cast(str, candidate_scope),
                    cast(bytes, raw),
                )
    finally:
        supervisor.close()


def test_forged_current_payload_is_typed_not_a_false_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        scope = _scope(supervisor, raw)
        original = CompanyStateOwner.query_snapshot

        def forged(state: CompanyStateOwner) -> CompanyQuerySnapshot:
            snapshot = original(state)
            objects = list(snapshot.objects)
            index = next(
                i for i, item in enumerate(objects)
                if item.contract_type == "LegacyBridgeCoverageObservationV1"
            )
            item = objects[index]
            payload = dict(cast(Mapping[str, Any], item.payload))
            payload["authority"] = "supervisor"
            objects[index] = replace(item, payload=payload)
            return replace(snapshot, objects=tuple(objects))

        monkeypatch.setattr(CompanyStateOwner, "query_snapshot", forged)
        with pytest.raises(
            LegacyBridgeGateError,
            match="current health payload is invalid",
        ):
            derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("record_id", "forged-record", "current health identity differs"),
        ("event_id", "forged-event", "current health event identity differs"),
        ("stream", "org", "current health metadata is malformed"),
    ),
)
def test_coverage_projection_metadata_is_cross_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    message: str,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        scope = _scope(supervisor, raw)
        original = CompanyStateOwner.query_snapshot

        def forged(state: CompanyStateOwner) -> CompanyQuerySnapshot:
            snapshot = original(state)
            objects = list(snapshot.objects)
            index = next(
                i for i, item in enumerate(objects)
                if item.contract_type == "LegacyBridgeCoverageObservationV1"
            )
            objects[index] = replace(objects[index], **{field: value})
            return replace(snapshot, objects=tuple(objects))

        monkeypatch.setattr(CompanyStateOwner, "query_snapshot", forged)
        with pytest.raises(LegacyBridgeGateError, match=message):
            derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
    finally:
        supervisor.close()


def test_foreign_company_and_missing_linked_observation_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        published = _publish(supervisor, raw)
        snapshot = CompanyStateOwner.query_snapshot(supervisor._state)
        coverage_index = next(
            i for i, item in enumerate(snapshot.objects)
            if item.contract_type == "LegacyBridgeCoverageObservationV1"
        )
        coverage_item = snapshot.objects[coverage_index]
        foreign = build_legacy_bridge_coverage(
            LegacyBridgeCompanyKey("other-company", 1, 0),
            legacy_archive_sha256=H,
            task_identity_digest=_identity_digest("task", "task-1"),
            source_document_sha256=coverage_item.payload["source_document_sha256"],
            source_document_size_bytes=coverage_item.payload[
                "source_document_size_bytes"
            ],
            ingest_state="observed",
            reason="provider_runtime_unavailable",
            assessed_at=coverage_item.payload["assessed_at"],
            observation_id=coverage_item.payload["observation_id"],
        )
        foreign_item = replace(
            coverage_item,
            object_key=foreign["bridge_scope_id"],
            record_id=foreign["assessment_id"],
            payload=foreign,
        )

        monkeypatch.setattr(
            CompanyStateOwner,
            "query_snapshot",
            lambda state: replace(snapshot, objects=(foreign_item,)),
        )
        with pytest.raises(LegacyBridgeGateError, match="health identity"):
            derive_legacy_bridge_prestart_gate(
                supervisor._state,
                foreign["bridge_scope_id"],
                raw,
            )

        monkeypatch.setattr(
            CompanyStateOwner,
            "query_snapshot",
            lambda state: replace(
                snapshot,
                objects=tuple(
                    item
                    for item in snapshot.objects
                    if item.contract_type != "LegacyBridgeObservationV1"
                ),
            ),
        )
        with pytest.raises(LegacyBridgeGateError, match="linked observation"):
            derive_legacy_bridge_prestart_gate(
                supervisor._state,
                published.bridge_scope_id,
                raw,
            )
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("record_id", "forged-observation-record"),
        ("event_id", "forged-observation-event"),
        ("stream", "execution"),
        ("global_sequence", 1),
    ),
)
def test_linked_observation_projection_metadata_is_cross_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        scope = _scope(supervisor, raw)
        snapshot = CompanyStateOwner.query_snapshot(supervisor._state)
        objects = list(snapshot.objects)
        index = next(
            i for i, item in enumerate(objects)
            if item.contract_type == "LegacyBridgeObservationV1"
        )
        objects[index] = replace(objects[index], **{field: value})
        monkeypatch.setattr(
            CompanyStateOwner,
            "query_snapshot",
            lambda state: replace(snapshot, objects=tuple(objects)),
        )
        with pytest.raises(LegacyBridgeGateError, match="linked observation"):
            derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
    finally:
        supervisor.close()


def test_cross_paired_valid_observation_is_rejected_by_durable_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    raw_a = _raw(_snapshot())
    changed = _snapshot()
    changed["legacy_state_sha256"] = "c" * 64
    raw_b = _raw(changed)
    try:
        published_a = _publish(supervisor, raw_a)
        snapshot_a = CompanyStateOwner.query_snapshot(supervisor._state)
        observation_a = next(
            item
            for item in snapshot_a.objects
            if item.contract_type == "LegacyBridgeObservationV1"
        )
        published_b = _publish(
            supervisor,
            raw_b,
            received_at="2026-08-04T02:00:00Z",
        )
        snapshot_b = CompanyStateOwner.query_snapshot(supervisor._state)
        observation_b = next(
            item
            for item in snapshot_b.objects
            if item.contract_type == "LegacyBridgeObservationV1"
        )
        coverage_b = next(
            item
            for item in snapshot_b.objects
            if item.contract_type == "LegacyBridgeCoverageObservationV1"
        )
        cross_coverage = build_legacy_bridge_coverage(
            LegacyBridgeCompanyKey(
                coverage_b.payload["company_id"],
                coverage_b.payload["company_incarnation"],
                coverage_b.payload["lock_domain_generation"],
            ),
            legacy_archive_sha256=H,
            task_identity_digest=_identity_digest("task", "task-1"),
            source_document_sha256=coverage_b.payload["source_document_sha256"],
            source_document_size_bytes=coverage_b.payload[
                "source_document_size_bytes"
            ],
            ingest_state="observed",
            reason="provider_runtime_unavailable",
            assessed_at=coverage_b.payload["assessed_at"],
            observation_id=observation_a.record_id,
        )
        forged: list[Any] = []
        for item in snapshot_b.objects:
            if item.contract_type == "LegacyBridgeObservationV1":
                forged.append(
                    replace(
                        observation_a,
                        event_id=observation_b.event_id,
                        global_sequence=observation_b.global_sequence,
                    )
                )
            elif item.contract_type == "LegacyBridgeCoverageObservationV1":
                forged.append(replace(coverage_b, payload=cross_coverage))
            else:
                forged.append(item)
        monkeypatch.setattr(
            CompanyStateOwner,
            "query_snapshot",
            lambda state: replace(snapshot_b, objects=tuple(forged)),
        )
        assert published_a.bridge_scope_id == published_b.bridge_scope_id
        with pytest.raises(LegacyBridgeGateError, match="durable event differs"):
            derive_legacy_bridge_prestart_gate(
                supervisor._state,
                published_b.bridge_scope_id,
                raw_b,
            )
    finally:
        supervisor.close()


def test_malformed_nested_snapshot_shape_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        scope = _scope(supervisor, raw)
        snapshot = CompanyStateOwner.query_snapshot(supervisor._state)
        monkeypatch.setattr(
            CompanyStateOwner,
            "query_snapshot",
            lambda state: replace(snapshot, health=cast(Any, object())),
        )
        with pytest.raises(
            LegacyBridgeGateError,
            match="current snapshot is unavailable",
        ):
            derive_legacy_bridge_prestart_gate(supervisor._state, scope, raw)
    finally:
        supervisor.close()


def test_effect_unknown_without_durable_readback_never_satisfies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aoi_orgware.company.ledger import LedgerCommitEffectUnknownError

    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot())
    try:
        monkeypatch.setattr(
            CompanySupervisor,
            "commit",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                LedgerCommitEffectUnknownError({"effect": "unknown"})
            ),
        )
        uncertain = _publish(supervisor, raw)
        assert uncertain.effect == "effect_unknown"
        gate = derive_legacy_bridge_prestart_gate(
            supervisor._state,
            uncertain.bridge_scope_id,
            raw,
        )
        assert (gate.decision, gate.reason, gate.publication_effect) == (
            "unknown", "current_health_missing", "unknown",
        )
    finally:
        supervisor.close()
