from __future__ import annotations

import copy
from pathlib import Path

from aoi_orgware.company.contracts import company_contract_sha256
from aoi_orgware.company.legacy_bridge_contract import LEGACY_BRIDGE_OBSERVATION_V1
from aoi_orgware.company.legacy_bridge_health import LEGACY_BRIDGE_COVERAGE_V1
from aoi_orgware.company.legacy_bridge_job_terminal import (
    LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
)
from aoi_orgware.company.legacy_bridge_job_terminal_publisher import (
    publish_legacy_bridge_job_terminal,
)
from aoi_orgware.company.legacy_bridge_views import (
    project_legacy_bridge_dashboard,
)
from aoi_orgware.company.views import CompanyViewService
from tests.company_v05.test_legacy_bridge import _raw
from tests.company_v05.test_legacy_bridge_job_terminal import (
    _terminal_evidence,
    _terminal_snapshot,
)
from tests.company_v05.test_legacy_bridge_supervisor import (
    R3,
    _initialized,
    _payloads,
    _publish,
)


NOW = "2026-08-08T00:10:00Z"


def _view(supervisor, cursor: int | None = None):  # type: ignore[no-untyped-def]
    service = CompanyViewService(supervisor._state, clock=lambda: NOW)
    return service.section("snapshot") if cursor is None else service.snapshot_at(cursor)


def _legacy_job(data: dict) -> tuple[dict, dict]:
    node = next(
        item for item in data["execution"]["nodes"]
        if item["execution_kind"] == "legacy_job"
    )
    job = next(item for item in data["jobs"] if item["job_id"] == node["execution_id"])
    return node, job


def test_terminal_receipt_enriches_same_entity_and_preserves_old_cursor(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        observation_cursor = supervisor.heads().global_head.global_sequence
        before = _view(supervisor)
        before_node, before_job = _legacy_job(before["data"])
        assert (
            before_node["runtime_status"], before_node["coverage_status"],
            before_node["effect_status"],
        ) == ("unknown", "degraded", "unknown")
        terminal = publish_legacy_bridge_job_terminal(
            supervisor, evidence, artifacts,
        )
        current = _view(supervisor)
        current_node, current_job = _legacy_job(current["data"])
        assert current_node["execution_id"] == before_node["execution_id"]
        assert current_node["parent_execution_id"] == before_node[
            "parent_execution_id"
        ]
        assert (
            current_node["engineering_status"], current_node["runtime_status"],
            current_node["coverage_status"], current_node["effect_status"],
        ) == ("blocked", "stopped", "degraded", "failed_known")
        assert current_node["projection_source"] == (
            "legacy_bridge_terminal_receipt"
        )
        assert current_node["terminal_receipt_id"] == terminal.receipt_id
        assert current_job["projection_source"] == (
            "legacy_bridge_terminal_receipt"
        )
        assert current_job["process_observation"]["state"] == "known"
        assert current_job["effect_evidence"]
        historical = _view(supervisor, observation_cursor)
        old_node, old_job = _legacy_job(historical["data"])
        assert old_node == before_node
        assert old_job == before_job
        assert old_node["runtime_status"] == "unknown"
        assert current["cursor"] == terminal.global_sequence
        assert "legacy_bridge_terminal_receipt_observed" in current["warnings"]
        assert current["completeness"] == "partial"
    finally:
        supervisor.close()


def test_no_receipt_keeps_existing_projection_byte_semantics(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    try:
        _publish(supervisor, _raw(_terminal_snapshot()))
        observations = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)
        coverages = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)
        legacy_call = project_legacy_bridge_dashboard(observations, coverages)
        explicit_empty = project_legacy_bridge_dashboard(
            observations, coverages, (),
        )
        assert explicit_empty == legacy_call
        node, job = _legacy_job(_view(supervisor)["data"])
        assert node["runtime_status"] == "unknown"
        assert job["effect_status"] == "unknown"
    finally:
        supervisor.close()


def test_later_source_drift_does_not_apply_stale_terminal_overlay(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        terminal = publish_legacy_bridge_job_terminal(
            supervisor, evidence, artifacts,
        )
        terminal_view = _view(supervisor, terminal.global_sequence)
        assert _legacy_job(terminal_view["data"])[0]["runtime_status"] == "stopped"
        changed = _terminal_snapshot()
        changed["legacy_state_sha256"] = "f" * 64
        job = next(item for item in changed["entries"] if item["kind"] == "job")
        job["source_record_sha256"] = "9" * 64
        latest = _publish(supervisor, _raw(changed), received_at=R3)
        current = _view(supervisor)
        node, projected_job = _legacy_job(current["data"])
        assert current["cursor"] == latest.global_sequence
        assert node["runtime_status"] == "unknown"
        assert node["effect_status"] == "unknown"
        assert projected_job["process_observation"]["state"] == "unknown"
        conflicts = [
            item for item in current["data"]["alerts"]["alerts"]
            if item["category"] == "legacy_bridge_terminal_conflict"
        ]
        assert len(conflicts) == 1
        assert conflicts[0]["execution_id"] == node["execution_id"]
        assert "legacy_bridge_terminal_conflict" in current["warnings"]
    finally:
        supervisor.close()


def test_packet_only_source_drift_removes_overlay_and_raises_conflict(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        changed = _terminal_snapshot()
        packet = next(
            item for item in changed["entries"] if item["kind"] == "packet"
        )
        packet["source_record_sha256"] = "7" * 64
        _publish(supervisor, _raw(changed), received_at=R3)
        current = _view(supervisor)
        node, job = _legacy_job(current["data"])
        assert node["runtime_status"] == "unknown"
        assert job["projection_source"] == "legacy_bridge_observation"
        conflicts = [
            item for item in current["data"]["alerts"]["alerts"]
            if item["category"] == "legacy_bridge_terminal_conflict"
        ]
        assert len(conflicts) == 1
        assert conflicts[0]["execution_id"] == node["execution_id"]
    finally:
        supervisor.close()


def test_divergent_valid_receipt_is_not_silently_selected(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        observations = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)
        coverages = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)
        receipt = _payloads(
            supervisor, LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
        )[0]
        forged = copy.deepcopy(receipt)
        forged["job_source_record_sha256"] = "8" * 64
        unsigned = {key: value for key, value in forged.items() if key != "receipt_sha256"}
        forged["receipt_sha256"] = company_contract_sha256(unsigned)
        projected = project_legacy_bridge_dashboard(
            observations, coverages, [forged],
        )
        node = next(
            item for item in projected.nodes
            if item["execution_kind"] == "legacy_job"
        )
        assert node["runtime_status"] == "unknown"
        assert node["projection_source"] == "legacy_bridge_observation"
        assert any(
            alert["category"] == "legacy_bridge_terminal_conflict"
            for alert in projected.alerts
        )
    finally:
        supervisor.close()
