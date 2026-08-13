from __future__ import annotations

from pathlib import Path

import pytest

from aoi_orgware.frozen_json import thaw_json_payload
from aoi_orgware.company.legacy_bridge_contract import LEGACY_BRIDGE_OBSERVATION_V1
from aoi_orgware.company.legacy_bridge_health import LEGACY_BRIDGE_COVERAGE_V1
from aoi_orgware.company.legacy_bridge_views import (
    LegacyBridgeViewError,
    project_legacy_bridge_dashboard,
)
from aoi_orgware.company.views import CompanyViewService
from tests.company_v05.test_legacy_bridge import _entry, _raw, _snapshot
from tests.company_v05.test_legacy_bridge_supervisor import _initialized, _publish


NOW = "2026-08-06T12:00:00Z"
DASHBOARD = Path(__file__).parents[2] / "src/aoi_orgware/resources/dashboard/index.html"


def _payloads(supervisor, contract_type: str) -> list[dict]:  # type: ignore[no-untyped-def]
    return [
        thaw_json_payload(item.payload)
        for item in supervisor.objects(contract_type=contract_type)
    ]


def _snapshot_view(supervisor) -> dict:  # type: ignore[no-untyped-def]
    return CompanyViewService(supervisor._state, clock=lambda: NOW).section(
        "snapshot",
    )


def test_current_and_historical_views_show_every_legacy_entity_truthfully(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        result = _publish(supervisor)
        current = _snapshot_view(supervisor)
        historical = CompanyViewService(
            supervisor._state,
            clock=lambda: NOW,
        ).snapshot_at(result.global_sequence)
        observation = _payloads(
            supervisor,
            LEGACY_BRIDGE_OBSERVATION_V1,
        )[0]
        entities = observation["projection"]["entities"]
        data = current["data"]
        nodes = data["execution"]["nodes"]
        by_bridge_id = {node["bridge_entity_id"]: node for node in nodes}

        assert len(nodes) == len(entities) == 5
        assert len(by_bridge_id) == len(nodes)
        for entity in entities:
            node = by_bridge_id[entity["bridge_entity_id"]]
            assert node["execution_id"].startswith("legacy-bridge-")
            assert node["execution_kind"] == f"legacy_{entity['kind']}"
            assert node["engineering_status"] == entity["engineering_status"]
            assert node["runtime_status"] == "unknown"
            assert node["coverage_status"] == "degraded"
            assert node["effect_status"] == entity["effect_status"]
            assert node["authority"] == "none"
            assert node["projection_source"] == "legacy_bridge_observation"
            parent = entity["parent_bridge_entity_id"]
            if parent is None:
                assert node["parent_execution_id"] is None
                assert node["execution_path"] == [node["execution_id"]]
            else:
                assert node["parent_execution_id"] == by_bridge_id[parent][
                    "execution_id"
                ]
                assert node["execution_path"][-2:] == [
                    node["parent_execution_id"],
                    node["execution_id"],
                ]

        assert len(data["jobs"]) == 1
        job = data["jobs"][0]
        legacy_job = next(item for item in entities if item["kind"] == "job")
        assert job["bridge_entity_id"] == legacy_job["bridge_entity_id"]
        assert job["state"] == "running"
        assert job["runtime_status"] == "unknown"
        assert job["external_handle"] == {"availability": "unavailable"}
        assert job["mutation_intent_id"] is None

        summary = data["evidence"]["legacy_bridge"]
        assert summary["entity_count"] == 5
        assert summary["entity_counts"] == {
            "agent": 1,
            "job": 1,
            "needs_user": 1,
            "packet": 1,
            "task": 1,
        }
        assert summary["authority"] == "none"
        assert summary["dispatch_capability"] == "absent"
        assert data["meta"]["coverage"]["state"] == "degraded"
        assert data["meta"]["coverage"]["legacy_bridge"][0][
            "reason"
        ] == "provider_runtime_unavailable"
        categories = {
            alert["category"] for alert in data["alerts"]["alerts"]
        }
        assert {"needs_user", "legacy_bridge_coverage_degraded"} <= categories
        assert current["completeness"] == "partial"
        assert "legacy_bridge_coverage_degraded" in current["warnings"]

        for section in ("execution", "jobs", "evidence", "alerts"):
            assert historical["data"][section] == data[section]
    finally:
        supervisor.close()


def test_failed_ingest_projects_coverage_attention_without_entities(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        _publish(supervisor, b"{}")
        data = _snapshot_view(supervisor)["data"]
        assert data["execution"]["nodes"] == []
        assert data["jobs"] == []
        summary = data["evidence"]["legacy_bridge"]
        assert summary["state"] == "unavailable"
        assert summary["entity_count"] == 0
        assert summary["coverage"][0]["ingest_state"] == "degraded"
        assert summary["coverage"][0]["reason"] == "snapshot_invalid"
        assert data["meta"]["coverage"]["state"] == "degraded"
        assert any(
            alert["category"] == "legacy_bridge_coverage_degraded"
            for alert in data["alerts"]["alerts"]
        )
    finally:
        supervisor.close()


def test_explicitly_unjoined_legacy_job_remains_visible_as_orphan(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    raw = _raw(_snapshot([
        _entry("task", "task-1", "active"),
        _entry("job", "job-1", "queued"),
    ]))
    try:
        _publish(supervisor, raw)
        data = _snapshot_view(supervisor)["data"]
        job = data["jobs"][0]
        assert job["state"] == "queued"
        assert job["owner_execution_id"] is None
        orphans = data["execution"]["orphans"]
        assert [item["execution_id"] for item in orphans] == [job["job_id"]]
        assert orphans[0]["orphan_reason"] == "explicit_parent_unavailable"
        assert any(
            alert["category"] == "execution_orphan"
            and alert["execution_id"] == job["job_id"]
            for alert in data["alerts"]["alerts"]
        )
    finally:
        supervisor.close()


def test_projection_rejects_ambiguous_scope_instead_of_overwriting(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        _publish(supervisor)
        observation = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)[0]
        coverage = _payloads(supervisor, LEGACY_BRIDGE_COVERAGE_V1)[0]
        with pytest.raises(
            LegacyBridgeViewError,
            match="ambiguous scope",
        ):
            project_legacy_bridge_dashboard(
                [observation, observation],
                [coverage],
            )
    finally:
        supervisor.close()


def test_packaged_dashboard_renders_each_legacy_truth_axis() -> None:
    source = DASHBOARD.read_text(encoding="utf-8")

    for axis in ("engineering", "runtime", "coverage", "effect"):
        assert f'pill("{axis}", item.{axis}_status ?? "unknown")' in source
    assert "${truthPills(detail)}" in source
    assert source.count("${truthPills(node)}") == 2
    assert "${truthPills(job)}" in source
