from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.service import (
    CompanyServiceOperationError,
    dispatch_service_department,
)
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_company_service_chief import (
    _carrier,
    _consume,
    _now,
    _prepare,
    _resident,
    _slot,
    _utc,
)


def _chief_and_departments(
    slot: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with CompanySupervisor.open(slot) as supervisor:
        term = next(
            dict(item.payload)
            for item in supervisor.objects(contract_type="chief_term_v1")
        )
        execution = next(
            dict(item.payload)
            for item in supervisor.objects(contract_type="execution_node_v1")
            if item.payload["role"] == "chief"
        )
        departments = [
            dict(item.payload)
            for item in supervisor.objects(contract_type="department_identity_v1")
        ]
    return {**term, "chief_execution_id": execution["execution_id"]}, departments


def _dispatch(
    slot: Path,
    runtime: Path,
    chief: dict[str, Any],
    department: dict[str, Any],
    *,
    label: str,
    task_id: str | None = None,
    admission_command_id: str | None = None,
) -> dict[str, Any]:
    return dispatch_service_department(
        slot,
        chief_id=str(chief["chief_id"]),
        carrier_id=str(chief["carrier_id"]),
        term=int(chief["term"]),
        epoch=int(chief["epoch"]),
        chief_execution_id=str(chief["chief_execution_id"]),
        department_id=str(department["department_id"]),
        enqueue_transaction_id=f"{label}-enqueue-transaction",
        enqueue_command_id=f"{label}-enqueue-command",
        admission_transaction_id=f"{label}-admission-transaction",
        admission_command_id=(
            admission_command_id or f"{label}-admission-command"
        ),
        dispatch_request_id=f"{label}-dispatch",
        reservation_id=f"{label}-reservation",
        task_id=task_id or f"{label}-task",
        packet_id=f"{label}-packet",
        route_policy_id=f"{label}-route",
        requested_role=f"{department['name'].lower()}_lead",
        requested_capability_tier="standard",
        runtime_root=runtime,
    )


def test_resident_dispatch_admits_three_departments_and_replays_exactly(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    chief, departments = _chief_and_departments(slot)
    with _resident(slot, runtime) as descriptor:
        results = [
            _dispatch(slot, runtime, chief, department, label=f"department-{index}")
            for index, department in enumerate(departments, start=1)
        ]
        assert all(result["queued_reason"] is None for result in results)
        assert all(
            result["admission_result"] is not None for result in results
        )

        replay = _dispatch(
            slot,
            runtime,
            chief,
            departments[0],
            label="department-1",
        )
        assert replay["cursor"] == results[0]["cursor"]
        assert replay["enqueue_result"]["idempotent_replay"] is True
        assert replay["admission_result"]["idempotent_replay"] is True

        with pytest.raises(CompanyServiceOperationError) as admission_collision:
            _dispatch(
                slot,
                runtime,
                chief,
                departments[0],
                label="department-1",
                admission_command_id="divergent-admission-command",
            )
        assert admission_collision.value.status == 409
        assert admission_collision.value.effect is None
        assert admission_collision.value.cursor == results[0]["cursor"]

        with pytest.raises(CompanyServiceOperationError) as divergent:
            _dispatch(
                slot,
                runtime,
                chief,
                departments[0],
                label="department-1",
                task_id="divergent-task",
            )
        assert divergent.value.status == 409
        assert divergent.value.effect is None

        stale_chief = {**chief, "chief_execution_id": "stale-chief-execution"}
        with pytest.raises(CompanyServiceOperationError) as stale:
            _dispatch(
                slot,
                runtime,
                stale_chief,
                departments[0],
                label="stale-chief-new-enqueue",
            )
        assert stale.value.status == 409
        assert stale.value.effect is None

        telemetry_capability = json.loads(
            Path(descriptor["telemetry_capabilities"]["otel"]).read_text(
                encoding="utf-8",
            ),
        )
        request = Request(
            str(descriptor["control_url"]) + "/control/v1/departments/dispatch",
            data=b"{}",
            method="POST",
            headers={
                "Authorization": f"Bearer {telemetry_capability['bearer_token']}",
                "Content-Type": "application/json",
            },
        )
        with pytest.raises(HTTPError) as forbidden:
            urlopen(request, timeout=3.0)  # noqa: S310 - verified loopback descriptor
        assert forbidden.value.code == 403


def test_department_dispatch_resumes_from_enqueue_only_after_service_restart(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    chief, departments = _chief_and_departments(slot)
    department = departments[0]
    with CompanySupervisor.open(slot) as supervisor:
        recorded_at = _utc(_now())
        enqueue = supervisor.enqueue_department_dispatch_fenced(
            str(department["department_id"]),
            chief_id=str(chief["chief_id"]),
            carrier_id=str(chief["carrier_id"]),
            term=int(chief["term"]),
            epoch=int(chief["epoch"]),
            chief_execution_id=str(chief["chief_execution_id"]),
            transaction_id="restart-window-enqueue-transaction",
            command_id="restart-window-enqueue-command",
            dispatch_request_id="restart-window-dispatch",
            reservation_id="restart-window-reservation",
            task_id="restart-window-task",
            packet_id="restart-window-packet",
            route_policy_id="restart-window-route",
            requested_role=f"{department['name'].lower()}_lead",
            requested_capability_tier="standard",
            requested_at=recorded_at,
            recorded_at=recorded_at,
        )
        assert enqueue.dispatch_state == "queued"
        assert supervisor.record_by_transaction_id(
            "restart-window-admission-transaction",
        ) is None

    with _resident(slot, runtime):
        admitted = _dispatch(
            slot,
            runtime,
            chief,
            department,
            label="restart-window",
        )
        assert admitted["enqueue_result"]["idempotent_replay"] is True
        assert admitted["admission_result"]["idempotent_replay"] is False

    with _resident(slot, runtime):
        replay = _dispatch(
            slot,
            runtime,
            chief,
            department,
            label="restart-window",
        )
        assert replay["enqueue_result"]["idempotent_replay"] is True
        assert replay["admission_result"]["idempotent_replay"] is True
        assert replay["cursor"] == admitted["cursor"]


def test_takeover_allows_only_the_original_chief_tuple_to_replay(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    chief, departments = _chief_and_departments(slot)
    with _resident(slot, runtime):
        original = _dispatch(
            slot,
            runtime,
            chief,
            departments[0],
            label="takeover-replay",
        )
        contender = _carrier(2)
        prepared = _prepare(
            slot,
            runtime,
            contender,
            suffix="department-replay",
        )
        _consume(slot, runtime, prepared, contender)

        replay = _dispatch(
            slot,
            runtime,
            chief,
            departments[0],
            label="takeover-replay",
        )
        assert replay["cursor"] == original["cursor"]
        assert replay["enqueue_result"]["idempotent_replay"] is True
        assert replay["admission_result"]["idempotent_replay"] is True

        for changed_field in (
            {"chief_id": "different-chief"},
            {"carrier_id": "different-carrier"},
            {"term": int(chief["term"]) + 10},
            {"epoch": int(chief["epoch"]) + 10},
            {"chief_execution_id": "different-chief-execution"},
        ):
            with pytest.raises(CompanyServiceOperationError) as rejected:
                _dispatch(
                    slot,
                    runtime,
                    {**chief, **changed_field},
                    departments[0],
                    label="takeover-replay",
                )
            assert rejected.value.status == 409
            assert rejected.value.effect is None
