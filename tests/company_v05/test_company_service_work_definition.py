from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.contracts import company_contract_sha256
import aoi_orgware.company.service as service_module
from aoi_orgware.company.service import (
    CompanyServiceOperationError,
    activate_service_work_definition_enforcement,
    register_service_work_definition,
    service_status,
)
from aoi_orgware.company.work_definition_control_protocol import (
    WORK_DEFINITION_REGISTER_SCHEMA,
)
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_company_service_chief import (
    _dashboard,
    _resident,
)
from tests.company_v05.test_work_definition_registration import (
    _chief_fence,
    _initialize,
    _work_bundle,
)


FIXED_SERVICE_NOW = datetime(2026, 7, 27, 0, 10, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fixed_service_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep resident-generated events inside the deterministic grant window."""

    monkeypatch.setattr(
        service_module,
        "_trusted_utc_now",
        lambda: FIXED_SERVICE_NOW,
    )


def _chief_and_bundle(
    slot: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    bytes,
]:
    """Build one valid immutable bundle before the resident owns the slot."""

    with CompanySupervisor.open(slot) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        chief = _chief_fence(supervisor)
    return chief, task, packet, context, prompt


def _slot(tmp_path: Path) -> Path:
    """Use the bundle fixture's exact company binding, then release its writer."""

    supervisor = _initialize(tmp_path)
    slot = supervisor.slot_root
    supervisor.close()
    return slot


def _register(
    slot: Path,
    runtime: Path,
    chief: Mapping[str, Any],
    task: Mapping[str, Any],
    packet: Mapping[str, Any],
    context: Mapping[str, Any],
    prompt: bytes,
    *,
    transaction_id: str = "resident-work-register-transaction",
    command_id: str = "resident-work-register-command",
) -> dict[str, Any]:
    return register_service_work_definition(
        slot,
        task,
        packet,
        context,
        prompt,
        chief_id=str(chief["chief_id"]),
        carrier_id=str(chief["carrier_id"]),
        term=int(chief["term"]),
        epoch=int(chief["epoch"]),
        chief_execution_id=str(chief["chief_execution_id"]),
        transaction_id=transaction_id,
        command_id=command_id,
        runtime_root=runtime,
    )


def _activate(
    slot: Path,
    runtime: Path,
    chief: Mapping[str, Any],
    *,
    transaction_id: str = "resident-work-enforcement-transaction",
    command_id: str = "resident-work-enforcement-command",
) -> dict[str, Any]:
    return activate_service_work_definition_enforcement(
        slot,
        chief_id=str(chief["chief_id"]),
        carrier_id=str(chief["carrier_id"]),
        term=int(chief["term"]),
        epoch=int(chief["epoch"]),
        chief_execution_id=str(chief["chief_execution_id"]),
        transaction_id=transaction_id,
        command_id=command_id,
        runtime_root=runtime,
    )


def _register_envelope(
    descriptor: Mapping[str, Any],
    chief: Mapping[str, Any],
    task: Mapping[str, Any],
    packet: Mapping[str, Any],
    context: Mapping[str, Any],
    prompt: bytes,
) -> dict[str, Any]:
    company = descriptor["company"]
    return {
        "schema_version": WORK_DEFINITION_REGISTER_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "chief_id": chief["chief_id"],
        "carrier_id": chief["carrier_id"],
        "term": chief["term"],
        "epoch": chief["epoch"],
        "chief_execution_id": chief["chief_execution_id"],
        "transaction_id": "client-timestamp-transaction",
        "command_id": "client-timestamp-command",
        "task_revision": dict(task),
        "work_packet": dict(packet),
        "context_manifest": dict(context),
        "prompt_base64": base64.b64encode(prompt).decode("ascii"),
    }


def _service_cursor(slot: Path, runtime: Path) -> int:
    """Wait for the resident's initial Dashboard refresh to publish its cursor."""

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        cursor = service_status(slot, runtime_root=runtime)["status"]["cursor"]
        if type(cursor) is int:
            return cursor
        time.sleep(0.01)
    raise AssertionError("resident did not publish its initial ledger cursor")


def test_resident_register_replays_and_projects_read_only_work_view(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    chief, task, packet, context, prompt = _chief_and_bundle(slot)

    with _resident(slot, runtime) as descriptor:
        first = _register(slot, runtime, chief, task, packet, context, prompt)
        replay = _register(slot, runtime, chief, task, packet, context, prompt)

        assert first["result"]["idempotent_replay"] is False
        assert replay["result"]["idempotent_replay"] is True
        assert replay["cursor"] == first["cursor"]
        assert replay["result"]["global_sequence"] == first["cursor"]

        with urlopen(
            str(descriptor["dashboard_url"]) + "api/v1/work",
            timeout=3.0,
        ) as response:  # noqa: S310 - resident descriptor is verified loopback
            work_response = json.loads(response.read())
        assert isinstance(work_response, dict)
        work = work_response["data"]
        assert [item["task_revision_id"] for item in work["tasks"]] == [
            task["task_revision_id"],
        ]
        assert [item["packet_id"] for item in work["packets"]] == [
            packet["packet_id"],
        ]
        assert work["gate"]["active"] is False
        assert work["provider_worker"]["state"] == "unavailable"
        assert work["environment"]["provider_live_verified"] is False

        snapshot = _dashboard(descriptor)
        assert snapshot["data"]["work"] == work


def test_resident_rejects_stale_chief_and_divergent_transaction_without_cursor_advance(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    chief, task, packet, context, prompt = _chief_and_bundle(slot)

    with _resident(slot, runtime):
        before = _service_cursor(slot, runtime)
        with pytest.raises(CompanyServiceOperationError) as stale:
            _register(
                slot,
                runtime,
                {**chief, "chief_execution_id": "stale-chief-execution"},
                task,
                packet,
                context,
                prompt,
                transaction_id="stale-chief-transaction",
                command_id="stale-chief-command",
            )
        assert stale.value.status == 409
        assert stale.value.code == "work_definition_rejected"
        assert stale.value.effect is None
        assert _service_cursor(slot, runtime) == before

        first = _register(slot, runtime, chief, task, packet, context, prompt)
        with pytest.raises(CompanyServiceOperationError) as changed_execution:
            _register(
                slot,
                runtime,
                {**chief, "chief_execution_id": "changed-chief-execution"},
                task,
                packet,
                context,
                prompt,
            )
        assert changed_execution.value.status == 409
        assert changed_execution.value.code == "work_definition_rejected"
        assert changed_execution.value.effect is None
        assert _service_cursor(slot, runtime) == first["cursor"]
        divergent_packet = copy.deepcopy(packet)
        divergent_prompt = prompt + b" divergent"
        divergent_packet["prompt_ref"]["sha256"] = hashlib.sha256(
            divergent_prompt,
        ).hexdigest()
        divergent_packet["prompt_ref"]["size_bytes"] = len(divergent_prompt)
        divergent_packet["packet_sha256"] = company_contract_sha256({
            key: value
            for key, value in divergent_packet.items()
            if key != "packet_sha256"
        })
        with pytest.raises(CompanyServiceOperationError) as collision:
            _register(
                slot,
                runtime,
                chief,
                task,
                divergent_packet,
                context,
                divergent_prompt,
            )
        assert collision.value.status == 409
        assert collision.value.code == "work_definition_rejected"
        assert collision.value.effect is None
        assert service_status(slot, runtime_root=runtime)["status"]["cursor"] == first[
            "cursor"
        ]


def test_resident_enforcement_is_one_way_replays_and_rejects_client_timestamp(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    chief, task, packet, context, prompt = _chief_and_bundle(slot)

    with _resident(slot, runtime) as descriptor:
        registered = _register(slot, runtime, chief, task, packet, context, prompt)
        first = _activate(slot, runtime, chief)
        replay = _activate(slot, runtime, chief)
        assert first["result"]["idempotent_replay"] is False
        assert replay["result"]["idempotent_replay"] is True
        assert replay["cursor"] == first["cursor"]
        assert first["result"]["mode"] == "registered_launch_required"

        with pytest.raises(CompanyServiceOperationError) as stale_execution:
            _activate(
                slot,
                runtime,
                {**chief, "chief_execution_id": "stale-chief-execution"},
            )
        assert stale_execution.value.status == 409
        assert stale_execution.value.code == "work_definition_rejected"
        assert stale_execution.value.effect is None
        assert _service_cursor(slot, runtime) == first["cursor"]

        with pytest.raises(CompanyServiceOperationError) as second_activation:
            _activate(
                slot,
                runtime,
                chief,
                transaction_id="second-enforcement-transaction",
                command_id="second-enforcement-command",
            )
        assert second_activation.value.status == 409
        assert second_activation.value.code == "work_definition_rejected"
        assert second_activation.value.effect is None
        assert service_status(slot, runtime_root=runtime)["status"]["cursor"] == first[
            "cursor"
        ]

        timestamped = _register_envelope(
            descriptor,
            chief,
            task,
            packet,
            context,
            prompt,
        )
        timestamped["recorded_at"] = "2020-01-01T00:00:00Z"
        request = Request(
            str(descriptor["control_url"])
            + "/control/v1/work-definitions/register",
            data=json.dumps(timestamped, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {descriptor['bearer_token']}",
                "Content-Type": "application/json",
            },
        )
        with pytest.raises(HTTPError) as rejected_timestamp:
            urlopen(request, timeout=3.0)  # noqa: S310 - resident descriptor is verified loopback
        assert rejected_timestamp.value.code == 400
        assert json.loads(rejected_timestamp.value.read()) == {
            "error": "invalid_request_fields",
        }
        assert service_status(slot, runtime_root=runtime)["status"]["cursor"] == first[
            "cursor"
        ]

        with urlopen(
            str(descriptor["dashboard_url"]) + "api/v1/work",
            timeout=3.0,
        ) as response:  # noqa: S310 - resident descriptor is verified loopback
            work_response = json.loads(response.read())
        assert isinstance(work_response, dict)
        assert work_response["data"]["gate"]["active"] is True
        assert work_response["cursor"] == first["cursor"]
        assert registered["cursor"] < first["cursor"]
