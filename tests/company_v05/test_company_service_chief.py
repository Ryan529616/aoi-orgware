from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Iterator
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.checkpoint import verify_plain_checkpoint
from aoi_orgware.company.contracts import COMPANY_MANIFEST_V1, EXTERNAL_JOB_V1
from aoi_orgware.company.control_protocol import (
    CHIEF_TAKEOVER_PREPARE_SCHEMA,
    parse_chief_takeover_prepare,
)
from aoi_orgware.company.sanitized_export import verify_sanitized_export
import aoi_orgware.company.service as service_module
from aoi_orgware.company.service import (
    CompanyServiceOperationError,
    consume_service_chief_takeover,
    prepare_service_chief_takeover,
    runtime_descriptor_path,
    service_status,
    stop_service,
)
from aoi_orgware.company.supervisor import CompanySupervisor


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00",
        "Z",
    )


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _manifest(created_at: str) -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "c",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": created_at,
        "observation": {"state": "known", "reason": "observed"},
    }


def _carrier(number: int) -> dict[str, Any]:
    return {
        "carrier_id": f"carrier-{number}",
        "provider": "codex" if number % 2 == 0 else "claude",
        "model": f"model-{number}",
        "session_id": f"session-{number}",
        "thread_id": f"thread-{number}",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _slot(tmp_path: Path) -> Path:
    started_at = _now()
    slot = tmp_path / "c"
    with CompanySupervisor.initialize(
        slot,
        _manifest(_utc(started_at)),
        bootstrap_at=_utc(started_at),
        grant_expires_at=_utc(started_at + timedelta(days=1)),
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=_carrier(1),
    ):
        pass
    return slot


def _unknown_slot(tmp_path: Path) -> Path:
    started_at = _now()
    slot = tmp_path / "c"
    with CompanySupervisor.initialize(
        slot,
        _manifest(_utc(started_at)),
        bootstrap_at=_utc(started_at),
        grant_expires_at=_utc(started_at + timedelta(days=1)),
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=None,
    ):
        pass
    return slot


def _descriptor(slot: Path, runtime: Path) -> dict[str, Any]:
    value = json.loads(
        runtime_descriptor_path(slot, runtime_root=runtime).read_text(
            encoding="utf-8",
        ),
    )
    assert isinstance(value, dict)
    return value


def _await_descriptor(
    slot: Path,
    runtime: Path,
) -> dict[str, Any]:
    deadline = time.monotonic() + service_module._SERVICE_READINESS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if runtime_descriptor_path(slot, runtime_root=runtime).exists():
            status = service_status(slot, runtime_root=runtime, timeout_seconds=0.3)
            if status["state"] == "running":
                return _descriptor(slot, runtime)
        time.sleep(0.05)
    raise AssertionError("resident service did not become ready")


@contextmanager
def _resident(slot: Path, runtime: Path) -> Iterator[dict[str, Any]]:
    service = service_module._ResidentService(slot.resolve(), runtime.resolve(), 0.01)
    outcome: list[int | BaseException] = []

    def run() -> None:
        try:
            outcome.append(service.run())
        except BaseException as exc:  # retain the resident startup failure for the assertion
            outcome.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield _await_descriptor(slot, runtime)
    finally:
        if thread.is_alive():
            stop_service(slot, runtime_root=runtime)
            thread.join(timeout=10.0)
        assert not thread.is_alive()
        assert outcome == [0]


def _prepare(
    slot: Path,
    runtime: Path,
    carrier: dict[str, Any],
    *,
    suffix: str,
) -> dict[str, Any]:
    return prepare_service_chief_takeover(
        slot,
        carrier,
        user_action_ref=f"fresh-user-action-{suffix}",
        objective_sha256="e" * 64,
        scope_sha256="f" * 64,
        nonce_sha256=hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
        runtime_root=runtime,
    )


def _consume(
    slot: Path,
    runtime: Path,
    prepared: dict[str, Any],
    carrier: dict[str, Any],
    *,
    consumed_at: datetime | None = None,
    grant_expires_at: str | None = None,
) -> dict[str, Any]:
    consumed = consumed_at or (_now() + timedelta(seconds=2))
    consumed_value = _utc(consumed)
    return consume_service_chief_takeover(
        slot,
        prepared["capability"],
        carrier,
        consumed_at=consumed_value,
        grant_expires_at=grant_expires_at or _utc(consumed + timedelta(days=30)),
        runtime_root=runtime,
    )


def _dashboard(descriptor: dict[str, Any]) -> dict[str, Any]:
    with urlopen(descriptor["dashboard_url"] + "api/v1/snapshot", timeout=3.0) as response:  # noqa: S310 - descriptor is verified literal loopback
        value = json.loads(response.read())
    assert isinstance(value, dict)
    return value


def _queue_job(slot: Path) -> tuple[dict[str, Any], str]:
    with CompanySupervisor.open(slot) as supervisor:
        owner = next(
            item.payload
            for item in supervisor.objects(contract_type="execution_node_v1")
            if item.payload["carrier_id"] == "carrier-1"
        )
        supervisor.queue_external_job(
            str(owner["execution_id"]),
            job_id="durable-chief-service-job",
            job_execution_id="durable-chief-service-job-execution",
            mutation_intent_id="durable-chief-service-job-intent",
            command_bytes=b'{"tool":"vcs"}',
            command_media_type="application/json",
            scope_sha256="f" * 64,
            display_name="Durable Chief service job",
            objective="Keep the queued job unchanged across resident takeover.",
            authority_grant_id="durable-chief-service-job-grant",
            grant_expires_at=_utc(_now() + timedelta(days=1)),
            transaction_id="durable-chief-service-job-transaction",
            command_id="durable-chief-service-job-command",
            recorded_at=_utc(_now()),
        )
        job = next(
            dict(item.payload)
            for item in supervisor.objects(contract_type=EXTERNAL_JOB_V1)
            if item.payload["job_id"] == "durable-chief-service-job"
        )
        record = next(
            item
            for item in supervisor.records_after(0)
            if item.request["transaction_id"] == "durable-chief-service-job-transaction"
        )
        event_sha256 = next(
            event.event_sha256
            for event in record.events
            if event.event["payload"]["contract_type"] == EXTERNAL_JOB_V1
        )
    return job, event_sha256


def test_resident_chief_handoff_creates_verified_evidence_and_updates_dashboard(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    contender = _carrier(2)
    with _resident(slot, runtime) as descriptor:
        prepared = _prepare(slot, runtime, contender, suffix="winner")
        consumed = _consume(slot, runtime, prepared, contender)

        result = consumed["result"]
        evidence = consumed["pre_takeover_evidence"]
        assert result["outcome"] == "consumed"
        assert result["idempotent_replay"] is False
        assert evidence["state"] == "pre_takeover_verified"
        assert evidence["cursor"] == result["global_sequence"] - 1
        incarnation_root = next((slot / "incarnations").iterdir())
        checkpoint_path = incarnation_root / "checkpoints" / str(evidence["checkpoint_id"])
        export_path = incarnation_root / "exports" / f"{evidence['export_id']}.json"
        checkpoint = verify_plain_checkpoint(checkpoint_path)
        exported = verify_sanitized_export(export_path, checkpoint_path=checkpoint_path)
        assert checkpoint.sha256 == evidence["checkpoint_manifest_sha256"]
        assert exported.sha256 == evidence["export_sha256"]

        deadline = time.monotonic() + 3.0
        dashboard = _dashboard(descriptor)
        while (
            dashboard["data"]["company"]["chief"]["carrier"]["carrier_id"]
            != contender["carrier_id"]
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
            dashboard = _dashboard(descriptor)
        chief = dashboard["data"]["company"]["chief"]
        assert chief["carrier"]["carrier_id"] == contender["carrier_id"]
        assert chief["takeover_attempts"][0]["outcome"] == "consumed"


def test_resident_unknown_genesis_first_bind_becomes_visible_without_prior_execution(
    tmp_path: Path,
) -> None:
    slot = _unknown_slot(tmp_path)
    runtime = tmp_path / "runtime"
    contender = _carrier(2)
    with _resident(slot, runtime) as descriptor:
        prepared = _prepare(slot, runtime, contender, suffix="first-bind")
        consumed = _consume(slot, runtime, prepared, contender)

        assert consumed["result"]["outcome"] == "consumed"
        assert consumed["result"]["global_sequence"] == 2
        assert (
            consumed["pre_takeover_evidence"]["state"]
            == "pre_takeover_verified"
        )
        deadline = time.monotonic() + 3.0
        dashboard = _dashboard(descriptor)
        while (
            dashboard["data"]["company"]["chief"]["carrier"]["carrier_id"]
            != contender["carrier_id"]
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
            dashboard = _dashboard(descriptor)
        chief_nodes = [
            item
            for item in dashboard["data"]["execution"]["nodes"]
            if item["role"] == "chief"
        ]
        assert [item["carrier_id"] for item in chief_nodes] == [
            contender["carrier_id"],
        ]


def test_resident_chief_admin_and_telemetry_capabilities_are_isolated(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    with _resident(slot, runtime) as descriptor:
        telemetry = json.loads(
            Path(descriptor["telemetry_capabilities"]["codex_app_server"]).read_text(
                encoding="utf-8",
            ),
        )
        assert isinstance(telemetry, dict)
        request = Request(
            descriptor["control_url"] + "/control/v1/chief-takeover/prepare",
            data=b"{}",
            headers={
                "Authorization": f"Bearer {telemetry['bearer_token']}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as rejected_chief:
            urlopen(request, timeout=3.0)  # noqa: S310 - verified literal loopback
        assert rejected_chief.value.code == 403

        request = Request(
            descriptor["control_url"] + "/control/v1/telemetry/codex",
            data=b"{}",
            headers={
                "Authorization": f"Bearer {descriptor['bearer_token']}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as rejected_telemetry:
            urlopen(request, timeout=3.0)  # noqa: S310 - verified literal loopback
        assert rejected_telemetry.value.code == 403


def test_same_head_contenders_leave_one_consumed_and_one_visible_fenced_loser(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    winner = _carrier(2)
    loser = _carrier(3)
    with _resident(slot, runtime) as descriptor:
        first = _prepare(slot, runtime, winner, suffix="winner")
        second = _prepare(slot, runtime, loser, suffix="loser")
        assert (
            first["capability"]["expected_head_sha256"]
            == second["capability"]["expected_head_sha256"]
        )
        first_result = _consume(slot, runtime, first, winner)
        second_result = _consume(slot, runtime, second, loser)
        assert first_result["result"]["outcome"] == "consumed"
        assert second_result["result"]["outcome"] == "fenced"
        assert (
            second_result["pre_takeover_evidence"]["state"]
            == "not_required_fenced_head_drift"
        )

        deadline = time.monotonic() + 3.0
        attempts: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            attempts = _dashboard(descriptor)["data"]["company"]["chief"][
                "takeover_attempts"
            ]
            if {item["outcome"] for item in attempts} == {"consumed", "fenced"}:
                break
            time.sleep(0.05)
        assert {item["outcome"] for item in attempts} == {"consumed", "fenced"}


def test_graceful_restart_replays_exact_chief_handoff_and_preserves_queued_job(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    before_job, before_receipt = _queue_job(slot)
    contender = _carrier(2)
    with _resident(slot, runtime):
        prepared = _prepare(slot, runtime, contender, suffix="restart")
        consumed_at = _now() + timedelta(seconds=2)
        first = _consume(
            slot,
            runtime,
            prepared,
            contender,
            consumed_at=consumed_at,
        )
    with _resident(slot, runtime):
        replay = _consume(
            slot,
            runtime,
            prepared,
            contender,
            consumed_at=consumed_at,
        )
        assert replay["result"]["idempotent_replay"] is True
        assert replay["result"]["global_sequence"] == first["result"]["global_sequence"]
        assert replay["cursor"] == first["cursor"]
    with CompanySupervisor.open(slot) as reopened:
        after_job = next(
            dict(item.payload)
            for item in reopened.objects(contract_type=EXTERNAL_JOB_V1)
            if item.payload["job_id"] == "durable-chief-service-job"
        )
        after_record = next(
            item
            for item in reopened.records_after(0)
            if item.request["transaction_id"] == "durable-chief-service-job-transaction"
        )
        after_receipt = next(
            event.event_sha256
            for event in after_record.events
            if event.event["payload"]["contract_type"] == EXTERNAL_JOB_V1
        )
    assert after_job == before_job
    assert after_receipt == before_receipt


def test_unknown_first_bind_restart_replays_after_capability_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _unknown_slot(tmp_path)
    runtime = tmp_path / "runtime"
    clock = {"now": _now()}
    monkeypatch.setattr(service_module, "_trusted_utc_now", lambda: clock["now"])
    contender = _carrier(2)
    consumed_at = clock["now"] + timedelta(seconds=2)
    with _resident(slot, runtime):
        prepared = _prepare(
            slot,
            runtime,
            contender,
            suffix="first-bind-expired-replay",
        )
        first = _consume(
            slot,
            runtime,
            prepared,
            contender,
            consumed_at=consumed_at,
        )
    clock["now"] += timedelta(minutes=16)
    with _resident(slot, runtime):
        replay = _consume(
            slot,
            runtime,
            prepared,
            contender,
            consumed_at=consumed_at,
        )
    assert replay["result"]["idempotent_replay"] is True
    assert replay["result"]["global_sequence"] == 2
    assert replay["cursor"] == first["cursor"]
    assert (
        replay["pre_takeover_evidence"]
        == first["pre_takeover_evidence"]
    )


def test_expired_wall_clock_rejects_backdated_consume_before_takeover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    clock = {"now": _now()}
    monkeypatch.setattr(service_module, "_trusted_utc_now", lambda: clock["now"])
    service = service_module._ResidentService(slot.resolve(), runtime.resolve(), 0.01)
    outcome: list[int | BaseException] = []
    thread = threading.Thread(target=lambda: outcome.append(service.run()), daemon=True)
    thread.start()
    try:
        _await_descriptor(slot, runtime)
        contender = _carrier(2)
        prepared = _prepare(slot, runtime, contender, suffix="expired")
        clock["now"] += timedelta(minutes=16)
        consumed_at = clock["now"] - timedelta(minutes=15)
        with pytest.raises(CompanyServiceOperationError) as rejected:
            _consume(
                slot,
                runtime,
                prepared,
                contender,
                consumed_at=consumed_at,
            )
        assert rejected.value.code == "chief_capability_expired"
        assert rejected.value.effect is None
        assert service_status(slot, runtime_root=runtime)["status"]["cursor"] == 1
    finally:
        if thread.is_alive():
            stop_service(slot, runtime_root=runtime)
            thread.join(timeout=10.0)
    assert not thread.is_alive()
    assert outcome == [0]


def test_divergent_chief_retry_is_rejected_at_effect_unknown_boundary(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    contender = _carrier(2)
    with _resident(slot, runtime):
        prepared = _prepare(slot, runtime, contender, suffix="divergent")
        consumed_at = _now() + timedelta(seconds=2)
        first = _consume(
            slot,
            runtime,
            prepared,
            contender,
            consumed_at=consumed_at,
        )
        with pytest.raises(CompanyServiceOperationError) as rejected_time:
            _consume(
                slot,
                runtime,
                prepared,
                contender,
                consumed_at=consumed_at + timedelta(seconds=1),
            )
        assert rejected_time.value.code == "chief_takeover_conflict"
        assert rejected_time.value.effect == "effect_unknown"
        with pytest.raises(CompanyServiceOperationError) as rejected_expiry:
            _consume(
                slot,
                runtime,
                prepared,
                contender,
                consumed_at=consumed_at,
                grant_expires_at=_utc(consumed_at + timedelta(days=30, seconds=1)),
            )
        assert rejected_expiry.value.code == "chief_takeover_conflict"
        assert rejected_expiry.value.effect == "effect_unknown"
        assert (
            service_status(slot, runtime_root=runtime)["status"]["cursor"]
            == first["cursor"]
        )


def test_telemetry_saturation_reserves_four_admin_control_slots(tmp_path: Path) -> None:
    slot = _slot(tmp_path)
    service = service_module._ResidentService(
        slot.resolve(),
        (tmp_path / "runtime").resolve(),
        0.01,
    )
    company = {
        "company_id": "c",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        "pointer_sha256": "b" * 64,
    }
    service._company_binding = dict(company)
    descriptor = {"service_instance_id": service.service_instance_id, "company": company}
    raw = b'{"method":"thread/tokenUsage/updated","params":{}}'
    telemetry_command = service_module._telemetry_ingest_command(
        {
            "schema_version": service_module.TELEMETRY_INGEST_SCHEMA,
            "service_instance_id": descriptor["service_instance_id"],
            "company_id": company["company_id"],
            "company_incarnation": company["company_incarnation"],
            "lock_domain_generation": company["lock_domain_generation"],
            "manifest_sha256": company["manifest_sha256"],
            "provider": "codex",
            "source_class": "codex_app_server",
            "adapter_instance_id": "saturation-adapter",
            "adapter_event_id": "saturation-event",
            "intake_sequence": 1,
            "transaction_id": "saturation-transaction",
            "command_id": "saturation-command",
            "received_at": _utc(_now()),
            "raw_base64": base64.b64encode(raw).decode("ascii"),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        },
    )
    chief_command = parse_chief_takeover_prepare(
        {
            "schema_version": CHIEF_TAKEOVER_PREPARE_SCHEMA,
            "service_instance_id": service.service_instance_id,
            "company_id": company["company_id"],
            "company_incarnation": company["company_incarnation"],
            "lock_domain_generation": company["lock_domain_generation"],
            "manifest_sha256": company["manifest_sha256"],
            "known_carrier": _carrier(2),
            "user_action_ref": "saturation-user-action",
            "objective_sha256": "e" * 64,
            "scope_sha256": "f" * 64,
            "nonce_sha256": "1" * 64,
        },
    )
    for _index in range(service_module._MAX_CONTROL_QUEUE - service_module._CONTROL_QUEUE_RESERVE):
        service._operations.put_nowait(service_module._PendingTelemetryIngest(telemetry_command))
    with pytest.raises(service_module._ControlRequestError) as telemetry_busy:
        service.submit_telemetry(telemetry_command)
    assert telemetry_busy.value.code == "ingest_busy"
    for _index in range(service_module._CONTROL_QUEUE_RESERVE):
        service._admit_operation(service_module._PendingChiefPrepare(chief_command), telemetry=False)
    assert service._operations.qsize() == service_module._MAX_CONTROL_QUEUE
    with pytest.raises(service_module._ControlRequestError) as admin_busy:
        service._admit_operation(service_module._PendingChiefPrepare(chief_command), telemetry=False)
    assert admin_busy.value.code == "control_busy"
    first = service._operations.get_nowait()
    assert isinstance(first, service_module._PendingChiefPrepare)
    service.request_stop()
