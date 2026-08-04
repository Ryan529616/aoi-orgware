from __future__ import annotations

import copy
from contextlib import contextmanager
from http import HTTPStatus
import json
import os
import pickle
from pathlib import Path
import threading
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.contracts import company_contract_sha256
from aoi_orgware.company.legacy_bridge_control_protocol import (
    LEGACY_BRIDGE_PRESTART_QUERY_SCHEMA,
    MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES,
    LegacyBridgeControlProtocolError,
    LegacyBridgePrestartQueryCommand,
    build_legacy_bridge_prestart_query,
    decode_legacy_bridge_prestart_wire_result,
    parse_legacy_bridge_prestart_query,
    require_verified_legacy_bridge_prestart_result,
    verify_legacy_bridge_prestart_result,
)
from aoi_orgware.company.legacy_bridge_publisher import (
    publish_legacy_bridge_snapshot,
)
import aoi_orgware.company.service as service_module
import aoi_orgware.company.legacy_bridge_control_protocol as protocol_module
from aoi_orgware.company.service import stop_service
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_company_service import (
    _await_status,
    _descriptor,
    _foreground_process,
    _raw_control_request,
)
from tests.company_v05.test_legacy_bridge import (
    H,
    _identity_digest,
    _raw,
    _snapshot,
)
from tests.company_v05.test_supervisor import manifest


ROUTE = "/control/v1/legacy-bridge/prestart/query"
TASK_DIGEST = _identity_digest("task", "task-1")
RECEIVED_AT = "2026-08-04T01:00:00Z"


def _prepare(
    tmp_path: Path,
    mode: str,
) -> tuple[Path, Path, bytes, str, tuple[int, str]]:
    slot = tmp_path / "company"
    runtime = tmp_path / "runtime"
    raw = _raw(_snapshot()) if mode != "degraded" else b"{}"
    with CompanySupervisor.initialize(
        slot,
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    ) as supervisor:
        if mode == "missing":
            scope = H
        else:
            scope = publish_legacy_bridge_snapshot(
                supervisor,
                raw,
                task_identity_digest=TASK_DIGEST,
                legacy_archive_sha256=H,
                received_at=RECEIVED_AT,
            ).bridge_scope_id
        head = supervisor.heads().global_head
        before = (head.global_sequence, head.transaction_sha256)
    return slot, runtime, raw, scope, before


@contextmanager
def _running_service(
    slot: Path,
    runtime: Path,
) -> Iterator[dict[str, Any]]:
    process = _foreground_process(slot, runtime)
    try:
        _await_status(slot, runtime, process)
        yield _descriptor(slot, runtime)
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
        process.wait(timeout=10.0)


def _command(
    descriptor: dict[str, Any],
    scope: str,
    raw: bytes,
) -> LegacyBridgePrestartQueryCommand:
    company = descriptor["company"]
    return build_legacy_bridge_prestart_query(
        service_instance_id=descriptor["service_instance_id"],
        company_id=company["company_id"],
        company_incarnation=company["company_incarnation"],
        lock_domain_generation=company["lock_domain_generation"],
        manifest_sha256=company["manifest_sha256"],
        bridge_scope_id=scope,
        source_document=raw,
    )


def _post(
    descriptor: dict[str, Any],
    payload: dict[str, Any],
    *,
    token: str | None = None,
    origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {
        "Authorization": f"Bearer {descriptor['bearer_token'] if token is None else token}",
        "Content-Type": "application/json",
    }
    if origin is not None:
        headers["Origin"] = origin
    request = Request(
        descriptor["control_url"] + ROUTE,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=3.0) as response:  # noqa: S310
            value = json.loads(response.read())
            assert isinstance(value, dict)
            return int(response.status), value
    except HTTPError as exc:
        value = json.loads(exc.read())
        assert isinstance(value, dict)
        return int(exc.code), value


def _reseal_gate(gate: dict[str, Any]) -> None:
    unsigned = {name: value for name, value in gate.items() if name != "gate_sha256"}
    gate["gate_sha256"] = company_contract_sha256(
        {"domain": "aoi.legacy-bridge.prestart-gate.v1", **unsigned},
    )


def test_live_query_is_exact_nonmutating_and_keeps_provider_degraded(
    tmp_path: Path,
) -> None:
    slot, runtime, raw, scope, before = _prepare(tmp_path, "observed")
    responses: list[tuple[LegacyBridgePrestartQueryCommand, dict[str, Any]]] = []
    with _running_service(slot, runtime) as descriptor:
        command = _command(descriptor, scope, raw)
        status, value = _post(descriptor, command.as_dict())
        assert status == 200
        result = decode_legacy_bridge_prestart_wire_result(value, command=command)
        assert result.cursor == before[0]
        assert result.gate.decision == "satisfied"
        assert result.gate.provider_coverage_state == "degraded"
        assert result.gate.authority == "none"
        assert result.gate.repo_write_capability == "absent"
        assert result.gate.dispatch_capability == "absent"
        assert result.gate.job_launch_capability == "absent"
        responses.append((command, value))

        stale = _command(descriptor, scope, raw + b"\n")
        stale_status, stale_value = _post(descriptor, stale.as_dict())
        assert stale_status == 200
        stale_result = decode_legacy_bridge_prestart_wire_result(
            stale_value,
            command=stale,
        )
        assert stale_result.gate.decision == "blocked"
        assert stale_result.gate.reason == "current_source_not_observed"
    assert len(responses) == 1
    with CompanySupervisor.open(slot) as reopened:
        verified = verify_legacy_bridge_prestart_result(
            reopened._state, responses[0][1], command=responses[0][0],
        )
        assert verified.verification == "resident_state_rederived"
        assert verified.result.gate.decision == "satisfied"
        after = reopened.heads().global_head
        assert (after.global_sequence, after.transaction_sha256) == before


@pytest.mark.parametrize(
    ("mode", "decision", "reason"),
    [
        ("degraded", "blocked", "current_ingest_degraded"),
        ("missing", "unknown", "current_health_missing"),
    ],
)
def test_structural_non_satisfaction_is_a_typed_200_result(
    tmp_path: Path,
    mode: str,
    decision: str,
    reason: str,
) -> None:
    slot, runtime, raw, scope, before = _prepare(tmp_path, mode)
    with _running_service(slot, runtime) as descriptor:
        command = _command(descriptor, scope, raw)
        status, value = _post(descriptor, command.as_dict())
        assert status == 200
        result = decode_legacy_bridge_prestart_wire_result(value, command=command)
        assert result.cursor == before[0]
        assert result.gate.decision == decision
        assert result.gate.reason == reason
        assert result.gate.authority == "none"


def test_authenticated_wire_rejects_bad_binding_auth_origin_and_duplicates(
    tmp_path: Path,
) -> None:
    slot, runtime, raw, scope, _before = _prepare(tmp_path, "observed")
    with _running_service(slot, runtime) as descriptor:
        command = _command(descriptor, scope, raw)
        wrong = command.as_dict()
        wrong["company_id"] = "another-company"
        assert _post(descriptor, wrong) == (
            409,
            {"error": "service_binding_mismatch"},
        )
        assert _post(descriptor, command.as_dict(), token="wrong") == (
            403,
            {"error": "forbidden"},
        )
        assert _post(
            descriptor,
            command.as_dict(),
            origin="http://127.0.0.1",
        ) == (403, {"error": "forbidden"})

        canonical = json.dumps(
            command.as_dict(),
            separators=(",", ":"),
        ).encode("utf-8")
        duplicate = (
            b'{"schema_version":"'
            + LEGACY_BRIDGE_PRESTART_QUERY_SCHEMA.encode("ascii")
            + b'",'
            + canonical[1:]
        )
        status, value = _raw_control_request(
            descriptor["control_url"],
            method="POST",
            path=ROUTE,
            headers=[
                ("Authorization", f"Bearer {descriptor['bearer_token']}"),
                ("Content-Type", "application/json"),
            ],
            body=duplicate,
        )
        assert (status, value) == (400, {"error": "invalid_json"})


def test_protocol_rejects_malformed_or_recomputed_forged_values(
    tmp_path: Path,
) -> None:
    slot, runtime, raw, scope, _before = _prepare(tmp_path, "observed")
    with _running_service(slot, runtime) as descriptor:
        command = _command(descriptor, scope, raw)
        invalid = command.as_dict()
        invalid["source_document_base64"] = "***"
        with pytest.raises(LegacyBridgeControlProtocolError):
            parse_legacy_bridge_prestart_query(invalid)
        oversized = command.as_dict()
        oversized["source_document_base64"] = (
            "A" * (MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES + 1)
        )
        with pytest.raises(LegacyBridgeControlProtocolError):
            parse_legacy_bridge_prestart_query(oversized)

        status, value = _post(descriptor, command.as_dict())
        assert status == 200
        with pytest.raises(LegacyBridgeControlProtocolError):
            verify_legacy_bridge_prestart_result(
                object(), value, command=command,  # type: ignore[arg-type]
            )
        with pytest.raises(LegacyBridgeControlProtocolError):
            decode_legacy_bridge_prestart_wire_result(value, command=object())  # type: ignore[arg-type]
        forged = copy.deepcopy(value)
        forged["gate"]["authority"] = "launch"
        _reseal_gate(forged["gate"])
        with pytest.raises(LegacyBridgeControlProtocolError):
            decode_legacy_bridge_prestart_wire_result(forged, command=command)
        forged = copy.deepcopy(value)
        forged["gate"]["ingest_state"] = "degraded"
        _reseal_gate(forged["gate"])
        with pytest.raises(LegacyBridgeControlProtocolError):
            decode_legacy_bridge_prestart_wire_result(forged, command=command)
        forged = copy.deepcopy(value)
        forged["cursor"] += 1
        with pytest.raises(LegacyBridgeControlProtocolError):
            decode_legacy_bridge_prestart_wire_result(forged, command=command)
        forged = copy.deepcopy(value)
        forged["gate"]["readmodel_cursor"] -= 1
        _reseal_gate(forged["gate"])
        with pytest.raises(LegacyBridgeControlProtocolError):
            decode_legacy_bridge_prestart_wire_result(forged, command=command)
        forged = copy.deepcopy(value)
        forged["gate"]["coverage_global_sequence"] -= 1
        _reseal_gate(forged["gate"])
        with pytest.raises(LegacyBridgeControlProtocolError):
            decode_legacy_bridge_prestart_wire_result(forged, command=command)
        for name, invalid in (("reason", []), ("schema_version", True)):
            forged = copy.deepcopy(value)
            forged["gate"][name] = invalid
            with pytest.raises(LegacyBridgeControlProtocolError):
                decode_legacy_bridge_prestart_wire_result(forged, command=command)


def test_recomputed_semantic_forgery_requires_resident_state(
    tmp_path: Path,
) -> None:
    slot, runtime, raw, scope, _before = _prepare(tmp_path, "observed")
    with _running_service(slot, runtime) as descriptor:
        exact_command = _command(descriptor, scope, raw)
        exact_status, exact_value = _post(descriptor, exact_command.as_dict())
        assert exact_status == 200
        stale_command = _command(descriptor, scope, raw + b"\n")
        stale_status, stale_value = _post(descriptor, stale_command.as_dict())
        assert stale_status == 200

    forged = copy.deepcopy(stale_value)
    forged["gate"].update({
        "decision": "satisfied",
        "reason": "current_structural_ingest_observed",
        "ingest_state": "observed",
        "source_currentness": "exact",
        "publication_effect": "durable_readback",
    })
    _reseal_gate(forged["gate"])
    decoded = decode_legacy_bridge_prestart_wire_result(
        forged, command=stale_command,
    )
    assert decoded.gate.decision == "satisfied"

    with CompanySupervisor.open(slot) as reopened:
        verified = verify_legacy_bridge_prestart_result(
            reopened._state, exact_value, command=exact_command,
        )
        assert verified.result.gate.decision == "satisfied"
        assert verified.verification == "resident_state_rederived"
        assert require_verified_legacy_bridge_prestart_result(verified) is verified.result
        assert not hasattr(verified, "__dict__")
        with pytest.raises(AttributeError):
            verified.result = verified.result  # type: ignore[misc]
        with pytest.raises(LegacyBridgeControlProtocolError):
            protocol_module._LegacyBridgePrestartVerifiedResultV1(
                verified.result,
            )
        with pytest.raises(TypeError):
            class ForgedVerified(
                protocol_module._LegacyBridgePrestartVerifiedResultV1,
            ):
                pass
        forged_exact = object.__new__(
            protocol_module._LegacyBridgePrestartVerifiedResultV1,
        )
        with pytest.raises(LegacyBridgeControlProtocolError):
            require_verified_legacy_bridge_prestart_result(forged_exact)
        try:
            copied = copy.copy(verified)
        except (TypeError, LegacyBridgeControlProtocolError):
            pass
        else:
            assert copied is verified
        try:
            unpickled = pickle.loads(pickle.dumps(verified))
        except (TypeError, LegacyBridgeControlProtocolError):
            pass
        else:
            with pytest.raises(LegacyBridgeControlProtocolError):
                require_verified_legacy_bridge_prestart_result(unpickled)
        with pytest.raises(
            LegacyBridgeControlProtocolError,
            match="result_state_mismatch",
        ):
            verify_legacy_bridge_prestart_result(
                reopened._state, forged, command=stale_command,
            )
        publish_legacy_bridge_snapshot(
            reopened,
            raw + b"\n\n",
            task_identity_digest=TASK_DIGEST,
            legacy_archive_sha256=H,
            received_at="2026-08-04T01:00:01Z",
        )
        with pytest.raises(
            LegacyBridgeControlProtocolError,
            match="result_state_mismatch",
        ):
            verify_legacy_bridge_prestart_result(
                reopened._state, exact_value, command=exact_command,
            )


def test_unknown_control_command_fails_closed_without_effect(
    tmp_path: Path,
) -> None:
    slot, runtime, _raw_bytes, _scope, before = _prepare(tmp_path, "observed")
    resident = service_module._ResidentService(slot, runtime, 0.2)
    pending = service_module._PendingControlOperation(object())  # type: ignore[arg-type]
    resident._operations.put_nowait(pending)
    owner = threading.Thread(target=resident.run)
    owner.start()
    try:
        assert pending.done.wait(10.0)
        assert pending.error_status == HTTPStatus.INTERNAL_SERVER_ERROR
        assert pending.error_code == "unsupported_control_command"
        assert pending.response is None
    finally:
        resident.request_stop()
        owner.join(timeout=10.0)
    assert not owner.is_alive()
    with CompanySupervisor.open(slot) as reopened:
        head = reopened.heads().global_head
        assert (head.global_sequence, head.transaction_sha256) == before


def test_service_restart_fences_the_old_descriptor(
    tmp_path: Path,
) -> None:
    slot, runtime, raw, scope, _before = _prepare(tmp_path, "observed")
    old_descriptor: dict[str, Any] | None = None
    with _running_service(slot, runtime) as descriptor:
        old_descriptor = descriptor
        command = _command(descriptor, scope, raw)
        assert _post(descriptor, command.as_dict())[0] == 200
    assert old_descriptor is not None
    with pytest.raises(URLError):
        _post(old_descriptor, _command(old_descriptor, scope, raw).as_dict())
    with _running_service(slot, runtime) as descriptor:
        assert descriptor["service_instance_id"] != old_descriptor["service_instance_id"]
        command = _command(descriptor, scope, raw)
        assert _post(descriptor, command.as_dict())[0] == 200


def test_stopping_and_timeout_are_nonmutating_control_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot, runtime, raw, scope, before = _prepare(tmp_path, "observed")
    resident = service_module._ResidentService(slot, runtime, 1.0)
    company = manifest()
    resident._company_binding = {
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company_contract_sha256(company),
    }
    command = build_legacy_bridge_prestart_query(
        service_instance_id=resident.service_instance_id,
        company_id=company["company_id"],
        company_incarnation=company["company_incarnation"],
        lock_domain_generation=company["lock_domain_generation"],
        manifest_sha256=resident._company_binding["manifest_sha256"],
        bridge_scope_id=scope,
        source_document=raw,
    )
    monkeypatch.setattr(service_module, "_CONTROL_OPERATION_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(service_module._ControlRequestError) as timed_out:
        resident.submit_legacy_bridge_prestart(command)
    assert timed_out.value.status == 504
    assert timed_out.value.effect is None
    resident.request_stop()
    with pytest.raises(service_module._ControlRequestError) as stopping:
        resident.submit_legacy_bridge_prestart(command)
    assert stopping.value.status == 503
    assert stopping.value.effect is None
    with CompanySupervisor.open(slot) as reopened:
        head = reopened.heads().global_head
        assert (head.global_sequence, head.transaction_sha256) == before
