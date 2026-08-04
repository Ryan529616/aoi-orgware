from __future__ import annotations

import copy
from contextlib import contextmanager
from http import HTTPStatus
import json
import os
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.legacy_bridge_control_protocol import (
    build_legacy_bridge_prestart_query,
    decode_legacy_bridge_prestart_wire_result,
)
from aoi_orgware.company.legacy_bridge_ingest_protocol import (
    LEGACY_BRIDGE_INGEST_SCHEMA,
    LegacyBridgeIngestProtocolError,
    build_legacy_bridge_ingest_command,
    build_legacy_bridge_ingest_wire_result,
    decode_legacy_bridge_ingest_wire_result,
    parse_legacy_bridge_ingest,
)
from aoi_orgware.company.legacy_bridge_publisher import (
    LegacyBridgeIngestResult,
    publish_legacy_bridge_snapshot,
)
import aoi_orgware.company.legacy_bridge_service_control as bridge_control
import aoi_orgware.company.service as service_module
from aoi_orgware.company.ledger import LedgerAppendResult, LedgerTransactionRecord
from aoi_orgware.company.service import stop_service
from aoi_orgware.company.state import CompanyProjectionDegradedError
from aoi_orgware.company.supervisor import (
    CompanySupervisor,
    CompanySupervisorDashboardRefreshError,
)
from tests.company_v05.test_company_service import (
    _await_status,
    _descriptor,
    _foreground_process,
)
from tests.company_v05.test_legacy_bridge import H, _identity_digest, _raw, _snapshot
from tests.company_v05.test_supervisor import manifest


INGEST_ROUTE = "/control/v1/legacy-bridge/ingest"
PRESTART_ROUTE = "/control/v1/legacy-bridge/prestart/query"
TASK_DIGEST = _identity_digest("task", "task-1")
RECEIVED_AT = "2026-08-04T01:00:00Z"


@contextmanager
def _running_service(
    tmp_path: Path,
) -> Iterator[tuple[dict[str, Any], bytes]]:
    slot = tmp_path / "company"
    runtime = tmp_path / "runtime"
    raw = _raw(_snapshot())
    with CompanySupervisor.initialize(
        slot,
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    ):
        pass
    process = _foreground_process(slot, runtime)
    try:
        _await_status(slot, runtime, process)
        yield _descriptor(slot, runtime), raw
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
        process.wait(timeout=10.0)


def _command(descriptor: dict[str, Any], raw: bytes):
    company = descriptor["company"]
    return build_legacy_bridge_ingest_command(
        service_instance_id=descriptor["service_instance_id"],
        company_id=company["company_id"],
        company_incarnation=company["company_incarnation"],
        lock_domain_generation=company["lock_domain_generation"],
        manifest_sha256=company["manifest_sha256"],
        source_document=raw,
        task_identity_digest=TASK_DIGEST,
        legacy_archive_sha256=H,
        received_at=RECEIVED_AT,
    )


def _post(
    descriptor: dict[str, Any],
    route: str,
    payload: dict[str, Any],
    *,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    request = Request(
        descriptor["control_url"] + route,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {descriptor['bearer_token'] if token is None else token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=3.0) as response:  # noqa: S310
            value = json.loads(response.read())
            assert type(value) is dict
            return int(response.status), value
    except HTTPError as exc:
        value = json.loads(exc.read())
        assert type(value) is dict
        return int(exc.code), value


def test_live_ingest_is_durable_and_prestart_rederives_current_gate(
    tmp_path: Path,
) -> None:
    with _running_service(tmp_path) as (descriptor, raw):
        command = _command(descriptor, raw)
        status, value = _post(descriptor, INGEST_ROUTE, command.as_dict())
        assert status == HTTPStatus.OK
        result = decode_legacy_bridge_ingest_wire_result(value, command=command)
        assert result.effect == "none"
        assert result.ingest_state == "observed"
        assert result.coverage_state == "degraded"
        assert result.global_sequence is not None

        replay_status, replay_value = _post(
            descriptor,
            INGEST_ROUTE,
            command.as_dict(),
        )
        assert replay_status == HTTPStatus.OK
        replay = decode_legacy_bridge_ingest_wire_result(
            replay_value,
            command=command,
        )
        assert replay.idempotent_replay is True
        assert replay.global_sequence == result.global_sequence

        query = build_legacy_bridge_prestart_query(
            service_instance_id=descriptor["service_instance_id"],
            company_id=command.company_id,
            company_incarnation=command.company_incarnation,
            lock_domain_generation=command.lock_domain_generation,
            manifest_sha256=command.manifest_sha256,
            bridge_scope_id=result.bridge_scope_id,
            source_document=raw,
        )
        query_status, query_value = _post(
            descriptor,
            PRESTART_ROUTE,
            query.as_dict(),
        )
        assert query_status == HTTPStatus.OK
        gate = decode_legacy_bridge_prestart_wire_result(
            query_value,
            command=query,
        ).gate
        assert gate.decision == "satisfied"
        assert gate.readmodel_cursor >= result.global_sequence
        assert gate.provider_coverage_state == "degraded"


def test_ingest_rejects_bad_auth_binding_and_semantic_forgery(
    tmp_path: Path,
) -> None:
    with _running_service(tmp_path) as (descriptor, raw):
        command = _command(descriptor, raw)
        wrong = command.as_dict()
        wrong["company_id"] = "another-company"
        assert _post(descriptor, INGEST_ROUTE, wrong) == (
            HTTPStatus.CONFLICT,
            {"error": "service_binding_mismatch"},
        )
        assert _post(
            descriptor,
            INGEST_ROUTE,
            command.as_dict(),
            token="wrong",
        ) == (HTTPStatus.FORBIDDEN, {"error": "forbidden"})
        malformed = command.as_dict()
        malformed["source_document_base64"] = "***"
        assert _post(descriptor, INGEST_ROUTE, malformed) == (
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_source_document_base64"},
        )
        _status, value = _post(descriptor, INGEST_ROUTE, command.as_dict())
        forged = copy.deepcopy(value)
        forged["observation_id"] = None
        with pytest.raises(LegacyBridgeIngestProtocolError):
            decode_legacy_bridge_ingest_wire_result(forged, command=command)


def test_protocol_effect_unknown_is_nonretryable_and_timeout_is_ambiguous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = build_legacy_bridge_ingest_command(
        service_instance_id="service-1",
        company_id="company-1",
        company_incarnation=1,
        lock_domain_generation=1,
        manifest_sha256="b" * 64,
        source_document=b"{}",
        task_identity_digest="c" * 64,
        legacy_archive_sha256="d" * 64,
        received_at=RECEIVED_AT,
    )
    scope = "placeholder"
    with pytest.raises(LegacyBridgeIngestProtocolError):
        parse_legacy_bridge_ingest({"schema_version": LEGACY_BRIDGE_INGEST_SCHEMA})
    # A publisher-originated ambiguous effect is a typed 200 result and cannot
    # contain a synthetic cursor or replay claim.
    from aoi_orgware.company.legacy_bridge_contract import legacy_bridge_scope_id
    from aoi_orgware.company.legacy_bridge import LegacyBridgeCompanyKey
    from aoi_orgware.company.legacy_bridge_health import legacy_bridge_attempt_id
    from aoi_orgware.company.contracts import company_contract_sha256

    scope = legacy_bridge_scope_id(
        LegacyBridgeCompanyKey("company-1", 1, 1),
        legacy_archive_sha256="d" * 64,
        task_identity_digest="c" * 64,
    )
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=command.source_document_sha256,
        source_document_size_bytes=2,
    )
    unknown_result = LegacyBridgeIngestResult(
        f"legacy-bridge-transaction-{attempt}",
        f"legacy-bridge-command-{attempt}",
        scope,
        company_contract_sha256({
            "domain": "aoi.legacy-bridge.coverage.v1",
            "attempt_id": attempt,
        }),
        None,
        "unknown",
        "unknown",
        "effect_unknown",
        None,
        False,
    )
    unknown = build_legacy_bridge_ingest_wire_result(command, unknown_result)
    assert unknown.effect == "effect_unknown"
    for name, invalid in (
        ("ingest_state", []),
        ("coverage_state", {}),
        ("effect", []),
    ):
        with pytest.raises(LegacyBridgeIngestProtocolError):
            build_legacy_bridge_ingest_wire_result(
                command,
                unknown_result._replace(**{name: invalid}),
            )
        malformed_result = unknown.as_dict()
        malformed_result[name] = invalid
        with pytest.raises(LegacyBridgeIngestProtocolError):
            decode_legacy_bridge_ingest_wire_result(
                malformed_result,
                command=command,
            )
    for name, invalid in (
        ("company_incarnation", True),
        ("lock_domain_generation", 1.0),
    ):
        malformed_result = unknown.as_dict()
        malformed_result[name] = invalid
        with pytest.raises(LegacyBridgeIngestProtocolError):
            decode_legacy_bridge_ingest_wire_result(
                malformed_result,
                command=command,
            )

    resident = service_module._ResidentService(tmp_path / "slot", tmp_path / "runtime", 1.0)
    resident._company_binding = {
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "b" * 64,
    }
    command = command._replace(service_instance_id=resident.service_instance_id)
    monkeypatch.setattr(service_module, "_CONTROL_OPERATION_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(service_module._ControlRequestError) as timed_out:
        resident.submit_legacy_bridge_control(command)
    assert timed_out.value.status == HTTPStatus.GATEWAY_TIMEOUT
    assert timed_out.value.effect == "effect_unknown"


@pytest.mark.parametrize(
    ("failure_kind", "expected_code", "expected_effect", "expected_cursor"),
    (
        ("projection", "committed_projection_degraded", "committed", 2),
        ("dashboard", "committed_dashboard_refresh_failed", "committed", 2),
        ("dashboard_non_ledger", "effect_unknown", "effect_unknown", None),
    ),
)
def test_ingest_post_commit_failures_preserve_only_verified_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    expected_code: str,
    expected_effect: str,
    expected_cursor: int | None,
) -> None:
    """Post-commit errors are terminal facts, never a blind retry signal."""

    slot = tmp_path / "company"
    record = LedgerTransactionRecord(
        global_sequence=2,
        request={},
        receipt={},
        events=(),
        reservations=(),
    )
    result = LedgerAppendResult(
        receipt={},
        idempotent_replay=False,
        record=record,
    )
    with CompanySupervisor.initialize(
        slot,
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    ) as supervisor:
        resident = service_module._ResidentService(
            slot,
            tmp_path / "runtime",
            1.0,
        )
        command = build_legacy_bridge_ingest_command(
            service_instance_id=resident.service_instance_id,
            company_id="company-1",
            company_incarnation=1,
            lock_domain_generation=1,
            manifest_sha256="b" * 64,
            source_document=b"{}",
            task_identity_digest="c" * 64,
            legacy_archive_sha256="d" * 64,
            received_at=RECEIVED_AT,
        )
        if failure_kind == "projection":
            failure: Exception = CompanyProjectionDegradedError(result)
        elif failure_kind == "dashboard":
            failure = CompanySupervisorDashboardRefreshError(result)
        else:
            failure = CompanySupervisorDashboardRefreshError(object())

        def fail_after_commit(*_args: Any, **_kwargs: Any) -> Any:
            raise failure

        monkeypatch.setattr(
            bridge_control,
            "publish_legacy_bridge_snapshot",
            fail_after_commit,
        )
        resident._supervisor = supervisor
        pending = service_module._PendingControlOperation(command)
        resident._execute_legacy_bridge_control(pending)

    assert pending.done.is_set()
    assert pending.response is None
    assert pending.error_status == (
        HTTPStatus.INTERNAL_SERVER_ERROR
        if expected_cursor is not None
        else HTTPStatus.SERVICE_UNAVAILABLE
    )
    assert pending.error_code == expected_code
    assert pending.error_effect == expected_effect
    assert pending.error_cursor == expected_cursor
    assert resident.status_payload()["cursor"] == expected_cursor


def test_ingest_committed_error_cursor_never_regresses_resident_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replayed older receipt remains exact without regressing live status."""

    slot = tmp_path / "company"
    raw = _raw(_snapshot())
    with CompanySupervisor.initialize(
        slot,
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    ) as supervisor:
        old = publish_legacy_bridge_snapshot(
            supervisor,
            raw,
            task_identity_digest=TASK_DIGEST,
            legacy_archive_sha256=H,
            received_at=RECEIVED_AT,
        )
        current = publish_legacy_bridge_snapshot(
            supervisor,
            raw,
            task_identity_digest=_identity_digest("task", "task-2"),
            legacy_archive_sha256=H,
            received_at="2026-08-04T01:01:00Z",
        )
        assert (old.global_sequence, current.global_sequence) == (2, 3)
        resident = service_module._ResidentService(slot, tmp_path / "runtime", 1.0)
        resident._supervisor = supervisor
        resident._cursor = current.global_sequence
        assert resident._cursor == 3
        assert resident.status_payload()["cursor"] == 3
        assert supervisor.heads().global_head.global_sequence == 3
        command = build_legacy_bridge_ingest_command(
            service_instance_id=resident.service_instance_id,
            company_id="company-1",
            company_incarnation=1,
            lock_domain_generation=1,
            manifest_sha256="b" * 64,
            source_document=b"{}",
            task_identity_digest="c" * 64,
            legacy_archive_sha256="d" * 64,
            received_at=RECEIVED_AT,
        )

        def inject(cursor: int) -> service_module._PendingControlOperation:
            record = LedgerTransactionRecord(
                global_sequence=cursor,
                request={},
                receipt={},
                events=(),
                reservations=(),
            )
            result = LedgerAppendResult({}, False, record)
            monkeypatch.setattr(
                bridge_control,
                "publish_legacy_bridge_snapshot",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    CompanySupervisorDashboardRefreshError(result),
                ),
            )
            pending = service_module._PendingControlOperation(command)
            resident._execute_legacy_bridge_control(pending)
            return pending

        replayed = inject(2)
        assert (replayed.error_cursor, replayed.error_effect) == (2, "committed")
        assert resident.status_payload()["cursor"] == 3
        assert supervisor.heads().global_head.global_sequence == 3

        forward = publish_legacy_bridge_snapshot(
            supervisor,
            raw,
            task_identity_digest=_identity_digest("task", "task-3"),
            legacy_archive_sha256=H,
            received_at="2026-08-04T01:02:00Z",
        )
        assert forward.global_sequence == 4
        advanced = inject(4)
        assert (advanced.error_cursor, advanced.error_effect) == (4, "committed")
        assert resident.status_payload()["cursor"] == 4
        assert supervisor.heads().global_head.global_sequence == 4
