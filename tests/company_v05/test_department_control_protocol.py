from __future__ import annotations

import pytest

from aoi_orgware.company.department_control_protocol import (
    DEPARTMENT_DISPATCH_SCHEMA,
    DepartmentControlProtocolError,
    parse_department_dispatch,
)


def _request() -> dict[str, object]:
    return {
        "schema_version": DEPARTMENT_DISPATCH_SCHEMA,
        "service_instance_id": "service-1",
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        "chief_id": "chief-1",
        "carrier_id": "carrier-1",
        "term": 1,
        "epoch": 1,
        "chief_execution_id": "chief-execution-1",
        "department_id": "department-1",
        "enqueue_transaction_id": "enqueue-transaction-1",
        "enqueue_command_id": "enqueue-command-1",
        "admission_transaction_id": "admission-transaction-1",
        "admission_command_id": "admission-command-1",
        "dispatch_request_id": "dispatch-1",
        "reservation_id": "reservation-1",
        "task_id": "task-1",
        "packet_id": "packet-1",
        "route_policy_id": "route-1",
        "requested_role": "rtl_lead",
        "requested_capability_tier": "standard",
    }


def test_department_dispatch_protocol_round_trips_exactly() -> None:
    command = parse_department_dispatch(_request())
    assert command.as_dict() == _request()


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("term", True, "invalid_term"),
        ("epoch", 0, "invalid_epoch"),
        ("manifest_sha256", "A" * 64, "invalid_manifest_sha256"),
        ("department_id", "bad id", "invalid_department_id"),
    ],
)
def test_department_dispatch_protocol_rejects_invalid_scalars(
    field: str,
    value: object,
    code: str,
) -> None:
    request = _request()
    request[field] = value
    with pytest.raises(DepartmentControlProtocolError, match=f"^{code}$"):
        parse_department_dispatch(request)


def test_department_dispatch_protocol_rejects_client_timestamp_and_extras() -> None:
    request = _request()
    request["requested_at"] = "2026-07-27T00:00:00Z"
    with pytest.raises(DepartmentControlProtocolError, match="invalid_request_schema"):
        parse_department_dispatch(request)
