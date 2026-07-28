"""Strict resident department-dispatch control protocol."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping


DEPARTMENT_DISPATCH_SCHEMA = "aoi.company.department-dispatch.v1"
DEPARTMENT_DISPATCH_RESULT_SCHEMA = "aoi.company.department-dispatch-result.v1"

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class DepartmentControlProtocolError(ValueError):
    """The untrusted department control envelope is not v1-valid."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _object(value: Any) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise DepartmentControlProtocolError("invalid_request_schema")
    return value


def _identifier(value: Any, *, name: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise DepartmentControlProtocolError(f"invalid_{name}")
    return value


def _positive_int(value: Any, *, name: str) -> int:
    if type(value) is not int or value < 1:
        raise DepartmentControlProtocolError(f"invalid_{name}")
    return value


def _sha256(value: Any, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DepartmentControlProtocolError(f"invalid_{name}")
    return value


@dataclass(frozen=True)
class DepartmentDispatchCommand:
    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    chief_id: str
    carrier_id: str
    term: int
    epoch: int
    chief_execution_id: str
    department_id: str
    enqueue_transaction_id: str
    enqueue_command_id: str
    admission_transaction_id: str
    admission_command_id: str
    dispatch_request_id: str
    reservation_id: str
    task_id: str
    packet_id: str
    route_policy_id: str
    requested_role: str
    requested_capability_tier: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": DEPARTMENT_DISPATCH_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "chief_id": self.chief_id,
            "carrier_id": self.carrier_id,
            "term": self.term,
            "epoch": self.epoch,
            "chief_execution_id": self.chief_execution_id,
            "department_id": self.department_id,
            "enqueue_transaction_id": self.enqueue_transaction_id,
            "enqueue_command_id": self.enqueue_command_id,
            "admission_transaction_id": self.admission_transaction_id,
            "admission_command_id": self.admission_command_id,
            "dispatch_request_id": self.dispatch_request_id,
            "reservation_id": self.reservation_id,
            "task_id": self.task_id,
            "packet_id": self.packet_id,
            "route_policy_id": self.route_policy_id,
            "requested_role": self.requested_role,
            "requested_capability_tier": self.requested_capability_tier,
        }


_FIELDS = frozenset({
    "schema_version",
    "service_instance_id",
    "company_id",
    "company_incarnation",
    "lock_domain_generation",
    "manifest_sha256",
    "chief_id",
    "carrier_id",
    "term",
    "epoch",
    "chief_execution_id",
    "department_id",
    "enqueue_transaction_id",
    "enqueue_command_id",
    "admission_transaction_id",
    "admission_command_id",
    "dispatch_request_id",
    "reservation_id",
    "task_id",
    "packet_id",
    "route_policy_id",
    "requested_role",
    "requested_capability_tier",
})


def parse_department_dispatch(value: Any) -> DepartmentDispatchCommand:
    """Parse one bounded request; timestamps are deliberately server-owned."""

    request = _object(value)
    if set(request) != _FIELDS or request.get("schema_version") != DEPARTMENT_DISPATCH_SCHEMA:
        raise DepartmentControlProtocolError("invalid_request_schema")
    return DepartmentDispatchCommand(
        service_instance_id=_identifier(request["service_instance_id"], name="service_instance_id"),
        company_id=_identifier(request["company_id"], name="company_id"),
        company_incarnation=_positive_int(request["company_incarnation"], name="company_incarnation"),
        lock_domain_generation=_positive_int(request["lock_domain_generation"], name="lock_domain_generation"),
        manifest_sha256=_sha256(request["manifest_sha256"], name="manifest_sha256"),
        chief_id=_identifier(request["chief_id"], name="chief_id"),
        carrier_id=_identifier(request["carrier_id"], name="carrier_id"),
        term=_positive_int(request["term"], name="term"),
        epoch=_positive_int(request["epoch"], name="epoch"),
        chief_execution_id=_identifier(request["chief_execution_id"], name="chief_execution_id"),
        department_id=_identifier(request["department_id"], name="department_id"),
        enqueue_transaction_id=_identifier(request["enqueue_transaction_id"], name="enqueue_transaction_id"),
        enqueue_command_id=_identifier(request["enqueue_command_id"], name="enqueue_command_id"),
        admission_transaction_id=_identifier(request["admission_transaction_id"], name="admission_transaction_id"),
        admission_command_id=_identifier(request["admission_command_id"], name="admission_command_id"),
        dispatch_request_id=_identifier(request["dispatch_request_id"], name="dispatch_request_id"),
        reservation_id=_identifier(request["reservation_id"], name="reservation_id"),
        task_id=_identifier(request["task_id"], name="task_id"),
        packet_id=_identifier(request["packet_id"], name="packet_id"),
        route_policy_id=_identifier(request["route_policy_id"], name="route_policy_id"),
        requested_role=_identifier(request["requested_role"], name="requested_role"),
        requested_capability_tier=_identifier(request["requested_capability_tier"], name="requested_capability_tier"),
    )


__all__ = [
    "DEPARTMENT_DISPATCH_RESULT_SCHEMA",
    "DEPARTMENT_DISPATCH_SCHEMA",
    "DepartmentControlProtocolError",
    "DepartmentDispatchCommand",
    "parse_department_dispatch",
]
