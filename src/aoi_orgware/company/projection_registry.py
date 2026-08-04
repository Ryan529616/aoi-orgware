"""Shared, immutable projection metadata for company ledger contracts.

The ledger, read model, and invariant reducer must agree on one stream,
projection identity, and logical identity for every top-level contract.  This
module owns only that metadata; it performs no validation, projection, or I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from .contracts import (
    ALERT_V1,
    ARTIFACT_EDGE_V1,
    AUTHORITY_GRANT_V1,
    BACKUP_ENVELOPE_V1,
    CANARY_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    CONTROL_INTENT_V1,
    CRYPTO_VERIFICATION_RECEIPT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    NEEDS_USER_REVISION_V1,
    NEEDS_USER_V1,
    OPTIMIZER_PROPOSAL_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_CODEX_HOME_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    RATE_CARD_V1,
    ROUTE_POLICY_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    TASK_REVISION_V1,
    USAGE_BURN_REVISION_V1,
    USAGE_COUNTER_SAMPLE_V1,
    USAGE_EVENT_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
)
from .write_admission import (
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
)
from .write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
)
from .legacy_bridge_contract import LEGACY_BRIDGE_OBSERVATION_V1


@dataclass(frozen=True, slots=True)
class ProjectionSpec:
    """One current-object projection identity."""

    stream: str
    object_key_field: str
    record_id_field: str


_STREAM_BY_CONTRACT = {
    COMPANY_MANIFEST_V1: "org",
    AUTHORITY_GRANT_V1: "org",
    TAKEOVER_CAPABILITY_V1: "org",
    TAKEOVER_CONSUMPTION_RECEIPT_V1: "org",
    ORGANIZATION_NODE_V1: "org",
    DEPARTMENT_IDENTITY_V1: "org",
    DEPARTMENT_SNAPSHOT_V1: "org",
    CHIEF_TERM_V1: "org",
    CARRIER_BINDING_V1: "org",
    ROUTE_POLICY_V1: "org",
    TASK_REVISION_V1: "org",
    WORK_DEFINITION_ENFORCEMENT_V1: "org",
    WRITE_DOMAIN_BINDING_V1: "org",
    WRITE_ADMISSION_ENFORCEMENT_V1: "org",
    EXECUTION_NODE_V1: "execution",
    EXECUTION_EVENT_V1: "execution",
    CONTROL_INTENT_V1: "execution",
    MUTATION_INTENT_V1: "execution",
    EXTERNAL_JOB_V1: "execution",
    DISPATCH_REQUEST_V1: "execution",
    WORK_PACKET_V1: "execution",
    WORK_DISPATCH_BINDING_V1: "execution",
    WORK_WRITE_CAPABILITY_V1: "execution",
    WORK_WRITE_INTENT_V1: "execution",
    PROVIDER_CODEX_HOME_V1: "execution",
    PROVIDER_LAUNCH_BINDING_V1: "execution",
    PROVIDER_WORKER_OPERATION_V1: "execution",
    PROVIDER_WORKER_IO_RECEIPT_V1: "evidence",
    PROVIDER_TURN_RESULT_RECEIPT_V1: "evidence",
    EXTERNAL_JOB_EFFECT_RECEIPT_V1: "evidence",
    WORK_RESULT_RECEIPT_V1: "evidence",
    PROVIDER_LIFECYCLE_RECEIPT_V1: "evidence",
    ENGINEERING_DISPOSITION_RECEIPT_V1: "evidence",
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1: "evidence",
    EVIDENCE_RECORD_V1: "evidence",
    ARTIFACT_EDGE_V1: "evidence",
    OPTIMIZER_PROPOSAL_V1: "evidence",
    CANARY_V1: "evidence",
    BACKUP_ENVELOPE_V1: "evidence",
    CRYPTO_VERIFICATION_RECEIPT_V1: "evidence",
    PROVIDER_TELEMETRY_RECEIPT_V1: "evidence",
    PROVIDER_COVERAGE_REVISION_V1: "evidence",
    USAGE_EVENT_V1: "usage",
    USAGE_BURN_REVISION_V1: "usage",
    USAGE_COUNTER_SAMPLE_V1: "usage",
    RATE_CARD_V1: "usage",
    ALERT_V1: "alert",
    NEEDS_USER_V1: "alert",
    NEEDS_USER_REVISION_V1: "alert",
    LEGACY_BRIDGE_OBSERVATION_V1: "evidence",
}

PROJECTABLE_STREAM: Final[Mapping[str, str]] = MappingProxyType(
    _STREAM_BY_CONTRACT,
)

_SPECS = {
    COMPANY_MANIFEST_V1: ProjectionSpec("org", "company_id", "company_id"),
    AUTHORITY_GRANT_V1: ProjectionSpec("org", "grant_id", "grant_id"),
    TAKEOVER_CAPABILITY_V1: ProjectionSpec(
        "org", "capability_id", "capability_id",
    ),
    TAKEOVER_CONSUMPTION_RECEIPT_V1: ProjectionSpec(
        "org", "consumption_id", "consumption_id",
    ),
    ORGANIZATION_NODE_V1: ProjectionSpec("org", "node_id", "node_id"),
    DEPARTMENT_IDENTITY_V1: ProjectionSpec(
        "org", "department_id", "department_id",
    ),
    DEPARTMENT_SNAPSHOT_V1: ProjectionSpec(
        "org", "department_id", "snapshot_id",
    ),
    CHIEF_TERM_V1: ProjectionSpec("org", "chief_id", "chief_id"),
    CARRIER_BINDING_V1: ProjectionSpec("org", "carrier_id", "carrier_id"),
    ROUTE_POLICY_V1: ProjectionSpec("org", "policy_id", "policy_id"),
    TASK_REVISION_V1: ProjectionSpec(
        "org", "task_revision_id", "task_revision_id",
    ),
    WORK_DEFINITION_ENFORCEMENT_V1: ProjectionSpec(
        "org", "gate_id", "gate_id",
    ),
    WRITE_DOMAIN_BINDING_V1: ProjectionSpec(
        "org", "binding_id", "binding_id",
    ),
    WRITE_ADMISSION_ENFORCEMENT_V1: ProjectionSpec(
        "org", "gate_id", "gate_id",
    ),
    PROVIDER_CODEX_HOME_V1: ProjectionSpec(
        "execution", "home_id", "home_id",
    ),
    EXECUTION_NODE_V1: ProjectionSpec(
        "execution", "execution_id", "execution_id",
    ),
    DISPATCH_REQUEST_V1: ProjectionSpec(
        "execution", "dispatch_request_id", "dispatch_revision_id",
    ),
    WORK_PACKET_V1: ProjectionSpec(
        "execution", "packet_id", "packet_id",
    ),
    WORK_DISPATCH_BINDING_V1: ProjectionSpec(
        "execution", "dispatch_request_id", "binding_id",
    ),
    WORK_WRITE_CAPABILITY_V1: ProjectionSpec(
        "execution", "capability_id", "capability_id",
    ),
    WORK_WRITE_INTENT_V1: ProjectionSpec(
        "execution", "intent_id", "intent_id",
    ),
    PROVIDER_LAUNCH_BINDING_V1: ProjectionSpec(
        "execution", "launch_binding_id", "launch_binding_id",
    ),
    PROVIDER_WORKER_OPERATION_V1: ProjectionSpec(
        "execution", "operation_id", "operation_id",
    ),
    EXECUTION_EVENT_V1: ProjectionSpec(
        "execution", "event_id", "event_id",
    ),
    CONTROL_INTENT_V1: ProjectionSpec(
        "execution", "control_intent_id", "control_intent_id",
    ),
    MUTATION_INTENT_V1: ProjectionSpec(
        "execution", "intent_id", "intent_id",
    ),
    EXTERNAL_JOB_V1: ProjectionSpec("execution", "job_id", "job_id"),
    EXTERNAL_JOB_EFFECT_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    WORK_RESULT_RECEIPT_V1: ProjectionSpec(
        "evidence", "result_receipt_id", "result_receipt_id",
    ),
    EVIDENCE_RECORD_V1: ProjectionSpec(
        "evidence", "evidence_id", "evidence_id",
    ),
    PROVIDER_LIFECYCLE_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    ENGINEERING_DISPOSITION_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    PROVIDER_TELEMETRY_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    PROVIDER_WORKER_IO_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    PROVIDER_TURN_RESULT_RECEIPT_V1: ProjectionSpec(
        "evidence", "result_receipt_id", "result_receipt_id",
    ),
    PROVIDER_COVERAGE_REVISION_V1: ProjectionSpec(
        "evidence", "coverage_scope_id", "revision_id",
    ),
    ARTIFACT_EDGE_V1: ProjectionSpec(
        "evidence", "edge_id", "edge_id",
    ),
    OPTIMIZER_PROPOSAL_V1: ProjectionSpec(
        "evidence", "proposal_id", "proposal_id",
    ),
    CANARY_V1: ProjectionSpec("evidence", "canary_id", "canary_id"),
    BACKUP_ENVELOPE_V1: ProjectionSpec(
        "evidence", "backup_id", "backup_id",
    ),
    CRYPTO_VERIFICATION_RECEIPT_V1: ProjectionSpec(
        "evidence", "receipt_id", "receipt_id",
    ),
    USAGE_EVENT_V1: ProjectionSpec("usage", "usage_id", "usage_id"),
    USAGE_COUNTER_SAMPLE_V1: ProjectionSpec(
        "usage", "sample_id", "sample_id",
    ),
    USAGE_BURN_REVISION_V1: ProjectionSpec(
        "usage", "burn_id", "burn_id",
    ),
    RATE_CARD_V1: ProjectionSpec(
        "usage", "rate_card_id", "rate_card_id",
    ),
    ALERT_V1: ProjectionSpec("alert", "alert_id", "alert_id"),
    NEEDS_USER_V1: ProjectionSpec("alert", "item_id", "item_id"),
    NEEDS_USER_REVISION_V1: ProjectionSpec(
        "alert", "item_id", "revision_id",
    ),
    LEGACY_BRIDGE_OBSERVATION_V1: ProjectionSpec(
        "evidence", "bridge_scope_id", "observation_id",
    ),
}

if {
    contract: spec.stream for contract, spec in _SPECS.items()
} != _STREAM_BY_CONTRACT:
    raise RuntimeError("company stream and projection registries differ")

PROJECTION_SPECS: Final[Mapping[str, ProjectionSpec]] = MappingProxyType(
    _SPECS,
)

LOGICAL_ID_FIELDS: Final[Mapping[str, str]] = MappingProxyType({
    ALERT_V1: "alert_id",
    AUTHORITY_GRANT_V1: "grant_id",
    TAKEOVER_CAPABILITY_V1: "capability_id",
    TAKEOVER_CONSUMPTION_RECEIPT_V1: "consumption_id",
    ORGANIZATION_NODE_V1: "node_id",
    DEPARTMENT_IDENTITY_V1: "department_id",
    DEPARTMENT_SNAPSHOT_V1: "department_id",
    CHIEF_TERM_V1: "chief_id",
    CARRIER_BINDING_V1: "carrier_id",
    EXECUTION_NODE_V1: "execution_id",
    DISPATCH_REQUEST_V1: "dispatch_request_id",
    EXTERNAL_JOB_EFFECT_RECEIPT_V1: "receipt_id",
    EXTERNAL_JOB_V1: "job_id",
    MUTATION_INTENT_V1: "intent_id",
    PROVIDER_LIFECYCLE_RECEIPT_V1: "receipt_id",
    ENGINEERING_DISPOSITION_RECEIPT_V1: "receipt_id",
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1: "receipt_id",
    PROVIDER_TELEMETRY_RECEIPT_V1: "receipt_id",
    PROVIDER_COVERAGE_REVISION_V1: "coverage_scope_id",
    USAGE_COUNTER_SAMPLE_V1: "sample_id",
    NEEDS_USER_REVISION_V1: "item_id",
    EVIDENCE_RECORD_V1: "evidence_id",
    EXECUTION_EVENT_V1: "event_id",
    CONTROL_INTENT_V1: "control_intent_id",
    TASK_REVISION_V1: "task_revision_id",
    WORK_PACKET_V1: "packet_id",
    WORK_DISPATCH_BINDING_V1: "dispatch_request_id",
    WORK_RESULT_RECEIPT_V1: "result_receipt_id",
    WORK_DEFINITION_ENFORCEMENT_V1: "gate_id",
    WRITE_DOMAIN_BINDING_V1: "binding_id",
    WRITE_ADMISSION_ENFORCEMENT_V1: "gate_id",
    WORK_WRITE_CAPABILITY_V1: "capability_id",
    WORK_WRITE_INTENT_V1: "intent_id",
    PROVIDER_CODEX_HOME_V1: "home_id",
    PROVIDER_LAUNCH_BINDING_V1: "launch_binding_id",
    PROVIDER_WORKER_IO_RECEIPT_V1: "receipt_id",
    PROVIDER_WORKER_OPERATION_V1: "operation_id",
    PROVIDER_TURN_RESULT_RECEIPT_V1: "result_receipt_id",
    LEGACY_BRIDGE_OBSERVATION_V1: "bridge_scope_id",
})

APPEND_ONCE_WORK_DEFINITION_TYPES: Final[frozenset[str]] = frozenset({
    TASK_REVISION_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
})

APPEND_ONCE_AUTHORITY_TYPES: Final[frozenset[str]] = frozenset({
    AUTHORITY_GRANT_V1,
})

APPEND_ONCE_PROVIDER_PROJECTION_TYPES: Final[frozenset[str]] = frozenset({
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
})

APPEND_ONCE_WRITE_ADMISSION_TYPES: Final[frozenset[str]] = frozenset({
    WRITE_DOMAIN_BINDING_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
    WORK_WRITE_CAPABILITY_V1,
    WORK_WRITE_INTENT_V1,
})


__all__ = [
    "APPEND_ONCE_AUTHORITY_TYPES",
    "APPEND_ONCE_PROVIDER_PROJECTION_TYPES",
    "APPEND_ONCE_WORK_DEFINITION_TYPES",
    "APPEND_ONCE_WRITE_ADMISSION_TYPES",
    "LOGICAL_ID_FIELDS",
    "PROJECTABLE_STREAM",
    "PROJECTION_SPECS",
    "ProjectionSpec",
]
