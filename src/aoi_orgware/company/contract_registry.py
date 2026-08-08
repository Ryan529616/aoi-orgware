"""Central validator registry for top-level company payloads.

The contract implementation remains in focused modules.  This registry is
loaded lazily by :func:`contracts.validate_company_contract`, avoiding a
module-initialization cycle while keeping one fail-closed dispatch table.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable, Final, Mapping

from . import contracts as _contracts
from .write_admission import (
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
    validate_work_write_intent,
    validate_write_domain_binding,
)
from .write_reservation import (
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
    validate_work_write_capability,
    validate_write_admission_enforcement,
)
from .legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    validate_legacy_bridge_observation,
)
from .legacy_bridge_health import (
    LEGACY_BRIDGE_COVERAGE_V1,
    validate_legacy_bridge_coverage,
)
from .legacy_bridge_job_terminal import (
    LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
    LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1,
    validate_legacy_bridge_job_terminal_receipt,
    validate_legacy_bridge_job_terminal_source,
)


Validator = Callable[[Any], dict[str, Any]]

CONTRACT_VALIDATORS: Final[Mapping[str, Validator]] = MappingProxyType({
    _contracts.COMPANY_MANIFEST_V1: _contracts.validate_company_manifest,
    _contracts.ACTOR_AUTHORITY_V1: _contracts.validate_actor_authority,
    _contracts.AUTHORITY_GRANT_V1: _contracts.validate_authority_grant,
    _contracts.CONTROL_INTENT_V1: _contracts.validate_control_intent,
    _contracts.TASK_REVISION_V1: _contracts.validate_task_revision,
    _contracts.WORK_PACKET_V1: _contracts.validate_work_packet,
    _contracts.WORK_RESULT_RECEIPT_V1:
        _contracts.validate_work_result_receipt,
    _contracts.WORK_DISPATCH_BINDING_V1:
        _contracts.validate_work_dispatch_binding,
    _contracts.WORK_DEFINITION_ENFORCEMENT_V1:
        _contracts.validate_work_definition_enforcement,
    WRITE_DOMAIN_BINDING_V1: validate_write_domain_binding,
    WORK_WRITE_CAPABILITY_V1: validate_work_write_capability,
    WORK_WRITE_INTENT_V1: validate_work_write_intent,
    WRITE_ADMISSION_ENFORCEMENT_V1:
        validate_write_admission_enforcement,
    _contracts.PROVIDER_CODEX_HOME_V1:
        _contracts.validate_provider_codex_home,
    _contracts.PROVIDER_LAUNCH_BINDING_V1:
        _contracts.validate_provider_launch_binding,
    _contracts.PROVIDER_WORKER_IO_RECEIPT_V1:
        _contracts.validate_provider_worker_io_receipt,
    _contracts.PROVIDER_WORKER_OPERATION_V1:
        _contracts.validate_provider_worker_operation,
    _contracts.PROVIDER_TURN_RESULT_RECEIPT_V1:
        _contracts.validate_provider_turn_result_receipt,
    _contracts.EXPECTED_HEAD_V1: _contracts.validate_expected_head,
    _contracts.EXPECTED_TRANSACTION_HEAD_V1:
        _contracts.validate_expected_transaction_head,
    _contracts.BLOB_REF_V1: _contracts.validate_blob_ref,
    _contracts.TAKEOVER_CAPABILITY_V1:
        _contracts.validate_takeover_capability,
    _contracts.TAKEOVER_CONSUMPTION_RECEIPT_V1:
        _contracts.validate_takeover_consumption_receipt,
    _contracts.COMPANY_EVENT_V1: _contracts.validate_company_event,
    _contracts.COMPANY_TRANSACTION_REQUEST_V1:
        _contracts.validate_company_transaction_request,
    _contracts.COMPANY_TRANSACTION_RECEIPT_V1:
        _contracts.validate_company_transaction_receipt,
    _contracts.ORGANIZATION_NODE_V1:
        _contracts.validate_organization_node,
    _contracts.DEPARTMENT_IDENTITY_V1:
        _contracts.validate_department_identity,
    _contracts.DEPARTMENT_SNAPSHOT_V1:
        _contracts.validate_department_snapshot,
    _contracts.CHIEF_TERM_V1: _contracts.validate_chief_term,
    _contracts.CARRIER_BINDING_V1: _contracts.validate_carrier_binding,
    _contracts.EXECUTION_NODE_V1: _contracts.validate_execution_node,
    _contracts.EXECUTION_EVENT_V1: _contracts.validate_execution_event,
    _contracts.MUTATION_INTENT_V1: _contracts.validate_mutation_intent,
    _contracts.EXTERNAL_JOB_V1: _contracts.validate_external_job,
    _contracts.DISPATCH_REQUEST_V1: _contracts.validate_dispatch_request,
    _contracts.PROVIDER_LIFECYCLE_RECEIPT_V1:
        _contracts.validate_provider_lifecycle_receipt,
    _contracts.EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1:
        _contracts.validate_execution_runtime_observation_receipt,
    _contracts.ENGINEERING_DISPOSITION_RECEIPT_V1:
        _contracts.validate_engineering_disposition_receipt,
    _contracts.PROVIDER_TELEMETRY_RECEIPT_V1:
        _contracts.validate_provider_telemetry_receipt,
    _contracts.PROVIDER_COVERAGE_REVISION_V1:
        _contracts.validate_provider_coverage_revision,
    _contracts.USAGE_COUNTER_SAMPLE_V1:
        _contracts.validate_usage_counter_sample,
    _contracts.EXTERNAL_JOB_EFFECT_RECEIPT_V1:
        _contracts.validate_external_job_effect_receipt,
    _contracts.EVIDENCE_RECORD_V1: _contracts.validate_evidence_record,
    _contracts.ARTIFACT_EDGE_V1: _contracts.validate_artifact_edge,
    _contracts.USAGE_EVENT_V1: _contracts.validate_usage_event,
    _contracts.USAGE_BURN_REVISION_V1:
        _contracts.validate_usage_burn_revision,
    _contracts.RATE_CARD_V1: _contracts.validate_rate_card,
    _contracts.ALERT_V1: _contracts.validate_alert,
    _contracts.NEEDS_USER_V1: _contracts.validate_needs_user,
    _contracts.NEEDS_USER_REVISION_V1:
        _contracts.validate_needs_user_revision,
    _contracts.ROUTE_POLICY_V1: _contracts.validate_route_policy,
    _contracts.OPTIMIZER_PROPOSAL_V1:
        _contracts.validate_optimizer_proposal,
    _contracts.CANARY_V1: _contracts.validate_canary,
    _contracts.BACKUP_ENVELOPE_V1: _contracts.validate_backup_envelope,
    _contracts.CRYPTO_VERIFICATION_RECEIPT_V1:
        _contracts.validate_crypto_verification_receipt,
    LEGACY_BRIDGE_OBSERVATION_V1: validate_legacy_bridge_observation,
    LEGACY_BRIDGE_COVERAGE_V1: validate_legacy_bridge_coverage,
    LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1:
        validate_legacy_bridge_job_terminal_receipt,
})

SOURCE_VALIDATORS: Final[Mapping[str, Validator]] = MappingProxyType({
    _contracts.PROVIDER_LIFECYCLE_SOURCE_V1:
        _contracts.validate_provider_lifecycle_source,
    _contracts.EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1:
        _contracts.validate_execution_runtime_observation_source,
    _contracts.ENGINEERING_DISPOSITION_SOURCE_V1:
        _contracts.validate_engineering_disposition_source,
    _contracts.EXTERNAL_JOB_EFFECT_SOURCE_V1:
        _contracts.validate_external_job_effect_source,
    LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1:
        validate_legacy_bridge_job_terminal_source,
})

DOCUMENT_VALIDATORS: Final[Mapping[str, Validator]] = MappingProxyType({
    _contracts.WORK_CONTEXT_MANIFEST_V1:
        _contracts.validate_work_context_manifest,
    _contracts.PROVIDER_TURN_RESULT_V1:
        _contracts.validate_provider_turn_result,
})


def contract_validator_for(
    contract_type: object,
    source_type: object,
    document_type: object,
) -> Validator | None:
    """Return the one validator selected by the frozen discriminator order."""

    if isinstance(contract_type, str):
        return CONTRACT_VALIDATORS.get(contract_type)
    if isinstance(source_type, str):
        return SOURCE_VALIDATORS.get(source_type)
    if isinstance(document_type, str):
        return DOCUMENT_VALIDATORS.get(document_type)
    return None


__all__ = [
    "CONTRACT_VALIDATORS",
    "DOCUMENT_VALIDATORS",
    "SOURCE_VALIDATORS",
    "Validator",
    "contract_validator_for",
]
