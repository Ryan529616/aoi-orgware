from __future__ import annotations

import copy
import hashlib

import pytest

from aoi_orgware import codex_app_server_stdio
from aoi_orgware.company import contracts as company_contracts
from aoi_orgware.company.blobs import BlobStore
from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1, ALERT_V1, ARTIFACT_EDGE_V1, AUTHORITY_GRANT_V1, BACKUP_ENVELOPE_V1,
    BLOB_REF_V1, CANARY_V1, CARRIER_BINDING_V1, CHIEF_TERM_V1,
    COMPANY_CONTRACT_SCHEMA_VERSION, COMPANY_EVENT_V1, CONTROL_INTENT_V1,
    COMPANY_MANIFEST_V1, COMPANY_TRANSACTION_RECEIPT_V1,
    COMPANY_TRANSACTION_REQUEST_V1, CRYPTO_VERIFICATION_RECEIPT_V1, DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_LIFECYCLE_RECEIPT_V1, DEPARTMENT_LIFECYCLE_REQUEST_V1, DEPARTMENT_LIFECYCLE_RESULT_V1, DEPARTMENT_SNAPSHOT_DOCUMENT_V1,
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE, DEPARTMENT_SNAPSHOT_V1, DISPATCH_REQUEST_V1, EVIDENCE_RECORD_V1, EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1, EXPECTED_HEAD_V1, EXPECTED_TRANSACTION_HEAD_V1, EXTERNAL_JOB_V1, MUTATION_INTENT_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1, EXTERNAL_JOB_EFFECT_SOURCE_MEDIA_TYPE,
    EXTERNAL_JOB_EFFECT_SOURCE_V1,
    NEEDS_USER_V1, OPTIMIZER_PROPOSAL_V1, ORGANIZATION_NODE_V1, RATE_CARD_V1,
    ROUTE_POLICY_V1, TAKEOVER_CAPABILITY_V1, TAKEOVER_CONSUMPTION_RECEIPT_V1,
    TASK_REVISION_V1, WORK_CONTEXT_MANIFEST_MEDIA_TYPE, WORK_CONTEXT_MANIFEST_V1,
    WORK_DEFINITION_ENFORCEMENT_V1, WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_PROMPT_MEDIA_TYPE, WORK_PACKET_V1, WORK_RESULT_RECEIPT_V1,
    PROVIDER_CODEX_HOME_V1, PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_TURN_RESULT_MEDIA_TYPE, PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_TURN_RESULT_V1, PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1, PROVIDER_WORKER_RAW_MEDIA_TYPE,
    USAGE_EVENT_V1, USAGE_BURN_REVISION_V1, ZERO_SHA256, CompanyContractError, canonical_company_json_bytes, company_contract_sha256,
    authority_from_grant, backup_aad_bytes, backup_aad_fields, validate_company_contract, validate_company_transaction_receipt,
    validate_company_transaction_request, validate_dispatch_request, validate_rate_card,
    validate_takeover_consumption_receipt, validate_usage_event, validate_usage_burn_revision,
    validate_department_lifecycle_receipt, validate_department_lifecycle_request, validate_department_lifecycle_result, validate_department_snapshot_document,
    authority_scope_is_subset, canonical_work_context_manifest_bytes, validate_task_revision,
    validate_work_context_manifest, validate_work_definition_bundle,
    validate_work_definition_enforcement, validate_work_dispatch_binding,
    validate_work_packet, validate_work_result_receipt,
    canonical_provider_turn_result_bytes, validate_provider_codex_home,
    validate_provider_launch_binding, validate_provider_turn_result,
    validate_provider_turn_result_receipt, validate_provider_worker_io_receipt,
    validate_provider_worker_operation,
    work_context_manifest_sha256,
)
from aoi_orgware.company.state import CompanyStateInvariantError, CompanyStateOwner


H = "a" * 64
B = {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 2}
T0, T1 = "2026-07-26T00:00:00Z", "2026-07-26T00:00:01Z"
DIMS = ("input", "cache_read", "cache_creation", "output", "reasoning_output", "total")


def observed() -> dict[str, object]:
    return {"state": "known", "reason": "observed"}


def blob() -> dict[str, object]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": H,
            "size_bytes": 1, "media_type": "text/plain", "availability": "available"}


def authority() -> dict[str, object]:
    return {"contract_type": ACTOR_AUTHORITY_V1, "schema_version": 1, **B,
            "actor_id": "chief-1", "actor_kind": "chief", "carrier_id": "carrier-1", "chief_epoch": 1, "term": 1,
            "authority_state": "active", "permissions": ["company.mutate", "repo.write", "job.start"],
            "scope_sha256": H, "authority_record_sha256": H, "provenance": "AOI_verified"}


def grant() -> dict[str, object]:
    value = {"contract_type": AUTHORITY_GRANT_V1, "schema_version": 1, **B,
             "grant_id": "grant-1", "actor_id": "chief-1", "actor_kind": "chief",
             "carrier_id": "carrier-1", "chief_epoch": 1, "term": 1,
             "authority_state": "active", "permissions": ["company.mutate", "repo.write", "job.start"],
             "scope_sha256": H, "issued_at": T0, "expires_at": "2026-07-26T01:00:00Z",
             "provenance": "AOI_verified"}
    value["grant_sha256"] = company_contract_sha256(value)
    return value


def control_intent() -> dict[str, object]:
    request_payload, result_payload, terminal_receipt = {"operation": "checkpoint"}, {"state": "written"}, {"cursor": 1}
    value = {"contract_type": CONTROL_INTENT_V1, "schema_version": 1, **B,
             "control_intent_id": "control-1", "command_id": "command-1", "execution_id": "exec-1",
             "authority_grant": grant(), "authority_grant_sha256": grant()["grant_sha256"],
             "request_payload": request_payload, "request_sha256": company_contract_sha256(request_payload, max_bytes=64 * 1024),
             "outcome": "committed", "result_payload": result_payload,
             "result_sha256": company_contract_sha256(result_payload, max_bytes=64 * 1024),
             "receipt_id": "control-receipt-1", "terminal_receipt": terminal_receipt,
             "receipt_sha256": company_contract_sha256(terminal_receipt, max_bytes=64 * 1024),
             "created_at": T0, "terminal_at": T1, "provenance": "AOI_verified", "observation": observed()}
    return value


def department_lifecycle_request(
    *, operation: str = "park", expected_department_status: str = "active",
) -> dict[str, object]:
    routing: dict[str, object] = {
        "dispatch_request_id": None, "reservation_id": None, "task_id": None, "packet_id": None,
        "route_policy_id": None, "requested_role": None, "requested_capability_tier": None,
    }
    if operation in {"resume", "enqueue"}:
        routing = {
            "dispatch_request_id": "dispatch-request-1", "reservation_id": "reservation-1", "task_id": "task-1",
            "packet_id": "packet-1", "route_policy_id": "route-policy-1", "requested_role": "worker",
            "requested_capability_tier": "standard",
        }
    if operation == "park":
        trigger, lead_status, snapshot_document = "explicit", "active", blob()
    elif operation == "resume":
        trigger, expected_department_status, lead_status, snapshot_document = "explicit", "parked", "parked", None
    else:
        trigger = "lazy_wake" if expected_department_status == "parked" else "explicit"
        lead_status, snapshot_document = "parked" if expected_department_status == "parked" else "active", None
    return {
        "request_type": DEPARTMENT_LIFECYCLE_REQUEST_V1, "schema_version": 1, **B,
        "operation": operation, "trigger": trigger, "requested_at": T0, "department_id": "department-1",
        "lead_node_id": "lead-1", "expected_global_sequence": 7, "expected_transaction_sha256": H,
        "expected_department_status": expected_department_status, "expected_department_payload_sha256": H,
        "expected_lead_status": lead_status, "expected_lead_payload_sha256": H, "expected_snapshot_id": "snapshot-1",
        "expected_snapshot_revision": 1, "expected_snapshot_payload_sha256": H, "expected_carrier_id": None,
        "expected_carrier_payload_sha256": None, "requested_scope_sha256": H, **routing,
        "snapshot_document": snapshot_document,
    }


def department_lifecycle_result(request: dict[str, object]) -> dict[str, object]:
    operation = request["operation"]
    if operation == "park":
        lifecycle_state, department_status, lead_status = "parked", "parked", "parked"
        dispatch_request_id = dispatch_revision = dispatch_state = execution_id = None
        carrier_transition, runtime_effect = "none", "none"
    elif operation == "resume":
        lifecycle_state, department_status, lead_status = "waking", "active", "active"
        dispatch_request_id, dispatch_revision, dispatch_state, execution_id = "dispatch-request-1", 1, "queued", None
        carrier_transition, runtime_effect = "pending", "pending_dispatch"
    else:
        lifecycle_state = "waking" if request["expected_department_status"] == "parked" else "active"
        department_status, lead_status = "active", "active"
        dispatch_request_id, dispatch_revision, dispatch_state, execution_id = "dispatch-request-1", 1, "queued", None
        carrier_transition, runtime_effect = "none", "pending_dispatch"
    return {
        "result_type": DEPARTMENT_LIFECYCLE_RESULT_V1, "schema_version": 1, **B,
        "operation": operation, "transaction_id": "transaction-1", "command_id": "command-1",
        "committed_cursor": request["expected_global_sequence"] + 1, "department_id": request["department_id"],
        "lead_node_id": request["lead_node_id"], "lifecycle_state": lifecycle_state,
        "department_status": department_status, "lead_status": lead_status, "snapshot_id": "snapshot-2",
        "snapshot_revision": 2, "snapshot_payload_sha256": H, "snapshot_cursor": 8,
        "carrier_transition": carrier_transition, "carrier_id": None, "carrier_state": None,
        "replaced_carrier_id": None, "dispatch_request_id": dispatch_request_id,
        "dispatch_revision": dispatch_revision, "dispatch_state": dispatch_state, "execution_id": execution_id,
        "runtime_effect": runtime_effect,
    }


def department_lifecycle_receipt(
    result: dict[str, object],
) -> dict[str, object]:
    return {
        "receipt_type": DEPARTMENT_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        **B,
        "transaction_id": result["transaction_id"],
        "command_id": result["command_id"],
        "committed_cursor": result["committed_cursor"],
        "operation": result["operation"],
        "department_id": result["department_id"],
    }


def department_snapshot_document(*, revision: int = 1, capture_reason: str = "checkpoint") -> dict[str, object]:
    named_ref = blob()
    return {
        "document_type": DEPARTMENT_SNAPSHOT_DOCUMENT_V1, "schema_version": 1, **B,
        "department_id": "department-1", "lead_node_id": "lead-1", "snapshot_id": "snapshot-1", "revision": revision,
        "previous_snapshot_id": None if revision == 1 else "snapshot-0",
        "previous_document_sha256": None if revision == 1 else H, "company_cursor": 7, "captured_at": T1,
        "capture_reason": capture_reason, "charter_ref": copy.deepcopy(named_ref), "constraints_ref": copy.deepcopy(named_ref),
        "decisions_ref": copy.deepcopy(named_ref), "dissent_ref": copy.deepcopy(named_ref),
        "open_questions_ref": copy.deepcopy(named_ref), "blockers_ref": copy.deepcopy(named_ref),
        "risks_ref": copy.deepcopy(named_ref), "backlog_ref": copy.deepcopy(named_ref), "handoff_ref": copy.deepcopy(named_ref),
        "active_dispatch_request_ids": [], "active_execution_ids": [], "job_ids": [], "evidence_ids": [],
        "artifact_refs": [copy.deepcopy(named_ref)],
    }


def execution_node() -> dict[str, object]:
    return {"contract_type": EXECUTION_NODE_V1, "schema_version": 1, **B,
            "execution_id": "exec-1", "execution_kind": "carrier", "display_name": "Chief",
            "organization_node_id": "chief-1", "department_id": None, "parent_execution_id": None,
            "execution_depth": 0, "execution_path": ["exec-1"], "task_id": "task-1", "packet_id": None,
            "thread_id": "thread-1", "turn_id": "turn-1", "agent_id": None, "job_id": None,
            "dispatch_id": None, "registration_id": None, "receipt_id": None, "provider": "codex",
            "model": "gpt-5", "effort": "high", "carrier_id": "carrier-1", "role": "chief",
            "delegation_depth": 0, "engineering_status": "active", "runtime_status": "running",
            "attention_overlays": ["suspected_stalled"], "objective": "work", "phase": "m1",
            "created_at": T0, "updated_at": T1, "last_event_at": T1, "heartbeat_at": T1,
            "wait_reason": None, "current_tool": None, "terminal_at": None, "usage_cursor": 0,
            "job_ids": [], "evidence_ids": [], "provenance": "AOI_verified", "observation": observed()}


def execution_event() -> dict[str, object]:
    return {"contract_type": EXECUTION_EVENT_V1, "schema_version": 1, **B,
            "event_id": "exec-event-1", "execution_id": "exec-1", "execution_kind": "carrier",
            "display_name": "Chief", "parent_execution_id": None, "execution_depth": 0,
            "execution_path": ["exec-1"], "task_id": "task-1", "packet_id": None,
            "thread_id": "thread-1", "turn_id": "turn-1", "agent_id": None, "job_id": None,
            "dispatch_id": None, "registration_id": None, "receipt_id": None, "provider": "codex",
            "model": "gpt-5", "effort": "high", "carrier_id": "carrier-1", "delegation_depth": 0,
            "event_type": "turn.started", "recorded_at": T0, "engineering_status": "active",
            "runtime_status": "running", "attention_overlays": ["suspected_stalled"], "payload": {},
            "payload_sha256": company_contract_sha256({}, max_bytes=64 * 1024), "evidence_ids": [],
            "provenance": "collector_received", "observation": observed()}


def head(stream: str, *, cursor: int = 0) -> dict[str, object]:
    return {"contract_type": EXPECTED_HEAD_V1, "schema_version": 1, **B,
            "transaction_id": "tx-1", "command_id": "command-1", "stream": stream,
            "cursor": cursor, "event_sha256": ZERO_SHA256 if cursor == 0 else H}


def transaction_head() -> dict[str, object]:
    return {"contract_type": EXPECTED_TRANSACTION_HEAD_V1, "schema_version": 1, **B,
            "transaction_id": "tx-1", "command_id": "command-1",
            "global_sequence": 0, "transaction_sha256": ZERO_SHA256}


def event(stream: str) -> dict[str, object]:
    payload = {"status": "unknown"}
    return {"contract_type": COMPANY_EVENT_V1, "schema_version": 1, **B,
            "transaction_id": "tx-1", "command_id": "command-1", "event_id": f"event-{stream}",
            "stream": stream, "event_type": "record.created", "recorded_at": T0,
            "actor_authority": authority(), "provenance": "AOI_verified", "payload": payload,
            "payload_sha256": company_contract_sha256(payload, max_bytes=64 * 1024)}


def request() -> dict[str, object]:
    value = {"contract_type": COMPANY_TRANSACTION_REQUEST_V1, "schema_version": 1, **B,
             "transaction_id": "tx-1", "command_id": "command-1", "actor_authority": authority(), "expected_transaction_head": transaction_head(),
             "expected_heads": [head("org"), head("usage")], "events": [event("org"), event("usage")]}
    value["request_sha256"] = company_contract_sha256(value)
    return value


def receipt(*, sequence: int = 1, previous: str = ZERO_SHA256) -> dict[str, object]:
    value = {"contract_type": COMPANY_TRANSACTION_RECEIPT_V1, "schema_version": 1, **B,
             "transaction_id": "tx-1", "command_id": "command-1", "request_sha256": request()["request_sha256"],
             "state": "committed", "recorded_at": T1, "global_sequence": sequence,
             "previous_transaction_sha256": previous, "result_heads": [head("org", cursor=1), head("usage", cursor=1)],
             "evidence": []}
    value["transaction_sha256"] = company_contract_sha256(value)
    value["receipt_sha256"] = company_contract_sha256(value)
    return value


def capability() -> dict[str, object]:
    value = {"contract_type": TAKEOVER_CAPABILITY_V1, "schema_version": 1, **B,
             "capability_id": "cap-1", "contender_carrier_id": "carrier-2", "expected_chief_id": "chief-1",
             "expected_term": 1, "expected_epoch": 1, "expected_head_sha256": H, "consumption_id": "consume-1", "consumption_transaction_id": "tx-1", "consumption_command_id": "command-1", "resulting_chief_id": "chief-1", "resulting_term": 2, "resulting_epoch": 2, "objective_sha256": "b" * 64,
             "scope_sha256": "c" * 64, "nonce_sha256": "d" * 64, "issued_at": T0,
             "expires_at": "2026-07-26T01:00:00Z", "user_action_ref": "action-1"}
    value["capability_sha256"] = company_contract_sha256(value)
    return value


def resulting_chief_term(cap: dict[str, object]) -> dict[str, object]:
    value = {"chief_id": cap["resulting_chief_id"], "carrier_id": cap["contender_carrier_id"],
             "term": cap["resulting_term"], "epoch": cap["resulting_epoch"],
             "takeover_capability_sha256": cap["capability_sha256"]}
    value["chief_term_sha256"] = company_contract_sha256(value)
    return value


def gates() -> dict[str, object]:
    return {"correctness_noninferior": None, "completion_noninferior": None,
            "rework_noninferior": None, "burn_noninferior": None,
            "latency_noninferior": None, "dissent_preserved": None,
            "critical_regression_free": None,
            "fenced_mutation_escape_free": None, "unknown_mutation_free": None,
            "evidence_downgrade_free": None, "burn_improvement_percent": None,
            "latency_improvement_percent": None}


def backup() -> dict[str, object]:
    value = {"contract_type": BACKUP_ENVELOPE_V1, "schema_version": 1, **B, "backup_id": "backup-1", "ledger_cursor": 1, "ledger_head_sha256": H, "manifest_sha256": H, "plaintext_sha256": H, "nonce_blob": {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": "c" * 64, "size_bytes": 12, "media_type": "application/octet-stream", "availability": "available"}, "aad_schema_version": 1, "algorithm": "AES-256-GCM", "key_fingerprint": "e" * 64, "state": "unverified", "created_at": T0, "verified_at": None, "failure_artifact": None, "crypto_verification_receipt": None, "crypto_verification_receipt_sha256": None, "observation": observed()}
    aad_sha256 = hashlib.sha256(backup_aad_bytes(value)).hexdigest()
    value["aad_sha256"] = aad_sha256
    value["ciphertext_sha256"] = "b" * 64
    value["envelope_blob"] = {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": value["ciphertext_sha256"], "size_bytes": 32, "media_type": "application/octet-stream", "availability": "available"}
    return value


def crypto_receipt(value: dict[str, object]) -> dict[str, object]:
    receipt = {"contract_type": CRYPTO_VERIFICATION_RECEIPT_V1, "schema_version": 1, **B,
               "receipt_id": "crypto-receipt-1", "backup_id": value["backup_id"],
               "aad_sha256": value["aad_sha256"], "ciphertext_sha256": value["ciphertext_sha256"],
               "envelope_sha256": value["envelope_blob"]["sha256"],
               "nonce_sha256": value["nonce_blob"]["sha256"], "algorithm": value["algorithm"],
               "key_fingerprint": value["key_fingerprint"], "verified_at": T1,
               "verification_artifact": blob()}
    receipt["receipt_sha256"] = company_contract_sha256(receipt)
    return receipt


def canary(*, state: str = "planned") -> dict[str, object]:
    return {"contract_type": CANARY_V1, "schema_version": 1, **B, "canary_id": "canary-1",
            "proposal_id": "proposal-1", "assignment_percent": 10,
            "assignment_reference_sha256": None, "baseline_cohort_manifest_sha256": None,
            "canary_cohort_manifest_sha256": None, "control_cohort_manifest_sha256": None,
            "matching_manifest_sha256": None, "external_oracle_ref": None,
            "external_oracle_sha256": None, "window_started_at": None, "window_ended_at": None,
            "baseline_count": 20, "canary_count": 0, "control_count": 0, "state": state,
            "started_at": T0, "ended_at": None, "evidence_ids": [], "evidence_artifacts": [],
            "hard_gates": gates(), "observation": observed()}


def route_policy() -> dict[str, object]:
    value = {"contract_type": ROUTE_POLICY_V1, "schema_version": 1, **B,
             "policy_id": "policy-1", "revision": 1,
             "allowed_providers": ["codex"], "allowed_models": ["gpt-5"],
             "allowed_efforts": ["high"], "created_at": T0,
             "observation": observed()}
    value["policy_sha256"] = company_contract_sha256(value)
    return value


def passed_canary() -> dict[str, object]:
    value = canary(state="passed")
    value.update({"assignment_reference_sha256": "b" * 64, "baseline_cohort_manifest_sha256": "c" * 64,
                  "canary_cohort_manifest_sha256": "d" * 64, "control_cohort_manifest_sha256": "e" * 64,
                  "matching_manifest_sha256": "f" * 64, "external_oracle_ref": "oracle-1",
                  "external_oracle_sha256": H, "window_started_at": T0, "window_ended_at": T1,
                  "canary_count": 20, "control_count": 20, "ended_at": T1,
                  "evidence_ids": ["evidence-1"], "evidence_artifacts": [blob()],
                  "hard_gates": {"correctness_noninferior": True, "completion_noninferior": True,
                                 "rework_noninferior": True, "burn_noninferior": True,
                                 "latency_noninferior": True, "dissent_preserved": True,
                                 "critical_regression_free": True, "fenced_mutation_escape_free": True,
                                 "unknown_mutation_free": True, "evidence_downgrade_free": True,
                                 "burn_improvement_percent": 10, "latency_improvement_percent": 0}})
    return value


def token_vector(n: int = 10, present: bool = True) -> dict[str, object]:
    return {d: {"present": present, "tokens": n if present else None} for d in DIMS}


def rate_card() -> dict[str, object]:
    weights = {d: (1_000_000 if d == "total" else 0) for d in DIMS}
    value = {"contract_type": RATE_CARD_V1, "schema_version": 1, **B, "rate_card_id": "card-1",
             "revision": 1, "provider": "codex", "model": "gpt-5", "effort": "high",
             "formula_version": "weighted-token-v1", "included_dimensions": ["total"],
             "dimension_weights": weights, "previous_rate_card_sha256": ZERO_SHA256, "observation": observed()}
    value["weights_sha256"] = company_contract_sha256({k: v for k, v in value.items() if k in {"rate_card_id", "revision", "provider", "model", "effort", "formula_version", "included_dimensions", "dimension_weights"}})
    value["rate_card_sha256"] = company_contract_sha256(value)
    return value


def usage() -> dict[str, object]:
    raw, assigned, remainder = token_vector(10), token_vector(7), token_vector(3)
    value = {"contract_type": USAGE_EVENT_V1, "schema_version": 1, **B, "usage_id": "usage-1",
            "aggregation_scope": "execution", "execution_id": "exec-1", "department_id": "rtl", "provider": "codex", "model": "gpt-5",
            "effort": "high", "sample_kind": "exact", "recorded_at": T0,
            "thread_id": "thread-1", "turn_id": "turn-1",
            "measurement_kind": "cumulative",
            "provider_counter_scope_id": "codex-thread-thread-1",
            "provider_update_id": "token-update-1", "provider_sequence": 1,
            "observation_started_at": T0, "observation_ended_at": T0,
            "previous_usage_sha256": ZERO_SHA256, "raw_token_vector": raw,
            "source": {"source_id": "sample-1", "source_sha256": H, "provenance": "provider_client_emitted"},
            "aggregation": {"observed_total": copy.deepcopy(raw), "attributions": [{"execution_id": "exec-1", "department_id": "rtl", "token_vector": assigned}], "unattributed": remainder}, "observation": observed()}
    value["usage_sha256"] = company_contract_sha256(value)
    return value


def test_transaction_streams_command_and_global_chain_are_exact() -> None:
    assert validate_company_transaction_request(request())["command_id"] == "command-1"
    valid = receipt()
    assert validate_company_transaction_receipt(valid)["global_sequence"] == 1
    second = receipt(sequence=2, previous=valid["transaction_sha256"])
    assert validate_company_transaction_receipt(second)["global_sequence"] == 2
    for change in (
        lambda v: v["events"].pop(),
        lambda v: v["events"][0].__setitem__("command_id", "other"),
    ):
        broken = request(); change(broken); broken["request_sha256"] = company_contract_sha256({k: x for k, x in broken.items() if k != "request_sha256"})
        with pytest.raises(CompanyContractError): validate_company_transaction_request(broken)
    for change in (
        lambda v: v["result_heads"][0].__setitem__("command_id", "other"),
        lambda v: v.__setitem__("previous_transaction_sha256", H),
    ):
        broken = receipt(); change(broken); broken["transaction_sha256"] = company_contract_sha256({k: x for k, x in broken.items() if k not in {"transaction_sha256", "receipt_sha256"}}); broken["receipt_sha256"] = company_contract_sha256({k: x for k, x in broken.items() if k != "receipt_sha256"})
        with pytest.raises(CompanyContractError): validate_company_transaction_receipt(broken)


def test_capability_expiry_and_usage_attribution_are_not_ambiguous() -> None:
    cap = capability()
    receipt_value = {"contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1, "schema_version": 1, **B,
                     "consumption_id": "consume-1", "transaction_id": "tx-1", "command_id": "command-1",
                     "capability": cap, "capability_sha256": cap["capability_sha256"], "outcome": "consumed", "resulting_chief_term": resulting_chief_term(cap), "consumed_at": T1}
    receipt_value["receipt_sha256"] = company_contract_sha256(receipt_value)
    assert validate_takeover_consumption_receipt(receipt_value)["command_id"] == "command-1"
    expired = copy.deepcopy(receipt_value); expired["consumed_at"] = "2026-07-26T01:00:00Z"; expired["receipt_sha256"] = company_contract_sha256({k: x for k, x in expired.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_takeover_consumption_receipt(expired)
    assert validate_usage_event(usage())["aggregation"]["attributions"][0]["execution_id"] == "exec-1"
    broken = usage(); broken["aggregation"]["attributions"][0]["token_vector"]["total"]["tokens"] = 8
    with pytest.raises(CompanyContractError): validate_usage_event(broken)
    broken = usage(); broken["sample_kind"] = "exact"; broken["source"]["provenance"] = "agent_reported"
    with pytest.raises(CompanyContractError): validate_usage_event(broken)
    unknown = usage(); unknown["sample_kind"] = "unknown"; unknown["raw_token_vector"] = token_vector(present=False); unknown["aggregation"] = {"observed_total": token_vector(present=False), "attributions": [], "unattributed": token_vector(present=False)}; unknown["source"]["provenance"] = "unknown"
    with pytest.raises(CompanyContractError): validate_usage_event(unknown)


def test_running_runtime_truth_requires_an_observed_non_unknown_source() -> None:
    for index in (6, 7):
        value = copy.deepcopy(family_records()[index])
        value["provenance"] = "unknown"
        value["observation"] = {"state": "unknown", "reason": "not_observed"}
        with pytest.raises(CompanyContractError, match="running"):
            validate_company_contract(value)

        value["runtime_status"] = "telemetry_silent"
        assert validate_company_contract(value)["runtime_status"] == "telemetry_silent"


def test_usage_cumulative_update_coordinates_are_strict_and_replayable() -> None:
    first = usage()
    validated = validate_usage_event(first)
    assert validated["thread_id"] == "thread-1"
    assert validated["measurement_kind"] == "cumulative"
    assert validated["provider_sequence"] == 1

    second = usage()
    second.update({
        "usage_id": "usage-2",
        "provider_update_id": "token-update-2",
        "provider_sequence": 2,
        "previous_usage_sha256": first["usage_sha256"],
    })
    second["source"]["source_id"] = "sample-2"
    second["usage_sha256"] = company_contract_sha256(
        {key: member for key, member in second.items() if key != "usage_sha256"}
    )
    assert validate_usage_event(second)["previous_usage_sha256"] == first["usage_sha256"]

    for change in (
        lambda value: value.__setitem__("thread_id", None),
        lambda value: value.__setitem__("provider_update_id", None),
        lambda value: value.__setitem__("provider_sequence", None),
        lambda value: value.__setitem__("observation_started_at", T1),
        lambda value: value.__setitem__("observation_ended_at", T1),
    ):
        malformed = usage()
        change(malformed)
        malformed["usage_sha256"] = company_contract_sha256(
            {key: member for key, member in malformed.items() if key != "usage_sha256"}
        )
        with pytest.raises(CompanyContractError):
            validate_usage_event(malformed)

    unknown_measurement = usage()
    unknown_measurement.update({
        "measurement_kind": "unknown",
        "provider_counter_scope_id": None,
        "provider_update_id": None,
        "provider_sequence": None,
        "observation_started_at": None,
        "observation_ended_at": None,
        "previous_usage_sha256": ZERO_SHA256,
    })
    unknown_measurement["usage_sha256"] = company_contract_sha256(
        {
            key: member for key, member in unknown_measurement.items()
            if key != "usage_sha256"
        }
    )
    assert validate_usage_event(unknown_measurement)["measurement_kind"] == "unknown"


def test_takeover_capability_preserves_logical_chief_and_validates_numbers_before_arithmetic() -> None:
    valid = capability()
    assert validate_company_contract(valid)["resulting_chief_id"] == "chief-1"

    changed_chief = capability()
    changed_chief["resulting_chief_id"] = "chief-2"
    changed_chief["capability_sha256"] = company_contract_sha256(
        {key: member for key, member in changed_chief.items() if key != "capability_sha256"}
    )
    with pytest.raises(CompanyContractError):
        validate_company_contract(changed_chief)

    for field in ("expected_term", "expected_epoch", "resulting_term", "resulting_epoch"):
        malformed = capability()
        malformed[field] = "not-an-integer"
        malformed["capability_sha256"] = company_contract_sha256(
            {key: member for key, member in malformed.items() if key != "capability_sha256"}
        )
        with pytest.raises(CompanyContractError):
            validate_company_contract(malformed)


def test_rate_card_excludes_double_counting_and_burn_is_separate() -> None:
    assert validate_rate_card(rate_card())["included_dimensions"] == ["total"]
    double = rate_card(); double["included_dimensions"] = ["total", "input"]; double["dimension_weights"]["input"] = 1; double["weights_sha256"] = company_contract_sha256({k: v for k, v in double.items() if k in {"rate_card_id", "revision", "provider", "model", "effort", "formula_version", "included_dimensions", "dimension_weights"}})
    with pytest.raises(CompanyContractError): validate_rate_card(double)
    burn = {"contract_type": USAGE_BURN_REVISION_V1, "schema_version": 1, **B,
            "burn_id": "burn-1", "raw_usage_id": "usage-1", "raw_usage_sha256": usage()["usage_sha256"],
            "rate_card_id": "card-1", "rate_card_revision": 1, "rate_card_sha256": rate_card()["rate_card_sha256"],
            "provider": "codex", "model": "gpt-5", "effort": "high",
            "previous_burn_sha256": ZERO_SHA256, "effective_cursor": 1, "formula_version": "weighted-token-v1", "burn_units": 10, "observation": observed()}
    burn["burn_sha256"] = company_contract_sha256(burn)
    assert validate_usage_burn_revision(burn)["raw_usage_id"] == "usage-1"


def family_records() -> list[dict[str, object]]:
    return [
        {"contract_type": COMPANY_MANIFEST_V1, "schema_version": 1, **B, "git_common_dir_sha256": H, "remote_fingerprint_sha256": H, "configuration_sha256": H, "state_root_sha256": H, "lock_domain_id": "lock-1", "created_at": T0, "observation": observed()},
        {"contract_type": ORGANIZATION_NODE_V1, "schema_version": 1, **B, "node_id": "chief-1", "department_id": None, "parent_node_id": None, "role": "chief", "reports_to_node_id": None, "can_delegate": True, "delegation_depth": 0, "status": "active", "visibility": "company", "created_at": T0, "observation": observed()},
        {"contract_type": DEPARTMENT_IDENTITY_V1, "schema_version": 1, **B, "department_id": "rtl", "name": "RTL", "charter_sha256": H, "scope_sha256": H, "lead_node_id": None, "created_at": T0, "status": "active", "observation": observed()},
        {"contract_type": DEPARTMENT_SNAPSHOT_V1, "schema_version": 1, **B, "snapshot_id": "snap-1", "department_id": "rtl", "revision": 1, "company_cursor": 1, "previous_snapshot_id": None, "charter_sha256": H, "constraints_sha256": H, "decisions_sha256": H, "open_questions_sha256": H, "handoff_sha256": H, "artifact_refs": [], "captured_at": T0, "observation": observed()},
        {"contract_type": CHIEF_TERM_V1, "schema_version": 1, **B, "chief_id": "chief-1", "carrier_id": None, "term": 1, "epoch": 1, "state": "active", "issued_at": T0, "ended_at": None, "previous_transaction_sha256": ZERO_SHA256, "takeover_capability_sha256": None, "takeover_consumption_receipt_sha256": None, "observation": observed()},
        {"contract_type": CARRIER_BINDING_V1, "schema_version": 1, **B, "carrier_id": "carrier-1", "actor_id": "chief-1", "provider": "codex", "model": "gpt-5", "session_id": "thread-1", "session_availability": "available", "state": "active", "bound_at": T0, "last_observed_at": T1, "observation": observed()},
        execution_node(),
        execution_event(),
        {"contract_type": MUTATION_INTENT_V1, "schema_version": 1, **B, "intent_id": "intent-1", "execution_id": "exec-1", "mutation_kind": "repo.write", "command_id": "command-1", "command_blob": blob(), "scope_sha256": H, "actor_authority": authority(), "state": "prepared", "expected_head_sha256": H, "created_at": T0, "updated_at": T1, "effect_evidence": [], "reconcile_ref": None, "observation": observed()},
        {"contract_type": EXTERNAL_JOB_V1, "schema_version": 1, **B, "job_id": "job-1", "owner_execution_id": "exec-1", "mutation_intent_id": "intent-1", "command_id": "command-1", "command_blob": blob(), "scope_sha256": H, "actor_authority": authority(), "state": "queued", "external_handle": None, "process_fingerprint_sha256": None, "process_observation": {"state": "unavailable", "reason": "not_started"}, "created_at": T0, "updated_at": T1, "terminal_at": None, "effect_evidence": [], "reconcile_ref": None, "observation": observed()},
        {"contract_type": EVIDENCE_RECORD_V1, "schema_version": 1, **B, "evidence_id": "evidence-1", "execution_id": "exec-1", "claim_id": None, "evidence_class": "runtime", "status": "pass", "artifact": blob(), "command_sha256": H, "verification_sha256": H, "recorded_at": T0, "provenance": "AOI_verified", "observation": observed()},
        {"contract_type": ARTIFACT_EDGE_V1, "schema_version": 1, **B, "edge_id": "edge-1", "source_kind": "blob", "source_id": "blob-1", "target_kind": "evidence", "target_id": "evidence-1", "relation": "produces", "recorded_at": T0, "observation": observed()},
        {"contract_type": ALERT_V1, "schema_version": 1, **B, "alert_id": "alert-1", "execution_id": None, "severity": "critical", "state": "open", "category": "coverage", "created_at": T0, "resolved_at": None, "detail_sha256": H, "observation": observed()},
        {"contract_type": NEEDS_USER_V1, "schema_version": 1, **B, "item_id": "need-1", "execution_id": None, "chief_term": 1, "state": "pending", "question_sha256": H, "created_at": T0, "answered_at": None, "observation": observed()},
        route_policy(),
        {"contract_type": OPTIMIZER_PROPOSAL_V1, "schema_version": 1, **B, "proposal_id": "proposal-1", "base_policy_sha256": H, "candidate_policy_sha256": "b" * 64, "changed_dimension": "model", "state": "proposed", "created_at": T0, "evidence_ids": [], "observation": observed()},
        canary(),
        backup(),
        usage(),
    ]


def test_every_planned_family_has_an_explicit_strict_schema() -> None:
    for record in family_records():
        assert validate_company_contract(record)["contract_type"] == record["contract_type"]
        bad = copy.deepcopy(record); bad["unexpected"] = True
        with pytest.raises(CompanyContractError):
            validate_company_contract(bad)


@pytest.mark.parametrize("bad_value", ([], {}), ids=("list", "dict"))
@pytest.mark.parametrize(("record_index", "field"), (
    (1, "status"),
    (5, "session_availability"),
    (8, "state"),
    (11, "relation"),
))
def test_enum_fields_reject_non_strings_as_contract_errors(
    record_index: int, field: str, bad_value: object,
) -> None:
    record = copy.deepcopy(family_records()[record_index])
    record[field] = bad_value
    with pytest.raises(CompanyContractError):
        validate_company_contract(record)


@pytest.mark.parametrize("bad_value", ([], {}), ids=("list", "dict"))
def test_mutation_kind_rejects_non_identifier_values_as_contract_errors(
    bad_value: object,
) -> None:
    mutation = copy.deepcopy(family_records()[8])
    mutation["mutation_kind"] = bad_value
    with pytest.raises(CompanyContractError):
        validate_company_contract(mutation)


def test_root_nullability_and_effect_unknown_are_not_faked() -> None:
    root = family_records()[1]
    assert validate_company_contract(root)["parent_node_id"] is None
    invalid = copy.deepcopy(root); invalid["parent_node_id"] = ""
    with pytest.raises(CompanyContractError): validate_company_contract(invalid)
    mutation = family_records()[8]; mutation["state"] = "effect_unknown"
    with pytest.raises(CompanyContractError): validate_company_contract(mutation)


def test_request_authority_and_genesis_heads_are_exact() -> None:
    valid = request()
    assert validate_company_transaction_request(valid)["actor_authority"]["carrier_id"] == "carrier-1"

    wrong_authority = request()
    wrong_authority["events"][0]["actor_authority"]["authority_record_sha256"] = "b" * 64
    wrong_authority["request_sha256"] = company_contract_sha256(
        {key: member for key, member in wrong_authority.items() if key != "request_sha256"}
    )
    with pytest.raises(CompanyContractError):
        validate_company_transaction_request(wrong_authority)

    invalid_genesis = request()
    invalid_genesis["expected_heads"][0]["event_sha256"] = H
    invalid_genesis["request_sha256"] = company_contract_sha256(
        {key: member for key, member in invalid_genesis.items() if key != "request_sha256"}
    )
    with pytest.raises(CompanyContractError):
        validate_company_transaction_request(invalid_genesis)

    invalid_result = receipt()
    invalid_result["result_heads"][0] = head("org")
    invalid_result["transaction_sha256"] = company_contract_sha256(
        {key: member for key, member in invalid_result.items()
         if key not in {"transaction_sha256", "receipt_sha256"}}
    )
    invalid_result["receipt_sha256"] = company_contract_sha256(
        {key: member for key, member in invalid_result.items() if key != "receipt_sha256"}
    )
    with pytest.raises(CompanyContractError):
        validate_company_transaction_receipt(invalid_result)


def test_request_global_genesis_requires_genesis_stream_heads() -> None:
    global_genesis_with_advanced_stream = request()
    global_genesis_with_advanced_stream["expected_heads"][0] = head("org", cursor=1)
    global_genesis_with_advanced_stream["request_sha256"] = company_contract_sha256(
        {key: member for key, member in global_genesis_with_advanced_stream.items()
         if key != "request_sha256"}
    )
    with pytest.raises(CompanyContractError):
        validate_company_transaction_request(global_genesis_with_advanced_stream)

    non_genesis_global_with_new_stream = request()
    non_genesis_global_with_new_stream["expected_transaction_head"] = {
        **transaction_head(), "global_sequence": 1, "transaction_sha256": H,
    }
    non_genesis_global_with_new_stream["expected_heads"][0] = head("org", cursor=1)
    non_genesis_global_with_new_stream["request_sha256"] = company_contract_sha256(
        {key: member for key, member in non_genesis_global_with_new_stream.items()
         if key != "request_sha256"}
    )
    validated = validate_company_transaction_request(non_genesis_global_with_new_stream)
    assert validated["expected_transaction_head"]["global_sequence"] == 1
    assert validated["expected_heads"][1]["cursor"] == 0


def test_request_rejects_rehashed_cross_company_expected_head() -> None:
    cross_company = request()
    cross_company["expected_heads"][0]["company_id"] = "company-2"
    cross_company["request_sha256"] = company_contract_sha256(
        {key: member for key, member in cross_company.items() if key != "request_sha256"}
    )
    with pytest.raises(CompanyContractError):
        validate_company_transaction_request(cross_company)


def test_root_reports_to_and_aborted_launch_claims_fail_closed() -> None:
    root = copy.deepcopy(family_records()[1])
    root["reports_to_node_id"] = "chief-2"
    with pytest.raises(CompanyContractError):
        validate_company_contract(root)

    aborted = copy.deepcopy(family_records()[9])
    aborted.update({"state": "aborted", "terminal_at": T1,
                    "process_observation": {"state": "unavailable", "reason": "aborted_before_launch"}})
    assert validate_company_contract(aborted)["state"] == "aborted"
    aborted["external_handle"] = {"provider": "eda", "namespace": "jobs", "resolver": "pid", "native_handle": "100", "host_fingerprint_sha256": H}
    with pytest.raises(CompanyContractError):
        validate_company_contract(aborted)


def test_local_graph_and_snapshot_lifecycle_constraints_fail_closed() -> None:
    child = copy.deepcopy(family_records()[1])
    child.update({"node_id": "rtl-lead", "parent_node_id": "chief-1", "reports_to_node_id": "chief-1",
                  "delegation_depth": 1, "department_id": "rtl", "role": "department_lead",
                  "visibility": "subtree"})
    assert validate_company_contract(child)["node_id"] == "rtl-lead"
    for field in ("parent_node_id", "reports_to_node_id"):
        self_link = copy.deepcopy(child)
        self_link[field] = "rtl-lead"
        with pytest.raises(CompanyContractError):
            validate_company_contract(self_link)

    first = copy.deepcopy(family_records()[3])
    assert validate_company_contract(first)["revision"] == 1
    first["previous_snapshot_id"] = "snap-0"
    with pytest.raises(CompanyContractError):
        validate_company_contract(first)
    second = copy.deepcopy(family_records()[3])
    second.update({"snapshot_id": "snap-2", "revision": 2, "previous_snapshot_id": "snap-1"})
    assert validate_company_contract(second)["previous_snapshot_id"] == "snap-1"
    second["previous_snapshot_id"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(second)

    edge = copy.deepcopy(family_records()[11])
    assert validate_company_contract(edge)["edge_id"] == "edge-1"
    edge.update({"target_kind": "blob", "target_id": "blob-1"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(edge)

    aborted = copy.deepcopy(family_records()[9])
    aborted.update({"state": "aborted", "terminal_at": T1, "process_fingerprint_sha256": H,
                    "process_observation": observed()})
    with pytest.raises(CompanyContractError):
        validate_company_contract(aborted)


def test_backup_aad_is_pre_encryption_and_verified_receipt_binds_outputs() -> None:
    value = backup()
    aad = backup_aad_bytes(value)
    assert len(aad) == 625
    assert hashlib.sha256(aad).hexdigest() == "185c226e69db10e796063159c1b5d8b7ae260d558b559ff5150a1337e04d53d5"
    pre_encryption = copy.deepcopy(value)
    pre_encryption.pop("ciphertext_sha256")
    pre_encryption.pop("envelope_blob")
    assert backup_aad_fields(pre_encryption) == backup_aad_fields(value)
    assert "ciphertext_sha256" not in backup_aad_fields(value)
    assert "envelope_blob" not in backup_aad_fields(value)

    value["ciphertext_sha256"] = "d" * 64
    value["envelope_blob"]["sha256"] = value["ciphertext_sha256"]
    assert validate_company_contract(value)["aad_sha256"] == backup()["aad_sha256"]

    verified = backup()
    verified.update({"state": "verified", "verified_at": T1})
    receipt = crypto_receipt(verified)
    verified.update({"crypto_verification_receipt": receipt,
                     "crypto_verification_receipt_sha256": receipt["receipt_sha256"]})
    assert validate_company_contract(verified)["state"] == "verified"
    verified["crypto_verification_receipt"]["aad_sha256"] = "f" * 64
    verified["crypto_verification_receipt"]["receipt_sha256"] = company_contract_sha256(
        {key: member for key, member in verified["crypto_verification_receipt"].items()
         if key != "receipt_sha256"}
    )
    verified["crypto_verification_receipt_sha256"] = verified["crypto_verification_receipt"]["receipt_sha256"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(verified)


def test_r14_backup_terminal_and_unknown_observation_truth_table() -> None:
    failed = backup()
    failed.update({"state": "failed", "failure_artifact": blob()})
    assert validate_company_contract(failed)["state"] == "failed"
    failed["observation"] = {"state": "partial", "reason": "collector_lag"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(failed)

    unknown = backup()
    unknown.update({"state": "unknown", "observation": {"state": "unknown", "reason": "verification_lost"}})
    assert validate_company_contract(unknown)["state"] == "unknown"
    for observation in (observed(), {"state": "partial", "reason": "collector_lag"}):
        invalid = copy.deepcopy(unknown)
        invalid["observation"] = observation
        with pytest.raises(CompanyContractError):
            validate_company_contract(invalid)


def test_m3_runtime_contracts_are_strict_and_leave_cross_record_idempotency_to_supervisor() -> None:
    current = grant()
    assert validate_company_contract(current)["grant_sha256"] == current["grant_sha256"]
    derived = authority_from_grant(current)
    assert derived["authority_record_sha256"] == current["grant_sha256"]
    for change in (
        lambda value: value.pop("expires_at"),
        lambda value: value.__setitem__("unexpected", True),
        lambda value: value.__setitem__("scope_sha256", "b" * 64),
    ):
        malformed = grant()
        change(malformed)
        with pytest.raises(CompanyContractError):
            validate_company_contract(malformed)

    nonactive = grant()
    nonactive.update({"authority_state": "fenced", "permissions": []})
    nonactive["grant_sha256"] = company_contract_sha256({key: member for key, member in nonactive.items() if key != "grant_sha256"})
    assert authority_from_grant(nonactive)["authority_state"] == "fenced"

    intent = control_intent()
    assert validate_company_contract(intent)["request_sha256"] == intent["request_sha256"]
    missing = copy.deepcopy(intent); missing.pop("terminal_receipt")
    with pytest.raises(CompanyContractError):
        validate_company_contract(missing)
    tampered = copy.deepcopy(intent); tampered["request_payload"] = {"operation": "publish"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(tampered)
    binding_mismatch = copy.deepcopy(intent)
    binding_mismatch["authority_grant"]["company_id"] = "company-2"
    binding_mismatch["authority_grant"]["grant_sha256"] = company_contract_sha256(
        {key: member for key, member in binding_mismatch["authority_grant"].items() if key != "grant_sha256"}
    )
    binding_mismatch["authority_grant_sha256"] = binding_mismatch["authority_grant"]["grant_sha256"]
    with pytest.raises(CompanyContractError, match="binding"):
        validate_company_contract(binding_mismatch)
    denied = copy.deepcopy(intent)
    denied["authority_grant"] = nonactive
    denied["authority_grant_sha256"] = nonactive["grant_sha256"]
    with pytest.raises(CompanyContractError, match="active"):
        validate_company_contract(denied)

    # Same command ID/payload is an exact replay; a different payload remains a
    # valid single record but must be rejected by the Supervisor's idempotency index.
    same = copy.deepcopy(intent)
    assert validate_company_contract(same)["control_intent_id"] == intent["control_intent_id"]
    different = copy.deepcopy(intent)
    different["request_payload"] = {"operation": "reconcile"}
    different["request_sha256"] = company_contract_sha256(different["request_payload"], max_bytes=64 * 1024)
    assert validate_company_contract(different)["request_sha256"] != intent["request_sha256"]


@pytest.mark.parametrize(("operation", "expected_department_status"), (
    ("park", "active"), ("resume", "parked"), ("enqueue", "parked"), ("enqueue", "active"),
))
def test_m4_department_lifecycle_payloads_accept_the_exact_operation_matrices(
    operation: str, expected_department_status: str,
) -> None:
    request = department_lifecycle_request(
        operation=operation, expected_department_status=expected_department_status,
    )
    result = department_lifecycle_result(request)
    assert validate_department_lifecycle_request(request)["operation"] == operation
    assert validate_department_lifecycle_result(result, request=request)["committed_cursor"] == 8

    intent = control_intent()
    intent["request_payload"] = request
    intent["request_sha256"] = company_contract_sha256(request, max_bytes=64 * 1024)
    intent["result_payload"] = result
    intent["result_sha256"] = company_contract_sha256(result, max_bytes=64 * 1024)
    receipt = department_lifecycle_receipt(result)
    intent["terminal_receipt"] = receipt
    intent["receipt_sha256"] = company_contract_sha256(
        receipt,
        max_bytes=64 * 1024,
    )
    assert validate_company_contract(intent)["result_payload"]["result_type"] == DEPARTMENT_LIFECYCLE_RESULT_V1


def test_m4_department_lifecycle_payloads_reject_unknown_cross_bound_and_unpaired_fields() -> None:
    request = department_lifecycle_request()
    request["unexpected"] = None
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_request(request)

    request = department_lifecycle_request()
    request["expected_carrier_id"] = "carrier-1"
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_request(request)

    request = department_lifecycle_request()
    request["dispatch_request_id"] = "dispatch-request-1"
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_request(request)

    request = department_lifecycle_request(operation="resume")
    request["snapshot_document"] = blob()
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_request(request)

    request = department_lifecycle_request(operation="enqueue", expected_department_status="parked")
    result = department_lifecycle_result(request)
    result["lifecycle_state"] = "active"
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_result(result, request=request)

    result = department_lifecycle_result(department_lifecycle_request())
    result["dispatch_state"] = "queued"
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_result(result)

    request = department_lifecycle_request()
    result = department_lifecycle_result(request)
    result["snapshot_cursor"] = 0
    with pytest.raises(CompanyContractError):
        validate_department_lifecycle_result(result, request=request)

    intent = control_intent()
    request = department_lifecycle_request()
    result = department_lifecycle_result(request)
    result["command_id"] = "different-command"
    intent["request_payload"] = request
    intent["request_sha256"] = company_contract_sha256(request, max_bytes=64 * 1024)
    intent["result_payload"] = result
    intent["result_sha256"] = company_contract_sha256(result, max_bytes=64 * 1024)
    receipt = department_lifecycle_receipt(result)
    intent["terminal_receipt"] = receipt
    intent["receipt_sha256"] = company_contract_sha256(
        receipt,
        max_bytes=64 * 1024,
    )
    with pytest.raises(CompanyContractError, match="command"):
        validate_company_contract(intent)

    intent = control_intent()
    request = department_lifecycle_request()
    intent["request_payload"] = request
    intent["request_sha256"] = company_contract_sha256(request, max_bytes=64 * 1024)
    with pytest.raises(CompanyContractError, match="must pair"):
        validate_company_contract(intent)


def test_m4_department_lifecycle_terminal_receipt_is_exactly_cross_bound() -> None:
    request = department_lifecycle_request()
    result = department_lifecycle_result(request)
    receipt = department_lifecycle_receipt(result)
    assert validate_department_lifecycle_receipt(
        receipt,
        result=result,
    )["committed_cursor"] == result["committed_cursor"]

    intent = control_intent()
    intent["request_payload"] = request
    intent["request_sha256"] = company_contract_sha256(
        request,
        max_bytes=64 * 1024,
    )
    intent["result_payload"] = result
    intent["result_sha256"] = company_contract_sha256(
        result,
        max_bytes=64 * 1024,
    )
    divergent = {
        **receipt,
        "transaction_id": "wrong-transaction",
        "command_id": "wrong-command",
        "committed_cursor": 999,
        "operation": "enqueue",
        "department_id": "wrong-department",
    }
    intent["terminal_receipt"] = divergent
    intent["receipt_sha256"] = company_contract_sha256(
        divergent,
        max_bytes=64 * 1024,
    )
    with pytest.raises(CompanyContractError, match="Receipt differs"):
        validate_company_contract(intent)

    intent = control_intent()
    result = department_lifecycle_result(department_lifecycle_request())
    intent["result_payload"] = result
    intent["result_sha256"] = company_contract_sha256(result, max_bytes=64 * 1024)
    with pytest.raises(CompanyContractError, match="must pair"):
        validate_company_contract(intent)


def test_m4_department_snapshot_document_is_strict_bounded_and_private() -> None:
    document = department_snapshot_document()
    assert validate_department_snapshot_document(document)["document_type"] == DEPARTMENT_SNAPSHOT_DOCUMENT_V1
    assert validate_department_snapshot_document(department_snapshot_document(revision=2))["revision"] == 2

    invalid = department_snapshot_document()
    invalid["previous_document_sha256"] = H
    with pytest.raises(CompanyContractError):
        validate_department_snapshot_document(invalid)

    invalid = department_snapshot_document(capture_reason="park")
    invalid["active_execution_ids"] = ["execution-1"]
    with pytest.raises(CompanyContractError):
        validate_department_snapshot_document(invalid)

    invalid = department_snapshot_document()
    invalid["charter_ref"]["availability"] = "unknown"
    invalid["charter_ref"]["sha256"] = None
    invalid["charter_ref"]["size_bytes"] = None
    with pytest.raises(CompanyContractError):
        validate_department_snapshot_document(invalid)

    invalid = department_snapshot_document()
    invalid["artifact_refs"] = [blob(), blob()]
    with pytest.raises(CompanyContractError):
        validate_department_snapshot_document(invalid)

    invalid = department_snapshot_document()
    invalid["session_id"] = "private-session"
    with pytest.raises(CompanyContractError):
        validate_department_snapshot_document(invalid)

    oversize = department_snapshot_document()
    long_ids = [f"{index:03d}-{'x' * 252}" for index in range(256)]
    oversize.update({
        "active_dispatch_request_ids": long_ids, "active_execution_ids": long_ids,
        "job_ids": long_ids, "evidence_ids": long_ids,
    })
    with pytest.raises(CompanyContractError):
        validate_department_snapshot_document(oversize)


def test_m4_generic_control_intent_payloads_remain_generic() -> None:
    assert validate_company_contract(control_intent())["request_payload"] == {"operation": "checkpoint"}


def test_m3_execution_identity_separates_execution_and_delegation_depth() -> None:
    root = execution_node()
    assert validate_company_contract(root)["thread_id"] == "thread-1"
    child = copy.deepcopy(root)
    child.update({"parent_execution_id": "exec-6", "execution_depth": 7,
                  "execution_path": ["exec-root", "exec-a", "exec-b", "exec-c", "exec-d", "exec-e", "exec-6", "exec-1"],
                  "delegation_depth": 6})
    assert validate_company_contract(child)["execution_depth"] == 7
    child["delegation_depth"] = 7
    with pytest.raises(CompanyContractError):
        validate_company_contract(child)
    invalid_path = execution_node(); invalid_path["execution_path"] = ["wrong"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(invalid_path)

    agent = execution_node()
    agent.update({"execution_kind": "agent", "agent_id": "agent-1", "dispatch_id": "dispatch-1"})
    assert validate_company_contract(agent)["dispatch_id"] == "dispatch-1"
    agent["registration_id"] = "registration-1"
    with pytest.raises(CompanyContractError):
        validate_company_contract(agent)
    job = execution_node()
    job.update({"execution_kind": "job", "carrier_id": None, "thread_id": None, "turn_id": None,
                "job_id": "job-1", "dispatch_id": None})
    assert validate_company_contract(job)["job_id"] == "job-1"
    job["agent_id"] = "agent-1"
    with pytest.raises(CompanyContractError):
        validate_company_contract(job)

    stopped = execution_event()
    stopped.update({"event_type": "turn.stopped", "runtime_status": "stopped"})
    assert validate_company_contract(stopped)["engineering_status"] == "active"
    lost = execution_event()
    lost["runtime_status"] = "confirmed_lost"
    with pytest.raises(CompanyContractError):
        validate_company_contract(lost)
    lost.update({"provenance": "AOI_verified", "evidence_ids": ["evidence-1"]})
    assert validate_company_contract(lost)["runtime_status"] == "confirmed_lost"
    raw_id_in_payload = execution_event()
    raw_id_in_payload["payload"] = {"thread_id": "forbidden"}
    raw_id_in_payload["payload_sha256"] = company_contract_sha256(raw_id_in_payload["payload"], max_bytes=64 * 1024)
    with pytest.raises(CompanyContractError, match="lifecycle identity"):
        validate_company_contract(raw_id_in_payload)


def test_r14_execution_link_matrix_accepts_turn_job_and_carrier_registration() -> None:
    carrier = execution_node()
    assert validate_company_contract(carrier)["registration_id"] is None
    carrier["registration_id"] = "registration-1"
    assert validate_company_contract(carrier)["registration_id"] == "registration-1"

    turn = execution_node()
    turn.update({"execution_kind": "turn", "registration_id": "registration-1"})
    assert validate_company_contract(turn)["execution_kind"] == "turn"
    turn_event = execution_event()
    turn_event.update({"execution_kind": "turn", "registration_id": "registration-1"})
    assert validate_company_contract(turn_event)["execution_kind"] == "turn"

    job = execution_node()
    job.update({"execution_kind": "job", "carrier_id": None, "thread_id": None, "turn_id": None,
                "job_id": "job-1", "dispatch_id": None, "registration_id": None})
    assert validate_company_contract(job)["registration_id"] is None


@pytest.mark.parametrize("missing", ("carrier_id", "thread_id", "turn_id", "registration_id"))
def test_r14_turn_requires_its_carrier_and_registration_links(missing: str) -> None:
    turn = execution_node()
    turn.update({"execution_kind": "turn", "registration_id": "registration-1"})
    turn[missing] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(turn)


@pytest.mark.parametrize("forbidden", ("agent_id", "job_id", "dispatch_id"))
def test_r14_turn_rejects_agent_job_and_dispatch_links(forbidden: str) -> None:
    turn = execution_node()
    turn.update({"execution_kind": "turn", "registration_id": "registration-1",
                 forbidden: f"{forbidden}-1"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(turn)


@pytest.mark.parametrize("dispatch_registration", (
    {"dispatch_id": None, "registration_id": None},
    {"dispatch_id": "dispatch-1", "registration_id": "registration-1"},
))
def test_r14_agent_rejects_neither_or_both_dispatch_registration(
    dispatch_registration: dict[str, object],
) -> None:
    node = execution_node()
    node.update({
        "execution_kind": "agent",
        "agent_id": "agent-1",
        "job_id": None,
        **dispatch_registration,
    })
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)


@pytest.mark.parametrize("forbidden", ("dispatch_id", "registration_id"))
def test_r14_job_rejects_dispatch_and_registration_links(
    forbidden: str,
) -> None:
    node = execution_node()
    node.update({
        "execution_kind": "job",
        "carrier_id": None,
        "thread_id": None,
        "turn_id": None,
        "agent_id": None,
        "job_id": "job-1",
        "dispatch_id": None,
        "registration_id": None,
        forbidden: f"{forbidden}-1",
    })
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)


@pytest.mark.parametrize("changes", (
    {"dispatch_id": "dispatch-1", "registration_id": None},
    {"parent_execution_id": "exec-parent-1", "execution_depth": 1,
     "execution_path": ["exec-parent-1", "exec-1"]},
    {"department_id": "department-1"},
))
def test_r14_organization_node_null_requires_registered_unattached_root(
    changes: dict[str, object],
) -> None:
    orphan = execution_node()
    orphan.update({"execution_kind": "agent", "agent_id": "agent-1", "dispatch_id": None,
                   "registration_id": "registration-1", "organization_node_id": None})
    assert validate_company_contract(orphan)["organization_node_id"] is None
    orphan.update(changes)
    with pytest.raises(CompanyContractError):
        validate_company_contract(orphan)


def test_r14_unknown_chief_term_cannot_claim_an_end_time() -> None:
    unknown = copy.deepcopy(family_records()[4])
    unknown.update({"state": "unknown", "ended_at": None,
                    "observation": {"state": "unknown", "reason": "term_outcome_unavailable"}})
    assert validate_company_contract(unknown)["state"] == "unknown"
    unknown["ended_at"] = T1
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown)


def test_r16_chief_term_observation_truth_table_rejects_adjacent_claims() -> None:
    active = copy.deepcopy(family_records()[4])
    active["observation"] = {"state": "partial", "reason": "collector_lag"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(active)

    unknown = copy.deepcopy(family_records()[4])
    unknown.update({"state": "unknown", "ended_at": None,
                    "observation": {"state": "known", "reason": "observed"}})
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown)


def test_passed_canary_requires_immutable_membership_oracle_window_and_evidence() -> None:
    assert validate_company_contract(passed_canary())["state"] == "passed"
    for field, value in (("assignment_reference_sha256", None), ("baseline_cohort_manifest_sha256", None),
                         ("external_oracle_ref", None), ("matching_manifest_sha256", None),
                         ("window_started_at", None), ("evidence_ids", []),
                         ("evidence_artifacts", [])):
        invalid = passed_canary()
        invalid[field] = value
        with pytest.raises(CompanyContractError):
            validate_company_contract(invalid)
    invalid = passed_canary()
    invalid["window_ended_at"] = "2026-10-25T00:00:01Z"
    with pytest.raises(CompanyContractError):
        validate_company_contract(invalid)
    invalid = passed_canary()
    invalid.update({"window_started_at": "2030-01-01T00:00:00Z", "window_ended_at": "2030-01-01T00:00:01Z"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(invalid)


def _terminal_canary_with_window(state: str) -> dict[str, object]:
    if state == "passed":
        return passed_canary()
    value = canary(state=state)
    value.update({"ended_at": T1, "evidence_ids": ["evidence-1"],
                  "evidence_artifacts": [blob()], "window_started_at": T0,
                  "window_ended_at": T1})
    if state == "failed":
        value["hard_gates"]["correctness_noninferior"] = False
    elif state == "rolled_back":
        value["hard_gates"]["critical_regression_free"] = False
    elif state != "inconclusive":
        raise AssertionError(f"missing terminal canary fixture: {state}")
    return value


@pytest.mark.parametrize("state", ("passed", "failed", "rolled_back", "inconclusive"))
def test_r18_terminal_canary_window_cannot_escape_lifecycle(state: str) -> None:
    value = _terminal_canary_with_window(state)
    assert validate_company_contract(value)["state"] == state
    for field, timestamp in (("window_started_at", "2026-07-24T00:00:00Z"),
                             ("window_ended_at", "2026-07-26T00:00:02Z")):
        escaped = copy.deepcopy(value)
        escaped[field] = timestamp
        with pytest.raises(CompanyContractError):
            validate_company_contract(escaped)
    reversed_window = copy.deepcopy(value)
    reversed_window.update({"window_started_at": T1, "window_ended_at": T0})
    with pytest.raises(CompanyContractError):
        validate_company_contract(reversed_window)


@pytest.mark.parametrize("state", ("passed", "failed", "rolled_back", "inconclusive"))
@pytest.mark.parametrize("field", ("window_started_at", "window_ended_at"))
def test_r20_terminal_canary_requires_each_window_endpoint(state: str, field: str) -> None:
    value = _terminal_canary_with_window(state)
    value[field] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)


@pytest.mark.parametrize(("state", "failed_gate"), (
    ("failed", "correctness_noninferior"),
    ("rolled_back", "critical_regression_free"),
))
def test_r14_failed_or_rolled_back_canary_requires_available_evidence_and_trigger(
    state: str, failed_gate: str,
) -> None:
    value = canary(state=state)
    value.update({"ended_at": T1, "evidence_ids": ["evidence-1"], "evidence_artifacts": [blob()],
                  "window_started_at": T0, "window_ended_at": T1})
    value["hard_gates"][failed_gate] = False
    assert validate_company_contract(value)["state"] == state

    for field, invalid_value in (("evidence_ids", []), ("evidence_artifacts", [])):
        invalid = copy.deepcopy(value)
        invalid[field] = invalid_value
        with pytest.raises(CompanyContractError):
            validate_company_contract(invalid)
    unavailable = copy.deepcopy(value)
    unavailable["evidence_artifacts"][0].update({"availability": "unknown", "sha256": None, "size_bytes": None})
    with pytest.raises(CompanyContractError):
        validate_company_contract(unavailable)
    no_trigger = copy.deepcopy(value)
    no_trigger["hard_gates"] = gates()
    with pytest.raises(CompanyContractError):
        validate_company_contract(no_trigger)


def test_r16_canary_unknown_gate_and_improvement_truth_table() -> None:
    for state in ("planned", "running", "unknown"):
        value = canary(state=state)
        if state == "unknown":
            value["observation"] = {"state": "unknown", "reason": "outcome_unavailable"}
        assert validate_company_contract(value)["state"] == state
        for field, asserted in (("correctness_noninferior", True), ("burn_noninferior", False),
                                ("burn_improvement_percent", 0), ("latency_improvement_percent", 10)):
            invalid = copy.deepcopy(value)
            invalid["hard_gates"][field] = asserted
            with pytest.raises(CompanyContractError):
                validate_company_contract(invalid)

    passed = passed_canary()
    passed["hard_gates"]["correctness_noninferior"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(passed)
    passed = passed_canary()
    passed["hard_gates"]["burn_improvement_percent"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(passed)

    rolled_back = canary(state="rolled_back")
    rolled_back.update({"ended_at": T1, "evidence_ids": ["evidence-1"],
                        "evidence_artifacts": [blob()], "window_started_at": T0,
                        "window_ended_at": T1})
    rolled_back["hard_gates"].update({"burn_noninferior": False, "burn_improvement_percent": 10})
    with pytest.raises(CompanyContractError):
        validate_company_contract(rolled_back)

    inconclusive = canary(state="inconclusive")
    inconclusive.update({"ended_at": T1, "evidence_ids": ["evidence-1"],
                         "evidence_artifacts": [blob()], "window_started_at": T0,
                         "window_ended_at": T1})
    assert validate_company_contract(inconclusive)["state"] == "inconclusive"
    inconclusive["evidence_artifacts"] = []
    with pytest.raises(CompanyContractError):
        validate_company_contract(inconclusive)


@pytest.mark.parametrize("gate", (
    "correctness_noninferior", "completion_noninferior", "rework_noninferior",
    "burn_noninferior", "latency_noninferior", "dissent_preserved",
    "critical_regression_free", "fenced_mutation_escape_free",
    "unknown_mutation_free", "evidence_downgrade_free",
))
def test_r18_inconclusive_rejects_every_explicit_false_gate(gate: str) -> None:
    value = canary(state="inconclusive")
    value.update({"ended_at": T1, "evidence_ids": ["evidence-1"],
                  "evidence_artifacts": [blob()], "window_started_at": T0,
                  "window_ended_at": T1})
    value["hard_gates"][gate] = False
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)


def test_r18_canary_terminal_evaluation_state_machine() -> None:
    pass_ready = passed_canary()
    pass_ready["state"] = "inconclusive"
    with pytest.raises(CompanyContractError):
        validate_company_contract(pass_ready)

    no_benefit = passed_canary()
    no_benefit.update({"state": "failed"})
    no_benefit["hard_gates"].update({"burn_improvement_percent": 0,
                                      "latency_improvement_percent": 0})
    assert validate_company_contract(no_benefit)["state"] == "failed"

    no_benefit["state"] = "inconclusive"
    with pytest.raises(CompanyContractError):
        validate_company_contract(no_benefit)

    incomplete = canary(state="failed")
    incomplete.update({"ended_at": T1, "evidence_ids": ["evidence-1"],
                       "evidence_artifacts": [blob()], "window_started_at": T0,
                       "window_ended_at": T1})
    with pytest.raises(CompanyContractError):
        validate_company_contract(incomplete)


@pytest.mark.parametrize("trigger", (
    "critical_regression_free", "dissent_preserved",
    "fenced_mutation_escape_free", "unknown_mutation_free",
    "evidence_downgrade_free",
))
def test_r18_rolled_back_requires_an_immediate_trigger(trigger: str) -> None:
    value = canary(state="rolled_back")
    value.update({"ended_at": T1, "evidence_ids": ["evidence-1"],
                  "evidence_artifacts": [blob()], "window_started_at": T0,
                  "window_ended_at": T1})
    value["hard_gates"][trigger] = False
    assert validate_company_contract(value)["state"] == "rolled_back"

    generic_only = copy.deepcopy(value)
    generic_only["hard_gates"] = gates()
    generic_only["hard_gates"]["correctness_noninferior"] = False
    with pytest.raises(CompanyContractError):
        validate_company_contract(generic_only)


@pytest.mark.parametrize(("field", "value"), (
    ("parent_node_id", "chief-parent"),
    ("department_id", "rtl"),
    ("role", "department_lead"),
    ("reports_to_node_id", "chief-parent"),
    ("can_delegate", False),
    ("delegation_depth", 1),
    ("status", "idle"),
    ("visibility", "subtree"),
    ("observation", {"state": "partial", "reason": "collector_lag"}),
))
def test_r18_root_node_requires_every_company_chief_invariant(field: str, value: object) -> None:
    root = copy.deepcopy(family_records()[1])
    root[field] = value
    with pytest.raises(CompanyContractError):
        validate_company_contract(root)


@pytest.mark.parametrize(("parent_node_id", "reports_to_node_id", "delegation_depth"), (
    ("parent-1", "parent-1", 1),
    ("parent-1", None, 2),
))
def test_r20_chief_role_is_reserved_for_the_company_root(
    parent_node_id: str, reports_to_node_id: str | None, delegation_depth: int,
) -> None:
    child = copy.deepcopy(family_records()[1])
    child.update({"parent_node_id": parent_node_id, "reports_to_node_id": reports_to_node_id,
                  "delegation_depth": delegation_depth})
    with pytest.raises(CompanyContractError):
        validate_company_contract(child)


def test_r16_backup_aad_helper_admits_only_complete_typed_aad_input() -> None:
    value = backup()
    for malformed in (None, [], {}, {"backup_id": "backup-1"}):
        for helper in (backup_aad_fields, backup_aad_bytes):
            with pytest.raises(CompanyContractError):
                helper(malformed)  # type: ignore[arg-type]
    for field in ("company_id", "nonce_blob", "created_at"):
        malformed = copy.deepcopy(value)
        malformed.pop(field)
        for helper in (backup_aad_fields, backup_aad_bytes):
            with pytest.raises(CompanyContractError):
                helper(malformed)
    for field, malformed_value in (("company_incarnation", "one"), ("nonce_blob", {}),
                                   ("created_at", 1)):
        malformed = copy.deepcopy(value)
        malformed[field] = malformed_value
        for helper in (backup_aad_fields, backup_aad_bytes):
            with pytest.raises(CompanyContractError):
                helper(malformed)


def test_r16_failed_backup_requires_only_available_failure_evidence() -> None:
    failed = backup()
    failed.update({"state": "failed", "failure_artifact": blob()})
    assert validate_company_contract(failed)["failure_artifact"] == blob()
    failed["failure_artifact"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(failed)
    failed["failure_artifact"] = {**blob(), "availability": "unknown", "sha256": None, "size_bytes": None}
    with pytest.raises(CompanyContractError):
        validate_company_contract(failed)
    for state in ("unverified", "verified", "unknown"):
        value = backup()
        value["state"] = state
        if state == "verified":
            value["verified_at"] = T1
            receipt_value = crypto_receipt(value)
            value.update({"crypto_verification_receipt": receipt_value,
                          "crypto_verification_receipt_sha256": receipt_value["receipt_sha256"]})
        if state == "unknown":
            value["observation"] = {"state": "unknown", "reason": "verification_lost"}
        value["failure_artifact"] = blob()
        with pytest.raises(CompanyContractError):
            validate_company_contract(value)


def test_execution_lifecycle_and_usage_scope_do_not_fake_runtime_or_tokens() -> None:
    node = copy.deepcopy(family_records()[6])
    node["runtime_status"] = "suspected_stalled"
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)
    node = copy.deepcopy(family_records()[6])
    node["engineering_status"] = "completed"
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)
    node = copy.deepcopy(family_records()[6])
    node["attention_overlays"] = ["not-an-overlay"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)

    absent = usage()
    absent["raw_token_vector"] = token_vector(present=False)
    absent["aggregation"] = {
        "observed_total": token_vector(present=False), "attributions": [],
        "unattributed": token_vector(present=False),
    }
    with pytest.raises(CompanyContractError):
        validate_usage_event(absent)
    wrong_scope = usage()
    wrong_scope["aggregation_scope"] = "department"
    with pytest.raises(CompanyContractError):
        validate_usage_event(wrong_scope)


def test_blob_backup_mutation_job_and_lifecycle_claims_are_cross_checked() -> None:
    unknown_blob = blob()
    unknown_blob.update({"availability": "unknown", "sha256": None, "size_bytes": None})
    assert validate_company_contract(unknown_blob)["availability"] == "unknown"
    unknown_blob["sha256"] = H
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown_blob)

    mutation = copy.deepcopy(family_records()[8])
    mutation.update({"state": "effect_unknown", "effect_evidence": [blob()], "reconcile_ref": "reconcile-1",
                     "observation": {"state": "unknown", "reason": "reconciliation pending"}})
    assert validate_company_contract(mutation)["state"] == "effect_unknown"
    mutation["updated_at"] = "2026-07-25T00:00:00Z"
    with pytest.raises(CompanyContractError):
        validate_company_contract(mutation)

    job = copy.deepcopy(family_records()[9])
    job.update({"state": "running",
                "external_handle": {"provider": "eda", "namespace": "jobs", "resolver": "pid",
                                    "native_handle": "100", "host_fingerprint_sha256": H},
                "process_observation": observed(), "process_fingerprint_sha256": H})
    assert validate_company_contract(job)["process_fingerprint_sha256"] == H
    job["process_fingerprint_sha256"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(job)

    backup = copy.deepcopy(family_records()[17])
    backup["nonce_blob"]["size_bytes"] = 11
    with pytest.raises(CompanyContractError):
        validate_company_contract(backup)
    backup = copy.deepcopy(family_records()[17])
    backup["envelope_blob"]["sha256"] = H
    with pytest.raises(CompanyContractError):
        validate_company_contract(backup)
    backup = copy.deepcopy(family_records()[17])
    backup["envelope_blob"]["size_bytes"] = 15
    with pytest.raises(CompanyContractError):
        validate_company_contract(backup)

    chief, alert, needs, canary = (copy.deepcopy(family_records()[index]) for index in (4, 12, 13, 16))
    chief["ended_at"] = T1
    alert["resolved_at"] = T1
    needs["answered_at"] = T1
    canary["assignment_percent"] = 11
    for record in (chief, alert, needs, canary):
        with pytest.raises(CompanyContractError):
            validate_company_contract(record)


def test_authority_paths_jobs_and_lifecycles_reject_inconsistent_claims() -> None:
    fenced = authority()
    fenced["authority_state"] = "fenced"
    with pytest.raises(CompanyContractError):
        validate_company_contract(fenced)

    malformed_usage = usage()
    malformed_usage["observation"] = []
    with pytest.raises(CompanyContractError):
        validate_usage_event(malformed_usage)

    node = copy.deepcopy(family_records()[6])
    node["execution_path"] = ["not-exec-1"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)
    execution_event = copy.deepcopy(family_records()[7])
    execution_event["execution_path"] = ["not-exec-1"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(execution_event)

    queued_job = copy.deepcopy(family_records()[9])
    queued_job["external_handle"] = "handle-1"
    with pytest.raises(CompanyContractError):
        validate_company_contract(queued_job)
    running_job = copy.deepcopy(family_records()[9])
    running_job["state"] = "running"
    with pytest.raises(CompanyContractError):
        validate_company_contract(running_job)
    uncertain_job = copy.deepcopy(family_records()[9])
    uncertain_job["state"] = "reconcile_required"
    with pytest.raises(CompanyContractError):
        validate_company_contract(uncertain_job)

    uncertain_job.update({
        "external_handle": {"provider": "eda", "namespace": "jobs", "resolver": "pid",
                            "native_handle": "100", "host_fingerprint_sha256": H},
        "effect_evidence": [blob()],
        "reconcile_ref": "reconcile-1",
        "process_observation": {"state": "unknown", "reason": "observer_lost"},
    })
    assert validate_company_contract(uncertain_job)["state"] == "reconcile_required"
    effect_unknown_job = copy.deepcopy(uncertain_job)
    effect_unknown_job["state"] = "effect_unknown"
    assert validate_company_contract(effect_unknown_job)["state"] == "effect_unknown"
    for field, value in (("external_handle", None), ("effect_evidence", [{"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": None, "size_bytes": None, "media_type": "text/plain", "availability": "unknown"}]), ("process_observation", {"state": "unavailable", "reason": "not_started"})):
        invalid = copy.deepcopy(uncertain_job)
        invalid[field] = value
        with pytest.raises(CompanyContractError):
            validate_company_contract(invalid)

    expired_need = copy.deepcopy(family_records()[13])
    expired_need.update({"state": "expired", "answered_at": T1})
    with pytest.raises(CompanyContractError):
        validate_company_contract(expired_need)
    unknown_alert = copy.deepcopy(family_records()[12])
    unknown_alert.update({"state": "unknown", "resolved_at": T1})
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown_alert)
    terminal_canary = copy.deepcopy(family_records()[16])
    terminal_canary["state"] = "passed"
    with pytest.raises(CompanyContractError):
        validate_company_contract(terminal_canary)
    verified_backup = copy.deepcopy(family_records()[17])
    verified_backup["state"] = "verified"
    with pytest.raises(CompanyContractError):
        validate_company_contract(verified_backup)

    invalid_incarnation = copy.deepcopy(family_records()[0])
    invalid_incarnation["company_incarnation"] = 0
    with pytest.raises(CompanyContractError):
        validate_company_contract(invalid_incarnation)
    carrier = copy.deepcopy(family_records()[5])
    carrier["last_observed_at"] = "2026-07-25T00:00:00Z"
    with pytest.raises(CompanyContractError):
        validate_company_contract(carrier)


def test_reviewer_counterexamples_fail_closed() -> None:
    unknown_permission = authority(); unknown_permission["permissions"] = ["future.root"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown_permission)
    zero_term = authority(); zero_term["term"] = 0
    with pytest.raises(CompanyContractError):
        validate_company_contract(zero_term)
    read_only = request(); read_only["actor_authority"]["authority_state"] = "read_only"; read_only["actor_authority"]["permissions"] = []
    read_only["events"][0]["actor_authority"] = copy.deepcopy(read_only["actor_authority"]); read_only["events"][1]["actor_authority"] = copy.deepcopy(read_only["actor_authority"])
    read_only["request_sha256"] = company_contract_sha256({k: v for k, v in read_only.items() if k != "request_sha256"})
    with pytest.raises(CompanyContractError):
        validate_company_transaction_request(read_only)
    no_global = request(); no_global.pop("expected_transaction_head"); no_global["request_sha256"] = company_contract_sha256(no_global)
    with pytest.raises(CompanyContractError):
        validate_company_transaction_request(no_global)

    prepared = receipt(); prepared["state"] = "prepared"; prepared["result_heads"] = []
    prepared["transaction_sha256"] = company_contract_sha256({k: v for k, v in prepared.items() if k not in {"transaction_sha256", "receipt_sha256"}})
    prepared["receipt_sha256"] = company_contract_sha256({k: v for k, v in prepared.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError):
        validate_company_transaction_receipt(prepared)
    aborted = copy.deepcopy(prepared); aborted["state"] = "aborted"
    aborted["transaction_sha256"] = company_contract_sha256({k: v for k, v in aborted.items() if k not in {"transaction_sha256", "receipt_sha256"}})
    aborted["receipt_sha256"] = company_contract_sha256({k: v for k, v in aborted.items() if k != "receipt_sha256"})
    assert validate_company_transaction_receipt(aborted)["state"] == "aborted"

    cap = capability(); cap["state"] = "consumed"; cap["capability_sha256"] = company_contract_sha256({k: v for k, v in cap.items() if k != "capability_sha256"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(cap)
    cap = capability(); cap["expected_epoch"] = 0; cap["capability_sha256"] = company_contract_sha256({k: v for k, v in cap.items() if k != "capability_sha256"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(cap)

    evidence = copy.deepcopy(family_records()[10]); evidence["artifact"] = {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": None, "size_bytes": None, "media_type": "text/plain", "availability": "unknown"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(evidence)
    mutation = copy.deepcopy(family_records()[8]); mutation.update({"state": "effect_unknown", "effect_evidence": [{"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": None, "size_bytes": None, "media_type": "text/plain", "availability": "unknown"}], "reconcile_ref": "reconcile-1"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(mutation)
    canary = copy.deepcopy(family_records()[16]); canary.update({"state": "passed", "ended_at": T1, "baseline_count": 0, "canary_count": 0, "control_count": 0})
    with pytest.raises(CompanyContractError):
        validate_company_contract(canary)

    child = copy.deepcopy(family_records()[6]); child.update({"parent_execution_id": "parent-1", "execution_depth": 1, "execution_path": ["other-parent", "exec-1"]})
    with pytest.raises(CompanyContractError):
        validate_company_contract(child)
    job = copy.deepcopy(family_records()[9]); job["external_handle"] = "unstructured-handle"
    with pytest.raises(CompanyContractError):
        validate_company_contract(job)
    verified_backup = backup(); verified_backup.update({"state": "verified", "verified_at": T1, "crypto_verification_receipt_sha256": None})
    with pytest.raises(CompanyContractError):
        validate_company_contract(verified_backup)


def _contract_headers(value: object) -> list[dict[str, object]]:
    headers: list[dict[str, object]] = []
    if isinstance(value, dict):
        if "contract_type" in value and "schema_version" in value:
            headers.append(value)
        for member in value.values():
            headers.extend(_contract_headers(member))
    elif isinstance(value, list):
        for member in value:
            headers.extend(_contract_headers(member))
    return headers


def test_schema_version_is_exact_integer_at_all_nested_contract_headers() -> None:
    for root in family_records() + [request(), receipt(), capability(), backup()]:
        for header in _contract_headers(root):
            for invalid_version in (True, 1.0):
                invalid_header = copy.deepcopy(header)
                invalid_header["schema_version"] = invalid_version
                with pytest.raises(CompanyContractError):
                    validate_company_contract(invalid_header)


def test_route_policy_optimizer_snapshot_and_job_regressions_fail_closed() -> None:
    policy = route_policy()
    assert validate_company_contract(policy)["policy_sha256"] == policy["policy_sha256"]
    changed_policy = copy.deepcopy(policy)
    changed_policy["allowed_models"] = ["gpt-5.1"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(changed_policy)
    changed_policy["policy_sha256"] = company_contract_sha256(
        {key: value for key, value in changed_policy.items() if key != "policy_sha256"}
    )
    assert validate_company_contract(changed_policy)["allowed_models"] == ["gpt-5.1"]

    proposal = copy.deepcopy(family_records()[15])
    assert validate_company_contract(proposal)["state"] == "proposed"
    proposal["candidate_policy_sha256"] = proposal["base_policy_sha256"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(proposal)
    for state in ("accepted", "promoted", "rolled_back"):
        terminal = copy.deepcopy(family_records()[15])
        terminal["state"] = state
        with pytest.raises(CompanyContractError):
            validate_company_contract(terminal)
        terminal["evidence_ids"] = ["evidence-1"]
        assert validate_company_contract(terminal)["state"] == state

    snapshot = copy.deepcopy(family_records()[3])
    snapshot.update({"revision": 2, "previous_snapshot_id": "snap-1"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(snapshot)

    handle = {"provider": "eda", "namespace": "jobs", "resolver": "pid",
              "native_handle": "100", "host_fingerprint_sha256": H}
    queued = copy.deepcopy(family_records()[9])
    queued.update({"process_observation": observed(), "process_fingerprint_sha256": H})
    with pytest.raises(CompanyContractError):
        validate_company_contract(queued)
    running = copy.deepcopy(family_records()[9])
    running.update({"state": "running", "external_handle": handle,
                    "process_observation": {"state": "unavailable", "reason": "not_started"}})
    with pytest.raises(CompanyContractError):
        validate_company_contract(running)
    for state in ("completed", "failed_known"):
        terminal = copy.deepcopy(family_records()[9])
        terminal.update({"state": state, "external_handle": handle,
                         "process_observation": observed(), "process_fingerprint_sha256": H,
                         "terminal_at": T1})
        with pytest.raises(CompanyContractError):
            validate_company_contract(terminal)
        terminal["effect_evidence"] = [blob()]
        assert validate_company_contract(terminal)["state"] == state


def test_r9c_lifecycle_and_single_aad_encoding_regressions_fail_closed() -> None:
    passed = passed_canary()
    passed["hard_gates"]["dissent_preserved"] = False
    with pytest.raises(CompanyContractError):
        validate_company_contract(passed)
    passed = passed_canary()
    passed["hard_gates"]["correctness_noninferior"] = False
    with pytest.raises(CompanyContractError):
        validate_company_contract(passed)
    for gate in ("burn_noninferior", "latency_noninferior"):
        passed = passed_canary()
        passed["hard_gates"][gate] = False
        with pytest.raises(CompanyContractError):
            validate_company_contract(passed)

    handle = {"provider": "eda", "namespace": "jobs", "resolver": "pid",
              "native_handle": "100", "host_fingerprint_sha256": H}
    for state in ("completed", "effect_unknown", "reconcile_required"):
        job = copy.deepcopy(family_records()[9])
        job.update({"state": state, "external_handle": handle,
                    "process_observation": {"state": "partial", "reason": "not_started"},
                    "effect_evidence": [blob()]})
        if state == "completed":
            job["terminal_at"] = T1
        with pytest.raises(CompanyContractError):
            validate_company_contract(job)

    node = copy.deepcopy(family_records()[6])
    node["runtime_status"] = "confirmed_lost"
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)
    node["evidence_ids"] = ["evidence-1"]
    assert validate_company_contract(node)["runtime_status"] == "confirmed_lost"
    node["observation"] = {"state": "unknown", "reason": "observer lost"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(node)
    event = copy.deepcopy(family_records()[7])
    event["runtime_status"] = "confirmed_lost"
    with pytest.raises(CompanyContractError):
        validate_company_contract(event)
    event.update({"provenance": "AOI_verified", "evidence_ids": ["evidence-1"]})
    assert validate_company_contract(event)["runtime_status"] == "confirmed_lost"
    event["observation"] = {"state": "unknown", "reason": "observer lost"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(event)

    for cursor, ledger_head in ((0, H), (1, ZERO_SHA256)):
        invalid_backup = backup()
        invalid_backup.update({"ledger_cursor": cursor, "ledger_head_sha256": ledger_head})
        with pytest.raises(CompanyContractError):
            validate_company_contract(invalid_backup)

    prepared = copy.deepcopy(family_records()[8])
    prepared["effect_evidence"] = [blob()]
    with pytest.raises(CompanyContractError):
        validate_company_contract(prepared)
    committed = copy.deepcopy(family_records()[8])
    committed["state"] = "committed"
    with pytest.raises(CompanyContractError):
        validate_company_contract(committed)
    committed["effect_evidence"] = [blob()]
    assert validate_company_contract(committed)["state"] == "committed"
    committed["reconcile_ref"] = "reconcile-1"
    with pytest.raises(CompanyContractError):
        validate_company_contract(committed)
    uncertain = copy.deepcopy(family_records()[8])
    uncertain.update({"state": "effect_unknown", "effect_evidence": [blob()],
                      "reconcile_ref": "reconcile-1"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(uncertain)
    uncertain["observation"] = {"state": "unknown", "reason": "reconciliation pending"}
    assert validate_company_contract(uncertain)["state"] == "effect_unknown"
    unknown = copy.deepcopy(family_records()[8])
    unknown["state"] = "unknown"
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown)
    unknown["observation"] = {"state": "unknown", "reason": "outcome unavailable"}
    assert validate_company_contract(unknown)["state"] == "unknown"
    unknown["effect_evidence"] = [blob()]
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown)
    unknown["effect_evidence"] = []
    unknown["reconcile_ref"] = "reconcile-1"
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown)

    value = backup()
    aad = backup_aad_bytes(value)
    assert aad == canonical_company_json_bytes(backup_aad_fields(value))
    assert value["aad_sha256"] == hashlib.sha256(aad).hexdigest()
    value["aad_fields_sha256"] = value["aad_sha256"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)


def _external_job_for_state(state: str) -> dict[str, object]:
    handle = {"provider": "eda", "namespace": "jobs", "resolver": "pid",
              "native_handle": "100", "host_fingerprint_sha256": H}
    job = copy.deepcopy(family_records()[9])
    if state == "queued":
        return job
    if state == "running":
        job.update({"state": state, "external_handle": handle,
                    "process_observation": observed(), "process_fingerprint_sha256": H})
    elif state in {"completed", "failed_known"}:
        job.update({"state": state, "external_handle": handle,
                    "process_observation": observed(), "process_fingerprint_sha256": H,
                    "terminal_at": T1, "effect_evidence": [blob()]})
    elif state in {"effect_unknown", "reconcile_required"}:
        job.update({"state": state, "external_handle": handle,
                    "process_observation": {"state": "unknown", "reason": "observer_lost"},
                    "effect_evidence": [blob()],
                    "reconcile_ref": "reconcile-1"})
    elif state == "aborted":
        job.update({"state": state, "terminal_at": T1,
                    "process_observation": {"state": "unavailable", "reason": "aborted_before_launch"}})
    elif state == "unknown":
        job.update({"state": state,
                    "process_observation": {"state": "unknown", "reason": "outcome_unavailable"},
                    "observation": {"state": "unknown", "reason": "outcome_unavailable"}})
    else:
        raise AssertionError(f"missing ExternalJob state fixture: {state}")
    return job


@pytest.mark.parametrize("state", (
    "queued", "running", "completed", "failed_known", "effect_unknown",
    "reconcile_required", "aborted", "unknown",
))
def test_r12_external_job_state_truth_table_accepts_only_complete_rows(state: str) -> None:
    assert validate_company_contract(_external_job_for_state(state))["state"] == state


@pytest.mark.parametrize(("state", "field", "value"), (
    ("queued", "effect_evidence", [blob()]),
    ("queued", "process_fingerprint_sha256", H),
    ("running", "process_observation", {"state": "unknown", "reason": "observer_lost"}),
    ("completed", "effect_evidence", []),
    ("failed_known", "observation", {"state": "unknown", "reason": "outcome_unavailable"}),
    ("effect_unknown", "effect_evidence", []),
    ("effect_unknown", "reconcile_ref", None),
    ("reconcile_required", "external_handle", None),
    ("aborted", "effect_evidence", [blob()]),
    ("aborted", "process_fingerprint_sha256", H),
    ("unknown", "external_handle", {"provider": "eda", "namespace": "jobs", "resolver": "pid", "native_handle": "100", "host_fingerprint_sha256": H}),
    ("unknown", "effect_evidence", [blob()]),
    ("unknown", "process_fingerprint_sha256", H),
), ids=(
    "queued-no-effects", "queued-no-fingerprint", "running-known-process", "completed-needs-effects",
    "failed-known-needs-observation", "effect-unknown-needs-evidence",
    "effect-unknown-needs-reconcile",
    "reconcile-needs-handle", "aborted-no-effects", "aborted-no-fingerprint",
    "unknown-no-handle", "unknown-no-effects", "unknown-no-fingerprint",
))
def test_r12_external_job_state_truth_table_rejects_adjacent_claims(
    state: str, field: str, value: object,
) -> None:
    job = _external_job_for_state(state)
    job[field] = copy.deepcopy(value)
    with pytest.raises(CompanyContractError):
        validate_company_contract(job)


def _resign_usage(value: dict[str, object]) -> None:
    value["usage_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "usage_sha256"}
    )


@pytest.mark.parametrize("status", ("pass", "fail"))
def test_r12_definitive_evidence_requires_known_observation_and_provenance(status: str) -> None:
    evidence = copy.deepcopy(family_records()[10])
    evidence["status"] = status
    evidence["observation"] = {"state": "unknown", "reason": "observer_lost"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(evidence)
    evidence = copy.deepcopy(family_records()[10])
    evidence["status"] = status
    evidence["provenance"] = "unknown"
    with pytest.raises(CompanyContractError):
        validate_company_contract(evidence)


@pytest.mark.parametrize("sample_kind", ("exact", "provider_estimate", "proxy"))
def test_r12_nonunknown_usage_requires_known_observation(sample_kind: str) -> None:
    value = usage()
    value["sample_kind"] = sample_kind
    value["observation"] = {"state": "unknown", "reason": "observer_lost"}
    _resign_usage(value)
    with pytest.raises(CompanyContractError):
        validate_usage_event(value)


def test_r12_unknown_usage_and_definitive_lifecycles_cannot_upgrade_unknown_facts() -> None:
    value = usage()
    value.update({"sample_kind": "unknown", "raw_token_vector": token_vector(present=False),
                  "aggregation": {"observed_total": token_vector(present=False), "attributions": [],
                                  "unattributed": token_vector(present=False)},
                  "source": {"source_id": "sample-1", "source_sha256": H, "provenance": "unknown"},
                  "observation": {"state": "partial", "reason": "collector_lag"}})
    _resign_usage(value)
    with pytest.raises(CompanyContractError):
        validate_usage_event(value)

    for state in ("committed", "failed_known"):
        mutation = copy.deepcopy(family_records()[8])
        mutation.update({"state": state, "effect_evidence": [blob()]})
        mutation["actor_authority"]["provenance"] = "unknown"
        with pytest.raises(CompanyContractError):
            validate_company_contract(mutation)
    aborted = copy.deepcopy(family_records()[8])
    aborted["state"] = "aborted"
    aborted["actor_authority"]["provenance"] = "unknown"
    with pytest.raises(CompanyContractError):
        validate_company_contract(aborted)

    canary_value = passed_canary()
    canary_value["observation"] = {"state": "unknown", "reason": "observer_lost"}
    with pytest.raises(CompanyContractError):
        validate_company_contract(canary_value)

    for state in ("completed", "failed_known", "aborted"):
        job = _external_job_for_state(state)
        job["actor_authority"]["provenance"] = "unknown"
        with pytest.raises(CompanyContractError):
            validate_company_contract(job)


def _r12_definitive_record(family: str, state: str) -> dict[str, object]:
    if family == "chief":
        value = copy.deepcopy(family_records()[4]); value.update({"state": state, "ended_at": T1})
    elif family == "carrier":
        value = copy.deepcopy(family_records()[5]); value["state"] = state
    elif family == "node_engineering":
        value = copy.deepcopy(family_records()[6]); value.update({"engineering_status": state, "terminal_at": T1})
    elif family == "node_runtime":
        value = copy.deepcopy(family_records()[6]); value["runtime_status"] = state
    elif family == "event_engineering":
        value = copy.deepcopy(family_records()[7]); value["engineering_status"] = state
    elif family == "event_runtime":
        value = copy.deepcopy(family_records()[7]); value["runtime_status"] = state
    elif family == "evidence":
        value = copy.deepcopy(family_records()[10]); value["status"] = state
    elif family == "alert":
        value = copy.deepcopy(family_records()[12]); value.update({"state": state, "resolved_at": T1})
    elif family == "needs_user":
        value = copy.deepcopy(family_records()[13]); value["state"] = state
        if state == "answered":
            value["answered_at"] = T1
    elif family == "optimizer":
        value = copy.deepcopy(family_records()[15]); value["state"] = state
        if state in {"accepted", "promoted", "rolled_back"}:
            value["evidence_ids"] = ["evidence-1"]
    elif family == "canary":
        value = passed_canary() if state == "passed" else canary(state=state)
        if state != "passed":
            value.update({"ended_at": T1, "window_started_at": T0, "window_ended_at": T1})
        if state in {"failed", "inconclusive", "rolled_back"}:
            value.update({"evidence_ids": ["evidence-1"], "evidence_artifacts": [blob()]})
        if state == "failed":
            value["hard_gates"]["correctness_noninferior"] = False
        if state == "rolled_back":
            value["hard_gates"]["critical_regression_free"] = False
    elif family == "backup":
        value = backup(); value.update({"state": "verified", "verified_at": T1})
        receipt_value = crypto_receipt(value)
        value.update({"crypto_verification_receipt": receipt_value,
                      "crypto_verification_receipt_sha256": receipt_value["receipt_sha256"]})
    elif family == "rate_card":
        value = rate_card()
    elif family == "burn":
        value = {"contract_type": USAGE_BURN_REVISION_V1, "schema_version": 1, **B,
                 "burn_id": "burn-1", "raw_usage_id": "usage-1", "raw_usage_sha256": usage()["usage_sha256"],
                 "rate_card_id": "card-1", "rate_card_revision": 1, "rate_card_sha256": rate_card()["rate_card_sha256"],
                 "provider": "codex", "model": "gpt-5", "effort": "high",
                 "previous_burn_sha256": ZERO_SHA256, "effective_cursor": 1,
                 "formula_version": "weighted-token-v1", "burn_units": 10, "observation": observed()}
        value["burn_sha256"] = company_contract_sha256(value)
    else:
        raise AssertionError(f"missing r12 definitive fixture: {family}")
    return value


@pytest.mark.parametrize(("family", "state"), (
    ("chief", "ended"), ("chief", "fenced"), ("carrier", "lost"), ("carrier", "fenced"),
    ("node_engineering", "completed"), ("node_engineering", "cancelled"), ("node_runtime", "stopped"),
    ("event_engineering", "completed"), ("event_engineering", "cancelled"), ("event_runtime", "stopped"),
    ("evidence", "pass"), ("evidence", "fail"), ("evidence", "blocked"), ("evidence", "skipped"),
    ("alert", "resolved"), ("needs_user", "answered"), ("needs_user", "expired"),
    ("optimizer", "accepted"), ("optimizer", "rejected"), ("optimizer", "inconclusive"),
    ("optimizer", "promoted"), ("optimizer", "rolled_back"),
    ("canary", "passed"), ("canary", "failed"), ("canary", "inconclusive"), ("canary", "rolled_back"),
    ("backup", "verified"), ("rate_card", "concrete"), ("burn", "concrete"),
))
def test_r12_definitive_outcomes_reject_nonknown_observation(family: str, state: str) -> None:
    value = _r12_definitive_record(family, state)
    assert validate_company_contract(value)["contract_type"] == value["contract_type"]
    value["observation"] = {"state": "partial", "reason": "collector_lag"}
    if family == "rate_card":
        value["rate_card_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "rate_card_sha256"}
        )
    if family == "burn":
        value["burn_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "burn_sha256"}
        )
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)


def test_r12_unknown_states_cannot_claim_known_observations_and_silent_telemetry_remains_uncertain() -> None:
    unknown_canary = canary(state="unknown")
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown_canary)
    unknown_canary["observation"] = {"state": "unknown", "reason": "outcome_unavailable"}
    assert validate_company_contract(unknown_canary)["state"] == "unknown"

    unknown_evidence = copy.deepcopy(family_records()[10]); unknown_evidence["status"] = "unknown"
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown_evidence)
    unknown_evidence["observation"] = {"state": "partial", "reason": "collector_lag"}
    assert validate_company_contract(unknown_evidence)["status"] == "unknown"

    for record_index in (6, 7):
        silent = copy.deepcopy(family_records()[record_index])
        silent.update({"runtime_status": "telemetry_silent", "provenance": "unknown",
                       "observation": {"state": "partial", "reason": "collector_lag"}})
        assert validate_company_contract(silent)["runtime_status"] == "telemetry_silent"


def test_r12_active_and_unknown_actor_authority_provenance_boundaries() -> None:
    active_unknown = authority(); active_unknown["provenance"] = "unknown"
    with pytest.raises(CompanyContractError):
        validate_company_contract(active_unknown)
    unknown = authority(); unknown.update({"authority_state": "unknown", "permissions": [], "chief_epoch": None,
                                             "provenance": "collector_received"})
    with pytest.raises(CompanyContractError):
        validate_company_contract(unknown)
    unknown["provenance"] = "unknown"
    assert validate_company_contract(unknown)["authority_state"] == "unknown"


def dispatch_request(*, state: str = "queued") -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": DISPATCH_REQUEST_V1, "schema_version": 1, **B,
        "dispatch_request_id": "dispatch-request-1", "dispatch_revision_id": "dispatch-revision-1",
        "revision": 1, "previous_event_id": None, "previous_payload_sha256": None,
        "command_id": "command-1", "reservation_id": "reservation-1", "task_id": None,
        "packet_id": None, "manager_node_id": "manager-1", "target_node_id": "target-1",
        "department_id": None, "parent_execution_id": "exec-parent-1", "requested_role": "worker",
        "requested_capability_tier": "standard", "route_policy_id": "policy-1",
        "scope_sha256": H, "delegation_depth": 1, "state": state,
        "attempt": 0 if state in {"queued", "admitted", "cancelled"} else 1,
        "provider_dispatch_id": None, "execution_id": None, "effect_evidence": [],
        "reconcile_ref": None, "resolves_event_ids": [], "created_at": T0, "updated_at": T1,
        "provenance": "AOI_verified", "observation": observed(),
    }
    if state == "dispatched":
        value.update({"provider_dispatch_id": "provider-dispatch-1", "execution_id": "exec-1",
                      "effect_evidence": [blob()]})
    elif state == "failed_known":
        value.update({"effect_evidence": [blob()]})
    elif state == "effect_unknown":
        value.update({"effect_evidence": [blob()], "reconcile_ref": "reconcile-1",
                      "observation": {"state": "partial", "reason": "collector_lag"}})
    return value


@pytest.mark.parametrize("state", (
    "queued", "admitted", "in_flight", "dispatched", "effect_unknown", "failed_known", "cancelled",
))
def test_r13_dispatch_request_accepts_every_complete_state_row(state: str) -> None:
    value = dispatch_request(state=state)
    assert validate_company_contract(value)["state"] == state
    assert validate_dispatch_request(value)["contract_type"] == DISPATCH_REQUEST_V1


def test_r13_dispatch_request_schema_predecessors_and_timestamps_are_strict() -> None:
    value = dispatch_request()
    value["unexpected"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(); del value["command_id"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(); value["previous_event_id"] = "event-0"
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    later = dispatch_request(); later.update({"revision": 2, "previous_event_id": "event-1",
                                               "previous_payload_sha256": H})
    assert validate_company_contract(later)["revision"] == 2
    later["previous_payload_sha256"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(later)
    value = dispatch_request(); value["updated_at"] = "2026-07-25T23:59:59Z"
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)


def test_r13_dispatch_request_attempt_identity_evidence_and_resolution_boundaries() -> None:
    value = dispatch_request(); value["attempt"] = 1
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(state="dispatched"); value["execution_id"] = None
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(); value["provider_dispatch_id"] = "provider-dispatch-1"
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(state="failed_known"); value["effect_evidence"][0].update(
        {"availability": "unknown", "sha256": None, "size_bytes": None}
    )
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(state="effect_unknown"); value["observation"] = observed()
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(state="dispatched"); value["provenance"] = "unknown"
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(); value["resolves_event_ids"] = ["event-1"]
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(state="failed_known"); value["resolves_event_ids"] = ["event-1", "event-2"]
    assert validate_company_contract(value)["resolves_event_ids"] == ["event-1", "event-2"]
    value["resolves_event_ids"] = [f"event-{index}" for index in range(257)]
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)


def test_r13_dispatch_request_rejects_bounds_and_returns_detached_canonical_value() -> None:
    value = dispatch_request(); value["delegation_depth"] = 7
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(); value["revision"] = 1_000_000_000_000
    with pytest.raises(CompanyContractError):
        validate_company_contract(value)
    value = dispatch_request(state="dispatched")
    validated = validate_company_contract(value)
    value["effect_evidence"][0]["media_type"] = "application/json"
    assert validated["effect_evidence"][0]["media_type"] == "text/plain"


def external_job_effect_source(
    *, observed_job_state: str = "completed", previous_job_state: str = "running",
) -> dict[str, object]:
    value: dict[str, object] = {
        "source_type": EXTERNAL_JOB_EFFECT_SOURCE_V1, "schema_version": 1, **B,
        "source_event_id": "external-effect-event-1", "receipt_id": "external-effect-receipt-1",
        "job_id": "job-1", "mutation_intent_id": "mutation-1", "command_id": "command-1",
        "transaction_id": "transaction-1",
        "transition_command_id": "transition-command-1",
        "previous_job_state": previous_job_state, "observed_job_state": observed_job_state,
        "external_handle_sha256": H, "process_fingerprint_sha256": H,
        "reconciliation_id": None, "resolves_reconciliation_id": None,
        "observed_at": T1, "provenance": "host_process_observed", "observation": observed(),
    }
    if observed_job_state in {"effect_unknown", "reconcile_required"}:
        value.update({
            "process_fingerprint_sha256": None, "reconciliation_id": "reconcile-1",
            "observation": {"state": "partial", "reason": "collector_lag"},
        })
    elif observed_job_state == "aborted":
        value.update({"external_handle_sha256": None, "process_fingerprint_sha256": None})
    return value


def external_job_effect_receipt(
    *, observed_job_state: str = "completed", previous_job_state: str = "running",
) -> dict[str, object]:
    source = external_job_effect_source(
        observed_job_state=observed_job_state,
        previous_job_state=previous_job_state,
    )
    value: dict[str, object] = {
        "contract_type": EXTERNAL_JOB_EFFECT_RECEIPT_V1, "schema_version": 1, **B,
        **{name: source[name] for name in (
            "source_event_id", "receipt_id", "job_id", "mutation_intent_id", "command_id",
            "transaction_id", "transition_command_id",
            "previous_job_state", "observed_job_state", "external_handle_sha256",
            "process_fingerprint_sha256", "reconciliation_id", "resolves_reconciliation_id",
            "observed_at", "provenance", "observation",
        )},
    }
    source_sha256 = company_contract_sha256(source)
    value.update({
        "source_sha256": source_sha256,
        "raw_artifact": {
            "contract_type": BLOB_REF_V1, "schema_version": 1,
            "sha256": source_sha256, "size_bytes": 1,
            "media_type": EXTERNAL_JOB_EFFECT_SOURCE_MEDIA_TYPE,
            "availability": "available",
        },
    })
    value["receipt_sha256"] = company_contract_sha256(value)
    return value


def _rehash_external_job_effect_receipt(value: dict[str, object]) -> None:
    unsigned = {key: member for key, member in value.items() if key != "receipt_sha256"}
    value["receipt_sha256"] = company_contract_sha256(unsigned)


@pytest.mark.parametrize(("previous_state", "observed_state"), (
    ("queued", "running"), ("queued", "effect_unknown"), ("queued", "aborted"),
    ("running", "completed"), ("running", "failed_known"),
    ("running", "effect_unknown"), ("effect_unknown", "reconcile_required"),
    ("effect_unknown", "completed"), ("effect_unknown", "failed_known"),
    ("reconcile_required", "completed"), ("reconcile_required", "failed_known"),
    ("unknown", "effect_unknown"),
))
def test_external_job_effect_source_and_receipt_accept_every_lifecycle_transition(
    previous_state: str, observed_state: str,
) -> None:
    source = external_job_effect_source(
        observed_job_state=observed_state, previous_job_state=previous_state,
    )
    assert validate_company_contract(source)["observed_job_state"] == observed_state
    receipt = external_job_effect_receipt(
        observed_job_state=observed_state, previous_job_state=previous_state,
    )
    assert validate_company_contract(receipt)["source_sha256"] == receipt["source_sha256"]


def test_external_job_effect_aborted_observation_has_no_process_or_handle() -> None:
    source = external_job_effect_source(
        observed_job_state="aborted", previous_job_state="queued",
    )
    assert validate_company_contract(source)["process_fingerprint_sha256"] is None
    receipt = external_job_effect_receipt(
        observed_job_state="aborted", previous_job_state="queued",
    )
    assert validate_company_contract(receipt)["external_handle_sha256"] is None


def test_external_job_effect_uncertainty_may_retain_a_known_process_identity() -> None:
    source = external_job_effect_source(
        observed_job_state="effect_unknown",
        previous_job_state="running",
    )
    source["process_fingerprint_sha256"] = H
    assert validate_company_contract(source)["process_fingerprint_sha256"] == H


@pytest.mark.parametrize("provenance", ("unknown", "AOI_verified"))
def test_external_job_effect_source_cannot_self_assert_verification(
    provenance: str,
) -> None:
    source = external_job_effect_source()
    source["provenance"] = provenance
    with pytest.raises(CompanyContractError):
        validate_company_contract(source)


@pytest.mark.parametrize("previous_state", ("completed", "failed_known", "aborted"))
def test_external_job_effect_rejects_terminal_previous_states(previous_state: str) -> None:
    source = external_job_effect_source(
        observed_job_state="effect_unknown", previous_job_state=previous_state,
    )
    with pytest.raises(CompanyContractError):
        validate_company_contract(source)
    receipt = external_job_effect_receipt(
        observed_job_state="effect_unknown", previous_job_state=previous_state,
    )
    _rehash_external_job_effect_receipt(receipt)
    with pytest.raises(CompanyContractError):
        validate_company_contract(receipt)


def test_external_job_effect_rejects_impossible_transition_and_binds_resolution_to_uncertainty() -> None:
    impossible = external_job_effect_receipt(
        observed_job_state="completed", previous_job_state="queued",
    )
    with pytest.raises(CompanyContractError):
        validate_company_contract(impossible)
    resolved = external_job_effect_receipt(
        observed_job_state="completed", previous_job_state="effect_unknown",
    )
    resolved["resolves_reconciliation_id"] = "reconcile-1"
    _rehash_external_job_effect_receipt(resolved)
    assert validate_company_contract(resolved)["resolves_reconciliation_id"] == "reconcile-1"


def test_external_job_effect_receipt_rejects_arbitrary_raw_blob_and_source_digest_mismatch() -> None:
    receipt = external_job_effect_receipt()
    receipt["raw_artifact"]["media_type"] = "application/json"  # type: ignore[index]
    _rehash_external_job_effect_receipt(receipt)
    with pytest.raises(CompanyContractError):
        validate_company_contract(receipt)
    receipt = external_job_effect_receipt()
    receipt["raw_artifact"]["sha256"] = "b" * 64  # type: ignore[index]
    _rehash_external_job_effect_receipt(receipt)
    with pytest.raises(CompanyContractError):
        validate_company_contract(receipt)


def test_external_job_effect_state_reconciliation_and_observation_matrices_fail_closed() -> None:
    uncertain = external_job_effect_receipt(observed_job_state="effect_unknown")
    uncertain["reconciliation_id"] = None
    _rehash_external_job_effect_receipt(uncertain)
    with pytest.raises(CompanyContractError):
        validate_company_contract(uncertain)
    uncertain = external_job_effect_receipt(observed_job_state="reconcile_required")
    uncertain.update({"observation": observed(), "process_fingerprint_sha256": H})
    _rehash_external_job_effect_receipt(uncertain)
    with pytest.raises(CompanyContractError):
        validate_company_contract(uncertain)
    completed = external_job_effect_receipt()
    completed["reconciliation_id"] = "reconcile-1"
    _rehash_external_job_effect_receipt(completed)
    with pytest.raises(CompanyContractError):
        validate_company_contract(completed)


def _work_ref(kind: str, path: str) -> dict[str, str]:
    return {"kind": kind, "path": path}


def _work_scope(
    *,
    leaf_paths: bool = False,
    write_refs: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    if leaf_paths:
        return {
            "read_refs": [_work_ref("file", "src/a.py")],
            "write_refs": [_work_ref("file", "src/a.py")] if write_refs is None else write_refs,
            "run_refs": [_work_ref("file", "src/a.py")],
            "export_refs": [],
            "provider_allowlist": ["codex"],
        }
    return {
        "read_refs": [_work_ref("tree", "src")],
        "write_refs": [_work_ref("tree", "src")] if write_refs is None else write_refs,
        "run_refs": [_work_ref("tree", "src")],
        "export_refs": [],
        "provider_allowlist": ["codex", "vcs"],
    }


def _work_blob(media_type: str, digest: str = H) -> dict[str, object]:
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": digest,
        "size_bytes": 1,
        "media_type": media_type,
        "availability": "available",
    }


def task_revision(*, revision: int = 1) -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": TASK_REVISION_V1,
        "schema_version": 1,
        **B,
        "task_id": "task-1",
        "task_revision_id": f"task-revision-{revision}",
        "revision": revision,
        "previous_task_revision_id": None if revision == 1 else "task-revision-1",
        "previous_task_sha256": None if revision == 1 else H,
        "display_name": "Directed VCS check",
        "objective": "Run the bounded directed check and return its receipt.",
        "authority_ceiling": _work_scope(),
        "completion_boundary_ref": _work_blob("text/plain"),
        "created_at": T0,
    }
    value["task_sha256"] = company_contract_sha256(value)
    return value


def work_packet(
    *,
    prompt_digest: str = H,
    context: dict[str, object] | None = None,
    task: dict[str, object] | None = None,
) -> dict[str, object]:
    context = work_context_manifest() if context is None else context
    task = task_revision() if task is None else task
    context_bytes = canonical_work_context_manifest_bytes(context)
    value: dict[str, object] = {
        "contract_type": WORK_PACKET_V1,
        "schema_version": 1,
        **B,
        "packet_id": "packet-1",
        "parent_packet_id": None,
        "parent_packet_sha256": None,
        "task_id": "task-1",
        "task_revision_id": "task-revision-1",
        "task_sha256": task["task_sha256"],
        "manager_node_id": None,
        "parent_execution_id": None,
        "target_node_id": "worker-1",
        "department_id": "rtl",
        "null_relationship_justifications": {
            "manager_node_id": "Chief-issued root packet.",
            "parent_execution_id": "No execution exists before admission.",
            "target_node_id": None,
            "department_id": None,
        },
        "delegation_depth": 1,
        "display_name": "Run directed VCS check",
        "objective": "Execute only the approved directed check.",
        "prompt_ref": _work_blob(WORK_PACKET_PROMPT_MEDIA_TYPE, prompt_digest),
        "context_manifest_ref": {
            **_work_blob(WORK_CONTEXT_MANIFEST_MEDIA_TYPE, work_context_manifest_sha256(context)),
            "size_bytes": len(context_bytes),
        },
        "source_manifest_sha256": context["source_manifest_sha256"],
        "config_manifest_sha256": context["config_manifest_sha256"],
        "dependency_manifest_sha256": context["dependency_manifest_sha256"],
        "authority_scope": _work_scope(leaf_paths=True),
        "redaction_policy": {
            "dashboard": "metadata_only",
            "secrets": "excluded",
            "chain_of_thought": "forbidden",
        },
        "created_at": T0,
        "expires_at": "2026-07-26T01:00:00Z",
    }
    value["packet_sha256"] = company_contract_sha256(value)
    return value


def work_context_manifest() -> dict[str, object]:
    value: dict[str, object] = {
        "document_type": WORK_CONTEXT_MANIFEST_V1,
        "schema_version": 1,
        **B,
        "repository_id": "repo-1",
        "repository_sha256": H,
        "cwd": ".",
        "department_snapshot_ref": _work_blob(DEPARTMENT_SNAPSHOT_MEDIA_TYPE, "b" * 64),
        "source_entries": [
            {"path": "src", "entry_type": "directory", "sha256": "b" * 64, "size_bytes": 0},
            {"path": "src/a.py", "entry_type": "file", "sha256": "c" * 64, "size_bytes": 3},
        ],
        "config_entries": [
            {"path": "aoi.toml", "entry_type": "file", "sha256": "d" * 64, "size_bytes": 4},
        ],
        "dependency_entries": [
            {"path": "requirements/base.txt", "entry_type": "file", "sha256": "e" * 64, "size_bytes": 5},
        ],
        "upstream_result_refs": [_work_blob("application/json", "f" * 64)],
    }
    for category, field in (
        ("source_entries", "source_manifest_sha256"),
        ("config_entries", "config_manifest_sha256"),
        ("dependency_entries", "dependency_manifest_sha256"),
    ):
        value[field] = hashlib.sha256(canonical_company_json_bytes(value[category])).hexdigest()
    return value


def _rehash_task(value: dict[str, object]) -> None:
    value["task_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "task_sha256"},
    )


def _rehash_packet(value: dict[str, object]) -> None:
    value["packet_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "packet_sha256"},
    )


def _rehash_context(value: dict[str, object]) -> None:
    for category, field in (
        ("source_entries", "source_manifest_sha256"),
        ("config_entries", "config_manifest_sha256"),
        ("dependency_entries", "dependency_manifest_sha256"),
    ):
        value[field] = hashlib.sha256(canonical_company_json_bytes(value[category])).hexdigest()


def work_result_receipt() -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": WORK_RESULT_RECEIPT_V1,
        "schema_version": 1,
        **B,
        "result_receipt_id": "result-receipt-1",
        "task_id": "task-1",
        "task_revision_id": "task-revision-1",
        "task_sha256": H,
        "packet_id": "packet-1",
        "packet_sha256": H,
        "producer_execution_id": "execution-1",
        "expected_execution_payload_sha256": H,
        "engineering_disposition_receipt_id": "disposition-receipt-1",
        "result_ref": _work_blob("application/json"),
        "recorded_at": T1,
        "provenance": "AOI_verified",
        "observation": observed(),
    }
    value["receipt_sha256"] = company_contract_sha256(value)
    return value


def work_dispatch_binding() -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": WORK_DISPATCH_BINDING_V1,
        "schema_version": 1,
        **B,
        "binding_id": "work-binding-1",
        "transaction_id": "transaction-1",
        "command_id": "command-1",
        "dispatch_request_id": "dispatch-request-1",
        "dispatch_revision_id": "dispatch-revision-1",
        "dispatch_payload_sha256": H,
        "task_id": "task-1",
        "task_revision_id": "task-revision-1",
        "task_sha256": H,
        "packet_id": "packet-1",
        "packet_sha256": H,
        "prompt_ref": _work_blob(WORK_PACKET_PROMPT_MEDIA_TYPE),
        "context_manifest_ref": _work_blob(WORK_CONTEXT_MANIFEST_MEDIA_TYPE),
        "department_id": "rtl",
        "target_node_id": "worker-1",
        "manager_node_id": "manager-1",
        "parent_execution_id": "execution-parent-1",
        "delegation_depth": 1,
        "authority_scope_sha256": H,
        "provider_allowlist": ["codex", "vcs"],
        "created_at": T0,
        "expires_at": "2026-07-26T01:00:00Z",
        "provenance": "AOI_verified",
        "observation": observed(),
    }
    value["binding_sha256"] = company_contract_sha256(value)
    return value


def work_definition_enforcement() -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": WORK_DEFINITION_ENFORCEMENT_V1,
        "schema_version": 1,
        **B,
        "gate_id": "work-definition-enforcement",
        "mode": "registered_launch_required",
        "previous_transaction_sha256": H,
        "activated_at": T1,
        "observation": observed(),
    }
    value["enforcement_sha256"] = company_contract_sha256(value)
    return value


def _rehash_work_result_receipt(value: dict[str, object]) -> None:
    value["receipt_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "receipt_sha256"},
    )


def _rehash_work_dispatch_binding(value: dict[str, object]) -> None:
    value["binding_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "binding_sha256"},
    )


def _rehash_work_definition_enforcement(value: dict[str, object]) -> None:
    value["enforcement_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "enforcement_sha256"},
    )


def provider_codex_home(
    *,
    revision: int = 1,
    platform: str = "windows",
    absolute_path: str | None = None,
) -> dict[str, object]:
    if absolute_path is None:
        absolute_path = "C:/isolated/codex-home" if platform == "windows" else "/isolated/codex-home"
    value: dict[str, object] = {
        "contract_type": PROVIDER_CODEX_HOME_V1, "schema_version": 1, **B,
        "home_id": "codex-home-1", "revision": revision,
        "previous_event_id": None if revision == 1 else "home-event-1",
        "previous_payload_sha256": ZERO_SHA256 if revision == 1 else H,
        "dispatch_request_id": "dispatch-request-1", "platform": platform,
        "absolute_path": absolute_path,
        "path_identity_sha256": company_contracts._provider_path_identity_sha256(
            platform=platform, absolute_path=absolute_path,
        ),
        "initial_inventory_sha256": "b" * 64,
        "config_sha256": H, "managed_config_sha256": "c" * 64,
        "thread_config_sha256": "d" * 64, "auth_present": True,
        "auth_size_bytes": 1, "state": "ready", "created_at": T0,
        "updated_at": T1, "observation": observed(),
    }
    value["home_sha256"] = company_contract_sha256(value)
    return value


def provider_launch_binding() -> dict[str, object]:
    home = provider_codex_home()
    value: dict[str, object] = {
        "contract_type": PROVIDER_LAUNCH_BINDING_V1, "schema_version": 1, **B,
        "launch_binding_id": "launch-1", "work_dispatch_binding_id": "work-binding-1",
        "work_dispatch_binding_sha256": H, "dispatch_request_id": "dispatch-request-1",
        "dispatch_revision_id": "dispatch-revision-1", "dispatch_revision": 1,
        "dispatch_payload_sha256": H, "route_policy_id": "policy-1",
        "route_policy_revision": 1, "route_policy_sha256": H, "provider": "codex",
        "model": "gpt-5", "effort": "high", "sandbox": "workspaceWrite",
        "worktree_root": "C:/worktree", "launch_cwd": "C:/worktree",
        "executable_path": "C:/bin/codex.exe", "executable_sha256": H,
        "executable_size_bytes": 1, "codex_cli_version": "0.145.0",
        "app_server_version": "0.145.0", "app_server_schema_version": "app-server-0.145",
        "branch": "main", "detached": False, "platform": "windows",
        "lock_domain_id": "windows-msvcrt-v1", "git_common_dir_sha256": H,
        "git_remote_sha256": H, "git_commit_sha256": H,
        "manifest_sha256": H, "repository_sha256": H, "source_sha256": H,
        "config_sha256": H, "dependency_sha256": H, "home_id": home["home_id"],
        "home_revision": home["revision"], "home_sha256": home["home_sha256"],
        "created_at": T0, "expires_at": "2026-07-26T01:00:00Z",
        "provenance": "AOI_verified", "observation": observed(),
    }
    value["binding_sha256"] = company_contract_sha256(value)
    return value


def provider_io_receipt(*, phase: str = "terminal_sealed", channel: str = "process") -> dict[str, object]:
    binding = provider_launch_binding()
    value: dict[str, object] = {
        "contract_type": PROVIDER_WORKER_IO_RECEIPT_V1, "schema_version": 1, **B,
        "receipt_id": "io-1", "operation_id": "operation-1",
        "launch_binding_id": binding["launch_binding_id"],
        "launch_binding_sha256": binding["binding_sha256"],
        "dispatch_request_id": binding["dispatch_request_id"],
        "dispatch_revision_id": binding["dispatch_revision_id"], "execution_id": "turn-exec-1",
        "thread_id": "thread-1", "turn_id": "turn-1", "channel": channel,
        "phase": phase, "sequence": 1, "method": None, "request_id": None,
        "raw_artifact": {**blob(), "media_type": PROVIDER_WORKER_RAW_MEDIA_TYPE},
        "observed_at": T1, "provenance": "adapter_receipt_persisted", "observation": observed(),
    }
    if phase in {"request_send_pending", "response_received"}:
        value["method"] = "turn/start"
        value["request_id"] = 1
    value["receipt_sha256"] = company_contract_sha256(value)
    return value


def provider_operation(*, state: str = "prepared", revision: int = 1) -> dict[str, object]:
    binding = provider_launch_binding()
    io = provider_io_receipt()
    value: dict[str, object] = {
        "contract_type": PROVIDER_WORKER_OPERATION_V1, "schema_version": 1, **B,
        "operation_id": "operation-1", "revision": revision,
        "previous_sha256": ZERO_SHA256 if revision == 1 else H,
        "launch_binding_id": binding["launch_binding_id"],
        "launch_binding_sha256": binding["binding_sha256"],
        "dispatch_request_id": binding["dispatch_request_id"],
        "dispatch_revision_id": binding["dispatch_revision_id"], "operation_kind": "result_extraction",
        "execution_id": "exec-1", "thread_id": "thread-1", "turn_id": "turn-1", "attempt": 1,
        "state": state,
        "previous_state": None if revision == 1 else (
            "effect_observed" if state == "committed" else "effect_unknown" if state == "reconcile_required" else "prepared" if state == "failed_known" else "effect_pending"
        ),
        "effect_receipt_ids": [], "result_receipt_id": None, "reconcile_ref": None,
        "created_at": T0, "updated_at": T1, "observation": observed(),
    }
    if state in {"effect_observed", "committed"}:
        value["effect_receipt_ids"] = [io["receipt_id"]]
    if state == "committed":
        value["result_receipt_id"] = "result-receipt-1"
    if state == "reconcile_required":
        value["reconcile_ref"] = "reconcile-1"
    value["operation_sha256"] = company_contract_sha256(value)
    return value


def provider_turn_result() -> dict[str, object]:
    binding = provider_launch_binding()
    return {
        "document_type": PROVIDER_TURN_RESULT_V1, "schema_version": 1, **B,
        "launch_binding_id": binding["launch_binding_id"],
        "launch_binding_sha256": binding["binding_sha256"], "operation_id": "operation-1",
        "agent_execution_id": "agent-exec-1", "turn_execution_id": "turn-exec-1",
        "thread_id": "thread-1", "turn_id": "turn-1",
        "terminal_status": "completed", "items_view": "summary",
        "availability": "available", "reason": "observed",
        "agent_message_items": [
            {"sequence": 1, "item_id": "agent-message-1", "text": "raw result"},
            {"sequence": 2, "item_id": "agent-message-2", "text": "second raw result"},
        ],
    }


def provider_turn_result_receipt() -> dict[str, object]:
    document = provider_turn_result()
    value: dict[str, object] = {
        "contract_type": PROVIDER_TURN_RESULT_RECEIPT_V1, "schema_version": 1, **B,
        "result_receipt_id": "result-receipt-1", "launch_binding_id": document["launch_binding_id"],
        "launch_binding_sha256": document["launch_binding_sha256"], "operation_id": document["operation_id"],
        "agent_execution_id": document["agent_execution_id"],
        "turn_execution_id": document["turn_execution_id"],
        "thread_id": document["thread_id"], "turn_id": document["turn_id"],
        "terminal_io_receipt_id": "io-1",
        "result_ref": {**blob(), "media_type": PROVIDER_TURN_RESULT_MEDIA_TYPE},
        "terminal_status": document["terminal_status"], "result_sha256": H,
        "recorded_at": T1, "provenance": "adapter_receipt_persisted", "observation": observed(),
    }
    value["receipt_sha256"] = company_contract_sha256(value)
    return value


def test_provider_worker_contracts_are_registered_hashed_and_bounded() -> None:
    home = provider_codex_home()
    binding = provider_launch_binding()
    io = provider_io_receipt()
    operation = provider_operation()
    receipt = provider_turn_result_receipt()
    assert validate_company_contract(home)["home_id"] == "codex-home-1"
    assert validate_provider_codex_home(home)["revision"] == 1
    assert validate_company_contract(binding)["model"] == "gpt-5"
    assert validate_provider_launch_binding(binding)["home_sha256"] == home["home_sha256"]
    assert validate_company_contract(io)["raw_artifact"]["media_type"] == PROVIDER_WORKER_RAW_MEDIA_TYPE
    assert validate_provider_worker_io_receipt(io)["sequence"] == 1
    assert validate_company_contract(operation)["state"] == "prepared"
    assert validate_provider_worker_operation(operation)["attempt"] == 1
    assert validate_company_contract(receipt)["result_receipt_id"] == "result-receipt-1"
    assert validate_provider_turn_result_receipt(receipt)["turn_id"] == "turn-1"

    for factory, digest in ((provider_codex_home, "home_sha256"), (provider_launch_binding, "binding_sha256"), (provider_io_receipt, "receipt_sha256"), (provider_operation, "operation_sha256"), (provider_turn_result_receipt, "receipt_sha256")):
        malformed = factory(); malformed[digest] = H if malformed[digest] != H else "b" * 64
        with pytest.raises(CompanyContractError):
            validate_company_contract(malformed)


def test_provider_worker_contracts_reject_paths_bool_unknown_and_illegal_effect_return() -> None:
    home = provider_codex_home(); home["absolute_path"] = "relative/home"
    home["home_sha256"] = company_contract_sha256({k: v for k, v in home.items() if k != "home_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_codex_home(home)
    home = provider_codex_home(); home["auth_present"] = False; home["auth_size_bytes"] = 0
    home["home_sha256"] = company_contract_sha256({k: v for k, v in home.items() if k != "home_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_codex_home(home)
    binding = provider_launch_binding(); binding["detached"] = True
    binding["binding_sha256"] = company_contract_sha256({k: v for k, v in binding.items() if k != "binding_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)
    binding = provider_launch_binding(); binding["expires_at"] = T0
    binding["binding_sha256"] = company_contract_sha256({k: v for k, v in binding.items() if k != "binding_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)
    io = provider_io_receipt(); io["sequence"] = True
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_io_receipt(io)
    io = provider_io_receipt(); io["channel"] = "stdin"; io["method"] = None
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_io_receipt(io)
    io = provider_io_receipt(phase="response_received", channel="stdout"); io["method"] = None
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_io_receipt(io)
    io = provider_io_receipt(phase="response_received", channel="stdout"); io["channel"] = "process"
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_io_receipt(io)
    operation = provider_operation(state="committed", revision=1)
    operation["operation_sha256"] = company_contract_sha256({k: v for k, v in operation.items() if k != "operation_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_operation(operation)
    assert validate_provider_worker_operation(provider_operation(state="failed_known", revision=2))["state"] == "failed_known"
    for operation_kind in ("initialize_request", "model_list_request"):
        operation = provider_operation(state="failed_known", revision=2)
        operation["operation_kind"] = operation_kind
        operation["operation_sha256"] = company_contract_sha256({k: v for k, v in operation.items() if k != "operation_sha256"})
        assert validate_provider_worker_operation(operation)["operation_kind"] == operation_kind
    operation = provider_operation()
    operation["operation_kind"] = "unknown_kind"
    operation["operation_sha256"] = company_contract_sha256({k: v for k, v in operation.items() if k != "operation_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_operation(operation)
    io = provider_io_receipt(); io["raw_artifact"]["media_type"] = "text/plain"  # type: ignore[index]
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_io_receipt(io)
    operation = provider_operation(state="effect_unknown", revision=2)
    operation["result_receipt_id"] = "result-receipt-1"
    operation["operation_sha256"] = company_contract_sha256({k: v for k, v in operation.items() if k != "operation_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_operation(operation)
    operation = provider_operation(state="committed", revision=2)
    operation["previous_state"] = "effect_unknown"
    operation["operation_sha256"] = company_contract_sha256({k: v for k, v in operation.items() if k != "operation_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_operation(operation)


def test_provider_turn_result_canonical_items_preserve_order_and_no_completion_inference() -> None:
    document = provider_turn_result()
    validated = validate_provider_turn_result(document)
    assert canonical_provider_turn_result_bytes(document) == canonical_company_json_bytes(validated)
    assert [entry["text"] for entry in validated["agent_message_items"]] == ["raw result", "second raw result"]
    malformed = provider_turn_result(); malformed["agent_message_items"].reverse()  # type: ignore[union-attr]
    with pytest.raises(CompanyContractError): validate_provider_turn_result(malformed)
    malformed = provider_turn_result(); malformed["agent_message_items"][1]["item_id"] = "agent-message-1"  # type: ignore[index]
    with pytest.raises(CompanyContractError): validate_provider_turn_result(malformed)
    malformed = provider_turn_result(); malformed["agent_message_items"][0]["item"] = {"type": "userMessage"}  # type: ignore[index]
    with pytest.raises(CompanyContractError): validate_provider_turn_result(malformed)
    malformed = provider_turn_result(); malformed["agent_message_items"] = []; malformed["availability"] = "unavailable"; malformed["reason"] = "not_loaded"  # type: ignore[assignment]
    with pytest.raises(CompanyContractError): validate_provider_turn_result(malformed)
    malformed = provider_turn_result(); malformed["agent_execution_id"] = None
    with pytest.raises(CompanyContractError): validate_provider_turn_result(malformed)


def test_provider_worker_b30_dialect_paths_and_home_lifecycle_regressions() -> None:
    response = provider_io_receipt(phase="response_received", channel="stdout")
    assert validate_provider_worker_io_receipt(response)["request_id"] == 1
    response["request_id"] = "1"
    response["receipt_sha256"] = company_contract_sha256({k: v for k, v in response.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_worker_io_receipt(response)

    binding = provider_launch_binding(); binding["sandbox"] = "readOnly"
    binding["binding_sha256"] = company_contract_sha256({k: v for k, v in binding.items() if k != "binding_sha256"})
    assert validate_provider_launch_binding(binding)["sandbox"] == "readOnly"
    binding["sandbox"] = "workspace-write"
    binding["binding_sha256"] = company_contract_sha256({k: v for k, v in binding.items() if k != "binding_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)

    binding = provider_launch_binding()
    validated = validate_provider_launch_binding(binding)
    assert company_contract_sha256({key: value for key, value in validated.items() if key != "binding_sha256"}) == validated["binding_sha256"]

    for field, value in (
        ("worktree_root", "C:\\worktree"),
        ("worktree_root", "C://worktree"),
        ("launch_cwd", "C:/worktree/"),
        ("executable_path", "C:\\bin\\codex.exe"),
    ):
        binding = provider_launch_binding()
        binding[field] = value
        binding["binding_sha256"] = company_contract_sha256({key: value for key, value in binding.items() if key != "binding_sha256"})
        with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)

    # Windows accepts no lossy aliases: ADS, device names, namespace spellings,
    # drive case aliases, and trim-equivalent components must all fail before a
    # provider process can be bound to hash-pinned launch bytes.
    for field, value in (
        ("worktree_root", "C:/worktree:stream"),
        ("launch_cwd", "C:/worktree/CON.txt"),
        ("executable_path", "C:/bin/NUL"),
        ("executable_path", "C:/bin/CLOCK$"),
        ("executable_path", "C:/bin/COM¹.txt"),
        ("launch_cwd", "C:/worktree/child. "),
        ("launch_cwd", "C:/worktree/child "),
        ("worktree_root", "c:/worktree"),
        ("worktree_root", "//?/C:/worktree"),
        ("worktree_root", "//./C:/worktree"),
        ("launch_cwd", "C:/worktree/./child"),
        ("launch_cwd", "C:/worktree/../outside"),
    ):
        binding = provider_launch_binding()
        binding[field] = value
        binding["binding_sha256"] = company_contract_sha256({key: value for key, value in binding.items() if key != "binding_sha256"})
        with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)

    linux_binding = provider_launch_binding()
    linux_binding.update({
        "platform": "linux", "worktree_root": "/worktree", "launch_cwd": "/worktree",
        "executable_path": "/bin/codex",
    })
    linux_binding["binding_sha256"] = company_contract_sha256({key: value for key, value in linux_binding.items() if key != "binding_sha256"})
    assert validate_provider_launch_binding(linux_binding)["platform"] == "linux"
    for field, value in (
        ("worktree_root", "/worktree/"),
        ("launch_cwd", "/worktree//child"),
        ("executable_path", "/bin//codex"),
    ):
        binding = copy.deepcopy(linux_binding)
        binding[field] = value
        binding["binding_sha256"] = company_contract_sha256({key: value for key, value in binding.items() if key != "binding_sha256"})
        with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)

    for platform, root, cwd in (
        ("windows", "C:/worktree", "C:/outside"),
        ("windows", "C:/worktree", "/worktree"),
        ("linux", "/worktree", "C:/worktree"),
    ):
        binding = provider_launch_binding()
        binding.update({"platform": platform, "worktree_root": root, "launch_cwd": cwd})
        binding["binding_sha256"] = company_contract_sha256({k: v for k, v in binding.items() if k != "binding_sha256"})
        with pytest.raises(CompanyContractError): validate_provider_launch_binding(binding)

    home = provider_codex_home(); home.update({"state": "active", "auth_present": False, "auth_size_bytes": 0})
    home["home_sha256"] = company_contract_sha256({k: v for k, v in home.items() if k != "home_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_codex_home(home)
    home = provider_codex_home(); home.update({"state": "retired", "auth_present": True, "auth_size_bytes": 1})
    home["home_sha256"] = company_contract_sha256({k: v for k, v in home.items() if k != "home_sha256"})
    with pytest.raises(CompanyContractError): validate_provider_codex_home(home)
    for auth_present, auth_size_bytes in ((False, 0), (True, 1)):
        home = provider_codex_home()
        home.update({"state": "cleanup_failed", "auth_present": auth_present, "auth_size_bytes": auth_size_bytes})
        home["home_sha256"] = company_contract_sha256({k: v for k, v in home.items() if k != "home_sha256"})
        assert validate_provider_codex_home(home)["state"] == "cleanup_failed"


def test_provider_worker_b35_home_and_launch_paths_have_one_platform_spelling() -> None:
    def rehash_home(value: dict[str, object]) -> None:
        value["home_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "home_sha256"},
        )

    def home_with_path(platform: str, absolute_path: str) -> dict[str, object]:
        value = provider_codex_home(platform=platform, absolute_path=absolute_path)
        value["path_identity_sha256"] = company_contracts._provider_path_identity_sha256(
            platform=platform, absolute_path=absolute_path,
        )
        rehash_home(value)
        return value

    windows_home = provider_codex_home()
    validated_windows_home = validate_provider_codex_home(windows_home)
    assert validated_windows_home["platform"] == "windows"
    assert validated_windows_home["path_identity_sha256"] == company_contracts._provider_path_identity_sha256(
        platform="windows", absolute_path="C:/isolated/codex-home",
    )
    for platform in ("linux", "macos", "wsl"):
        posix_home = provider_codex_home(platform=platform)
        assert validate_provider_codex_home(posix_home)["absolute_path"] == "/isolated/codex-home"

    # A Home identity is derived from its platform plus the already-canonical
    # path; an arbitrary caller-selected SHA-256 can never be durable.
    home = provider_codex_home()
    home["path_identity_sha256"] = H
    rehash_home(home)
    with pytest.raises(CompanyContractError):
        validate_provider_codex_home(home)

    for platform, absolute_path in (
        ("windows", "C:\\isolated\\codex-home"),
        ("windows", "c:/isolated/codex-home"),
        ("windows", "C:/isolated/Codex-home"),
        ("windows", "C:/isolated/codex-home:stream"),
        ("windows", "C:/isolated/CON.txt"),
        ("windows", "C:/isolated/codex-home."),
        ("windows", "C:/isolated/e\u0301"),
        ("windows", "//?/C:/isolated/codex-home"),
        ("windows", "//./C:/isolated/codex-home"),
        ("windows", "/isolated/codex-home"),
        ("linux", "C:/isolated/codex-home"),
    ):
        with pytest.raises(CompanyContractError):
            validate_provider_codex_home(home_with_path(platform, absolute_path))

    binding = provider_launch_binding()
    binding["launch_cwd"] = "C:/worktree/child"
    binding["binding_sha256"] = company_contract_sha256(
        {key: value for key, value in binding.items() if key != "binding_sha256"},
    )
    assert validate_provider_launch_binding(binding)["launch_cwd"] == "C:/worktree/child"
    for launch_cwd in ("C:/worktree/Child", "C:/worktree-shadow/child"):
        binding = provider_launch_binding()
        binding["launch_cwd"] = launch_cwd
        binding["binding_sha256"] = company_contract_sha256(
            {key: value for key, value in binding.items() if key != "binding_sha256"},
        )
        with pytest.raises(CompanyContractError):
            validate_provider_launch_binding(binding)


def test_provider_worker_b37_rejects_unresolved_windows_8dot3_path_aliases() -> None:
    def rehash_home(value: dict[str, object]) -> None:
        value["home_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "home_sha256"},
        )

    def rehash_binding(value: dict[str, object]) -> None:
        value["binding_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "binding_sha256"},
        )

    home = provider_codex_home(absolute_path="C:/progra~1/codex-home")
    home["path_identity_sha256"] = company_contracts._provider_path_identity_sha256(
        platform="windows", absolute_path="C:/progra~1/codex-home",
    )
    rehash_home(home)
    with pytest.raises(CompanyContractError):
        validate_provider_codex_home(home)

    for field, path in (
        ("worktree_root", "C:/progra~1/worktree"),
        ("launch_cwd", "C:/progra~1/child"),
        ("executable_path", "C:/progra~1/codex.exe"),
    ):
        binding = provider_launch_binding()
        binding[field] = path
        rehash_binding(binding)
        with pytest.raises(CompanyContractError):
            validate_provider_launch_binding(binding)

    with pytest.raises(CompanyContractError):
        company_contracts._provider_launch_path(
            "C:/isolated/codex~1.ini", "test.path", platform="windows",
        )

    # Legitimate tilde names are not short-name aliases unless they end in an
    # ASCII numeric short-name suffix (with at most one extension).
    assert company_contracts._provider_launch_path(
        "C:/isolated/codex~archive", "test.path", platform="windows",
    ) == "C:/isolated/codex~archive"
    assert company_contracts._provider_launch_path(
        "C:/isolated/codex~1x", "test.path", platform="windows",
    ) == "C:/isolated/codex~1x"


def test_provider_worker_b39_wsl_drive_mounts_use_windows_identity_semantics() -> None:
    def rehash_home(value: dict[str, object]) -> None:
        value["home_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "home_sha256"},
        )

    def rehash_binding(value: dict[str, object]) -> None:
        value["binding_sha256"] = company_contract_sha256(
            {key: member for key, member in value.items() if key != "binding_sha256"},
        )

    def wsl_binding() -> dict[str, object]:
        value = provider_launch_binding()
        value.update({
            "platform": "wsl", "worktree_root": "/mnt/c/aoi/worktree",
            "launch_cwd": "/mnt/c/aoi/worktree/child",
            "executable_path": "/mnt/c/bin/codex.exe",
        })
        rehash_binding(value)
        return value

    mounted_home = provider_codex_home(
        platform="wsl", absolute_path="/mnt/c/users/ryan/codex-home",
    )
    assert validate_provider_codex_home(mounted_home)["absolute_path"] == "/mnt/c/users/ryan/codex-home"
    assert validate_provider_launch_binding(wsl_binding())["platform"] == "wsl"

    # Exact lowercase WSL drive mounts use the same fail-closed spelling rules
    # as Windows for Home, worktree root, cwd, and executable paths.
    for absolute_path in (
        "/mnt/c/users/Ryan/codex-home", "/mnt/c/progra~1/codex-home",
    ):
        with pytest.raises(CompanyContractError):
            validate_provider_codex_home(provider_codex_home(
                platform="wsl", absolute_path=absolute_path,
            ))
    for field, path in (
        ("worktree_root", "/mnt/c/aoi/Worktree"),
        ("launch_cwd", "/mnt/c/aoi/worktree/Child"),
        ("executable_path", "/mnt/c/bin/Codex.exe"),
        ("worktree_root", "/mnt/c/progra~1/worktree"),
        ("launch_cwd", "/mnt/c/aoi/worktree/progra~1"),
        ("executable_path", "/mnt/c/bin/progra~1.exe"),
    ):
        binding = wsl_binding()
        binding[field] = path
        rehash_binding(binding)
        with pytest.raises(CompanyContractError):
            validate_provider_launch_binding(binding)

    for path in ("/mnt", "/mnt/", "/mnt/C/aoi", "/mnt/cc/aoi", "/mnt/custom/aoi"):
        with pytest.raises(CompanyContractError):
            company_contracts._provider_launch_path(path, "test.path", platform="wsl")

    # Unambiguous WSL-native paths preserve case-sensitive POSIX semantics and
    # accept ordinary tilde names, including names that look like Windows 8.3.
    for path in ("/home/Ryan/codex~1", "/home/ryan/Codex", "/opt/Tools/codex~1"):
        assert company_contracts._provider_launch_path(path, "test.path", platform="wsl") == path
    native_binding = provider_launch_binding()
    native_binding.update({
        "platform": "wsl", "worktree_root": "/home/Ryan/Repo",
        "launch_cwd": "/home/Ryan/Repo/Child", "executable_path": "/opt/Tools/codex~1",
    })
    rehash_binding(native_binding)
    assert validate_provider_launch_binding(native_binding)["worktree_root"] == "/home/Ryan/Repo"

    mounted_identity = company_contracts._provider_path_identity_sha256(
        platform="wsl", absolute_path="/mnt/c/aoi/worktree",
    )
    native_identity = company_contracts._provider_path_identity_sha256(
        platform="wsl", absolute_path="/home/Ryan/Repo",
    )
    assert mounted_identity == company_contract_sha256({
        "identity_schema_version": 2, "platform": "wsl",
        "filesystem_semantics": "wsl-windows-drive-mount-v1",
        "absolute_path": "/mnt/c/aoi/worktree",
    })
    assert native_identity == company_contract_sha256({
        "identity_schema_version": 2, "platform": "wsl",
        "filesystem_semantics": "posix-v1", "absolute_path": "/home/Ryan/Repo",
    })
    assert native_identity != company_contracts._provider_path_identity_sha256(
        platform="wsl", absolute_path="/home/ryan/Repo",
    )


def test_provider_worker_b33_pinned_dialect_matches_stdio() -> None:
    assert company_contracts._CODEX_APP_SERVER_REQUEST_METHODS == codex_app_server_stdio._REQUEST_METHODS
    assert company_contracts._CODEX_APP_SERVER_SERVER_NOTIFICATION_METHODS == codex_app_server_stdio._NOTIFICATION_METHODS


def test_provider_worker_b33_pins_method_direction_and_clean_terminal_seal() -> None:
    def rehash(receipt: dict[str, object]) -> None:
        receipt["receipt_sha256"] = company_contract_sha256(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )

    for method in ("initialize", "model/list", "thread/start", "turn/start", "turn/interrupt"):
        receipt = provider_io_receipt(phase="response_received", channel="stdout")
        receipt["method"] = method
        rehash(receipt)
        assert validate_provider_worker_io_receipt(receipt)["method"] == method

    for phase, channel, method in (
        ("response_received", "stdout", "turn/completed"),
        ("request_send_pending", "stdin", "initialized"),
        ("client_notification_send_pending", "stdin", "turn/completed"),
        ("client_notification_written", "stdin", "model/list"),
        ("notification_received", "stdout", "initialized"),
        ("notification_received", "stdout", "unknown/notification"),
    ):
        receipt = provider_io_receipt()
        receipt.update({"phase": phase, "channel": channel, "method": method})
        receipt["request_id"] = 1 if phase in {"response_received", "request_send_pending"} else None
        rehash(receipt)
        with pytest.raises(CompanyContractError):
            validate_provider_worker_io_receipt(receipt)

    for phase in ("client_notification_send_pending", "client_notification_written"):
        receipt = provider_io_receipt()
        receipt.update({"phase": phase, "channel": "stdin", "method": "initialized", "request_id": None})
        rehash(receipt)
        assert validate_provider_worker_io_receipt(receipt)["method"] == "initialized"
    receipt = provider_io_receipt()
    receipt.update({"phase": "notification_received", "channel": "stdout", "method": "turn/completed", "request_id": None})
    rehash(receipt)
    assert validate_provider_worker_io_receipt(receipt)["method"] == "turn/completed"

    for provenance, observation in (
        ("collector_received", observed()),
        ("provider_client_emitted", observed()),
        ("adapter_receipt_persisted", {"state": "unknown", "reason": "collector_lost"}),
    ):
        receipt = provider_io_receipt()
        receipt["provenance"] = provenance
        receipt["observation"] = observation
        rehash(receipt)
        with pytest.raises(CompanyContractError):
            validate_provider_worker_io_receipt(receipt)


def test_provider_worker_state_reopens_raw_and_exact_canonical_result_cas(tmp_path: object) -> None:
    store = BlobStore(str(tmp_path))
    raw_metadata = store.put(b"provider wire bytes")
    io = provider_io_receipt()
    io["raw_artifact"] = {**blob(), "sha256": raw_metadata.sha256,
                          "size_bytes": raw_metadata.size_bytes,
                          "media_type": PROVIDER_WORKER_RAW_MEDIA_TYPE}
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    document = provider_turn_result()
    result_metadata = store.put(canonical_provider_turn_result_bytes(document))
    receipt = provider_turn_result_receipt()
    receipt["result_ref"] = {**blob(), "sha256": result_metadata.sha256,
                             "size_bytes": result_metadata.size_bytes,
                             "media_type": PROVIDER_TURN_RESULT_MEDIA_TYPE}
    receipt["result_sha256"] = result_metadata.sha256
    receipt["receipt_sha256"] = company_contract_sha256({k: v for k, v in receipt.items() if k != "receipt_sha256"})

    class Probe:
        def __init__(self) -> None:
            self.blobs = store

    request = {"events": [{"payload": io}, {"payload": receipt}]}
    CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), request)  # type: ignore[arg-type]

    wrong_size = copy.deepcopy(io)
    wrong_size["raw_artifact"]["size_bytes"] = raw_metadata.size_bytes + 1  # type: ignore[index]
    wrong_size["receipt_sha256"] = company_contract_sha256({k: v for k, v in wrong_size.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": wrong_size}]})  # type: ignore[arg-type]

    missing = copy.deepcopy(io)
    missing["raw_artifact"]["sha256"] = "f" * 64  # type: ignore[index]
    missing["receipt_sha256"] = company_contract_sha256({k: v for k, v in missing.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": missing}]})  # type: ignore[arg-type]

    noncanonical = store.put(b'{"document_type":"provider_turn_result_v1"}')
    bad_result = copy.deepcopy(receipt)
    bad_result["result_ref"] = {**blob(), "sha256": noncanonical.sha256,
                                "size_bytes": noncanonical.size_bytes,
                                "media_type": PROVIDER_TURN_RESULT_MEDIA_TYPE}
    bad_result["result_sha256"] = noncanonical.sha256
    bad_result["receipt_sha256"] = company_contract_sha256({k: v for k, v in bad_result.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": bad_result}]})  # type: ignore[arg-type]


def test_provider_turn_result_requires_exact_terminal_io_in_transaction_or_projection(tmp_path: object) -> None:
    store = BlobStore(str(tmp_path))
    raw_metadata = store.put(b"provider terminal seal bytes")
    io = provider_io_receipt()
    io["raw_artifact"] = {**blob(), "sha256": raw_metadata.sha256,
                          "size_bytes": raw_metadata.size_bytes,
                          "media_type": PROVIDER_WORKER_RAW_MEDIA_TYPE}
    io["receipt_sha256"] = company_contract_sha256({k: v for k, v in io.items() if k != "receipt_sha256"})
    document = provider_turn_result()
    result_metadata = store.put(canonical_provider_turn_result_bytes(document))
    receipt = provider_turn_result_receipt()
    receipt["result_ref"] = {**blob(), "sha256": result_metadata.sha256,
                             "size_bytes": result_metadata.size_bytes,
                             "media_type": PROVIDER_TURN_RESULT_MEDIA_TYPE}
    receipt["result_sha256"] = result_metadata.sha256
    receipt["receipt_sha256"] = company_contract_sha256({k: v for k, v in receipt.items() if k != "receipt_sha256"})

    class Projected:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

    class ReadModel:
        def __init__(self, projected: dict[str, object] | None) -> None:
            self.projected = projected

        def object(self, contract_type: str, object_key: str) -> Projected | None:
            assert contract_type == PROVIDER_WORKER_IO_RECEIPT_V1
            assert object_key == "io-1"
            return None if self.projected is None else Projected(self.projected)

    class Probe:
        def __init__(self, projected: dict[str, object] | None = None) -> None:
            self.blobs = store
            self.readmodel = ReadModel(projected)

    CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": io}, {"payload": receipt}]})  # type: ignore[arg-type]
    CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(io), {"events": [{"payload": receipt}]})  # type: ignore[arg-type]
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": receipt}]})  # type: ignore[arg-type]

    response = copy.deepcopy(io)
    response.update({"channel": "stdout", "phase": "response_received", "method": "turn/start", "request_id": 1})
    response["receipt_sha256"] = company_contract_sha256({k: v for k, v in response.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": response}, {"payload": receipt}]})  # type: ignore[arg-type]

    mismatch = copy.deepcopy(io); mismatch["execution_id"] = "other-turn-exec"
    mismatch["receipt_sha256"] = company_contract_sha256({k: v for k, v in mismatch.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": mismatch}, {"payload": receipt}]})  # type: ignore[arg-type]

    untrusted = copy.deepcopy(io); untrusted["provenance"] = "collector_received"
    untrusted["receipt_sha256"] = company_contract_sha256({k: v for k, v in untrusted.items() if k != "receipt_sha256"})
    with pytest.raises(CompanyStateInvariantError):
        CompanyStateOwner._verify_provider_worker_artifacts_unlocked(Probe(), {"events": [{"payload": untrusted}, {"payload": receipt}]})  # type: ignore[arg-type]


def test_work_definition_launch_contracts_are_strict_and_registered() -> None:
    result = work_result_receipt()
    binding = work_dispatch_binding()
    enforcement = work_definition_enforcement()
    assert validate_company_contract(result)["result_receipt_id"] == result["result_receipt_id"]
    assert validate_work_result_receipt(result)["provenance"] == "AOI_verified"
    assert validate_company_contract(binding)["binding_id"] == binding["binding_id"]
    assert validate_work_dispatch_binding(binding)["provider_allowlist"] == ["codex", "vcs"]
    assert validate_company_contract(enforcement)["mode"] == "registered_launch_required"
    assert validate_work_definition_enforcement(enforcement)["gate_id"] == "work-definition-enforcement"

    for factory, digest, rehash in (
        (work_result_receipt, "receipt_sha256", _rehash_work_result_receipt),
        (work_dispatch_binding, "binding_sha256", _rehash_work_dispatch_binding),
        (work_definition_enforcement, "enforcement_sha256", _rehash_work_definition_enforcement),
    ):
        extra = factory()
        extra["unexpected"] = True
        with pytest.raises(CompanyContractError):
            validate_company_contract(extra)
        missing = factory()
        missing.pop(digest)
        with pytest.raises(CompanyContractError):
            validate_company_contract(missing)
        tampered = factory()
        tampered[digest] = "9" * 64
        with pytest.raises(CompanyContractError):
            validate_company_contract(tampered)
        rehashed = factory()
        rehash(rehashed)
        assert validate_company_contract(rehashed)

    unavailable_result = work_result_receipt()
    unavailable_result["result_ref"]["availability"] = "unavailable"  # type: ignore[index]
    _rehash_work_result_receipt(unavailable_result)
    with pytest.raises(CompanyContractError):
        validate_company_contract(unavailable_result)
    wrong_result_fixed = work_result_receipt()
    wrong_result_fixed["provenance"] = "agent_reported"
    _rehash_work_result_receipt(wrong_result_fixed)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_result_fixed)
    result_digest_tamper = work_result_receipt()
    result_digest_tamper["task_sha256"] = "9" * 64
    with pytest.raises(CompanyContractError):
        validate_company_contract(result_digest_tamper)

    for field in ("prompt_ref", "context_manifest_ref"):
        unavailable = work_dispatch_binding()
        unavailable[field]["availability"] = "unavailable"  # type: ignore[index]
        _rehash_work_dispatch_binding(unavailable)
        with pytest.raises(CompanyContractError):
            validate_company_contract(unavailable)
        wrong_media = work_dispatch_binding()
        wrong_media[field]["media_type"] = "text/plain"  # type: ignore[index]
        _rehash_work_dispatch_binding(wrong_media)
        with pytest.raises(CompanyContractError):
            validate_company_contract(wrong_media)
    for providers in (["vcs", "codex"], ["codex", "codex"]):
        invalid_providers = work_dispatch_binding()
        invalid_providers["provider_allowlist"] = providers
        _rehash_work_dispatch_binding(invalid_providers)
        with pytest.raises(CompanyContractError):
            validate_company_contract(invalid_providers)
    bool_depth = work_dispatch_binding()
    bool_depth["delegation_depth"] = True
    _rehash_work_dispatch_binding(bool_depth)
    with pytest.raises(CompanyContractError):
        validate_company_contract(bool_depth)
    inverted = work_dispatch_binding()
    inverted["expires_at"] = T0
    _rehash_work_dispatch_binding(inverted)
    with pytest.raises(CompanyContractError):
        validate_company_contract(inverted)
    wrong_binding_fixed = work_dispatch_binding()
    wrong_binding_fixed["observation"] = {"state": "unknown", "reason": "pending"}
    _rehash_work_dispatch_binding(wrong_binding_fixed)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_binding_fixed)
    binding_digest_tamper = work_dispatch_binding()
    binding_digest_tamper["authority_scope_sha256"] = "9" * 64
    with pytest.raises(CompanyContractError):
        validate_company_contract(binding_digest_tamper)

    wrong_enforcement_fixed = work_definition_enforcement()
    wrong_enforcement_fixed["mode"] = "optional"
    _rehash_work_definition_enforcement(wrong_enforcement_fixed)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_enforcement_fixed)
    wrong_enforcement_observation = work_definition_enforcement()
    wrong_enforcement_observation["observation"] = {"state": "unknown", "reason": "pending"}
    _rehash_work_definition_enforcement(wrong_enforcement_observation)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_enforcement_observation)
    enforcement_digest_tamper = work_definition_enforcement()
    enforcement_digest_tamper["previous_transaction_sha256"] = "9" * 64
    with pytest.raises(CompanyContractError):
        validate_company_contract(enforcement_digest_tamper)


def test_work_definition_contracts_are_strict_and_hash_bound() -> None:
    task = task_revision()
    packet = work_packet()
    assert validate_company_contract(task)["task_sha256"] == task["task_sha256"]
    assert validate_task_revision(task)["task_id"] == "task-1"
    assert validate_company_contract(packet)["packet_sha256"] == packet["packet_sha256"]
    assert validate_work_packet(packet)["delegation_depth"] == 1
    assert validate_work_definition_bundle(task, packet, work_context_manifest())["work_packet"]["packet_id"] == "packet-1"
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, packet, work_context_manifest(), parent_context_manifest=work_context_manifest(),
        )

    changed_prompt = work_packet(prompt_digest="9" * 64)
    assert changed_prompt["packet_id"] == packet["packet_id"]
    assert changed_prompt["packet_sha256"] != packet["packet_sha256"]

    for malformed in (copy.deepcopy(task), copy.deepcopy(packet)):
        malformed["unexpected"] = True
        with pytest.raises(CompanyContractError):
            validate_company_contract(malformed)
    missing = work_packet()
    missing.pop("objective")
    with pytest.raises(CompanyContractError):
        validate_company_contract(missing)
    wrong_type = task_revision()
    wrong_type["revision"] = True
    _rehash_task(wrong_type)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_type)
    tampered = work_packet()
    tampered["objective"] = "broadened objective"
    with pytest.raises(CompanyContractError):
        validate_company_contract(tampered)


def test_work_packet_parent_nulls_scope_order_expiry_and_media_are_strict() -> None:
    packet = work_packet()
    parent_pair = copy.deepcopy(packet)
    parent_pair["parent_packet_id"] = "packet-parent"
    _rehash_packet(parent_pair)
    with pytest.raises(CompanyContractError):
        validate_company_contract(parent_pair)

    unjustified = copy.deepcopy(packet)
    unjustified["null_relationship_justifications"]["manager_node_id"] = None  # type: ignore[index]
    _rehash_packet(unjustified)
    with pytest.raises(CompanyContractError):
        validate_company_contract(unjustified)

    unordered = copy.deepcopy(packet)
    unordered["authority_scope"]["read_refs"] = [  # type: ignore[index]
        _work_ref("file", "src/z.py"), _work_ref("file", "src/a.py"),
    ]
    _rehash_packet(unordered)
    with pytest.raises(CompanyContractError):
        validate_company_contract(unordered)
    duplicate = copy.deepcopy(packet)
    duplicate["authority_scope"]["write_refs"] = [  # type: ignore[index]
        _work_ref("file", "src/a.py"), _work_ref("file", "src/a.py"),
    ]
    _rehash_packet(duplicate)
    with pytest.raises(CompanyContractError):
        validate_company_contract(duplicate)
    wrong_ref_shape = copy.deepcopy(packet)
    wrong_ref_shape["authority_scope"]["read_refs"] = ["src/a.py"]  # type: ignore[index]
    _rehash_packet(wrong_ref_shape)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_ref_shape)
    wrong_ref_kind = copy.deepcopy(packet)
    wrong_ref_kind["authority_scope"]["read_refs"] = [_work_ref("glob", "src/a.py")]  # type: ignore[index]
    _rehash_packet(wrong_ref_kind)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_ref_kind)
    case_duplicate = copy.deepcopy(packet)
    case_duplicate["authority_scope"]["read_refs"] = [  # type: ignore[index]
        _work_ref("file", "src/a.py"), _work_ref("file", "SRC/A.py"),
    ]
    _rehash_packet(case_duplicate)
    with pytest.raises(CompanyContractError):
        validate_company_contract(case_duplicate)
    overlapping_kinds = copy.deepcopy(packet)
    overlapping_kinds["authority_scope"]["read_refs"] = [  # type: ignore[index]
        _work_ref("file", "src/a.py"), _work_ref("tree", "src/a.py"),
    ]
    _rehash_packet(overlapping_kinds)
    with pytest.raises(CompanyContractError):
        validate_company_contract(overlapping_kinds)

    child_scope = copy.deepcopy(packet)
    child_scope["packet_id"] = "packet-child"
    child_scope["parent_packet_id"] = "packet-1"
    child_scope["parent_packet_sha256"] = H
    child_scope["delegation_depth"] = 2
    child_scope["authority_scope"] = {
        "read_refs": [_work_ref("file", "src/a.py")], "write_refs": [], "run_refs": [],
        "export_refs": [], "provider_allowlist": ["codex"],
    }
    _rehash_packet(child_scope)
    assert validate_company_contract(child_scope)["packet_id"] == "packet-child"

    expired = copy.deepcopy(packet)
    expired["expires_at"] = T0
    _rehash_packet(expired)
    with pytest.raises(CompanyContractError):
        validate_company_contract(expired)
    wrong_prompt_media = copy.deepcopy(packet)
    wrong_prompt_media["prompt_ref"]["media_type"] = "text/plain"  # type: ignore[index]
    _rehash_packet(wrong_prompt_media)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_prompt_media)
    wrong_context_media = copy.deepcopy(packet)
    wrong_context_media["context_manifest_ref"]["media_type"] = "application/json"  # type: ignore[index]
    _rehash_packet(wrong_context_media)
    with pytest.raises(CompanyContractError):
        validate_company_contract(wrong_context_media)


def test_work_definition_bundle_binds_context_task_parent_and_authority() -> None:
    task = task_revision()
    context = work_context_manifest()
    root = work_packet(task=task, context=context)
    bundle = validate_work_definition_bundle(task, root, context)
    assert bundle["parent_packet"] is None
    assert authority_scope_is_subset(root["authority_scope"], task["authority_ceiling"])

    explicit_tree = copy.deepcopy(root)
    explicit_tree["authority_scope"] = _work_scope()
    _rehash_packet(explicit_tree)
    assert validate_work_definition_bundle(task, explicit_tree, context)["work_packet"]["packet_id"] == "packet-1"
    descendant_only = copy.deepcopy(context)
    descendant_only["source_entries"] = descendant_only["source_entries"][1:]  # type: ignore[index]
    _rehash_context(descendant_only)
    tree_without_directory = work_packet(task=task, context=descendant_only)
    tree_without_directory["authority_scope"] = _work_scope()
    _rehash_packet(tree_without_directory)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, tree_without_directory, descendant_only)

    child = work_packet(task=task, context=context)
    child["packet_id"] = "packet-child"
    child["parent_packet_id"] = root["packet_id"]
    child["parent_packet_sha256"] = root["packet_sha256"]
    child["delegation_depth"] = 2
    child["authority_scope"] = {
        "read_refs": [_work_ref("file", "src/a.py")], "write_refs": [], "run_refs": [],
        "export_refs": [], "provider_allowlist": ["codex"],
    }
    _rehash_packet(child)
    assert validate_work_definition_bundle(
        task, child, context, parent_packet=root, parent_context_manifest=context,
    )["parent_packet"]["packet_id"] == "packet-1"

    root_depth = copy.deepcopy(root)
    root_depth["delegation_depth"] = 2
    _rehash_packet(root_depth)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, root_depth, context)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, root, context, parent_packet=root)

    no_parent = copy.deepcopy(child)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, no_parent, context)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, child, context, parent_packet=root)
    wrong_parent_hash = copy.deepcopy(child)
    wrong_parent_hash["parent_packet_sha256"] = "9" * 64
    _rehash_packet(wrong_parent_hash)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, wrong_parent_hash, context, parent_packet=root, parent_context_manifest=context,
        )
    wrong_child_depth = copy.deepcopy(child)
    wrong_child_depth["delegation_depth"] = 3
    _rehash_packet(wrong_child_depth)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, wrong_child_depth, context, parent_packet=root, parent_context_manifest=context,
        )

    for field in ("company_id", "task_id", "task_revision_id", "task_sha256"):
        wrong = copy.deepcopy(root)
        wrong[field] = "other-task" if field != "task_sha256" else "9" * 64
        _rehash_packet(wrong)
        with pytest.raises(CompanyContractError):
            validate_work_definition_bundle(task, wrong, context)
    wrong_context_ref = copy.deepcopy(root)
    wrong_context_ref["context_manifest_ref"]["size_bytes"] = 1  # type: ignore[index]
    _rehash_packet(wrong_context_ref)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, wrong_context_ref, context)
    wrong_manifest_digest = copy.deepcopy(root)
    wrong_manifest_digest["source_manifest_sha256"] = "9" * 64
    _rehash_packet(wrong_manifest_digest)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, wrong_manifest_digest, context)
    outside_context = copy.deepcopy(root)
    outside_context["authority_scope"]["read_refs"] = [_work_ref("file", "secret.txt")]  # type: ignore[index]
    _rehash_packet(outside_context)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, outside_context, context)
    outside_task = copy.deepcopy(root)
    outside_task["authority_scope"]["write_refs"] = [_work_ref("file", "requirements/base.txt")]  # type: ignore[index]
    _rehash_packet(outside_task)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, outside_task, context)
    parent_escape = work_packet(task=task, context=context)
    parent_escape["packet_id"] = "packet-grandchild"
    parent_escape["parent_packet_id"] = child["packet_id"]
    parent_escape["parent_packet_sha256"] = child["packet_sha256"]
    parent_escape["delegation_depth"] = 3
    parent_escape["authority_scope"] = {
        "read_refs": [_work_ref("file", "src/a.py")],
        "write_refs": [_work_ref("file", "src/a.py")],
        "run_refs": [], "export_refs": [], "provider_allowlist": ["codex"],
    }
    _rehash_packet(parent_escape)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, parent_escape, context, parent_packet=child, parent_context_manifest=context,
        )


def test_work_definition_bundle_child_inherits_context_cut_and_lifecycle() -> None:
    task = task_revision()
    context = work_context_manifest()
    parent = work_packet(task=task, context=context)
    parent["created_at"] = "2026-07-26T00:00:10Z"
    parent["expires_at"] = "2026-07-26T02:00:00Z"
    _rehash_packet(parent)

    child = work_packet(task=task, context=context)
    child.update({"packet_id": "packet-child", "parent_packet_id": parent["packet_id"],
                  "parent_packet_sha256": parent["packet_sha256"], "delegation_depth": 2,
                  "created_at": "2026-07-26T00:00:10Z", "expires_at": "2026-07-26T02:00:00Z",
                  "authority_scope": {"read_refs": [_work_ref("file", "src/a.py")],
                                      "write_refs": [], "run_refs": [], "export_refs": [],
                                      "provider_allowlist": ["codex"]}})
    _rehash_packet(child)
    assert validate_work_definition_bundle(
        task, child, context, parent_packet=parent, parent_context_manifest=context,
    )["work_packet"]["packet_id"] == "packet-child"

    later_task = task_revision()
    later_task["created_at"] = "2026-07-26T00:00:01Z"
    _rehash_task(later_task)
    earlier_packet = work_packet(task=later_task, context=context)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(later_task, earlier_packet, context)

    for field, value in (("created_at", T0), ("expires_at", "2026-07-26T03:00:00Z")):
        invalid = copy.deepcopy(child)
        invalid[field] = value
        _rehash_packet(invalid)
        with pytest.raises(CompanyContractError):
            validate_work_definition_bundle(
                task, invalid, context, parent_packet=parent, parent_context_manifest=context,
            )

    changed_context = copy.deepcopy(context)
    changed_context["config_entries"][0]["sha256"] = "9" * 64  # type: ignore[index]
    _rehash_context(changed_context)
    changed_child = work_packet(task=task, context=changed_context)
    changed_child.update({"packet_id": "packet-child", "parent_packet_id": parent["packet_id"],
                          "parent_packet_sha256": parent["packet_sha256"], "delegation_depth": 2,
                          "created_at": parent["created_at"], "expires_at": parent["expires_at"],
                          "authority_scope": child["authority_scope"]})
    _rehash_packet(changed_child)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, changed_child, changed_context, parent_packet=parent, parent_context_manifest=context,
        )

    changed_cut = copy.deepcopy(context)
    changed_cut["upstream_result_refs"] = [_work_blob("application/json", "9" * 64)]
    changed_cut_child = work_packet(task=task, context=changed_cut)
    changed_cut_child.update({"packet_id": "packet-child", "parent_packet_id": parent["packet_id"],
                              "parent_packet_sha256": parent["packet_sha256"], "delegation_depth": 2,
                              "created_at": parent["created_at"], "expires_at": parent["expires_at"],
                              "authority_scope": child["authority_scope"]})
    _rehash_packet(changed_cut_child)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, changed_cut_child, changed_cut, parent_packet=parent, parent_context_manifest=context,
        )


def test_work_definition_bundle_child_derives_parent_context_and_validates_parent() -> None:
    task = task_revision()
    context = work_context_manifest()
    parent = work_packet(task=task, context=context)
    parent["created_at"] = "2026-07-26T00:00:10Z"
    parent["expires_at"] = "2026-07-26T02:00:00Z"
    _rehash_packet(parent)

    def child_for(child_context: dict[str, object]) -> dict[str, object]:
        child = work_packet(task=task, context=child_context)
        child.update({
            "packet_id": "packet-child", "parent_packet_id": parent["packet_id"],
            "parent_packet_sha256": parent["packet_sha256"], "delegation_depth": 2,
            "created_at": parent["created_at"], "expires_at": parent["expires_at"],
            "authority_scope": {"read_refs": [_work_ref("file", "src/a.py")],
                                "write_refs": [], "run_refs": [], "export_refs": [],
                                "provider_allowlist": ["codex"]},
        })
        _rehash_packet(child)
        return child

    child = child_for(context)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(task, child, context, parent_packet=parent)
    mismatched_parent_context = copy.deepcopy(context)
    mismatched_parent_context["upstream_result_refs"] = []
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, child, context, parent_packet=parent,
            parent_context_manifest=mismatched_parent_context,
        )

    overlay = copy.deepcopy(context)
    added_ref = _work_blob("application/json", "a" * 64)
    overlay["upstream_result_refs"] = [
        added_ref, context["upstream_result_refs"][0],  # type: ignore[index]
    ]
    overlay_child = child_for(overlay)
    bundle = validate_work_definition_bundle(
        task, overlay_child, overlay, parent_packet=parent, parent_context_manifest=context,
    )
    assert bundle["context_derivation"]["added_upstream_result_refs"] == [added_ref]

    for upstream_refs in ([], [_work_blob("application/json", "9" * 64)]):
        invalid_context = copy.deepcopy(context)
        invalid_context["upstream_result_refs"] = upstream_refs
        with pytest.raises(CompanyContractError):
            validate_work_definition_bundle(
                task, child_for(invalid_context), invalid_context, parent_packet=parent,
                parent_context_manifest=context,
            )

    immutable_cut = copy.deepcopy(context)
    immutable_cut["config_entries"][0]["sha256"] = "9" * 64  # type: ignore[index]
    _rehash_context(immutable_cut)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            task, child_for(immutable_cut), immutable_cut, parent_packet=parent,
            parent_context_manifest=context,
        )
    fresh_snapshot = copy.deepcopy(context)
    fresh_snapshot["department_snapshot_ref"] = _work_blob(DEPARTMENT_SNAPSHOT_MEDIA_TYPE, "8" * 64)
    with pytest.raises(CompanyContractError, match="fresh department snapshot requires a future schema"):
        validate_work_definition_bundle(
            task, child_for(fresh_snapshot), fresh_snapshot, parent_packet=parent,
            parent_context_manifest=context,
        )

    later_task = copy.deepcopy(task)
    later_task["created_at"] = "2026-07-26T00:00:20Z"
    _rehash_task(later_task)
    early_parent = copy.deepcopy(parent)
    early_parent["task_sha256"] = later_task["task_sha256"]
    _rehash_packet(early_parent)
    early_child = child_for(context)
    early_child["task_sha256"] = later_task["task_sha256"]
    early_child["parent_packet_sha256"] = early_parent["packet_sha256"]
    _rehash_packet(early_child)
    with pytest.raises(CompanyContractError):
        validate_work_definition_bundle(
            later_task, early_child, context, parent_packet=early_parent,
            parent_context_manifest=context,
        )

    out_of_task_parent = copy.deepcopy(parent)
    out_of_task_parent["authority_scope"] = {
        "read_refs": [_work_ref("file", "requirements/base.txt")], "write_refs": [],
        "run_refs": [], "export_refs": [], "provider_allowlist": ["codex"],
    }
    _rehash_packet(out_of_task_parent)
    out_of_task_child = child_for(context)
    out_of_task_child["parent_packet_sha256"] = out_of_task_parent["packet_sha256"]
    _rehash_packet(out_of_task_child)
    with pytest.raises(CompanyContractError, match="parent authority exceeds task ceiling"):
        validate_work_definition_bundle(
            task, out_of_task_child, context, parent_packet=out_of_task_parent,
            parent_context_manifest=context,
        )

    out_of_context_parent = copy.deepcopy(parent)
    out_of_context_parent["authority_scope"] = {
        "read_refs": [_work_ref("file", "src/missing.py")], "write_refs": [],
        "run_refs": [], "export_refs": [], "provider_allowlist": ["codex"],
    }
    _rehash_packet(out_of_context_parent)
    out_of_context_child = child_for(context)
    out_of_context_child["parent_packet_sha256"] = out_of_context_parent["packet_sha256"]
    _rehash_packet(out_of_context_child)
    with pytest.raises(CompanyContractError, match="parent authority is outside context"):
        validate_work_definition_bundle(
            task, out_of_context_child, context, parent_packet=out_of_context_parent,
            parent_context_manifest=context,
        )


def test_work_definition_bundle_file_scope_requires_file_manifest_entry() -> None:
    for entry_type in ("directory", "artifact", "package", "tool"):
        context = work_context_manifest()
        context["source_entries"][1]["entry_type"] = entry_type  # type: ignore[index]
        _rehash_context(context)
        with pytest.raises(CompanyContractError, match="packet authority is outside context"):
            validate_work_definition_bundle(task_revision(), work_packet(context=context), context)


def test_work_context_manifest_is_canonical_cas_without_prompt_or_path_escape() -> None:
    manifest = work_context_manifest()
    validated = validate_company_contract(manifest)
    assert validated["document_type"] == WORK_CONTEXT_MANIFEST_V1
    assert canonical_work_context_manifest_bytes(manifest) == canonical_company_json_bytes(validated)
    assert work_context_manifest_sha256(manifest) == hashlib.sha256(
        canonical_company_json_bytes(validated),
    ).hexdigest()

    for forbidden_field in (
        "prompt", "credential", "session", "token", "chain_of_thought",
    ):
        forbidden = copy.deepcopy(manifest)
        forbidden[forbidden_field] = "hidden instruction"
        with pytest.raises(CompanyContractError):
            validate_work_context_manifest(forbidden)
    traversal = copy.deepcopy(manifest)
    traversal["source_entries"][0]["path"] = "../secret"  # type: ignore[index]
    with pytest.raises(CompanyContractError):
        validate_work_context_manifest(traversal)
    unsorted = copy.deepcopy(manifest)
    unsorted["source_entries"] = [  # type: ignore[assignment]
        {"path": "src/z.py", "entry_type": "file", "sha256": "1" * 64, "size_bytes": 1},
        {"path": "src/a.py", "entry_type": "file", "sha256": "2" * 64, "size_bytes": 1},
    ]
    with pytest.raises(CompanyContractError):
        validate_work_context_manifest(unsorted)
    for bad_path in (
        "C:relative", "C:/absolute", "src/a.py:ads", "src/<bad.py", "src/control\x01.py",
        "src/trailing.", "src/trailing ", "src/con.txt", "src/COM¹.txt", "src/LPT²",
        "src/CONIN$.txt", "src/CONOUT$",
    ):
        malformed = copy.deepcopy(manifest)
        malformed["source_entries"][0]["path"] = bad_path  # type: ignore[index]
        malformed["source_manifest_sha256"] = hashlib.sha256(  # type: ignore[index]
            canonical_company_json_bytes(malformed["source_entries"]),
        ).hexdigest()
        with pytest.raises(CompanyContractError):
            validate_work_context_manifest(malformed)
    case_alias = copy.deepcopy(manifest)
    case_alias["source_entries"] = [  # type: ignore[assignment]
        {"path": "src/a.py", "entry_type": "file", "sha256": "1" * 64, "size_bytes": 1},
        {"path": "SRC/A.py", "entry_type": "file", "sha256": "2" * 64, "size_bytes": 1},
    ]
    case_alias["source_manifest_sha256"] = hashlib.sha256(  # type: ignore[index]
        canonical_company_json_bytes(case_alias["source_entries"]),
    ).hexdigest()
    with pytest.raises(CompanyContractError):
        validate_work_context_manifest(case_alias)
    cross_category = copy.deepcopy(manifest)
    cross_category["config_entries"][0]["path"] = "SRC/A.py"  # type: ignore[index]
    cross_category["config_manifest_sha256"] = hashlib.sha256(  # type: ignore[index]
        canonical_company_json_bytes(cross_category["config_entries"]),
    ).hexdigest()
    with pytest.raises(CompanyContractError):
        validate_work_context_manifest(cross_category)
    unicode_case_alias = copy.deepcopy(manifest)
    unicode_case_alias["source_entries"] = [  # type: ignore[assignment]
        {"path": "src", "entry_type": "directory", "sha256": "1" * 64, "size_bytes": 0},
        {"path": "src/café.py", "entry_type": "file", "sha256": "2" * 64, "size_bytes": 1},
    ]
    unicode_case_alias["config_entries"][0]["path"] = "SRC/CAFÉ.PY"  # type: ignore[index]
    _rehash_context(unicode_case_alias)
    with pytest.raises(CompanyContractError):
        validate_work_context_manifest(unicode_case_alias)
    decomposed = copy.deepcopy(manifest)
    decomposed["source_entries"][1]["path"] = "src/café.py"  # type: ignore[index]
    _rehash_context(decomposed)
    with pytest.raises(CompanyContractError):
        validate_work_context_manifest(decomposed)
    running = external_job_effect_receipt(
        observed_job_state="running", previous_job_state="queued",
    )
    running["resolves_reconciliation_id"] = "reconcile-1"
    _rehash_external_job_effect_receipt(running)
    with pytest.raises(CompanyContractError):
        validate_company_contract(running)
    completed = external_job_effect_receipt()
    completed["provenance"] = "unknown"
    _rehash_external_job_effect_receipt(completed)
    with pytest.raises(CompanyContractError):
        validate_company_contract(completed)
