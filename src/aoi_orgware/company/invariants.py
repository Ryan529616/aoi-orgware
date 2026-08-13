"""Pure company dispatch/capacity invariant reduction.

This module deliberately owns no ledger or clock state.  Its inputs are the
already-addressed current records plus, optionally, one terminal transaction
attempt.  The returned projection is safe for a read model to consume, but is
not itself a persistence format.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn, TypeAlias

from .contracts import (
    ALERT_V1,
    AUTHORITY_GRANT_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    COMPANY_TRANSACTION_RECEIPT_V1,
    CONTROL_INTENT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    NEEDS_USER_REVISION_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_CODEX_HOME_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    ROUTE_POLICY_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    TASK_REVISION_V1,
    USAGE_COUNTER_SAMPLE_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    ZERO_SHA256,
    CompanyContractError,
    authority_from_grant,
    company_contract_sha256,
    validate_company_contract,
    validate_company_transaction_request,
)
from ..frozen_json import (
    FrozenJsonError,
    FrozenJsonMapping,
    thaw_json_payload,
)
from .invariant_carriers import (
    CompanyInvariantError as CompanyInvariantError,
    InvariantObject as InvariantObject,
    InvariantTransition as InvariantTransition,
    UncertainDispatch as UncertainDispatch,
)
from .telemetry_policy import (
    TelemetryPolicyError,
    automatic_coverage_state,
    coverage_event_kinds,
    exact_provider_telemetry_join,
    telemetry_id,
    unknown_drop,
)
from .projection_registry import (
    APPEND_ONCE_AUTHORITY_TYPES as _APPEND_ONCE_AUTHORITY_TYPES,
    APPEND_ONCE_PROVIDER_PROJECTION_TYPES as _APPEND_ONCE_PROVIDER_PROJECTION_TYPES,
    APPEND_ONCE_WRITE_ADMISSION_TYPES as _APPEND_ONCE_WRITE_ADMISSION_TYPES,
    APPEND_ONCE_WORK_DEFINITION_TYPES as _APPEND_ONCE_WORK_DEFINITION_TYPES,
    LOGICAL_ID_FIELDS as _LOGICAL_ID_FIELDS,
)
from .write_admission_invariants import (
    WriteAdmissionInvariantError,
    validate_relevant_write_admission_invariants,
)


MAX_ACTIVE_CARRIERS = 16
MAX_MANAGER_ACTIVE_FANOUT = 4
MAX_DELEGATION_DEPTH = 6

_HELD = frozenset({"admitted", "in_flight", "effect_unknown"})
_ACTIVE_EXECUTION = frozenset({"running", "telemetry_silent", "unknown"})
_RESOLUTION_STATES = frozenset({"dispatched", "failed_known"})
_RECEIPT_STATES = frozenset({"committed", "effect_unknown", "reconcile_required", "failed_known", "aborted"})
_PROVIDER_OBSERVATION_PROVENANCE = frozenset({
    "provider_client_emitted",
    "adapter_receipt_persisted",
    "collector_received",
    "host_process_observed",
})
_TRANSITIONS = {
    "queued": frozenset({"admitted", "cancelled"}),
    "admitted": frozenset({"in_flight", "cancelled"}),
    "in_flight": frozenset({"dispatched", "effect_unknown", "failed_known"}),
    "effect_unknown": frozenset({"dispatched", "failed_known"}),
    "dispatched": frozenset(), "failed_known": frozenset(), "cancelled": frozenset(),
}
QueueItem: TypeAlias = InvariantObject | UncertainDispatch


@dataclass(frozen=True)
class InvariantProjection:
    """Normalized state exposed to company state/view integration."""
    objects: tuple[InvariantObject, ...]
    dispatch_requests: tuple[InvariantObject, ...]
    queue_items: tuple[QueueItem, ...]
    company_capacity: int
    manager_capacity: tuple[tuple[str, int], ...]
    manager_capacity_complete: bool
    unattributed_active: tuple[str, ...]
    unresolved_shadows: tuple[UncertainDispatch, ...]


def _error(message: str) -> NoReturn:
    raise CompanyInvariantError(message)


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value,
    )


def _validate_object(value: InvariantObject) -> InvariantObject:
    if type(value) is not InvariantObject:
        _error("current objects must be InvariantObject values")
    try:
        valid_shape = (
            type(value.payload) is FrozenJsonMapping
            and all(
                type(getattr(value, name)) is str
                for name in (
                    "contract_type",
                    "object_key",
                    "event_id",
                    "payload_sha256",
                )
            )
            and type(value.global_sequence) is int
        )
    except AttributeError:
        valid_shape = False
    if not valid_shape:
        _error("current objects must be InvariantObject values")
    if value.global_sequence < 0:
        _error("invariant object global_sequence is invalid")
    try:
        payload = validate_company_contract(thaw_json_payload(value.payload))
        digest = company_contract_sha256(payload)
    except (CompanyContractError, FrozenJsonError) as exc:
        raise CompanyInvariantError(f"invariant object payload is invalid: {exc}") from exc
    if value.contract_type != payload.get("contract_type"):
        _error("invariant object contract type differs from payload")
    if digest != value.payload_sha256:
        _error("invariant object payload SHA-256 differs")
    return InvariantObject(value.contract_type, value.object_key, value.event_id,
                           value.global_sequence, value.payload_sha256, payload)


def _validate_shadow(value: UncertainDispatch) -> UncertainDispatch:
    if type(value) is not UncertainDispatch:
        _error("uncertain dispatch is invalid")
    try:
        valid_shape = (
            type(value.payload) is FrozenJsonMapping
            and all(
                type(getattr(value, name)) is str
                for name in (
                    "reservation_id",
                    "dispatch_request_id",
                    "source_event_id",
                    "source_transaction_id",
                    "source_command_id",
                    "receipt_state",
                    "requested_state",
                    "payload_sha256",
                )
            )
            and type(value.source_global_sequence) is int
        )
    except AttributeError:
        valid_shape = False
    if not valid_shape:
        _error("uncertain dispatch is invalid")
    if value.receipt_state not in {"effect_unknown", "reconcile_required"}:
        _error("uncertain dispatch is invalid")
    try:
        payload = validate_company_contract(thaw_json_payload(value.payload))
        digest = company_contract_sha256(payload)
    except (CompanyContractError, FrozenJsonError) as exc:
        raise CompanyInvariantError(f"uncertain dispatch payload is invalid: {exc}") from exc
    if payload.get("contract_type") != DISPATCH_REQUEST_V1 or digest != value.payload_sha256:
        _error("uncertain dispatch payload differs")
    if (
        not isinstance(value.source_global_sequence, int)
        or isinstance(value.source_global_sequence, bool)
        or value.source_global_sequence < 1
        or not value.source_event_id
        or not value.source_transaction_id
        or not value.source_command_id
    ):
        _error("uncertain dispatch source identity is invalid")
    required = ("reservation_id", "dispatch_request_id", "state")
    if (value.reservation_id, value.dispatch_request_id, value.requested_state) != tuple(payload[name] for name in required):
        _error("uncertain dispatch identity differs from payload")
    if (
        value.source_command_id != payload["command_id"]
        or value.requested_state != "effect_unknown"
    ):
        _error("uncertain dispatch command or requested state is invalid")
    return UncertainDispatch(value.reservation_id, value.dispatch_request_id,
                             value.source_event_id, value.source_global_sequence,
                             value.source_transaction_id, value.source_command_id,
                             value.receipt_state, value.requested_state,
                             value.payload_sha256, payload)


def _normalize_shadows(
    values: Sequence[UncertainDispatch],
) -> tuple[UncertainDispatch, ...]:
    """Deduplicate exact replay while rejecting divergent source bindings."""
    by_source: dict[str, UncertainDispatch] = {}
    for value in values:
        shadow = _validate_shadow(value)
        prior = by_source.get(shadow.source_event_id)
        if prior is None:
            by_source[shadow.source_event_id] = shadow
        elif prior != shadow:
            _error("uncertain dispatch source event has a divergent binding")
    return tuple(
        sorted(
            by_source.values(),
            key=lambda item: (
                item.reservation_id,
                item.dispatch_request_id,
                item.source_event_id,
            ),
        ),
    )


def _latest(objects: Sequence[InvariantObject], contract_type: str, field: str) -> dict[str, InvariantObject]:
    result: dict[str, InvariantObject] = {}
    for item in objects:
        if item.contract_type != contract_type:
            continue
        identity = item.payload[field]
        prior = result.get(identity)
        if prior is None or (item.global_sequence, item.event_id) > (prior.global_sequence, prior.event_id):
            result[identity] = item
    return result


def _logical_key(item: InvariantObject) -> str:
    """Use contract identity, never an incidental read-model storage key."""
    field = _LOGICAL_ID_FIELDS.get(item.contract_type)
    return str(item.payload[field]) if field is not None else item.object_key


def _payload_logical_key(
    payload: Mapping[str, Any],
    fallback: str,
) -> str:
    field = _LOGICAL_ID_FIELDS.get(str(payload["contract_type"]))
    return fallback if field is None else str(payload[field])


def _normalize_current(
    values: Sequence[InvariantObject],
) -> dict[tuple[str, str], InvariantObject]:
    """Require one unambiguous current revision for every logical object."""
    result: dict[tuple[str, str], InvariantObject] = {}
    for value in values:
        item = _validate_object(value)
        key = (item.contract_type, _logical_key(item))
        prior = result.get(key)
        if prior is None:
            result[key] = item
        elif prior != item:
            _error("current objects have divergent logical revisions")
    return result


def _of_type(
    objects: Mapping[tuple[str, str], InvariantObject],
    contract_type: str,
) -> tuple[InvariantObject, ...]:
    return tuple(
        item
        for (item_type, _), item in objects.items()
        if item_type == contract_type
    )


def _chief_term(
    objects: Mapping[tuple[str, str], InvariantObject],
) -> InvariantObject | None:
    terms = _of_type(objects, CHIEF_TERM_V1)
    if len(terms) > 1:
        _error("company has multiple logical Chief identities")
    return None if not terms else terms[0]


def _validate_transaction_authority(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
) -> None:
    """Bind every governed mutation to a previously durable grant.

    Genesis is the only exception: its empty pre-state may use the Supervisor
    grant created in that same first transaction.  Once any authority/Chief
    state exists, a transaction cannot authorize itself with a newly emitted
    grant.
    """

    old_grants = _of_type(old_objects, AUTHORITY_GRANT_V1)
    old_term = _chief_term(old_objects)
    batch_grants = tuple(
        item for item in batch if item.contract_type == AUTHORITY_GRANT_V1
    )
    governed = bool(
        old_grants
        or old_term is not None
        or batch_grants
        or any(
            item.contract_type
            in {
                CHIEF_TERM_V1,
                TAKEOVER_CAPABILITY_V1,
                TAKEOVER_CONSUMPTION_RECEIPT_V1,
            }
            for item in batch
        )
    )
    if not governed:
        return
    authority = request["actor_authority"]
    grant_pool = old_grants if old_grants else batch_grants
    matches = [
        item
        for item in grant_pool
        if item.payload["grant_sha256"]
        == authority["authority_record_sha256"]
    ]
    if len(matches) != 1:
        _error("transaction authority lacks one exact durable grant")
    grant = matches[0].payload
    issued_at = _parsed_time(str(grant["issued_at"]))
    expires_at = grant.get("expires_at")
    if expires_at is None or any(
        not issued_at <= _parsed_time(str(event["recorded_at"]))
        < _parsed_time(str(expires_at))
        for event in request["events"]
    ):
        _error("transaction authority grant is unavailable at event fence")
    try:
        derived = authority_from_grant(grant)
    except CompanyContractError as exc:
        raise CompanyInvariantError(
            f"transaction authority grant is invalid: {exc}",
        ) from exc
    if derived != authority:
        _error("transaction authority differs from its durable grant")
    if authority["actor_kind"] == "chief" and old_term is not None:
        term = old_term.payload
        carrier = old_objects.get(
            (CARRIER_BINDING_V1, str(term["carrier_id"])),
        )
        chief_executions = [
            item
            for item in _of_type(old_objects, EXECUTION_NODE_V1)
            if (
                item.payload["carrier_id"] == term["carrier_id"]
                and item.payload["execution_kind"] == "carrier"
                and item.payload["role"] == "chief"
            )
        ]
        if (
            term["state"] != "active"
            or authority["actor_id"] != term["chief_id"]
            or authority["carrier_id"] != term["carrier_id"]
            or authority["term"] != term["term"]
            or authority["chief_epoch"] != term["epoch"]
            or carrier is None
            or carrier.payload["state"] != "active"
            or carrier.payload["session_availability"] != "available"
            or carrier.payload["session_id"] is None
            or carrier.payload["observation"]["state"] != "known"
            or len(chief_executions) != 1
            or chief_executions[0].payload["runtime_status"]
            not in _ACTIVE_EXECUTION
            or chief_executions[0].payload["engineering_status"]
            in {"completed", "cancelled"}
        ):
            _error(
                "Chief mutation authority is fenced or unavailable",
            )


def _validate_chief_graph(
    objects: Mapping[tuple[str, str], InvariantObject],
) -> None:
    term_item = _chief_term(objects)
    if term_item is None:
        return
    term = term_item.payload
    if term["state"] != "active" or term["carrier_id"] is None:
        _error("logical Chief must have one active current term and carrier")
    carriers = {
        str(item.payload["carrier_id"]): item
        for item in _of_type(objects, CARRIER_BINDING_V1)
    }
    carrier = carriers.get(str(term["carrier_id"]))
    if (
        carrier is None
        or carrier.payload["actor_id"] != term["chief_id"]
        or carrier.payload["state"] == "fenced"
    ):
        _error("current Chief term and carrier binding differ")
    matching_grants = [
        item
        for item in _of_type(objects, AUTHORITY_GRANT_V1)
        if (
            item.payload["actor_kind"] == "chief"
            and item.payload["actor_id"] == term["chief_id"]
            and item.payload["carrier_id"] == term["carrier_id"]
            and item.payload["term"] == term["term"]
            and item.payload["chief_epoch"] == term["epoch"]
            and item.payload["authority_state"] == "active"
            and "company.mutate" in item.payload["permissions"]
        )
    ]
    if len(matching_grants) != 1:
        _error("current Chief term lacks one exact active authority grant")
    organization = _of_type(objects, ORGANIZATION_NODE_V1)
    if organization:
        roots = [
            item
            for item in organization
            if (
                item.payload["role"] == "chief"
                and item.payload["parent_node_id"] is None
                and item.payload["reports_to_node_id"] is None
            )
        ]
        if len(roots) != 1:
            _error("company organization lacks one logical Chief root")


def _same_payload_except(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *allowed: str,
) -> bool:
    ignored = set(allowed)
    return {
        key: value for key, value in left.items() if key not in ignored
    } == {
        key: value for key, value in right.items() if key not in ignored
    }


def _department_live_carrier(
    objects: Mapping[tuple[str, str], InvariantObject],
    lead_node_id: str,
) -> InvariantObject | None:
    carriers = [
        item
        for item in _of_type(objects, CARRIER_BINDING_V1)
        if (
            item.payload["actor_id"] == lead_node_id
            and item.payload["state"] in {"active", "parked", "unknown"}
        )
    ]
    if len(carriers) > 1:
        _error("department lead has multiple current carriers")
    return None if not carriers else carriers[0]


def _validate_department_graph(
    objects: Mapping[tuple[str, str], InvariantObject],
) -> None:
    """Keep durable department identity separate from replaceable carriers."""

    identities = {
        str(item.payload["department_id"]): item
        for item in _of_type(objects, DEPARTMENT_IDENTITY_V1)
    }
    snapshots = {
        str(item.payload["department_id"]): item
        for item in _of_type(objects, DEPARTMENT_SNAPSHOT_V1)
    }
    nodes = {
        str(item.payload["node_id"]): item
        for item in _of_type(objects, ORGANIZATION_NODE_V1)
    }
    roots = [
        item
        for item in nodes.values()
        if item.payload["role"] == "chief"
        and item.payload["parent_node_id"] is None
    ]
    root_id = None if len(roots) != 1 else str(roots[0].payload["node_id"])

    for department_id, identity_item in identities.items():
        identity = identity_item.payload
        lead_node_id = identity["lead_node_id"]
        snapshot = snapshots.get(department_id)
        # A newly declared future department may be parked before a lead and
        # first snapshot are assigned.  Once a stable lead exists, both the
        # organization relation and snapshot are mandatory.
        if lead_node_id is None:
            continue
        lead = nodes.get(str(lead_node_id))
        if (
            lead is None
            or lead.payload["department_id"] != department_id
            or lead.payload["delegation_depth"] != 1
            or lead.payload["parent_node_id"] != root_id
            or lead.payload["reports_to_node_id"] != root_id
            or not lead.payload["can_delegate"]
            or snapshot is None
        ):
            _error("department identity, lead, and snapshot graph differ")
        if identity["status"] == "parked" and lead.payload["status"] != "parked":
            _error("parked department requires a parked durable lead")
        if (
            identity["status"] == "active"
            and lead.payload["status"] not in {"active", "idle"}
        ):
            _error("active department requires an active or idle durable lead")
        carrier = _department_live_carrier(objects, str(lead_node_id))
        if (
            identity["status"] == "parked"
            and carrier is not None
            and carrier.payload["state"] in {"active", "unknown"}
        ):
            _error("parked department cannot retain an active or unknown carrier")

    for department_id in snapshots:
        if department_id not in identities:
            _error("department snapshot lacks a durable department identity")


def _department_scope_sha256(
    department_id: str,
    snapshot: InvariantObject,
) -> str:
    return company_contract_sha256({
        "department_id": department_id,
        "snapshot_id": snapshot.payload["snapshot_id"],
        "snapshot_payload_sha256": snapshot.payload_sha256,
    })


def _validate_lifecycle_event(
    item: InvariantObject,
    wrapper: Mapping[str, Any],
    *,
    stream: str,
    event_type: str,
    provenance: str,
    recorded_at: str,
) -> None:
    if (
        wrapper["stream"] != stream
        or wrapper["event_type"] != event_type
        or wrapper["provenance"] != provenance
        or wrapper["recorded_at"] != recorded_at
        or wrapper["payload_sha256"] != item.payload_sha256
        or wrapper["payload"] != item.payload
    ):
        _error(
            f"{item.contract_type} department lifecycle event envelope "
            "is not canonical",
        )


def _department_execution_is_busy(payload: Mapping[str, Any]) -> bool:
    return (
        payload["engineering_status"] in {
            "active", "waiting", "blocked", "unknown",
        }
        or payload["runtime_status"] in _ACTIVE_EXECUTION
    )


def _validate_department_park_preconditions(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    department_id: str,
) -> None:
    dispatches = _of_type(old_objects, DISPATCH_REQUEST_V1)
    if any(
        item.payload["department_id"] == department_id
        and item.payload["state"] in {
            "queued", "admitted", "in_flight", "effect_unknown",
        }
        for item in dispatches
    ):
        _error("department with pending or uncertain dispatch cannot park")
    executions = [
        item
        for item in _of_type(old_objects, EXECUTION_NODE_V1)
        if item.payload["department_id"] == department_id
    ]
    if any(_department_execution_is_busy(item.payload) for item in executions):
        _error("department with active or unknown execution cannot park")
    execution_ids = {
        str(item.payload["execution_id"])
        for item in executions
    }
    if any(
        item.payload["owner_execution_id"] in execution_ids
        and item.payload["state"] not in {
            "completed", "failed_known", "aborted",
        }
        for item in _of_type(old_objects, EXTERNAL_JOB_V1)
    ):
        _error("department with nonterminal external job cannot park")


def _validate_department_lifecycle_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
) -> None:
    lifecycle_intents = [
        item
        for item in batch
        if (
            item.contract_type == CONTROL_INTENT_V1
            and item.payload["request_payload"].get("request_type")
            == "department_lifecycle_request_v1"
        )
    ]
    existing_departments = {
        str(item.payload["department_id"])
        for item in _of_type(old_objects, DEPARTMENT_IDENTITY_V1)
    }
    existing_leads = {
        str(item.payload["lead_node_id"])
        for item in _of_type(old_objects, DEPARTMENT_IDENTITY_V1)
        if item.payload["lead_node_id"] is not None
    }
    mutates_existing_department = any(
        (
            item.contract_type in {
                DEPARTMENT_IDENTITY_V1,
                DEPARTMENT_SNAPSHOT_V1,
            }
            and str(item.payload["department_id"]) in existing_departments
        )
        or (
            item.contract_type == ORGANIZATION_NODE_V1
            and str(item.payload["node_id"]) in existing_leads
        )
        for item in batch
    )
    if not lifecycle_intents:
        if mutates_existing_department:
            _error(
                "existing department lifecycle can change only through "
                "ControlIntent",
            )
        return
    if len(lifecycle_intents) != 1:
        _error("department lifecycle transaction requires one ControlIntent")

    intent_item = lifecycle_intents[0]
    intent = intent_item.payload
    lifecycle_request = intent["request_payload"]
    lifecycle_result = intent["result_payload"]
    operation = str(lifecycle_request["operation"])
    department_id = str(lifecycle_request["department_id"])
    lead_node_id = str(lifecycle_request["lead_node_id"])
    old_identity = old_objects.get(
        (DEPARTMENT_IDENTITY_V1, department_id),
    )
    old_snapshot = old_objects.get(
        (DEPARTMENT_SNAPSHOT_V1, department_id),
    )
    old_lead = old_objects.get((ORGANIZATION_NODE_V1, lead_node_id))
    if old_identity is None or old_snapshot is None or old_lead is None:
        _error("department lifecycle target is not fully durable")
    if (
        old_identity.payload["lead_node_id"] != lead_node_id
        or old_lead.payload["department_id"] != department_id
    ):
        _error("department lifecycle target identity differs")

    expected_head = request["expected_transaction_head"]
    if (
        lifecycle_request["company_id"] != request["company_id"]
        or lifecycle_request["company_incarnation"]
        != request["company_incarnation"]
        or lifecycle_request["lock_domain_generation"]
        != request["lock_domain_generation"]
        or lifecycle_request["expected_global_sequence"]
        != expected_head["global_sequence"]
        or lifecycle_request["expected_transaction_sha256"]
        != expected_head["transaction_sha256"]
        or lifecycle_request["expected_department_status"]
        != old_identity.payload["status"]
        or lifecycle_request["expected_department_payload_sha256"]
        != old_identity.payload_sha256
        or lifecycle_request["expected_lead_status"]
        != old_lead.payload["status"]
        or lifecycle_request["expected_lead_payload_sha256"]
        != old_lead.payload_sha256
        or lifecycle_request["expected_snapshot_id"]
        != old_snapshot.payload["snapshot_id"]
        or lifecycle_request["expected_snapshot_revision"]
        != old_snapshot.payload["revision"]
        or lifecycle_request["expected_snapshot_payload_sha256"]
        != old_snapshot.payload_sha256
        or lifecycle_request["requested_scope_sha256"]
        != _department_scope_sha256(department_id, old_snapshot)
    ):
        _error("department lifecycle expected state differs")

    live_carrier = _department_live_carrier(old_objects, lead_node_id)
    expected_carrier_id = (
        None if live_carrier is None else live_carrier.payload["carrier_id"]
    )
    expected_carrier_sha256 = (
        None if live_carrier is None else live_carrier.payload_sha256
    )
    if (
        lifecycle_request["expected_carrier_id"] != expected_carrier_id
        or lifecycle_request["expected_carrier_payload_sha256"]
        != expected_carrier_sha256
    ):
        _error("department lifecycle current carrier differs")

    try:
        derived_authority = authority_from_grant(intent["authority_grant"])
    except CompanyContractError as exc:
        raise CompanyInvariantError(
            f"department lifecycle authority grant is invalid: {exc}",
        ) from exc
    if (
        intent["command_id"] != request["command_id"]
        or derived_authority != request["actor_authority"]
        or intent["authority_grant_sha256"]
        != intent["authority_grant"]["grant_sha256"]
        or intent["outcome"] != "committed"
        or intent["provenance"] != "AOI_verified"
        or intent["observation"]["state"] != "known"
    ):
        _error("department lifecycle ControlIntent binding differs")

    committed_cursor = int(expected_head["global_sequence"]) + 1
    if (
        lifecycle_result["company_id"] != request["company_id"]
        or lifecycle_result["company_incarnation"]
        != request["company_incarnation"]
        or lifecycle_result["lock_domain_generation"]
        != request["lock_domain_generation"]
        or lifecycle_result["operation"] != operation
        or lifecycle_result["transaction_id"] != request["transaction_id"]
        or lifecycle_result["command_id"] != request["command_id"]
        or lifecycle_result["committed_cursor"] != committed_cursor
        or lifecycle_result["department_id"] != department_id
        or lifecycle_result["lead_node_id"] != lead_node_id
        or lifecycle_result["snapshot_id"]
        != old_snapshot.payload["snapshot_id"]
        and operation != "park"
    ):
        _error("department lifecycle result binding differs")

    event_items = {
        item.event_id: item
        for item in batch
    }
    wrappers = list(request["events"])
    recorded_at_values = {
        str(wrapper["recorded_at"]) for wrapper in wrappers
    }
    if len(recorded_at_values) != 1:
        _error("department lifecycle events require one recorded_at")
    recorded_at = next(iter(recorded_at_values))
    if (
        intent["terminal_at"] != recorded_at
        or intent["created_at"] != lifecycle_request["requested_at"]
    ):
        _error("department lifecycle timestamps differ")

    new_identity = next(
        (
            item for item in batch
            if item.contract_type == DEPARTMENT_IDENTITY_V1
            and item.payload["department_id"] == department_id
        ),
        None,
    )
    new_lead = next(
        (
            item for item in batch
            if item.contract_type == ORGANIZATION_NODE_V1
            and item.payload["node_id"] == lead_node_id
        ),
        None,
    )
    new_snapshot = next(
        (
            item for item in batch
            if item.contract_type == DEPARTMENT_SNAPSHOT_V1
            and item.payload["department_id"] == department_id
        ),
        None,
    )
    dispatch = next(
        (
            item for item in batch
            if item.contract_type == DISPATCH_REQUEST_V1
            and item.payload["department_id"] == department_id
        ),
        None,
    )
    work_binding = next(
        (
            item for item in batch
            if item.contract_type == WORK_DISPATCH_BINDING_V1
            and (
                dispatch is None
                or item.payload["dispatch_request_id"]
                == dispatch.payload["dispatch_request_id"]
            )
        ),
        None,
    )

    if operation == "park":
        _validate_department_park_preconditions(
            old_objects,
            department_id,
        )
        parked_carrier = next(
            (
                item for item in batch
                if item.contract_type == CARRIER_BINDING_V1
                and item.payload["actor_id"] == lead_node_id
            ),
            None,
        )
        expected_types = [
            DEPARTMENT_SNAPSHOT_V1,
            ORGANIZATION_NODE_V1,
            DEPARTMENT_IDENTITY_V1,
        ]
        if parked_carrier is not None:
            expected_types.append(CARRIER_BINDING_V1)
        expected_types.append(CONTROL_INTENT_V1)
        if [item.contract_type for item in batch] != expected_types:
            _error("park transaction event membership or order differs")
        if new_identity is None or new_lead is None or new_snapshot is None:
            _error("park transaction lacks lifecycle records")
        if (
            not _same_payload_except(
                old_identity.payload,
                new_identity.payload,
                "status",
                "observation",
            )
            or new_identity.payload["status"] != "parked"
            or not _same_payload_except(
                old_lead.payload,
                new_lead.payload,
                "status",
                "observation",
            )
            or new_lead.payload["status"] != "parked"
            or new_snapshot.payload["revision"]
            != old_snapshot.payload["revision"] + 1
            or new_snapshot.payload["previous_snapshot_id"]
            != old_snapshot.payload["snapshot_id"]
            or new_snapshot.payload["company_cursor"] != committed_cursor
            or new_snapshot.payload["captured_at"] != recorded_at
        ):
            _error("park lifecycle record revision differs")
        if live_carrier is not None and live_carrier.payload["state"] in {
            "active", "unknown",
        }:
            if parked_carrier is None:
                _error("park must publish the stopped department carrier")
            matching_executions = [
                item
                for item in _of_type(old_objects, EXECUTION_NODE_V1)
                if item.payload["carrier_id"]
                == live_carrier.payload["carrier_id"]
            ]
            if (
                any(
                    item.payload["runtime_status"] in _ACTIVE_EXECUTION
                    for item in matching_executions
                )
                or parked_carrier.payload["carrier_id"]
                != live_carrier.payload["carrier_id"]
                or parked_carrier.payload["state"] != "parked"
                or not _same_payload_except(
                    live_carrier.payload,
                    parked_carrier.payload,
                    "state",
                    "session_id",
                    "session_availability",
                    "last_observed_at",
                    "observation",
                )
            ):
                _error("department carrier cannot be safely parked")
        elif parked_carrier is not None:
            _error("park transaction has an unnecessary carrier revision")
        snapshot_ref = lifecycle_request["snapshot_document"]
        if (
            len(new_snapshot.payload["artifact_refs"]) != 1
            or new_snapshot.payload["artifact_refs"][0] != snapshot_ref
            or snapshot_ref["media_type"]
            != "application/vnd.aoi.department-snapshot+json;version=1"
            or lifecycle_result["lifecycle_state"] != "parked"
            or lifecycle_result["department_status"] != "parked"
            or lifecycle_result["lead_status"] != "parked"
            or lifecycle_result["snapshot_id"]
            != new_snapshot.payload["snapshot_id"]
            or lifecycle_result["snapshot_revision"]
            != new_snapshot.payload["revision"]
            or lifecycle_result["snapshot_payload_sha256"]
            != new_snapshot.payload_sha256
            or lifecycle_result["snapshot_cursor"] != committed_cursor
            or lifecycle_result["carrier_transition"]
            != ("parked" if parked_carrier is not None else "none")
            or lifecycle_result["dispatch_request_id"] is not None
            or lifecycle_result["dispatch_revision"] is not None
            or lifecycle_result["dispatch_state"] is not None
            or lifecycle_result["execution_id"] is not None
            or lifecycle_result["runtime_effect"] != "none"
        ):
            _error("park lifecycle result differs")
        event_specs = [
            ("org", "department.snapshot.recorded", "AOI_verified"),
            ("org", "department.organization.parked", "AOI_verified"),
            ("org", "department.identity.parked", "AOI_verified"),
        ]
        if parked_carrier is not None:
            event_specs.append(
                ("org", "department.carrier.parked", "AOI_verified"),
            )
        event_specs.append(
            (
                "execution",
                "department.park.intent.committed",
                "AOI_verified",
            ),
        )
    else:
        old_is_parked = old_identity.payload["status"] == "parked"
        if operation == "resume" and not old_is_parked:
            _error("resume requires a parked department")
        expected_types = (
            [
                ORGANIZATION_NODE_V1,
                DEPARTMENT_IDENTITY_V1,
                DISPATCH_REQUEST_V1,
            ]
            if old_is_parked
            else [DISPATCH_REQUEST_V1]
        )
        if work_binding is not None:
            expected_types.append(WORK_DISPATCH_BINDING_V1)
        expected_types.append(CONTROL_INTENT_V1)
        if [item.contract_type for item in batch] != expected_types:
            _error("department wake transaction membership or order differs")
        if dispatch is None:
            _error("department wake transaction lacks queued dispatch")
        if old_is_parked:
            if (
                new_identity is None
                or new_lead is None
                or not _same_payload_except(
                    old_identity.payload,
                    new_identity.payload,
                    "status",
                    "observation",
                )
                or new_identity.payload["status"] != "active"
                or not _same_payload_except(
                    old_lead.payload,
                    new_lead.payload,
                    "status",
                    "observation",
                )
                or new_lead.payload["status"] != "active"
            ):
                _error("department wake activation differs")
        elif new_identity is not None or new_lead is not None:
            _error("active department enqueue cannot rewrite lifecycle state")
        current_term = _chief_term(old_objects)
        current_chief_executions = [
            item
            for item in _of_type(old_objects, EXECUTION_NODE_V1)
            if (
                current_term is not None
                and item.payload["role"] == "chief"
                and item.payload["carrier_id"]
                == current_term.payload["carrier_id"]
                and item.payload["runtime_status"] in _ACTIVE_EXECUTION
            )
        ]
        if len(current_chief_executions) != 1:
            _error("department wake requires one current Chief execution")
        chief_execution = current_chief_executions[0]
        if (
            dispatch.payload["revision"] != 1
            or dispatch.payload["state"] != "queued"
            or dispatch.payload["dispatch_request_id"]
            != lifecycle_request["dispatch_request_id"]
            or dispatch.payload["reservation_id"]
            != lifecycle_request["reservation_id"]
            or dispatch.payload["task_id"] != lifecycle_request["task_id"]
            or dispatch.payload["packet_id"] != lifecycle_request["packet_id"]
            or dispatch.payload["route_policy_id"]
            != lifecycle_request["route_policy_id"]
            or dispatch.payload["requested_role"]
            != lifecycle_request["requested_role"]
            or dispatch.payload["requested_capability_tier"]
            != lifecycle_request["requested_capability_tier"]
            or dispatch.payload["scope_sha256"]
            != (
                lifecycle_request["requested_scope_sha256"]
                if work_binding is None
                else work_binding.payload["authority_scope_sha256"]
            )
            or dispatch.payload["manager_node_id"]
            != old_lead.payload["parent_node_id"]
            or dispatch.payload["target_node_id"] != lead_node_id
            or dispatch.payload["department_id"] != department_id
            or dispatch.payload["parent_execution_id"]
            != chief_execution.payload["execution_id"]
            or intent["execution_id"]
            != chief_execution.payload["execution_id"]
            or dispatch.payload["delegation_depth"] != 1
        ):
            _error("department wake dispatch binding differs")
        lifecycle_state = "waking" if old_is_parked else "active"
        if (
            lifecycle_result["lifecycle_state"] != lifecycle_state
            or lifecycle_result["department_status"] != "active"
            or lifecycle_result["lead_status"] != "active"
            or lifecycle_result["snapshot_id"]
            != old_snapshot.payload["snapshot_id"]
            or lifecycle_result["snapshot_revision"]
            != old_snapshot.payload["revision"]
            or lifecycle_result["snapshot_payload_sha256"]
            != old_snapshot.payload_sha256
            or lifecycle_result["snapshot_cursor"]
            != old_snapshot.payload["company_cursor"]
            or lifecycle_result["carrier_transition"] != "pending"
            or lifecycle_result["carrier_id"] != expected_carrier_id
            or lifecycle_result["carrier_state"]
            != (
                None
                if live_carrier is None
                else live_carrier.payload["state"]
            )
            or lifecycle_result["replaced_carrier_id"] is not None
            or lifecycle_result["dispatch_request_id"]
            != dispatch.payload["dispatch_request_id"]
            or lifecycle_result["dispatch_revision"] != 1
            or lifecycle_result["dispatch_state"] != "queued"
            or lifecycle_result["execution_id"] is not None
            or lifecycle_result["runtime_effect"] != "pending_dispatch"
        ):
            _error("department wake result differs")
        event_specs = (
            [
                (
                    "org",
                    "department.organization.activated",
                    "AOI_verified",
                ),
                ("org", "department.identity.activated", "AOI_verified"),
            ]
            if old_is_parked
            else []
        )
        event_specs.extend((
            ("execution", "dispatch.request.queued", "AOI_verified"),
        ))
        if work_binding is not None:
            event_specs.append(
                ("execution", "work.dispatch.bound", "AOI_verified"),
            )
        event_specs.append(
            (
                "execution",
                (
                    "department.resume.intent.committed"
                    if operation == "resume"
                    else "department.dispatch.intent.committed"
                ),
                "AOI_verified",
            ),
        )

    if len(event_specs) != len(wrappers):
        _error("department lifecycle event count differs")
    for item, wrapper, (stream, event_type, provenance) in zip(
        batch,
        wrappers,
        event_specs,
        strict=True,
    ):
        if event_items.get(str(wrapper["event_id"])) != item:
            _error("department lifecycle event order differs")
        _validate_lifecycle_event(
            item,
            wrapper,
            stream=stream,
            event_type=event_type,
            provenance=provenance,
            recorded_at=recorded_at,
        )


def _provider_receipt_event_id(receipt: Mapping[str, Any]) -> str:
    digest = company_contract_sha256({
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "receipt_id": receipt["receipt_id"],
    })
    return f"provider-lifecycle-receipt-{digest}"


def _provider_evidence_event_id(receipt: Mapping[str, Any]) -> str:
    digest = company_contract_sha256({
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "source_event_id": receipt["source_event_id"],
    })
    return f"provider-lifecycle-evidence-{digest}"


def _validate_provider_lifecycle_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
) -> None:
    """Bind provider facts to one raw artifact and the exact lifecycle effect."""

    receipts = [
        item
        for item in batch
        if item.contract_type == PROVIDER_LIFECYCLE_RECEIPT_V1
    ]
    if not receipts:
        return
    if len(receipts) != 1:
        _error("provider lifecycle transaction requires one typed receipt")
    receipt_item = receipts[0]
    receipt = receipt_item.payload
    if (
        receipt["transaction_id"] != request["transaction_id"]
        or receipt["command_id"] != request["command_id"]
        or (
            PROVIDER_LIFECYCLE_RECEIPT_V1,
            str(receipt["receipt_id"]),
        ) in old_objects
        or any(
            item.payload["source_event_id"] == receipt["source_event_id"]
            for item in _of_type(
                old_objects,
                PROVIDER_LIFECYCLE_RECEIPT_V1,
            )
        )
    ):
        _error("provider lifecycle receipt identity is stale or divergent")

    evidence_items = [
        item
        for item in batch
        if (
            item.contract_type == EVIDENCE_RECORD_V1
            and item.payload["claim_id"] == receipt["receipt_id"]
        )
    ]
    if len(evidence_items) != 1:
        _error("provider lifecycle receipt lacks one durable evidence record")
    evidence_item = evidence_items[0]
    evidence = evidence_item.payload
    if (
        (
            EVIDENCE_RECORD_V1,
            str(evidence["evidence_id"]),
        ) in old_objects
        or evidence["execution_id"] != receipt["execution_id"]
        or evidence["evidence_class"] != "runtime"
        or evidence["status"] != "observed"
        or evidence["artifact"] != receipt["raw_artifact"]
        or evidence["command_sha256"] is not None
        or evidence["verification_sha256"] != receipt["receipt_sha256"]
        or evidence["recorded_at"] != receipt["observed_at"]
        or evidence["provenance"] != receipt["provenance"]
        or evidence["observation"] != receipt["observation"]
    ):
        _error("provider lifecycle evidence binding differs")

    wrappers = {
        str(wrapper["event_id"]): wrapper
        for wrapper in request["events"]
    }
    receipt_wrapper = wrappers.get(receipt_item.event_id)
    evidence_wrapper = wrappers.get(evidence_item.event_id)
    if (
        receipt_item.event_id != _provider_receipt_event_id(receipt)
        or evidence_item.event_id != _provider_evidence_event_id(receipt)
        or receipt_wrapper is None
        or evidence_wrapper is None
    ):
        _error("provider lifecycle evidence event identity differs")
    _validate_lifecycle_event(
        receipt_item,
        receipt_wrapper,
        stream="evidence",
        event_type=f"provider.lifecycle.{receipt['event_kind']}",
        provenance=str(receipt["provenance"]),
        recorded_at=str(receipt["observed_at"]),
    )
    _validate_lifecycle_event(
        evidence_item,
        evidence_wrapper,
        stream="evidence",
        event_type="evidence.provider_lifecycle.observed",
        provenance=str(receipt["provenance"]),
        recorded_at=str(receipt["observed_at"]),
    )

    if receipt["event_kind"] != "execution_stopped":
        expected_state = {
            "dispatch_succeeded": "dispatched",
            "dispatch_failed": "failed_known",
            "dispatch_effect_unknown": "effect_unknown",
        }[str(receipt["event_kind"])]
        matching_dispatches = [
            item
            for item in batch
            if (
                item.contract_type == DISPATCH_REQUEST_V1
                and item.payload["dispatch_request_id"]
                == receipt["dispatch_request_id"]
            )
        ]
        if len(matching_dispatches) != 1:
            _error("provider lifecycle receipt lacks one dispatch revision")
        dispatch = matching_dispatches[0].payload
        if (
            dispatch["state"] != expected_state
            or dispatch["revision"] != receipt["dispatch_revision"]
            or dispatch["dispatch_revision_id"]
            != receipt["dispatch_revision_id"]
            or dispatch["target_node_id"] != receipt["organization_node_id"]
            or dispatch["effect_evidence"] != [receipt["raw_artifact"]]
            or dispatch["reconcile_ref"] != receipt["reconcile_ref"]
            or dispatch["provenance"] != receipt["provenance"]
            or dispatch["observation"] != receipt["observation"]
            or (
                expected_state == "dispatched"
                and (
                    dispatch["provider_dispatch_id"]
                    != receipt["provider_dispatch_id"]
                    or dispatch["execution_id"] != receipt["execution_id"]
                )
            )
        ):
            _error("provider lifecycle dispatch binding differs")
        return

    old_dispatches = [
        item
        for item in _of_type(old_objects, DISPATCH_REQUEST_V1)
        if item.payload["dispatch_request_id"] == receipt["dispatch_request_id"]
    ]
    old_executions = [
        item
        for item in _of_type(old_objects, EXECUTION_NODE_V1)
        if item.payload["execution_id"] == receipt["execution_id"]
    ]
    current_executions = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload["execution_id"] == receipt["execution_id"]
        )
    ]
    if len(old_executions) != 1 or len(current_executions) != 1:
        _error("provider stop receipt lifecycle ancestry is incomplete")
    old_execution = old_executions[0].payload
    carriers = [
        item
        for item in _of_type(old_objects, CARRIER_BINDING_V1)
        if item.payload["carrier_id"] == receipt["carrier_id"]
    ]
    if len(carriers) != 1:
        _error("provider stop receipt carrier is missing")
    carrier = carriers[0].payload
    if receipt["dispatch_request_id"] is None:
        if (
            receipt["dispatch_revision"] is not None
            or receipt["dispatch_revision_id"] is not None
            or receipt["provider_dispatch_id"] is not None
            or old_dispatches
            or old_execution["execution_kind"] != "carrier"
            or old_execution["role"] != "chief"
            or old_execution["department_id"] is not None
            or old_execution["parent_execution_id"] is not None
            or old_execution["dispatch_id"] is not None
            or old_execution["organization_node_id"]
            != receipt["organization_node_id"]
            or old_execution["carrier_id"] != receipt["carrier_id"]
            or old_execution["provider"] != receipt["provider"]
            or old_execution["model"] != receipt["model"]
            or old_execution["effort"] != receipt["effort"]
            or old_execution["thread_id"] != receipt["thread_id"]
            or carrier["provider"] != receipt["provider"]
            or carrier["model"] != receipt["model"]
            or carrier["session_id"] != receipt["session_id"]
        ):
            _error("provider root stop receipt runtime binding differs")
        return
    if len(old_dispatches) != 1:
        _error("provider stop receipt dispatch ancestry is incomplete")
    dispatch = old_dispatches[0].payload
    if (
        dispatch["state"] != "dispatched"
        or dispatch["revision"] != receipt["dispatch_revision"]
        or dispatch["dispatch_revision_id"]
        != receipt["dispatch_revision_id"]
        or dispatch["provider_dispatch_id"] != receipt["provider_dispatch_id"]
        or dispatch["execution_id"] != receipt["execution_id"]
        or dispatch["target_node_id"] != receipt["organization_node_id"]
        or old_execution["dispatch_id"] != receipt["dispatch_request_id"]
        or old_execution["organization_node_id"]
        != receipt["organization_node_id"]
        or old_execution["carrier_id"] != receipt["carrier_id"]
        or old_execution["provider"] != receipt["provider"]
        or old_execution["model"] != receipt["model"]
        or old_execution["effort"] != receipt["effort"]
        or old_execution["thread_id"] != receipt["thread_id"]
        or carrier["provider"] != receipt["provider"]
        or carrier["model"] != receipt["model"]
        or carrier["session_id"] != receipt["session_id"]
    ):
        _error("provider stop receipt runtime binding differs")


def _telemetry_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "company_id": value["company_id"],
        "company_incarnation": value["company_incarnation"],
        "lock_domain_generation": value["lock_domain_generation"],
    }


def _expected_telemetry_coverage(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    receipt: Mapping[str, Any],
    *,
    surface: str,
    state: str,
    reason: str,
    dropped: Mapping[str, Any],
) -> dict[str, Any]:
    binding = _telemetry_binding(receipt)
    scope_id = telemetry_id(
        binding,
        "coverage-scope",
        str(receipt["provider"]),
        str(receipt["source_class"]),
        str(receipt["adapter_instance_id"]),
        surface,
    )
    prior_item = old_objects.get((
        PROVIDER_COVERAGE_REVISION_V1,
        scope_id,
    ))
    prior = None if prior_item is None else prior_item.payload
    if (
        prior is not None
        and _parsed_time(str(receipt["received_at"]))
        <= _parsed_time(str(prior["assessed_at"]))
    ):
        _error("provider telemetry coverage time does not advance")
    revision = 1 if prior is None else int(prior["revision"]) + 1
    gap_started_at = (
        None
        if state in {"observed", "unavailable", "unknown"}
        else (
            prior["gap_started_at"]
            if prior is not None and prior["gap_started_at"] is not None
            else receipt["received_at"]
        )
    )
    observation = (
        {"state": "known", "reason": "observed"}
        if state in {"observed", "degraded"}
        else {"state": state, "reason": reason}
    )
    return {
        "coverage_scope_id": scope_id,
        "coverage_surface": surface,
        "revision_id": telemetry_id(
            binding,
            "coverage-revision",
            scope_id,
            str(revision),
        ),
        "revision": revision,
        "previous_revision_sha256": (
            ZERO_SHA256
            if prior is None
            else prior["coverage_sha256"]
        ),
        "provider": receipt["provider"],
        "adapter_instance_id": receipt["adapter_instance_id"],
        "source_class": receipt["source_class"],
        "declared_event_kinds": coverage_event_kinds(
            str(receipt["provider"]),
            str(receipt["source_class"]),
            surface,
        ),
        "state": state,
        "reason": reason,
        "assessment_source": "receipt",
        "last_receipt_id": receipt["receipt_id"],
        "last_received_at": receipt["received_at"],
        "gap_started_at": gap_started_at,
        "dropped_event_count": dropped,
        "assessed_at": receipt["received_at"],
        "observation": observation,
    }


def _validate_telemetry_coverage_payload(
    actual: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> None:
    if any(actual[key] != expected[key] for key in expected):
        _error("provider telemetry coverage revision differs")


def _validate_explicit_telemetry_coverage_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    """Seal coverage-only revision adjacency and its canonical event envelope."""

    coverage_items = [
        item
        for item in batch
        if item.contract_type == PROVIDER_COVERAGE_REVISION_V1
    ]
    if not coverage_items:
        return
    if (
        len(coverage_items) != 1
        or len(batch) != 1
        or len(request["events"]) != 1
        or receipt_state != "committed"
    ):
        _error("explicit provider coverage transaction membership differs")
    item = coverage_items[0]
    coverage = item.payload
    binding = _telemetry_binding(coverage)
    expected_scope_id = telemetry_id(
        binding,
        "coverage-scope",
        str(coverage["provider"]),
        str(coverage["source_class"]),
        str(coverage["adapter_instance_id"]),
        str(coverage["coverage_surface"]),
    )
    prior_item = old_objects.get((
        PROVIDER_COVERAGE_REVISION_V1,
        expected_scope_id,
    ))
    prior = None if prior_item is None else prior_item.payload
    expected_revision = 1 if prior is None else int(prior["revision"]) + 1
    expected_previous = (
        ZERO_SHA256
        if prior is None
        else str(prior["coverage_sha256"])
    )
    expected_revision_id = telemetry_id(
        binding,
        "coverage-revision",
        expected_scope_id,
        str(expected_revision),
    )
    if (
        coverage["coverage_scope_id"] != expected_scope_id
        or coverage["revision"] != expected_revision
        or coverage["previous_revision_sha256"] != expected_previous
        or coverage["revision_id"] != expected_revision_id
        or (
            prior is not None
            and _parsed_time(str(coverage["assessed_at"]))
            <= _parsed_time(str(prior["assessed_at"]))
        )
    ):
        _error("explicit provider coverage revision chain differs")

    last_receipt_id = coverage["last_receipt_id"]
    if last_receipt_id is not None:
        receipt_item = old_objects.get((
            PROVIDER_TELEMETRY_RECEIPT_V1,
            str(last_receipt_id),
        ))
        if receipt_item is None:
            _error("explicit provider coverage receipt is not durable")
        receipt = receipt_item.payload
        if (
            receipt["provider"] != coverage["provider"]
            or receipt["source_class"] != coverage["source_class"]
            or receipt["adapter_instance_id"]
            != coverage["adapter_instance_id"]
            or receipt["received_at"] != coverage["last_received_at"]
        ):
            _error("explicit provider coverage receipt binding differs")
    if coverage["state"] == "observed":
        matching_receipts = [
            candidate.payload
            for candidate in _of_type(
                old_objects,
                PROVIDER_TELEMETRY_RECEIPT_V1,
            )
            if (
                candidate.payload["provider"] == coverage["provider"]
                and candidate.payload["source_class"]
                == coverage["source_class"]
                and candidate.payload["adapter_instance_id"]
                == coverage["adapter_instance_id"]
            )
        ]
        latest_receipt = max(
            matching_receipts,
            key=lambda value: (
                _parsed_time(str(value["received_at"])),
                str(value["receipt_id"]),
            ),
            default=None,
        )
        if latest_receipt is None or last_receipt_id is None:
            _error(
                "explicit observed provider coverage lacks a durable receipt",
            )
        if (
            last_receipt_id != latest_receipt["receipt_id"]
            or coverage["last_received_at"]
            != latest_receipt["received_at"]
        ):
            _error("explicit provider coverage receipt is not latest")
    elif last_receipt_id is not None:
        _error("explicit non-observed provider coverage has a receipt")

    expected_event_id = telemetry_id(
        binding,
        "coverage-event",
        str(request["transaction_id"]),
        str(coverage["coverage_surface"]),
    )
    wrapper = request["events"][0]
    if (
        item.event_id != expected_event_id
        or wrapper["event_id"] != expected_event_id
    ):
        _error("explicit provider coverage event identity differs")
    _validate_lifecycle_event(
        item,
        wrapper,
        stream="evidence",
        event_type="provider.coverage.explicit",
        provenance="AOI_verified",
        recorded_at=str(coverage["assessed_at"]),
    )


def _validate_provider_telemetry_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    """Re-derive provider attribution and coverage at the historical cursor."""

    receipt_items = [
        item
        for item in batch
        if item.contract_type == PROVIDER_TELEMETRY_RECEIPT_V1
    ]
    if not receipt_items:
        if any(
            item.contract_type == USAGE_COUNTER_SAMPLE_V1
            for item in batch
        ):
            _error(
                "usage counter sample requires a same-transaction "
                "provider telemetry receipt",
            )
        _validate_explicit_telemetry_coverage_transition(
            old_objects,
            batch,
            request,
            receipt_state,
        )
        return
    if len(receipt_items) != 1 or receipt_state != "committed":
        _error("provider telemetry requires one committed typed receipt")
    receipt_item = receipt_items[0]
    receipt = receipt_item.payload
    binding = _telemetry_binding(receipt)
    if (
        receipt["transaction_id"] != request["transaction_id"]
        or receipt["command_id"] != request["command_id"]
        or receipt["receipt_id"]
        != telemetry_id(
            binding,
            "receipt",
            str(receipt["adapter_instance_id"]),
            str(receipt["adapter_event_id"]),
        )
        or (
            PROVIDER_TELEMETRY_RECEIPT_V1,
            str(receipt["receipt_id"]),
        )
        in old_objects
    ):
        _error("provider telemetry receipt identity differs")
    prior_receipts = _of_type(
        old_objects,
        PROVIDER_TELEMETRY_RECEIPT_V1,
    )
    if any(
        prior.payload["adapter_instance_id"]
        == receipt["adapter_instance_id"]
        and prior.payload["adapter_event_id"]
        == receipt["adapter_event_id"]
        for prior in prior_receipts
    ):
        _error("provider telemetry adapter occurrence was reused")
    registry_cursor = int(
        request["expected_transaction_head"]["global_sequence"],
    )
    try:
        expected_join = exact_provider_telemetry_join(
            provider=str(receipt["provider"]),
            facts=receipt["facts"],
            executions=[
                item.payload
                for item in _of_type(old_objects, EXECUTION_NODE_V1)
            ],
            dispatches=[
                item.payload
                for item in _of_type(old_objects, DISPATCH_REQUEST_V1)
            ],
            registry_cursor=registry_cursor,
        )
    except TelemetryPolicyError as exc:
        raise CompanyInvariantError(str(exc)) from exc
    if receipt["dispatch_join"] != expected_join:
        _error("provider telemetry dispatch join differs from registry")

    matching_adapter_receipts = [
        prior.payload
        for prior in prior_receipts
        if (
            prior.payload["provider"] == receipt["provider"]
            and prior.payload["source_class"] == receipt["source_class"]
            and prior.payload["adapter_instance_id"]
            == receipt["adapter_instance_id"]
        )
    ]
    prior_sequence = max(
        (
            int(value["intake_sequence"])
            for value in matching_adapter_receipts
        ),
        default=None,
    )
    lifecycle_scope_id = telemetry_id(
        binding,
        "coverage-scope",
        str(receipt["provider"]),
        str(receipt["source_class"]),
        str(receipt["adapter_instance_id"]),
        "lifecycle",
    )
    prior_lifecycle_item = old_objects.get((
        PROVIDER_COVERAGE_REVISION_V1,
        lifecycle_scope_id,
    ))
    prior_lifecycle = (
        None
        if prior_lifecycle_item is None
        else prior_lifecycle_item.payload
    )
    lifecycle_state, lifecycle_reason, lifecycle_drop = (
        automatic_coverage_state(
            str(receipt["parse_outcome"]),
            prior_sequence,
            int(receipt["intake_sequence"]),
            prior=prior_lifecycle,
        )
    )
    if (
        receipt["parse_outcome"] == "normalized"
        and receipt["dispatch_join"]["state"] != "exact"
        and lifecycle_state == "observed"
    ):
        lifecycle_state = "degraded"
        lifecycle_reason = (
            "provider_telemetry_unattributed"
            if receipt["dispatch_join"]["state"] == "none"
            else "provider_telemetry_attribution_ambiguous"
        )
        lifecycle_drop = unknown_drop(lifecycle_reason)

    coverage_items = [
        item
        for item in batch
        if item.contract_type == PROVIDER_COVERAGE_REVISION_V1
    ]
    lifecycle_items = [
        item
        for item in coverage_items
        if item.payload["coverage_surface"] == "lifecycle"
    ]
    usage_coverage_items = [
        item
        for item in coverage_items
        if item.payload["coverage_surface"] == "usage"
    ]
    sample_items = [
        item
        for item in batch
        if item.contract_type == USAGE_COUNTER_SAMPLE_V1
    ]
    if len(lifecycle_items) != 1 or len(sample_items) > 1:
        _error("provider telemetry transaction membership differs")
    _validate_telemetry_coverage_payload(
        lifecycle_items[0].payload,
        _expected_telemetry_coverage(
            old_objects,
            receipt,
            surface="lifecycle",
            state=lifecycle_state,
            reason=lifecycle_reason,
            dropped=lifecycle_drop,
        ),
    )

    usage_required = bool(sample_items) or receipt["provider"] == "claude"
    if len(usage_coverage_items) != int(usage_required):
        _error("provider telemetry usage coverage membership differs")
    if sample_items:
        sample = sample_items[0].payload
        facts = receipt["facts"]
        expected_provenance_facts = {
            name: facts[name]
            for name in (
                "actual_provider",
                "actual_model",
                "actual_effort",
                "actual_role",
                "routing",
            )
        }
        if (
            receipt["provider"] != "codex"
            or facts["thread_id"]["quality"] != "observed"
            or facts["turn_id"]["quality"] != "observed"
            or sample["sample_id"]
            != telemetry_id(
                binding,
                "usage-sample",
                str(receipt["adapter_instance_id"]),
                str(receipt["adapter_event_id"]),
            )
            or sample["telemetry_receipt_id"] != receipt["receipt_id"]
            or sample["telemetry_receipt_sha256"]
            != receipt["receipt_sha256"]
            or sample["thread_id"] != facts["thread_id"]["value"]
            or sample["turn_id"] != facts["turn_id"]["value"]
            or sample["counter_scope_id"] != facts["thread_id"]["value"]
            or sample["provider_sequence"] is not None
            or sample["provenance_facts"] != expected_provenance_facts
            or any(
                sample[left] != receipt[right]
                for left, right in (
                    ("adapter_instance_id", "adapter_instance_id"),
                    ("adapter_event_id", "adapter_event_id"),
                    ("intake_sequence", "intake_sequence"),
                    ("provider", "provider"),
                    ("received_at", "received_at"),
                    ("raw_artifact", "raw_artifact"),
                    ("provenance", "provenance"),
                    ("observation", "observation"),
                )
            )
        ):
            _error("provider telemetry usage sample binding differs")
    if usage_required:
        if sample_items:
            usage_state = lifecycle_state
            usage_reason = lifecycle_reason
            usage_drop = lifecycle_drop
        else:
            usage_state = "unavailable"
            usage_reason = "provider_usage_unavailable"
            usage_drop = unknown_drop(usage_reason)
        _validate_telemetry_coverage_payload(
            usage_coverage_items[0].payload,
            _expected_telemetry_coverage(
                old_objects,
                receipt,
                surface="usage",
                state=usage_state,
                reason=usage_reason,
                dropped=usage_drop,
            ),
        )

    ordered: list[tuple[InvariantObject, str, str]] = [
        (
            receipt_item,
            "evidence",
            "provider.telemetry.received",
        ),
        (
            lifecycle_items[0],
            "evidence",
            "provider.coverage.lifecycle",
        ),
    ]
    if sample_items:
        ordered.append((
            sample_items[0],
            "usage",
            "usage.counter.observed",
        ))
    if usage_required:
        ordered.append((
            usage_coverage_items[0],
            "evidence",
            "provider.coverage.usage",
        ))
    wrappers = list(request["events"])
    expected_event_ids = [
        telemetry_id(
            binding,
            "event",
            str(request["transaction_id"]),
            str(index),
        )
        for index in range(1, len(ordered) + 1)
    ]
    if (
        len(wrappers) != len(ordered)
        or expected_event_ids
        != [str(wrapper["event_id"]) for wrapper in wrappers]
        or [item.event_id for item, _stream, _event_type in ordered]
        != expected_event_ids
    ):
        _error("provider telemetry event envelope membership differs")
    for (item, stream, event_type), wrapper in zip(
        ordered,
        wrappers,
        strict=True,
    ):
        _validate_lifecycle_event(
            item,
            wrapper,
            stream=stream,
            event_type=event_type,
            provenance="adapter_receipt_persisted",
            recorded_at=str(receipt["received_at"]),
        )


def _validate_runtime_observation_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    """Observation is nonterminal engineering evidence, never a stop shortcut."""
    receipts = [item for item in batch if item.contract_type == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1]
    if not receipts:
        return
    if len(receipts) != 1 or receipt_state != "committed":
        _error("runtime observation requires one committed typed receipt")
    receipt = receipts[0].payload
    if receipt["transaction_id"] != request["transaction_id"] or receipt["command_id"] != request["command_id"]:
        _error("runtime observation receipt differs from transaction")
    if (
        (
            EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
            str(receipt["receipt_id"]),
        )
        in old_objects
        or any(
            item.payload["source_event_id"] == receipt["source_event_id"]
            for item in _of_type(
                old_objects,
                EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
            )
        )
    ):
        _error("runtime observation receipt identity is stale or divergent")
    old = old_objects.get((EXECUTION_NODE_V1, str(receipt["execution_id"])))
    current_items = [item for item in batch if item.contract_type == EXECUTION_NODE_V1 and item.payload["execution_id"] == receipt["execution_id"]]
    if old is None or len(current_items) != 1:
        _error("runtime observation requires one existing execution revision")
    before, after = old.payload, current_items[0].payload
    if before["carrier_id"] != receipt["carrier_id"] or after["carrier_id"] != receipt["carrier_id"] or before["engineering_status"] != after["engineering_status"] or after["engineering_status"] in {"completed", "cancelled"}:
        _error("runtime observation cannot change engineering state or carrier")
    if not _same_payload_except(before, after, "runtime_status", "updated_at", "last_event_at", "heartbeat_at", "evidence_ids", "provenance", "observation"):
        _error("runtime observation rewrites execution identity")
    evidence = [item for item in batch if item.contract_type == EVIDENCE_RECORD_V1 and item.payload["claim_id"] == receipt["receipt_id"]]
    if len(evidence) != 1 or evidence[0].payload["execution_id"] != receipt["execution_id"] or evidence[0].payload["artifact"] != receipt["raw_artifact"] or evidence[0].payload["verification_sha256"] != receipt["receipt_sha256"]:
        _error("runtime observation evidence binding differs")
    transition = receipt["transition"]
    allowed = {
        "telemetry_silent": ({"running", "unknown"}, "telemetry_silent"),
        "recovered": ({"telemetry_silent"}, "running"),
        "confirmed_lost": ({"telemetry_silent"}, "confirmed_lost"),
    }
    valid_before, expected_after = allowed[transition]
    if before["runtime_status"] not in valid_before or after["runtime_status"] != expected_after or after["receipt_id"] != before["receipt_id"] or after["evidence_ids"] != [*before["evidence_ids"], evidence[0].payload["evidence_id"]] or after["updated_at"] != receipt["observed_at"] or after["last_event_at"] != receipt["observed_at"]:
        _error("runtime observation transition differs")
    if transition == "confirmed_lost":
        if (
            after["provenance"] != "AOI_verified"
            or after["observation"] != receipt["observation"]
            or after["heartbeat_at"] != before["heartbeat_at"]
        ):
            _error("confirmed loss node observation differs")
    elif (
        after["provenance"] != before["provenance"]
        or after["observation"] != before["observation"]
    ):
        _error("silent/recovered runtime rewrites provider observation")
    if transition == "recovered":
        provider_receipt = old_objects.get((
            PROVIDER_TELEMETRY_RECEIPT_V1,
            str(receipt["source_event_id"]),
        ))
        if provider_receipt is None:
            _error("runtime recovery lacks one durable provider receipt")
        telemetry = provider_receipt.payload
        join = telemetry["dispatch_join"]
        relation = telemetry["provider_native_relation"]
        activity_kind = receipt["activity_kind"]
        activity_matches = (
            activity_kind == "codex.item_started"
            and telemetry["provider"] == "codex"
            and telemetry["normalized_kind"]
            == "item_started_runtime_observed"
        ) or (
            activity_kind == "codex.subagent_activity"
            and telemetry["provider"] == "codex"
            and telemetry["normalized_kind"]
            in {
                "item_started_runtime_observed",
                "item_completed_runtime_observed",
            }
            and relation["kind"] == "subagent_activity"
        ) or (
            activity_kind == "claude.subagent_started"
            and telemetry["provider"] == "claude"
            and telemetry["normalized_kind"]
            == "subagent_start_runtime_observed"
        )
        if (
            not activity_matches
            or telemetry["provider"] != before["provider"]
            or join["state"] != "exact"
            or join["execution_id"] != receipt["execution_id"]
            or join["carrier_id"] != receipt["carrier_id"]
            or _parsed_time(str(telemetry["received_at"]))
            <= _parsed_time(str(before["updated_at"]))
            or _parsed_time(str(telemetry["received_at"]))
            > _parsed_time(str(receipt["observed_at"]))
        ):
            _error("runtime recovery provider receipt binding differs")
        if after["heartbeat_at"] != telemetry["received_at"]:
            _error("runtime recovery heartbeat differs from provider receipt")
    elif after["heartbeat_at"] != before["heartbeat_at"]:
        _error("non-recovery runtime observation rewrites heartbeat")
    if after["attention_overlays"] != before["attention_overlays"]:
        _error("runtime observation cannot infer an SLA attention overlay")
    alerts = [
        item for item in batch
        if item.contract_type == ALERT_V1
    ]
    if transition == "confirmed_lost":
        if (
            len(alerts) != 1
            or alerts[0].payload["execution_id"] != receipt["execution_id"]
            or alerts[0].payload["severity"] != "critical"
            or alerts[0].payload["state"] != "open"
            or alerts[0].payload["category"] != "confirmed_lost"
            or alerts[0].payload["created_at"] != receipt["observed_at"]
            or alerts[0].payload["detail_sha256"]
            != receipt["receipt_sha256"]
            or alerts[0].payload["observation"] != receipt["observation"]
        ):
            _error("confirmed loss requires one bound critical alert")
    elif alerts:
        _error("non-loss runtime observation cannot append an alert")
    carriers = [item for item in batch if item.contract_type == CARRIER_BINDING_V1 and item.payload["carrier_id"] == receipt["carrier_id"]]
    if transition != "confirmed_lost":
        if carriers:
            _error("only confirmed loss may revise carrier availability")
    else:
        siblings = [item.payload for item in old_objects.values() if item.contract_type == EXECUTION_NODE_V1 and item.payload["carrier_id"] == receipt["carrier_id"] and item.payload["execution_id"] != receipt["execution_id"] and item.payload["runtime_status"] in _ACTIVE_EXECUTION]
        if siblings:
            if carriers:
                _error("shared carrier remains occupied after one execution loss")
        elif len(carriers) != 1 or carriers[0].payload["state"] != "lost" or carriers[0].payload["session_availability"] != "unavailable":
            _error("last lost carrier execution requires lost unavailable carrier")

    wrappers = list(request["events"])
    expected: list[tuple[InvariantObject, str, str]] = [
        (
            receipts[0],
            "evidence",
            f"runtime.observation.{transition}",
        ),
        (
            evidence[0],
            "evidence",
            "evidence.runtime_observation.observed",
        ),
    ]
    if transition == "confirmed_lost":
        expected.append((
            alerts[0],
            "alert",
            "alert.execution.confirmed_lost",
        ))
        if carriers:
            expected.append((
                carriers[0],
                "org",
                "carrier.runtime.confirmed_lost",
            ))
    expected.append((
        current_items[0],
        "execution",
        f"execution.runtime.{transition}",
    ))
    if (
        len(wrappers) != len(expected)
        or [item.event_id for item, _stream, _event_type in expected]
        != [str(wrapper["event_id"]) for wrapper in wrappers]
    ):
        _error("runtime observation transaction membership differs")
    for (item, stream, event_type), wrapper in zip(
        expected,
        wrappers,
        strict=True,
    ):
        _validate_lifecycle_event(
            item,
            wrapper,
            stream=stream,
            event_type=event_type,
            provenance="AOI_verified",
            recorded_at=str(receipt["observed_at"]),
        )


def _validate_department_dispatch_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    dispatches = [
        item
        for item in batch
        if (
            item.contract_type == DISPATCH_REQUEST_V1
            and item.payload["department_id"] is not None
        )
    ]
    lifecycle_intents = [
        item
        for item in batch
        if (
            item.contract_type == CONTROL_INTENT_V1
            and item.payload["request_payload"].get("request_type")
            == "department_lifecycle_request_v1"
        )
    ]
    revision_one = [
        item for item in dispatches if item.payload["revision"] == 1
    ]
    if revision_one:
        if len(dispatches) != 1 or len(lifecycle_intents) != 1:
            _error(
                "new department dispatch requires one lifecycle ControlIntent",
            )
        return
    if not dispatches:
        return
    if len(dispatches) != 1 or lifecycle_intents:
        _error(
            "automatic department dispatch transaction membership differs",
        )
    dispatch_item = dispatches[0]
    dispatch = dispatch_item.payload
    state = str(dispatch["state"])
    expected_receipt = (
        "effect_unknown" if state == "effect_unknown" else "committed"
    )
    if (
        state not in {
            "admitted",
            "in_flight",
            "failed_known",
            "effect_unknown",
            "dispatched",
        }
        or receipt_state != expected_receipt
    ):
        _error("automatic department dispatch receipt or state differs")
    wrappers = list(request["events"])
    events_by_id = {
        str(wrapper["event_id"]): wrapper for wrapper in wrappers
    }
    recorded_at_values = {
        str(wrapper["recorded_at"]) for wrapper in wrappers
    }
    if len(recorded_at_values) != 1:
        _error("automatic department dispatch timestamps differ")
    recorded_at = next(iter(recorded_at_values))
    if dispatch["updated_at"] != recorded_at:
        _error("automatic department dispatch payload timestamp differs")
    expected_provenance = (
        "AOI_verified"
        if state in {"admitted", "in_flight"}
        else str(dispatch["provenance"])
    )
    if (
        state in {"failed_known", "effect_unknown", "dispatched"}
        and expected_provenance not in _PROVIDER_OBSERVATION_PROVENANCE
    ):
        _error("automatic department dispatch provenance is not provider grade")
    provider_receipts = [
        item
        for item in batch
        if item.contract_type == PROVIDER_LIFECYCLE_RECEIPT_V1
    ]
    provider_evidence = [
        item
        for item in batch
        if (
            item.contract_type == EVIDENCE_RECORD_V1
            and item.payload["status"] == "observed"
        )
    ]
    terminal_provider_state = state in {
        "failed_known",
        "effect_unknown",
        "dispatched",
    }
    if terminal_provider_state:
        if len(provider_receipts) != 1 or len(provider_evidence) != 1:
            _error("terminal department dispatch lacks typed provider evidence")
    elif provider_receipts or provider_evidence:
        _error("local dispatch transition cannot assert provider evidence")

    if state != "dispatched":
        provider_start_operations = [
            item for item in batch
            if (
                item.contract_type == PROVIDER_WORKER_OPERATION_V1
                and item.payload["state"] == "effect_pending"
                and item.payload["operation_kind"] == "process_start"
            )
        ]
        provider_start_receipts = [
            item for item in batch
            if (
                item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1
                and item.payload["phase"] == "process_start_pending"
            )
        ]
        provider_start_membership = (
            state == "in_flight"
            and len(batch) == 3
            and len(provider_start_operations) == 1
            and len(provider_start_receipts) == 1
            and provider_start_receipts[0].payload["operation_id"]
            == provider_start_operations[0].payload["operation_id"]
            and provider_start_receipts[0].payload["receipt_id"]
            in provider_start_operations[0].payload["effect_receipt_ids"]
            and provider_start_operations[0].payload["dispatch_request_id"]
            == dispatch["dispatch_request_id"]
        )
        if state == "in_flight" and not provider_start_membership and any(
            item.contract_type == PROVIDER_LAUNCH_BINDING_V1
            and item.payload["dispatch_request_id"]
            == dispatch["dispatch_request_id"]
            for item in (*old_objects.values(), *batch)
        ):
            _error(
                "provider-bound department dispatch requires atomic process start",
            )
        expected_batch_size = 3 if terminal_provider_state else 1
        if len(batch) != expected_batch_size and not provider_start_membership:
            _error(
                "non-success department dispatch cannot create runtime objects",
            )
        wrapper = events_by_id.get(dispatch_item.event_id)
        if wrapper is None:
            _error("automatic department dispatch event is missing")
        _validate_lifecycle_event(
            dispatch_item,
            wrapper,
            stream="execution",
            event_type=f"dispatch.request.{state}",
            provenance=expected_provenance,
            recorded_at=recorded_at,
        )
        if terminal_provider_state and [
            item.event_id for item in (
                provider_receipts[0],
                provider_evidence[0],
                dispatch_item,
            )
        ] != [str(wrapper["event_id"]) for wrapper in wrappers]:
            _error("terminal provider dispatch event order differs")
        return

    active_carriers = [
        item
        for item in batch
        if (
            item.contract_type == CARRIER_BINDING_V1
            and item.payload["state"] == "active"
            and item.payload["actor_id"] == dispatch["target_node_id"]
        )
    ]
    executions = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload["execution_id"] == dispatch["execution_id"]
        )
    ]
    fences = [
        item
        for item in batch
        if (
            item.contract_type == CARRIER_BINDING_V1
            and item.payload["state"] == "fenced"
            and item.payload["actor_id"] == dispatch["target_node_id"]
        )
    ]
    if (
        len(active_carriers) != 1
        or len(executions) != 1
        or len(fences) > 1
        or len(batch) != 5 + len(fences)
    ):
        _error("known department dispatch success membership differs")
    carrier = active_carriers[0]
    execution = executions[0]
    receipt = provider_receipts[0].payload
    evidence = provider_evidence[0].payload
    if (
        carrier.payload["carrier_id"] != execution.payload["carrier_id"]
        or carrier.payload["provider"] != execution.payload["provider"]
        or carrier.payload["model"] != execution.payload["model"]
        or carrier.payload["provider"] == "unknown"
        or carrier.payload["session_id"] is None
        or carrier.payload["session_availability"] != "available"
        or carrier.payload["last_observed_at"] != recorded_at
        or carrier.payload["observation"]["state"] != "known"
        or execution.payload["created_at"] != recorded_at
        or execution.payload["updated_at"] != recorded_at
        or execution.payload["last_event_at"] != recorded_at
        or execution.payload["heartbeat_at"] != recorded_at
        or receipt["event_kind"] != "dispatch_succeeded"
        or receipt["dispatch_revision_id"]
        != dispatch["dispatch_revision_id"]
        or receipt["carrier_id"] != carrier.payload["carrier_id"]
        or receipt["organization_node_id"] != carrier.payload["actor_id"]
        or receipt["provider"] != carrier.payload["provider"]
        or receipt["model"] != carrier.payload["model"]
        or receipt["session_id"] != carrier.payload["session_id"]
        or receipt["thread_id"] != execution.payload["thread_id"]
        or receipt["effort"] != execution.payload["effort"]
        or execution.payload["receipt_id"] != receipt["receipt_id"]
        or execution.payload["evidence_ids"] != [evidence["evidence_id"]]
    ):
        _error("known department dispatch carrier or execution differs")
    old_carrier = _department_live_carrier(
        old_objects,
        str(dispatch["target_node_id"]),
    )
    carrier_event_type = "department.carrier.bound"
    if old_carrier is None:
        if (
            fences
            or (
                CARRIER_BINDING_V1,
                str(carrier.payload["carrier_id"]),
            ) in old_objects
        ):
            _error("new department carrier is not fresh")
    elif old_carrier.payload["state"] == "parked":
        carrier_event_type = "department.carrier.resumed"
        if (
            fences
            or carrier.payload["carrier_id"]
            != old_carrier.payload["carrier_id"]
            or carrier.payload["provider"]
            != old_carrier.payload["provider"]
            or carrier.payload["model"] != old_carrier.payload["model"]
            or carrier.payload["bound_at"]
            != old_carrier.payload["bound_at"]
        ):
            _error("parked department carrier resume differs")
    else:
        if (
            len(fences) != 1
            or fences[0].payload["carrier_id"]
            != old_carrier.payload["carrier_id"]
            or carrier.payload["carrier_id"]
            == old_carrier.payload["carrier_id"]
            or (
                CARRIER_BINDING_V1,
                str(carrier.payload["carrier_id"]),
            ) in old_objects
        ):
            _error("active department carrier replacement differs")

    ordered = [
        provider_receipts[0],
        provider_evidence[0],
        *((fences[0],) if fences else ()),
        carrier,
        execution,
        dispatch_item,
    ]
    if [item.event_id for item in ordered] != [
        str(wrapper["event_id"]) for wrapper in wrappers
    ]:
        _error("known department dispatch event order differs")
    if fences:
        _validate_lifecycle_event(
            fences[0],
            wrappers[2],
            stream="org",
            event_type="department.carrier.fenced",
            provenance="AOI_verified",
            recorded_at=recorded_at,
        )
    offset = 3 if fences else 2
    for item, wrapper, stream, event_type in (
        (
            carrier,
            wrappers[offset],
            "org",
            carrier_event_type,
        ),
        (
            execution,
            wrappers[offset + 1],
            "execution",
            "execution.department_lead.created",
        ),
        (
            dispatch_item,
            wrappers[offset + 2],
            "execution",
            "dispatch.request.dispatched",
        ),
    ):
        _validate_lifecycle_event(
            item,
            wrapper,
            stream=stream,
            event_type=event_type,
            provenance=expected_provenance,
            recorded_at=recorded_at,
        )


def _validate_department_execution_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    if any(item.contract_type == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1 for item in batch):
        return
    job_owner_ids = {
        str(item.payload["owner_execution_id"])
        for item in batch
        if item.contract_type == EXTERNAL_JOB_V1
    }
    department_executions = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload["department_id"] is not None
            # This validator owns only the provider-dispatch lifecycle used
            # for department lead carriers.  Registered descendants, turns,
            # and external-job nodes have separate transaction contracts and
            # must not be mistaken for another lead dispatch.
            and item.payload["execution_kind"] == "agent"
            and item.payload["dispatch_id"] is not None
            and item.payload["execution_id"] not in job_owner_ids
        )
    ]
    provider_exit_stop_ids = {
        str(event["event_id"])
        for event in request["events"]
        if event["event_type"] == "execution.provider_exit.stopped"
    }
    # The exact provider-exit validator below owns this coupled transaction:
    # it contains the exit receipt, Home retirement, and both agent/turn
    # runtime revisions, so it cannot satisfy the generic three-member
    # department runtime-stop shape.
    if department_executions and all(
        item.event_id in provider_exit_stop_ids for item in department_executions
    ):
        return
    engineering_receipts = [
        item
        for item in batch
        if item.contract_type == ENGINEERING_DISPOSITION_RECEIPT_V1
    ]
    if not department_executions:
        if engineering_receipts:
            _error(
                "engineering disposition lacks one department execution",
            )
        return
    has_dispatch_success = any(
        item.contract_type == DISPATCH_REQUEST_V1
        and item.payload["state"] == "dispatched"
        for item in batch
    )
    new_items = [
        item
        for item in department_executions
        if (
            EXECUTION_NODE_V1,
            str(item.payload["execution_id"]),
        ) not in old_objects
    ]
    if new_items:
        if len(new_items) != 1 or not has_dispatch_success:
            _error(
                "new department execution requires known dispatch success",
            )
        return
    if len(department_executions) != 1 or receipt_state != "committed":
        _error("department execution status transaction membership differs")
    current = department_executions[0]
    previous = old_objects[(
        EXECUTION_NODE_V1,
        str(current.payload["execution_id"]),
    )]
    receipts = [
        item
        for item in batch
        if item.contract_type == PROVIDER_LIFECYCLE_RECEIPT_V1
    ]
    evidence = [
        item
        for item in batch
        if (
            item.contract_type == EVIDENCE_RECORD_V1
            and item.payload["status"] == "observed"
        )
    ]
    disposition_receipts = engineering_receipts
    work_results = [
        item
        for item in batch
        if item.contract_type == WORK_RESULT_RECEIPT_V1
    ]
    if (
        not receipts
        and not disposition_receipts
        and previous.payload["runtime_status"] in _ACTIVE_EXECUTION
        and current.payload["runtime_status"] == "stopped"
        and current.payload["engineering_status"]
        == previous.payload["engineering_status"]
    ):
        _error("department execution status transaction membership differs")
    if receipts:
        if len(batch) != 3:
            _error(
                "department runtime stop transaction membership differs",
            )
        if (
            previous.payload["runtime_status"] not in _ACTIVE_EXECUTION
            or previous.payload["engineering_status"]
            in {"completed", "cancelled"}
            or not _same_payload_except(
                previous.payload,
                current.payload,
                "runtime_status",
                "updated_at",
                "last_event_at",
                "heartbeat_at",
                "current_tool",
                "receipt_id",
                "evidence_ids",
                "provenance",
                "observation",
            )
            or current.payload["engineering_status"]
            != previous.payload["engineering_status"]
            or current.payload["runtime_status"] != "stopped"
            or current.payload["heartbeat_at"] is not None
            or current.payload["current_tool"] is not None
            or current.payload["updated_at"]
            != current.payload["last_event_at"]
            or _parsed_time(str(current.payload["updated_at"]))
            < _parsed_time(str(previous.payload["updated_at"]))
            or current.payload["provenance"]
            not in _PROVIDER_OBSERVATION_PROVENANCE
            or current.payload["observation"]["state"] != "known"
            or not current.payload["evidence_ids"]
        ):
            _error("department runtime stop transition differs")
        if (
            len(receipts) != 1
            or len(evidence) != 1
            or receipts[0].payload["event_kind"] != "execution_stopped"
            or current.payload["updated_at"]
            != receipts[0].payload["observed_at"]
            or current.payload["provenance"]
            != receipts[0].payload["provenance"]
            or current.payload["observation"]
            != receipts[0].payload["observation"]
            or current.payload["receipt_id"]
            != receipts[0].payload["receipt_id"]
            or current.payload["evidence_ids"]
            != [
                *previous.payload["evidence_ids"],
                evidence[0].payload["evidence_id"],
            ]
            or [
                item.event_id
                for item in (receipts[0], evidence[0], current)
            ]
            != [str(wrapper["event_id"]) for wrapper in request["events"]]
        ):
            _error("department execution stop provider evidence differs")
        wrapper = request["events"][2]
        _validate_lifecycle_event(
            current,
            wrapper,
            stream="execution",
            event_type="execution.department_lead.stopped",
            provenance=str(current.payload["provenance"]),
            recorded_at=str(current.payload["updated_at"]),
        )
        return

    registered_binding = (
        None
        if previous.payload["dispatch_id"] is None
        else old_objects.get(
            (
                WORK_DISPATCH_BINDING_V1,
                str(previous.payload["dispatch_id"]),
            ),
        )
    )
    if (
        len(work_results) != (1 if registered_binding is not None else 0)
        or len(batch) != 3 + len(work_results)
        or len(disposition_receipts) != 1
        or len(evidence) != 1
        or previous.payload["runtime_status"] != "stopped"
        or previous.payload["engineering_status"]
        in {"completed", "cancelled", "idle"}
        or not _same_payload_except(
            previous.payload,
            current.payload,
            "engineering_status",
            "updated_at",
            "last_event_at",
            "wait_reason",
            "current_tool",
            "evidence_ids",
            "provenance",
            "observation",
        )
        or current.payload["engineering_status"] != "idle"
        or current.payload["runtime_status"]
        != previous.payload["runtime_status"]
        or current.payload["wait_reason"] != "park_ready"
        or current.payload["current_tool"] is not None
        or current.payload["updated_at"]
        != current.payload["last_event_at"]
        or _parsed_time(str(current.payload["updated_at"]))
        < _parsed_time(str(previous.payload["updated_at"]))
        or current.payload["provenance"] != "agent_reported"
        or current.payload["observation"]
        != {"state": "known", "reason": "observed"}
    ):
        _error("department engineering idle transition differs")
    disposition_receipt = disposition_receipts[0]
    disposition = evidence[0]
    carrier = old_objects.get(
        (
            CARRIER_BINDING_V1,
            str(previous.payload["carrier_id"]),
        ),
    )
    if (
        (
            ENGINEERING_DISPOSITION_RECEIPT_V1,
            str(disposition_receipt.payload["receipt_id"]),
        )
        in old_objects
        or any(
            item.payload["source_event_id"]
            == disposition_receipt.payload["source_event_id"]
            for item in _of_type(
                old_objects,
                ENGINEERING_DISPOSITION_RECEIPT_V1,
            )
        )
        or carrier is None
        or disposition_receipt.payload["execution_id"]
        != current.payload["execution_id"]
        or disposition_receipt.payload[
            "expected_execution_payload_sha256"
        ]
        != previous.payload_sha256
        or disposition_receipt.payload["reporter_execution_id"]
        != current.payload["execution_id"]
        or disposition_receipt.payload["reporter_carrier_id"]
        != current.payload["carrier_id"]
        or disposition_receipt.payload["provider"]
        != current.payload["provider"]
        or disposition_receipt.payload["session_id"]
        != carrier.payload["session_id"]
        or disposition_receipt.payload["thread_id"]
        != current.payload["thread_id"]
        or disposition_receipt.payload["from_status"]
        != previous.payload["engineering_status"]
        or disposition_receipt.payload["to_status"] != "idle"
        or disposition_receipt.payload["result_packet_id"]
        != current.payload["packet_id"]
        or disposition_receipt.payload["observed_at"]
        != current.payload["updated_at"]
        or disposition_receipt.payload["provenance"]
        != "agent_reported"
        or disposition_receipt.payload["observation"]
        != {"state": "known", "reason": "observed"}
        or disposition.payload["execution_id"]
        != current.payload["execution_id"]
        or disposition.payload["evidence_class"]
        != "engineering_inference"
        or disposition.payload["artifact"]["media_type"]
        != ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE
        or disposition.payload["artifact"]["availability"] != "available"
        or disposition.payload["artifact"]
        != disposition_receipt.payload["raw_artifact"]
        or disposition.payload["claim_id"]
        != disposition_receipt.payload["receipt_id"]
        or disposition.payload["verification_sha256"]
        != disposition_receipt.payload["receipt_sha256"]
        or disposition.payload["provenance"] != "agent_reported"
        or disposition.payload["observation"]
        != {"state": "known", "reason": "observed"}
        or disposition.payload["recorded_at"]
        != current.payload["updated_at"]
        or current.payload["evidence_ids"]
        != [
            *previous.payload["evidence_ids"],
            disposition.payload["evidence_id"],
        ]
        or [
            item.event_id
            for item in (
                disposition_receipt,
                disposition,
                current,
            )
        ]
        != [
            str(wrapper["event_id"])
            for wrapper in request["events"][:3]
        ]
    ):
        _error("department engineering idle evidence differs")
    _validate_lifecycle_event(
        disposition_receipt,
        request["events"][0],
        stream="evidence",
        event_type="engineering_disposition.agent_reported",
        provenance="agent_reported",
        recorded_at=str(current.payload["updated_at"]),
    )
    _validate_lifecycle_event(
        disposition,
        request["events"][1],
        stream="evidence",
        event_type="evidence.engineering_disposition.observed",
        provenance="agent_reported",
        recorded_at=str(current.payload["updated_at"]),
    )
    _validate_lifecycle_event(
        current,
        request["events"][2],
        stream="execution",
        event_type="execution.department_lead.idle",
        provenance="agent_reported",
        recorded_at=str(current.payload["updated_at"]),
    )


def _validate_chief_execution_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    job_owner_ids = {
        str(item.payload["owner_execution_id"])
        for item in batch
        if item.contract_type == EXTERNAL_JOB_V1
    }
    chief_executions: list[InvariantObject] = []
    for item in batch:
        if item.contract_type != EXECUTION_NODE_V1:
            continue
        if str(item.payload["execution_id"]) in job_owner_ids:
            # External-job admission owns this otherwise immutable job_ids
            # append and validates the complete owner/job/intent relation.
            continue
        previous = old_objects.get(
            (EXECUTION_NODE_V1, str(item.payload["execution_id"])),
        )
        current_is_root = (
            item.payload["role"] == "chief"
            and item.payload["department_id"] is None
            and item.payload["parent_execution_id"] is None
        )
        previous_is_root = (
            previous is not None
            and previous.payload["role"] == "chief"
            and previous.payload["department_id"] is None
            and previous.payload["parent_execution_id"] is None
        )
        if current_is_root or previous_is_root:
            chief_executions.append(item)
    if not chief_executions:
        return
    if any(
        item.contract_type == TAKEOVER_CONSUMPTION_RECEIPT_V1
        for item in batch
    ):
        return
    # A receipt-bound runtime observation has its own strict transition
    # validator.  It is deliberately not a provider ``execution_stopped``
    # lifecycle and must not inherit that engineering-completion path.
    if any(
        item.contract_type == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1
        for item in batch
    ):
        return
    new_items = [
        item
        for item in chief_executions
        if (
            EXECUTION_NODE_V1,
            str(item.payload["execution_id"]),
        ) not in old_objects
    ]
    if new_items:
        if _chief_term(old_objects) is not None:
            _error("new Chief execution requires a takeover transaction")
        return
    if len(chief_executions) != 1 or receipt_state != "committed":
        _error("Chief execution status transaction membership differs")
    current = chief_executions[0]
    previous = old_objects[(
        EXECUTION_NODE_V1,
        str(current.payload["execution_id"]),
    )]
    receipts = [
        item
        for item in batch
        if item.contract_type == PROVIDER_LIFECYCLE_RECEIPT_V1
    ]
    evidence = [
        item
        for item in batch
        if (
            item.contract_type == EVIDENCE_RECORD_V1
            and item.payload["status"] == "observed"
        )
    ]
    if len(receipts) != 1 or len(evidence) != 1:
        _error("Chief execution status transaction membership differs")
    receipt = receipts[0].payload
    carrier = old_objects.get(
        (CARRIER_BINDING_V1, str(previous.payload["carrier_id"])),
    )
    carrier_revisions = [
        item
        for item in batch
        if (
            item.contract_type == CARRIER_BINDING_V1
            and item.payload["carrier_id"]
            == previous.payload["carrier_id"]
        )
    ]
    current_stop = (
        carrier is not None
        and carrier.payload["state"] == "active"
        and len(carrier_revisions) == 1
        and carrier_revisions[0].payload["state"] == "lost"
    )
    fenced_stop = (
        carrier is not None
        and carrier.payload["state"] == "fenced"
        and not carrier_revisions
    )
    if (
        (current_stop and len(batch) != 4)
        or (fenced_stop and len(batch) != 3)
        or not (current_stop or fenced_stop)
    ):
        _error("Chief execution stop carrier transition differs")
    if (
        previous.payload["execution_kind"] != "carrier"
        or previous.payload["dispatch_id"] is not None
        or previous.payload["runtime_status"] not in _ACTIVE_EXECUTION
        or previous.payload["engineering_status"]
        in {"completed", "cancelled"}
        or current.payload["runtime_status"] != "stopped"
        or current.payload["heartbeat_at"] is not None
        or current.payload["current_tool"] is not None
        or current.payload["updated_at"] != current.payload["last_event_at"]
        or _parsed_time(str(current.payload["updated_at"]))
        < _parsed_time(str(previous.payload["updated_at"]))
        or current.payload["updated_at"] != receipt["observed_at"]
        or current.payload["provenance"]
        not in _PROVIDER_OBSERVATION_PROVENANCE
        or current.payload["provenance"] != receipt["provenance"]
        or current.payload["observation"] != receipt["observation"]
        or current.payload["observation"]["state"] != "known"
        or receipt["event_kind"] != "execution_stopped"
        or receipt["dispatch_request_id"] is not None
        or receipt["dispatch_revision_id"] is not None
        or receipt["dispatch_revision"] is not None
        or receipt["provider_dispatch_id"] is not None
        or receipt["execution_id"] != current.payload["execution_id"]
        or receipt["organization_node_id"]
        != current.payload["organization_node_id"]
        or receipt["carrier_id"] != current.payload["carrier_id"]
        or receipt["provider"] != current.payload["provider"]
        or receipt["model"] != current.payload["model"]
        or receipt["effort"] != current.payload["effort"]
        or receipt["thread_id"] != current.payload["thread_id"]
        or carrier is None
        or carrier.payload["session_id"] != receipt["session_id"]
        or current.payload["receipt_id"] != receipt["receipt_id"]
        or current.payload["evidence_ids"]
        != [
            *previous.payload["evidence_ids"],
            evidence[0].payload["evidence_id"],
        ]
    ):
        _error(
            "fenced Chief execution stop transition differs"
            if fenced_stop
            else "current Chief execution stop transition differs",
        )
    if current_stop:
        lost = carrier_revisions[0]
        preserved_carrier_fields = set(carrier.payload) - {
            "session_id",
            "session_availability",
            "state",
            "last_observed_at",
            "observation",
        }
        if (
            not _same_payload_except(
                previous.payload,
                current.payload,
                "runtime_status",
                "updated_at",
                "last_event_at",
                "heartbeat_at",
                "wait_reason",
                "current_tool",
                "receipt_id",
                "evidence_ids",
                "provenance",
                "observation",
            )
            or current.payload["engineering_status"]
            != previous.payload["engineering_status"]
            or current.payload["wait_reason"] != "carrier_stopped"
            or any(
                lost.payload[field] != carrier.payload[field]
                for field in preserved_carrier_fields
            )
            or lost.payload["session_id"] is not None
            or lost.payload["session_availability"] != "unavailable"
            or lost.payload["state"] != "lost"
            or lost.payload["last_observed_at"] != receipt["observed_at"]
            or lost.payload["observation"] != receipt["observation"]
            or [
                item.event_id
                for item in (
                    receipts[0],
                    evidence[0],
                    lost,
                    current,
                )
            ]
            != [str(wrapper["event_id"]) for wrapper in request["events"]]
        ):
            _error("current Chief execution stop transition differs")
        _validate_lifecycle_event(
            lost,
            request["events"][2],
            stream="org",
            event_type="carrier.current_chief.lost",
            provenance=str(receipt["provenance"]),
            recorded_at=str(current.payload["updated_at"]),
        )
        _validate_lifecycle_event(
            current,
            request["events"][3],
            stream="execution",
            event_type="execution.chief_current.stopped",
            provenance=str(current.payload["provenance"]),
            recorded_at=str(current.payload["updated_at"]),
        )
        return
    if (
        previous.payload["engineering_status"] != "waiting"
        or previous.payload["wait_reason"] != "fenced_read_only"
        or not _same_payload_except(
            previous.payload,
            current.payload,
            "runtime_status",
            "updated_at",
            "last_event_at",
            "heartbeat_at",
            "current_tool",
            "receipt_id",
            "evidence_ids",
            "provenance",
            "observation",
        )
        or current.payload["engineering_status"] != "waiting"
        or current.payload["runtime_status"] != "stopped"
        or current.payload["heartbeat_at"] is not None
        or current.payload["wait_reason"] != "fenced_read_only"
        or current.payload["current_tool"] is not None
        or [item.event_id for item in (receipts[0], evidence[0], current)]
        != [str(wrapper["event_id"]) for wrapper in request["events"]]
    ):
        _error("fenced Chief execution stop transition differs")
    wrapper = request["events"][2]
    _validate_lifecycle_event(
        current,
        wrapper,
        stream="execution",
        event_type="execution.chief_fenced.stopped",
        provenance=str(current.payload["provenance"]),
        recorded_at=str(current.payload["updated_at"]),
    )


def _takeover_root_node_id(
    old_objects: Mapping[tuple[str, str], InvariantObject],
) -> str | None:
    roots = [
        item
        for item in _of_type(old_objects, ORGANIZATION_NODE_V1)
        if (
            item.payload["role"] == "chief"
            and item.payload["parent_node_id"] is None
            and item.payload["reports_to_node_id"] is None
        )
    ]
    if not roots:
        return None
    if len(roots) != 1:
        _error("takeover cannot identify one Chief organization root")
    return str(roots[0].payload["node_id"])


def _validate_takeover_carrier(
    item: InvariantObject,
    *,
    chief_id: str,
    carrier_id: str,
    state: str,
    consumed_at: str,
) -> None:
    payload = item.payload
    if (
        payload["carrier_id"] != carrier_id
        or payload["actor_id"] != chief_id
        or payload["state"] != state
        or payload["provider"] == "unknown"
        or payload["session_id"] is None
        or payload["session_availability"] != "available"
        or payload["bound_at"] != consumed_at
        or payload["last_observed_at"] != consumed_at
        or payload["observation"]["state"] != "known"
    ):
        _error("takeover contender CarrierBinding is not a known exact binding")


def _validate_takeover_execution(
    item: InvariantObject,
    *,
    carrier: InvariantObject,
    chief_node_id: str | None,
    outcome: str,
    consumed_at: str,
    old_objects: Mapping[tuple[str, str], InvariantObject],
) -> None:
    payload = item.payload
    if (
        (EXECUTION_NODE_V1, str(payload["execution_id"])) in old_objects
        or payload["execution_kind"] != "carrier"
        or payload["carrier_id"] != carrier.payload["carrier_id"]
        or payload["provider"] != carrier.payload["provider"]
        or payload["model"] != carrier.payload["model"]
        or payload["thread_id"] is None
        or payload["parent_execution_id"] is not None
        or payload["execution_depth"] != 0
        or payload["execution_path"] != [payload["execution_id"]]
        or payload["role"] != "chief"
        or payload["delegation_depth"] != 0
        or payload["runtime_status"] != "running"
        or payload["phase"] != "handoff"
        or payload["created_at"] != consumed_at
        or payload["updated_at"] != consumed_at
        or payload["last_event_at"] != consumed_at
        or payload["heartbeat_at"] != consumed_at
        or (
            chief_node_id is not None
            and payload["organization_node_id"] != chief_node_id
        )
    ):
        _error("takeover root ExecutionNode differs from its carrier")
    if outcome == "consumed":
        if (
            payload["engineering_status"] != "active"
            or payload["wait_reason"] is not None
        ):
            _error("consumed takeover execution is not active")
    elif (
        payload["engineering_status"] != "waiting"
        or payload["wait_reason"] != "fenced_read_only"
    ):
        _error("fenced takeover execution is not visibly read-only")


def _validate_takeover_prior_execution_fence(
    item: InvariantObject,
    *,
    prior_carrier_id: str,
    consumed_at: str,
    old_objects: Mapping[tuple[str, str], InvariantObject],
) -> None:
    payload = item.payload
    previous = old_objects.get(
        (EXECUTION_NODE_V1, str(payload["execution_id"])),
    )
    if (
        previous is None
        or previous.payload["role"] != "chief"
        or previous.payload["carrier_id"] != prior_carrier_id
        or payload["carrier_id"] != prior_carrier_id
    ):
        _error("takeover cannot identify the prior Chief execution")
    preserved_fields = set(previous.payload) - {
        "engineering_status",
        "updated_at",
        "last_event_at",
        "wait_reason",
    }
    if (
        any(
            payload[field] != previous.payload[field]
            for field in preserved_fields
        )
        or payload["runtime_status"] != previous.payload["runtime_status"]
        or payload["updated_at"] != consumed_at
        or payload["last_event_at"] != consumed_at
        or _parsed_time(str(payload["updated_at"]))
        < _parsed_time(str(previous.payload["updated_at"]))
    ):
        _error("takeover prior Chief execution fence is not exact")
    prior_is_live = (
        previous.payload["runtime_status"]
        in {"running", "telemetry_silent", "unknown"}
        and previous.payload["engineering_status"]
        not in {"completed", "cancelled"}
    )
    if prior_is_live:
        if (
            payload["engineering_status"] != "waiting"
            or payload["wait_reason"] != "fenced_read_only"
        ):
            _error("takeover live prior Chief is not visibly read-only")
    elif (
        payload["engineering_status"]
        != previous.payload["engineering_status"]
        or payload["wait_reason"] != previous.payload["wait_reason"]
    ):
        _error("takeover rewrites a terminal prior Chief execution")


def _validate_takeover_event_envelope(
    item: InvariantObject,
    events_by_id: Mapping[str, Mapping[str, Any]],
    *,
    stream: str,
    event_type: str,
    provenance: str,
    recorded_at: str,
) -> None:
    event = events_by_id.get(item.event_id)
    if (
        event is None
        or event["stream"] != stream
        or event["event_type"] != event_type
        or event["provenance"] != provenance
        or event["recorded_at"] != recorded_at
        or event["payload_sha256"] != item.payload_sha256
        or event["payload"] != item.payload
    ):
        _error(
            f"{item.contract_type} takeover event envelope is not canonical",
        )


def _genesis_id(binding: Mapping[str, Any], label: str) -> str:
    suffix = company_contract_sha256({
        "company_id": binding["company_id"],
        "company_incarnation": binding["company_incarnation"],
        "lock_domain_generation": binding["lock_domain_generation"],
        "label": label,
    })[:24]
    return f"genesis-{label.replace('_', '-')}-{suffix}"


def _is_unknown_genesis_first_bind(
    prior_term: Mapping[str, Any],
    prior_carrier: InvariantObject | None,
    old_objects: Mapping[tuple[str, str], InvariantObject],
) -> bool:
    if prior_carrier is None:
        return False
    binding = {
        "company_id": prior_term["company_id"],
        "company_incarnation": prior_term["company_incarnation"],
        "lock_domain_generation": prior_term["lock_domain_generation"],
    }
    carrier = prior_carrier.payload
    has_prior_execution = any(
        item.contract_type == EXECUTION_NODE_V1
        and item.payload["carrier_id"] == carrier["carrier_id"]
        for item in old_objects.values()
    )
    return bool(
        prior_term["chief_id"] == _genesis_id(binding, "chief")
        and prior_term["carrier_id"]
        == _genesis_id(binding, "chief_carrier")
        and prior_term["term"] == 1
        and prior_term["epoch"] == 1
        and prior_term["state"] == "active"
        and prior_term["ended_at"] is None
        and prior_term["previous_transaction_sha256"] == ZERO_SHA256
        and prior_term["takeover_capability_sha256"] is None
        and prior_term[
            "takeover_consumption_receipt_sha256"
        ] is None
        and carrier["carrier_id"] == prior_term["carrier_id"]
        and carrier["actor_id"] == prior_term["chief_id"]
        and carrier["provider"] == "unknown"
        and carrier["model"] is None
        and carrier["session_id"] is None
        and carrier["session_availability"] == "unknown"
        and carrier["state"] == "unknown"
        and carrier["bound_at"] == prior_term["issued_at"]
        and carrier["last_observed_at"] == carrier["bound_at"]
        and carrier["observation"] == {
            "state": "unknown",
            "reason": "provider_session_unavailable",
        }
        and not has_prior_execution
    )


def _provider_session_holders(
    carriers: Mapping[str, InvariantObject],
    executions: Mapping[str, InvariantObject],
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Return current physical-session holder carrier IDs.

    Authority fencing alone never releases a physical provider slot.  A
    fenced binding remains a holder while one of its latest non-job execution
    nodes is runtime-occupied.  Conversely, a positively stopped fenced
    carrier may release the session for a later binding.
    """

    live_execution_carriers = {
        str(item.payload["carrier_id"])
        for item in executions.values()
        if (
            item.payload["execution_kind"] != "job"
            and item.payload["carrier_id"] is not None
            and _is_runtime_occupied(item.payload)
        )
    }
    holders: dict[tuple[str, str], list[str]] = {}
    for carrier_id, item in carriers.items():
        payload = item.payload
        session_id = payload["session_id"]
        if session_id is None or not (
            payload["state"] in {"active", "unknown"}
            or carrier_id in live_execution_carriers
        ):
            continue
        holders.setdefault(
            (str(payload["provider"]), str(session_id)),
            [],
        ).append(carrier_id)
    return {
        key: tuple(sorted(carrier_ids))
        for key, carrier_ids in holders.items()
    }


def _validate_takeover_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
) -> None:
    capabilities = [
        item for item in batch
        if item.contract_type == TAKEOVER_CAPABILITY_V1
    ]
    receipts = [
        item for item in batch
        if item.contract_type == TAKEOVER_CONSUMPTION_RECEIPT_V1
    ]
    prior_term_item = _chief_term(old_objects)
    if not capabilities and not receipts:
        if (
            prior_term_item is not None
            and any(item.contract_type == CHIEF_TERM_V1 for item in batch)
        ):
            _error("an existing ChiefTerm can advance only through takeover")
        return
    if len(capabilities) != 1 or len(receipts) != 1:
        _error("takeover transaction requires one capability and receipt")
    if prior_term_item is None:
        _error("takeover requires an existing logical Chief")
    capability = capabilities[0].payload
    receipt = receipts[0].payload
    if (
        receipt["capability"] != capability
        or receipt["capability_sha256"]
        != capability["capability_sha256"]
        or capability["consumption_id"] != receipt["consumption_id"]
        or capability["consumption_transaction_id"]
        != request["transaction_id"]
        or capability["consumption_command_id"] != request["command_id"]
        or receipt["transaction_id"] != request["transaction_id"]
        or receipt["command_id"] != request["command_id"]
    ):
        _error("takeover capability and receipt differ from the outer request")
    prior_term = prior_term_item.payload
    expected_head = request["expected_transaction_head"][
        "transaction_sha256"
    ]
    can_consume = (
        capability["expected_head_sha256"] == expected_head
        and capability["expected_chief_id"] == prior_term["chief_id"]
        and capability["expected_term"] == prior_term["term"]
        and capability["expected_epoch"] == prior_term["epoch"]
    )
    outcome = str(receipt["outcome"])
    if (outcome == "consumed") != can_consume:
        _error("takeover outcome differs from current head and Chief term")
    prior_carrier_id = str(prior_term["carrier_id"])
    prior_carrier_item = old_objects.get(
        (CARRIER_BINDING_V1, prior_carrier_id),
    )
    unknown_genesis_first_bind = (
        outcome == "consumed"
        and _is_unknown_genesis_first_bind(
            prior_term,
            prior_carrier_item,
            old_objects,
        )
    )
    counts = Counter(item.contract_type for item in batch)
    expected_counts = (
        {
            TAKEOVER_CAPABILITY_V1: 1,
            TAKEOVER_CONSUMPTION_RECEIPT_V1: 1,
            CHIEF_TERM_V1: 1,
            AUTHORITY_GRANT_V1: 1,
            CARRIER_BINDING_V1: 2,
            EXECUTION_NODE_V1: (
                1 if unknown_genesis_first_bind else 2
            ),
        }
        if outcome == "consumed"
        else {
            TAKEOVER_CAPABILITY_V1: 1,
            TAKEOVER_CONSUMPTION_RECEIPT_V1: 1,
            CARRIER_BINDING_V1: 1,
            EXECUTION_NODE_V1: 1,
        }
    )
    if counts != expected_counts:
        _error("takeover transaction composition is not exact")
    consumed_at = str(receipt["consumed_at"])
    events_by_id = {
        str(event["event_id"]): event
        for event in request["events"]
    }
    _validate_takeover_event_envelope(
        capabilities[0],
        events_by_id,
        stream="org",
        event_type="chief.takeover.capability.consumed",
        provenance="AOI_verified",
        recorded_at=consumed_at,
    )
    _validate_takeover_event_envelope(
        receipts[0],
        events_by_id,
        stream="org",
        event_type=f"chief.takeover.{outcome}",
        provenance="AOI_verified",
        recorded_at=consumed_at,
    )
    chief_node_id = _takeover_root_node_id(old_objects)
    contender_id = str(capability["contender_carrier_id"])
    if contender_id == prior_carrier_id:
        _error("takeover contender must use a different carrier")
    if (CARRIER_BINDING_V1, contender_id) in old_objects:
        _error("takeover contender must use a new durable carrier ID")
    carrier_items = [
        item for item in batch if item.contract_type == CARRIER_BINDING_V1
    ]
    contender = next(
        (
            item for item in carrier_items
            if item.payload["carrier_id"] == contender_id
        ),
        None,
    )
    if contender is None:
        _error("takeover contender carrier is missing")
    _validate_takeover_carrier(
        contender,
        chief_id=str(prior_term["chief_id"]),
        carrier_id=contender_id,
        state="active" if outcome == "consumed" else "fenced",
        consumed_at=consumed_at,
    )
    _validate_takeover_event_envelope(
        contender,
        events_by_id,
        stream="org",
        event_type=(
            "carrier.bound" if outcome == "consumed" else "carrier.fenced"
        ),
        provenance="agent_reported",
        recorded_at=consumed_at,
    )
    execution_items = [
        item for item in batch if item.contract_type == EXECUTION_NODE_V1
    ]
    execution = next(
        (
            item for item in execution_items
            if item.payload["carrier_id"] == contender_id
        ),
        None,
    )
    if execution is None:
        _error("takeover contender execution is missing")
    _validate_takeover_execution(
        execution,
        carrier=contender,
        chief_node_id=chief_node_id,
        outcome=outcome,
        consumed_at=consumed_at,
        old_objects=old_objects,
    )
    _validate_takeover_event_envelope(
        execution,
        events_by_id,
        stream="execution",
        event_type="execution.created",
        provenance="agent_reported",
        recorded_at=consumed_at,
    )
    if outcome == "fenced":
        if receipt["resulting_chief_term"] is not None:
            _error("fenced takeover cannot publish a resulting ChiefTerm")
        return

    prior_execution = next(
        (
            item for item in execution_items
            if item.payload["carrier_id"] == prior_carrier_id
        ),
        None,
    )
    if unknown_genesis_first_bind:
        if prior_execution is not None:
            _error("unknown genesis takeover fabricated a prior execution")
    else:
        if prior_execution is None:
            _error("consumed takeover lacks the prior execution fence")
        _validate_takeover_prior_execution_fence(
            prior_execution,
            prior_carrier_id=prior_carrier_id,
            consumed_at=consumed_at,
            old_objects=old_objects,
        )
        _validate_takeover_event_envelope(
            prior_execution,
            events_by_id,
            stream="execution",
            event_type="execution.authority_fenced",
            provenance="AOI_verified",
            recorded_at=consumed_at,
        )

    fenced_prior = next(
        (
            item for item in carrier_items
            if item.payload["carrier_id"] == prior_carrier_id
        ),
        None,
    )
    if prior_carrier_item is None or fenced_prior is None:
        _error("consumed takeover lacks the prior carrier fence")
    _validate_takeover_event_envelope(
        fenced_prior,
        events_by_id,
        stream="org",
        event_type="carrier.fenced",
        provenance="AOI_verified",
        recorded_at=consumed_at,
    )
    if unknown_genesis_first_bind:
        preserved_fields = set(prior_carrier_item.payload) - {"state"}
        if (
            any(
                fenced_prior.payload[field]
                != prior_carrier_item.payload[field]
                for field in preserved_fields
            )
            or fenced_prior.payload["state"] != "fenced"
        ):
            _error(
                "unknown genesis takeover does not preserve its observation",
            )
    else:
        preserved_fields = {
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "carrier_id",
            "actor_id",
            "provider",
            "model",
            "session_id",
            "session_availability",
            "bound_at",
        }
        if (
            any(
                fenced_prior.payload[field]
                != prior_carrier_item.payload[field]
                for field in preserved_fields
            )
            or fenced_prior.payload["state"] != "fenced"
            or fenced_prior.payload["last_observed_at"] != consumed_at
            or fenced_prior.payload["observation"]["state"] != "known"
        ):
            _error(
                "consumed takeover does not exactly fence the prior carrier",
            )
    new_term_item = next(
        item for item in batch if item.contract_type == CHIEF_TERM_V1
    )
    _validate_takeover_event_envelope(
        new_term_item,
        events_by_id,
        stream="org",
        event_type="chief.term.advanced",
        provenance="AOI_verified",
        recorded_at=consumed_at,
    )
    new_term = new_term_item.payload
    if (
        new_term["chief_id"] != capability["resulting_chief_id"]
        or new_term["carrier_id"] != contender_id
        or new_term["term"] != capability["resulting_term"]
        or new_term["epoch"] != capability["resulting_epoch"]
        or new_term["state"] != "active"
        or new_term["issued_at"] != consumed_at
        or new_term["ended_at"] is not None
        or new_term["previous_transaction_sha256"] != expected_head
        or new_term["takeover_capability_sha256"]
        != capability["capability_sha256"]
        or new_term["takeover_consumption_receipt_sha256"]
        != receipt["receipt_sha256"]
        or new_term["observation"]["state"] != "known"
    ):
        _error("consumed takeover ChiefTerm differs from its capability")
    resulting = receipt["resulting_chief_term"]
    if (
        resulting is None
        or resulting["chief_id"] != new_term["chief_id"]
        or resulting["carrier_id"] != new_term["carrier_id"]
        or resulting["term"] != new_term["term"]
        or resulting["epoch"] != new_term["epoch"]
        or resulting["takeover_capability_sha256"]
        != new_term["takeover_capability_sha256"]
    ):
        _error("takeover receipt resulting ChiefTerm differs")
    grant_item = next(
        item for item in batch if item.contract_type == AUTHORITY_GRANT_V1
    )
    _validate_takeover_event_envelope(
        grant_item,
        events_by_id,
        stream="org",
        event_type="authority.granted",
        provenance="AOI_verified",
        recorded_at=consumed_at,
    )
    grant = grant_item.payload
    if (
        grant["actor_kind"] != "chief"
        or grant["actor_id"] != new_term["chief_id"]
        or grant["carrier_id"] != contender_id
        or grant["chief_epoch"] != new_term["epoch"]
        or grant["term"] != new_term["term"]
        or grant["authority_state"] != "active"
        or grant["permissions"] != ["company.mutate"]
        or grant["scope_sha256"] != capability["scope_sha256"]
        or grant["issued_at"] != consumed_at
    ):
        _error("takeover Chief authority grant differs from the new term")


def _validate_carrier_revisions(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
) -> None:
    """Require every existing carrier revision to use a typed lifecycle."""

    wrappers = {
        str(wrapper["event_id"]): wrapper for wrapper in request["events"]
    }
    for item in batch:
        if item.contract_type != CARRIER_BINDING_V1:
            continue
        key = (CARRIER_BINDING_V1, str(item.payload["carrier_id"]))
        if key not in old_objects:
            continue
        wrapper = wrappers.get(item.event_id)
        if wrapper is None:
            _error("carrier revision lacks its transaction event")
        event_type = str(wrapper["event_type"])
        allowed = False
        if event_type == "department.carrier.parked":
            allowed = any(
                candidate.contract_type == CONTROL_INTENT_V1
                and candidate.payload["request_payload"].get(
                    "request_type",
                ) == "department_lifecycle_request_v1"
                and candidate.payload["request_payload"].get(
                    "operation",
                ) == "park"
                for candidate in batch
            )
        elif event_type in {
            "department.carrier.resumed",
            "department.carrier.fenced",
        }:
            allowed = (
                any(
                    candidate.contract_type == DISPATCH_REQUEST_V1
                    and candidate.payload["state"] == "dispatched"
                    for candidate in batch
                )
                and any(
                    candidate.contract_type
                    == PROVIDER_LIFECYCLE_RECEIPT_V1
                    for candidate in batch
                )
            )
        elif event_type == "carrier.fenced":
            allowed = any(
                candidate.contract_type
                == TAKEOVER_CONSUMPTION_RECEIPT_V1
                and candidate.payload["outcome"] == "consumed"
                for candidate in batch
            )
        elif event_type == "carrier.current_chief.lost":
            allowed = (
                any(
                    candidate.contract_type
                    == PROVIDER_LIFECYCLE_RECEIPT_V1
                    and candidate.payload["event_kind"]
                    == "execution_stopped"
                    for candidate in batch
                )
                and any(
                    candidate.contract_type == EXECUTION_NODE_V1
                    and candidate.payload["carrier_id"]
                    == item.payload["carrier_id"]
                    and candidate.payload["role"] == "chief"
                    for candidate in batch
                )
            )
        elif event_type == "carrier.runtime.confirmed_lost":
            allowed = any(
                candidate.contract_type == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1
                and candidate.payload["transition"] == "confirmed_lost"
                and candidate.payload["carrier_id"] == item.payload["carrier_id"]
                for candidate in batch
            )
        if not allowed:
            _error("carrier revision lacks one typed lifecycle transaction")


_EXECUTION_REVISION_IDENTITY_FIELDS = (
    "company_id",
    "company_incarnation",
    "lock_domain_generation",
    "execution_id",
    "execution_kind",
    "display_name",
    "organization_node_id",
    "department_id",
    "parent_execution_id",
    "execution_depth",
    "execution_path",
    "task_id",
    "packet_id",
    "thread_id",
    "turn_id",
    "agent_id",
    "job_id",
    "dispatch_id",
    "registration_id",
    "provider",
    "model",
    "effort",
    "carrier_id",
    "role",
    "delegation_depth",
    "created_at",
)


def _provider_exit_runtime_stop_is_observed(
    item: InvariantObject,
    old: Mapping[str, Any],
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any] | None,
) -> bool:
    """Recognize the exact process-exit stop for one provider-bound node.

    Process exit, rather than a terminal/result observation, is the runtime
    fact.  The stop preserves every engineering and identity fact and is
    admitted only with the persisted exit receipt for the same launch.
    """

    payload = item.payload
    allowed_changes = {
        "runtime_status", "updated_at", "last_event_at", "heartbeat_at",
        "current_tool",
    }
    if (
        request is None
        or old["engineering_status"] in {"completed", "cancelled"}
        or old["runtime_status"] not in _ACTIVE_EXECUTION
        or payload["engineering_status"] != old["engineering_status"]
        or payload["runtime_status"] != "stopped"
        or payload["heartbeat_at"] is not None
        or payload["current_tool"] is not None
        or any(
            payload[field] != old[field]
            for field in payload
            if field not in allowed_changes
        )
    ):
        return False

    candidate = dict(old_objects)
    for member in batch:
        candidate[(member.contract_type, _logical_key(member))] = member
    launches = _latest(
        tuple(candidate.values()), PROVIDER_LAUNCH_BINDING_V1,
        "launch_binding_id",
    )
    executions = _latest(
        tuple(candidate.values()), EXECUTION_NODE_V1, "execution_id",
    )
    exits = [
        member for member in batch
        if (
            member.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1
            and member.payload["phase"] == "process_exit_observed"
        )
    ]
    matching: list[tuple[InvariantObject, InvariantObject]] = []
    for exit_receipt in exits:
        launch = launches.get(str(exit_receipt.payload["launch_binding_id"]))
        if launch is None:
            continue
        launch_payload = launch.payload
        if payload["execution_kind"] == "agent":
            exact = (
                payload["dispatch_id"] == launch_payload["dispatch_request_id"]
                and payload["carrier_id"] is not None
                and all(
                    payload[field] == launch_payload[field]
                    for field in ("provider", "model", "effort")
                )
            )
        elif payload["execution_kind"] == "turn":
            parent = executions.get(str(payload["parent_execution_id"]))
            exact = (
                payload["registration_id"] == launch_payload["launch_binding_id"]
                and parent is not None
                and parent.payload["execution_kind"] == "agent"
                and parent.payload["dispatch_id"]
                == launch_payload["dispatch_request_id"]
                and payload["thread_id"] == parent.payload["thread_id"]
                and payload["carrier_id"] == parent.payload["carrier_id"]
                and payload["carrier_id"] is not None
                and all(
                    node.payload[field] == launch_payload[field]
                    for node in (parent, item)
                    for field in ("provider", "model", "effort")
                )
            )
        else:
            exact = False
        if exact:
            matching.append((exit_receipt, launch))
    if len(matching) != 1:
        return False
    exit_receipt, _launch = matching[0]
    if (
        payload["updated_at"] != exit_receipt.payload["observed_at"]
        or payload["last_event_at"] != exit_receipt.payload["observed_at"]
    ):
        return False
    wrapper = next((
        event for event in request["events"]
        if event["event_id"] == item.event_id
    ), None)
    if wrapper is None:
        return False
    _validate_lifecycle_event(
        item,
        wrapper,
        stream="execution",
        event_type="execution.provider_exit.stopped",
        provenance=str(payload["provenance"]),
        recorded_at=str(payload["updated_at"]),
    )
    return True


def _provider_launch_bound_execution(
    payload: Mapping[str, Any],
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
) -> bool:
    """Return whether a pre-existing node belongs to any projected launch."""

    candidate = dict(old_objects)
    for member in batch:
        candidate[(member.contract_type, _logical_key(member))] = member
    launches = _latest(
        tuple(candidate.values()), PROVIDER_LAUNCH_BINDING_V1,
        "launch_binding_id",
    )
    if payload["execution_kind"] == "agent":
        return any(
            payload["dispatch_id"] == launch.payload["dispatch_request_id"]
            and payload["carrier_id"] is not None
            and all(
                payload[field] == launch.payload[field]
                for field in ("provider", "model", "effort")
            )
            for launch in launches.values()
        )
    return payload["execution_kind"] == "turn" and payload["registration_id"] in launches


def _provider_turn_idle_event_id(
    execution_id: str,
    *,
    result_receipt_id: str,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "result_receipt_id": result_receipt_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "provider_turn_engineering_idle",
    })
    return f"provider-turn-engineering-idle-{digest}"


def _provider_turn_idle_is_observed(
    item: InvariantObject,
    old: Mapping[str, Any],
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any] | None,
) -> bool:
    """Recognize the one B50 handoff from a stopped provider turn to idle."""

    if request is None:
        return False
    payload = item.payload
    if (
        payload["execution_kind"] != "turn"
        or old["execution_kind"] != "turn"
        or old["runtime_status"] != "stopped"
        or old["engineering_status"] in {"completed", "cancelled", "idle"}
        or payload["runtime_status"] != "stopped"
        or payload["engineering_status"] != "idle"
        or payload["wait_reason"] != "park_ready"
        or payload["current_tool"] is not None
        or payload["provenance"] != "AOI_verified"
        or payload["observation"] != {"state": "known", "reason": "observed"}
        or not _same_payload_except(
            old,
            payload,
            "engineering_status", "updated_at", "last_event_at",
            "wait_reason", "current_tool", "evidence_ids", "provenance",
            "observation",
        )
        or payload["evidence_ids"][:len(old["evidence_ids"])] != old["evidence_ids"]
        or len(payload["evidence_ids"]) != len(old["evidence_ids"]) + 1
    ):
        return False
    wrappers = {str(event["event_id"]): event for event in request["events"]}
    wrapper = wrappers.get(item.event_id)
    if wrapper is None:
        return False
    evidence_id = payload["evidence_ids"][-1]
    evidence = next((
        candidate for candidate in batch
        if candidate.contract_type == EVIDENCE_RECORD_V1
        and candidate.object_key == evidence_id
    ), None)
    if evidence is None:
        return False
    result_id = evidence.payload["claim_id"]
    candidate = dict(old_objects)
    for member in batch:
        candidate[(member.contract_type, _logical_key(member))] = member
    results = _latest(
        tuple(candidate.values()), PROVIDER_TURN_RESULT_RECEIPT_V1,
        "result_receipt_id",
    )
    launches = _latest(
        tuple(candidate.values()), PROVIDER_LAUNCH_BINDING_V1,
        "launch_binding_id",
    )
    receipts = _latest(
        tuple(candidate.values()), PROVIDER_WORKER_IO_RECEIPT_V1,
        "receipt_id",
    )
    executions = _latest(
        tuple(candidate.values()), EXECUTION_NODE_V1, "execution_id",
    )
    result = results.get(str(result_id))
    parent = executions.get(str(payload["parent_execution_id"]))
    launch = None if result is None else launches.get(str(result.payload["launch_binding_id"]))
    exits = [] if launch is None else [
        receipt for receipt in receipts.values()
        if (
            receipt.payload["phase"] == "process_exit_observed"
            and receipt.payload["launch_binding_id"] == launch.payload["launch_binding_id"]
            and receipt.payload["execution_id"] == payload["execution_id"]
            and receipt.payload["thread_id"] == payload["thread_id"]
            and receipt.payload["turn_id"] == payload["turn_id"]
        )
    ]
    if (
        len(batch) != 2
        or len(request["events"]) != 2
        or result is None
        or result in batch
        or launch is None
        or parent is None
        or len(exits) != 1
        or exits[0] in batch
        or result.payload["terminal_status"] != "completed"
        or tuple(result.payload[field] for field in (
            "launch_binding_id", "launch_binding_sha256", "agent_execution_id",
            "turn_execution_id", "thread_id", "turn_id",
        )) != (
            launch.payload["launch_binding_id"], launch.payload["binding_sha256"],
            parent.payload["execution_id"], payload["execution_id"],
            payload["thread_id"], payload["turn_id"],
        )
        or parent.payload["execution_kind"] != "agent"
        or parent.payload["dispatch_id"] != launch.payload["dispatch_request_id"]
        or parent.payload["thread_id"] != payload["thread_id"]
        or parent.payload["carrier_id"] is None
        or parent.payload["carrier_id"] != payload["carrier_id"]
        or any(
            node.payload[field] != launch.payload[field]
            for node in (parent, item)
            for field in ("provider", "model", "effort")
        )
        or evidence.payload != {
            "contract_type": EVIDENCE_RECORD_V1,
            "schema_version": 1,
            "company_id": result.payload["company_id"],
            "company_incarnation": result.payload["company_incarnation"],
            "lock_domain_generation": result.payload["lock_domain_generation"],
            "evidence_id": f"provider-turn-idle-evidence-{result.payload['receipt_sha256']}",
            "execution_id": payload["execution_id"],
            "claim_id": result.payload["result_receipt_id"],
            "evidence_class": "engineering_inference",
            "status": "observed",
            "artifact": result.payload["result_ref"],
            "command_sha256": None,
            "verification_sha256": result.payload["receipt_sha256"],
            "recorded_at": payload["updated_at"],
            "provenance": "AOI_verified",
            "observation": {"state": "known", "reason": "observed"},
        }
        or (EVIDENCE_RECORD_V1, str(evidence_id)) in old_objects
        or _parsed_time(str(payload["updated_at"])) < _parsed_time(str(exits[0].payload["observed_at"]))
        or _parsed_time(str(payload["updated_at"])) < _parsed_time(str(result.payload["recorded_at"]))
        or _parsed_time(str(payload["updated_at"])) < _parsed_time(str(old["updated_at"]))
        or wrapper["event_id"] != _provider_turn_idle_event_id(
            str(payload["execution_id"]),
            result_receipt_id=str(result.payload["result_receipt_id"]),
            transaction_id=str(request["transaction_id"]),
            command_id=str(request["command_id"]),
        )
        or any(member.contract_type == WORK_RESULT_RECEIPT_V1 for member in batch)
    ):
        return False
    try:
        _validate_lifecycle_event(
            evidence, wrappers.get(evidence.event_id, {}), stream="evidence",
            event_type="evidence.provider_turn.idle.observed",
            provenance="AOI_verified", recorded_at=str(payload["updated_at"]),
        )
        _validate_lifecycle_event(
            item, wrapper, stream="execution", event_type="execution.provider_turn.idle",
            provenance="AOI_verified", recorded_at=str(payload["updated_at"]),
        )
    except (CompanyInvariantError, KeyError):
        return False
    return True


def _validate_execution_revisions(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any] | None,
) -> None:
    """Keep execution identity and append-only link lists immutable."""

    new_job_owners = {
        str(item.payload["owner_execution_id"]): str(item.payload["job_id"])
        for item in batch
        if (
            item.contract_type == EXTERNAL_JOB_V1
            and (
                EXTERNAL_JOB_V1,
                str(item.payload["job_id"]),
            )
            not in old_objects
        )
    }
    for item in batch:
        if item.contract_type != EXECUTION_NODE_V1:
            continue
        payload = item.payload
        previous = old_objects.get(
            (EXECUTION_NODE_V1, str(payload["execution_id"])),
        )
        if previous is None:
            continue
        old = previous.payload
        owner_job_id = new_job_owners.get(str(payload["execution_id"]))
        owner_job_append = (
            owner_job_id is not None
            and payload["job_ids"] == [*old["job_ids"], owner_job_id]
            and _same_payload_except(
                old,
                payload,
                "job_ids",
                "updated_at",
                "last_event_at",
            )
            and payload["updated_at"] == payload["last_event_at"]
        )
        provider_exit_stop = _provider_exit_runtime_stop_is_observed(
            item,
            old,
            old_objects,
            batch,
            request,
        )
        provider_turn_idle = _provider_turn_idle_is_observed(
            item,
            old,
            old_objects,
            batch,
            request,
        )
        provider_launch_bound = _provider_launch_bound_execution(
            old,
            old_objects,
            batch,
        )
        if (
            (old["registration_id"] is not None or provider_launch_bound)
            and payload != old
            and not owner_job_append
            and not provider_exit_stop
            and not provider_turn_idle
            and not any(
                candidate.contract_type
                == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1
                and candidate.payload["execution_id"] == payload["execution_id"]
                for candidate in batch
            )
        ):
            # Registered provider activity may change only through a future
            # typed provider-lifecycle transition.  A bare ExecutionNode
            # revision must never promote an unobserved stop/completion fact.
            _error(
                "registered ExecutionNode revision lacks typed lifecycle "
                "evidence",
            )
        if any(
            payload[field] != old[field]
            for field in _EXECUTION_REVISION_IDENTITY_FIELDS
        ):
            _error("ExecutionNode revision changes immutable identity")
        for field in ("job_ids", "evidence_ids"):
            old_members = list(old[field])
            current_members = list(payload[field])
            if current_members[:len(old_members)] != old_members:
                _error(f"ExecutionNode revision rewrites {field}")
        if (
            int(payload["usage_cursor"]) < int(old["usage_cursor"])
            or _parsed_time(str(payload["updated_at"]))
            < _parsed_time(str(old["updated_at"]))
        ):
            _error("ExecutionNode revision regresses its durable cursor")


def _validate_execution_graph(
    executions: Mapping[str, InvariantObject],
    nodes: Mapping[str, InvariantObject],
    carriers: Mapping[str, InvariantObject],
) -> None:
    """Validate current execution ancestry before it reaches the ledger."""

    for execution_id, item in executions.items():
        payload = item.payload
        parent_id = payload["parent_execution_id"]
        organization_node_id = payload["organization_node_id"]
        organization = (
            None
            if organization_node_id is None
            else nodes.get(str(organization_node_id))
        )
        if organization_node_id is None:
            if (
                payload["registration_id"] is None
                or parent_id is not None
                or payload["execution_depth"] != 0
                or payload["execution_path"] != [execution_id]
                or payload["department_id"] is not None
            ):
                _error("unattributed ExecutionNode is not a registered root")
        elif organization is None:
            _error("ExecutionNode organization identity is absent")
        elif (
            payload["department_id"]
            != organization.payload["department_id"]
        ):
            _error("ExecutionNode department differs from its organization")

        if parent_id is None:
            if (
                organization_node_id is not None
                and (
                    payload["execution_kind"] != "carrier"
                    or payload["role"] != "chief"
                    or organization is None
                    or organization.payload["role"] != "chief"
                    or organization.payload["parent_node_id"] is not None
                )
            ):
                _error("attached execution root is not the logical Chief")
            parent = None
        else:
            parent = executions.get(str(parent_id))
            if parent is None:
                _error("ExecutionNode parent identity is absent")
            if (
                int(payload["execution_depth"])
                != int(parent.payload["execution_depth"]) + 1
                or payload["execution_path"]
                != [
                    *parent.payload["execution_path"],
                    execution_id,
                ]
            ):
                _error("ExecutionNode ancestry differs from its parent")

        kind = str(payload["execution_kind"])
        if kind == "carrier":
            if parent is not None or int(payload["delegation_depth"]) != 0:
                _error("carrier ExecutionNode must be a depth-zero root")
        elif parent is not None and kind == "agent":
            if (
                int(payload["delegation_depth"])
                != int(parent.payload["delegation_depth"]) + 1
                or int(payload["delegation_depth"])
                > MAX_DELEGATION_DEPTH
                or organization is None
                or parent.payload["organization_node_id"] is None
                or (
                    organization.payload["parent_node_id"],
                    organization.payload["reports_to_node_id"],
                )
                != (
                    parent.payload["organization_node_id"],
                    parent.payload["organization_node_id"],
                )
            ):
                _error(
                    "agent ExecutionNode delegation differs from its parent",
                )
        elif parent is not None and kind in {"turn", "job"}:
            if (
                int(payload["delegation_depth"])
                != int(parent.payload["delegation_depth"])
                or payload["organization_node_id"]
                != parent.payload["organization_node_id"]
                or payload["department_id"] != parent.payload["department_id"]
            ):
                _error(
                    f"{kind} ExecutionNode context differs from its parent",
                )
            if kind == "turn" and (
                parent.payload["execution_kind"] not in {"carrier", "agent"}
                or payload["carrier_id"] != parent.payload["carrier_id"]
            ):
                _error("turn ExecutionNode carrier differs from its parent")

        carrier_id = payload["carrier_id"]
        if carrier_id is not None:
            carrier = carriers.get(str(carrier_id))
            if (
                carrier is None
                or carrier.payload["provider"] != payload["provider"]
                or carrier.payload["model"] != payload["model"]
            ):
                _error("ExecutionNode carrier binding differs")


_REGISTRATION_EVENT_MATCH_FIELDS = (
    "execution_id",
    "execution_kind",
    "display_name",
    "parent_execution_id",
    "execution_depth",
    "execution_path",
    "task_id",
    "packet_id",
    "thread_id",
    "turn_id",
    "agent_id",
    "job_id",
    "dispatch_id",
    "registration_id",
    "receipt_id",
    "provider",
    "model",
    "effort",
    "carrier_id",
    "delegation_depth",
    "engineering_status",
    "runtime_status",
    "attention_overlays",
    "evidence_ids",
    "provenance",
    "observation",
)


def _validate_execution_registration_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    """Bind one provider registration to its event, evidence, and node."""

    registered_nodes = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload["registration_id"] is not None
            and (
                EXECUTION_NODE_V1,
                str(item.payload["execution_id"]),
            )
            not in old_objects
        )
    ]
    if not registered_nodes:
        return
    if (
        receipt_state != "committed"
        or len(registered_nodes) != 1
        or len(batch) != 3
    ):
        _error("execution registration transaction membership differs")
    node = registered_nodes[0]
    registration_id = str(node.payload["registration_id"])
    events = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_EVENT_V1
            and item.payload["registration_id"] == registration_id
        )
    ]
    evidence = [
        item
        for item in batch
        if (
            item.contract_type == EVIDENCE_RECORD_V1
            and item.payload["claim_id"] == registration_id
        )
    ]
    if len(events) != 1 or len(evidence) != 1:
        _error("execution registration lacks exact event and evidence")
    event = events[0]
    observed = evidence[0]
    if (
        event.event_id != registration_id
        or event.payload["event_id"] != registration_id
        or event.payload["event_type"] != "execution.registered"
        or event.payload["recorded_at"] != node.payload["created_at"]
        or any(
            event.payload[field] != node.payload[field]
            for field in _REGISTRATION_EVENT_MATCH_FIELDS
        )
        or observed.payload["execution_id"] != node.payload["execution_id"]
        or observed.payload["status"] != "observed"
        or observed.payload["evidence_class"] != "runtime"
        or observed.payload["recorded_at"] != node.payload["created_at"]
        or observed.payload["artifact"]["media_type"]
        != EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE
        or observed.payload["verification_sha256"]
        != observed.payload["artifact"]["sha256"]
        or node.payload["evidence_ids"]
        != [observed.payload["evidence_id"]]
        or observed.payload["provenance"] != node.payload["provenance"]
        or observed.payload["observation"] != node.payload["observation"]
    ):
        _error("execution registration relation differs")
    wrappers = request["events"]
    if [
        str(wrapper["event_id"]) for wrapper in wrappers
    ] != [observed.event_id, event.event_id, node.event_id]:
        _error("execution registration event order differs")
    _validate_lifecycle_event(
        observed,
        wrappers[0],
        stream="evidence",
        event_type="evidence.execution_registration.observed",
        provenance=str(observed.payload["provenance"]),
        recorded_at=str(node.payload["created_at"]),
    )
    _validate_lifecycle_event(
        event,
        wrappers[1],
        stream="execution",
        event_type="execution.registered",
        provenance=str(node.payload["provenance"]),
        recorded_at=str(node.payload["created_at"]),
    )
    _validate_lifecycle_event(
        node,
        wrappers[2],
        stream="execution",
        event_type="execution.registered.current",
        provenance=str(node.payload["provenance"]),
        recorded_at=str(node.payload["created_at"]),
    )


_EXTERNAL_JOB_IDENTITY_FIELDS = (
    "company_id",
    "company_incarnation",
    "lock_domain_generation",
    "job_id",
    "owner_execution_id",
    "mutation_intent_id",
    "command_id",
    "command_blob",
    "scope_sha256",
    "actor_authority",
    "created_at",
)
_JOB_INTENT_IDENTITY_FIELDS = (
    "company_id",
    "company_incarnation",
    "lock_domain_generation",
    "intent_id",
    "execution_id",
    "mutation_kind",
    "command_id",
    "command_blob",
    "scope_sha256",
    "actor_authority",
    "expected_head_sha256",
    "created_at",
)
_EXTERNAL_JOB_TRANSITIONS = {
    "queued": frozenset({
        "running",
        "effect_unknown",
        "aborted",
    }),
    "running": frozenset({
        "completed",
        "failed_known",
        "effect_unknown",
    }),
    "effect_unknown": frozenset({
        "reconcile_required",
        "completed",
        "failed_known",
    }),
    "reconcile_required": frozenset({
        "completed",
        "failed_known",
    }),
    "completed": frozenset(),
    "failed_known": frozenset(),
    "aborted": frozenset(),
    "unknown": frozenset({"effect_unknown"}),
}
_JOB_STATE_TO_INTENT_STATES = {
    "queued": frozenset({"admitted", "in_flight"}),
    "running": frozenset({"in_flight"}),
    "completed": frozenset({"committed"}),
    "failed_known": frozenset({"failed_known"}),
    "effect_unknown": frozenset({"effect_unknown"}),
    "reconcile_required": frozenset({"reconcile_required"}),
    "aborted": frozenset({"aborted"}),
    "unknown": frozenset({"unknown"}),
}
_JOB_PRIOR_INTENT_STATES = {
    ("queued", "running"): frozenset({"in_flight"}),
    ("queued", "effect_unknown"): frozenset({"in_flight"}),
    # Once launch admission has advanced to in_flight, an adapter may no
    # longer collapse uncertainty into an abort claim.
    ("queued", "aborted"): frozenset({"admitted"}),
    ("running", "completed"): frozenset({"in_flight"}),
    ("running", "failed_known"): frozenset({"in_flight"}),
    ("running", "effect_unknown"): frozenset({"in_flight"}),
    ("effect_unknown", "reconcile_required"): frozenset({"effect_unknown"}),
    ("effect_unknown", "completed"): frozenset({"effect_unknown"}),
    ("effect_unknown", "failed_known"): frozenset({"effect_unknown"}),
    ("reconcile_required", "completed"): frozenset({"reconcile_required"}),
    ("reconcile_required", "failed_known"): frozenset({"reconcile_required"}),
    ("unknown", "effect_unknown"): frozenset({"unknown"}),
}
_JOB_EXECUTION_STATUSES = {
    "queued": ("waiting", "stopped"),
    "running": ("active", "running"),
    "completed": ("completed", "stopped"),
    "failed_known": ("completed", "stopped"),
    "effect_unknown": ("blocked", "unknown"),
    "reconcile_required": ("blocked", "unknown"),
    "aborted": ("cancelled", "stopped"),
    "unknown": ("unknown", "unknown"),
}


def _validate_external_job_execution(
    job: Mapping[str, Any],
    execution: Mapping[str, Any],
) -> None:
    expected_engineering, expected_runtime = _JOB_EXECUTION_STATUSES[
        str(job["state"])
    ]
    state = str(job["state"])
    expected_attention = (
        ["coverage_degraded"]
        if state in {"effect_unknown", "reconcile_required", "unknown"}
        else []
    )
    expected_wait_reason = {
        "queued": "queued",
        "running": None,
        "completed": None,
        "failed_known": "failed_known",
        "effect_unknown": "effect_unknown",
        "reconcile_required": "reconcile_required",
        "aborted": "aborted_before_launch",
        "unknown": "outcome_unknown",
    }[state]
    if (
        execution["execution_kind"] != "job"
        or execution["job_id"] != job["job_id"]
        or execution["parent_execution_id"] != job["owner_execution_id"]
        or execution["provider"] != "external"
        or execution["model"] is not None
        or execution["effort"] is not None
        or execution["carrier_id"] is not None
        or execution["dispatch_id"] is not None
        or execution["registration_id"] is not None
        or execution["receipt_id"] is not None
        or execution["role"] != "external_job"
        or execution["phase"] != "external_job"
        or execution["engineering_status"] != expected_engineering
        or execution["runtime_status"] != expected_runtime
        or execution["attention_overlays"] != expected_attention
        or execution["created_at"] != job["created_at"]
        or execution["updated_at"] != job["updated_at"]
        or execution["last_event_at"] != job["updated_at"]
        or execution["heartbeat_at"]
        != (job["updated_at"] if state == "running" else None)
        or execution["wait_reason"] != expected_wait_reason
        or execution["current_tool"] is not None
        or execution["terminal_at"] != job["terminal_at"]
        or (
            state in {"completed", "failed_known", "aborted"}
            and job["terminal_at"] != job["updated_at"]
        )
        or execution["usage_cursor"] != 0
        or execution["job_ids"]
        or execution["evidence_ids"]
        or execution["provenance"] != job["actor_authority"]["provenance"]
        or execution["observation"] != job["observation"]
    ):
        _error("ExternalJob execution projection differs")


def _validate_external_job_graph(
    jobs: Mapping[str, InvariantObject],
    intents: Mapping[str, InvariantObject],
    executions: Mapping[str, InvariantObject],
    grants: Mapping[str, InvariantObject],
    carriers: Mapping[str, InvariantObject],
    effect_receipts: Mapping[str, InvariantObject],
) -> None:
    """Bind every durable job to one owner, intent, grant, and job node."""

    job_executions: dict[str, list[InvariantObject]] = {}
    for execution in executions.values():
        if execution.payload["execution_kind"] == "job":
            job_executions.setdefault(
                str(execution.payload["job_id"]),
                [],
            ).append(execution)
    jobs_by_owner: dict[str, set[str]] = {}
    linked_intents: dict[str, str] = {}
    grants_by_sha256 = {
        str(item.payload["grant_sha256"]): item
        for item in grants.values()
    }
    receipts_by_job: dict[str, list[InvariantObject]] = {}
    source_event_ids: set[str] = set()
    reconciliation_owners: dict[str, str] = {}
    resolved_reconciliations: set[str] = set()
    for receipt_item in effect_receipts.values():
        receipt = receipt_item.payload
        job_id = str(receipt["job_id"])
        source_event_id = str(receipt["source_event_id"])
        if source_event_id in source_event_ids:
            _error("ExternalJob effect source identity was reused")
        source_event_ids.add(source_event_id)
        receipts_by_job.setdefault(job_id, []).append(receipt_item)
        reconciliation_id = receipt["reconciliation_id"]
        if reconciliation_id is not None:
            prior_owner = reconciliation_owners.setdefault(
                str(reconciliation_id),
                job_id,
            )
            if prior_owner != job_id:
                _error("ExternalJob reconciliation has multiple owners")
        resolves_id = receipt["resolves_reconciliation_id"]
        if resolves_id is not None:
            if str(resolves_id) in resolved_reconciliations:
                _error("ExternalJob reconciliation was resolved twice")
            resolved_reconciliations.add(str(resolves_id))
    for job_id, item in jobs.items():
        job = item.payload
        owner_id = str(job["owner_execution_id"])
        owner = executions.get(owner_id)
        intent = intents.get(str(job["mutation_intent_id"]))
        matching_executions = job_executions.get(job_id, [])
        authority = job["actor_authority"]
        grant = grants_by_sha256.get(
            str(authority["authority_record_sha256"]),
        )
        if (
            owner is None
            or intent is None
            or len(matching_executions) != 1
            or grant is None
        ):
            _error("ExternalJob durable relation is incomplete")
        if authority_from_grant(grant.payload) != authority:
            _error("ExternalJob authority differs from its durable grant")
        owner_payload = owner.payload
        if owner_payload["execution_kind"] == "agent":
            expected_actor_id = owner_payload["agent_id"]
        elif owner_payload["execution_kind"] == "carrier":
            carrier_id = owner_payload["carrier_id"]
            carrier = (
                None
                if carrier_id is None
                else carriers.get(str(carrier_id))
            )
            expected_actor_id = (
                None if carrier is None else carrier.payload["actor_id"]
            )
        else:
            expected_actor_id = None
        if (
            expected_actor_id is None
            or authority["actor_id"] != expected_actor_id
            or authority["carrier_id"] != owner_payload["carrier_id"]
            or authority["scope_sha256"] != job["scope_sha256"]
            or "job.start" not in authority["permissions"]
            or _parsed_time(str(grant.payload["issued_at"]))
            > _parsed_time(str(job["created_at"]))
            or grant.payload["expires_at"] is None
            or _parsed_time(str(grant.payload["expires_at"]))
            <= _parsed_time(str(job["created_at"]))
        ):
            _error("ExternalJob owner authority differs")
        intent_payload = intent.payload
        if (
            intent_payload["mutation_kind"] != "job.start"
            or intent_payload["execution_id"] != owner_id
            or intent_payload["command_id"] != job["command_id"]
            or intent_payload["command_blob"] != job["command_blob"]
            or intent_payload["scope_sha256"] != job["scope_sha256"]
            or intent_payload["actor_authority"] != authority
            or intent_payload["state"]
            not in _JOB_STATE_TO_INTENT_STATES[str(job["state"])]
            or intent_payload["effect_evidence"] != job["effect_evidence"]
            or intent_payload["reconcile_ref"] != job["reconcile_ref"]
            or intent_payload["observation"] != job["observation"]
        ):
            _error("ExternalJob MutationIntent relation differs")
        history = sorted(
            receipts_by_job.get(job_id, []),
            key=lambda receipt_item: receipt_item.global_sequence,
        )
        lifecycle_state = "queued"
        expected_effect_evidence: list[Mapping[str, Any]] = []
        open_reconciliation: str | None = None
        for receipt_item in history:
            receipt = receipt_item.payload
            observed_state = str(receipt["observed_job_state"])
            if (
                receipt["job_id"] != job_id
                or receipt["mutation_intent_id"]
                != job["mutation_intent_id"]
                or receipt["command_id"] != job["command_id"]
                or receipt["previous_job_state"] != lifecycle_state
                or observed_state
                not in _EXTERNAL_JOB_TRANSITIONS[lifecycle_state]
                or receipt["raw_artifact"]["sha256"]
                == job["command_blob"]["sha256"]
            ):
                _error("ExternalJob effect receipt chain differs")
            if observed_state not in {"running", "aborted"}:
                expected_effect_evidence.append(
                    receipt["raw_artifact"],
                )
            if observed_state in {"effect_unknown", "reconcile_required"}:
                reconciliation_id = str(receipt["reconciliation_id"])
                if (
                    open_reconciliation is not None
                    and reconciliation_id != open_reconciliation
                ):
                    _error("ExternalJob reconciliation identity changed")
                open_reconciliation = reconciliation_id
            elif observed_state in {"completed", "failed_known"}:
                resolves_id = receipt["resolves_reconciliation_id"]
                if (
                    (open_reconciliation is None and resolves_id is not None)
                    or (
                        open_reconciliation is not None
                        and resolves_id != open_reconciliation
                    )
                ):
                    _error("ExternalJob terminal resolution differs")
                open_reconciliation = None
            lifecycle_state = observed_state
        last_receipt = history[-1].payload if history else None
        expected_handle_sha256 = (
            None
            if job["external_handle"] is None
            else company_contract_sha256(job["external_handle"])
        )
        if (
            (job["state"] == "queued" and history)
            or (job["state"] != "queued" and not history)
            or lifecycle_state != job["state"]
            or job["effect_evidence"] != expected_effect_evidence
            or job["reconcile_ref"] != open_reconciliation
            or (
                last_receipt is not None
                and (
                    last_receipt["external_handle_sha256"]
                    != expected_handle_sha256
                    or last_receipt["process_fingerprint_sha256"]
                    != job["process_fingerprint_sha256"]
                    or last_receipt["observation"] != job["observation"]
                )
            )
        ):
            _error("ExternalJob effect receipt projection differs")
        previous_job_id = linked_intents.setdefault(
            str(job["mutation_intent_id"]),
            job_id,
        )
        if previous_job_id != job_id:
            _error("MutationIntent is bound to multiple ExternalJobs")
        jobs_by_owner.setdefault(owner_id, set()).add(job_id)
        job_execution = matching_executions[0].payload
        if (
            job_execution["task_id"] != owner_payload["task_id"]
            or job_execution["packet_id"] != owner_payload["packet_id"]
        ):
            _error("ExternalJob execution work context differs from its owner")
        _validate_external_job_execution(job, job_execution)

    for job_id in job_executions:
        if job_id not in jobs:
            _error("job ExecutionNode lacks an ExternalJob")
    for execution_id, execution in executions.items():
        expected = jobs_by_owner.get(execution_id, set())
        actual = set(str(job_id) for job_id in execution.payload["job_ids"])
        if actual != expected:
            _error("ExecutionNode job_ids differ from owned ExternalJobs")
    for intent_id, intent in intents.items():
        if (
            intent.payload["mutation_kind"] == "job.start"
            and intent_id not in linked_intents
        ):
            _error("job.start MutationIntent lacks an ExternalJob")
    if set(receipts_by_job) - set(jobs):
        _error("ExternalJob effect receipt lacks a durable job")


def _validate_job_execution_event(
    job: Mapping[str, Any],
    intent: Mapping[str, Any],
    execution: InvariantObject,
    event: InvariantObject,
) -> None:
    payload = event.payload
    expected_payload = {
        "job_state": job["state"],
        "mutation_state": intent["state"],
    }
    if (
        event.contract_type != EXECUTION_EVENT_V1
        or payload["event_type"] != f"external_job.{job['state']}"
        or payload["recorded_at"] != job["updated_at"]
        or payload["payload"] != expected_payload
        or any(
            payload[field] != execution.payload[field]
            for field in _REGISTRATION_EVENT_MATCH_FIELDS
        )
    ):
        _error("ExternalJob execution event differs")


def _validate_external_job_transition(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any],
    receipt_state: str,
) -> None:
    """Enforce atomic queue, launch admission, and lifecycle revisions."""

    job_items = [
        item for item in batch if item.contract_type == EXTERNAL_JOB_V1
    ]
    job_intents = [
        item
        for item in batch
        if (
            item.contract_type == MUTATION_INTENT_V1
            and item.payload["mutation_kind"] == "job.start"
        )
    ]
    job_executions = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload["execution_kind"] == "job"
        )
    ]
    job_events = [
        item
        for item in batch
        if (
            item.contract_type == EXECUTION_EVENT_V1
            and item.payload["execution_kind"] == "job"
        )
    ]
    effect_receipts = [
        item
        for item in batch
        if item.contract_type == EXTERNAL_JOB_EFFECT_RECEIPT_V1
    ]
    if not any((
        job_items,
        job_intents,
        job_executions,
        job_events,
        effect_receipts,
    )):
        return
    if receipt_state != "committed":
        _error("ExternalJob lifecycle transaction must commit exactly")

    wrappers = list(request["events"])
    recorded_at_values = {
        str(wrapper["recorded_at"]) for wrapper in wrappers
    }
    if len(recorded_at_values) != 1:
        _error("ExternalJob lifecycle requires one recorded_at")
    recorded_at = next(iter(recorded_at_values))

    # The launch claim advances only the MutationIntent.  It is the CAS point
    # that prevents two adapters from launching the same queued job.
    if (
        not job_items
        and not job_executions
        and not job_events
        and not effect_receipts
    ):
        if len(job_intents) != 1 or len(batch) != 1:
            _error("ExternalJob launch admission membership differs")
        current = job_intents[0]
        previous = old_objects.get((
            MUTATION_INTENT_V1,
            str(current.payload["intent_id"]),
        ))
        matching_jobs = [
            item
            for item in old_objects.values()
            if (
                item.contract_type == EXTERNAL_JOB_V1
                and item.payload["mutation_intent_id"]
                == current.payload["intent_id"]
            )
        ]
        if (
            previous is None
            or len(matching_jobs) != 1
            or matching_jobs[0].payload["state"] != "queued"
            or previous.payload["state"] != "admitted"
            or current.payload["state"] != "in_flight"
            or not _same_payload_except(
                previous.payload,
                current.payload,
                "state",
                "updated_at",
            )
            or current.payload["updated_at"] != recorded_at
            or _parsed_time(str(current.payload["updated_at"]))
            <= _parsed_time(str(previous.payload["updated_at"]))
        ):
            _error("ExternalJob launch admission transition differs")
        _validate_lifecycle_event(
            current,
            wrappers[0],
            stream="execution",
            event_type="external_job.launch.admitted",
            provenance="AOI_verified",
            recorded_at=recorded_at,
        )
        return

    if (
        len(job_items) != 1
        or len(job_intents) != 1
        or len(job_executions) != 1
        or len(job_events) != 1
    ):
        _error("ExternalJob lifecycle membership differs")
    job_item = job_items[0]
    job = job_item.payload
    intent = job_intents[0]
    execution = job_executions[0]
    event = job_events[0]
    previous_job = old_objects.get((EXTERNAL_JOB_V1, str(job["job_id"])))
    previous_intent = old_objects.get((
        MUTATION_INTENT_V1,
        str(intent.payload["intent_id"]),
    ))
    previous_execution = old_objects.get((
        EXECUTION_NODE_V1,
        str(execution.payload["execution_id"]),
    ))
    _validate_external_job_execution(job, execution.payload)
    _validate_job_execution_event(job, intent.payload, execution, event)

    if previous_job is None:
        owner = old_objects.get((
            EXECUTION_NODE_V1,
            str(job["owner_execution_id"]),
        ))
        owner_revisions = [
            item
            for item in batch
            if (
                item.contract_type == EXECUTION_NODE_V1
                and item.payload["execution_id"] == job["owner_execution_id"]
            )
        ]
        grants = [
            item
            for item in batch
            if item.contract_type == AUTHORITY_GRANT_V1
        ]
        expected_items = [
            *grants,
            *owner_revisions,
            execution,
            event,
            intent,
            job_item,
        ]
        if (
            owner is None
            or previous_intent is not None
            or previous_execution is not None
            or effect_receipts
            or len(owner_revisions) != 1
            or len(grants) > 1
            or len(batch) != 5 + len(grants)
            or job["state"] != "queued"
            or intent.payload["state"] != "admitted"
            or job["command_id"] != request["command_id"]
            or intent.payload["expected_head_sha256"]
            != request["expected_transaction_head"]["transaction_sha256"]
            or any(
                member["created_at"] != recorded_at
                or member["updated_at"] != recorded_at
                for member in (job, intent.payload)
            )
            or execution.payload["created_at"] != recorded_at
            or [
                item.event_id for item in expected_items
            ] != [
                str(wrapper["event_id"]) for wrapper in wrappers
            ]
        ):
            _error("ExternalJob queue transaction differs")
        owner_carrier_id = owner.payload["carrier_id"]
        owner_carrier = (
            None
            if owner_carrier_id is None
            else old_objects.get((
                CARRIER_BINDING_V1,
                str(owner_carrier_id),
            ))
        )
        current_term = _chief_term(old_objects)
        owner_kind = str(owner.payload["execution_kind"])
        if (
            owner.payload["organization_node_id"] is None
            or owner.payload["engineering_status"]
            in {"completed", "cancelled"}
            or owner.payload["runtime_status"] not in _ACTIVE_EXECUTION
            or owner_carrier is None
            or owner_carrier.payload["state"] != "active"
            or (
                owner_kind == "carrier"
                and (
                    owner.payload["role"] != "chief"
                    or current_term is None
                    or current_term.payload["state"] != "active"
                    or current_term.payload["carrier_id"]
                    != owner_carrier_id
                )
            )
            or owner_kind not in {"carrier", "agent"}
        ):
            _error("ExternalJob queue owner is not active and attributed")
        owner_revision = owner_revisions[0]
        if (
            owner_revision.payload["job_ids"]
            != [*owner.payload["job_ids"], job["job_id"]]
            or not _same_payload_except(
                owner.payload,
                owner_revision.payload,
                "job_ids",
                "updated_at",
                "last_event_at",
            )
            or owner_revision.payload["updated_at"] != recorded_at
            or owner_revision.payload["last_event_at"] != recorded_at
        ):
            _error("ExternalJob owner revision differs")
        if grants:
            grant = grants[0]
            if (
                (
                    AUTHORITY_GRANT_V1,
                    str(grant.payload["grant_id"]),
                )
                in old_objects
                or authority_from_grant(grant.payload)
                != job["actor_authority"]
            ):
                _error("ExternalJob queue authority grant differs")
        else:
            matching_old_grants = [
                item
                for item in old_objects.values()
                if (
                    item.contract_type == AUTHORITY_GRANT_V1
                    and authority_from_grant(item.payload)
                    == job["actor_authority"]
                )
            ]
            if len(matching_old_grants) != 1:
                _error("ExternalJob queue authority grant is unavailable")
        envelope_specs = [
            *(
                [
                    (
                        grants[0],
                        "org",
                        "authority.granted",
                    ),
                ]
                if grants
                else []
            ),
            (
                owner_revision,
                "execution",
                "execution.external_job.attached",
            ),
            (
                execution,
                "execution",
                "external_job.queued.current",
            ),
            (
                event,
                "execution",
                "external_job.queued",
            ),
            (
                intent,
                "execution",
                "mutation_intent.admitted",
            ),
            (
                job_item,
                "execution",
                "external_job.queued",
            ),
        ]
        for envelope_item, wrapper, stream, event_type in zip(
            (item for item, _stream, _event_type in envelope_specs),
            wrappers,
            (stream for _item, stream, _event_type in envelope_specs),
            (
                event_type
                for _item, _stream, event_type in envelope_specs
            ),
            strict=True,
        ):
            _validate_lifecycle_event(
                envelope_item,
                wrapper,
                stream=stream,
                event_type=event_type,
                provenance="AOI_verified",
                recorded_at=recorded_at,
            )
        return

    if len(effect_receipts) != 1:
        _error("ExternalJob effect receipt membership differs")
    effect_receipt = effect_receipts[0]
    prior_state = str(previous_job.payload["state"])
    current_state = str(job["state"])
    if (
        previous_intent is None
        or previous_execution is None
        or len(batch) != 5
        or [
            effect_receipt.event_id,
            execution.event_id,
            event.event_id,
            intent.event_id,
            job_item.event_id,
        ] != [
            str(wrapper["event_id"]) for wrapper in wrappers
        ]
        or current_state not in _EXTERNAL_JOB_TRANSITIONS[prior_state]
        or previous_intent.payload["state"]
        not in _JOB_PRIOR_INTENT_STATES.get(
            (prior_state, current_state),
            frozenset(),
        )
        or any(
            job[field] != previous_job.payload[field]
            for field in _EXTERNAL_JOB_IDENTITY_FIELDS
        )
        or any(
            intent.payload[field] != previous_intent.payload[field]
            for field in _JOB_INTENT_IDENTITY_FIELDS
        )
        or intent.payload["state"]
        not in _JOB_STATE_TO_INTENT_STATES[str(job["state"])]
        or _parsed_time(str(job["updated_at"]))
        <= _parsed_time(str(previous_job.payload["updated_at"]))
        or job["updated_at"] != recorded_at
        or intent.payload["updated_at"] != recorded_at
        or _parsed_time(str(intent.payload["updated_at"]))
        <= _parsed_time(str(previous_intent.payload["updated_at"]))
        or job["effect_evidence"][:len(previous_job.payload["effect_evidence"])]
        != previous_job.payload["effect_evidence"]
        or intent.payload["effect_evidence"] != job["effect_evidence"]
        or intent.payload["reconcile_ref"] != job["reconcile_ref"]
        or intent.payload["observation"] != job["observation"]
        or (
            previous_job.payload["external_handle"] is not None
            and job["external_handle"]
            != previous_job.payload["external_handle"]
        )
        or (
            previous_job.payload["process_fingerprint_sha256"] is not None
            and job["process_fingerprint_sha256"]
            != previous_job.payload["process_fingerprint_sha256"]
        )
        or not _same_payload_except(
            previous_execution.payload,
            execution.payload,
            "engineering_status",
            "runtime_status",
            "attention_overlays",
            "updated_at",
            "last_event_at",
            "heartbeat_at",
            "wait_reason",
            "terminal_at",
            "provenance",
            "observation",
        )
    ):
        _error("ExternalJob lifecycle revision differs")
    receipt = effect_receipt.payload
    expected_handle_sha256 = (
        None
        if job["external_handle"] is None
        else company_contract_sha256(job["external_handle"])
    )
    expected_evidence = [
        *previous_job.payload["effect_evidence"],
        *(
            [receipt["raw_artifact"]]
            if current_state not in {"running", "aborted"}
            else []
        ),
    ]
    previous_reconcile_ref = previous_job.payload["reconcile_ref"]
    expected_reconcile_ref = (
        receipt["reconciliation_id"]
        if current_state in {"effect_unknown", "reconcile_required"}
        else None
    )
    previous_receipts = [
        item
        for item in old_objects.values()
        if item.contract_type == EXTERNAL_JOB_EFFECT_RECEIPT_V1
    ]
    if (
        (
            EXTERNAL_JOB_EFFECT_RECEIPT_V1,
            str(receipt["receipt_id"]),
        )
        in old_objects
        or any(
            item.payload["source_event_id"] == receipt["source_event_id"]
            for item in previous_receipts
        )
        or receipt["job_id"] != job["job_id"]
        or receipt["mutation_intent_id"] != job["mutation_intent_id"]
        or receipt["command_id"] != job["command_id"]
        or receipt["transaction_id"] != request["transaction_id"]
        or receipt["transition_command_id"] != request["command_id"]
        or receipt["previous_job_state"] != prior_state
        or receipt["observed_job_state"] != current_state
        or receipt["external_handle_sha256"] != expected_handle_sha256
        or receipt["process_fingerprint_sha256"]
        != job["process_fingerprint_sha256"]
        or receipt["observed_at"] != recorded_at
        or receipt["observation"] != job["observation"]
        or receipt["raw_artifact"]["sha256"]
        == job["command_blob"]["sha256"]
        or job["effect_evidence"] != expected_evidence
        or job["reconcile_ref"] != expected_reconcile_ref
        or (
            current_state in {"effect_unknown", "reconcile_required"}
            and prior_state in {"effect_unknown", "reconcile_required"}
            and receipt["reconciliation_id"]
            != previous_reconcile_ref
        )
        or (
            current_state in {"completed", "failed_known"}
            and prior_state in {"effect_unknown", "reconcile_required"}
            and receipt["resolves_reconciliation_id"]
            != previous_reconcile_ref
        )
        or (
            current_state in {"completed", "failed_known"}
            and prior_state not in {"effect_unknown", "reconcile_required"}
            and receipt["resolves_reconciliation_id"] is not None
        )
        or any(
            (
                receipt["reconciliation_id"] is not None
                and item.payload["reconciliation_id"]
                == receipt["reconciliation_id"]
                and item.payload["job_id"] != receipt["job_id"]
            )
            or (
                receipt["resolves_reconciliation_id"] is not None
                and item.payload["resolves_reconciliation_id"]
                == receipt["resolves_reconciliation_id"]
            )
            for item in previous_receipts
        )
    ):
        _error("ExternalJob effect receipt differs")
    for envelope_item, wrapper, stream, event_type, provenance in zip(
        (effect_receipt, execution, event, intent, job_item),
        wrappers,
        ("evidence", "execution", "execution", "execution", "execution"),
        (
            f"external_job.effect.{current_state}.observed",
            f"external_job.{current_state}.current",
            f"external_job.{current_state}",
            f"mutation_intent.{intent.payload['state']}",
            f"external_job.{current_state}",
        ),
        (
            str(receipt["provenance"]),
            "AOI_verified",
            "AOI_verified",
            "AOI_verified",
            "AOI_verified",
        ),
        strict=True,
    ):
        _validate_lifecycle_event(
            envelope_item,
            wrapper,
            stream=stream,
            event_type=event_type,
            provenance=provenance,
            recorded_at=recorded_at,
        )


def _dispatch_identity(payload: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(payload[name] for name in (
        "reservation_id", "task_id", "packet_id", "manager_node_id",
        "target_node_id", "department_id", "parent_execution_id", "requested_role",
        "requested_capability_tier", "route_policy_id", "scope_sha256",
        "delegation_depth", "created_at",
    ))


def _validate_revision(previous: InvariantObject | None, current: InvariantObject) -> None:
    payload = current.payload
    if previous is None:
        if payload["revision"] != 1 or payload["state"] != "queued":
            _error("a new dispatch request must start queued at revision one")
        return
    old = previous.payload
    if current.global_sequence <= previous.global_sequence:
        _error("dispatch revision does not advance the company cursor")
    if payload["revision"] != old["revision"] + 1:
        _error("dispatch revision is not adjacent")
    if (payload["previous_event_id"], payload["previous_payload_sha256"]) != (previous.event_id, previous.payload_sha256):
        _error("dispatch predecessor differs")
    if payload["dispatch_revision_id"] == old["dispatch_revision_id"]:
        _error("dispatch revision identity was reused")
    if payload["command_id"] == old["command_id"]:
        _error("dispatch revision command identity was reused")
    if _dispatch_identity(payload) != _dispatch_identity(old):
        _error("dispatch immutable identity differs")
    if payload["state"] == old["state"] or payload["state"] not in _TRANSITIONS[old["state"]]:
        _error("dispatch state transition is invalid")


def _node_check(
    dispatch: Mapping[str, Any],
    nodes: Mapping[str, InvariantObject],
    *,
    require_dispatched_active: bool = False,
) -> None:
    target = nodes.get(dispatch["target_node_id"])
    manager = nodes.get(dispatch["manager_node_id"])
    if target is None or manager is None:
        _error("dispatch target or manager OrganizationNode is missing")
    target_payload, manager_payload = target.payload, manager.payload
    if (target_payload["parent_node_id"], target_payload["reports_to_node_id"],
            target_payload["delegation_depth"], target_payload["department_id"]) != (
                dispatch["manager_node_id"], dispatch["manager_node_id"],
                dispatch["delegation_depth"], dispatch["department_id"]):
        _error("dispatch target OrganizationNode relation differs")
    if dispatch["delegation_depth"] > MAX_DELEGATION_DEPTH:
        _error("dispatch delegation depth exceeds the company limit")
    requires_active = (
        dispatch["state"] in _HELD
        or (
            dispatch["state"] == "dispatched"
            and require_dispatched_active
        )
    )
    if requires_active and (
        manager_payload["status"] != "active" or not manager_payload["can_delegate"]
    ):
        _error("active dispatch requires an active delegating manager")
    if (
        requires_active
        and target_payload["status"] != "active"
    ):
        _error("active dispatch requires an active target")


def _is_runtime_occupied(payload: Mapping[str, Any]) -> bool:
    """Runtime occupancy is independent from engineering completion state."""
    return payload["runtime_status"] in _ACTIVE_EXECUTION


def _validate_dispatched(
    dispatch: Mapping[str, Any],
    executions: Mapping[str, InvariantObject],
    carriers: Mapping[str, InvariantObject],
    provider_receipts: Mapping[str, InvariantObject],
    evidence_records: Mapping[str, InvariantObject],
) -> None:
    if dispatch["state"] != "dispatched":
        return
    execution = executions.get(dispatch["execution_id"])
    if execution is None:
        _error("dispatched request has no matching ExecutionNode")
    payload = execution.payload
    if (payload["dispatch_id"], payload["organization_node_id"], payload["department_id"],
            payload["parent_execution_id"], payload["delegation_depth"], payload["execution_kind"]) != (
                dispatch["dispatch_request_id"], dispatch["target_node_id"], dispatch["department_id"],
                dispatch["parent_execution_id"], dispatch["delegation_depth"], "agent"):
        _error("dispatched request ExecutionNode relation differs")
    if (
        payload["observation"]["state"] != "known"
        or dispatch["provenance"] not in _PROVIDER_OBSERVATION_PROVENANCE
        or (
            payload["runtime_status"] in _ACTIVE_EXECUTION
            and payload["provenance"]
            not in _PROVIDER_OBSERVATION_PROVENANCE
        )
        or (
            payload["runtime_status"] == "stopped"
            and payload["provenance"]
            not in {*_PROVIDER_OBSERVATION_PROVENANCE, "agent_reported"}
        )
    ):
        _error("dispatched request lacks a provider-grade observation")
    receipt_id = payload["receipt_id"]
    current_receipt = (
        None
        if receipt_id is None
        else provider_receipts.get(str(receipt_id))
    )
    carrier_id = payload["carrier_id"]
    carrier = (
        None if carrier_id is None else carriers.get(str(carrier_id))
    )
    if current_receipt is None or carrier is None:
        _error("dispatched request lacks current provider receipt binding")
    receipt = current_receipt.payload
    if (
        receipt["event_kind"]
        not in {"dispatch_succeeded", "execution_stopped"}
        or receipt["dispatch_request_id"] != dispatch["dispatch_request_id"]
        or receipt["dispatch_revision_id"]
        != dispatch["dispatch_revision_id"]
        or receipt["dispatch_revision"] != dispatch["revision"]
        or receipt["provider_dispatch_id"]
        != dispatch["provider_dispatch_id"]
        or receipt["execution_id"] != payload["execution_id"]
        or receipt["carrier_id"] != payload["carrier_id"]
        or receipt["organization_node_id"]
        != payload["organization_node_id"]
        or receipt["provider"] != payload["provider"]
        or receipt["model"] != payload["model"]
        or receipt["effort"] != payload["effort"]
        or receipt["thread_id"] != payload["thread_id"]
        or (
            carrier.payload["state"] == "active"
            and receipt["session_id"] != carrier.payload["session_id"]
        )
        or (
            carrier.payload["state"] == "parked"
            and (
                carrier.payload["session_id"] is not None
                or receipt["session_id"] is None
            )
        )
    ):
        _error("dispatched request current provider receipt differs")
    if (
        (
            payload["runtime_status"] in _ACTIVE_EXECUTION
            and receipt["event_kind"] != "dispatch_succeeded"
        )
        or (
            payload["runtime_status"] == "stopped"
            # A process-exit stop preserves the original dispatch receipt and
            # evidence; its causal receipt is the separately typed provider
            # exit envelope, validated at the transition boundary.
            and receipt["event_kind"]
            not in {"dispatch_succeeded", "execution_stopped"}
        )
    ):
        _error("dispatched request provider receipt status differs")

    current_evidence = [
        evidence_records[evidence_id]
        for evidence_id in payload["evidence_ids"]
        if evidence_id in evidence_records
        and evidence_records[evidence_id].payload["claim_id"]
        == receipt["receipt_id"]
    ]
    if (
        len(current_evidence) != 1
        or current_evidence[0].payload["execution_id"]
        != receipt["execution_id"]
        or current_evidence[0].payload["evidence_class"] != "runtime"
        or current_evidence[0].payload["status"] != "observed"
        or current_evidence[0].payload["artifact"]
        != receipt["raw_artifact"]
        or current_evidence[0].payload["command_sha256"] is not None
        or current_evidence[0].payload["verification_sha256"]
        != receipt["receipt_sha256"]
        or current_evidence[0].payload["recorded_at"]
        != receipt["observed_at"]
        or current_evidence[0].payload["provenance"]
        != receipt["provenance"]
        or current_evidence[0].payload["observation"]
        != receipt["observation"]
    ):
        _error("dispatched request current provider evidence differs")

    launch_receipts = [
        item
        for item in provider_receipts.values()
        if (
            item.payload["event_kind"] == "dispatch_succeeded"
            and item.payload["dispatch_request_id"]
            == dispatch["dispatch_request_id"]
            and item.payload["dispatch_revision_id"]
            == dispatch["dispatch_revision_id"]
            and item.payload["dispatch_revision"] == dispatch["revision"]
            and item.payload["execution_id"] == payload["execution_id"]
            and item.payload["raw_artifact"] in dispatch["effect_evidence"]
        )
    ]
    if len(launch_receipts) != 1:
        _error("dispatched request launch receipt is missing or ambiguous")
    launch_receipt = launch_receipts[0].payload
    launch_evidence = [
        evidence_records[evidence_id]
        for evidence_id in payload["evidence_ids"]
        if evidence_id in evidence_records
        and evidence_records[evidence_id].payload["claim_id"]
        == launch_receipt["receipt_id"]
    ]
    if (
        len(launch_evidence) != 1
        or launch_evidence[0].payload["execution_id"]
        != launch_receipt["execution_id"]
        or launch_evidence[0].payload["evidence_class"] != "runtime"
        or launch_evidence[0].payload["status"] != "observed"
        or launch_evidence[0].payload["artifact"]
        != launch_receipt["raw_artifact"]
        or launch_evidence[0].payload["command_sha256"] is not None
        or launch_evidence[0].payload["verification_sha256"]
        != launch_receipt["receipt_sha256"]
        or launch_evidence[0].payload["recorded_at"]
        != launch_receipt["observed_at"]
        or launch_evidence[0].payload["provenance"]
        != launch_receipt["provenance"]
        or launch_evidence[0].payload["observation"]
        != launch_receipt["observation"]
    ):
        _error("dispatched request launch evidence differs")


def _shadow_holds(shadow: UncertainDispatch, dispatches: Mapping[str, InvariantObject]) -> bool:
    if shadow.requested_state in _HELD | {"dispatched"}:
        return True
    prior = dispatches.get(shadow.dispatch_request_id)
    return prior is not None and prior.payload["state"] in _HELD | {"dispatched"}


def _validate_unique_bindings(
    dispatches: Mapping[str, InvariantObject],
    executions: Mapping[str, InvariantObject],
    shadows: Sequence[UncertainDispatch],
) -> None:
    reservations: dict[str, tuple[Any, ...]] = {}
    reservation_shadow_sources: dict[str, str] = {}
    provider_dispatches: dict[str, str] = {}
    revision_ids: dict[str, str] = {}
    for request_id, item in dispatches.items():
        payload = item.payload
        reservation_binding = (request_id, *_dispatch_identity(payload))
        prior_reservation = reservations.setdefault(
            str(payload["reservation_id"]),
            reservation_binding,
        )
        if prior_reservation != reservation_binding:
            _error("dispatch reservation has a divergent request binding")
        revision_id = str(payload["dispatch_revision_id"])
        prior_revision = revision_ids.setdefault(revision_id, request_id)
        if prior_revision != request_id:
            _error("dispatch revision identity has a divergent request binding")
        provider_dispatch_id = payload["provider_dispatch_id"]
        if provider_dispatch_id is not None:
            prior_provider = provider_dispatches.setdefault(
                str(provider_dispatch_id),
                request_id,
            )
            if prior_provider != request_id:
                _error("provider dispatch identity has a divergent request binding")
    for shadow in shadows:
        reservation_binding = (
            shadow.dispatch_request_id,
            *_dispatch_identity(shadow.payload),
        )
        prior_reservation = reservations.setdefault(
            shadow.reservation_id,
            reservation_binding,
        )
        if prior_reservation != reservation_binding:
            _error("uncertain dispatch reservation has a divergent request binding")
        prior_source = reservation_shadow_sources.setdefault(
            shadow.reservation_id,
            shadow.source_event_id,
        )
        if prior_source != shadow.source_event_id:
            _error("dispatch reservation has multiple unresolved effects")

    dispatch_executions: dict[str, str] = {}
    registrations: dict[str, str] = {}
    for execution_id, item in executions.items():
        payload = item.payload
        dispatch_id = payload["dispatch_id"]
        registration_id = payload["registration_id"]
        if dispatch_id is not None:
            prior_execution = dispatch_executions.setdefault(
                str(dispatch_id),
                execution_id,
            )
            if prior_execution != execution_id:
                _error("dispatch identity is bound to multiple ExecutionNodes")
        if registration_id is not None:
            prior_execution = registrations.setdefault(
                str(registration_id),
                execution_id,
            )
            if prior_execution != execution_id:
                _error("registration identity is bound to multiple ExecutionNodes")


def _capacity(
    carriers: Mapping[str, InvariantObject], dispatches: Mapping[str, InvariantObject],
    executions: Mapping[str, InvariantObject], nodes: Mapping[str, InvariantObject],
    shadows: Sequence[UncertainDispatch],
) -> tuple[int, tuple[tuple[str, int], ...], bool, tuple[str, ...]]:
    occupied: set[str] = set()
    manager_targets: dict[str, set[str]] = {}

    unattributed: set[str] = set()
    runtime_by_carrier: dict[str, list[InvariantObject]] = {}
    for item in executions.values():
        payload = item.payload
        if (
            payload["execution_kind"] != "job"
            and _is_runtime_occupied(payload)
            and payload["carrier_id"] is not None
        ):
            runtime_by_carrier.setdefault(
                str(payload["carrier_id"]),
                [],
            ).append(item)
    session_holders = _provider_session_holders(carriers, executions)
    for carrier_ids in session_holders.values():
        if len(carrier_ids) > 1:
            unattributed.update(
                f"carrier:{carrier_id}" for carrier_id in carrier_ids
            )

    def carrier_slot(carrier_id: str, binding: InvariantObject) -> str:
        payload = binding.payload
        session_id = payload["session_id"]
        if session_id is None:
            return f"carrier:{carrier_id}"
        # Provider session IDs are sensitive and must not appear in a
        # Dashboard-facing attribution marker.  The canonical digest still
        # makes the physical provider session one capacity slot.
        return "session:" + company_contract_sha256({
            "provider": payload["provider"],
            "session_id": session_id,
        })

    def attribute(target_node_id: str, marker: str) -> None:
        target = nodes.get(target_node_id)
        if target is None:
            unattributed.add(marker)
            return
        parent = target.payload["parent_node_id"]
        reports_to = target.payload["reports_to_node_id"]
        if parent is None:
            return
        if reports_to != parent:
            unattributed.add(marker)
            return
        if str(parent) not in nodes:
            unattributed.add(marker)
            return
        manager_targets.setdefault(str(parent), set()).add(target_node_id)

    for carrier_id, item in carriers.items():
        payload = item.payload
        if payload["state"] not in {"active", "unknown"}:
            continue
        occupied.add(carrier_slot(carrier_id, item))
        # CarrierBinding.actor_id names the logical actor, not an
        # OrganizationNode.  Manager attribution comes from a runtime-occupied
        # ExecutionNode that binds this carrier to organization_node_id.
        # Without that execution link the company slot is still occupied, but
        # per-manager availability is truthfully incomplete.
        linked = runtime_by_carrier.get(carrier_id, [])
        session_id = payload["session_id"]
        if (
            session_id is not None
            and len(session_holders.get(
                (str(payload["provider"]), str(session_id)),
                (),
            )) != 1
        ):
            unattributed.add(f"carrier:{carrier_id}")
        if not linked:
            unattributed.add(f"carrier:{carrier_id}")
        elif len({
            str(execution.payload["organization_node_id"])
            for execution in linked
        }) != 1:
            # One logical carrier cannot truthfully erase fanout across
            # multiple organization identities.  Preserve the observed
            # targets below, but freeze new admission as a claim conflict.
            unattributed.add(f"carrier:{carrier_id}")

    for execution_id, item in executions.items():
        payload = item.payload
        if payload["execution_kind"] == "job" or not _is_runtime_occupied(payload):
            continue
        carrier_id = payload["carrier_id"]
        if carrier_id is not None:
            binding = carriers.get(str(carrier_id))
            if (
                binding is None
                or binding.payload["state"]
                not in {"active", "unknown", "fenced"}
                or (
                    binding.payload["provider"],
                    binding.payload["model"],
                ) != (
                    payload["provider"],
                    payload["model"],
                )
            ):
                # A missing, non-observable, or provider/model-divergent
                # binding cannot prove this is the same physical slot.  A
                # fenced binding is deliberately accepted here: authority and
                # runtime occupancy are orthogonal, so a late old carrier
                # remains a physical slot until its ExecutionNode stops.
                slot = f"execution:{execution_id}"
                unattributed.add(slot)
            else:
                slot = carrier_slot(str(carrier_id), binding)
        elif payload["registration_id"] is not None:
            slot = f"registration:{payload['registration_id']}"
            # A registered runtime without a carrier is still a live physical
            # occupant, but its provider/session identity cannot be tied to a
            # manager safely.  Do not let its OrganizationNode association
            # manufacture complete manager capacity.
            unattributed.add(f"execution:{execution_id}")
        elif payload["dispatch_id"] is not None:
            slot = f"dispatch:{payload['dispatch_id']}"
        else:
            # Contract validation should make this unreachable for a
            # non-job execution, but preserve a truthful conservative slot.
            slot = f"execution:{execution_id}"
            unattributed.add(slot)
        occupied.add(slot)
        organization_node_id = str(payload["organization_node_id"])
        attribute(organization_node_id, f"execution:{execution_id}")
        dispatch_id = payload["dispatch_id"]
        if (
            payload["execution_kind"] == "agent"
            and dispatch_id is not None
            and (
                str(dispatch_id) not in dispatches
                or dispatches[str(dispatch_id)].payload["state"] != "dispatched"
            )
        ):
            unattributed.add(f"execution:{execution_id}")

    for request_id, item in dispatches.items():
        payload = item.payload
        if payload["state"] in _HELD:
            occupied.add(f"reservation:{payload['reservation_id']}")
            manager_targets.setdefault(payload["manager_node_id"], set()).add(payload["target_node_id"])
    for shadow in shadows:
        if _shadow_holds(shadow, dispatches):
            payload = shadow.payload
            occupied.add(f"reservation:{shadow.reservation_id}")
            manager_targets.setdefault(payload["manager_node_id"], set()).add(payload["target_node_id"])
    fanout = tuple(sorted((manager, len(targets)) for manager, targets in manager_targets.items()))
    unattributed_items = tuple(sorted(unattributed))
    return len(occupied), fanout, not unattributed_items, unattributed_items


def _validate_resolution(
    old_dispatches: Mapping[str, InvariantObject], shadows: Sequence[UncertainDispatch],
    final_dispatches: Mapping[str, InvariantObject],
) -> tuple[UncertainDispatch, ...]:
    remaining = list(shadows)
    for request_id, current in final_dispatches.items():
        previous = old_dispatches.get(request_id)
        changed = previous is None or current != previous
        if not changed:
            continue
        payload = current.payload
        required: set[str] = set()
        if previous is not None and previous.payload["state"] == "effect_unknown":
            required.add(previous.event_id)
        required.update(
            shadow.source_event_id
            for shadow in shadows
            if (
                shadow.dispatch_request_id == request_id
                and shadow.reservation_id == payload["reservation_id"]
            )
        )
        resolved = set(payload["resolves_event_ids"])
        if required:
            if payload["state"] not in _RESOLUTION_STATES or resolved != required:
                _error("dispatch must resolve exactly all uncertain source events")
            remaining = [
                shadow
                for shadow in remaining
                if not (
                    shadow.dispatch_request_id == request_id
                    and shadow.reservation_id == payload["reservation_id"]
                    and shadow.source_event_id in resolved
                )
            ]
        elif resolved:
            _error("dispatch without uncertainty cannot resolve events")
    return tuple(remaining)


def _validate_append_once_projection_ids(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
) -> None:
    """Reject generic commits that would overwrite immutable projected facts."""

    for item in batch:
        if item.contract_type in _APPEND_ONCE_AUTHORITY_TYPES:
            error = "immutable authority grant logical ID is already durable"
        elif item.contract_type in _APPEND_ONCE_WORK_DEFINITION_TYPES:
            error = "immutable work definition logical ID is already durable"
        elif item.contract_type in _APPEND_ONCE_WRITE_ADMISSION_TYPES:
            error = "immutable write-admission logical ID is already durable"
        elif item.contract_type in _APPEND_ONCE_PROVIDER_PROJECTION_TYPES:
            error = "append-only provider projection logical ID is already durable"
        else:
            continue
        key = (item.contract_type, _logical_key(item))
        if key in old_objects:
            _error(error)


def _validate_work_definitions(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any] | None,
) -> None:
    """Validate the resident, immutable work-definition joins.

    Work definitions are deliberately reduced from the complete candidate
    record set.  Their event order is therefore irrelevant both for a
    transaction that creates a task and packet together and for read-model
    replay of the already committed records.
    """
    candidate = dict(old_objects)
    for item in batch:
        candidate[(item.contract_type, _logical_key(item))] = item

    task_items = _of_type(candidate, TASK_REVISION_V1)
    packet_items = _of_type(candidate, WORK_PACKET_V1)
    tasks_by_revision: dict[str, InvariantObject] = {}
    task_revisions: dict[str, dict[int, InvariantObject]] = {}
    for item in task_items:
        payload = item.payload
        revision_id = str(payload["task_revision_id"])
        prior = tasks_by_revision.setdefault(revision_id, item)
        if prior != item:
            _error("task revision identity has divergent bindings")
        revisions = task_revisions.setdefault(str(payload["task_id"]), {})
        revision = int(payload["revision"])
        if revision in revisions and revisions[revision] != item:
            _error("task revision number has divergent bindings")
        revisions[revision] = item
    for task_id, revisions in task_revisions.items():
        for expected_revision, item in enumerate(
            (revisions[index] for index in sorted(revisions)),
            start=1,
        ):
            payload = item.payload
            if int(payload["revision"]) != expected_revision:
                _error("task revision chain is not adjacent")
            if expected_revision == 1:
                continue
            predecessor = revisions[expected_revision - 1].payload
            if (
                payload["previous_task_revision_id"]
                != predecessor["task_revision_id"]
                or payload["previous_task_sha256"]
                != predecessor["task_sha256"]
                or payload["task_id"] != task_id
            ):
                _error("task revision predecessor differs")

    packets_by_id: dict[str, InvariantObject] = {}
    packets_for_task_revision: dict[str, list[InvariantObject]] = {}
    for item in packet_items:
        payload = item.payload
        packet_id = str(payload["packet_id"])
        prior = packets_by_id.setdefault(packet_id, item)
        if prior != item:
            _error("work packet identity has divergent bindings")
        task = tasks_by_revision.get(str(payload["task_revision_id"]))
        if task is None or (
            payload["task_id"], payload["task_sha256"]
        ) != (
            task.payload["task_id"], task.payload["task_sha256"],
        ):
            _error("work packet task revision binding differs")
        packets_for_task_revision.setdefault(
            str(payload["task_revision_id"]), [],
        ).append(item)
    for task_revision_id in tasks_by_revision:
        if not packets_for_task_revision.get(task_revision_id):
            _error("task revision has no work packet")
    for packet in packet_items:
        payload = packet.payload
        parent_id = payload["parent_packet_id"]
        if parent_id is None:
            if payload["delegation_depth"] != 1:
                _error("root work packet depth differs")
            continue
        parent = packets_by_id.get(str(parent_id))
        if parent is None:
            _error("work packet parent is missing")
        parent_payload = parent.payload
        if (
            payload["parent_packet_sha256"] != parent_payload["packet_sha256"]
            or payload["delegation_depth"] != parent_payload["delegation_depth"] + 1
            or tuple(payload[name] for name in ("task_id", "task_revision_id", "task_sha256"))
            != tuple(parent_payload[name] for name in ("task_id", "task_revision_id", "task_sha256"))
        ):
            _error("work packet parent binding differs")
        seen: set[str] = {str(payload["packet_id"])}
        cursor = parent
        while cursor.payload["parent_packet_id"] is not None:
            cursor_id = str(cursor.payload["packet_id"])
            if cursor_id in seen:
                _error("work packet parent chain contains a cycle")
            seen.add(cursor_id)
            next_packet = packets_by_id.get(str(cursor.payload["parent_packet_id"]))
            if next_packet is None:
                _error("work packet parent is missing")
            cursor = next_packet
        if str(cursor.payload["packet_id"]) in seen:
            _error("work packet parent chain contains a cycle")

    dispatches = _latest(
        tuple(candidate.values()), DISPATCH_REQUEST_V1, "dispatch_request_id",
    )
    executions = _latest(
        tuple(candidate.values()), EXECUTION_NODE_V1, "execution_id",
    )
    dispositions = _latest(
        tuple(candidate.values()), ENGINEERING_DISPOSITION_RECEIPT_V1, "receipt_id",
    )
    bindings = _latest(
        tuple(candidate.values()), WORK_DISPATCH_BINDING_V1, "dispatch_request_id",
    )
    gates = _of_type(candidate, WORK_DEFINITION_ENFORCEMENT_V1)
    binding_ids: dict[str, str] = {}
    for dispatch_request_id, binding in bindings.items():
        binding_id = str(binding.payload["binding_id"])
        prior_request = binding_ids.setdefault(
            binding_id,
            dispatch_request_id,
        )
        if prior_request != dispatch_request_id:
            _error("work binding ID is bound to multiple dispatch requests")
    result_receipts = _of_type(candidate, WORK_RESULT_RECEIPT_V1)
    result_by_packet: dict[str, str] = {}
    result_by_execution: dict[str, str] = {}
    result_by_disposition: dict[str, str] = {}
    for item in result_receipts:
        payload = item.payload
        result_id = str(payload["result_receipt_id"])
        for index, value, label in (
            (
                result_by_packet,
                str(payload["packet_id"]),
                "work packet",
            ),
            (
                result_by_execution,
                str(payload["producer_execution_id"]),
                "producer execution",
            ),
            (
                result_by_disposition,
                str(payload["engineering_disposition_receipt_id"]),
                "engineering disposition",
            ),
        ):
            prior_result = index.setdefault(value, result_id)
            if prior_result != result_id:
                _error(f"{label} has multiple work result receipts")
        result_task = tasks_by_revision.get(str(payload["task_revision_id"]))
        result_packet = packets_by_id.get(str(payload["packet_id"]))
        execution = executions.get(str(payload["producer_execution_id"]))
        disposition = dispositions.get(
            str(payload["engineering_disposition_receipt_id"]),
        )
        old_execution = old_objects.get(
            (
                EXECUTION_NODE_V1,
                str(payload["producer_execution_id"]),
            ),
        )
        batch_executions = [
            candidate_item
            for candidate_item in batch
            if (
                candidate_item.contract_type == EXECUTION_NODE_V1
                and candidate_item.payload["execution_id"]
                == payload["producer_execution_id"]
            )
        ]
        batch_dispositions = [
            candidate_item
            for candidate_item in batch
            if (
                candidate_item.contract_type
                == ENGINEERING_DISPOSITION_RECEIPT_V1
                and candidate_item.payload["receipt_id"]
                == payload["engineering_disposition_receipt_id"]
            )
        ]
        result_binding = (
            None
            if execution is None or execution.payload["dispatch_id"] is None
            else bindings.get(str(execution.payload["dispatch_id"]))
        )
        result_dispatch = (
            None
            if result_binding is None
            else dispatches.get(
                str(result_binding.payload["dispatch_request_id"]),
            )
        )
        if item in batch and (
            old_execution is None
            or len(batch_executions) != 1
            or batch_executions[0] != execution
            or len(batch_dispositions) != 1
            or batch_dispositions[0] != disposition
            or old_execution.payload["runtime_status"] != "stopped"
            or old_execution.payload["engineering_status"]
            in {"completed", "cancelled", "idle"}
            or old_execution.payload["dispatch_id"] is None
        ):
            _error(
                "work result receipt lacks one atomic stopped-to-idle transition",
            )
        if (
            result_task is None
            or result_packet is None
            or execution is None
            or disposition is None
            or result_binding is None
            or result_dispatch is None
            or (payload["task_id"], payload["task_sha256"])
            != (
                result_task.payload["task_id"],
                result_task.payload["task_sha256"],
            )
            or tuple(
                result_packet.payload[name]
                for name in ("task_id", "task_revision_id", "task_sha256")
            )
            != tuple(payload[name] for name in ("task_id", "task_revision_id", "task_sha256"))
            or payload["packet_sha256"]
            != result_packet.payload["packet_sha256"]
            or (
                item in batch
                and old_execution is not None
                and payload["expected_execution_payload_sha256"]
                != old_execution.payload_sha256
            )
            or disposition.payload["expected_execution_payload_sha256"]
            != payload["expected_execution_payload_sha256"]
            or execution.payload["task_id"] != payload["task_id"]
            or execution.payload["packet_id"] != payload["packet_id"]
            or execution.payload["dispatch_id"]
            != result_binding.payload["dispatch_request_id"]
            or execution.payload["provider"]
            not in result_binding.payload["provider_allowlist"]
            or tuple(
                result_binding.payload[name]
                for name in (
                    "task_id",
                    "task_revision_id",
                    "task_sha256",
                    "packet_id",
                    "packet_sha256",
                )
            )
            != tuple(
                payload[name]
                for name in (
                    "task_id",
                    "task_revision_id",
                    "task_sha256",
                    "packet_id",
                    "packet_sha256",
                )
            )
            or result_dispatch.payload["dispatch_request_id"]
            != result_binding.payload["dispatch_request_id"]
            or execution.payload["engineering_status"] != "idle"
            or execution.payload["runtime_status"] != "stopped"
            or execution.payload["updated_at"] != payload["recorded_at"]
            or disposition.payload["execution_id"] != payload["producer_execution_id"]
            or disposition.payload["observed_at"] != payload["recorded_at"]
            or disposition.payload["result_packet_id"] != payload["packet_id"]
        ):
            _error("work result receipt cross-record binding differs")

    batch_dispatches = {
        str(item.payload["dispatch_request_id"]): item
        for item in batch
        if item.contract_type == DISPATCH_REQUEST_V1
    }
    for binding in _of_type(candidate, WORK_DISPATCH_BINDING_V1):
        if binding not in batch:
            continue
        payload = binding.payload
        binding_packet = packets_by_id.get(str(payload["packet_id"]))
        dispatch = batch_dispatches.get(str(payload["dispatch_request_id"]))
        if request is None or dispatch is None or binding_packet is None:
            _error("work dispatch binding lacks its queued transaction dispatch")
        dispatch_payload = dispatch.payload
        if (
            payload["transaction_id"] != request["transaction_id"]
            or payload["command_id"] != request["command_id"]
            or dispatch_payload["state"] != "queued"
            or payload["dispatch_revision_id"] != dispatch_payload["dispatch_revision_id"]
            or payload["dispatch_payload_sha256"] != dispatch.payload_sha256
            or tuple(payload[name] for name in ("task_id", "packet_id", "department_id", "target_node_id", "manager_node_id", "parent_execution_id", "delegation_depth"))
            != tuple(dispatch_payload[name] for name in ("task_id", "packet_id", "department_id", "target_node_id", "manager_node_id", "parent_execution_id", "delegation_depth"))
            or tuple(payload[name] for name in ("task_id", "task_revision_id", "task_sha256", "packet_id", "packet_sha256", "prompt_ref", "context_manifest_ref", "department_id", "target_node_id", "manager_node_id", "parent_execution_id", "delegation_depth", "expires_at"))
            != tuple(binding_packet.payload[name] for name in ("task_id", "task_revision_id", "task_sha256", "packet_id", "packet_sha256", "prompt_ref", "context_manifest_ref", "department_id", "target_node_id", "manager_node_id", "parent_execution_id", "delegation_depth", "expires_at"))
            or payload["authority_scope_sha256"]
            != company_contract_sha256(
                binding_packet.payload["authority_scope"],
            )
            or payload["provider_allowlist"]
            != binding_packet.payload["authority_scope"]["provider_allowlist"]
        ):
            _error("work dispatch binding differs from its queued work definition")

    for dispatch in batch:
        if (
            dispatch.contract_type != DISPATCH_REQUEST_V1
            or dispatch.payload["state"] != "queued"
            or dispatch.payload["revision"] != 1
        ):
            continue
        payload = dispatch.payload
        queued_packet = packets_by_id.get(str(payload["packet_id"]))
        has_named_task = bool(
            task_revisions.get(str(payload["task_id"])),
        )
        if queued_packet is None:
            if has_named_task:
                _error(
                    "queued dispatch names a registered task without its packet",
                )
            if gates:
                _error(
                    "registered work enforcement rejects an unbound queue item",
                )
            continue
        if (
            queued_packet.payload["task_id"] != payload["task_id"]
            or str(payload["dispatch_request_id"]) not in bindings
        ):
            _error(
                "registered queued dispatch lacks its exact work binding",
            )

    if len(gates) > 1:
        _error("work definition enforcement gate is not singleton")
    gate_in_batch = [
        item for item in batch
        if item.contract_type == WORK_DEFINITION_ENFORCEMENT_V1
    ]
    if gate_in_batch:
        if request is None or len(gate_in_batch) != 1 or _of_type(old_objects, WORK_DEFINITION_ENFORCEMENT_V1):
            _error("work definition enforcement gate is not a one-time activation")
        if gate_in_batch[0].payload["previous_transaction_sha256"] != request["expected_transaction_head"]["transaction_sha256"]:
            _error("work definition enforcement gate transaction head differs")
        old_bindings = _latest(
            _of_type(old_objects, WORK_DISPATCH_BINDING_V1),
            WORK_DISPATCH_BINDING_V1,
            "dispatch_request_id",
        )
        old_dispatches = _latest(
            _of_type(old_objects, DISPATCH_REQUEST_V1), DISPATCH_REQUEST_V1,
            "dispatch_request_id",
        )
        if any(
            item.payload["state"] == "in_flight"
            and request_id not in old_bindings
            for request_id, item in old_dispatches.items()
        ):
            _error("work definition enforcement cannot activate over unbound in-flight dispatch")
    if gates:
        old_dispatches = _latest(
            _of_type(old_objects, DISPATCH_REQUEST_V1), DISPATCH_REQUEST_V1,
            "dispatch_request_id",
        )
        for request_id, dispatch in dispatches.items():
            previous = old_dispatches.get(request_id)
            if (
                previous is not None
                and previous.payload["state"] == "admitted"
                and dispatch.payload["state"] == "in_flight"
            ):
                dispatch_binding = bindings.get(request_id)
                if dispatch_binding is None:
                    _error(
                        "registered launch requires a durable work dispatch "
                        "binding",
                    )
                if (
                    _parsed_time(
                        str(dispatch_binding.payload["expires_at"]),
                    )
                    <= _parsed_time(str(dispatch.payload["updated_at"]))
                ):
                    _error(
                        "registered launch work dispatch binding is expired",
                    )
            if dispatch.payload["state"] != "dispatched":
                continue
            dispatch_binding = bindings.get(request_id)
            execution_id = dispatch.payload["execution_id"]
            execution = None if execution_id is None else executions.get(str(execution_id))
            if (
                dispatch_binding is None
                or execution is None
                or execution.payload["provider"]
                not in dispatch_binding.payload["provider_allowlist"]
            ):
                _error("registered launch provider is absent from the exact allowlist")


def _validate_provider_worker_projection(
    old_objects: Mapping[tuple[str, str], InvariantObject],
    batch: Sequence[InvariantObject],
    request: Mapping[str, Any] | None,
    receipt_state: str | None,
) -> None:
    """Validate provider-worker projections without asserting a provider launch.

    These joins intentionally use only projected immutable facts.  Live host
    paths, Git worktrees, and CAS document bytes are verified by the state
    owner, not reconstructed from this read-model reducer.
    """
    provider_types = frozenset({
        PROVIDER_CODEX_HOME_V1, PROVIDER_LAUNCH_BINDING_V1,
        PROVIDER_WORKER_IO_RECEIPT_V1, PROVIDER_WORKER_OPERATION_V1,
        PROVIDER_TURN_RESULT_RECEIPT_V1,
    })
    provider_batch = tuple(item for item in batch if item.contract_type in provider_types)
    if provider_batch and receipt_state != "committed":
        _error("provider-worker projections require a committed receipt")
    for item in provider_batch:
        key = (item.contract_type, _logical_key(item))
        prior = old_objects.get(key)
        if item.contract_type == PROVIDER_CODEX_HOME_V1 and prior is not None:
            payload, old = item.payload, prior.payload
            if (
                payload["revision"] != old["revision"] + 1
                or payload["previous_event_id"] != prior.event_id
                or payload["previous_payload_sha256"] != prior.payload_sha256
                or item.global_sequence <= prior.global_sequence
                or tuple(payload[field] for field in (
                    "home_id", "dispatch_request_id", "platform", "absolute_path",
                    "path_identity_sha256", "initial_inventory_sha256", "config_sha256",
                    "managed_config_sha256", "thread_config_sha256", "created_at",
                )) != tuple(old[field] for field in (
                    "home_id", "dispatch_request_id", "platform", "absolute_path",
                    "path_identity_sha256", "initial_inventory_sha256", "config_sha256",
                    "managed_config_sha256", "thread_config_sha256", "created_at",
                ))
                or payload["state"] not in {
                    "ready": {"active", "retired", "cleanup_failed"},
                    "active": {"retired", "cleanup_failed"},
                    "cleanup_failed": {"retired"},
                    "retired": set(),
                }.get(old["state"], set())
                or _parsed_time(str(payload["updated_at"])) <= _parsed_time(str(old["updated_at"]))
            ):
                _error("provider Codex home revision predecessor differs")
        if (
            item.contract_type == PROVIDER_CODEX_HOME_V1
            and prior is None
            and item.payload["revision"] != 1
        ):
            _error("provider Codex home genesis revision must be one")
        if item.contract_type == PROVIDER_CODEX_HOME_V1 and prior is None and item.payload["state"] == "active":
            _error("provider Codex home cannot begin active")
        if item.contract_type == PROVIDER_WORKER_OPERATION_V1 and prior is not None:
            payload, old = item.payload, prior.payload
            if (
                payload["revision"] != old["revision"] + 1
                or payload["previous_sha256"] != old["operation_sha256"]
                or payload["previous_state"] != old["state"]
                or item.global_sequence <= prior.global_sequence
                or tuple(payload[field] for field in (
                    "operation_id", "launch_binding_id", "launch_binding_sha256",
                    "dispatch_request_id", "dispatch_revision_id", "operation_kind",
                    "execution_id", "thread_id", "turn_id", "attempt", "created_at",
                )) != tuple(old[field] for field in (
                    "operation_id", "launch_binding_id", "launch_binding_sha256",
                    "dispatch_request_id", "dispatch_revision_id", "operation_kind",
                    "execution_id", "thread_id", "turn_id", "attempt", "created_at",
                ))
                or tuple(old["effect_receipt_ids"]) != tuple(
                    payload["effect_receipt_ids"][:len(old["effect_receipt_ids"])]
                )
                or _parsed_time(str(payload["updated_at"])) <= _parsed_time(str(old["updated_at"]))
            ):
                _error("provider worker operation revision predecessor differs")
        if (
            item.contract_type == PROVIDER_WORKER_OPERATION_V1
            and prior is None
            and item.payload["revision"] != 1
        ):
            _error("provider worker operation genesis revision must be one")

    candidate = dict(old_objects)
    for item in batch:
        candidate[(item.contract_type, _logical_key(item))] = item
    provider_present = any(item.contract_type in provider_types for item in candidate.values())
    if not provider_present:
        return

    manifests = _of_type(candidate, COMPANY_MANIFEST_V1)
    if len(manifests) != 1:
        _error("provider-worker projection requires one company manifest")
    manifest = manifests[0].payload
    homes = _latest(tuple(candidate.values()), PROVIDER_CODEX_HOME_V1, "home_id")
    launches = _latest(tuple(candidate.values()), PROVIDER_LAUNCH_BINDING_V1, "launch_binding_id")
    operations = _latest(tuple(candidate.values()), PROVIDER_WORKER_OPERATION_V1, "operation_id")
    dispatches = _latest(tuple(candidate.values()), DISPATCH_REQUEST_V1, "dispatch_request_id")
    bindings = _latest(tuple(candidate.values()), WORK_DISPATCH_BINDING_V1, "dispatch_request_id")
    packets = _latest(tuple(candidate.values()), WORK_PACKET_V1, "packet_id")
    policies = _latest(tuple(candidate.values()), ROUTE_POLICY_V1, "policy_id")
    executions = _latest(tuple(candidate.values()), EXECUTION_NODE_V1, "execution_id")
    receipts = _latest(tuple(candidate.values()), PROVIDER_WORKER_IO_RECEIPT_V1, "receipt_id")
    results = _latest(tuple(candidate.values()), PROVIDER_TURN_RESULT_RECEIPT_V1, "result_receipt_id")
    evidence_records = _latest(tuple(candidate.values()), EVIDENCE_RECORD_V1, "evidence_id")

    # These are partial-injective joins: a dispatch has at most one Home and
    # at most one launch, and a Home has at most one launch.  A ready Home
    # may intentionally have no launch; every launch must name that same
    # dispatch's Home.  Only an active Home needs one launch/process join.
    home_dispatch_ids: set[str] = set()
    for home_item in homes.values():
        dispatch_id = str(home_item.payload["dispatch_request_id"])
        if dispatch_id in home_dispatch_ids:
            _error("provider Codex homes share a dispatch request")
        home_dispatch_ids.add(dispatch_id)

    launch_home_ids: set[str] = set()
    launch_dispatch_ids: set[str] = set()
    for launch in launches.values():
        home_id = str(launch.payload["home_id"])
        dispatch_id = str(launch.payload["dispatch_request_id"])
        if home_id in launch_home_ids:
            _error("provider launch bindings share a Codex home")
        if dispatch_id in launch_dispatch_ids:
            _error("provider launch bindings share a dispatch request")
        launch_home_ids.add(home_id)
        launch_dispatch_ids.add(dispatch_id)

    for launch in launches.values():
        payload = launch.payload
        home = homes.get(str(payload["home_id"]))
        dispatch = dispatches.get(str(payload["dispatch_request_id"]))
        binding = bindings.get(str(payload["dispatch_request_id"]))
        policy = policies.get(str(payload["route_policy_id"]))
        if home is None or dispatch is None or binding is None or policy is None:
            _error("provider launch binding has a missing projected join")
        home_payload, dispatch_payload = home.payload, dispatch.payload
        binding_payload, policy_payload = binding.payload, policy.payload
        packet = packets.get(str(binding_payload["packet_id"]))
        if packet is None:
            _error("provider launch binding lacks its work packet")
        packet_payload = packet.payload
        if (
            home_payload["dispatch_request_id"] != payload["dispatch_request_id"]
            or home_payload["platform"] != payload["platform"]
            or tuple(payload[field] for field in (
                "work_dispatch_binding_id", "work_dispatch_binding_sha256",
            )) != tuple(binding_payload[field] for field in (
                "binding_id", "binding_sha256",
            ))
            or payload["provider"] not in binding_payload["provider_allowlist"]
            or payload["manifest_sha256"] != company_contract_sha256(manifest)
            or tuple(payload[field] for field in (
                "source_sha256", "config_sha256", "dependency_sha256",
            )) != tuple(packet_payload[field] for field in (
                "source_manifest_sha256", "config_manifest_sha256", "dependency_manifest_sha256",
            ))
            or payload["lock_domain_id"] != manifest["lock_domain_id"]
            or payload["git_common_dir_sha256"] != manifest["git_common_dir_sha256"]
            or payload["git_remote_sha256"] != manifest["remote_fingerprint_sha256"]
            or (payload["sandbox"] == "workspaceWrite" and not packet_payload["authority_scope"]["write_refs"])
        ):
            _error("provider launch binding projected facts differ")
        if launch in provider_batch:
            if (
                dispatch_payload["state"] != "admitted"
                or home_payload["state"] != "ready"
                or tuple(payload[field] for field in (
                    "dispatch_revision_id", "dispatch_revision", "dispatch_payload_sha256",
                )) != (
                    dispatch_payload["dispatch_revision_id"], dispatch_payload["revision"],
                    dispatch.payload_sha256,
                )
                or (payload["home_revision"], payload["home_sha256"])
                != (home_payload["revision"], home_payload["home_sha256"])
                or (payload["route_policy_revision"], payload["route_policy_sha256"])
                != (policy_payload["revision"], policy_payload["policy_sha256"])
                or dispatch_payload["route_policy_id"] != payload["route_policy_id"]
                or any(payload[field] not in policy_payload[allowed] for field, allowed in (
                    ("provider", "allowed_providers"), ("model", "allowed_models"),
                    ("effort", "allowed_efforts"),
                ))
            ):
                _error("new provider launch binding lacks its admitted projected facts")
        elif (
            home_payload["revision"] < payload["home_revision"]
            or policy_payload["revision"] < payload["route_policy_revision"]
            or (
                home_payload["revision"] == payload["home_revision"]
                and home_payload["home_sha256"] != payload["home_sha256"]
            )
            or (
                policy_payload["revision"] == payload["route_policy_revision"]
                and policy_payload["policy_sha256"] != payload["route_policy_sha256"]
            )
        ):
            _error("provider launch binding projected revision regressed")

    for home in homes.values():
        if str(home.payload["dispatch_request_id"]) not in dispatches:
            _error("provider Codex home lacks its dispatch request")

    operation_slots: set[tuple[Any, ...]] = set()
    for operation in operations.values():
        payload = operation.payload
        operation_launch = launches.get(str(payload["launch_binding_id"]))
        if operation_launch is None:
            _error("provider worker operation launch binding differs")
        if tuple(payload[field] for field in (
            "launch_binding_sha256", "dispatch_request_id", "dispatch_revision_id",
        )) != tuple(operation_launch.payload[field.removeprefix("launch_")] if field == "launch_binding_sha256" else operation_launch.payload[field] for field in (
            "launch_binding_sha256", "dispatch_request_id", "dispatch_revision_id",
        )):
            _error("provider worker operation launch binding differs")
        slot = tuple(payload[field] for field in (
            "launch_binding_id", "operation_kind", "execution_id", "thread_id", "turn_id",
        ))
        if slot in operation_slots:
            _error("provider worker operation would resend an existing logical operation")
        operation_slots.add(slot)

    by_operation: dict[str, list[InvariantObject]] = {}
    for receipt in receipts.values():
        payload = receipt.payload
        receipt_operation = operations.get(str(payload["operation_id"]))
        receipt_launch = launches.get(str(payload["launch_binding_id"]))
        if receipt_operation is None or receipt_launch is None:
            _error("provider worker IO receipt launch or operation differs")
        receipt_join = tuple(payload[field] for field in (
            "launch_binding_id", "launch_binding_sha256", "dispatch_request_id", "dispatch_revision_id",
        ))
        launch_join = (
            receipt_launch.payload["launch_binding_id"], receipt_launch.payload["binding_sha256"],
            receipt_launch.payload["dispatch_request_id"], receipt_launch.payload["dispatch_revision_id"],
        )
        operation_join = tuple(receipt_operation.payload[field] for field in (
            "launch_binding_id", "launch_binding_sha256", "dispatch_request_id", "dispatch_revision_id",
        ))
        if receipt_join != launch_join or receipt_join != operation_join:
            _error("provider worker IO receipt launch or operation differs")
        if tuple(payload[field] for field in (
            "execution_id", "thread_id", "turn_id",
        )) != tuple(receipt_operation.payload[field] for field in (
            "execution_id", "thread_id", "turn_id",
        )):
            _error("provider worker IO receipt execution subject differs")
        by_operation.setdefault(str(payload["operation_id"]), []).append(receipt)

    receipts_by_launch: dict[str, list[InvariantObject]] = {}
    for receipt in receipts.values():
        receipts_by_launch.setdefault(str(receipt.payload["launch_binding_id"]), []).append(receipt)
    for launch_receipts in receipts_by_launch.values():
        ordered = sorted(launch_receipts, key=lambda item: int(item.payload["sequence"]))
        if [int(item.payload["sequence"]) for item in ordered] != list(range(1, len(ordered) + 1)):
            _error("provider worker IO receipt sequence is not a contiguous prefix")
        if any(
            _parsed_time(str(later.payload["observed_at"])) < _parsed_time(str(earlier.payload["observed_at"]))
            for earlier, later in zip(ordered, ordered[1:])
        ):
            _error("provider worker IO receipt timestamps are not monotonic")
        terminal = [item for item in ordered if item.payload["phase"] == "terminal_sealed"]
        if len(terminal) > 1 or (terminal and terminal[0] != ordered[-1]):
            _error("provider worker terminal seal is not a final unique receipt")
        requests: dict[int, str] = {}
        responses: set[int] = set()
        initialized_pending = False
        initialized_written = False
        process_pending = False
        process_started = False
        thread_started = False
        turn_started = False
        terminal_observed = False
        process_exited = False
        for receipt in ordered:
            payload = receipt.payload
            phase = payload["phase"]
            if process_exited and phase != "terminal_sealed":
                _error("provider worker receipt follows process exit")
            if phase == "request_send_pending":
                request_id = int(payload["request_id"])
                if request_id in requests:
                    _error("provider worker request would resend an existing request")
                if not process_started or terminal_observed or process_exited:
                    _error("provider worker request precedes process start")
                if not requests and payload["method"] != "initialize":
                    _error("provider worker initialize must be the first request")
                if payload["method"] == "model/list" and not initialized_written:
                    _error("provider worker model list precedes initialized write")
                if payload["method"] == "thread/start" and not initialized_written:
                    _error("provider worker thread start precedes initialized write")
                if payload["method"] == "turn/start" and not thread_started:
                    _error("provider worker turn start precedes thread start")
                requests[request_id] = str(payload["method"])
            elif phase == "response_received":
                request_id = int(payload["request_id"])
                if (
                    requests.get(request_id) != payload["method"]
                    or request_id in responses
                ):
                    _error("provider worker response lacks one prior request")
                responses.add(request_id)
                if payload["method"] == "thread/start":
                    thread_started = True
                elif payload["method"] == "turn/start":
                    turn_started = True
            elif phase == "client_notification_send_pending":
                if not process_started or "initialize" not in {
                    method for request_id, method in requests.items()
                    if request_id in responses
                } or initialized_pending:
                    _error("provider worker would resend initialized notification")
                initialized_pending = True
            elif phase == "client_notification_written":
                if not initialized_pending or initialized_written:
                    _error("provider worker initialized write lacks one pending send")
                initialized_written = True
            elif phase == "process_start_pending":
                if process_pending or process_started or requests:
                    _error("provider worker process start is not a lawful prefix")
                process_pending = True
            elif phase == "process_started":
                if not process_pending or process_started:
                    _error("provider worker process start lacks one pending receipt")
                process_started = True
            elif phase == "host_process_observed":
                if not process_started:
                    _error("provider worker host process observation precedes start")
            elif phase == "notification_received":
                if not process_started:
                    _error("provider worker notification precedes process start")
                if payload["method"] == "turn/completed":
                    if not turn_started or terminal_observed:
                        _error("provider worker terminal observation is not lawful")
                    terminal_observed = True
            elif phase == "process_exit_observed":
                if not process_started or process_exited:
                    _error("provider worker process exit is not lawful")
                process_exited = True
            elif phase == "terminal_sealed":
                if not terminal_observed or not process_exited:
                    _error("provider worker terminal seal lacks terminal process evidence")
    for operation_id, operation in operations.items():
        if operation.payload["state"] == "prepared" and operation_id in by_operation:
            _error("prepared provider worker operation has durable IO")
    for operation_id, operation_receipts in by_operation.items():
        operation_payload = operations[operation_id].payload
        effect_ids = {str(value) for value in operation_payload["effect_receipt_ids"]}
        receipt_ids = {str(item.payload["receipt_id"]) for item in operation_receipts}
        if effect_ids != receipt_ids:
            _error("provider worker operation effect receipts differ from durable IO")
    for operation_id, operation in operations.items():
        if operation not in provider_batch or operation.payload["state"] != "effect_pending":
            continue
        pending_spec = {
            "process_start": ("process_start_pending", None),
            "initialize_request": ("request_send_pending", "initialize"),
            "initialized_notification": ("client_notification_send_pending", "initialized"),
            "model_list_request": ("request_send_pending", "model/list"),
            "thread_start_request": ("request_send_pending", "thread/start"),
            "turn_start_request": ("request_send_pending", "turn/start"),
            "turn_interrupt_request": ("request_send_pending", "turn/interrupt"),
        }.get(str(operation.payload["operation_kind"]))
        if pending_spec is None:
            continue
        pending_phase, pending_method = pending_spec
        pending = [
            receipt for receipt in by_operation.get(operation_id, [])
            if receipt in provider_batch
            and receipt.payload["phase"] == pending_phase
            and receipt.payload["method"] == pending_method
        ]
        if len(pending) != 1:
            _error("provider worker effect-pending lacks one atomic pending IO")

    for result in results.values():
        payload = result.payload
        result_operation = operations.get(str(payload["operation_id"]))
        result_terminal = receipts.get(str(payload["terminal_io_receipt_id"]))
        result_launch = launches.get(str(payload["launch_binding_id"]))
        result_agent = executions.get(str(payload["agent_execution_id"]))
        result_turn = executions.get(str(payload["turn_execution_id"]))
        if (
            result_operation is None or result_terminal is None
            or result_launch is None or result_agent is None or result_turn is None
        ):
            _error("provider turn result receipt binding differs")
        exits = [
            item for item in receipts.values()
            if (
                item.payload["phase"] == "process_exit_observed"
                and item.payload["launch_binding_id"] == payload["launch_binding_id"]
                and item.payload["execution_id"] == payload["turn_execution_id"]
                and item.payload["thread_id"] == payload["thread_id"]
                and item.payload["turn_id"] == payload["turn_id"]
            )
        ]
        if len(exits) != 1:
            _error("provider turn result receipt binding differs")
        evidence_id = f"provider-turn-idle-evidence-{payload['receipt_sha256']}"
        idle_evidence = evidence_records.get(evidence_id)
        disposition_at: str | None = None
        if idle_evidence is not None:
            evidence_payload = idle_evidence.payload
            owners = [
                execution for execution in executions.values()
                if evidence_id in execution.payload["evidence_ids"]
            ]
            expected_evidence = {
                "contract_type": EVIDENCE_RECORD_V1,
                "schema_version": 1,
                "company_id": payload["company_id"],
                "company_incarnation": payload["company_incarnation"],
                "lock_domain_generation": payload["lock_domain_generation"],
                "evidence_id": evidence_id,
                "execution_id": payload["turn_execution_id"],
                "claim_id": payload["result_receipt_id"],
                "evidence_class": "engineering_inference",
                "status": "observed",
                "artifact": payload["result_ref"],
                "command_sha256": None,
                "verification_sha256": payload["receipt_sha256"],
                "recorded_at": evidence_payload["recorded_at"],
                "provenance": "AOI_verified",
                "observation": {"state": "known", "reason": "observed"},
            }
            if (
                evidence_payload != expected_evidence
                or len(owners) != 1
                or owners[0].payload["execution_id"] != payload["turn_execution_id"]
            ):
                _error("provider turn idle evidence differs")
            disposition_at = str(evidence_payload["recorded_at"])
        elif result_turn.payload["engineering_status"] == "idle":
            _error("provider idle turn lacks durable disposition evidence")
        try:
            validate_provider_turn_result_lifecycle(
                payload, None, result_terminal.payload, exits[0].payload,
                result_operation.payload, result_launch.payload, result_agent.payload,
                result_turn.payload, disposition_at,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompanyInvariantError(
                "provider turn result receipt binding differs",
            ) from exc

    for home in homes.values():
        if home.payload["state"] != "active":
            continue
        matching_launches = {
            launch_id for launch_id, launch in launches.items()
            if launch.payload["home_id"] == home.payload["home_id"]
        }
        if len(matching_launches) != 1 or not any(
            receipt.payload["launch_binding_id"] in matching_launches
            and receipt.payload["phase"] in {"process_started", "host_process_observed"}
            and (process_operation := operations.get(str(receipt.payload["operation_id"]))) is not None
            and process_operation.payload["operation_kind"] == "process_start"
            and process_operation.payload["state"] in {"effect_observed", "committed"}
            for receipt in receipts.values()
        ):
            _error("provider Codex home active lacks launch process evidence")

    exit_receipts = [
        item for item in provider_batch
        if (
            item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1
            and item.payload["phase"] == "process_exit_observed"
        )
    ]
    exit_stop_ids: set[str] = set()
    for receipt in exit_receipts:
        if receipt_state != "committed":
            _error("provider worker process exit requires a committed transaction")
        launch = launches[str(receipt.payload["launch_binding_id"])]
        matching_cleanup = [
            home for home in provider_batch
            if (
                home.contract_type == PROVIDER_CODEX_HOME_V1
                and home.payload["home_id"] == launch.payload["home_id"]
                and home.payload["state"] in {"retired", "cleanup_failed"}
                and (previous := old_objects.get((PROVIDER_CODEX_HOME_V1, home.object_key))) is not None
                and previous.payload["state"] == "active"
            )
        ]
        if len(matching_cleanup) != 1:
            _error("provider worker process exit lacks one atomic Codex home cleanup")
        cleanup = matching_cleanup[0]
        active_home = old_objects[(PROVIDER_CODEX_HOME_V1, cleanup.object_key)]
        if (
            _parsed_time(str(active_home.payload["updated_at"]))
            > _parsed_time(str(receipt.payload["observed_at"]))
            or cleanup.payload["updated_at"] != receipt.payload["observed_at"]
        ):
            _error("provider worker process exit Codex home causality differs")

        # The only runtime truth carried by process exit is that every exact
        # active execution for this launch stopped.  There is deliberately no
        # engineering disposition here: B50 owns that boundary.
        exact_agents = {
            str(node.payload["execution_id"]): node
            for node in executions.values()
            if (
                node.payload["execution_kind"] == "agent"
                and node.payload["dispatch_id"]
                == launch.payload["dispatch_request_id"]
                and node.payload["carrier_id"] is not None
                and all(
                    node.payload[field] == launch.payload[field]
                    for field in ("provider", "model", "effort")
                )
            )
        }
        exact_turns: dict[str, InvariantObject] = {}
        for node in executions.values():
            if (
                node.payload["execution_kind"] != "turn"
                or node.payload["registration_id"]
                != launch.payload["launch_binding_id"]
            ):
                continue
            parent = executions.get(str(node.payload["parent_execution_id"]))
            if (
                parent is None
                or str(parent.payload["execution_id"]) not in exact_agents
                or node.payload["thread_id"] != parent.payload["thread_id"]
                or node.payload["carrier_id"] != parent.payload["carrier_id"]
                or node.payload["carrier_id"] is None
                or any(
                    candidate.payload[field] != launch.payload[field]
                    for candidate in (parent, node)
                    for field in ("provider", "model", "effort")
                )
            ):
                _error("provider exit turn parent join differs")
            exact_turns[str(node.payload["execution_id"])] = node

        expected_ids = {
            execution_id
            for execution_id in {*exact_agents, *exact_turns}
            if (
                (previous := old_objects.get((EXECUTION_NODE_V1, execution_id)))
                is not None
                and previous.payload["runtime_status"] in _ACTIVE_EXECUTION
            )
        }
        observed_ids = {
            str(item.payload["execution_id"])
            for item in batch
            if (
                item.contract_type == EXECUTION_NODE_V1
                and str(item.payload["execution_id"]) in expected_ids
                and _provider_exit_runtime_stop_is_observed(
                    item, old_objects[(EXECUTION_NODE_V1, str(item.payload["execution_id"]))].payload,
                    old_objects, batch, request,
                )
            )
        }
        if observed_ids != expected_ids:
            _error("provider worker process exit lacks exact active runtime stops")
        exit_stop_ids.update(expected_ids)

    for item in batch:
        if item.contract_type != EXECUTION_NODE_V1:
            continue
        if request is None:
            continue
        wrapper = next((
            event for event in request["events"]
            if event["event_id"] == item.event_id
        ), None)
        if (
            wrapper is not None
            and wrapper["event_type"] == "execution.provider_exit.stopped"
            and str(item.payload["execution_id"]) not in exit_stop_ids
        ):
            _error("provider worker process exit has an unrelated runtime stop")

    for home_id, home in homes.items():
        previous = old_objects.get((PROVIDER_CODEX_HOME_V1, home_id))
        if (
            home not in provider_batch
            or previous is None
            or previous.payload["state"] != "active"
            or home.payload["state"] not in {"retired", "cleanup_failed"}
        ):
            continue
        matching_launches = {
            launch_id for launch_id, launch in launches.items()
            if launch.payload["home_id"] == home.payload["home_id"]
        }
        if not any(
            receipt.payload["launch_binding_id"] in matching_launches
            and receipt.payload["phase"] == "process_exit_observed"
            for receipt in exit_receipts
        ):
            _error("provider Codex home cleanup lacks one atomic process exit")

    result_batch = [item for item in provider_batch if item.contract_type == PROVIDER_TURN_RESULT_RECEIPT_V1]
    if result_batch and any(item.contract_type == WORK_RESULT_RECEIPT_V1 for item in batch):
        _error("provider turn result cannot imply a work result receipt")
    result_execution_ids = {
        str(item.payload[field])
        for item in result_batch
        for field in ("agent_execution_id", "turn_execution_id")
    }
    for result in result_batch:
        payload = result.payload
        agent_payload = executions[str(payload["agent_execution_id"])].payload
        turn_payload = executions[str(payload["turn_execution_id"])].payload
        if (
            turn_payload["runtime_status"] != "stopped"
        ):
            _error("new provider turn result must not infer engineering completion")
    if any(
        item.contract_type == EXECUTION_NODE_V1
        and str(item.payload["execution_id"]) in result_execution_ids
        and item.payload["engineering_status"] in {"completed", "cancelled"}
        for item in batch
    ):
        _error("provider turn result cannot imply engineering completion")

    if request is None:
        return
    wrappers = {str(event["event_id"]): event for event in request["events"]}
    for item in provider_batch:
        wrapper = wrappers.get(item.event_id)
        if wrapper is None:
            _error("provider-worker projection lacks its event envelope")
        payload = item.payload
        if item.contract_type == PROVIDER_CODEX_HOME_V1:
            envelope = ("execution", f"provider.codex_home.{payload['state']}", "AOI_verified", payload["updated_at"])
        elif item.contract_type == PROVIDER_LAUNCH_BINDING_V1:
            envelope = ("execution", "provider.launch.bound", "AOI_verified", payload["created_at"])
        elif item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1:
            envelope = ("evidence", "provider.worker.io.persisted", payload["provenance"], payload["observed_at"])
        elif item.contract_type == PROVIDER_WORKER_OPERATION_V1:
            envelope = ("execution", f"provider.worker.operation.{payload['state']}", "AOI_verified", payload["updated_at"])
        else:
            envelope = ("evidence", "provider.turn.result.observed", payload["provenance"], payload["recorded_at"])
        _validate_lifecycle_event(item, wrapper, stream=envelope[0], event_type=envelope[1], provenance=envelope[2], recorded_at=envelope[3])


def validate_provider_turn_result_lifecycle(
    receipt: Mapping[str, Any],
    document: Mapping[str, Any] | None,
    terminal: Mapping[str, Any],
    process_exit: Mapping[str, Any],
    operation: Mapping[str, Any],
    launch: Mapping[str, Any],
    agent: Mapping[str, Any],
    turn: Mapping[str, Any],
    disposition_at: str | None = None,
) -> None:
    """Validate the exact durable result and stopped-provider lifecycle join.

    This is deliberately pure so append preflight, the public idle path, and
    idempotent replay cannot drift on completed-result truth.
    """
    shared = (
        "company_id", "company_incarnation", "lock_domain_generation",
        "launch_binding_id", "launch_binding_sha256", "operation_id",
        "agent_execution_id", "turn_execution_id", "thread_id", "turn_id",
        "terminal_status",
    )
    if (
        (document is not None and any(receipt[field] != document[field] for field in shared))
        or receipt["terminal_status"] != "completed"
        or receipt["result_ref"]["availability"] != "available"
        or (document is not None and (
            document["availability"] != "available"
            or document["items_view"] != "summary"
            or document["reason"] != "observed"
            or not document["agent_message_items"]
        ))
        or terminal["channel"] != "process"
        or terminal["phase"] != "terminal_sealed"
        or terminal["provenance"] != "adapter_receipt_persisted"
        or terminal["observation"] != {"state": "known", "reason": "observed"}
        or tuple(receipt[field] for field in (
            "operation_id", "launch_binding_id", "launch_binding_sha256",
            "thread_id", "turn_id",
        )) != tuple(terminal[field] for field in (
            "operation_id", "launch_binding_id", "launch_binding_sha256",
            "thread_id", "turn_id",
        ))
        or terminal["execution_id"] != receipt["turn_execution_id"]
        or process_exit["channel"] != "process"
        or process_exit["phase"] != "process_exit_observed"
        or process_exit["provenance"] != "adapter_receipt_persisted"
        or process_exit["observation"] != {"state": "known", "reason": "observed"}
        or tuple(process_exit[field] for field in (
            "launch_binding_id", "launch_binding_sha256", "thread_id", "turn_id",
        )) != tuple(receipt[field] for field in (
            "launch_binding_id", "launch_binding_sha256", "thread_id", "turn_id",
        ))
        or process_exit["execution_id"] != receipt["turn_execution_id"]
        or operation["operation_kind"] != "result_extraction"
        or operation["state"] != "committed"
        or operation["result_receipt_id"] != receipt["result_receipt_id"]
        or tuple(operation[field] for field in ("execution_id", "thread_id", "turn_id"))
        != tuple(receipt[field] for field in ("turn_execution_id", "thread_id", "turn_id"))
        or agent["execution_kind"] != "agent"
        or agent["dispatch_id"] != launch["dispatch_request_id"]
        or agent["thread_id"] != receipt["thread_id"]
        or agent["carrier_id"] is None
        or turn["execution_kind"] != "turn"
        or turn["registration_id"] != launch["launch_binding_id"]
        or turn["parent_execution_id"] != agent["execution_id"]
        or turn["thread_id"] != receipt["thread_id"]
        or turn["turn_id"] != receipt["turn_id"]
        or turn["carrier_id"] != agent["carrier_id"]
        or any(
            node[field] != launch[field]
            for node in (agent, turn)
            for field in ("provider", "model", "effort")
        )
        or agent["runtime_status"] != "stopped"
        or turn["runtime_status"] != "stopped"
        or any(
            _parsed_time(str(receipt["recorded_at"])) < _parsed_time(str(value))
            for value in (
                terminal["observed_at"], process_exit["observed_at"],
                operation["updated_at"],
            )
        )
        or (
            disposition_at is None
            and _parsed_time(str(receipt["recorded_at"]))
            < _parsed_time(str(turn["updated_at"]))
        )
        or (
            disposition_at is not None
            and any(
                _parsed_time(disposition_at) < _parsed_time(str(value))
                for value in (
                    receipt["recorded_at"], process_exit["observed_at"],
                )
            )
        )
    ):
        raise ValueError("provider turn result lifecycle differs")


def reduce_company_invariants(
    current: Sequence[InvariantObject], uncertain: Sequence[UncertainDispatch],
    transition: InvariantTransition | None = None,
) -> InvariantProjection:
    """Reduce a transaction independently of event order, without side effects."""
    objects_by_key = _normalize_current(current)
    shadows = _normalize_shadows(uncertain)
    old_objects = tuple(objects_by_key.values())
    old_dispatches = _latest(old_objects, DISPATCH_REQUEST_V1, "dispatch_request_id")
    _validate_chief_graph(objects_by_key)
    _validate_department_graph(objects_by_key)

    receipt_state: str | None = None
    request: Mapping[str, Any] | None = None
    requested_dispatches: list[InvariantObject] = []
    batch: list[InvariantObject] = []
    if transition is not None:
        if type(transition) is not InvariantTransition:
            _error("invariant transition receipt state is invalid")
        try:
            valid_transition = (
                type(transition.request) is FrozenJsonMapping
                and type(transition.receipt_state) is str
                and transition.receipt_state in _RECEIPT_STATES
            )
        except (AttributeError, FrozenJsonError):
            valid_transition = False
        if not valid_transition:
            _error("invariant transition receipt state is invalid")
        receipt_state = transition.receipt_state
        try:
            request = validate_company_transaction_request(
                thaw_json_payload(transition.request),
            )
        except (CompanyContractError, FrozenJsonError) as exc:
            raise CompanyInvariantError(f"transaction request is invalid: {exc}") from exc
        source_sequence = request["expected_transaction_head"]["global_sequence"] + 1
        for event in request["events"]:
            payload = event["payload"]
            if not isinstance(payload, Mapping) or "contract_type" not in payload:
                continue
            try:
                contract = validate_company_contract(payload)
            except CompanyContractError as exc:
                raise CompanyInvariantError(f"transaction event payload is invalid: {exc}") from exc
            item = InvariantObject(contract["contract_type"], _payload_logical_key(contract, str(event["event_id"])),
                                   event["event_id"], source_sequence, event["payload_sha256"], contract)
            batch.append(item)
            if item.contract_type == DISPATCH_REQUEST_V1:
                if item.payload["command_id"] != request["command_id"]:
                    _error(
                        "DispatchRequest command differs from its transaction",
                    )
                requested_dispatches.append(item)
        seen_batch: set[tuple[str, str]] = set()
        for item in batch:
            key = (item.contract_type, item.object_key)
            if key in seen_batch:
                _error("transaction has duplicate invariant object revisions")
            seen_batch.add(key)
        _validate_append_once_projection_ids(objects_by_key, batch)
        _validate_work_definitions(objects_by_key, batch, request)
        _validate_provider_worker_projection(
            objects_by_key, batch, request, receipt_state,
        )
        _validate_transaction_authority(
            objects_by_key,
            batch,
            request,
        )
        _validate_execution_registration_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_department_lifecycle_transition(
            objects_by_key,
            batch,
            request,
        )
        _validate_provider_lifecycle_transition(
            objects_by_key,
            batch,
            request,
        )
        _validate_provider_telemetry_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_runtime_observation_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_department_dispatch_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_external_job_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_department_execution_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_chief_execution_transition(
            objects_by_key,
            batch,
            request,
            receipt_state,
        )
        _validate_takeover_transition(
            objects_by_key,
            batch,
            request,
        )
        _validate_carrier_revisions(
            objects_by_key,
            batch,
            request,
        )
        _validate_execution_revisions(
            objects_by_key,
            batch,
            request,
        )
        try:
            validate_relevant_write_admission_invariants(
                old_objects,
                batch,
                shadows,
                request,
                receipt_state,
            )
        except WriteAdmissionInvariantError as exc:
            raise CompanyInvariantError(
                f"write admission invariant is invalid: {exc}",
            ) from exc
        if receipt_state == "committed":
            for item in batch:
                objects_by_key[(item.contract_type, _logical_key(item))] = item
        elif receipt_state in {"effect_unknown", "reconcile_required"}:
            additions: list[UncertainDispatch] = []
            for item in requested_dispatches:
                payload = item.payload
                additions.append(UncertainDispatch(payload["reservation_id"], payload["dispatch_request_id"],
                    item.event_id, source_sequence, request["transaction_id"], request["command_id"],
                    receipt_state, payload["state"], item.payload_sha256, payload))
            shadows = _normalize_shadows((*shadows, *additions))

    if transition is None:
        _validate_work_definitions(objects_by_key, (), None)
        _validate_provider_worker_projection(objects_by_key, (), None, None)
        try:
            validate_relevant_write_admission_invariants(
                old_objects,
                (),
                shadows,
                None,
                None,
            )
        except WriteAdmissionInvariantError as exc:
            raise CompanyInvariantError(
                f"write admission invariant is invalid: {exc}",
            ) from exc

    final_objects = tuple(objects_by_key.values())
    _validate_chief_graph(objects_by_key)
    _validate_department_graph(objects_by_key)
    nodes = _latest(final_objects, ORGANIZATION_NODE_V1, "node_id")
    carriers = _latest(final_objects, CARRIER_BINDING_V1, "carrier_id")
    executions = _latest(final_objects, EXECUTION_NODE_V1, "execution_id")
    external_jobs = _latest(final_objects, EXTERNAL_JOB_V1, "job_id")
    mutation_intents = _latest(
        final_objects,
        MUTATION_INTENT_V1,
        "intent_id",
    )
    authority_grants = _latest(
        final_objects,
        AUTHORITY_GRANT_V1,
        "grant_id",
    )
    dispatches = _latest(final_objects, DISPATCH_REQUEST_V1, "dispatch_request_id")
    provider_receipts = _latest(
        final_objects,
        PROVIDER_LIFECYCLE_RECEIPT_V1,
        "receipt_id",
    )
    external_job_effect_receipts = _latest(
        final_objects,
        EXTERNAL_JOB_EFFECT_RECEIPT_V1,
        "receipt_id",
    )
    evidence_records = _latest(
        final_objects,
        EVIDENCE_RECORD_V1,
        "evidence_id",
    )
    if receipt_state == "committed":
        _validate_execution_graph(
            executions,
            nodes,
            carriers,
        )
        _validate_external_job_graph(
            external_jobs,
            mutation_intents,
            executions,
            authority_grants,
            carriers,
            external_job_effect_receipts,
        )

    for request_id, item in dispatches.items():
        previous = old_dispatches.get(request_id)
        new_revision = (
            previous is None
            or item.event_id != previous.event_id
        )
        if previous is not None and item.event_id == previous.event_id:
            if item != previous:
                _error("dispatch event identity has divergent bytes")
        else:
            _validate_revision(previous, item)
        _node_check(
            item.payload,
            nodes,
            require_dispatched_active=new_revision,
        )
        _validate_dispatched(
            item.payload,
            executions,
            carriers,
            provider_receipts,
            evidence_records,
        )

    # A terminal receipt with an uncertain external effect never promotes its
    # requested revision into current_objects.  Each shadow must therefore be
    # a legal alternative effect_unknown successor of the still-current head.
    shadow_bases = old_dispatches if receipt_state == "committed" else dispatches
    for shadow in shadows:
        shadow_item = InvariantObject(
            DISPATCH_REQUEST_V1,
            shadow.dispatch_request_id,
            shadow.source_event_id,
            shadow.source_global_sequence,
            shadow.payload_sha256,
            shadow.payload,
        )
        _validate_revision(
            shadow_bases.get(shadow.dispatch_request_id),
            shadow_item,
        )
        _node_check(shadow.payload, nodes)

    _validate_unique_bindings(dispatches, executions, shadows)
    if receipt_state == "committed":
        shadows = _validate_resolution(old_dispatches, shadows, dispatches)
    capacity, fanout, fanout_complete, unattributed = _capacity(
        carriers,
        dispatches,
        executions,
        nodes,
        shadows,
    )
    if (
        receipt_state == "committed"
        and any(
            len(carrier_ids) > 1
            for carrier_ids in _provider_session_holders(
                carriers,
                executions,
            ).values()
        )
    ):
        _error(
            "provider session has multiple current carrier holders",
        )
    if capacity > MAX_ACTIVE_CARRIERS:
        _error("company active carrier capacity exceeded")
    if any(count > MAX_MANAGER_ACTIVE_FANOUT for _, count in fanout):
        _error("manager active fanout exceeded")
    if (
        not fanout_complete
        and receipt_state == "committed"
        and any(
            item.payload["state"] in _HELD | {"dispatched"}
            for item in requested_dispatches
        )
    ):
        _error("manager active fanout is unattributed; admission is unsafe")
    dispatch_items = tuple(sorted(dispatches.values(), key=lambda item: item.payload["dispatch_request_id"]))
    visible_dispatches = [
        item
        for item in dispatch_items
        if item.payload["state"] in {
            "effect_unknown",
            "in_flight",
            "admitted",
            "queued",
        }
    ]
    state_priority = {
        "effect_unknown": 0,
        "in_flight": 1,
        "admitted": 2,
        "queued": 3,
    }
    shadows_sorted = _normalize_shadows(shadows)
    frozen_reservations = {
        shadow.reservation_id
        for shadow in shadows_sorted
    }
    queue_items: tuple[QueueItem, ...] = (
        *shadows_sorted,
        *sorted(
            (
                item
                for item in visible_dispatches
                if str(item.payload["reservation_id"]) not in frozen_reservations
            ),
            key=lambda item: (
                state_priority[str(item.payload["state"])],
                str(item.payload["dispatch_request_id"]),
            ),
        ),
    )
    return InvariantProjection(
        objects=tuple(sorted(final_objects, key=lambda item: (item.contract_type, item.object_key, item.global_sequence, item.event_id))),
        dispatch_requests=dispatch_items, queue_items=queue_items, company_capacity=capacity,
        manager_capacity=fanout,
        manager_capacity_complete=fanout_complete,
        unattributed_active=unattributed,
        unresolved_shadows=shadows_sorted,
    )
