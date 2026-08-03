"""Owner-verified, observation-only readiness facts for runtime policy V2.

The exact current ledger head is replayed through the invariant reducer.  This
module never activates policy, admits work, mutates state, proves provider
transport, or proves retiring-Chief writer quiescence.  Its trust boundary
rejects caller snapshots and ordinary instance-method shadows; it does not
claim protection from class monkeypatching, ``ctypes``, or private-state edits.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from typing import Any, NamedTuple, Never, cast

from .contracts import (
    AUTHORITY_GRANT_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    DEPARTMENT_IDENTITY_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    MAX_CONTRACT_BYTES,
    MAX_LIST_ITEMS,
    ORGANIZATION_NODE_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from .invariants import InvariantObject
from .readmodel import ProjectedObject
from .runtime_policy import (
    RuntimePolicyDefinitionV2,
    runtime_policy_definition_v2,
    validate_runtime_policy_definition_v2,
)
from .runtime_policy_readiness_state import (
    RuntimePolicyReadinessStateError,
    VerifiedRuntimePolicyContextV1,
    plain_projected_payload,
    verified_runtime_policy_context,
)
from .state import CompanyStateOwner


RUNTIME_POLICY_READINESS_OBSERVATION_V1 = "runtime_policy_readiness_observation_v1"
RUNTIME_POLICY_READINESS_DERIVATION_V1 = "owner-current-head-full-reducer-v1"
LEGACY_ACTIVE_CARRIER_LIMIT = 16
LEGACY_DELEGATION_DEPTH_LIMIT = 6

_ACTIVE_RUNTIME = frozenset({"running", "telemetry_silent", "unknown"})
_HELD_DISPATCH = frozenset({"admitted", "in_flight", "effect_unknown"})
_ZERO_SHA256 = "0" * 64
_REPORT_DOMAIN = "aoi.company.runtime-policy-readiness-observation.v1"
_WITNESS_DOMAIN = "aoi.company.runtime-policy-readiness-witness.v1"
_SESSION_SLOT_DOMAIN = "aoi.company.runtime-policy-session-slot.v1"
_CHIEF_ROLES = frozenset({"chief", "chief_turn"})

class RuntimePolicyReadinessError(CompanyContractError):
    """The exact current company head cannot yield a complete observation."""

class RuntimePolicySourceWitnessV1(NamedTuple):
    source_kind: str
    contract_type: str
    object_key: str
    record_id: str
    event_id: str
    global_sequence: int
    payload_sha256: str

class RuntimePolicyChiefCoverageV1(NamedTuple):
    actor_id: str | None
    carrier_id: str | None
    physical_slot_id: str | None
    execution_ids: tuple[str, ...]
    runtime_statuses: tuple[str, ...]
    coverage_state: str
    reason_codes: tuple[str, ...]

class RuntimePolicySubordinateSlotV1(NamedTuple):
    physical_slot_id: str
    holder_execution_ids: tuple[str, ...]
    department_id: str
    role_class: str
    delegation_depth: int
    observation_quality: str

class RuntimePolicyHoldV1(NamedTuple):
    hold_kind: str
    holder_id: str
    reason_codes: tuple[str, ...]

class RuntimePolicyDepthObservationV1(NamedTuple):
    execution_id: str
    raw_depth: int
    role: str
    department_id: str | None
    engineering_status: str
    runtime_status: str
    lifecycle_class: str

class RuntimePolicyReadinessObservationV1(NamedTuple):
    document_type: str
    schema_version: int
    derivation_algorithm: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    cursor: int
    head_sha256: str
    currentness_semantics: str
    policy_definition_sha256: str
    activation_state: str
    admission_state: str
    operational_effect: str
    legacy_active_carrier_limit: int
    legacy_delegation_depth_limit: int
    candidate_subordinate_carrier_limit: int
    candidate_current_admitted_max_depth: int
    current_chief_state: str
    current_chief: tuple[RuntimePolicyChiefCoverageV1, ...]
    retiring_candidates: tuple[RuntimePolicyChiefCoverageV1, ...]
    writer_quiescence_state: str
    transport_capability_state: str
    subordinate_occupied_lower_bound: int
    subordinate_capacity_quality: str
    subordinate_slots: tuple[RuntimePolicySubordinateSlotV1, ...]
    holds: tuple[RuntimePolicyHoldV1, ...]
    over_depth: tuple[RuntimePolicyDepthObservationV1, ...]
    blockers: tuple[str, ...]
    source_witnesses: tuple[RuntimePolicySourceWitnessV1, ...]
    source_witness_sha256: str
    observation_sha256: str

    def to_dict(self) -> dict[str, object]:
        return _report_dict(self)

def _fail(message: str) -> Never:
    raise RuntimePolicyReadinessError(message)

def _wire(value: Any) -> Any:
    """Return the JSON-facing form of an internally constructed value object."""

    named_types = {
        RuntimePolicyChiefCoverageV1,
        RuntimePolicyDepthObservationV1,
        RuntimePolicyHoldV1,
        RuntimePolicyReadinessObservationV1,
        RuntimePolicySourceWitnessV1,
        RuntimePolicySubordinateSlotV1,
    }
    if type(value) in named_types:
        fields = type(value)._fields
        if tuple.__len__(value) != len(fields):
            _fail("runtime-policy readiness nested value shape is invalid")
        return {field: _wire(getattr(value, field)) for field in fields}
    if type(value) is tuple:
        if len(value) > MAX_LIST_ITEMS:
            _fail("runtime-policy readiness nested collection exceeds bounded limits")
        return [_wire(member) for member in value]
    if value is None or type(value) in {int, str}:
        return value
    _fail("runtime-policy readiness nested value type is invalid")

def _verified_context(state: CompanyStateOwner) -> VerifiedRuntimePolicyContextV1:
    try:
        return verified_runtime_policy_context(state)
    except RuntimePolicyReadinessStateError as exc:
        raise RuntimePolicyReadinessError(str(exc)) from exc

def _by_type(
    objects: Sequence[InvariantObject], contract_type: str
) -> dict[str, InvariantObject]:
    return {
        item.object_key: item
        for item in objects
        if item.contract_type == contract_type
    }

def _session_slot(provider: object, session_id: object, availability: object) -> str | None:
    if (
        type(provider) is not str or type(session_id) is not str or not session_id
        or availability != "available"
    ):
        return None
    digest = company_contract_sha256({
        "derivation_domain": _SESSION_SLOT_DOMAIN,
        "provider": provider,
        "session_id": session_id,
    })
    return f"provider-session:{digest}"

def _role_class(
    execution: InvariantObject,
    *,
    executions: Mapping[str, InvariantObject],
    nodes: Mapping[str, InvariantObject],
    identities: Mapping[str, InvariantObject],
    policy: RuntimePolicyDefinitionV2,
) -> tuple[str, str, int, tuple[tuple[str, str], ...]] | None:
    payload = execution.payload
    depth = payload.get("delegation_depth")
    execution_key = (execution.contract_type, execution.object_key)
    if payload.get("execution_kind") == "turn":
        parent_id = payload.get("parent_execution_id")
        parent = executions.get(parent_id) if type(parent_id) is str else None
        if parent is None or any(
            payload.get(field) != parent.payload.get(field)
            for field in (
                "carrier_id", "department_id", "delegation_depth",
                "organization_node_id", "role",
            )
        ):
            return None
        parent_class = _role_class(
            parent, executions=executions, nodes=nodes,
            identities=identities, policy=policy,
        )
        if parent_class is None:
            return None
        dependencies = set(parent_class[3])
        dependencies.add(execution_key)
        return (
            parent_class[0], parent_class[1], parent_class[2],
            tuple(sorted(dependencies)),
        )
    node_id = payload.get("organization_node_id")
    if type(depth) is not int or type(node_id) is not str or depth not in {1, 2, 3}:
        return None
    node = nodes.get(node_id)
    if node is None or node.payload.get("delegation_depth") != depth:
        return None
    department_id = node.payload.get("department_id")
    if type(department_id) is not str or payload.get("department_id") != department_id:
        return None
    role = payload.get("role")
    if role != node.payload.get("role"):
        return None
    if depth == 1:
        identity = identities.get(department_id)
        if (
            type(role) is not str
            or role not in policy.working_lead_roles
            or identity is None
            or identity.payload.get("lead_node_id") != node_id
        ):
            return None
        dependencies = {
            execution_key,
            (node.contract_type, node.object_key),
            (identity.contract_type, identity.object_key),
        }
        return ("working_lead", department_id, depth, tuple(sorted(dependencies)))
    expected = "worker" if depth == 2 else "reviewer"
    parent_id = payload.get("parent_execution_id")
    parent = executions.get(str(parent_id)) if type(parent_id) is str else None
    expected_parent = "working_lead" if depth == 2 else "worker"
    parent_class = (
        _role_class(
            parent, executions=executions, nodes=nodes,
            identities=identities, policy=policy,
        )
        if parent is not None else None
    )
    if (
        role != expected
        or parent is None
        or parent.payload.get("department_id") != department_id
        or parent.payload.get("delegation_depth") != depth - 1
        or parent_class is None
        or parent_class[0] != expected_parent
    ):
        return None
    dependencies = set(parent_class[3])
    dependencies.update({execution_key, (node.contract_type, node.object_key)})
    return (expected, department_id, depth, tuple(sorted(dependencies)))

def _chief_coverage(
    *, actor_id: object, carrier_id: object, slot_id: str | None,
    executions: Sequence[InvariantObject], state: str, reasons: Sequence[str],
) -> RuntimePolicyChiefCoverageV1:
    return RuntimePolicyChiefCoverageV1(
        actor_id=actor_id if type(actor_id) is str else None,
        carrier_id=carrier_id if type(carrier_id) is str else None,
        physical_slot_id=slot_id,
        execution_ids=tuple(sorted(str(item.payload["execution_id"]) for item in executions)),
        runtime_statuses=tuple(sorted({str(item.payload["runtime_status"]) for item in executions})),
        coverage_state=state,
        reason_codes=tuple(sorted(set(reasons))),
    )

def _witness(
    item: ProjectedObject,
    payload_sha256: str,
) -> RuntimePolicySourceWitnessV1:
    return RuntimePolicySourceWitnessV1(
        "projected_object", item.contract_type, item.object_key, item.record_id,
        item.event_id, item.global_sequence, payload_sha256,
    )

def _report_dict(value: RuntimePolicyReadinessObservationV1) -> dict[str, object]:
    return cast(dict[str, object], _wire(value))

def derive_runtime_policy_readiness(
    state: CompanyStateOwner,
) -> RuntimePolicyReadinessObservationV1:
    """Derive one exact-current-head blocker inventory with no runtime effect."""

    context = _verified_context(state)
    policy = validate_runtime_policy_definition_v2(runtime_policy_definition_v2())
    objects = context.objects
    manifests = _by_type(objects, COMPANY_MANIFEST_V1)
    terms = _by_type(objects, CHIEF_TERM_V1)
    carriers = _by_type(objects, CARRIER_BINDING_V1)
    grants = _by_type(objects, AUTHORITY_GRANT_V1)
    executions = _by_type(objects, EXECUTION_NODE_V1)
    nodes = _by_type(objects, ORGANIZATION_NODE_V1)
    identities = _by_type(objects, DEPARTMENT_IDENTITY_V1)
    dispatches = _by_type(objects, DISPATCH_REQUEST_V1)

    consulted: set[tuple[str, str]] = set()
    for item in manifests.values():
        consulted.add((item.contract_type, item.object_key))

    blockers = {
        "legacy_runtime_policy_16_6_active",
        "runtime_policy_v2_not_activated",
        "admission_authority_unavailable",
        "transport_capability_unavailable",
        "writer_quiescence_contract_unavailable",
    }
    holds: dict[tuple[str, str], set[str]] = {}

    def hold(kind: str, holder: str, *reasons: str) -> None:
        holds.setdefault((kind, holder), set()).update(reasons)

    term_items = list(terms.values())
    current_chief: tuple[RuntimePolicyChiefCoverageV1, ...] = ()
    current_carrier_id: str | None = None
    current_chief_slot: str | None = None
    current_chief_state = "missing"
    if len(term_items) != 1:
        blockers.add("current_chief_missing_or_ambiguous")
    else:
        term = term_items[0]
        consulted.add((term.contract_type, term.object_key))
        term_payload = term.payload
        carrier_value = term_payload.get("carrier_id")
        current_carrier_id = carrier_value if type(carrier_value) is str else None
        carrier = (
            carriers.get(current_carrier_id)
            if current_carrier_id is not None else None
        )
        if carrier is not None:
            consulted.add((carrier.contract_type, carrier.object_key))
        for grant in grants.values():
            consulted.add((grant.contract_type, grant.object_key))
        matching_grants = [
            grant for grant in grants.values()
            if grant.payload.get("actor_kind") == "chief"
            and grant.payload.get("actor_id") == term_payload.get("chief_id")
            and grant.payload.get("carrier_id") == current_carrier_id
            and grant.payload.get("term") == term_payload.get("term")
            and grant.payload.get("chief_epoch") == term_payload.get("epoch")
            and grant.payload.get("authority_state") == "active"
            and "company.mutate" in grant.payload.get("permissions", ())
        ]
        chief_exec = [
            item for item in executions.values()
            if item.payload.get("carrier_id") == current_carrier_id
            and item.payload.get("role") == "chief"
            and item.payload.get("execution_kind") == "carrier"
        ]
        for item in chief_exec:
            consulted.add((item.contract_type, item.object_key))
        active = [item for item in chief_exec if item.payload.get("runtime_status") in _ACTIVE_RUNTIME]
        slot = None if carrier is None else _session_slot(
            carrier.payload.get("provider"), carrier.payload.get("session_id"),
            carrier.payload.get("session_availability"),
        )
        current_chief_slot = slot
        reasons: list[str] = []
        if carrier is None or carrier.payload.get("state") != "active":
            reasons.append("current_carrier_not_active")
        if slot is None:
            reasons.append("current_provider_session_unavailable")
        if len(active) != 1:
            reasons.append("current_chief_execution_unavailable")
        if len(matching_grants) != 1:
            reasons.append("current_chief_grant_unavailable")
        current_chief_state = (
            "exact_identity_carrier_observed" if not reasons
            else "exact_identity_carrier_unavailable"
        )
        if reasons:
            blockers.add("current_chief_carrier_coverage_unavailable")
        current_chief = (_chief_coverage(
            actor_id=term_payload.get("chief_id"),
            carrier_id=current_carrier_id,
            slot_id=slot,
            executions=chief_exec,
            state=current_chief_state,
            reasons=reasons or ("current_head_identity_observed",),
        ),)

    active_executions = [
        item for item in executions.values()
        if item.payload.get("execution_kind") != "job"
        and item.payload.get("runtime_status") in _ACTIVE_RUNTIME
    ]
    for item in active_executions:
        consulted.add((item.contract_type, item.object_key))

    live_carrier_ids = {
        str(item.payload["carrier_id"])
        for item in active_executions
        if type(item.payload.get("carrier_id")) is str
    }
    session_holders: dict[tuple[str, str], set[str]] = {}
    for carrier_id, carrier in carriers.items():
        payload = carrier.payload
        carrier_state = payload.get("state")
        if not (
            carrier_state in {"active", "unknown"}
            or (carrier_state == "fenced" and carrier_id in live_carrier_ids)
        ):
            continue
        provider, session = payload.get("provider"), payload.get("session_id")
        if (
            type(provider) is str
            and type(session) is str
            and _session_slot(provider, session, payload.get("session_availability"))
        ):
            consulted.add((carrier.contract_type, carrier.object_key))
            session_holders.setdefault((provider, session), set()).add(carrier_id)

    retiring_groups: dict[str, list[InvariantObject]] = {}
    for item in sorted(active_executions, key=lambda value: value.object_key):
        payload = item.payload
        if payload.get("role") not in _CHIEF_ROLES:
            continue
        retiring_carrier_id = payload.get("carrier_id")
        if type(retiring_carrier_id) is str and retiring_carrier_id == current_carrier_id:
            continue
        group_key = (
            f"carrier:{retiring_carrier_id}"
            if type(retiring_carrier_id) is str
            else f"execution:{item.object_key}"
        )
        retiring_groups.setdefault(group_key, []).append(item)
    retiring: list[RuntimePolicyChiefCoverageV1] = []
    for members in retiring_groups.values():
        carrier_ids = {
            str(item.payload["carrier_id"])
            for item in members
            if type(item.payload.get("carrier_id")) is str
        }
        retiring_carrier_id = next(iter(carrier_ids)) if len(carrier_ids) == 1 else None
        carrier = (
            carriers.get(retiring_carrier_id)
            if type(retiring_carrier_id) is str else None
        )
        if carrier is not None:
            consulted.add((carrier.contract_type, carrier.object_key))
        slot = None if carrier is None else _session_slot(
            carrier.payload.get("provider"), carrier.payload.get("session_id"),
            carrier.payload.get("session_availability"),
        )
        retiring.append(_chief_coverage(
            actor_id=None if carrier is None else carrier.payload.get("actor_id"),
            carrier_id=retiring_carrier_id if carrier is not None else None,
            slot_id=slot,
            executions=members,
            state="retiring_candidate_unverified",
            reasons=("runtime_still_active", "writer_quiescence_unavailable"),
        ))
    if retiring:
        blockers.add("retiring_chief_candidates_observed")
    if len(retiring) > 1:
        blockers.add("retiring_chief_candidate_stack")
    chief_carrier_ids = {
        value for value in (
            current_carrier_id,
            *(item.carrier_id for item in retiring),
        ) if value is not None
    }
    chief_slot_ids = {
        value for value in (
            current_chief_slot,
            *(item.physical_slot_id for item in retiring),
        ) if value is not None
    }

    grouped: dict[str, list[InvariantObject]] = {}
    for item in active_executions:
        payload = item.payload
        if payload.get("role") in _CHIEF_ROLES:
            continue
        execution_id = str(payload["execution_id"])
        member_carrier_id = payload.get("carrier_id")
        carrier = (
            carriers.get(member_carrier_id)
            if type(member_carrier_id) is str else None
        )
        if carrier is None:
            hold("unattributed_runtime", execution_id, "carrier_binding_unavailable")
            continue
        consulted.add((carrier.contract_type, carrier.object_key))
        provider = carrier.payload.get("provider")
        session = carrier.payload.get("session_id")
        slot = _session_slot(provider, session, carrier.payload.get("session_availability"))
        if slot is None:
            hold("unattributed_runtime", execution_id, "provider_session_unavailable")
            continue
        if member_carrier_id in chief_carrier_ids or slot in chief_slot_ids:
            hold("unattributed_runtime", execution_id, "chief_physical_slot_overlap")
            blockers.add("subordinate_chief_physical_slot_overlap")
            continue
        if (
            type(provider) is not str
            or type(session) is not str
            or len(session_holders.get((provider, session), ())) != 1
        ):
            hold("unattributed_runtime", execution_id, "provider_session_binding_ambiguous")
            continue
        grouped.setdefault(slot, []).append(item)

    subordinate_slots: list[RuntimePolicySubordinateSlotV1] = []
    for slot, members in sorted(grouped.items()):
        classifications = [
            _role_class(
                item, executions=executions, nodes=nodes,
                identities=identities, policy=policy,
            )
            for item in members
        ]
        for classification in classifications:
            if classification is not None:
                consulted.update(classification[3])
        known = {item[:3] for item in classifications if item is not None}
        if len(known) != 1 or any(item is None for item in classifications):
            for item in members:
                hold(
                    "unattributed_runtime", str(item.payload["execution_id"]),
                    "role_or_topology_attribution_unavailable",
                )
            continue
        role_class, department_id, depth = known.pop()
        subordinate_slots.append(RuntimePolicySubordinateSlotV1(
            physical_slot_id=slot,
            holder_execution_ids=tuple(sorted(str(item.payload["execution_id"]) for item in members)),
            department_id=department_id,
            role_class=role_class,
            delegation_depth=depth,
            observation_quality="known_physical_provider_session",
        ))

    linked_carriers = {
        str(item.payload["carrier_id"])
        for item in active_executions
        if type(item.payload.get("carrier_id")) is str
    }
    for carrier_id, carrier in carriers.items():
        if (
            carrier_id != current_carrier_id
            and carrier.payload.get("state") in {"active", "unknown"}
            and carrier_id not in linked_carriers
        ):
            consulted.add((carrier.contract_type, carrier.object_key))
            hold("unattributed_carrier", carrier_id, "active_carrier_without_runtime_attribution")

    reservation_reasons: dict[str, set[str]] = {}
    for item in dispatches.values():
        payload = item.payload
        if payload.get("state") in _HELD_DISPATCH:
            reservation_id = str(payload["reservation_id"])
            reservation_reasons.setdefault(reservation_id, set()).add(
                f"dispatch_{payload['state']}"
            )
            consulted.add((item.contract_type, item.object_key))
    for shadow in context.snapshot.uncertain_dispatches:
        reservation_reasons.setdefault(shadow.reservation_id, set()).add(
            f"uncertain_{shadow.requested_state}"
        )
    for reservation_id, reservation_reason_set in reservation_reasons.items():
        hold("dispatch_reservation", reservation_id, *sorted(reservation_reason_set))
        blockers.add("held_dispatch_reservations_observed")
        if any("effect_unknown" in reason for reason in reservation_reason_set):
            blockers.add("effect_unknown_hold_observed")

    over_depth: list[RuntimePolicyDepthObservationV1] = []
    for item in executions.values():
        payload = item.payload
        raw_depth = payload.get("delegation_depth")
        if type(raw_depth) is not int or raw_depth < 4:
            continue
        consulted.add((item.contract_type, item.object_key))
        runtime = str(payload["runtime_status"])
        engineering = str(payload["engineering_status"])
        if runtime in _ACTIVE_RUNTIME:
            lifecycle = "active_legacy_blocker"
            blockers.add("active_over_depth_execution_observed")
        elif engineering in {"completed", "cancelled", "idle"}:
            lifecycle = "historical_terminal_legacy"
        else:
            lifecycle = "closure_unavailable"
            blockers.add("over_depth_execution_closure_unavailable")
        over_depth.append(RuntimePolicyDepthObservationV1(
            execution_id=str(payload["execution_id"]),
            raw_depth=raw_depth,
            role=str(payload["role"]),
            department_id=(
                payload["department_id"]
                if type(payload.get("department_id")) is str else None
            ),
            engineering_status=engineering,
            runtime_status=runtime,
            lifecycle_class=lifecycle,
        ))

    hold_values = tuple(RuntimePolicyHoldV1(
        hold_kind=kind,
        holder_id=holder,
        reason_codes=tuple(sorted(reasons)),
    ) for (kind, holder), reasons in sorted(holds.items()))
    if any(value.hold_kind.startswith("unattributed") for value in hold_values):
        blockers.add("subordinate_attribution_unavailable")
    if len(subordinate_slots) > policy.subordinate_carrier_limit:
        blockers.add("known_subordinate_lower_bound_exceeds_candidate_limit")

    witness_values: list[RuntimePolicySourceWitnessV1] = []
    for key in sorted(consulted):
        projected_item = context.projected.get(key)
        if projected_item is None:
            _fail("runtime-policy readiness consulted source is unavailable")
        witness_values.append(_witness(
            projected_item,
            company_contract_sha256(plain_projected_payload(projected_item.payload)),
        ))
    for shadow in context.snapshot.uncertain_dispatches:
        witness_values.append(RuntimePolicySourceWitnessV1(
            "uncertain_dispatch_shadow",
            DISPATCH_REQUEST_V1,
            shadow.reservation_id,
            shadow.source_transaction_id,
            shadow.source_event_id,
            shadow.source_global_sequence,
            shadow.payload_sha256,
        ))
    witness_values.sort()
    if (
        len(witness_values) > MAX_LIST_ITEMS
        or len(retiring) > MAX_LIST_ITEMS
        or len(subordinate_slots) > MAX_LIST_ITEMS
        or len(hold_values) > MAX_LIST_ITEMS
        or len(over_depth) > MAX_LIST_ITEMS
    ):
        _fail("runtime-policy readiness relevant observation exceeds bounded limits")
    witnesses = tuple(witness_values)
    witness_sha256 = company_contract_sha256({
        "derivation_domain": _WITNESS_DOMAIN,
        "company": list(context.company),
        "cursor": context.cursor,
        "head_sha256": context.head_sha256,
        "policy_definition_sha256": policy.definition_sha256,
        "witnesses": [_wire(item) for item in witnesses],
    })
    provisional = RuntimePolicyReadinessObservationV1(
        document_type=RUNTIME_POLICY_READINESS_OBSERVATION_V1,
        schema_version=1,
        derivation_algorithm=RUNTIME_POLICY_READINESS_DERIVATION_V1,
        company_id=context.company[0],
        company_incarnation=context.company[1],
        lock_domain_generation=context.company[2],
        cursor=context.cursor,
        head_sha256=context.head_sha256,
        currentness_semantics="current_as_of_exact_verified_head",
        policy_definition_sha256=policy.definition_sha256,
        activation_state="inactive",
        admission_state="unavailable",
        operational_effect="none",
        legacy_active_carrier_limit=LEGACY_ACTIVE_CARRIER_LIMIT,
        legacy_delegation_depth_limit=LEGACY_DELEGATION_DEPTH_LIMIT,
        candidate_subordinate_carrier_limit=policy.subordinate_carrier_limit,
        candidate_current_admitted_max_depth=policy.current_admitted_max_depth,
        current_chief_state=current_chief_state,
        current_chief=current_chief,
        retiring_candidates=tuple(retiring),
        writer_quiescence_state="unavailable",
        transport_capability_state="unavailable",
        subordinate_occupied_lower_bound=len(subordinate_slots),
        subordinate_capacity_quality=(
            "known_lower_bound_with_unattributed_holds"
            if any(value.hold_kind.startswith("unattributed") for value in hold_values)
            else "known_lower_bound"
        ),
        subordinate_slots=tuple(subordinate_slots),
        holds=hold_values,
        over_depth=tuple(sorted(over_depth)),
        blockers=tuple(sorted(blockers)),
        source_witnesses=witnesses,
        source_witness_sha256=witness_sha256,
        observation_sha256=_ZERO_SHA256,
    )
    payload = _report_dict(provisional)
    payload["observation_sha256"] = _ZERO_SHA256
    digest = hashlib.sha256(canonical_company_json_bytes(
        {"derivation_domain": _REPORT_DOMAIN, "observation": payload},
        max_bytes=MAX_CONTRACT_BYTES,
    )).hexdigest()
    result = provisional._replace(observation_sha256=digest)
    canonical_company_json_bytes(_report_dict(result), max_bytes=MAX_CONTRACT_BYTES)
    return result

def _validate_report_structure(value: object) -> RuntimePolicyReadinessObservationV1:
    if (
        type(value) is not RuntimePolicyReadinessObservationV1
    ):
        _fail("runtime-policy readiness observation type is invalid")
    item = value
    if tuple.__len__(item) != len(RuntimePolicyReadinessObservationV1._fields):
        _fail("runtime-policy readiness observation type is invalid")
    collections: tuple[tuple[object, type[tuple[Any, ...]]], ...] = (
        (item.current_chief, RuntimePolicyChiefCoverageV1),
        (item.retiring_candidates, RuntimePolicyChiefCoverageV1),
        (item.subordinate_slots, RuntimePolicySubordinateSlotV1),
        (item.holds, RuntimePolicyHoldV1),
        (item.over_depth, RuntimePolicyDepthObservationV1),
        (item.source_witnesses, RuntimePolicySourceWitnessV1),
    )
    for values, expected_type in collections:
        if type(values) is not tuple or len(values) > MAX_LIST_ITEMS:
            _fail("runtime-policy readiness collection type is invalid")
        if any(type(member) is not expected_type for member in values):
            _fail("runtime-policy readiness collection member type is invalid")
    if type(item.blockers) is not tuple or any(type(v) is not str for v in item.blockers):
        _fail("runtime-policy readiness blockers are invalid")
    if type(item.current_chief) is not tuple or len(item.current_chief) > 1:
        _fail("runtime-policy readiness current Chief cardinality is invalid")
    if any(type(value) is not int for value in (
        item.schema_version, item.company_incarnation,
        item.lock_domain_generation, item.cursor,
        item.legacy_active_carrier_limit,
        item.legacy_delegation_depth_limit,
        item.candidate_subordinate_carrier_limit,
        item.candidate_current_admitted_max_depth,
        item.subordinate_occupied_lower_bound,
    )):
        _fail("runtime-policy readiness integer field type is invalid")
    canonical_company_json_bytes(_report_dict(item), max_bytes=MAX_CONTRACT_BYTES)
    return item

def _validate_exact_report(value: object) -> RuntimePolicyReadinessObservationV1:
    try:
        return _validate_report_structure(value)
    except RuntimePolicyReadinessError:
        raise
    except MemoryError:
        raise
    except (
        AttributeError, CompanyContractError, KeyError, OSError,
        RecursionError, TypeError, ValueError,
    ) as exc:
        raise RuntimePolicyReadinessError(
            "runtime-policy readiness observation structure is invalid"
        ) from exc

def validate_runtime_policy_readiness_observation(
    state: CompanyStateOwner,
    value: object,
) -> RuntimePolicyReadinessObservationV1:
    """Re-derive at the exact current head; structural self-hashes are insufficient."""

    candidate = _validate_exact_report(value)
    expected = derive_runtime_policy_readiness(state)
    if candidate != expected:
        _fail("runtime-policy readiness observation differs from exact derivation")
    return expected


__all__ = [
    "LEGACY_ACTIVE_CARRIER_LIMIT", "LEGACY_DELEGATION_DEPTH_LIMIT",
    "RUNTIME_POLICY_READINESS_DERIVATION_V1", "RUNTIME_POLICY_READINESS_OBSERVATION_V1",
    "RuntimePolicyChiefCoverageV1", "RuntimePolicyDepthObservationV1",
    "RuntimePolicyHoldV1", "RuntimePolicyReadinessError",
    "RuntimePolicyReadinessObservationV1", "RuntimePolicySourceWitnessV1",
    "RuntimePolicySubordinateSlotV1", "derive_runtime_policy_readiness",
    "validate_runtime_policy_readiness_observation",
]
