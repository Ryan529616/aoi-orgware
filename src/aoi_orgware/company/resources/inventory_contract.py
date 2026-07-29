"""Closed private values for a caller-owned, off-ledger resource observation."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Literal, NamedTuple, cast

from aoi_orgware.company.contracts import CompanyContractError, canonical_company_json_bytes


QuantityAvailabilityV1 = Literal["exact", "unavailable"]
ResourceUnitV1 = Literal["slot", "millicore", "byte"]
ResourceKindV1 = Literal[
    "carrier", "cpu", "ram", "gpu", "vram", "vm", "execution_pool",
    "license", "storage", "workspace", "output_namespace",
]
ResourceRoleV1 = Literal["pool", "resource"]
ResourceNodeStateV1 = Literal["present", "unavailable", "unknown"]
RelationKindV1 = Literal["contains", "carve_out"]
CoverageStateV1 = Literal["complete", "partial", "unknown"]
NumericRelationStateV1 = Literal["verified", "unavailable", "not_applicable"]
FreshnessStateV1 = Literal["fresh", "expired", "clock_mismatch", "clock_regressed"]
FreshnessReasonCodeV1 = Literal["fresh", "ttl_expired", "clock_domain_mismatch", "evaluation_precedes_observation"]

_OPAQUE_ID = re.compile(r"^(?:inv|res|clk|src|rcls)_[0-9a-f]{32}$")
_COMPANY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MAX_CAPACITY = (1 << 63) - 1
_MAX_FOREST_ITEMS = 4096
_MAX_BINDING_GENERATION = 999_999_999
_MAX_OBSERVATION_CANONICAL_BYTES = 16 * 1024 * 1024
_CONTRACT_TYPE = "resource_inventory_observation_v1"
_SCHEMA_VERSION = 1
_UNAVAILABLE_REASONS = frozenset({
    "not_observed", "node_unavailable", "node_unknown", "coverage_unknown",
    "relation_operand_unavailable", "root_has_no_parent", "contains_has_no_charge",
})
_UNITS_BY_KIND: dict[ResourceKindV1, ResourceUnitV1] = {
    "cpu": "millicore", "ram": "byte", "vram": "byte", "storage": "byte",
    "carrier": "slot", "gpu": "slot", "vm": "slot", "execution_pool": "slot",
    "license": "slot", "workspace": "slot", "output_namespace": "slot",
}


class ResourceInventoryContractError(ValueError):
    """A supplied private inventory value violates the v1 closed schema."""


class ResourceQuantityV1(NamedTuple):
    availability: QuantityAvailabilityV1
    unit: ResourceUnitV1
    value: int | None
    reason_code: str | None


class ResourceCapacityVectorV1(NamedTuple):
    total: ResourceQuantityV1
    allocatable: ResourceQuantityV1
    reserved: ResourceQuantityV1
    parent_carveout: ResourceQuantityV1
    numeric_relation_state: NumericRelationStateV1


class ResourceInventoryNodeV1(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    resource_id: str
    resource_generation: int
    role: ResourceRoleV1
    kind: ResourceKindV1
    resource_class_id: str
    node_state: ResourceNodeStateV1
    capacity: ResourceCapacityVectorV1


class ResourceInventoryRelationV1(NamedTuple):
    child_resource_id: str
    child_resource_generation: int
    parent_resource_id: str
    parent_resource_generation: int
    relation: RelationKindV1
    numeric_relation_state: NumericRelationStateV1 = "not_applicable"


class ResourceInventoryProvenanceV1(NamedTuple):
    source_kind: Literal["manual_attestation", "external_observation", "synthetic_fixture"]
    source_id: str
    evidence_sha256: str


class ResourceInventoryCoverageV1(NamedTuple):
    state: CoverageStateV1
    reason_code: str


class ResourceInventoryMembershipV1(NamedTuple):
    resource_id: str
    resource_generation: int
    membership: Literal["root", "included_in_root"]
    root_resource_id: str
    root_resource_generation: int


class ResourcePoolForestV1(NamedTuple):
    nodes: tuple[ResourceInventoryNodeV1, ...]
    relations: tuple[ResourceInventoryRelationV1, ...]
    memberships: tuple[ResourceInventoryMembershipV1, ...]


class ResourceInventoryObservationV1(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    inventory_id: str
    inventory_generation: int
    clock_domain_id: str
    observed_at: str
    expires_at: str
    provenance: ResourceInventoryProvenanceV1
    coverage: ResourceInventoryCoverageV1
    nodes: tuple[ResourceInventoryNodeV1, ...]
    relations: tuple[ResourceInventoryRelationV1, ...]
    memberships: tuple[ResourceInventoryMembershipV1, ...] = ()
    activation_mode: Literal["manual_only"] = "manual_only"
    quantity_policy: Literal["exact_or_unavailable_fixed_unit"] = "exact_or_unavailable_fixed_unit"
    contract_scope: Literal["private_off_ledger"] = "private_off_ledger"
    authority_state: Literal["unverified"] = "unverified"
    admission_state: Literal["not_evaluated"] = "not_evaluated"
    accounting_policy: Literal["root_only"] = "root_only"
    overlap_proof: Literal["unverified"] = "unverified"
    observation_sha256: str = ""


class ResourceInventoryFreshnessV1(NamedTuple):
    observation_sha256: str
    state: FreshnessStateV1
    reason_code: FreshnessReasonCodeV1
    evaluated_at: str
    clock_domain_id: str


def _fail(message: str) -> None:
    raise ResourceInventoryContractError(message)


def _closed_string(value: object, allowed: frozenset[str], field: str) -> str:
    if type(value) is not str or value not in allowed:
        _fail(f"{field} is outside the exact closed string schema")
    return cast(str, value)


def _company(value: object) -> str:
    if type(value) is not str or not _COMPANY_ID.fullmatch(value):
        _fail("company_id must be a canonical bounded company identifier")
    return cast(str, value)


def _opaque(value: object, prefix: str, field: str) -> str:
    if type(value) is not str or not _OPAQUE_ID.fullmatch(value) or not value.startswith(prefix):
        _fail(f"{field} must be a canonical opaque {prefix} identifier")
    return cast(str, value)


def _positive_generation(value: object, field: str) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_CAPACITY:
        _fail(f"{field} must be a bounded positive integer")
    return cast(int, value)


def _binding_generation(value: object, field: str, minimum: int) -> int:
    if type(value) is not int or value < minimum or value > _MAX_BINDING_GENERATION:
        _fail(f"{field} must be a bounded exact integer")
    return cast(int, value)


def _canonical_time(value: object, field: str) -> datetime:
    if type(value) is not str or not _CANONICAL_UTC.fullmatch(value):
        _fail(f"{field} must be canonical UTC with a Z suffix")
    try:
        return datetime.strptime(cast(str, value), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ResourceInventoryContractError(f"{field} must be a valid UTC instant") from error


def _validate_quantity(value: object, unit: ResourceUnitV1, field: str) -> ResourceQuantityV1:
    if type(value) is not ResourceQuantityV1:
        _fail(f"{field} must be an exact ResourceQuantityV1")
    quantity = cast(ResourceQuantityV1, value)
    availability = _closed_string(quantity.availability, frozenset({"exact", "unavailable"}), f"{field}.availability")
    if type(quantity.unit) is not str or quantity.unit != unit:
        _fail(f"{field} has an invalid availability or fixed unit")
    if availability == "exact":
        if type(quantity.value) is not int or not 0 <= quantity.value <= _MAX_CAPACITY or quantity.reason_code is not None:
            _fail(f"{field} exact value must be a bounded integer with no reason")
    elif (
        quantity.value is not None
        or type(quantity.reason_code) is not str
        or quantity.reason_code not in _UNAVAILABLE_REASONS
    ):
        _fail(f"{field} unavailable value requires a closed reason and no numeric value")
    return quantity


def _validate_capacity(node: ResourceInventoryNodeV1) -> None:
    if type(node.capacity) is not ResourceCapacityVectorV1:
        _fail("node kind or capacity is outside the exact closed schema")
    capacity = node.capacity
    unit = _UNITS_BY_KIND[node.kind]
    total = _validate_quantity(capacity.total, unit, "capacity.total")
    allocatable = _validate_quantity(capacity.allocatable, unit, "capacity.allocatable")
    reserved = _validate_quantity(capacity.reserved, unit, "capacity.reserved")
    parent_carveout = _validate_quantity(capacity.parent_carveout, unit, "capacity.parent_carveout")
    primary_reasons = {
        "present": frozenset({"not_observed", "coverage_unknown"}),
        "unavailable": frozenset({"node_unavailable", "coverage_unknown"}),
        "unknown": frozenset({"node_unknown", "coverage_unknown"}),
    }
    if any(
        item.availability == "unavailable" and item.reason_code not in primary_reasons[node.node_state]
        for item in (total, allocatable, reserved)
    ):
        _fail("primary unavailable reason is incompatible with node state")
    parent_reasons = primary_reasons[node.node_state] | {
        "relation_operand_unavailable",
        "root_has_no_parent",
        "contains_has_no_charge",
    }
    if parent_carveout.availability == "unavailable" and parent_carveout.reason_code not in parent_reasons:
        _fail("parent carveout unavailable reason is incompatible with node state")
    if node.node_state in ("unavailable", "unknown"):
        if any(item.availability != "unavailable" for item in (total, allocatable, reserved)):
            _fail("unavailable or unknown node cannot encode primary capacity")
        if parent_carveout.availability != "unavailable":
            _fail("unavailable or unknown node cannot encode an exact parent carveout")
    exact_primary = all(item.availability == "exact" for item in (total, allocatable, reserved))
    numeric_relation_state = _closed_string(
        capacity.numeric_relation_state,
        frozenset({"verified", "unavailable", "not_applicable"}),
        "capacity.numeric_relation_state",
    )
    if numeric_relation_state != ("verified" if exact_primary else "unavailable"):
        _fail("capacity numeric state does not match primary operand availability")
    known_total = total.value if total.availability == "exact" else None
    known_allocatable = allocatable.value if allocatable.availability == "exact" else None
    known_reserved = reserved.value if reserved.availability == "exact" else None
    if known_reserved is not None and known_allocatable is not None and known_reserved > known_allocatable:
        _fail("capacity must satisfy reserved <= allocatable whenever both are known")
    if known_allocatable is not None and known_total is not None and known_allocatable > known_total:
        _fail("capacity must satisfy allocatable <= total whenever both are known")
    if known_reserved is not None and known_total is not None and known_reserved > known_total:
        _fail("capacity must satisfy reserved <= total whenever both are known")


def _validate_node(
    node: object,
    company_id: str,
    company_incarnation: int,
    lock_domain_generation: int,
) -> ResourceInventoryNodeV1:
    if type(node) is not ResourceInventoryNodeV1:
        _fail("node must be an exact ResourceInventoryNodeV1")
    item = cast(ResourceInventoryNodeV1, node)
    _company(item.company_id)
    _binding_generation(item.company_incarnation, "node.company_incarnation", 1)
    _binding_generation(item.lock_domain_generation, "node.lock_domain_generation", 0)
    if (
        item.company_id != company_id
        or item.company_incarnation != company_incarnation
        or item.lock_domain_generation != lock_domain_generation
    ):
        _fail("node company binding must exactly match the forest")
    _opaque(item.resource_id, "res_", "resource_id")
    _opaque(item.resource_class_id, "rcls_", "resource_class_id")
    _positive_generation(item.resource_generation, "resource_generation")
    _closed_string(item.role, frozenset({"pool", "resource"}), "node.role")
    kind = _closed_string(item.kind, frozenset(_UNITS_BY_KIND), "node.kind")
    if kind not in _UNITS_BY_KIND:
        _fail("node kind is outside the exact closed schema")
    _closed_string(item.node_state, frozenset({"present", "unavailable", "unknown"}), "node.node_state")
    _validate_capacity(item)
    return item


def _validate_provenance(value: object) -> ResourceInventoryProvenanceV1:
    if type(value) is not ResourceInventoryProvenanceV1:
        _fail("provenance must be an exact ResourceInventoryProvenanceV1")
    item = cast(ResourceInventoryProvenanceV1, value)
    _closed_string(item.source_kind, frozenset({"manual_attestation", "external_observation", "synthetic_fixture"}), "provenance.source_kind")
    _opaque(item.source_id, "src_", "source_id")
    if type(item.evidence_sha256) is not str or not _SHA256.fullmatch(item.evidence_sha256):
        _fail("provenance evidence must be a lowercase SHA-256")
    return item


def _validate_unknown_coverage_quantities(nodes: tuple[ResourceInventoryNodeV1, ...]) -> None:
    for node in nodes:
        for quantity in (node.capacity.total, node.capacity.allocatable, node.capacity.reserved, node.capacity.parent_carveout):
            if quantity.availability != "unavailable":
                _fail("unknown coverage must never encode an exact capacity or parent carveout")


def _validate_coverage(value: object, nodes: tuple[ResourceInventoryNodeV1, ...]) -> ResourceInventoryCoverageV1:
    if type(value) is not ResourceInventoryCoverageV1:
        _fail("coverage must be an exact ResourceInventoryCoverageV1")
    item = cast(ResourceInventoryCoverageV1, value)
    state = _closed_string(item.state, frozenset({"complete", "partial", "unknown"}), "coverage.state")
    expected = {"complete": "observed_empty" if not nodes else "observed_complete", "partial": "coverage_partial", "unknown": "coverage_unknown"}
    if type(item.reason_code) is not str or item.reason_code != expected[state]:
        _fail("coverage requires its fixed state/reason pairing")
    if state == "unknown":
        _validate_unknown_coverage_quantities(nodes)
    return item


def _validate_membership(value: object) -> ResourceInventoryMembershipV1:
    if type(value) is not ResourceInventoryMembershipV1:
        _fail("membership must be an exact ResourceInventoryMembershipV1")
    membership = cast(ResourceInventoryMembershipV1, value)
    _opaque(membership.resource_id, "res_", "membership.resource_id")
    _positive_generation(membership.resource_generation, "membership.resource_generation")
    _closed_string(membership.membership, frozenset({"root", "included_in_root"}), "membership.membership")
    _opaque(membership.root_resource_id, "res_", "membership.root_resource_id")
    _positive_generation(membership.root_resource_generation, "membership.root_resource_generation")
    return membership


def _canonical_payload(observation: ResourceInventoryObservationV1) -> bytes:
    def quantity(value: ResourceQuantityV1) -> dict[str, object]:
        return {"availability": value.availability, "unit": value.unit, "value": value.value, "reason_code": value.reason_code}
    try:
        return canonical_company_json_bytes({
            "contract_type": _CONTRACT_TYPE, "schema_version": _SCHEMA_VERSION,
            "company_id": observation.company_id,
            "company_incarnation": observation.company_incarnation,
            "lock_domain_generation": observation.lock_domain_generation,
            "inventory_id": observation.inventory_id,
            "inventory_generation": observation.inventory_generation, "clock_domain_id": observation.clock_domain_id,
            "observed_at": observation.observed_at, "expires_at": observation.expires_at,
            "provenance": {"source_kind": observation.provenance.source_kind, "source_id": observation.provenance.source_id, "evidence_sha256": observation.provenance.evidence_sha256},
            "coverage": {"state": observation.coverage.state, "reason_code": observation.coverage.reason_code},
            "nodes": [{"company_id": node.company_id, "company_incarnation": node.company_incarnation, "lock_domain_generation": node.lock_domain_generation, "resource_id": node.resource_id, "resource_generation": node.resource_generation, "role": node.role, "kind": node.kind, "resource_class_id": node.resource_class_id, "node_state": node.node_state, "capacity": {"total": quantity(node.capacity.total), "allocatable": quantity(node.capacity.allocatable), "reserved": quantity(node.capacity.reserved), "parent_carveout": quantity(node.capacity.parent_carveout), "numeric_relation_state": node.capacity.numeric_relation_state}} for node in observation.nodes],
            "relations": [dict(zip(("child_resource_id", "child_resource_generation", "parent_resource_id", "parent_resource_generation", "relation", "numeric_relation_state"), relation)) for relation in observation.relations],
            "memberships": [dict(zip(("resource_id", "resource_generation", "membership", "root_resource_id", "root_resource_generation"), membership)) for membership in observation.memberships],
            "fixed": {"activation_mode": observation.activation_mode, "quantity_policy": observation.quantity_policy, "contract_scope": observation.contract_scope, "authority_state": observation.authority_state, "admission_state": observation.admission_state, "accounting_policy": observation.accounting_policy, "overlap_proof": observation.overlap_proof},
        }, max_bytes=_MAX_OBSERVATION_CANONICAL_BYTES)
    except CompanyContractError as error:
        raise ResourceInventoryContractError("private observation canonicalization failed") from error


def observe_resource_inventory_v1(observation: ResourceInventoryObservationV1) -> ResourceInventoryObservationV1:
    """Validate one private value; private scope is not a same-process security boundary."""
    if type(observation) is not ResourceInventoryObservationV1:
        _fail("observation must be an exact ResourceInventoryObservationV1")
    _company(observation.company_id)
    _binding_generation(observation.company_incarnation, "company_incarnation", 1)
    _binding_generation(observation.lock_domain_generation, "lock_domain_generation", 0)
    _opaque(observation.inventory_id, "inv_", "inventory_id")
    _positive_generation(observation.inventory_generation, "inventory_generation")
    _opaque(observation.clock_domain_id, "clk_", "clock_domain_id")
    if _canonical_time(observation.expires_at, "expires_at") <= _canonical_time(observation.observed_at, "observed_at"):
        _fail("expires_at must be later than observed_at")
    _validate_provenance(observation.provenance)
    if type(observation.nodes) is not tuple or type(observation.relations) is not tuple or type(observation.memberships) is not tuple:
        _fail("nodes, relations, and memberships must be exact immutable tuples")
    if (
        len(observation.nodes) > _MAX_FOREST_ITEMS
        or len(observation.relations) > _MAX_FOREST_ITEMS
        or len(observation.memberships) > _MAX_FOREST_ITEMS
    ):
        _fail("private forest exceeds its bounded item count")
    if type(observation.coverage) is not ResourceInventoryCoverageV1:
        _fail("coverage must be an exact closed ResourceInventoryCoverageV1")
    coverage_state = cast(
        CoverageStateV1,
        _closed_string(observation.coverage.state, frozenset({"complete", "partial", "unknown"}), "coverage.state"),
    )
    for node in observation.nodes:
        _validate_node(
            node,
            observation.company_id,
            observation.company_incarnation,
            observation.lock_domain_generation,
        )
    from .inventory_relations import validate_resource_pool_forest_v1
    forest = validate_resource_pool_forest_v1(observation.nodes, observation.relations, coverage_state)
    _validate_coverage(observation.coverage, forest.nodes)
    if observation.memberships:
        for membership in observation.memberships:
            _validate_membership(membership)
    if observation.memberships and observation.memberships != forest.memberships:
        _fail("caller-supplied memberships diverge from the canonical derived memberships")
    fixed = (
        _closed_string(observation.activation_mode, frozenset({"manual_only"}), "activation_mode"),
        _closed_string(observation.quantity_policy, frozenset({"exact_or_unavailable_fixed_unit"}), "quantity_policy"),
        _closed_string(observation.contract_scope, frozenset({"private_off_ledger"}), "contract_scope"),
        _closed_string(observation.authority_state, frozenset({"unverified"}), "authority_state"),
        _closed_string(observation.admission_state, frozenset({"not_evaluated"}), "admission_state"),
        _closed_string(observation.accounting_policy, frozenset({"root_only"}), "accounting_policy"),
        _closed_string(observation.overlap_proof, frozenset({"unverified"}), "overlap_proof"),
    )
    if fixed != ("manual_only", "exact_or_unavailable_fixed_unit", "private_off_ledger", "unverified", "not_evaluated", "root_only", "unverified"):
        _fail("fixed private observation outputs cannot be changed")
    canonical = observation._replace(nodes=forest.nodes, relations=forest.relations, memberships=forest.memberships, observation_sha256="")
    digest = hashlib.sha256(_canonical_payload(canonical)).hexdigest()
    if type(observation.observation_sha256) is not str or observation.observation_sha256 not in ("", digest):
        _fail("observation SHA-256 does not match canonical private values")
    return canonical._replace(observation_sha256=digest)


def evaluate_resource_inventory_freshness_v1(observation: ResourceInventoryObservationV1, evaluated_at: str, clock_domain_id: str) -> ResourceInventoryFreshnessV1:
    """Evaluate the half-open observation window only in its opaque clock domain."""
    validated = observe_resource_inventory_v1(observation)
    evaluated = _canonical_time(evaluated_at, "evaluated_at")
    _opaque(clock_domain_id, "clk_", "clock_domain_id")
    state: FreshnessStateV1
    reason: FreshnessReasonCodeV1
    if clock_domain_id != validated.clock_domain_id:
        state, reason = "clock_mismatch", "clock_domain_mismatch"
    elif evaluated < _canonical_time(validated.observed_at, "observed_at"):
        state, reason = "clock_regressed", "evaluation_precedes_observation"
    elif evaluated >= _canonical_time(validated.expires_at, "expires_at"):
        state, reason = "expired", "ttl_expired"
    else:
        state, reason = "fresh", "fresh"
    return ResourceInventoryFreshnessV1(validated.observation_sha256, state, reason, evaluated_at, clock_domain_id)
