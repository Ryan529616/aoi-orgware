"""Private, reader-only mapping candidates from generic QoS to inventory roots.

This module intentionally creates no request, reservation, lease, admission, or
activation authority.  Its values are caller-supplied, off-ledger candidates.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple, NoReturn, cast

from aoi_orgware.company.contracts import (
    CompanyContractError,
    company_contract_sha256,
)
from aoi_orgware.company.resources.inventory_contract import (
    ResourceCapacityVectorV1,
    ResourceInventoryCoverageV1,
    ResourceInventoryMembershipV1,
    ResourceInventoryObservationV1,
    ResourceInventoryNodeV1,
    ResourceInventoryProvenanceV1,
    ResourceInventoryRelationV1,
    ResourceQuantityV1,
    observe_resource_inventory_v1,
)
from aoi_orgware.company.resources.inventory_relations import (
    validate_resource_pool_forest_v1,
)
from aoi_orgware.company.scheduling.qos import (
    BudgetV1,
    ConfiguredCapacityV1,
    ContextBindingV1,
    FreshnessV1,
    IntentScopeV1,
    ResourceBoundV1,
    UsageScopeV1,
    WorkQoSIntentV1,
    validate_work_qos_intent_v1,
)


MAX_MAPPING_VALUE = (1 << 63) - 1
_MAPPING_UNAVAILABLE = "mapping_unavailable"
_MAPPING_CANDIDATE = "mapping_candidate"
_CANDIDATE_SCOPE = "private_off_ledger"
_QUALITY = "caller_supplied_unverified"
_SHA256_LENGTH = 64
_COMPANY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_INVENTORY_ID = re.compile(r"^inv_[0-9a-f]{32}$")
_REASON_CODES = {
    "cpu": "cpu_cores_to_millicore_checked",
    "memory": "memory_mib_to_ram_byte_checked",
    "accelerator": "accelerator_count_to_gpu_slot_caller_selected_unverified",
    "network": "network_mbps_no_inventory_kind_mapping",
}
_QOS_UNITS = {
    "cpu": "cores",
    "memory": "mib",
    "accelerator": "count",
    "network": "mbps",
}
_MAPPED_KINDS = {
    "cpu": ("cpu", "millicore"),
    "memory": ("ram", "byte"),
    "accelerator": ("gpu", "slot"),
}


class ResourceRequirementMappingError(ValueError):
    """A private resource requirement mapping candidate is malformed."""


class ResourceMappingSelectionV1(NamedTuple):
    """One explicit caller selection; network has no inventory-node selection."""

    qos_kind: str
    resource_id: str | None
    resource_generation: int | None


class ResourceRequirementMappingCandidateV1(NamedTuple):
    """A non-operational conversion candidate, never a capacity decision."""

    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    task_binding_sha256: str
    packet_binding_sha256: str
    qos_intent_digest: str
    qos_intent_revision: int
    inventory_id: str
    inventory_generation: int
    inventory_observation_sha256: str
    qos_kind: str
    qos_unit: str
    selected_resource_id: str | None
    selected_resource_generation: int | None
    canonical_root_resource_id: str | None
    canonical_root_resource_generation: int | None
    mapped_resource_kind: str | None
    mapped_resource_unit: str | None
    mapped_minimum: int | None
    mapped_maximum: int | None
    mapping_state: str
    mapping_reason_code: str
    contract_scope: str
    mapping_quality: str
    authority_state: str
    inventory_currentness: str
    cross_clock_relation: str
    capacity_fit: str
    root_residual_state: str
    exclusivity_state: str
    reservation_state: str
    candidate_sha256: str

    def to_dict(self) -> dict[str, object]:
        return dict(self._asdict())


class ResourceRequirementMappingBundleV1(NamedTuple):
    """Complete private mapping result; only this has semantic validation."""

    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    qos_intent_digest: str
    qos_intent_revision: int
    task_binding_sha256: str
    packet_binding_sha256: str
    inventory_id: str
    inventory_generation: int
    inventory_observation_sha256: str
    selection_sha256: str
    expected_candidate_count: int
    candidates: tuple[ResourceRequirementMappingCandidateV1, ...]
    contract_scope: str
    mapping_quality: str
    authority_state: str
    bundle_sha256: str

    def to_dict(self) -> dict[str, object]:
        result = dict(self._asdict())
        result["candidates"] = [item.to_dict() for item in self.candidates]
        return result


def _fail(message: str) -> NoReturn:
    raise ResourceRequirementMappingError(message)


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_MAPPING_VALUE:
        _fail(f"{label} must be a bounded exact integer")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or len(value) != _SHA256_LENGTH or any(character not in "0123456789abcdef" for character in value):
        _fail(f"{label} must be lowercase SHA-256")
    return value


def _binding_sha256(label: str, value: object) -> str:
    if type(value) is not str:
        _fail(f"{label} must be an exact string")
    try:
        return company_contract_sha256({
            "derivation_domain": f"aoi.resources.requirement-mapping-{label}.v1",
            "binding": value,
        })
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as error:
        raise ResourceRequirementMappingError(f"{label} binding canonicalization failed") from error


def _opaque_resource_id(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 36 or not value.startswith("res_"):
        _fail(f"{label} must be an opaque inventory resource identifier")
    suffix = value[4:]
    if any(character not in "0123456789abcdef" for character in suffix):
        _fail(f"{label} must be an opaque inventory resource identifier")
    return value


def _selection(value: object) -> ResourceMappingSelectionV1:
    if type(value) is not ResourceMappingSelectionV1:
        _fail("selection must be an exact ResourceMappingSelectionV1")
    item = value
    if type(item.qos_kind) is not str or item.qos_kind not in {"cpu", "memory", "accelerator", "network"}:
        _fail("selection qos_kind is outside the closed mapping schema")
    if item.qos_kind == "network":
        if item.resource_id is not None or item.resource_generation is not None:
            _fail("network selection must not choose an arbitrary inventory node")
    else:
        _opaque_resource_id(item.resource_id, "selection.resource_id")
        _exact_int(item.resource_generation, "selection.resource_generation", minimum=1)
    return item


def validate_resource_mapping_selection_v1(value: object) -> ResourceMappingSelectionV1:
    """Validate shape only; this does not bind a selection to QoS or inventory."""
    return _selection(value)


def _canonical_payload(value: ResourceRequirementMappingCandidateV1) -> dict[str, object]:
    payload = value.to_dict()
    payload["candidate_sha256"] = "0" * _SHA256_LENGTH
    return {"derivation_domain": "aoi.resources.requirement-mapping-candidate.v1", "candidate": payload}


def _candidate_digest(value: ResourceRequirementMappingCandidateV1) -> str:
    try:
        # Keep the candidate binding on the same public canonical helper used by
        # the company contracts; it is integrity only, never authority.
        return company_contract_sha256(_canonical_payload(value))
    except (CompanyContractError, RecursionError, OverflowError, TypeError, ValueError) as error:
        raise ResourceRequirementMappingError("candidate canonicalization failed") from error


def _bundle_payload(value: ResourceRequirementMappingBundleV1) -> dict[str, object]:
    payload = value.to_dict()
    payload["bundle_sha256"] = "0" * _SHA256_LENGTH
    return {"derivation_domain": "aoi.resources.requirement-mapping-bundle.v1", "bundle": payload}


def _bundle_digest(value: ResourceRequirementMappingBundleV1) -> str:
    try:
        return company_contract_sha256(_bundle_payload(value))
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("bundle canonicalization failed") from error


def _selection_digest(qos: WorkQoSIntentV1, selections: tuple[ResourceMappingSelectionV1, ...]) -> str:
    try:
        return company_contract_sha256({
            "derivation_domain": "aoi.resources.requirement-mapping-selection.v1",
            "qos_intent_digest": qos.intent_digest,
            "selections": [item._asdict() for item in selections],
        })
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("selection canonicalization failed") from error


def _qos_nested_types(value: WorkQoSIntentV1) -> None:
    if (
        type(value.intent_scope) is not IntentScopeV1
        or type(value.usage_scope) is not UsageScopeV1
        or type(value.context_binding) is not ContextBindingV1
        or type(value.configured_capacity) is not ConfiguredCapacityV1
        or type(value.freshness) is not FreshnessV1
        or type(value.budgets) is not tuple
        or type(value.resources) is not tuple
    ):
        _fail("qos intent nested value types are invalid")
    for item in value.budgets:
        if type(item) is not tuple or len(item) != 2 or type(item[0]) is not str or type(item[1]) is not BudgetV1:
            _fail("qos intent budget value types are invalid")
    if any(type(item) is not ResourceBoundV1 for item in value.resources):
        _fail("qos intent resource value types are invalid")


def _inventory_nested_types(value: ResourceInventoryObservationV1) -> None:
    if (
        type(value.provenance) is not ResourceInventoryProvenanceV1
        or type(value.coverage) is not ResourceInventoryCoverageV1
        or type(value.nodes) is not tuple
        or type(value.relations) is not tuple
        or type(value.memberships) is not tuple
    ):
        _fail("inventory nested value types are invalid")
    for node in value.nodes:
        if type(node) is not ResourceInventoryNodeV1 or type(node.capacity) is not ResourceCapacityVectorV1:
            _fail("inventory node value types are invalid")
        if any(
            type(quantity) is not ResourceQuantityV1
            for quantity in (
                node.capacity.total,
                node.capacity.allocatable,
                node.capacity.reserved,
                node.capacity.parent_carveout,
            )
        ):
            _fail("inventory quantity value types are invalid")
    if any(type(item) is not ResourceInventoryRelationV1 for item in value.relations):
        _fail("inventory relation value types are invalid")
    if any(type(item) is not ResourceInventoryMembershipV1 for item in value.memberships):
        _fail("inventory membership value types are invalid")


def _validated_qos(value: object) -> WorkQoSIntentV1:
    if type(value) is not WorkQoSIntentV1:
        _fail("qos intent must be an exact WorkQoSIntentV1")
    try:
        _qos_nested_types(value)
        # The public raw validator intentionally excludes the derived display
        # semantics field from ConfiguredCapacityV1.to_dict().  Reconstruct
        # only its canonical raw input, then require exact immutable equality.
        raw = value.to_dict()
        configured = cast(dict[str, object], raw["configured_capacity"])
        raw["configured_capacity"] = {
            "configured_capacity_id": configured["configured_capacity_id"],
            "configured_capacity_tokens": configured["configured_capacity_tokens"],
        }
        validated = validate_work_qos_intent_v1(raw)
        if validated != value:
            _fail("qos intent differs from its exact public canonical validation")
        return validated
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequirementMappingError:
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("qos intent validation failed") from error


def _validated_inventory(value: object) -> ResourceInventoryObservationV1:
    if type(value) is not ResourceInventoryObservationV1:
        _fail("inventory observation must be an exact ResourceInventoryObservationV1")
    try:
        _inventory_nested_types(value)
        observation = observe_resource_inventory_v1(value)
        forest = validate_resource_pool_forest_v1(observation.nodes, observation.relations, observation.coverage.state)
        if forest.nodes != observation.nodes or forest.memberships != observation.memberships:
            _fail("inventory canonical forest diverges")
        if observation != value:
            _fail("inventory differs from its exact public canonical observation")
        return observation
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequirementMappingError:
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("inventory observation validation failed") from error


def _require_same_company(qos: WorkQoSIntentV1, inventory: ResourceInventoryObservationV1) -> None:
    if (
        qos.intent_scope.company_id,
        qos.intent_scope.company_incarnation,
        qos.intent_scope.lock_domain_generation,
    ) != (
        inventory.company_id,
        inventory.company_incarnation,
        inventory.lock_domain_generation,
    ):
        _fail("qos intent and inventory company binding differ")


def _selection_tuple(value: object) -> tuple[ResourceMappingSelectionV1, ...]:
    if type(value) is not tuple or len(value) > 4:
        _fail("selections must be a bounded immutable tuple")
    result = tuple(_selection(item) for item in value)
    if len({item.qos_kind for item in result}) != len(result):
        _fail("selections cannot duplicate a QoS resource kind")
    node_keys = [(item.resource_id, item.resource_generation) for item in result if item.resource_id is not None]
    if len(set(node_keys)) != len(node_keys):
        _fail("selections cannot duplicate an inventory node")
    return tuple(sorted(result, key=lambda item: (item.qos_kind, item.resource_id or "", item.resource_generation or 0)))


def _qos_bounds(qos: WorkQoSIntentV1) -> dict[str, ResourceBoundV1]:
    bounds = {item.kind: item for item in qos.resources}
    if len(bounds) != len(qos.resources):
        _fail("qos intent resource bounds are ambiguous")
    return bounds


def _root_memberships(inventory: ResourceInventoryObservationV1) -> dict[tuple[str, int], tuple[str, int]]:
    result = {
        (item.resource_id, item.resource_generation): (item.root_resource_id, item.root_resource_generation)
        for item in inventory.memberships
    }
    if len(result) != len(inventory.memberships):
        _fail("inventory memberships are ambiguous")
    return result


def _node_map(inventory: ResourceInventoryObservationV1) -> dict[tuple[str, int], ResourceInventoryNodeV1]:
    result = {(item.resource_id, item.resource_generation): item for item in inventory.nodes}
    if len(result) != len(inventory.nodes):
        _fail("inventory nodes are ambiguous")
    return result


def _multiply(value: int, factor: int, label: str) -> int:
    if value > MAX_MAPPING_VALUE // factor:
        _fail(f"{label} overflows the closed mapping domain")
    return value * factor


def _mapped_values(
    bound: ResourceBoundV1,
    selection: ResourceMappingSelectionV1,
    node: ResourceInventoryNodeV1 | None,
) -> tuple[str | None, str | None, int | None, int | None, str, str]:
    if bound.kind == "network":
        return None, None, None, None, _MAPPING_UNAVAILABLE, _REASON_CODES["network"]
    if node is None:
        _fail("mapped selection needs an exact inventory node")
    expected = {
        "cpu": ("cpu", "millicore", 1000),
        "memory": ("ram", "byte", 1_048_576),
        "accelerator": ("gpu", "slot", 1),
    }.get(bound.kind)
    if expected is None or selection.qos_kind != bound.kind:
        _fail("selection and QoS resource bound differ")
    inventory_kind, unit, factor = expected
    if node.kind != inventory_kind or node.capacity.total.unit != unit:
        _fail("selection inventory node kind or fixed unit differs")
    return (
        inventory_kind,
        unit,
        _multiply(bound.minimum, factor, "mapped minimum"),
        _multiply(bound.maximum, factor, "mapped maximum"),
        _MAPPING_CANDIDATE,
        _REASON_CODES[bound.kind],
    )


def _derive(qos: WorkQoSIntentV1, inventory: ResourceInventoryObservationV1, selections: tuple[ResourceMappingSelectionV1, ...]) -> tuple[ResourceRequirementMappingCandidateV1, ...]:
    _require_same_company(qos, inventory)
    task_binding = _binding_sha256("task-binding", qos.intent_scope.task_id)
    packet_binding = _binding_sha256("packet-binding", qos.intent_scope.packet_id)
    bounds = _qos_bounds(qos)
    nodes = _node_map(inventory)
    memberships = _root_memberships(inventory)
    if {selection.qos_kind for selection in selections} != set(bounds):
        _fail("selections must exactly cover the QoS resource kinds")
    roots: set[tuple[str, int]] = set()
    result: list[ResourceRequirementMappingCandidateV1] = []
    for selection in selections:
        bound = bounds[selection.qos_kind]
        key = (selection.resource_id, selection.resource_generation)
        node = None if selection.resource_id is None else nodes.get(cast(tuple[str, int], key))
        if selection.resource_id is not None and node is None:
            _fail("selection inventory node is absent")
        root = None if node is None else memberships.get((node.resource_id, node.resource_generation))
        if node is not None and root is None:
            _fail("selection inventory root membership is absent")
        if root is not None:
            if root in roots:
                _fail("selections cannot duplicate a canonical inventory root")
            roots.add(root)
        mapped_kind, mapped_unit, minimum, maximum, state, reason = _mapped_values(bound, selection, node)
        provisional = ResourceRequirementMappingCandidateV1(
            qos.intent_scope.company_id, qos.intent_scope.company_incarnation, qos.intent_scope.lock_domain_generation,
            task_binding, packet_binding, qos.intent_digest, qos.intent_revision,
            inventory.inventory_id, inventory.inventory_generation, inventory.observation_sha256,
            bound.kind, bound.unit, selection.resource_id, selection.resource_generation,
            None if root is None else root[0], None if root is None else root[1],
            mapped_kind, mapped_unit, minimum, maximum, state, reason,
            _CANDIDATE_SCOPE, _QUALITY, "unverified", "unavailable", "unavailable",
            "not_evaluated", "not_evaluated", "not_evaluated", "not_evaluated", "",
        )
        result.append(provisional._replace(candidate_sha256=_candidate_digest(provisional)))
    return tuple(sorted(result, key=lambda item: (item.qos_kind, item.selected_resource_id or "")))


def _candidate_structure(value: object) -> ResourceRequirementMappingCandidateV1:
    """Check one self-contained candidate only; this never proves completeness."""
    if type(value) is not ResourceRequirementMappingCandidateV1:
        _fail("candidate must be an exact ResourceRequirementMappingCandidateV1")
    try:
        item = value
        for name in (
            "company_id", "task_binding_sha256", "packet_binding_sha256", "qos_intent_digest",
            "inventory_id", "inventory_observation_sha256", "qos_kind", "qos_unit",
            "mapping_state", "mapping_reason_code", "contract_scope", "mapping_quality",
            "authority_state", "inventory_currentness", "cross_clock_relation", "capacity_fit",
            "root_residual_state", "exclusivity_state", "reservation_state", "candidate_sha256",
        ):
            if type(getattr(item, name)) is not str:
                _fail(f"candidate.{name} must be an exact string")
        if _COMPANY_ID.fullmatch(item.company_id) is None:
            _fail("candidate.company_id is not canonical")
        if _INVENTORY_ID.fullmatch(item.inventory_id) is None:
            _fail("candidate.inventory_id is not canonical")
        for name, minimum in (
            ("company_incarnation", 1), ("lock_domain_generation", 0), ("qos_intent_revision", 1),
            ("inventory_generation", 1),
        ):
            _exact_int(getattr(item, name), f"candidate.{name}", minimum=minimum)
        for name in ("selected_resource_generation", "canonical_root_resource_generation"):
            field = getattr(item, name)
            if field is not None:
                _exact_int(field, f"candidate.{name}", minimum=1)
        for name in ("mapped_minimum", "mapped_maximum"):
            field = getattr(item, name)
            if field is not None:
                _exact_int(field, f"candidate.{name}", minimum=0)
        for name in ("selected_resource_id", "canonical_root_resource_id", "mapped_resource_kind", "mapped_resource_unit"):
            field = getattr(item, name)
            if field is not None and type(field) is not str:
                _fail(f"candidate.{name} must be string or unavailable")
        for identifier, generation, label in (
            (item.selected_resource_id, item.selected_resource_generation, "selected resource"),
            (item.canonical_root_resource_id, item.canonical_root_resource_generation, "canonical root resource"),
        ):
            if (identifier is None) != (generation is None):
                _fail(f"candidate.{label} identity and generation must be paired")
            if identifier is not None:
                _opaque_resource_id(identifier, f"candidate.{label.replace(' ', '_')}_id")
        for name in ("task_binding_sha256", "packet_binding_sha256", "qos_intent_digest", "inventory_observation_sha256", "candidate_sha256"):
            _digest(getattr(item, name), f"candidate.{name}")
        if item.qos_kind not in _REASON_CODES or item.mapping_reason_code != _REASON_CODES[item.qos_kind]:
            _fail("candidate mapping reason code is invalid")
        if item.qos_unit != _QOS_UNITS[item.qos_kind]:
            _fail("candidate QoS kind and unit are not canonical")
        selected = (item.selected_resource_id, item.selected_resource_generation)
        root = (item.canonical_root_resource_id, item.canonical_root_resource_generation)
        mapped = (
            item.mapped_resource_kind,
            item.mapped_resource_unit,
            item.mapped_minimum,
            item.mapped_maximum,
        )
        if item.qos_kind == "network":
            if item.mapping_state != _MAPPING_UNAVAILABLE or selected != (None, None) or root != (None, None) or mapped != (None,) * 4:
                _fail("network mapping must remain unavailable without an inventory value")
        else:
            expected_kind, expected_unit = _MAPPED_KINDS[item.qos_kind]
            if item.mapping_state != _MAPPING_CANDIDATE or None in selected or None in root:
                _fail("mapped candidate identity or state is invalid")
            if (item.mapped_resource_kind, item.mapped_resource_unit) != (expected_kind, expected_unit):
                _fail("mapped candidate kind or unit is invalid")
            if item.mapped_minimum is None or item.mapped_maximum is None or item.mapped_minimum > item.mapped_maximum:
                _fail("mapped candidate range is invalid")
        if (item.contract_scope, item.mapping_quality, item.authority_state) != (_CANDIDATE_SCOPE, _QUALITY, "unverified"):
            _fail("candidate private truth boundary is invalid")
        if (item.inventory_currentness, item.cross_clock_relation) != ("unavailable", "unavailable"):
            _fail("candidate currentness boundary is invalid")
        if (item.capacity_fit, item.root_residual_state, item.exclusivity_state, item.reservation_state) != ("not_evaluated",) * 4:
            _fail("candidate operational axes are invalid")
        if item.candidate_sha256 != _candidate_digest(item):
            _fail("candidate SHA-256 differs from canonical candidate")
        return item
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequirementMappingError:
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("candidate structural validation failed") from error


def validate_resource_requirement_mapping_candidate_structure_v1(
    candidate: object,
) -> ResourceRequirementMappingCandidateV1:
    """Validate one candidate's local shape only; it makes no bundle claim."""
    return _candidate_structure(candidate)


def _bundle_structure(value: object) -> ResourceRequirementMappingBundleV1:
    if type(value) is not ResourceRequirementMappingBundleV1:
        _fail("bundle must be an exact ResourceRequirementMappingBundleV1")
    try:
        item = value
        for name in (
            "company_id", "qos_intent_digest", "task_binding_sha256", "packet_binding_sha256",
            "inventory_id", "inventory_observation_sha256", "selection_sha256", "contract_scope",
            "mapping_quality", "authority_state", "bundle_sha256",
        ):
            if type(getattr(item, name)) is not str:
                _fail(f"bundle.{name} must be an exact string")
        for name, minimum in (
            ("company_incarnation", 1), ("lock_domain_generation", 0), ("qos_intent_revision", 1),
            ("inventory_generation", 1), ("expected_candidate_count", 0),
        ):
            _exact_int(getattr(item, name), f"bundle.{name}", minimum=minimum)
        if item.expected_candidate_count > 4:
            _fail("bundle candidate count exceeds the closed mapping bound")
        for name in ("qos_intent_digest", "task_binding_sha256", "packet_binding_sha256", "inventory_observation_sha256", "selection_sha256", "bundle_sha256"):
            _digest(getattr(item, name), f"bundle.{name}")
        if type(item.candidates) is not tuple or len(item.candidates) != item.expected_candidate_count:
            _fail("bundle candidates do not match expected candidate count")
        candidates = tuple(_candidate_structure(candidate) for candidate in item.candidates)
        if candidates != tuple(sorted(candidates, key=lambda candidate: (candidate.qos_kind, candidate.selected_resource_id or ""))):
            _fail("bundle candidates are not in canonical order")
        for candidate in candidates:
            if (
                candidate.company_id,
                candidate.company_incarnation,
                candidate.lock_domain_generation,
                candidate.qos_intent_digest,
                candidate.qos_intent_revision,
                candidate.task_binding_sha256,
                candidate.packet_binding_sha256,
                candidate.inventory_id,
                candidate.inventory_generation,
                candidate.inventory_observation_sha256,
            ) != (
                item.company_id,
                item.company_incarnation,
                item.lock_domain_generation,
                item.qos_intent_digest,
                item.qos_intent_revision,
                item.task_binding_sha256,
                item.packet_binding_sha256,
                item.inventory_id,
                item.inventory_generation,
                item.inventory_observation_sha256,
            ):
                _fail("bundle and candidate shared identities differ")
        if (item.contract_scope, item.mapping_quality, item.authority_state) != (_CANDIDATE_SCOPE, _QUALITY, "unverified"):
            _fail("bundle private truth boundary is invalid")
        if item.bundle_sha256 != _bundle_digest(item):
            _fail("bundle SHA-256 differs from canonical bundle")
        return item
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequirementMappingError:
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("bundle structural validation failed") from error


def derive_resource_requirement_mapping_bundle_v1(
    qos_intent: object,
    inventory_observation: object,
    selections: object,
) -> ResourceRequirementMappingBundleV1:
    """Derive one complete private bundle; it never proves capacity or authority."""
    try:
        qos = _validated_qos(qos_intent)
        inventory = _validated_inventory(inventory_observation)
        canonical_selections = _selection_tuple(selections)
        candidates = _derive(qos, inventory, canonical_selections)
        provisional = ResourceRequirementMappingBundleV1(
            qos.intent_scope.company_id, qos.intent_scope.company_incarnation, qos.intent_scope.lock_domain_generation,
            qos.intent_digest, qos.intent_revision,
            _binding_sha256("task-binding", qos.intent_scope.task_id),
            _binding_sha256("packet-binding", qos.intent_scope.packet_id),
            inventory.inventory_id, inventory.inventory_generation, inventory.observation_sha256,
            _selection_digest(qos, canonical_selections), len(candidates), candidates,
            _CANDIDATE_SCOPE, _QUALITY, "unverified", "",
        )
        return provisional._replace(bundle_sha256=_bundle_digest(provisional))
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequirementMappingError:
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("resource mapping derivation failed") from error


def validate_resource_requirement_mapping_bundle_v1(
    bundle: object,
    qos_intent: object,
    inventory_observation: object,
    selections: object,
) -> ResourceRequirementMappingBundleV1:
    """Re-derive the complete candidate tuple; partial or mixed bundles fail."""
    try:
        item = _bundle_structure(bundle)
        derived = derive_resource_requirement_mapping_bundle_v1(qos_intent, inventory_observation, selections)
        if item != derived:
            _fail("bundle differs from exact complete witness-bound derivation")
        return item
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequirementMappingError:
        raise
    except Exception as error:
        raise ResourceRequirementMappingError("bundle semantic validation failed") from error
