# AOI-SYNTHETIC-FIXTURE-V1
"""Reader-only resource requirement mapping fixtures."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

import pytest

import aoi_orgware.company.resources.request_mapping as resource_mapping

from aoi_orgware.company.resources.inventory_contract import (
    ResourceCapacityVectorV1,
    CoverageStateV1,
    ResourceInventoryCoverageV1,
    ResourceKindV1,
    ResourceInventoryNodeV1,
    ResourceInventoryObservationV1,
    ResourceInventoryProvenanceV1,
    ResourceQuantityV1,
    ResourceInventoryRelationV1,
    ResourceNodeStateV1,
    observe_resource_inventory_v1,
    ResourceUnitV1,
)
from aoi_orgware.company.resources.request_mapping import (
    ResourceMappingSelectionV1,
    ResourceRequirementMappingCandidateV1,
    ResourceRequirementMappingBundleV1,
    ResourceRequirementMappingError,
    derive_resource_requirement_mapping_bundle_v1,
    validate_resource_requirement_mapping_candidate_structure_v1,
    validate_resource_requirement_mapping_bundle_v1,
)
from aoi_orgware.company.scheduling.qos import (
    WorkQoSIntentV1,
    validate_work_qos_intent_v1,
    work_qos_intent_v1_preimage_sha256,
)


MARKER = "AOI-SYNTHETIC-FIXTURE-V1"
H = "a" * 64
COMPANY = "company-1"


def _q(value: int | None, unit: ResourceUnitV1, reason: str = "not_observed") -> ResourceQuantityV1:
    return ResourceQuantityV1("exact", unit, value, None) if value is not None else ResourceQuantityV1("unavailable", unit, None, reason)


def _node(
    number: int,
    kind: ResourceKindV1,
    unit: ResourceUnitV1,
    *,
    state: ResourceNodeStateV1 = "present",
) -> ResourceInventoryNodeV1:
    reason = {"present": "not_observed", "unavailable": "node_unavailable", "unknown": "node_unknown"}[state]
    exact = 10 if state == "present" else None
    return ResourceInventoryNodeV1(
        COMPANY, 1, 2, f"res_{number:032x}", 1, "pool", kind, f"rcls_{number:032x}", state,
        ResourceCapacityVectorV1(_q(exact, unit, reason), _q(exact, unit, reason), _q(0 if exact is not None else None, unit, reason), _q(None, unit, "root_has_no_parent"), "verified" if exact is not None else "unavailable"),
    )


def _inventory(
    *,
    coverage: CoverageStateV1 = "complete",
    state: ResourceNodeStateV1 = "present",
    included_ram: bool = False,
    alternate_cpu: bool = False,
) -> ResourceInventoryObservationV1:
    nodes: tuple[ResourceInventoryNodeV1, ...] = (
        _node(1, "cpu", "millicore", state=state),
        _node(2, "ram", "byte", state=state),
        _node(3, "gpu", "slot", state=state),
    )
    relations: tuple[ResourceInventoryRelationV1, ...] = ()
    if included_ram:
        child = _node(4, "ram", "byte", state=state)._replace(
            role="resource",
            capacity=ResourceCapacityVectorV1(
                _q(10, "byte"), _q(10, "byte"), _q(0, "byte"),
                _q(None, "byte", "contains_has_no_charge"), "verified",
            ),
        )
        nodes += (child,)
        relations = (ResourceInventoryRelationV1(child.resource_id, 1, nodes[0].resource_id, 1, "contains"),)
    if alternate_cpu:
        nodes += (_node(5, "cpu", "millicore", state=state),)
    reason = {"complete": "observed_complete", "partial": "coverage_partial", "unknown": "coverage_unknown"}[coverage]
    if coverage == "unknown":
        nodes = tuple(node._replace(node_state="unknown", capacity=ResourceCapacityVectorV1(_q(None, node.capacity.total.unit, "node_unknown"), _q(None, node.capacity.total.unit, "node_unknown"), _q(None, node.capacity.total.unit, "node_unknown"), _q(None, node.capacity.total.unit, "root_has_no_parent"), "unavailable")) for node in nodes)
    return observe_resource_inventory_v1(ResourceInventoryObservationV1(
        COMPANY, 1, 2, "inv_00000000000000000000000000000001", 1, "clk_00000000000000000000000000000001",
        "2026-07-31T00:00:00Z", "2026-08-01T00:00:00Z",
        ResourceInventoryProvenanceV1("synthetic_fixture", "src_00000000000000000000000000000001", H),
        ResourceInventoryCoverageV1(coverage, reason), nodes, relations, (),
    ))


def _qos(
    *,
    resources: list[dict[str, object]] | None = None,
    revision: int = 1,
    task_id: str = "task-1",
    packet_id: str = "packet-1",
) -> WorkQoSIntentV1:
    defaults: list[dict[str, object]] = [
        {"kind": "cpu", "unit": "cores", "minimum": 1, "maximum": 2},
        {"kind": "memory", "unit": "mib", "minimum": 2, "maximum": 3},
        {"kind": "accelerator", "unit": "count", "minimum": 1, "maximum": 1},
        {"kind": "network", "unit": "mbps", "minimum": 1, "maximum": 9},
    ]
    value: dict[str, Any] = {
        "document_type": "work_qos_intent_v1", "schema_version": 1,
        "intent_scope": {"company_id": COMPANY, "company_incarnation": 1, "lock_domain_generation": 2, "task_id": task_id, "packet_id": packet_id},
        "usage_scope": {"company_id": COMPANY, "company_incarnation": 1, "lock_domain_generation": 2, "provider": "codex", "counter_scope_id": "thread-1"},
        "intent_revision": revision, "intent_digest": "0" * 64,
        "context_binding": {"context_v2_semantic_sha256": H, "v1_carrier_sha256": "b" * 64, "v1_carrier_size_bytes": 17},
        "configured_capacity": {"configured_capacity_id": "operator-reference-1", "configured_capacity_tokens": 99},
        "budgets": {name: {"budget": 1, "reserve": 0} for name in ("context", "input", "cache", "output", "reasoning", "tool")},
        "latency_class": "standard", "deadline_at": "2026-08-01T00:00:00Z",
        "freshness": {"state": "fresh", "clock": "2026-07-31T00:00:00Z", "expires_at": "2026-08-02T00:00:00Z"},
        "verification_requirement": "required", "provider_class": "generic_api", "model_class": "generic_standard", "effort_class": "medium",
        "resources": defaults if resources is None else resources,
    }
    value["intent_digest"] = work_qos_intent_v1_preimage_sha256(value)
    return validate_work_qos_intent_v1(value)


def _selections() -> tuple[ResourceMappingSelectionV1, ...]:
    return (
        ResourceMappingSelectionV1("cpu", "res_00000000000000000000000000000001", 1),
        ResourceMappingSelectionV1("memory", "res_00000000000000000000000000000002", 1),
        ResourceMappingSelectionV1("accelerator", "res_00000000000000000000000000000003", 1),
        ResourceMappingSelectionV1("network", None, None),
    )


def test_actual_objects_rederive_deterministic_conversions_and_network_absence() -> None:
    result = derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), _selections())
    again = derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), tuple(reversed(_selections())))
    assert result == again and [item.qos_kind for item in result.candidates] == ["accelerator", "cpu", "memory", "network"]
    values = {item.qos_kind: item for item in result.candidates}
    assert (values["cpu"].mapped_resource_kind, values["cpu"].mapped_minimum, values["cpu"].mapped_maximum) == ("cpu", 1000, 2000)
    assert (values["memory"].mapped_resource_kind, values["memory"].mapped_minimum, values["memory"].mapped_maximum) == ("ram", 2 * 1_048_576, 3 * 1_048_576)
    assert (values["accelerator"].mapped_resource_kind, values["accelerator"].mapped_resource_unit) == ("gpu", "slot")
    assert values["network"].mapping_state == "mapping_unavailable"
    assert values["network"].selected_resource_id is None and values["network"].mapped_minimum is None
    assert {item.capacity_fit for item in result.candidates} == {"not_evaluated"}
    assert {item.mapping_quality for item in result.candidates} == {"caller_supplied_unverified"}
    assert {item.contract_scope for item in result.candidates} == {"private_off_ledger"}
    assert {item.authority_state for item in result.candidates} == {"unverified"}
    assert {item.inventory_currentness for item in result.candidates} == {"unavailable"}
    assert {item.cross_clock_relation for item in result.candidates} == {"unavailable"}
    assert {item.root_residual_state for item in result.candidates} == {"not_evaluated"}
    assert {item.exclusivity_state for item in result.candidates} == {"not_evaluated"}
    assert {item.reservation_state for item in result.candidates} == {"not_evaluated"}
    assert {item.mapping_reason_code for item in result.candidates} == {
        "cpu_cores_to_millicore_checked",
        "memory_mib_to_ram_byte_checked",
        "accelerator_count_to_gpu_slot_caller_selected_unverified",
        "network_mbps_no_inventory_kind_mapping",
    }
    assert validate_resource_requirement_mapping_bundle_v1(result, _qos(), _inventory(), _selections()) == result


def test_forgery_and_all_cross_binding_mismatches_reject() -> None:
    qos, inventory, selections = _qos(), _inventory(), _selections()
    bundle = derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(bundle._replace(candidates=(bundle.candidates[0]._replace(mapped_minimum=7), *bundle.candidates[1:])), qos, inventory, selections)
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(bundle._replace(candidates=(bundle.candidates[0]._replace(canonical_root_resource_id="res_00000000000000000000000000000002"), *bundle.candidates[1:])), qos, inventory, selections)
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(qos._replace(intent_digest="0" * 64), inventory, selections)
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(qos, inventory._replace(inventory_generation=2), selections)
    bad_company = inventory._replace(company_id="company-2")
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(qos, bad_company, selections)
    for bad in (
        ResourceMappingSelectionV1("cpu", "res_00000000000000000000000000000002", 1),
        ResourceMappingSelectionV1("cpu", "res_00000000000000000000000000000001", 2),
        ResourceMappingSelectionV1("network", "res_00000000000000000000000000000001", 1),
        ResourceMappingSelectionV1("missing", "res_00000000000000000000000000000001", 1),
    ):
        with pytest.raises(ResourceRequirementMappingError):
            derive_resource_requirement_mapping_bundle_v1(qos, inventory, (bad,))
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(qos, inventory, (object(),))


def test_selection_must_exactly_cover_qos_resources_and_allow_empty_only_for_empty_qos() -> None:
    qos, inventory = _qos(), _inventory()
    for selections in (_selections()[:-1], _selections()[1:], (), (_selections()[0],)):
        with pytest.raises(ResourceRequirementMappingError, match="exactly cover"):
            derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)
    empty_qos = _qos(resources=[])
    assert derive_resource_requirement_mapping_bundle_v1(empty_qos, inventory, ()).candidates == ()
    with pytest.raises(ResourceRequirementMappingError, match="exactly cover"):
        derive_resource_requirement_mapping_bundle_v1(empty_qos, inventory, (_selections()[0],))


def test_revision_and_included_child_root_are_bound_and_duplicate_roots_reject() -> None:
    memory = [{"kind": "memory", "unit": "mib", "minimum": 2, "maximum": 3}]
    qos = _qos(resources=memory, revision=7)
    child = ResourceMappingSelectionV1("memory", "res_00000000000000000000000000000004", 1)
    candidate = derive_resource_requirement_mapping_bundle_v1(qos, _inventory(included_ram=True), (child,)).candidates[0]
    assert candidate.qos_intent_revision == 7
    assert (candidate.canonical_root_resource_id, candidate.canonical_root_resource_generation) == (
        "res_00000000000000000000000000000001", 1,
    )
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(
            derive_resource_requirement_mapping_bundle_v1(qos, _inventory(included_ram=True), (child,))._replace(
                candidates=(candidate._replace(qos_intent_revision=8),),
            ), qos, _inventory(included_ram=True), (child,),
        )
    two = _qos(resources=[
        {"kind": "cpu", "unit": "cores", "minimum": 1, "maximum": 2}, *memory,
    ])
    with pytest.raises(ResourceRequirementMappingError, match="canonical inventory root"):
        derive_resource_requirement_mapping_bundle_v1(
            two, _inventory(included_ram=True), (
                _selections()[0], child,
            ),
        )


def test_duplicates_bounds_unknown_and_immutability_reject_or_remain_non_operational() -> None:
    qos, inventory = _qos(), _inventory()
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(qos, inventory, (_selections()[0], _selections()[0]))
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(qos, inventory, _selections() + (ResourceMappingSelectionV1("cpu", "res_00000000000000000000000000000001", 1),))
    unknown = derive_resource_requirement_mapping_bundle_v1(qos, _inventory(coverage="unknown"), _selections())
    assert {item.capacity_fit for item in unknown.candidates} == {"not_evaluated"}
    candidate = unknown.candidates[0]
    assert not hasattr(candidate, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(candidate, "qos_kind", "network")


@pytest.mark.parametrize("bad", [True, -1, (1 << 63), 1.5])
def test_numeric_selection_values_reject(bad: object) -> None:
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), (ResourceMappingSelectionV1("cpu", "res_00000000000000000000000000000001", cast(Any, bad)),))


def test_upstream_resource_overflow_rejects_as_typed_mapping_error() -> None:
    qos = _qos()
    invalid_qos = qos._replace(
        resources=(
            qos.resources[0]._replace(maximum=(1 << 63) - 1),
            *qos.resources[1:],
        )
    )
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(
            invalid_qos, _inventory(), (_selections()[0],),
        )


def test_privacy_and_off_ledger_surface() -> None:
    result = derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), _selections())
    serialized = repr(result.to_dict()).lower()
    for forbidden in ("allocatable", "reserved", "provenance", "host", "vm", "license", "configured_capacity", "request", "lease", "admission", "activation", "release"):
        assert forbidden not in serialized
    source = Path(__file__).parents[2] / "src/aoi_orgware/company/resources/request_mapping.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(token in text.lower() for text in imported | modules for token in ("ledger", "registry", "readmodel", "supervisor", "dispatch", "views", "export", "provider", "dashboard", "vm", "eda"))
    assert not any(hasattr(__import__("aoi_orgware.company.resources.request_mapping", fromlist=["*"]), name) for name in ("request", "lease", "admit", "activate", "hold", "release", "probe", "wake"))


def test_invalid_extra_shape_and_canonical_digest_tamper_reject() -> None:
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(_qos().to_dict(), _inventory(), _selections())
    bundle = derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), _selections())
    forged = ResourceRequirementMappingBundleV1(*bundle[:-1], "0" * 64)
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(forged, _qos(), _inventory(), _selections())


def test_semantic_validation_requires_the_complete_derived_bundle() -> None:
    qos, inventory, selections = _qos(), _inventory(), _selections()
    full = derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)
    partial = full._replace(expected_candidate_count=1, candidates=full.candidates[:1], bundle_sha256="")
    partial = partial._replace(bundle_sha256=resource_mapping._bundle_digest(partial))
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(partial, qos, inventory, selections)
    assert validate_resource_requirement_mapping_bundle_v1(full, qos, inventory, selections) == full


def test_same_qos_kind_in_distinct_complete_bundles_cannot_mix() -> None:
    resources = [
        {"kind": "cpu", "unit": "cores", "minimum": 1, "maximum": 2},
        {"kind": "memory", "unit": "mib", "minimum": 2, "maximum": 3},
    ]
    qos, inventory = _qos(resources=resources), _inventory(alternate_cpu=True)
    first_selections = (_selections()[0], _selections()[1])
    second_selections = (
        ResourceMappingSelectionV1("cpu", "res_00000000000000000000000000000005", 1),
        _selections()[1],
    )
    first = derive_resource_requirement_mapping_bundle_v1(qos, inventory, first_selections)
    second = derive_resource_requirement_mapping_bundle_v1(qos, inventory, second_selections)
    assert first.bundle_sha256 != second.bundle_sha256
    assert first.selection_sha256 != second.selection_sha256
    assert {item.qos_kind for item in first.candidates} == {"cpu", "memory"}
    mixed = second._replace(candidates=(first.candidates[0], second.candidates[1]), bundle_sha256="")
    mixed = mixed._replace(bundle_sha256=resource_mapping._bundle_digest(mixed))
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(mixed, qos, inventory, second_selections)


def test_hostile_nested_inputs_and_recursion_are_typed_mapping_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qos, inventory, selections = _qos(), _inventory(), _selections()
    with pytest.raises(ResourceRequirementMappingError):
        derive_resource_requirement_mapping_bundle_v1(
            qos._replace(intent_scope=cast(Any, object())), inventory, selections,
        )
    bundle = derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)
    hostile_candidate = bundle.candidates[0]._replace(company_id=cast(Any, object()))
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(
            bundle._replace(candidates=(hostile_candidate, *bundle.candidates[1:])),
            qos, inventory, selections,
        )
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(
            ResourceRequirementMappingBundleV1(*bundle[:-1], cast(str, object())),
            qos, inventory, selections,
        )

    def _recursive_hash(_: object) -> str:
        raise RecursionError("synthetic deep canonical input")

    monkeypatch.setattr(resource_mapping, "company_contract_sha256", _recursive_hash)
    with pytest.raises(ResourceRequirementMappingError, match="binding canonicalization"):
        derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)


def test_task_packet_bindings_are_private_and_change_bundle_identity() -> None:
    path_task = "C:/private/project/task-1"
    path_packet = "home/private/project/packet-1"
    first = derive_resource_requirement_mapping_bundle_v1(
        _qos(task_id=path_task, packet_id=path_packet), _inventory(), _selections(),
    )
    second = derive_resource_requirement_mapping_bundle_v1(
        _qos(task_id=path_task + "-other", packet_id=path_packet), _inventory(), _selections(),
    )
    serialized = repr(first.to_dict())
    assert path_task not in serialized and path_packet not in serialized
    assert first.task_binding_sha256 != second.task_binding_sha256
    assert first.bundle_sha256 != second.bundle_sha256
    assert {item.task_binding_sha256 for item in first.candidates} == {first.task_binding_sha256}


def test_public_qos_and_inventory_values_must_round_trip_exactly() -> None:
    qos, inventory, selections = _qos(), _inventory(), _selections()
    with pytest.raises(ResourceRequirementMappingError, match="exact public canonical"):
        derive_resource_requirement_mapping_bundle_v1(
            qos._replace(
                configured_capacity=qos.configured_capacity._replace(
                    configured_capacity_semantics="drifted",
                ),
            ),
            inventory,
            selections,
        )
    with pytest.raises(ResourceRequirementMappingError, match="exact public canonical"):
        derive_resource_requirement_mapping_bundle_v1(
            qos._replace(resources=tuple(reversed(qos.resources))), inventory, selections,
        )
    with pytest.raises(ResourceRequirementMappingError, match="exact public canonical"):
        derive_resource_requirement_mapping_bundle_v1(
            qos, inventory._replace(observation_sha256=""), selections,
        )
    with pytest.raises(ResourceRequirementMappingError, match="exact public canonical"):
        derive_resource_requirement_mapping_bundle_v1(
            qos,
            inventory._replace(nodes=tuple(reversed(inventory.nodes)), observation_sha256=""),
            selections,
        )


def test_structural_ids_and_bundle_count_are_closed_even_with_recomputed_digests() -> None:
    qos, inventory, selections = _qos(), _inventory(), _selections()
    bundle = derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)
    candidate = bundle.candidates[0]._replace(
        selected_resource_id="C:/private/project/resource",
        candidate_sha256="",
    )
    candidate = candidate._replace(candidate_sha256=resource_mapping._candidate_digest(candidate))
    with pytest.raises(ResourceRequirementMappingError, match="opaque inventory resource"):
        validate_resource_requirement_mapping_candidate_structure_v1(candidate)
    forged = bundle._replace(candidates=(candidate, *bundle.candidates[1:]), bundle_sha256="")
    forged = forged._replace(bundle_sha256=resource_mapping._bundle_digest(forged))
    with pytest.raises(ResourceRequirementMappingError):
        validate_resource_requirement_mapping_bundle_v1(forged, qos, inventory, selections)
    oversized = bundle._replace(
        expected_candidate_count=5,
        candidates=(*bundle.candidates, bundle.candidates[0]),
        bundle_sha256="",
    )
    oversized = oversized._replace(bundle_sha256=resource_mapping._bundle_digest(oversized))
    with pytest.raises(ResourceRequirementMappingError, match="candidate count"):
        validate_resource_requirement_mapping_bundle_v1(oversized, qos, inventory, selections)


def _rehashed_candidate(
    candidate: ResourceRequirementMappingCandidateV1,
    **changes: object,
) -> ResourceRequirementMappingCandidateV1:
    provisional = cast(
        ResourceRequirementMappingCandidateV1,
        cast(Any, candidate)._replace(**changes, candidate_sha256=""),
    )
    return provisional._replace(candidate_sha256=resource_mapping._candidate_digest(provisional))


@pytest.mark.parametrize(
    ("label", "changes"),
    [
        ("selected generation zero", {"selected_resource_generation": 0}),
        ("root generation zero", {"canonical_root_resource_generation": 0}),
        ("path-shaped QoS unit", {"qos_unit": "C:/private/cores"}),
        ("path-shaped mapped kind", {"mapped_resource_kind": "C:/private/cpu"}),
        ("mapped candidate unavailable", {"mapping_state": "mapping_unavailable"}),
        ("selected identity unavailable", {"selected_resource_id": None}),
        ("root identity unavailable", {"canonical_root_resource_id": None}),
        ("mapped minimum unavailable", {"mapped_minimum": None}),
        ("mapped maximum unavailable", {"mapped_maximum": None}),
        ("mapped inverted range", {"mapped_minimum": 2_001, "mapped_maximum": 2_000}),
    ],
)
def test_mapped_candidate_finite_matrix_rejects_rehashed_invalid_values(
    label: str,
    changes: dict[str, object],
) -> None:
    bundle = derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), _selections())
    cpu = next(candidate for candidate in bundle.candidates if candidate.qos_kind == "cpu")
    with pytest.raises(ResourceRequirementMappingError, match="candidate|mapped|identity|range|canonical"):
        validate_resource_requirement_mapping_candidate_structure_v1(_rehashed_candidate(cpu, **changes))
    assert label


@pytest.mark.parametrize(
    ("label", "changes"),
    [
        ("network candidate state", {"mapping_state": "mapping_candidate"}),
        (
            "network selected identity",
            {
                "selected_resource_id": "res_00000000000000000000000000000001",
                "selected_resource_generation": 1,
            },
        ),
        ("network mapped value", {"mapped_minimum": 0}),
        ("network mapped kind", {"mapped_resource_kind": "gpu"}),
    ],
)
def test_network_candidate_finite_matrix_rejects_rehashed_invalid_values(
    label: str,
    changes: dict[str, object],
) -> None:
    bundle = derive_resource_requirement_mapping_bundle_v1(_qos(), _inventory(), _selections())
    network = next(candidate for candidate in bundle.candidates if candidate.qos_kind == "network")
    with pytest.raises(ResourceRequirementMappingError, match="network"):
        validate_resource_requirement_mapping_candidate_structure_v1(_rehashed_candidate(network, **changes))
    assert label


def test_bundle_candidate_shared_identities_are_not_independently_forgeable() -> None:
    qos, inventory, selections = _qos(), _inventory(), _selections()
    bundle = derive_resource_requirement_mapping_bundle_v1(qos, inventory, selections)
    altered = _rehashed_candidate(bundle.candidates[0], task_binding_sha256="f" * 64)
    forged = bundle._replace(candidates=(altered, *bundle.candidates[1:]), bundle_sha256="")
    forged = forged._replace(bundle_sha256=resource_mapping._bundle_digest(forged))
    with pytest.raises(ResourceRequirementMappingError, match="shared identities"):
        validate_resource_requirement_mapping_bundle_v1(forged, qos, inventory, selections)
