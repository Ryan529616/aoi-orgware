# AOI-SYNTHETIC-FIXTURE-V1
"""Private inventory contract tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import aoi_orgware.company as company
import pytest
from aoi_orgware.company.contracts import CompanyContractError, validate_company_contract
from aoi_orgware.company.resources import (
    ResourceCapacityVectorV1,
    ResourceInventoryContractError,
    ResourceInventoryCoverageV1,
    ResourceInventoryMembershipV1,
    ResourceInventoryNodeV1,
    ResourceInventoryObservationV1,
    ResourceInventoryProvenanceV1,
    ResourceInventoryRelationV1,
    ResourceQuantityV1,
    evaluate_resource_inventory_freshness_v1,
    observe_resource_inventory_v1,
)
from aoi_orgware.company.resources.inventory_contract import _canonical_payload


MARKER = "AOI-SYNTHETIC-FIXTURE-V1"
COMPANY = "company-1"
INCARNATION = 1
LOCK_GENERATION = 0
INV = "inv_00000000000000000000000000000001"
CLK = "clk_00000000000000000000000000000001"
SRC = "src_00000000000000000000000000000001"
RES = "res_00000000000000000000000000000001"
RCLS = "rcls_00000000000000000000000000000001"
T0 = "2026-07-29T00:00:00Z"
T1 = "2026-07-29T00:01:00Z"


def _q(value: int | None, reason: str = "not_observed") -> ResourceQuantityV1:
    if value is None:
        return ResourceQuantityV1("unavailable", "slot", None, reason)
    return ResourceQuantityV1("exact", "slot", value, None)


def _node() -> ResourceInventoryNodeV1:
    return ResourceInventoryNodeV1(
        COMPANY, INCARNATION, LOCK_GENERATION, RES, 1, "pool", "gpu", RCLS, "present",
        ResourceCapacityVectorV1(_q(8), _q(7), _q(1), _q(None, "root_has_no_parent"), "verified"),
    )


def _observation(**changes: object) -> ResourceInventoryObservationV1:
    value = ResourceInventoryObservationV1(
        COMPANY, INCARNATION, LOCK_GENERATION, INV, 1, CLK, T0, T1,
        ResourceInventoryProvenanceV1("synthetic_fixture", SRC, "0" * 64),
        ResourceInventoryCoverageV1("complete", "observed_complete"), (_node(),), (),
    )
    return value._replace(**changes)


def test_observe_closed_schema_canonical_digest_and_fixed_outputs() -> None:
    observed = observe_resource_inventory_v1(_observation())
    assert MARKER == "AOI-SYNTHETIC-FIXTURE-V1"
    assert observed.nodes == (_node(),)
    assert observed.observation_sha256 == observe_resource_inventory_v1(observed).observation_sha256
    assert (
        observed.activation_mode, observed.quantity_policy, observed.contract_scope,
        observed.authority_state, observed.admission_state,
    ) == ("manual_only", "exact_or_unavailable_fixed_unit", "private_off_ledger", "unverified", "not_evaluated")
    with pytest.raises(ResourceInventoryContractError, match="positive"):
        observe_resource_inventory_v1(_observation(inventory_generation=False))
    with pytest.raises(ResourceInventoryContractError, match="canonical UTC"):
        observe_resource_inventory_v1(_observation(observed_at="2026-07-29T00:00:00+00:00"))
    with pytest.raises(AttributeError):
        observed.nodes[0].capacity.total.value = 3  # type: ignore[misc]


def test_canonical_hashed_payload_has_fixed_numeric_schema_abi() -> None:
    observed = observe_resource_inventory_v1(_observation())
    payload = json.loads(_canonical_payload(observed).decode("utf-8"))
    assert payload["contract_type"] == "resource_inventory_observation_v1"
    assert payload["schema_version"] == 1
    assert type(payload["schema_version"]) is int


@pytest.mark.parametrize("company_id", ("Company/One", "company.one", "a" * 129))
def test_company_id_rejects_non_registry_identity_grammar(company_id: str) -> None:
    with pytest.raises(ResourceInventoryContractError, match="company_id"):
        observe_resource_inventory_v1(_observation(company_id=company_id))


def test_company_id_accepts_128_character_registry_identity_boundary() -> None:
    company_id = "a" * 128
    node = _node()._replace(company_id=company_id)
    observed = observe_resource_inventory_v1(_observation(company_id=company_id, nodes=(node,)))
    assert observed.company_id == company_id


def test_empty_coverage_states_are_semantically_and_digest_distinct() -> None:
    complete = observe_resource_inventory_v1(_observation(
        nodes=(), coverage=ResourceInventoryCoverageV1("complete", "observed_empty"),
    ))
    partial = observe_resource_inventory_v1(_observation(
        nodes=(), coverage=ResourceInventoryCoverageV1("partial", "coverage_partial"),
    ))
    unknown = observe_resource_inventory_v1(_observation(
        nodes=(), coverage=ResourceInventoryCoverageV1("unknown", "coverage_unknown"),
    ))
    assert (complete.coverage.state, partial.coverage.state, unknown.coverage.state) == ("complete", "partial", "unknown")
    assert len({complete.observation_sha256, partial.observation_sha256, unknown.observation_sha256}) == 3


def test_unknown_known_nodes_cannot_claim_numeric_capacity() -> None:
    unknown_node = _node()._replace(
        node_state="unknown",
        capacity=ResourceCapacityVectorV1(
            _q(None, "node_unknown"), _q(None, "node_unknown"), _q(None, "node_unknown"),
            _q(None, "root_has_no_parent"), "unavailable",
        ),
    )
    observed = observe_resource_inventory_v1(_observation(
        nodes=(unknown_node,), coverage=ResourceInventoryCoverageV1("unknown", "coverage_unknown"),
    ))
    assert observed.nodes[0].node_state == "unknown"
    with pytest.raises(ResourceInventoryContractError, match="unknown coverage"):
        observe_resource_inventory_v1(_observation(
            coverage=ResourceInventoryCoverageV1("unknown", "coverage_unknown"),
        ))


def test_unknown_node_and_unknown_coverage_reject_exact_parent_carveout() -> None:
    for node_state, reason in (("unknown", "node_unknown"), ("unavailable", "node_unavailable")):
        unavailable_primary = (_q(None, reason),) * 3
        unavailable_node = _node()._replace(
            node_state=node_state,
            capacity=ResourceCapacityVectorV1(*unavailable_primary, _q(1), "unavailable"),
        )
        with pytest.raises(ResourceInventoryContractError, match="exact parent carveout"):
            observe_resource_inventory_v1(_observation(nodes=(unavailable_node,)))

    root = _node()._replace(capacity=ResourceCapacityVectorV1(
        _q(None), _q(None), _q(None), _q(None, "root_has_no_parent"), "unavailable",
    ))
    child_id = "res_00000000000000000000000000000002"
    child = ResourceInventoryNodeV1(
        COMPANY, INCARNATION, LOCK_GENERATION, child_id, 1, "resource", "gpu", RCLS, "present",
        ResourceCapacityVectorV1(_q(None), _q(None), _q(None), _q(1), "unavailable"),
    )
    relation = ResourceInventoryRelationV1(child_id, 1, RES, 1, "carve_out", "unavailable")
    unknown_observation = _observation(
        nodes=(root, child), relations=(relation,),
        coverage=ResourceInventoryCoverageV1("unknown", "coverage_unknown"),
    )
    with pytest.raises(ResourceInventoryContractError, match="unknown coverage"):
        observe_resource_inventory_v1(unknown_observation)

    accepted = observe_resource_inventory_v1(unknown_observation._replace(nodes=(root, child._replace(
        capacity=child.capacity._replace(parent_carveout=_q(None, "relation_operand_unavailable")),
    ))))
    assert accepted.relations[0].numeric_relation_state == "unavailable"


def test_capacity_type_range_and_company_binding_are_strict() -> None:
    with pytest.raises(ResourceInventoryContractError, match="bounded"):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(
            capacity=_node().capacity._replace(total=_q(1 << 63)),
        ),)))
    with pytest.raises(ResourceInventoryContractError, match="bounded"):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(
            capacity=_node().capacity._replace(total=ResourceQuantityV1("exact", "slot", True, None)),
        ),)))
    with pytest.raises(ResourceInventoryContractError, match="company_id"):
        observe_resource_inventory_v1(_observation(company_id="-invalid-company"))


def test_company_triple_cross_binding_and_digest_domain_are_exact() -> None:
    second_company = "company-2"
    second_node = _node()._replace(company_id=second_company)
    second = observe_resource_inventory_v1(_observation(company_id=second_company, nodes=(second_node,)))
    with pytest.raises(ResourceInventoryContractError, match="company binding"):
        observe_resource_inventory_v1(_observation(nodes=second.nodes, observation_sha256=second.observation_sha256))
    with pytest.raises(ResourceInventoryContractError, match="company binding"):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(company_incarnation=2),)))
    with pytest.raises(ResourceInventoryContractError, match="company binding"):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(lock_domain_generation=1),)))

    original = observe_resource_inventory_v1(_observation())
    with pytest.raises(ResourceInventoryContractError, match="SHA-256"):
        observe_resource_inventory_v1(_observation(
            company_incarnation=2,
            nodes=(_node()._replace(company_incarnation=2),),
            observation_sha256=original.observation_sha256,
        ))
    rebound = observe_resource_inventory_v1(_observation(
        company_incarnation=2, nodes=(_node()._replace(company_incarnation=2),),
    ))
    relocked = observe_resource_inventory_v1(_observation(
        lock_domain_generation=1, nodes=(_node()._replace(lock_domain_generation=1),),
    ))
    assert len({original.observation_sha256, second.observation_sha256, rebound.observation_sha256, relocked.observation_sha256}) == 4


def test_closed_scalar_schema_rejects_mutable_string_subclasses() -> None:
    class MutableText(str):
        pass

    def node_with(capacity: ResourceCapacityVectorV1) -> ResourceInventoryObservationV1:
        return _observation(nodes=(_node()._replace(capacity=capacity),))

    base = _node()
    candidates = (
        node_with(base.capacity._replace(total=ResourceQuantityV1(MutableText("exact"), "slot", 8, None))),
        node_with(base.capacity._replace(total=ResourceQuantityV1("exact", MutableText("slot"), 8, None))),
        node_with(base.capacity._replace(parent_carveout=ResourceQuantityV1("unavailable", "slot", None, MutableText("root_has_no_parent")))),
        node_with(base.capacity._replace(numeric_relation_state=MutableText("verified"))),
        _observation(nodes=(base._replace(role=MutableText("pool")),)),
        _observation(nodes=(base._replace(kind=MutableText("gpu")),)),
        _observation(nodes=(base._replace(node_state=MutableText("present")),)),
        _observation(provenance=ResourceInventoryProvenanceV1(MutableText("synthetic_fixture"), SRC, "0" * 64)),
        _observation(coverage=ResourceInventoryCoverageV1(MutableText("complete"), "observed_complete")),
        _observation(coverage=ResourceInventoryCoverageV1("complete", MutableText("observed_complete"))),
        _observation(observation_sha256=MutableText("")),
    )
    for candidate in candidates:
        with pytest.raises(ResourceInventoryContractError):
            observe_resource_inventory_v1(candidate)
    for field, expected in (
        ("activation_mode", "manual_only"),
        ("quantity_policy", "exact_or_unavailable_fixed_unit"),
        ("contract_scope", "private_off_ledger"),
        ("authority_state", "unverified"),
        ("admission_state", "not_evaluated"),
        ("accounting_policy", "root_only"),
        ("overlap_proof", "unverified"),
    ):
        with pytest.raises(ResourceInventoryContractError):
            observe_resource_inventory_v1(_observation(**{field: MutableText(expected)}))
    observed = observe_resource_inventory_v1(_observation())
    mutable_member = observed.memberships[0]._replace(membership=MutableText("root"))
    with pytest.raises(ResourceInventoryContractError):
        observe_resource_inventory_v1(_observation(memberships=(mutable_member,)))


@pytest.mark.parametrize("capacity, message", [
    (ResourceCapacityVectorV1(_q(None), _q(3), _q(4), _q(None, "root_has_no_parent"), "unavailable"), "reserved <= allocatable"),
    (ResourceCapacityVectorV1(_q(3), _q(4), _q(None), _q(None, "root_has_no_parent"), "unavailable"), "allocatable <= total"),
    (ResourceCapacityVectorV1(_q(3), _q(None), _q(4), _q(None, "root_has_no_parent"), "unavailable"), "reserved <= total"),
])
def test_partial_capacity_known_pair_contradictions_reject(capacity: ResourceCapacityVectorV1, message: str) -> None:
    with pytest.raises(ResourceInventoryContractError, match=message):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(capacity=capacity),)))


@pytest.mark.parametrize("field", ("total", "allocatable", "reserved"))
@pytest.mark.parametrize("node_state, valid_reason, invalid_reason", [
    ("present", "not_observed", "root_has_no_parent"),
    ("unavailable", "node_unavailable", "relation_operand_unavailable"),
    ("unknown", "node_unknown", "contains_has_no_charge"),
])
def test_primary_unavailable_reasons_are_state_bound(field: str, node_state: str, valid_reason: str, invalid_reason: str) -> None:
    capacity = ResourceCapacityVectorV1(
        _q(None, valid_reason), _q(None, valid_reason), _q(None, valid_reason),
        _q(None, "root_has_no_parent"), "unavailable",
    )._replace(**{field: _q(None, invalid_reason)})
    with pytest.raises(ResourceInventoryContractError, match="primary unavailable reason"):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(
            node_state=node_state, capacity=capacity,
        ),)))


@pytest.mark.parametrize("field", ("company_id", "company_incarnation", "lock_domain_generation"))
def test_evil_node_binding_values_typed_fail_before_comparison(field: str) -> None:
    class Evil:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("must not compare")

        def __ne__(self, other: object) -> bool:
            raise RuntimeError("must not compare")

    with pytest.raises(ResourceInventoryContractError):
        observe_resource_inventory_v1(_observation(nodes=(_node()._replace(**{field: Evil()}),)))


@pytest.mark.parametrize("field", (
    "resource_id", "resource_generation", "membership", "root_resource_id", "root_resource_generation",
))
def test_evil_membership_values_typed_fail_before_tuple_comparison(field: str) -> None:
    class Evil:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("must not compare")

        def __ne__(self, other: object) -> bool:
            raise RuntimeError("must not compare")

    observed = observe_resource_inventory_v1(_observation())
    evil_member = observed.memberships[0]._replace(**{field: Evil()})
    with pytest.raises(ResourceInventoryContractError):
        observe_resource_inventory_v1(_observation(memberships=(evil_member,)))


def test_membership_input_is_empty_or_canonical_derived_only() -> None:
    observed = observe_resource_inventory_v1(_observation())
    assert observe_resource_inventory_v1(_observation(memberships=observed.memberships)).memberships == observed.memberships
    with pytest.raises(ResourceInventoryContractError, match="diverge"):
        observe_resource_inventory_v1(_observation(memberships=(ResourceInventoryMembershipV1(
            RES, 1, "root", RES, 2,
        ),)))


def test_membership_bound_is_inclusive_and_rejects_before_membership_walk() -> None:
    count = 4096
    root = _node()._replace(capacity=ResourceCapacityVectorV1(
        _q(count), _q(count), _q(0), _q(None, "root_has_no_parent"), "verified",
    ))
    children = tuple(
        ResourceInventoryNodeV1(
            COMPANY, INCARNATION, LOCK_GENERATION, f"res_{number:032x}", 1,
            "resource", "gpu", RCLS, "present",
            ResourceCapacityVectorV1(
                _q(1), _q(1), _q(0), _q(None, "contains_has_no_charge"), "verified",
            ),
        )
        for number in range(2, count + 1)
    )
    relations = tuple(
        ResourceInventoryRelationV1(child.resource_id, 1, RES, 1, "contains")
        for child in children
    )
    observed = observe_resource_inventory_v1(_observation(nodes=(root, *children), relations=relations))
    assert len(observed.memberships) == count
    with pytest.raises(ResourceInventoryContractError, match="bounded"):
        observe_resource_inventory_v1(observed._replace(
            memberships=observed.memberships + (observed.memberships[0],),
        ))
    with pytest.raises(ResourceInventoryContractError, match="bounded"):
        observe_resource_inventory_v1(_observation(
            nodes=(root, *children, children[-1]._replace(resource_id=f"res_{count + 1:032x}")),
            relations=relations,
        ))


def test_freshness_binds_digest_and_fixed_reason_code() -> None:
    observed = observe_resource_inventory_v1(_observation())
    fresh = evaluate_resource_inventory_freshness_v1(observed, T0, CLK)
    assert (fresh.observation_sha256, fresh.state, fresh.reason_code) == (observed.observation_sha256, "fresh", "fresh")
    assert evaluate_resource_inventory_freshness_v1(observed, T1, CLK).reason_code == "ttl_expired"
    assert evaluate_resource_inventory_freshness_v1(observed, "2026-07-28T23:59:59Z", CLK).reason_code == "evaluation_precedes_observation"
    assert evaluate_resource_inventory_freshness_v1(observed, T0, "clk_00000000000000000000000000000002").reason_code == "clock_domain_mismatch"


def test_off_ledger_surface_is_not_registered_or_promoted() -> None:
    assert all("ResourceInventory" not in name for name in company.__all__)
    with pytest.raises(CompanyContractError):
        validate_company_contract({"contract_type": "resource_inventory_observation_v1"})
    modules = (
        Path(__file__).parents[2] / "src/aoi_orgware/company/resources/inventory_contract.py",
        Path(__file__).parents[2] / "src/aoi_orgware/company/resources/inventory_relations.py",
    )
    imported = {
        alias.name
        for module in modules
        for statement in ast.walk(ast.parse(module.read_text(encoding="utf-8")))
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for alias in statement.names
    }
    imported_modules = {
        statement.module or ""
        for module in modules
        for statement in ast.walk(ast.parse(module.read_text(encoding="utf-8")))
        if isinstance(statement, ast.ImportFrom)
    }
    assert not any(
        token in name
        for name in imported | imported_modules
        for token in ("ledger", "registry", "readmodel", "supervisor", "view", "dashboard", "export")
    )
