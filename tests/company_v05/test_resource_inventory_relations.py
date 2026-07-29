# AOI-SYNTHETIC-FIXTURE-V1
"""Private inventory forest tests."""

from __future__ import annotations

import pytest
from aoi_orgware.company.resources import (
    ResourceCapacityVectorV1,
    ResourceInventoryContractError,
    ResourceInventoryNodeV1,
    ResourceInventoryRelationV1,
    ResourceQuantityV1,
    validate_resource_pool_forest_v1,
)


MARKER = "AOI-SYNTHETIC-FIXTURE-V1"
COMPANY = "company-1"
INCARNATION = 1
LOCK_GENERATION = 0


def _id(number: int) -> str:
    return f"res_{number:032x}"


def _class_id(number: int = 1) -> str:
    return f"rcls_{number:032x}"


def _q(value: int | None, reason: str = "not_observed") -> ResourceQuantityV1:
    if value is None:
        return ResourceQuantityV1("unavailable", "slot", None, reason)
    return ResourceQuantityV1("exact", "slot", value, None)


def _node(
    number: int,
    role: str,
    total: int | None,
    reserved: int | None,
    carveout: int | None = None,
    *,
    carve_reason: str = "root_has_no_parent",
    resource_class: int = 1,
) -> ResourceInventoryNodeV1:
    return ResourceInventoryNodeV1(
        COMPANY, INCARNATION, LOCK_GENERATION, _id(number), 1, role, "gpu", _class_id(resource_class), "present",
        ResourceCapacityVectorV1(
            _q(total), _q(total), _q(reserved), _q(carveout, carve_reason),
            "verified" if total is not None and reserved is not None else "unavailable",
        ),
    )


def _relation(child: int, parent: int, kind: str, state: str = "not_applicable") -> ResourceInventoryRelationV1:
    return ResourceInventoryRelationV1(_id(child), 1, _id(parent), 1, kind, state)


def test_forest_canonical_membership_contains_and_carveout() -> None:
    root = _node(1, "pool", 10, 6)
    contains = _node(2, "resource", 1, 0, carve_reason="contains_has_no_charge")
    child = _node(3, "resource", 4, 0, 4)
    relations = (_relation(3, 1, "carve_out", "verified"), _relation(2, 1, "contains"))
    forest = validate_resource_pool_forest_v1((child, root, contains), relations)
    assert MARKER == "AOI-SYNTHETIC-FIXTURE-V1"
    assert tuple(node.resource_id for node in forest.nodes) == tuple(sorted(node.resource_id for node in (root, contains, child)))
    assert {member.membership for member in forest.memberships} == {"root", "included_in_root"}
    assert validate_resource_pool_forest_v1((root, contains, child), tuple(reversed(relations))) == forest


@pytest.mark.parametrize("relations, message", [
    ((_relation(2, 1, "contains"), _relation(2, 3, "contains")), "at most one parent"),
    ((_relation(2, 99, "contains"),), "missing"),
    ((_relation(2, 1, "contains"), _relation(2, 1, "contains")), "duplicate"),
    ((_relation(1, 1, "contains"),), "self"),
])
def test_graph_failures(relations: tuple[ResourceInventoryRelationV1, ...], message: str) -> None:
    nodes = (
        _node(1, "pool", 2, 0),
        _node(2, "resource", 1, 0, carve_reason="contains_has_no_charge"),
        _node(3, "pool", 2, 0),
    )
    with pytest.raises(ResourceInventoryContractError, match=message):
        validate_resource_pool_forest_v1(nodes, relations)


def test_cycle_and_direct_public_shape_validation() -> None:
    first = _node(1, "pool", 2, 0, carve_reason="contains_has_no_charge")
    second = _node(2, "pool", 2, 0, carve_reason="contains_has_no_charge")
    with pytest.raises(ResourceInventoryContractError, match="cycle"):
        validate_resource_pool_forest_v1(
            (first, second), (_relation(1, 2, "contains"), _relation(2, 1, "contains")),
        )
    bad_unit = first._replace(kind="ram")
    with pytest.raises(ResourceInventoryContractError, match="fixed unit"):
        validate_resource_pool_forest_v1((bad_unit,), ())
    duplicate_generation = first._replace(resource_generation=2)
    with pytest.raises(ResourceInventoryContractError, match="more than one generation"):
        validate_resource_pool_forest_v1((first, duplicate_generation), ())
    malformed = _relation(2, 1, "contains")._replace(child_resource_id="res_bad")
    with pytest.raises(ResourceInventoryContractError, match="opaque"):
        validate_resource_pool_forest_v1((first, second), (malformed,))
    with pytest.raises(ResourceInventoryContractError, match="company binding"):
        validate_resource_pool_forest_v1((first, second._replace(company_id="cmp_00000000000000000000000000000002")), ())


@pytest.mark.parametrize("field", ("company_id", "company_incarnation", "lock_domain_generation"))
def test_direct_forest_first_binding_malformed_typed_fails(field: str) -> None:
    with pytest.raises(ResourceInventoryContractError):
        validate_resource_pool_forest_v1((_node(1, "pool", 2, 0)._replace(**{field: None}),), ())


def test_direct_unknown_coverage_and_relation_scalars_are_closed() -> None:
    class MutableText(str):
        pass

    root = _node(1, "pool", None, None)
    child = _node(2, "resource", None, None, 1)
    carve = _relation(2, 1, "carve_out", "unavailable")
    with pytest.raises(ResourceInventoryContractError, match="unknown coverage"):
        validate_resource_pool_forest_v1((root, child), (carve,), "unknown")
    with pytest.raises(ResourceInventoryContractError, match="closed string"):
        validate_resource_pool_forest_v1((root, child), (carve,), MutableText("unknown"))
    with pytest.raises(ResourceInventoryContractError, match="closed string"):
        validate_resource_pool_forest_v1((root, child), (carve._replace(relation=MutableText("carve_out")),))
    with pytest.raises(ResourceInventoryContractError, match="closed string"):
        validate_resource_pool_forest_v1((root, child), (carve._replace(numeric_relation_state=MutableText("unavailable")),), "partial")
    accepted = validate_resource_pool_forest_v1(
        (root, child._replace(capacity=child.capacity._replace(parent_carveout=_q(None, "relation_operand_unavailable")))),
        (carve,), "unknown",
    )
    assert accepted.relations[0].numeric_relation_state == "unavailable"


def test_carveout_allows_closed_unavailable_operand_and_checks_known_predicates() -> None:
    root = _node(1, "pool", 10, 4)
    unavailable_child = _node(2, "resource", None, None, None, carve_reason="relation_operand_unavailable")
    relation = _relation(2, 1, "carve_out", "unavailable")
    forest = validate_resource_pool_forest_v1((root, unavailable_child), (relation,), "partial")
    assert forest.relations[0].numeric_relation_state == "unavailable"

    too_large = _node(2, "resource", 5, 0, 4)
    with pytest.raises(ResourceInventoryContractError, match="cannot exceed"):
        validate_resource_pool_forest_v1((root, too_large), (relation._replace(numeric_relation_state="unavailable"),), "partial")
    overcommitted = _node(2, "resource", 4, 0, 4)
    with pytest.raises(ResourceInventoryContractError, match="reserved"):
        validate_resource_pool_forest_v1((root._replace(capacity=root.capacity._replace(reserved=_q(3))), overcommitted), (relation._replace(numeric_relation_state="unavailable"),), "partial")
    with pytest.raises(ResourceInventoryContractError, match="resource class"):
        validate_resource_pool_forest_v1((root, overcommitted._replace(resource_class_id=_class_id(2))), (relation._replace(numeric_relation_state="verified"),))


def test_known_partial_sibling_sum_and_overflow_are_rejected() -> None:
    maximum = (1 << 63) - 1
    root = _node(1, "pool", None, None)
    first = _node(2, "resource", None, None, maximum)
    second = _node(3, "resource", None, None, 1)
    relations = (_relation(2, 1, "carve_out", "unavailable"), _relation(3, 1, "carve_out", "unavailable"))
    with pytest.raises(ResourceInventoryContractError, match="overflows"):
        validate_resource_pool_forest_v1((root, first, second), relations, "partial")


def test_many_siblings_have_bounded_single_parent_summary() -> None:
    count = 128
    root = _node(1, "pool", count, count)
    children = tuple(_node(number, "resource", 1, 0, 1) for number in range(2, count + 2))
    relations = tuple(_relation(number, 1, "carve_out", "verified") for number in range(2, count + 2))
    forest = validate_resource_pool_forest_v1((root, *children), relations)
    assert len(forest.relations) == count
    assert all(relation.numeric_relation_state == "verified" for relation in forest.relations)
