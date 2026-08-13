"""Forest validation for private resource-inventory values only."""

from __future__ import annotations

from typing import cast

from .inventory_contract import (
    CoverageStateV1,
    NumericRelationStateV1,
    ResourceInventoryMembershipV1,
    ResourceInventoryNodeV1,
    ResourceInventoryRelationV1,
    ResourcePoolForestV1,
    _MAX_CAPACITY,
    _MAX_FOREST_ITEMS,
    _closed_string,
    _fail,
    _opaque,
    _positive_generation,
    _validate_node,
    _validate_unknown_coverage_quantities,
)


def _node_key(node: ResourceInventoryNodeV1) -> tuple[str, int]:
    return node.resource_id, node.resource_generation


def _relation_key(relation: ResourceInventoryRelationV1) -> tuple[object, ...]:
    return (
        relation.child_resource_id,
        relation.child_resource_generation,
        relation.parent_resource_id,
        relation.parent_resource_generation,
        relation.relation,
    )


def _validate_relation(value: object) -> ResourceInventoryRelationV1:
    if type(value) is not ResourceInventoryRelationV1:
        _fail("relation must be exactly ResourceInventoryRelationV1")
    relation = cast(ResourceInventoryRelationV1, value)
    _opaque(relation.child_resource_id, "res_", "child_resource_id")
    _opaque(relation.parent_resource_id, "res_", "parent_resource_id")
    _positive_generation(relation.child_resource_generation, "child_resource_generation")
    _positive_generation(relation.parent_resource_generation, "parent_resource_generation")
    _closed_string(relation.relation, frozenset({"contains", "carve_out"}), "relation.relation")
    if (
        relation.child_resource_id == relation.parent_resource_id
        and relation.child_resource_generation == relation.parent_resource_generation
    ):
        _fail("relation cannot be self-referential")
    _closed_string(
        relation.numeric_relation_state,
        frozenset({"verified", "unavailable", "not_applicable"}),
        "relation.numeric_relation_state",
    )
    return relation


def _exact(node: ResourceInventoryNodeV1, name: str) -> int | None:
    quantity = getattr(node.capacity, name)
    return quantity.value if quantity.availability == "exact" else None


def _expected_carve_state(
    coverage_state: CoverageStateV1,
    child_total: int | None,
    parent_reserved: int | None,
    all_sibling_carveouts_exact: bool,
) -> NumericRelationStateV1:
    if (
        coverage_state == "complete"
        and child_total is not None
        and parent_reserved is not None
        and all_sibling_carveouts_exact
    ):
        return "verified"
    return "unavailable"


def validate_resource_pool_forest_v1(
    nodes: tuple[ResourceInventoryNodeV1, ...],
    relations: tuple[ResourceInventoryRelationV1, ...],
    coverage_state: CoverageStateV1 = "complete",
) -> ResourcePoolForestV1:
    """Validate and canonically order a single-company, acyclic pool forest."""
    if type(nodes) is not tuple or type(relations) is not tuple:
        _fail("forest inputs must be immutable tuples")
    if len(nodes) > _MAX_FOREST_ITEMS or len(relations) > _MAX_FOREST_ITEMS:
        _fail("forest exceeds the bounded item count")
    coverage_state = cast(
        CoverageStateV1,
        _closed_string(coverage_state, frozenset({"complete", "partial", "unknown"}), "coverage_state"),
    )

    by_key: dict[tuple[str, int], ResourceInventoryNodeV1] = {}
    seen_ids: set[str] = set()
    if nodes:
        first = nodes[0]
        if type(first) is not ResourceInventoryNodeV1:
            _fail("forest nodes must be exactly ResourceInventoryNodeV1")
        _validate_node(
            first,
            first.company_id,
            first.company_incarnation,
            first.lock_domain_generation,
        )
        company_id = first.company_id
        company_incarnation = first.company_incarnation
        lock_domain_generation = first.lock_domain_generation
    else:
        company_id = ""
        company_incarnation = 0
        lock_domain_generation = 0
    for node in nodes:
        if type(node) is not ResourceInventoryNodeV1:
            _fail("forest nodes must be exactly ResourceInventoryNodeV1")
        _validate_node(node, company_id, company_incarnation, lock_domain_generation)
        key = _node_key(node)
        if node.resource_id in seen_ids:
            _fail("a resource ID cannot appear at more than one generation")
        if key in by_key:
            _fail("forest contains duplicate nodes")
        seen_ids.add(node.resource_id)
        by_key[key] = node
    if coverage_state == "unknown":
        _validate_unknown_coverage_quantities(tuple(by_key.values()))

    parent_of: dict[tuple[str, int], ResourceInventoryRelationV1] = {}
    carveout_summary: dict[tuple[str, int], tuple[int, bool]] = {}
    seen_relations: set[tuple[object, ...]] = set()
    for raw_relation in relations:
        relation = _validate_relation(raw_relation)
        relation_key = _relation_key(relation)
        if relation_key in seen_relations:
            _fail("forest contains duplicate relations")
        seen_relations.add(relation_key)
        child_key = (relation.child_resource_id, relation.child_resource_generation)
        parent_key = (relation.parent_resource_id, relation.parent_resource_generation)
        if child_key not in by_key or parent_key not in by_key:
            _fail("relation endpoint is missing from the forest")
        if by_key[parent_key].role != "pool":
            _fail("every relation parent must be a pool")
        if child_key in parent_of:
            _fail("a forest node may have at most one parent")
        parent_of[child_key] = relation
        if relation.relation == "carve_out":
            carveout = _exact(by_key[child_key], "parent_carveout")
            known_sum, all_exact = carveout_summary.get(parent_key, (0, True))
            if carveout is None:
                all_exact = False
            else:
                known_sum += carveout
                if known_sum > _MAX_CAPACITY:
                    _fail("direct carve-out sum overflows the bounded capacity domain")
            carveout_summary[parent_key] = (known_sum, all_exact)

    roots: dict[tuple[str, int], tuple[str, int]] = {}
    for start in by_key:
        if start in roots:
            continue
        path: list[tuple[str, int]] = []
        path_seen: set[tuple[str, int]] = set()
        cursor = start
        while cursor not in roots and cursor in parent_of:
            if cursor in path_seen:
                _fail("forest contains a cycle")
            path_seen.add(cursor)
            path.append(cursor)
            relation = parent_of[cursor]
            cursor = (relation.parent_resource_id, relation.parent_resource_generation)
        if cursor in path_seen:
            _fail("forest contains a cycle")
        root = roots[cursor] if cursor in roots else cursor
        if by_key[root].role != "pool":
            _fail("every non-root must reach exactly one pool root")
        for key in path:
            roots[key] = root
        roots.setdefault(start, root)

    for key, node in by_key.items():
        parent_relation = parent_of.get(key)
        parent_carveout = node.capacity.parent_carveout
        if parent_relation is None:
            if (
                parent_carveout.availability != "unavailable"
                or parent_carveout.reason_code != "root_has_no_parent"
            ):
                _fail("pool roots must use root_has_no_parent")
            continue
        if parent_relation.relation == "contains":
            if (
                parent_carveout.availability != "unavailable"
                or parent_carveout.reason_code != "contains_has_no_charge"
            ):
                _fail("contains children must use contains_has_no_charge")
            if parent_relation.numeric_relation_state != "not_applicable":
                _fail("contains relation numeric state must be not_applicable")
            continue

        parent_key = (parent_relation.parent_resource_id, parent_relation.parent_resource_generation)
        parent = by_key[parent_key]
        if (
            node.kind != parent.kind
            or node.resource_class_id != parent.resource_class_id
            or parent_carveout.unit != parent.capacity.total.unit
        ):
            _fail("carve-out child must have the same kind, unit, and resource class as its parent")
        if parent_carveout.availability == "unavailable" and parent_carveout.reason_code in (
            "root_has_no_parent",
            "contains_has_no_charge",
        ):
            _fail("carve-out unavailable parent carveout needs an observation reason")
        child_total = _exact(node, "total")
        parent_reserved = _exact(parent, "reserved")
        known_sum, all_sibling_exact = carveout_summary[parent_key]
        carveout = _exact(node, "parent_carveout")
        if child_total is not None and carveout is not None and child_total > carveout:
            _fail("carve-out child total cannot exceed its parent carveout")
        if parent_reserved is not None and known_sum > parent_reserved:
            _fail("direct carve-out sum cannot exceed parent reserved capacity")
        expected = _expected_carve_state(coverage_state, child_total, parent_reserved, all_sibling_exact)
        if parent_relation.numeric_relation_state != expected:
            _fail("carve-out numeric state must reflect coverage and operand availability")

    memberships = tuple(
        sorted(
            (
                ResourceInventoryMembershipV1(
                    resource_id=node.resource_id,
                    resource_generation=node.resource_generation,
                    membership="root" if key == roots[key] else "included_in_root",
                    root_resource_id=roots[key][0],
                    root_resource_generation=roots[key][1],
                )
                for key, node in by_key.items()
            ),
            key=lambda value: (value.resource_id, value.resource_generation),
        )
    )
    return ResourcePoolForestV1(
        nodes=tuple(sorted(by_key.values(), key=_node_key)),
        relations=tuple(sorted(relations, key=_relation_key)),
        memberships=memberships,
    )
