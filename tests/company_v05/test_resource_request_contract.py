# AOI-SYNTHETIC-FIXTURE-V1
"""Synthetic fixtures for immutable resource-request content only."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

import pytest

import aoi_orgware.company.resources.request_contract as request_contract
from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    TASK_REVISION_V1,
    WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    WORK_PACKET_V1,
    company_contract_sha256,
)
from aoi_orgware.company.resources.request_contract import (
    ResourceRequestV1,
    ResourceRequestV1Error,
    ResourceRequestRequirementV1,
    derive_resource_request_v1,
    validate_resource_request_structure_v1,
    validate_resource_request_v1,
)
from aoi_orgware.company.resources.request_mapping import (
    ResourceMappingSelectionV1,
    ResourceRequirementMappingBundleV1,
    derive_resource_requirement_mapping_bundle_v1,
)
from aoi_orgware.company.scheduling.qos import (
    WorkQoSIntentV1,
    validate_work_qos_intent_v1,
    work_qos_intent_v1_preimage_sha256,
)
from tests.company_v05.test_resource_request_mapping import COMPANY, H, _inventory, _qos, _selections


MARKER = "AOI-SYNTHETIC-FIXTURE-V1"


def _blob(media_type: str, digest: str = H) -> dict[str, object]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": digest,
            "size_bytes": 1, "media_type": media_type, "availability": "available"}


def _scope() -> dict[str, object]:
    return {"read_refs": [{"kind": "tree", "path": "src"}], "write_refs": [],
            "run_refs": [{"kind": "tree", "path": "src"}], "export_refs": [],
            "provider_allowlist": ["codex"]}


def _task() -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": TASK_REVISION_V1, "schema_version": 1,
        "company_id": COMPANY, "company_incarnation": 1, "lock_domain_generation": 2,
        "task_id": "task-1", "task_revision_id": "task-revision-1", "revision": 1,
        "previous_task_revision_id": None, "previous_task_sha256": None,
        "display_name": "fixture task", "objective": "private objective must not serialize",
        "authority_ceiling": _scope(), "completion_boundary_ref": _blob("text/plain"),
        "created_at": "2026-07-31T00:00:00Z",
    }
    value["task_sha256"] = company_contract_sha256(value)
    return value


def _packet(
    task: dict[str, object], *, packet_id: str = "packet-1", created_at: str = "2026-07-31T00:00:00Z",
) -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": WORK_PACKET_V1, "schema_version": 1,
        "company_id": COMPANY, "company_incarnation": 1, "lock_domain_generation": 2,
        "packet_id": packet_id, "parent_packet_id": None, "parent_packet_sha256": None,
        "task_id": task["task_id"], "task_revision_id": task["task_revision_id"], "task_sha256": task["task_sha256"],
        "manager_node_id": None, "parent_execution_id": None, "target_node_id": "worker-1", "department_id": "rtl",
        "null_relationship_justifications": {"manager_node_id": "root", "parent_execution_id": "pre-admission",
            "target_node_id": None, "department_id": None}, "delegation_depth": 1,
        "display_name": "fixture packet", "objective": "private packet objective must not serialize",
        "prompt_ref": _blob(WORK_PACKET_PROMPT_MEDIA_TYPE),
        "context_manifest_ref": _blob(WORK_CONTEXT_MANIFEST_MEDIA_TYPE),
        "source_manifest_sha256": H, "config_manifest_sha256": "b" * 64, "dependency_manifest_sha256": "c" * 64,
        "authority_scope": _scope(),
        "redaction_policy": {"dashboard": "metadata_only", "secrets": "excluded", "chain_of_thought": "forbidden"},
        "created_at": created_at, "expires_at": "2026-08-02T00:00:00Z",
    }
    value["packet_sha256"] = company_contract_sha256(value)
    return value


def _bundle(
    qos: WorkQoSIntentV1 | None = None,
    selections: tuple[ResourceMappingSelectionV1, ...] | None = None,
) -> tuple[WorkQoSIntentV1, tuple[ResourceMappingSelectionV1, ...], ResourceRequirementMappingBundleV1]:
    intent = _qos() if qos is None else qos
    chosen = _selections() if selections is None else selections
    return intent, chosen, derive_resource_requirement_mapping_bundle_v1(intent, _inventory(), chosen)


def _request(
    qos: WorkQoSIntentV1 | None = None,
    selections: tuple[ResourceMappingSelectionV1, ...] | None = None,
) -> tuple[ResourceRequestV1, dict[str, object], dict[str, object], WorkQoSIntentV1, ResourceRequirementMappingBundleV1, tuple[ResourceMappingSelectionV1, ...]]:
    task = _task()
    packet = _packet(task)
    intent, chosen, bundle = _bundle(qos, selections)
    return (derive_resource_request_v1(task, packet, intent, bundle, _inventory(), chosen),
            task, packet, intent, bundle, chosen)


def _rehash_request(value: ResourceRequestV1, **changes: object) -> ResourceRequestV1:
    provisional = cast(ResourceRequestV1, cast(Any, value)._replace(**changes, request_sha256=""))
    return provisional._replace(request_sha256=request_contract._request_digest(provisional))


def _rehash_first_requirement(
    value: ResourceRequestV1, **changes: object,
) -> ResourceRequestV1:
    requirements = cast(
        tuple[ResourceRequestRequirementV1, ...],
        (cast(Any, value.requirements[0])._replace(**changes), *value.requirements[1:]),
    )
    provisional = value._replace(
        requirements=requirements,
        demand_sha256=request_contract._demand_digest(requirements),
        request_sha256="",
    )
    return provisional._replace(request_sha256=request_contract._request_digest(provisional))


def _changed_qos(qos: WorkQoSIntentV1, **changes: object) -> WorkQoSIntentV1:
    raw = qos.to_dict()
    configured = cast(dict[str, object], raw["configured_capacity"])
    raw["configured_capacity"] = {"configured_capacity_id": configured["configured_capacity_id"],
                                    "configured_capacity_tokens": configured["configured_capacity_tokens"]}
    raw.update(changes)
    raw["intent_digest"] = work_qos_intent_v1_preimage_sha256(raw)
    return validate_work_qos_intent_v1(raw)


class _IntSubclass(int):
    pass


class _StringSubclass(str):
    pass


class _EqualOtherInt(int):
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class _EqualOtherString(str):
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


def _rehash_task_contract(value: dict[str, object]) -> None:
    value["task_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "task_sha256"}
    )


def _rehash_packet_contract(value: dict[str, object]) -> None:
    value["packet_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "packet_sha256"}
    )


def _benign_scalar_subclass(value: object) -> object:
    if type(value) is int:
        return _IntSubclass(value)
    return _StringSubclass(cast(str, value))


def _cpu_request() -> tuple[
    ResourceRequestV1, dict[str, object], dict[str, object], WorkQoSIntentV1,
    ResourceRequirementMappingBundleV1, tuple[ResourceMappingSelectionV1, ...],
]:
    return _request(
        _qos(resources=[{"kind": "cpu", "unit": "cores", "minimum": 1, "maximum": 2}]),
        (_selections()[0],),
    )


def _assert_requirement_rejected_by_both_validators(
    request: ResourceRequestV1,
    task: dict[str, object],
    packet: dict[str, object],
    qos: WorkQoSIntentV1,
    bundle: ResourceRequirementMappingBundleV1,
    selections: tuple[ResourceMappingSelectionV1, ...],
) -> None:
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(request)
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_v1(request, task, packet, qos, bundle, _inventory(), selections)


_REQUIREMENT_FIELDS = (
    "qos_kind", "qos_unit", "original_minimum", "original_maximum",
    "mapped_resource_kind", "mapped_resource_unit", "mapped_minimum", "mapped_maximum",
    "mapping_state", "resolution_state",
)


@pytest.mark.parametrize("field", _REQUIREMENT_FIELDS)
def test_requirement_same_content_subclasses_reject_in_structural_and_semantic_validation(
    field: str,
) -> None:
    request, task, packet, qos, bundle, selections = _cpu_request()
    forged = _rehash_first_requirement(
        request, **{field: _benign_scalar_subclass(getattr(request.requirements[0], field))},
    )
    _assert_requirement_rejected_by_both_validators(forged, task, packet, qos, bundle, selections)


@pytest.mark.parametrize("field", _REQUIREMENT_FIELDS)
def test_requirement_different_content_custom_equality_subclasses_reject_structurally(
    field: str,
) -> None:
    request, *_ = _cpu_request()
    original = getattr(request.requirements[0], field)
    replacement: object = _EqualOtherInt(int(original) + 1) if type(original) is int else _EqualOtherString("other")
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(_rehash_first_requirement(request, **{field: replacement}))


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("mapped_resource_kind", _EqualOtherString("not-none")),
        ("mapped_resource_unit", _EqualOtherString("not-none")),
        ("mapped_minimum", _EqualOtherInt(1)),
        ("mapped_maximum", _EqualOtherInt(1)),
    ),
)
def test_network_requirement_subclasses_cannot_imitate_none(
    field: str, replacement: object,
) -> None:
    network = _qos(resources=[{"kind": "network", "unit": "mbps", "minimum": 0, "maximum": 9}])
    request, task, packet, qos, bundle, selections = _request(network, (_selections()[-1],))
    forged = _rehash_first_requirement(request, **{field: replacement})
    _assert_requirement_rejected_by_both_validators(forged, task, packet, qos, bundle, selections)


@pytest.mark.parametrize(
    ("source", "field"),
    (
        *(("task", field) for field in (
            "company_id", "company_incarnation", "lock_domain_generation", "task_id",
            "task_revision_id", "revision", "task_sha256", "created_at",
        )),
        *(("packet", field) for field in (
            "company_id", "company_incarnation", "lock_domain_generation", "packet_id",
            "task_id", "task_revision_id", "task_sha256", "packet_sha256", "created_at", "expires_at",
        )),
    ),
)
def test_derive_rejects_retained_upstream_scalar_subclasses(
    source: str, field: str
) -> None:
    task = _task()
    if source == "task":
        task[field] = _benign_scalar_subclass(task[field])
        _rehash_task_contract(task)
        if field == "task_sha256":
            task[field] = _StringSubclass(cast(str, task[field]))

    packet = _packet(task)
    if source == "packet":
        packet[field] = _benign_scalar_subclass(packet[field])
        _rehash_packet_contract(packet)
        if field == "packet_sha256":
            packet[field] = _StringSubclass(cast(str, packet[field]))

    qos, selections, bundle = _bundle()
    with pytest.raises(ResourceRequestV1Error):
        derive_resource_request_v1(task, packet, qos, bundle, _inventory(), selections)


@pytest.mark.parametrize(
    ("source", "field", "replacement"),
    (
        ("packet", "task_id", _EqualOtherString("other-task")),
        ("packet", "task_revision_id", _EqualOtherString("other-task-revision")),
        ("packet", "task_sha256", _EqualOtherString("d" * 64)),
        ("task", "company_id", _EqualOtherString("other-company")),
        ("packet", "company_incarnation", _EqualOtherInt(9)),
        ("packet", "lock_domain_generation", _EqualOtherInt(9)),
    ),
)
def test_derive_rejects_custom_equality_upstream_bindings(
    source: str, field: str, replacement: object,
) -> None:
    task = _task()
    if source == "task":
        task[field] = replacement
        _rehash_task_contract(task)
    packet = _packet(task)
    if source == "packet":
        packet[field] = replacement
        _rehash_packet_contract(packet)

    qos, selections, bundle = _bundle()
    with pytest.raises(ResourceRequestV1Error):
        derive_resource_request_v1(task, packet, qos, bundle, _inventory(), selections)


def test_content_is_deterministic_deep_immutable_and_exactly_rederives() -> None:
    first, task, packet, qos, bundle, selections = _request()
    alternate = derive_resource_requirement_mapping_bundle_v1(qos, _inventory(), tuple(reversed(selections)))
    second = derive_resource_request_v1(task, packet, qos, alternate, _inventory(), tuple(reversed(selections)))
    assert first == second and validate_resource_request_v1(first, task, packet, qos, bundle, _inventory(), selections) == first
    assert not hasattr(first, "__dict__") and type(first.requirements) is tuple
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(first, "task_revision", 9)
    detached = first.to_dict()
    cast(list[object], detached["requirements"]).clear()
    assert first.requirements


def test_demand_is_resource_only_but_request_binds_mapping_and_qos() -> None:
    first, task, packet, qos, _, _ = _request()
    alternate_selection = ("cpu", "res_00000000000000000000000000000005", 1)
    inventory = _inventory(alternate_cpu=True)
    selected = list(_selections())
    selected[0] = type(selected[0])(*alternate_selection)
    alternate_bundle = derive_resource_requirement_mapping_bundle_v1(qos, inventory, tuple(selected))
    moved = derive_resource_request_v1(task, packet, qos, alternate_bundle, inventory, tuple(selected))
    changed = _changed_qos(qos, latency_class="batch")
    changed_bundle = derive_resource_requirement_mapping_bundle_v1(changed, _inventory(), _selections())
    changed_request = derive_resource_request_v1(task, packet, changed, changed_bundle, _inventory(), _selections())
    assert first.demand_sha256 == moved.demand_sha256 == changed_request.demand_sha256
    assert first.request_sha256 != moved.request_sha256 != changed_request.request_sha256


def test_network_empty_and_named_zero_content_boundaries() -> None:
    network = _qos(resources=[{"kind": "network", "unit": "mbps", "minimum": 0, "maximum": 9}])
    request, *_ = _request(network, (_selections()[-1],))
    requirement = request.requirements[0]
    assert (requirement.original_minimum, requirement.original_maximum, requirement.mapping_state,
            requirement.resolution_state, requirement.mapped_minimum) == (0, 9, "mapping_unavailable", "unresolved", None)
    empty = _qos(resources=[])
    empty_request, *_ = _request(empty, ())
    assert empty_request.requirements == () and empty_request.demand_sha256 != request.demand_sha256
    zero = _qos(resources=[{"kind": "cpu", "unit": "cores", "minimum": 0, "maximum": 0}])
    with pytest.raises(ResourceRequestV1Error, match="zero-to-zero"):
        _request(zero, (_selections()[0],))


def test_crossbindings_and_complete_mapping_witnesses_reject_even_recomputed() -> None:
    request, task, packet, qos, bundle, selections = _request()
    wrong_packet = dict(packet, task_revision_id="other")
    wrong_packet["packet_sha256"] = company_contract_sha256({key: value for key, value in wrong_packet.items() if key != "packet_sha256"})
    with pytest.raises(ResourceRequestV1Error):
        derive_resource_request_v1(task, wrong_packet, qos, bundle, _inventory(), selections)
    wrong_qos = _changed_qos(qos)
    wrong_qos = cast(Any, wrong_qos)._replace(intent_scope=cast(Any, wrong_qos.intent_scope._replace(packet_id="other")))
    with pytest.raises(ResourceRequestV1Error):
        derive_resource_request_v1(task, packet, wrong_qos, bundle, _inventory(), selections)
    partial = cast(Any, bundle)._replace(expected_candidate_count=1, candidates=bundle.candidates[:1], bundle_sha256="")
    partial = partial._replace(bundle_sha256=__import__("aoi_orgware.company.resources.request_mapping", fromlist=["*"])._bundle_digest(partial))
    with pytest.raises(ResourceRequestV1Error):
        derive_resource_request_v1(task, packet, qos, partial, _inventory(), selections)
    assert request


def test_fixed_semantics_and_privacy_cannot_be_forged_or_operationalized() -> None:
    request, task, packet, qos, bundle, selections = _request()
    forged = _rehash_request(request, capacity_state="available")
    with pytest.raises(ResourceRequestV1Error, match="semantic"):
        validate_resource_request_structure_v1(forged)
    serialized = repr(request.to_dict()).lower()
    for forbidden in ("task-1", "packet-1", "objective", "counter_scope", "configured_capacity", "selected_resource",
                      "canonical_root", "inventory_id", "topology", "host", "vm", "license", "path"):
        assert forbidden not in serialized
    tree = ast.parse((Path(__file__).parents[2] / "src/aoi_orgware/company/resources/request_contract.py").read_text(encoding="utf-8"))
    modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(token in module.lower() for module in modules for token in ("ledger", "registry", "readmodel", "supervisor", "dispatch", "views", "provider"))
    assert not any(hasattr(request_contract, name) for name in ("reserve", "lease", "admit", "activate", "hold", "release", "dispatch"))
    assert validate_resource_request_v1(request, task, packet, qos, bundle, _inventory(), selections) == request


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("company_id", "company id"),
        ("task_revision_id", ""),
        ("task_revision_id", "revision id"),
        ("qos_deadline_at", "2026-08-01T00:00:00+00:00"),
        ("qos_deadline_at", "2026-02-30T00:00:00Z"),
        ("qos_deadline_at", ""),
    ],
)
def test_structural_api_rejects_recomputed_invalid_identifiers_and_qos_deadlines(
    field: str, value: str,
) -> None:
    request, *_ = _request()
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(_rehash_request(request, **{field: value}))


def test_qos_deadline_must_be_within_packet_lifetime_and_can_equal_created_at() -> None:
    request, task, _, qos, bundle, selections = _request()
    late_packet = _packet(task, created_at="2026-08-01T00:00:01Z")
    with pytest.raises(ResourceRequestV1Error, match="outside packet"):
        derive_resource_request_v1(task, late_packet, qos, bundle, _inventory(), selections)
    with pytest.raises(ResourceRequestV1Error, match="outside packet"):
        validate_resource_request_v1(request, task, late_packet, qos, bundle, _inventory(), selections)
    boundary_packet = _packet(task, created_at=qos.deadline_at)
    boundary = derive_resource_request_v1(task, boundary_packet, qos, bundle, _inventory(), selections)
    assert boundary.qos_deadline_at == boundary_packet["created_at"] and request


@pytest.mark.parametrize(
    "field",
    ("company_incarnation", "lock_domain_generation", "task_revision", "qos_intent_revision"),
)
def test_structural_contract_revision_bounds_are_exact_and_recomputed(field: str) -> None:
    request, *_ = _request()
    maximum = request_contract.MAX_CONTRACT_REVISION
    assert validate_resource_request_structure_v1(_rehash_request(request, **{field: maximum}))._fields == request._fields
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(_rehash_request(request, **{field: maximum + 1}))


@pytest.mark.parametrize("field", ("original_minimum", "original_maximum"))
def test_structural_qos_resource_bounds_reject_recomputed_max_plus_one(field: str) -> None:
    request, *_ = _request(_qos(resources=[{"kind": "cpu", "unit": "cores", "minimum": 1, "maximum": 2}]), (_selections()[0],))
    maximum = request_contract.MAX_QOS_RESOURCE_VALUE
    changes: dict[str, object] = {field: maximum + 1}
    if field == "original_minimum":
        changes["original_maximum"] = maximum + 1
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(_rehash_first_requirement(request, **changes))
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(_rehash_first_requirement(request, **{field: True}))


def test_exact_upstream_bounds_preserve_large_mapped_values_without_raw_qos_cap() -> None:
    maximum = request_contract.MAX_QOS_RESOURCE_VALUE
    qos = _qos(
        resources=[{"kind": "cpu", "unit": "cores", "minimum": maximum, "maximum": maximum}],
        revision=request_contract.MAX_CONTRACT_REVISION,
    )
    request, task, packet, intent, bundle, selections = _request(qos, (_selections()[0],))
    requirement = request.requirements[0]
    assert (request.qos_intent_revision, requirement.original_minimum, requirement.original_maximum,
            requirement.mapped_minimum, requirement.mapped_maximum) == (
                request_contract.MAX_CONTRACT_REVISION, maximum, maximum, maximum * 1_000, maximum * 1_000,
            )
    assert validate_resource_request_v1(request, task, packet, intent, bundle, _inventory(), selections) == request
    task["revision"] = request_contract.MAX_CONTRACT_REVISION
    task["task_revision_id"] = "task-revision-999999999"
    task["previous_task_revision_id"] = "task-revision-999999998"
    task["previous_task_sha256"] = H
    task["task_sha256"] = company_contract_sha256({key: value for key, value in task.items() if key != "task_sha256"})
    task_bound_packet = _packet(task)
    task_bound = derive_resource_request_v1(task, task_bound_packet, intent, bundle, _inventory(), selections)
    assert task_bound.task_revision == request_contract.MAX_CONTRACT_REVISION


@pytest.mark.parametrize("bad", [True, -1, 1 << 63, 1.5, object()])
def test_hostile_inputs_become_typed_errors(bad: object) -> None:
    request, task, packet, qos, bundle, selections = _request()
    with pytest.raises(ResourceRequestV1Error):
        derive_resource_request_v1(cast(Any, bad), packet, qos, bundle, _inventory(), selections)
    malformed = request._replace(task_revision=cast(Any, bad))
    with pytest.raises(ResourceRequestV1Error):
        validate_resource_request_structure_v1(malformed)
    assert task
