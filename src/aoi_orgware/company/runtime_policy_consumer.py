"""Writer-off consumers and synthetic evaluators for runtime policy V2.

This module deliberately has no ledger, reducer, Supervisor, dispatch, or view
dependency.  The production consumer remains inactive and reports the legacy
16-carrier/depth-6 truth.  Synthetic evaluations describe what V2 would do;
they are caller-supplied, unverified, and have no operational effect.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, NamedTuple, NoReturn, cast

from aoi_orgware.company.contracts import (
    CompanyContractError,
    canonical_company_json_bytes,
)
from aoi_orgware.company.runtime_policy import (
    RuntimePolicyDefinitionV2,
    runtime_policy_definition_v2,
    validate_runtime_policy_definition_v2,
)


RUNTIME_POLICY_CONSUMER_VIEW_V1 = "runtime_policy_consumer_view_v1"
LEGACY_ACTIVE_CARRIER_LIMIT = 16
LEGACY_DELEGATION_DEPTH_LIMIT = 6

_ZERO_SHA256 = "0" * 64
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CONSUMER_VIEW_DOMAIN = "aoi.company.runtime-policy-consumer-view.v1"
_SYNTHETIC_EVALUATION_DOMAIN = (
    "aoi.company.runtime-policy-synthetic-evaluation.v1"
)
_DEPARTMENTS = ("rtl", "dv", "pd")
_LEAD_ROLE_DEPARTMENT = {
    "rtl_lead": "rtl",
    "dv_lead": "dv",
    "pd_lead": "pd",
}


class RuntimePolicyConsumerError(CompanyContractError):
    """An inactive consumer view or synthetic evaluation is malformed."""


class RuntimePolicyConsumerViewV1(NamedTuple):
    """Inactive current consumer truth; never an activation or decision."""

    document_type: str
    schema_version: int
    activation_state: str
    legacy_active_carrier_limit: int
    legacy_delegation_depth_limit: int
    candidate_definition_sha256: str
    candidate_definition_state: str
    authority_semantics: str
    admission_semantics: str
    capacity_semantics: str
    operational_effect: str
    view_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self._fields}


class RuntimePolicySyntheticEvaluationV1(NamedTuple):
    """Caller-supplied shadow result with no runtime or admission authority."""

    role_class: str
    department: str | None
    parent_role_class: str | None
    parent_department: str | None
    delegation_depth: int | None
    can_delegate: bool | None
    subordinate_occupied: int | None
    occupancy_quality: str
    acquisition_kind: str
    effect_unknown_holder: bool
    topology_disposition: str
    capacity_disposition: str
    effect_unknown_disposition: str
    chief_cardinality_disposition: str
    synthetic_disposition: str
    authority_semantics: str
    operational_effect: str
    definition_sha256: str
    evaluation_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self._fields}


def _fail(message: str) -> NoReturn:
    raise RuntimePolicyConsumerError(message)


def _hash(value: dict[str, object], *, domain: str) -> str:
    payload = {"derivation_domain": domain, "value": value}
    return hashlib.sha256(canonical_company_json_bytes(payload)).hexdigest()


def _value_digest(value: NamedTuple, *, field: str, domain: str) -> str:
    payload = {name: getattr(value, name) for name in value._fields}
    payload[field] = _ZERO_SHA256
    return _hash(payload, domain=domain)


def _record(
    value: object,
    value_type: type[tuple[Any, ...]],
    fields: tuple[str, ...],
    label: str,
) -> dict[str, object]:
    if type(value) is value_type and tuple.__len__(value) == len(fields):
        return {field: getattr(value, field) for field in fields}
    if type(value) is dict:
        item = cast(dict[object, object], value)
        if any(type(key) is not str for key in item) or set(item) != set(fields):
            _fail(f"{label} fields are invalid")
        return {field: item[field] for field in fields}
    _fail(f"{label} must be an exact value object or dict")


def _exact_match(actual: object, expected: object, label: str) -> object:
    if type(actual) is not type(expected) or actual != expected:
        _fail(f"{label} differs from exact derivation")
    return actual


def _optional_text(
    value: object,
    choices: tuple[str, ...],
    label: str,
) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value not in choices:
        _fail(f"{label} is invalid")
    return value


def inactive_runtime_policy_consumer_view_v1(
    definition: object | None = None,
) -> RuntimePolicyConsumerViewV1:
    """Describe the legacy current view before any durable V2 activation."""
    policy = validate_runtime_policy_definition_v2(
        runtime_policy_definition_v2() if definition is None else definition
    )
    provisional = RuntimePolicyConsumerViewV1(
        document_type=RUNTIME_POLICY_CONSUMER_VIEW_V1,
        schema_version=1,
        activation_state="inactive",
        legacy_active_carrier_limit=LEGACY_ACTIVE_CARRIER_LIMIT,
        legacy_delegation_depth_limit=LEGACY_DELEGATION_DEPTH_LIMIT,
        candidate_definition_sha256=policy.definition_sha256,
        candidate_definition_state="candidate_definition_only",
        authority_semantics="no_durable_activation",
        admission_semantics="no_admission_decision",
        capacity_semantics="legacy_runtime_unchanged",
        operational_effect="none",
        view_sha256=_ZERO_SHA256,
    )
    return provisional._replace(
        view_sha256=_value_digest(
            provisional,
            field="view_sha256",
            domain=_CONSUMER_VIEW_DOMAIN,
        )
    )


def validate_runtime_policy_consumer_view_v1(
    value: object,
    definition: object | None = None,
) -> RuntimePolicyConsumerViewV1:
    """Re-derive an inactive view exactly; this does not establish currentness."""
    item = _record(
        value,
        RuntimePolicyConsumerViewV1,
        RuntimePolicyConsumerViewV1._fields,
        "runtime policy consumer view",
    )
    expected = inactive_runtime_policy_consumer_view_v1(definition)
    for field in RuntimePolicyConsumerViewV1._fields:
        _exact_match(item[field], getattr(expected, field), f"view.{field}")
    return expected


def canonical_runtime_policy_consumer_view_v1_bytes(value: object) -> bytes:
    return canonical_company_json_bytes(
        validate_runtime_policy_consumer_view_v1(value).to_dict()
    )


def evaluate_runtime_policy_v2_synthetic(
    *,
    role_class: object,
    department: object,
    parent_role_class: object,
    parent_department: object,
    delegation_depth: object,
    can_delegate: object,
    subordinate_occupied: object,
    occupancy_quality: object,
    acquisition_kind: object,
    effect_unknown_holder: object,
    definition: object | None = None,
) -> RuntimePolicySyntheticEvaluationV1:
    """Evaluate synthetic V2 inputs without reading or mutating company state."""
    policy = validate_runtime_policy_definition_v2(
        runtime_policy_definition_v2() if definition is None else definition
    )
    roles = ("chief", *_LEAD_ROLE_DEPARTMENT, "worker", "reviewer", "unknown")
    role = _optional_text(role_class, roles, "role_class")
    if role is None:
        _fail("role_class is required")
    dept = _optional_text(department, (*_DEPARTMENTS, "unknown"), "department")
    parent = _optional_text(
        parent_role_class,
        ("chief", *_LEAD_ROLE_DEPARTMENT, "worker", "unknown"),
        "parent_role_class",
    )
    parent_dept = _optional_text(
        parent_department,
        (*_DEPARTMENTS, "unknown"),
        "parent_department",
    )
    if delegation_depth is not None and (
        type(delegation_depth) is not int
        or not 0 <= delegation_depth <= policy.history_structural_max_depth
    ):
        _fail("delegation_depth is invalid")
    if can_delegate is not None and type(can_delegate) is not bool:
        _fail("can_delegate is invalid")
    quality = _optional_text(
        occupancy_quality,
        ("exact", "unknown_or_unattributed"),
        "occupancy_quality",
    )
    kind = _optional_text(
        acquisition_kind,
        ("chief_carrier", "subordinate_carrier", "no_new_carrier", "unknown"),
        "acquisition_kind",
    )
    if quality is None or kind is None or type(effect_unknown_holder) is not bool:
        _fail("synthetic capacity inputs are invalid")
    if effect_unknown_holder and kind != "no_new_carrier":
        _fail("effect_unknown holder cannot request a new carrier acquisition")

    if quality == "exact":
        if type(subordinate_occupied) is not int or not (
            0 <= subordinate_occupied <= LEGACY_ACTIVE_CARRIER_LIMIT
        ):
            _fail("exact subordinate_occupied is invalid")
        if (
            effect_unknown_holder
            and role != "chief"
            and subordinate_occupied == 0
        ):
            _fail("effect_unknown holder must remain represented in occupancy")
    else:
        if subordinate_occupied is not None:
            _fail("unknown occupancy must not carry a guessed count")
    if kind == "chief_carrier":
        capacity = "not_applicable_chief_excluded"
    elif kind == "no_new_carrier":
        capacity = "not_applicable_no_new_slot"
    elif quality == "unknown_or_unattributed" or kind == "unknown":
        capacity = "unavailable"
    else:
        projected = cast(int, subordinate_occupied) + 1
        capacity = (
            "within_candidate_limit"
            if projected <= policy.subordinate_carrier_limit
            else "would_queue"
        )

    role_ok = (
        role == "chief"
        and department is None
        and parent is None
        and parent_department is None
        and delegation_depth == 0
        and can_delegate is True
        and kind != "subordinate_carrier"
    ) or (
        role in _LEAD_ROLE_DEPARTMENT
        and dept == _LEAD_ROLE_DEPARTMENT[role]
        and parent == "chief"
        and parent_department is None
        and delegation_depth == 1
        and can_delegate is True
        and kind != "chief_carrier"
    ) or (
        role == "worker"
        and dept in _DEPARTMENTS
        and parent in _LEAD_ROLE_DEPARTMENT
        and dept == _LEAD_ROLE_DEPARTMENT[parent]
        and parent_dept == dept
        and delegation_depth == 2
        and can_delegate is True
        and kind != "chief_carrier"
    ) or (
        role == "reviewer"
        and dept in _DEPARTMENTS
        and parent == "worker"
        and parent_dept == dept
        and delegation_depth == 3
        and can_delegate is False
        and kind != "chief_carrier"
    )
    epistemic_unknown = (
        role == "unknown"
        or delegation_depth is None
        or can_delegate is None
        or kind == "unknown"
        or dept == "unknown"
        or parent == "unknown"
        or parent_dept == "unknown"
        or (
            role in (*_LEAD_ROLE_DEPARTMENT, "worker", "reviewer")
            and (dept is None or parent is None)
        )
        or (
            role == "worker"
            and parent in _LEAD_ROLE_DEPARTMENT
            and parent_dept is None
        )
        or (
            role == "reviewer"
            and parent == "worker"
            and parent_dept is None
        )
    )
    if (
        delegation_depth is not None
        and delegation_depth > policy.current_admitted_max_depth
    ):
        topology = "would_reject_over_depth"
    elif epistemic_unknown:
        topology = "unavailable"
    else:
        topology = (
            "within_candidate_policy" if role_ok else "would_reject_topology"
        )

    chief_cardinality = "unavailable"
    if effect_unknown_holder:
        disposition = "would_hold_effect_unknown"
    elif topology.startswith("would_reject"):
        disposition = "would_reject"
    elif capacity == "would_queue":
        disposition = "would_queue"
    elif "unavailable" in {topology, capacity, chief_cardinality}:
        disposition = "unavailable"
    else:
        disposition = "would_admit"
    provisional = RuntimePolicySyntheticEvaluationV1(
        role_class=role,
        department=dept,
        parent_role_class=parent,
        parent_department=parent_dept,
        delegation_depth=delegation_depth,
        can_delegate=can_delegate,
        subordinate_occupied=subordinate_occupied,
        occupancy_quality=quality,
        acquisition_kind=kind,
        effect_unknown_holder=effect_unknown_holder,
        topology_disposition=topology,
        capacity_disposition=capacity,
        effect_unknown_disposition=(
            "retained" if effect_unknown_holder else "not_applicable"
        ),
        chief_cardinality_disposition=chief_cardinality,
        synthetic_disposition=disposition,
        authority_semantics="synthetic_unverified",
        operational_effect="none",
        definition_sha256=policy.definition_sha256,
        evaluation_sha256=_ZERO_SHA256,
    )
    return provisional._replace(
        evaluation_sha256=_value_digest(
            provisional,
            field="evaluation_sha256",
            domain=_SYNTHETIC_EVALUATION_DOMAIN,
        )
    )


def validate_runtime_policy_v2_synthetic_evaluation(
    value: object,
    definition: object | None = None,
) -> RuntimePolicySyntheticEvaluationV1:
    """Re-derive a synthetic evaluation exactly from its caller-supplied inputs."""
    item = _record(
        value,
        RuntimePolicySyntheticEvaluationV1,
        RuntimePolicySyntheticEvaluationV1._fields,
        "synthetic runtime policy evaluation",
    )
    expected = evaluate_runtime_policy_v2_synthetic(
        role_class=item["role_class"],
        department=item["department"],
        parent_role_class=item["parent_role_class"],
        parent_department=item["parent_department"],
        delegation_depth=item["delegation_depth"],
        can_delegate=item["can_delegate"],
        subordinate_occupied=item["subordinate_occupied"],
        occupancy_quality=item["occupancy_quality"],
        acquisition_kind=item["acquisition_kind"],
        effect_unknown_holder=item["effect_unknown_holder"],
        definition=definition,
    )
    for field in RuntimePolicySyntheticEvaluationV1._fields:
        _exact_match(
            item[field],
            getattr(expected, field),
            f"evaluation.{field}",
        )
    if not _SHA256.fullmatch(expected.evaluation_sha256):
        _fail("evaluation_sha256 is invalid")
    return expected


def canonical_runtime_policy_v2_synthetic_evaluation_bytes(
    value: object,
) -> bytes:
    return canonical_company_json_bytes(
        validate_runtime_policy_v2_synthetic_evaluation(value).to_dict()
    )


__all__ = [
    "LEGACY_ACTIVE_CARRIER_LIMIT",
    "LEGACY_DELEGATION_DEPTH_LIMIT",
    "RUNTIME_POLICY_CONSUMER_VIEW_V1",
    "RuntimePolicyConsumerError",
    "RuntimePolicyConsumerViewV1",
    "RuntimePolicySyntheticEvaluationV1",
    "canonical_runtime_policy_consumer_view_v1_bytes",
    "canonical_runtime_policy_v2_synthetic_evaluation_bytes",
    "evaluate_runtime_policy_v2_synthetic",
    "inactive_runtime_policy_consumer_view_v1",
    "validate_runtime_policy_consumer_view_v1",
    "validate_runtime_policy_v2_synthetic_evaluation",
]
