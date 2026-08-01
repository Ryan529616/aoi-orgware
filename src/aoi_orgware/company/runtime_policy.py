"""Immutable AOI company runtime-policy definition without runtime authority.

The values in this module describe the approved v0.5 topology and capacity
semantics.  This module has no direct runtime-wiring dependency and does not
publish or activate a policy, read company state, authorize work, admit a
carrier, reserve capacity, or change a projection.  Importing it through the
existing ``aoi_orgware.company`` package may still load that package's existing
public exports.  Callers must bind this definition to a separately reviewed
durable activation before using it for any operational decision.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, NamedTuple, NoReturn, cast

from aoi_orgware.company.contracts import (
    CompanyContractError,
    canonical_company_json_bytes,
)


RUNTIME_POLICY_DEFINITION_V1 = "runtime_policy_definition_v1"
RUNTIME_POLICY_ID = "company-runtime-policy"
RUNTIME_POLICY_REVISION = 1
CURRENT_ADMITTED_MAX_DEPTH = 3
HISTORY_STRUCTURAL_MAX_DEPTH = 6
SUBORDINATE_CARRIER_LIMIT = 4

_DEFINITION_DOMAIN = "aoi.company.runtime-policy-definition.v1"
_CLASSIFICATION_DOMAIN = "aoi.company.runtime-policy-depth-classification.v1"
_ZERO_SHA256 = "0" * 64
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ROLE_DEPTHS = (
    ("chief", 0),
    ("working_lead", 1),
    ("worker", 2),
    ("reviewer", 3),
)
_CAPACITY_BASIS = "physical_provider_model_carrier"
_CHIEF_CAPACITY_ACCOUNTING = "separate_excluded_from_subordinate"
_CHIEF_IDENTITY_BASIS = "exact_current_chief_term_carrier"
_UNKNOWN_CAPACITY_ACCOUNTING = "conservatively_occupied"
_AMBIGUOUS_CHIEF_ACCOUNTING = "unavailable_not_subtracted"
_OVERFLOW_DISPOSITION = "queue"
_OVER_DEPTH_ADMISSION = "reject"
_HISTORICAL_OVER_DEPTH = "preserve_raw_policy_invalid"
_ROLE_BINDING_SEMANTICS = "definition_only_unmapped"
_AUTHORITY_SEMANTICS = "requires_separate_durable_activation"
_OPERATIONAL_EFFECT = "none"
_FIXED_TEXT_FIELDS = (
    ("capacity_basis", _CAPACITY_BASIS),
    ("chief_capacity_accounting", _CHIEF_CAPACITY_ACCOUNTING),
    ("chief_identity_basis", _CHIEF_IDENTITY_BASIS),
    ("unknown_capacity_accounting", _UNKNOWN_CAPACITY_ACCOUNTING),
    ("ambiguous_chief_accounting", _AMBIGUOUS_CHIEF_ACCOUNTING),
    ("overflow_disposition", _OVERFLOW_DISPOSITION),
    ("over_depth_admission", _OVER_DEPTH_ADMISSION),
    ("historical_over_depth", _HISTORICAL_OVER_DEPTH),
    ("role_binding_semantics", _ROLE_BINDING_SEMANTICS),
    ("authority_semantics", _AUTHORITY_SEMANTICS),
    ("operational_effect", _OPERATIONAL_EFFECT),
)


class RuntimePolicyDefinitionError(CompanyContractError):
    """A runtime-policy definition or pure classification is malformed."""


class RuntimeRoleDepthV1(NamedTuple):
    """One fixed logical company role class and its delegation depth."""

    role_class: str
    delegation_depth: int

    def to_dict(self) -> dict[str, object]:
        return _role_depth_dict(self)


class RuntimePolicyDefinitionV1(NamedTuple):
    """Fixed policy bytes; never an activation, receipt, or admission grant."""

    document_type: str
    schema_version: int
    policy_id: str
    policy_revision: int
    role_depths: tuple[RuntimeRoleDepthV1, ...]
    current_admitted_max_depth: int
    history_structural_max_depth: int
    subordinate_carrier_limit: int
    capacity_basis: str
    chief_capacity_accounting: str
    chief_identity_basis: str
    unknown_capacity_accounting: str
    ambiguous_chief_accounting: str
    overflow_disposition: str
    over_depth_admission: str
    historical_over_depth: str
    role_binding_semantics: str
    authority_semantics: str
    operational_effect: str
    definition_sha256: str

    def to_dict(self) -> dict[str, object]:
        return _definition_dict(self)


class DelegationDepthClassificationV1(NamedTuple):
    """Pure caller-supplied classification with no admission authority."""

    raw_depth: int | None
    policy_relation: str
    history_relation: str
    reason_code: str
    authority_semantics: str
    admission_semantics: str
    definition_sha256: str
    classification_sha256: str

    def to_dict(self) -> dict[str, object]:
        return _classification_dict(self)


def _fail(message: str) -> NoReturn:
    raise RuntimePolicyDefinitionError(message)


def _role_depth_dict(value: RuntimeRoleDepthV1) -> dict[str, object]:
    if type(value) is not RuntimeRoleDepthV1:
        _fail("runtime role depth must be an exact value object")
    if tuple.__len__(value) != len(RuntimeRoleDepthV1._fields):
        _fail("runtime role depth tuple shape is invalid")
    if type(value.role_class) is not str or type(value.delegation_depth) is not int:
        _fail("runtime role depth has invalid exact scalar types")
    if (value.role_class, value.delegation_depth) not in _ROLE_DEPTHS:
        _fail("runtime role depth is outside the fixed policy definition")
    return {
        "role_class": value.role_class,
        "delegation_depth": value.delegation_depth,
    }


def _classification_plain_dict(value: DelegationDepthClassificationV1) -> dict[str, object]:
    if type(value) is not DelegationDepthClassificationV1:
        _fail("delegation depth classification must be an exact value object")
    if tuple.__len__(value) != len(DelegationDepthClassificationV1._fields):
        _fail("delegation depth classification tuple shape is invalid")
    if value.raw_depth is not None and (
        type(value.raw_depth) is not int
        or not 0 <= value.raw_depth <= HISTORY_STRUCTURAL_MAX_DEPTH
    ):
        _fail("delegation depth classification.raw_depth is invalid")
    string_fields = (
        "policy_relation", "history_relation", "reason_code",
        "authority_semantics", "admission_semantics",
        "definition_sha256", "classification_sha256",
    )
    for field in string_fields:
        if type(getattr(value, field)) is not str:
            _fail(f"delegation depth classification.{field} has an invalid exact type")
    if value.policy_relation not in {
        "within_defined_current_policy", "above_defined_current_policy", "unknown",
    }:
        _fail("delegation depth classification.policy_relation is invalid")
    if value.history_relation not in {"within_structural_history_bound", "unknown"}:
        _fail("delegation depth classification.history_relation is invalid")
    if value.reason_code not in {
        "raw_depth_within_defined_current_policy",
        "raw_depth_preserved_policy_invalid",
        "raw_depth_unavailable",
    }:
        _fail("delegation depth classification.reason_code is invalid")
    if value.authority_semantics != "caller_supplied_unverified":
        _fail("delegation depth classification.authority_semantics is invalid")
    if value.admission_semantics != "no_admission_decision":
        _fail("delegation depth classification.admission_semantics is invalid")
    _digest(value.definition_sha256, "delegation depth classification.definition_sha256")
    _digest(value.classification_sha256, "delegation depth classification.classification_sha256")
    return {
        field: getattr(value, field)
        for field in DelegationDepthClassificationV1._fields
    }


def _classification_dict(value: DelegationDepthClassificationV1) -> dict[str, object]:
    """Serialize only a classification matching the fixed pure derivation."""
    return _classification_plain_dict(validate_delegation_depth_classification_v1(value))


def _exact_object(value: object, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{label} must be an exact dictionary")
    item = cast(dict[object, object], value)
    if any(type(key) is not str for key in item) or tuple(sorted(cast(dict[str, Any], item))) != tuple(sorted(fields)):
        _fail(f"{label} schema is invalid")
    return cast(dict[str, Any], item).copy()


def _exact_int(value: object, expected: int, label: str) -> int:
    if type(value) is not int or value != expected:
        _fail(f"{label} is invalid")
    return value


def _fixed_text(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        _fail(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        _fail(f"{label} must be lowercase SHA-256")
    return value


def _canonical_hash(value: object, label: str) -> str:
    try:
        return hashlib.sha256(canonical_company_json_bytes(value)).hexdigest()
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except RuntimePolicyDefinitionError:
        raise
    except Exception as error:
        raise RuntimePolicyDefinitionError(f"{label} canonicalization failed") from error


def _definition_plain_dict(value: RuntimePolicyDefinitionV1) -> dict[str, object]:
    """Serialize exact scalar/nested types without trusting nested methods."""
    if type(value) is not RuntimePolicyDefinitionV1:
        _fail("runtime policy definition must be an exact value object")
    if tuple.__len__(value) != len(RuntimePolicyDefinitionV1._fields):
        _fail("runtime policy definition tuple shape is invalid")
    scalar_types: tuple[tuple[str, type[object]], ...] = (
        ("document_type", str),
        ("schema_version", int),
        ("policy_id", str),
        ("policy_revision", int),
        ("current_admitted_max_depth", int),
        ("history_structural_max_depth", int),
        ("subordinate_carrier_limit", int),
        ("capacity_basis", str),
        ("chief_capacity_accounting", str),
        ("chief_identity_basis", str),
        ("unknown_capacity_accounting", str),
        ("ambiguous_chief_accounting", str),
        ("overflow_disposition", str),
        ("over_depth_admission", str),
        ("historical_over_depth", str),
        ("role_binding_semantics", str),
        ("authority_semantics", str),
        ("operational_effect", str),
        ("definition_sha256", str),
    )
    for field, expected_type in scalar_types:
        if type(getattr(value, field)) is not expected_type:
            _fail(f"runtime policy definition.{field} has an invalid exact type")
    if type(value.role_depths) is not tuple or len(value.role_depths) != len(_ROLE_DEPTHS):
        _fail("runtime policy definition.role_depths is invalid")
    roles: list[dict[str, object]] = []
    for index, role in enumerate(value.role_depths):
        if type(role) is not RuntimeRoleDepthV1:
            _fail(f"runtime policy definition.role_depths[{index}] has an invalid exact type")
        roles.append(_role_depth_dict(role))
    result = {
        field: getattr(value, field)
        for field in RuntimePolicyDefinitionV1._fields
    }
    result["role_depths"] = roles
    return result


def _definition_dict(value: RuntimePolicyDefinitionV1) -> dict[str, object]:
    """Serialize only the exact fixed, digest-bound definition."""
    return _definition_plain_dict(validate_runtime_policy_definition_v1(value))


def _definition_digest(value: RuntimePolicyDefinitionV1) -> str:
    payload = _definition_plain_dict(value)
    payload["definition_sha256"] = _ZERO_SHA256
    return _canonical_hash(
        {"derivation_domain": _DEFINITION_DOMAIN, "definition": payload},
        "runtime policy definition",
    )


def _classification_digest(value: DelegationDepthClassificationV1) -> str:
    payload = _classification_plain_dict(value)
    payload["classification_sha256"] = _ZERO_SHA256
    return _canonical_hash(
        {"derivation_domain": _CLASSIFICATION_DOMAIN, "classification": payload},
        "delegation depth classification",
    )


def _fixed_definition(digest: str) -> RuntimePolicyDefinitionV1:
    return RuntimePolicyDefinitionV1(
        document_type=RUNTIME_POLICY_DEFINITION_V1,
        schema_version=1,
        policy_id=RUNTIME_POLICY_ID,
        policy_revision=RUNTIME_POLICY_REVISION,
        role_depths=tuple(RuntimeRoleDepthV1(role, depth) for role, depth in _ROLE_DEPTHS),
        current_admitted_max_depth=CURRENT_ADMITTED_MAX_DEPTH,
        history_structural_max_depth=HISTORY_STRUCTURAL_MAX_DEPTH,
        subordinate_carrier_limit=SUBORDINATE_CARRIER_LIMIT,
        capacity_basis=_CAPACITY_BASIS,
        chief_capacity_accounting=_CHIEF_CAPACITY_ACCOUNTING,
        chief_identity_basis=_CHIEF_IDENTITY_BASIS,
        unknown_capacity_accounting=_UNKNOWN_CAPACITY_ACCOUNTING,
        ambiguous_chief_accounting=_AMBIGUOUS_CHIEF_ACCOUNTING,
        overflow_disposition=_OVERFLOW_DISPOSITION,
        over_depth_admission=_OVER_DEPTH_ADMISSION,
        historical_over_depth=_HISTORICAL_OVER_DEPTH,
        role_binding_semantics=_ROLE_BINDING_SEMANTICS,
        authority_semantics=_AUTHORITY_SEMANTICS,
        operational_effect=_OPERATIONAL_EFFECT,
        definition_sha256=digest,
    )


def runtime_policy_definition_v1() -> RuntimePolicyDefinitionV1:
    """Return the fixed v0.5 policy definition without activating it."""
    provisional = _fixed_definition(_ZERO_SHA256)
    return provisional._replace(definition_sha256=_definition_digest(provisional))


def validate_runtime_policy_definition_v1(value: object) -> RuntimePolicyDefinitionV1:
    """Validate exact fixed definition bytes, without deriving currentness."""
    if type(value) is RuntimePolicyDefinitionV1:
        item = _definition_plain_dict(value)
    else:
        item = _exact_object(value, RuntimePolicyDefinitionV1._fields, "runtime policy definition")

    _fixed_text(item["document_type"], RUNTIME_POLICY_DEFINITION_V1, "document_type")
    _exact_int(item["schema_version"], 1, "schema_version")
    _fixed_text(item["policy_id"], RUNTIME_POLICY_ID, "policy_id")
    _exact_int(item["policy_revision"], RUNTIME_POLICY_REVISION, "policy_revision")

    raw_roles = item["role_depths"]
    if type(raw_roles) not in {list, tuple}:
        _fail("role_depths is invalid")
    role_sequence = cast(list[object] | tuple[object, ...], raw_roles)
    if len(role_sequence) != len(_ROLE_DEPTHS):
        _fail("role_depths is invalid")
    roles: list[RuntimeRoleDepthV1] = []
    for index, expected_role in enumerate(_ROLE_DEPTHS):
        raw = role_sequence[index]
        if type(raw) is RuntimeRoleDepthV1:
            role = raw
            raw = role.to_dict()
        role_item = _exact_object(raw, RuntimeRoleDepthV1._fields, f"role_depths[{index}]")
        role_class = _fixed_text(role_item["role_class"], expected_role[0], f"role_depths[{index}].role_class")
        depth = _exact_int(role_item["delegation_depth"], expected_role[1], f"role_depths[{index}].delegation_depth")
        roles.append(RuntimeRoleDepthV1(role_class, depth))

    fixed_ints = {
        "current_admitted_max_depth": CURRENT_ADMITTED_MAX_DEPTH,
        "history_structural_max_depth": HISTORY_STRUCTURAL_MAX_DEPTH,
        "subordinate_carrier_limit": SUBORDINATE_CARRIER_LIMIT,
    }
    for field, expected_integer in fixed_ints.items():
        _exact_int(item[field], expected_integer, field)
    for field, expected_text in _FIXED_TEXT_FIELDS:
        _fixed_text(item[field], expected_text, field)

    candidate = RuntimePolicyDefinitionV1(
        document_type=RUNTIME_POLICY_DEFINITION_V1,
        schema_version=1,
        policy_id=RUNTIME_POLICY_ID,
        policy_revision=RUNTIME_POLICY_REVISION,
        role_depths=tuple(roles),
        current_admitted_max_depth=CURRENT_ADMITTED_MAX_DEPTH,
        history_structural_max_depth=HISTORY_STRUCTURAL_MAX_DEPTH,
        subordinate_carrier_limit=SUBORDINATE_CARRIER_LIMIT,
        capacity_basis=_CAPACITY_BASIS,
        chief_capacity_accounting=_CHIEF_CAPACITY_ACCOUNTING,
        chief_identity_basis=_CHIEF_IDENTITY_BASIS,
        unknown_capacity_accounting=_UNKNOWN_CAPACITY_ACCOUNTING,
        ambiguous_chief_accounting=_AMBIGUOUS_CHIEF_ACCOUNTING,
        overflow_disposition=_OVERFLOW_DISPOSITION,
        over_depth_admission=_OVER_DEPTH_ADMISSION,
        historical_over_depth=_HISTORICAL_OVER_DEPTH,
        role_binding_semantics=_ROLE_BINDING_SEMANTICS,
        authority_semantics=_AUTHORITY_SEMANTICS,
        operational_effect=_OPERATIONAL_EFFECT,
        definition_sha256=_digest(item["definition_sha256"], "definition_sha256"),
    )
    if candidate.definition_sha256 != _definition_digest(candidate):
        _fail("definition_sha256 does not bind the canonical definition")
    return candidate


def canonical_runtime_policy_definition_v1_bytes(value: object) -> bytes:
    """Return canonical validated definition bytes; never activation bytes."""
    return canonical_company_json_bytes(validate_runtime_policy_definition_v1(value).to_dict())


def classify_delegation_depth_v1(
    value: object,
    definition: object | None = None,
) -> DelegationDepthClassificationV1:
    """Classify a caller-supplied raw depth without making an admission decision."""
    policy = validate_runtime_policy_definition_v1(
        runtime_policy_definition_v1() if definition is None else definition
    )
    if value is None:
        raw_depth = None
        relation = "unknown"
        history = "unknown"
        reason = "raw_depth_unavailable"
    else:
        if type(value) is not int or not 0 <= value <= policy.history_structural_max_depth:
            _fail("raw_depth must be unavailable or a bounded exact structural depth")
        raw_depth = value
        if raw_depth <= policy.current_admitted_max_depth:
            relation = "within_defined_current_policy"
            reason = "raw_depth_within_defined_current_policy"
        else:
            relation = "above_defined_current_policy"
            reason = "raw_depth_preserved_policy_invalid"
        history = "within_structural_history_bound"

    provisional = DelegationDepthClassificationV1(
        raw_depth=raw_depth,
        policy_relation=relation,
        history_relation=history,
        reason_code=reason,
        authority_semantics="caller_supplied_unverified",
        admission_semantics="no_admission_decision",
        definition_sha256=policy.definition_sha256,
        classification_sha256=_ZERO_SHA256,
    )
    return provisional._replace(classification_sha256=_classification_digest(provisional))


def validate_delegation_depth_classification_v1(
    value: object,
    definition: object | None = None,
) -> DelegationDepthClassificationV1:
    """Re-derive and compare one pure classification exactly."""
    if type(value) is not DelegationDepthClassificationV1:
        _fail("classification must be an exact DelegationDepthClassificationV1")
    candidate = value
    _classification_plain_dict(candidate)
    if candidate.raw_depth is not None and type(candidate.raw_depth) is not int:
        _fail("classification.raw_depth is invalid")
    relation = _fixed_text(
        candidate.policy_relation,
        classify_delegation_depth_v1(candidate.raw_depth, definition).policy_relation,
        "classification.policy_relation",
    )
    expected = classify_delegation_depth_v1(candidate.raw_depth, definition)
    history = _fixed_text(candidate.history_relation, expected.history_relation, "classification.history_relation")
    reason = _fixed_text(candidate.reason_code, expected.reason_code, "classification.reason_code")
    authority = _fixed_text(
        candidate.authority_semantics,
        "caller_supplied_unverified",
        "classification.authority_semantics",
    )
    admission = _fixed_text(
        candidate.admission_semantics,
        "no_admission_decision",
        "classification.admission_semantics",
    )
    definition_digest = _digest(candidate.definition_sha256, "classification.definition_sha256")
    classification_digest = _digest(candidate.classification_sha256, "classification.classification_sha256")
    normalized = DelegationDepthClassificationV1(
        raw_depth=candidate.raw_depth,
        policy_relation=relation,
        history_relation=history,
        reason_code=reason,
        authority_semantics=authority,
        admission_semantics=admission,
        definition_sha256=definition_digest,
        classification_sha256=classification_digest,
    )
    if normalized.classification_sha256 != _classification_digest(normalized):
        _fail("classification_sha256 does not bind the canonical classification")
    if _classification_plain_dict(normalized) != _classification_plain_dict(expected):
        _fail("classification differs from exact pure derivation")
    return normalized


# V2 deliberately remains a fixed policy definition. It is not registered,
# activated, or a substitute for a durable runtime view.
RUNTIME_POLICY_DEFINITION_V2 = "runtime_policy_definition_v2"
RUNTIME_POLICY_V2_REVISION = 2
_DEFINITION_V2_DOMAIN = "aoi.company.runtime-policy-definition.v2"
_V2_LEAD_ROLES = ("rtl_lead", "dv_lead", "pd_lead")
_V2_ROLE_DEPTHS = (("chief", 0), *_ROLE_DEPTHS[1:])
_V2_FIXED_TEXT = (
    ("current_chief_semantics", "one_exact_current_chief_and_at_most_one_exact_immediate_retiring_predecessor_d0_excluded_from_subordinate_capacity_visible_in_physical_coverage"),
    ("retiring_chief_semantics", "retiring_chief_requires_exact_writer_quiescence_proof_no_stack"),
    ("retiring_release_semantics", "retiring_chief_physical_coverage_remains_visible_until_exact_writer_quiescence_proof"),
    ("lead_semantics", "d1_only_rtl_lead_dv_lead_pd_lead_department_identity_bound"),
    ("worker_semantics", "d2_worker_may_delegate_only_d3_reviewer"),
    ("reviewer_semantics", "d3_reviewer_cannot_delegate"),
    ("turn_semantics", "inherits_owner_depth_adds_no_carrier_slot"),
    ("external_job_semantics", "inherits_owner_depth_adds_no_carrier_slot"),
    ("capacity_semantics", "union_dedup_d1_d2_d3_carrier_and_reservation_holder_identities_limit_four"),
    ("overflow_disposition", "queue"),
    ("over_depth_admission", "new_d4_to_d6_reject_before_append"),
    ("unknown_semantics", "unknown_or_unattributed_not_subtracted_capacity_and_admission_unavailable"),
    ("effect_unknown_semantics", "effect_unknown_holds_reservation_write_and_output_claim"),
    ("over_depth_semantics", "d4_to_d6_raw_preserved_history_only_requires_exact_surface_specific_durable_terminal_closure_never_reactivates"),
    ("state_proof_semantics", "policy_semantics_not_current_state_proof"),
    ("authority_semantics", "requires_separate_durable_activation"),
    ("operational_effect", "none"),
)


class RuntimePolicyDefinitionV2(NamedTuple):
    """Immutable V2 policy semantics; not a current-state or authority receipt."""

    document_type: str
    schema_version: int
    policy_id: str
    policy_revision: int
    supersedes_definition_sha256: str
    role_depths: tuple[RuntimeRoleDepthV1, ...]
    working_lead_roles: tuple[str, ...]
    current_admitted_max_depth: int
    history_structural_max_depth: int
    subordinate_carrier_limit: int
    current_chief_semantics: str
    retiring_chief_semantics: str
    retiring_release_semantics: str
    lead_semantics: str
    worker_semantics: str
    reviewer_semantics: str
    turn_semantics: str
    external_job_semantics: str
    capacity_semantics: str
    overflow_disposition: str
    over_depth_admission: str
    unknown_semantics: str
    effect_unknown_semantics: str
    over_depth_semantics: str
    state_proof_semantics: str
    authority_semantics: str
    operational_effect: str
    definition_sha256: str

    def to_dict(self) -> dict[str, object]:
        return _definition_v2_dict(self)


def _definition_v2_plain_dict(value: RuntimePolicyDefinitionV2) -> dict[str, object]:
    if type(value) is not RuntimePolicyDefinitionV2 or tuple.__len__(value) != len(RuntimePolicyDefinitionV2._fields):
        _fail("runtime policy V2 definition must be an exact value object")
    for field in RuntimePolicyDefinitionV2._fields:
        item = getattr(value, field)
        if field in {"schema_version", "policy_revision", "current_admitted_max_depth", "history_structural_max_depth", "subordinate_carrier_limit"}:
            if type(item) is not int:
                _fail(f"runtime policy V2 definition.{field} has an invalid exact type")
        elif field == "role_depths":
            if type(item) is not tuple:
                _fail("runtime policy V2 definition.role_depths has an invalid exact type")
            if len(cast(tuple[object, ...], item)) != len(_V2_ROLE_DEPTHS):
                _fail("runtime policy V2 definition.role_depths has an invalid length")
        elif field == "working_lead_roles":
            if type(item) is not tuple:
                _fail("runtime policy V2 definition.working_lead_roles has an invalid exact type")
            lead_items = cast(tuple[object, ...], item)
            if len(lead_items) != len(_V2_LEAD_ROLES) or any(type(role) is not str for role in lead_items):
                _fail("runtime policy V2 definition.working_lead_roles has an invalid value")
        elif type(item) is not str:
            _fail(f"runtime policy V2 definition.{field} has an invalid exact type")
    return {**{field: getattr(value, field) for field in RuntimePolicyDefinitionV2._fields},
            "role_depths": [_role_depth_dict(role) for role in value.role_depths],
            "working_lead_roles": list(value.working_lead_roles)}


def _definition_v2_digest(value: RuntimePolicyDefinitionV2) -> str:
    payload = _definition_v2_plain_dict(value)
    payload["definition_sha256"] = _ZERO_SHA256
    return _canonical_hash({"derivation_domain": _DEFINITION_V2_DOMAIN, "definition": payload}, "runtime policy V2 definition")


def runtime_policy_definition_v2() -> RuntimePolicyDefinitionV2:
    """Return fixed V2 semantics without publishing, activating, or admitting."""
    v1 = runtime_policy_definition_v1()
    values: dict[str, object] = {
        "document_type": RUNTIME_POLICY_DEFINITION_V2, "schema_version": 1,
        "policy_id": RUNTIME_POLICY_ID, "policy_revision": RUNTIME_POLICY_V2_REVISION,
        "supersedes_definition_sha256": v1.definition_sha256,
        "role_depths": tuple(RuntimeRoleDepthV1(role, depth) for role, depth in _V2_ROLE_DEPTHS),
        "working_lead_roles": _V2_LEAD_ROLES,
        "current_admitted_max_depth": CURRENT_ADMITTED_MAX_DEPTH,
        "history_structural_max_depth": HISTORY_STRUCTURAL_MAX_DEPTH,
        "subordinate_carrier_limit": SUBORDINATE_CARRIER_LIMIT,
        **dict(_V2_FIXED_TEXT), "definition_sha256": _ZERO_SHA256,
    }
    provisional = RuntimePolicyDefinitionV2(**cast(Any, values))
    return provisional._replace(definition_sha256=_definition_v2_digest(provisional))


def validate_runtime_policy_definition_v2(value: object) -> RuntimePolicyDefinitionV2:
    """Validate fixed V2 definition bytes; it cannot establish runtime truth."""
    item = _definition_v2_plain_dict(value) if type(value) is RuntimePolicyDefinitionV2 else _exact_object(value, RuntimePolicyDefinitionV2._fields, "runtime policy V2 definition")
    for field, expected in (("document_type", RUNTIME_POLICY_DEFINITION_V2), ("policy_id", RUNTIME_POLICY_ID)):
        _fixed_text(item[field], expected, field)
    _exact_int(item["schema_version"], 1, "schema_version")
    _exact_int(item["policy_revision"], RUNTIME_POLICY_V2_REVISION, "policy_revision")
    _digest(item["supersedes_definition_sha256"], "supersedes_definition_sha256")
    if item["supersedes_definition_sha256"] != runtime_policy_definition_v1().definition_sha256:
        _fail("supersedes_definition_sha256 does not bind exact V1 definition")
    raw_roles = item["role_depths"]
    if type(raw_roles) not in {list, tuple}:
        _fail("role_depths is invalid")
    roles = cast(list[object] | tuple[object, ...], raw_roles)
    if len(roles) != len(_V2_ROLE_DEPTHS):
        _fail("role_depths is invalid")
    normalized_roles: list[RuntimeRoleDepthV1] = []
    for index, (role_name, role_depth) in enumerate(_V2_ROLE_DEPTHS):
        role = _exact_object(roles[index], RuntimeRoleDepthV1._fields, f"role_depths[{index}]")
        normalized_roles.append(RuntimeRoleDepthV1(_fixed_text(role["role_class"], role_name, "role_class"), _exact_int(role["delegation_depth"], role_depth, "delegation_depth")))
    raw_lead_roles = item["working_lead_roles"]
    if type(raw_lead_roles) not in {list, tuple}:
        _fail("working_lead_roles is invalid")
    lead_roles = cast(list[object] | tuple[object, ...], raw_lead_roles)
    if len(lead_roles) != len(_V2_LEAD_ROLES) or any(type(role) is not str for role in lead_roles):
        _fail("working_lead_roles is invalid")
    if tuple(lead_roles) != _V2_LEAD_ROLES:
        _fail("working_lead_roles is invalid")
    _exact_int(item["current_admitted_max_depth"], CURRENT_ADMITTED_MAX_DEPTH, "current_admitted_max_depth")
    _exact_int(item["history_structural_max_depth"], HISTORY_STRUCTURAL_MAX_DEPTH, "history_structural_max_depth")
    _exact_int(item["subordinate_carrier_limit"], SUBORDINATE_CARRIER_LIMIT, "subordinate_carrier_limit")
    for field, expected in _V2_FIXED_TEXT:
        _fixed_text(item[field], expected, field)
    values: dict[str, object] = {"document_type": RUNTIME_POLICY_DEFINITION_V2, "schema_version": 1, "policy_id": RUNTIME_POLICY_ID, "policy_revision": RUNTIME_POLICY_V2_REVISION, "supersedes_definition_sha256": item["supersedes_definition_sha256"], "role_depths": tuple(normalized_roles), "working_lead_roles": _V2_LEAD_ROLES, "current_admitted_max_depth": CURRENT_ADMITTED_MAX_DEPTH, "history_structural_max_depth": HISTORY_STRUCTURAL_MAX_DEPTH, "subordinate_carrier_limit": SUBORDINATE_CARRIER_LIMIT, **dict(_V2_FIXED_TEXT), "definition_sha256": _digest(item["definition_sha256"], "definition_sha256")}
    candidate = RuntimePolicyDefinitionV2(**cast(Any, values))
    if candidate.definition_sha256 != _definition_v2_digest(candidate):
        _fail("definition_sha256 does not bind the canonical V2 definition")
    return candidate


def _definition_v2_dict(value: RuntimePolicyDefinitionV2) -> dict[str, object]:
    return _definition_v2_plain_dict(validate_runtime_policy_definition_v2(value))


def canonical_runtime_policy_definition_v2_bytes(value: object) -> bytes:
    return canonical_company_json_bytes(validate_runtime_policy_definition_v2(value).to_dict())
