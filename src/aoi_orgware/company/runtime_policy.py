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
