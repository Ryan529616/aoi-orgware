# AOI-SYNTHETIC-FIXTURE-V1
"""Adversarial tests for the writer-off runtime-policy definition."""
from __future__ import annotations

import ast
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import CompanyContractError, canonical_company_json_bytes
from aoi_orgware.company.runtime_policy import (
    CURRENT_ADMITTED_MAX_DEPTH,
    HISTORY_STRUCTURAL_MAX_DEPTH,
    RUNTIME_POLICY_DEFINITION_V1,
    SUBORDINATE_CARRIER_LIMIT,
    DelegationDepthClassificationV1,
    RuntimePolicyDefinitionError,
    RuntimePolicyDefinitionV1,
    canonical_runtime_policy_definition_v1_bytes,
    classify_delegation_depth_v1,
    runtime_policy_definition_v1,
    validate_delegation_depth_classification_v1,
    validate_runtime_policy_definition_v1,
)


MARKER = "AOI-SYNTHETIC-FIXTURE-V1"


class _IntSubclass(int):
    pass


class _StringSubclass(str):
    pass


class _AlwaysEqual:
    def __eq__(self, other: object) -> bool:
        return True


class _ExplodingEqual:
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("untrusted equality executed")


class _ExplodingToDict:
    def to_dict(self) -> dict[str, object]:
        raise RuntimeError("untrusted serializer executed")


def _rehash(raw: dict[str, object]) -> dict[str, object]:
    payload = dict(raw)
    payload["definition_sha256"] = "0" * 64
    raw["definition_sha256"] = sha256(canonical_company_json_bytes({
        "derivation_domain": "aoi.company.runtime-policy-definition.v1",
        "definition": payload,
    })).hexdigest()
    return raw


def test_fixed_definition_has_exact_approved_semantics() -> None:
    value = runtime_policy_definition_v1()
    assert value.document_type == RUNTIME_POLICY_DEFINITION_V1
    assert value.schema_version == 1
    assert value.policy_id == "company-runtime-policy"
    assert value.policy_revision == 1
    assert [(item.role_class, item.delegation_depth) for item in value.role_depths] == [
        ("chief", 0), ("working_lead", 1), ("worker", 2), ("reviewer", 3),
    ]
    assert value.current_admitted_max_depth == CURRENT_ADMITTED_MAX_DEPTH == 3
    assert value.history_structural_max_depth == HISTORY_STRUCTURAL_MAX_DEPTH == 6
    assert value.subordinate_carrier_limit == SUBORDINATE_CARRIER_LIMIT == 4
    assert value.capacity_basis == "physical_provider_model_carrier"
    assert value.chief_capacity_accounting == "separate_excluded_from_subordinate"
    assert value.chief_identity_basis == "exact_current_chief_term_carrier"
    assert value.unknown_capacity_accounting == "conservatively_occupied"
    assert value.ambiguous_chief_accounting == "unavailable_not_subtracted"
    assert value.overflow_disposition == "queue"
    assert value.over_depth_admission == "reject"
    assert value.historical_over_depth == "preserve_raw_policy_invalid"
    assert value.role_binding_semantics == "definition_only_unmapped"
    assert value.authority_semantics == "requires_separate_durable_activation"
    assert value.operational_effect == "none"


def test_definition_digest_has_independent_hard_coded_oracle() -> None:
    value = runtime_policy_definition_v1()
    assert value.definition_sha256 == "d62315e882de44e307c42148eb155008ce97a0dba553e32b21805cf6ac22242d"
    assert validate_runtime_policy_definition_v1(value) == value


def test_definition_round_trip_is_canonical_and_order_independent() -> None:
    value = runtime_policy_definition_v1()
    raw = value.to_dict()
    reversed_raw = dict(reversed(tuple(raw.items())))
    assert validate_runtime_policy_definition_v1(reversed_raw) == value
    assert canonical_runtime_policy_definition_v1_bytes(reversed_raw) == canonical_company_json_bytes(raw)


def test_definition_is_deep_immutable_and_to_dict_is_detached() -> None:
    value = runtime_policy_definition_v1()
    assert not hasattr(value, "__dict__")
    assert not hasattr(value.role_depths[0], "__dict__")
    with pytest.raises(AttributeError):
        cast(Any, value).subordinate_carrier_limit = 99
    raw = value.to_dict()
    cast(list[dict[str, object]], raw["role_depths"])[0]["delegation_depth"] = 99
    assert value.role_depths[0].delegation_depth == 0
    assert validate_runtime_policy_definition_v1(value) == value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("policy_revision", _IntSubclass(1)),
        ("current_admitted_max_depth", 4),
        ("history_structural_max_depth", 3),
        ("subordinate_carrier_limit", 5),
        ("policy_id", _StringSubclass("company-runtime-policy")),
        ("chief_capacity_accounting", "subtract_one_from_total"),
        ("authority_semantics", "active"),
        ("operational_effect", "admission"),
    ],
)
def test_fixed_definition_rejects_scalar_drift(field: str, value: object) -> None:
    raw = runtime_policy_definition_v1().to_dict()
    raw[field] = value
    _rehash(raw)
    with pytest.raises(RuntimePolicyDefinitionError):
        validate_runtime_policy_definition_v1(raw)


def test_definition_rejects_schema_and_role_drift() -> None:
    value = runtime_policy_definition_v1()
    missing = value.to_dict()
    missing.pop("operational_effect")
    extra = value.to_dict()
    extra["activation_cursor"] = 1
    reordered = value.to_dict()
    roles = cast(list[dict[str, object]], reordered["role_depths"])
    roles[1], roles[2] = roles[2], roles[1]
    _rehash(reordered)
    for raw in (missing, extra, reordered):
        with pytest.raises(RuntimePolicyDefinitionError):
            validate_runtime_policy_definition_v1(raw)


@pytest.mark.parametrize("malformed_role", [object(), _ExplodingToDict()])
def test_exact_definition_with_malformed_nested_role_is_typed_error(malformed_role: object) -> None:
    roles = list(runtime_policy_definition_v1().role_depths)
    roles[2] = cast(Any, malformed_role)
    value = runtime_policy_definition_v1()._replace(role_depths=cast(Any, tuple(roles)))
    with pytest.raises(CompanyContractError):
        value.to_dict()
    with pytest.raises(CompanyContractError):
        validate_runtime_policy_definition_v1(value)
    with pytest.raises(CompanyContractError):
        canonical_runtime_policy_definition_v1_bytes(value)
    with pytest.raises(CompanyContractError):
        classify_delegation_depth_v1(1, value)


def test_definition_to_dict_rejects_untrusted_outer_scalar_without_equality() -> None:
    value = runtime_policy_definition_v1()._replace(authority_semantics=cast(Any, _ExplodingEqual()))
    with pytest.raises(CompanyContractError):
        value.to_dict()


@pytest.mark.parametrize(
    "role",
    [
        cast(Any, tuple.__new__(type(runtime_policy_definition_v1().role_depths[0]), (["chief"], 0))),
        cast(Any, tuple.__new__(type(runtime_policy_definition_v1().role_depths[0]), ("chief", [0]))),
    ],
)
def test_role_depth_to_dict_rejects_mutable_aliases(role: object) -> None:
    with pytest.raises(CompanyContractError):
        cast(Any, role).to_dict()


def test_exact_named_tuple_shape_rejects_missing_and_hidden_members() -> None:
    definition = runtime_policy_definition_v1()
    classification = classify_delegation_depth_v1(4)
    role = definition.role_depths[0]

    def assert_rejected(
        value: tuple[object, ...],
        validator: Callable[[object], object] | None,
    ) -> None:
        for members in (tuple(value)[:-1], (*tuple(value), [])):
            malformed = tuple.__new__(type(value), members)
            with pytest.raises(CompanyContractError):
                cast(Any, malformed).to_dict()
            if validator is not None:
                with pytest.raises(CompanyContractError):
                    validator(malformed)

    assert_rejected(role, None)
    assert_rejected(definition, validate_runtime_policy_definition_v1)
    assert_rejected(classification, validate_delegation_depth_classification_v1)


def test_public_serializers_reject_semantic_and_digest_drift() -> None:
    definition = runtime_policy_definition_v1()
    for definition_forged in (
        definition._replace(policy_id="attacker-policy"),
        definition._replace(operational_effect="admission"),
        definition._replace(definition_sha256="f" * 64),
    ):
        with pytest.raises(CompanyContractError):
            definition_forged.to_dict()

    classification = classify_delegation_depth_v1(4)
    for classification_forged in (
        classification._replace(policy_relation="within_defined_current_policy"),
        classification._replace(classification_sha256="f" * 64),
    ):
        with pytest.raises(CompanyContractError):
            classification_forged.to_dict()


def test_definition_rejects_digest_forgery() -> None:
    raw = runtime_policy_definition_v1().to_dict()
    raw["definition_sha256"] = "f" * 64
    with pytest.raises(RuntimePolicyDefinitionError, match="does not bind"):
        validate_runtime_policy_definition_v1(raw)
    raw["definition_sha256"] = "F" * 64
    with pytest.raises(RuntimePolicyDefinitionError, match="lowercase"):
        validate_runtime_policy_definition_v1(raw)


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_current_depths_are_classified_without_admission_authority(depth: int) -> None:
    result = classify_delegation_depth_v1(depth)
    assert result.raw_depth == depth
    assert result.policy_relation == "within_defined_current_policy"
    assert result.history_relation == "within_structural_history_bound"
    assert result.authority_semantics == "caller_supplied_unverified"
    assert result.admission_semantics == "no_admission_decision"
    assert validate_delegation_depth_classification_v1(result) == result


@pytest.mark.parametrize("depth", [4, 5, 6])
def test_legacy_depths_remain_visible_and_policy_invalid(depth: int) -> None:
    result = classify_delegation_depth_v1(depth)
    assert result.raw_depth == depth
    assert result.policy_relation == "above_defined_current_policy"
    assert result.history_relation == "within_structural_history_bound"
    assert result.reason_code == "raw_depth_preserved_policy_invalid"


def test_unknown_depth_remains_unknown() -> None:
    result = classify_delegation_depth_v1(None)
    assert result.raw_depth is None
    assert result.policy_relation == "unknown"
    assert result.history_relation == "unknown"
    assert result.reason_code == "raw_depth_unavailable"
    assert result.admission_semantics == "no_admission_decision"


@pytest.mark.parametrize("depth", [-1, 7, True, _IntSubclass(3), "3"])
def test_depth_classification_rejects_invalid_or_out_of_structural_range(depth: object) -> None:
    with pytest.raises(RuntimePolicyDefinitionError):
        classify_delegation_depth_v1(depth)


def test_classification_is_immutable_and_digest_bound() -> None:
    result = classify_delegation_depth_v1(4)
    assert not hasattr(result, "__dict__")
    with pytest.raises(AttributeError):
        cast(Any, result).raw_depth = 3
    forged = result._replace(reason_code="raw_depth_within_defined_current_policy")
    with pytest.raises(RuntimePolicyDefinitionError):
        validate_delegation_depth_classification_v1(forged)
    forged_digest = result._replace(classification_sha256="0" * 64)
    with pytest.raises(RuntimePolicyDefinitionError, match="does not bind"):
        validate_delegation_depth_classification_v1(forged_digest)


def test_classification_to_dict_rejects_mutable_aliases() -> None:
    result = classify_delegation_depth_v1(2)
    mutable = ["within_defined_current_policy"]
    malformed = result._replace(policy_relation=cast(Any, mutable))
    with pytest.raises(CompanyContractError):
        malformed.to_dict()
    mutable.append("changed")
    with pytest.raises(CompanyContractError):
        malformed.to_dict()


@pytest.mark.parametrize("forgery", [_StringSubclass("above_defined_current_policy"), _AlwaysEqual(), _ExplodingEqual()])
def test_classification_rejects_untrusted_equality_and_string_subclasses(forgery: object) -> None:
    result = classify_delegation_depth_v1(4)
    forged = result._replace(policy_relation=cast(Any, forgery))
    with pytest.raises(CompanyContractError):
        validate_delegation_depth_classification_v1(forged)


def test_definition_error_is_a_company_contract_error() -> None:
    assert issubclass(RuntimePolicyDefinitionError, CompanyContractError)
    with pytest.raises(CompanyContractError):
        validate_runtime_policy_definition_v1(object())


def _direct_imports(source: str) -> set[str]:
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." * node.level + (node.module or ""))
    return imported


_ALLOWED_RUNTIME_POLICY_IMPORTS = {
    "__future__",
    "aoi_orgware.company.contracts",
    "hashlib",
    "re",
    "typing",
}


def test_module_source_has_no_direct_runtime_wiring_imports() -> None:
    source_path = Path(__file__).parents[2] / "src" / "aoi_orgware" / "company" / "runtime_policy.py"
    imported = _direct_imports(source_path.read_text(encoding="utf-8"))
    assert imported == _ALLOWED_RUNTIME_POLICY_IMPORTS


@pytest.mark.parametrize(
    "source",
    (
        "from .service import CompanyService",
        "from . import service",
        "from ..company.service import CompanyService",
        "import aoi_orgware.runtime.service",
    ),
)
def test_runtime_wiring_import_guard_detects_unapproved_imports(source: str) -> None:
    assert _direct_imports(source) - _ALLOWED_RUNTIME_POLICY_IMPORTS


def test_contract_contains_no_activation_or_runtime_state_fields() -> None:
    fields = set(RuntimePolicyDefinitionV1._fields)
    assert not fields & {
        "activated_at", "activation_id", "activation_cursor", "company_id",
        "company_incarnation", "lock_domain_generation", "previous_transaction_sha256",
        "receipt_id", "state", "admitted", "occupied", "available",
    }
    assert set(DelegationDepthClassificationV1._fields) >= {
        "authority_semantics", "admission_semantics", "definition_sha256",
    }
