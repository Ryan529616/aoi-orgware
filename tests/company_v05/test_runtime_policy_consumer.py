# AOI-SYNTHETIC-FIXTURE-V1
"""Adversarial tests for the writer-off runtime-policy consumer seam."""
from __future__ import annotations

import ast
import copy
import os
from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.company.contract_registry import contract_validator_for
from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    COMPANY_EVENT_V1,
    COMPANY_MANIFEST_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    ZERO_SHA256,
    CompanyContractError,
    company_contract_sha256,
)
from aoi_orgware.company.invariants import (
    MAX_ACTIVE_CARRIERS,
    MAX_DELEGATION_DEPTH,
)
from aoi_orgware.company.projection_registry import PROJECTABLE_STREAM
from aoi_orgware.company.runtime_policy import runtime_policy_definition_v2
from aoi_orgware.company.runtime_policy_consumer import (
    LEGACY_ACTIVE_CARRIER_LIMIT,
    LEGACY_DELEGATION_DEPTH_LIMIT,
    RuntimePolicyConsumerError,
    RuntimePolicyConsumerViewV1,
    RuntimePolicySyntheticEvaluationV1,
    canonical_runtime_policy_consumer_view_v1_bytes,
    canonical_runtime_policy_v2_synthetic_evaluation_bytes,
    evaluate_runtime_policy_v2_synthetic,
    inactive_runtime_policy_consumer_view_v1,
    validate_runtime_policy_consumer_view_v1,
    validate_runtime_policy_v2_synthetic_evaluation,
)
from aoi_orgware.company.state import CompanyStateInvariantError, CompanyStateOwner


T = "2026-08-03T00:00:00Z"
H = "a" * 64


class _IntSubclass(int):
    pass


class _StringSubclass(str):
    pass


def _evaluate(**overrides: object) -> RuntimePolicySyntheticEvaluationV1:
    values: dict[str, object] = {
        "role_class": "worker",
        "department": "rtl",
        "parent_role_class": "rtl_lead",
        "parent_department": "rtl",
        "delegation_depth": 2,
        "can_delegate": True,
        "subordinate_occupied": 3,
        "occupancy_quality": "exact",
        "acquisition_kind": "subordinate_carrier",
        "effect_unknown_holder": False,
    }
    values.update(overrides)
    return evaluate_runtime_policy_v2_synthetic(**values)


def test_inactive_view_preserves_actual_legacy_limits() -> None:
    view = inactive_runtime_policy_consumer_view_v1()
    assert view.activation_state == "inactive"
    assert view.legacy_active_carrier_limit == LEGACY_ACTIVE_CARRIER_LIMIT == MAX_ACTIVE_CARRIERS == 16
    assert view.legacy_delegation_depth_limit == LEGACY_DELEGATION_DEPTH_LIMIT == MAX_DELEGATION_DEPTH == 6
    assert view.candidate_definition_sha256 == runtime_policy_definition_v2().definition_sha256
    assert view.candidate_definition_state == "candidate_definition_only"
    assert view.authority_semantics == "no_durable_activation"
    assert view.admission_semantics == "no_admission_decision"
    assert view.capacity_semantics == "legacy_runtime_unchanged"
    assert view.operational_effect == "none"


def test_inactive_view_is_immutable_canonical_and_exactly_rederived() -> None:
    view = inactive_runtime_policy_consumer_view_v1()
    assert not hasattr(view, "__dict__")
    with pytest.raises(AttributeError):
        cast(Any, view).activation_state = "active"
    reversed_dict = dict(reversed(tuple(view.to_dict().items())))
    assert validate_runtime_policy_consumer_view_v1(reversed_dict) == view
    assert canonical_runtime_policy_consumer_view_v1_bytes(reversed_dict) == canonical_runtime_policy_consumer_view_v1_bytes(view)
    forged = view._replace(view_sha256="f" * 64)
    with pytest.raises(RuntimePolicyConsumerError):
        validate_runtime_policy_consumer_view_v1(forged)
    extra = view.to_dict(); extra["activation_cursor"] = 1
    with pytest.raises(RuntimePolicyConsumerError):
        validate_runtime_policy_consumer_view_v1(extra)


@pytest.mark.parametrize(
    ("role", "department", "parent", "parent_department", "depth", "can_delegate", "kind"),
    (
        ("chief", None, None, None, 0, True, "chief_carrier"),
        ("rtl_lead", "rtl", "chief", None, 1, True, "subordinate_carrier"),
        ("dv_lead", "dv", "chief", None, 1, True, "subordinate_carrier"),
        ("pd_lead", "pd", "chief", None, 1, True, "subordinate_carrier"),
        ("worker", "rtl", "rtl_lead", "rtl", 2, True, "subordinate_carrier"),
        ("reviewer", "rtl", "worker", "rtl", 3, False, "no_new_carrier"),
    ),
)
def test_synthetic_topology_accepts_only_d0_through_d3_shape(
    role: str,
    department: str | None,
    parent: str | None,
    parent_department: str | None,
    depth: int,
    can_delegate: bool,
    kind: str,
) -> None:
    result = _evaluate(
        role_class=role,
        department=department,
        parent_role_class=parent,
        parent_department=parent_department,
        delegation_depth=depth,
        can_delegate=can_delegate,
        acquisition_kind=kind,
    )
    assert result.topology_disposition == "within_candidate_policy"
    assert result.synthetic_disposition == "unavailable"
    assert result.authority_semantics == "synthetic_unverified"
    assert result.operational_effect == "none"


@pytest.mark.parametrize(
    "overrides,reason",
    (
        ({"role_class": "rtl_lead", "department": "dv", "parent_role_class": "chief", "delegation_depth": 1}, "would_reject_topology"),
        ({"parent_role_class": "chief"}, "would_reject_topology"),
        ({"role_class": "reviewer", "parent_role_class": "worker", "delegation_depth": 3, "can_delegate": True}, "would_reject_topology"),
        ({"delegation_depth": 4}, "would_reject_over_depth"),
        ({"delegation_depth": 6}, "would_reject_over_depth"),
    ),
)
def test_synthetic_topology_fail_closed_candidates(
    overrides: dict[str, object],
    reason: str,
) -> None:
    result = _evaluate(**overrides)
    assert result.topology_disposition == reason
    assert result.synthetic_disposition == "would_reject"
    assert result.operational_effect == "none"


def test_synthetic_capacity_keeps_chief_separate_and_queues_fifth_slot() -> None:
    fourth = _evaluate(subordinate_occupied=3)
    fifth = _evaluate(subordinate_occupied=4)
    chief = _evaluate(
        role_class="chief",
        department=None,
        parent_role_class=None,
        parent_department=None,
        delegation_depth=0,
        acquisition_kind="chief_carrier",
        subordinate_occupied=4,
    )
    assert fourth.capacity_disposition == "within_candidate_limit"
    assert fourth.synthetic_disposition == "unavailable"
    assert fifth.capacity_disposition == "would_queue"
    assert fifth.synthetic_disposition == "would_queue"
    assert chief.capacity_disposition == "not_applicable_chief_excluded"
    assert chief.chief_cardinality_disposition == "unavailable"
    assert chief.synthetic_disposition == "unavailable"


def test_chief_and_no_new_carrier_never_enter_subordinate_capacity_gate() -> None:
    chief_unknown = _evaluate(
        role_class="chief",
        department=None,
        parent_role_class=None,
        parent_department=None,
        delegation_depth=0,
        acquisition_kind="chief_carrier",
        subordinate_occupied=None,
        occupancy_quality="unknown_or_unattributed",
    )
    chief_overfull = _evaluate(
        role_class="chief",
        department=None,
        parent_role_class=None,
        parent_department=None,
        delegation_depth=0,
        acquisition_kind="chief_carrier",
        subordinate_occupied=5,
    )
    no_new = _evaluate(
        acquisition_kind="no_new_carrier",
        subordinate_occupied=5,
    )
    assert chief_unknown.capacity_disposition == "not_applicable_chief_excluded"
    assert chief_overfull.capacity_disposition == "not_applicable_chief_excluded"
    assert no_new.capacity_disposition == "not_applicable_no_new_slot"
    assert chief_unknown.synthetic_disposition == "unavailable"
    assert chief_overfull.synthetic_disposition == "unavailable"
    assert no_new.synthetic_disposition == "unavailable"


def test_unknown_or_unattributed_capacity_never_guesses_zero_or_available() -> None:
    result = _evaluate(
        role_class="unknown",
        department=None,
        parent_role_class="unknown",
        parent_department="unknown",
        delegation_depth=None,
        can_delegate=None,
        subordinate_occupied=None,
        occupancy_quality="unknown_or_unattributed",
        acquisition_kind="subordinate_carrier",
    )
    assert result.subordinate_occupied is None
    assert result.topology_disposition == "unavailable"
    assert result.capacity_disposition == "unavailable"
    assert result.synthetic_disposition == "unavailable"
    with pytest.raises(RuntimePolicyConsumerError):
        _evaluate(subordinate_occupied=0, occupancy_quality="unknown_or_unattributed")


@pytest.mark.parametrize(
    "overrides",
    (
        {"parent_role_class": "unknown"},
        {"department": None},
        {"department": "unknown"},
        {"parent_department": None},
        {"parent_department": "unknown"},
        {"role_class": "reviewer", "parent_role_class": "unknown", "parent_department": "unknown", "delegation_depth": 3, "can_delegate": False},
        {"role_class": "chief", "department": None, "parent_role_class": "unknown", "parent_department": "unknown", "delegation_depth": 0},
        {"acquisition_kind": "unknown"},
    ),
)
def test_partial_unknown_topology_is_unavailable_not_rejected(
    overrides: dict[str, object],
) -> None:
    result = _evaluate(**overrides)
    assert result.topology_disposition == "unavailable"
    assert result.synthetic_disposition == "unavailable"


def test_exact_over_depth_rejects_even_when_other_attribution_is_unknown() -> None:
    result = _evaluate(
        role_class="unknown",
        department="unknown",
        parent_role_class="unknown",
        parent_department="unknown",
        delegation_depth=4,
    )
    assert result.topology_disposition == "would_reject_over_depth"
    assert result.synthetic_disposition == "would_reject"


@pytest.mark.parametrize(
    "overrides",
    (
        {"department": "rtl", "parent_role_class": "dv_lead", "parent_department": "dv"},
        {"role_class": "reviewer", "department": "rtl", "parent_role_class": "worker", "parent_department": "dv", "delegation_depth": 3, "can_delegate": False},
    ),
)
def test_cross_department_subordinate_topology_is_rejected(
    overrides: dict[str, object],
) -> None:
    result = _evaluate(**overrides)
    assert result.topology_disposition == "would_reject_topology"
    assert result.synthetic_disposition == "would_reject"


def test_effect_unknown_holder_is_retained_and_must_be_counted() -> None:
    result = _evaluate(
        subordinate_occupied=1,
        acquisition_kind="no_new_carrier",
        effect_unknown_holder=True,
    )
    assert result.effect_unknown_disposition == "retained"
    assert result.synthetic_disposition == "would_hold_effect_unknown"
    with pytest.raises(RuntimePolicyConsumerError):
        _evaluate(
            subordinate_occupied=0,
            acquisition_kind="no_new_carrier",
            effect_unknown_holder=True,
        )
    with pytest.raises(RuntimePolicyConsumerError):
        _evaluate(effect_unknown_holder=True)


@pytest.mark.parametrize(
    "overrides",
    (
        {"delegation_depth": True},
        {"delegation_depth": _IntSubclass(2)},
        {"subordinate_occupied": True},
        {"subordinate_occupied": _IntSubclass(3)},
        {"effect_unknown_holder": 1},
        {"role_class": _StringSubclass("worker")},
        {"occupancy_quality": "exact", "subordinate_occupied": None},
    ),
)
def test_synthetic_inputs_require_exact_types(overrides: dict[str, object]) -> None:
    with pytest.raises(RuntimePolicyConsumerError):
        _evaluate(**overrides)


def test_synthetic_evaluation_is_canonical_immutable_and_digest_bound() -> None:
    result = _evaluate()
    assert not hasattr(result, "__dict__")
    reversed_dict = dict(reversed(tuple(result.to_dict().items())))
    assert validate_runtime_policy_v2_synthetic_evaluation(reversed_dict) == result
    assert canonical_runtime_policy_v2_synthetic_evaluation_bytes(reversed_dict) == canonical_runtime_policy_v2_synthetic_evaluation_bytes(result)
    forged = result._replace(capacity_disposition="within_candidate_limit", evaluation_sha256="f" * 64)
    with pytest.raises(RuntimePolicyConsumerError):
        validate_runtime_policy_v2_synthetic_evaluation(forged)
    malformed = tuple.__new__(RuntimePolicySyntheticEvaluationV1, tuple(result)[:-1])
    with pytest.raises(RuntimePolicyConsumerError):
        validate_runtime_policy_v2_synthetic_evaluation(malformed)


def _manifest() -> dict[str, object]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": H,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def _authority() -> dict[str, object]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "actor_id": "supervisor-1",
        "actor_kind": "supervisor",
        "carrier_id": None,
        "chief_epoch": None,
        "term": 1,
        "authority_state": "active",
        "permissions": ["company.mutate"],
        "scope_sha256": H,
        "authority_record_sha256": H,
        "provenance": "AOI_verified",
    }


def test_activation_remains_unregistered_and_generic_commit_is_zero_append(
    tmp_path: Path,
) -> None:
    activation = {
        "contract_type": "runtime_policy_activation_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "activation_id": "activation-1",
        "definition_sha256": runtime_policy_definition_v2().definition_sha256,
    }
    assert contract_validator_for(activation["contract_type"], None, None) is None
    assert activation["contract_type"] not in PROJECTABLE_STREAM
    owner = CompanyStateOwner.initialize(
        tmp_path / "company",
        _manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    before = owner.heads()
    authority = _authority()
    event = {
        "contract_type": COMPANY_EVENT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "transaction_id": "tx-activation",
        "command_id": "cmd-activation",
        "event_id": "event-activation",
        "stream": "org",
        "event_type": "runtime_policy.activated",
        "recorded_at": T,
        "actor_authority": copy.deepcopy(authority),
        "provenance": "AOI_verified",
        "payload": activation,
        "payload_sha256": company_contract_sha256(activation),
    }
    request: dict[str, object] = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "transaction_id": "tx-activation",
        "command_id": "cmd-activation",
        "actor_authority": authority,
        "expected_transaction_head": {
            "contract_type": EXPECTED_TRANSACTION_HEAD_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "transaction_id": "tx-activation",
            "command_id": "cmd-activation",
            "global_sequence": before.global_head.global_sequence,
            "transaction_sha256": before.global_head.transaction_sha256,
        },
        "expected_heads": [{
            "contract_type": EXPECTED_HEAD_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "transaction_id": "tx-activation",
            "command_id": "cmd-activation",
            "stream": "org",
            "cursor": 0,
            "event_sha256": ZERO_SHA256,
        }],
        "events": [event],
    }
    request["request_sha256"] = company_contract_sha256(request)
    try:
        with pytest.raises(CompanyStateInvariantError, match="unsupported"):
            owner.commit(request, recorded_at=T)
        assert owner.heads() == before
    finally:
        owner.close()


def _direct_imports(source: str) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            result.add("." * node.level + (node.module or ""))
    return result


def test_consumer_module_has_no_runtime_wiring_and_no_consumer_is_active() -> None:
    root = Path(__file__).parents[2]
    source_path = root / "src" / "aoi_orgware" / "company" / "runtime_policy_consumer.py"
    assert _direct_imports(source_path.read_text(encoding="utf-8")) == {
        "__future__",
        "hashlib",
        "re",
        "typing",
        "aoi_orgware.company.contracts",
        "aoi_orgware.company.runtime_policy",
    }
    for name in (
        "invariants.py",
        "state.py",
        "readmodel.py",
        "supervisor.py",
        "views.py",
    ):
        source = (root / "src" / "aoi_orgware" / "company" / name).read_text(encoding="utf-8")
        assert "runtime_policy_consumer" not in source
    dispatch = (root / "src" / "aoi_orgware" / "dispatch_protocol.py").read_text(encoding="utf-8")
    assert "runtime_policy_consumer" not in dispatch


def test_public_results_expose_no_authoritative_runtime_claim_fields() -> None:
    forbidden = {
        "activation_id",
        "activation_cursor",
        "admitted",
        "available",
        "company_id",
        "current",
        "lease_id",
        "occupied",
        "receipt_id",
    }
    assert not forbidden & set(RuntimePolicyConsumerViewV1._fields)
    assert not forbidden & set(RuntimePolicySyntheticEvaluationV1._fields)
