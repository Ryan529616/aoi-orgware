"""State-bound tests for the writer-off runtime-policy activation kernel."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
from typing import Any, Mapping, cast

import pytest

from aoi_orgware.company.contracts import (
    EXECUTION_NODE_V1,
    canonical_company_json_bytes,
)
from aoi_orgware.company.runtime_policy_activation import (
    RUNTIME_POLICY_ACTIVATION_V1,
    RuntimePolicyActivationV1,
    derive_runtime_policy_activation_v1,
    validate_runtime_policy_activation_structure_v1,
)
from aoi_orgware.company.runtime_policy_admission import (
    RuntimePolicyActivationAdmissionError,
    RuntimePolicyActivationAdmissionV1,
    canonical_runtime_policy_activation_admission_v1_bytes,
    derive_runtime_policy_activation_admission_v1,
    validate_runtime_policy_activation_admission_structure_v1,
    validate_runtime_policy_activation_admission_v1,
)
from aoi_orgware.company.runtime_policy_readiness import (
    RuntimePolicyReadinessObservationV1,
    derive_runtime_policy_readiness,
)
from aoi_orgware.company.state import CompanyDeliveryPartialError
from aoi_orgware.company.supervisor import CompanySupervisor


_TEST_DIR = Path(__file__).resolve().parent
if str(_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_TEST_DIR))

import test_runtime_policy_activation_contract as activation_support  # type: ignore[import-not-found]
import test_supervisor as supervisor_tests  # type: ignore[import-not-found]
import test_write_admission_projection as support  # type: ignore[import-not-found]


CHECKPOINT_ID = "pre-activation-checkpoint-verified"
EXPORT_ID = "pre-activation-export-verified"
CHECKPOINT_AT = "2026-07-27T00:01:30Z"


_initialize = activation_support._initialize


def _candidate(
    supervisor: CompanySupervisor,
    *,
    issuer: Mapping[str, Any] | None = None,
    grant_id: str = "runtime-policy-change-grant-1",
    grant_recorded_at: str = activation_support.ISSUED,
    checkpoint_at: str = CHECKPOINT_AT,
    requested_at: str = activation_support.REQUESTED,
) -> tuple[
    RuntimePolicyActivationV1,
    RuntimePolicyReadinessObservationV1,
    dict[str, Any],
    dict[str, Any],
]:
    grant, actual_issuer = activation_support._grant(
        supervisor,
        grant_id=grant_id,
        actor_grant=issuer,
        recorded_at=grant_recorded_at,
    )
    delivery = supervisor.create_checkpoint_export(
        CHECKPOINT_ID,
        EXPORT_ID,
        checkpoint_at,
    )
    assert delivery.checkpoint.state == "verified"
    assert delivery.checkpoint.current
    assert delivery.checkpoint.manifest_sha256 is not None
    readiness = derive_runtime_policy_readiness(supervisor._state)
    candidate = derive_runtime_policy_activation_v1(
        readiness,
        grant,
        grant_issuer_authority_record_sha256=actual_issuer["grant_sha256"],
        pre_activation_checkpoint_id=CHECKPOINT_ID,
        pre_activation_checkpoint_manifest_sha256=(
            delivery.checkpoint.manifest_sha256
        ),
        transport_capability_receipt_sha256=activation_support.TRANSPORT_SHA,
        writer_quiescence_receipt_sha256=activation_support.QUIESCENCE_SHA,
        requested_activation_at=requested_at,
    )
    return candidate, readiness, grant, actual_issuer


def _rehash_admission(
    value: RuntimePolicyActivationAdmissionV1,
    **changes: object,
) -> RuntimePolicyActivationAdmissionV1:
    provisional = cast(
        RuntimePolicyActivationAdmissionV1,
        cast(Any, value)._replace(**changes, admission_sha256="0" * 64),
    )
    payload = dict(provisional._asdict())
    payload["blockers"] = list(provisional.blockers)
    digest = hashlib.sha256(canonical_company_json_bytes({
        "derivation_domain": (
            "aoi.company.runtime-policy-activation-admission.v1"
        ),
        "admission": payload,
    })).hexdigest()
    return provisional._replace(admission_sha256=digest)


def test_owner_replayed_candidate_is_blocked_at_current_missing_seams(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        assert result.candidate_disposition == "blocked"
        assert result.operational_effect == "none"
        assert result.registration_state == "writer_off_unregistered"
        assert result.policy_change_grant_state == "verified_prior_singleton"
        assert (
            result.policy_change_grant_issuer_state
            == "verified_prior_current_chief"
        )
        assert result.pre_activation_checkpoint_state == "verified_current"
        assert result.transport_capability_state == "unavailable"
        assert result.writer_quiescence_state == "unavailable"
        assert result.capacity_state == "lower_bound_only"
        assert {
            "subordinate_capacity_exactness_unavailable",
            "transport_capability_receipt_join_unavailable",
            "writer_quiescence_receipt_join_unavailable",
        } <= set(result.blockers)
        assert validate_runtime_policy_activation_admission_structure_v1(
            result
        ) == result
        assert validate_runtime_policy_activation_admission_v1(
            supervisor._state,
            result,
            candidate,
            readiness,
        ) == result
        assert canonical_runtime_policy_activation_admission_v1_bytes(
            result
        ) == canonical_runtime_policy_activation_admission_v1_bytes(
            result.to_dict()
        )


def test_degraded_current_chief_is_self_consistent_after_reopen(
    tmp_path: Path,
) -> None:
    slot_root = tmp_path / "state" / "companies" / "company-1"
    with _initialize(tmp_path) as supervisor:
        grant, issuer = activation_support._grant(supervisor)
        chief = next(
            item for item in supervisor_tests._objects(supervisor, EXECUTION_NODE_V1)
            if item["role"] == "chief" and item["engineering_status"] == "active"
        )
        receipt = supervisor_tests.fenced_chief_stop_receipt(
            supervisor,
            execution_id=chief["execution_id"],
            transaction_id="runtime-policy-chief-stop-transaction",
            command_id="runtime-policy-chief-stop-command",
            recorded_at="2026-07-27T00:01:15Z",
        )
        supervisor.record_current_chief_execution_stopped(
            chief["execution_id"], receipt,
            transaction_id="runtime-policy-chief-stop-transaction",
            command_id="runtime-policy-chief-stop-command",
            recorded_at="2026-07-27T00:01:15Z",
        )
        try:
            supervisor.create_checkpoint_export(CHECKPOINT_ID, EXPORT_ID, CHECKPOINT_AT)
        except CompanyDeliveryPartialError:
            pass
        checkpoint = supervisor._state.delivery_snapshot().checkpoint
        assert checkpoint.manifest_sha256 is not None
        readiness = derive_runtime_policy_readiness(supervisor._state)
        candidate = activation_support._unchecked_activation_candidate(
            readiness, grant, issuer, CHECKPOINT_ID, checkpoint.manifest_sha256,
        )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state, candidate, readiness,
        )
        assert readiness.current_chief_state == "exact_identity_carrier_unavailable"
        assert {"current_chief_carrier_coverage_unavailable", "current_chief_unavailable"} <= set(result.blockers)
        assert validate_runtime_policy_activation_admission_structure_v1(result) == result
    with CompanySupervisor.open(slot_root) as reopened:
        reopened_readiness = derive_runtime_policy_readiness(reopened._state)
        assert derive_runtime_policy_activation_admission_v1(
            reopened._state, candidate, reopened_readiness,
        ) == result


def test_stale_readiness_after_any_append_is_rejected(tmp_path: Path) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        activation_support._grant(
            supervisor,
            grant_id="unrelated-release-grant-1",
            permission="release.publish",
        )
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="current readiness",
        ):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state,
                candidate,
                readiness,
            )


@pytest.mark.parametrize(
    ("grant_recorded_at", "checkpoint_at", "requested_at", "match"),
    [
        ("2026-07-27T00:04:00Z", CHECKPOINT_AT,
         "2026-07-27T00:02:00Z", "grant"),
        (activation_support.ISSUED, "2026-07-27T00:05:00Z",
         "2026-07-27T00:02:00Z", "checkpoint"),
        ("2026-07-27T00:04:00Z", CHECKPOINT_AT,
         activation_support.REQUESTED, "checkpoint"),
        ("2026-07-27T00:00:30Z", CHECKPOINT_AT,
         activation_support.REQUESTED, "grant"),
        (activation_support.ISSUED, "2098-01-01T00:00:00Z",
         "2099-01-01T00:00:00Z", "checkpoint"),
    ],
)
def test_grant_and_checkpoint_chronology_fail_closed_after_reopen(
    tmp_path: Path,
    grant_recorded_at: str,
    checkpoint_at: str,
    requested_at: str,
    match: str,
) -> None:
    slot_root = tmp_path / "state" / "companies" / "company-1"
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(
            supervisor,
            grant_recorded_at=grant_recorded_at,
            checkpoint_at=checkpoint_at,
            requested_at=requested_at,
        )
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match=match,
        ):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state, candidate, readiness,
            )
    with CompanySupervisor.open(slot_root) as reopened:
        reopened_readiness = derive_runtime_policy_readiness(reopened._state)
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match=match,
        ):
            derive_runtime_policy_activation_admission_v1(
                reopened._state, candidate, reopened_readiness,
            )


def test_exact_company_and_readiness_cross_binding_is_required(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        cross_bound = candidate._replace(company_incarnation=2)
        # Structural bytes cannot be salvaged by retaining the old digest.
        with pytest.raises(RuntimePolicyActivationAdmissionError):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state,
                cross_bound,
                readiness,
            )


def test_candidate_scope_forgery_is_rejected_at_exact_owner_head(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        forged = activation_support._rehash_activation(
            candidate,
            policy_change_scope_sha256="f" * 64,
        )
        assert validate_runtime_policy_activation_structure_v1(forged) == forged
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="exact current readiness",
        ):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state,
                forged,
                readiness,
            )


def test_durable_wrong_scope_grant_is_rejected_at_exact_owner_head(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        grant, issuer = activation_support._grant(
            supervisor,
            scope_sha256="f" * 64,
        )
        delivery = supervisor.create_checkpoint_export(
            CHECKPOINT_ID,
            EXPORT_ID,
            CHECKPOINT_AT,
        )
        assert delivery.checkpoint.manifest_sha256 is not None
        readiness = derive_runtime_policy_readiness(supervisor._state)
        candidate = activation_support._unchecked_activation_candidate(
            readiness,
            grant,
            issuer,
            CHECKPOINT_ID,
            delivery.checkpoint.manifest_sha256,
        )
        assert validate_runtime_policy_activation_structure_v1(candidate) == candidate
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="durable policy-change grant scope",
        ):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state,
                candidate,
                readiness,
            )


@pytest.mark.parametrize(
    ("subject_actor_id", "subject_carrier_id"),
    [("foreign-chief", None), (None, "foreign-carrier")],
)
def test_durable_grant_subject_must_be_current_chief_after_reopen(
    tmp_path: Path,
    subject_actor_id: str | None,
    subject_carrier_id: str | None,
) -> None:
    slot_root = tmp_path / "state" / "companies" / "company-1"
    with _initialize(tmp_path) as supervisor:
        grant, issuer = activation_support._grant(
            supervisor,
            subject_actor_id=subject_actor_id,
            subject_carrier_id=subject_carrier_id,
        )
        delivery = supervisor.create_checkpoint_export(
            CHECKPOINT_ID, EXPORT_ID, CHECKPOINT_AT,
        )
        assert delivery.checkpoint.manifest_sha256 is not None
        readiness = derive_runtime_policy_readiness(supervisor._state)
        candidate = activation_support._unchecked_activation_candidate(
            readiness, grant, issuer, CHECKPOINT_ID,
            delivery.checkpoint.manifest_sha256,
        )
        with pytest.raises(RuntimePolicyActivationAdmissionError, match="subject"):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state, candidate, readiness,
            )
    with CompanySupervisor.open(slot_root) as reopened:
        reopened_readiness = derive_runtime_policy_readiness(reopened._state)
        with pytest.raises(RuntimePolicyActivationAdmissionError, match="subject"):
            derive_runtime_policy_activation_admission_v1(
                reopened._state, candidate, reopened_readiness,
            )
        with pytest.raises(RuntimePolicyActivationAdmissionError):
            derive_runtime_policy_activation_admission_v1(
                supervisor._state,
                candidate,
                readiness._replace(cursor=True),
            )


@pytest.mark.parametrize(
    ("requested_at", "expected_grant_state"),
    [
        (activation_support.REQUESTED, "verified_prior_singleton"),
        ("2100-07-28T00:00:00Z", "expired"),
    ],
)
def test_grant_issuer_truth_preserves_independent_expiry_after_reopen(
    tmp_path: Path,
    requested_at: str,
    expected_grant_state: str,
) -> None:
    slot_root = tmp_path / "state" / "companies" / "company-1"
    with _initialize(tmp_path) as supervisor:
        supervisor_grant = support._supervisor_grant(supervisor)
        grant, issuer = activation_support._grant(
            supervisor,
            actor_grant=supervisor_grant,
        )
        assert issuer["actor_kind"] == "supervisor"
        delivery = supervisor.create_checkpoint_export(
            CHECKPOINT_ID, EXPORT_ID, CHECKPOINT_AT,
        )
        assert delivery.checkpoint.manifest_sha256 is not None
        readiness = derive_runtime_policy_readiness(supervisor._state)
        candidate = activation_support._unchecked_activation_candidate(
            readiness, grant, issuer, CHECKPOINT_ID,
            delivery.checkpoint.manifest_sha256,
            requested_at=requested_at,
        )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state, candidate, readiness,
        )
        assert result.policy_change_grant_state == expected_grant_state
        assert result.policy_change_grant_issuer_state == "mismatched"
        assert "policy_change_grant_issuer_mismatched" in result.blockers
        assert (
            "policy_change_grant_outside_time_fence" in result.blockers
        ) == (expected_grant_state == "expired")
        assert result.candidate_disposition == "blocked"
    with CompanySupervisor.open(slot_root) as reopened:
        reopened_readiness = derive_runtime_policy_readiness(reopened._state)
        assert derive_runtime_policy_activation_admission_v1(
            reopened._state, candidate, reopened_readiness,
        ) == result


def test_non_verified_policy_grant_never_becomes_verified_after_reopen(
    tmp_path: Path,
) -> None:
    slot_root = tmp_path / "state" / "companies" / "company-1"
    with _initialize(tmp_path) as supervisor:
        grant, issuer = activation_support._grant(
            supervisor, provenance="agent_reported",
        )
        delivery = supervisor.create_checkpoint_export(
            CHECKPOINT_ID, EXPORT_ID, CHECKPOINT_AT,
        )
        assert delivery.checkpoint.manifest_sha256 is not None
        readiness = derive_runtime_policy_readiness(supervisor._state)
        candidate = activation_support._unchecked_activation_candidate(
            readiness, grant, issuer, CHECKPOINT_ID,
            delivery.checkpoint.manifest_sha256,
        )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state, candidate, readiness,
        )
        assert result.policy_change_grant_state == "mismatched"
        assert result.policy_change_grant_issuer_state == "unavailable"
        assert "policy_change_grant_mismatched" in result.blockers
    with CompanySupervisor.open(slot_root) as reopened:
        reopened_readiness = derive_runtime_policy_readiness(reopened._state)
        assert derive_runtime_policy_activation_admission_v1(
            reopened._state, candidate, reopened_readiness,
        ) == result


def test_second_policy_change_grant_is_ambiguous_and_never_collapsed(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        first, _, _, issuer = _candidate(supervisor)
        activation_support._grant(
            supervisor,
            grant_id="runtime-policy-change-grant-2",
        )
        delivery = supervisor.create_checkpoint_export(
            "pre-activation-checkpoint-second",
            "pre-activation-export-second",
            "2026-07-27T00:03:00Z",
        )
        assert delivery.checkpoint.manifest_sha256 is not None
        readiness = derive_runtime_policy_readiness(supervisor._state)
        first_grant = next(
            activation_support._plain(item.payload)
            for item in supervisor.objects(contract_type="authority_grant_v1")
            if item.object_key == first.policy_change_grant_id
        )
        candidate = derive_runtime_policy_activation_v1(
            readiness,
            first_grant,
            grant_issuer_authority_record_sha256=issuer["grant_sha256"],
            pre_activation_checkpoint_id="pre-activation-checkpoint-second",
            pre_activation_checkpoint_manifest_sha256=(
                delivery.checkpoint.manifest_sha256
            ),
            transport_capability_receipt_sha256=activation_support.TRANSPORT_SHA,
            writer_quiescence_receipt_sha256=activation_support.QUIESCENCE_SHA,
            requested_activation_at=activation_support.REQUESTED,
        )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        assert result.policy_change_grant_state == "ambiguous"
        assert "policy_change_grant_ambiguous" in result.blockers


def test_checkpoint_identity_and_currentness_are_rederived(tmp_path: Path) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        forged = candidate._replace(
            pre_activation_checkpoint_id="different-checkpoint",
        )
        # Recompute a structurally valid candidate through the supported builder
        # using an incorrect but well-formed checkpoint identity.
        grant = next(
            activation_support._plain(item.payload)
            for item in supervisor.objects(contract_type="authority_grant_v1")
            if item.object_key == candidate.policy_change_grant_id
        )
        issuer = activation_support._chief_grant(supervisor)
        forged = derive_runtime_policy_activation_v1(
            readiness,
            grant,
            grant_issuer_authority_record_sha256=issuer["grant_sha256"],
            pre_activation_checkpoint_id="different-checkpoint",
            pre_activation_checkpoint_manifest_sha256=(
                candidate.pre_activation_checkpoint_manifest_sha256
            ),
            transport_capability_receipt_sha256=activation_support.TRANSPORT_SHA,
            writer_quiescence_receipt_sha256=activation_support.QUIESCENCE_SHA,
            requested_activation_at=activation_support.REQUESTED,
        )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            forged,
            readiness,
        )
        assert result.pre_activation_checkpoint_state == "unavailable_or_stale"
        assert "pre_activation_checkpoint_unavailable" in result.blockers


def test_structural_admission_forgery_does_not_pass_semantic_validator(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        forged = _rehash_admission(
            result,
            blockers=tuple(
                item for item in result.blockers
                if item != "subordinate_capacity_exactness_unavailable"
            ),
        )
        with pytest.raises(RuntimePolicyActivationAdmissionError):
            validate_runtime_policy_activation_admission_structure_v1(forged)
        with pytest.raises(RuntimePolicyActivationAdmissionError):
            validate_runtime_policy_activation_admission_v1(
                supervisor._state,
                result._replace(admission_sha256="f" * 64),
                candidate,
                readiness,
            )


def test_structural_admission_rejects_unknown_and_contradictory_blockers(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        for blocker, match in (
            ("invented_positive_evidence", "closed vocabulary"),
            ("policy_change_grant_missing", "contradicts"),
        ):
            forged = _rehash_admission(
                result,
                blockers=tuple(sorted((*result.blockers, blocker))),
            )
            with pytest.raises(RuntimePolicyActivationAdmissionError, match=match):
                validate_runtime_policy_activation_admission_structure_v1(forged)


def test_structural_grant_and_issuer_truth_table_is_exact(tmp_path: Path) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state, candidate, readiness,
        )
        grant_blockers = {
            "missing": "policy_change_grant_missing",
            "ambiguous": "policy_change_grant_ambiguous",
            "mismatched": "policy_change_grant_mismatched",
            "expired": "policy_change_grant_outside_time_fence",
        }
        valid = {
            ("missing", "unavailable"), ("ambiguous", "unavailable"),
            ("mismatched", "unavailable"),
            ("expired", "verified_prior_current_chief"),
            ("expired", "mismatched"), ("expired", "unavailable"),
            ("verified_prior_singleton", "verified_prior_current_chief"),
            ("verified_prior_singleton", "mismatched"),
            ("verified_prior_singleton", "unavailable"),
        }
        grant_states = (*grant_blockers, "verified_prior_singleton")
        issuer_states = (
            "unavailable", "mismatched", "verified_prior_current_chief",
        )
        for grant_state in grant_states:
            for issuer_state in issuer_states:
                blockers = set(result.blockers)
                if grant_state in grant_blockers:
                    blockers.add(grant_blockers[grant_state])
                if issuer_state == "mismatched":
                    blockers.add("policy_change_grant_issuer_mismatched")
                elif (
                    issuer_state == "unavailable"
                    and grant_state in {"expired", "verified_prior_singleton"}
                ):
                    blockers.add("current_chief_term_missing_or_ambiguous")
                forged = _rehash_admission(
                    result,
                    policy_change_grant_state=grant_state,
                    policy_change_grant_issuer_state=issuer_state,
                    blockers=tuple(sorted(blockers)),
                )
                if (grant_state, issuer_state) in valid:
                    assert validate_runtime_policy_activation_admission_structure_v1(
                        forged
                    ) == forged
                else:
                    with pytest.raises(RuntimePolicyActivationAdmissionError):
                        validate_runtime_policy_activation_admission_structure_v1(
                            forged
                        )
        for grant_state in ("expired", "verified_prior_singleton"):
            blockers = {
                *result.blockers,
                "policy_change_grant_issuer_prior_grant_unavailable",
            }
            if grant_state == "expired":
                blockers.add("policy_change_grant_outside_time_fence")
            prior_unavailable = _rehash_admission(
                result,
                policy_change_grant_state=grant_state,
                policy_change_grant_issuer_state="unavailable",
                blockers=tuple(sorted(blockers)),
            )
            assert validate_runtime_policy_activation_admission_structure_v1(
                prior_unavailable
            ) == prior_unavailable


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("capacity_state", "exact_available"),
        ("transport_capability_state", "verified"),
        ("writer_quiescence_state", "verified"),
    ],
)
def test_structural_admission_rejects_positive_writer_off_evidence_claims(
    tmp_path: Path,
    field: str,
    forged_value: str,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        forged = _rehash_admission(result, **{field: forged_value})
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="writer-off state vocabulary",
        ):
            validate_runtime_policy_activation_admission_structure_v1(forged)


def test_kernel_rejects_non_owner_and_exposes_no_positive_runtime_claims(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="exact CompanyStateOwner",
        ):
            derive_runtime_policy_activation_admission_v1(
                cast(Any, object()),
                candidate,
                readiness,
            )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        forbidden_fields = {
            "active", "activated", "admitted", "available", "current",
            "receipt_id",
        }
        assert not forbidden_fields & set(RuntimePolicyActivationAdmissionV1._fields)
        values = {value for value in result if type(value) is str}
        assert not {"active", "activated", "admitted", "available"} & values
        with pytest.raises(AttributeError):
            result.candidate_disposition = "eligible_candidate"  # type: ignore[misc]


def test_blockers_are_canonical_and_duplicate_input_cannot_be_hidden(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        assert result.blockers == tuple(sorted(set(result.blockers)))
        duplicate = result._replace(blockers=result.blockers + (result.blockers[0],))
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="blockers",
        ):
            validate_runtime_policy_activation_admission_structure_v1(duplicate)
        unsorted = result._replace(blockers=tuple(reversed(result.blockers)))
        with pytest.raises(
            RuntimePolicyActivationAdmissionError,
            match="blockers",
        ):
            validate_runtime_policy_activation_admission_structure_v1(unsorted)


def test_candidate_digest_fields_cannot_replace_missing_typed_receipt_joins(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, _, _ = _candidate(supervisor)
        assert candidate.transport_capability_receipt_sha256 == (
            activation_support.TRANSPORT_SHA
        )
        assert candidate.writer_quiescence_receipt_sha256 == (
            activation_support.QUIESCENCE_SHA
        )
        result = derive_runtime_policy_activation_admission_v1(
            supervisor._state,
            candidate,
            readiness,
        )
        assert "transport_capability_receipt_join_unavailable" in result.blockers
        assert "writer_quiescence_receipt_join_unavailable" in result.blockers
        assert result.candidate_disposition == "blocked"
