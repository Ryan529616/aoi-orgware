"""Writer-off contract tests for runtime-policy activation candidate bytes."""
from __future__ import annotations

import ast
import copy
import hashlib
import os
from pathlib import Path
import sys
from typing import Any, Mapping, cast

import pytest

from aoi_orgware.company.contract_registry import contract_validator_for
from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.projection_registry import PROJECTABLE_STREAM
from aoi_orgware.company.runtime_policy import runtime_policy_definition_v2
from aoi_orgware.company.runtime_policy_activation import (
    RUNTIME_POLICY_ACTIVATION_ID,
    RUNTIME_POLICY_ACTIVATION_V1,
    RuntimePolicyActivationError,
    RuntimePolicyActivationV1,
    canonical_runtime_policy_activation_v1_bytes,
    derive_runtime_policy_activation_v1,
    runtime_policy_activation_scope_sha256_v1,
    validate_runtime_policy_activation_structure_v1,
    validate_runtime_policy_activation_v1,
)
from aoi_orgware.company.runtime_policy_readiness import (
    RuntimePolicyReadinessObservationV1,
    RuntimePolicySubordinateSlotV1,
    derive_runtime_policy_readiness,
)
from aoi_orgware.company.supervisor import CompanySupervisor


_TEST_DIR = Path(__file__).resolve().parent
if str(_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_TEST_DIR))

import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_write_admission_projection as support  # type: ignore[import-not-found]


ISSUED = "2026-07-27T00:01:00Z"
REQUESTED = "2099-07-27T00:02:00Z"
EXPIRES = "2100-07-28T00:00:00Z"
CHECKPOINT_SHA = "c" * 64
TRANSPORT_SHA = "d" * 64
QUIESCENCE_SHA = "e" * 64


class IntSubclass(int):
    pass


class StrSubclass(str):
    pass


def _initialize(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        lifecycle._manifest(),
        bootstrap_at=lifecycle.T,
        grant_expires_at=lifecycle.EXPIRY,
        known_carrier=lifecycle._known_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(member) for key, member in value.items()}
    if type(value) in {tuple, list}:
        return [_plain(member) for member in value]
    return value


def _named_wire(value: Any) -> Any:
    fields = getattr(type(value), "_fields", None)
    if type(fields) is tuple and type(value).__bases__ == (tuple,):
        return {field: _named_wire(getattr(value, field)) for field in fields}
    if type(value) in {tuple, list}:
        return [_named_wire(member) for member in value]
    return value


def _rehash_activation(
    value: RuntimePolicyActivationV1,
    **changes: object,
) -> RuntimePolicyActivationV1:
    provisional = cast(
        RuntimePolicyActivationV1,
        cast(Any, value)._replace(**changes, activation_sha256="0" * 64),
    )
    digest = hashlib.sha256(canonical_company_json_bytes({
        "derivation_domain": "aoi.company.runtime-policy-activation.v1",
        "value": dict(provisional._asdict()),
    })).hexdigest()
    return provisional._replace(activation_sha256=digest)


def _unchecked_activation_candidate(
    readiness: RuntimePolicyReadinessObservationV1,
    grant: Mapping[str, Any],
    issuer: Mapping[str, Any],
    checkpoint_id: str,
    checkpoint_manifest_sha256: str,
    *,
    requested_at: str = REQUESTED,
) -> RuntimePolicyActivationV1:
    policy = runtime_policy_definition_v2()
    witness = next(
        item for item in readiness.source_witnesses
        if item.object_key == grant["grant_id"]
    )
    chief = readiness.current_chief[0]
    provisional = RuntimePolicyActivationV1(
        contract_type=RUNTIME_POLICY_ACTIVATION_V1,
        schema_version=1,
        company_id=readiness.company_id,
        company_incarnation=readiness.company_incarnation,
        lock_domain_generation=readiness.lock_domain_generation,
        activation_id=RUNTIME_POLICY_ACTIVATION_ID,
        policy_id=policy.policy_id,
        policy_revision=policy.policy_revision,
        policy_definition_sha256=policy.definition_sha256,
        pre_activation_cursor=readiness.cursor,
        pre_activation_head_sha256=readiness.head_sha256,
        readiness_observation_sha256=readiness.observation_sha256,
        readiness_source_witness_sha256=readiness.source_witness_sha256,
        policy_change_grant_id=grant["grant_id"],
        policy_change_grant_sha256=grant["grant_sha256"],
        policy_change_grant_event_id=witness.event_id,
        policy_change_grant_global_sequence=witness.global_sequence,
        policy_change_grant_payload_sha256=witness.payload_sha256,
        policy_change_scope_sha256=runtime_policy_activation_scope_sha256_v1(
            company_id=readiness.company_id,
            company_incarnation=readiness.company_incarnation,
            lock_domain_generation=readiness.lock_domain_generation,
            definition=policy,
        ),
        grant_issuer_authority_record_sha256=issuer["grant_sha256"],
        activating_chief_id=cast(str, chief.actor_id),
        activating_chief_carrier_id=cast(str, chief.carrier_id),
        activating_chief_term=grant["term"],
        activating_chief_epoch=grant["chief_epoch"],
        pre_activation_checkpoint_id=checkpoint_id,
        pre_activation_checkpoint_manifest_sha256=checkpoint_manifest_sha256,
        transport_capability_receipt_sha256=TRANSPORT_SHA,
        writer_quiescence_receipt_sha256=QUIESCENCE_SHA,
        requested_activation_at=requested_at,
        activation_mode="enforce_new_acquisitions_preserve_legacy_history",
        standalone_state="candidate_unregistered",
        authority_semantics=(
            "candidate_bytes_require_owner_replay_and_registered_reducer_admission"
        ),
        operational_effect="none",
        activation_sha256="0" * 64,
    )
    return _rehash_activation(provisional)


def _rehash_readiness(
    value: RuntimePolicyReadinessObservationV1,
    **changes: object,
) -> RuntimePolicyReadinessObservationV1:
    provisional = cast(
        RuntimePolicyReadinessObservationV1,
        cast(Any, value)._replace(**changes, observation_sha256="0" * 64),
    )
    payload = _named_wire(provisional)
    assert type(payload) is dict
    digest = hashlib.sha256(canonical_company_json_bytes({
        "derivation_domain": "aoi.company.runtime-policy-readiness-observation.v1",
        "observation": payload,
    })).hexdigest()
    return provisional._replace(observation_sha256=digest)


def _slot(index: int, *, physical_slot_id: str | None = None) -> RuntimePolicySubordinateSlotV1:
    return RuntimePolicySubordinateSlotV1(
        physical_slot_id=(
            f"provider-session:{index:064x}"
            if physical_slot_id is None else physical_slot_id
        ),
        holder_execution_ids=(f"execution-{index:03d}",),
        department_id="department-rtl",
        role_class="worker",
        delegation_depth=2,
        observation_quality="known_physical_provider_session",
    )


def _chief_grant(supervisor: CompanySupervisor) -> dict[str, Any]:
    matches = [
        _plain(item.payload)
        for item in supervisor.objects(contract_type=AUTHORITY_GRANT_V1)
        if (
            item.payload["actor_kind"] == "chief"
            and item.payload["authority_state"] == "active"
            and item.payload["permissions"] == ("company.mutate",)
        )
    ]
    assert len(matches) == 1
    return cast(dict[str, Any], matches[0])


def _grant(
    supervisor: CompanySupervisor,
    *,
    grant_id: str = "runtime-policy-change-grant-1",
    permission: str = "policy.change",
    scope_sha256: str | None = None,
    actor_grant: Mapping[str, Any] | None = None,
    recorded_at: str = ISSUED,
    subject_actor_id: str | None = None,
    subject_carrier_id: str | None = None,
    provenance: str = "AOI_verified",
) -> tuple[dict[str, Any], dict[str, Any]]:
    chief = _chief_grant(supervisor)
    binding = {
        "company_id": chief["company_id"],
        "company_incarnation": chief["company_incarnation"],
        "lock_domain_generation": chief["lock_domain_generation"],
    }
    policy = runtime_policy_definition_v2()
    unsigned: dict[str, Any] = {
        "contract_type": AUTHORITY_GRANT_V1,
        "schema_version": 1,
        **binding,
        "grant_id": grant_id,
        "actor_id": (
            chief["actor_id"] if subject_actor_id is None else subject_actor_id
        ),
        "actor_kind": "chief",
        "carrier_id": (
            chief["carrier_id"]
            if subject_carrier_id is None else subject_carrier_id
        ),
        "chief_epoch": chief["chief_epoch"],
        "term": chief["term"],
        "authority_state": "active",
        "permissions": [permission],
        "scope_sha256": (
            runtime_policy_activation_scope_sha256_v1(
                **binding,
                definition=policy,
            )
            if scope_sha256 is None else scope_sha256
        ),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "provenance": provenance,
    }
    grant = {**unsigned, "grant_sha256": company_contract_sha256(unsigned)}
    issuer = chief if actor_grant is None else _plain(actor_grant)
    supervisor.commit(
        support._request(
            supervisor,
            [grant],
            transaction_id=f"{grant_id}-transaction",
            command_id=f"{grant_id}-command",
            recorded_at=recorded_at,
            actor_grant=issuer,
        ),
        recorded_at=recorded_at,
    )
    return grant, issuer


def _candidate(
    supervisor: CompanySupervisor,
) -> tuple[RuntimePolicyActivationV1, object, dict[str, Any], dict[str, Any]]:
    grant, issuer = _grant(supervisor)
    readiness = derive_runtime_policy_readiness(supervisor._state)
    result = derive_runtime_policy_activation_v1(
        readiness,
        grant,
        grant_issuer_authority_record_sha256=issuer["grant_sha256"],
        pre_activation_checkpoint_id="pre-activation-checkpoint-1",
        pre_activation_checkpoint_manifest_sha256=CHECKPOINT_SHA,
        transport_capability_receipt_sha256=TRANSPORT_SHA,
        writer_quiescence_receipt_sha256=QUIESCENCE_SHA,
        requested_activation_at=REQUESTED,
    )
    return result, readiness, grant, issuer


def _derive_inputs(issuer: Mapping[str, Any]) -> dict[str, object]:
    return {
        "grant_issuer_authority_record_sha256": issuer["grant_sha256"],
        "pre_activation_checkpoint_id": "pre-activation-checkpoint-1",
        "pre_activation_checkpoint_manifest_sha256": CHECKPOINT_SHA,
        "transport_capability_receipt_sha256": TRANSPORT_SHA,
        "writer_quiescence_receipt_sha256": QUIESCENCE_SHA,
        "requested_activation_at": REQUESTED,
    }


def test_candidate_round_trip_is_deterministic_and_explicitly_writer_off(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, grant, issuer = _candidate(supervisor)
        assert candidate.activation_id == RUNTIME_POLICY_ACTIVATION_ID
        assert candidate.standalone_state == "candidate_unregistered"
        assert candidate.operational_effect == "none"
        assert candidate.authority_semantics.endswith("registered_reducer_admission")
        assert validate_runtime_policy_activation_structure_v1(candidate) == candidate
        assert validate_runtime_policy_activation_v1(
            candidate,
            readiness,
            grant,
            **_derive_inputs(issuer),
        ) == candidate
        raw = canonical_runtime_policy_activation_v1_bytes(candidate)
        assert raw == canonical_runtime_policy_activation_v1_bytes(candidate.to_dict())
        assert derive_runtime_policy_activation_v1(
            readiness,
            grant,
            **_derive_inputs(issuer),
        ) == candidate


@pytest.mark.parametrize(
    "field",
    [
        "schema_version", "company_incarnation", "lock_domain_generation",
        "policy_revision", "pre_activation_cursor",
        "policy_change_grant_global_sequence", "activating_chief_term",
        "activating_chief_epoch",
    ],
)
@pytest.mark.parametrize("bad", [True, IntSubclass(1)])
def test_candidate_rejects_bool_and_integer_subclasses(
    tmp_path: Path,
    field: str,
    bad: object,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, _, _, _ = _candidate(supervisor)
        with pytest.raises(RuntimePolicyActivationError):
            validate_runtime_policy_activation_structure_v1(
                cast(Any, candidate)._replace(**{field: bad})
            )


@pytest.mark.parametrize(
    "field",
    [
        "company_id", "activation_id", "policy_change_grant_id",
        "policy_change_grant_event_id", "activating_chief_id",
        "activating_chief_carrier_id", "pre_activation_checkpoint_id",
        "policy_definition_sha256", "activation_sha256",
    ],
)
def test_candidate_rejects_string_subclasses(
    tmp_path: Path,
    field: str,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, _, _, _ = _candidate(supervisor)
        with pytest.raises(RuntimePolicyActivationError):
            validate_runtime_policy_activation_structure_v1(
                cast(Any, candidate)._replace(
                    **{field: StrSubclass(getattr(candidate, field))}
                )
            )


def test_candidate_digest_and_schema_tamper_fail_closed(tmp_path: Path) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, _, _, _ = _candidate(supervisor)
        with pytest.raises(RuntimePolicyActivationError, match="activation_sha256"):
            validate_runtime_policy_activation_structure_v1(
                candidate._replace(pre_activation_head_sha256="f" * 64)
            )
        raw = candidate.to_dict()
        raw["extra"] = "forbidden"
        with pytest.raises(RuntimePolicyActivationError, match="schema"):
            validate_runtime_policy_activation_structure_v1(raw)
        raw = candidate.to_dict()
        raw.pop("activation_id")
        with pytest.raises(RuntimePolicyActivationError, match="schema"):
            validate_runtime_policy_activation_structure_v1(raw)
        with pytest.raises(RuntimePolicyActivationError):
            validate_runtime_policy_activation_structure_v1([candidate.to_dict()])


def test_semantic_validator_contains_missing_and_unknown_derivation_keys(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, readiness, grant, issuer = _candidate(supervisor)
        missing = _derive_inputs(issuer)
        missing.pop("requested_activation_at")
        unknown = {**_derive_inputs(issuer), "unexpected_argument": "value"}
        for inputs in (missing, unknown):
            with pytest.raises(
                RuntimePolicyActivationError,
                match="derivation inputs",
            ):
                validate_runtime_policy_activation_v1(
                    candidate,
                    readiness,
                    grant,
                    **inputs,
                )


def test_candidate_requires_exact_policy_change_grant_semantics(tmp_path: Path) -> None:
    with _initialize(tmp_path) as supervisor:
        grant, issuer = _grant(supervisor, permission="release.publish")
        readiness = derive_runtime_policy_readiness(supervisor._state)
        with pytest.raises(RuntimePolicyActivationError, match="active Chief grant"):
            derive_runtime_policy_activation_v1(
                readiness,
                grant,
                **_derive_inputs(issuer),
            )


def test_candidate_requires_scope_time_chief_and_exact_readiness_witness(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        grant, issuer = _grant(supervisor)
        readiness = derive_runtime_policy_readiness(supervisor._state)
        bad_scope = copy.deepcopy(grant)
        bad_scope["scope_sha256"] = "f" * 64
        unsigned = {key: value for key, value in bad_scope.items() if key != "grant_sha256"}
        bad_scope["grant_sha256"] = company_contract_sha256(unsigned)
        with pytest.raises(RuntimePolicyActivationError, match="scope"):
            derive_runtime_policy_activation_v1(
                readiness,
                bad_scope,
                **_derive_inputs(issuer),
            )
        inputs = _derive_inputs(issuer)
        inputs["requested_activation_at"] = EXPIRES
        with pytest.raises(RuntimePolicyActivationError, match="window"):
            derive_runtime_policy_activation_v1(readiness, grant, **inputs)
        with pytest.raises(RuntimePolicyActivationError):
            derive_runtime_policy_activation_v1(
                readiness._replace(current_chief_state="exact_identity_carrier_unavailable"),
                grant,
                **_derive_inputs(issuer),
            )
        witness = readiness.source_witnesses[-1]
        malformed = readiness._replace(
            source_witnesses=readiness.source_witnesses[:-1] + (
                witness._replace(payload_sha256="f" * 64),
            )
        )
        with pytest.raises(RuntimePolicyActivationError):
            derive_runtime_policy_activation_v1(
                malformed,
                grant,
                **_derive_inputs(issuer),
            )


@pytest.mark.parametrize("forgery", ["oversized", "bool_depth", "duplicate_slot"])
def test_candidate_rejects_forged_nested_readiness_collections(
    tmp_path: Path,
    forgery: str,
) -> None:
    with _initialize(tmp_path) as supervisor:
        grant, issuer = _grant(supervisor)
        readiness = derive_runtime_policy_readiness(supervisor._state)
        if forgery == "oversized":
            slots = tuple(_slot(index) for index in range(257))
        elif forgery == "bool_depth":
            slots = (_slot(1)._replace(delegation_depth=cast(Any, True)),)
        else:
            slots = (
                _slot(1, physical_slot_id="provider-session:" + "a" * 64),
                _slot(2, physical_slot_id="provider-session:" + "a" * 64),
            )
        forged = _rehash_readiness(
            readiness,
            subordinate_slots=slots,
            subordinate_occupied_lower_bound=len(slots),
        )
        with pytest.raises(RuntimePolicyActivationError):
            derive_runtime_policy_activation_v1(
                forged,
                grant,
                **_derive_inputs(issuer),
            )


def test_candidate_remains_unregistered_and_generic_commit_is_zero_append(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        candidate, _, _, _ = _candidate(supervisor)
        assert contract_validator_for(RUNTIME_POLICY_ACTIVATION_V1, None, None) is None
        assert RUNTIME_POLICY_ACTIVATION_V1 not in PROJECTABLE_STREAM
        before = supervisor.heads()
        with pytest.raises(CompanyContractError, match="unsupported"):
            supervisor.commit(
                support._request(
                    supervisor,
                    [candidate.to_dict()],
                    transaction_id="activation-candidate-transaction",
                    command_id="activation-candidate-command",
                    recorded_at=REQUESTED,
                    actor_grant=_chief_grant(supervisor),
                ),
                recorded_at=REQUESTED,
            )
        assert supervisor.heads() == before


def _direct_imports(source: str) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            result.add("." * node.level + (node.module or ""))
    return result


def test_activation_contract_has_no_production_wiring() -> None:
    root = Path(__file__).parents[2]
    source = (
        root / "src" / "aoi_orgware" / "company" / "runtime_policy_activation.py"
    ).read_text(encoding="utf-8")
    assert _direct_imports(source) == {
        "__future__", "datetime", "hashlib", "re", "typing",
        ".contracts", ".runtime_policy", ".runtime_policy_readiness",
    }
    for name in (
        "contract_registry.py", "projection_registry.py", "invariants.py",
        "state.py", "supervisor.py", "views.py", "__init__.py",
    ):
        text = (
            root / "src" / "aoi_orgware" / "company" / name
        ).read_text(encoding="utf-8")
        assert "runtime_policy_activation" not in text
    dispatch = (root / "src" / "aoi_orgware" / "dispatch_protocol.py").read_text(
        encoding="utf-8"
    )
    assert "runtime_policy_activation" not in dispatch
