"""Unregistered runtime-policy activation candidate bytes.

This module defines the future append-once activation payload, but it does not
register, publish, persist, or activate that payload.  Its derivation inputs
are caller supplied.  Only the state-bound admission module may compare these
bytes with an exact current company head, and even that result has no runtime
effect until a later reducer/Supervisor tranche is accepted.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import re
from typing import Any, NamedTuple, Never, cast

from .contracts import (
    AUTHORITY_GRANT_V1,
    MAX_LIST_ITEMS,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_authority_grant,
)
from .runtime_policy import (
    RUNTIME_POLICY_ID,
    RUNTIME_POLICY_V2_REVISION,
    RuntimePolicyDefinitionV2,
    runtime_policy_definition_v2,
    validate_runtime_policy_definition_v2,
)
from .runtime_policy_readiness import (
    LEGACY_ACTIVE_CARRIER_LIMIT,
    LEGACY_DELEGATION_DEPTH_LIMIT,
    RUNTIME_POLICY_READINESS_DERIVATION_V1,
    RUNTIME_POLICY_READINESS_OBSERVATION_V1,
    RuntimePolicyChiefCoverageV1,
    RuntimePolicyDepthObservationV1,
    RuntimePolicyHoldV1,
    RuntimePolicyReadinessObservationV1,
    RuntimePolicySourceWitnessV1,
    RuntimePolicySubordinateSlotV1,
)


RUNTIME_POLICY_ACTIVATION_V1 = "runtime_policy_activation_v1"
RUNTIME_POLICY_ACTIVATION_ID = "company-runtime-policy-activation"

_ZERO_SHA256 = "0" * 64
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_ACTIVATION_DOMAIN = "aoi.company.runtime-policy-activation.v1"
_ACTIVATION_SCOPE_DOMAIN = "aoi.company.runtime-policy-activation-scope.v1"
_READINESS_REPORT_DOMAIN = "aoi.company.runtime-policy-readiness-observation.v1"
_READINESS_WITNESS_DOMAIN = "aoi.company.runtime-policy-readiness-witness.v1"
_ACTIVATION_MODE = "enforce_new_acquisitions_preserve_legacy_history"
_STANDALONE_STATE = "candidate_unregistered"
_AUTHORITY_SEMANTICS = (
    "candidate_bytes_require_owner_replay_and_registered_reducer_admission"
)
_OPERATIONAL_EFFECT = "none"


class RuntimePolicyActivationError(CompanyContractError):
    """An activation candidate is malformed, ambiguous, or cross-bound."""


class RuntimePolicyActivationV1(NamedTuple):
    """One immutable, unregistered activation candidate with no authority."""

    contract_type: str
    schema_version: int
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    activation_id: str
    policy_id: str
    policy_revision: int
    policy_definition_sha256: str
    pre_activation_cursor: int
    pre_activation_head_sha256: str
    readiness_observation_sha256: str
    readiness_source_witness_sha256: str
    policy_change_grant_id: str
    policy_change_grant_sha256: str
    policy_change_grant_event_id: str
    policy_change_grant_global_sequence: int
    policy_change_grant_payload_sha256: str
    policy_change_scope_sha256: str
    grant_issuer_authority_record_sha256: str
    activating_chief_id: str
    activating_chief_carrier_id: str
    activating_chief_term: int
    activating_chief_epoch: int
    pre_activation_checkpoint_id: str
    pre_activation_checkpoint_manifest_sha256: str
    transport_capability_receipt_sha256: str
    writer_quiescence_receipt_sha256: str
    requested_activation_at: str
    activation_mode: str
    standalone_state: str
    authority_semantics: str
    operational_effect: str
    activation_sha256: str

    def to_dict(self) -> dict[str, object]:
        return _activation_dict(self)


def _fail(message: str) -> Never:
    raise RuntimePolicyActivationError(message)


def _exact_text(value: object, label: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(f"{label} is invalid")
    text = value
    try:
        if len(text.encode("utf-8")) > maximum:
            _fail(f"{label} is too large")
    except UnicodeEncodeError as exc:
        raise RuntimePolicyActivationError(f"{label} is invalid Unicode") from exc
    return text


def _exact_id(value: object, label: str) -> str:
    text = _exact_text(value, label, maximum=128)
    if not _SAFE_ID.fullmatch(text):
        _fail(f"{label} is not a safe canonical identifier")
    return text


def _exact_digest(value: object, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _exact_int(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 999_999_999_999,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _exact_timestamp(value: object, label: str) -> tuple[str, datetime]:
    text = _exact_text(value, label, maximum=64)
    if not _TIMESTAMP.fullmatch(text):
        _fail(f"{label} is not an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
    except ValueError as exc:
        raise RuntimePolicyActivationError(f"{label} is not a real timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"{label} requires a timezone")
    return text, parsed


def _wire(value: object) -> object:
    if type(value) in {
        RuntimePolicyActivationV1,
        RuntimePolicyChiefCoverageV1,
        RuntimePolicyDepthObservationV1,
        RuntimePolicyHoldV1,
        RuntimePolicyReadinessObservationV1,
        RuntimePolicySourceWitnessV1,
        RuntimePolicySubordinateSlotV1,
    }:
        item = cast(tuple[object, ...], value)
        fields = cast(Any, type(value))._fields
        if tuple.__len__(item) != len(fields):
            _fail("runtime-policy activation nested value shape is invalid")
        return {field: _wire(member) for field, member in zip(fields, item)}
    if type(value) is tuple:
        members = cast(tuple[object, ...], value)
        if len(members) > MAX_LIST_ITEMS:
            _fail("runtime-policy activation nested collection exceeds bounded limits")
        return [_wire(member) for member in members]
    if value is None or type(value) in {int, str}:
        return value
    _fail("runtime-policy activation nested value type is invalid")


def _hash(value: object, *, domain: str) -> str:
    try:
        return hashlib.sha256(canonical_company_json_bytes({
            "derivation_domain": domain,
            "value": value,
        })).hexdigest()
    except CompanyContractError as exc:
        raise RuntimePolicyActivationError(
            "runtime-policy activation canonicalization failed"
        ) from exc


def _activation_plain(value: RuntimePolicyActivationV1) -> dict[str, object]:
    if (
        type(value) is not RuntimePolicyActivationV1
        or tuple.__len__(value) != len(RuntimePolicyActivationV1._fields)
    ):
        _fail("runtime-policy activation must be an exact value object")
    return {field: getattr(value, field) for field in value._fields}


def _activation_digest(value: RuntimePolicyActivationV1) -> str:
    payload = _activation_plain(value)
    payload["activation_sha256"] = _ZERO_SHA256
    return _hash(payload, domain=_ACTIVATION_DOMAIN)


def _activation_dict(value: RuntimePolicyActivationV1) -> dict[str, object]:
    return _activation_plain(validate_runtime_policy_activation_structure_v1(value))


def _canonical_text_tuple(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > MAX_LIST_ITEMS:
        _fail(f"{label} must be a bounded exact tuple")
    items = tuple(
        _exact_text(member, f"{label}[]")
        for member in cast(tuple[object, ...], value)
    )
    if items != tuple(sorted(set(items))):
        _fail(f"{label} is not canonical")
    return items


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _exact_text(value, label)


def _unique_identity(values: tuple[object, ...], keys: tuple[object, ...], label: str) -> None:
    if len(keys) != len(values) or len(set(keys)) != len(keys):
        _fail(f"{label} contains duplicate identity")


def _readiness_payload(value: RuntimePolicyReadinessObservationV1) -> dict[str, object]:
    if (
        type(value) is not RuntimePolicyReadinessObservationV1
        or tuple.__len__(value) != len(RuntimePolicyReadinessObservationV1._fields)
    ):
        _fail("readiness observation must be the exact public value object")
    for field in (
        "schema_version", "company_incarnation", "lock_domain_generation",
        "cursor", "legacy_active_carrier_limit",
        "legacy_delegation_depth_limit", "candidate_subordinate_carrier_limit",
        "candidate_current_admitted_max_depth", "subordinate_occupied_lower_bound",
    ):
        _exact_int(getattr(value, field), f"readiness.{field}")
    for field in (
        "document_type", "derivation_algorithm", "company_id", "head_sha256",
        "currentness_semantics", "policy_definition_sha256", "activation_state",
        "admission_state", "operational_effect", "current_chief_state",
        "writer_quiescence_state", "transport_capability_state",
        "subordinate_capacity_quality", "source_witness_sha256",
        "observation_sha256",
    ):
        _exact_text(getattr(value, field), f"readiness.{field}", maximum=512)
    collections = (
        ("current_chief", RuntimePolicyChiefCoverageV1),
        ("retiring_candidates", RuntimePolicyChiefCoverageV1),
        ("subordinate_slots", RuntimePolicySubordinateSlotV1),
        ("holds", RuntimePolicyHoldV1),
        ("over_depth", RuntimePolicyDepthObservationV1),
        ("source_witnesses", RuntimePolicySourceWitnessV1),
    )
    for field, expected_type in collections:
        members = getattr(value, field)
        if type(members) is not tuple or len(members) > MAX_LIST_ITEMS:
            _fail(f"readiness.{field} must be a bounded exact tuple")
        if any(type(item) is not expected_type for item in members):
            _fail(f"readiness.{field} member type is invalid")
    if type(value.blockers) is not tuple or len(value.blockers) > MAX_LIST_ITEMS:
        _fail("readiness.blockers must be a bounded exact tuple")

    chief_values = value.current_chief + value.retiring_candidates
    for index, chief in enumerate(chief_values):
        prefix = f"readiness.chief[{index}]"
        _optional_text(chief.actor_id, f"{prefix}.actor_id")
        _optional_text(chief.carrier_id, f"{prefix}.carrier_id")
        _optional_text(chief.physical_slot_id, f"{prefix}.physical_slot_id")
        _canonical_text_tuple(chief.execution_ids, f"{prefix}.execution_ids")
        _canonical_text_tuple(chief.runtime_statuses, f"{prefix}.runtime_statuses")
        _exact_text(chief.coverage_state, f"{prefix}.coverage_state")
        _canonical_text_tuple(chief.reason_codes, f"{prefix}.reason_codes")
    _unique_identity(
        cast(tuple[object, ...], chief_values),
        tuple(
            (item.actor_id, item.carrier_id, item.physical_slot_id, item.execution_ids)
            for item in chief_values
        ),
        "readiness Chief observations",
    )

    all_holder_ids: list[str] = []
    for index, slot in enumerate(value.subordinate_slots):
        prefix = f"readiness.subordinate_slots[{index}]"
        _exact_text(slot.physical_slot_id, f"{prefix}.physical_slot_id")
        holders = _canonical_text_tuple(
            slot.holder_execution_ids, f"{prefix}.holder_execution_ids",
        )
        if not holders:
            _fail(f"{prefix}.holder_execution_ids is empty")
        all_holder_ids.extend(holders)
        _exact_text(slot.department_id, f"{prefix}.department_id")
        _exact_text(slot.role_class, f"{prefix}.role_class")
        _exact_int(slot.delegation_depth, f"{prefix}.delegation_depth", minimum=1, maximum=3)
        if slot.observation_quality != "known_physical_provider_session":
            _fail(f"{prefix}.observation_quality is invalid")
    _unique_identity(
        cast(tuple[object, ...], value.subordinate_slots),
        tuple(item.physical_slot_id for item in value.subordinate_slots),
        "readiness subordinate slots",
    )
    if len(set(all_holder_ids)) != len(all_holder_ids):
        _fail("readiness subordinate holder identity is duplicated")

    for index, hold in enumerate(value.holds):
        prefix = f"readiness.holds[{index}]"
        _exact_text(hold.hold_kind, f"{prefix}.hold_kind")
        _exact_text(hold.holder_id, f"{prefix}.holder_id")
        _canonical_text_tuple(hold.reason_codes, f"{prefix}.reason_codes")
    _unique_identity(
        cast(tuple[object, ...], value.holds),
        tuple((item.hold_kind, item.holder_id) for item in value.holds),
        "readiness holds",
    )

    for index, depth in enumerate(value.over_depth):
        prefix = f"readiness.over_depth[{index}]"
        _exact_text(depth.execution_id, f"{prefix}.execution_id")
        _exact_int(depth.raw_depth, f"{prefix}.raw_depth", maximum=999_999)
        _exact_text(depth.role, f"{prefix}.role")
        _optional_text(depth.department_id, f"{prefix}.department_id")
        _exact_text(depth.engineering_status, f"{prefix}.engineering_status")
        _exact_text(depth.runtime_status, f"{prefix}.runtime_status")
        _exact_text(depth.lifecycle_class, f"{prefix}.lifecycle_class")
    _unique_identity(
        cast(tuple[object, ...], value.over_depth),
        tuple(item.execution_id for item in value.over_depth),
        "readiness over-depth observations",
    )

    for index, witness in enumerate(value.source_witnesses):
        prefix = f"readiness.source_witnesses[{index}]"
        for field in (
            "source_kind", "contract_type", "object_key", "record_id", "event_id",
        ):
            _exact_text(getattr(witness, field), f"{prefix}.{field}")
        _exact_int(witness.global_sequence, f"{prefix}.global_sequence", minimum=1)
        _exact_digest(witness.payload_sha256, f"{prefix}.payload_sha256")
    _unique_identity(
        cast(tuple[object, ...], value.source_witnesses),
        tuple(
            (
                item.source_kind, item.contract_type, item.object_key,
                item.record_id, item.event_id, item.global_sequence,
            )
            for item in value.source_witnesses
        ),
        "readiness source witnesses",
    )
    for members, label in (
        (value.subordinate_slots, "readiness.subordinate_slots"),
        (value.holds, "readiness.holds"),
        (value.over_depth, "readiness.over_depth"),
        (value.source_witnesses, "readiness.source_witnesses"),
    ):
        if members != tuple(sorted(members)):
            _fail(f"{label} is not canonically ordered")
    if (
        any(type(item) is not str for item in value.blockers)
        or value.blockers != tuple(sorted(set(value.blockers)))
    ):
        _fail("readiness blockers are not canonical")
    if (
        value.document_type != RUNTIME_POLICY_READINESS_OBSERVATION_V1
        or value.derivation_algorithm != RUNTIME_POLICY_READINESS_DERIVATION_V1
        or value.currentness_semantics != "current_as_of_exact_verified_head"
        or value.activation_state != "inactive"
        or value.admission_state != "unavailable"
        or value.operational_effect != "none"
        or value.legacy_active_carrier_limit != LEGACY_ACTIVE_CARRIER_LIMIT
        or value.legacy_delegation_depth_limit != LEGACY_DELEGATION_DEPTH_LIMIT
        or value.writer_quiescence_state != "unavailable"
        or value.transport_capability_state != "unavailable"
    ):
        _fail("readiness observation is not a writer-off pre-activation observation")
    if len(value.current_chief) != 1:
        _fail("readiness observation lacks one exact current Chief candidate")
    if value.subordinate_occupied_lower_bound != len(value.subordinate_slots):
        _fail("readiness subordinate occupied lower bound is inconsistent")
    expected_quality = (
        "known_lower_bound_with_unattributed_holds"
        if any(item.hold_kind.startswith("unattributed") for item in value.holds)
        else "known_lower_bound"
    )
    if value.subordinate_capacity_quality != expected_quality:
        _fail("readiness subordinate capacity quality is inconsistent")
    for field in (
        "head_sha256", "policy_definition_sha256", "source_witness_sha256",
        "observation_sha256",
    ):
        _exact_digest(getattr(value, field), f"readiness.{field}")
    payload = cast(dict[str, object], _wire(value))
    witness_payload = {
        "derivation_domain": _READINESS_WITNESS_DOMAIN,
        "company": [
            value.company_id,
            value.company_incarnation,
            value.lock_domain_generation,
        ],
        "cursor": value.cursor,
        "head_sha256": value.head_sha256,
        "policy_definition_sha256": value.policy_definition_sha256,
        "witnesses": [_wire(item) for item in value.source_witnesses],
    }
    if value.source_witness_sha256 != company_contract_sha256(witness_payload):
        _fail("readiness source witness digest differs")
    digest_payload = dict(payload)
    digest_payload["observation_sha256"] = _ZERO_SHA256
    expected = hashlib.sha256(canonical_company_json_bytes({
        "derivation_domain": _READINESS_REPORT_DOMAIN,
        "observation": digest_payload,
    })).hexdigest()
    if value.observation_sha256 != expected:
        _fail("readiness observation digest differs")
    canonical_company_json_bytes(payload)
    return payload


def runtime_policy_activation_scope_sha256_v1(
    *,
    company_id: object,
    company_incarnation: object,
    lock_domain_generation: object,
    definition: object | None = None,
) -> str:
    """Bind the singleton activation scope without implying grant authority."""

    policy = validate_runtime_policy_definition_v2(
        runtime_policy_definition_v2() if definition is None else definition
    )
    return _hash({
        "company_id": _exact_id(company_id, "company_id"),
        "company_incarnation": _exact_int(
            company_incarnation, "company_incarnation", minimum=1,
        ),
        "lock_domain_generation": _exact_int(
            lock_domain_generation, "lock_domain_generation", minimum=1,
        ),
        "activation_id": RUNTIME_POLICY_ACTIVATION_ID,
        "policy_id": policy.policy_id,
        "policy_revision": policy.policy_revision,
        "policy_definition_sha256": policy.definition_sha256,
    }, domain=_ACTIVATION_SCOPE_DOMAIN)


def _validated_grant(value: object) -> dict[str, Any]:
    try:
        grant = validate_authority_grant(value)
    except CompanyContractError as exc:
        raise RuntimePolicyActivationError("policy-change grant is invalid") from exc
    for field in (
        "contract_type", "company_id", "grant_id", "actor_id", "actor_kind",
        "carrier_id", "authority_state", "scope_sha256", "issued_at",
        "expires_at", "provenance", "grant_sha256",
    ):
        if type(grant.get(field)) is not str:
            _fail(f"policy-change grant.{field} has an invalid exact type")
    for field in (
        "schema_version", "company_incarnation", "lock_domain_generation",
        "chief_epoch", "term",
    ):
        if type(grant.get(field)) is not int:
            _fail(f"policy-change grant.{field} has an invalid exact type")
    if type(grant.get("permissions")) is not list or any(
        type(item) is not str for item in cast(list[object], grant["permissions"])
    ):
        _fail("policy-change grant.permissions has an invalid exact type")
    return grant


def derive_runtime_policy_activation_v1(
    readiness: object,
    policy_change_grant: object,
    *,
    grant_issuer_authority_record_sha256: object,
    pre_activation_checkpoint_id: object,
    pre_activation_checkpoint_manifest_sha256: object,
    transport_capability_receipt_sha256: object,
    writer_quiescence_receipt_sha256: object,
    requested_activation_at: object,
    definition: object | None = None,
) -> RuntimePolicyActivationV1:
    """Derive candidate bytes from caller inputs; never authorize activation."""

    policy = validate_runtime_policy_definition_v2(
        runtime_policy_definition_v2() if definition is None else definition
    )
    if type(policy) is not RuntimePolicyDefinitionV2:
        _fail("runtime-policy definition type is invalid")
    if type(readiness) is not RuntimePolicyReadinessObservationV1:
        _fail("readiness observation type is invalid")
    observation = readiness
    _readiness_payload(observation)
    if observation.policy_definition_sha256 != policy.definition_sha256:
        _fail("readiness does not bind the exact policy definition")
    if (
        observation.candidate_subordinate_carrier_limit
        != policy.subordinate_carrier_limit
        or observation.candidate_current_admitted_max_depth
        != policy.current_admitted_max_depth
    ):
        _fail("readiness candidate limits differ from policy definition")

    grant = _validated_grant(policy_change_grant)
    company = (
        observation.company_id,
        observation.company_incarnation,
        observation.lock_domain_generation,
    )
    if (
        grant["contract_type"] != AUTHORITY_GRANT_V1
        or (
            grant["company_id"], grant["company_incarnation"],
            grant["lock_domain_generation"],
        ) != company
        or grant["actor_kind"] != "chief"
        or grant["authority_state"] != "active"
        or grant["permissions"] != ["policy.change"]
        or grant["provenance"] != "AOI_verified"
    ):
        _fail("policy-change grant does not bind an exact active Chief grant")
    scope = runtime_policy_activation_scope_sha256_v1(
        company_id=company[0],
        company_incarnation=company[1],
        lock_domain_generation=company[2],
        definition=policy,
    )
    if grant["scope_sha256"] != scope:
        _fail("policy-change grant scope differs from activation scope")
    chief = observation.current_chief[0]
    if (
        observation.current_chief_state != "exact_identity_carrier_observed"
        or chief.coverage_state != "exact_identity_carrier_observed"
        or type(chief.actor_id) is not str
        or type(chief.carrier_id) is not str
        or grant["actor_id"] != chief.actor_id
        or grant["carrier_id"] != chief.carrier_id
    ):
        _fail("policy-change grant differs from the observed current Chief")
    requested_text, requested = _exact_timestamp(
        requested_activation_at, "requested_activation_at",
    )
    _, issued = _exact_timestamp(grant["issued_at"], "grant.issued_at")
    _, expires = _exact_timestamp(grant["expires_at"], "grant.expires_at")
    if not issued <= requested < expires:
        _fail("requested activation is outside the policy-change grant window")

    grant_payload_sha256 = company_contract_sha256(grant)
    witnesses = tuple(
        item for item in observation.source_witnesses
        if (
            item.contract_type == AUTHORITY_GRANT_V1
            and item.object_key == grant["grant_id"]
            and item.payload_sha256 == grant_payload_sha256
        )
    )
    if len(witnesses) != 1:
        _fail("readiness lacks one exact policy-change grant witness")
    witness = witnesses[0]
    if witness.global_sequence > observation.cursor:
        _fail("policy-change grant witness is beyond the readiness cursor")

    provisional = RuntimePolicyActivationV1(
        contract_type=RUNTIME_POLICY_ACTIVATION_V1,
        schema_version=1,
        company_id=_exact_id(company[0], "company_id"),
        company_incarnation=_exact_int(
            company[1], "company_incarnation", minimum=1,
        ),
        lock_domain_generation=_exact_int(
            company[2], "lock_domain_generation", minimum=1,
        ),
        activation_id=RUNTIME_POLICY_ACTIVATION_ID,
        policy_id=RUNTIME_POLICY_ID,
        policy_revision=RUNTIME_POLICY_V2_REVISION,
        policy_definition_sha256=policy.definition_sha256,
        pre_activation_cursor=observation.cursor,
        pre_activation_head_sha256=_exact_digest(
            observation.head_sha256, "readiness.head_sha256",
        ),
        readiness_observation_sha256=_exact_digest(
            observation.observation_sha256, "readiness.observation_sha256",
        ),
        readiness_source_witness_sha256=_exact_digest(
            observation.source_witness_sha256,
            "readiness.source_witness_sha256",
        ),
        policy_change_grant_id=_exact_id(grant["grant_id"], "grant.grant_id"),
        policy_change_grant_sha256=_exact_digest(
            grant["grant_sha256"], "grant.grant_sha256",
        ),
        policy_change_grant_event_id=_exact_id(
            witness.event_id, "grant_witness.event_id",
        ),
        policy_change_grant_global_sequence=_exact_int(
            witness.global_sequence, "grant_witness.global_sequence", minimum=1,
        ),
        policy_change_grant_payload_sha256=_exact_digest(
            witness.payload_sha256, "grant_witness.payload_sha256",
        ),
        policy_change_scope_sha256=scope,
        grant_issuer_authority_record_sha256=_exact_digest(
            grant_issuer_authority_record_sha256,
            "grant_issuer_authority_record_sha256",
        ),
        activating_chief_id=_exact_id(grant["actor_id"], "grant.actor_id"),
        activating_chief_carrier_id=_exact_id(
            grant["carrier_id"], "grant.carrier_id",
        ),
        activating_chief_term=_exact_int(
            grant["term"], "grant.term", minimum=1,
        ),
        activating_chief_epoch=_exact_int(
            grant["chief_epoch"], "grant.chief_epoch", minimum=1,
        ),
        pre_activation_checkpoint_id=_exact_id(
            pre_activation_checkpoint_id, "pre_activation_checkpoint_id",
        ),
        pre_activation_checkpoint_manifest_sha256=_exact_digest(
            pre_activation_checkpoint_manifest_sha256,
            "pre_activation_checkpoint_manifest_sha256",
        ),
        transport_capability_receipt_sha256=_exact_digest(
            transport_capability_receipt_sha256,
            "transport_capability_receipt_sha256",
        ),
        writer_quiescence_receipt_sha256=_exact_digest(
            writer_quiescence_receipt_sha256,
            "writer_quiescence_receipt_sha256",
        ),
        requested_activation_at=requested_text,
        activation_mode=_ACTIVATION_MODE,
        standalone_state=_STANDALONE_STATE,
        authority_semantics=_AUTHORITY_SEMANTICS,
        operational_effect=_OPERATIONAL_EFFECT,
        activation_sha256=_ZERO_SHA256,
    )
    result = provisional._replace(activation_sha256=_activation_digest(provisional))
    canonical_company_json_bytes(_activation_plain(result))
    return result


def validate_runtime_policy_activation_structure_v1(
    value: object,
) -> RuntimePolicyActivationV1:
    """Validate local bytes only; this does not prove durability or currentness."""

    try:
        if type(value) is RuntimePolicyActivationV1:
            raw = _activation_plain(value)
        elif type(value) is dict and set(cast(dict[object, object], value)) == set(
            RuntimePolicyActivationV1._fields
        ):
            raw = cast(dict[str, object], dict(cast(dict[object, object], value)))
        else:
            _fail("runtime-policy activation schema is invalid")
        fixed = {
            "contract_type": RUNTIME_POLICY_ACTIVATION_V1,
            "activation_id": RUNTIME_POLICY_ACTIVATION_ID,
            "policy_id": RUNTIME_POLICY_ID,
            "activation_mode": _ACTIVATION_MODE,
            "standalone_state": _STANDALONE_STATE,
            "authority_semantics": _AUTHORITY_SEMANTICS,
            "operational_effect": _OPERATIONAL_EFFECT,
        }
        for field, expected in fixed.items():
            if _exact_text(raw[field], field, maximum=512) != expected:
                _fail(f"{field} differs from the fixed activation contract")
        integers = {
            "schema_version": (1, 1),
            "company_incarnation": (1, 999_999_999),
            "lock_domain_generation": (1, 999_999_999),
            "policy_revision": (RUNTIME_POLICY_V2_REVISION, RUNTIME_POLICY_V2_REVISION),
            "pre_activation_cursor": (1, 999_999_999_999),
            "policy_change_grant_global_sequence": (1, 999_999_999_999),
            "activating_chief_term": (1, 999_999_999),
            "activating_chief_epoch": (1, 999_999_999),
        }
        for field, (minimum, maximum) in integers.items():
            _exact_int(raw[field], field, minimum=minimum, maximum=maximum)
        for field in (
            "company_id", "policy_change_grant_id", "policy_change_grant_event_id",
            "activating_chief_id", "activating_chief_carrier_id",
            "pre_activation_checkpoint_id",
        ):
            _exact_id(raw[field], field)
        for field in (
            "policy_definition_sha256", "pre_activation_head_sha256",
            "readiness_observation_sha256", "readiness_source_witness_sha256",
            "policy_change_grant_sha256", "policy_change_grant_payload_sha256",
            "policy_change_scope_sha256", "grant_issuer_authority_record_sha256",
            "pre_activation_checkpoint_manifest_sha256",
            "transport_capability_receipt_sha256",
            "writer_quiescence_receipt_sha256", "activation_sha256",
        ):
            _exact_digest(raw[field], field)
        _exact_timestamp(raw["requested_activation_at"], "requested_activation_at")
        candidate = RuntimePolicyActivationV1(**cast(Any, raw))
        if candidate.policy_change_grant_global_sequence > candidate.pre_activation_cursor:
            _fail("policy-change grant is not prior to the pre-activation cursor")
        if candidate.activation_sha256 != _activation_digest(candidate):
            _fail("activation_sha256 differs from canonical candidate bytes")
        canonical_company_json_bytes(_activation_plain(candidate))
        return candidate
    except RuntimePolicyActivationError:
        raise
    except MemoryError:
        raise
    except (
        AttributeError, CompanyContractError, KeyError, OSError,
        RecursionError, TypeError, ValueError,
    ) as exc:
        raise RuntimePolicyActivationError(
            "runtime-policy activation structure is invalid"
        ) from exc


def validate_runtime_policy_activation_v1(
    value: object,
    readiness: object,
    policy_change_grant: object,
    **derivation_inputs: object,
) -> RuntimePolicyActivationV1:
    """Re-derive caller-bound candidate bytes without claiming current state."""

    candidate = validate_runtime_policy_activation_structure_v1(value)
    required_inputs = {
        "grant_issuer_authority_record_sha256", "pre_activation_checkpoint_id",
        "pre_activation_checkpoint_manifest_sha256",
        "transport_capability_receipt_sha256", "writer_quiescence_receipt_sha256",
        "requested_activation_at",
    }
    if frozenset(derivation_inputs) not in {frozenset(required_inputs), frozenset({
        *required_inputs, "definition",
    })}:
        _fail("runtime-policy activation derivation inputs are invalid")
    try:
        expected = derive_runtime_policy_activation_v1(
            readiness, policy_change_grant, **derivation_inputs,
        )
    except TypeError as exc:
        raise RuntimePolicyActivationError(
            "runtime-policy activation derivation inputs are invalid"
        ) from exc
    if candidate != expected:
        _fail("runtime-policy activation differs from exact candidate derivation")
    return expected


def canonical_runtime_policy_activation_v1_bytes(value: object) -> bytes:
    """Return canonical candidate bytes; never an activation receipt."""

    return canonical_company_json_bytes(
        validate_runtime_policy_activation_structure_v1(value).to_dict()
    )


__all__ = [
    "RUNTIME_POLICY_ACTIVATION_ID",
    "RUNTIME_POLICY_ACTIVATION_V1",
    "RuntimePolicyActivationError",
    "RuntimePolicyActivationV1",
    "canonical_runtime_policy_activation_v1_bytes",
    "derive_runtime_policy_activation_v1",
    "runtime_policy_activation_scope_sha256_v1",
    "validate_runtime_policy_activation_structure_v1",
    "validate_runtime_policy_activation_v1",
]
