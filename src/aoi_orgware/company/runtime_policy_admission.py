"""Owner-replayed, writer-off admission at one exact company head."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any, NamedTuple, Never, cast

from .contracts import (
    AUTHORITY_GRANT_V1,
    CHIEF_TERM_V1,
    CompanyContractError,
    authority_from_grant,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_actor_authority,
    validate_authority_grant,
)
from .runtime_policy import runtime_policy_definition_v2
from .runtime_policy_activation import (
    RuntimePolicyActivationV1,
    runtime_policy_activation_scope_sha256_v1,
    validate_runtime_policy_activation_structure_v1,
)
from .runtime_policy_readiness import (
    RuntimePolicyReadinessObservationV1,
    validate_runtime_policy_readiness_observation,
)
from .runtime_policy_readiness_state import (
    RuntimePolicyReadinessStateError,
    plain_projected_payload,
    verified_runtime_policy_context,
)
from .state import CompanyStateOwner


RUNTIME_POLICY_ACTIVATION_ADMISSION_V1 = "runtime_policy_activation_admission_v1"
_ZERO_SHA256 = "0" * 64
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ADMISSION_DOMAIN = "aoi.company.runtime-policy-activation-admission.v1"
_CURRENTNESS = "exact_owner_head_at_evaluation_not_atomic_with_future_commit"
_AUTHORITY = "candidate_eligibility_only_no_activation_authority"
_OPERATIONAL_EFFECT = "none"
_EXPECTED_READINESS_BLOCKERS = frozenset({
    "legacy_runtime_policy_16_6_active", "runtime_policy_v2_not_activated",
    "admission_authority_unavailable", "transport_capability_unavailable",
    "writer_quiescence_contract_unavailable",
})
_GRANT_BLOCKERS_BY_STATE = {
    "missing": frozenset({"policy_change_grant_missing"}),
    "ambiguous": frozenset({"policy_change_grant_ambiguous"}),
    "mismatched": frozenset({"policy_change_grant_mismatched"}),
    "expired": frozenset({"policy_change_grant_outside_time_fence"}),
    "verified_prior_singleton": frozenset(),
}
_ISSUER_BLOCKERS = frozenset({
    "policy_change_grant_issuer_mismatched", "current_chief_term_missing_or_ambiguous",
    "policy_change_grant_issuer_prior_grant_unavailable"})
_CHIEF_BLOCKERS_BY_STATE = {
    "missing": frozenset({"current_chief_missing_or_ambiguous", "current_chief_unavailable"}),
    "exact_identity_carrier_unavailable": frozenset({"current_chief_carrier_coverage_unavailable", "current_chief_unavailable"}),
    "exact_identity_carrier_observed": frozenset(),
}
_NO_BLOCKERS: frozenset[str] = frozenset()
_ALLOWED_ISSUER_RELATIONS = frozenset({
    ("missing", "unavailable", _NO_BLOCKERS), ("ambiguous", "unavailable", _NO_BLOCKERS),
    ("mismatched", "unavailable", _NO_BLOCKERS), ("expired", "verified_prior_current_chief", _NO_BLOCKERS),
    ("expired", "mismatched", frozenset({"policy_change_grant_issuer_mismatched"})),
    ("expired", "unavailable", frozenset({"current_chief_term_missing_or_ambiguous"})),
    ("expired", "unavailable", frozenset({"policy_change_grant_issuer_prior_grant_unavailable"})),
    ("verified_prior_singleton", "verified_prior_current_chief", _NO_BLOCKERS),
    ("verified_prior_singleton", "mismatched", frozenset({"policy_change_grant_issuer_mismatched"})),
    ("verified_prior_singleton", "unavailable", frozenset({"current_chief_term_missing_or_ambiguous"})),
    ("verified_prior_singleton", "unavailable", frozenset({"policy_change_grant_issuer_prior_grant_unavailable"})),
})
_ALLOWED_BLOCKERS = frozenset({
    "retiring_chief_candidates_observed", "retiring_chief_candidate_stack",
    "subordinate_chief_physical_slot_overlap", "held_dispatch_reservations_observed",
    "effect_unknown_hold_observed", "active_over_depth_execution_observed",
    "over_depth_execution_closure_unavailable", "subordinate_attribution_unavailable",
    "known_subordinate_lower_bound_exceeds_candidate_limit",
    "pre_activation_checkpoint_unavailable", "candidate_topology_unavailable",
    "runtime_policy_holds_present", "subordinate_capacity_exactness_unavailable",
    "transport_capability_receipt_join_unavailable", "writer_quiescence_receipt_join_unavailable",
}) | frozenset().union(*_GRANT_BLOCKERS_BY_STATE.values()) | _ISSUER_BLOCKERS \
    | frozenset().union(*_CHIEF_BLOCKERS_BY_STATE.values())


class RuntimePolicyActivationAdmissionError(CompanyContractError):
    """The candidate cannot be evaluated against an exact current head."""


class RuntimePolicyActivationAdmissionV1(NamedTuple):
    """Immutable owner-replayed candidate eligibility with no runtime effect."""

    document_type: str
    schema_version: int
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    activation_id: str
    activation_sha256: str
    policy_definition_sha256: str
    evaluated_cursor: int
    evaluated_head_sha256: str
    readiness_observation_sha256: str
    readiness_source_witness_sha256: str
    current_chief_state: str
    policy_change_grant_state: str
    policy_change_grant_issuer_state: str
    pre_activation_checkpoint_state: str
    transport_capability_state: str
    writer_quiescence_state: str
    topology_state: str
    capacity_state: str
    registration_state: str
    candidate_disposition: str
    blockers: tuple[str, ...]
    currentness_semantics: str
    authority_semantics: str
    operational_effect: str
    admission_sha256: str

    def to_dict(self) -> dict[str, object]:
        return _admission_dict(self)


def _fail(message: str) -> Never:
    raise RuntimePolicyActivationAdmissionError(message)

def _exact_text(value: object, label: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(f"{label} is invalid")
    text = value
    try:
        if len(text.encode("utf-8")) > maximum:
            _fail(f"{label} is too large")
    except UnicodeEncodeError as exc:
        raise RuntimePolicyActivationAdmissionError(
            f"{label} is invalid Unicode"
        ) from exc
    return text

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

def _digest(value: object, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value

def _plain(value: object, label: str) -> object:
    """Detach one frozen ledger value through a typed, bounded boundary."""

    if isinstance(value, Mapping):
        try:
            entries = tuple(value.items())
        except MemoryError:
            raise
        except Exception as exc:
            raise RuntimePolicyActivationAdmissionError(
                f"{label} mapping cannot be traversed"
            ) from exc
        result: dict[str, object] = {}
        if len(entries) > 256:
            _fail(f"{label} mapping is too large")
        for pair in entries:
            if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
                _fail(f"{label} mapping entry is invalid")
            if pair[0] in result:
                _fail(f"{label} mapping contains a duplicate key")
            result[pair[0]] = _plain(pair[1], f"{label}.{pair[0]}")
        return result
    if type(value) in {tuple, list}:
        values = cast(tuple[object, ...] | list[object], value)
        if len(values) > 256:
            _fail(f"{label} sequence is too large")
        return [_plain(member, f"{label}[]") for member in values]
    if value is None or type(value) in {str, int, bool}:
        return value
    _fail(f"{label} contains an unsupported value")

def _parsed_time(value: object, label: str) -> datetime:
    text = _exact_text(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
    except ValueError as exc:
        raise RuntimePolicyActivationAdmissionError(
            f"{label} is not a real timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"{label} requires a timezone")
    return parsed


def _admission_plain(
    value: RuntimePolicyActivationAdmissionV1,
) -> dict[str, object]:
    if (
        type(value) is not RuntimePolicyActivationAdmissionV1
        or tuple.__len__(value) != len(RuntimePolicyActivationAdmissionV1._fields)
    ):
        _fail("runtime-policy activation admission must be an exact value object")
    return {field: getattr(value, field) for field in value._fields}


def _admission_digest(value: RuntimePolicyActivationAdmissionV1) -> str:
    payload = _admission_wire(value)
    payload["admission_sha256"] = _ZERO_SHA256
    try:
        return hashlib.sha256(canonical_company_json_bytes({
            "derivation_domain": _ADMISSION_DOMAIN,
            "admission": payload,
        })).hexdigest()
    except CompanyContractError as exc:
        raise RuntimePolicyActivationAdmissionError(
            "runtime-policy activation admission canonicalization failed"
        ) from exc


def _admission_dict(
    value: RuntimePolicyActivationAdmissionV1,
) -> dict[str, object]:
    return _admission_wire(
        validate_runtime_policy_activation_admission_structure_v1(value)
    )


def _admission_wire(
    value: RuntimePolicyActivationAdmissionV1,
) -> dict[str, object]:
    payload = _admission_plain(value)
    payload["blockers"] = list(value.blockers)
    return payload


def _same_company(
    activation: RuntimePolicyActivationV1,
    readiness: RuntimePolicyReadinessObservationV1,
) -> bool:
    return (
        activation.company_id,
        activation.company_incarnation,
        activation.lock_domain_generation,
    ) == (
        readiness.company_id,
        readiness.company_incarnation,
        readiness.lock_domain_generation,
    )


def _find_grant_event(
    state: CompanyStateOwner,
    activation: RuntimePolicyActivationV1,
    *,
    expected_cursor: int,
    expected_head_sha256: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Return exact policy grant, event authority, and request authority."""

    try:
        replay = CompanyStateOwner.historical_replay_input(state)
    except MemoryError:
        raise
    except Exception as exc:
        raise RuntimePolicyActivationAdmissionError(
            "activation admission ledger replay is unavailable"
        ) from exc
    if (
        replay.heads.global_head != (expected_cursor, expected_head_sha256)
        or len(replay.records) != expected_cursor
    ):
        _fail("company head changed during activation admission evaluation")
    matches: list[tuple[dict[str, object], dict[str, object], dict[str, object]]] = []
    for record in replay.records:
        if type(record.global_sequence) is not int:
            _fail("ledger global sequence type is invalid")
        request = _plain(record.request, "ledger request")
        if type(request) is not dict:
            _fail("ledger request is invalid")
        request_dict = cast(dict[str, object], request)
        for event_record in record.events:
            event = _plain(event_record.event, "ledger event")
            if type(event) is not dict:
                _fail("ledger event is invalid")
            event_dict = cast(dict[str, object], event)
            if event_dict.get("event_id") != activation.policy_change_grant_event_id:
                continue
            payload = event_dict.get("payload")
            if type(payload) is not dict:
                _fail("policy-change grant event payload is invalid")
            matches.append((cast(dict[str, object], payload), event_dict, request_dict))
    if len(matches) != 1:
        _fail("policy-change grant event is missing or ambiguous")
    return matches[0]


def _grant_and_issuer_states(
    state: CompanyStateOwner,
    activation: RuntimePolicyActivationV1,
    readiness: RuntimePolicyReadinessObservationV1,
    *,
    context_objects: tuple[Any, ...],
    expected_scope_sha256: str,
) -> tuple[str, str, set[str], datetime | None]:
    blockers: set[str] = set()
    grants = [item for item in context_objects if item.contract_type == AUTHORITY_GRANT_V1]
    policy_grants: list[dict[str, Any]] = []
    for item in grants:
        try:
            payload = plain_projected_payload(item.payload)
            normalized = validate_authority_grant(payload)
        except (CompanyContractError, RuntimePolicyReadinessStateError) as exc:
            raise RuntimePolicyActivationAdmissionError(
                "projected AuthorityGrant is invalid"
            ) from exc
        if (
            normalized["authority_state"] == "active"
            and normalized["permissions"] == ["policy.change"]
        ):
            policy_grants.append(normalized)
    if len(policy_grants) == 0:
        return "missing", "unavailable", {"policy_change_grant_missing"}, None
    if len(policy_grants) != 1:
        return "ambiguous", "unavailable", {"policy_change_grant_ambiguous"}, None
    grant = policy_grants[0]
    if grant["scope_sha256"] != expected_scope_sha256:
        _fail("durable policy-change grant scope differs from activation scope")
    expected_payload, event, request = _find_grant_event(
        state,
        activation,
        expected_cursor=readiness.cursor,
        expected_head_sha256=readiness.head_sha256,
    )
    try:
        event_grant = validate_authority_grant(expected_payload)
    except CompanyContractError as exc:
        raise RuntimePolicyActivationAdmissionError(
            "policy-change grant event payload is invalid"
        ) from exc
    projected_matches = [
        item for item in grants
        if (
            item.object_key == activation.policy_change_grant_id
            and item.event_id == activation.policy_change_grant_event_id
            and item.global_sequence == activation.policy_change_grant_global_sequence
            and company_contract_sha256(plain_projected_payload(item.payload))
            == activation.policy_change_grant_payload_sha256
        )
    ]
    if (
        len(projected_matches) != 1
        or grant != event_grant
        or grant["grant_id"] != activation.policy_change_grant_id
        or grant["grant_sha256"] != activation.policy_change_grant_sha256
        or grant["provenance"] != "AOI_verified"
        or company_contract_sha256(grant)
        != activation.policy_change_grant_payload_sha256
        or event.get("payload_sha256")
        != activation.policy_change_grant_payload_sha256
    ):
        return "mismatched", "unavailable", {"policy_change_grant_mismatched"}, None
    if (
        grant["actor_id"], grant["actor_kind"], grant["carrier_id"],
        grant["term"], grant["chief_epoch"],
    ) != (
        activation.activating_chief_id, "chief",
        activation.activating_chief_carrier_id,
        activation.activating_chief_term, activation.activating_chief_epoch,
    ):
        _fail("durable policy-change grant subject differs from current Chief")
    activated = _parsed_time(activation.requested_activation_at, "requested_activation_at")
    issued = _parsed_time(grant["issued_at"], "grant.issued_at")
    expires = _parsed_time(grant["expires_at"], "grant.expires_at")
    recorded = _parsed_time(event.get("recorded_at"), "grant_event.recorded_at")
    if not issued <= recorded <= activated:
        _fail("durable policy-change grant chronology is invalid")
    if not issued <= activated < expires:
        blockers.add("policy_change_grant_outside_time_fence")
    grant_state = "expired" if blockers else "verified_prior_singleton"
    try:
        event_authority = validate_actor_authority(event.get("actor_authority"))
        request_authority = validate_actor_authority(request.get("actor_authority"))
    except CompanyContractError as exc:
        raise RuntimePolicyActivationAdmissionError(
            "policy-change grant issuer authority is invalid"
        ) from exc
    if event_authority != request_authority:
        return grant_state, "mismatched", blockers | {
            "policy_change_grant_issuer_mismatched",
        }, recorded
    chief_terms = [item for item in context_objects if item.contract_type == CHIEF_TERM_V1]
    current = [item for item in chief_terms if item.payload.get("state") == "active"]
    if len(current) != 1:
        return grant_state, "unavailable", blockers | {
            "current_chief_term_missing_or_ambiguous",
        }, recorded
    term = plain_projected_payload(current[0].payload)
    if type(term) is not dict:
        _fail("current Chief term payload is invalid")
    expected_actor = (
        activation.activating_chief_id,
        activation.activating_chief_carrier_id,
        activation.activating_chief_term,
        activation.activating_chief_epoch,
    )
    authority_actor = (
        event_authority["actor_id"], event_authority["carrier_id"],
        event_authority["term"], event_authority["chief_epoch"],
    )
    term_actor = (
        term.get("chief_id"), term.get("carrier_id"),
        term.get("term"), term.get("epoch"),
    )
    if (
        authority_actor != expected_actor
        or term_actor != expected_actor
        or event_authority["actor_kind"] != "chief"
        or event_authority["authority_state"] != "active"
        or event_authority["permissions"] != ["company.mutate"]
        or event_authority["provenance"] != "AOI_verified"
        or event_authority["authority_record_sha256"]
        != activation.grant_issuer_authority_record_sha256
    ):
        return grant_state, "mismatched", blockers | {
            "policy_change_grant_issuer_mismatched",
        }, recorded
    issuer_grants = [
        item for item in grants
        if (
            item.global_sequence < activation.policy_change_grant_global_sequence
            and item.payload.get("grant_sha256")
            == activation.grant_issuer_authority_record_sha256
        )
    ]
    if len(issuer_grants) != 1:
        return grant_state, "unavailable", blockers | {
            "policy_change_grant_issuer_prior_grant_unavailable",
        }, recorded
    try:
        issuer_grant = validate_authority_grant(
            plain_projected_payload(issuer_grants[0].payload)
        )
        if authority_from_grant(issuer_grant) != event_authority:
            _fail("policy-change grant issuer differs from prior durable grant")
    except CompanyContractError as exc:
        raise RuntimePolicyActivationAdmissionError(
            "policy-change grant issuer prior grant is invalid"
        ) from exc
    return grant_state, "verified_prior_current_chief", blockers, recorded


def derive_runtime_policy_activation_admission_v1(
    state: CompanyStateOwner,
    activation: object,
    readiness: object,
) -> RuntimePolicyActivationAdmissionV1:
    """Evaluate candidate eligibility at one owner-replayed current head."""

    if type(state) is not CompanyStateOwner:
        _fail("activation admission requires exact CompanyStateOwner")
    try:
        candidate = validate_runtime_policy_activation_structure_v1(activation)
    except CompanyContractError as exc:
        raise RuntimePolicyActivationAdmissionError(
            "runtime-policy activation candidate is invalid"
        ) from exc
    try:
        current = validate_runtime_policy_readiness_observation(state, readiness)
        context = verified_runtime_policy_context(state)
    except (CompanyContractError, RuntimePolicyReadinessStateError) as exc:
        raise RuntimePolicyActivationAdmissionError(
            "exact current readiness observation is unavailable"
        ) from exc
    if type(current) is not RuntimePolicyReadinessObservationV1:
        _fail("current readiness type is invalid")
    if (
        context.company
        != (
            current.company_id,
            current.company_incarnation,
            current.lock_domain_generation,
        )
        or context.cursor != current.cursor
        or context.head_sha256 != current.head_sha256
    ):
        _fail("company head changed during readiness validation")
    policy = runtime_policy_definition_v2()
    expected_scope_sha256 = runtime_policy_activation_scope_sha256_v1(
        company_id=current.company_id,
        company_incarnation=current.company_incarnation,
        lock_domain_generation=current.lock_domain_generation,
        definition=policy,
    )
    if (
        not _same_company(candidate, current)
        or candidate.policy_definition_sha256 != policy.definition_sha256
        or candidate.policy_definition_sha256 != current.policy_definition_sha256
        or candidate.pre_activation_cursor != current.cursor
        or candidate.pre_activation_head_sha256 != current.head_sha256
        or candidate.readiness_observation_sha256 != current.observation_sha256
        or candidate.readiness_source_witness_sha256
        != current.source_witness_sha256
        or candidate.policy_change_scope_sha256 != expected_scope_sha256
    ):
        _fail("activation candidate differs from exact current readiness")

    grant_state, issuer_state, grant_blockers, grant_recorded_at = _grant_and_issuer_states(
        state, candidate, current,
        context_objects=context.objects,
        expected_scope_sha256=expected_scope_sha256,
    )
    blockers = set(current.blockers) - _EXPECTED_READINESS_BLOCKERS
    blockers.update(grant_blockers)

    try:
        delivery = CompanyStateOwner.delivery_snapshot(state)
        final_heads = CompanyStateOwner.heads(state)
    except MemoryError:
        raise
    except Exception as exc:
        raise RuntimePolicyActivationAdmissionError(
            "pre-activation checkpoint observation is unavailable"
        ) from exc
    if (
        final_heads.global_head.global_sequence != current.cursor
        or final_heads.global_head.transaction_sha256 != current.head_sha256
    ):
        _fail("company head changed during checkpoint validation")
    checkpoint = delivery.checkpoint
    requested_at = _parsed_time(
        candidate.requested_activation_at,
        "requested_activation_at",
    )
    checkpoint_generated_at = (
        None if checkpoint.generated_at is None
        else _parsed_time(checkpoint.generated_at, "checkpoint.generated_at")
    )
    checkpoint_verified_at = (
        None if checkpoint.verified_at is None
        else _parsed_time(checkpoint.verified_at, "checkpoint.verified_at")
    )
    if checkpoint.state == "verified" and (
        checkpoint_generated_at is None or checkpoint_generated_at > requested_at
        or checkpoint_verified_at is None or checkpoint_verified_at > requested_at
        or checkpoint_generated_at > checkpoint_verified_at
        or grant_recorded_at is not None and (
            grant_recorded_at > checkpoint_generated_at
            or grant_recorded_at > checkpoint_verified_at
        )
    ):
        _fail("verified checkpoint chronology is invalid")
    checkpoint_state = "verified_current" if (
        checkpoint.state == "verified"
        and checkpoint.current
        and checkpoint.checkpoint_id == candidate.pre_activation_checkpoint_id
        and checkpoint.cursor == candidate.pre_activation_cursor
        and checkpoint.head_sha256 == candidate.pre_activation_head_sha256
        and checkpoint.manifest_sha256
        == candidate.pre_activation_checkpoint_manifest_sha256
    ) else "unavailable_or_stale"
    if checkpoint_state != "verified_current":
        blockers.add("pre_activation_checkpoint_unavailable")

    current_chief_state = current.current_chief_state
    if current_chief_state != "exact_identity_carrier_observed":
        blockers.add("current_chief_unavailable")
    topology_state = "verified_candidate_topology" if (
        not current.retiring_candidates
        and all(
            item.lifecycle_class == "historical_terminal_legacy"
            for item in current.over_depth
        )
    ) else "unavailable_or_legacy_active"
    if topology_state != "verified_candidate_topology":
        blockers.add("candidate_topology_unavailable")
    if current.holds:
        blockers.add("runtime_policy_holds_present")

    # G2b exposes only a lower bound.  It is never exact capacity proof.
    capacity_state = "lower_bound_only"
    blockers.add("subordinate_capacity_exactness_unavailable")

    # No typed receipt joins exist in this four-file writer-off cut.  Candidate
    # digest fields cannot replace durable reducer evidence.
    transport_state = current.transport_capability_state
    quiescence_state = current.writer_quiescence_state
    blockers.add("transport_capability_receipt_join_unavailable")
    blockers.add("writer_quiescence_receipt_join_unavailable")

    canonical_blockers = tuple(sorted(blockers))
    provisional = RuntimePolicyActivationAdmissionV1(
        document_type=RUNTIME_POLICY_ACTIVATION_ADMISSION_V1,
        schema_version=1,
        company_id=current.company_id,
        company_incarnation=current.company_incarnation,
        lock_domain_generation=current.lock_domain_generation,
        activation_id=candidate.activation_id,
        activation_sha256=candidate.activation_sha256,
        policy_definition_sha256=policy.definition_sha256,
        evaluated_cursor=current.cursor,
        evaluated_head_sha256=current.head_sha256,
        readiness_observation_sha256=current.observation_sha256,
        readiness_source_witness_sha256=current.source_witness_sha256,
        current_chief_state=current_chief_state,
        policy_change_grant_state=grant_state,
        policy_change_grant_issuer_state=issuer_state,
        pre_activation_checkpoint_state=checkpoint_state,
        transport_capability_state=transport_state,
        writer_quiescence_state=quiescence_state,
        topology_state=topology_state,
        capacity_state=capacity_state,
        registration_state="writer_off_unregistered",
        candidate_disposition="blocked",
        blockers=canonical_blockers,
        currentness_semantics=_CURRENTNESS,
        authority_semantics=_AUTHORITY,
        operational_effect=_OPERATIONAL_EFFECT,
        admission_sha256=_ZERO_SHA256,
    )
    result = provisional._replace(admission_sha256=_admission_digest(provisional))
    return validate_runtime_policy_activation_admission_structure_v1(result)


def validate_runtime_policy_activation_admission_structure_v1(
    value: object,
) -> RuntimePolicyActivationAdmissionV1:
    """Validate self-consistent bytes only, without an authority claim."""

    try:
        if type(value) is RuntimePolicyActivationAdmissionV1:
            raw = _admission_plain(value)
        elif type(value) is dict and set(cast(dict[object, object], value)) == set(
            RuntimePolicyActivationAdmissionV1._fields
        ):
            raw = cast(dict[str, object], dict(cast(dict[object, object], value)))
        else:
            _fail("runtime-policy activation admission schema is invalid")
        fixed = {
            "document_type": RUNTIME_POLICY_ACTIVATION_ADMISSION_V1,
            "registration_state": "writer_off_unregistered",
            "candidate_disposition": "blocked",
            "currentness_semantics": _CURRENTNESS,
            "authority_semantics": _AUTHORITY,
            "operational_effect": _OPERATIONAL_EFFECT,
        }
        for field, expected in fixed.items():
            if _exact_text(raw[field], field) != expected:
                _fail(f"{field} differs from the writer-off admission contract")
        for field, minimum, maximum in (
            ("schema_version", 1, 1),
            ("company_incarnation", 1, 999_999_999),
            ("lock_domain_generation", 1, 999_999_999),
            ("evaluated_cursor", 1, 999_999_999_999),
        ):
            _exact_int(raw[field], field, minimum=minimum, maximum=maximum)
        state_fields = (
            "company_id", "activation_id", "current_chief_state",
            "policy_change_grant_state", "policy_change_grant_issuer_state",
            "pre_activation_checkpoint_state", "transport_capability_state",
            "writer_quiescence_state", "topology_state", "capacity_state",
        )
        for field in state_fields:
            _exact_text(raw[field], field)
        for field in (
            "activation_sha256", "policy_definition_sha256",
            "evaluated_head_sha256", "readiness_observation_sha256",
            "readiness_source_witness_sha256", "admission_sha256",
        ):
            _digest(raw[field], field)
        blockers = raw["blockers"]
        if type(blockers) not in {tuple, list}:
            _fail("activation admission blockers are not canonical")
        blocker_values = cast(tuple[object, ...] | list[object], blockers)
        if (
            not blocker_values
            or len(blocker_values) > 64
            or any(type(item) is not str or not item for item in blocker_values)
            or tuple(blocker_values)
            != tuple(sorted(set(cast(tuple[str, ...] | list[str], blocker_values))))
        ):
            _fail("activation admission blockers are not canonical")
        raw["blockers"] = tuple(cast(tuple[str, ...] | list[str], blocker_values))
        blockers_tuple = cast(tuple[str, ...], raw["blockers"])
        blocker_set = set(blockers_tuple)
        if not blocker_set <= _ALLOWED_BLOCKERS:
            _fail("activation admission blocker is outside the closed vocabulary")
        closed_states = {
            "current_chief_state": set(_CHIEF_BLOCKERS_BY_STATE),
            "policy_change_grant_state": set(_GRANT_BLOCKERS_BY_STATE),
            "policy_change_grant_issuer_state": {"unavailable", "mismatched", "verified_prior_current_chief"},
            "pre_activation_checkpoint_state": {"verified_current", "unavailable_or_stale"},
            "transport_capability_state": {"unavailable"},
            "writer_quiescence_state": {"unavailable"},
            "topology_state": {"verified_candidate_topology", "unavailable_or_legacy_active"},
            "capacity_state": {"lower_bound_only"},
        }
        for field, allowed in closed_states.items():
            if raw[field] not in allowed:
                _fail(f"{field} is outside the writer-off state vocabulary")
        required_blockers = {
            "subordinate_capacity_exactness_unavailable",
            "transport_capability_receipt_join_unavailable",
            "writer_quiescence_receipt_join_unavailable",
        }
        if not required_blockers <= blocker_set:
            _fail("activation admission omits a mandatory writer-off blocker")
        expected_grant_blockers = _GRANT_BLOCKERS_BY_STATE[
            cast(str, raw["policy_change_grant_state"])
        ]
        all_grant_blockers = frozenset().union(*_GRANT_BLOCKERS_BY_STATE.values())
        if blocker_set & all_grant_blockers != expected_grant_blockers:
            _fail("policy_change_grant_state contradicts its blockers")
        expected_chief_blockers = _CHIEF_BLOCKERS_BY_STATE[
            cast(str, raw["current_chief_state"])
        ]
        if blocker_set & frozenset().union(*_CHIEF_BLOCKERS_BY_STATE.values()) != expected_chief_blockers:
            _fail("current_chief_state contradicts its blockers")
        issuer_state = raw["policy_change_grant_issuer_state"]
        grant_state = raw["policy_change_grant_state"]
        issuer_blockers = blocker_set & _ISSUER_BLOCKERS
        issuer_relation = (grant_state, issuer_state, frozenset(issuer_blockers))
        if issuer_relation not in _ALLOWED_ISSUER_RELATIONS:
            _fail("policy-change grant issuer state contradicts its blockers")
        paired = (
            ("pre_activation_checkpoint_state", "unavailable_or_stale",
             "pre_activation_checkpoint_unavailable"),
            ("topology_state", "unavailable_or_legacy_active",
             "candidate_topology_unavailable"),
        )
        for field, unavailable, blocker in paired:
            if (raw[field] == unavailable) != (blocker in blocker_set):
                _fail(f"{field} contradicts activation admission blockers")
        candidate = RuntimePolicyActivationAdmissionV1(**cast(Any, raw))
        if candidate.admission_sha256 != _admission_digest(candidate):
            _fail("admission_sha256 differs from canonical admission bytes")
        canonical_company_json_bytes(_admission_wire(candidate))
        return candidate
    except RuntimePolicyActivationAdmissionError:
        raise
    except MemoryError:
        raise
    except (
        AttributeError, CompanyContractError, KeyError, OSError,
        RecursionError, TypeError, ValueError,
    ) as exc:
        raise RuntimePolicyActivationAdmissionError(
            "runtime-policy activation admission structure is invalid"
        ) from exc


def validate_runtime_policy_activation_admission_v1(
    state: CompanyStateOwner,
    value: object,
    activation: object,
    readiness: object,
) -> RuntimePolicyActivationAdmissionV1:
    """Re-derive exact owner-head evaluation; self-hashes are insufficient."""

    candidate = validate_runtime_policy_activation_admission_structure_v1(value)
    expected = derive_runtime_policy_activation_admission_v1(
        state,
        activation,
        readiness,
    )
    if candidate != expected:
        _fail("activation admission differs from exact owner-head derivation")
    return expected


def canonical_runtime_policy_activation_admission_v1_bytes(
    value: object,
) -> bytes:
    """Return canonical observation bytes; never an admission receipt."""

    return canonical_company_json_bytes(
        validate_runtime_policy_activation_admission_structure_v1(value).to_dict()
    )


__all__ = [
    "RUNTIME_POLICY_ACTIVATION_ADMISSION_V1",
    "RuntimePolicyActivationAdmissionError",
    "RuntimePolicyActivationAdmissionV1",
    "canonical_runtime_policy_activation_admission_v1_bytes",
    "derive_runtime_policy_activation_admission_v1",
    "validate_runtime_policy_activation_admission_structure_v1",
    "validate_runtime_policy_activation_admission_v1",
]
