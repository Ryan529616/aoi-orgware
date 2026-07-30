"""Pure lower-bound usage observation over caller-supplied projection objects.

This module deliberately has no ledger reader, replay record, or snapshot
authority.  It validates object shape and joins selected samples to immutable
telemetry receipts, but cannot establish ledger membership, prefix ordering,
provenance, or completeness.  Projection capacity and queue fields are ignored
and untrusted.  The result neither authorizes work nor derives a company total.
"""
from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, NamedTuple, NoReturn

from aoi_orgware.company.contracts import (
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_provider_coverage_revision,
    validate_provider_telemetry_receipt,
    validate_usage_counter_sample,
)
from aoi_orgware.company.invariants import InvariantObject, InvariantProjection
from aoi_orgware.company.telemetry_policy import coverage_event_kinds, telemetry_id


_DIMENSIONS = ("input", "cache_read", "cache_creation", "output", "reasoning_output", "total")
_MANDATORY_DIMENSIONS = frozenset(_DIMENSIONS) - {"cache_creation"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_INT64_MAX = (1 << 63) - 1
_OBSERVATION_STATES = frozenset({"observed", "degraded", "unavailable"})
_QUANTITY_CLASSES = frozenset({"observed_lower_bound", "unavailable"})
_COVERAGE_STATES = frozenset({"observed", "degraded", "unavailable", "unknown"})
_EVIDENCE_CONTRACT_TYPES = frozenset({
    USAGE_COUNTER_SAMPLE_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    PROVIDER_COVERAGE_REVISION_V1,
})
_REASON_CODES = frozenset({
    "ledger_head_not_bound", "terminal_counter_sample_unproven", "parent_child_overlap_unproven",
    "provider_order_unavailable", "attribution_unavailable", "projection_completeness_unverified",
    "counter_scope_unobserved", "usage_sample_missing_for_receipt", "reset_or_reorder_ambiguous",
    "token_dimension_missingness", "usage_coverage_missing", "usage_coverage_degraded",
    "usage_coverage_unavailable",
})
_BASE_REASONS = frozenset({
    "ledger_head_not_bound", "terminal_counter_sample_unproven", "parent_child_overlap_unproven",
    "provider_order_unavailable", "attribution_unavailable", "projection_completeness_unverified",
})


class UsageHighWaterError(CompanyContractError):
    """The unverified input cannot support a safe observation."""


class UsageCounterScopeKey(NamedTuple):
    """Exact scope only; parent/child and company aggregation are excluded."""

    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    provider: str
    counter_scope_id: str


class TokenDimensionHighWater(NamedTuple):
    dimension: str
    tokens: int | None
    availability: str
    winning_sample_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]


class UsageCoverageRevision(NamedTuple):
    coverage_scope_id: str
    revision_id: str
    revision: int
    state: str
    reason: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str


class UsageEvidenceRef(NamedTuple):
    contract_type: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str


class UsageHighWaterObservation(NamedTuple):
    key: UsageCounterScopeKey
    observation_state: str
    quantity_classification: str
    selected_evidence_max_global_sequence: int | None
    dimensions: tuple[TokenDimensionHighWater, ...]
    coverage: tuple[UsageCoverageRevision, ...]
    evidence: tuple[UsageEvidenceRef, ...]
    observation_digest: str
    reason_codes: tuple[str, ...]
    input_ordering: str
    provider_order_quality: str
    attribution_quality: str
    aggregation_quality: str
    terminal_sample_quality: str
    projection_provenance: str
    projection_completeness: str


def _fail(message: str) -> NoReturn:
    raise UsageHighWaterError(message)


def _identity(item: InvariantObject) -> UsageEvidenceRef:
    if type(item) is not InvariantObject:
        _fail("usage observation invariant object metadata is invalid")
    try:
        valid = (
            type(item.contract_type) is str
            and type(item.object_key) is str
            and type(item.event_id) is str
            and type(item.global_sequence) is int
            and type(item.payload_sha256) is str
            and bool(_ID.fullmatch(item.contract_type))
            and bool(_ID.fullmatch(item.object_key))
            and bool(_ID.fullmatch(item.event_id))
            and item.global_sequence >= 0
            and bool(_SHA256.fullmatch(item.payload_sha256))
        )
    except AttributeError:
        valid = False
    if not valid:
        _fail("usage observation invariant object metadata is invalid")
    return UsageEvidenceRef(
        item.contract_type, item.object_key, item.event_id,
        item.global_sequence, item.payload_sha256,
    )


def _expect_projection(projection: InvariantProjection) -> InvariantProjection:
    if type(projection) is not InvariantProjection or type(projection.objects) is not tuple:
        _fail("usage observation requires exact caller-supplied projection objects")
    objects: list[InvariantObject] = []
    seen: dict[UsageEvidenceRef, bytes] = {}
    for item in projection.objects:
        identity = _identity(item)
        try:
            payload_bytes = canonical_company_json_bytes(item.payload)
        except CompanyContractError as exc:
            _fail(f"usage observation invariant object payload is invalid: {exc}")
        previous_bytes = seen.get(identity)
        if previous_bytes is None:
            seen[identity] = payload_bytes
            objects.append(item)
        elif previous_bytes != payload_bytes:
            _fail("usage observation duplicate invariant object payload differs")
    return replace(projection, objects=tuple(objects))


def _validated(item: InvariantObject, kind: str) -> dict[str, Any]:
    try:
        if kind == USAGE_COUNTER_SAMPLE_V1:
            payload = validate_usage_counter_sample(item.payload)
            identifier = payload["sample_id"]
        elif kind == PROVIDER_TELEMETRY_RECEIPT_V1:
            payload = validate_provider_telemetry_receipt(item.payload)
            identifier = payload["receipt_id"]
        else:
            payload = validate_provider_coverage_revision(item.payload)
            identifier = payload["coverage_scope_id"]
    except CompanyContractError as exc:
        _fail(f"usage observation {kind} is invalid: {exc}")
    if item.object_key != identifier or item.payload_sha256 != company_contract_sha256(payload):
        _fail(f"usage observation {kind} object identity differs")
    return payload


def _binding(key: UsageCounterScopeKey) -> dict[str, Any]:
    return {
        "company_id": key.company_id,
        "company_incarnation": key.company_incarnation,
        "lock_domain_generation": key.lock_domain_generation,
    }


def _utc_timestamp(value: str) -> datetime:
    """Normalise an already contract-validated RFC3339 timestamp for equality."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _matches_key(payload: dict[str, Any], key: UsageCounterScopeKey) -> bool:
    return all((
        payload["company_id"] == key.company_id,
        payload["company_incarnation"] == key.company_incarnation,
        payload["lock_domain_generation"] == key.lock_domain_generation,
        payload["provider"] == key.provider,
    ))


def _canonical_receipt_id(receipt: dict[str, Any], key: UsageCounterScopeKey) -> str:
    return telemetry_id(
        _binding(key),
        "receipt",
        receipt["adapter_instance_id"],
        receipt["adapter_event_id"],
    )


def _samples(projection: InvariantProjection, key: UsageCounterScopeKey) -> tuple[tuple[InvariantObject, dict[str, Any]], ...]:
    found: list[tuple[InvariantObject, dict[str, Any]]] = []
    sample_ids: set[str] = set()
    event_ids: set[str] = set()
    for item in projection.objects:
        if item.contract_type != USAGE_COUNTER_SAMPLE_V1:
            continue
        payload = _validated(item, USAGE_COUNTER_SAMPLE_V1)
        if not _matches_key(payload, key) or payload["counter_scope_id"] != key.counter_scope_id:
            continue
        identity = _identity(item)
        if (
            payload["sample_id"] in sample_ids
            or identity.event_id in event_ids
            or payload["counter_scope_id"] != payload["thread_id"]
            or payload["provider_sequence"] is not None
        ):
            _fail("usage observation sample identity or cumulative scope is invalid")
        sample_ids.add(payload["sample_id"])
        event_ids.add(identity.event_id)
        found.append((item, payload))
    return tuple(sorted(found, key=lambda pair: (pair[0].global_sequence, pair[1]["sample_id"], pair[0].event_id)))


def _receipts(projection: InvariantProjection) -> dict[str, tuple[InvariantObject, dict[str, Any]]]:
    found: dict[str, tuple[InvariantObject, dict[str, Any]]] = {}
    occurrences: set[tuple[str, str]] = set()
    for item in projection.objects:
        if item.contract_type != PROVIDER_TELEMETRY_RECEIPT_V1:
            continue
        payload = _validated(item, PROVIDER_TELEMETRY_RECEIPT_V1)
        occurrence = (payload["adapter_instance_id"], payload["adapter_event_id"])
        if payload["receipt_id"] in found or occurrence in occurrences:
            _fail("usage observation contains duplicate telemetry receipt occurrence")
        found[payload["receipt_id"]] = (item, payload)
        occurrences.add(occurrence)
    return found


def _relevant_usage_receipts(
    receipts: dict[str, tuple[InvariantObject, dict[str, Any]]],
    key: UsageCounterScopeKey,
) -> tuple[tuple[InvariantObject, dict[str, Any]], ...]:
    """Return all canonical usage receipts for this exact counter scope.

    A receipt is relevant before a counter sample is considered: an adapter can
    report a token update while sample collection is unavailable.  That fact is
    evidence of an incomplete numeric view, rather than evidence for zero use.
    """
    found: list[tuple[InvariantObject, dict[str, Any]]] = []
    for item, receipt in receipts.values():
        if (
            not _matches_key(receipt, key)
            or receipt["normalized_kind"] != "thread_token_usage_updated"
            or receipt["facts"]["thread_id"]["quality"] != "observed"
            or receipt["facts"]["thread_id"]["value"] != key.counter_scope_id
        ):
            continue
        if receipt["receipt_id"] != _canonical_receipt_id(receipt, key):
            _fail("usage observation relevant telemetry receipt identity differs")
        found.append((item, receipt))
    return tuple(sorted(found, key=lambda pair: (pair[0].global_sequence, pair[1]["receipt_id"], pair[0].event_id)))


def _joined_samples(
    samples: tuple[tuple[InvariantObject, dict[str, Any]], ...],
    receipts: dict[str, tuple[InvariantObject, dict[str, Any]]],
    key: UsageCounterScopeKey,
) -> tuple[tuple[InvariantObject, dict[str, Any], InvariantObject, dict[str, Any]], ...]:
    joined: list[tuple[InvariantObject, dict[str, Any], InvariantObject, dict[str, Any]]] = []
    occurrences: set[tuple[str, str]] = set()
    for sample_item, sample in samples:
        pair = receipts.get(sample["telemetry_receipt_id"])
        if pair is None:
            _fail("usage counter sample has no referenced telemetry receipt")
        receipt_item, receipt = pair
        occurrence = (sample["adapter_instance_id"], sample["adapter_event_id"])
        facts = receipt["facts"]
        expected_facts = {name: facts[name] for name in ("actual_provider", "actual_model", "actual_effort", "actual_role", "routing")}
        expected_id = telemetry_id(_binding(key), "usage-sample", *occurrence)
        expected_receipt_id = _canonical_receipt_id(receipt, key)
        same = all(sample[left] == receipt[right] for left, right in (
            ("adapter_instance_id", "adapter_instance_id"), ("adapter_event_id", "adapter_event_id"),
            ("intake_sequence", "intake_sequence"), ("provider", "provider"),
            ("received_at", "received_at"), ("raw_artifact", "raw_artifact"),
            ("provenance", "provenance"), ("observation", "observation"),
        ))
        if (
            occurrence in occurrences
            or sample_item.global_sequence != receipt_item.global_sequence
            or receipt["receipt_id"] != expected_receipt_id
            or sample["telemetry_receipt_sha256"] != receipt["receipt_sha256"]
            or not _matches_key(receipt, key)
            or receipt["normalized_kind"] != "thread_token_usage_updated"
            or facts["thread_id"]["quality"] != "observed"
            or facts["turn_id"]["quality"] != "observed"
            or sample["thread_id"] != facts["thread_id"]["value"]
            or sample["turn_id"] != facts["turn_id"]["value"]
            or sample["provenance_facts"] != expected_facts
            or sample["sample_id"] != expected_id
            or not same
        ):
            _fail("usage counter sample receipt join differs")
        occurrences.add(occurrence)
        joined.append((sample_item, sample, receipt_item, receipt))
    return tuple(joined)


def _coverage(
    projection: InvariantProjection,
    key: UsageCounterScopeKey,
    relevant_receipts: tuple[tuple[InvariantObject, dict[str, Any]], ...],
    receipts: dict[str, tuple[InvariantObject, dict[str, Any]]],
) -> tuple[
    tuple[tuple[InvariantObject, dict[str, Any]], ...],
    tuple[InvariantObject, ...],
    bool,
]:
    expected: dict[str, tuple[str, list[str], int, str]] = {}
    for receipt_item, receipt in relevant_receipts:
        adapter = receipt["adapter_instance_id"]
        candidate = (
            telemetry_id(_binding(key), "coverage-scope", key.provider, receipt["source_class"], adapter, "usage"),
            coverage_event_kinds(key.provider, receipt["source_class"], "usage"),
            receipt_item.global_sequence,
            receipt["received_at"],
        )
        previous = expected.get(adapter)
        if previous is not None and previous[:2] != candidate[:2]:
            _fail("usage observation adapter source class is ambiguous")
        if previous is not None:
            latest_received = (
                previous[3]
                if _utc_timestamp(previous[3]) >= _utc_timestamp(candidate[3])
                else candidate[3]
            )
            candidate = candidate[:2] + (max(previous[2], candidate[2]), latest_received)
        expected[adapter] = candidate
    selected: dict[str, tuple[InvariantObject, dict[str, Any]]] = {}
    anchors: dict[str, InvariantObject] = {}
    canonical_candidates: set[str] = set()
    for item in projection.objects:
        if item.contract_type != PROVIDER_COVERAGE_REVISION_V1:
            continue
        payload = _validated(item, PROVIDER_COVERAGE_REVISION_V1)
        adapter = payload["adapter_instance_id"]
        if not _matches_key(payload, key) or adapter not in expected or payload["coverage_surface"] != "usage":
            continue
        scope, kinds, minimum_sequence, minimum_received_at = expected[adapter]
        if payload["coverage_scope_id"] != scope or payload["declared_event_kinds"] != kinds:
            continue
        if adapter in canonical_candidates:
            _fail("usage observation contains duplicate canonical usage coverage")
        canonical_candidates.add(adapter)
        anchor_pair = None if payload["last_receipt_id"] is None else receipts.get(payload["last_receipt_id"])
        if anchor_pair is None or payload["last_received_at"] is None:
            continue
        anchor_item, anchor = anchor_pair
        if (
            item.global_sequence < minimum_sequence
            or not _matches_key(anchor, key)
            or anchor["adapter_instance_id"] != adapter
            or anchor["source_class"] != payload["source_class"]
            or anchor["normalized_kind"] != "thread_token_usage_updated"
            or anchor["receipt_id"] != _canonical_receipt_id(anchor, key)
            or anchor_item.global_sequence < minimum_sequence
            or anchor_item.global_sequence > item.global_sequence
            or _utc_timestamp(payload["last_received_at"]) != _utc_timestamp(anchor["received_at"])
            or _utc_timestamp(payload["last_received_at"]) < _utc_timestamp(minimum_received_at)
        ):
            continue
        selected[adapter] = (item, payload)
        anchors[adapter] = anchor_item
    ordered = tuple(sorted(selected.values(), key=lambda pair: (pair[1]["coverage_scope_id"], pair[1]["revision"], pair[0].event_id)))
    return ordered, tuple(anchors[key] for key in sorted(anchors)), set(selected) != set(expected)


def _dimension(name: str, samples: tuple[tuple[InvariantObject, dict[str, Any]], ...]) -> tuple[TokenDimensionHighWater, bool]:
    present = [pair for pair in samples if pair[1]["total_token_vector"][name]["present"]]
    if name not in _MANDATORY_DIMENSIONS and len(present) != len(samples):
        return TokenDimensionHighWater(name, None, "unavailable", (), ("optional_dimension_partial_or_missing",)), False
    if not present:
        return TokenDimensionHighWater(name, None, "unavailable", (), ("counter_scope_unobserved",)), False
    sequence_maxima: dict[int, int] = {}
    for item, payload in present:
        tokens = payload["total_token_vector"][name]["tokens"]
        sequence_maxima[item.global_sequence] = max(sequence_maxima.get(item.global_sequence, tokens), tokens)
    maximum = max(sequence_maxima.values())
    ordered_maxima = [tokens for _, tokens in sorted(sequence_maxima.items())]
    reset = any(right < left for left, right in zip(ordered_maxima, ordered_maxima[1:]))
    winners = tuple(sorted(payload["sample_id"] for _, payload in present if payload["total_token_vector"][name]["tokens"] == maximum))
    return TokenDimensionHighWater(name, maximum, "observed_lower_bound", winners, ("reset_or_reorder_ambiguous",) if reset else ()), reset


def _digest_payload(value: UsageHighWaterObservation) -> dict[str, Any]:
    return {
        "derivation_domain": "aoi.usage.high-water.observation.v1",
        "derivation_version": 1,
        "scope": value.key._asdict(),
        "selected_evidence_max_global_sequence": value.selected_evidence_max_global_sequence,
        "dimensions": [item._asdict() | {"winning_sample_ids": list(item.winning_sample_ids), "reason_codes": list(item.reason_codes)} for item in value.dimensions],
        "coverage": [item._asdict() for item in value.coverage],
        "evidence": [item._asdict() for item in value.evidence],
        "reason_codes": list(value.reason_codes),
        "semantics": {
            "observation_state": value.observation_state,
            "quantity_classification": value.quantity_classification,
            "input_ordering": value.input_ordering,
            "provider_order_quality": value.provider_order_quality,
            "attribution_quality": value.attribution_quality,
            "aggregation_quality": value.aggregation_quality,
            "terminal_sample_quality": value.terminal_sample_quality,
            "projection_provenance": value.projection_provenance,
            "projection_completeness": value.projection_completeness,
        },
    }


def _valid_observation_key(value: Any) -> UsageCounterScopeKey:
    if (
        type(value) is not UsageCounterScopeKey or type(value.company_id) is not str
        or type(value.counter_scope_id) is not str or type(value.provider) is not str
        or type(value.company_incarnation) is not int or isinstance(value.company_incarnation, bool)
        or type(value.lock_domain_generation) is not int or isinstance(value.lock_domain_generation, bool)
        or not _ID.fullmatch(value.company_id) or not _ID.fullmatch(value.counter_scope_id)
        or not 1 <= value.company_incarnation <= 999_999_999
        or not 0 <= value.lock_domain_generation <= 999_999_999 or value.provider != "codex"
    ):
        _fail("usage observation requires an exact Codex UsageCounterScopeKey")
    return value


def _observation_text(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(f"usage observation {label} is invalid")
    return value


def _observation_integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= _INT64_MAX:
        _fail(f"usage observation {label} is invalid")
    return value


def _observation_reasons(value: Any, label: str, allowed: frozenset[str]) -> tuple[str, ...]:
    if type(value) is not tuple:
        _fail(f"usage observation {label} is invalid")
    result = tuple(_observation_text(item, f"{label}[{index}]") for index, item in enumerate(value))
    if tuple(sorted(set(result))) != result or any(item not in allowed for item in result):
        _fail(f"usage observation {label} is invalid")
    return result


def _validate_observation(value: Any, expected_key: UsageCounterScopeKey | None) -> UsageHighWaterObservation:
    """Validate B105's immutable carrier, not raw receipts or producer provenance."""
    if type(value) is not UsageHighWaterObservation:
        _fail("usage observation requires the exact immutable public carrier")
    observation = value
    key = _valid_observation_key(observation.key)
    if expected_key is not None and key != _valid_observation_key(expected_key):
        _fail("usage observation key differs from the expected exact scope")
    if observation.observation_state not in _OBSERVATION_STATES or observation.quantity_classification not in _QUANTITY_CLASSES:
        _fail("usage observation state or quantity classification is invalid")
    if (
        observation.input_ordering != "projection_global_sequence_metadata_only"
        or observation.provider_order_quality != "unavailable" or observation.attribution_quality != "unavailable"
        or observation.aggregation_quality != "parent_child_overlap_unproven"
        or observation.terminal_sample_quality != "unavailable" or observation.projection_provenance != "unverified"
        or observation.projection_completeness != "unverified"
    ):
        _fail("usage observation fixed semantic quality is invalid")
    if observation.selected_evidence_max_global_sequence is not None:
        _observation_integer(observation.selected_evidence_max_global_sequence, "selected evidence sequence")
    if type(observation.dimensions) is not tuple or len(observation.dimensions) != len(_DIMENSIONS):
        _fail("usage observation dimensions are invalid")
    dimensions: list[TokenDimensionHighWater] = []
    for index, name in enumerate(_DIMENSIONS):
        item = observation.dimensions[index]
        if type(item) is not TokenDimensionHighWater or item.dimension != name or type(item.winning_sample_ids) is not tuple:
            _fail("usage observation dimensions are invalid")
        winners = tuple(_observation_text(sample_id, f"dimension {name} winner") for sample_id in item.winning_sample_ids)
        if tuple(sorted(set(winners))) != winners:
            _fail("usage observation dimension winners are invalid")
        if item.availability == "observed_lower_bound":
            if item.tokens is None or not winners:
                _fail("usage observation observed dimension is inconsistent")
            _observation_integer(item.tokens, f"dimension {name} tokens")
            reasons = _observation_reasons(item.reason_codes, f"dimension {name} reasons", frozenset({"reset_or_reorder_ambiguous"}))
        elif item.availability == "unavailable":
            allowed = frozenset({"counter_scope_unobserved"}) if name != "cache_creation" else frozenset({"counter_scope_unobserved", "optional_dimension_partial_or_missing"})
            if item.tokens is not None or winners or len(item.reason_codes) != 1:
                _fail("usage observation unavailable dimension is inconsistent")
            reasons = _observation_reasons(item.reason_codes, f"dimension {name} reasons", allowed)
        else:
            _fail("usage observation dimension availability is invalid")
        dimensions.append(item._replace(winning_sample_ids=winners, reason_codes=reasons))
    if type(observation.coverage) is not tuple or type(observation.evidence) is not tuple:
        _fail("usage observation coverage or evidence is invalid")
    coverage_ids: set[tuple[str, str]] = set()
    coverage_scope_ids: set[str] = set()
    prior_coverage: tuple[str, int, str] | None = None
    for coverage_item in observation.coverage:
        if type(coverage_item) is not UsageCoverageRevision:
            _fail("usage observation coverage is invalid")
        scope = _observation_text(coverage_item.coverage_scope_id, "coverage scope")
        if coverage_item.object_key != scope or coverage_item.state not in _COVERAGE_STATES:
            _fail("usage observation coverage is inconsistent")
        _observation_text(coverage_item.revision_id, "coverage revision")
        coverage_reason = _observation_text(coverage_item.reason, "coverage reason")
        if (coverage_item.state == "observed") != (coverage_reason == "observed"):
            _fail("usage observation coverage state and reason are inconsistent")
        _observation_text(coverage_item.event_id, "coverage event")
        _observation_integer(coverage_item.revision, "coverage revision", 1)
        _observation_integer(coverage_item.global_sequence, "coverage sequence")
        if type(coverage_item.payload_sha256) is not str or not _SHA256.fullmatch(coverage_item.payload_sha256):
            _fail("usage observation coverage digest is invalid")
        identity = (coverage_item.object_key, coverage_item.event_id)
        coverage_order = (scope, coverage_item.revision, coverage_item.event_id)
        if scope in coverage_scope_ids or identity in coverage_ids or (prior_coverage is not None and coverage_order <= prior_coverage):
            _fail("usage observation coverage identity or ordering is invalid")
        coverage_scope_ids.add(scope)
        coverage_ids.add(identity)
        prior_coverage = coverage_order
    evidence_ids: set[tuple[str, str]] = set()
    evidence_events: set[str] = set()
    prior_evidence: tuple[str, str, str, int, str] | None = None
    evidence: list[UsageEvidenceRef] = []
    for evidence_item in observation.evidence:
        if type(evidence_item) is not UsageEvidenceRef:
            _fail("usage observation evidence is invalid")
        contract_type = _observation_text(evidence_item.contract_type, "evidence contract type")
        if contract_type not in _EVIDENCE_CONTRACT_TYPES:
            _fail("usage observation evidence contract type is invalid")
        object_key = _observation_text(evidence_item.object_key, "evidence object key")
        event_id = _observation_text(evidence_item.event_id, "evidence event")
        sequence = _observation_integer(evidence_item.global_sequence, "evidence sequence")
        if type(evidence_item.payload_sha256) is not str or not _SHA256.fullmatch(evidence_item.payload_sha256):
            _fail("usage observation evidence digest is invalid")
        identity = (contract_type, object_key)
        evidence_order = (contract_type, object_key, event_id, sequence, evidence_item.payload_sha256)
        if identity in evidence_ids or event_id in evidence_events or (prior_evidence is not None and evidence_order <= prior_evidence):
            _fail("usage observation evidence identity or ordering is invalid")
        evidence_ids.add(identity)
        evidence_events.add(event_id)
        prior_evidence = evidence_order
        evidence.append(evidence_item)
    coverage_summary = {
        (item.object_key, item.event_id, item.global_sequence, item.payload_sha256)
        for item in observation.coverage
    }
    coverage_evidence = {
        (item.object_key, item.event_id, item.global_sequence, item.payload_sha256)
        for item in evidence if item.contract_type == PROVIDER_COVERAGE_REVISION_V1
    }
    if coverage_summary != coverage_evidence:
        _fail("usage observation coverage and evidence differ")
    sample_keys = {item.object_key for item in evidence if item.contract_type == USAGE_COUNTER_SAMPLE_V1}
    if any(winner not in sample_keys for item in dimensions for winner in item.winning_sample_ids):
        _fail("usage observation dimension winner is absent from evidence")
    selected = max((item.global_sequence for item in evidence), default=None)
    if observation.selected_evidence_max_global_sequence != selected:
        _fail("usage observation selected evidence sequence differs")
    reasons = _observation_reasons(observation.reason_codes, "reasons", _REASON_CODES)
    # A nonempty summary never proves full coverage: a partial gap remains an
    # explicit unverified assertion, and projection completeness is fixed unverified.
    empty_coverage_requires_reason = (
        not observation.coverage
        and (
            observation.quantity_classification == "observed_lower_bound"
            or any(item.contract_type == PROVIDER_TELEMETRY_RECEIPT_V1 for item in evidence)
        )
    )
    if empty_coverage_requires_reason and "usage_coverage_missing" not in reasons:
        _fail("usage observation empty coverage missingness is not visible")
    unavailable = [item for item in dimensions if item.availability == "unavailable"]
    reset = any("reset_or_reorder_ambiguous" in item.reason_codes for item in dimensions)
    coverage_states = {item.state for item in observation.coverage}
    if not _BASE_REASONS <= set(reasons) or ("token_dimension_missingness" in reasons) != bool(unavailable) or ("reset_or_reorder_ambiguous" in reasons) != reset:
        _fail("usage observation reason codes are inconsistent")
    if ("usage_coverage_degraded" in reasons) != ("degraded" in coverage_states) or ("usage_coverage_unavailable" in reasons) != bool({"unavailable", "unknown"} & coverage_states):
        _fail("usage observation coverage reasons are inconsistent")
    all_unavailable = len(unavailable) == len(_DIMENSIONS)
    counter_scope_unobserved = "counter_scope_unobserved" in reasons
    if counter_scope_unobserved != all_unavailable:
        _fail("usage observation unobserved reason is inconsistent")
    optional = next(item for item in dimensions if item.dimension == "cache_creation")
    if optional.availability == "unavailable":
        expected_optional_reason = "counter_scope_unobserved" if all_unavailable else "optional_dimension_partial_or_missing"
        if optional.reason_codes != (expected_optional_reason,):
            _fail("usage observation optional dimension missingness is inconsistent")
    if observation.quantity_classification == "observed_lower_bound" and any(
        item.availability != "observed_lower_bound" for item in dimensions if item.dimension in _MANDATORY_DIMENSIONS
    ):
        _fail("usage observation lower-bound classification is inconsistent")
    unavailable_matrix = all_unavailable and counter_scope_unobserved
    if (observation.quantity_classification == "unavailable") != unavailable_matrix or (
        observation.observation_state == "unavailable"
    ) != unavailable_matrix:
        _fail("usage observation unavailable matrix is inconsistent")
    degradation_trigger = (
        reset
        or "usage_sample_missing_for_receipt" in reasons
        or "usage_coverage_missing" in reasons
        or any(state != "observed" for state in coverage_states)
        or "token_dimension_missingness" in reasons
    )
    observed_matrix = (
        observation.quantity_classification == "observed_lower_bound"
        and all(item.availability == "observed_lower_bound" for item in dimensions)
        and bool(observation.coverage)
        and coverage_states == {"observed"}
        and not degradation_trigger
    )
    degraded_matrix = (
        observation.quantity_classification == "observed_lower_bound"
        and all(item.availability == "observed_lower_bound" for item in dimensions if item.dimension in _MANDATORY_DIMENSIONS)
        and degradation_trigger
    )
    if (observation.observation_state == "observed") != observed_matrix:
        _fail("usage observation observed state is inconsistent")
    if (observation.observation_state == "degraded") != degraded_matrix:
        _fail("usage observation degraded state is inconsistent")
    expected_digest = company_contract_sha256(_digest_payload(observation))
    if observation.observation_digest != expected_digest:
        _fail("usage observation digest differs")
    return observation


def validate_usage_high_water_observation(value: Any, expected_key: UsageCounterScopeKey | None = None) -> UsageHighWaterObservation:
    """Check B105 carrier self-consistency; provenance remains unverified."""
    try:
        return _validate_observation(value, expected_key)
    except UsageHighWaterError:
        raise
    except (AttributeError, StopIteration, RecursionError, RuntimeError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise UsageHighWaterError("usage observation validation failed") from exc


def derive_usage_high_water(projection: InvariantProjection, key: UsageCounterScopeKey) -> UsageHighWaterObservation:
    """Return component maxima only; the caller must not treat them as totals."""
    try:
        projection = _expect_projection(projection)
        key = _valid_observation_key(key)
        samples = _samples(projection, key)
        receipts = _receipts(projection)
        relevant_receipts = _relevant_usage_receipts(receipts, key)
        joined = _joined_samples(samples, receipts, key)
        joined_receipt_counts: dict[str, int] = {}
        for _, _, _, receipt in joined:
            receipt_id = receipt["receipt_id"]
            joined_receipt_counts[receipt_id] = joined_receipt_counts.get(receipt_id, 0) + 1
        if any(count > 1 for count in joined_receipt_counts.values()):
            _fail("usage observation relevant telemetry receipt has multiple samples")
        missing_sample_receipts = tuple(
            pair for pair in relevant_receipts if joined_receipt_counts.get(pair[1]["receipt_id"], 0) == 0
        )
        coverage_items, coverage_anchors, coverage_missing = _coverage(projection, key, relevant_receipts, receipts)
        dimension_flags = tuple(_dimension(name, samples) for name in _DIMENSIONS)
        dimensions = tuple(item for item, _ in dimension_flags)
        reset = any(flag for _, flag in dimension_flags)
        coverage = tuple(UsageCoverageRevision(
            payload["coverage_scope_id"], payload["revision_id"], payload["revision"], payload["state"], payload["reason"],
            item.object_key, item.event_id, item.global_sequence, item.payload_sha256,
        ) for item, payload in coverage_items)
        evidence_candidates = (
            tuple(_identity(item) for item, _, _, _ in joined)
            + tuple(_identity(item) for item, _ in relevant_receipts)
            + tuple(_identity(item) for item, _ in coverage_items)
            + tuple(_identity(item) for item in coverage_anchors)
        )
        evidence = tuple(sorted(
            dict.fromkeys(evidence_candidates),
            key=lambda item: (item.contract_type, item.object_key, item.event_id, item.global_sequence, item.payload_sha256),
        ))
        if (
            len({item.event_id for item in evidence}) != len(evidence)
            or len({(item.contract_type, item.object_key) for item in evidence}) != len(evidence)
        ):
            _fail("usage observation contains duplicate accepted evidence identity")
        reasons = {
            "ledger_head_not_bound", "terminal_counter_sample_unproven", "parent_child_overlap_unproven",
            "provider_order_unavailable", "attribution_unavailable", "projection_completeness_unverified",
        }
        if not samples:
            reasons.add("counter_scope_unobserved")
        if missing_sample_receipts:
            reasons.add("usage_sample_missing_for_receipt")
        if reset:
            reasons.add("reset_or_reorder_ambiguous")
        if any(item.availability != "observed_lower_bound" for item in dimensions):
            reasons.add("token_dimension_missingness")
        states = {item.state for item in coverage}
        if coverage_missing:
            reasons.add("usage_coverage_missing")
        if "degraded" in states:
            reasons.add("usage_coverage_degraded")
        if "unavailable" in states or "unknown" in states:
            reasons.add("usage_coverage_unavailable")
        if not samples:
            state, quantity = "unavailable", "unavailable"
        elif (
            reset
            or missing_sample_receipts
            or coverage_missing
            or states != {"observed"}
            or "token_dimension_missingness" in reasons
        ):
            state, quantity = "degraded", "observed_lower_bound"
        else:
            state, quantity = "observed", "observed_lower_bound"
        provisional = UsageHighWaterObservation(
            key, state, quantity, max((item.global_sequence for item in evidence), default=None), dimensions, coverage, evidence,
            "", tuple(sorted(reasons)), "projection_global_sequence_metadata_only", "unavailable", "unavailable",
            "parent_child_overlap_unproven", "unavailable", "unverified", "unverified",
        )
        result = provisional._replace(observation_digest=company_contract_sha256(_digest_payload(provisional)))
        return validate_usage_high_water_observation(result, key)
    except UsageHighWaterError:
        raise
    except (
        CompanyContractError, AttributeError, StopIteration, RuntimeError,
        KeyError, TypeError, ValueError, OverflowError,
    ) as exc:
        raise UsageHighWaterError("usage observation payload processing failed") from exc
