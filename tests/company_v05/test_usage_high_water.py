from __future__ import annotations

import copy
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RAW_MEDIA_TYPE,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    ZERO_SHA256,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_provider_coverage_revision,
    validate_provider_telemetry_receipt,
    validate_usage_counter_sample,
)
from aoi_orgware.company.invariants import InvariantObject, InvariantProjection
from aoi_orgware.company.telemetry_policy import coverage_event_kinds, telemetry_id
from aoi_orgware.company.usage import high_water
from aoi_orgware.company.usage.high_water import (
    UsageCounterScopeKey,
    UsageHighWaterObservation,
    UsageHighWaterError,
    derive_usage_high_water,
    validate_usage_high_water_observation,
)


T = "2026-07-29T00:00:00Z"
H = "a" * 64
KEY = UsageCounterScopeKey("company-1", 1, 1, "codex", "thread-1")


def _rehash(value: dict[str, Any], field: str) -> dict[str, Any]:
    value[field] = company_contract_sha256({key: item for key, item in value.items() if key != field})
    return value


def _blob() -> dict[str, Any]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": H, "size_bytes": 12,
            "media_type": PROVIDER_TELEMETRY_RAW_MEDIA_TYPE, "availability": "available"}


def _fact(value: Any = None, *, source: str = "none", quality: str = "unavailable", reason: str = "not_exposed") -> dict[str, Any]:
    return {"value": value, "source": source, "quality": quality, "reason": reason}


def _facts(thread: str, turn: str) -> dict[str, dict[str, Any]]:
    names = ("actual_provider", "actual_model", "actual_effort", "actual_role", "routing", "session_id", "thread_id", "turn_id", "agent_id", "parent_thread_id", "event_time", "engineering_completion")
    result = {name: _fact() for name in names}
    result["actual_provider"] = _fact("openai", source="provider_payload", quality="observed", reason="provider_model_provider")
    result["thread_id"] = _fact(thread, source="provider_payload", quality="observed", reason="provider_thread_id")
    result["turn_id"] = _fact(turn, source="provider_payload", quality="observed", reason="provider_turn_id")
    return result


def _relation() -> dict[str, Any]:
    return {"kind": "none", "sender_thread_id": None, "receiver_thread_ids": [], "child_thread_id": None,
            "agent_path": None, "activity_kind": None, "native_depth": None, "reason": "provider_relation_not_present"}


def _join() -> dict[str, Any]:
    return {"state": "none", "binding_kind": "none", "registry_cursor": 2, "dispatch_request_id": None,
            "dispatch_revision_id": None, "registration_id": None, "execution_id": None, "carrier_id": None,
            "candidate_count": 0, "candidates_sha256": ZERO_SHA256, "reason": "no_registered_match"}


def _vector(total: int, *, cache_creation: int | None = 0) -> dict[str, dict[str, Any]]:
    return {"input": {"present": True, "tokens": total - 2}, "cache_read": {"present": True, "tokens": 0},
            "cache_creation": {"present": cache_creation is not None, "tokens": cache_creation},
            "output": {"present": True, "tokens": 2}, "reasoning_output": {"present": True, "tokens": 0},
            "total": {"present": True, "tokens": total}}


def _binding(key: UsageCounterScopeKey) -> dict[str, Any]:
    return {"company_id": key.company_id, "company_incarnation": key.company_incarnation,
            "lock_domain_generation": key.lock_domain_generation}


def _receipt(tag: str, *, key: UsageCounterScopeKey = KEY, adapter: str = "adapter-1", thread: str | None = None) -> dict[str, Any]:
    thread = thread or key.counter_scope_id
    value = {"contract_type": PROVIDER_TELEMETRY_RECEIPT_V1, "schema_version": 1, "company_id": key.company_id,
             "company_incarnation": key.company_incarnation, "lock_domain_generation": key.lock_domain_generation,
             "transaction_id": f"transaction-{tag}", "command_id": f"command-{tag}",
             "receipt_id": telemetry_id(_binding(key), "receipt", adapter, f"event-{tag}"),
             "adapter_instance_id": adapter, "adapter_event_id": f"event-{tag}", "intake_sequence": 1,
             "provider": "codex", "source_class": "codex_app_server", "parser_id": "codex_adapter", "parser_version": "v1",
             "parse_outcome": "normalized", "normalized_kind": "thread_token_usage_updated", "facts": _facts(thread, "turn-1"),
             "provider_native_relation": _relation(), "dispatch_join": _join(), "received_at": T, "raw_artifact": _blob(),
             "provenance": "adapter_receipt_persisted", "observation": {"state": "known", "reason": "observed"},
             "receipt_sha256": ZERO_SHA256}
    return _rehash(value, "receipt_sha256")


def _sample(receipt: dict[str, Any], total: int, *, key: UsageCounterScopeKey = KEY, cache_creation: int | None = 0) -> dict[str, Any]:
    facts = receipt["facts"]
    value = {"contract_type": USAGE_COUNTER_SAMPLE_V1, "schema_version": 1, "company_id": key.company_id,
             "company_incarnation": key.company_incarnation, "lock_domain_generation": key.lock_domain_generation,
             "sample_id": telemetry_id(_binding(key), "usage-sample", receipt["adapter_instance_id"], receipt["adapter_event_id"]),
             "telemetry_receipt_id": receipt["receipt_id"], "telemetry_receipt_sha256": receipt["receipt_sha256"],
             "adapter_instance_id": receipt["adapter_instance_id"], "adapter_event_id": receipt["adapter_event_id"],
             "intake_sequence": receipt["intake_sequence"], "provider": "codex", "thread_id": facts["thread_id"]["value"],
             "turn_id": facts["turn_id"]["value"], "counter_scope_id": facts["thread_id"]["value"], "provider_sequence": None,
             "counting_semantics": "non_additive_cumulative", "total_token_vector": _vector(total, cache_creation=cache_creation),
             "last_token_vector": _vector(2), "model_context_window": {"present": False, "value": None},
             "provenance_facts": {name: facts[name] for name in ("actual_provider", "actual_model", "actual_effort", "actual_role", "routing")},
             "received_at": receipt["received_at"], "raw_artifact": receipt["raw_artifact"], "provenance": receipt["provenance"],
             "observation": receipt["observation"], "sample_sha256": ZERO_SHA256}
    return _rehash(value, "sample_sha256")


def _coverage(receipt: dict[str, Any], *, key: UsageCounterScopeKey = KEY, state: str = "observed", canonical: bool = True) -> dict[str, Any]:
    adapter = receipt["adapter_instance_id"]
    scope = telemetry_id(_binding(key), "coverage-scope", "codex", receipt["source_class"], adapter, "usage") if canonical else f"arbitrary-{adapter}"
    unavailable = state == "unavailable"
    value = {"contract_type": PROVIDER_COVERAGE_REVISION_V1, "schema_version": 1, "company_id": key.company_id,
             "company_incarnation": key.company_incarnation, "lock_domain_generation": key.lock_domain_generation,
             "coverage_scope_id": scope, "coverage_surface": "usage", "revision_id": f"coverage-{adapter}", "revision": 1,
             "previous_revision_sha256": ZERO_SHA256, "provider": "codex", "adapter_instance_id": adapter,
             "source_class": receipt["source_class"], "declared_event_kinds": coverage_event_kinds("codex", receipt["source_class"], "usage"),
             "state": state, "reason": "adapter_unavailable" if unavailable else ("observed" if state == "observed" else "adapter_gap"),
             "assessment_source": "configuration" if unavailable else "receipt",
             "last_receipt_id": None if unavailable else receipt["receipt_id"], "last_received_at": None if unavailable else T,
             "gap_started_at": None if state in {"observed", "unavailable"} else T,
             "dropped_event_count": {"value": None, "source": "none", "quality": "unavailable", "reason": "adapter_unavailable"} if unavailable else {"value": 0, "source": "collector", "quality": "observed", "reason": "observed"},
             "assessed_at": T, "observation": {"state": "unavailable", "reason": "adapter_unavailable"} if unavailable else {"state": "known", "reason": "observed"}, "coverage_sha256": ZERO_SHA256}
    return _rehash(value, "coverage_sha256")


def _object(payload: dict[str, Any], sequence: int, *, event: str | None = None) -> InvariantObject:
    validators = {USAGE_COUNTER_SAMPLE_V1: validate_usage_counter_sample, PROVIDER_TELEMETRY_RECEIPT_V1: validate_provider_telemetry_receipt,
                  PROVIDER_COVERAGE_REVISION_V1: validate_provider_coverage_revision}
    value = validators[payload["contract_type"]](payload)
    identifier = value.get("sample_id") or value.get("receipt_id") or value["coverage_scope_id"]
    return InvariantObject(value["contract_type"], identifier, event or f"ledger-{identifier}", sequence, company_contract_sha256(value), value)


def _projection(*objects: InvariantObject) -> InvariantProjection:
    return InvariantProjection(tuple(objects), (), (), 16, (), True, (), ())


def _bundle(tag: str, total: int, *, adapter: str = "adapter-1", sequence: int = 10, coverage: bool = True, key: UsageCounterScopeKey = KEY) -> tuple[InvariantObject, ...]:
    receipt = _receipt(tag, key=key, adapter=adapter)
    result = (_object(_sample(receipt, total, key=key), sequence), _object(receipt, sequence))
    return result + ((_object(_coverage(receipt, key=key), sequence + 1),) if coverage else ())


def _total(value: UsageHighWaterObservation) -> int | None:
    return next(item.tokens for item in value.dimensions if item.dimension == "total")


def test_canonical_receipt_and_coverage_yield_only_unverified_lower_bound_metadata() -> None:
    observation = derive_usage_high_water(_projection(*_bundle("one", 20)), KEY)
    assert _total(observation) == 20 and observation.observation_state == "observed"
    assert observation.selected_evidence_max_global_sequence == 11
    assert (observation.input_ordering, observation.provider_order_quality) == ("projection_global_sequence_metadata_only", "unavailable")
    assert (observation.projection_provenance, observation.projection_completeness, observation.terminal_sample_quality) == ("unverified", "unverified", "unavailable")
    assert "ledger_head_not_bound" in observation.reason_codes and "terminal_counter_sample_unproven" in observation.reason_codes
    assert {"authoritative_total", "remaining_unknown", "model_cost_attribution", "evidence_digest"}.isdisjoint(observation._fields)


def test_unpaired_relevant_receipt_degrades_and_advances_evidence_horizon() -> None:
    base_objects = _bundle("one", 10)
    base = derive_usage_high_water(_projection(*base_objects), KEY)
    late = _object(_receipt("late"), 12)
    observation = derive_usage_high_water(_projection(*base_objects, late), KEY)
    assert _total(observation) == 10 and observation.observation_state == "degraded"
    assert observation.selected_evidence_max_global_sequence == 12
    assert observation.observation_digest != base.observation_digest
    assert "usage_sample_missing_for_receipt" in observation.reason_codes
    assert any(item.event_id == late.event_id for item in observation.evidence)


def test_relevant_receipt_without_sample_is_numeric_unavailable_not_zero() -> None:
    receipt = _object(_receipt("only"), 12)
    observation = derive_usage_high_water(_projection(receipt), KEY)
    assert observation.observation_state == observation.quantity_classification == "unavailable"
    assert observation.selected_evidence_max_global_sequence == 12
    assert all(item.tokens is None for item in observation.dimensions)
    assert "usage_sample_missing_for_receipt" in observation.reason_codes
    assert any(item.event_id == receipt.event_id for item in observation.evidence)


def test_two_adapters_need_two_canonical_coverage_revisions() -> None:
    first = _bundle("one", 10, adapter="adapter-1", sequence=10)
    second = _bundle("two", 20, adapter="adapter-2", sequence=20, coverage=False)
    observation = derive_usage_high_water(_projection(*first, *second), KEY)
    assert _total(observation) == 20 and observation.observation_state == "degraded"
    assert "usage_coverage_missing" in observation.reason_codes


def test_arbitrary_coverage_cannot_qualify_and_duplicate_canonical_fails() -> None:
    receipt = _receipt("one")
    sample = _object(_sample(receipt, 10), 10)
    receipt_object = _object(receipt, 10)
    arbitrary = _object(_coverage(receipt, canonical=False), 11)
    assert derive_usage_high_water(_projection(sample, receipt_object, arbitrary), KEY).observation_state == "degraded"
    canonical = _object(_coverage(receipt), 12)
    with pytest.raises(UsageHighWaterError, match="duplicate canonical"):
        derive_usage_high_water(_projection(sample, receipt_object, canonical, _object(_coverage(receipt), 13)), KEY)


def test_stale_coverage_and_distinct_sample_identity_reuse_cannot_qualify() -> None:
    receipt = _receipt("one")
    sample = _object(_sample(receipt, 10), 10)
    receipt_object = _object(receipt, 10)
    stale = _object(_coverage(receipt), 9)
    assert derive_usage_high_water(_projection(sample, receipt_object, stale), KEY).observation_state == "degraded"
    with pytest.raises(UsageHighWaterError, match="duplicate canonical"):
        derive_usage_high_water(_projection(sample, receipt_object, stale, _object(_coverage(receipt), 11)), KEY)
    duplicate = copy.deepcopy(sample)
    duplicate = InvariantObject(sample.contract_type, sample.object_key, "other-event", 12, sample.payload_sha256, sample.payload)
    with pytest.raises(UsageHighWaterError, match="sample identity"):
        derive_usage_high_water(_projection(sample, duplicate, receipt_object), KEY)
    other = _bundle("two", 11, adapter="adapter-2", sequence=20)
    reused_event = InvariantObject(other[0].contract_type, other[0].object_key, sample.event_id, other[0].global_sequence, other[0].payload_sha256, other[0].payload)
    with pytest.raises(UsageHighWaterError, match="sample identity"):
        derive_usage_high_water(_projection(sample, receipt_object, reused_event, *other[1:]), KEY)


def test_distinct_samples_and_receipts_can_share_one_transaction_sequence() -> None:
    """A ledger transaction sequence is not a unique event or sample identity."""
    first = _bundle("one", 20, adapter="adapter-1", sequence=10)
    second = _bundle("two", 30, adapter="adapter-2", sequence=10)
    left = derive_usage_high_water(_projection(*(first + second)), KEY)
    right = derive_usage_high_water(_projection(*reversed(first + second)), KEY)
    values = {item.dimension: item.tokens for item in left.dimensions}
    bound = {
        (item.contract_type, item.object_key, item.event_id, item.global_sequence)
        for item in left.evidence
    }
    assert left == right and left.observation_digest == right.observation_digest
    assert left.observation_state == "observed"
    assert "reset_or_reorder_ambiguous" not in left.reason_codes
    assert values == {
        "input": 28,
        "cache_read": 0,
        "cache_creation": 0,
        "output": 2,
        "reasoning_output": 0,
        "total": 30,
    }
    assert {(first[0].contract_type, first[0].object_key, first[0].event_id, 10),
            (first[1].contract_type, first[1].object_key, first[1].event_id, 10),
            (second[0].contract_type, second[0].object_key, second[0].event_id, 10),
            (second[1].contract_type, second[1].object_key, second[1].event_id, 10)} <= bound


def test_exact_duplicate_evidence_is_order_independent_and_rederives_identically() -> None:
    bundle = _bundle("one", 20)
    base = derive_usage_high_water(_projection(*bundle), KEY)
    duplicated = derive_usage_high_water(_projection(*(bundle + tuple(reversed(bundle)))), KEY)
    permuted = derive_usage_high_water(_projection(*reversed(bundle + tuple(reversed(bundle)))), KEY)
    assert duplicated == base == permuted
    assert duplicated.observation_digest == base.observation_digest == permuted.observation_digest


@pytest.mark.parametrize("forged_first", (False, True))
def test_duplicate_canonical_bytes_override_module_local_hash_collision(
    monkeypatch: pytest.MonkeyPatch,
    forged_first: bool,
) -> None:
    bundle = _bundle("one", 20)
    valid = bundle[0]
    forged_payload = copy.deepcopy(dict(valid.payload))
    forged_payload["total_token_vector"]["total"]["tokens"] = 99
    forged = InvariantObject(
        valid.contract_type, valid.object_key, valid.event_id, valid.global_sequence,
        valid.payload_sha256, forged_payload,
    )
    valid_bytes = canonical_company_json_bytes(valid.payload)
    forged_bytes = canonical_company_json_bytes(forged_payload)
    original_hash = company_contract_sha256

    def collision_hash(value: Any) -> str:
        if canonical_company_json_bytes(value) in {valid_bytes, forged_bytes}:
            return valid.payload_sha256
        return original_hash(value)

    monkeypatch.setattr(high_water, "company_contract_sha256", collision_hash)
    base = derive_usage_high_water(_projection(*bundle), KEY)
    duplicated = derive_usage_high_water(_projection(*(bundle + tuple(reversed(bundle)))), KEY)
    assert duplicated == base
    objects = (forged, valid) if forged_first else (valid, forged)
    with pytest.raises(UsageHighWaterError, match="duplicate invariant object payload differs"):
        derive_usage_high_water(_projection(*objects), KEY)


@pytest.mark.parametrize("forged_first", (False, True))
def test_duplicate_sample_metadata_with_divergent_payload_fails_independent_of_order(
    forged_first: bool,
) -> None:
    receipt = _receipt("one")
    valid = _object(_sample(receipt, 20), 10)
    forged_payload = copy.deepcopy(dict(valid.payload))
    forged_payload["total_token_vector"]["total"]["tokens"] = 99
    forged = InvariantObject(
        valid.contract_type, valid.object_key, valid.event_id, valid.global_sequence,
        valid.payload_sha256, forged_payload,
    )
    objects = (forged, valid) if forged_first else (valid, forged)
    with pytest.raises(UsageHighWaterError, match="duplicate invariant object payload differs"):
        derive_usage_high_water(_projection(*objects), KEY)


@pytest.mark.parametrize("forged_first", (False, True))
def test_duplicate_receipt_metadata_with_divergent_payload_fails_independent_of_order(
    forged_first: bool,
) -> None:
    valid = _object(_receipt("one"), 10)
    forged_payload = copy.deepcopy(dict(valid.payload))
    forged_payload["received_at"] = "2026-07-29T00:00:01Z"
    forged = InvariantObject(
        valid.contract_type, valid.object_key, valid.event_id, valid.global_sequence,
        valid.payload_sha256, forged_payload,
    )
    objects = (forged, valid) if forged_first else (valid, forged)
    with pytest.raises(UsageHighWaterError, match="duplicate invariant object payload differs"):
        derive_usage_high_water(_projection(*objects), KEY)


def test_later_sequence_decrease_remains_degraded_after_a_higher_lower_bound() -> None:
    first = _bundle("one", 30, adapter="adapter-1", sequence=10)
    lower = _bundle("two", 20, adapter="adapter-2", sequence=20)
    higher = _bundle("three", 40, adapter="adapter-3", sequence=30)
    observation = derive_usage_high_water(_projection(*first, *lower, *higher), KEY)
    assert _total(observation) == 40
    assert observation.observation_state == "degraded"
    assert "reset_or_reorder_ambiguous" in observation.reason_codes
    dimensions = {item.dimension: item for item in observation.dimensions}
    assert "reset_or_reorder_ambiguous" in dimensions["input"].reason_codes
    assert "reset_or_reorder_ambiguous" in dimensions["total"].reason_codes


def test_non_usage_coverage_anchor_cannot_qualify() -> None:
    receipt = _receipt("one")
    sample = _object(_sample(receipt, 10), 10)
    receipt_object = _object(receipt, 10)
    anchor = _receipt("anchor")
    anchor["normalized_kind"] = "thread_waiting_on_user_input"
    _rehash(anchor, "receipt_sha256")
    coverage = _coverage(receipt)
    coverage["last_receipt_id"] = anchor["receipt_id"]
    _rehash(coverage, "coverage_sha256")
    observation = derive_usage_high_water(_projection(sample, receipt_object, _object(anchor, 10), _object(coverage, 11)), KEY)
    assert observation.observation_state == "degraded"


def test_noncanonical_other_thread_coverage_anchor_cannot_qualify() -> None:
    receipt = _receipt("one")
    sample = _object(_sample(receipt, 10), 10)
    receipt_object = _object(receipt, 10)
    foreign = _receipt("foreign", thread="other-thread")
    foreign["receipt_id"] = "noncanonical-foreign-receipt"
    _rehash(foreign, "receipt_sha256")
    coverage = _coverage(foreign)
    observation = derive_usage_high_water(
        _projection(sample, receipt_object, _object(foreign, 12), _object(coverage, 13)), KEY,
    )
    assert observation.observation_state == "degraded"
    assert "usage_coverage_missing" in observation.reason_codes


def test_missing_divergent_and_reused_receipts_fail_closed() -> None:
    receipt = _receipt("one")
    sample = _object(_sample(receipt, 10), 10)
    with pytest.raises(UsageHighWaterError, match="no referenced"):
        derive_usage_high_water(_projection(sample), KEY)
    divergent = copy.deepcopy(receipt)
    divergent["received_at"] = "2026-07-29T00:00:01Z"
    _rehash(divergent, "receipt_sha256")
    with pytest.raises(UsageHighWaterError, match="receipt join differs"):
        derive_usage_high_water(_projection(sample, _object(divergent, 10)), KEY)
    with pytest.raises(UsageHighWaterError, match="receipt join differs"):
        derive_usage_high_water(_projection(sample, _object(receipt, 11)), KEY)
    duplicate = copy.deepcopy(receipt)
    duplicate["receipt_id"] = "receipt-two"
    _rehash(duplicate, "receipt_sha256")
    with pytest.raises(UsageHighWaterError, match="duplicate telemetry receipt occurrence"):
        derive_usage_high_water(_projection(sample, _object(receipt, 10), _object(duplicate, 11)), KEY)


def test_coverage_anchor_handles_offset_equivalence_and_missing_last_as_degraded() -> None:
    receipt = _receipt("one")
    sample = _object(_sample(receipt, 10), 10)
    receipt_object = _object(receipt, 10)
    equivalent = _coverage(receipt)
    equivalent["last_received_at"] = "2026-07-29T08:00:00+08:00"
    _rehash(equivalent, "coverage_sha256")
    assert derive_usage_high_water(_projection(sample, receipt_object, _object(equivalent, 11)), KEY).observation_state == "observed"
    missing = _coverage(receipt, state="unavailable")
    assert derive_usage_high_water(_projection(sample, receipt_object, _object(missing, 11)), KEY).observation_state == "degraded"


def test_equal_maxima_are_deterministic_and_last_vector_is_ignored() -> None:
    first = list(_bundle("one", 20, adapter="adapter-1", sequence=10))
    second = list(_bundle("two", 20, adapter="adapter-2", sequence=20))
    payload = copy.deepcopy(dict(first[0].payload))
    payload["last_token_vector"] = _vector(999_999_999)
    first[0] = _object(_rehash(payload, "sample_sha256"), 10)
    observation = derive_usage_high_water(_projection(*reversed(first + second)), KEY)
    total = next(item for item in observation.dimensions if item.dimension == "total")
    assert total.tokens == 20 and total.winning_sample_ids == tuple(sorted((first[0].payload["sample_id"], second[0].payload["sample_id"])))


def test_permutation_mixed_vector_and_routing_drift_remain_one_unattributed_scope() -> None:
    first_receipt = _receipt("one", adapter="adapter-1")
    second_receipt = _receipt("two", adapter="adapter-2")
    second_receipt["facts"]["actual_model"] = _fact("model-b", source="provider_payload", quality="observed", reason="provider_model")
    second_receipt["facts"]["actual_effort"] = _fact("high", source="provider_payload", quality="observed", reason="provider_effort")
    second_receipt["facts"]["routing"] = _fact({"kind": "model_reroute", "requested_model": None, "requested_effort": None, "tool": None, "status": None, "from_model": "model-a", "to_model": "model-b"}, source="provider_payload", quality="observed", reason="provider_reroute")
    _rehash(second_receipt, "receipt_sha256")
    first = (_object(_sample(first_receipt, 20), 10), _object(first_receipt, 10), _object(_coverage(first_receipt), 11))
    mixed = _sample(second_receipt, 12)
    mixed["total_token_vector"]["input"]["tokens"] = 30
    mixed["total_token_vector"]["output"]["tokens"] = 1
    _rehash(mixed, "sample_sha256")
    second = (_object(mixed, 20), _object(second_receipt, 20), _object(_coverage(second_receipt), 21))
    left = derive_usage_high_water(_projection(*(first + second)), KEY)
    right = derive_usage_high_water(_projection(*reversed(first + second)), KEY)
    values = {item.dimension: item.tokens for item in left.dimensions}
    assert left == right and left.observation_digest == right.observation_digest
    assert (values["input"], values["output"], values["total"], left.attribution_quality) == (30, 2, 20, "unavailable")


def test_legacy_usage_event_and_child_counter_scope_are_ignored() -> None:
    parent = _bundle("parent", 12, adapter="adapter-1", sequence=10)
    child_receipt = _receipt("child", adapter="adapter-2", thread="thread-child")
    child = (_object(_sample(child_receipt, 99), 20), _object(child_receipt, 20), _object(_coverage(child_receipt), 21))
    legacy = InvariantObject("usage_event_v1", "legacy-1", "legacy-event-1", 99, H, {"not": "read"})
    observation = derive_usage_high_water(_projection(*parent, *child, legacy), KEY)
    assert _total(observation) == 12
    assert all(item.contract_type != "usage_event_v1" for item in observation.evidence)


def test_generation_zero_is_valid_and_child_scope_is_ignored() -> None:
    zero = UsageCounterScopeKey("company-1", 1, 0, "codex", "thread-1")
    bundle = _bundle("zero", 12, key=zero)
    child_receipt = _receipt("child", key=zero, adapter="adapter-2", thread="thread-child")
    child = (_object(_sample(child_receipt, 99, key=zero), 20), _object(child_receipt, 20), _object(_coverage(child_receipt, key=zero), 21))
    observation = derive_usage_high_water(_projection(*bundle, *child), zero)
    assert _total(observation) == 12 and observation.aggregation_quality == "parent_child_overlap_unproven"


def test_decrease_optional_missing_and_unobserved_scope_are_honest() -> None:
    first = _bundle("one", 20, adapter="adapter-1", sequence=10)
    receipt = _receipt("two", adapter="adapter-2")
    sample = _sample(receipt, 10, cache_creation=None)
    second = (_object(sample, 20), _object(receipt, 20), _object(_coverage(receipt), 21))
    observation = derive_usage_high_water(_projection(*first, *second), KEY)
    assert observation.observation_state == "degraded"
    assert {"reset_or_reorder_ambiguous", "token_dimension_missingness"}.issubset(observation.reason_codes)
    empty = derive_usage_high_water(_projection(), KEY)
    assert empty.quantity_classification == "unavailable" and empty.selected_evidence_max_global_sequence is None


def test_bad_key_and_projection_metadata_are_typed_fail_closed() -> None:
    with pytest.raises(UsageHighWaterError):
        derive_usage_high_water(_projection(), UsageCounterScopeKey("company-1", 1_000_000_000, 0, "codex", "thread-1"))
    malformed = InvariantObject(USAGE_COUNTER_SAMPLE_V1, "sample-1", "event-1", True, H, {})
    with pytest.raises(UsageHighWaterError):
        derive_usage_high_water(_projection(malformed), KEY)
    uninitialized = object.__new__(InvariantObject)
    with pytest.raises(UsageHighWaterError):
        derive_usage_high_water(_projection(uninitialized), KEY)


@pytest.mark.parametrize("error_type", (AttributeError, StopIteration, CompanyContractError, RuntimeError, KeyError, TypeError, RecursionError))
def test_hostile_payload_exceptions_are_typed_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    def hostile(_: InvariantProjection) -> InvariantProjection:
        raise error_type("hostile payload")

    monkeypatch.setattr(high_water, "_expect_projection", hostile)
    with pytest.raises(UsageHighWaterError, match="payload processing failed"):
        derive_usage_high_water(_projection(), KEY)


@pytest.mark.parametrize("error_type", (KeyboardInterrupt, SystemExit, MemoryError))
def test_critical_exceptions_are_not_converted(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    def interrupt(_: InvariantProjection) -> InvariantProjection:
        raise error_type("do not swallow")

    monkeypatch.setattr(high_water, "_expect_projection", interrupt)
    with pytest.raises(error_type):
        derive_usage_high_water(_projection(), KEY)


def test_public_observation_validator_accepts_all_real_output_classes_and_is_company_typed() -> None:
    observed = derive_usage_high_water(_projection(*_bundle("one", 20)), KEY)
    degraded = derive_usage_high_water(_projection(*_bundle("one", 20), _object(_receipt("late"), 12)), KEY)
    unavailable = derive_usage_high_water(_projection(), KEY)
    for observation in (observed, degraded, unavailable):
        assert validate_usage_high_water_observation(observation, KEY) is observation
    with pytest.raises(CompanyContractError):
        validate_usage_high_water_observation(observed, UsageCounterScopeKey("company-1", 1, 1, "codex", "other-thread"))


def test_public_observation_validator_rejects_b164_carrier_counterexamples() -> None:
    observation = derive_usage_high_water(_projection(*_bundle("one", 20)), KEY)
    total_index = next(index for index, item in enumerate(observation.dimensions) if item.dimension == "total")
    bad_dimensions = list(observation.dimensions)
    bad_dimensions[total_index] = bad_dimensions[total_index]._replace(tokens=True)
    cases: tuple[object, ...] = (
        tuple(observation),
        observation._replace(dimensions=observation.dimensions[:-1]),
        observation._replace(dimensions=tuple(reversed(observation.dimensions))),
        observation._replace(dimensions=tuple(bad_dimensions)),
        observation._replace(selected_evidence_max_global_sequence=0),
        observation._replace(coverage=observation.coverage + observation.coverage),
        observation._replace(evidence=observation.evidence + observation.evidence[:1]),
        observation._replace(reason_codes=observation.reason_codes + ("unknown_reason",)),
        observation._replace(observation_digest="0" * 64),
    )
    for malformed in cases:
        with pytest.raises(UsageHighWaterError):
            validate_usage_high_water_observation(malformed, KEY)


def _redigest(observation: UsageHighWaterObservation) -> UsageHighWaterObservation:
    return observation._replace(observation_digest=company_contract_sha256(high_water._digest_payload(observation)))


def test_public_observation_validator_rejects_b166_recomputed_digest_matrix_counterexamples() -> None:
    observed = derive_usage_high_water(_projection(*_bundle("one", 20)), KEY)
    optional_missing = derive_usage_high_water(_projection(
        _object(_sample(_receipt("optional"), 20, cache_creation=None), 10),
        _object(_receipt("optional"), 10), _object(_coverage(_receipt("optional")), 11),
    ), KEY)
    empty = derive_usage_high_water(_projection(), KEY)
    coverage_reason_mismatch = observed.coverage[0]._replace(reason="adapter_gap")
    optional = next(item for item in optional_missing.dimensions if item.dimension == "cache_creation")
    bad_optional = tuple(
        item._replace(reason_codes=("counter_scope_unobserved",)) if item.dimension == "cache_creation" else item
        for item in optional_missing.dimensions
    )
    cases = (
        observed._replace(observation_state="unavailable", quantity_classification="unavailable"),
        observed._replace(observation_state="degraded"),
        observed._replace(coverage=(coverage_reason_mismatch,)),
        optional_missing._replace(dimensions=bad_optional),
        empty._replace(reason_codes=tuple(reason for reason in empty.reason_codes if reason != "counter_scope_unobserved")),
    )
    assert optional.reason_codes == ("optional_dimension_partial_or_missing",)
    for malformed in cases:
        with pytest.raises(UsageHighWaterError):
            validate_usage_high_water_observation(_redigest(malformed), KEY)


def test_public_observation_validator_enforces_b168_coverage_evidence_and_empty_missingness() -> None:
    observed = derive_usage_high_water(_projection(*_bundle("one", 20)), KEY)
    partial = derive_usage_high_water(_projection(
        *_bundle("one", 20, adapter="adapter-1", sequence=10),
        *_bundle("two", 30, adapter="adapter-2", sequence=20, coverage=False),
    ), KEY)
    empty = derive_usage_high_water(_projection(), KEY)
    for real_output in (observed, partial, empty):
        assert validate_usage_high_water_observation(real_output, KEY) is real_output
        assert real_output.projection_completeness == "unverified"
    assert "usage_coverage_missing" in partial.reason_codes
    no_coverage_summary = observed._replace(coverage=())
    no_coverage_evidence = tuple(
        item for item in observed.evidence if item.contract_type != PROVIDER_COVERAGE_REVISION_V1
    )
    summary_without_evidence = observed._replace(
        evidence=no_coverage_evidence,
        selected_evidence_max_global_sequence=max(item.global_sequence for item in no_coverage_evidence),
    )
    numeric_empty_without_reason = observed._replace(
        coverage=(), evidence=no_coverage_evidence,
        selected_evidence_max_global_sequence=max(item.global_sequence for item in no_coverage_evidence),
    )
    bogus_evidence = observed.evidence[:-1] + (
        observed.evidence[-1]._replace(contract_type="ZZ_BOGUS_EVIDENCE_V1"),
    )
    cases = (no_coverage_summary, summary_without_evidence, numeric_empty_without_reason,
             observed._replace(evidence=bogus_evidence))
    for malformed in cases:
        with pytest.raises(UsageHighWaterError):
            validate_usage_high_water_observation(_redigest(malformed), KEY)
