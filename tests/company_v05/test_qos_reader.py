"""AOI-SYNTHETIC-FIXTURE-V1: pure QoS reader contract fixtures only."""
from __future__ import annotations

import copy
from typing import Any, cast

import pytest

from aoi_orgware.company.invariants import InvariantProjection
from aoi_orgware.company.contracts import company_contract_sha256
from aoi_orgware.company.scheduling import qos
from aoi_orgware.company.scheduling.qos import (
    WorkQoSIntentV1Error,
    canonical_work_qos_intent_v1_bytes,
    derive_token_pressure_advisory,
    validate_work_qos_intent_v1,
    work_qos_intent_v1_preimage_sha256,
    work_qos_intent_v1_sha256,
)
from aoi_orgware.company.usage.high_water import (
    TokenDimensionHighWater,
    UsageCounterScopeKey,
    UsageCoverageRevision,
    UsageEvidenceRef,
    UsageHighWaterObservation,
)
from aoi_orgware.company.usage import high_water


H = "a" * 64
KEY = UsageCounterScopeKey("company-1", 1, 2, "codex", "thread-1")


def _intent() -> dict[str, Any]:
    budgets = {name: {"budget": 0, "reserve": 0} for name in ("context", "input", "cache", "output", "reasoning", "tool")}
    budgets["context"] = {"budget": 100, "reserve": 10}
    value: dict[str, Any] = {
        "document_type": "work_qos_intent_v1", "schema_version": 1,
        "intent_scope": {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 2, "task_id": "task-1", "packet_id": "packet-1"},
        "usage_scope": {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 2, "provider": "codex", "counter_scope_id": "thread-1"},
        "intent_revision": 1, "intent_digest": "0" * 64,
        "context_binding": {"context_v2_semantic_sha256": H, "v1_carrier_sha256": "e" * 64, "v1_carrier_size_bytes": 17},
        "configured_capacity": {"configured_capacity_id": "operator-reference-1", "configured_capacity_tokens": 200},
        "budgets": budgets, "latency_class": "standard", "deadline_at": "2026-07-29T01:00:00Z",
        "freshness": {"state": "fresh", "clock": "2026-07-29T00:00:00Z", "expires_at": "2026-07-30T00:00:00Z"},
        "verification_requirement": "required", "provider_class": "generic_api", "model_class": "generic_standard",
        "effort_class": "medium", "resources": [{"kind": "cpu", "unit": "cores", "minimum": 1, "maximum": 2}],
    }
    value["intent_digest"] = work_qos_intent_v1_preimage_sha256(value)
    return value


def _observation(total: int | None, *, state: str = "observed", reasons: tuple[str, ...] = ()) -> UsageHighWaterObservation:
    base_reasons = {
        "ledger_head_not_bound", "terminal_counter_sample_unproven", "parent_child_overlap_unproven",
        "provider_order_unavailable", "attribution_unavailable", "projection_completeness_unverified",
    }
    coverage_state = "degraded" if state == "degraded" else "observed"
    coverage_reason = "adapter_gap" if coverage_state == "degraded" else "observed"
    coverage = UsageCoverageRevision("coverage-1", "revision-1", 1, coverage_state, coverage_reason, "coverage-1", "event-1", 1, H)
    evidence = (
        UsageEvidenceRef("provider_coverage_revision_v1", "coverage-1", "event-1", 1, H),
        UsageEvidenceRef("usage_counter_sample_v1", "sample-1", "sample-event-1", 1, H),
    ) if total is not None else (UsageEvidenceRef("provider_coverage_revision_v1", "coverage-1", "event-1", 1, H),)
    dimensions = tuple(
        TokenDimensionHighWater(name, total if name == "total" else 0, "observed_lower_bound", ("sample-1",), ("reset_or_reorder_ambiguous",) if "reset_or_reorder_ambiguous" in reasons and name == "total" else ())
        for name in ("input", "cache_read", "cache_creation", "output", "reasoning_output", "total")
    ) if total is not None else tuple(
        TokenDimensionHighWater(name, None, "unavailable", (), ("counter_scope_unobserved",))
        for name in ("input", "cache_read", "cache_creation", "output", "reasoning_output", "total")
    )
    all_reasons = base_reasons | set(reasons)
    if coverage_state == "degraded":
        all_reasons.add("usage_coverage_degraded")
    if total is None:
        all_reasons |= {"counter_scope_unobserved", "token_dimension_missingness"}
    provisional = UsageHighWaterObservation(
        KEY, state if total is not None else "unavailable", "observed_lower_bound" if total is not None else "unavailable",
        1, dimensions, (coverage,), evidence, "", tuple(sorted(all_reasons)),
        "projection_global_sequence_metadata_only", "unavailable", "unavailable", "parent_child_overlap_unproven",
        "unavailable", "unverified", "unverified",
    )
    return provisional._replace(observation_digest=company_contract_sha256(high_water._digest_payload(provisional)))


def _derive(monkeypatch: pytest.MonkeyPatch, observation: UsageHighWaterObservation) -> qos.TokenPressureAdvisoryV1:
    monkeypatch.setattr(qos, "derive_usage_high_water", lambda projection, key: observation)
    return derive_token_pressure_advisory(_intent(), cast(InvariantProjection, object()))


def test_exact_scopes_digest_and_renamed_carrier_identity() -> None:
    value = _intent()
    result = validate_work_qos_intent_v1(value)
    assert result.intent_scope.task_id == "task-1"
    assert result.usage_scope.counter_scope_id == "thread-1"
    assert result.context_binding.v1_carrier_sha256 == "e" * 64
    assert result.configured_capacity.to_dict() == {
        "configured_capacity_id": "operator-reference-1",
        "configured_capacity_tokens": 200,
        "configured_capacity_semantics": "operator_configured_reference_not_provider_quota",
    }
    assert "scope" not in result.to_dict() and "v1_transport_digest" not in result.to_dict()["context_binding"]
    changed = copy.deepcopy(value)
    changed["usage_scope"]["counter_scope_id"] = "thread-2"
    with pytest.raises(WorkQoSIntentV1Error, match="intent_digest"):
        validate_work_qos_intent_v1(changed)
    mismatch = _intent()
    mismatch["usage_scope"]["company_id"] = "company-2"
    with pytest.raises(WorkQoSIntentV1Error, match="company binding"):
        validate_work_qos_intent_v1(mismatch)
    ambiguous = _intent()
    ambiguous["configured_capacity"]["configured_capacity_semantics"] = "caller_selected"
    with pytest.raises(WorkQoSIntentV1Error, match="configured_capacity schema"):
        validate_work_qos_intent_v1(ambiguous)


def test_namedtuple_values_are_deeply_immutable_and_caller_detached() -> None:
    value = _intent()
    result = validate_work_qos_intent_v1(value)
    value["budgets"]["context"]["budget"] = 1
    assert dict(result.budgets)["context"].budget == 100
    assert not hasattr(result, "__dict__") and not hasattr(result.intent_scope, "__dict__")
    for target, field, replacement in ((result, "intent_revision", 2), (result.intent_scope, "task_id", "other"), (dict(result.budgets)["context"], "budget", 1)):
        with pytest.raises((AttributeError, TypeError)):
            object.__setattr__(target, field, replacement)


@pytest.mark.parametrize("path,bad", [
    (("budgets", "context", "budget"), True), (("budgets", "context", "reserve"), True),
    (("budgets", "context", "reserve"), 101), (("intent_scope", "company_incarnation"), True),
    (("resources", 0, "minimum"), True), (("resources", 0, "maximum"), -1),
    (("configured_capacity", "configured_capacity_tokens"), True),
    (("configured_capacity", "configured_capacity_tokens"), 0),
])
def test_all_numeric_bounds_reject_bool_and_invalid_ranges(path: tuple[object, ...], bad: object) -> None:
    value = _intent()
    target: Any = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = bad
    with pytest.raises(WorkQoSIntentV1Error):
        validate_work_qos_intent_v1(value)


@pytest.mark.parametrize(("total", "state", "band", "threshold"), [
    (139, "not_proven_crossed", "unproven_crossing", None),
    (140, "advisory_only", "at_or_above_70_lower_bound", 70),
    (179, "advisory_only", "at_or_above_70_lower_bound", 70),
    (180, "advisory_only", "at_or_above_90_lower_bound", 90),
    (199, "advisory_only", "at_or_above_90_lower_bound", 90),
    (200, "advisory_only", "at_or_above_100_lower_bound", 100),
])
def test_configured_capacity_exact_integer_boundaries(monkeypatch: pytest.MonkeyPatch, total: int, state: str, band: str, threshold: int | None) -> None:
    result = _derive(monkeypatch, _observation(total))
    assert (result.advisory_state, result.pressure_band, result.threshold_percent) == (state, band, threshold)
    assert result.configured_capacity.to_dict() == {
        "configured_capacity_id": "operator-reference-1",
        "configured_capacity_tokens": 200,
        "configured_capacity_semantics": "operator_configured_reference_not_provider_quota",
    }


@pytest.mark.parametrize(("total", "band"), [(140, "at_or_above_70_lower_bound"), (180, "at_or_above_90_lower_bound"), (200, "at_or_above_100_lower_bound")])
def test_degraded_reset_reroute_coverage_and_missing_receipt_keep_crossed_lower_bound(monkeypatch: pytest.MonkeyPatch, total: int, band: str) -> None:
    observation = _observation(total, state="degraded", reasons=("reset_or_reorder_ambiguous", "usage_sample_missing_for_receipt"))
    result = _derive(monkeypatch, observation)
    assert (result.advisory_state, result.pressure_band, result.total_observed_lower_bound) == ("advisory_only", band, total)
    assert result.reset_or_reorder_ambiguous is True
    assert result.coverage_states == ("degraded",)
    assert "usage_sample_missing_for_receipt" in result.missingness_reason_codes


def test_degraded_numeric_below_threshold_is_only_not_proven_crossed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _derive(monkeypatch, _observation(139, state="degraded", reasons=("usage_coverage_degraded",)))
    assert result.total_observed_lower_bound == 139
    assert (result.advisory_state, result.pressure_band) == ("not_proven_crossed", "unproven_crossing")


def test_unavailable_and_hostile_b105_are_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    unavailable = _derive(monkeypatch, _observation(None, reasons=("counter_scope_unobserved",)))
    assert unavailable.total_observed_lower_bound is None and unavailable.advisory_state == "not_proven"
    monkeypatch.setattr(qos, "derive_usage_high_water", lambda projection, key: (_ for _ in ()).throw(TypeError("hostile")))
    with pytest.raises(WorkQoSIntentV1Error, match="B105 derivation"):
        derive_token_pressure_advisory(_intent(), cast(InvariantProjection, object()))


def test_recomputed_digest_unavailable_b105_carrier_cannot_reach_thresholds(monkeypatch: pytest.MonkeyPatch) -> None:
    observed = _observation(200)
    malformed = observed._replace(observation_state="unavailable")
    malformed = malformed._replace(observation_digest=company_contract_sha256(high_water._digest_payload(malformed)))
    monkeypatch.setattr(qos, "derive_usage_high_water", lambda projection, key: malformed)
    with pytest.raises(WorkQoSIntentV1Error, match="B105"):
        derive_token_pressure_advisory(_intent(), cast(InvariantProjection, object()))
    monkeypatch.setattr(qos, "validate_usage_high_water_observation", lambda value, key: malformed)
    result = _derive(monkeypatch, malformed)
    assert (result.advisory_state, result.pressure_band, result.threshold_percent) == ("not_proven", "unavailable", None)


@pytest.mark.parametrize("error_type", (AttributeError, StopIteration))
def test_b105_ordinary_exceptions_are_typed(monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]) -> None:
    def hostile(projection: InvariantProjection, key: UsageCounterScopeKey) -> UsageHighWaterObservation:
        raise error_type("hostile")

    monkeypatch.setattr(qos, "derive_usage_high_water", hostile)
    with pytest.raises(WorkQoSIntentV1Error, match="B105 derivation"):
        derive_token_pressure_advisory(_intent(), cast(InvariantProjection, object()))


@pytest.mark.parametrize("malformed", (
    None,
    object(),
    _observation(140)._replace(key=UsageCounterScopeKey("company-1", 1, 2, "codex", "thread-2")),
    _observation(140)._replace(dimensions=cast(tuple[TokenDimensionHighWater, ...], (object(),))),
    _observation(140)._replace(coverage=cast(tuple[UsageCoverageRevision, ...], (object(),))),
))
def test_malformed_b105_returns_are_typed_fail_closed(monkeypatch: pytest.MonkeyPatch, malformed: object) -> None:
    monkeypatch.setattr(qos, "derive_usage_high_water", lambda projection, key: malformed)
    with pytest.raises(WorkQoSIntentV1Error, match="B105"):
        derive_token_pressure_advisory(_intent(), cast(InvariantProjection, object()))


@pytest.mark.parametrize("error_type", (KeyboardInterrupt, SystemExit, MemoryError))
def test_b105_process_control_exceptions_propagate(monkeypatch: pytest.MonkeyPatch, error_type: type[BaseException]) -> None:
    def interrupt(projection: InvariantProjection, key: UsageCounterScopeKey) -> UsageHighWaterObservation:
        raise error_type("do not swallow")

    monkeypatch.setattr(qos, "derive_usage_high_water", interrupt)
    with pytest.raises(error_type):
        derive_token_pressure_advisory(_intent(), cast(InvariantProjection, object()))


def test_advisory_digest_binds_scopes_quality_and_observation_deterministically(monkeypatch: pytest.MonkeyPatch) -> None:
    observation = _observation(140, state="degraded", reasons=("usage_coverage_degraded", "usage_sample_missing_for_receipt"))
    first = _derive(monkeypatch, observation)
    second = _derive(monkeypatch, _observation(140, state="degraded", reasons=("usage_sample_missing_for_receipt",)))
    assert first.advisory_digest == second.advisory_digest
    assert first.counter_scope_to_work_binding_quality == "unavailable"
    assert first.counter_scope_to_work_binding_reason == "counter_scope_to_work_binding_not_authoritatively_available"
    changed = _intent()
    changed["intent_scope"]["packet_id"] = "packet-2"
    changed["intent_digest"] = work_qos_intent_v1_preimage_sha256(changed)
    changed_advisory = derive_token_pressure_advisory(changed, cast(InvariantProjection, object()))
    assert changed_advisory.advisory_digest != first.advisory_digest
    changed_capacity_id = _intent()
    changed_capacity_id["configured_capacity"]["configured_capacity_id"] = "operator-reference-2"
    changed_capacity_id["intent_digest"] = work_qos_intent_v1_preimage_sha256(changed_capacity_id)
    changed_capacity_tokens = _intent()
    changed_capacity_tokens["configured_capacity"]["configured_capacity_tokens"] = 201
    changed_capacity_tokens["intent_digest"] = work_qos_intent_v1_preimage_sha256(changed_capacity_tokens)
    id_intent = validate_work_qos_intent_v1(changed_capacity_id)
    tokens_intent = validate_work_qos_intent_v1(changed_capacity_tokens)
    assert id_intent.intent_digest != validate_work_qos_intent_v1(_intent()).intent_digest
    assert tokens_intent.intent_digest != validate_work_qos_intent_v1(_intent()).intent_digest
    id_advisory = derive_token_pressure_advisory(changed_capacity_id, cast(InvariantProjection, object()))
    tokens_advisory = derive_token_pressure_advisory(changed_capacity_tokens, cast(InvariantProjection, object()))
    assert id_advisory.advisory_digest != first.advisory_digest
    assert tokens_advisory.advisory_digest != first.advisory_digest
    fields = set(first.to_dict()) | set(validate_work_qos_intent_v1(_intent()).to_dict())
    forbidden = {"company_total", "company_sum", "cost", "usd", "quota", "remaining", "hard_stop", "admission", "stop_in_flight", "binding_witness"}
    assert fields.isdisjoint(forbidden)
    assert set(first.configured_capacity.to_dict()).isdisjoint(forbidden)
    assert canonical_work_qos_intent_v1_bytes(_intent()) == canonical_work_qos_intent_v1_bytes(_intent())
    assert work_qos_intent_v1_sha256(_intent()) == work_qos_intent_v1_sha256(_intent())
