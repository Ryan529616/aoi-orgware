"""Pure reader-only QoS intent validation and B105 lower-bound advice.

This module neither binds a counter scope to a work item nor authorizes,
admits, stops, or accounts for work.  It only carries caller supplied intent
and B105 observation evidence in deterministic, immutable public values.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Any, NamedTuple, NoReturn, cast

from aoi_orgware.company.contracts import MAX_CONTRACT_BYTES, canonical_company_json_bytes
from aoi_orgware.company.invariants import InvariantProjection
from aoi_orgware.company.usage.high_water import (
    UsageCounterScopeKey,
    UsageHighWaterError,
    UsageHighWaterObservation,
    derive_usage_high_water,
    validate_usage_high_water_observation,
)


WORK_QOS_INTENT_V1 = "work_qos_intent_v1"
MAX_BUDGET = 1_000_000_000
MAX_RESOURCES = 8
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_BUDGETS = ("context", "input", "cache", "output", "reasoning", "tool")
_LATENCY = frozenset({"interactive", "standard", "batch"})
_FRESHNESS = frozenset({"fresh", "stale", "unknown"})
_VERIFY = frozenset({"required", "best_effort", "none"})
_PROVIDER = frozenset({"generic_api", "generic_local"})
_MODEL = frozenset({"generic_small", "generic_standard", "generic_large"})
_EFFORT = frozenset({"none", "low", "medium", "high"})
_KIND_UNITS = {"cpu": "cores", "memory": "mib", "accelerator": "count", "network": "mbps"}
_BINDING_QUALITY = "unavailable"
_BINDING_REASON = "counter_scope_to_work_binding_not_authoritatively_available"
CONFIGURED_CAPACITY_SEMANTICS = "operator_configured_reference_not_provider_quota"


class WorkQoSIntentV1Error(ValueError):
    """The supplied reader-only QoS value is malformed."""


class IntentScopeV1(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    task_id: str
    packet_id: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


class UsageScopeV1(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    provider: str
    counter_scope_id: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


class BudgetV1(NamedTuple):
    budget: int
    reserve: int

    def to_dict(self) -> dict[str, int]:
        return {"budget": self.budget, "reserve": self.reserve}


class ContextBindingV1(NamedTuple):
    """Frozen V2 semantic and V1 carrier identities, not transport evidence."""

    context_v2_semantic_sha256: str
    v1_carrier_sha256: str
    v1_carrier_size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


class FreshnessV1(NamedTuple):
    state: str
    clock: str
    expires_at: str

    def to_dict(self) -> dict[str, str]:
        return dict(self._asdict())


class ResourceBoundV1(NamedTuple):
    kind: str
    unit: str
    minimum: int
    maximum: int

    def to_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


class ConfiguredCapacityV1(NamedTuple):
    """Operator-configured reference only; never a provider quota."""

    configured_capacity_id: str
    configured_capacity_tokens: int
    configured_capacity_semantics: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


class WorkQoSIntentV1(NamedTuple):
    intent_scope: IntentScopeV1
    usage_scope: UsageScopeV1
    intent_revision: int
    intent_digest: str
    context_binding: ContextBindingV1
    configured_capacity: ConfiguredCapacityV1
    budgets: tuple[tuple[str, BudgetV1], ...]
    latency_class: str
    deadline_at: str
    freshness: FreshnessV1
    verification_requirement: str
    provider_class: str
    model_class: str
    effort_class: str
    resources: tuple[ResourceBoundV1, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": WORK_QOS_INTENT_V1, "schema_version": 1,
            "intent_scope": self.intent_scope.to_dict(), "usage_scope": self.usage_scope.to_dict(),
            "intent_revision": self.intent_revision, "intent_digest": self.intent_digest,
            "context_binding": self.context_binding.to_dict(),
            "configured_capacity": self.configured_capacity.to_dict(),
            "budgets": {name: item.to_dict() for name, item in self.budgets},
            "latency_class": self.latency_class, "deadline_at": self.deadline_at,
            "freshness": self.freshness.to_dict(),
            "verification_requirement": self.verification_requirement,
            "provider_class": self.provider_class, "model_class": self.model_class,
            "effort_class": self.effort_class,
            "resources": [item.to_dict() for item in self.resources],
        }


class TokenPressureAdvisoryV1(NamedTuple):
    """One-way advisory derived from an exact B105 usage scope only."""

    intent_scope: IntentScopeV1
    usage_scope: UsageScopeV1
    intent_digest: str
    configured_capacity: ConfiguredCapacityV1
    advisory_state: str
    pressure_band: str
    total_observed_lower_bound: int | None
    threshold_percent: int | None
    observation_state: str
    quantity_classification: str
    reset_or_reorder_ambiguous: bool
    coverage_states: tuple[str, ...]
    coverage_reasons: tuple[str, ...]
    missingness_reason_codes: tuple[str, ...]
    observation_reason_codes: tuple[str, ...]
    observation_digest: str
    counter_scope_to_work_binding_quality: str
    counter_scope_to_work_binding_reason: str
    advisory_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_scope": self.intent_scope.to_dict(), "usage_scope": self.usage_scope.to_dict(),
            "intent_digest": self.intent_digest, "advisory_state": self.advisory_state,
            "configured_capacity": self.configured_capacity.to_dict(),
            "pressure_band": self.pressure_band,
            "total_observed_lower_bound": self.total_observed_lower_bound,
            "threshold_percent": self.threshold_percent,
            "observation_state": self.observation_state,
            "quantity_classification": self.quantity_classification,
            "reset_or_reorder_ambiguous": self.reset_or_reorder_ambiguous,
            "coverage_states": list(self.coverage_states), "coverage_reasons": list(self.coverage_reasons),
            "missingness_reason_codes": list(self.missingness_reason_codes),
            "observation_reason_codes": list(self.observation_reason_codes),
            "observation_digest": self.observation_digest,
            "counter_scope_to_work_binding_quality": self.counter_scope_to_work_binding_quality,
            "counter_scope_to_work_binding_reason": self.counter_scope_to_work_binding_reason,
            "advisory_digest": self.advisory_digest,
        }


def _fail(message: str) -> NoReturn:
    raise WorkQoSIntentV1Error(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields):
        _fail(f"{label} schema is invalid")
    if any(type(key) is not str for key in value) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return value.copy()


def _sequence(value: Any, label: str, maximum: int) -> list[Any] | tuple[Any, ...]:
    if type(value) not in {list, tuple} or len(value) > maximum:
        _fail(f"{label} is invalid")
    return cast(list[Any] | tuple[Any, ...], value)


def _id(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _integer(value: Any, label: str, maximum: int = MAX_BUDGET, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> tuple[str, datetime]:
    if type(value) is not str or not _UTC.fullmatch(value):
        _fail(f"{label} must be canonical UTC")
    try:
        return value, datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise WorkQoSIntentV1Error(f"{label} must be canonical UTC") from exc


def _company_binding(item: dict[str, Any], label: str) -> tuple[str, int, int]:
    return (
        _id(item["company_id"], f"{label}.company_id"),
        _integer(item["company_incarnation"], f"{label}.company_incarnation", 999_999_999, 1),
        _integer(item["lock_domain_generation"], f"{label}.lock_domain_generation", 999_999_999),
    )


def _intent_scope(value: Any) -> IntentScopeV1:
    item = _object(value, {"company_id", "company_incarnation", "lock_domain_generation", "task_id", "packet_id"}, "intent_scope")
    company_id, incarnation, generation = _company_binding(item, "intent_scope")
    return IntentScopeV1(company_id, incarnation, generation, _id(item["task_id"], "intent_scope.task_id"), _id(item["packet_id"], "intent_scope.packet_id"))


def _usage_scope(value: Any, intent_scope: IntentScopeV1) -> UsageScopeV1:
    item = _object(value, {"company_id", "company_incarnation", "lock_domain_generation", "provider", "counter_scope_id"}, "usage_scope")
    binding = _company_binding(item, "usage_scope")
    if binding != intent_scope[:3]:
        _fail("usage_scope company binding differs from intent_scope")
    provider = _id(item["provider"], "usage_scope.provider")
    if provider != "codex":
        _fail("usage_scope.provider is not the exact B105 provider")
    return UsageScopeV1(*binding, provider, _id(item["counter_scope_id"], "usage_scope.counter_scope_id"))


def _context_binding(value: Any) -> ContextBindingV1:
    item = _object(value, {"context_v2_semantic_sha256", "v1_carrier_sha256", "v1_carrier_size_bytes"}, "context_binding")
    return ContextBindingV1(
        _digest(item["context_v2_semantic_sha256"], "context_binding.context_v2_semantic_sha256"),
        _digest(item["v1_carrier_sha256"], "context_binding.v1_carrier_sha256"),
        _integer(item["v1_carrier_size_bytes"], "context_binding.v1_carrier_size_bytes", MAX_CONTRACT_BYTES, 1),
    )


def _configured_capacity(value: Any) -> ConfiguredCapacityV1:
    item = _object(value, {"configured_capacity_id", "configured_capacity_tokens"}, "configured_capacity")
    return ConfiguredCapacityV1(
        _id(item["configured_capacity_id"], "configured_capacity.configured_capacity_id"),
        _integer(item["configured_capacity_tokens"], "configured_capacity.configured_capacity_tokens", MAX_BUDGET, 1),
        CONFIGURED_CAPACITY_SEMANTICS,
    )


def _budgets(value: Any) -> tuple[tuple[str, BudgetV1], ...]:
    item = _object(value, set(_BUDGETS), "budgets")
    result: list[tuple[str, BudgetV1]] = []
    for name in _BUDGETS:
        bound = _object(item[name], {"budget", "reserve"}, f"budgets.{name}")
        budget = _integer(bound["budget"], f"budgets.{name}.budget")
        reserve = _integer(bound["reserve"], f"budgets.{name}.reserve")
        if reserve > budget:
            _fail(f"budgets.{name}.reserve exceeds budget")
        result.append((name, BudgetV1(budget, reserve)))
    return tuple(result)


def _freshness(value: Any) -> FreshnessV1:
    item = _object(value, {"state", "clock", "expires_at"}, "freshness")
    if type(item["state"]) is not str or item["state"] not in _FRESHNESS:
        _fail("freshness.state is invalid")
    clock, clock_dt = _utc(item["clock"], "freshness.clock")
    expires, expires_dt = _utc(item["expires_at"], "freshness.expires_at")
    expected = "fresh" if clock_dt < expires_dt else "stale"
    if item["state"] not in {"unknown", expected}:
        _fail("freshness.state differs from clock and expiry")
    return FreshnessV1(item["state"], clock, expires)


def _resources(value: Any) -> tuple[ResourceBoundV1, ...]:
    values = _sequence(value, "resources", MAX_RESOURCES)
    result: list[ResourceBoundV1] = []
    for index, raw in enumerate(values):
        item = _object(raw, {"kind", "unit", "minimum", "maximum"}, f"resources[{index}]")
        kind, unit = item["kind"], item["unit"]
        if type(kind) is not str or type(unit) is not str or _KIND_UNITS.get(kind) != unit:
            _fail(f"resources[{index}] has invalid generic kind or unit")
        minimum = _integer(item["minimum"], f"resources[{index}].minimum")
        maximum = _integer(item["maximum"], f"resources[{index}].maximum")
        if minimum > maximum:
            _fail(f"resources[{index}] minimum exceeds maximum")
        result.append(ResourceBoundV1(kind, unit, minimum, maximum))
    ordered = tuple(sorted(result, key=lambda item: item.kind))
    if len({item.kind for item in ordered}) != len(ordered):
        _fail("resources contain duplicate kinds")
    return ordered


def _validate(value: Any, check_digest: bool) -> WorkQoSIntentV1:
    fields = {
        "document_type", "schema_version", "intent_scope", "usage_scope", "intent_revision", "intent_digest",
        "context_binding", "configured_capacity", "budgets", "latency_class", "deadline_at", "freshness", "verification_requirement",
        "provider_class", "model_class", "effort_class", "resources",
    }
    item = _object(value, fields, "WorkQoSIntentV1")
    if (type(item["document_type"]) is not str or item["document_type"] != WORK_QOS_INTENT_V1
            or _integer(item["schema_version"], "schema_version", 1, 1) != 1):
        _fail("WorkQoSIntentV1 header is invalid")
    intent_scope = _intent_scope(item["intent_scope"])
    usage_scope = _usage_scope(item["usage_scope"], intent_scope)
    if type(item["latency_class"]) is not str or item["latency_class"] not in _LATENCY:
        _fail("latency_class is invalid")
    if type(item["verification_requirement"]) is not str or item["verification_requirement"] not in _VERIFY:
        _fail("verification_requirement is invalid")
    if (type(item["provider_class"]) is not str or type(item["model_class"]) is not str
            or type(item["effort_class"]) is not str or item["provider_class"] not in _PROVIDER
            or item["model_class"] not in _MODEL or item["effort_class"] not in _EFFORT):
        _fail("generic provider/model/effort envelope is invalid")
    deadline, deadline_dt = _utc(item["deadline_at"], "deadline_at")
    freshness = _freshness(item["freshness"])
    if deadline_dt < datetime.fromisoformat(freshness.clock.replace("Z", "+00:00")).astimezone(timezone.utc):
        _fail("deadline_at precedes freshness.clock")
    result = WorkQoSIntentV1(
        intent_scope, usage_scope, _integer(item["intent_revision"], "intent_revision", 999_999_999, 1),
        _digest(item["intent_digest"], "intent_digest"), _context_binding(item["context_binding"]),
        _configured_capacity(item["configured_capacity"]), _budgets(item["budgets"]), item["latency_class"], deadline, freshness,
        item["verification_requirement"], item["provider_class"], item["model_class"],
        item["effort_class"], _resources(item["resources"]),
    )
    if check_digest and result.intent_digest != _preimage_digest(result):
        _fail("intent_digest differs")
    return result


def _preimage_digest(value: WorkQoSIntentV1) -> str:
    payload = value.to_dict()
    payload["intent_digest"] = "0" * 64
    return hashlib.sha256(canonical_company_json_bytes(payload)).hexdigest()


def validate_work_qos_intent_v1(value: Any) -> WorkQoSIntentV1:
    """Return a detached immutable reader-only intent; its digest is not authority."""
    return _validate(value, True)


def work_qos_intent_v1_preimage_sha256(value: Any) -> str:
    if type(value) is not dict:
        _fail("QoS intent preimage requires a mapping")
    candidate = value.copy()
    candidate["intent_digest"] = "0" * 64
    return _preimage_digest(_validate(candidate, False))


def canonical_work_qos_intent_v1_bytes(value: Any) -> bytes:
    """Return deterministic bytes only; this creates no transport or receipt."""
    return canonical_company_json_bytes(validate_work_qos_intent_v1(value).to_dict())


def work_qos_intent_v1_sha256(value: Any) -> str:
    """Return an integrity digest only, never an authority token."""
    return hashlib.sha256(canonical_work_qos_intent_v1_bytes(value)).hexdigest()


def _advisory_digest(value: TokenPressureAdvisoryV1) -> str:
    payload = value.to_dict()
    payload["advisory_digest"] = "0" * 64
    return hashlib.sha256(canonical_company_json_bytes({
        "derivation_domain": "aoi.scheduling.token-pressure-advisory.v1", "advisory": payload,
    })).hexdigest()


def _missingness(reasons: tuple[str, ...]) -> tuple[str, ...]:
    markers = ("missing", "unavailable", "unobserved", "completeness")
    return tuple(reason for reason in reasons if any(marker in reason for marker in markers))


def _advisory(qos: WorkQoSIntentV1, observation: Any, total: int | None, state: str, band: str, threshold: int | None) -> TokenPressureAdvisoryV1:
    reasons = tuple(sorted(set(observation.reason_codes)))
    coverage_states = tuple(sorted(item.state for item in observation.coverage))
    coverage_reasons = tuple(sorted(item.reason for item in observation.coverage))
    reset = "reset_or_reorder_ambiguous" in reasons or any(
        "reset_or_reorder_ambiguous" in item.reason_codes for item in observation.dimensions
    )
    provisional = TokenPressureAdvisoryV1(
        qos.intent_scope, qos.usage_scope, qos.intent_digest, qos.configured_capacity, state, band, total, threshold,
        observation.observation_state, observation.quantity_classification, reset,
        coverage_states, coverage_reasons, _missingness(reasons), reasons,
        observation.observation_digest, _BINDING_QUALITY, _BINDING_REASON, "",
    )
    return provisional._replace(advisory_digest=_advisory_digest(provisional))


def derive_token_pressure_advisory(intent: Any, projection: InvariantProjection) -> TokenPressureAdvisoryV1:
    """Retain B105's numeric exact-scope lower bound without a control decision."""
    qos = validate_work_qos_intent_v1(intent)
    key = UsageCounterScopeKey(*qos.usage_scope)
    try:
        observation = validate_usage_high_water_observation(derive_usage_high_water(projection, key), key)
    except WorkQoSIntentV1Error:
        raise
    except (UsageHighWaterError, AttributeError, StopIteration, RuntimeError, KeyError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise WorkQoSIntentV1Error(f"token advisory B105 derivation is invalid: {exc}") from exc
    total_dimension = next((item for item in observation.dimensions if item.dimension == "total"), None)
    total = None
    if (
        observation.observation_state != "unavailable"
        and observation.quantity_classification == "observed_lower_bound" and total_dimension is not None
        and total_dimension.availability == "observed_lower_bound" and type(total_dimension.tokens) is int
    ):
        total = total_dimension.tokens
    if total is None:
        return _advisory(qos, observation, None, "not_proven", "unavailable", None)
    capacity = qos.configured_capacity.configured_capacity_tokens
    if total >= capacity:
        return _advisory(qos, observation, total, "advisory_only", "at_or_above_100_lower_bound", 100)
    if total * 10 >= capacity * 9:
        return _advisory(qos, observation, total, "advisory_only", "at_or_above_90_lower_bound", 90)
    if total * 10 >= capacity * 7:
        return _advisory(qos, observation, total, "advisory_only", "at_or_above_70_lower_bound", 70)
    return _advisory(qos, observation, total, "not_proven_crossed", "unproven_crossing", None)
