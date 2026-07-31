"""Immutable resource-request content, deliberately without lifecycle authority.

This module records what a caller asked for after an exact private mapping
derivation.  It never publishes, reserves, admits, leases, or selects capacity.
"""
from __future__ import annotations

from datetime import datetime
import re
from typing import Any, NamedTuple, NoReturn, cast

from aoi_orgware.company.contracts import (
    MAX_CONTRACT_BYTES,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_task_revision,
    validate_work_packet,
)
from aoi_orgware.company.resources.inventory_contract import ResourceInventoryObservationV1
from aoi_orgware.company.resources.request_mapping import (
    ResourceMappingSelectionV1,
    ResourceRequirementMappingBundleV1,
    ResourceRequirementMappingError,
    validate_resource_requirement_mapping_bundle_v1,
)
from aoi_orgware.company.scheduling.qos import (
    ConfiguredCapacityV1,
    WorkQoSIntentV1,
    WorkQoSIntentV1Error,
    validate_work_qos_intent_v1,
)


MAX_MAPPED_VALUE = (1 << 63) - 1
MAX_CONTRACT_REVISION = 999_999_999
MAX_QOS_RESOURCE_VALUE = 1_000_000_000
MAX_REQUEST_REQUIREMENTS = 4
_SHA256_LENGTH = 64
_DOMAIN = "aoi.resources.request-content.v1"
_DEMAND_DOMAIN = "aoi.resources.request-content-demand.v1"
_REQUEST_ROLE = "request_content"
_FIXED_SEMANTICS = (
    "caller_supplied_unverified", "none", "none", "requires_separate_receipt",
    "unavailable", "not_evaluated", "not_evaluated", "not_evaluated",
    "not_evaluated", "not_created",
)
_UNITS = {"cpu": "cores", "memory": "mib", "accelerator": "count", "network": "mbps"}
_MAPPED = {"cpu": ("cpu", "millicore", 1_000), "memory": ("ram", "byte", 1_048_576), "accelerator": ("gpu", "slot", 1)}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_QOS_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_TASK_INPUT_SCALARS: tuple[tuple[str, type[Any]], ...] = (
    ("company_id", str), ("company_incarnation", int), ("lock_domain_generation", int),
    ("task_id", str), ("task_revision_id", str), ("revision", int),
    ("task_sha256", str), ("created_at", str),
)
_PACKET_INPUT_SCALARS: tuple[tuple[str, type[Any]], ...] = (
    ("company_id", str), ("company_incarnation", int), ("lock_domain_generation", int),
    ("packet_id", str), ("task_id", str), ("task_revision_id", str),
    ("task_sha256", str), ("packet_sha256", str), ("created_at", str), ("expires_at", str),
)


class ResourceRequestV1Error(ValueError):
    """Resource-request content is malformed or differs from exact derivation."""


class ResourceRequestRequirementV1(NamedTuple):
    """One original QoS resource range and its non-operational mapped form."""

    qos_kind: str
    qos_unit: str
    original_minimum: int
    original_maximum: int
    mapped_resource_kind: str | None
    mapped_resource_unit: str | None
    mapped_minimum: int | None
    mapped_maximum: int | None
    mapping_state: str
    resolution_state: str

    def to_dict(self) -> dict[str, object]:
        return dict(self._asdict())


class ResourceRequestV1(NamedTuple):
    """Private off-ledger content retaining the opaque canonical task revision ID.

    This is not a sanitized or public-export contract.  A later separate
    receipt owns any published request identifier and all lifecycle authority.
    """

    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    task_revision_id: str
    task_revision: int
    task_sha256: str
    packet_sha256: str
    qos_intent_revision: int
    qos_intent_digest: str
    qos_deadline_at: str
    mapping_bundle_sha256: str
    demand_sha256: str
    requirements: tuple[ResourceRequestRequirementV1, ...]
    contract_role: str
    provenance_quality: str
    authority_semantics: str
    operational_effect: str
    publication_semantics: str
    inventory_currentness: str
    capacity_state: str
    exclusivity_state: str
    policy_state: str
    admission_state: str
    lease_semantics: str
    request_sha256: str

    def to_dict(self) -> dict[str, object]:
        result = dict(self._asdict())
        result["requirements"] = [item.to_dict() for item in self.requirements]
        return result


def _fail(message: str) -> NoReturn:
    raise ResourceRequestV1Error(message)


def _exact_int(
    value: object, label: str, minimum: int = 0, maximum: int = MAX_MAPPED_VALUE,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} must be a bounded exact integer")
    return value


def _mapped_value(value: int, factor: int, label: str) -> int:
    if value > MAX_MAPPED_VALUE // factor:
        _fail(f"{label} exceeds mapped integer bounds")
    return value * factor


def _digest(value: object, label: str) -> str:
    if type(value) is not str or len(value) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in value):
        _fail(f"{label} must be lowercase SHA-256")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail(f"{label} must be an exact canonical identifier")
    return value


def _canonical_hash(value: object, label: str) -> str:
    try:
        if len(canonical_company_json_bytes(value)) > MAX_CONTRACT_BYTES:
            _fail(f"{label} exceeds canonical size bound")
        return company_contract_sha256(value)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except Exception as error:
        raise ResourceRequestV1Error(f"{label} canonicalization failed") from error


def _request_digest(value: ResourceRequestV1) -> str:
    payload = value.to_dict()
    payload["request_sha256"] = "0" * _SHA256_LENGTH
    return _canonical_hash({"derivation_domain": _DOMAIN, "request": payload}, "request")


def _demand_digest(requirements: tuple[ResourceRequestRequirementV1, ...]) -> str:
    return _canonical_hash({
        "derivation_domain": _DEMAND_DOMAIN,
        "resource_vector": [
            {"kind": item.qos_kind, "unit": item.qos_unit,
             "minimum": item.original_minimum, "maximum": item.original_maximum}
            for item in requirements
        ],
    }, "demand")


def _exact_input_scalars(
    value: dict[str, Any], label: str, expected: tuple[tuple[str, type[Any]], ...],
) -> None:
    for field, expected_type in expected:
        if type(value[field]) is not expected_type:
            _fail(f"{label}.{field} must be an exact {expected_type.__name__}")


def _validated_task(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("task revision must be an exact TaskRevision dictionary")
    try:
        _exact_input_scalars(value, "task revision", _TASK_INPUT_SCALARS)
        result = validate_task_revision(value)
        _exact_input_scalars(result, "task revision", _TASK_INPUT_SCALARS)
        if result != value:
            _fail("task revision differs from exact public canonical validation")
        return result
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except Exception as error:
        raise ResourceRequestV1Error("task revision validation failed") from error


def _validated_packet(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("work packet must be an exact WorkPacket dictionary")
    try:
        _exact_input_scalars(value, "work packet", _PACKET_INPUT_SCALARS)
        result = validate_work_packet(value)
        _exact_input_scalars(result, "work packet", _PACKET_INPUT_SCALARS)
        if result != value:
            _fail("work packet differs from exact public canonical validation")
        return result
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except Exception as error:
        raise ResourceRequestV1Error("work packet validation failed") from error


def _validated_qos(value: object) -> WorkQoSIntentV1:
    if type(value) is not WorkQoSIntentV1:
        _fail("qos intent must be an exact WorkQoSIntentV1")
    try:
        raw = value.to_dict()
        configured = cast(dict[str, object], raw["configured_capacity"])
        raw["configured_capacity"] = {
            "configured_capacity_id": configured["configured_capacity_id"],
            "configured_capacity_tokens": configured["configured_capacity_tokens"],
        }
        result = validate_work_qos_intent_v1(raw)
        if result != value or type(value.configured_capacity) is not ConfiguredCapacityV1:
            _fail("qos intent differs from exact public canonical validation")
        return result
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except Exception as error:
        raise ResourceRequestV1Error("qos intent validation failed") from error


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str:
        _fail(f"{label} must be a validated timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as error:
        raise ResourceRequestV1Error(f"{label} must be a validated timestamp") from error


def _qos_utc_timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or not _QOS_UTC.fullmatch(value):
        _fail(f"{label} must be a real canonical UTC QoS timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ResourceRequestV1Error(f"{label} must be a real canonical UTC QoS timestamp") from error


def _crossbind(task: dict[str, Any], packet: dict[str, Any], qos: WorkQoSIntentV1) -> None:
    task_company = (task["company_id"], task["company_incarnation"], task["lock_domain_generation"])
    packet_company = (packet["company_id"], packet["company_incarnation"], packet["lock_domain_generation"])
    qos_company = (qos.intent_scope.company_id, qos.intent_scope.company_incarnation, qos.intent_scope.lock_domain_generation)
    if task_company != packet_company or task_company != qos_company:
        _fail("task, packet, and qos company bindings differ")
    if (packet["task_id"], packet["task_revision_id"], packet["task_sha256"]) != (
        task["task_id"], task["task_revision_id"], task["task_sha256"],
    ):
        _fail("work packet task revision binding differs")
    if (qos.intent_scope.task_id, qos.intent_scope.packet_id) != (task["task_id"], packet["packet_id"]):
        _fail("qos task or packet binding differs")
    packet_created = _timestamp(packet["created_at"], "packet.created_at")
    packet_expires = _timestamp(packet["expires_at"], "packet.expires_at")
    qos_deadline = _qos_utc_timestamp(qos.deadline_at, "qos.deadline_at")
    if packet_created < _timestamp(task["created_at"], "task.created_at"):
        _fail("packet.created_at precedes task.created_at")
    if not packet_created <= qos_deadline <= packet_expires:
        _fail("qos.deadline_at is outside packet created and expiry bounds")


def _requirements_from_qos(
    qos: WorkQoSIntentV1, bundle: ResourceRequirementMappingBundleV1,
) -> tuple[ResourceRequestRequirementV1, ...]:
    candidates = {candidate.qos_kind: candidate for candidate in bundle.candidates}
    if len(candidates) != len(bundle.candidates) or set(candidates) != {bound.kind for bound in qos.resources}:
        _fail("mapping bundle resource witnesses do not exactly cover qos demand")
    result: list[ResourceRequestRequirementV1] = []
    for bound in qos.resources:
        if bound.minimum == 0 and bound.maximum == 0:
            _fail("named zero-to-zero resource demand is not request content")
        candidate = candidates[bound.kind]
        if candidate.qos_unit != bound.unit:
            _fail("mapping bundle qos unit differs from qos demand")
        if bound.kind == "network":
            result.append(ResourceRequestRequirementV1(
                bound.kind, bound.unit, bound.minimum, bound.maximum,
                None, None, None, None, "mapping_unavailable", "unresolved",
            ))
            continue
        mapped_kind, mapped_unit, factor = _MAPPED[bound.kind]
        if (candidate.mapped_resource_kind, candidate.mapped_resource_unit,
                candidate.mapped_minimum, candidate.mapped_maximum) != (
                mapped_kind, mapped_unit,
                _mapped_value(bound.minimum, factor, "mapped minimum"),
                _mapped_value(bound.maximum, factor, "mapped maximum"),
        ):
            _fail("mapping bundle converted resource demand differs")
        result.append(ResourceRequestRequirementV1(
            bound.kind, bound.unit, bound.minimum, bound.maximum,
            mapped_kind, mapped_unit, candidate.mapped_minimum, candidate.mapped_maximum,
            "mapping_candidate", "resolved",
        ))
    return tuple(result)


def _requirement_structure(value: object) -> ResourceRequestRequirementV1:
    if type(value) is not ResourceRequestRequirementV1:
        _fail("requirement must be an exact ResourceRequestRequirementV1")
    item = value
    if (type(item.qos_kind) is not str or type(item.qos_unit) is not str
            or type(item.mapping_state) is not str or type(item.resolution_state) is not str):
        _fail("requirement scalar strings must be exact")
    if _UNITS.get(item.qos_kind) != item.qos_unit:
        _fail("requirement qos kind or unit is invalid")
    minimum = _exact_int(
        item.original_minimum, "requirement.original_minimum", maximum=MAX_QOS_RESOURCE_VALUE,
    )
    maximum = _exact_int(
        item.original_maximum, "requirement.original_maximum", maximum=MAX_QOS_RESOURCE_VALUE,
    )
    if minimum > maximum or (minimum == 0 and maximum == 0):
        _fail("requirement original demand range is invalid")
    if item.qos_kind == "network":
        if any(field is not None for field in (
            item.mapped_resource_kind, item.mapped_resource_unit, item.mapped_minimum, item.mapped_maximum,
        )):
            _fail("network requirement mapped fields must be None")
        if (item.mapping_state, item.resolution_state) != ("mapping_unavailable", "unresolved"):
            _fail("network requirement must remain unresolved")
        return item
    mapped_kind, mapped_unit, factor = _MAPPED[item.qos_kind]
    if type(item.mapped_resource_kind) is not str or type(item.mapped_resource_unit) is not str:
        _fail("requirement mapped resource strings must be exact")
    mapped_minimum = _exact_int(item.mapped_minimum, "requirement.mapped_minimum")
    mapped_maximum = _exact_int(item.mapped_maximum, "requirement.mapped_maximum")
    if (item.mapped_resource_kind, item.mapped_resource_unit, item.mapping_state, item.resolution_state) != (
            mapped_kind, mapped_unit, "mapping_candidate", "resolved"):
        _fail("mapped requirement state is invalid")
    if (mapped_minimum, mapped_maximum) != (
            _mapped_value(minimum, factor, "mapped minimum"),
            _mapped_value(maximum, factor, "mapped maximum"),
    ):
        _fail("mapped requirement range is invalid")
    return item


def _structure(value: object) -> ResourceRequestV1:
    if type(value) is not ResourceRequestV1:
        _fail("request must be an exact ResourceRequestV1")
    try:
        item = value
        for name in ("company_id", "task_revision_id", "task_sha256", "packet_sha256", "qos_intent_digest",
                     "qos_deadline_at", "mapping_bundle_sha256", "demand_sha256", "contract_role",
                     "provenance_quality", "authority_semantics", "operational_effect", "publication_semantics",
                     "inventory_currentness", "capacity_state", "exclusivity_state", "policy_state", "admission_state",
                     "lease_semantics", "request_sha256"):
            if type(getattr(item, name)) is not str:
                _fail(f"request.{name} must be an exact string")
        _identifier(item.company_id, "request.company_id")
        _identifier(item.task_revision_id, "request.task_revision_id")
        _qos_utc_timestamp(item.qos_deadline_at, "request.qos_deadline_at")
        for name, minimum in (("company_incarnation", 1), ("lock_domain_generation", 0),
                              ("task_revision", 1), ("qos_intent_revision", 1)):
            _exact_int(
                getattr(item, name), f"request.{name}", minimum, MAX_CONTRACT_REVISION,
            )
        for name in ("task_sha256", "packet_sha256", "qos_intent_digest", "mapping_bundle_sha256", "demand_sha256", "request_sha256"):
            _digest(getattr(item, name), f"request.{name}")
        if type(item.requirements) is not tuple or len(item.requirements) > MAX_REQUEST_REQUIREMENTS:
            _fail("request requirements must be a bounded immutable tuple")
        requirements = tuple(_requirement_structure(entry) for entry in item.requirements)
        if requirements != tuple(sorted(requirements, key=lambda entry: entry.qos_kind)):
            _fail("request requirements are not canonical")
        if len({entry.qos_kind for entry in requirements}) != len(requirements):
            _fail("request requirements duplicate qos kinds")
        if item.demand_sha256 != _demand_digest(requirements):
            _fail("request demand SHA-256 differs")
        if (item.contract_role, item.provenance_quality, item.authority_semantics, item.operational_effect,
                item.publication_semantics, item.inventory_currentness, item.capacity_state, item.exclusivity_state,
                item.policy_state, item.admission_state, item.lease_semantics) != (_REQUEST_ROLE, *_FIXED_SEMANTICS):
            _fail("request permanent semantic boundary is invalid")
        if item.request_sha256 != _request_digest(item):
            _fail("request SHA-256 differs from canonical content")
        return item
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except Exception as error:
        raise ResourceRequestV1Error("request structural validation failed") from error


def validate_resource_request_structure_v1(request: object) -> ResourceRequestV1:
    """Validate local shape, digest, and permanent semantics only.

    This validates neither mapping witnesses nor task/packet/QoS crossbinding,
    and establishes no publication, lifecycle, or other authority.
    """
    return _structure(request)


def derive_resource_request_v1(
    task_revision: object,
    work_packet: object,
    qos_intent: object,
    mapping_bundle: object,
    inventory_observation: object,
    selections: object,
) -> ResourceRequestV1:
    """Derive immutable content from exact public inputs and one full mapping witness."""
    try:
        task = _validated_task(task_revision)
        packet = _validated_packet(work_packet)
        qos = _validated_qos(qos_intent)
        if type(mapping_bundle) is not ResourceRequirementMappingBundleV1:
            _fail("mapping bundle must be an exact ResourceRequirementMappingBundleV1")
        if type(inventory_observation) is not ResourceInventoryObservationV1:
            _fail("inventory observation must be an exact ResourceInventoryObservationV1")
        if type(selections) is not tuple or any(type(selection) is not ResourceMappingSelectionV1 for selection in selections):
            _fail("selections must be an exact tuple of ResourceMappingSelectionV1")
        bundle = validate_resource_requirement_mapping_bundle_v1(
            mapping_bundle, qos, inventory_observation, selections,
        )
        _crossbind(task, packet, qos)
        requirements = _requirements_from_qos(qos, bundle)
        provisional = ResourceRequestV1(
            task["company_id"], task["company_incarnation"], task["lock_domain_generation"],
            task["task_revision_id"], task["revision"], task["task_sha256"], packet["packet_sha256"],
            qos.intent_revision, qos.intent_digest, qos.deadline_at, bundle.bundle_sha256, _demand_digest(requirements),
            requirements, _REQUEST_ROLE, *_FIXED_SEMANTICS, "",
        )
        return _structure(
            provisional._replace(request_sha256=_request_digest(provisional))
        )
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except (ResourceRequirementMappingError, WorkQoSIntentV1Error) as error:
        raise ResourceRequestV1Error("resource request derivation input is invalid") from error
    except Exception as error:
        raise ResourceRequestV1Error("resource request derivation failed") from error


def validate_resource_request_v1(
    request: object,
    task_revision: object,
    work_packet: object,
    qos_intent: object,
    mapping_bundle: object,
    inventory_observation: object,
    selections: object,
) -> ResourceRequestV1:
    """Require an exact full mapping rederivation and exact request-content match."""
    try:
        item = _structure(request)
        derived = derive_resource_request_v1(
            task_revision, work_packet, qos_intent, mapping_bundle, inventory_observation, selections,
        )
        if item != derived:
            _fail("request differs from exact full witness-bound derivation")
        return item
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except ResourceRequestV1Error:
        raise
    except Exception as error:
        raise ResourceRequestV1Error("resource request semantic validation failed") from error
