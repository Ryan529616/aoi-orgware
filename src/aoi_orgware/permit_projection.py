"""Pure task-global transition-permit consumption projections.

This module deliberately imports no routing or filesystem runtime.  It is the
one-way dependency shared by the permit writer and routing's authenticated
after-image inspector, so both sides apply exactly the same compact receipt.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any

from . import harnesslib as h
from . import semantic_events as semantic
from . import transition_permits as permits


PERMIT_RUNTIME_SCHEMA_VERSION = 1
PERMIT_NAMESPACE_KEY = "transition_permits"
MAX_PERMIT_CONSUMPTIONS = 4_096
MAX_PERMIT_NAMESPACE_BYTES = 2 * 1024 * 1024
MAX_COHORT_ROUTING_SLOTS = 12

_SHA256 = re.compile(r"[0-9a-f]{64}")
_CONSUMPTION_FIELDS = {
    "schema_version",
    "permit_sha256",
    "decision_sha256",
    "replay_marker",
    "action",
    "target_ids",
    "routing_slots",
    "cohort_state",
}
_NAMESPACE_FIELDS = {"schema_version", "consumptions", "replay_markers"}
_COHORT_STATE_FIELDS = {
    "schema_version",
    "cohort_sha256",
    "wave_index",
    "selection_sha256",
}


class PermitProjectionError(ValueError):
    """A compact consumption receipt or its task-global index is invalid."""


def _fail(message: str, exc: BaseException | None = None) -> PermitProjectionError:
    return PermitProjectionError(message if exc is None else f"{message}: {exc}")


def _clone(value: Any, *, maximum: int) -> Any:
    try:
        return json.loads(
            semantic.canonical_json_bytes(value, max_bytes=maximum).decode("utf-8")
        )
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("permit projection value is not bounded canonical JSON", exc) from exc


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise PermitProjectionError(f"{label} is not lowercase SHA-256")
    return value


def _exact_version(value: Any, expected: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise PermitProjectionError(f"{label} is invalid")
    return expected


def _bounded_wave_index(value: Any) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 1_000_000
    ):
        raise PermitProjectionError("cohort permit wave index is invalid")
    return value


def validate_cohort_consumption_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the compact exact-selection identity stored on consumption."""

    if not isinstance(value, dict) or set(value) != _COHORT_STATE_FIELDS:
        raise PermitProjectionError("cohort permit consumption state schema is invalid")
    item = _clone(value, maximum=permits.MAX_PERMIT_BYTES)
    return {
        "schema_version": _exact_version(
            item["schema_version"],
            PERMIT_RUNTIME_SCHEMA_VERSION,
            "cohort permit consumption state version",
        ),
        "cohort_sha256": _sha(
            item["cohort_sha256"], "cohort permit plan SHA-256"
        ),
        "wave_index": _bounded_wave_index(item["wave_index"]),
        "selection_sha256": _sha(
            item["selection_sha256"], "cohort permit selection SHA-256"
        ),
    }


def validate_permit_consumption(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one compact, digest-only consumed-permit projection row."""

    if not isinstance(value, dict) or set(value) != _CONSUMPTION_FIELDS:
        raise PermitProjectionError("permit consumption projection schema is invalid")
    item = _clone(value, maximum=permits.MAX_PERMIT_BYTES)
    _exact_version(
        item["schema_version"],
        PERMIT_RUNTIME_SCHEMA_VERSION,
        "permit consumption schema version",
    )
    target_ids = item["target_ids"]
    routing_slots = item["routing_slots"]
    if not isinstance(target_ids, list) or len(target_ids) != 1:
        raise PermitProjectionError("permit consumption target shape is invalid")
    try:
        target_id = h.validate_id(target_ids[0], "permit target id")
    except h.HarnessError as exc:
        raise _fail("permit consumption target identity is invalid", exc) from exc
    if not isinstance(routing_slots, list):
        raise PermitProjectionError("permit consumption routing slots are invalid")
    slots = [
        _sha(slot, "consumed routing slot") for slot in routing_slots
    ]
    action = item["action"]
    if action == "packet.arm":
        if (
            len(slots) != 1
            or slots != sorted(set(slots))
            or item["cohort_state"] is not None
        ):
            raise PermitProjectionError("packet.arm permit consumption shape is invalid")
        cohort_state = None
    elif action == "cohort.advance":
        if (
            not 1 <= len(slots) <= MAX_COHORT_ROUTING_SLOTS
            or slots != sorted(set(slots))
            or not isinstance(item["cohort_state"], dict)
        ):
            raise PermitProjectionError(
                "cohort.advance permit consumption shape is invalid"
            )
        cohort_state = validate_cohort_consumption_state(item["cohort_state"])
    else:
        raise PermitProjectionError("permit consumption action is invalid")
    checked = {
        "schema_version": PERMIT_RUNTIME_SCHEMA_VERSION,
        "permit_sha256": _sha(item["permit_sha256"], "consumed permit SHA-256"),
        "decision_sha256": _sha(
            item["decision_sha256"], "consumed decision SHA-256"
        ),
        "replay_marker": _sha(item["replay_marker"], "consumed replay marker"),
        "action": action,
        "target_ids": [target_id],
        "routing_slots": slots,
        "cohort_state": cohort_state,
    }
    try:
        semantic.canonical_json_bytes(checked, max_bytes=permits.MAX_PERMIT_BYTES)
    except semantic.SemanticEventError as exc:
        raise _fail("permit consumption exceeds its canonical JSON bound", exc) from exc
    return checked


def validate_permit_namespace(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the task-global consumption and replay-marker indexes."""

    if value is None:
        return {
            "schema_version": PERMIT_RUNTIME_SCHEMA_VERSION,
            "consumptions": {},
            "replay_markers": {},
        }
    if not isinstance(value, dict) or set(value) != _NAMESPACE_FIELDS:
        raise PermitProjectionError("permit projection namespace schema is invalid")
    _exact_version(
        value.get("schema_version"),
        PERMIT_RUNTIME_SCHEMA_VERSION,
        "permit projection namespace version",
    )
    consumptions = value.get("consumptions")
    replay_markers = value.get("replay_markers")
    if (
        not isinstance(consumptions, dict)
        or not isinstance(replay_markers, dict)
        or len(consumptions) > MAX_PERMIT_CONSUMPTIONS
        or len(replay_markers) > MAX_PERMIT_CONSUMPTIONS
        or len(consumptions) != len(replay_markers)
    ):
        raise PermitProjectionError(
            "permit projection indexes are invalid or over bound"
        )
    checked_consumptions: dict[str, dict[str, Any]] = {}
    checked_markers: dict[str, str] = {}
    for identity, raw in consumptions.items():
        identity = _sha(identity, "permit consumption identity")
        checked_consumptions[identity] = validate_permit_consumption(raw)
    for marker, identity in replay_markers.items():
        marker = _sha(marker, "permit replay marker index")
        identity = _sha(identity, "permit replay marker consumption identity")
        receipt = checked_consumptions.get(identity)
        if receipt is None or receipt["replay_marker"] != marker:
            raise PermitProjectionError(
                "permit replay-marker index cross-binding is invalid"
            )
        checked_markers[marker] = identity
    if {
        receipt["replay_marker"] for receipt in checked_consumptions.values()
    } != set(checked_markers):
        raise PermitProjectionError(
            "permit consumption lacks a unique replay-marker index"
        )
    checked = {
        "schema_version": PERMIT_RUNTIME_SCHEMA_VERSION,
        "consumptions": {
            identity: checked_consumptions[identity]
            for identity in sorted(checked_consumptions)
        },
        "replay_markers": {
            marker: checked_markers[marker] for marker in sorted(checked_markers)
        },
    }
    try:
        semantic.canonical_json_bytes(checked, max_bytes=MAX_PERMIT_NAMESPACE_BYTES)
    except semantic.SemanticEventError as exc:
        raise _fail("permit projection namespace exceeds its byte bound", exc) from exc
    return checked


def permit_namespace_from_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    try:
        domain = semantic.projection_domain(projection)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("permit projection is invalid", exc) from exc
    return validate_permit_namespace(domain.get(PERMIT_NAMESPACE_KEY))


def packet_consumption_receipt(
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    routing_slot: str,
) -> tuple[str, dict[str, Any]]:
    pair = permits.validate_decision_permit_pair(decision, permit)
    checked_decision = pair["decision"]
    checked_permit = pair["permit"]
    identity = permits.permit_consumption_identity(checked_permit)
    return identity, validate_permit_consumption(
        {
            "schema_version": PERMIT_RUNTIME_SCHEMA_VERSION,
            "permit_sha256": checked_permit["permit_sha256"],
            "decision_sha256": checked_decision["decision_sha256"],
            "replay_marker": permits.permit_replay_marker(checked_permit),
            "action": checked_permit["action"],
            "target_ids": checked_permit["target_ids"],
            "routing_slots": [_sha(routing_slot, "consumed routing slot")],
            "cohort_state": None,
        }
    )


def cohort_consumption_receipt(
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    *,
    cohort_sha256: str,
    wave_index: int,
    selection_sha256: str,
    routing_slots: list[str],
) -> tuple[str, dict[str, Any]]:
    pair = permits.validate_decision_permit_pair(decision, permit)
    checked_decision = pair["decision"]
    checked_permit = pair["permit"]
    if checked_permit["action"] != "cohort.advance":
        raise PermitProjectionError("permit is not a cohort.advance authorization")
    parameters = checked_permit["parameters"]
    checked_cohort_sha256 = _sha(cohort_sha256, "cohort permit plan SHA-256")
    checked_wave_index = _bounded_wave_index(wave_index)
    if (
        parameters["cohort_sha256"] != checked_cohort_sha256
        or parameters["wave_index"] != checked_wave_index
    ):
        raise PermitProjectionError(
            "cohort permit consumption differs from authorized plan or wave"
        )
    identity = permits.permit_consumption_identity(checked_permit)
    return identity, validate_permit_consumption(
        {
            "schema_version": PERMIT_RUNTIME_SCHEMA_VERSION,
            "permit_sha256": checked_permit["permit_sha256"],
            "decision_sha256": checked_decision["decision_sha256"],
            "replay_marker": permits.permit_replay_marker(checked_permit),
            "action": "cohort.advance",
            "target_ids": checked_permit["target_ids"],
            "routing_slots": sorted(routing_slots),
            "cohort_state": {
                "schema_version": PERMIT_RUNTIME_SCHEMA_VERSION,
                "cohort_sha256": checked_cohort_sha256,
                "wave_index": checked_wave_index,
                "selection_sha256": _sha(
                    selection_sha256, "cohort permit selection SHA-256"
                ),
            },
        }
    )


def advance_permit_projection(
    base: Mapping[str, Any], identity: str, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    domain = semantic.projection_domain(base)
    namespace = validate_permit_namespace(domain.get(PERMIT_NAMESPACE_KEY))
    identity = _sha(identity, "permit consumption identity")
    checked = validate_permit_consumption(receipt)
    marker = checked["replay_marker"]
    if identity in namespace["consumptions"]:
        raise PermitProjectionError("permit consumption identity is already committed")
    if marker in namespace["replay_markers"]:
        raise PermitProjectionError("permit replay marker is already committed")
    if len(namespace["consumptions"]) >= MAX_PERMIT_CONSUMPTIONS:
        raise PermitProjectionError(
            "permit consumption projection reached its count bound"
        )
    namespace["consumptions"][identity] = checked
    namespace["replay_markers"][marker] = identity
    domain[PERMIT_NAMESPACE_KEY] = validate_permit_namespace(namespace)
    try:
        semantic.canonical_json_bytes(
            domain, max_bytes=semantic.MAX_CANONICAL_JSON_BYTES
        )
    except semantic.SemanticEventError as exc:
        raise _fail("permitted result projection exceeds its byte bound", exc) from exc
    return domain


__all__ = [
    "MAX_COHORT_ROUTING_SLOTS",
    "MAX_PERMIT_CONSUMPTIONS",
    "MAX_PERMIT_NAMESPACE_BYTES",
    "PERMIT_NAMESPACE_KEY",
    "PERMIT_RUNTIME_SCHEMA_VERSION",
    "PermitProjectionError",
    "advance_permit_projection",
    "cohort_consumption_receipt",
    "packet_consumption_receipt",
    "permit_namespace_from_projection",
    "validate_cohort_consumption_state",
    "validate_permit_consumption",
    "validate_permit_namespace",
]
