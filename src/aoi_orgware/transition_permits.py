"""Pure, sealed one-shot transition permits (no filesystem I/O).

A permit is deliberately not Chief authority.  It is a content-addressed,
time-bounded authorization for one already-made technical decision.  The
caller must persist ``consumption_identity`` and ``replay_marker`` with the
same compare-and-swap transaction that commits the lifecycle transition.
This module only validates the exact decision boundary; it cannot consume a
permit or make that transaction atomic.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping
from datetime import datetime
import re
from typing import Any, NoReturn

from .semantic_events import SemanticEventError, canonical_sha256


DECISION_SCHEMA_VERSION = 1
PERMIT_SCHEMA_VERSION = 1
MAX_PERMIT_BYTES = 64 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
# Lifecycle records are addressed by the AOI canonical ID grammar, not the
# broader transport/reference grammar.  In particular, a permit must never
# preserve a path-like or URI-like lifecycle target.
_LIFECYCLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}")
_PERMITTED_ACTIONS = frozenset({"packet.arm", "cohort.advance"})
_PACKET_ARM_PARAMETER_FIELDS = {
    "packet_id",
    "packet_schema_version",
    "routing_authority_sha256",
}
_COHORT_ADVANCE_PARAMETER_FIELDS = {"cohort_id", "cohort_sha256", "wave_index"}
_MAX_WAVE_INDEX = 1_000_000
_DECISION_BASE_FIELDS = {
    "schema_version",
    "task_id",
    "action",
    "target_ids",
    "parameters",
    "technical_payload_sha256",
}
_SEALED_DECISION_FIELDS = _DECISION_BASE_FIELDS | {"decision_sha256"}
_BASE_FIELDS = {
    "schema_version",
    "task_id",
    "expected_semantic_head_sha256",
    "decision_sha256",
    "action",
    "target_ids",
    "parameters",
    "expires_at",
    "nonce",
    "chief_authority",
}
_SEALED_FIELDS = _BASE_FIELDS | {"permit_sha256"}
_CHIEF_AUTHORITY_FIELDS = {"session_id", "epoch"}


class TransitionPermitError(ValueError):
    """A transition permit or attempted consumption is invalid."""


def _fail(message: str) -> NoReturn:
    raise TransitionPermitError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _lifecycle_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _LIFECYCLE_ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _action(value: Any) -> str:
    if not isinstance(value, str) or value not in _PERMITTED_ACTIONS:
        _fail("action is invalid")
    return value


def _expiry(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 64:
        _fail("expires_at is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise TransitionPermitError("expires_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("expires_at needs a timezone")
    return value


def _expiry_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def _nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE.fullmatch(value):
        _fail("nonce is invalid")
    return value


def _target_ids(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) != 1:
        _fail("target_ids is invalid")
    targets = [_lifecycle_id(item, "target_id") for item in value]
    return targets


def _bounded_int(value: Any, label: str, *, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _exact_int(value: Any, label: str, *, expected: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        _fail(f"{label} is invalid")
    return expected


def _parameters(action: str, value: Any, target_ids: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("parameters must be an object")
    item = dict(value)
    if action == "packet.arm":
        if set(item) != _PACKET_ARM_PARAMETER_FIELDS:
            _fail("packet.arm parameters schema is invalid")
        packet_id = _lifecycle_id(item["packet_id"], "parameters.packet_id")
        if target_ids != [packet_id]:
            _fail("packet.arm target_ids must name parameters.packet_id")
        return {
            "packet_id": packet_id,
            "packet_schema_version": _exact_packet_schema_version(item["packet_schema_version"]),
            "routing_authority_sha256": _sha256(
                item["routing_authority_sha256"], "parameters.routing_authority_sha256"
            ),
        }
    if action == "cohort.advance":
        if set(item) != _COHORT_ADVANCE_PARAMETER_FIELDS:
            _fail("cohort.advance parameters schema is invalid")
        cohort_id = _lifecycle_id(item["cohort_id"], "parameters.cohort_id")
        if target_ids != [cohort_id]:
            _fail("cohort.advance target_ids must name parameters.cohort_id")
        return {
            "cohort_id": cohort_id,
            "cohort_sha256": _sha256(item["cohort_sha256"], "parameters.cohort_sha256"),
            "wave_index": _bounded_int(
                item["wave_index"], "parameters.wave_index", maximum=_MAX_WAVE_INDEX
            ),
        }
    _fail("action is invalid")


def _exact_packet_schema_version(value: Any) -> int:
    return _exact_int(
        value,
        "parameters.packet_schema_version",
        expected=6,
    )


def _chief_authority(value: Any) -> dict[str, Any]:
    item = _object(value, _CHIEF_AUTHORITY_FIELDS, "chief_authority")
    epoch = item["epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        _fail("chief_authority.epoch is invalid")
    return {
        "session_id": _lifecycle_id(item["session_id"], "chief_authority.session_id"),
        "epoch": epoch,
    }


def _decision_base(value: Any) -> dict[str, Any]:
    item = _object(value, _DECISION_BASE_FIELDS, "decision")
    _exact_int(
        item["schema_version"],
        "decision schema_version",
        expected=DECISION_SCHEMA_VERSION,
    )
    action = _action(item["action"])
    target_ids = _target_ids(item["target_ids"])
    return {
        "schema_version": DECISION_SCHEMA_VERSION,
        "task_id": _lifecycle_id(item["task_id"], "task_id"),
        "action": action,
        "target_ids": target_ids,
        "parameters": _parameters(action, item["parameters"], target_ids),
        "technical_payload_sha256": _sha256(
            item["technical_payload_sha256"], "technical_payload_sha256"
        ),
    }


def transition_decision_sha256(decision: Mapping[str, Any]) -> str:
    """Return the canonical hash of an unsealed, exact decision base record."""

    base = _decision_base(decision)
    try:
        return canonical_sha256(base, max_bytes=MAX_PERMIT_BYTES)
    except SemanticEventError as exc:
        raise TransitionPermitError(str(exc)) from exc


def seal_transition_decision(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and append the deterministic decision SHA-256."""

    base = _decision_base(decision)
    try:
        base["decision_sha256"] = canonical_sha256(base, max_bytes=MAX_PERMIT_BYTES)
    except SemanticEventError as exc:
        raise TransitionPermitError(str(exc)) from exc
    return base


def validate_transition_decision(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a sealed decision and return a detached canonical copy."""

    item = _object(decision, _SEALED_DECISION_FIELDS, "decision")
    base = _decision_base({key: item[key] for key in _DECISION_BASE_FIELDS})
    expected = transition_decision_sha256(base)
    if item["decision_sha256"] != expected:
        _fail("decision_sha256 does not match decision")
    return {**base, "decision_sha256": expected}


def _permit_base(value: Any) -> dict[str, Any]:
    item = _object(value, _BASE_FIELDS, "permit")
    _exact_int(
        item["schema_version"],
        "permit schema_version",
        expected=PERMIT_SCHEMA_VERSION,
    )
    action = _action(item["action"])
    target_ids = _target_ids(item["target_ids"])
    return {
        "schema_version": PERMIT_SCHEMA_VERSION,
        "task_id": _lifecycle_id(item["task_id"], "task_id"),
        "expected_semantic_head_sha256": _sha256(
            item["expected_semantic_head_sha256"], "expected_semantic_head_sha256"
        ),
        "decision_sha256": _sha256(item["decision_sha256"], "decision_sha256"),
        "action": action,
        "target_ids": target_ids,
        "parameters": _parameters(action, item["parameters"], target_ids),
        "expires_at": _expiry(item["expires_at"]),
        "nonce": _nonce(item["nonce"]),
        "chief_authority": _chief_authority(item["chief_authority"]),
    }


def transition_permit_sha256(permit: Mapping[str, Any]) -> str:
    """Return the canonical hash of an unsealed, exact permit base record."""

    base = _permit_base(permit)
    try:
        return canonical_sha256(base, max_bytes=MAX_PERMIT_BYTES)
    except SemanticEventError as exc:
        raise TransitionPermitError(str(exc)) from exc


def seal_transition_permit(permit: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and append the deterministic permit SHA-256."""

    base = _permit_base(permit)
    try:
        base["permit_sha256"] = canonical_sha256(base, max_bytes=MAX_PERMIT_BYTES)
    except SemanticEventError as exc:
        raise TransitionPermitError(str(exc)) from exc
    return base


def validate_transition_permit(permit: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a sealed permit and return a detached canonical copy."""

    item = _object(permit, _SEALED_FIELDS, "permit")
    base = _permit_base({key: item[key] for key in _BASE_FIELDS})
    expected = transition_permit_sha256(base)
    if item["permit_sha256"] != expected:
        _fail("permit_sha256 does not match permit")
    return {**base, "permit_sha256": expected}


def validate_decision_permit_pair(
    decision: Mapping[str, Any], permit: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Fail closed unless a sealed permit authorizes this exact decision."""

    validated_decision = validate_transition_decision(decision)
    validated_permit = validate_transition_permit(permit)
    for field in ("task_id", "action", "target_ids", "parameters"):
        if validated_permit[field] != validated_decision[field]:
            _fail(f"permit {field} does not match decision")
    if validated_permit["decision_sha256"] != validated_decision["decision_sha256"]:
        _fail("permit decision_sha256 does not match decision")
    return {"decision": validated_decision, "permit": validated_permit}


def permit_replay_marker(permit: Mapping[str, Any]) -> str:
    """Stable nonce identity to reserve with the transition's atomic commit."""

    item = validate_transition_permit(permit)
    return canonical_sha256(
        {
            "schema_version": PERMIT_SCHEMA_VERSION,
            "task_id": item["task_id"],
            "chief_authority": item["chief_authority"],
            "nonce": item["nonce"],
        },
        max_bytes=MAX_PERMIT_BYTES,
    )


def permit_consumption_identity(permit: Mapping[str, Any]) -> str:
    """Stable identity for the one exact sealed permit consumption."""

    item = validate_transition_permit(permit)
    return canonical_sha256(
        {
            "schema_version": PERMIT_SCHEMA_VERSION,
            "permit_sha256": item["permit_sha256"],
            "replay_marker": permit_replay_marker(item),
        },
        max_bytes=MAX_PERMIT_BYTES,
    )


def _consumed(value: Collection[str], label: str) -> set[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Collection):
        _fail(f"{label} is invalid")
    result: set[str] = set()
    for item in value:
        result.add(_sha256(item, label))
    return result


def _current_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail("current_time needs a timezone-aware datetime")
    return value


def validate_transition_consumption(
    permit: Mapping[str, Any],
    *,
    task_id: str,
    semantic_head_sha256: str,
    decision_sha256: str,
    action: str,
    target_ids: list[str],
    parameters: Mapping[str, Any],
    chief_authority: Mapping[str, Any],
    current_time: datetime,
    consumed_identities: Collection[str] = (),
    consumed_replay_markers: Collection[str] = (),
) -> dict[str, Any]:
    """Fail closed unless this is the exact unconsumed transition.

    The returned identity and marker must be recorded atomically with the
    semantic transition.  This function deliberately does not mutate either
    collection, persist a receipt, or obtain a clock.
    """

    item = validate_transition_permit(permit)
    if item["task_id"] != _lifecycle_id(task_id, "task_id"):
        _fail("task_id does not match permit")
    if item["expected_semantic_head_sha256"] != _sha256(
        semantic_head_sha256, "semantic_head_sha256"
    ):
        _fail("semantic head does not match permit")
    if item["decision_sha256"] != _sha256(decision_sha256, "decision_sha256"):
        _fail("decision_sha256 does not match permit")
    if item["action"] != _action(action):
        _fail("action does not match permit")
    if item["target_ids"] != _target_ids(target_ids):
        _fail("target_ids do not match permit")
    if item["parameters"] != _parameters(item["action"], parameters, item["target_ids"]):
        _fail("parameters do not match permit")
    if item["chief_authority"] != _chief_authority(chief_authority):
        _fail("chief_authority does not match permit")
    if _expiry_datetime(item["expires_at"]) <= _current_time(current_time):
        _fail("permit is expired")

    replay_marker = permit_replay_marker(item)
    consumption_identity = permit_consumption_identity(item)
    if consumption_identity in _consumed(consumed_identities, "consumed_identities"):
        _fail("permit consumption identity was already consumed")
    if replay_marker in _consumed(consumed_replay_markers, "consumed_replay_markers"):
        _fail("permit replay marker was already consumed")
    return {
        "permit": item,
        "permit_sha256": item["permit_sha256"],
        "consumption_identity": consumption_identity,
        "replay_marker": replay_marker,
    }
