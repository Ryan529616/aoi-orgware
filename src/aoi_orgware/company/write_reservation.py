"""Bounded W2 write-admission payload contracts.

``WorkWriteCapabilityV1`` is append-only evidence, not an admission decision.
Self-validation proves only canonical payload shape and its digest.  In
particular, a registered domain, an ``AOI_verified`` provenance label, or a
self-validating capability does not confer authority.  W2b must prove that the
capability was issued in a prior committed transaction by the applicable
durable authority, that its issuer grant was active at ``issued_at``, and the
exact allowed subset/equality relation of its opaque refs to the durable intent.

The true held-reservation lifecycle is derived by W2b from durable owner
lifecycle events.  It intentionally has no independently mutable reservation
record in this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from ..semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256
from .write_admission import validate_active_write_ref


WORK_WRITE_CAPABILITY_V1 = "WorkWriteCapabilityV1"
WRITE_ADMISSION_ENFORCEMENT_V1 = "WriteAdmissionEnforcementV1"
WRITE_RESERVATION_SCHEMA_VERSION = 1
MAX_OPAQUE_REFS = 64
MAX_TIMESTAMP = 64
MAX_COMPANY_INCARNATION = 999_999_999
MAX_LOCK_DOMAIN_GENERATION = 999_999_999
MAX_CAPABILITY_TTL = timedelta(hours=24)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{6})?Z"
)
_OBSERVED = {"state": "known", "reason": "observed"}
_CAPABILITY_FIELDS = frozenset({
    "contract_type", "schema_version", "company_id", "company_incarnation",
    "lock_domain_generation", "capability_id", "domain_binding_id",
    "domain_binding_sha256", "task_id", "packet_id", "packet_sha256",
    "authority_scope_sha256", "intent_id", "intent_sha256", "issuer_grant_id",
    "issuer_grant_sha256", "issuer_action", "owner_kind", "owner_id",
    "owner_generation_id",
    "owner_anchor_sha256", "owner_reservation_id", "opaque_refs",
    "opaque_refs_sha256", "issued_at", "expires_at", "provenance",
    "observation", "capability_sha256",
})
_ENFORCEMENT_FIELDS = frozenset({
    "contract_type", "schema_version", "company_id", "company_incarnation",
    "lock_domain_generation", "gate_id", "mode", "domain_binding_id",
    "domain_binding_sha256", "previous_transaction_sha256", "activated_at",
    "provenance", "observation", "enforcement_sha256",
})


class WriteReservationError(ValueError):
    """A W2 write-admission payload is malformed, ambiguous, or tampered."""


def _object(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WriteReservationError(f"{label} schema is invalid")
    return dict(value)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WriteReservationError(f"{label} is not a canonical identifier")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise WriteReservationError(f"{label} is not lowercase SHA-256")
    return value


def _plain_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise WriteReservationError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_TIMESTAMP
        or not _TIMESTAMP.fullmatch(value)
    ):
        raise WriteReservationError(f"{label} must use bounded UTC Z form")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WriteReservationError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise WriteReservationError(f"{label} must use UTC")
    canonical = parsed.isoformat(
        timespec="microseconds" if parsed.microsecond else "seconds",
    ).replace("+00:00", "Z")
    if value != canonical:
        raise WriteReservationError(f"{label} is not canonically spelled")
    return value


def _canonical_sha256(value: Any, label: str) -> str:
    try:
        return canonical_sha256(value)
    except SemanticEventError as exc:
        raise WriteReservationError(f"{label} is not canonical JSON") from exc


def _canonical_bytes(value: Any, label: str) -> bytes:
    try:
        return canonical_json_bytes(value)
    except SemanticEventError as exc:
        raise WriteReservationError(f"{label} is not canonical JSON") from exc


def _binding(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "company_id": _identifier(item["company_id"], "company_id"),
        "company_incarnation": _plain_int(
            item["company_incarnation"], "company_incarnation", minimum=1,
            maximum=MAX_COMPANY_INCARNATION,
        ),
        "lock_domain_generation": _plain_int(
            item["lock_domain_generation"], "lock_domain_generation", minimum=1,
            maximum=MAX_LOCK_DOMAIN_GENERATION,
        ),
    }


def _version(item: Mapping[str, Any], contract_type: str, label: str) -> None:
    if item["contract_type"] != contract_type or _plain_int(
        item["schema_version"], "schema_version", minimum=1,
        maximum=WRITE_RESERVATION_SCHEMA_VERSION,
    ) != WRITE_RESERVATION_SCHEMA_VERSION:
        raise WriteReservationError(f"{label} version is invalid")


def _known_observation(value: Any, label: str) -> dict[str, str]:
    item = _object(value, frozenset({"state", "reason"}), label)
    if item != _OBSERVED:
        raise WriteReservationError(f"{label} must be known and observed")
    return dict(_OBSERVED)


def _opaque_refs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_OPAQUE_REFS:
        raise WriteReservationError("opaque refs are unbounded")
    refs: list[dict[str, Any]] = []
    for index, member in enumerate(value):
        try:
            reference = validate_active_write_ref(member)
        except ValueError as exc:
            raise WriteReservationError(f"opaque_refs[{index}] is invalid") from exc
        if reference["kind"] not in {"output_namespace", "serialization_key"}:
            raise WriteReservationError("opaque refs must not name files or trees")
        refs.append(reference)
    encoded = [_canonical_bytes(ref, "opaque ref") for ref in refs]
    if encoded != sorted(encoded):
        raise WriteReservationError("opaque refs are not canonically sorted")
    if len(set(encoded)) != len(encoded):
        raise WriteReservationError("opaque refs are duplicated")
    return refs


def validate_work_write_capability(value: Any) -> dict[str, Any]:
    """Validate payload integrity only; this never proves admission authority."""
    item = _object(value, _CAPABILITY_FIELDS, "WorkWriteCapability")
    _version(item, WORK_WRITE_CAPABILITY_V1, "WorkWriteCapability")
    issued_at = _timestamp(item["issued_at"], "issued_at")
    expires_at = _timestamp(item["expires_at"], "expires_at")
    issued = datetime.fromisoformat(issued_at[:-1] + "+00:00")
    expires = datetime.fromisoformat(expires_at[:-1] + "+00:00")
    if not issued < expires <= issued + MAX_CAPABILITY_TTL:
        raise WriteReservationError(
            "capability expiry must follow issuance by at most 24 hours",
        )
    if item["provenance"] != "AOI_verified":
        raise WriteReservationError("WorkWriteCapability must be AOI-verified")
    if item["issuer_action"] != "write_capability.issue":
        raise WriteReservationError("WorkWriteCapability issuer action is invalid")
    owner_kind = item["owner_kind"]
    if owner_kind not in {"dispatch_request", "external_job"}:
        raise WriteReservationError("WorkWriteCapability owner kind is invalid")
    opaque_refs = _opaque_refs(item["opaque_refs"])
    opaque_refs_sha256 = _sha256(item["opaque_refs_sha256"], "opaque_refs_sha256")
    if opaque_refs_sha256 != _canonical_sha256(opaque_refs, "opaque refs"):
        raise WriteReservationError("opaque refs digest differs")
    result: dict[str, Any] = {
        "contract_type": WORK_WRITE_CAPABILITY_V1,
        "schema_version": WRITE_RESERVATION_SCHEMA_VERSION,
        **_binding(item),
        "capability_id": _identifier(item["capability_id"], "capability_id"),
        "domain_binding_id": _identifier(item["domain_binding_id"], "domain_binding_id"),
        "domain_binding_sha256": _sha256(item["domain_binding_sha256"], "domain_binding_sha256"),
        "task_id": _identifier(item["task_id"], "task_id"),
        "packet_id": _identifier(item["packet_id"], "packet_id"),
        "packet_sha256": _sha256(item["packet_sha256"], "packet_sha256"),
        "authority_scope_sha256": _sha256(item["authority_scope_sha256"], "authority_scope_sha256"),
        "intent_id": _identifier(item["intent_id"], "intent_id"),
        "intent_sha256": _sha256(item["intent_sha256"], "intent_sha256"),
        "issuer_grant_id": _identifier(item["issuer_grant_id"], "issuer_grant_id"),
        "issuer_grant_sha256": _sha256(item["issuer_grant_sha256"], "issuer_grant_sha256"),
        "issuer_action": "write_capability.issue",
        "owner_kind": owner_kind,
        "owner_id": _identifier(item["owner_id"], "owner_id"),
        "owner_generation_id": _identifier(item["owner_generation_id"], "owner_generation_id"),
        "owner_anchor_sha256": _sha256(item["owner_anchor_sha256"], "owner_anchor_sha256"),
        "owner_reservation_id": _identifier(item["owner_reservation_id"], "owner_reservation_id"),
        "opaque_refs": opaque_refs,
        "opaque_refs_sha256": opaque_refs_sha256,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "provenance": "AOI_verified",
        "observation": _known_observation(item["observation"], "observation"),
        "capability_sha256": _sha256(item["capability_sha256"], "capability_sha256"),
    }
    unsigned = {key: result[key] for key in _CAPABILITY_FIELDS - {"capability_sha256"}}
    if result["capability_sha256"] != _canonical_sha256(unsigned, "WorkWriteCapability"):
        raise WriteReservationError("WorkWriteCapability digest differs")
    return result


def seal_work_write_capability(value: Any) -> dict[str, Any]:
    """Seal one complete unsigned append-only capability payload."""
    item = _object(value, _CAPABILITY_FIELDS - {"capability_sha256"}, "unsigned WorkWriteCapability")
    sealed = {**item, "capability_sha256": _canonical_sha256(item, "WorkWriteCapability")}
    return validate_work_write_capability(sealed)


def validate_write_admission_enforcement(value: Any) -> dict[str, Any]:
    """Validate the fixed durable admission gate; it does not admit a write."""
    item = _object(value, _ENFORCEMENT_FIELDS, "WriteAdmissionEnforcement")
    _version(item, WRITE_ADMISSION_ENFORCEMENT_V1, "WriteAdmissionEnforcement")
    if item["gate_id"] != "write-admission-v1" or item["mode"] != "enforced":
        raise WriteReservationError("write admission gate and mode are fixed")
    if item["provenance"] != "AOI_verified":
        raise WriteReservationError("WriteAdmissionEnforcement must be AOI-verified")
    result: dict[str, Any] = {
        "contract_type": WRITE_ADMISSION_ENFORCEMENT_V1,
        "schema_version": WRITE_RESERVATION_SCHEMA_VERSION,
        **_binding(item),
        "gate_id": "write-admission-v1",
        "mode": "enforced",
        "domain_binding_id": _identifier(item["domain_binding_id"], "domain_binding_id"),
        "domain_binding_sha256": _sha256(item["domain_binding_sha256"], "domain_binding_sha256"),
        "previous_transaction_sha256": _sha256(item["previous_transaction_sha256"], "previous_transaction_sha256"),
        "activated_at": _timestamp(item["activated_at"], "activated_at"),
        "provenance": "AOI_verified",
        "observation": _known_observation(item["observation"], "observation"),
        "enforcement_sha256": _sha256(item["enforcement_sha256"], "enforcement_sha256"),
    }
    unsigned = {key: result[key] for key in _ENFORCEMENT_FIELDS - {"enforcement_sha256"}}
    if result["enforcement_sha256"] != _canonical_sha256(unsigned, "WriteAdmissionEnforcement"):
        raise WriteReservationError("WriteAdmissionEnforcement digest differs")
    return result


def seal_write_admission_enforcement(value: Any) -> dict[str, Any]:
    """Seal one complete unsigned write-admission enforcement record."""
    item = _object(value, _ENFORCEMENT_FIELDS - {"enforcement_sha256"}, "unsigned WriteAdmissionEnforcement")
    sealed = {**item, "enforcement_sha256": _canonical_sha256(item, "WriteAdmissionEnforcement")}
    return validate_write_admission_enforcement(sealed)


__all__ = [
    "MAX_OPAQUE_REFS",
    "MAX_CAPABILITY_TTL",
    "WORK_WRITE_CAPABILITY_V1",
    "WRITE_ADMISSION_ENFORCEMENT_V1",
    "WRITE_RESERVATION_SCHEMA_VERSION",
    "WriteReservationError",
    "seal_work_write_capability",
    "seal_write_admission_enforcement",
    "validate_work_write_capability",
    "validate_write_admission_enforcement",
]
