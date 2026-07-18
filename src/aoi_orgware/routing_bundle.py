"""Pure, ephemeral dispatch-routing validation bundles.

This module has no task-state, filesystem, lock, or CLI interface.  It is a
bounded validation/assembly object only.  Production persistence must use
content-addressed immutable objects with compact semantic references; never
place this full authority/outcome bundle in a task projection.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

from .routing_authority import (
    MAX_RECORD_BYTES,
    RoutingAuthorityError,
    capacity_routing_view,
    validate_arm_authority,
    validate_dispatch_outcome,
    validate_unattempted_v6_cancellation_outcome,
)
from .semantic_events import SemanticEventError, canonical_json_bytes


ROUTING_BUNDLE_SCHEMA_VERSION = 1
MAX_ROUTING_BUNDLE_RECORDS = 4_096
MAX_ROUTING_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_V6_RECORD_BYTES = (2 * MAX_RECORD_BYTES) + 4_096

_BUNDLE_FIELDS = {"schema_version", "records"}
_V6_RECORD_FIELDS = {"kind", "authority", "outcome", "terminal_status", "typed_outcome"}
_LEGACY_RECORD_FIELDS = {"kind", "legacy_outcome"}
_UNATTEMPTED_V6_RECORD_FIELDS = {"kind", "unattempted_v6_outcome"}
_TERMINAL_TYPED_OUTCOMES_BY_STATUS = {
    "done": {"accepted", "rejected", "no_material_work", "superseded", "unclassified"},
    "failed": {
        "rejected",
        "procedural_failure",
        "transport_failure",
        "no_material_work",
        "unclassified",
    },
    "cancelled": {
        "cancelled",
        "procedural_failure",
        "superseded",
        "no_material_work",
        "unclassified",
    },
}


class RoutingBundleError(ValueError):
    """A pure routing bundle, record, or terminal pair is invalid."""


def _fail(message: str) -> None:
    raise RoutingBundleError(message)


def _clone(value: Any, *, max_bytes: int | None = None) -> Any:
    try:
        bound = MAX_ROUTING_BUNDLE_BYTES if max_bytes is None else max_bytes
        return json.loads(canonical_json_bytes(value, max_bytes=bound).decode("utf-8"))
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise RoutingBundleError("routing bundle input is not bounded JSON") from exc


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return value


def _terminal(status: Any, typed_outcome: Any) -> tuple[str, str]:
    if not isinstance(status, str) or status not in _TERMINAL_TYPED_OUTCOMES_BY_STATUS:
        _fail("terminal status is invalid")
    if (
        not isinstance(typed_outcome, str)
        or typed_outcome not in _TERMINAL_TYPED_OUTCOMES_BY_STATUS[status]
    ):
        _fail("typed outcome is invalid for terminal status")
    return status, typed_outcome


def build_v6_record(
    authority: Mapping[str, Any], outcome: Mapping[str, Any]
) -> dict[str, Any]:
    """Assemble one immutable v6 routing sample with an unset terminal pair."""
    try:
        arm = validate_arm_authority(authority)
        sealed_outcome = validate_dispatch_outcome(arm, outcome)
    except RoutingAuthorityError as exc:
        raise RoutingBundleError(str(exc)) from exc
    return _clone({
        "kind": "v6",
        "authority": arm,
        "outcome": sealed_outcome,
        "terminal_status": None,
        "typed_outcome": None,
    }, max_bytes=MAX_V6_RECORD_BYTES)


def validate_v6_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and detach one v6 record without changing caller-owned data."""
    value = _object(record, _V6_RECORD_FIELDS, "v6 routing record")
    if value["kind"] != "v6":
        _fail("v6 routing record kind is invalid")
    try:
        authority = validate_arm_authority(value["authority"])
        outcome = validate_dispatch_outcome(authority, value["outcome"])
    except RoutingAuthorityError as exc:
        raise RoutingBundleError(str(exc)) from exc
    if (value["terminal_status"] is None) != (value["typed_outcome"] is None):
        _fail("v6 terminal pair is partially finalized")
    if value["terminal_status"] is not None:
        _terminal(value["terminal_status"], value["typed_outcome"])
    return _clone({
        "kind": "v6",
        "authority": authority,
        "outcome": outcome,
        "terminal_status": value["terminal_status"],
        "typed_outcome": value["typed_outcome"],
    }, max_bytes=MAX_V6_RECORD_BYTES)


def finalize_v6_record(
    record: Mapping[str, Any], *, terminal_status: str, typed_outcome: str
) -> dict[str, Any]:
    """Pure one-shot finalization; only an exact terminal retry is accepted."""
    value = validate_v6_record(record)
    wanted = _terminal(terminal_status, typed_outcome)
    existing = (value["terminal_status"], value["typed_outcome"])
    if existing == (None, None):
        value["terminal_status"], value["typed_outcome"] = wanted
    elif existing != wanted:
        _fail("v6 terminal pair has already been finalized differently")
    return _clone(value, max_bytes=MAX_V6_RECORD_BYTES)


def _validate_legacy_record(record: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(record, _LEGACY_RECORD_FIELDS, "legacy routing record")
    if value["kind"] != "legacy":
        _fail("legacy routing record kind is invalid")
    try:
        capacity_routing_view([{"legacy_outcome": value["legacy_outcome"]}])
    except RoutingAuthorityError as exc:
        raise RoutingBundleError(str(exc)) from exc
    return {"kind": "legacy", "legacy_outcome": _clone(value["legacy_outcome"], max_bytes=MAX_RECORD_BYTES)}


def _validate_unattempted_v6_record(record: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(record, _UNATTEMPTED_V6_RECORD_FIELDS, "unattempted v6 routing record")
    if value["kind"] != "unattempted_v6":
        _fail("unattempted v6 routing record kind is invalid")
    try:
        outcome = validate_unattempted_v6_cancellation_outcome(
            value["unattempted_v6_outcome"]
        )
    except RoutingAuthorityError as exc:
        raise RoutingBundleError(str(exc)) from exc
    return {"kind": "unattempted_v6", "unattempted_v6_outcome": outcome}


def _validate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        _fail("routing bundle record is invalid")
    kind = record.get("kind")
    if kind == "v6":
        return validate_v6_record(record)
    if kind == "legacy":
        return _validate_legacy_record(record)
    if kind == "unattempted_v6":
        return _validate_unattempted_v6_record(record)
    _fail("routing bundle record kind is invalid")


def validate_routing_bundle(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Validate exact bundle shape, identity uniqueness, and byte/count bounds."""
    value = _object(_clone(bundle), _BUNDLE_FIELDS, "routing bundle")
    version = value["schema_version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != ROUTING_BUNDLE_SCHEMA_VERSION
    ):
        _fail("routing bundle schema version is unsupported")
    records = value["records"]
    if not isinstance(records, list) or len(records) > MAX_ROUTING_BUNDLE_RECORDS:
        _fail("routing bundle record collection is invalid")
    checked_records: list[dict[str, Any]] = []
    packet_ids: set[str] = set()
    observation_ids: set[str] = set()
    v6_slots: set[str] = set()
    legacy_identities: set[str] = set()
    unattempted_identities: set[str] = set()
    for record in records:
        checked = _validate_record(record)
        if checked["kind"] == "v6":
            outcome = checked["outcome"]
            packet_id = checked["authority"]["packet_authority"]["packet_id"]
            identity = outcome["outcome_slot_sha256"]
            if identity in v6_slots:
                _fail("duplicate v6 outcome CAS slot")
            v6_slots.add(identity)
            observation = outcome["observation_identity_sha256"]
            if observation is not None:
                if observation in observation_ids:
                    _fail("duplicate dispatch observation identity")
                observation_ids.add(observation)
        elif checked["kind"] == "legacy":
            outcome = checked["legacy_outcome"]
            packet_id = outcome["legacy_packet_snapshot"]["packet_id"]
            identity = outcome["legacy_snapshot_identity_sha256"]
            if identity in legacy_identities:
                _fail("duplicate legacy packet snapshot identity")
            legacy_identities.add(identity)
        else:
            outcome = checked["unattempted_v6_outcome"]
            packet_id = outcome["unattempted_v6_packet_snapshot"]["packet_id"]
            identity = outcome["unattempted_v6_snapshot_identity_sha256"]
            if identity in unattempted_identities:
                _fail("duplicate unattempted v6 packet snapshot identity")
            unattempted_identities.add(identity)
        if packet_id in packet_ids:
            _fail("duplicate packet_id across routing bundle records")
        packet_ids.add(packet_id)
        checked_records.append(checked)
    checked_bundle = {
        "schema_version": ROUTING_BUNDLE_SCHEMA_VERSION,
        "records": checked_records,
    }
    return _clone(checked_bundle)


def build_routing_bundle(records: Any) -> dict[str, Any]:
    """Build a detached bundle from exact record wrappers or fail without I/O."""
    return validate_routing_bundle(
        {"schema_version": ROUTING_BUNDLE_SCHEMA_VERSION, "records": _clone(records)}
    )


def routing_capacity_view(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Return capacity rows for finalized v6 and every terminal legacy row only."""
    checked = validate_routing_bundle(bundle)
    records: list[dict[str, Any]] = []
    for record in checked["records"]:
        if record["kind"] == "v6":
            if record["terminal_status"] is not None:
                records.append(
                    {
                        "authority": record["authority"],
                        "outcome": record["outcome"],
                        "terminal_status": record["terminal_status"],
                        "typed_outcome": record["typed_outcome"],
                    }
                )
        elif record["kind"] == "legacy":
            records.append({"legacy_outcome": record["legacy_outcome"]})
        else:
            records.append(
                {"unattempted_v6_outcome": record["unattempted_v6_outcome"]}
            )
    try:
        return capacity_routing_view(records)
    except RoutingAuthorityError as exc:
        raise RoutingBundleError(str(exc)) from exc
