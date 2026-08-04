"""Durable, non-authoritative projection contract for legacy AOI observations."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, NoReturn

from .contracts import MAX_LIST_ITEMS, CompanyContractError, canonical_company_json_bytes
from .legacy_bridge import (
    LEGACY_BRIDGE_SOURCE_KIND,
    LegacyBridgeCompanyKey,
    LegacyBridgeEntity,
    LegacyBridgeProjectionV1,
    LegacyBridgeReceiptRef,
)


LEGACY_BRIDGE_OBSERVATION_V1 = "LegacyBridgeObservationV1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_VERSION = re.compile(
    r"0\.4\.0a(?:3|4)"
    r"(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?"
)
_SOURCE_VERSION_MAX_BYTES = 128
_KINDS = ("task", "packet", "agent", "job", "needs_user")
_KIND_ORDER = {kind: index for index, kind in enumerate(_KINDS)}
_STATUSES = {
    "task": frozenset({"active", "blocked", "done", "cancelled", "unknown"}),
    "packet": frozenset(
        {"ready", "armed", "dispatched", "done", "failed", "cancelled", "unknown"}
    ),
    "agent": frozenset({"unknown"}),
    "job": frozenset({"queued", "running", "pass", "fail", "stopped", "unknown"}),
    "needs_user": frozenset({"needs_user", "answered", "expired"}),
}
_ENGINEERING = {
    "task": {
        "active": "active", "blocked": "blocked", "done": "completed",
        "cancelled": "cancelled", "unknown": "unknown",
    },
    "packet": {
        "ready": "waiting", "armed": "waiting", "dispatched": "active",
        "done": "completed", "failed": "blocked", "cancelled": "cancelled",
        "unknown": "unknown",
    },
    "agent": {"unknown": "unknown"},
    "job": {
        "queued": "waiting", "running": "active", "pass": "completed",
        "fail": "blocked", "stopped": "unknown", "unknown": "unknown",
    },
    "needs_user": {
        "needs_user": "waiting", "answered": "completed", "expired": "cancelled",
    },
}
_PARENT_KINDS = {
    "task": frozenset(),
    "packet": frozenset({"task", "packet"}),
    "agent": frozenset({"packet", "agent"}),
    "job": frozenset({"task", "packet", "agent"}),
    "needs_user": frozenset({"task", "packet", "agent", "job"}),
}
_ORPHAN_REASONS = frozenset(
    {
        "explicit_parent_unavailable",
        "explicit_parent_kind_not_allowed",
        "explicit_parent_absent",
        "explicit_parent_cycle",
        "explicit_parent_ancestor_invalid",
    }
)
_RECEIPT_KINDS = frozenset(
    {"packet_result", "job_result", "provider_lifecycle", "needs_user"}
)


class LegacyBridgeContractError(CompanyContractError):
    """A durable bridge observation is malformed or overstates its evidence."""


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeContractError(message)


def _object(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        _fail(f"{label} fields are invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= 999_999_999:
        _fail(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        _fail(f"{label} is invalid: {exc}")
    if parsed.tzinfo is None:
        _fail(f"{label} lacks a timezone")
    return value


def _source_version(value: Any) -> str:
    if (
        type(value) is not str
        or not value.isascii()
        or len(value) > _SOURCE_VERSION_MAX_BYTES
        or _VERSION.fullmatch(value) is None
    ):
        _fail("legacy bridge observation source version is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    try:
        encoded = canonical_company_json_bytes(value)
    except (CompanyContractError, RecursionError) as exc:
        _fail(f"{label} is not bounded canonical JSON: {exc}")
    return hashlib.sha256(encoded).hexdigest()


def _receipt(value: Any) -> LegacyBridgeReceiptRef:
    item = _object(
        value,
        frozenset({"receipt_kind", "receipt_identity_digest", "receipt_sha256"}),
        "legacy bridge observation receipt",
    )
    kind = item["receipt_kind"]
    if type(kind) is not str or kind not in _RECEIPT_KINDS:
        _fail("legacy bridge observation receipt kind is invalid")
    return LegacyBridgeReceiptRef(
        kind,
        _sha(item["receipt_identity_digest"], "legacy receipt identity digest"),
        _sha(item["receipt_sha256"], "legacy receipt payload digest"),
    )


def _entity(value: Any) -> LegacyBridgeEntity:
    fields = frozenset(LegacyBridgeEntity._fields)
    item = _object(value, fields, "legacy bridge observation entity")
    kind = item["kind"]
    if type(kind) is not str or kind not in _KINDS:
        _fail("legacy bridge observation entity kind is invalid")
    status = item["stated_status"]
    if type(status) is not str or status not in _STATUSES[kind]:
        _fail("legacy bridge observation stated status is invalid")
    parent = item["parent_bridge_entity_id"]
    if parent is not None:
        parent = _sha(parent, "legacy bridge parent entity id")
    orphan = item["orphan_reason"]
    if orphan is not None and (type(orphan) is not str or orphan not in _ORPHAN_REASONS):
        _fail("legacy bridge observation orphan reason is invalid")
    expected_engineering = _ENGINEERING[kind][status]
    if item["engineering_status"] != expected_engineering:
        _fail("legacy bridge engineering status differs from stated status")
    if item["runtime_status"] != "unknown" or item["coverage_status"] != "degraded":
        _fail("legacy bridge runtime or coverage truth is overstated")
    expected_effect = "effect_unknown" if kind == "job" and status == "unknown" else "unknown"
    if item["effect_status"] != expected_effect:
        _fail("legacy bridge effect truth differs from stated status")
    expected_needs_user = kind == "needs_user" and status == "needs_user"
    if type(item["needs_user"]) is not bool or item["needs_user"] is not expected_needs_user:
        _fail("legacy bridge needs-user truth differs from stated status")
    raw_refs = item["receipt_refs"]
    if type(raw_refs) is not list or len(raw_refs) > 64:
        _fail("legacy bridge observation receipt refs are invalid")
    refs = tuple(_receipt(ref) for ref in raw_refs)
    if len(set(refs)) != len(refs):
        _fail("legacy bridge observation receipt refs contain duplicates")
    return LegacyBridgeEntity(
        _sha(item["bridge_entity_id"], "legacy bridge entity id"),
        kind,
        _sha(item["legacy_identity_digest"], "legacy identity digest"),
        parent,
        orphan,
        status,
        expected_engineering,
        "unknown",
        "degraded",
        expected_effect,
        expected_needs_user,
        _sha(item["source_record_sha256"], "legacy source record digest"),
        refs,
    )


def _entity_plain(entity: LegacyBridgeEntity) -> dict[str, Any]:
    return entity._asdict() | {
        "receipt_refs": [ref._asdict() for ref in entity.receipt_refs],
    }


def _canonical_entities(
    entities: tuple[LegacyBridgeEntity, ...],
) -> tuple[LegacyBridgeEntity, ...]:
    normalized = tuple(
        entity._replace(
            receipt_refs=tuple(sorted(
                entity.receipt_refs,
                key=lambda ref: (
                    ref.receipt_kind,
                    ref.receipt_identity_digest,
                    ref.receipt_sha256,
                ),
            )),
        )
        for entity in entities
    )
    return tuple(sorted(
        normalized,
        key=lambda entity: (
            _KIND_ORDER[entity.kind],
            entity.legacy_identity_digest,
            entity.bridge_entity_id,
        ),
    ))


def _projection_digest(projection: LegacyBridgeProjectionV1) -> str:
    payload = {
        "domain": "aoi.legacy-bridge.projection.v1",
        "key": projection.key._asdict(),
        "source_kind": projection.source_kind,
        "source_version": projection.source_version,
        "legacy_archive_sha256": projection.legacy_archive_sha256,
        "legacy_state_sha256": projection.legacy_state_sha256,
        "legacy_receipt_set_sha256": projection.legacy_receipt_set_sha256,
        "legacy_receipt_quality": projection.legacy_receipt_quality,
        "observed_at": projection.observed_at,
        "task_identity_digest": projection.task_identity_digest,
        "task_bridge_entity_id": projection.task_bridge_entity_id,
        "entities": [_entity_plain(entity) for entity in projection.entities],
        "snapshot_sha256": projection.snapshot_sha256,
        "truth_boundary": {
            "projection_provenance": projection.projection_provenance,
            "projection_completeness": projection.projection_completeness,
            "authority": projection.authority,
            "repo_write_capability": projection.repo_write_capability,
            "dispatch_capability": projection.dispatch_capability,
            "job_launch_capability": projection.job_launch_capability,
        },
    }
    return _digest(payload, "legacy bridge projection digest input")


def _validate_parent_graph(entities: tuple[LegacyBridgeEntity, ...]) -> None:
    by_id = {entity.bridge_entity_id: entity for entity in entities}
    if len(by_id) != len(entities):
        _fail("legacy bridge observation entity id is ambiguous")
    identities = {(entity.kind, entity.legacy_identity_digest) for entity in entities}
    if len(identities) != len(entities):
        _fail("legacy bridge observation legacy identity is ambiguous")
    for entity in entities:
        parent_id = entity.parent_bridge_entity_id
        if entity.kind == "task":
            if parent_id is not None or entity.orphan_reason is not None:
                _fail("legacy bridge task root parent truth is invalid")
            continue
        if parent_id is None:
            if entity.orphan_reason is None:
                _fail("legacy bridge orphan reason is unavailable")
            continue
        if entity.orphan_reason is not None:
            _fail("legacy bridge joined entity cannot also be orphaned")
        parent = by_id.get(parent_id)
        if parent is None or parent.kind not in _PARENT_KINDS[entity.kind]:
            _fail("legacy bridge explicit parent join is invalid")
        if parent.orphan_reason is not None:
            _fail("legacy bridge joined entity has an orphan ancestor")
    for entity in entities:
        seen: set[str] = set()
        current = entity
        while current.parent_bridge_entity_id is not None:
            if current.bridge_entity_id in seen:
                _fail("legacy bridge projected parent graph contains a cycle")
            seen.add(current.bridge_entity_id)
            current = by_id[current.parent_bridge_entity_id]


def _validate_projection(
    value: Any,
    key: LegacyBridgeCompanyKey,
    *,
    require_canonical_order: bool = True,
) -> LegacyBridgeProjectionV1:
    fields = frozenset(LegacyBridgeProjectionV1._fields) - {"key"}
    item = _object(value, fields, "legacy bridge observation projection")
    raw_entities = item["entities"]
    if type(raw_entities) is not list or not 1 <= len(raw_entities) <= MAX_LIST_ITEMS:
        _fail("legacy bridge observation entities are invalid")
    entities = tuple(_entity(entity) for entity in raw_entities)
    if require_canonical_order and entities != _canonical_entities(entities):
        _fail("legacy bridge observation entity or receipt order is not canonical")
    _validate_parent_graph(entities)
    task_identity = _sha(item["task_identity_digest"], "legacy task identity digest")
    task_bridge_id = _sha(item["task_bridge_entity_id"], "legacy task bridge id")
    roots = [entity for entity in entities if entity.kind == "task"]
    if (
        len(roots) != 1
        or roots[0].bridge_entity_id != task_bridge_id
        or roots[0].legacy_identity_digest != task_identity
    ):
        _fail("legacy bridge observation task root differs")
    quality = item["legacy_receipt_quality"]
    receipt_set = item["legacy_receipt_set_sha256"]
    if type(quality) is not str or quality not in {"exact", "unavailable"}:
        _fail("legacy bridge observation receipt quality is invalid")
    if receipt_set is not None:
        receipt_set = _sha(receipt_set, "legacy receipt set digest")
    if (quality == "exact") != (receipt_set is not None):
        _fail("legacy bridge observation receipt quality and digest differ")
    if quality == "unavailable" and any(entity.receipt_refs for entity in entities):
        _fail("unavailable legacy receipt observation contains receipt refs")
    receipt_identities: dict[str, tuple[str, str]] = {}
    for entity in entities:
        for ref in entity.receipt_refs:
            identity = (ref.receipt_kind, ref.receipt_sha256)
            previous = receipt_identities.setdefault(ref.receipt_identity_digest, identity)
            if previous != identity:
                _fail("legacy receipt identity has divergent projected evidence")
    fixed = {
        "source_kind": LEGACY_BRIDGE_SOURCE_KIND,
        "projection_provenance": "caller_supplied_digest_bound_unverified",
        "projection_completeness": "legacy_state_inventory_only_provider_runtime_unavailable",
        "authority": "none",
        "repo_write_capability": "absent",
        "dispatch_capability": "absent",
        "job_launch_capability": "absent",
    }
    if any(item[field] != expected for field, expected in fixed.items()):
        _fail("legacy bridge observation truth boundary is invalid")
    projection = LegacyBridgeProjectionV1(
        key,
        LEGACY_BRIDGE_SOURCE_KIND,
        _source_version(item["source_version"]),
        _sha(item["legacy_archive_sha256"], "legacy archive digest"),
        _sha(item["legacy_state_sha256"], "legacy state digest"),
        receipt_set,
        quality,
        _timestamp(item["observed_at"], "legacy observed_at"),
        task_identity,
        task_bridge_id,
        entities,
        _sha(item["snapshot_sha256"], "legacy snapshot digest"),
        _sha(item["projection_digest"], "legacy projection digest"),
        fixed["projection_provenance"],
        fixed["projection_completeness"],
        "none",
        "absent",
        "absent",
        "absent",
    )
    if projection.projection_digest != _projection_digest(projection._replace(projection_digest="")):
        _fail("legacy bridge observation projection digest differs")
    return projection


def _projection_plain(projection: LegacyBridgeProjectionV1) -> dict[str, Any]:
    return {
        field: (
            [_entity_plain(entity) for entity in projection.entities]
            if field == "entities"
            else getattr(projection, field)
        )
        for field in LegacyBridgeProjectionV1._fields
        if field != "key"
    }


def _validate_projection_runtime_types(
    projection: LegacyBridgeProjectionV1,
) -> None:
    if type(projection.key) is not LegacyBridgeCompanyKey:
        _fail("legacy bridge projection key has an invalid runtime type")
    if type(projection.entities) is not tuple:
        _fail("legacy bridge projection entities have an invalid runtime type")
    for entity in projection.entities:
        if type(entity) is not LegacyBridgeEntity:
            _fail("legacy bridge projection entity has an invalid runtime type")
        if type(entity.receipt_refs) is not tuple:
            _fail("legacy bridge projection receipt refs have an invalid runtime type")
        if any(type(ref) is not LegacyBridgeReceiptRef for ref in entity.receipt_refs):
            _fail("legacy bridge projection receipt ref has an invalid runtime type")


def _scope_id(projection: LegacyBridgeProjectionV1) -> str:
    return _digest(
        {
            "domain": "aoi.legacy-bridge.scope.v1",
            "key": projection.key._asdict(),
            "source_kind": projection.source_kind,
            "legacy_archive_sha256": projection.legacy_archive_sha256,
            "task_identity_digest": projection.task_identity_digest,
        },
        "legacy bridge scope identity",
    )


def validate_legacy_bridge_observation(value: Any) -> dict[str, Any]:
    fields = frozenset(
        {
            "contract_type", "schema_version", "company_id", "company_incarnation",
            "lock_domain_generation", "bridge_scope_id", "observation_id",
            "ingested_at", "projection", "observation_sha256",
        }
    )
    item = _object(value, fields, "LegacyBridgeObservationV1")
    if (
        item["contract_type"] != LEGACY_BRIDGE_OBSERVATION_V1
        or type(item["schema_version"]) is not int
        or item["schema_version"] != 1
    ):
        _fail("legacy bridge observation discriminator is invalid")
    key = LegacyBridgeCompanyKey(
        _identifier(item["company_id"], "legacy bridge company id"),
        _integer(item["company_incarnation"], "legacy company incarnation", minimum=1),
        _integer(item["lock_domain_generation"], "legacy lock generation", minimum=0),
    )
    projection = _validate_projection(item["projection"], key)
    scope_id = _sha(item["bridge_scope_id"], "legacy bridge scope id")
    if scope_id != _scope_id(projection):
        _fail("legacy bridge observation scope id differs")
    ingested_at = _timestamp(item["ingested_at"], "legacy bridge ingested_at")
    expected_id = _digest(
        {
            "domain": "aoi.legacy-bridge.observation-id.v1",
            "bridge_scope_id": scope_id,
            "projection_digest": projection.projection_digest,
            "ingested_at": ingested_at,
        },
        "legacy bridge observation identity",
    )
    observation_id = _sha(item["observation_id"], "legacy bridge observation id")
    if observation_id != expected_id:
        _fail("legacy bridge observation id differs")
    normalized = {
        "contract_type": LEGACY_BRIDGE_OBSERVATION_V1,
        "schema_version": 1,
        **key._asdict(),
        "bridge_scope_id": scope_id,
        "observation_id": observation_id,
        "ingested_at": ingested_at,
        "projection": _projection_plain(projection),
        "observation_sha256": _sha(
            item["observation_sha256"],
            "legacy bridge observation digest",
        ),
    }
    unsigned = {key: member for key, member in normalized.items() if key != "observation_sha256"}
    if normalized["observation_sha256"] != _digest(unsigned, "legacy observation digest input"):
        _fail("legacy bridge observation digest differs")
    return normalized


def build_legacy_bridge_observation(
    projection: LegacyBridgeProjectionV1,
    *,
    ingested_at: str,
) -> dict[str, Any]:
    """Seal one normalizer output without granting mutation authority."""

    if type(projection) is not LegacyBridgeProjectionV1:
        _fail("legacy bridge projection has an invalid runtime type")
    _validate_projection_runtime_types(projection)
    projection_plain = _projection_plain(projection)
    validated_source = _validate_projection(
        projection_plain,
        projection.key,
        require_canonical_order=False,
    )
    provisional = validated_source._replace(
        entities=_canonical_entities(validated_source.entities),
        projection_digest="",
    )
    durable_projection = provisional._replace(
        projection_digest=_projection_digest(provisional),
    )
    projection_plain = _projection_plain(durable_projection)
    validated_projection = _validate_projection(projection_plain, projection.key)
    scope_id = _scope_id(validated_projection)
    normalized_time = _timestamp(ingested_at, "legacy bridge ingested_at")
    observation_id = _digest(
        {
            "domain": "aoi.legacy-bridge.observation-id.v1",
            "bridge_scope_id": scope_id,
            "projection_digest": validated_projection.projection_digest,
            "ingested_at": normalized_time,
        },
        "legacy bridge observation identity",
    )
    unsigned = {
        "contract_type": LEGACY_BRIDGE_OBSERVATION_V1,
        "schema_version": 1,
        **projection.key._asdict(),
        "bridge_scope_id": scope_id,
        "observation_id": observation_id,
        "ingested_at": normalized_time,
        "projection": projection_plain,
    }
    return validate_legacy_bridge_observation(
        {**unsigned, "observation_sha256": _digest(unsigned, "legacy observation digest input")}
    )


__all__ = [
    "LEGACY_BRIDGE_OBSERVATION_V1",
    "LegacyBridgeContractError",
    "build_legacy_bridge_observation",
    "validate_legacy_bridge_observation",
]
