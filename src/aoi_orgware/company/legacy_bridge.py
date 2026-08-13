"""Pure, non-authoritative normalization for legacy AOI company observations.

The bridge input is a canonical, digest-bound inventory prepared from one
legacy AOI task.  This module does not read a repository, open company state,
write a ledger, dispatch work, or launch a job.  It deliberately leaves
provider runtime, coverage, and effects unknown unless a later typed durable
receipt establishes them.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, NamedTuple, NoReturn

from .contracts import (
    MAX_CONTRACT_BYTES,
    MAX_LIST_ITEMS,
    CompanyContractError,
    canonical_company_json_bytes,
)


LEGACY_BRIDGE_SNAPSHOT_V1 = "legacy_bridge_snapshot_v1"
LEGACY_BRIDGE_SOURCE_KIND = "aoi_legacy_v04"

# Raw identifiers are used only for bounded in-memory joins.  The projection
# exposes domain-separated digests, never these caller-supplied values.
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SOURCE_VERSION_MAX_BYTES = 128
_VERSION = re.compile(
    r"0\.4\.0a(?:3|4)"
    r"(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?"
)
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_KINDS = ("task", "packet", "agent", "job", "needs_user")
_KIND_ORDER = {kind: index for index, kind in enumerate(_KINDS)}
_STATUS_BY_KIND = {
    "task": frozenset({"active", "blocked", "done", "cancelled", "unknown"}),
    "packet": frozenset(
        {"ready", "armed", "dispatched", "done", "failed", "cancelled", "unknown"}
    ),
    "agent": frozenset({"unknown"}),
    "job": frozenset({"queued", "running", "pass", "fail", "stopped", "unknown"}),
    "needs_user": frozenset({"needs_user", "answered", "expired"}),
}
_ALLOWED_PARENT_KINDS = {
    "task": frozenset(),
    "packet": frozenset({"task", "packet"}),
    "agent": frozenset({"packet", "agent"}),
    "job": frozenset({"task", "packet", "agent"}),
    "needs_user": frozenset({"task", "packet", "agent", "job"}),
}
_RECEIPT_KINDS = frozenset(
    {"packet_result", "job_result", "provider_lifecycle", "needs_user"}
)
_RECEIPT_QUALITIES = frozenset({"exact", "unavailable"})


class LegacyBridgeError(CompanyContractError):
    """A legacy bridge inventory is malformed, ambiguous, or overstated."""


class LegacyBridgeCompanyKey(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int


class LegacyBridgeReceiptRef(NamedTuple):
    receipt_kind: str
    receipt_identity_digest: str
    receipt_sha256: str


class LegacyBridgeEntity(NamedTuple):
    bridge_entity_id: str
    kind: str
    legacy_identity_digest: str
    parent_bridge_entity_id: str | None
    orphan_reason: str | None
    stated_status: str
    engineering_status: str
    runtime_status: str
    coverage_status: str
    effect_status: str
    needs_user: bool
    source_record_sha256: str
    receipt_refs: tuple[LegacyBridgeReceiptRef, ...]


class LegacyBridgeProjectionV1(NamedTuple):
    key: LegacyBridgeCompanyKey
    source_kind: str
    source_version: str
    legacy_archive_sha256: str
    legacy_state_sha256: str
    legacy_receipt_set_sha256: str | None
    legacy_receipt_quality: str
    observed_at: str
    task_identity_digest: str
    task_bridge_entity_id: str
    entities: tuple[LegacyBridgeEntity, ...]
    snapshot_sha256: str
    projection_digest: str
    projection_provenance: str
    projection_completeness: str
    authority: str
    repo_write_capability: str
    dispatch_capability: str
    job_launch_capability: str


class _ReceiptRef(NamedTuple):
    receipt_kind: str
    receipt_id: str
    receipt_sha256: str


class _Entry(NamedTuple):
    kind: str
    legacy_id: str
    parent_kind: str | None
    parent_legacy_id: str | None
    stated_status: str
    source_record_sha256: str
    receipt_refs: tuple[_ReceiptRef, ...]


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _exact_object(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
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


def _timestamp(value: Any) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        _fail("legacy bridge observed_at is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        _fail(f"legacy bridge observed_at is invalid: {exc}")
    if parsed.tzinfo is None:
        _fail("legacy bridge observed_at lacks a timezone")
    return value


def _source_version(value: Any) -> str:
    if (
        type(value) is not str
        or len(value.encode("utf-8")) > _SOURCE_VERSION_MAX_BYTES
        or _VERSION.fullmatch(value) is None
    ):
        _fail("legacy bridge source version is invalid")
    return value


def _canonical_input(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_CONTRACT_BYTES:
        _fail("legacy bridge snapshot bytes are invalid")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
        )
        canonical = canonical_company_json_bytes(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        CompanyContractError,
    ) as exc:
        _fail(f"legacy bridge snapshot is not canonical JSON: {exc}")
    if type(value) is not dict or canonical != raw:
        _fail("legacy bridge snapshot bytes are not canonical")
    return value


def _canonical_digest(value: Any, label: str) -> str:
    try:
        encoded = canonical_company_json_bytes(value)
    except (CompanyContractError, RecursionError) as exc:
        _fail(f"{label} is not bounded canonical JSON: {exc}")
    return hashlib.sha256(encoded).hexdigest()


def _receipt_ref(value: Any) -> _ReceiptRef:
    item = _exact_object(
        value,
        frozenset({"receipt_kind", "receipt_id", "receipt_sha256"}),
        "legacy bridge receipt ref",
    )
    kind = item["receipt_kind"]
    if type(kind) is not str or kind not in _RECEIPT_KINDS:
        _fail("legacy bridge receipt kind is invalid")
    return _ReceiptRef(
        kind,
        _identifier(item["receipt_id"], "legacy bridge receipt id"),
        _sha(item["receipt_sha256"], "legacy bridge receipt digest"),
    )


def _entry(value: Any) -> _Entry:
    item = _exact_object(
        value,
        frozenset(
            {
                "kind",
                "legacy_id",
                "parent_kind",
                "parent_legacy_id",
                "stated_status",
                "source_record_sha256",
                "receipt_refs",
            }
        ),
        "legacy bridge entry",
    )
    kind = item["kind"]
    if type(kind) is not str or kind not in _KINDS:
        _fail("legacy bridge entry kind is invalid")
    legacy_id = _identifier(item["legacy_id"], "legacy bridge entry id")
    parent_kind = item["parent_kind"]
    parent_id = item["parent_legacy_id"]
    if (parent_kind is None) != (parent_id is None):
        _fail("legacy bridge parent identity is partial")
    if parent_kind is not None:
        if type(parent_kind) is not str or parent_kind not in _KINDS:
            _fail("legacy bridge parent kind is invalid")
        parent_id = _identifier(parent_id, "legacy bridge parent id")
    status = item["stated_status"]
    if type(status) is not str or status not in _STATUS_BY_KIND[kind]:
        _fail("legacy bridge stated status is invalid")
    raw_refs = item["receipt_refs"]
    if type(raw_refs) is not list or len(raw_refs) > 64:
        _fail("legacy bridge receipt refs are invalid")
    refs = tuple(sorted((_receipt_ref(ref) for ref in raw_refs)))
    if len(set(refs)) != len(refs):
        _fail("legacy bridge receipt refs contain duplicates")
    return _Entry(
        kind,
        legacy_id,
        parent_kind,
        parent_id,
        status,
        _sha(item["source_record_sha256"], "legacy bridge source record digest"),
        refs,
    )


def _entity_id(
    key: LegacyBridgeCompanyKey,
    archive_sha256: str,
    task_id: str,
    kind: str,
    legacy_id: str,
) -> str:
    payload = {
        "domain": "aoi.legacy-bridge.entity.v1",
        "company": key._asdict(),
        "legacy_archive_sha256": archive_sha256,
        "task_id": task_id,
        "kind": kind,
        "legacy_id": legacy_id,
    }
    return _canonical_digest(payload, "legacy bridge entity identity")


def _identity_digest(kind: str, legacy_id: str) -> str:
    payload = {
        "domain": "aoi.legacy-bridge.legacy-identity.v1",
        "kind": kind,
        "legacy_id": legacy_id,
    }
    return _canonical_digest(payload, "legacy bridge redacted identity")


def _project_receipt_ref(ref: _ReceiptRef) -> LegacyBridgeReceiptRef:
    return LegacyBridgeReceiptRef(
        ref.receipt_kind,
        _identity_digest(f"receipt:{ref.receipt_kind}", ref.receipt_id),
        ref.receipt_sha256,
    )


def _engineering(kind: str, status: str) -> str:
    mapping = {
        "task": {
            "active": "active",
            "blocked": "blocked",
            "done": "completed",
            "cancelled": "cancelled",
            "unknown": "unknown",
        },
        "packet": {
            "ready": "waiting",
            "armed": "waiting",
            "dispatched": "active",
            "done": "completed",
            "failed": "blocked",
            "cancelled": "cancelled",
            "unknown": "unknown",
        },
        "agent": {"unknown": "unknown"},
        "job": {
            "queued": "waiting",
            "running": "active",
            "pass": "completed",
            "fail": "blocked",
            "stopped": "unknown",
            "unknown": "unknown",
        },
        "needs_user": {
            "needs_user": "waiting",
            "answered": "completed",
            "expired": "cancelled",
        },
    }
    return mapping[kind][status]


def _effect(kind: str, status: str) -> str:
    if kind == "job" and status == "unknown":
        return "effect_unknown"
    return "unknown"


def _receipt_set_digest(entries: tuple[_Entry, ...]) -> str:
    inventory = sorted(
        [
            {
                "entry_kind": entry.kind,
                "entry_legacy_id": entry.legacy_id,
                **ref._asdict(),
            }
            for entry in entries
            for ref in entry.receipt_refs
        ],
        key=lambda item: (
            item["entry_kind"],
            item["entry_legacy_id"].encode("utf-8"),
            item["receipt_kind"],
            item["receipt_id"].encode("utf-8"),
            item["receipt_sha256"],
        ),
    )
    return _canonical_digest(inventory, "legacy receipt set digest input")


def _semantic_snapshot_digest(
    item: dict[str, Any],
    entries: tuple[_Entry, ...],
) -> str:
    """Hash the snapshot as an unordered, normalized entity inventory."""

    normalized_entries = [
        {
            "kind": entry.kind,
            "legacy_id": entry.legacy_id,
            "parent_kind": entry.parent_kind,
            "parent_legacy_id": entry.parent_legacy_id,
            "stated_status": entry.stated_status,
            "source_record_sha256": entry.source_record_sha256,
            "receipt_refs": [ref._asdict() for ref in entry.receipt_refs],
        }
        for entry in sorted(
            entries,
            key=lambda entry: (
                _KIND_ORDER[entry.kind],
                entry.legacy_id.encode("utf-8"),
            ),
        )
    ]
    normalized = {key: value for key, value in item.items() if key != "entries"}
    normalized["entries"] = normalized_entries
    return _canonical_digest(normalized, "legacy semantic snapshot digest input")


def _parent_resolution(
    entry: _Entry,
    entries: dict[tuple[str, str], _Entry],
) -> tuple[tuple[str, str] | None, str | None]:
    if entry.kind == "task":
        return None, None
    if entry.parent_kind is None or entry.parent_legacy_id is None:
        return None, "explicit_parent_unavailable"
    parent = (entry.parent_kind, entry.parent_legacy_id)
    if entry.parent_kind not in _ALLOWED_PARENT_KINDS[entry.kind]:
        return None, "explicit_parent_kind_not_allowed"
    if parent not in entries:
        return None, "explicit_parent_absent"
    if parent == (entry.kind, entry.legacy_id):
        return None, "explicit_parent_cycle"
    return parent, None


def _valid_parent_chains(
    entries: dict[tuple[str, str], _Entry],
) -> tuple[dict[tuple[str, str], tuple[str, str] | None], dict[tuple[str, str], str]]:
    parents: dict[tuple[str, str], tuple[str, str] | None] = {}
    reasons: dict[tuple[str, str], str] = {}
    for identity, entry in entries.items():
        parent, reason = _parent_resolution(entry, entries)
        parents[identity] = parent
        if reason is not None:
            reasons[identity] = reason

    state: dict[tuple[str, str], int] = {}

    def visit(identity: tuple[str, str], stack: tuple[tuple[str, str], ...]) -> bool:
        known = state.get(identity)
        if known is not None:
            return known == 2
        if identity in stack:
            start = stack.index(identity)
            for cycle_identity in stack[start:]:
                reasons[cycle_identity] = "explicit_parent_cycle"
                parents[cycle_identity] = None
                state[cycle_identity] = 3
            return False
        if identity in reasons:
            state[identity] = 3
            return False
        parent = parents[identity]
        if parent is None:
            state[identity] = 2
            return True
        if not visit(parent, (*stack, identity)):
            if identity not in reasons:
                reasons[identity] = "explicit_parent_ancestor_invalid"
                parents[identity] = None
            state[identity] = 3
            return False
        state[identity] = 2
        return True

    for identity in entries:
        visit(identity, ())
    return parents, reasons


def _projection_digest(value: LegacyBridgeProjectionV1) -> str:
    payload = {
        "domain": "aoi.legacy-bridge.projection.v1",
        "key": value.key._asdict(),
        "source_kind": value.source_kind,
        "source_version": value.source_version,
        "legacy_archive_sha256": value.legacy_archive_sha256,
        "legacy_state_sha256": value.legacy_state_sha256,
        "legacy_receipt_set_sha256": value.legacy_receipt_set_sha256,
        "legacy_receipt_quality": value.legacy_receipt_quality,
        "observed_at": value.observed_at,
        "task_identity_digest": value.task_identity_digest,
        "task_bridge_entity_id": value.task_bridge_entity_id,
        "entities": [
            entity._asdict()
            | {"receipt_refs": [ref._asdict() for ref in entity.receipt_refs]}
            for entity in value.entities
        ],
        "snapshot_sha256": value.snapshot_sha256,
        "truth_boundary": {
            "projection_provenance": value.projection_provenance,
            "projection_completeness": value.projection_completeness,
            "authority": value.authority,
            "repo_write_capability": value.repo_write_capability,
            "dispatch_capability": value.dispatch_capability,
            "job_launch_capability": value.job_launch_capability,
        },
    }
    return _canonical_digest(payload, "legacy projection digest input")


def normalize_legacy_bridge_snapshot(raw: bytes) -> LegacyBridgeProjectionV1:
    """Normalize one canonical legacy inventory without creating authority."""

    value = _canonical_input(raw)
    item = _exact_object(
        value,
        frozenset(
            {
                "document_type",
                "schema_version",
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
                "source_kind",
                "source_version",
                "legacy_archive_sha256",
                "legacy_state_sha256",
                "legacy_receipt_set_sha256",
                "legacy_receipt_quality",
                "observed_at",
                "task_id",
                "entries",
            }
        ),
        "legacy bridge snapshot",
    )
    if (
        type(item["document_type"]) is not str
        or item["document_type"] != LEGACY_BRIDGE_SNAPSHOT_V1
        or type(item["schema_version"]) is not int
        or item["schema_version"] != 1
    ):
        _fail("legacy bridge snapshot discriminator is invalid")
    key = LegacyBridgeCompanyKey(
        _identifier(item["company_id"], "legacy bridge company id"),
        _integer(
            item["company_incarnation"],
            "legacy bridge company incarnation",
            minimum=1,
        ),
        _integer(
            item["lock_domain_generation"],
            "legacy bridge lock generation",
            minimum=0,
        ),
    )
    if item["source_kind"] != LEGACY_BRIDGE_SOURCE_KIND:
        _fail("legacy bridge source kind is invalid")
    version = _source_version(item["source_version"])
    archive_sha = _sha(item["legacy_archive_sha256"], "legacy archive digest")
    state_sha = _sha(item["legacy_state_sha256"], "legacy state digest")
    quality = item["legacy_receipt_quality"]
    if type(quality) is not str or quality not in _RECEIPT_QUALITIES:
        _fail("legacy receipt quality is invalid")
    receipt_sha = item["legacy_receipt_set_sha256"]
    if receipt_sha is not None:
        receipt_sha = _sha(receipt_sha, "legacy receipt set digest")
    if (quality == "exact") != (receipt_sha is not None):
        _fail("legacy receipt digest and quality differ")
    observed_at = _timestamp(item["observed_at"])
    task_id = _identifier(item["task_id"], "legacy bridge task id")
    raw_entries = item["entries"]
    if type(raw_entries) is not list or not 1 <= len(raw_entries) <= MAX_LIST_ITEMS:
        _fail("legacy bridge entries are invalid")
    parsed_entries = tuple(_entry(entry) for entry in raw_entries)
    snapshot_sha256 = _semantic_snapshot_digest(item, parsed_entries)
    identities = [(entry.kind, entry.legacy_id) for entry in parsed_entries]
    if len(set(identities)) != len(identities):
        _fail("legacy bridge entry identity is ambiguous")
    entries = {identity: entry for identity, entry in zip(identities, parsed_entries)}
    task_entries = [
        entry
        for entry in parsed_entries
        if entry.kind == "task" and entry.legacy_id == task_id
    ]
    if (
        len(task_entries) != 1
        or sum(entry.kind == "task" for entry in parsed_entries) != 1
    ):
        _fail("legacy bridge snapshot requires exactly one matching task root")
    task_entry = task_entries[0]
    if task_entry.parent_kind is not None or task_entry.parent_legacy_id is not None:
        _fail("legacy bridge task root cannot have a parent")
    if quality == "unavailable" and any(entry.receipt_refs for entry in parsed_entries):
        _fail("unavailable legacy receipt inventory cannot contain receipt refs")
    receipt_identities: dict[str, tuple[str, str]] = {}
    for entry in parsed_entries:
        for ref in entry.receipt_refs:
            identity = (ref.receipt_kind, ref.receipt_sha256)
            previous = receipt_identities.setdefault(ref.receipt_id, identity)
            if previous != identity:
                _fail("legacy receipt identity has divergent evidence")
    if quality == "exact" and receipt_sha != _receipt_set_digest(parsed_entries):
        _fail("legacy receipt set digest differs")

    parents, orphan_reasons = _valid_parent_chains(entries)
    ordered = sorted(
        entries.items(),
        key=lambda pair: (_KIND_ORDER[pair[0][0]], pair[0][1].encode("utf-8")),
    )
    projected: list[LegacyBridgeEntity] = []
    for identity, entry in ordered:
        parent = parents[identity]
        parent_id = (
            None
            if parent is None
            else _entity_id(key, archive_sha, task_id, parent[0], parent[1])
        )
        projected.append(
            LegacyBridgeEntity(
                _entity_id(key, archive_sha, task_id, entry.kind, entry.legacy_id),
                entry.kind,
                _identity_digest(entry.kind, entry.legacy_id),
                parent_id,
                orphan_reasons.get(identity),
                entry.stated_status,
                _engineering(entry.kind, entry.stated_status),
                "unknown",
                "degraded",
                _effect(entry.kind, entry.stated_status),
                entry.kind == "needs_user" and entry.stated_status == "needs_user",
                entry.source_record_sha256,
                tuple(_project_receipt_ref(ref) for ref in entry.receipt_refs),
            )
        )
    task_bridge_id = _entity_id(key, archive_sha, task_id, "task", task_id)
    provisional = LegacyBridgeProjectionV1(
        key,
        LEGACY_BRIDGE_SOURCE_KIND,
        version,
        archive_sha,
        state_sha,
        receipt_sha,
        quality,
        observed_at,
        _identity_digest("task", task_id),
        task_bridge_id,
        tuple(projected),
        snapshot_sha256,
        "",
        "caller_supplied_digest_bound_unverified",
        "legacy_state_inventory_only_provider_runtime_unavailable",
        "none",
        "absent",
        "absent",
        "absent",
    )
    return provisional._replace(projection_digest=_projection_digest(provisional))


__all__ = [
    "LEGACY_BRIDGE_SNAPSHOT_V1",
    "LEGACY_BRIDGE_SOURCE_KIND",
    "LegacyBridgeCompanyKey",
    "LegacyBridgeEntity",
    "LegacyBridgeError",
    "LegacyBridgeProjectionV1",
    "LegacyBridgeReceiptRef",
    "normalize_legacy_bridge_snapshot",
]
