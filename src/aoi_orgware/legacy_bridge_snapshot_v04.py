"""Bounded, read-only producer for one legacy v0.4 bridge snapshot.

This adapter intentionally exports a small inventory only.  It does not infer
relationships from names, lanes, timestamps, paths, or task prose, and it
never exposes source-state content in the resulting bridge document.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from typing import Any, NamedTuple, NoReturn

from .company.contracts import CompanyContractError, canonical_company_json_bytes
from .company.legacy_bridge import (
    LEGACY_BRIDGE_SNAPSHOT_V1,
    LEGACY_BRIDGE_SOURCE_KIND,
    LegacyBridgeProjectionV1,
    normalize_legacy_bridge_snapshot,
)
from .evidence_artifacts import read_regular_artifact
from .harnesslib import (
    MANAGED_JSON_MAX_BYTES,
    HarnessError,
    HarnessPaths,
    is_semantic_v2_task,
    state_lock,
    task_state_path,
    validate_task_claim_references,
    validate_task_state,
)


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ROOTED_AGENT_ID = re.compile(
    r"/root/[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*"
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SOURCE_VERSION = re.compile(
    r"0\.4\.0a(?:3|4)(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?"
)
_STATUS = {
    "task": {"active", "blocked", "done", "cancelled"},
    "packet": {"ready", "armed", "dispatched", "done", "failed", "cancelled"},
    "job": {"queued", "running", "pass", "fail", "stopped", "unknown"},
    "needs_user": {"needs_user", "resolved", "cancelled"},
}


class LegacyBridgeSnapshotV04Error(CompanyContractError):
    """The bounded v0.4 legacy observation cannot be safely produced."""


class LegacyBridgeSnapshotV04Result(NamedTuple):
    """Immutable canonical snapshot bytes, digest, and validated projection."""

    snapshot_bytes: bytes
    snapshot_sha256: str
    projection: LegacyBridgeProjectionV1


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeSnapshotV04Error(message)


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def legacy_bridge_agent_id_v04(raw_agent_id: Any) -> str:
    """Map a raw v0.4 agent ID into the bridge-safe identity domain."""

    if type(raw_agent_id) is not str:
        _fail("legacy agent id is invalid")
    if _SAFE_ID.fullmatch(raw_agent_id) is not None:
        return raw_agent_id
    if len(raw_agent_id) <= 256 and _ROOTED_AGENT_ID.fullmatch(raw_agent_id) is not None:
        digest = hashlib.sha256(
            b"aoi-orgware:legacy-bridge-agent-v04\x00" + raw_agent_id.encode("utf-8")
        ).hexdigest()
        return f"root@{digest}"
    _fail("legacy agent id is invalid")


def _integer(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= 999_999_999:
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _source_version(value: Any) -> str:
    if type(value) is not str:
        _fail("source_version is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail("source_version is invalid")
    if len(encoded) > 128 or _SOURCE_VERSION.fullmatch(value) is None:
        _fail("source_version is invalid")
    return value


def _canonical_digest(value: Any, label: str) -> str:
    try:
        return hashlib.sha256(canonical_company_json_bytes(value)).hexdigest()
    except (CompanyContractError, RecursionError, TypeError, ValueError):
        _fail(f"{label} is not bounded canonical JSON")


def _record(
    item: Any, *, kind: str, identity_field: str, parent_field: str | None = None
) -> tuple[str, str, dict[str, Any]]:
    if type(item) is not dict:
        _fail(f"legacy {kind} record is invalid")
    identity = _identifier(item.get(identity_field), f"legacy {kind} id")
    status = item.get("status")
    if type(status) is not str or status not in _STATUS[kind]:
        _fail(f"legacy {kind} status is invalid")
    if parent_field is not None:
        parent = item.get(parent_field, "")
        if parent is None:
            parent = ""
        if type(parent) is not str or (parent and _SAFE_ID.fullmatch(parent) is None):
            _fail(f"legacy {kind} parent is invalid")
    return identity, status, item


def _unique(
    records: list[tuple[str, str, dict[str, Any]]], label: str
) -> list[tuple[str, str, dict[str, Any]]]:
    identities = [record[0] for record in records]
    if len(identities) != len(set(identities)):
        _fail(f"legacy {label} identifiers are ambiguous")
    return sorted(records, key=lambda record: record[0].encode("utf-8"))


def _agent_records(state: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    raw_packets = state.get("packets", [])
    if type(raw_packets) is not list:
        _fail("legacy packets are invalid")
    owners: dict[str, tuple[str, dict[str, Any]]] = {}
    for packet in raw_packets:
        if type(packet) is not dict:
            _fail("legacy packet record is invalid")
        packet_id = _identifier(packet.get("packet_id"), "legacy packet id")
        agent_id = packet.get("agent_id", "")
        if agent_id in (None, ""):
            continue
        agent_id = legacy_bridge_agent_id_v04(agent_id)
        owner = owners.setdefault(agent_id, (packet_id, packet))
        if owner[0] != packet_id:
            _fail("legacy agent belongs to multiple packets")
    return [
        (agent_id, "unknown", owner[1])
        for agent_id, owner in sorted(owners.items(), key=lambda item: item[0].encode("utf-8"))
    ]


def _entries(state: dict[str, Any], task_id: str, state_digest: str) -> list[dict[str, Any]]:
    task_status = state.get("status")
    if type(task_status) is not str or task_status not in _STATUS["task"]:
        _fail("legacy task status is invalid")
    entries: list[dict[str, Any]] = [
        {
            "kind": "task", "legacy_id": task_id, "parent_kind": None,
            "parent_legacy_id": None, "stated_status": task_status,
            "source_record_sha256": state_digest, "receipt_refs": [],
        }
    ]
    raw_packets = state.get("packets", [])
    if type(raw_packets) is not list:
        _fail("legacy packets are invalid")
    packets = _unique(
        [_record(item, kind="packet", identity_field="packet_id", parent_field="parent_packet_id") for item in raw_packets],
        "packet",
    )
    for packet_id, status, record in packets:
        parent_id = record.get("parent_packet_id", "") or ""
        entries.append({
            "kind": "packet", "legacy_id": packet_id,
            "parent_kind": "packet" if parent_id else "task",
            "parent_legacy_id": parent_id or task_id, "stated_status": status,
            "source_record_sha256": _canonical_digest(record, "legacy packet record"),
            "receipt_refs": [],
        })
    for agent_id, _, record in _agent_records(state):
        entries.append({
            "kind": "agent", "legacy_id": agent_id, "parent_kind": "packet",
            "parent_legacy_id": _identifier(record.get("packet_id"), "legacy packet id"), "stated_status": "unknown",
            "source_record_sha256": _canonical_digest(record, "legacy agent record"),
            "receipt_refs": [],
        })
    raw_jobs = state.get("jobs", [])
    if type(raw_jobs) is not list:
        _fail("legacy jobs are invalid")
    jobs = _unique(
        [_record(item, kind="job", identity_field="run_id", parent_field="owner_packet_id") for item in raw_jobs],
        "job",
    )
    for run_id, status, record in jobs:
        owner = record.get("owner_packet_id", "") or ""
        entries.append({
            "kind": "job", "legacy_id": run_id,
            "parent_kind": "packet" if owner else None,
            "parent_legacy_id": owner or None, "stated_status": status,
            "source_record_sha256": _canonical_digest(record, "legacy job record"),
            "receipt_refs": [],
        })
    raw_needs_user = state.get("needs_user_escalations", [])
    if type(raw_needs_user) is not list:
        _fail("legacy needs-user escalations are invalid")
    needs_user = _unique(
        [_record(item, kind="needs_user", identity_field="escalation_id") for item in raw_needs_user],
        "needs-user escalation",
    )
    for escalation_id, status, record in needs_user:
        entries.append({
            "kind": "needs_user", "legacy_id": escalation_id,
            "parent_kind": None, "parent_legacy_id": None,
            "stated_status": {"resolved": "answered", "cancelled": "expired"}.get(status, status),
            "source_record_sha256": _canonical_digest(record, "legacy needs-user record"),
            "receipt_refs": [],
        })
    return entries


def _stable_state_read(path: Any) -> tuple[tuple[int, int], bytes]:
    """Use the public artifact reader, then pin the path identity after its read."""

    resolved, payload = read_regular_artifact(
        path, "legacy task state", max_bytes=MANAGED_JSON_MAX_BYTES
    )
    try:
        metadata = os.lstat(resolved)
    except OSError:
        _fail("legacy task state identity read failed")
    return (metadata.st_dev, metadata.st_ino), payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("non-finite number")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite number")
    return parsed


def _parse_exact_state(raw: bytes) -> dict[str, Any]:
    """Parse precisely the first bounded state bytes; never trigger another read."""

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail("legacy task state bytes are invalid")
    if type(value) is not dict:
        _fail("legacy task state must be an object")
    return value


def _validate_legacy_integrity(paths: HarnessPaths, state: dict[str, Any]) -> None:
    """Reuse current CLI-composed legacy integrity policies without diagnostics.

    The CLI is AOI's composition root for these current policy factories.  This
    read-only local import avoids copying that configuration; only a fixed
    producer error crosses this adapter boundary.
    """

    try:
        from . import cli

        errors = (
            cli.packet_integrity_errors(paths, state)
            + cli.job_integrity_errors(paths, state)
            + cli.portfolio_integrity_errors(state, paths)
        )
    except MemoryError:
        raise
    except Exception:
        _fail("legacy task integrity validation failed")
    if errors:
        _fail("legacy task integrity validation failed")


def produce_legacy_bridge_snapshot_v04(
    paths: HarnessPaths,
    task_id: str,
    company_id: str,
    incarnation: int,
    generation: int,
    legacy_archive_sha256: str,
    source_version: str,
    observed_at: str,
) -> LegacyBridgeSnapshotV04Result:
    """Produce a canonical, redacted snapshot of one non-semantic v0.4 task."""

    if not isinstance(paths, HarnessPaths):
        _fail("paths must be HarnessPaths")
    task_id = _identifier(task_id, "task_id")
    company_id = _identifier(company_id, "company_id")
    incarnation = _integer(incarnation, "incarnation", minimum=1)
    generation = _integer(generation, "generation", minimum=0)
    archive_sha = _sha(legacy_archive_sha256, "legacy_archive_sha256")
    source_version = _source_version(source_version)
    if type(observed_at) is not str:
        _fail("observed_at is invalid")
    try:
        with state_lock(paths, create_layout=False):
            if is_semantic_v2_task(paths, task_id):
                _fail("semantic-v2 tasks are not legacy v0.4 sources")
            state_path = task_state_path(paths, task_id)
            before_identity, before_bytes = _stable_state_read(state_path)
            state = _parse_exact_state(before_bytes)
            validate_task_state(state, state_path, paths=paths)
            if (
                state.get("task_id") != task_id
                or state.get("profile_id") != paths.project.profile_id
                or state.get("config_sha256") != paths.project.sha256
            ):
                _fail("legacy task binding is invalid")
            validate_task_claim_references(paths, state)
            _validate_legacy_integrity(paths, state)
            after_identity, after_bytes = _stable_state_read(state_path)
    except LegacyBridgeSnapshotV04Error:
        raise
    except (CompanyContractError, HarnessError, OSError, ValueError, TypeError, RecursionError):
        _fail("legacy v0.4 task read failed")
    if before_identity != after_identity or before_bytes != after_bytes:
        _fail("legacy task state changed during bounded snapshot read")
    state_sha = hashlib.sha256(before_bytes).hexdigest()
    try:
        document = {
            "document_type": LEGACY_BRIDGE_SNAPSHOT_V1, "schema_version": 1,
            "company_id": company_id, "company_incarnation": incarnation,
            "lock_domain_generation": generation, "source_kind": LEGACY_BRIDGE_SOURCE_KIND,
            "source_version": source_version, "legacy_archive_sha256": archive_sha,
            "legacy_state_sha256": state_sha, "legacy_receipt_set_sha256": None,
            "legacy_receipt_quality": "unavailable", "observed_at": observed_at,
            "task_id": task_id, "entries": _entries(state, task_id, state_sha),
        }
        snapshot_bytes = canonical_company_json_bytes(document)
        projection = normalize_legacy_bridge_snapshot(snapshot_bytes)
    except LegacyBridgeSnapshotV04Error:
        raise
    except (CompanyContractError, ValueError, TypeError, RecursionError):
        _fail("legacy v0.4 snapshot is invalid")
    return LegacyBridgeSnapshotV04Result(
        snapshot_bytes, hashlib.sha256(snapshot_bytes).hexdigest(), projection
    )


__all__ = [
    "LegacyBridgeSnapshotV04Error", "LegacyBridgeSnapshotV04Result",
    "legacy_bridge_agent_id_v04", "produce_legacy_bridge_snapshot_v04",
]
