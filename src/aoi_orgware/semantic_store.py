"""Filesystem persistence for semantic-v2 task ledgers.

This module deliberately owns only the small persistence boundary between the
pure :mod:`semantic_events` contract and AOI's existing atomic-file helpers.
The ledger is authoritative; ``state.json`` is a replaceable projection.  It
does not acquire the task/state lock itself: callers that append transitions
must do that at their lifecycle authority boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import harnesslib as h
from . import semantic_events as semantic
from ._version import __version__


SEMANTIC_DIRECTORY_NAME = "semantic-v2"
SEMANTIC_EVENTS_DIRECTORY_NAME = "events"
LEGACY_SNAPSHOT_NAME = "legacy-state.json"
MIGRATION_RECEIPT_NAME = "migration-receipt.json"
MIGRATION_ROLLBACK_NAME = "migration-rollback.json"
MIGRATION_ROLLBACK_COMPLETION_NAME = "migration-rollback-complete.json"
MIGRATION_SCHEMA_VERSION = 1
MIGRATION_ROLLBACK_SCHEMA_VERSION = 1
MIGRATION_ROLLBACK_COMPLETION_SCHEMA_VERSION = 1
MAX_MIGRATION_RECORD_BYTES = 256 * 1024
MAX_SEMANTIC_EVENT_FILES = min(
    semantic.MAX_LEDGER_EVENTS, h.TREE_IDENTITY_SCAN_MAX_ENTRIES
)


class SemanticStoreError(h.HarnessError):
    """The semantic ledger or its filesystem representation is unsafe."""


@dataclass(frozen=True)
class SemanticAppendResult:
    """Result of one authoritative compare-and-append operation."""

    projection: dict[str, Any]
    event: dict[str, Any]
    idempotent_replay: bool


def semantic_event_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    """Return the fixed ledger directory without creating or inspecting it."""

    return h.task_dir(paths, task_id) / SEMANTIC_DIRECTORY_NAME / SEMANTIC_EVENTS_DIRECTORY_NAME


def _semantic_root(paths: h.HarnessPaths, task_id: str) -> Path:
    return h.task_dir(paths, task_id) / SEMANTIC_DIRECTORY_NAME


def _store_error(message: str, exc: BaseException | None = None) -> SemanticStoreError:
    if exc is None:
        return SemanticStoreError(message)
    return SemanticStoreError(f"{message}: {exc}")


def _require_private_directory(path: Path, label: str, *, create: bool) -> Path:
    """Reject link-like/non-private directories before enumerating them."""

    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        existed = canonical.exists()
        if not existed:
            if not create:
                raise FileNotFoundError(canonical)
            canonical.mkdir(parents=True, exist_ok=False)
            if os.name != "nt":
                os.chmod(canonical, 0o700)
        h.validate_existing_regular_directory(canonical, label)
        metadata = canonical.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise SemanticStoreError(f"{label} is not a directory: {canonical}")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SemanticStoreError(f"{label} is not private: {canonical}")
        if h.canonicalize_no_link_traversal(canonical, label) != canonical:
            raise SemanticStoreError(f"{label} changed while being checked: {canonical}")
        return canonical
    except SemanticStoreError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _store_error(f"invalid {label}", exc) from exc


def _event_directory_exists(paths: h.HarnessPaths, task_id: str) -> bool:
    root = _semantic_root(paths, task_id)
    events = semantic_event_directory(paths, task_id)
    try:
        root_canonical = h.canonicalize_no_link_traversal(root, "semantic ledger root")
        events_canonical = h.canonicalize_no_link_traversal(
            events, "semantic event directory"
        )
    except h.HarnessError as exc:
        raise _store_error("invalid semantic ledger path", exc) from exc
    if not root_canonical.exists() and not events_canonical.exists():
        return False
    if root_canonical.exists() and not events_canonical.exists():
        # Creating the root and its events child cannot be one filesystem
        # transaction.  A process kill between those mkdir operations leaves
        # one private, empty root.  Treat only that exact state as an
        # uninitialized ledger so an exact init retry can finish the tree.
        # Any residue remains fail-closed.
        _require_private_directory(
            root_canonical, "semantic ledger root", create=False
        )
        try:
            root_has_residue = h.directory_has_any_entry(
                root_canonical, "semantic ledger root"
            )
        except h.HarnessError as exc:
            raise _store_error("cannot inspect incomplete semantic ledger root", exc) from exc
        if root_has_residue:
            raise SemanticStoreError(
                "semantic ledger directory tree is incomplete and its root is not empty"
            )
        return False
    # An events directory without its validated root cannot be recovered as a
    # new ledger.  It indicates replacement or injected filesystem state.
    if not root_canonical.exists() or not events_canonical.exists():
        raise SemanticStoreError("semantic ledger directory tree is incomplete")
    _require_private_directory(root_canonical, "semantic ledger root", create=False)
    _require_private_directory(events_canonical, "semantic event directory", create=False)
    return True


def has_semantic_ledger(paths: h.HarnessPaths, task_id: str) -> bool:
    """Return whether a complete semantic ledger directory tree exists."""

    exists = _event_directory_exists(paths, task_id)
    if not exists:
        return False
    marker = _migration_rollback_path(paths, task_id)
    if not marker.exists():
        return True
    completion = _migration_rollback_completion_path(paths, task_id)
    if completion.exists():
        # Once the exact restore has its own immutable completion receipt the
        # semantic history is inert.  Later legitimate legacy transitions may
        # advance state away from the preserved snapshot without reactivating
        # the old ledger.
        _validate_migration_rollback_completion(paths, task_id)
        return False
    # Marker publication precedes state restoration.  Until the separate
    # completion receipt exists, keep the semantic boundary active so only the
    # explicit rollback retry can finish the interrupted transaction.
    _validate_migration_rollback_marker(paths, task_id, require_state_match=False)
    return True


def semantic_ledger_is_empty(paths: h.HarnessPaths, task_id: str) -> bool:
    """Return whether a complete private ledger tree has no published event."""

    if not _event_directory_exists(paths, task_id):
        return False
    return _event_directory_is_empty(semantic_event_directory(paths, task_id))


def _create_event_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    task = h.task_dir(paths, task_id)
    try:
        task = h.canonicalize_no_link_traversal(task, "semantic task directory")
        h.validate_existing_regular_directory(task, "semantic task directory")
        if not task.exists():
            raise SemanticStoreError(f"semantic task directory is missing: {task}")
    except SemanticStoreError:
        raise
    except h.HarnessError as exc:
        raise _store_error("invalid semantic task directory", exc) from exc
    root = _require_private_directory(
        _semantic_root(paths, task_id), "semantic ledger root", create=True
    )
    return _require_private_directory(
        root / SEMANTIC_EVENTS_DIRECTORY_NAME, "semantic event directory", create=True
    )


def _require_private_event_file(path: Path) -> None:
    try:
        h.validate_existing_regular_file(path, "semantic event")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SemanticStoreError(f"semantic event is not a private regular file: {path}")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SemanticStoreError(f"semantic event is not private: {path}")
    except SemanticStoreError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _store_error("invalid semantic event file", exc) from exc


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SemanticStoreError(f"semantic JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _decode_canonical_event(path: Path) -> dict[str, Any]:
    _require_private_event_file(path)
    try:
        _identity, payload = h._read_regular_file_snapshot(
            path, "semantic event", max_bytes=semantic.MAX_EVENT_BYTES
        )
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except SemanticStoreError:
        raise
    except (h.HarnessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _store_error(f"invalid semantic event bytes at {path}", exc) from exc
    if not isinstance(value, dict):
        raise SemanticStoreError(f"semantic event must be a JSON object: {path}")
    try:
        canonical = semantic.canonical_json_bytes(value, max_bytes=semantic.MAX_EVENT_BYTES)
    except semantic.SemanticEventError as exc:
        raise _store_error(f"invalid semantic event at {path}", exc) from exc
    if payload != canonical:
        raise SemanticStoreError(f"semantic event bytes are not canonical JSON: {path}")
    return value


def _enumerate_event_paths(event_directory: Path) -> list[tuple[int, Path]]:
    """Enumerate exactly one bounded, private, contiguous event namespace."""

    entries: list[tuple[int, Path]] = []
    try:
        with os.scandir(event_directory) as scan:
            for entry in scan:
                if len(entries) >= MAX_SEMANTIC_EVENT_FILES:
                    raise SemanticStoreError(
                        "semantic ledger reached its event-file enumeration bound"
                    )
                try:
                    sequence = semantic.parse_event_filename(entry.name)
                except semantic.SemanticEventError as exc:
                    raise _store_error(
                        f"unexpected file in semantic event directory: {entry.name!r}", exc
                    ) from exc
                path = event_directory / entry.name
                # ``DirEntry.is_file`` must not follow a link.  Recheck with
                # harnesslib before opening so a replacement cannot become a
                # different managed-file class between enumeration and read.
                if not entry.is_file(follow_symlinks=False) or entry.is_symlink():
                    raise SemanticStoreError(f"semantic event is not a regular file: {path}")
                _require_private_event_file(path)
                entries.append((sequence, path))
    except SemanticStoreError:
        raise
    except OSError as exc:
        raise _store_error("cannot enumerate semantic event directory", exc) from exc
    entries.sort(key=lambda item: item[0])
    if not entries:
        raise SemanticStoreError("semantic ledger has no genesis event")
    for expected, (sequence, _path) in enumerate(entries, start=1):
        if sequence != expected:
            raise SemanticStoreError("semantic ledger filename sequence gap or reordering")
    return entries


def _event_directory_is_empty(event_directory: Path) -> bool:
    try:
        with os.scandir(event_directory) as scan:
            return next(scan, None) is None
    except OSError as exc:
        raise _store_error("cannot inspect semantic event directory", exc) from exc


def _read_ledger(paths: h.HarnessPaths, task_id: str) -> list[dict[str, Any]]:
    if not _event_directory_exists(paths, task_id):
        raise SemanticStoreError(f"semantic ledger is missing for task {task_id}")
    event_directory = semantic_event_directory(paths, task_id)
    events = [_decode_canonical_event(path) for _sequence, path in _enumerate_event_paths(event_directory)]
    try:
        semantic.replay_events(events)
    except semantic.SemanticEventError as exc:
        raise _store_error("semantic ledger replay failed", exc) from exc
    return events


def _replay_ledger(paths: h.HarnessPaths, task_id: str) -> dict[str, Any]:
    events = _read_ledger(paths, task_id)
    try:
        return semantic.replay_events(events)
    except semantic.SemanticEventError as exc:  # defensive: _read_ledger already validates
        raise _store_error("semantic ledger replay failed", exc) from exc


def semantic_head(paths: h.HarnessPaths, task_id: str) -> dict[str, Any]:
    """Return the authenticated current head without exposing mutable storage."""

    events = _read_ledger(paths, task_id)
    head = events[-1]
    return {
        "sequence": head["sequence"],
        "event_sha256": head["event_sha256"],
        "command_id": head["command_id"],
        "event_type": head["event_type"],
    }


def load_semantic_events(paths: h.HarnessPaths, task_id: str) -> list[dict[str, Any]]:
    """Return the complete authenticated ledger as detached in-memory records.

    This is the public integration boundary for lifecycle writers that need to
    prepare an exact content-binding transaction.  The records are decoded
    afresh from canonical storage and fully replay-validated before return;
    mutating the returned list cannot mutate the persisted ledger.
    """

    return _read_ledger(paths, task_id)


def preflight_semantic_append(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    command_id: str,
    expected_head_sha256: str,
) -> dict[str, Any]:
    """Fail before publishing side artifacts for a new semantic command.

    This is not the commit CAS; :func:`append_semantic_transition` rechecks the
    same conditions immediately before event publication.  It lets lifecycle
    commands that must stage an immutable artifact first reject a stale head or
    reused command id without corrupting their currently referenced artifact.
    """

    h._require_chief_lock(paths)
    task_id = h.validate_id(task_id, "task id")
    command_id = h.validate_id(command_id, "semantic command id")
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_head_sha256)):
        raise SemanticStoreError("semantic expected head SHA-256 is invalid")
    events = _read_ledger(paths, task_id)
    if events[-1]["event_sha256"] != expected_head_sha256:
        raise SemanticStoreError(
            "semantic expected head does not match current authority"
        )
    if any(event.get("command_id") == command_id for event in events):
        raise SemanticStoreError("semantic command id already exists")
    return dict(events[-1])


def _read_projection(paths: h.HarnessPaths, task_id: str) -> dict[str, Any] | None:
    path = h.task_state_path(paths, task_id)
    if not path.exists():
        return None
    try:
        _identity, raw = h._read_regular_file_snapshot(
            path, "semantic projection", max_bytes=semantic.MAX_CANONICAL_JSON_BYTES
        )
        projection = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except SemanticStoreError:
        raise
    except (h.HarnessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _store_error("invalid semantic projection bytes", exc) from exc
    if not isinstance(projection, dict):
        raise SemanticStoreError("semantic projection must be a JSON object")
    return projection


def _projection_bytes(projection: dict[str, Any]) -> bytes:
    payload = (
        json.dumps(projection, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    if len(payload) > h.MANAGED_JSON_MAX_BYTES:
        raise SemanticStoreError(
            "semantic projection exceeds the managed state byte bound"
        )
    return payload


def legacy_snapshot_path(paths: h.HarnessPaths, task_id: str) -> Path:
    return _semantic_root(paths, task_id) / LEGACY_SNAPSHOT_NAME


def migration_receipt_path(paths: h.HarnessPaths, task_id: str) -> Path:
    return _semantic_root(paths, task_id) / MIGRATION_RECEIPT_NAME


def _migration_rollback_path(paths: h.HarnessPaths, task_id: str) -> Path:
    return _semantic_root(paths, task_id) / MIGRATION_ROLLBACK_NAME


def _migration_rollback_completion_path(
    paths: h.HarnessPaths, task_id: str
) -> Path:
    return _semantic_root(paths, task_id) / MIGRATION_ROLLBACK_COMPLETION_NAME


def _read_canonical_record(path: Path, label: str) -> dict[str, Any]:
    _require_private_event_file(path)
    try:
        _identity, raw = h._read_regular_file_snapshot(
            path, label, max_bytes=MAX_MIGRATION_RECORD_BYTES
        )
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        if not isinstance(value, dict):
            raise SemanticStoreError(f"{label} must be a JSON object")
        canonical = semantic.canonical_json_bytes(
            value, max_bytes=MAX_MIGRATION_RECORD_BYTES
        )
    except SemanticStoreError:
        raise
    except (h.HarnessError, UnicodeDecodeError, json.JSONDecodeError, semantic.SemanticEventError) as exc:
        raise _store_error(f"invalid {label}", exc) from exc
    if raw != canonical:
        raise SemanticStoreError(f"{label} bytes are not canonical JSON")
    return value


def _record_sha256(record: dict[str, Any], field: str) -> str:
    preimage = {key: value for key, value in record.items() if key != field}
    return semantic.canonical_sha256(preimage, max_bytes=MAX_MIGRATION_RECORD_BYTES)


def _migration_receipt_for(
    *,
    task_id: str,
    command_id: str,
    event: dict[str, Any],
    legacy_bytes: bytes,
    legacy_state: dict[str, Any],
    profile_id: str,
    config_sha256: str,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "migration_schema_version": MIGRATION_SCHEMA_VERSION,
        "task_id": task_id,
        "command_id": command_id,
        "legacy_snapshot_relative_path": f"{SEMANTIC_DIRECTORY_NAME}/{LEGACY_SNAPSHOT_NAME}",
        "legacy_snapshot_sha256": hashlib.sha256(legacy_bytes).hexdigest(),
        "legacy_snapshot_size": len(legacy_bytes),
        "legacy_projection_sha256": semantic.canonical_sha256(legacy_state),
        "genesis_event_sha256": event["event_sha256"],
        "authority_ref": event["authority_ref"],
        "migrated_at": event["recorded_at"],
        "tool_version": __version__,
        "profile_id": profile_id,
        "config_sha256": config_sha256,
    }
    record["migration_receipt_sha256"] = _record_sha256(
        record, "migration_receipt_sha256"
    )
    return record


def _validate_migration_receipt_record(record: dict[str, Any]) -> dict[str, Any]:
    required = {
        "migration_schema_version",
        "task_id",
        "command_id",
        "legacy_snapshot_relative_path",
        "legacy_snapshot_sha256",
        "legacy_snapshot_size",
        "legacy_projection_sha256",
        "genesis_event_sha256",
        "authority_ref",
        "migrated_at",
        "tool_version",
        "profile_id",
        "config_sha256",
        "migration_receipt_sha256",
    }
    if set(record) != required or record.get("migration_schema_version") != 1:
        raise SemanticStoreError("semantic migration receipt schema is invalid")
    for field in required - {"migration_schema_version", "legacy_snapshot_size"}:
        if not isinstance(record.get(field), str) or not record[field]:
            raise SemanticStoreError(f"semantic migration receipt {field} is invalid")
    if (
        isinstance(record.get("legacy_snapshot_size"), bool)
        or not isinstance(record.get("legacy_snapshot_size"), int)
        or record["legacy_snapshot_size"] < 2
        or record["legacy_snapshot_size"] > h.MANAGED_JSON_MAX_BYTES
    ):
        raise SemanticStoreError("semantic migration receipt snapshot size is invalid")
    for field in (
        "legacy_snapshot_sha256",
        "legacy_projection_sha256",
        "genesis_event_sha256",
        "config_sha256",
        "migration_receipt_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", record[field]):
            raise SemanticStoreError(f"semantic migration receipt {field} is invalid")
    if record["legacy_snapshot_relative_path"] != (
        f"{SEMANTIC_DIRECTORY_NAME}/{LEGACY_SNAPSHOT_NAME}"
    ):
        raise SemanticStoreError("semantic migration snapshot path is invalid")
    if record["migration_receipt_sha256"] != _record_sha256(
        record, "migration_receipt_sha256"
    ):
        raise SemanticStoreError("semantic migration receipt digest mismatch")
    return dict(record)


def validate_semantic_migration(
    paths: h.HarnessPaths, task_id: str
) -> dict[str, Any]:
    """Authenticate a legacy genesis, its exact snapshot, and migration receipt."""

    events = _read_ledger(paths, task_id)
    genesis = events[0]
    if genesis.get("event_type") != "legacy_genesis":
        raise SemanticStoreError("semantic task does not have a legacy migration genesis")
    receipt = _validate_migration_receipt_record(
        _read_canonical_record(
            migration_receipt_path(paths, task_id), "semantic migration receipt"
        )
    )
    snapshot = legacy_snapshot_path(paths, task_id)
    _require_private_event_file(snapshot)
    try:
        _identity, raw = h._read_regular_file_snapshot(
            snapshot, "semantic legacy snapshot", max_bytes=h.MANAGED_JSON_MAX_BYTES
        )
        legacy = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (h.HarnessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _store_error("invalid semantic legacy snapshot", exc) from exc
    if not isinstance(legacy, dict):
        raise SemanticStoreError("semantic legacy snapshot must be a JSON object")
    if (
        receipt["task_id"] != task_id
        or receipt["command_id"] != genesis["command_id"]
        or receipt["genesis_event_sha256"] != genesis["event_sha256"]
        or receipt["authority_ref"] != genesis["authority_ref"]
        or receipt["migrated_at"] != genesis["recorded_at"]
        or receipt["legacy_snapshot_size"] != len(raw)
        or receipt["legacy_snapshot_sha256"] != hashlib.sha256(raw).hexdigest()
        or receipt["legacy_projection_sha256"] != semantic.canonical_sha256(legacy)
        or receipt["profile_id"] != legacy.get("profile_id")
        or receipt["config_sha256"] != legacy.get("config_sha256")
        or legacy.get("task_id") != task_id
        or genesis["payload"].get("legacy_snapshot_sha256")
        != receipt["legacy_snapshot_sha256"]
        or semantic.canonical_json_bytes(genesis["payload"].get("snapshot"))
        != semantic.canonical_json_bytes(legacy)
    ):
        raise SemanticStoreError("semantic migration cross-binding is invalid")
    return receipt


def _migration_quiescence_errors(state: dict[str, Any]) -> list[str]:
    """Boundedly classify nested legacy execution state before migration.

    This is deliberately stricter than silently ignoring malformed entries:
    migration may only snapshot a task whose execution side effects are
    understood.  In particular, arbitrary nested JSON must not escape as a
    Python ``TypeError`` from this authority boundary.
    """

    errors: list[str] = []
    packets = state.get("packets", [])
    if not isinstance(packets, list):
        errors.append("packet collection is malformed")
    else:
        for index, packet in enumerate(packets):
            if not isinstance(packet, dict):
                errors.append(f"packet {index} is malformed")
                continue
            packet_id = packet.get("packet_id", "<unknown>")
            packet_status = packet.get("status")
            if not isinstance(packet_status, str):
                errors.append(f"packet {packet_id} status is malformed")
            elif packet_status not in h.PACKET_STATUSES:
                errors.append(f"packet {packet_id} status is unknown")
            elif packet_status in {"armed", "dispatched"}:
                errors.append(f"packet {packet_id} is executing")
            attempts = packet.get("dispatch_attempts", [])
            if not isinstance(attempts, list):
                errors.append(f"packet {packet_id} dispatch attempts are malformed")
                continue
            for attempt_index, attempt in enumerate(attempts):
                if not isinstance(attempt, dict):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} is malformed"
                    )
                else:
                    attempt_status = attempt.get("status")
                    if not isinstance(attempt_status, str):
                        errors.append(
                            f"packet {packet_id} dispatch attempt {attempt_index} status is malformed"
                        )
                    elif attempt_status not in {
                        "armed",
                        "consumed",
                        "transport_reserved",
                        "disarmed",
                        "expired",
                    }:
                        errors.append(
                            f"packet {packet_id} dispatch attempt {attempt_index} status is unknown"
                        )
                    elif attempt_status == "armed":
                        errors.append(f"packet {packet_id} has a live arm")

    jobs = state.get("jobs", [])
    if not isinstance(jobs, list):
        errors.append("job collection is malformed")
    else:
        for index, job in enumerate(jobs):
            if not isinstance(job, dict):
                errors.append(f"job {index} is malformed")
            else:
                job_status = job.get("status")
                if not isinstance(job_status, str):
                    errors.append(f"job {job.get('job_id', '<unknown>')} status is malformed")
                elif job_status not in h.JOB_STATUSES:
                    errors.append(f"job {job.get('job_id', '<unknown>')} status is unknown")
                elif job_status in h.ACTIVE_JOB_STATUSES:
                    errors.append(f"job {job.get('job_id', '<unknown>')} is active")

    incidents = state.get("subagent_incidents", [])
    if not isinstance(incidents, list):
        errors.append("subagent incident collection is malformed")
    else:
        for index, incident in enumerate(incidents):
            if not isinstance(incident, dict):
                errors.append(f"subagent incident {index} is malformed")
            else:
                incident_status = incident.get("status")
                if not isinstance(incident_status, str):
                    errors.append(
                        f"subagent incident {incident.get('incident_id', '<unknown>')} status is malformed"
                    )
                elif incident_status not in {"open", "accounted"}:
                    errors.append(
                        f"subagent incident {incident.get('incident_id', '<unknown>')} status is unknown"
                    )
                elif incident_status == "open":
                    errors.append(
                        f"subagent incident {incident.get('incident_id', '<unknown>')} is open"
                    )
    return sorted(set(errors))


def migrate_legacy_task(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    command_id: str,
    expected_legacy_sha256: str,
    recorded_at: str,
    authority_ref: str,
) -> SemanticAppendResult:
    """Cut one quiescent legacy task over to a byte-preserving semantic genesis."""

    h._require_chief_lock(paths)
    task_id = h.validate_id(task_id, "task id")
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_legacy_sha256)):
        raise SemanticStoreError("expected legacy state SHA-256 is invalid")
    if _migration_rollback_path(paths, task_id).exists():
        raise SemanticStoreError("semantic migration was rolled back and is an inert archive")

    event_directory_exists = _event_directory_exists(paths, task_id)
    events: list[dict[str, Any]] | None = None
    if event_directory_exists and not _event_directory_is_empty(
        semantic_event_directory(paths, task_id)
    ):
        events = _read_ledger(paths, task_id)
        genesis = events[0]
        if (
            genesis.get("event_type") != "legacy_genesis"
            or genesis.get("command_id") != command_id
            or genesis.get("payload", {}).get("legacy_snapshot_sha256")
            != expected_legacy_sha256
        ):
            raise SemanticStoreError("semantic migration command conflicts with the ledger")
        snapshot = legacy_snapshot_path(paths, task_id)
        _require_private_event_file(snapshot)
        _identity, legacy_bytes = h._read_regular_file_snapshot(
            snapshot,
            "semantic legacy snapshot",
            max_bytes=h.MANAGED_JSON_MAX_BYTES,
        )
        try:
            legacy_state = json.loads(
                legacy_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _store_error("invalid semantic legacy snapshot", exc) from exc
        if not isinstance(legacy_state, dict):
            raise SemanticStoreError("semantic legacy snapshot must be a JSON object")
        receipt = _migration_receipt_for(
            task_id=task_id,
            command_id=command_id,
            event=genesis,
            legacy_bytes=legacy_bytes,
            legacy_state=legacy_state,
            profile_id=str(legacy_state.get("profile_id", "")),
            config_sha256=str(legacy_state.get("config_sha256", "")),
        )
        receipt_path = migration_receipt_path(paths, task_id)
        receipt_bytes = semantic.canonical_json_bytes(
            receipt, max_bytes=MAX_MIGRATION_RECORD_BYTES
        )
        if not receipt_path.exists():
            h.atomic_create_bytes(receipt_path, receipt_bytes)
        # If a prior invocation published the receipt under an older AOI
        # version, its sealed tool_version remains historical evidence.  Full
        # validation below cross-binds every authoritative field; do not make
        # an exact retry depend on the currently installed package version.
        validate_semantic_migration(paths, task_id)
        projection = semantic.replay_events(events)
        current_state_path = h.task_state_path(paths, task_id)
        _current_identity, current_bytes = h._read_regular_file_snapshot(
            current_state_path,
            "semantic migration projection",
            max_bytes=h.MANAGED_JSON_MAX_BYTES,
        )
        if current_bytes == legacy_bytes:
            h.atomic_write_bytes(current_state_path, _projection_bytes(projection))
        else:
            projection = repair_semantic_projection(paths, task_id)
        return SemanticAppendResult(
            projection=projection,
            event=dict(genesis),
            idempotent_replay=True,
        )

    snapshot_path = legacy_snapshot_path(paths, task_id)
    state_path = h.task_state_path(paths, task_id)
    try:
        if snapshot_path.exists():
            _require_private_event_file(snapshot_path)
            _identity, legacy_bytes = h._read_regular_file_snapshot(
                snapshot_path,
                "semantic legacy snapshot",
                max_bytes=h.MANAGED_JSON_MAX_BYTES,
            )
            # A kill after publishing only the snapshot leaves the task on the
            # legacy writer path.  Another legacy command may then acquire the
            # lock and advance state before this command is retried.  The
            # unpublished snapshot is not authority, so never use it to erase
            # a newer live legacy state.
            _live_identity, live_legacy_bytes = h._read_regular_file_snapshot(
                state_path,
                "legacy task state",
                max_bytes=h.MANAGED_JSON_MAX_BYTES,
            )
            if live_legacy_bytes != legacy_bytes:
                raise SemanticStoreError(
                    "legacy task state changed after the migration snapshot"
                )
        else:
            _identity, legacy_bytes = h._read_regular_file_snapshot(
                state_path, "legacy task state", max_bytes=h.MANAGED_JSON_MAX_BYTES
            )
        legacy_state = json.loads(
            legacy_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (h.HarnessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _store_error("invalid legacy task state", exc) from exc
    if not isinstance(legacy_state, dict):
        raise SemanticStoreError("legacy task state must be a JSON object")
    if hashlib.sha256(legacy_bytes).hexdigest() != expected_legacy_sha256:
        raise SemanticStoreError("legacy task state changed from the expected bytes")
    if legacy_state.get("task_id") != task_id or semantic.SEMANTIC_ENVELOPE_KEY in legacy_state:
        raise SemanticStoreError("legacy task identity or schema is invalid")
    try:
        h.validate_task_state(legacy_state, state_path)
    except (h.HarnessError, TypeError, ValueError, KeyError) as exc:
        raise _store_error("invalid legacy task state", exc) from exc
    if (
        legacy_state.get("profile_id") != paths.project.profile_id
        or legacy_state.get("config_sha256") != paths.project.sha256
    ):
        raise SemanticStoreError("legacy task configuration binding is not current")
    quiescence_errors = _migration_quiescence_errors(legacy_state)
    if quiescence_errors:
        raise SemanticStoreError(
            "legacy task is not quiescent: " + "; ".join(quiescence_errors)
        )
    temporary_records = h.scan_atomic_temporaries(paths)
    if temporary_records:
        raise SemanticStoreError(
            "managed temporary residue blocks semantic migration"
        )

    if not event_directory_exists:
        _create_event_directory(paths, task_id)
    if not snapshot_path.exists():
        h.atomic_create_bytes(snapshot_path, legacy_bytes)
    else:
        _identity, persisted_snapshot = h._read_regular_file_snapshot(
            snapshot_path,
            "semantic legacy snapshot",
            max_bytes=h.MANAGED_JSON_MAX_BYTES,
        )
        if persisted_snapshot != legacy_bytes:
            raise SemanticStoreError("semantic legacy snapshot conflicts with live bytes")
    try:
        event = semantic.create_legacy_genesis_event(
            legacy_state,
            legacy_snapshot_sha256=expected_legacy_sha256,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=authority_ref,
        )
        projection = semantic.projection_for_event(legacy_state, event)
        _projection_bytes(projection)
    except semantic.SemanticEventError as exc:
        raise _store_error("invalid semantic migration event", exc) from exc
    event_path = semantic_event_directory(paths, task_id) / semantic.event_filename(1)
    if not event_path.exists():
        h.atomic_create_bytes(
            event_path,
            semantic.canonical_json_bytes(event, max_bytes=semantic.MAX_EVENT_BYTES),
        )
    else:
        published = _read_ledger(paths, task_id)
        try:
            existing = semantic.resolve_command_retry(published, event)
        except semantic.SemanticEventError as exc:
            raise _store_error("semantic migration event conflicts", exc) from exc
        if existing is None:
            raise SemanticStoreError("semantic migration event publication conflicted")
        event = existing
    receipt = _migration_receipt_for(
        task_id=task_id,
        command_id=command_id,
        event=event,
        legacy_bytes=legacy_bytes,
        legacy_state=legacy_state,
        profile_id=str(legacy_state["profile_id"]),
        config_sha256=str(legacy_state["config_sha256"]),
    )
    receipt_path = migration_receipt_path(paths, task_id)
    receipt_bytes = semantic.canonical_json_bytes(
        receipt, max_bytes=MAX_MIGRATION_RECORD_BYTES
    )
    if not receipt_path.exists():
        h.atomic_create_bytes(receipt_path, receipt_bytes)
    elif _read_canonical_record(receipt_path, "semantic migration receipt") != receipt:
        raise SemanticStoreError("semantic migration receipt conflicts with the event")
    validate_semantic_migration(paths, task_id)
    h.atomic_write_bytes(state_path, _projection_bytes(projection))
    return SemanticAppendResult(
        projection=projection,
        event=dict(event),
        idempotent_replay=False,
    )


def _rollback_marker_preimage(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "rollback_sha256"}


def _rollback_completion_preimage(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key != "rollback_completion_sha256"
    }


def _validate_migration_rollback_marker(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    require_state_match: bool,
) -> dict[str, Any]:
    marker = _read_canonical_record(
        _migration_rollback_path(paths, task_id), "semantic migration rollback"
    )
    required = {
        "rollback_schema_version",
        "task_id",
        "command_id",
        "migration_receipt_sha256",
        "head_event_sha256",
        "legacy_snapshot_sha256",
        "authority_ref",
        "rolled_back_at",
        "rollback_sha256",
    }
    if set(marker) != required or marker.get("rollback_schema_version") != 1:
        raise SemanticStoreError("semantic migration rollback schema is invalid")
    if marker.get("task_id") != task_id:
        raise SemanticStoreError("semantic migration rollback task binding is invalid")
    for field in required - {"rollback_schema_version"}:
        if not isinstance(marker.get(field), str) or not marker[field]:
            raise SemanticStoreError(f"semantic migration rollback {field} is invalid")
    try:
        h.validate_id(marker["command_id"], "semantic rollback command id")
        if h.parse_tz_aware_time(marker["rolled_back_at"]) is None:
            raise SemanticStoreError(
                "semantic migration rollback timestamp is invalid"
            )
    except h.HarnessError as exc:
        raise _store_error("semantic migration rollback identity is invalid", exc) from exc
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,159}", marker["authority_ref"]):
        raise SemanticStoreError("semantic migration rollback authority is invalid")
    for field in (
        "migration_receipt_sha256",
        "head_event_sha256",
        "legacy_snapshot_sha256",
        "rollback_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", marker[field]):
            raise SemanticStoreError(f"semantic migration rollback {field} is invalid")
    if marker["rollback_sha256"] != semantic.canonical_sha256(
        _rollback_marker_preimage(marker), max_bytes=MAX_MIGRATION_RECORD_BYTES
    ):
        raise SemanticStoreError("semantic migration rollback digest mismatch")
    events = _read_ledger(paths, task_id)
    receipt = validate_semantic_migration(paths, task_id)
    if (
        len(events) != 1
        or events[0]["event_sha256"] != marker["head_event_sha256"]
        or receipt["migration_receipt_sha256"]
        != marker["migration_receipt_sha256"]
        or receipt["legacy_snapshot_sha256"] != marker["legacy_snapshot_sha256"]
    ):
        raise SemanticStoreError("semantic migration rollback authority is invalid")
    if require_state_match and not _rollback_live_state_matches_snapshot(paths, task_id):
        raise SemanticStoreError("semantic migration rollback state restoration is incomplete")
    return marker


def _rollback_live_state_matches_snapshot(
    paths: h.HarnessPaths, task_id: str
) -> bool:
    try:
        _state_identity, state_bytes = h._read_regular_file_snapshot(
            h.task_state_path(paths, task_id),
            "rolled-back legacy task state",
            max_bytes=h.MANAGED_JSON_MAX_BYTES,
        )
        _snapshot_identity, snapshot_bytes = h._read_regular_file_snapshot(
            legacy_snapshot_path(paths, task_id),
            "semantic legacy snapshot",
            max_bytes=h.MANAGED_JSON_MAX_BYTES,
        )
    except h.HarnessError:
        return False
    return state_bytes == snapshot_bytes


def _validate_migration_rollback_completion(
    paths: h.HarnessPaths, task_id: str
) -> dict[str, Any]:
    marker = _validate_migration_rollback_marker(
        paths, task_id, require_state_match=False
    )
    completion = _read_canonical_record(
        _migration_rollback_completion_path(paths, task_id),
        "semantic migration rollback completion",
    )
    required = {
        "rollback_completion_schema_version",
        "task_id",
        "rollback_sha256",
        "legacy_snapshot_sha256",
        "restored_state_sha256",
        "restored_at",
        "rollback_completion_sha256",
    }
    if (
        set(completion) != required
        or completion.get("rollback_completion_schema_version")
        != MIGRATION_ROLLBACK_COMPLETION_SCHEMA_VERSION
    ):
        raise SemanticStoreError(
            "semantic migration rollback completion schema is invalid"
        )
    for field in required - {"rollback_completion_schema_version"}:
        if not isinstance(completion.get(field), str) or not completion[field]:
            raise SemanticStoreError(
                f"semantic migration rollback completion {field} is invalid"
            )
    for field in (
        "rollback_sha256",
        "legacy_snapshot_sha256",
        "restored_state_sha256",
        "rollback_completion_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", completion[field]):
            raise SemanticStoreError(
                f"semantic migration rollback completion {field} is invalid"
            )
    if h.parse_tz_aware_time(completion["restored_at"]) is None:
        raise SemanticStoreError(
            "semantic migration rollback completion timestamp is invalid"
        )
    if (
        completion["task_id"] != task_id
        or completion["rollback_sha256"] != marker["rollback_sha256"]
        or completion["legacy_snapshot_sha256"]
        != marker["legacy_snapshot_sha256"]
        or completion["restored_state_sha256"]
        != marker["legacy_snapshot_sha256"]
        or completion["restored_at"] != marker["rolled_back_at"]
        or completion["rollback_completion_sha256"]
        != semantic.canonical_sha256(
            _rollback_completion_preimage(completion),
            max_bytes=MAX_MIGRATION_RECORD_BYTES,
        )
    ):
        raise SemanticStoreError(
            "semantic migration rollback completion cross-binding is invalid"
        )
    return completion


def semantic_migration_rolled_back(paths: h.HarnessPaths, task_id: str) -> bool:
    marker = _migration_rollback_path(paths, task_id)
    if not marker.exists():
        return False
    if not _migration_rollback_completion_path(paths, task_id).exists():
        raise SemanticStoreError(
            "semantic migration rollback is incomplete"
        )
    _validate_migration_rollback_completion(paths, task_id)
    return True


def rollback_semantic_migration(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    command_id: str,
    expected_head_sha256: str,
    expected_migration_receipt_sha256: str,
    recorded_at: str,
    authority_ref: str,
) -> tuple[dict[str, Any], bool]:
    """Restore exact legacy bytes only while migration genesis is still the head."""

    h._require_chief_lock(paths)
    task_id = h.validate_id(task_id, "task id")
    events = _read_ledger(paths, task_id)
    receipt = validate_semantic_migration(paths, task_id)
    if (
        len(events) != 1
        or events[0]["event_type"] != "legacy_genesis"
        or events[0]["event_sha256"] != expected_head_sha256
        or receipt["migration_receipt_sha256"]
        != expected_migration_receipt_sha256
    ):
        raise SemanticStoreError(
            "semantic migration rollback requires the exact untouched migration genesis"
        )
    marker_path = _migration_rollback_path(paths, task_id)
    marker_preexisted = marker_path.exists()
    if marker_preexisted:
        marker = _validate_migration_rollback_marker(
            paths, task_id, require_state_match=False
        )
        if marker.get("command_id") != command_id:
            raise SemanticStoreError("semantic migration rollback command conflicts")
    else:
        marker = {
            "rollback_schema_version": MIGRATION_ROLLBACK_SCHEMA_VERSION,
            "task_id": task_id,
            "command_id": h.validate_id(command_id, "semantic rollback command id"),
            "migration_receipt_sha256": receipt["migration_receipt_sha256"],
            "head_event_sha256": events[0]["event_sha256"],
            "legacy_snapshot_sha256": receipt["legacy_snapshot_sha256"],
            "authority_ref": authority_ref,
            "rolled_back_at": recorded_at,
        }
        marker["rollback_sha256"] = semantic.canonical_sha256(
            _rollback_marker_preimage(marker), max_bytes=MAX_MIGRATION_RECORD_BYTES
        )
        h.atomic_create_bytes(
            marker_path,
            semantic.canonical_json_bytes(marker, max_bytes=MAX_MIGRATION_RECORD_BYTES),
        )
    completion_path = _migration_rollback_completion_path(paths, task_id)
    if completion_path.exists():
        _validate_migration_rollback_completion(paths, task_id)
        return marker, True
    if not _rollback_live_state_matches_snapshot(paths, task_id):
        _identity, legacy_bytes = h._read_regular_file_snapshot(
            legacy_snapshot_path(paths, task_id),
            "semantic legacy snapshot",
            max_bytes=h.MANAGED_JSON_MAX_BYTES,
        )
        h.atomic_write_bytes(h.task_state_path(paths, task_id), legacy_bytes)
    completion = {
        "rollback_completion_schema_version": (
            MIGRATION_ROLLBACK_COMPLETION_SCHEMA_VERSION
        ),
        "task_id": task_id,
        "rollback_sha256": marker["rollback_sha256"],
        "legacy_snapshot_sha256": marker["legacy_snapshot_sha256"],
        "restored_state_sha256": marker["legacy_snapshot_sha256"],
        "restored_at": marker["rolled_back_at"],
    }
    completion["rollback_completion_sha256"] = semantic.canonical_sha256(
        _rollback_completion_preimage(completion),
        max_bytes=MAX_MIGRATION_RECORD_BYTES,
    )
    h.atomic_create_bytes(
        completion_path,
        semantic.canonical_json_bytes(
            completion, max_bytes=MAX_MIGRATION_RECORD_BYTES
        ),
    )
    _validate_migration_rollback_completion(paths, task_id)
    return marker, marker_preexisted


def semantic_integrity_errors(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    require_current_projection: bool = False,
) -> list[str]:
    """Return bounded ledger/projection/migration integrity errors for gates."""

    try:
        if _migration_rollback_path(paths, task_id).exists():
            _validate_migration_rollback_completion(paths, task_id)
            return []
        if not _event_directory_exists(paths, task_id):
            return []
        events = _read_ledger(paths, task_id)
        projection = _read_projection(paths, task_id)
        if projection is None:
            if require_current_projection:
                raise SemanticStoreError("semantic projection is missing")
        else:
            status = semantic.validate_projection(events, projection).status
            if require_current_projection and status != "current":
                raise SemanticStoreError(f"semantic projection is {status}")
        if events[0].get("event_type") == "legacy_genesis":
            validate_semantic_migration(paths, task_id)
        return []
    except (
        SemanticStoreError,
        semantic.SemanticEventError,
        h.HarnessError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        return [str(exc)]


def semantic_projection_status(paths: h.HarnessPaths, task_id: str) -> str:
    """Classify a valid projection as ``current``, ``behind``, or ``missing``."""

    events = _read_ledger(paths, task_id)
    projection = _read_projection(paths, task_id)
    if projection is None:
        return "missing"
    try:
        return semantic.validate_projection(events, projection).status
    except semantic.SemanticEventError as exc:
        raise _store_error("semantic projection diverges from its ledger", exc) from exc


def load_semantic_task(paths: h.HarnessPaths, task_id: str) -> dict[str, Any]:
    """Return the authoritative in-memory projection, replaying a valid tail."""

    events = _read_ledger(paths, task_id)
    try:
        projection = semantic.replay_events(events)
    except semantic.SemanticEventError as exc:  # defensive: _read_ledger already validates
        raise _store_error("semantic ledger replay failed", exc) from exc
    stored = _read_projection(paths, task_id)
    if stored is not None:
        try:
            semantic.validate_projection(events, stored)
        except semantic.SemanticEventError as exc:
            raise _store_error("semantic projection diverges from its ledger", exc) from exc
    return projection


def repair_semantic_projection(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    expected_command_id: str | None = None,
) -> dict[str, Any]:
    """Explicitly publish the replayed projection if it is missing or behind."""

    if expected_command_id is not None:
        events = _read_ledger(paths, task_id)
        if events[0]["command_id"] != expected_command_id:
            raise SemanticStoreError(
                "semantic genesis command id differs from the requested retry"
            )
    projection = load_semantic_task(paths, task_id)
    status = semantic_projection_status(paths, task_id)
    if status in {"missing", "behind"}:
        try:
            h.atomic_write_bytes(
                h.task_state_path(paths, task_id), _projection_bytes(projection)
            )
        except h.HarnessError as exc:
            raise _store_error("cannot publish semantic projection", exc) from exc
    return projection


def _transition_retry(
    events: list[dict[str, Any]],
    *,
    command_id: str,
    event_type: str,
    authority_ref: str | None,
    expected_head_sha256: str,
    result_domain: dict[str, Any],
) -> SemanticAppendResult | None:
    """Recognize only an exact, still-terminal retry of a published command."""

    matches = [event for event in events if event.get("command_id") == command_id]
    if not matches:
        return None
    if len(matches) != 1:
        raise SemanticStoreError("semantic command id is not unique")
    existing = matches[0]
    if existing is not events[-1]:
        raise SemanticStoreError(
            "semantic command already exists but is no longer the ledger head"
        )
    if (
        existing.get("event_type") != event_type
        or (
            authority_ref is not None
            and existing.get("authority_ref") != authority_ref
        )
        or existing.get("prev_event_sha256") != expected_head_sha256
        or existing.get("result_projection_sha256")
        != semantic.canonical_sha256(result_domain)
    ):
        raise SemanticStoreError("semantic command id was reused for different semantics")
    projection = semantic.replay_events(events)
    if semantic.canonical_json_bytes(semantic.projection_domain(projection)) != (
        semantic.canonical_json_bytes(result_domain)
    ):
        raise SemanticStoreError("semantic retry result differs from the published event")
    return SemanticAppendResult(
        projection=projection,
        event=dict(existing),
        idempotent_replay=True,
    )


def published_semantic_close_summary(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    command_id: str,
    expected_head_sha256: str,
) -> str:
    """Return the one summary appended by an exact terminal close event.

    ``facts`` is cumulative, so membership in the latest projection cannot
    establish which fact a previous close command added.  Reconstruct the
    immediately preceding and resulting domains from the immutable ledger and
    accept only a close transition that appended exactly one non-empty string.
    """

    h._require_chief_lock(paths)
    try:
        task_id = h.validate_id(task_id, "task id")
        command_id = h.validate_id(command_id, "semantic command id")
        if not re.fullmatch(r"[0-9a-f]{64}", str(expected_head_sha256)):
            raise SemanticStoreError("semantic expected head SHA-256 is invalid")
        events = _read_ledger(paths, task_id)
        matches = [event for event in events if event.get("command_id") == command_id]
        if len(matches) != 1 or matches[0] is not events[-1]:
            raise SemanticStoreError("semantic close command is not the terminal ledger event")
        close_event = matches[0]
        if (
            close_event.get("event_type") != "task_closed"
            or close_event.get("prev_event_sha256") != expected_head_sha256
        ):
            raise SemanticStoreError("semantic close command differs from the published close")
        if len(events) < 2:
            raise SemanticStoreError("semantic close event has no preceding authority")
        before = semantic.projection_domain(semantic.replay_events(events[:-1]))
        after = semantic.projection_domain(semantic.replay_events(events))
        before_facts = before.get("facts")
        after_facts = after.get("facts")
        if (
            not isinstance(before_facts, list)
            or not isinstance(after_facts, list)
            or len(after_facts) != len(before_facts) + 1
            or after_facts[:-1] != before_facts
            or not isinstance(after_facts[-1], str)
            or not after_facts[-1].strip()
        ):
            raise SemanticStoreError(
                "published semantic close does not append exactly one string summary"
            )
        return after_facts[-1]
    except SemanticStoreError:
        raise
    except (h.HarnessError, semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _store_error("invalid published semantic close", exc) from exc


def recover_published_semantic_transition(
    paths: h.HarnessPaths,
    task_id: str,
    result_state: dict[str, Any],
    *,
    event_type: str,
    command_id: str,
    expected_head_sha256: str,
) -> SemanticAppendResult:
    """Repair an already-published exact command under the current Chief lock.

    A successor Chief may complete replaceable projection or derived side
    effects after the original Chief published the immutable event.  This
    function never appends and never changes the event's historical authority;
    it requires the exact terminal command, previous head, type, and result.
    """

    h._require_chief_lock(paths)
    try:
        task_id = h.validate_id(task_id, "task id")
        command_id = h.validate_id(command_id, "semantic command id")
        if not isinstance(result_state, dict):
            raise SemanticStoreError("semantic transition result must be an object")
        result_domain = (
            semantic.projection_domain(result_state)
            if semantic.SEMANTIC_ENVELOPE_KEY in result_state
            else json.loads(
                semantic.canonical_json_bytes(result_state).decode("utf-8")
            )
        )
        if result_domain.get("task_id") != task_id:
            raise SemanticStoreError("semantic transition task identity mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", str(expected_head_sha256)):
            raise SemanticStoreError("semantic expected head SHA-256 is invalid")
        events = _read_ledger(paths, task_id)
        recovered = _transition_retry(
            events,
            command_id=command_id,
            event_type=event_type,
            authority_ref=None,
            expected_head_sha256=expected_head_sha256,
            result_domain=result_domain,
        )
        if recovered is None:
            raise SemanticStoreError(
                "semantic command is not an already-published terminal transition"
            )
    except SemanticStoreError:
        raise
    except (h.HarnessError, semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _store_error("invalid semantic transition recovery", exc) from exc
    projection = repair_semantic_projection(paths, task_id)
    return SemanticAppendResult(
        projection=projection,
        event=recovered.event,
        idempotent_replay=True,
    )


def append_semantic_transition(
    paths: h.HarnessPaths,
    task_id: str,
    result_state: dict[str, Any],
    *,
    event_type: str,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
    expected_head_sha256: str,
) -> SemanticAppendResult:
    """Publish one semantic event before its replaceable task projection.

    The caller must hold AOI's state lock.  ``expected_head_sha256`` is the
    command's base authority and remains the same on retry.  A retry succeeds
    only when that command is still the terminal event and its exact semantics
    match; a reused command id or a stale head fails closed.
    """

    h._require_chief_lock(paths)
    try:
        task_id = h.validate_id(task_id, "task id")
        if not isinstance(result_state, dict):
            raise SemanticStoreError("semantic transition result must be an object")
        result_domain = (
            semantic.projection_domain(result_state)
            if semantic.SEMANTIC_ENVELOPE_KEY in result_state
            else json.loads(semantic.canonical_json_bytes(result_state).decode("utf-8"))
        )
        if result_domain.get("task_id") != task_id:
            raise SemanticStoreError("semantic transition task identity mismatch")
        if (
            not isinstance(expected_head_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_head_sha256)
        ):
            raise SemanticStoreError("semantic expected head SHA-256 is invalid")
        events = _read_ledger(paths, task_id)
        replayed = semantic.replay_events(events)
        retry = _transition_retry(
            events,
            command_id=command_id,
            event_type=event_type,
            authority_ref=authority_ref,
            expected_head_sha256=expected_head_sha256,
            result_domain=result_domain,
        )
        if retry is not None:
            repaired = repair_semantic_projection(paths, task_id)
            return SemanticAppendResult(
                projection=repaired,
                event=retry.event,
                idempotent_replay=True,
            )
        previous = events[-1]
        if previous["event_sha256"] != expected_head_sha256:
            raise SemanticStoreError("semantic expected head does not match current authority")
        # A writer repairs an authenticated missing/behind projection before
        # adding a new semantic head.  This is a derived-state write only.
        stored = _read_projection(paths, task_id)
        if stored is None or semantic.validate_projection(events, stored).status == "behind":
            h.atomic_write_bytes(
                h.task_state_path(paths, task_id), _projection_bytes(replayed)
            )
        proposed = semantic.create_transition_event(
            previous,
            replayed,
            result_domain,
            event_type=event_type,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=authority_ref,
        )
        projected = semantic.projection_for_event(result_domain, proposed)
        _projection_bytes(projected)
    except SemanticStoreError:
        raise
    except (h.HarnessError, semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _store_error("invalid semantic transition request", exc) from exc

    destination = semantic_event_directory(paths, task_id) / semantic.event_filename(
        proposed["sequence"]
    )
    recovered_publication = False
    try:
        h.atomic_create_bytes(
            destination,
            semantic.canonical_json_bytes(proposed, max_bytes=semantic.MAX_EVENT_BYTES),
        )
    except h.HarnessError as exc:
        try:
            published = _read_ledger(paths, task_id)
            retry = _transition_retry(
                published,
                command_id=command_id,
                event_type=event_type,
                authority_ref=authority_ref,
                expected_head_sha256=expected_head_sha256,
                result_domain=result_domain,
            )
        except (SemanticStoreError, semantic.SemanticEventError) as retry_exc:
            raise _store_error("semantic transition publication conflicted", retry_exc) from retry_exc
        if retry is None:
            raise _store_error("cannot publish semantic transition event", exc) from exc
        proposed = retry.event
        recovered_publication = True
    projection = repair_semantic_projection(paths, task_id)
    return SemanticAppendResult(
        projection=projection,
        event=dict(proposed),
        idempotent_replay=recovered_publication,
    )


def initialize_semantic_task(
    paths: h.HarnessPaths,
    state: dict[str, Any],
    *,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    """Publish an idempotent semantic genesis event before its projection.

    An event with the same command id must have exactly the same genesis
    semantics.  A retry never replaces its event file; it only repairs the
    replaceable projection after replay has authenticated the existing chain.
    """

    if not isinstance(state, dict) or not isinstance(state.get("task_id"), str):
        raise SemanticStoreError("semantic initialization state requires a string task_id")
    try:
        task_id = h.validate_id(state["task_id"], "task id")
        proposed = semantic.create_genesis_event(
            state,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=authority_ref,
        )
        # Refuse an event-first commit that could never publish its bounded
        # managed projection. This check happens before creating ledger paths.
        _projection_bytes(semantic.projection_for_event(state, proposed))
    except (h.HarnessError, semantic.SemanticEventError) as exc:
        raise _store_error("invalid semantic initialization request", exc) from exc

    event_directory: Path
    if _event_directory_exists(paths, task_id):
        event_directory = semantic_event_directory(paths, task_id)
        if _event_directory_is_empty(event_directory):
            if h.task_state_path(paths, task_id).exists():
                raise SemanticStoreError(
                    "semantic projection exists but the ledger has no genesis event"
                )
            # Recover an interrupted init that created only the private
            # directory tree. Any temporary or unexpected entry is non-empty
            # and therefore still fails through the strict ledger reader.
        else:
            events = _read_ledger(paths, task_id)
            try:
                existing = semantic.resolve_command_retry(events, proposed)
            except semantic.SemanticEventError as exc:
                raise _store_error("semantic initialization command conflict", exc) from exc
            if existing is None:
                raise SemanticStoreError(
                    "semantic ledger already exists for a different command"
                )
            return repair_semantic_projection(
                paths, task_id, expected_command_id=command_id
            )
    else:
        projection_path = h.task_state_path(paths, task_id)
        try:
            projection_path = h.canonicalize_no_link_traversal(
                projection_path, "semantic projection"
            )
            h.validate_existing_regular_file(
                projection_path, "semantic projection"
            )
        except h.HarnessError as exc:
            raise _store_error(
                "semantic projection path is unsafe before genesis", exc
            ) from exc
        if projection_path.exists():
            raise SemanticStoreError(
                "semantic projection exists without a genesis event"
            )
        event_directory = _create_event_directory(paths, task_id)
    destination = event_directory / semantic.event_filename(1)
    payload = semantic.canonical_json_bytes(proposed, max_bytes=semantic.MAX_EVENT_BYTES)
    try:
        h.atomic_create_bytes(destination, payload)
    except h.HarnessError as exc:
        # A concurrent/crash-retry publication may have won the no-replace
        # create.  Authenticate it before treating this command as idempotent.
        if not _event_directory_exists(paths, task_id):
            raise _store_error("cannot publish semantic genesis event", exc) from exc
        events = _read_ledger(paths, task_id)
        try:
            existing = semantic.resolve_command_retry(events, proposed)
        except semantic.SemanticEventError as retry_exc:
            raise _store_error("semantic initialization command conflict", retry_exc) from retry_exc
        if existing is None:
            raise _store_error("semantic genesis publication conflicted", exc) from exc
    return repair_semantic_projection(paths, task_id, expected_command_id=command_id)
