"""Filesystem persistence for semantic-v2 task ledgers.

This module deliberately owns only the small persistence boundary between the
pure :mod:`semantic_events` contract and AOI's existing atomic-file helpers.
The ledger is authoritative; ``state.json`` is a replaceable projection.  It
does not acquire the task/state lock itself: callers that append transitions
must do that at their lifecycle authority boundary.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Iterable

from . import harnesslib as h
from . import semantic_events as semantic


SEMANTIC_DIRECTORY_NAME = "semantic-v2"
SEMANTIC_EVENTS_DIRECTORY_NAME = "events"
MAX_SEMANTIC_EVENT_FILES = min(
    semantic.MAX_LEDGER_EVENTS, h.TREE_IDENTITY_SCAN_MAX_ENTRIES
)


class SemanticStoreError(h.HarnessError):
    """The semantic ledger or its filesystem representation is unsafe."""


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

    return _event_directory_exists(paths, task_id)


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
