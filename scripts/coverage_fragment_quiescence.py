#!/usr/bin/env python3
"""Bounded, fail-closed quiescence for raw coverage.py fragments.

The seal is a cooperative-writer lstat-metadata bracket.  It detects observed
set or identity changes but does not claim content-byte identity, hostile
same-user pathname isolation, or permanent writer closure after the bracket.
"""

from __future__ import annotations

import math
import os
import sqlite3
import stat
import time
from hashlib import sha256
from pathlib import Path
from typing import Callable, NamedTuple


MAX_FRAGMENT_FILES = 4096
MAX_FRAGMENT_BYTES = 64 * 1024 * 1024
MAX_FRAGMENT_SET_BYTES = 4 * 1024 * 1024 * 1024
MAX_FRAGMENT_NAME_BYTES = 1024
MAX_FRAGMENT_STABILITY_ATTEMPTS = 8
MAX_COMBINE_ATTEMPTS = 3
FRAGMENT_STABILITY_INTERVAL_SECONDS = 0.25
FRAGMENT_IDENTITY_SEMANTICS = "cooperative_lstat_metadata_v1"
_RESERVED_DESTINATION = ".coverage"
_SQLITE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


class CoveragePathMappingError(RuntimeError):
    """The configured aliases did not preserve the trusted measurement boundary."""


class _FragmentSetChanged(CoveragePathMappingError):
    """A cooperative coverage writer changed the frozen shard set."""


class FragmentIdentity(NamedTuple):
    """The lstat identity that must remain fixed while a shard is trusted."""

    file_type: int
    inode: int
    size: int
    mtime_ns: int


class _SnapshotProblem(NamedTuple):
    """A bounded classification without exposing a raw shard basename."""

    reason: str
    name_sha256: str
    identity: FragmentIdentity


def _fragment_name_bytes(fragment: Path) -> bytes:
    """Return the filesystem spelling without leaking an undecodable basename."""

    try:
        encoded = os.fsencode(fragment.name)
    except (TypeError, UnicodeEncodeError, ValueError):
        raise CoveragePathMappingError(
            "coverage fragment basename cannot be encoded"
        ) from None
    if not encoded or len(encoded) > MAX_FRAGMENT_NAME_BYTES:
        raise CoveragePathMappingError(
            "coverage fragment basename is outside the byte bound"
        )
    return encoded


def _fragment_identity(fragment: Path) -> FragmentIdentity:
    try:
        status = os.lstat(fragment)
    except OSError as exc:
        raise _FragmentSetChanged(
            "coverage fragment disappeared during identity check"
        ) from exc
    return FragmentIdentity(
        stat.S_IFMT(status.st_mode),
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
    )


def _snapshot_fragments(fragment_directory: Path) -> dict[Path, FragmentIdentity]:
    """Capture every directory member without following a coverage fragment."""

    try:
        children: list[Path] = []
        for fragment in fragment_directory.iterdir():
            children.append(fragment)
            if len(children) > MAX_FRAGMENT_FILES:
                raise CoveragePathMappingError(
                    "coverage fragment count is outside the bound "
                    f"(reason=fragment_count_oversize, "
                    f"member_count_at_least={len(children)})"
                )
        children.sort(key=_fragment_name_bytes)
    except CoveragePathMappingError:
        raise
    except OSError as exc:
        raise CoveragePathMappingError(
            "coverage fragment directory cannot be enumerated"
        ) from exc
    snapshot: dict[Path, FragmentIdentity] = {}
    for fragment in children:
        snapshot[fragment] = _fragment_identity(fragment)
    return snapshot


def _snapshot_digest(snapshot: dict[Path, FragmentIdentity]) -> str:
    material = bytearray(b"aoi-coverage-fragment-snapshot-v1\0")
    for path, identity in sorted(
        snapshot.items(), key=lambda item: _fragment_name_bytes(item[0])
    ):
        name = _fragment_name_bytes(path)
        material.extend(len(name).to_bytes(4, "big"))
        material.extend(name)
        for value in identity:
            encoded = str(value).encode("ascii")
            material.extend(len(encoded).to_bytes(2, "big"))
            material.extend(encoded)
    return sha256(material).hexdigest()


def _snapshot_diagnostic(
    snapshot: dict[Path, FragmentIdentity],
    *,
    reason: str,
) -> str:
    total_bytes = sum(max(0, identity.size) for identity in snapshot.values())
    return (
        f"reason={reason}, member_count={len(snapshot)}, "
        f"total_bytes={total_bytes}, "
        f"identity_semantics={FRAGMENT_IDENTITY_SEMANTICS}, "
        f"metadata_snapshot_sha256={_snapshot_digest(snapshot)}"
    )


def _snapshot_problems(
    snapshot: dict[Path, FragmentIdentity],
) -> tuple[_SnapshotProblem, ...]:
    problems: list[_SnapshotProblem] = []
    for fragment, identity in snapshot.items():
        name = _fragment_name_bytes(fragment)
        reason: str | None = None
        if name == os.fsencode(_RESERVED_DESTINATION):
            reason = "reserved_destination_conflict"
        elif name.endswith(tuple(os.fsencode(item) for item in _SQLITE_SIDECAR_SUFFIXES)):
            reason = "sqlite_writer_sidecar"
        elif not name.startswith(b".coverage."):
            reason = "unexpected_name"
        elif identity.file_type != stat.S_IFREG:
            reason = "non_regular_member"
        elif identity.size == 0:
            reason = "incomplete_zero_byte"
        elif identity.size > MAX_FRAGMENT_BYTES:
            reason = "fragment_oversize"
        if reason is not None:
            problems.append(
                _SnapshotProblem(
                    reason,
                    sha256(name).hexdigest(),
                    identity,
                )
            )
    return tuple(problems)


def _has_problem(problems: tuple[_SnapshotProblem, ...], reason: str) -> bool:
    return any(problem.reason == reason for problem in problems)


def _validate_fragment_snapshot(
    snapshot: dict[Path, FragmentIdentity],
) -> tuple[_SnapshotProblem, ...]:
    """Return retryable incompleteness; raise for stable non-writer invalidity."""

    if len(snapshot) > MAX_FRAGMENT_FILES:
        raise CoveragePathMappingError(
            "coverage fragment count is outside the bound "
            f"({_snapshot_diagnostic(snapshot, reason='fragment_count_oversize')})"
        )
    total_bytes = sum(max(0, identity.size) for identity in snapshot.values())
    if total_bytes > MAX_FRAGMENT_SET_BYTES:
        raise CoveragePathMappingError(
            "coverage fragment bytes are outside the aggregate bound "
            f"({_snapshot_diagnostic(snapshot, reason='fragment_set_oversize')})"
        )
    if not snapshot:
        sentinel = FragmentIdentity(stat.S_IFREG, 0, 0, 0)
        return (
            _SnapshotProblem(
                "fragment_set_empty",
                sha256(b"").hexdigest(),
                sentinel,
            ),
        )
    problems = _snapshot_problems(snapshot)
    retryable = {
        "fragment_set_empty",
        "incomplete_zero_byte",
        "sqlite_writer_sidecar",
    }
    stable_invalid = tuple(
        problem for problem in problems if problem.reason not in retryable
    )
    if stable_invalid:
        reason = stable_invalid[0].reason
        raise CoveragePathMappingError(
            "coverage directory contains an unexpected or empty fragment "
            f"({_snapshot_diagnostic(snapshot, reason=reason)})"
        )
    return problems


def _read_stable_fragment_set(
    fragment_directory: Path,
    reader: Callable[[Path], tuple[str, ...]],
    *,
    snapshot: Callable[[Path], dict[Path, FragmentIdentity]] = _snapshot_fragments,
    attempts: int = MAX_FRAGMENT_STABILITY_ATTEMPTS,
    stability_interval: float = FRAGMENT_STABILITY_INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[tuple[Path, ...], dict[Path, tuple[str, ...]], dict[Path, FragmentIdentity]]:
    """Seal a complete raw set or fail after bounded full-set observations."""

    if (
        not isinstance(attempts, int)
        or isinstance(attempts, bool)
        or not 1 <= attempts <= MAX_FRAGMENT_STABILITY_ATTEMPTS
    ):
        raise CoveragePathMappingError(
            "coverage fragment stability attempt bound is invalid"
        )
    if (
        type(stability_interval) not in {int, float}
        or not math.isfinite(stability_interval)
        or stability_interval <= 0
    ):
        raise CoveragePathMappingError("coverage fragment stability interval is invalid")

    start = monotonic()
    if not math.isfinite(start):
        raise CoveragePathMappingError("coverage fragment stability clock is invalid")
    last_time = start
    last_snapshot: dict[Path, FragmentIdentity] = {}
    last_reason = "writer_not_quiescent"
    last_reader_error = False

    def post_interval_snapshot() -> dict[Path, FragmentIdentity]:
        nonlocal last_time
        before_sleep = monotonic()
        if not math.isfinite(before_sleep) or before_sleep < last_time:
            raise CoveragePathMappingError(
                "coverage fragment stability clock moved backwards"
            )
        sleeper(stability_interval)
        after_sleep = monotonic()
        if not math.isfinite(after_sleep) or after_sleep < before_sleep:
            raise CoveragePathMappingError(
                "coverage fragment stability clock moved backwards"
            )
        if after_sleep < before_sleep + stability_interval:
            raise CoveragePathMappingError(
                "coverage fragment stability interval did not elapse"
            )
        last_time = after_sleep
        return snapshot(fragment_directory)

    for _ in range(attempts):
        before = snapshot(fragment_directory)
        last_snapshot = before
        before_problems = _snapshot_problems(before)
        if _has_problem(before_problems, "reserved_destination_conflict"):
            raise CoveragePathMappingError(
                "combined coverage destination already exists "
                f"({_snapshot_diagnostic(before, reason='reserved_destination_conflict')})"
            )
        stable = post_interval_snapshot()
        last_snapshot = stable
        if before != stable:
            last_reason = "writer_not_quiescent"
            continue
        problems = _validate_fragment_snapshot(stable)
        if problems:
            last_reason = problems[0].reason
            continue
        measured_by_fragment: dict[Path, tuple[str, ...]] = {}
        for fragment in stable:
            try:
                measured_by_fragment[fragment] = tuple(reader(fragment))
            except Exception:
                last_reader_error = True
                last_reason = "coverage_data_incomplete_or_invalid"
                break
        else:
            if snapshot(fragment_directory) == stable:
                return tuple(stable), measured_by_fragment, stable
            last_reason = "writer_not_quiescent"
            continue

    diagnostic = _snapshot_diagnostic(last_snapshot, reason=last_reason)
    if last_reader_error and last_reason == "coverage_data_incomplete_or_invalid":
        raise CoveragePathMappingError(
            "coverage fragment is stably unreadable or invalid "
            f"({diagnostic})"
        ) from None
    if last_reason in {
        "fragment_set_empty",
        "incomplete_zero_byte",
        "sqlite_writer_sidecar",
    }:
        raise CoveragePathMappingError(
            "coverage directory contains an unexpected or empty fragment "
            f"({diagnostic})"
        )
    raise CoveragePathMappingError(
        "coverage fragment set did not stabilize within the bounded attempt limit "
        f"({diagnostic})"
    )


def _assert_fragment_snapshot(
    fragment_directory: Path,
    expected: dict[Path, FragmentIdentity],
) -> None:
    actual = _snapshot_fragments(fragment_directory)
    if actual != expected:
        added = len(actual.keys() - expected.keys())
        removed = len(expected.keys() - actual.keys())
        changed = sum(
            actual[path] != expected[path]
            for path in actual.keys() & expected.keys()
        )
        raise _FragmentSetChanged(
            "coverage fragment set or identity changed "
            f"(added={added}, removed={removed}, changed={changed}, "
            f"actual_sha256={_snapshot_digest(actual)})"
        )


def _validate_coverage_fragment_schema(fragment: Path) -> None:
    """Require an existing schema without letting coverage.py initialize the shard."""

    try:
        resolved = fragment.resolve(strict=True)
        with sqlite3.connect(
            f"{resolved.as_uri()}?mode=ro&immutable=1", uri=True, timeout=0
        ) as database:
            database.execute("PRAGMA query_only = ON")
            rows = database.execute("SELECT version FROM coverage_schema").fetchall()
    except (OSError, sqlite3.Error, ValueError):
        raise CoveragePathMappingError(
            "coverage fragment schema is missing or invalid"
        ) from None
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
        raise CoveragePathMappingError(
            "coverage fragment schema is missing or invalid"
        )
