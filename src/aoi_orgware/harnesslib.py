#!/usr/bin/env python3
"""Small, dependency-free state library for AOI orgware."""

from __future__ import annotations

import contextlib
import base64
import datetime as dt
import errno
import hmac
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Iterator

if os.name == "nt":
    import msvcrt
else:
    import fcntl

from .config import CONFIG_FILE, ProjectConfig, load_config


SCHEMA_VERSION = 1
TASK_STATUSES = {"active", "blocked", "done", "cancelled"}
TASK_PHASES = {
    "planning",
    "gathering",
    "diagnosing",
    "implementing",
    "waiting_external",
    "verifying",
    "reviewing",
    "closing",
}
CLAIM_STATUSES = {"active", "blocked", "done", "released", "stale"}
RESERVING_CLAIM_STATUSES = {"active", "blocked"}
TERMINAL_CLAIM_STATUSES = {"done", "released", "stale"}
JOB_STATUSES = {"queued", "running", "pass", "fail", "stopped", "unknown"}
ACTIVE_JOB_STATUSES = {"queued", "running", "unknown"}
PACKET_STATUSES = {"ready", "armed", "dispatched", "done", "failed", "cancelled"}
ACTIVE_PACKET_STATUSES = {"ready", "armed", "dispatched"}
VERIFICATION_STATUSES = {"pending", "pass", "fail", "blocked", "skipped"}
ACCOUNTED_VERIFICATION_STATUSES = VERIFICATION_STATUSES - {"pending"}
DELIVERY_MODES = {"pending", "pushed", "local-only", "blocked", "none"}
CHECKPOINT_COMPACT_THRESHOLD_BYTES = 16 * 1024
CHECKPOINT_MAX_BYTES = 32 * 1024
MANAGED_JSON_MAX_BYTES = 16 * 1024 * 1024
COMPACT_CLAIM_HISTORY_THRESHOLD = 16
COMPACT_CLAIM_RECENT_TAIL = 3
COMPACT_VERIFICATION_HISTORY_THRESHOLD = 16
COMPACT_VERIFICATION_RECENT_TAIL = 3
COMPACT_JOB_HISTORY_THRESHOLD = 8
COMPACT_JOB_RECENT_TAIL = 3
COMPACT_PACKET_HISTORY_THRESHOLD = 16
COMPACT_PACKET_RECENT_TAIL = 3
COMPACT_FACT_HISTORY_THRESHOLD = 16
COMPACT_FACT_RECENT_TAIL = 8
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,191}$")
EXTERNAL_LOCK_NAMESPACE = "external"
PLATFORM_MARKER_SCHEMA_VERSION = 1
CHIEF_AUTHORITY_SCHEMA_VERSION = 1
CHIEF_TOKEN_BYTES = 32
CHIEF_DEFAULT_TTL_SECONDS = 60 * 60
CHIEF_MIN_TTL_SECONDS = 60
CHIEF_MAX_TTL_SECONDS = 24 * 60 * 60
CHIEF_CLOCK_SKEW_TOLERANCE_SECONDS = 5
CHIEF_AUDIT_TAIL_MAX = 32
CHIEF_AUTHORITY_STATUSES = {"active", "inactive"}
CHIEF_CREDENTIAL_SCHEMA_VERSION = 1
CHIEF_CREDENTIAL_MAX_BYTES = 8 * 1024
WINDOWS_REPLACE_RETRY_SECONDS = 2.0
TREE_IDENTITY_SCAN_MAX_ENTRIES = 100_000
WINDOWS_RESERVED_BASENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

TASK_STRING_LIST_FIELDS = {
    "blockers",
    "changed_files",
    "claims",
    "decisions",
    "facts",
    "rejected_paths",
    "session_ids",
    "subagent_parent_session_ids",
}
# Fields that accept legacy plain-string entries alongside typed objects.
# Legacy states keep loading byte-identical; new writers append typed entries.
TASK_MIXED_LIST_FIELDS = {"risks"}
RISK_STATUSES = {"open", "retired", "materialized"}
RISK_ID_RE = re.compile(r"r[1-9][0-9]{0,5}")
TASK_OBJECT_LIST_FIELDS = {
    "branch_adoptions",
    "capacity_reviews",
    "coordination_requests",
    "context_provider_benchmarks",
    "context_provider_receipts",
    "cross_lane_sessions",
    "execution_briefs",
    "execution_selections",
    "improvement_requests",
    "integration_baselines",
    "jobs",
    "lane_dependencies",
    "lanes",
    "needs_user_escalations",
    "override_requests",
    "packets",
    "resource_config_events",
    "skill_adoption_events",
    "skill_releases",
    "subagent_incidents",
    "verification",
}


class HarnessError(RuntimeError):
    """Expected user-facing harness failure."""


@dataclass(frozen=True)
class HarnessPaths:
    root: Path
    config: Path
    project: ProjectConfig
    harness: Path
    tasks: Path
    claims: Path
    claims_active: Path
    claims_archive: Path
    legacy_pending: Path
    legacy_decisions: Path
    sessions: Path
    templates: Path
    index: Path
    lock: Path
    platform: Path
    chief_authority: Path


def discover_root(start: Path | None = None) -> Path:
    configured = os.environ.get("AOI_ROOT")
    if start is not None:
        raw_candidate = start
        explicit = True
    elif configured is not None:
        raw_candidate = Path(configured).expanduser()
        explicit = True
    else:
        raw_candidate = Path.cwd()
        explicit = False
    candidate = (
        canonicalize_no_link_traversal(raw_candidate, "explicit AOI root")
        if explicit
        else raw_candidate.resolve()
    )
    if explicit:
        root = candidate
    else:
        search = (candidate, *candidate.parents)
        root = next((item for item in search if (item / CONFIG_FILE).is_file()), None)
        if root is None:
            root = next((item for item in search if (item / ".git").exists()), candidate)
    if root == Path(root.anchor) or root == Path.home().resolve():
        raise HarnessError(f"refusing dangerous AOI project root: {root}")
    if os.name == "nt" and str(root.anchor).startswith("\\\\"):
        raise HarnessError("native Windows AOI does not support UNC/network project roots")
    return root


def paths_for_project(root: Path, project: ProjectConfig) -> HarnessPaths:
    """Construct paths for an already validated project profile."""

    global EXTERNAL_LOCK_NAMESPACE
    root = root.resolve()
    EXTERNAL_LOCK_NAMESPACE = project.external_lock_namespace
    harness = root / project.state_dir
    resolved_harness = canonicalize_no_link_traversal(
        harness, "AOI state directory"
    )
    try:
        resolved_harness.relative_to(root)
    except ValueError as exc:
        raise HarnessError("AOI state directory must remain inside the project root") from exc
    claims = harness / "claims"
    return HarnessPaths(
        root=root,
        config=root / CONFIG_FILE,
        project=project,
        harness=harness,
        tasks=harness / "tasks",
        claims=claims,
        claims_active=claims / "active",
        claims_archive=claims / "archive",
        legacy_pending=claims / "legacy_pending",
        legacy_decisions=claims / "legacy_decisions",
        sessions=harness / "sessions",
        templates=harness / "templates",
        index=harness / "INDEX.md",
        lock=harness / ".state.lock",
        platform=harness / "platform.json",
        chief_authority=harness / "chief-authority.json",
    )


def get_paths(root: Path | None = None) -> HarnessPaths:
    root = discover_root(root)
    config_path = root / CONFIG_FILE
    if config_path.exists():
        canonical_config = canonicalize_no_link_traversal(
            config_path, "AOI configuration"
        )
        if canonical_config != config_path:
            raise HarnessError("AOI configuration path changed during validation")
        validate_existing_regular_file(config_path, "AOI configuration")
    try:
        project = load_config(root, allow_missing=True)
    except ValueError as exc:
        raise HarnessError(str(exc)) from exc
    return paths_for_project(root, project)


def ensure_layout(paths: HarnessPaths) -> None:
    preflight_layout(paths)
    _ensure_platform_domain(paths)
    directories = [
        paths.claims,
        paths.tasks,
        paths.claims_active,
        paths.claims_archive,
        paths.sessions,
        paths.templates,
    ]
    if paths.project.legacy_enabled:
        directories.extend((paths.legacy_pending, paths.legacy_decisions))
    for directory in directories:
        validate_existing_regular_directory(directory, "AOI managed directory")
        directory.mkdir(parents=True, exist_ok=True)
        _chmod_private(directory, 0o700)
    preflight_layout(paths)


def preflight_layout(paths: HarnessPaths) -> None:
    """Validate an existing state tree without creating or changing it."""

    managed_directories = [
        paths.harness,
        paths.claims,
        paths.tasks,
        paths.claims_active,
        paths.claims_archive,
        paths.sessions,
        paths.templates,
    ]
    if paths.project.legacy_enabled:
        managed_directories.extend((paths.legacy_pending, paths.legacy_decisions))
    for directory in managed_directories:
        validate_existing_regular_directory(directory, "AOI managed directory")

    managed_files = [
        paths.platform,
        paths.lock,
        paths.index,
        paths.chief_authority,
        paths.harness / "POLICY.md",
        *(
            paths.templates / name
            for name in (
                "plan.md",
                "packet.md",
                "checkpoint.md",
                "source_receipt.example.json",
            )
        ),
    ]
    for managed_file in managed_files:
        validate_existing_regular_file(managed_file, "AOI managed file")

    if not paths.harness.exists():
        return
    try:
        entries = list(paths.harness.iterdir())
    except OSError as exc:
        raise HarnessError(f"cannot inspect AOI state path {paths.harness}: {exc}") from exc
    if not paths.platform.exists():
        if os.name == "nt" and entries:
            raise HarnessError(
                "untagged pre-v0.1.2 AOI state cannot be opened by native Windows; "
                "run one POSIX/WSL AOI command first or initialize a fresh state tree"
            )
        return
    marker = _read_platform_marker(paths.platform)
    expected = runtime_lock_domain()
    if marker.get("lock_domain") != expected:
        raise HarnessError(
            f"AOI state lock domain is {marker.get('lock_domain')!r}, but this runtime "
            f"requires {expected!r}; simultaneous or alternating WSL/native writers "
            "are unsupported"
        )


def runtime_lock_domain() -> str:
    return "windows-msvcrt-v1" if os.name == "nt" else "posix-flock-v1"


def platform_capabilities() -> dict[str, Any]:
    if os.name == "nt":
        return {
            "lock_domain": runtime_lock_domain(),
            "lock_backend": "msvcrt-byte-range",
            "atomic_visibility": True,
            "file_fsync": True,
            "parent_directory_fsync": False,
            "private_permissions": "windows-acl-unverified",
        }
    return {
        "lock_domain": runtime_lock_domain(),
        "lock_backend": "fcntl-flock",
        "atomic_visibility": True,
        "file_fsync": True,
        "parent_directory_fsync": True,
        "private_permissions": "posix-mode",
    }


def _chmod_private(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(mode)
    except OSError:
        pass


def _path_is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction and is_junction():
        return True
    if os.name == "nt":
        try:
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
        except (FileNotFoundError, OSError):
            return False
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def canonicalize_no_link_traversal(path: Path, label: str) -> Path:
    """Return one canonical path after rejecting real linked components.

    ``Path.resolve()`` also expands benign Windows path aliases such as the
    ``RUNNER~1`` spelling used by GitHub-hosted runners.  Comparing that result
    with the lexical path therefore cannot distinguish an NTFS 8.3 alias from
    a symlink or junction.  Inspect existing components directly, then resolve
    only after the traversal boundary has been validated.
    """

    # Keep raw parent components until after the component walk.  Normalizing
    # first can erase an already-traversed symlink (``link/../target``) or turn
    # a path through a missing directory into a different writable path.
    lexical = path.expanduser()
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        if part == "..":
            raise HarnessError(f"{label} may not contain parent traversal")
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise HarnessError(
                f"cannot inspect {label} path component {current}: {exc}"
            ) from exc
        is_link = stat.S_ISLNK(metadata.st_mode)
        if os.name == "nt":
            attributes = getattr(metadata, "st_file_attributes", 0)
            is_link = is_link or bool(
                attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        if is_link:
            raise HarnessError(f"{label} may not traverse symlinks or junctions")
    try:
        return current.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise HarnessError(f"cannot resolve {label} path {lexical}: {exc}") from exc


def validate_existing_regular_directory(path: Path, label: str) -> None:
    """Reject linked, junction-backed, or non-directory managed paths."""

    if _path_is_link_like(path):
        raise HarnessError(f"{label} must not be a symlink or junction: {path}")
    if path.exists() and not path.is_dir():
        raise HarnessError(f"{label} must be a regular directory: {path}")


def validate_existing_regular_file(path: Path, label: str) -> None:
    """Reject linked, junction-backed, or non-file managed paths."""

    if _path_is_link_like(path):
        raise HarnessError(f"{label} must be a regular non-linked file: {path}")
    if path.exists():
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise HarnessError(f"cannot inspect {label} {path}: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise HarnessError(
                f"{label} must be one private regular non-linked file: {path}"
            )


def _read_regular_file_snapshot(
    path: Path, label: str, *, max_bytes: int
) -> tuple[tuple[int, int], bytes]:
    """Read a bounded regular file while pinning its filesystem identity."""

    path = canonicalize_no_link_traversal(path, label)
    validate_existing_regular_file(path, label)
    try:
        before = path.lstat()
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if _lock_identity(before) != _lock_identity(opened):
                raise HarnessError(f"{label} changed while being opened: {path}")
            payload = handle.read(max_bytes + 1)
        after = path.lstat()
    except OSError as exc:
        raise HarnessError(f"cannot read {label} {path}: {exc}") from exc
    if _lock_identity(after) != _lock_identity(before):
        raise HarnessError(f"{label} changed while being read: {path}")
    if len(payload) > max_bytes:
        raise HarnessError(f"{label} exceeds {max_bytes} bytes: {path}")
    return _lock_identity(before), payload


def _platform_marker_payload() -> dict[str, Any]:
    capabilities = platform_capabilities()
    return {
        "schema_version": PLATFORM_MARKER_SCHEMA_VERSION,
        "lock_domain": capabilities["lock_domain"],
        "lock_backend": capabilities["lock_backend"],
        "created_at": now_iso(),
    }


def _read_platform_marker(path: Path) -> dict[str, Any]:
    if _path_is_link_like(path) or not path.is_file():
        raise HarnessError(f"AOI platform marker must be a regular non-linked file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError(f"invalid AOI platform marker {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise HarnessError(f"AOI platform marker must contain an object: {path}")
    marker_version = payload.get("schema_version")
    if (
        not isinstance(marker_version, int)
        or isinstance(marker_version, bool)
        or marker_version != PLATFORM_MARKER_SCHEMA_VERSION
    ):
        raise HarnessError(f"unsupported AOI platform marker schema: {path}")
    domain = payload.get("lock_domain")
    if domain not in {"posix-flock-v1", "windows-msvcrt-v1"}:
        raise HarnessError(f"invalid AOI lock domain in {path}: {domain!r}")
    return payload


def _create_platform_marker(path: Path) -> bool:
    payload = (
        json.dumps(_platform_marker_payload(), indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _chmod_private(path, 0o600)
        fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        raise
    return True


def _platform_marker_partial_prefix(payload: bytes) -> bool:
    """Recognize only a byte prefix emitted by this platform-marker writer."""

    marker = "__AOI_CREATED_AT__"
    template = _platform_marker_payload()
    template["created_at"] = marker
    rendered = (
        json.dumps(template, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    before, after = rendered.split(marker.encode("ascii"), 1)
    if len(payload) <= len(before):
        return before.startswith(payload)
    if not payload.startswith(before):
        return False
    remainder = payload[len(before) :]
    if b'"' not in remainder:
        return bool(
            len(remainder) <= 64
            and re.fullmatch(rb"[0-9T:+.\-Z]*", remainder) is not None
        )
    timestamp, suffix_tail = remainder.split(b'"', 1)
    try:
        timestamp_text = timestamp.decode("ascii")
        normalized = (
            timestamp_text[:-1] + "+00:00"
            if timestamp_text.endswith("Z")
            else timestamp_text
        )
        parsed = dt.datetime.fromisoformat(normalized)
    except (UnicodeDecodeError, ValueError):
        return False
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return False
    observed_suffix = b'"' + suffix_tail
    return len(observed_suffix) < len(after) and after.startswith(observed_suffix)


def _torn_platform_marker_snapshot(
    path: Path,
) -> tuple[tuple[int, int], bytes] | None:
    """Return a provable current-writer prefix; reject valid future schemas."""

    identity, payload = _read_regular_file_snapshot(
        path, "AOI platform marker", max_bytes=4096
    )
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        if not _platform_marker_partial_prefix(payload):
            raise HarnessError(
                f"invalid AOI platform marker is not a recoverable current-schema prefix: {path}"
            )
        return identity, payload
    if not isinstance(decoded, dict):
        raise HarnessError(f"AOI platform marker must contain an object: {path}")
    # Preserve unsupported/future schemas and wrong lock domains. Only malformed
    # byte prefixes from this exact writer are eligible for in-place recovery.
    _read_platform_marker(path)
    return None


def _rewrite_torn_platform_marker(
    path: Path, snapshot: tuple[tuple[int, int], bytes]
) -> None:
    """Rewrite the pinned torn inode without unlinking a concurrent replacement."""

    expected_identity, expected_payload = snapshot
    path = canonicalize_no_link_traversal(path, "AOI platform marker")
    validate_existing_regular_file(path, "AOI platform marker")
    payload = (
        json.dumps(_platform_marker_payload(), indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        before = path.lstat()
        with path.open("r+b") as handle:
            opened = os.fstat(handle.fileno())
            if (
                _lock_identity(before) != expected_identity
                or _lock_identity(opened) != expected_identity
            ):
                raise HarnessError(
                    "AOI platform marker changed before interrupted-init recovery"
                )
            current_payload = handle.read(4097)
            if current_payload != expected_payload:
                raise HarnessError(
                    "AOI platform marker bytes changed before interrupted-init recovery"
                )
            handle.seek(0)
            handle.truncate(0)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        after = path.lstat()
    except OSError as exc:
        raise HarnessError(f"cannot recover AOI platform marker {path}: {exc}") from exc
    if _lock_identity(after) != expected_identity:
        raise HarnessError(
            "AOI platform marker path changed during interrupted-init recovery"
        )
    fsync_directory(path.parent)


def _ensure_platform_domain(paths: HarnessPaths) -> None:
    existed = paths.harness.exists()
    if existed and (_path_is_link_like(paths.harness) or not paths.harness.is_dir()):
        raise HarnessError(f"AOI state path must be a regular directory: {paths.harness}")
    legacy_nonempty = existed and any(paths.harness.iterdir())
    paths.harness.mkdir(parents=True, exist_ok=True)
    _chmod_private(paths.harness, 0o700)

    if not paths.platform.exists():
        if os.name == "nt" and legacy_nonempty:
            raise HarnessError(
                "untagged pre-v0.1.2 AOI state cannot be opened by native Windows; "
                "run one POSIX/WSL AOI command first or initialize a fresh state tree"
            )
        _create_platform_marker(paths.platform)

    marker = _read_platform_marker(paths.platform)
    expected = runtime_lock_domain()
    if marker.get("lock_domain") != expected:
        raise HarnessError(
            f"AOI state lock domain is {marker.get('lock_domain')!r}, but this runtime "
            f"requires {expected!r}; simultaneous or alternating WSL/native writers "
            "are unsupported"
        )


_STATE_LOCK_LOCAL = threading.local()


def _held_state_locks() -> dict[str, dict[str, int]]:
    held = getattr(_STATE_LOCK_LOCAL, "held", None)
    if held is None:
        held = {}
        _STATE_LOCK_LOCAL.held = held
    return held


def _lock_identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _validate_state_lock_metadata(
    metadata: os.stat_result, path: Path, *, require_private_mode: bool
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise HarnessError(
            f"AOI state lock must be one private regular non-linked file: {path}"
        )
    if (
        require_private_mode
        and os.name != "nt"
        and stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise HarnessError(
            f"AOI state lock permissions are not private (expected 0600): {path}"
        )


def _validate_held_state_lock(paths: HarnessPaths, entry: dict[str, int]) -> None:
    if entry.get("pid") != os.getpid():
        raise HarnessError(
            "AOI state lock context was inherited across a process boundary; "
            "forked children must not reenter the parent lock"
        )
    path = canonicalize_no_link_traversal(paths.lock, "AOI state lock")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HarnessError(f"cannot inspect held AOI state lock {path}: {exc}") from exc
    _validate_state_lock_metadata(metadata, path, require_private_mode=True)
    if _lock_identity(metadata) != (entry["st_dev"], entry["st_ino"]):
        raise HarnessError("AOI state lock path changed while the lock was held")


@contextlib.contextmanager
def state_lock(
    paths: HarnessPaths,
    *,
    create_layout: bool = True,
    bootstrap_empty_lock: bool = False,
) -> Iterator[None]:
    """Hold one project state lock, with exact-path same-thread reentrancy.

    Central Chief fencing wraps a complete command while existing handlers keep
    their narrower ``state_lock`` scopes.  Only a nested acquisition by the same
    thread for the exact canonical lock path is reentrant; other threads,
    processes, and project paths still acquire the platform lock normally.
    """

    if create_layout and bootstrap_empty_lock:
        raise HarnessError("bootstrap_empty_lock requires an existing validated layout")
    lock_path = canonicalize_no_link_traversal(paths.lock, "AOI state lock")
    key = os.path.normcase(str(lock_path))
    held = _held_state_locks()
    entry = held.get(key)
    if entry is not None:
        _validate_held_state_lock(paths, entry)
        if create_layout:
            ensure_layout(paths)
        else:
            preflight_layout(paths)
        _validate_held_state_lock(paths, entry)
        entry["depth"] += 1
        try:
            yield
        finally:
            entry["depth"] -= 1
        return

    if create_layout:
        ensure_layout(paths)
        if not paths.lock.exists():
            try:
                atomic_create_bytes(paths.lock, b"\0")
            except HarnessError:
                # Atomic publication can report a post-publication durability
                # failure. Continue only if the exact destination now exists;
                # the opened-file checks below still reject every other result.
                if not paths.lock.exists():
                    raise
    else:
        preflight_layout(paths)
        if not paths.lock.is_file():
            raise HarnessError(
                "AOI state lock is missing; initialize or repair Chief authority first"
            )
    current_lock_path = canonicalize_no_link_traversal(paths.lock, "AOI state lock")
    if current_lock_path != lock_path:
        raise HarnessError("AOI state lock path changed during layout validation")
    mode = "r+b" if create_layout or bootstrap_empty_lock or os.name == "nt" else "rb"
    with lock_path.open(mode) as handle:
        before = lock_path.lstat()
        opened = os.fstat(handle.fileno())
        _validate_state_lock_metadata(
            before,
            lock_path,
            require_private_mode=not (create_layout or bootstrap_empty_lock),
        )
        _validate_state_lock_metadata(
            opened,
            lock_path,
            require_private_mode=not (create_layout or bootstrap_empty_lock),
        )
        if _lock_identity(before) != _lock_identity(opened):
            raise HarnessError("AOI state lock changed while being opened")
        if create_layout or bootstrap_empty_lock:
            _chmod_private(lock_path, 0o600)
            before = lock_path.lstat()
            opened = os.fstat(handle.fileno())
            _validate_state_lock_metadata(before, lock_path, require_private_mode=True)
            _validate_state_lock_metadata(opened, lock_path, require_private_mode=True)
            if _lock_identity(before) != _lock_identity(opened):
                raise HarnessError("AOI state lock changed while permissions were set")
        initialized_empty_lock = False
        lock_size = int(opened.st_size)
        if lock_size == 0 and bootstrap_empty_lock:
            handle.seek(0)
            handle.write(b"\0")
            handle.truncate(1)
            handle.flush()
            os.fsync(handle.fileno())
            initialized_empty_lock = True
        elif lock_size != 1:
            raise HarnessError(
                "AOI state lock payload is invalid; expected one NUL sentinel byte"
            )
        acquired = False
        _acquire_state_lock(handle)
        acquired = True
        acquisition_pid = os.getpid()
        try:
            current = lock_path.lstat()
            locked = os.fstat(handle.fileno())
            _validate_state_lock_metadata(current, lock_path, require_private_mode=True)
            _validate_state_lock_metadata(locked, lock_path, require_private_mode=True)
            identity = _lock_identity(locked)
            if _lock_identity(current) != identity:
                raise HarnessError("AOI state lock path changed during lock acquisition")
            if canonicalize_no_link_traversal(lock_path, "AOI state lock") != lock_path:
                raise HarnessError("AOI state lock path changed during lock acquisition")
            handle.seek(0)
            if handle.read(2) != b"\0":
                raise HarnessError("AOI state lock payload changed during lock acquisition")
            held[key] = {
                "depth": 1,
                "st_dev": identity[0],
                "st_ino": identity[1],
                "pid": acquisition_pid,
            }
            try:
                yield
            finally:
                held.pop(key, None)
        except BaseException:
            if (
                bootstrap_empty_lock
                and initialized_empty_lock
                and os.getpid() == acquisition_pid
            ):
                handle.seek(0)
                handle.truncate(0)
                handle.flush()
                os.fsync(handle.fileno())
            raise
        finally:
            # A forked child inherits both this Python frame and the same flock
            # open-file description.  Calling LOCK_UN from the child would
            # silently release the parent's lock.  Closing the child's copied
            # descriptor is safe; only the acquiring process may unlock it.
            if acquired and os.getpid() == acquisition_pid:
                _release_state_lock(handle)


def _acquire_state_lock(handle: Any) -> None:
    if os.name != "nt":
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return

    # msvcrt locks a byte range rather than the whole file. Keep one durable
    # byte at offset zero and retry the non-blocking operation so Windows has
    # the same wait-until-exclusive behavior as POSIX flock.
    handle.seek(0)
    while True:
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise HarnessError(f"could not acquire AOI state lock: {exc}") from exc
            time.sleep(0.05)


def _release_state_lock(handle: Any) -> None:
    if os.name != "nt":
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError as exc:
        raise HarnessError(f"could not release AOI state lock: {exc}") from exc


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="microseconds")


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    raw = value.strip()
    if raw.lower() in {"n/a", "none", "unknown", "-"}:
        return None
    if raw.endswith(" CST"):
        raw = raw[:-4]
        try:
            parsed = dt.datetime.strptime(raw, "%Y-%m-%d %H:%M")
            return parsed.replace(tzinfo=dt.timezone(dt.timedelta(hours=8)))
        except ValueError:
            try:
                parsed = dt.datetime.strptime(raw, "%Y-%m-%d")
                return parsed.replace(tzinfo=dt.timezone(dt.timedelta(hours=8)))
            except ValueError:
                return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.datetime.now().astimezone().tzinfo)
    return parsed


def is_expired(value: str | None) -> bool:
    parsed = parse_time(value)
    return parsed is not None and parsed < dt.datetime.now().astimezone()


def chief_utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _chief_now(value: dt.datetime | None = None) -> dt.datetime:
    current = chief_utc_now() if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        raise HarnessError("Chief authority time must be timezone-aware")
    return current.astimezone(dt.timezone.utc)


def _chief_not_before(
    current: dt.datetime, reference: dt.datetime, *, label: str
) -> dt.datetime:
    """Clamp sub-second wall-clock jitter without accepting real rollback."""

    if current >= reference:
        return current
    if reference - current > dt.timedelta(
        seconds=CHIEF_CLOCK_SKEW_TOLERANCE_SECONDS
    ):
        delta = (reference - current).total_seconds()
        raise HarnessError(
            f"system clock precedes the {label} by {delta:.6f}s "
            f"(tolerance {CHIEF_CLOCK_SKEW_TOLERANCE_SECONDS}s)"
        )
    return reference


def _chief_iso(value: dt.datetime) -> str:
    return _chief_now(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _chief_exact_int(value: Any, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def validate_chief_ttl(value: int) -> int:
    if (
        not _chief_exact_int(value, CHIEF_MIN_TTL_SECONDS)
        or value > CHIEF_MAX_TTL_SECONDS
    ):
        raise HarnessError(
            "Chief lease TTL must be an integer between "
            f"{CHIEF_MIN_TTL_SECONDS} and {CHIEF_MAX_TTL_SECONDS} seconds"
        )
    return value


def _validate_chief_session_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise HarnessError(
            "Chief session id must be 1-512 trimmed characters with no control characters"
        )
    return value


def _validate_chief_reason(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise HarnessError(
            f"{label} must be 1-2048 trimmed characters with no control characters"
        )
    return value


def new_chief_token() -> str:
    return secrets.token_urlsafe(CHIEF_TOKEN_BYTES)


def chief_token_sha256(token: str) -> str:
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise HarnessError("Chief lease credential is missing or malformed")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _chief_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise HarnessError(f"Chief authority {label} must be an ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HarnessError(
            f"Chief authority {label} must be timezone-aware ISO-8601"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HarnessError(f"Chief authority {label} must be timezone-aware ISO-8601")
    return parsed.astimezone(dt.timezone.utc)


_CHIEF_RECORD_FIELDS = {
    "schema_version",
    "epoch",
    "status",
    "session_id",
    "token_sha256",
    "issued_at",
    "renewed_at",
    "expires_at",
    "renewal_count",
    "transition_seq",
    "omitted_transition_count",
    "audit_tail",
    "updated_at",
}
_CHIEF_EVENT_FIELDS = {
    "seq",
    "action",
    "at",
    "old_epoch",
    "new_epoch",
    "session_id",
    "previous_session_id",
    "reason",
    "forced_live",
}
_CHIEF_EVENT_ACTIONS = {"acquire", "renew", "release", "takeover"}


def validate_chief_authority_record(
    paths: HarnessPaths, payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _CHIEF_RECORD_FIELDS:
        raise HarnessError("Chief authority record has an unsupported field set")
    if not _chief_exact_int(payload.get("schema_version"), 1) or payload.get(
        "schema_version"
    ) != CHIEF_AUTHORITY_SCHEMA_VERSION:
        raise HarnessError("unsupported Chief authority schema version")
    epoch = payload.get("epoch")
    if not _chief_exact_int(epoch, 1):
        raise HarnessError("Chief authority epoch must be a positive integer")
    status = payload.get("status")
    if not isinstance(status, str) or status not in CHIEF_AUTHORITY_STATUSES:
        raise HarnessError("Chief authority status is invalid")
    renewal_count = payload.get("renewal_count")
    transition_seq = payload.get("transition_seq")
    omitted_count = payload.get("omitted_transition_count")
    if not _chief_exact_int(renewal_count) or not _chief_exact_int(transition_seq, 1):
        raise HarnessError("Chief authority counters are invalid")
    if not _chief_exact_int(omitted_count):
        raise HarnessError("Chief authority omitted transition count is invalid")
    audit_tail = payload.get("audit_tail")
    if (
        not isinstance(audit_tail, list)
        or not audit_tail
        or len(audit_tail) > CHIEF_AUDIT_TAIL_MAX
        or transition_seq != omitted_count + len(audit_tail)
        or epoch > transition_seq
    ):
        raise HarnessError("Chief authority audit tail is invalid")
    previous_time: dt.datetime | None = None
    previous_event: dict[str, Any] | None = None
    for offset, event in enumerate(audit_tail, start=omitted_count + 1):
        if not isinstance(event, dict) or set(event) != _CHIEF_EVENT_FIELDS:
            raise HarnessError("Chief authority audit event has an invalid field set")
        action = event.get("action")
        if (
            not _chief_exact_int(event.get("seq"), 1)
            or event.get("seq") != offset
            or not isinstance(action, str)
            or action not in _CHIEF_EVENT_ACTIONS
        ):
            raise HarnessError("Chief authority audit event sequence/action is invalid")
        event_time = _chief_time(event.get("at"), "audit event time")
        if previous_time is not None and event_time < previous_time:
            raise HarnessError("Chief authority audit event time moved backwards")
        previous_time = event_time
        old_epoch = event.get("old_epoch")
        new_epoch = event.get("new_epoch")
        if not _chief_exact_int(old_epoch) or not _chief_exact_int(new_epoch, 1):
            raise HarnessError("Chief authority audit event epoch is invalid")
        action = event["action"]
        if action in {"acquire", "takeover"}:
            if new_epoch != old_epoch + 1:
                raise HarnessError("Chief acquire/takeover must increment the epoch")
        elif new_epoch != old_epoch:
            raise HarnessError("Chief renew/release must preserve the epoch")
        if omitted_count == 0 and offset == 1 and (
            action != "acquire" or old_epoch != 0 or new_epoch != 1
        ):
            raise HarnessError(
                "complete Chief authority history must begin with acquire epoch 0 -> 1"
            )
        session_id = _validate_chief_session_id(event.get("session_id"))
        previous_session = event.get("previous_session_id")
        if previous_session:
            _validate_chief_session_id(previous_session)
        elif previous_session != "":
            raise HarnessError("Chief authority previous session id is invalid")
        _validate_chief_reason(event.get("reason"), "Chief authority audit reason")
        if not isinstance(event.get("forced_live"), bool):
            raise HarnessError("Chief authority forced-live marker is invalid")
        if action != "takeover" and event["forced_live"]:
            raise HarnessError("only a Chief takeover may carry forced_live=true")
        if action == "acquire" and previous_session != "":
            raise HarnessError("Chief acquire audit event has a previous holder")
        if action in {"renew", "release"} and previous_session != session_id:
            raise HarnessError("Chief renew/release audit holder chain is invalid")
        if action == "takeover" and previous_session == "":
            raise HarnessError("Chief takeover audit event lacks the previous holder")
        if previous_event is not None:
            if old_epoch != previous_event["new_epoch"]:
                raise HarnessError("Chief authority audit epoch chain is discontinuous")
            if previous_event["action"] == "release":
                if action != "acquire":
                    raise HarnessError("inactive Chief authority must next be acquired")
            elif action == "acquire":
                raise HarnessError("active Chief authority cannot be acquired again")
            elif previous_session != previous_event["session_id"]:
                raise HarnessError("Chief authority audit session chain is discontinuous")
        previous_event = event
    last_event = audit_tail[-1]
    if last_event["new_epoch"] != epoch or payload.get("updated_at") != last_event["at"]:
        raise HarnessError("Chief authority record differs from its audit tail")
    updated_at = _chief_time(payload.get("updated_at"), "updated_at")
    if previous_time != updated_at:
        raise HarnessError("Chief authority updated_at is not the latest audit time")
    if status == "active":
        session_id = _validate_chief_session_id(payload.get("session_id"))
        if session_id != last_event["session_id"]:
            raise HarnessError("Chief authority holder differs from its latest audit event")
        token_digest = payload.get("token_sha256")
        if not isinstance(token_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", token_digest):
            raise HarnessError("Chief authority token digest is invalid")
        issued_at = _chief_time(payload.get("issued_at"), "issued_at")
        renewed_at = _chief_time(payload.get("renewed_at"), "renewed_at")
        expires_at = _chief_time(payload.get("expires_at"), "expires_at")
        if issued_at > renewed_at or renewed_at >= expires_at:
            raise HarnessError("Chief authority lease timestamps are inconsistent")
        lease_ttl_seconds = (expires_at - renewed_at).total_seconds()
        if not (
            lease_ttl_seconds.is_integer()
            and CHIEF_MIN_TTL_SECONDS
            <= lease_ttl_seconds
            <= CHIEF_MAX_TTL_SECONDS
        ):
            raise HarnessError(
                "Chief authority lease duration is outside the supported TTL bounds"
            )
        if renewed_at != updated_at:
            raise HarnessError("active Chief authority renewed_at differs from updated_at")
        if last_event["action"] not in {"acquire", "renew", "takeover"}:
            raise HarnessError("active Chief authority has a terminal audit action")
        origin_index = next(
            (
                index
                for index in range(len(audit_tail) - 1, -1, -1)
                if audit_tail[index]["action"] in {"acquire", "takeover"}
                and audit_tail[index]["new_epoch"] == epoch
            ),
            None,
        )
        visible_renewals = sum(
            event["action"] == "renew" and event["new_epoch"] == epoch
            for event in audit_tail[
                origin_index + 1 if origin_index is not None else 0:
            ]
        )
        if origin_index is not None:
            origin_time = _chief_time(
                audit_tail[origin_index]["at"], "current epoch origin time"
            )
            if issued_at != origin_time:
                raise HarnessError(
                    "Chief authority issued_at differs from its current epoch origin"
                )
            if renewal_count != visible_renewals:
                raise HarnessError(
                    "Chief authority renewal count differs from its visible epoch history"
                )
        elif renewal_count < visible_renewals:
            raise HarnessError(
                "Chief authority renewal count is below its visible epoch history"
            )
    else:
        if any(
            payload.get(field) != ""
            for field in ("session_id", "token_sha256", "issued_at", "renewed_at", "expires_at")
        ) or renewal_count != 0:
            raise HarnessError("inactive Chief authority retains live lease material")
        if last_event["action"] != "release":
            raise HarnessError("inactive Chief authority lacks a release audit action")
    return payload


def load_chief_authority(
    paths: HarnessPaths, *, allow_missing: bool = False
) -> dict[str, Any] | None:
    if not paths.chief_authority.exists():
        if allow_missing:
            return None
        raise HarnessError(
            "Chief authority is not initialized; run `aoi chief-acquire --session-id <id>`"
        )
    payload = load_json(paths.chief_authority)
    return validate_chief_authority_record(paths, payload)


def _chief_lock_is_held(paths: HarnessPaths) -> bool:
    lock_path = canonicalize_no_link_traversal(paths.lock, "AOI state lock")
    entry = _held_state_locks().get(os.path.normcase(str(lock_path)))
    if entry is None:
        return False
    _validate_held_state_lock(paths, entry)
    return True


def _require_chief_lock(paths: HarnessPaths) -> None:
    if not _chief_lock_is_held(paths):
        raise HarnessError("Chief authority transition requires the project state lock")


def _append_chief_event(
    previous: dict[str, Any] | None,
    *,
    action: str,
    at: str,
    old_epoch: int,
    new_epoch: int,
    session_id: str,
    previous_session_id: str,
    reason: str,
    forced_live: bool,
) -> tuple[int, int, list[dict[str, Any]]]:
    transition_seq = int(previous.get("transition_seq", 0) if previous else 0) + 1
    omitted = int(previous.get("omitted_transition_count", 0) if previous else 0)
    tail = list(previous.get("audit_tail", []) if previous else [])
    tail.append(
        {
            "seq": transition_seq,
            "action": action,
            "at": at,
            "old_epoch": old_epoch,
            "new_epoch": new_epoch,
            "session_id": session_id,
            "previous_session_id": previous_session_id,
            "reason": reason.strip(),
            "forced_live": forced_live,
        }
    )
    if len(tail) > CHIEF_AUDIT_TAIL_MAX:
        removed = len(tail) - CHIEF_AUDIT_TAIL_MAX
        tail = tail[removed:]
        omitted += removed
    return transition_seq, omitted, tail


def _write_chief_authority(paths: HarnessPaths, record: dict[str, Any]) -> None:
    _require_chief_lock(paths)
    validate_chief_authority_record(paths, record)
    atomic_write_json(paths.chief_authority, record)


def _chief_authority_definitely_not_published(
    paths: HarnessPaths, record: dict[str, Any]
) -> bool:
    """Return true only when the canonical authority is provably not ``record``.

    A post-replace canonicalization or directory-fsync failure is ambiguous: the
    new authority may already be live.  Its matching credential must survive so
    the published lease cannot be stranded without a usable secret.
    """

    try:
        current = load_chief_authority(paths, allow_missing=True)
    except (HarnessError, OSError):
        return False
    return current != record


def _chief_summary_from_record(
    record: dict[str, Any] | None, *, now: dt.datetime | None = None
) -> dict[str, Any]:
    current = _chief_now(now)
    if record is None:
        return {
            "status": "uninitialized",
            "epoch": 0,
            "session_id": "",
            "issued_at": "",
            "renewed_at": "",
            "expires_at": "",
            "expired": False,
            "renewal_count": 0,
            "transition_seq": 0,
            "omitted_transition_count": 0,
            "latest_action": "",
        }
    expires = _chief_time(record["expires_at"], "expires_at") if record["status"] == "active" else None
    return {
        "status": record["status"],
        "epoch": record["epoch"],
        "session_id": record["session_id"],
        "issued_at": record["issued_at"],
        "renewed_at": record["renewed_at"],
        "expires_at": record["expires_at"],
        "expired": bool(expires is not None and expires <= current),
        "renewal_count": record["renewal_count"],
        "transition_seq": record["transition_seq"],
        "omitted_transition_count": record["omitted_transition_count"],
        "latest_action": record["audit_tail"][-1]["action"],
    }


def chief_authority_summary(
    paths: HarnessPaths, *, now: dt.datetime | None = None
) -> dict[str, Any]:
    return _chief_summary_from_record(
        load_chief_authority(paths, allow_missing=True), now=now
    )


def required_layout_entries(
    paths: HarnessPaths, *, include_lock: bool = True
) -> tuple[Path, ...]:
    directories = [
        paths.harness,
        paths.claims,
        paths.tasks,
        paths.claims_active,
        paths.claims_archive,
        paths.sessions,
        paths.templates,
    ]
    if paths.project.legacy_enabled:
        directories.extend((paths.legacy_pending, paths.legacy_decisions))
    files = [
        paths.platform,
        paths.index,
        paths.harness / "POLICY.md",
        *(paths.templates / name for name in (
            "plan.md",
            "packet.md",
            "checkpoint.md",
            "source_receipt.example.json",
        )),
    ]
    if include_lock:
        files.append(paths.lock)
    return tuple((*directories, *files))


def require_complete_layout(paths: HarnessPaths, *, include_lock: bool = True) -> None:
    preflight_layout(paths)
    missing = [
        str(path)
        for path in required_layout_entries(paths, include_lock=include_lock)
        if not path.exists()
    ]
    if missing:
        raise HarnessError("AOI layout is incomplete; missing: " + ", ".join(missing))


def _validate_interrupted_initialization_prefix(
    paths: HarnessPaths, *, initialized_lock: bool
) -> tuple[tuple[int, int], bytes] | None:
    """Validate the exact pre-lock init prefix and return a pinned torn marker."""

    validate_existing_regular_file(paths.config, "AOI configuration")
    if not paths.config.is_file():
        raise HarnessError("interrupted initialization recovery requires aoi.toml")
    if paths.chief_authority.exists():
        raise HarnessError("interrupted initialization recovery found Chief authority")

    allowed_directories = {
        paths.harness,
        paths.claims,
        paths.tasks,
        paths.claims_active,
        paths.claims_archive,
        paths.sessions,
        paths.templates,
    }
    if paths.project.legacy_enabled:
        allowed_directories.update((paths.legacy_pending, paths.legacy_decisions))
    allowed_files = {paths.platform, paths.lock}

    if paths.harness.exists():
        validate_existing_regular_directory(paths.harness, "AOI state directory")
        pending = [paths.harness]
        while pending:
            directory = pending.pop()
            try:
                entries = list(directory.iterdir())
            except OSError as exc:
                raise HarnessError(
                    f"cannot inspect interrupted AOI initialization prefix {directory}: {exc}"
                ) from exc
            for entry in entries:
                if _path_is_link_like(entry):
                    raise HarnessError(
                        f"interrupted initialization prefix contains a linked entry: {entry}"
                    )
                try:
                    metadata = entry.lstat()
                except OSError as exc:
                    raise HarnessError(
                        f"cannot inspect interrupted AOI initialization entry {entry}: {exc}"
                    ) from exc
                if stat.S_ISDIR(metadata.st_mode):
                    if entry not in allowed_directories:
                        raise HarnessError(
                            f"interrupted initialization prefix contains an unknown directory: {entry}"
                        )
                    pending.append(entry)
                    continue
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or entry not in allowed_files
                ):
                    raise HarnessError(
                        f"interrupted initialization prefix contains material or unknown state: {entry}"
                    )

    if paths.lock.exists():
        expected_lock_payload = b"\0" if initialized_lock else b""
        if initialized_lock and _chief_lock_is_held(paths):
            # Windows byte-range locking prevents a second handle from reading
            # the locked byte. state_lock already pinned the inode and exact NUL
            # payload; repeat the path/size checks through the held entry.
            metadata = paths.lock.lstat()
            if metadata.st_size != len(expected_lock_payload):
                raise HarnessError(
                    "interrupted initialization recovery found an unexpected state lock payload"
                )
        else:
            identity, lock_payload = _read_regular_file_snapshot(
                paths.lock, "AOI state lock", max_bytes=2
            )
            metadata = paths.lock.lstat()
            if _lock_identity(metadata) != identity:
                raise HarnessError(
                    "interrupted initialization state lock changed during validation"
                )
            _validate_state_lock_metadata(
                metadata, paths.lock, require_private_mode=initialized_lock
            )
            if lock_payload != expected_lock_payload:
                raise HarnessError(
                    "interrupted initialization recovery found an unexpected state lock payload"
                )
    elif initialized_lock:
        raise HarnessError("interrupted initialization recovery lost its state lock")

    torn_platform: tuple[tuple[int, int], bytes] | None = None
    if paths.platform.exists():
        torn_platform = _torn_platform_marker_snapshot(paths.platform)
        if torn_platform is not None:
            if initialized_lock:
                raise HarnessError(
                    "initialized interrupted-init prefix retains a torn platform marker"
                )
        else:
            marker = _read_platform_marker(paths.platform)
            if marker.get("lock_domain") != runtime_lock_domain():
                raise HarnessError(
                    "interrupted initialization prefix belongs to another lock domain"
                )
    elif initialized_lock:
        raise HarnessError("interrupted initialization recovery lost its platform marker")
    return torn_platform


def _repair_interrupted_initialization_prefix(paths: HarnessPaths) -> None:
    """Repair only the structural prefix that first ``aoi init`` may leave.

    Before the first state lock is initialized, ``aoi init`` can only have
    created the state directory, platform marker, structural directories, and
    an empty lock.  Any authority, lifecycle payload, managed resource, or
    unknown entry means this is an established/ambiguous tree and must not be
    repaired without a Chief. The exact scan is repeated while holding the new
    lock so two cooperative recovery attempts cannot widen the prefix.
    """

    torn_platform = _validate_interrupted_initialization_prefix(
        paths, initialized_lock=False
    )
    if torn_platform is not None:
        _rewrite_torn_platform_marker(paths.platform, torn_platform)

    # This is the one narrow unauthenticated repair. It creates only structural
    # directories/platform/empty lock. The sentinel is committed only while
    # holding that same lock after an exact second scan; a failed scan restores
    # the empty, untrusted legacy/bootstrap state.
    paths.harness.mkdir(parents=True, exist_ok=True)
    _chmod_private(paths.harness, 0o700)
    if not paths.platform.exists():
        _create_platform_marker(paths.platform)
    ensure_layout(paths)
    if not paths.lock.exists():
        try:
            atomic_create_bytes(paths.lock, b"")
        except HarnessError:
            if not paths.lock.exists():
                raise
    _identity, lock_payload = _read_regular_file_snapshot(
        paths.lock, "AOI state lock", max_bytes=2
    )
    if lock_payload == b"":
        with state_lock(
            paths, create_layout=False, bootstrap_empty_lock=True
        ):
            _validate_interrupted_initialization_prefix(
                paths, initialized_lock=True
            )
    elif lock_payload == b"\0":
        # A concurrent cooperative recovery may have committed the sentinel.
        # It is trusted only after this process locks and repeats the exact scan.
        with state_lock(paths, create_layout=False):
            _validate_interrupted_initialization_prefix(
                paths, initialized_lock=True
            )
    else:
        raise HarnessError(
            "interrupted initialization recovery found an invalid state lock collision"
        )


def bootstrap_chief_state_lock(paths: HarnessPaths) -> bool:
    """Create only a missing lock for a complete pre-v0.2/inactive state tree.

    This is the narrow migration exception used by ``chief-acquire``.  It must
    not repair directories, policies, or other state before a Chief exists.
    """

    if paths.lock.exists():
        identity, lock_payload = _read_regular_file_snapshot(
            paths.lock, "AOI state lock", max_bytes=2
        )
        metadata = paths.lock.lstat()
        if _lock_identity(metadata) != identity:
            raise HarnessError("AOI state lock changed during Chief bootstrap")
        _validate_state_lock_metadata(
            metadata,
            paths.lock,
            require_private_mode=lock_payload == b"\0",
        )
        if lock_payload == b"\0":
            # A committed sentinel is not a blanket fast path. Revalidate either
            # the complete layout or the exact resumable prefix under the lock
            # so a prior failed repair cannot authorize later material state.
            with state_lock(paths, create_layout=False):
                previous = load_chief_authority(paths, allow_missing=True)
                try:
                    require_complete_layout(paths)
                except HarnessError as complete_exc:
                    if previous is not None:
                        raise HarnessError(
                            "Chief lock bootstrap found incomplete established state: "
                            f"{complete_exc}"
                        ) from complete_exc
                    try:
                        _validate_interrupted_initialization_prefix(
                            paths, initialized_lock=True
                        )
                    except HarnessError as recovery_exc:
                        raise HarnessError(
                            "Chief lock bootstrap requires a complete existing AOI layout or "
                            "an exact interrupted-init prefix: "
                            f"complete-layout check failed ({complete_exc}); "
                            f"recovery refused ({recovery_exc})"
                        ) from recovery_exc
            return False
        if lock_payload != b"":
            raise HarnessError(
                "AOI state lock payload is invalid; expected empty legacy lock or one NUL sentinel"
            )
        try:
            preflight_layout(paths)
            previous = load_chief_authority(paths, allow_missing=True)
            if previous is not None and previous["status"] == "active":
                raise HarnessError("active Chief authority has an empty state lock")
            require_complete_layout(paths)
        except HarnessError as complete_exc:
            try:
                _repair_interrupted_initialization_prefix(paths)
            except HarnessError as recovery_exc:
                raise HarnessError(
                    "Chief lock bootstrap requires a complete existing AOI layout or "
                    "an exact interrupted-init prefix: "
                    f"complete-layout check failed ({complete_exc}); "
                    f"recovery refused ({recovery_exc})"
                ) from recovery_exc
        else:
            # POSIX AOI v0.1.3 used a legitimate zero-byte flock file. Convert
            # it to the cross-platform one-byte sentinel only after validating
            # the complete legacy layout and inactive/uninitialized authority,
            # then repeat those checks while holding the converted lock.
            with state_lock(
                paths, create_layout=False, bootstrap_empty_lock=True
            ):
                previous = load_chief_authority(paths, allow_missing=True)
                if previous is not None and previous["status"] == "active":
                    raise HarnessError("active Chief authority has an empty state lock")
                require_complete_layout(paths)
        return True

    try:
        preflight_layout(paths)
        previous = load_chief_authority(paths, allow_missing=True)
        if previous is not None and previous["status"] == "active":
            raise HarnessError("active Chief authority has a missing state lock")
        require_complete_layout(paths, include_lock=False)
    except HarnessError as exc:
        try:
            _repair_interrupted_initialization_prefix(paths)
        except HarnessError as recovery_exc:
            raise HarnessError(
                "Chief lock bootstrap requires a complete existing AOI layout or "
                "an exact interrupted-init prefix: "
                f"complete-layout check failed ({exc}); recovery refused ({recovery_exc})"
            ) from recovery_exc
        return True
    try:
        atomic_create_bytes(paths.lock, b"")
    except HarnessError:
        if not paths.lock.exists():
            raise
    _identity, lock_payload = _read_regular_file_snapshot(
        paths.lock, "AOI state lock", max_bytes=2
    )
    if lock_payload == b"":
        with state_lock(
            paths, create_layout=False, bootstrap_empty_lock=True
        ):
            previous = load_chief_authority(paths, allow_missing=True)
            if previous is not None and previous["status"] == "active":
                raise HarnessError("active Chief authority appeared during lock migration")
            require_complete_layout(paths)
    elif lock_payload == b"\0":
        with state_lock(paths, create_layout=False):
            previous = load_chief_authority(paths, allow_missing=True)
            if previous is not None and previous["status"] == "active":
                raise HarnessError("active Chief authority appeared during lock migration")
            require_complete_layout(paths)
    else:
        raise HarnessError(
            "AOI state lock collision produced neither an empty legacy lock nor the NUL sentinel"
        )
    return True


_CHIEF_CREDENTIAL_FIELDS = {
    "schema_version",
    "project_key",
    "lock_domain",
    "session_id",
    "epoch",
    "token_sha256",
    "created_at",
    "secret_scheme",
    "secret_value",
}


def chief_project_key(paths: HarnessPaths) -> str:
    identity = (
        runtime_lock_domain()
        + "\0"
        + os.path.normcase(str(paths.root.resolve()))
        + "\0"
        + paths.project.state_dir
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _chief_credential_root(
    paths: HarnessPaths, credential_home: Path | None = None
) -> Path:
    if credential_home is not None:
        raw = credential_home.expanduser()
        if not raw.is_absolute():
            raise HarnessError("Chief credential directory must be an absolute path")
    else:
        configured = os.environ.get("AOI_CHIEF_CREDENTIAL_HOME")
        if configured:
            raw = Path(configured).expanduser()
            if not raw.is_absolute():
                raise HarnessError("AOI_CHIEF_CREDENTIAL_HOME must be an absolute path")
        elif os.name == "nt":
            local = os.environ.get("LOCALAPPDATA")
            if local and not Path(local).expanduser().is_absolute():
                raise HarnessError("LOCALAPPDATA must be an absolute path")
            raw = (
                Path(local).expanduser()
                if local
                else Path.home() / "AppData" / "Local"
            ) / "AOI" / "credentials" / "v1"
        else:
            state_home = os.environ.get("XDG_STATE_HOME")
            if state_home and not Path(state_home).expanduser().is_absolute():
                raise HarnessError("XDG_STATE_HOME must be an absolute path")
            raw = (
                Path(state_home).expanduser()
                if state_home
                else Path.home() / ".local" / "state"
            ) / "aoi" / "credentials" / "v1"
    root = canonicalize_no_link_traversal(raw, "Chief credential directory")
    project_root = paths.root.resolve()
    filesystem_root = Path(root.anchor).resolve()
    user_home = Path.home().resolve()
    if root == filesystem_root:
        raise HarnessError("Chief credential directory may not be a filesystem root")
    if root == user_home:
        raise HarnessError("Chief credential directory may not be the user home directory")
    if (
        root == project_root
        or project_root in root.parents
        or root in project_root.parents
    ):
        raise HarnessError(
            "Chief credential directory must be separate from the project repository "
            "and its ancestors"
        )
    _validate_credential_ancestor_chain(root)
    return root


def _validate_credential_ancestor_chain(path: Path) -> None:
    """Reject link-like or non-sticky group/world-writable credential ancestors."""

    current = canonicalize_no_link_traversal(path, "Chief credential directory").parent
    while True:
        validate_existing_regular_directory(current, "Chief credential ancestor")
        if current.exists() and os.name != "nt":
            try:
                metadata = current.stat()
            except OSError as exc:
                raise HarnessError(
                    f"cannot inspect Chief credential ancestor {current}: {exc}"
                ) from exc
            if metadata.st_uid not in {0, os.geteuid()}:
                raise HarnessError(
                    f"Chief credential ancestor has an untrusted owner: {current}"
                )
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o022 and not mode & stat.S_ISVTX:
                raise HarnessError(
                    "Chief credential ancestor is group/world-writable without the "
                    f"sticky bit: {current}"
                )
        if current.parent == current:
            break
        current = current.parent


def _validate_private_credential_directory(path: Path) -> None:
    validate_existing_regular_directory(path, "Chief credential directory")
    if not path.is_dir():
        raise HarnessError(f"Chief credential directory is missing: {path}")
    metadata = path.stat()
    if os.name != "nt":
        if metadata.st_uid != os.geteuid():
            raise HarnessError(f"Chief credential directory has a different owner: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise HarnessError(
                f"Chief credential directory permissions are not private (expected 0700): {path}"
            )


def _ensure_private_credential_directory(path: Path) -> Path:
    canonical = canonicalize_no_link_traversal(path, "Chief credential directory")
    _validate_credential_ancestor_chain(canonical)
    missing: list[Path] = []
    current = canonical
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            raise HarnessError(
                f"cannot find an existing ancestor for Chief credential directory {canonical}"
            )
        current = current.parent
    validate_existing_regular_directory(current, "Chief credential ancestor")
    for directory in reversed(missing):
        created = False
        try:
            directory.mkdir(mode=0o700, exist_ok=False)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise HarnessError(
                f"cannot create Chief credential directory {directory}: {exc}"
            ) from exc
        if created:
            _chmod_private(directory, 0o700)
        _validate_private_credential_directory(directory)
        _validate_credential_ancestor_chain(directory)
    if canonicalize_no_link_traversal(canonical, "Chief credential directory") != canonical:
        raise HarnessError("Chief credential directory changed during creation")
    _validate_private_credential_directory(canonical)
    return canonical


def _validate_private_credential_file(path: Path) -> None:
    path = canonicalize_no_link_traversal(path, "Chief credential file")
    validate_existing_regular_file(path, "Chief credential file")
    if not path.is_file():
        raise HarnessError(f"Chief credential file is missing: {path}")
    metadata = path.stat()
    if metadata.st_size > CHIEF_CREDENTIAL_MAX_BYTES:
        raise HarnessError("Chief credential file exceeds the 8 KiB size bound")
    if os.name != "nt":
        if metadata.st_uid != os.geteuid():
            raise HarnessError(f"Chief credential file has a different owner: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise HarnessError(
                f"Chief credential file permissions are not private (expected 0600): {path}"
            )


def _windows_dpapi_transform(data: bytes, *, protect: bool) -> bytes:
    if os.name != "nt":
        raise HarnessError("Windows DPAPI is unavailable on this platform")
    try:
        import ctypes
        from ctypes import wintypes

        class DataBlob(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        buffer = ctypes.create_string_buffer(data)
        incoming = DataBlob(
            len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        )
        outgoing = DataBlob()
        flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
        if protect:
            ok = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(incoming),
                "AOI Chief credential",
                None,
                None,
                None,
                flags,
                ctypes.byref(outgoing),
            )
        else:
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(incoming),
                None,
                None,
                None,
                None,
                flags,
                ctypes.byref(outgoing),
            )
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(outgoing.pbData, outgoing.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(outgoing.pbData)
    except (OSError, ValueError) as exc:
        operation = "protect" if protect else "unprotect"
        raise HarnessError(f"Windows DPAPI could not {operation} Chief credential") from exc


def _encode_chief_secret(token: str) -> tuple[str, str]:
    if os.name == "nt":
        protected = _windows_dpapi_transform(token.encode("ascii"), protect=True)
        return "dpapi-current-user-v1", base64.b64encode(protected).decode("ascii")
    return "plain-posix-mode-v1", token


def _decode_chief_secret(scheme: Any, value: Any) -> str:
    if not isinstance(scheme, str) or not isinstance(value, str):
        raise HarnessError("Chief credential secret encoding is malformed")
    if scheme == "plain-posix-mode-v1" and os.name != "nt":
        token = value
    elif scheme == "dpapi-current-user-v1" and os.name == "nt":
        try:
            protected = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise HarnessError("Chief credential DPAPI payload is malformed") from exc
        try:
            token = _windows_dpapi_transform(protected, protect=False).decode("ascii")
        except UnicodeDecodeError as exc:
            raise HarnessError("Chief credential DPAPI payload is malformed") from exc
    else:
        raise HarnessError("Chief credential secret scheme is unsupported here")
    chief_token_sha256(token)
    return token


def chief_credential_path(
    paths: HarnessPaths,
    *,
    session_id: str,
    epoch: int,
    token_sha256: str,
    credential_home: Path | None = None,
    create_directories: bool = False,
) -> Path:
    session_id = _validate_chief_session_id(session_id)
    if not _chief_exact_int(epoch, 1):
        raise HarnessError("Chief credential epoch must be a positive integer")
    if not isinstance(token_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", token_sha256
    ):
        raise HarnessError("Chief credential token digest is malformed")
    root = _chief_credential_root(paths, credential_home)
    project = root / chief_project_key(paths)[:32]
    session = project / hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
    if create_directories:
        _ensure_private_credential_directory(root)
        _ensure_private_credential_directory(project)
        _ensure_private_credential_directory(session)
    destination = canonicalize_no_link_traversal(
        session / f"e{epoch}-{token_sha256[:16]}.json", "Chief credential file"
    )
    project_root = paths.root.resolve()
    if destination == project_root or project_root in destination.parents:
        raise HarnessError("Chief credential file must remain outside the project repository")
    return destination


def stage_chief_credential(
    paths: HarnessPaths,
    record: dict[str, Any],
    token: str,
    *,
    credential_home: Path | None = None,
) -> Path:
    _require_chief_lock(paths)
    digest = chief_token_sha256(token)
    if record.get("status") != "active" or record.get("token_sha256") != digest:
        raise HarnessError("Chief credential candidate differs from the authority record")
    destination = chief_credential_path(
        paths,
        session_id=str(record.get("session_id", "")),
        epoch=int(record.get("epoch", 0)),
        token_sha256=digest,
        credential_home=credential_home,
        create_directories=True,
    )
    scheme, secret_value = _encode_chief_secret(token)
    payload = {
        "schema_version": CHIEF_CREDENTIAL_SCHEMA_VERSION,
        "project_key": chief_project_key(paths),
        "lock_domain": runtime_lock_domain(),
        "session_id": record["session_id"],
        "epoch": record["epoch"],
        "token_sha256": digest,
        "created_at": record["issued_at"],
        "secret_scheme": scheme,
        "secret_value": secret_value,
    }
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(encoded) > CHIEF_CREDENTIAL_MAX_BYTES:
        raise HarnessError("Chief credential payload exceeds the 8 KiB size bound")
    existed_before = destination.exists()
    try:
        atomic_create_bytes(destination, encoded)
        _validate_private_credential_file(destination)
    except BaseException:
        if not existed_before:
            _remove_exact_chief_credential_candidate(destination, encoded)
        raise
    return destination


def _remove_exact_chief_credential_candidate(path: Path, expected: bytes) -> bool:
    """Best-effort cleanup after an ambiguous credential create failure.

    Only unlink a single-link, current-user regular file whose descriptor,
    pathname identity, and complete bytes still match this invocation's random
    candidate.  A pre-existing destination is never routed here.
    """

    try:
        target = canonicalize_no_link_traversal(path, "Chief credential candidate")
        before = target.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            return False
        if os.name != "nt" and before.st_uid != os.geteuid():
            return False
        with target.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if _lock_identity(before) != _lock_identity(opened):
                return False
            actual = handle.read(CHIEF_CREDENTIAL_MAX_BYTES + 1)
        after = target.lstat()
        if _lock_identity(after) != _lock_identity(opened) or after.st_nlink != 1:
            return False
        if not hmac.compare_digest(actual, expected):
            return False
        target.unlink()
        fsync_directory(target.parent)
        return True
    except (HarnessError, OSError):
        return False


def load_chief_credential(
    paths: HarnessPaths,
    *,
    session_id: str | None,
    epoch: int | None,
    credential_file: Path | None = None,
) -> tuple[str, Path]:
    _require_chief_lock(paths)
    if session_id is None or epoch is None:
        raise HarnessError("Chief session id and epoch are required to load a credential")
    session_id = _validate_chief_session_id(session_id)
    if not _chief_exact_int(epoch, 1):
        raise HarnessError("Chief credential epoch must be a positive integer")
    authority = load_chief_authority(paths)
    if (
        authority["status"] != "active"
        or authority["session_id"] != session_id
        or authority["epoch"] != epoch
    ):
        raise HarnessError("Chief credential does not match the current authority")
    if credential_file is None:
        credential_root = _chief_credential_root(paths)
        path = chief_credential_path(
            paths,
            session_id=session_id,
            epoch=epoch,
            token_sha256=authority["token_sha256"],
        )
        for directory in (credential_root, path.parent.parent, path.parent):
            _validate_private_credential_directory(directory)
    else:
        raw = credential_file.expanduser()
        if not raw.is_absolute():
            raise HarnessError("Chief credential file must be an absolute path")
        path = canonicalize_no_link_traversal(raw, "Chief credential file")
        project_root = paths.root.resolve()
        if path == project_root or project_root in path.parents:
            raise HarnessError("Chief credential file must remain outside the project repository")
        _validate_credential_ancestor_chain(path)
        _validate_private_credential_directory(path.parent)
    _validate_private_credential_file(path)
    payload = load_json(path)
    if set(payload) != _CHIEF_CREDENTIAL_FIELDS:
        raise HarnessError("Chief credential file has an unsupported field set")
    if payload.get("schema_version") != CHIEF_CREDENTIAL_SCHEMA_VERSION:
        raise HarnessError("Chief credential file has an unsupported schema version")
    if (
        payload.get("project_key") != chief_project_key(paths)
        or payload.get("lock_domain") != runtime_lock_domain()
        or payload.get("session_id") != session_id
        or payload.get("epoch") != epoch
        or payload.get("token_sha256") != authority["token_sha256"]
    ):
        raise HarnessError("Chief credential file does not match the current authority")
    _chief_time(payload.get("created_at"), "credential created_at")
    token = _decode_chief_secret(
        payload.get("secret_scheme"), payload.get("secret_value")
    )
    if not hmac.compare_digest(chief_token_sha256(token), authority["token_sha256"]):
        raise HarnessError("Chief credential secret does not match its digest")
    return token, path


def remove_chief_credential(path: Path | None) -> bool:
    if path is None:
        return False
    target = canonicalize_no_link_traversal(path, "Chief credential file")
    if not target.exists():
        return False
    _validate_credential_ancestor_chain(target)
    _validate_private_credential_directory(target.parent)
    _validate_private_credential_file(target)
    target.unlink()
    fsync_directory(target.parent)
    return True


def require_chief_authority(
    paths: HarnessPaths,
    *,
    session_id: str | None,
    epoch: int | None,
    token: str | None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    _require_chief_lock(paths)
    if session_id is None or epoch is None or token is None:
        raise HarnessError(
            "Chief credential is required; set AOI_CHIEF_SESSION_ID, "
            "AOI_CHIEF_EPOCH, and AOI_CHIEF_TOKEN or use the global options"
        )
    session_id = _validate_chief_session_id(session_id)
    if not _chief_exact_int(epoch, 1):
        raise HarnessError("Chief credential epoch must be a positive integer")
    supplied_digest = chief_token_sha256(token)
    record = load_chief_authority(paths)
    if record["status"] != "active":
        raise HarnessError("Chief authority is inactive; acquire a new lease")
    current = _chief_now(now)
    renewed_at = _chief_time(record["renewed_at"], "renewed_at")
    current = _chief_not_before(
        current, renewed_at, label="Chief lease renewal time"
    )
    if _chief_time(record["expires_at"], "expires_at") <= current:
        raise HarnessError(
            "Chief lease is expired; use chief-takeover with the expected epoch"
        )
    if (
        record["session_id"] != session_id
        or record["epoch"] != epoch
        or not hmac.compare_digest(record["token_sha256"], supplied_digest)
    ):
        raise HarnessError("Chief credential does not match the current authority")
    return record


def acquire_chief_authority(
    paths: HarnessPaths,
    *,
    session_id: str,
    ttl_seconds: int = CHIEF_DEFAULT_TTL_SECONDS,
    credential_home: Path | None = None,
    now: dt.datetime | None = None,
) -> tuple[dict[str, Any], Path]:
    _require_chief_lock(paths)
    session_id = _validate_chief_session_id(session_id)
    ttl_seconds = validate_chief_ttl(ttl_seconds)
    current = _chief_now(now)
    previous = load_chief_authority(paths, allow_missing=True)
    if previous is not None and previous["status"] == "active":
        if _chief_time(previous["expires_at"], "expires_at") <= current:
            raise HarnessError(
                "expired Chief authority requires explicit chief-takeover with expected epoch"
            )
        raise HarnessError("an active Chief lease already exists")
    if previous is not None:
        current = _chief_not_before(
            current,
            _chief_time(previous["updated_at"], "updated_at"),
            label="last Chief authority transition",
        )
    old_epoch = int(previous["epoch"] if previous else 0)
    epoch = old_epoch + 1
    at = _chief_iso(current)
    token = new_chief_token()
    transition_seq, omitted, tail = _append_chief_event(
        previous,
        action="acquire",
        at=at,
        old_epoch=old_epoch,
        new_epoch=epoch,
        session_id=session_id,
        previous_session_id="",
        reason="explicit Chief lease acquisition",
        forced_live=False,
    )
    record = {
        "schema_version": CHIEF_AUTHORITY_SCHEMA_VERSION,
        "epoch": epoch,
        "status": "active",
        "session_id": session_id,
        "token_sha256": chief_token_sha256(token),
        "issued_at": at,
        "renewed_at": at,
        "expires_at": _chief_iso(current + dt.timedelta(seconds=ttl_seconds)),
        "renewal_count": 0,
        "transition_seq": transition_seq,
        "omitted_transition_count": omitted,
        "audit_tail": tail,
        "updated_at": at,
    }
    credential_path = stage_chief_credential(
        paths, record, token, credential_home=credential_home
    )
    try:
        _write_chief_authority(paths, record)
    except BaseException:
        if _chief_authority_definitely_not_published(paths, record):
            with contextlib.suppress(HarnessError, OSError):
                remove_chief_credential(credential_path)
        raise
    return record, credential_path


def renew_chief_authority(
    paths: HarnessPaths,
    *,
    session_id: str | None,
    epoch: int | None,
    token: str | None,
    ttl_seconds: int = CHIEF_DEFAULT_TTL_SECONDS,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    _require_chief_lock(paths)
    ttl_seconds = validate_chief_ttl(ttl_seconds)
    current = _chief_now(now)
    previous = require_chief_authority(
        paths, session_id=session_id, epoch=epoch, token=token, now=current
    )
    current = _chief_not_before(
        current,
        _chief_time(previous["renewed_at"], "renewed_at"),
        label="Chief lease renewal time",
    )
    at = _chief_iso(current)
    transition_seq, omitted, tail = _append_chief_event(
        previous,
        action="renew",
        at=at,
        old_epoch=previous["epoch"],
        new_epoch=previous["epoch"],
        session_id=previous["session_id"],
        previous_session_id=previous["session_id"],
        reason="explicit Chief lease renewal",
        forced_live=False,
    )
    record = {
        **previous,
        "renewed_at": at,
        "expires_at": _chief_iso(current + dt.timedelta(seconds=ttl_seconds)),
        "renewal_count": previous["renewal_count"] + 1,
        "transition_seq": transition_seq,
        "omitted_transition_count": omitted,
        "audit_tail": tail,
        "updated_at": at,
    }
    _write_chief_authority(paths, record)
    return record


def release_chief_authority(
    paths: HarnessPaths,
    *,
    session_id: str | None,
    epoch: int | None,
    token: str | None,
    reason: str,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    _require_chief_lock(paths)
    reason = _validate_chief_reason(reason, "Chief release reason")
    current = _chief_now(now)
    previous = require_chief_authority(
        paths, session_id=session_id, epoch=epoch, token=token, now=current
    )
    current = _chief_not_before(
        current,
        _chief_time(previous["renewed_at"], "renewed_at"),
        label="Chief lease renewal time",
    )
    at = _chief_iso(current)
    transition_seq, omitted, tail = _append_chief_event(
        previous,
        action="release",
        at=at,
        old_epoch=previous["epoch"],
        new_epoch=previous["epoch"],
        session_id=previous["session_id"],
        previous_session_id=previous["session_id"],
        reason=reason,
        forced_live=False,
    )
    record = {
        **previous,
        "status": "inactive",
        "session_id": "",
        "token_sha256": "",
        "issued_at": "",
        "renewed_at": "",
        "expires_at": "",
        "renewal_count": 0,
        "transition_seq": transition_seq,
        "omitted_transition_count": omitted,
        "audit_tail": tail,
        "updated_at": at,
    }
    _write_chief_authority(paths, record)
    return record


def takeover_chief_authority(
    paths: HarnessPaths,
    *,
    session_id: str,
    expected_epoch: int,
    reason: str,
    force_live: bool = False,
    ttl_seconds: int = CHIEF_DEFAULT_TTL_SECONDS,
    credential_home: Path | None = None,
    now: dt.datetime | None = None,
) -> tuple[dict[str, Any], Path]:
    _require_chief_lock(paths)
    session_id = _validate_chief_session_id(session_id)
    if not _chief_exact_int(expected_epoch, 1):
        raise HarnessError("Chief takeover expected epoch must be a positive integer")
    reason = _validate_chief_reason(reason, "Chief takeover reason")
    if not isinstance(force_live, bool):
        raise HarnessError("Chief takeover force_live must be a boolean")
    ttl_seconds = validate_chief_ttl(ttl_seconds)
    current = _chief_now(now)
    previous = load_chief_authority(paths)
    if previous["status"] != "active":
        raise HarnessError("inactive Chief authority must use chief-acquire, not takeover")
    if previous["epoch"] != expected_epoch:
        raise HarnessError("Chief takeover expected epoch CAS failed")
    renewed_at = _chief_time(previous["renewed_at"], "renewed_at")
    current = _chief_not_before(
        current, renewed_at, label="Chief lease renewal time"
    )
    live = _chief_time(previous["expires_at"], "expires_at") > current
    if live and not force_live:
        raise HarnessError("live Chief authority requires --force-live for takeover")
    old_epoch = previous["epoch"]
    epoch = old_epoch + 1
    at = _chief_iso(current)
    token = new_chief_token()
    transition_seq, omitted, tail = _append_chief_event(
        previous,
        action="takeover",
        at=at,
        old_epoch=old_epoch,
        new_epoch=epoch,
        session_id=session_id,
        previous_session_id=previous["session_id"],
        reason=reason,
        forced_live=bool(live and force_live),
    )
    record = {
        **previous,
        "epoch": epoch,
        "status": "active",
        "session_id": session_id,
        "token_sha256": chief_token_sha256(token),
        "issued_at": at,
        "renewed_at": at,
        "expires_at": _chief_iso(current + dt.timedelta(seconds=ttl_seconds)),
        "renewal_count": 0,
        "transition_seq": transition_seq,
        "omitted_transition_count": omitted,
        "audit_tail": tail,
        "updated_at": at,
    }
    credential_path = stage_chief_credential(
        paths, record, token, credential_home=credential_home
    )
    try:
        _write_chief_authority(paths, record)
    except BaseException:
        if _chief_authority_definitely_not_published(paths, record):
            with contextlib.suppress(HarnessError, OSError):
                remove_chief_credential(credential_path)
        raise
    return record, credential_path


def validate_id(value: str, label: str = "identifier") -> str:
    if not ID_RE.fullmatch(value):
        raise HarnessError(
            f"invalid {label}: {value!r}; use 1-128 ASCII letters, digits, dot, dash, or underscore"
        )
    return value


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_create_text(path: Path, text: str) -> None:
    atomic_create_bytes(path, text.encode("utf-8"))


def atomic_create_bytes(path: Path, payload: bytes) -> None:
    """Atomically publish one complete private file without replacement."""

    path = canonicalize_no_link_traversal(path, "atomic create destination")
    path.parent.mkdir(parents=True, exist_ok=True)
    if canonicalize_no_link_traversal(path, "atomic create destination") != path:
        raise HarnessError("atomic create destination changed during parent creation")
    descriptor: int | None = None
    temp_name = ""
    try:
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.tmp-", dir=path.parent
        )
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if canonicalize_no_link_traversal(path, "atomic create destination") != path:
            raise HarnessError("atomic create destination changed before publication")
        try:
            if os.name == "nt":
                # Windows rename is atomic and refuses an existing destination.
                os.rename(temp_name, path)
                temp_name = ""
            else:
                os.link(temp_name, path, follow_symlinks=False)
                Path(temp_name).unlink()
                temp_name = ""
        except FileExistsError as exc:
            raise HarnessError(
                f"refusing to replace existing file during create: {path}"
            ) from exc
        if canonicalize_no_link_traversal(path, "atomic create destination") != path:
            raise HarnessError("atomic create destination changed after publication")
        fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temp_name:
            with contextlib.suppress(FileNotFoundError):
                Path(temp_name).unlink()


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path = canonicalize_no_link_traversal(path, "atomic write destination")
    path.parent.mkdir(parents=True, exist_ok=True)
    if canonicalize_no_link_traversal(path, "atomic write destination") != path:
        raise HarnessError("atomic write destination changed during parent creation")
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            temp_name = handle.name
            handle.flush()
            os.fsync(handle.fileno())
        if canonicalize_no_link_traversal(path, "atomic write destination") != path:
            raise HarnessError("atomic write destination changed before publication")
        replace_file(Path(temp_name), path)
        temp_name = ""
        if canonicalize_no_link_traversal(path, "atomic write destination") != path:
            raise HarnessError("atomic write destination changed after publication")
        fsync_directory(path.parent)
    finally:
        if temp_name:
            with contextlib.suppress(FileNotFoundError):
                Path(temp_name).unlink()


def replace_file(source: Path, destination: Path) -> None:
    """Atomically replace destination, retrying transient Windows sharing failures."""

    destination = canonicalize_no_link_traversal(
        destination, "atomic replace destination"
    )
    deadline = time.monotonic() + WINDOWS_REPLACE_RETRY_SECONDS
    while True:
        try:
            if (
                canonicalize_no_link_traversal(
                    destination, "atomic replace destination"
                )
                != destination
            ):
                raise HarnessError("atomic replace destination changed before publication")
            os.replace(source, destination)
            if (
                canonicalize_no_link_traversal(
                    destination, "atomic replace destination"
                )
                != destination
            ):
                raise HarnessError("atomic replace destination changed after publication")
            return
        except PermissionError as exc:
            if os.name != "nt" or time.monotonic() >= deadline:
                raise HarnessError(
                    f"atomic replace remained blocked by another process: {destination}"
                ) from exc
            time.sleep(0.05)


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # Python exposes no portable directory-handle fsync on Windows. The
        # temporary file itself is fsynced before os.replace; crash durability
        # of the directory entry remains a documented platform boundary.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    try:
        path = canonicalize_no_link_traversal(path, "managed JSON state")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise HarnessError(f"managed JSON state must be a private regular file: {path}")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read(MANAGED_JSON_MAX_BYTES + 1)
            finished = os.fstat(handle.fileno())
        if len(data) > MANAGED_JSON_MAX_BYTES:
            raise HarnessError(f"managed JSON state exceeds the size bound: {path}")
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if any(
            getattr(metadata, field, None) != getattr(opened, field, None)
            or getattr(opened, field, None) != getattr(finished, field, None)
            for field in identity_fields
        ) or opened.st_nlink != 1 or len(data) != finished.st_size:
            raise HarnessError(f"managed JSON state changed while being read: {path}")
        if canonicalize_no_link_traversal(path, "managed JSON state") != path:
            raise HarnessError(f"managed JSON state path changed while being read: {path}")
        value = json.loads(data.decode("utf-8"))
    except FileNotFoundError as exc:
        raise HarnessError(f"missing state file: {path}") from exc
    except HarnessError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"invalid state file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise HarnessError(f"state file must contain a JSON object: {path}")
    return value


def session_key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def session_path(paths: HarnessPaths, session_id: str) -> Path:
    return paths.sessions / f"{session_key(session_id)}.json"


def task_dir(paths: HarnessPaths, task_id: str) -> Path:
    validate_id(task_id, "task id")
    return paths.tasks / task_id


def task_state_path(paths: HarnessPaths, task_id: str) -> Path:
    return task_dir(paths, task_id) / "state.json"


def load_task(paths: HarnessPaths, task_id: str) -> dict[str, Any]:
    state = load_json(task_state_path(paths, task_id))
    validate_task_state(state, task_state_path(paths, task_id))
    if state.get("task_id") != task_id:
        raise HarnessError(f"task state identity does not match requested task {task_id}")
    if state.get("profile_id") != paths.project.profile_id:
        raise HarnessError(
            f"task {task_id} profile differs from current AOI configuration"
        )
    if state.get("config_sha256") != paths.project.sha256:
        raise HarnessError(
            f"task {task_id} configuration changed; review and migrate it explicitly"
        )
    return state


def validate_task_state(state: dict[str, Any], source: Path | None = None) -> None:
    where = f" in {source}" if source else ""
    schema_version = state.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
        raise HarnessError(f"unsupported task schema{where}")
    if not isinstance(state.get("profile_id"), str) or not state.get("profile_id"):
        raise HarnessError(f"task lacks profile identity{where}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(state.get("config_sha256", ""))):
        raise HarnessError(f"task lacks AOI configuration digest{where}")
    validate_id(str(state.get("task_id", "")), "task id")
    if state.get("status") not in TASK_STATUSES:
        raise HarnessError(f"invalid task status{where}: {state.get('status')!r}")
    if state.get("phase") not in TASK_PHASES:
        raise HarnessError(f"invalid task phase{where}: {state.get('phase')!r}")
    if state.get("profile", "full") not in {"full", "mini"}:
        raise HarnessError(f"invalid task profile{where}: {state.get('profile')!r}")
    revision = state.get("revision")
    checkpoint_revision = state.get("checkpoint_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise HarnessError(f"invalid task revision{where}")
    if (
        isinstance(checkpoint_revision, bool)
        or not isinstance(checkpoint_revision, int)
        or checkpoint_revision < 0
    ):
        raise HarnessError(f"invalid checkpoint revision{where}")
    if checkpoint_revision > revision:
        raise HarnessError(f"checkpoint revision exceeds task revision{where}")
    for field in sorted(
        TASK_STRING_LIST_FIELDS | TASK_OBJECT_LIST_FIELDS | TASK_MIXED_LIST_FIELDS
    ):
        if field not in state:
            continue
        value = state[field]
        if not isinstance(value, list):
            raise HarnessError(f"task field {field!r} must be a list{where}")
        if field in TASK_MIXED_LIST_FIELDS:
            for item in value:
                if isinstance(item, str):
                    continue
                if not isinstance(item, dict):
                    raise HarnessError(
                        f"task field {field!r} entries must be strings or objects{where}"
                    )
                if (
                    not RISK_ID_RE.fullmatch(str(item.get("id", "")))
                    or not str(item.get("text", "")).strip()
                    or item.get("status") not in RISK_STATUSES
                ):
                    raise HarnessError(
                        f"task field {field!r} typed entry requires id, text, and "
                        f"a status in {sorted(RISK_STATUSES)}{where}"
                    )
            continue
        expected_type = dict if field in TASK_OBJECT_LIST_FIELDS else str
        if any(not isinstance(item, expected_type) for item in value):
            kind = "objects" if expected_type is dict else "strings"
            raise HarnessError(f"task field {field!r} must contain only {kind}{where}")
    if "delivery" in state and not isinstance(state["delivery"], dict):
        raise HarnessError(f"task field 'delivery' must be an object{where}")


def bump_task(state: dict[str, Any], checkpoint_required: bool = True) -> None:
    state["revision"] = int(state.get("revision", 0)) + 1
    state["updated_at"] = now_iso()
    if checkpoint_required:
        state["checkpoint_required"] = True


def write_task(paths: HarnessPaths, state: dict[str, Any]) -> None:
    validate_task_state(state)
    atomic_write_json(task_state_path(paths, state["task_id"]), state)


def _normalize_repo_path(raw: str) -> str:
    if "\x00" in raw or "\\" in raw:
        raise HarnessError(f"repo lock must use POSIX separators: {raw!r}")
    if not raw or raw.startswith("/"):
        raise HarnessError(f"repo lock path must be relative: {raw!r}")
    if any(marker in raw for marker in ("*", "?", "[", "]", "{", "}")):
        raise HarnessError(f"structured repo locks may not contain glob syntax: {raw!r}")
    path = PurePosixPath(raw)
    if any(part in {"", ".."} for part in path.parts):
        raise HarnessError(f"repo lock path escapes the repo: {raw!r}")
    normalized = path.as_posix()
    if normalized == ".":
        return "."
    if normalized.startswith("../"):
        raise HarnessError(f"repo lock path escapes the repo: {raw!r}")
    normalized = normalized.rstrip("/")
    # Native Windows support is explicitly limited to ordinary
    # case-insensitive local filesystems. Canonicalize repo locks to the same
    # comparison domain so alternate casing cannot bypass mutual exclusion.
    if os.name == "nt":
        _validate_windows_path_components(raw.split("/"), "repo lock", raw)
        normalized = normalized.casefold()
    return normalized


def _normalize_external_path(raw: str) -> str:
    if not raw or "\x00" in raw or "\\" in raw:
        raise HarnessError(f"external lock must use POSIX separators: {raw!r}")
    if raw.startswith("//"):
        raise HarnessError(f"external lock path may not use a double-slash root: {raw!r}")
    path = PurePosixPath(raw)
    if any(marker in raw for marker in ("*", "?", "[", "]", "{", "}")):
        raise HarnessError(f"structured external locks may not contain glob syntax: {raw!r}")
    if not path.is_absolute():
        raise HarnessError(f"external lock path must be absolute: {raw!r}")
    if ".." in path.parts:
        raise HarnessError(f"external lock path may not contain '..': {raw!r}")
    return path.as_posix().rstrip("/") or "/"


def _validate_windows_path_components(
    parts: Iterable[str], label: str, raw: str
) -> None:
    invalid_characters = set('<>:"|?*')
    for part in parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise HarnessError(f"{label} path may not contain '..': {raw!r}")
        if part.endswith((".", " ")):
            raise HarnessError(
                f"{label} path component may not end with dot or space: {raw!r}"
            )
        if any(ord(character) < 32 for character in part) or any(
            character in invalid_characters for character in part
        ):
            raise HarnessError(
                f"{label} path contains a Win32-reserved character: {raw!r}"
            )
        basename = part.split(".", 1)[0].casefold()
        if basename in WINDOWS_RESERVED_BASENAMES:
            raise HarnessError(
                f"{label} path uses a Win32-reserved device name: {raw!r}"
            )


def _looks_like_ntfs_short_name(component: str) -> bool:
    stem, separator, extension = component.partition(".")
    return bool(
        len(stem) <= 8
        and re.fullmatch(
            r"[A-Za-z0-9!#$%&'()@^_`{}~\-\u0080-\uffff]{1,6}~[0-9]+",
            stem,
            re.IGNORECASE,
        )
        and (
            not separator
            or re.fullmatch(
                r"[A-Za-z0-9!#$%&'()@^_`{}~\-\u0080-\uffff]{1,3}",
                extension,
                re.IGNORECASE,
            )
        )
    )


def _normalize_host_path(raw: str) -> str:
    if not raw or "\x00" in raw or "\\" in raw:
        raise HarnessError(f"host lock must use a Windows drive path with '/' separators: {raw!r}")
    if raw.startswith("//") or any(marker in raw for marker in ("*", "?", "[", "]", "{", "}")):
        raise HarnessError(f"invalid host lock path: {raw!r}")
    if not re.fullmatch(r"[A-Za-z]:/.*", raw):
        raise HarnessError(f"host lock path must be drive-absolute, for example D:/path: {raw!r}")
    if ":" in raw[2:]:
        raise HarnessError(f"host lock path may not contain an NTFS alternate stream: {raw!r}")
    raw_parts = raw[3:].split("/")
    if any(part in {".", ".."} for part in raw_parts):
        raise HarnessError(f"host lock path may not contain '.' or '..': {raw!r}")
    _validate_windows_path_components(raw_parts, "host lock", raw)
    path = PureWindowsPath(raw)
    if not path.drive or not path.root or len(path.drive) != 2:
        raise HarnessError(f"host lock path must be drive-absolute: {raw!r}")
    drive = path.drive[0].upper()
    parts = [part.casefold() for part in raw_parts if part]
    suffix = "/".join(parts)
    return f"{drive}:/{suffix}" if suffix else f"{drive}:/"


def host_path_to_runtime(raw: str) -> Path:
    canonical = _normalize_host_path(raw)
    if os.name == "nt":
        return Path(PureWindowsPath(canonical))
    drive = canonical[0].lower()
    suffix = canonical[3:]
    mount_root = Path(os.environ.get("AOI_HOST_MOUNT_ROOT", "/mnt"))
    return mount_root / drive / suffix


def host_path_to_wsl(raw: str) -> Path:
    """Compatibility alias for the pre-v0.1.2 public helper name."""

    return host_path_to_runtime(raw)


def _host_trusted_root(raw: str) -> Path:
    canonical = _normalize_host_path(raw)
    if os.name == "nt":
        return Path(PureWindowsPath(canonical).anchor)
    mount_root = Path(os.environ.get("AOI_HOST_MOUNT_ROOT", "/mnt"))
    return mount_root / canonical[0].lower()


def _path_uses_windows_host_mount(path: Path) -> bool:
    """Return whether a POSIX path is below the configured drive mount root."""

    mount_root = Path(os.environ.get("AOI_HOST_MOUNT_ROOT", "/mnt")).resolve(
        strict=False
    )
    candidate = path.resolve(strict=False)
    try:
        relative = candidate.relative_to(mount_root)
    except ValueError:
        return False
    return bool(relative.parts and re.fullmatch(r"[A-Za-z]", relative.parts[0]))


def _reject_link_traversal(
    candidate: Path, trusted_root: Path, *, namespace: str, raw_path: str
) -> None:
    if _path_is_link_like(trusted_root):
        raise HarnessError(
            f"{namespace} lock trusted root may not be a symlink or junction: {trusted_root}"
        )
    try:
        relative = candidate.relative_to(trusted_root)
    except ValueError as exc:
        raise HarnessError(
            f"{namespace} lock escapes its trusted root: {raw_path}"
        ) from exc
    current = trusted_root
    for part in relative.parts:
        current /= part
        if _path_is_link_like(current):
            raise HarnessError(
                f"{namespace} lock may not traverse a symlink or junction: {raw_path}"
            )
    try:
        resolved_root = trusted_root.resolve()
        candidate.resolve(strict=False).relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HarnessError(
            f"{namespace} lock escapes its trusted root: {raw_path}"
        ) from exc


def _validate_existing_tree_identity(
    candidate: Path, *, namespace: str, raw_path: str
) -> int | None:
    """Reject alternate filesystem identities inside an existing tree."""

    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HarnessError(
            f"cannot inspect {namespace} tree lock target {raw_path}: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise HarnessError(f"tree lock target is not a directory: {candidate}")

    inspected = 0
    pending = [candidate]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = list(entries)
        except OSError as exc:
            raise HarnessError(
                f"cannot inspect {namespace} tree lock target {raw_path}: {exc}"
            ) from exc
        for entry in children:
            inspected += 1
            if inspected > TREE_IDENTITY_SCAN_MAX_ENTRIES:
                raise HarnessError(
                    f"{namespace} tree lock exceeds the fail-closed identity scan "
                    f"limit of {TREE_IDENTITY_SCAN_MAX_ENTRIES} entries: {raw_path}"
                )
            child = Path(entry.path)
            try:
                if _path_is_link_like(child):
                    raise HarnessError(
                        f"{namespace} tree lock may not contain a symlink or "
                        f"junction: {raw_path}"
                    )
                child_metadata = entry.stat(follow_symlinks=False)
            except HarnessError:
                raise
            except OSError as exc:
                raise HarnessError(
                    f"cannot inspect {namespace} tree lock target {raw_path}: {exc}"
                ) from exc
            if stat.S_ISDIR(child_metadata.st_mode):
                pending.append(child)
            elif stat.S_ISREG(child_metadata.st_mode):
                if child_metadata.st_nlink != 1:
                    raise HarnessError(
                        f"{namespace} tree lock may not contain a hard-linked "
                        f"file: {raw_path}"
                    )
            else:
                raise HarnessError(
                    f"{namespace} tree lock may not contain a special filesystem "
                    f"node: {raw_path}"
                )
    return inspected


def normalize_lock(lock: str) -> str:
    if lock != lock.strip():
        raise HarnessError("lock URI may not have leading or trailing whitespace")
    parts = lock.split(":", 2)
    if len(parts) == 3 and parts[0] in {"repo", EXTERNAL_LOCK_NAMESPACE, "host"}:
        namespace, kind, raw_path = parts
        if kind not in {"file", "tree"}:
            raise HarnessError(f"invalid lock kind in {lock!r}")
        normalized = (
            _normalize_repo_path(raw_path)
            if namespace == "repo"
            else _normalize_host_path(raw_path)
            if namespace == "host"
            else _normalize_external_path(raw_path)
        )
        return f"{namespace}:{kind}:{normalized}"
    if len(parts) == 2 and parts[0] == "contract":
        slug = parts[1]
        if not ID_RE.fullmatch(slug):
            raise HarnessError(f"invalid contract lock slug: {slug!r}")
        return f"contract:{slug}"
    if len(parts) == 3 and parts[0] == "git" and parts[1] == "merge":
        branch = parts[2]
        if not SLUG_RE.fullmatch(branch) or ".." in PurePosixPath(branch).parts:
            raise HarnessError(f"invalid git merge branch: {branch!r}")
        if os.name == "nt":
            branch = branch.casefold()
        return f"git:merge:{branch}"
    raise HarnessError(f"invalid lock URI: {lock!r}")


def parse_lock(lock: str) -> tuple[str, str, str]:
    canonical = normalize_lock(lock)
    parts = canonical.split(":", 2)
    if canonical.startswith("contract:"):
        return "contract", "exact", parts[1]
    if canonical.startswith("git:merge:"):
        return "git", "merge", parts[2]
    return parts[0], parts[1], parts[2]


def validate_lock_identity(
    paths: HarnessPaths,
    lock: str,
    repo_root: Path | None = None,
) -> str:
    """Require one stable long-path lock identity for Windows-backed paths.

    Pure lock normalization remains filesystem-independent.  Authority entry
    points call this validator before persisting or comparing a lock so an
    existing NTFS short-name spelling cannot become a second identity.
    """

    canonical = normalize_lock(lock)
    namespace, kind, raw_path = parse_lock(canonical)
    if namespace == "git":
        if os.name != "nt" and _path_uses_windows_host_mount(
            Path(repo_root or paths.root)
        ):
            return f"git:merge:{raw_path.casefold()}"
        return canonical
    if namespace == "repo":
        raw_components = list(PurePosixPath(raw_path).parts)
    elif namespace == "host":
        raw_components = [part for part in raw_path[3:].split("/") if part]
    else:
        return canonical
    short_name_components = [
        part for part in raw_components if _looks_like_ntfs_short_name(part)
    ]
    if os.name != "nt":
        repo_uses_host_mount = namespace == "repo" and _path_uses_windows_host_mount(
            Path(repo_root or paths.root)
        )
        if short_name_components and (namespace == "host" or repo_uses_host_mount):
            raise HarnessError(
                f"{namespace} lock URI contains an unresolved NTFS 8.3-style component; "
                "use canonical long spelling: "
                f"{raw_path!r}"
            )
        if repo_uses_host_mount:
            _validate_windows_path_components(
                raw_components,
                "repo lock on a Windows drive mount",
                raw_path,
            )
            return f"repo:{kind}:{raw_path.casefold()}"
        return canonical
    if namespace == "repo":
        trusted_root = canonicalize_no_link_traversal(
            repo_root or paths.root, "repo lock root"
        )
        candidate = trusted_root / raw_path
        resolved = canonicalize_no_link_traversal(candidate, "repo lock path")
        try:
            relative = resolved.relative_to(trusted_root).as_posix()
        except ValueError as exc:
            raise HarnessError(f"repo lock escapes its trusted root: {raw_path}") from exc
        expected = f"repo:{kind}:{_normalize_repo_path(relative)}"
    elif namespace == "host":
        trusted_root = canonicalize_no_link_traversal(
            _host_trusted_root(raw_path), "host lock root"
        )
        resolved = canonicalize_no_link_traversal(
            host_path_to_runtime(raw_path), "host lock path"
        )
        try:
            resolved.relative_to(trusted_root)
        except ValueError as exc:
            raise HarnessError(f"host lock escapes its trusted root: {raw_path}") from exc
        expected = f"host:{kind}:{_normalize_host_path(resolved.as_posix())}"
    else:
        return canonical
    if expected != canonical:
        raise HarnessError(
            f"{namespace} lock URI must use canonical long spelling; "
            f"use {expected!r} instead of {canonical!r}"
        )
    if short_name_components:
        probe = trusted_root
        for component in raw_components:
            probe /= component
            if _looks_like_ntfs_short_name(component) and not probe.exists():
                raise HarnessError(
                    f"{namespace} lock URI contains an unresolved NTFS 8.3-style "
                    f"component {component!r}; use canonical long spelling"
                )
    return canonical


def validate_persisted_lock_identity(
    paths: HarnessPaths,
    lock: str,
    repo_root: Path | None = None,
) -> str:
    """Reject persisted authority that predates path-aware canonicalization."""

    normalized = normalize_lock(lock)
    canonical = validate_lock_identity(paths, normalized, repo_root=repo_root)
    if canonical != normalized:
        raise HarnessError(
            "persisted lock URI must use its canonical Windows-mount identity; "
            f"use {canonical!r} instead of {normalized!r}"
        )
    return canonical


def validated_state_worktree(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    """Return one canonical absolute worktree or reject malformed state."""

    task_id = str(state.get("task_id") or "unknown")
    raw_worktree = state.get("worktree")
    recorded = raw_worktree is not None and raw_worktree != ""
    if recorded:
        if not isinstance(raw_worktree, str) or not raw_worktree.strip():
            raise HarnessError(f"task {task_id} worktree must be a path string")
        candidate = Path(raw_worktree)
        if not candidate.is_absolute():
            raise HarnessError(f"task {task_id} worktree must be an absolute path")
    else:
        candidate = paths.root
    try:
        canonical = canonicalize_no_link_traversal(
            candidate,
            f"task {task_id} worktree",
        )
    except HarnessError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HarnessError(f"task {task_id} worktree is invalid: {exc}") from exc
    if recorded and canonical != candidate:
        raise HarnessError(
            f"task {task_id} worktree must use canonical spelling: "
            f"{canonical} instead of {candidate}"
        )
    return canonical


def validate_packet_lock_identities(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> None:
    """Validate lock authority already persisted in one delegation packet."""

    packet_id = str(packet.get("packet_id") or "unknown")
    locks = packet.get("locks", [])
    if not isinstance(locks, list):
        raise HarnessError(f"packet {packet_id} locks must be a list")
    repo_root = validated_state_worktree(paths, state)
    try:
        for lock in locks:
            validate_persisted_lock_identity(
                paths,
                str(lock),
                repo_root=repo_root,
            )
    except HarnessError as exc:
        raise HarnessError(
            f"packet {packet_id} has non-canonical lock authority: {exc}"
        ) from exc


def _is_descendant_or_same(child: str, parent: str) -> bool:
    if parent in {".", "/"}:
        return True
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def locks_overlap(left: str, right: str) -> bool:
    left_ns, left_kind, left_path = parse_lock(left)
    right_ns, right_kind, right_path = parse_lock(right)
    if left_ns != right_ns:
        return False
    if left_ns in {"contract", "git"}:
        return left_kind == right_kind and left_path == right_path
    if left_kind == "file" and right_kind == "file":
        return left_path == right_path
    if left_kind == "file" and right_kind == "tree":
        return _is_descendant_or_same(left_path, right_path)
    if left_kind == "tree" and right_kind == "file":
        return _is_descendant_or_same(right_path, left_path)
    return _is_descendant_or_same(left_path, right_path) or _is_descendant_or_same(
        right_path, left_path
    )


def lock_covers(outer: str, inner: str) -> bool:
    """Return whether owning outer fully owns the narrower inner lock."""
    outer_ns, outer_kind, outer_path = parse_lock(outer)
    inner_ns, inner_kind, inner_path = parse_lock(inner)
    if outer_ns != inner_ns:
        return False
    if outer_ns in {"contract", "git"}:
        return outer_kind == inner_kind and outer_path == inner_path
    if outer_kind == "file":
        return inner_kind == "file" and outer_path == inner_path
    if inner_kind == "file":
        return _is_descendant_or_same(inner_path, outer_path)
    return _is_descendant_or_same(inner_path, outer_path)


def sha256_file(path: Path) -> str:
    path = canonicalize_no_link_traversal(path, "SHA-256 input")
    try:
        before = path.lstat()
    except OSError as exc:
        raise HarnessError(f"SHA-256 input is missing or unreadable: {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise HarnessError(f"SHA-256 input must be a non-linked regular file: {path}")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise HarnessError(f"SHA-256 input changed while being opened: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        finished = os.fstat(descriptor)
        if (
            finished.st_size != opened.st_size
            or getattr(finished, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
        ):
            raise HarnessError(f"SHA-256 input changed while being read: {path}")
    finally:
        os.close(descriptor)
    if canonicalize_no_link_traversal(path, "SHA-256 input") != path:
        raise HarnessError(f"SHA-256 input path changed while being read: {path}")
    return digest.hexdigest()


def baselines_for_locks(
    paths: HarnessPaths, locks: Iterable[str], repo_root: Path | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    baseline_root = (repo_root or paths.root).resolve()
    for lock in locks:
        lock = validate_persisted_lock_identity(
            paths, lock, repo_root=baseline_root
        )
        namespace, kind, raw_path = parse_lock(lock)
        if namespace not in {"repo", "host"}:
            continue
        candidate = (
            baseline_root / raw_path
            if namespace == "repo"
            else host_path_to_runtime(raw_path)
        )
        if namespace == "repo":
            _reject_link_traversal(
                candidate, baseline_root, namespace="repo", raw_path=raw_path
            )
        else:
            _reject_link_traversal(
                candidate,
                _host_trusted_root(raw_path),
                namespace="host",
                raw_path=raw_path,
            )
        if kind == "tree":
            _validate_existing_tree_identity(
                candidate, namespace=namespace, raw_path=raw_path
            )
            continue
        if candidate.exists() and not stat.S_ISREG(candidate.stat().st_mode):
            raise HarnessError(f"file lock target is not a regular file: {candidate}")
        if candidate.is_file():
            if candidate.stat().st_nlink != 1:
                raise HarnessError(
                    f"file lock target must not be hard-linked: {candidate}"
                )
            result[lock] = {"exists": True, "sha256": sha256_file(candidate)}
        else:
            result[lock] = {"exists": False, "sha256": None}
    return result


def claim_path(paths: HarnessPaths, token: str, active: bool = True) -> Path:
    validate_id(token, "claim token")
    base = paths.claims_active if active else paths.claims_archive
    return base / f"{token}.json"


def _claim_files(directory: Path) -> Iterator[Path]:
    if directory.is_dir():
        yield from sorted(directory.glob("*.json"))


def load_claim_file(path: Path) -> dict[str, Any]:
    claim = load_json(path)
    schema_version = claim.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
        raise HarnessError(f"unsupported claim schema: {path}")
    if not claim.get("legacy"):
        validate_id(str(claim.get("token", "")), "claim token")
        if claim.get("status") not in CLAIM_STATUSES:
            raise HarnessError(f"invalid claim status in {path}")
    locks = claim.get("locks", [])
    if not isinstance(locks, list):
        raise HarnessError(f"claim locks must be a list: {path}")
    claim["locks"] = [normalize_lock(str(item)) for item in locks]
    return claim


def validate_claim_lock_identities(
    paths: HarnessPaths, claim: dict[str, Any]
) -> None:
    token = str(claim.get("token") or "unknown")
    raw_worktree = claim.get("worktree")
    if claim.get("legacy"):
        if raw_worktree is None or raw_worktree == "":
            repo_root = paths.root
        elif isinstance(raw_worktree, str) and raw_worktree.strip():
            repo_root = Path(raw_worktree)
            if not repo_root.is_absolute():
                raise HarnessError(f"claim {token} worktree must be an absolute path")
        else:
            raise HarnessError(f"claim {token} worktree must be a path string")
    else:
        if not isinstance(raw_worktree, str) or not raw_worktree.strip():
            raise HarnessError(
                f"structured claim {token} worktree must be a path string"
            )
        recorded_root = Path(raw_worktree)
        if not recorded_root.is_absolute():
            raise HarnessError(f"claim {token} worktree must be an absolute path")
        task_id = validate_id(str(claim.get("task_id", "")), "claim task id")
        task = load_task(paths, task_id)
        task_root = validated_state_worktree(paths, task)
        claim_root = canonicalize_no_link_traversal(
            recorded_root,
            f"claim {token} worktree",
        )
        if claim_root != recorded_root or claim_root != task_root:
            raise HarnessError(
                f"structured claim {token} worktree must exactly match owning task "
                f"worktree {task_root}"
            )
        repo_root = task_root
    try:
        for lock in claim.get("locks", []):
            validate_persisted_lock_identity(
                paths, str(lock), repo_root=repo_root
            )
    except HarnessError as exc:
        raise HarnessError(
            f"claim {token} has non-canonical lock authority: {exc}"
        ) from exc


def reserving_claims(paths: HarnessPaths) -> Iterator[dict[str, Any]]:
    for path in _claim_files(paths.claims_active):
        claim = load_claim_file(path)
        if claim.get("status") in RESERVING_CLAIM_STATUSES:
            validate_claim_lock_identities(paths, claim)
            claim["_path"] = str(path)
            yield claim
    for path in _claim_files(paths.legacy_pending):
        claim = load_claim_file(path)
        if claim.get("status") in RESERVING_CLAIM_STATUSES:
            validate_claim_lock_identities(paths, claim)
            claim["_path"] = str(path)
            yield claim


def find_conflicts(
    paths: HarnessPaths,
    locks: Iterable[str],
    ignore_token: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, str]]:
    requested = [
        validate_lock_identity(paths, item, repo_root=repo_root)
        for item in locks
    ]
    conflicts: list[dict[str, str]] = []
    for existing in reserving_claims(paths):
        if ignore_token and existing.get("token") == ignore_token:
            continue
        held_locks = [str(item) for item in existing.get("locks", [])]
        for proposed in requested:
            for held in held_locks:
                if locks_overlap(proposed, held):
                    conflicts.append(
                        {
                            "requested": proposed,
                            "held": held,
                            "token": str(existing.get("token", "unknown")),
                            "owner": str(existing.get("owner", "unknown")),
                            "source": str(existing.get("source", "structured")),
                            "status": str(existing.get("status", "unknown")),
                            "expires_at": str(existing.get("expires_at", "")),
                        }
                    )
    return conflicts


def load_all_tasks(paths: HarnessPaths) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    if not paths.tasks.is_dir():
        return tasks
    for path in sorted(paths.tasks.glob("*/state.json")):
        state = load_json(path)
        validate_task_state(state, path)
        if state.get("task_id") != path.parent.name:
            raise HarnessError(f"task state identity does not match directory: {path}")
        tasks.append(state)
    return tasks


def load_all_claims(paths: HarnessPaths) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for directory in (paths.claims_active, paths.claims_archive, paths.legacy_pending):
        for path in _claim_files(directory):
            claim = load_claim_file(path)
            claim["_path"] = str(path)
            claims.append(claim)
    return claims


def _markdown_list(values: Iterable[str], empty: str = "- None recorded.") -> str:
    items = [str(value).strip() for value in values if str(value).strip()]
    return "\n".join(f"- {item}" for item in items) if items else empty


def claims_for_task(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    validate_reserving: bool = True,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for token in state.get("claims", []):
        active_path = claim_path(paths, token, active=True)
        archive_path = claim_path(paths, token, active=False)
        if active_path.exists():
            claim = load_claim_file(active_path)
            if (
                validate_reserving
                and claim.get("status") in RESERVING_CLAIM_STATUSES
            ):
                validate_claim_lock_identities(paths, claim)
            result.append(claim)
        elif archive_path.exists():
            result.append(load_claim_file(archive_path))
        else:
            result.append({"token": token, "status": "missing", "locks": []})
    return result


def claims_owned_by_task(paths: HarnessPaths, task_id: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for directory in (paths.claims_active, paths.claims_archive):
        for path in _claim_files(directory):
            claim = load_claim_file(path)
            if not claim.get("legacy") and claim.get("task_id") == task_id:
                if claim.get("status") in RESERVING_CLAIM_STATUSES:
                    validate_claim_lock_identities(paths, claim)
                claim["_path"] = str(path)
                result.append(claim)
    return result


def validate_task_claim_references(
    paths: HarnessPaths,
    state: dict[str, Any],
) -> None:
    """Reject missing, foreign, duplicate, or orphan structured claim records."""

    task_id = str(state.get("task_id", ""))
    referenced = [str(token) for token in state.get("claims", [])]
    errors: list[str] = []
    if len(set(referenced)) != len(referenced):
        errors.append("task claim references contain duplicates")
    owned_records = [
        claim
        for claim in load_all_claims(paths)
        if not claim.get("legacy") and str(claim.get("task_id", "")) == task_id
    ]
    owned_counts: dict[str, int] = {}
    for claim in owned_records:
        token = str(claim.get("token", ""))
        owned_counts[token] = owned_counts.get(token, 0) + 1
    for token, count in sorted(owned_counts.items()):
        if count != 1:
            errors.append(f"claim {token} has {count} active/archive records")
    referenced_set = set(referenced)
    owned_set = set(owned_counts)
    for token in sorted(referenced_set - owned_set):
        errors.append(f"task references missing/foreign claim {token}")
    for token in sorted(owned_set - referenced_set):
        errors.append(f"orphan claim {token} is absent from task state")
    if errors:
        raise HarnessError(
            f"task {task_id} claim reference integrity failed: " + "; ".join(errors)
        )


def _checkpoint_compaction_marker(
    label: str,
    records: list[dict[str, Any]],
    compact_statuses: set[str],
    omitted_fields_per_record: int,
) -> str:
    compact_count = sum(
        str(record.get("status")) in compact_statuses for record in records
    )
    full_count = len(records) - compact_count
    status_counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    counts = ",".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    ) or "none"
    return (
        f"Terminal-detail fallback for {label}: total={len(records)}; "
        f"full_detail={full_count}; compact_detail={compact_count}; "
        f"omitted_field_slots={compact_count * omitted_fields_per_record}; "
        f"status_counts={counts}; complete records remain in state.json"
    )


def _compact_claim_reference(
    paths: HarnessPaths,
    claim: dict[str, Any],
) -> str:
    token = str(claim.get("token") or "missing")
    status = str(claim.get("status") or "missing")
    locks = sorted(str(lock) for lock in claim.get("locks", []))
    lock_payload = json.dumps(
        locks,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    lock_digest = hashlib.sha256(lock_payload).hexdigest()

    if status in RESERVING_CLAIM_STATUSES:
        record_path = claim_path(paths, token, active=True)
    elif status in TERMINAL_CLAIM_STATUSES:
        record_path = claim_path(paths, token, active=False)
    else:
        record_path = None
    if record_path is None:
        record = "missing"
    else:
        try:
            record = record_path.relative_to(paths.harness).as_posix()
        except ValueError:
            record = str(record_path)
    return (
        f"{token} [{status}]: locks={len(locks)}; "
        f"lock_set_sha256={lock_digest}; record={record}"
    )


def _canonical_claim_record(claim: dict[str, Any]) -> dict[str, Any]:
    """Return the path-independent claim payload used by history digests."""

    return {
        str(key): value
        for key, value in claim.items()
        if key != "_path"
    }


def _compact_terminal_claim_history(
    paths: HarnessPaths,
    state: dict[str, Any],
    claims: list[dict[str, Any]],
) -> str | None:
    terminal = [
        _canonical_claim_record(claim)
        for claim in claims
        if claim.get("status") in TERMINAL_CLAIM_STATUSES
    ]
    if len(terminal) < COMPACT_CLAIM_HISTORY_THRESHOLD:
        return None

    canonical_claims = sorted(
        terminal,
        key=lambda claim: str(claim.get("token") or ""),
    )
    canonical = json.dumps(
        canonical_claims,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()

    status_counts: dict[str, int] = {}
    for claim in canonical_claims:
        status = str(claim.get("status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    counts = ",".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    )

    chronological = sorted(
        canonical_claims,
        key=lambda claim: (
            str(claim.get("updated_at") or ""),
            str(claim.get("token") or ""),
        ),
    )
    recent_items = []
    for claim in chronological[-COMPACT_CLAIM_RECENT_TAIL:]:
        payload = json.dumps(
            claim,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        recent_items.append(
            f"{claim.get('token')}[{claim.get('status')}]=sha256:"
            f"{hashlib.sha256(payload).hexdigest()[:12]}"
        )
    recent = ",".join(recent_items)

    state_path = task_dir(paths, state["task_id"]) / "state.json"
    try:
        task_record = state_path.relative_to(paths.harness).as_posix()
        claim_records = paths.claims_archive.relative_to(paths.harness).as_posix()
    except ValueError:
        task_record = str(state_path)
        claim_records = str(paths.claims_archive)
    return (
        f"Terminal claim history: count={len(canonical_claims)}; "
        f"status_counts={counts}; history_sha256={digest}; "
        f"task_record={task_record}#claims; claim_records={claim_records}; "
        f"recent={recent or 'none'}"
    )


def _task_state_record_reference(
    paths: HarnessPaths,
    state: dict[str, Any],
    field: str,
) -> str:
    state_path = task_dir(paths, state["task_id"]) / "state.json"
    try:
        record = state_path.relative_to(paths.harness).as_posix()
    except ValueError:
        record = str(state_path)
    return f"{record}#{field}"


def _compact_terminal_verification_history(
    paths: HarnessPaths,
    state: dict[str, Any],
    verification: list[dict[str, Any]],
) -> str | None:
    terminal = [
        (index, item)
        for index, item in enumerate(verification, start=1)
        if item.get("status") in ACCOUNTED_VERIFICATION_STATUSES
    ]
    if len(terminal) < COMPACT_VERIFICATION_HISTORY_THRESHOLD:
        return None

    canonical_records = [item for _, item in terminal]
    canonical = json.dumps(
        canonical_records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()

    status_counts: dict[str, int] = {}
    for item in canonical_records:
        status = str(item.get("status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    counts = ",".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    )

    recent_items = []
    for index, item in terminal[-COMPACT_VERIFICATION_RECENT_TAIL:]:
        payload = json.dumps(
            item,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        recent_items.append(
            f"#{index}:{item.get('category')}[{item.get('status')}]=sha256:"
            f"{hashlib.sha256(payload).hexdigest()[:12]}"
        )
    recent = ",".join(recent_items)
    return (
        f"Terminal verification history: count={len(terminal)}; "
        f"status_counts={counts}; history_sha256={digest}; "
        f"record={_task_state_record_reference(paths, state, 'verification')}; "
        f"recent={recent or 'none'}"
    )


def _compact_terminal_job_history(
    paths: HarnessPaths,
    state: dict[str, Any],
    jobs: list[dict[str, Any]],
) -> str | None:
    terminal_statuses = JOB_STATUSES - ACTIVE_JOB_STATUSES
    terminal = [job for job in jobs if job.get("status") in terminal_statuses]
    if len(terminal) < COMPACT_JOB_HISTORY_THRESHOLD:
        return None

    canonical = json.dumps(
        terminal,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()

    status_counts: dict[str, int] = {}
    for job in terminal:
        status = str(job.get("status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    counts = ",".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    )

    recent_items = []
    for job in terminal[-COMPACT_JOB_RECENT_TAIL:]:
        payload = json.dumps(
            job,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        recent_items.append(
            f"{job.get('run_id')}[{job.get('status')}]=sha256:"
            f"{hashlib.sha256(payload).hexdigest()[:12]}"
        )
    recent = ",".join(recent_items)
    return (
        f"Terminal job history: count={len(terminal)}; "
        f"status_counts={counts}; history_sha256={digest}; "
        f"record={_task_state_record_reference(paths, state, 'jobs')}; "
        f"recent={recent or 'none'}"
    )


def _compact_fact_history(
    paths: HarnessPaths,
    state: dict[str, Any],
    facts: list[str],
) -> str | None:
    if len(facts) < COMPACT_FACT_HISTORY_THRESHOLD:
        return None

    canonical = json.dumps(
        facts,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    recent_count = min(len(facts), COMPACT_FACT_RECENT_TAIL)
    return (
        f"Established fact history: count={len(facts)}; "
        f"history_sha256={digest}; "
        f"record={_task_state_record_reference(paths, state, 'facts')}; "
        f"recent_verbatim={recent_count}"
    )


def _compact_packet_result_reference(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> str:
    raw_result = str(packet.get("result_path") or "").strip()
    if not raw_result:
        return "n/a"

    result_path = Path(raw_result)
    if not result_path.is_absolute():
        display = raw_result
    else:
        try:
            canonical_result_path = canonicalize_no_link_traversal(
                result_path, "packet result path"
            )
            canonical_task_dir = canonicalize_no_link_traversal(
                task_dir(paths, state["task_id"]), "packet task directory"
            )
            display = canonical_result_path.relative_to(canonical_task_dir).as_posix()
        except (HarnessError, ValueError):
            display = raw_result

    digest = str(packet.get("result_sha256") or "")
    valid_digest = bool(re.fullmatch(r"[0-9a-f]{64}", digest))
    canonical_result = f"results/{packet.get('packet_id')}.md"
    if display == canonical_result and valid_digest:
        return f"sha256:{digest[:12]}"
    if valid_digest:
        display = f"{display}@{digest[:12]}"
    return display


def _compact_terminal_packet_history(
    paths: HarnessPaths,
    state: dict[str, Any],
    packets: list[dict[str, Any]],
) -> str | None:
    terminal_statuses = PACKET_STATUSES - ACTIVE_PACKET_STATUSES
    terminal = [
        packet for packet in packets if packet.get("status") in terminal_statuses
    ]
    if len(terminal) < COMPACT_PACKET_HISTORY_THRESHOLD:
        return None

    canonical = json.dumps(
        terminal,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    status_counts: dict[str, int] = {}
    for packet in terminal:
        status = str(packet.get("status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    counts = ",".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    )
    recent = ",".join(
        f"{packet.get('packet_id')}[{packet.get('status')}]="
        f"{_compact_packet_result_reference(paths, state, packet)}"
        for packet in terminal[-COMPACT_PACKET_RECENT_TAIL:]
    )
    state_path = task_dir(paths, state["task_id"]) / "state.json"
    try:
        record = state_path.relative_to(paths.harness).as_posix()
    except ValueError:
        record = str(state_path)
    return (
        f"Terminal packet history: count={len(terminal)}; "
        f"status_counts={counts}; history_sha256={digest}; "
        f"record={record}#packets; recent={recent or 'none'}"
    )


def render_checkpoint(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    compact_terminal_detail: bool = False,
) -> str:
    validate_task_claim_references(paths, state)
    for packet in state.get("packets", []):
        if packet.get("status") in ACTIVE_PACKET_STATUSES:
            validate_packet_lock_identities(paths, state, packet)
    claims = claims_for_task(paths, state)
    compact_claim_history = (
        _compact_terminal_claim_history(paths, state, claims)
        if compact_terminal_detail
        else None
    )
    claim_lines = []
    for claim in claims:
        if compact_terminal_detail:
            if (
                compact_claim_history is not None
                and claim.get("status") in TERMINAL_CLAIM_STATUSES
            ):
                continue
            if claim.get("status") not in TERMINAL_CLAIM_STATUSES:
                locks = ", ".join(claim.get("locks", [])) or "no machine locks"
                claim_lines.append(
                    f"{claim.get('token')} [{claim.get('status')}]: {locks}"
                )
            else:
                claim_lines.append(_compact_claim_reference(paths, claim))
        else:
            locks = ", ".join(claim.get("locks", [])) or "no machine locks"
            claim_lines.append(
                f"{claim.get('token')} [{claim.get('status')}]: {locks}"
            )
    if compact_terminal_detail:
        if compact_claim_history is not None:
            claim_lines.insert(0, compact_claim_history)
        claim_lines.insert(
            0,
            _checkpoint_compaction_marker(
                "claims",
                claims,
                TERMINAL_CLAIM_STATUSES,
                3,
            ),
        )

    verification = list(state.get("verification", []))
    compact_verification_history = (
        _compact_terminal_verification_history(paths, state, verification)
        if compact_terminal_detail
        else None
    )
    verification_lines = []
    for item in verification:
        if (
            compact_terminal_detail
            and item.get("status") in ACCOUNTED_VERIFICATION_STATUSES
        ):
            if compact_verification_history is not None:
                continue
            verification_lines.append(
                f"{item.get('category')} [{item.get('status')}]: "
                f"evidence={item.get('evidence') or 'n/a'}; "
                f"boundary={item.get('boundary') or 'n/a'}; "
                "command omitted (complete record in state.json)"
            )
        else:
            command = (
                f"; command={item.get('command')}" if item.get("command") else ""
            )
            boundary = (
                f"; boundary={item.get('boundary')}"
                if item.get("boundary")
                else ""
            )
            verification_lines.append(
                f"{item.get('category')} [{item.get('status')}]: "
                f"{item.get('evidence')}{command}{boundary}"
            )
    if compact_terminal_detail:
        if compact_verification_history is not None:
            verification_lines.insert(0, compact_verification_history)
        verification_lines.insert(
            0,
            _checkpoint_compaction_marker(
                "verification",
                verification,
                ACCOUNTED_VERIFICATION_STATUSES,
                1,
            ),
        )

    jobs = list(state.get("jobs", []))
    job_lines = []
    terminal_job_statuses = JOB_STATUSES - ACTIVE_JOB_STATUSES
    compact_job_history = (
        _compact_terminal_job_history(paths, state, jobs)
        if compact_terminal_detail
        else None
    )
    for job in jobs:
        if compact_terminal_detail and job.get("status") in terminal_job_statuses:
            if compact_job_history is not None:
                continue
            job_lines.append(
                f"{job.get('run_id')} [{job.get('status')}]: "
                f"log={job.get('log') or 'n/a'}; "
                "terminal detail omitted (complete record in state.json)"
            )
        else:
            job_lines.append(
                f"{job.get('run_id')} [{job.get('status')}]: "
                f"host={job.get('host')}, tool={job.get('tool')}, "
                f"log={job.get('log')}, pid={job.get('pid') or 'n/a'}, "
                f"tmux={job.get('tmux') or 'n/a'}, "
                f"stop={job.get('stop_condition') or 'n/a'}, "
                f"source_sha={job.get('source_sha') or 'n/a'}, "
                f"source_scope={job.get('source_scope') or 'n/a'}, "
                f"evidence={job.get('evidence') or 'n/a'}"
            )
    if compact_terminal_detail:
        if compact_job_history is not None:
            job_lines.insert(0, compact_job_history)
        job_lines.insert(
            0,
            _checkpoint_compaction_marker(
                "jobs",
                jobs,
                terminal_job_statuses,
                8,
            ),
        )

    packets = list(state.get("packets", []))
    packet_lines = []
    terminal_packet_statuses = PACKET_STATUSES - ACTIVE_PACKET_STATUSES
    compact_packet_history = (
        _compact_terminal_packet_history(paths, state, packets)
        if compact_terminal_detail
        else None
    )
    for packet in packets:
        if (
            compact_terminal_detail
            and packet.get("status") in terminal_packet_statuses
        ):
            if compact_packet_history is not None:
                continue
            packet_lines.append(
                f"{packet.get('packet_id')} [{packet.get('status')}]: "
                "result="
                f"{_compact_packet_result_reference(paths, state, packet)}"
            )
        else:
            packet_lines.append(
                f"{packet.get('packet_id')} [{packet.get('status')}]: "
                f"requested={packet.get('agent_role')}/{packet.get('model_tier')}; "
                f"agent={packet.get('agent_id') or 'n/a'}; "
                f"result={packet.get('result_path') or 'n/a'}; "
                f"summary={packet.get('summary') or 'not recorded'}"
            )
    if compact_terminal_detail:
        if compact_packet_history is not None:
            packet_lines.insert(0, compact_packet_history)
        packet_lines.insert(
            0,
            _checkpoint_compaction_marker(
                "packets",
                packets,
                terminal_packet_statuses,
                4,
            ),
        )

    incidents = list(state.get("subagent_incidents", []))
    open_incidents = [
        item for item in incidents if item.get("status") == "open"
    ]
    incident_lines = [
        f"{item.get('incident_id')} [open]: reason={item.get('reason_code')}; "
        f"agent={item.get('agent_id') or 'n/a'}; type={item.get('agent_type') or 'n/a'}; "
        f"observed={item.get('observed_at') or 'n/a'}"
        for item in open_incidents
    ]
    accounted_incidents = sum(
        item.get("status") == "accounted" for item in incidents
    )
    if accounted_incidents:
        incident_lines.append(
            f"Accounted spawn incidents: {accounted_incidents}; complete records are in state.json"
        )

    engaged_lanes = [
        lane
        for lane in state.get("lanes", [])
        if lane.get("status") in {"active", "waiting", "recovering", "blocked"}
    ]
    engaged_lanes.sort(key=lambda item: str(item.get("lane_id", "")))
    lane_limit = 4 if compact_terminal_detail else 12
    lane_lines = [
        f"{lane.get('lane_id')} [{lane.get('status')}], rev={lane.get('revision')}, "
        f"owner={lane.get('owner')}, next={lane.get('next_action') or 'not recorded'}"
        for lane in engaged_lanes[:lane_limit]
    ]
    if len(engaged_lanes) > lane_limit:
        lane_lines.append(
            f"{len(engaged_lanes) - lane_limit} additional engaged lanes omitted; see state.json"
        )
    active_coordination = sum(
        request.get("status") not in {"rejected", "resolved", "superseded"}
        for request in state.get("coordination_requests", [])
    )
    active_capacity = sum(
        review.get("status") not in {"rejected", "consumed", "superseded"}
        for review in state.get("capacity_reviews", [])
    )
    active_improvements = sum(
        request.get("status") not in {"rejected", "adopted", "rolled_back", "deprecated"}
        for request in state.get("improvement_requests", [])
    )
    active_cross_sessions = sum(
        item.get("status") == "open" for item in state.get("cross_lane_sessions", [])
    )
    needs_user = sum(
        item.get("status") == "needs_user"
        for item in state.get("needs_user_escalations", [])
    )
    open_overrides = sum(
        item.get("status") in {"awaiting_chief", "approved"}
        for item in state.get("override_requests", [])
    )
    control_plane_lines = [
        f"Steward inbox: coordination={active_coordination}, capacity={active_capacity}, "
        f"improvement={active_improvements}, cross_lane={active_cross_sessions}; "
        f"needs_user={needs_user}, overrides={open_overrides}; "
        f"resource_events={len(state.get('resource_config_events', []))}; "
        f"execution_briefs={len(state.get('execution_briefs', []))}; "
        "complete records are in state.json"
    ]

    open_risk_lines: list[str] = []
    retired_risks: list[str] = []
    materialized_risks: list[str] = []
    for item in state.get("risks", []):
        if isinstance(item, str):
            open_risk_lines.append(f"RISK: {item}")
        elif item.get("status") == "retired":
            retired_risks.append(str(item.get("id", "")))
        elif item.get("status") == "materialized":
            materialized_risks.append(str(item.get("id", "")))
        else:
            open_risk_lines.append(f"RISK[{item.get('id', '')}]: {item.get('text', '')}")
    if retired_risks or materialized_risks:
        open_risk_lines.append(
            "RISKS ACCOUNTED: "
            f"retired={len(retired_risks)} ({', '.join(retired_risks) or 'none'}), "
            f"materialized={len(materialized_risks)} "
            f"({', '.join(materialized_risks) or 'none'}); "
            "full text in state.json"
        )
    blockers_and_risks = [
        *(f"BLOCKER: {item}" for item in state.get("blockers", [])),
        *open_risk_lines,
    ]
    facts = list(state.get("facts", []))
    compact_fact_history = (
        _compact_fact_history(paths, state, facts)
        if compact_terminal_detail
        else None
    )
    fact_lines = facts
    if compact_fact_history is not None:
        fact_lines = [
            compact_fact_history,
            *facts[-COMPACT_FACT_RECENT_TAIL:],
        ]
    return (
        f"# Checkpoint — {state['task_id']}\n\n"
        f"- State revision: `{state['revision']}`\n"
        f"- Updated: `{state['updated_at']}`\n"
        f"- Status / phase: `{state['status']}` / `{state['phase']}`\n\n"
        "## Plan\n\n"
        f"- Approved: `{str(bool(state.get('plan_ready'))).lower()}`\n"
        f"- SHA-256: {state.get('plan_sha256') or 'not recorded'}\n\n"
        "## Objective\n\n"
        f"{state.get('objective') or 'Not recorded.'}\n\n"
        "## Completion boundary\n\n"
        f"{state.get('completion_boundary') or 'Not recorded.'}\n\n"
        "## Claims\n\n"
        f"{_markdown_list(claim_lines)}\n\n"
        "## Portfolio control plane\n\n"
        f"{_markdown_list([*lane_lines, *control_plane_lines])}\n\n"
        "## Established facts\n\n"
        f"{_markdown_list(fact_lines)}\n\n"
        "## Decisions\n\n"
        f"{_markdown_list(state.get('decisions', []))}\n\n"
        "## Rejected paths\n\n"
        f"{_markdown_list(state.get('rejected_paths', []))}\n\n"
        "## Changed files\n\n"
        f"{_markdown_list(state.get('changed_files', []))}\n\n"
        "## Verification and evidence boundary\n\n"
        f"{_markdown_list(verification_lines)}\n\n"
        "## Active jobs\n\n"
        f"{_markdown_list(job_lines)}\n\n"
        "## Delegation packets\n\n"
        f"{_markdown_list(packet_lines)}\n\n"
        "## Sub-agent spawn incidents\n\n"
        f"{_markdown_list(incident_lines)}\n\n"
        "## Blockers and risks\n\n"
        f"{_markdown_list(blockers_and_risks)}\n\n"
        "## Delivery\n\n"
        f"- Mode: `{state.get('delivery', {}).get('mode', 'pending')}`\n"
        f"- Detail: {state.get('delivery', {}).get('detail') or 'Not recorded.'}\n"
        f"- Commit: {state.get('delivery', {}).get('commit') or 'n/a'}\n\n"
        "## Exact next action\n\n"
        f"{state.get('next_action') or 'Not recorded.'}\n"
    )


def prepare_checkpoint(
    paths: HarnessPaths, state: dict[str, Any]
) -> tuple[Path, str, str]:
    destination = task_dir(paths, state["task_id"]) / "checkpoint.md"
    text = render_checkpoint(paths, state)
    if len(text.encode("utf-8")) > CHECKPOINT_COMPACT_THRESHOLD_BYTES:
        text = render_checkpoint(paths, state, compact_terminal_detail=True)
    if len(text.encode("utf-8")) > CHECKPOINT_MAX_BYTES:
        raise HarnessError(
            "checkpoint exceeds 32 KiB hard ceiling; summarize facts/evidence and keep raw logs outside state"
        )
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return destination, text, digest


def write_checkpoint(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    destination, text, _ = prepare_checkpoint(paths, state)
    atomic_write_text(destination, text)
    return destination


def checkpoint_matches(
    paths: HarnessPaths, state: dict[str, Any]
) -> tuple[bool, str]:
    if state.get("checkpoint_required"):
        return False, "checkpoint_required is true"
    if state.get("checkpoint_revision") != state.get("revision"):
        return False, "checkpoint revision differs from state revision"
    expected = state.get("checkpoint_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False, "checkpoint SHA-256 is missing or invalid"
    destination = task_dir(paths, state["task_id"]) / "checkpoint.md"
    if not destination.is_file():
        return False, "checkpoint file is missing"
    actual = sha256_file(destination)
    if actual != expected:
        return False, "checkpoint file SHA-256 differs from state"
    return True, "current"


def render_index(paths: HarnessPaths) -> str:
    tasks = load_all_tasks(paths)
    active_tasks = [task for task in tasks if task.get("status") in {"active", "blocked"}]
    active_claims = [
        claim
        for claim in load_all_claims(paths)
        if claim.get("status") in RESERVING_CLAIM_STATUSES
    ]
    structured = [claim for claim in active_claims if not claim.get("legacy")]
    legacy = [claim for claim in active_claims if claim.get("legacy")]
    expired = [claim for claim in active_claims if is_expired(claim.get("expires_at"))]

    lines = [
        f"# AOI Index — {paths.project.name}",
        "",
        f"Generated: `{now_iso()}`",
        "",
        f"Configuration: `{paths.config}` (`{paths.project.sha256}`); policy: "
        f"`{paths.harness / 'POLICY.md'}`.",
        "",
        "## Active tasks",
        "",
    ]
    if active_tasks:
        for task in sorted(active_tasks, key=lambda item: item.get("updated_at", ""), reverse=True):
            checkpoint_ok, _ = checkpoint_matches(paths, task)
            stale = "checkpoint current" if checkpoint_ok else "checkpoint stale"
            plan_file = task_dir(paths, task["task_id"]) / "plan.md"
            plan_current = bool(
                task.get("plan_ready")
                and plan_file.is_file()
                and task.get("plan_sha256") == sha256_file(plan_file)
            )
            plan_label = "plan current" if plan_current else "plan not approved/current"
            lines.append(
                f"- `{task['task_id']}` — {task.get('status')}/{task.get('phase')}, "
                f"rev {task.get('revision')}, {stale}, {plan_label}, "
                f"engaged lanes={sum(lane.get('status') in {'active', 'waiting', 'recovering', 'blocked'} for lane in task.get('lanes', []))}, "
                f"chief inbox={sum(review.get('status') == 'awaiting_chief' for review in task.get('capacity_reviews', [])) + sum(request.get('status') == 'awaiting_chief' for request in task.get('improvement_requests', []))}, "
                f"needs_user={sum(item.get('status') == 'needs_user' for item in task.get('needs_user_escalations', []))}; next: "
                f"{task.get('next_action') or 'not recorded'}"
            )
    else:
        lines.append("- None.")

    lines.extend(["", "## Structured reserving claims", ""])
    if structured:
        for claim in structured:
            expiry = " EXPIRED—STILL RESERVED" if is_expired(claim.get("expires_at")) else ""
            lines.append(
                f"- `{claim.get('token')}` [{claim.get('status')}] owner="
                f"{claim.get('owner')}; locks={', '.join(claim.get('locks', [])) or 'none'}"
                f"{expiry}"
            )
    else:
        lines.append("- None.")

    if paths.project.legacy_enabled:
        lines.extend(["", "## Legacy quarantine", ""])
        lines.append(
            f"- Pending non-terminal legacy rows: **{len(legacy)}**; expired but unaudited: "
            f"**{sum(1 for item in legacy if item.get('legacy_classification') == 'expired_unverified')}**."
        )
        ambiguous = sum(1 for item in legacy if item.get("scope_parse_warnings"))
        lines.append(f"- Rows with ambiguous/unparsed scope text: **{ambiguous}**.")
        if legacy:
            lines.append("- Inspect with `aoi status --legacy`.")

    lines.extend(["", "## Immediate warnings", ""])
    if expired:
        lines.append(
            f"- {len(expired)} reserving claim(s) are expired. Expiry is warning-only; audit owner/job state before marking stale."
        )
    stale_tasks = [
        task
        for task in active_tasks
        if not checkpoint_matches(paths, task)[0]
    ]
    if stale_tasks:
        lines.append(
            "- Stale checkpoints: " + ", ".join(f"`{task['task_id']}`" for task in stale_tasks)
        )
    if not expired and not stale_tasks:
        lines.append("- None.")

    lines.extend(
        [
            "",
            "## Commands",
            "",
            "```bash",
            "aoi status",
            "aoi doctor",
            "aoi resume --task <task-id>",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def write_index(paths: HarnessPaths) -> None:
    atomic_write_text(paths.index, render_index(paths))


def legacy_is_terminal(raw_status: str) -> bool:
    normalized = raw_status.strip().lower()
    return normalized.startswith(
        (
            "done",
            "complete",
            "released",
            "stale",
            "cancelled",
            "canceled",
            "closed",
            "rejected",
            "stopped",
            "superseded",
        )
    )


LEGACY_REPO_ROOTS = {
    "AGENTS.md",
    ".codex",
    "app",
    "config",
    "constraints",
    "examples",
    "infra",
    "lib",
    "packages",
    "src",
    "tests",
    "scripts",
    "docs",
    "notes",
    "paper",
    "experiments",
    "build",
    "runs",
    "tools",
}


def _infer_legacy_lock(paths: HarnessPaths, candidate: str) -> str | None:
    raw = candidate.strip().strip(".,;:")
    if not raw or " " in raw:
        return None
    if raw == "LEGACY_CONTROL.md":
        return None
    configured_prefix = f"{paths.project.external_lock_namespace}:/"
    if raw.startswith(configured_prefix):
        raw = raw.removeprefix(f"{paths.project.external_lock_namespace}:")
    elif raw.startswith("external:/"):
        raw = raw.removeprefix("external:")
    elif raw.startswith("~/"):
        raw = str(Path(raw).expanduser())
    glob_positions = [
        raw.find(marker)
        for marker in ("*", "?", "[", "]", "{", "}")
        if marker in raw
    ]
    had_glob = bool(glob_positions)
    if had_glob:
        prefix = raw[: min(glob_positions)]
        if prefix.endswith("/"):
            raw = prefix.rstrip("/")
        else:
            raw = PurePosixPath(prefix).parent.as_posix()
    raw = raw.rstrip("/")
    if not raw:
        raw = "/" if candidate.strip().startswith(("/", configured_prefix, "external:/", "~/")) else "."
    # The historical table intentionally let every owner append its own row to
    # the shared coordination ledger. Treating that shared bookkeeping file as
    # an exclusive technical lock would make every legacy claim conflict with
    # every other one and would prevent migration itself.
    if raw.startswith("/"):
        kind = "tree" if had_glob or not PurePosixPath(raw).suffix else "file"
        try:
            return normalize_lock(
                f"{paths.project.external_lock_namespace}:{kind}:{raw}"
            )
        except HarnessError:
            return None
    if raw.startswith(("./", "../")):
        raw = raw[2:] if raw.startswith("./") else raw
    first = raw.split("/", 1)[0]
    if first not in LEGACY_REPO_ROOTS and not (paths.root / raw).exists():
        return None
    kind = "tree" if had_glob or (paths.root / raw).is_dir() else "file"
    if not had_glob and not (paths.root / raw).exists() and not PurePosixPath(raw).suffix:
        kind = "tree"
    try:
        return normalize_lock(f"repo:{kind}:{raw}")
    except HarnessError:
        return None


def extract_markdown_code_spans(text: str) -> list[str]:
    spans: list[str] = []
    index = 0
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] != "`":
            index += 1
            continue
        end = index
        while end < len(text) and text[end] == "`":
            end += 1
        delimiter_length = end - index
        cursor = end
        while cursor < len(text):
            if text[cursor] != "`":
                cursor += 1
                continue
            close = cursor
            while close < len(text) and text[close] == "`":
                close += 1
            if close - cursor == delimiter_length:
                spans.append(text[end:cursor])
                index = close
                break
            cursor = close
        else:
            raise HarnessError(
                f"unclosed Markdown code span with {delimiter_length} backtick(s)"
            )
    return spans


def _legacy_candidate_looks_pathlike(candidate: str) -> bool:
    raw = candidate.strip().strip(".,;:")
    if not raw or raw == "LEGACY_CONTROL.md":
        return False
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?ns(?:/[0-9]+(?:\.[0-9]+)?ns)*", raw):
        return False
    first = raw.removeprefix("external:").removeprefix("~/").split("/", 1)[0]
    return (
        raw.startswith(("/", "~/", "./", "../", "external:/", "."))
        or first in LEGACY_REPO_ROOTS
        or any(marker in raw for marker in ("*", "?", "[", "]", "{", "}"))
        or "/" in raw
    )


def legacy_scope_locks(paths: HarnessPaths, scope: str) -> tuple[list[str], list[str]]:
    candidates = extract_markdown_code_spans(scope)
    locks: list[str] = []
    warnings: list[str] = []
    for candidate in candidates:
        if candidate.strip().strip(".,;:") == "LEGACY_CONTROL.md":
            continue
        lock = _infer_legacy_lock(paths, candidate)
        if lock:
            if lock not in locks:
                locks.append(lock)
        elif _legacy_candidate_looks_pathlike(candidate):
            warnings.append(candidate)
    if not candidates:
        warnings.append("no backtick-delimited path could be parsed")
    return locks, warnings


def load_legacy_decision(paths: HarnessPaths, token: str) -> dict[str, Any] | None:
    decision_path = paths.legacy_decisions / f"{session_key(token)}.json"
    return load_json(decision_path) if decision_path.exists() else None


def record_legacy_decision(
    paths: HarnessPaths, token: str, decision: str, detail: str
) -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "token": token,
        "decision": decision,
        "detail": detail,
        "updated_at": now_iso(),
    }
    atomic_write_json(paths.legacy_decisions / f"{session_key(token)}.json", payload)


def split_markdown_row(line: str) -> list[str]:
    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        raise HarnessError("Markdown table row must start and end with '|'")
    cells: list[str] = []
    current: list[str] = []
    body = stripped[1:-1]
    escaped = False
    code_delimiter = 0
    index = 0
    while index < len(body):
        character = body[index]
        if code_delimiter:
            if character == "`":
                end = index
                while end < len(body) and body[end] == "`":
                    end += 1
                run = end - index
                current.extend("`" * run)
                if run == code_delimiter:
                    code_delimiter = 0
                index = end
                continue
            current.append(character)
        elif escaped:
            if character == "|":
                current.append("|")
            else:
                current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "`":
            end = index
            while end < len(body) and body[end] == "`":
                end += 1
            code_delimiter = end - index
            current.extend("`" * code_delimiter)
            index = end
            continue
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
        index += 1
    if escaped:
        current.append("\\")
    if code_delimiter:
        raise HarnessError(
            f"unclosed Markdown code span with {code_delimiter} backtick(s)"
        )
    cells.append("".join(current).strip())
    return cells


def parse_legacy_table(paths: HarnessPaths, source: Path) -> list[dict[str, Any]]:
    text = source.read_text(encoding="utf-8")
    marker = "### Active Claims"
    start = text.find(marker)
    if start < 0:
        raise HarnessError(f"legacy table marker not found in {source}")
    all_lines = text.splitlines()
    start_line = text[:start].count("\n")
    rows: list[dict[str, Any]] = []
    reserving_tokens: dict[str, int] = {}
    malformed: list[str] = []
    in_table = False
    for line_index in range(start_line, len(all_lines)):
        line_number = line_index + 1
        line = all_lines[line_index]
        if not line.lstrip().startswith("|"):
            if in_table:
                break
            continue
        try:
            parts = split_markdown_row(line)
        except HarnessError as exc:
            malformed.append(f"line {line_number}: {exc}")
            continue
        if len(parts) != 9:
            malformed.append(
                f"line {line_number}: expected 9 cells, found {len(parts)}"
            )
            continue
        if parts[0].lower() == "token" or set(parts[0]) <= {"-"}:
            in_table = True
            continue
        in_table = True
        token, owner, kind, scope, intent, validation, started, expires, raw_status = parts
        if legacy_is_terminal(raw_status):
            continue
        if token in reserving_tokens:
            malformed.append(
                f"line {line_number}: duplicate non-terminal token {token!r}; "
                f"first seen on line {reserving_tokens[token]}"
            )
            continue
        reserving_tokens[token] = line_number
        decision = load_legacy_decision(paths, token)
        if decision and decision.get("decision") in {
            "adopted_structured",
            "released",
            "stale",
        }:
            continue
        locks, warnings = legacy_scope_locks(paths, scope)
        expired = is_expired(expires)
        row = {
                "schema_version": SCHEMA_VERSION,
                "legacy": True,
                "source": "legacy_control",
                "source_file": str(source),
                "source_line": line_number,
                "token": token,
                "owner": owner,
                "kind": kind,
                "raw_scope": scope,
                "intent": intent,
                "validation": validation,
                "started_at": started,
                "expires_at": expires,
                "raw_status": raw_status,
                "status": "blocked" if raw_status.lower().startswith("blocked") else "active",
                "legacy_classification": "expired_unverified" if expired else "active_unverified",
                "locks": locks,
                "scope_parse_warnings": warnings,
                "imported_at": now_iso(),
            }
        if decision and decision.get("decision") == "still-active":
            row["legacy_classification"] = "confirmed_active"
            row["audit_detail"] = decision.get("detail", "")
            row["audit_updated_at"] = decision.get("updated_at", "")
        rows.append(row)
    if malformed:
        preview = "; ".join(malformed[:8])
        suffix = f"; plus {len(malformed) - 8} more" if len(malformed) > 8 else ""
        raise HarnessError(
            f"legacy claim table contains malformed rows: {preview}{suffix}"
        )
    return rows


def legacy_pending_path(paths: HarnessPaths, token: str) -> Path:
    return paths.legacy_pending / f"{session_key(token)}.json"


def import_legacy(paths: HarnessPaths, source: Path) -> dict[str, Any]:
    rows = parse_legacy_table(paths, source)
    for existing_path in _claim_files(paths.legacy_pending):
        existing = load_claim_file(existing_path)
        if existing.get("legacy") and legacy_is_terminal(str(existing.get("raw_status", ""))):
            existing_path.unlink()
    for row in rows:
        atomic_write_json(legacy_pending_path(paths, row["token"]), row)
    return {
        "source": str(source),
        "pending_rows": len(rows),
        "expired_unverified": sum(
            1 for row in rows if row["legacy_classification"] == "expired_unverified"
        ),
        "ambiguous_scope_rows": sum(1 for row in rows if row["scope_parse_warnings"]),
    }


def adopt_legacy_if_present(paths: HarnessPaths, token: str, detail: str) -> None:
    pending = legacy_pending_path(paths, token)
    if pending.exists():
        record_legacy_decision(paths, token, "adopted_structured", detail)
        pending.unlink()


def task_summary(state: dict[str, Any]) -> dict[str, Any]:
    engaged_lanes = [
        {
            "lane_id": lane.get("lane_id"),
            "kind": lane.get("kind"),
            "status": lane.get("status"),
            "revision": lane.get("revision"),
            "next_action": lane.get("next_action"),
        }
        for lane in state.get("lanes", [])
        if lane.get("status") in {"active", "waiting", "recovering", "blocked"}
    ]
    engaged_lanes.sort(key=lambda item: str(item.get("lane_id", "")))
    return {
        "task_id": state["task_id"],
        "profile": state.get("profile", "full"),
        "title": state.get("title"),
        "status": state.get("status"),
        "phase": state.get("phase"),
        "revision": state.get("revision"),
        "checkpoint_revision": state.get("checkpoint_revision"),
        "checkpoint_required": state.get("checkpoint_required"),
        "checkpoint_sha256": state.get("checkpoint_sha256"),
        "plan_ready": state.get("plan_ready"),
        "plan_sha256": state.get("plan_sha256"),
        "outcome": state.get("outcome"),
        "worktree": state.get("worktree"),
        "branch": state.get("branch"),
        "head_sha": state.get("head_sha"),
        "updated_at": state.get("updated_at"),
        "next_action": state.get("next_action"),
        "claims": state.get("claims", []),
        "portfolio": {
            "engaged_lanes": engaged_lanes[:12],
            "engaged_lane_count": len(engaged_lanes),
            "coordination_inbox_count": sum(
                request.get("status") not in {"rejected", "resolved", "superseded"}
                for request in state.get("coordination_requests", [])
            ),
            "capacity_inbox_count": sum(
                review.get("status") not in {"rejected", "consumed", "superseded"}
                for review in state.get("capacity_reviews", [])
            ),
            "improvement_inbox_count": sum(
                request.get("status")
                not in {"rejected", "adopted", "rolled_back", "deprecated"}
                for request in state.get("improvement_requests", [])
            ),
            "open_cross_lane_session_count": sum(
                item.get("status") == "open"
                for item in state.get("cross_lane_sessions", [])
            ),
            "needs_user_count": sum(
                item.get("status") == "needs_user"
                for item in state.get("needs_user_escalations", [])
            ),
            "override_inbox_count": sum(
                item.get("status") in {"awaiting_chief", "approved"}
                for item in state.get("override_requests", [])
            ),
            "resource_config_event_count": len(
                state.get("resource_config_events", [])
            ),
            "open_subagent_incident_count": sum(
                item.get("status") == "open"
                for item in state.get("subagent_incidents", [])
            ),
            "execution_brief_count": len(state.get("execution_briefs", [])),
        },
        "packets": [
            {
                "packet_id": packet.get("packet_id"),
                "status": packet.get("status"),
                "agent_role": packet.get("agent_role"),
                "model_tier": packet.get("model_tier"),
                "routing_verified": packet.get("routing_verified"),
                "dispatch_provenance": packet.get("dispatch_provenance")
                or (
                    "legacy_unverified"
                    if packet.get("status") in {"dispatched", "done", "failed", "cancelled"}
                    else "none"
                ),
            }
            for packet in state.get("packets", [])
        ],
    }
