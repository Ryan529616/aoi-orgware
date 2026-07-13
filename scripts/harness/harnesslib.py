#!/usr/bin/env python3
"""Small, dependency-free state library for the ARISE Codex harness."""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Iterator


SCHEMA_VERSION = 1
TASK_STATUSES = {"active", "blocked", "done", "cancelled"}
TASK_PHASES = {
    "planning",
    "gathering",
    "diagnosing",
    "implementing",
    "waiting_eda",
    "verifying",
    "reviewing",
    "closing",
}
CLAIM_STATUSES = {"active", "blocked", "done", "released", "stale"}
RESERVING_CLAIM_STATUSES = {"active", "blocked"}
TERMINAL_CLAIM_STATUSES = {"done", "released", "stale"}
JOB_STATUSES = {"queued", "running", "pass", "fail", "stopped", "unknown"}
ACTIVE_JOB_STATUSES = {"queued", "running", "unknown"}
PACKET_STATUSES = {"ready", "dispatched", "done", "failed", "cancelled"}
ACTIVE_PACKET_STATUSES = {"ready", "dispatched"}
VERIFICATION_STATUSES = {"pending", "pass", "fail", "blocked", "skipped"}
ACCOUNTED_VERIFICATION_STATUSES = VERIFICATION_STATUSES - {"pending"}
DELIVERY_MODES = {"pending", "pushed", "local-only", "blocked", "none"}
CHECKPOINT_MAX_BYTES = 12 * 1024
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


class HarnessError(RuntimeError):
    """Expected user-facing harness failure."""


@dataclass(frozen=True)
class HarnessPaths:
    root: Path
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


def get_paths(root: Path | None = None) -> HarnessPaths:
    if root is None:
        configured = os.environ.get("ARISE_HARNESS_ROOT")
        root = Path(configured) if configured else Path(__file__).resolve().parents[2]
    root = root.resolve()
    harness = root / "notes" / "harness"
    claims = harness / "claims"
    return HarnessPaths(
        root=root,
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
    )


def ensure_layout(paths: HarnessPaths) -> None:
    for directory in (
        paths.harness,
        paths.tasks,
        paths.claims_active,
        paths.claims_archive,
        paths.legacy_pending,
        paths.legacy_decisions,
        paths.sessions,
        paths.templates,
    ):
        directory.mkdir(parents=True, exist_ok=True)


@contextlib.contextmanager
def state_lock(paths: HarnessPaths) -> Iterator[None]:
    ensure_layout(paths)
    with paths.lock.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def validate_id(value: str, label: str = "identifier") -> str:
    if not ID_RE.fullmatch(value):
        raise HarnessError(
            f"invalid {label}: {value!r}; use 1-128 ASCII letters, digits, dot, dash, or underscore"
        )
    return value


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
            handle.write(payload)
            temp_name = handle.name
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        temp_name = ""
        fsync_directory(path.parent)
    finally:
        if temp_name:
            with contextlib.suppress(FileNotFoundError):
                Path(temp_name).unlink()


def fsync_directory(path: Path) -> None:
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
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HarnessError(f"missing state file: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
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
    return state


def validate_task_state(state: dict[str, Any], source: Path | None = None) -> None:
    where = f" in {source}" if source else ""
    if state.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError(f"unsupported task schema{where}")
    validate_id(str(state.get("task_id", "")), "task id")
    if state.get("status") not in TASK_STATUSES:
        raise HarnessError(f"invalid task status{where}: {state.get('status')!r}")
    if state.get("phase") not in TASK_PHASES:
        raise HarnessError(f"invalid task phase{where}: {state.get('phase')!r}")
    if state.get("profile", "full") not in {"full", "mini"}:
        raise HarnessError(f"invalid task profile{where}: {state.get('profile')!r}")
    revision = state.get("revision")
    checkpoint_revision = state.get("checkpoint_revision")
    if not isinstance(revision, int) or revision < 1:
        raise HarnessError(f"invalid task revision{where}")
    if not isinstance(checkpoint_revision, int) or checkpoint_revision < 0:
        raise HarnessError(f"invalid checkpoint revision{where}")
    if checkpoint_revision > revision:
        raise HarnessError(f"checkpoint revision exceeds task revision{where}")


def bump_task(state: dict[str, Any], checkpoint_required: bool = True) -> None:
    state["revision"] = int(state.get("revision", 0)) + 1
    state["updated_at"] = now_iso()
    if checkpoint_required:
        state["checkpoint_required"] = True


def write_task(paths: HarnessPaths, state: dict[str, Any]) -> None:
    validate_task_state(state)
    atomic_write_json(task_state_path(paths, state["task_id"]), state)


def _normalize_repo_path(raw: str) -> str:
    if "\\" in raw:
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
    return normalized.rstrip("/")


def _normalize_eda_path(raw: str) -> str:
    if "\\" in raw:
        raise HarnessError(f"EDA lock must use POSIX separators: {raw!r}")
    path = PurePosixPath(raw)
    if any(marker in raw for marker in ("*", "?", "[", "]", "{", "}")):
        raise HarnessError(f"structured EDA locks may not contain glob syntax: {raw!r}")
    if not path.is_absolute():
        raise HarnessError(f"EDA lock path must be absolute: {raw!r}")
    if ".." in path.parts:
        raise HarnessError(f"EDA lock path may not contain '..': {raw!r}")
    return path.as_posix().rstrip("/") or "/"


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
    path = PureWindowsPath(raw)
    if not path.drive or not path.root or len(path.drive) != 2:
        raise HarnessError(f"host lock path must be drive-absolute: {raw!r}")
    drive = path.drive[0].upper()
    parts = [part.casefold() for part in raw_parts if part]
    suffix = "/".join(parts)
    return f"{drive}:/{suffix}" if suffix else f"{drive}:/"


def host_path_to_wsl(raw: str) -> Path:
    canonical = _normalize_host_path(raw)
    drive = canonical[0].lower()
    suffix = canonical[3:]
    mount_root = Path(os.environ.get("ARISE_HARNESS_HOST_MOUNT_ROOT", "/mnt"))
    return mount_root / drive / suffix


def normalize_lock(lock: str) -> str:
    parts = lock.strip().split(":", 2)
    if len(parts) == 3 and parts[0] in {"repo", "eda", "host"}:
        namespace, kind, raw_path = parts
        if kind not in {"file", "tree"}:
            raise HarnessError(f"invalid lock kind in {lock!r}")
        normalized = (
            _normalize_repo_path(raw_path)
            if namespace == "repo"
            else _normalize_eda_path(raw_path)
            if namespace == "eda"
            else _normalize_host_path(raw_path)
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
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def baselines_for_locks(
    paths: HarnessPaths, locks: Iterable[str], repo_root: Path | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    baseline_root = (repo_root or paths.root).resolve()
    for lock in locks:
        namespace, kind, raw_path = parse_lock(lock)
        if kind != "file" or namespace not in {"repo", "host"}:
            continue
        candidate = (
            baseline_root / raw_path
            if namespace == "repo"
            else host_path_to_wsl(raw_path)
        )
        if namespace == "host" and candidate.is_symlink():
            raise HarnessError(f"host file lock may not target a symlink: {raw_path}")
        if candidate.exists() and not stat.S_ISREG(candidate.stat().st_mode):
            raise HarnessError(f"file lock target is not a regular file: {candidate}")
        if candidate.is_file():
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
    if claim.get("schema_version") != SCHEMA_VERSION:
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


def reserving_claims(paths: HarnessPaths) -> Iterator[dict[str, Any]]:
    for path in _claim_files(paths.claims_active):
        claim = load_claim_file(path)
        if claim.get("status") in RESERVING_CLAIM_STATUSES:
            claim["_path"] = str(path)
            yield claim
    for path in _claim_files(paths.legacy_pending):
        claim = load_claim_file(path)
        if claim.get("status") in RESERVING_CLAIM_STATUSES:
            claim["_path"] = str(path)
            yield claim


def find_conflicts(
    paths: HarnessPaths, locks: Iterable[str], ignore_token: str | None = None
) -> list[dict[str, str]]:
    requested = [normalize_lock(item) for item in locks]
    conflicts: list[dict[str, str]] = []
    for existing in reserving_claims(paths):
        if ignore_token and existing.get("token") == ignore_token:
            continue
        for proposed in requested:
            for held in existing.get("locks", []):
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


def claims_for_task(paths: HarnessPaths, state: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for token in state.get("claims", []):
        active_path = claim_path(paths, token, active=True)
        archive_path = claim_path(paths, token, active=False)
        if active_path.exists():
            result.append(load_claim_file(active_path))
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
                claim["_path"] = str(path)
                result.append(claim)
    return result


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
    try:
        display = result_path.relative_to(
            task_dir(paths, state["task_id"])
        ).as_posix()
    except ValueError:
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
    control_plane_lines = [
        f"Steward inbox: coordination={active_coordination}, capacity={active_capacity}, "
        f"improvement={active_improvements}, cross_lane={active_cross_sessions}; "
        f"needs_user={needs_user}; complete records are in state.json"
    ]

    blockers_and_risks = [
        *(f"BLOCKER: {item}" for item in state.get("blockers", [])),
        *(f"RISK: {item}" for item in state.get("risks", [])),
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
    if len(text.encode("utf-8")) > CHECKPOINT_MAX_BYTES:
        text = render_checkpoint(paths, state, compact_terminal_detail=True)
    if len(text.encode("utf-8")) > CHECKPOINT_MAX_BYTES:
        raise HarnessError(
            "checkpoint exceeds 12 KiB; summarize facts/evidence and keep raw logs outside state"
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
        "# ARISE Harness Index",
        "",
        f"Generated: `{now_iso()}`",
        "",
        "Start with `AGENTS.md` and `notes/harness/POLICY.md`; do not scan the full "
        "legacy ledger unless a warning below points to a specific token.",
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

    lines.extend(["", "## Legacy quarantine", ""])
    lines.append(
        f"- Pending non-terminal legacy rows: **{len(legacy)}**; expired but unaudited: "
        f"**{sum(1 for item in legacy if item.get('legacy_classification') == 'expired_unverified')}**."
    )
    ambiguous = sum(1 for item in legacy if item.get("scope_parse_warnings"))
    lines.append(f"- Rows with ambiguous/unparsed scope text: **{ambiguous}**.")
    if legacy:
        lines.append("- Inspect with `python3 scripts/harness/arise_harness.py status --legacy`.")

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
            "python3 scripts/harness/arise_harness.py status",
            "python3 scripts/harness/arise_harness.py doctor",
            "python3 scripts/harness/arise_harness.py resume --task <task-id>",
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
    "constraints",
    "rtl",
    "rtl_canonical",
    "rtl_shadow_fullmodel",
    "tb",
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
    if raw == "notes/SESSION_CONTROL.md":
        return None
    if raw.startswith("eda:/"):
        raw = raw.removeprefix("eda:")
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
        raw = "/" if candidate.strip().startswith(("/", "eda:/", "~/")) else "."
    # The historical table intentionally let every owner append its own row to
    # the shared coordination ledger. Treating that shared bookkeeping file as
    # an exclusive technical lock would make every legacy claim conflict with
    # every other one and would prevent migration itself.
    if raw.startswith("/"):
        kind = "tree" if had_glob or not PurePosixPath(raw).suffix else "file"
        try:
            return normalize_lock(f"eda:{kind}:{raw}")
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
    if not raw or raw == "notes/SESSION_CONTROL.md":
        return False
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?ns(?:/[0-9]+(?:\.[0-9]+)?ns)*", raw):
        return False
    first = raw.removeprefix("eda:").removeprefix("~/").split("/", 1)[0]
    return (
        raw.startswith(("/", "~/", "./", "../", "eda:/", "."))
        or first in LEGACY_REPO_ROOTS
        or any(marker in raw for marker in ("*", "?", "[", "]", "{", "}"))
        or "/" in raw
    )


def legacy_scope_locks(paths: HarnessPaths, scope: str) -> tuple[list[str], list[str]]:
    candidates = extract_markdown_code_spans(scope)
    locks: list[str] = []
    warnings: list[str] = []
    for candidate in candidates:
        if candidate.strip().strip(".,;:") == "notes/SESSION_CONTROL.md":
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
                "source": "legacy_session_control",
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
        },
        "packets": [
            {
                "packet_id": packet.get("packet_id"),
                "status": packet.get("status"),
                "agent_role": packet.get("agent_role"),
                "model_tier": packet.get("model_tier"),
                "routing_verified": packet.get("routing_verified"),
            }
            for packet in state.get("packets", [])
        ],
    }
