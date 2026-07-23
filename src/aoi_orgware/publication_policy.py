"""Standalone, content-addressed publication-policy snapshots.

This module deliberately receives a root, policy object, and config digest from
its caller.  It never discovers ``aoi.toml`` or AOI state: a persisted snapshot
is the complete policy authority used by :mod:`publication_gate`.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Any, Mapping, NoReturn


SCHEMA_VERSION = 1
MAX_RULES = 256
MAX_CONTENT = 20_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_PROTECTED_TOTAL_BYTES = 512 * 1024 * 1024
MAX_PROTECTED_TREE_ENTRIES = 40_000
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REPARSE_POINT = 0x0400
_WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)


class PublicationPolicyError(ValueError):
    """A publication-policy snapshot or protected origin is unsafe."""


def _fail(message: str) -> NoReturn:
    raise PublicationPolicyError(message)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_link_like(path: Path, metadata: os.stat_result | None = None) -> bool:
    try:
        observed = metadata if metadata is not None else path.lstat()
    except OSError as exc:
        _fail(f"cannot inspect {path}: {exc}")
    return stat.S_ISLNK(observed.st_mode) or bool(
        getattr(observed, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _absolute_path(value: Path | str, label: str) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _fail(f"{label} is invalid")
    return Path(os.path.abspath(raw))


def _validate_chain(path: Path, label: str) -> None:
    anchor = Path(path.anchor)
    if not anchor:
        _fail(f"{label} is not absolute")
    current = anchor
    try:
        if _is_link_like(current):
            _fail(f"{label} traverses a symlink, junction, or reparse point")
    except FileNotFoundError:
        pass
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            _fail(f"cannot inspect {label}: {exc}")
        if _is_link_like(current, metadata):
            _fail(f"{label} traverses a symlink, junction, or reparse point")


def _directory(path: Path, label: str) -> os.stat_result:
    _validate_chain(path, label)
    try:
        metadata = path.lstat()
    except OSError as exc:
        _fail(f"cannot inspect {label}: {exc}")
    if _is_link_like(path, metadata) or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be a directory without links or reparse points")
    return metadata


def _regular_file(path: Path, label: str) -> os.stat_result:
    _validate_chain(path, label)
    try:
        metadata = path.lstat()
    except OSError as exc:
        _fail(f"cannot inspect {label}: {exc}")
    if _is_link_like(path, metadata) or not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be a regular non-link file")
    if metadata.st_nlink != 1:
        _fail(f"{label} must not be hard linked")
    if metadata.st_size > MAX_FILE_BYTES:
        _fail(f"{label} exceeds the protected-origin byte bound")
    return metadata


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_nlink == right.st_nlink
    )


def _stable_file_identity(path: Path, label: str) -> tuple[str, int]:
    before = _regular_file(path, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not _same_identity(before, opened):
                _fail(f"{label} changed while opening")
            digest = hashlib.sha256()
            read_count = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                read_count += len(chunk)
                if read_count > MAX_FILE_BYTES:
                    _fail(f"{label} exceeds the protected-origin byte bound")
                digest.update(chunk)
            finished = os.fstat(handle.fileno())
    except PublicationPolicyError:
        raise
    except OSError as exc:
        _fail(f"cannot read {label}: {exc}")
    after = _regular_file(path, label)
    if (
        not _same_identity(before, opened)
        or not _same_identity(before, finished)
        or not _same_identity(before, after)
        or read_count != before.st_size
    ):
        _fail(f"{label} changed while being read")
    return digest.hexdigest(), read_count


def _stable_snapshot_bytes(path: Path) -> bytes:
    """Read one bounded snapshot through the same identity-pinned pattern."""

    before = _regular_file(path, "policy snapshot")
    if before.st_size == 0 or before.st_size > MAX_SNAPSHOT_BYTES:
        _fail("policy snapshot has an invalid size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not _same_identity(before, opened):
                _fail("policy snapshot changed while opening")
            raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
            finished = os.fstat(handle.fileno())
    except PublicationPolicyError:
        raise
    except OSError as exc:
        _fail(f"cannot read policy snapshot: {exc}")
    after = _regular_file(path, "policy snapshot")
    if (
        len(raw) != before.st_size
        or not _same_identity(before, opened)
        or not _same_identity(before, finished)
        or not _same_identity(before, after)
    ):
        _fail("policy snapshot changed while being read")
    return raw


def _safe_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        _fail(f"{label} must be a canonical project-relative POSIX path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or not posix.parts
        or str(posix) != value
    ):
        _fail(f"{label} must be a canonical project-relative POSIX path")
    for part in posix.parts:
        folded = part.casefold()
        stem = folded.split(".", 1)[0]
        if (
            folded in {".", "..", ".git"}
            or stem in _WINDOWS_RESERVED
            or part.endswith((" ", "."))
            or any(character in _WINDOWS_FORBIDDEN for character in part)
            or any(ord(character) < 32 for character in part)
        ):
            _fail(f"{label} must be a canonical project-relative POSIX path")
    return value


def _covers(rule_path: str, kind: str, candidate: str) -> bool:
    if kind == "file":
        return candidate.casefold() == rule_path.casefold()
    prefix = rule_path.casefold() + "/"
    return candidate.casefold().startswith(prefix)


def _normalise_rules(value: Any, *, mode: str) -> list[dict[str, Any]]:
    if mode not in {"standard", "local_files"}:
        _fail("publication policy mode is invalid")
    if not isinstance(value, (list, tuple)) or len(value) > MAX_RULES:
        _fail("protected rules are invalid")
    rows: list[dict[str, Any]] = []
    for index, rule in enumerate(value):
        if isinstance(rule, Mapping):
            raw = rule
        else:
            raw = {
                "path": getattr(rule, "path", None),
                "kind": getattr(rule, "kind", None),
                "policy": getattr(rule, "policy", None),
                "home_remote": getattr(rule, "home_remote", None),
                "home_destination": getattr(rule, "home_destination", None),
            }
        if set(raw) != {"path", "kind", "policy", "home_remote", "home_destination"}:
            _fail(f"protected rule {index} schema is invalid")
        path = _safe_path(raw["path"], f"protected rule {index} path")
        kind = raw["kind"]
        policy = raw["policy"]
        remote = raw["home_remote"]
        destination = raw["home_destination"]
        if kind not in {"file", "tree"} or policy not in {"local_only", "home_remote_only"}:
            _fail(f"protected rule {index} policy is invalid")
        if policy == "home_remote_only":
            if not isinstance(remote, str) or _REMOTE.fullmatch(remote) is None:
                _fail(f"protected rule {index} home remote is invalid")
            if (
                not isinstance(destination, str)
                or not destination
                or destination != destination.strip()
                or len(destination) > 2048
                or any(ord(char) < 32 for char in destination)
            ):
                _fail(f"protected rule {index} home destination is invalid")
        elif remote is not None or destination is not None:
            _fail(f"protected rule {index} local_only home binding is invalid")
        rows.append(
            {
                "path": path,
                "kind": kind,
                "policy": policy,
                "home_remote": remote,
                "home_destination": destination,
            }
        )
    if mode == "standard" and rows:
        _fail("standard publication policy may not contain protected rules")
    rows.sort(key=lambda row: (row["path"].casefold(), row["path"]))
    for previous, current in zip(rows, rows[1:]):
        if _covers(previous["path"], previous["kind"], current["path"]) or _covers(
            current["path"], current["kind"], previous["path"]
        ):
            _fail("protected rules overlap or duplicate")
    return rows


def _walk_protected_tree(root: Path, rule_path: str) -> list[Path]:
    origin = root.joinpath(*PurePosixPath(rule_path).parts)
    _directory(origin, f"protected origin {rule_path}")
    pending = [origin]
    files: list[Path] = []
    entry_count = 0
    while pending:
        current = pending.pop()
        _directory(current, f"protected origin {rule_path}")
        try:
            with os.scandir(current) as scanner:
                entries = []
                for entry in scanner:
                    entry_count += 1
                    if entry_count > MAX_PROTECTED_TREE_ENTRIES:
                        _fail(
                            f"protected origin {rule_path} exceeds its entry-count bound"
                        )
                    entries.append(entry)
            entries.sort(key=lambda entry: (entry.name.casefold(), entry.name))
        except OSError as exc:
            _fail(f"cannot scan protected origin {rule_path}: {exc}")
        folded: set[str] = set()
        for entry in entries:
            if entry.name.casefold() in folded:
                _fail(f"protected origin {rule_path} has case-colliding entries")
            folded.add(entry.name.casefold())
            candidate = Path(entry.path)
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                _fail(f"cannot inspect protected origin {rule_path}: {exc}")
            if _is_link_like(candidate, metadata):
                _fail(f"protected origin {rule_path} contains a link or reparse point")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(candidate)
            elif stat.S_ISREG(metadata.st_mode):
                if len(files) >= MAX_CONTENT:
                    _fail("protected content exceeds its entry-count bound")
                files.append(candidate)
            else:
                _fail(f"protected origin {rule_path} contains a special entry")
    return sorted(files, key=lambda item: (str(item).casefold(), str(item)))


def protected_content_identities(root: Path | str, rules: Any) -> list[dict[str, Any]]:
    """Read exact protected origins and return stable content identities."""

    checked_root = _absolute_path(root, "project root")
    _directory(checked_root, "project root")
    # This helper deliberately accepts the normalized rule rows from a snapshot.
    checked_rules = _normalise_rules(rules, mode="local_files")
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    for rule in checked_rules:
        rule_path = rule["path"]
        origin = checked_root.joinpath(*PurePosixPath(rule_path).parts)
        files = (
            [origin]
            if rule["kind"] == "file"
            else _walk_protected_tree(checked_root, rule_path)
        )
        for file_path in files:
            if len(rows) >= MAX_CONTENT:
                _fail("protected content exceeds its entry-count bound")
            metadata = _regular_file(file_path, f"protected origin {rule_path}")
            if total_bytes + metadata.st_size > MAX_PROTECTED_TOTAL_BYTES:
                _fail("protected content exceeds its total-byte bound")
            digest, size = _stable_file_identity(file_path, f"protected origin {rule_path}")
            total_bytes += size
            if total_bytes > MAX_PROTECTED_TOTAL_BYTES:
                _fail("protected content exceeds its total-byte bound")
            try:
                actual = file_path.relative_to(checked_root).as_posix()
            except ValueError:
                _fail("protected origin escapes project root")
            actual = _safe_path(actual, "protected content path")
            if not _covers(rule_path, rule["kind"], actual):
                _fail("protected content does not match its rule")
            rows.append(
                {"rule_path": rule_path, "path": actual, "sha256": digest, "size_bytes": size}
            )
    rows.sort(key=lambda row: (row["rule_path"].casefold(), row["rule_path"], row["path"].casefold(), row["path"]))
    if len(rows) > MAX_CONTENT:
        _fail("protected content exceeds its entry-count bound")
    return rows


def build_publication_policy_snapshot(
    root: Path | str, policy: Any, source_config_sha256: str
) -> dict[str, Any]:
    """Capture an immutable snapshot from an explicit live root/policy/config SHA."""

    if not isinstance(source_config_sha256, str) or _SHA256.fullmatch(source_config_sha256) is None:
        _fail("source config SHA-256 is invalid")
    mode = getattr(policy, "mode", None)
    if not isinstance(mode, str):
        _fail("publication policy mode is invalid")
    rules = _normalise_rules(getattr(policy, "protected", None), mode=mode)
    content = protected_content_identities(root, rules)
    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_config_sha256": source_config_sha256,
        "mode": mode,
        "protected_rules": rules,
        "protected_rule_count": len(rules),
        "protected_policy_sha256": hashlib.sha256(_canonical_bytes({"protected_rules": rules})).hexdigest(),
        "protected_content": content,
        "protected_content_count": len(content),
    }
    snapshot = {**base, "snapshot_sha256": _digest(base)}
    return validate_publication_policy_snapshot(snapshot)


def require_current_publication_policy_snapshot(
    root: Path | str,
    policy: Any,
    source_config_sha256: str,
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Require a persisted snapshot to match the live local policy and bytes.

    This is the local-authority check.  A remote clean checkout intentionally
    cannot repeat it when a protected origin is local-only or untracked; the
    standalone publication gate instead consumes the immutable snapshot.
    """

    observed = validate_publication_policy_snapshot(snapshot)
    expected = build_publication_policy_snapshot(root, policy, source_config_sha256)
    if observed != expected:
        _fail("publication policy snapshot is stale relative to the live local policy")
    return expected


def validate_publication_policy_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Validate exact snapshot schema, normalization, counts, and self-digest."""

    expected = {
        "schema_version", "source_config_sha256", "mode", "protected_rules",
        "protected_rule_count", "protected_policy_sha256", "protected_content",
        "protected_content_count", "snapshot_sha256",
    }
    if not isinstance(snapshot, Mapping) or set(snapshot) != expected:
        _fail("publication policy snapshot schema is invalid")
    if (
        type(snapshot.get("schema_version")) is not int
        or snapshot.get("schema_version") != SCHEMA_VERSION
    ):
        _fail("publication policy snapshot version is invalid")
    source_sha = snapshot.get("source_config_sha256")
    if not isinstance(source_sha, str) or _SHA256.fullmatch(source_sha) is None:
        _fail("publication policy snapshot source config SHA-256 is invalid")
    mode = snapshot.get("mode")
    if not isinstance(mode, str):
        _fail("publication policy snapshot mode is invalid")
    rules = _normalise_rules(snapshot.get("protected_rules"), mode=mode)
    rule_count = snapshot.get("protected_rule_count")
    if (
        snapshot.get("protected_rules") != rules
        or type(rule_count) is not int
        or rule_count != len(rules)
    ):
        _fail("publication policy snapshot protected rules are not normalized")
    policy_sha = hashlib.sha256(_canonical_bytes({"protected_rules": rules})).hexdigest()
    if snapshot.get("protected_policy_sha256") != policy_sha:
        _fail("publication policy snapshot protected policy digest is invalid")
    content = snapshot.get("protected_content")
    if not isinstance(content, list):
        _fail("publication policy snapshot protected content is invalid")
    content_count = snapshot.get("protected_content_count")
    if (
        len(content) > MAX_CONTENT
        or type(content_count) is not int
        or content_count != len(content)
    ):
        _fail("publication policy snapshot protected content count is invalid")
    by_path = {row["path"]: row for row in rules}
    normalized_content: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    total_bytes = 0
    for index, row in enumerate(content):
        if not isinstance(row, Mapping) or set(row) != {"rule_path", "path", "sha256", "size_bytes"}:
            _fail(f"publication policy snapshot content {index} schema is invalid")
        rule_path = _safe_path(row.get("rule_path"), f"snapshot content {index} rule path")
        actual = _safe_path(row.get("path"), f"snapshot content {index} path")
        digest = row.get("sha256")
        size = row.get("size_bytes")
        rule = by_path.get(rule_path)
        if rule is None or not _covers(rule_path, rule["kind"], actual):
            _fail(f"publication policy snapshot content {index} does not match a rule")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None or type(size) is not int or size < 0 or size > MAX_FILE_BYTES:
            _fail(f"publication policy snapshot content {index} identity is invalid")
        total_bytes += size
        if total_bytes > MAX_PROTECTED_TOTAL_BYTES:
            _fail("publication policy snapshot protected content exceeds its total-byte bound")
        key = (rule_path.casefold(), actual.casefold())
        if key in seen:
            _fail("publication policy snapshot has duplicate protected content")
        seen.add(key)
        normalized_content.append({"rule_path": rule_path, "path": actual, "sha256": digest, "size_bytes": size})
    normalized_content.sort(key=lambda row: (row["rule_path"].casefold(), row["rule_path"], row["path"].casefold(), row["path"]))
    if content != normalized_content:
        _fail("publication policy snapshot protected content is not normalized")
    base = {key: snapshot[key] for key in expected - {"snapshot_sha256"}}
    digest = snapshot.get("snapshot_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None or digest != _digest(base):
        _fail("publication policy snapshot self-digest is invalid")
    return dict(snapshot)


def load_publication_policy_snapshot(path: Path | str) -> dict[str, Any]:
    """Safely read one canonical standalone JSON snapshot file."""

    source = _absolute_path(path, "policy snapshot")
    raw = _stable_snapshot_bytes(source)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"policy snapshot is not strict JSON: {exc}")
    checked = validate_publication_policy_snapshot(decoded)
    if raw != canonical_publication_policy_snapshot_bytes(checked):
        _fail("policy snapshot is not canonical JSON")
    return checked


def canonical_publication_policy_snapshot_bytes(
    snapshot: Mapping[str, Any],
) -> bytes:
    """Return the sole tracked-file encoding for a validated snapshot."""

    return _canonical_bytes(validate_publication_policy_snapshot(snapshot)) + b"\n"


__all__ = [
    "PublicationPolicyError",
    "SCHEMA_VERSION",
    "build_publication_policy_snapshot",
    "canonical_publication_policy_snapshot_bytes",
    "load_publication_policy_snapshot",
    "protected_content_identities",
    "require_current_publication_policy_snapshot",
    "validate_publication_policy_snapshot",
]
