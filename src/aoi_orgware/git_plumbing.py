"""Git worktree metadata, ancestry, and legacy-claim scope checks.

The CLI stays the composition root and remains the canonical source for
``require_full_commit``/``require_text`` (see :mod:`aoi_orgware.state_lookup`);
this module keeps small private duplicates of those two pure helpers so its
own git-facing functions are self-contained without importing the CLI. This
module imports only sibling packages (:mod:`aoi_orgware.harnesslib`) and
never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    RESERVING_CLAIM_STATUSES,
    lock_covers,
    load_claim_file,
    normalize_lock,
    validated_state_worktree,
)


COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
MAX_GIT_STATUS_BYTES = 4 * 1024 * 1024
MAX_GIT_STATUS_RECORDS = 10_000
MAX_GIT_STATUS_PATH_BYTES = 16 * 1024
MAX_GIT_COMMAND_BYTES = 4 * 1024 * 1024
MAX_GIT_COMMAND_STDERR_BYTES = 64 * 1024
_GIT_MODE_RE = re.compile(rb"^[0-7]{6}$")
_GIT_OID_RE = re.compile(rb"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GIT_SCORE_RE = re.compile(rb"^[RC](?:[0-9]{1,2}|100)$")
_GIT_XY_CHARS = frozenset(b".MTADRCU")
_GIT_SUBMODULE_RE = re.compile(rb"^(?:N\.\.\.|S[.C][.M][.U])$")
GIT_STATUS_SNAPSHOT_SCHEMA = "aoi.git-status-porcelain-v2.snapshot.v1"
GIT_MUTATION_SNAPSHOT_SCHEMA = "aoi.git-mutation-snapshot.v2"
GIT_TASK_CLAIM_SCOPE_SCHEMA = "aoi.git-task-live-claim-scope.v1"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _require_task_id(value: object) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise HarnessError("task_id must be non-empty text without surrounding whitespace")
    return value


def _git_environment() -> dict[str, str]:
    """Disable Git's optional locks; a snapshot is strictly read-only."""

    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _run_git_bytes_bounded(
    worktree: Path,
    arguments: Iterable[str],
    *,
    label: str,
    timeout: float = 10,
    stdout_limit: int | None = None,
) -> bytes:
    """Run Git while enforcing output limits as bytes arrive, not afterwards.

    ``communicate``/``capture_output`` retain the complete child output before a
    caller can apply a limit.  Two small reader threads instead drain both pipes
    concurrently, retain only bounded prefixes, and terminate the child as soon
    as either stream crosses its cap.  This also avoids a stderr-pipe deadlock.
    """

    command = ["git", "-C", str(worktree), *arguments]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:
        raise HarnessError(f"{label} command failed: {exc}") from exc
    assert process.stdout is not None
    assert process.stderr is not None
    output_limit = MAX_GIT_COMMAND_BYTES if stdout_limit is None else stdout_limit
    if output_limit < 0:
        raise HarnessError(f"{label} output limit may not be negative")
    outputs: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = threading.Event()

    def drain(stream: Any, name: str, limit: int) -> None:
        while True:
            chunk = stream.read(min(64 * 1024, limit + 1))
            if not chunk:
                return
            destination = outputs[name]
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                exceeded.set()
                try:
                    process.kill()
                except OSError:
                    pass
                # Continue draining until EOF so the child cannot block on its
                # other pipe while it exits.

    readers = [
        threading.Thread(target=drain, args=(process.stdout, "stdout", output_limit)),
        threading.Thread(target=drain, args=(process.stderr, "stderr", MAX_GIT_COMMAND_STDERR_BYTES)),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        returncode = process.wait()
        for reader in readers:
            reader.join()
        process.stdout.close()
        process.stderr.close()
        raise HarnessError(f"{label} command timed out") from exc
    for reader in readers:
        reader.join()
    process.stdout.close()
    process.stderr.close()
    if exceeded.is_set():
        raise HarnessError(f"{label} command output exceeds the configured byte bound")
    if returncode != 0:
        detail = bytes(outputs["stderr"] or outputs["stdout"]).decode("utf-8", "replace").strip()
        raise HarnessError(f"{label} command failed: {detail or 'unknown error'}")
    return bytes(outputs["stdout"])


def _unb64(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise HarnessError(f"{label} must be a base64 string")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise HarnessError(f"{label} is not valid base64") from exc
    if _b64(result) != value:
        raise HarnessError(f"{label} must use canonical base64")
    return result


def _require_git_path(raw: bytes, label: str) -> bytes:
    if not raw or len(raw) > MAX_GIT_STATUS_PATH_BYTES:
        raise HarnessError(f"{label} is empty or exceeds the configured path bound")
    if raw.startswith(b"/") or b"\x00" in raw or b"\\" in raw:
        raise HarnessError(f"{label} is not a relative POSIX Git path")
    if any(component in {b"", b".", b".."} for component in raw.split(b"/")):
        raise HarnessError(f"{label} is not a canonical Git path")
    return raw


def _split_status_fields(raw: bytes, fields_before_path: int, label: str) -> list[bytes]:
    fields = raw.split(b" ", fields_before_path)
    if len(fields) != fields_before_path + 1 or not fields[-1]:
        raise HarnessError(f"malformed Git porcelain v2 {label} record")
    return fields


def _validate_xy_submodule(xy: bytes, submodule: bytes, label: str) -> None:
    if len(xy) != 2 or any(value not in _GIT_XY_CHARS for value in xy):
        raise HarnessError(f"malformed Git porcelain v2 {label} XY field")
    if not _GIT_SUBMODULE_RE.fullmatch(submodule):
        raise HarnessError(f"malformed Git porcelain v2 {label} submodule field")


def _validate_modes_oids(modes: Iterable[bytes], oids: Iterable[bytes], label: str) -> None:
    if not all(_GIT_MODE_RE.fullmatch(mode) for mode in modes):
        raise HarnessError(f"malformed Git porcelain v2 {label} mode")
    if not all(_GIT_OID_RE.fullmatch(oid) for oid in oids):
        raise HarnessError(f"malformed Git porcelain v2 {label} object id")


def _parse_git_status_porcelain_v2(raw: bytes) -> list[dict[str, Any]]:
    """Parse the exact NUL-delimited payload produced by status porcelain v2.

    Paths stay opaque bytes and are represented as canonical base64 only at the
    public boundary.  This prevents Unicode decoding, quote handling, or host
    filesystem normalization from changing Git's path identity.
    """

    if len(raw) > MAX_GIT_STATUS_BYTES:
        raise HarnessError("Git status output exceeds the configured byte bound")
    if raw and not raw.endswith(b"\x00"):
        raise HarnessError("malformed Git porcelain v2 output is not NUL terminated")
    tokens = raw[:-1].split(b"\x00") if raw else []
    records: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            raise HarnessError("malformed Git porcelain v2 output contains an empty record")
        prefix = token[:2]
        if prefix == b"1 ":
            fields = _split_status_fields(token, 8, "1")
            _, xy, submodule, *tail = fields
            modes, oids, path = tail[:3], tail[3:5], tail[5]
            _validate_xy_submodule(xy, submodule, "1")
            _validate_modes_oids(modes, oids, "1")
            records.append(
                {
                    "record": "1",
                    "xy": xy.decode("ascii"),
                    "submodule": submodule.decode("ascii"),
                    "modes": [item.decode("ascii") for item in modes],
                    "oids": [item.decode("ascii") for item in oids],
                    "path_b64": _b64(_require_git_path(path, "Git status path")),
                }
            )
        elif prefix == b"2 ":
            if index + 1 >= len(tokens):
                raise HarnessError("malformed Git porcelain v2 rename/copy record")
            fields = _split_status_fields(token, 9, "2")
            _, xy, submodule, *tail = fields
            modes, oids, score, destination = tail[:3], tail[3:5], tail[5], tail[6]
            source = tokens[index + 1]
            _validate_xy_submodule(xy, submodule, "2")
            _validate_modes_oids(modes, oids, "2")
            if not _GIT_SCORE_RE.fullmatch(score):
                raise HarnessError("malformed Git porcelain v2 rename/copy score")
            records.append(
                {
                    "record": "2",
                    "xy": xy.decode("ascii"),
                    "submodule": submodule.decode("ascii"),
                    "modes": [item.decode("ascii") for item in modes],
                    "oids": [item.decode("ascii") for item in oids],
                    "score": score.decode("ascii"),
                    "path_b64": _b64(_require_git_path(destination, "Git rename/copy destination")),
                    "source_path_b64": _b64(_require_git_path(source, "Git rename/copy source")),
                }
            )
            index += 1
        elif prefix == b"u ":
            fields = _split_status_fields(token, 10, "u")
            _, xy, submodule, *tail = fields
            modes, oids, path = tail[:4], tail[4:7], tail[7]
            _validate_xy_submodule(xy, submodule, "u")
            _validate_modes_oids(modes, oids, "u")
            records.append(
                {
                    "record": "u",
                    "xy": xy.decode("ascii"),
                    "submodule": submodule.decode("ascii"),
                    "modes": [item.decode("ascii") for item in modes],
                    "oids": [item.decode("ascii") for item in oids],
                    "path_b64": _b64(_require_git_path(path, "Git unmerged path")),
                }
            )
        elif prefix == b"? ":
            records.append(
                {
                    "record": "?",
                    "path_b64": _b64(_require_git_path(token[2:], "Git untracked path")),
                }
            )
        else:
            raise HarnessError("unsupported or malformed Git porcelain v2 record")
        if len(records) > MAX_GIT_STATUS_RECORDS:
            raise HarnessError("Git status output exceeds the configured record bound")
        index += 1
    return records


def _snapshot_mutation_paths(records: Iterable[Mapping[str, Any]]) -> list[bytes]:
    paths: set[bytes] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise HarnessError("Git status snapshot record must be an object")
        kind = record.get("record")
        if kind not in {"1", "2", "u", "?"}:
            raise HarnessError("Git status snapshot has an unsupported record")
        paths.add(_require_git_path(_unb64(record.get("path_b64"), "Git status path"), "Git status path"))
        if kind == "2":
            paths.add(
                _require_git_path(
                    _unb64(record.get("source_path_b64"), "Git rename/copy source"),
                    "Git rename/copy source",
                )
            )
    return sorted(paths)


def _parse_git_name_status(raw: bytes) -> list[dict[str, Any]]:
    """Parse ``git diff --name-status -z`` without decoding path bytes."""

    if len(raw) > MAX_GIT_COMMAND_BYTES:
        raise HarnessError("Git diff output exceeds the configured byte bound")
    if raw and not raw.endswith(b"\x00"):
        raise HarnessError("malformed Git diff output is not NUL terminated")
    tokens = raw[:-1].split(b"\x00") if raw else []
    records: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        status = tokens[index]
        if not status:
            raise HarnessError("malformed Git diff output contains an empty status")
        if not re.fullmatch(rb"[ACDMRTUXB][0-9]{0,3}", status):
            raise HarnessError("malformed Git diff name-status record")
        if index + 1 >= len(tokens):
            raise HarnessError("malformed Git diff output is missing a path")
        kind = status[:1]
        if kind in {b"R", b"C"}:
            if index + 2 >= len(tokens):
                raise HarnessError("malformed Git diff rename/copy record")
            source = _require_git_path(tokens[index + 1], "Git diff rename/copy source")
            destination = _require_git_path(tokens[index + 2], "Git diff rename/copy destination")
            records.append(
                {
                    "status": status.decode("ascii"),
                    "path_b64": _b64(destination),
                    "source_path_b64": _b64(source),
                }
            )
            index += 3
            continue
        path = _require_git_path(tokens[index + 1], "Git diff path")
        records.append({"status": status.decode("ascii"), "path_b64": _b64(path)})
        index += 2
    records.sort(key=lambda record: _canonical_json_bytes(record))
    if len(records) > MAX_GIT_STATUS_RECORDS:
        raise HarnessError("Git diff output exceeds the configured record bound")
    return records


def _diff_mutation_paths(records: Iterable[Mapping[str, Any]]) -> list[bytes]:
    paths: set[bytes] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise HarnessError("Git diff snapshot record must be an object")
        status = record.get("status")
        if not isinstance(status, str) or not re.fullmatch(r"[ACDMRTUXB][0-9]{0,3}", status):
            raise HarnessError("Git diff snapshot has an unsupported status")
        paths.add(_require_git_path(_unb64(record.get("path_b64"), "Git diff path"), "Git diff path"))
        if status.startswith(("R", "C")):
            paths.add(
                _require_git_path(
                    _unb64(record.get("source_path_b64"), "Git diff rename/copy source"),
                    "Git diff rename/copy source",
                )
            )
        elif "source_path_b64" in record:
            raise HarnessError("Git diff non-rename record may not have a source path")
    return sorted(paths)


def _claimable_utf8_paths(paths: Iterable[bytes]) -> list[tuple[bytes, str]]:
    result: list[tuple[bytes, str]] = []
    for raw in sorted(set(paths)):
        raw = _require_git_path(raw, "Git mutation path")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HarnessError("Git mutation path is not valid UTF-8 and cannot be claimed") from exc
        try:
            normalize_lock(f"repo:file:{text}")
        except HarnessError as exc:
            raise HarnessError(f"Git mutation path cannot be claimed: {text!r}") from exc
        result.append((raw, text))
    return result


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def _lstat_snapshot_path(worktree: Path, raw_path: bytes, text_path: str) -> dict[str, Any]:
    """Capture one path without following any link or reparse-point component."""

    current = worktree
    for component in text_path.split("/"):
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            # Only the final path may be absent.  A missing parent makes the
            # observed Git mutation impossible to attribute safely.
            if component == text_path.split("/")[-1]:
                return {"path_b64": _b64(raw_path), "absent": True}
            raise HarnessError(f"Git mutation path parent is absent: {text_path!r}")
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise HarnessError(f"Git mutation path traverses a symlink or reparse point: {text_path!r}")
        if component != text_path.split("/")[-1] and not stat.S_ISDIR(metadata.st_mode):
            raise HarnessError(f"Git mutation path parent is not a directory: {text_path!r}")
    if stat.S_ISDIR(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HarnessError(f"Git mutation path is not a regular file: {text_path!r}")
    if metadata.st_nlink != 1:
        raise HarnessError(f"Git mutation path is hard-linked: {text_path!r}")
    digest = hashlib.sha256()
    try:
        with current.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise HarnessError(f"Git mutation path changed while opening: {text_path!r}")
            while chunk := handle.read(64 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise HarnessError(f"could not hash Git mutation path {text_path!r}: {exc}") from exc
    return {
        "path_b64": _b64(raw_path),
        "absent": False,
        "lstat_mode": int(metadata.st_mode),
        "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "content_sha256": digest.hexdigest(),
    }


def task_mutation_snapshot(
    task_id: str, worktree: Path, baseline_head: str
) -> dict[str, Any]:
    """Capture a task-bound, content-addressed mutation snapshot.

    The supplied baseline is compared with the current ``HEAD`` while porcelain
    v2 captures staged, unstaged, untracked, deletion, rename, and case-only
    state.  Git paths must be UTF-8 before they can be joined to AOI's claim
    namespace; this is intentionally fail-closed rather than lossy escaping.
    """

    task_id = _require_task_id(task_id)
    baseline_head = require_full_commit(baseline_head, "baseline_head")
    metadata = git_metadata(worktree)
    resolved = Path(metadata["worktree"])
    current_head = metadata["head_sha"]
    diff_records = _parse_git_name_status(
        _run_git_bytes_bounded(
            resolved,
            ["diff", "--name-status", "-z", f"{baseline_head}..{current_head}"],
            label="Git task mutation diff",
        )
    )
    status_records = _parse_git_status_porcelain_v2(
        _run_git_bytes_bounded(
            resolved,
            ["status", "--porcelain=v2", "-z", "--untracked-files=all"],
            label="Git task mutation status",
            stdout_limit=MAX_GIT_STATUS_BYTES,
        )
    )
    if any(
        record.get("record") in {"1", "2", "u"} and record.get("submodule") != "N..."
        for record in status_records
    ):
        raise HarnessError("Git task mutation snapshot refuses submodule state")
    status_records.sort(key=_canonical_json_bytes)
    union_paths = sorted(set(_diff_mutation_paths(diff_records)) | set(_snapshot_mutation_paths(status_records)))
    claimable_paths = _claimable_utf8_paths(union_paths)
    path_entries = [_lstat_snapshot_path(resolved, raw, text) for raw, text in claimable_paths]
    preimage = {
        "schema": GIT_MUTATION_SNAPSHOT_SCHEMA,
        "task_id": task_id,
        "worktree": str(resolved),
        "baseline_head": baseline_head,
        "current_head": current_head,
        "baseline_to_current_name_status": diff_records,
        "porcelain_v2": status_records,
        "mutation_paths_b64": [_b64(raw) for raw in union_paths],
        "paths": path_entries,
    }
    return {**preimage, "snapshot_sha256": hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest()}


def validate_task_mutation_snapshot(snapshot: Mapping[str, Any]) -> tuple[str, list[bytes]]:
    """Validate a v2 snapshot's canonical structure and return its task/path set."""

    if not isinstance(snapshot, Mapping):
        raise HarnessError("Git task mutation snapshot must be an object")
    if snapshot.get("schema") != GIT_MUTATION_SNAPSHOT_SCHEMA:
        raise HarnessError("unsupported Git task mutation snapshot schema")
    task_id = _require_task_id(snapshot.get("task_id"))
    if not isinstance(snapshot.get("worktree"), str) or not snapshot["worktree"]:
        raise HarnessError("Git task mutation snapshot worktree must be non-empty text")
    for key in ("baseline_head", "current_head"):
        value = snapshot.get(key)
        if not isinstance(value, str):
            raise HarnessError(f"Git task mutation snapshot {key} must be text")
        require_full_commit(value, key)
    diff_records = snapshot.get("baseline_to_current_name_status")
    status_records = snapshot.get("porcelain_v2")
    if not isinstance(diff_records, list) or not isinstance(status_records, list):
        raise HarnessError("Git task mutation snapshot records must be lists")
    diff_paths = _diff_mutation_paths(diff_records)
    status_paths = _snapshot_mutation_paths(status_records)
    if any(
        record.get("record") in {"1", "2", "u"} and record.get("submodule") != "N..."
        for record in status_records
    ):
        raise HarnessError("Git task mutation snapshot refuses submodule state")
    expected_paths = sorted(set(diff_paths) | set(status_paths))
    mutation_paths = snapshot.get("mutation_paths_b64")
    if mutation_paths != [_b64(raw) for raw in expected_paths]:
        raise HarnessError("Git task mutation snapshot paths are not canonical")
    entries = snapshot.get("paths")
    if not isinstance(entries, list) or len(entries) != len(expected_paths):
        raise HarnessError("Git task mutation snapshot path entries are not canonical")
    for expected, entry in zip(expected_paths, entries):
        if not isinstance(entry, Mapping) or entry.get("path_b64") != _b64(expected):
            raise HarnessError("Git task mutation snapshot path entries are not canonical")
        absent = entry.get("absent")
        if not isinstance(absent, bool):
            raise HarnessError("Git task mutation snapshot path absent flag must be boolean")
        if absent:
            if set(entry) != {"path_b64", "absent"}:
                raise HarnessError("absent Git task mutation path has unexpected metadata")
            continue
        if set(entry) != {"path_b64", "absent", "lstat_mode", "mode", "content_sha256"}:
            raise HarnessError("present Git task mutation path has unexpected metadata")
        if isinstance(entry.get("lstat_mode"), bool) or not isinstance(entry.get("lstat_mode"), int):
            raise HarnessError("Git task mutation path lstat mode must be an integer")
        if not isinstance(entry.get("mode"), str) or not re.fullmatch(r"[0-7]{4}", entry["mode"]):
            raise HarnessError("Git task mutation path mode is malformed")
        if not isinstance(entry.get("content_sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry["content_sha256"]
        ):
            raise HarnessError("Git task mutation path content digest is malformed")
    preimage = dict(snapshot)
    actual_digest = preimage.pop("snapshot_sha256", None)
    if actual_digest != hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest():
        raise HarnessError("Git task mutation snapshot digest does not match its canonical preimage")
    return task_id, expected_paths


def git_status_snapshot(worktree: Path) -> dict[str, Any]:
    """Return one bounded, canonical, NUL-safe porcelain-v2 mutation snapshot."""

    resolved = worktree.resolve()
    if not resolved.is_dir():
        raise HarnessError(f"worktree does not exist: {resolved}")
    records = _parse_git_status_porcelain_v2(
        _run_git_bytes_bounded(
            resolved,
            ["status", "--porcelain=v2", "-z", "--untracked-files=all"],
            label="Git status snapshot",
            stdout_limit=MAX_GIT_STATUS_BYTES,
        )
    )
    records.sort(
        key=lambda record: json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )
    preimage = {
        "schema": GIT_STATUS_SNAPSHOT_SCHEMA,
        "records": records,
        "mutation_paths_b64": [_b64(path) for path in _snapshot_mutation_paths(records)],
    }
    canonical = json.dumps(
        preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {**preimage, "snapshot_sha256": hashlib.sha256(canonical).hexdigest()}


def mutation_claim_coverage(
    mutation_paths: Iterable[bytes | str], claims: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Compare every observed Git mutation with active/reserving repo claims.

    The function is pure: callers supply opaque Git paths and already-loaded
    claims.  It uses the claim subsystem's canonicalization and ``lock_covers``
    relation; a file lock therefore covers only the exact path, while a tree
    lock covers descendants.  Rename/copy callers must supply both endpoints.
    """

    required: dict[bytes, str] = {}
    for raw_path in mutation_paths:
        raw = (
            raw_path
            if isinstance(raw_path, bytes)
            else raw_path.encode("utf-8")
            if isinstance(raw_path, str)
            else None
        )
        if raw is None:
            raise HarnessError("Git mutation path must be bytes or text")
        raw = _require_git_path(raw, "Git mutation path")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HarnessError("Git mutation path is not valid UTF-8 and cannot be claimed") from exc
        required[raw] = normalize_lock(f"repo:file:{text}")

    held: list[str] = []
    for claim in claims:
        if not isinstance(claim, Mapping):
            raise HarnessError("claim must be an object")
        if claim.get("status") not in RESERVING_CLAIM_STATUSES:
            continue
        locks = claim.get("locks")
        if not isinstance(locks, list):
            raise HarnessError("reserving claim locks must be a list")
        for lock in locks:
            if not isinstance(lock, str):
                raise HarnessError("reserving claim lock must be text")
            canonical = normalize_lock(lock)
            if canonical.startswith(("repo:file:", "repo:tree:")):
                held.append(canonical)
    held = sorted(set(held))

    entries = []
    for raw, required_lock in sorted(required.items()):
        covering = [lock for lock in held if lock_covers(lock, required_lock)]
        entries.append(
            {
                "path_b64": _b64(raw),
                "required_lock": required_lock,
                "covering_locks": covering,
            }
        )
    uncovered = [entry["path_b64"] for entry in entries if not entry["covering_locks"]]
    return {
        "covered": not uncovered,
        "paths": entries,
        "uncovered_paths_b64": uncovered,
    }


def _task_live_claim_scope(
    task_id: str,
    claims: Iterable[Mapping[str, Any]],
    *,
    expected_worktree: str | None = None,
) -> list[dict[str, Any]]:
    """Return the strictly validated, canonical live scope for one task only."""

    scope: list[dict[str, Any]] = []
    tokens: set[str] = set()
    for claim in claims:
        if not isinstance(claim, Mapping):
            raise HarnessError("claim must be an object")
        if claim.get("task_id") != task_id:
            continue
        status = claim.get("status")
        if status in {"done", "released", "stale"}:
            continue
        if status not in RESERVING_CLAIM_STATUSES:
            raise HarnessError("task claim has an unsupported non-terminal status")
        token = claim.get("token")
        owner = claim.get("owner")
        worktree = claim.get("worktree")
        if not isinstance(token, str) or not token or token.strip() != token:
            raise HarnessError("live task claim token must be non-empty text without surrounding whitespace")
        if token in tokens:
            raise HarnessError(f"duplicate live task claim token: {token!r}")
        if not isinstance(owner, str) or not owner or owner.strip() != owner:
            raise HarnessError("live task claim owner must be non-empty text without surrounding whitespace")
        if not isinstance(worktree, str) or not worktree or worktree.strip() != worktree:
            raise HarnessError("live task claim worktree must be non-empty text without surrounding whitespace")
        if expected_worktree is not None and worktree != expected_worktree:
            raise HarnessError("live task claim worktree differs from the task mutation snapshot")
        locks = claim.get("locks")
        if not isinstance(locks, list) or not locks:
            raise HarnessError("live task claim locks must be a non-empty list")
        canonical_locks: list[str] = []
        for lock in locks:
            if not isinstance(lock, str):
                raise HarnessError("live task claim lock must be text")
            canonical_locks.append(normalize_lock(lock))
        if len(set(canonical_locks)) != len(canonical_locks):
            raise HarnessError("live task claim locks must not contain duplicates")
        tokens.add(token)
        scope.append(
            {
                "token": token,
                "owner": owner,
                "status": status,
                "worktree": worktree,
                "locks": sorted(canonical_locks),
            }
        )
    return sorted(scope, key=lambda item: item["token"])


def _immutable_claim_scope(scope: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project a claim scope onto the fields that survive a terminal transition."""

    return [
        {
            "token": claim["token"],
            "owner": claim["owner"],
            "worktree": claim["worktree"],
            "locks": claim["locks"],
        }
        for claim in scope
    ]


def _claim_scope_digest(task_id: str, scope: Iterable[Mapping[str, Any]]) -> str:
    preimage = {
        "schema": GIT_TASK_CLAIM_SCOPE_SCHEMA,
        "task_id": task_id,
        "claims": _immutable_claim_scope(scope),
    }
    return hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest()


def validate_sealed_task_claim_scope(
    task_id: str,
    covered_tokens: Iterable[str],
    expected_digest: str,
    claims: Iterable[Mapping[str, Any]],
    expected_worktree: str,
) -> dict[str, Any]:
    """Revalidate an exact sealed claim scope after claims become terminal.

    A seal binds only immutable ownership and lock scope.  The claim status is
    intentionally reported, but never hashed, so a normal active-to-released
    transition does not invalidate an already-authorized mutation snapshot.
    """

    task_id = _require_task_id(task_id)
    if isinstance(covered_tokens, (str, bytes)):
        raise HarnessError("covered claim tokens must be a canonical list of text")
    tokens = list(covered_tokens)
    if any(not isinstance(token, str) or not token or token.strip() != token for token in tokens):
        raise HarnessError("covered claim tokens must be non-empty text without surrounding whitespace")
    if tokens != sorted(set(tokens)):
        raise HarnessError("covered claim tokens must be sorted and unique")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise HarnessError("sealed task claim scope digest must be a lowercase SHA-256 hex string")
    if (
        not isinstance(expected_worktree, str)
        or not expected_worktree
        or expected_worktree.strip() != expected_worktree
    ):
        raise HarnessError("expected worktree must be non-empty text without surrounding whitespace")

    wanted = set(tokens)
    found: dict[str, dict[str, Any]] = {}
    known_statuses = RESERVING_CLAIM_STATUSES | {"done", "released", "stale"}
    for claim in claims:
        if not isinstance(claim, Mapping):
            raise HarnessError("claim must be an object")
        token = claim.get("token")
        if not isinstance(token, str):
            continue
        if token not in wanted:
            continue
        if claim.get("task_id") != task_id:
            raise HarnessError(f"foreign task claim uses sealed token: {token!r}")
        if token in found:
            raise HarnessError(f"duplicate sealed task claim token: {token!r}")
        status = claim.get("status")
        if status not in known_statuses:
            raise HarnessError("sealed task claim has an unsupported status")
        owner = claim.get("owner")
        worktree = claim.get("worktree")
        if not isinstance(owner, str) or not owner or owner.strip() != owner:
            raise HarnessError("sealed task claim owner must be non-empty text without surrounding whitespace")
        if not isinstance(worktree, str) or not worktree or worktree.strip() != worktree:
            raise HarnessError("sealed task claim worktree must be non-empty text without surrounding whitespace")
        if worktree != expected_worktree:
            raise HarnessError("sealed task claim worktree differs from the task mutation snapshot")
        locks = claim.get("locks")
        if not isinstance(locks, list) or not locks:
            raise HarnessError("sealed task claim locks must be a non-empty list")
        canonical_locks: list[str] = []
        for lock in locks:
            if not isinstance(lock, str):
                raise HarnessError("sealed task claim lock must be text")
            canonical_locks.append(normalize_lock(lock))
        if len(set(canonical_locks)) != len(canonical_locks):
            raise HarnessError("sealed task claim locks must not contain duplicates")
        found[token] = {
            "token": token,
            "owner": owner,
            "status": status,
            "worktree": worktree,
            "locks": sorted(canonical_locks),
        }
    missing = [token for token in tokens if token not in found]
    if missing:
        raise HarnessError(f"sealed task claim tokens are missing: {missing!r}")
    scope = [found[token] for token in tokens]
    digest = _claim_scope_digest(task_id, scope)
    if digest != expected_digest:
        raise HarnessError("sealed task claim scope digest does not match")
    return {
        "task_id": task_id,
        "covered_claim_tokens": tokens,
        "claims": [
            {"token": claim["token"], "observed_status": claim["status"]}
            for claim in scope
        ],
        "claim_scope_sha256": digest,
    }


def validate_task_mutation_snapshot_claim_scope(
    snapshot: Mapping[str, Any],
    covered_tokens: Iterable[str],
    expected_digest: str,
    claims: Iterable[Mapping[str, Any]],
    *,
    sealed: bool,
) -> dict[str, Any]:
    """Rebuild and validate one persisted snapshot's exact claim coverage.

    Draft snapshots must still be covered by the task's current reserving
    claims.  A sealed snapshot instead accepts the exact recorded claims after
    their normal active-to-terminal transition, but it still recomputes every
    path coverage relation; a matching immutable-scope digest alone is not
    sufficient authority for an uncovered mutation.
    """

    task_id, mutation_paths = validate_task_mutation_snapshot(snapshot)
    if isinstance(covered_tokens, (str, bytes)):
        raise HarnessError("covered claim tokens must be a canonical list of text")
    tokens = list(covered_tokens)
    if any(not isinstance(token, str) or not token or token.strip() != token for token in tokens):
        raise HarnessError("covered claim tokens must be non-empty text without surrounding whitespace")
    if tokens != sorted(set(tokens)):
        raise HarnessError("covered claim tokens must be sorted and unique")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise HarnessError("task claim scope digest must be a lowercase SHA-256 hex string")

    claims_list = list(claims)
    if sealed:
        # Validate the immutable exact token scope first, including claims
        # which are terminal only because the seal authorized their release.
        validate_sealed_task_claim_scope(
            task_id,
            tokens,
            expected_digest,
            claims_list,
            snapshot["worktree"],
        )
        wanted = set(tokens)
        scoped_claims = [
            claim
            for claim in claims_list
            if isinstance(claim, Mapping) and claim.get("token") in wanted
        ]
        scope = _task_live_claim_scope(task_id, scoped_claims, expected_worktree=snapshot["worktree"])
        # ``_task_live_claim_scope`` intentionally excludes terminal records;
        # reconstruct the same strict immutable projection for sealed scope.
        if len(scope) != len(tokens):
            scope = []
            known_statuses = RESERVING_CLAIM_STATUSES | {"done", "released", "stale"}
            for claim in scoped_claims:
                if not isinstance(claim, Mapping):
                    raise HarnessError("claim must be an object")
                if claim.get("task_id") != task_id:
                    continue
                token = claim.get("token")
                if token not in wanted:
                    continue
                if claim.get("status") not in known_statuses:
                    raise HarnessError("sealed task claim has an unsupported status")
                owner = claim.get("owner")
                worktree = claim.get("worktree")
                locks = claim.get("locks")
                if (
                    not isinstance(owner, str)
                    or not owner
                    or owner.strip() != owner
                    or not isinstance(worktree, str)
                    or worktree != snapshot["worktree"]
                    or not isinstance(locks, list)
                    or not locks
                ):
                    raise HarnessError("sealed task claim is malformed")
                canonical_locks: list[str] = []
                for lock in locks:
                    if not isinstance(lock, str):
                        raise HarnessError("sealed task claim locks are malformed")
                    canonical_locks.append(normalize_lock(lock))
                if len(set(canonical_locks)) != len(canonical_locks):
                    raise HarnessError("sealed task claim locks are malformed")
                scope.append(
                    {
                        "token": token,
                        "owner": owner,
                        "status": claim["status"],
                        "worktree": worktree,
                        "locks": sorted(canonical_locks),
                    }
                )
            scope.sort(key=lambda item: item["token"])
    else:
        scope = _task_live_claim_scope(task_id, claims_list, expected_worktree=snapshot["worktree"])

    coverage = _task_mutation_claim_coverage_from_scope(task_id, mutation_paths, scope)
    if not coverage["covered"]:
        raise HarnessError("task mutation snapshot has uncovered paths under its recorded claim scope")
    if coverage["covered_claim_tokens"] != tokens:
        raise HarnessError("task mutation snapshot covered claim tokens differ from its record")
    if coverage["claim_scope_sha256"] != expected_digest:
        raise HarnessError("task mutation snapshot claim scope digest differs from its record")
    return coverage


def _mutation_path_requirements(mutation_paths: Iterable[bytes | str]) -> dict[bytes, str]:
    required: dict[bytes, str] = {}
    for raw_path in mutation_paths:
        raw = (
            raw_path
            if isinstance(raw_path, bytes)
            else raw_path.encode("utf-8")
            if isinstance(raw_path, str)
            else None
        )
        if raw is None:
            raise HarnessError("Git mutation path must be bytes or text")
        raw = _require_git_path(raw, "Git mutation path")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HarnessError("Git mutation path is not valid UTF-8 and cannot be claimed") from exc
        required[raw] = normalize_lock(f"repo:file:{text}")
    return required


def _task_mutation_claim_coverage_from_scope(
    task_id: str, mutation_paths: Iterable[bytes | str], scope: list[dict[str, Any]]
) -> dict[str, Any]:
    requirements = _mutation_path_requirements(mutation_paths)
    entries: list[dict[str, Any]] = []
    covered_tokens: set[str] = set()
    for raw, required_lock in sorted(requirements.items()):
        covering_claims = [
            claim
            for claim in scope
            if any(lock_covers(lock, required_lock) for lock in claim["locks"])
        ]
        covering_locks = sorted(
            {
                lock
                for claim in covering_claims
                for lock in claim["locks"]
                if lock_covers(lock, required_lock)
            }
        )
        covering_tokens = [claim["token"] for claim in covering_claims]
        covered_tokens.update(covering_tokens)
        entries.append(
            {
                "path_b64": _b64(raw),
                "required_lock": required_lock,
                "covering_locks": covering_locks,
                "covering_claim_tokens": covering_tokens,
            }
        )
    uncovered = [entry["path_b64"] for entry in entries if not entry["covering_claim_tokens"]]
    covered_scope = [claim for claim in scope if claim["token"] in covered_tokens]
    return {
        "task_id": task_id,
        "covered": not uncovered,
        "paths": entries,
        "uncovered_paths_b64": uncovered,
        "covered_claim_tokens": sorted(covered_tokens),
        "covered_claims": [
            {"token": claim["token"], "observed_status": claim["status"]}
            for claim in covered_scope
        ],
        "claim_scope_sha256": _claim_scope_digest(task_id, covered_scope),
    }


def task_mutation_claim_coverage(
    task_id: str, mutation_paths: Iterable[bytes | str], claims: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Cover mutations with only this task's live, reserving structured claims.

    Terminal claims deliberately do not qualify here: a future sealed-scope
    digest is a separate authority, not an excuse to reuse a released claim.
    """

    task_id = _require_task_id(task_id)
    scope = _task_live_claim_scope(task_id, claims)
    return _task_mutation_claim_coverage_from_scope(task_id, mutation_paths, scope)


def git_status_claim_coverage(
    snapshot: Mapping[str, Any], claims: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Return pure reserving-claim coverage for one canonical status snapshot."""

    if not isinstance(snapshot, Mapping):
        raise HarnessError("Git status snapshot must be an object")
    if snapshot.get("schema") != GIT_STATUS_SNAPSHOT_SCHEMA:
        raise HarnessError("unsupported Git status snapshot schema")
    records = snapshot.get("records")
    if not isinstance(records, list):
        raise HarnessError("Git status snapshot records must be a list")
    paths = _snapshot_mutation_paths(records)
    expected_paths = [_b64(path) for path in paths]
    if snapshot.get("mutation_paths_b64") != expected_paths:
        raise HarnessError("Git status snapshot mutation paths are not canonical")
    preimage = {
        "schema": GIT_STATUS_SNAPSHOT_SCHEMA,
        "records": records,
        "mutation_paths_b64": expected_paths,
    }
    canonical = json.dumps(
        preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if snapshot.get("snapshot_sha256") != hashlib.sha256(canonical).hexdigest():
        raise HarnessError("Git status snapshot digest does not match its canonical preimage")
    return mutation_claim_coverage(paths, claims)


def task_mutation_snapshot_claim_coverage(
    snapshot: Mapping[str, Any], claims: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Verify a v2 snapshot digest then evaluate exact task-local live claims."""

    task_id, paths = validate_task_mutation_snapshot(snapshot)
    scope = _task_live_claim_scope(task_id, claims, expected_worktree=snapshot["worktree"])
    return _task_mutation_claim_coverage_from_scope(task_id, paths, scope)


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_full_commit(value: str, label: str) -> str:
    commit = require_text(value, label).lower()
    if not FULL_COMMIT_RE.fullmatch(commit):
        raise HarnessError(f"{label} must be a full 40-64 hex commit id")
    return commit


def git_metadata(worktree: Path) -> dict[str, str]:
    resolved = worktree.resolve()
    if not resolved.is_dir():
        raise HarnessError(f"worktree does not exist: {resolved}")

    def run(*arguments: str) -> str:
        return _run_git_bytes_bounded(
            resolved, arguments, label=f"Git metadata ({' '.join(arguments)})"
        ).decode("utf-8", "strict").strip()

    top = run("rev-parse", "--show-toplevel")
    if Path(top).resolve() != resolved:
        raise HarnessError(
            f"--worktree must be the Git worktree root, got {resolved} (root is {top})"
        )
    head_sha = run("rev-parse", "HEAD").lower()
    if not FULL_COMMIT_RE.fullmatch(head_sha):
        raise HarnessError(f"Git worktree has no valid HEAD commit: {head_sha!r}")
    branch = run("branch", "--show-current") or "detached"
    return {
        "worktree": str(resolved),
        "branch": branch,
        "head_sha": head_sha,
    }


def git_is_ancestor(worktree: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(worktree), "merge-base", "--is-ancestor", ancestor, descendant],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode not in {0, 1}:
        detail = (result.stderr or result.stdout).strip()
        raise HarnessError(f"Git ancestry check failed: {detail or result.returncode}")
    return result.returncode == 0


def resolve_task_commit(state: dict[str, Any], value: str, label: str) -> str:
    requested = require_full_commit(value, label)
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(Path(state.get("worktree", "")).resolve()),
                "rev-parse",
                f"{requested}^{{commit}}",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"could not resolve {label}: {exc}") from exc
    resolved = result.stdout.strip().lower()
    if result.returncode != 0 or not FULL_COMMIT_RE.fullmatch(resolved):
        raise HarnessError(f"{label} is not a commit in the task worktree")
    if resolved != requested:
        raise HarnessError(f"{label} must name the exact full commit, got {resolved}")
    return resolved


def state_worktree(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    return validated_state_worktree(paths, state)


def worktree_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> tuple[list[str], dict[str, str] | None]:
    try:
        current = git_metadata(state_worktree(paths, state))
    except HarnessError as exc:
        return [str(exc)], None
    errors: list[str] = []
    if current["worktree"] != str(state.get("worktree", "")):
        errors.append(
            f"recorded worktree {state.get('worktree')!r} differs from {current['worktree']!r}"
        )
    if current["branch"] != state.get("branch"):
        errors.append(
            f"task branch changed from {state.get('branch')!r} to {current['branch']!r}"
        )
    if not FULL_COMMIT_RE.fullmatch(str(state.get("head_sha", ""))):
        errors.append("task starting HEAD is missing or invalid")
    return errors, current


def legacy_ambiguities(
    paths: HarnessPaths, *, ignore_token: str | None = None
) -> list[dict[str, Any]]:
    ambiguous: list[dict[str, Any]] = []
    for pending in sorted(paths.legacy_pending.glob("*.json")):
        claim = load_claim_file(pending)
        if claim.get("token") == ignore_token:
            continue
        if claim.get("scope_parse_warnings"):
            ambiguous.append(
                {
                    "token": claim.get("token"),
                    "owner": claim.get("owner"),
                    "raw_scope": claim.get("raw_scope"),
                    "warnings": claim.get("scope_parse_warnings"),
                    "locks": claim.get("locks", []),
                    "source_file": claim.get("source_file"),
                    "source_line": claim.get("source_line"),
                    "pending_file": str(pending),
                }
            )
    return ambiguous


def remote_ref_tip(worktree: Path, remote: str, remote_ref: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", remote):
        raise HarnessError(f"invalid Git remote name: {remote!r}")
    if not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", remote_ref) or ".." in remote_ref:
        raise HarnessError(f"--remote-ref must be a full refs/heads/... ref: {remote_ref!r}")
    try:
        result = subprocess.run(
            ["git", "-C", str(worktree), "ls-remote", "--exit-code", remote, remote_ref],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"could not verify pushed remote ref: {exc}") from exc
    if result.returncode != 0:
        raise HarnessError(
            "could not verify pushed remote ref: "
            + ((result.stderr or result.stdout).strip() or "ref not found")
        )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError(f"expected exactly one remote ref result, got {len(lines)}")
    tip = lines[0].split()[0].lower()
    if not FULL_COMMIT_RE.fullmatch(tip):
        raise HarnessError(f"remote ref returned invalid commit id: {tip!r}")
    return tip


__all__ = [
    "COMMIT_RE",
    "FULL_COMMIT_RE",
    "GIT_MUTATION_SNAPSHOT_SCHEMA",
    "GIT_STATUS_SNAPSHOT_SCHEMA",
    "GIT_TASK_CLAIM_SCOPE_SCHEMA",
    "MAX_GIT_COMMAND_BYTES",
    "MAX_GIT_COMMAND_STDERR_BYTES",
    "MAX_GIT_STATUS_BYTES",
    "MAX_GIT_STATUS_PATH_BYTES",
    "MAX_GIT_STATUS_RECORDS",
    "git_is_ancestor",
    "git_metadata",
    "task_mutation_snapshot",
    "task_mutation_snapshot_claim_coverage",
    "task_mutation_claim_coverage",
    "validate_sealed_task_claim_scope",
    "validate_task_mutation_snapshot_claim_scope",
    "validate_task_mutation_snapshot",
    "git_status_claim_coverage",
    "git_status_snapshot",
    "legacy_ambiguities",
    "mutation_claim_coverage",
    "remote_ref_tip",
    "resolve_task_commit",
    "state_worktree",
    "worktree_integrity_errors",
]
