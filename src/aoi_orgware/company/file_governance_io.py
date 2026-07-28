"""Bounded Git-tree and no-follow worktree readers for file governance."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from importlib import resources
import os
from pathlib import Path
import re
import stat
import subprocess
from threading import Thread
import time
from typing import Any, Literal

from .file_governance import (
    MAX_FILE_BYTES,
    MAX_SCOPE_BYTES,
    SCOPE_ROOTS,
    ExactExclusionV1,
    FileGovernanceError,
    FileGovernanceWaiverV1,
    GitBlob,
    GitScopeSnapshot,
    GovernanceFinding,
    GovernanceReport,
    ImportBoundaryRuleV1,
    _evaluate_verified_candidate,
    baseline_manifest_bytes,
    build_baseline_manifest,
    normalize_repo_path,
    parse_baseline_manifest,
    validate_baseline_manifest,
)
from .file_governance_process import (
    quiesce_git_process,
    spawn_git_process,
)
from .import_governance import (
    DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES,
    evaluate_import_governance,
)


_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_LS_TREE_RECORD = re.compile(
    rb"^(?P<mode>[0-9]{6}) (?P<type>[a-z]+) "
    rb"(?P<oid>[0-9a-f]{40}) +(?P<size>[0-9]+)\t(?P<path>.+)$"
)

class GitProcessTreeCleanupError(FileGovernanceError):
    """A primary observation error whose process tree could not be quiesced."""

    def __init__(
        self,
        primary_error: BaseException,
        cleanup_error: BaseException,
    ) -> None:
        super().__init__(
            "bounded Git process-tree cleanup failed after observation error"
        )
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error


def _supported_git_arguments(arguments: Sequence[str]) -> bool:
    args = tuple(arguments)
    roots = tuple(SCOPE_ROOTS)
    if len(args) == 3 and args[:2] == ("rev-parse", "--verify"):
        return any(
            args[2].endswith(suffix)
            and bool(_HEX40.fullmatch(args[2][:-len(suffix)]))
            for suffix in ("^{commit}", "^{tree}")
        )
    if args[:5] == ("ls-tree", "-r", "-z", "-l", "--full-tree"):
        return (
            len(args) == 7 + len(roots)
            and bool(_HEX40.fullmatch(args[5]))
            and args[6:] == ("--", *roots)
        )
    if args[:2] == ("cat-file", "blob"):
        return len(args) == 3 and bool(_HEX40.fullmatch(args[2]))
    return args in {
        ("ls-files", "-z", "--stage", "--cached", "--", *roots),
        (
            "ls-files", "-z", "--others", "--ignored",
            "--exclude-standard", "--", *roots,
        ),
    }


def _run_git(
    root: Path,
    arguments: Sequence[str],
    *,
    timeout: int,
    output_limit: int,
) -> bytes:
    if not _supported_git_arguments(arguments):
        raise FileGovernanceError("unsupported bounded Git observation")
    try:
        tree = spawn_git_process(
            ["git", "-C", str(root), *arguments],
        )
    except OSError as exc:
        raise FileGovernanceError("bounded Git observation failed") from exc
    process = tree.process
    stdout = process.stdout
    if stdout is None:
        cleanup_error = quiesce_git_process(tree, None)
        raise FileGovernanceError("bounded Git observation failed") from cleanup_error
    captured = bytearray()
    overflow: list[bool] = []
    reader_error: list[BaseException] = []

    def read_stdout() -> None:
        try:
            while True:
                remaining = output_limit + 1 - len(captured)
                if remaining <= 0:
                    overflow.append(True)
                    return
                chunk = stdout.read(min(64 * 1024, remaining))
                if not chunk:
                    return
                captured.extend(chunk)
                if len(captured) > output_limit:
                    overflow.append(True)
                    return
        except BaseException as exc:
            reader_error.append(exc)
        finally:
            try:
                stdout.close()
            except BaseException as exc:
                reader_error.append(exc)

    reader = Thread(
        target=read_stdout,
        name="aoi-file-governance-git-reader",
        daemon=True,
    )
    primary_error: BaseException | None = None
    returncode: int | None = None
    try:
        reader.start()
        wait_deadline = time.monotonic() + timeout
        while True:
            if overflow or reader_error:
                break
            remaining = wait_deadline - time.monotonic()
            if remaining <= 0:
                primary_error = subprocess.TimeoutExpired(process.args, timeout)
                break
            try:
                returncode = process.wait(timeout=min(0.05, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException as exc:
        primary_error = exc
    cleanup_error = quiesce_git_process(tree, reader)
    if primary_error is not None:
        if cleanup_error is not None:
            raise GitProcessTreeCleanupError(
                primary_error,
                cleanup_error,
            ) from cleanup_error
        if isinstance(primary_error, subprocess.TimeoutExpired):
            raise FileGovernanceError(
                "bounded Git observation timed out"
            ) from primary_error
        if not isinstance(primary_error, Exception):
            raise primary_error
        raise FileGovernanceError("bounded Git observation failed") from primary_error
    if cleanup_error is not None:
        raise FileGovernanceError(
            "bounded Git process-tree cleanup failed"
        ) from cleanup_error
    if returncode != 0 or overflow or reader_error:
        cause = reader_error[0] if reader_error else None
        raise FileGovernanceError("bounded Git observation failed") from cause
    return bytes(captured)


def _root(repo_root: Path) -> Path:
    original = Path(repo_root)
    if _link_or_reparse(original):
        raise FileGovernanceError("repository root may not be a link/reparse point")
    resolved = original.resolve(strict=True)
    if not resolved.is_dir():
        raise FileGovernanceError("repository root is not a directory")
    return resolved


def _decode_path(raw: bytes, label: str) -> str:
    try:
        return normalize_repo_path(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise FileGovernanceError(f"{label} path is not UTF-8") from exc


def _reject_aliases(paths: Sequence[str]) -> None:
    if len(paths) != len(set(paths)):
        raise FileGovernanceError("duplicate observed repository path")
    folded: dict[str, str] = {}
    for path in paths:
        prior = folded.setdefault(path.casefold(), path)
        if prior != path:
            raise FileGovernanceError("case-folding observed path collision")


def read_git_commit_scope(
    repo_root: Path,
    commit_sha1: str,
) -> GitScopeSnapshot:
    """Read every governed tree blob with ls-tree/cat-file, never archive."""

    if not _HEX40.fullmatch(commit_sha1):
        raise FileGovernanceError("commit identity must be lowercase SHA-1")
    root = _root(repo_root)
    observed_commit = _run_git(
        root,
        ["rev-parse", "--verify", f"{commit_sha1}^{{commit}}"],
        timeout=15,
        output_limit=128,
    ).decode("ascii").strip()
    if observed_commit != commit_sha1:
        raise FileGovernanceError("commit identity did not resolve exactly")
    tree_sha1 = _run_git(
        root,
        ["rev-parse", "--verify", f"{commit_sha1}^{{tree}}"],
        timeout=15,
        output_limit=128,
    ).decode("ascii").strip()
    if not _HEX40.fullmatch(tree_sha1):
        raise FileGovernanceError("tree identity is invalid")
    inventory = _run_git(
        root,
        [
            "ls-tree",
            "-r",
            "-z",
            "-l",
            "--full-tree",
            commit_sha1,
            "--",
            *SCOPE_ROOTS,
        ],
        timeout=30,
        output_limit=MAX_SCOPE_BYTES,
    )
    records: list[tuple[str, Literal["100644", "100755"], str, int]] = []
    for raw_record in inventory.split(b"\0"):
        if not raw_record:
            continue
        match = _LS_TREE_RECORD.fullmatch(raw_record)
        if match is None:
            raise FileGovernanceError("invalid ls-tree record")
        mode = match.group("mode").decode("ascii")
        object_type = match.group("type")
        if object_type != b"blob" or mode not in {"100644", "100755"}:
            raise FileGovernanceError("tracked non-regular entry is forbidden")
        size = int(match.group("size"))
        if size > MAX_FILE_BYTES:
            raise FileGovernanceError("tracked blob exceeds the byte bound")
        path = _decode_path(match.group("path"), "tracked")
        records.append((
            path,
            "100755" if mode == "100755" else "100644",
            match.group("oid").decode("ascii"),
            size,
        ))
    _reject_aliases([record[0] for record in records])
    files: dict[str, GitBlob] = {}
    total = 0
    for path, mode, oid, expected_size in sorted(
        records,
        key=lambda record: record[0].encode("utf-8"),
    ):
        data = _run_git(
            root,
            ["cat-file", "blob", oid],
            timeout=30,
            output_limit=expected_size,
        )
        if len(data) != expected_size:
            raise FileGovernanceError("cat-file size differs from ls-tree")
        total += len(data)
        if total > MAX_SCOPE_BYTES:
            raise FileGovernanceError("tracked scope exceeds the byte bound")
        files[path] = GitBlob(mode, data)
    return GitScopeSnapshot(commit_sha1, tree_sha1, files)


def build_baseline_from_git(
    repo_root: Path,
    commit_sha1: str,
    *,
    exclusions: Sequence[ExactExclusionV1] | None = None,
) -> dict[str, Any]:
    return build_baseline_manifest(
        read_git_commit_scope(repo_root, commit_sha1),
        exclusions=exclusions,
    )


def verify_baseline_against_git(
    repo_root: Path,
    baseline: bytes | Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild from the named commit and require exact canonical equality."""

    checked = (
        parse_baseline_manifest(baseline)
        if isinstance(baseline, bytes)
        else validate_baseline_manifest(baseline)
    )
    exclusions = tuple(
        ExactExclusionV1(
            item["path"],
            item["kind"],
            item["reason"],
            item["self_unbound"],
        )
        for item in checked["exact_exclusions"]
    )
    rebuilt = build_baseline_from_git(
        repo_root,
        checked["accepted_commit_sha1"],
        exclusions=exclusions,
    )
    if baseline_manifest_bytes(rebuilt) != baseline_manifest_bytes(checked):
        raise FileGovernanceError("baseline does not match its exact Git tree")
    return checked


def _link_or_reparse(path: Path) -> bool:
    info = os.lstat(path)
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _tracked_modes(root: Path) -> dict[str, Literal["100644", "100755"]]:
    raw = _run_git(
        root,
        ["ls-files", "-z", "--stage", "--cached", "--", *SCOPE_ROOTS],
        timeout=30,
        output_limit=MAX_SCOPE_BYTES,
    )
    result: dict[str, Literal["100644", "100755"]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            prefix, raw_path = record.split(b"\t", 1)
            mode = prefix.split(b" ", 1)[0].decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise FileGovernanceError("invalid Git index record") from exc
        path = _decode_path(raw_path, "index")
        if mode not in {"100644", "100755"} or path in result:
            raise FileGovernanceError("non-regular or duplicate index entry")
        result[path] = "100755" if mode == "100755" else "100644"
    _reject_aliases(list(result))
    return result


def _ignored_paths(root: Path) -> tuple[str, ...]:
    raw = _run_git(
        root,
        [
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            *SCOPE_ROOTS,
        ],
        timeout=30,
        output_limit=MAX_SCOPE_BYTES,
    )
    paths = tuple(
        sorted(
            (_decode_path(item, "ignored") for item in raw.split(b"\0") if item),
            key=lambda item: item.encode("utf-8"),
        )
    )
    _reject_aliases(list(paths))
    return paths


def _walk_scope(root: Path) -> list[Path]:
    result: list[Path] = []
    stack = [root / scope for scope in reversed(SCOPE_ROOTS)]
    while stack:
        current = stack.pop()
        if not os.path.lexists(current):
            continue
        if _link_or_reparse(current):
            raise FileGovernanceError("scope traversal encountered link/reparse")
        if current.is_file():
            result.append(current)
            continue
        if not current.is_dir():
            raise FileGovernanceError("scope traversal encountered special entry")
        children = sorted(
            current.iterdir(),
            key=lambda path: path.name.encode("utf-8"),
            reverse=True,
        )
        stack.extend(children)
    return result


def _read_stable_file(path: Path) -> bytes:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size > MAX_FILE_BYTES
        or _link_or_reparse(path)
    ):
        raise FileGovernanceError("candidate is not a bounded regular file")
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    after = os.lstat(path)
    if (
        len(data) != before.st_size
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise FileGovernanceError("candidate changed during read")
    return data


def read_worktree_scope(
    repo_root: Path,
    *,
    exact_ignored_allowlist: Sequence[str] = (),
) -> dict[str, GitBlob]:
    """Read all scope files; ignored paths require exact caller acknowledgement."""

    root = _root(repo_root)
    ignored = _ignored_paths(root)
    allowed = tuple(
        sorted(
            (normalize_repo_path(path) for path in exact_ignored_allowlist),
            key=lambda item: item.encode("utf-8"),
        )
    )
    _reject_aliases(list(allowed))
    if ignored != allowed:
        raise FileGovernanceError(
            "ignored scope paths differ from the exact runtime allowlist"
        )
    ignored_set = set(ignored)
    modes = _tracked_modes(root)
    files: dict[str, GitBlob] = {}
    total = 0
    for absolute in _walk_scope(root):
        relative = normalize_repo_path(absolute.relative_to(root).as_posix())
        if relative in ignored_set:
            continue
        data = _read_stable_file(absolute)
        total += len(data)
        if total > MAX_SCOPE_BYTES:
            raise FileGovernanceError("candidate scope exceeds the byte bound")
        mode = modes.get(relative)
        if mode is None:
            mode = (
                "100755"
                if os.name != "nt" and os.access(absolute, os.X_OK)
                else "100644"
            )
        files[relative] = GitBlob(mode, data)
    _reject_aliases(list(files))
    return files


def evaluate_file_governance(
    repo_root: Path,
    *,
    baseline: bytes | Mapping[str, Any],
    current_files: Mapping[str, GitBlob],
    release: str,
    observed_at: datetime,
    import_rules: Sequence[ImportBoundaryRuleV1],
    waivers: Sequence[FileGovernanceWaiverV1] = (),
    known_values: Sequence[tuple[str, bytes | str]] = (),
) -> GovernanceReport:
    """Verify the immutable Git tree, then enforce file and import policy."""

    checked = verify_baseline_against_git(repo_root, baseline)
    report = _evaluate_verified_candidate(
        baseline=checked,
        current_files=current_files,
        release=release,
        observed_at=observed_at,
        waivers=waivers,
        known_values=known_values,
    )
    if not import_rules:
        return report
    return _merge_import_findings(
        report,
        evaluate_import_governance(current_files, import_rules),
    )


def _merge_import_findings(
    report: GovernanceReport,
    findings: Sequence[GovernanceFinding],
) -> GovernanceReport:
    errors = tuple(sorted(set((
        *report.errors,
        *(item for item in findings if item.severity == "error"),
    ))))
    warnings = tuple(sorted(set((
        *report.warnings,
        *(item for item in findings if item.severity == "warning"),
    ))))
    return GovernanceReport(
        report.accepted and not errors,
        report.baseline_commit_sha1,
        report.baseline_tree_sha1,
        report.scanned_file_count,
        report.scanned_size_bytes,
        errors,
        warnings,
    )


def evaluate_packaged_file_governance(
    repo_root: Path,
    *,
    current_files: Mapping[str, GitBlob],
    release: str,
    observed_at: datetime,
    waivers: Sequence[FileGovernanceWaiverV1] = (),
    known_values: Sequence[tuple[str, bytes | str]] = (),
) -> GovernanceReport:
    resource = resources.files("aoi_orgware").joinpath(
        "resources", "company", "file-governance-baseline-v1.json"
    )
    return evaluate_file_governance(
        repo_root,
        baseline=resource.read_bytes(),
        current_files=current_files,
        release=release,
        observed_at=observed_at,
        import_rules=DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES,
        waivers=waivers,
        known_values=known_values,
    )


__all__ = [
    "build_baseline_from_git",
    "evaluate_file_governance",
    "evaluate_packaged_file_governance",
    "read_git_commit_scope",
    "read_worktree_scope",
    "verify_baseline_against_git",
]
