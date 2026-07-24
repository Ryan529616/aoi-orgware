#!/usr/bin/env python3
"""Fail closed when combining coverage data from copied AOI source trees.

Coverage stores the path observed by each Python process.  The test suite starts
children from a source checkout and from an installed copy, so blindly using
``coverage combine`` turns one source tree into several unrelated trees.  This
driver proves that every measured tree is byte-for-byte the reviewed canonical
tree before using CoverageData.update's documented ``map_path`` API.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import ntpath
import os
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from importlib.metadata import distribution

import coverage
import pytest
from coverage import CoverageData


EXPECTED_COVERAGE_VERSION = "7.15.2"
EXPECTED_PYTEST_VERSION = "9.1.1"


class CoverageProvenanceError(RuntimeError):
    """The submitted coverage data cannot be tied to canonical source."""


@dataclass(frozen=True)
class TreeEntry:
    relative: str
    sha256: str
    kind: str = "file"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_unlinked(path: Path, label: str) -> os.stat_result:
    try:
        value = path.lstat()
    except FileNotFoundError as exc:
        raise CoverageProvenanceError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise CoverageProvenanceError(f"{label} must be one regular non-linked file: {path}")
    return value


def _is_reparse(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _directory_identity(path: Path, label: str) -> tuple[int, int]:
    try:
        value = path.lstat()
    except FileNotFoundError as exc:
        raise CoverageProvenanceError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(value.st_mode) or _is_reparse(value) or not stat.S_ISDIR(value.st_mode):
        raise CoverageProvenanceError(f"{label} must be a non-link directory: {path}")
    return value.st_dev, value.st_ino


def _directory_entry(relative: str) -> TreeEntry:
    """Represent an exact logical directory without changing file hashes."""
    identity = hashlib.sha256(f"directory\0{relative}".encode("utf-8")).hexdigest()
    return TreeEntry(relative, identity, "directory")


def _tree_manifest(root: Path) -> tuple[TreeEntry, ...]:
    root = root.absolute()
    _directory_identity(root, "source root")
    entries: list[TreeEntry] = []
    pending_children: dict[Path, tuple[int, int]] = {}
    visited: dict[Path, tuple[int, int]] = {}

    def walk_error(error: OSError) -> None:
        raise CoverageProvenanceError(f"source tree walk failed: {error}") from error

    for directory, directories, names in os.walk(root, followlinks=False, onerror=walk_error):
        current = Path(directory).absolute()
        current_identity = _directory_identity(current, "source directory")
        expected_identity = pending_children.pop(current, None)
        if expected_identity is not None and current_identity != expected_identity:
            raise CoverageProvenanceError(f"source directory entry changed before descent: {current}")
        if current in visited:
            raise CoverageProvenanceError(f"source tree visited one directory more than once: {current}")
        visited[current] = current_identity
        for name in directories:
            path = current / name
            identity = _directory_identity(path, "source directory entry")
            if path in pending_children or path in visited:
                raise CoverageProvenanceError(f"source tree listed one directory more than once: {path}")
            pending_children[path] = identity
            entries.append(_directory_entry(path.relative_to(root).as_posix()))
        for name in sorted(names):
            path = current / name
            _regular_unlinked(path, "source file")
            entries.append(TreeEntry(path.relative_to(root).as_posix(), _sha256(path)))
    if pending_children:
        missing = sorted(path.as_posix() for path in pending_children)[0]
        raise CoverageProvenanceError(f"source directory entry was not visited: {missing}")
    for path, expected_identity in visited.items():
        if _directory_identity(path, "source directory") != expected_identity:
            raise CoverageProvenanceError(f"source directory identity changed during manifest: {path}")
    if not any(entry.kind == "file" for entry in entries):
        raise CoverageProvenanceError(f"source root has no Python files: {root}")
    return tuple(sorted(entries, key=lambda item: item.relative))


def _git_package_manifest(repo_root: Path) -> tuple[TreeEntry, ...]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-tree", "-r", "-z", "HEAD", "--", "src/aoi_orgware"],
        check=False, capture_output=True,
    )
    if result.returncode:
        raise CoverageProvenanceError("cannot list HEAD package manifest")
    entries: list[TreeEntry] = []
    directories: set[str] = set()
    for row in result.stdout.split(b"\0"):
        if not row:
            continue
        meta, path = row.split(b"\t", 1)
        mode, kind, object_id = meta.decode("ascii").split()
        relative = path.decode("utf-8").removeprefix("src/aoi_orgware/")
        if not relative or relative.startswith("../") or "/../" in relative or kind != "blob" or mode == "120000":
            raise CoverageProvenanceError("invalid Git package entry")
        entries.append(TreeEntry(relative, object_id))
        parts = relative.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    if not entries:
        raise CoverageProvenanceError("HEAD has no tracked aoi_orgware package files")
    entries.extend(_directory_entry(relative) for relative in directories)
    return tuple(sorted(entries, key=lambda item: item.relative))


def _git_worktree_manifest(repo_root: Path, root: Path) -> tuple[TreeEntry, ...]:
    entries: list[TreeEntry] = []
    for entry in _tree_manifest(root):
        if entry.kind == "directory":
            entries.append(entry)
            continue
        relative = entry.relative
        repository_path = f"src/aoi_orgware/{relative}"
        result = subprocess.run(
            ["git", "-C", str(repo_root), "hash-object", "--path", repository_path, str(root / relative)],
            check=False, capture_output=True, text=True,
        )
        if result.returncode:
            raise CoverageProvenanceError(f"cannot hash canonical Git path: {repository_path}")
        entries.append(TreeEntry(relative, result.stdout.strip()))
    return tuple(entries)


def _reject_special_git_flags(repo_root: Path) -> None:
    output = subprocess.run(["git", "-C", str(repo_root), "ls-files", "-v", "-z"], check=True, capture_output=True).stdout
    for row in output.split(b"\0"):
        if row and (chr(row[0]).islower() or row[:1] == b"S"):
            raise CoverageProvenanceError("assume-unchanged or skip-worktree index entry is forbidden")


def _reject_ancestor_reparse(path: Path, label: str) -> None:
    path = path.absolute()
    probe = Path(path.anchor)
    for part in path.parts[1:]:
        probe /= part
        try:
            value = probe.lstat()
        except FileNotFoundError:
            break
        if probe.is_symlink() or _is_reparse(value):
            raise CoverageProvenanceError(f"{label} has a symlink/reparse ancestor: {probe}")


def _root_id(root: Path) -> str:
    value = root.lstat()
    if _is_reparse(value) or root.is_symlink():
        raise CoverageProvenanceError(f"source root is link/reparse point: {root}")
    return f"{value.st_dev:x}:{value.st_ino:x}"


def _identity(path: Path, label: str) -> tuple[int, int, int, str]:
    value = _regular_unlinked(path, label)
    return value.st_dev, value.st_ino, value.st_size, _sha256(path)


def _same_existing_file(left: Path, right: Path) -> bool:
    if not left.exists() or not right.exists():
        return False
    left_value = left.lstat()
    right_value = right.lstat()
    return (left_value.st_dev, left_value.st_ino) == (right_value.st_dev, right_value.st_ino)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except ValueError:
        return False
    return True


def _reject_path_traversal(path: Path, label: str) -> None:
    """Reject lexical ``..`` before path normalization can hide it."""
    if ".." in path.parts:
        raise CoverageProvenanceError(f"{label} must not contain traversal: {path}")


def _reject_windows_path_alias(path: Path, label: str) -> None:
    """Reject Windows namespace and alternate-data-stream path spellings."""
    raw = str(path).replace("/", "\\")
    if raw.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise CoverageProvenanceError(f"{label} must not use a Windows namespace alias: {path}")
    _, tail = ntpath.splitdrive(raw)
    if any(":" in part for part in tail.split("\\") if part):
        raise CoverageProvenanceError(f"{label} must not use a Windows named stream: {path}")


def _preflight_paths(
    *,
    data_dir: Path,
    source_root: Path,
    output_file: Path,
    output_root: Path | None,
    receipt_file: Path,
    lock_path: Path,
    repo_root: Path,
    sitecustomize: Path | None,
) -> None:
    """Reject traversal before allocating the private staging directory."""
    candidates: list[tuple[Path, str]] = [
        (data_dir, "coverage inputs"),
        (source_root, "source root"),
        (output_file, "coverage output"),
        (output_root or output_file.parent, "allowed coverage output root"),
        (receipt_file, "coverage receipt"),
        (lock_path, "coverage lock"),
        (repo_root, "repository"),
    ]
    if sitecustomize is not None:
        candidates.append((sitecustomize, "coverage sitecustomize"))
    for path, label in candidates:
        _reject_path_traversal(path, label)
        _reject_windows_path_alias(path, label)


def _publish_no_replace(path: Path, payload: bytes, label: str) -> tuple[int, int, int, str]:
    """Publish one immutable file, refusing to replace an existing pathname."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise CoverageProvenanceError(f"{label} already exists; refusing replacement: {path}") from exc
    owned_value = os.fstat(descriptor)
    owned_inode = (owned_value.st_dev, owned_value.st_ino)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        # The descriptor is closed by the context manager before this handler.
        # Never unlink a pathname after losing that handle: it may have been
        # replaced.  Preserve the unreceipted orphan and fail closed instead.
        raise
    published = _identity(path, label)
    if (
        published[:2] != owned_inode
        or published[2] != len(payload)
        or published[3] != hashlib.sha256(payload).hexdigest()
    ):
        raise CoverageProvenanceError(f"{label} changed before publication identity was captured: {path}")
    return published


def _validate_publication_targets(
    *,
    output_root: Path,
    output_base: Path,
    receipt_file: Path,
    protected: Iterable[Path],
) -> None:
    """Reject aliases before any publication or cleanup can touch them."""
    _reject_path_traversal(output_root, "allowed coverage output root")
    _reject_path_traversal(output_base, "coverage output base")
    _reject_path_traversal(receipt_file, "coverage receipt")
    _reject_windows_path_alias(output_root, "allowed coverage output root")
    _reject_windows_path_alias(output_base, "coverage output base")
    _reject_windows_path_alias(receipt_file, "coverage receipt")
    output_root = output_root.absolute()
    _reject_ancestor_reparse(output_root, "allowed coverage output root")
    root_value = output_root.lstat()
    if output_root.is_symlink() or _is_reparse(root_value) or not stat.S_ISDIR(root_value.st_mode):
        raise CoverageProvenanceError("allowed coverage output root must be a non-link directory")
    for target, label in ((output_base, "coverage output base"), (receipt_file, "coverage receipt")):
        _reject_ancestor_reparse(target.parent, label)
        if not _inside(target, output_root):
            raise CoverageProvenanceError(f"{label} is outside the allowed output root: {target}")
    if output_base.absolute() == receipt_file.absolute() or _same_existing_file(output_base, receipt_file):
        raise CoverageProvenanceError("coverage output and receipt must be distinct files")
    for item in protected:
        if item.exists() and item.is_dir() and (_inside(output_root, item) or _inside(item, output_root)):
            raise CoverageProvenanceError("allowed coverage output root overlaps protected provenance input")
        for target, label in ((output_base, "coverage output"), (receipt_file, "coverage receipt")):
            if target.absolute() == item.absolute() or _same_existing_file(target, item):
                raise CoverageProvenanceError(f"{label} aliases protected provenance input")


def _manifest_json(entries: Iterable[TreeEntry]) -> list[dict[str, str]]:
    return [{"path": item.relative, "sha256": item.sha256, "kind": item.kind} for item in entries]


def _root_and_relative(filename: str) -> tuple[Path, str]:
    path = Path(filename)
    _reject_windows_path_alias(path, "measured source file")
    _reject_path_traversal(path, "measured source file")
    if not path.is_absolute() or path.suffix != ".py":
        raise CoverageProvenanceError(f"measured file is not an absolute Python source path: {filename}")
    indexes = [index for index, part in enumerate(path.parts) if part == "aoi_orgware"]
    if len(indexes) != 1:
        raise CoverageProvenanceError(f"measured file has ambiguous aoi_orgware root: {filename}")
    index = indexes[0]
    root = Path(*path.parts[: index + 1])
    relative = Path(*path.parts[index + 1 :]).as_posix()
    if not relative:
        raise CoverageProvenanceError(f"measured file is the package directory: {filename}")
    _reject_windows_path_alias(root, "measured source root")
    _reject_path_traversal(root, "measured source root")
    _reject_ancestor_reparse(root, "measured source root")
    _directory_identity(root, "measured source root")
    _reject_ancestor_reparse(path, "measured source file")
    _regular_unlinked(path, "measured source file")
    return root, relative


def _git_identity(repo_root: Path) -> dict[str, object]:
    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise CoverageProvenanceError(
                f"cannot collect Git provenance ({' '.join(args)}): {result.stderr.strip()}"
            )
        return result.stdout

    head = git("rev-parse", "HEAD").strip()
    tree = git("rev-parse", "HEAD^{tree}").strip()
    porcelain = git("status", "--porcelain=v1", "-z")
    return {
        "commit": head,
        "tree": tree,
        "clean": not porcelain,
        "status_sha256": hashlib.sha256(porcelain.encode("utf-8")).hexdigest(),
    }


def _validate_distribution(name: str, version: str, module_file: str | None = None) -> dict[str, object]:
    """Validate every installed wheel payload listed by RECORD."""
    try:
        item = distribution(name)
        record = next(path for path in (item.files or ()) if path.name == "RECORD")
        record_path = Path(item.locate_file(record))
        install_root = Path(item.locate_file(""))
    except Exception as exc:
        raise CoverageProvenanceError(f"locked dependency is not installed with RECORD: {name}") from exc
    if item.version != version:
        raise CoverageProvenanceError(f"locked dependency version drift: {name}={item.version}")
    _regular_unlinked(record_path, f"{name} RECORD")
    rows: list[dict[str, object]] = []
    expected_module = Path(module_file).resolve(strict=True) if module_file is not None else None
    install_root = install_root.resolve(strict=True)
    scripts_root = Path(sysconfig.get_path("scripts")).resolve(strict=True)
    module_seen = expected_module is None
    with record_path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream):
            if len(row) != 3 or not row[0]:
                raise CoverageProvenanceError(f"malformed {name} RECORD row")
            relative, digest, size = row
            relative_path = Path(relative)
            if relative_path.is_absolute() or "\x00" in relative:
                raise CoverageProvenanceError(f"unsafe {name} RECORD path: {relative}")
            # Wheel RECORD may legitimately include console scripts via ../../bin
            # (or ..\\..\\Scripts on Windows), but no other resolved escape.
            payload = (install_root / relative_path).resolve(strict=False)
            if not _inside(payload, install_root) and not _inside(payload, scripts_root):
                raise CoverageProvenanceError(f"unsafe {name} RECORD path escape: {relative}")
            _reject_ancestor_reparse(payload, f"{name} RECORD payload")
            generated_bytecode = "__pycache__" in relative_path.parts and relative_path.suffix == ".pyc"
            if not digest and not size and generated_bytecode:
                # pip may record generated bytecode with no wheel hash. It is
                # not an owned wheel payload, so exclude it from the stable
                # receipt tree; if present it must still be an ordinary file.
                if payload.exists():
                    _regular_unlinked(payload, f"{name} generated bytecode")
                continue
            _regular_unlinked(payload, f"{name} RECORD payload")
            if expected_module is not None and payload == expected_module:
                module_seen = True
            if payload != record_path.resolve(strict=True):
                if not digest.startswith("sha256=") or not size.isdigit():
                    raise CoverageProvenanceError(f"{name} RECORD lacks sha256/size for {relative}")
                expected_digest = base64.urlsafe_b64decode(digest.removeprefix("sha256=") + "===").hex()
                if _sha256(payload) != expected_digest or payload.stat().st_size != int(size):
                    raise CoverageProvenanceError(f"{name} RECORD payload mismatch: {relative}")
            elif digest or size:
                raise CoverageProvenanceError(f"{name} RECORD self-row must omit hash and size")
            rows.append({"path": relative_path.as_posix(), "sha256": _sha256(payload), "size": payload.stat().st_size})
    if not module_seen:
        raise CoverageProvenanceError(f"imported {name} module is not owned by selected distribution RECORD")
    if not rows:
        raise CoverageProvenanceError(f"empty {name} RECORD")
    tree = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "name": name.lower(),
        "version": version,
        "record_sha256": _sha256(record_path),
        "tree_sha256": tree,
        "record_entries": len(rows),
    }


def _validate_toolchain(lock_path: Path) -> dict[str, object]:
    versions = {"coverage": coverage.__version__, "pytest": pytest.__version__}
    expected = {"coverage": EXPECTED_COVERAGE_VERSION, "pytest": EXPECTED_PYTEST_VERSION}
    if versions != expected:
        raise CoverageProvenanceError(f"coverage toolchain drift: expected {expected}, got {versions}")
    _regular_unlinked(lock_path, "coverage lock")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock_path.read_text(encoding="utf-8"), re.MULTILINE)
    if not pins:
        raise CoverageProvenanceError("coverage lock has no pinned packages")
    modules = {"coverage": coverage.__file__, "pytest": pytest.__file__}
    records = []
    for name, version in pins:
        records.append(_validate_distribution(name, version, modules.get(name.lower())))
    return {**versions, "lock_sha256": _sha256(lock_path), "python": sys.version.split()[0], "records": sorted(records, key=lambda row: row["name"])}


def _combine_impl(
    *,
    data_dir: Path,
    source_root: Path,
    output_file: Path,
    output_root: Path | None,
    receipt_file: Path,
    lock_path: Path,
    repo_root: Path,
    expected_root_count: int = 3,
    between_manifests: Callable[[], None] | None = None,
    before_publication: Callable[[], None] | None = None,
    after_output_publication: Callable[[], None] | None = None,
    after_receipt_publication: Callable[[], None] | None = None,
    sitecustomize: Path | None = None,
    stage: Path,
) -> dict[str, object]:
    """Verify, remap, and combine one exact set of parallel coverage files."""
    if expected_root_count < 1:
        raise CoverageProvenanceError("expected root count must be positive")
    _preflight_paths(
        data_dir=data_dir,
        source_root=source_root,
        output_file=output_file,
        output_root=output_root,
        receipt_file=receipt_file,
        lock_path=lock_path,
        repo_root=repo_root,
        sitecustomize=sitecustomize,
    )
    repo_root = repo_root.absolute()
    source_root = source_root.absolute()
    data_dir = data_dir.absolute()
    output_file = output_file.absolute()
    output_root = (output_root or output_file.parent).absolute()
    receipt_file = receipt_file.absolute()
    lock_path = lock_path.absolute()
    for candidate, label in ((repo_root, "repository"), (source_root, "source root"), (data_dir, "coverage inputs"), (output_root, "allowed coverage output root"), (receipt_file.parent, "receipt"), (lock_path, "coverage lock")):
        _reject_ancestor_reparse(candidate, label)
    expected_source = repo_root / "src" / "aoi_orgware"
    if source_root != expected_source:
        raise CoverageProvenanceError("source root must be exactly <repo>/src/aoi_orgware")
    if lock_path.absolute() != repo_root / "requirements" / "coverage-tools.lock":
        raise CoverageProvenanceError("coverage lock must be the repository pinned lock")
    toolchain = _validate_toolchain(lock_path)
    lock_identity = _identity(lock_path, "coverage lock")
    config_path = repo_root / ".coveragerc"
    _regular_unlinked(config_path, "coverage config")
    config_sha256 = _sha256(config_path)
    config_identity = _identity(config_path, "coverage config")
    config_text = config_path.read_text(encoding="utf-8")
    if "source = aoi_orgware" not in config_text or "parallel = true" not in config_text:
        raise CoverageProvenanceError("coverage config does not bind canonical parallel source collection")
    sitecustomize_sha256: str | None = None
    sitecustomize_identity: tuple[int, int, int, str] | None = None
    if sitecustomize is not None:
        _regular_unlinked(sitecustomize, "coverage sitecustomize")
        if "coverage.process_startup()" not in sitecustomize.read_text(encoding="utf-8"):
            raise CoverageProvenanceError("coverage sitecustomize does not start coverage")
        sitecustomize_sha256 = _sha256(sitecustomize)
        sitecustomize_identity = _identity(sitecustomize, "coverage sitecustomize")
    git_identity = _git_identity(repo_root)
    if not git_identity["clean"]:
        raise CoverageProvenanceError("Git worktree must be clean before coverage combine")
    _reject_special_git_flags(repo_root)
    git_package = _git_package_manifest(repo_root)
    canonical_before = _tree_manifest(source_root)
    if _git_worktree_manifest(repo_root, source_root) != git_package:
        raise CoverageProvenanceError("live canonical package differs from HEAD Git manifest")
    data_files = sorted(data_dir.glob(".coverage.*"))
    if not data_files:
        raise CoverageProvenanceError(f"no parallel coverage files found in {data_dir}")
    _validate_publication_targets(
        output_root=output_root,
        output_base=output_file,
        receipt_file=receipt_file,
        protected=(source_root, *data_files, lock_path, config_path, *( [sitecustomize] if sitecustomize is not None else [])),
    )
    output_root_id = _root_id(output_root)

    roots: dict[Path, set[str]] = {}
    inputs: list[dict[str, object]] = []
    input_hashes: dict[Path, str] = {}
    input_ids: dict[Path, tuple[int, int]] = {}
    staged_files: list[Path] = []
    for index, data_file in enumerate(data_files):
        initial_value = _regular_unlinked(data_file, "coverage data")
        initial_id = (initial_value.st_dev, initial_value.st_ino)
        before_hash = _sha256(data_file)
        data = CoverageData(basename=str(data_file))
        data.read()
        measured = sorted(data.measured_files())
        if not measured:
            raise CoverageProvenanceError(f"coverage data has no measured files: {data_file}")
        for filename in measured:
            root, relative = _root_and_relative(filename)
            roots.setdefault(root.absolute(), set()).add(relative)
        if before_hash != _sha256(data_file):
            raise CoverageProvenanceError(f"coverage data changed while inspected: {data_file}")
        inspected_value = data_file.lstat()
        if (inspected_value.st_dev, inspected_value.st_ino) != initial_id:
            raise CoverageProvenanceError(f"coverage data identity changed while inspected: {data_file}")
        input_hashes[data_file] = before_hash
        input_ids[data_file] = initial_id
        inputs.append(
            {
                "input_id": f"input-{index}",
                "sha256": before_hash,
                "measured_relative_paths": sorted(
                    {_root_and_relative(filename)[1] for filename in measured}
                ),
            }
        )
    root_identities = {root: _root_id(root) for root in roots}
    root_ids = set(root_identities.values())
    if len(root_ids) != len(roots):
        raise CoverageProvenanceError("multiple coverage roots resolve to one physical root")
    if len(roots) != expected_root_count:
        raise CoverageProvenanceError(
            f"expected exactly {expected_root_count} aoi_orgware roots, found {len(roots)}"
        )
    canonical_root = source_root
    if canonical_root not in roots:
        raise CoverageProvenanceError("canonical src/aoi_orgware was not measured")

    root_receipts: list[dict[str, object]] = []
    role_roots = [canonical_root] + sorted(
        (root for root in roots if root != canonical_root),
        key=lambda root: (tuple(sorted(roots[root])), _root_id(root)),
    )
    root_roles: dict[Path, str] = {}
    for role_index, root in enumerate(role_roots):
        before = _tree_manifest(root)
        measured_relative = roots[root]
        if measured_relative - {entry.relative for entry in before}:
            raise CoverageProvenanceError(f"measured source is absent from root manifest: {root}")
        if before != canonical_before:
            raise CoverageProvenanceError(f"source root diverges from canonical source: {root}")
        role = "canonical" if role_index == 0 else f"external-{role_index}"
        root_roles[root] = role
        root_receipts.append({"role": role, "manifest": _manifest_json(before)})

    if between_manifests is not None:
        between_manifests()
    if sorted(data_dir.glob(".coverage.*")) != data_files:
        raise CoverageProvenanceError("coverage input set changed during combine")
    for root in roots:
        if _tree_manifest(root) != canonical_before:
            raise CoverageProvenanceError(f"source root changed during combine: {root}")
    if _tree_manifest(source_root) != canonical_before:
        raise CoverageProvenanceError("canonical source changed during combine")

    # Do not copy any coverage input until every measured filename/root has
    # passed the alias and full-ancestor validation above.
    for index, data_file in enumerate(data_files):
        current_value = _regular_unlinked(data_file, "coverage data")
        if (current_value.st_dev, current_value.st_ino) != input_ids[data_file] or _sha256(data_file) != input_hashes[data_file]:
            raise CoverageProvenanceError(f"coverage data changed before staging: {data_file}")
        staged = stage / f"input-{index}"
        shutil.copyfile(data_file, staged)
        _regular_unlinked(staged, "staged coverage data")
        if _sha256(staged) != input_hashes[data_file]:
            raise CoverageProvenanceError("coverage input staging hash mismatch")
        staged_files.append(staged)

    output_temp = stage / "combined.sqlite"
    combined = CoverageData(basename=str(output_temp))
    mappings: list[dict[str, str]] = []

    def map_path(filename: str) -> str:
        root, relative = _root_and_relative(filename)
        root = root.absolute()
        if root not in roots or relative not in roots[root]:
            raise CoverageProvenanceError(f"unverified measured path while combining: {filename}")
        mappings.append({"role": root_roles[root], "path": relative})
        return str(canonical_root / relative)

    for data_file, staged in zip(data_files, staged_files, strict=True):
        _regular_unlinked(data_file, "coverage data")
        value = data_file.lstat()
        if (value.st_dev, value.st_ino) != input_ids[data_file]:
            raise CoverageProvenanceError(f"coverage input identity changed before combine: {data_file}")
        if _sha256(data_file) != input_hashes[data_file]:
            raise CoverageProvenanceError(f"coverage data changed before combine: {data_file}")
        data = CoverageData(basename=str(staged))
        data.read()
        combined.update(data, map_path=map_path)
        if _sha256(data_file) != input_hashes[data_file]:
            raise CoverageProvenanceError(f"coverage data changed during combine: {data_file}")
    combined.write()
    _regular_unlinked(output_temp, "combined coverage temporary")
    combined = CoverageData(basename=str(output_temp))
    combined.read()
    combined_files = sorted(combined.measured_files())
    canonical_files = sorted(str(canonical_root / entry.relative) for entry in canonical_before)
    if any(Path(filename).absolute().parent != canonical_root and canonical_root not in Path(filename).absolute().parents for filename in combined_files):
        raise CoverageProvenanceError("combined data contains a non-canonical source tree")
    if not set(combined_files).issubset(set(canonical_files)):
        raise CoverageProvenanceError("combined data contains a non-canonical measured file")
    if _tree_manifest(source_root) != canonical_before:
        raise CoverageProvenanceError("canonical source changed after combine")
    semantic = []
    for name in combined_files:
        semantic.append(
            {
                "path": Path(name).relative_to(canonical_root).as_posix(),
                "lines": sorted(combined.lines(name) or ()),
                "arcs": sorted(combined.arcs(name) or ()),
                "contexts": [
                    {"line": line, "contexts": sorted(contexts)}
                    for line, contexts in sorted(combined.contexts_by_lineno(name).items())
                ],
            }
        )
    relative_combined_files = [Path(name).relative_to(canonical_root).as_posix() for name in combined_files]
    if before_publication is not None:
        before_publication()
    def assert_stable_inputs() -> None:
        git_after = _git_identity(repo_root)
        if git_after != git_identity or not git_after["clean"]:
            raise CoverageProvenanceError("Git identity changed during coverage combine")
        if (
            # The immutable output itself uses the parallel-data prefix after
            # O_EXCL publication, but it is not a newly supplied input.
            sorted(path for path in data_dir.glob(".coverage.*") if path != output_file) != data_files
            or any(_identity(path, "coverage data")[0:2] != input_ids[path] or _sha256(path) != input_hashes[path] for path in data_files)
        ):
            raise CoverageProvenanceError("coverage inputs changed before publication")
        if (
            _tree_manifest(source_root) != canonical_before
            or any(_root_id(root) != root_identities[root] or _tree_manifest(root) != canonical_before for root in roots)
            or _identity(config_path, "coverage config") != config_identity
            or _identity(lock_path, "coverage lock") != lock_identity
            or _validate_toolchain(lock_path) != toolchain
            or _root_id(output_root) != output_root_id
        ):
            raise CoverageProvenanceError("source/config changed before publication")
        if sitecustomize is not None and _identity(sitecustomize, "coverage sitecustomize") != sitecustomize_identity:
            raise CoverageProvenanceError("coverage sitecustomize changed before publication")

    assert_stable_inputs()
    output_sha256 = _sha256(output_temp)
    output_file = output_root / f"{output_file.name}.{output_sha256}"
    _validate_publication_targets(
        output_root=output_root,
        output_base=output_file,
        receipt_file=receipt_file,
        protected=(source_root, *data_files, lock_path, config_path, *( [sitecustomize] if sitecustomize is not None else [])),
    )
    stable_mappings = [
        {"role": role, "path": relative}
        for role, relative in sorted({(row["role"], row["path"]) for row in mappings})
    ]
    canonical_payload = {
        "schema_version": 1,
        "roots": root_receipts,
        "mappings": stable_mappings,
        "combined_measured_files": relative_combined_files,
        "canonical_manifest": _manifest_json(canonical_before),
        "git_package_manifest": [{"path": item.relative, "git_object": item.sha256} for item in git_package],
        "combined_semantic_sha256": hashlib.sha256(json.dumps(semantic, sort_keys=True).encode()).hexdigest(),
        "coveragerc_sha256": config_sha256,
        "sitecustomize_sha256": sitecustomize_sha256,
        "git": git_identity,
        "toolchain": toolchain,
    }
    receipt = {
        "schema_version": 1,
        "canonical_payload": canonical_payload,
        "canonical_payload_sha256": hashlib.sha256(
            json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "run": {
            "inputs": inputs,
            "combined_output_filename": output_file.name,
            "combined_output_sha256": output_sha256,
            "snapshot_boundary": "cooperative: pre/post identities are checked; writers must not mutate inputs during combine",
        },
    }
    output_identity = _publish_no_replace(output_file, output_temp.read_bytes(), "combined coverage output")
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    receipt_identity: tuple[int, int, int, str] | None = None
    try:
        if after_output_publication is not None:
            after_output_publication()
        assert_stable_inputs()
        receipt_identity = _publish_no_replace(receipt_file, receipt_bytes, "coverage receipt")
        if after_receipt_publication is not None:
            after_receipt_publication()
        assert_stable_inputs()
        readback = json.loads(receipt_file.read_text(encoding="utf-8"))
        if (
            readback != receipt
            or readback["run"]["combined_output_sha256"] != output_identity[3]
            or readback["run"]["combined_output_filename"] != output_file.name
            or _identity(output_file, "combined coverage output") != output_identity
            or _identity(receipt_file, "coverage receipt") != receipt_identity
        ):
            raise CoverageProvenanceError("publication readback did not match captured output and receipt identities")
    except Exception:
        # Publication files are already closed here.  Do not attempt pathname
        # cleanup; an unreceipted orphan is safer than a TOCTOU unlink.
        raise
    return receipt


def _combine(
    *,
    data_dir: Path,
    source_root: Path,
    output_file: Path,
    receipt_file: Path,
    lock_path: Path,
    repo_root: Path,
    output_root: Path | None = None,
    expected_root_count: int = 3,
    between_manifests: Callable[[], None] | None = None,
    before_publication: Callable[[], None] | None = None,
    after_output_publication: Callable[[], None] | None = None,
    after_receipt_publication: Callable[[], None] | None = None,
    sitecustomize: Path | None = None,
) -> dict[str, object]:
    """Run the combine in a private, always-cleaned staging directory."""
    _preflight_paths(
        data_dir=data_dir,
        source_root=source_root,
        output_file=output_file,
        output_root=output_root,
        receipt_file=receipt_file,
        lock_path=lock_path,
        repo_root=repo_root,
        sitecustomize=sitecustomize,
    )
    stage = Path(tempfile.mkdtemp(prefix="aoi-coverage-stage-"))
    os.chmod(stage, stat.S_IRWXU)
    try:
        return _combine_impl(
            data_dir=data_dir,
            source_root=source_root,
            output_file=output_file,
            output_root=output_root,
            receipt_file=receipt_file,
            lock_path=lock_path,
            repo_root=repo_root,
            expected_root_count=expected_root_count,
            between_manifests=between_manifests,
            before_publication=before_publication,
            after_output_publication=after_output_publication,
            after_receipt_publication=after_receipt_publication,
            sitecustomize=sitecustomize,
            stage=stage,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def combine(**kwargs: object) -> dict[str, object]:
    return _combine(**kwargs)  # type: ignore[arg-type]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path("src/aoi_orgware"))
    parser.add_argument("--output-file", type=Path, default=Path("covdata/.coverage"))
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--receipt", type=Path, default=Path("covdata/coverage-provenance.json"))
    parser.add_argument("--lock", type=Path, default=Path("requirements/coverage-tools.lock"))
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--expected-root-count", type=int, default=3)
    parser.add_argument("--sitecustomize", type=Path)
    args = parser.parse_args(argv)
    try:
        combine(
            data_dir=args.data_dir,
            source_root=args.source_root,
            output_file=args.output_file,
            output_root=args.output_root,
            receipt_file=args.receipt,
            lock_path=args.lock,
            repo_root=args.repo_root,
            expected_root_count=args.expected_root_count,
            sitecustomize=args.sitecustomize,
        )
    except CoverageProvenanceError as exc:
        print(f"coverage provenance failure: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
