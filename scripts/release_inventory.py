#!/usr/bin/env python3
"""Capture and enforce the exact distribution files allowed for publication.

The inventory deliberately records only artifact *names*.  Callers provide a
directory root explicitly, so this tool never turns a wildcard or an arbitrary
path from an untrusted inventory into a publish input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_AGGREGATE_BYTES = 128 * 1024 * 1024
MAX_INVENTORY_BYTES = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DISTRIBUTION = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*"
    r"(?:(?:a|b|rc)(?:0|[1-9][0-9]*))?"
    r"(?:\.post(?:0|[1-9][0-9]*))?"
    r"(?:\.dev(?:0|[1-9][0-9]*))?"
    r"(?:\+[a-z0-9]+(?:[.-][a-z0-9]+)*)?\Z"
)
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", "CLOCK$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class InventoryError(RuntimeError):
    """The inventory or its files cannot be used for a release."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _secure_directory(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        info = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except FileNotFoundError as exc:
        raise InventoryError(f"{label} does not exist: {path}") from exc
    except OSError as exc:
        raise InventoryError(f"cannot resolve {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
        raise InventoryError(f"{label} must be a real directory, not a link: {path}")
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        raise InventoryError(f"{label} must not traverse a link or alias: {path}")
    return absolute


def _validate_name(name: object) -> str:
    if not isinstance(name, str) or not name or len(name) > 240:
        raise InventoryError("artifact name must be a nonempty short string")
    if _contains_control(name) or name in {".", ".."}:
        raise InventoryError(f"unsafe artifact name: {name!r}")
    if "/" in name or "\\" in name or ":" in name or name.endswith((".", " ")):
        raise InventoryError(f"unsafe artifact name: {name!r}")
    if Path(name).name != name:
        raise InventoryError(f"unsafe artifact name: {name!r}")
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise InventoryError(f"Windows-reserved artifact name: {name!r}")
    return name


def _artifact_kind(name: str) -> str:
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith(".tar.gz"):
        return "sdist"
    raise InventoryError(f"unsupported distribution artifact: {name!r}")


def _validate_artifact_filename(name: str, distribution_name: str, package_version: str) -> str:
    kind = _artifact_kind(name)
    archive_prefix = f"{distribution_name.replace('-', '_')}-{package_version}"
    if kind == "sdist":
        if name != f"{archive_prefix}.tar.gz":
            raise InventoryError("sdist filename does not match inventory distribution/version")
        return kind
    if not name.startswith(archive_prefix + "-") or not name.endswith(".whl"):
        raise InventoryError("wheel filename does not match inventory distribution/version")
    tags = name[len(archive_prefix) + 1 : -4].split("-")
    if len(tags) == 4:
        build_tag = tags.pop(0)
        # PEP 427 build tags are optional, but when present must sort after a
        # wheel with no build tag: they therefore begin with an ASCII digit.
        if re.fullmatch(r"[0-9][A-Za-z0-9_]*", build_tag) is None:
            raise InventoryError("wheel filename has an invalid build tag")
    if len(tags) != 3 or any(
        not tag or re.fullmatch(r"[A-Za-z0-9_.]+", tag) is None for tag in tags
    ):
        raise InventoryError("wheel filename has invalid build or compatibility tags")
    return kind


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return the stable identity fields available on POSIX and Windows."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_nlink,
        getattr(info, "st_file_attributes", 0),
    )


def _file_digest(path: Path, *, expected_size: int | None = None) -> tuple[int, str]:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise InventoryError(f"artifact is missing: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or _is_reparse_point(before):
        raise InventoryError(f"artifact must not be a link: {path.name}")
    if not stat.S_ISREG(before.st_mode):
        raise InventoryError(f"artifact is not a regular file: {path.name}")
    if before.st_nlink != 1:
        raise InventoryError(f"artifact must not be hard-linked: {path.name}")
    if before.st_size <= 0 or before.st_size > MAX_ARTIFACT_BYTES:
        raise InventoryError(f"artifact has invalid size: {path.name}")
    if expected_size is not None and before.st_size != expected_size:
        raise InventoryError(f"artifact size changed: {path.name}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if _is_reparse_point(opened) or _identity(opened) != _identity(before):
                raise InventoryError(f"artifact changed while opening: {path.name}")
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise InventoryError(f"cannot read artifact: {path.name}") from exc
    after = path.lstat()
    if _identity(after) != _identity(before):
        raise InventoryError(f"artifact changed while hashing: {path.name}")
    return before.st_size, digest.hexdigest()


def _read_inventory_file(path: Path) -> bytes:
    """Read a small inventory without following a final-path link or race."""
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise InventoryError(f"inventory does not exist: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or _is_reparse_point(before) or not stat.S_ISREG(before.st_mode):
        raise InventoryError("inventory must be a real regular file, not a link")
    if before.st_nlink != 1 or not 0 < before.st_size <= MAX_INVENTORY_BYTES:
        raise InventoryError("inventory has invalid size or link count")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            identity = _identity(before)
            if _is_reparse_point(opened) or _identity(opened) != identity:
                raise InventoryError("inventory changed while opening")
            raw = handle.read(MAX_INVENTORY_BYTES + 1)
    except OSError as exc:
        raise InventoryError(f"cannot read inventory: {path}") from exc
    after = path.lstat()
    if _identity(after) != identity:
        raise InventoryError("inventory changed while reading")
    return raw


def _validate_distribution(value: object) -> str:
    if not isinstance(value, str) or not _DISTRIBUTION.fullmatch(value):
        raise InventoryError("distribution_name must be a canonical lowercase name")
    return value


def _validate_version(value: object) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise InventoryError("package_version must be a canonical normalized release version")
    return value


def _payload(inventory: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in inventory.items() if key != "inventory_sha256"}


def _validate_inventory(inventory: object) -> dict[str, Any]:
    if not isinstance(inventory, dict):
        raise InventoryError("inventory must be a JSON object")
    expected_keys = {
        "schema_version", "distribution_name", "package_version", "artifacts", "inventory_sha256",
    }
    if set(inventory) != expected_keys:
        raise InventoryError("inventory has unexpected or missing fields")
    if inventory["schema_version"] != SCHEMA_VERSION:
        raise InventoryError("unsupported inventory schema_version")
    _validate_distribution(inventory["distribution_name"])
    _validate_version(inventory["package_version"])
    recorded_digest = inventory["inventory_sha256"]
    if not isinstance(recorded_digest, str) or not _SHA256.fullmatch(recorded_digest):
        raise InventoryError("inventory_sha256 must be a lowercase SHA-256")
    artifacts = inventory["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise InventoryError("inventory must contain exactly two artifacts")
    names: list[str] = []
    kinds: list[str] = []
    aggregate = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"name", "size_bytes", "sha256"}:
            raise InventoryError("artifact has unexpected or missing fields")
        name = _validate_name(artifact["name"])
        names.append(name)
        kinds.append(
            _validate_artifact_filename(
                name,
                inventory["distribution_name"],
                inventory["package_version"],
            )
        )
        size = artifact["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_BYTES:
            raise InventoryError(f"invalid artifact size: {name}")
        aggregate += size
        if aggregate > MAX_ARTIFACT_AGGREGATE_BYTES:
            raise InventoryError("artifacts exceed their aggregate byte bound")
        digest = artifact["sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise InventoryError(f"invalid artifact sha256: {name}")
    if names != sorted(names) or len({name.casefold() for name in names}) != len(names):
        raise InventoryError("artifact names must be sorted and casefold-unique")
    if sorted(kinds) != ["sdist", "wheel"]:
        raise InventoryError("inventory requires exactly one wheel and one .tar.gz sdist")
    if hashlib.sha256(_canonical_json(_payload(inventory))).hexdigest() != recorded_digest:
        raise InventoryError("inventory_sha256 does not match inventory content")
    return inventory


def load_inventory(path: Path) -> dict[str, Any]:
    raw = _read_inventory_file(path)
    if not raw or len(raw) > MAX_INVENTORY_BYTES:
        raise InventoryError("inventory has invalid size")
    try:
        decoded = raw.decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("inventory is not valid UTF-8 JSON") from exc
    inventory = _validate_inventory(parsed)
    if raw != _canonical_json(inventory):
        raise InventoryError("inventory JSON is not canonical")
    return inventory


def _clean_entries(root: Path) -> list[Path]:
    _secure_directory(root, label="artifact root")
    entries = sorted(root.iterdir(), key=lambda item: item.name)
    if not entries:
        raise InventoryError("artifact root is empty")
    for entry in entries:
        _validate_name(entry.name)
    return entries


def capture(dist_dir: Path, *, distribution_name: str, package_version: str) -> dict[str, Any]:
    distribution_name = _validate_distribution(distribution_name)
    package_version = _validate_version(package_version)
    root = _secure_directory(dist_dir, label="dist directory")
    entries = _clean_entries(root)
    artifacts: list[dict[str, Any]] = []
    aggregate = 0
    for entry in entries:
        name = _validate_name(entry.name)
        _validate_artifact_filename(name, distribution_name, package_version)
        size, digest = _file_digest(entry)
        aggregate += size
        if aggregate > MAX_ARTIFACT_AGGREGATE_BYTES:
            raise InventoryError("artifacts exceed their aggregate byte bound")
        artifacts.append({"name": name, "size_bytes": size, "sha256": digest})
    artifacts.sort(key=lambda item: item["name"])
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "distribution_name": distribution_name,
        "package_version": package_version,
        "artifacts": artifacts,
    }
    inventory = {
        **payload,
        "inventory_sha256": hashlib.sha256(_canonical_json(payload)).hexdigest(),
    }
    return _validate_inventory(inventory)


def verify(inventory: dict[str, Any], root: Path) -> None:
    inventory = _validate_inventory(inventory)
    artifact_root = _secure_directory(root, label="artifact root")
    expected = {artifact["name"]: artifact for artifact in inventory["artifacts"]}
    entries = _clean_entries(artifact_root)
    actual = {entry.name: entry for entry in entries}
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        detail = ([f"missing={','.join(missing)}"] if missing else []) + ([f"extra={','.join(extra)}"] if extra else [])
        raise InventoryError("artifact root does not exactly match inventory: " + "; ".join(detail))
    if len({name.casefold() for name in actual}) != len(actual):
        raise InventoryError("artifact root has casefold-colliding names")
    for name, artifact in expected.items():
        size, digest = _file_digest(actual[name], expected_size=artifact["size_bytes"])
        if size != artifact["size_bytes"] or digest != artifact["sha256"]:
            raise InventoryError(f"artifact hash does not match inventory: {name}")


def _copy_exact(source: Path, destination: Path, size: int, sha256: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before = source.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse_point(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != size
        ):
            raise InventoryError(f"artifact changed before staging: {source.name}")
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise InventoryError(f"cannot safely open artifact for staging: {source.name}") from exc
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as input_handle, destination.open("xb", buffering=0) as output_handle:
            opened = os.fstat(input_handle.fileno())
            if _is_reparse_point(opened) or _identity(opened) != _identity(before):
                raise InventoryError(f"artifact changed while opening for staging: {source.name}")
            copied = 0
            digest = hashlib.sha256()
            while chunk := input_handle.read(1024 * 1024):
                copied += len(chunk)
                digest.update(chunk)
                output_handle.write(chunk)
    except OSError as exc:
        raise InventoryError(f"cannot stage artifact: {source.name}") from exc
    if copied != size:
        raise InventoryError(f"artifact changed during staging: {source.name}")
    try:
        after = source.lstat()
    except OSError as exc:
        raise InventoryError(f"cannot recheck staged artifact: {source.name}") from exc
    if _identity(after) != _identity(before) or digest.hexdigest() != sha256:
        raise InventoryError(f"artifact changed during staging: {source.name}")


def stage(inventory: dict[str, Any], source_root: Path, destination_root: Path) -> dict[str, Any]:
    inventory = _validate_inventory(inventory)
    verify(inventory, source_root)
    if destination_root.exists():
        if destination_root.is_symlink() or not destination_root.is_dir():
            raise InventoryError("destination_root must be a new real directory")
        if any(destination_root.iterdir()):
            raise InventoryError("destination_root must be empty")
    else:
        _secure_directory(destination_root.parent, label="destination_root parent")
        destination_root.mkdir(parents=True, exist_ok=False)
    destination = _secure_directory(destination_root, label="destination_root")
    try:
        for artifact in inventory["artifacts"]:
            source = source_root / artifact["name"]
            target = destination / artifact["name"]
            _copy_exact(source, target, artifact["size_bytes"], artifact["sha256"])
        verify(inventory, destination)
    except Exception:
        # Preserve the created directory for forensic inspection, but never report success.
        raise
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "distribution_name": inventory["distribution_name"],
        "package_version": inventory["package_version"],
        "inventory_sha256": inventory["inventory_sha256"],
        "staged_artifacts": inventory["artifacts"],
    }
    receipt["stage_receipt_sha256"] = hashlib.sha256(_canonical_json(receipt)).hexdigest()
    return receipt


def _write_canonical(path: Path, value: object) -> None:
    encoded = _canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(encoded)
    except FileExistsError as exc:
        raise InventoryError(f"refusing to overwrite output: {path}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--dist-dir", required=True, type=Path)
    capture_parser.add_argument("--distribution-name", required=True)
    capture_parser.add_argument("--package-version", required=True)
    capture_parser.add_argument("--output", required=True, type=Path)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--inventory", required=True, type=Path)
    verify_parser.add_argument("--root", required=True, type=Path)
    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--inventory", required=True, type=Path)
    stage_parser.add_argument("--source-root", required=True, type=Path)
    stage_parser.add_argument("--destination-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "capture":
            _write_canonical(
                args.output,
                capture(args.dist_dir, distribution_name=args.distribution_name, package_version=args.package_version),
            )
            return 0
        inventory = load_inventory(args.inventory)
        if args.command == "verify":
            verify(inventory, args.root)
            return 0
        receipt = stage(inventory, args.source_root, args.destination_root)
        sys.stdout.buffer.write(_canonical_json(receipt))
        return 0
    except (InventoryError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
