"""State-backup command family: syntax registration and command bodies.

This module owns the ``backup-state`` and ``verify-backup`` command
implementations together with their archive/verification helpers.  It stays a
leaf of the composition root: it imports only sibling packages (``harnesslib``)
and the standard library, never the monolithic :mod:`aoi_orgware.cli`.  The CLI
imports the command bodies back for handler wiring (and ``_check_json_file`` for
``cmd_doctor``) and keeps the mutable-constant/factory composition root.
``emit`` and ``require_text`` are pure leaf helpers redeclared module-locally
(neither project-mutable nor test-patched), mirroring the sibling extraction
precedent.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import tarfile
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    atomic_write_bytes,
    atomic_write_json,
    fsync_directory,
    load_json,
    sha256_file,
    state_lock,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"backup_state", "verify_backup"})


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif isinstance(payload, str):
        print(payload)
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def _check_json_file(path: Path, errors: list[str]) -> None:
    try:
        load_json(path)
    except HarnessError as exc:
        errors.append(str(exc))


def _backup_sources(paths: HarnessPaths) -> list[tuple[str, Path]]:
    sources: list[tuple[str, Path]] = []

    def add_file(archive_name: str, source: Path) -> None:
        if not source.exists():
            return
        if source.is_symlink() or not source.is_file() or source.stat().st_nlink != 1:
            raise HarnessError(f"backup source must be one regular non-linked file: {source}")
        sources.append((archive_name, source))

    def add_tree(prefix: str, source_root: Path) -> None:
        if not source_root.exists():
            return
        for source in sorted(source_root.rglob("*"), key=lambda item: item.as_posix()):
            if source.name == ".state.lock" or "__pycache__" in source.parts:
                continue
            if source.suffix == ".pyc":
                continue
            if source.is_symlink():
                raise HarnessError(f"backup source tree contains symlink: {source}")
            if source.is_file():
                if source.stat().st_nlink != 1:
                    raise HarnessError(f"backup source has multiple hard links: {source}")
                relative = source.relative_to(source_root).as_posix()
                sources.append((f"{prefix}/{relative}", source))

    add_file("project/aoi.toml", paths.config)
    add_tree("project/state", paths.harness)
    names = [name for name, _ in sources]
    if len(names) != len(set(names)):
        raise HarnessError("backup allowlist produced duplicate archive names")
    return sorted(sources, key=lambda item: item[0])


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _build_backup_archive(paths: HarnessPaths) -> tuple[bytes, dict[str, Any]]:
    members: list[tuple[str, bytes]] = []
    manifest_members: list[dict[str, Any]] = []
    for name, source in _backup_sources(paths):
        payload = source.read_bytes()
        members.append((name, payload))
        manifest_members.append(
            {"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        )
    manifest = {"format_version": 1, "members": manifest_members}
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        + b"\n"
    )
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(_tarinfo("manifest.json", len(manifest_bytes)), io.BytesIO(manifest_bytes))
        for name, payload in members:
            archive.addfile(_tarinfo(name, len(payload)), io.BytesIO(payload))
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gzip_buffer, mtime=0) as zipped:
        zipped.write(tar_buffer.getvalue())
    return gzip_buffer.getvalue(), manifest


def verify_backup(archive_path: Path, sidecar_path: Path) -> dict[str, Any]:
    sidecar = load_json(sidecar_path)
    archive_sha = sha256_file(archive_path)
    if sidecar.get("format_version") != 1 or sidecar.get("archive_sha256") != archive_sha:
        raise HarnessError("backup sidecar does not match archive SHA-256")
    seen: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or member.name in seen
            ):
                raise HarnessError(f"unsafe or duplicate backup member: {member.name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise HarnessError(f"backup member cannot be read: {member.name}")
            seen[member.name] = handle.read()
    manifest_bytes = seen.pop("manifest.json", None)
    if manifest_bytes is None:
        raise HarnessError("backup archive lacks manifest.json")
    if hashlib.sha256(manifest_bytes).hexdigest() != sidecar.get("manifest_sha256"):
        raise HarnessError("backup internal manifest SHA-256 mismatch")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"invalid backup internal manifest: {exc}") from exc
    members = manifest.get("members")
    if manifest.get("format_version") != 1 or not isinstance(members, list):
        raise HarnessError("backup internal manifest has an unsupported schema")
    expected: dict[str, dict[str, Any]] = {}
    for item in members:
        if not isinstance(item, dict):
            raise HarnessError("backup internal manifest member is not an object")
        name = str(item.get("path", ""))
        path = PurePosixPath(name)
        if not name or path.is_absolute() or ".." in path.parts or name in expected:
            raise HarnessError(f"unsafe or duplicate backup manifest member: {name!r}")
        expected[name] = item
    if set(expected) != set(seen):
        raise HarnessError("backup member set differs from internal manifest")
    if sidecar.get("member_count") != len(expected):
        raise HarnessError("backup sidecar member count differs from internal manifest")
    for name, payload in seen.items():
        item = expected[name]
        if item.get("size") != len(payload) or item.get("sha256") != hashlib.sha256(
            payload
        ).hexdigest():
            raise HarnessError(f"backup member hash mismatch: {name}")
    return {
        "archive": str(archive_path),
        "archive_sha256": archive_sha,
        "manifest": str(sidecar_path),
        "member_count": len(seen),
        "verified": True,
    }


def cmd_backup_state(args: argparse.Namespace, paths: HarnessPaths) -> int:
    configured_raw = Path(
        os.environ.get(
            "AOI_BACKUP_ROOT",
            str(Path.home() / ".local" / "state" / "aoi" / "backups" / paths.root.name),
        )
    ).expanduser()
    requested_raw = Path(args.destination).expanduser() if args.destination else configured_raw
    if not configured_raw.is_absolute() or not requested_raw.is_absolute():
        raise HarnessError("backup root and destination must be absolute paths")
    if ".." in requested_raw.parts:
        raise HarnessError("backup destination may not contain '..'")
    configured_root = configured_raw.resolve()
    destination = requested_raw.resolve()
    if destination != configured_root and configured_root not in destination.parents:
        raise HarnessError(f"backup destination must stay within {configured_root}")
    if destination == paths.root or paths.root in destination.parents:
        raise HarnessError("backup destination may not be inside the implementation repo")
    current = requested_raw
    while True:
        if current.exists() and current.is_symlink():
            raise HarnessError(f"backup destination path may not contain symlinks: {current}")
        if current == configured_raw or current.parent == current:
            break
        current = current.parent
    destination.mkdir(parents=True, exist_ok=True)
    with state_lock(paths):
        archive_bytes, manifest = _build_backup_archive(paths)
    archive_sha = hashlib.sha256(archive_bytes).hexdigest()
    archive_path = destination / f"aoi-state-{archive_sha[:16]}.tar.gz"
    sidecar_path = archive_path.with_suffix(archive_path.suffix + ".manifest.json")
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        + b"\n"
    )
    sidecar = {
        "format_version": 1,
        "archive": archive_path.name,
        "archive_sha256": archive_sha,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "member_count": len(manifest["members"]),
        "durability_boundary": "same-host recovery copy; not off-host disaster recovery",
    }
    if archive_path.exists() or sidecar_path.exists():
        if not (archive_path.exists() and sidecar_path.exists()):
            raise HarnessError("backup publication is incomplete; archive/sidecar pair differs")
        result = verify_backup(archive_path, sidecar_path)
        result["existing"] = True
        emit(result, args.json)
        return 0
    atomic_write_bytes(archive_path, archive_bytes)
    atomic_write_json(sidecar_path, sidecar)
    fsync_directory(destination)
    result = verify_backup(archive_path, sidecar_path)
    result["existing"] = False
    emit(result, args.json)
    return 0


def cmd_verify_backup(args: argparse.Namespace, paths: HarnessPaths) -> int:
    sidecar = Path(args.manifest).resolve()
    payload = load_json(sidecar)
    archive_name = require_text(str(payload.get("archive", "")), "archive name")
    archive_posix = PurePosixPath(archive_name)
    if archive_posix.name != archive_name or "\\" in archive_name:
        raise HarnessError("backup sidecar archive must be a plain filename")
    archive = sidecar.parent / archive_name
    result = verify_backup(archive, sidecar)
    emit(result, args.json)
    return 0


def register_backup_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``backup-state`` and ``verify-backup``."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "backup command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("backup-state")
    parser.add_argument("--destination")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["backup_state"])

    parser = subparsers.add_parser("verify-backup")
    parser.add_argument("--manifest", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["verify_backup"])


__all__ = [
    "cmd_backup_state",
    "cmd_verify_backup",
    "register_backup_commands",
    "verify_backup",
]
