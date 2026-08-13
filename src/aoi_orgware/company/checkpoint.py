"""Plain, immutable company checkpoint export.

This module deliberately does not acquire a company lock or open a Supervisor.
The caller supplies the already-owned company context, the authoritative ledger,
and the blob store.  A checkpoint contains only the pointer, manifest, verified
plain ledger copy, and BlobRefs reachable from the ledger; the read model is
intentionally excluded because it is replaceable.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import ctypes
from dataclasses import dataclass
from datetime import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
from typing import Any
import uuid

from .blobs import BlobStore, BlobStoreError
from .contracts import (
    BLOB_REF_V1,
    ZERO_SHA256,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_manifest,
)
from .ledger import CompanyLedger, LedgerHeadsSnapshot, LedgerTransactionRecord
from .readmodel import CompanyReadModel
from .registry import CompanyLockWitness, ResolvedCompanyState


CHECKPOINT_SCHEMA_VERSION = 1
_CHECKPOINT_NAME = "checkpoint-manifest.json"
_CHECKPOINT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_LEDGER_BYTES = 512 * 1024 * 1024
_MAX_BLOB_MEMBERS = 1024
_MAX_BLOB_BYTES = 512 * 1024 * 1024
_MAX_SINGLE_BLOB_BYTES = 64 * 1024 * 1024
_STAGE_PREFIX = ".c-"


class CompanyCheckpointError(RuntimeError):
    """A company checkpoint cannot be published or verified safely."""


@dataclass(frozen=True)
class VerifiedCompanyCheckpoint:
    """The immutable result returned by the pure checkpoint verifier."""

    path: Path
    sha256: str
    manifest: Mapping[str, Any]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_owned(lock: CompanyLockWitness) -> None:
    try:
        lock.assert_owned()
    except Exception as exc:
        raise CompanyCheckpointError("company lock witness is not owned") from exc


def _assert_lock_binding(
    lock: CompanyLockWitness,
    resolved: ResolvedCompanyState,
) -> None:
    _assert_owned(lock)
    supplied = getattr(lock, "path", None)
    if not isinstance(supplied, Path) or not _same_path(
        supplied,
        resolved.slot.lock,
    ):
        raise CompanyCheckpointError(
            "company lock witness differs from the active company slot",
        )


def _is_reparse(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if not isinstance(attributes, int) or not isinstance(flag, int):
        raise CompanyCheckpointError("Windows reparse-point inspection is unavailable")
    return bool(attributes & flag)


def _regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CompanyCheckpointError(f"{label} is unavailable: {path}") from exc
    if _is_reparse(metadata) or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CompanyCheckpointError(f"{label} must be a regular non-link file")
    if metadata.st_nlink != 1:
        raise CompanyCheckpointError(f"{label} must not have multiple hard links")
    return metadata


def _directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CompanyCheckpointError(f"{label} is unavailable: {path}") from exc
    if _is_reparse(metadata) or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CompanyCheckpointError(f"{label} must be a directory, not a link")
    return metadata


def _fsync_directory(path: Path) -> None:
    """Durably order directory entries where the platform supports it."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CompanyCheckpointError("checkpoint directory fsync cannot be opened") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise CompanyCheckpointError("checkpoint directory fsync failed") from exc
    finally:
        os.close(descriptor)


def _publish_no_replace(stage: Path, target: Path) -> None:
    """Atomically publish a staged directory without an overwrite fallback.

    Windows ``MoveFile`` semantics exposed by :func:`os.rename` already reject
    an existing target.  Linux uses ``renameat2(RENAME_NOREPLACE)``; platforms
    without an equivalent primitive fail closed instead of relying on a
    time-of-check/time-of-use existence check.
    """
    if os.name == "nt":
        os.rename(stage, target)
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise CompanyCheckpointError("atomic no-replace publication is unavailable") from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(-100, os.fsencode(stage), -100, os.fsencode(target), 1)
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, os.strerror(error), os.fspath(target))
    raise OSError(error, os.strerror(error), os.fspath(target))


def _checkpoint_id(value: object) -> str:
    if not isinstance(value, str) or _CHECKPOINT_ID.fullmatch(value) is None:
        raise CompanyCheckpointError("checkpoint ID is invalid")
    return value


def _absolute_root(value: str | os.PathLike[str], label: str) -> Path:
    root = Path(value)
    if not root.is_absolute() or ".." in root.parts:
        raise CompanyCheckpointError(f"{label} must be an absolute traversal-free path")
    return root


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(
        os.path.abspath(os.fspath(left)),
    ) == os.path.normcase(
        os.path.abspath(os.fspath(right)),
    )


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise CompanyCheckpointError("checkpoint generated_at is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise CompanyCheckpointError("checkpoint generated_at is invalid") from exc
    if parsed.tzinfo is None:
        raise CompanyCheckpointError("checkpoint generated_at lacks a timezone")
    return value


def _canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise CompanyCheckpointError(f"{label} exceeds its byte bound")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CompanyCheckpointError(f"{label} is not canonical JSON") from exc
    try:
        canonical = canonical_company_json_bytes(
            value,
            max_bytes=_MAX_MANIFEST_BYTES,
        )
    except CompanyContractError as exc:
        raise CompanyCheckpointError(
            f"{label} is not canonical JSON",
        ) from exc
    if not isinstance(value, dict) or canonical != raw:
        raise CompanyCheckpointError(f"{label} is not canonical JSON")
    return value


def _read_regular(
    path: Path,
    label: str,
    *,
    max_bytes: int = _MAX_MANIFEST_BYTES,
) -> bytes:
    metadata = _regular(path, label)
    if metadata.st_size > max_bytes:
        raise CompanyCheckpointError(f"{label} exceeds its byte bound")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CompanyCheckpointError(f"cannot read {label}") from exc
    if len(raw) != int(metadata.st_size):
        raise CompanyCheckpointError(f"{label} changed while read")
    return raw


def _stream_digest(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[str, int]:
    metadata = _regular(path, label)
    size = int(metadata.st_size)
    if size > max_bytes:
        raise CompanyCheckpointError(f"{label} exceeds its byte bound")
    digest = hashlib.sha256()
    observed = 0
    try:
        with path.open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                observed += len(block)
                if observed > max_bytes:
                    raise CompanyCheckpointError(
                        f"{label} exceeds its byte bound",
                    )
                digest.update(block)
    except CompanyCheckpointError:
        raise
    except OSError as exc:
        raise CompanyCheckpointError(f"cannot read {label}") from exc
    if observed != size:
        raise CompanyCheckpointError(f"{label} changed while read")
    return digest.hexdigest(), observed


def _validated_pointer(value: Mapping[str, Any]) -> Mapping[str, Any]:
    required = {
        "schema_version", "company_id", "incarnation_id", "company_incarnation",
        "lock_domain_generation", "manifest_sha256", "updated_at",
        "previous_pointer_sha256", "pointer_sha256",
    }
    if set(value) != required or value.get("schema_version") != 1:
        raise CompanyCheckpointError("company current pointer schema is invalid")
    if (
        not isinstance(value["company_id"], str)
        or not isinstance(value["incarnation_id"], str)
        or not isinstance(value["company_incarnation"], int)
        or isinstance(value["company_incarnation"], bool)
        or value["company_incarnation"] < 1
        or not isinstance(value["lock_domain_generation"], int)
        or isinstance(value["lock_domain_generation"], bool)
        or value["lock_domain_generation"] < 1
        or any(not isinstance(value[key], str) or _SHA256.fullmatch(value[key]) is None for key in ("manifest_sha256", "previous_pointer_sha256", "pointer_sha256"))
    ):
        raise CompanyCheckpointError("company current pointer fields are invalid")
    _timestamp(value["updated_at"])
    unsigned = {key: value[key] for key in required if key != "pointer_sha256"}
    if company_contract_sha256(unsigned) != value["pointer_sha256"]:
        raise CompanyCheckpointError("company current pointer digest differs")
    expected_incarnation = f"i{value['company_incarnation']:08d}-{value['manifest_sha256'][:12]}"
    if value["incarnation_id"] != expected_incarnation:
        raise CompanyCheckpointError("company current pointer incarnation binding differs")
    if (value["company_incarnation"] == 1) != (value["previous_pointer_sha256"] == ZERO_SHA256):
        raise CompanyCheckpointError("company current pointer predecessor differs")
    return value


def _pointer_and_manifest(
    resolved: ResolvedCompanyState,
) -> tuple[bytes, bytes, dict[str, Any], dict[str, Any]]:
    pointer_raw = _read_regular(resolved.slot.current, "active current pointer")
    manifest_raw = _read_regular(resolved.incarnation.manifest, "active company manifest")
    pointer = _validated_pointer(_canonical_json(pointer_raw, "active current pointer"))
    manifest = _canonical_json(manifest_raw, "active company manifest")
    try:
        normalized_manifest = validate_company_manifest(manifest)
    except CompanyContractError as exc:
        raise CompanyCheckpointError("active company manifest is invalid") from exc
    expected = resolved.pointer
    binding = (
        str(normalized_manifest["company_id"]),
        int(normalized_manifest["company_incarnation"]),
        int(normalized_manifest["lock_domain_generation"]),
    )
    if (
        binding
        != (expected.company_id, expected.company_incarnation, expected.lock_domain_generation)
        or _sha256(manifest_raw) != expected.manifest_sha256
        or pointer.get("pointer_sha256") != expected.pointer_sha256
        or pointer.get("company_id") != expected.company_id
        or pointer.get("company_incarnation") != expected.company_incarnation
        or pointer.get("lock_domain_generation") != expected.lock_domain_generation
        or pointer.get("manifest_sha256") != expected.manifest_sha256
    ):
        raise CompanyCheckpointError("active pointer and manifest differ from caller context")
    return pointer_raw, manifest_raw, dict(pointer), normalized_manifest


def _available_blob_refs(value: object) -> tuple[Mapping[str, Any], ...]:
    references: list[Mapping[str, Any]] = []

    def visit(member: object) -> None:
        if isinstance(member, Mapping):
            if member.get("contract_type") == BLOB_REF_V1:
                if member.get("availability") == "available":
                    references.append(member)
                return
            for child in member.values():
                visit(child)
        elif isinstance(member, Sequence) and not isinstance(member, (str, bytes, bytearray)):
            for child in member:
                visit(child)

    visit(value)
    return tuple(references)


def _blob_members(records: Sequence[LedgerTransactionRecord]) -> dict[str, int]:
    result: dict[str, int] = {}
    for record in records:
        for reference in _available_blob_refs((
            record.request,
            record.receipt,
            tuple(item.event for item in record.events),
            tuple(item.event for item in record.reservations),
        )):
            digest = reference.get("sha256")
            size = reference.get("size_bytes")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                raise CompanyCheckpointError("reachable BlobRef digest is invalid")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise CompanyCheckpointError("reachable BlobRef size is invalid")
            previous = result.setdefault(digest, size)
            if previous != size:
                raise CompanyCheckpointError("reachable BlobRef has conflicting sizes")
    return result


def _bounded_blob_members(
    records: Sequence[LedgerTransactionRecord],
) -> dict[str, int]:
    result = _blob_members(records)
    if len(result) > _MAX_BLOB_MEMBERS:
        raise CompanyCheckpointError(
            "checkpoint reachable blob count exceeds its bound",
        )
    if sum(result.values()) > _MAX_BLOB_BYTES:
        raise CompanyCheckpointError(
            "checkpoint reachable blob bytes exceed their bound",
        )
    return result


def _heads_from_records(records: Sequence[LedgerTransactionRecord]) -> tuple[int, str, dict[str, tuple[int, str]]]:
    stream_heads: dict[str, tuple[int, str]] = {}
    for record in records:
        for event in record.events:
            stream_heads[str(event.event["stream"])] = (event.stream_sequence, event.event_sha256)
    if not records:
        return 0, ZERO_SHA256, stream_heads
    return records[-1].global_sequence, str(records[-1].receipt["transaction_sha256"]), stream_heads


def _copy_regular(path: Path, payload: bytes) -> None:
    _directory(path.parent, "checkpoint member parent")
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise CompanyCheckpointError(f"cannot create checkpoint member: {path}") from exc


def _copy_blob(stage: Path, blobs: BlobStore, digest: str, expected_size: int) -> tuple[str, int]:
    try:
        metadata = blobs.metadata(digest)
        payload = blobs.read(digest)
    except (BlobStoreError, OSError) as exc:
        raise CompanyCheckpointError(f"reachable BlobRef is unavailable: {digest}") from exc
    if metadata.sha256 != digest or metadata.size_bytes != expected_size or len(payload) != expected_size or _sha256(payload) != digest:
        raise CompanyCheckpointError("reachable BlobRef differs from its declared bytes")
    relative = Path("blobs") / digest[:2] / digest[2:4] / digest
    destination = stage / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    _directory(destination.parent, "checkpoint blob fanout directory")
    _copy_regular(destination, payload)
    return relative.as_posix(), len(payload)


def _blob_file_digest(relative: str) -> str | None:
    parts = relative.split("/")
    if (
        len(parts) != 4
        or parts[0] != "blobs"
        or re.fullmatch(r"[0-9a-f]{2}", parts[1]) is None
        or re.fullmatch(r"[0-9a-f]{2}", parts[2]) is None
        or _SHA256.fullmatch(parts[3]) is None
        or parts[3][:2] != parts[1]
        or parts[3][2:4] != parts[2]
    ):
        return None
    return parts[3]


def _blob_directory_is_valid(relative: str) -> bool:
    parts = relative.split("/")
    return (
        parts == ["blobs"]
        or (
            len(parts) == 2
            and parts[0] == "blobs"
            and re.fullmatch(r"[0-9a-f]{2}", parts[1]) is not None
        )
        or (
            len(parts) == 3
            and parts[0] == "blobs"
            and re.fullmatch(r"[0-9a-f]{2}", parts[1]) is not None
            and re.fullmatch(r"[0-9a-f]{2}", parts[2]) is not None
        )
    )


def _members(stage: Path) -> dict[str, tuple[str, int, str]]:
    members: dict[str, tuple[str, int, str]] = {}
    blob_count = 0
    blob_bytes = 0

    def visit(directory: Path) -> None:
        nonlocal blob_count, blob_bytes
        _directory(directory, "checkpoint directory")
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise CompanyCheckpointError("checkpoint directory cannot be enumerated") from exc
        for child in children:
            relative = child.relative_to(stage).as_posix()
            metadata = child.lstat()
            if _is_reparse(metadata) or stat.S_ISLNK(metadata.st_mode):
                raise CompanyCheckpointError("checkpoint must not contain links")
            if stat.S_ISDIR(metadata.st_mode):
                if not _blob_directory_is_valid(relative):
                    raise CompanyCheckpointError(
                        "checkpoint contains an invalid directory",
                    )
                visit(child)
            elif stat.S_ISREG(metadata.st_mode):
                if relative == "ledger.sqlite3":
                    kind = relative
                    bound = _MAX_LEDGER_BYTES
                elif relative in {
                    "current.json",
                    "manifest.json",
                    _CHECKPOINT_NAME,
                }:
                    kind = relative
                    bound = _MAX_MANIFEST_BYTES
                else:
                    blob_digest = _blob_file_digest(relative)
                    if blob_digest is None:
                        raise CompanyCheckpointError(
                            "checkpoint contains an invalid member",
                        )
                    blob_count += 1
                    blob_bytes += int(metadata.st_size)
                    if blob_count > _MAX_BLOB_MEMBERS:
                        raise CompanyCheckpointError(
                            "checkpoint reachable blob count exceeds its bound",
                        )
                    if blob_bytes > _MAX_BLOB_BYTES:
                        raise CompanyCheckpointError(
                            "checkpoint reachable blob bytes exceed their bound",
                        )
                    kind = "blob"
                    bound = _MAX_SINGLE_BLOB_BYTES
                digest, size = _stream_digest(
                    child,
                    "checkpoint member",
                    max_bytes=bound,
                )
                members[relative] = (digest, size, kind)
            else:
                raise CompanyCheckpointError("checkpoint contains a non-regular member")

    visit(stage)
    return members


def _directories(stage: Path) -> set[str]:
    directories: set[str] = set()

    def visit(directory: Path) -> None:
        _directory(directory, "checkpoint directory")
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise CompanyCheckpointError("checkpoint directory cannot be enumerated") from exc
        for child in children:
            metadata = child.lstat()
            if _is_reparse(metadata) or stat.S_ISLNK(metadata.st_mode):
                raise CompanyCheckpointError("checkpoint must not contain links")
            if stat.S_ISDIR(metadata.st_mode):
                relative = child.relative_to(stage).as_posix()
                if not _blob_directory_is_valid(relative):
                    raise CompanyCheckpointError(
                        "checkpoint contains an invalid directory",
                    )
                directories.add(relative)
                visit(child)
            elif not stat.S_ISREG(metadata.st_mode):
                raise CompanyCheckpointError("checkpoint contains a non-regular member")

    visit(stage)
    return directories


def _member_list(members: Mapping[str, tuple[str, int, str]]) -> list[dict[str, Any]]:
    return [
        {"path": path, "sha256": digest, "size_bytes": size, "kind": kind}
        for path, (digest, size, kind) in sorted(members.items())
    ]


def _checkpoint_document(
    *,
    generated_at: str,
    pointer_raw: bytes,
    manifest_raw: bytes,
    pointer: Mapping[str, Any],
    manifest: Mapping[str, Any],
    heads: LedgerHeadsSnapshot,
    members: Mapping[str, tuple[str, int, str]],
) -> dict[str, Any]:
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "company": {
            "company_id": str(manifest["company_id"]),
            "company_incarnation": int(manifest["company_incarnation"]),
            "lock_domain_generation": int(manifest["lock_domain_generation"]),
            "manifest_sha256": _sha256(manifest_raw),
            "pointer_sha256": str(pointer["pointer_sha256"]),
            "current_pointer_file_sha256": _sha256(pointer_raw),
        },
        "ledger": {
            "global_sequence": heads.global_head.global_sequence,
            "transaction_sha256": heads.global_head.transaction_sha256,
            "stream_heads": [
                {"stream": stream, "cursor": cursor, "event_sha256": digest}
                for stream, (cursor, digest) in sorted(heads.stream_heads.items())
            ],
        },
        "members": _member_list(members),
    }


def _remove_stage(path: Path) -> None:
    if not path.name.startswith(_STAGE_PREFIX):
        raise CompanyCheckpointError("refusing to remove a non-checkpoint temporary")
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise CompanyCheckpointError("checkpoint temporary cleanup failed") from exc


def write_plain_checkpoint(
    *,
    lock: CompanyLockWitness,
    resolved: ResolvedCompanyState,
    ledger: CompanyLedger,
    blobs: BlobStore,
    checkpoint_id: str,
    generated_at: str,
) -> str:
    """Stage and atomically publish one digest-bound, plain checkpoint.

    This is a cooperative writer operation: ``lock`` must be the caller's
    existing company lifetime lock.  It grants no standalone writer authority.
    Exact replay of an already-published checkpoint ID returns its digest;
    divergent collisions fail without overwriting the existing directory.
    """
    _assert_lock_binding(lock, resolved)
    identifier = _checkpoint_id(checkpoint_id)
    when = _timestamp(generated_at)
    checkpoints = _absolute_root(resolved.incarnation.checkpoints, "company checkpoint root")
    _directory(checkpoints, "company checkpoint root")
    pointer_raw, manifest_raw, pointer, manifest = _pointer_and_manifest(resolved)
    if (
        not _same_path(
            _absolute_root(ledger.path, "source ledger"),
            _absolute_root(resolved.incarnation.ledger, "active company ledger"),
        )
        or not _same_path(
            _absolute_root(blobs.root, "source blob root"),
            _absolute_root(resolved.incarnation.blobs, "active company blob root"),
        )
    ):
        raise CompanyCheckpointError(
            "checkpoint source storage differs from the active incarnation",
        )
    expected_identity = (
        str(manifest["company_id"]),
        int(manifest["company_incarnation"]),
        int(manifest["lock_domain_generation"]),
    )
    source_heads = ledger.snapshot_heads()
    if (
        source_heads.identity is None
        and source_heads.global_head.global_sequence == 0
    ):
        raise CompanyCheckpointError(
            "company genesis transaction is required before checkpoint",
        )
    if source_heads.identity != expected_identity:
        raise CompanyCheckpointError(
            "checkpoint source ledger identity differs from the active company",
        )
    target = checkpoints / identifier
    stage = Path()
    for _attempt in range(16):
        candidate = checkpoints / f"{_STAGE_PREFIX}{uuid.uuid4().hex[:8]}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        stage = candidate
        break
    if stage == Path():
        raise CompanyCheckpointError("checkpoint temporary namespace is exhausted")
    try:
        _directory(stage, "checkpoint temporary")
        _copy_regular(stage / "current.json", pointer_raw)
        _copy_regular(stage / "manifest.json", manifest_raw)
        heads = ledger.snapshot_to(stage / "ledger.sqlite3")
        try:
            ledger_size = (stage / "ledger.sqlite3").stat().st_size
        except OSError as exc:
            raise CompanyCheckpointError(
                "checkpoint ledger copy size is unavailable",
            ) from exc
        if ledger_size > _MAX_LEDGER_BYTES:
            raise CompanyCheckpointError(
                "checkpoint ledger copy exceeds its byte bound",
            )
        if heads.identity != expected_identity:
            raise CompanyCheckpointError(
                "checkpoint ledger snapshot identity differs",
            )
        records = ledger.load_records()
        sequence, transaction_sha256, stream_heads = _heads_from_records(records)
        if (
            (sequence, transaction_sha256) != (heads.global_head.global_sequence, heads.global_head.transaction_sha256)
            or stream_heads != dict(heads.stream_heads)
        ):
            raise CompanyCheckpointError("source ledger advanced during checkpoint staging")
        blob_members = _bounded_blob_members(records)
        for digest, size in sorted(blob_members.items()):
            _copy_blob(stage, blobs, digest, size)
        _assert_lock_binding(lock, resolved)
        raw_members = _members(stage)
        document = _checkpoint_document(
            generated_at=when,
            pointer_raw=pointer_raw,
            manifest_raw=manifest_raw,
            pointer=pointer,
            manifest=manifest,
            heads=heads,
            members=raw_members,
        )
        try:
            manifest_bytes = canonical_company_json_bytes(
                document,
                max_bytes=_MAX_MANIFEST_BYTES,
            )
        except CompanyContractError as exc:
            raise CompanyCheckpointError(
                "checkpoint manifest exceeds its canonical bound",
            ) from exc
        _copy_regular(stage / _CHECKPOINT_NAME, manifest_bytes)
        digest = _sha256(manifest_bytes)
        verified_stage = verify_plain_checkpoint(stage)
        if verified_stage.sha256 != digest:
            raise CompanyCheckpointError("staged checkpoint digest readback differs")
        _fsync_directory(stage)
        _fsync_directory(checkpoints)
        try:
            _publish_no_replace(stage, target)
        except FileExistsError:
            existing = verify_plain_checkpoint(target)
            if existing.sha256 == digest:
                return digest
            raise CompanyCheckpointError("checkpoint ID already has divergent content")
        except OSError as exc:
            if target.exists():
                existing = verify_plain_checkpoint(target)
                if existing.sha256 == digest:
                    return digest
                raise CompanyCheckpointError("checkpoint ID already has divergent content") from exc
            raise CompanyCheckpointError("checkpoint publication failed") from exc
        _fsync_directory(checkpoints)
        stage = Path()
        return digest
    finally:
        if stage != Path() and stage.exists():
            _remove_stage(stage)


def _manifest_members(value: object) -> dict[str, tuple[str, int, str]]:
    if not isinstance(value, list):
        raise CompanyCheckpointError("checkpoint members are invalid")
    result: dict[str, tuple[str, int, str]] = {}
    for member in value:
        if not isinstance(member, dict) or set(member) != {"path", "sha256", "size_bytes", "kind"}:
            raise CompanyCheckpointError("checkpoint member schema is invalid")
        path = member["path"]
        digest = member["sha256"]
        size = member["size_bytes"]
        kind = member["kind"]
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(kind, str)
            or not kind
            or path == _CHECKPOINT_NAME
            or path in result
        ):
            raise CompanyCheckpointError("checkpoint member is invalid")
        result[path] = (digest, size, kind)
    return result


def _validate_document(value: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, tuple[str, int, str]]]:
    if set(value) != {"schema_version", "generated_at", "company", "ledger", "members"}:
        raise CompanyCheckpointError("checkpoint manifest schema is invalid")
    if value["schema_version"] != CHECKPOINT_SCHEMA_VERSION:
        raise CompanyCheckpointError("checkpoint manifest schema version is invalid")
    _timestamp(value["generated_at"])
    company = value["company"]
    ledger = value["ledger"]
    if not isinstance(company, dict) or set(company) != {
        "company_id", "company_incarnation", "lock_domain_generation", "manifest_sha256", "pointer_sha256", "current_pointer_file_sha256",
    }:
        raise CompanyCheckpointError("checkpoint company binding is invalid")
    if not isinstance(company["company_id"], str) or not isinstance(company["company_incarnation"], int) or isinstance(company["company_incarnation"], bool) or not isinstance(company["lock_domain_generation"], int) or isinstance(company["lock_domain_generation"], bool):
        raise CompanyCheckpointError("checkpoint company tuple is invalid")
    if any(not isinstance(company[key], str) or _SHA256.fullmatch(company[key]) is None for key in ("manifest_sha256", "pointer_sha256", "current_pointer_file_sha256")):
        raise CompanyCheckpointError("checkpoint company digest is invalid")
    if not isinstance(ledger, dict) or set(ledger) != {"global_sequence", "transaction_sha256", "stream_heads"}:
        raise CompanyCheckpointError("checkpoint ledger binding is invalid")
    if not isinstance(ledger["global_sequence"], int) or isinstance(ledger["global_sequence"], bool) or ledger["global_sequence"] < 0 or not isinstance(ledger["transaction_sha256"], str) or _SHA256.fullmatch(ledger["transaction_sha256"]) is None:
        raise CompanyCheckpointError("checkpoint ledger head is invalid")
    streams = ledger["stream_heads"]
    if not isinstance(streams, list):
        raise CompanyCheckpointError("checkpoint stream heads are invalid")
    prior = ""
    for head in streams:
        if not isinstance(head, dict) or set(head) != {"stream", "cursor", "event_sha256"} or not isinstance(head["stream"], str) or head["stream"] <= prior or not isinstance(head["cursor"], int) or isinstance(head["cursor"], bool) or head["cursor"] < 1 or not isinstance(head["event_sha256"], str) or _SHA256.fullmatch(head["event_sha256"]) is None:
            raise CompanyCheckpointError("checkpoint stream head is invalid")
        prior = head["stream"]
    members = _manifest_members(value["members"])
    return dict(value), members


def _verify_checkpoint_ledger(path: Path) -> tuple[LedgerHeadsSnapshot, tuple[LedgerTransactionRecord, ...]]:
    temporary_root = Path(tempfile.mkdtemp(prefix="aoi-checkpoint-ledger-"))
    temporary = temporary_root / "ledger.sqlite3"
    source: sqlite3.Connection | None = None
    destination: sqlite3.Connection | None = None
    copied: CompanyLedger | None = None
    try:
        if path.stat().st_size > _MAX_LEDGER_BYTES:
            raise CompanyCheckpointError(
                "checkpoint ledger exceeds its byte bound",
            )
        source = sqlite3.connect(
            f"{path.as_uri()}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
        destination = sqlite3.connect(temporary, isolation_level=None)
        source.backup(destination)
        destination.close()
        destination = None
        copied = CompanyLedger(temporary)
        records = copied.load_records()
        heads = copied.snapshot_heads()
        return heads, records
    except Exception as exc:
        if isinstance(exc, CompanyCheckpointError):
            raise
        raise CompanyCheckpointError("checkpoint ledger verification failed") from exc
    finally:
        if copied is not None:
            copied.close()
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
        for candidate in (temporary, temporary.with_name(f"{temporary.name}-wal"), temporary.with_name(f"{temporary.name}-shm"), temporary.with_name(f"{temporary.name}-journal")):
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass
        shutil.rmtree(temporary_root, ignore_errors=True)


def _verify_rebuilt_readmodel(root: Path, records: Sequence[LedgerTransactionRecord], heads: LedgerHeadsSnapshot) -> None:
    del root
    temporary_root = Path(tempfile.mkdtemp(prefix="aoi-checkpoint-readmodel-"))
    temporary = temporary_root / "readmodel.sqlite3"
    model: CompanyReadModel | None = None
    try:
        CompanyReadModel.rebuild(temporary, records)
        model = CompanyReadModel(temporary)
        rebuilt = model.verify_integrity()
        if (rebuilt.global_sequence, rebuilt.transaction_sha256) != (heads.global_head.global_sequence, heads.global_head.transaction_sha256):
            raise CompanyCheckpointError("rebuilt read model differs from checkpoint ledger head")
    except Exception as exc:
        if isinstance(exc, CompanyCheckpointError):
            raise
        raise CompanyCheckpointError("checkpoint read-model rebuild verification failed") from exc
    finally:
        if model is not None:
            model.close()
        for candidate in (temporary, temporary.with_name(f"{temporary.name}-wal"), temporary.with_name(f"{temporary.name}-shm"), temporary.with_name(f"{temporary.name}-journal")):
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass
        shutil.rmtree(temporary_root, ignore_errors=True)


def verify_plain_checkpoint(path: str | os.PathLike[str]) -> VerifiedCompanyCheckpoint:
    """Purely verify one published checkpoint without modifying its tree."""
    root = _absolute_root(path, "checkpoint root")
    _directory(root, "checkpoint root")
    manifest_path = root / _CHECKPOINT_NAME
    manifest_raw = _read_regular(manifest_path, "checkpoint manifest")
    document, expected_members = _validate_document(_canonical_json(manifest_raw, "checkpoint manifest"))
    actual_members = _members(root)
    actual_members.pop(_CHECKPOINT_NAME, None)
    if actual_members != expected_members:
        raise CompanyCheckpointError("checkpoint member inventory differs from manifest")
    required = {"current.json", "manifest.json", "ledger.sqlite3"}
    ordinary_members = {
        name: kind
        for name, (_digest, _size, kind) in expected_members.items()
        if kind != "blob"
    }
    if ordinary_members != {name: name for name in required}:
        raise CompanyCheckpointError(
            "checkpoint ordinary member inventory is invalid",
        )
    if any(name.endswith(suffix) for name in actual_members for suffix in ("-wal", "-shm", "-journal")):
        raise CompanyCheckpointError("checkpoint contains a SQLite sidecar")
    pointer_raw = _read_regular(root / "current.json", "checkpoint current pointer")
    company_manifest_raw = _read_regular(root / "manifest.json", "checkpoint company manifest")
    pointer = _validated_pointer(_canonical_json(pointer_raw, "checkpoint current pointer"))
    company_manifest = _canonical_json(company_manifest_raw, "checkpoint company manifest")
    try:
        normalized_manifest = validate_company_manifest(company_manifest)
    except CompanyContractError as exc:
        raise CompanyCheckpointError("checkpoint company manifest is invalid") from exc
    company = document["company"]
    if (
        _sha256(pointer_raw) != company["current_pointer_file_sha256"]
        or _sha256(company_manifest_raw) != company["manifest_sha256"]
        or pointer.get("pointer_sha256") != company["pointer_sha256"]
        or tuple(company[key] for key in ("company_id", "company_incarnation", "lock_domain_generation"))
        != (normalized_manifest["company_id"], normalized_manifest["company_incarnation"], normalized_manifest["lock_domain_generation"])
        or pointer.get("company_id") != company["company_id"]
        or pointer.get("company_incarnation") != company["company_incarnation"]
        or pointer.get("lock_domain_generation") != company["lock_domain_generation"]
        or pointer.get("manifest_sha256") != company["manifest_sha256"]
    ):
        raise CompanyCheckpointError("checkpoint pointer and company binding differ")
    heads, records = _verify_checkpoint_ledger(root / "ledger.sqlite3")
    ledger = document["ledger"]
    expected_stream_heads = {
        str(item["stream"]): (int(item["cursor"]), str(item["event_sha256"]))
        for item in ledger["stream_heads"]
    }
    if (
        (heads.global_head.global_sequence, heads.global_head.transaction_sha256)
        != (ledger["global_sequence"], ledger["transaction_sha256"])
        or dict(heads.stream_heads) != expected_stream_heads
        or heads.identity
        != (
            company["company_id"],
            company["company_incarnation"],
            company["lock_domain_generation"],
        )
    ):
        raise CompanyCheckpointError("checkpoint ledger binding differs")
    reachable = _bounded_blob_members(records)
    blob_paths = {
        f"blobs/{digest[:2]}/{digest[2:4]}/{digest}"
        for digest in reachable
    }
    if {name for name, (_digest, _size, kind) in expected_members.items() if kind == "blob"} != blob_paths:
        raise CompanyCheckpointError("checkpoint blob closure differs")
    expected_directories = {
        directory
        for blob_path in blob_paths
        for directory in (
            "blobs",
            "/".join(blob_path.split("/")[:2]),
            "/".join(blob_path.split("/")[:3]),
        )
    }
    if _directories(root) != expected_directories:
        raise CompanyCheckpointError("checkpoint directory inventory differs")
    for digest, size in reachable.items():
        member = expected_members.get(f"blobs/{digest[:2]}/{digest[2:4]}/{digest}")
        if member is None or member[0] != digest or member[1] != size:
            raise CompanyCheckpointError("checkpoint BlobRef member differs")
    _verify_rebuilt_readmodel(root, records, heads)
    final_members = _members(root)
    final_manifest_raw = final_members.pop(_CHECKPOINT_NAME, None)
    if (
        final_manifest_raw is None
        or final_manifest_raw
        != (_sha256(manifest_raw), len(manifest_raw), _CHECKPOINT_NAME)
        or final_members != expected_members
        or _directories(root) != expected_directories
    ):
        raise CompanyCheckpointError(
            "checkpoint changed during verification",
        )
    return VerifiedCompanyCheckpoint(root, _sha256(manifest_raw), document)
