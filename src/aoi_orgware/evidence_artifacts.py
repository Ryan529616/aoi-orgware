"""Content-addressed evidence artifact reads, snapshots, and recovery replay.

The CLI stays the composition root.  Only ``BOUND_ARTIFACT_TOTAL_MAX_BYTES``
remains a live CLI global (a test patches it on the CLI module), so every CLI
wrapper snapshots it into an immutable :class:`EvidenceArtifactsPolicy` and
passes that policy in explicitly.  Keeping the aggregate byte budget in the
policy prevents this security-sensitive code from observing a stale or
mid-call-mutated bound after the CLI global is patched.  All other artifact
byte and count bounds are module-local constants.  This module imports only
sibling packages and never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    atomic_create_bytes,
    atomic_write_bytes,
    canonicalize_no_link_traversal,
    fsync_directory,
    parse_time,
    sha256_file,
    task_dir,
)


COMMAND_ARTIFACT_MAX_BYTES = 1024 * 1024
TERMINAL_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
BOUND_ARTIFACT_MAX_COUNT = 64
RECOVERY_TAR_MAX_MEMBERS = 4096


@dataclass(frozen=True)
class EvidenceArtifactsPolicy:
    """Immutable aggregate byte budget for bounded artifact and recovery reads."""

    bound_artifact_total_max_bytes: int

    def __post_init__(self) -> None:
        if self.bound_artifact_total_max_bytes < 1:
            raise ValueError("bound artifact total max bytes must be positive")


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_evidence_detail(value: str, label: str) -> str:
    detail = require_text(value, label)
    if len(detail) < 12 or detail.lower() in {"pass", "passed", "ok", "success", "done"}:
        raise HarnessError(
            f"{label} is too generic; cite an artifact, command result, or bounded observation"
        )
    return detail


def canonical_record_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _is_canonical_snapshot_version(value: Any) -> bool:
    return _is_exact_int(value, 1)


def _is_legacy_snapshot_version(value: Any) -> bool:
    return value is None or _is_exact_int(value, 0)


def _packet_schema_version(packet: dict[str, Any]) -> int | None:
    value = packet.get("packet_schema_version", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return value


def read_regular_artifact(
    value: str | Path,
    label: str,
    *,
    max_bytes: int,
    require_utf8: bool = False,
) -> tuple[Path, bytes]:
    """Read one stable regular file without following a final-component symlink."""
    source = canonicalize_no_link_traversal(
        Path(value).expanduser(), f"{label} path"
    )
    try:
        before = os.lstat(source)
    except OSError as exc:
        raise HarnessError(f"{label} is missing or unreadable: {source}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise HarnessError(f"{label} must be a regular non-symlink file")
    if before.st_nlink != 1:
        raise HarnessError(f"{label} must not be hard-linked")
    if before.st_size <= 0 or before.st_size > max_bytes:
        raise HarnessError(f"{label} must be non-empty and at most {max_bytes} bytes")
    # Windows low-level descriptors default to text mode, which silently
    # translates CRLF to LF and breaks physical SHA-256 identity. Always read
    # artifacts as exact bytes on every platform.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise HarnessError(f"{label} could not be opened safely: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise HarnessError(f"{label} changed while it was being opened")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        finished = os.fstat(descriptor)
        if (
            finished.st_size != opened.st_size
            or getattr(finished, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
        ):
            raise HarnessError(f"{label} changed while it was being read")
    finally:
        os.close(descriptor)
    if not data or len(data) > max_bytes:
        raise HarnessError(f"{label} must be non-empty and at most {max_bytes} bytes")
    if require_utf8:
        if b"\x00" in data:
            raise HarnessError(f"{label} may not contain NUL bytes")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HarnessError(f"{label} is not UTF-8: {exc}") from exc
    if canonicalize_no_link_traversal(source, f"{label} path") != source:
        raise HarnessError(f"{label} path changed while it was being read")
    return source, data


def snapshot_evidence_artifact(
    paths: HarnessPaths,
    task_id: str,
    source_value: str | Path,
    expected_sha: str,
    *,
    label: str,
    basename: str,
    max_bytes: int = TERMINAL_ARTIFACT_MAX_BYTES,
) -> dict[str, Any]:
    expected = require_text(expected_sha, f"{label} SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise HarnessError(f"{label} SHA-256 must be full 64 hex")
    source, data = read_regular_artifact(
        source_value, label, max_bytes=max_bytes
    )
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise HarnessError(
            f"{label} SHA-256 mismatch: expected {expected}, actual {actual}"
        )
    destination = task_dir(paths, task_id) / "results" / basename
    if destination.exists():
        raise HarnessError(f"canonical {label} snapshot already exists: {destination}")
    atomic_write_bytes(destination, data)
    os.chmod(destination, 0o600)
    return {
        "source_path": str(source),
        "path": str(destination),
        "sha256": actual,
        "size_bytes": len(data),
    }


def artifact_blob_path(paths: HarnessPaths, task_id: str, digest: str) -> Path:
    """Return the canonical task-local path for one content-addressed artifact."""

    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise HarnessError("artifact blob SHA-256 must be full 64 hex")
    return task_dir(paths, task_id) / "results" / "artifact-blobs" / digest[:2] / digest


def ensure_artifact_blob_parent(
    paths: HarnessPaths, task_id: str, digest: str, *, create: bool
) -> Path:
    """Validate every managed blob ancestor and optionally create missing dirs."""

    destination = artifact_blob_path(paths, task_id, digest)
    boundary = paths.root
    try:
        relative_parent = destination.parent.relative_to(boundary)
    except ValueError as exc:
        raise HarnessError("artifact blob path escapes the harness root") from exc
    current = boundary
    for part in relative_parent.parts:
        parent = current
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise HarnessError(f"artifact blob ancestor is missing: {current}")
            try:
                os.mkdir(current, 0o700)
                fsync_directory(parent)
            except FileExistsError:
                pass
            metadata = os.lstat(current)
        is_junction = bool(getattr(current, "is_junction", lambda: False)())
        is_reparse = os.name == "nt" and bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if (
            stat.S_ISLNK(metadata.st_mode)
            or is_junction
            or is_reparse
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise HarnessError(
                f"artifact blob ancestor must be a real directory: {current}"
            )
    return destination.parent


def prepare_bound_artifacts(
    values: Iterable[str],
    label: str,
    *,
    policy: EvidenceArtifactsPolicy,
) -> list[dict[str, Any]]:
    """Safely read and SHA-bind a bounded set of artifacts before state mutation."""

    raw_values = list(values)
    if len(raw_values) > BOUND_ARTIFACT_MAX_COUNT:
        raise HarnessError(
            f"{label} accepts at most {BOUND_ARTIFACT_MAX_COUNT} artifacts"
        )
    prepared: list[dict[str, Any]] = []
    total_bytes = 0
    for index, value in enumerate(raw_values, start=1):
        path_text, separator, digest = value.rpartition("=")
        if not separator:
            raise HarnessError(f"{label} must use absolute-path=sha256")
        digest = digest.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HarnessError(f"{label} SHA-256 must be full 64 hex")
        source, data = read_regular_artifact(
            path_text,
            f"{label} #{index}",
            max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
        )
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise HarnessError(
                f"{label} #{index} SHA-256 mismatch: expected {digest}, actual {actual}"
            )
        total_bytes += len(data)
        if total_bytes > policy.bound_artifact_total_max_bytes:
            raise HarnessError(
                f"{label} aggregate size exceeds {policy.bound_artifact_total_max_bytes} bytes"
            )
        prepared.append(
            {
                "source_path": str(source),
                "sha256": actual,
                "size_bytes": len(data),
                "data": data,
            }
        )
    return prepared


def preserve_bound_artifacts(
    paths: HarnessPaths,
    task_id: str,
    prepared: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Create or safely reuse canonical content-addressed task artifact blobs."""

    preserved: list[dict[str, Any]] = []
    for item in prepared:
        digest = str(item["sha256"])
        data = bytes(item["data"])
        destination = artifact_blob_path(paths, task_id, digest)
        ensure_artifact_blob_parent(paths, task_id, digest, create=True)
        if destination.exists():
            _, existing = read_regular_artifact(
                destination,
                "existing task artifact blob",
                max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
            )
            if hashlib.sha256(existing).hexdigest() != digest or existing != data:
                raise HarnessError(
                    f"canonical task artifact blob is missing or tampered: {destination}"
                )
        else:
            try:
                atomic_create_bytes(destination, data)
            except HarnessError:
                if not destination.exists():
                    raise
                _, existing = read_regular_artifact(
                    destination,
                    "concurrently published task artifact blob",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
                if hashlib.sha256(existing).hexdigest() != digest or existing != data:
                    raise
        preserved.append(
            {
                "snapshot_version": 1,
                "source_path": str(item["source_path"]),
                "path": str(destination),
                "sha256": digest,
                "size_bytes": len(data),
            }
        )
    return preserved


def canonical_recovery_archive_member(member_name: str) -> str:
    """Return the canonical relative POSIX member name used in recovery receipts."""

    member_name = require_text(member_name, "recovery archive member")
    member_path = PurePosixPath(member_name)
    if (
        "\\" in member_name
        or member_path.is_absolute()
        or member_path.as_posix() != member_name
        or any(part in {"", ".", ".."} for part in member_path.parts)
    ):
        raise HarnessError("recovery archive member must be a canonical relative POSIX path")
    return member_name


def read_recovery_tar_member(
    archive_data: bytes,
    member_name: str,
    *,
    budget: dict[str, int] | None = None,
    policy: EvidenceArtifactsPolicy,
) -> bytes:
    """Read one exact regular member from a bounded in-memory tar archive."""

    member_name = canonical_recovery_archive_member(member_name)
    if budget is None:
        budget = {
            "decompressed_bytes": 0,
            "member_count": 0,
            "declared_bytes": 0,
            "extracted_bytes": 0,
        }
    required_budget_fields = {
        "decompressed_bytes",
        "member_count",
        "declared_bytes",
        "extracted_bytes",
    }
    if set(budget) != required_budget_fields or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in budget.values()
    ):
        raise HarnessError("recovery archive replay budget is invalid")
    try:
        remaining_decompressed = (
            policy.bound_artifact_total_max_bytes - budget["decompressed_bytes"]
        )
        if remaining_decompressed < 0:
            raise HarnessError("recovery archive aggregate decompressed budget is exceeded")
        if archive_data.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(archive_data), mode="rb") as stream:
                tar_data = stream.read(remaining_decompressed + 1)
        else:
            tar_data = archive_data[: remaining_decompressed + 1]
        if len(tar_data) > remaining_decompressed:
            raise HarnessError(
                "recovery archive aggregate decompressed budget is exceeded"
            )
        budget["decompressed_bytes"] += len(tar_data)
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            match: tarfile.TarInfo | None = None
            for candidate in archive:
                budget["member_count"] += 1
                if budget["member_count"] > RECOVERY_TAR_MAX_MEMBERS:
                    raise HarnessError(
                        "recovery archive aggregate member budget is exceeded"
                    )
                if candidate.isfile():
                    if candidate.size < 0 or candidate.size > TERMINAL_ARTIFACT_MAX_BYTES:
                        raise HarnessError(
                            "recovery archive contains a file outside the size bound"
                        )
                    budget["declared_bytes"] += candidate.size
                    if budget["declared_bytes"] > policy.bound_artifact_total_max_bytes:
                        raise HarnessError(
                            "recovery archive aggregate declared-size budget is exceeded"
                        )
                if candidate.name == member_name:
                    if match is not None:
                        raise HarnessError("recovery archive member name is duplicated")
                    match = candidate
            if match is None:
                raise HarnessError("recovery archive member is missing")
            if not match.isfile() or match.issym() or match.islnk():
                raise HarnessError("recovery archive member must be a regular file")
            if match.size <= 0 or match.size > TERMINAL_ARTIFACT_MAX_BYTES:
                raise HarnessError("recovery archive member size is outside the allowed bound")
            stream = archive.extractfile(match)
            if stream is None:
                raise HarnessError("recovery archive member cannot be read")
            remaining_extracted = (
                policy.bound_artifact_total_max_bytes - budget["extracted_bytes"]
            )
            if remaining_extracted < match.size:
                raise HarnessError("recovery archive aggregate extraction budget is exceeded")
            data = stream.read(min(TERMINAL_ARTIFACT_MAX_BYTES, remaining_extracted) + 1)
            if len(data) != match.size:
                raise HarnessError("recovery archive member size does not match its header")
            budget["extracted_bytes"] += len(data)
            return data
    except HarnessError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, zlib.error, OSError, EOFError) as exc:
        raise HarnessError(f"recovery archive is invalid: {exc}") from exc


def recovery_record_preimage(
    state: dict[str, Any],
    packet: dict[str, Any],
    target_index: int,
    target: dict[str, Any],
    carrier_index: int,
    carrier: dict[str, Any],
    recovery: dict[str, Any],
) -> dict[str, Any]:
    """Build the sealed semantic preimage for one packet-bound recovery."""

    return {
        "task_id": state.get("task_id"),
        "packet_id": packet.get("packet_id"),
        "packet_schema_version": packet.get("packet_schema_version"),
        "target_input_index": target_index + 1,
        "target_source_path": target.get("source_path"),
        "target_sha256": target.get("sha256"),
        "target_size_bytes": target.get("size_bytes"),
        "carrier_input_index": carrier_index + 1,
        "carrier_sha256": carrier.get("sha256"),
        "carrier_size_bytes": carrier.get("size_bytes"),
        "archive_member": recovery.get("archive_member"),
        "packet_result_sha256": recovery.get("packet_result_sha256"),
        "reason": recovery.get("reason"),
        "recovered_at": recovery.get("recovered_at"),
    }


def artifact_ref_integrity_error(
    paths: HarnessPaths,
    state: dict[str, Any],
    artifact: dict[str, Any],
    *,
    require_origin: bool,
) -> str | None:
    """Validate a legacy live ref or a canonical snapshot without mutating state."""

    digest = str(artifact.get("sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return "artifact SHA-256 is invalid"
    expected_size = artifact.get("size_bytes")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size <= 0
    ):
        return "artifact size is invalid"
    snapshot_version = artifact.get("snapshot_version")
    if _is_canonical_snapshot_version(snapshot_version):
        expected_path = artifact_blob_path(paths, state["task_id"], digest)
        recorded_path = Path(str(artifact.get("path", "")))
        if recorded_path != expected_path:
            return "artifact snapshot path is not canonical"
        try:
            ensure_artifact_blob_parent(
                paths, state["task_id"], digest, create=False
            )
        except HarnessError as exc:
            return str(exc)
        try:
            _, data = read_regular_artifact(
                recorded_path,
                "artifact snapshot",
                max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
            )
        except HarnessError as exc:
            return str(exc)
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
            return "artifact snapshot identity mismatch"
        if require_origin:
            source_path = Path(str(artifact.get("source_path", "")))
            if not source_path.is_absolute():
                return "artifact source path is not absolute"
            try:
                _, source_data = read_regular_artifact(
                    source_path,
                    "artifact source",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
            except HarnessError as exc:
                return str(exc)
            if (
                len(source_data) != expected_size
                or hashlib.sha256(source_data).hexdigest() != digest
            ):
                return "artifact source changed after snapshot creation"
        return None
    if not _is_legacy_snapshot_version(snapshot_version):
        return "artifact snapshot version is unsupported"
    legacy_path = Path(str(artifact.get("path", "")))
    try:
        _, data = read_regular_artifact(
            legacy_path,
            "legacy artifact reference",
            max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
        )
    except HarnessError as exc:
        return str(exc)
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
        return "legacy artifact reference identity mismatch"
    return None


def packet_recovery_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    policy: EvidenceArtifactsPolicy,
) -> list[str]:
    """Validate sealed recovery provenance and the still-bound archive member."""

    errors: list[str] = []
    recovery_count = 0
    aggregate_carrier_bytes = 0
    aggregate_recovered_bytes = 0
    replay_budget = {
        "decompressed_bytes": 0,
        "member_count": 0,
        "declared_bytes": 0,
        "extracted_bytes": 0,
    }
    required_fields = {
        "version",
        "method",
        "carrier_input_index",
        "carrier_sha256",
        "archive_member",
        "packet_result_sha256",
        "reason",
        "recovered_at",
        "record_sha256",
    }
    legacy_required_fields = required_fields - {"record_sha256"}
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        refs = packet.get("input_artifact_refs", [])
        for target_index, target in enumerate(refs):
            if "recovery" not in target:
                continue
            recovery_count += 1
            label = f"packet {packet_id} recovered input #{target_index + 1}"
            if recovery_count > BOUND_ARTIFACT_MAX_COUNT:
                errors.append(
                    f"packet recovery receipts exceed {BOUND_ARTIFACT_MAX_COUNT} records"
                )
                return errors
            recovery = target.get("recovery")
            recovery_fields = set(recovery) if isinstance(recovery, dict) else set()
            sealed_receipt = recovery_fields == required_fields
            legacy_receipt = recovery_fields == legacy_required_fields
            if (
                not isinstance(recovery, dict)
                or not (sealed_receipt or legacy_receipt)
                or not _is_exact_int(recovery.get("version"), 1)
                or recovery.get("method") != "packet-bound-tar-member"
            ):
                errors.append(f"{label} receipt schema is invalid")
                continue
            packet_schema_version = packet.get("packet_schema_version")
            if (
                not isinstance(packet_schema_version, int)
                or isinstance(packet_schema_version, bool)
                or packet_schema_version < 1
                or packet_schema_version >= 4
                or packet.get("status") != "done"
                or not _is_exact_int(packet.get("integrity_version"), 1)
            ):
                errors.append(f"{label} is attached to an ineligible packet")
                continue
            if not _is_canonical_snapshot_version(target.get("snapshot_version")):
                errors.append(f"{label} target is not a canonical snapshot")
                continue
            target_error = artifact_ref_integrity_error(
                paths, state, target, require_origin=False
            )
            if target_error:
                errors.append(f"{label} target: {target_error}")
                continue
            target_source = Path(str(target.get("source_path", "")))
            if not target_source.is_absolute():
                errors.append(f"{label} source path is not absolute")
                continue
            carrier_number = recovery.get("carrier_input_index")
            if (
                not isinstance(carrier_number, int)
                or isinstance(carrier_number, bool)
                or carrier_number < 1
                or carrier_number > len(refs)
                or carrier_number == target_index + 1
            ):
                errors.append(f"{label} carrier input index is invalid")
                continue
            carrier_index = carrier_number - 1
            carrier = refs[carrier_index]
            carrier_sha = str(recovery.get("carrier_sha256", ""))
            if (
                not re.fullmatch(r"[0-9a-f]{64}", carrier_sha)
                or carrier_sha != carrier.get("sha256")
            ):
                errors.append(f"{label} carrier SHA-256 binding is invalid")
                continue
            carrier_error = artifact_ref_integrity_error(
                paths, state, carrier, require_origin=False
            )
            if carrier_error:
                errors.append(f"{label} carrier: {carrier_error}")
                continue
            packet_result_sha = str(recovery.get("packet_result_sha256", ""))
            expected_result_path = (
                task_dir(paths, state["task_id"]) / "results" / f"{packet_id}.md"
            )
            if (
                not re.fullmatch(r"[0-9a-f]{64}", packet_result_sha)
                or packet_result_sha != packet.get("result_sha256")
                or Path(str(packet.get("result_path", ""))) != expected_result_path
                or not expected_result_path.is_file()
                or expected_result_path.is_symlink()
                or sha256_file(expected_result_path) != packet_result_sha
            ):
                errors.append(f"{label} packet result binding is invalid")
                continue
            stored_member = recovery.get("archive_member")
            try:
                canonical_member = canonical_recovery_archive_member(stored_member)
            except (AttributeError, HarnessError) as exc:
                errors.append(f"{label} archive member is invalid: {exc}")
                continue
            if canonical_member != stored_member:
                errors.append(f"{label} archive member is not canonical")
                continue
            reason = recovery.get("reason")
            if not isinstance(reason, str) or reason != reason.strip():
                errors.append(f"{label} reason is not canonical text")
                continue
            try:
                require_evidence_detail(reason, f"{label} reason")
            except HarnessError as exc:
                errors.append(str(exc))
                continue
            recovered_at = recovery.get("recovered_at")
            if (
                not isinstance(recovered_at, str)
                or parse_time(recovered_at) is None
                or re.search(r"(?:Z|[+-]\d{2}:\d{2})$", recovered_at) is None
            ):
                errors.append(f"{label} recovered_at is not a timezone-aware timestamp")
                continue
            if sealed_receipt:
                record_sha = str(recovery.get("record_sha256", ""))
                expected_record_sha = canonical_record_sha256(
                    recovery_record_preimage(
                        state,
                        packet,
                        target_index,
                        target,
                        carrier_index,
                        carrier,
                        recovery,
                    )
                )
                if (
                    not re.fullmatch(r"[0-9a-f]{64}", record_sha)
                    or record_sha != expected_record_sha
                ):
                    errors.append(f"{label} receipt record SHA-256 mismatch")
                    continue
            carrier_size = carrier.get("size_bytes")
            target_size = target.get("size_bytes")
            if (
                not isinstance(carrier_size, int)
                or isinstance(carrier_size, bool)
                or not isinstance(target_size, int)
                or isinstance(target_size, bool)
            ):
                errors.append(f"{label} size metadata is invalid")
                continue
            aggregate_carrier_bytes += carrier_size
            aggregate_recovered_bytes += target_size
            if (
                aggregate_carrier_bytes > policy.bound_artifact_total_max_bytes
                or aggregate_recovered_bytes > policy.bound_artifact_total_max_bytes
            ):
                errors.append("packet recovery aggregate byte budget is exceeded")
                return errors
            try:
                _, carrier_data = read_regular_artifact(
                    Path(str(carrier.get("path", ""))),
                    "packet recovery carrier",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
                recovered_data = read_recovery_tar_member(
                    carrier_data,
                    canonical_member,
                    budget=replay_budget,
                    policy=policy,
                )
            except HarnessError as exc:
                errors.append(f"{label} archive replay failed: {exc}")
                continue
            if (
                hashlib.sha256(recovered_data).hexdigest() != target.get("sha256")
                or len(recovered_data) != target_size
            ):
                errors.append(f"{label} archive member no longer matches the target")
    return errors


__all__ = [
    "BOUND_ARTIFACT_MAX_COUNT",
    "COMMAND_ARTIFACT_MAX_BYTES",
    "EvidenceArtifactsPolicy",
    "RECOVERY_TAR_MAX_MEMBERS",
    "TERMINAL_ARTIFACT_MAX_BYTES",
    "artifact_blob_path",
    "artifact_ref_integrity_error",
    "canonical_recovery_archive_member",
    "ensure_artifact_blob_parent",
    "packet_recovery_integrity_errors",
    "prepare_bound_artifacts",
    "preserve_bound_artifacts",
    "read_recovery_tar_member",
    "read_regular_artifact",
    "recovery_record_preimage",
    "snapshot_evidence_artifact",
]
