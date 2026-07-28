"""Checkpoint-bound, redacted company snapshot export for operational alpha.

The plain checkpoint remains the only authority.  This module never opens a
live ``CompanyStateOwner``: it verifies a checkpoint, copies its ledger into a
private temporary directory, rebuilds the replaceable projection, and renders
the ordinary read-only company view through a deliberately tiny facade.
"""
from __future__ import annotations

from collections.abc import Mapping
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
from types import SimpleNamespace
from typing import Any, cast
import uuid

from .checkpoint import CompanyCheckpointError, verify_plain_checkpoint
from .contracts import CompanyContractError, canonical_company_json_bytes
from .ledger import CompanyLedger, LedgerHeadsSnapshot
from .readmodel import CompanyReadModel
from .registry import CompanyLockWitness, ResolvedCompanyState
from .state import CompanyQuerySnapshot, CompanyStateHealth, CompanyStateOwner
from .views import CompanyViewService


SANITIZED_EXPORT_SCHEMA_VERSION = 1
MAX_SANITIZED_EXPORT_BYTES = 32 * 1024 * 1024
_EXPORT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_STAGE_PREFIX = ".s-"
_SAFE_RAW_KEYS = frozenset({"raw_token_vector", "raw_artifact"})
_OPERATIONAL_REDACTION_WARNING = (
    "operational_redaction_not_security_boundary"
)


class CompanySanitizedExportError(RuntimeError):
    """A checkpoint-bound sanitized export cannot be produced or verified."""


@dataclass(frozen=True)
class VerifiedSanitizedExport:
    """The result of a pure sanitized-export verification."""

    path: Path
    sha256: str
    bundle: Mapping[str, Any]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _absolute_path(value: str | os.PathLike[str], label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise CompanySanitizedExportError(
            f"{label} must be an absolute traversal-free path",
        )
    return path


def _is_windows_reparse(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if not isinstance(attributes, int) or not isinstance(flag, int):
        raise CompanySanitizedExportError(
            "Windows reparse-point inspection is unavailable",
        )
    return bool(attributes & flag)


def _directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CompanySanitizedExportError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_windows_reparse(metadata)
    ):
        raise CompanySanitizedExportError(f"{label} must be a directory, not a link")


def _regular(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or _is_windows_reparse(metadata)
            or metadata.st_nlink != 1
        ):
            raise CompanySanitizedExportError(f"{label} must be a regular non-link file")
        raw = path.read_bytes()
    except OSError as exc:
        raise CompanySanitizedExportError(f"{label} is unavailable") from exc
    if len(raw) != metadata.st_size:
        raise CompanySanitizedExportError(f"{label} changed while read")
    return raw


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(os.fspath(left))) == os.path.normcase(
        os.path.abspath(os.fspath(right)),
    )


def _assert_safe_ancestors(path: Path, label: str) -> None:
    """Reject link/reparse ancestors without resolving a caller-controlled path."""

    current = path
    while True:
        _directory(current, label)
        parent = current.parent
        if parent == current:
            return
        current = parent


def _assert_owned(lock: CompanyLockWitness) -> None:
    try:
        lock.assert_owned()
    except Exception as exc:
        raise CompanySanitizedExportError("company lock witness is not owned") from exc


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
        raise CompanySanitizedExportError(
            "company lock witness differs from the active company slot",
        )


def _writer_roots(
    lock: CompanyLockWitness,
    resolved: ResolvedCompanyState,
    checkpoint: Path,
) -> tuple[Path, Path]:
    """Bind a cooperative writer to one lock-held incarnation exactly."""

    _assert_lock_binding(lock, resolved)
    checkpoints = _absolute_path(
        resolved.incarnation.checkpoints, "company checkpoint root",
    )
    exports = _absolute_path(resolved.incarnation.exports, "company export root")
    if not _same_path(checkpoint.parent, checkpoints):
        raise CompanySanitizedExportError(
            "checkpoint must be an immediate child of the active checkpoint root",
        )
    _directory(checkpoints, "company checkpoint root")
    _directory(exports, "company export root")
    _assert_safe_ancestors(checkpoints, "company checkpoint ancestor")
    _assert_safe_ancestors(exports, "company export ancestor")
    return checkpoints, exports


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise CompanySanitizedExportError("generated_at is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise CompanySanitizedExportError("generated_at is invalid") from exc
    if parsed.tzinfo is None:
        raise CompanySanitizedExportError("generated_at lacks a timezone")
    return value


def _export_id(value: object) -> str:
    if not isinstance(value, str) or _EXPORT_ID.fullmatch(value) is None:
        raise CompanySanitizedExportError("export ID is invalid")
    return value


def _canonical_bundle(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_SANITIZED_EXPORT_BYTES:
        raise CompanySanitizedExportError("sanitized export exceeds its byte bound")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CompanySanitizedExportError("sanitized export is not canonical JSON") from exc
    try:
        canonical = canonical_company_json_bytes(
            value,
            max_bytes=MAX_SANITIZED_EXPORT_BYTES,
        )
    except CompanyContractError as exc:
        raise CompanySanitizedExportError(
            "sanitized export is not canonical JSON",
        ) from exc
    if not isinstance(value, dict) or canonical != raw:
        raise CompanySanitizedExportError("sanitized export is not canonical JSON")
    return value


def _deny_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in _SAFE_RAW_KEYS:
        return False
    return (
        "session" in normalized
        or "thread" in normalized
        or "resume" in normalized
        or "native_handle" in normalized
        or "prompt" in normalized
        or "chain_of_thought" in normalized
        or normalized in {"cot", "nonce"}
        or "nonce" in normalized
        or "user_action" in normalized
        or "credential" in normalized
        or "secret" in normalized
        or normalized.endswith("_token")
        or normalized
        in {
            "token",
            "api_key",
            "password",
            "authorization",
            "cookie",
            "set_cookie",
            "private_key",
        }
        or "password" in normalized
        or "raw" in normalized
        or ("blob" in normalized and ("byte" in normalized or normalized.endswith("_blob")))
    )


def _safe_raw_artifact_metadata(value: Any) -> dict[str, Any]:
    """Keep the BlobRef-like digest envelope, never raw artifact contents."""

    if not isinstance(value, Mapping):
        raise CompanySanitizedExportError("raw artifact metadata is invalid")
    result = {
        "availability": value.get("availability"),
        "sha256": value.get("sha256"),
        "size_bytes": value.get("size_bytes"),
        "media_type": value.get("media_type"),
    }
    availability = result["availability"]
    digest = result["sha256"]
    size = result["size_bytes"]
    media_type = result["media_type"]
    if availability not in {"available", "unavailable", "unknown"}:
        raise CompanySanitizedExportError("raw artifact availability is invalid")
    if not isinstance(media_type, str) or not media_type or len(media_type) > 128:
        raise CompanySanitizedExportError("raw artifact media type is invalid")
    if availability == "available":
        if (
            not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise CompanySanitizedExportError("raw artifact digest metadata is invalid")
    elif digest is not None or size is not None:
        raise CompanySanitizedExportError("unavailable raw artifact has digest metadata")
    return result


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 64:
        raise CompanySanitizedExportError("sanitized snapshot nesting exceeds its bound")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized == "raw_artifact":
                result[str(key)] = _safe_raw_artifact_metadata(item)
            elif not _deny_key(str(key)):
                result[str(key)] = _sanitize(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 4096:
            raise CompanySanitizedExportError("sanitized snapshot list exceeds its bound")
        return [_sanitize(item, depth=depth + 1) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise CompanySanitizedExportError("sanitized snapshot contains a non-JSON value")


def _assert_sanitized(value: Any, *, depth: int = 0) -> None:
    """Independently reject forbidden fields after redaction."""

    if depth > 64:
        raise CompanySanitizedExportError("sanitized snapshot nesting exceeds its bound")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or _deny_key(key):
                raise CompanySanitizedExportError("sanitized snapshot contains a denied field")
            if key.lower().replace("-", "_") == "raw_artifact":
                _safe_raw_artifact_metadata(item)
            else:
                _assert_sanitized(item, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 4096:
            raise CompanySanitizedExportError("sanitized snapshot list exceeds its bound")
        for item in value:
            _assert_sanitized(item, depth=depth + 1)
    elif not isinstance(value, (str, int, float, bool)) and value is not None:
        raise CompanySanitizedExportError("sanitized snapshot contains a non-JSON value")


class _CheckpointViewState:
    """The minimal read-only state surface consumed by ``CompanyViewService``."""

    def __init__(
        self,
        *,
        manifest: Mapping[str, Any],
        pointer_sha256: str,
        ledger_heads: LedgerHeadsSnapshot,
        readmodel: CompanyReadModel,
    ) -> None:
        self.resolved = SimpleNamespace(manifest=manifest)
        self._readmodel = readmodel
        self._health = CompanyStateHealth(
            status="ready",
            ledger_status="ready",
            projection_status="ready",
            pointer_sha256=pointer_sha256,
            ledger_heads=ledger_heads,
            readmodel_head=readmodel.head(),
            blob_status="ready",
            degradation_reasons=(),
        )

    def query_snapshot(self) -> CompanyQuerySnapshot:
        return CompanyQuerySnapshot(
            health=self._health,
            objects=self._readmodel.objects(),
            uncertain_dispatches=self._readmodel.uncertain_dispatches(),
        )

    def records_after(self, _cursor: int, *, limit: int) -> tuple[Any, ...]:
        del limit
        return ()


def _copied_ledger(source: Path, temporary: Path) -> None:
    read_connection: sqlite3.Connection | None = None
    write_connection: sqlite3.Connection | None = None
    try:
        read_connection = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True, isolation_level=None)
        write_connection = sqlite3.connect(temporary, isolation_level=None)
        read_connection.backup(write_connection)
    except sqlite3.Error as exc:
        raise CompanySanitizedExportError("checkpoint ledger copy failed") from exc
    finally:
        if write_connection is not None:
            write_connection.close()
        if read_connection is not None:
            read_connection.close()


def _snapshot_from_checkpoint(
    checkpoint_path: Path,
    generated_at: str,
) -> tuple[dict[str, Any], str, str, list[str], Mapping[str, Any]]:
    try:
        checkpoint = verify_plain_checkpoint(checkpoint_path)
    except CompanyCheckpointError as exc:
        raise CompanySanitizedExportError("plain checkpoint verification failed") from exc
    temporary_root = Path(tempfile.mkdtemp(prefix="aoi-sanitized-export-"))
    ledger: CompanyLedger | None = None
    model: CompanyReadModel | None = None
    try:
        temporary_ledger = temporary_root / "ledger.sqlite3"
        _copied_ledger(checkpoint.path / "ledger.sqlite3", temporary_ledger)
        ledger = CompanyLedger(temporary_ledger)
        records = ledger.load_records()
        heads = ledger.snapshot_heads()
        document = checkpoint.manifest
        binding = document["company"]
        expected_ledger = document["ledger"]
        if (
            heads.identity != (
                binding["company_id"], binding["company_incarnation"], binding["lock_domain_generation"],
            )
            or heads.global_head.global_sequence != expected_ledger["global_sequence"]
            or heads.global_head.transaction_sha256 != expected_ledger["transaction_sha256"]
        ):
            raise CompanySanitizedExportError("checkpoint ledger binding differs during export")
        temporary_model = temporary_root / "readmodel.sqlite3"
        CompanyReadModel.rebuild(temporary_model, records)
        model = CompanyReadModel(temporary_model)
        rebuilt = model.verify_integrity()
        if (
            rebuilt.global_sequence != heads.global_head.global_sequence
            or rebuilt.transaction_sha256 != heads.global_head.transaction_sha256
        ):
            raise CompanySanitizedExportError("rebuilt read model differs from checkpoint ledger")
        facade = _CheckpointViewState(
            manifest=document["company"],
            pointer_sha256=str(binding["pointer_sha256"]),
            ledger_heads=heads,
            readmodel=model,
        )
        snapshot = CompanyViewService(
            cast(CompanyStateOwner, facade), clock=lambda: generated_at,
        ).section("snapshot")
        if snapshot["cursor"] != heads.global_head.global_sequence:
            raise CompanySanitizedExportError("view cursor differs from checkpoint ledger")
        data = snapshot["data"]
        if not isinstance(data, dict):
            raise CompanySanitizedExportError("checkpoint view snapshot is invalid")
        data = dict(data)
        data.pop("export", None)
        sanitized = _sanitize(data)
        _assert_sanitized(sanitized)
        completeness = snapshot["completeness"]
        warnings = snapshot["warnings"]
        if not isinstance(completeness, str) or not isinstance(warnings, list):
            raise CompanySanitizedExportError("checkpoint view completeness is invalid")
        return sanitized, checkpoint.sha256, completeness, warnings, document
    except CompanySanitizedExportError:
        raise
    except Exception as exc:
        raise CompanySanitizedExportError("checkpoint snapshot reconstruction failed") from exc
    finally:
        if model is not None:
            model.close()
        if ledger is not None:
            ledger.close()
        shutil.rmtree(temporary_root, ignore_errors=True)


def _assert_active_checkpoint_binding(
    resolved: ResolvedCompanyState,
    checkpoint_manifest: Mapping[str, Any],
) -> None:
    company = checkpoint_manifest.get("company")
    if not isinstance(company, Mapping):
        raise CompanySanitizedExportError(
            "checkpoint company binding is unavailable",
        )
    expected = resolved.pointer
    if (
        company.get("company_id") != expected.company_id
        or company.get("company_incarnation")
        != expected.company_incarnation
        or company.get("lock_domain_generation")
        != expected.lock_domain_generation
        or company.get("manifest_sha256") != expected.manifest_sha256
        or company.get("pointer_sha256") != expected.pointer_sha256
    ):
        raise CompanySanitizedExportError(
            "checkpoint differs from the active company incarnation",
        )


def _export_warnings(warnings: list[str]) -> list[str]:
    result = list(warnings)
    if _OPERATIONAL_REDACTION_WARNING not in result:
        result.append(_OPERATIONAL_REDACTION_WARNING)
    return result


def _bundle(
    *, checkpoint_path: Path, checkpoint_manifest_sha256: str,
    checkpoint_manifest: Mapping[str, Any], generated_at: str,
    completeness: str, warnings: list[str], snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    company = checkpoint_manifest["company"]
    ledger = checkpoint_manifest["ledger"]
    return {
        "schema_version": SANITIZED_EXPORT_SCHEMA_VERSION,
        "checkpoint": {
            "checkpoint_id": checkpoint_path.name,
            "manifest_sha256": checkpoint_manifest_sha256,
        },
        "company": {
            "company_id": company["company_id"],
            "company_incarnation": company["company_incarnation"],
            "lock_domain_generation": company["lock_domain_generation"],
            "manifest_sha256": company["manifest_sha256"],
        },
        "ledger": {"cursor": ledger["global_sequence"], "head_sha256": ledger["transaction_sha256"]},
        "generated_at": generated_at,
        "completeness": completeness,
        "warnings": _export_warnings(warnings),
        "snapshot": snapshot,
    }


def _publish_no_replace(stage: Path, target: Path) -> None:
    if os.name == "nt":
        os.rename(stage, target)
        return
    try:
        os.link(stage, target)
    except FileExistsError:
        raise
    except OSError as exc:
        if exc.errno in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(exc.errno, os.strerror(exc.errno), os.fspath(target)) from exc
        raise CompanySanitizedExportError("atomic no-replace export publication is unavailable") from exc
    stage.unlink()


def _fsync_directory(path: Path) -> None:
    """Durably order a POSIX export entry; Windows has no equivalent here."""

    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise CompanySanitizedExportError("export root fsync cannot be opened") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise CompanySanitizedExportError("export root fsync failed") from exc
    finally:
        os.close(descriptor)


def _remove_stage(stage: Path) -> None:
    if not stage.name.startswith(_STAGE_PREFIX):
        raise CompanySanitizedExportError("refusing to remove a non-export temporary")
    try:
        stage.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise CompanySanitizedExportError("export temporary cleanup failed") from exc


def write_sanitized_export(
    *,
    lock: CompanyLockWitness,
    resolved: ResolvedCompanyState,
    checkpoint_path: str | os.PathLike[str],
    export_id: str,
    generated_at: str,
) -> str:
    """Publish one exact-replay checkpoint-derived sanitized JSON bundle."""

    checkpoint = _absolute_path(checkpoint_path, "checkpoint path")
    identifier = _export_id(export_id)
    when = _timestamp(generated_at)
    _checkpoints, exports = _writer_roots(lock, resolved, checkpoint)
    snapshot, checkpoint_sha256, completeness, warnings, manifest = _snapshot_from_checkpoint(checkpoint, when)
    _assert_active_checkpoint_binding(resolved, manifest)
    bundle = _bundle(
        checkpoint_path=checkpoint, checkpoint_manifest_sha256=checkpoint_sha256,
        checkpoint_manifest=manifest, generated_at=when,
        completeness=completeness, warnings=warnings, snapshot=snapshot,
    )
    _validate_bundle(bundle)
    try:
        raw = canonical_company_json_bytes(
            bundle,
            max_bytes=MAX_SANITIZED_EXPORT_BYTES,
        )
    except CompanyContractError as exc:
        raise CompanySanitizedExportError(
            "sanitized export exceeds its canonical byte bound",
        ) from exc
    if len(raw) > MAX_SANITIZED_EXPORT_BYTES:
        raise CompanySanitizedExportError("sanitized export exceeds its byte bound")
    digest = _sha256(raw)
    target = exports / f"{identifier}.json"
    stage = exports / f"{_STAGE_PREFIX}{uuid.uuid4().hex}.json"
    try:
        with stage.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _assert_lock_binding(lock, resolved)
        try:
            _publish_no_replace(stage, target)
        except FileExistsError:
            existing = verify_sanitized_export(target, checkpoint_path=checkpoint)
            if existing.sha256 == digest:
                return digest
            raise CompanySanitizedExportError("export ID already has divergent content")
        _fsync_directory(exports)
        return digest
    finally:
        if stage.exists():
            _remove_stage(stage)


def _validate_bundle(value: Mapping[str, Any]) -> None:
    required = {"schema_version", "checkpoint", "company", "ledger", "generated_at", "completeness", "warnings", "snapshot"}
    if set(value) != required or value["schema_version"] != SANITIZED_EXPORT_SCHEMA_VERSION:
        raise CompanySanitizedExportError("sanitized export schema is invalid")
    _timestamp(value["generated_at"])
    checkpoint = value["checkpoint"]
    company = value["company"]
    ledger = value["ledger"]
    if not isinstance(checkpoint, dict) or set(checkpoint) != {"checkpoint_id", "manifest_sha256"}:
        raise CompanySanitizedExportError("sanitized export checkpoint binding is invalid")
    _export_id(checkpoint.get("checkpoint_id"))
    if not isinstance(checkpoint.get("manifest_sha256"), str) or _SHA256.fullmatch(checkpoint["manifest_sha256"]) is None:
        raise CompanySanitizedExportError("sanitized export checkpoint digest is invalid")
    if not isinstance(company, dict) or set(company) != {"company_id", "company_incarnation", "lock_domain_generation", "manifest_sha256"}:
        raise CompanySanitizedExportError("sanitized export company binding is invalid")
    if (
        not isinstance(company["company_id"], str)
        or not isinstance(company["company_incarnation"], int)
        or isinstance(company["company_incarnation"], bool)
        or company["company_incarnation"] < 1
        or not isinstance(company["lock_domain_generation"], int)
        or isinstance(company["lock_domain_generation"], bool)
        or company["lock_domain_generation"] < 1
        or not isinstance(company["manifest_sha256"], str)
        or _SHA256.fullmatch(company["manifest_sha256"]) is None
    ):
        raise CompanySanitizedExportError("sanitized export company tuple is invalid")
    if not isinstance(ledger, dict) or set(ledger) != {"cursor", "head_sha256"}:
        raise CompanySanitizedExportError("sanitized export ledger binding is invalid")
    if (
        not isinstance(ledger["cursor"], int)
        or isinstance(ledger["cursor"], bool)
        or ledger["cursor"] < 0
        or not isinstance(ledger["head_sha256"], str)
        or _SHA256.fullmatch(ledger["head_sha256"]) is None
        or value["completeness"] not in {"complete", "partial"}
        or not isinstance(value["warnings"], list)
        or len(value["warnings"]) > 256
        or any(not isinstance(item, str) or len(item) > 256 for item in value["warnings"])
        or not isinstance(value["snapshot"], dict)
    ):
        raise CompanySanitizedExportError("sanitized export fields are invalid")
    _assert_sanitized(value["snapshot"])
    if "export" in value["snapshot"]:
        raise CompanySanitizedExportError("sanitized export contains an inner export reference")


def verify_sanitized_export(
    path: str | os.PathLike[str],
    *,
    checkpoint_path: str | os.PathLike[str] | None = None,
) -> VerifiedSanitizedExport:
    """Purely verify canonical schema, redaction, and checkpoint binding."""

    export_path = _absolute_path(path, "sanitized export path")
    _assert_safe_ancestors(export_path.parent, "sanitized export ancestor")
    raw = _regular(export_path, "sanitized export")
    bundle = _canonical_bundle(raw)
    _validate_bundle(bundle)
    inferred = export_path.parent.parent / "checkpoints" / str(bundle["checkpoint"]["checkpoint_id"])
    checkpoint = inferred if checkpoint_path is None else _absolute_path(checkpoint_path, "checkpoint path")
    if checkpoint.name != bundle["checkpoint"]["checkpoint_id"]:
        raise CompanySanitizedExportError("sanitized export checkpoint ID differs")
    _assert_safe_ancestors(checkpoint.parent, "checkpoint ancestor")
    try:
        verified = verify_plain_checkpoint(checkpoint)
    except CompanyCheckpointError as exc:
        raise CompanySanitizedExportError("plain checkpoint verification failed") from exc
    company = verified.manifest["company"]
    ledger = verified.manifest["ledger"]
    if (
        verified.sha256 != bundle["checkpoint"]["manifest_sha256"]
        or bundle["company"] != {
            "company_id": company["company_id"],
            "company_incarnation": company["company_incarnation"],
            "lock_domain_generation": company["lock_domain_generation"],
            "manifest_sha256": company["manifest_sha256"],
        }
        or bundle["ledger"] != {"cursor": ledger["global_sequence"], "head_sha256": ledger["transaction_sha256"]}
    ):
        raise CompanySanitizedExportError("sanitized export checkpoint binding differs")
    (
        reconstructed_snapshot,
        reconstructed_checkpoint_sha256,
        reconstructed_completeness,
        reconstructed_warnings,
        _reconstructed_manifest,
    ) = _snapshot_from_checkpoint(
        checkpoint,
        str(bundle["generated_at"]),
    )
    if (
        reconstructed_checkpoint_sha256 != verified.sha256
        or bundle["snapshot"] != reconstructed_snapshot
        or bundle["completeness"] != reconstructed_completeness
        or bundle["warnings"] != _export_warnings(
            reconstructed_warnings,
        )
    ):
        raise CompanySanitizedExportError(
            "sanitized export snapshot differs from its checkpoint",
        )
    return VerifiedSanitizedExport(export_path, _sha256(raw), bundle)


__all__ = [
    "CompanySanitizedExportError",
    "MAX_SANITIZED_EXPORT_BYTES",
    "SANITIZED_EXPORT_SCHEMA_VERSION",
    "VerifiedSanitizedExport",
    "verify_sanitized_export",
    "write_sanitized_export",
]
