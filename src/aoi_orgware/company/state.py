"""Locked ownership of one active company ledger and replaceable read model."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
from typing import Any
from typing import Literal, Never, cast

from .blobs import BlobStore, BlobStoreError
from .contracts import (
    BLOB_REF_V1,
    COMPANY_MANIFEST_V1,
    CONTROL_INTENT_V1,
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    validate_execution_runtime_observation_receipt,
    validate_execution_runtime_observation_source,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    NEEDS_USER_ANSWER_MEDIA_TYPE,
    NEEDS_USER_QUESTION_MEDIA_TYPE,
    NEEDS_USER_REVISION_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    TASK_REVISION_V1,
    USAGE_COUNTER_SAMPLE_V1,
    WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_department_snapshot_document,
    validate_engineering_disposition_source,
    validate_execution_event,
    validate_external_job_effect_receipt,
    validate_external_job_effect_source,
    validate_needs_user_revision,
    validate_company_transaction_request,
    validate_provider_telemetry_receipt,
    validate_usage_counter_sample,
    validate_provider_lifecycle_receipt,
    validate_provider_lifecycle_source,
    validate_provider_turn_result,
    validate_provider_turn_result_receipt,
    validate_provider_worker_io_receipt,
    validate_work_context_manifest,
    validate_work_definition_bundle,
)
from .invariants import (
    CompanyInvariantError,
    InvariantObject,
    InvariantTransition,
    reduce_company_invariants,
    validate_provider_turn_result_lifecycle,
)
from .ledger import (
    CompanyLedger,
    LedgerAppendResult,
    LedgerCommitEffectUnknownError,
    LedgerHead,
    LedgerHeadsSnapshot,
    LedgerTransactionRecord,
)
from .process_lock import CompanyProcessLock, CompanyProcessLockBusyError
from .readmodel import (
    CompanyReadModel,
    ProjectedObject,
    ReadModelCorruptionError,
    ReadModelError,
    ReadModelHead,
)
from .state_reader import (
    CompanyCheckpointDelivery,
    CompanyDeliverySnapshot,
    CompanyHistoricalReplayInput,
    CompanyQuerySnapshot,
    CompanySanitizedExportDelivery,
    CompanyStateHealth,
    CompanyStateReaderError,
    _DEFAULT_DELIVERY_SNAPSHOT,
    _unavailable_checkpoint,
    _unavailable_sanitized_export,
    immutable_historical_replay_input,
    immutable_ledger_heads,
    validate_historical_ledger_snapshot,
)
from .registry import (
    CompanyRegistry,
    ResolvedCompanyState,
)
from .telemetry import (
    normalize_claude_telemetry,
    normalize_codex_telemetry,
    provider_native_relation_payload,
    telemetry_facts_payload,
)


class CompanyStateError(RuntimeError):
    """The active company state cannot be opened or projected safely."""


class CompanyStateClosedError(CompanyStateError):
    """The state owner has already released its lifetime lock."""


class CompanyStateInvariantError(CompanyStateError):
    """A requested dispatch violates the durable company admission rules."""


class CompanyProjectionDegradedError(CompanyStateError):
    """The ledger committed but its replaceable projection could not recover."""

    def __init__(self, result: LedgerAppendResult) -> None:
        super().__init__(
            "ledger transaction committed but read-model recovery failed",
        )
        self.result = result


class CompanyDeliveryPartialError(CompanyStateError):
    """Checkpoint published, but its requested sanitized export did not."""

    def __init__(self, snapshot: CompanyDeliverySnapshot) -> None:
        super().__init__("checkpoint published but sanitized export creation failed")
        self.snapshot = snapshot


_MAX_WORK_PROMPT_BYTES = 256 * 1024


_LOCAL_SLOTS_LOCK = threading.Lock()
_LOCAL_SLOTS: set[str] = set()


def _local_slot_key(path: Path) -> str:
    return os.path.normcase(str(path.absolute()))


def _claim_local_slot(path: Path) -> str:
    key = _local_slot_key(path)
    with _LOCAL_SLOTS_LOCK:
        if key in _LOCAL_SLOTS:
            raise CompanyProcessLockBusyError(
                f"company slot already has an owner in this process: {path}",
            )
        _LOCAL_SLOTS.add(key)
    return key


def _release_local_slot(key: str) -> None:
    with _LOCAL_SLOTS_LOCK:
        _LOCAL_SLOTS.discard(key)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(member) for key, member in value.items()}
    if isinstance(value, tuple):
        return [_plain(member) for member in value]
    if isinstance(value, list):
        return [_plain(member) for member in value]
    return value


def _current_invariant_objects(
    objects: Sequence[ProjectedObject],
) -> tuple[InvariantObject, ...]:
    """Detach the replaceable projection into reducer-owned current records."""

    return tuple(
        InvariantObject(
            contract_type=item.contract_type,
            object_key=item.object_key,
            event_id=item.event_id,
            global_sequence=item.global_sequence,
            payload_sha256=company_contract_sha256(_plain(item.payload)),
            payload=_plain(item.payload),
        )
        for item in objects
    )


def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if not isinstance(attributes, int) or not isinstance(reparse, int):
        raise CompanyStateError(
            "Windows reparse-point inspection is unavailable",
        )
    return bool(attributes & reparse)


def _assert_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CompanyStateError(f"{label} is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_windows_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise CompanyStateError(f"{label} must be a non-link directory")


def _ensure_slot_root(root: Path) -> None:
    if not root.is_absolute() or ".." in root.parts:
        raise CompanyStateError(
            "company slot must be an explicit traversal-free absolute path",
        )
    missing: list[Path] = []
    cursor = root
    while not cursor.exists():
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            raise CompanyStateError(
                "company slot has no trusted existing ancestor",
            )
        cursor = parent
    _assert_directory(cursor, "company slot ancestor")
    for path in reversed(missing):
        try:
            path.mkdir(mode=0o700)
            if os.name != "nt":
                path.chmod(0o700)
        except OSError as exc:
            raise CompanyStateError(
                f"cannot create company slot directory: {path}",
            ) from exc
        _assert_directory(path, "company slot directory")
    _assert_directory(root, "company slot")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class CompanyStateOwner:
    """Own all active company storage behind one lifetime process lock."""

    def __init__(
        self,
        *,
        registry: CompanyRegistry,
        lock: CompanyProcessLock,
        resolved: ResolvedCompanyState,
        local_slot_key: str,
    ) -> None:
        self.registry = registry
        self.lock = lock
        self.resolved = resolved
        self._local_slot_key = local_slot_key
        self._mutex = threading.RLock()
        self.__ledger: CompanyLedger | None = None
        self._readmodel: CompanyReadModel | None = None
        self._blobs: BlobStore | None = None
        self._closed = False
        self._projection_status = "opening"
        self._blob_status = "checking"
        self._degradation_reasons: tuple[str, ...] = ()
        self._delivery_snapshot = _DEFAULT_DELIVERY_SNAPSHOT
        try:
            self._open_storage()
        except BaseException:
            try:
                if self._readmodel is not None:
                    self._readmodel.close()
            finally:
                self._readmodel = None
                try:
                    if self.__ledger is not None:
                        CompanyLedger.close(self.__ledger)
                finally:
                    self.__ledger = None
                    self._blobs = None
            raise

    @classmethod
    def initialize(
        cls,
        slot_root: str | os.PathLike[str],
        manifest: Mapping[str, Any],
        *,
        platform: str,
        lock_timeout_seconds: float = 5.0,
    ) -> CompanyStateOwner:
        root = Path(slot_root)
        _ensure_slot_root(root)
        local_slot_key = _claim_local_slot(root)
        registry = CompanyRegistry(root)
        lock = CompanyProcessLock(
            registry.paths.lock,
            timeout_seconds=lock_timeout_seconds,
        )
        try:
            lock.acquire()
        except BaseException:
            lock.close()
            _release_local_slot(local_slot_key)
            raise
        try:
            resolved = registry.initialize(
                lock,
                manifest,
                platform=platform,
            )
            return cls(
                registry=registry,
                lock=lock,
                resolved=resolved,
                local_slot_key=local_slot_key,
            )
        except BaseException:
            lock.close()
            _release_local_slot(local_slot_key)
            raise

    @classmethod
    def open(
        cls,
        slot_root: str | os.PathLike[str],
        *,
        lock_timeout_seconds: float = 5.0,
    ) -> CompanyStateOwner:
        root = Path(slot_root)
        _assert_directory(root, "company slot")
        local_slot_key = _claim_local_slot(root)
        registry = CompanyRegistry(root)
        lock = CompanyProcessLock(
            registry.paths.lock,
            timeout_seconds=lock_timeout_seconds,
            create_if_missing=False,
        )
        try:
            lock.acquire()
        except BaseException:
            lock.close()
            _release_local_slot(local_slot_key)
            raise
        try:
            resolved = registry.resolve_current(lock)
            return cls(
                registry=registry,
                lock=lock,
                resolved=resolved,
                local_slot_key=local_slot_key,
            )
        except BaseException:
            lock.close()
            _release_local_slot(local_slot_key)
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise CompanyStateClosedError(
                "company state owner is closed",
            )
        self.lock.assert_owned()

    @property
    def ledger(self) -> Never:
        """Deny raw append access; reads use owner APIs and writes use commit()."""

        raise CompanyStateError(
            "raw company ledger access is unavailable; use heads(), "
            "records_after(), record_by_transaction_id(), "
            "record_by_command_id(), or commit()",
        )

    @property
    def readmodel(self) -> CompanyReadModel:
        self._require_open()
        if self._readmodel is None:
            raise CompanyStateError("company read model is unavailable")
        return self._readmodel

    @property
    def blobs(self) -> BlobStore:
        self._require_open()
        if self._blobs is None:
            raise CompanyStateError("company blob store is unavailable")
        return self._blobs

    def _open_storage(self) -> None:
        self.lock.assert_owned()
        paths = self.resolved.incarnation
        self._blobs = BlobStore(paths.blobs)
        self.__ledger = CompanyLedger(paths.ledger)
        try:
            self._readmodel = CompanyReadModel(paths.readmodel)
        except ReadModelError:
            self._readmodel = None
            self._rebuild_projection_unlocked()
        self._synchronize_projection_unlocked()
        self._validate_binding_unlocked()
        self._verify_snapshot_blobs_unlocked()
        self._verify_work_definition_blobs_unlocked()
        self._projection_status = "ready"
        self._refresh_current_blob_health_unlocked()
        self._discover_delivery_unlocked()

    def _synchronize_projection_unlocked(self) -> None:
        ledger = cast(CompanyLedger, self.__ledger)
        model = self.readmodel
        ledger_heads = CompanyLedger.snapshot_heads(ledger)
        model_head = model.head()
        if (
            model_head.global_sequence > ledger_heads.global_head.global_sequence
            or (
                model_head.global_sequence
                == ledger_heads.global_head.global_sequence
                and model_head.transaction_sha256
                != ledger_heads.global_head.transaction_sha256
            )
        ):
            self._rebuild_projection_unlocked()
            return
        cursor = model_head.global_sequence
        while cursor < ledger_heads.global_head.global_sequence:
            records = CompanyLedger.records_after(ledger, cursor, limit=1024)
            if not records:
                raise CompanyStateError(
                    "ledger catch-up returned an empty nonterminal page",
                )
            model.apply_many(records)
            cursor = records[-1].global_sequence
        final_head = model.head()
        if (
            final_head.global_sequence
            != ledger_heads.global_head.global_sequence
            or final_head.transaction_sha256
            != ledger_heads.global_head.transaction_sha256
        ):
            raise CompanyStateError(
                "read model does not project the active ledger head",
            )

    def _rebuild_projection_unlocked(self) -> None:
        """Close-before-replace rebuild owned by the lifetime state lock."""

        self.lock.assert_owned()
        self._projection_status = "rebuilding"
        if self._readmodel is not None:
            self._readmodel.close()
            self._readmodel = None
        ledger = cast(CompanyLedger, self.__ledger)
        records = CompanyLedger.load_records(ledger)
        target = self.resolved.incarnation.readmodel
        if os.name == "nt":
            # Windows may deny replace-over-existing even after SQLite and the
            # path guard are closed.  The projection is non-authoritative, so
            # deleting it under the lifetime lock is a safe crash boundary:
            # the next open rebuilds it from the ledger.
            for candidate in (
                target,
                target.with_name(f"{target.name}-wal"),
                target.with_name(f"{target.name}-shm"),
            ):
                try:
                    candidate.unlink(missing_ok=True)
                except OSError as exc:
                    self._projection_status = "degraded"
                    raise CompanyStateError(
                        f"cannot retire the closed read model: {candidate}",
                    ) from exc
        CompanyReadModel.rebuild(
            target,
            records,
        )
        _fsync_directory(self.resolved.incarnation.root)
        self._readmodel = CompanyReadModel(
            self.resolved.incarnation.readmodel,
        )
        ledger_head = CompanyLedger.snapshot_heads(ledger).global_head
        projection_head = self._readmodel.verify_integrity()
        if (
            projection_head.global_sequence != ledger_head.global_sequence
            or projection_head.transaction_sha256
            != ledger_head.transaction_sha256
        ):
            self._projection_status = "degraded"
            raise CompanyStateError(
                "rebuilt read model does not match the ledger head",
            )
        self._projection_status = "ready"

    def rebuild_projection(self) -> ReadModelHead:
        with self._mutex:
            self._require_open()
            self._rebuild_projection_unlocked()
            self._validate_binding_unlocked()
            self._verify_snapshot_blobs_unlocked()
            self._verify_work_definition_blobs_unlocked()
            self._refresh_current_blob_health_unlocked()
            return self.readmodel.head()

    def _validate_binding_unlocked(self) -> None:
        ledger = cast(CompanyLedger, self.__ledger)
        heads = CompanyLedger.snapshot_heads(ledger)
        expected_identity = (
            str(self.resolved.manifest["company_id"]),
            int(self.resolved.manifest["company_incarnation"]),
            int(self.resolved.manifest["lock_domain_generation"]),
        )
        if heads.identity not in {None, expected_identity}:
            raise CompanyStateError(
                "ledger identity differs from active registry binding",
            )
        model_head = self.readmodel.head()
        if model_head.global_sequence == 0:
            if heads.global_head.global_sequence != 0:
                raise CompanyStateError(
                    "empty projection differs from non-empty ledger",
                )
            return
        if (
            model_head.company_id,
            model_head.company_incarnation,
            model_head.lock_domain_generation,
        ) != expected_identity:
            raise CompanyStateError(
                "read-model identity differs from active registry binding",
            )
        manifests = self.readmodel.objects(
            contract_type=COMPANY_MANIFEST_V1,
        )
        if (
            len(manifests) != 1
            or canonical_company_json_bytes(_plain(manifests[0].payload))
            != canonical_company_json_bytes(
                _plain(self.resolved.manifest),
            )
        ):
            raise CompanyStateError(
                "ledger manifest projection differs from registry manifest",
            )

    def _read_snapshot_document_unlocked(
        self,
        reference: Mapping[str, Any],
    ) -> dict[str, Any]:
        if (
            reference.get("availability") != "available"
            or reference.get("media_type")
            != DEPARTMENT_SNAPSHOT_MEDIA_TYPE
        ):
            raise CompanyStateError(
                "department snapshot document reference is unavailable",
            )
        try:
            raw = self.blobs.read(str(reference["sha256"]))
            if len(raw) != int(reference["size_bytes"]):
                raise CompanyStateError(
                    "department snapshot document size differs",
                )
            document = validate_department_snapshot_document(
                json.loads(raw.decode("utf-8")),
            )
            if canonical_company_json_bytes(document) != raw:
                raise CompanyStateError(
                    "department snapshot document is not canonical JSON",
                )
            return document
        except CompanyStateError:
            raise
        except (
            BlobStoreError,
            OSError,
            CompanyContractError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise CompanyStateError(
                "department snapshot document cannot be verified",
            ) from exc

    def _verify_snapshot_member_refs_unlocked(
        self,
        document: Mapping[str, Any],
    ) -> None:
        fields = (
            "charter_ref",
            "constraints_ref",
            "decisions_ref",
            "dissent_ref",
            "open_questions_ref",
            "blockers_ref",
            "risks_ref",
            "backlog_ref",
            "handoff_ref",
        )
        for field in fields:
            reference = document[field]
            try:
                metadata = self.blobs.metadata(str(reference["sha256"]))
                if metadata.size_bytes != int(reference["size_bytes"]):
                    raise CompanyStateError(
                        "department snapshot member size differs",
                    )
            except CompanyStateError:
                raise
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateError(
                    "department snapshot member cannot be verified",
                ) from exc
        for reference in document["artifact_refs"]:
            try:
                metadata = self.blobs.metadata(str(reference["sha256"]))
                if metadata.size_bytes != int(reference["size_bytes"]):
                    raise CompanyStateError(
                        "department snapshot artifact size differs",
                    )
            except CompanyStateError:
                raise
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateError(
                    "department snapshot artifact cannot be verified",
                ) from exc

    def _verify_snapshot_blobs_unlocked(self) -> None:
        """Audit every durable snapshot document and predecessor on open."""

        snapshots_by_id: dict[str, Mapping[str, Any]] = {}
        ledger = cast(CompanyLedger, self.__ledger)
        for record in CompanyLedger.load_records(ledger):
            for member in record.events:
                payload = member.event["payload"]
                if payload.get("contract_type") != DEPARTMENT_SNAPSHOT_V1:
                    continue
                snapshot_id = str(payload["snapshot_id"])
                if snapshot_id in snapshots_by_id:
                    raise CompanyStateError(
                        "department snapshot ID is duplicated",
                    )
                snapshots_by_id[snapshot_id] = payload
        named_digests = {
            "charter_sha256": "charter_ref",
            "constraints_sha256": "constraints_ref",
            "decisions_sha256": "decisions_ref",
            "open_questions_sha256": "open_questions_ref",
            "handoff_sha256": "handoff_ref",
        }
        for snapshot_id, snapshot in snapshots_by_id.items():
            references = snapshot["artifact_refs"]
            if (
                not isinstance(references, Sequence)
                or isinstance(references, (str, bytes, bytearray))
                or len(references) != 1
                or not isinstance(references[0], Mapping)
            ):
                raise CompanyStateError(
                    "department snapshot lacks one document reference",
                )
            reference = references[0]
            document = self._read_snapshot_document_unlocked(reference)
            self._verify_snapshot_member_refs_unlocked(document)
            if (
                document["snapshot_id"] != snapshot_id
                or document["company_id"] != snapshot["company_id"]
                or document["company_incarnation"]
                != snapshot["company_incarnation"]
                or document["lock_domain_generation"]
                != snapshot["lock_domain_generation"]
                or document["department_id"] != snapshot["department_id"]
                or document["revision"] != snapshot["revision"]
                or document["previous_snapshot_id"]
                != snapshot["previous_snapshot_id"]
                or document["company_cursor"]
                != snapshot["company_cursor"]
                or document["captured_at"] != snapshot["captured_at"]
                or any(
                    snapshot[digest_name]
                    != document[reference_name]["sha256"]
                    for digest_name, reference_name
                    in named_digests.items()
                )
            ):
                raise CompanyStateError(
                    "department snapshot differs from its document",
                )
            previous_snapshot_id = document["previous_snapshot_id"]
            previous_document_sha256 = document[
                "previous_document_sha256"
            ]
            if previous_snapshot_id is None:
                if previous_document_sha256 is not None:
                    raise CompanyStateError(
                        "genesis department snapshot predecessor differs",
                    )
                continue
            previous = snapshots_by_id.get(str(previous_snapshot_id))
            if previous is None:
                raise CompanyStateError(
                    "department snapshot predecessor is missing",
                )
            previous_refs = previous["artifact_refs"]
            if (
                len(previous_refs) != 1
                or previous_document_sha256
                != previous_refs[0]["sha256"]
            ):
                raise CompanyStateError(
                    "department snapshot predecessor digest differs",
                )

    def _read_work_prompt_unlocked(
        self,
        reference: Mapping[str, Any],
    ) -> bytes:
        """Read one exact, bounded UTF-8 prompt from the company CAS."""

        if (
            reference.get("availability") != "available"
            or reference.get("media_type") != WORK_PACKET_PROMPT_MEDIA_TYPE
        ):
            raise CompanyStateError(
                "work packet prompt reference is unavailable",
            )
        try:
            raw = self.blobs.read(str(reference["sha256"]))
            if (
                len(raw) != int(reference["size_bytes"])
                or not raw
                or len(raw) > _MAX_WORK_PROMPT_BYTES
            ):
                raise CompanyStateError(
                    "work packet prompt size differs",
                )
            text = raw.decode("utf-8")
            if text.encode("utf-8") != raw or "\x00" in text:
                raise CompanyStateError(
                    "work packet prompt is not canonical UTF-8 text",
                )
            return raw
        except CompanyStateError:
            raise
        except (
            BlobStoreError,
            OSError,
            UnicodeDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise CompanyStateError(
                "work packet prompt bytes cannot be verified",
            ) from exc

    def _read_work_context_manifest_unlocked(
        self,
        reference: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Read one canonical WorkContextManifest and all nested blob refs."""

        if (
            reference.get("availability") != "available"
            or reference.get("media_type") != WORK_CONTEXT_MANIFEST_MEDIA_TYPE
        ):
            raise CompanyStateError(
                "work context manifest reference is unavailable",
            )
        try:
            raw = self.blobs.read(str(reference["sha256"]))
            if len(raw) != int(reference["size_bytes"]):
                raise CompanyStateError(
                    "work context manifest size differs",
                )
            document = validate_work_context_manifest(
                json.loads(raw.decode("utf-8")),
            )
            if canonical_company_json_bytes(document) != raw:
                raise CompanyStateError(
                    "work context manifest is not canonical JSON",
                )
            for nested in self._available_blob_refs(document):
                metadata = self.blobs.metadata(str(nested["sha256"]))
                if metadata.size_bytes != int(nested["size_bytes"]):
                    raise CompanyStateError(
                        "work context nested blob size differs",
                    )
            return document
        except CompanyStateError:
            raise
        except (
            BlobStoreError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            CompanyContractError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise CompanyStateError(
                "work context manifest bytes cannot be verified",
            ) from exc

    def _verify_work_definition_request_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Bind new work packets to exact prompt/context CAS bytes pre-append."""

        tasks: dict[str, Mapping[str, Any]] = {}
        packets: dict[str, Mapping[str, Any]] = {}
        result_receipts = [
            _plain(item.payload)
            for item in self.readmodel.objects(
                contract_type=WORK_RESULT_RECEIPT_V1,
            )
        ]
        for event in request.get("events", ()):
            if not (
                isinstance(event, Mapping)
                and isinstance(event.get("payload"), Mapping)
            ):
                continue
            payload = event["payload"]
            if payload.get("contract_type") == TASK_REVISION_V1:
                task_revision_id = str(payload["task_revision_id"])
                prior_task = tasks.setdefault(task_revision_id, payload)
                if prior_task != payload:
                    raise CompanyStateInvariantError(
                        "task revision ID is duplicated in one transaction",
                    )
            elif payload.get("contract_type") == WORK_PACKET_V1:
                packet_id = str(payload["packet_id"])
                prior_packet = packets.setdefault(packet_id, payload)
                if prior_packet != payload:
                    raise CompanyStateInvariantError(
                        "work packet ID is duplicated in one transaction",
                    )
            elif payload.get("contract_type") == WORK_RESULT_RECEIPT_V1:
                result_receipts.append(_plain(payload))
        for packet in packets.values():
            task_revision_id = str(packet["task_revision_id"])
            task = tasks.get(task_revision_id)
            if task is None:
                projected = self.readmodel.object(
                    TASK_REVISION_V1,
                    task_revision_id,
                )
                if projected is None:
                    raise CompanyStateInvariantError(
                        "work packet task revision is not durable",
                    )
                task = _plain(projected.payload)
            self._read_work_prompt_unlocked(packet["prompt_ref"])
            context = self._read_work_context_manifest_unlocked(
                packet["context_manifest_ref"],
            )
            parent = None
            parent_context = None
            parent_packet_id = packet["parent_packet_id"]
            if parent_packet_id is not None:
                parent = packets.get(str(parent_packet_id))
                if parent is None:
                    projected_parent = self.readmodel.object(
                        WORK_PACKET_V1,
                        str(parent_packet_id),
                    )
                    if projected_parent is None:
                        raise CompanyStateInvariantError(
                            "work packet parent is not durable",
                        )
                    parent = _plain(projected_parent.payload)
                self._read_work_prompt_unlocked(parent["prompt_ref"])
                parent_context = self._read_work_context_manifest_unlocked(
                    parent["context_manifest_ref"],
                )
            try:
                validated_bundle = validate_work_definition_bundle(
                    task,
                    packet,
                    context,
                    parent_packet=parent,
                    parent_context_manifest=parent_context,
                )
            except CompanyContractError as exc:
                raise CompanyStateInvariantError(
                    "work definition CAS bundle is invalid",
                ) from exc
            for reference in validated_bundle["context_derivation"][
                "added_upstream_result_refs"
            ]:
                matches = [
                    result
                    for result in result_receipts
                    if (
                        result["packet_id"] == parent_packet_id
                        and result["producer_execution_id"]
                        == packet["parent_execution_id"]
                        and result["result_ref"] == reference
                    )
                ]
                if len(matches) != 1:
                    raise CompanyStateInvariantError(
                        "work context upstream result lacks one durable producer",
                    )

    def _verify_work_definition_blobs_unlocked(self) -> None:
        """Audit every registered work definition and retained result on open."""

        tasks = {
            str(item.payload["task_revision_id"]): _plain(item.payload)
            for item in self.readmodel.objects(
                contract_type=TASK_REVISION_V1,
            )
        }
        packets = {
            str(item.payload["packet_id"]): _plain(item.payload)
            for item in self.readmodel.objects(
                contract_type=WORK_PACKET_V1,
            )
        }
        contexts: dict[str, dict[str, Any]] = {}
        for packet_id, packet in packets.items():
            self._read_work_prompt_unlocked(packet["prompt_ref"])
            contexts[packet_id] = self._read_work_context_manifest_unlocked(
                packet["context_manifest_ref"],
            )
        result_receipts = [
            _plain(item.payload)
            for item in self.readmodel.objects(
                contract_type=WORK_RESULT_RECEIPT_V1,
            )
        ]
        for packet_id, packet in sorted(
            packets.items(),
            key=lambda member: (
                int(member[1]["delegation_depth"]),
                member[0],
            ),
        ):
            task = tasks.get(str(packet["task_revision_id"]))
            if task is None:
                raise CompanyStateError(
                    "registered work packet task revision is missing",
                )
            parent_id = packet["parent_packet_id"]
            parent = (
                None
                if parent_id is None
                else packets.get(str(parent_id))
            )
            parent_context = (
                None
                if parent_id is None
                else contexts.get(str(parent_id))
            )
            try:
                validated_bundle = validate_work_definition_bundle(
                    task,
                    packet,
                    contexts[packet_id],
                    parent_packet=parent,
                    parent_context_manifest=parent_context,
                )
            except CompanyContractError as exc:
                raise CompanyStateError(
                    "registered work definition cannot be replayed",
                ) from exc
            added_refs = validated_bundle["context_derivation"][
                "added_upstream_result_refs"
            ]
            for reference in added_refs:
                matches = [
                    result
                    for result in result_receipts
                    if (
                        result["packet_id"] == parent_id
                        and result["producer_execution_id"]
                        == packet["parent_execution_id"]
                        and result["result_ref"] == reference
                    )
                ]
                if len(matches) != 1:
                    raise CompanyStateError(
                        "work context upstream result lacks one durable producer",
                    )
        retained = [
            _plain(item.payload)
            for item in self.readmodel.objects(
                contract_type=TASK_REVISION_V1,
            )
        ]
        retained.extend(
            _plain(item.payload)
            for item in self.readmodel.objects(
                contract_type=WORK_RESULT_RECEIPT_V1,
            )
        )
        for reference in self._available_blob_refs(retained):
            try:
                metadata = self.blobs.metadata(str(reference["sha256"]))
                if metadata.size_bytes != int(reference["size_bytes"]):
                    raise CompanyStateError(
                        "registered work retained blob size differs",
                    )
            except CompanyStateError:
                raise
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateError(
                    "registered work retained blob is unavailable",
                ) from exc

    @staticmethod
    def _available_blob_refs(value: Any) -> tuple[Mapping[str, Any], ...]:
        references: list[Mapping[str, Any]] = []

        def inspect(member: Any) -> None:
            if isinstance(member, Mapping):
                if (
                    member.get("contract_type") == BLOB_REF_V1
                    and member.get("availability") == "available"
                ):
                    references.append(member)
                    return
                for child in member.values():
                    inspect(child)
            elif (
                isinstance(member, Sequence)
                and not isinstance(member, (str, bytes, bytearray))
            ):
                for child in member:
                    inspect(child)

        inspect(value)
        return tuple(references)

    def _verify_new_available_blob_refs_unlocked(
        self,
        request: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
    ) -> None:
        """Reject a new durable ``available`` claim before the ledger append."""

        for reference in self._available_blob_refs((request, evidence)):
            try:
                metadata = self.blobs.metadata(str(reference["sha256"]))
                if metadata.size_bytes != int(reference["size_bytes"]):
                    raise CompanyStateInvariantError(
                        "new available blob size differs from stored bytes",
                    )
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "new available blob bytes cannot be verified",
                ) from exc

    def _verify_provider_lifecycle_sources_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Validate raw provider bytes at the sole-writer boundary."""

        shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "event_kind",
            "dispatch_request_id",
            "provider_dispatch_id",
            "execution_id",
            "carrier_id",
            "organization_node_id",
            "provider",
            "model",
            "effort",
            "session_id",
            "thread_id",
            "reconcile_ref",
            "observed_at",
            "provenance",
            "observation",
        )
        for event in request.get("events", ()):
            if (
                not isinstance(event, Mapping)
                or not isinstance(event.get("payload"), Mapping)
                or event["payload"].get("contract_type")
                != PROVIDER_LIFECYCLE_RECEIPT_V1
            ):
                continue
            try:
                receipt = validate_provider_lifecycle_receipt(
                    event["payload"],
                )
                raw_bytes = self.blobs.read(
                    str(receipt["raw_artifact"]["sha256"]),
                )
                source = validate_provider_lifecycle_source(
                    json.loads(raw_bytes.decode("utf-8")),
                )
                if (
                    canonical_company_json_bytes(source) != raw_bytes
                    or any(
                        receipt[field] != source[field]
                        for field in shared_fields
                    )
                ):
                    raise CompanyStateInvariantError(
                        "provider lifecycle source differs from its receipt",
                    )
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                CompanyContractError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "provider lifecycle source bytes are invalid",
                ) from exc

    def _verify_provider_worker_artifacts_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Reopen canonical provider CAS and its exact stopped lifecycle join."""
        io_by_id: dict[str, Mapping[str, Any]] = {}
        for event in request.get("events", ()):
            if not isinstance(event, Mapping) or not isinstance(event.get("payload"), Mapping):
                continue
            payload = event["payload"]
            try:
                if payload.get("contract_type") == PROVIDER_WORKER_IO_RECEIPT_V1:
                    receipt = validate_provider_worker_io_receipt(payload)
                    raw = self.blobs.read(str(receipt["raw_artifact"]["sha256"]))
                    if len(raw) != int(receipt["raw_artifact"]["size_bytes"]):
                        raise CompanyStateInvariantError("provider worker raw size differs")
                    io_by_id[receipt["receipt_id"]] = receipt
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError,
                CompanyContractError, KeyError, TypeError, ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "provider worker CAS bytes are invalid",
                ) from exc

        idle_dispositions: dict[str, str] = {}
        for event in request.get("events", ()):
            if not isinstance(event, Mapping) or not isinstance((payload := event.get("payload")), Mapping):
                continue
            if (
                event.get("event_type") == "evidence.provider_turn.idle.observed"
                and
                payload.get("contract_type") == EVIDENCE_RECORD_V1
                and str(payload.get("evidence_id", "")).startswith("provider-turn-idle-evidence-")
            ):
                result_id = str(payload["claim_id"])
                idle_dispositions[result_id] = str(event["recorded_at"])

        def validate_result_artifact(
            result_payload: Mapping[str, Any],
        ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
            try:
                receipt = validate_provider_turn_result_receipt(result_payload)
                raw = self.blobs.read(str(receipt["result_ref"]["sha256"]))
                document = validate_provider_turn_result(json.loads(raw.decode("utf-8")))
                if canonical_company_json_bytes(document) != raw:
                    raise CompanyStateInvariantError("provider turn result is not canonical JSON")
                if (
                    hashlib.sha256(raw).hexdigest() != receipt["result_ref"]["sha256"]
                    or len(raw) != int(receipt["result_ref"]["size_bytes"])
                ):
                    raise CompanyStateInvariantError("provider turn result size differs")
                if any(
                    receipt[field] != document[field]
                    for field in (
                        "company_id", "company_incarnation", "lock_domain_generation",
                        "launch_binding_id", "launch_binding_sha256", "operation_id",
                        "agent_execution_id", "turn_execution_id", "thread_id", "turn_id",
                        "terminal_status",
                    )
                ):
                    raise CompanyStateInvariantError("provider turn result differs from receipt")
                terminal = io_by_id.get(receipt["terminal_io_receipt_id"])
                if terminal is None:
                    projected = self.readmodel.object(
                        PROVIDER_WORKER_IO_RECEIPT_V1,
                        str(receipt["terminal_io_receipt_id"]),
                    )
                    if projected is None:
                        raise CompanyStateInvariantError("provider terminal I/O is unavailable")
                    terminal = _plain(projected.payload)
                terminal = validate_provider_worker_io_receipt(terminal)
                terminal_raw = self.blobs.read(str(terminal["raw_artifact"]["sha256"]))
                if (
                    hashlib.sha256(terminal_raw).hexdigest() != terminal["raw_artifact"]["sha256"]
                    or len(terminal_raw) != int(terminal["raw_artifact"]["size_bytes"])
                ):
                    raise CompanyStateInvariantError("provider terminal I/O raw size differs")
                if (
                    terminal["channel"] != "process"
                    or terminal["phase"] != "terminal_sealed"
                    or terminal["provenance"] != "adapter_receipt_persisted"
                    or terminal["observation"] != {"state": "known", "reason": "observed"}
                    or terminal["execution_id"] != receipt["turn_execution_id"]
                    or any(
                        terminal[field] != receipt[field]
                        for field in (
                            "operation_id", "launch_binding_id", "launch_binding_sha256",
                            "thread_id", "turn_id",
                        )
                    )
                ):
                    raise CompanyStateInvariantError(
                        "provider terminal I/O differs from result receipt",
                    )
                return receipt, document, terminal
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError,
                CompanyContractError, KeyError, TypeError, ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "provider worker CAS bytes are invalid",
                ) from exc

        for event in request.get("events", ()):
            if (
                isinstance(event, Mapping)
                and isinstance((payload := event.get("payload")), Mapping)
                and payload.get("contract_type") == PROVIDER_TURN_RESULT_RECEIPT_V1
            ):
                validate_result_artifact(payload)

        # Result receipt append retains its historical lightweight CAS/terminal
        # contract.  B50 is the only transaction that changes lifecycle state,
        # so only its idle evidence requires a full read-model join.
        if not idle_dispositions:
            return

        key_fields = {
            PROVIDER_WORKER_IO_RECEIPT_V1: "receipt_id",
            PROVIDER_WORKER_OPERATION_V1: "operation_id",
            PROVIDER_LAUNCH_BINDING_V1: "launch_binding_id",
            PROVIDER_TURN_RESULT_RECEIPT_V1: "result_receipt_id",
            EXECUTION_NODE_V1: "execution_id",
        }
        projected: dict[tuple[str, str], Mapping[str, Any]] = {
            (item.contract_type, str(item.payload[key_fields[item.contract_type]])): _plain(item.payload)
            for contract_type in key_fields
            for item in self.readmodel.objects(contract_type=contract_type)
        }
        for event in request.get("events", ()):
            if not isinstance(event, Mapping) or not isinstance(event.get("payload"), Mapping):
                continue
            payload = event["payload"]
            contract_type = payload.get("contract_type")
            key_field = key_fields.get(contract_type)
            if key_field is not None and key_field in payload:
                projected[(str(contract_type), str(payload[key_field]))] = payload

        for result_receipt_id, disposition_at in idle_dispositions.items():
            payload = projected.get((PROVIDER_TURN_RESULT_RECEIPT_V1, result_receipt_id))
            if payload is None:
                raise CompanyStateInvariantError("provider turn result receipt is unavailable")
            try:
                receipt, document, terminal = validate_result_artifact(payload)
                exits = [
                    value for (contract_type, _key), value in projected.items()
                    if (
                        contract_type == PROVIDER_WORKER_IO_RECEIPT_V1
                        and value["phase"] == "process_exit_observed"
                        and value["launch_binding_id"] == receipt["launch_binding_id"]
                        and value["execution_id"] == receipt["turn_execution_id"]
                        and value["thread_id"] == receipt["thread_id"]
                        and value["turn_id"] == receipt["turn_id"]
                    )
                ]
                if len(exits) != 1:
                    raise CompanyStateInvariantError("provider turn lacks one exact process exit")
                operation = projected.get((PROVIDER_WORKER_OPERATION_V1, str(receipt["operation_id"])))
                launch = projected.get((PROVIDER_LAUNCH_BINDING_V1, str(receipt["launch_binding_id"])))
                agent = projected.get((EXECUTION_NODE_V1, str(receipt["agent_execution_id"])))
                turn = projected.get((EXECUTION_NODE_V1, str(receipt["turn_execution_id"])))
                if operation is None or launch is None or agent is None or turn is None:
                    raise CompanyStateInvariantError("provider result lifecycle projection is unavailable")
                validate_provider_turn_result_lifecycle(
                    receipt, document, terminal, exits[0], operation, launch, agent, turn,
                    disposition_at,
                )
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError,
                CompanyContractError, KeyError, TypeError, ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "provider worker CAS bytes are invalid",
                ) from exc

    def _verify_runtime_observation_sources_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Bind every runtime inference to canonical, available raw bytes."""
        shared = (
            "company_id", "company_incarnation", "lock_domain_generation",
            "source_event_id", "receipt_id", "execution_id", "carrier_id",
            "transition", "activity_kind", "provider_registry", "host_process",
            "terminal_grace", "collector_health", "observed_at", "provenance",
            "observation",
        )
        for event in request.get("events", ()):
            if not isinstance(event, Mapping) or not isinstance(event.get("payload"), Mapping) or event["payload"].get("contract_type") != EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1:
                continue
            try:
                receipt = validate_execution_runtime_observation_receipt(event["payload"])
                raw = self.blobs.read(str(receipt["raw_artifact"]["sha256"]))
                source = validate_execution_runtime_observation_source(json.loads(raw.decode("utf-8")))
                if canonical_company_json_bytes(source) != raw or any(receipt[field] != source[field] for field in shared):
                    raise CompanyStateInvariantError("runtime observation source differs from receipt")
            except CompanyStateInvariantError:
                raise
            except (BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError, CompanyContractError, KeyError, TypeError, ValueError) as exc:
                raise CompanyStateInvariantError("runtime observation source bytes are invalid") from exc

    @staticmethod
    def _raw_token_vector_payload(vector: Any) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "present": getattr(vector, name) is not None,
                "tokens": getattr(vector, name),
            }
            for name in (
                "input", "cache_read", "cache_creation", "output",
                "reasoning_output", "total",
            )
        }

    @staticmethod
    def _plain_json_value(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): CompanyStateOwner._plain_json_value(member) for key, member in value.items()}
        if isinstance(value, tuple):
            return [CompanyStateOwner._plain_json_value(member) for member in value]
        if isinstance(value, list):
            return [CompanyStateOwner._plain_json_value(member) for member in value]
        return value

    def _normalize_provider_telemetry_receipt_unlocked(
        self,
        receipt: Mapping[str, Any],
    ) -> Any:
        """Read and replay one receipt without assigning AOI lineage."""
        raw = self.blobs.read(str(receipt["raw_artifact"]["sha256"]))
        if receipt["provider"] == "codex":
            normalized = normalize_codex_telemetry(raw)
        else:
            normalized = normalize_claude_telemetry(
                raw,
                cast(Literal["claude_hook", "otel"], receipt["source_class"]),
            )
        expected = {
            "provider": normalized.provider,
            "source_class": normalized.source_class,
            "parser_id": normalized.parser_id,
            "parser_version": normalized.parser_version,
            "parse_outcome": normalized.parse_outcome,
            "normalized_kind": normalized.normalized_kind,
            "facts": telemetry_facts_payload(normalized),
            "provider_native_relation": provider_native_relation_payload(
                normalized,
            ),
        }
        if (
            any(
                self._plain_json_value(receipt[key]) != value
                for key, value in expected.items()
            )
            or receipt["raw_artifact"]["sha256"] != normalized.raw_sha256
            or receipt["raw_artifact"]["size_bytes"]
            != normalized.raw_size_bytes
        ):
            raise CompanyStateInvariantError(
                "provider telemetry source differs from its receipt",
            )
        return normalized

    def _verify_provider_telemetry_sources_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Replay raw telemetry and bind cumulative counters in this append."""
        receipts: dict[str, tuple[Mapping[str, Any], Any]] = {}
        samples: list[Mapping[str, Any]] = []
        try:
            for event in request.get("events", ()):
                if not isinstance(event, Mapping) or not isinstance(
                    event.get("payload"), Mapping,
                ):
                    continue
                payload = event["payload"]
                if payload.get("contract_type") == PROVIDER_TELEMETRY_RECEIPT_V1:
                    receipt: Mapping[str, Any] = validate_provider_telemetry_receipt(payload)
                    receipt_id = str(receipt["receipt_id"])
                    if receipt_id in receipts:
                        raise CompanyStateInvariantError(
                            "provider telemetry receipt id is ambiguous",
                        )
                    receipts[receipt_id] = (
                        receipt,
                        self._normalize_provider_telemetry_receipt_unlocked(
                            receipt,
                        ),
                    )
                elif payload.get("contract_type") == USAGE_COUNTER_SAMPLE_V1:
                    samples.append(validate_usage_counter_sample(payload))
            samples_by_receipt: dict[str, list[Mapping[str, Any]]] = {}
            for sample in samples:
                samples_by_receipt.setdefault(
                    str(sample["telemetry_receipt_id"]),
                    [],
                ).append(sample)
                joined = receipts.get(str(sample["telemetry_receipt_id"]))
                if joined is None:
                    raise CompanyStateInvariantError(
                        "usage sample lacks a same-transaction telemetry receipt",
                    )
                receipt, normalized = joined
                if any(
                    sample[left] != receipt[right]
                    for left, right in (
                        ("telemetry_receipt_sha256", "receipt_sha256"),
                        ("adapter_instance_id", "adapter_instance_id"),
                        ("adapter_event_id", "adapter_event_id"),
                        ("intake_sequence", "intake_sequence"),
                        ("provider", "provider"),
                        ("raw_artifact", "raw_artifact"),
                        ("provenance", "provenance"),
                        ("received_at", "received_at"),
                    )
                ):
                    raise CompanyStateInvariantError(
                        "usage sample differs from its telemetry receipt",
                    )
                raw_sample = normalized.raw_cumulative_tokens
                facts = telemetry_facts_payload(normalized)
                exact_usage_identity = (
                    facts["thread_id"]["quality"] == "observed"
                    and facts["turn_id"]["quality"] == "observed"
                )
                expected_provenance_facts = {
                    name: facts[name]
                    for name in (
                        "actual_provider",
                        "actual_model",
                        "actual_effort",
                        "actual_role",
                        "routing",
                    )
                }
                if raw_sample is None or (
                    not exact_usage_identity
                    or sample["thread_id"] != facts["thread_id"]["value"]
                    or sample["turn_id"] != facts["turn_id"]["value"]
                    or sample["counter_scope_id"]
                    != facts["thread_id"]["value"]
                    or sample["provider_sequence"] is not None
                    or sample["counting_semantics"]
                    != "non_additive_cumulative"
                    or sample["provenance_facts"]
                    != expected_provenance_facts
                    or sample["total_token_vector"]
                    != self._raw_token_vector_payload(raw_sample.total)
                    or sample["last_token_vector"]
                    != self._raw_token_vector_payload(raw_sample.last)
                    or sample["model_context_window"]
                    != {
                        "present": raw_sample.model_context_window is not None,
                        "value": raw_sample.model_context_window,
                    }
                ):
                    raise CompanyStateInvariantError(
                        "usage sample differs from raw cumulative telemetry",
                    )
            for receipt_id, (_receipt, normalized) in receipts.items():
                expected_count = int(
                    normalized.raw_cumulative_tokens is not None,
                )
                if len(samples_by_receipt.get(receipt_id, ())) != expected_count:
                    raise CompanyStateInvariantError(
                        "provider telemetry usage sample cardinality differs",
                    )
        except CompanyStateInvariantError:
            raise
        except (
            BlobStoreError, OSError, CompanyContractError, KeyError,
            TypeError, ValueError,
        ) as exc:
            raise CompanyStateInvariantError(
                "provider telemetry source bytes are invalid",
            ) from exc

    def _verify_needs_user_revision_sources_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Require canonical question/answer documents before append."""
        for event in request.get("events", ()):
            if not isinstance(event, Mapping) or not isinstance(
                event.get("payload"), Mapping,
            ) or event["payload"].get("contract_type") != NEEDS_USER_REVISION_V1:
                continue
            try:
                revision = validate_needs_user_revision(event["payload"])
                entries: tuple[tuple[str, str, str], ...] = (("question_blob", "question", NEEDS_USER_QUESTION_MEDIA_TYPE),)
                if revision["answer_blob"] is not None:
                    entries += (("answer_blob", "answer", NEEDS_USER_ANSWER_MEDIA_TYPE),)
                for field, content_type, media_type in entries:
                    reference = revision[field]
                    if reference["media_type"] != media_type:
                        raise CompanyStateInvariantError("needs-user content media type differs")
                    raw = self.blobs.read(str(reference["sha256"]))
                    document = json.loads(raw.decode("utf-8"))
                    if (
                        canonical_company_json_bytes(document) != raw
                        or document != {
                            "schema_version": 1,
                            "content_type": content_type,
                            "text": document.get("text") if isinstance(document, Mapping) else None,
                        }
                        or not isinstance(document.get("text"), str)
                        or not document["text"]
                    ):
                        raise CompanyStateInvariantError(
                            "needs-user content differs from canonical document",
                        )
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError,
                CompanyContractError, KeyError, TypeError, ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "needs-user content bytes are invalid",
                ) from exc

    def _verify_external_job_effect_sources_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Bind every external-job effect receipt to canonical raw bytes."""

        shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "receipt_id",
            "job_id",
            "mutation_intent_id",
            "command_id",
            "transaction_id",
            "transition_command_id",
            "previous_job_state",
            "observed_job_state",
            "external_handle_sha256",
            "process_fingerprint_sha256",
            "reconciliation_id",
            "resolves_reconciliation_id",
            "observed_at",
            "provenance",
            "observation",
        )
        for event in request.get("events", ()):
            if (
                not isinstance(event, Mapping)
                or not isinstance(event.get("payload"), Mapping)
                or event["payload"].get("contract_type")
                != EXTERNAL_JOB_EFFECT_RECEIPT_V1
            ):
                continue
            try:
                receipt = validate_external_job_effect_receipt(
                    event["payload"],
                )
                raw_bytes = self.blobs.read(
                    str(receipt["raw_artifact"]["sha256"]),
                )
                source = validate_external_job_effect_source(
                    json.loads(raw_bytes.decode("utf-8")),
                )
                if (
                    canonical_company_json_bytes(source) != raw_bytes
                    or any(
                        receipt[field] != source[field]
                        for field in shared_fields
                    )
                ):
                    raise CompanyStateInvariantError(
                        "external job effect source differs from its receipt",
                    )
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                CompanyContractError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "external job effect source bytes are invalid",
                ) from exc

    def _verify_execution_registration_sources_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Bind each registration evidence blob to its exact execution event."""

        events = request.get("events", ())
        registration_events: dict[str, Mapping[str, Any]] = {}
        registration_evidence: dict[str, Mapping[str, Any]] = {}
        registration_nodes: list[Mapping[str, Any]] = []
        for wrapper in events:
            if not isinstance(wrapper, Mapping):
                continue
            payload = wrapper.get("payload")
            if not isinstance(payload, Mapping):
                continue
            contract_type = payload.get("contract_type")
            if (
                contract_type == EXECUTION_EVENT_V1
                and payload.get("event_type") == "execution.registered"
                and isinstance(payload.get("registration_id"), str)
            ):
                registration_events[str(payload["registration_id"])] = payload
            elif (
                contract_type == EVIDENCE_RECORD_V1
                and payload.get("status") == "observed"
                and isinstance(payload.get("claim_id"), str)
            ):
                registration_evidence[str(payload["claim_id"])] = payload
            elif (
                contract_type == EXECUTION_NODE_V1
                and isinstance(payload.get("registration_id"), str)
                and self.readmodel.object(
                    EXECUTION_NODE_V1,
                    str(payload.get("execution_id")),
                )
                is None
            ):
                registration_nodes.append(payload)

        for node in registration_nodes:
            registration_id = str(node["registration_id"])
            event = registration_events.get(registration_id)
            evidence = registration_evidence.get(registration_id)
            if event is None or evidence is None:
                # The pure reducer produces the canonical membership error;
                # fail here too so no raw source is accepted by omission.
                raise CompanyStateInvariantError(
                    "execution registration source relation is incomplete",
                )
            reference = evidence.get("artifact")
            if (
                not isinstance(reference, Mapping)
                or reference.get("availability") != "available"
                or reference.get("media_type")
                != EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE
                or evidence.get("verification_sha256")
                != reference.get("sha256")
            ):
                raise CompanyStateInvariantError(
                    "execution registration source reference is invalid",
                )
            try:
                raw_bytes = self.blobs.read(str(reference["sha256"]))
                source = validate_execution_event(
                    json.loads(raw_bytes.decode("utf-8")),
                )
                if (
                    canonical_company_json_bytes(source) != raw_bytes
                    or source != event
                    or evidence["execution_id"] != node["execution_id"]
                    or evidence["claim_id"] != registration_id
                ):
                    raise CompanyStateInvariantError(
                        "execution registration source differs from its event",
                    )
            except CompanyStateInvariantError:
                raise
            except (
                BlobStoreError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                CompanyContractError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyStateInvariantError(
                    "execution registration source bytes are invalid",
                ) from exc

    def _current_blob_inputs_unlocked(
        self,
    ) -> tuple[
        tuple[Mapping[str, Any], ...],
        tuple[Mapping[str, Any], ...],
        tuple[str, ...],
    ]:
        """Resolve only provider facts reachable from current lifecycle state."""

        references: list[Mapping[str, Any]] = []
        receipts: dict[str, Mapping[str, Any]] = {}
        receipt_ids: set[str] = set()
        reasons: set[str] = set()

        def accept_receipt(payload: Mapping[str, Any]) -> None:
            receipt_id = str(payload["receipt_id"])
            prior = receipts.get(receipt_id)
            if prior is not None and prior != payload:
                reasons.add("provider_lifecycle_binding_ambiguous")
                return
            receipts[receipt_id] = payload

        def receipt_from_record(
            record: LedgerTransactionRecord | None,
        ) -> None:
            if record is None:
                reasons.add("provider_lifecycle_binding_unavailable")
                return
            matched = 0
            for member in record.events:
                payload = member.event["payload"]
                if (
                    payload.get("contract_type")
                    == PROVIDER_LIFECYCLE_RECEIPT_V1
                ):
                    accept_receipt(payload)
                    matched += 1
            for reservation in record.reservations:
                payload = reservation.event["payload"]
                if (
                    payload.get("contract_type")
                    == PROVIDER_LIFECYCLE_RECEIPT_V1
                ):
                    accept_receipt(payload)
                    matched += 1
            if matched != 1:
                reasons.add("provider_lifecycle_binding_unavailable")

        for item in self.readmodel.objects(
            contract_type=DISPATCH_REQUEST_V1,
        ):
            dispatch = item.payload
            state = str(dispatch["state"])
            if state not in {"dispatched", "failed_known"}:
                continue
            references.extend(dispatch["effect_evidence"])
            if state == "failed_known":
                ledger = cast(CompanyLedger, self.__ledger)
                receipt_from_record(
                    CompanyLedger.record_by_command_id(
                        ledger,
                        str(dispatch["command_id"]),
                    ),
                )
                continue
            execution_id = dispatch["execution_id"]
            execution = (
                None
                if execution_id is None
                else self.readmodel.object(
                    EXECUTION_NODE_V1,
                    str(execution_id),
                )
            )
            if execution is None:
                reasons.add("provider_lifecycle_binding_unavailable")
                continue
            receipt_id = execution.payload["receipt_id"]
            if receipt_id is not None:
                receipt_ids.add(str(receipt_id))
            for evidence_id in execution.payload["evidence_ids"]:
                evidence = self.readmodel.object(
                    EVIDENCE_RECORD_V1,
                    str(evidence_id),
                )
                if (
                    evidence is None
                    or evidence.payload["status"] != "observed"
                ):
                    reasons.add("provider_lifecycle_binding_unavailable")
                    continue
                references.append(evidence.payload["artifact"])
                if (
                    evidence.payload["artifact"]["media_type"]
                    != ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE
                ):
                    receipt_ids.add(str(evidence.payload["claim_id"]))

        # Non-dispatch executions (currently Chief carrier episodes, and later
        # formally registered runtimes) still retain provider receipt/evidence
        # reachability.  Filter by actual receipt/evidence links below rather
        # than inventing a DispatchRequest ancestry.
        for item in self.readmodel.objects(
            contract_type=EXECUTION_NODE_V1,
        ):
            root_execution_payload = item.payload
            if root_execution_payload["dispatch_id"] is not None:
                continue
            receipt_id = root_execution_payload["receipt_id"]
            if receipt_id is not None:
                receipt_ids.add(str(receipt_id))
            for evidence_id in root_execution_payload["evidence_ids"]:
                evidence = self.readmodel.object(
                    EVIDENCE_RECORD_V1,
                    str(evidence_id),
                )
                if (
                    evidence is None
                    or evidence.payload["status"] != "observed"
                ):
                    reasons.add("provider_lifecycle_binding_unavailable")
                    continue
                references.append(evidence.payload["artifact"])
                receipt_id = root_execution_payload["receipt_id"]
                registration_id = root_execution_payload["registration_id"]
                if (
                    receipt_id is not None
                    and evidence.payload["claim_id"] == receipt_id
                ):
                    receipt_ids.add(str(receipt_id))
                elif (
                    registration_id is None
                    or evidence.payload["claim_id"] != registration_id
                ):
                    reasons.add("provider_lifecycle_binding_unavailable")

        for shadow in self.readmodel.uncertain_dispatches():
            references.extend(shadow.payload["effect_evidence"])
            ledger = cast(CompanyLedger, self.__ledger)
            receipt_from_record(
                CompanyLedger.record_by_transaction_id(
                    ledger,
                    shadow.source_transaction_id,
                ),
            )

        for receipt_id in sorted(receipt_ids):
            receipt = self.readmodel.object(
                PROVIDER_LIFECYCLE_RECEIPT_V1,
                receipt_id,
            )
            if receipt is None:
                reasons.add("provider_lifecycle_binding_unavailable")
                continue
            accept_receipt(receipt.payload)

        references.extend(
            receipt["raw_artifact"] for receipt in receipts.values()
        )
        unique_references: dict[
            tuple[str, int, str, str],
            Mapping[str, Any],
        ] = {}
        for reference in references:
            key = (
                str(reference["sha256"]),
                int(reference["size_bytes"]),
                str(reference["media_type"]),
                str(reference["availability"]),
            )
            unique_references[key] = reference
        return (
            tuple(unique_references.values()),
            tuple(receipts[key] for key in sorted(receipts)),
            tuple(sorted(reasons)),
        )

    def _refresh_current_blob_health_unlocked(self) -> None:
        """Degrade current coverage without freezing lawful history retention."""

        references, receipts, structural_reasons = (
            self._current_blob_inputs_unlocked()
        )
        reasons = set(structural_reasons)
        for reference in references:
            try:
                metadata = self.blobs.metadata(str(reference["sha256"]))
                if metadata.size_bytes != int(reference["size_bytes"]):
                    reasons.add("provider_lifecycle_evidence_size_mismatch")
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ):
                reasons.add("provider_lifecycle_evidence_unavailable")
        shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "event_kind",
            "dispatch_request_id",
            "provider_dispatch_id",
            "execution_id",
            "carrier_id",
            "organization_node_id",
            "provider",
            "model",
            "effort",
            "session_id",
            "thread_id",
            "reconcile_ref",
            "observed_at",
            "provenance",
            "observation",
        )
        for receipt in receipts:
            try:
                raw_bytes = self.blobs.read(
                    str(receipt["raw_artifact"]["sha256"]),
                )
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ):
                continue
            try:
                source = validate_provider_lifecycle_source(
                    json.loads(raw_bytes.decode("utf-8")),
                )
                if (
                    canonical_company_json_bytes(source) != raw_bytes
                    or any(
                        receipt[field] != source[field]
                        for field in shared_fields
                    )
                ):
                    reasons.add("provider_lifecycle_evidence_invalid")
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                CompanyContractError,
            ):
                reasons.add("provider_lifecycle_evidence_invalid")
        engineering_shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "receipt_id",
            "execution_id",
            "expected_execution_payload_sha256",
            "reporter_execution_id",
            "reporter_carrier_id",
            "provider",
            "session_id",
            "thread_id",
            "from_status",
            "to_status",
            "reason_code",
            "result_packet_id",
            "observed_at",
            "provenance",
            "observation",
        )
        for item in self.readmodel.objects(
            contract_type=ENGINEERING_DISPOSITION_RECEIPT_V1,
        ):
            receipt = item.payload
            try:
                raw_bytes = self.blobs.read(
                    str(receipt["raw_artifact"]["sha256"]),
                )
                source = validate_engineering_disposition_source(
                    json.loads(raw_bytes.decode("utf-8")),
                )
                if (
                    len(raw_bytes)
                    != int(receipt["raw_artifact"]["size_bytes"])
                    or canonical_company_json_bytes(source) != raw_bytes
                    or any(
                        receipt[field] != source[field]
                        for field in engineering_shared_fields
                    )
                ):
                    reasons.add(
                        "engineering_disposition_source_invalid",
                    )
            except (
                BlobStoreError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                CompanyContractError,
                KeyError,
                TypeError,
                ValueError,
            ):
                reasons.add(
                    "engineering_disposition_source_unavailable",
                )
        external_job_shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "receipt_id",
            "job_id",
            "mutation_intent_id",
            "command_id",
            "transaction_id",
            "transition_command_id",
            "previous_job_state",
            "observed_job_state",
            "external_handle_sha256",
            "process_fingerprint_sha256",
            "reconciliation_id",
            "resolves_reconciliation_id",
            "observed_at",
            "provenance",
            "observation",
        )
        for item in self.readmodel.objects(
            contract_type=EXTERNAL_JOB_EFFECT_RECEIPT_V1,
        ):
            receipt = item.payload
            try:
                metadata = self.blobs.metadata(
                    str(receipt["raw_artifact"]["sha256"]),
                )
                if metadata.size_bytes != int(
                    receipt["raw_artifact"]["size_bytes"],
                ):
                    reasons.add(
                        "external_job_effect_source_size_mismatch",
                    )
                    continue
                raw_bytes = self.blobs.read(
                    str(receipt["raw_artifact"]["sha256"]),
                )
                source = validate_external_job_effect_source(
                    json.loads(raw_bytes.decode("utf-8")),
                )
                if (
                    canonical_company_json_bytes(source) != raw_bytes
                    or any(
                        receipt[field] != source[field]
                        for field in external_job_shared_fields
                    )
                ):
                    reasons.add("external_job_effect_source_invalid")
            except (
                BlobStoreError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                CompanyContractError,
                KeyError,
                TypeError,
                ValueError,
            ):
                reasons.add("external_job_effect_source_unavailable")
        telemetry_by_id = {
            str(item.payload["receipt_id"]): item.payload
            for item in self.readmodel.objects(
                contract_type=PROVIDER_TELEMETRY_RECEIPT_V1,
            )
        }
        for receipt in telemetry_by_id.values():
            try:
                self._normalize_provider_telemetry_receipt_unlocked(receipt)
            except FileNotFoundError:
                reasons.add("provider_telemetry_raw_unavailable")
            except (BlobStoreError, OSError, CompanyContractError, KeyError, TypeError, ValueError):
                reasons.add("provider_telemetry_raw_invalid")
            except CompanyStateInvariantError:
                reasons.add("provider_telemetry_raw_invalid")
        for item in self.readmodel.objects(contract_type=USAGE_COUNTER_SAMPLE_V1):
            sample = item.payload
            usage_receipt: Mapping[str, Any] | None = telemetry_by_id.get(
                str(sample["telemetry_receipt_id"]),
            )
            if usage_receipt is None:
                reasons.add("usage_counter_raw_invalid")
                continue
            try:
                normalized = self._normalize_provider_telemetry_receipt_unlocked(usage_receipt)
                raw_sample = normalized.raw_cumulative_tokens
                if raw_sample is None or (
                    sample["total_token_vector"] != self._raw_token_vector_payload(raw_sample.total)
                    or sample["last_token_vector"] != self._raw_token_vector_payload(raw_sample.last)
                    or sample["model_context_window"] != {
                        "present": raw_sample.model_context_window is not None,
                        "value": raw_sample.model_context_window,
                    }
                ):
                    reasons.add("usage_counter_raw_invalid")
            except FileNotFoundError:
                reasons.add("usage_counter_raw_unavailable")
            except (BlobStoreError, OSError, CompanyContractError, KeyError, TypeError, ValueError, CompanyStateInvariantError):
                reasons.add("usage_counter_raw_invalid")
        for item in self.readmodel.objects(contract_type=NEEDS_USER_REVISION_V1):
            revision = item.payload
            entries: tuple[tuple[str, str, str], ...] = (("question_blob", "question", "needs_user_question"),)
            if revision["answer_blob"] is not None:
                entries += (("answer_blob", "answer", "needs_user_answer"),)
            for field, content_type, reason_prefix in entries:
                try:
                    raw = self.blobs.read(str(revision[field]["sha256"]))
                    document = json.loads(raw.decode("utf-8"))
                    if (
                        canonical_company_json_bytes(document) != raw
                        or document != {
                            "schema_version": 1,
                            "content_type": content_type,
                            "text": document.get("text") if isinstance(document, Mapping) else None,
                        }
                        or not isinstance(document.get("text"), str)
                        or not document["text"]
                    ):
                        reasons.add(f"{reason_prefix}_invalid")
                except FileNotFoundError:
                    reasons.add(f"{reason_prefix}_unavailable")
                except (BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                    reasons.add(f"{reason_prefix}_invalid")
        self._degradation_reasons = tuple(sorted(reasons))
        self._blob_status = "ready" if not reasons else "degraded"

    def _preflight_invariants_unlocked(
        self,
        request: Mapping[str, Any],
        *,
        receipt_state: str,
    ) -> None:
        """Reject unsafe company lifecycle effects before the ledger mutation.

        The ledger remains the exact-byte/idempotency authority.  This bounded
        preflight reads the projection while the sole state-owner mutex is
        held.  Dispatch queue rules and Chief authority/fencing therefore use
        the same pure reducer as replay, and a rejected admission cannot
        advance either ledger head.
        """

        has_dispatch_claim = any(
            isinstance(event, Mapping)
            and isinstance(event.get("payload"), Mapping)
            and event["payload"].get("contract_type")
            == DISPATCH_REQUEST_V1
            for event in request.get("events", ())
        )
        try:
            canonical = validate_company_transaction_request(request)
        except CompanyContractError as exc:
            if has_dispatch_claim:
                raise CompanyStateInvariantError(
                    f"DispatchRequest transaction is invalid: {exc}",
                ) from exc
            # The ledger retains ownership of non-dispatch request diagnostics.
            return

        # A durable transaction is immutable as a whole.  Once any later
        # lifecycle revision becomes current, replaying an older byte-exact
        # request must still reach the ledger's idempotency path rather than be
        # reinterpreted against the newer projection.
        ledger = cast(CompanyLedger, self.__ledger)
        durable = CompanyLedger.record_by_transaction_id(
            ledger,
            str(canonical["transaction_id"]),
        )
        if durable is not None and (
            canonical_company_json_bytes(_plain(durable.request))
            == canonical_company_json_bytes(canonical)
            and str(durable.receipt["state"]) == receipt_state
        ):
            return

        dispatch_events = tuple(
            event
            for event in canonical["events"]
            if event["payload"]["contract_type"] == DISPATCH_REQUEST_V1
        )
        self._preflight_department_snapshot_unlocked(canonical)

        seen_revision_ids: set[str] = set()
        for event in dispatch_events:
            payload = event["payload"]
            revision_id = str(payload["dispatch_revision_id"])
            if revision_id in seen_revision_ids:
                raise CompanyStateInvariantError(
                    "DispatchRequest revision is duplicated in one transaction",
                )
            seen_revision_ids.add(revision_id)
            existing = self.readmodel.dispatch_revision(revision_id)
            if existing is None:
                continue
            exact_replay = (
                existing.dispatch_request_id
                == str(payload["dispatch_request_id"])
                and existing.event_id == str(event["event_id"])
                and existing.transaction_id == str(canonical["transaction_id"])
                and existing.command_id == str(canonical["command_id"])
                and existing.payload_sha256 == str(event["payload_sha256"])
                and existing.receipt_state == receipt_state
            )
            if not exact_replay:
                raise CompanyStateInvariantError(
                    "DispatchRequest revision ID has a divergent durable binding",
                )

        try:
            reduce_company_invariants(
                _current_invariant_objects(self.readmodel.objects()),
                self.readmodel.uncertain_dispatches(),
                InvariantTransition(canonical, receipt_state),
            )
        except CompanyInvariantError as exc:
            raise CompanyStateInvariantError(
                f"company invariant admission failed: {exc}",
            ) from exc

    def _preflight_department_snapshot_unlocked(
        self,
        request: Mapping[str, Any],
    ) -> None:
        """Verify a lifecycle snapshot blob before any authoritative append."""

        lifecycle_intents = [
            event["payload"]
            for event in request["events"]
            if (
                event["payload"]["contract_type"] == CONTROL_INTENT_V1
                and event["payload"]["request_payload"].get("request_type")
                == "department_lifecycle_request_v1"
            )
        ]
        if not lifecycle_intents:
            return
        if len(lifecycle_intents) != 1:
            raise CompanyStateInvariantError(
                "department lifecycle transaction requires one ControlIntent",
            )
        intent = lifecycle_intents[0]
        lifecycle_request = intent["request_payload"]
        if lifecycle_request["operation"] != "park":
            return
        reference = lifecycle_request["snapshot_document"]
        if (
            not isinstance(reference, Mapping)
            or reference.get("availability") != "available"
        ):
            raise CompanyStateInvariantError(
                "department park snapshot document is unavailable",
            )
        try:
            document = self._read_snapshot_document_unlocked(reference)
            self._verify_snapshot_member_refs_unlocked(document)
        except CompanyStateError as exc:
            raise CompanyStateInvariantError(
                "department snapshot blob cannot be verified",
            ) from exc

        current_snapshots = [
            item.payload
            for item in self.readmodel.objects(
                contract_type=DEPARTMENT_SNAPSHOT_V1,
            )
            if (
                item.payload["department_id"]
                == lifecycle_request["department_id"]
            )
        ]
        if len(current_snapshots) != 1:
            raise CompanyStateInvariantError(
                "department snapshot predecessor is missing",
            )
        current_snapshot = current_snapshots[0]
        current_refs = current_snapshot["artifact_refs"]
        if (
            len(current_refs) != 1
            or document["previous_snapshot_id"]
            != current_snapshot["snapshot_id"]
            or document["previous_document_sha256"]
            != current_refs[0]["sha256"]
        ):
            raise CompanyStateInvariantError(
                "department snapshot predecessor digest differs",
            )

        snapshots = [
            event["payload"]
            for event in request["events"]
            if (
                event["payload"]["contract_type"] == DEPARTMENT_SNAPSHOT_V1
                and event["payload"]["department_id"]
                == lifecycle_request["department_id"]
            )
        ]
        if len(snapshots) != 1:
            raise CompanyStateInvariantError(
                "department park requires one snapshot record",
            )
        snapshot = snapshots[0]
        named_digests = {
            "charter_sha256": "charter_ref",
            "constraints_sha256": "constraints_ref",
            "decisions_sha256": "decisions_ref",
            "open_questions_sha256": "open_questions_ref",
            "handoff_sha256": "handoff_ref",
        }
        if (
            document["company_id"] != request["company_id"]
            or document["company_incarnation"]
            != request["company_incarnation"]
            or document["lock_domain_generation"]
            != request["lock_domain_generation"]
            or document["department_id"]
            != lifecycle_request["department_id"]
            or document["lead_node_id"] != lifecycle_request["lead_node_id"]
            or document["snapshot_id"] != snapshot["snapshot_id"]
            or document["revision"] != snapshot["revision"]
            or document["previous_snapshot_id"]
            != snapshot["previous_snapshot_id"]
            or document["company_cursor"] != snapshot["company_cursor"]
            or document["captured_at"] != snapshot["captured_at"]
            or document["capture_reason"] != "park"
            or any(
                snapshot[digest_name]
                != document[reference_name]["sha256"]
                for digest_name, reference_name in named_digests.items()
            )
            or snapshot["artifact_refs"] != [dict(reference)]
        ):
            raise CompanyStateInvariantError(
                "department snapshot record differs from its document",
            )

    def commit(
        self,
        request: Mapping[str, Any],
        *,
        state: str = "committed",
        evidence: Sequence[Mapping[str, Any]] = (),
        recorded_at: str | None = None,
        crash_at: str | None = None,
    ) -> LedgerAppendResult:
        """Append once, project the exact record, and publish no false success."""

        with self._mutex:
            self._require_open()
            self._verify_new_available_blob_refs_unlocked(
                request,
                evidence,
            )
            self._verify_provider_worker_artifacts_unlocked(request)
            self._verify_provider_lifecycle_sources_unlocked(request)
            self._verify_runtime_observation_sources_unlocked(request)
            self._verify_provider_telemetry_sources_unlocked(request)
            self._verify_needs_user_revision_sources_unlocked(request)
            self._verify_external_job_effect_sources_unlocked(request)
            self._verify_execution_registration_sources_unlocked(request)
            self._verify_work_definition_request_unlocked(request)
            self._preflight_invariants_unlocked(
                request,
                receipt_state=state,
            )
            try:
                ledger = cast(CompanyLedger, self.__ledger)
                result = CompanyLedger.append(
                    ledger,
                    request,
                    state=state,
                    evidence=evidence,
                    recorded_at=recorded_at,
                    crash_at=crash_at,
                )
            except LedgerCommitEffectUnknownError:
                self._projection_status = "quarantined"
                raise
            try:
                self.readmodel.apply(result.record)
                self._validate_binding_unlocked()
            except (ReadModelError, CompanyStateError):
                self._projection_status = "degraded"
                try:
                    self._rebuild_projection_unlocked()
                    self._validate_binding_unlocked()
                except BaseException as exc:
                    raise CompanyProjectionDegradedError(result) from exc
            self._refresh_current_blob_health_unlocked()
            self._reconcile_delivery_currentness_unlocked()
            return result

    @staticmethod
    def _verified_at() -> str:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace(
            "+00:00",
            "Z",
        )

    def _checkpoint_currentness_unlocked(
        self,
        delivery: CompanyCheckpointDelivery,
    ) -> tuple[bool, str | None]:
        if delivery.state != "verified":
            return False, delivery.reason
        if delivery.reason in {
            "company_binding_differs",
            "discovery_incomplete",
        }:
            return False, delivery.reason
        if delivery.cursor is None or delivery.head_sha256 is None:
            return False, "company_binding_differs"
        ledger = cast(CompanyLedger, self.__ledger)
        head = CompanyLedger.snapshot_heads(ledger).global_head
        if (
            delivery.cursor != head.global_sequence
            or delivery.head_sha256 != head.transaction_sha256
        ):
            return False, "ledger_cursor_or_head_drift"
        return True, None

    def _reconcile_delivery_currentness_unlocked(self) -> None:
        checkpoint = self._delivery_snapshot.checkpoint
        checkpoint_current, checkpoint_reason = self._checkpoint_currentness_unlocked(
            checkpoint,
        )
        checkpoint = replace(
            checkpoint,
            current=checkpoint_current,
            reason=checkpoint_reason,
        )
        sanitized_export = self._delivery_snapshot.sanitized_export
        if sanitized_export.state == "unavailable":
            export_current = False
            export_reason = sanitized_export.reason
            export_state = "unavailable"
        elif sanitized_export.reason in {
            "company_binding_differs",
            "discovery_incomplete",
        }:
            export_current = False
            export_reason = sanitized_export.reason
            export_state = "stale"
        elif (
            not checkpoint_current
            or sanitized_export.source_checkpoint_manifest_sha256
            != checkpoint.manifest_sha256
            or sanitized_export.source_checkpoint_id != checkpoint.checkpoint_id
        ):
            export_current = False
            export_reason = "checkpoint_digest_drift"
        elif (
            sanitized_export.cursor != checkpoint.cursor
            or sanitized_export.head_sha256 != checkpoint.head_sha256
        ):
            export_current = False
            export_reason = "ledger_cursor_or_head_drift"
        else:
            export_current = True
            export_reason = None
            export_state = "available"
        if not export_current and sanitized_export.state != "unavailable":
            export_state = "stale"
        self._delivery_snapshot = CompanyDeliverySnapshot(
            checkpoint=checkpoint,
            sanitized_export=replace(
                sanitized_export,
                state=export_state,
                current=export_current,
                reason=export_reason,
            ),
            warnings=self._delivery_snapshot.warnings,
        )

    def _checkpoint_delivery_from_verified_unlocked(
        self,
        checkpoint_id: str,
        verified: Any,
        *,
        verified_at: str,
    ) -> CompanyCheckpointDelivery:
        manifest = verified.manifest
        company = manifest["company"]
        ledger = manifest["ledger"]
        binding_matches = (
            company["company_id"] == self.resolved.pointer.company_id
            and company["company_incarnation"]
            == self.resolved.pointer.company_incarnation
            and company["lock_domain_generation"]
            == self.resolved.pointer.lock_domain_generation
            and company["manifest_sha256"]
            == self.resolved.pointer.manifest_sha256
        )
        delivery = CompanyCheckpointDelivery(
            state="verified",
            reason=None if binding_matches else "company_binding_differs",
            checkpoint_id=checkpoint_id,
            cursor=int(ledger["global_sequence"]),
            head_sha256=str(ledger["transaction_sha256"]),
            manifest_sha256=str(verified.sha256),
            generated_at=str(manifest["generated_at"]),
            verified_at=verified_at,
            current=False,
        )
        current, reason = self._checkpoint_currentness_unlocked(delivery)
        return replace(delivery, current=current, reason=reason)

    def _sanitized_export_delivery_from_verified_unlocked(
        self,
        export_id: str,
        verified: Any,
        *,
        verified_at: str,
    ) -> CompanySanitizedExportDelivery:
        bundle = verified.bundle
        company = bundle["company"]
        ledger = bundle["ledger"]
        checkpoint = bundle["checkpoint"]
        from .sanitized_export import MAX_SANITIZED_EXPORT_BYTES

        try:
            raw = verified.path.read_bytes()
        except OSError as exc:
            raise CompanyStateError("verified sanitized export is unavailable") from exc
        if len(raw) > MAX_SANITIZED_EXPORT_BYTES:
            raise CompanyStateError("verified sanitized export exceeds byte bound")
        if raw != canonical_company_json_bytes(
            bundle,
            max_bytes=MAX_SANITIZED_EXPORT_BYTES,
        ):
            raise CompanyStateError("verified sanitized export is not canonical")
        if hashlib.sha256(raw).hexdigest() != verified.sha256:
            raise CompanyStateError("verified sanitized export digest differs")
        binding_matches = (
            company["company_id"] == self.resolved.pointer.company_id
            and company["company_incarnation"]
            == self.resolved.pointer.company_incarnation
            and company["lock_domain_generation"]
            == self.resolved.pointer.lock_domain_generation
            and company["manifest_sha256"]
            == self.resolved.pointer.manifest_sha256
        )
        return CompanySanitizedExportDelivery(
            state="available",
            reason=None if binding_matches else "company_binding_differs",
            export_id=export_id,
            export_sha256=str(verified.sha256),
            generated_at=str(bundle["generated_at"]),
            verified_at=verified_at,
            source_checkpoint_id=str(checkpoint["checkpoint_id"]),
            source_checkpoint_manifest_sha256=str(
                checkpoint["manifest_sha256"],
            ),
            cursor=int(ledger["cursor"]),
            head_sha256=str(ledger["head_sha256"]),
            current=False,
            canonical_bundle_json=raw,
        )

    def _delivery_candidates_unlocked(
        self,
        root: Path,
        *,
        stage_prefix: str,
        require_json: bool,
        label: str,
    ) -> tuple[tuple[Path, ...], tuple[str, ...], bool]:
        candidates: list[tuple[int, str, Path]] = []
        warnings: list[str] = []
        incomplete = False
        try:
            iterator = root.iterdir()
            for index, path in enumerate(iterator):
                if index >= 256:
                    warnings.append(f"{label}_discovery_truncated")
                    incomplete = True
                    break
                if path.name.startswith(stage_prefix):
                    continue
                if require_json and path.suffix != ".json":
                    continue
                try:
                    metadata = path.lstat()
                except OSError:
                    warnings.append(f"{label}_candidate_unreadable")
                    continue
                candidates.append((metadata.st_mtime_ns, path.name, path))
        except OSError:
            warnings.append(f"{label}_discovery_unavailable")
        candidates.sort(key=lambda item: (-item[0], item[1]))
        if len(candidates) > 8:
            warnings.append(f"{label}_verification_budget_exhausted")
            incomplete = True
        return tuple(item[2] for item in candidates[:8]), tuple(warnings), incomplete

    def _discover_delivery_unlocked(self) -> None:
        """Bound startup discovery; malformed artifacts degrade delivery only."""

        from .checkpoint import CompanyCheckpointError, verify_plain_checkpoint
        from .sanitized_export import (
            CompanySanitizedExportError,
            verify_sanitized_export,
        )

        warnings: list[str] = []
        checkpoints, checkpoint_warnings, checkpoint_incomplete = self._delivery_candidates_unlocked(
            self.resolved.incarnation.checkpoints,
            stage_prefix=".c-",
            require_json=False,
            label="checkpoint",
        )
        warnings.extend(checkpoint_warnings)
        verified_checkpoints: list[CompanyCheckpointDelivery] = []
        for path in checkpoints:
            try:
                verified_checkpoint = verify_plain_checkpoint(path)
                delivery_checkpoint = self._checkpoint_delivery_from_verified_unlocked(
                    path.name,
                    verified_checkpoint,
                    verified_at=self._verified_at(),
                )
            except (CompanyCheckpointError, OSError, ValueError, KeyError):
                warnings.append("checkpoint_corrupt")
                continue
            verified_checkpoints.append(delivery_checkpoint)
        checkpoint_delivery = (
            max(
                verified_checkpoints,
                key=lambda item: (
                    -1 if item.cursor is None else item.cursor,
                    "" if item.generated_at is None else item.generated_at,
                    "" if item.checkpoint_id is None else item.checkpoint_id,
                ),
            )
            if verified_checkpoints
            else _unavailable_checkpoint("no_verified_checkpoint")
        )

        exports, export_warnings, export_incomplete = (
            self._delivery_candidates_unlocked(
                self.resolved.incarnation.exports,
                stage_prefix=".s-",
                require_json=True,
                label="sanitized_export",
            )
        )
        if checkpoint_delivery.state == "verified" and checkpoint_incomplete:
            checkpoint_delivery = replace(
                checkpoint_delivery,
                current=False,
                reason="discovery_incomplete",
            )

        warnings.extend(export_warnings)
        verified_exports: list[CompanySanitizedExportDelivery] = []
        for path in exports:
            try:
                verified_export = verify_sanitized_export(path)
                delivery_export = self._sanitized_export_delivery_from_verified_unlocked(
                    path.stem,
                    verified_export,
                    verified_at=self._verified_at(),
                )
            except (
                CompanyCheckpointError,
                CompanySanitizedExportError,
                OSError,
                ValueError,
                KeyError,
            ):
                warnings.append("sanitized_export_corrupt")
                continue
            verified_exports.append(delivery_export)
        export_delivery = (
            max(
                verified_exports,
                key=lambda item: (
                    -1 if item.cursor is None else item.cursor,
                    "" if item.generated_at is None else item.generated_at,
                    "" if item.export_id is None else item.export_id,
                ),
            )
            if verified_exports
            else _unavailable_sanitized_export("no_verified_sanitized_export")
        )
        if export_delivery.state == "available" and export_incomplete:
            export_delivery = replace(
                export_delivery,
                state="stale",
                current=False,
                reason="discovery_incomplete",
            )
        self._delivery_snapshot = CompanyDeliverySnapshot(
            checkpoint=checkpoint_delivery,
            sanitized_export=export_delivery,
            warnings=tuple(warnings),
        )
        self._reconcile_delivery_currentness_unlocked()

    def delivery_snapshot(self) -> CompanyDeliverySnapshot:
        """Return the immutable, post-verified delivery projection."""

        with self._mutex:
            self._require_open()
            self._reconcile_delivery_currentness_unlocked()
            return self._delivery_snapshot

    def create_plain_checkpoint_delivery(
        self,
        checkpoint_id: str,
        generated_at: str,
    ) -> CompanyDeliverySnapshot:
        """Publish then fully verify one checkpoint under the owner mutex."""

        from .checkpoint import verify_plain_checkpoint, write_plain_checkpoint

        with self._mutex:
            self._require_open()
            digest = write_plain_checkpoint(
                lock=self.lock,
                resolved=self.resolved,
                ledger=cast(CompanyLedger, self.__ledger),
                blobs=self.blobs,
                checkpoint_id=checkpoint_id,
                generated_at=generated_at,
            )
            path = self.resolved.incarnation.checkpoints / checkpoint_id
            verified = verify_plain_checkpoint(path)
            if verified.sha256 != digest:
                raise CompanyStateError("published checkpoint digest differs")
            previous = self._delivery_snapshot.checkpoint
            checkpoint = self._checkpoint_delivery_from_verified_unlocked(
                checkpoint_id,
                verified,
                verified_at=(
                    previous.verified_at
                    if (
                        previous.checkpoint_id == checkpoint_id
                        and previous.manifest_sha256 == verified.sha256
                        and previous.verified_at is not None
                    )
                    else self._verified_at()
                ),
            )
            self._delivery_snapshot = CompanyDeliverySnapshot(
                checkpoint=checkpoint,
                sanitized_export=self._delivery_snapshot.sanitized_export,
                warnings=self._delivery_snapshot.warnings,
            )
            self._reconcile_delivery_currentness_unlocked()
            return self._delivery_snapshot

    def create_sanitized_export_delivery(
        self,
        checkpoint_id: str,
        export_id: str,
        generated_at: str,
    ) -> CompanyDeliverySnapshot:
        """Publish then fully verify one sanitized export under the owner mutex."""

        from .checkpoint import verify_plain_checkpoint
        from .sanitized_export import verify_sanitized_export, write_sanitized_export

        with self._mutex:
            self._require_open()
            checkpoint_path = self.resolved.incarnation.checkpoints / checkpoint_id
            digest = write_sanitized_export(
                lock=self.lock,
                resolved=self.resolved,
                checkpoint_path=checkpoint_path,
                export_id=export_id,
                generated_at=generated_at,
            )
            verified_checkpoint = verify_plain_checkpoint(checkpoint_path)
            verified = verify_sanitized_export(
                self.resolved.incarnation.exports / f"{export_id}.json",
                checkpoint_path=checkpoint_path,
            )
            if verified.sha256 != digest:
                raise CompanyStateError("published sanitized export digest differs")
            previous_checkpoint = self._delivery_snapshot.checkpoint
            previous_export = self._delivery_snapshot.sanitized_export
            checkpoint = self._checkpoint_delivery_from_verified_unlocked(
                checkpoint_id,
                verified_checkpoint,
                verified_at=(
                    previous_checkpoint.verified_at
                    if (
                        previous_checkpoint.checkpoint_id == checkpoint_id
                        and previous_checkpoint.manifest_sha256
                        == verified_checkpoint.sha256
                        and previous_checkpoint.verified_at is not None
                    )
                    else self._verified_at()
                ),
            )
            sanitized_export = self._sanitized_export_delivery_from_verified_unlocked(
                export_id,
                verified,
                verified_at=(
                    previous_export.verified_at
                    if (
                        previous_export.export_id == export_id
                        and previous_export.export_sha256 == verified.sha256
                        and previous_export.verified_at is not None
                    )
                    else self._verified_at()
                ),
            )
            self._delivery_snapshot = CompanyDeliverySnapshot(
                checkpoint=checkpoint,
                sanitized_export=sanitized_export,
                warnings=self._delivery_snapshot.warnings,
            )
            self._reconcile_delivery_currentness_unlocked()
            return self._delivery_snapshot

    def create_checkpoint_export_delivery(
        self,
        checkpoint_id: str,
        export_id: str,
        generated_at: str,
    ) -> CompanyDeliverySnapshot:
        """Create the checkpoint first and retain that fact if export fails."""

        self.create_plain_checkpoint_delivery(checkpoint_id, generated_at)
        try:
            return self.create_sanitized_export_delivery(
                checkpoint_id,
                export_id,
                generated_at,
            )
        except Exception as exc:
            with self._mutex:
                self._require_open()
                self._delivery_snapshot = CompanyDeliverySnapshot(
                    checkpoint=self._delivery_snapshot.checkpoint,
                    sanitized_export=_unavailable_sanitized_export(
                        "sanitized_export_creation_failed",
                    ),
                    warnings=(
                        *self._delivery_snapshot.warnings,
                        "sanitized_export_creation_failed",
                    ),
                )
                self._reconcile_delivery_currentness_unlocked()
                raise CompanyDeliveryPartialError(
                    self._delivery_snapshot,
                ) from exc

    def heads(self) -> LedgerHeadsSnapshot:
        with self._mutex:
            self._require_open()
            ledger = cast(CompanyLedger, self.__ledger)
            return CompanyLedger.snapshot_heads(ledger)

    def objects(
        self,
        *,
        contract_type: str | None = None,
    ) -> tuple[ProjectedObject, ...]:
        with self._mutex:
            self._require_open()
            return self.readmodel.objects(contract_type=contract_type)

    def records_after(
        self,
        global_sequence: int,
        *,
        limit: int = 1024,
    ) -> tuple[LedgerTransactionRecord, ...]:
        with self._mutex:
            self._require_open()
            ledger = cast(CompanyLedger, self.__ledger)
            return CompanyLedger.records_after(
                ledger,
                global_sequence,
                limit=limit,
            )

    def record_by_transaction_id(
        self,
        transaction_id: str,
    ) -> LedgerTransactionRecord | None:
        with self._mutex:
            self._require_open()
            ledger = cast(CompanyLedger, self.__ledger)
            return CompanyLedger.record_by_transaction_id(ledger, transaction_id)

    def record_by_command_id(
        self,
        command_id: str,
    ) -> LedgerTransactionRecord | None:
        with self._mutex:
            self._require_open()
            ledger = cast(CompanyLedger, self.__ledger)
            return CompanyLedger.record_by_command_id(ledger, command_id)

    def health(self) -> CompanyStateHealth:
        with self._mutex:
            self._require_open()
            return self._health_unlocked()

    def _health_unlocked(self) -> CompanyStateHealth:
        self._refresh_current_blob_health_unlocked()
        ledger = cast(CompanyLedger, self.__ledger)
        ledger_heads = CompanyLedger.snapshot_heads(ledger)
        readmodel_head = self.readmodel.head()
        projection_matches = (
            ledger_heads.global_head.global_sequence
            == readmodel_head.global_sequence
            and ledger_heads.global_head.transaction_sha256
            == readmodel_head.transaction_sha256
        )
        status = (
            "ready"
            if (
                ledger.health == "ready"
                and self._projection_status == "ready"
                and self._blob_status == "ready"
                and projection_matches
            )
            else "degraded"
        )
        reasons = self._degradation_reasons
        if not projection_matches:
            reasons = (*reasons, "ledger_projection_head_mismatch")
        return CompanyStateHealth(
            status=status,
            ledger_status=ledger.health,
            projection_status=self._projection_status,
            pointer_sha256=self.resolved.pointer.pointer_sha256,
            ledger_heads=ledger_heads,
            readmodel_head=readmodel_head,
            blob_status=self._blob_status,
            degradation_reasons=reasons,
        )

    def query_snapshot(self) -> CompanyQuerySnapshot:
        """Return health/cursor and current objects from one owner-locked view."""

        with self._mutex:
            self._require_open()
            health = self._health_unlocked()
            objects = self.readmodel.objects()
            uncertain_dispatches = self.readmodel.uncertain_dispatches()
            return CompanyQuerySnapshot(
                health=health,
                objects=objects,
                uncertain_dispatches=uncertain_dispatches,
                delivery=self._delivery_snapshot,
            )

    def query_snapshot_at(self, global_sequence: int) -> CompanyQuerySnapshot:
        """Rebuild one exact historical prefix without touching active state.

        The current read model is intentionally never rewound: a historical
        Dashboard request gets a fresh, short-lived projection derived from a
        fully chain-verified ledger snapshot.  Cursor zero is not a company
        projection because no committed ``CompanyManifest`` exists yet.
        """

        return self.project_historical_replay(
            self.historical_replay_input(),
            global_sequence,
        )

    def historical_replay_input(self) -> CompanyHistoricalReplayInput:
        """Freeze verified ledger facts for a detached Dashboard replay.

        This must run on the Supervisor/state-owner thread.  Consumers may
        subsequently create temporary projections without touching the live
        ledger or read model.
        """
        with self._mutex:
            self._require_open()
            ledger = cast(CompanyLedger, self.__ledger)
            records = CompanyLedger.load_records(ledger)
            try:
                heads = validate_historical_ledger_snapshot(
                    records,
                    immutable_ledger_heads(
                        CompanyLedger.snapshot_heads(ledger),
                    ),
                )
                replay = immutable_historical_replay_input(
                    CompanyHistoricalReplayInput(
                        records=records,
                        heads=heads,
                        state_root=self.resolved.incarnation.root.resolve(),
                        pointer_sha256=self.resolved.pointer.pointer_sha256,
                        ledger_status=ledger.health,
                        projection_status=self._projection_status,
                        blob_status=self._blob_status,
                        degradation_reasons=self._degradation_reasons,
                    )
                )
                return replay
            except CompanyStateReaderError as exc:
                raise CompanyStateError(
                    "company ledger replay snapshot cannot be verified",
                ) from exc

    @staticmethod
    def project_historical_replay(
        replay: CompanyHistoricalReplayInput,
        global_sequence: int,
    ) -> CompanyQuerySnapshot:
        """Build one projection using only frozen verified replay input."""

        try:
            replay = immutable_historical_replay_input(replay)
            replay_heads = replay.heads
        except CompanyStateReaderError as exc:
            raise CompanyStateError(
                "historical replay input cannot be verified",
            ) from exc

        if (
            not isinstance(global_sequence, int)
            or isinstance(global_sequence, bool)
            or global_sequence < 0
        ):
            raise ValueError("historical cursor must be a non-negative integer")
        if global_sequence == 0:
            raise ValueError(
                "historical cursor 0 predates the first committed company manifest",
            )
        records = replay.records
        if global_sequence > replay_heads.global_head[0]:
            raise ValueError("historical cursor is ahead of the ledger head")
        prefix = records[:global_sequence]
        if (
            len(prefix) != global_sequence
            or prefix[-1].global_sequence != global_sequence
        ):
            raise CompanyStateError(
                "verified ledger prefix does not contain the requested cursor",
            )

        temporary_root = Path(tempfile.mkdtemp(prefix="aoi-company-history-"))
        model: CompanyReadModel | None = None
        try:
            temporary_resolved = temporary_root.resolve()
            if temporary_resolved.is_relative_to(replay.state_root):
                raise CompanyStateError(
                    "historical projection temporary root overlaps company state",
                )
            temporary_model = temporary_root / "readmodel.sqlite3"
            CompanyReadModel.rebuild(temporary_model, prefix)
            model = CompanyReadModel(temporary_model)
            readmodel_head = model.verify_integrity()
            if (
                readmodel_head.global_sequence != global_sequence
                or readmodel_head.transaction_sha256
                != prefix[-1].receipt["transaction_sha256"]
            ):
                raise CompanyStateError(
                    "historical read model head differs from ledger prefix",
                )
            stream_heads: dict[str, tuple[int, str]] = {}
            for record in prefix:
                for event in record.events:
                    stream_heads[str(event.event["stream"])] = (
                        event.stream_sequence,
                        event.event_sha256,
                    )
            identity = (
                str(prefix[0].request["company_id"]),
                int(prefix[0].request["company_incarnation"]),
                int(prefix[0].request["lock_domain_generation"]),
            )
            historical_heads = LedgerHeadsSnapshot(
                identity=identity,
                global_head=LedgerHead(
                    global_sequence,
                    str(prefix[-1].receipt["transaction_sha256"]),
                ),
                stream_heads=stream_heads,
            )
            health = CompanyStateHealth(
                status=(
                    "ready"
                    if replay.ledger_status == "ready"
                    and replay.projection_status == "ready"
                    else "degraded"
                ),
                ledger_status=replay.ledger_status,
                projection_status="historical_prefix_replay",
                pointer_sha256=replay.pointer_sha256,
                ledger_heads=historical_heads,
                readmodel_head=readmodel_head,
                blob_status=replay.blob_status,
                degradation_reasons=replay.degradation_reasons,
            )
            return CompanyQuerySnapshot(
                health=health,
                objects=model.objects(),
                uncertain_dispatches=model.uncertain_dispatches(),
                # Delivery records are current operational state, not facts at
                # an arbitrary ledger cursor.  Do not splice them into history.
                delivery=_DEFAULT_DELIVERY_SNAPSHOT,
            )
        finally:
            if model is not None:
                model.close()
            shutil.rmtree(temporary_root, ignore_errors=False)

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            error: BaseException | None = None
            try:
                if self._readmodel is not None:
                    self._readmodel.close()
                    self._readmodel = None
                if self.__ledger is not None:
                    CompanyLedger.close(self.__ledger)
                    self.__ledger = None
                self._blobs = None
            except BaseException as exc:
                error = exc
            finally:
                self._closed = True
                try:
                    self.lock.close()
                except BaseException as exc:
                    if error is None:
                        error = exc
                finally:
                    _release_local_slot(self._local_slot_key)
            if error is not None:
                raise error

    def __enter__(self) -> CompanyStateOwner:
        self._require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


__all__ = [
    "CompanyCheckpointDelivery",
    "CompanyDeliveryPartialError",
    "CompanyDeliverySnapshot",
    "CompanyHistoricalReplayInput",
    "CompanyQuerySnapshot",
    "CompanyProjectionDegradedError",
    "CompanyStateClosedError",
    "CompanyStateError",
    "CompanyStateHealth",
    "CompanyStateInvariantError",
    "CompanyStateOwner",
    "CompanySanitizedExportDelivery",
]
