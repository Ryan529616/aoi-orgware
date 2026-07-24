"""Verification-record and supersession-chain integrity validators.

The CLI remains the composition root.  It snapshots the current project
profile into :class:`VerificationPolicy` and passes that immutable policy to
the category-aware validators here, so extracted code never observes a stale
module global after a project-specific evidence vocabulary is loaded.  Every
other dependency (hashing, timestamp parsing, artifact-reference integrity,
snapshot-version predicates) is imported from a sibling package.  This module
imports only sibling packages and never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import stat
from collections.abc import Mapping, Set
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .harnesslib import (
    ACCOUNTED_VERIFICATION_STATUSES,
    VERIFICATION_STATUSES,
    HarnessError,
    HarnessPaths,
    canonicalize_no_link_traversal,
    parse_time,
    task_dir,
    validate_id,
)
from .evidence_artifacts import (
    _is_canonical_snapshot_version,
    _is_exact_int,
    _is_legacy_snapshot_version,
    artifact_ref_integrity_error,
    canonical_record_sha256,
    read_regular_artifact,
    require_evidence_detail,
    verify_generated_artifact_blob,
)
from .exact_test_receipts import (
    ExactTestReceiptError,
    MAX_RECEIPT_BYTES,
    parse_exact_test_receipt_bytes,
)


@dataclass(frozen=True)
class VerificationPolicy:
    """Immutable project vocabulary required by verification-domain decisions."""

    verification_categories: Set[str]
    close_qualifying_categories: Set[str]

    def __post_init__(self) -> None:
        for field in ("verification_categories", "close_qualifying_categories"):
            object.__setattr__(self, field, frozenset(getattr(self, field)))


SUPERSESSION_MUTATION_FIELDS = {
    "supersession_version",
    "source_record_sha256",
    "original_status",
    "superseded_at",
    "supersession_reason",
    "replacement_index",
    "replacement_record_sha256",
    "replacement_materialization",
}

EXACT_TEST_EVIDENCE_SCHEMA_VERSION = 1
EXACT_TEST_VERIFICATION_INTEGRITY_VERSION = 2
EXACT_TEST_BINDING_SCHEMA_VERSION = 1
EXACT_TEST_BINDING_KIND = "aoi.exact_test_verification_binding.v1"
EXACT_TEST_BINDING_MAX_BYTES = 64 * 1024
EXACT_TEST_BINDING_MAX_COUNT = 4096
EXACT_TEST_EVIDENCE_FIELDS = {
    "schema_version",
    "receipt_artifact",
    "log_artifact",
    "receipt_file_sha256",
    "receipt_sha256",
    "log_sha256",
    "source",
    "platform",
    "github_matrix_identity",
    "github_matrix_required",
    "accepted",
    "terminal_status",
    "pytest_exit_code",
    "semantic_transition",
    "binding_sha256",
}
EXACT_TEST_SOURCE_FIELDS = {"head", "index_tree", "manifest_sha256"}
EXACT_TEST_SEMANTIC_TRANSITION_FIELDS = {
    "event_type",
    "command_id",
    "expected_head_sha256",
    "recorded_at",
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SEMANTIC_RECORDED_AT_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        raw = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise HarnessError(f"exact-test binding is not canonical JSON data: {exc}") from exc
    if len(raw) > EXACT_TEST_BINDING_MAX_BYTES:
        raise HarnessError("exact-test binding exceeds its byte bound")
    return raw


def _canonical_json_equal(left: Any, right: Any) -> bool:
    try:
        return _canonical_json_bytes({"value": left}) == _canonical_json_bytes(
            {"value": right}
        )
    except HarnessError:
        return False


def exact_test_binding_bytes(
    task_id: str,
    verification_index: int,
    record: Mapping[str, Any],
) -> tuple[bytes, str]:
    """Build one immutable record-external provenance marker."""

    validate_id(task_id, "task id")
    if (
        not isinstance(verification_index, int)
        or isinstance(verification_index, bool)
        or verification_index < 1
    ):
        raise HarnessError("exact-test verification index is invalid")
    if not isinstance(record, Mapping):
        raise HarnessError("exact-test verification record is not an object")
    record_preimage = copy.deepcopy(dict(record))
    if record_preimage.get("superseded_at"):
        record_preimage = verification_source_preimage(record_preimage)
    evidence_preimage = record_preimage.get("exact_test_evidence")
    if not isinstance(evidence_preimage, dict):
        raise HarnessError("exact-test evidence is not an object")
    evidence_preimage.pop("binding_sha256", None)
    record_sha256 = hashlib.sha256(_canonical_json_bytes(record_preimage)).hexdigest()
    payload = {
        "schema_version": EXACT_TEST_BINDING_SCHEMA_VERSION,
        "kind": EXACT_TEST_BINDING_KIND,
        "task_id": task_id,
        "verification_index": verification_index,
        "record_sha256": record_sha256,
    }
    raw = _canonical_json_bytes(payload)
    return raw, hashlib.sha256(raw).hexdigest()


def exact_test_binding_path(
    paths: HarnessPaths, task_id: str, binding_sha256: str
) -> Path:
    validate_id(task_id, "task id")
    if _SHA256_RE.fullmatch(binding_sha256) is None:
        raise HarnessError("exact-test binding SHA-256 must be full lowercase hex")
    return (
        task_dir(paths, task_id)
        / "results"
        / "exact-test-bindings"
        / f"{binding_sha256}.json"
    )


def _exact_test_binding_files(
    paths: HarnessPaths, state: dict[str, Any]
) -> tuple[dict[str, bytes], list[str]]:
    task_id = state.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return {}, ["exact-test binding ledger task identity is invalid"]
    try:
        validate_id(task_id, "task id")
        root = task_dir(paths, task_id) / "results" / "exact-test-bindings"
    except HarnessError as exc:
        return {}, [f"exact-test binding ledger task identity is invalid: {exc}"]
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as exc:
        return {}, [f"exact-test binding ledger cannot be inspected: {exc}"]
    try:
        canonical = canonicalize_no_link_traversal(
            root, "exact-test binding ledger"
        )
    except HarnessError as exc:
        return {}, [str(exc)]
    if canonical != root or not stat.S_ISDIR(metadata.st_mode):
        return {}, ["exact-test binding ledger must be a real canonical directory"]
    try:
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return {}, [f"exact-test binding ledger cannot be listed: {exc}"]
    if len(entries) > EXACT_TEST_BINDING_MAX_COUNT:
        return {}, ["exact-test binding ledger exceeds its record-count bound"]
    bindings: dict[str, bytes] = {}
    errors: list[str] = []
    for entry in entries:
        match = re.fullmatch(r"([0-9a-f]{64})\.json", entry.name)
        if match is None:
            errors.append(
                f"exact-test binding ledger has a noncanonical entry: {entry.name!r}"
            )
            continue
        digest = match.group(1)
        try:
            _path, raw = read_regular_artifact(
                entry,
                "exact-test binding ledger entry",
                max_bytes=EXACT_TEST_BINDING_MAX_BYTES,
            )
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        if hashlib.sha256(raw).hexdigest() != digest:
            errors.append(
                f"exact-test binding ledger entry {digest} has a digest mismatch"
            )
            continue
        bindings[digest] = raw
    return bindings, errors


def exact_test_binding_ledger_integrity_errors(
    paths: HarnessPaths | None,
    state: dict[str, Any],
    *,
    pending_bindings: Mapping[str, bytes] | None = None,
) -> list[str]:
    """Require every immutable binding marker to have one exact v2 record."""

    if paths is None:
        return []
    bindings, errors = _exact_test_binding_files(paths, state)
    for digest, raw in (pending_bindings or {}).items():
        if (
            not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
            or not isinstance(raw, bytes)
            or not raw
            or len(raw) > EXACT_TEST_BINDING_MAX_BYTES
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            errors.append("pending exact-test binding is invalid")
            continue
        existing = bindings.get(digest)
        if existing is not None and existing != raw:
            errors.append(
                f"pending exact-test binding {digest} conflicts with its ledger entry"
            )
            continue
        bindings[digest] = raw
    records = state.get("verification", [])
    if not isinstance(records, list):
        return errors
    claimed: dict[str, int] = {}
    for index, item in enumerate(records, start=1):
        if not isinstance(item, dict) or not _is_exact_int(
            item.get("integrity_version"),
            EXACT_TEST_VERIFICATION_INTEGRITY_VERSION,
        ):
            continue
        evidence = item.get("exact_test_evidence")
        if not isinstance(evidence, dict):
            continue
        binding_sha256 = evidence.get("binding_sha256")
        if not isinstance(binding_sha256, str) or _SHA256_RE.fullmatch(
            binding_sha256
        ) is None:
            continue
        if binding_sha256 in claimed:
            errors.append(
                "exact-test binding "
                f"{binding_sha256} is claimed by verification #{claimed[binding_sha256]} "
                f"and verification #{index}"
            )
        else:
            claimed[binding_sha256] = index
    task_version = state.get("verification_integrity_version")
    if task_version is None:
        if bindings or claimed:
            errors.append(
                "task lacks verification_integrity_version=2 for exact-test bindings"
            )
    elif not _is_exact_int(task_version, 2):
        errors.append("task verification_integrity_version is invalid")
    elif not bindings and not claimed:
        errors.append(
            "task verification_integrity_version=2 lacks exact-test provenance"
        )
    for digest in sorted(bindings.keys() - claimed.keys()):
        errors.append(
            f"exact-test binding ledger entry {digest} has no exact v2 verification"
        )
    for digest in sorted(claimed.keys() - bindings.keys()):
        errors.append(
            f"exact v2 verification #{claimed[digest]} lacks binding ledger entry {digest}"
        )
    return errors


def _exact_test_evidence_errors(
    paths: HarnessPaths | None,
    state: dict[str, Any],
    item: dict[str, Any],
    label: str,
    verification_index: int,
    pending_bindings: Mapping[str, bytes] | None = None,
) -> list[str]:
    """Reopen and cross-bind one optional exact-test CAS evidence pair."""

    if "exact_test_evidence" not in item:
        return []
    evidence = item["exact_test_evidence"]
    prefix = f"{label} exact-test evidence"
    if not isinstance(evidence, dict) or set(evidence) != EXACT_TEST_EVIDENCE_FIELDS:
        return [f"{prefix} schema is invalid"]
    if not _is_exact_int(
        evidence.get("schema_version"), EXACT_TEST_EVIDENCE_SCHEMA_VERSION
    ):
        return [f"{prefix} schema version is invalid"]
    matrix_required = evidence.get("github_matrix_required")
    if type(matrix_required) is not bool:
        return [f"{prefix} GitHub matrix requirement is invalid"]
    semantic_transition = evidence.get("semantic_transition")
    if (
        not isinstance(semantic_transition, dict)
        or set(semantic_transition) != EXACT_TEST_SEMANTIC_TRANSITION_FIELDS
    ):
        return [f"{prefix} semantic transition schema is invalid"]
    semantic_recorded_at = semantic_transition.get("recorded_at")
    semantic_command_id = semantic_transition.get("command_id")
    if not isinstance(semantic_command_id, str):
        return [f"{prefix} semantic command id is invalid"]
    try:
        validate_id(
            semantic_command_id,
            "exact-test semantic command id",
        )
    except HarnessError:
        return [f"{prefix} semantic command id is invalid"]
    if semantic_transition.get("event_type") != "verification_added":
        return [f"{prefix} semantic event type is invalid"]
    if (
        not isinstance(semantic_transition.get("expected_head_sha256"), str)
        or _SHA256_RE.fullmatch(
            semantic_transition["expected_head_sha256"]
        )
        is None
    ):
        return [f"{prefix} semantic expected head SHA-256 is invalid"]
    if (
        not isinstance(semantic_recorded_at, str)
        or _SEMANTIC_RECORDED_AT_RE.fullmatch(semantic_recorded_at) is None
        or parse_time(semantic_recorded_at) is None
        or semantic_recorded_at != item.get("recorded_at")
    ):
        return [f"{prefix} semantic recorded_at binding is invalid"]
    if paths is None:
        return [f"{prefix} cannot be verified without AOI paths"]
    task_id = state.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return [f"{prefix} task binding is invalid"]
    receipt_artifact = evidence.get("receipt_artifact")
    log_artifact = evidence.get("log_artifact")
    if not isinstance(receipt_artifact, dict) or not isinstance(log_artifact, dict):
        return [f"{prefix} artifact reference schema is invalid"]
    errors: list[str] = []
    binding_sha256 = evidence.get("binding_sha256")
    if not isinstance(binding_sha256, str) or _SHA256_RE.fullmatch(
        binding_sha256
    ) is None:
        errors.append(f"{prefix} binding SHA-256 is invalid")
    else:
        try:
            expected_binding, expected_binding_sha256 = exact_test_binding_bytes(
                task_id,
                verification_index,
                item,
            )
            if binding_sha256 != expected_binding_sha256:
                errors.append(f"{prefix} immutable binding digest is invalid")
            if pending_bindings is not None and binding_sha256 in pending_bindings:
                observed_binding = pending_bindings[binding_sha256]
            else:
                _path, observed_binding = read_regular_artifact(
                    exact_test_binding_path(paths, task_id, binding_sha256),
                    f"{prefix} immutable binding",
                    max_bytes=EXACT_TEST_BINDING_MAX_BYTES,
                )
            if observed_binding != expected_binding:
                errors.append(f"{prefix} immutable binding bytes differ")
        except HarnessError as exc:
            errors.append(f"{prefix} immutable binding: {exc}")
    try:
        receipt_bytes = verify_generated_artifact_blob(
            paths,
            task_id,
            receipt_artifact,
            label=f"{prefix} receipt",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        log_bytes = verify_generated_artifact_blob(
            paths,
            task_id,
            log_artifact,
            label=f"{prefix} combined log",
        )
        receipt = parse_exact_test_receipt_bytes(
            receipt_bytes,
            require_github_matrix=matrix_required,
        )
    except (HarnessError, ExactTestReceiptError) as exc:
        errors.append(f"{prefix}: {exc}")
        return errors

    receipt_file_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    log_sha256 = hashlib.sha256(log_bytes).hexdigest()
    if (
        evidence.get("receipt_file_sha256") != receipt_file_sha256
        or receipt_artifact.get("sha256") != receipt_file_sha256
    ):
        errors.append(f"{prefix} receipt file SHA-256 binding is invalid")
    if evidence.get("receipt_sha256") != receipt["receipt_sha256"]:
        errors.append(f"{prefix} internal receipt SHA-256 binding is invalid")
    if (
        evidence.get("log_sha256") != receipt["log"]["sha256"]
        or log_artifact.get("sha256") != receipt["log"]["sha256"]
        or len(log_bytes) != receipt["log"]["size"]
    ):
        errors.append(f"{prefix} combined log binding is invalid")
    source = evidence.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != EXACT_TEST_SOURCE_FIELDS
        or source
        != {
            key: receipt["source"][key]
            for key in ("head", "index_tree", "manifest_sha256")
        }
    ):
        errors.append(f"{prefix} source binding is invalid")
    if not _canonical_json_equal(evidence.get("platform"), receipt["platform"]):
        errors.append(f"{prefix} platform binding is invalid")
    if not _canonical_json_equal(
        evidence.get("github_matrix_identity"),
        receipt["github_matrix_identity"],
    ):
        errors.append(f"{prefix} GitHub matrix binding is invalid")
    for field in ("accepted", "terminal_status", "pytest_exit_code"):
        if type(evidence.get(field)) is not type(receipt[field]) or evidence.get(
            field
        ) != receipt[field]:
            errors.append(f"{prefix} {field} binding is invalid")
    effective_status = (
        item.get("original_status")
        if item.get("superseded_at")
        else item.get("status")
    )
    expected_status = "pass" if receipt["accepted"] else "fail"
    if effective_status != expected_status:
        errors.append(
            f"{prefix} maps to original verification status "
            f"{expected_status!r}, not {effective_status!r}"
        )
    return errors


def verification_source_preimage(record: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the exact verification record before supersession mutation."""

    preimage = copy.deepcopy(record)
    original_status = preimage.get("original_status")
    for field in SUPERSESSION_MUTATION_FIELDS:
        preimage.pop(field, None)
    preimage["status"] = original_status
    return preimage


def verification_legacy_seal_preimage(record: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the legacy supersession record immediately before sealing."""

    preimage = copy.deepcopy(record)
    for field in (
        "supersession_version",
        "source_record_sha256",
        "replacement_materialization",
    ):
        preimage.pop(field, None)
    return preimage


def verification_legacy_materialization_preimage(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct a legacy live-ref record from canonical snapshot refs."""

    preimage = copy.deepcopy(record)
    refs: list[dict[str, Any]] = []
    artifact_refs = preimage.get("artifact_refs", [])
    if not isinstance(artifact_refs, list):
        raise HarnessError("replacement materialization artifact_refs must be an array")
    for artifact in artifact_refs:
        if not isinstance(artifact, dict):
            raise HarnessError(
                "replacement materialization artifact reference is malformed"
            )
        if not _is_canonical_snapshot_version(artifact.get("snapshot_version")):
            raise HarnessError(
                "replacement materialization preimage requires canonical snapshots"
            )
        source_path = str(artifact.get("source_path", ""))
        if not Path(source_path).is_absolute():
            raise HarnessError("canonical snapshot lacks an absolute legacy source path")
        refs.append(
            {
                "path": source_path,
                "sha256": artifact.get("sha256"),
                "size_bytes": artifact.get("size_bytes"),
            }
        )
    preimage["artifact_refs"] = refs
    preimage.pop("artifact_snapshot_version", None)
    return preimage


def verification_integrity_warnings(state: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    records = state.get("verification", [])
    if not isinstance(records, list):
        return warnings
    for index, item in enumerate(records, start=1):
        if not isinstance(item, dict):
            continue
        artifact_refs = item.get("artifact_refs", [])
        if not isinstance(artifact_refs, list):
            continue
        legacy_refs = [
            artifact
            for artifact in artifact_refs
            if isinstance(artifact, dict)
            and _is_legacy_snapshot_version(artifact.get("snapshot_version"))
        ]
        if not legacy_refs:
            continue
        if item.get("superseded_at"):
            warnings.append(
                f"verification #{index} is explicitly superseded with legacy "
                "digest-only artifact metadata"
            )
        else:
            warnings.append(
                f"verification #{index} uses legacy live artifact references; "
                "materialize or supersede it before the origins evolve"
            )
    return warnings


def verification_supersession_errors(state: dict[str, Any]) -> list[str]:
    """Validate immutable supersession identities and every chain to a pass leaf."""

    records = state.get("verification", [])
    errors: list[str] = []
    if not isinstance(records, list):
        return ["verification records must be an array"]
    for source_index, source in enumerate(records, start=1):
        label = f"verification #{source_index}"
        if not isinstance(source, dict):
            errors.append(f"{label} is malformed")
            continue
        superseded_raw = source.get("superseded_at")
        superseded = superseded_raw is not None and superseded_raw != ""
        metadata_present = any(
            field in source for field in SUPERSESSION_MUTATION_FIELDS
        )
        if not superseded:
            if metadata_present:
                errors.append(f"{label} has supersession metadata without superseded_at")
            continue
        superseded_time = (
            parse_time(superseded_raw) if isinstance(superseded_raw, str) else None
        )
        if superseded_time is None:
            errors.append(f"{label} superseded_at is not a valid timestamp")
        reason = source.get("supersession_reason")
        if not isinstance(reason, str):
            errors.append(f"{label} supersession reason is not text")
        else:
            try:
                require_evidence_detail(reason, f"{label} supersession reason")
            except HarnessError as exc:
                errors.append(str(exc))
        if not _is_exact_int(source.get("supersession_version"), 2):
            errors.append(f"{label} supersession is not sealed as version 2")
            continue
        source_sha = str(source.get("source_record_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
            errors.append(f"{label} source record SHA-256 is invalid")
        elif canonical_record_sha256(verification_source_preimage(source)) != source_sha:
            errors.append(f"{label} source preimage SHA-256 mismatch")
        original_status = source.get("original_status")
        if not isinstance(original_status, str) or original_status not in (
            ACCOUNTED_VERIFICATION_STATUSES - {"skipped"}
        ):
            errors.append(f"{label} has invalid original superseded status")
        replacement_index = source.get("replacement_index")
        if (
            not isinstance(replacement_index, int)
            or isinstance(replacement_index, bool)
            or replacement_index < 1
            or replacement_index > len(records)
            or replacement_index == source_index
        ):
            errors.append(f"{label} has invalid replacement index")
            continue
        replacement = records[replacement_index - 1]
        if not isinstance(replacement, dict):
            errors.append(f"{label} replacement record is malformed")
            continue
        stored_replacement_sha = str(source.get("replacement_record_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", stored_replacement_sha):
            errors.append(f"{label} replacement record SHA-256 is invalid")
            continue
        effective_replacement_sha = stored_replacement_sha
        materialization = source.get("replacement_materialization")
        if materialization is not None:
            required_materialization_fields = {
                "version",
                "method",
                "from_record_sha256",
                "to_record_sha256",
                "sealed_at",
            }
            if (
                not isinstance(materialization, dict)
                or set(materialization) != required_materialization_fields
                or not _is_exact_int(materialization.get("version"), 1)
                or materialization.get("method")
                != "canonical-artifact-materialization"
            ):
                errors.append(f"{label} replacement materialization receipt is invalid")
                continue
            from_sha = str(materialization.get("from_record_sha256", ""))
            to_sha = str(materialization.get("to_record_sha256", ""))
            if from_sha != stored_replacement_sha or not re.fullmatch(
                r"[0-9a-f]{64}", to_sha
            ) or from_sha == to_sha:
                errors.append(f"{label} replacement materialization SHA mapping is invalid")
                continue
            sealed_raw = materialization.get("sealed_at")
            sealed_time = parse_time(sealed_raw) if isinstance(sealed_raw, str) else None
            if (
                sealed_time is None
                or superseded_time is None
                or sealed_time < superseded_time
            ):
                errors.append(f"{label} replacement materialization time is invalid")
                continue
            replacement_pre_supersede = (
                verification_source_preimage(replacement)
                if replacement.get("superseded_at")
                and _is_exact_int(replacement.get("supersession_version"), 2)
                else replacement
            )
            try:
                legacy_preimage_sha = canonical_record_sha256(
                    verification_legacy_materialization_preimage(
                        replacement_pre_supersede
                    )
                )
            except HarnessError as exc:
                errors.append(f"{label} replacement materialization: {exc}")
                continue
            if legacy_preimage_sha != from_sha:
                errors.append(f"{label} replacement legacy preimage SHA-256 mismatch")
            effective_replacement_sha = to_sha
        replacement_identity = (
            str(replacement.get("source_record_sha256", ""))
            if replacement.get("superseded_at")
            and _is_exact_int(replacement.get("supersession_version"), 2)
            else canonical_record_sha256(replacement)
        )
        if replacement_identity != effective_replacement_sha:
            errors.append(f"{label} replacement record SHA-256 mismatch")
        source_time = parse_time(str(source.get("recorded_at", "")))
        replacement_time = parse_time(str(replacement.get("recorded_at", "")))
        if (
            source.get("category") != replacement.get("category")
            or source_time is None
            or replacement_time is None
            or replacement_time <= source_time
            or superseded_time is None
            or superseded_time < replacement_time
        ):
            errors.append(f"{label} replacement category/time relationship is invalid")

        seen: set[int] = set()
        cursor = source_index
        while True:
            if cursor in seen:
                errors.append(f"{label} replacement chain contains a cycle")
                break
            seen.add(cursor)
            current = records[cursor - 1]
            if not isinstance(current, dict):
                errors.append(
                    f"{label} replacement chain record #{cursor} is malformed"
                )
                break
            if not current.get("superseded_at"):
                if current.get("status") != "pass":
                    errors.append(f"{label} replacement chain does not end in pass")
                break
            next_index = current.get("replacement_index")
            if (
                not isinstance(next_index, int)
                or isinstance(next_index, bool)
                or next_index < 1
                or next_index > len(records)
            ):
                break
            cursor = next_index
    return errors


def verification_record_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    indexed_records: Iterable[tuple[int, dict[str, Any]]] | None = None,
    *,
    policy: VerificationPolicy,
    pending_exact_test_bindings: Mapping[str, bytes] | None = None,
) -> list[str]:
    """Validate individual verification records without reindexing graph edges."""

    errors: list[str] = []
    records: Iterable[tuple[int, Any]]
    if indexed_records is None:
        state_records = state.get("verification", [])
        if not isinstance(state_records, list):
            return ["verification records must be an array"]
        records = enumerate(state_records, start=1)
    else:
        records = indexed_records
    for index, item in records:
        label = f"verification #{index}"
        if not isinstance(item, dict):
            errors.append(f"{label} is malformed")
            continue
        integrity_version = item.get("integrity_version")
        legacy_version = _is_exact_int(integrity_version, 1)
        exact_test_version = _is_exact_int(
            integrity_version, EXACT_TEST_VERIFICATION_INTEGRITY_VERSION
        )
        if not legacy_version and not exact_test_version:
            errors.append(
                f"{label} lacks integrity_version=1 or exact-test "
                f"integrity_version={EXACT_TEST_VERIFICATION_INTEGRITY_VERSION}"
            )
            continue
        has_exact_test_evidence = "exact_test_evidence" in item
        if exact_test_version and not has_exact_test_evidence:
            errors.append(
                f"{label} exact-test integrity_version="
                f"{EXACT_TEST_VERIFICATION_INTEGRITY_VERSION} requires "
                "exact_test_evidence"
            )
        if legacy_version and has_exact_test_evidence:
            errors.append(
                f"{label} legacy integrity_version=1 may not contain "
                "exact_test_evidence"
            )
        category = item.get("category")
        status = item.get("status")
        if not isinstance(category, str) or category not in policy.verification_categories:
            errors.append(f"{label} has unknown category {category!r}")
        if not isinstance(status, str) or status not in VERIFICATION_STATUSES:
            errors.append(f"{label} has invalid status {status!r}")
        evidence = item.get("evidence")
        boundary = item.get("boundary")
        command = item.get("command")
        if not isinstance(evidence, str) or not evidence.strip():
            errors.append(f"{label} has empty evidence")
        if not isinstance(boundary, str) or not boundary.strip():
            errors.append(f"{label} has empty evidence boundary")
        if isinstance(status, str) and status in {"pass", "fail"} and (
            not isinstance(command, str) or not command.strip()
        ):
            errors.append(f"{label} pass/fail record has empty command or method")
        if item.get("superseded_at"):
            if item.get("status") != "skipped":
                errors.append(f"{label} superseded record must have status='skipped'")
            if not isinstance(item.get("supersession_reason"), str) or not item.get(
                "supersession_reason", ""
            ).strip():
                errors.append(f"{label} superseded record lacks a reason")
        if item.get("category") == "independent_review" and any(
            item.get(field)
            for field in (
                "review_packet_id",
                "review_result_sha256",
                "reviewer_agent_id",
            )
        ):
            try:
                validate_id(
                    str(item.get("review_packet_id", "")),
                    "independent review packet id",
                )
            except HarnessError as exc:
                errors.append(f"{label} {exc}")
            if not re.fullmatch(
                r"[0-9a-f]{64}", str(item.get("review_result_sha256", ""))
            ):
                errors.append(f"{label} lacks reviewer result SHA-256")
            reviewer_agent_id = item.get("reviewer_agent_id")
            if not isinstance(reviewer_agent_id, str) or not reviewer_agent_id.strip():
                errors.append(f"{label} lacks reviewer agent identity")
        artifact_refs = item.get("artifact_refs", [])
        if not isinstance(artifact_refs, list):
            errors.append(f"{label} artifact_refs must be an array")
            continue
        for artifact in artifact_refs:
            if not isinstance(artifact, dict):
                errors.append(f"{label} artifact reference is malformed")
                continue
            if item.get("superseded_at") and _is_legacy_snapshot_version(
                artifact.get("snapshot_version")
            ):
                continue
            error = artifact_ref_integrity_error(
                paths, state, artifact, require_origin=False
            )
            if error:
                errors.append(f"{label} artifact reference: {error}")
        if exact_test_version:
            errors.extend(
                _exact_test_evidence_errors(
                    paths,
                    state,
                    item,
                    label,
                    index,
                    pending_exact_test_bindings,
                )
            )
    return errors


def verification_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    policy: VerificationPolicy,
    pending_exact_test_bindings: Mapping[str, bytes] | None = None,
) -> list[str]:
    if not isinstance(state.get("verification", []), list):
        return ["verification records must be an array"]
    errors = verification_record_integrity_errors(
        paths,
        state,
        policy=policy,
        pending_exact_test_bindings=pending_exact_test_bindings,
    )
    seen = set(errors)
    for error in verification_supersession_errors(state):
        if error not in seen:
            errors.append(error)
            seen.add(error)
    for error in exact_test_binding_ledger_integrity_errors(
        paths, state, pending_bindings=pending_exact_test_bindings
    ):
        if error not in seen:
            errors.append(error)
            seen.add(error)
    return errors


def verification_migration_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    policy: VerificationPolicy,
) -> list[str]:
    """Allow only the explicit unsealed-edge error during one-by-one migration."""

    return [
        error
        for error in verification_integrity_errors(paths, state, policy=policy)
        if not re.fullmatch(
            r"verification #\d+ supersession is not sealed as version 2",
            error,
        )
    ]


__all__ = [
    "EXACT_TEST_BINDING_MAX_BYTES",
    "EXACT_TEST_VERIFICATION_INTEGRITY_VERSION",
    "SUPERSESSION_MUTATION_FIELDS",
    "VerificationPolicy",
    "exact_test_binding_bytes",
    "exact_test_binding_ledger_integrity_errors",
    "exact_test_binding_path",
    "verification_integrity_errors",
    "verification_integrity_warnings",
    "verification_legacy_materialization_preimage",
    "verification_legacy_seal_preimage",
    "verification_migration_integrity_errors",
    "verification_record_integrity_errors",
    "verification_source_preimage",
    "verification_supersession_errors",
]
