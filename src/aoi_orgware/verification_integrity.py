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
import re
from collections.abc import Set
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .harnesslib import (
    ACCOUNTED_VERIFICATION_STATUSES,
    VERIFICATION_STATUSES,
    HarnessError,
    HarnessPaths,
    parse_time,
    validate_id,
)
from .evidence_artifacts import (
    _is_canonical_snapshot_version,
    _is_exact_int,
    _is_legacy_snapshot_version,
    artifact_ref_integrity_error,
    canonical_record_sha256,
    require_evidence_detail,
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
    for artifact in preimage.get("artifact_refs", []):
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
    for index, item in enumerate(state.get("verification", []), start=1):
        legacy_refs = [
            artifact
            for artifact in item.get("artifact_refs", [])
            if _is_legacy_snapshot_version(artifact.get("snapshot_version"))
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
    for source_index, source in enumerate(records, start=1):
        label = f"verification #{source_index}"
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
        if original_status not in ACCOUNTED_VERIFICATION_STATUSES - {"skipped"}:
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
) -> list[str]:
    """Validate individual verification records without reindexing graph edges."""

    errors: list[str] = []
    records = (
        indexed_records
        if indexed_records is not None
        else enumerate(state.get("verification", []), start=1)
    )
    for index, item in records:
        label = f"verification #{index}"
        if not _is_exact_int(item.get("integrity_version"), 1):
            errors.append(f"{label} lacks integrity_version=1")
            continue
        if item.get("category") not in policy.verification_categories:
            errors.append(f"{label} has unknown category {item.get('category')!r}")
        if item.get("status") not in VERIFICATION_STATUSES:
            errors.append(f"{label} has invalid status {item.get('status')!r}")
        if not str(item.get("evidence", "")).strip():
            errors.append(f"{label} has empty evidence")
        if not str(item.get("boundary", "")).strip():
            errors.append(f"{label} has empty evidence boundary")
        if item.get("status") in {"pass", "fail"} and not str(
            item.get("command", "")
        ).strip():
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
            if not str(item.get("reviewer_agent_id", "")).strip():
                errors.append(f"{label} lacks reviewer agent identity")
        for artifact in item.get("artifact_refs", []):
            if item.get("superseded_at") and _is_legacy_snapshot_version(
                artifact.get("snapshot_version")
            ):
                continue
            error = artifact_ref_integrity_error(
                paths, state, artifact, require_origin=False
            )
            if error:
                errors.append(f"{label} artifact reference: {error}")
    return errors


def verification_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    policy: VerificationPolicy,
) -> list[str]:
    errors = verification_record_integrity_errors(paths, state, policy=policy)
    errors.extend(verification_supersession_errors(state))
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
    "SUPERSESSION_MUTATION_FIELDS",
    "VerificationPolicy",
    "verification_integrity_errors",
    "verification_integrity_warnings",
    "verification_legacy_materialization_preimage",
    "verification_legacy_seal_preimage",
    "verification_migration_integrity_errors",
    "verification_record_integrity_errors",
    "verification_source_preimage",
    "verification_supersession_errors",
]
