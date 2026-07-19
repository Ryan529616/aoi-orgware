"""Pure persisted integrity-contract records for AOI task state.

This module deliberately has no state, Git, artifact-store, or CLI dependency.
It defines the bytes-bound records which those layers may persist.  A task that
has not adopted the contract remains a supported legacy task; once adopted,
the contract is fail-closed and every record is content-addressed.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any, TypeGuard


INTEGRITY_CONTRACT_SCHEMA_VERSION = 1
INTEGRITY_CONTRACT_MODE = "required_v1"
MAX_INTEGRITY_RECORDS = 1024
MAX_INTEGRITY_RECORD_BYTES = 64 * 1024
MAX_INTEGRITY_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_INTEGRITY_TEXT_BYTES = 4096

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_GIT_HEAD_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_FINDING_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CONTRACT_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "adopted_at",
        "baseline_head",
        "snapshots",
        "review_results",
        "findings",
        "fixes",
        "review_verifications",
        "seal",
    }
)
_ARTIFACT_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_SNAPSHOT_FIELDS = frozenset(
    {
        "record_type",
        "task_id",
        "worktree",
        "baseline_head",
        "current_head",
        "artifact",
        "snapshot_sha256",
        "claim_scope_sha256",
        "covered_claim_tokens",
        "purpose",
        "producer_agent_ids",
        "record_sha256",
    }
)
_REVIEW_FIELDS = frozenset(
    {
        "record_type",
        "snapshot_sha256",
        "reviewer_agent_id",
        "producer_agent_ids",
        "result_artifact",
        "outcome",
        "finding_ids",
        "record_sha256",
    }
)
_FINDING_FIELDS = frozenset(
    {
        "record_type",
        "finding_id",
        "review_result_record_sha256",
        "snapshot_sha256",
        "reviewer_agent_id",
        "finding_artifact_sha256",
        "record_sha256",
    }
)
_FIX_FIELDS = frozenset(
    {
        "record_type",
        "finding_id",
        "finding_record_sha256",
        "post_fix_snapshot_sha256",
        "fix_artifact",
        "producer_agent_ids",
        "record_sha256",
    }
)
_VERIFICATION_FIELDS = frozenset(
    {
        "record_type",
        "finding_id",
        "fix_record_sha256",
        "snapshot_sha256",
        "reviewer_agent_id",
        "verification_artifact",
        "outcome",
        "record_sha256",
    }
)
_SEAL_FIELDS = frozenset(
    {
        "record_type",
        "latest_candidate_snapshot_sha256",
        "latest_review_result_record_sha256",
        "claim_scope_sha256",
        "sealed_at",
        "record_sha256",
    }
)
_COLLECTION_RECORD_TYPE = {
    "snapshots": "snapshot",
    "review_results": "review_result",
    "findings": "finding",
    "fixes": "fix",
    "review_verifications": "review_verification",
}


class IntegrityRecordError(ValueError):
    """A persisted integrity-contract record is absent, malformed, or stale."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        values = (errors,) if isinstance(errors, str) else tuple(errors)
        self.errors = tuple(str(value) for value in values)
        super().__init__("integrity contract failed: " + "; ".join(self.errors))


def _canonical_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IntegrityRecordError("record is not canonical JSON") from exc
    if len(encoded) > MAX_INTEGRITY_RECORD_BYTES:
        raise IntegrityRecordError("record exceeds compact byte bound")
    return encoded


def integrity_record_sha256(record: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 for a record excluding ``record_sha256``."""

    if not isinstance(record, Mapping):
        raise IntegrityRecordError("record is not an object")
    preimage = {key: value for key, value in record.items() if key != "record_sha256"}
    return hashlib.sha256(_canonical_bytes(preimage)).hexdigest()


def _is_exact_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise IntegrityRecordError(f"{label} must be a lowercase SHA-256")
    return value


def _head(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _GIT_HEAD_RE.fullmatch(value):
        raise IntegrityRecordError(f"{label} must be a full 40-64 lowercase Git head")
    return value


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise IntegrityRecordError(f"{label} must be non-empty exact text")
    if "\x00" in value or len(value.encode("utf-8")) > MAX_INTEGRITY_TEXT_BYTES:
        raise IntegrityRecordError(f"{label} exceeds text bounds")
    if pattern is not None and not pattern.fullmatch(value):
        raise IntegrityRecordError(f"{label} has invalid syntax")
    return value


def _time(value: Any, label: str) -> str:
    text = _text(value, label)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntegrityRecordError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IntegrityRecordError(f"{label} requires an explicit timezone")
    return text


def _worktree(value: Any, label: str) -> str:
    text = _text(value, label)
    if not (PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute()):
        raise IntegrityRecordError(f"{label} must be an absolute path")
    return text


def _sorted_unique_texts(value: Any, label: str, *, pattern: re.Pattern[str]) -> list[str]:
    if not isinstance(value, list):
        raise IntegrityRecordError(f"{label} must be an array")
    if len(value) > MAX_INTEGRITY_RECORDS:
        raise IntegrityRecordError(f"{label} exceeds {MAX_INTEGRITY_RECORDS} entries")
    values = [_text(item, label, pattern=pattern) for item in value]
    if values != sorted(set(values)):
        raise IntegrityRecordError(f"{label} must be sorted and unique")
    return values


def _artifact(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ARTIFACT_FIELDS:
        raise IntegrityRecordError(f"{label} schema is invalid")
    path = _text(value.get("path"), f"{label}.path")
    if PurePath(path).is_absolute() or PureWindowsPath(path).is_absolute() or path.startswith("/"):
        raise IntegrityRecordError(f"{label}.path must be a relative artifact path")
    if "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise IntegrityRecordError(f"{label}.path must be a normalized POSIX relative path")
    size = value.get("size_bytes")
    if not _is_exact_int(size) or size < 0 or size > MAX_INTEGRITY_ARTIFACT_BYTES:
        raise IntegrityRecordError(f"{label}.size_bytes is invalid")
    return {"path": path, "sha256": _sha256(value.get("sha256"), label), "size_bytes": size}


def build_artifact_ref(*, path: Any, sha256: Any, size_bytes: Any) -> dict[str, Any]:
    """Build one exact, compact persisted artifact reference."""

    return _artifact({"path": path, "sha256": sha256, "size_bytes": size_bytes}, "artifact")


def _seal_record(record: dict[str, Any]) -> dict[str, Any]:
    record["record_sha256"] = integrity_record_sha256(record)
    return record


def build_snapshot_record(
    *, task_id: Any, worktree: Any, baseline_head: Any, current_head: Any,
    artifact: Mapping[str, Any], snapshot_sha256: Any, claim_scope_sha256: Any,
    covered_claim_tokens: Iterable[Any], purpose: Any, producer_agent_ids: Iterable[Any],
) -> dict[str, Any]:
    """Build a candidate, post-fix, or close snapshot bound to task authority."""

    record = {
        "record_type": "snapshot",
        "task_id": _text(task_id, "snapshot.task_id", pattern=_TOKEN_RE),
        "worktree": _worktree(worktree, "snapshot.worktree"),
        "baseline_head": _head(baseline_head, "snapshot.baseline_head"),
        "current_head": _head(current_head, "snapshot.current_head"),
        "artifact": _artifact(artifact, "snapshot.artifact"),
        "snapshot_sha256": _sha256(snapshot_sha256, "snapshot.snapshot_sha256"),
        "claim_scope_sha256": _sha256(claim_scope_sha256, "snapshot.claim_scope_sha256"),
        "covered_claim_tokens": _normalized_iterable(
            covered_claim_tokens, "snapshot.covered_claim_tokens", _TOKEN_RE, nonempty=False
        ),
        "purpose": _one_of(purpose, "snapshot.purpose", {"candidate", "post_fix", "close"}),
        "producer_agent_ids": _normalized_iterable(
            producer_agent_ids, "snapshot.producer_agent_ids", _TOKEN_RE, nonempty=True
        ),
    }
    return _seal_record(record)


def _normalized_iterable(
    value: Iterable[Any], label: str, pattern: re.Pattern[str], *, nonempty: bool
) -> list[str]:
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise IntegrityRecordError(f"{label} must be an array")
    try:
        values = list(value)
    except TypeError as exc:
        raise IntegrityRecordError(f"{label} must be an array") from exc
    if len(values) > MAX_INTEGRITY_RECORDS:
        raise IntegrityRecordError(f"{label} exceeds {MAX_INTEGRITY_RECORDS} entries")
    texts = [_text(item, label, pattern=pattern) for item in values]
    if texts != sorted(set(texts)):
        raise IntegrityRecordError(f"{label} must be sorted and unique")
    if nonempty and not texts:
        raise IntegrityRecordError(f"{label} may not be empty")
    return texts


def _one_of(value: Any, label: str, options: set[str]) -> str:
    if value not in options:
        raise IntegrityRecordError(f"{label} is invalid")
    return str(value)


def build_review_result_record(
    *, snapshot_sha256: Any, reviewer_agent_id: Any, producer_agent_ids: Iterable[Any],
    result_artifact: Mapping[str, Any], outcome: Any, finding_ids: Iterable[Any],
) -> dict[str, Any]:
    """Build the mandatory review result, including a zero-finding clean review."""

    producers = _normalized_iterable(
        producer_agent_ids, "review_result.producer_agent_ids", _TOKEN_RE, nonempty=True
    )
    reviewer = _text(reviewer_agent_id, "review_result.reviewer_agent_id", pattern=_TOKEN_RE)
    if reviewer in producers:
        raise IntegrityRecordError("review_result is self-review")
    findings = _normalized_iterable(finding_ids, "review_result.finding_ids", _FINDING_RE, nonempty=False)
    outcome_text = _one_of(outcome, "review_result.outcome", {"clean", "findings"})
    if (outcome_text == "clean") != (not findings):
        raise IntegrityRecordError("review_result outcome conflicts with finding_ids")
    return _seal_record(
        {
            "record_type": "review_result",
            "snapshot_sha256": _sha256(snapshot_sha256, "review_result.snapshot_sha256"),
            "reviewer_agent_id": reviewer,
            "producer_agent_ids": producers,
            "result_artifact": _artifact(result_artifact, "review_result.result_artifact"),
            "outcome": outcome_text,
            "finding_ids": findings,
        }
    )


def build_finding_record(
    *, finding_id: Any, review_result_record_sha256: Any, snapshot_sha256: Any,
    reviewer_agent_id: Any, finding_artifact_sha256: Any,
) -> dict[str, Any]:
    return _seal_record(
        {
            "record_type": "finding",
            "finding_id": _text(finding_id, "finding.finding_id", pattern=_FINDING_RE),
            "review_result_record_sha256": _sha256(review_result_record_sha256, "finding.review_result_record_sha256"),
            "snapshot_sha256": _sha256(snapshot_sha256, "finding.snapshot_sha256"),
            "reviewer_agent_id": _text(reviewer_agent_id, "finding.reviewer_agent_id", pattern=_TOKEN_RE),
            "finding_artifact_sha256": _sha256(finding_artifact_sha256, "finding.finding_artifact_sha256"),
        }
    )


def build_fix_record(
    *, finding_id: Any, finding_record_sha256: Any, post_fix_snapshot_sha256: Any,
    fix_artifact: Mapping[str, Any], producer_agent_ids: Iterable[Any],
) -> dict[str, Any]:
    return _seal_record(
        {
            "record_type": "fix",
            "finding_id": _text(finding_id, "fix.finding_id", pattern=_FINDING_RE),
            "finding_record_sha256": _sha256(finding_record_sha256, "fix.finding_record_sha256"),
            "post_fix_snapshot_sha256": _sha256(post_fix_snapshot_sha256, "fix.post_fix_snapshot_sha256"),
            "fix_artifact": _artifact(fix_artifact, "fix.fix_artifact"),
            "producer_agent_ids": _normalized_iterable(
                producer_agent_ids, "fix.producer_agent_ids", _TOKEN_RE, nonempty=True
            ),
        }
    )


def build_review_verification_record(
    *, finding_id: Any, fix_record_sha256: Any, snapshot_sha256: Any,
    reviewer_agent_id: Any, verification_artifact: Mapping[str, Any], outcome: Any,
) -> dict[str, Any]:
    return _seal_record(
        {
            "record_type": "review_verification",
            "finding_id": _text(finding_id, "review_verification.finding_id", pattern=_FINDING_RE),
            "fix_record_sha256": _sha256(fix_record_sha256, "review_verification.fix_record_sha256"),
            "snapshot_sha256": _sha256(snapshot_sha256, "review_verification.snapshot_sha256"),
            "reviewer_agent_id": _text(reviewer_agent_id, "review_verification.reviewer_agent_id", pattern=_TOKEN_RE),
            "verification_artifact": _artifact(verification_artifact, "review_verification.verification_artifact"),
            "outcome": _one_of(outcome, "review_verification.outcome", {"pass", "fail"}),
        }
    )


def build_integrity_seal(
    *, latest_candidate_snapshot_sha256: Any, latest_review_result_record_sha256: Any,
    claim_scope_sha256: Any, sealed_at: Any,
) -> dict[str, Any]:
    return _seal_record(
        {
            "record_type": "seal",
            "latest_candidate_snapshot_sha256": _sha256(latest_candidate_snapshot_sha256, "seal.latest_candidate_snapshot_sha256"),
            "latest_review_result_record_sha256": _sha256(latest_review_result_record_sha256, "seal.latest_review_result_record_sha256"),
            "claim_scope_sha256": _sha256(claim_scope_sha256, "seal.claim_scope_sha256"),
            "sealed_at": _time(sealed_at, "seal.sealed_at"),
        }
    )


def build_integrity_contract(*, baseline_head: Any, adopted_at: Any) -> dict[str, Any]:
    """Build an empty, adopted v1 contract.  It is valid until snapshots exist."""

    return {
        "schema_version": INTEGRITY_CONTRACT_SCHEMA_VERSION,
        "mode": INTEGRITY_CONTRACT_MODE,
        "adopted_at": _time(adopted_at, "integrity_contract.adopted_at"),
        "baseline_head": _head(baseline_head, "integrity_contract.baseline_head"),
        "snapshots": [],
        "review_results": [],
        "findings": [],
        "fixes": [],
        "review_verifications": [],
        "seal": None,
    }


def adopt_integrity_contract(task_state: Mapping[str, Any], *, baseline_head: Any, adopted_at: Any) -> dict[str, Any]:
    """Return a copied task projection with its one-way required-v1 adoption."""

    if not isinstance(task_state, Mapping):
        raise IntegrityRecordError("task state is not an object")
    if "integrity_contract" in task_state:
        raise IntegrityRecordError("task already has an integrity_contract")
    result = copy.deepcopy(dict(task_state))
    result["integrity_contract"] = build_integrity_contract(
        baseline_head=baseline_head, adopted_at=adopted_at
    )
    return result


def append_integrity_record(
    contract: Mapping[str, Any], collection: str, record: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a copied, unsealed contract with one pre-sealed typed record appended.

    Appending is intentionally structural rather than terminal validation: a
    candidate snapshot is followed by a review record in the same task update.
    Call :func:`validate_integrity_contract` before persistence/closure.
    """

    if collection not in _COLLECTION_RECORD_TYPE:
        raise IntegrityRecordError("integrity record collection is invalid")
    if not isinstance(contract, Mapping) or not isinstance(record, Mapping):
        raise IntegrityRecordError("integrity contract and record must be objects")
    result = copy.deepcopy(dict(contract))
    if result.get("seal") is not None:
        raise IntegrityRecordError("sealed integrity contract is immutable")
    records = result.get(collection)
    if not isinstance(records, list):
        raise IntegrityRecordError(f"integrity contract {collection} is not an array")
    if len(records) >= MAX_INTEGRITY_RECORDS:
        raise IntegrityRecordError(f"integrity contract {collection} exceeds {MAX_INTEGRITY_RECORDS} records")
    if record.get("record_type") != _COLLECTION_RECORD_TYPE[collection]:
        raise IntegrityRecordError("record type does not match integrity collection")
    _validate_record(dict(record), _COLLECTION_RECORD_TYPE[collection], "appended record")
    records.append(copy.deepcopy(dict(record)))
    return result


def append_snapshot(contract: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    return append_integrity_record(contract, "snapshots", record)


def append_review_result(contract: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    return append_integrity_record(contract, "review_results", record)


def append_finding(contract: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    return append_integrity_record(contract, "findings", record)


def append_fix(contract: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    return append_integrity_record(contract, "fixes", record)


def append_review_verification(contract: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    return append_integrity_record(contract, "review_verifications", record)


def seal_integrity_contract(
    contract: Mapping[str, Any], seal: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a terminal contract only if the supplied seal closes its full graph."""

    if not isinstance(contract, Mapping) or not isinstance(seal, Mapping):
        raise IntegrityRecordError("integrity contract and seal must be objects")
    result = copy.deepcopy(dict(contract))
    if result.get("seal") is not None:
        raise IntegrityRecordError("sealed integrity contract is immutable")
    _validate_record(dict(seal), "seal", "integrity_contract.seal")
    result["seal"] = copy.deepcopy(dict(seal))
    validate_integrity_contract(result, require_complete=True)
    return result


def _validate_record(record: dict[str, Any], record_type: str, label: str) -> None:
    fields = {
        "snapshot": _SNAPSHOT_FIELDS,
        "review_result": _REVIEW_FIELDS,
        "finding": _FINDING_FIELDS,
        "fix": _FIX_FIELDS,
        "review_verification": _VERIFICATION_FIELDS,
        "seal": _SEAL_FIELDS,
    }[record_type]
    if set(record) != fields or record.get("record_type") != record_type:
        raise IntegrityRecordError(f"{label} schema is invalid")
    if record.get("record_sha256") != integrity_record_sha256(record):
        raise IntegrityRecordError(f"{label} record_sha256 is invalid")
    # Reuse builders as exact schema validators without trusting their returned copy.
    try:
        if record_type == "snapshot":
            expected = build_snapshot_record(**{key: record[key] for key in fields - {"record_type", "record_sha256"}})
        elif record_type == "review_result":
            expected = build_review_result_record(**{key: record[key] for key in fields - {"record_type", "record_sha256"}})
        elif record_type == "finding":
            expected = build_finding_record(**{key: record[key] for key in fields - {"record_type", "record_sha256"}})
        elif record_type == "fix":
            expected = build_fix_record(**{key: record[key] for key in fields - {"record_type", "record_sha256"}})
        elif record_type == "review_verification":
            expected = build_review_verification_record(**{key: record[key] for key in fields - {"record_type", "record_sha256"}})
        else:
            expected = build_integrity_seal(**{key: record[key] for key in fields - {"record_type", "record_sha256"}})
    except (KeyError, IntegrityRecordError) as exc:
        raise IntegrityRecordError(f"{label} values are invalid: {exc}") from exc
    if record != expected:
        raise IntegrityRecordError(f"{label} is not canonical")


def _record_list(contract: Mapping[str, Any], name: str, record_type: str, errors: list[str]) -> list[dict[str, Any]]:
    raw = contract.get(name)
    if not isinstance(raw, list):
        errors.append(f"integrity_contract.{name} must be an array")
        return []
    if len(raw) > MAX_INTEGRITY_RECORDS:
        errors.append(f"integrity_contract.{name} exceeds {MAX_INTEGRITY_RECORDS} records")
        return []
    records: list[dict[str, Any]] = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, Mapping):
            errors.append(f"{name} record {index} is not an object")
            continue
        record = dict(item)
        try:
            _validate_record(record, record_type, f"{name} record {index}")
        except IntegrityRecordError as exc:
            errors.extend(exc.errors)
            continue
        records.append(record)
    return records


def integrity_contract_errors(
    contract: Any,
    *,
    task_id: Any | None = None,
    worktree: Any | None = None,
    require_complete: bool = False,
) -> list[str]:
    """Return deterministic v1 errors, optionally requiring close completeness.

    Drafts remain structurally fail-closed: malformed records, dangling hash
    links, and self-review are always errors.  A candidate may deliberately be
    persisted before its review result, and a finding before its latest fix is
    independently verified; those are only errors at the close/seal boundary.
    """

    errors: list[str] = []
    if not isinstance(contract, Mapping) or set(contract) != _CONTRACT_FIELDS:
        return ["integrity_contract schema is invalid"]
    if contract.get("schema_version") != INTEGRITY_CONTRACT_SCHEMA_VERSION:
        errors.append("integrity_contract schema_version is invalid")
    if contract.get("mode") != INTEGRITY_CONTRACT_MODE:
        errors.append("integrity_contract mode is invalid")
    try:
        _time(contract.get("adopted_at"), "integrity_contract.adopted_at")
        baseline = _head(contract.get("baseline_head"), "integrity_contract.baseline_head")
    except IntegrityRecordError as exc:
        errors.extend(exc.errors)
        baseline = None
    snapshots = _record_list(contract, "snapshots", "snapshot", errors)
    reviews = _record_list(contract, "review_results", "review_result", errors)
    findings = _record_list(contract, "findings", "finding", errors)
    fixes = _record_list(contract, "fixes", "fix", errors)
    verifications = _record_list(contract, "review_verifications", "review_verification", errors)
    raw_seal = contract.get("seal")
    seal: dict[str, Any] | None = None
    if raw_seal is not None:
        if not isinstance(raw_seal, Mapping):
            errors.append("integrity_contract.seal is not an object")
        else:
            try:
                _validate_record(dict(raw_seal), "seal", "integrity_contract.seal")
                seal = dict(raw_seal)
            except IntegrityRecordError as exc:
                errors.extend(exc.errors)
    complete_required = require_complete or seal is not None
    if require_complete and seal is None:
        errors.append("complete integrity contract requires a seal")

    candidate_by_sha: dict[str, dict[str, Any]] = {}
    snapshot_by_sha: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        snapshot_sha = snapshot["snapshot_sha256"]
        if snapshot_sha in snapshot_by_sha:
            errors.append("duplicate snapshot_sha256")
            continue
        snapshot_by_sha[snapshot_sha] = snapshot
        if baseline is not None and snapshot["baseline_head"] != baseline:
            errors.append("snapshot baseline_head differs from integrity contract")
        if task_id is not None and snapshot["task_id"] != task_id:
            errors.append("snapshot task_id differs from task state")
        if worktree not in (None, "") and snapshot["worktree"] != worktree:
            errors.append("snapshot worktree differs from task state")
        if snapshot["purpose"] == "candidate":
            candidate_by_sha[snapshot_sha] = snapshot

    reviews_by_snapshot: dict[str, dict[str, Any]] = {}
    reviews_by_record_sha: dict[str, dict[str, Any]] = {}
    for review in reviews:
        record_sha = review["record_sha256"]
        if record_sha in reviews_by_record_sha:
            errors.append("duplicate review_result record_sha256")
        reviews_by_record_sha[record_sha] = review
        reviewed_snapshot = candidate_by_sha.get(review["snapshot_sha256"])
        if reviewed_snapshot is None:
            errors.append("review_result does not bind a candidate snapshot")
            continue
        if review["producer_agent_ids"] != reviewed_snapshot["producer_agent_ids"]:
            errors.append("review_result producer identities differ from its snapshot")
        if review["reviewer_agent_id"] in reviewed_snapshot["producer_agent_ids"]:
            errors.append("review_result is self-review")
        if review["snapshot_sha256"] in reviews_by_snapshot:
            errors.append("candidate snapshot has multiple review results")
        reviews_by_snapshot[review["snapshot_sha256"]] = review
    if complete_required:
        for candidate_sha in candidate_by_sha:
            if candidate_sha not in reviews_by_snapshot:
                errors.append("candidate snapshot lacks mandatory review result")

    findings_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        finding_id = finding["finding_id"]
        if finding_id in findings_by_id:
            errors.append(f"duplicate finding_id {finding_id}")
            continue
        findings_by_id[finding_id] = finding
        finding_review = reviews_by_record_sha.get(finding["review_result_record_sha256"])
        if finding_review is None:
            errors.append(f"finding {finding_id} does not bind a review result")
            continue
        if (
            finding["snapshot_sha256"] != finding_review["snapshot_sha256"]
            or finding["reviewer_agent_id"] != finding_review["reviewer_agent_id"]
            or finding["finding_artifact_sha256"] != finding_review["result_artifact"]["sha256"]
            or finding_id not in finding_review["finding_ids"]
        ):
            errors.append(f"finding {finding_id} lost review binding")
    for review in reviews:
        actual = sorted(
            finding_id for finding_id, finding in findings_by_id.items()
            if finding.get("review_result_record_sha256") == review["record_sha256"]
        )
        if actual != review["finding_ids"]:
            errors.append("review_result finding_ids differ from finding records")

    fixes_by_finding: dict[str, list[dict[str, Any]]] = {}
    fixes_by_record_sha: dict[str, dict[str, Any]] = {}
    for fix in fixes:
        finding_id = fix["finding_id"]
        if fix["record_sha256"] in fixes_by_record_sha:
            errors.append("duplicate fix record_sha256")
            continue
        fixes_by_record_sha[fix["record_sha256"]] = fix
        fixes_by_finding.setdefault(finding_id, []).append(fix)
        fix_finding = findings_by_id.get(finding_id)
        fix_snapshot = snapshot_by_sha.get(fix["post_fix_snapshot_sha256"])
        if fix_finding is None or fix["finding_record_sha256"] != fix_finding["record_sha256"]:
            errors.append(f"fix for finding {finding_id} lost finding hash chain")
        if fix_snapshot is None or fix_snapshot["purpose"] != "post_fix":
            errors.append(f"fix for finding {finding_id} lacks post_fix snapshot")

    verifications_by_fix_sha: dict[str, list[dict[str, Any]]] = {}
    verifications_by_record_sha: dict[str, dict[str, Any]] = {}
    for verification in verifications:
        finding_id = verification["finding_id"]
        record_sha = verification["record_sha256"]
        if record_sha in verifications_by_record_sha:
            errors.append("duplicate review_verification record_sha256")
            continue
        verifications_by_record_sha[record_sha] = verification
        verification_fix = fixes_by_record_sha.get(verification["fix_record_sha256"])
        verification_snapshot = snapshot_by_sha.get(verification["snapshot_sha256"])
        if verification_fix is None or finding_id != verification_fix["finding_id"]:
            errors.append(f"review verification for finding {finding_id} lost fix hash chain")
        else:
            verifications_by_fix_sha.setdefault(verification_fix["record_sha256"], []).append(verification)
            if verification["snapshot_sha256"] != verification_fix["post_fix_snapshot_sha256"]:
                errors.append(
                    f"review verification for finding {finding_id} lost post_fix snapshot binding"
                )
            producers = set(verification_fix["producer_agent_ids"])
            if verification_snapshot is not None:
                producers.update(verification_snapshot["producer_agent_ids"])
            if verification["reviewer_agent_id"] in producers:
                errors.append(f"review verification for finding {finding_id} is self-review")
        if snapshot is None or snapshot["purpose"] != "post_fix":
            errors.append(f"review verification for finding {finding_id} lacks post_fix snapshot")
    if complete_required:
        for finding_id in findings_by_id:
            attempts = fixes_by_finding.get(finding_id, [])
            if not attempts:
                errors.append(f"finding {finding_id} lacks fix")
                continue
            latest_fix = attempts[-1]
            latest_verifications = verifications_by_fix_sha.get(
                latest_fix["record_sha256"], []
            )
            if not latest_verifications:
                errors.append(
                    f"finding {finding_id} latest fix lacks independent review verification"
                )
            elif latest_verifications[-1]["outcome"] != "pass":
                errors.append(
                    f"finding {finding_id} latest fix is not resolved by a passing verification"
                )

    if seal is not None:
        candidates = [record for record in snapshots if record["purpose"] == "candidate"]
        if not candidates:
            errors.append("seal requires a candidate snapshot")
        else:
            latest_candidate = candidates[-1]
            latest_review = reviews_by_snapshot.get(latest_candidate["snapshot_sha256"])
            if seal["latest_candidate_snapshot_sha256"] != latest_candidate["snapshot_sha256"]:
                errors.append("seal does not bind latest candidate snapshot")
            if latest_review is None or seal["latest_review_result_record_sha256"] != latest_review["record_sha256"]:
                errors.append("seal does not bind latest candidate review result")
            if seal["claim_scope_sha256"] != latest_candidate["claim_scope_sha256"]:
                errors.append("seal does not bind latest candidate claim scope")
    return sorted(set(errors))


def validate_integrity_contract(
    contract: Any,
    *,
    task_id: Any | None = None,
    worktree: Any | None = None,
    require_complete: bool = False,
) -> dict[str, Any]:
    """Validate and return a deep copy of one persisted contract."""

    errors = integrity_contract_errors(
        contract,
        task_id=task_id,
        worktree=worktree,
        require_complete=require_complete,
    )
    if errors:
        raise IntegrityRecordError(errors)
    return copy.deepcopy(dict(contract))


__all__ = [
    "INTEGRITY_CONTRACT_MODE",
    "INTEGRITY_CONTRACT_SCHEMA_VERSION",
    "MAX_INTEGRITY_ARTIFACT_BYTES",
    "MAX_INTEGRITY_RECORDS",
    "IntegrityRecordError",
    "adopt_integrity_contract",
    "append_finding",
    "append_fix",
    "append_integrity_record",
    "append_review_result",
    "append_review_verification",
    "append_snapshot",
    "build_artifact_ref",
    "build_finding_record",
    "build_fix_record",
    "build_integrity_contract",
    "build_integrity_seal",
    "build_review_result_record",
    "build_review_verification_record",
    "build_snapshot_record",
    "integrity_contract_errors",
    "integrity_record_sha256",
    "seal_integrity_contract",
    "validate_integrity_contract",
]
