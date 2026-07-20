"""Ordered, content-addressed integrity records (required_v2).

This is deliberately a pure data-contract module.  Runtime artifact lookup is
owned by the persistence layer; this module only validates what was persisted.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any

from .agent_identity import AgentIdentityError, validate_agent_id as _shared_agent_id
from . import integrity_records as _v1

INTEGRITY_CONTRACT_SCHEMA_VERSION = 2
INTEGRITY_CONTRACT_MODE = "required_v2"
MAX_INTEGRITY_RECORD_BYTES = 64 * 1024
MAX_INTEGRITY_RECORD_LIST_ENTRIES = 1024
# A valid v1 prefix can contain five independently capped collections.  The
# exact graph maximum is one fewer than 5 * 1024: any non-empty fixes/
# verifications collection needs a post_fix snapshot, leaving at most 1023
# candidate snapshots/reviews.  Keep at least a full 1024-record native tail
# after it.
MAX_V1_MIGRATED_RECORDS = (5 * MAX_INTEGRITY_RECORD_LIST_ENTRIES) - 1
MAX_INTEGRITY_RECORDS = 6 * MAX_INTEGRITY_RECORD_LIST_ENTRIES
MAX_INTEGRITY_ARTIFACT_BYTES = 64 * 1024 * 1024
# This mirrors the v1 managed task-state load bound.  Keep it local and
# literal: this pure records module must not import the persistence layer.
# MAX_INTEGRITY_RECORDS remains only a logical graph-count cap, not a promise
# that an arbitrarily large source state is loadable.
MAX_INTEGRITY_MIGRATION_SOURCE_BYTES = 16 * 1024 * 1024
# Mapping adds fixed v2 provenance/sequence fields to each managed v1 record.
# It is therefore bounded by the source plus this compact semantic allowance,
# never by the obsolete 384 MiB theoretical inline-prefix maximum.
MAX_INTEGRITY_MIGRATION_EFFECTIVE_PREFIX_BYTES = MAX_INTEGRITY_MIGRATION_SOURCE_BYTES + 1024 * 1024
MAX_INTEGRITY_MIGRATION_SEMANTIC_DELTA_BYTES = 1024 * 1024
# Compatibility name for integration code that consumed the prior constant.
MAX_INTEGRITY_MIGRATION_AGGREGATE_BYTES = MAX_INTEGRITY_MIGRATION_SOURCE_BYTES
MAX_INTEGRITY_TEXT_BYTES = 4096

_SHA = re.compile(r"[0-9a-f]{64}")
_HEAD = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_COMMON = frozenset({"record_type", "integrity_seq", "source_v1_record_sha256", "record_sha256"})
_CONTRACT = frozenset({"schema_version", "mode", "adopted_at", "baseline_head", "migration_receipt", "records", "seal"})
_ARTIFACT = frozenset({"path", "sha256", "size_bytes"})


class IntegrityRecordError(ValueError):
    def __init__(self, errors: str | Iterable[str]) -> None:
        self.errors = (errors,) if isinstance(errors, str) else tuple(str(x) for x in errors)
        super().__init__("integrity contract v2 failed: " + "; ".join(self.errors))


def _canonical(value: Any) -> bytes:
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IntegrityRecordError("record is not canonical JSON") from exc
    if len(result) > MAX_INTEGRITY_RECORD_BYTES:
        raise IntegrityRecordError("record exceeds compact byte bound")
    return result


def integrity_record_sha256(record: Mapping[str, Any]) -> str:
    if not isinstance(record, Mapping):
        raise IntegrityRecordError("record is not an object")
    return hashlib.sha256(_canonical({k: v for k, v in record.items() if k != "record_sha256"})).hexdigest()


def _records_sha256(records: list[dict[str, Any]]) -> str:
    try:
        encoded = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IntegrityRecordError("migrated records are not canonical JSON") from exc
    if len(encoded) > MAX_INTEGRITY_MIGRATION_EFFECTIVE_PREFIX_BYTES:
        raise IntegrityRecordError("migrated records exceed aggregate byte bound")
    return hashlib.sha256(encoded).hexdigest()


def _integer(value: Any, label: str, *, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise IntegrityRecordError(f"{label} must be an integer >= {minimum}")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\0" in value or len(value.encode()) > MAX_INTEGRITY_TEXT_BYTES:
        raise IntegrityRecordError(f"{label} must be non-empty exact text")
    if pattern is not None and not pattern.fullmatch(value):
        raise IntegrityRecordError(f"{label} has invalid syntax")
    return value


def _sha(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise IntegrityRecordError(f"{label} must be a lowercase SHA-256")
    return value


def _head(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEAD.fullmatch(value):
        raise IntegrityRecordError(f"{label} must be a full 40-64 lowercase Git head")
    return value


def _time(value: Any, label: str) -> str:
    value = _text(value, label)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntegrityRecordError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IntegrityRecordError(f"{label} requires an explicit timezone")
    return value


def validate_agent_id(value: Any, label: str = "agent id") -> str:
    try:
        return _shared_agent_id(value, label)
    except AgentIdentityError as exc:
        raise IntegrityRecordError(str(exc)) from exc


def _many(value: Iterable[Any], label: str, pattern: re.Pattern[str], *, nonempty: bool = False) -> list[str]:
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise IntegrityRecordError(f"{label} must be an array")
    try:
        result = [_text(x, label, pattern) for x in value]
    except TypeError as exc:
        raise IntegrityRecordError(f"{label} must be an array") from exc
    if len(result) > MAX_INTEGRITY_RECORD_LIST_ENTRIES or result != sorted(set(result)) or (nonempty and not result):
        raise IntegrityRecordError(f"{label} must be bounded, sorted, unique" + (", and non-empty" if nonempty else ""))
    return result


def _agents(value: Iterable[Any], label: str, *, nonempty: bool = True) -> list[str]:
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise IntegrityRecordError(f"{label} must be an array")
    try:
        result = [validate_agent_id(x, label) for x in value]
    except TypeError as exc:
        raise IntegrityRecordError(f"{label} must be an array") from exc
    if len(result) > MAX_INTEGRITY_RECORD_LIST_ENTRIES or result != sorted(set(result)) or (nonempty and not result):
        raise IntegrityRecordError(f"{label} must be bounded, sorted, unique" + (", and non-empty" if nonempty else ""))
    return result


def _artifact(value: Mapping[str, Any], label: str, *, max_size_bytes: int = MAX_INTEGRITY_ARTIFACT_BYTES) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ARTIFACT:
        raise IntegrityRecordError(f"{label} schema is invalid")
    path = _text(value.get("path"), f"{label}.path")
    if PurePath(path).is_absolute() or PureWindowsPath(path).is_absolute() or path.startswith("/") or "\\" in path or any(x in {"", ".", ".."} for x in path.split("/")):
        raise IntegrityRecordError(f"{label}.path must be a normalized POSIX relative path")
    size = value.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= max_size_bytes:
        raise IntegrityRecordError(f"{label}.size_bytes is invalid")
    return {"path": path, "sha256": _sha(value.get("sha256"), label), "size_bytes": size}


def build_artifact_ref(*, path: Any, sha256: Any, size_bytes: Any) -> dict[str, Any]:
    return _artifact({"path": path, "sha256": sha256, "size_bytes": size_bytes}, "artifact")


def build_migration_source_contract_artifact_ref(*, path: Any, sha256: Any, size_bytes: Any) -> dict[str, Any]:
    """Build the bounded receipt artifact reference for a v1 source contract."""

    return _artifact(
        {"path": path, "sha256": sha256, "size_bytes": size_bytes},
        "migration source contract artifact",
        max_size_bytes=MAX_INTEGRITY_MIGRATION_AGGREGATE_BYTES,
    )


def _common(record_type: str, integrity_seq: Any, source_v1_record_sha256: Any) -> dict[str, Any]:
    # Builders intentionally permit None; append assigns the deterministic next seq.
    return {"record_type": record_type, "integrity_seq": integrity_seq, "source_v1_record_sha256": _sha(source_v1_record_sha256, f"{record_type}.source_v1_record_sha256", nullable=True)}


def _seal(record: dict[str, Any]) -> dict[str, Any]:
    if record["integrity_seq"] is not None:
        _integer(record["integrity_seq"], f"{record['record_type']}.integrity_seq")
    record["record_sha256"] = integrity_record_sha256(record)
    return record


def build_snapshot_record(*, task_id: Any, worktree: Any, baseline_head: Any, current_head: Any, artifact: Mapping[str, Any], snapshot_sha256: Any, claim_scope_sha256: Any, covered_claim_tokens: Iterable[Any], purpose: Any, producer_agent_ids: Iterable[Any], integrity_seq: Any | None = None, attempt_id: Any | None = None, source_v1_record_sha256: Any = None) -> dict[str, Any]:
    path = _text(worktree, "snapshot.worktree")
    if not (PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute()):
        raise IntegrityRecordError("snapshot.worktree must be an absolute path")
    if purpose not in {"candidate", "post_fix", "close"}:
        raise IntegrityRecordError("snapshot.purpose is invalid")
    if attempt_id is not None:
        _integer(attempt_id, "snapshot.attempt_id")
    record = _common("snapshot", integrity_seq, source_v1_record_sha256)
    record.update({"attempt_id": attempt_id, "task_id": _text(task_id, "snapshot.task_id", _TOKEN), "worktree": path, "baseline_head": _head(baseline_head, "snapshot.baseline_head"), "current_head": _head(current_head, "snapshot.current_head"), "artifact": _artifact(artifact, "snapshot.artifact"), "snapshot_sha256": _sha(snapshot_sha256, "snapshot.snapshot_sha256"), "claim_scope_sha256": _sha(claim_scope_sha256, "snapshot.claim_scope_sha256"), "covered_claim_tokens": _many(covered_claim_tokens, "snapshot.covered_claim_tokens", _TOKEN), "purpose": purpose, "producer_agent_ids": _agents(producer_agent_ids, "snapshot.producer_agent_ids")})
    return _seal(record)


def build_review_result_record(*, snapshot_record_sha256: Any, reviewer_agent_id: Any, producer_agent_ids: Iterable[Any], result_artifact: Mapping[str, Any], outcome: Any, finding_ids: Iterable[Any], basis_review_verification_record_sha256s: Iterable[Any] = (), integrity_seq: Any | None = None, source_v1_record_sha256: Any = None) -> dict[str, Any]:
    findings = _many(finding_ids, "review_result.finding_ids", _TOKEN)
    if outcome not in {"clean", "findings"} or (outcome == "clean") != (not findings):
        raise IntegrityRecordError("review_result outcome conflicts with finding_ids")
    producers = _agents(producer_agent_ids, "review_result.producer_agent_ids")
    reviewer = validate_agent_id(reviewer_agent_id, "review_result.reviewer_agent_id")
    if reviewer in producers:
        raise IntegrityRecordError("review_result is self-review")
    record = _common("review_result", integrity_seq, source_v1_record_sha256)
    record.update({"snapshot_record_sha256": _sha(snapshot_record_sha256, "review_result.snapshot_record_sha256"), "reviewer_agent_id": reviewer, "producer_agent_ids": producers, "result_artifact": _artifact(result_artifact, "review_result.result_artifact"), "outcome": outcome, "finding_ids": findings, "basis_review_verification_record_sha256s": _many(basis_review_verification_record_sha256s, "review_result.basis_review_verification_record_sha256s", _SHA)})
    return _seal(record)


def build_finding_record(*, finding_id: Any, review_result_record_sha256: Any, snapshot_record_sha256: Any, reviewer_agent_id: Any, finding_artifact_sha256: Any, integrity_seq: Any | None = None, source_v1_record_sha256: Any = None) -> dict[str, Any]:
    record = _common("finding", integrity_seq, source_v1_record_sha256)
    record.update({"finding_id": _text(finding_id, "finding.finding_id", _TOKEN), "review_result_record_sha256": _sha(review_result_record_sha256, "finding.review_result_record_sha256"), "snapshot_record_sha256": _sha(snapshot_record_sha256, "finding.snapshot_record_sha256"), "reviewer_agent_id": validate_agent_id(reviewer_agent_id, "finding.reviewer_agent_id"), "finding_artifact_sha256": _sha(finding_artifact_sha256, "finding.finding_artifact_sha256")})
    return _seal(record)


def build_fix_record(*, finding_id: Any, finding_record_sha256: Any, post_fix_snapshot_record_sha256: Any, fix_artifact: Mapping[str, Any], producer_agent_ids: Iterable[Any], integrity_seq: Any | None = None, source_v1_record_sha256: Any = None) -> dict[str, Any]:
    record = _common("fix", integrity_seq, source_v1_record_sha256)
    record.update({"finding_id": _text(finding_id, "fix.finding_id", _TOKEN), "finding_record_sha256": _sha(finding_record_sha256, "fix.finding_record_sha256"), "post_fix_snapshot_record_sha256": _sha(post_fix_snapshot_record_sha256, "fix.post_fix_snapshot_record_sha256"), "fix_artifact": _artifact(fix_artifact, "fix.fix_artifact"), "producer_agent_ids": _agents(producer_agent_ids, "fix.producer_agent_ids")})
    return _seal(record)


def build_review_verification_record(*, finding_id: Any, fix_record_sha256: Any, verification_snapshot_record_sha256: Any, reviewer_agent_id: Any, verification_artifact: Mapping[str, Any], outcome: Any, integrity_seq: Any | None = None, source_v1_record_sha256: Any = None) -> dict[str, Any]:
    if outcome not in {"pass", "fail"}:
        raise IntegrityRecordError("review_verification.outcome is invalid")
    record = _common("review_verification", integrity_seq, source_v1_record_sha256)
    record.update({"finding_id": _text(finding_id, "review_verification.finding_id", _TOKEN), "fix_record_sha256": _sha(fix_record_sha256, "review_verification.fix_record_sha256"), "verification_snapshot_record_sha256": _sha(verification_snapshot_record_sha256, "review_verification.verification_snapshot_record_sha256"), "reviewer_agent_id": validate_agent_id(reviewer_agent_id, "review_verification.reviewer_agent_id"), "verification_artifact": _artifact(verification_artifact, "review_verification.verification_artifact"), "outcome": outcome})
    return _seal(record)


def build_integrity_seal(*, terminal_snapshot_record_sha256: Any, terminal_review_result_record_sha256: Any, claim_scope_sha256: Any, sealed_at: Any, integrity_seq: Any, source_v1_record_sha256: Any = None) -> dict[str, Any]:
    record = _common("seal", integrity_seq, source_v1_record_sha256)
    record.update({"terminal_snapshot_record_sha256": _sha(terminal_snapshot_record_sha256, "seal.terminal_snapshot_record_sha256"), "terminal_review_result_record_sha256": _sha(terminal_review_result_record_sha256, "seal.terminal_review_result_record_sha256"), "claim_scope_sha256": _sha(claim_scope_sha256, "seal.claim_scope_sha256"), "sealed_at": _time(sealed_at, "seal.sealed_at")})
    return _seal(record)


def build_integrity_contract(*, baseline_head: Any, adopted_at: Any) -> dict[str, Any]:
    return {"schema_version": 2, "mode": "required_v2", "adopted_at": _time(adopted_at, "integrity_contract.adopted_at"), "baseline_head": _head(baseline_head, "integrity_contract.baseline_head"), "migration_receipt": None, "records": [], "seal": None}


def next_integrity_sequence(contract: Mapping[str, Any]) -> int:
    records = contract.get("records") if isinstance(contract, Mapping) else None
    if not isinstance(records, list):
        raise IntegrityRecordError("integrity_contract.records must be an array")
    receipt = contract.get("migration_receipt") if isinstance(contract, Mapping) else None
    if isinstance(receipt, Mapping) and receipt.get("prefix_storage") == "source_v1_cas_v1":
        return _integer(receipt.get("migrated_record_count"), "migration_receipt.migrated_record_count", minimum=0) + len(records) + 1
    return len(records) + 1


def next_snapshot_attempt_id(contract: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> int:
    records = contract.get("records") if isinstance(contract, Mapping) else None
    if not isinstance(records, list):
        raise IntegrityRecordError("integrity_contract.records must be an array")
    if integrity_contract_source_required(contract):
        if source_v1_contract is None:
            raise IntegrityRecordError("migration source contract is required to allocate a native snapshot attempt")
        records = materialize_effective_integrity_records(contract, source_v1_contract)
    return sum(isinstance(r, Mapping) and r.get("record_type") == "snapshot" for r in records) + 1


def _reseal(record: Mapping[str, Any], *, seq: int, attempt: int | None = None) -> dict[str, Any]:
    result = copy.deepcopy(dict(record)); result["integrity_seq"] = seq
    if attempt is not None: result["attempt_id"] = attempt
    result["record_sha256"] = integrity_record_sha256(result)
    return result


def append_integrity_record(contract: Mapping[str, Any], *args: Any, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Append one record to the ordered log; accepts legacy collection arg too."""
    record = args[-1] if len(args) in {1, 2} else None
    if not isinstance(contract, Mapping) or not isinstance(record, Mapping):
        raise IntegrityRecordError("integrity contract and record must be objects")
    if len(args) == 2 and args[0] not in {"records", "snapshots", "review_results", "findings", "fixes", "review_verifications"}:
        raise IntegrityRecordError("integrity record collection is invalid")
    return append_integrity_records(contract, [record], source_v1_contract=source_v1_contract)


def append_integrity_records(contract: Mapping[str, Any], records_to_append: Iterable[Mapping[str, Any]], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Append a validated tail as one in-memory transaction.

    A review that declares findings is only a valid graph together with every
    matching finding record.  Build the whole tail before validating/publishing
    it so callers never have to expose that invalid intermediate form.
    """
    if not isinstance(contract, Mapping):
        raise IntegrityRecordError("integrity contract must be an object")
    if isinstance(records_to_append, (str, bytes, bytearray, Mapping)):
        raise IntegrityRecordError("integrity records to append must be an array")
    try:
        pending = list(records_to_append)
    except TypeError as exc:
        raise IntegrityRecordError("integrity records to append must be an array") from exc
    result = copy.deepcopy(dict(contract))
    if result.get("seal") is not None: raise IntegrityRecordError("sealed integrity contract is immutable")
    tail = result.get("records")
    if not isinstance(tail, list) or len(tail) + len(pending) > MAX_INTEGRITY_RECORDS: raise IntegrityRecordError("integrity_contract.records is invalid or full")
    compact = integrity_contract_source_required(result)
    if compact and source_v1_contract is None:
        raise IntegrityRecordError("migration source contract is required to append a native record")
    for record in pending:
        if not isinstance(record, Mapping):
            raise IntegrityRecordError("appended record is not an object")
        if record.get("record_type") == "seal":
            raise IntegrityRecordError("seal must be assigned only to integrity_contract.seal")
        item = _reseal(record, seq=next_integrity_sequence(result), attempt=next_snapshot_attempt_id(result, source_v1_contract=source_v1_contract) if record.get("record_type") == "snapshot" else None)
        if compact and item.get("source_v1_record_sha256") is not None:
            raise IntegrityRecordError("native migration tail may not contain source_v1_record_sha256")
        _validate_record(item, "appended record")
        tail.append(item)
    if compact:
        validate_integrity_contract(result, source_v1_contract=source_v1_contract)
    return result


def append_snapshot(contract: Mapping[str, Any], record: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]: return append_integrity_record(contract, record, source_v1_contract=source_v1_contract)
def append_review_result(contract: Mapping[str, Any], record: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]: return append_integrity_record(contract, record, source_v1_contract=source_v1_contract)
def append_finding(contract: Mapping[str, Any], record: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]: return append_integrity_record(contract, record, source_v1_contract=source_v1_contract)
def append_fix(contract: Mapping[str, Any], record: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]: return append_integrity_record(contract, record, source_v1_contract=source_v1_contract)
def append_review_verification(contract: Mapping[str, Any], record: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]: return append_integrity_record(contract, record, source_v1_contract=source_v1_contract)


_FIELDS = {
 "snapshot": _COMMON | {"attempt_id","task_id","worktree","baseline_head","current_head","artifact","snapshot_sha256","claim_scope_sha256","covered_claim_tokens","purpose","producer_agent_ids"},
 "review_result": _COMMON | {"snapshot_record_sha256","reviewer_agent_id","producer_agent_ids","result_artifact","outcome","finding_ids","basis_review_verification_record_sha256s"},
 "finding": _COMMON | {"finding_id","review_result_record_sha256","snapshot_record_sha256","reviewer_agent_id","finding_artifact_sha256"},
 "fix": _COMMON | {"finding_id","finding_record_sha256","post_fix_snapshot_record_sha256","fix_artifact","producer_agent_ids"},
 "review_verification": _COMMON | {"finding_id","fix_record_sha256","verification_snapshot_record_sha256","reviewer_agent_id","verification_artifact","outcome"},
 "seal": _COMMON | {"terminal_snapshot_record_sha256","terminal_review_result_record_sha256","claim_scope_sha256","sealed_at"},
}


def _validate_record(record: dict[str, Any], label: str) -> None:
    typ = record.get("record_type")
    if typ not in _FIELDS or set(record) != _FIELDS[typ]: raise IntegrityRecordError(f"{label} schema is invalid")
    if record.get("record_sha256") != integrity_record_sha256(record): raise IntegrityRecordError(f"{label} record_sha256 is invalid")
    if record.get("integrity_seq") is None: raise IntegrityRecordError(f"{label}.integrity_seq is required")
    try:
        kw = {k: v for k, v in record.items() if k not in {"record_type", "record_sha256"}}
        builders: dict[str, Callable[..., dict[str, Any]]] = {"snapshot": build_snapshot_record, "review_result": build_review_result_record, "finding": build_finding_record, "fix": build_fix_record, "review_verification": build_review_verification_record, "seal": build_integrity_seal}
        if builders[typ](**kw) != record: raise IntegrityRecordError(f"{label} is not canonical")
    except (KeyError, IntegrityRecordError) as exc:
        if isinstance(exc, IntegrityRecordError): raise IntegrityRecordError(f"{label} values are invalid: {exc}") from exc
        raise IntegrityRecordError(f"{label} values are invalid") from exc


def review_basis_review_verification_record_sha256s(contract: Mapping[str, Any], *, before_integrity_seq: int | None = None, snapshot_record_sha256: str | None = None) -> list[str]:
    """Return the exact authoritative passing-verification basis at a frontier."""
    records = contract.get("records", []) if isinstance(contract, Mapping) else []
    cutoff = before_integrity_seq if before_integrity_seq is not None else len(records) + 1
    findings: dict[str, dict[str, Any]] = {}; fixes: dict[str, dict[str, Any]] = {}; verifications: dict[str, dict[str, Any]] = {}
    for r in records:
        if not isinstance(r, Mapping) or r.get("integrity_seq", cutoff) >= cutoff: continue
        if r.get("record_type") == "finding": findings[r["finding_id"]] = dict(r)
        elif r.get("record_type") == "fix": fixes[r["finding_id"]] = dict(r)
        elif r.get("record_type") == "review_verification": verifications[r["fix_record_sha256"]] = dict(r)
    basis: list[str] = []
    for finding_id in sorted(findings):
        fix = fixes.get(finding_id); verification = verifications.get(fix["record_sha256"]) if fix else None
        if verification and verification.get("outcome") == "pass" and (snapshot_record_sha256 is None or verification.get("verification_snapshot_record_sha256") == snapshot_record_sha256): basis.append(verification["record_sha256"])
    return sorted(basis)


def _integrity_contract_errors(contract: Any, *, task_id: Any | None = None, worktree: Any | None = None, require_complete: bool = False, source_v1_contract: Mapping[str, Any] | None = None, materialized_records: list[dict[str, Any]] | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(contract, Mapping) or set(contract) != _CONTRACT: return ["integrity_contract schema is invalid"]
    if contract.get("schema_version") != 2: errors.append("integrity_contract schema_version is invalid")
    if contract.get("mode") != "required_v2": errors.append("integrity_contract mode is invalid")
    try: _time(contract.get("adopted_at"), "integrity_contract.adopted_at"); base = _head(contract.get("baseline_head"), "integrity_contract.baseline_head")
    except IntegrityRecordError as exc: errors.extend(exc.errors); base = None
    raw = materialized_records if materialized_records is not None else contract.get("records"); records: list[dict[str, Any]] = []
    if not isinstance(raw, list) or len(raw) > MAX_INTEGRITY_RECORDS: return sorted(set(errors + ["integrity_contract.records must be a bounded array"]))
    if integrity_contract_source_required(contract) and materialized_records is None:
        return sorted(set(errors + _compact_integrity_contract_errors(
            contract, task_id=task_id, worktree=worktree, require_complete=require_complete,
            source_v1_contract=source_v1_contract,
        )))
    for i, item in enumerate(raw, 1):
        if not isinstance(item, Mapping): errors.append(f"records record {i} is not an object"); continue
        r = dict(item)
        try: _validate_record(r, f"records record {i}")
        except IntegrityRecordError as exc: errors.extend(exc.errors); continue
        if r["integrity_seq"] != i: errors.append("records integrity_seq must be exact 1..N")
        records.append(r)
    by_sha = {r["record_sha256"]: r for r in records}
    if len(by_sha) != len(records): errors.append("duplicate record_sha256")
    snapshots = [r for r in records if r["record_type"] == "snapshot"]
    reviews = [r for r in records if r["record_type"] == "review_result"]
    findings = [r for r in records if r["record_type"] == "finding"]
    fixes = [r for r in records if r["record_type"] == "fix"]
    verifications = [r for r in records if r["record_type"] == "review_verification"]
    snaps = {r["record_sha256"]: r for r in snapshots}; review_by_sha = {r["record_sha256"]: r for r in reviews}; finding_by_id: dict[str, dict[str, Any]] = {}
    for index, s in enumerate(snapshots, 1):
        if s["attempt_id"] != index: errors.append("snapshot attempt_id must be sequential")
        if base and s["baseline_head"] != base: errors.append("snapshot baseline_head differs from integrity contract")
        if task_id is not None and s["task_id"] != task_id: errors.append("snapshot task_id differs from task state")
        if worktree not in (None, "") and s["worktree"] != worktree: errors.append("snapshot worktree differs from task state")
    review_by_attempt: set[int] = set()
    for r in reviews:
        source_snapshot = snaps.get(r["snapshot_record_sha256"])
        if not source_snapshot or source_snapshot["integrity_seq"] >= r["integrity_seq"]: errors.append("review_result must follow its snapshot") ; continue
        if source_snapshot["attempt_id"] in review_by_attempt: errors.append("snapshot attempt has multiple review results")
        review_by_attempt.add(source_snapshot["attempt_id"])
        prior = [x for x in snapshots if x["integrity_seq"] < r["integrity_seq"]]
        if r["source_v1_record_sha256"] is None and prior and source_snapshot["record_sha256"] != prior[-1]["record_sha256"]: errors.append("review_result only reviews the frontier snapshot")
        if r["producer_agent_ids"] != source_snapshot["producer_agent_ids"] or r["reviewer_agent_id"] in source_snapshot["producer_agent_ids"]: errors.append("review_result producer identities/self-review are invalid")
        if r["source_v1_record_sha256"] is None:
            expected_basis = review_basis_review_verification_record_sha256s(contract, before_integrity_seq=r["integrity_seq"], snapshot_record_sha256=r["snapshot_record_sha256"])
            if r["basis_review_verification_record_sha256s"] != expected_basis: errors.append("review_result basis is not exact")
            for prior_finding in (f for f in findings if f["integrity_seq"] < r["integrity_seq"]):
                prior_fixes = [x for x in fixes if x["finding_id"] == prior_finding["finding_id"] and x["integrity_seq"] < r["integrity_seq"]]
                current_fix = prior_fixes[-1] if prior_fixes else None
                prior_verifications = [x for x in verifications if current_fix and x["fix_record_sha256"] == current_fix["record_sha256"] and x["integrity_seq"] < r["integrity_seq"]]
                current_verification = prior_verifications[-1] if prior_verifications else None
                if not current_verification or current_verification["outcome"] != "pass" or current_verification["verification_snapshot_record_sha256"] != r["snapshot_record_sha256"]:
                    errors.append(f"review_result lacks exact passing basis for finding {prior_finding['finding_id']}")
        if r["source_v1_record_sha256"] is None and r["outcome"] == "clean" and r["integrity_seq"] != len(records):
            errors.append("clean review_result must be the final graph record")
    for f in findings:
        if f["finding_id"] in finding_by_id: errors.append(f"duplicate finding_id {f['finding_id']}"); continue
        finding_by_id[f["finding_id"]] = f; review = review_by_sha.get(f["review_result_record_sha256"])
        if not review or review["integrity_seq"] >= f["integrity_seq"] or f["snapshot_record_sha256"] != (review or {}).get("snapshot_record_sha256") or f["reviewer_agent_id"] != (review or {}).get("reviewer_agent_id") or f["finding_artifact_sha256"] != (review or {}).get("result_artifact", {}).get("sha256") or f["finding_id"] not in (review or {}).get("finding_ids", []): errors.append(f"finding {f['finding_id']} lost review binding")
    for r in reviews:
        actual = sorted(f["finding_id"] for f in findings if f["review_result_record_sha256"] == r["record_sha256"])
        if actual != r["finding_ids"]: errors.append("review_result finding_ids differ from finding records")
    latest_fix: dict[str, dict[str, Any]] = {}
    for f in fixes:
        finding = finding_by_id.get(f["finding_id"]); snap = snaps.get(f["post_fix_snapshot_record_sha256"])
        if not finding or f["finding_record_sha256"] != finding["record_sha256"] or not snap or snap["purpose"] != "post_fix" or f["integrity_seq"] <= snap["integrity_seq"] or (f["source_v1_record_sha256"] is None and snap["integrity_seq"] <= finding["integrity_seq"]): errors.append(f"fix for finding {f['finding_id']} has invalid order/binding")
        prior = [x for x in snapshots if x["integrity_seq"] < f["integrity_seq"]]
        if f["source_v1_record_sha256"] is None and prior and snap and snap["record_sha256"] != prior[-1]["record_sha256"]:
            errors.append(f"fix for finding {f['finding_id']} only targets the frontier snapshot")
        old = latest_fix.get(f["finding_id"])
        # v1 allowed repeated or decreasing post-fix targets; retain that
        # historical order exactly.  Any native fix must still advance from
        # the current latest attempt, including a migrated latest fix.
        if f["source_v1_record_sha256"] is None and old and snap and snaps.get(old["post_fix_snapshot_record_sha256"], {}).get("attempt_id", 0) >= snap["attempt_id"]: errors.append(f"finding {f['finding_id']} fix target attempts must strictly increase")
        latest_fix[f["finding_id"]] = f
    latest_verification: dict[str, dict[str, Any]] = {}
    for v in verifications:
        fix = by_sha.get(v["fix_record_sha256"]); snap = snaps.get(v["verification_snapshot_record_sha256"])
        if not fix or fix.get("record_type") != "fix" or v["finding_id"] != fix["finding_id"] or not snap or v["integrity_seq"] <= fix["integrity_seq"] or v["integrity_seq"] <= snap["integrity_seq"]: errors.append(f"review verification for finding {v['finding_id']} has invalid order/binding"); continue
        prior = [x for x in snapshots if x["integrity_seq"] < v["integrity_seq"]]
        if v["source_v1_record_sha256"] is None and prior and snap["record_sha256"] != prior[-1]["record_sha256"]:
            errors.append(f"review verification for finding {v['finding_id']} only targets the frontier snapshot")
        target = snaps.get(fix["post_fix_snapshot_record_sha256"])
        if not target or snap["attempt_id"] < target["attempt_id"]: errors.append(f"review verification for finding {v['finding_id']} targets stale attempt")
        if v["reviewer_agent_id"] in set(fix["producer_agent_ids"]) | set(snap["producer_agent_ids"]): errors.append(f"review verification for finding {v['finding_id']} is self-review")
        latest_verification[fix["record_sha256"]] = v
    receipt = contract.get("migration_receipt")
    prefix = 0
    if receipt is not None:
        try:
            _validate_receipt(receipt); prefix = receipt["migrated_record_count"]
            if task_id is not None and receipt["source_task_id"] != task_id:
                errors.append("migration receipt source_task_id differs from task state")
            if worktree not in (None, "") and receipt["source_worktree"] != worktree:
                errors.append("migration receipt source_worktree differs from task state")
            if base is not None and receipt["source_baseline_head"] != base:
                errors.append("migration receipt source_baseline_head differs from integrity contract")
            if prefix > len(records) or _records_sha256(records[:prefix]) != receipt["migrated_records_sha256"]: errors.append("migration receipt migrated prefix digest/count is invalid")
            elif any(r["source_v1_record_sha256"] is None for r in records[:prefix]) or any(r["source_v1_record_sha256"] is not None for r in records[prefix:]): errors.append("migration receipt source markers are invalid")
            else:
                prefix_snapshots = [r for r in records[:prefix] if r["record_type"] == "snapshot"]
                expected_anchor = prefix_snapshots[-1]["record_sha256"] if prefix_snapshots else None
                if receipt["anchor_snapshot_record_sha256"] != expected_anchor:
                    errors.append("migration receipt anchor snapshot is invalid")
        except IntegrityRecordError as exc: errors.extend(exc.errors)
    elif any(r["source_v1_record_sha256"] is not None for r in records): errors.append("native contract may not contain source_v1_record_sha256")
    seal = contract.get("seal")
    if seal is not None:
        if not isinstance(seal, Mapping): errors.append("integrity_contract.seal is not an object")
        else:
            try: _validate_record(dict(seal), "integrity_contract.seal")
            except IntegrityRecordError as exc: errors.extend(exc.errors)
            else:
                if seal["integrity_seq"] != len(records)+1: errors.append("seal integrity_seq must be N+1")
                if not snapshots or seal["terminal_snapshot_record_sha256"] != snapshots[-1]["record_sha256"]: errors.append("seal does not bind terminal snapshot")
                terminal = by_sha.get(seal["terminal_review_result_record_sha256"])
                if not terminal or terminal.get("record_type") != "review_result" or terminal["integrity_seq"] != len(records): errors.append("seal terminal review must be final graph record")
                elif terminal["outcome"] != "clean" or terminal["snapshot_record_sha256"] != seal["terminal_snapshot_record_sha256"] or terminal["source_v1_record_sha256"] is not None: errors.append("seal requires native clean terminal review")
                if snapshots and seal["claim_scope_sha256"] != snapshots[-1]["claim_scope_sha256"]: errors.append("seal does not bind terminal claim scope")
                for fid, f in finding_by_id.items():
                    fix = latest_fix.get(fid); verify = latest_verification.get(fix["record_sha256"]) if fix else None
                    if not fix or not verify or verify["outcome"] != "pass" or verify["verification_snapshot_record_sha256"] != seal["terminal_snapshot_record_sha256"]: errors.append(f"finding {fid} lacks exact terminal passing verification")
    if require_complete and seal is None: errors.append("complete integrity contract requires a seal")
    return sorted(set(errors))


def integrity_contract_errors(contract: Any, *, task_id: Any | None = None, worktree: Any | None = None, require_complete: bool = False, source_v1_contract: Mapping[str, Any] | None = None) -> list[str]:
    """Return public contract diagnostics; source-backed expansion stays private."""

    return _integrity_contract_errors(
        contract, task_id=task_id, worktree=worktree,
        require_complete=require_complete, source_v1_contract=source_v1_contract,
    )


def integrity_contract_validation_status(contract: Any, *, source_v1_contract: Mapping[str, Any] | None = None, task_id: Any | None = None, worktree: Any | None = None, require_complete: bool = False) -> dict[str, Any]:
    """Expose whether a compact contract has received full source-backed validation."""

    required = integrity_contract_source_required(contract) and source_v1_contract is None
    return {
        "errors": integrity_contract_errors(contract, task_id=task_id, worktree=worktree, require_complete=require_complete, source_v1_contract=source_v1_contract),
        "source_required": required,
        "full_validation": not required,
    }


def validate_integrity_contract(contract: Any, *, task_id: Any | None = None, worktree: Any | None = None, require_complete: bool = False, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]:
    errors = integrity_contract_errors(contract, task_id=task_id, worktree=worktree, require_complete=require_complete, source_v1_contract=source_v1_contract)
    if errors: raise IntegrityRecordError(errors)
    return copy.deepcopy(dict(contract))


def seal_integrity_contract(contract: Mapping[str, Any], seal: Mapping[str, Any], *, source_v1_contract: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(contract, Mapping) or not isinstance(seal, Mapping): raise IntegrityRecordError("integrity contract and seal must be objects")
    if contract.get("seal") is not None: raise IntegrityRecordError("sealed integrity contract is immutable")
    result = copy.deepcopy(dict(contract)); result["seal"] = copy.deepcopy(dict(seal)); validate_integrity_contract(result, require_complete=True, source_v1_contract=source_v1_contract); return result


_RECEIPT = frozenset({"record_type","prefix_storage","source_schema_version","source_mode","source_contract_artifact","source_contract_sha256","source_task_id","source_worktree","source_baseline_head","source_semantic_head_sha256","migrated_at","migrated_record_count","migrated_records_sha256","anchor_snapshot_record_sha256","prefix_open_finding_ids","record_sha256"})


def integrity_contract_source_required(contract: Any) -> bool:
    """Whether full validation needs the CAS-bound frozen v1 source.

    A compact migrated contract deliberately persists only its native v2 tail.
    Its v1-derived prefix is recoverable only from the immutable source CAS
    artifact named by the migration receipt.
    """

    return isinstance(contract, Mapping) and isinstance(contract.get("migration_receipt"), Mapping) and contract["migration_receipt"].get("prefix_storage") == "source_v1_cas_v1"


def _validate_receipt(receipt: Any) -> None:
    if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT or receipt.get("record_type") != "integrity_migration_receipt": raise IntegrityRecordError("migration_receipt schema is invalid")
    if receipt.get("record_sha256") != integrity_record_sha256(receipt): raise IntegrityRecordError("migration_receipt record_sha256 is invalid")
    if receipt.get("prefix_storage") != "source_v1_cas_v1": raise IntegrityRecordError("migration_receipt prefix_storage must be source_v1_cas_v1")
    if receipt.get("source_schema_version") != 1 or receipt.get("source_mode") != "required_v1": raise IntegrityRecordError("migration_receipt source version is invalid")
    source_contract_artifact = receipt.get("source_contract_artifact")
    if not isinstance(source_contract_artifact, Mapping):
        raise IntegrityRecordError("migration_receipt.source_contract_artifact schema is invalid")
    art = _artifact(source_contract_artifact, "migration_receipt.source_contract_artifact", max_size_bytes=MAX_INTEGRITY_MIGRATION_AGGREGATE_BYTES)
    if receipt.get("source_contract_sha256") != art["sha256"]: raise IntegrityRecordError("migration_receipt source_contract_sha256 must equal artifact sha256")
    _text(receipt.get("source_task_id"), "migration_receipt.source_task_id", _TOKEN)
    source_worktree = _text(receipt.get("source_worktree"), "migration_receipt.source_worktree")
    if not (PurePosixPath(source_worktree).is_absolute() or PureWindowsPath(source_worktree).is_absolute()):
        raise IntegrityRecordError("migration_receipt.source_worktree must be an absolute path")
    _head(receipt.get("source_baseline_head"), "migration_receipt.source_baseline_head"); _sha(receipt.get("source_semantic_head_sha256"), "migration_receipt.source_semantic_head_sha256", nullable=True); _time(receipt.get("migrated_at"), "migration_receipt.migrated_at"); _integer(receipt.get("migrated_record_count"), "migration_receipt.migrated_record_count", minimum=0); _sha(receipt.get("migrated_records_sha256"), "migration_receipt.migrated_records_sha256"); _sha(receipt.get("anchor_snapshot_record_sha256"), "migration_receipt.anchor_snapshot_record_sha256", nullable=True)
    obligations = receipt.get("prefix_open_finding_ids")
    if not isinstance(obligations, list):
        raise IntegrityRecordError("migration_receipt.prefix_open_finding_ids must be an array")
    _many(obligations, "migration_receipt.prefix_open_finding_ids", _TOKEN)


def _v1_source_binding(v1_contract: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    """Prove that ``v1_contract`` is exactly the CAS source named by receipt."""

    _v1.validate_integrity_contract(v1_contract, require_complete=False)
    if v1_contract.get("seal") is not None:
        raise IntegrityRecordError("sealed v1 contracts cannot be materialized")
    source_bytes = json.dumps(v1_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    artifact = receipt["source_contract_artifact"]
    if hashlib.sha256(source_bytes).hexdigest() != artifact["sha256"] or len(source_bytes) != artifact["size_bytes"]:
        raise IntegrityRecordError("migration source CAS binding does not match supplied v1 bytes")
    if v1_contract["baseline_head"] != receipt["source_baseline_head"]:
        raise IntegrityRecordError("migration source baseline differs from receipt")
    snapshots = v1_contract["snapshots"]
    if snapshots:
        if snapshots[0]["task_id"] != receipt["source_task_id"] or snapshots[0]["worktree"] != receipt["source_worktree"]:
            raise IntegrityRecordError("migration source identity differs from receipt")


def _materialize_v1_prefix(v1_contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Map a validated frozen v1 graph to its deterministic v2 effective prefix."""

    result = build_integrity_contract(baseline_head=v1_contract["baseline_head"], adopted_at=v1_contract["adopted_at"])
    s_by_hash: dict[str, dict[str, Any]] = {}; r_by_hash: dict[str, dict[str, Any]] = {}; f_by_hash: dict[str, dict[str, Any]] = {}; x_by_hash: dict[str, dict[str, Any]] = {}
    reviews = list(v1_contract["review_results"]); findings = list(v1_contract["findings"]); fixes = list(v1_contract["fixes"]); verifies = list(v1_contract["review_verifications"])
    for old_s in v1_contract["snapshots"]:
        result = append_snapshot(result, build_snapshot_record(**{k: old_s[k] for k in ("task_id","worktree","baseline_head","current_head","artifact","snapshot_sha256","claim_scope_sha256","covered_claim_tokens","purpose","producer_agent_ids")}, source_v1_record_sha256=old_s["record_sha256"]))
        s_by_hash[old_s["snapshot_sha256"]] = result["records"][-1]
        for old_r in [r for r in reviews if r["snapshot_sha256"] == old_s["snapshot_sha256"]]:
            rr = build_review_result_record(snapshot_record_sha256=s_by_hash[old_s["snapshot_sha256"]]["record_sha256"], reviewer_agent_id=old_r["reviewer_agent_id"], producer_agent_ids=old_r["producer_agent_ids"], result_artifact=old_r["result_artifact"], outcome=old_r["outcome"], finding_ids=old_r["finding_ids"], source_v1_record_sha256=old_r["record_sha256"])
            result = append_review_result(result, rr); r_by_hash[old_r["record_sha256"]] = result["records"][-1]
            for old_f in [f for f in findings if f["review_result_record_sha256"] == old_r["record_sha256"]]:
                ff = build_finding_record(finding_id=old_f["finding_id"], review_result_record_sha256=r_by_hash[old_r["record_sha256"]]["record_sha256"], snapshot_record_sha256=s_by_hash[old_f["snapshot_sha256"]]["record_sha256"], reviewer_agent_id=old_f["reviewer_agent_id"], finding_artifact_sha256=old_f["finding_artifact_sha256"], source_v1_record_sha256=old_f["record_sha256"])
                result = append_finding(result, ff); f_by_hash[old_f["record_sha256"]] = result["records"][-1]
    for old_x in fixes:
        if old_x["finding_record_sha256"] not in f_by_hash or old_x["post_fix_snapshot_sha256"] not in s_by_hash:
            raise IntegrityRecordError("v1 migration has fix backedge")
        xx = build_fix_record(finding_id=old_x["finding_id"], finding_record_sha256=f_by_hash[old_x["finding_record_sha256"]]["record_sha256"], post_fix_snapshot_record_sha256=s_by_hash[old_x["post_fix_snapshot_sha256"]]["record_sha256"], fix_artifact=old_x["fix_artifact"], producer_agent_ids=old_x["producer_agent_ids"], source_v1_record_sha256=old_x["record_sha256"])
        result = append_fix(result, xx); x_by_hash[old_x["record_sha256"]] = result["records"][-1]
    for old_v in verifies:
        if old_v["fix_record_sha256"] not in x_by_hash or old_v["snapshot_sha256"] not in s_by_hash:
            raise IntegrityRecordError("v1 migration has review verification backedge")
        vv = build_review_verification_record(finding_id=old_v["finding_id"], fix_record_sha256=x_by_hash[old_v["fix_record_sha256"]]["record_sha256"], verification_snapshot_record_sha256=s_by_hash[old_v["snapshot_sha256"]]["record_sha256"], reviewer_agent_id=old_v["reviewer_agent_id"], verification_artifact=old_v["verification_artifact"], outcome=old_v["outcome"], source_v1_record_sha256=old_v["record_sha256"])
        result = append_review_verification(result, vv)
    source_hashes = [r["record_sha256"] for name in ("snapshots", "review_results", "findings", "fixes", "review_verifications") for r in v1_contract[name]]
    mapped_hashes = [r["source_v1_record_sha256"] for r in result["records"]]
    if len(mapped_hashes) != len(source_hashes) or sorted(mapped_hashes) != sorted(source_hashes):
        raise IntegrityRecordError("v1 migration did not prove an exact one-to-one remap")
    return copy.deepcopy(result["records"])


def _prefix_open_finding_ids(records: Iterable[Mapping[str, Any]]) -> list[str]:
    findings: dict[str, Mapping[str, Any]] = {}; fixes: dict[str, Mapping[str, Any]] = {}; verifications: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record["record_type"] == "finding": findings[record["finding_id"]] = record
        elif record["record_type"] == "fix": fixes[record["finding_id"]] = record
        elif record["record_type"] == "review_verification": verifications[record["fix_record_sha256"]] = record
    return sorted(fid for fid in findings if (fix := fixes.get(fid)) is None or (verification := verifications.get(fix["record_sha256"])) is None or verification["outcome"] != "pass")


def materialize_effective_integrity_records(contract: Mapping[str, Any], source_v1_contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the exact v1-derived prefix followed by the persisted native tail."""

    receipt = contract.get("migration_receipt") if isinstance(contract, Mapping) else None
    if not isinstance(receipt, Mapping) or receipt.get("prefix_storage") != "source_v1_cas_v1":
        raise IntegrityRecordError("compact migration receipt is required to materialize an effective prefix")
    _validate_receipt(receipt); _v1_source_binding(source_v1_contract, receipt)
    prefix = _materialize_v1_prefix(source_v1_contract)
    if len(prefix) != receipt["migrated_record_count"] or _records_sha256(prefix) != receipt["migrated_records_sha256"]:
        raise IntegrityRecordError("migration receipt prefix digest/count does not match source CAS")
    anchor = next((r["record_sha256"] for r in reversed(prefix) if r["record_type"] == "snapshot"), None)
    if anchor != receipt["anchor_snapshot_record_sha256"] or _prefix_open_finding_ids(prefix) != receipt["prefix_open_finding_ids"]:
        raise IntegrityRecordError("migration receipt prefix anchor/obligations do not match source CAS")
    tail = contract.get("records")
    if not isinstance(tail, list):
        raise IntegrityRecordError("integrity_contract.records must be an array")
    for index, record in enumerate(tail, len(prefix) + 1):
        if not isinstance(record, Mapping):
            raise IntegrityRecordError(f"native migration tail record {index} is not an object")
        if record.get("integrity_seq") != index or record.get("source_v1_record_sha256") is not None:
            raise IntegrityRecordError("native migration tail sequence/source markers are invalid")
    return prefix + copy.deepcopy(tail)


def combine_native_integrity_tail(contract: Mapping[str, Any], source_v1_contract: Mapping[str, Any], native_tail: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Replace a compact contract's native tail after proving its effective sequence."""

    prefix = materialize_effective_integrity_records(contract, source_v1_contract)
    prefix_count = len(prefix) - len(contract["records"])
    try:
        replacement = list(native_tail)
    except TypeError as exc:
        raise IntegrityRecordError("native migration tail must be an array") from exc
    result = copy.deepcopy(dict(contract)); result["records"] = []
    for index, record in enumerate(replacement, prefix_count + 1):
        if not isinstance(record, Mapping):
            raise IntegrityRecordError(f"native migration tail record {index} is not an object")
        result["records"].append(copy.deepcopy(dict(record)))
    for index, record in enumerate(result["records"], prefix_count + 1):
        _validate_record(record, "native migration tail record")
        if record["integrity_seq"] != index or record["source_v1_record_sha256"] is not None:
            raise IntegrityRecordError("native migration tail sequence/source markers are invalid")
    validate_integrity_contract(result, source_v1_contract=source_v1_contract)
    return result


def compact_effective_integrity_contract(effective_contract: Mapping[str, Any], source_v1_contract: Mapping[str, Any]) -> dict[str, Any]:
    """Strip a materialized source prefix, retaining only the native v2 tail."""

    receipt = effective_contract.get("migration_receipt") if isinstance(effective_contract, Mapping) else None
    if not isinstance(receipt, Mapping):
        raise IntegrityRecordError("migration receipt is required to compact an effective contract")
    template = copy.deepcopy(dict(effective_contract)); template["records"] = []
    prefix = materialize_effective_integrity_records(template, source_v1_contract)
    actual = effective_contract.get("records")
    if not isinstance(actual, list) or actual[:len(prefix)] != prefix:
        raise IntegrityRecordError("effective contract prefix does not exactly match source CAS")
    template["records"] = copy.deepcopy(actual[len(prefix):])
    return combine_native_integrity_tail(template, source_v1_contract, template["records"])


def _compact_integrity_contract_errors(contract: Mapping[str, Any], *, task_id: Any | None, worktree: Any | None, require_complete: bool, source_v1_contract: Mapping[str, Any] | None) -> list[str]:
    """Validate the persisted compact form, or its full effective graph with source."""

    errors: list[str] = []
    receipt = contract.get("migration_receipt")
    try:
        _validate_receipt(receipt)
        assert isinstance(receipt, Mapping)
        if receipt["prefix_storage"] != "source_v1_cas_v1":
            raise IntegrityRecordError("persisted migrated contract must use source_v1_cas_v1 prefix storage")
        if task_id is not None and receipt["source_task_id"] != task_id:
            errors.append("migration receipt source_task_id differs from task state")
        if worktree not in (None, "") and receipt["source_worktree"] != worktree:
            errors.append("migration receipt source_worktree differs from task state")
        if receipt["source_baseline_head"] != contract.get("baseline_head"):
            errors.append("migration receipt source_baseline_head differs from integrity contract")
        tail = contract.get("records")
        if not isinstance(tail, list):
            raise IntegrityRecordError("integrity_contract.records must be an array")
        prefix_count = receipt["migrated_record_count"]
        for index, item in enumerate(tail, prefix_count + 1):
            if not isinstance(item, Mapping):
                errors.append(f"native migration tail record {index} is not an object")
                continue
            _validate_record(dict(item), f"native migration tail record {index}")
            if item["integrity_seq"] != index or item["source_v1_record_sha256"] is not None:
                errors.append("native migration tail sequence/source markers are invalid")
        if len({item["record_sha256"] for item in tail if isinstance(item, Mapping)}) != len(tail):
            errors.append("duplicate native migration tail record_sha256")
        seal = contract.get("seal")
        if seal is not None:
            _validate_record(dict(seal), "integrity_contract.seal")
            if seal["integrity_seq"] != prefix_count + len(tail) + 1:
                errors.append("seal integrity_seq must follow effective records")
    except IntegrityRecordError as exc:
        errors.extend(exc.errors)
        return sorted(set(errors))
    if source_v1_contract is None:
        # The receipt and native tail are structurally valid, but links from
        # tail/seal to the omitted prefix cannot be proven without the CAS
        # source.  Callers can inspect this explicitly via validation_status.
        if require_complete:
            errors.append("migration source contract is required for complete validation")
        return sorted(set(errors))
    try:
        # This private materialization is only a validation view.  The public
        # contract keeps the exact source-CAS receipt; it is never rewritten to
        # an inline prefix form that could be persisted or self-consistently
        # remapped without the original v1 bytes.
        errors.extend(_integrity_contract_errors(
            contract, task_id=task_id, worktree=worktree,
            require_complete=require_complete,
            materialized_records=materialize_effective_integrity_records(
                contract, source_v1_contract
            ),
        ))
    except IntegrityRecordError as exc:
        errors.extend(exc.errors)
    return sorted(set(errors))


def migrate_v1_integrity_contract(v1_contract: Mapping[str, Any], *, source_contract_artifact: Mapping[str, Any], migrated_at: Any, source_semantic_head_sha256: Any = None, expected_v1_contract_sha256: Any = None, source_contract_sha256: Any = None, source_task_id: Any = None, source_worktree: Any = None) -> dict[str, Any]:
    """Create a compact v2 contract bound to, but not bloated by, frozen v1 CAS."""
    _v1.validate_integrity_contract(v1_contract, require_complete=False)
    if v1_contract.get("seal") is not None: raise IntegrityRecordError("sealed v1 contracts cannot be migrated")
    art = _artifact(source_contract_artifact, "migration.source_contract_artifact", max_size_bytes=MAX_INTEGRITY_MIGRATION_AGGREGATE_BYTES)
    source_bytes = json.dumps(v1_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(source_bytes) > MAX_INTEGRITY_MIGRATION_SOURCE_BYTES:
        raise IntegrityRecordError("migration source contract exceeds managed-state byte bound")
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if art["sha256"] != source_digest:
        raise IntegrityRecordError("migration source_contract_artifact sha256 does not match v1 bytes")
    if art["size_bytes"] != len(source_bytes):
        raise IntegrityRecordError("migration source_contract_artifact size_bytes does not match v1 bytes")
    for supplied, label in ((expected_v1_contract_sha256, "expected_v1_contract_sha256"), (source_contract_sha256, "source_contract_sha256")):
        if supplied is not None and _sha(supplied, label) != source_digest:
            raise IntegrityRecordError(f"migration {label} does not match v1 bytes")
    old_snapshots = v1_contract["snapshots"]
    if old_snapshots:
        source_task = old_snapshots[0]["task_id"]
        source_tree = old_snapshots[0]["worktree"]
        if source_task_id is not None and _text(source_task_id, "migration.source_task_id", _TOKEN) != source_task:
            raise IntegrityRecordError("migration source_task_id differs from v1 snapshots")
        if source_worktree is not None and _text(source_worktree, "migration.source_worktree") != source_tree:
            raise IntegrityRecordError("migration source_worktree differs from v1 snapshots")
    else:
        source_task = _text(source_task_id, "migration.source_task_id", _TOKEN)
        source_tree = _text(source_worktree, "migration.source_worktree")
        if not (PurePosixPath(source_tree).is_absolute() or PureWindowsPath(source_tree).is_absolute()):
            raise IntegrityRecordError("migration.source_worktree must be an absolute path")
    prefix = _materialize_v1_prefix(v1_contract)
    anchor = next((r["record_sha256"] for r in reversed(prefix) if r["record_type"] == "snapshot"), None)
    receipt = {"record_type":"integrity_migration_receipt","prefix_storage":"source_v1_cas_v1","source_schema_version":1,"source_mode":"required_v1","source_contract_artifact":art,"source_contract_sha256":art["sha256"],"source_task_id":source_task,"source_worktree":source_tree,"source_baseline_head":v1_contract["baseline_head"],"source_semantic_head_sha256":_sha(source_semantic_head_sha256,"migration.source_semantic_head_sha256",nullable=True),"migrated_at":_time(migrated_at,"migration.migrated_at"),"migrated_record_count":len(prefix),"migrated_records_sha256":_records_sha256(prefix),"anchor_snapshot_record_sha256":anchor,"prefix_open_finding_ids":_prefix_open_finding_ids(prefix)}
    receipt["record_sha256"] = integrity_record_sha256(receipt)
    result = build_integrity_contract(baseline_head=v1_contract["baseline_head"], adopted_at=v1_contract["adopted_at"])
    result["migration_receipt"] = receipt
    if len(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) >= MAX_INTEGRITY_MIGRATION_SEMANTIC_DELTA_BYTES:
        raise IntegrityRecordError("compact migration semantic delta exceeds byte bound")
    validate_integrity_contract(result, source_v1_contract=v1_contract); return result


convert_v1_integrity_contract = migrate_v1_integrity_contract

__all__ = [name for name in globals() if name.startswith(("INTEGRITY_", "MAX_INTEGRITY_", "build_", "append_", "next_", "review_basis", "integrity_", "validate_", "seal_", "migrate_", "convert_", "materialize_", "combine_", "compact_"))] + ["IntegrityRecordError", "validate_agent_id"]
