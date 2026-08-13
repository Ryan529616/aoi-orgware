"""Closed semantic-v2 workflow transitions for the Phase-1 IC loop.

The workflow is deliberately an append-only sub-ledger inside AOI's existing
semantic task projection.  It compiles typed requests into a new projection;
it does not write files, launch processes, or create a second authority store.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple, cast

from . import harnesslib as h
from . import packet_integrity
from . import semantic_events as semantic
from . import semantic_workflow_jobs as workflow_jobs
from .ic_rag import (
    ICRagDocumentV1,
    ICRagError,
    derive_ic_rag_context,
    receipt_to_dict,
)


WORKFLOW_SCHEMA_VERSION = 1
REQUEST_SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_WORKFLOW_RECORDS = 4096
MAX_TEXT_CHARACTERS = 4096
WORKFLOW_KEY = "ic_engineering_v1"

OPERATIONS = frozenset(
    {
        "plan_publish",
        "claim_create",
        "claim_release",
        "packet_create",
        "external_job_queue",
        "external_job_launch",
        "external_job_observe",
        "verification_record",
        "checkpoint_record",
    }
)
JOB_STAGES = workflow_jobs.JOB_STAGES
JOB_EFFECTS = workflow_jobs.JOB_EFFECTS
VERIFICATION_OUTCOMES = frozenset({"accepted", "rejected", "blocked"})

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_UTC_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00"
)
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "operation_id",
        "recorded_at",
        "payload",
        "context_receipt",
        "record_sha256",
    }
)
_RAG_RECEIPT_FIELDS = frozenset(
    {
        "audience",
        "close_qualifying",
        "document_set_sha256",
        "hits",
        "max_excerpt_bytes",
        "max_hits",
        "max_hits_per_kind",
        "missing_source_kinds",
        "phase",
        "present_source_kinds",
        "project_fact_precedence",
        "query",
        "query_sha256",
        "receipt_sha256",
        "result_quality",
        "retrieval_method",
        "schema_version",
        "source_order",
        "technical_verdict_authority",
        "unmatched_query_terms",
    }
)


class SemanticWorkflowError(ValueError):
    """Typed fail-closed boundary for workflow requests and projections."""


class SemanticWorkflowTransitionV1(NamedTuple):
    operation: str
    operation_id: str
    event_type: str
    result_state: dict[str, Any]
    workflow_view: dict[str, Any]
    workflow_record_sha256: str


class _DuplicateKeyError(ValueError):
    pass


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError(key)
        value[key] = item
    return value


def _clone(value: Any, *, maximum: int = semantic.MAX_CANONICAL_JSON_BYTES) -> Any:
    try:
        return json.loads(semantic.canonical_json_bytes(value, max_bytes=maximum))
    except (
        semantic.SemanticEventError, UnicodeDecodeError, json.JSONDecodeError, RecursionError
    ) as exc:
        raise SemanticWorkflowError("workflow value is not bounded canonical JSON") from exc


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value.keys())
    if actual != expected:
        raise SemanticWorkflowError(
            f"{label} fields are invalid: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT_CHARACTERS) -> str:
    if not isinstance(value, str) or "\x00" in value or not value.strip():
        raise SemanticWorkflowError(f"{label} must be non-empty text")
    if len(value) > maximum:
        raise SemanticWorkflowError(f"{label} exceeds its character bound")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SemanticWorkflowError(f"{label} must be valid UTF-8 text") from exc
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, maximum=128)
    if not _ID_RE.fullmatch(text):
        raise SemanticWorkflowError(f"{label} must be a lowercase portable identifier")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SemanticWorkflowError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: Any, label: str = "workflow recorded_at") -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise SemanticWorkflowError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise SemanticWorkflowError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise SemanticWorkflowError(f"{label} must use UTC")
    if parsed.isoformat() != value:
        raise SemanticWorkflowError(f"{label} is non-canonical")
    return value


def _state_timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise SemanticWorkflowError("current task updated_at must be a timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise SemanticWorkflowError("current task updated_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SemanticWorkflowError("current task updated_at must include a timezone")
    return parsed


def _exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SemanticWorkflowError(f"{label} must be an integer >= {minimum}")
    return value


def _nullable_identifier(value: Any, label: str) -> str | None:
    return None if value is None else _identifier(value, label)


def _string_list(value: Any, label: str, *, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise SemanticWorkflowError(f"{label} must be a bounded array")
    result = [_identifier(item, f"{label} item") for item in value]
    if result != sorted(set(result)):
        raise SemanticWorkflowError(f"{label} must be sorted and unique")
    return result


def _lock_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise SemanticWorkflowError("claim locks must contain 1..64 items")
    try:
        locks = [h.normalize_lock(_text(item, "claim lock", maximum=4096)) for item in value]
    except h.HarnessError as exc:
        raise SemanticWorkflowError(str(exc)) from exc
    if locks != sorted(set(locks)):
        raise SemanticWorkflowError("claim locks must be canonical, sorted, and unique")
    return locks


def _normalize_command(value: Any, expected_sha256: Any) -> tuple[str, str]:
    command = _text(value, "packet canonical_command", maximum=64 * 1024)
    try:
        canonical = packet_integrity.normalize_exact_command_bytes(command.encode("utf-8"))
    except h.HarnessError as exc:
        raise SemanticWorkflowError(str(exc)) from exc
    canonical_text = canonical.decode("utf-8")
    if command != canonical_text:
        raise SemanticWorkflowError("packet canonical_command is not canonically normalized")
    digest = hashlib.sha256(canonical).hexdigest()
    if _sha256(expected_sha256, "packet command_sha256") != digest:
        raise SemanticWorkflowError("packet command SHA-256 differs from canonical command")
    return canonical_text, digest


def parse_workflow_request_bytes(data: bytes) -> dict[str, Any]:
    """Decode one exact canonical workflow request with typed error handling."""

    if not isinstance(data, bytes) or not data or len(data) > MAX_REQUEST_BYTES:
        raise SemanticWorkflowError("workflow request byte length is invalid")
    try:
        decoded = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_object)
        canonical = semantic.canonical_json_bytes(decoded, max_bytes=MAX_REQUEST_BYTES)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateKeyError,
        semantic.SemanticEventError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise SemanticWorkflowError("workflow request is invalid canonical JSON") from exc
    if data != canonical or not isinstance(decoded, dict):
        raise SemanticWorkflowError("workflow request must be one canonical JSON object")
    return _validate_request(decoded)


def _validate_request(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        frozenset({"schema_version", "operation", "task_id", "operation_id", "payload"}),
        "workflow request",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise SemanticWorkflowError("workflow request schema_version is unsupported")
    operation = value["operation"]
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise SemanticWorkflowError("workflow operation is unsupported")
    task_id = _identifier(value["task_id"], "workflow task_id")
    operation_id = _identifier(value["operation_id"], "workflow operation_id")
    if not isinstance(value["payload"], dict):
        raise SemanticWorkflowError("workflow payload must be an object")
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "operation": operation,
        "task_id": task_id,
        "operation_id": operation_id,
        "payload": _clone(value["payload"], maximum=MAX_REQUEST_BYTES),
    }


def _canonical_digest(value: Any, label: str) -> str:
    try:
        return hashlib.sha256(semantic.canonical_json_bytes(value)).hexdigest()
    except (semantic.SemanticEventError, RecursionError, TypeError, ValueError) as exc:
        raise SemanticWorkflowError(f"{label} is not bounded canonical JSON") from exc


def _receipt_digest(receipt: Mapping[str, Any]) -> str:
    preimage = dict(receipt)
    preimage.pop("receipt_sha256", None)
    return _canonical_digest(preimage, "workflow context receipt")


def _validate_context_receipt(
    value: Any, *, phase: str, audience: str, query: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticWorkflowError("workflow context receipt must be an object")
    _exact_fields(value, _RAG_RECEIPT_FIELDS, "workflow context receipt")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("phase") != phase
        or value.get("audience") != audience
        or value.get("query") != query
        or value.get("technical_verdict_authority") != "none"
        or value.get("project_fact_precedence")
        != "repository_source_and_runtime_receipts"
        or value.get("close_qualifying") is not False
        or _sha256(value.get("query_sha256"), "context query digest")
        != hashlib.sha256(query.encode("utf-8")).hexdigest()
        or _sha256(value.get("receipt_sha256"), "context receipt digest")
        != _receipt_digest(value)
    ):
        raise SemanticWorkflowError("workflow context receipt binding is invalid")
    if not isinstance(value.get("hits"), list):
        raise SemanticWorkflowError("workflow context receipt hits must be an array")
    return cast(dict[str, Any], _clone(value))


def _record_preimage(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in sorted(_RECORD_FIELDS - {"record_sha256"})}


def _record_digest(record: Mapping[str, Any]) -> str:
    return _canonical_digest(_record_preimage(record), "workflow record")


def _new_view() -> dict[str, Any]:
    return {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "plan": None,
        "claims": {},
        "packets": {},
        "external_jobs": {},
        "verifications": {},
        "checkpoints": {},
        "operation_ids": set(),
        "last_recorded_at": None,
    }


def _payload(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticWorkflowError(f"{label} payload must be an object")
    _exact_fields(value, fields, f"{label} payload")
    return value


def _active_claim(view: dict[str, Any], claim_id: str) -> dict[str, Any]:
    claim = view["claims"].get(claim_id)
    if not isinstance(claim, dict) or claim.get("status") != "active":
        raise SemanticWorkflowError(f"claim {claim_id!r} is not active")
    return claim


def _apply_plan(
    view: dict[str, Any], payload: Any, context: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    item = _payload(
        payload,
        frozenset({"plan_id", "plan_sha256", "source_manifest_sha256", "objective", "query"}),
        "plan_publish",
    )
    if view["plan"] is not None:
        raise SemanticWorkflowError("workflow plan is append-once in Phase 1")
    query = _text(item["query"], "plan query", maximum=512)
    receipt = _validate_context_receipt(context, phase="planning", audience="rtl", query=query)
    plan = {
        "plan_id": _identifier(item["plan_id"], "plan_id"),
        "plan_sha256": _sha256(item["plan_sha256"], "plan_sha256"),
        "source_manifest_sha256": _sha256(
            item["source_manifest_sha256"], "plan source_manifest_sha256"
        ),
        "objective": _text(item["objective"], "plan objective"),
        "query": query,
        "context_receipt": receipt,
        "context_receipt_sha256": receipt["receipt_sha256"],
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    view["plan"] = plan
    return {
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "source_manifest_sha256": plan["source_manifest_sha256"],
        "objective": plan["objective"],
        "query": query,
    }


def _apply_claim_create(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    item = _payload(payload, frozenset({"claim_id", "locks", "intent", "validation"}), "claim_create")
    claim_id = _identifier(item["claim_id"], "claim_id")
    if claim_id in view["claims"]:
        raise SemanticWorkflowError("claim_id already exists")
    locks = _lock_list(item["locks"])
    for current in view["claims"].values():
        if current["status"] != "active":
            continue
        for left in locks:
            for right in current["locks"]:
                if h.locks_overlap(left, right):
                    raise SemanticWorkflowError(
                        f"claim lock overlaps active claim {current['claim_id']!r}"
                    )
    view["claims"][claim_id] = {
        "claim_id": claim_id,
        "revision": 1,
        "status": "active",
        "locks": locks,
        "intent": _text(item["intent"], "claim intent"),
        "validation": _text(item["validation"], "claim validation"),
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    return {
        "claim_id": claim_id,
        "locks": locks,
        "intent": view["claims"][claim_id]["intent"],
        "validation": view["claims"][claim_id]["validation"],
    }


def _apply_packet(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    item = _payload(
        payload,
        frozenset(
            {
                "packet_id",
                "role",
                "mode",
                "parent_packet_id",
                "claim_ids",
                "canonical_command",
                "command_sha256",
            }
        ),
        "packet_create",
    )
    if view["plan"] is None:
        raise SemanticWorkflowError("packet requires a published workflow plan")
    packet_id = _identifier(item["packet_id"], "packet_id")
    if packet_id in view["packets"]:
        raise SemanticWorkflowError("packet_id already exists")
    role = item["role"]
    mode = item["mode"]
    if role not in {"rtl", "dv"} or mode not in {"exact_command", "read_only"}:
        raise SemanticWorkflowError("packet role or mode is unsupported")
    parent = _nullable_identifier(item["parent_packet_id"], "parent_packet_id")
    if parent is not None and parent not in view["packets"]:
        raise SemanticWorkflowError("packet parent is not durable")
    claim_ids = _string_list(item["claim_ids"], "packet claim_ids")
    if role == "rtl" and mode == "exact_command":
        if not claim_ids:
            raise SemanticWorkflowError("RTL exact-command packet requires an active claim")
        for claim_id in claim_ids:
            _active_claim(view, claim_id)
        command, command_sha = _normalize_command(
            item["canonical_command"], item["command_sha256"]
        )
    elif role == "dv" and mode == "read_only":
        if claim_ids or item["canonical_command"] is not None or item["command_sha256"] is not None:
            raise SemanticWorkflowError("DV read-only packet may not hold mutation authority")
        command = None
        command_sha = None
    else:
        raise SemanticWorkflowError("Phase-1 packet role and mode combination is unsupported")
    packet = {
        "packet_id": packet_id,
        "role": role,
        "mode": mode,
        "parent_packet_id": parent,
        "claim_ids": claim_ids,
        "canonical_command": command,
        "command_sha256": command_sha,
        "plan_id": view["plan"]["plan_id"],
        "plan_sha256": view["plan"]["plan_sha256"],
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    view["packets"][packet_id] = packet
    return {key: packet[key] for key in item.keys()}


def _apply_verification(
    view: dict[str, Any], payload: Any, context: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    item = _payload(
        payload,
        frozenset({"verification_id", "packet_id", "job_id", "outcome", "evidence_sha256", "query"}),
        "verification_record",
    )
    verification_id = _identifier(item["verification_id"], "verification_id")
    if verification_id in view["verifications"]:
        raise SemanticWorkflowError("verification_id already exists")
    packet_id = _identifier(item["packet_id"], "verification packet_id")
    packet = view["packets"].get(packet_id)
    if not isinstance(packet, dict) or packet["role"] != "dv" or packet["mode"] != "read_only":
        raise SemanticWorkflowError("verification requires a read-only DV packet")
    job_id = _identifier(item["job_id"], "verification job_id")
    job = view["external_jobs"].get(job_id)
    if not isinstance(job, dict):
        raise SemanticWorkflowError("verification job is not durable")
    if packet["parent_packet_id"] != job["packet_id"]:
        raise SemanticWorkflowError("verification DV packet is not the job's RTL child")
    outcome = item["outcome"]
    expected = {"completed": "accepted", "failed_known": "rejected", "effect_unknown": "blocked"}.get(
        job["status"]
    )
    if outcome not in VERIFICATION_OUTCOMES or outcome != expected:
        raise SemanticWorkflowError("verification outcome overstates or differs from job truth")
    query = _text(item["query"], "verification query", maximum=512)
    receipt = _validate_context_receipt(
        context, phase="independent_review", audience="dv", query=query
    )
    verification = {
        "verification_id": verification_id,
        "packet_id": packet_id,
        "job_id": job_id,
        "outcome": outcome,
        "evidence_sha256": _sha256(item["evidence_sha256"], "verification evidence digest"),
        "query": query,
        "context_receipt": receipt,
        "context_receipt_sha256": receipt["receipt_sha256"],
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    view["verifications"][verification_id] = verification
    return {
        "verification_id": verification_id,
        "packet_id": packet_id,
        "job_id": job_id,
        "outcome": outcome,
        "evidence_sha256": verification["evidence_sha256"],
        "query": query,
    }


def _apply_checkpoint(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    item = _payload(
        payload,
        frozenset(
            {
                "checkpoint_id",
                "job_id",
                "verification_id",
                "summary_sha256",
                "worktree_sha256",
                "expected_semantic_head_sha256",
            }
        ),
        "checkpoint_record",
    )
    checkpoint_id = _identifier(item["checkpoint_id"], "checkpoint_id")
    if checkpoint_id in view["checkpoints"]:
        raise SemanticWorkflowError("checkpoint_id already exists")
    job_id = _identifier(item["job_id"], "checkpoint job_id")
    verification_id = _identifier(item["verification_id"], "checkpoint verification_id")
    if job_id not in view["external_jobs"] or verification_id not in view["verifications"]:
        raise SemanticWorkflowError("checkpoint requires durable job and verification")
    if view["verifications"][verification_id]["job_id"] != job_id:
        raise SemanticWorkflowError("checkpoint job and verification differ")
    checkpoint = {
        "checkpoint_id": checkpoint_id,
        "job_id": job_id,
        "verification_id": verification_id,
        "summary_sha256": _sha256(item["summary_sha256"], "checkpoint summary digest"),
        "worktree_sha256": _sha256(item["worktree_sha256"], "checkpoint worktree digest"),
        "expected_semantic_head_sha256": _sha256(
            item["expected_semantic_head_sha256"], "checkpoint semantic head digest"
        ),
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    view["checkpoints"][checkpoint_id] = checkpoint
    return {key: checkpoint[key] for key in item.keys()}


def _apply_record(view: dict[str, Any], record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise SemanticWorkflowError("workflow record must be an object")
    _exact_fields(record, _RECORD_FIELDS, "workflow record")
    if type(record["schema_version"]) is not int or record["schema_version"] != WORKFLOW_SCHEMA_VERSION:
        raise SemanticWorkflowError("workflow record schema_version is unsupported")
    operation = record["operation"]
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise SemanticWorkflowError("workflow record operation is unsupported")
    operation_id = _identifier(record["operation_id"], "workflow record operation_id")
    if operation_id in view["operation_ids"]:
        raise SemanticWorkflowError("workflow record operation_id is duplicated")
    recorded_at = _timestamp(record["recorded_at"])
    previous = view["last_recorded_at"]
    if previous is not None and dt.datetime.fromisoformat(recorded_at) < dt.datetime.fromisoformat(previous):
        raise SemanticWorkflowError("workflow record chronology regresses")
    if _sha256(record["record_sha256"], "workflow record digest") != _record_digest(record):
        raise SemanticWorkflowError("workflow record digest differs")
    context = record["context_receipt"]
    if operation not in {"plan_publish", "verification_record"} and context is not None:
        raise SemanticWorkflowError("workflow operation may not carry a context receipt")
    if operation == "plan_publish":
        normalized = _apply_plan(view, record["payload"], context, operation_id, recorded_at)
    elif operation == "claim_create":
        normalized = _apply_claim_create(view, record["payload"], operation_id, recorded_at)
    elif operation == "packet_create":
        normalized = _apply_packet(view, record["payload"], operation_id, recorded_at)
    elif operation in {
        "claim_release", "external_job_queue", "external_job_launch", "external_job_observe"
    }:
        handler = {
            "claim_release": workflow_jobs.apply_claim_release,
            "external_job_queue": workflow_jobs.apply_job_queue,
            "external_job_launch": workflow_jobs.apply_job_launch,
            "external_job_observe": workflow_jobs.apply_job_observe,
        }[operation]
        try:
            normalized = handler(view, record["payload"], operation_id, recorded_at)
        except workflow_jobs.SemanticWorkflowJobError as exc:
            raise SemanticWorkflowError(str(exc)) from exc
    elif operation == "verification_record":
        normalized = _apply_verification(view, record["payload"], context, operation_id, recorded_at)
    else:
        normalized = _apply_checkpoint(view, record["payload"], operation_id, recorded_at)
    if semantic.canonical_json_bytes(normalized) != semantic.canonical_json_bytes(record["payload"]):
        raise SemanticWorkflowError("workflow record payload is not normalized")
    view["operation_ids"].add(operation_id)
    view["last_recorded_at"] = recorded_at
    return normalized


def _namespace_records(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    if state.get("semantic_write_policy") != "explicit_transition_only":
        raise SemanticWorkflowError("workflow requires an explicit-transition semantic-v2 task")
    value = state.get(WORKFLOW_KEY)
    if value is None:
        return []
    if not isinstance(value, dict):
        raise SemanticWorkflowError("workflow namespace must be an object")
    _exact_fields(value, frozenset({"schema_version", "records"}), "workflow namespace")
    if type(value["schema_version"]) is not int or value["schema_version"] != WORKFLOW_SCHEMA_VERSION:
        raise SemanticWorkflowError("workflow namespace schema_version is unsupported")
    records = value["records"]
    if not isinstance(records, list) or len(records) > MAX_WORKFLOW_RECORDS:
        raise SemanticWorkflowError("workflow record count is invalid")
    return cast(list[dict[str, Any]], _clone(records))


def _replay(state: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = _namespace_records(state)
    view = _new_view()
    for record in records:
        _apply_record(view, record)
    return records, view


def _portable_view(view: dict[str, Any], records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "plan": _clone(view["plan"]) if view["plan"] is not None else None,
        "claims": [_clone(view["claims"][key]) for key in sorted(view["claims"])],
        "packets": [_clone(view["packets"][key]) for key in sorted(view["packets"])],
        "external_jobs": [
            _clone(view["external_jobs"][key]) for key in sorted(view["external_jobs"])
        ],
        "verifications": [
            _clone(view["verifications"][key]) for key in sorted(view["verifications"])
        ],
        "checkpoints": [
            _clone(view["checkpoints"][key]) for key in sorted(view["checkpoints"])
        ],
        "record_count": len(records),
        "records_sha256": _canonical_digest(list(records), "workflow records"),
        "authority_boundary": "semantic_ledger_self_consistency_not_process_or_eda_authority",
    }


def derive_workflow_view(state: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and deterministically derive the portable Phase-1 workflow view."""

    records, view = _replay(state)
    return _portable_view(view, records)


def compile_workflow_transition(
    state: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    recorded_at: str,
    rag_documents: Sequence[ICRagDocumentV1] | None = None,
    expected_semantic_head_sha256: str | None = None,
) -> SemanticWorkflowTransitionV1:
    """Compile exactly one closed operation without writing or launching anything."""

    if not isinstance(state, dict):
        raise SemanticWorkflowError("semantic task state must be an object")
    checked_request = _validate_request(request)
    if state.get("task_id") != checked_request["task_id"]:
        raise SemanticWorkflowError("workflow request task identity mismatch")
    recorded_at = _timestamp(recorded_at)
    if dt.datetime.fromisoformat(recorded_at) < _state_timestamp(state.get("updated_at")):
        raise SemanticWorkflowError("workflow transition predates current task state")
    records, view = _replay(state)
    if len(records) >= MAX_WORKFLOW_RECORDS:
        raise SemanticWorkflowError("workflow record bound is exhausted")
    operation = checked_request["operation"]
    payload = checked_request["payload"]
    checkpoint_head = payload.get("expected_semantic_head_sha256")
    if operation == "checkpoint_record":
        if _sha256(expected_semantic_head_sha256, "expected semantic head") != checkpoint_head:
            raise SemanticWorkflowError("checkpoint semantic head differs from caller authority")
    elif expected_semantic_head_sha256 is not None:
        raise SemanticWorkflowError("only checkpoint_record accepts semantic head binding")
    if operation in {"plan_publish", "verification_record"}:
        if rag_documents is None:
            raise SemanticWorkflowError("workflow operation requires IC RAG witnesses")
        query = payload.get("query") if isinstance(payload, dict) else None
        query = _text(query, "workflow context query", maximum=512)
        try:
            receipt = derive_ic_rag_context(
                query=query,
                phase="planning" if operation == "plan_publish" else "independent_review",
                audience="rtl" if operation == "plan_publish" else "dv",
                documents=rag_documents,
            )
            context: dict[str, Any] | None = receipt_to_dict(receipt)
        except ICRagError as exc:
            raise SemanticWorkflowError(f"workflow context derivation failed: {exc}") from exc
    else:
        if rag_documents is not None:
            raise SemanticWorkflowError("workflow operation does not accept IC RAG witnesses")
        context = None
    record: dict[str, Any] = {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "operation": operation,
        "operation_id": checked_request["operation_id"],
        "recorded_at": recorded_at,
        "payload": payload,
        "context_receipt": context,
        "record_sha256": "0" * 64,
    }
    record["record_sha256"] = _record_digest(record)
    normalized_payload = _apply_record(view, record)
    record["payload"] = normalized_payload
    record["record_sha256"] = _record_digest(record)
    records.append(_clone(record))
    result_state = _clone(state)
    result_state[WORKFLOW_KEY] = {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "records": records,
    }
    result_state["revision"] = _exact_int(result_state.get("revision"), "task revision", minimum=1) + 1
    result_state["updated_at"] = recorded_at
    result_state["checkpoint_required"] = operation != "checkpoint_record"
    if operation == "plan_publish":
        result_state["plan_ready"] = True
        result_state["plan_sha256"] = normalized_payload["plan_sha256"]
        result_state["phase"] = "implementing"
    if operation == "checkpoint_record":
        result_state["checkpoint_revision"] = result_state["revision"]
        result_state["checkpoint_sha256"] = normalized_payload["summary_sha256"]
    try:
        semantic.canonical_json_bytes(result_state)
    except (semantic.SemanticEventError, RecursionError) as exc:
        raise SemanticWorkflowError("workflow result exceeds semantic projection bounds") from exc
    return SemanticWorkflowTransitionV1(
        operation=operation,
        operation_id=checked_request["operation_id"],
        event_type=f"ic_workflow_{operation}",
        result_state=result_state,
        workflow_view=_portable_view(view, records),
        workflow_record_sha256=record["record_sha256"],
    )


__all__ = [
    "JOB_EFFECTS",
    "JOB_STAGES",
    "MAX_REQUEST_BYTES",
    "OPERATIONS",
    "REQUEST_SCHEMA_VERSION",
    "SemanticWorkflowError",
    "SemanticWorkflowTransitionV1",
    "WORKFLOW_KEY",
    "compile_workflow_transition",
    "derive_workflow_view",
    "parse_workflow_request_bytes",
]
