"""Pure ExternalJob state machine used by the Phase-1 semantic workflow."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from . import harnesslib as h


JOB_STAGES = ("preflight", "compile", "elaboration", "runtime", "numeric")
STAGE_STATUSES = frozenset({"pass", "fail", "inconclusive"})
JOB_EFFECTS = frozenset({"active", "completed", "failed_known", "effect_unknown"})

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ORACLE_FIELDS = frozenset(
    {
        "schema_version",
        "oracle_id",
        "job_id",
        "run_id",
        "rtl_packet_id",
        "dv_packet_id",
        "source_sha256",
        "tool_sha256",
        "command_sha256",
        "numeric_evidence_sha256",
        "outcome",
        "mismatch_count",
        "authority",
        "receipt_sha256",
    }
)
_ORACLE_AUTHORITY = "caller_supplied_digest_bound_not_ledger_or_eda_authority"


class SemanticWorkflowJobError(ValueError):
    """Typed error raised by the pure job transition boundary."""


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value.keys())
    if actual != expected:
        raise SemanticWorkflowJobError(
            f"{label} fields are invalid: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _payload(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticWorkflowJobError(f"{label} payload must be an object")
    _exact_fields(value, fields, f"{label} payload")
    return value


def _text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or "\x00" in value or not value.strip():
        raise SemanticWorkflowJobError(f"{label} must be non-empty text")
    if len(value) > maximum:
        raise SemanticWorkflowJobError(f"{label} exceeds its character bound")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SemanticWorkflowJobError(f"{label} must be valid UTF-8 text") from exc
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, maximum=128)
    if not _ID_RE.fullmatch(text):
        raise SemanticWorkflowJobError(f"{label} must be a lowercase portable identifier")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SemanticWorkflowJobError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _nullable_identifier(value: Any, label: str) -> str | None:
    return None if value is None else _identifier(value, label)


def _active_claim(view: dict[str, Any], claim_id: str) -> dict[str, Any]:
    claim = view["claims"].get(claim_id)
    if not isinstance(claim, dict) or claim.get("status") != "active":
        raise SemanticWorkflowJobError(f"claim {claim_id!r} is not active")
    return claim


def _oracle_receipt(
    view: dict[str, Any], value: Any, job: dict[str, Any], evidence_sha256: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticWorkflowJobError("numeric pass requires a structured oracle receipt")
    _exact_fields(value, _ORACLE_FIELDS, "oracle receipt")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise SemanticWorkflowJobError("oracle receipt schema_version is unsupported")
    oracle_id = _identifier(value["oracle_id"], "oracle_id")
    dv_packet_id = _identifier(value["dv_packet_id"], "oracle dv_packet_id")
    dv_packet = view["packets"].get(dv_packet_id)
    if (
        not isinstance(dv_packet, dict)
        or dv_packet.get("role") != "dv"
        or dv_packet.get("mode") != "read_only"
        or dv_packet.get("parent_packet_id") != job["packet_id"]
    ):
        raise SemanticWorkflowJobError("oracle receipt requires the job's child DV packet")
    expected = {
        "schema_version": 1,
        "oracle_id": oracle_id,
        "job_id": job["job_id"],
        "run_id": job["run_id"],
        "rtl_packet_id": job["packet_id"],
        "dv_packet_id": dv_packet_id,
        "source_sha256": job["source_sha256"],
        "tool_sha256": job["tool_sha256"],
        "command_sha256": job["command_sha256"],
        "numeric_evidence_sha256": evidence_sha256,
        "outcome": "pass",
        "mismatch_count": 0,
        "authority": _ORACLE_AUTHORITY,
    }
    for key, expected_value in expected.items():
        if value[key] != expected_value or (
            key == "mismatch_count" and type(value[key]) is not int
        ):
            raise SemanticWorkflowJobError(f"oracle receipt {key} differs from job evidence")
    canonical = json.dumps(
        expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if _sha256(value["receipt_sha256"], "oracle receipt digest") != hashlib.sha256(
        canonical
    ).hexdigest():
        raise SemanticWorkflowJobError("oracle receipt digest differs")
    return {**expected, "receipt_sha256": value["receipt_sha256"]}


def apply_claim_release(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    """Release a claim only after every bound job has a known terminal effect."""

    item = _payload(payload, frozenset({"claim_id", "reason"}), "claim_release")
    claim_id = _identifier(item["claim_id"], "claim_id")
    current = _active_claim(view, claim_id)
    for job in view["external_jobs"].values():
        packet = view["packets"][job["packet_id"]]
        if claim_id in packet["claim_ids"] and job["status"] in {
            "queued",
            "running",
            "effect_unknown",
        }:
            raise SemanticWorkflowJobError("claim is held by a nonterminal external job")
    reason = _text(item["reason"], "claim release reason")
    current.update(
        {
            "revision": current["revision"] + 1,
            "status": "released",
            "release_reason": reason,
            "operation_id": operation_id,
            "recorded_at": recorded_at,
        }
    )
    return {"claim_id": claim_id, "reason": reason}


def apply_job_queue(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    """Queue one job from a durable exact-command RTL packet."""

    item = _payload(
        payload,
        frozenset(
            {"job_id", "run_id", "packet_id", "source_sha256", "tool_sha256", "output_lock"}
        ),
        "external_job_queue",
    )
    job_id = _identifier(item["job_id"], "job_id")
    run_id = _identifier(item["run_id"], "run_id")
    if job_id in view["external_jobs"]:
        raise SemanticWorkflowJobError("job_id already exists")
    if any(job["run_id"] == run_id for job in view["external_jobs"].values()):
        raise SemanticWorkflowJobError("run_id already exists")
    packet_id = _identifier(item["packet_id"], "job packet_id")
    packet = view["packets"].get(packet_id)
    if not isinstance(packet, dict) or packet["role"] != "rtl" or packet["mode"] != "exact_command":
        raise SemanticWorkflowJobError("job requires an exact-command RTL packet")
    if any(job["packet_id"] == packet_id for job in view["external_jobs"].values()):
        raise SemanticWorkflowJobError("exact-command packet already owns an immutable job")
    claims = [_active_claim(view, claim_id) for claim_id in packet["claim_ids"]]
    try:
        output_lock = h.normalize_lock(_text(item["output_lock"], "job output_lock"))
    except h.HarnessError as exc:
        raise SemanticWorkflowJobError(str(exc)) from exc
    if not any(any(h.lock_covers(lock, output_lock) for lock in claim["locks"]) for claim in claims):
        raise SemanticWorkflowJobError("job output_lock is outside packet claim authority")
    source_sha256 = _sha256(item["source_sha256"], "job source_sha256")
    if source_sha256 != view["plan"]["source_manifest_sha256"]:
        raise SemanticWorkflowJobError("job source differs from the published plan")
    tool_sha256 = _sha256(item["tool_sha256"], "job tool_sha256")
    for current in view["external_jobs"].values():
        held = current["status"] in {"queued", "running", "effect_unknown"}
        same_execution = (
            current["command_sha256"] == packet["command_sha256"]
            and current["source_sha256"] == source_sha256
            and current["tool_sha256"] == tool_sha256
        )
        if held and (same_execution or h.locks_overlap(current["output_lock"], output_lock)):
            raise SemanticWorkflowJobError("external execution identity or output is already held")
    job = {
        "job_id": job_id,
        "run_id": run_id,
        "packet_id": packet_id,
        "command_sha256": packet["command_sha256"],
        "source_sha256": source_sha256,
        "tool_sha256": tool_sha256,
        "output_lock": output_lock,
        "revision": 1,
        "status": "queued",
        "effect": "not_acquired",
        "attempt": 0,
        "stage_evidence": [],
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    view["external_jobs"][job_id] = job
    return {
        "job_id": job_id,
        "run_id": run_id,
        "packet_id": packet_id,
        "source_sha256": job["source_sha256"],
        "tool_sha256": job["tool_sha256"],
        "output_lock": output_lock,
    }


def apply_job_launch(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    """Move exactly one queued job to its sole launch attempt."""

    item = _payload(payload, frozenset({"job_id"}), "external_job_launch")
    job_id = _identifier(item["job_id"], "job_id")
    job = view["external_jobs"].get(job_id)
    if not isinstance(job, dict) or job["status"] != "queued" or job["attempt"] != 0:
        raise SemanticWorkflowJobError("external job is not eligible for its single launch")
    packet = view["packets"][job["packet_id"]]
    for claim_id in packet["claim_ids"]:
        _active_claim(view, claim_id)
    job.update(
        {
            "revision": 2,
            "status": "running",
            "effect": "in_flight",
            "attempt": 1,
            "operation_id": operation_id,
            "recorded_at": recorded_at,
        }
    )
    return {"job_id": job_id}


def apply_job_observe(
    view: dict[str, Any], payload: Any, operation_id: str, recorded_at: str
) -> dict[str, Any]:
    """Append one ordered stage observation and preserve unknown effects."""

    item = _payload(
        payload,
        frozenset(
            {
                "job_id",
                "stage",
                "stage_status",
                "evidence_sha256",
                "oracle_receipt",
                "terminal_effect",
                "reconcile_id",
            }
        ),
        "external_job_observe",
    )
    job_id = _identifier(item["job_id"], "job_id")
    job = view["external_jobs"].get(job_id)
    if not isinstance(job, dict) or job["status"] != "running" or job["attempt"] != 1:
        raise SemanticWorkflowJobError("external job is not running or is already terminal")
    stage = item["stage"]
    stage_status = item["stage_status"]
    terminal_effect = item["terminal_effect"]
    if stage not in JOB_STAGES or stage_status not in STAGE_STATUSES or terminal_effect not in JOB_EFFECTS:
        raise SemanticWorkflowJobError("job stage observation enum is unsupported")
    evidence = job["stage_evidence"]
    expected_stage = JOB_STAGES[len(evidence)] if len(evidence) < len(JOB_STAGES) else None
    if stage != expected_stage:
        raise SemanticWorkflowJobError("job stage evidence is out of order")
    evidence_sha256 = _sha256(item["evidence_sha256"], "stage evidence digest")
    oracle = None
    if stage == "numeric" and stage_status == "pass":
        oracle = _oracle_receipt(view, item["oracle_receipt"], job, evidence_sha256)
    elif item["oracle_receipt"] is not None:
        raise SemanticWorkflowJobError("oracle receipt is only valid for numeric evidence")
    reconcile_id = _nullable_identifier(item["reconcile_id"], "reconcile_id")
    if stage_status == "inconclusive":
        if terminal_effect != "effect_unknown" or reconcile_id is None:
            raise SemanticWorkflowJobError(
                "inconclusive evidence requires effect_unknown reconciliation"
            )
    elif stage_status == "fail":
        if terminal_effect != "failed_known" or reconcile_id is not None:
            raise SemanticWorkflowJobError("known failure must terminate as failed_known")
    elif stage_status == "pass":
        if stage == "numeric":
            if terminal_effect != "completed" or reconcile_id is not None:
                raise SemanticWorkflowJobError("numeric pass must complete without reconciliation")
            if not any(
                row["stage"] == "runtime" and row["stage_status"] == "pass"
                for row in evidence
            ):
                raise SemanticWorkflowJobError("numeric completion requires passing runtime evidence")
        elif terminal_effect != "active" or reconcile_id is not None:
            raise SemanticWorkflowJobError("pre-numeric pass must remain active")
    else:
        raise SemanticWorkflowJobError("passing evidence must remain active or complete")
    observation = {
        "stage": stage,
        "stage_status": stage_status,
        "evidence_sha256": evidence_sha256,
        "oracle_receipt": oracle,
        "terminal_effect": terminal_effect,
        "reconcile_id": reconcile_id,
        "operation_id": operation_id,
        "recorded_at": recorded_at,
    }
    evidence.append(observation)
    job.update(
        {
            "revision": job["revision"] + 1,
            "status": "running" if terminal_effect == "active" else terminal_effect,
            "effect": "in_flight" if terminal_effect == "active" else terminal_effect,
            "operation_id": operation_id,
            "recorded_at": recorded_at,
        }
    )
    return {
        "job_id": job_id,
        "stage": stage,
        "stage_status": stage_status,
        "evidence_sha256": observation["evidence_sha256"],
        "oracle_receipt": oracle,
        "terminal_effect": terminal_effect,
        "reconcile_id": reconcile_id,
    }


__all__ = [
    "JOB_EFFECTS",
    "JOB_STAGES",
    "SemanticWorkflowJobError",
    "apply_claim_release",
    "apply_job_launch",
    "apply_job_observe",
    "apply_job_queue",
]
