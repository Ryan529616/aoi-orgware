"""Append-only terminal truth for one explicitly owned legacy bridge job.

The legacy inventory contract remains unchanged and deliberately reports
provider runtime as unknown.  This additive contract records a narrower fact:
one registered legacy job process produced a complete, digest-bound non-zero
exit observation.  It does not prove provider closure, process-tree
quiescence, numeric correctness, or task completion.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Mapping, NoReturn

from .contracts import (
    BLOB_REF_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    validate_blob_ref,
)


LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1 = "LegacyBridgeJobTerminalSourceV1"
LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1 = "LegacyBridgeJobTerminalReceiptV1"
LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE = (
    "application/vnd.aoi.legacy-bridge-job-terminal-source-v1+json"
)
MAX_LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_BYTES = 1_048_576
MAX_LEGACY_BRIDGE_JOB_COMMAND_BYTES = 262_144
EXACT_COMMAND_NORMALIZATION_V1 = "terminal-whitespace-lf-v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_WINDOWS_100NS_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"\.[0-9]{7}Z"
)
_REQUIRED_ARTIFACT_ROLES = frozenset(
    {
        "command", "legacy_state", "terminal_manifest", "primary_log",
        "process_exit",
    },
)


def _normalize_exact_command_bytes(value: bytes) -> bytes:
    """Mirror the packet ABI without importing outside the company boundary."""

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        _fail("legacy terminal command must be UTF-8")
    if "\x00" in text:
        _fail("legacy terminal command may not contain NUL")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").rstrip(" \t\n")
    if not normalized:
        _fail("legacy terminal command may not be empty")
    return (normalized + "\n").encode("utf-8")
_SOURCE_FIELDS = frozenset(
    {
        "source_type",
        "schema_version",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "bridge_scope_id",
        "source_observation_id",
        "source_observation_payload_sha256",
        "source_observation_global_sequence",
        "request_evidence_sha256",
        "legacy_archive_sha256",
        "legacy_state_sha256",
        "task_identity_digest",
        "task_bridge_entity_id",
        "task_id",
        "task_source_record_sha256",
        "owner_packet_bridge_entity_id",
        "owner_packet_id",
        "owner_packet_source_record_sha256",
        "owner_packet_contract_sha256",
        "job_bridge_entity_id",
        "run_id",
        "job_source_record_sha256",
        "canonical_command",
        "command_normalization",
        "command_sha256",
        "command_size_bytes",
        "host_fingerprint_sha256",
        "process_fingerprint_sha256",
        "closure_kind",
        "closure_scope",
        "exit_code",
        "artifacts",
        "terminal_at",
        "observed_at",
        "truth_boundary",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "contract_type",
        "schema_version",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "bridge_scope_id",
        "terminal_key_id",
        "receipt_id",
        "source_observation_id",
        "source_observation_payload_sha256",
        "source_observation_global_sequence",
        "request_evidence_sha256",
        "legacy_archive_sha256",
        "legacy_state_sha256",
        "task_identity_digest",
        "task_bridge_entity_id",
        "task_id",
        "task_source_record_sha256",
        "owner_packet_bridge_entity_id",
        "owner_packet_id",
        "owner_packet_source_record_sha256",
        "owner_packet_contract_sha256",
        "job_bridge_entity_id",
        "run_id",
        "job_source_record_sha256",
        "command_normalization",
        "command_sha256",
        "command_size_bytes",
        "host_fingerprint_sha256",
        "process_fingerprint_sha256",
        "closure_kind",
        "closure_scope",
        "exit_code",
        "artifacts",
        "terminal_at",
        "observed_at",
        "engineering_status",
        "runtime_status",
        "coverage_status",
        "effect_status",
        "source_sha256",
        "raw_artifact",
        "provenance",
        "observation",
        "receipt_sha256",
    }
)
_EVIDENCE_FIELDS = _SOURCE_FIELDS - frozenset({
    "source_type", "schema_version", "source_observation_id",
    "source_observation_payload_sha256", "source_observation_global_sequence",
    "request_evidence_sha256", "truth_boundary",
})
_ARTIFACT_FIELDS = frozenset({"role", "sha256", "size_bytes", "media_type"})
_TRUTH_BOUNDARY = {
    "runtime_claim": "registered_job_process_stopped",
    "effect_claim": "known_nonzero_exit",
    "coverage_claim": "legacy_provider_coverage_degraded",
    "provider_closure": "unavailable",
    "process_tree_quiescence": "unavailable",
    "numeric_correctness": "unavailable",
    "task_completion": "unavailable",
}
_OBSERVATION = {
    "state": "known",
    "reason": "legacy_registered_process_nonzero_exit_reconciled",
}


class LegacyBridgeJobTerminalError(CompanyContractError):
    """Terminal source or receipt is malformed or overstates its evidence."""


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeJobTerminalError(message)


def _object(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        _fail(f"{label} fields are invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or isinstance(value, bool) or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str:
        _fail(f"{label} is invalid")
    is_windows_100ns = _WINDOWS_100NS_TIMESTAMP.fullmatch(value) is not None
    if _TIMESTAMP.fullmatch(value) is None and not is_windows_100ns:
        _fail(f"{label} is invalid")
    parse_value = value[:-2] + "Z" if is_windows_100ns else value
    try:
        parsed = datetime.fromisoformat(parse_value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        raise LegacyBridgeJobTerminalError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        _fail(f"{label} lacks a timezone")
    return value


def legacy_bridge_job_terminal_ledger_recorded_at(value: Any) -> str:
    """Project raw Windows 100 ns evidence onto the ledger microsecond clock."""

    timestamp = _timestamp(value, "legacy terminal ledger time")
    if _WINDOWS_100NS_TIMESTAMP.fullmatch(timestamp) is not None:
        return timestamp[:-2] + "Z"
    return timestamp


def _digest(value: Any, label: str) -> str:
    try:
        return hashlib.sha256(canonical_company_json_bytes(value)).hexdigest()
    except (CompanyContractError, RecursionError, TypeError, ValueError) as exc:
        raise LegacyBridgeJobTerminalError(
            f"{label} is not bounded canonical JSON",
        ) from exc


def legacy_bridge_job_terminal_request_evidence_sha256(
    evidence: Mapping[str, Any],
) -> str:
    """Hash only caller evidence, excluding Supervisor-owned source fields."""

    if type(evidence) is not dict or frozenset(evidence) != _EVIDENCE_FIELDS:
        _fail("legacy terminal evidence fields are invalid")
    return _digest(dict(evidence), "legacy terminal request evidence")


def legacy_bridge_job_terminal_receipt_id(
    terminal_key_id: str,
    request_evidence_sha256: str,
) -> str:
    """Derive the immutable receipt identity from the exact client evidence."""

    return _digest(
        {
            "domain": "aoi.legacy-bridge.job-terminal-receipt-id.v1",
            "terminal_key_id": _sha(terminal_key_id, "legacy terminal key id"),
            "request_evidence_sha256": _sha(
                request_evidence_sha256,
                "legacy terminal request evidence digest",
            ),
        },
        "legacy terminal receipt id",
    )


def _artifact(value: Any) -> dict[str, Any]:
    item = _object(value, _ARTIFACT_FIELDS, "terminal artifact")
    media_type = item["media_type"]
    if (
        type(media_type) is not str
        or not media_type.isascii()
        or not 1 <= len(media_type) <= 128
    ):
        _fail("terminal artifact media type is invalid")
    return {
        "role": _identifier(item["role"], "terminal artifact role"),
        "sha256": _sha(item["sha256"], "terminal artifact digest"),
        "size_bytes": _integer(
            item["size_bytes"],
            "terminal artifact size",
            minimum=1,
            maximum=1_073_741_824,
        ),
        "media_type": media_type,
    }


def _artifacts(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(_REQUIRED_ARTIFACT_ROLES):
        _fail("terminal artifacts are invalid")
    artifacts = [_artifact(member) for member in value]
    roles = [artifact["role"] for artifact in artifacts]
    if len(roles) != len(set(roles)) or frozenset(roles) != _REQUIRED_ARTIFACT_ROLES:
        _fail("terminal artifact roles are missing or duplicated")
    ordered = sorted(artifacts, key=lambda artifact: artifact["role"].encode("utf-8"))
    if artifacts != ordered:
        _fail("terminal artifacts are not in canonical order")
    return artifacts


def _shared_source(value: Any) -> dict[str, Any]:
    item = _object(value, _SOURCE_FIELDS, LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1)
    if item["source_type"] != LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1 or item[
        "schema_version"
    ] != 1:
        _fail("legacy terminal source discriminator is invalid")
    if type(item["schema_version"]) is not int:
        _fail("legacy terminal source schema version is invalid")
    command = item["canonical_command"]
    if type(command) is not str:
        _fail("legacy terminal canonical command is invalid")
    try:
        command_bytes = command.encode("utf-8")
        normalized = _normalize_exact_command_bytes(command_bytes)
    except Exception as exc:
        if isinstance(exc, (MemoryError, SystemExit, KeyboardInterrupt)):
            raise
        raise LegacyBridgeJobTerminalError(
            "legacy terminal canonical command is invalid",
        ) from exc
    if (
        command_bytes != normalized
        or len(command_bytes) > MAX_LEGACY_BRIDGE_JOB_COMMAND_BYTES
        or item["command_normalization"] != EXACT_COMMAND_NORMALIZATION_V1
        or _sha(item["command_sha256"], "legacy terminal command digest")
        != hashlib.sha256(command_bytes).hexdigest()
        or _integer(
            item["command_size_bytes"],
            "legacy terminal command size",
            minimum=1,
            maximum=MAX_LEGACY_BRIDGE_JOB_COMMAND_BYTES,
        )
        != len(command_bytes)
    ):
        _fail("legacy terminal canonical command identity differs")
    if item["closure_kind"] != "process_exit_observed" or item[
        "closure_scope"
    ] != "registered_job_process":
        _fail("legacy terminal closure claim is invalid")
    exit_code = _integer(
        item["exit_code"],
        "legacy terminal exit code",
        minimum=-2_147_483_648,
        maximum=2_147_483_647,
    )
    if exit_code == 0:
        _fail("legacy terminal v1 requires a nonzero exit code")
    if item["truth_boundary"] != _TRUTH_BOUNDARY:
        _fail("legacy terminal truth boundary is invalid")
    terminal_at = _timestamp(item["terminal_at"], "terminal time")
    observed_at = _timestamp(item["observed_at"], "observed time")
    if observed_at != terminal_at:
        _fail("legacy terminal observation time is not replay-stable")
    normalized_source = {
        "source_type": LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1,
        "schema_version": 1,
        "company_id": _identifier(item["company_id"], "company id"),
        "company_incarnation": _integer(
            item["company_incarnation"], "company incarnation", minimum=1, maximum=999_999_999,
        ),
        "lock_domain_generation": _integer(
            item["lock_domain_generation"], "lock generation", minimum=0, maximum=999_999_999,
        ),
        "bridge_scope_id": _sha(item["bridge_scope_id"], "bridge scope id"),
        "source_observation_id": _sha(
            item["source_observation_id"], "source observation id",
        ),
        "source_observation_payload_sha256": _sha(
            item["source_observation_payload_sha256"],
            "source observation payload digest",
        ),
        "source_observation_global_sequence": _integer(
            item["source_observation_global_sequence"],
            "source observation sequence",
            minimum=1,
            maximum=9_223_372_036_854_775_807,
        ),
        "request_evidence_sha256": _sha(
            item["request_evidence_sha256"],
            "legacy terminal request evidence digest",
        ),
        "legacy_archive_sha256": _sha(item["legacy_archive_sha256"], "legacy archive digest"),
        "legacy_state_sha256": _sha(item["legacy_state_sha256"], "legacy state digest"),
        "task_identity_digest": _sha(item["task_identity_digest"], "task identity digest"),
        "task_bridge_entity_id": _sha(item["task_bridge_entity_id"], "task bridge entity id"),
        "task_id": _identifier(item["task_id"], "task id"),
        "task_source_record_sha256": _sha(item["task_source_record_sha256"], "task record digest"),
        "owner_packet_bridge_entity_id": _sha(
            item["owner_packet_bridge_entity_id"], "owner packet bridge entity id",
        ),
        "owner_packet_id": _identifier(item["owner_packet_id"], "owner packet id"),
        "owner_packet_source_record_sha256": _sha(
            item["owner_packet_source_record_sha256"], "owner packet record digest",
        ),
        "owner_packet_contract_sha256": _sha(
            item["owner_packet_contract_sha256"], "owner packet contract digest",
        ),
        "job_bridge_entity_id": _sha(item["job_bridge_entity_id"], "job bridge entity id"),
        "run_id": _identifier(item["run_id"], "run id"),
        "job_source_record_sha256": _sha(item["job_source_record_sha256"], "job record digest"),
        "canonical_command": command,
        "command_normalization": EXACT_COMMAND_NORMALIZATION_V1,
        "command_sha256": item["command_sha256"],
        "command_size_bytes": len(command_bytes),
        "host_fingerprint_sha256": _sha(item["host_fingerprint_sha256"], "host fingerprint"),
        "process_fingerprint_sha256": _sha(
            item["process_fingerprint_sha256"], "process fingerprint",
        ),
        "closure_kind": "process_exit_observed",
        "closure_scope": "registered_job_process",
        "exit_code": exit_code,
        "artifacts": _artifacts(item["artifacts"]),
        "terminal_at": terminal_at,
        "observed_at": observed_at,
        "truth_boundary": dict(_TRUTH_BOUNDARY),
    }
    evidence = {key: normalized_source[key] for key in _EVIDENCE_FIELDS}
    if normalized_source["request_evidence_sha256"] != (
        legacy_bridge_job_terminal_request_evidence_sha256(evidence)
    ):
        _fail("legacy terminal request evidence digest differs")
    return normalized_source


def validate_legacy_bridge_job_terminal_source(value: Any) -> dict[str, Any]:
    """Validate one canonical source document without granting authority."""

    normalized = _shared_source(value)
    if canonical_company_json_bytes(normalized) != canonical_company_json_bytes(value):
        _fail("legacy terminal source spelling is non-canonical")
    return normalized


def build_legacy_bridge_job_terminal_source(
    evidence: Mapping[str, Any],
    *,
    source_observation_id: str,
    source_observation_payload_sha256: str,
    source_observation_global_sequence: int,
) -> dict[str, Any]:
    """Complete adapter evidence with Supervisor-owned observation metadata."""

    if type(evidence) is not dict or frozenset(evidence) != _EVIDENCE_FIELDS:
        _fail("legacy terminal evidence fields are invalid")
    return validate_legacy_bridge_job_terminal_source({
        "source_type": LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1,
        "schema_version": 1,
        **dict(evidence),
        "source_observation_id": source_observation_id,
        "source_observation_payload_sha256": source_observation_payload_sha256,
        "source_observation_global_sequence": source_observation_global_sequence,
        "request_evidence_sha256": (
            legacy_bridge_job_terminal_request_evidence_sha256(evidence)
        ),
        "truth_boundary": dict(_TRUTH_BOUNDARY),
    })


def legacy_bridge_job_terminal_key_id(source: Mapping[str, Any]) -> str:
    normalized = validate_legacy_bridge_job_terminal_source(dict(source))
    return _digest(
        {
            "domain": "aoi.legacy-bridge.job-terminal-key.v1",
            "company_id": normalized["company_id"],
            "company_incarnation": normalized["company_incarnation"],
            "lock_domain_generation": normalized["lock_domain_generation"],
            "bridge_scope_id": normalized["bridge_scope_id"],
            "job_bridge_entity_id": normalized["job_bridge_entity_id"],
        },
        "legacy terminal key",
    )


def _receipt_unsigned(
    source: Mapping[str, Any],
    *,
    source_sha256: str,
    raw_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    item = validate_legacy_bridge_job_terminal_source(dict(source))
    source_sha = _sha(source_sha256, "legacy terminal source digest")
    raw = validate_blob_ref(raw_artifact)
    if (
        raw["availability"] != "available"
        or raw["media_type"] != LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE
        or raw["sha256"] != source_sha
    ):
        _fail("legacy terminal raw source reference is invalid")
    terminal_key = legacy_bridge_job_terminal_key_id(item)
    receipt_id = legacy_bridge_job_terminal_receipt_id(
        terminal_key,
        item["request_evidence_sha256"],
    )
    copied = {
        key: item[key]
        for key in (
            "company_id", "company_incarnation", "lock_domain_generation",
            "bridge_scope_id", "source_observation_id",
            "source_observation_payload_sha256",
            "source_observation_global_sequence", "request_evidence_sha256",
            "legacy_archive_sha256",
            "legacy_state_sha256", "task_identity_digest", "task_bridge_entity_id",
            "task_id", "task_source_record_sha256",
            "owner_packet_bridge_entity_id", "owner_packet_id",
            "owner_packet_source_record_sha256", "owner_packet_contract_sha256",
            "job_bridge_entity_id", "run_id", "job_source_record_sha256",
            "command_normalization", "command_sha256", "command_size_bytes",
            "host_fingerprint_sha256", "process_fingerprint_sha256",
            "closure_kind", "closure_scope", "exit_code", "artifacts",
            "terminal_at", "observed_at",
        )
    }
    return {
        "contract_type": LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
        "schema_version": 1,
        **copied,
        "terminal_key_id": terminal_key,
        "receipt_id": receipt_id,
        "engineering_status": "blocked",
        "runtime_status": "stopped",
        "coverage_status": "degraded",
        "effect_status": "failed_known",
        "source_sha256": source_sha,
        "raw_artifact": dict(raw),
        "provenance": "adapter_receipt_persisted",
        "observation": dict(_OBSERVATION),
    }


def build_legacy_bridge_job_terminal_receipt(
    source: Mapping[str, Any],
    *,
    source_sha256: str,
    raw_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Build and seal the one append-once terminal receipt for ``source``."""

    unsigned = _receipt_unsigned(
        source,
        source_sha256=source_sha256,
        raw_artifact=raw_artifact,
    )
    return validate_legacy_bridge_job_terminal_receipt(
        {**unsigned, "receipt_sha256": _digest(unsigned, "legacy terminal receipt")},
    )


def validate_legacy_bridge_job_terminal_receipt(value: Any) -> dict[str, Any]:
    """Validate receipt shape, source binding metadata, and evidence boundary."""

    item = _object(value, _RECEIPT_FIELDS, LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1)
    if item["contract_type"] != LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1 or type(
        item["schema_version"]
    ) is not int or item["schema_version"] != 1:
        _fail("legacy terminal receipt discriminator is invalid")
    raw = validate_blob_ref(item["raw_artifact"])
    if (
        raw["availability"] != "available"
        or raw["media_type"] != LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE
        or raw["sha256"] != _sha(item["source_sha256"], "legacy terminal source digest")
        or type(raw["size_bytes"]) is not int
        or not 1 <= raw["size_bytes"] <= MAX_LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_BYTES
    ):
        _fail("legacy terminal receipt raw source reference is invalid")
    if (
        _identifier(item["company_id"], "company id") != item["company_id"]
        or _integer(item["company_incarnation"], "company incarnation", minimum=1, maximum=999_999_999) != item["company_incarnation"]
        or _integer(item["lock_domain_generation"], "lock generation", minimum=0, maximum=999_999_999) != item["lock_domain_generation"]
        or any(_sha(item[field], field) != item[field] for field in (
            "bridge_scope_id", "source_observation_id",
            "source_observation_payload_sha256", "request_evidence_sha256",
            "legacy_archive_sha256",
            "legacy_state_sha256", "task_identity_digest",
            "task_bridge_entity_id", "task_source_record_sha256",
            "owner_packet_bridge_entity_id", "owner_packet_source_record_sha256",
            "owner_packet_contract_sha256", "job_bridge_entity_id",
            "job_source_record_sha256", "host_fingerprint_sha256",
            "process_fingerprint_sha256",
        ))
        or _identifier(item["task_id"], "task id") != item["task_id"]
        or _identifier(item["owner_packet_id"], "owner packet id") != item["owner_packet_id"]
        or _identifier(item["run_id"], "run id") != item["run_id"]
        or _integer(item["source_observation_global_sequence"], "source observation sequence", minimum=1, maximum=9_223_372_036_854_775_807) != item["source_observation_global_sequence"]
        or item["closure_kind"] != "process_exit_observed"
        or item["closure_scope"] != "registered_job_process"
        or _integer(item["exit_code"], "exit code", minimum=-2_147_483_648, maximum=2_147_483_647) == 0
        or _artifacts(item["artifacts"]) != item["artifacts"]
        or _timestamp(item["terminal_at"], "terminal time") != item["terminal_at"]
        or _timestamp(item["observed_at"], "observed time") != item["observed_at"]
        or item["observed_at"] != item["terminal_at"]
        or item["command_normalization"] != EXACT_COMMAND_NORMALIZATION_V1
        or _sha(item["command_sha256"], "legacy terminal command digest")
        != item["command_sha256"]
        or _integer(
            item["command_size_bytes"],
            "legacy terminal command size",
            minimum=1,
            maximum=MAX_LEGACY_BRIDGE_JOB_COMMAND_BYTES,
        )
        != item["command_size_bytes"]
        or item["engineering_status"] != "blocked"
        or item["runtime_status"] != "stopped"
        or item["coverage_status"] != "degraded"
        or item["effect_status"] != "failed_known"
        or item["provenance"] != "adapter_receipt_persisted"
        or item["observation"] != _OBSERVATION
    ):
        _fail("legacy terminal receipt truth boundary is invalid")
    terminal_key = _sha(item["terminal_key_id"], "legacy terminal key id")
    expected_key = _digest(
        {
            "domain": "aoi.legacy-bridge.job-terminal-key.v1",
            "company_id": item["company_id"],
            "company_incarnation": item["company_incarnation"],
            "lock_domain_generation": item["lock_domain_generation"],
            "bridge_scope_id": item["bridge_scope_id"],
            "job_bridge_entity_id": item["job_bridge_entity_id"],
        },
        "legacy terminal key",
    )
    receipt_id = _sha(item["receipt_id"], "legacy terminal receipt id")
    expected_receipt_id = legacy_bridge_job_terminal_receipt_id(
        terminal_key,
        item["request_evidence_sha256"],
    )
    if terminal_key != expected_key or receipt_id != expected_receipt_id:
        _fail("legacy terminal receipt identity differs")
    normalized_receipt = {
        key: (
            dict(raw)
            if key == "raw_artifact"
            else [dict(member) for member in item["artifacts"]]
            if key == "artifacts"
            else dict(_OBSERVATION)
            if key == "observation"
            else item[key]
        )
        for key in _RECEIPT_FIELDS
    }
    receipt_sha = _sha(item["receipt_sha256"], "legacy terminal receipt digest")
    unsigned = {
        key: member
        for key, member in normalized_receipt.items()
        if key != "receipt_sha256"
    }
    if receipt_sha != _digest(unsigned, "legacy terminal receipt"):
        _fail("legacy terminal receipt digest differs")
    normalized_receipt["receipt_sha256"] = receipt_sha
    return normalized_receipt


__all__ = [
    "LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1",
    "LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE",
    "LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_V1",
    "LegacyBridgeJobTerminalError",
    "MAX_LEGACY_BRIDGE_JOB_COMMAND_BYTES",
    "MAX_LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_BYTES",
    "build_legacy_bridge_job_terminal_source",
    "build_legacy_bridge_job_terminal_receipt",
    "legacy_bridge_job_terminal_receipt_id",
    "legacy_bridge_job_terminal_ledger_recorded_at",
    "legacy_bridge_job_terminal_request_evidence_sha256",
    "legacy_bridge_job_terminal_key_id",
    "validate_legacy_bridge_job_terminal_receipt",
    "validate_legacy_bridge_job_terminal_source",
]
