"""Durable health truth for the read-only legacy-company bridge.

This contract records only what the Supervisor observed while importing one
bounded legacy snapshot.  It never grants legacy mutation, dispatch, or job
launch authority, and it explicitly does not claim that a legacy PreToolUse
gate enforced the observation.
"""
from __future__ import annotations

from datetime import datetime
import re
from typing import Any, NoReturn

from .contracts import (
    MAX_CONTRACT_BYTES,
    CompanyContractError,
    company_contract_sha256,
)
from .legacy_bridge import LegacyBridgeCompanyKey
from .legacy_bridge_contract import legacy_bridge_scope_id


LEGACY_BRIDGE_COVERAGE_V1 = "LegacyBridgeCoverageObservationV1"
LEGACY_BRIDGE_PUBLISHER_VERSION = 1
MAX_SOURCE_DOCUMENT_BYTES = MAX_CONTRACT_BYTES + 1

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_FAILURE_REASONS = frozenset(
    {"snapshot_invalid", "binding_mismatch", "projection_unpublishable"},
)
_TRUTH = {
    "authority": "none",
    "repo_write_capability": "absent",
    "dispatch_capability": "absent",
    "job_launch_capability": "absent",
    "legacy_spawn_job_preflight": "not_enforced_by_observation_bridge",
}


class LegacyBridgeHealthError(CompanyContractError):
    """A bridge-health fact is malformed or overstates its evidence."""


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeHealthError(message)


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
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        _fail(f"{label} is invalid: {exc}")
    if parsed.tzinfo is None:
        _fail(f"{label} lacks a timezone")
    return value


def _nullable_sha(value: Any, label: str) -> str | None:
    return None if value is None else _sha(value, label)


def legacy_bridge_attempt_id(
    bridge_scope_id: str,
    *,
    source_document_sha256: str,
    source_document_size_bytes: int,
) -> str:
    """Derive one replay identity independent of intake wall time."""

    return company_contract_sha256(
        {
            "domain": "aoi.legacy-bridge.ingest-attempt.v1",
            "publisher_version": LEGACY_BRIDGE_PUBLISHER_VERSION,
            "bridge_scope_id": _sha(bridge_scope_id, "bridge scope id"),
            "source_document_sha256": _sha(
                source_document_sha256,
                "source document digest",
            ),
            "source_document_size_bytes": _integer(
                source_document_size_bytes,
                "source document size",
                minimum=0,
                maximum=MAX_SOURCE_DOCUMENT_BYTES,
            ),
        }
    )


def validate_legacy_bridge_coverage(value: Any) -> dict[str, Any]:
    fields = frozenset(
        {
            "contract_type", "schema_version", "company_id",
            "company_incarnation", "lock_domain_generation",
            "bridge_scope_id", "assessment_id", "publisher_version",
            "source_document_sha256", "source_document_size_bytes",
            "legacy_archive_sha256", "task_identity_digest",
            "ingest_state", "coverage_state", "reason", "assessed_at",
            "observation_id", "coverage_completeness",
            "authority", "repo_write_capability", "dispatch_capability",
            "job_launch_capability", "legacy_spawn_job_preflight",
            "coverage_sha256",
        }
    )
    item = _object(value, fields, LEGACY_BRIDGE_COVERAGE_V1)
    if (
        item["contract_type"] != LEGACY_BRIDGE_COVERAGE_V1
        or type(item["schema_version"]) is not int
        or item["schema_version"] != 1
        or type(item["publisher_version"]) is not int
        or item["publisher_version"] != LEGACY_BRIDGE_PUBLISHER_VERSION
    ):
        _fail("legacy bridge coverage discriminator is invalid")
    key = LegacyBridgeCompanyKey(
        _identifier(item["company_id"], "company id"),
        _integer(
            item["company_incarnation"],
            "company incarnation",
            minimum=1,
            maximum=999_999_999,
        ),
        _integer(
            item["lock_domain_generation"],
            "lock generation",
            minimum=0,
            maximum=999_999_999,
        ),
    )
    archive = _sha(item["legacy_archive_sha256"], "legacy archive digest")
    task = _sha(item["task_identity_digest"], "task identity digest")
    scope = _sha(item["bridge_scope_id"], "bridge scope id")
    if scope != legacy_bridge_scope_id(
        key,
        legacy_archive_sha256=archive,
        task_identity_digest=task,
    ):
        _fail("legacy bridge coverage scope differs")
    source_sha = _sha(item["source_document_sha256"], "source document digest")
    source_size = _integer(
        item["source_document_size_bytes"],
        "source document size",
        minimum=0,
        maximum=MAX_SOURCE_DOCUMENT_BYTES,
    )
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=source_sha,
        source_document_size_bytes=source_size,
    )
    assessment = _sha(item["assessment_id"], "coverage assessment id")
    expected_assessment = company_contract_sha256(
        {"domain": "aoi.legacy-bridge.coverage.v1", "attempt_id": attempt}
    )
    if assessment != expected_assessment:
        _fail("legacy bridge coverage assessment id differs")
    ingest_state = item["ingest_state"]
    reason = item["reason"]
    observation = _nullable_sha(item["observation_id"], "observation id")
    if ingest_state == "observed":
        if reason != "provider_runtime_unavailable" or observation is None:
            _fail("observed bridge ingest truth is invalid")
        completeness = "legacy_state_inventory_only_provider_runtime_unavailable"
    elif ingest_state == "degraded":
        if (
            type(reason) is not str
            or reason not in _FAILURE_REASONS
            or observation is not None
        ):
            _fail("degraded bridge ingest reason is invalid")
        completeness = "legacy_bridge_ingest_failed"
    else:
        _fail("legacy bridge ingest state is invalid")
    if (
        item["coverage_state"] != "degraded"
        or item["coverage_completeness"] != completeness
        or any(item[field] != expected for field, expected in _TRUTH.items())
    ):
        _fail("legacy bridge coverage truth boundary is invalid")
    normalized = {
        "contract_type": LEGACY_BRIDGE_COVERAGE_V1,
        "schema_version": 1,
        **key._asdict(),
        "bridge_scope_id": scope,
        "assessment_id": assessment,
        "publisher_version": LEGACY_BRIDGE_PUBLISHER_VERSION,
        "source_document_sha256": source_sha,
        "source_document_size_bytes": source_size,
        "legacy_archive_sha256": archive,
        "task_identity_digest": task,
        "ingest_state": ingest_state,
        "coverage_state": "degraded",
        "reason": reason,
        "assessed_at": _timestamp(item["assessed_at"], "coverage assessed_at"),
        "observation_id": observation,
        "coverage_completeness": completeness,
        **_TRUTH,
        "coverage_sha256": _sha(item["coverage_sha256"], "coverage digest"),
    }
    unsigned = {
        key: member
        for key, member in normalized.items()
        if key != "coverage_sha256"
    }
    if normalized["coverage_sha256"] != company_contract_sha256(unsigned):
        _fail("legacy bridge coverage digest differs")
    return normalized


def build_legacy_bridge_coverage(
    key: LegacyBridgeCompanyKey,
    *,
    legacy_archive_sha256: str,
    task_identity_digest: str,
    source_document_sha256: str,
    source_document_size_bytes: int,
    ingest_state: str,
    reason: str,
    assessed_at: str,
    observation_id: str | None,
) -> dict[str, Any]:
    """Seal one Supervisor-observed ingest outcome without adding authority."""

    scope = legacy_bridge_scope_id(
        key,
        legacy_archive_sha256=legacy_archive_sha256,
        task_identity_digest=task_identity_digest,
    )
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=source_document_sha256,
        source_document_size_bytes=source_document_size_bytes,
    )
    completeness = (
        "legacy_state_inventory_only_provider_runtime_unavailable"
        if ingest_state == "observed"
        else "legacy_bridge_ingest_failed"
    )
    unsigned = {
        "contract_type": LEGACY_BRIDGE_COVERAGE_V1,
        "schema_version": 1,
        **key._asdict(),
        "bridge_scope_id": scope,
        "assessment_id": company_contract_sha256(
            {"domain": "aoi.legacy-bridge.coverage.v1", "attempt_id": attempt}
        ),
        "publisher_version": LEGACY_BRIDGE_PUBLISHER_VERSION,
        "source_document_sha256": source_document_sha256,
        "source_document_size_bytes": source_document_size_bytes,
        "legacy_archive_sha256": legacy_archive_sha256,
        "task_identity_digest": task_identity_digest,
        "ingest_state": ingest_state,
        "coverage_state": "degraded",
        "reason": reason,
        "assessed_at": assessed_at,
        "observation_id": observation_id,
        "coverage_completeness": completeness,
        **_TRUTH,
    }
    return validate_legacy_bridge_coverage(
        {**unsigned, "coverage_sha256": company_contract_sha256(unsigned)}
    )


__all__ = [
    "LEGACY_BRIDGE_COVERAGE_V1",
    "LEGACY_BRIDGE_PUBLISHER_VERSION",
    "MAX_SOURCE_DOCUMENT_BYTES",
    "LegacyBridgeHealthError",
    "build_legacy_bridge_coverage",
    "legacy_bridge_attempt_id",
    "validate_legacy_bridge_coverage",
]
