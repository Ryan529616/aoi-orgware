"""Strict, bounded, dependency-free v0.5 company data contracts.

These functions are intentionally pure: they neither create authority nor write
the company ledger.  They give the future Supervisor one canonical payload
boundary and reject unrecognised fields, unbounded collections, and ambiguous
missing values before persistence.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from datetime import datetime
import hashlib
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any, Callable, NoReturn
import unicodedata

from ..semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


COMPANY_CONTRACT_SCHEMA_VERSION = 1
MAX_CONTRACT_BYTES = 256 * 1024
MAX_TEXT_BYTES = 4096
MAX_SHORT_TEXT_BYTES = 512
MAX_LIST_ITEMS = 256
MAX_EVENT_PAYLOAD_BYTES = 64 * 1024
MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES = 64 * 1024
MAX_PROVIDER_TELEMETRY_RAW_BYTES = 1024 * 1024
MAX_NEEDS_USER_CONTENT_BYTES = 64 * 1024
MAX_TRANSACTION_EVENTS = 64
MAX_DEPTH = 6
MAX_EXECUTION_DEPTH = 64
ZERO_SHA256 = "0" * 64

COMPANY_MANIFEST_V1 = "company_manifest_v1"
ACTOR_AUTHORITY_V1 = "actor_authority_v1"
AUTHORITY_GRANT_V1 = "authority_grant_v1"
CONTROL_INTENT_V1 = "control_intent_v1"
DEPARTMENT_LIFECYCLE_REQUEST_V1 = "department_lifecycle_request_v1"
DEPARTMENT_LIFECYCLE_RESULT_V1 = "department_lifecycle_result_v1"
DEPARTMENT_LIFECYCLE_RECEIPT_V1 = "department_lifecycle_receipt_v1"
DEPARTMENT_SNAPSHOT_DOCUMENT_V1 = "department_snapshot_document_v1"
DEPARTMENT_SNAPSHOT_MEDIA_TYPE = "application/vnd.aoi.department-snapshot+json;version=1"
TASK_REVISION_V1 = "task_revision_v1"
WORK_PACKET_V1 = "work_packet_v1"
WORK_CONTEXT_MANIFEST_V1 = "work_context_manifest_v1"
WORK_CONTEXT_MANIFEST_MEDIA_TYPE = (
    "application/vnd.aoi.work-context-manifest+json;version=1"
)
WORK_PACKET_PROMPT_MEDIA_TYPE = (
    "application/vnd.aoi.work-packet-prompt+text;version=1"
)
WORK_RESULT_RECEIPT_V1 = "work_result_receipt_v1"
WORK_DISPATCH_BINDING_V1 = "work_dispatch_binding_v1"
WORK_DEFINITION_ENFORCEMENT_V1 = "work_definition_enforcement_v1"
EXPECTED_HEAD_V1 = "expected_head_v1"
EXPECTED_TRANSACTION_HEAD_V1 = "expected_transaction_head_v1"
BLOB_REF_V1 = "blob_ref_v1"
TAKEOVER_CAPABILITY_V1 = "takeover_capability_v1"
TAKEOVER_CONSUMPTION_RECEIPT_V1 = "takeover_consumption_receipt_v1"
COMPANY_EVENT_V1 = "company_event_v1"
COMPANY_TRANSACTION_REQUEST_V1 = "company_transaction_request_v1"
COMPANY_TRANSACTION_RECEIPT_V1 = "company_transaction_receipt_v1"
ORGANIZATION_NODE_V1 = "organization_node_v1"
DEPARTMENT_IDENTITY_V1 = "department_identity_v1"
DEPARTMENT_SNAPSHOT_V1 = "department_snapshot_v1"
CHIEF_TERM_V1 = "chief_term_v1"
CARRIER_BINDING_V1 = "carrier_binding_v1"
EXECUTION_NODE_V1 = "execution_node_v1"
EXECUTION_EVENT_V1 = "execution_event_v1"
EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE = (
    "application/vnd.aoi.execution-event+json;version=1"
)
MUTATION_INTENT_V1 = "mutation_intent_v1"
EXTERNAL_JOB_V1 = "external_job_v1"
DISPATCH_REQUEST_V1 = "dispatch_request_v1"
PROVIDER_LIFECYCLE_RECEIPT_V1 = "provider_lifecycle_receipt_v1"
PROVIDER_LIFECYCLE_SOURCE_V1 = "provider_lifecycle_source_v1"
PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE = (
    "application/vnd.aoi.provider-lifecycle-source+json;version=1"
)
EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1 = (
    "execution_runtime_observation_receipt_v1"
)
EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1 = (
    "execution_runtime_observation_source_v1"
)
EXECUTION_RUNTIME_OBSERVATION_SOURCE_MEDIA_TYPE = (
    "application/vnd.aoi.execution-runtime-observation+json;version=1"
)
ENGINEERING_DISPOSITION_RECEIPT_V1 = (
    "engineering_disposition_receipt_v1"
)
ENGINEERING_DISPOSITION_SOURCE_V1 = (
    "engineering_disposition_source_v1"
)
ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE = (
    "application/vnd.aoi.engineering-disposition-source+json;version=1"
)
PROVIDER_TELEMETRY_RECEIPT_V1 = "provider_telemetry_receipt_v1"
PROVIDER_TELEMETRY_RAW_MEDIA_TYPE = (
    "application/vnd.aoi.provider-telemetry.raw;version=1"
)
PROVIDER_COVERAGE_REVISION_V1 = "provider_coverage_revision_v1"
USAGE_COUNTER_SAMPLE_V1 = "usage_counter_sample_v1"
NEEDS_USER_REVISION_V1 = "needs_user_revision_v1"
NEEDS_USER_QUESTION_MEDIA_TYPE = (
    "application/vnd.aoi.needs-user-question+json;version=1"
)
NEEDS_USER_ANSWER_MEDIA_TYPE = (
    "application/vnd.aoi.needs-user-answer+json;version=1"
)
EXTERNAL_JOB_EFFECT_SOURCE_V1 = "external_job_effect_source_v1"
EXTERNAL_JOB_EFFECT_RECEIPT_V1 = "external_job_effect_receipt_v1"
EXTERNAL_JOB_EFFECT_SOURCE_MEDIA_TYPE = (
    "application/vnd.aoi.external-job-effect-source+json;version=1"
)
EVIDENCE_RECORD_V1 = "evidence_record_v1"
ARTIFACT_EDGE_V1 = "artifact_edge_v1"
USAGE_EVENT_V1 = "usage_event_v1"
USAGE_BURN_REVISION_V1 = "usage_burn_revision_v1"
RATE_CARD_V1 = "rate_card_v1"
ALERT_V1 = "alert_v1"
NEEDS_USER_V1 = "needs_user_v1"
ROUTE_POLICY_V1 = "route_policy_v1"
OPTIMIZER_PROPOSAL_V1 = "optimizer_proposal_v1"
CANARY_V1 = "canary_v1"
BACKUP_ENVELOPE_V1 = "backup_envelope_v1"
CRYPTO_VERIFICATION_RECEIPT_V1 = "crypto_verification_receipt_v1"
PROVIDER_CODEX_HOME_V1 = "provider_codex_home_v1"
PROVIDER_LAUNCH_BINDING_V1 = "provider_launch_binding_v1"
PROVIDER_WORKER_IO_RECEIPT_V1 = "provider_worker_io_receipt_v1"
PROVIDER_WORKER_OPERATION_V1 = "provider_worker_operation_v1"
PROVIDER_TURN_RESULT_RECEIPT_V1 = "provider_turn_result_receipt_v1"
PROVIDER_TURN_RESULT_V1 = "provider_turn_result_v1"
PROVIDER_WORKER_RAW_MEDIA_TYPE = (
    "application/vnd.aoi.provider-worker.raw;version=1"
)
PROVIDER_TURN_RESULT_MEDIA_TYPE = (
    "application/vnd.aoi.provider-turn-result+json;version=1"
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_STREAMS = frozenset({"org", "execution", "evidence", "usage", "alert"})
_PROVENANCE = frozenset({
    "provider_client_emitted", "adapter_receipt_persisted", "collector_received",
    "host_process_observed", "agent_reported", "AOI_verified", "unknown",
})
_OBSERVATION = frozenset({"known", "unknown", "unavailable", "partial"})
_MUTATION_STATES = frozenset({
    "prepared", "admitted", "in_flight", "committed", "failed_known",
    "effect_unknown", "reconcile_required", "aborted", "unknown",
})
_TOKEN_DIMENSIONS = (
    "input", "cache_read", "cache_creation", "output", "reasoning_output", "total",
)
_TAKEOVER_OUTCOMES = frozenset({"consumed", "fenced"})
_MUTATION_PERMISSIONS = frozenset({
    "company.mutate", "repo.write", "job.start", "policy.change", "release.publish",
})
_MUTATION_KIND_PERMISSIONS = {
    "repo.write": "repo.write", "job.start": "job.start",
    "policy.change": "policy.change", "release.publish": "release.publish",
}
_TERMINAL_MUTATION_STATES = frozenset({
    "committed", "failed_known", "effect_unknown", "reconcile_required", "aborted",
})
_DISPATCH_REQUEST_STATES = frozenset({
    "queued", "admitted", "in_flight", "dispatched", "effect_unknown",
    "failed_known", "cancelled",
})
_PROVIDER_RECEIPT_PROVENANCE = frozenset({
    "provider_client_emitted",
    "adapter_receipt_persisted",
    "collector_received",
    "host_process_observed",
})
_CODEX_APP_SERVER_REQUEST_METHODS = frozenset({
    "initialize", "model/list", "thread/start", "turn/start", "turn/interrupt",
})
_CODEX_APP_SERVER_CLIENT_NOTIFICATION_METHODS = frozenset({"initialized"})
# This is the generated App Server 0.145.0 ServerNotification method union,
# copied as a contract pin rather than inferred from a wire direction or a
# broadly named event.  Changing this set is a protocol migration.
_CODEX_APP_SERVER_SERVER_NOTIFICATION_METHODS = frozenset({
    "account/login/completed", "account/rateLimits/updated", "account/updated",
    "app/list/updated", "command/exec/outputDelta", "configWarning",
    "deprecationNotice", "error", "externalAgentConfig/import/completed",
    "externalAgentConfig/import/progress", "fs/changed",
    "fuzzyFileSearch/sessionCompleted", "fuzzyFileSearch/sessionUpdated",
    "guardianWarning", "hook/completed", "hook/started", "item/agentMessage/delta",
    "item/autoApprovalReview/completed", "item/autoApprovalReview/started",
    "item/commandExecution/outputDelta", "item/commandExecution/terminalInteraction",
    "item/fileChange/outputDelta", "item/fileChange/patchUpdated",
    "item/mcpToolCall/progress", "item/completed", "item/plan/delta",
    "item/reasoning/summaryPartAdded", "item/reasoning/summaryTextDelta",
    "item/reasoning/textDelta", "item/started", "mcpServer/oauthLogin/completed",
    "mcpServer/startupStatus/updated", "model/rerouted", "model/safetyBuffering/updated",
    "model/verification", "process/exited", "process/outputDelta",
    "remoteControl/status/changed", "serverRequest/resolved", "skills/changed",
    "thread/archived", "thread/closed", "thread/compacted", "thread/deleted",
    "thread/environment/connected", "thread/environment/disconnected",
    "thread/goal/cleared", "thread/goal/updated", "thread/name/updated",
    "thread/realtime/closed", "thread/realtime/error", "thread/realtime/itemAdded",
    "thread/realtime/outputAudio/delta", "thread/realtime/sdp", "thread/realtime/started",
    "thread/realtime/transcript/delta", "thread/realtime/transcript/done",
    "thread/settings/updated", "thread/started", "thread/status/changed", "thread/tokenUsage/updated",
    "thread/unarchived", "turn/completed", "turn/diff/updated",
    "turn/moderationMetadata", "turn/plan/updated", "turn/started", "warning",
    "windows/worldWritableWarning", "windowsSandbox/setupCompleted",
})
_EXTERNAL_JOB_EFFECT_STATES = frozenset({
    "running", "completed", "failed_known", "effect_unknown",
    "reconcile_required", "aborted",
})
_EXTERNAL_JOB_EFFECT_PREVIOUS_STATES = frozenset({
    "queued", "running", "effect_unknown", "reconcile_required", "unknown",
})
_EXTERNAL_JOB_EFFECT_TRANSITIONS = {
    "queued": frozenset({"running", "effect_unknown", "aborted"}),
    "running": frozenset({"completed", "failed_known", "effect_unknown"}),
    "effect_unknown": frozenset({
        "reconcile_required", "completed", "failed_known",
    }),
    "reconcile_required": frozenset({"completed", "failed_known"}),
    "unknown": frozenset({"effect_unknown"}),
}
_EXTERNAL_JOB_EFFECT_UNCERTAIN_STATES = frozenset({
    "effect_unknown", "reconcile_required",
})
_EXTERNAL_JOB_EFFECT_PROVENANCE = frozenset({
    "provider_client_emitted",
    "adapter_receipt_persisted",
    "collector_received",
    "host_process_observed",
    "agent_reported",
})
_PROVIDER_LIFECYCLE_EVENTS = frozenset({
    "dispatch_succeeded",
    "dispatch_failed",
    "dispatch_effect_unknown",
    "execution_stopped",
})
_DEPARTMENT_OPERATIONS = frozenset({"park", "resume", "enqueue"})
_DEPARTMENT_TRIGGERS = frozenset({"explicit", "lazy_wake", "idle_policy"})
_DEPARTMENT_STATUSES = frozenset({"active", "parked"})
_DEPARTMENT_LEAD_STATUSES = frozenset({"active", "idle", "parked"})
_DEPARTMENT_LIFECYCLE_STATES = frozenset({"parked", "waking", "active", "idle", "unknown"})
_CARRIER_TRANSITIONS = frozenset({"none", "parked", "pending", "resumed", "replaced"})
_CARRIER_STATES = frozenset({"active", "parked", "lost", "fenced", "unknown"})
_SNAPSHOT_CAPTURE_REASONS = frozenset({"genesis", "park", "checkpoint", "handoff"})
_WORK_MANIFEST_ENTRY_TYPES = frozenset({
    "file", "directory", "artifact", "package", "tool",
})
_WORK_AUTHORITY_REF_KINDS = frozenset({"file", "tree"})
_WINDOWS_RESERVED_DEVICE_ALIASES = frozenset({
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
})
_WORK_NULL_RELATIONSHIP_KEYS = frozenset({
    "manager_node_id", "parent_execution_id", "target_node_id", "department_id",
})


class CompanyContractError(ValueError):
    """A v0.5 company contract is malformed, unbounded, or ambiguous."""


def _fail(message: str) -> NoReturn:
    raise CompanyContractError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(f"{label} is invalid")
    try:
        if len(value.encode("utf-8")) > maximum:
            _fail(f"{label} is too large")
    except UnicodeEncodeError as exc:
        raise CompanyContractError(f"{label} is invalid Unicode") from exc
    return value


def _id(value: Any, label: str) -> str:
    text = _text(value, label, maximum=256)
    if not _ID.fullmatch(text):
        _fail(f"{label} is not a canonical identifier")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, maximum=64)
    if not _TIMESTAMP.fullmatch(text):
        _fail(f"{label} is not an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise CompanyContractError(f"{label} is not a real timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"{label} requires a timezone")
    return text


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _enum(value: Any, label: str, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        _fail(f"{label} is invalid")
    return value


def _bounded_list(value: Any, label: str, item: Callable[[Any, str], Any], *, maximum: int = MAX_LIST_ITEMS) -> list[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence) or len(value) > maximum:
        _fail(f"{label} is invalid")
    return [item(member, f"{label}[{index}]") for index, member in enumerate(value)]


def _canonical(value: Any, label: str, *, maximum: int = MAX_CONTRACT_BYTES) -> Any:
    try:
        return copy.deepcopy(value) if len(canonical_json_bytes(value, max_bytes=maximum)) >= 0 else None
    except SemanticEventError as exc:
        raise CompanyContractError(f"{label}: {exc}") from exc


def canonical_company_json_bytes(value: Any, *, max_bytes: int = MAX_CONTRACT_BYTES) -> bytes:
    """Return the canonical UTF-8 representation after v0.5 size admission."""
    try:
        result: bytes = canonical_json_bytes(value, max_bytes=max_bytes)
        return result
    except SemanticEventError as exc:
        raise CompanyContractError(f"canonical company JSON is invalid: {exc}") from exc


def company_contract_sha256(value: Any, *, max_bytes: int = MAX_CONTRACT_BYTES) -> str:
    """Return the SHA-256 of canonical company JSON, without accepting a schema."""
    try:
        result: str = canonical_sha256(value, max_bytes=max_bytes)
        return result
    except SemanticEventError as exc:
        raise CompanyContractError(f"company contract hash is invalid: {exc}") from exc


def _header(item: Mapping[str, Any], contract_type: str, fields: set[str], label: str) -> dict[str, Any]:
    result = _object(item, fields, label)
    if result["contract_type"] != contract_type:
        _fail(f"{label}.contract_type is invalid")
    if _integer(
        result["schema_version"],
        f"{label}.schema_version",
        minimum=COMPANY_CONTRACT_SCHEMA_VERSION,
        maximum=COMPANY_CONTRACT_SCHEMA_VERSION,
    ) != COMPANY_CONTRACT_SCHEMA_VERSION:
        _fail(f"{label}.schema_version is unsupported")
    return result


def _company_binding(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} binding is invalid")
    missing = {"company_id", "company_incarnation", "lock_domain_generation"} - set(value)
    if missing:
        _fail(f"{label} binding is incomplete")
    item = dict(value)
    return {
        "company_id": _id(item["company_id"], f"{label}.company_id"),
        "company_incarnation": _integer(item["company_incarnation"], f"{label}.company_incarnation", minimum=1, maximum=999_999_999),
        "lock_domain_generation": _integer(item["lock_domain_generation"], f"{label}.lock_domain_generation", maximum=999_999_999),
    }


def _embedded_binding(item: Mapping[str, Any], label: str) -> dict[str, Any]:
    return _company_binding({key: item[key] for key in ("company_id", "company_incarnation", "lock_domain_generation")}, label)


def _observation(value: Any, label: str) -> dict[str, str]:
    item = _object(value, {"state", "reason"}, label)
    state = _enum(item["state"], f"{label}.state", _OBSERVATION)
    reason = _text(item["reason"], f"{label}.reason", maximum=MAX_SHORT_TEXT_BYTES)
    if state == "known" and reason != "observed":
        _fail(f"{label}.reason must be observed when known")
    if state != "known" and reason == "observed":
        _fail(f"{label}.reason must explain non-known state")
    return {"state": state, "reason": reason}


def validate_actor_authority(value: Any) -> dict[str, Any]:
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "actor_id", "actor_kind", "carrier_id", "chief_epoch", "term", "authority_state", "permissions", "scope_sha256", "authority_record_sha256", "provenance"}
    item = _header(value, ACTOR_AUTHORITY_V1, fields, "ActorAuthority")
    binding = _embedded_binding(item, "ActorAuthority")
    kind = _enum(item["actor_kind"], "ActorAuthority.actor_kind", frozenset({"user", "chief", "department_lead", "worker", "adapter", "supervisor"}))
    state = _enum(item["authority_state"], "ActorAuthority.authority_state", frozenset({"active", "fenced", "read_only", "unknown"}))
    carrier_id = _nullable_id(item["carrier_id"], "ActorAuthority.carrier_id")
    epoch = item["chief_epoch"]
    if kind in {"user", "supervisor"} and carrier_id is not None:
        _fail("ActorAuthority user/supervisor cannot bind a carrier")
    if kind not in {"user", "supervisor"} and carrier_id is None:
        _fail("ActorAuthority carrier is required for provider actors")
    if kind == "chief":
        if state == "unknown":
            if epoch is not None:
                _fail("unknown chief authority cannot assert chief_epoch")
        elif epoch is None:
            _fail("known chief authority requires chief_epoch")
        else:
            epoch = _integer(epoch, "ActorAuthority.chief_epoch", minimum=1, maximum=999_999_999)
    elif epoch is not None:
        _fail("ActorAuthority non-chief cannot assert chief_epoch")
    permissions = _bounded_list(item["permissions"], "ActorAuthority.permissions", _id, maximum=32)
    if len(set(permissions)) != len(permissions):
        _fail("ActorAuthority.permissions contains duplicates")
    if not set(permissions) <= _MUTATION_PERMISSIONS:
        _fail("ActorAuthority.permissions contains an unknown permission")
    if state == "unknown" and permissions:
        _fail("unknown authority cannot assert permissions")
    if state != "active" and permissions:
        _fail("non-active authority cannot assert mutation permissions")
    provenance = _enum(item["provenance"], "ActorAuthority.provenance", _PROVENANCE)
    if state == "active" and permissions and provenance == "unknown":
        _fail("active ActorAuthority mutation permissions require non-unknown provenance")
    if state == "unknown" and provenance != "unknown":
        _fail("unknown ActorAuthority requires unknown provenance")
    return {"contract_type": ACTOR_AUTHORITY_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding,
            "actor_id": _id(item["actor_id"], "ActorAuthority.actor_id"),
            "actor_kind": kind, "carrier_id": carrier_id, "chief_epoch": epoch,
            "term": _integer(item["term"], "ActorAuthority.term", minimum=1, maximum=999_999_999),
            "authority_state": state, "permissions": permissions,
            "scope_sha256": _sha256(item["scope_sha256"], "ActorAuthority.scope_sha256"),
            "authority_record_sha256": _sha256(item["authority_record_sha256"], "ActorAuthority.authority_record_sha256"),
            "provenance": provenance}


def validate_authority_grant(value: Any) -> dict[str, Any]:
    """Validate the immutable authority material from which authority derives."""
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "grant_id", "actor_id", "actor_kind", "carrier_id", "chief_epoch", "term", "authority_state", "permissions", "scope_sha256", "issued_at", "expires_at", "provenance", "grant_sha256"}
    item = _header(value, AUTHORITY_GRANT_V1, fields, "AuthorityGrant")
    binding = _embedded_binding(item, "AuthorityGrant")
    kind = _enum(item["actor_kind"], "AuthorityGrant.actor_kind", frozenset({"user", "chief", "department_lead", "worker", "adapter", "supervisor"}))
    state = _enum(item["authority_state"], "AuthorityGrant.authority_state", frozenset({"active", "fenced", "read_only", "unknown"}))
    carrier_id = _nullable_id(item["carrier_id"], "AuthorityGrant.carrier_id")
    epoch = item["chief_epoch"]
    if kind in {"user", "supervisor"} and carrier_id is not None:
        _fail("AuthorityGrant user/supervisor cannot bind a carrier")
    if kind not in {"user", "supervisor"} and carrier_id is None:
        _fail("AuthorityGrant carrier is required for provider actors")
    if kind == "chief":
        if state == "unknown":
            if epoch is not None:
                _fail("unknown chief grant cannot assert chief_epoch")
        elif epoch is None:
            _fail("known chief grant requires chief_epoch")
        else:
            epoch = _integer(epoch, "AuthorityGrant.chief_epoch", minimum=1, maximum=999_999_999)
    elif epoch is not None:
        _fail("AuthorityGrant non-chief cannot assert chief_epoch")
    permissions = _bounded_list(item["permissions"], "AuthorityGrant.permissions", _id, maximum=32)
    if len(set(permissions)) != len(permissions) or not set(permissions) <= _MUTATION_PERMISSIONS:
        _fail("AuthorityGrant.permissions is invalid")
    provenance = _enum(item["provenance"], "AuthorityGrant.provenance", _PROVENANCE)
    issued_at = _timestamp(item["issued_at"], "AuthorityGrant.issued_at")
    expires_at = None if item["expires_at"] is None else _timestamp(item["expires_at"], "AuthorityGrant.expires_at")
    if expires_at is not None and _parsed_timestamp(expires_at) <= _parsed_timestamp(issued_at):
        _fail("AuthorityGrant.expires_at must follow issued_at")
    if state == "active":
        if not permissions or provenance == "unknown" or expires_at is None:
            _fail("active AuthorityGrant requires permissions, provenance, and expiry")
    elif permissions:
        _fail("non-active AuthorityGrant cannot assert mutation permissions")
    if state == "unknown" and (provenance != "unknown" or expires_at is not None):
        _fail("unknown AuthorityGrant requires unknown provenance and expiry")
    unsigned = {key: item[key] for key in fields - {"grant_sha256"}}
    grant_sha256 = _sha256(item["grant_sha256"], "AuthorityGrant.grant_sha256")
    if grant_sha256 != company_contract_sha256(unsigned):
        _fail("AuthorityGrant.grant_sha256 differs")
    return {"contract_type": AUTHORITY_GRANT_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding,
            "grant_id": _id(item["grant_id"], "AuthorityGrant.grant_id"), "actor_id": _id(item["actor_id"], "AuthorityGrant.actor_id"),
            "actor_kind": kind, "carrier_id": carrier_id, "chief_epoch": epoch,
            "term": _integer(item["term"], "AuthorityGrant.term", minimum=1, maximum=999_999_999),
            "authority_state": state, "permissions": permissions, "scope_sha256": _sha256(item["scope_sha256"], "AuthorityGrant.scope_sha256"),
            "issued_at": issued_at, "expires_at": expires_at, "provenance": provenance, "grant_sha256": grant_sha256}


def authority_from_grant(value: Any) -> dict[str, Any]:
    """Derive the only ActorAuthority permitted by an AuthorityGrant."""
    grant = validate_authority_grant(value)
    return validate_actor_authority({
        "contract_type": ACTOR_AUTHORITY_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION,
        **_company_binding(grant, "AuthorityGrant"), "actor_id": grant["actor_id"],
        "actor_kind": grant["actor_kind"], "carrier_id": grant["carrier_id"],
        "chief_epoch": grant["chief_epoch"], "term": grant["term"],
        "authority_state": grant["authority_state"], "permissions": grant["permissions"],
        "scope_sha256": grant["scope_sha256"], "authority_record_sha256": grant["grant_sha256"],
        "provenance": grant["provenance"],
    })


def validate_control_intent(value: Any) -> dict[str, Any]:
    """Validate a terminal, replay-safe Supervisor control intent."""
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "control_intent_id", "command_id", "execution_id", "authority_grant", "authority_grant_sha256", "request_payload", "request_sha256", "outcome", "result_payload", "result_sha256", "receipt_id", "terminal_receipt", "receipt_sha256", "created_at", "terminal_at", "provenance", "observation"}
    item = _header(value, CONTROL_INTENT_V1, fields, "ControlIntent")
    binding = _embedded_binding(item, "ControlIntent")
    grant = validate_authority_grant(item["authority_grant"])
    if _company_binding(grant, "ControlIntent.authority_grant") != binding:
        _fail("ControlIntent authority grant binding differs")
    if _sha256(item["authority_grant_sha256"], "ControlIntent.authority_grant_sha256") != grant["grant_sha256"]:
        _fail("ControlIntent authority grant digest differs")
    authority = authority_from_grant(grant)
    if authority["authority_state"] != "active" or "company.mutate" not in authority["permissions"]:
        _fail("ControlIntent requires active company.mutate authority")
    request = _canonical(item["request_payload"], "ControlIntent.request_payload", maximum=MAX_EVENT_PAYLOAD_BYTES)
    result = _canonical(item["result_payload"], "ControlIntent.result_payload", maximum=MAX_EVENT_PAYLOAD_BYTES)
    has_department_request = isinstance(request, Mapping) and request.get("request_type") == DEPARTMENT_LIFECYCLE_REQUEST_V1
    has_department_result = isinstance(result, Mapping) and result.get("result_type") == DEPARTMENT_LIFECYCLE_RESULT_V1
    if has_department_request != has_department_result:
        _fail("ControlIntent department lifecycle request and result must pair")
    department_request = (
        validate_department_lifecycle_request(request)
        if has_department_request
        else None
    )
    department_result = (
        validate_department_lifecycle_result(result, request=department_request)
        if has_department_result
        else None
    )
    if department_request is not None:
        if _company_binding(department_request, "ControlIntent.department_request") != binding:
            _fail("ControlIntent department request binding differs")
        request = department_request
    if department_result is not None:
        if _company_binding(department_result, "ControlIntent.department_result") != binding:
            _fail("ControlIntent department result binding differs")
        if department_result["command_id"] != item["command_id"]:
            _fail("ControlIntent department result command differs")
        result = department_result
    receipt = _canonical(item["terminal_receipt"], "ControlIntent.terminal_receipt", maximum=MAX_EVENT_PAYLOAD_BYTES)
    if department_result is not None:
        receipt = validate_department_lifecycle_receipt(
            receipt,
            result=department_result,
        )
    request_sha256 = _sha256(item["request_sha256"], "ControlIntent.request_sha256")
    result_sha256 = _sha256(item["result_sha256"], "ControlIntent.result_sha256")
    receipt_sha256 = _sha256(item["receipt_sha256"], "ControlIntent.receipt_sha256")
    if request_sha256 != company_contract_sha256(request, max_bytes=MAX_EVENT_PAYLOAD_BYTES):
        _fail("ControlIntent.request_sha256 differs")
    if result_sha256 != company_contract_sha256(result, max_bytes=MAX_EVENT_PAYLOAD_BYTES):
        _fail("ControlIntent.result_sha256 differs")
    if receipt_sha256 != company_contract_sha256(receipt, max_bytes=MAX_EVENT_PAYLOAD_BYTES):
        _fail("ControlIntent.receipt_sha256 differs")
    created_at = _timestamp(item["created_at"], "ControlIntent.created_at")
    terminal_at = _timestamp(item["terminal_at"], "ControlIntent.terminal_at")
    if _parsed_timestamp(terminal_at) < _parsed_timestamp(created_at):
        _fail("ControlIntent.terminal_at precedes created_at")
    outcome = _enum(item["outcome"], "ControlIntent.outcome", _TERMINAL_MUTATION_STATES)
    provenance = _enum(item["provenance"], "ControlIntent.provenance", _PROVENANCE)
    observation = _observation(item["observation"], "ControlIntent.observation")
    if outcome in {"committed", "failed_known", "aborted"} and (provenance == "unknown" or observation["state"] != "known"):
        _fail("known ControlIntent outcome requires known observation and provenance")
    if department_result is not None and outcome != "committed":
        _fail("department lifecycle result requires a committed ControlIntent")
    return {"contract_type": CONTROL_INTENT_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding,
            "control_intent_id": _id(item["control_intent_id"], "ControlIntent.control_intent_id"), "command_id": _id(item["command_id"], "ControlIntent.command_id"),
            "execution_id": _id(item["execution_id"], "ControlIntent.execution_id"), "authority_grant": grant,
            "authority_grant_sha256": grant["grant_sha256"], "request_payload": request, "request_sha256": request_sha256,
            "outcome": outcome, "result_payload": result, "result_sha256": result_sha256,
            "receipt_id": _id(item["receipt_id"], "ControlIntent.receipt_id"), "terminal_receipt": receipt,
            "receipt_sha256": receipt_sha256, "created_at": created_at, "terminal_at": terminal_at,
            "provenance": provenance, "observation": observation}


def validate_expected_head(value: Any) -> dict[str, Any]:
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "transaction_id", "command_id", "stream", "cursor", "event_sha256"}
    item = _header(value, EXPECTED_HEAD_V1, fields, "ExpectedHead")
    cursor = _integer(item["cursor"], "ExpectedHead.cursor", maximum=999_999_999_999)
    event_sha256 = _sha256(item["event_sha256"], "ExpectedHead.event_sha256")
    if (cursor == 0) != (event_sha256 == ZERO_SHA256):
        _fail("ExpectedHead genesis cursor and hash differ")
    return {"contract_type": EXPECTED_HEAD_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **_embedded_binding(item, "ExpectedHead"),
            "transaction_id": _id(item["transaction_id"], "ExpectedHead.transaction_id"),
            "command_id": _id(item["command_id"], "ExpectedHead.command_id"),
            "stream": _enum(item["stream"], "ExpectedHead.stream", _STREAMS),
            "cursor": cursor, "event_sha256": event_sha256}


def validate_expected_transaction_head(value: Any) -> dict[str, Any]:
    """Validate the request-wide CAS head for the single global chain."""
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "transaction_id", "command_id", "global_sequence", "transaction_sha256"}
    item = _header(value, EXPECTED_TRANSACTION_HEAD_V1, fields, "ExpectedTransactionHead")
    sequence = _integer(item["global_sequence"], "ExpectedTransactionHead.global_sequence", maximum=999_999_999_999)
    digest = _sha256(item["transaction_sha256"], "ExpectedTransactionHead.transaction_sha256")
    if (sequence == 0) != (digest == ZERO_SHA256):
        _fail("ExpectedTransactionHead genesis sequence and hash differ")
    return {"contract_type": EXPECTED_TRANSACTION_HEAD_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION,
            **_embedded_binding(item, "ExpectedTransactionHead"),
            "transaction_id": _id(item["transaction_id"], "ExpectedTransactionHead.transaction_id"),
            "command_id": _id(item["command_id"], "ExpectedTransactionHead.command_id"),
            "global_sequence": sequence, "transaction_sha256": digest}


def validate_blob_ref(value: Any) -> dict[str, Any]:
    fields = {"contract_type", "schema_version", "sha256", "size_bytes", "media_type", "availability"}
    item = _header(value, BLOB_REF_V1, fields, "BlobRef")
    availability = _enum(item["availability"], "BlobRef.availability", frozenset({"available", "unavailable", "unknown"}))
    size = item["size_bytes"]
    sha256 = item["sha256"]
    if availability == "available":
        sha256 = _sha256(sha256, "BlobRef.sha256")
        size = _integer(size, "BlobRef.size_bytes", maximum=MAX_CONTRACT_BYTES * 1024)
    elif size is not None or sha256 is not None:
        _fail("unavailable or unknown blob bytes must be null")
    return {"contract_type": BLOB_REF_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION,
            "sha256": sha256, "size_bytes": size,
            "media_type": _text(item["media_type"], "BlobRef.media_type", maximum=128), "availability": availability}


def validate_department_lifecycle_request(value: Any) -> dict[str, Any]:
    """Validate the strict payload used for one department lifecycle intent."""
    fields = {
        "request_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation",
        "operation", "trigger", "requested_at", "department_id", "lead_node_id",
        "expected_global_sequence", "expected_transaction_sha256", "expected_department_status",
        "expected_department_payload_sha256", "expected_lead_status", "expected_lead_payload_sha256",
        "expected_snapshot_id", "expected_snapshot_revision", "expected_snapshot_payload_sha256",
        "expected_carrier_id", "expected_carrier_payload_sha256", "requested_scope_sha256",
        "dispatch_request_id", "reservation_id", "task_id", "packet_id", "route_policy_id",
        "requested_role", "requested_capability_tier", "snapshot_document",
    }
    item = _object(value, fields, "DepartmentLifecycleRequest")
    if item["request_type"] != DEPARTMENT_LIFECYCLE_REQUEST_V1:
        _fail("DepartmentLifecycleRequest.request_type is invalid")
    if _integer(item["schema_version"], "DepartmentLifecycleRequest.schema_version", minimum=1, maximum=1) != 1:
        _fail("DepartmentLifecycleRequest.schema_version is unsupported")
    binding = _embedded_binding(item, "DepartmentLifecycleRequest")
    operation = _enum(item["operation"], "DepartmentLifecycleRequest.operation", _DEPARTMENT_OPERATIONS)
    trigger = _enum(item["trigger"], "DepartmentLifecycleRequest.trigger", _DEPARTMENT_TRIGGERS)
    carrier_id = _nullable_id(item["expected_carrier_id"], "DepartmentLifecycleRequest.expected_carrier_id")
    carrier_sha256 = _nullable_sha256(item["expected_carrier_payload_sha256"], "DepartmentLifecycleRequest.expected_carrier_payload_sha256")
    if (carrier_id is None) != (carrier_sha256 is None):
        _fail("DepartmentLifecycleRequest expected carrier id and digest differ")
    routing_fields = (
        "dispatch_request_id", "reservation_id", "task_id", "packet_id", "route_policy_id",
        "requested_role", "requested_capability_tier",
    )
    routing = {name: _nullable_id(item[name], f"DepartmentLifecycleRequest.{name}") for name in routing_fields}
    snapshot_document = None if item["snapshot_document"] is None else validate_blob_ref(item["snapshot_document"])
    if operation == "park":
        if item["expected_department_status"] != "active" or trigger not in {"explicit", "idle_policy"}:
            _fail("DepartmentLifecycleRequest park matrix is invalid")
        if snapshot_document is None or snapshot_document["availability"] != "available":
            _fail("DepartmentLifecycleRequest park requires an available snapshot document")
        if any(member is not None for member in routing.values()):
            _fail("DepartmentLifecycleRequest park cannot reserve dispatch routing")
    elif operation == "resume":
        if item["expected_department_status"] != "parked" or item["expected_lead_status"] != "parked" or trigger != "explicit":
            _fail("DepartmentLifecycleRequest resume matrix is invalid")
        if snapshot_document is not None or any(member is None for member in routing.values()):
            _fail("DepartmentLifecycleRequest resume requires complete dispatch routing without a snapshot document")
    else:
        expected_department_status = item["expected_department_status"]
        if ((expected_department_status == "parked" and trigger != "lazy_wake")
                or (expected_department_status == "active" and trigger != "explicit")):
            _fail("DepartmentLifecycleRequest enqueue matrix is invalid")
        if snapshot_document is not None or any(member is None for member in routing.values()):
            _fail("DepartmentLifecycleRequest enqueue requires complete dispatch routing without a snapshot document")
    return {
        "request_type": DEPARTMENT_LIFECYCLE_REQUEST_V1, "schema_version": 1, **binding,
        "operation": operation, "trigger": trigger,
        "requested_at": _timestamp(item["requested_at"], "DepartmentLifecycleRequest.requested_at"),
        "department_id": _id(item["department_id"], "DepartmentLifecycleRequest.department_id"),
        "lead_node_id": _id(item["lead_node_id"], "DepartmentLifecycleRequest.lead_node_id"),
        "expected_global_sequence": _integer(item["expected_global_sequence"], "DepartmentLifecycleRequest.expected_global_sequence", minimum=1, maximum=999_999_999_999),
        "expected_transaction_sha256": _sha256(item["expected_transaction_sha256"], "DepartmentLifecycleRequest.expected_transaction_sha256"),
        "expected_department_status": _enum(item["expected_department_status"], "DepartmentLifecycleRequest.expected_department_status", _DEPARTMENT_STATUSES),
        "expected_department_payload_sha256": _sha256(item["expected_department_payload_sha256"], "DepartmentLifecycleRequest.expected_department_payload_sha256"),
        "expected_lead_status": _enum(item["expected_lead_status"], "DepartmentLifecycleRequest.expected_lead_status", _DEPARTMENT_LEAD_STATUSES),
        "expected_lead_payload_sha256": _sha256(item["expected_lead_payload_sha256"], "DepartmentLifecycleRequest.expected_lead_payload_sha256"),
        "expected_snapshot_id": _id(item["expected_snapshot_id"], "DepartmentLifecycleRequest.expected_snapshot_id"),
        "expected_snapshot_revision": _integer(item["expected_snapshot_revision"], "DepartmentLifecycleRequest.expected_snapshot_revision", minimum=1, maximum=999_999_999_999),
        "expected_snapshot_payload_sha256": _sha256(item["expected_snapshot_payload_sha256"], "DepartmentLifecycleRequest.expected_snapshot_payload_sha256"),
        "expected_carrier_id": carrier_id, "expected_carrier_payload_sha256": carrier_sha256,
        "requested_scope_sha256": _sha256(item["requested_scope_sha256"], "DepartmentLifecycleRequest.requested_scope_sha256"),
        **routing, "snapshot_document": snapshot_document,
    }


def validate_department_lifecycle_result(
    value: Any, *, request: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the durable result of one department lifecycle transaction."""
    fields = {
        "result_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation",
        "operation", "transaction_id", "command_id", "committed_cursor", "department_id", "lead_node_id",
        "lifecycle_state", "department_status", "lead_status", "snapshot_id", "snapshot_revision",
        "snapshot_payload_sha256", "snapshot_cursor", "carrier_transition", "carrier_id", "carrier_state",
        "replaced_carrier_id", "dispatch_request_id", "dispatch_revision", "dispatch_state", "execution_id",
        "runtime_effect",
    }
    item = _object(value, fields, "DepartmentLifecycleResult")
    if item["result_type"] != DEPARTMENT_LIFECYCLE_RESULT_V1:
        _fail("DepartmentLifecycleResult.result_type is invalid")
    if _integer(item["schema_version"], "DepartmentLifecycleResult.schema_version", minimum=1, maximum=1) != 1:
        _fail("DepartmentLifecycleResult.schema_version is unsupported")
    binding = _embedded_binding(item, "DepartmentLifecycleResult")
    operation = _enum(item["operation"], "DepartmentLifecycleResult.operation", _DEPARTMENT_OPERATIONS)
    carrier_id = _nullable_id(item["carrier_id"], "DepartmentLifecycleResult.carrier_id")
    carrier_state = None if item["carrier_state"] is None else _enum(item["carrier_state"], "DepartmentLifecycleResult.carrier_state", _CARRIER_STATES)
    replaced_carrier_id = _nullable_id(item["replaced_carrier_id"], "DepartmentLifecycleResult.replaced_carrier_id")
    if (carrier_id is None) != (carrier_state is None):
        _fail("DepartmentLifecycleResult carrier id and state differ")
    carrier_transition = _enum(item["carrier_transition"], "DepartmentLifecycleResult.carrier_transition", _CARRIER_TRANSITIONS)
    if carrier_transition == "none" and (carrier_id is not None or replaced_carrier_id is not None):
        _fail("DepartmentLifecycleResult none carrier transition cannot name carriers")
    if carrier_transition == "parked" and (carrier_id is None or carrier_state != "parked" or replaced_carrier_id is not None):
        _fail("DepartmentLifecycleResult parked carrier transition is invalid")
    if carrier_transition == "resumed" and (carrier_id is None or carrier_state != "active" or replaced_carrier_id is not None):
        _fail("DepartmentLifecycleResult resumed carrier transition is invalid")
    if carrier_transition == "replaced" and (carrier_id is None or carrier_state != "active" or replaced_carrier_id is None or replaced_carrier_id == carrier_id):
        _fail("DepartmentLifecycleResult replaced carrier transition is invalid")
    dispatch_request_id = _nullable_id(item["dispatch_request_id"], "DepartmentLifecycleResult.dispatch_request_id")
    dispatch_revision = None if item["dispatch_revision"] is None else _integer(item["dispatch_revision"], "DepartmentLifecycleResult.dispatch_revision", minimum=1, maximum=999_999_999_999)
    dispatch_state = None if item["dispatch_state"] is None else _enum(item["dispatch_state"], "DepartmentLifecycleResult.dispatch_state", _DISPATCH_REQUEST_STATES)
    execution_id = _nullable_id(item["execution_id"], "DepartmentLifecycleResult.execution_id")
    lifecycle_state = _enum(item["lifecycle_state"], "DepartmentLifecycleResult.lifecycle_state", _DEPARTMENT_LIFECYCLE_STATES)
    department_status = _enum(item["department_status"], "DepartmentLifecycleResult.department_status", frozenset({"active", "parked", "unknown"}))
    lead_status = _enum(item["lead_status"], "DepartmentLifecycleResult.lead_status", frozenset({"active", "idle", "parked", "unknown"}))
    runtime_effect = _enum(item["runtime_effect"], "DepartmentLifecycleResult.runtime_effect", frozenset({"none", "pending_dispatch"}))
    queued_dispatch = (dispatch_request_id is not None and dispatch_revision == 1 and dispatch_state == "queued" and execution_id is None)
    if operation == "park":
        if (lifecycle_state != "parked" or department_status != "parked" or lead_status != "parked"
                or any(member is not None for member in (dispatch_request_id, dispatch_revision, dispatch_state, execution_id))
                or runtime_effect != "none"):
            _fail("DepartmentLifecycleResult park matrix is invalid")
    elif operation == "resume":
        if (lifecycle_state != "waking" or department_status != "active" or lead_status != "active"
                or not queued_dispatch or carrier_transition != "pending" or runtime_effect != "pending_dispatch"):
            _fail("DepartmentLifecycleResult resume matrix is invalid")
    else:
        if (not queued_dispatch or runtime_effect != "pending_dispatch"
                or lifecycle_state not in {"waking", "active"} or department_status != "active"):
            _fail("DepartmentLifecycleResult enqueue matrix is invalid")
    result = {
        "result_type": DEPARTMENT_LIFECYCLE_RESULT_V1, "schema_version": 1, **binding,
        "operation": operation, "transaction_id": _id(item["transaction_id"], "DepartmentLifecycleResult.transaction_id"),
        "command_id": _id(item["command_id"], "DepartmentLifecycleResult.command_id"),
        "committed_cursor": _integer(item["committed_cursor"], "DepartmentLifecycleResult.committed_cursor", minimum=1, maximum=999_999_999_999),
        "department_id": _id(item["department_id"], "DepartmentLifecycleResult.department_id"),
        "lead_node_id": _id(item["lead_node_id"], "DepartmentLifecycleResult.lead_node_id"),
        "lifecycle_state": lifecycle_state, "department_status": department_status, "lead_status": lead_status,
        "snapshot_id": _id(item["snapshot_id"], "DepartmentLifecycleResult.snapshot_id"),
        "snapshot_revision": _integer(item["snapshot_revision"], "DepartmentLifecycleResult.snapshot_revision", minimum=1, maximum=999_999_999_999),
        "snapshot_payload_sha256": _sha256(item["snapshot_payload_sha256"], "DepartmentLifecycleResult.snapshot_payload_sha256"),
        "snapshot_cursor": _integer(item["snapshot_cursor"], "DepartmentLifecycleResult.snapshot_cursor", minimum=1, maximum=999_999_999_999),
        "carrier_transition": carrier_transition, "carrier_id": carrier_id, "carrier_state": carrier_state,
        "replaced_carrier_id": replaced_carrier_id, "dispatch_request_id": dispatch_request_id,
        "dispatch_revision": dispatch_revision, "dispatch_state": dispatch_state, "execution_id": execution_id,
        "runtime_effect": runtime_effect,
    }
    if request is not None:
        nested_request = validate_department_lifecycle_request(request)
        if (_company_binding(nested_request, "DepartmentLifecycleResult.request") != binding
                or nested_request["operation"] != operation
                or nested_request["department_id"] != result["department_id"]
                or nested_request["lead_node_id"] != result["lead_node_id"]
                or result["committed_cursor"] != nested_request["expected_global_sequence"] + 1):
            _fail("DepartmentLifecycleResult request binding differs")
        if operation == "enqueue":
            expected_lifecycle = "waking" if nested_request["expected_department_status"] == "parked" else "active"
            if lifecycle_state != expected_lifecycle:
                _fail("DepartmentLifecycleResult enqueue lifecycle differs from request")
    return result


def validate_department_lifecycle_receipt(
    value: Any,
    *,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Cross-bind a lifecycle terminal receipt to its exact durable result."""

    fields = {
        "receipt_type",
        "schema_version",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "transaction_id",
        "command_id",
        "committed_cursor",
        "operation",
        "department_id",
    }
    item = _object(value, fields, "DepartmentLifecycleReceipt")
    if item["receipt_type"] != DEPARTMENT_LIFECYCLE_RECEIPT_V1:
        _fail("DepartmentLifecycleReceipt.receipt_type is invalid")
    if _integer(
        item["schema_version"],
        "DepartmentLifecycleReceipt.schema_version",
        minimum=1,
        maximum=1,
    ) != 1:
        _fail("DepartmentLifecycleReceipt.schema_version is unsupported")
    normalized_result = validate_department_lifecycle_result(result)
    binding = _embedded_binding(item, "DepartmentLifecycleReceipt")
    normalized = {
        "receipt_type": DEPARTMENT_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        **binding,
        "transaction_id": _id(
            item["transaction_id"],
            "DepartmentLifecycleReceipt.transaction_id",
        ),
        "command_id": _id(
            item["command_id"],
            "DepartmentLifecycleReceipt.command_id",
        ),
        "committed_cursor": _integer(
            item["committed_cursor"],
            "DepartmentLifecycleReceipt.committed_cursor",
            minimum=1,
            maximum=999_999_999_999,
        ),
        "operation": _enum(
            item["operation"],
            "DepartmentLifecycleReceipt.operation",
            _DEPARTMENT_OPERATIONS,
        ),
        "department_id": _id(
            item["department_id"],
            "DepartmentLifecycleReceipt.department_id",
        ),
    }
    expected = {
        "receipt_type": DEPARTMENT_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        **{
            key: normalized_result[key]
            for key in (
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
                "transaction_id",
                "command_id",
                "committed_cursor",
                "operation",
                "department_id",
            )
        },
    }
    if normalized != expected:
        _fail("DepartmentLifecycleReceipt differs from lifecycle result")
    return normalized


def validate_department_snapshot_document(value: Any) -> dict[str, Any]:
    """Validate one bounded, content-addressed department snapshot document."""
    fields = {
        "document_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation",
        "department_id", "lead_node_id", "snapshot_id", "revision", "previous_snapshot_id",
        "previous_document_sha256", "company_cursor", "captured_at", "capture_reason", "charter_ref",
        "constraints_ref", "decisions_ref", "dissent_ref", "open_questions_ref", "blockers_ref", "risks_ref",
        "backlog_ref", "handoff_ref", "active_dispatch_request_ids", "active_execution_ids", "job_ids",
        "evidence_ids", "artifact_refs",
    }
    item = _object(_canonical(value, "DepartmentSnapshotDocument"), fields, "DepartmentSnapshotDocument")
    if item["document_type"] != DEPARTMENT_SNAPSHOT_DOCUMENT_V1:
        _fail("DepartmentSnapshotDocument.document_type is invalid")
    if _integer(item["schema_version"], "DepartmentSnapshotDocument.schema_version", minimum=1, maximum=1) != 1:
        _fail("DepartmentSnapshotDocument.schema_version is unsupported")
    binding = _embedded_binding(item, "DepartmentSnapshotDocument")
    revision = _integer(item["revision"], "DepartmentSnapshotDocument.revision", minimum=1, maximum=999_999_999_999)
    snapshot_id = _id(item["snapshot_id"], "DepartmentSnapshotDocument.snapshot_id")
    previous_snapshot_id = _nullable_id(item["previous_snapshot_id"], "DepartmentSnapshotDocument.previous_snapshot_id")
    previous_document_sha256 = _nullable_sha256(item["previous_document_sha256"], "DepartmentSnapshotDocument.previous_document_sha256")
    if (revision == 1) != (previous_snapshot_id is None and previous_document_sha256 is None):
        _fail("DepartmentSnapshotDocument revision and predecessor differ")
    if revision > 1 and (previous_snapshot_id is None or previous_document_sha256 is None):
        _fail("DepartmentSnapshotDocument later revision requires predecessors")
    if previous_snapshot_id == snapshot_id:
        _fail("DepartmentSnapshotDocument cannot name itself as predecessor")
    reference_names = (
        "charter_ref", "constraints_ref", "decisions_ref", "dissent_ref", "open_questions_ref", "blockers_ref",
        "risks_ref", "backlog_ref", "handoff_ref",
    )
    references = {name: validate_blob_ref(item[name]) for name in reference_names}
    if any(reference["availability"] != "available" for reference in references.values()):
        _fail("DepartmentSnapshotDocument named references must be available")
    artifact_refs = _blob_refs(item["artifact_refs"], "DepartmentSnapshotDocument.artifact_refs")
    if any(reference["availability"] != "available" for reference in artifact_refs):
        _fail("DepartmentSnapshotDocument artifact references must be available")
    if len({reference["sha256"] for reference in artifact_refs}) != len(artifact_refs):
        _fail("DepartmentSnapshotDocument artifact references contain duplicates")
    active_dispatch_request_ids = _id_list(item["active_dispatch_request_ids"], "DepartmentSnapshotDocument.active_dispatch_request_ids")
    active_execution_ids = _id_list(item["active_execution_ids"], "DepartmentSnapshotDocument.active_execution_ids")
    job_ids = _id_list(item["job_ids"], "DepartmentSnapshotDocument.job_ids")
    evidence_ids = _id_list(item["evidence_ids"], "DepartmentSnapshotDocument.evidence_ids")
    capture_reason = _enum(item["capture_reason"], "DepartmentSnapshotDocument.capture_reason", _SNAPSHOT_CAPTURE_REASONS)
    if capture_reason == "park" and any((active_dispatch_request_ids, active_execution_ids, job_ids)):
        _fail("DepartmentSnapshotDocument park capture cannot retain active work")
    return {
        "document_type": DEPARTMENT_SNAPSHOT_DOCUMENT_V1, "schema_version": 1, **binding,
        "department_id": _id(item["department_id"], "DepartmentSnapshotDocument.department_id"),
        "lead_node_id": _id(item["lead_node_id"], "DepartmentSnapshotDocument.lead_node_id"),
        "snapshot_id": snapshot_id, "revision": revision, "previous_snapshot_id": previous_snapshot_id,
        "previous_document_sha256": previous_document_sha256,
        "company_cursor": _integer(item["company_cursor"], "DepartmentSnapshotDocument.company_cursor", maximum=999_999_999_999),
        "captured_at": _timestamp(item["captured_at"], "DepartmentSnapshotDocument.captured_at"),
        "capture_reason": capture_reason, **references,
        "active_dispatch_request_ids": active_dispatch_request_ids, "active_execution_ids": active_execution_ids,
        "job_ids": job_ids, "evidence_ids": evidence_ids, "artifact_refs": artifact_refs,
    }


def validate_takeover_capability(value: Any) -> dict[str, Any]:
    # This is an issuance, never a mutable capability lifecycle record.  The
    # ledger records a single consumption separately under its own CAS.
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "capability_id", "contender_carrier_id", "expected_chief_id", "expected_term", "expected_epoch", "expected_head_sha256", "consumption_id", "consumption_transaction_id", "consumption_command_id", "resulting_chief_id", "resulting_term", "resulting_epoch", "objective_sha256", "scope_sha256", "nonce_sha256", "issued_at", "expires_at", "user_action_ref", "capability_sha256"}
    item = _header(value, TAKEOVER_CAPABILITY_V1, fields, "TakeoverCapability")
    issued_at = _timestamp(item["issued_at"], "TakeoverCapability.issued_at")
    expires_at = _timestamp(item["expires_at"], "TakeoverCapability.expires_at")
    if _parsed_timestamp(expires_at) <= _parsed_timestamp(issued_at):
        _fail("TakeoverCapability.expires_at must be after issued_at")
    expected_chief_id = _id(item["expected_chief_id"], "TakeoverCapability.expected_chief_id")
    resulting_chief_id = _id(item["resulting_chief_id"], "TakeoverCapability.resulting_chief_id")
    expected_term = _integer(item["expected_term"], "TakeoverCapability.expected_term", minimum=1, maximum=999_999_999)
    expected_epoch = _integer(item["expected_epoch"], "TakeoverCapability.expected_epoch", minimum=1, maximum=999_999_999)
    resulting_term = _integer(item["resulting_term"], "TakeoverCapability.resulting_term", minimum=1, maximum=999_999_999)
    resulting_epoch = _integer(item["resulting_epoch"], "TakeoverCapability.resulting_epoch", minimum=1, maximum=999_999_999)
    if resulting_chief_id != expected_chief_id:
        _fail("TakeoverCapability must preserve the logical Chief identity")
    if resulting_term != expected_term + 1 or resulting_epoch != expected_epoch + 1:
        _fail("TakeoverCapability resulting term and epoch must advance exactly once")
    unsigned = {key: item[key] for key in fields - {"capability_sha256"}}
    capability_sha256 = _sha256(item["capability_sha256"], "TakeoverCapability.capability_sha256")
    if capability_sha256 != company_contract_sha256(unsigned):
        _fail("TakeoverCapability.capability_sha256 differs")
    return {"contract_type": TAKEOVER_CAPABILITY_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **_embedded_binding(item, "TakeoverCapability"),
            "capability_id": _id(item["capability_id"], "TakeoverCapability.capability_id"), "contender_carrier_id": _id(item["contender_carrier_id"], "TakeoverCapability.contender_carrier_id"),
            "expected_chief_id": expected_chief_id,
            "expected_term": expected_term,
            "expected_epoch": expected_epoch,
            "expected_head_sha256": _sha256(item["expected_head_sha256"], "TakeoverCapability.expected_head_sha256"),
            "consumption_id": _id(item["consumption_id"], "TakeoverCapability.consumption_id"),
            "consumption_transaction_id": _id(item["consumption_transaction_id"], "TakeoverCapability.consumption_transaction_id"),
            "consumption_command_id": _id(item["consumption_command_id"], "TakeoverCapability.consumption_command_id"),
            "resulting_chief_id": resulting_chief_id,
            "resulting_term": resulting_term,
            "resulting_epoch": resulting_epoch,
            "objective_sha256": _sha256(item["objective_sha256"], "TakeoverCapability.objective_sha256"),
            "scope_sha256": _sha256(item["scope_sha256"], "TakeoverCapability.scope_sha256"),
            "nonce_sha256": _sha256(item["nonce_sha256"], "TakeoverCapability.nonce_sha256"),
            "issued_at": issued_at, "expires_at": expires_at,
            "user_action_ref": _id(item["user_action_ref"], "TakeoverCapability.user_action_ref"), "capability_sha256": capability_sha256}


def validate_takeover_consumption_receipt(value: Any) -> dict[str, Any]:
    """Validate one immutable takeover attempt.

    This pure boundary can prove that the signed capability was unexpired for
    this attempt.  It cannot prove uniqueness across attempts: the sole ledger
    writer must atomically consume ``capability_id`` while committing this
    receipt in the global transaction chain.
    """
    fields = {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "consumption_id", "transaction_id", "command_id", "capability", "capability_sha256", "outcome", "resulting_chief_term", "consumed_at", "receipt_sha256"}
    item = _header(value, TAKEOVER_CONSUMPTION_RECEIPT_V1, fields, "TakeoverConsumptionReceipt")
    binding = _embedded_binding(item, "TakeoverConsumptionReceipt")
    capability = validate_takeover_capability(item["capability"])
    if _company_binding(capability, "TakeoverConsumptionReceipt.capability") != binding:
        _fail("TakeoverConsumptionReceipt capability binding differs")
    capability_sha256 = _sha256(item["capability_sha256"], "TakeoverConsumptionReceipt.capability_sha256")
    if capability_sha256 != capability["capability_sha256"]:
        _fail("TakeoverConsumptionReceipt capability digest differs")
    if (item["consumption_id"], item["transaction_id"], item["command_id"]) != (capability["consumption_id"], capability["consumption_transaction_id"], capability["consumption_command_id"]):
        _fail("TakeoverConsumptionReceipt is not the capability's one bound consumption")
    consumed_at = _timestamp(item["consumed_at"], "TakeoverConsumptionReceipt.consumed_at")
    if _parsed_timestamp(consumed_at) < _parsed_timestamp(capability["issued_at"]):
        _fail("TakeoverConsumptionReceipt.consumed_at precedes issuance")
    if _parsed_timestamp(consumed_at) >= _parsed_timestamp(capability["expires_at"]):
        _fail("TakeoverConsumptionReceipt capability is expired")
    outcome = _enum(item["outcome"], "TakeoverConsumptionReceipt.outcome", _TAKEOVER_OUTCOMES)
    resulting = item["resulting_chief_term"]
    if outcome == "fenced":
        if resulting is not None:
            _fail("fenced takeover cannot create a ChiefTerm")
    else:
        fields_result = {"chief_id", "carrier_id", "term", "epoch", "takeover_capability_sha256", "chief_term_sha256"}
        result_item = _object(resulting, fields_result, "TakeoverConsumptionReceipt.resulting_chief_term")
        result_unsigned = {key: result_item[key] for key in fields_result - {"chief_term_sha256"}}
        if _sha256(result_item["chief_term_sha256"], "TakeoverConsumptionReceipt.resulting_chief_term.chief_term_sha256") != company_contract_sha256(result_unsigned):
            _fail("TakeoverConsumptionReceipt resulting ChiefTerm digest differs")
        if (_id(result_item["chief_id"], "TakeoverConsumptionReceipt.resulting_chief_term.chief_id") != capability["resulting_chief_id"]
                or _id(result_item["carrier_id"], "TakeoverConsumptionReceipt.resulting_chief_term.carrier_id") != capability["contender_carrier_id"]
                or _integer(result_item["term"], "TakeoverConsumptionReceipt.resulting_chief_term.term", minimum=1) != capability["resulting_term"]
                or _integer(result_item["epoch"], "TakeoverConsumptionReceipt.resulting_chief_term.epoch", minimum=1) != capability["resulting_epoch"]
                or _sha256(result_item["takeover_capability_sha256"], "TakeoverConsumptionReceipt.resulting_chief_term.takeover_capability_sha256") != capability_sha256):
            _fail("TakeoverConsumptionReceipt resulting ChiefTerm is not capability-bound")
        resulting = {**result_unsigned, "chief_term_sha256": result_item["chief_term_sha256"]}
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(item["receipt_sha256"], "TakeoverConsumptionReceipt.receipt_sha256")
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("TakeoverConsumptionReceipt.receipt_sha256 differs")
    return {"contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding,
            "consumption_id": _id(item["consumption_id"], "TakeoverConsumptionReceipt.consumption_id"),
            "transaction_id": _id(item["transaction_id"], "TakeoverConsumptionReceipt.transaction_id"),
            "command_id": _id(item["command_id"], "TakeoverConsumptionReceipt.command_id"),
            "capability": capability, "capability_sha256": capability_sha256,
            "outcome": outcome, "resulting_chief_term": resulting,
            "consumed_at": consumed_at, "receipt_sha256": receipt_sha256}


def validate_company_manifest(value: Any) -> dict[str, Any]:
    fields = _common_fields({"git_common_dir_sha256", "remote_fingerprint_sha256", "configuration_sha256", "state_root_sha256", "lock_domain_id", "created_at", "observation"})
    item, result = _base(value, COMPANY_MANIFEST_V1, fields, "CompanyManifest")
    result.update({
        "git_common_dir_sha256": _sha256(item["git_common_dir_sha256"], "CompanyManifest.git_common_dir_sha256"),
        "remote_fingerprint_sha256": _sha256(item["remote_fingerprint_sha256"], "CompanyManifest.remote_fingerprint_sha256"),
        "configuration_sha256": _sha256(item["configuration_sha256"], "CompanyManifest.configuration_sha256"),
        "state_root_sha256": _sha256(item["state_root_sha256"], "CompanyManifest.state_root_sha256"),
        "lock_domain_id": _id(item["lock_domain_id"], "CompanyManifest.lock_domain_id"),
        "created_at": _timestamp(item["created_at"], "CompanyManifest.created_at"),
        "observation": _observation(item["observation"], "CompanyManifest.observation"),
    })
    return result


def validate_company_event(value: Any) -> dict[str, Any]:
    fields = _common_fields({"transaction_id", "command_id", "event_id", "stream", "event_type", "recorded_at", "actor_authority", "provenance", "payload", "payload_sha256"})
    item = _header(value, COMPANY_EVENT_V1, fields, "CompanyEvent")
    binding = _embedded_binding(item, "CompanyEvent")
    authority = validate_actor_authority(item["actor_authority"])
    if _company_binding(authority, "CompanyEvent.actor_authority") != binding:
        _fail("CompanyEvent.actor_authority binding differs")
    payload = _canonical(item["payload"], "CompanyEvent.payload", maximum=MAX_EVENT_PAYLOAD_BYTES)
    if company_contract_sha256(payload, max_bytes=MAX_EVENT_PAYLOAD_BYTES) != _sha256(item["payload_sha256"], "CompanyEvent.payload_sha256"):
        _fail("CompanyEvent.payload_sha256 differs")
    return {"contract_type": COMPANY_EVENT_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding,
            "transaction_id": _id(item["transaction_id"], "CompanyEvent.transaction_id"), "command_id": _id(item["command_id"], "CompanyEvent.command_id"),
            "event_id": _id(item["event_id"], "CompanyEvent.event_id"), "stream": _enum(item["stream"], "CompanyEvent.stream", _STREAMS), "event_type": _id(item["event_type"], "CompanyEvent.event_type"),
            "recorded_at": _timestamp(item["recorded_at"], "CompanyEvent.recorded_at"), "actor_authority": authority,
            "provenance": _enum(item["provenance"], "CompanyEvent.provenance", _PROVENANCE), "payload": payload, "payload_sha256": item["payload_sha256"]}


def validate_company_transaction_request(value: Any) -> dict[str, Any]:
    fields = _common_fields({"transaction_id", "command_id", "actor_authority", "expected_transaction_head", "expected_heads", "events", "request_sha256"})
    item = _header(value, COMPANY_TRANSACTION_REQUEST_V1, fields, "CompanyTransactionRequest")
    binding = _embedded_binding(item, "CompanyTransactionRequest")
    authority = validate_actor_authority(item["actor_authority"])
    global_head = validate_expected_transaction_head(item["expected_transaction_head"])
    heads = _bounded_list(item["expected_heads"], "CompanyTransactionRequest.expected_heads", lambda member, _label: validate_expected_head(member), maximum=len(_STREAMS))
    events = _bounded_list(item["events"], "CompanyTransactionRequest.events", lambda member, _label: validate_company_event(member), maximum=MAX_TRANSACTION_EVENTS)
    if not events or len({event["event_id"] for event in events}) != len(events):
        _fail("CompanyTransactionRequest.events is empty or duplicated")
    if not heads or len({head["stream"] for head in heads}) != len(heads):
        _fail("CompanyTransactionRequest.expected_heads is empty or has duplicate streams")
    if any(head["transaction_id"] != item["transaction_id"] or head["command_id"] != item["command_id"] for head in heads):
        _fail("CompanyTransactionRequest expected head is not bound to this request")
    if global_head["transaction_id"] != item["transaction_id"] or global_head["command_id"] != item["command_id"]:
        _fail("CompanyTransactionRequest global expected head is not bound to this request")
    if global_head["global_sequence"] == 0 and any(head["cursor"] != 0 for head in heads):
        _fail("CompanyTransactionRequest genesis global head requires genesis stream heads")
    if {head["stream"] for head in heads} != {event["stream"] for event in events}:
        _fail("CompanyTransactionRequest expected and event streams differ")
    if any(event["transaction_id"] != item["transaction_id"] or event["command_id"] != item["command_id"] for event in events):
        _fail("CompanyTransactionRequest event is not bound to this request")
    if (_company_binding(authority, "CompanyTransactionRequest.actor_authority") != binding
            or _company_binding(global_head, "CompanyTransactionRequest.expected_transaction_head") != binding
            or any(_company_binding(head, "CompanyTransactionRequest.expected_head") != binding for head in heads)
            or any(_company_binding(event, "CompanyTransactionRequest.event") != binding for event in events)):
        _fail("CompanyTransactionRequest nested binding differs")
    if authority["authority_state"] != "active" or "company.mutate" not in authority["permissions"]:
        _fail("CompanyTransactionRequest requires active company.mutate authority")
    if any(event["actor_authority"] != authority for event in events):
        _fail("CompanyTransactionRequest event authority differs from request authority")
    unsigned = {key: item[key] for key in fields - {"request_sha256"}}
    expected_hash = company_contract_sha256(unsigned)
    if _sha256(item["request_sha256"], "CompanyTransactionRequest.request_sha256") != expected_hash:
        _fail("CompanyTransactionRequest.request_sha256 differs")
    return {"contract_type": COMPANY_TRANSACTION_REQUEST_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding, "transaction_id": _id(item["transaction_id"], "CompanyTransactionRequest.transaction_id"), "command_id": _id(item["command_id"], "CompanyTransactionRequest.command_id"), "actor_authority": authority, "expected_transaction_head": global_head, "expected_heads": heads, "events": events, "request_sha256": item["request_sha256"]}


def validate_company_transaction_receipt(value: Any) -> dict[str, Any]:
    """Validate one committed-ledger envelope.

    ``transaction_sha256`` is the canonical hash excluding itself and the
    receipt digest; ``receipt_sha256`` then covers that transaction digest.
    The validator enforces only genesis/non-genesis shape.  The sole writer
    must atomically enforce sequence adjacency and that ``previous`` equals
    the persisted prior transaction hash.
    """
    fields = _common_fields({"transaction_id", "command_id", "request_sha256", "state", "recorded_at", "global_sequence", "previous_transaction_sha256", "transaction_sha256", "result_heads", "evidence", "receipt_sha256"})
    item = _header(value, COMPANY_TRANSACTION_RECEIPT_V1, fields, "CompanyTransactionReceipt")
    binding = _embedded_binding(item, "CompanyTransactionReceipt")
    heads = _bounded_list(item["result_heads"], "CompanyTransactionReceipt.result_heads", lambda member, _label: validate_expected_head(member), maximum=len(_STREAMS))
    evidence = _bounded_list(item["evidence"], "CompanyTransactionReceipt.evidence", lambda member, _label: validate_blob_ref(member), maximum=32)
    if any(_company_binding(head, "CompanyTransactionReceipt.head") != binding for head in heads):
        _fail("CompanyTransactionReceipt result head binding differs")
    if len({head["stream"] for head in heads}) != len(heads):
        _fail("CompanyTransactionReceipt.result_heads has duplicate streams")
    if any(head["transaction_id"] != item["transaction_id"] or head["command_id"] != item["command_id"] for head in heads):
        _fail("CompanyTransactionReceipt result head is not bound to this transaction and command")
    state = _enum(item["state"], "CompanyTransactionReceipt.state", _MUTATION_STATES)
    if state not in _TERMINAL_MUTATION_STATES:
        _fail("CompanyTransactionReceipt cannot chain a non-terminal state")
    if state == "committed" and not heads:
        _fail("committed receipt requires result heads")
    if state == "committed" and any(head["cursor"] == 0 for head in heads):
        _fail("committed receipt cannot retain a genesis result head")
    if state != "committed" and heads:
        _fail("non-committed receipt cannot advance result heads")
    sequence = _integer(item["global_sequence"], "CompanyTransactionReceipt.global_sequence", minimum=1, maximum=999_999_999_999)
    previous = _sha256(item["previous_transaction_sha256"], "CompanyTransactionReceipt.previous_transaction_sha256")
    if (sequence == 1) != (previous == ZERO_SHA256):
        _fail("CompanyTransactionReceipt genesis chain fields differ")
    transaction_unsigned = {key: item[key] for key in fields - {"transaction_sha256", "receipt_sha256"}}
    transaction_sha256 = _sha256(item["transaction_sha256"], "CompanyTransactionReceipt.transaction_sha256")
    if transaction_sha256 != company_contract_sha256(transaction_unsigned):
        _fail("CompanyTransactionReceipt.transaction_sha256 differs")
    receipt_unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    if _sha256(item["receipt_sha256"], "CompanyTransactionReceipt.receipt_sha256") != company_contract_sha256(receipt_unsigned):
        _fail("CompanyTransactionReceipt.receipt_sha256 differs")
    return {"contract_type": COMPANY_TRANSACTION_RECEIPT_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **binding,
            "transaction_id": _id(item["transaction_id"], "CompanyTransactionReceipt.transaction_id"), "command_id": _id(item["command_id"], "CompanyTransactionReceipt.command_id"),
            "request_sha256": _sha256(item["request_sha256"], "CompanyTransactionReceipt.request_sha256"), "state": state,
            "recorded_at": _timestamp(item["recorded_at"], "CompanyTransactionReceipt.recorded_at"), "global_sequence": sequence,
            "previous_transaction_sha256": previous, "transaction_sha256": transaction_sha256,
            "result_heads": heads, "evidence": evidence, "receipt_sha256": _sha256(item["receipt_sha256"], "CompanyTransactionReceipt.receipt_sha256")}


def _common_fields(fields: set[str]) -> set[str]:
    return {"contract_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation"} | fields


def _base(value: Any, contract_type: str, fields: set[str], label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    item = _header(value, contract_type, fields, label)
    return item, {"contract_type": contract_type, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **_embedded_binding(item, label)}


def _nullable_id(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _id(value, label)


def _nullable_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _id_list(value: Any, label: str, *, maximum: int = MAX_LIST_ITEMS) -> list[str]:
    result = _bounded_list(value, label, _id, maximum=maximum)
    if len(result) != len(set(result)):
        _fail(f"{label} contains duplicates")
    return result


def _sha_list(value: Any, label: str, *, maximum: int = MAX_LIST_ITEMS) -> list[str]:
    result = _bounded_list(value, label, _sha256, maximum=maximum)
    if len(result) != len(set(result)):
        _fail(f"{label} contains duplicates")
    return result


def _blob_refs(value: Any, label: str) -> list[dict[str, Any]]:
    return _bounded_list(value, label, lambda member, _label: validate_blob_ref(member), maximum=32)


def _attention_overlays(value: Any, label: str) -> list[str]:
    overlays = _id_list(value, label, maximum=16)
    if not set(overlays) <= {"suspected_stalled", "high_burn", "coverage_degraded", "needs_user"}:
        _fail(f"{label} is invalid")
    return overlays


def validate_organization_node(value: Any) -> dict[str, Any]:
    fields = _common_fields({"node_id", "department_id", "parent_node_id", "role", "reports_to_node_id", "can_delegate", "delegation_depth", "status", "visibility", "created_at", "observation"})
    item, result = _base(value, ORGANIZATION_NODE_V1, fields, "OrganizationNode")
    parent = _nullable_id(item["parent_node_id"], "OrganizationNode.parent_node_id")
    reports_to = _nullable_id(item["reports_to_node_id"], "OrganizationNode.reports_to_node_id")
    node_id = _id(item["node_id"], "OrganizationNode.node_id")
    department_id = _nullable_id(item["department_id"], "OrganizationNode.department_id")
    role = _id(item["role"], "OrganizationNode.role")
    can_delegate = item["can_delegate"] if isinstance(item["can_delegate"], bool) else _fail("OrganizationNode.can_delegate is invalid")
    depth = _integer(item["delegation_depth"], "OrganizationNode.delegation_depth", maximum=MAX_DEPTH)
    status = _enum(item["status"], "OrganizationNode.status", frozenset({"active", "parked", "idle", "unknown"}))
    visibility = _enum(item["visibility"], "OrganizationNode.visibility", frozenset({"company", "subtree", "task", "unknown"}))
    created_at = _timestamp(item["created_at"], "OrganizationNode.created_at")
    observation = _observation(item["observation"], "OrganizationNode.observation")
    # Validate every field before applying the root-specific relation.  This
    # prevents malformed values from selecting a misleading root branch.
    if (role == "chief") != (parent is None):
        _fail("OrganizationNode chief role must identify the company root")
    if parent is None and (depth != 0 or reports_to is not None):
        _fail("OrganizationNode root requires depth zero and no reports-to node")
    if parent is None and (role != "chief" or department_id is not None or not can_delegate or status != "active" or visibility != "company" or observation["state"] != "known"):
        _fail("OrganizationNode root must be the active company Chief")
    if parent is not None and depth == 0:
        _fail("OrganizationNode child requires nonzero depth")
    if node_id == parent or node_id == reports_to:
        _fail("OrganizationNode cannot parent or report to itself")
    result.update({"node_id": node_id, "department_id": department_id,
                   "parent_node_id": parent, "role": role, "reports_to_node_id": reports_to,
                   "can_delegate": can_delegate, "delegation_depth": depth,
                   "status": status, "visibility": visibility,
                   "created_at": created_at, "observation": observation})
    return result


def validate_department_identity(value: Any) -> dict[str, Any]:
    fields = _common_fields({"department_id", "name", "charter_sha256", "scope_sha256", "lead_node_id", "created_at", "status", "observation"})
    item, result = _base(value, DEPARTMENT_IDENTITY_V1, fields, "DepartmentIdentity")
    result.update({"department_id": _id(item["department_id"], "DepartmentIdentity.department_id"), "name": _text(item["name"], "DepartmentIdentity.name", maximum=128),
                   "charter_sha256": _sha256(item["charter_sha256"], "DepartmentIdentity.charter_sha256"), "scope_sha256": _sha256(item["scope_sha256"], "DepartmentIdentity.scope_sha256"),
                   "lead_node_id": _nullable_id(item["lead_node_id"], "DepartmentIdentity.lead_node_id"), "created_at": _timestamp(item["created_at"], "DepartmentIdentity.created_at"),
                   "status": _enum(item["status"], "DepartmentIdentity.status", frozenset({"active", "parked", "unknown"})), "observation": _observation(item["observation"], "DepartmentIdentity.observation")})
    return result


def validate_department_snapshot(value: Any) -> dict[str, Any]:
    fields = _common_fields({"snapshot_id", "department_id", "revision", "company_cursor", "previous_snapshot_id", "charter_sha256", "constraints_sha256", "decisions_sha256", "open_questions_sha256", "handoff_sha256", "artifact_refs", "captured_at", "observation"})
    item, result = _base(value, DEPARTMENT_SNAPSHOT_V1, fields, "DepartmentSnapshot")
    revision = _integer(item["revision"], "DepartmentSnapshot.revision", minimum=1, maximum=999_999_999_999)
    snapshot_id = _id(item["snapshot_id"], "DepartmentSnapshot.snapshot_id")
    previous_snapshot_id = _nullable_id(item["previous_snapshot_id"], "DepartmentSnapshot.previous_snapshot_id")
    if (revision == 1) != (previous_snapshot_id is None):
        _fail("DepartmentSnapshot revision and predecessor differ")
    if snapshot_id == previous_snapshot_id:
        _fail("DepartmentSnapshot cannot name itself as predecessor")
    result.update({"snapshot_id": snapshot_id, "department_id": _id(item["department_id"], "DepartmentSnapshot.department_id"),
                   "revision": revision, "company_cursor": _integer(item["company_cursor"], "DepartmentSnapshot.company_cursor", maximum=999_999_999_999), "previous_snapshot_id": previous_snapshot_id, "charter_sha256": _sha256(item["charter_sha256"], "DepartmentSnapshot.charter_sha256"),
                   "constraints_sha256": _sha256(item["constraints_sha256"], "DepartmentSnapshot.constraints_sha256"), "decisions_sha256": _sha256(item["decisions_sha256"], "DepartmentSnapshot.decisions_sha256"),
                   "open_questions_sha256": _sha256(item["open_questions_sha256"], "DepartmentSnapshot.open_questions_sha256"), "handoff_sha256": _sha256(item["handoff_sha256"], "DepartmentSnapshot.handoff_sha256"),
                   "artifact_refs": _blob_refs(item["artifact_refs"], "DepartmentSnapshot.artifact_refs"), "captured_at": _timestamp(item["captured_at"], "DepartmentSnapshot.captured_at"), "observation": _observation(item["observation"], "DepartmentSnapshot.observation")})
    return result


def validate_chief_term(value: Any) -> dict[str, Any]:
    fields = _common_fields({"chief_id", "carrier_id", "term", "epoch", "state", "issued_at", "ended_at", "previous_transaction_sha256", "takeover_capability_sha256", "takeover_consumption_receipt_sha256", "observation"})
    item, result = _base(value, CHIEF_TERM_V1, fields, "ChiefTerm")
    issued, ended = _timestamp(item["issued_at"], "ChiefTerm.issued_at"), item["ended_at"]
    ended_at = None if ended is None else _timestamp(ended, "ChiefTerm.ended_at")
    if ended_at is not None and _parsed_timestamp(ended_at) < _parsed_timestamp(issued):
        _fail("ChiefTerm.ended_at precedes issued_at")
    state = _enum(item["state"], "ChiefTerm.state", frozenset({"active", "fenced", "ended", "unknown"}))
    if state == "active" and ended_at is not None:
        _fail("active ChiefTerm cannot have ended_at")
    if state in {"ended", "fenced"} and ended_at is None:
        _fail("ended or fenced ChiefTerm requires ended_at")
    if state == "unknown" and ended_at is not None:
        _fail("unknown ChiefTerm cannot assert ended_at")
    if (item["takeover_capability_sha256"] is None) != (item["takeover_consumption_receipt_sha256"] is None):
        _fail("ChiefTerm takeover capability and consumption receipt must bind together")
    observation = _observation(item["observation"], "ChiefTerm.observation")
    if state in {"active", "ended", "fenced"} and observation["state"] != "known":
        _fail("active, ended, or fenced ChiefTerm requires a known observation")
    if state == "unknown" and observation["state"] != "unknown":
        _fail("unknown ChiefTerm requires an unknown observation")
    result.update({"chief_id": _id(item["chief_id"], "ChiefTerm.chief_id"), "carrier_id": _nullable_id(item["carrier_id"], "ChiefTerm.carrier_id"), "term": _integer(item["term"], "ChiefTerm.term", minimum=1, maximum=999_999_999), "epoch": _integer(item["epoch"], "ChiefTerm.epoch", minimum=1, maximum=999_999_999),
                   "state": state, "issued_at": issued, "ended_at": ended_at,
                   "previous_transaction_sha256": _sha256(item["previous_transaction_sha256"], "ChiefTerm.previous_transaction_sha256"),
                   "takeover_capability_sha256": None if item["takeover_capability_sha256"] is None else _sha256(item["takeover_capability_sha256"], "ChiefTerm.takeover_capability_sha256"),
                   "takeover_consumption_receipt_sha256": None if item["takeover_consumption_receipt_sha256"] is None else _sha256(item["takeover_consumption_receipt_sha256"], "ChiefTerm.takeover_consumption_receipt_sha256"), "observation": observation})
    return result


def validate_carrier_binding(value: Any) -> dict[str, Any]:
    fields = _common_fields({"carrier_id", "actor_id", "provider", "model", "session_id", "session_availability", "state", "bound_at", "last_observed_at", "observation"})
    item, result = _base(value, CARRIER_BINDING_V1, fields, "CarrierBinding")
    carrier_id = _id(item["carrier_id"], "CarrierBinding.carrier_id")
    actor_id = _id(item["actor_id"], "CarrierBinding.actor_id")
    provider = _id(item["provider"], "CarrierBinding.provider")
    model = _nullable_id(item["model"], "CarrierBinding.model")
    session = _nullable_id(item["session_id"], "CarrierBinding.session_id")
    availability = _enum(item["session_availability"], "CarrierBinding.session_availability", frozenset({"available", "unavailable", "unknown"}))
    if (session is None) == (availability == "available"):
        _fail("CarrierBinding session availability differs from session_id")
    bound_at = _timestamp(item["bound_at"], "CarrierBinding.bound_at")
    last_observed_at = _timestamp(item["last_observed_at"], "CarrierBinding.last_observed_at")
    if _parsed_timestamp(last_observed_at) < _parsed_timestamp(bound_at):
        _fail("CarrierBinding.last_observed_at precedes bound_at")
    state = _enum(item["state"], "CarrierBinding.state", frozenset({"active", "parked", "lost", "fenced", "unknown"}))
    observation = _observation(item["observation"], "CarrierBinding.observation")
    genesis_binding = {
        "company_id": result["company_id"],
        "company_incarnation": result["company_incarnation"],
        "lock_domain_generation": result["lock_domain_generation"],
    }
    expected_genesis_chief = (
        "genesis-chief-"
        + company_contract_sha256({
            **genesis_binding,
            "label": "chief",
        })[:24]
    )
    expected_genesis_carrier = (
        "genesis-chief-carrier-"
        + company_contract_sha256({
            **genesis_binding,
            "label": "chief_carrier",
        })[:24]
    )
    unknown_genesis_fence = (
        state == "fenced"
        and carrier_id == expected_genesis_carrier
        and actor_id == expected_genesis_chief
        and provider == "unknown"
        and model is None
        and session is None
        and availability == "unknown"
        and last_observed_at == bound_at
        and observation == {
            "state": "unknown",
            "reason": "provider_session_unavailable",
        }
    )
    if (
        state in {"lost", "fenced"}
        and observation["state"] != "known"
        and not unknown_genesis_fence
    ):
        _fail("terminal CarrierBinding requires a known observation")
    result.update({"carrier_id": carrier_id, "actor_id": actor_id, "provider": provider, "model": model, "session_id": session, "session_availability": availability,
                   "state": state, "bound_at": bound_at, "last_observed_at": last_observed_at, "observation": observation})
    return result


_EXECUTION_LINK_FIELDS = ("task_id", "packet_id", "thread_id", "turn_id", "agent_id", "job_id", "dispatch_id", "registration_id", "receipt_id")


def _execution_identity(item: Mapping[str, Any], label: str, *, require_parent: bool) -> dict[str, Any]:
    execution_id = _id(item["execution_id"], f"{label}.execution_id")
    execution_kind = _enum(item["execution_kind"], f"{label}.execution_kind", frozenset({"carrier", "agent", "turn", "job"}))
    execution_depth = _integer(item["execution_depth"], f"{label}.execution_depth", maximum=MAX_EXECUTION_DEPTH)
    execution_path = _id_list(item["execution_path"], f"{label}.execution_path", maximum=MAX_EXECUTION_DEPTH + 1)
    if len(execution_path) != execution_depth + 1 or execution_path[-1] != execution_id:
        _fail(f"{label}.execution_path does not identify this execution ancestry")
    parent = _nullable_id(item["parent_execution_id"], f"{label}.parent_execution_id") if require_parent else None
    if require_parent:
        if (parent is None) != (execution_depth == 0):
            _fail(f"{label} parent/execution_depth relation is invalid")
        if parent is not None and execution_path[-2] != parent:
            _fail(f"{label}.parent_execution_id must be the penultimate execution path")
    links = {name: _nullable_id(item[name], f"{label}.{name}") for name in _EXECUTION_LINK_FIELDS}
    carrier_id = _nullable_id(item["carrier_id"], f"{label}.carrier_id")
    if execution_kind == "carrier":
        if carrier_id is None or links["thread_id"] is None or any(links[name] is not None for name in ("agent_id", "job_id", "dispatch_id")):
            _fail(f"{label} carrier links are invalid")
    elif execution_kind == "agent":
        if links["agent_id"] is None or links["job_id"] is not None or (links["dispatch_id"] is None) == (links["registration_id"] is None):
            _fail(f"{label} agent links are invalid")
    elif execution_kind == "turn":
        if (carrier_id is None or links["thread_id"] is None or links["turn_id"] is None
                or links["registration_id"] is None
                or any(links[name] is not None for name in ("agent_id", "job_id", "dispatch_id"))):
            _fail(f"{label} turn links are invalid")
    elif (carrier_id is not None or links["job_id"] is None
            or any(links[name] is not None for name in ("thread_id", "turn_id", "agent_id"))
            or links["dispatch_id"] is not None
            or links["registration_id"] is not None):
        _fail(f"{label} job links are invalid")
    return {"execution_id": execution_id, "execution_kind": execution_kind, "execution_depth": execution_depth,
            "execution_path": execution_path, "parent_execution_id": parent, "carrier_id": carrier_id, **links}


def _execution_payload(value: Any, label: str) -> Any:
    payload = _canonical(value, label, maximum=MAX_EVENT_PAYLOAD_BYTES)
    protected = set(_EXECUTION_LINK_FIELDS) | {"execution_id", "execution_kind", "execution_depth", "execution_path", "parent_execution_id", "carrier_id", "provider", "model", "effort"}

    def inspect(member: Any) -> None:
        if isinstance(member, Mapping):
            if protected & set(member):
                _fail(f"{label} cannot carry lifecycle identity fields")
            for child in member.values():
                inspect(child)
        elif isinstance(member, Sequence) and not isinstance(member, (str, bytes, bytearray)):
            for child in member:
                inspect(child)

    inspect(payload)
    return payload


def validate_execution_node(value: Any) -> dict[str, Any]:
    fields = _common_fields({"execution_id", "execution_kind", "display_name", "organization_node_id", "department_id", "parent_execution_id", "execution_depth", "execution_path", "task_id", "packet_id", "thread_id", "turn_id", "agent_id", "job_id", "dispatch_id", "registration_id", "receipt_id", "provider", "model", "effort", "carrier_id", "role", "delegation_depth", "engineering_status", "runtime_status", "attention_overlays", "objective", "phase", "created_at", "updated_at", "last_event_at", "heartbeat_at", "wait_reason", "current_tool", "terminal_at", "usage_cursor", "job_ids", "evidence_ids", "provenance", "observation"})
    item, result = _base(value, EXECUTION_NODE_V1, fields, "ExecutionNode")
    identity = _execution_identity(item, "ExecutionNode", require_parent=True)
    delegation_depth = _integer(item["delegation_depth"], "ExecutionNode.delegation_depth", maximum=MAX_DEPTH)
    created = _timestamp(item["created_at"], "ExecutionNode.created_at")
    updated = _timestamp(item["updated_at"], "ExecutionNode.updated_at")
    last_event = _timestamp(item["last_event_at"], "ExecutionNode.last_event_at")
    heartbeat = None if item["heartbeat_at"] is None else _timestamp(item["heartbeat_at"], "ExecutionNode.heartbeat_at")
    terminal = None if item["terminal_at"] is None else _timestamp(item["terminal_at"], "ExecutionNode.terminal_at")
    if _parsed_timestamp(updated) < _parsed_timestamp(created) or _parsed_timestamp(last_event) < _parsed_timestamp(created) or _parsed_timestamp(last_event) > _parsed_timestamp(updated):
        _fail("ExecutionNode event timestamps are inconsistent")
    if heartbeat is not None and not (_parsed_timestamp(created) <= _parsed_timestamp(heartbeat) <= _parsed_timestamp(updated)):
        _fail("ExecutionNode heartbeat timestamp is inconsistent")
    engineering = _enum(item["engineering_status"], "ExecutionNode.engineering_status", frozenset({"active", "idle", "waiting", "blocked", "completed", "cancelled", "unknown"}))
    if engineering in {"completed", "cancelled"} and terminal is None:
        _fail("terminal engineering status requires terminal_at")
    if engineering not in {"completed", "cancelled"} and terminal is not None:
        _fail("nonterminal engineering status cannot have terminal_at")
    if terminal is not None and not (_parsed_timestamp(created) <= _parsed_timestamp(terminal) <= _parsed_timestamp(updated)):
        _fail("ExecutionNode terminal timestamp is inconsistent")
    runtime = _enum(item["runtime_status"], "ExecutionNode.runtime_status", frozenset({"running", "telemetry_silent", "confirmed_lost", "stopped", "unknown"}))
    evidence_ids = _id_list(item["evidence_ids"], "ExecutionNode.evidence_ids")
    provenance = _enum(item["provenance"], "ExecutionNode.provenance", _PROVENANCE)
    observation = _observation(item["observation"], "ExecutionNode.observation")
    if runtime == "running" and (
        provenance == "unknown" or observation["state"] != "known"
    ):
        _fail("running ExecutionNode requires known observation and non-unknown provenance")
    if runtime == "confirmed_lost" and (provenance != "AOI_verified" or not evidence_ids or observation != {"state": "known", "reason": "observed"}):
        _fail("confirmed_lost ExecutionNode requires AOI-verified evidence")
    if (engineering in {"completed", "cancelled"} or runtime == "stopped") and (provenance == "unknown" or observation["state"] != "known"):
        _fail("terminal ExecutionNode requires known observation and non-unknown provenance")
    organization_node_id = _nullable_id(item["organization_node_id"], "ExecutionNode.organization_node_id")
    department_id = _nullable_id(item["department_id"], "ExecutionNode.department_id")
    if organization_node_id is None and (
        identity["registration_id"] is None or identity["dispatch_id"] is not None
        or identity["parent_execution_id"] is not None or identity["execution_depth"] != 0
        or identity["execution_path"] != [identity["execution_id"]] or department_id is not None
    ):
        _fail("organization_node_id may be null only for a registered unattached root execution")
    result.update({**identity, "display_name": _text(item["display_name"], "ExecutionNode.display_name", maximum=256), "organization_node_id": organization_node_id, "department_id": department_id,
                   "provider": _id(item["provider"], "ExecutionNode.provider"), "model": _nullable_id(item["model"], "ExecutionNode.model"), "effort": _nullable_id(item["effort"], "ExecutionNode.effort"), "role": _id(item["role"], "ExecutionNode.role"), "delegation_depth": delegation_depth,
                   "engineering_status": engineering, "runtime_status": runtime, "attention_overlays": _attention_overlays(item["attention_overlays"], "ExecutionNode.attention_overlays"),
                   "objective": _text(item["objective"], "ExecutionNode.objective"), "phase": _id(item["phase"], "ExecutionNode.phase"), "created_at": created, "updated_at": updated, "last_event_at": last_event, "heartbeat_at": heartbeat, "wait_reason": None if item["wait_reason"] is None else _text(item["wait_reason"], "ExecutionNode.wait_reason", maximum=MAX_SHORT_TEXT_BYTES), "current_tool": _nullable_id(item["current_tool"], "ExecutionNode.current_tool"), "terminal_at": terminal, "usage_cursor": _integer(item["usage_cursor"], "ExecutionNode.usage_cursor", maximum=999_999_999_999), "job_ids": _id_list(item["job_ids"], "ExecutionNode.job_ids"), "evidence_ids": evidence_ids, "provenance": provenance, "observation": observation})
    return result


def validate_execution_event(value: Any) -> dict[str, Any]:
    fields = _common_fields({"event_id", "execution_id", "execution_kind", "display_name", "parent_execution_id", "execution_depth", "execution_path", "task_id", "packet_id", "thread_id", "turn_id", "agent_id", "job_id", "dispatch_id", "registration_id", "receipt_id", "provider", "model", "effort", "carrier_id", "delegation_depth", "event_type", "recorded_at", "engineering_status", "runtime_status", "attention_overlays", "payload", "payload_sha256", "evidence_ids", "provenance", "observation"})
    item, result = _base(value, EXECUTION_EVENT_V1, fields, "ExecutionEvent")
    identity = _execution_identity(item, "ExecutionEvent", require_parent=True)
    delegation_depth = _integer(item["delegation_depth"], "ExecutionEvent.delegation_depth", maximum=MAX_DEPTH)
    payload = _execution_payload(item["payload"], "ExecutionEvent.payload")
    if company_contract_sha256(payload, max_bytes=MAX_EVENT_PAYLOAD_BYTES) != _sha256(item["payload_sha256"], "ExecutionEvent.payload_sha256"):
        _fail("ExecutionEvent.payload_sha256 differs")
    engineering = _enum(item["engineering_status"], "ExecutionEvent.engineering_status", frozenset({"active", "idle", "waiting", "blocked", "completed", "cancelled", "unknown"}))
    runtime = _enum(item["runtime_status"], "ExecutionEvent.runtime_status", frozenset({"running", "telemetry_silent", "confirmed_lost", "stopped", "unknown"}))
    evidence_ids = _id_list(item["evidence_ids"], "ExecutionEvent.evidence_ids")
    provenance = _enum(item["provenance"], "ExecutionEvent.provenance", _PROVENANCE)
    observation = _observation(item["observation"], "ExecutionEvent.observation")
    if runtime == "running" and (
        provenance == "unknown" or observation["state"] != "known"
    ):
        _fail("running ExecutionEvent requires known observation and non-unknown provenance")
    if runtime == "confirmed_lost" and (provenance != "AOI_verified" or not evidence_ids or observation != {"state": "known", "reason": "observed"}):
        _fail("confirmed_lost ExecutionEvent requires AOI-verified evidence")
    if (engineering in {"completed", "cancelled"} or runtime == "stopped") and (provenance == "unknown" or observation["state"] != "known"):
        _fail("terminal ExecutionEvent requires known observation and non-unknown provenance")
    result.update({"event_id": _id(item["event_id"], "ExecutionEvent.event_id"), **identity, "display_name": _text(item["display_name"], "ExecutionEvent.display_name", maximum=256), "provider": _id(item["provider"], "ExecutionEvent.provider"), "model": _nullable_id(item["model"], "ExecutionEvent.model"), "effort": _nullable_id(item["effort"], "ExecutionEvent.effort"), "delegation_depth": delegation_depth, "event_type": _id(item["event_type"], "ExecutionEvent.event_type"), "recorded_at": _timestamp(item["recorded_at"], "ExecutionEvent.recorded_at"),
                   "engineering_status": engineering, "runtime_status": runtime, "attention_overlays": _attention_overlays(item["attention_overlays"], "ExecutionEvent.attention_overlays"), "payload": payload, "payload_sha256": _sha256(item["payload_sha256"], "ExecutionEvent.payload_sha256"), "evidence_ids": evidence_ids, "provenance": provenance, "observation": observation})
    return result


def validate_mutation_intent(value: Any) -> dict[str, Any]:
    fields = _common_fields({"intent_id", "execution_id", "mutation_kind", "command_id", "command_blob", "scope_sha256", "actor_authority", "state", "expected_head_sha256", "created_at", "updated_at", "effect_evidence", "reconcile_ref", "observation"})
    item, result = _base(value, MUTATION_INTENT_V1, fields, "MutationIntent")
    authority = validate_actor_authority(item["actor_authority"])
    if _company_binding(authority, "MutationIntent.actor_authority") != _embedded_binding(item, "MutationIntent"):
        _fail("MutationIntent actor binding differs")
    state = _enum(item["state"], "MutationIntent.state", _MUTATION_STATES)
    mutation_kind = _id(item["mutation_kind"], "MutationIntent.mutation_kind")
    permission = _MUTATION_KIND_PERMISSIONS.get(mutation_kind)
    if authority["authority_state"] != "active" or permission is None or permission not in authority["permissions"]:
        _fail("MutationIntent requires active authority for its known mutation_kind")
    evidence = _blob_refs(item["effect_evidence"], "MutationIntent.effect_evidence")
    reconcile = _nullable_id(item["reconcile_ref"], "MutationIntent.reconcile_ref")
    observation = _observation(item["observation"], "MutationIntent.observation")
    if state in {"prepared", "admitted", "in_flight"} and (evidence or reconcile is not None):
        _fail("nonterminal MutationIntent cannot assert effect evidence or reconciliation")
    if state in {"committed", "failed_known"} and (not evidence or reconcile is not None or observation["state"] != "known" or authority["provenance"] == "unknown" or any(blob["availability"] != "available" for blob in evidence)):
        _fail("terminal MutationIntent requires available effect evidence without reconciliation")
    if state in {"effect_unknown", "reconcile_required"} and (not evidence or reconcile is None or observation["state"] == "known" or any(blob["availability"] != "available" for blob in evidence)):
        _fail("uncertain mutation requires evidence and reconciliation")
    if state == "aborted" and (evidence or reconcile is not None or observation["state"] != "known" or authority["provenance"] == "unknown"):
        _fail("aborted MutationIntent requires a known, non-unknown-provenance observation without effect claims")
    if state == "unknown" and (observation["state"] != "unknown" or evidence or reconcile is not None):
        _fail("unknown MutationIntent requires unknown observation without effect claims")
    command_blob = validate_blob_ref(item["command_blob"])
    if command_blob["availability"] != "available":
        _fail("MutationIntent command_blob must be available")
    created = _timestamp(item["created_at"], "MutationIntent.created_at")
    updated = _timestamp(item["updated_at"], "MutationIntent.updated_at")
    if _parsed_timestamp(updated) < _parsed_timestamp(created):
        _fail("MutationIntent.updated_at precedes created_at")
    result.update({"intent_id": _id(item["intent_id"], "MutationIntent.intent_id"), "execution_id": _nullable_id(item["execution_id"], "MutationIntent.execution_id"), "mutation_kind": mutation_kind, "command_id": _id(item["command_id"], "MutationIntent.command_id"), "command_blob": command_blob, "scope_sha256": _sha256(item["scope_sha256"], "MutationIntent.scope_sha256"), "actor_authority": authority, "state": state, "expected_head_sha256": _sha256(item["expected_head_sha256"], "MutationIntent.expected_head_sha256"), "created_at": created, "updated_at": updated, "effect_evidence": evidence, "reconcile_ref": reconcile, "observation": observation})
    return result


def _external_job_handle(value: Any, label: str) -> dict[str, str] | None:
    if value is None:
        return None
    item = _object(value, {"provider", "namespace", "resolver", "native_handle", "host_fingerprint_sha256"}, label)
    return {"provider": _id(item["provider"], f"{label}.provider"),
            "namespace": _id(item["namespace"], f"{label}.namespace"),
            "resolver": _id(item["resolver"], f"{label}.resolver"),
            "native_handle": _id(item["native_handle"], f"{label}.native_handle"),
            "host_fingerprint_sha256": _sha256(item["host_fingerprint_sha256"], f"{label}.host_fingerprint_sha256")}


def validate_external_job(value: Any) -> dict[str, Any]:
    fields = _common_fields({"job_id", "owner_execution_id", "mutation_intent_id", "command_id", "command_blob", "scope_sha256", "actor_authority", "state", "external_handle", "process_fingerprint_sha256", "process_observation", "created_at", "updated_at", "terminal_at", "effect_evidence", "reconcile_ref", "observation"})
    item, result = _base(value, EXTERNAL_JOB_V1, fields, "ExternalJob")
    authority = validate_actor_authority(item["actor_authority"])
    if _company_binding(authority, "ExternalJob.actor_authority") != _embedded_binding(item, "ExternalJob"):
        _fail("ExternalJob actor binding differs")
    state = _enum(item["state"], "ExternalJob.state", frozenset({"queued", "running", "completed", "failed_known", "effect_unknown", "reconcile_required", "aborted", "unknown"}))
    if authority["authority_state"] != "active" or "job.start" not in authority["permissions"]:
        _fail("ExternalJob requires active job.start authority")
    evidence = _blob_refs(item["effect_evidence"], "ExternalJob.effect_evidence")
    reconcile_ref = _nullable_id(
        item["reconcile_ref"],
        "ExternalJob.reconcile_ref",
    )
    command_blob = validate_blob_ref(item["command_blob"])
    if command_blob["availability"] != "available":
        _fail("ExternalJob command_blob must be available")
    created = _timestamp(item["created_at"], "ExternalJob.created_at")
    updated = _timestamp(item["updated_at"], "ExternalJob.updated_at")
    terminal = None if item["terminal_at"] is None else _timestamp(item["terminal_at"], "ExternalJob.terminal_at")
    if _parsed_timestamp(updated) < _parsed_timestamp(created) or (terminal is not None and not (_parsed_timestamp(created) <= _parsed_timestamp(terminal) <= _parsed_timestamp(updated))):
        _fail("ExternalJob timestamps are inconsistent")
    if state in {"completed", "failed_known", "aborted"} and terminal is None:
        _fail("terminal ExternalJob state requires terminal_at")
    if state not in {"completed", "failed_known", "aborted"} and terminal is not None:
        _fail("nonterminal ExternalJob state cannot have terminal_at")
    external_handle = _external_job_handle(item["external_handle"], "ExternalJob.external_handle")
    process_observation = _observation(item["process_observation"], "ExternalJob.process_observation")
    fingerprint = None if item["process_fingerprint_sha256"] is None else _sha256(item["process_fingerprint_sha256"], "ExternalJob.process_fingerprint_sha256")
    if process_observation["state"] == "known" and fingerprint is None:
        _fail("known process observation requires a process fingerprint")
    if (
        process_observation["state"] != "known"
        and fingerprint is not None
        and state not in {"effect_unknown", "reconcile_required"}
    ):
        _fail("non-known process observation cannot assert a process fingerprint")
    observation = _observation(item["observation"], "ExternalJob.observation")
    if state == "queued":
        if external_handle is not None or fingerprint is not None or evidence or reconcile_ref is not None or process_observation != {"state": "unavailable", "reason": "not_started"}:
            _fail("queued ExternalJob cannot claim a process or effects")
    elif state == "running":
        if external_handle is None or reconcile_ref is not None or process_observation["state"] != "known" or observation["state"] != "known" or authority["provenance"] == "unknown":
            _fail("running ExternalJob requires a known, non-unknown-provenance process observation")
    elif state in {"completed", "failed_known"}:
        if external_handle is None or reconcile_ref is not None or process_observation["state"] != "known" or observation["state"] != "known" or authority["provenance"] == "unknown" or not evidence or any(blob["availability"] != "available" for blob in evidence):
            _fail("completed or failed ExternalJob requires known provenance, observation, process, and available effects")
    if state in {"effect_unknown", "reconcile_required"}:
        if not evidence or any(blob["availability"] != "available" for blob in evidence):
            _fail("uncertain ExternalJob requires available effect evidence")
        if external_handle is None:
            _fail("uncertain ExternalJob requires a durable external handle")
        if reconcile_ref is None:
            _fail("uncertain ExternalJob requires reconciliation")
        if process_observation["reason"] == "not_started":
            _fail("uncertain ExternalJob cannot claim it was not started")
    if state == "aborted" and (external_handle is not None or fingerprint is not None or evidence or reconcile_ref is not None or process_observation != {"state": "unavailable", "reason": "aborted_before_launch"} or observation["state"] != "known" or authority["provenance"] == "unknown"):
        _fail("aborted-before-launch ExternalJob requires a known, non-unknown-provenance observation without process or effect claims")
    if state == "unknown" and (external_handle is not None or fingerprint is not None or evidence or reconcile_ref is not None or process_observation["state"] != "unknown" or observation["state"] != "unknown"):
        _fail("unknown ExternalJob requires unknown observation without process or effect claims")
    # The ledger/reconciler must still bind uncertain jobs to the referenced
    # MutationIntent atomically; this pure payload has no authority to prove it.
    result.update({"job_id": _id(item["job_id"], "ExternalJob.job_id"), "owner_execution_id": _id(item["owner_execution_id"], "ExternalJob.owner_execution_id"), "mutation_intent_id": _id(item["mutation_intent_id"], "ExternalJob.mutation_intent_id"), "command_id": _id(item["command_id"], "ExternalJob.command_id"), "command_blob": command_blob, "scope_sha256": _sha256(item["scope_sha256"], "ExternalJob.scope_sha256"), "actor_authority": authority, "state": state, "external_handle": external_handle, "process_fingerprint_sha256": fingerprint, "process_observation": process_observation, "created_at": created, "updated_at": updated, "terminal_at": terminal, "effect_evidence": evidence, "reconcile_ref": reconcile_ref, "observation": observation})
    return result


def validate_dispatch_request(value: Any) -> dict[str, Any]:
    """Validate one immutable dispatch-request revision without resolving it."""
    fields = _common_fields({
        "dispatch_request_id", "dispatch_revision_id", "revision",
        "previous_event_id", "previous_payload_sha256", "command_id",
        "reservation_id", "task_id", "packet_id", "manager_node_id",
        "target_node_id", "department_id", "parent_execution_id",
        "requested_role", "requested_capability_tier", "route_policy_id",
        "scope_sha256", "delegation_depth", "state", "attempt",
        "provider_dispatch_id", "execution_id", "effect_evidence",
        "reconcile_ref", "resolves_event_ids", "created_at", "updated_at",
        "provenance", "observation",
    })
    item, result = _base(value, DISPATCH_REQUEST_V1, fields, "DispatchRequest")
    revision = _integer(item["revision"], "DispatchRequest.revision", minimum=1, maximum=999_999_999_999)
    previous_event_id = _nullable_id(item["previous_event_id"], "DispatchRequest.previous_event_id")
    previous_payload_sha256 = _nullable_sha256(
        item["previous_payload_sha256"], "DispatchRequest.previous_payload_sha256"
    )
    if (revision == 1 and (previous_event_id is not None or previous_payload_sha256 is not None)) or (
        revision > 1 and (previous_event_id is None or previous_payload_sha256 is None)
    ):
        _fail("DispatchRequest revision and predecessor differ")
    state = _enum(item["state"], "DispatchRequest.state", _DISPATCH_REQUEST_STATES)
    attempt = _integer(item["attempt"], "DispatchRequest.attempt", maximum=1)
    expected_attempt = 0 if state in {"queued", "admitted", "cancelled"} else 1
    if attempt != expected_attempt:
        _fail("DispatchRequest attempt and state differ")
    provider_dispatch_id = _nullable_id(item["provider_dispatch_id"], "DispatchRequest.provider_dispatch_id")
    execution_id = _nullable_id(item["execution_id"], "DispatchRequest.execution_id")
    if state == "dispatched":
        if provider_dispatch_id is None or execution_id is None:
            _fail("dispatched DispatchRequest requires provider and execution identity")
    elif provider_dispatch_id is not None or execution_id is not None:
        _fail("only dispatched DispatchRequest may assert provider or execution identity")
    evidence = _blob_refs(item["effect_evidence"], "DispatchRequest.effect_evidence")
    reconcile_ref = _nullable_id(item["reconcile_ref"], "DispatchRequest.reconcile_ref")
    observation = _observation(item["observation"], "DispatchRequest.observation")
    provenance = _enum(item["provenance"], "DispatchRequest.provenance", _PROVENANCE)
    if state in {"queued", "admitted", "in_flight", "cancelled"} and (evidence or reconcile_ref is not None):
        _fail("unresolved DispatchRequest cannot assert effect evidence or reconciliation")
    if state in {"dispatched", "failed_known"} and (
        not evidence or any(blob["availability"] != "available" for blob in evidence)
        or reconcile_ref is not None or observation["state"] != "known" or provenance == "unknown"
    ):
        _fail("known DispatchRequest outcome requires available evidence and known provenance")
    if state == "effect_unknown" and (
        not evidence or any(blob["availability"] != "available" for blob in evidence)
        or reconcile_ref is None or observation["state"] == "known"
    ):
        _fail("effect-unknown DispatchRequest requires available evidence, reconciliation, and non-known observation")
    resolves_event_ids = _id_list(item["resolves_event_ids"], "DispatchRequest.resolves_event_ids")
    if resolves_event_ids and state not in {"dispatched", "failed_known"}:
        _fail("only dispatched or failed DispatchRequest may resolve events")
    created_at = _timestamp(item["created_at"], "DispatchRequest.created_at")
    updated_at = _timestamp(item["updated_at"], "DispatchRequest.updated_at")
    if _parsed_timestamp(updated_at) < _parsed_timestamp(created_at):
        _fail("DispatchRequest.updated_at precedes created_at")
    # The reducer, not this standalone payload validator, proves predecessor
    # adjacency and whether resolved events belong to another revision.
    result.update({
        "dispatch_request_id": _id(item["dispatch_request_id"], "DispatchRequest.dispatch_request_id"),
        "dispatch_revision_id": _id(item["dispatch_revision_id"], "DispatchRequest.dispatch_revision_id"),
        "revision": revision, "previous_event_id": previous_event_id,
        "previous_payload_sha256": previous_payload_sha256,
        "command_id": _id(item["command_id"], "DispatchRequest.command_id"),
        "reservation_id": _id(item["reservation_id"], "DispatchRequest.reservation_id"),
        "task_id": _nullable_id(item["task_id"], "DispatchRequest.task_id"),
        "packet_id": _nullable_id(item["packet_id"], "DispatchRequest.packet_id"),
        "manager_node_id": _id(item["manager_node_id"], "DispatchRequest.manager_node_id"),
        "target_node_id": _id(item["target_node_id"], "DispatchRequest.target_node_id"),
        "department_id": _nullable_id(item["department_id"], "DispatchRequest.department_id"),
        "parent_execution_id": _id(item["parent_execution_id"], "DispatchRequest.parent_execution_id"),
        "requested_role": _id(item["requested_role"], "DispatchRequest.requested_role"),
        "requested_capability_tier": _id(item["requested_capability_tier"], "DispatchRequest.requested_capability_tier"),
        "route_policy_id": _id(item["route_policy_id"], "DispatchRequest.route_policy_id"),
        "scope_sha256": _sha256(item["scope_sha256"], "DispatchRequest.scope_sha256"),
        "delegation_depth": _integer(item["delegation_depth"], "DispatchRequest.delegation_depth", maximum=MAX_DEPTH),
        "state": state, "attempt": attempt, "provider_dispatch_id": provider_dispatch_id,
        "execution_id": execution_id, "effect_evidence": evidence,
        "reconcile_ref": reconcile_ref, "resolves_event_ids": resolves_event_ids,
        "created_at": created_at, "updated_at": updated_at,
        "provenance": provenance, "observation": observation,
    })
    return result


def validate_provider_lifecycle_receipt(value: Any) -> dict[str, Any]:
    """Validate one structurally cross-bindable provider lifecycle fact.

    This receipt is cooperative adapter evidence, not a provider signature.  Its
    raw artifact remains content-addressed so the state owner can degrade
    coverage if those bytes are no longer available.
    """

    fields = _common_fields({
        "receipt_id", "source_event_id", "event_kind", "transaction_id",
        "command_id", "dispatch_request_id", "dispatch_revision_id",
        "dispatch_revision",
        "provider_dispatch_id", "execution_id", "carrier_id",
        "organization_node_id", "provider", "model", "effort",
        "session_id", "thread_id", "reconcile_ref", "observed_at",
        "provenance", "observation", "raw_artifact", "receipt_sha256",
    })
    item, result = _base(
        value,
        PROVIDER_LIFECYCLE_RECEIPT_V1,
        fields,
        "ProviderLifecycleReceipt",
    )
    event_kind = _enum(
        item["event_kind"],
        "ProviderLifecycleReceipt.event_kind",
        _PROVIDER_LIFECYCLE_EVENTS,
    )
    dispatch_request_id = _nullable_id(
        item["dispatch_request_id"],
        "ProviderLifecycleReceipt.dispatch_request_id",
    )
    dispatch_revision_id = _nullable_id(
        item["dispatch_revision_id"],
        "ProviderLifecycleReceipt.dispatch_revision_id",
    )
    dispatch_revision = (
        None
        if item["dispatch_revision"] is None
        else _integer(
            item["dispatch_revision"],
            "ProviderLifecycleReceipt.dispatch_revision",
            minimum=1,
            maximum=999_999_999_999,
        )
    )
    provider_dispatch_id = _nullable_id(
        item["provider_dispatch_id"],
        "ProviderLifecycleReceipt.provider_dispatch_id",
    )
    execution_id = _nullable_id(
        item["execution_id"],
        "ProviderLifecycleReceipt.execution_id",
    )
    carrier_id = _nullable_id(
        item["carrier_id"],
        "ProviderLifecycleReceipt.carrier_id",
    )
    session_id = _nullable_id(
        item["session_id"],
        "ProviderLifecycleReceipt.session_id",
    )
    thread_id = _nullable_id(
        item["thread_id"],
        "ProviderLifecycleReceipt.thread_id",
    )
    reconcile_ref = _nullable_id(
        item["reconcile_ref"],
        "ProviderLifecycleReceipt.reconcile_ref",
    )
    dispatch_lineage = (
        dispatch_request_id,
        dispatch_revision_id,
        dispatch_revision,
    )
    runtime_identity = (
        provider_dispatch_id,
        execution_id,
        carrier_id,
        session_id,
        thread_id,
    )
    if event_kind == "dispatch_succeeded":
        if (
            any(member is None for member in dispatch_lineage)
            or any(member is None for member in runtime_identity)
        ):
            _fail(
                "known provider runtime lifecycle requires complete runtime "
                "identity",
            )
        if reconcile_ref is not None:
            _fail("known provider runtime lifecycle cannot require reconciliation")
    elif event_kind == "execution_stopped":
        root_stop = (
            all(member is None for member in dispatch_lineage)
            and provider_dispatch_id is None
        )
        dispatched_stop = (
            all(member is not None for member in dispatch_lineage)
            and provider_dispatch_id is not None
        )
        if (
            execution_id is None
            or carrier_id is None
            or session_id is None
            or thread_id is None
            or not (root_stop or dispatched_stop)
        ):
            _fail(
                "provider execution stop requires exact root or dispatch "
                "lineage",
            )
        if reconcile_ref is not None:
            _fail("known provider runtime lifecycle cannot require reconciliation")
    elif (
        any(member is None for member in dispatch_lineage)
        or any(member is not None for member in runtime_identity)
    ):
        _fail(
            "provider dispatch outcome requires dispatch lineage without "
            "runtime identity",
        )
    elif event_kind == "dispatch_effect_unknown":
        if reconcile_ref is None:
            _fail("effect-unknown provider lifecycle requires reconciliation")
    elif reconcile_ref is not None:
        _fail("known dispatch failure cannot require reconciliation")

    provenance = _enum(
        item["provenance"],
        "ProviderLifecycleReceipt.provenance",
        _PROVENANCE,
    )
    if provenance not in _PROVIDER_RECEIPT_PROVENANCE:
        _fail("ProviderLifecycleReceipt provenance is not provider grade")
    observation = _observation(
        item["observation"],
        "ProviderLifecycleReceipt.observation",
    )
    if event_kind == "dispatch_effect_unknown":
        if observation["state"] == "known":
            _fail("effect-unknown provider lifecycle cannot be known")
    elif observation["state"] != "known":
        _fail("known provider lifecycle requires a known observation")
    raw_artifact = validate_blob_ref(item["raw_artifact"])
    if (
        raw_artifact["availability"] != "available"
        or raw_artifact["media_type"]
        != PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE
        or raw_artifact["size_bytes"]
        > MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES
    ):
        _fail("ProviderLifecycleReceipt requires an available raw artifact")
    provider = _id(item["provider"], "ProviderLifecycleReceipt.provider")
    if provider == "unknown":
        _fail("ProviderLifecycleReceipt requires a known provider")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(
        item["receipt_sha256"],
        "ProviderLifecycleReceipt.receipt_sha256",
    )
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("ProviderLifecycleReceipt.receipt_sha256 differs")
    result.update({
        "receipt_id": _id(
            item["receipt_id"],
            "ProviderLifecycleReceipt.receipt_id",
        ),
        "source_event_id": _id(
            item["source_event_id"],
            "ProviderLifecycleReceipt.source_event_id",
        ),
        "event_kind": event_kind,
        "transaction_id": _id(
            item["transaction_id"],
            "ProviderLifecycleReceipt.transaction_id",
        ),
        "command_id": _id(
            item["command_id"],
            "ProviderLifecycleReceipt.command_id",
        ),
        "dispatch_request_id": dispatch_request_id,
        "dispatch_revision_id": dispatch_revision_id,
        "dispatch_revision": dispatch_revision,
        "provider_dispatch_id": provider_dispatch_id,
        "execution_id": execution_id,
        "carrier_id": carrier_id,
        "organization_node_id": _id(
            item["organization_node_id"],
            "ProviderLifecycleReceipt.organization_node_id",
        ),
        "provider": provider,
        "model": _nullable_id(
            item["model"],
            "ProviderLifecycleReceipt.model",
        ),
        "effort": _nullable_id(
            item["effort"],
            "ProviderLifecycleReceipt.effort",
        ),
        "session_id": session_id,
        "thread_id": thread_id,
        "reconcile_ref": reconcile_ref,
        "observed_at": _timestamp(
            item["observed_at"],
            "ProviderLifecycleReceipt.observed_at",
        ),
        "provenance": provenance,
        "observation": observation,
        "raw_artifact": raw_artifact,
        "receipt_sha256": receipt_sha256,
    })
    return result


def validate_provider_lifecycle_source(value: Any) -> dict[str, Any]:
    """Validate the canonical adapter source bytes referenced by a receipt."""

    fields = {
        "source_type", "schema_version", "company_id",
        "company_incarnation", "lock_domain_generation", "source_event_id",
        "event_kind", "dispatch_request_id", "provider_dispatch_id",
        "execution_id", "carrier_id", "organization_node_id", "provider",
        "model", "effort", "session_id", "thread_id", "reconcile_ref",
        "observed_at", "provenance", "observation",
    }
    item = _object(value, fields, "ProviderLifecycleSource")
    if item["source_type"] != PROVIDER_LIFECYCLE_SOURCE_V1:
        _fail("ProviderLifecycleSource.source_type is invalid")
    if _integer(
        item["schema_version"],
        "ProviderLifecycleSource.schema_version",
        minimum=1,
        maximum=1,
    ) != 1:
        _fail("ProviderLifecycleSource.schema_version is unsupported")
    binding = _embedded_binding(item, "ProviderLifecycleSource")
    event_kind = _enum(
        item["event_kind"],
        "ProviderLifecycleSource.event_kind",
        _PROVIDER_LIFECYCLE_EVENTS,
    )
    dispatch_request_id = _nullable_id(
        item["dispatch_request_id"],
        "ProviderLifecycleSource.dispatch_request_id",
    )
    provider_dispatch_id = _nullable_id(
        item["provider_dispatch_id"],
        "ProviderLifecycleSource.provider_dispatch_id",
    )
    execution_id = _nullable_id(
        item["execution_id"],
        "ProviderLifecycleSource.execution_id",
    )
    carrier_id = _nullable_id(
        item["carrier_id"],
        "ProviderLifecycleSource.carrier_id",
    )
    session_id = _nullable_id(
        item["session_id"],
        "ProviderLifecycleSource.session_id",
    )
    thread_id = _nullable_id(
        item["thread_id"],
        "ProviderLifecycleSource.thread_id",
    )
    reconcile_ref = _nullable_id(
        item["reconcile_ref"],
        "ProviderLifecycleSource.reconcile_ref",
    )
    runtime_identity = (
        provider_dispatch_id,
        execution_id,
        carrier_id,
        session_id,
        thread_id,
    )
    if event_kind == "dispatch_succeeded":
        if (
            dispatch_request_id is None
            or any(member is None for member in runtime_identity)
        ):
            _fail(
                "known provider source requires complete runtime identity",
            )
        if reconcile_ref is not None:
            _fail("known provider source cannot require reconciliation")
    elif event_kind == "execution_stopped":
        root_stop = (
            dispatch_request_id is None
            and provider_dispatch_id is None
        )
        dispatched_stop = (
            dispatch_request_id is not None
            and provider_dispatch_id is not None
        )
        if (
            execution_id is None
            or carrier_id is None
            or session_id is None
            or thread_id is None
            or not (root_stop or dispatched_stop)
        ):
            _fail(
                "provider execution stop source requires exact root or "
                "dispatch lineage",
            )
        if reconcile_ref is not None:
            _fail("known provider source cannot require reconciliation")
    elif (
        dispatch_request_id is None
        or any(member is not None for member in runtime_identity)
    ):
        _fail(
            "provider dispatch source requires dispatch lineage without "
            "runtime identity",
        )
    elif event_kind == "dispatch_effect_unknown":
        if reconcile_ref is None:
            _fail("effect-unknown provider source requires reconciliation")
    elif reconcile_ref is not None:
        _fail("known provider source failure cannot require reconciliation")
    provenance = _enum(
        item["provenance"],
        "ProviderLifecycleSource.provenance",
        _PROVENANCE,
    )
    if provenance not in _PROVIDER_RECEIPT_PROVENANCE:
        _fail("ProviderLifecycleSource provenance is not provider grade")
    observation = _observation(
        item["observation"],
        "ProviderLifecycleSource.observation",
    )
    if event_kind == "dispatch_effect_unknown":
        if observation["state"] == "known":
            _fail("effect-unknown provider source cannot be known")
    elif observation["state"] != "known":
        _fail("known provider source requires a known observation")
    provider = _id(item["provider"], "ProviderLifecycleSource.provider")
    if provider == "unknown":
        _fail("ProviderLifecycleSource requires a known provider")
    return {
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        **binding,
        "source_event_id": _id(
            item["source_event_id"],
            "ProviderLifecycleSource.source_event_id",
        ),
        "event_kind": event_kind,
        "dispatch_request_id": dispatch_request_id,
        "provider_dispatch_id": provider_dispatch_id,
        "execution_id": execution_id,
        "carrier_id": carrier_id,
        "organization_node_id": _id(
            item["organization_node_id"],
            "ProviderLifecycleSource.organization_node_id",
        ),
        "provider": provider,
        "model": _nullable_id(
            item["model"],
            "ProviderLifecycleSource.model",
        ),
        "effort": _nullable_id(
            item["effort"],
            "ProviderLifecycleSource.effort",
        ),
        "session_id": session_id,
        "thread_id": thread_id,
        "reconcile_ref": reconcile_ref,
        "observed_at": _timestamp(
            item["observed_at"],
            "ProviderLifecycleSource.observed_at",
        ),
        "provenance": provenance,
        "observation": observation,
    }


_RUNTIME_OBSERVATION_TRANSITIONS = frozenset({
    "telemetry_silent", "recovered", "confirmed_lost",
})
_RUNTIME_RECOVERY_ACTIVITY_KINDS = frozenset({
    "codex.item_started", "codex.subagent_activity",
    "claude.subagent_started",
})


def _runtime_observation_source_fields(value: Any, label: str) -> dict[str, Any]:
    fields = {
        "source_type", "schema_version", "company_id", "company_incarnation",
        "lock_domain_generation", "source_event_id", "receipt_id",
        "execution_id", "carrier_id", "transition", "activity_kind",
        "provider_registry", "host_process", "terminal_grace", "collector_health",
        "observed_at", "provenance", "observation",
    }
    item = _object(value, fields, label)
    if item["source_type"] != EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1:
        _fail(f"{label}.source_type is invalid")
    if _integer(item["schema_version"], f"{label}.schema_version", minimum=1, maximum=1) != 1:
        _fail(f"{label}.schema_version is unsupported")
    binding = _embedded_binding(item, label)
    transition = _enum(item["transition"], f"{label}.transition", _RUNTIME_OBSERVATION_TRANSITIONS)
    activity_kind = _nullable_id(item["activity_kind"], f"{label}.activity_kind")
    registry = _enum(item["provider_registry"], f"{label}.provider_registry", frozenset({"absent", "present", "unknown"}))
    host = _enum(item["host_process"], f"{label}.host_process", frozenset({"absent", "present", "unknown"}))
    grace = _enum(item["terminal_grace"], f"{label}.terminal_grace", frozenset({"elapsed", "not_elapsed", "unknown"}))
    collector = _enum(item["collector_health"], f"{label}.collector_health", frozenset({"healthy", "unhealthy", "unknown"}))
    provenance = _enum(item["provenance"], f"{label}.provenance", _PROVENANCE)
    observation = _observation(item["observation"], f"{label}.observation")
    if (
        provenance != "AOI_verified"
        or observation != {"state": "known", "reason": "observed"}
    ):
        _fail(f"{label} requires an AOI-verified known observation")
    if transition == "recovered":
        if activity_kind not in _RUNTIME_RECOVERY_ACTIVITY_KINDS:
            _fail(f"{label}.recovered requires an exact joined activity")
    elif activity_kind is not None:
        _fail(f"{label} only recovery may assert activity_kind")
    if transition == "telemetry_silent" and collector != "healthy":
        _fail(f"{label}.telemetry_silent requires healthy collector coverage")
    if transition == "confirmed_lost":
        if (registry, host, grace, collector) != (
            "absent",
            "absent",
            "elapsed",
            "healthy",
        ):
            _fail(f"{label}.confirmed_lost evidence matrix is incomplete")
    return {
        "source_type": EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1,
        "schema_version": 1, **binding,
        "source_event_id": _id(item["source_event_id"], f"{label}.source_event_id"),
        "receipt_id": _id(item["receipt_id"], f"{label}.receipt_id"),
        "execution_id": _id(item["execution_id"], f"{label}.execution_id"),
        "carrier_id": _id(item["carrier_id"], f"{label}.carrier_id"),
        "transition": transition, "activity_kind": activity_kind,
        "provider_registry": registry, "host_process": host,
        "terminal_grace": grace, "collector_health": collector,
        "observed_at": _timestamp(item["observed_at"], f"{label}.observed_at"),
        "provenance": provenance, "observation": observation,
    }


def validate_execution_runtime_observation_source(value: Any) -> dict[str, Any]:
    """Validate immutable raw observation bytes for a nonterminal runtime change."""
    return _runtime_observation_source_fields(value, "ExecutionRuntimeObservationSource")


def validate_execution_runtime_observation_receipt(value: Any) -> dict[str, Any]:
    fields = _common_fields({
        "receipt_id", "source_event_id", "transaction_id", "command_id",
        "execution_id", "carrier_id", "transition", "activity_kind",
        "provider_registry", "host_process", "terminal_grace", "collector_health",
        "observed_at", "provenance", "observation", "raw_artifact", "receipt_sha256",
    })
    item, result = _base(value, EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1, fields, "ExecutionRuntimeObservationReceipt")
    source = _runtime_observation_source_fields({
        "source_type": EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1, "schema_version": 1,
        "company_id": item["company_id"], "company_incarnation": item["company_incarnation"],
        "lock_domain_generation": item["lock_domain_generation"], "source_event_id": item["source_event_id"],
        "receipt_id": item["receipt_id"], "execution_id": item["execution_id"], "carrier_id": item["carrier_id"],
        "transition": item["transition"], "activity_kind": item["activity_kind"],
        "provider_registry": item["provider_registry"], "host_process": item["host_process"],
        "terminal_grace": item["terminal_grace"], "collector_health": item["collector_health"],
        "observed_at": item["observed_at"], "provenance": item["provenance"], "observation": item["observation"],
    }, "ExecutionRuntimeObservationReceipt")
    raw = validate_blob_ref(item["raw_artifact"])
    if raw["availability"] != "available" or raw["media_type"] != EXECUTION_RUNTIME_OBSERVATION_SOURCE_MEDIA_TYPE or raw["size_bytes"] > MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES:
        _fail("ExecutionRuntimeObservationReceipt requires an available raw artifact")
    receipt_sha256 = _sha256(item["receipt_sha256"], "ExecutionRuntimeObservationReceipt.receipt_sha256")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("ExecutionRuntimeObservationReceipt.receipt_sha256 differs")
    result.update({key: source[key] for key in (
        "receipt_id", "source_event_id", "execution_id", "carrier_id", "transition", "activity_kind",
        "provider_registry", "host_process", "terminal_grace", "collector_health", "observed_at", "provenance", "observation",
    )})
    result.update({"transaction_id": _id(item["transaction_id"], "ExecutionRuntimeObservationReceipt.transaction_id"), "command_id": _id(item["command_id"], "ExecutionRuntimeObservationReceipt.command_id"), "raw_artifact": raw, "receipt_sha256": receipt_sha256})
    return result


def _engineering_disposition_fields(
    item: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    from_status = _enum(
        item["from_status"],
        f"{label}.from_status",
        frozenset({"active", "waiting", "blocked", "unknown"}),
    )
    to_status = _enum(
        item["to_status"],
        f"{label}.to_status",
        frozenset({"idle"}),
    )
    reason_code = _enum(
        item["reason_code"],
        f"{label}.reason_code",
        frozenset({"handoff_ready", "idle_no_work"}),
    )
    provider = _id(item["provider"], f"{label}.provider")
    if provider == "unknown":
        _fail(f"{label} requires a known provider")
    provenance = _enum(
        item["provenance"],
        f"{label}.provenance",
        _PROVENANCE,
    )
    observation = _observation(
        item["observation"],
        f"{label}.observation",
    )
    if (
        provenance != "agent_reported"
        or observation != {"state": "known", "reason": "observed"}
    ):
        _fail(
            f"{label} requires an attributable agent-reported observation",
        )
    execution_id = _id(item["execution_id"], f"{label}.execution_id")
    reporter_execution_id = _id(
        item["reporter_execution_id"],
        f"{label}.reporter_execution_id",
    )
    if reporter_execution_id != execution_id:
        _fail(f"{label} alpha contract requires a self-report")
    return {
        "source_event_id": _id(
            item["source_event_id"],
            f"{label}.source_event_id",
        ),
        "receipt_id": _id(item["receipt_id"], f"{label}.receipt_id"),
        "execution_id": execution_id,
        "expected_execution_payload_sha256": _sha256(
            item["expected_execution_payload_sha256"],
            f"{label}.expected_execution_payload_sha256",
        ),
        "reporter_execution_id": reporter_execution_id,
        "reporter_carrier_id": _id(
            item["reporter_carrier_id"],
            f"{label}.reporter_carrier_id",
        ),
        "provider": provider,
        "session_id": _id(item["session_id"], f"{label}.session_id"),
        "thread_id": _id(item["thread_id"], f"{label}.thread_id"),
        "from_status": from_status,
        "to_status": to_status,
        "reason_code": reason_code,
        "result_packet_id": _id(
            item["result_packet_id"],
            f"{label}.result_packet_id",
        ),
        "observed_at": _timestamp(
            item["observed_at"],
            f"{label}.observed_at",
        ),
        "provenance": provenance,
        "observation": observation,
    }


def validate_engineering_disposition_source(
    value: Any,
) -> dict[str, Any]:
    fields = {
        "source_type", "schema_version", "company_id",
        "company_incarnation", "lock_domain_generation",
        "source_event_id", "receipt_id", "execution_id",
        "expected_execution_payload_sha256", "reporter_execution_id",
        "reporter_carrier_id", "provider", "session_id", "thread_id",
        "from_status", "to_status", "reason_code", "result_packet_id",
        "observed_at", "provenance", "observation",
    }
    item = _object(value, fields, "EngineeringDispositionSource")
    if item["source_type"] != ENGINEERING_DISPOSITION_SOURCE_V1:
        _fail("EngineeringDispositionSource.source_type is invalid")
    if _integer(
        item["schema_version"],
        "EngineeringDispositionSource.schema_version",
        minimum=1,
        maximum=1,
    ) != 1:
        _fail("EngineeringDispositionSource.schema_version is unsupported")
    return {
        "source_type": ENGINEERING_DISPOSITION_SOURCE_V1,
        "schema_version": 1,
        **_embedded_binding(item, "EngineeringDispositionSource"),
        **_engineering_disposition_fields(
            item,
            "EngineeringDispositionSource",
        ),
    }


def validate_engineering_disposition_receipt(
    value: Any,
) -> dict[str, Any]:
    fields = _common_fields({
        "source_event_id", "receipt_id", "transaction_id", "command_id",
        "execution_id", "expected_execution_payload_sha256",
        "reporter_execution_id", "reporter_carrier_id", "provider",
        "session_id", "thread_id", "from_status", "to_status",
        "reason_code", "result_packet_id", "observed_at", "provenance",
        "observation", "raw_artifact", "receipt_sha256",
    })
    item, result = _base(
        value,
        ENGINEERING_DISPOSITION_RECEIPT_V1,
        fields,
        "EngineeringDispositionReceipt",
    )
    shared = _engineering_disposition_fields(
        item,
        "EngineeringDispositionReceipt",
    )
    raw_artifact = validate_blob_ref(item["raw_artifact"])
    if (
        raw_artifact["availability"] != "available"
        or raw_artifact["media_type"]
        != ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE
        or raw_artifact["size_bytes"]
        > MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES
    ):
        _fail(
            "EngineeringDispositionReceipt requires an available raw artifact",
        )
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(
        item["receipt_sha256"],
        "EngineeringDispositionReceipt.receipt_sha256",
    )
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("EngineeringDispositionReceipt.receipt_sha256 differs")
    result.update({
        **shared,
        "transaction_id": _id(
            item["transaction_id"],
            "EngineeringDispositionReceipt.transaction_id",
        ),
        "command_id": _id(
            item["command_id"],
            "EngineeringDispositionReceipt.command_id",
        ),
        "raw_artifact": raw_artifact,
        "receipt_sha256": receipt_sha256,
    })
    return result


def _external_job_effect_fields(
    item: Mapping[str, Any], label: str,
) -> dict[str, Any]:
    """Validate fields shared by an external-job source and its receipt.

    This only validates one claimed, allowed transition.  The state
    owner/invariants must prove that its previous state is the actual current
    job state and that raw source bytes encode the repeated receipt fields.
    """
    binding = _embedded_binding(item, label)
    observed_job_state = _enum(
        item["observed_job_state"],
        f"{label}.observed_job_state",
        _EXTERNAL_JOB_EFFECT_STATES,
    )
    previous_job_state = _enum(
        item["previous_job_state"],
        f"{label}.previous_job_state",
        _EXTERNAL_JOB_EFFECT_PREVIOUS_STATES,
    )
    if observed_job_state not in _EXTERNAL_JOB_EFFECT_TRANSITIONS[previous_job_state]:
        _fail(f"{label} previous and observed job states do not form a lifecycle transition")
    external_handle_sha256 = _nullable_sha256(
        item["external_handle_sha256"],
        f"{label}.external_handle_sha256",
    )
    observation = _observation(item["observation"], f"{label}.observation")
    process_fingerprint_sha256 = _nullable_sha256(
        item["process_fingerprint_sha256"],
        f"{label}.process_fingerprint_sha256",
    )
    if observed_job_state == "aborted":
        if external_handle_sha256 is not None or process_fingerprint_sha256 is not None:
            _fail(f"{label} aborted observation cannot assert a process or handle")
    elif external_handle_sha256 is None:
        _fail(f"{label} only aborted observations may omit an external handle")
    elif (
        observed_job_state in {"running", "completed", "failed_known"}
        and process_fingerprint_sha256 is None
    ):
        _fail(
            f"{label} known process outcome requires a process fingerprint",
        )
    provenance = _enum(
        item["provenance"],
        f"{label}.provenance",
        _EXTERNAL_JOB_EFFECT_PROVENANCE,
    )
    reconciliation_id = _nullable_id(
        item["reconciliation_id"], f"{label}.reconciliation_id",
    )
    resolves_reconciliation_id = _nullable_id(
        item["resolves_reconciliation_id"],
        f"{label}.resolves_reconciliation_id",
    )
    if observed_job_state in _EXTERNAL_JOB_EFFECT_UNCERTAIN_STATES:
        if reconciliation_id is None or resolves_reconciliation_id is not None:
            _fail(f"{label} uncertain observation reconciliation fields differ")
        if observation["state"] == "known":
            _fail(f"{label} uncertain observation cannot be known")
    elif observed_job_state in {"completed", "failed_known"}:
        if reconciliation_id is not None:
            _fail(f"{label} known terminal observation cannot require reconciliation")
        if (
            resolves_reconciliation_id is not None
            and previous_job_state not in {"effect_unknown", "reconcile_required"}
        ):
            _fail(f"{label} resolution requires an uncertain previous job state")
        if observation["state"] != "known" or provenance == "unknown":
            _fail(f"{label} known terminal observation requires known provenance")
    else:
        if reconciliation_id is not None or resolves_reconciliation_id is not None:
            _fail(f"{label} running or aborted observation has reconciliation fields")
        if observation["state"] != "known" or provenance == "unknown":
            _fail(f"{label} known observation requires known provenance")
    return {
        **binding,
        "source_event_id": _id(item["source_event_id"], f"{label}.source_event_id"),
        "receipt_id": _id(item["receipt_id"], f"{label}.receipt_id"),
        "job_id": _id(item["job_id"], f"{label}.job_id"),
        "mutation_intent_id": _id(
            item["mutation_intent_id"], f"{label}.mutation_intent_id",
        ),
        "command_id": _id(item["command_id"], f"{label}.command_id"),
        "transaction_id": _id(
            item["transaction_id"], f"{label}.transaction_id",
        ),
        "transition_command_id": _id(
            item["transition_command_id"],
            f"{label}.transition_command_id",
        ),
        "previous_job_state": previous_job_state,
        "observed_job_state": observed_job_state,
        "external_handle_sha256": external_handle_sha256,
        "process_fingerprint_sha256": process_fingerprint_sha256,
        "reconciliation_id": reconciliation_id,
        "resolves_reconciliation_id": resolves_reconciliation_id,
        "observed_at": _timestamp(item["observed_at"], f"{label}.observed_at"),
        "provenance": provenance,
        "observation": observation,
    }


def validate_external_job_effect_source(value: Any) -> dict[str, Any]:
    """Validate canonical adapter source bytes for one external-job effect."""
    fields = {
        "source_type", "schema_version", "company_id", "company_incarnation",
        "lock_domain_generation", "source_event_id", "receipt_id", "job_id",
        "mutation_intent_id", "command_id", "transaction_id",
        "transition_command_id", "previous_job_state",
        "observed_job_state", "external_handle_sha256",
        "process_fingerprint_sha256", "reconciliation_id",
        "resolves_reconciliation_id", "observed_at", "provenance", "observation",
    }
    item = _object(value, fields, "ExternalJobEffectSource")
    if item["source_type"] != EXTERNAL_JOB_EFFECT_SOURCE_V1:
        _fail("ExternalJobEffectSource.source_type is invalid")
    if _integer(
        item["schema_version"], "ExternalJobEffectSource.schema_version",
        minimum=1, maximum=1,
    ) != 1:
        _fail("ExternalJobEffectSource.schema_version is unsupported")
    shared = _external_job_effect_fields(item, "ExternalJobEffectSource")
    return {
        "source_type": EXTERNAL_JOB_EFFECT_SOURCE_V1,
        "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION,
        **shared,
    }


def validate_external_job_effect_receipt(value: Any) -> dict[str, Any]:
    """Validate a receipt that references one canonical external-job source.

    The content-addressed raw artifact binds this receipt to source bytes.  Raw
    byte decoding and actual-predecessor validation remain state-owner/invariant
    responsibilities; a pure receipt validator has neither source bytes nor a
    lifecycle history to prove either fact.
    """
    fields = _common_fields({
        "receipt_id", "source_event_id", "job_id", "mutation_intent_id",
        "command_id", "transaction_id", "transition_command_id",
        "previous_job_state", "observed_job_state",
        "external_handle_sha256", "process_fingerprint_sha256",
        "reconciliation_id", "resolves_reconciliation_id", "observed_at",
        "provenance", "observation", "source_sha256", "raw_artifact",
        "receipt_sha256",
    })
    item, result = _base(
        value, EXTERNAL_JOB_EFFECT_RECEIPT_V1, fields,
        "ExternalJobEffectReceipt",
    )
    shared = _external_job_effect_fields(item, "ExternalJobEffectReceipt")
    raw_artifact = validate_blob_ref(item["raw_artifact"])
    source_sha256 = _sha256(
        item["source_sha256"], "ExternalJobEffectReceipt.source_sha256",
    )
    if (
        raw_artifact["availability"] != "available"
        or raw_artifact["media_type"] != EXTERNAL_JOB_EFFECT_SOURCE_MEDIA_TYPE
        or raw_artifact["sha256"] != source_sha256
    ):
        _fail("ExternalJobEffectReceipt raw artifact must bind the source bytes")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(
        item["receipt_sha256"], "ExternalJobEffectReceipt.receipt_sha256",
    )
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("ExternalJobEffectReceipt.receipt_sha256 differs")
    result.update({
        **shared,
        "source_sha256": source_sha256,
        "raw_artifact": raw_artifact,
        "receipt_sha256": receipt_sha256,
    })
    return result


def validate_evidence_record(value: Any) -> dict[str, Any]:
    fields = _common_fields({"evidence_id", "execution_id", "claim_id", "evidence_class", "status", "artifact", "command_sha256", "verification_sha256", "recorded_at", "provenance", "observation"})
    item, result = _base(value, EVIDENCE_RECORD_V1, fields, "EvidenceRecord")
    status = _enum(item["status"], "EvidenceRecord.status", frozenset({"pass", "fail", "blocked", "skipped", "observed", "unknown"}))
    artifact = validate_blob_ref(item["artifact"])
    verification = None if item["verification_sha256"] is None else _sha256(item["verification_sha256"], "EvidenceRecord.verification_sha256")
    provenance = _enum(item["provenance"], "EvidenceRecord.provenance", _PROVENANCE)
    observation = _observation(item["observation"], "EvidenceRecord.observation")
    if status in {"pass", "fail"} and (artifact["availability"] != "available" or verification is None):
        _fail("PASS/FAIL evidence requires an available artifact and verification")
    if status == "observed" and (
        artifact["availability"] != "available" or verification is None
    ):
        _fail("observed evidence requires an available artifact and verification")
    if status not in {"unknown", "observed"} and (
        provenance == "unknown" or observation["state"] != "known"
    ):
        _fail("known EvidenceRecord verdict requires known observation and non-unknown provenance")
    if status == "observed" and (
        provenance == "unknown" or observation["state"] == "unknown"
    ):
        _fail("observed EvidenceRecord requires attributable observation")
    if status == "unknown" and observation["state"] == "known":
        _fail("unknown EvidenceRecord cannot claim a known observation")
    result.update({"evidence_id": _id(item["evidence_id"], "EvidenceRecord.evidence_id"), "execution_id": _nullable_id(item["execution_id"], "EvidenceRecord.execution_id"), "claim_id": _nullable_id(item["claim_id"], "EvidenceRecord.claim_id"), "evidence_class": _enum(item["evidence_class"], "EvidenceRecord.evidence_class", frozenset({"compile_acceptance", "runtime", "local_synthesis_anchor", "proxy", "exploratory_physical", "engineering_inference", "unknown"})), "status": status, "artifact": artifact, "command_sha256": _nullable_id(item["command_sha256"], "EvidenceRecord.command_sha256") if item["command_sha256"] is None else _sha256(item["command_sha256"], "EvidenceRecord.command_sha256"), "verification_sha256": verification, "recorded_at": _timestamp(item["recorded_at"], "EvidenceRecord.recorded_at"), "provenance": provenance, "observation": observation})
    return result


def validate_artifact_edge(value: Any) -> dict[str, Any]:
    fields = _common_fields({"edge_id", "source_kind", "source_id", "target_kind", "target_id", "relation", "recorded_at", "observation"})
    item, result = _base(value, ARTIFACT_EDGE_V1, fields, "ArtifactEdge")
    source_kind = _enum(item["source_kind"], "ArtifactEdge.source_kind", frozenset({"blob", "evidence", "execution", "snapshot"}))
    source_id = _id(item["source_id"], "ArtifactEdge.source_id")
    target_kind = _enum(item["target_kind"], "ArtifactEdge.target_kind", frozenset({"blob", "evidence", "execution", "snapshot"}))
    target_id = _id(item["target_id"], "ArtifactEdge.target_id")
    if source_kind == target_kind and source_id == target_id:
        _fail("ArtifactEdge cannot link an artifact to itself")
    result.update({"edge_id": _id(item["edge_id"], "ArtifactEdge.edge_id"), "source_kind": source_kind, "source_id": source_id, "target_kind": target_kind, "target_id": target_id, "relation": _enum(item["relation"], "ArtifactEdge.relation", frozenset({"produces", "consumes", "derived_from", "verification", "promotion", "invalidation"})), "recorded_at": _timestamp(item["recorded_at"], "ArtifactEdge.recorded_at"), "observation": _observation(item["observation"], "ArtifactEdge.observation")})
    return result

def _token_value(value: Any, label: str) -> dict[str, Any]:
    item = _object(value, {"present", "tokens"}, label)
    if not isinstance(item["present"], bool):
        _fail(f"{label}.present is invalid")
    if item["present"]:
        return {"present": True, "tokens": _integer(item["tokens"], f"{label}.tokens")}
    if item["tokens"] is not None:
        _fail(f"{label}.tokens must be null when absent")
    return {"present": False, "tokens": None}


def _token_vector(value: Any, label: str) -> dict[str, dict[str, Any]]:
    item = _object(value, set(_TOKEN_DIMENSIONS), label)
    return {dimension: _token_value(item[dimension], f"{label}.{dimension}") for dimension in _TOKEN_DIMENSIONS}


def _token_vectors_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left[dimension] == right[dimension] for dimension in _TOKEN_DIMENSIONS)


def _usage_attribution(value: Any, label: str) -> dict[str, Any]:
    item = _object(value, {"execution_id", "department_id", "token_vector"}, label)
    execution_id = _nullable_id(item["execution_id"], f"{label}.execution_id")
    department_id = _nullable_id(item["department_id"], f"{label}.department_id")
    if execution_id is None and department_id is None:
        _fail(f"{label} requires execution or department attribution")
    return {"execution_id": execution_id, "department_id": department_id,
            "token_vector": _token_vector(item["token_vector"], f"{label}.token_vector")}


def _sum_token_vectors(vectors: Sequence[Mapping[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for dimension in _TOKEN_DIMENSIONS:
        values = [vector[dimension] for vector in vectors]
        if any(not member["present"] for member in values):
            _fail(f"{label}.{dimension} is missing")
        result[dimension] = {"present": True, "tokens": sum(member["tokens"] for member in values)}
    return result


def _usage_aggregation(value: Any, label: str, raw_tokens: Mapping[str, Any]) -> dict[str, Any]:
    item = _object(value, {"observed_total", "attributions", "unattributed"}, label)
    observed_total = _token_vector(item["observed_total"], f"{label}.observed_total")
    attributions = _bounded_list(item["attributions"], f"{label}.attributions", _usage_attribution, maximum=MAX_LIST_ITEMS)
    keys = [(entry["execution_id"], entry["department_id"]) for entry in attributions]
    if len(keys) != len(set(keys)):
        _fail(f"{label}.attributions contains duplicate execution/department assignments")
    unattributed = _token_vector(item["unattributed"], f"{label}.unattributed")
    if not _token_vectors_equal(observed_total, raw_tokens):
        _fail(f"{label}.observed_total differs from raw_token_vector")
    for dimension in _TOKEN_DIMENSIONS:
        observed = observed_total[dimension]
        unattributed_value = unattributed[dimension]
        if observed["present"]:
            if not unattributed_value["present"] or any(not entry["token_vector"][dimension]["present"] for entry in attributions):
                _fail(f"{label}.{dimension} allocation is incomplete")
            attributed_total = sum(entry["token_vector"][dimension]["tokens"] for entry in attributions)
            if attributed_total + unattributed_value["tokens"] != observed["tokens"]:
                _fail(f"{label}.{dimension} violates conservation")
        elif unattributed_value["present"] or any(entry["token_vector"][dimension]["present"] for entry in attributions):
            _fail(f"{label}.{dimension} allocates an absent observed total")
    return {"observed_total": observed_total, "attributions": attributions, "unattributed": unattributed}


def _usage_source(value: Any, label: str) -> dict[str, str]:
    item = _object(value, {"source_id", "source_sha256", "provenance"}, label)
    return {"source_id": _id(item["source_id"], f"{label}.source_id"),
            "source_sha256": _sha256(item["source_sha256"], f"{label}.source_sha256"),
            "provenance": _enum(item["provenance"], f"{label}.provenance", _PROVENANCE)}


def _rate_card_binding(value: Any, label: str) -> dict[str, Any]:
    item = _object(value, {"rate_card_id", "revision", "provider", "model", "effort", "formula_version", "weights_sha256"}, label)
    return {"rate_card_id": _id(item["rate_card_id"], f"{label}.rate_card_id"),
            "revision": _integer(item["revision"], f"{label}.revision", minimum=1, maximum=999_999_999_999),
            "provider": _id(item["provider"], f"{label}.provider"), "model": _id(item["model"], f"{label}.model"), "effort": _id(item["effort"], f"{label}.effort"),
            "formula_version": _id(item["formula_version"], f"{label}.formula_version"),
            "weights_sha256": _sha256(item["weights_sha256"], f"{label}.weights_sha256")}


def _dimension_weights(value: Any, label: str) -> dict[str, int]:
    item = _object(value, set(_TOKEN_DIMENSIONS), label)
    return {dimension: _integer(item[dimension], f"{label}.{dimension}", minimum=0, maximum=1_000_000_000_000) for dimension in _TOKEN_DIMENSIONS}


def validate_usage_event(value: Any) -> dict[str, Any]:
    fields = _common_fields({
        "usage_id", "aggregation_scope", "execution_id", "department_id",
        "provider", "model", "effort", "sample_kind", "recorded_at",
        "thread_id", "turn_id", "measurement_kind",
        "provider_counter_scope_id", "provider_update_id",
        "provider_sequence", "observation_started_at",
        "observation_ended_at", "previous_usage_sha256",
        "raw_token_vector", "source", "aggregation", "observation",
        "usage_sha256",
    })
    item = _header(value, USAGE_EVENT_V1, fields, "UsageEvent")
    recorded_at = _timestamp(item["recorded_at"], "UsageEvent.recorded_at")
    thread_id = _nullable_id(item["thread_id"], "UsageEvent.thread_id")
    turn_id = _nullable_id(item["turn_id"], "UsageEvent.turn_id")
    if turn_id is not None and thread_id is None:
        _fail("UsageEvent turn linkage requires a thread linkage")
    measurement_kind = _enum(
        item["measurement_kind"],
        "UsageEvent.measurement_kind",
        frozenset({"cumulative", "delta", "snapshot", "unknown"}),
    )
    counter_scope_id = _nullable_id(
        item["provider_counter_scope_id"],
        "UsageEvent.provider_counter_scope_id",
    )
    provider_update_id = _nullable_id(
        item["provider_update_id"], "UsageEvent.provider_update_id",
    )
    provider_sequence = (
        None
        if item["provider_sequence"] is None
        else _integer(
            item["provider_sequence"],
            "UsageEvent.provider_sequence",
            maximum=999_999_999_999,
        )
    )
    observation_started_at = (
        None
        if item["observation_started_at"] is None
        else _timestamp(
            item["observation_started_at"],
            "UsageEvent.observation_started_at",
        )
    )
    observation_ended_at = (
        None
        if item["observation_ended_at"] is None
        else _timestamp(
            item["observation_ended_at"],
            "UsageEvent.observation_ended_at",
        )
    )
    previous_usage_sha256 = _sha256(
        item["previous_usage_sha256"], "UsageEvent.previous_usage_sha256",
    )
    measurement_coordinates = (
        counter_scope_id,
        provider_update_id,
        provider_sequence,
        observation_started_at,
        observation_ended_at,
    )
    if measurement_kind == "unknown":
        if any(member is not None for member in measurement_coordinates):
            _fail("unknown UsageEvent measurement cannot assert update coordinates")
        if previous_usage_sha256 != ZERO_SHA256:
            _fail("unknown UsageEvent measurement cannot assert a predecessor")
    else:
        if any(member is None for member in measurement_coordinates):
            _fail("known UsageEvent measurement requires complete update coordinates")
        assert observation_started_at is not None
        assert observation_ended_at is not None
        if (
            _parsed_timestamp(observation_ended_at)
            < _parsed_timestamp(observation_started_at)
            or _parsed_timestamp(recorded_at)
            < _parsed_timestamp(observation_ended_at)
        ):
            _fail("UsageEvent observation window is inconsistent")
    if measurement_kind == "cumulative" and thread_id is None:
        _fail("cumulative UsageEvent requires thread-level linkage")
    raw_tokens = _token_vector(item["raw_token_vector"], "UsageEvent.raw_token_vector")
    sample_kind = _enum(item["sample_kind"], "UsageEvent.sample_kind", frozenset({"exact", "provider_estimate", "proxy", "unknown"}))
    source = _usage_source(item["source"], "UsageEvent.source")
    observation = _observation(item["observation"], "UsageEvent.observation")
    provider_source = {"provider_client_emitted", "adapter_receipt_persisted"}
    if sample_kind in {"exact", "provider_estimate"} and source["provenance"] not in provider_source:
        _fail("provider usage requires provider or adapter provenance")
    if sample_kind in {"exact", "provider_estimate", "proxy"} and observation["state"] != "known":
        _fail("known usage sample requires a known observation")
    if sample_kind == "unknown":
        if source["provenance"] != "unknown" or any(member["present"] for member in raw_tokens.values()):
            _fail("unknown usage cannot assert source provenance or raw tokens")
        if observation["state"] != "unknown":
            _fail("unknown usage requires an unknown observation")
    elif source["provenance"] == "unknown":
        _fail("known usage sample cannot use unknown provenance")
    elif not any(member["present"] for member in raw_tokens.values()):
        _fail("non-unknown usage cannot omit every raw token dimension")
    execution_id = _nullable_id(item["execution_id"], "UsageEvent.execution_id")
    department_id = _nullable_id(item["department_id"], "UsageEvent.department_id")
    scope = _enum(item["aggregation_scope"], "UsageEvent.aggregation_scope", frozenset({"execution", "department", "company"}))
    aggregation = _usage_aggregation(item["aggregation"], "UsageEvent.aggregation", raw_tokens)
    attributions = aggregation["attributions"]
    if scope == "execution":
        if execution_id is None or any(entry["execution_id"] != execution_id for entry in attributions):
            _fail("execution usage scope requires matching execution attributions")
        if department_id is not None and any(entry["department_id"] != department_id for entry in attributions):
            _fail("execution usage department differs from attribution")
    elif scope == "department":
        if execution_id is not None or department_id is None or any(entry["department_id"] != department_id for entry in attributions):
            _fail("department usage scope requires matching department attributions")
    elif execution_id is not None or department_id is not None:
        _fail("company usage scope cannot assert execution or department")
    unsigned = {key: item[key] for key in fields - {"usage_sha256"}}
    usage_sha256 = _sha256(item["usage_sha256"], "UsageEvent.usage_sha256")
    if usage_sha256 != company_contract_sha256(unsigned):
        _fail("UsageEvent.usage_sha256 differs")
    return {"contract_type": USAGE_EVENT_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **_embedded_binding(item, "UsageEvent"),
            "usage_id": _id(item["usage_id"], "UsageEvent.usage_id"), "provider": _id(item["provider"], "UsageEvent.provider"),
            "aggregation_scope": scope, "execution_id": execution_id, "department_id": department_id, "model": _id(item["model"], "UsageEvent.model"), "effort": _id(item["effort"], "UsageEvent.effort"), "sample_kind": sample_kind,
            "recorded_at": recorded_at, "thread_id": thread_id, "turn_id": turn_id,
            "measurement_kind": measurement_kind,
            "provider_counter_scope_id": counter_scope_id,
            "provider_update_id": provider_update_id,
            "provider_sequence": provider_sequence,
            "observation_started_at": observation_started_at,
            "observation_ended_at": observation_ended_at,
            "previous_usage_sha256": previous_usage_sha256,
            "raw_token_vector": raw_tokens,
            "source": source,
            "aggregation": aggregation, "observation": observation,
            "usage_sha256": usage_sha256}


def validate_usage_burn_revision(value: Any) -> dict[str, Any]:
    """Validate a derived burn revision without mutating its raw UsageEvent."""
    fields = _common_fields({"burn_id", "raw_usage_id", "raw_usage_sha256", "rate_card_id", "rate_card_revision", "rate_card_sha256", "provider", "model", "effort", "previous_burn_sha256", "effective_cursor", "formula_version", "burn_units", "burn_sha256", "observation"})
    item = _header(value, USAGE_BURN_REVISION_V1, fields, "UsageBurnRevision")
    cursor = _integer(item["effective_cursor"], "UsageBurnRevision.effective_cursor", maximum=999_999_999_999)
    previous = _sha256(item["previous_burn_sha256"], "UsageBurnRevision.previous_burn_sha256")
    unsigned = {key: item[key] for key in fields - {"burn_sha256"}}
    digest = _sha256(item["burn_sha256"], "UsageBurnRevision.burn_sha256")
    if digest != company_contract_sha256(unsigned):
        _fail("UsageBurnRevision.burn_sha256 differs")
    observation = _observation(item["observation"], "UsageBurnRevision.observation")
    if observation["state"] != "known":
        _fail("UsageBurnRevision concrete burn requires a known observation")
    return {"contract_type": USAGE_BURN_REVISION_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION,
            **_embedded_binding(item, "UsageBurnRevision"), "burn_id": _id(item["burn_id"], "UsageBurnRevision.burn_id"),
            "raw_usage_id": _id(item["raw_usage_id"], "UsageBurnRevision.raw_usage_id"),
            "raw_usage_sha256": _sha256(item["raw_usage_sha256"], "UsageBurnRevision.raw_usage_sha256"),
            "rate_card_id": _id(item["rate_card_id"], "UsageBurnRevision.rate_card_id"),
            "rate_card_revision": _integer(item["rate_card_revision"], "UsageBurnRevision.rate_card_revision", minimum=1, maximum=999_999_999_999),
            "rate_card_sha256": _sha256(item["rate_card_sha256"], "UsageBurnRevision.rate_card_sha256"),
            "provider": _id(item["provider"], "UsageBurnRevision.provider"),
            "model": _id(item["model"], "UsageBurnRevision.model"),
            "effort": _id(item["effort"], "UsageBurnRevision.effort"),
            "previous_burn_sha256": previous, "effective_cursor": cursor,
            "formula_version": _id(item["formula_version"], "UsageBurnRevision.formula_version"),
            "burn_units": _integer(item["burn_units"], "UsageBurnRevision.burn_units", maximum=2**63 - 1),
            "burn_sha256": digest, "observation": observation}


def validate_rate_card(value: Any) -> dict[str, Any]:
    fields = _common_fields({"rate_card_id", "revision", "provider", "model", "effort", "formula_version", "included_dimensions", "dimension_weights", "previous_rate_card_sha256", "weights_sha256", "rate_card_sha256", "observation"})
    item = _header(value, RATE_CARD_V1, fields, "RateCard")
    weights = _dimension_weights(item["dimension_weights"], "RateCard.dimension_weights")
    formula_version = _enum(item["formula_version"], "RateCard.formula_version", frozenset({"weighted-token-v1"}))
    included = _id_list(item["included_dimensions"], "RateCard.included_dimensions", maximum=len(_TOKEN_DIMENSIONS))
    if not included or not set(included) <= set(_TOKEN_DIMENSIONS):
        _fail("RateCard.included_dimensions is invalid")
    if "total" in included and any(dimension in included for dimension in ("input", "cache_read", "cache_creation", "output", "reasoning_output")):
        _fail("RateCard cannot double count total and component token dimensions")
    if any(weights[dimension] != 0 for dimension in _TOKEN_DIMENSIONS if dimension not in included):
        _fail("RateCard excluded dimensions require zero weight")
    if any(weights[dimension] <= 0 for dimension in included):
        _fail("RateCard included dimensions require positive weight")
    weights_unsigned = {"rate_card_id": item["rate_card_id"], "revision": item["revision"], "provider": item["provider"], "model": item["model"], "effort": item["effort"], "formula_version": item["formula_version"], "included_dimensions": item["included_dimensions"], "dimension_weights": item["dimension_weights"]}
    weights_sha256 = _sha256(item["weights_sha256"], "RateCard.weights_sha256")
    if weights_sha256 != company_contract_sha256(weights_unsigned):
        _fail("RateCard.weights_sha256 differs")
    revision = _integer(item["revision"], "RateCard.revision", minimum=1, maximum=999_999_999_999)
    previous_rate_card_sha256 = _sha256(item["previous_rate_card_sha256"], "RateCard.previous_rate_card_sha256")
    if (revision == 1) != (previous_rate_card_sha256 == ZERO_SHA256):
        _fail("RateCard history genesis differs")
    unsigned = {key: item[key] for key in fields - {"rate_card_sha256"}}
    rate_card_sha256 = _sha256(item["rate_card_sha256"], "RateCard.rate_card_sha256")
    if rate_card_sha256 != company_contract_sha256(unsigned):
        _fail("RateCard.rate_card_sha256 differs")
    observation = _observation(item["observation"], "RateCard.observation")
    if observation["state"] != "known":
        _fail("RateCard concrete weights require a known observation")
    return {"contract_type": RATE_CARD_V1, "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION, **_embedded_binding(item, "RateCard"),
            "rate_card_id": _id(item["rate_card_id"], "RateCard.rate_card_id"),
            "revision": revision,
            "provider": _id(item["provider"], "RateCard.provider"), "model": _id(item["model"], "RateCard.model"), "effort": _id(item["effort"], "RateCard.effort"), "formula_version": formula_version, "included_dimensions": included, "dimension_weights": weights,
            "previous_rate_card_sha256": previous_rate_card_sha256,
            "weights_sha256": weights_sha256, "rate_card_sha256": rate_card_sha256,
            "observation": observation}


def validate_alert(value: Any) -> dict[str, Any]:
    fields = _common_fields({"alert_id", "execution_id", "severity", "state", "category", "created_at", "resolved_at", "detail_sha256", "observation"})
    item, result = _base(value, ALERT_V1, fields, "Alert")
    created = _timestamp(item["created_at"], "Alert.created_at")
    resolved = None if item["resolved_at"] is None else _timestamp(item["resolved_at"], "Alert.resolved_at")
    if resolved is not None and _parsed_timestamp(resolved) < _parsed_timestamp(created):
        _fail("Alert.resolved_at precedes created_at")
    state = _enum(item["state"], "Alert.state", frozenset({"open", "resolved", "unknown"}))
    if state == "open" and resolved is not None:
        _fail("open Alert cannot have resolved_at")
    if state == "resolved" and resolved is None:
        _fail("resolved Alert requires resolved_at")
    if state == "unknown" and resolved is not None:
        _fail("unknown Alert cannot assert resolved_at")
    observation = _observation(item["observation"], "Alert.observation")
    if state == "resolved" and observation["state"] != "known":
        _fail("resolved Alert requires a known observation")
    result.update({"alert_id": _id(item["alert_id"], "Alert.alert_id"), "execution_id": _nullable_id(item["execution_id"], "Alert.execution_id"), "severity": _enum(item["severity"], "Alert.severity", frozenset({"info", "warning", "critical", "unknown"})), "state": state, "category": _id(item["category"], "Alert.category"), "created_at": created, "resolved_at": resolved, "detail_sha256": _sha256(item["detail_sha256"], "Alert.detail_sha256"), "observation": observation})
    return result


def validate_needs_user(value: Any) -> dict[str, Any]:
    fields = _common_fields({"item_id", "execution_id", "chief_term", "state", "question_sha256", "created_at", "answered_at", "observation"})
    item, result = _base(value, NEEDS_USER_V1, fields, "NeedsUser")
    created = _timestamp(item["created_at"], "NeedsUser.created_at")
    answered = None if item["answered_at"] is None else _timestamp(item["answered_at"], "NeedsUser.answered_at")
    if answered is not None and _parsed_timestamp(answered) < _parsed_timestamp(created):
        _fail("NeedsUser.answered_at precedes created_at")
    state = _enum(item["state"], "NeedsUser.state", frozenset({"pending", "answered", "expired", "unknown"}))
    if state in {"pending", "expired", "unknown"} and answered is not None:
        _fail("non-answered NeedsUser cannot have answered_at")
    if state == "answered" and answered is None:
        _fail("answered NeedsUser requires answered_at")
    observation = _observation(item["observation"], "NeedsUser.observation")
    if state in {"answered", "expired"} and observation["state"] != "known":
        _fail("terminal NeedsUser requires a known observation")
    result.update({"item_id": _id(item["item_id"], "NeedsUser.item_id"), "execution_id": _nullable_id(item["execution_id"], "NeedsUser.execution_id"), "chief_term": _integer(item["chief_term"], "NeedsUser.chief_term", minimum=1, maximum=999_999_999), "state": state, "question_sha256": _sha256(item["question_sha256"], "NeedsUser.question_sha256"), "created_at": created, "answered_at": answered, "observation": observation})
    return result


def validate_route_policy(value: Any) -> dict[str, Any]:
    fields = _common_fields({"policy_id", "revision", "policy_sha256", "allowed_providers", "allowed_models", "allowed_efforts", "created_at", "observation"})
    item, result = _base(value, ROUTE_POLICY_V1, fields, "RoutePolicy")
    unsigned = {**result,
                "policy_id": _id(item["policy_id"], "RoutePolicy.policy_id"),
                "revision": _integer(item["revision"], "RoutePolicy.revision", minimum=1, maximum=999_999_999_999),
                "allowed_providers": _id_list(item["allowed_providers"], "RoutePolicy.allowed_providers", maximum=64),
                "allowed_models": _id_list(item["allowed_models"], "RoutePolicy.allowed_models", maximum=128),
                "allowed_efforts": _id_list(item["allowed_efforts"], "RoutePolicy.allowed_efforts", maximum=32),
                "created_at": _timestamp(item["created_at"], "RoutePolicy.created_at"),
                "observation": _observation(item["observation"], "RoutePolicy.observation")}
    policy_sha256 = _sha256(item["policy_sha256"], "RoutePolicy.policy_sha256")
    if policy_sha256 != company_contract_sha256(unsigned):
        _fail("RoutePolicy.policy_sha256 differs")
    result.update({**unsigned, "policy_sha256": policy_sha256})
    return result


def validate_optimizer_proposal(value: Any) -> dict[str, Any]:
    fields = _common_fields({"proposal_id", "base_policy_sha256", "candidate_policy_sha256", "changed_dimension", "state", "created_at", "evidence_ids", "observation"})
    item, result = _base(value, OPTIMIZER_PROPOSAL_V1, fields, "OptimizerProposal")
    base_policy_sha256 = _sha256(item["base_policy_sha256"], "OptimizerProposal.base_policy_sha256")
    candidate_policy_sha256 = _sha256(item["candidate_policy_sha256"], "OptimizerProposal.candidate_policy_sha256")
    if base_policy_sha256 == candidate_policy_sha256:
        _fail("OptimizerProposal candidate policy must differ from base policy")
    state = _enum(item["state"], "OptimizerProposal.state", frozenset({"proposed", "accepted", "rejected", "inconclusive", "promoted", "rolled_back", "unknown"}))
    evidence_ids = _id_list(item["evidence_ids"], "OptimizerProposal.evidence_ids")
    if state in {"accepted", "promoted", "rolled_back"} and not evidence_ids:
        _fail("terminal OptimizerProposal requires evidence")
    observation = _observation(item["observation"], "OptimizerProposal.observation")
    if state in {"accepted", "rejected", "inconclusive", "promoted", "rolled_back"} and observation["state"] != "known":
        _fail("terminal OptimizerProposal requires a known observation")
    result.update({"proposal_id": _id(item["proposal_id"], "OptimizerProposal.proposal_id"), "base_policy_sha256": base_policy_sha256, "candidate_policy_sha256": candidate_policy_sha256, "changed_dimension": _enum(item["changed_dimension"], "OptimizerProposal.changed_dimension", frozenset({"provider", "model", "effort"})), "state": state, "created_at": _timestamp(item["created_at"], "OptimizerProposal.created_at"), "evidence_ids": evidence_ids, "observation": observation})
    return result


def validate_canary(value: Any) -> dict[str, Any]:
    fields = _common_fields({"canary_id", "proposal_id", "assignment_percent", "assignment_reference_sha256", "baseline_cohort_manifest_sha256", "canary_cohort_manifest_sha256", "control_cohort_manifest_sha256", "matching_manifest_sha256", "external_oracle_ref", "external_oracle_sha256", "window_started_at", "window_ended_at", "baseline_count", "canary_count", "control_count", "state", "started_at", "ended_at", "evidence_ids", "evidence_artifacts", "hard_gates", "observation"})
    item, result = _base(value, CANARY_V1, fields, "Canary")
    started = _timestamp(item["started_at"], "Canary.started_at")
    ended = None if item["ended_at"] is None else _timestamp(item["ended_at"], "Canary.ended_at")
    if ended is not None and _parsed_timestamp(ended) < _parsed_timestamp(started):
        _fail("Canary.ended_at precedes started_at")
    assignment = _integer(item["assignment_percent"], "Canary.assignment_percent", minimum=1, maximum=100)
    if assignment != 10:
        _fail("Canary v1 assignment_percent must be exactly 10")
    state = _enum(item["state"], "Canary.state", frozenset({"planned", "running", "passed", "failed", "inconclusive", "rolled_back", "unknown"}))
    terminal_state = state in {"passed", "failed", "inconclusive", "rolled_back"}
    if terminal_state:
        if ended is None:
            _fail("terminal Canary requires ended_at")
    elif ended is not None:
        _fail("nonterminal Canary cannot have ended_at")
    window_started = None if item["window_started_at"] is None else _timestamp(item["window_started_at"], "Canary.window_started_at")
    window_ended = None if item["window_ended_at"] is None else _timestamp(item["window_ended_at"], "Canary.window_ended_at")
    if window_started is not None and window_ended is not None:
        window_seconds = (_parsed_timestamp(window_ended) - _parsed_timestamp(window_started)).total_seconds()
        if not 0 <= window_seconds <= 90 * 24 * 60 * 60:
            _fail("Canary evidence window must be within 90 days")
    if terminal_state:
        if ended is None or window_started is None or window_ended is None:
            _fail("terminal Canary requires both evidence window endpoints")
        if not (_parsed_timestamp(started) <= _parsed_timestamp(window_started) <= _parsed_timestamp(window_ended) <= _parsed_timestamp(ended)):
            _fail("terminal Canary evidence window must be within its lifecycle")
    gates = _object(item["hard_gates"], {"correctness_noninferior", "completion_noninferior", "rework_noninferior", "burn_noninferior", "latency_noninferior", "dissent_preserved", "critical_regression_free", "fenced_mutation_escape_free", "unknown_mutation_free", "evidence_downgrade_free", "burn_improvement_percent", "latency_improvement_percent"}, "Canary.hard_gates")
    bool_gates = ("correctness_noninferior", "completion_noninferior", "rework_noninferior", "burn_noninferior", "latency_noninferior", "dissent_preserved", "critical_regression_free", "fenced_mutation_escape_free", "unknown_mutation_free", "evidence_downgrade_free")
    if any(gates[name] is not None and not isinstance(gates[name], bool) for name in bool_gates):
        _fail("Canary.hard_gates verdict fields are invalid")
    burn = None if gates["burn_improvement_percent"] is None else _integer(
        gates["burn_improvement_percent"], "Canary.hard_gates.burn_improvement_percent", maximum=100,
    )
    latency = None if gates["latency_improvement_percent"] is None else _integer(
        gates["latency_improvement_percent"], "Canary.hard_gates.latency_improvement_percent", maximum=100,
    )
    if burn is not None and gates["burn_noninferior"] is not True:
        _fail("Canary burn improvement requires a known noninferior burn gate")
    if latency is not None and gates["latency_noninferior"] is not True:
        _fail("Canary latency improvement requires a known noninferior latency gate")
    baseline_count = _integer(item["baseline_count"], "Canary.baseline_count", maximum=999_999_999)
    canary_count = _integer(item["canary_count"], "Canary.canary_count", maximum=999_999_999)
    control_count = _integer(item["control_count"], "Canary.control_count", maximum=999_999_999)
    assignment_reference = _nullable_sha256(item["assignment_reference_sha256"], "Canary.assignment_reference_sha256")
    baseline_manifest = _nullable_sha256(item["baseline_cohort_manifest_sha256"], "Canary.baseline_cohort_manifest_sha256")
    canary_manifest = _nullable_sha256(item["canary_cohort_manifest_sha256"], "Canary.canary_cohort_manifest_sha256")
    control_manifest = _nullable_sha256(item["control_cohort_manifest_sha256"], "Canary.control_cohort_manifest_sha256")
    matching_manifest = _nullable_sha256(item["matching_manifest_sha256"], "Canary.matching_manifest_sha256")
    oracle_ref = _nullable_id(item["external_oracle_ref"], "Canary.external_oracle_ref")
    oracle_sha256 = _nullable_sha256(item["external_oracle_sha256"], "Canary.external_oracle_sha256")
    evidence_ids = _id_list(item["evidence_ids"], "Canary.evidence_ids")
    evidence_artifacts = _blob_refs(item["evidence_artifacts"], "Canary.evidence_artifacts")
    observation = _observation(item["observation"], "Canary.observation")
    if state in {"passed", "failed", "inconclusive", "rolled_back"} and observation["state"] != "known":
        _fail("terminal Canary requires a known observation")
    if state == "unknown" and observation["state"] != "unknown":
        _fail("unknown Canary requires an unknown observation")
    if state in {"planned", "running", "unknown"} and (
        any(gates[name] is not None for name in bool_gates) or burn is not None or latency is not None
    ):
        _fail("nonterminal or unknown Canary cannot assert gate verdicts or improvements")
    evidence_available = bool(evidence_ids and evidence_artifacts) and all(
        artifact["availability"] == "available" for artifact in evidence_artifacts
    )
    evaluation_complete = (
        assignment_reference is not None
        and baseline_manifest is not None
        and canary_manifest is not None
        and control_manifest is not None
        and matching_manifest is not None
        and oracle_ref is not None
        and oracle_sha256 is not None
        and window_started is not None
        and window_ended is not None
        and baseline_count >= 20
        and canary_count >= 20
        and control_count >= 20
        and evidence_available
        and all(gates[name] is not None for name in bool_gates)
        and burn is not None
        and latency is not None
    )
    all_gates_true = all(gates[name] is True for name in bool_gates)
    any_gate_false = any(gates[name] is False for name in bool_gates)
    immediate_rollback_gates = (
        "critical_regression_free", "dissent_preserved",
        "fenced_mutation_escape_free", "unknown_mutation_free",
        "evidence_downgrade_free",
    )
    immediate_rollback = any(gates[name] is False for name in immediate_rollback_gates)
    meets_improvement = burn is not None and latency is not None and (burn >= 10 or latency >= 10)
    if state == "passed" and (
        not evaluation_complete or not all_gates_true or not meets_improvement
    ):
        _fail("passed Canary lacks required samples or hard gates")
    if state == "inconclusive" and (
        not evidence_available or any_gate_false or evaluation_complete
    ):
        _fail("inconclusive Canary must have available but incomplete non-regressing evidence")
    if state == "failed" and (
        not evidence_available
        or immediate_rollback
        or not (any_gate_false or (evaluation_complete and all_gates_true and not meets_improvement))
    ):
        _fail("failed Canary requires a non-immediate regression or complete no-benefit evaluation")
    if state == "rolled_back" and (not evidence_available or not immediate_rollback):
        _fail("rolled-back Canary requires available evidence and an immediate rollback trigger")
    result.update({"canary_id": _id(item["canary_id"], "Canary.canary_id"), "proposal_id": _id(item["proposal_id"], "Canary.proposal_id"), "assignment_percent": assignment, "assignment_reference_sha256": assignment_reference, "baseline_cohort_manifest_sha256": baseline_manifest, "canary_cohort_manifest_sha256": canary_manifest, "control_cohort_manifest_sha256": control_manifest, "matching_manifest_sha256": matching_manifest, "external_oracle_ref": oracle_ref, "external_oracle_sha256": oracle_sha256, "window_started_at": window_started, "window_ended_at": window_ended, "baseline_count": baseline_count, "canary_count": canary_count, "control_count": control_count, "state": state, "started_at": started, "ended_at": ended, "evidence_ids": evidence_ids, "evidence_artifacts": evidence_artifacts, "hard_gates": {**{name: gates[name] for name in bool_gates}, "burn_improvement_percent": burn, "latency_improvement_percent": latency}, "observation": observation})
    return result


_BACKUP_AAD_REQUIRED_FIELDS = frozenset({
    "aad_schema_version", "company_id", "company_incarnation", "lock_domain_generation",
    "backup_id", "ledger_cursor", "ledger_head_sha256", "manifest_sha256",
    "plaintext_sha256", "algorithm", "nonce_blob", "key_fingerprint", "created_at",
})


def _backup_aad_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("BackupEnvelope.aad is not a mapping")
    item = dict(value)
    if _BACKUP_AAD_REQUIRED_FIELDS - set(item):
        _fail("BackupEnvelope.aad is incomplete")
    return item


def backup_aad_fields(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the complete AES-GCM AAD payload before encryption begins."""
    item = _backup_aad_input(value)
    binding = _company_binding(item, "BackupEnvelope.aad")
    nonce = validate_blob_ref(item["nonce_blob"])
    if nonce["availability"] != "available" or nonce["size_bytes"] != 12:
        _fail("BackupEnvelope AES-GCM nonce must be an available 12-byte blob")
    ledger_cursor = _integer(item["ledger_cursor"], "BackupEnvelope.ledger_cursor", maximum=999_999_999_999)
    ledger_head = _sha256(item["ledger_head_sha256"], "BackupEnvelope.ledger_head_sha256")
    if (ledger_cursor == 0) != (ledger_head == ZERO_SHA256):
        _fail("BackupEnvelope ledger cursor and genesis head differ")
    return {"schema_version": _integer(item["aad_schema_version"], "BackupEnvelope.aad_schema_version", minimum=1, maximum=1), **binding,
            "backup_id": _id(item["backup_id"], "BackupEnvelope.backup_id"),
            "ledger_cursor": ledger_cursor,
            "ledger_head_sha256": ledger_head,
            "manifest_sha256": _sha256(item["manifest_sha256"], "BackupEnvelope.manifest_sha256"),
            "plaintext_sha256": _sha256(item["plaintext_sha256"], "BackupEnvelope.plaintext_sha256"),
            "algorithm": _enum(item["algorithm"], "BackupEnvelope.algorithm", frozenset({"AES-256-GCM"})),
            "nonce_sha256": nonce["sha256"],
            "key_fingerprint": _sha256(item["key_fingerprint"], "BackupEnvelope.key_fingerprint"),
            "created_at": _timestamp(item["created_at"], "BackupEnvelope.created_at")}


def backup_aad_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the sole canonical AES-GCM AAD encoding for a BackupEnvelope."""
    return canonical_company_json_bytes(backup_aad_fields(value))


def validate_crypto_verification_receipt(value: Any) -> dict[str, Any]:
    fields = _common_fields({"receipt_id", "backup_id", "aad_sha256", "ciphertext_sha256", "envelope_sha256", "nonce_sha256", "algorithm", "key_fingerprint", "verified_at", "verification_artifact", "receipt_sha256"})
    item, result = _base(value, CRYPTO_VERIFICATION_RECEIPT_V1, fields, "CryptoVerificationReceipt")
    artifact = validate_blob_ref(item["verification_artifact"])
    if artifact["availability"] != "available":
        _fail("CryptoVerificationReceipt requires an available verification artifact")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(item["receipt_sha256"], "CryptoVerificationReceipt.receipt_sha256")
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("CryptoVerificationReceipt.receipt_sha256 differs")
    result.update({"receipt_id": _id(item["receipt_id"], "CryptoVerificationReceipt.receipt_id"), "backup_id": _id(item["backup_id"], "CryptoVerificationReceipt.backup_id"), "aad_sha256": _sha256(item["aad_sha256"], "CryptoVerificationReceipt.aad_sha256"), "ciphertext_sha256": _sha256(item["ciphertext_sha256"], "CryptoVerificationReceipt.ciphertext_sha256"), "envelope_sha256": _sha256(item["envelope_sha256"], "CryptoVerificationReceipt.envelope_sha256"), "nonce_sha256": _sha256(item["nonce_sha256"], "CryptoVerificationReceipt.nonce_sha256"), "algorithm": _enum(item["algorithm"], "CryptoVerificationReceipt.algorithm", frozenset({"AES-256-GCM"})), "key_fingerprint": _sha256(item["key_fingerprint"], "CryptoVerificationReceipt.key_fingerprint"), "verified_at": _timestamp(item["verified_at"], "CryptoVerificationReceipt.verified_at"), "verification_artifact": artifact, "receipt_sha256": receipt_sha256})
    return result


def validate_backup_envelope(value: Any) -> dict[str, Any]:
    fields = _common_fields({"backup_id", "ledger_cursor", "ledger_head_sha256", "manifest_sha256", "plaintext_sha256", "ciphertext_sha256", "nonce_blob", "aad_schema_version", "aad_sha256", "envelope_blob", "algorithm", "key_fingerprint", "state", "created_at", "verified_at", "failure_artifact", "crypto_verification_receipt", "crypto_verification_receipt_sha256", "observation"})
    item, result = _base(value, BACKUP_ENVELOPE_V1, fields, "BackupEnvelope")
    created = _timestamp(item["created_at"], "BackupEnvelope.created_at")
    verified = None if item["verified_at"] is None else _timestamp(item["verified_at"], "BackupEnvelope.verified_at")
    if verified is not None and _parsed_timestamp(verified) < _parsed_timestamp(created):
        _fail("BackupEnvelope.verified_at precedes created_at")
    nonce = validate_blob_ref(item["nonce_blob"])
    envelope = validate_blob_ref(item["envelope_blob"])
    if nonce["availability"] != "available" or nonce["size_bytes"] != 12:
        _fail("BackupEnvelope AES-GCM nonce must be an available 12-byte blob")
    ciphertext = _sha256(item["ciphertext_sha256"], "BackupEnvelope.ciphertext_sha256")
    if envelope["availability"] != "available" or envelope["sha256"] != ciphertext:
        _fail("BackupEnvelope envelope blob must bind ciphertext")
    if envelope["size_bytes"] < 16:
        _fail("BackupEnvelope AES-GCM envelope must include its 16-byte tag")
    aad_fields = backup_aad_fields(item)
    ledger_cursor = aad_fields["ledger_cursor"]
    ledger_head = aad_fields["ledger_head_sha256"]
    aad_schema_version = aad_fields["schema_version"]
    expected_aad_sha256 = hashlib.sha256(backup_aad_bytes(item)).hexdigest()
    aad_sha256 = _sha256(item["aad_sha256"], "BackupEnvelope.aad_sha256")
    if aad_sha256 != expected_aad_sha256:
        _fail("BackupEnvelope deterministic AAD digest differs")
    state = _enum(item["state"], "BackupEnvelope.state", frozenset({"verified", "unverified", "failed", "unknown"}))
    if state == "verified" and verified is None:
        _fail("verified BackupEnvelope requires verified_at")
    if state != "verified" and verified is not None:
        _fail("non-verified BackupEnvelope cannot assert verified_at")
    observation = _observation(item["observation"], "BackupEnvelope.observation")
    if state in {"verified", "failed"} and observation["state"] != "known":
        _fail("verified or failed BackupEnvelope requires a known observation")
    if state == "unknown" and observation["state"] != "unknown":
        _fail("unknown BackupEnvelope requires an unknown observation")
    failure_artifact = None if item["failure_artifact"] is None else validate_blob_ref(item["failure_artifact"])
    if state == "failed" and (failure_artifact is None or failure_artifact["availability"] != "available"):
        _fail("failed BackupEnvelope requires an available failure artifact")
    if state != "failed" and failure_artifact is not None:
        _fail("non-failed BackupEnvelope cannot assert a failure artifact")
    verification = None if item["crypto_verification_receipt_sha256"] is None else _sha256(item["crypto_verification_receipt_sha256"], "BackupEnvelope.crypto_verification_receipt_sha256")
    receipt = None if item["crypto_verification_receipt"] is None else validate_crypto_verification_receipt(item["crypto_verification_receipt"])
    if receipt is not None and (_company_binding(receipt, "BackupEnvelope.crypto_verification_receipt") != _embedded_binding(item, "BackupEnvelope") or receipt["backup_id"] != item["backup_id"] or receipt["aad_sha256"] != aad_sha256 or receipt["ciphertext_sha256"] != ciphertext or receipt["envelope_sha256"] != envelope["sha256"] or receipt["nonce_sha256"] != nonce["sha256"] or receipt["algorithm"] != item["algorithm"] or receipt["key_fingerprint"] != item["key_fingerprint"] or receipt["verified_at"] != verified):
        _fail("BackupEnvelope crypto verification receipt binding differs")
    if state == "verified" and (verification is None or receipt is None or verification != receipt["receipt_sha256"]):
        _fail("verified BackupEnvelope requires a crypto verification receipt")
    if state != "verified" and (verification is not None or receipt is not None):
        _fail("unverified BackupEnvelope cannot assert a crypto verification receipt")
    result.update({"backup_id": _id(item["backup_id"], "BackupEnvelope.backup_id"), "ledger_cursor": ledger_cursor, "ledger_head_sha256": ledger_head, "manifest_sha256": _sha256(item["manifest_sha256"], "BackupEnvelope.manifest_sha256"), "plaintext_sha256": _sha256(item["plaintext_sha256"], "BackupEnvelope.plaintext_sha256"), "ciphertext_sha256": ciphertext, "nonce_blob": nonce, "aad_schema_version": aad_schema_version, "aad_sha256": aad_sha256, "envelope_blob": envelope, "algorithm": _enum(item["algorithm"], "BackupEnvelope.algorithm", frozenset({"AES-256-GCM"})), "key_fingerprint": _sha256(item["key_fingerprint"], "BackupEnvelope.key_fingerprint"), "state": state, "created_at": created, "verified_at": verified, "failure_artifact": failure_artifact, "crypto_verification_receipt": receipt, "crypto_verification_receipt_sha256": verification, "observation": observation})
    return result


_TELEMETRY_FACT_KEYS = frozenset({
    "actual_provider", "actual_model", "actual_effort", "actual_role", "routing",
    "session_id", "thread_id", "turn_id", "agent_id", "parent_thread_id",
    "event_time", "engineering_completion",
})
_USAGE_PROVENANCE_FACT_KEYS = frozenset({
    "actual_provider", "actual_model", "actual_effort", "actual_role", "routing",
})
_FACT_SOURCES = frozenset({
    "provider_payload", "adapter_route", "aoi_registry", "collector", "none",
})
_FACT_QUALITIES = frozenset({"observed", "missing", "unavailable", "ambiguous"})


def _nullable_short_text(value: Any, label: str) -> str | None:
    return (
        None
        if value is None
        else _text(value, label, maximum=MAX_SHORT_TEXT_BYTES)
    )


def _telemetry_routing(value: Any, label: str) -> dict[str, Any]:
    fields = {
        "kind", "requested_model", "requested_effort", "tool", "status",
        "from_model", "to_model",
    }
    item = _object(value, fields, label)
    kind = _enum(
        item["kind"],
        f"{label}.kind",
        frozenset({"collab_request", "model_reroute"}),
    )
    result = {
        "kind": kind,
        "requested_model": _nullable_short_text(
            item["requested_model"],
            f"{label}.requested_model",
        ),
        "requested_effort": _nullable_short_text(
            item["requested_effort"],
            f"{label}.requested_effort",
        ),
        "tool": _nullable_short_text(item["tool"], f"{label}.tool"),
        "status": _nullable_short_text(
            item["status"],
            f"{label}.status",
        ),
        "from_model": _nullable_short_text(
            item["from_model"],
            f"{label}.from_model",
        ),
        "to_model": _nullable_short_text(
            item["to_model"],
            f"{label}.to_model",
        ),
    }
    if kind == "collab_request":
        if (
            result["tool"] is None
            or result["status"] is None
            or result["from_model"] is not None
            or result["to_model"] is not None
        ):
            _fail(f"{label} collaboration routing matrix is invalid")
    elif (
        result["from_model"] is None
        or result["to_model"] is None
        or any(
            result[key] is not None
            for key in (
                "requested_model",
                "requested_effort",
                "tool",
                "status",
            )
        )
    ):
        _fail(f"{label} model reroute matrix is invalid")
    return result


def _telemetry_fact_value(value: Any, label: str, fact_name: str) -> Any:
    if fact_name == "event_time":
        return _integer(
            value,
            f"{label}.value",
            minimum=-(2**63),
            maximum=2**63 - 1,
        )
    if fact_name == "routing":
        return _telemetry_routing(value, f"{label}.value")
    return _text(value, f"{label}.value", maximum=MAX_SHORT_TEXT_BYTES)


def _telemetry_fact(
    value: Any,
    label: str,
    *,
    fact_name: str,
) -> dict[str, Any]:
    item = _object(value, {"value", "source", "quality", "reason"}, label)
    actual = (
        None
        if item["value"] is None
        else _telemetry_fact_value(item["value"], label, fact_name)
    )
    source = _enum(item["source"], f"{label}.source", _FACT_SOURCES)
    quality = _enum(item["quality"], f"{label}.quality", _FACT_QUALITIES)
    reason = _text(item["reason"], f"{label}.reason", maximum=MAX_SHORT_TEXT_BYTES)
    if quality == "observed":
        if actual is None or source == "none":
            _fail(f"{label} observed value is invalid")
    elif actual is not None or reason == "observed":
        _fail(f"{label} non-observed value is invalid")
    return {"value": actual, "source": source, "quality": quality, "reason": reason}


def _telemetry_facts(value: Any, label: str, keys: frozenset[str]) -> dict[str, dict[str, Any]]:
    item = _object(value, set(keys), label)
    return {
        key: _telemetry_fact(
            item[key],
            f"{label}.{key}",
            fact_name=key,
        )
        for key in sorted(keys)
    }


def _integer_fact(value: Any, label: str) -> dict[str, Any]:
    item = _object(value, {"value", "source", "quality", "reason"}, label)
    actual = None if item["value"] is None else _integer(
        item["value"], f"{label}.value", maximum=999_999_999_999,
    )
    source = _enum(item["source"], f"{label}.source", _FACT_SOURCES)
    quality = _enum(item["quality"], f"{label}.quality", _FACT_QUALITIES)
    reason = _text(item["reason"], f"{label}.reason", maximum=MAX_SHORT_TEXT_BYTES)
    if quality == "observed":
        if actual is None or source == "none" or reason != "observed":
            _fail(f"{label} observed value is invalid")
    elif actual is not None or reason == "observed":
        _fail(f"{label} non-observed value is invalid")
    return {"value": actual, "source": source, "quality": quality, "reason": reason}


def _telemetry_raw_blob(value: Any, label: str, *, maximum: int) -> dict[str, Any]:
    blob = validate_blob_ref(value)
    if (
        blob["availability"] != "available"
        or blob["media_type"] != PROVIDER_TELEMETRY_RAW_MEDIA_TYPE
        or blob["size_bytes"] is None
        or blob["size_bytes"] > maximum
    ):
        _fail(f"{label} requires bounded available provider telemetry bytes")
    return blob


def _dispatch_join(value: Any, label: str) -> dict[str, Any]:
    fields = {
        "state", "binding_kind", "registry_cursor", "dispatch_request_id",
        "dispatch_revision_id", "registration_id", "execution_id", "carrier_id",
        "candidate_count", "candidates_sha256", "reason",
    }
    item = _object(value, fields, label)
    state = _enum(item["state"], f"{label}.state", frozenset({"exact", "none", "ambiguous"}))
    binding_kind = _enum(
        item["binding_kind"], f"{label}.binding_kind",
        frozenset({"dispatch", "registration", "carrier", "none"}),
    )
    dispatch_request_id = _nullable_id(item["dispatch_request_id"], f"{label}.dispatch_request_id")
    dispatch_revision_id = _nullable_id(item["dispatch_revision_id"], f"{label}.dispatch_revision_id")
    registration_id = _nullable_id(item["registration_id"], f"{label}.registration_id")
    execution_id = _nullable_id(item["execution_id"], f"{label}.execution_id")
    carrier_id = _nullable_id(item["carrier_id"], f"{label}.carrier_id")
    candidate_count = _integer(item["candidate_count"], f"{label}.candidate_count", maximum=MAX_LIST_ITEMS)
    candidates_sha256 = _sha256(item["candidates_sha256"], f"{label}.candidates_sha256")
    reason = _text(item["reason"], f"{label}.reason", maximum=MAX_SHORT_TEXT_BYTES)
    if state == "exact":
        if candidate_count != 1 or execution_id is None or carrier_id is None or candidates_sha256 == ZERO_SHA256:
            _fail(f"{label} exact candidate binding is invalid")
        if binding_kind == "dispatch":
            if dispatch_request_id is None or dispatch_revision_id is None or registration_id is not None:
                _fail(f"{label} dispatch binding is invalid")
        elif binding_kind == "registration":
            if registration_id is None or dispatch_request_id is not None or dispatch_revision_id is not None:
                _fail(f"{label} registration binding is invalid")
        elif binding_kind == "carrier":
            if any(member is not None for member in (dispatch_request_id, dispatch_revision_id, registration_id)):
                _fail(f"{label} carrier binding is invalid")
        else:
            _fail(f"{label} exact binding requires a binding kind")
    elif state == "none":
        if (
            binding_kind != "none" or candidate_count != 0 or candidates_sha256 != ZERO_SHA256
            or any(member is not None for member in (
                dispatch_request_id, dispatch_revision_id, registration_id, execution_id, carrier_id,
            ))
        ):
            _fail(f"{label} none binding is invalid")
    elif (
        binding_kind != "none" or candidate_count < 2 or candidates_sha256 == ZERO_SHA256
        or any(member is not None for member in (
            dispatch_request_id, dispatch_revision_id, registration_id, execution_id, carrier_id,
        ))
    ):
        _fail(f"{label} ambiguous binding is invalid")
    return {
        "state": state, "binding_kind": binding_kind,
        "registry_cursor": _integer(item["registry_cursor"], f"{label}.registry_cursor", maximum=999_999_999_999),
        "dispatch_request_id": dispatch_request_id, "dispatch_revision_id": dispatch_revision_id,
        "registration_id": registration_id, "execution_id": execution_id, "carrier_id": carrier_id,
        "candidate_count": candidate_count, "candidates_sha256": candidates_sha256, "reason": reason,
    }


def _provider_native_relation(value: Any, label: str) -> dict[str, Any]:
    fields = {
        "kind", "sender_thread_id", "receiver_thread_ids",
        "child_thread_id", "agent_path", "activity_kind", "native_depth",
        "reason",
    }
    item = _object(value, fields, label)
    kind = _enum(
        item["kind"],
        f"{label}.kind",
        frozenset({
            "none",
            "thread_spawn",
            "collab_request",
            "subagent_activity",
        }),
    )
    sender = _nullable_short_text(
        item["sender_thread_id"],
        f"{label}.sender_thread_id",
    )
    receivers = _bounded_list(
        item["receiver_thread_ids"],
        f"{label}.receiver_thread_ids",
        lambda member, member_label: _text(
            member,
            member_label,
            maximum=MAX_SHORT_TEXT_BYTES,
        ),
        maximum=64,
    )
    if len(receivers) != len(set(receivers)):
        _fail(f"{label}.receiver_thread_ids contain duplicates")
    if receivers != sorted(receivers):
        _fail(f"{label}.receiver_thread_ids require canonical sorting")
    child = _nullable_short_text(
        item["child_thread_id"],
        f"{label}.child_thread_id",
    )
    agent_path = _nullable_short_text(item["agent_path"], f"{label}.agent_path")
    activity = _nullable_id(item["activity_kind"], f"{label}.activity_kind")
    depth = (
        None
        if item["native_depth"] is None
        else _integer(
            item["native_depth"],
            f"{label}.native_depth",
            maximum=MAX_EXECUTION_DEPTH,
        )
    )
    reason = _text(item["reason"], f"{label}.reason", maximum=MAX_SHORT_TEXT_BYTES)
    if kind == "none":
        if (
            sender is not None
            or receivers
            or child is not None
            or agent_path is not None
            or activity is not None
            or depth is not None
            or reason == "observed"
        ):
            _fail(f"{label} absent provider relation is invalid")
    elif kind == "thread_spawn":
        if (
            sender is None
            or child is None
            or receivers != [child]
            or activity is not None
        ):
            _fail(f"{label} native thread-spawn relation is invalid")
    elif kind == "collab_request":
        if (
            sender is None
            or not receivers
            or child is not None
            or agent_path is not None
            or activity is not None
            or depth is not None
        ):
            _fail(f"{label} native collaboration relation is invalid")
    elif (
        sender is None
        or child is None
        or receivers != [child]
        or agent_path is None
        or activity is None
        or depth is not None
    ):
        _fail(f"{label} native subagent activity relation is invalid")
    return {
        "kind": kind,
        "sender_thread_id": sender,
        "receiver_thread_ids": receivers,
        "child_thread_id": child,
        "agent_path": agent_path,
        "activity_kind": activity,
        "native_depth": depth,
        "reason": reason,
    }


_CODEX_NORMALIZED_KINDS = frozenset({
    "thread_started",
    "thread_waiting_on_user_input",
    "thread_status_changed",
    "turn_started_runtime_observed",
    "turn_completed_runtime_observed",
    "item_started_runtime_observed",
    "item_completed_runtime_observed",
    "model_rerouted_runtime_observed",
    "thread_token_usage_updated",
})
_CLAUDE_HOOK_NORMALIZED_KINDS = frozenset({
    "subagent_start_runtime_observed",
    "stop_runtime_observed",
})


def _provider_telemetry_matrix(
    *,
    provider: str,
    source_class: str,
    parser_id: str,
    parser_version: str,
    outcome: str,
    normalized_kind: str,
    facts: Mapping[str, Mapping[str, Any]],
    relation: Mapping[str, Any],
    provenance: str,
) -> None:
    if parser_version != "v1" or provenance != "adapter_receipt_persisted":
        _fail("ProviderTelemetryReceipt parser or provenance matrix is invalid")
    if provider == "codex":
        if source_class != "codex_app_server" or parser_id != "codex_adapter":
            _fail("ProviderTelemetryReceipt Codex source matrix is invalid")
        allowed = _CODEX_NORMALIZED_KINDS
    elif provider == "claude":
        if (
            source_class not in {"claude_hook", "otel"}
            or parser_id != "claude_adapter"
        ):
            _fail("ProviderTelemetryReceipt Claude source matrix is invalid")
        allowed = (
            _CLAUDE_HOOK_NORMALIZED_KINDS
            if source_class == "claude_hook"
            else frozenset()
        )
    else:
        _fail("ProviderTelemetryReceipt provider is invalid")
    if outcome == "normalized":
        if normalized_kind not in allowed:
            _fail("ProviderTelemetryReceipt normalized kind is invalid")
    elif any(fact["quality"] == "observed" for fact in facts.values()):
        _fail("ProviderTelemetryReceipt unparsed payload cannot assert facts")
    engineering = facts["engineering_completion"]
    if (
        engineering["quality"] != "unavailable"
        or engineering["value"] is not None
        or engineering["source"] != "none"
    ):
        _fail(
            "ProviderTelemetryReceipt runtime telemetry cannot assert "
            "engineering completion",
        )
    required_observed: dict[str, tuple[str, ...]] = {
        "thread_started": (
            "actual_provider", "session_id", "thread_id", "event_time",
        ),
        "thread_waiting_on_user_input": ("thread_id",),
        "thread_status_changed": ("thread_id",),
        "turn_started_runtime_observed": ("thread_id", "turn_id"),
        "turn_completed_runtime_observed": ("thread_id", "turn_id"),
        "item_started_runtime_observed": (
            "thread_id", "turn_id", "event_time",
        ),
        "item_completed_runtime_observed": (
            "thread_id", "turn_id", "event_time",
        ),
        "model_rerouted_runtime_observed": (
            "thread_id", "turn_id", "actual_model", "routing",
        ),
        "thread_token_usage_updated": ("thread_id", "turn_id"),
    }
    for key in required_observed.get(normalized_kind, ()):
        if facts[key]["quality"] != "observed":
            _fail(
                "ProviderTelemetryReceipt required provider fact is absent",
            )
    relation_kind = str(relation["kind"])
    if outcome != "normalized" and relation_kind != "none":
        _fail("ProviderTelemetryReceipt unparsed payload cannot assert a relation")
    if provider == "claude" and relation_kind != "none":
        _fail("ProviderTelemetryReceipt Claude relation matrix is invalid")
    if relation_kind in {"thread_spawn", "collab_request", "subagent_activity"}:
        if provider != "codex":
            _fail("ProviderTelemetryReceipt native relation provider differs")


def validate_provider_telemetry_receipt(value: Any) -> dict[str, Any]:
    """Validate one immutable adapter intake receipt; it never infers parentage."""
    fields = _common_fields({
        "transaction_id", "command_id", "receipt_id", "adapter_instance_id", "adapter_event_id", "intake_sequence", "provider",
        "source_class", "parser_id", "parser_version", "parse_outcome", "normalized_kind",
        "facts", "provider_native_relation", "dispatch_join", "received_at",
        "raw_artifact", "provenance", "observation",
        "receipt_sha256",
    })
    item, result = _base(value, PROVIDER_TELEMETRY_RECEIPT_V1, fields, "ProviderTelemetryReceipt")
    outcome = _enum(item["parse_outcome"], "ProviderTelemetryReceipt.parse_outcome", frozenset({"normalized", "unsupported_valid", "malformed"}))
    normalized_kind = _id(item["normalized_kind"], "ProviderTelemetryReceipt.normalized_kind")
    if (outcome == "normalized" and normalized_kind in {"unsupported", "malformed"}) or (
        outcome == "unsupported_valid" and normalized_kind != "unsupported"
    ) or (outcome == "malformed" and normalized_kind != "malformed"):
        _fail("ProviderTelemetryReceipt parse outcome and normalized kind differ")
    facts = _telemetry_facts(item["facts"], "ProviderTelemetryReceipt.facts", _TELEMETRY_FACT_KEYS)
    relation = _provider_native_relation(
        item["provider_native_relation"],
        "ProviderTelemetryReceipt.provider_native_relation",
    )
    observation = _observation(item["observation"], "ProviderTelemetryReceipt.observation")
    if observation != {"state": "known", "reason": "observed"}:
        _fail("ProviderTelemetryReceipt intake must be a known observation")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(item["receipt_sha256"], "ProviderTelemetryReceipt.receipt_sha256")
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("ProviderTelemetryReceipt.receipt_sha256 differs")
    provider = _enum(
        item["provider"],
        "ProviderTelemetryReceipt.provider",
        frozenset({"codex", "claude"}),
    )
    source_class = _enum(
        item["source_class"],
        "ProviderTelemetryReceipt.source_class",
        frozenset({"codex_app_server", "claude_hook", "otel"}),
    )
    parser_id = _enum(
        item["parser_id"],
        "ProviderTelemetryReceipt.parser_id",
        frozenset({"codex_adapter", "claude_adapter"}),
    )
    parser_version = _enum(
        item["parser_version"],
        "ProviderTelemetryReceipt.parser_version",
        frozenset({"v1"}),
    )
    provenance = _enum(
        item["provenance"],
        "ProviderTelemetryReceipt.provenance",
        _PROVIDER_RECEIPT_PROVENANCE,
    )
    _provider_telemetry_matrix(
        provider=provider,
        source_class=source_class,
        parser_id=parser_id,
        parser_version=parser_version,
        outcome=outcome,
        normalized_kind=normalized_kind,
        facts=facts,
        relation=relation,
        provenance=provenance,
    )
    result.update({
        "transaction_id": _id(item["transaction_id"], "ProviderTelemetryReceipt.transaction_id"),
        "command_id": _id(item["command_id"], "ProviderTelemetryReceipt.command_id"),
        "receipt_id": _id(item["receipt_id"], "ProviderTelemetryReceipt.receipt_id"),
        "adapter_instance_id": _id(item["adapter_instance_id"], "ProviderTelemetryReceipt.adapter_instance_id"),
        "adapter_event_id": _id(item["adapter_event_id"], "ProviderTelemetryReceipt.adapter_event_id"),
        "intake_sequence": _integer(item["intake_sequence"], "ProviderTelemetryReceipt.intake_sequence", minimum=1, maximum=999_999_999_999),
        "provider": provider, "source_class": source_class,
        "parser_id": parser_id, "parser_version": parser_version,
        "parse_outcome": outcome, "normalized_kind": normalized_kind,
        "facts": facts, "provider_native_relation": relation,
        "dispatch_join": _dispatch_join(item["dispatch_join"], "ProviderTelemetryReceipt.dispatch_join"),
        "received_at": _timestamp(item["received_at"], "ProviderTelemetryReceipt.received_at"),
        "raw_artifact": _telemetry_raw_blob(item["raw_artifact"], "ProviderTelemetryReceipt.raw_artifact", maximum=MAX_PROVIDER_TELEMETRY_RAW_BYTES),
        "provenance": provenance,
        "observation": observation, "receipt_sha256": receipt_sha256,
    })
    return result


def validate_provider_coverage_revision(value: Any) -> dict[str, Any]:
    """Validate one coverage assessment; revision adjacency is Supervisor-owned."""
    fields = _common_fields({
        "coverage_scope_id", "coverage_surface", "revision_id", "revision", "previous_revision_sha256", "provider",
        "adapter_instance_id", "source_class", "declared_event_kinds", "state", "reason",
        "assessment_source", "last_receipt_id", "last_received_at", "gap_started_at",
        "dropped_event_count", "assessed_at", "observation", "coverage_sha256",
    })
    item, result = _base(value, PROVIDER_COVERAGE_REVISION_V1, fields, "ProviderCoverageRevision")
    revision = _integer(item["revision"], "ProviderCoverageRevision.revision", minimum=1, maximum=999_999_999_999)
    previous = _sha256(item["previous_revision_sha256"], "ProviderCoverageRevision.previous_revision_sha256")
    if (revision == 1) != (previous == ZERO_SHA256):
        _fail("ProviderCoverageRevision genesis predecessor differs")
    event_kinds = _id_list(item["declared_event_kinds"], "ProviderCoverageRevision.declared_event_kinds", maximum=64)
    if not event_kinds or event_kinds != sorted(event_kinds):
        _fail("ProviderCoverageRevision declared event kinds require sorted uniqueness")
    state = _enum(item["state"], "ProviderCoverageRevision.state", frozenset({"observed", "degraded", "unavailable", "unknown"}))
    reason = _text(item["reason"], "ProviderCoverageRevision.reason", maximum=MAX_SHORT_TEXT_BYTES)
    last_receipt_id = _nullable_id(item["last_receipt_id"], "ProviderCoverageRevision.last_receipt_id")
    last_received_at = None if item["last_received_at"] is None else _timestamp(item["last_received_at"], "ProviderCoverageRevision.last_received_at")
    if (last_receipt_id is None) != (last_received_at is None):
        _fail("ProviderCoverageRevision last receipt linkage differs")
    gap_started_at = None if item["gap_started_at"] is None else _timestamp(item["gap_started_at"], "ProviderCoverageRevision.gap_started_at")
    assessed_at = _timestamp(item["assessed_at"], "ProviderCoverageRevision.assessed_at")
    if (
        last_received_at is not None
        and _parsed_timestamp(last_received_at) > _parsed_timestamp(assessed_at)
    ):
        _fail("ProviderCoverageRevision last receipt follows assessment")
    if gap_started_at is not None and _parsed_timestamp(gap_started_at) > _parsed_timestamp(assessed_at):
        _fail("ProviderCoverageRevision gap starts after assessment")
    dropped = _integer_fact(item["dropped_event_count"], "ProviderCoverageRevision.dropped_event_count")
    observation = _observation(item["observation"], "ProviderCoverageRevision.observation")
    assessment_source = _enum(
        item["assessment_source"],
        "ProviderCoverageRevision.assessment_source",
        frozenset({
            "receipt",
            "adapter_health",
            "collector_health",
            "spool",
            "configuration",
        }),
    )
    provider = _enum(
        item["provider"],
        "ProviderCoverageRevision.provider",
        frozenset({"codex", "claude"}),
    )
    source_class = _enum(
        item["source_class"],
        "ProviderCoverageRevision.source_class",
        frozenset({"codex_app_server", "claude_hook", "otel"}),
    )
    if (
        (provider == "codex" and source_class != "codex_app_server")
        or (
            provider == "claude"
            and source_class not in {"claude_hook", "otel"}
        )
    ):
        _fail("ProviderCoverageRevision provider/source matrix is invalid")
    if assessment_source == "receipt" and last_receipt_id is None:
        _fail("ProviderCoverageRevision receipt assessment lacks a receipt")
    if state == "observed":
        if (
            reason != "observed"
            or observation != {"state": "known", "reason": "observed"}
            or assessment_source
            not in {"receipt", "adapter_health", "collector_health"}
            or last_receipt_id is None
            or gap_started_at is not None
            or dropped
            != {
                "value": 0,
                "source": dropped["source"],
                "quality": "observed",
                "reason": "observed",
            }
        ):
            _fail("ProviderCoverageRevision observed matrix is invalid")
    elif state == "degraded":
        if (
            reason == "observed"
            or observation != {"state": "known", "reason": "observed"}
            or gap_started_at is None
        ):
            _fail("ProviderCoverageRevision degraded state requires an explanation")
    elif state == "unavailable":
        if (
            reason == "observed"
            or dropped["quality"] == "observed"
            or observation["state"] != "unavailable"
        ):
            _fail("ProviderCoverageRevision unavailable coverage cannot claim a zero drop count")
    elif (
        reason == "observed"
        or dropped["quality"] == "observed"
        or observation["state"] != "unknown"
    ):
        _fail("ProviderCoverageRevision unknown coverage matrix is invalid")
    unsigned = {key: item[key] for key in fields - {"coverage_sha256"}}
    coverage_sha256 = _sha256(item["coverage_sha256"], "ProviderCoverageRevision.coverage_sha256")
    if coverage_sha256 != company_contract_sha256(unsigned):
        _fail("ProviderCoverageRevision.coverage_sha256 differs")
    result.update({
        "coverage_scope_id": _id(item["coverage_scope_id"], "ProviderCoverageRevision.coverage_scope_id"),
        "coverage_surface": _enum(item["coverage_surface"], "ProviderCoverageRevision.coverage_surface", frozenset({"lifecycle", "usage", "collector"})),
        "revision_id": _id(item["revision_id"], "ProviderCoverageRevision.revision_id"),
        "revision": revision, "previous_revision_sha256": previous,
        "provider": provider,
        "adapter_instance_id": _id(item["adapter_instance_id"], "ProviderCoverageRevision.adapter_instance_id"),
        "source_class": source_class,
        "declared_event_kinds": event_kinds, "state": state, "reason": reason,
        "assessment_source": assessment_source,
        "last_receipt_id": last_receipt_id, "last_received_at": last_received_at,
        "gap_started_at": gap_started_at, "dropped_event_count": dropped,
        "assessed_at": assessed_at, "observation": observation, "coverage_sha256": coverage_sha256,
    })
    return result


def _model_context_window(value: Any, label: str) -> dict[str, Any]:
    item = _object(value, {"present", "value"}, label)
    if not isinstance(item["present"], bool):
        _fail(f"{label}.present is invalid")
    if item["present"]:
        return {"present": True, "value": _integer(item["value"], f"{label}.value", maximum=999_999_999_999)}
    if item["value"] is not None:
        _fail(f"{label}.value must be null when absent")
    return {"present": False, "value": None}


def validate_usage_counter_sample(value: Any) -> dict[str, Any]:
    """Validate one raw non-additive cumulative provider counter sample."""
    fields = _common_fields({
        "sample_id", "telemetry_receipt_id", "telemetry_receipt_sha256", "adapter_instance_id",
        "adapter_event_id", "intake_sequence", "provider", "thread_id", "turn_id",
        "counter_scope_id", "provider_sequence", "counting_semantics", "total_token_vector",
        "last_token_vector", "model_context_window", "provenance_facts", "received_at",
        "raw_artifact", "provenance", "observation", "sample_sha256",
    })
    item, result = _base(value, USAGE_COUNTER_SAMPLE_V1, fields, "UsageCounterSample")
    if item["counting_semantics"] != "non_additive_cumulative":
        _fail("UsageCounterSample counting semantics is invalid")
    if item["provider"] != "codex":
        _fail("UsageCounterSample v1 is limited to Codex cumulative telemetry")
    thread_id = _text(
        item["thread_id"],
        "UsageCounterSample.thread_id",
        maximum=MAX_SHORT_TEXT_BYTES,
    )
    turn_id = _text(
        item["turn_id"],
        "UsageCounterSample.turn_id",
        maximum=MAX_SHORT_TEXT_BYTES,
    )
    counter_scope_id = _text(
        item["counter_scope_id"],
        "UsageCounterSample.counter_scope_id",
        maximum=MAX_SHORT_TEXT_BYTES,
    )
    provider_sequence = None if item["provider_sequence"] is None else _integer(
        item["provider_sequence"], "UsageCounterSample.provider_sequence", maximum=999_999_999_999,
    )
    observation = _observation(item["observation"], "UsageCounterSample.observation")
    if observation != {"state": "known", "reason": "observed"}:
        _fail("UsageCounterSample receipt must be a known observation")
    total_vector = _token_vector(
        item["total_token_vector"],
        "UsageCounterSample.total_token_vector",
    )
    last_vector = _token_vector(
        item["last_token_vector"],
        "UsageCounterSample.last_token_vector",
    )
    mandatory_dimensions = (
        "input",
        "cache_read",
        "output",
        "reasoning_output",
        "total",
    )
    if any(
        not vector[dimension]["present"]
        for vector in (total_vector, last_vector)
        for dimension in mandatory_dimensions
    ):
        _fail("UsageCounterSample required Codex token dimension is absent")
    unsigned = {key: item[key] for key in fields - {"sample_sha256"}}
    sample_sha256 = _sha256(item["sample_sha256"], "UsageCounterSample.sample_sha256")
    if sample_sha256 != company_contract_sha256(unsigned):
        _fail("UsageCounterSample.sample_sha256 differs")
    result.update({
        "sample_id": _id(item["sample_id"], "UsageCounterSample.sample_id"),
        "telemetry_receipt_id": _id(item["telemetry_receipt_id"], "UsageCounterSample.telemetry_receipt_id"),
        "telemetry_receipt_sha256": _sha256(item["telemetry_receipt_sha256"], "UsageCounterSample.telemetry_receipt_sha256"),
        "adapter_instance_id": _id(item["adapter_instance_id"], "UsageCounterSample.adapter_instance_id"),
        "adapter_event_id": _id(item["adapter_event_id"], "UsageCounterSample.adapter_event_id"),
        "intake_sequence": _integer(item["intake_sequence"], "UsageCounterSample.intake_sequence", minimum=1, maximum=999_999_999_999),
        "provider": _id(item["provider"], "UsageCounterSample.provider"), "thread_id": thread_id,
        "turn_id": turn_id, "counter_scope_id": counter_scope_id,
        "provider_sequence": provider_sequence, "counting_semantics": "non_additive_cumulative",
        "total_token_vector": total_vector,
        "last_token_vector": last_vector,
        "model_context_window": _model_context_window(item["model_context_window"], "UsageCounterSample.model_context_window"),
        "provenance_facts": _telemetry_facts(item["provenance_facts"], "UsageCounterSample.provenance_facts", _USAGE_PROVENANCE_FACT_KEYS),
        "received_at": _timestamp(item["received_at"], "UsageCounterSample.received_at"),
        "raw_artifact": _telemetry_raw_blob(item["raw_artifact"], "UsageCounterSample.raw_artifact", maximum=MAX_PROVIDER_TELEMETRY_RAW_BYTES),
        "provenance": _enum(item["provenance"], "UsageCounterSample.provenance", _PROVIDER_RECEIPT_PROVENANCE),
        "observation": observation, "sample_sha256": sample_sha256,
    })
    return result


def _needs_user_blob(value: Any, label: str, *, media_type: str) -> dict[str, Any]:
    blob = validate_blob_ref(value)
    if (
        blob["availability"] != "available" or blob["media_type"] != media_type
        or blob["size_bytes"] is None or blob["size_bytes"] < 1
        or blob["size_bytes"] > MAX_NEEDS_USER_CONTENT_BYTES
    ):
        _fail(f"{label} requires bounded available content")
    return blob


def validate_needs_user_revision(value: Any) -> dict[str, Any]:
    """Validate a NeedsUser revision; adjacency, question immutability, and Chief/fresh-user authority are Supervisor-owned."""
    fields = _common_fields({
        "item_id", "revision_id", "revision", "previous_revision_sha256", "origin_execution_id",
        "opened_chief_term", "state", "question_sha256", "question_blob", "answer_sha256",
        "answer_blob", "created_at", "updated_at", "answered_at", "answered_by_chief_term",
        "answer_control_intent_id", "observation", "revision_sha256",
    })
    item, result = _base(value, NEEDS_USER_REVISION_V1, fields, "NeedsUserRevision")
    revision = _integer(
        item["revision"],
        "NeedsUserRevision.revision",
        minimum=1,
        maximum=2,
    )
    previous = _sha256(item["previous_revision_sha256"], "NeedsUserRevision.previous_revision_sha256")
    if (revision == 1) != (previous == ZERO_SHA256):
        _fail("NeedsUserRevision genesis predecessor differs")
    state = _enum(item["state"], "NeedsUserRevision.state", frozenset({"pending", "answered", "expired"}))
    created_at = _timestamp(item["created_at"], "NeedsUserRevision.created_at")
    updated_at = _timestamp(item["updated_at"], "NeedsUserRevision.updated_at")
    if _parsed_timestamp(updated_at) < _parsed_timestamp(created_at):
        _fail("NeedsUserRevision updated_at precedes created_at")
    answered_at = None if item["answered_at"] is None else _timestamp(item["answered_at"], "NeedsUserRevision.answered_at")
    if answered_at is not None and _parsed_timestamp(answered_at) < _parsed_timestamp(created_at):
        _fail("NeedsUserRevision answered_at precedes created_at")
    if (
        answered_at is not None
        and _parsed_timestamp(answered_at) != _parsed_timestamp(updated_at)
    ):
        _fail("NeedsUserRevision answered_at differs from updated_at")
    question_blob = _needs_user_blob(item["question_blob"], "NeedsUserRevision.question_blob", media_type=NEEDS_USER_QUESTION_MEDIA_TYPE)
    question_sha256 = _sha256(item["question_sha256"], "NeedsUserRevision.question_sha256")
    if question_sha256 != question_blob["sha256"]:
        _fail("NeedsUserRevision question digest differs")
    answer_blob = None if item["answer_blob"] is None else _needs_user_blob(
        item["answer_blob"], "NeedsUserRevision.answer_blob", media_type=NEEDS_USER_ANSWER_MEDIA_TYPE,
    )
    answer_sha256 = _nullable_sha256(item["answer_sha256"], "NeedsUserRevision.answer_sha256")
    answered_term = None if item["answered_by_chief_term"] is None else _integer(
        item["answered_by_chief_term"], "NeedsUserRevision.answered_by_chief_term", minimum=1, maximum=999_999_999,
    )
    control_intent = _nullable_id(item["answer_control_intent_id"], "NeedsUserRevision.answer_control_intent_id")
    observation = _observation(item["observation"], "NeedsUserRevision.observation")
    if (
        revision == 1
        and (
            state != "pending"
            or _parsed_timestamp(updated_at) != _parsed_timestamp(created_at)
        )
    ):
        _fail("NeedsUserRevision genesis must be pending at creation")
    if revision == 2 and state == "pending":
        _fail("NeedsUserRevision successor must be terminal")
    if (
        revision == 2
        and _parsed_timestamp(updated_at) <= _parsed_timestamp(created_at)
    ):
        _fail("NeedsUserRevision successor must update after creation")
    if state == "answered":
        if (
            answer_blob is None or answer_sha256 is None or answer_sha256 != answer_blob["sha256"]
            or answered_at is None or answered_term is None or control_intent is None
            or observation != {"state": "known", "reason": "observed"}
        ):
            _fail("NeedsUserRevision answered matrix is invalid")
    elif any(member is not None for member in (answer_blob, answer_sha256, answered_at, answered_term, control_intent)):
        _fail("NeedsUserRevision non-answered state cannot assert an answer")
    elif state == "expired" and (
        observation != {"state": "known", "reason": "observed"}
        or _parsed_timestamp(updated_at) <= _parsed_timestamp(created_at)
    ):
        _fail("NeedsUserRevision expired state requires a later known update")
    unsigned = {key: item[key] for key in fields - {"revision_sha256"}}
    revision_sha256 = _sha256(item["revision_sha256"], "NeedsUserRevision.revision_sha256")
    if revision_sha256 != company_contract_sha256(unsigned):
        _fail("NeedsUserRevision.revision_sha256 differs")
    result.update({
        "item_id": _id(item["item_id"], "NeedsUserRevision.item_id"),
        "revision_id": _id(item["revision_id"], "NeedsUserRevision.revision_id"),
        "revision": revision, "previous_revision_sha256": previous,
        "origin_execution_id": _nullable_id(item["origin_execution_id"], "NeedsUserRevision.origin_execution_id"),
        "opened_chief_term": _integer(item["opened_chief_term"], "NeedsUserRevision.opened_chief_term", minimum=1, maximum=999_999_999),
        "state": state, "question_sha256": question_sha256, "question_blob": question_blob,
        "answer_sha256": answer_sha256, "answer_blob": answer_blob, "created_at": created_at,
        "updated_at": updated_at, "answered_at": answered_at,
        "answered_by_chief_term": answered_term, "answer_control_intent_id": control_intent,
        "observation": observation, "revision_sha256": revision_sha256,
    })
    return result


def _dashboard_text(value: Any, label: str, *, maximum: int) -> str:
    """Accept bounded single-line text that is safe to render as metadata."""
    text = _text(value, label, maximum=maximum)
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        _fail(f"{label} contains a dashboard-unsafe control character")
    return text


def _work_path(value: Any, label: str, *, allow_dot: bool = False) -> str:
    original_path = _text(value, label, maximum=1024)
    path = unicodedata.normalize("NFC", original_path)
    if path != original_path:
        _fail(f"{label} must use NFC-normalized Unicode")
    if "\\" in path or path.startswith("/") or "//" in path:
        _fail(f"{label} is not a canonical relative path")
    if re.match(r"^[A-Za-z]:", path) or ":" in path:
        _fail(f"{label} is not a canonical relative path")
    if path == ".":
        if allow_dot:
            return path
        _fail(f"{label} cannot name the repository root")
    for segment in path.split("/"):
        if segment in {"", ".", ".."}:
            _fail(f"{label} contains path traversal")
        if any(ord(character) < 32 or ord(character) == 127 for character in segment):
            _fail(f"{label} contains a control character")
        if any(character in '<>:"\\|?*' for character in segment):
            _fail(f"{label} contains a Windows-invalid character")
        if segment.endswith((".", " ")):
            _fail(f"{label} has a Windows-ambiguous trailing suffix")
        device_stem = unicodedata.normalize("NFKC", segment.split(".", 1)[0]).casefold()
        if device_stem in _WINDOWS_RESERVED_DEVICE_ALIASES:
            _fail(f"{label} names a Windows device alias")
    return path


def _work_path_identity(path: str) -> str:
    """Return the cross-platform collision identity of one canonical work path."""
    return unicodedata.normalize("NFC", path).casefold()


def _sorted_unique_strings(
    value: Any,
    label: str,
    item: Callable[[Any, str], str],
    *,
    maximum: int,
) -> list[str]:
    result = _bounded_list(value, label, item, maximum=maximum)
    if result != sorted(result) or len(result) != len(set(result)):
        _fail(f"{label} must be sorted and unique")
    return result


def _authority_ref(value: Any, label: str) -> dict[str, str]:
    item = _object(value, {"kind", "path"}, label)
    return {
        "kind": _enum(item["kind"], f"{label}.kind", _WORK_AUTHORITY_REF_KINDS),
        "path": _work_path(item["path"], f"{label}.path"),
    }


def _authority_refs(value: Any, label: str) -> list[dict[str, str]]:
    refs = _bounded_list(value, label, _authority_ref, maximum=64)
    sort_key = lambda reference: (_work_path_identity(reference["path"]), reference["path"], reference["kind"])
    if refs != sorted(refs, key=sort_key):
        _fail(f"{label} must be canonically sorted")
    identities = {_work_path_identity(reference["path"]) for reference in refs}
    if len(identities) != len(refs):
        _fail(f"{label} contains duplicate references")
    return refs


def _authority_ref_covers(parent: Mapping[str, str], child: Mapping[str, str]) -> bool:
    """Return whether one canonical file/tree authority covers another."""
    parent_path = parent["path"]
    child_path = child["path"]
    if parent["kind"] == "file":
        return child["kind"] == "file" and parent_path == child_path
    return child_path == parent_path or child_path.startswith(f"{parent_path}/")


def authority_scope_is_subset(
    candidate: Any,
    ceiling: Any,
) -> bool:
    """Return whether every typed authority in ``candidate`` is covered by ``ceiling``.

    Both values are revalidated so callers cannot turn a pre-normalized mapping
    into a broader scope by bypassing the contract boundary.
    """
    candidate_scope = _authority_scope(candidate, "candidate_authority_scope")
    ceiling_scope = _authority_scope(ceiling, "ceiling_authority_scope")
    for member in ("read_refs", "write_refs", "run_refs", "export_refs"):
        if any(
            not any(_authority_ref_covers(parent, child) for parent in ceiling_scope[member])
            for child in candidate_scope[member]
        ):
            return False
    return set(candidate_scope["provider_allowlist"]).issubset(
        ceiling_scope["provider_allowlist"],
    )


def _authority_scope(value: Any, label: str) -> dict[str, Any]:
    """Validate a representable scope without asserting cross-record subsets."""
    item = _object(
        value,
        {"read_refs", "write_refs", "run_refs", "export_refs", "provider_allowlist"},
        label,
    )
    return {
        "read_refs": _authority_refs(item["read_refs"], f"{label}.read_refs"),
        "write_refs": _authority_refs(item["write_refs"], f"{label}.write_refs"),
        "run_refs": _authority_refs(item["run_refs"], f"{label}.run_refs"),
        "export_refs": _authority_refs(item["export_refs"], f"{label}.export_refs"),
        "provider_allowlist": _sorted_unique_strings(
            item["provider_allowlist"], f"{label}.provider_allowlist", _id,
            maximum=16,
        ),
    }


def _available_blob_ref(value: Any, label: str, *, media_type: str | None = None) -> dict[str, Any]:
    result = validate_blob_ref(value)
    if result["availability"] != "available":
        _fail(f"{label} must reference available bytes")
    if media_type is not None and result["media_type"] != media_type:
        _fail(f"{label} has an unexpected media type")
    return result


def _work_manifest_entries(value: Any, label: str) -> list[dict[str, Any]]:
    raw_entries = _bounded_list(
        value, label, lambda member, _member_label: member, maximum=128,
    )
    entries: list[dict[str, Any]] = []
    for index, member in enumerate(raw_entries):
        member_label = f"{label}[{index}]"
        item = _object(member, {"path", "entry_type", "sha256", "size_bytes"}, member_label)
        entries.append({
            "path": _work_path(item["path"], f"{member_label}.path"),
            "entry_type": _enum(
                item["entry_type"], f"{member_label}.entry_type", _WORK_MANIFEST_ENTRY_TYPES,
            ),
            "sha256": _sha256(item["sha256"], f"{member_label}.sha256"),
            "size_bytes": _integer(
                item["size_bytes"], f"{member_label}.size_bytes", maximum=MAX_CONTRACT_BYTES * 1024,
            ),
        })
    sort_key = lambda entry: (
        _work_path_identity(entry["path"]), entry["path"], entry["entry_type"], entry["sha256"], entry["size_bytes"],
    )
    if entries != sorted(entries, key=sort_key):
        _fail(f"{label} must be canonically sorted")
    if len({_work_path_identity(entry["path"]) for entry in entries}) != len(entries):
        _fail(f"{label} contains duplicate paths")
    return entries


def _work_manifest_entries_sha256(entries: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(canonical_company_json_bytes(list(entries))).hexdigest()


def work_manifest_entries_sha256(value: Any) -> str:
    """Return the canonical digest of one validated context entry list."""
    return _work_manifest_entries_sha256(_work_manifest_entries(value, "WorkManifestEntries"))


def _sorted_available_blob_refs(value: Any, label: str) -> list[dict[str, Any]]:
    refs = _bounded_list(
        value, label, lambda member, _member_label: _available_blob_ref(member, _member_label), maximum=64,
    )
    if refs != sorted(refs, key=lambda reference: str(reference["sha256"])):
        _fail(f"{label} must be canonically sorted")
    if len({reference["sha256"] for reference in refs}) != len(refs):
        _fail(f"{label} contains duplicate references")
    return refs


def validate_task_revision(value: Any) -> dict[str, Any]:
    """Validate an immutable dashboard-safe task revision and its self-digest."""
    fields = _common_fields({
        "task_id", "task_revision_id", "revision", "previous_task_revision_id",
        "previous_task_sha256", "display_name", "objective", "authority_ceiling",
        "completion_boundary_ref", "created_at", "task_sha256",
    })
    item, result = _base(value, TASK_REVISION_V1, fields, "TaskRevision")
    revision = _integer(item["revision"], "TaskRevision.revision", minimum=1, maximum=999_999_999)
    predecessor_id = _nullable_id(
        item["previous_task_revision_id"], "TaskRevision.previous_task_revision_id",
    )
    predecessor_sha256 = _nullable_sha256(
        item["previous_task_sha256"], "TaskRevision.previous_task_sha256",
    )
    if (revision == 1) != (predecessor_id is None and predecessor_sha256 is None):
        _fail("TaskRevision revision and predecessor fields differ")
    if revision > 1 and (predecessor_id is None or predecessor_sha256 is None):
        _fail("TaskRevision later revision requires a predecessor")
    task_revision_id = _id(item["task_revision_id"], "TaskRevision.task_revision_id")
    if predecessor_id == task_revision_id:
        _fail("TaskRevision cannot name itself as its predecessor")
    unsigned = {key: item[key] for key in fields - {"task_sha256"}}
    task_sha256 = _sha256(item["task_sha256"], "TaskRevision.task_sha256")
    if task_sha256 != company_contract_sha256(unsigned):
        _fail("TaskRevision.task_sha256 differs")
    result.update({
        "task_id": _id(item["task_id"], "TaskRevision.task_id"),
        "task_revision_id": task_revision_id,
        "revision": revision,
        "previous_task_revision_id": predecessor_id,
        "previous_task_sha256": predecessor_sha256,
        "display_name": _dashboard_text(item["display_name"], "TaskRevision.display_name", maximum=160),
        "objective": _dashboard_text(item["objective"], "TaskRevision.objective", maximum=2048),
        "authority_ceiling": _authority_scope(item["authority_ceiling"], "TaskRevision.authority_ceiling"),
        "completion_boundary_ref": _available_blob_ref(
            item["completion_boundary_ref"], "TaskRevision.completion_boundary_ref",
        ),
        "created_at": _timestamp(item["created_at"], "TaskRevision.created_at"),
        "task_sha256": task_sha256,
    })
    return result


def validate_work_packet(value: Any) -> dict[str, Any]:
    """Validate a pure immutable dispatch definition, not its admission result."""
    fields = _common_fields({
        "packet_id", "parent_packet_id", "parent_packet_sha256", "task_id",
        "task_revision_id", "task_sha256", "manager_node_id", "parent_execution_id",
        "target_node_id", "department_id", "null_relationship_justifications",
        "delegation_depth", "display_name", "objective", "prompt_ref",
        "context_manifest_ref", "source_manifest_sha256", "config_manifest_sha256",
        "dependency_manifest_sha256", "authority_scope", "redaction_policy",
        "created_at", "expires_at", "packet_sha256",
    })
    item, result = _base(value, WORK_PACKET_V1, fields, "WorkPacket")
    parent_packet_id = _nullable_id(item["parent_packet_id"], "WorkPacket.parent_packet_id")
    parent_packet_sha256 = _nullable_sha256(
        item["parent_packet_sha256"], "WorkPacket.parent_packet_sha256",
    )
    if (parent_packet_id is None) != (parent_packet_sha256 is None):
        _fail("WorkPacket parent packet id and digest differ")
    packet_id = _id(item["packet_id"], "WorkPacket.packet_id")
    if parent_packet_id == packet_id:
        _fail("WorkPacket cannot name itself as its parent")
    justifications = _object(
        item["null_relationship_justifications"], set(_WORK_NULL_RELATIONSHIP_KEYS),
        "WorkPacket.null_relationship_justifications",
    )
    relationships: dict[str, str | None] = {}
    normalized_justifications: dict[str, str | None] = {}
    for name in sorted(_WORK_NULL_RELATIONSHIP_KEYS):
        relationship = _nullable_id(item[name], f"WorkPacket.{name}")
        justification = justifications[name]
        if relationship is None:
            if justification is None:
                _fail(f"WorkPacket.{name} requires an explicit null justification")
            normalized_justifications[name] = _dashboard_text(
                justification, f"WorkPacket.null_relationship_justifications.{name}", maximum=160,
            )
        else:
            if justification is not None:
                _fail(f"WorkPacket.{name} cannot justify a non-null relationship")
            normalized_justifications[name] = None
        relationships[name] = relationship
    redaction_policy = _object(
        item["redaction_policy"], {"dashboard", "secrets", "chain_of_thought"},
        "WorkPacket.redaction_policy",
    )
    if redaction_policy != {
        "dashboard": "metadata_only", "secrets": "excluded", "chain_of_thought": "forbidden",
    }:
        _fail("WorkPacket.redaction_policy is not the fixed policy")
    created_at = _timestamp(item["created_at"], "WorkPacket.created_at")
    expires_at = _timestamp(item["expires_at"], "WorkPacket.expires_at")
    if _parsed_timestamp(expires_at) <= _parsed_timestamp(created_at):
        _fail("WorkPacket.expires_at must follow created_at")
    unsigned = {key: item[key] for key in fields - {"packet_sha256"}}
    packet_sha256 = _sha256(item["packet_sha256"], "WorkPacket.packet_sha256")
    if packet_sha256 != company_contract_sha256(unsigned):
        _fail("WorkPacket.packet_sha256 differs")
    result.update({
        "packet_id": packet_id,
        "parent_packet_id": parent_packet_id,
        "parent_packet_sha256": parent_packet_sha256,
        "task_id": _id(item["task_id"], "WorkPacket.task_id"),
        "task_revision_id": _id(item["task_revision_id"], "WorkPacket.task_revision_id"),
        "task_sha256": _sha256(item["task_sha256"], "WorkPacket.task_sha256"),
        **relationships,
        "null_relationship_justifications": normalized_justifications,
        "delegation_depth": _integer(
            item["delegation_depth"], "WorkPacket.delegation_depth", minimum=1, maximum=MAX_DEPTH,
        ),
        "display_name": _dashboard_text(item["display_name"], "WorkPacket.display_name", maximum=160),
        "objective": _dashboard_text(item["objective"], "WorkPacket.objective", maximum=2048),
        "prompt_ref": _available_blob_ref(
            item["prompt_ref"], "WorkPacket.prompt_ref", media_type=WORK_PACKET_PROMPT_MEDIA_TYPE,
        ),
        "context_manifest_ref": _available_blob_ref(
            item["context_manifest_ref"], "WorkPacket.context_manifest_ref",
            media_type=WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
        ),
        "source_manifest_sha256": _sha256(
            item["source_manifest_sha256"], "WorkPacket.source_manifest_sha256",
        ),
        "config_manifest_sha256": _sha256(
            item["config_manifest_sha256"], "WorkPacket.config_manifest_sha256",
        ),
        "dependency_manifest_sha256": _sha256(
            item["dependency_manifest_sha256"], "WorkPacket.dependency_manifest_sha256",
        ),
        "authority_scope": _authority_scope(item["authority_scope"], "WorkPacket.authority_scope"),
        "redaction_policy": dict(redaction_policy),
        "created_at": created_at,
        "expires_at": expires_at,
        "packet_sha256": packet_sha256,
    })
    return result


def validate_work_context_manifest(value: Any) -> dict[str, Any]:
    """Validate a canonical CAS context document with no prompt or secret channel."""
    fields = {
        "document_type", "schema_version", "company_id", "company_incarnation",
        "lock_domain_generation", "repository_id", "repository_sha256", "cwd",
        "department_snapshot_ref", "source_entries", "config_entries", "dependency_entries",
        "source_manifest_sha256", "config_manifest_sha256", "dependency_manifest_sha256",
        "upstream_result_refs",
    }
    item = _object(_canonical(value, "WorkContextManifest"), fields, "WorkContextManifest")
    if item["document_type"] != WORK_CONTEXT_MANIFEST_V1:
        _fail("WorkContextManifest.document_type is invalid")
    if _integer(item["schema_version"], "WorkContextManifest.schema_version", minimum=1, maximum=1) != 1:
        _fail("WorkContextManifest.schema_version is unsupported")
    binding = _embedded_binding(item, "WorkContextManifest")
    source_entries = _work_manifest_entries(
        item["source_entries"], "WorkContextManifest.source_entries",
    )
    config_entries = _work_manifest_entries(
        item["config_entries"], "WorkContextManifest.config_entries",
    )
    dependency_entries = _work_manifest_entries(
        item["dependency_entries"], "WorkContextManifest.dependency_entries",
    )
    source_manifest_sha256 = _sha256(
        item["source_manifest_sha256"], "WorkContextManifest.source_manifest_sha256",
    )
    config_manifest_sha256 = _sha256(
        item["config_manifest_sha256"], "WorkContextManifest.config_manifest_sha256",
    )
    dependency_manifest_sha256 = _sha256(
        item["dependency_manifest_sha256"], "WorkContextManifest.dependency_manifest_sha256",
    )
    if source_manifest_sha256 != _work_manifest_entries_sha256(source_entries):
        _fail("WorkContextManifest.source_manifest_sha256 differs")
    if config_manifest_sha256 != _work_manifest_entries_sha256(config_entries):
        _fail("WorkContextManifest.config_manifest_sha256 differs")
    if dependency_manifest_sha256 != _work_manifest_entries_sha256(dependency_entries):
        _fail("WorkContextManifest.dependency_manifest_sha256 differs")
    all_paths = [
        _work_path_identity(entry["path"])
        for entries in (source_entries, config_entries, dependency_entries)
        for entry in entries
    ]
    if len(set(all_paths)) != len(all_paths):
        _fail("WorkContextManifest entries collide across categories")
    return {
        "document_type": WORK_CONTEXT_MANIFEST_V1,
        "schema_version": COMPANY_CONTRACT_SCHEMA_VERSION,
        **binding,
        "repository_id": _id(item["repository_id"], "WorkContextManifest.repository_id"),
        "repository_sha256": _sha256(item["repository_sha256"], "WorkContextManifest.repository_sha256"),
        "cwd": _work_path(item["cwd"], "WorkContextManifest.cwd", allow_dot=True),
        "department_snapshot_ref": _available_blob_ref(
            item["department_snapshot_ref"], "WorkContextManifest.department_snapshot_ref",
            media_type=DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
        ),
        "source_entries": source_entries,
        "config_entries": config_entries,
        "dependency_entries": dependency_entries,
        "source_manifest_sha256": source_manifest_sha256,
        "config_manifest_sha256": config_manifest_sha256,
        "dependency_manifest_sha256": dependency_manifest_sha256,
        "upstream_result_refs": _sorted_available_blob_refs(
            item["upstream_result_refs"], "WorkContextManifest.upstream_result_refs",
        ),
    }


def canonical_work_context_manifest_bytes(value: Any) -> bytes:
    """Return CAS-ready canonical bytes only for a valid context manifest."""
    return canonical_company_json_bytes(validate_work_context_manifest(value))


def work_context_manifest_sha256(value: Any) -> str:
    """Return the stable CAS key for a valid context manifest."""
    return hashlib.sha256(canonical_work_context_manifest_bytes(value)).hexdigest()


def _scope_refs_bind_context(scope: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    entries = [
        entry
        for category in ("source_entries", "config_entries", "dependency_entries")
        for entry in context[category]
    ]
    for member in ("read_refs", "write_refs", "run_refs", "export_refs"):
        for reference in scope[member]:
            path = reference["path"]
            if reference["kind"] == "file":
                bound = any(
                    entry["path"] == path and entry["entry_type"] == "file"
                    for entry in entries
                )
            else:
                bound = any(
                    entry["path"] == path and entry["entry_type"] == "directory"
                    for entry in entries
                )
            if not bound:
                return False
    return True


def validate_work_definition_bundle(
    task_revision: Any,
    work_packet: Any,
    context_manifest: Any,
    *,
    parent_packet: Any | None = None,
    parent_context_manifest: Any | None = None,
) -> dict[str, Any]:
    """Validate the immutable task/packet/context bundle before admission.

    This is deliberately a pure cross-document check.  It neither resolves CAS
    storage nor admits a carrier.  A child requires its immediate parent's
    immutable context manifest so this function can validate that parent
    against the same task.  Durable parent-chain resolution remains a
    Supervisor responsibility.
    """
    task = validate_task_revision(task_revision)
    packet = validate_work_packet(work_packet)
    context = validate_work_context_manifest(context_manifest)
    for field in ("company_id", "company_incarnation", "lock_domain_generation"):
        if task[field] != packet[field] or packet[field] != context[field]:
            _fail(f"WorkDefinitionBundle.{field} differs")
    if (
        packet["task_id"] != task["task_id"]
        or packet["task_revision_id"] != task["task_revision_id"]
        or packet["task_sha256"] != task["task_sha256"]
    ):
        _fail("WorkDefinitionBundle task binding differs")
    if _parsed_timestamp(packet["created_at"]) < _parsed_timestamp(task["created_at"]):
        _fail("WorkDefinitionBundle packet precedes task revision")
    canonical_context_bytes = canonical_company_json_bytes(context)
    if (
        packet["context_manifest_ref"]["sha256"] != hashlib.sha256(canonical_context_bytes).hexdigest()
        or packet["context_manifest_ref"]["size_bytes"] != len(canonical_context_bytes)
    ):
        _fail("WorkDefinitionBundle context manifest reference differs")
    for field in (
        "source_manifest_sha256", "config_manifest_sha256", "dependency_manifest_sha256",
    ):
        if packet[field] != context[field]:
            _fail(f"WorkDefinitionBundle.{field} differs")
    if not authority_scope_is_subset(packet["authority_scope"], task["authority_ceiling"]):
        _fail("WorkDefinitionBundle packet authority exceeds task ceiling")
    if not _scope_refs_bind_context(packet["authority_scope"], context):
        _fail("WorkDefinitionBundle packet authority is outside context")
    is_root = packet["parent_packet_id"] is None
    if is_root:
        if (
            parent_packet is not None
            or parent_context_manifest is not None
            or packet["delegation_depth"] != 1
        ):
            _fail("WorkDefinitionBundle root parent/depth binding is invalid")
        parent = None
        parent_context = None
        added_upstream_result_refs: list[dict[str, Any]] = []
    else:
        if parent_packet is None:
            _fail("WorkDefinitionBundle child requires its parent packet")
        if parent_context_manifest is None:
            _fail("WorkDefinitionBundle child requires its parent context manifest")
        parent = validate_work_packet(parent_packet)
        parent_context = validate_work_context_manifest(parent_context_manifest)
        if (
            packet["parent_packet_id"] != parent["packet_id"]
            or packet["parent_packet_sha256"] != parent["packet_sha256"]
            or packet["delegation_depth"] != parent["delegation_depth"] + 1
        ):
            _fail("WorkDefinitionBundle child parent/depth binding differs")
        for field in (
            "company_id", "company_incarnation", "lock_domain_generation", "task_id",
            "task_revision_id", "task_sha256",
        ):
            if packet[field] != parent[field]:
                _fail(f"WorkDefinitionBundle child {field} differs")
        for field in ("company_id", "company_incarnation", "lock_domain_generation"):
            if parent[field] != task[field] or parent_context[field] != task[field]:
                _fail(f"WorkDefinitionBundle parent {field} differs")
        if (
            parent["task_id"] != task["task_id"]
            or parent["task_revision_id"] != task["task_revision_id"]
            or parent["task_sha256"] != task["task_sha256"]
        ):
            _fail("WorkDefinitionBundle parent task binding differs")
        if _parsed_timestamp(parent["created_at"]) < _parsed_timestamp(task["created_at"]):
            _fail("WorkDefinitionBundle parent packet precedes task revision")
        parent_context_bytes = canonical_company_json_bytes(parent_context)
        if (
            parent["context_manifest_ref"]["sha256"]
            != hashlib.sha256(parent_context_bytes).hexdigest()
            or parent["context_manifest_ref"]["size_bytes"] != len(parent_context_bytes)
        ):
            _fail("WorkDefinitionBundle parent context manifest reference differs")
        for field in (
            "source_manifest_sha256", "config_manifest_sha256", "dependency_manifest_sha256",
        ):
            if parent[field] != parent_context[field]:
                _fail(f"WorkDefinitionBundle parent {field} differs")
        if not authority_scope_is_subset(parent["authority_scope"], task["authority_ceiling"]):
            _fail("WorkDefinitionBundle parent authority exceeds task ceiling")
        if not _scope_refs_bind_context(parent["authority_scope"], parent_context):
            _fail("WorkDefinitionBundle parent authority is outside context")
        for field in (
            "company_id", "company_incarnation", "lock_domain_generation", "repository_id",
            "repository_sha256", "cwd", "department_snapshot_ref", "source_entries",
            "config_entries", "dependency_entries", "source_manifest_sha256",
            "config_manifest_sha256", "dependency_manifest_sha256",
        ):
            if context[field] != parent_context[field]:
                if field == "department_snapshot_ref":
                    _fail(
                        "WorkDefinitionBundle child fresh department snapshot requires a future schema",
                    )
                _fail(f"WorkDefinitionBundle child immutable context {field} differs")
        parent_upstream_refs = {
            canonical_company_json_bytes(reference) for reference in parent_context["upstream_result_refs"]
        }
        child_upstream_refs = {
            canonical_company_json_bytes(reference) for reference in context["upstream_result_refs"]
        }
        if not parent_upstream_refs <= child_upstream_refs:
            _fail("WorkDefinitionBundle child upstream result refs remove or replace a parent reference")
        added_upstream_result_refs = [
            reference for reference in context["upstream_result_refs"]
            if canonical_company_json_bytes(reference) not in parent_upstream_refs
        ]
        if _parsed_timestamp(packet["created_at"]) < _parsed_timestamp(parent["created_at"]):
            _fail("WorkDefinitionBundle child precedes parent packet")
        if _parsed_timestamp(packet["expires_at"]) > _parsed_timestamp(parent["expires_at"]):
            _fail("WorkDefinitionBundle child expiry exceeds parent packet")
        if not authority_scope_is_subset(packet["authority_scope"], parent["authority_scope"]):
            _fail("WorkDefinitionBundle child authority exceeds parent scope")
    return {
        "task_revision": task,
        "work_packet": packet,
        "context_manifest": context,
        "parent_packet": parent,
        "parent_context_manifest": parent_context,
        "context_derivation": {
            "added_upstream_result_refs": added_upstream_result_refs,
        },
    }


def validate_work_result_receipt(value: Any) -> dict[str, Any]:
    """Validate one immutable, verified result receipt for a work packet."""
    fields = _common_fields({
        "result_receipt_id", "task_id", "task_revision_id", "task_sha256",
        "packet_id", "packet_sha256", "producer_execution_id",
        "expected_execution_payload_sha256", "engineering_disposition_receipt_id",
        "result_ref", "recorded_at", "provenance", "observation", "receipt_sha256",
    })
    item, result = _base(value, WORK_RESULT_RECEIPT_V1, fields, "WorkResultReceipt")
    provenance = _enum(item["provenance"], "WorkResultReceipt.provenance", _PROVENANCE)
    observation = _observation(item["observation"], "WorkResultReceipt.observation")
    if provenance != "AOI_verified" or observation != {"state": "known", "reason": "observed"}:
        _fail("WorkResultReceipt provenance and observation must be AOI-verified and known")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    receipt_sha256 = _sha256(item["receipt_sha256"], "WorkResultReceipt.receipt_sha256")
    if receipt_sha256 != company_contract_sha256(unsigned):
        _fail("WorkResultReceipt.receipt_sha256 differs")
    result.update({
        "result_receipt_id": _id(item["result_receipt_id"], "WorkResultReceipt.result_receipt_id"),
        "task_id": _id(item["task_id"], "WorkResultReceipt.task_id"),
        "task_revision_id": _id(item["task_revision_id"], "WorkResultReceipt.task_revision_id"),
        "task_sha256": _sha256(item["task_sha256"], "WorkResultReceipt.task_sha256"),
        "packet_id": _id(item["packet_id"], "WorkResultReceipt.packet_id"),
        "packet_sha256": _sha256(item["packet_sha256"], "WorkResultReceipt.packet_sha256"),
        "producer_execution_id": _id(item["producer_execution_id"], "WorkResultReceipt.producer_execution_id"),
        "expected_execution_payload_sha256": _sha256(
            item["expected_execution_payload_sha256"],
            "WorkResultReceipt.expected_execution_payload_sha256",
        ),
        "engineering_disposition_receipt_id": _id(
            item["engineering_disposition_receipt_id"],
            "WorkResultReceipt.engineering_disposition_receipt_id",
        ),
        "result_ref": _available_blob_ref(item["result_ref"], "WorkResultReceipt.result_ref"),
        "recorded_at": _timestamp(item["recorded_at"], "WorkResultReceipt.recorded_at"),
        "provenance": provenance,
        "observation": observation,
        "receipt_sha256": receipt_sha256,
    })
    return result


def validate_work_dispatch_binding(value: Any) -> dict[str, Any]:
    """Validate the immutable, registered binding required before a work launch."""
    fields = _common_fields({
        "binding_id", "transaction_id", "command_id", "dispatch_request_id",
        "dispatch_revision_id", "dispatch_payload_sha256", "task_id",
        "task_revision_id", "task_sha256", "packet_id", "packet_sha256",
        "prompt_ref", "context_manifest_ref", "department_id", "target_node_id",
        "manager_node_id", "parent_execution_id", "delegation_depth",
        "authority_scope_sha256", "provider_allowlist", "expires_at", "created_at",
        "provenance", "observation", "binding_sha256",
    })
    item, result = _base(value, WORK_DISPATCH_BINDING_V1, fields, "WorkDispatchBinding")
    created_at = _timestamp(item["created_at"], "WorkDispatchBinding.created_at")
    expires_at = _timestamp(item["expires_at"], "WorkDispatchBinding.expires_at")
    if _parsed_timestamp(expires_at) <= _parsed_timestamp(created_at):
        _fail("WorkDispatchBinding.expires_at must follow created_at")
    provenance = _enum(item["provenance"], "WorkDispatchBinding.provenance", _PROVENANCE)
    observation = _observation(item["observation"], "WorkDispatchBinding.observation")
    if provenance != "AOI_verified" or observation != {"state": "known", "reason": "observed"}:
        _fail("WorkDispatchBinding provenance and observation must be AOI-verified and known")
    unsigned = {key: item[key] for key in fields - {"binding_sha256"}}
    binding_sha256 = _sha256(item["binding_sha256"], "WorkDispatchBinding.binding_sha256")
    if binding_sha256 != company_contract_sha256(unsigned):
        _fail("WorkDispatchBinding.binding_sha256 differs")
    result.update({
        "binding_id": _id(item["binding_id"], "WorkDispatchBinding.binding_id"),
        "transaction_id": _id(item["transaction_id"], "WorkDispatchBinding.transaction_id"),
        "command_id": _id(item["command_id"], "WorkDispatchBinding.command_id"),
        "dispatch_request_id": _id(item["dispatch_request_id"], "WorkDispatchBinding.dispatch_request_id"),
        "dispatch_revision_id": _id(item["dispatch_revision_id"], "WorkDispatchBinding.dispatch_revision_id"),
        "dispatch_payload_sha256": _sha256(item["dispatch_payload_sha256"], "WorkDispatchBinding.dispatch_payload_sha256"),
        "task_id": _id(item["task_id"], "WorkDispatchBinding.task_id"),
        "task_revision_id": _id(item["task_revision_id"], "WorkDispatchBinding.task_revision_id"),
        "task_sha256": _sha256(item["task_sha256"], "WorkDispatchBinding.task_sha256"),
        "packet_id": _id(item["packet_id"], "WorkDispatchBinding.packet_id"),
        "packet_sha256": _sha256(item["packet_sha256"], "WorkDispatchBinding.packet_sha256"),
        "prompt_ref": _available_blob_ref(
            item["prompt_ref"], "WorkDispatchBinding.prompt_ref",
            media_type=WORK_PACKET_PROMPT_MEDIA_TYPE,
        ),
        "context_manifest_ref": _available_blob_ref(
            item["context_manifest_ref"], "WorkDispatchBinding.context_manifest_ref",
            media_type=WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
        ),
        "department_id": _id(item["department_id"], "WorkDispatchBinding.department_id"),
        "target_node_id": _id(item["target_node_id"], "WorkDispatchBinding.target_node_id"),
        "manager_node_id": _id(item["manager_node_id"], "WorkDispatchBinding.manager_node_id"),
        "parent_execution_id": _id(item["parent_execution_id"], "WorkDispatchBinding.parent_execution_id"),
        "delegation_depth": _integer(
            item["delegation_depth"], "WorkDispatchBinding.delegation_depth",
            minimum=1, maximum=MAX_DEPTH,
        ),
        "authority_scope_sha256": _sha256(
            item["authority_scope_sha256"], "WorkDispatchBinding.authority_scope_sha256",
        ),
        "provider_allowlist": _sorted_unique_strings(
            item["provider_allowlist"], "WorkDispatchBinding.provider_allowlist", _id,
            maximum=16,
        ),
        "expires_at": expires_at,
        "created_at": created_at,
        "provenance": provenance,
        "observation": observation,
        "binding_sha256": binding_sha256,
    })
    return result


def validate_work_definition_enforcement(value: Any) -> dict[str, Any]:
    """Validate the immutable opt-in gate for registered work-definition launch."""
    fields = _common_fields({
        "gate_id", "mode", "previous_transaction_sha256", "activated_at",
        "observation", "enforcement_sha256",
    })
    item, result = _base(
        value, WORK_DEFINITION_ENFORCEMENT_V1, fields, "WorkDefinitionEnforcement",
    )
    gate_id = _id(item["gate_id"], "WorkDefinitionEnforcement.gate_id")
    mode = _id(item["mode"], "WorkDefinitionEnforcement.mode")
    observation = _observation(item["observation"], "WorkDefinitionEnforcement.observation")
    if gate_id != "work-definition-enforcement" or mode != "registered_launch_required":
        _fail("WorkDefinitionEnforcement gate and mode are fixed")
    if observation != {"state": "known", "reason": "observed"}:
        _fail("WorkDefinitionEnforcement observation must be known")
    unsigned = {key: item[key] for key in fields - {"enforcement_sha256"}}
    enforcement_sha256 = _sha256(
        item["enforcement_sha256"], "WorkDefinitionEnforcement.enforcement_sha256",
    )
    if enforcement_sha256 != company_contract_sha256(unsigned):
        _fail("WorkDefinitionEnforcement.enforcement_sha256 differs")
    result.update({
        "gate_id": gate_id,
        "mode": mode,
        "previous_transaction_sha256": _sha256(
            item["previous_transaction_sha256"],
            "WorkDefinitionEnforcement.previous_transaction_sha256",
        ),
        "activated_at": _timestamp(item["activated_at"], "WorkDefinitionEnforcement.activated_at"),
        "observation": observation,
        "enforcement_sha256": enforcement_sha256,
    })
    return result


def _absolute_path(value: Any, label: str) -> str:
    """Accept a bounded, explicit Unix or drive-rooted provider path."""
    path = _text(value, label, maximum=MAX_TEXT_BYTES)
    if not (path.startswith("/") or re.match(r"^[A-Za-z]:[\\\\/]", path)):
        _fail(f"{label} must be absolute")
    pieces = re.split(r"[\\\\/]", path)
    if any(piece in {".", ".."} for piece in pieces):
        _fail(f"{label} must not contain traversal")
    return path


def _validate_windows_path_components(components: tuple[str, ...], label: str) -> None:
    """Reject Win32 spellings that lack one durable canonical identity."""
    for component in components:
        if not component or component in {".", ".."}:
            _fail(f"{label} contains an ambiguous Windows path component")
        # There is deliberately no host-filesystem normalization here.
        # Windows accepts several spellings for the same namespace entry; the
        # binding contract has exactly one spelling instead: NFC and Unicode
        # case-folded components.  Reject aliases rather than converting them
        # before hashing.
        if unicodedata.normalize("NFC", component) != component:
            _fail(f"{label} contains a non-canonical Unicode component")
        if component.casefold() != component:
            _fail(f"{label} contains a non-canonical Windows case alias")
        if component.endswith((".", " ")):
            _fail(f"{label} contains a trailing-dot or trailing-space alias")
        # Win32 can resolve a short 8.3 alias (for example, ``progra~1``) to a
        # different long-name component.  Without a durable resolution receipt,
        # such a spelling cannot safely become hash-bound launch evidence.
        if re.fullmatch(r"[^.]+~[0-9]+(?:\.[^.]+)?", component):
            _fail(f"{label} contains an unresolved Windows 8.3 short-name alias")
        if ":" in component:
            _fail(f"{label} must not contain a Windows alternate data stream")
        if any(ord(character) < 32 or character in '<>"|?*' for character in component):
            _fail(f"{label} contains a Windows-invalid path component")
        device_name = unicodedata.normalize("NFKC", component.split(".", 1)[0]).casefold()
        if device_name in _WINDOWS_RESERVED_DEVICE_ALIASES:
            _fail(f"{label} contains a Windows reserved device component")


def _provider_path_filesystem_semantics(*, platform: str, absolute_path: str) -> str:
    """Derive the filesystem semantics used by a validated launch path."""
    if platform == "windows":
        return "windows-win32-v1"
    if platform == "wsl" and re.fullmatch(r"/mnt/[a-z](?:/.*)?", absolute_path):
        return "wsl-windows-drive-mount-v1"
    return "posix-v1"


def _provider_launch_path(value: Any, label: str, *, platform: str) -> str:
    """Validate one platform-native absolute provider launch path."""
    path = _absolute_path(value, label)
    if platform == "windows":
        # Provider launch bindings must never rely on Win32's lossy spelling
        # rules.  The bytes are hash-bound, so accept only the single explicit
        # drive-rooted spelling that can be compared lexically later.
        slash_folded = path.replace("\\", "/").casefold()
        if slash_folded.startswith(("//?/", "//./", "/??/", "/device/")):
            _fail(f"{label} must not use a Windows namespace or device prefix")
        if not re.match(r"^[A-Z]:/", path):
            _fail(f"{label} must use an uppercase drive-rooted Windows spelling")
        remainder = path[3:]
        components = () if not remainder else tuple(remainder.split("/"))
        _validate_windows_path_components(components, label)
        parsed = PureWindowsPath(path)
        if not parsed.is_absolute() or not parsed.drive:
            _fail(f"{label} must be a Windows absolute path")
        canonical = parsed.as_posix()
    else:
        if "\\" in path or PureWindowsPath(path).drive:
            _fail(f"{label} must be a POSIX absolute path")
        parsed_posix = PurePosixPath(path)
        if not parsed_posix.is_absolute():
            _fail(f"{label} must be a POSIX absolute path")
        canonical = str(parsed_posix)
        if platform == "wsl" and (path == "/mnt" or path.startswith("/mnt/")):
            mount = re.fullmatch(r"/mnt/([a-z])(?:/(.*))?", path)
            if mount is None:
                _fail(f"{label} must use an exact lowercase WSL drive mount")
            remainder = mount.group(2)
            components = () if remainder is None else tuple(remainder.split("/"))
            _validate_windows_path_components(components, label)
    if path != canonical:
        _fail(f"{label} must use canonical platform-native spelling")
    return path


def _provider_path_identity_sha256(*, platform: str, absolute_path: str) -> str:
    """Return the versioned, collision-resistant identity of a provider path.

    ``absolute_path`` has already passed ``_provider_launch_path``.  It is
    therefore the only accepted spelling; this hash never silently folds a
    platform path into another spelling before it becomes durable evidence.
    """
    return company_contract_sha256({
        "identity_schema_version": 2,
        "platform": platform,
        "filesystem_semantics": _provider_path_filesystem_semantics(
            platform=platform, absolute_path=absolute_path,
        ),
        "absolute_path": absolute_path,
    })


def _provider_launch_cwd_within_worktree(
    worktree_root: Any,
    launch_cwd: Any,
    *,
    platform: str,
) -> tuple[str, str]:
    """Require lexical cwd containment in the pinned platform path dialect."""
    root = _provider_launch_path(
        worktree_root, "ProviderLaunchBinding.worktree_root", platform=platform,
    )
    cwd = _provider_launch_path(
        launch_cwd, "ProviderLaunchBinding.launch_cwd", platform=platform,
    )
    path_type = PureWindowsPath if platform == "windows" else PurePosixPath
    if not path_type(cwd).is_relative_to(path_type(root)):
        _fail("ProviderLaunchBinding.launch_cwd escapes worktree_root")
    # PurePath containment observes Windows' case-insensitive semantics.  The
    # provider launch binding must additionally preserve the root's exact
    # hash-bound spelling, otherwise separately supplied root/cwd strings can
    # smuggle a case alias through that lexical containment check.
    root_prefix = root if root.endswith("/") else f"{root}/"
    if cwd != root and not cwd.startswith(root_prefix):
        _fail("ProviderLaunchBinding.launch_cwd root prefix spelling differs")
    return root, cwd


def _revision_predecessor(
    item: Mapping[str, Any], label: str,
) -> tuple[int, str]:
    revision = _integer(item["revision"], f"{label}.revision", minimum=1,
                        maximum=999_999_999_999)
    previous = _sha256(item["previous_sha256"], f"{label}.previous_sha256")
    if (revision == 1) != (previous == ZERO_SHA256):
        _fail(f"{label} revision and predecessor differ")
    return revision, previous


def validate_provider_codex_home(value: Any) -> dict[str, Any]:
    """Validate a non-secret revisioned Codex-home policy identity."""
    fields = _common_fields({
        "home_id", "revision", "previous_event_id", "previous_payload_sha256",
        "dispatch_request_id", "platform", "absolute_path", "path_identity_sha256",
        "initial_inventory_sha256", "config_sha256", "managed_config_sha256",
        "thread_config_sha256", "auth_present", "auth_size_bytes", "state",
        "created_at", "updated_at", "observation", "home_sha256",
    })
    item, result = _base(value, PROVIDER_CODEX_HOME_V1, fields, "ProviderCodexHome")
    revision = _integer(item["revision"], "ProviderCodexHome.revision", minimum=1, maximum=999_999_999_999)
    previous_event_id = _nullable_id(item["previous_event_id"], "ProviderCodexHome.previous_event_id")
    previous_payload_sha256 = _sha256(item["previous_payload_sha256"], "ProviderCodexHome.previous_payload_sha256")
    if revision == 1:
        if previous_event_id is not None or previous_payload_sha256 != ZERO_SHA256:
            _fail("genesis ProviderCodexHome predecessor is invalid")
    elif previous_event_id is None or previous_payload_sha256 == ZERO_SHA256:
        _fail("revised ProviderCodexHome predecessor is required")
    observation = _observation(item["observation"], "ProviderCodexHome.observation")
    if observation["state"] != "known":
        _fail("ProviderCodexHome observation must be known")
    auth_present = item["auth_present"]
    if not isinstance(auth_present, bool):
        _fail("ProviderCodexHome.auth_present is invalid")
    auth_size_bytes = _integer(item["auth_size_bytes"], "ProviderCodexHome.auth_size_bytes")
    if (auth_present and auth_size_bytes == 0) or (not auth_present and auth_size_bytes != 0):
        _fail("ProviderCodexHome auth presence and size disagree")
    state = _enum(
        item["state"], "ProviderCodexHome.state",
        frozenset({"ready", "active", "retired", "cleanup_failed"}),
    )
    if state in {"ready", "active"} and not auth_present:
        _fail("ready or active ProviderCodexHome requires auth")
    if state == "retired" and auth_present:
        _fail("retired ProviderCodexHome must not retain auth")
    platform = _enum(
        item["platform"], "ProviderCodexHome.platform",
        frozenset({"windows", "linux", "macos", "wsl"}),
    )
    absolute_path = _provider_launch_path(
        item["absolute_path"], "ProviderCodexHome.absolute_path", platform=platform,
    )
    path_identity_sha256 = _sha256(
        item["path_identity_sha256"], "ProviderCodexHome.path_identity_sha256",
    )
    if path_identity_sha256 != _provider_path_identity_sha256(
        platform=platform, absolute_path=absolute_path,
    ):
        _fail("ProviderCodexHome.path_identity_sha256 differs")
    unsigned = {key: item[key] for key in fields - {"home_sha256"}}
    digest = _sha256(item["home_sha256"], "ProviderCodexHome.home_sha256")
    if digest != company_contract_sha256(unsigned):
        _fail("ProviderCodexHome.home_sha256 differs")
    result.update({
        "home_id": _id(item["home_id"], "ProviderCodexHome.home_id"),
        "revision": revision, "previous_event_id": previous_event_id,
        "previous_payload_sha256": previous_payload_sha256,
        "dispatch_request_id": _id(item["dispatch_request_id"], "ProviderCodexHome.dispatch_request_id"),
        "platform": platform, "absolute_path": absolute_path,
        "path_identity_sha256": path_identity_sha256,
        "initial_inventory_sha256": _sha256(item["initial_inventory_sha256"], "ProviderCodexHome.initial_inventory_sha256"),
        "config_sha256": _sha256(item["config_sha256"], "ProviderCodexHome.config_sha256"),
        "managed_config_sha256": _sha256(item["managed_config_sha256"], "ProviderCodexHome.managed_config_sha256"),
        "thread_config_sha256": _sha256(item["thread_config_sha256"], "ProviderCodexHome.thread_config_sha256"),
        "auth_present": auth_present, "auth_size_bytes": auth_size_bytes,
        "state": state,
        "created_at": _timestamp(item["created_at"], "ProviderCodexHome.created_at"),
        "updated_at": _timestamp(item["updated_at"], "ProviderCodexHome.updated_at"),
        "observation": observation, "home_sha256": digest,
    })
    if _parsed_timestamp(result["updated_at"]) < _parsed_timestamp(result["created_at"]):
        _fail("ProviderCodexHome.updated_at precedes created_at")
    return result


def validate_provider_launch_binding(value: Any) -> dict[str, Any]:
    """Validate every immutable pin required before a provider process exists."""
    fields = _common_fields({
        "launch_binding_id", "work_dispatch_binding_id", "work_dispatch_binding_sha256",
        "dispatch_request_id", "dispatch_revision_id", "dispatch_revision",
        "dispatch_payload_sha256", "route_policy_id", "route_policy_revision",
        "route_policy_sha256", "provider", "model", "effort", "sandbox",
        "worktree_root", "launch_cwd", "executable_path", "executable_sha256",
        "executable_size_bytes", "codex_cli_version", "app_server_version", "app_server_schema_version",
        "branch", "detached", "platform", "lock_domain_id", "git_common_dir_sha256",
        "git_remote_sha256", "git_commit_sha256",
        "manifest_sha256", "repository_sha256", "source_sha256", "config_sha256",
        "dependency_sha256", "home_id", "home_revision", "home_sha256", "created_at",
        "expires_at", "provenance", "observation", "binding_sha256",
    })
    item, result = _base(value, PROVIDER_LAUNCH_BINDING_V1, fields, "ProviderLaunchBinding")
    observation = _observation(item["observation"], "ProviderLaunchBinding.observation")
    if observation["state"] != "known":
        _fail("ProviderLaunchBinding observation must be known")
    if item["provenance"] != "AOI_verified":
        _fail("ProviderLaunchBinding provenance must be AOI_verified")
    detached = item["detached"]
    if not isinstance(detached, bool):
        _fail("ProviderLaunchBinding.detached is invalid")
    branch = _nullable_id(item["branch"], "ProviderLaunchBinding.branch")
    if (detached and branch is not None) or (not detached and branch is None):
        _fail("ProviderLaunchBinding branch and detached disagree")
    unsigned = {key: item[key] for key in fields - {"binding_sha256"}}
    digest = _sha256(item["binding_sha256"], "ProviderLaunchBinding.binding_sha256")
    if digest != company_contract_sha256(unsigned):
        _fail("ProviderLaunchBinding.binding_sha256 differs")
    platform = _enum(item["platform"], "ProviderLaunchBinding.platform", frozenset({"windows", "linux", "macos", "wsl"}))
    worktree_root, launch_cwd = _provider_launch_cwd_within_worktree(
        item["worktree_root"], item["launch_cwd"], platform=platform,
    )
    sandbox = _enum(
        item["sandbox"], "ProviderLaunchBinding.sandbox",
        frozenset({"readOnly", "workspaceWrite"}),
    )
    result.update({
        "launch_binding_id": _id(item["launch_binding_id"], "ProviderLaunchBinding.launch_binding_id"),
        "work_dispatch_binding_id": _id(item["work_dispatch_binding_id"], "ProviderLaunchBinding.work_dispatch_binding_id"),
        "work_dispatch_binding_sha256": _sha256(item["work_dispatch_binding_sha256"], "ProviderLaunchBinding.work_dispatch_binding_sha256"),
        "dispatch_request_id": _id(item["dispatch_request_id"], "ProviderLaunchBinding.dispatch_request_id"),
        "dispatch_revision_id": _id(item["dispatch_revision_id"], "ProviderLaunchBinding.dispatch_revision_id"),
        "dispatch_revision": _integer(item["dispatch_revision"], "ProviderLaunchBinding.dispatch_revision", minimum=1, maximum=999_999_999_999),
        "dispatch_payload_sha256": _sha256(item["dispatch_payload_sha256"], "ProviderLaunchBinding.dispatch_payload_sha256"),
        "route_policy_id": _id(item["route_policy_id"], "ProviderLaunchBinding.route_policy_id"),
        "route_policy_revision": _integer(item["route_policy_revision"], "ProviderLaunchBinding.route_policy_revision", minimum=1, maximum=999_999_999_999),
        "route_policy_sha256": _sha256(item["route_policy_sha256"], "ProviderLaunchBinding.route_policy_sha256"),
        "provider": _id(item["provider"], "ProviderLaunchBinding.provider"),
        "model": _id(item["model"], "ProviderLaunchBinding.model"),
        "effort": _id(item["effort"], "ProviderLaunchBinding.effort"),
        "sandbox": sandbox,
        "worktree_root": worktree_root,
        "launch_cwd": launch_cwd,
        "executable_path": _provider_launch_path(
            item["executable_path"], "ProviderLaunchBinding.executable_path", platform=platform,
        ),
        "executable_sha256": _sha256(item["executable_sha256"], "ProviderLaunchBinding.executable_sha256"),
        "executable_size_bytes": _integer(item["executable_size_bytes"], "ProviderLaunchBinding.executable_size_bytes", minimum=1),
        "codex_cli_version": _text(item["codex_cli_version"], "ProviderLaunchBinding.codex_cli_version", maximum=MAX_SHORT_TEXT_BYTES),
        "app_server_version": _text(item["app_server_version"], "ProviderLaunchBinding.app_server_version", maximum=MAX_SHORT_TEXT_BYTES),
        "app_server_schema_version": _id(item["app_server_schema_version"], "ProviderLaunchBinding.app_server_schema_version"),
        "branch": branch, "detached": detached,
        "platform": platform,
        "lock_domain_id": _id(item["lock_domain_id"], "ProviderLaunchBinding.lock_domain_id"),
        "git_common_dir_sha256": _sha256(item["git_common_dir_sha256"], "ProviderLaunchBinding.git_common_dir_sha256"),
        "git_remote_sha256": _sha256(item["git_remote_sha256"], "ProviderLaunchBinding.git_remote_sha256"),
        "git_commit_sha256": _sha256(item["git_commit_sha256"], "ProviderLaunchBinding.git_commit_sha256"),
        "manifest_sha256": _sha256(item["manifest_sha256"], "ProviderLaunchBinding.manifest_sha256"),
        "repository_sha256": _sha256(item["repository_sha256"], "ProviderLaunchBinding.repository_sha256"),
        "source_sha256": _sha256(item["source_sha256"], "ProviderLaunchBinding.source_sha256"),
        "config_sha256": _sha256(item["config_sha256"], "ProviderLaunchBinding.config_sha256"),
        "dependency_sha256": _sha256(item["dependency_sha256"], "ProviderLaunchBinding.dependency_sha256"),
        "home_id": _id(item["home_id"], "ProviderLaunchBinding.home_id"),
        "home_revision": _integer(item["home_revision"], "ProviderLaunchBinding.home_revision", minimum=1, maximum=999_999_999_999),
        "home_sha256": _sha256(item["home_sha256"], "ProviderLaunchBinding.home_sha256"),
        "created_at": _timestamp(item["created_at"], "ProviderLaunchBinding.created_at"),
        "expires_at": _timestamp(item["expires_at"], "ProviderLaunchBinding.expires_at"),
        "provenance": "AOI_verified", "observation": observation, "binding_sha256": digest,
    })
    if _parsed_timestamp(result["expires_at"]) <= _parsed_timestamp(result["created_at"]):
        _fail("ProviderLaunchBinding.expires_at must follow created_at")
    return result


def validate_provider_worker_io_receipt(value: Any) -> dict[str, Any]:
    """Validate one raw provider I/O observation; no provider claim is inferred."""
    fields = _common_fields({
        "receipt_id", "operation_id", "launch_binding_id", "launch_binding_sha256",
        "dispatch_request_id", "dispatch_revision_id", "execution_id", "thread_id",
        "turn_id", "channel", "phase", "sequence", "method", "request_id",
        "raw_artifact", "observed_at", "provenance", "observation", "receipt_sha256",
    })
    item, result = _base(value, PROVIDER_WORKER_IO_RECEIPT_V1, fields, "ProviderWorkerIOReceipt")
    channel = _enum(item["channel"], "ProviderWorkerIOReceipt.channel", frozenset({"process", "stdin", "stdout", "stderr"}))
    phase = _enum(item["phase"], "ProviderWorkerIOReceipt.phase", frozenset({"process_start_pending", "process_started", "request_send_pending", "response_received", "client_notification_send_pending", "client_notification_written", "notification_received", "host_process_observed", "process_exit_observed", "terminal_sealed"}))
    permitted_phases = {
        "process": frozenset({"process_start_pending", "process_started", "host_process_observed", "process_exit_observed", "terminal_sealed"}),
        "stdin": frozenset({"request_send_pending", "client_notification_send_pending", "client_notification_written"}),
        "stdout": frozenset({"response_received", "notification_received"}),
        "stderr": frozenset({"host_process_observed", "process_exit_observed"}),
    }
    if phase not in permitted_phases[channel]:
        _fail("ProviderWorkerIOReceipt channel and phase disagree")
    method = _nullable_id(item["method"], "ProviderWorkerIOReceipt.method")
    request_id = (
        None if item["request_id"] is None else _integer(
            item["request_id"], "ProviderWorkerIOReceipt.request_id",
            minimum=1, maximum=999_999_999_999,
        )
    )
    if phase == "request_send_pending" and (method is None or request_id is None):
        _fail("request-send receipt requires method and request_id")
    if phase == "response_received" and (method is None or request_id is None):
        _fail("response receipt requires method and request_id")
    if phase in {"client_notification_send_pending", "client_notification_written", "notification_received"} and (method is None or request_id is not None):
        _fail("notification receipt requires only method")
    if phase not in {"request_send_pending", "response_received", "client_notification_send_pending", "client_notification_written", "notification_received"} and (method is not None or request_id is not None):
        _fail("process receipt cannot assert method or request_id")
    observation = _observation(item["observation"], "ProviderWorkerIOReceipt.observation")
    if phase in {"request_send_pending", "response_received"} and method not in _CODEX_APP_SERVER_REQUEST_METHODS:
        _fail("request/response receipt method is outside the pinned App Server request dialect")
    if phase in {"client_notification_send_pending", "client_notification_written"} and method not in _CODEX_APP_SERVER_CLIENT_NOTIFICATION_METHODS:
        _fail("client notification receipt method is outside the pinned App Server dialect")
    if phase == "notification_received" and method not in _CODEX_APP_SERVER_SERVER_NOTIFICATION_METHODS:
        _fail("server notification receipt method is outside the pinned App Server dialect")
    if phase == "terminal_sealed" and (
        item["provenance"] != "adapter_receipt_persisted"
        or observation != {"state": "known", "reason": "observed"}
    ):
        _fail("terminal-sealed receipt requires a known observed adapter receipt")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    digest = _sha256(item["receipt_sha256"], "ProviderWorkerIOReceipt.receipt_sha256")
    if digest != company_contract_sha256(unsigned):
        _fail("ProviderWorkerIOReceipt.receipt_sha256 differs")
    result.update({
        "receipt_id": _id(item["receipt_id"], "ProviderWorkerIOReceipt.receipt_id"),
        "operation_id": _id(item["operation_id"], "ProviderWorkerIOReceipt.operation_id"),
        "launch_binding_id": _id(item["launch_binding_id"], "ProviderWorkerIOReceipt.launch_binding_id"),
        "launch_binding_sha256": _sha256(item["launch_binding_sha256"], "ProviderWorkerIOReceipt.launch_binding_sha256"),
        "dispatch_request_id": _id(item["dispatch_request_id"], "ProviderWorkerIOReceipt.dispatch_request_id"),
        "dispatch_revision_id": _id(item["dispatch_revision_id"], "ProviderWorkerIOReceipt.dispatch_revision_id"),
        "execution_id": _nullable_id(item["execution_id"], "ProviderWorkerIOReceipt.execution_id"),
        "thread_id": _nullable_id(item["thread_id"], "ProviderWorkerIOReceipt.thread_id"),
        "turn_id": _nullable_id(item["turn_id"], "ProviderWorkerIOReceipt.turn_id"),
        "channel": channel, "phase": phase,
        "sequence": _integer(item["sequence"], "ProviderWorkerIOReceipt.sequence", minimum=1, maximum=999_999_999_999),
        "method": method, "request_id": request_id,
        "raw_artifact": _available_blob_ref(item["raw_artifact"], "ProviderWorkerIOReceipt.raw_artifact", media_type=PROVIDER_WORKER_RAW_MEDIA_TYPE),
        "observed_at": _timestamp(item["observed_at"], "ProviderWorkerIOReceipt.observed_at"),
        "provenance": _enum(item["provenance"], "ProviderWorkerIOReceipt.provenance", _PROVIDER_RECEIPT_PROVENANCE),
        "observation": observation, "receipt_sha256": digest,
    })
    return result


def validate_provider_worker_operation(value: Any) -> dict[str, Any]:
    """Validate one no-resend provider operation lifecycle revision."""
    fields = _common_fields({
        "operation_id", "revision", "previous_sha256", "launch_binding_id",
        "launch_binding_sha256", "dispatch_request_id", "dispatch_revision_id",
        "operation_kind", "execution_id", "thread_id", "turn_id", "attempt", "state", "previous_state", "effect_receipt_ids", "result_receipt_id",
        "reconcile_ref", "created_at", "updated_at", "observation", "operation_sha256",
    })
    item, result = _base(value, PROVIDER_WORKER_OPERATION_V1, fields, "ProviderWorkerOperation")
    revision, previous = _revision_predecessor(item, "ProviderWorkerOperation")
    state = _enum(item["state"], "ProviderWorkerOperation.state", frozenset({"prepared", "effect_pending", "effect_observed", "committed", "failed_known", "effect_unknown", "reconcile_required"}))
    previous_state = None if item["previous_state"] is None else _enum(item["previous_state"], "ProviderWorkerOperation.previous_state", frozenset({"prepared", "effect_pending", "effect_observed", "committed", "failed_known", "effect_unknown", "reconcile_required"}))
    allowed = {
        "prepared": frozenset({"effect_pending", "failed_known"}),
        "effect_pending": frozenset({"effect_observed", "failed_known", "effect_unknown"}),
        "effect_observed": frozenset({"committed", "failed_known", "effect_unknown"}),
        "effect_unknown": frozenset({"reconcile_required"}),
    }
    if (revision == 1 and (state != "prepared" or previous_state is not None)) or (revision > 1 and (previous_state is None or state not in allowed.get(previous_state, frozenset()))):
        _fail("ProviderWorkerOperation state transition is invalid")
    effect_receipts = _id_list(item["effect_receipt_ids"], "ProviderWorkerOperation.effect_receipt_ids", maximum=32)
    if effect_receipts != sorted(effect_receipts):
        _fail("ProviderWorkerOperation.effect_receipt_ids must be sorted")
    result_receipt_id = _nullable_id(item["result_receipt_id"], "ProviderWorkerOperation.result_receipt_id")
    reconcile_ref = _nullable_id(item["reconcile_ref"], "ProviderWorkerOperation.reconcile_ref")
    if _integer(item["attempt"], "ProviderWorkerOperation.attempt", minimum=1, maximum=1) != 1:
        _fail("ProviderWorkerOperation attempt must be one")
    if state == "prepared" and (effect_receipts or result_receipt_id is not None or reconcile_ref is not None):
        _fail("prepared ProviderWorkerOperation cannot claim effect")
    if state in {"effect_observed", "committed"} and not effect_receipts:
        _fail("ProviderWorkerOperation observed effect state requires receipts")
    operation_kind = _enum(item["operation_kind"], "ProviderWorkerOperation.operation_kind", frozenset({"process_start", "initialize_request", "initialized_notification", "model_list_request", "thread_start_request", "turn_start_request", "turn_interrupt_request", "turn_observation", "terminal_seal", "result_extraction", "cleanup"}))
    if state == "committed" and operation_kind == "result_extraction" and result_receipt_id is None:
        _fail("committed ProviderWorkerOperation requires a result receipt")
    if (state == "committed" and operation_kind != "result_extraction" and result_receipt_id is not None) or (state != "committed" and result_receipt_id is not None):
        _fail("ProviderWorkerOperation result receipt is invalid for state or kind")
    if state == "reconcile_required" and (result_receipt_id is not None or reconcile_ref is None):
        _fail("effect-unknown ProviderWorkerOperation cannot return or resend")
    if state != "reconcile_required" and reconcile_ref is not None:
        _fail("ProviderWorkerOperation reconcile_ref is invalid")
    unsigned = {key: item[key] for key in fields - {"operation_sha256"}}
    digest = _sha256(item["operation_sha256"], "ProviderWorkerOperation.operation_sha256")
    if digest != company_contract_sha256(unsigned):
        _fail("ProviderWorkerOperation.operation_sha256 differs")
    created_at = _timestamp(item["created_at"], "ProviderWorkerOperation.created_at")
    updated_at = _timestamp(item["updated_at"], "ProviderWorkerOperation.updated_at")
    if _parsed_timestamp(updated_at) < _parsed_timestamp(created_at):
        _fail("ProviderWorkerOperation.updated_at precedes created_at")
    result.update({
        "operation_id": _id(item["operation_id"], "ProviderWorkerOperation.operation_id"),
        "revision": revision, "previous_sha256": previous,
        "launch_binding_id": _id(item["launch_binding_id"], "ProviderWorkerOperation.launch_binding_id"),
        "launch_binding_sha256": _sha256(item["launch_binding_sha256"], "ProviderWorkerOperation.launch_binding_sha256"),
        "dispatch_request_id": _id(item["dispatch_request_id"], "ProviderWorkerOperation.dispatch_request_id"),
        "dispatch_revision_id": _id(item["dispatch_revision_id"], "ProviderWorkerOperation.dispatch_revision_id"),
        "operation_kind": operation_kind,
        "execution_id": _nullable_id(item["execution_id"], "ProviderWorkerOperation.execution_id"),
        "thread_id": _nullable_id(item["thread_id"], "ProviderWorkerOperation.thread_id"),
        "turn_id": _nullable_id(item["turn_id"], "ProviderWorkerOperation.turn_id"),
        "attempt": 1, "state": state, "previous_state": previous_state,
        "effect_receipt_ids": effect_receipts, "result_receipt_id": result_receipt_id,
        "reconcile_ref": reconcile_ref, "created_at": created_at, "updated_at": updated_at,
        "observation": _observation(item["observation"], "ProviderWorkerOperation.observation"),
        "operation_sha256": digest,
    })
    return result


def validate_provider_turn_result(value: Any) -> dict[str, Any]:
    """Validate the exact CAS document without asserting engineering completion."""
    fields = {"document_type", "schema_version", "company_id", "company_incarnation", "lock_domain_generation", "launch_binding_id", "launch_binding_sha256", "operation_id", "agent_execution_id", "turn_execution_id", "thread_id", "turn_id", "terminal_status", "items_view", "availability", "reason", "agent_message_items"}
    item = _object(value, fields, "ProviderTurnResult")
    if item["document_type"] != PROVIDER_TURN_RESULT_V1 or _integer(item["schema_version"], "ProviderTurnResult.schema_version", minimum=1, maximum=1) != 1:
        _fail("ProviderTurnResult header is invalid")
    binding = _embedded_binding(item, "ProviderTurnResult")
    terminal_status = _enum(item["terminal_status"], "ProviderTurnResult.terminal_status", frozenset({"completed", "failed", "interrupted"}))
    items_view = _enum(item["items_view"], "ProviderTurnResult.items_view", frozenset({"not_loaded", "summary"}))
    availability = _enum(item["availability"], "ProviderTurnResult.availability", frozenset({"available", "unavailable"}))
    reason = _text(item["reason"], "ProviderTurnResult.reason", maximum=MAX_SHORT_TEXT_BYTES)
    entries = _bounded_list(item["agent_message_items"], "ProviderTurnResult.agent_message_items", lambda member, _label: member, maximum=128)
    canonical_entries: list[dict[str, Any]] = []
    for index, member in enumerate(entries):
        entry = _object(member, {"sequence", "item_id", "text"}, f"ProviderTurnResult.agent_message_items[{index}]")
        canonical_entries.append({"sequence": _integer(entry["sequence"], "ProviderTurnResult.agent_message_items.sequence", minimum=1), "item_id": _id(entry["item_id"], "ProviderTurnResult.agent_message_items.item_id"), "text": _text(entry["text"], "ProviderTurnResult.agent_message_items.text")})
    if canonical_entries != sorted(canonical_entries, key=lambda entry: entry["sequence"]) or len({entry["sequence"] for entry in canonical_entries}) != len(canonical_entries) or len({entry["item_id"] for entry in canonical_entries}) != len(canonical_entries):
        _fail("ProviderTurnResult agent message items must be sorted and unique")
    if terminal_status == "completed" and items_view == "summary":
        if availability != "available" or reason != "observed" or not canonical_entries:
            _fail("completed ProviderTurnResult summary must be observed and available")
    elif availability != "unavailable" or reason == "observed" or canonical_entries or items_view != "not_loaded":
        _fail("unavailable ProviderTurnResult must be a not-loaded empty summary")
    return {"document_type": PROVIDER_TURN_RESULT_V1, "schema_version": 1, **binding,
            "launch_binding_id": _id(item["launch_binding_id"], "ProviderTurnResult.launch_binding_id"),
            "launch_binding_sha256": _sha256(item["launch_binding_sha256"], "ProviderTurnResult.launch_binding_sha256"),
            "operation_id": _id(item["operation_id"], "ProviderTurnResult.operation_id"),
            "agent_execution_id": _id(item["agent_execution_id"], "ProviderTurnResult.agent_execution_id"),
            "turn_execution_id": _id(item["turn_execution_id"], "ProviderTurnResult.turn_execution_id"),
            "thread_id": _id(item["thread_id"], "ProviderTurnResult.thread_id"),
            "turn_id": _id(item["turn_id"], "ProviderTurnResult.turn_id"),
            "terminal_status": terminal_status, "items_view": items_view,
            "availability": availability, "reason": reason,
            "agent_message_items": canonical_entries}


def canonical_provider_turn_result_bytes(value: Any) -> bytes:
    """Return only valid, exact CAS bytes for one ProviderTurnResult document."""
    return canonical_company_json_bytes(validate_provider_turn_result(value))


def validate_provider_turn_result_receipt(value: Any) -> dict[str, Any]:
    fields = _common_fields({
        "result_receipt_id", "launch_binding_id", "launch_binding_sha256", "operation_id",
        "agent_execution_id", "turn_execution_id", "thread_id", "turn_id", "terminal_io_receipt_id", "result_ref",
        "terminal_status", "result_sha256", "recorded_at", "provenance", "observation", "receipt_sha256",
    })
    item, result = _base(value, PROVIDER_TURN_RESULT_RECEIPT_V1, fields, "ProviderTurnResultReceipt")
    observation = _observation(item["observation"], "ProviderTurnResultReceipt.observation")
    if observation["state"] != "known":
        _fail("ProviderTurnResultReceipt observation must be known")
    result_ref = _available_blob_ref(
        item["result_ref"], "ProviderTurnResultReceipt.result_ref",
        media_type=PROVIDER_TURN_RESULT_MEDIA_TYPE,
    )
    if item["result_sha256"] != result_ref["sha256"]:
        _fail("ProviderTurnResultReceipt.result_sha256 differs from result_ref")
    unsigned = {key: item[key] for key in fields - {"receipt_sha256"}}
    digest = _sha256(item["receipt_sha256"], "ProviderTurnResultReceipt.receipt_sha256")
    if digest != company_contract_sha256(unsigned):
        _fail("ProviderTurnResultReceipt.receipt_sha256 differs")
    result.update({
        "result_receipt_id": _id(item["result_receipt_id"], "ProviderTurnResultReceipt.result_receipt_id"),
        "launch_binding_id": _id(item["launch_binding_id"], "ProviderTurnResultReceipt.launch_binding_id"),
        "launch_binding_sha256": _sha256(item["launch_binding_sha256"], "ProviderTurnResultReceipt.launch_binding_sha256"),
        "operation_id": _id(item["operation_id"], "ProviderTurnResultReceipt.operation_id"),
        "agent_execution_id": _id(item["agent_execution_id"], "ProviderTurnResultReceipt.agent_execution_id"),
        "turn_execution_id": _id(item["turn_execution_id"], "ProviderTurnResultReceipt.turn_execution_id"),
        "thread_id": _id(item["thread_id"], "ProviderTurnResultReceipt.thread_id"),
        "turn_id": _id(item["turn_id"], "ProviderTurnResultReceipt.turn_id"),
        "terminal_io_receipt_id": _id(item["terminal_io_receipt_id"], "ProviderTurnResultReceipt.terminal_io_receipt_id"),
        "result_ref": result_ref,
        "terminal_status": _enum(item["terminal_status"], "ProviderTurnResultReceipt.terminal_status", frozenset({"completed", "failed", "interrupted"})),
        "result_sha256": _sha256(item["result_sha256"], "ProviderTurnResultReceipt.result_sha256"),
        "recorded_at": _timestamp(item["recorded_at"], "ProviderTurnResultReceipt.recorded_at"),
        "provenance": _enum(item["provenance"], "ProviderTurnResultReceipt.provenance", _PROVIDER_RECEIPT_PROVENANCE),
        "observation": observation, "receipt_sha256": digest,
    })
    return result


def validate_company_contract(value: Any) -> dict[str, Any]:
    """Validate one known v0.5 contract and return a detached canonical value."""
    if not isinstance(value, Mapping):
        _fail("company contract type is missing")
    from .contract_registry import contract_validator_for

    contract_type = value.get("contract_type")
    source_type = value.get("source_type")
    document_type = value.get("document_type")
    validator = contract_validator_for(
        contract_type,
        source_type,
        document_type,
    )
    if validator is None:
        _fail("company contract type is unsupported")
    try:
        result = validator(value)
    except CompanyContractError:
        raise
    except ValueError as exc:
        _fail(str(exc))
    _canonical(result, "company contract")
    return result
