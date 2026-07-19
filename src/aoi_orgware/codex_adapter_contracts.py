"""Pure, bounded receipts emitted by the optional Codex hook adapter.

These contracts preserve what the hook actually observed.  They do not turn a
stop event into a completion packet, a cooperative pre-tool decision into a
sandbox guarantee, or a post-tool event into proof of mutation without paired
before/after evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any, NoReturn

from .agent_identity import AgentIdentityError, validate_agent_id
from .semantic_events import SemanticEventError, canonical_sha256


MAX_RECEIPT_BYTES = 64 * 1024
MAX_TARGETS = 64
CODEX_SUBAGENT_STOP_V1 = "codex_subagent_stop_v1"
CODEX_PRETOOL_CLAIM_DECISION_V1 = "codex_pretool_claim_decision_v1"
CODEX_POSTTOOL_MUTATION_OBSERVATION_V1 = "codex_posttool_mutation_observation_v1"

_RECEIPT_TYPES = frozenset(
    {
        CODEX_SUBAGENT_STOP_V1,
        CODEX_PRETOOL_CLAIM_DECISION_V1,
        CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_STOP_IDENTITY_FIELDS = {"session_id", "turn_id", "agent_id", "event_id"}
# Tool receipts correlate the official stable triple only.  ``agent_id`` and
# ``event_id`` are optional attribution/event metadata and can drift between
# the platform's PreToolUse and PostToolUse deliveries.
_TOOL_IDENTITY_FIELDS = {"session_id", "turn_id", "tool_use_id"}
_OBSERVATION_FIELDS = {"status", "value"}
_OBSERVATION_STATUSES = frozenset({"observed", "missing", "invalid_type", "unsafe"})
_START_CORRELATION_STATUSES = frozenset({"matched", "missing", "ambiguous", "mismatch"})
_SESSION_MAPPING_STATUSES = frozenset({"mapped", "missing", "ambiguous", "mismatch"})
_CLAIM_COVERAGE = frozenset({"covered", "unclaimed", "uncovered"})
_DECISIONS = frozenset({"allow", "deny"})

_STOP_FIELDS = {
    "receipt_type",
    "event_identity",
    "observed_at",
    "transcript_path_observation",
    "last_assistant_message",
    "model_observation",
    "permission_mode_observation",
    "start_correlation",
    "no_material_work_verified",
}
_PRE_FIELDS = {
    "receipt_type",
    "event_identity",
    "tool_name",
    "input_sha256",
    "parser",
    "targets",
    "session_mapping",
    "claim_snapshot_sha256",
    "claim_coverage",
    "decision",
    "provider_verification",
    "profile_verification",
    "sandbox_verification",
}
_POST_FIELDS = {
    "receipt_type",
    "event_identity",
    "pre_receipt_sha256",
    "input_sha256",
    "response_sha256",
    "targets",
    "tool_completion_observed",
    "mutation_effect_verified",
}


class CodexAdapterContractError(ValueError):
    """A Codex adapter receipt is malformed, oversized, or tampered."""


def _fail(message: str) -> NoReturn:
    raise CodexAdapterContractError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        _fail(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _timestamp(value: Any) -> str:
    text = _text(value, "observed_at", maximum=64)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise CodexAdapterContractError("observed_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("observed_at needs a timezone")
    return text


def _identity(
    value: Any, fields: set[str], *, strict_agent_id: bool = True
) -> dict[str, str]:
    item = _object(value, fields, "event_identity")
    identity: dict[str, str] = {}
    for field in sorted(fields):
        if field == "agent_id" and strict_agent_id:
            try:
                identity[field] = validate_agent_id(
                    item[field], "event_identity.agent_id"
                )
            except AgentIdentityError as exc:
                raise CodexAdapterContractError(str(exc)) from exc
        else:
            identity[field] = _text(
                item[field], f"event_identity.{field}", maximum=512
            )
    return identity


def _observation(value: Any, label: str, *, sha256: bool = False, decimal: bool = False,
                 presence: bool = False) -> dict[str, str | None]:
    item = _object(value, _OBSERVATION_FIELDS, label)
    status = item["status"]
    observed = status == "observed"
    if not isinstance(status, str) or status not in _OBSERVATION_STATUSES:
        _fail(f"{label}.status is invalid")
    raw = item["value"]
    if observed:
        # Do not stringify a platform number here.  A numeric value must be
        # reported by the adapter as invalid_type with a null value.
        text = _text(raw, f"{label}.value")
        if sha256:
            text = _sha256(text, f"{label}.value")
        if decimal and (not text.isdecimal() or (len(text) > 1 and text.startswith("0"))):
            _fail(f"{label}.value is not canonical decimal text")
        if presence and text not in {"present", "absent"}:
            _fail(f"{label}.value is invalid")
        return {"status": status, "value": text}
    if raw is not None:
        _fail(f"{label}.value must be null unless observed")
    return {"status": status, "value": None}


def _targets(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_TARGETS:
        _fail("targets is invalid")
    targets = [_text(item, "target", maximum=1024) for item in value]
    if targets != sorted(targets) or len(set(targets)) != len(targets):
        _fail("targets must be sorted and unique")
    return targets


def _stop_base(value: Any, *, strict_agent_id: bool = True) -> dict[str, Any]:
    item = _object(value, _STOP_FIELDS, "codex subagent stop receipt")
    if item["receipt_type"] != CODEX_SUBAGENT_STOP_V1:
        _fail("receipt_type is invalid for stop receipt")
    no_material = item["no_material_work_verified"]
    if no_material is not False:
        _fail("no_material_work_verified must be false")
    message = _object(item["last_assistant_message"], {"sha256", "size_bytes", "presence"}, "last_assistant_message")
    correlation = _object(item["start_correlation"], {"status", "start_receipt_sha256"}, "start_correlation")
    status = correlation["status"]
    if not isinstance(status, str) or status not in _START_CORRELATION_STATUSES:
        _fail("start_correlation.status is invalid")
    start_sha = _observation(correlation["start_receipt_sha256"], "start_correlation.start_receipt_sha256", sha256=True)
    if status == "matched" and start_sha["status"] != "observed":
        _fail("matched start correlation needs a start receipt SHA-256")
    if status in {"missing", "ambiguous"} and start_sha["status"] == "observed":
        _fail("unresolved start correlation cannot name one start receipt")
    return {
        "receipt_type": CODEX_SUBAGENT_STOP_V1,
        "event_identity": _identity(
            item["event_identity"],
            _STOP_IDENTITY_FIELDS,
            strict_agent_id=strict_agent_id,
        ),
        "observed_at": _timestamp(item["observed_at"]),
        "transcript_path_observation": _observation(item["transcript_path_observation"], "transcript_path_observation"),
        "last_assistant_message": {
            "sha256": _observation(message["sha256"], "last_assistant_message.sha256", sha256=True),
            "size_bytes": _observation(message["size_bytes"], "last_assistant_message.size_bytes", decimal=True),
            "presence": _observation(message["presence"], "last_assistant_message.presence", presence=True),
        },
        "model_observation": _observation(item["model_observation"], "model_observation"),
        "permission_mode_observation": _observation(item["permission_mode_observation"], "permission_mode_observation"),
        "start_correlation": {"status": status, "start_receipt_sha256": start_sha},
        "no_material_work_verified": False,
    }


def _pre_base(value: Any) -> dict[str, Any]:
    item = _object(value, _PRE_FIELDS, "codex pretool claim decision receipt")
    if item["receipt_type"] != CODEX_PRETOOL_CLAIM_DECISION_V1:
        _fail("receipt_type is invalid for pretool receipt")
    parser = _object(item["parser"], {"id", "version"}, "parser")
    mapping = _object(item["session_mapping"], {"status", "task_id"}, "session_mapping")
    mapping_status = mapping["status"]
    if not isinstance(mapping_status, str) or mapping_status not in _SESSION_MAPPING_STATUSES:
        _fail("session_mapping.status is invalid")
    task_id = _observation(mapping["task_id"], "session_mapping.task_id")
    if mapping_status == "mapped" and task_id["status"] != "observed":
        _fail("mapped session_mapping needs a task id")
    if mapping_status in {"missing", "ambiguous"} and task_id["status"] == "observed":
        _fail("unresolved session_mapping cannot name one task")
    for field in ("provider_verification", "profile_verification", "sandbox_verification"):
        if item[field] != "unavailable":
            _fail(f"{field} must be unavailable")
    coverage = item["claim_coverage"]
    decision = item["decision"]
    if not isinstance(coverage, str) or coverage not in _CLAIM_COVERAGE:
        _fail("claim_coverage is invalid")
    if not isinstance(decision, str) or decision not in _DECISIONS:
        _fail("decision is invalid")
    return {
        "receipt_type": CODEX_PRETOOL_CLAIM_DECISION_V1,
        "event_identity": _identity(item["event_identity"], _TOOL_IDENTITY_FIELDS),
        "tool_name": _text(item["tool_name"], "tool_name", maximum=512),
        "input_sha256": _sha256(item["input_sha256"], "input_sha256"),
        "parser": {"id": _text(parser["id"], "parser.id", maximum=512), "version": _text(parser["version"], "parser.version", maximum=512)},
        "targets": _targets(item["targets"]),
        "session_mapping": {"status": mapping_status, "task_id": task_id},
        "claim_snapshot_sha256": _observation(item["claim_snapshot_sha256"], "claim_snapshot_sha256", sha256=True),
        "claim_coverage": coverage,
        "decision": decision,
        "provider_verification": "unavailable",
        "profile_verification": "unavailable",
        "sandbox_verification": "unavailable",
    }


def _mutation_effect(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        _fail("mutation_effect_verified schema is invalid")
    item = dict(value)
    status = item.get("status")
    if status == "unavailable" and set(item) == {"status"}:
        return {"status": "unavailable"}
    if status == "verified" and set(item) == {"status", "before_sha256", "after_sha256"}:
        before = _sha256(item["before_sha256"], "mutation_effect_verified.before_sha256")
        after = _sha256(item["after_sha256"], "mutation_effect_verified.after_sha256")
        if before == after:
            _fail("mutation_effect_verified before/after evidence must differ")
        return {"status": "verified", "before_sha256": before, "after_sha256": after}
    _fail("mutation_effect_verified must be unavailable or paired before/after evidence")


def _post_base(value: Any) -> dict[str, Any]:
    item = _object(value, _POST_FIELDS, "codex posttool mutation observation receipt")
    if item["receipt_type"] != CODEX_POSTTOOL_MUTATION_OBSERVATION_V1:
        _fail("receipt_type is invalid for posttool receipt")
    completion = item["tool_completion_observed"]
    if not isinstance(completion, bool):
        _fail("tool_completion_observed is invalid")
    return {
        "receipt_type": CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
        "event_identity": _identity(item["event_identity"], _TOOL_IDENTITY_FIELDS),
        "pre_receipt_sha256": _sha256(item["pre_receipt_sha256"], "pre_receipt_sha256"),
        "input_sha256": _sha256(item["input_sha256"], "input_sha256"),
        "response_sha256": _sha256(item["response_sha256"], "response_sha256"),
        "targets": _targets(item["targets"]),
        "tool_completion_observed": completion,
        "mutation_effect_verified": _mutation_effect(item["mutation_effect_verified"]),
    }


def _base(receipt: Any, *, strict_agent_id: bool = True) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        _fail("receipt must be an object")
    receipt_type = receipt.get("receipt_type")
    if receipt_type == CODEX_SUBAGENT_STOP_V1:
        return _stop_base(receipt, strict_agent_id=strict_agent_id)
    if receipt_type == CODEX_PRETOOL_CLAIM_DECISION_V1:
        return _pre_base(receipt)
    if receipt_type == CODEX_POSTTOOL_MUTATION_OBSERVATION_V1:
        return _post_base(receipt)
    _fail("receipt_type is unsupported")


def codex_adapter_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    """Return the canonical hash of one unsealed exact receipt."""

    base = _base(receipt)
    try:
        return canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES)
    except SemanticEventError as exc:
        raise CodexAdapterContractError(str(exc)) from exc


def seal_codex_adapter_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an unsealed receipt and append its deterministic digest."""

    base = _base(receipt)
    try:
        base["receipt_sha256"] = canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES)
    except SemanticEventError as exc:
        raise CodexAdapterContractError(str(exc)) from exc
    return base


def validate_codex_adapter_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed unless one receipt is exact, bounded, and untampered."""

    if not isinstance(receipt, Mapping):
        _fail("receipt must be an object")
    item = dict(receipt)
    receipt_type = item.get("receipt_type")
    if not isinstance(receipt_type, str) or receipt_type not in _RECEIPT_TYPES:
        _fail("receipt_type is unsupported")
    required_fields = {
        CODEX_SUBAGENT_STOP_V1: _STOP_FIELDS,
        CODEX_PRETOOL_CLAIM_DECISION_V1: _PRE_FIELDS,
        CODEX_POSTTOOL_MUTATION_OBSERVATION_V1: _POST_FIELDS,
    }[receipt_type]
    if set(item) != required_fields | {"receipt_sha256"}:
        _fail("sealed receipt schema is invalid")
    supplied = _sha256(item["receipt_sha256"], "receipt_sha256")
    # v1 readers retain compatibility with receipts sealed before the shared
    # agent grammar was enforced.  All current hash/seal writers remain strict.
    base = _base(
        {field: item[field] for field in required_fields}, strict_agent_id=False
    )
    try:
        expected = canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES)
    except SemanticEventError as exc:
        raise CodexAdapterContractError(str(exc)) from exc
    if supplied != expected:
        _fail("receipt_sha256 does not match receipt")
    return {**base, "receipt_sha256": expected}


def _typed_hash(receipt: Mapping[str, Any], receipt_type: str) -> str:
    if receipt.get("receipt_type") != receipt_type:
        _fail("receipt_type is invalid")
    return codex_adapter_receipt_sha256(receipt)


def _typed_seal(receipt: Mapping[str, Any], receipt_type: str) -> dict[str, Any]:
    if receipt.get("receipt_type") != receipt_type:
        _fail("receipt_type is invalid")
    return seal_codex_adapter_receipt(receipt)


def _typed_validate(receipt: Mapping[str, Any], receipt_type: str) -> dict[str, Any]:
    sealed = validate_codex_adapter_receipt(receipt)
    if sealed["receipt_type"] != receipt_type:
        _fail("receipt_type is invalid")
    return sealed


def codex_subagent_stop_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    return _typed_hash(receipt, CODEX_SUBAGENT_STOP_V1)


def seal_codex_subagent_stop_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _typed_seal(receipt, CODEX_SUBAGENT_STOP_V1)


def validate_codex_subagent_stop_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _typed_validate(receipt, CODEX_SUBAGENT_STOP_V1)


def codex_pretool_claim_decision_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    return _typed_hash(receipt, CODEX_PRETOOL_CLAIM_DECISION_V1)


def seal_codex_pretool_claim_decision_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _typed_seal(receipt, CODEX_PRETOOL_CLAIM_DECISION_V1)


def validate_codex_pretool_claim_decision_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _typed_validate(receipt, CODEX_PRETOOL_CLAIM_DECISION_V1)


def codex_posttool_mutation_observation_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    return _typed_hash(receipt, CODEX_POSTTOOL_MUTATION_OBSERVATION_V1)


def seal_codex_posttool_mutation_observation_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _typed_seal(receipt, CODEX_POSTTOOL_MUTATION_OBSERVATION_V1)


def validate_codex_posttool_mutation_observation_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _typed_validate(receipt, CODEX_POSTTOOL_MUTATION_OBSERVATION_V1)
