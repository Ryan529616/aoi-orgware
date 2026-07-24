"""Pure contracts for the optional local Codex App Server transport bridge.

This module intentionally owns no process, socket, credential, or AOI-state
write.  It makes the small v0.4 bridge auditable before a controller is added:
one immutable launch intent, one consumed permit reservation, a hash-chained
journal, and one terminal receipt.  The wire payloads are deliberately absent:
raw prompts, assistant text, and command output never enter these contracts.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal, NoReturn

from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


MAX_CONTRACT_BYTES = 64 * 1024
MAX_JOURNAL_EVENTS = 1024
MAX_TEXT = 512
MAX_CWD_BYTES = 4096
MAX_PROMPT_BYTES = 256 * 1024
MAX_WIRE_PAYLOAD_BYTES = 4 * 1024 * 1024
ZERO_SHA256 = "0" * 64

CODEX_TRANSPORT_LAUNCH_INTENT_V1 = "codex_transport_launch_intent_v1"
CODEX_TRANSPORT_LAUNCH_INTENT_V2 = "codex_transport_launch_intent_v2"
CODEX_LAUNCH_AUTHORITY_V1 = "codex_launch_authority_v1"
CODEX_PACKET_TRANSPORT_OWNERSHIP_V1 = "codex_packet_transport_ownership_v1"
CODEX_TRANSPORT_RESERVATION_V1 = "codex_transport_reservation_v1"
CODEX_TRANSPORT_RESERVATION_V2 = "codex_transport_reservation_v2"
CODEX_TRANSPORT_JOURNAL_EVENT_V1 = "codex_transport_journal_event_v1"
CODEX_TRANSPORT_JOURNAL_EVENT_V2 = "codex_transport_journal_event_v2"
CODEX_TRANSPORT_TERMINAL_RECEIPT_V1 = "codex_transport_terminal_receipt_v1"
CODEX_TRANSPORT_TERMINAL_RECEIPT_V2 = "codex_transport_terminal_receipt_v2"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_STATES = frozenset(
    {
        "reserved",
        "thread_started",
        "turn_started",
        "completed",
        "failed",
        "interrupted",
        "launch_unknown",
        "runtime_unknown",
    }
)
_TERMINAL_STATES = frozenset(
    {"completed", "failed", "interrupted", "launch_unknown", "runtime_unknown"}
)
_EVENT_TYPES = frozenset(
    {
        "reserved",
        "process_start_pending",
        "process_started",
        "initialize_send_pending",
        "initialized",
        "model_list_send_pending",
        "model_list_observed",
        "thread_start_send_pending",
        "thread_started",
        "turn_start_send_pending",
        "turn_started",
        "interrupt_send_pending",
        "interrupt_observed",
        "item_started",
        "item_completed",
        "completed",
        "failed",
        "interrupted",
        "launch_unknown",
        "runtime_unknown",
    }
)
_EVIDENCE_LEVELS = frozenset({"codex_runtime_observed", "verified_mutation"})
_REQUESTED_MODELS = frozenset(
    {
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
        "gpt-5.5",
        "gpt-5.4",
        "gpt-5.4-mini",
        "gpt-5.3-codex-spark",
    }
)
_REQUESTED_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
_SANDBOXES = frozenset({"readOnly", "workspaceWrite"})
_WIRE_METHODS = frozenset(
    {
        "aoi/reservation",
        "process/start",
        "process/started",
        "initialize",
        "initialized",
        "model/list",
        "model/rerouted",
        "thread/start",
        "thread/started",
        "turn/start",
        "turn/started",
        "turn/interrupt",
        "item/started",
        "item/completed",
        "turn/completed",
        "process/exited",
        "runtime/disconnected",
    }
)
_WIRE_STATUSES = frozenset({"observed", "completed", "failed", "interrupted", "unknown"})
_FAULT_KINDS = frozenset(
    {
        "AppServerError",
        "AppServerResponseError",
        "CodexTransportControllerError",
        "ProtocolViolation",
        "ModelCatalogViolation",
        "ModelReroutedViolation",
        "ResponsePolicyViolation",
        "ResponseSchemaViolation",
        "RuntimeDisconnected",
        "ServerRequestDenied",
    }
)
_EVENT_WIRE_METHOD = {
    "reserved": "aoi/reservation",
    "process_start_pending": "process/start",
    "process_started": "process/started",
    "initialize_send_pending": "initialize",
    "initialized": "initialize",
    "model_list_send_pending": "model/list",
    "model_list_observed": "model/list",
    "thread_start_send_pending": "thread/start",
    "thread_started": "thread/start",
    "turn_start_send_pending": "turn/start",
    "turn_started": "turn/start",
    "interrupt_send_pending": "turn/interrupt",
    "interrupt_observed": "turn/interrupt",
    "item_started": "item/started",
    "item_completed": "item/completed",
    "completed": "turn/completed",
    "failed": "process/exited",
    "interrupted": "turn/interrupt",
    "launch_unknown": "thread/start",
    "runtime_unknown": "runtime/disconnected",
}
_EVENT_WIRE_STATUS = {
    "reserved": "observed",
    "process_start_pending": "observed",
    "process_started": "observed",
    "initialize_send_pending": "observed",
    "initialized": "observed",
    "model_list_send_pending": "observed",
    "model_list_observed": "observed",
    "thread_start_send_pending": "observed",
    "thread_started": "observed",
    "turn_start_send_pending": "observed",
    "turn_started": "observed",
    "interrupt_send_pending": "observed",
    "interrupt_observed": "observed",
    "item_started": "observed",
    "item_completed": "completed",
    "completed": "completed",
    "failed": "failed",
    "interrupted": "interrupted",
    "launch_unknown": "unknown",
    "runtime_unknown": "unknown",
}
_INTENT_FIELDS = {
    "contract_type",
    "task_id",
    "packet_id",
    "routing_binding",
    "expected_semantic_head_sha256",
    "prompt_sha256",
    "prompt_size_bytes",
    "cwd",
    "requested_model",
    "requested_effort",
    "sandbox",
    "approval",
    "runtime_pin",
    "pre_git_binding",
}
_INTENT_FIELDS_V2 = _INTENT_FIELDS | {"network_access"}
_LAUNCH_AUTHORITY_FIELDS = {
    "contract_type",
    "task_id",
    "packet_id",
    "packet_contract_sha256",
    "attempt_number",
    "arm_id",
    "armed_at",
    "expires_at",
    "dispatch_attempt_authority_sha256",
    "chief_authority_sha256",
    "parent_session_id",
    "expected_agent_type",
    "routing_binding",
    "expected_semantic_head_sha256",
    "launch_intent_sha256",
}
_PACKET_TRANSPORT_OWNERSHIP_FIELDS = {
    "contract_type",
    "task_id",
    "packet_id",
    "launch_id",
    "arm_id",
    "launch_intent_sha256",
    "permit_sha256",
    "reservation_sha256",
    "launch_authority_sha256",
    "routing_authority_sha256",
    "reservation_effective_at",
    "owner_kind",
}
_RESERVATION_FIELDS = {
    "contract_type",
    "reservation_id",
    "launch_intent_sha256",
    "permit_sha256",
    "runtime_pin",
    "state",
    "correlation",
}
_RESERVATION_FIELDS_V2 = _RESERVATION_FIELDS | {"evidence_level"}
_EVENT_FIELDS = {
    "contract_type",
    "event_id",
    "sequence",
    "prev_event_sha256",
    "launch_intent_sha256",
    "reservation_sha256",
    "event_type",
    "state",
    "wire_method",
    "wire_event_sha256",
    "payload_size_bytes",
    "item_type",
    "status",
    "request_id",
    "request_bytes_sha256",
    "response_sha256",
    "fault_kind",
    "fault_evidence_sha256",
    "fault_evidence_size_bytes",
    "correlation",
}
_EVENT_FIELDS_V2 = _EVENT_FIELDS | {"request_witness"}
_TERMINAL_FIELDS = {
    "contract_type",
    "reservation_sha256",
    "journal_head_sha256",
    "terminal_state",
    "correlation",
    "evidence_level",
    "mutation_verification",
}
_REQUEST_WITNESS_FIELDS = {
    "schema_version",
    "launch_intent_sha256",
    "permit_sha256",
    "expected_semantic_head_sha256",
    "request_id",
    "wire_method",
    "request_envelope_sha256",
    "request_size_bytes",
    "prompt_sha256",
    "prompt_size_bytes",
    "cwd",
    "requested_model",
    "requested_effort",
    "approval",
    "sandbox",
    "network_access",
    "runtime_pin",
    "thread_start_config",
    "correlation",
}
_THREAD_START_CONFIG = {
    "web_search": "disabled",
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
    "apps": {"_default": {"enabled": False}},
}


class CodexTransportContractError(ValueError):
    """A bridge contract is malformed, unpinned, or causally inconsistent."""


@dataclass(frozen=True)
class JournalState:
    state: Literal[
        "reserved",
        "thread_started",
        "turn_started",
        "completed",
        "failed",
        "interrupted",
        "launch_unknown",
        "runtime_unknown",
    ]
    correlation: dict[str, str | None]
    head_sha256: str
    next_sequence: int
    last_event_type: str
    last_request_id: str | None
    last_request_bytes_sha256: str | None


def _fail(message: str) -> NoReturn:
    raise CodexTransportContractError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        _fail(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _optional_sha256(value: Any, label: str) -> str | None:
    return None if value is None else _sha256(value, label)


def _optional_text(value: Any, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _nonnegative_bounded_int(value: Any, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _canonical_hash(value: Mapping[str, Any], label: str) -> str:
    try:
        return canonical_sha256(value, max_bytes=MAX_CONTRACT_BYTES)
    except SemanticEventError as exc:
        raise CodexTransportContractError(f"{label}: {exc}") from exc


def _routing_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("routing_binding schema is invalid")
    item = dict(value)
    kind = item.get("kind")
    common_fields = {
        "kind",
        "routing_authority_sha256",
        "transport",
        "parent_session_id",
        "expected_agent_type",
    }
    if kind == "standalone":
        fields = common_fields
    elif kind == "cohort":
        fields = common_fields | {
            "cohort_id",
            "cohort_sha256",
            "wave_index",
            "transport_slot_sha256",
        }
    else:
        _fail("routing_binding.kind is invalid")
    if set(item) != fields:
        _fail("routing_binding schema is invalid")
    if item["transport"] != "codex":
        _fail("routing_binding.transport must be codex")
    result: dict[str, Any] = {
        "kind": kind,
        "routing_authority_sha256": _sha256(
            item["routing_authority_sha256"],
            "routing_binding.routing_authority_sha256",
        ),
        "transport": "codex",
        "parent_session_id": _text(
            item["parent_session_id"], "routing_binding.parent_session_id"
        ),
        "expected_agent_type": _text(
            item["expected_agent_type"], "routing_binding.expected_agent_type"
        ),
    }
    if kind == "cohort":
        result.update(
            {
                "cohort_id": _text(
                    item["cohort_id"], "routing_binding.cohort_id"
                ),
                "cohort_sha256": _sha256(
                    item["cohort_sha256"], "routing_binding.cohort_sha256"
                ),
                "wave_index": _nonnegative_bounded_int(
                    item["wave_index"],
                    "routing_binding.wave_index",
                    999_999_999,
                ),
                "transport_slot_sha256": _sha256(
                    item["transport_slot_sha256"],
                    "routing_binding.transport_slot_sha256",
                ),
            }
        )
    return result


def validate_routing_binding(value: Any) -> dict[str, Any]:
    """Return one closed standalone/cohort routing binding."""

    return _routing_binding(value)


def _absolute_path(value: Any, label: str, *, maximum: int = MAX_CWD_BYTES) -> str:
    cwd = _text(value, label, maximum=maximum)
    if "\\" in cwd:
        _fail(f"{label} must use canonical slash separators")
    windows = re.fullmatch(r"([A-Z]):/(.*)", cwd)
    if windows is not None:
        tail = windows.group(2)
    elif cwd.startswith("/"):
        tail = cwd[1:]
    else:
        _fail(f"{label} must be an absolute canonical Windows or POSIX path")
    if not tail or cwd.endswith("/") or "//" in cwd:
        _fail(f"{label} is not canonical")
    if any(part in {"", ".", ".."} for part in tail.split("/")):
        _fail(f"{label} is not canonical")
    return cwd


def _cwd(value: Any) -> str:
    return _absolute_path(value, "cwd")


def _bounded_positive_int(value: Any, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _correlation(value: Any, label: str = "correlation") -> dict[str, str | None]:
    item = _object(value, {"thread_id", "turn_id", "item_id"}, label)
    thread_id = item["thread_id"]
    turn_id = item["turn_id"]
    item_id = item["item_id"]
    if thread_id is None:
        if turn_id is not None or item_id is not None:
            _fail(f"{label} cannot name turn/item without thread")
    elif turn_id is None:
        if item_id is not None:
            _fail(f"{label} cannot name item without turn")
    return {
        "thread_id": None if thread_id is None else _text(thread_id, f"{label}.thread_id"),
        "turn_id": None if turn_id is None else _text(turn_id, f"{label}.turn_id"),
        "item_id": None if item_id is None else _text(item_id, f"{label}.item_id"),
    }


def _network_denied(value: Any, label: str = "network_access") -> bool:
    if value is not False:
        _fail(f"{label} must be false")
    return False


def _thread_start_config(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        normalized = json.loads(
            canonical_json_bytes(value, max_bytes=MAX_CONTRACT_BYTES)
        )
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise CodexTransportContractError(
            "request witness thread_start_config is not bounded canonical JSON"
        ) from exc
    if normalized != _THREAD_START_CONFIG:
        _fail("request witness thread_start_config is outside the closed allowlist")
    return normalized


def _runtime_pin_shape(value: Any) -> dict[str, Any]:
    fields = {
        "codex_cli_version",
        "codex_app_server_version",
        "app_server_executable_sha256",
        "schema_manifest_sha256",
        "combined_v2_schema_sha256",
        "executable_path",
        "executable_size_bytes",
    }
    item = _object(value, fields, "runtime_pin")
    result = {
        "codex_cli_version": _text(item["codex_cli_version"], "runtime_pin.codex_cli_version"),
        "codex_app_server_version": _text(item["codex_app_server_version"], "runtime_pin.codex_app_server_version"),
        "app_server_executable_sha256": _sha256(item["app_server_executable_sha256"], "runtime_pin.app_server_executable_sha256"),
        "schema_manifest_sha256": _sha256(item["schema_manifest_sha256"], "runtime_pin.schema_manifest_sha256"),
        "combined_v2_schema_sha256": _sha256(item["combined_v2_schema_sha256"], "runtime_pin.combined_v2_schema_sha256"),
        "executable_path": _absolute_path(item["executable_path"], "runtime_pin.executable_path"),
        "executable_size_bytes": _bounded_positive_int(
            item["executable_size_bytes"], "runtime_pin.executable_size_bytes", 2**63 - 1
        ),
    }
    return result


def _runtime_pin_v1(value: Any) -> dict[str, Any]:
    result = _runtime_pin_shape(value)
    expected = pinned_runtime_binding()
    if {key: result[key] for key in expected} != expected:
        _fail("runtime_pin differs from frozen V1 Codex App Server pin")
    return result


def _runtime_pin_v2(value: Any) -> dict[str, Any]:
    result = _runtime_pin_shape(value)
    expected = pinned_runtime_binding_v2()
    if {key: result[key] for key in expected} != expected:
        _fail(
            "runtime_pin differs from canonical-semantic V2 Codex App Server pin"
        )
    return result


def _pre_git_binding(value: Any) -> dict[str, str]:
    fields = {"git_head_sha256", "git_tree_sha256", "git_status_sha256", "claim_coverage_sha256"}
    item = _object(value, fields, "pre_git_binding")
    return {field: _sha256(item[field], f"pre_git_binding.{field}") for field in sorted(fields)}


def _intent_base(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("launch intent must be an object")
    contract_type = value.get("contract_type")
    if contract_type == CODEX_TRANSPORT_LAUNCH_INTENT_V1:
        fields = _INTENT_FIELDS
    elif contract_type == CODEX_TRANSPORT_LAUNCH_INTENT_V2:
        fields = _INTENT_FIELDS_V2
    else:
        _fail("launch intent contract_type is invalid")
    item = _object(value, fields, "launch intent")
    requested_model = _text(item["requested_model"], "requested_model")
    requested_effort = _text(item["requested_effort"], "requested_effort")
    sandbox = _text(item["sandbox"], "sandbox")
    approval = _text(item["approval"], "approval")
    if requested_model not in _REQUESTED_MODELS:
        _fail("requested_model is not an approved bounded model")
    if requested_effort not in _REQUESTED_EFFORTS:
        _fail("requested_effort is not an approved bounded effort")
    if sandbox not in _SANDBOXES:
        _fail("sandbox is not an approved App Server sandbox")
    if approval != "never":
        _fail("approval must be never for the transport bridge")
    result = {
        "contract_type": contract_type,
        "task_id": _text(item["task_id"], "task_id"),
        "packet_id": _text(item["packet_id"], "packet_id"),
        "routing_binding": _routing_binding(item["routing_binding"]),
        "expected_semantic_head_sha256": _sha256(item["expected_semantic_head_sha256"], "expected_semantic_head_sha256"),
        "prompt_sha256": _sha256(item["prompt_sha256"], "prompt_sha256"),
        "prompt_size_bytes": _bounded_positive_int(item["prompt_size_bytes"], "prompt_size_bytes", MAX_PROMPT_BYTES),
        "cwd": _cwd(item["cwd"]),
        "requested_model": requested_model,
        "requested_effort": requested_effort,
        "sandbox": sandbox,
        "approval": approval,
        "runtime_pin": (
            _runtime_pin_v1(item["runtime_pin"])
            if contract_type == CODEX_TRANSPORT_LAUNCH_INTENT_V1
            else _runtime_pin_v2(item["runtime_pin"])
        ),
        "pre_git_binding": _pre_git_binding(item["pre_git_binding"]),
    }
    if contract_type == CODEX_TRANSPORT_LAUNCH_INTENT_V2:
        result["network_access"] = _network_denied(item["network_access"])
    return result


def launch_intent_sha256(intent: Mapping[str, Any]) -> str:
    """Return the immutable intent hash; permits are deliberately not part of it."""

    return _canonical_hash(_intent_base(intent), "launch intent")


def seal_launch_intent(intent: Mapping[str, Any]) -> dict[str, Any]:
    base = _intent_base(intent)
    return {**base, "intent_sha256": _canonical_hash(base, "launch intent")}


def validate_launch_intent(intent: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(intent, Mapping):
        _fail("sealed launch intent schema is invalid")
    contract_type = intent.get("contract_type")
    fields = (
        _INTENT_FIELDS
        if contract_type == CODEX_TRANSPORT_LAUNCH_INTENT_V1
        else _INTENT_FIELDS_V2
        if contract_type == CODEX_TRANSPORT_LAUNCH_INTENT_V2
        else set()
    )
    if not fields or set(intent) != fields | {"intent_sha256"}:
        _fail("sealed launch intent schema is invalid")
    base = _intent_base({field: intent[field] for field in fields})
    supplied = _sha256(intent["intent_sha256"], "intent_sha256")
    expected = _canonical_hash(base, "launch intent")
    if supplied != expected:
        _fail("intent_sha256 does not match launch intent")
    return {**base, "intent_sha256": expected}


def _launch_authority_base(value: Any) -> dict[str, Any]:
    item = _object(value, _LAUNCH_AUTHORITY_FIELDS, "Codex launch authority")
    if item["contract_type"] != CODEX_LAUNCH_AUTHORITY_V1:
        _fail("Codex launch authority contract_type is invalid")
    attempt_number = item["attempt_number"]
    if (
        not isinstance(attempt_number, int)
        or isinstance(attempt_number, bool)
        or attempt_number < 1
    ):
        _fail("Codex launch authority attempt_number is invalid")
    return {
        "contract_type": CODEX_LAUNCH_AUTHORITY_V1,
        "task_id": _text(item["task_id"], "launch authority task_id"),
        "packet_id": _text(item["packet_id"], "launch authority packet_id"),
        "packet_contract_sha256": _sha256(
            item["packet_contract_sha256"],
            "launch authority packet_contract_sha256",
        ),
        "attempt_number": attempt_number,
        "arm_id": _text(item["arm_id"], "launch authority arm_id"),
        "armed_at": _text(item["armed_at"], "launch authority armed_at"),
        "expires_at": _text(item["expires_at"], "launch authority expires_at"),
        "dispatch_attempt_authority_sha256": _sha256(
            item["dispatch_attempt_authority_sha256"],
            "launch authority dispatch_attempt_authority_sha256",
        ),
        "chief_authority_sha256": _sha256(
            item["chief_authority_sha256"],
            "launch authority chief_authority_sha256",
        ),
        "parent_session_id": _text(
            item["parent_session_id"], "launch authority parent_session_id"
        ),
        "expected_agent_type": _text(
            item["expected_agent_type"], "launch authority expected_agent_type"
        ),
        "routing_binding": _routing_binding(item["routing_binding"]),
        "expected_semantic_head_sha256": _sha256(
            item["expected_semantic_head_sha256"],
            "launch authority expected_semantic_head_sha256",
        ),
        "launch_intent_sha256": _sha256(
            item["launch_intent_sha256"],
            "launch authority launch_intent_sha256",
        ),
    }


def seal_launch_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    """Seal the exact canonical packet arm consumed by one launch intent."""

    base = _launch_authority_base(value)
    return {
        **base,
        "launch_authority_sha256": _canonical_hash(base, "Codex launch authority"),
    }


def validate_launch_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != (
        _LAUNCH_AUTHORITY_FIELDS | {"launch_authority_sha256"}
    ):
        _fail("sealed Codex launch authority schema is invalid")
    base = _launch_authority_base(
        {field: value[field] for field in _LAUNCH_AUTHORITY_FIELDS}
    )
    supplied = _sha256(
        value["launch_authority_sha256"], "launch_authority_sha256"
    )
    expected = _canonical_hash(base, "Codex launch authority")
    if supplied != expected:
        _fail("launch_authority_sha256 does not match Codex launch authority")
    return {**base, "launch_authority_sha256": expected}


def _packet_transport_ownership_base(value: Any) -> dict[str, Any]:
    item = _object(
        value,
        _PACKET_TRANSPORT_OWNERSHIP_FIELDS,
        "Codex packet transport ownership",
    )
    if (
        item["contract_type"] != CODEX_PACKET_TRANSPORT_OWNERSHIP_V1
        or item["owner_kind"] != "codex_app_server_stdio"
    ):
        _fail("Codex packet transport ownership identity is invalid")
    return {
        "contract_type": CODEX_PACKET_TRANSPORT_OWNERSHIP_V1,
        "task_id": _text(item["task_id"], "packet ownership task_id"),
        "packet_id": _text(item["packet_id"], "packet ownership packet_id"),
        "launch_id": _text(item["launch_id"], "packet ownership launch_id"),
        "arm_id": _text(item["arm_id"], "packet ownership arm_id"),
        "launch_intent_sha256": _sha256(
            item["launch_intent_sha256"], "packet ownership launch_intent_sha256"
        ),
        "permit_sha256": _sha256(
            item["permit_sha256"], "packet ownership permit_sha256"
        ),
        "reservation_sha256": _sha256(
            item["reservation_sha256"], "packet ownership reservation_sha256"
        ),
        "launch_authority_sha256": _sha256(
            item["launch_authority_sha256"],
            "packet ownership launch_authority_sha256",
        ),
        "routing_authority_sha256": _sha256(
            item["routing_authority_sha256"],
            "packet ownership routing_authority_sha256",
        ),
        "reservation_effective_at": _text(
            item["reservation_effective_at"],
            "packet ownership reservation_effective_at",
        ),
        "owner_kind": "codex_app_server_stdio",
    }


def seal_packet_transport_ownership(value: Mapping[str, Any]) -> dict[str, Any]:
    """Seal truthful bridge ownership without fabricating a hook observation."""

    base = _packet_transport_ownership_base(value)
    return {
        **base,
        "ownership_sha256": _canonical_hash(
            base, "Codex packet transport ownership"
        ),
    }


def validate_packet_transport_ownership(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != (
        _PACKET_TRANSPORT_OWNERSHIP_FIELDS | {"ownership_sha256"}
    ):
        _fail("sealed Codex packet transport ownership schema is invalid")
    base = _packet_transport_ownership_base(
        {field: value[field] for field in _PACKET_TRANSPORT_OWNERSHIP_FIELDS}
    )
    supplied = _sha256(value["ownership_sha256"], "ownership_sha256")
    expected = _canonical_hash(base, "Codex packet transport ownership")
    if supplied != expected:
        _fail("ownership_sha256 does not match packet transport ownership")
    return {**base, "ownership_sha256": expected}


def _reservation_base(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("reservation receipt must be an object")
    contract_type = value.get("contract_type")
    if contract_type == CODEX_TRANSPORT_RESERVATION_V1:
        fields = _RESERVATION_FIELDS
    elif contract_type == CODEX_TRANSPORT_RESERVATION_V2:
        fields = _RESERVATION_FIELDS_V2
    else:
        _fail("reservation receipt contract_type is invalid")
    item = _object(value, fields, "reservation receipt")
    if item["state"] != "reserved":
        _fail("reservation receipt must be reserved")
    correlation = _correlation(item["correlation"])
    if any(value is not None for value in correlation.values()):
        _fail("reserved receipt cannot name a runtime object")
    result = {
        "contract_type": contract_type,
        "reservation_id": _text(item["reservation_id"], "reservation_id"),
        "launch_intent_sha256": _sha256(item["launch_intent_sha256"], "launch_intent_sha256"),
        "permit_sha256": _sha256(item["permit_sha256"], "permit_sha256"),
        "runtime_pin": (
            _runtime_pin_v1(item["runtime_pin"])
            if contract_type == CODEX_TRANSPORT_RESERVATION_V1
            else _runtime_pin_v2(item["runtime_pin"])
        ),
        "state": "reserved",
        "correlation": correlation,
    }
    if contract_type == CODEX_TRANSPORT_RESERVATION_V2:
        if item["evidence_level"] != "transport_reserved":
            _fail("V2 reservation evidence_level must be transport_reserved")
        result["evidence_level"] = "transport_reserved"
    return result


def reservation_sha256(receipt: Mapping[str, Any]) -> str:
    return _canonical_hash(_reservation_base(receipt), "reservation receipt")


def seal_reservation(receipt: Mapping[str, Any]) -> dict[str, Any]:
    base = _reservation_base(receipt)
    return {**base, "reservation_sha256": _canonical_hash(base, "reservation receipt")}


def validate_reservation(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        _fail("sealed reservation schema is invalid")
    contract_type = receipt.get("contract_type")
    fields = (
        _RESERVATION_FIELDS
        if contract_type == CODEX_TRANSPORT_RESERVATION_V1
        else _RESERVATION_FIELDS_V2
        if contract_type == CODEX_TRANSPORT_RESERVATION_V2
        else set()
    )
    if not fields or set(receipt) != fields | {"reservation_sha256"}:
        _fail("sealed reservation schema is invalid")
    base = _reservation_base({field: receipt[field] for field in fields})
    supplied = _sha256(receipt["reservation_sha256"], "reservation_sha256")
    expected = _canonical_hash(base, "reservation receipt")
    if supplied != expected:
        _fail("reservation_sha256 does not match reservation receipt")
    return {**base, "reservation_sha256": expected}


def validate_reservation_against_intent(
    receipt: Mapping[str, Any], intent: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind the one-shot consumed-permit reservation to its exact launch intent."""

    normalized_receipt = validate_reservation(receipt)
    normalized_intent = validate_launch_intent(intent)
    if normalized_receipt["launch_intent_sha256"] != normalized_intent["intent_sha256"]:
        _fail("reservation does not bind the supplied launch intent")
    if normalized_receipt["runtime_pin"] != normalized_intent["runtime_pin"]:
        _fail("reservation runtime pin does not match launch intent")
    versions = (
        normalized_receipt["contract_type"].rsplit("_", 1)[-1],
        normalized_intent["contract_type"].rsplit("_", 1)[-1],
    )
    if versions[0] != versions[1]:
        _fail("reservation and launch intent contract versions differ")
    return normalized_receipt


def _request_witness_base(value: Any) -> dict[str, Any]:
    item = _object(value, _REQUEST_WITNESS_FIELDS, "request witness")
    if item["schema_version"] != 1:
        _fail("request witness schema_version is invalid")
    method = _text(item["wire_method"], "request witness wire_method")
    if method not in {
        "process/start",
        "initialize",
        "model/list",
        "thread/start",
        "turn/start",
        "turn/interrupt",
    }:
        _fail("request witness wire_method is invalid")
    config = _thread_start_config(item["thread_start_config"])
    if (method == "thread/start") != (config is not None):
        _fail("request witness thread_start_config does not match its method")
    requested_model = _text(
        item["requested_model"], "request witness requested_model"
    )
    requested_effort = _text(
        item["requested_effort"], "request witness requested_effort"
    )
    sandbox = _text(item["sandbox"], "request witness sandbox")
    approval = _text(item["approval"], "request witness approval")
    if requested_model not in _REQUESTED_MODELS:
        _fail("request witness requested_model is invalid")
    if requested_effort not in _REQUESTED_EFFORTS:
        _fail("request witness requested_effort is invalid")
    if sandbox not in _SANDBOXES or approval != "never":
        _fail("request witness sandbox/approval policy is invalid")
    return {
        "schema_version": 1,
        "launch_intent_sha256": _sha256(
            item["launch_intent_sha256"],
            "request witness launch_intent_sha256",
        ),
        "permit_sha256": _sha256(
            item["permit_sha256"], "request witness permit_sha256"
        ),
        "expected_semantic_head_sha256": _sha256(
            item["expected_semantic_head_sha256"],
            "request witness expected_semantic_head_sha256",
        ),
        "request_id": _text(item["request_id"], "request witness request_id"),
        "wire_method": method,
        "request_envelope_sha256": _sha256(
            item["request_envelope_sha256"],
            "request witness request_envelope_sha256",
        ),
        "request_size_bytes": _bounded_positive_int(
            item["request_size_bytes"],
            "request witness request_size_bytes",
            MAX_WIRE_PAYLOAD_BYTES,
        ),
        "prompt_sha256": _sha256(
            item["prompt_sha256"], "request witness prompt_sha256"
        ),
        "prompt_size_bytes": _bounded_positive_int(
            item["prompt_size_bytes"],
            "request witness prompt_size_bytes",
            MAX_PROMPT_BYTES,
        ),
        "cwd": _absolute_path(item["cwd"], "request witness cwd"),
        "requested_model": requested_model,
        "requested_effort": requested_effort,
        "approval": approval,
        "sandbox": sandbox,
        "network_access": _network_denied(
            item["network_access"], "request witness network_access"
        ),
        "runtime_pin": _runtime_pin_shape(item["runtime_pin"]),
        "thread_start_config": config,
        "correlation": _correlation(
            item["correlation"], "request witness correlation"
        ),
    }


def seal_request_witness(value: Mapping[str, Any]) -> dict[str, Any]:
    base = _request_witness_base(value)
    return {
        **base,
        "witness_sha256": _canonical_hash(base, "request witness"),
    }


def validate_request_witness(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != (
        _REQUEST_WITNESS_FIELDS | {"witness_sha256"}
    ):
        _fail("sealed request witness schema is invalid")
    base = _request_witness_base(
        {field: value[field] for field in _REQUEST_WITNESS_FIELDS}
    )
    supplied = _sha256(value["witness_sha256"], "request witness SHA-256")
    expected = _canonical_hash(base, "request witness")
    if supplied != expected:
        _fail("request witness SHA-256 does not match contents")
    return {**base, "witness_sha256": expected}


def validate_request_witness_against_launch(
    value: Mapping[str, Any],
    intent: Mapping[str, Any],
    reservation: Mapping[str, Any],
) -> dict[str, Any]:
    witness = validate_request_witness(value)
    checked_intent = validate_launch_intent(intent)
    checked_reservation = validate_reservation_against_intent(
        reservation, checked_intent
    )
    expected = {
        "launch_intent_sha256": checked_intent["intent_sha256"],
        "permit_sha256": checked_reservation["permit_sha256"],
        "expected_semantic_head_sha256": checked_intent[
            "expected_semantic_head_sha256"
        ],
        "prompt_sha256": checked_intent["prompt_sha256"],
        "prompt_size_bytes": checked_intent["prompt_size_bytes"],
        "cwd": checked_intent["cwd"],
        "requested_model": checked_intent["requested_model"],
        "requested_effort": checked_intent["requested_effort"],
        "approval": checked_intent["approval"],
        "sandbox": checked_intent["sandbox"],
        "network_access": checked_intent.get("network_access"),
        "runtime_pin": checked_intent["runtime_pin"],
    }
    if any(witness[key] != value for key, value in expected.items()):
        _fail("request witness differs from immutable launch policy")
    return witness


def _event_base(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("transport journal event must be an object")
    contract_type = value.get("contract_type")
    if contract_type == CODEX_TRANSPORT_JOURNAL_EVENT_V1:
        fields = _EVENT_FIELDS
    elif contract_type == CODEX_TRANSPORT_JOURNAL_EVENT_V2:
        fields = _EVENT_FIELDS_V2
    else:
        _fail("journal event contract_type is invalid")
    item = _object(value, fields, "transport journal event")
    if not isinstance(item["sequence"], int) or isinstance(item["sequence"], bool) or not 1 <= item["sequence"] <= MAX_JOURNAL_EVENTS:
        _fail("journal event sequence is invalid")
    event_type = item["event_type"]
    state = item["state"]
    if (
        not isinstance(event_type, str)
        or not isinstance(state, str)
        or event_type not in _EVENT_TYPES
        or state not in _STATES
    ):
        _fail("journal event type/state is invalid")
    wire_method = item["wire_method"]
    status = item["status"]
    if not isinstance(wire_method, str) or wire_method not in _WIRE_METHODS:
        _fail("journal wire_method is invalid")
    if not isinstance(status, str) or status not in _WIRE_STATUSES:
        _fail("journal wire status is invalid")
    if event_type == "launch_unknown":
        expected_methods = {"process/start", "thread/start", "turn/start"}
    elif event_type == "failed":
        expected_methods = {
            "process/exited",
            "initialize",
            "model/list",
            "model/rerouted",
            "thread/start",
            "turn/start",
            "turn/interrupt",
            "turn/completed",
        }
    elif event_type == "interrupted":
        expected_methods = {"turn/interrupt", "turn/completed"}
    else:
        expected_methods = {_EVENT_WIRE_METHOD[event_type]}
    if wire_method not in expected_methods or status != _EVENT_WIRE_STATUS[event_type]:
        _fail("journal event wire metadata does not match event type")
    item_type = _optional_text(item["item_type"], "item_type")
    if event_type in {"item_started", "item_completed"} and item_type is None:
        _fail("item event requires item_type")
    if event_type not in {"item_started", "item_completed"} and item_type is not None:
        _fail("non-item event cannot name item_type")
    request_id = _optional_text(item["request_id"], "request_id")
    request_bytes_sha256 = _optional_sha256(item["request_bytes_sha256"], "request_bytes_sha256")
    response_sha256 = _optional_sha256(item["response_sha256"], "response_sha256")
    wire_event_sha256 = _optional_sha256(item["wire_event_sha256"], "wire_event_sha256")
    fault_kind = _optional_text(item["fault_kind"], "fault_kind")
    fault_evidence_sha256 = _optional_sha256(
        item["fault_evidence_sha256"], "fault_evidence_sha256"
    )
    fault_size_value = item["fault_evidence_size_bytes"]
    fault_evidence_size_bytes = (
        None
        if fault_size_value is None
        else _nonnegative_bounded_int(
            fault_size_value,
            "fault_evidence_size_bytes",
            MAX_WIRE_PAYLOAD_BYTES,
        )
    )
    fault_fields = (
        fault_kind,
        fault_evidence_sha256,
        fault_evidence_size_bytes,
    )
    if any(value is not None for value in fault_fields) != all(
        value is not None for value in fault_fields
    ):
        _fail("fault evidence fields must be all present or all absent")
    has_fault = fault_kind is not None
    if has_fault and fault_kind not in _FAULT_KINDS:
        _fail("fault_kind is invalid")
    if has_fault and fault_evidence_size_bytes == 0:
        _fail("fault evidence must bind nonempty bytes")
    if has_fault and event_type not in {"failed", "launch_unknown", "runtime_unknown"}:
        _fail("non-fault event cannot claim fault evidence")
    pending = event_type.endswith("_pending")
    request_bound = pending or event_type == "launch_unknown"
    if request_bound != (request_id is not None and request_bytes_sha256 is not None):
        _fail("request-bound event must have exactly one request id/bytes digest")
    if not request_bound and (request_id is not None or request_bytes_sha256 is not None):
        _fail("non-request event cannot claim request bytes")
    if pending and (
        response_sha256 is not None or wire_event_sha256 is not None or has_fault
    ):
        _fail("send-pending event cannot claim response, event, or fault evidence")
    if event_type == "launch_unknown" and (
        response_sha256 is not None or wire_event_sha256 is not None or not has_fault
    ):
        _fail("launch_unknown requires fault evidence and cannot claim response/event bytes")
    response_events = {
        "initialized",
        "model_list_observed",
        "thread_started",
        "turn_started",
        "interrupt_observed",
    }
    wire_only_events = {
        "process_started",
        "item_started",
        "item_completed",
        "completed",
        "interrupted",
    }
    if event_type in response_events:
        if (
            response_sha256 is None
            or wire_event_sha256 is None
            or response_sha256 != wire_event_sha256
            or has_fault
        ):
            _fail("request response event requires one exact response/wire digest")
    if event_type in wire_only_events:
        if wire_event_sha256 is None or response_sha256 is not None or has_fault:
            _fail("wire observation requires an event digest but no response/fault claim")
    if event_type == "runtime_unknown" and (
        not has_fault or response_sha256 is not None or wire_event_sha256 is not None
    ):
        _fail("runtime_unknown requires fault evidence only")
    if event_type == "failed":
        if wire_method == "turn/completed":
            valid_failed_evidence = (
                wire_event_sha256 is not None
                and response_sha256 is None
                and not has_fault
            )
        elif wire_method == "process/exited":
            valid_failed_evidence = (
                has_fault
                and wire_event_sha256 is None
                and response_sha256 is None
            )
        else:
            exact_error_response = (
                wire_event_sha256 is not None
                and response_sha256 == wire_event_sha256
                and not has_fault
            )
            request_fault = (
                has_fault
                and wire_event_sha256 is None
                and response_sha256 is None
            )
            valid_failed_evidence = exact_error_response or request_fault
        if not valid_failed_evidence:
            _fail("failed event evidence does not match its wire/fault source")
    if event_type == "reserved" and any(
        candidate is not None
        for candidate in (
            request_id,
            request_bytes_sha256,
            response_sha256,
            wire_event_sha256,
            fault_kind,
            fault_evidence_sha256,
            fault_evidence_size_bytes,
        )
    ):
        _fail("reserved event cannot claim wire bytes")
    payload_size_bytes = _nonnegative_bounded_int(
        item["payload_size_bytes"], "payload_size_bytes", MAX_WIRE_PAYLOAD_BYTES
    )
    if event_type == "reserved" and payload_size_bytes != 0:
        _fail("reserved event must have zero wire payload size")
    if event_type != "reserved" and payload_size_bytes == 0:
        _fail("runtime event must bind a nonzero wire payload size")
    if has_fault and payload_size_bytes != fault_evidence_size_bytes:
        _fail("fault payload size differs from fault evidence size")
    request_witness: dict[str, Any] | None = None
    if contract_type == CODEX_TRANSPORT_JOURNAL_EVENT_V2:
        raw_witness = item["request_witness"]
        if request_bound:
            if not isinstance(raw_witness, Mapping):
                _fail("V2 request-bound event requires a sealed request witness")
            request_witness = validate_request_witness(raw_witness)
            if (
                request_witness["launch_intent_sha256"]
                != item["launch_intent_sha256"]
                or request_witness["request_id"] != request_id
                or request_witness["request_envelope_sha256"]
                != request_bytes_sha256
                or request_witness["wire_method"] != wire_method
                or request_witness["correlation"]
                != _correlation(item["correlation"])
            ):
                _fail("V2 request witness does not bind its journal event")
            if pending and request_witness["request_size_bytes"] != payload_size_bytes:
                _fail("V2 request witness size differs from pending event payload")
        elif raw_witness is not None:
            _fail("V2 non-request event cannot carry a request witness")
    result = {
        "contract_type": contract_type,
        "event_id": _text(item["event_id"], "event_id"),
        "sequence": item["sequence"],
        "prev_event_sha256": _sha256(item["prev_event_sha256"], "prev_event_sha256"),
        "launch_intent_sha256": _sha256(item["launch_intent_sha256"], "launch_intent_sha256"),
        "reservation_sha256": _sha256(item["reservation_sha256"], "reservation_sha256"),
        "event_type": event_type,
        "state": state,
        "wire_method": wire_method,
        "wire_event_sha256": wire_event_sha256,
        "payload_size_bytes": payload_size_bytes,
        "item_type": item_type,
        "status": status,
        "request_id": request_id,
        "request_bytes_sha256": request_bytes_sha256,
        "response_sha256": response_sha256,
        "fault_kind": fault_kind,
        "fault_evidence_sha256": fault_evidence_sha256,
        "fault_evidence_size_bytes": fault_evidence_size_bytes,
        "correlation": _correlation(item["correlation"]),
    }
    if contract_type == CODEX_TRANSPORT_JOURNAL_EVENT_V2:
        result["request_witness"] = request_witness
    return result


def journal_event_sha256(event: Mapping[str, Any]) -> str:
    return _canonical_hash(_event_base(event), "transport journal event")


def seal_journal_event(event: Mapping[str, Any]) -> dict[str, Any]:
    base = _event_base(event)
    return {**base, "event_sha256": _canonical_hash(base, "transport journal event")}


def validate_journal_event(event: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        _fail("sealed journal event schema is invalid")
    contract_type = event.get("contract_type")
    fields = (
        _EVENT_FIELDS
        if contract_type == CODEX_TRANSPORT_JOURNAL_EVENT_V1
        else _EVENT_FIELDS_V2
        if contract_type == CODEX_TRANSPORT_JOURNAL_EVENT_V2
        else set()
    )
    if not fields or set(event) != fields | {"event_sha256"}:
        _fail("sealed journal event schema is invalid")
    base = _event_base({field: event[field] for field in fields})
    supplied = _sha256(event["event_sha256"], "event_sha256")
    expected = _canonical_hash(base, "transport journal event")
    if supplied != expected:
        _fail("event_sha256 does not match journal event")
    return {**base, "event_sha256": expected}


def _required_correlation(event_type: str, correlation: Mapping[str, str | None]) -> None:
    thread, turn, item = (correlation["thread_id"], correlation["turn_id"], correlation["item_id"])
    if event_type in {
        "reserved",
        "process_start_pending",
        "process_started",
        "initialize_send_pending",
        "initialized",
        "model_list_send_pending",
        "model_list_observed",
        "thread_start_send_pending",
    }:
        valid = thread is None and turn is None and item is None
    elif event_type in {"thread_started", "turn_start_send_pending"}:
        valid = thread is not None and turn is None and item is None
    elif event_type in {"turn_started", "interrupt_send_pending", "interrupt_observed", "completed", "interrupted"}:
        valid = thread is not None and turn is not None and item is None
    elif event_type in {"item_started", "item_completed"}:
        valid = thread is not None and turn is not None and item is not None
    elif event_type in {"failed", "launch_unknown", "runtime_unknown"}:
        valid = True
    else:
        valid = True
    if not valid:
        _fail(f"{event_type} has invalid runtime correlation")


def previous_event_method(event_type: str) -> str:
    """Return the pinned wire method for one transport journal event type."""

    return _EVENT_WIRE_METHOD[event_type]


def _transition(previous: JournalState | None, event: Mapping[str, Any]) -> JournalState:
    event_type = event["event_type"]
    state = event["state"]
    correlation = event["correlation"]
    _required_correlation(event_type, correlation)
    if previous is None:
        if event_type != "reserved" or state != "reserved" or event["sequence"] != 1 or event["prev_event_sha256"] != ZERO_SHA256:
            _fail("journal must begin with a reserved event")
    else:
        if event["sequence"] != previous.next_sequence or event["prev_event_sha256"] != previous.head_sha256:
            _fail("journal sequence or hash chain is broken")
        if previous.state in _TERMINAL_STATES:
            _fail("terminal journal state cannot transition")
        allowed: dict[str, set[str]] = {
            "reserved": {"process_start_pending", "failed"},
            "process_start_pending": {"process_started", "launch_unknown", "failed"},
            "process_started": {"initialize_send_pending", "failed"},
            "initialize_send_pending": {"initialized", "failed"},
            # Historical v0.4 journals may transition directly from initialize
            # to thread/start.  New controllers always insert the read-only
            # model-list preflight, while the reader keeps old terminal bytes
            # replayable instead of silently reinterpreting them.
            "initialized": {"model_list_send_pending", "thread_start_send_pending", "failed"},
            "model_list_send_pending": {"model_list_observed", "failed"},
            "model_list_observed": {"thread_start_send_pending", "failed"},
            "thread_start_send_pending": {"thread_started", "launch_unknown", "failed"},
            "thread_started": {"turn_start_send_pending", "failed"},
            "turn_start_send_pending": {"turn_started", "launch_unknown", "failed"},
            "turn_started": {
                "item_started", "item_completed", "interrupt_send_pending",
                "completed", "failed", "interrupted", "runtime_unknown",
            },
            "item_started": {
                "item_started", "item_completed", "interrupt_send_pending",
                "completed", "failed", "interrupted", "runtime_unknown",
            },
            "item_completed": {
                "item_started", "interrupt_send_pending", "completed", "failed", "interrupted", "runtime_unknown",
            },
            "interrupt_send_pending": {"interrupt_observed", "failed", "runtime_unknown"},
            "interrupt_observed": {
                "item_started", "item_completed", "completed", "failed",
                "interrupted", "runtime_unknown",
            },
        }
        if event_type not in allowed.get(previous.last_event_type, set()) or state not in _STATES:
            _fail("illegal journal state transition")
        old = previous.correlation
        if event_type in {"failed", "runtime_unknown"} and correlation != old:
            _fail(f"{event_type} must preserve the last known runtime correlation")
        if event_type == "launch_unknown":
            if previous.last_event_type in {"process_start_pending", "thread_start_send_pending"} and correlation != {"thread_id": None, "turn_id": None, "item_id": None}:
                _fail("process/thread start launch_unknown must have no runtime identity")
            if previous.last_event_type == "turn_start_send_pending" and correlation != old:
                _fail("turn/start launch_unknown must preserve only the known thread identity")
            if event["wire_method"] != previous_event_method(previous.last_event_type):
                _fail("launch_unknown must bind the uncertain start request method")
            # The only allowed ambiguity is the exact durable request which
            # preceded a lost response.  A controller must not synthesize a
            # fresh request and call it reconciliation.
            if (
                event["request_id"] != previous.last_request_id
                or event["request_bytes_sha256"] != previous.last_request_bytes_sha256
            ):
                _fail("launch_unknown must bind the exact prior start request")
        for field in ("thread_id", "turn_id"):
            if old[field] is not None and correlation[field] != old[field]:
                _fail(f"journal {field} correlation changed")
        if event_type == "thread_started" and old["thread_id"] is not None:
            _fail("thread_started may occur only once")
        if event_type == "turn_started" and old["turn_id"] is not None:
            _fail("turn_started may occur only once")
    expected_state = {
        "reserved": "reserved",
        "process_start_pending": "reserved",
        "process_started": "reserved",
        "initialize_send_pending": "reserved",
        "initialized": "reserved",
        "model_list_send_pending": "reserved",
        "model_list_observed": "reserved",
        "thread_start_send_pending": "reserved",
        "thread_started": "thread_started",
        "turn_start_send_pending": "thread_started",
        "turn_started": "turn_started",
        "interrupt_send_pending": "turn_started",
        "interrupt_observed": "turn_started",
        "item_started": "turn_started",
        "item_completed": "turn_started",
        "completed": "completed",
        "failed": "failed",
        "interrupted": "interrupted",
        "launch_unknown": "launch_unknown",
        "runtime_unknown": "runtime_unknown",
    }[event_type]
    if state != expected_state:
        _fail("journal event state does not match event type")
    return JournalState(
        state=state,
        correlation=dict(correlation),
        head_sha256=event["event_sha256"],
        next_sequence=event["sequence"] + 1,
        last_event_type=event_type,
        last_request_id=event["request_id"],
        last_request_bytes_sha256=event["request_bytes_sha256"],
    )


def validate_transport_journal(events: Sequence[Mapping[str, Any]]) -> JournalState:
    """Validate a stored unique journal and return its exact state/head."""

    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)) or not events or len(events) > MAX_JOURNAL_EVENTS:
        _fail("transport journal must contain 1..MAX_JOURNAL_EVENTS events")
    state: JournalState | None = None
    event_ids: set[str] = set()
    item_lifecycle: dict[str, str] = {}
    binding: tuple[str, str] | None = None
    journal_contract_type: str | None = None
    last_request_witness_sha256: str | None = None
    for raw in events:
        event = validate_journal_event(raw)
        if journal_contract_type is None:
            journal_contract_type = event["contract_type"]
        elif event["contract_type"] != journal_contract_type:
            _fail("transport journal cannot mix V1 and V2 event contracts")
        if event["event_id"] in event_ids:
            _fail("stored journal contains a duplicate event_id")
        event_ids.add(event["event_id"])
        current_binding = (event["launch_intent_sha256"], event["reservation_sha256"])
        if binding is None:
            binding = current_binding
        elif binding != current_binding:
            _fail("journal event does not bind the same intent/reservation")
        state = _transition(state, event)
        witness = event.get("request_witness")
        if event["event_type"].endswith("_pending"):
            last_request_witness_sha256 = (
                None if witness is None else witness["witness_sha256"]
            )
        elif (
            event["event_type"] == "launch_unknown"
            and event["contract_type"] == CODEX_TRANSPORT_JOURNAL_EVENT_V2
        ):
            if (
                witness is None
                or witness["witness_sha256"] != last_request_witness_sha256
            ):
                _fail(
                    "launch_unknown must preserve the exact pending request witness"
                )
        if event["event_type"] == "item_started":
            item_id = event["correlation"]["item_id"]
            assert item_id is not None
            if item_id in item_lifecycle:
                _fail("journal item_started duplicates item_id")
            item_lifecycle[item_id] = "started"
        elif event["event_type"] == "item_completed":
            item_id = event["correlation"]["item_id"]
            assert item_id is not None
            if item_lifecycle.get(item_id) != "started":
                _fail("journal item_completed has no matching item_started")
            item_lifecycle[item_id] = "completed"
    assert state is not None
    if state.state in {"completed", "failed", "interrupted"} and any(
        status == "started" for status in item_lifecycle.values()
    ):
        _fail("terminal journal cannot leave a lifecycle item started")
    return state


def append_transport_journal_event(
    events: Sequence[Mapping[str, Any]], candidate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Idempotently append one event; same id/different bytes fails closed."""

    candidate_event = validate_journal_event(candidate)
    normalized = [validate_journal_event(event) for event in events]
    for event in normalized:
        if event["event_id"] == candidate_event["event_id"]:
            if event["event_sha256"] == candidate_event["event_sha256"]:
                return normalized
            _fail("duplicate event_id has conflicting bytes")
    if len(normalized) >= MAX_JOURNAL_EVENTS:
        _fail("transport journal exceeds MAX_JOURNAL_EVENTS")
    prior = validate_transport_journal(normalized) if normalized else None
    if prior is None:
        _transition(None, candidate_event)
    else:
        _transition(prior, candidate_event)
        first = normalized[0]
        if (candidate_event["launch_intent_sha256"], candidate_event["reservation_sha256"]) != (first["launch_intent_sha256"], first["reservation_sha256"]):
            _fail("journal event does not bind the same intent/reservation")
    appended = [*normalized, candidate_event]
    validate_transport_journal(appended)
    return appended


def _cas_reference(value: Any, label: str, content_type: str) -> dict[str, str]:
    item = _object(value, {"cas_sha256", "content_type"}, label)
    if item["content_type"] != content_type:
        _fail(f"{label}.content_type is invalid")
    return {
        "cas_sha256": _sha256(item["cas_sha256"], f"{label}.cas_sha256"),
        "content_type": content_type,
    }


def validate_mutation_verification_payload(value: Any) -> dict[str, Any]:
    """Validate only the structural mutation-evidence object.

    CAS references are deliberately opaque here: their materialization,
    snapshot-to-tree checks, and claim coverage review belong to the semantic
    object/Chief boundary.  In particular, identical pre/post tree hashes are
    valid (a verified no-op is still a real observation), and a structurally
    valid hash reference never promotes a task by itself.
    """

    fields = {
        "contract_type",
        "launch_intent_sha256",
        "reservation_sha256",
        "journal_head_sha256",
        "pre_git_snapshot",
        "post_git_snapshot",
        "claim_coverage",
        "pre_git_tree",
        "post_git_tree",
    }
    item = _object(value, fields, "mutation_verification")
    if item["contract_type"] != "codex_mutation_verification_v1":
        _fail("mutation_verification contract_type is invalid")
    return {
        "contract_type": "codex_mutation_verification_v1",
        "launch_intent_sha256": _sha256(item["launch_intent_sha256"], "mutation_verification.launch_intent_sha256"),
        "reservation_sha256": _sha256(item["reservation_sha256"], "mutation_verification.reservation_sha256"),
        "journal_head_sha256": _sha256(item["journal_head_sha256"], "mutation_verification.journal_head_sha256"),
        "pre_git_snapshot": _cas_reference(item["pre_git_snapshot"], "mutation_verification.pre_git_snapshot", "git_snapshot"),
        "post_git_snapshot": _cas_reference(item["post_git_snapshot"], "mutation_verification.post_git_snapshot", "git_snapshot"),
        "claim_coverage": _cas_reference(item["claim_coverage"], "mutation_verification.claim_coverage", "claim_coverage"),
        "pre_git_tree": _cas_reference(item["pre_git_tree"], "mutation_verification.pre_git_tree", "git_tree"),
        "post_git_tree": _cas_reference(item["post_git_tree"], "mutation_verification.post_git_tree", "git_tree"),
    }


def _mutation_verification_reference(
    value: Any, evidence_level: str, terminal_state: str
) -> dict[str, str | None]:
    item = _object(value, {"status", "object_sha256"}, "mutation_verification")
    if evidence_level == "codex_runtime_observed":
        if item != {"status": "unavailable", "object_sha256": None}:
            _fail("runtime-observed evidence cannot assert mutation verification")
        return {"status": "unavailable", "object_sha256": None}
    if terminal_state != "completed" or item.get("status") != "referenced":
        _fail("verified mutation reference requires a completed terminal receipt")
    return {
        "status": "referenced",
        "object_sha256": _sha256(item["object_sha256"], "mutation_verification.object_sha256"),
    }


def _terminal_base(value: Any) -> dict[str, Any]:
    item = _object(value, _TERMINAL_FIELDS, "terminal receipt")
    contract_type = item["contract_type"]
    if contract_type not in {
        CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
        CODEX_TRANSPORT_TERMINAL_RECEIPT_V2,
    }:
        _fail("terminal receipt contract_type is invalid")
    terminal_state = item["terminal_state"]
    evidence_level = item["evidence_level"]
    if (
        not isinstance(terminal_state, str)
        or not isinstance(evidence_level, str)
        or terminal_state not in _TERMINAL_STATES
        or evidence_level not in _EVIDENCE_LEVELS
    ):
        _fail("terminal receipt state/evidence level is invalid")
    correlation = _correlation(item["correlation"])
    if terminal_state == "launch_unknown" and not (
        correlation == {"thread_id": None, "turn_id": None, "item_id": None}
        or (
            correlation["thread_id"] is not None
            and correlation["turn_id"] is None
            and correlation["item_id"] is None
        )
    ):
        _fail("launch_unknown terminal receipt may preserve only a known thread")
    if terminal_state in {"completed", "interrupted"} and (correlation["thread_id"] is None or correlation["turn_id"] is None or correlation["item_id"] is not None):
        _fail("completed/interrupted terminal receipt requires exact thread/turn only")
    if terminal_state == "runtime_unknown" and (
        correlation["thread_id"] is None or correlation["turn_id"] is None
    ):
        _fail("runtime_unknown terminal receipt requires the known thread and turn")
    return {
        "contract_type": contract_type,
        "reservation_sha256": _sha256(item["reservation_sha256"], "reservation_sha256"),
        "journal_head_sha256": _sha256(item["journal_head_sha256"], "journal_head_sha256"),
        "terminal_state": terminal_state,
        "correlation": correlation,
        "evidence_level": evidence_level,
        "mutation_verification": _mutation_verification_reference(
            item["mutation_verification"], evidence_level, terminal_state
        ),
    }


def terminal_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    return _canonical_hash(_terminal_base(receipt), "terminal receipt")


def seal_terminal_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    base = _terminal_base(receipt)
    return {**base, "receipt_sha256": _canonical_hash(base, "terminal receipt")}


def validate_terminal_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping) or set(receipt) != _TERMINAL_FIELDS | {"receipt_sha256"}:
        _fail("sealed terminal receipt schema is invalid")
    base = _terminal_base({field: receipt[field] for field in _TERMINAL_FIELDS})
    supplied = _sha256(receipt["receipt_sha256"], "receipt_sha256")
    expected = _canonical_hash(base, "terminal receipt")
    if supplied != expected:
        _fail("receipt_sha256 does not match terminal receipt")
    return {**base, "receipt_sha256": expected}


def validate_terminal_receipt_against_journal(
    receipt: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Bind a sealed terminal receipt to one sealed, terminal journal.

    A controller may only publish this after it has persisted every runtime
    event it relies upon.  This helper deliberately does not infer task
    completion or a Git mutation from the App Server terminal notification.
    """

    normalized = validate_terminal_receipt(receipt)
    journal = validate_transport_journal(events)
    first = validate_journal_event(events[0])
    expected_terminal_contract = (
        CODEX_TRANSPORT_TERMINAL_RECEIPT_V1
        if first["contract_type"] == CODEX_TRANSPORT_JOURNAL_EVENT_V1
        else CODEX_TRANSPORT_TERMINAL_RECEIPT_V2
    )
    if normalized["contract_type"] != expected_terminal_contract:
        _fail("terminal receipt and journal contract versions differ")
    if normalized["reservation_sha256"] != first["reservation_sha256"]:
        _fail("terminal receipt reservation does not match journal")
    if normalized["journal_head_sha256"] != journal.head_sha256:
        _fail("terminal receipt does not name journal head")
    if normalized["terminal_state"] != journal.state:
        _fail("terminal receipt state does not match journal")
    if normalized["correlation"] != journal.correlation:
        _fail("terminal receipt correlation does not match journal")
    return normalized


def _resource_root() -> Path:
    return Path(__file__).resolve().parent / "resources" / "codex_app_server" / "0.145.0"


_FROZEN_V1_RUNTIME_BINDING: dict[str, str | int] = {
    "codex_cli_version": "codex-cli 0.145.0",
    "codex_app_server_version": "codex-app-server 0.145.0",
    "app_server_executable_sha256": "5163c75ed88d460b35b03c8d8f4ef190b3bdd09971d7ac2bd90b48c435f1cf14",
    "executable_size_bytes": 299117872,
    "schema_manifest_sha256": "6b8bfa74e475c6c9b46926c46f287f47873d188b13ab3df8db4633602db73262",
    "combined_v2_schema_sha256": "6253fd70273c2f33c42d0b6090eac771580c994b3c6eed4277598de08a5e69ec",
}


_PACKAGED_RUNTIME_PIN_0_145_0_V2: dict[str, Any] = {
    "schema_version": 2,
    "release_tag": "rust-v0.145.0",
    "release_url": "https://github.com/openai/codex/releases/tag/rust-v0.145.0",
    "codex_cli_version": "codex-cli 0.145.0",
    "codex_app_server_version": "codex-app-server 0.145.0",
    "app_server_asset": {
        "name": "codex-app-server-x86_64-pc-windows-msvc.exe.zip",
        "size": 98743440,
        "sha256": "dfc57f87b9bc61d1d4503b7a60fbe5bae5f13a5283234c86a4c0da6c97a12961",
        "url": "https://github.com/openai/codex/releases/download/rust-v0.145.0/codex-app-server-x86_64-pc-windows-msvc.exe.zip",
    },
    "app_server_executable": {
        "name": "codex-app-server-x86_64-pc-windows-msvc.exe",
        "size": 299117872,
        "sha256": "5163c75ed88d460b35b03c8d8f4ef190b3bdd09971d7ac2bd90b48c435f1cf14",
    },
    "schema_generator_asset": {
        "name": "codex-x86_64-pc-windows-msvc.exe.zip",
        "size": 119947181,
        "sha256": "bc6ae808bf5a9cdf113364ac281594d6da76dc103c19129e9d32caed54ec3cda",
        "url": "https://github.com/openai/codex/releases/download/rust-v0.145.0/codex-x86_64-pc-windows-msvc.exe.zip",
    },
    "schema_generator_executable": {
        "name": "codex-x86_64-pc-windows-msvc.exe",
        "size": 359245096,
        "sha256": "83751f15cb6a0a7b97df67752c001e3fe1c20e18ffbfec3ff63567296205eb6c",
    },
    "stable_schema": {
        "generator_arguments": ["app-server", "generate-json-schema", "--out", "<fresh-empty-directory>"],
        "experimental": False,
        "file_count": 273,
        "canonicalization": "strict UTF-8 JSON; duplicate keys and non-finite numbers rejected; recursive key sort; compact separators; ASCII escapes; no trailing newline",
        "manifest_format": "canonical-json sorted array of path,sha256,size; sha256 and size bind canonical per-file JSON; POSIX relative paths; ASCII; no trailing newline",
        "manifest_size": 36091,
        "manifest_sha256": "c05875501c6e9a6778cc4afc5488cdb87aae539217121ebbb5c8dd14c79bc025",
        "combined_v2_schema_size": 269688,
        "combined_v2_schema_sha256": "27f8d983f19d8e1a5548d52176de0a460fb05aaf2a72110f913c6f4af2bd4f27",
    },
}
_MAX_PACKAGED_RUNTIME_METADATA_BYTES = 64 * 1024
_MAX_PACKAGED_COMBINED_SCHEMA_BYTES = 1024 * 1024


def _require_exact_packaged_pin(actual: Any, expected: Any, field: str) -> None:
    """Fail closed on every stable-runtime pin value, including scalar types."""

    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or set(actual) != set(expected):
            _fail(f"packaged Codex runtime pin field {field} differs from the stable contract")
        for key, value in expected.items():
            _require_exact_packaged_pin(actual[key], value, f"{field}.{key}")
        return
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            _fail(f"packaged Codex runtime pin field {field} differs from the stable contract")
        for index, value in enumerate(expected):
            _require_exact_packaged_pin(actual[index], value, f"{field}[{index}]")
        return
    if type(actual) is not type(expected) or actual != expected:
        _fail(f"packaged Codex runtime pin field {field} differs from the stable contract")


def _reject_packaged_json_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"packaged Codex runtime metadata has duplicate key {key!r}")
        value[key] = item
    return value


def _reject_packaged_json_constant(value: str) -> None:
    _fail(f"packaged Codex runtime metadata has non-finite number {value}")


def _read_bounded_packaged_resource(
    path: Path, *, maximum_bytes: int, label: str
) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise CodexTransportContractError(
            f"packaged Codex {label} is unreadable"
        ) from exc
    if len(raw) > maximum_bytes:
        _fail(f"packaged Codex {label} exceeds its byte bound")
    return raw


def _validate_packaged_runtime_payload(
    pin_bytes: bytes, manifest_bytes: bytes, combined_bytes: bytes
) -> dict[str, str | int]:
    """Validate bytes shipped with the package; kept public-for-tests in spirit.

    The adapter separately hashes the runtime executable at the absolute path
    in each launch intent.  This function anchors what that executable/schema
    tuple must be, without starting a process.
    """

    expected_app = _PACKAGED_RUNTIME_PIN_0_145_0_V2["app_server_executable"]
    expected_stable = _PACKAGED_RUNTIME_PIN_0_145_0_V2["stable_schema"]
    try:
        pin = json.loads(
            pin_bytes,
            object_pairs_hook=_reject_packaged_json_duplicates,
            parse_constant=_reject_packaged_json_constant,
        )
        manifest = json.loads(
            manifest_bytes,
            object_pairs_hook=_reject_packaged_json_duplicates,
            parse_constant=_reject_packaged_json_constant,
        )
        combined = json.loads(
            combined_bytes,
            object_pairs_hook=_reject_packaged_json_duplicates,
            parse_constant=_reject_packaged_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexTransportContractError("packaged Codex runtime pin is unreadable") from exc
    if canonical_json_bytes(manifest, max_bytes=MAX_CONTRACT_BYTES) != manifest_bytes:
        _fail("schema-manifest.json is not canonical JSON")
    if (
        canonical_json_bytes(
            combined, max_bytes=_MAX_PACKAGED_COMBINED_SCHEMA_BYTES
        )
        != combined_bytes
    ):
        _fail("combined v2 schema is not canonical JSON")
    if not isinstance(pin, Mapping) or not isinstance(manifest, list):
        _fail("packaged Codex runtime pin schema is invalid")
    _require_exact_packaged_pin(
        pin, _PACKAGED_RUNTIME_PIN_0_145_0_V2, "runtime-pin.json"
    )
    if (
        expected_stable["manifest_size"] != len(manifest_bytes)
        or expected_stable["combined_v2_schema_size"] != len(combined_bytes)
        or hashlib.sha256(manifest_bytes).hexdigest() != expected_stable["manifest_sha256"]
        or hashlib.sha256(combined_bytes).hexdigest() != expected_stable["combined_v2_schema_sha256"]
        or len(manifest) != expected_stable["file_count"]
    ):
        _fail("packaged Codex runtime pin/schema digest drifted")
    previous_path: str | None = None
    paths: set[str] = set()
    combined_manifest_entry: Mapping[str, Any] | None = None
    for entry in manifest:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "size", "sha256"}:
            _fail("packaged schema manifest entry is invalid")
        path = entry["path"]
        if (
            not isinstance(path, str) or not path or path.startswith("/") or path.endswith("/")
            or "\\" in path or "//" in path or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            _fail("packaged schema manifest path is invalid")
        if previous_path is not None and path <= previous_path:
            _fail("packaged schema manifest paths are not strictly sorted")
        if path in paths:
            _fail("packaged schema manifest path is duplicated")
        paths.add(path)
        previous_path = path
        if not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] <= 0:
            _fail("packaged schema manifest size is invalid")
        _sha256(entry["sha256"], "packaged schema manifest sha256")
        if path == "codex_app_server_protocol.v2.schemas.json":
            combined_manifest_entry = entry
    if combined_manifest_entry != {
        "path": "codex_app_server_protocol.v2.schemas.json",
        "size": len(combined_bytes),
        "sha256": hashlib.sha256(combined_bytes).hexdigest(),
    }:
        _fail("packaged schema manifest does not bind the combined v2 schema")
    return {
        "codex_cli_version": _PACKAGED_RUNTIME_PIN_0_145_0_V2[
            "codex_cli_version"
        ],
        "codex_app_server_version": _PACKAGED_RUNTIME_PIN_0_145_0_V2[
            "codex_app_server_version"
        ],
        "app_server_executable_sha256": expected_app["sha256"],
        "executable_size_bytes": expected_app["size"],
        "schema_manifest_sha256": expected_stable["manifest_sha256"],
        "combined_v2_schema_sha256": expected_stable["combined_v2_schema_sha256"],
    }


def pinned_runtime_binding() -> dict[str, str | int]:
    """Return the frozen raw-byte runtime identity accepted by V1 readers.

    V1 records are content-addressed and cannot be reinterpreted after the
    discovery that generator object ordering is nondeterministic. New launch
    writers must use :func:`pinned_runtime_binding_v2`.
    """

    return dict(_FROZEN_V1_RUNTIME_BINDING)


def pinned_runtime_binding_v2() -> dict[str, str | int]:
    """Read and verify the canonical-semantic 0.145.0 generated-schema pin.

    This is read-only by design.  It checks the canonical 273-file manifest and
    the combined-v2 schema before returning the only runtime binding accepted by
    new V2 launch-intent and reservation contracts.
    """

    root = _resource_root()
    pin_bytes = _read_bounded_packaged_resource(
        root / "runtime-pin.json",
        maximum_bytes=_MAX_PACKAGED_RUNTIME_METADATA_BYTES,
        label="runtime pin",
    )
    manifest_bytes = _read_bounded_packaged_resource(
        root / "schema-manifest.json",
        maximum_bytes=_MAX_PACKAGED_RUNTIME_METADATA_BYTES,
        label="schema manifest",
    )
    combined_bytes = _read_bounded_packaged_resource(
        root / "codex_app_server_protocol.v2.schemas.json",
        maximum_bytes=_MAX_PACKAGED_COMBINED_SCHEMA_BYTES,
        label="combined schema",
    )
    return _validate_packaged_runtime_payload(pin_bytes, manifest_bytes, combined_bytes)
