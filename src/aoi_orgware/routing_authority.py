"""Pure, sealed dispatch-v6 routing authority records (no filesystem I/O).

The caller must persist ``outcome_slot_sha256`` with compare-and-swap
semantics.  This module supplies deterministic authority, observation, outcome,
and capacity identities; a pure function cannot make a write one-shot.

``build_arm_authority`` accepts the real, byte-bound resource receipt envelope.
It validates the exact receipt once, then seals only its bounded reviewed plan
and digest preimages.  Backup bytes are deliberately not copied into every arm.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Any, Mapping

from .resource_config import resource_plan_sha256, validate_resource_receipt
from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 512 * 1024
MAX_CAPACITY_ROWS = 100_000

_SHA = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}")
_HOOK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}")
_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_PROFILE_PATH = re.compile(r"\.codex/agents/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.toml")

_REQUEST = {
    "requested_role",
    "requested_capability_tier",
    "requested_profile",
    "requested_model",
    "requested_reasoning_effort",
    "requested_sandbox_profile",
}
_EVENT = {
    "integrity_version",
    "event_id",
    "status",
    "plan_sha256",
    "task_plan_sha256",
    "override_id",
    "receipt_path",
    "receipt_sha256",
    "resolved",
    "dynamic_envelope",
    "execution_selection_id",
    "required_locks",
    "restart_required",
    "config_applicability",
    "applicability_basis",
    "inapplicable_acknowledged",
    "root_session_id",
    "applied_at",
    "rollback",
}
_ASSIGNMENT = {
    "capability_tier",
    "profile",
    "model",
    "model_reasoning_effort",
    "profile_source_kind",
    "profile_source_sha256",
}
_PLAN_FILE = {
    "relative_path",
    "before_exists",
    "before_sha256",
    "after_sha256",
    "source_kind",
    "source_sha256",
}
_STARTUP_RECEIPT_BASE = {
    "schema_version",
    "hook_protocol_version",
    "session_id",
    "source",
    "observed_at",
    "cwd",
    "project_root",
    "aoi_config_sha256",
    "observed_resource_files",
    "observed_resource_files_sha256",
}
_STARTUP_RECEIPT_V1_BASE = _STARTUP_RECEIPT_BASE - {
    "observed_resource_files",
    "observed_resource_files_sha256",
}
_REGISTRAR_CHIEF_AUTHORITY = {
    "session_id",
    "epoch",
    "authority_record_sha256",
}
_REGISTRATION_BASE = {
    "registration_schema_version",
    "session_id",
    "task_id",
    "task_plan_sha256",
    "startup_receipt_snapshot",
    "startup_receipt_sha256",
    "resource_config_event_id",
    "resource_event_applied_snapshot",
    "resource_event_applied_sha256",
    "resource_receipt_relative_path",
    "resource_receipt_sha256",
    "resource_plan_sha256",
    "aoi_config_sha256",
    "project_config_sha256",
    "resource_files_manifest_sha256",
    "startup_resource_files_match",
    "task_worktree",
    "config_ancestry_verified",
    "resource_files_verified",
    "startup_resource_state_equivalent",
    "freshness_verdict",
    "config_loaded_verified",
    "registrar_chief_authority",
    "registration_identity_sha256",
    "registered_at",
}
_TERMINAL_TYPED_OUTCOMES_BY_STATUS = {
    "done": {"accepted", "rejected", "no_material_work", "superseded", "unclassified"},
    "failed": {
        "rejected",
        "procedural_failure",
        "transport_failure",
        "no_material_work",
        "unclassified",
    },
    "cancelled": {
        "cancelled",
        "procedural_failure",
        "superseded",
        "no_material_work",
        "unclassified",
    },
}
_TECHNICAL_OUTCOMES = {"accepted", "rejected"}


class RoutingAuthorityError(ValueError):
    """A bounded v6 routing authority, observation, or outcome is invalid."""


def _fail(message: str) -> None:
    raise RoutingAuthorityError(message)


def _canonical(value: Any, *, max_bytes: int = MAX_RECORD_BYTES) -> bytes:
    try:
        return canonical_json_bytes(value, max_bytes=max_bytes)
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise RoutingAuthorityError(str(exc)) from exc


def _clone(value: Any, *, max_bytes: int = MAX_RECORD_BYTES) -> Any:
    return json.loads(_canonical(value, max_bytes=max_bytes).decode("utf-8"))


def _plain_copy(value: Any) -> Any:
    """Break benign caller aliasing before sealing a JSON record."""
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise RoutingAuthorityError("authority input is not serializable JSON") from exc


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _hook_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HOOK_ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _dt(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        _fail(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise RoutingAuthorityError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"{label} needs a timezone")
    return parsed


def _text(
    value: Any,
    label: str,
    *,
    empty: bool = False,
    limit: int = 128,
    strip: bool = True,
) -> str:
    if (
        not isinstance(value, str)
        or len(value) > limit
        or "\x00" in value
        or (strip and value != value.strip())
        or (not empty and not value)
    ):
        _fail(f"{label} is invalid")
    return value


def _request(value: Any) -> dict[str, str]:
    item = _object(value, _REQUEST, "requested routing")
    result = {key: _text(item[key], key) for key in _REQUEST}
    if result["requested_sandbox_profile"] != "unavailable":
        _fail("requested sandbox profile must be unavailable")
    return result


def _snapshot(value: Any, label: str) -> dict[str, Any]:
    item = _object(value, {"snapshot", "snapshot_sha256"}, label)
    _sha(item["snapshot_sha256"], f"{label} snapshot sha256")
    if canonical_sha256(item["snapshot"], max_bytes=MAX_RECORD_BYTES) != item["snapshot_sha256"]:
        _fail(f"{label} snapshot hash mismatch")
    return item


def _receipt_file_sha(receipt: Mapping[str, Any]) -> str:
    # commands.resource publishes this exact pretty-printed payload.
    payload = (json.dumps(receipt, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _relative_receipt_path(event_id: str) -> str:
    return f"results/resource-config-{event_id}.json"


def _event_path_matches(path: Any, relative: str) -> bool:
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    normalized = path.replace("\\", "/")
    return normalized == relative or normalized.endswith("/" + relative)


def _resource_event(value: Any) -> dict[str, Any]:
    event = _object(value, _EVENT, "resource event snapshot")
    if (
        event["integrity_version"] != 1
        or event["status"] != "applied"
        or event["rollback"] is not None
        or event["restart_required"] is not True
        or event["config_applicability"] != "applicable"
        or event["inapplicable_acknowledged"] is not False
    ):
        _fail("resource event is not an applicable non-rollback applied event")
    _id(event["event_id"], "resource event id")
    _sha(event["plan_sha256"], "resource plan sha256")
    _sha(event["task_plan_sha256"], "resource task plan sha256")
    _sha(event["receipt_sha256"], "resource event receipt sha256")
    _hook_id(event["root_session_id"], "resource root session id")
    _dt(event["applied_at"], "resource applied_at")
    _text(event["receipt_path"], "resource receipt path", limit=4096, strip=False)
    _text(event["applicability_basis"], "resource applicability basis", limit=4096)
    for key in ("override_id", "execution_selection_id"):
        if event[key] != "":
            _id(event[key], key)
    if not isinstance(event["dynamic_envelope"], dict):
        _fail("resource event dynamic envelope is invalid")
    locks = event["required_locks"]
    if not isinstance(locks, list) or not locks or len(locks) > 65:
        _fail("resource event required locks are invalid")
    seen_locks: set[str] = set()
    for lock in locks:
        _text(lock, "resource event required lock", limit=512)
        if lock in seen_locks:
            _fail("resource event required locks are invalid")
        seen_locks.add(lock)
    return event


def _assignments(event: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    resolved = event["resolved"]
    if not isinstance(resolved, dict) or set(resolved) != {"max_threads", "max_depth", "agents"}:
        _fail("resource event resolved view is invalid")
    if (
        isinstance(resolved["max_threads"], bool)
        or not isinstance(resolved["max_threads"], int)
        or not 1 <= resolved["max_threads"] <= 12
    ):
        _fail("resource event max_threads is invalid")
    if resolved["max_depth"] not in {1, 2}:
        _fail("resource event max_depth is invalid")
    agents = resolved["agents"]
    if not isinstance(agents, dict) or not agents or len(agents) > 64:
        _fail("resource event assignments are invalid")
    output: dict[str, dict[str, Any]] = {}
    for role, assignment in agents.items():
        _id(role, "resource event role")
        data = _object(assignment, _ASSIGNMENT, "resource event agent assignment")
        _text(data["capability_tier"], "capability tier")
        if not isinstance(data["profile"], str) or not _PROFILE.fullmatch(data["profile"]):
            _fail("profile is invalid")
        _text(data["model"], "model", limit=128)
        _text(data["model_reasoning_effort"], "model reasoning effort")
        if data["profile_source_kind"] not in {"project", "user_template"}:
            _fail("profile source kind is invalid")
        _sha(data["profile_source_sha256"], "profile source sha256")
        output[role] = data
    return output


def _plan_files(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = plan.get("files")
    if not isinstance(raw, list) or not raw or len(raw) > 64:
        _fail("resource plan file view is invalid")
    records: dict[str, dict[str, Any]] = {}
    for candidate in raw:
        record = _object(candidate, _PLAN_FILE, "resource plan file")
        relative = record["relative_path"]
        if not isinstance(relative, str) or not (
            relative == ".codex/config.toml" or _PROFILE_PATH.fullmatch(relative)
        ):
            _fail("resource plan file path is invalid")
        if relative in records:
            _fail("resource plan repeats a file path")
        if not isinstance(record["before_exists"], bool):
            _fail("resource plan before_exists is invalid")
        for key in ("before_sha256", "after_sha256", "source_sha256"):
            _sha(record[key], f"resource plan {key}")
        if record["source_kind"] not in {"generated", "project", "user_template"}:
            _fail("resource plan source kind is invalid")
        records[relative] = record
    return records


def resource_files_manifest_sha256(plan: Mapping[str, Any]) -> str:
    """Hash the exact post-apply path/byte identities a startup must verify."""
    records = _plan_files(plan)
    view = [
        {"relative_path": path, "after_sha256": records[path]["after_sha256"]}
        for path in sorted(records)
    ]
    return canonical_sha256(view, max_bytes=MAX_RECORD_BYTES)


def _resource_file_identities(
    value: Any, *, label: str, allow_empty: bool
) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 64 or (not allow_empty and not value):
        _fail(f"{label} is invalid")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for candidate in value:
        item = _object(
            candidate,
            {"relative_path", "after_sha256"},
            f"{label} file",
        )
        relative = item["relative_path"]
        if not isinstance(relative, str) or not (
            relative == ".codex/config.toml" or _PROFILE_PATH.fullmatch(relative)
        ):
            _fail(f"{label} path is invalid")
        if relative in seen:
            _fail(f"{label} repeats a path")
        seen.add(relative)
        _sha(item["after_sha256"], f"{label} file sha256")
        records.append(
            {
                "relative_path": relative,
                "after_sha256": item["after_sha256"],
            }
        )
    if [item["relative_path"] for item in records] != sorted(seen):
        _fail(f"{label} paths are not canonical")
    return records


def startup_resource_files_match(
    startup_receipt: Mapping[str, Any], plan: Mapping[str, Any]
) -> list[dict[str, str]]:
    """Return the exact reviewed file identities observed at SessionStart.

    The startup hook snapshots every managed project resource file.  A plan can
    govern a subset of that tree, so registration extracts the reviewed subset
    and fails closed if even one planned after-image was absent or different.
    """

    startup = _startup_receipt(_plain_copy(startup_receipt))
    records = _plan_files(plan)
    expected = [
        {
            "relative_path": relative,
            "after_sha256": records[relative]["after_sha256"],
        }
        for relative in sorted(records)
    ]
    observed = {
        item["relative_path"]: item["after_sha256"]
        for item in startup["observed_resource_files"]
    }
    if any(
        observed.get(item["relative_path"]) != item["after_sha256"]
        for item in expected
    ):
        _fail(
            "startup receipt did not observe the reviewed resource file after-images"
        )
    return expected


def _validate_real_receipt_input(
    envelope: Any,
    event: Mapping[str, Any],
    packet: Mapping[str, Any],
) -> dict[str, Any]:
    item = _object(
        envelope,
        {"receipt", "receipt_relative_path", "receipt_file_sha256"},
        "resource receipt envelope",
    )
    receipt = item["receipt"]
    if not isinstance(receipt, dict):
        _fail("resource receipt payload is invalid")
    try:
        validate_resource_receipt(receipt)
    except Exception as exc:
        raise RoutingAuthorityError(
            f"resource receipt is not a real make_resource_receipt payload: {exc}"
        ) from exc
    event_id = event["event_id"]
    if item["receipt_relative_path"] != _relative_receipt_path(event_id):
        _fail("resource receipt relative path is invalid")
    _sha(item["receipt_file_sha256"], "resource receipt file sha256")
    if _receipt_file_sha(receipt) != item["receipt_file_sha256"]:
        _fail("resource receipt exact file SHA-256 is invalid")
    plan = receipt["plan"]
    if (
        receipt["event_id"] != event_id
        or receipt["task_id"] != packet["task_id"]
        or receipt["plan_sha256"] != event["plan_sha256"]
        or resource_plan_sha256(plan) != receipt["plan_sha256"]
        or event["receipt_sha256"] != item["receipt_file_sha256"]
        or not _event_path_matches(event["receipt_path"], item["receipt_relative_path"])
        or receipt["applied_at"] != event["applied_at"]
        or receipt["root_session_id"] != event["root_session_id"]
        or receipt["restart_required"] is not True
    ):
        _fail("resource receipt and event are not cross-bound")
    return receipt


def _compact_receipt_authority(
    envelope: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    plan = _plain_copy(receipt["plan"])
    return {
        "receipt_relative_path": envelope["receipt_relative_path"],
        "receipt_file_sha256": envelope["receipt_file_sha256"],
        "event_id": receipt["event_id"],
        "task_id": receipt["task_id"],
        "plan_sha256": receipt["plan_sha256"],
        "root_session_id": receipt["root_session_id"],
        "applied_at": receipt["applied_at"],
        "restart_required": receipt["restart_required"],
        "plan_snapshot": plan,
        "plan_snapshot_sha256": canonical_sha256(plan, max_bytes=MAX_RECORD_BYTES),
    }


def _receipt_authority(
    value: Any,
    event: Mapping[str, Any],
    packet: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    fields = {
        "receipt_relative_path",
        "receipt_file_sha256",
        "event_id",
        "task_id",
        "plan_sha256",
        "root_session_id",
        "applied_at",
        "restart_required",
        "plan_snapshot",
        "plan_snapshot_sha256",
    }
    item = _object(value, fields, "compact resource receipt authority")
    _sha(item["receipt_file_sha256"], "compact receipt file sha256")
    _sha(item["plan_sha256"], "compact receipt plan sha256")
    _sha(item["plan_snapshot_sha256"], "compact receipt plan snapshot sha256")
    plan = item["plan_snapshot"]
    if not isinstance(plan, dict):
        _fail("compact receipt plan snapshot is invalid")
    if (
        canonical_sha256(plan, max_bytes=MAX_RECORD_BYTES) != item["plan_snapshot_sha256"]
        or resource_plan_sha256(plan) != item["plan_sha256"]
        or plan.get("plan_sha256") != item["plan_sha256"]
    ):
        _fail("compact receipt plan hash is invalid")
    _sha(plan.get("aoi_config_sha256"), "resource plan AOI config sha256")
    files = _plan_files(plan)
    if (
        item["receipt_relative_path"] != _relative_receipt_path(event["event_id"])
        or item["receipt_file_sha256"] != event["receipt_sha256"]
        or not _event_path_matches(event["receipt_path"], item["receipt_relative_path"])
        or item["event_id"] != event["event_id"]
        or item["task_id"] != packet["task_id"]
        or item["plan_sha256"] != event["plan_sha256"]
        or item["root_session_id"] != event["root_session_id"]
        or item["applied_at"] != event["applied_at"]
        or item["restart_required"] is not True
        or plan.get("event_id") != event["event_id"]
        or plan.get("task_id") != packet["task_id"]
        or plan.get("approved_task_plan_sha256") != packet["task_plan_sha256"]
        or plan.get("resolved") != event["resolved"]
        or plan.get("dynamic_envelope") != event["dynamic_envelope"]
        or plan.get("override_id", "") != event["override_id"]
        or plan.get("required_locks") != event["required_locks"]
        or plan.get("restart_required") is not True
        or plan.get("config_applicability") != "applicable"
        or plan.get("applicability_basis") != event["applicability_basis"]
    ):
        _fail("compact receipt authority is not the exact event/packet preimage")
    selection = event["dynamic_envelope"].get("execution_selection_id", "")
    if event["execution_selection_id"] != selection:
        _fail("resource event execution selection is not its envelope selection")
    return item, files


def seal_startup_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Seal the task-independent receipt emitted by SessionStart(source=startup)."""
    base = _object(
        _plain_copy(receipt),
        _STARTUP_RECEIPT_BASE,
        "unsealed startup receipt",
    )
    sealed = {
        **base,
        "startup_receipt_sha256": canonical_sha256(base, max_bytes=MAX_RECORD_BYTES),
    }
    return _startup_receipt(sealed)


def _startup_receipt(value: Any) -> dict[str, Any]:
    item = _object(
        value,
        _STARTUP_RECEIPT_BASE | {"startup_receipt_sha256"},
        "startup receipt",
    )
    if item["schema_version"] != 2 or item["hook_protocol_version"] != 6:
        _fail("startup receipt version is unsupported")
    _hook_id(item["session_id"], "startup session id")
    if item["source"] != "startup":
        _fail("only a fresh startup may produce a startup receipt")
    _dt(item["observed_at"], "startup observed_at")
    _text(item["cwd"], "startup cwd", limit=4096, strip=False)
    _text(item["project_root"], "startup project root", limit=4096, strip=False)
    _sha(item["aoi_config_sha256"], "startup AOI config sha256")
    observed = _resource_file_identities(
        item["observed_resource_files"],
        label="startup observed resource files",
        allow_empty=True,
    )
    _sha(
        item["observed_resource_files_sha256"],
        "startup observed resource files sha256",
    )
    if (
        canonical_sha256(observed, max_bytes=MAX_RECORD_BYTES)
        != item["observed_resource_files_sha256"]
    ):
        _fail("startup observed resource files SHA-256 is invalid")
    _sha(item["startup_receipt_sha256"], "startup receipt sha256")
    base = {key: item[key] for key in _STARTUP_RECEIPT_BASE}
    if canonical_sha256(base, max_bytes=MAX_RECORD_BYTES) != item["startup_receipt_sha256"]:
        _fail("startup receipt SHA-256 is invalid")
    return item


def validate_stored_startup_receipt(value: Any) -> dict[str, Any]:
    """Validate a persisted receipt without inventing missing v2 evidence.

    Schema v1 shipped before managed-file identities were observed.  Those
    records remain readable, hash-verified historical data so one legacy store
    member cannot block unrelated v2 startups.  Registration authority still
    uses the v2-only validator above; no v1 receipt is upgraded in place.
    """

    candidate = _plain_copy(value)
    if isinstance(candidate, dict) and candidate.get("schema_version") == 2:
        return _startup_receipt(candidate)
    item = _object(
        candidate,
        _STARTUP_RECEIPT_V1_BASE | {"startup_receipt_sha256"},
        "legacy startup receipt",
    )
    if item["schema_version"] != 1 or item["hook_protocol_version"] != 6:
        _fail("legacy startup receipt version is unsupported")
    _hook_id(item["session_id"], "legacy startup session id")
    if item["source"] != "startup":
        _fail("only a fresh startup may produce a legacy startup receipt")
    _dt(item["observed_at"], "legacy startup observed_at")
    _text(item["cwd"], "legacy startup cwd", limit=4096, strip=False)
    _text(item["project_root"], "legacy startup project root", limit=4096, strip=False)
    _sha(item["aoi_config_sha256"], "legacy startup AOI config sha256")
    _sha(item["startup_receipt_sha256"], "legacy startup receipt sha256")
    base = {key: item[key] for key in _STARTUP_RECEIPT_V1_BASE}
    if canonical_sha256(base, max_bytes=MAX_RECORD_BYTES) != item["startup_receipt_sha256"]:
        _fail("legacy startup receipt SHA-256 is invalid")
    return item


def registration_identity_preimage(
    registration: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the replay identity that deliberately excludes time and renewals."""

    try:
        registrar = registration["registrar_chief_authority"]
        if not isinstance(registrar, Mapping):
            _fail("registration Chief authority is invalid")
        return {
            "session_id": registration["session_id"],
            "task_id": registration["task_id"],
            "task_plan_sha256": registration["task_plan_sha256"],
            "startup_receipt_sha256": registration["startup_receipt_sha256"],
            "resource_config_event_id": registration["resource_config_event_id"],
            "resource_event_applied_sha256": registration[
                "resource_event_applied_sha256"
            ],
            "resource_receipt_relative_path": registration[
                "resource_receipt_relative_path"
            ],
            "resource_receipt_sha256": registration["resource_receipt_sha256"],
            "resource_plan_sha256": registration["resource_plan_sha256"],
            "aoi_config_sha256": registration["aoi_config_sha256"],
            "project_config_sha256": registration["project_config_sha256"],
            "resource_files_manifest_sha256": registration[
                "resource_files_manifest_sha256"
            ],
            "task_worktree": registration["task_worktree"],
            "registrar_chief_session_id": registrar["session_id"],
            "registrar_chief_epoch": registrar["epoch"],
        }
    except KeyError as exc:
        raise RoutingAuthorityError(
            "registration identity preimage is incomplete"
        ) from exc


def registration_identity_sha256(registration: Mapping[str, Any]) -> str:
    return canonical_sha256(
        registration_identity_preimage(registration), max_bytes=MAX_RECORD_BYTES
    )


def seal_session_registration(registration: Mapping[str, Any]) -> dict[str, Any]:
    """Seal a v2 Chief registration and its rollback-stable applied snapshot."""
    base = _object(
        _plain_copy(registration),
        _REGISTRATION_BASE,
        "unsealed session registration",
    )
    sealed = {
        **base,
        "registration_sha256": canonical_sha256(base, max_bytes=MAX_RECORD_BYTES),
    }
    return _registration(sealed)


def _registration(value: Any) -> dict[str, Any]:
    item = _object(
        value,
        _REGISTRATION_BASE | {"registration_sha256"},
        "session registration",
    )
    if item["registration_schema_version"] != 2:
        _fail("session registration version is unsupported")
    _hook_id(item["session_id"], "registered session id")
    _id(item["task_id"], "registration task id")
    startup = _startup_receipt(item["startup_receipt_snapshot"])
    if (
        item["startup_receipt_sha256"] != startup["startup_receipt_sha256"]
        or item["session_id"] != startup["session_id"]
        or item["aoi_config_sha256"] != startup["aoi_config_sha256"]
        or item["task_worktree"] != startup["project_root"]
    ):
        _fail("session registration is not bound to its startup receipt")
    event = _resource_event(item["resource_event_applied_snapshot"])
    _id(item["resource_config_event_id"], "registration resource event id")
    _text(
        item["resource_receipt_relative_path"],
        "registration resource receipt relative path",
        limit=4096,
        strip=False,
    )
    for key in (
        "task_plan_sha256",
        "startup_receipt_sha256",
        "resource_event_applied_sha256",
        "resource_receipt_sha256",
        "resource_plan_sha256",
        "aoi_config_sha256",
        "project_config_sha256",
        "resource_files_manifest_sha256",
        "registration_identity_sha256",
        "registration_sha256",
    ):
        _sha(item[key], key)
    base = {key: item[key] for key in _REGISTRATION_BASE}
    if canonical_sha256(base, max_bytes=MAX_RECORD_BYTES) != item["registration_sha256"]:
        _fail("session registration SHA-256 is invalid")
    startup_at = _dt(startup["observed_at"], "startup observed_at")
    registered_at = _dt(item["registered_at"], "registered_at")
    registrar = _object(
        item["registrar_chief_authority"],
        _REGISTRAR_CHIEF_AUTHORITY,
        "registration Chief authority",
    )
    _hook_id(registrar["session_id"], "registration Chief session id")
    if (
        isinstance(registrar["epoch"], bool)
        or not isinstance(registrar["epoch"], int)
        or registrar["epoch"] < 1
    ):
        _fail("registration Chief epoch is invalid")
    _sha(
        registrar["authority_record_sha256"],
        "registration Chief authority record sha256",
    )
    startup_match = _resource_file_identities(
        item["startup_resource_files_match"],
        label="registration startup resource file match",
        allow_empty=False,
    )
    observed = {
        record["relative_path"]: record["after_sha256"]
        for record in startup["observed_resource_files"]
    }
    project_matches = [
        record
        for record in startup_match
        if record["relative_path"] == ".codex/config.toml"
    ]
    if (
        item["resource_config_event_id"] != event["event_id"]
        or item["resource_event_applied_sha256"]
        != canonical_sha256(event, max_bytes=MAX_RECORD_BYTES)
        or item["resource_receipt_relative_path"]
        != _relative_receipt_path(event["event_id"])
        or item["resource_receipt_sha256"] != event["receipt_sha256"]
        or item["resource_plan_sha256"] != event["plan_sha256"]
        or item["task_plan_sha256"] != event["task_plan_sha256"]
        or item["registration_identity_sha256"]
        != registration_identity_sha256(item)
        or registrar["session_id"] != item["session_id"]
        or not startup_at < registered_at
        or canonical_sha256(startup_match, max_bytes=MAX_RECORD_BYTES)
        != item["resource_files_manifest_sha256"]
        or any(
            observed.get(record["relative_path"]) != record["after_sha256"]
            for record in startup_match
        )
        or len(project_matches) != 1
        or project_matches[0]["after_sha256"] != item["project_config_sha256"]
        or item["config_ancestry_verified"] is not True
        or item["resource_files_verified"] is not True
        or item["startup_resource_state_equivalent"] is not True
        or item["freshness_verdict"]
        != "registered_byte_state_equivalent_only"
        or item["config_loaded_verified"] != "unavailable"
    ):
        _fail("session registration startup authority is invalid")
    _text(item["task_worktree"], "registration task worktree", limit=4096, strip=False)
    return item


def validate_session_registration(registration: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and detach one sealed registration without filesystem I/O."""

    return _clone(_registration(_plain_copy(registration)))


def resource_event_snapshot_sha256(event: Mapping[str, Any]) -> str:
    """Hash one exact applicable, non-rollback applied resource event."""

    return canonical_sha256(
        _resource_event(_plain_copy(event)), max_bytes=MAX_RECORD_BYTES
    )


def _packet(value: Any) -> dict[str, Any]:
    fields = {
        "task_id",
        "packet_id",
        "packet_contract_sha256",
        "task_plan_sha256",
        "delegation_depth",
        "parent_packet_id",
        "agent_role",
    }
    item = _object(value, fields, "packet authority")
    _id(item["task_id"], "task id")
    _id(item["packet_id"], "packet id")
    _id(item["agent_role"], "packet agent role")
    _sha(item["packet_contract_sha256"], "packet contract sha256")
    _sha(item["task_plan_sha256"], "task plan sha256")
    if item["delegation_depth"] not in {1, 2}:
        _fail("packet delegation depth is invalid")
    if item["delegation_depth"] == 1 and item["parent_packet_id"] != "":
        _fail("depth-one packet may not name a parent")
    if item["delegation_depth"] == 2:
        _id(item["parent_packet_id"], "parent packet id")
    return item


def _validate_authority(authority: Mapping[str, Any], *, nested: bool = False) -> dict[str, Any]:
    fields = {
        "schema_version",
        "task_id",
        "packet_authority",
        "attempt_identity",
        "chief_authority",
        "parent_authority",
        "transport_authority",
        "resource_authority",
        "session_registration",
        "resource_envelope",
        "topology_authority",
    }
    value = _object(authority, fields, "routing authority")
    if value["schema_version"] != SCHEMA_VERSION:
        _fail("routing authority version is unsupported")
    packet = _packet(value["packet_authority"])
    if value["task_id"] != packet["task_id"]:
        _fail("routing authority task is not packet task")
    attempt = _object(
        value["attempt_identity"],
        {"attempt", "arm_id", "armed_at", "expires_at"},
        "attempt identity",
    )
    if (
        isinstance(attempt["attempt"], bool)
        or not isinstance(attempt["attempt"], int)
        or not 1 <= attempt["attempt"] <= 1_000_000
    ):
        _fail("attempt number is invalid")
    _id(attempt["arm_id"], "arm id")
    armed = _dt(attempt["armed_at"], "armed_at")
    expires = _dt(attempt["expires_at"], "expires_at")
    if not armed < expires <= armed + timedelta(seconds=900):
        _fail("arm lifetime must be positive and at most 900 seconds")
    chief = _object(
        value["chief_authority"],
        {"session_id", "epoch", "authority_sha256"},
        "chief authority",
    )
    _hook_id(chief["session_id"], "chief session id")
    _sha(chief["authority_sha256"], "chief authority sha256")
    if (
        isinstance(chief["epoch"], bool)
        or not isinstance(chief["epoch"], int)
        or chief["epoch"] < 1
    ):
        _fail("chief epoch is invalid")
    transport = _object(
        value["transport_authority"],
        {"transport", "expected_agent_type"},
        "transport authority",
    )
    if transport["transport"] != "codex":
        _fail("only Codex transport is supported")
    if transport["expected_agent_type"] != "*":
        _hook_id(transport["expected_agent_type"], "expected agent type")

    resource_fields = {
        "event_snapshot",
        "event_snapshot_sha256",
        "receipt_authority",
        "role_profile_relative_path",
        "role_profile_after_sha256",
        "project_config_after_sha256",
    }
    resource = _object(value["resource_authority"], resource_fields, "resource authority")
    event = _resource_event(resource["event_snapshot"])
    _sha(resource["event_snapshot_sha256"], "resource event snapshot sha256")
    if canonical_sha256(event, max_bytes=MAX_RECORD_BYTES) != resource["event_snapshot_sha256"]:
        _fail("resource event snapshot hash mismatch")
    if event["task_plan_sha256"] != packet["task_plan_sha256"]:
        _fail("packet task plan does not match resource event")
    assignments = _assignments(event)
    if packet["agent_role"] not in assignments:
        _fail("packet role is absent from resource assignments")
    receipt_authority, receipt_files = _receipt_authority(
        resource["receipt_authority"], event, packet
    )
    assignment = assignments[packet["agent_role"]]
    role_path = f".codex/agents/{assignment['profile']}.toml"
    role_file = receipt_files.get(role_path)
    config_file = receipt_files.get(".codex/config.toml")
    if role_file is None or config_file is None:
        _fail("receipt plan does not contain the selected profile and project config")
    if (
        resource["role_profile_relative_path"] != role_path
        or resource["role_profile_after_sha256"] != role_file["after_sha256"]
        or resource["project_config_after_sha256"] != config_file["after_sha256"]
        or assignment["profile_source_kind"] != role_file["source_kind"]
        or assignment["profile_source_sha256"] != role_file["source_sha256"]
    ):
        _fail("selected profile/config hashes are not derived from the reviewed receipt plan")
    _sha(resource["role_profile_after_sha256"], "role profile after sha256")
    _sha(resource["project_config_after_sha256"], "project config after sha256")

    registration = _registration(value["session_registration"])
    registered = _dt(registration["registered_at"], "registered_at")
    if registered >= armed:
        _fail("registration postdates arm authority")
    plan = receipt_authority["plan_snapshot"]
    registrar = registration["registrar_chief_authority"]
    if (
        chief["session_id"] != registrar["session_id"]
        or chief["epoch"] != registrar["epoch"]
        or registration["task_id"] != packet["task_id"]
        or registration["task_plan_sha256"] != packet["task_plan_sha256"]
        or registration["resource_config_event_id"] != event["event_id"]
        or registration["resource_event_applied_snapshot"] != event
        or registration["resource_event_applied_sha256"]
        != resource["event_snapshot_sha256"]
        or registration["resource_receipt_relative_path"]
        != receipt_authority["receipt_relative_path"]
        or registration["resource_receipt_sha256"] != event["receipt_sha256"]
        or registration["resource_plan_sha256"] != event["plan_sha256"]
        or registration["aoi_config_sha256"] != plan["aoi_config_sha256"]
        or registration["project_config_sha256"] != resource["project_config_after_sha256"]
        or registration["resource_files_manifest_sha256"]
        != resource_files_manifest_sha256(plan)
    ):
        _fail(
            "session registration does not bind the current Chief and exact "
            "resource/AOI/Codex startup hashes"
        )

    envelope = _snapshot(value["resource_envelope"], "resource envelope")
    if envelope["snapshot"] != event["dynamic_envelope"]:
        _fail("resource envelope is not the exact event dynamic envelope")
    topology = _snapshot(value["topology_authority"], "topology authority")["snapshot"]
    parent_fields = {
        "session_id",
        "mapping_kind",
        "parent_packet_id",
        "root_registration_snapshot",
        "parent_authority_preimage",
        "parent_dispatch_outcome_preimage",
        "inherited_parent_routing_authority_sha256",
        "inherited_parent_routing_outcome_sha256",
    }
    parent = _object(value["parent_authority"], parent_fields, "parent authority")
    _hook_id(parent["session_id"], "parent session id")
    if packet["delegation_depth"] == 1:
        if (
            parent["mapping_kind"] != "root"
            or parent["parent_packet_id"] != ""
            or parent["parent_authority_preimage"] is not None
            or parent["parent_dispatch_outcome_preimage"] is not None
            or parent["inherited_parent_routing_authority_sha256"] is not None
            or parent["inherited_parent_routing_outcome_sha256"] is not None
        ):
            _fail("depth-one parent authority is invalid")
        if (
            _registration(parent["root_registration_snapshot"]) != registration
            or parent["session_id"] != registration["session_id"]
        ):
            _fail("depth-one requires its fresh root startup registration")
        expected_topology = {
            "delegation_depth": 1,
            "parent_packet_id": "",
            "parent_resource_event_id": "",
            "parent_routing_authority_sha256": "",
        }
    else:
        if (
            parent["mapping_kind"] != "subagent_parent"
            or parent["parent_packet_id"] != packet["parent_packet_id"]
        ):
            _fail("depth-two parent identity is invalid")
        inherited = _registration(parent["root_registration_snapshot"])
        _sha(
            parent["inherited_parent_routing_authority_sha256"],
            "inherited parent routing authority sha256",
        )
        _sha(
            parent["inherited_parent_routing_outcome_sha256"],
            "inherited parent routing outcome sha256",
        )
        parent_preimage = parent["parent_authority_preimage"]
        parent_outcome_preimage = parent["parent_dispatch_outcome_preimage"]
        if not isinstance(parent_preimage, dict) or not isinstance(parent_outcome_preimage, dict) or nested:
            _fail("depth-two parent preimages are invalid")
        parent_arm = _validate_authority(parent_preimage, nested=True)
        parent_arm_sha = authority_sha256(parent_arm)
        parent_outcome = validate_dispatch_outcome(parent_arm, parent_outcome_preimage)
        observation = parent_outcome["observation"]
        if (
            parent_arm["packet_authority"]["delegation_depth"] != 1
            or parent_arm_sha != parent["inherited_parent_routing_authority_sha256"]
            or outcome_sha256(parent_outcome)
            != parent["inherited_parent_routing_outcome_sha256"]
            or parent_arm["packet_authority"]["packet_id"] != packet["parent_packet_id"]
            or parent_arm["task_id"] != packet["task_id"]
            or parent_arm["resource_authority"]["event_snapshot"]["event_id"]
            != event["event_id"]
            or parent_arm["session_registration"] != inherited
            or registration != inherited
            or parent_outcome["dispatch_provenance"] != "codex_subagent_start_observed"
            or not isinstance(observation, dict)
            or parent["session_id"] != observation["agent_id"]
            or _dt(parent_outcome["recorded_at"], "parent outcome recorded_at") > armed
        ):
            _fail("depth-two parent preimages do not bind the observed parent session")
        expected_topology = {
            "delegation_depth": 2,
            "parent_packet_id": packet["parent_packet_id"],
            "parent_resource_event_id": event["event_id"],
            "parent_routing_authority_sha256": parent_arm_sha,
        }
    if topology != expected_topology:
        _fail("topology authority schema or parent preimage is invalid")
    return _clone(value)


def authority_sha256(authority: Mapping[str, Any]) -> str:
    """Hash the complete arm authority; there is intentionally no self-hash."""
    return canonical_sha256(_validate_authority(authority), max_bytes=MAX_RECORD_BYTES)


def build_arm_authority(
    *,
    packet: Mapping[str, Any],
    attempt_identity: Mapping[str, Any],
    chief_authority: Mapping[str, Any],
    parent_authority: Mapping[str, Any],
    resource_event_snapshot: Mapping[str, Any],
    resource_receipt: Mapping[str, Any],
    session_registration: Mapping[str, Any],
    resource_envelope: Mapping[str, Any],
    topology_authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Build an arm from an exact real receipt envelope and immutable preimages."""
    packet_copy = _packet(_plain_copy(packet))
    event_copy = _resource_event(_plain_copy(resource_event_snapshot))
    receipt_input = _object(
        _plain_copy(resource_receipt),
        {"receipt", "receipt_relative_path", "receipt_file_sha256"},
        "resource receipt envelope",
    )
    receipt = _validate_real_receipt_input(receipt_input, event_copy, packet_copy)
    compact_receipt = _compact_receipt_authority(receipt_input, receipt)
    assignments = _assignments(event_copy)
    assignment = assignments.get(packet_copy["agent_role"])
    if assignment is None:
        _fail("packet role is absent from resource assignments")
    role_path = f".codex/agents/{assignment['profile']}.toml"
    files = _plan_files(receipt["plan"])
    role_file = files.get(role_path)
    config_file = files.get(".codex/config.toml")
    if role_file is None or config_file is None:
        _fail("receipt does not contain the selected profile and project config")
    attempt = _plain_copy(attempt_identity)
    if not isinstance(attempt, dict):
        _fail("attempt identity is invalid")
    expected_agent_type = attempt.pop("expected_agent_type", None)
    authority = {
        "schema_version": SCHEMA_VERSION,
        "task_id": packet_copy["task_id"],
        "packet_authority": packet_copy,
        "attempt_identity": attempt,
        "chief_authority": _plain_copy(chief_authority),
        "parent_authority": _plain_copy(parent_authority),
        "transport_authority": {
            "transport": "codex",
            "expected_agent_type": expected_agent_type,
        },
        "resource_authority": {
            "event_snapshot": event_copy,
            "event_snapshot_sha256": canonical_sha256(event_copy, max_bytes=MAX_RECORD_BYTES),
            "receipt_authority": compact_receipt,
            "role_profile_relative_path": role_path,
            "role_profile_after_sha256": role_file["after_sha256"],
            "project_config_after_sha256": config_file["after_sha256"],
        },
        "session_registration": _plain_copy(session_registration),
        "resource_envelope": _plain_copy(resource_envelope),
        "topology_authority": _plain_copy(topology_authority),
    }
    return _validate_authority(authority)


def validate_arm_authority(authority: Mapping[str, Any]) -> dict[str, Any]:
    return _validate_authority(authority)


def codex_observation_event_id(observation: Mapping[str, Any]) -> str:
    """Derive the exact event id used by dispatch_protocol.subagent_event_id."""
    try:
        identity = {
            "session_id": observation["parent_session_id"],
            "turn_id": observation["turn_id"],
            "agent_id": observation["agent_id"],
            "agent_type": observation["agent_type"],
            "hook_protocol_version": observation["hook_protocol_version"],
        }
    except (KeyError, TypeError) as exc:
        raise RoutingAuthorityError("Codex observation event preimage is incomplete") from exc
    return "spawn-" + canonical_sha256(identity, max_bytes=MAX_RECORD_BYTES)[:32]


def _validate_observation(value: Any, arm: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "event_id",
        "hook_protocol_version",
        "parent_session_id",
        "turn_id",
        "agent_id",
        "agent_type",
        "permission_mode",
        "model",
        "observed_at",
        "observation_sha256",
    }
    item = _object(value, fields, "Codex observation")
    _id(item["event_id"], "observation event id")
    _hook_id(item["parent_session_id"], "observation parent session id")
    _hook_id(item["agent_id"], "observation agent id")
    _hook_id(item["agent_type"], "observation agent type")
    _text(item["turn_id"], "observation turn id", empty=True, limit=512)
    _text(item["permission_mode"], "permission mode", empty=True, limit=128)
    _text(item["model"], "observed model", empty=True, limit=128)
    if item["hook_protocol_version"] != 6:
        _fail("hook protocol version must be exactly 6")
    if item["event_id"] != codex_observation_event_id(item):
        _fail("observation event id is not the dispatch protocol identity")
    observed = _dt(item["observed_at"], "observed_at")
    _sha(item["observation_sha256"], "observation sha256")
    preimage = {key: val for key, val in item.items() if key != "observation_sha256"}
    if canonical_sha256(preimage, max_bytes=MAX_RECORD_BYTES) != item["observation_sha256"]:
        _fail("observation SHA-256 mismatch")
    expected = arm["transport_authority"]["expected_agent_type"]
    if (
        item["parent_session_id"] != arm["parent_authority"]["session_id"]
        or (expected != "*" and item["agent_type"] != expected)
    ):
        _fail("observation transport binding is invalid")
    attempt = arm["attempt_identity"]
    if not _dt(attempt["armed_at"], "armed_at") <= observed <= _dt(
        attempt["expires_at"], "expires_at"
    ):
        _fail("observation is outside its arm window")
    return _clone(item)


def _outcome_hash(outcome: Mapping[str, Any]) -> str:
    preimage = {key: value for key, value in outcome.items() if key != "routing_outcome_sha256"}
    return canonical_sha256(preimage, max_bytes=MAX_RECORD_BYTES)


def outcome_sha256(outcome: Mapping[str, Any]) -> str:
    if not isinstance(outcome, dict):
        _fail("routing outcome must be an object")
    if "legacy_packet_snapshot" in outcome:
        _validate_legacy_outcome(outcome)
    elif outcome.get("routing_outcome_sha256") != _outcome_hash(outcome):
        _fail("routing outcome hash mismatch")
    return _outcome_hash(outcome)


def _binding(
    arm: Mapping[str, Any],
    observation: Mapping[str, Any] | None,
    provenance: str,
) -> dict[str, Any]:
    packet = arm["packet_authority"]
    attempt = arm["attempt_identity"]
    return {
        "routing_authority_sha256": authority_sha256(arm),
        "packet_id": packet["packet_id"],
        "arm_id": attempt["arm_id"],
        "attempt": attempt["attempt"],
        "observation_sha256": None if observation is None else observation["observation_sha256"],
        "dispatch_provenance": provenance,
    }


def _slot(binding: Mapping[str, Any]) -> str:
    # Every terminal claim for one arm collides, including manual-vs-observed.
    preimage = {
        key: binding[key]
        for key in ("routing_authority_sha256", "packet_id", "arm_id", "attempt")
    }
    return canonical_sha256(preimage, max_bytes=MAX_RECORD_BYTES)


def build_dispatch_outcome(
    authority: Mapping[str, Any],
    *,
    dispatch_provenance: str,
    observation: Mapping[str, Any] | None,
    recorded_at: str,
) -> dict[str, Any]:
    arm = _validate_authority(authority)
    recorded = _dt(recorded_at, "recorded_at")
    attempt = arm["attempt_identity"]
    armed = _dt(attempt["armed_at"], "armed_at")
    expires = _dt(attempt["expires_at"], "expires_at")
    if not armed <= recorded <= expires:
        _fail("recorded outcome is outside its arm window")
    if dispatch_provenance == "manual_unverified":
        if observation is not None:
            _fail("manual outcome may not carry an observation")
        observed = None
        verdict = "manual_unverified"
        model = None
        match = "unavailable"
    elif dispatch_provenance == "codex_subagent_start_observed":
        if observation is None:
            _fail("observed provenance requires an observation")
        observed = _validate_observation(observation, arm)
        if recorded < _dt(observed["observed_at"], "observed_at"):
            _fail("recorded outcome predates its observation")
        model = observed["model"] or None
        requested_model = arm["resource_authority"]["event_snapshot"]["resolved"]["agents"][
            arm["packet_authority"]["agent_role"]
        ]["model"]
        match = "unavailable" if model is None else ("match" if model == requested_model else "mismatch")
        verdict = "actual_model_unobserved" if model is None else f"observed_model_slug_{match}"
    else:
        _fail("dispatch provenance is invalid")
    assignment = arm["resource_authority"]["event_snapshot"]["resolved"]["agents"][
        arm["packet_authority"]["agent_role"]
    ]
    request = _request(
        {
            "requested_role": arm["packet_authority"]["agent_role"],
            "requested_capability_tier": assignment["capability_tier"],
            "requested_profile": assignment["profile"],
            "requested_model": assignment["model"],
            "requested_reasoning_effort": assignment["model_reasoning_effort"],
            "requested_sandbox_profile": "unavailable",
        }
    )
    binding = _binding(arm, observed, dispatch_provenance)
    outcome = {
        "schema_version": SCHEMA_VERSION,
        "routing_authority_sha256": authority_sha256(arm),
        "dispatch_provenance": dispatch_provenance,
        "observation": observed,
        "observation_binding": binding,
        "observation_identity_sha256": None
        if observed is None
        else observed["observation_sha256"],
        "outcome_slot_sha256": _slot(binding),
        **request,
        "active_model_slug_observed": model,
        "observed_model_slug_match": match,
        "config_loaded_verified": "unavailable",
        "provider_route_verified": "unavailable",
        "runtime_profile_verified": "unavailable",
        "runtime_sandbox_profile_verified": "unavailable",
        "fresh_session_evidence": "registered_byte_state_equivalent_only"
        if arm["packet_authority"]["delegation_depth"] == 1
        else "inherited_root_registration",
        "verdict": verdict,
        "recorded_at": recorded_at,
        "routing_outcome_sha256": "0" * 64,
    }
    outcome["routing_outcome_sha256"] = _outcome_hash(outcome)
    return _clone(outcome)


def validate_dispatch_outcome(
    authority: Mapping[str, Any], outcome: Mapping[str, Any]
) -> dict[str, Any]:
    arm = _validate_authority(authority)
    fields = {
        "schema_version",
        "routing_authority_sha256",
        "dispatch_provenance",
        "observation",
        "observation_binding",
        "observation_identity_sha256",
        "outcome_slot_sha256",
        *_REQUEST,
        "active_model_slug_observed",
        "observed_model_slug_match",
        "config_loaded_verified",
        "provider_route_verified",
        "runtime_profile_verified",
        "runtime_sandbox_profile_verified",
        "fresh_session_evidence",
        "verdict",
        "recorded_at",
        "routing_outcome_sha256",
    }
    item = _object(outcome, fields, "routing outcome")
    if item["schema_version"] != SCHEMA_VERSION or item["routing_authority_sha256"] != authority_sha256(arm):
        _fail("routing outcome authority binding is invalid")
    generated = build_dispatch_outcome(
        arm,
        dispatch_provenance=item["dispatch_provenance"],
        observation=item["observation"],
        recorded_at=item["recorded_at"],
    )
    if _clone(item) != generated:
        _fail("routing outcome derivation, observation binding, or slot is invalid")
    return _clone(item)


def _terminal_classification(status: Any, typed_outcome: Any) -> tuple[str, str]:
    if not isinstance(status, str) or status not in _TERMINAL_TYPED_OUTCOMES_BY_STATUS:
        _fail("packet terminal status is invalid")
    if (
        not isinstance(typed_outcome, str)
        or typed_outcome not in _TERMINAL_TYPED_OUTCOMES_BY_STATUS[status]
    ):
        _fail("typed outcome is invalid for packet terminal status")
    return status, typed_outcome


def _validate_legacy_outcome(item: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version",
        "legacy_packet_snapshot",
        "legacy_packet_snapshot_sha256",
        "legacy_snapshot_identity_sha256",
        "dispatch_provenance",
        "terminal_status",
        "typed_outcome",
        "active_model_slug_observed",
        "observed_model_slug_match",
        "fresh_session_evidence",
        "verdict",
        "recorded_at",
        "routing_outcome_sha256",
    }
    value = _object(item, fields, "legacy routing outcome")
    snapshot = value["legacy_packet_snapshot"]
    if not isinstance(snapshot, dict) or snapshot.get("packet_schema_version") != 5:
        _fail("legacy packet snapshot is not schema v5")
    typed = snapshot.get("typed_outcome") or "unclassified"
    status, typed = _terminal_classification(snapshot.get("status"), typed)
    digest = canonical_sha256(snapshot, max_bytes=MAX_RECORD_BYTES)
    if any(
        value[key] != digest
        for key in ("legacy_packet_snapshot_sha256", "legacy_snapshot_identity_sha256")
    ):
        _fail("legacy packet snapshot identity is invalid")
    if (
        value["terminal_status"] != status
        or value["typed_outcome"] != typed
        or value["dispatch_provenance"] != "legacy_unverified"
        or value["active_model_slug_observed"] is not None
        or value["observed_model_slug_match"] != "unavailable"
        or value["fresh_session_evidence"] != "unavailable"
        or value["verdict"] != "legacy_actual_model_unobserved"
    ):
        _fail("legacy routing outcome is invalid")
    _dt(value["recorded_at"], "recorded_at")
    if _outcome_hash(value) != value["routing_outcome_sha256"]:
        _fail("legacy routing outcome hash mismatch")
    return _clone(value)


def build_legacy_outcome(
    packet_snapshot: Mapping[str, Any], *, recorded_at: str
) -> dict[str, Any]:
    """Seal one terminal v5 snapshot without upgrading its routing evidence."""
    snapshot = _clone(packet_snapshot)
    typed = snapshot.get("typed_outcome") or "unclassified"
    status, typed = _terminal_classification(snapshot.get("status"), typed)
    digest = canonical_sha256(snapshot, max_bytes=MAX_RECORD_BYTES)
    outcome = {
        "schema_version": SCHEMA_VERSION,
        "legacy_packet_snapshot": snapshot,
        "legacy_packet_snapshot_sha256": digest,
        "legacy_snapshot_identity_sha256": digest,
        "dispatch_provenance": "legacy_unverified",
        "terminal_status": status,
        "typed_outcome": typed,
        "active_model_slug_observed": None,
        "observed_model_slug_match": "unavailable",
        "fresh_session_evidence": "unavailable",
        "verdict": "legacy_actual_model_unobserved",
        "recorded_at": recorded_at,
        "routing_outcome_sha256": "0" * 64,
    }
    outcome["routing_outcome_sha256"] = _outcome_hash(outcome)
    return _validate_legacy_outcome(outcome)


def capacity_routing_view(outcomes: Any) -> dict[str, Any]:
    """Return every terminal row; eligibility is explicit and never re-derived."""
    if not isinstance(outcomes, list) or len(outcomes) > MAX_CAPACITY_ROWS:
        _fail("capacity outcomes collection is invalid")
    rows: list[dict[str, Any]] = []
    seen_v6: set[str] = set()
    seen_legacy: set[str] = set()
    observed_authorities: dict[str, str] = {}
    for stored in outcomes:
        if not isinstance(stored, dict):
            _fail("capacity stored outcome is invalid")
        if "legacy_outcome" in stored:
            _object(stored, {"legacy_outcome"}, "legacy capacity row")
            outcome = _validate_legacy_outcome(stored["legacy_outcome"])
            identity = outcome["legacy_snapshot_identity_sha256"]
            if identity in seen_legacy:
                _fail("duplicate legacy packet snapshot identity")
            seen_legacy.add(identity)
            authority = None
            terminal_status = outcome["terminal_status"]
            typed = outcome["typed_outcome"]
            role = tier = profile = requested_model = "unavailable"
            observed_model = None
            observation_identity = None
        else:
            _object(
                stored,
                {"authority", "outcome", "terminal_status", "typed_outcome"},
                "v6 capacity row",
            )
            terminal_status, typed = _terminal_classification(
                stored["terminal_status"], stored["typed_outcome"]
            )
            authority = _validate_authority(stored["authority"])
            outcome = validate_dispatch_outcome(authority, stored["outcome"])
            identity = outcome["outcome_slot_sha256"]
            if identity in seen_v6:
                _fail("duplicate v6 outcome CAS slot")
            seen_v6.add(identity)
            observation_identity = outcome["observation_identity_sha256"]
            authority_hash = authority_sha256(authority)
            if observation_identity is not None:
                previous = observed_authorities.setdefault(observation_identity, authority_hash)
                if previous != authority_hash:
                    _fail("one observation cannot bind two packet authorities")
            role = outcome["requested_role"]
            tier = outcome["requested_capability_tier"]
            profile = outcome["requested_profile"]
            requested_model = outcome["requested_model"]
            observed_model = outcome["active_model_slug_observed"]
        technical = typed in _TECHNICAL_OUTCOMES
        slug_attribution = outcome["verdict"] == "observed_model_slug_match"
        row = {
            "routing_outcome_sha256": outcome["routing_outcome_sha256"],
            "authority_sha256": None if authority is None else authority_sha256(authority),
            "sample_identity_sha256": identity,
            "observation_identity_sha256": observation_identity,
            "dispatch_provenance": outcome["dispatch_provenance"],
            "verdict": outcome["verdict"],
            "terminal_status": terminal_status,
            "typed_outcome": typed,
            "role": role,
            "capability_tier": tier,
            "profile": profile,
            "requested_model": requested_model,
            "observed_model_slug": observed_model,
            "technical_outcome_eligible": technical,
            "model_slug_attribution_eligible": slug_attribution,
            "model_quality_eligible": technical and slug_attribution,
        }
        row["row_identity_sha256"] = canonical_sha256(row, max_bytes=MAX_RECORD_BYTES)
        rows.append(row)
    rows.sort(key=lambda row: (row["sample_identity_sha256"], row["routing_outcome_sha256"]))
    fingerprint = canonical_sha256(
        [row["row_identity_sha256"] for row in rows],
        max_bytes=16 * 1024 * 1024,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "input_order": [row["routing_outcome_sha256"] for row in rows],
        "input_fingerprint": fingerprint,
        "rows": rows,
    }
