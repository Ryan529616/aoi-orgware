"""Event-authoritative claim transactions for semantic-v2 tasks.

The mutable active/archive files are deliberately only side projections.  They
reserve cooperative locks while a transaction is in flight, but callers must
use :func:`authenticated_claims_for_task` before treating one as authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Never

from . import harnesslib as h
from . import semantic_events as events


CLAIM_NAMESPACE = "semantic_claims_v1"
CLAIM_NAMESPACE_VERSION = 1
_ZERO = "0" * 64
_SHA = re.compile(r"[0-9a-f]{64}")
_OPERATIONS = frozenset({"acquire", "status", "release"})
_EVENT_TYPES = {
    "acquire": "claim_acquired",
    "status": "claim_status_changed",
    "release": "claim_released",
}
_ROW_FIELDS = frozenset(
    {
        "token", "operation", "status", "location", "object_sha256",
        "prior_object_sha256", "binding_key", "command_id", "recorded_at",
        "lock_scope_sha256",
    }
)
_NAMESPACE_FIELDS = frozenset({"schema_version", "claims"})
_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version", "phase", "operation", "object_sha256",
        "binding_sha256", "expected_head_sha256", "planned_event_sha256",
        "result_projection_sha256", "command_id", "recorded_at",
    }
)
_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version", "operation", "task_id", "token", "command_id",
        "recorded_at", "expected_head_sha256", "authority_ref", "prior_object_sha256", "claim",
    }
)


class SemanticClaimError(h.HarnessError):
    """A semantic claim lifecycle record is malformed or unauthenticated."""


def _fail(message: str) -> Never:
    raise SemanticClaimError(message)


def _clone(value: Any) -> Any:
    try:
        return json.loads(events.canonical_json_bytes(value, max_bytes=64 * 1024))
    except (events.SemanticEventError, TypeError, ValueError) as exc:
        raise SemanticClaimError(f"semantic claim value is not bounded canonical JSON: {exc}") from exc


def _sha(value: Any) -> str:
    try:
        return events.canonical_sha256(value, max_bytes=64 * 1024)
    except events.SemanticEventError as exc:
        raise SemanticClaimError(f"semantic claim value cannot be hashed: {exc}") from exc


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _text(value: Any, label: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _fail(f"{label} must be a non-empty string")
    return value.strip()


def _command_args(args: Any) -> tuple[str, str, str, str]:
    command = _text(getattr(args, "semantic_command_id", None), "semantic command id", 256)
    try:
        command = h.validate_id(command, "semantic command id")
    except h.HarnessError as exc:
        raise SemanticClaimError(str(exc)) from exc
    expected = _digest(
        getattr(args, "expected_head_sha256", None)
        or getattr(args, "semantic_expected_head_sha256", None),
        "expected semantic head SHA-256",
    )
    recorded = _text(
        getattr(args, "recorded_at", None) or getattr(args, "semantic_recorded_at", None),
        "recorded_at", 64,
    )
    authority = _text(getattr(args, "_aoi_authority_ref", None), "Chief authority reference")
    # Reuse the event parser for timestamp and authority grammar without
    # manufacturing a transaction event.
    try:
        events.create_genesis_event(
            {"task_id": "semantic-claim-probe"}, command_id=command,
            recorded_at=recorded, authority_ref=authority,
        )
    except events.SemanticEventError as exc:
        raise SemanticClaimError(f"semantic claim command metadata is invalid: {exc}") from exc
    return command, expected, recorded, authority


def _claim_body(value: Any, *, task_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("semantic claim body must be an object")
    if "_path" in value or "semantic_authority" in value:
        _fail("semantic claim body may not carry side-record fields")
    claim = _clone(value)
    required = {
        "schema_version", "legacy", "source", "token", "task_id", "owner", "kind",
        "locks", "intent", "validation", "status", "created_at", "updated_at",
        "expires_at", "worktree", "baselines",
    }
    permitted = required | {"status_reason", "close_reason", "final_baselines", "baseline_changed", "stale_lock_authority_error"}
    if not required.issubset(claim) or set(claim) - permitted or claim.get("schema_version") != h.SCHEMA_VERSION:
        _fail("semantic claim body has an incomplete structured-claim schema")
    if claim.get("legacy") is not False or claim.get("source") != "structured":
        _fail("semantic claim body must be structured, not legacy")
    if claim.get("task_id") != task_id:
        _fail("semantic claim body task identity differs from object task")
    try:
        if not isinstance(claim.get("token"), str) or not isinstance(claim.get("task_id"), str):
            _fail("semantic claim token and task id must be strings")
        h.validate_id(claim["token"], "claim token")
        h.validate_id(task_id, "task id")
    except h.HarnessError as exc:
        raise SemanticClaimError(str(exc)) from exc
    if claim.get("status") not in h.CLAIM_STATUSES or not isinstance(claim.get("locks"), list):
        _fail("semantic claim body status or locks is invalid")
    for field in ("owner", "kind", "intent", "validation", "created_at", "updated_at", "expires_at", "worktree"):
        if not isinstance(claim.get(field), str):
            _fail(f"semantic claim {field} must be a string")
    if not isinstance(claim.get("baselines"), dict):
        _fail("semantic claim baselines must be an object")
    for field in ("status_reason", "close_reason", "stale_lock_authority_error"):
        if field in claim and not isinstance(claim[field], str):
            _fail(f"semantic claim {field} must be a string")
    for field in ("final_baselines", "baseline_changed"):
        if field in claim and not isinstance(claim[field], dict):
            _fail(f"semantic claim {field} must be an object")
    return claim


def validate_semantic_claim_object_payload(payload: Any, *, task_id: str) -> dict[str, Any]:
    """Validate the closed immutable payload registered as ``semantic_claim``."""

    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        _fail("semantic claim object payload schema is invalid")
    if payload.get("schema_version") != 1:
        _fail("semantic claim object payload schema version is unsupported")
    operation = payload.get("operation")
    if operation not in _OPERATIONS:
        _fail("semantic claim object operation is invalid")
    if payload.get("task_id") != task_id:
        _fail("semantic claim object task identity differs from wrapper")
    token = payload.get("token")
    try:
        if not isinstance(token, str) or not isinstance(payload.get("command_id"), str):
            _fail("semantic claim token and command id must be strings")
        h.validate_id(token, "claim token")
        h.validate_id(payload["command_id"], "semantic command id")
    except h.HarnessError as exc:
        raise SemanticClaimError(str(exc)) from exc
    _text(payload.get("recorded_at"), "recorded_at", 64)
    _digest(payload.get("expected_head_sha256"), "expected semantic head SHA-256")
    _text(payload.get("authority_ref"), "Chief authority reference")
    prior = _digest(payload.get("prior_object_sha256"), "prior object SHA-256")
    if (operation == "acquire") != (prior == _ZERO):
        _fail("semantic claim acquire must use zero prior object SHA-256")
    claim = _claim_body(payload.get("claim"), task_id=task_id)
    if claim["token"] != token:
        _fail("semantic claim token differs from its body")
    if operation == "status" and claim["status"] not in h.RESERVING_CLAIM_STATUSES:
        _fail("semantic claim status transition must remain reserving")
    if operation == "release" and claim["status"] not in h.TERMINAL_CLAIM_STATUSES:
        _fail("semantic claim release must be terminal")
    if operation == "acquire" and (claim["status"] != "active" or set(claim) - {key for key in claim if key not in {"status_reason", "close_reason", "final_baselines", "baseline_changed", "stale_lock_authority_error"}}):
        _fail("semantic claim acquisition may not carry lifecycle terminal fields")
    if operation == "status" and "status_reason" not in claim:
        _fail("semantic claim status transition requires status_reason")
    if operation == "release" and not {"close_reason", "final_baselines", "baseline_changed"}.issubset(claim):
        _fail("semantic claim release has incomplete terminal fields")
    return {
        "schema_version": 1, "operation": operation, "task_id": task_id,
        "token": token, "command_id": payload["command_id"],
        "recorded_at": payload["recorded_at"], "expected_head_sha256": payload["expected_head_sha256"],
        "authority_ref": payload["authority_ref"], "prior_object_sha256": prior,
        "claim": claim,
    }


def _namespace(state: Mapping[str, Any]) -> dict[str, Any]:
    value = state.get(CLAIM_NAMESPACE)
    if value is None:
        return {"schema_version": CLAIM_NAMESPACE_VERSION, "claims": []}
    if not isinstance(value, dict) or set(value) != _NAMESPACE_FIELDS:
        _fail("semantic claim projection namespace is invalid")
    if value.get("schema_version") != CLAIM_NAMESPACE_VERSION or not isinstance(value.get("claims"), list):
        _fail("semantic claim projection namespace version is invalid")
    if len(value["claims"]) > 4096:
        _fail("semantic claim projection exceeds claim bound")
    rows = []
    seen: set[str] = set()
    for row in value["claims"]:
        if not isinstance(row, dict) or set(row) != _ROW_FIELDS:
            _fail("semantic claim projection row is invalid")
        token = row.get("token")
        if not isinstance(token, str):
            _fail("semantic claim projection token must be a string")
        try:
            h.validate_id(token, "claim token")
            h.validate_id(str(row.get("command_id", "")), "semantic command id")
        except h.HarnessError as exc:
            raise SemanticClaimError(str(exc)) from exc
        if token in seen or row.get("operation") not in _OPERATIONS:
            _fail("semantic claim projection contains duplicate or invalid token")
        seen.add(token)
        if row.get("status") not in h.CLAIM_STATUSES or row.get("location") not in {"active", "archive"}:
            _fail("semantic claim projection status or location is invalid")
        _digest(row.get("object_sha256"), "claim object SHA-256")
        _digest(row.get("prior_object_sha256"), "prior object SHA-256")
        _text(row.get("binding_key"), "claim binding key", 512)
        _text(row.get("recorded_at"), "recorded_at", 64)
        _digest(row.get("lock_scope_sha256"), "claim lock scope SHA-256")
        rows.append(_clone(row))
    return {"schema_version": CLAIM_NAMESPACE_VERSION, "claims": rows}


def _side_authority(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _AUTHORITY_FIELDS:
        _fail("semantic claim side authority schema is invalid")
    if value.get("schema_version") != 1 or value.get("phase") not in {"pending", "committed"}:
        _fail("semantic claim side authority phase is invalid")
    if value.get("operation") not in _OPERATIONS:
        _fail("semantic claim side authority operation is invalid")
    for key in ("object_sha256", "binding_sha256", "expected_head_sha256", "planned_event_sha256", "result_projection_sha256"):
        _digest(value.get(key), key.replace("_", " "))
    try:
        h.validate_id(str(value.get("command_id", "")), "semantic command id")
    except h.HarnessError as exc:
        raise SemanticClaimError(str(exc)) from exc
    _text(value.get("recorded_at"), "recorded_at", 64)
    return _clone(value)


def _read_side(path: Path, *, task_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        side = h.load_json(path)
    except h.HarnessError as exc:
        raise SemanticClaimError(f"cannot read semantic claim side record: {exc}") from exc
    if not isinstance(side, dict) or "semantic_authority" not in side:
        _fail("semantic claim side record is missing semantic authority")
    claim = dict(side)
    authority = claim.pop("semantic_authority")
    return _claim_body(claim, task_id=task_id), _side_authority(authority)


def _side_payload(claim: Mapping[str, Any], authority: Mapping[str, Any]) -> dict[str, Any]:
    return {**_clone(claim), "semantic_authority": _clone(authority)}


def _side_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return exactly the bytes produced by ``h.atomic_write_json``.

    Side records are an intentionally narrow crash-recovery protocol.  Parsed
    JSON equality is insufficient here: accepting a differently serialized
    existing record would turn an overwrite retry into an unverified mutation.
    """

    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _side_is_exact(path: Path, payload: Mapping[str, Any]) -> bool:
    try:
        return path.read_bytes() == _side_bytes(payload)
    except OSError:
        return False


def _create_or_accept_exact_side(path: Path, payload: Mapping[str, Any]) -> None:
    """Create a side record, or accept only the exact retry bytes."""

    encoded = _side_bytes(payload)
    if path.exists():
        if _side_is_exact(path, payload):
            return
        _fail(f"semantic claim side record already exists with divergent bytes: {path}")
    try:
        h.atomic_create_bytes(path, encoded)
    except h.HarnessError as exc:
        if _side_is_exact(path, payload):
            return
        raise SemanticClaimError(
            f"cannot create exact semantic claim side record: {path}: {exc}"
        ) from exc
    if not _side_is_exact(path, payload):
        _fail(f"semantic claim side record changed during creation: {path}")


def _stage_pending_side(
    path: Path,
    *,
    pending_claim: Mapping[str, Any],
    pending_authority: Mapping[str, Any],
    prior_claim: Mapping[str, Any] | None,
    prior_authority: Mapping[str, Any] | None,
) -> None:
    """Stage pending side data without accepting an arbitrary overwrite."""

    pending = _side_payload(pending_claim, pending_authority)
    if _side_is_exact(path, pending):
        return
    if prior_claim is None or prior_authority is None:
        _fail(f"semantic claim pending side lacks authenticated prior record: {path}")
    prior = _side_payload(prior_claim, prior_authority)
    if not _side_is_exact(path, prior):
        _fail(f"semantic claim side record differs from authenticated prior bytes: {path}")
    try:
        h.atomic_write_bytes(path, _side_bytes(pending))
    except h.HarnessError as exc:
        raise SemanticClaimError(f"cannot stage pending semantic claim side record: {path}: {exc}") from exc
    if not _side_is_exact(path, pending):
        _fail(f"semantic claim side record changed during pending staging: {path}")


def _repair_committed_active_side(
    path: Path,
    *,
    claim: Mapping[str, Any],
    pending_authority: Mapping[str, Any],
    committed_authority: Mapping[str, Any],
) -> None:
    """After event publication, replace only the exact pending side record."""

    pending = _side_payload(claim, pending_authority)
    committed = _side_payload(claim, committed_authority)
    if _side_is_exact(path, committed):
        return
    if not _side_is_exact(path, pending):
        _fail(f"semantic claim committed repair found divergent side bytes: {path}")
    try:
        h.atomic_write_bytes(path, _side_bytes(committed))
    except h.HarnessError as exc:
        raise SemanticClaimError(f"cannot repair committed semantic claim side record: {path}: {exc}") from exc
    if not _side_is_exact(path, committed):
        _fail(f"semantic claim side record changed during committed repair: {path}")


def _repair_release_archive_then_unlink(
    active_path: Path,
    archive_path: Path,
    *,
    active_claim: Mapping[str, Any],
    pending_authority: Mapping[str, Any],
    archive_claim: Mapping[str, Any],
    committed_authority: Mapping[str, Any],
) -> None:
    """Publish/verify archive before unlinking only exact pending active bytes."""

    archive = _side_payload(archive_claim, committed_authority)
    _create_or_accept_exact_side(archive_path, archive)
    if not active_path.exists():
        return
    pending = _side_payload(active_claim, pending_authority)
    if not _side_is_exact(active_path, pending):
        _fail(f"semantic claim release found divergent active side bytes: {active_path}")
    try:
        active_path.unlink()
    except OSError as exc:
        raise SemanticClaimError(f"cannot remove exact pending semantic claim side record: {active_path}: {exc}") from exc


def _binding_key(token: str, command: str) -> str:
    return f"{token}:{command}"


def _row(payload: Mapping[str, Any], object_sha: str, *, location: str) -> dict[str, Any]:
    claim = payload["claim"]
    return {
        "token": payload["token"], "operation": payload["operation"], "status": claim["status"],
        "location": location, "object_sha256": object_sha,
        "prior_object_sha256": payload["prior_object_sha256"],
        "binding_key": _binding_key(payload["token"], payload["command_id"]),
        "command_id": payload["command_id"], "recorded_at": payload["recorded_at"],
        "lock_scope_sha256": _sha(sorted(claim["locks"])),
    }


def _result_state(state: Mapping[str, Any], row: Mapping[str, Any], *, add_claim: bool, recorded_at: str) -> dict[str, Any]:
    result = events.projection_domain(state) if events.SEMANTIC_ENVELOPE_KEY in state else _clone(state)
    namespace = _namespace(result)
    namespace["claims"] = [item for item in namespace["claims"] if item["token"] != row["token"]]
    namespace["claims"].append(_clone(row))
    namespace["claims"].sort(key=lambda item: item["token"])
    result[CLAIM_NAMESPACE] = namespace
    if add_claim:
        claims = list(result.get("claims", []))
        if row["token"] not in claims:
            claims.append(row["token"])
        result["claims"] = claims
    # ``bump_task`` deliberately reads wall time for legacy mutations.  A
    # semantic retry must reproduce the same result projection byte-for-byte.
    result["revision"] = int(result.get("revision", 0)) + 1
    result["updated_at"] = recorded_at
    result["checkpoint_required"] = True
    return result


def _ledger(paths: h.HarnessPaths, task_id: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    # Local imports keep semantic_objects -> semantic_claims validation acyclic.
    from . import semantic_store as store
    if not h.is_semantic_v2_task(paths, task_id):
        _fail("semantic claim lifecycle requires a semantic-v2 task")
    chain = store._read_ledger(paths, task_id)  # exact, authenticated private reader
    return store, chain, store.load_semantic_task(paths, task_id)


def _objects_report(paths: h.HarnessPaths, task_id: str, chain: list[dict[str, Any]]) -> dict[str, Any]:
    from . import semantic_objects
    return semantic_objects.inspect_semantic_objects(paths, task_id, chain)


def _retry_payload(paths: h.HarnessPaths, task_id: str, command: str, chain: list[dict[str, Any]]) -> tuple[dict[str, Any], str] | None:
    report = _objects_report(paths, task_id, chain)
    found: list[tuple[dict[str, Any], str]] = []
    for wrapped in report["objects"]:
        if wrapped.get("object_type") != "semantic_claim":
            continue
        payload = validate_semantic_claim_object_payload(wrapped.get("payload"), task_id=task_id)
        if payload["command_id"] == command:
            found.append((payload, wrapped["object_sha256"]))
    if len(found) > 1:
        _fail("semantic command id has multiple claim objects")
    return found[0] if found else None


def _authority(payload: Mapping[str, Any], object_sha: str, binding: Mapping[str, Any], *, phase: str) -> dict[str, Any]:
    return {
        "schema_version": 1, "phase": phase, "operation": payload["operation"],
        "object_sha256": object_sha, "binding_sha256": binding["binding_sha256"],
        "expected_head_sha256": binding["expected_semantic_head_sha256"],
        "planned_event_sha256": binding["planned_event_sha256"],
        "result_projection_sha256": binding["result_projection_sha256"],
        "command_id": payload["command_id"], "recorded_at": payload["recorded_at"],
    }


def _pending_claim(
    paths: h.HarnessPaths,
    task_id: str,
    chain: list[dict[str, Any]],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the body that must remain in the active sidecar while pending."""

    if payload["operation"] != "release":
        return _clone(payload["claim"])
    prior_sha = payload["prior_object_sha256"]
    report = _objects_report(paths, task_id, chain)
    previous = [item for item in report["objects"] if item.get("object_sha256") == prior_sha]
    if len(previous) != 1 or previous[0].get("object_type") != "semantic_claim":
        _fail("semantic release pending side lacks its immutable prior object")
    prior = validate_semantic_claim_object_payload(previous[0].get("payload"), task_id=task_id)
    if prior["token"] != payload["token"]:
        _fail("semantic release prior object token differs from pending claim")
    return prior["claim"]


def _historical_side_repair_is_safe(
    paths: h.HarnessPaths,
    task_id: str,
    chain: list[dict[str, Any]],
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
    object_sha: str,
) -> bool:
    """Permit only derived repair after an unrelated successor event."""

    try:
        event_index = next(index for index, item in enumerate(chain) if item is event)
    except StopIteration:
        return False
    report = _objects_report(paths, task_id, chain)
    objects = {item.get("object_sha256"): item for item in report["objects"]}
    bindings_by_event = {
        item.get("planned_event_sha256"): item
        for item in report["bindings"]
        if item.get("classification") == "committed" and item.get("binding_kind") == "semantic_claim_lifecycle"
    }
    for successor in chain[event_index + 1:]:
        binding = bindings_by_event.get(successor.get("event_sha256"))
        if binding is None:
            continue
        referenced = [objects.get(digest) for digest in binding.get("object_sha256s", [])]
        if len(referenced) != 1 or referenced[0] is None:
            return False
        try:
            successor_payload = validate_semantic_claim_object_payload(
                referenced[0].get("payload"), task_id=task_id
            )
        except SemanticClaimError:
            return False
        if successor_payload["token"] == payload["token"]:
            return False
    state = events.replay_events(chain)
    row = _row(payload, object_sha, location="archive" if payload["operation"] == "release" else "active")
    try:
        rows = [item for item in _namespace(state)["claims"] if item["token"] == payload["token"]]
    except SemanticClaimError:
        return False
    return rows == [row]


def _request_matches(payload: Mapping[str, Any], args: Any) -> None:
    """Reject a command-id reuse before accepting a recovered intent.

    Baselines are measured data and intentionally are *not* recomputed here.
    The caller supplied semantic intent, however, must still be identical.
    """

    command, head, recorded, authority_ref = _command_args(args)
    claim = payload["claim"]
    if (payload["command_id"], payload["recorded_at"], payload["expected_head_sha256"], payload["authority_ref"]) != (command, recorded, head, authority_ref):
        _fail("semantic command id was reused with different command metadata")
    if payload["operation"] == "acquire":
        supplied_locks = list(dict.fromkeys(h.normalize_lock(item) for item in getattr(args, "lock", [])))
        fields = {"owner": getattr(args, "owner", None), "kind": getattr(args, "kind", None), "intent": getattr(args, "intent", None), "validation": getattr(args, "validation", None), "expires_at": getattr(args, "expires_at", None)}
        if supplied_locks != claim["locks"] or any(claim[key] != value for key, value in fields.items()):
            _fail("semantic command id was reused for different claim acquisition")
    elif payload["operation"] == "status":
        if getattr(args, "status", None) != claim["status"] or getattr(args, "reason", None) != claim.get("status_reason"):
            _fail("semantic command id was reused for different claim status transition")
    elif payload["operation"] == "release":
        if getattr(args, "status", None) != claim["status"] or getattr(args, "reason", None) != claim.get("close_reason"):
            _fail("semantic command id was reused for different claim release")


def _prepare_binding(paths: h.HarnessPaths, task_id: str, state: Mapping[str, Any], chain: list[dict[str, Any],], payload: Mapping[str, Any], object_sha: str, expected: str, authority: str, *, add_claim: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    from . import semantic_objects
    if payload["expected_head_sha256"] != expected or payload["authority_ref"] != authority:
        _fail("semantic claim object authority differs from transaction request")
    if chain[-1]["event_sha256"] != expected:
        _fail("semantic expected head does not match current authority")
    row = _row(payload, object_sha, location="archive" if payload["operation"] == "release" else "active")
    result = _result_state(state, row, add_claim=add_claim, recorded_at=payload["recorded_at"])
    proposed = events.create_transition_event(
        chain[-1], state, result, event_type=_EVENT_TYPES[payload["operation"]],
        command_id=payload["command_id"], recorded_at=payload["recorded_at"], authority_ref=authority,
    )
    binding = semantic_objects.create_semantic_binding(
        binding_kind="semantic_claim_lifecycle", task_id=task_id,
        binding_key=row["binding_key"], expected_semantic_head_sha256=expected,
        planned_event_sha256=proposed["event_sha256"],
        result_projection_sha256=events.canonical_sha256(result), object_sha256s=[object_sha],
    )
    return result, binding


def _commit(paths: h.HarnessPaths, task_id: str, state: Mapping[str, Any], chain: list[dict[str, Any]], payload: Mapping[str, Any], object_sha: str, expected: str, authority_ref: str, *, add_claim: bool, prior_side: tuple[Mapping[str, Any], Mapping[str, Any]] | None = None) -> dict[str, Any]:
    from . import semantic_objects
    if payload["expected_head_sha256"] != expected or payload["authority_ref"] != authority_ref:
        _fail("semantic claim object authority differs from transaction request")
    store, _unused, _current = _ledger(paths, task_id)
    # A retry cannot silently take a successor head; refresh solely to decide
    # whether the command already committed.
    chain = store._read_ledger(paths, task_id)
    published = [item for item in chain if item.get("command_id") == payload["command_id"]]
    if len(published) > 1:
        _fail("semantic command id is not unique")
    if published:
        event = published[0]
        if event.get("event_type") != _EVENT_TYPES[payload["operation"]] or event.get("prev_event_sha256") != expected:
            _fail("semantic command id was reused for different lifecycle semantics")
        # A terminal retry may repair an append-before-projection crash.  Once
        # another event exists, however, this command can repair only its
        # derived sidecar and only when no later lifecycle transition replaced
        # the token.
        if event is chain[-1]:
            store.repair_semantic_projection(paths, task_id)
            chain = store._read_ledger(paths, task_id)
        elif not _historical_side_repair_is_safe(paths, task_id, chain, event, payload, object_sha):
            _fail("historical semantic claim retry is no longer safe to repair")
        report = _objects_report(paths, task_id, chain)
        matching = [item for item in report["bindings"] if item.get("binding_key") == _binding_key(payload["token"], payload["command_id"])]
        if len(matching) != 1 or matching[0].get("classification") != "committed" or object_sha not in matching[0].get("object_sha256s", []):
            _fail("published semantic claim command lacks its committed binding")
        binding = matching[0]
        if binding.get("planned_event_sha256") != event.get("event_sha256"):
            _fail("published semantic claim event differs from its binding")
        pending_authority = _authority(payload, object_sha, binding, phase="pending")
        committed_authority = _authority(payload, object_sha, binding, phase="committed")
        pending_claim = _pending_claim(paths, task_id, chain, payload)
        if payload["operation"] == "release":
            archive = h.claim_path(paths, payload["token"], active=False)
            active = h.claim_path(paths, payload["token"], active=True)
            _repair_release_archive_then_unlink(
                active, archive, active_claim=pending_claim,
                pending_authority=pending_authority, archive_claim=payload["claim"],
                committed_authority=committed_authority,
            )
        else:
            _repair_committed_active_side(
                h.claim_path(paths, payload["token"], active=True), claim=pending_claim,
                pending_authority=pending_authority, committed_authority=committed_authority,
            )
        _authenticated(paths, task_id)
        h.write_index(paths)
        return {"token": payload["token"], "status": payload["claim"]["status"], "object_sha256": object_sha, "binding_sha256": binding["binding_sha256"], "event_sha256": event["event_sha256"], "idempotent_replay": True}
    result, binding = _prepare_binding(paths, task_id, state, chain, payload, object_sha, expected, authority_ref, add_claim=add_claim)
    semantic_objects.publish_semantic_object(paths, semantic_objects.create_semantic_object(
        object_type="semantic_claim", task_id=task_id,
        object_identity=f"{payload['token']}:{payload['command_id']}", payload=payload,
    ))
    # Every pre-event intent is staged in the active file.  In particular a
    # release must not create an archive (nor remove the active reservation)
    # until its immutable lifecycle event has committed.
    side_path = h.claim_path(paths, payload["token"], active=True)
    pending_authority = _authority(payload, object_sha, binding, phase="pending")
    pending_claim = _pending_claim(paths, task_id, chain, payload)
    if payload["operation"] == "acquire":
        _create_or_accept_exact_side(side_path, _side_payload(pending_claim, pending_authority))
    else:
        if prior_side is None:
            # Object-only retries can be resumed before staging only when the
            # old active side still authenticates against the prior event.
            prior_task, prior_claim, prior_authority = _current_active(paths, payload["token"])
            if prior_task != task_id:
                _fail("semantic claim prior side task differs from transaction")
        else:
            # The caller's mappings are authenticated inputs, but take a
            # detached snapshot before passing them to the side-write path.
            prior_claim, prior_authority = dict(prior_side[0]), dict(prior_side[1])
        _stage_pending_side(
            side_path, pending_claim=pending_claim, pending_authority=pending_authority,
            prior_claim=prior_claim, prior_authority=prior_authority,
        )
    semantic_objects.publish_semantic_binding(paths, binding, chain)
    appended = store.append_semantic_transition(
        paths, task_id, result, event_type=_EVENT_TYPES[payload["operation"]],
        command_id=payload["command_id"], recorded_at=payload["recorded_at"], authority_ref=authority_ref,
        expected_head_sha256=expected,
    )
    # Event publication is the irreversible point.  Side repair is safe and
    # required on an exact retry; release archives before unlinking active.
    if payload["operation"] == "release":
        archive = h.claim_path(paths, payload["token"], active=False)
        active = h.claim_path(paths, payload["token"], active=True)
        _repair_release_archive_then_unlink(
            active, archive, active_claim=pending_claim, pending_authority=pending_authority,
            archive_claim=payload["claim"],
            committed_authority=_authority(payload, object_sha, binding, phase="committed"),
        )
    else:
        _repair_committed_active_side(
            side_path, claim=pending_claim, pending_authority=pending_authority,
            committed_authority=_authority(payload, object_sha, binding, phase="committed"),
        )
    _authenticated(paths, task_id)
    h.write_index(paths)
    return {"token": payload["token"], "status": payload["claim"]["status"], "object_sha256": object_sha, "binding_sha256": binding["binding_sha256"], "event_sha256": appended.event["event_sha256"], "idempotent_replay": appended.idempotent_replay}


def _existing_or_payload(paths: h.HarnessPaths, args: Any, task_id: str, chain: list[dict[str, Any]], builder: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], str, bool]:
    command, _expected, _recorded, _authority = _command_args(args)
    retry = _retry_payload(paths, task_id, command, chain)
    if retry is not None:
        return retry[0], retry[1], True
    payload = builder()
    from . import semantic_objects
    object_value = semantic_objects.create_semantic_object(
        object_type="semantic_claim", task_id=task_id,
        object_identity=f"{payload['token']}:{command}", payload=payload,
    )
    return payload, object_value["object_sha256"], False


def acquire_semantic_claim(args: Any, paths: h.HarnessPaths, *, require_plan_ready: Callable[[h.HarnessPaths, dict[str, Any], str], None]) -> dict[str, Any]:
    command, expected, recorded, authority = _command_args(args)
    task_id = h.validate_id(_text(getattr(args, "task", None), "task id"), "task id")
    store, chain, state = _ledger(paths, task_id)
    token = h.validate_id(_text(getattr(args, "token", None), "claim token"), "claim token")
    if getattr(args, "adopt_legacy", False) or getattr(args, "adoption_evidence", None) or getattr(args, "ack_legacy_ambiguity", False):
        _fail("semantic claim acquisition does not permit legacy adoption")
    def build() -> dict[str, Any]:
        if state.get("status") not in {"active", "blocked"} or state.get("profile") == "mini":
            _fail("task is not eligible to acquire a semantic claim")
        require_plan_ready(paths, state, "acquire claim")
        locks = list(dict.fromkeys(h.normalize_lock(item) for item in getattr(args, "lock", [])))
        if not locks:
            _fail("at least one --lock is required")
        root = h.validated_state_worktree(paths, state)
        locks = list(dict.fromkeys(h.validate_lock_identity(paths, lock, repo_root=root) for lock in locks))
        if h.claim_path(paths, token, True).exists() or h.claim_path(paths, token, False).exists():
            _fail(f"claim token already exists: {token}")
        conflicts = h.find_conflicts(paths, locks, repo_root=root)
        if conflicts:
            _fail("claim conflict(s): " + json.dumps(conflicts, sort_keys=True))
        planned = h.admit_new_claim_locks(paths, locks, repo_root=root, allow_nonexistent=bool(getattr(args, "allow_nonexistent", False)))
        baselines = h.baselines_for_locks(paths, locks, repo_root=root)
        for lock in planned:
            baselines[lock]["planned"] = True
        claim = {"schema_version": h.SCHEMA_VERSION, "legacy": False, "source": "structured", "token": token, "task_id": task_id,
            "owner": _text(getattr(args, "owner", None), "owner"), "kind": _text(getattr(args, "kind", None), "kind"), "locks": locks,
            "intent": _text(getattr(args, "intent", None), "intent"), "validation": _text(getattr(args, "validation", None), "validation"),
            "status": "active", "created_at": recorded, "updated_at": recorded, "expires_at": getattr(args, "expires_at", None),
            "worktree": state.get("worktree"), "baselines": baselines}
        return validate_semantic_claim_object_payload({"schema_version": 1, "operation": "acquire", "task_id": task_id, "token": token, "command_id": command, "recorded_at": recorded, "expected_head_sha256": expected, "authority_ref": authority, "prior_object_sha256": _ZERO, "claim": claim}, task_id=task_id)
    payload, object_sha, retry = _existing_or_payload(paths, args, task_id, chain, build)
    if retry:
        _request_matches(payload, args)
        # Never recapture baselines, but a detached object does not reserve
        # scope.  Recheck current admission before binding it to the ledger.
        root = h.validated_state_worktree(paths, state)
        require_plan_ready(paths, state, "acquire claim")
        conflicts = h.find_conflicts(paths, payload["claim"]["locks"], ignore_token=token, repo_root=root)
        if conflicts:
            _fail("claim conflict(s) prevent semantic object retry: " + json.dumps(conflicts, sort_keys=True))
    if payload["operation"] != "acquire" or payload["token"] != token or payload["command_id"] != command:
        _fail("semantic command id was reused for different claim acquisition")
    return _commit(paths, task_id, state, chain, payload, object_sha, expected, authority, add_claim=True)


def _current_active(paths: h.HarnessPaths, token: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    path = h.claim_path(paths, token, active=True)
    if not path.exists():
        _fail(f"semantic active claim is missing: {token}")
    raw = h.load_json(path)
    task_id = raw.get("task_id") if isinstance(raw, dict) else None
    if not isinstance(task_id, str):
        _fail("semantic active claim has no task identity")
    # Do not let a raw file seed a new typed event.  It must first agree with
    # the current committed object/binding/ledger projection.
    authenticated = {item["token"]: item for item in _authenticated(paths, task_id)}
    if token not in authenticated:
        _fail(f"semantic active claim is not authenticated: {token}")
    claim, side = _read_side(path, task_id=task_id)
    if claim != authenticated[token] or side.get("phase") != "committed":
        _fail(f"semantic active claim differs from committed authority: {token}")
    return task_id, claim, side


def set_semantic_claim_status(args: Any, paths: h.HarnessPaths) -> dict[str, Any]:
    command, expected, recorded, authority = _command_args(args)
    token = h.validate_id(_text(getattr(args, "token", None), "claim token"), "claim token")
    retry_task = getattr(args, "task", None)
    if isinstance(retry_task, str) and retry_task.strip():
        retry_task = h.validate_id(retry_task.strip(), "task id")
        _store, retry_chain, retry_state = _ledger(paths, retry_task)
        retry = _retry_payload(paths, retry_task, command, retry_chain)
        if retry is not None:
            payload, object_sha = retry
            if payload["operation"] != "status" or payload["token"] != token:
                _fail("semantic command id was reused for different claim status transition")
            _request_matches(payload, args)
            return _commit(paths, retry_task, retry_state, retry_chain, payload, object_sha, expected, authority, add_claim=False)
    task_id, active, active_authority = _current_active(paths, token)
    _store, chain, state = _ledger(paths, task_id)
    status = getattr(args, "status", None)
    if status not in h.RESERVING_CLAIM_STATUSES:
        _fail("set semantic claim status accepts active or blocked only")
    def build() -> dict[str, Any]:
        previous = active_authority["object_sha256"]
        claim = _clone(active); claim.update({"status": status, "status_reason": _text(getattr(args, "reason", None), "reason"), "updated_at": recorded})
        return validate_semantic_claim_object_payload({"schema_version": 1, "operation": "status", "task_id": task_id, "token": token, "command_id": command, "recorded_at": recorded, "expected_head_sha256": expected, "authority_ref": authority, "prior_object_sha256": previous, "claim": claim}, task_id=task_id)
    payload, object_sha, _retry = _existing_or_payload(paths, args, task_id, chain, build)
    if _retry:
        _request_matches(payload, args)
    if payload["operation"] != "status" or payload["token"] != token:
        _fail("semantic command id was reused for different claim status transition")
    return _commit(paths, task_id, state, chain, payload, object_sha, expected, authority, add_claim=False, prior_side=(active, active_authority))


def release_semantic_claim(args: Any, paths: h.HarnessPaths, *, uncovered_dependencies_after_release: Callable[[h.HarnessPaths, dict[str, Any], str], list[str]]) -> dict[str, Any]:
    command, expected, recorded, authority = _command_args(args)
    token = h.validate_id(_text(getattr(args, "token", None), "claim token"), "claim token")
    retry_task = getattr(args, "task", None)
    if isinstance(retry_task, str) and retry_task.strip():
        retry_task = h.validate_id(retry_task.strip(), "task id")
        _store, retry_chain, retry_state = _ledger(paths, retry_task)
        retry = _retry_payload(paths, retry_task, command, retry_chain)
        if retry is not None:
            payload, object_sha = retry
            if payload["operation"] != "release" or payload["token"] != token:
                _fail("semantic command id was reused for different claim release")
            _request_matches(payload, args)
            return _commit(paths, retry_task, retry_state, retry_chain, payload, object_sha, expected, authority, add_claim=False)
    task_id, active, active_authority = _current_active(paths, token)
    _store, chain, state = _ledger(paths, task_id)
    status = getattr(args, "status", None)
    if status not in h.TERMINAL_CLAIM_STATUSES:
        _fail("release status must be done, released, or stale")
    def build() -> dict[str, Any]:
        uncovered = uncovered_dependencies_after_release(paths, state, token)
        if uncovered:
            _fail("cannot release claim while active work depends on its locks: " + "; ".join(uncovered))
        claim = _clone(active); claim.update({"status": status, "close_reason": _text(getattr(args, "reason", None), "reason"), "updated_at": recorded})
        stale_error = ""
        try:
            claim["final_baselines"] = h.baselines_for_locks(paths, claim["locks"], repo_root=h.validated_state_worktree(paths, state))
        except h.HarnessError as exc:
            if status != "stale":
                raise SemanticClaimError(f"claim lock authority cannot be revalidated: {exc}") from exc
            claim["final_baselines"] = {}; stale_error = str(exc); claim["stale_lock_authority_error"] = stale_error
        changed = {lock: baseline != claim["final_baselines"].get(lock) for lock, baseline in claim.get("baselines", {}).items()}
        if stale_error:
            changed.update({str(lock): True for lock in claim["locks"]})
        claim["baseline_changed"] = changed
        return validate_semantic_claim_object_payload({"schema_version": 1, "operation": "release", "task_id": task_id, "token": token, "command_id": command, "recorded_at": recorded, "expected_head_sha256": expected, "authority_ref": authority, "prior_object_sha256": active_authority["object_sha256"], "claim": claim}, task_id=task_id)
    payload, object_sha, _retry = _existing_or_payload(paths, args, task_id, chain, build)
    if _retry:
        _request_matches(payload, args)
    if payload["operation"] != "release" or payload["token"] != token:
        _fail("semantic command id was reused for different claim release")
    return _commit(paths, task_id, state, chain, payload, object_sha, expected, authority, add_claim=False, prior_side=(active, active_authority))


def _authenticated(paths: h.HarnessPaths, task_id: str) -> list[dict[str, Any]]:
    _store, chain, state = _ledger(paths, task_id)
    report = _objects_report(paths, task_id, chain)
    if report.get("pending_binding_sha256s"):
        _fail("semantic claim authority is unavailable while semantic bindings are pending")
    namespace = _namespace(state)
    bindings = {item["binding_sha256"]: item for item in report["bindings"] if item["classification"] == "committed" and item["binding_kind"] == "semantic_claim_lifecycle"}
    objects = {item["object_sha256"]: item for item in report["objects"]}
    bindings_by_event = {item["planned_event_sha256"]: item for item in bindings.values()}
    latest: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
    for index, event in enumerate(chain):
        binding = bindings_by_event.get(event["event_sha256"])
        if binding is None:
            continue
        if event.get("event_type") not in set(_EVENT_TYPES.values()) or event.get("command_id") is None:
            _fail("semantic claim binding event has invalid type or command")
        if event["event_type"] not in _EVENT_TYPES.values():
            _fail("semantic claim binding has non-claim event")
        referenced = [objects.get(digest) for digest in binding["object_sha256s"]]
        if len(referenced) != 1:
            _fail("semantic claim binding must reference exactly one claim object")
        referenced_object = referenced[0]
        if referenced_object is None or referenced_object.get("object_type") != "semantic_claim":
            _fail("semantic claim binding must reference exactly one claim object")
        object_sha = referenced_object["object_sha256"]
        payload = validate_semantic_claim_object_payload(referenced_object.get("payload"), task_id=task_id)
        if (
            event["event_type"] != _EVENT_TYPES[payload["operation"]]
            or event["command_id"] != payload["command_id"]
            or event["recorded_at"] != payload["recorded_at"]
            or event["authority_ref"] != payload["authority_ref"]
            or event["prev_event_sha256"] != payload["expected_head_sha256"]
        ):
            _fail("semantic claim event differs from its bound object")
        if binding["binding_key"] != _binding_key(payload["token"], payload["command_id"]):
            _fail("semantic claim binding key differs from its bound object")
        if referenced_object.get("object_identity") != f"{payload['token']}:{payload['command_id']}":
            _fail("semantic claim object identity differs from its bound object")
        projected = events.replay_events(chain[: index + 1])
        if binding["result_projection_sha256"] != events.canonical_sha256(events.projection_domain(projected)):
            _fail("semantic claim binding result differs from its event projection")
        expected_row = _row(payload, object_sha, location="archive" if payload["operation"] == "release" else "active")
        prior_projection = events.replay_events(chain[:index])
        expected_projection = _result_state(
            prior_projection, expected_row, add_claim=payload["operation"] == "acquire",
            recorded_at=payload["recorded_at"],
        )
        if events.canonical_json_bytes(events.projection_domain(projected)) != events.canonical_json_bytes(expected_projection):
            _fail("semantic claim event projection differs from its complete expected result")
        at_event = _namespace(projected)
        actual_rows = [row for row in at_event["claims"] if row["token"] == payload["token"]]
        if actual_rows != [expected_row]:
            _fail(f"semantic claim {payload['token']} event projection row is not exact")
        previous = latest.get(payload["token"])
        if payload["operation"] == "acquire":
            if previous is not None or payload["prior_object_sha256"] != _ZERO:
                _fail(f"semantic claim {payload['token']} acquisition prior chain is invalid")
        elif previous is None or payload["prior_object_sha256"] != previous[0]["object_sha256"]:
            _fail(f"semantic claim {payload['token']} prior object chain is invalid")
        latest[payload["token"]] = (expected_row, payload, binding)

    final_rows = {row["token"]: row for row in namespace["claims"]}
    if final_rows != {token: value[0] for token, value in latest.items()}:
        _fail("semantic claim current namespace differs from typed event history")
    current_claims = state.get("claims")
    if (
        not isinstance(current_claims, list)
        or any(not isinstance(token, str) for token in current_claims)
        or len(set(current_claims)) != len(current_claims)
        or set(current_claims) != set(final_rows)
    ):
        _fail("task claims backlink differs from semantic claim projection")
    # A raw side file is never inert for a migrated task: it may still reserve
    # a lock through the legacy conflict iterator.  Reject every unprojected,
    # duplicate, or legacy-looking task-owned row at the authenticated boundary.
    observed_sides: dict[str, set[str]] = {}
    scanned_sides = 0
    for location, directory in (("active", paths.claims_active), ("archive", paths.claims_archive)):
        if not directory.is_dir():
            continue
        for candidate in directory.glob("*.json"):
            scanned_sides += 1
            if scanned_sides > h.TREE_IDENTITY_SCAN_MAX_ENTRIES:
                _fail("semantic claim side scan exceeds bounded entry limit")
            raw = h.load_json(candidate)
            if not isinstance(raw, dict) or raw.get("task_id") != task_id:
                continue
            token = raw.get("token")
            if not isinstance(token, str) or token not in final_rows:
                _fail("semantic task has an unprojected claim side record")
            if "semantic_authority" not in raw:
                _fail(f"semantic claim {token} side record lacks semantic authority")
            observed_sides.setdefault(token, set()).add(location)
    for token, row in final_rows.items():
        expected_location = row["location"]
        if observed_sides.get(token) != {expected_location}:
            _fail(f"semantic claim {token} active/archive side location diverges from projection")
    rows: list[dict[str, Any]] = []
    for token, (row, payload, binding) in sorted(latest.items()):
        path = h.claim_path(paths, row["token"], active=row["location"] == "active")
        if not path.exists():
            _fail(f"semantic claim {row['token']} {row['location']} side record is missing")
        claim, side = _read_side(path, task_id=task_id)
        if side.get("phase") != "committed" or claim != payload["claim"] or side != _authority(payload, row["object_sha256"], binding, phase="committed"):
            _fail(f"semantic claim {row['token']} side record is not exact committed authority")
        if not _side_is_exact(path, _side_payload(claim, side)):
            _fail(f"semantic claim {row['token']} side record bytes are not exact")
        opposite = h.claim_path(paths, row["token"], active=row["location"] != "active")
        if opposite.exists():
            _fail(f"semantic claim {row['token']} has duplicate active/archive side records")
        rows.append(_clone(claim))
    return rows


def authenticated_claims_for_task(paths: h.HarnessPaths, state: dict[str, Any]) -> list[dict[str, Any]]:
    task_id = state.get("task_id") if isinstance(state, dict) else None
    if not isinstance(task_id, str):
        _fail("authenticated claim lookup requires task state")
    return _authenticated(paths, task_id)


def authenticated_claims_owned_by_task(paths: h.HarnessPaths, task_id: str) -> list[dict[str, Any]]:
    return _authenticated(paths, h.validate_id(task_id, "task id"))


def semantic_claim_integrity_errors(paths: h.HarnessPaths, task_id: str) -> list[str]:
    try:
        _authenticated(paths, h.validate_id(task_id, "task id"))
        return []
    except (SemanticClaimError, h.HarnessError, events.SemanticEventError, TypeError, ValueError, KeyError) as exc:
        return [str(exc)]
