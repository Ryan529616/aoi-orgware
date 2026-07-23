"""Chief-fenced semantic runtime for one optional Codex transport launch.

The controller deliberately receives a sealed one-shot permit, never a Chief
credential.  Every externally observed transport milestone is first rendered
as a closed, hash-only contract object and then appended through AOI's normal
semantic binding/ledger transaction.  This module starts no process; the stdio
adapter supplies the already-scrubbed wire digests to :func:`record_milestone`.
"""
from __future__ import annotations

import contextlib
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from . import codex_transport_contracts as contracts
from . import codex_transport_authority as launch_authority
from . import codex_transport_projection as projection
from . import harnesslib as h
from . import packet_integrity as packet_integrity_impl
from . import semantic_events as semantic
from . import semantic_objects as objects
from . import semantic_store as store
from . import state_lookup
from . import transition_permits as permits


ISSUANCE_DIRECTORY = "codex-transport-issuances-v1"
ISSUANCE_SCHEMA_VERSION = 2
RUN_LOCK_DIRECTORY = "codex-transport-run-locks-v1"
MAX_ISSUANCE_BYTES = 64 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")


class CodexTransportRuntimeError(h.HarnessError):
    """The one-shot launch cannot be authenticated or advanced safely."""


def _fail(message: str, exc: BaseException | None = None) -> CodexTransportRuntimeError:
    return CodexTransportRuntimeError(message if exc is None else f"{message}: {exc}")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise CodexTransportRuntimeError(f"{label} is not lowercase SHA-256")
    return value


def _records(event_chain: Iterable[Mapping[str, Any]], task_id: str) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    try:
        records = [dict(event) for event in event_chain]
        state = semantic.replay_events(records)
        domain = semantic.projection_domain(state)
        if domain.get("task_id") != h.validate_id(task_id, "task id"):
            raise CodexTransportRuntimeError("semantic event chain belongs to another task")
        head = state[semantic.SEMANTIC_ENVELOPE_KEY]["head_event_sha256"]
        return records, state, _sha(head, "semantic ledger head")
    except CodexTransportRuntimeError:
        raise
    except (h.HarnessError, semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("semantic event chain is invalid", exc) from exc


def _live_records(paths: h.HarnessPaths, task_id: str, event_chain: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    records, state, head = _records(event_chain, task_id)
    try:
        live = store.semantic_head(paths, task_id)
    except (h.HarnessError, store.SemanticStoreError) as exc:
        raise _fail("cannot authenticate live semantic head", exc) from exc
    if live["event_sha256"] != head or live["sequence"] != records[-1]["sequence"]:
        raise CodexTransportRuntimeError("semantic event chain does not match live head")
    return records, state, head


def _launch_id(value: Any) -> str:
    try:
        return h.validate_id(value, "Codex launch id")
    except h.HarnessError as exc:
        raise _fail("Codex launch id is invalid", exc) from exc


def _authority_ref(launch_id: str) -> str:
    return f"codex-transport:{launch_id}"


def _wrap(object_type: str, task_id: str, identity: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return objects.create_semantic_object(
            object_type=object_type, task_id=task_id, object_identity=identity, payload=dict(payload)
        )
    except objects.SemanticObjectError as exc:
        raise _fail("cannot seal Codex transport object", exc) from exc


def _event_for(
    intent: Mapping[str, Any], reservation: Mapping[str, Any], *, event_id: str,
    sequence: int, previous: str, event_type: str, correlation: Mapping[str, Any],
    wire_event_sha256: str | None = None, response_sha256: str | None = None,
    request_id: str | None = None, request_bytes_sha256: str | None = None,
    item_type: str | None = None, payload_size_bytes: int | None = None,
    fault_kind: str | None = None, fault_evidence_sha256: str | None = None,
    fault_evidence_size_bytes: int | None = None,
) -> dict[str, Any]:
    pending = event_type.endswith("_pending")
    if event_type == "reserved":
        size = 0
    else:
        size = 1 if payload_size_bytes is None else payload_size_bytes
    if pending or event_type == "launch_unknown":
        if request_id is None or request_bytes_sha256 is None:
            raise CodexTransportRuntimeError("request milestone needs exact request id and bytes digest")
    method = contracts.previous_event_method(event_type)
    status = {"item_completed": "completed", "completed": "completed", "failed": "failed", "interrupted": "interrupted", "launch_unknown": "unknown", "runtime_unknown": "unknown"}.get(event_type, "observed")
    state = {"reserved": "reserved", "process_start_pending": "reserved", "process_started": "reserved", "initialize_send_pending": "reserved", "initialized": "reserved", "thread_start_send_pending": "reserved", "thread_started": "thread_started", "turn_start_send_pending": "thread_started", "turn_started": "turn_started", "interrupt_send_pending": "turn_started", "interrupt_observed": "turn_started", "item_started": "turn_started", "item_completed": "turn_started", "completed": "completed", "failed": "failed", "interrupted": "interrupted", "launch_unknown": "launch_unknown", "runtime_unknown": "runtime_unknown"}[event_type]
    try:
        return contracts.seal_journal_event({
            "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
            "event_id": event_id, "sequence": sequence, "prev_event_sha256": previous,
            "launch_intent_sha256": intent["intent_sha256"], "reservation_sha256": reservation["reservation_sha256"],
            "event_type": event_type, "state": state, "wire_method": method,
            "wire_event_sha256": wire_event_sha256, "payload_size_bytes": size, "item_type": item_type,
            "status": status, "request_id": request_id, "request_bytes_sha256": request_bytes_sha256,
            "response_sha256": response_sha256, "fault_kind": fault_kind,
            "fault_evidence_sha256": fault_evidence_sha256,
            "fault_evidence_size_bytes": fault_evidence_size_bytes,
            "correlation": dict(correlation),
        })
    except contracts.CodexTransportContractError as exc:
        raise _fail("Codex transport milestone is invalid", exc) from exc


def _validate_launch_material(
    task_id: str,
    intent: Mapping[str, Any],
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    authority_contract: Mapping[str, Any],
    launch_id: str,
    head: str,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        checked_intent = contracts.validate_launch_intent(intent)
        checked_authority = contracts.validate_launch_authority(authority_contract)
        pair = permits.validate_decision_permit_pair(decision, permit)
        checked_decision, checked_permit = pair["decision"], pair["permit"]
        params = checked_permit["parameters"]
        binding = checked_intent["routing_binding"]
        if checked_intent["task_id"] != task_id or checked_permit["task_id"] != task_id:
            raise CodexTransportRuntimeError("launch material task identity differs")
        if checked_permit["action"] != "codex.launch" or params["launch_id"] != launch_id:
            raise CodexTransportRuntimeError("permit does not authorize this exact launch")
        if checked_permit["expected_semantic_head_sha256"] != head or checked_intent["expected_semantic_head_sha256"] != head:
            raise CodexTransportRuntimeError("launch expected semantic head drifted")
        if params["packet_id"] != checked_intent["packet_id"]:
            raise CodexTransportRuntimeError(
                "permit packet_id differs from launch intent"
            )
        if params["routing_binding"] != binding:
            raise CodexTransportRuntimeError(
                "permit routing_binding differs from launch intent"
            )
        if params["launch_intent_sha256"] != checked_intent["intent_sha256"]:
            raise CodexTransportRuntimeError("permit does not bind launch intent")
        if (
            checked_authority["task_id"] != task_id
            or checked_authority["packet_id"] != checked_intent["packet_id"]
            or checked_authority["routing_binding"] != binding
            or checked_authority["expected_semantic_head_sha256"] != head
            or checked_authority["launch_intent_sha256"]
            != checked_intent["intent_sha256"]
        ):
            raise CodexTransportRuntimeError(
                "launch authority does not bind the exact launch intent and head"
            )
        arm_expires = h.parse_tz_aware_time(checked_authority["expires_at"])
        permit_expires = h.parse_tz_aware_time(checked_permit["expires_at"])
        if arm_expires is None or permit_expires is None:
            raise CodexTransportRuntimeError("launch authority expiry is invalid")
        if permit_expires > arm_expires:
            raise CodexTransportRuntimeError(
                "launch permit expires after the canonical packet arm"
            )
        if now >= arm_expires:
            raise CodexTransportRuntimeError("canonical packet arm is expired")
        permits.validate_transition_consumption(checked_permit, task_id=task_id, semantic_head_sha256=head,
            decision_sha256=checked_decision["decision_sha256"], action="codex.launch", target_ids=[launch_id],
            parameters=params, chief_authority=checked_permit["chief_authority"], current_time=now)
        return checked_intent, checked_decision, checked_permit, checked_authority
    except (contracts.CodexTransportContractError, permits.TransitionPermitError) as exc:
        raise _fail("Codex launch material is invalid", exc) from exc


def prepare_codex_launch_transaction(*, task_id: str, event_chain: Iterable[Mapping[str, Any],], intent: Mapping[str, Any], decision: Mapping[str, Any], permit: Mapping[str, Any], launch_authority_contract: Mapping[str, Any], launch_id: str, command_id: str, recorded_at: str, current_time: datetime) -> dict[str, Any]:
    """Prepare the immutable reserved milestone without Chief credentials."""
    task_id = h.validate_id(task_id, "task id")
    records, state, head = _records(event_chain, task_id)
    checked_intent, checked_decision, checked_permit, checked_authority = _validate_launch_material(task_id, intent, decision, permit, launch_authority_contract, _launch_id(launch_id), head, current_time)
    reservation = contracts.seal_reservation({"contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1, "reservation_id": launch_id,
        "launch_intent_sha256": checked_intent["intent_sha256"], "permit_sha256": checked_permit["permit_sha256"], "runtime_pin": checked_intent["runtime_pin"], "state": "reserved", "correlation": {"thread_id": None, "turn_id": None, "item_id": None}})
    reserved = _event_for(checked_intent, reservation, event_id=f"{launch_id}:reserved", sequence=1, previous=contracts.ZERO_SHA256, event_type="reserved", correlation={"thread_id": None, "turn_id": None, "item_id": None})
    owned = launch_authority.reserve_packet_for_codex_launch(
        state,
        intent=checked_intent,
        permit=checked_permit,
        reservation=reservation,
        launch_authority=checked_authority,
        launch_id=launch_id,
        reservation_effective_at=recorded_at,
    )
    domain = projection.advance_codex_transport_projection(owned, launch_id=launch_id, intent=checked_intent, reservation=reservation, journal=[reserved])
    planned = semantic.create_transition_event(records[-1], state, domain, event_type="codex_transport_reserved", command_id=h.validate_id(command_id, "command id"), recorded_at=recorded_at, authority_ref=_authority_ref(launch_id))
    wrapped = [
        _wrap("codex_launch_intent", task_id, f"{launch_id}:intent", checked_intent),
        _wrap("codex_launch_authority", task_id, f"{launch_id}:authority", checked_authority),
        _wrap("transition_decision", task_id, f"{launch_id}:decision", checked_decision),
        _wrap("transition_permit", task_id, f"{launch_id}:permit", checked_permit),
        _wrap("codex_transport_receipt", task_id, f"{launch_id}:reservation", {"receipt_kind": "reservation", "receipt": reservation}),
        _wrap("codex_transport_receipt", task_id, f"{launch_id}:reserved", {"receipt_kind": "journal_event", "receipt": reserved}),
    ]
    binding = objects.create_semantic_binding(binding_kind="codex_launch_reservation", task_id=task_id, binding_key=launch_id, expected_semantic_head_sha256=head, planned_event_sha256=planned["event_sha256"], result_projection_sha256=semantic.canonical_sha256(domain), object_sha256s=sorted(row["object_sha256"] for row in wrapped))
    return {"task_id": task_id, "launch_id": launch_id, "command_id": command_id, "recorded_at": recorded_at, "expected_semantic_head_sha256": head, "intent": checked_intent, "decision": checked_decision, "permit": checked_permit, "launch_authority": checked_authority, "reservation": reservation, "journal": [reserved], "objects": wrapped, "binding": binding, "result_domain": domain, "planned_event_sha256": planned["event_sha256"]}


def _issuance_path(paths: h.HarnessPaths, task_id: str, permit_sha256: str) -> Path:
    return h.task_dir(paths, task_id) / ISSUANCE_DIRECTORY / f"{_sha(permit_sha256, 'permit SHA-256')}.json"


def _ensure_issuance_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    """Create the private marker root without accepting links or residue."""
    task = h.task_dir(paths, task_id)
    directory = task / ISSUANCE_DIRECTORY
    try:
        if not directory.exists() and not h._path_is_link_like(directory):
            directory.mkdir(mode=0o700)
            if os.name != "nt":
                directory.chmod(0o700)
        canonical = h.canonicalize_no_link_traversal(directory, "Codex issuance directory")
        metadata = canonical.lstat()
        if canonical != directory or h._path_is_link_like(canonical) or not stat.S_ISDIR(metadata.st_mode):
            raise CodexTransportRuntimeError("Codex issuance directory is unsafe")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CodexTransportRuntimeError("Codex issuance directory is not private")
        return canonical
    except CodexTransportRuntimeError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _fail("cannot create Codex issuance directory", exc) from exc


def _run_lock_path(paths: h.HarnessPaths, task_id: str, launch_id: str) -> Path:
    identity = _launch_id(launch_id)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return h.task_dir(paths, task_id) / RUN_LOCK_DIRECTORY / f"{digest}.lock"


def _ensure_run_lock_file(
    paths: h.HarnessPaths, task_id: str, launch_id: str
) -> Path:
    """Create the one immutable lock inode while the AOI state lock is held."""

    h._require_chief_lock(paths)
    directory = h.task_dir(paths, task_id) / RUN_LOCK_DIRECTORY
    try:
        if not directory.exists() and not h._path_is_link_like(directory):
            directory.mkdir(mode=0o700)
            if os.name != "nt":
                directory.chmod(0o700)
        canonical_directory = h.canonicalize_no_link_traversal(
            directory, "Codex run-lock directory"
        )
        h.validate_existing_regular_directory(
            canonical_directory, "Codex run-lock directory"
        )
        if canonical_directory != directory:
            raise CodexTransportRuntimeError(
                "Codex run-lock directory is non-canonical"
            )
        metadata = directory.lstat()
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CodexTransportRuntimeError(
                "Codex run-lock directory is not private"
            )
        path = _run_lock_path(paths, task_id, launch_id)
        if h._path_is_link_like(path):
            raise CodexTransportRuntimeError("Codex run lock is link-like")
        if not path.exists():
            h.atomic_create_bytes(path, b"\0")
            if os.name != "nt":
                path.chmod(0o600)
        canonical = h.canonicalize_no_link_traversal(path, "Codex run lock")
        metadata = canonical.lstat()
        if (
            canonical != path
            or h._path_is_link_like(canonical)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != 1
            or canonical.read_bytes() != b"\0"
        ):
            raise CodexTransportRuntimeError("Codex run lock is unsafe")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CodexTransportRuntimeError("Codex run lock is not private")
        return canonical
    except CodexTransportRuntimeError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _fail("cannot prepare Codex run lock", exc) from exc


@contextlib.contextmanager
def codex_launch_process_lock(
    paths: h.HarnessPaths, *, task_id: str, launch_id: str
) -> Iterator[None]:
    """Serialize the complete controller lifetime for one launch id.

    The file is created only by Chief-side issuance.  ``run`` merely locks the
    authenticated inode, so a controller never receives a reusable authority.
    This lock must never be acquired while AOI's global state lock is held.
    """

    path = _run_lock_path(paths, task_id, launch_id)
    try:
        canonical = h.canonicalize_no_link_traversal(path, "Codex run lock")
        if canonical != path:
            raise CodexTransportRuntimeError("Codex run lock is non-canonical")
        mode = "r+b" if os.name == "nt" else "rb"
        with path.open(mode) as handle:
            before = path.lstat()
            opened = os.fstat(handle.fileno())
            for metadata in (before, opened):
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size != 1
                    or (
                        os.name != "nt"
                        and stat.S_IMODE(metadata.st_mode) & 0o077
                    )
                ):
                    raise CodexTransportRuntimeError("Codex run lock is unsafe")
            if h._lock_identity(before) != h._lock_identity(opened):
                raise CodexTransportRuntimeError(
                    "Codex run lock changed while being opened"
                )
            h._acquire_state_lock(handle)
            acquisition_pid = os.getpid()
            try:
                current = path.lstat()
                locked = os.fstat(handle.fileno())
                if (
                    h._lock_identity(current) != h._lock_identity(locked)
                    or h.canonicalize_no_link_traversal(path, "Codex run lock")
                    != path
                ):
                    raise CodexTransportRuntimeError(
                        "Codex run lock changed during acquisition"
                    )
                handle.seek(0)
                if handle.read(2) != b"\0":
                    raise CodexTransportRuntimeError(
                        "Codex run lock sentinel changed"
                    )
                yield
            finally:
                if os.getpid() == acquisition_pid:
                    h._release_state_lock(handle)
    except CodexTransportRuntimeError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _fail("cannot acquire Codex run lock", exc) from exc


def _marker(
    tx: Mapping[str, Any],
    issuer: Mapping[str, Any],
    *,
    pre_git_endpoint_cas_sha256: str | None,
) -> dict[str, Any]:
    base = {"schema_version": ISSUANCE_SCHEMA_VERSION, "task_id": tx["task_id"], "launch_id": tx["launch_id"], "command_id": tx["command_id"], "recorded_at": tx["recorded_at"], "permit_sha256": tx["permit"]["permit_sha256"], "intent_sha256": tx["intent"]["intent_sha256"], "launch_authority_sha256": tx["launch_authority"]["launch_authority_sha256"], "reservation_sha256": tx["reservation"]["reservation_sha256"], "expected_semantic_head_sha256": tx["expected_semantic_head_sha256"], "planned_event_sha256": tx["planned_event_sha256"], "binding_sha256": tx["binding"]["binding_sha256"], "pre_git_endpoint_cas_sha256": pre_git_endpoint_cas_sha256, "issuer_chief_authority": {"session_id": issuer["session_id"], "epoch": issuer["epoch"]}}
    return {**base, "issuance_sha256": semantic.canonical_sha256(base, max_bytes=MAX_ISSUANCE_BYTES)}


def _read_marker(paths: h.HarnessPaths, task_id: str, permit_sha256: str) -> dict[str, Any]:
    path = _issuance_path(paths, task_id, permit_sha256)
    try:
        if h.canonicalize_no_link_traversal(path, "Codex issuance marker") != path:
            raise CodexTransportRuntimeError("issuance marker path is non-canonical")
        metadata = path.lstat()
        if h._path_is_link_like(path) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CodexTransportRuntimeError("issuance marker is not one regular file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CodexTransportRuntimeError("issuance marker is not private")
        raw = path.read_bytes()
        if len(raw) > MAX_ISSUANCE_BYTES or path.lstat().st_size != len(raw):
            raise CodexTransportRuntimeError("issuance marker changed while being read")
        value = json.loads(raw.decode("utf-8"))
        canonical = semantic.canonical_json_bytes(value, max_bytes=MAX_ISSUANCE_BYTES)
        if raw != canonical or not isinstance(value, dict):
            raise CodexTransportRuntimeError("issuance marker is not canonical")
        base = {key: value[key] for key in value if key != "issuance_sha256"}
        if set(base) != {"schema_version", "task_id", "launch_id", "command_id", "recorded_at", "permit_sha256", "intent_sha256", "launch_authority_sha256", "reservation_sha256", "expected_semantic_head_sha256", "planned_event_sha256", "binding_sha256", "pre_git_endpoint_cas_sha256", "issuer_chief_authority"} or value.get("schema_version") != ISSUANCE_SCHEMA_VERSION or value.get("issuance_sha256") != semantic.canonical_sha256(base, max_bytes=MAX_ISSUANCE_BYTES):
            raise CodexTransportRuntimeError("issuance marker schema or digest is invalid")
        issuer = value["issuer_chief_authority"]
        if (
            not isinstance(issuer, dict)
            or set(issuer) != {"session_id", "epoch"}
            or not isinstance(issuer.get("session_id"), str)
            or not issuer["session_id"]
            or type(issuer.get("epoch")) is not int
            or issuer["epoch"] < 1
        ):
            raise CodexTransportRuntimeError(
                "issuance marker issuing Chief authority is invalid"
            )
        _sha(value["launch_authority_sha256"], "launch authority SHA-256")
        pre_endpoint = value["pre_git_endpoint_cas_sha256"]
        if pre_endpoint is not None:
            _sha(pre_endpoint, "pre Git endpoint CAS SHA-256")
        if value["task_id"] != task_id or path.name != f"{permit_sha256}.json":
            raise CodexTransportRuntimeError("issuance marker identity is invalid")
        return value
    except CodexTransportRuntimeError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, semantic.SemanticEventError, KeyError, TypeError) as exc:
        raise _fail("cannot read immutable Codex issuance marker", exc) from exc


def _derived_transition_identity(
    marker: Mapping[str, Any], *, ordinal: int, kind: str, content_sha256: str
) -> tuple[str, str]:
    """Derive retry-stable semantic command/time from immutable issuance bytes."""

    if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1:
        raise CodexTransportRuntimeError("Codex transition ordinal is invalid")
    try:
        base = h.parse_tz_aware_time(marker["recorded_at"])
    except (KeyError, TypeError, h.HarnessError) as exc:
        raise _fail("issuance marker recorded_at is invalid", exc) from exc
    if base is None:
        raise CodexTransportRuntimeError("issuance marker recorded_at is invalid")
    recorded_at = (
        (base.astimezone(UTC) + timedelta(microseconds=ordinal))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    command_id = h.validate_id(
        f"codex-{kind}-{ordinal}-{_sha(content_sha256, 'transition content SHA-256')[:24]}",
        "command id",
    )
    return command_id, recorded_at


def _transition_base(
    records: list[dict[str, Any]],
    command_id: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Return the exact pre-command ledger prefix for a fresh call or retry.

    Semantic-store retries are accepted only while the command is the live
    ledger head.  Reconstructing that command's base projection here lets the
    transport layer reproduce the exact result domain and binding bytes before
    delegating the final idempotence check to ``append_semantic_transition``.
    """

    matches = [index for index, event in enumerate(records) if event.get("command_id") == command_id]
    if not matches:
        state = semantic.replay_events(records)
        return records, state, _sha(records[-1]["event_sha256"], "semantic ledger head")
    if len(matches) != 1 or matches[0] != len(records) - 1:
        raise CodexTransportRuntimeError(
            "Codex transport semantic command exists but is not the unique live head"
        )
    base_records = records[:-1]
    if not base_records:
        raise CodexTransportRuntimeError(
            "Codex transport semantic command cannot replace the genesis event"
        )
    try:
        state = semantic.replay_events(base_records)
    except semantic.SemanticEventError as exc:
        raise _fail("Codex transport retry base is invalid", exc) from exc
    return (
        base_records,
        state,
        _sha(base_records[-1]["event_sha256"], "semantic retry base head"),
    )


def issue_codex_launch_transaction(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    *,
    chief_session_id: str,
    chief_epoch: int,
    chief_token: str,
    current_time: datetime,
    packet_integrity_services: packet_integrity_impl.PacketIntegrityServices,
    pre_git_endpoint_cas_sha256: str | None = None,
) -> dict[str, Any]:
    """Chief-only issuance: objects first, immutable marker last."""
    h._require_chief_lock(paths)
    tx = dict(transaction)
    records, _state, head = _live_records(paths, tx["task_id"], event_chain)
    if head != tx["expected_semantic_head_sha256"]:
        raise CodexTransportRuntimeError("issuance semantic head drifted")
    try:
        live = h.require_chief_authority(paths, session_id=chief_session_id, epoch=chief_epoch, token=chief_token, now=current_time)
    except h.HarnessError as exc:
        raise _fail("Codex issuance requires live Chief authority", exc) from exc
    canonical_authority = launch_authority.require_canonical_launch_authority(
        paths,
        task_id=tx["task_id"],
        intent=tx["intent"],
        event_chain=records,
        current_time=current_time,
        packet_integrity_services=packet_integrity_services,
    )
    if tx.get("launch_authority") != canonical_authority:
        raise CodexTransportRuntimeError(
            "prepared launch authority differs from canonical live packet arm"
        )
    # Rebuild rather than trust a caller's stale nested objects.
    rebuilt = prepare_codex_launch_transaction(task_id=tx["task_id"], event_chain=records, intent=tx["intent"], decision=tx["decision"], permit=tx["permit"], launch_authority_contract=canonical_authority, launch_id=tx["launch_id"], command_id=tx["command_id"], recorded_at=tx["recorded_at"], current_time=current_time)
    if pre_git_endpoint_cas_sha256 is None:
        raise CodexTransportRuntimeError(
            f"{rebuilt['intent']['sandbox']} issuance requires a pre Git "
            "endpoint CAS SHA-256"
        )
    pre_git_endpoint_cas_sha256 = _sha(
        pre_git_endpoint_cas_sha256, "pre Git endpoint CAS SHA-256"
    )
    permit_authority = rebuilt["permit"]["chief_authority"]
    if (
        permit_authority["session_id"] != live["session_id"]
        or permit_authority["epoch"] != live["epoch"]
    ):
        raise CodexTransportRuntimeError(
            "Codex launch permit Chief authority differs from the live Chief session"
        )
    for wrapped in rebuilt["objects"]:
        objects.publish_semantic_object(paths, wrapped)
    marker = _marker(
        rebuilt,
        live,
        pre_git_endpoint_cas_sha256=pre_git_endpoint_cas_sha256,
    )
    _ensure_issuance_directory(paths, rebuilt["task_id"])
    _ensure_run_lock_file(paths, rebuilt["task_id"], rebuilt["launch_id"])
    raw = semantic.canonical_json_bytes(marker, max_bytes=MAX_ISSUANCE_BYTES)
    destination = _issuance_path(paths, rebuilt["task_id"], rebuilt["permit"]["permit_sha256"])
    idempotent_replay = False
    try:
        h.atomic_create_bytes(destination, raw)
    except h.HarnessError as exc:
        if _read_marker(paths, rebuilt["task_id"], rebuilt["permit"]["permit_sha256"]) != marker:
            raise _fail("Codex issuance marker collided", exc) from exc
        idempotent_replay = True
    return {"issuance_sha256": marker["issuance_sha256"], "permit_sha256": marker["permit_sha256"], "idempotent_replay": idempotent_replay}


def _deduplicate_exact_payloads(
    values: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse repeated references to identical content-addressed objects."""

    result: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for value in values:
        raw = semantic.canonical_json_bytes(dict(value))
        if raw in seen:
            continue
        seen.add(raw)
        result.append(dict(value))
    return result


def _issued_launch_material(
    paths: h.HarnessPaths,
    task_id: str,
    records: Iterable[Mapping[str, Any]],
    marker: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load the issued objects; never use the controller's mutable copy."""

    try:
        report = objects.inspect_semantic_objects(paths, task_id, records)
        intents = _deduplicate_exact_payloads([
            row["payload"] for row in report["objects"]
            if row["object_type"] == "codex_launch_intent"
            and isinstance(row.get("payload"), dict)
            and row["payload"].get("intent_sha256") == marker["intent_sha256"]
        ])
        permits_found = _deduplicate_exact_payloads([
            row["payload"] for row in report["objects"]
            if row["object_type"] == "transition_permit"
            and isinstance(row.get("payload"), dict)
            and row["payload"].get("permit_sha256") == marker["permit_sha256"]
        ])
        if len(intents) != 1 or len(permits_found) != 1:
            raise CodexTransportRuntimeError("issued launch objects are missing or ambiguous")
        authorities = _deduplicate_exact_payloads([
            row["payload"]
            for row in report["objects"]
            if row["object_type"] == "codex_launch_authority"
            and isinstance(row.get("payload"), dict)
            and row["payload"].get("launch_authority_sha256")
            == marker["launch_authority_sha256"]
        ])
        if len(authorities) != 1:
            raise CodexTransportRuntimeError(
                "issued launch authority is missing or ambiguous"
            )
        permit = permits_found[0]
        decisions = _deduplicate_exact_payloads([
            row["payload"] for row in report["objects"]
            if row["object_type"] == "transition_decision"
            and isinstance(row.get("payload"), dict)
            and row["payload"].get("decision_sha256") == permit.get("decision_sha256")
        ])
        if len(decisions) != 1:
            raise CodexTransportRuntimeError("issued launch decision is missing or ambiguous")
        return (
            dict(intents[0]),
            dict(decisions[0]),
            dict(permit),
            dict(authorities[0]),
        )
    except CodexTransportRuntimeError:
        raise
    except (objects.SemanticObjectError, KeyError, TypeError) as exc:
        raise _fail("cannot authenticate issued Codex launch material", exc) from exc


def _reservation_base_records(
    records: list[dict[str, Any]], marker: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Return the exact pre-reservation prefix, accepting only an exact retry."""

    expected = marker["expected_semantic_head_sha256"]
    matches = [index for index, event in enumerate(records) if event["event_sha256"] == expected]
    if len(matches) != 1:
        raise CodexTransportRuntimeError("issued launch base semantic head is not in the live ledger")
    index = matches[0]
    trailing = records[index + 1:]
    if trailing and (len(trailing) != 1 or trailing[0]["event_sha256"] != marker["planned_event_sha256"]):
        raise CodexTransportRuntimeError("issued launch reservation is no longer the terminal semantic transition")
    return records[:index + 1]


def _has_exact_pending_reservation_binding(
    paths: h.HarnessPaths,
    task_id: str,
    records: list[dict[str, Any]],
    marker: Mapping[str, Any],
) -> bool:
    """Authenticate the binding-only crash witness for one issued launch.

    Publishing the immutable reservation binding is the point at which an
    otherwise fresh launch becomes recovery work.  The semantic event may not
    yet exist if the writer crashed between the two durable publications.  A
    different pending binding must never relax this launch's permit expiry.
    """

    try:
        report = objects.inspect_semantic_objects(paths, task_id, records)
    except objects.SemanticObjectError as exc:
        raise _fail("cannot authenticate Codex reservation binding", exc) from exc
    pending = report["pending_binding_sha256s"]
    if not pending:
        return False
    expected = _sha(marker["binding_sha256"], "reservation binding SHA-256")
    if pending != [expected]:
        raise CodexTransportRuntimeError(
            "pending semantic binding differs from the issued Codex reservation"
        )
    matches = [
        binding
        for binding in report["bindings"]
        if binding["binding_sha256"] == expected
    ]
    if len(matches) != 1:
        raise CodexTransportRuntimeError(
            "issued Codex reservation binding is missing or ambiguous"
        )
    binding = matches[0]
    if (
        binding["classification"] != "pending"
        or binding["binding_kind"] != "codex_launch_reservation"
        or binding["binding_key"] != marker["launch_id"]
        or binding["expected_semantic_head_sha256"]
        != marker["expected_semantic_head_sha256"]
        or binding["planned_event_sha256"] != marker["planned_event_sha256"]
    ):
        raise CodexTransportRuntimeError(
            "pending Codex reservation binding differs from its issuance marker"
        )
    return True


def _require_exact_transaction(candidate: Mapping[str, Any], rebuilt: Mapping[str, Any]) -> None:
    """Reject a controller-supplied after-image that differs from issuance."""

    try:
        if semantic.canonical_json_bytes(dict(candidate)) != semantic.canonical_json_bytes(dict(rebuilt)):
            raise CodexTransportRuntimeError("controller transaction differs from authenticated issued reservation")
    except CodexTransportRuntimeError:
        raise
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("controller transaction cannot be canonicalized", exc) from exc


def reconstruct_issued_launch_transaction(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    permit_sha256: str,
    event_chain: Iterable[Mapping[str, Any]],
    current_time: datetime,
) -> dict[str, Any]:
    """Rebuild one issued reservation from AOI objects/marker, without Chief credentials."""

    task_id = h.validate_id(task_id, "task id")
    records, _state, _head = _live_records(paths, task_id, event_chain)
    marker = _read_marker(paths, task_id, permit_sha256)
    base_records = _reservation_base_records(records, marker)
    intent, decision, permit, authority_contract = _issued_launch_material(
        paths, task_id, records, marker
    )
    reservation_committed = len(records) > len(base_records)
    binding_only_recovery = not reservation_committed and _has_exact_pending_reservation_binding(
        paths, task_id, records, marker
    )
    validation_time = current_time
    if reservation_committed or binding_only_recovery:
        # The exact committed event or its authenticated pending binding proves
        # that publication of this one-shot reservation already began while
        # valid.  Reconstructing the same still-terminal command after expiry
        # is recovery, not a fresh launch authorization.
        expires_at = h.parse_tz_aware_time(permit.get("expires_at"))
        if expires_at is None:
            raise CodexTransportRuntimeError("issued launch permit expiry is invalid")
        if validation_time >= expires_at:
            validation_time = expires_at - timedelta(microseconds=1)
    rebuilt = prepare_codex_launch_transaction(
        task_id=task_id,
        event_chain=base_records,
        intent=intent,
        decision=decision,
        permit=permit,
        launch_authority_contract=authority_contract,
        launch_id=marker["launch_id"],
        command_id=marker["command_id"],
        recorded_at=marker["recorded_at"],
        current_time=validation_time,
    )
    if (
        rebuilt["intent"]["intent_sha256"] != marker["intent_sha256"]
        or rebuilt["launch_authority"]["launch_authority_sha256"]
        != marker["launch_authority_sha256"]
        or rebuilt["reservation"]["reservation_sha256"] != marker["reservation_sha256"]
        or rebuilt["binding"]["binding_sha256"] != marker["binding_sha256"]
        or rebuilt["planned_event_sha256"] != marker["planned_event_sha256"]
    ):
        raise CodexTransportRuntimeError(
            "issued launch marker does not bind reconstructed reservation"
        )
    return rebuilt


def inspect_codex_launch_issuance(
    paths: h.HarnessPaths, *, task_id: str, permit_sha256: str
) -> dict[str, Any]:
    """Return one authenticated hash-only issuance marker without authority."""

    task_id = h.validate_id(task_id, "task id")
    return dict(_read_marker(paths, task_id, permit_sha256))


def reserve_codex_launch(paths: h.HarnessPaths, transaction: Mapping[str, Any], event_chain: Iterable[Mapping[str, Any]], *, current_time: datetime, packet_integrity_services: packet_integrity_impl.PacketIntegrityServices) -> dict[str, Any]:
    """Consume an issued permit and commit only the reserved after-image.

    This function takes no Chief credential.  Its exact semantic command is
    safely retryable after response loss; it never restarts a runtime process.
    """
    h._require_chief_lock(paths)
    candidate = dict(transaction)
    try:
        task_id = h.validate_id(candidate["task_id"], "task id")
        permit_sha256 = _sha(candidate["permit"]["permit_sha256"], "permit SHA-256")
    except (KeyError, TypeError, h.HarnessError) as exc:
        raise _fail("reservation request lacks a task and permit identity", exc) from exc
    records, _state, _head = _live_records(paths, task_id, event_chain)
    marker = _read_marker(paths, task_id, permit_sha256)
    base_records = _reservation_base_records(records, marker)
    binding_only_recovery = (
        len(records) == len(base_records)
        and _has_exact_pending_reservation_binding(paths, task_id, records, marker)
    )
    if len(records) == len(base_records) and not binding_only_recovery:
        intent, _decision, _permit, issued_authority = _issued_launch_material(
            paths, task_id, records, marker
        )
        canonical_authority = launch_authority.require_canonical_launch_authority(
            paths,
            task_id=task_id,
            intent=intent,
            event_chain=records,
            current_time=current_time,
            packet_integrity_services=packet_integrity_services,
        )
        if canonical_authority != issued_authority:
            raise CodexTransportRuntimeError(
                "issued launch authority drifted before permit consumption"
            )
    rebuilt = reconstruct_issued_launch_transaction(
        paths,
        task_id=task_id,
        permit_sha256=permit_sha256,
        event_chain=records,
        current_time=current_time,
    )
    _require_exact_transaction(candidate, rebuilt)
    for wrapped in rebuilt["objects"]:
        objects.publish_semantic_object(paths, wrapped)
    objects.publish_semantic_binding(paths, rebuilt["binding"], records)
    result = store.append_semantic_transition(paths, task_id, rebuilt["result_domain"], event_type="codex_transport_reserved", command_id=rebuilt["command_id"], recorded_at=rebuilt["recorded_at"], authority_ref=_authority_ref(rebuilt["launch_id"]), expected_head_sha256=rebuilt["expected_semantic_head_sha256"])
    return {"semantic_event_sha256": result.event["event_sha256"], "reservation_sha256": rebuilt["reservation"]["reservation_sha256"], "idempotent_replay": result.idempotent_replay}


def record_milestone(paths: h.HarnessPaths, *, task_id: str, launch_id: str, intent: Mapping[str, Any], reservation: Mapping[str, Any], journal: Iterable[Mapping[str, Any]], milestone: Mapping[str, Any], event_chain: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Persist one already-observed milestone; it cannot launch or retry Codex."""
    h._require_chief_lock(paths)
    records, _state, _head = _live_records(paths, task_id, event_chain)
    prior = [contracts.validate_journal_event(event) for event in journal]
    try:
        next_journal = contracts.append_transport_journal_event(prior, milestone)
        checked_intent = contracts.validate_launch_intent(intent); checked_reservation = contracts.validate_reservation(reservation)
        marker = _read_marker(paths, task_id, checked_reservation["permit_sha256"])
        command_id, recorded_at = _derived_transition_identity(
            marker,
            ordinal=len(next_journal),
            kind="milestone",
            content_sha256=next_journal[-1]["event_sha256"],
        )
        base_records, base_state, base_head = _transition_base(records, command_id)
        domain = projection.advance_codex_transport_projection(base_state, launch_id=_launch_id(launch_id), intent=checked_intent, reservation=checked_reservation, journal=next_journal)
        planned = semantic.create_transition_event(base_records[-1], base_state, domain, event_type="codex_transport_milestone", command_id=h.validate_id(command_id, "command id"), recorded_at=recorded_at, authority_ref=_authority_ref(launch_id))
    except (contracts.CodexTransportContractError, projection.CodexTransportProjectionError, semantic.SemanticEventError, h.HarnessError) as exc:
        raise _fail("Codex transport milestone cannot advance", exc) from exc
    wrapped = _wrap("codex_transport_receipt", task_id, f"{launch_id}:journal:{milestone['event_sha256']}", {"receipt_kind": "journal_event", "receipt": dict(milestone)})
    objects.publish_semantic_object(paths, wrapped)
    binding = objects.create_semantic_binding(binding_kind="codex_transport_milestone", task_id=task_id, binding_key=f"{launch_id}:journal:{milestone['event_sha256']}", expected_semantic_head_sha256=base_head, planned_event_sha256=planned["event_sha256"], result_projection_sha256=semantic.canonical_sha256(domain), object_sha256s=sorted([wrapped["object_sha256"]]))
    objects.publish_semantic_binding(paths, binding, records)
    result = store.append_semantic_transition(paths, task_id, domain, event_type="codex_transport_milestone", command_id=command_id, recorded_at=recorded_at, authority_ref=_authority_ref(launch_id), expected_head_sha256=base_head)
    return {"journal": next_journal, "semantic_event_sha256": result.event["event_sha256"], "idempotent_replay": result.idempotent_replay}


def publish_terminal_receipt(paths: h.HarnessPaths, *, task_id: str, launch_id: str, intent: Mapping[str, Any], reservation: Mapping[str, Any], journal: Iterable[Mapping[str, Any]], receipt: Mapping[str, Any], event_chain: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Publish the terminal receipt as a separate, crash-recoverable step."""
    h._require_chief_lock(paths)
    records, _state, _head = _live_records(paths, task_id, event_chain)
    checked_journal = [contracts.validate_journal_event(event) for event in journal]
    try:
        checked_intent = contracts.validate_launch_intent(intent)
        checked_reservation = contracts.validate_reservation(reservation)
        checked_receipt = contracts.validate_terminal_receipt_against_journal(receipt, checked_journal)
        marker = _read_marker(paths, task_id, checked_reservation["permit_sha256"])
        command_id, recorded_at = _derived_transition_identity(
            marker,
            ordinal=len(checked_journal) + 1,
            kind="terminal",
            content_sha256=checked_receipt["receipt_sha256"],
        )
        base_records, base_state, base_head = _transition_base(records, command_id)
        domain = projection.advance_codex_transport_projection(base_state, launch_id=_launch_id(launch_id), intent=checked_intent, reservation=checked_reservation, journal=checked_journal, terminal_receipt=checked_receipt)
        planned = semantic.create_transition_event(base_records[-1], base_state, domain, event_type="codex_transport_terminal_receipt", command_id=h.validate_id(command_id, "command id"), recorded_at=recorded_at, authority_ref=_authority_ref(launch_id))
    except (contracts.CodexTransportContractError, projection.CodexTransportProjectionError, semantic.SemanticEventError, h.HarnessError) as exc:
        raise _fail("Codex terminal receipt cannot publish", exc) from exc
    wrapped = _wrap("codex_transport_receipt", task_id, f"{launch_id}:terminal:{checked_receipt['receipt_sha256']}", {"receipt_kind": "terminal", "receipt": checked_receipt})
    objects.publish_semantic_object(paths, wrapped)
    binding = objects.create_semantic_binding(binding_kind="codex_transport_milestone", task_id=task_id, binding_key=f"{launch_id}:terminal:{checked_receipt['receipt_sha256']}", expected_semantic_head_sha256=base_head, planned_event_sha256=planned["event_sha256"], result_projection_sha256=semantic.canonical_sha256(domain), object_sha256s=[wrapped["object_sha256"]])
    objects.publish_semantic_binding(paths, binding, records)
    result = store.append_semantic_transition(paths, task_id, domain, event_type="codex_transport_terminal_receipt", command_id=command_id, recorded_at=recorded_at, authority_ref=_authority_ref(launch_id), expected_head_sha256=base_head)
    return {"receipt_sha256": checked_receipt["receipt_sha256"], "semantic_event_sha256": result.event["event_sha256"], "idempotent_replay": result.idempotent_replay}


def load_codex_transport_launch(
    paths: h.HarnessPaths,
    task_id: str,
    launch_id: str,
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Load one authenticated launch plus at most one crash-pending publication."""

    records, state, head = _live_records(paths, task_id, event_chain)
    identity = _launch_id(launch_id)
    namespace = projection.codex_transport_namespace_from_projection(state)
    row = namespace["launches"].get(identity)
    if not isinstance(row, Mapping):
        raise CodexTransportRuntimeError("Codex transport launch is not reserved")
    report = objects.inspect_semantic_objects(paths, task_id, records)
    object_rows = report["objects"]
    intents = _deduplicate_exact_payloads([
        item["payload"]
        for item in object_rows
        if item["object_type"] == "codex_launch_intent"
        and isinstance(item.get("payload"), dict)
        and item["payload"].get("intent_sha256") == row["intent_sha256"]
    ])
    reservation_receipts = _deduplicate_exact_payloads([
        item["payload"]["receipt"]
        for item in object_rows
        if item["object_type"] == "codex_transport_receipt"
        and isinstance(item.get("payload"), dict)
        and item["payload"].get("receipt_kind") == "reservation"
        and isinstance(item["payload"].get("receipt"), dict)
        and item["payload"]["receipt"].get("reservation_sha256") == row["reservation_sha256"]
    ])
    marker_candidates = _deduplicate_exact_payloads([
        _read_marker(paths, task_id, receipt["permit_sha256"])
        for receipt in reservation_receipts
        if isinstance(receipt, Mapping)
        and isinstance(receipt.get("permit_sha256"), str)
    ])
    authorities = _deduplicate_exact_payloads([
        item["payload"]
        for item in object_rows
        if item["object_type"] == "codex_launch_authority"
        and isinstance(item.get("payload"), dict)
        and any(
            item["payload"].get("launch_authority_sha256")
            == marker.get("launch_authority_sha256")
            for marker in marker_candidates
        )
    ])
    launch_permits = _deduplicate_exact_payloads([
        item["payload"]
        for item in object_rows
        if item["object_type"] == "transition_permit"
        and isinstance(item.get("payload"), dict)
        and any(
            item["payload"].get("permit_sha256") == marker.get("permit_sha256")
            for marker in marker_candidates
        )
    ])
    if (
        len(intents) != 1
        or len(reservation_receipts) != 1
        or len(marker_candidates) != 1
        or len(authorities) != 1
        or len(launch_permits) != 1
    ):
        raise CodexTransportRuntimeError(
            "Codex transport launch intent/authority/permit/reservation object is missing or ambiguous"
        )
    try:
        intent = contracts.validate_launch_intent(intents[0])
        authority_contract = contracts.validate_launch_authority(authorities[0])
        launch_permit = permits.validate_transition_permit(launch_permits[0])
        reservation = contracts.validate_reservation_against_intent(
            reservation_receipts[0], intent
        )
        if (
            authority_contract["launch_intent_sha256"] != intent["intent_sha256"]
            or authority_contract["task_id"] != task_id
            or authority_contract["packet_id"] != intent["packet_id"]
            or authority_contract["routing_binding"] != intent["routing_binding"]
            or launch_permit["action"] != "codex.launch"
            or launch_permit["task_id"] != task_id
            or launch_permit["permit_sha256"] != reservation["permit_sha256"]
            or launch_permit["parameters"].get("launch_id") != identity
            or launch_permit["parameters"].get("launch_intent_sha256")
            != intent["intent_sha256"]
        ):
            raise CodexTransportRuntimeError(
                "stored Codex launch authority or permit does not bind its intent"
            )
        journal = [
            contracts.validate_journal_event(item["payload"]["receipt"])
            for item in object_rows
            if item["object_type"] == "codex_transport_receipt"
            and isinstance(item.get("payload"), dict)
            and item["payload"].get("receipt_kind") == "journal_event"
            and isinstance(item["payload"].get("receipt"), dict)
            and item["payload"]["receipt"].get("reservation_sha256")
            == reservation["reservation_sha256"]
        ]
        journal.sort(key=lambda item: item["sequence"])
        journal_state = contracts.validate_transport_journal(journal)
    except (
        contracts.CodexTransportContractError,
        permits.TransitionPermitError,
    ) as exc:
        raise _fail("stored Codex transport launch objects are invalid", exc) from exc
    committed_count = row["journal_sequence"]
    if len(journal) not in {committed_count, committed_count + 1}:
        raise CodexTransportRuntimeError(
            "stored Codex journal is not the committed prefix plus at most one pending event"
        )
    committed = journal[:committed_count]
    committed_state = contracts.validate_transport_journal(committed)
    if (
        committed_state.head_sha256 != row["journal_head_sha256"]
        or committed_state.state != row["state"]
        or committed_state.correlation["thread_id"] != row["thread_id"]
        or committed_state.correlation["turn_id"] != row["turn_id"]
    ):
        raise CodexTransportRuntimeError(
            "stored Codex journal does not match the semantic projection"
        )
    terminal_rows: list[tuple[dict[str, Any], Mapping[str, Any]]] = []
    try:
        for item in object_rows:
            if (
                item["object_type"] == "codex_transport_receipt"
                and isinstance(item.get("payload"), dict)
                and item["payload"].get("receipt_kind") == "terminal"
                and isinstance(item["payload"].get("receipt"), dict)
                and item["payload"]["receipt"].get("reservation_sha256")
                == reservation["reservation_sha256"]
            ):
                terminal_rows.append(
                    (contracts.validate_terminal_receipt(item["payload"]["receipt"]), item)
                )
    except contracts.CodexTransportContractError as exc:
        raise _fail("stored Codex terminal receipt is invalid", exc) from exc
    runtime_rows = [
        pair for pair in terminal_rows if pair[0]["evidence_level"] == "codex_runtime_observed"
    ]
    verified_rows = [
        pair for pair in terminal_rows if pair[0]["evidence_level"] == "verified_mutation"
    ]
    if len(runtime_rows) > 1 or len(verified_rows) > 1:
        raise CodexTransportRuntimeError("stored Codex terminal receipt is ambiguous")
    terminal = runtime_rows[0][0] if runtime_rows else None
    committed_mutation_bindings = {
        item["binding_sha256"]
        for item in report["bindings"]
        if item["binding_kind"] == "codex_mutation_verification"
        and item["classification"] == "committed"
    }
    pending_mutation_bindings = {
        item["binding_sha256"]
        for item in report["bindings"]
        if item["binding_kind"] == "codex_mutation_verification"
        and item["classification"] == "pending"
    }
    verified_terminal: dict[str, Any] | None = None
    pending_verified_terminal: dict[str, Any] | None = None
    if verified_rows:
        verified, wrapped_row = verified_rows[0]
        owners = set(wrapped_row.get("binding_sha256s", []))
        if owners.intersection(committed_mutation_bindings):
            verified_terminal = verified
        elif owners.intersection(pending_mutation_bindings):
            pending_verified_terminal = verified
    committed_terminal: dict[str, Any] | None = None
    pending_terminal: dict[str, Any] | None = None
    if row["terminal_receipt_sha256"] is not None:
        if terminal is None or terminal["receipt_sha256"] != row["terminal_receipt_sha256"]:
            raise CodexTransportRuntimeError(
                "semantic projection names a missing Codex terminal receipt"
            )
        contracts.validate_terminal_receipt_against_journal(terminal, committed)
        committed_terminal = terminal
    elif terminal is not None:
        contracts.validate_terminal_receipt_against_journal(terminal, committed)
        pending_terminal = terminal
    return {
        "task_id": task_id,
        "launch_id": identity,
        "semantic_head_sha256": head,
        "intent": intent,
        "launch_authority": authority_contract,
        "launch_permit": launch_permit,
        "reservation_effective_at": marker_candidates[0]["recorded_at"],
        "pre_git_endpoint_cas_sha256": marker_candidates[0][
            "pre_git_endpoint_cas_sha256"
        ],
        "reservation": reservation,
        "journal": committed,
        "pending_journal_event": journal[committed_count] if len(journal) > committed_count else None,
        "terminal_receipt": committed_terminal,
        "pending_terminal_receipt": pending_terminal,
        "verified_terminal_receipt": verified_terminal,
        "pending_verified_terminal_receipt": pending_verified_terminal,
        "task_completion": "not_inferred",
    }


def require_codex_process_start_window(
    launch: Mapping[str, Any], *, current_time: datetime
) -> None:
    """Fail closed if an unstarted reservation outlived permit or packet arm.

    Callers must invoke this from the ``process_start_pending`` callback,
    immediately before durably committing that milestone.  A committed pending
    milestone authorizes the following Popen; any crash after it is ambiguous
    and must reconcile without an automatic restart.
    """

    try:
        authority_contract = contracts.validate_launch_authority(
            launch["launch_authority"]
        )
        launch_permit = permits.validate_transition_permit(
            launch["launch_permit"]
        )
        reservation = contracts.validate_reservation(launch["reservation"])
        arm_expiry = h.parse_tz_aware_time(authority_contract["expires_at"])
        permit_expiry = h.parse_tz_aware_time(launch_permit["expires_at"])
        if (
            launch_permit["action"] != "codex.launch"
            or launch_permit["task_id"] != launch.get("task_id")
            or launch_permit["permit_sha256"] != reservation["permit_sha256"]
            or launch_permit["parameters"].get("launch_id")
            != launch.get("launch_id")
            or launch_permit["parameters"].get("launch_intent_sha256")
            != authority_contract["launch_intent_sha256"]
        ):
            raise CodexTransportRuntimeError(
                "Codex process-start permit is not bound to this launch"
            )
    except (
        KeyError,
        TypeError,
        contracts.CodexTransportContractError,
        permits.TransitionPermitError,
        h.HarnessError,
    ) as exc:
        raise _fail("cannot validate Codex process-start authority", exc) from exc
    if (
        not isinstance(current_time, datetime)
        or current_time.tzinfo is None
        or current_time.utcoffset() is None
        or arm_expiry is None
        or permit_expiry is None
    ):
        raise CodexTransportRuntimeError(
            "Codex process-start authority time is invalid"
        )
    expiry = min(arm_expiry, permit_expiry)
    if current_time >= expiry:
        raise CodexTransportRuntimeError(
            "Codex process start is forbidden after permit or packet arm expiry"
        )


def _require_released_issuing_chief(
    paths: h.HarnessPaths, marker: Mapping[str, Any]
) -> None:
    """Require the marker's issuer to be the exact latest released Chief."""

    h._require_chief_lock(paths)
    try:
        issuer = marker["issuer_chief_authority"]
        if not isinstance(issuer, Mapping):
            raise CodexTransportRuntimeError(
                "issuance marker issuing Chief authority is invalid"
            )
        issuer_session = issuer["session_id"]
        issuer_epoch = issuer["epoch"]
        if (
            not isinstance(issuer_session, str)
            or not issuer_session
            or type(issuer_epoch) is not int
            or issuer_epoch < 1
        ):
            raise CodexTransportRuntimeError(
                "issuance marker issuing Chief authority is invalid"
            )
        current = h.load_chief_authority(paths)
        audit_tail = current["audit_tail"]
        if not isinstance(audit_tail, list) or not audit_tail:
            raise CodexTransportRuntimeError(
                "current Chief authority lacks a release audit event"
            )
        latest = audit_tail[-1]
    except CodexTransportRuntimeError:
        raise
    except (KeyError, TypeError, h.HarnessError) as exc:
        raise _fail(
            "cannot validate released issuing Chief for Codex process start", exc
        ) from exc

    if (
        current.get("status") != "inactive"
        or current.get("epoch") != issuer_epoch
        or current.get("session_id") != ""
        or current.get("token_sha256") != ""
        or current.get("issued_at") != ""
        or current.get("renewed_at") != ""
        or current.get("expires_at") != ""
        or current.get("renewal_count") != 0
        or not isinstance(latest, Mapping)
        or latest.get("action") != "release"
        or latest.get("seq") != current.get("transition_seq")
        or latest.get("at") != current.get("updated_at")
        or latest.get("session_id") != issuer_session
        or latest.get("previous_session_id") != issuer_session
        or latest.get("old_epoch") != issuer_epoch
        or latest.get("new_epoch") != issuer_epoch
        or latest.get("forced_live") is not False
    ):
        raise CodexTransportRuntimeError(
            "Codex process start requires exact release of the issuing Chief"
        )


def require_codex_process_start_authority(
    paths: h.HarnessPaths,
    launch: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    *,
    current_time: datetime,
) -> None:
    """Revalidate exclusive packet ownership at the durable Popen boundary."""

    h._require_chief_lock(paths)
    require_codex_process_start_window(launch, current_time=current_time)
    try:
        task_id = h.validate_id(launch["task_id"], "task id")
        launch_id = _launch_id(launch["launch_id"])
        records, state, _head = _live_records(paths, task_id, event_chain)
        if not records:
            raise CodexTransportRuntimeError("Codex process-start ledger is empty")
        intent = contracts.validate_launch_intent(launch["intent"])
        authority_contract = contracts.validate_launch_authority(
            launch["launch_authority"]
        )
        launch_permit = permits.validate_transition_permit(
            launch["launch_permit"]
        )
        reservation = contracts.validate_reservation(launch["reservation"])
        marker = _read_marker(paths, task_id, launch_permit["permit_sha256"])
        if (
            marker["task_id"] != task_id
            or marker["launch_id"] != launch_id
            or marker["permit_sha256"] != launch_permit["permit_sha256"]
            or marker["intent_sha256"] != intent["intent_sha256"]
            or marker["launch_authority_sha256"]
            != authority_contract["launch_authority_sha256"]
            or marker["reservation_sha256"] != reservation["reservation_sha256"]
        ):
            raise CodexTransportRuntimeError(
                "Codex process-start issuance marker is not bound to this launch"
            )
        _require_released_issuing_chief(paths, marker)
        namespace = projection.codex_transport_namespace_from_projection(state)
        row = namespace["launches"].get(launch_id)
        if (
            not isinstance(row, Mapping)
            or row.get("state") != "reserved"
            or row.get("intent_sha256") != intent["intent_sha256"]
            or row.get("reservation_sha256") != reservation["reservation_sha256"]
            or row.get("journal_sequence") != 1
            or row.get("terminal_receipt_sha256") is not None
        ):
            raise CodexTransportRuntimeError(
                "Codex process start requires one fresh reserved launch"
            )
        packet = state_lookup._packet_by_id(state, intent["packet_id"])
        if (
            packet.get("status") != "dispatched"
            or packet.get("dispatch_provenance")
            != launch_authority.CODEX_TRANSPORT_DISPATCH_PROVENANCE
            or packet.get("dispatch_version")
            != launch_authority.CODEX_TRANSPORT_DISPATCH_MODEL_VERSION
            or state.get("dispatch_model_version")
            != launch_authority.CODEX_TRANSPORT_DISPATCH_MODEL_VERSION
            or packet.get("packet_contract_sha256")
            != authority_contract["packet_contract_sha256"]
        ):
            raise CodexTransportRuntimeError(
                "Codex process-start packet is no longer bridge-owned dispatched"
            )
        ownership = contracts.validate_packet_transport_ownership(
            packet.get("transport_ownership")
        )
        expected = contracts.seal_packet_transport_ownership({
            "contract_type": contracts.CODEX_PACKET_TRANSPORT_OWNERSHIP_V1,
            "task_id": task_id,
            "packet_id": intent["packet_id"],
            "launch_id": launch_id,
            "arm_id": authority_contract["arm_id"],
            "launch_intent_sha256": intent["intent_sha256"],
            "permit_sha256": launch_permit["permit_sha256"],
            "reservation_sha256": reservation["reservation_sha256"],
            "launch_authority_sha256": authority_contract[
                "launch_authority_sha256"
            ],
            "routing_authority_sha256": intent["routing_binding"][
                "routing_authority_sha256"
            ],
            "reservation_effective_at": launch[
                "reservation_effective_at"
            ],
            "owner_kind": "codex_app_server_stdio",
        })
        if ownership != expected:
            raise CodexTransportRuntimeError(
                "Codex process-start packet ownership differs from the launch"
            )
        attempts = [
            attempt
            for attempt in packet.get("dispatch_attempts", [])
            if isinstance(attempt, Mapping)
            and attempt.get("status")
            == launch_authority.CODEX_TRANSPORT_ATTEMPT_STATUS
        ]
        if (
            len(attempts) != 1
            or attempts[0].get("transport_ownership") != ownership
            or attempts[0].get("arm_id") != authority_contract["arm_id"]
            or attempts[0].get("observation") is not None
        ):
            raise CodexTransportRuntimeError(
                "Codex process-start dispatch attempt is not exclusively owned"
            )
    except CodexTransportRuntimeError:
        raise
    except (
        KeyError,
        TypeError,
        h.HarnessError,
        contracts.CodexTransportContractError,
        permits.TransitionPermitError,
        projection.CodexTransportProjectionError,
        semantic.SemanticEventError,
    ) as exc:
        raise _fail("cannot validate Codex process-start ownership", exc) from exc


def inspect_codex_transport_runtime(paths: h.HarnessPaths, task_id: str, event_chain: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Read-only authenticated transport report; never upgrades task evidence."""
    records, state, head = _live_records(paths, task_id, event_chain)
    report = objects.inspect_semantic_objects(paths, task_id, records)
    namespace = projection.codex_transport_namespace_from_projection(state)
    markers: dict[str, dict[str, Any]] = {}
    directory = _issuance_path(paths, task_id, "0" * 64).parent
    if directory.exists() or h._path_is_link_like(directory):
        checked_directory = _ensure_issuance_directory(paths, task_id)
        try:
            for entry in checked_directory.iterdir():
                if not entry.is_file() or not re.fullmatch(r"[0-9a-f]{64}\.json", entry.name):
                    raise CodexTransportRuntimeError("Codex issuance store has an unexpected entry")
                issued_marker = _read_marker(paths, task_id, entry.stem)
                if issued_marker["launch_id"] in markers:
                    raise CodexTransportRuntimeError("Codex issuance store repeats a launch")
                markers[issued_marker["launch_id"]] = issued_marker
        except OSError as exc:
            raise _fail("cannot enumerate Codex issuance store", exc) from exc
    rows: list[dict[str, Any]] = []
    for launch_id, row in namespace["launches"].items():
        marker = markers.get(launch_id)
        if marker is None or marker["intent_sha256"] != row["intent_sha256"] or marker["reservation_sha256"] != row["reservation_sha256"]:
            raise CodexTransportRuntimeError("transport launch lacks an authentic issuance marker")
        rows.append({"launch_id": launch_id, "state": row["state"], "thread_id": row["thread_id"], "turn_id": row["turn_id"], "terminal_receipt_sha256": row["terminal_receipt_sha256"], "issuance_sha256": marker["issuance_sha256"], "evidence_level": "codex_runtime_observed", "task_completion": "not_inferred"})
    return {"task_id": task_id, "semantic_head_sha256": head, "launches": rows, "pending_binding_sha256s": report["pending_binding_sha256s"], "task_completion": "not_inferred"}


__all__ = ["CodexTransportRuntimeError", "ISSUANCE_DIRECTORY", "ISSUANCE_SCHEMA_VERSION", "RUN_LOCK_DIRECTORY", "codex_launch_process_lock", "inspect_codex_launch_issuance", "issue_codex_launch_transaction", "inspect_codex_transport_runtime", "load_codex_transport_launch", "prepare_codex_launch_transaction", "publish_terminal_receipt", "reconstruct_issued_launch_transaction", "record_milestone", "require_codex_process_start_authority", "require_codex_process_start_window", "reserve_codex_launch"]
