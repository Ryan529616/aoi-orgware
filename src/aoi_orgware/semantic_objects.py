"""Immutable semantic-v2 content objects and exact task-local bindings.

This deliberately has no lifecycle or CLI knowledge.  A lifecycle writer holds
the AOI state lock, creates immutable objects, and then publishes one exact
binding which later becomes committed only when its planned ledger event is
authenticated by the caller.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from itertools import islice
from pathlib import Path
from typing import Any, Iterable, Mapping, cast

from . import harnesslib as h
from . import semantic_events as semantic


OBJECT_SCHEMA_VERSION = 1
BINDING_SCHEMA_VERSION = 1
MAX_OBJECT_BYTES = 512 * 1024
MAX_SMALL_OBJECT_BYTES = 64 * 1024
MAX_COHORT_OBJECT_BYTES = 128 * 1024
# Transport payloads are strict, hash-only (apart from the audited cwd/model
# fields in the launch intent).  Their contract records cap at 64 KiB; allow
# room for the immutable semantic-object wrapper without giving them the
# generic 512 KiB ceiling.
MAX_CODEX_LAUNCH_INTENT_OBJECT_BYTES = 96 * 1024
MAX_CODEX_LAUNCH_AUTHORITY_OBJECT_BYTES = 96 * 1024
MAX_CODEX_TRANSPORT_RECEIPT_OBJECT_BYTES = 96 * 1024
MAX_CODEX_MUTATION_VERIFICATION_OBJECT_BYTES = 16 * 1024
MAX_BINDING_BYTES = 64 * 1024
MAX_OBJECTS_PER_TASK = 16_384
MAX_BINDINGS_PER_TASK = 16_384
MAX_OBJECT_AGGREGATE_BYTES = 256 * 1024 * 1024
MAX_OBJECT_IDENTITY_CHARS = 256
MAX_BINDING_KEY_CHARS = 512
# A 64 KiB canonical binding cannot encode 1,024 SHA-256 string references
# (even before its required wrapper fields).  Keep this independent iterator
# cap above that representable maximum so hostile iterables are never drained.
MAX_OBJECT_REFERENCES_PER_BINDING = 1_024
MAX_BINDING_DISPOSITIONS = 256
MAX_BINDING_DISPOSITION_BYTES = 2 * 1024 * 1024

BINDING_DISPOSITIONS_KEY = "semantic_binding_dispositions"
BINDING_DISPOSITION_SCHEMA_VERSION = 1
RELEASE_ABANDONMENT_EVENT_TYPE = "release_promotion_abandoned"
RELEASE_PROMOTION_EVENT_TYPE = "release_promoted"

OBJECT_TYPES = frozenset(
    {
        "routing_authority",
        "routing_outcome",
        "routing_terminal",
        "transition_decision",
        "transition_permit",
        "cohort_plan",
        "release_manifest",
        "release_observation",
        "promotion_receipt",
        "release_promotion_intent",
        "codex_launch_intent",
        "codex_launch_authority",
        "codex_transport_receipt",
        "codex_mutation_verification",
    }
)
SMALL_OBJECT_TYPES = frozenset(
    {"routing_terminal", "transition_decision", "transition_permit"}
)
BINDING_KINDS = frozenset(
    {
        "packet_authority",
        "outcome_slot",
        "terminal_slot",
        "permit_consumption",
        "cohort_advance",
        "release_promotion",
        "codex_launch_reservation",
        "codex_transport_milestone",
        "codex_mutation_verification",
    }
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHARD = re.compile(r"[0-9a-f]{2}")
_OBJECT_FIELDS = frozenset(
    {
        "schema_version",
        "object_type",
        "task_id",
        "object_identity",
        "payload",
        "payload_sha256",
        "object_sha256",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "binding_kind",
        "task_id",
        "binding_key",
        "expected_semantic_head_sha256",
        "planned_event_sha256",
        "result_projection_sha256",
        "object_sha256s",
        "binding_sha256",
    }
)
_DISPOSITION_FIELDS = frozenset({"schema_version", "abandoned"})
_ABANDONMENT_V1_FIELDS = frozenset(
    {
        "schema_version",
        "task_id",
        "binding_sha256",
        "binding_kind",
        "binding_key",
        "expected_semantic_head_sha256",
        "planned_event_sha256",
        "result_projection_sha256",
        "original_event",
        "takeover",
        "reason",
        "abandonment_command_id",
        "abandonment_recorded_at",
        "abandonment_authority_ref",
    }
)
_ABANDONMENT_V2_FIELDS = frozenset(
    {
        "schema_version",
        "task_id",
        "binding_sha256",
        "binding_kind",
        "binding_key",
        "expected_semantic_head_sha256",
        "planned_event_sha256",
        "result_projection_sha256",
        "original_event",
        "retirement_proof",
        "reason",
        "abandonment_command_id",
        "abandonment_recorded_at",
        "abandonment_authority_ref",
    }
)
_ORIGINAL_EVENT_FIELDS = frozenset(
    {"event_type", "command_id", "recorded_at", "authority_ref", "event_sha256"}
)
_TAKEOVER_FIELDS = frozenset(
    {
        "seq",
        "action",
        "at",
        "old_epoch",
        "new_epoch",
        "session_id",
        "previous_session_id",
        "reason",
        "forced_live",
        "audit_event_sha256",
    }
)
_RETIREMENT_PROOF_FIELDS = frozenset(
    {
        "proof_kind",
        "successor_session_id",
        "successor_epoch",
        "issued_at",
        "expires_at",
        "current_authority_record_sha256",
    }
)
_RELEASE_AUTHORITY_REF = re.compile(
    r"chief:([A-Za-z0-9._-]{1,128}):e([1-9][0-9]*):release:([0-9a-f]{64})"
)
_RELEASE_ABANDON_AUTHORITY_REF = re.compile(
    r"chief:([A-Za-z0-9._-]{1,128}):e([1-9][0-9]*):release-abandon:([0-9a-f]{64})"
)
_CODEX_TRANSPORT_RECEIPT_FIELDS = frozenset({"receipt_kind", "receipt"})


class SemanticObjectError(h.HarnessError):
    """A semantic object/binding or its managed filesystem representation is unsafe."""


def _error(message: str, exc: BaseException | None = None) -> SemanticObjectError:
    return SemanticObjectError(message if exc is None else f"{message}: {exc}")


def _clone(value: Any, *, max_bytes: int) -> Any:
    try:
        return json.loads(semantic.canonical_json_bytes(value, max_bytes=max_bytes).decode("utf-8"))
    except (semantic.SemanticEventError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("semantic value is not bounded canonical JSON", exc) from exc


def _sha(value: Any, *, max_bytes: int) -> str:
    try:
        return semantic.canonical_sha256(value, max_bytes=max_bytes)
    except semantic.SemanticEventError as exc:
        raise _error("semantic value cannot be hashed", exc) from exc


def _validate_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SemanticObjectError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_version(value: Any, expected: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise SemanticObjectError(f"unsupported {label} schema version")


def _validate_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SemanticObjectError(f"{label} must be a non-empty string no longer than {maximum} characters")
    return value


def _task_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    try:
        task_id = h.validate_id(task_id, "task id")
        task = h.task_dir(paths, task_id)
        canonical = h.canonicalize_no_link_traversal(task, "semantic object task directory")
        if canonical != task or not canonical.exists():
            raise SemanticObjectError("semantic object task directory is missing or non-canonical")
        h.validate_existing_regular_directory(canonical, "semantic object task directory")
        return canonical
    except SemanticObjectError:
        raise
    except h.HarnessError as exc:
        raise _error("invalid semantic object task directory", exc) from exc


def _private_directory(path: Path, label: str, *, create: bool) -> Path:
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        if canonical != path:
            raise SemanticObjectError(f"{label} is non-canonical")
        if not canonical.exists():
            if not create:
                raise FileNotFoundError(canonical)
            canonical.mkdir(mode=0o700)
            if os.name != "nt":
                canonical.chmod(0o700)
        h.validate_existing_regular_directory(canonical, label)
        metadata = canonical.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise SemanticObjectError(f"{label} is not a directory")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SemanticObjectError(f"{label} is not private")
        if h.canonicalize_no_link_traversal(canonical, label) != canonical:
            raise SemanticObjectError(f"{label} changed while being checked")
        return canonical
    except SemanticObjectError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _error(f"invalid {label}", exc) from exc


def semantic_object_path(paths: h.HarnessPaths, task_id: str, object_sha256: str) -> Path:
    """Return the sole permitted path for an object digest, without I/O."""

    _validate_sha(object_sha256, "object SHA-256")
    return h.task_dir(paths, task_id) / "semantic-objects" / "sha256" / object_sha256[:2] / f"{object_sha256}.json"


def semantic_binding_path(
    paths: h.HarnessPaths, task_id: str, binding_kind: str, binding_key: str
) -> Path:
    """Return the sole permitted path for one binding kind/key slot, without I/O."""

    if not isinstance(binding_kind, str) or binding_kind not in BINDING_KINDS:
        raise SemanticObjectError("unsupported semantic binding kind")
    key = _validate_text(binding_key, "binding key", MAX_BINDING_KEY_CHARS)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return h.task_dir(paths, task_id) / "semantic-bindings" / binding_kind / digest[:2] / f"{digest}.json"


def _object_base(
    *, object_type: str, task_id: str, object_identity: str, payload: Any
) -> dict[str, Any]:
    if not isinstance(object_type, str) or object_type not in OBJECT_TYPES:
        raise SemanticObjectError("unsupported semantic object type")
    task_id = h.validate_id(task_id, "task id")
    identity = _validate_text(object_identity, "object identity", MAX_OBJECT_IDENTITY_CHARS)
    payload_copy = _clone(payload, max_bytes=MAX_OBJECT_BYTES)
    payload_copy = _validate_transport_payload(object_type, task_id, payload_copy)
    return {
        "schema_version": OBJECT_SCHEMA_VERSION,
        "object_type": object_type,
        "task_id": task_id,
        "object_identity": identity,
        "payload": payload_copy,
        "payload_sha256": _sha(payload_copy, max_bytes=MAX_OBJECT_BYTES),
    }


def _validate_transport_payload(object_type: str, task_id: str, payload: Any) -> Any:
    """Return a closed transport payload, or the generic payload for v0.3 types.

    Semantic objects are intentionally generic for the pre-v0.4 object types.
    These new transport registrations are different: they carry execution
    authority/evidence, so they must be validated as the closed pure-contract
    records.  In particular, raw prompts, assistant output, tool output, and
    arbitrary App Server JSON cannot enter AOI merely through a registered
    object type.
    """

    if object_type not in {
        "codex_launch_intent",
        "codex_launch_authority",
        "codex_transport_receipt",
        "codex_mutation_verification",
    }:
        return payload

    # This is a stdlib-only, pure contract dependency; it neither launches
    # Codex nor gives semantic-object storage a controller/Chief credential.
    from . import codex_transport_contracts as transport

    try:
        if object_type == "codex_launch_intent":
            normalized = transport.validate_launch_intent(payload)
            if normalized["task_id"] != task_id:
                raise SemanticObjectError("Codex launch intent task identity does not match object")
            return normalized

        if object_type == "codex_launch_authority":
            normalized = transport.validate_launch_authority(payload)
            if normalized["task_id"] != task_id:
                raise SemanticObjectError(
                    "Codex launch authority task identity does not match object"
                )
            return normalized

        if object_type == "codex_transport_receipt":
            if not isinstance(payload, dict) or set(payload) != _CODEX_TRANSPORT_RECEIPT_FIELDS:
                raise SemanticObjectError("Codex transport receipt schema is invalid")
            kind = payload["receipt_kind"]
            validators = {
                "reservation": transport.validate_reservation,
                "journal_event": transport.validate_journal_event,
                "terminal": transport.validate_terminal_receipt,
            }
            if not isinstance(kind, str) or kind not in validators:
                raise SemanticObjectError("Codex transport receipt kind is invalid")
            return {"receipt_kind": kind, "receipt": validators[kind](payload["receipt"])}

        # This only validates a closed set of structural CAS references.  It
        # deliberately does not materialize those references, reconstruct Git
        # snapshots, assess claim coverage, or promote a task: those are
        # controller/Chief responsibilities.  Equal pre/post tree hashes are
        # valid when an observed working-tree change does not move HEAD/tree.
        return transport.validate_mutation_verification_payload(payload)
    except SemanticObjectError:
        raise
    except transport.CodexTransportContractError as exc:
        raise SemanticObjectError(f"Codex transport payload is invalid: {exc}") from exc


def create_semantic_object(
    *, object_type: str, task_id: str, object_identity: str, payload: Any
) -> dict[str, Any]:
    """Create a detached, sealed immutable object wrapper (without I/O)."""

    try:
        base = _object_base(
            object_type=object_type,
            task_id=task_id,
            object_identity=object_identity,
            payload=payload,
        )
        maximum = _object_limit(object_type)
        digest = _sha(base, max_bytes=maximum)
        wrapped = {**base, "object_sha256": digest}
        _clone(wrapped, max_bytes=maximum)
        return wrapped
    except SemanticObjectError:
        raise
    except (h.HarnessError, TypeError, ValueError) as exc:
        raise _error("invalid semantic object request", exc) from exc


seal_semantic_object = create_semantic_object


def validate_semantic_object(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached object wrapper."""

    if not isinstance(value, dict) or set(value) != _OBJECT_FIELDS:
        raise SemanticObjectError("semantic object schema is invalid")
    _validate_version(value.get("schema_version"), OBJECT_SCHEMA_VERSION, "semantic object")
    object_type = value.get("object_type")
    if not isinstance(object_type, str) or object_type not in OBJECT_TYPES:
        raise SemanticObjectError("unsupported semantic object type")
    try:
        base = _object_base(
            object_type=object_type,
            task_id=value["task_id"],
            object_identity=value["object_identity"],
            payload=value.get("payload"),
        )
    except (h.HarnessError, TypeError, ValueError) as exc:
        raise _error("semantic object fields are invalid", exc) from exc
    if value.get("payload_sha256") != base["payload_sha256"]:
        raise SemanticObjectError("semantic object payload SHA-256 is invalid")
    maximum = _object_limit(object_type)
    expected = _sha(base, max_bytes=maximum)
    if value.get("object_sha256") != expected:
        raise SemanticObjectError("semantic object SHA-256 is invalid")
    wrapped = {**base, "object_sha256": expected}
    _clone(wrapped, max_bytes=maximum)
    return wrapped


def _binding_base(
    *,
    binding_kind: str,
    task_id: str,
    binding_key: str,
    expected_semantic_head_sha256: str,
    planned_event_sha256: str,
    result_projection_sha256: str,
    object_sha256s: Iterable[str],
) -> dict[str, Any]:
    if not isinstance(binding_kind, str) or binding_kind not in BINDING_KINDS:
        raise SemanticObjectError("unsupported semantic binding kind")
    task_id = h.validate_id(task_id, "task id")
    key = _validate_text(binding_key, "binding key", MAX_BINDING_KEY_CHARS)
    references = list(
        islice(iter(object_sha256s), MAX_OBJECT_REFERENCES_PER_BINDING + 1)
    )
    if len(references) > MAX_OBJECT_REFERENCES_PER_BINDING:
        raise SemanticObjectError("semantic binding exceeds object reference count bound")
    if not references:
        raise SemanticObjectError("semantic binding must reference at least one object SHA-256")
    if any(not isinstance(item, str) for item in references):
        raise SemanticObjectError("semantic binding object digests must be strings")
    for item in references:
        _validate_sha(item, "semantic binding object SHA-256")
    if references != sorted(set(references)):
        raise SemanticObjectError("semantic binding object digests must be sorted and unique")
    return {
        "schema_version": BINDING_SCHEMA_VERSION,
        "binding_kind": binding_kind,
        "task_id": task_id,
        "binding_key": key,
        "expected_semantic_head_sha256": _validate_sha(
            expected_semantic_head_sha256, "expected semantic head SHA-256"
        ),
        "planned_event_sha256": _validate_sha(planned_event_sha256, "planned event SHA-256"),
        "result_projection_sha256": _validate_sha(
            result_projection_sha256, "result projection SHA-256"
        ),
        "object_sha256s": references,
    }


def create_semantic_binding(
    *,
    binding_kind: str,
    task_id: str,
    binding_key: str,
    expected_semantic_head_sha256: str,
    planned_event_sha256: str,
    result_projection_sha256: str,
    object_sha256s: Iterable[str],
) -> dict[str, Any]:
    """Create a detached, sealed exact-binding wrapper (without I/O)."""

    try:
        base = _binding_base(
            binding_kind=binding_kind,
            task_id=task_id,
            binding_key=binding_key,
            expected_semantic_head_sha256=expected_semantic_head_sha256,
            planned_event_sha256=planned_event_sha256,
            result_projection_sha256=result_projection_sha256,
            object_sha256s=object_sha256s,
        )
        wrapped = {**base, "binding_sha256": _sha(base, max_bytes=MAX_BINDING_BYTES)}
        _clone(wrapped, max_bytes=MAX_BINDING_BYTES)
        return wrapped
    except SemanticObjectError:
        raise
    except (h.HarnessError, TypeError, ValueError) as exc:
        raise _error("invalid semantic binding request", exc) from exc


seal_semantic_binding = create_semantic_binding


def validate_semantic_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached binding wrapper."""

    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        raise SemanticObjectError("semantic binding schema is invalid")
    _validate_version(value.get("schema_version"), BINDING_SCHEMA_VERSION, "semantic binding")
    try:
        base = _binding_base(
            binding_kind=value["binding_kind"],
            task_id=value["task_id"],
            binding_key=value["binding_key"],
            expected_semantic_head_sha256=value["expected_semantic_head_sha256"],
            planned_event_sha256=value["planned_event_sha256"],
            result_projection_sha256=value["result_projection_sha256"],
            object_sha256s=value["object_sha256s"],
        )
    except (h.HarnessError, TypeError, ValueError) as exc:
        raise _error("semantic binding fields are invalid", exc) from exc
    expected = _sha(base, max_bytes=MAX_BINDING_BYTES)
    if value.get("binding_sha256") != expected:
        raise SemanticObjectError("semantic binding SHA-256 is invalid")
    wrapped = {**base, "binding_sha256": expected}
    _clone(wrapped, max_bytes=MAX_BINDING_BYTES)
    return wrapped


def _require_lock(paths: h.HarnessPaths) -> None:
    try:
        h._require_chief_lock(paths)
    except h.HarnessError as exc:
        raise _error("semantic object publication requires the project state lock", exc) from exc


def _ensure_object_shard(paths: h.HarnessPaths, task_id: str, digest: str) -> Path:
    task = _task_directory(paths, task_id)
    root = _private_directory(task / "semantic-objects", "semantic object root", create=True)
    sha_root = _private_directory(root / "sha256", "semantic object SHA-256 root", create=True)
    return _private_directory(sha_root / digest[:2], "semantic object shard", create=True)


def _ensure_binding_shard(paths: h.HarnessPaths, task_id: str, kind: str, key: str) -> Path:
    task = _task_directory(paths, task_id)
    root = _private_directory(task / "semantic-bindings", "semantic binding root", create=True)
    kind_root = _private_directory(root / kind, "semantic binding kind directory", create=True)
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return _private_directory(kind_root / key_digest[:2], "semantic binding shard", create=True)


def _read_private_json(path: Path, label: str, *, maximum: int) -> dict[str, Any]:
    try:
        if h.canonicalize_no_link_traversal(path, label) != path:
            raise SemanticObjectError(f"{label} path is non-canonical")
        h.validate_existing_regular_file(path, label)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SemanticObjectError(f"{label} must be one private regular non-linked file")
        if os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077:
            raise SemanticObjectError(f"{label} is not private")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise SemanticObjectError(f"{label} changed while being opened")
            raw = handle.read(maximum + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise _error(f"{label} is missing", exc) from exc
    except SemanticObjectError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _error(f"cannot read {label}", exc) from exc
    if len(raw) > maximum:
        raise SemanticObjectError(f"{label} exceeds byte bound")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(raw) != finished.st_size
        or (os.name != "nt" and stat.S_IMODE(after.st_mode) & 0o077)
        or h.canonicalize_no_link_traversal(path, label) != path
    ):
        raise SemanticObjectError(f"{label} changed while being read")
    try:
        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise SemanticObjectError(f"{label} has duplicate JSON key {key!r}")
                result[key] = item
            return result

        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        if not isinstance(value, dict):
            raise SemanticObjectError(f"{label} must contain a JSON object")
        canonical = semantic.canonical_json_bytes(value, max_bytes=maximum)
    except SemanticObjectError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, semantic.SemanticEventError) as exc:
        raise _error(f"invalid {label} JSON", exc) from exc
    if raw != canonical:
        raise SemanticObjectError(f"{label} bytes are not canonical JSON")
    return value


def _object_limit(object_type: str) -> int:
    if object_type == "cohort_plan":
        return MAX_COHORT_OBJECT_BYTES
    if object_type == "codex_launch_intent":
        return MAX_CODEX_LAUNCH_INTENT_OBJECT_BYTES
    if object_type == "codex_launch_authority":
        return MAX_CODEX_LAUNCH_AUTHORITY_OBJECT_BYTES
    if object_type == "codex_transport_receipt":
        return MAX_CODEX_TRANSPORT_RECEIPT_OBJECT_BYTES
    if object_type == "codex_mutation_verification":
        return MAX_CODEX_MUTATION_VERIFICATION_OBJECT_BYTES
    return MAX_SMALL_OBJECT_BYTES if object_type in SMALL_OBJECT_TYPES else MAX_OBJECT_BYTES


def _load_object(path: Path, task_id: str) -> dict[str, Any]:
    value = _read_private_json(path, "semantic object", maximum=MAX_OBJECT_BYTES)
    wrapped = validate_semantic_object(value)
    if wrapped["task_id"] != task_id:
        raise SemanticObjectError("semantic object task identity does not match its store")
    if len(semantic.canonical_json_bytes(wrapped, max_bytes=_object_limit(wrapped["object_type"]))) > _object_limit(wrapped["object_type"]):
        raise SemanticObjectError("semantic object exceeds type byte bound")
    expected = f"{wrapped['object_sha256']}.json"
    if path.name != expected or path.parent.name != wrapped["object_sha256"][:2]:
        raise SemanticObjectError("semantic object filename does not match its digest")
    return wrapped


def _load_binding(path: Path, task_id: str, kind: str) -> dict[str, Any]:
    value = _read_private_json(path, "semantic binding", maximum=MAX_BINDING_BYTES)
    wrapped = validate_semantic_binding(value)
    if wrapped["task_id"] != task_id or wrapped["binding_kind"] != kind:
        raise SemanticObjectError("semantic binding identity does not match its store")
    key_digest = hashlib.sha256(wrapped["binding_key"].encode("utf-8")).hexdigest()
    if path.name != f"{key_digest}.json" or path.parent.name != key_digest[:2]:
        raise SemanticObjectError("semantic binding filename does not match its key")
    return wrapped


def _scan_object_paths(
    paths: h.HarnessPaths, task_id: str, *, allow_empty_root_without_sha256: bool = False
) -> list[Path]:
    """Enumerate the exact object namespace, never treating root residue as inert.

    An object writer may recover only one interrupted first-create prefix: a
    private, otherwise empty ``semantic-objects`` directory without its
    ``sha256`` child.  Readers and binding writers cannot infer that recovery.
    """

    task = _task_directory(paths, task_id)
    root = task / "semantic-objects"
    if not root.exists() and not h._path_is_link_like(root):
        return []
    root = _private_directory(root, "semantic object root", create=False)
    try:
        with os.scandir(root) as entries:
            # Only zero, one, or "too many" matters at this level.  Bound the
            # scan so hostile directory iterators cannot be drained.
            root_entries = list(islice(entries, 2))
    except OSError as exc:
        raise _error("cannot enumerate semantic object root", exc) from exc
    if not root_entries:
        if allow_empty_root_without_sha256:
            return []
        raise SemanticObjectError("semantic object store is incomplete: missing SHA-256 root")
    if len(root_entries) != 1 or root_entries[0].name != "sha256":
        raise SemanticObjectError("semantic object root has an unexpected entry")
    sha_root = _private_directory(
        root / "sha256", "semantic object SHA-256 root", create=False
    )
    paths_out: list[Path] = []
    try:
        with os.scandir(sha_root) as shards:
            for shard_entry in shards:
                shard = Path(shard_entry.path)
                if not _SHARD.fullmatch(shard.name):
                    raise SemanticObjectError("semantic object store has an unexpected shard")
                _private_directory(shard, "semantic object shard", create=False)
                with os.scandir(shard) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name):
                            raise SemanticObjectError("semantic object store has an unexpected entry")
                        paths_out.append(path)
                        if len(paths_out) > MAX_OBJECTS_PER_TASK:
                            raise SemanticObjectError("semantic object store exceeds object count bound")
    except SemanticObjectError:
        raise
    except OSError as exc:
        raise _error("cannot enumerate semantic object store", exc) from exc
    return sorted(paths_out, key=lambda item: item.name)


def _validated_object_namespace(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    allow_empty_root_without_sha256: bool = False,
) -> tuple[list[tuple[Path, dict[str, Any]]], int]:
    """Authenticate every object and its aggregate storage budget."""

    entries: list[tuple[Path, dict[str, Any]]] = []
    aggregate = 0
    seen: set[str] = set()
    for path in _scan_object_paths(
        paths,
        task_id,
        allow_empty_root_without_sha256=allow_empty_root_without_sha256,
    ):
        wrapped = _load_object(path, task_id)
        digest = wrapped["object_sha256"]
        if digest in seen:
            raise SemanticObjectError("semantic object store has duplicate object digest")
        seen.add(digest)
        aggregate += len(
            semantic.canonical_json_bytes(
                wrapped, max_bytes=_object_limit(wrapped["object_type"])
            )
        )
        if aggregate > MAX_OBJECT_AGGREGATE_BYTES:
            raise SemanticObjectError("semantic object store exceeds aggregate byte bound")
        entries.append((path, wrapped))
    return entries, aggregate


def _scan_binding_paths(paths: h.HarnessPaths, task_id: str) -> list[tuple[str, Path]]:
    task = _task_directory(paths, task_id)
    root = task / "semantic-bindings"
    if not root.exists() and not h._path_is_link_like(root):
        return []
    root = _private_directory(root, "semantic binding root", create=False)
    found: list[tuple[str, Path]] = []
    try:
        with os.scandir(root) as kinds:
            for kind_entry in kinds:
                kind = kind_entry.name
                if kind not in BINDING_KINDS:
                    raise SemanticObjectError("semantic binding store has an unsupported kind")
                kind_path = _private_directory(Path(kind_entry.path), "semantic binding kind directory", create=False)
                with os.scandir(kind_path) as shards:
                    for shard_entry in shards:
                        shard = Path(shard_entry.path)
                        if not _SHARD.fullmatch(shard.name):
                            raise SemanticObjectError("semantic binding store has an unexpected shard")
                        _private_directory(shard, "semantic binding shard", create=False)
                        with os.scandir(shard) as entries:
                            for entry in entries:
                                path = Path(entry.path)
                                if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name):
                                    raise SemanticObjectError("semantic binding store has an unexpected entry")
                                found.append((kind, path))
                                if len(found) > MAX_BINDINGS_PER_TASK:
                                    raise SemanticObjectError("semantic binding store exceeds binding count bound")
    except SemanticObjectError:
        raise
    except OSError as exc:
        raise _error("cannot enumerate semantic binding store", exc) from exc
    return sorted(found, key=lambda item: (item[0], item[1].name))


def _authenticated_event_chain(
    paths: h.HarnessPaths,
    event_chain: Iterable[Mapping[str, Any]],
    task_id: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], str, dict[str, Any]]:
    """Replay one bounded task-local chain and match it to the live ledger head."""

    try:
        records = list(islice(iter(event_chain), semantic.MAX_LEDGER_EVENTS + 1))
        projection = semantic.replay_events(records)
        genesis_snapshot = records[0]["payload"]["snapshot"]
        if not isinstance(genesis_snapshot, Mapping) or genesis_snapshot.get("task_id") != task_id:
            raise SemanticObjectError("semantic ledger genesis task identity does not match binding store")
        for record in records[1:]:
            delta = record["payload"]["delta"]
            for operation in delta["operations"]:
                path = operation["path"]
                if path[0] == "task_id":
                    raise SemanticObjectError("semantic ledger transition may not mutate task identity")
        domain = semantic.projection_domain(projection)
        if domain.get("task_id") != task_id:
            raise SemanticObjectError("semantic event chain task identity does not match binding store")
        envelope = projection[semantic.SEMANTIC_ENVELOPE_KEY]
        head = envelope["head_event_sha256"]
        # Keep this import local: semantic_store intentionally does not depend
        # on semantic objects, and this preserves that one-way import boundary.
        from . import semantic_store

        live_head = semantic_store.semantic_head(paths, task_id)
        if live_head["sequence"] != records[-1]["sequence"] or live_head["event_sha256"] != head:
            raise SemanticObjectError("semantic event chain does not match the live ledger head")
        by_sha: dict[str, dict[str, Any]] = {}
        for record in records:
            # ``replay_events`` validates every record first; this local index
            # deliberately exposes only those replay-authenticated metadata.
            digest = record["event_sha256"]
            if digest in by_sha:
                raise SemanticObjectError("semantic ledger contains duplicate event SHA-256")
            by_sha[digest] = cast(dict[str, Any], record)
        return cast(list[dict[str, Any]], records), by_sha, cast(str, head), projection
    except SemanticObjectError:
        raise
    except (KeyError, TypeError, h.HarnessError, semantic.SemanticEventError) as exc:
        raise _error("semantic event chain is invalid", exc) from exc


def _validate_binding_event_match(
    binding: Mapping[str, Any], event_by_sha: Mapping[str, Mapping[str, Any]]
) -> bool:
    """Return whether the planned event committed this binding, fail-closed on mismatch."""

    event = event_by_sha.get(binding["planned_event_sha256"])
    if event is None:
        return False
    if (
        event["prev_event_sha256"] != binding["expected_semantic_head_sha256"]
        or event["result_projection_sha256"] != binding["result_projection_sha256"]
    ):
        raise SemanticObjectError("semantic binding does not match its planned ledger event")
    return True


def _disposition_time(value: Any, label: str):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 64
    ):
        raise SemanticObjectError(f"{label} is invalid")
    parsed = h.parse_tz_aware_time(value)
    if parsed is None:
        raise SemanticObjectError(f"{label} is invalid")
    return parsed


def _validate_release_abandonment_row_v1(
    value: Any,
    *,
    task_id: str,
    binding_sha256: str,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one ledger-owned release-binding abandonment row."""

    if not isinstance(value, Mapping) or set(value) != _ABANDONMENT_V1_FIELDS:
        raise SemanticObjectError("semantic binding abandonment row schema is invalid")
    row = _clone(value, max_bytes=MAX_BINDING_DISPOSITION_BYTES)
    if row["schema_version"] != BINDING_DISPOSITION_SCHEMA_VERSION:
        raise SemanticObjectError("semantic binding abandonment row version is unsupported")
    try:
        if h.validate_id(row["task_id"], "task id") != task_id:
            raise SemanticObjectError("semantic binding abandonment task identity is invalid")
        h.validate_id(row["abandonment_command_id"], "semantic command id")
    except (h.HarnessError, TypeError) as exc:
        raise _error("semantic binding abandonment identity is invalid", exc) from exc
    if row["binding_sha256"] != binding_sha256:
        raise SemanticObjectError("semantic binding abandonment key/digest mismatch")
    for key, label in (
        ("binding_sha256", "semantic binding abandonment binding SHA-256"),
        ("expected_semantic_head_sha256", "semantic binding abandonment expected head"),
        ("planned_event_sha256", "semantic binding abandonment planned event"),
        ("result_projection_sha256", "semantic binding abandonment result projection"),
    ):
        _validate_sha(row[key], label)
    if row["binding_kind"] != "release_promotion":
        raise SemanticObjectError("semantic binding abandonment kind is unsupported")
    _validate_text(row["binding_key"], "semantic binding abandonment key", MAX_BINDING_KEY_CHARS)
    reason = row["reason"]
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or reason != reason.strip()
        or len(reason.encode("utf-8")) > 2048
        or any(ord(character) < 0x20 for character in reason)
    ):
        raise SemanticObjectError("semantic binding abandonment reason is invalid")

    original = row["original_event"]
    if not isinstance(original, Mapping) or set(original) != _ORIGINAL_EVENT_FIELDS:
        raise SemanticObjectError("semantic binding abandonment original event is invalid")
    try:
        h.validate_id(original["command_id"], "semantic command id")
    except (h.HarnessError, TypeError) as exc:
        raise _error("semantic binding abandonment original command is invalid", exc) from exc
    original_at = _disposition_time(
        original["recorded_at"], "semantic binding abandonment original recorded_at"
    )
    if (
        original["event_type"] != RELEASE_PROMOTION_EVENT_TYPE
        or original["event_sha256"] != row["planned_event_sha256"]
    ):
        raise SemanticObjectError("semantic binding abandonment original event does not match binding")
    old_authority = _RELEASE_AUTHORITY_REF.fullmatch(str(original["authority_ref"]))
    if old_authority is None:
        raise SemanticObjectError("semantic binding abandonment original authority is invalid")

    takeover = row["takeover"]
    if not isinstance(takeover, Mapping) or set(takeover) != _TAKEOVER_FIELDS:
        raise SemanticObjectError("semantic binding abandonment takeover proof is invalid")
    audit_base = {
        key: takeover[key]
        for key in _TAKEOVER_FIELDS
        if key != "audit_event_sha256"
    }
    if takeover["audit_event_sha256"] != _sha(audit_base, max_bytes=MAX_BINDING_BYTES):
        raise SemanticObjectError("semantic binding abandonment takeover digest is invalid")
    if (
        not isinstance(takeover["seq"], int)
        or isinstance(takeover["seq"], bool)
        or takeover["seq"] < 1
        or takeover["action"] != "takeover"
        or not isinstance(takeover["old_epoch"], int)
        or isinstance(takeover["old_epoch"], bool)
        or takeover["old_epoch"] < 1
        or not isinstance(takeover["new_epoch"], int)
        or isinstance(takeover["new_epoch"], bool)
        or takeover["new_epoch"] != takeover["old_epoch"] + 1
        or not isinstance(takeover["forced_live"], bool)
    ):
        raise SemanticObjectError("semantic binding abandonment takeover fields are invalid")
    try:
        h.validate_id(takeover["session_id"], "Chief session id")
        h.validate_id(takeover["previous_session_id"], "previous Chief session id")
    except (h.HarnessError, TypeError) as exc:
        raise _error("semantic binding abandonment takeover identity is invalid", exc) from exc
    takeover_reason = takeover["reason"]
    if (
        not isinstance(takeover_reason, str)
        or not takeover_reason.strip()
        or takeover_reason != takeover_reason.strip()
        or len(takeover_reason.encode("utf-8")) > 2048
    ):
        raise SemanticObjectError("semantic binding abandonment takeover reason is invalid")
    takeover_at = _disposition_time(
        takeover["at"], "semantic binding abandonment takeover time"
    )
    abandonment_at = _disposition_time(
        row["abandonment_recorded_at"],
        "semantic binding abandonment recorded_at",
    )
    if not original_at < takeover_at <= abandonment_at:
        raise SemanticObjectError("semantic binding abandonment time order is invalid")
    if (
        old_authority.group(1) != takeover["previous_session_id"]
        or int(old_authority.group(2)) != takeover["old_epoch"]
    ):
        raise SemanticObjectError("semantic binding abandonment takeover does not retire original authority")

    abandon_authority = _RELEASE_ABANDON_AUTHORITY_REF.fullmatch(
        str(row["abandonment_authority_ref"])
    )
    if (
        abandon_authority is None
        or abandon_authority.group(1) != takeover["session_id"]
        or int(abandon_authority.group(2)) != takeover["new_epoch"]
        or abandon_authority.group(3) != binding_sha256
        or event.get("event_type") != RELEASE_ABANDONMENT_EVENT_TYPE
        or event.get("command_id") != row["abandonment_command_id"]
        or event.get("recorded_at") != row["abandonment_recorded_at"]
        or event.get("authority_ref") != row["abandonment_authority_ref"]
        or event.get("prev_event_sha256") != row["expected_semantic_head_sha256"]
    ):
        raise SemanticObjectError("semantic binding abandonment event metadata is invalid")
    return row


def _validate_release_abandonment_row_v2(
    value: Any,
    *,
    task_id: str,
    binding_sha256: str,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the audit-tail-independent retirement proof row."""

    if not isinstance(value, Mapping) or set(value) != _ABANDONMENT_V2_FIELDS:
        raise SemanticObjectError("semantic binding abandonment row schema is invalid")
    row = _clone(value, max_bytes=MAX_BINDING_DISPOSITION_BYTES)
    if row["schema_version"] != 2:
        raise SemanticObjectError("semantic binding abandonment row version is unsupported")
    try:
        if h.validate_id(row["task_id"], "task id") != task_id:
            raise SemanticObjectError("semantic binding abandonment task identity is invalid")
        h.validate_id(row["abandonment_command_id"], "semantic command id")
    except (h.HarnessError, TypeError) as exc:
        raise _error("semantic binding abandonment identity is invalid", exc) from exc
    if row["binding_sha256"] != binding_sha256:
        raise SemanticObjectError("semantic binding abandonment key/digest mismatch")
    for key, label in (
        ("binding_sha256", "semantic binding abandonment binding SHA-256"),
        ("expected_semantic_head_sha256", "semantic binding abandonment expected head"),
        ("planned_event_sha256", "semantic binding abandonment planned event"),
        ("result_projection_sha256", "semantic binding abandonment result projection"),
    ):
        _validate_sha(row[key], label)
    if row["binding_kind"] != "release_promotion":
        raise SemanticObjectError("semantic binding abandonment kind is unsupported")
    _validate_text(row["binding_key"], "semantic binding abandonment key", MAX_BINDING_KEY_CHARS)
    reason = row["reason"]
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or reason != reason.strip()
        or len(reason.encode("utf-8")) > 2048
        or any(ord(character) < 0x20 for character in reason)
    ):
        raise SemanticObjectError("semantic binding abandonment reason is invalid")
    original = row["original_event"]
    if not isinstance(original, Mapping) or set(original) != _ORIGINAL_EVENT_FIELDS:
        raise SemanticObjectError("semantic binding abandonment original event is invalid")
    try:
        h.validate_id(original["command_id"], "semantic command id")
    except (h.HarnessError, TypeError) as exc:
        raise _error("semantic binding abandonment original command is invalid", exc) from exc
    original_at = _disposition_time(
        original["recorded_at"], "semantic binding abandonment original recorded_at"
    )
    if (
        original["event_type"] != RELEASE_PROMOTION_EVENT_TYPE
        or original["event_sha256"] != row["planned_event_sha256"]
    ):
        raise SemanticObjectError("semantic binding abandonment original event does not match binding")
    retired_authority = _RELEASE_AUTHORITY_REF.fullmatch(str(original["authority_ref"]))
    if retired_authority is None:
        raise SemanticObjectError("semantic binding abandonment original authority is invalid")
    proof = row["retirement_proof"]
    if not isinstance(proof, Mapping) or set(proof) != _RETIREMENT_PROOF_FIELDS:
        raise SemanticObjectError("semantic binding abandonment retirement proof is invalid")
    if proof["proof_kind"] != "monotonic_chief_epoch":
        raise SemanticObjectError("semantic binding abandonment retirement proof kind is invalid")
    try:
        successor_session_id = h.validate_id(proof["successor_session_id"], "Chief session id")
    except (h.HarnessError, TypeError) as exc:
        raise _error("semantic binding abandonment successor identity is invalid", exc) from exc
    successor_epoch = proof["successor_epoch"]
    retired_epoch = int(retired_authority.group(2))
    if (
        not isinstance(successor_epoch, int)
        or isinstance(successor_epoch, bool)
        or successor_epoch <= retired_epoch
    ):
        raise SemanticObjectError("semantic binding abandonment successor epoch is invalid")
    _validate_sha(
        proof["current_authority_record_sha256"],
        "semantic binding abandonment authority record SHA-256",
    )
    issued_at = _disposition_time(
        proof["issued_at"], "semantic binding abandonment successor issued_at"
    )
    expires_at = _disposition_time(
        proof["expires_at"], "semantic binding abandonment successor expires_at"
    )
    abandonment_at = _disposition_time(
        row["abandonment_recorded_at"],
        "semantic binding abandonment recorded_at",
    )
    if not original_at < issued_at <= abandonment_at < expires_at:
        raise SemanticObjectError("semantic binding abandonment time order is invalid")
    abandon_authority = _RELEASE_ABANDON_AUTHORITY_REF.fullmatch(
        str(row["abandonment_authority_ref"])
    )
    if (
        abandon_authority is None
        or abandon_authority.group(1) != successor_session_id
        or int(abandon_authority.group(2)) != successor_epoch
        or abandon_authority.group(3) != binding_sha256
        or event.get("event_type") != RELEASE_ABANDONMENT_EVENT_TYPE
        or event.get("command_id") != row["abandonment_command_id"]
        or event.get("recorded_at") != row["abandonment_recorded_at"]
        or event.get("authority_ref") != row["abandonment_authority_ref"]
        or event.get("prev_event_sha256") != row["expected_semantic_head_sha256"]
    ):
        raise SemanticObjectError("semantic binding abandonment event metadata is invalid")
    return row


def _validate_release_abandonment_row(
    value: Any,
    *,
    task_id: str,
    binding_sha256: str,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Dual-read historical v1 rows and write-era v2 rows under namespace v1."""

    if not isinstance(value, Mapping):
        raise SemanticObjectError("semantic binding abandonment row schema is invalid")
    if value.get("schema_version") == 1:
        return _validate_release_abandonment_row_v1(
            value, task_id=task_id, binding_sha256=binding_sha256, event=event
        )
    if value.get("schema_version") == 2:
        return _validate_release_abandonment_row_v2(
            value, task_id=task_id, binding_sha256=binding_sha256, event=event
        )
    raise SemanticObjectError("semantic binding abandonment row version is unsupported")


def _validated_binding_dispositions(
    records: list[dict[str, Any]],
    projection: Mapping[str, Any],
    task_id: str,
) -> dict[str, dict[str, Any]]:
    """Authenticate the append-only disposition namespace in one linear scan."""

    genesis = records[0]["payload"]["snapshot"]
    if isinstance(genesis, Mapping) and BINDING_DISPOSITIONS_KEY in genesis:
        raise SemanticObjectError("semantic binding dispositions may not be injected at genesis")
    dispositions: dict[str, dict[str, Any]] = {}
    for event in records[1:]:
        payload = event["payload"]
        delta = payload["delta"]
        operations = delta["operations"]
        touches = [
            operation
            for operation in operations
            if isinstance(operation, Mapping)
            and isinstance(operation.get("path"), list)
            and operation["path"]
            and operation["path"][0] == BINDING_DISPOSITIONS_KEY
        ]
        if not touches and event["event_type"] != RELEASE_ABANDONMENT_EVENT_TYPE:
            continue
        if event["event_type"] != RELEASE_ABANDONMENT_EVENT_TYPE or len(operations) != 1 or len(touches) != 1:
            raise SemanticObjectError("semantic binding disposition event/delta ownership is invalid")
        operation = touches[0]
        if operation.get("op") != "set" or set(operation) != {"op", "path", "value"}:
            raise SemanticObjectError("semantic binding disposition must be one set operation")
        path = operation["path"]
        value = operation["value"]
        if not dispositions:
            if path != [BINDING_DISPOSITIONS_KEY]:
                raise SemanticObjectError("first semantic binding disposition must create its namespace")
            if not isinstance(value, Mapping) or set(value) != _DISPOSITION_FIELDS:
                raise SemanticObjectError("semantic binding disposition namespace schema is invalid")
            abandoned = value.get("abandoned")
            if (
                value.get("schema_version") != BINDING_DISPOSITION_SCHEMA_VERSION
                or not isinstance(abandoned, Mapping)
                or len(abandoned) != 1
            ):
                raise SemanticObjectError("first semantic binding disposition namespace is invalid")
            binding_sha256, raw_row = next(iter(abandoned.items()))
        else:
            if (
                len(path) != 3
                or path[:2] != [BINDING_DISPOSITIONS_KEY, "abandoned"]
            ):
                raise SemanticObjectError("semantic binding disposition append path is invalid")
            binding_sha256 = path[2]
            raw_row = value
        _validate_sha(binding_sha256, "semantic binding disposition key")
        if binding_sha256 in dispositions:
            raise SemanticObjectError("semantic binding disposition may not overwrite a row")
        if len(dispositions) >= MAX_BINDING_DISPOSITIONS:
            raise SemanticObjectError("semantic binding disposition count exceeds its bound")
        row = _validate_release_abandonment_row(
            raw_row,
            task_id=task_id,
            binding_sha256=binding_sha256,
            event=event,
        )
        dispositions[binding_sha256] = {
            "row": row,
            "event_sha256": event["event_sha256"],
        }
        namespace = {
            "schema_version": BINDING_DISPOSITION_SCHEMA_VERSION,
            "abandoned": {
                digest: item["row"] for digest, item in sorted(dispositions.items())
            },
        }
        semantic.canonical_json_bytes(
            namespace, max_bytes=MAX_BINDING_DISPOSITION_BYTES
        )

    domain = semantic.projection_domain(projection)
    expected_namespace = (
        {
            "schema_version": BINDING_DISPOSITION_SCHEMA_VERSION,
            "abandoned": {
                digest: item["row"] for digest, item in sorted(dispositions.items())
            },
        }
        if dispositions
        else None
    )
    if domain.get(BINDING_DISPOSITIONS_KEY) != expected_namespace:
        if expected_namespace is None and BINDING_DISPOSITIONS_KEY not in domain:
            return dispositions
        raise SemanticObjectError("semantic binding disposition projection differs from its ledger events")
    return dispositions


def _validated_binding_namespace(
    paths: h.HarnessPaths,
    task_id: str,
    objects: Mapping[str, Mapping[str, Any]],
    event_by_sha: Mapping[str, Mapping[str, Any]],
    current_head: str,
    dispositions: Mapping[str, Mapping[str, Any]],
) -> list[tuple[str, Path, dict[str, Any], str, dict[str, Any] | None]]:
    """Authenticate all bindings, references, event matches, and planned-event uniqueness."""

    entries: list[
        tuple[str, Path, dict[str, Any], str, dict[str, Any] | None]
    ] = []
    planned_events: set[str] = set()
    observed_bindings: set[str] = set()
    pending_count = 0
    for kind, path in _scan_binding_paths(paths, task_id):
        binding = _load_binding(path, task_id, kind)
        planned = binding["planned_event_sha256"]
        if planned in planned_events:
            raise SemanticObjectError("semantic binding store has duplicate planned ledger event")
        planned_events.add(planned)
        for digest in binding["object_sha256s"]:
            if digest not in objects:
                raise SemanticObjectError("semantic binding references a missing object")
        binding_sha256 = binding["binding_sha256"]
        observed_bindings.add(binding_sha256)
        disposition = dispositions.get(binding_sha256)
        committed = _validate_binding_event_match(binding, event_by_sha)
        if committed and disposition is not None:
            raise SemanticObjectError("semantic binding is both committed and abandoned")
        if committed:
            classification = "committed"
            abandonment = None
        elif disposition is not None:
            row = disposition.get("row")
            if not isinstance(row, Mapping):
                raise SemanticObjectError("semantic binding abandonment report is invalid")
            for field in (
                "task_id",
                "binding_sha256",
                "binding_kind",
                "binding_key",
                "expected_semantic_head_sha256",
                "planned_event_sha256",
                "result_projection_sha256",
            ):
                if row.get(field) != binding[field]:
                    raise SemanticObjectError("semantic binding abandonment differs from its binding")
            classification = "abandoned"
            abandonment = {
                "row": _clone(row, max_bytes=MAX_BINDING_DISPOSITION_BYTES),
                "event_sha256": disposition.get("event_sha256"),
            }
        else:
            if binding["expected_semantic_head_sha256"] != current_head:
                raise SemanticObjectError("semantic binding pending retry expected head is no longer current")
            classification = "pending"
            abandonment = None
            pending_count += 1
            if pending_count > 1:
                raise SemanticObjectError("semantic binding store has more than one pending binding")
        entries.append((kind, path, binding, classification, abandonment))
    if set(dispositions) != observed_bindings.intersection(dispositions):
        raise SemanticObjectError("semantic binding disposition references a missing binding")
    return entries


def publish_semantic_object(paths: h.HarnessPaths, value: Mapping[str, Any]) -> dict[str, Any]:
    """No-replace publish one sealed object; exact existing bytes are a retry."""

    _require_lock(paths)
    wrapped = validate_semantic_object(value)
    task_id = wrapped["task_id"]
    digest = wrapped["object_sha256"]
    raw = semantic.canonical_json_bytes(wrapped, max_bytes=_object_limit(wrapped["object_type"]))
    # Validate the whole managed namespace before accepting another writer.
    # This keeps an injected alias/tamper from being ignored merely because it
    # is unrelated to the digest the caller happens to publish.
    existing_entries, aggregate = _validated_object_namespace(
        paths, task_id, allow_empty_root_without_sha256=True
    )
    existing = [item for _path, item in existing_entries]
    if aggregate > MAX_OBJECT_AGGREGATE_BYTES:
        raise SemanticObjectError("semantic object store exceeds aggregate byte bound")
    destination = semantic_object_path(paths, task_id, digest)
    if destination.exists() or h._path_is_link_like(destination):
        stored = _load_object(destination, task_id)
        stored_raw = semantic.canonical_json_bytes(stored, max_bytes=_object_limit(stored["object_type"]))
        if stored_raw != raw:
            raise SemanticObjectError("semantic object digest collision has divergent bytes")
        return _clone(stored, max_bytes=_object_limit(stored["object_type"]))
    if len(existing) >= MAX_OBJECTS_PER_TASK:
        raise SemanticObjectError("semantic object store exceeds object count bound")
    if aggregate + len(raw) > MAX_OBJECT_AGGREGATE_BYTES:
        raise SemanticObjectError("semantic object store exceeds aggregate byte bound")
    _ensure_object_shard(paths, task_id, digest)
    try:
        h.atomic_create_bytes(destination, raw)
    except h.HarnessError as exc:
        if not (destination.exists() or h._path_is_link_like(destination)):
            raise _error("cannot publish semantic object", exc) from exc
        stored = _load_object(destination, task_id)
        stored_raw = semantic.canonical_json_bytes(stored, max_bytes=_object_limit(stored["object_type"]))
        if stored_raw != raw:
            raise SemanticObjectError("semantic object publication collided with divergent bytes") from exc
    return _clone(wrapped, max_bytes=_object_limit(wrapped["object_type"]))


def publish_semantic_binding(
    paths: h.HarnessPaths,
    value: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Publish one binding against a replay-authenticated current ledger chain.

    A new binding is admitted only before its planned event and only at its
    declared ledger head.  Exact existing bytes remain recoverable after a
    crash, including once the planned event has committed.
    """

    _require_lock(paths)
    wrapped = validate_semantic_binding(value)
    task_id = wrapped["task_id"]
    kind = wrapped["binding_kind"]
    raw = semantic.canonical_json_bytes(wrapped, max_bytes=MAX_BINDING_BYTES)
    records, event_by_sha, current_head, projection = _authenticated_event_chain(
        paths, event_chain, task_id
    )
    dispositions = _validated_binding_dispositions(records, projection, task_id)
    object_entries, _aggregate = _validated_object_namespace(paths, task_id)
    stored_objects = {item["object_sha256"]: item for _path, item in object_entries}
    existing_entries = _validated_binding_namespace(
        paths, task_id, stored_objects, event_by_sha, current_head, dispositions
    )
    destination = semantic_binding_path(paths, task_id, kind, wrapped["binding_key"])
    if destination.exists() or h._path_is_link_like(destination):
        stored = _load_binding(destination, task_id, kind)
        stored_raw = semantic.canonical_json_bytes(stored, max_bytes=MAX_BINDING_BYTES)
        if stored_raw != raw:
            raise SemanticObjectError("semantic binding key collision has divergent bytes")
        return _clone(stored, max_bytes=MAX_BINDING_BYTES)
    if any(
        classification == "pending"
        for _existing_kind, _existing_path, _existing, classification, _abandonment in existing_entries
    ):
        raise SemanticObjectError("semantic task has a pending binding")
    if len(existing_entries) >= MAX_BINDINGS_PER_TASK:
        raise SemanticObjectError("semantic binding store exceeds binding count bound")
    if any(
        existing["planned_event_sha256"] == wrapped["planned_event_sha256"]
        for _existing_kind, _existing_path, existing, _classification, _abandonment in existing_entries
    ):
        raise SemanticObjectError("semantic binding planned ledger event is already bound")
    # Validate all references before publishing the binding, so an ordinary
    # missing-reference request cannot create an authoritative partial binding.
    for digest in wrapped["object_sha256s"]:
        if digest not in stored_objects:
            raise SemanticObjectError("semantic binding references a missing object")
    if wrapped["planned_event_sha256"] in event_by_sha:
        raise SemanticObjectError("semantic binding planned ledger event is already committed")
    if wrapped["expected_semantic_head_sha256"] != current_head:
        raise SemanticObjectError("semantic binding expected head does not match current ledger head")
    _ensure_binding_shard(paths, task_id, kind, wrapped["binding_key"])
    try:
        h.atomic_create_bytes(destination, raw)
    except h.HarnessError as exc:
        if not (destination.exists() or h._path_is_link_like(destination)):
            raise _error("cannot publish semantic binding", exc) from exc
        stored = _load_binding(destination, task_id, kind)
        stored_raw = semantic.canonical_json_bytes(stored, max_bytes=MAX_BINDING_BYTES)
        if stored_raw != raw:
            raise SemanticObjectError("semantic binding publication collided with divergent bytes") from exc
    return _clone(wrapped, max_bytes=MAX_BINDING_BYTES)


def inspect_semantic_objects(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Authenticate stored items and classify bindings against a full ledger chain."""

    task_id = h.validate_id(task_id, "task id")
    records, event_by_sha, current_head, projection = _authenticated_event_chain(
        paths, event_chain, task_id
    )
    dispositions = _validated_binding_dispositions(records, projection, task_id)
    object_entries, _aggregate = _validated_object_namespace(paths, task_id)
    objects = {wrapped["object_sha256"]: wrapped for _path, wrapped in object_entries}
    bindings: list[dict[str, Any]] = []
    references: dict[str, list[str]] = {digest: [] for digest in objects}
    for _kind, _path, wrapped, classification, abandonment in _validated_binding_namespace(
        paths, task_id, objects, event_by_sha, current_head, dispositions
    ):
        for digest in wrapped["object_sha256s"]:
            references[digest].append(wrapped["binding_sha256"])
        row = {
            **_clone(wrapped, max_bytes=MAX_BINDING_BYTES),
            "classification": classification,
        }
        if abandonment is not None:
            row["abandonment"] = abandonment["row"]
            row["abandonment_event_sha256"] = abandonment["event_sha256"]
        bindings.append(row)
    bindings.sort(key=lambda item: (item["binding_kind"], item["binding_key"], item["binding_sha256"]))
    binding_classification = {
        item["binding_sha256"]: item["classification"] for item in bindings
    }
    object_rows = []
    for digest, wrapped in sorted(objects.items()):
        owners = sorted(references[digest])
        object_rows.append(
            {
                **_clone(wrapped, max_bytes=_object_limit(wrapped["object_type"])),
                "classification": "orphan" if not owners else "referenced",
                "binding_sha256s": owners,
                "committed_binding_sha256s": [
                    owner for owner in owners if binding_classification[owner] == "committed"
                ],
                "pending_binding_sha256s": [
                    owner for owner in owners if binding_classification[owner] == "pending"
                ],
                "abandoned_binding_sha256s": [
                    owner for owner in owners if binding_classification[owner] == "abandoned"
                ],
            }
        )
    pending = [item["binding_sha256"] for item in bindings if item["classification"] == "pending"]
    committed = [item["binding_sha256"] for item in bindings if item["classification"] == "committed"]
    abandoned = [item["binding_sha256"] for item in bindings if item["classification"] == "abandoned"]
    orphans = [item["object_sha256"] for item in object_rows if item["classification"] == "orphan"]
    return {
        "task_id": task_id,
        "objects": object_rows,
        "bindings": bindings,
        "committed_binding_sha256s": sorted(committed),
        "pending_binding_sha256s": sorted(pending),
        "abandoned_binding_sha256s": sorted(abandoned),
        "orphan_object_sha256s": sorted(orphans),
    }


def require_no_pending_bindings(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    *,
    expected_binding_sha256: str | None = None,
) -> dict[str, Any]:
    """Fail if uncommitted bindings remain, except one exact crash-retry binding."""

    _require_lock(paths)
    report = inspect_semantic_objects(paths, task_id, event_chain)
    pending = report["pending_binding_sha256s"]
    if expected_binding_sha256 is not None:
        _validate_sha(expected_binding_sha256, "expected pending binding SHA-256")
    if pending and (expected_binding_sha256 is None or pending != [expected_binding_sha256]):
        raise SemanticObjectError("semantic task has pending bindings")
    return report
