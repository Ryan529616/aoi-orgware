"""Pure, provider-neutral active-write admission contracts and comparison.

This module deliberately performs no ledger, dispatch, job, or filesystem I/O.
It freezes the strict W1 data and overlap semantics that the durable reducer
will consume in a later slice.  A digest, owner lineage, or scope digest is
never treated as mutual-exclusion evidence by itself.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Literal, cast

from ..semantic_events import (
    SemanticEventError,
    canonical_json_bytes,
    canonical_sha256,
)
from .file_governance import (
    ActiveWriteRefV1,
    FileGovernanceError,
    WriteRefKind,
)


WRITE_DOMAIN_BINDING_V1 = "WriteDomainBindingV1"
WORK_WRITE_INTENT_V1 = "WorkWriteIntentV1"
WRITE_ADMISSION_SCHEMA_VERSION = 1
MAX_WRITE_REFS = 64
MAX_OPAQUE_NAMESPACES = 64
MAX_HELD_WRITE_INTENTS = 256
MAX_HELD_WRITE_REFS = 4096
MAX_COVERAGE_GAPS = 256

OwnerKind = Literal["dispatch_request", "external_job"]
FilesystemFamily = Literal["posix-v1", "windows-backed-v1"]
OverlapStatus = Literal["overlap_clear", "conflict", "coverage_unknown"]
ConflictReason = Literal[
    "file_exact",
    "candidate_file_within_held_tree",
    "candidate_tree_contains_held_file",
    "tree_ancestor_overlap",
    "file_ancestor_topology",
    "output_namespace_exact",
    "serialization_key_exact",
]
CoverageGapReason = Literal[
    "legacy_active_owner_missing_intent",
    "active_owner_state_unknown",
    "active_owner_domain_unreconciled",
]

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_NAMESPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_SEMANTICS = frozenset(
    {"windows-win32-v1", "wsl-windows-drive-mount-v1"}
)
_REF_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "namespace",
        "canonical_identity",
        "filesystem_semantics",
    }
)
_DOMAIN_FIELDS = frozenset(
    {
        "contract_type",
        "schema_version",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "binding_id",
        "root_namespace",
        "filesystem_family",
        "opaque_namespaces",
        "created_at",
        "provenance",
        "observation",
        "binding_sha256",
    }
)
_INTENT_FIELDS = frozenset(
    {
        "contract_type",
        "schema_version",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "intent_id",
        "domain_binding_id",
        "domain_binding_sha256",
        "owner_kind",
        "owner_id",
        "owner_generation_id",
        "owner_anchor_sha256",
        "reservation_id",
        "task_id",
        "packet_id",
        "packet_sha256",
        "authority_scope_sha256",
        "refs",
        "refs_sha256",
        "created_at",
        "provenance",
        "observation",
        "intent_sha256",
    }
)


class WriteAdmissionError(ValueError):
    """A write-domain, intent, authority, or comparison input is ambiguous."""


@dataclass(frozen=True, slots=True, order=True)
class WriteConflictV1:
    """One deterministic conflict between a candidate and a held intent."""

    held_intent_id: str
    held_owner_kind: OwnerKind
    held_owner_id: str
    candidate_ref_index: int
    held_ref_index: int
    candidate_ref_sha256: str
    held_ref_sha256: str
    reason: ConflictReason


@dataclass(frozen=True, slots=True, order=True)
class WriteCoverageGapV1:
    """One active owner whose exact write coverage cannot be proven."""

    owner_kind: OwnerKind
    owner_id: str
    reason: CoverageGapReason

    def __post_init__(self) -> None:
        _identifier(self.owner_id, "coverage owner id")
        if not isinstance(self.owner_kind, str) or self.owner_kind not in {
            "dispatch_request",
            "external_job",
        }:
            raise WriteAdmissionError("coverage owner kind is invalid")
        if not isinstance(self.reason, str) or self.reason not in {
            "legacy_active_owner_missing_intent",
            "active_owner_state_unknown",
            "active_owner_domain_unreconciled",
        }:
            raise WriteAdmissionError("coverage gap reason is invalid")


@dataclass(frozen=True, slots=True)
class WriteAdmissionEvaluation:
    """Overlap-only input for a later authoritative reducer gate."""

    overlap_status: OverlapStatus
    authority_status: Literal["not_evaluated"]
    candidate_intent_id: str
    idempotent_replay: bool
    conflicts: tuple[WriteConflictV1, ...]
    coverage_gaps: tuple[WriteCoverageGapV1, ...]


def _object(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WriteAdmissionError(f"{label} schema is invalid")
    return dict(value)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WriteAdmissionError(f"{label} is not a canonical identifier")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise WriteAdmissionError(f"{label} is not lowercase SHA-256")
    return value


def _namespace(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAMESPACE.fullmatch(value):
        raise WriteAdmissionError(f"{label} is not a canonical namespace")
    return value


def _plain_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise WriteAdmissionError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise WriteAdmissionError(f"{label} must use bounded UTC Z form")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WriteAdmissionError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise WriteAdmissionError(f"{label} must use UTC")
    return value


def _known_observation(value: Any, label: str) -> dict[str, str]:
    item = _object(value, frozenset({"state", "reason"}), label)
    if item != {"state": "known", "reason": "observed"}:
        raise WriteAdmissionError(f"{label} must be known and observed")
    return cast(dict[str, str], item)


def _canonical_bytes(value: Any, label: str) -> bytes:
    try:
        return canonical_json_bytes(value)
    except SemanticEventError as exc:
        raise WriteAdmissionError(f"{label} is not canonical JSON") from exc


def _canonical_sha256(value: Any, label: str) -> str:
    try:
        return canonical_sha256(value)
    except SemanticEventError as exc:
        raise WriteAdmissionError(f"{label} is not canonical JSON") from exc


def _ref_payload(reference: ActiveWriteRefV1) -> dict[str, Any]:
    return {
        "schema_version": reference.schema_version,
        "kind": reference.kind,
        "namespace": reference.namespace,
        "canonical_identity": reference.canonical_identity,
        "filesystem_semantics": reference.filesystem_semantics,
    }


def validate_active_write_ref(value: Any) -> dict[str, Any]:
    """Validate and detach one canonical repo-wide or opaque write reference."""
    item = _object(value, _REF_FIELDS, "ActiveWriteRef")
    identity = item["canonical_identity"]
    try:
        if not isinstance(identity, str) or len(identity.encode("utf-8")) > 1024:
            raise WriteAdmissionError("ActiveWriteRef identity is unbounded")
    except UnicodeEncodeError as exc:
        raise WriteAdmissionError("ActiveWriteRef identity is invalid Unicode") from exc
    if (
        _plain_int(item["schema_version"], "ActiveWriteRef.schema_version", minimum=1)
        != WRITE_ADMISSION_SCHEMA_VERSION
    ):
        raise WriteAdmissionError("ActiveWriteRef version is invalid")
    try:
        reference = ActiveWriteRefV1(
            schema_version=cast(Literal[1], item["schema_version"]),
            kind=cast(WriteRefKind, item["kind"]),
            namespace=cast(str, item["namespace"]),
            canonical_identity=cast(str, item["canonical_identity"]),
            filesystem_semantics=cast(str, item["filesystem_semantics"]),
        )
    except (FileGovernanceError, TypeError) as exc:
        raise WriteAdmissionError("ActiveWriteRef is invalid") from exc
    result = _ref_payload(reference)
    if result != item:
        raise WriteAdmissionError("ActiveWriteRef is not canonically spelled")
    return result
def _ref_sort_key(reference: Mapping[str, Any]) -> bytes:
    return _canonical_bytes(reference, "ActiveWriteRef")


def _path_family(semantics: str) -> str:
    if semantics == "posix-v1":
        return "posix"
    if semantics in _WINDOWS_SEMANTICS:
        return "windows"
    raise WriteAdmissionError("filesystem semantics are unsupported")
def _path_identity(reference: Mapping[str, Any]) -> tuple[str, ...]:
    path = cast(str, reference["canonical_identity"])
    if _path_family(cast(str, reference["filesystem_semantics"])) == "windows":
        path = path.casefold()
    return tuple(path.split("/"))


def _path_relation(
    candidate: Mapping[str, Any],
    held: Mapping[str, Any],
) -> ConflictReason | None:
    candidate_parts = _path_identity(candidate)
    held_parts = _path_identity(held)
    candidate_kind = cast(str, candidate["kind"])
    held_kind = cast(str, held["kind"])
    candidate_prefix = candidate_parts == held_parts[: len(candidate_parts)]
    held_prefix = held_parts == candidate_parts[: len(held_parts)]
    if candidate_kind == held_kind == "file":
        if candidate_parts == held_parts:
            return "file_exact"
        if candidate_prefix or held_prefix:
            return "file_ancestor_topology"
        return None
    if candidate_kind == "file" and held_kind == "tree":
        if held_prefix:
            return "candidate_file_within_held_tree"
        if candidate_prefix:
            return "file_ancestor_topology"
        return None
    if candidate_kind == "tree" and held_kind == "file":
        if candidate_prefix:
            return "candidate_tree_contains_held_file"
        if held_prefix:
            return "file_ancestor_topology"
        return None
    if candidate_prefix or held_prefix:
        return "tree_ancestor_overlap"
    return None


def _ref_relation(
    candidate: Mapping[str, Any],
    held: Mapping[str, Any],
) -> ConflictReason | None:
    if candidate["namespace"] != held["namespace"]:
        return None
    candidate_kind = cast(str, candidate["kind"])
    held_kind = cast(str, held["kind"])
    if candidate_kind in {"file", "tree"} and held_kind in {"file", "tree"}:
        if _path_family(cast(str, candidate["filesystem_semantics"])) != _path_family(
            cast(str, held["filesystem_semantics"])
        ):
            raise WriteAdmissionError(
                "same write namespace has incompatible filesystem semantics"
            )
        return _path_relation(candidate, held)
    if candidate_kind != held_kind:
        return None
    if candidate["canonical_identity"] != held["canonical_identity"]:
        return None
    if candidate_kind == "output_namespace":
        return "output_namespace_exact"
    if candidate_kind == "serialization_key":
        return "serialization_key_exact"
    return None


def _validate_ref_sequence(value: Any) -> list[dict[str, Any]]:
    if (
        isinstance(value, (str, bytes, bytearray))
        or not isinstance(value, Sequence)
        or not 1 <= len(value) <= MAX_WRITE_REFS
    ):
        raise WriteAdmissionError("write refs are unbounded or empty")
    refs = [validate_active_write_ref(member) for member in value]
    if refs != sorted(refs, key=_ref_sort_key):
        raise WriteAdmissionError("write refs are not canonically sorted")
    for left_index, left in enumerate(refs):
        for right in refs[left_index + 1 :]:
            try:
                relation = _ref_relation(left, right)
            except WriteAdmissionError as exc:
                raise WriteAdmissionError(
                    "one intent mixes incompatible filesystem semantics"
                ) from exc
            if relation is not None:
                raise WriteAdmissionError(
                    "one intent contains duplicate or redundant write refs"
                )
    return refs


def _validate_opaque_namespaces(value: Any) -> list[dict[str, str]]:
    if (
        isinstance(value, (str, bytes, bytearray))
        or not isinstance(value, Sequence)
        or len(value) > MAX_OPAQUE_NAMESPACES
    ):
        raise WriteAdmissionError("opaque namespaces are invalid")
    result: list[dict[str, str]] = []
    for index, member in enumerate(value):
        item = _object(
            member,
            frozenset({"kind", "namespace"}),
            f"opaque_namespaces[{index}]",
        )
        kind = item["kind"]
        if not isinstance(kind, str) or kind not in {
            "output_namespace",
            "serialization_key",
        }:
            raise WriteAdmissionError("opaque namespace kind is invalid")
        result.append(
            {
                "kind": kind,
                "namespace": _namespace(
                    item["namespace"], f"opaque_namespaces[{index}].namespace"
                ),
            }
        )
    expected = sorted(
        result, key=lambda item: (item["kind"].encode(), item["namespace"].encode())
    )
    if result != expected or len({(item["kind"], item["namespace"]) for item in result}) != len(result):
        raise WriteAdmissionError("opaque namespaces must be sorted and unique")
    return result


def validate_write_domain_binding(value: Any) -> dict[str, Any]:
    """Validate an opaque domain registry without embedding deployment facts."""
    item = _object(value, _DOMAIN_FIELDS, "WriteDomainBinding")
    if (
        item["contract_type"] != WRITE_DOMAIN_BINDING_V1
        or _plain_int(item["schema_version"], "schema_version", minimum=1)
        != WRITE_ADMISSION_SCHEMA_VERSION
    ):
        raise WriteAdmissionError("WriteDomainBinding version is invalid")
    family = item["filesystem_family"]
    if not isinstance(family, str) or family not in {
        "posix-v1",
        "windows-backed-v1",
    }:
        raise WriteAdmissionError("WriteDomainBinding filesystem family is invalid")
    result: dict[str, Any] = {
        "contract_type": WRITE_DOMAIN_BINDING_V1,
        "schema_version": WRITE_ADMISSION_SCHEMA_VERSION,
        "company_id": _identifier(item["company_id"], "company_id"),
        "company_incarnation": _identifier(
            item["company_incarnation"], "company_incarnation"
        ),
        "lock_domain_generation": _plain_int(
            item["lock_domain_generation"], "lock_domain_generation", minimum=1
        ),
        "binding_id": _identifier(item["binding_id"], "binding_id"),
        "root_namespace": _namespace(item["root_namespace"], "root_namespace"),
        "filesystem_family": family,
        "opaque_namespaces": _validate_opaque_namespaces(item["opaque_namespaces"]),
        "created_at": _timestamp(item["created_at"], "created_at"),
        "provenance": item["provenance"],
        "observation": _known_observation(item["observation"], "observation"),
        "binding_sha256": _sha256(item["binding_sha256"], "binding_sha256"),
    }
    if result["provenance"] != "AOI_verified":
        raise WriteAdmissionError("WriteDomainBinding must be AOI-verified")
    unsigned = {key: result[key] for key in _DOMAIN_FIELDS - {"binding_sha256"}}
    if result["binding_sha256"] != _canonical_sha256(
        unsigned, "WriteDomainBinding"
    ):
        raise WriteAdmissionError("WriteDomainBinding digest differs")
    return result


def seal_write_domain_binding(value: Any) -> dict[str, Any]:
    """Seal and validate one unsigned domain binding."""
    unsigned_fields = _DOMAIN_FIELDS - {"binding_sha256"}
    item = _object(value, unsigned_fields, "unsigned WriteDomainBinding")
    sealed = {**item, "binding_sha256": _canonical_sha256(item, "WriteDomainBinding")}
    return validate_write_domain_binding(sealed)


def validate_work_write_intent(value: Any) -> dict[str, Any]:
    """Validate one immutable acquisition intent without resolving its owner."""
    item = _object(value, _INTENT_FIELDS, "WorkWriteIntent")
    if (
        item["contract_type"] != WORK_WRITE_INTENT_V1
        or _plain_int(item["schema_version"], "schema_version", minimum=1)
        != WRITE_ADMISSION_SCHEMA_VERSION
    ):
        raise WriteAdmissionError("WorkWriteIntent version is invalid")
    owner_kind = item["owner_kind"]
    if not isinstance(owner_kind, str) or owner_kind not in {
        "dispatch_request",
        "external_job",
    }:
        raise WriteAdmissionError("WorkWriteIntent owner kind is invalid")
    task_id = _identifier(item["task_id"], "task_id")
    packet_id = _identifier(item["packet_id"], "packet_id")
    packet_sha256 = _sha256(item["packet_sha256"], "packet_sha256")
    authority_scope_sha256 = _sha256(
        item["authority_scope_sha256"], "authority_scope_sha256"
    )
    refs = _validate_ref_sequence(item["refs"])
    refs_sha256 = _sha256(item["refs_sha256"], "refs_sha256")
    if refs_sha256 != _canonical_sha256(refs, "write refs"):
        raise WriteAdmissionError("write refs digest differs")
    result: dict[str, Any] = {
        "contract_type": WORK_WRITE_INTENT_V1,
        "schema_version": WRITE_ADMISSION_SCHEMA_VERSION,
        "company_id": _identifier(item["company_id"], "company_id"),
        "company_incarnation": _identifier(
            item["company_incarnation"], "company_incarnation"
        ),
        "lock_domain_generation": _plain_int(
            item["lock_domain_generation"], "lock_domain_generation", minimum=1
        ),
        "intent_id": _identifier(item["intent_id"], "intent_id"),
        "domain_binding_id": _identifier(
            item["domain_binding_id"], "domain_binding_id"
        ),
        "domain_binding_sha256": _sha256(
            item["domain_binding_sha256"], "domain_binding_sha256"
        ),
        "owner_kind": owner_kind,
        "owner_id": _identifier(item["owner_id"], "owner_id"),
        "owner_generation_id": _identifier(
            item["owner_generation_id"], "owner_generation_id"
        ),
        "owner_anchor_sha256": _sha256(
            item["owner_anchor_sha256"], "owner_anchor_sha256"
        ),
        "reservation_id": _identifier(item["reservation_id"], "reservation_id"),
        "task_id": task_id,
        "packet_id": packet_id,
        "packet_sha256": packet_sha256,
        "authority_scope_sha256": authority_scope_sha256,
        "refs": refs,
        "refs_sha256": refs_sha256,
        "created_at": _timestamp(item["created_at"], "created_at"),
        "provenance": item["provenance"],
        "observation": _known_observation(item["observation"], "observation"),
        "intent_sha256": _sha256(item["intent_sha256"], "intent_sha256"),
    }
    if result["provenance"] != "AOI_verified":
        raise WriteAdmissionError("WorkWriteIntent must be AOI-verified")
    unsigned = {key: result[key] for key in _INTENT_FIELDS - {"intent_sha256"}}
    if result["intent_sha256"] != _canonical_sha256(unsigned, "WorkWriteIntent"):
        raise WriteAdmissionError("WorkWriteIntent digest differs")
    return result


def seal_work_write_intent(value: Any) -> dict[str, Any]:
    """Seal and validate one unsigned work-write intent."""
    unsigned_fields = _INTENT_FIELDS - {"intent_sha256"}
    item = _object(value, unsigned_fields, "unsigned WorkWriteIntent")
    sealed = {**item, "intent_sha256": _canonical_sha256(item, "WorkWriteIntent")}
    return validate_work_write_intent(sealed)


def validate_intent_domain_binding(
    intent: Any,
    domain: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Cross-bind caller-selected refs to one registered opaque domain."""
    normalized_intent = validate_work_write_intent(intent)
    normalized_domain = validate_write_domain_binding(domain)
    if (
        normalized_intent["company_id"],
        normalized_intent["company_incarnation"],
        normalized_intent["lock_domain_generation"],
        normalized_intent["domain_binding_id"],
        normalized_intent["domain_binding_sha256"],
    ) != (
        normalized_domain["company_id"],
        normalized_domain["company_incarnation"],
        normalized_domain["lock_domain_generation"],
        normalized_domain["binding_id"],
        normalized_domain["binding_sha256"],
    ):
        raise WriteAdmissionError("write intent domain binding differs")
    allowed_opaque = {
        (item["kind"], item["namespace"])
        for item in normalized_domain["opaque_namespaces"]
    }
    family = cast(str, normalized_domain["filesystem_family"])
    for reference in normalized_intent["refs"]:
        kind = reference["kind"]
        if kind in {"file", "tree"}:
            if reference["namespace"] != normalized_domain["root_namespace"]:
                raise WriteAdmissionError("filesystem write namespace is unregistered")
            semantics = reference["filesystem_semantics"]
            if (
                family == "posix-v1"
                and semantics != "posix-v1"
                or family == "windows-backed-v1"
                and semantics not in _WINDOWS_SEMANTICS
            ):
                raise WriteAdmissionError("filesystem semantics differ from domain")
        elif (kind, reference["namespace"]) not in allowed_opaque:
            raise WriteAdmissionError("opaque write namespace is unregistered")
    return normalized_intent, normalized_domain


def evaluate_write_overlap(
    candidate: Any,
    held_intents: Sequence[Any],
    *,
    domain: Any,
    coverage_gaps: Sequence[WriteCoverageGapV1] = (),
) -> WriteAdmissionEvaluation:
    """Compare one candidate with the exact durable held set.

    ``held_intents`` must already be selected from authoritative owner
    lifecycles by the later reducer.  This pure layer never guesses whether a
    queued, stopped, terminal, or uncertain owner holds a claim.
    """
    if (
        isinstance(held_intents, (str, bytes, bytearray))
        or not isinstance(held_intents, Sequence)
    ):
        raise WriteAdmissionError("held write intent set is invalid")
    if (
        isinstance(coverage_gaps, (str, bytes, bytearray))
        or not isinstance(coverage_gaps, Sequence)
    ):
        raise WriteAdmissionError("write coverage gap set is invalid")
    if len(held_intents) > MAX_HELD_WRITE_INTENTS:
        raise WriteAdmissionError("held write intent set is too large")
    if len(coverage_gaps) > MAX_COVERAGE_GAPS:
        raise WriteAdmissionError("write coverage gap set is too large")
    normalized_candidate, normalized_domain = validate_intent_domain_binding(
        candidate, domain
    )
    normalized_held: list[dict[str, Any]] = []
    domain_gaps: list[WriteCoverageGapV1] = []
    seen_intent_ids: set[str] = set()
    replay = False
    held_ref_count = 0
    for raw in held_intents:
        held = validate_work_write_intent(raw)
        held_ref_count += len(held["refs"])
        if held_ref_count > MAX_HELD_WRITE_REFS:
            raise WriteAdmissionError("held write ref set is too large")
        held_id = cast(str, held["intent_id"])
        if held_id in seen_intent_ids:
            raise WriteAdmissionError("held write intent identity is duplicated")
        seen_intent_ids.add(held_id)
        if held_id == normalized_candidate["intent_id"]:
            if held["intent_sha256"] != normalized_candidate["intent_sha256"]:
                raise WriteAdmissionError("write intent identity is divergent")
            replay = True
            continue
        try:
            validate_intent_domain_binding(held, normalized_domain)
        except WriteAdmissionError:
            domain_gaps.append(
                WriteCoverageGapV1(
                    owner_kind=cast(OwnerKind, held["owner_kind"]),
                    owner_id=cast(str, held["owner_id"]),
                    reason="active_owner_domain_unreconciled",
                )
            )
            continue
        normalized_held.append(held)
    all_gaps = list(coverage_gaps) + domain_gaps
    if any(not isinstance(gap, WriteCoverageGapV1) for gap in all_gaps):
        raise WriteAdmissionError("write coverage gap is invalid")
    sorted_gaps = tuple(sorted(all_gaps))
    if len(set(sorted_gaps)) != len(sorted_gaps):
        raise WriteAdmissionError("write coverage gap is duplicated")
    conflicts: list[WriteConflictV1] = []
    for held in sorted(normalized_held, key=lambda item: cast(str, item["intent_id"])):
        for candidate_index, candidate_ref in enumerate(
            normalized_candidate["refs"]
        ):
            for held_index, held_ref in enumerate(held["refs"]):
                relation = _ref_relation(candidate_ref, held_ref)
                if relation is not None:
                    conflicts.append(
                        WriteConflictV1(
                            held_intent_id=cast(str, held["intent_id"]),
                            held_owner_kind=cast(OwnerKind, held["owner_kind"]),
                            held_owner_id=cast(str, held["owner_id"]),
                            candidate_ref_index=candidate_index,
                            held_ref_index=held_index,
                            candidate_ref_sha256=_canonical_sha256(
                                candidate_ref, "candidate write ref"
                            ),
                            held_ref_sha256=_canonical_sha256(
                                held_ref, "held write ref"
                            ),
                            reason=relation,
                        )
                    )
    ordered_conflicts = tuple(sorted(conflicts))
    status: OverlapStatus = (
        "coverage_unknown"
        if sorted_gaps
        else "conflict"
        if ordered_conflicts
        else "overlap_clear"
    )
    return WriteAdmissionEvaluation(
        overlap_status=status,
        authority_status="not_evaluated",
        candidate_intent_id=cast(str, normalized_candidate["intent_id"]),
        idempotent_replay=replay,
        conflicts=ordered_conflicts,
        coverage_gaps=sorted_gaps,
    )


__all__ = [
    "CoverageGapReason",
    "FilesystemFamily",
    "MAX_COVERAGE_GAPS",
    "MAX_HELD_WRITE_INTENTS",
    "MAX_HELD_WRITE_REFS",
    "MAX_OPAQUE_NAMESPACES",
    "MAX_WRITE_REFS",
    "OverlapStatus",
    "OwnerKind",
    "WORK_WRITE_INTENT_V1",
    "WRITE_ADMISSION_SCHEMA_VERSION",
    "WRITE_DOMAIN_BINDING_V1",
    "WriteAdmissionError",
    "WriteAdmissionEvaluation",
    "WriteConflictV1",
    "WriteCoverageGapV1",
    "evaluate_write_overlap",
    "seal_work_write_intent",
    "seal_write_domain_binding",
    "validate_active_write_ref",
    "validate_intent_domain_binding",
    "validate_work_write_intent",
    "validate_write_domain_binding",
]
