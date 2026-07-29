"""Pure acceptance-candidate derivation, deliberately below completion authority.

The caller supplies a bounded :class:`InvariantProjection`.  This module does
not prove that projection is complete, current, ledger-authoritative, or CAS
resident.  Its output is an ``acceptance_candidate`` review episode only; it
never changes task state and is not an engineering-completion receipt.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, NamedTuple, NoReturn

from aoi_orgware.company.contracts import (
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_NODE_V1,
    TASK_REVISION_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    canonical_work_context_manifest_bytes,
    company_contract_sha256,
    validate_dispatch_request,
    validate_engineering_disposition_receipt,
    validate_evidence_record,
    validate_execution_node,
    validate_task_revision,
    validate_work_dispatch_binding,
    validate_work_context_manifest,
    validate_work_definition_bundle,
    validate_work_packet,
    validate_work_result_receipt,
)
from aoi_orgware.company.invariants import InvariantObject, InvariantProjection
from aoi_orgware.company.latency.acceptance_history import (
    AcceptanceHistoryError,
    select_current_dispatch,
    select_current_execution,
    timestamp_precedes,
    validate_dispatch_history,
    validate_execution_predecessor_pair,
)


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA = re.compile(r"[0-9a-f]{64}")
_UNAVAILABLE = (
    ("work_plan_and_plan_node", "work_plan_revision_v1_is_not_available"),
    ("durable_work_attempt", "work_attempt_v1_is_not_available"),
    ("acceptance_time_current_baseline", "bounded_projection_cannot_prove_current_baseline"),
    ("ledger_head_currentness_completeness", "caller_supplied_projection_is_not_a_verified_snapshot"),
    ("cas_residency", "blob_residency_is_not_checked"),
    ("authenticated_identity", "execution_identity_is_cooperative_only"),
    ("common_monotonic_instant", "candidate_has_no_supervisor_clock_bracket"),
)
class EngineeringAcceptanceCandidateError(ValueError):
    """The bounded material cannot safely produce an acceptance candidate."""


class AcceptanceEvidenceRef(NamedTuple):
    contract_type: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str
    artifact_sha256: str
    command_sha256: str | None
    verification_sha256: str
    status: str
    reviewer_execution_id: str
    reviewer_execution_object_key: str
    reviewer_execution_event_id: str
    reviewer_execution_global_sequence: int
    reviewer_execution_payload_sha256: str
    reviewer_agent_id: str
    reviewer_carrier_id: str
    reviewer_thread_id: str
    canonical_payload_json: str
    reviewer_execution_payload_json: str


class AcceptanceObjectRef(NamedTuple):
    contract_type: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str
    canonical_payload_json: str


class AcceptanceUnavailableFact(NamedTuple):
    fact: str
    availability: str
    reason: str


class EngineeringAcceptanceCandidateReceiptV1(NamedTuple):
    candidate_id: str
    candidate_sha256: str
    receipt_state: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    task_id: str
    task_revision_id: str
    task_revision: int
    task_sha256: str
    packet_id: str
    packet_sha256: str
    context_manifest_sha256: str
    context_manifest_json: str
    repository_sha256: str
    source_manifest_sha256: str
    config_manifest_sha256: str
    dependency_manifest_sha256: str
    completion_boundary_sha256: str
    dispatch_request_id: str
    dispatch_revision_id: str
    dispatch_revision: int
    dispatch_payload_sha256: str
    origin_dispatch_revision_id: str
    origin_dispatch_payload_sha256: str
    dispatch_binding_id: str
    dispatch_binding_sha256: str
    result_receipt_id: str
    result_receipt_sha256: str
    result_artifact_sha256: str
    result_artifact_size_bytes: int
    result_artifact_media_type: str
    producer_execution_id: str
    producer_execution_payload_sha256: str
    producer_pre_transition_execution_payload_sha256: str
    producer_agent_id: str
    producer_carrier_id: str
    producer_thread_id: str
    producer_disposition_receipt_id: str
    reviewer_outcome: str
    lineage: tuple[AcceptanceObjectRef, ...]
    task_revision_history: tuple[AcceptanceObjectRef, ...]
    dispatch_revision_history: tuple[AcceptanceObjectRef, ...]
    evidence: tuple[AcceptanceEvidenceRef, ...]
    unavailable_facts: tuple[AcceptanceUnavailableFact, ...]
    independence_scope: str
    identity_assurance: str
    projection_provenance: str
    projection_completeness: str


def _fail(message: str) -> NoReturn:
    raise EngineeringAcceptanceCandidateError(message)


def _id(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or not _SHA.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _identity(item: Any) -> tuple[str, str, str, int, str]:
    if (
        type(item) is not InvariantObject
        or type(item.contract_type) is not str
        or type(item.object_key) is not str
        or type(item.event_id) is not str
        or type(item.global_sequence) is not int
        or isinstance(item.global_sequence, bool)
        or item.global_sequence < 0
    ):
        _fail("candidate requires exact invariant objects")
    return (
        _id(item.contract_type, "contract_type"), _id(item.object_key, "object_key"),
        _id(item.event_id, "event_id"), item.global_sequence,
        _sha(item.payload_sha256, "payload_sha256"),
    )


def _object_map(projection: Any) -> dict[str, list[tuple[InvariantObject, dict[str, Any]]]]:
    if type(projection) is not InvariantProjection or type(projection.objects) is not tuple:
        _fail("candidate requires caller-supplied InvariantProjection objects")
    if not projection.objects or len(projection.objects) > 256:
        _fail("candidate projection object count is unavailable or exceeds the bounded contract")
    result: dict[str, list[tuple[InvariantObject, dict[str, Any]]]] = {}
    validators = {
        TASK_REVISION_V1: validate_task_revision,
        WORK_PACKET_V1: validate_work_packet,
        WORK_DISPATCH_BINDING_V1: validate_work_dispatch_binding,
        DISPATCH_REQUEST_V1: validate_dispatch_request,
        WORK_RESULT_RECEIPT_V1: validate_work_result_receipt,
        ENGINEERING_DISPOSITION_RECEIPT_V1: validate_engineering_disposition_receipt,
        EXECUTION_NODE_V1: validate_execution_node,
        EVIDENCE_RECORD_V1: validate_evidence_record,
    }
    seen: set[tuple[str, str, str, str, int]] = set()
    event_seen: set[str] = set()
    for item in projection.objects:
        contract_type, object_key, event_id, sequence, payload_sha = _identity(item)
        current = (contract_type, object_key, event_id, payload_sha, sequence)
        if current in seen:
            _fail("candidate projection has duplicate object identity")
        seen.add(current)
        if event_id in event_seen:
            _fail("candidate projection has duplicate event identity")
        event_seen.add(event_id)
        validator = validators.get(contract_type)
        if validator is None:
            continue
        try:
            payload = validator(item.payload)
        except CompanyContractError as exc:
            _fail(f"candidate {contract_type} payload is invalid: {exc}")
        logical = {
            WORK_DISPATCH_BINDING_V1: "dispatch_request_id",
            TASK_REVISION_V1: "task_revision_id", WORK_PACKET_V1: "packet_id",
            DISPATCH_REQUEST_V1: "dispatch_request_id", WORK_RESULT_RECEIPT_V1: "result_receipt_id",
            ENGINEERING_DISPOSITION_RECEIPT_V1: "receipt_id", EXECUTION_NODE_V1: "execution_id",
            EVIDENCE_RECORD_V1: "evidence_id",
        }[contract_type]
        # ``InvariantObject`` hashes the committed JSON payload.  Contract
        # validators intentionally normalize JSON lists into immutable tuples,
        # which are not the committed wire spelling and therefore must not be
        # re-hashed as the event witness.
        if item.object_key != payload[logical]:
            _fail("candidate object key differs from its contract identity")
        if item.payload_sha256 != company_contract_sha256(item.payload):
            _fail("candidate object payload hash differs")
        result.setdefault(contract_type, []).append((item, payload))
    return result


def _one(
    values: list[tuple[InvariantObject, dict[str, Any]]],
    key: str,
    value: str,
    label: str,
) -> tuple[InvariantObject, dict[str, Any]]:
    found = [entry for entry in values if entry[1].get(key) == value]
    if len(found) != 1:
        _fail(f"candidate requires exactly one {label}")
    return found[0]


def _binding(payload: dict[str, Any]) -> tuple[str, int, int]:
    return payload["company_id"], payload["company_incarnation"], payload["lock_domain_generation"]


def _execution_path_is_independent(left: list[str], right: list[str]) -> bool:
    return not (left == right[:len(left)] or right == left[:len(right)])


def _evidence_ref(item: InvariantObject, evidence: dict[str, Any], reviewer_item: InvariantObject) -> AcceptanceEvidenceRef:
    if evidence["artifact"]["availability"] != "available" or evidence["verification_sha256"] is None:
        _fail("candidate evidence lacks immutable verification")
    return AcceptanceEvidenceRef(
        item.contract_type, item.object_key, item.event_id, item.global_sequence,
        item.payload_sha256, evidence["artifact"]["sha256"], evidence["command_sha256"],
        evidence["verification_sha256"], evidence["status"], "", "", "", 0, "", "", "", "",
        canonical_company_json_bytes(evidence).decode("utf-8"), canonical_company_json_bytes(reviewer_item.payload).decode("utf-8"),
    )


def _object_ref(item: InvariantObject) -> AcceptanceObjectRef:
    return AcceptanceObjectRef(item.contract_type, item.object_key, item.event_id, item.global_sequence, item.payload_sha256, canonical_company_json_bytes(item.payload).decode("utf-8"))


def _unsigned(candidate: EngineeringAcceptanceCandidateReceiptV1) -> dict[str, Any]:
    values = candidate._asdict()
    values.pop("candidate_id")
    values.pop("candidate_sha256")
    values["evidence"] = [value._asdict() for value in candidate.evidence]
    values["lineage"] = [value._asdict() for value in candidate.lineage]
    values["task_revision_history"] = [value._asdict() for value in candidate.task_revision_history]
    values["dispatch_revision_history"] = [value._asdict() for value in candidate.dispatch_revision_history]
    values["unavailable_facts"] = [value._asdict() for value in candidate.unavailable_facts]
    return values


def _candidate_digest(unsigned: dict[str, Any]) -> str:
    try:
        return hashlib.sha256(canonical_company_json_bytes(unsigned)).hexdigest()
    except CompanyContractError as exc:
        _fail(f"candidate canonical payload is invalid: {exc}")


def validate_engineering_acceptance_candidate_receipt(value: Any) -> EngineeringAcceptanceCandidateReceiptV1:
    """Decode bounded receipt shape only; this is deliberately not semantic proof.

    Candidate hashes and embedded source text are self-authenticated claims.  Use
    :func:`validate_engineering_acceptance_candidate_against_witness` with an
    exact bounded projection and canonical context bytes before relying on one.
    """
    if type(value) is not EngineeringAcceptanceCandidateReceiptV1:
        _fail("candidate must be EngineeringAcceptanceCandidateReceiptV1")
    id_fields = (
        "candidate_id", "company_id", "task_id", "task_revision_id", "packet_id",
        "dispatch_request_id", "dispatch_revision_id", "dispatch_binding_id", "result_receipt_id",
        "producer_execution_id", "producer_agent_id", "producer_carrier_id", "producer_thread_id",
        "producer_disposition_receipt_id",
    )
    sha_fields = (
        "candidate_sha256", "task_sha256", "packet_sha256", "context_manifest_sha256",
        "repository_sha256", "source_manifest_sha256", "config_manifest_sha256",
        "dependency_manifest_sha256", "completion_boundary_sha256", "dispatch_payload_sha256",
        "dispatch_binding_sha256", "result_receipt_sha256", "result_artifact_sha256",
        "producer_execution_payload_sha256", "producer_pre_transition_execution_payload_sha256",
        "origin_dispatch_payload_sha256",
    )
    for name in id_fields:
        _id(getattr(value, name), f"candidate.{name}")
    for name in sha_fields:
        _sha(getattr(value, name), f"candidate.{name}")
    for name in ("company_incarnation", "task_revision", "dispatch_revision"):
        if type(getattr(value, name)) is not int or getattr(value, name) < 1:
            _fail(f"candidate.{name} is invalid")
    for name in ("lock_domain_generation", "result_artifact_size_bytes"):
        if type(getattr(value, name)) is not int or getattr(value, name) < 0:
            _fail(f"candidate.{name} is invalid")
    if type(value.result_artifact_media_type) is not str or not value.result_artifact_media_type or len(value.result_artifact_media_type) > 255:
        _fail("candidate.result_artifact_media_type is invalid")
    if value.receipt_state != "acceptance_candidate" or value.reviewer_outcome not in {"accepted_candidate", "rejected_candidate"}:
        _fail("candidate outcome or kind is invalid")
    if type(value.context_manifest_json) is not str or len(value.context_manifest_json.encode("utf-8")) > 262_144:
        _fail("candidate context source shape is invalid")
    for name in ("lineage", "task_revision_history", "dispatch_revision_history"):
        refs = getattr(value, name)
        if type(refs) is not tuple or not refs or len(refs) > 32 or any(type(item) is not AcceptanceObjectRef for item in refs):
            _fail(f"candidate.{name} shape is invalid")
    if len(value.lineage) != 8:
        _fail("candidate lineage shape is invalid")
    for ref in (*value.lineage, *value.task_revision_history, *value.dispatch_revision_history):
        for name in ("contract_type", "object_key", "event_id"):
            _id(getattr(ref, name), f"candidate.source.{name}")
        _sha(ref.payload_sha256, "candidate.source.payload_sha256")
        if type(ref.global_sequence) is not int or ref.global_sequence < 1 or type(ref.canonical_payload_json) is not str:
            _fail("candidate source reference shape is invalid")
        if len(ref.canonical_payload_json.encode("utf-8")) > 262_144:
            _fail("candidate source reference exceeds bounded shape")
    if type(value.evidence) is not tuple or not value.evidence or len(value.evidence) > 64:
        _fail("candidate requires terminal review evidence")
    if any(type(item) is not AcceptanceEvidenceRef for item in value.evidence):
        _fail("candidate evidence is mutable or invalid")
    statuses: set[str] = set()
    evidence_identity: set[tuple[str, str, str, int]] = set()
    for item in value.evidence:
        if item.contract_type != EVIDENCE_RECORD_V1 or item.object_key == "":
            _fail("candidate evidence contract identity differs")
        for name in ("contract_type", "object_key", "event_id", "reviewer_execution_id", "reviewer_execution_object_key", "reviewer_execution_event_id", "reviewer_agent_id", "reviewer_carrier_id", "reviewer_thread_id"):
            _id(getattr(item, name), f"candidate.evidence.{name}")
        for name in ("payload_sha256", "artifact_sha256", "verification_sha256", "reviewer_execution_payload_sha256"):
            _sha(getattr(item, name), f"candidate.evidence.{name}")
        if item.command_sha256 is not None:
            _sha(item.command_sha256, "candidate.evidence.command_sha256")
        if (type(item.global_sequence) is not int or item.global_sequence < 1
                or type(item.reviewer_execution_global_sequence) is not int
                or item.reviewer_execution_global_sequence < 1
                or item.status not in {"pass", "fail"}):
            _fail("candidate evidence terminal state is invalid")
        if item.reviewer_execution_object_key != item.reviewer_execution_id:
            _fail("candidate reviewer execution wrapper identity differs")
        if (type(item.canonical_payload_json) is not str or type(item.reviewer_execution_payload_json) is not str
                or len(item.canonical_payload_json.encode("utf-8")) > 262_144
                or len(item.reviewer_execution_payload_json.encode("utf-8")) > 262_144):
            _fail("candidate evidence source shape is invalid")
        identity = (item.contract_type, item.object_key, item.event_id, item.global_sequence)
        if identity in evidence_identity:
            _fail("candidate evidence identities are duplicated")
        evidence_identity.add(identity)
        statuses.add(item.status)
    if (value.reviewer_outcome == "accepted_candidate") != (statuses == {"pass"}):
        _fail("candidate outcome and evidence verdicts differ")
    if value.reviewer_outcome == "rejected_candidate" and "fail" not in statuses:
        _fail("rejected candidate requires failed evidence")
    if type(value.unavailable_facts) is not tuple or len(value.unavailable_facts) != len(_UNAVAILABLE) or any(type(item) is not AcceptanceUnavailableFact for item in value.unavailable_facts):
        _fail("candidate unavailable facts are invalid")
    if tuple((item.fact, item.reason) for item in value.unavailable_facts) != _UNAVAILABLE or any(item.availability != "unavailable" for item in value.unavailable_facts):
        _fail("candidate unavailable facts differ")
    if (value.independence_scope, value.identity_assurance, value.projection_provenance, value.projection_completeness) != (
        "cooperative_identity_only", "authentication_and_capability_unverified",
        "caller_supplied_bounded_projection", "unverified",
    ):
        _fail("candidate assurance boundary differs")
    digest = _candidate_digest(_unsigned(value))
    if value.candidate_id != f"acceptance-candidate-{digest}" or value.candidate_sha256 != digest:
        _fail("candidate self digest differs")
    return value


def validate_engineering_acceptance_candidate_against_witness(
    value: Any,
    projection: InvariantProjection,
    context_manifest_bytes: bytes,
) -> EngineeringAcceptanceCandidateReceiptV1:
    """Re-derive a candidate from bounded caller witnesses and compare exactly.

    This is the only semantic validation entrypoint.  It deliberately does not
    infer a ledger head, snapshot completeness, or engineering completion.
    """
    candidate = validate_engineering_acceptance_candidate_receipt(value)
    if type(projection) is not InvariantProjection or type(context_manifest_bytes) is not bytes:
        _fail("candidate semantic validation requires exact bounded witnesses")

    def source_item(ref: AcceptanceObjectRef) -> InvariantObject:
        matches = [item for item in projection.objects if _identity(item) == (
            ref.contract_type, ref.object_key, ref.event_id, ref.global_sequence, ref.payload_sha256,
        )]
        if len(matches) != 1:
            _fail("candidate witness source is absent or divergent")
        return matches[0]

    expected = build_engineering_acceptance_candidate(
        projection, task_revision_id=candidate.task_revision_id, packet_id=candidate.packet_id,
        dispatch_request_id=candidate.dispatch_request_id, dispatch_binding_id=candidate.dispatch_binding_id,
        result_receipt_id=candidate.result_receipt_id, context_manifest_bytes=context_manifest_bytes,
        dispatch_revision_history=tuple(source_item(ref) for ref in candidate.dispatch_revision_history),
        pre_transition_execution=source_item(candidate.lineage[6]),
    )
    if expected != candidate:
        _fail("candidate differs from bounded witness re-derivation")
    return candidate


def build_engineering_acceptance_candidate(
    projection: InvariantProjection,
    *,
    task_revision_id: str,
    packet_id: str,
    dispatch_request_id: str,
    dispatch_binding_id: str,
    result_receipt_id: str,
    context_manifest_bytes: bytes,
    dispatch_revision_history: tuple[InvariantObject, ...],
    pre_transition_execution: InvariantObject,
) -> EngineeringAcceptanceCandidateReceiptV1:
    """Derive a cooperative, bounded review candidate without completion authority."""
    task_revision_id = _id(task_revision_id, "task_revision_id")
    packet_id = _id(packet_id, "packet_id")
    dispatch_request_id = _id(dispatch_request_id, "dispatch_request_id")
    dispatch_binding_id = _id(dispatch_binding_id, "dispatch_binding_id")
    result_receipt_id = _id(result_receipt_id, "result_receipt_id")
    if type(context_manifest_bytes) is not bytes:
        _fail("candidate context bytes are invalid")
    try:
        manifest = validate_work_context_manifest(json.loads(context_manifest_bytes.decode("utf-8", "strict")))
        if canonical_work_context_manifest_bytes(manifest) != context_manifest_bytes:
            _fail("candidate context bytes are not canonical")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, CompanyContractError) as exc:
        _fail(f"candidate context bytes are invalid: {exc}")
    objects = _object_map(projection)
    task_item, task = _one(objects.get(TASK_REVISION_V1, []), "task_revision_id", task_revision_id, "task revision")
    packet_item, packet = _one(objects.get(WORK_PACKET_V1, []), "packet_id", packet_id, "work packet")
    binding_item, binding = _one(objects.get(WORK_DISPATCH_BINDING_V1, []), "binding_id", dispatch_binding_id, "work dispatch binding")
    try:
        current_dispatch = select_current_dispatch(
            objects.get(DISPATCH_REQUEST_V1, []), dispatch_request_id,
        )
        history = validate_dispatch_history(dispatch_revision_history, dispatch_request_id)
    except AcceptanceHistoryError as exc:
        _fail(f"candidate dispatch history differs: {exc}")
    dispatch_item, dispatch = current_dispatch
    if type(projection.dispatch_requests) is not tuple or not projection.dispatch_requests:
        _fail("candidate dispatch projection is invalid")
    visible = [item for item in projection.dispatch_requests if _identity(item)[0:2] == (DISPATCH_REQUEST_V1, dispatch_request_id)]
    if len(visible) != 1 or _identity(visible[0]) != _identity(dispatch_item):
        _fail("candidate current dispatch projection differs from object projection")
    if _identity(history[-1].item) != _identity(dispatch_item):
        _fail("candidate current dispatch is not history tail")
    if history[-1].payload["state"] != "dispatched":
        _fail("candidate current dispatch has not reached dispatched")
    result_item, result = _one(objects.get(WORK_RESULT_RECEIPT_V1, []), "result_receipt_id", result_receipt_id, "work result receipt")
    disposition_item, disposition = _one(objects.get(ENGINEERING_DISPOSITION_RECEIPT_V1, []), "receipt_id", result["engineering_disposition_receipt_id"], "engineering disposition receipt")
    try:
        current_producer = select_current_execution(
            objects.get(EXECUTION_NODE_V1, []), result["producer_execution_id"],
        )
    except AcceptanceHistoryError as exc:
        _fail(f"candidate producer execution history differs: {exc}")
    producer_item, producer = current_producer
    company = _binding(task)
    if any(_binding(value) != company for value in (packet, binding, dispatch, result, disposition, producer)):
        _fail("candidate company binding differs")
    if dispatch.get("execution_id") != producer["execution_id"]:
        _fail("candidate dispatched execution differs from result producer")
    task_revisions = [entry for entry in objects.get(TASK_REVISION_V1, []) if entry[1]["task_id"] == task["task_id"]]
    if len({entry[1]["revision"] for entry in task_revisions}) != len(task_revisions):
        _fail("candidate task revisions have a divergent ordinal")
    if sorted(entry[1]["revision"] for entry in task_revisions) != list(range(1, task["revision"] + 1)):
        _fail("candidate task revision ordinals are incomplete")
    if any(entry[1]["revision"] > task["revision"] for entry in task_revisions):
        _fail("candidate task revision is stale within bounded projection")
    expected_previous: tuple[str | None, str | None] = (None, None)
    for _, revision in sorted(task_revisions, key=lambda entry: entry[1]["revision"]):
        if (revision["previous_task_revision_id"], revision["previous_task_sha256"]) != expected_previous:
            _fail("candidate task revision predecessor chain is incomplete")
        expected_previous = (revision["task_revision_id"], revision["task_sha256"])
    if packet["parent_packet_id"] is not None:
        _fail("candidate child packet parent context is unavailable in this bounded API")
    try:
        validate_work_definition_bundle(task, packet, manifest)
    except CompanyContractError as exc:
        _fail(f"candidate direct task, packet, and context lineage differs: {exc}")
    if (
        binding["dispatch_request_id"] != dispatch_request_id
        or binding["task_revision_id"] != task_revision_id
        or binding["packet_id"] != packet_id
        or binding["task_id"] != task["task_id"]
        or binding["task_sha256"] != task["task_sha256"]
        or binding["packet_sha256"] != packet["packet_sha256"]
        or binding["prompt_ref"] != packet["prompt_ref"]
        or binding["context_manifest_ref"] != packet["context_manifest_ref"]
        or dispatch["task_id"] != task["task_id"]
        or dispatch["packet_id"] != packet_id
        or result["task_revision_id"] != task_revision_id
        or result["task_id"] != task["task_id"]
        or result["packet_id"] != packet_id
        or result["task_sha256"] != task["task_sha256"]
        or result["packet_sha256"] != packet["packet_sha256"]
        or producer["task_id"] != task["task_id"]
        or producer["packet_id"] != packet_id
        or producer.get("dispatch_id") != dispatch_request_id
        or producer["provider"] not in binding["provider_allowlist"]
    ):
        _fail("candidate task, packet, dispatch, or result lineage differs")
    origin_item, origin_dispatch = history[0]
    if (
        (binding["dispatch_revision_id"], binding["dispatch_payload_sha256"])
        != (origin_dispatch["dispatch_revision_id"], origin_item.payload_sha256)
        or binding_item.global_sequence != origin_item.global_sequence
        or binding["command_id"] != origin_dispatch["command_id"]
        or any(binding[name] != origin_dispatch[name] for name in (
            "department_id", "target_node_id", "manager_node_id", "parent_execution_id", "delegation_depth", "task_id", "packet_id",
        ))
        or any(binding[left] != packet[right] for left, right in (
            ("task_revision_id", "task_revision_id"), ("task_id", "task_id"), ("task_sha256", "task_sha256"),
            ("packet_id", "packet_id"), ("packet_sha256", "packet_sha256"), ("prompt_ref", "prompt_ref"),
            ("context_manifest_ref", "context_manifest_ref"), ("department_id", "department_id"),
            ("target_node_id", "target_node_id"), ("manager_node_id", "manager_node_id"),
            ("parent_execution_id", "parent_execution_id"), ("delegation_depth", "delegation_depth"), ("expires_at", "expires_at"),
        ))
        or not (
            origin_dispatch["scope_sha256"] == binding["authority_scope_sha256"]
            == company_contract_sha256(packet["authority_scope"])
        )
        or binding["provider_allowlist"] != packet["authority_scope"]["provider_allowlist"]
        or binding["created_at"] != origin_dispatch["created_at"]
    ):
        _fail("candidate binding origin dispatch witness differs")
    if _identity(pre_transition_execution)[0:2] != (EXECUTION_NODE_V1, producer["execution_id"]):
        _fail("candidate stopped predecessor witness differs")
    try:
        predecessor = validate_execution_node(pre_transition_execution.payload)
    except CompanyContractError as exc:
        _fail(f"candidate stopped predecessor witness is invalid: {exc}")
    if pre_transition_execution.payload_sha256 != company_contract_sha256(predecessor):
        _fail("candidate stopped predecessor payload hash differs")
    try:
        validate_execution_predecessor_pair(pre_transition_execution, producer_item)
    except AcceptanceHistoryError as exc:
        _fail(f"candidate stopped predecessor history differs: {exc}")
    if (
        predecessor["execution_id"] != producer["execution_id"] or predecessor["runtime_status"] != "stopped"
        or predecessor["engineering_status"] in {"idle", "completed", "cancelled"}
        or predecessor.get("dispatch_id") != dispatch_request_id
        or result["expected_execution_payload_sha256"] != pre_transition_execution.payload_sha256
        or disposition["expected_execution_payload_sha256"] != pre_transition_execution.payload_sha256
    ):
        _fail("candidate stopped predecessor does not bind result disposition")
    if (
        disposition["execution_id"] != producer["execution_id"]
        or disposition["expected_execution_payload_sha256"] != result["expected_execution_payload_sha256"]
        or disposition["result_packet_id"] != packet_id
        or disposition["provider"] != producer["provider"]
        or disposition["reporter_carrier_id"] != producer["carrier_id"]
        or disposition["thread_id"] != producer["thread_id"]
        or disposition["observed_at"] != result["recorded_at"]
        or producer["engineering_status"] != "idle"
        or producer["runtime_status"] != "stopped"
        or producer["updated_at"] != result["recorded_at"]
    ):
        _fail("candidate engineering disposition differs")
    if not (
        result_item.global_sequence == disposition_item.global_sequence
        == producer_item.global_sequence
    ):
        _fail("candidate terminal result, disposition, and producer are not one committed observation")
    if pre_transition_execution.global_sequence >= producer_item.global_sequence:
        _fail("candidate stopped predecessor is not earlier than terminal execution")
    if producer["execution_kind"] != "agent" or any(producer[field] is None for field in ("carrier_id", "agent_id", "thread_id")):
        _fail("candidate requires an independently identified producer agent")
    evidence_by_id = {payload["evidence_id"]: (item, payload) for item, payload in objects.get(EVIDENCE_RECORD_V1, [])}
    if len(evidence_by_id) != len(objects.get(EVIDENCE_RECORD_V1, [])):
        _fail("candidate evidence identities are ambiguous")
    selected_entries = sorted(
        ((item, payload) for item, payload in objects.get(EVIDENCE_RECORD_V1, []) if payload["claim_id"] == result_receipt_id),
        key=lambda entry: (entry[1]["evidence_id"], entry[0].event_id, entry[0].global_sequence),
    )
    if not selected_entries or len(selected_entries) > 64:
        _fail("candidate requires bounded visible result review evidence")
    selected: list[AcceptanceEvidenceRef] = []
    reviewers: list[dict[str, Any]] = []
    for item, evidence in selected_entries:
        if _binding(evidence) != company or evidence["claim_id"] != result_receipt_id or evidence["execution_id"] is None:
            _fail("candidate evidence reviewer/result binding differs")
        if evidence["status"] not in {"pass", "fail"}:
            _fail("candidate evidence is not a terminal review verdict")
        try:
            evidence_precedes_result = timestamp_precedes(
                evidence["recorded_at"], result["recorded_at"],
            )
        except AcceptanceHistoryError as exc:
            _fail(f"candidate evidence chronology differs: {exc}")
        if item.global_sequence <= result_item.global_sequence or evidence_precedes_result:
            _fail("candidate review evidence precedes the result")
        try:
            current_reviewer = select_current_execution(
                objects.get(EXECUTION_NODE_V1, []), evidence["execution_id"],
            )
        except AcceptanceHistoryError as exc:
            _fail(f"candidate reviewer execution history differs: {exc}")
        reviewer_item, reviewer = current_reviewer
        if (
            reviewer["execution_kind"] != "agent" or reviewer["role"] != "reviewer"
            or reviewer["task_id"] != task["task_id"] or reviewer["packet_id"] != packet_id
            or _binding(reviewer) != company
            or any(reviewer[field] is None for field in ("carrier_id", "agent_id", "thread_id"))
        ):
            _fail("candidate reviewer execution is not an exact reviewer agent")
        if (
            producer["execution_id"] == reviewer["execution_id"]
            or producer["carrier_id"] == reviewer["carrier_id"]
            or producer["agent_id"] == reviewer["agent_id"]
            or producer["thread_id"] == reviewer["thread_id"]
            or not _execution_path_is_independent(producer["execution_path"], reviewer["execution_path"])
            or evidence["evidence_id"] not in reviewer["evidence_ids"]
        ):
            _fail("candidate producer and reviewer identities are not independent")
        if evidence["artifact"]["sha256"] == result["result_ref"]["sha256"]:
            _fail("candidate reviewer evidence cannot reuse the result artifact")
        reviewers.append(reviewer)
        base = _evidence_ref(item, evidence, reviewer_item)
        selected.append(base._replace(
            reviewer_execution_id=reviewer["execution_id"],
            reviewer_execution_object_key=reviewer_item.object_key,
            reviewer_execution_event_id=reviewer_item.event_id,
            reviewer_execution_global_sequence=reviewer_item.global_sequence,
            reviewer_execution_payload_sha256=reviewer_item.payload_sha256,
            reviewer_agent_id=reviewer["agent_id"], reviewer_carrier_id=reviewer["carrier_id"],
            reviewer_thread_id=reviewer["thread_id"],
        ))
    selected.sort(key=lambda value: (value.object_key, value.event_id, value.global_sequence))
    for index, left in enumerate(reviewers):
        for right in reviewers[index + 1:]:
            if any(left[field] == right[field] for field in ("execution_id", "carrier_id", "agent_id", "thread_id")) or not _execution_path_is_independent(left["execution_path"], right["execution_path"]):
                _fail("candidate reviewers are not pairwise independent")
    outcome = "rejected_candidate" if any(value.status == "fail" for value in selected) else "accepted_candidate"
    context_sha = hashlib.sha256(context_manifest_bytes).hexdigest()
    unavailable = tuple(AcceptanceUnavailableFact(fact, "unavailable", reason) for fact, reason in _UNAVAILABLE)
    unsigned = {
        "receipt_state": "acceptance_candidate", "company_id": company[0], "company_incarnation": company[1], "lock_domain_generation": company[2],
        "task_id": task["task_id"], "task_revision_id": task_revision_id, "task_revision": task["revision"], "task_sha256": task["task_sha256"],
        "packet_id": packet_id, "packet_sha256": packet["packet_sha256"], "context_manifest_sha256": context_sha, "context_manifest_json": context_manifest_bytes.decode("utf-8"),
        "repository_sha256": manifest["repository_sha256"], "source_manifest_sha256": packet["source_manifest_sha256"], "config_manifest_sha256": packet["config_manifest_sha256"], "dependency_manifest_sha256": packet["dependency_manifest_sha256"], "completion_boundary_sha256": task["completion_boundary_ref"]["sha256"],
        "dispatch_request_id": dispatch_request_id, "dispatch_revision_id": dispatch["dispatch_revision_id"], "dispatch_revision": dispatch["revision"], "dispatch_payload_sha256": dispatch_item.payload_sha256, "origin_dispatch_revision_id": binding["dispatch_revision_id"], "origin_dispatch_payload_sha256": binding["dispatch_payload_sha256"], "dispatch_binding_id": dispatch_binding_id, "dispatch_binding_sha256": binding["binding_sha256"],
        "result_receipt_id": result_receipt_id, "result_receipt_sha256": result["receipt_sha256"], "result_artifact_sha256": result["result_ref"]["sha256"], "result_artifact_size_bytes": result["result_ref"]["size_bytes"], "result_artifact_media_type": result["result_ref"]["media_type"],
        "producer_execution_id": producer["execution_id"], "producer_execution_payload_sha256": producer_item.payload_sha256, "producer_pre_transition_execution_payload_sha256": pre_transition_execution.payload_sha256, "producer_agent_id": producer["agent_id"], "producer_carrier_id": producer["carrier_id"], "producer_thread_id": producer["thread_id"], "producer_disposition_receipt_id": result["engineering_disposition_receipt_id"],
        "reviewer_outcome": outcome,
        "lineage": [value._asdict() for value in (_object_ref(task_item), _object_ref(packet_item), _object_ref(dispatch_item), _object_ref(binding_item), _object_ref(result_item), _object_ref(disposition_item), _object_ref(pre_transition_execution), _object_ref(producer_item))], "task_revision_history": [value._asdict() for value in (_object_ref(item) for item, _ in sorted(task_revisions, key=lambda entry: entry[1]["revision"]))], "dispatch_revision_history": [value._asdict() for value in (_object_ref(entry.item) for entry in history)], "evidence": [value._asdict() for value in selected], "unavailable_facts": [value._asdict() for value in unavailable],
        "independence_scope": "cooperative_identity_only", "identity_assurance": "authentication_and_capability_unverified", "projection_provenance": "caller_supplied_bounded_projection", "projection_completeness": "unverified",
    }
    digest = _candidate_digest(unsigned)
    candidate = EngineeringAcceptanceCandidateReceiptV1(
        f"acceptance-candidate-{digest}", digest,
        **{**unsigned, "lineage": tuple(_object_ref(item) for item in (
            task_item, packet_item, dispatch_item, binding_item, result_item, disposition_item, pre_transition_execution, producer_item,
        )), "task_revision_history": tuple(_object_ref(item) for item, _ in sorted(task_revisions, key=lambda entry: entry[1]["revision"])), "dispatch_revision_history": tuple(_object_ref(entry.item) for entry in history), "evidence": tuple(selected), "unavailable_facts": unavailable},
    )
    return validate_engineering_acceptance_candidate_receipt(candidate)
