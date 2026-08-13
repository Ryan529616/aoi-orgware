"""Pure, caller-captured Supervisor commit brackets for one future latency cohort.

These values are not ledger records.  They bind a caller's claimed pre/post
monotonic observations but cannot prove commit membership, currentness, or
transaction atomicity until a future Supervisor capture path persists them.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, NamedTuple, NoReturn

from aoi_orgware.company.contracts import (
    CompanyContractError, company_contract_sha256, validate_dispatch_request,
    validate_work_dispatch_binding,
)
from .acceptance_contract import (
    EngineeringAcceptanceCandidateReceiptV1,
    validate_engineering_acceptance_candidate_against_witness,
)
from aoi_orgware.company.invariants import InvariantProjection

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA = re.compile(r"[0-9a-f]{64}")
_CLOCK_DOMAIN = "python_monotonic_ns"
_CLOCK_SCOPE = "supervisor_local"
_CLOCK_PROVENANCE = "supervisor_local_python_monotonic_ns"


class StageSpanError(ValueError):
    """The supplied capture cannot safely support a latency-bound claim."""


class SupervisorStageMarkV1(NamedTuple):
    mark_id: str
    mark_sha256: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    observer_service_id: str
    observer_process_incarnation_id: str
    clock_domain_id: str
    clock_scope: str
    clock_resolution_ns: int | None
    clock_provenance: str
    clock_generation: int
    transaction_id: str
    transaction_receipt_sha256: str
    global_sequence: int
    event_id: str
    event_payload_sha256: str
    dispatch_payload_sha256: str
    origin_dispatch_revision_id: str
    origin_dispatch_payload_sha256: str
    binding_id: str
    binding_sha256: str
    task_id: str
    packet_id: str
    dispatch_request_id: str
    stage: str
    subject_id: str
    subject_sha256: str
    candidate_outcome: str | None
    pre_tick: int | None
    pre_monotonic_ns: int | None
    post_tick: int
    post_monotonic_ns: int
    commit_observation: str
    capture_authority: str


class SupervisorStageSpanV1(NamedTuple):
    span_id: str
    span_sha256: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    task_id: str
    packet_id: str
    dispatch_request_id: str
    start_mark: SupervisorStageMarkV1
    end_mark: SupervisorStageMarkV1 | None
    elapsed_lower_ns: int | None
    elapsed_upper_ns: int | None
    duration_availability: str
    cohort_state: str
    reason: str
    derivation_scope: str


def _fail(message: str) -> NoReturn:
    raise StageSpanError(message)


def _id(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or not _SHA.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _uint(value: Any, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 9_223_372_036_854_775_807:
        _fail(f"{label} is invalid")
    return value


def _digest(value: dict[str, Any]) -> str:
    try:
        return company_contract_sha256(value)
    except CompanyContractError as exc:
        _fail(f"canonical capture value is invalid: {exc}")


def _unsigned(mark: SupervisorStageMarkV1) -> dict[str, Any]:
    value = mark._asdict()
    value.pop("mark_id")
    value.pop("mark_sha256")
    return value


def _validated_mark(value: Any) -> SupervisorStageMarkV1:
    if type(value) is not SupervisorStageMarkV1:
        _fail("stage mark must be SupervisorStageMarkV1")
    for name in (
        "mark_id", "company_id", "observer_service_id", "observer_process_incarnation_id",
        "clock_domain_id", "clock_scope", "clock_provenance", "transaction_id", "event_id", "binding_id", "origin_dispatch_revision_id", "task_id",
        "packet_id", "dispatch_request_id", "subject_id",
    ):
        _id(getattr(value, name), f"mark.{name}")
    for name in ("mark_sha256", "transaction_receipt_sha256", "event_payload_sha256", "dispatch_payload_sha256", "origin_dispatch_payload_sha256", "binding_sha256", "subject_sha256"):
        _sha(getattr(value, name), f"mark.{name}")
    for name in ("company_incarnation", "lock_domain_generation", "clock_generation", "global_sequence", "post_tick", "post_monotonic_ns"):
        _uint(getattr(value, name), f"mark.{name}")
    if value.clock_resolution_ns is not None:
        _uint(value.clock_resolution_ns, "mark.clock_resolution_ns")
        if value.clock_resolution_ns == 0:
            _fail("mark.clock_resolution_ns must be observed or unavailable")
    if (value.pre_tick is None) != (value.pre_monotonic_ns is None):
        _fail("pre tick and monotonic value must both be present or absent")
    if value.pre_tick is not None:
        _uint(value.pre_tick, "mark.pre_tick")
        _uint(value.pre_monotonic_ns, "mark.pre_monotonic_ns")
        assert value.pre_monotonic_ns is not None
        if value.pre_tick > value.post_tick or value.pre_monotonic_ns > value.post_monotonic_ns:
            _fail("mark monotonic bracket is definitely reversed")
    if value.stage not in {"dispatch_accepted", "engineering_acceptance_candidate_receipt_sealed"}:
        _fail("mark stage is invalid")
    if value.company_incarnation < 1 or value.clock_generation < 0 or value.global_sequence < 1:
        _fail("mark immutable generation or sequence is invalid")
    if (value.clock_domain_id, value.clock_scope) != (_CLOCK_DOMAIN, _CLOCK_SCOPE):
        _fail("mark clock semantics are unavailable")
    if value.clock_provenance != _CLOCK_PROVENANCE:
        _fail("mark clock provenance differs")
    if value.stage == "dispatch_accepted":
        if (value.candidate_outcome is not None
                or value.subject_sha256 != value.event_payload_sha256
                or value.dispatch_payload_sha256 != value.event_payload_sha256):
            _fail("dispatch start cannot carry a candidate outcome")
        if (
            value.subject_id != value.origin_dispatch_revision_id
            or value.subject_sha256 != value.origin_dispatch_payload_sha256
        ):
            _fail("dispatch start subject must bind origin dispatch")
    elif (
        value.candidate_outcome not in {"accepted_candidate", "rejected_candidate"}
        or value.subject_sha256 != value.event_payload_sha256
        or value.subject_id != f"acceptance-candidate-{value.subject_sha256}"
    ):
        _fail("candidate end must carry an exact outcome")
    if value.commit_observation != "newly_committed" or value.capture_authority != "caller_supplied_unverified":
        _fail("mark cannot claim replay or capture authority")
    digest = _digest(_unsigned(value))
    if value.mark_sha256 != digest or value.mark_id != f"supervisor-stage-mark-{digest}":
        _fail("mark self digest differs")
    return value


def _build_mark(**kwargs: Any) -> SupervisorStageMarkV1:
    for name in (
        "company_id", "observer_service_id", "observer_process_incarnation_id", "clock_domain_id", "clock_scope", "clock_provenance",
        "transaction_id", "event_id", "binding_id", "task_id", "packet_id",
        "dispatch_request_id", "origin_dispatch_revision_id", "subject_id",
    ):
        _id(kwargs[name], name)
    for name in ("transaction_receipt_sha256", "event_payload_sha256", "dispatch_payload_sha256", "origin_dispatch_payload_sha256", "binding_sha256", "subject_sha256"):
        _sha(kwargs[name], name)
    for name in ("company_incarnation", "lock_domain_generation", "clock_generation", "global_sequence", "post_tick", "post_monotonic_ns"):
        _uint(kwargs[name], name)
    if kwargs["clock_resolution_ns"] is not None:
        _uint(kwargs["clock_resolution_ns"], "clock_resolution_ns")
        if kwargs["clock_resolution_ns"] == 0:
            _fail("clock_resolution_ns must be observed or unavailable")
    if (kwargs["pre_tick"] is None) != (kwargs["pre_monotonic_ns"] is None):
        _fail("one-sided pre capture is invalid")
    if kwargs["pre_tick"] is not None:
        _uint(kwargs["pre_tick"], "pre_tick")
        _uint(kwargs["pre_monotonic_ns"], "pre_monotonic_ns")
        if kwargs["pre_tick"] > kwargs["post_tick"] or kwargs["pre_monotonic_ns"] > kwargs["post_monotonic_ns"]:
            _fail("capture bracket is definitely reversed")
    if kwargs["stage"] not in {"dispatch_accepted", "engineering_acceptance_candidate_receipt_sealed"}:
        _fail("unknown stage")
    if kwargs.get("commit_observation") != "newly_committed":
        _fail("only a caller-observed newly committed transaction may mint a mark")
    if kwargs.get("capture_authority") != "caller_supplied_unverified":
        _fail("stage capture authority must remain caller supplied and unverified")
    digest = _digest(kwargs)
    return _validated_mark(SupervisorStageMarkV1(f"supervisor-stage-mark-{digest}", digest, **kwargs))


def build_dispatch_accepted_mark(
    dispatch_request: Any, dispatch_binding: Any, *, observer_service_id: str,
    observer_process_incarnation_id: str, clock_domain_id: str, clock_generation: int,
    clock_resolution_ns: int | None,
    transaction_receipt_sha256: str, global_sequence: int, event_id: str,
    commit_observation: str,
    pre_tick: int | None, pre_monotonic_ns: int | None, post_tick: int, post_monotonic_ns: int,
) -> SupervisorStageMarkV1:
    """Capture queued revision 1 plus its binding; it includes queue wait by design.

    DispatchRequest has no transaction ID in the existing schema.  The binding
    transaction is therefore carried as a caller claim, not proven membership.
    """
    try:
        request = validate_dispatch_request(dispatch_request)
        binding = validate_work_dispatch_binding(dispatch_binding)
    except CompanyContractError as exc:
        _fail(f"dispatch capture material is invalid: {exc}")
    payload_sha = company_contract_sha256(request)
    if (
        request["state"] != "queued" or request["revision"] != 1 or request["attempt"] != 0
        or request["dispatch_request_id"] != binding["dispatch_request_id"]
        or request["dispatch_revision_id"] != binding["dispatch_revision_id"]
        or payload_sha != binding["dispatch_payload_sha256"]
        or request["task_id"] != binding["task_id"] or request["packet_id"] != binding["packet_id"]
        or request["company_id"] != binding["company_id"]
        or request["company_incarnation"] != binding["company_incarnation"]
        or request["lock_domain_generation"] != binding["lock_domain_generation"]
    ):
        _fail("queued revision-one request and binding differ")
    return _build_mark(
        company_id=request["company_id"], company_incarnation=request["company_incarnation"],
        lock_domain_generation=request["lock_domain_generation"], observer_service_id=observer_service_id,
        observer_process_incarnation_id=observer_process_incarnation_id, clock_domain_id=clock_domain_id, clock_scope=_CLOCK_SCOPE, clock_resolution_ns=clock_resolution_ns, clock_provenance=_CLOCK_PROVENANCE,
        clock_generation=clock_generation, transaction_id=binding["transaction_id"],
        transaction_receipt_sha256=transaction_receipt_sha256, global_sequence=global_sequence,
        event_id=event_id, event_payload_sha256=payload_sha, dispatch_payload_sha256=payload_sha, origin_dispatch_revision_id=binding["dispatch_revision_id"], origin_dispatch_payload_sha256=binding["dispatch_payload_sha256"],
        binding_id=binding["binding_id"], binding_sha256=binding["binding_sha256"],
        task_id=request["task_id"], packet_id=request["packet_id"], dispatch_request_id=request["dispatch_request_id"],
        stage="dispatch_accepted", subject_id=request["dispatch_revision_id"], subject_sha256=payload_sha,
        pre_tick=pre_tick, pre_monotonic_ns=pre_monotonic_ns, post_tick=post_tick,
        post_monotonic_ns=post_monotonic_ns, candidate_outcome=None,
        commit_observation=commit_observation, capture_authority="caller_supplied_unverified",
    )


def build_engineering_acceptance_candidate_receipt_sealed_mark(
    candidate: EngineeringAcceptanceCandidateReceiptV1, *, observer_service_id: str,
    observer_process_incarnation_id: str, clock_domain_id: str, clock_generation: int,
    transaction_id: str, transaction_receipt_sha256: str, global_sequence: int,
    event_id: str, commit_observation: str, pre_tick: int | None,
    pre_monotonic_ns: int | None, post_tick: int, post_monotonic_ns: int,
    clock_resolution_ns: int | None, projection: InvariantProjection,
    context_manifest_bytes: bytes,
) -> SupervisorStageMarkV1:
    candidate = validate_engineering_acceptance_candidate_against_witness(
        candidate, projection, context_manifest_bytes,
    )
    _require_seal_after_candidate_witnesses(candidate, global_sequence)
    return _build_mark(
        company_id=candidate.company_id, company_incarnation=candidate.company_incarnation,
        lock_domain_generation=candidate.lock_domain_generation, observer_service_id=observer_service_id,
        observer_process_incarnation_id=observer_process_incarnation_id, clock_domain_id=clock_domain_id, clock_scope=_CLOCK_SCOPE, clock_resolution_ns=clock_resolution_ns, clock_provenance=_CLOCK_PROVENANCE,
        clock_generation=clock_generation, transaction_id=transaction_id,
        transaction_receipt_sha256=transaction_receipt_sha256, global_sequence=global_sequence,
        event_id=event_id, event_payload_sha256=candidate.candidate_sha256,
        dispatch_payload_sha256=candidate.dispatch_payload_sha256, origin_dispatch_revision_id=candidate.origin_dispatch_revision_id, origin_dispatch_payload_sha256=candidate.origin_dispatch_payload_sha256,
        binding_id=candidate.dispatch_binding_id, binding_sha256=candidate.dispatch_binding_sha256, task_id=candidate.task_id,
        packet_id=candidate.packet_id, dispatch_request_id=candidate.dispatch_request_id,
        stage="engineering_acceptance_candidate_receipt_sealed", subject_id=candidate.candidate_id,
        subject_sha256=candidate.candidate_sha256, pre_tick=pre_tick, pre_monotonic_ns=pre_monotonic_ns,
        post_tick=post_tick, post_monotonic_ns=post_monotonic_ns, candidate_outcome=candidate.reviewer_outcome,
        commit_observation=commit_observation, capture_authority="caller_supplied_unverified",
    )


def _require_seal_after_candidate_witnesses(
    candidate: EngineeringAcceptanceCandidateReceiptV1, global_sequence: int,
) -> None:
    """Require the caller's seal observation to follow every embedded witness.

    The candidate is already re-derived from its bounded projection before this
    helper is called.  A seal at an equal or older cursor would otherwise make
    a structurally self-consistent end mark look like it happened after review
    material that was not yet visible at that cursor.
    """
    _uint(global_sequence, "global_sequence")
    witness_sequences = (
        *(item.global_sequence for item in candidate.lineage),
        *(item.global_sequence for item in candidate.task_revision_history),
        *(item.global_sequence for item in candidate.dispatch_revision_history),
        *(item.global_sequence for item in candidate.evidence),
        *(item.reviewer_execution_global_sequence for item in candidate.evidence),
    )
    if global_sequence <= max(witness_sequences):
        _fail("candidate seal cursor must strictly follow every embedded witness")


def derive_stage_span(
    start_mark: SupervisorStageMarkV1, end_mark: SupervisorStageMarkV1 | None = None,
    *, candidate: EngineeringAcceptanceCandidateReceiptV1 | None = None,
    projection: InvariantProjection | None = None, context_manifest_bytes: bytes | None = None,
    open_reason: str = "engineering_acceptance_unknown",
) -> SupervisorStageSpanV1:
    """Derive independent lower/upper bounds without an aggregate latency claim."""
    start = _validated_mark(start_mark)
    if start.stage != "dispatch_accepted":
        _fail("span start must be dispatch_accepted")
    end = None if end_mark is None else _validated_mark(end_mark)
    lower: int | None = None
    upper: int | None = None
    cohort: str
    reason: str
    if end is None:
        if open_reason not in {"effect_unknown_start_proven", "engineering_acceptance_unknown"}:
            _fail("open cohort reason is invalid")
        availability, cohort, reason = "unavailable", "open_right_censored", open_reason
    else:
        if candidate is None or projection is None or context_manifest_bytes is None:
            _fail("span end requires a re-derived bounded acceptance witness")
        candidate = validate_engineering_acceptance_candidate_against_witness(
            candidate, projection, context_manifest_bytes,
        )
        _require_seal_after_candidate_witnesses(candidate, end.global_sequence)
        if (end.subject_id, end.subject_sha256, end.candidate_outcome) != (
            candidate.candidate_id, candidate.candidate_sha256, candidate.reviewer_outcome,
        ):
            _fail("span end candidate witness differs")
        candidate_start_dispatch_lineage = (
            candidate.company_id, candidate.company_incarnation,
            candidate.lock_domain_generation, candidate.task_id, candidate.packet_id,
            candidate.dispatch_request_id, candidate.origin_dispatch_payload_sha256,
            candidate.origin_dispatch_revision_id,
            candidate.origin_dispatch_payload_sha256, candidate.dispatch_binding_id,
            candidate.dispatch_binding_sha256,
        )
        candidate_end_dispatch_lineage = (
            candidate.company_id, candidate.company_incarnation,
            candidate.lock_domain_generation, candidate.task_id, candidate.packet_id,
            candidate.dispatch_request_id, candidate.dispatch_payload_sha256,
            candidate.origin_dispatch_revision_id,
            candidate.origin_dispatch_payload_sha256, candidate.dispatch_binding_id,
            candidate.dispatch_binding_sha256,
        )
        start_dispatch_lineage = (
            start.company_id, start.company_incarnation, start.lock_domain_generation,
            start.task_id, start.packet_id, start.dispatch_request_id,
            start.dispatch_payload_sha256, start.origin_dispatch_revision_id,
            start.origin_dispatch_payload_sha256, start.binding_id, start.binding_sha256,
        )
        end_dispatch_lineage = (
            end.company_id, end.company_incarnation, end.lock_domain_generation,
            end.task_id, end.packet_id, end.dispatch_request_id,
            end.dispatch_payload_sha256, end.origin_dispatch_revision_id,
            end.origin_dispatch_payload_sha256, end.binding_id, end.binding_sha256,
        )
        # The start is the queued origin revision; the sealed candidate/end
        # carries the later current dispatch revision plus that same origin.
        if start_dispatch_lineage != candidate_start_dispatch_lineage:
            _fail("span start candidate dispatch lineage differs")
        if end_dispatch_lineage != candidate_end_dispatch_lineage:
            _fail("span end candidate dispatch lineage differs")
        same_subject = (
            end.stage == "engineering_acceptance_candidate_receipt_sealed"
        )
        if not same_subject:
            _fail("span end subject differs")
        if (
            end.global_sequence <= start.global_sequence
            or end.transaction_id == start.transaction_id
            or end.transaction_receipt_sha256 == start.transaction_receipt_sha256
            or end.event_id == start.event_id
        ):
            _fail("span end is not a later distinct commit observation")
        cohort = (
            "candidate_acceptance_endpoint"
            if end.candidate_outcome == "accepted_candidate"
            else "review_rejected_rework_signal"
        )
        reason_prefix = (
            "accepted_candidate"
            if end.candidate_outcome == "accepted_candidate"
            else "review_rejected_rework_signal"
        )
        same_clock = (start.observer_service_id, start.observer_process_incarnation_id, start.clock_domain_id, start.clock_scope, start.clock_generation) == (end.observer_service_id, end.observer_process_incarnation_id, end.clock_domain_id, end.clock_scope, end.clock_generation)
        if not same_clock:
            availability, reason = "unavailable", f"{reason_prefix}_cross_process_or_clock_domain"
        else:
            if start.pre_tick is not None and end.post_tick < start.pre_tick:
                _fail("span tick chronology is definitely reversed")
            if start.pre_monotonic_ns is not None and end.post_monotonic_ns < start.pre_monotonic_ns:
                _fail("span pre/post chronology is definitely reversed")
            if start.clock_resolution_ns is None or end.clock_resolution_ns is None:
                availability, reason = "unavailable", f"{reason_prefix}_clock_resolution_unavailable"
                sample_uncertainty = None
            else:
                sample_uncertainty = start.clock_resolution_ns + end.clock_resolution_ns
            if sample_uncertainty is None:
                pass
            else:
                if end.pre_monotonic_ns is not None:
                    lower = max(0, end.pre_monotonic_ns - start.post_monotonic_ns - sample_uncertainty)
                if start.pre_monotonic_ns is not None:
                    upper = end.post_monotonic_ns - start.pre_monotonic_ns + sample_uncertainty
                    if upper < 0:
                        _fail("span pre/post chronology is definitely reversed")
                availability = "bounded" if lower is not None and upper is not None else (
                    "partially_unavailable" if lower is not None or upper is not None else "unavailable"
                )
                if availability == "bounded":
                    reason = f"{reason_prefix}_caller_supplied_supervisor_commit_brackets_rederived_candidate_and_resolution_bound"
                elif availability == "partially_unavailable":
                    reason = f"{reason_prefix}_one_sided_supervisor_commit_bracket"
                else:
                    reason = f"{reason_prefix}_supervisor_commit_brackets_unavailable"
    unsigned = {
        "company_id": start.company_id, "company_incarnation": start.company_incarnation,
        "lock_domain_generation": start.lock_domain_generation, "task_id": start.task_id,
        "packet_id": start.packet_id, "dispatch_request_id": start.dispatch_request_id,
        "start_mark": start._asdict(), "end_mark": None if end is None else end._asdict(),
        "candidate_id": None if candidate is None else candidate.candidate_id,
        "candidate_sha256": None if candidate is None else candidate.candidate_sha256,
        "elapsed_lower_ns": lower, "elapsed_upper_ns": upper, "duration_availability": availability,
        "cohort_state": cohort, "reason": reason, "derivation_scope": "pure_off_ledger_no_latency_aggregate",
    }
    digest = _digest(unsigned)
    return SupervisorStageSpanV1(
        f"supervisor-stage-span-{digest}", digest, start.company_id, start.company_incarnation,
        start.lock_domain_generation, start.task_id, start.packet_id, start.dispatch_request_id,
        start, end, lower, upper, availability, cohort, reason,
        "pure_off_ledger_no_latency_aggregate",
    )
