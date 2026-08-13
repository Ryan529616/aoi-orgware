"""AOI-SYNTHETIC-FIXTURE-V1 tests for the pure acceptance-candidate contract."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    ENGINEERING_DISPOSITION_RECEIPT_V1, EVIDENCE_RECORD_V1, EXECUTION_NODE_V1,
    WORK_DISPATCH_BINDING_V1, WORK_RESULT_RECEIPT_V1, canonical_company_json_bytes, company_contract_sha256,
    validate_execution_node,
)
from aoi_orgware.company.invariants import InvariantObject, InvariantProjection
from aoi_orgware.company.latency.acceptance_contract import (
    EngineeringAcceptanceCandidateError, build_engineering_acceptance_candidate,
    validate_engineering_acceptance_candidate_against_witness,
    validate_engineering_acceptance_candidate_receipt,
)
from aoi_orgware.company.latency.stage_spans import (
    StageSpanError,
    build_dispatch_accepted_mark, build_engineering_acceptance_candidate_receipt_sealed_mark,
    derive_stage_span,
)
from aoi_orgware.company.latency import acceptance_contract as acceptance

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_work_dispatch_result as work_result  # type: ignore[import-not-found]


def _projection(objects: list[InvariantObject], dispatch_requests: tuple[InvariantObject, ...] = ()) -> InvariantProjection:
    return InvariantProjection(tuple(objects), dispatch_requests, (), 0, (), True, (), ())


def _history(supervisor: Any, contract_type: str, object_key: str) -> tuple[InvariantObject, ...]:
    identity_field = {
        "dispatch_request_v1": "dispatch_request_id",
        EXECUTION_NODE_V1: "execution_id",
    }.get(contract_type)
    if identity_field is None:
        raise AssertionError(f"unsupported history contract {contract_type}")
    result: list[InvariantObject] = []
    for record in supervisor.records_after(0, limit=128):
        for event in record.events:
            payload = event.event.get("payload")
            if isinstance(payload, Mapping) and payload.get("contract_type") == contract_type:
                key = payload.get(identity_field)
                if key == object_key:
                    result.append(_item(contract_type, object_key, str(event.event["event_id"]), record.global_sequence, _thaw(payload)))
    return tuple(result)


def _recorded_item(
    supervisor: Any, contract_type: str, identity_field: str, identity_value: str,
    *, object_key: str | None = None,
) -> InvariantObject:
    matches: list[InvariantObject] = []
    for record in supervisor.records_after(0, limit=128):
        for event in record.events:
            payload = event.event.get("payload")
            if (
                isinstance(payload, Mapping)
                and payload.get("contract_type") == contract_type
                and payload.get(identity_field) == identity_value
            ):
                matches.append(_item(
                    contract_type, identity_value if object_key is None else object_key,
                    str(event.event["event_id"]),
                    record.global_sequence, _thaw(payload),
                ))
    assert len(matches) == 1
    return matches[0]


def _item(contract_type: str, key: str, event_id: str, sequence: int, payload: dict[str, Any]) -> InvariantObject:
    return InvariantObject(contract_type, key, event_id, sequence, company_contract_sha256(payload), payload)


def _as_invariant(item: Any, key: str, sequence: int) -> InvariantObject:
    def thaw(value: Any) -> Any:
        if isinstance(value, Mapping): return {name: thaw(member) for name, member in value.items()}
        if isinstance(value, (tuple, list)): return [thaw(member) for member in value]
        return value
    return _item(item.contract_type, key, f"synthetic-projection-event-{sequence}", sequence, thaw(item.payload))


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping): return {name: _thaw(member) for name, member in value.items()}
    if isinstance(value, (tuple, list)): return [_thaw(member) for member in value]
    return value


def _reviewer(producer: InvariantObject, *, suffix: str = "", evidence_id: str = "synthetic-review-evidence") -> InvariantObject:
    def thaw(value: Any) -> Any:
        if isinstance(value, Mapping): return {key: thaw(member) for key, member in value.items()}
        if isinstance(value, (tuple, list)): return [thaw(member) for member in value]
        return value
    raw = thaw(producer.payload)
    raw.update({
        "execution_id": f"synthetic-reviewer-execution{suffix}", "display_name": "AOI-SYNTHETIC-FIXTURE-V1 reviewer",
        "role": "reviewer", "agent_id": f"synthetic-reviewer-agent{suffix}", "carrier_id": f"synthetic-reviewer-carrier{suffix}",
        "thread_id": f"synthetic-reviewer-thread{suffix}", "turn_id": f"synthetic-reviewer-turn{suffix}",
    })
    raw["execution_path"] = [*raw["execution_path"][:-1], raw["execution_id"]]
    raw["evidence_ids"] = [evidence_id]
    checked = validate_execution_node(raw)
    return _item(EXECUTION_NODE_V1, checked["execution_id"], f"synthetic-reviewer-event{suffix}", 900 + len(suffix), checked)


def _evidence(result: dict[str, Any], reviewer: InvariantObject, *, status: str = "pass", evidence_id: str = "synthetic-review-evidence", sequence: int = 901) -> InvariantObject:
    artifact = {key: value for key, value in result["result_ref"].items()}
    artifact["sha256"] = "d" * 64
    raw = {
        "contract_type": EVIDENCE_RECORD_V1, "schema_version": 1,
        "company_id": result["company_id"], "company_incarnation": result["company_incarnation"],
        "lock_domain_generation": result["lock_domain_generation"], "evidence_id": evidence_id,
        "execution_id": reviewer.payload["execution_id"], "claim_id": result["result_receipt_id"],
        "evidence_class": "runtime", "status": status, "artifact": artifact,
        "command_sha256": "a" * 64, "verification_sha256": "b" * 64,
        "recorded_at": "2026-07-27T00:08:00Z", "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    }
    return _item(EVIDENCE_RECORD_V1, raw["evidence_id"], f"synthetic-evidence-event-{evidence_id}", sequence, raw)


def _candidate_witness_max_sequence(candidate: Any) -> int:
    return max(
        *(item.global_sequence for item in candidate.lineage),
        *(item.global_sequence for item in candidate.task_revision_history),
        *(item.global_sequence for item in candidate.dispatch_revision_history),
        *(item.global_sequence for item in candidate.evidence),
        *(item.reviewer_execution_global_sequence for item in candidate.evidence),
    )


def test_candidate_binds_all_visible_terminal_review_material(tmp_path: Path) -> None:
    # Build the canonical context through the registration helper, then add only
    # synthetic review identities; no host/provider facts are in this fixture.
    supervisor, task, packet, execution_id, disposition_bytes, disposition = work_result._registered_stopped_execution(tmp_path)
    try:
        supervisor.record_department_execution_idle(execution_id, disposition_bytes, disposition, transaction_id="registered-idle-transaction", command_id="registered-idle-command", recorded_at="2026-07-27T00:07:00Z", result_bytes=b"AOI-SYNTHETIC-FIXTURE-V1", result_media_type="text/plain")
        by_type: dict[str, list[InvariantObject]] = {}
        for item in supervisor.objects(): by_type.setdefault(item.contract_type, []).append(item)
        result_id = by_type[WORK_RESULT_RECEIPT_V1][0].payload["result_receipt_id"]
        result_item = _recorded_item(supervisor, WORK_RESULT_RECEIPT_V1, "result_receipt_id", result_id)
        result_raw = _thaw(result_item.payload)
        disposition_id = result_raw["engineering_disposition_receipt_id"]
        disposition_item = _recorded_item(
            supervisor, ENGINEERING_DISPOSITION_RECEIPT_V1, "receipt_id", disposition_id,
        )
        disposition_raw = _thaw(disposition_item.payload)
        execution_history = _history(supervisor, EXECUTION_NODE_V1, execution_id)
        pre_transition = execution_history[-2]
        producer_item = execution_history[-1]
        reviewer = _reviewer(producer_item)
        evidence = _evidence(result_raw, reviewer)
        objects = [
            _as_invariant(by_type["task_revision_v1"][0], task["task_revision_id"], 1),
            _as_invariant(by_type["work_packet_v1"][0], packet["packet_id"], 2),
                _recorded_item(
                    supervisor, WORK_DISPATCH_BINDING_V1, "binding_id",
                    by_type[WORK_DISPATCH_BINDING_V1][0].payload["binding_id"],
                    object_key="registered-dispatch",
                ),
            result_item, disposition_item, pre_transition, producer_item, reviewer, evidence,
        ]
        _, _, manifest, _ = work_result.registration._work_bundle(supervisor)
        history = _history(supervisor, "dispatch_request_v1", "registered-dispatch")
        objects[3:3] = history
        projection = _projection(objects, (history[-1],))
        context_bytes = canonical_company_json_bytes(manifest)
        candidate = build_engineering_acceptance_candidate(projection, task_revision_id=task["task_revision_id"], packet_id=packet["packet_id"], dispatch_request_id="registered-dispatch", dispatch_binding_id=by_type[WORK_DISPATCH_BINDING_V1][0].payload["binding_id"], result_receipt_id=result_item.payload["result_receipt_id"], context_manifest_bytes=context_bytes, dispatch_revision_history=history, pre_transition_execution=pre_transition)
        assert candidate.receipt_state == "acceptance_candidate"
        assert candidate.reviewer_outcome == "accepted_candidate"
        assert candidate.projection_completeness == "unverified"
        assert validate_engineering_acceptance_candidate_against_witness(candidate, projection, context_bytes) == candidate
        accepted_witness_max = _candidate_witness_max_sequence(candidate)
        start = build_dispatch_accepted_mark(
            history[0].payload, objects[2].payload, observer_service_id="synthetic-observer",
            observer_process_incarnation_id="synthetic-process", clock_domain_id="python_monotonic_ns",
            clock_generation=0, clock_resolution_ns=100, transaction_receipt_sha256="c" * 64,
            global_sequence=11, event_id="synthetic-stage-start", commit_observation="newly_committed",
            pre_tick=10, pre_monotonic_ns=1000, post_tick=11, post_monotonic_ns=1100,
        )
        end = build_engineering_acceptance_candidate_receipt_sealed_mark(
            candidate, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
            clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
            transaction_id="synthetic-stage-end-tx", transaction_receipt_sha256="d" * 64,
            global_sequence=accepted_witness_max + 1, event_id="synthetic-stage-end", commit_observation="newly_committed",
            pre_tick=12, pre_monotonic_ns=1200, post_tick=13, post_monotonic_ns=1300,
            projection=projection, context_manifest_bytes=context_bytes,
        )
        assert derive_stage_span(start, end, candidate=candidate, projection=projection, context_manifest_bytes=context_bytes).cohort_state == "candidate_acceptance_endpoint"
        unknown_resolution_end = build_engineering_acceptance_candidate_receipt_sealed_mark(
            candidate, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
            clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=None,
            transaction_id="synthetic-stage-unknown-resolution", transaction_receipt_sha256="e" * 64,
            global_sequence=accepted_witness_max + 2, event_id="synthetic-stage-unknown-resolution", commit_observation="newly_committed",
            pre_tick=14, pre_monotonic_ns=1400, post_tick=15, post_monotonic_ns=1500,
            projection=projection, context_manifest_bytes=context_bytes,
        )
        assert derive_stage_span(start, unknown_resolution_end, candidate=candidate, projection=projection, context_manifest_bytes=context_bytes).duration_availability == "unavailable"
        # A missing resolution bound does not hide a definitely reversed
        # same-clock bracket.  These use the real candidate and its witness,
        # rather than a stand-alone mark fixture.
        with pytest.raises(StageSpanError, match="definitely reversed"):
            derive_stage_span(
                start,
                build_engineering_acceptance_candidate_receipt_sealed_mark(
                    candidate, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
                    clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=None,
                    transaction_id="synthetic-accepted-reversed", transaction_receipt_sha256="8" * 64,
                    global_sequence=accepted_witness_max + 3, event_id="synthetic-accepted-reversed", commit_observation="newly_committed",
                    pre_tick=8, pre_monotonic_ns=800, post_tick=9, post_monotonic_ns=900,
                    projection=projection, context_manifest_bytes=context_bytes,
                ),
                candidate=candidate, projection=projection, context_manifest_bytes=context_bytes,
            )
        accepted_cross_end = build_engineering_acceptance_candidate_receipt_sealed_mark(
            candidate, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-other-process",
            clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
            transaction_id="synthetic-accepted-cross", transaction_receipt_sha256="0" * 64,
            global_sequence=accepted_witness_max + 4, event_id="synthetic-accepted-cross", commit_observation="newly_committed",
            pre_tick=18, pre_monotonic_ns=1800, post_tick=19, post_monotonic_ns=1900,
            projection=projection, context_manifest_bytes=context_bytes,
        )
        accepted_one_sided_end = build_engineering_acceptance_candidate_receipt_sealed_mark(
            candidate, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
            clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
            transaction_id="synthetic-accepted-one-sided", transaction_receipt_sha256="9" * 64,
            global_sequence=accepted_witness_max + 5, event_id="synthetic-accepted-one-sided", commit_observation="newly_committed",
            pre_tick=None, pre_monotonic_ns=None, post_tick=19, post_monotonic_ns=1900,
            projection=projection, context_manifest_bytes=context_bytes,
        )
        accepted_spans = tuple(
            derive_stage_span(start, mark, candidate=candidate, projection=projection, context_manifest_bytes=context_bytes)
            for mark in (end, unknown_resolution_end, accepted_cross_end, accepted_one_sided_end)
        )
        assert [(span.cohort_state, span.duration_availability) for span in accepted_spans] == [
            ("candidate_acceptance_endpoint", "bounded"),
            ("candidate_acceptance_endpoint", "unavailable"),
            ("candidate_acceptance_endpoint", "unavailable"),
            ("candidate_acceptance_endpoint", "partially_unavailable"),
        ]
        assert all(span.reason.startswith("accepted_candidate_") for span in accepted_spans)
        arguments = dict(task_revision_id=task["task_revision_id"], packet_id=packet["packet_id"], dispatch_request_id="registered-dispatch", dispatch_binding_id=by_type[WORK_DISPATCH_BINDING_V1][0].payload["binding_id"], result_receipt_id=result_item.payload["result_receipt_id"], context_manifest_bytes=canonical_company_json_bytes(manifest), dispatch_revision_history=history, pre_transition_execution=pre_transition)
        assert build_engineering_acceptance_candidate(_projection(list(reversed(objects)), (history[-1],)), **arguments).candidate_sha256 == candidate.candidate_sha256
        reviewer_two = _reviewer(producer_item, suffix="-two", evidence_id="synthetic-review-evidence-two")
        evidence_two = _evidence(result_raw, reviewer_two, evidence_id="synthetic-review-evidence-two", sequence=902)
        accepted_two = build_engineering_acceptance_candidate(_projection([*objects, reviewer_two, evidence_two], (history[-1],)), **arguments)
        assert len(accepted_two.evidence) == 2
        rejected_reviewer = _reviewer(producer_item, suffix="-fail", evidence_id="synthetic-review-evidence-fail")
        rejected_evidence = _evidence(result_raw, rejected_reviewer, status="fail", evidence_id="synthetic-review-evidence-fail", sequence=903)
        rejected_projection = _projection([*objects, rejected_reviewer, rejected_evidence], (history[-1],))
        rejected = build_engineering_acceptance_candidate(rejected_projection, **arguments)
        assert rejected.reviewer_outcome == "rejected_candidate"
        rejected_witness_max = _candidate_witness_max_sequence(rejected)
        # Candidate outcome and duration availability are orthogonal.  Every
        # rejected terminal witness stays in the rework cohort, even when a
        # same-process bracket cannot yield a complete duration.
        rejected_marks = (
            build_engineering_acceptance_candidate_receipt_sealed_mark(
                rejected, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
                clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
                transaction_id="synthetic-rejected-known", transaction_receipt_sha256="1" * 64,
                global_sequence=rejected_witness_max + 1, event_id="synthetic-rejected-known", commit_observation="newly_committed",
                pre_tick=20, pre_monotonic_ns=2000, post_tick=21, post_monotonic_ns=2100,
                projection=rejected_projection, context_manifest_bytes=context_bytes,
            ),
            build_engineering_acceptance_candidate_receipt_sealed_mark(
                rejected, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
                clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=None,
                transaction_id="synthetic-rejected-unknown", transaction_receipt_sha256="2" * 64,
                global_sequence=rejected_witness_max + 2, event_id="synthetic-rejected-unknown", commit_observation="newly_committed",
                pre_tick=22, pre_monotonic_ns=2200, post_tick=23, post_monotonic_ns=2300,
                projection=rejected_projection, context_manifest_bytes=context_bytes,
            ),
            build_engineering_acceptance_candidate_receipt_sealed_mark(
                rejected, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-other-process",
                clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
                transaction_id="synthetic-rejected-cross", transaction_receipt_sha256="3" * 64,
                global_sequence=rejected_witness_max + 3, event_id="synthetic-rejected-cross", commit_observation="newly_committed",
                pre_tick=24, pre_monotonic_ns=2400, post_tick=25, post_monotonic_ns=2500,
                projection=rejected_projection, context_manifest_bytes=context_bytes,
            ),
            build_engineering_acceptance_candidate_receipt_sealed_mark(
                rejected, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
                clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
                transaction_id="synthetic-rejected-one-sided", transaction_receipt_sha256="4" * 64,
                global_sequence=rejected_witness_max + 4, event_id="synthetic-rejected-one-sided", commit_observation="newly_committed",
                pre_tick=None, pre_monotonic_ns=None, post_tick=27, post_monotonic_ns=2700,
                projection=rejected_projection, context_manifest_bytes=context_bytes,
            ),
        )
        spans = tuple(derive_stage_span(start, mark, candidate=rejected, projection=rejected_projection, context_manifest_bytes=context_bytes) for mark in rejected_marks)
        assert [span.duration_availability for span in spans] == ["bounded", "unavailable", "unavailable", "partially_unavailable"]
        assert all(span.cohort_state == "review_rejected_rework_signal" for span in spans)
        assert [span.reason for span in spans] == [
            "review_rejected_rework_signal_caller_supplied_supervisor_commit_brackets_rederived_candidate_and_resolution_bound",
            "review_rejected_rework_signal_clock_resolution_unavailable",
            "review_rejected_rework_signal_cross_process_or_clock_domain",
            "review_rejected_rework_signal_one_sided_supervisor_commit_bracket",
        ]
        with pytest.raises(StageSpanError, match="definitely reversed"):
            derive_stage_span(
                start,
                build_engineering_acceptance_candidate_receipt_sealed_mark(
                    rejected, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
                    clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=None,
                    transaction_id="synthetic-rejected-reversed", transaction_receipt_sha256="7" * 64,
                    global_sequence=rejected_witness_max + 5, event_id="synthetic-rejected-reversed", commit_observation="newly_committed",
                    pre_tick=8, pre_monotonic_ns=800, post_tick=9, post_monotonic_ns=900,
                    projection=rejected_projection, context_manifest_bytes=context_bytes,
                ),
                candidate=rejected, projection=rejected_projection, context_manifest_bytes=context_bytes,
            )
        pre_result_sequence = _item(
            EVIDENCE_RECORD_V1, evidence.payload["evidence_id"], "synthetic-pre-result-sequence",
            result_item.global_sequence, _thaw(evidence.payload),
        )
        with pytest.raises(EngineeringAcceptanceCandidateError, match="precedes the result"):
            build_engineering_acceptance_candidate(
                _projection([*objects[:-1], pre_result_sequence], (history[-1],)), **arguments,
            )
        pre_result_time = _thaw(evidence.payload)
        pre_result_time["recorded_at"] = "2026-07-27T00:06:59Z"
        with pytest.raises(EngineeringAcceptanceCandidateError, match="precedes the result"):
            build_engineering_acceptance_candidate(
                _projection([
                    *objects[:-1],
                    _item(EVIDENCE_RECORD_V1, pre_result_time["evidence_id"], "synthetic-pre-result-time", 909, pre_result_time),
                ], (history[-1],)), **arguments,
            )
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:-1], _evidence(result_raw, reviewer, status="skipped")], (history[-1],)), **arguments)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([replace(objects[0], object_key="wrong-task-key"), *objects[1:]], (history[-1],)), **arguments)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection(objects, (replace(history[-1], event_id="synthetic-stale-dispatch-event"),)), **arguments)
        divergent_predecessor_event = replace(
            pre_transition,
            event_id=producer_item.event_id,
        )
        with pytest.raises(EngineeringAcceptanceCandidateError, match="event identity"):
            build_engineering_acceptance_candidate(
                projection,
                **{**arguments, "pre_transition_execution": divergent_predecessor_event},
            )
        binding_raw = _thaw(objects[2].payload)
        binding_raw["task_sha256"] = "f" * 64
        binding_raw["binding_sha256"] = company_contract_sha256({key: value for key, value in binding_raw.items() if key != "binding_sha256"})
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:2], _item(WORK_DISPATCH_BINDING_V1, binding_raw["dispatch_request_id"], "synthetic-mutated-binding", 904, binding_raw), *objects[3:]], (history[-1],)), **arguments)
        binding_revision_two = _thaw(objects[2].payload)
        binding_revision_two["dispatch_revision_id"] = history[1].payload["dispatch_revision_id"]
        binding_revision_two["dispatch_payload_sha256"] = history[1].payload_sha256
        binding_revision_two["binding_sha256"] = company_contract_sha256({key: value for key, value in binding_revision_two.items() if key != "binding_sha256"})
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:2], _item(WORK_DISPATCH_BINDING_V1, binding_revision_two["binding_id"], "synthetic-revision-two-binding", 905, binding_revision_two), *objects[3:]], (history[-1],)), **arguments)
        binding_command = _thaw(objects[2].payload)
        binding_command["command_id"] = "synthetic-divergent-origin-command"
        binding_command["binding_sha256"] = company_contract_sha256({key: value for key, value in binding_command.items() if key != "binding_sha256"})
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:2], _item(WORK_DISPATCH_BINDING_V1, binding_command["dispatch_request_id"], "synthetic-divergent-origin-command", objects[2].global_sequence, binding_command), *objects[3:]], (history[-1],)), **arguments)
        binding_scope = _thaw(objects[2].payload)
        binding_scope["authority_scope_sha256"] = "0" * 64
        binding_scope["binding_sha256"] = company_contract_sha256({key: value for key, value in binding_scope.items() if key != "binding_sha256"})
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:2], _item(WORK_DISPATCH_BINDING_V1, binding_scope["dispatch_request_id"], "synthetic-divergent-origin-scope", objects[2].global_sequence, binding_scope), *objects[3:]], (history[-1],)), **arguments)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:2], replace(objects[2], global_sequence=999), *objects[3:]], (history[-1],)), **arguments)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([
                *(replace(item, global_sequence=item.global_sequence + 1) if item is result_item else item for item in objects),
            ], (history[-1],)), **arguments)
        result_mutated = _thaw(result_raw)
        result_mutated["packet_sha256"] = "e" * 64
        result_mutated["receipt_sha256"] = company_contract_sha256({key: value for key, value in result_mutated.items() if key != "receipt_sha256"})
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:4], _item(WORK_RESULT_RECEIPT_V1, result_mutated["result_receipt_id"], "synthetic-mutated-result", 905, result_mutated), *objects[5:]], (history[-1],)), **arguments)
        reused_reviewer = _reviewer(producer_item, suffix="-reused", evidence_id="synthetic-reused-evidence")
        reused_artifact = _evidence(result_raw, reused_reviewer, evidence_id="synthetic-reused-evidence", sequence=907)
        reused_raw = _thaw(reused_artifact.payload)
        reused_raw["artifact"]["sha256"] = result_raw["result_ref"]["sha256"]
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects, reused_reviewer, _item(EVIDENCE_RECORD_V1, reused_raw["evidence_id"], "synthetic-reused-result-artifact", 907, reused_raw)], (history[-1],)), **arguments)
        current_reviewer_raw = _thaw(reviewer.payload)
        current_reviewer_raw.update({"role": "worker", "updated_at": "2026-07-27T00:08:01Z"})
        current_reviewer = _item(EXECUTION_NODE_V1, current_reviewer_raw["execution_id"], "synthetic-reviewer-current-worker", 908, current_reviewer_raw)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects, current_reviewer], (history[-1],)), **arguments)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([current_reviewer, *objects], (history[-1],)), **arguments)
        disposition_mutated = _thaw(disposition_raw)
        disposition_mutated["provider"] = "synthetic-other-provider"
        disposition_mutated["receipt_sha256"] = company_contract_sha256({key: value for key, value in disposition_mutated.items() if key != "receipt_sha256"})
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate(_projection([*objects[:5], _item(ENGINEERING_DISPOSITION_RECEIPT_V1, disposition_mutated["receipt_id"], "synthetic-mutated-disposition", 906, disposition_mutated), *objects[6:]], (history[-1],)), **arguments)
        with pytest.raises(AttributeError):
            candidate.evidence[0].status = "fail"  # type: ignore[misc]
        with pytest.raises(EngineeringAcceptanceCandidateError):
            validate_engineering_acceptance_candidate_receipt(candidate._replace(task_revision=-1))
        with pytest.raises(EngineeringAcceptanceCandidateError):
            validate_engineering_acceptance_candidate_receipt(candidate._replace(
                reviewer_outcome="accepted_candidate",
                evidence=(candidate.evidence[0]._replace(status="fail"),),
            ))
        forged = candidate._replace(
            reviewer_outcome="rejected_candidate",
            evidence=(candidate.evidence[0]._replace(status="fail"),),
        )
        forged_digest = acceptance._candidate_digest(acceptance._unsigned(forged))
        forged = forged._replace(candidate_id=f"acceptance-candidate-{forged_digest}", candidate_sha256=forged_digest)
        assert validate_engineering_acceptance_candidate_receipt(forged) == forged
        with pytest.raises(EngineeringAcceptanceCandidateError):
            validate_engineering_acceptance_candidate_against_witness(forged, projection, context_bytes)
        with pytest.raises(EngineeringAcceptanceCandidateError):
            build_engineering_acceptance_candidate_receipt_sealed_mark(
                forged, observer_service_id="synthetic-observer", observer_process_incarnation_id="synthetic-process",
                clock_domain_id="python_monotonic_ns", clock_generation=0, clock_resolution_ns=100,
                transaction_id="synthetic-forged-end", transaction_receipt_sha256="f" * 64,
                global_sequence=14, event_id="synthetic-forged-end", commit_observation="newly_committed",
                pre_tick=16, pre_monotonic_ns=1600, post_tick=17, post_monotonic_ns=1700,
                projection=projection, context_manifest_bytes=context_bytes,
            )
    finally:
        supervisor.close()


def test_candidate_requires_a_real_projection(tmp_path: Path) -> None:
    # This exact failure boundary prevents callers from selecting only passing reviews.
    with pytest.raises(EngineeringAcceptanceCandidateError):
        build_engineering_acceptance_candidate(None, task_revision_id="x", packet_id="y", dispatch_request_id="z", dispatch_binding_id="q", result_receipt_id="r", context_manifest_bytes=b"{}", dispatch_revision_history=(), pre_transition_execution=None)


def test_real_supervisor_failed_known_tail_cannot_build_a_candidate(tmp_path: Path) -> None:
    supervisor = work_result.lifecycle._initialize(tmp_path)
    try:
        task, packet, context, prompt = work_result.registration._work_bundle(supervisor)
        work_result.registration._register(supervisor, task, packet, context, prompt)
        identity, _, _ = work_result.lifecycle._rtl(supervisor)
        supervisor.enqueue_department_dispatch(
            identity["department_id"], transaction_id="failed-tail-enqueue-transaction",
            command_id="failed-tail-enqueue-command", dispatch_request_id="failed-tail-dispatch",
            reservation_id="failed-tail-reservation", task_id=task["task_id"], packet_id=packet["packet_id"],
            route_policy_id="failed-tail-route", requested_role="rtl_lead",
            requested_capability_tier="standard", requested_at="2026-07-27T00:01:00Z",
            recorded_at="2026-07-27T00:02:00Z",
        )
        supervisor.admit_department_dispatch(
            "failed-tail-dispatch", transaction_id="failed-tail-admit-transaction",
            command_id="failed-tail-admit-command", recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.begin_department_dispatch(
            "failed-tail-dispatch", transaction_id="failed-tail-begin-transaction",
            command_id="failed-tail-begin-command", recorded_at="2026-07-27T00:04:00Z",
        )
        receipt = work_result.lifecycle._provider_receipt(
            supervisor, event_kind="dispatch_failed", transaction_id="failed-tail-fail-transaction",
            command_id="failed-tail-fail-command", recorded_at="2026-07-27T00:05:00Z",
        )
        supervisor.fail_department_dispatch(
            "failed-tail-dispatch", receipt, transaction_id="failed-tail-fail-transaction",
            command_id="failed-tail-fail-command", recorded_at="2026-07-27T00:05:00Z",
        )
        history = _history(supervisor, "dispatch_request_v1", "failed-tail-dispatch")
        assert history[-1].payload["state"] == "failed_known"
        binding = supervisor.objects(contract_type=WORK_DISPATCH_BINDING_V1)[0]
        objects = [
            _as_invariant(supervisor.objects(contract_type="task_revision_v1")[0], task["task_revision_id"], 1),
            _as_invariant(supervisor.objects(contract_type="work_packet_v1")[0], packet["packet_id"], 2),
            _recorded_item(supervisor, WORK_DISPATCH_BINDING_V1, "binding_id", binding.payload["binding_id"], object_key="failed-tail-dispatch"),
            *history,
        ]
        with pytest.raises(EngineeringAcceptanceCandidateError, match="has not reached dispatched"):
            build_engineering_acceptance_candidate(
                _projection(objects, (history[-1],)), task_revision_id=task["task_revision_id"],
                packet_id=packet["packet_id"], dispatch_request_id="failed-tail-dispatch",
                dispatch_binding_id=binding.payload["binding_id"], result_receipt_id="missing-result",
                context_manifest_bytes=canonical_company_json_bytes(context),
                dispatch_revision_history=history, pre_transition_execution=None,
            )
    finally:
        supervisor.close()
