"""AOI-SYNTHETIC-FIXTURE-V1 tests for pure Supervisor bracket arithmetic."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

from aoi_orgware.company.contracts import (
    DISPATCH_REQUEST_V1, ENGINEERING_DISPOSITION_RECEIPT_V1,
    WORK_DISPATCH_BINDING_V1, WORK_RESULT_RECEIPT_V1, canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.latency.acceptance_contract import build_engineering_acceptance_candidate
from aoi_orgware.company.latency.stage_spans import (
    StageSpanError, SupervisorStageMarkV1, _build_mark, build_dispatch_accepted_mark,
    build_engineering_acceptance_candidate_receipt_sealed_mark, derive_stage_span,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_work_dispatch_result as work_result  # type: ignore[import-not-found]
import test_engineering_acceptance_contract as acceptance_fixture  # type: ignore[import-not-found]


def _mark(stage: str, *, pre: int | None, post: int, process: str = "synthetic-process", sequence: int | None = None, binding_id: str = "synthetic-binding", transaction_id: str | None = None, transaction_receipt_sha256: str | None = None):
    is_start = stage == "dispatch_accepted"
    return _build_mark(
        company_id="synthetic-company", company_incarnation=1, lock_domain_generation=1,
        observer_service_id="synthetic-supervisor", observer_process_incarnation_id=process,
        clock_domain_id="python_monotonic_ns", clock_scope="supervisor_local", clock_resolution_ns=100, clock_provenance="supervisor_local_python_monotonic_ns", clock_generation=0, transaction_id=("synthetic-start-tx" if is_start else "synthetic-end-tx") if transaction_id is None else transaction_id,
        transaction_receipt_sha256=(("a" * 64 if is_start else "e" * 64) if transaction_receipt_sha256 is None else transaction_receipt_sha256), global_sequence=(1 if is_start else 2) if sequence is None else sequence, event_id=("synthetic-start-event" if is_start else "synthetic-end-event"),
        event_payload_sha256="b" * 64, dispatch_payload_sha256="b" * 64, origin_dispatch_revision_id="synthetic-origin", origin_dispatch_payload_sha256="b" * 64,
        binding_id=binding_id, binding_sha256="c" * 64,
        task_id="synthetic-task", packet_id="synthetic-packet", dispatch_request_id="synthetic-dispatch",
        stage=stage, subject_id=("synthetic-origin" if is_start else "acceptance-candidate-" + "b" * 64), subject_sha256="b" * 64,
        pre_tick=None if pre is None else pre, pre_monotonic_ns=pre, post_tick=post, post_monotonic_ns=post,
        candidate_outcome=None if stage == "dispatch_accepted" else "accepted_candidate",
        commit_observation="newly_committed", capture_authority="caller_supplied_unverified",
    )


def _self_rehashed_mark(mark: SupervisorStageMarkV1, **replacement: object) -> SupervisorStageMarkV1:
    """Construct a caller-supplied, self-consistent mark with altered subject data."""
    unsigned = {
        key: value for key, value in mark._asdict().items()
        if key not in {"mark_id", "mark_sha256"}
    }
    unsigned.update(replacement)
    digest = company_contract_sha256(unsigned)
    return SupervisorStageMarkV1(
        f"supervisor-stage-mark-{digest}", digest, **unsigned,
    )


def test_public_derivation_rejects_self_rehashed_start_subject_not_bound_to_origin() -> None:
    start = _mark("dispatch_accepted", pre=10, post=20)
    with pytest.raises(StageSpanError, match="subject must bind origin dispatch"):
        derive_stage_span(_self_rehashed_mark(start, subject_id="other-origin"))
    with pytest.raises(StageSpanError, match="subject must bind origin dispatch"):
        derive_stage_span(_self_rehashed_mark(
            start, subject_sha256="d" * 64, event_payload_sha256="d" * 64,
            dispatch_payload_sha256="d" * 64,
        ))


def test_overlap_is_zero_lower_bound_and_positive_upper_bound() -> None:
    start = _mark("dispatch_accepted", pre=10, post=20)
    end = _mark("engineering_acceptance_candidate_receipt_sealed", pre=15, post=30)
    # A self-hashed end mark is only a structural capture claim.  It cannot
    # close a span until the bounded candidate/projection/context witnesses are
    # supplied to the public derivation API.
    with pytest.raises(StageSpanError):
        derive_stage_span(start, end)


def test_one_sided_capture_never_claims_a_full_duration() -> None:
    start = _mark("dispatch_accepted", pre=None, post=20)
    end = _mark("engineering_acceptance_candidate_receipt_sealed", pre=30, post=40)
    with pytest.raises(StageSpanError):
        derive_stage_span(start, end)


def test_definite_reverse_is_only_pre_start_after_end_and_replay_cannot_mint_mark() -> None:
    start = _mark("dispatch_accepted", pre=20, post=30)
    with pytest.raises(StageSpanError):
        derive_stage_span(start, _mark("engineering_acceptance_candidate_receipt_sealed", pre=1, post=19))
    with pytest.raises(StageSpanError):
        derive_stage_span(start, _mark("engineering_acceptance_candidate_receipt_sealed", pre=1, post=31, transaction_id="synthetic-start-tx"))
    with pytest.raises(StageSpanError):
        derive_stage_span(start, _mark("engineering_acceptance_candidate_receipt_sealed", pre=1, post=31, transaction_receipt_sha256="a" * 64))
    with pytest.raises(StageSpanError):
        _build_mark(
            **{**_mark("dispatch_accepted", pre=1, post=2)._asdict(),
               "mark_id": "ignored", "mark_sha256": "0" * 64,
               "commit_observation": "idempotent_replay"}
        )


def test_after_only_brackets_and_lineage_mismatch_are_explicitly_unavailable_or_rejected() -> None:
    start = _mark("dispatch_accepted", pre=None, post=20)
    end = _mark("engineering_acceptance_candidate_receipt_sealed", pre=None, post=30)
    with pytest.raises(StageSpanError):
        derive_stage_span(start, end)
    assert derive_stage_span(start, None, open_reason="effect_unknown_start_proven").cohort_state == "open_right_censored"
    with pytest.raises(AttributeError):
        start.post_tick = 99  # type: ignore[misc]
    with pytest.raises(StageSpanError):
        derive_stage_span(start, _mark("engineering_acceptance_candidate_receipt_sealed", pre=None, post=30, binding_id="other-binding"))


def test_public_start_builder_rejects_idempotent_replay_capture(tmp_path: Path) -> None:
    supervisor = work_result.lifecycle._initialize(tmp_path)
    try:
        task, packet, context, prompt = work_result.registration._work_bundle(supervisor)
        work_result.registration._register(supervisor, task, packet, context, prompt)
        identity, _, _ = work_result.lifecycle._rtl(supervisor)
        supervisor.enqueue_department_dispatch(
            identity["department_id"], transaction_id="synthetic-stage-enqueue",
            command_id="synthetic-stage-command", dispatch_request_id="synthetic-stage-dispatch",
            reservation_id="synthetic-stage-reservation", task_id=task["task_id"], packet_id=packet["packet_id"],
            route_policy_id="synthetic-stage-route", requested_role="rtl_lead",
            requested_capability_tier="standard", requested_at="2026-07-27T00:01:00Z",
            recorded_at="2026-07-27T00:02:00Z",
        )
        request = supervisor.objects(contract_type=DISPATCH_REQUEST_V1)[0].payload
        binding = supervisor.objects(contract_type=WORK_DISPATCH_BINDING_V1)[0].payload
        with pytest.raises(StageSpanError):
            build_dispatch_accepted_mark(
                request, binding, observer_service_id="synthetic-observer",
                observer_process_incarnation_id="synthetic-process", clock_domain_id="python_monotonic_ns",
                clock_generation=1, transaction_receipt_sha256="d" * 64, global_sequence=1,
                event_id="synthetic-stage-event", commit_observation="idempotent_replay",
                pre_tick=1, pre_monotonic_ns=1, post_tick=2, post_monotonic_ns=2,
                clock_resolution_ns=100,
            )
    finally:
        supervisor.close()


def test_public_two_dispatch_path_cannot_cross_wire_a_candidate_witness(tmp_path: Path) -> None:
    """A real candidate for one dispatch cannot close another valid queued dispatch."""
    supervisor, task, packet, execution_id, disposition_bytes, disposition = (
        work_result._registered_stopped_execution(tmp_path)
    )
    try:
        supervisor.record_department_execution_idle(
            execution_id, disposition_bytes, disposition,
            transaction_id="registered-idle-transaction", command_id="registered-idle-command",
            recorded_at="2026-07-27T00:07:00Z", result_bytes=b"AOI-SYNTHETIC-FIXTURE-V1",
            result_media_type="text/plain",
        )
        by_type: dict[str, list[object]] = {}
        for item in supervisor.objects():
            by_type.setdefault(item.contract_type, []).append(item)
        result_id = by_type[WORK_RESULT_RECEIPT_V1][0].payload["result_receipt_id"]
        result_item = acceptance_fixture._recorded_item(
            supervisor, WORK_RESULT_RECEIPT_V1, "result_receipt_id", result_id,
        )
        result_raw = acceptance_fixture._thaw(result_item.payload)
        disposition_item = acceptance_fixture._recorded_item(
            supervisor, ENGINEERING_DISPOSITION_RECEIPT_V1, "receipt_id",
            result_raw["engineering_disposition_receipt_id"],
        )
        history = acceptance_fixture._history(supervisor, DISPATCH_REQUEST_V1, "registered-dispatch")
        execution_history = acceptance_fixture._history(supervisor, "execution_node_v1", execution_id)
        pre_transition, producer = execution_history[-2:]
        reviewer = acceptance_fixture._reviewer(producer)
        evidence = acceptance_fixture._evidence(result_raw, reviewer)
        binding = by_type[WORK_DISPATCH_BINDING_V1][0]
        binding_raw = acceptance_fixture._thaw(binding.payload)
        binding_item = acceptance_fixture._recorded_item(
            supervisor, WORK_DISPATCH_BINDING_V1, "binding_id", binding_raw["binding_id"],
            object_key="registered-dispatch",
        )
        objects = [
            acceptance_fixture._as_invariant(by_type["task_revision_v1"][0], task["task_revision_id"], 1),
            acceptance_fixture._as_invariant(by_type["work_packet_v1"][0], packet["packet_id"], 2),
            binding_item, *history, result_item, disposition_item, pre_transition, producer,
            reviewer, evidence,
        ]
        _, _, manifest, _ = work_result.registration._work_bundle(supervisor)
        projection = acceptance_fixture._projection(objects, (history[-1],))
        context_bytes = canonical_company_json_bytes(manifest)
        candidate = build_engineering_acceptance_candidate(
            projection, task_revision_id=task["task_revision_id"], packet_id=packet["packet_id"],
            dispatch_request_id="registered-dispatch", dispatch_binding_id=binding_raw["binding_id"],
            result_receipt_id=result_id, context_manifest_bytes=context_bytes,
            dispatch_revision_history=history, pre_transition_execution=pre_transition,
        )
        candidate_witness_max = acceptance_fixture._candidate_witness_max_sequence(candidate)
        start = build_dispatch_accepted_mark(
            acceptance_fixture._thaw(history[0].payload), binding_raw,
            observer_service_id="synthetic-observer",
            observer_process_incarnation_id="synthetic-process", clock_domain_id="python_monotonic_ns",
            clock_generation=0, clock_resolution_ns=100, transaction_receipt_sha256="c" * 64,
            global_sequence=11, event_id="synthetic-stage-first-start",
            commit_observation="newly_committed", pre_tick=10, pre_monotonic_ns=1000,
            post_tick=11, post_monotonic_ns=1100,
        )
        for invalid_sequence in (candidate_witness_max - 1, candidate_witness_max):
            with pytest.raises(StageSpanError, match="strictly follow every embedded witness"):
                build_engineering_acceptance_candidate_receipt_sealed_mark(
                    candidate, observer_service_id="synthetic-observer",
                    observer_process_incarnation_id="synthetic-process",
                    clock_domain_id="python_monotonic_ns", clock_generation=0,
                    clock_resolution_ns=100, transaction_id="synthetic-stage-stale-end-tx",
                    transaction_receipt_sha256="d" * 64, global_sequence=invalid_sequence,
                    event_id=f"synthetic-stage-stale-end-{invalid_sequence}",
                    commit_observation="newly_committed", pre_tick=12,
                    pre_monotonic_ns=1200, post_tick=13, post_monotonic_ns=1300,
                    projection=projection, context_manifest_bytes=context_bytes,
                )
        with pytest.raises(StageSpanError, match="global_sequence is invalid"):
            build_engineering_acceptance_candidate_receipt_sealed_mark(
                candidate, observer_service_id="synthetic-observer",
                observer_process_incarnation_id="synthetic-process",
                clock_domain_id="python_monotonic_ns", clock_generation=0,
                clock_resolution_ns=100, transaction_id="synthetic-stage-malformed-end-tx",
                transaction_receipt_sha256="d" * 64, global_sequence=True,
                event_id="synthetic-stage-malformed-end",
                commit_observation="newly_committed", pre_tick=12,
                pre_monotonic_ns=1200, post_tick=13, post_monotonic_ns=1300,
                projection=projection, context_manifest_bytes=context_bytes,
            )
        end = build_engineering_acceptance_candidate_receipt_sealed_mark(
            candidate, observer_service_id="synthetic-observer",
            observer_process_incarnation_id="synthetic-process", clock_domain_id="python_monotonic_ns",
            clock_generation=0, clock_resolution_ns=100, transaction_id="synthetic-stage-end-tx",
            transaction_receipt_sha256="d" * 64, global_sequence=candidate_witness_max + 1,
            event_id="synthetic-stage-end", commit_observation="newly_committed",
            pre_tick=12, pre_monotonic_ns=1200, post_tick=13, post_monotonic_ns=1300,
            projection=projection, context_manifest_bytes=context_bytes,
        )
        identity, _, _ = work_result.lifecycle._rtl(supervisor)
        supervisor.enqueue_department_dispatch(
            identity["department_id"], transaction_id="other-enqueue-transaction",
            command_id="other-enqueue-command", dispatch_request_id="other-dispatch",
            reservation_id="other-reservation", task_id=task["task_id"], packet_id=packet["packet_id"],
            route_policy_id="other-route", requested_role="rtl_lead",
            requested_capability_tier="standard", requested_at="2026-07-27T00:08:00Z",
            recorded_at="2026-07-27T00:09:00Z",
        )
        other_request = acceptance_fixture._thaw(next(
            item.payload for item in supervisor.objects(contract_type=DISPATCH_REQUEST_V1)
            if item.payload["dispatch_request_id"] == "other-dispatch"
        ))
        other_binding = acceptance_fixture._thaw(next(
            item.payload for item in supervisor.objects(contract_type=WORK_DISPATCH_BINDING_V1)
            if item.payload["dispatch_request_id"] == "other-dispatch"
        ))
        other_start = build_dispatch_accepted_mark(
            other_request, other_binding, observer_service_id="synthetic-observer",
            observer_process_incarnation_id="synthetic-process", clock_domain_id="python_monotonic_ns",
            clock_generation=0, clock_resolution_ns=100, transaction_receipt_sha256="e" * 64,
            global_sequence=13, event_id="synthetic-stage-other-start",
            commit_observation="newly_committed", pre_tick=14, pre_monotonic_ns=1400,
            post_tick=15, post_monotonic_ns=1500,
        )
        assert derive_stage_span(
            start, end, candidate=candidate, projection=projection,
            context_manifest_bytes=context_bytes,
        ).cohort_state == "candidate_acceptance_endpoint"
        cursor_bypass_end = _build_mark(**{
            key: value for key, value in end._asdict().items()
            if key not in {"mark_id", "mark_sha256"}
        } | {"global_sequence": candidate_witness_max})
        with pytest.raises(StageSpanError, match="strictly follow every embedded witness"):
            derive_stage_span(
                start, cursor_bypass_end, candidate=candidate, projection=projection,
                context_manifest_bytes=context_bytes,
            )
        with pytest.raises(StageSpanError, match="start candidate dispatch lineage differs"):
            derive_stage_span(
                other_start, end, candidate=candidate, projection=projection,
                context_manifest_bytes=context_bytes,
            )
        cross_wired_end = _build_mark(**{
            key: value for key, value in end._asdict().items()
            if key not in {"mark_id", "mark_sha256"}
        } | {
            "dispatch_request_id": other_start.dispatch_request_id,
            "dispatch_payload_sha256": other_start.dispatch_payload_sha256,
            "origin_dispatch_revision_id": other_start.origin_dispatch_revision_id,
            "origin_dispatch_payload_sha256": other_start.origin_dispatch_payload_sha256,
            "binding_id": other_start.binding_id, "binding_sha256": other_start.binding_sha256,
        })
        with pytest.raises(StageSpanError, match="end candidate dispatch lineage differs"):
            derive_stage_span(
                start, cross_wired_end, candidate=candidate, projection=projection,
                context_manifest_bytes=context_bytes,
            )
    finally:
        supervisor.close()
