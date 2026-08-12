from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path

from aoi_orgware.ic_pack import (
    canonical_command,
    canonical_json_bytes,
    execute_request,
    fixture_manifest_sha256,
    oracle_to_dict,
    request_bytes,
    synthetic_tool_sha256,
)
from aoi_orgware.ic_pack_worker import derive_worker_receipt
from aoi_orgware.semantic_workflow import derive_workflow_view

from tests.test_ic_pack import make_request
from tests.test_semantic_workflow import (
    DOCUMENTS,
    SHA_A,
    WorkflowBuilder,
    claim_request,
    dv_packet_request,
    job_queue_request,
    plan_request,
    request,
    rtl_packet_request,
)


def setup_workflow(output_root: Path):
    pack_request = make_request(
        output_root,
        task_id="ic-loop",
        source_manifest_sha256=fixture_manifest_sha256(),
        tool_sha256=synthetic_tool_sha256(),
    )
    data = request_bytes(pack_request)
    command = canonical_command(data)
    output_lock = f"host:tree:{output_root.as_posix()}"
    flow = WorkflowBuilder()
    plan = plan_request()
    plan["payload"]["source_manifest_sha256"] = fixture_manifest_sha256()
    flow.apply(plan, documents=DOCUMENTS)
    claim = claim_request()
    claim["payload"]["locks"] = [output_lock]
    flow.apply(claim)
    rtl = rtl_packet_request()
    rtl["payload"]["canonical_command"] = command
    rtl["payload"]["command_sha256"] = hashlib.sha256(command.encode()).hexdigest()
    flow.apply(rtl)
    flow.apply(dv_packet_request())
    queue = job_queue_request()
    queue["payload"]["source_sha256"] = fixture_manifest_sha256()
    queue["payload"]["tool_sha256"] = synthetic_tool_sha256()
    queue["payload"]["output_lock"] = output_lock
    flow.apply(queue)
    flow.apply(request("external_job_launch", "job-launch-1", {"job_id": "job-1"}))
    return flow, pack_request


def test_pack_result_crosses_handoff_into_review_and_checkpoint_once(tmp_path: Path) -> None:
    flow, pack_request = setup_workflow(tmp_path / "pack-run")
    data = request_bytes(pack_request)
    digest = hashlib.sha256(data).hexdigest()
    calls: list[str] = []

    def launch(worker_data: bytes) -> tuple[int, bytes, bytes]:
        calls.append(hashlib.sha256(worker_data).hexdigest())
        return 0, canonical_json_bytes(derive_worker_receipt(pack_request)), b""

    result = execute_request(pack_request, digest, launcher=launch)
    pre_handoff = derive_workflow_view(flow.state)
    successor = WorkflowBuilder()
    successor.state = deepcopy(flow.state)
    for index, stage in enumerate(result.stages):
        terminal = "completed" if stage.stage == "numeric" else "active"
        successor.apply(
            request(
                "external_job_observe",
                f"pack-observe-{index}",
                {
                    "job_id": "job-1",
                    "stage": stage.stage,
                    "stage_status": stage.status,
                    "evidence_sha256": stage.evidence_sha256,
                    "oracle_receipt": (
                        oracle_to_dict(result.oracle_receipt)
                        if stage.stage == "numeric" and result.oracle_receipt is not None
                        else None
                    ),
                    "terminal_effect": terminal,
                    "reconcile_id": None,
                },
            )
        )
    verification = successor.apply(
        request(
            "verification_record",
            "pack-verify-1",
            {
                "verification_id": "pack-verify-1",
                "packet_id": "packet-dv",
                "job_id": "job-1",
                "outcome": "accepted",
                "evidence_sha256": result.terminal_receipt_sha256,
                "query": "synthetic IC fixture stage and oracle evidence",
            },
        ),
        documents=DOCUMENTS,
    )
    successor.apply(
        request(
            "checkpoint_record",
            "pack-checkpoint-1",
            {
                "checkpoint_id": "pack-checkpoint-1",
                "job_id": "job-1",
                "verification_id": "pack-verify-1",
                "summary_sha256": result.terminal_receipt_sha256,
                "worktree_sha256": fixture_manifest_sha256(),
                "expected_semantic_head_sha256": SHA_A,
            },
        ),
        expected_head=SHA_A,
    )
    replay = execute_request(pack_request, digest, launcher=launch)
    post = derive_workflow_view(successor.state)
    assert calls == [digest]
    assert replay.idempotent_replay is True
    assert pre_handoff["external_jobs"][0]["job_id"] == post["external_jobs"][0]["job_id"]
    assert pre_handoff["external_jobs"][0]["run_id"] == post["external_jobs"][0]["run_id"]
    assert post["external_jobs"][0]["status"] == "completed"
    assert verification.workflow_view["verifications"][0]["outcome"] == "accepted"
    assert post["checkpoints"][0]["job_id"] == "job-1"


def test_unknown_pack_effect_survives_handoff_and_replay_without_launch(tmp_path: Path) -> None:
    flow, pack_request = setup_workflow(tmp_path / "pack-unknown")
    digest = hashlib.sha256(request_bytes(pack_request)).hexdigest()
    calls = 0

    def uncertain(_: bytes) -> tuple[int, bytes, bytes]:
        nonlocal calls
        calls += 1
        raise TimeoutError("terminal channel unavailable")

    result = execute_request(pack_request, digest, launcher=uncertain)
    successor = WorkflowBuilder()
    successor.state = deepcopy(flow.state)
    successor.apply(
        request(
            "external_job_observe",
            "pack-effect-unknown",
            {
                "job_id": "job-1",
                "stage": "preflight",
                "stage_status": "inconclusive",
                "evidence_sha256": hashlib.sha256(result.launch_id.encode()).hexdigest(),
                "oracle_receipt": None,
                "terminal_effect": "effect_unknown",
                "reconcile_id": "pack-run-1-reconcile",
            },
        )
    )
    replay = execute_request(pack_request, digest, launcher=uncertain)
    job = derive_workflow_view(successor.state)["external_jobs"][0]
    assert calls == 1
    assert result.terminal_effect == replay.terminal_effect == "effect_unknown"
    assert replay.idempotent_replay is True
    assert job["job_id"] == "job-1"
    assert job["run_id"] == "run-1"
    assert job["effect"] == "effect_unknown"
