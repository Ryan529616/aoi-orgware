from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from typing import Any

from aoi_orgware.ic_rag import ICRagDocumentV1
from aoi_orgware.semantic_events import canonical_json_bytes
from aoi_orgware.semantic_workflow import (
    SemanticWorkflowError,
    compile_workflow_transition,
    derive_workflow_view,
    parse_workflow_request_bytes,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
STAMP = "2026-08-11T07:00:00+00:00"


def document(kind: str, index: int) -> ICRagDocumentV1:
    authority = {
        "project_graph": "project_design_intent",
        "ic_knowledge_base": "reviewed_reference",
        "eda_runbook": "operational_guidance",
    }[kind]
    text = f"RTL compile runtime numeric evidence for source {kind}."
    return ICRagDocumentV1(
        source_id=f"source-{index}",
        source_kind=kind,
        authority=authority,
        source_generation_sha256=hashlib.sha256(f"generation-{index}".encode()).hexdigest(),
        freshness="fresh",
        freshness_checked_at="2026-08-11T06:00:00+00:00",
        freshness_evidence_sha256=hashlib.sha256(f"fresh-{index}".encode()).hexdigest(),
        document_id=f"document-{index}",
        locator=f"docs/source-{index}.md",
        content_sha256=hashlib.sha256(text.encode()).hexdigest(),
        content_size_bytes=len(text.encode()),
        text=text,
    )


DOCUMENTS = tuple(
    document(kind, index)
    for index, kind in enumerate(
        ("project_graph", "ic_knowledge_base", "eda_runbook"), start=1
    )
)


def base_state() -> dict[str, Any]:
    return {
        "schema_version": 5,
        "task_id": "ic-loop",
        "semantic_write_policy": "explicit_transition_only",
        "revision": 1,
        "checkpoint_revision": 0,
        "checkpoint_required": True,
        "checkpoint_sha256": "",
        "plan_ready": False,
        "plan_sha256": "",
        "phase": "planning",
        "updated_at": STAMP,
    }


def request(operation: str, operation_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operation": operation,
        "task_id": "ic-loop",
        "operation_id": operation_id,
        "payload": payload,
    }


def plan_request() -> dict[str, Any]:
    return request(
        "plan_publish",
        "plan-1",
        {
            "plan_id": "plan-1",
            "plan_sha256": SHA_A,
            "source_manifest_sha256": SHA_B,
            "objective": "Compile a tiny IC fixture and preserve stage truth.",
            "query": "RTL compile runtime numeric evidence",
        },
    )


def claim_request(claim_id: str = "rtl-claim") -> dict[str, Any]:
    return request(
        "claim_create",
        f"create-{claim_id}",
        {
            "claim_id": claim_id,
            "locks": ["external:tree:/tmp/aoi-ic-pack"],
            "intent": "Own the isolated IC Pack output root.",
            "validation": "Canonical log and manifest hashes must match.",
        },
    )


def rtl_packet_request() -> dict[str, Any]:
    command = "printf tiny\n"
    return request(
        "packet_create",
        "packet-rtl-create",
        {
            "packet_id": "packet-rtl",
            "role": "rtl",
            "mode": "exact_command",
            "parent_packet_id": None,
            "claim_ids": ["rtl-claim"],
            "canonical_command": command,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
        },
    )


def dv_packet_request() -> dict[str, Any]:
    return request(
        "packet_create",
        "packet-dv-create",
        {
            "packet_id": "packet-dv",
            "role": "dv",
            "mode": "read_only",
            "parent_packet_id": "packet-rtl",
            "claim_ids": [],
            "canonical_command": None,
            "command_sha256": None,
        },
    )


def job_queue_request() -> dict[str, Any]:
    return request(
        "external_job_queue",
        "job-queue-1",
        {
            "job_id": "job-1",
            "run_id": "run-1",
            "packet_id": "packet-rtl",
            "source_sha256": SHA_B,
            "tool_sha256": SHA_C,
            "output_lock": "external:tree:/tmp/aoi-ic-pack/run-1",
        },
    )


def observation(
    stage: str,
    status: str,
    effect: str,
    *,
    operation_id: str | None = None,
    oracle: dict[str, Any] | None = None,
    reconcile_id: str | None = None,
) -> dict[str, Any]:
    return request(
        "external_job_observe",
        operation_id or f"observe-{stage}",
        {
            "job_id": "job-1",
            "stage": stage,
            "stage_status": status,
            "evidence_sha256": hashlib.sha256(f"{stage}-{status}".encode()).hexdigest(),
            "oracle_receipt": oracle,
            "terminal_effect": effect,
            "reconcile_id": reconcile_id,
        },
    )


def oracle_receipt(evidence_sha256: str, **changes: Any) -> dict[str, Any]:
    command_sha256 = hashlib.sha256("printf tiny\n".encode()).hexdigest()
    value: dict[str, Any] = {
        "schema_version": 1,
        "oracle_id": "oracle-1",
        "job_id": "job-1",
        "run_id": "run-1",
        "rtl_packet_id": "packet-rtl",
        "dv_packet_id": "packet-dv",
        "source_sha256": SHA_B,
        "tool_sha256": SHA_C,
        "command_sha256": command_sha256,
        "numeric_evidence_sha256": evidence_sha256,
        "outcome": "pass",
        "mismatch_count": 0,
        "authority": "caller_supplied_digest_bound_not_ledger_or_eda_authority",
    }
    value.update(changes)
    value["receipt_sha256"] = hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


class WorkflowBuilder:
    def __init__(self) -> None:
        self.state = base_state()

    def apply(
        self,
        value: dict[str, Any],
        *,
        documents: tuple[ICRagDocumentV1, ...] | None = None,
        expected_head: str | None = None,
    ) -> Any:
        result = compile_workflow_transition(
            self.state,
            value,
            recorded_at=STAMP,
            rag_documents=documents,
            expected_semantic_head_sha256=expected_head,
        )
        self.state = result.result_state
        return result

    def through_launch(self) -> None:
        self.apply(plan_request(), documents=DOCUMENTS)
        self.apply(claim_request())
        self.apply(rtl_packet_request())
        self.apply(dv_packet_request())
        self.apply(job_queue_request())
        self.apply(request("external_job_launch", "job-launch-1", {"job_id": "job-1"}))


class SemanticWorkflowTests(unittest.TestCase):
    def test_complete_loop_preserves_distinct_rtl_and_dv_context(self) -> None:
        flow = WorkflowBuilder()
        flow.through_launch()
        for stage in ("preflight", "compile", "elaboration", "runtime"):
            flow.apply(observation(stage, "pass", "active"))
        numeric_sha = hashlib.sha256(b"numeric-pass").hexdigest()
        flow.apply(
            observation(
                "numeric", "pass", "completed", oracle=oracle_receipt(numeric_sha)
            )
        )
        verification = flow.apply(
            request(
                "verification_record",
                "verify-1",
                {
                    "verification_id": "verify-1",
                    "packet_id": "packet-dv",
                    "job_id": "job-1",
                    "outcome": "accepted",
                    "evidence_sha256": SHA_C,
                    "query": "RTL compile runtime numeric evidence",
                },
            ),
            documents=DOCUMENTS,
        )
        result = flow.apply(
            request(
                "checkpoint_record",
                "checkpoint-1",
                {
                    "checkpoint_id": "checkpoint-1",
                    "job_id": "job-1",
                    "verification_id": "verify-1",
                    "summary_sha256": SHA_A,
                    "worktree_sha256": SHA_B,
                    "expected_semantic_head_sha256": SHA_D,
                },
            ),
            expected_head=SHA_D,
        )
        view = derive_workflow_view(result.result_state)
        self.assertEqual(view, result.workflow_view)
        self.assertEqual(view["external_jobs"][0]["status"], "completed")
        self.assertEqual([row["stage"] for row in view["external_jobs"][0]["stage_evidence"]], list(("preflight", "compile", "elaboration", "runtime", "numeric")))
        self.assertEqual(view["verifications"][0]["outcome"], "accepted")
        self.assertEqual(view["plan"]["context_receipt"]["audience"], "rtl")
        self.assertEqual(
            verification.workflow_view["verifications"][0]["context_receipt"]["audience"],
            "dv",
        )
        self.assertNotEqual(
            view["plan"]["context_receipt_sha256"],
            view["verifications"][0]["context_receipt_sha256"],
        )
        self.assertFalse(result.result_state["checkpoint_required"])

    def test_effect_unknown_blocks_relaunch_and_requires_blocked_review(self) -> None:
        flow = WorkflowBuilder()
        flow.through_launch()
        flow.apply(
            observation(
                "preflight",
                "inconclusive",
                "effect_unknown",
                reconcile_id="reconcile-run-1",
            )
        )
        with self.assertRaisesRegex(SemanticWorkflowError, "single launch"):
            flow.apply(request("external_job_launch", "launch-again", {"job_id": "job-1"}))
        replacement = job_queue_request()
        replacement["operation_id"] = "queue-replacement"
        replacement["payload"]["job_id"] = "job-2"
        replacement["payload"]["run_id"] = "run-2"
        with self.assertRaisesRegex(SemanticWorkflowError, "immutable job"):
            flow.apply(replacement)
        second_packet = rtl_packet_request()
        second_packet["operation_id"] = "packet-rtl-2-create"
        second_packet["payload"]["packet_id"] = "packet-rtl-2"
        flow.apply(second_packet)
        replacement["payload"]["packet_id"] = "packet-rtl-2"
        with self.assertRaisesRegex(SemanticWorkflowError, "already held"):
            flow.apply(replacement)
        blocked = flow.apply(
            request(
                "verification_record",
                "verify-blocked",
                {
                    "verification_id": "verify-blocked",
                    "packet_id": "packet-dv",
                    "job_id": "job-1",
                    "outcome": "blocked",
                    "evidence_sha256": SHA_A,
                    "query": "runtime effect uncertainty evidence",
                },
            ),
            documents=DOCUMENTS,
        )
        self.assertEqual(blocked.workflow_view["external_jobs"][0]["attempt"], 1)
        self.assertEqual(blocked.workflow_view["external_jobs"][0]["effect"], "effect_unknown")

    def test_known_failure_requires_rejected_review(self) -> None:
        flow = WorkflowBuilder()
        flow.through_launch()
        flow.apply(observation("preflight", "pass", "active"))
        flow.apply(observation("compile", "fail", "failed_known"))
        bad = request(
            "verification_record",
            "verify-bad",
            {
                "verification_id": "verify-bad",
                "packet_id": "packet-dv",
                "job_id": "job-1",
                "outcome": "accepted",
                "evidence_sha256": SHA_A,
                "query": "compile failure evidence",
            },
        )
        with self.assertRaisesRegex(SemanticWorkflowError, "overstates"):
            flow.apply(bad, documents=DOCUMENTS)
        bad["payload"]["outcome"] = "rejected"
        result = flow.apply(bad, documents=DOCUMENTS)
        self.assertEqual(result.workflow_view["verifications"][0]["outcome"], "rejected")

    def test_claim_overlap_and_release_are_fail_closed(self) -> None:
        flow = WorkflowBuilder()
        flow.apply(plan_request(), documents=DOCUMENTS)
        flow.apply(claim_request())
        overlapping = claim_request("other-claim")
        with self.assertRaisesRegex(SemanticWorkflowError, "overlaps"):
            flow.apply(overlapping)
        flow.apply(
            request(
                "claim_release",
                "release-rtl",
                {"claim_id": "rtl-claim", "reason": "No material launch remains."},
            )
        )
        flow.apply(overlapping)
        dv = dv_packet_request()
        dv["payload"]["parent_packet_id"] = None
        self.assertEqual(len(flow.apply(dv).workflow_view["claims"]), 2)

    def test_nonterminal_job_holds_claim_and_output_requires_one_way_coverage(self) -> None:
        flow = WorkflowBuilder()
        flow.apply(plan_request(), documents=DOCUMENTS)
        flow.apply(claim_request())
        flow.apply(rtl_packet_request())
        too_wide = job_queue_request()
        too_wide["payload"]["output_lock"] = "external:tree:/tmp"
        with self.assertRaisesRegex(SemanticWorkflowError, "outside packet claim"):
            flow.apply(too_wide)
        flow.apply(job_queue_request())
        with self.assertRaisesRegex(SemanticWorkflowError, "held by a nonterminal"):
            flow.apply(
                request(
                    "claim_release",
                    "release-held-claim",
                    {"claim_id": "rtl-claim", "reason": "Unsafe early release."},
                )
            )

    def test_packet_authority_and_command_digest_are_exact(self) -> None:
        flow = WorkflowBuilder()
        flow.apply(plan_request(), documents=DOCUMENTS)
        flow.apply(claim_request())
        bad = rtl_packet_request()
        bad["payload"]["command_sha256"] = SHA_A
        with self.assertRaisesRegex(SemanticWorkflowError, "differs"):
            flow.apply(bad)
        dv = dv_packet_request()
        dv["payload"]["parent_packet_id"] = None
        dv["payload"]["claim_ids"] = ["rtl-claim"]
        with self.assertRaisesRegex(SemanticWorkflowError, "may not hold"):
            flow.apply(dv)

    def test_job_stage_order_numeric_oracle_and_completion_are_exact(self) -> None:
        flow = WorkflowBuilder()
        flow.through_launch()
        with self.assertRaisesRegex(SemanticWorkflowError, "out of order"):
            flow.apply(observation("compile", "pass", "active"))
        for stage in ("preflight", "compile", "elaboration", "runtime"):
            flow.apply(observation(stage, "pass", "active"))
        early = WorkflowBuilder()
        early.through_launch()
        for stage in ("preflight", "compile", "elaboration"):
            early.apply(observation(stage, "pass", "active"))
        with self.assertRaisesRegex(SemanticWorkflowError, "pre-numeric pass"):
            early.apply(observation("runtime", "pass", "completed"))
        with self.assertRaisesRegex(SemanticWorkflowError, "oracle"):
            flow.apply(observation("numeric", "pass", "completed"))
        numeric_sha = hashlib.sha256(b"numeric-pass").hexdigest()
        forged = oracle_receipt(numeric_sha, run_id="run-forged")
        with self.assertRaisesRegex(SemanticWorkflowError, "run_id differs"):
            flow.apply(observation("numeric", "pass", "completed", oracle=forged))
        result = flow.apply(
            observation(
                "numeric", "pass", "completed", oracle=oracle_receipt(numeric_sha)
            )
        )
        self.assertEqual(result.workflow_view["external_jobs"][0]["status"], "completed")

    def test_job_source_and_dv_lineage_bind_plan_and_execution(self) -> None:
        flow = WorkflowBuilder()
        flow.apply(plan_request(), documents=DOCUMENTS)
        flow.apply(claim_request())
        flow.apply(rtl_packet_request())
        wrong_source = job_queue_request()
        wrong_source["payload"]["source_sha256"] = SHA_A
        with self.assertRaisesRegex(SemanticWorkflowError, "published plan"):
            flow.apply(wrong_source)
        flow.apply(dv_packet_request())
        flow.apply(job_queue_request())
        flow.apply(request("external_job_launch", "job-launch-1", {"job_id": "job-1"}))
        flow.apply(observation("preflight", "fail", "failed_known"))
        unrelated = dv_packet_request()
        unrelated["operation_id"] = "packet-dv-unrelated-create"
        unrelated["payload"]["packet_id"] = "packet-dv-unrelated"
        unrelated["payload"]["parent_packet_id"] = None
        flow.apply(unrelated)
        verify = request(
            "verification_record",
            "verify-unrelated",
            {
                "verification_id": "verify-unrelated",
                "packet_id": "packet-dv-unrelated",
                "job_id": "job-1",
                "outcome": "rejected",
                "evidence_sha256": SHA_A,
                "query": "compile failure evidence",
            },
        )
        with self.assertRaisesRegex(SemanticWorkflowError, "RTL child"):
            flow.apply(verify, documents=DOCUMENTS)

    def test_first_workflow_record_may_not_predate_task_state(self) -> None:
        with self.assertRaisesRegex(SemanticWorkflowError, "predates current task"):
            compile_workflow_transition(
                base_state(),
                plan_request(),
                recorded_at="2026-08-10T07:00:00+00:00",
                rag_documents=DOCUMENTS,
            )

    def test_checkpoint_requires_exact_caller_head(self) -> None:
        flow = WorkflowBuilder()
        flow.through_launch()
        flow.apply(observation("preflight", "fail", "failed_known"))
        flow.apply(
            request(
                "verification_record",
                "verify-1",
                {
                    "verification_id": "verify-1",
                    "packet_id": "packet-dv",
                    "job_id": "job-1",
                    "outcome": "rejected",
                    "evidence_sha256": SHA_A,
                    "query": "preflight failure evidence",
                },
            ),
            documents=DOCUMENTS,
        )
        checkpoint = request(
            "checkpoint_record",
            "checkpoint-1",
            {
                "checkpoint_id": "checkpoint-1",
                "job_id": "job-1",
                "verification_id": "verify-1",
                "summary_sha256": SHA_A,
                "worktree_sha256": SHA_B,
                "expected_semantic_head_sha256": SHA_C,
            },
        )
        with self.assertRaisesRegex(SemanticWorkflowError, "caller authority"):
            flow.apply(checkpoint, expected_head=SHA_D)

    def test_existing_record_tamper_and_duplicate_operation_fail(self) -> None:
        flow = WorkflowBuilder()
        first = flow.apply(plan_request(), documents=DOCUMENTS)
        tampered = deepcopy(first.result_state)
        tampered["ic_engineering_v1"]["records"][0]["payload"]["plan_sha256"] = SHA_C
        with self.assertRaisesRegex(SemanticWorkflowError, "digest differs"):
            derive_workflow_view(tampered)
        duplicate = deepcopy(first.result_state)
        duplicate["ic_engineering_v1"]["records"].append(
            deepcopy(duplicate["ic_engineering_v1"]["records"][0])
        )
        with self.assertRaisesRegex(SemanticWorkflowError, "duplicated"):
            derive_workflow_view(duplicate)

    def test_request_parser_rejects_noncanonical_duplicate_huge_and_deep_json(self) -> None:
        canonical = canonical_json_bytes(plan_request())
        self.assertEqual(parse_workflow_request_bytes(canonical), plan_request())
        with self.assertRaises(SemanticWorkflowError):
            parse_workflow_request_bytes(canonical + b"\n")
        with self.assertRaises(SemanticWorkflowError):
            parse_workflow_request_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(SemanticWorkflowError):
            parse_workflow_request_bytes(
                b'{"schema_version":' + b"9" * 5000 + b',"operation":"plan_publish"}'
            )
        deep = b"[" * 1100 + b"0" + b"]" * 1100
        with self.assertRaises(SemanticWorkflowError):
            parse_workflow_request_bytes(deep)

    def test_bool_schema_and_nonsemantic_state_are_rejected(self) -> None:
        value = plan_request()
        value["schema_version"] = True
        with self.assertRaises(SemanticWorkflowError):
            compile_workflow_transition(base_state(), value, recorded_at=STAMP, rag_documents=DOCUMENTS)
        state = base_state()
        state["semantic_write_policy"] = "legacy"
        with self.assertRaisesRegex(SemanticWorkflowError, "explicit-transition"):
            compile_workflow_transition(state, plan_request(), recorded_at=STAMP, rag_documents=DOCUMENTS)


if __name__ == "__main__":
    unittest.main()
