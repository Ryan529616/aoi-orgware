#!/usr/bin/env python3
"""Focused contracts for persisted O8 integrity records."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import integrity_records as ir  # noqa: E402
from aoi_orgware.harnesslib import HarnessError, validate_task_state  # noqa: E402


H = {
    "base": "0" * 40,
    "candidate_head": "1" * 40,
    "post_fix_head": "2" * 40,
    "candidate": "a" * 64,
    "claim": "b" * 64,
    "review_artifact": "c" * 64,
    "finding_artifact": "d" * 64,
    "post_fix": "e" * 64,
    "post_fix_claim": "f" * 64,
    "fix_artifact": "3" * 64,
    "verification_artifact": "4" * 64,
}
TASK_ID = "task-1"
WORKTREE = "/work/aoi"
ADOPTED_AT = "2026-07-19T10:00:00+00:00"


def artifact(name: str, digest: str) -> dict[str, object]:
    return ir.build_artifact_ref(path=f"evidence/{name}", sha256=digest, size_bytes=12)


def candidate() -> dict[str, object]:
    return ir.build_snapshot_record(
        task_id=TASK_ID,
        worktree=WORKTREE,
        baseline_head=H["base"],
        current_head=H["candidate_head"],
        artifact=artifact("candidate.json", H["candidate"]),
        snapshot_sha256=H["candidate"],
        claim_scope_sha256=H["claim"],
        covered_claim_tokens=["claim-1"],
        purpose="candidate",
        producer_agent_ids=["producer"],
    )


def post_fix() -> dict[str, object]:
    return ir.build_snapshot_record(
        task_id=TASK_ID,
        worktree=WORKTREE,
        baseline_head=H["base"],
        current_head=H["post_fix_head"],
        artifact=artifact("post-fix.json", H["post_fix"]),
        snapshot_sha256=H["post_fix"],
        claim_scope_sha256=H["post_fix_claim"],
        covered_claim_tokens=["claim-1"],
        purpose="post_fix",
        producer_agent_ids=["fixer"],
    )


def append(contract: dict[str, object], collection: str, record: dict[str, object]) -> dict[str, object]:
    return ir.append_integrity_record(contract, collection, record)


def complete_contract(*, with_finding: bool = False, sealed: bool = False) -> dict[str, object]:
    contract: dict[str, object] = ir.build_integrity_contract(
        baseline_head=H["base"], adopted_at=ADOPTED_AT
    )
    source = candidate()
    contract = append(contract, "snapshots", source)
    review = ir.build_review_result_record(
        snapshot_sha256=H["candidate"],
        reviewer_agent_id="reviewer",
        producer_agent_ids=["producer"],
        result_artifact=artifact("review.md", H["review_artifact"]),
        outcome="findings" if with_finding else "clean",
        finding_ids=["finding-1"] if with_finding else [],
    )
    contract = append(contract, "review_results", review)
    if with_finding:
        finding = ir.build_finding_record(
            finding_id="finding-1",
            review_result_record_sha256=review["record_sha256"],
            snapshot_sha256=H["candidate"],
            reviewer_agent_id="reviewer",
            finding_artifact_sha256=H["review_artifact"],
        )
        contract = append(contract, "findings", finding)
        fixed = post_fix()
        contract = append(contract, "snapshots", fixed)
        fix = ir.build_fix_record(
            finding_id="finding-1",
            finding_record_sha256=finding["record_sha256"],
            post_fix_snapshot_sha256=H["post_fix"],
            fix_artifact=artifact("fix.md", H["fix_artifact"]),
            producer_agent_ids=["fixer"],
        )
        contract = append(contract, "fixes", fix)
        verification = ir.build_review_verification_record(
            finding_id="finding-1",
            fix_record_sha256=fix["record_sha256"],
            snapshot_sha256=H["post_fix"],
            reviewer_agent_id="verifier",
            verification_artifact=artifact("verify.md", H["verification_artifact"]),
            outcome="pass",
        )
        contract = append(contract, "review_verifications", verification)
    if sealed:
        seal = ir.build_integrity_seal(
            latest_candidate_snapshot_sha256=H["candidate"],
            latest_review_result_record_sha256=review["record_sha256"],
            claim_scope_sha256=H["claim"],
            sealed_at="2026-07-19T11:00:00+00:00",
        )
        contract = ir.seal_integrity_contract(contract, seal)
    return contract


class IntegrityRecordTests(unittest.TestCase):
    def test_codex_canonical_agent_ids_are_bound_without_relaxing_tokens(self) -> None:
        snapshot = ir.build_snapshot_record(
            task_id=TASK_ID,
            worktree=WORKTREE,
            baseline_head=H["base"],
            current_head=H["candidate_head"],
            artifact=artifact("canonical-agent.json", H["candidate"]),
            snapshot_sha256=H["candidate"],
            claim_scope_sha256=H["claim"],
            covered_claim_tokens=["claim-1"],
            purpose="candidate",
            producer_agent_ids=["/root/implementer"],
        )
        review = ir.build_review_result_record(
            snapshot_sha256=H["candidate"],
            reviewer_agent_id="/root/independent/reviewer",
            producer_agent_ids=snapshot["producer_agent_ids"],
            result_artifact=artifact("canonical-agent-review.md", H["review_artifact"]),
            outcome="clean",
            finding_ids=[],
        )
        self.assertEqual(snapshot["producer_agent_ids"], ["/root/implementer"])
        self.assertEqual(review["reviewer_agent_id"], "/root/independent/reviewer")
        self.assertEqual(
            ir.validate_agent_id("operator@example.invalid"),
            "operator@example.invalid",
        )

        for invalid in ("", "agent identity", "agent\nidentity", "a" * 513):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ir.IntegrityRecordError, "1-512 ASCII"
            ):
                ir.validate_agent_id(invalid)
        with self.assertRaisesRegex(ir.IntegrityRecordError, "task_id"):
            ir.build_snapshot_record(
                task_id="/root/not-a-task-id",
                worktree=WORKTREE,
                baseline_head=H["base"],
                current_head=H["candidate_head"],
                artifact=artifact("invalid-task.json", H["candidate"]),
                snapshot_sha256=H["candidate"],
                claim_scope_sha256=H["claim"],
                covered_claim_tokens=[],
                purpose="candidate",
                producer_agent_ids=["/root/implementer"],
            )

    def test_canonical_agent_ids_cover_full_finding_fix_verification_chain(self) -> None:
        boundary = "/" + "a" * 511
        self.assertEqual(ir.validate_agent_id(boundary), boundary)
        with self.assertRaisesRegex(ir.IntegrityRecordError, "1-512"):
            ir.validate_agent_id("/" + "a" * 512)

        contract = ir.build_integrity_contract(
            baseline_head=H["base"], adopted_at=ADOPTED_AT
        )
        source = ir.build_snapshot_record(
            task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"],
            current_head=H["candidate_head"],
            artifact=artifact("canonical-chain.json", H["candidate"]),
            snapshot_sha256=H["candidate"], claim_scope_sha256=H["claim"],
            covered_claim_tokens=["claim-1"], purpose="candidate",
            producer_agent_ids=[boundary],
        )
        contract = append(contract, "snapshots", source)
        review = ir.build_review_result_record(
            snapshot_sha256=H["candidate"],
            reviewer_agent_id="/root/reviewer",
            producer_agent_ids=[boundary],
            result_artifact=artifact("canonical-review.md", H["review_artifact"]),
            outcome="findings", finding_ids=["finding-1"],
        )
        contract = append(contract, "review_results", review)
        finding = ir.build_finding_record(
            finding_id="finding-1", review_result_record_sha256=review["record_sha256"],
            snapshot_sha256=H["candidate"], reviewer_agent_id="/root/reviewer",
            finding_artifact_sha256=H["review_artifact"],
        )
        contract = append(contract, "findings", finding)
        fixed = ir.build_snapshot_record(
            task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"],
            current_head=H["post_fix_head"],
            artifact=artifact("canonical-post-fix.json", H["post_fix"]),
            snapshot_sha256=H["post_fix"], claim_scope_sha256=H["post_fix_claim"],
            covered_claim_tokens=["claim-1"], purpose="post_fix",
            producer_agent_ids=["/root/fixer"],
        )
        contract = append(contract, "snapshots", fixed)
        fix = ir.build_fix_record(
            finding_id="finding-1", finding_record_sha256=finding["record_sha256"],
            post_fix_snapshot_sha256=H["post_fix"],
            fix_artifact=artifact("canonical-fix.md", H["fix_artifact"]),
            producer_agent_ids=["/root/fixer"],
        )
        contract = append(contract, "fixes", fix)
        verification = ir.build_review_verification_record(
            finding_id="finding-1", fix_record_sha256=fix["record_sha256"],
            snapshot_sha256=H["post_fix"], reviewer_agent_id="/root/verifier",
            verification_artifact=artifact(
                "canonical-verification.md", H["verification_artifact"]
            ), outcome="pass",
        )
        contract = append(contract, "review_verifications", verification)
        sealed = ir.seal_integrity_contract(
            contract,
            ir.build_integrity_seal(
                latest_candidate_snapshot_sha256=H["candidate"],
                latest_review_result_record_sha256=review["record_sha256"],
                claim_scope_sha256=H["claim"],
                sealed_at="2026-07-19T11:00:00+00:00",
            ),
        )
        self.assertEqual(ir.integrity_contract_errors(sealed, require_complete=True), [])

    def test_zero_finding_review_is_required_and_sealable(self) -> None:
        contract = ir.build_integrity_contract(baseline_head=H["base"], adopted_at=ADOPTED_AT)
        contract = append(contract, "snapshots", candidate())
        self.assertEqual(ir.integrity_contract_errors(contract), [])
        self.assertIn(
            "candidate snapshot lacks mandatory review result",
            ir.integrity_contract_errors(contract, require_complete=True),
        )
        complete = complete_contract(sealed=True)
        self.assertEqual(ir.integrity_contract_errors(complete), [])

    def test_tampered_record_and_task_binding_fail_closed(self) -> None:
        contract = complete_contract()
        contract["snapshots"][0]["current_head"] = H["post_fix_head"]  # type: ignore[index]
        errors = ir.integrity_contract_errors(contract)
        self.assertTrue(any("record_sha256" in error for error in errors), errors)

        valid = complete_contract()
        errors = ir.integrity_contract_errors(valid, task_id="other-task", worktree=WORKTREE)
        self.assertIn("snapshot task_id differs from task state", errors)

    def test_zero_mutation_snapshot_allows_empty_claim_coverage_only(self) -> None:
        zero_mutation = ir.build_snapshot_record(
            task_id=TASK_ID,
            worktree=WORKTREE,
            baseline_head=H["base"],
            current_head=H["candidate_head"],
            artifact=artifact("zero-mutation.json", H["candidate"]),
            snapshot_sha256=H["candidate"],
            claim_scope_sha256=H["claim"],
            covered_claim_tokens=[],
            purpose="candidate",
            producer_agent_ids=["producer"],
        )
        self.assertEqual(zero_mutation["covered_claim_tokens"], [])
        contract = ir.build_integrity_contract(baseline_head=H["base"], adopted_at=ADOPTED_AT)
        contract = append(contract, "snapshots", zero_mutation)
        review = ir.build_review_result_record(
            snapshot_sha256=H["candidate"],
            reviewer_agent_id="reviewer",
            producer_agent_ids=["producer"],
            result_artifact=artifact("zero-mutation-review.md", H["review_artifact"]),
            outcome="clean",
            finding_ids=[],
        )
        contract = append(contract, "review_results", review)
        sealed = ir.seal_integrity_contract(
            contract,
            ir.build_integrity_seal(
                latest_candidate_snapshot_sha256=H["candidate"],
                latest_review_result_record_sha256=review["record_sha256"],
                claim_scope_sha256=H["claim"],
                sealed_at="2026-07-19T11:00:00+00:00",
            ),
        )
        self.assertEqual(ir.integrity_contract_errors(sealed, require_complete=True), [])
        with self.assertRaisesRegex(ir.IntegrityRecordError, "sorted and unique"):
            ir.build_snapshot_record(
                task_id=TASK_ID,
                worktree=WORKTREE,
                baseline_head=H["base"],
                current_head=H["candidate_head"],
                artifact=artifact("noncanonical.json", H["candidate"]),
                snapshot_sha256=H["candidate"],
                claim_scope_sha256=H["claim"],
                covered_claim_tokens=["claim-2", "claim-1"],
                purpose="candidate",
                producer_agent_ids=["producer"],
            )

    def test_self_review_is_rejected_for_result_and_verification(self) -> None:
        with self.assertRaisesRegex(ir.IntegrityRecordError, "self-review"):
            ir.build_review_result_record(
                snapshot_sha256=H["candidate"],
                reviewer_agent_id="producer",
                producer_agent_ids=["producer"],
                result_artifact=artifact("review.md", H["review_artifact"]),
                outcome="clean",
                finding_ids=[],
            )
        contract = complete_contract(with_finding=True)
        contract["review_verifications"][0]["reviewer_agent_id"] = "fixer"  # type: ignore[index]
        contract["review_verifications"][0]["record_sha256"] = ir.integrity_record_sha256(  # type: ignore[index]
            contract["review_verifications"][0]
        )
        self.assertTrue(
            any("self-review" in error for error in ir.integrity_contract_errors(contract))
        )

    def test_stale_candidate_review_is_rejected(self) -> None:
        contract = complete_contract()
        fresh = copy.deepcopy(candidate())
        fresh["current_head"] = "5" * 40
        fresh["snapshot_sha256"] = "6" * 64
        fresh["artifact"]["sha256"] = "7" * 64
        fresh["record_sha256"] = ir.integrity_record_sha256(fresh)
        contract = append(contract, "snapshots", fresh)
        errors = ir.integrity_contract_errors(contract, require_complete=True)
        self.assertIn("candidate snapshot lacks mandatory review result", errors)

    def test_finding_fix_verification_hash_chain_and_seal(self) -> None:
        contract = complete_contract(with_finding=True, sealed=True)
        self.assertEqual(ir.integrity_contract_errors(contract), [])
        tampered = copy.deepcopy(contract)
        tampered["review_verifications"][0]["fix_record_sha256"] = "8" * 64  # type: ignore[index]
        tampered["review_verifications"][0]["record_sha256"] = ir.integrity_record_sha256(  # type: ignore[index]
            tampered["review_verifications"][0]
        )
        errors = ir.integrity_contract_errors(tampered)
        self.assertTrue(any("hash chain" in error for error in errors), errors)

        stale_seal = copy.deepcopy(contract)
        stale_seal["seal"]["claim_scope_sha256"] = H["post_fix_claim"]  # type: ignore[index]
        stale_seal["seal"]["record_sha256"] = ir.integrity_record_sha256(stale_seal["seal"])  # type: ignore[index]
        self.assertIn("seal does not bind latest candidate claim scope", ir.integrity_contract_errors(stale_seal))

    def test_finding_must_bind_its_review_artifact(self) -> None:
        contract = complete_contract(with_finding=True)
        finding = contract["findings"][0]
        finding["finding_artifact_sha256"] = H["finding_artifact"]
        finding["record_sha256"] = ir.integrity_record_sha256(finding)
        errors = ir.integrity_contract_errors(contract, require_complete=True)
        self.assertIn("finding finding-1 lost review binding", errors)

    def test_latest_verification_outcome_and_duplicate_sha_fail_closed(self) -> None:
        contract = complete_contract(with_finding=True)
        passed = contract["review_verifications"][0]
        failed = ir.build_review_verification_record(
            finding_id="finding-1",
            fix_record_sha256=passed["fix_record_sha256"],
            snapshot_sha256=H["post_fix"],
            reviewer_agent_id="verifier-2",
            verification_artifact=artifact("verify-later-fail.md", "5" * 64),
            outcome="fail",
        )
        contract = append(contract, "review_verifications", failed)
        self.assertIn(
            "finding finding-1 latest fix is not resolved by a passing verification",
            ir.integrity_contract_errors(contract, require_complete=True),
        )
        later_pass = ir.build_review_verification_record(
            finding_id="finding-1",
            fix_record_sha256=passed["fix_record_sha256"],
            snapshot_sha256=H["post_fix"],
            reviewer_agent_id="verifier-3",
            verification_artifact=artifact("verify-later-pass.md", "6" * 64),
            outcome="pass",
        )
        contract = append(contract, "review_verifications", later_pass)
        contract = ir.seal_integrity_contract(
            contract,
            ir.build_integrity_seal(
                latest_candidate_snapshot_sha256=H["candidate"],
                latest_review_result_record_sha256=contract["review_results"][0]["record_sha256"],
                claim_scope_sha256=H["claim"],
                sealed_at="2026-07-19T12:00:00+00:00",
            ),
        )
        self.assertEqual(ir.integrity_contract_errors(contract, require_complete=True), [])
        duplicate = copy.deepcopy(later_pass)
        contract["review_verifications"].append(duplicate)
        self.assertIn(
            "duplicate review_verification record_sha256",
            ir.integrity_contract_errors(contract, require_complete=True),
        )

    def test_bounds_and_legacy_task_loading(self) -> None:
        with self.assertRaisesRegex(ir.IntegrityRecordError, "exceeds 1024"):
            ir.build_snapshot_record(
                task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"], current_head=H["candidate_head"],
                artifact=artifact("candidate.json", H["candidate"]), snapshot_sha256=H["candidate"],
                claim_scope_sha256=H["claim"], covered_claim_tokens=[f"claim-{index}" for index in range(1025)],
                purpose="candidate", producer_agent_ids=["producer"],
            )
        state = {
            "schema_version": 1, "profile_id": "test", "config_sha256": "a" * 64,
            "task_id": TASK_ID, "status": "active", "phase": "planning", "profile": "full",
            "revision": 1, "checkpoint_revision": 0,
        }
        validate_task_state(state)
        adopted = ir.adopt_integrity_contract(state, baseline_head=H["base"], adopted_at=ADOPTED_AT)
        adopted["worktree"] = WORKTREE
        validate_task_state(adopted)
        adopted["integrity_contract"] = complete_contract()
        validate_task_state(adopted)
        adopted["integrity_contract"]["mode"] = "optional"  # type: ignore[index]
        with self.assertRaisesRegex(HarnessError, "integrity contract"):
            validate_task_state(adopted)

    def test_draft_loads_before_review_but_close_requires_completion(self) -> None:
        state = {
            "schema_version": 1, "profile_id": "test", "config_sha256": "a" * 64,
            "task_id": TASK_ID, "status": "active", "phase": "planning", "profile": "full",
            "revision": 1, "checkpoint_revision": 0, "worktree": WORKTREE,
        }
        state = ir.adopt_integrity_contract(state, baseline_head=H["base"], adopted_at=ADOPTED_AT)
        state["integrity_contract"] = append(state["integrity_contract"], "snapshots", candidate())
        validate_task_state(state)
        state["phase"] = "closing"
        with self.assertRaisesRegex(HarnessError, "mandatory review"):
            validate_task_state(state)

    def test_artifact_cap_and_latest_fix_attempt_resolution(self) -> None:
        self.assertEqual(
            ir.build_artifact_ref(
                path="evidence/large.bin",
                sha256=H["candidate"],
                size_bytes=ir.MAX_INTEGRITY_ARTIFACT_BYTES,
            )["size_bytes"],
            ir.MAX_INTEGRITY_ARTIFACT_BYTES,
        )
        with self.assertRaisesRegex(ir.IntegrityRecordError, "size_bytes"):
            ir.build_artifact_ref(
                path="evidence/too-large.bin",
                sha256=H["candidate"],
                size_bytes=ir.MAX_INTEGRITY_ARTIFACT_BYTES + 1,
            )

        contract = complete_contract(with_finding=True)
        second_snapshot = copy.deepcopy(post_fix())
        second_snapshot["current_head"] = "5" * 40
        second_snapshot["snapshot_sha256"] = "6" * 64
        second_snapshot["artifact"]["sha256"] = "7" * 64
        second_snapshot["record_sha256"] = ir.integrity_record_sha256(second_snapshot)
        contract = append(contract, "snapshots", second_snapshot)
        finding = contract["findings"][0]
        second_fix = ir.build_fix_record(
            finding_id="finding-1",
            finding_record_sha256=finding["record_sha256"],
            post_fix_snapshot_sha256="6" * 64,
            fix_artifact=artifact("fix-attempt-2.md", "8" * 64),
            producer_agent_ids=["fixer-2"],
        )
        contract = append(contract, "fixes", second_fix)
        self.assertEqual(ir.integrity_contract_errors(contract), [])
        self.assertIn(
            "finding finding-1 latest fix lacks independent review verification",
            ir.integrity_contract_errors(contract, require_complete=True),
        )
        second_verification = ir.build_review_verification_record(
            finding_id="finding-1",
            fix_record_sha256=second_fix["record_sha256"],
            snapshot_sha256="6" * 64,
            reviewer_agent_id="verifier-2",
            verification_artifact=artifact("verify-attempt-2.md", "9" * 64),
            outcome="pass",
        )
        contract = append(contract, "review_verifications", second_verification)
        contract = ir.seal_integrity_contract(
            contract,
            ir.build_integrity_seal(
                latest_candidate_snapshot_sha256=H["candidate"],
                latest_review_result_record_sha256=contract["review_results"][0]["record_sha256"],
                claim_scope_sha256=H["claim"],
                sealed_at="2026-07-19T12:00:00+00:00",
            ),
        )
        self.assertEqual(ir.integrity_contract_errors(contract, require_complete=True), [])


if __name__ == "__main__":
    unittest.main()
