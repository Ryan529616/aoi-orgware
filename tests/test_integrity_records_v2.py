#!/usr/bin/env python3
"""Contract tests for ordered, attempt-aware required-v2 integrity records."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import integrity_records_v2 as ir  # noqa: E402
from aoi_orgware import integrity_records as ir_v1  # noqa: E402


H = {
    "base": "0" * 40,
    "candidate_head": "1" * 40,
    "post_fix_head": "2" * 40,
    "candidate": "a" * 64,
    "post_fix": "e" * 64,
    "claim": "b" * 64,
    "review": "c" * 64,
    "fix": "d" * 64,
    "verify": "f" * 64,
}
TASK_ID = "task-v2"
WORKTREE = "/work/aoi"
ADOPTED_AT = "2026-07-19T10:00:00+00:00"


def _call(name: str, **kwargs: object) -> dict[str, object]:
    """Call a v2 builder while explicitly supplying its public record fields."""

    builder = getattr(ir, name)
    parameters = inspect.signature(builder).parameters
    return builder(**{key: value for key, value in kwargs.items() if key in parameters})


def artifact(name: str, digest: str) -> dict[str, object]:
    return ir.build_artifact_ref(path=f"evidence/{name}", sha256=digest, size_bytes=12)


def empty_contract() -> dict[str, object]:
    return ir.build_integrity_contract(baseline_head=H["base"], adopted_at=ADOPTED_AT)


def _sequence(contract: dict[str, object]) -> int:
    return len(contract["records"]) + 1


def _append(contract: dict[str, object], record: dict[str, object]) -> dict[str, object]:
    parameters = inspect.signature(ir.append_integrity_record).parameters
    if "collection" in parameters:
        return ir.append_integrity_record(contract, "records", record)
    return ir.append_integrity_record(contract, record)


def snapshot(
    contract: dict[str, object], *, purpose: str, attempt_id: int,
    content_sha: str, current_head: str, producer: str = "producer",
) -> dict[str, object]:
    return _call(
        "build_snapshot_record",
        integrity_seq=_sequence(contract),
        source_v1_record_sha256=None,
        task_id=TASK_ID,
        worktree=WORKTREE,
        baseline_head=H["base"],
        current_head=current_head,
        artifact=artifact(f"{purpose}-{attempt_id}.json", content_sha),
        snapshot_sha256=content_sha,
        claim_scope_sha256=H["claim"],
        covered_claim_tokens=["claim-1"],
        purpose=purpose,
        producer_agent_ids=[producer],
        attempt_id=attempt_id,
    )


def review(
    contract: dict[str, object], source: dict[str, object], *, outcome: str,
    finding_ids: list[str], basis: list[str], reviewer: str = "reviewer",
) -> dict[str, object]:
    return _call(
        "build_review_result_record",
        integrity_seq=_sequence(contract),
        source_v1_record_sha256=None,
        snapshot_record_sha256=source["record_sha256"],
        reviewer_agent_id=reviewer,
        producer_agent_ids=source["producer_agent_ids"],
        result_artifact=artifact("review.md", H["review"]),
        outcome=outcome,
        finding_ids=finding_ids,
        basis_review_verification_record_sha256s=basis,
    )


def finding(
    contract: dict[str, object], source: dict[str, object], review_record: dict[str, object],
    finding_id: str,
) -> dict[str, object]:
    return _call(
        "build_finding_record",
        integrity_seq=_sequence(contract),
        source_v1_record_sha256=None,
        finding_id=finding_id,
        review_result_record_sha256=review_record["record_sha256"],
        snapshot_record_sha256=source["record_sha256"],
        reviewer_agent_id=review_record["reviewer_agent_id"],
        finding_artifact_sha256=H["review"],
    )


def fix(
    contract: dict[str, object], finding_record: dict[str, object], target: dict[str, object],
    finding_id: str, *, producer: str = "fixer",
) -> dict[str, object]:
    return _call(
        "build_fix_record",
        integrity_seq=_sequence(contract),
        source_v1_record_sha256=None,
        finding_id=finding_id,
        finding_record_sha256=finding_record["record_sha256"],
        post_fix_snapshot_record_sha256=target["record_sha256"],
        fix_artifact=artifact(f"fix-{finding_id}.md", H["fix"]),
        producer_agent_ids=[producer],
    )


def verification(
    contract: dict[str, object], finding_id: str, fixed: dict[str, object],
    target: dict[str, object], *, outcome: str = "pass",
) -> dict[str, object]:
    return _call(
        "build_review_verification_record",
        integrity_seq=_sequence(contract),
        source_v1_record_sha256=None,
        finding_id=finding_id,
        fix_record_sha256=fixed["record_sha256"],
        verification_snapshot_record_sha256=target["record_sha256"],
        reviewer_agent_id="verifier",
        verification_artifact=artifact(f"verify-{finding_id}.md", H["verify"]),
        outcome=outcome,
    )


def seal(contract: dict[str, object], terminal: dict[str, object], clean_review: dict[str, object]) -> dict[str, object]:
    record = _call(
        "build_integrity_seal",
        integrity_seq=_sequence(contract),
        source_v1_record_sha256=None,
        terminal_snapshot_record_sha256=terminal["record_sha256"],
        terminal_review_result_record_sha256=clean_review["record_sha256"],
        claim_scope_sha256=terminal["claim_scope_sha256"],
        sealed_at="2026-07-19T11:00:00+00:00",
    )
    return ir.seal_integrity_contract(contract, record)


def canonical(record: dict[str, object]) -> dict[str, object]:
    record["record_sha256"] = ir.integrity_record_sha256(record)
    return record


def v1_source_with_closed_finding(*, sealed: bool = False) -> dict[str, object]:
    """A valid unsealed v1 history whose full obligations must survive migration."""

    contract = ir_v1.build_integrity_contract(baseline_head=H["base"], adopted_at=ADOPTED_AT)
    candidate = ir_v1.build_snapshot_record(
        task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"],
        current_head=H["candidate_head"], artifact=ir_v1.build_artifact_ref(
            path="evidence/v1-candidate.json", sha256=H["candidate"], size_bytes=12
        ), snapshot_sha256=H["candidate"], claim_scope_sha256=H["claim"],
        covered_claim_tokens=["claim-1"], purpose="candidate", producer_agent_ids=["producer"],
    )
    contract = ir_v1.append_snapshot(contract, candidate)
    if sealed:
        clean = ir_v1.build_review_result_record(
            snapshot_sha256=H["candidate"], reviewer_agent_id="reviewer-2",
            producer_agent_ids=["producer"], result_artifact=ir_v1.build_artifact_ref(
                path="evidence/v1-clean.md", sha256="9" * 64, size_bytes=12
            ), outcome="clean", finding_ids=[],
        )
        contract = ir_v1.append_review_result(contract, clean)
        return ir_v1.seal_integrity_contract(contract, ir_v1.build_integrity_seal(
            latest_candidate_snapshot_sha256=H["candidate"],
            latest_review_result_record_sha256=clean["record_sha256"],
            claim_scope_sha256=H["claim"], sealed_at="2026-07-19T11:00:00+00:00",
        ))
    rejected = ir_v1.build_review_result_record(
        snapshot_sha256=H["candidate"], reviewer_agent_id="reviewer",
        producer_agent_ids=["producer"], result_artifact=ir_v1.build_artifact_ref(
            path="evidence/v1-review.md", sha256=H["review"], size_bytes=12
        ), outcome="findings", finding_ids=["finding-1"],
    )
    contract = ir_v1.append_review_result(contract, rejected)
    issue = ir_v1.build_finding_record(
        finding_id="finding-1", review_result_record_sha256=rejected["record_sha256"],
        snapshot_sha256=H["candidate"], reviewer_agent_id="reviewer",
        finding_artifact_sha256=H["review"],
    )
    contract = ir_v1.append_finding(contract, issue)
    post_fix_record = ir_v1.build_snapshot_record(
        task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"],
        current_head=H["post_fix_head"], artifact=ir_v1.build_artifact_ref(
            path="evidence/v1-post-fix.json", sha256=H["post_fix"], size_bytes=12
        ), snapshot_sha256=H["post_fix"], claim_scope_sha256=H["claim"],
        covered_claim_tokens=["claim-1"], purpose="post_fix", producer_agent_ids=["fixer"],
    )
    contract = ir_v1.append_snapshot(contract, post_fix_record)
    repaired = ir_v1.build_fix_record(
        finding_id="finding-1", finding_record_sha256=issue["record_sha256"],
        post_fix_snapshot_sha256=H["post_fix"], fix_artifact=ir_v1.build_artifact_ref(
            path="evidence/v1-fix.md", sha256=H["fix"], size_bytes=12
        ), producer_agent_ids=["fixer"],
    )
    contract = ir_v1.append_fix(contract, repaired)
    passed = ir_v1.build_review_verification_record(
        finding_id="finding-1", fix_record_sha256=repaired["record_sha256"],
        snapshot_sha256=H["post_fix"], reviewer_agent_id="verifier",
        verification_artifact=ir_v1.build_artifact_ref(
            path="evidence/v1-verify.md", sha256=H["verify"], size_bytes=12
        ), outcome="pass",
    )
    contract = ir_v1.append_review_verification(contract, passed)
    return contract


def v1_digest(contract: dict[str, object]) -> tuple[str, int]:
    blob = json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), len(blob)


def v1_source_over_legacy_v2_cap() -> dict[str, object]:
    """Build an actual valid v1 prefix with 1,025 records, not a mock."""

    contract = ir_v1.build_integrity_contract(baseline_head=H["base"], adopted_at=ADOPTED_AT)
    for index in range(ir_v1.MAX_INTEGRITY_RECORDS):
        digest = f"{index + 1:064x}"
        record = ir_v1.build_snapshot_record(
            task_id=TASK_ID,
            worktree=WORKTREE,
            baseline_head=H["base"],
            current_head=f"{index + 1:040x}",
            artifact=ir_v1.build_artifact_ref(
                path=f"evidence/v1-candidate-{index:04d}.json", sha256=digest, size_bytes=12
            ),
            snapshot_sha256=digest,
            claim_scope_sha256=H["claim"],
            covered_claim_tokens=["claim-1"],
            purpose="candidate",
            producer_agent_ids=["producer"],
        )
        contract = ir_v1.append_snapshot(contract, record)
    review_record = ir_v1.build_review_result_record(
        snapshot_sha256=contract["snapshots"][-1]["snapshot_sha256"],
        reviewer_agent_id="reviewer",
        producer_agent_ids=["producer"],
        result_artifact=ir_v1.build_artifact_ref(
            path="evidence/v1-cap-review.md", sha256=H["review"], size_bytes=12
        ),
        outcome="clean",
        finding_ids=[],
    )
    return ir_v1.append_review_result(contract, review_record)


def migrate_v1(contract: dict[str, object], *, digest: str | None = None) -> dict[str, object]:
    expected_digest, size_bytes = v1_digest(contract)
    actual_digest = expected_digest if digest is None else digest
    kwargs: dict[str, object] = {
        "contract": contract,
        "v1_contract": contract,
        "source_contract": contract,
        "expected_v1_contract_sha256": actual_digest,
        "source_v1_contract_sha256": actual_digest,
        "expected_source_contract_sha256": actual_digest,
        "source_contract_sha256": actual_digest,
        "source_contract_artifact": ir.build_artifact_ref(
            path="integrity/v1-contract.json", sha256=actual_digest, size_bytes=size_bytes
        ),
        "source_artifact": ir.build_artifact_ref(
            path="integrity/v1-contract.json", sha256=actual_digest, size_bytes=size_bytes
        ),
        "anchor_snapshot_record_sha256": contract["snapshots"][-1]["record_sha256"],
        "migrated_at": "2026-07-19T12:00:00+00:00",
    }
    return _call("migrate_v1_integrity_contract", **kwargs)


class IntegrityRecordV2Tests(unittest.TestCase):
    def test_migration_source_contract_reference_uses_managed_state_bound(self) -> None:
        with self.assertRaises(ir.IntegrityRecordError):
            ir.build_artifact_ref(
                path="integrity/v1-contract.json", sha256=H["candidate"],
                size_bytes=ir.MAX_INTEGRITY_ARTIFACT_BYTES + 1,
            )
        reference = ir.build_migration_source_contract_artifact_ref(
            path="integrity/v1-contract.json", sha256=H["candidate"],
            size_bytes=ir.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES,
        )
        self.assertEqual(reference["size_bytes"], ir.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES)
        self.assertEqual(ir.MAX_INTEGRITY_MIGRATION_AGGREGATE_BYTES, ir.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES)
        with self.assertRaises(ir.IntegrityRecordError):
            ir.build_migration_source_contract_artifact_ref(
                path="integrity/v1-contract.json", sha256=H["candidate"],
                size_bytes=ir.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES + 1,
            )

    def test_native_candidate_clean_review_seals(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        clean = review(contract, candidate, outcome="clean", finding_ids=[], basis=[])
        contract = _append(contract, clean)
        sealed = seal(contract, candidate, clean)
        self.assertEqual(ir.integrity_contract_errors(sealed, require_complete=True), [])

    def test_candidate_findings_post_fix_verify_terminal_clean_review_seals(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        terminal = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, terminal)
        repaired = fix(contract, issue, terminal, "finding-1")
        contract = _append(contract, repaired)
        passed = verification(contract, "finding-1", repaired, terminal)
        contract = _append(contract, passed)
        clean = review(contract, terminal, outcome="clean", finding_ids=[], basis=[passed["record_sha256"]])
        contract = _append(contract, clean)
        self.assertEqual(ir.integrity_contract_errors(seal(contract, terminal, clean), require_complete=True), [])

    def test_native_fix_requires_the_frontier_post_fix_snapshot(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        first_post_fix = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, first_post_fix)
        latest_post_fix = snapshot(contract, purpose="post_fix", attempt_id=3, content_sha="9" * 64, current_head="3" * 40)
        contract = _append(contract, latest_post_fix)
        contract = _append(contract, fix(contract, issue, first_post_fix, "finding-1"))
        self.assertIn(
            "fix for finding finding-1 only targets the frontier snapshot",
            ir.integrity_contract_errors(contract),
        )

    def test_native_verification_requires_the_frontier_snapshot(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        first_post_fix = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, first_post_fix)
        repaired = fix(contract, issue, first_post_fix, "finding-1")
        contract = _append(contract, repaired)
        latest_post_fix = snapshot(contract, purpose="post_fix", attempt_id=3, content_sha="9" * 64, current_head="3" * 40)
        contract = _append(contract, latest_post_fix)
        contract = _append(contract, verification(contract, "finding-1", repaired, first_post_fix))
        self.assertIn(
            "review verification for finding finding-1 only targets the frontier snapshot",
            ir.integrity_contract_errors(contract),
        )

    def test_same_content_post_fix_attempt_can_reverify_all_prior_findings_then_seal(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        first_review = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, first_review)
        first_finding = finding(contract, candidate, first_review, "finding-1")
        contract = _append(contract, first_finding)
        first_post_fix = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, first_post_fix)
        first_fix = fix(contract, first_finding, first_post_fix, "finding-1")
        contract = _append(contract, first_fix)
        first_pass = verification(contract, "finding-1", first_fix, first_post_fix)
        contract = _append(contract, first_pass)
        second_review = review(contract, first_post_fix, outcome="findings", finding_ids=["finding-2"], basis=[first_pass["record_sha256"]])
        contract = _append(contract, second_review)
        second_finding = finding(contract, first_post_fix, second_review, "finding-2")
        contract = _append(contract, second_finding)
        final_post_fix = snapshot(contract, purpose="post_fix", attempt_id=3, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        self.assertEqual(first_post_fix["snapshot_sha256"], final_post_fix["snapshot_sha256"])
        self.assertNotEqual(first_post_fix["record_sha256"], final_post_fix["record_sha256"])
        contract = _append(contract, final_post_fix)
        newest_first_fix = fix(contract, first_finding, final_post_fix, "finding-1")
        contract = _append(contract, newest_first_fix)
        newest_second_fix = fix(contract, second_finding, final_post_fix, "finding-2")
        contract = _append(contract, newest_second_fix)
        first_reverified = verification(contract, "finding-1", newest_first_fix, final_post_fix)
        contract = _append(contract, first_reverified)
        second_pass = verification(contract, "finding-2", newest_second_fix, final_post_fix)
        contract = _append(contract, second_pass)
        clean = review(contract, final_post_fix, outcome="clean", finding_ids=[], basis=sorted([first_reverified["record_sha256"], second_pass["record_sha256"]]))
        contract = _append(contract, clean)
        self.assertEqual(ir.integrity_contract_errors(seal(contract, final_post_fix, clean), require_complete=True), [])

    def test_later_terminal_attempt_requires_reverification_but_may_reuse_same_fix(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        first_terminal = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, first_terminal)
        repaired = fix(contract, issue, first_terminal, "finding-1")
        contract = _append(contract, repaired)
        first_pass = verification(contract, "finding-1", repaired, first_terminal)
        contract = _append(contract, first_pass)
        latest_terminal = snapshot(contract, purpose="post_fix", attempt_id=3, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, latest_terminal)

        stale_review = review(contract, latest_terminal, outcome="clean", finding_ids=[], basis=[first_pass["record_sha256"]])
        stale_contract = _append(contract, stale_review)
        self.assertTrue(ir.integrity_contract_errors(stale_contract, require_complete=True))

        terminal_pass = verification(contract, "finding-1", repaired, latest_terminal)
        contract = _append(contract, terminal_pass)
        clean = review(contract, latest_terminal, outcome="clean", finding_ids=[], basis=[terminal_pass["record_sha256"]])
        contract = _append(contract, clean)
        self.assertEqual(ir.integrity_contract_errors(seal(contract, latest_terminal, clean), require_complete=True), [])

    def test_later_fail_then_pass_uses_latest_verification_and_clean_review_is_terminal(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        terminal = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, terminal)
        repaired = fix(contract, issue, terminal, "finding-1")
        contract = _append(contract, repaired)
        first_pass = verification(contract, "finding-1", repaired, terminal)
        contract = _append(contract, first_pass)
        failed = verification(contract, "finding-1", repaired, terminal, outcome="fail")
        contract = _append(contract, failed)

        rejected_after_fail = _append(
            contract,
            review(contract, terminal, outcome="clean", finding_ids=[], basis=[first_pass["record_sha256"]]),
        )
        self.assertTrue(ir.integrity_contract_errors(rejected_after_fail, require_complete=True))

        recovered = verification(contract, "finding-1", repaired, terminal)
        contract = _append(contract, recovered)
        clean = review(contract, terminal, outcome="clean", finding_ids=[], basis=[recovered["record_sha256"]])
        contract = _append(contract, clean)
        self.assertEqual(ir.integrity_contract_errors(seal(contract, terminal, clean), require_complete=True), [])

        appended_after_clean = _append(
            contract,
            snapshot(contract, purpose="post_fix", attempt_id=3, content_sha=H["post_fix"], current_head=H["post_fix_head"]),
        )
        self.assertTrue(ir.integrity_contract_errors(appended_after_clean))

    def test_ordered_graph_rejects_gaps_duplicate_hashes_backedges_stale_and_bad_basis(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        terminal = snapshot(contract, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"])
        contract = _append(contract, terminal)
        repaired = fix(contract, issue, terminal, "finding-1")
        contract = _append(contract, repaired)
        passed = verification(contract, "finding-1", repaired, terminal)
        contract = _append(contract, passed)
        clean = review(contract, terminal, outcome="clean", finding_ids=[], basis=[passed["record_sha256"]])
        contract = _append(contract, clean)

        cases: dict[str, dict[str, object]] = {}
        sequence_gap = copy.deepcopy(contract)
        sequence_gap["records"][3]["integrity_seq"] = 9
        canonical(sequence_gap["records"][3])
        cases["sequence gap"] = sequence_gap
        duplicate_hash = copy.deepcopy(contract)
        duplicate_hash["records"][3]["record_sha256"] = duplicate_hash["records"][0]["record_sha256"]
        cases["duplicate record hash"] = duplicate_hash
        backedge = copy.deepcopy(contract)
        backedge["records"][4]["post_fix_snapshot_record_sha256"] = backedge["records"][0]["record_sha256"]
        canonical(backedge["records"][4])
        cases["backedge"] = backedge
        stale = copy.deepcopy(contract)
        stale["records"][5]["verification_snapshot_record_sha256"] = stale["records"][0]["record_sha256"]
        canonical(stale["records"][5])
        cases["stale verification snapshot"] = stale
        missing_basis = copy.deepcopy(contract)
        missing_basis["records"][6]["basis_review_verification_record_sha256s"] = []
        canonical(missing_basis["records"][6])
        cases["missing basis"] = missing_basis
        extra_basis = copy.deepcopy(contract)
        extra_basis["records"][6]["basis_review_verification_record_sha256s"] = sorted([passed["record_sha256"], "0" * 64])
        canonical(extra_basis["records"][6])
        cases["extra basis"] = extra_basis
        for label, malformed in cases.items():
            with self.subTest(label=label):
                self.assertTrue(ir.integrity_contract_errors(malformed), label)

    def test_terminal_rejects_later_events_multiple_reviews_self_review_and_tampered_seal(self) -> None:
        contract = empty_contract()
        candidate = snapshot(contract, purpose="candidate", attempt_id=1, content_sha=H["candidate"], current_head=H["candidate_head"])
        contract = _append(contract, candidate)
        clean = review(contract, candidate, outcome="clean", finding_ids=[], basis=[])
        contract = _append(contract, clean)
        sealed = seal(contract, candidate, clean)

        tampered = copy.deepcopy(sealed)
        tampered["seal"]["claim_scope_sha256"] = "0" * 64
        self.assertTrue(ir.integrity_contract_errors(tampered, require_complete=True))

        duplicate_review = _append(contract, review(contract, candidate, outcome="clean", finding_ids=[], basis=[], reviewer="another-reviewer"))
        self.assertTrue(ir.integrity_contract_errors(duplicate_review))
        with self.assertRaises(ir.IntegrityRecordError):
            review(contract, candidate, outcome="clean", finding_ids=[], basis=[], reviewer="producer")
        with self.assertRaises(ir.IntegrityRecordError):
            _append(sealed, snapshot(sealed, purpose="post_fix", attempt_id=2, content_sha=H["post_fix"], current_head=H["post_fix_head"]))

    def test_v1_migration_keeps_provenance_records_and_opening_obligations(self) -> None:
        source = v1_source_with_closed_finding()
        migrated = migrate_v1(source)
        self.assertEqual(migrated["schema_version"], 2)
        self.assertEqual(migrated["mode"], "required_v2")
        receipt = migrated["migration_receipt"]
        digest, size_bytes = v1_digest(source)
        self.assertEqual(receipt["source_schema_version"], 1)
        self.assertEqual(receipt["source_mode"], "required_v1")
        self.assertEqual(receipt["prefix_storage"], "source_v1_cas_v1")
        self.assertEqual(receipt["source_contract_artifact"]["sha256"], digest)
        self.assertEqual(receipt["source_contract_artifact"]["size_bytes"], size_bytes)
        source_hashes = {
            record["record_sha256"]
            for collection in ("snapshots", "review_results", "findings", "fixes", "review_verifications")
            for record in source[collection]
        }
        effective = ir.materialize_effective_integrity_records(migrated, source)
        migrated_source_hashes = {
            record["source_v1_record_sha256"]
            for record in effective
            if record["source_v1_record_sha256"] is not None
        }
        self.assertTrue(source_hashes <= migrated_source_hashes)
        self.assertEqual(migrated["records"], [])
        self.assertEqual(ir.integrity_contract_errors(migrated), [])
        self.assertEqual(ir.integrity_contract_errors(migrated, source_v1_contract=source), [])

    def test_v1_migration_accepts_an_actual_prefix_over_1024_records(self) -> None:
        source = v1_source_over_legacy_v2_cap()
        collections = ("snapshots", "review_results", "findings", "fixes", "review_verifications")
        self.assertEqual(sum(len(source[name]) for name in collections), 1025)
        ir_v1.validate_integrity_contract(source)

        migrated = migrate_v1(source)

        self.assertEqual(migrated["records"], [])
        self.assertEqual(migrated["migration_receipt"]["migrated_record_count"], 1025)
        self.assertGreater(len(ir.materialize_effective_integrity_records(migrated, source)), 1024)
        self.assertLess(
            len(json.dumps(migrated, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
            ir.MAX_INTEGRITY_MIGRATION_SEMANTIC_DELTA_BYTES,
        )
        self.assertEqual(ir.integrity_contract_errors(migrated), [])

    def test_compact_migration_exposes_source_requirement_and_rejects_tampered_receipt(self) -> None:
        source = v1_source_with_closed_finding()
        migrated = migrate_v1(source)
        status = ir.integrity_contract_validation_status(migrated)
        self.assertTrue(status["source_required"])
        self.assertFalse(status["full_validation"])
        self.assertEqual(status["errors"], [])
        full = ir.integrity_contract_validation_status(migrated, source_v1_contract=source)
        self.assertFalse(full["source_required"])
        self.assertTrue(full["full_validation"])
        self.assertEqual(full["errors"], [])

        tampered = copy.deepcopy(migrated)
        tampered["migration_receipt"]["migrated_records_sha256"] = "0" * 64
        self.assertTrue(ir.integrity_contract_errors(tampered))
        with self.assertRaises(ir.IntegrityRecordError):
            ir.materialize_effective_integrity_records(tampered, source)

    def test_compact_migration_native_tail_uses_effective_sequence_and_compacts_round_trip(self) -> None:
        source = v1_source_with_closed_finding()
        migrated = migrate_v1(source)
        prefix = ir.materialize_effective_integrity_records(migrated, source)
        record = ir.build_snapshot_record(
            integrity_seq=None, source_v1_record_sha256=None, task_id=TASK_ID,
            worktree=WORKTREE, baseline_head=H["base"], current_head="3" * 40,
            artifact=artifact("native-after-prefix.json", "3" * 64), snapshot_sha256="3" * 64,
            claim_scope_sha256=H["claim"], covered_claim_tokens=["claim-1"], purpose="candidate",
            producer_agent_ids=["native-producer"], attempt_id=None,
        )
        with_tail = ir.append_snapshot(migrated, record, source_v1_contract=source)
        self.assertEqual(with_tail["records"][0]["integrity_seq"], len(prefix) + 1)
        self.assertEqual(with_tail["records"][0]["attempt_id"], 3)
        self.assertEqual(ir.integrity_contract_errors(with_tail, source_v1_contract=source), [])

        malformed = copy.deepcopy(with_tail)
        malformed["records"][0]["integrity_seq"] = 1
        canonical(malformed["records"][0])
        self.assertTrue(ir.integrity_contract_errors(malformed))

        effective = copy.deepcopy(with_tail)
        effective["records"] = ir.materialize_effective_integrity_records(with_tail, source)
        compacted = ir.compact_effective_integrity_contract(effective, source)
        self.assertEqual(compacted["records"], with_tail["records"])

    def test_v1_migration_rejects_wrong_digest_sealed_and_backedge_source(self) -> None:
        source = v1_source_with_closed_finding()
        with self.assertRaises(ValueError):
            migrate_v1(source, digest="0" * 64)

        sealed_source = v1_source_with_closed_finding(sealed=True)
        with self.assertRaises(ValueError):
            migrate_v1(sealed_source)

        backedge = copy.deepcopy(source)
        backedge["fixes"][0]["post_fix_snapshot_sha256"] = H["candidate"]
        backedge["fixes"][0]["record_sha256"] = ir_v1.integrity_record_sha256(backedge["fixes"][0])
        with self.assertRaises(ValueError):
            migrate_v1(backedge)

    def test_v1_migration_preserves_same_and_decreasing_fix_target_order(self) -> None:
        """v1 collection order, not target attempt, defines its latest fix."""
        source = v1_source_with_closed_finding()
        finding = source["findings"][0]
        later_snapshot = ir_v1.build_snapshot_record(
            task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"],
            current_head="8" * 40, artifact=ir_v1.build_artifact_ref(
                path="evidence/v1-later-post-fix.json", sha256="7" * 64, size_bytes=12,
            ), snapshot_sha256="7" * 64, claim_scope_sha256=H["claim"],
            covered_claim_tokens=["claim-1"], purpose="post_fix",
            producer_agent_ids=["fixer-2"],
        )
        source = ir_v1.append_snapshot(source, later_snapshot)
        later_fix = ir_v1.build_fix_record(
            finding_id="finding-1", finding_record_sha256=finding["record_sha256"],
            post_fix_snapshot_sha256="7" * 64, fix_artifact=ir_v1.build_artifact_ref(
                path="evidence/v1-fix-later.md", sha256="6" * 64, size_bytes=12,
            ), producer_agent_ids=["fixer-2"],
        )
        same_target_fix = ir_v1.build_fix_record(
            finding_id="finding-1", finding_record_sha256=finding["record_sha256"],
            post_fix_snapshot_sha256="7" * 64, fix_artifact=ir_v1.build_artifact_ref(
                path="evidence/v1-fix-same-target.md", sha256="5" * 64, size_bytes=12,
            ), producer_agent_ids=["fixer-3"],
        )
        original_fix = source["fixes"][0]
        # Both repeated target and target-attempt decrease are valid v1; the
        # final original fix is the v1 latest solely because it is last.
        source["fixes"] = [later_fix, same_target_fix, original_fix]
        ir_v1.validate_integrity_contract(source)

        migrated = migrate_v1(source)
        self.assertEqual(
            [record["source_v1_record_sha256"] for record in ir.materialize_effective_integrity_records(migrated, source)
             if record["record_type"] == "fix"],
            [record["record_sha256"] for record in source["fixes"]],
        )
        self.assertEqual(ir.integrity_contract_errors(migrated), [])

    def test_v1_migration_accepts_post_fix_before_candidate_collection_order(self) -> None:
        """Frozen v1 permits this collection order; source mapping stays exact."""
        source = v1_source_with_closed_finding()
        # Keep this focused on frozen snapshot collection order.  The v1
        # verifier has separate dependent-record ordering rules, exercised by
        # the migration tests above.
        source["review_results"] = []
        source["findings"] = []
        source["fixes"] = []
        source["review_verifications"] = []
        source["snapshots"] = [source["snapshots"][1], source["snapshots"][0]]
        ir_v1.validate_integrity_contract(source)

        migrated = migrate_v1(source)
        for collection, record_type in (
            ("snapshots", "snapshot"),
            ("fixes", "fix"),
            ("review_verifications", "review_verification"),
        ):
            with self.subTest(collection=collection):
                self.assertEqual(
                    [record["source_v1_record_sha256"] for record in ir.materialize_effective_integrity_records(migrated, source)
                     if record["record_type"] == record_type],
                    [record["record_sha256"] for record in source[collection]],
                )
        self.assertEqual(ir.integrity_contract_errors(migrated), [])

    def test_fix_target_must_be_post_fix_snapshot(self) -> None:
        contract = empty_contract()
        candidate = snapshot(
            contract, purpose="candidate", attempt_id=1,
            content_sha=H["candidate"], current_head=H["candidate_head"],
        )
        contract = _append(contract, candidate)
        rejected = review(contract, candidate, outcome="findings", finding_ids=["finding-1"], basis=[])
        contract = _append(contract, rejected)
        issue = finding(contract, candidate, rejected, "finding-1")
        contract = _append(contract, issue)
        wrong_target = snapshot(
            contract, purpose="candidate", attempt_id=2,
            content_sha=H["post_fix"], current_head=H["post_fix_head"],
        )
        contract = _append(contract, wrong_target)
        contract = _append(contract, fix(contract, issue, wrong_target, "finding-1"))
        self.assertTrue(ir.integrity_contract_errors(contract))

    def test_empty_v1_migration_requires_explicit_source_binding_and_keeps_zero_prefix(self) -> None:
        source = ir_v1.build_integrity_contract(baseline_head=H["base"], adopted_at=ADOPTED_AT)
        digest, size_bytes = v1_digest(source)
        artifact_ref = ir.build_artifact_ref(
            path="integrity/empty-v1-contract.json", sha256=digest, size_bytes=size_bytes
        )
        kwargs = {
            "v1_contract": source,
            "source_contract_artifact": artifact_ref,
            "migrated_at": "2026-07-19T12:00:00+00:00",
            "expected_v1_contract_sha256": digest,
            "source_task_id": TASK_ID,
            "source_worktree": WORKTREE,
        }
        migrated = ir.migrate_v1_integrity_contract(**kwargs)
        receipt = migrated["migration_receipt"]
        self.assertEqual(receipt["source_task_id"], TASK_ID)
        self.assertEqual(receipt["source_worktree"], WORKTREE)
        self.assertEqual(receipt["migrated_record_count"], 0)
        self.assertEqual(receipt["anchor_snapshot_record_sha256"], None)
        self.assertEqual(migrated["records"], [])
        self.assertEqual(ir.integrity_contract_errors(migrated), [])

        without_task = dict(kwargs)
        without_task["source_task_id"] = None
        with self.assertRaises(ValueError):
            ir.migrate_v1_integrity_contract(**without_task)
        without_worktree = dict(kwargs)
        without_worktree["source_worktree"] = None
        with self.assertRaises(ValueError):
            ir.migrate_v1_integrity_contract(**without_worktree)

    def test_compact_receipt_cannot_downgrade_to_a_self_consistent_inline_prefix(self) -> None:
        source = v1_source_with_closed_finding()
        migrated = migrate_v1(source)
        inline = copy.deepcopy(migrated)
        inline["records"] = ir.materialize_effective_integrity_records(migrated, source)
        inline["migration_receipt"]["prefix_storage"] = "inline_v1_prefix"
        inline["migration_receipt"]["record_sha256"] = ir.integrity_record_sha256(
            inline["migration_receipt"]
        )

        errors = ir.integrity_contract_errors(inline)
        self.assertIn(
            "migration_receipt prefix_storage must be source_v1_cas_v1", errors
        )

    def test_compact_tail_malformed_item_is_fail_closed_diagnostic(self) -> None:
        source = ir_v1.build_integrity_contract(
            baseline_head=H["base"], adopted_at=ADOPTED_AT
        )
        digest, size_bytes = v1_digest(source)
        migrated = ir.migrate_v1_integrity_contract(
            source,
            source_contract_artifact=ir.build_artifact_ref(
                path="integrity/empty-v1-contract.json", sha256=digest,
                size_bytes=size_bytes,
            ),
            migrated_at="2026-07-19T12:00:00+00:00", source_task_id=TASK_ID,
            source_worktree=WORKTREE,
        )
        malformed = copy.deepcopy(migrated)
        malformed["records"] = [None]

        self.assertIn(
            "native migration tail record 1 is not an object",
            ir.integrity_contract_errors(malformed),
        )
        with self.assertRaisesRegex(ir.IntegrityRecordError, "tail record 1 is not an object"):
            ir.materialize_effective_integrity_records(malformed, source)

    def test_compact_review_and_findings_are_one_validated_tail_transaction(self) -> None:
        source = ir_v1.build_integrity_contract(
            baseline_head=H["base"], adopted_at=ADOPTED_AT
        )
        digest, size_bytes = v1_digest(source)
        migrated = ir.migrate_v1_integrity_contract(
            source,
            source_contract_artifact=ir.build_artifact_ref(
                path="integrity/empty-v1-contract.json", sha256=digest,
                size_bytes=size_bytes,
            ),
            migrated_at="2026-07-19T12:00:00+00:00", source_task_id=TASK_ID,
            source_worktree=WORKTREE,
        )
        candidate = ir.build_snapshot_record(
            integrity_seq=None, attempt_id=None, source_v1_record_sha256=None,
            task_id=TASK_ID, worktree=WORKTREE, baseline_head=H["base"],
            current_head=H["candidate_head"], artifact=artifact("compact-candidate.json", H["candidate"]),
            snapshot_sha256=H["candidate"], claim_scope_sha256=H["claim"],
            covered_claim_tokens=["claim-1"], purpose="candidate",
            producer_agent_ids=["producer"],
        )
        with_snapshot = ir.append_snapshot(
            migrated, candidate, source_v1_contract=source
        )
        review_record = ir.build_review_result_record(
            integrity_seq=2, source_v1_record_sha256=None,
            snapshot_record_sha256=with_snapshot["records"][0]["record_sha256"],
            reviewer_agent_id="reviewer", producer_agent_ids=["producer"],
            result_artifact=artifact("compact-review.md", H["review"]),
            outcome="findings", finding_ids=["finding-1", "finding-2"],
        )
        pending = [
            review_record,
            ir.build_finding_record(
                integrity_seq=3, source_v1_record_sha256=None, finding_id="finding-1",
                review_result_record_sha256=review_record["record_sha256"],
                snapshot_record_sha256=with_snapshot["records"][0]["record_sha256"],
                reviewer_agent_id="reviewer", finding_artifact_sha256=H["review"],
            ),
            ir.build_finding_record(
                integrity_seq=4, source_v1_record_sha256=None, finding_id="finding-2",
                review_result_record_sha256=review_record["record_sha256"],
                snapshot_record_sha256=with_snapshot["records"][0]["record_sha256"],
                reviewer_agent_id="reviewer", finding_artifact_sha256=H["review"],
            ),
        ]

        with self.assertRaisesRegex(ir.IntegrityRecordError, "finding_ids differ"):
            ir.append_review_result(
                with_snapshot, review_record, source_v1_contract=source
            )
        updated = ir.append_integrity_records(
            with_snapshot, pending, source_v1_contract=source
        )
        self.assertEqual(ir.integrity_contract_errors(updated, source_v1_contract=source), [])

    def test_seal_public_api_requires_source_and_cannot_enter_records_ledger(self) -> None:
        contract = empty_contract()
        candidate = snapshot(
            contract, purpose="candidate", attempt_id=1,
            content_sha=H["candidate"], current_head=H["candidate_head"],
        )
        contract = _append(contract, candidate)
        seal_record = ir.build_integrity_seal(
            integrity_seq=2, terminal_snapshot_record_sha256=candidate["record_sha256"],
            terminal_review_result_record_sha256=H["review"],
            claim_scope_sha256=H["claim"], sealed_at="2026-07-19T11:00:00+00:00",
        )
        with self.assertRaisesRegex(ir.IntegrityRecordError, "only to integrity_contract.seal"):
            ir.append_integrity_record(contract, seal_record)

        source = ir_v1.build_integrity_contract(
            baseline_head=H["base"], adopted_at=ADOPTED_AT
        )
        digest, size_bytes = v1_digest(source)
        migrated = ir.migrate_v1_integrity_contract(
            source,
            source_contract_artifact=ir.build_artifact_ref(
                path="integrity/empty-v1-contract.json", sha256=digest,
                size_bytes=size_bytes,
            ),
            migrated_at="2026-07-19T12:00:00+00:00", source_task_id=TASK_ID,
            source_worktree=WORKTREE,
        )
        with self.assertRaisesRegex(ir.IntegrityRecordError, "migration source contract is required"):
            ir.seal_integrity_contract(migrated, seal_record)


if __name__ == "__main__":
    unittest.main()
