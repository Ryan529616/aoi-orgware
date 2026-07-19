#!/usr/bin/env python3
"""Focused contracts for pure reviewer identity and fix-chain integrity."""

from __future__ import annotations

import unittest
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
from aoi_orgware import review_integrity as ri


SHA = {
    "candidate": "a" * 64,
    "mutation": "b" * 64,
    "fix": "c" * 64,
    "verification": "d" * 64,
}


def valid_graph() -> dict[str, object]:
    finding_id = "finding-1"
    graph: dict[str, object] = {
        "task_owner": "chief",
        "candidate_packets": [{"agent_role": "worker", "agent_id": "implementer"}],
        "result_packets": [{"actual_role": "architect", "agent_id": "designer"}],
        "mutations": [
            {
                "finding_id": finding_id,
                "candidate_snapshot_sha256": SHA["candidate"],
                "mutation_snapshot_sha256": SHA["mutation"],
                "actor_agent_id": "fixer",
            }
        ],
        "findings": [
            {
                "finding_id": finding_id,
                "candidate_snapshot_sha256": SHA["candidate"],
                "reviewer_agent_id": "finding-reviewer",
            }
        ],
        "fix_results": [
            {
                "finding_id": finding_id,
                "mutation_snapshot_sha256": SHA["mutation"],
                "fix_result_sha256": SHA["fix"],
            }
        ],
        "verifications": [
            {
                "finding_id": finding_id,
                "fix_result_sha256": SHA["fix"],
                "reviewer_agent_id": "verification-reviewer",
                "verification_sha256": SHA["verification"],
            }
        ],
        "chains": [
            ri.build_finding_fix_verification_chain(
                finding_id=finding_id,
                candidate_snapshot_sha256=SHA["candidate"],
                mutation_snapshot_sha256=SHA["mutation"],
                fix_result_sha256=SHA["fix"],
                reviewer_agent_id="verification-reviewer",
                verification_sha256=SHA["verification"],
            )
        ],
    }
    graph["review_result"] = ri.build_review_result(
        reviewer_agent_id="verification-reviewer",
        producer_agent_ids={"chief", "implementer", "designer", "fixer"},
        candidate_snapshot_sha256=SHA["candidate"],
        mutation_snapshot_sha256=SHA["mutation"],
        review_result_sha256=SHA["verification"],
        outcome="findings_resolved",
        finding_ids=[finding_id],
    )
    return graph


class ProducerIdentityTests(unittest.TestCase):
    def test_owner_packets_of_every_role_and_mutation_actor_are_producers(self) -> None:
        identities = ri.producer_identity_set(
            task_owner="chief",
            candidate_packets=[
                {"agent_role": "worker", "agent_id": "candidate"},
                {"agent_role": "reviewer", "agent_id": "reviewer"},
            ],
            result_packets=[{"actual_role": "architect", "agent_id": "result"}],
            mutations=[{"actor_agent_id": "fixer"}],
        )
        self.assertEqual(
            identities, {"chief", "candidate", "reviewer", "result", "fixer"}
        )

    def test_role_relabel_cannot_remove_a_producer(self) -> None:
        common = {
            "task_owner": "chief",
            "result_packets": [],
            "mutations": [],
        }
        worker = ri.producer_identity_set(
            **common,
            candidate_packets=[{"agent_role": "worker", "agent_id": "author"}],
        )
        reviewer = ri.producer_identity_set(
            **common,
            candidate_packets=[{"agent_role": "reviewer", "agent_id": "author"}],
        )
        self.assertEqual(worker, reviewer)
        with self.assertRaisesRegex(ri.ReviewIntegrityError, "self-review"):
            ri.validate_reviewer_identity("author", reviewer)

    def test_legacy_identity_omission_is_not_treated_as_independent(self) -> None:
        with self.assertRaisesRegex(ri.ReviewIntegrityError, "explicit agent_id"):
            ri.producer_identity_set(
                task_owner="chief", candidate_packets=[{"agent_role": "worker"}]
            )

    def test_self_review_is_rejected(self) -> None:
        with self.assertRaisesRegex(ri.ReviewIntegrityError, "self-review"):
            ri.validate_reviewer_identity("producer", {"producer"})


class FindingFixVerificationTests(unittest.TestCase):
    def test_zero_finding_review_still_requires_independent_result(self) -> None:
        empty = {
            "task_owner": "chief",
            "candidate_packets": [{"agent_role": "worker", "agent_id": "producer"}],
            "result_packets": [],
            "mutations": [],
            "findings": [],
            "fix_results": [],
            "verifications": [],
            "chains": [],
        }
        self.assertIn(
            "mandatory review result is missing",
            ri.review_integrity_errors(**empty),
        )
        empty["review_result"] = ri.build_review_result(
            reviewer_agent_id="independent",
            producer_agent_ids={"chief", "producer"},
            candidate_snapshot_sha256=SHA["candidate"],
            mutation_snapshot_sha256=SHA["mutation"],
            review_result_sha256=SHA["verification"],
            outcome="clean",
            finding_ids=[],
        )
        self.assertEqual(ri.review_integrity_errors(**empty), [])
        with self.assertRaisesRegex(ri.ReviewIntegrityError, "self-review"):
            ri.build_review_result(
                reviewer_agent_id="producer",
                producer_agent_ids={"chief", "producer"},
                candidate_snapshot_sha256=SHA["candidate"],
                mutation_snapshot_sha256=SHA["mutation"],
                review_result_sha256=SHA["verification"],
                outcome="clean",
                finding_ids=[],
            )

    def test_valid_finding_fix_verification_chain(self) -> None:
        graph = valid_graph()
        self.assertEqual(ri.review_integrity_errors(**graph), [])
        ri.validate_review_integrity(**graph)

    def test_generator_inputs_are_materialized_once(self) -> None:
        graph = valid_graph()
        for key in (
            "candidate_packets",
            "result_packets",
            "mutations",
            "findings",
            "fix_results",
            "verifications",
            "chains",
        ):
            graph[key] = iter(graph[key])  # type: ignore[index, arg-type]
        self.assertEqual(ri.review_integrity_errors(**graph), [])

    def test_duplicate_missing_and_extra_records_are_rejected(self) -> None:
        graph = valid_graph()
        graph["chains"] = []
        graph["fix_results"] = list(graph["fix_results"]) + [
            {
                "finding_id": "extra-1",
                "mutation_snapshot_sha256": SHA["mutation"],
                "fix_result_sha256": SHA["fix"],
            }
        ]
        graph["verifications"] = list(graph["verifications"]) * 2
        errors = ri.review_integrity_errors(**graph)
        self.assertTrue(any("missing review chain" in error for error in errors), errors)
        self.assertTrue(any("extra fix result" in error for error in errors), errors)
        self.assertTrue(any("duplicate verification" in error for error in errors), errors)

    def test_tampered_chain_and_self_review_verification_are_rejected(self) -> None:
        graph = valid_graph()
        graph["chains"][0]["fix_result_sha256"] = "e" * 64  # type: ignore[index]
        graph["verifications"][0]["reviewer_agent_id"] = "fixer"  # type: ignore[index]
        errors = ri.review_integrity_errors(**graph)
        self.assertTrue(any("tampered" in error for error in errors), errors)
        self.assertTrue(any("self-review" in error for error in errors), errors)

    def test_source_snapshot_tamper_is_rejected(self) -> None:
        graph = valid_graph()
        graph["mutations"][0]["candidate_snapshot_sha256"] = "e" * 64  # type: ignore[index]
        errors = ri.review_integrity_errors(**graph)
        self.assertIn("finding finding-1 candidate snapshot binding is tampered", errors)

    def test_review_result_binds_the_complete_finding_graph(self) -> None:
        graph = valid_graph()
        graph["review_result"]["candidate_snapshot_sha256"] = "e" * 64  # type: ignore[index]
        graph["review_result"]["mutation_snapshot_sha256"] = "f" * 64  # type: ignore[index]
        graph["review_result"]["reviewer_agent_id"] = "other-reviewer"  # type: ignore[index]
        graph["review_result"]["finding_ids"] = ["other-finding"]  # type: ignore[index]
        errors = ri.review_integrity_errors(**graph)
        self.assertIn("review result finding set differs from the finding graph", errors)
        self.assertIn("review result candidate snapshot differs from findings", errors)
        self.assertIn("review result mutation snapshot differs from mutations", errors)
        self.assertIn("review result reviewer identity differs from verifications", errors)

    def test_review_result_schema_is_strict_and_bounded(self) -> None:
        graph = valid_graph()
        graph["review_result"]["review_integrity_version"] = 0  # type: ignore[index]
        self.assertIn("review result version is invalid", ri.review_integrity_errors(**graph))

        with self.assertRaisesRegex(ri.ReviewIntegrityError, "must be an array"):
            ri.build_review_result(
                reviewer_agent_id="reviewer",
                producer_agent_ids="producer",
                candidate_snapshot_sha256=SHA["candidate"],
                mutation_snapshot_sha256=SHA["mutation"],
                review_result_sha256=SHA["verification"],
                outcome="clean",
                finding_ids=[],
            )
        with self.assertRaisesRegex(ri.ReviewIntegrityError, "exceeds"):
            ri.build_review_result(
                reviewer_agent_id="reviewer",
                producer_agent_ids=[f"producer-{index}" for index in range(1025)],
                candidate_snapshot_sha256=SHA["candidate"],
                mutation_snapshot_sha256=SHA["mutation"],
                review_result_sha256=SHA["verification"],
                outcome="clean",
                finding_ids=[],
            )

    def test_builder_is_strict_and_deterministic(self) -> None:
        first = ri.build_finding_fix_verification_chain(
            finding_id="finding-1",
            candidate_snapshot_sha256=SHA["candidate"],
            mutation_snapshot_sha256=SHA["mutation"],
            fix_result_sha256=SHA["fix"],
            reviewer_agent_id="reviewer",
            verification_sha256=SHA["verification"],
        )
        second = ri.build_finding_fix_verification_chain(
            finding_id="finding-1",
            candidate_snapshot_sha256=SHA["candidate"],
            mutation_snapshot_sha256=SHA["mutation"],
            fix_result_sha256=SHA["fix"],
            reviewer_agent_id="reviewer",
            verification_sha256=SHA["verification"],
        )
        self.assertEqual(first, second)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.build_finding_fix_verification_chain(
                finding_id="finding-1",
                candidate_snapshot_sha256="bad",
                mutation_snapshot_sha256=SHA["mutation"],
                fix_result_sha256=SHA["fix"],
                reviewer_agent_id="reviewer",
                verification_sha256=SHA["verification"],
            )


if __name__ == "__main__":
    unittest.main()
