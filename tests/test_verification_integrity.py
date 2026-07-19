#!/usr/bin/env python3
"""Fast contract tests for the extracted verification-integrity boundary."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import verification_integrity as vi  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "verification_integrity.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "aoi_orgware.cli" for alias in node.names):
                    violations.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"cli", "aoi_orgware.cli"} or any(
                    alias.name == "cli" for alias in node.names
                ):
                    violations.append(f"{path.name}:{node.lineno}")
        self.assertEqual(violations, [])


class ModuleSurfaceTests(unittest.TestCase):
    def test_public_surface_is_sorted_and_complete(self) -> None:
        self.assertEqual(vi.__all__, sorted(vi.__all__))
        self.assertEqual(
            set(vi.__all__),
            {
                "SUPERSESSION_MUTATION_FIELDS",
                "VerificationPolicy",
                "verification_integrity_errors",
                "verification_integrity_warnings",
                "verification_legacy_materialization_preimage",
                "verification_legacy_seal_preimage",
                "verification_migration_integrity_errors",
                "verification_record_integrity_errors",
                "verification_source_preimage",
                "verification_supersession_errors",
            },
        )


class VerificationPolicyTests(unittest.TestCase):
    def test_post_init_freezes_category_sets(self) -> None:
        policy = vi.VerificationPolicy(
            verification_categories={"unit_test", "static_check"},
            close_qualifying_categories={"unit_test"},
        )
        self.assertIsInstance(policy.verification_categories, frozenset)
        self.assertIsInstance(policy.close_qualifying_categories, frozenset)
        self.assertEqual(policy.verification_categories, {"unit_test", "static_check"})
        self.assertEqual(policy.close_qualifying_categories, {"unit_test"})

    def test_policy_is_immutable(self) -> None:
        policy = vi.VerificationPolicy(
            verification_categories={"unit_test"},
            close_qualifying_categories={"unit_test"},
        )
        with self.assertRaises(Exception):
            policy.verification_categories = frozenset()  # type: ignore[misc]

    def test_cli_factory_snapshots_live_globals_freshly(self) -> None:
        # The composition-root factory must observe the *current* mutable
        # globals every call, so project-config reloads are never stale.
        from aoi_orgware import cli as cli_impl

        original = cli_impl.VERIFICATION_CATEGORIES
        try:
            cli_impl.VERIFICATION_CATEGORIES = {"unit_test", "sentinel_category"}
            policy = cli_impl._verification_policy()
            self.assertIn("sentinel_category", policy.verification_categories)
            self.assertIsInstance(policy.verification_categories, frozenset)
        finally:
            cli_impl.VERIFICATION_CATEGORIES = original


class PreimageTests(unittest.TestCase):
    def test_source_preimage_strips_metadata_and_restores_status(self) -> None:
        record = {
            "status": "skipped",
            "original_status": "pass",
            "supersession_version": 2,
            "source_record_sha256": "a" * 64,
            "replacement_index": 3,
            "category": "unit_test",
            "nested": {"x": [1]},
        }
        preimage = vi.verification_source_preimage(record)
        self.assertEqual(preimage["status"], "pass")
        for field in vi.SUPERSESSION_MUTATION_FIELDS:
            self.assertNotIn(field, preimage)
        self.assertEqual(preimage["category"], "unit_test")
        # Deep copy: mutating the preimage must not touch the source record.
        preimage["nested"]["x"].append(2)
        self.assertEqual(record["nested"]["x"], [1])
        self.assertEqual(record["status"], "skipped")

    def test_legacy_seal_preimage_strips_seal_fields_only(self) -> None:
        record = {
            "supersession_version": 2,
            "source_record_sha256": "b" * 64,
            "replacement_materialization": {"version": 1},
            "replacement_index": 4,
            "category": "unit_test",
        }
        preimage = vi.verification_legacy_seal_preimage(record)
        self.assertNotIn("supersession_version", preimage)
        self.assertNotIn("source_record_sha256", preimage)
        self.assertNotIn("replacement_materialization", preimage)
        # Non-seal fields survive.
        self.assertEqual(preimage["replacement_index"], 4)
        self.assertEqual(preimage["category"], "unit_test")

    def test_malformed_materialization_refs_raise_harness_error(self) -> None:
        for artifact_refs in ("not-an-array", [[]], [{"snapshot_version": 1}]):
            with self.subTest(artifact_refs=artifact_refs), self.assertRaises(
                vi.HarnessError
            ):
                vi.verification_legacy_materialization_preimage(
                    {"artifact_refs": artifact_refs}
                )


class WarningsTests(unittest.TestCase):
    def test_legacy_live_refs_emit_materialize_warning(self) -> None:
        state = {
            "verification": [
                {"artifact_refs": [{"snapshot_version": 0}]},
            ]
        }
        warnings = vi.verification_integrity_warnings(state)
        self.assertTrue(
            any("uses legacy live artifact references" in w for w in warnings),
            warnings,
        )

    def test_superseded_legacy_refs_emit_superseded_warning(self) -> None:
        state = {
            "verification": [
                {
                    "superseded_at": "2026-01-01T00:00:00Z",
                    "artifact_refs": [{"snapshot_version": 0}],
                },
            ]
        }
        warnings = vi.verification_integrity_warnings(state)
        self.assertTrue(
            any("explicitly superseded with legacy" in w for w in warnings),
            warnings,
        )

    def test_no_legacy_refs_no_warnings(self) -> None:
        state = {"verification": [{"artifact_refs": [{"snapshot_version": 1}]}]}
        self.assertEqual(vi.verification_integrity_warnings(state), [])


class SupersessionErrorsTests(unittest.TestCase):
    def test_metadata_without_superseded_at_is_reported(self) -> None:
        state = {"verification": [{"replacement_index": 2}]}
        errors = vi.verification_supersession_errors(state)
        self.assertTrue(
            any("has supersession metadata without superseded_at" in e for e in errors),
            errors,
        )

    def test_empty_state_has_no_errors(self) -> None:
        self.assertEqual(vi.verification_supersession_errors({}), [])
        self.assertEqual(vi.verification_supersession_errors({"verification": []}), [])

    def test_malformed_later_chain_hop_returns_error_not_attribute_error(self) -> None:
        source = {
            "status": "skipped",
            "category": "unit_test",
            "recorded_at": "2026-01-01T00:00:00Z",
            "original_status": "pass",
            "superseded_at": "2026-01-03T00:00:00Z",
            "supersession_reason": "Replace the exact older verification evidence",
            "supersession_version": 2,
            "source_record_sha256": "a" * 64,
            "replacement_index": 2,
            "replacement_record_sha256": "b" * 64,
        }
        middle = {
            "status": "skipped",
            "category": "unit_test",
            "recorded_at": "2026-01-02T00:00:00Z",
            "superseded_at": "2026-01-04T00:00:00Z",
            "replacement_index": 3,
        }
        errors = vi.verification_supersession_errors(
            {"verification": [source, middle, []]}
        )
        self.assertTrue(
            any("replacement chain record #3 is malformed" in error for error in errors),
            errors,
        )


class RecordIntegrityErrorsTests(unittest.TestCase):
    def _policy(self, categories: set[str]) -> vi.VerificationPolicy:
        return vi.VerificationPolicy(
            verification_categories=categories,
            close_qualifying_categories=categories,
        )

    def test_unknown_category_flagged_against_policy(self) -> None:
        state = {
            "verification": [
                {
                    "integrity_version": 1,
                    "category": "not_a_category",
                    "status": "pass",
                    "evidence": "a bounded observation here",
                    "boundary": "module scope",
                    "command": "pytest -q",
                }
            ]
        }
        errors = vi.verification_record_integrity_errors(
            None, state, policy=self._policy({"unit_test"})
        )
        self.assertTrue(
            any("has unknown category 'not_a_category'" in e for e in errors), errors
        )

    def test_known_category_no_category_error(self) -> None:
        state = {
            "verification": [
                {
                    "integrity_version": 1,
                    "category": "unit_test",
                    "status": "pass",
                    "evidence": "a bounded observation here",
                    "boundary": "module scope",
                    "command": "pytest -q",
                }
            ]
        }
        errors = vi.verification_record_integrity_errors(
            None, state, policy=self._policy({"unit_test"})
        )
        self.assertFalse(any("unknown category" in e for e in errors), errors)

    def test_malformed_category_and_status_return_errors_not_type_errors(self) -> None:
        policy = self._policy({"unit_test"})
        for field in ("category", "status"):
            for malformed in ({}, []):
                record = {
                    "integrity_version": 1,
                    "category": "unit_test",
                    "status": "pass",
                    "evidence": "A bounded verification observation",
                    "boundary": "Exact verification boundary",
                    "command": "pytest -q",
                    "artifact_refs": [],
                    field: malformed,
                }
                with self.subTest(field=field, malformed=malformed):
                    errors = vi.verification_integrity_errors(
                        None, {"verification": [record]}, policy=policy
                    )
                    self.assertTrue(
                        any(
                            phrase in error
                            for error in errors
                            for phrase in ("unknown category", "invalid status")
                        ),
                        errors,
                    )

    def test_missing_integrity_version_short_circuits(self) -> None:
        state = {"verification": [{"category": "unit_test"}]}
        errors = vi.verification_record_integrity_errors(
            None, state, policy=self._policy({"unit_test"})
        )
        self.assertEqual(errors, ["verification #1 lacks integrity_version=1"])

    def test_independent_reviewer_identity_preserves_legacy_read_compatibility(self) -> None:
        record = {
            "integrity_version": 1,
            "category": "independent_review",
            "status": "pass",
            "evidence": "Independent reviewer inspected the bounded candidate",
            "boundary": "Exact candidate only",
            "command": "review exact candidate",
            "review_packet_id": "review-packet",
            "review_result_sha256": "a" * 64,
            "reviewer_agent_id": "/root/reviewer",
            "artifact_refs": [],
        }
        policy = self._policy({"independent_review"})
        for reviewer in (
            "/root/reviewer",
            "legacy reviewer",
            "reviewer+identity",
            "審查者",
        ):
            record["reviewer_agent_id"] = reviewer
            errors = vi.verification_record_integrity_errors(
                None, {"verification": [record]}, policy=policy
            )
            self.assertFalse(
                any("reviewer agent identity" in error for error in errors), errors
            )

        for malformed in ("", None, ["/root/reviewer"], {"id": "reviewer"}, 7):
            record["reviewer_agent_id"] = malformed
            errors = vi.verification_record_integrity_errors(
                None, {"verification": [record]}, policy=policy
            )
            with self.subTest(malformed=malformed):
                self.assertIn("verification #1 lacks reviewer agent identity", errors)


if __name__ == "__main__":
    unittest.main()
