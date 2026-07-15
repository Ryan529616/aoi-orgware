#!/usr/bin/env python3
"""Fast contract tests for the extracted context-receipt boundary."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import context_receipts as cr  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "context_receipts.py"
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
        self.assertEqual(cr.__all__, sorted(cr.__all__))
        self.assertEqual(
            set(cr.__all__),
            {
                "benchmark_ledger_preimage",
                "context_benchmark_integrity_errors",
                "context_provider_brief_bindings",
                "context_receipt_integrity_errors",
                "context_receipt_reports",
                "validate_benchmark_ledger_record",
            },
        )


class BenchmarkLedgerPreimageTests(unittest.TestCase):
    def test_strips_record_sha256_and_deep_copies(self) -> None:
        record = {
            "benchmark_id": "b1",
            "record_sha256": "deadbeef",
            "nested": {"values": [1, 2]},
        }
        preimage = cr.benchmark_ledger_preimage(record)
        self.assertNotIn("record_sha256", preimage)
        self.assertEqual(preimage, {"benchmark_id": "b1", "nested": {"values": [1, 2]}})
        # Deep copy: mutating the preimage must not touch the source record.
        preimage["nested"]["values"].append(3)
        self.assertEqual(record["nested"]["values"], [1, 2])
        self.assertIn("record_sha256", record)

    def test_absent_record_sha256_is_tolerated(self) -> None:
        preimage = cr.benchmark_ledger_preimage({"benchmark_id": "b2"})
        self.assertEqual(preimage, {"benchmark_id": "b2"})


class ContextBenchmarkIntegrityErrorsTests(unittest.TestCase):
    def test_empty_state_reports_no_errors(self) -> None:
        self.assertEqual(cr.context_benchmark_integrity_errors(None, {}), [])
        self.assertEqual(
            cr.context_benchmark_integrity_errors(
                None, {"context_provider_benchmarks": []}
            ),
            [],
        )

    def test_duplicate_benchmark_id_is_reported(self) -> None:
        # Malformed field-sets fail validation before any paths access, so the
        # duplicate-id guard can be exercised without a HarnessPaths fixture.
        state = {
            "context_provider_benchmarks": [
                {"benchmark_id": "dup"},
                {"benchmark_id": "dup"},
            ]
        }
        errors = cr.context_benchmark_integrity_errors(None, state)
        self.assertTrue(
            any("codebase-memory benchmark id is duplicated: dup" in e for e in errors),
            errors,
        )


class ValidateBenchmarkLedgerRecordTests(unittest.TestCase):
    def test_non_dict_record_is_rejected(self) -> None:
        with self.assertRaisesRegex(HarnessError, "must be an object"):
            cr.validate_benchmark_ledger_record(None, {}, ["not", "a", "dict"])

    def test_unexpected_field_set_is_rejected(self) -> None:
        with self.assertRaisesRegex(HarnessError, "ledger fields are invalid"):
            cr.validate_benchmark_ledger_record(None, {}, {"benchmark_id": "b1"})


if __name__ == "__main__":
    unittest.main()
