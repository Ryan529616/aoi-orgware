#!/usr/bin/env python3
"""Fast contract tests for the extracted evidence-artifact boundary."""

from __future__ import annotations

import ast
import dataclasses
import io
import sys
import tarfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import evidence_artifacts as ea  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


def _make_tar(member: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(member)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class EvidenceArtifactsPolicyTests(unittest.TestCase):
    def test_policy_is_frozen_and_validates_budget(self) -> None:
        policy = ea.EvidenceArtifactsPolicy(bound_artifact_total_max_bytes=42)
        self.assertEqual(policy.bound_artifact_total_max_bytes, 42)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.bound_artifact_total_max_bytes = 7  # type: ignore[misc]
        with self.assertRaisesRegex(ValueError, "must be positive"):
            ea.EvidenceArtifactsPolicy(bound_artifact_total_max_bytes=0)


class RecoveryArchiveMemberTests(unittest.TestCase):
    def test_canonical_member_accepts_relative_posix_and_rejects_traversal(self) -> None:
        self.assertEqual(
            ea.canonical_recovery_archive_member("release/evidence.bin"),
            "release/evidence.bin",
        )
        for bad in (
            "/absolute/evidence.bin",
            "release\\evidence.bin",
            "../evidence.bin",
            "release/../evidence.bin",
            "release//evidence.bin",
            "   ",
        ):
            with self.subTest(member=bad):
                with self.assertRaises(HarnessError):
                    ea.canonical_recovery_archive_member(bad)


class PacketSchemaVersionTests(unittest.TestCase):
    def test_packet_schema_version_requires_exact_non_boolean_integer(self) -> None:
        self.assertEqual(ea._packet_schema_version({"packet_schema_version": 3}), 3)
        self.assertEqual(ea._packet_schema_version({}), 0)
        self.assertIsNone(ea._packet_schema_version({"packet_schema_version": True}))
        self.assertIsNone(ea._packet_schema_version({"packet_schema_version": -1}))
        self.assertIsNone(ea._packet_schema_version({"packet_schema_version": "4"}))


class RecoveryTarReplayPolicyTests(unittest.TestCase):
    def test_bounded_member_read_uses_injected_budget(self) -> None:
        archive = _make_tar("release/evidence.bin", b"payload-bytes")
        generous = ea.EvidenceArtifactsPolicy(bound_artifact_total_max_bytes=1 << 20)
        self.assertEqual(
            ea.read_recovery_tar_member(
                archive, "release/evidence.bin", policy=generous
            ),
            b"payload-bytes",
        )
        starved = ea.EvidenceArtifactsPolicy(bound_artifact_total_max_bytes=1)
        with self.assertRaisesRegex(HarnessError, "budget is exceeded"):
            ea.read_recovery_tar_member(
                archive, "release/evidence.bin", policy=starved
            )


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "evidence_artifacts.py"
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


if __name__ == "__main__":
    unittest.main()
