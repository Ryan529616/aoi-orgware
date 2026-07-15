#!/usr/bin/env python3
"""Fast contract tests for the extracted git-plumbing boundary."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import git_plumbing as gp  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class CommitRegexTests(unittest.TestCase):
    def test_full_commit_re_requires_forty_to_sixty_four_hex(self) -> None:
        self.assertTrue(gp.FULL_COMMIT_RE.fullmatch("a" * 40))
        self.assertTrue(gp.FULL_COMMIT_RE.fullmatch("a" * 64))
        self.assertIsNone(gp.FULL_COMMIT_RE.fullmatch("a" * 39))
        self.assertIsNone(gp.FULL_COMMIT_RE.fullmatch("z" * 40))

    def test_require_full_commit_normalizes_case_and_rejects_short_ids(self) -> None:
        self.assertEqual(gp.require_full_commit("A" * 40, "commit"), "a" * 40)
        with self.assertRaisesRegex(HarnessError, "full 40-64 hex"):
            gp.require_full_commit("abc123", "commit")
        with self.assertRaisesRegex(HarnessError, "may not be empty"):
            gp.require_full_commit("   ", "commit")


class GitMetadataTests(unittest.TestCase):
    def test_git_metadata_rejects_missing_directory(self) -> None:
        with self.assertRaisesRegex(HarnessError, "worktree does not exist"):
            gp.git_metadata(Path("this-path-should-not-exist-anywhere-12345"))

    def test_git_is_ancestor_rejects_unknown_worktree(self) -> None:
        with self.assertRaises((HarnessError, OSError)):
            gp.git_is_ancestor(
                Path("this-path-should-not-exist-anywhere-12345"), "HEAD", "HEAD"
            )


class RemoteRefTipTests(unittest.TestCase):
    def test_remote_ref_tip_rejects_invalid_remote_name(self) -> None:
        with self.assertRaisesRegex(HarnessError, "invalid Git remote name"):
            gp.remote_ref_tip(Path("."), "bad remote!", "refs/heads/main")

    def test_remote_ref_tip_rejects_non_canonical_ref(self) -> None:
        with self.assertRaisesRegex(HarnessError, "must be a full refs/heads"):
            gp.remote_ref_tip(Path("."), "origin", "main")


class LegacyAmbiguitiesTests(unittest.TestCase):
    def test_legacy_ambiguities_returns_empty_for_missing_pending_dir(self) -> None:
        class FakePaths:
            legacy_pending = Path("this-legacy-pending-dir-should-not-exist-12345")

        self.assertEqual(gp.legacy_ambiguities(FakePaths()), [])  # type: ignore[arg-type]


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "git_plumbing.py"
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
