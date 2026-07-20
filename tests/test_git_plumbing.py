#!/usr/bin/env python3
"""Fast contract tests for the extracted git-plumbing boundary."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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


class TempGitRepoTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is required")
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self._git("init", "-q")
        self._git("config", "user.email", "tests@example.invalid")
        self._git("config", "user.name", "AOI test")
        for name, content in {
            "base.txt": b"base\n",
            "delete.txt": b"delete\n",
            "rename-source.txt": b"rename\n",
        }.items():
            (self.repo / name).write_bytes(content)
        self._git("add", ".")
        self._git("commit", "-qm", "baseline")
        self.baseline = self._git("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            text=True,
            capture_output=True,
        ).stdout

    def test_status_snapshot_is_deterministic_and_stream_bounded(self) -> None:
        (self.repo / "base.txt").write_bytes(b"drift\n")
        (self.repo / "untracked.txt").write_bytes(b"new\n")
        first = gp.git_status_snapshot(self.repo)
        second = gp.git_status_snapshot(self.repo)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], gp.GIT_STATUS_SNAPSHOT_SCHEMA)
        self.assertEqual(
            {base64.b64decode(item).decode("utf-8") for item in first["mutation_paths_b64"]},
            {"base.txt", "untracked.txt"},
        )
        with mock.patch.object(gp, "MAX_GIT_STATUS_BYTES", 2):
            with self.assertRaisesRegex(HarnessError, "byte bound"):
                gp.git_status_snapshot(self.repo)

    def test_name_status_keeps_both_case_only_rename_endpoints(self) -> None:
        records = gp._parse_git_name_status(b"R100\x00src/name.py\x00src/Name.py\x00")
        self.assertEqual(
            [base64.b64decode(item) for item in [
                records[0]["source_path_b64"], records[0]["path_b64"]
            ]],
            [b"src/name.py", b"src/Name.py"],
        )


class MutationClaimCoverageTests(unittest.TestCase):
    def test_coverage_requires_rename_source_destination_and_other_mutations(self) -> None:
        mutations = ["src/Name.py", "src/name.py", "deleted.py", "new.py"]
        claims = [
            {"status": "active", "locks": ["repo:tree:src"]},
            {"status": "blocked", "locks": ["repo:file:deleted.py"]},
            {"status": "released", "locks": ["repo:file:new.py"]},
        ]
        result = gp.mutation_claim_coverage(mutations, claims)
        self.assertFalse(result["covered"])
        self.assertEqual(
            result["uncovered_paths_b64"],
            [base64.b64encode(b"new.py").decode("ascii")],
        )

        claims[2]["status"] = "active"
        self.assertTrue(gp.mutation_claim_coverage(mutations, claims)["covered"])

    def test_coverage_rejects_non_utf8_or_malformed_claim_authority(self) -> None:
        with self.assertRaisesRegex(HarnessError, "not valid UTF-8"):
            gp.mutation_claim_coverage([b"bad-\xff"], [])
        with self.assertRaisesRegex(HarnessError, "invalid lock URI"):
            gp.mutation_claim_coverage(
                ["owned.py"], [{"status": "active", "locks": ["not-a-lock"]}]
            )

    def test_snapshot_coverage_requires_untampered_canonical_snapshot(self) -> None:
        snapshot = {
            "schema": gp.GIT_STATUS_SNAPSHOT_SCHEMA,
            "records": [
                {
                    "record": "2",
                    "path_b64": base64.b64encode(b"new.py").decode("ascii"),
                    "source_path_b64": base64.b64encode(b"old.py").decode("ascii"),
                }
            ],
            "mutation_paths_b64": [
                base64.b64encode(b"new.py").decode("ascii"),
                base64.b64encode(b"old.py").decode("ascii"),
            ],
        }
        snapshot["snapshot_sha256"] = hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        result = gp.git_status_claim_coverage(
            snapshot, [{"status": "active", "locks": ["repo:file:new.py"]}]
        )
        self.assertFalse(result["covered"])
        self.assertEqual(
            result["uncovered_paths_b64"], [base64.b64encode(b"old.py").decode("ascii")]
        )
        snapshot["snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(HarnessError, "digest"):
            gp.git_status_claim_coverage(snapshot, [])


class TaskMutationSnapshotTests(TempGitRepoTests):
    TASK_ID = "task-1"

    def test_snapshot_captures_committed_staged_untracked_delete_and_rename_without_index_write(self) -> None:
        (self.repo / "committed.txt").write_bytes(b"committed\n")
        self._git("add", "committed.txt")
        self._git("commit", "-qm", "post-baseline")
        (self.repo / "base.txt").write_bytes(b"unstaged\n")
        (self.repo / "staged.txt").write_bytes(b"staged\n")
        self._git("add", "staged.txt")
        (self.repo / "delete.txt").unlink()
        self._git("mv", "rename-source.txt", "rename-destination.txt")
        (self.repo / "untracked.txt").write_bytes(b"untracked\n")
        index = self.repo / ".git" / "index"
        index_before = index.read_bytes()

        snapshot = gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)

        self.assertEqual(snapshot["schema"], gp.GIT_MUTATION_SNAPSHOT_SCHEMA)
        self.assertEqual(snapshot["task_id"], self.TASK_ID)
        self.assertEqual(snapshot["baseline_head"], self.baseline)
        self.assertEqual(index.read_bytes(), index_before)
        paths = {base64.b64decode(item).decode("utf-8") for item in snapshot["mutation_paths_b64"]}
        self.assertEqual(
            paths,
            {
                "base.txt",
                "committed.txt",
                "delete.txt",
                "rename-source.txt",
                "rename-destination.txt",
                "staged.txt",
                "untracked.txt",
            },
        )
        entries = {
            base64.b64decode(item["path_b64"]).decode("utf-8"): item for item in snapshot["paths"]
        }
        self.assertTrue(entries["delete.txt"]["absent"])
        self.assertFalse(entries["base.txt"]["absent"])
        self.assertEqual(entries["base.txt"]["content_sha256"], hashlib.sha256(b"unstaged\n").hexdigest())
        self.assertTrue(any(item["record"] == "2" for item in snapshot["porcelain_v2"]))
        self.assertEqual(
            {item["status"] for item in snapshot["baseline_to_current_name_status"]}, {"A"}
        )

    def test_byte_drift_changes_canonical_digest(self) -> None:
        (self.repo / "base.txt").write_bytes(b"first\n")
        first = gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)
        (self.repo / "base.txt").write_bytes(b"second\n")
        second = gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_exact_task_claim_coverage_rejects_other_and_terminal_scope(self) -> None:
        (self.repo / "base.txt").write_bytes(b"drift\n")
        snapshot = gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)
        claims = [
            {"task_id": "other", "status": "active", "locks": ["repo:tree:"]},
            {"task_id": self.TASK_ID, "status": "done", "locks": ["repo:file:base.txt"]},
        ]
        result = gp.task_mutation_snapshot_claim_coverage(snapshot, claims)
        self.assertFalse(result["covered"])
        claims.append(
            {
                "task_id": self.TASK_ID,
                "token": "live-base",
                "owner": "owner-a",
                "status": "active",
                "worktree": str(self.repo.resolve()),
                "locks": ["repo:file:base.txt"],
            }
        )
        covered = gp.task_mutation_snapshot_claim_coverage(snapshot, claims)
        self.assertTrue(covered["covered"])
        self.assertEqual(covered["covered_claim_tokens"], ["live-base"])
        self.assertEqual(covered["paths"][0]["covering_claim_tokens"], ["live-base"])
        digest = covered["claim_scope_sha256"]
        sealed = [
            {
                "task_id": self.TASK_ID,
                "token": "live-base",
                "owner": "owner-a",
                "status": "released",
                "worktree": str(self.repo.resolve()),
                "locks": ["repo:file:base.txt"],
            }
        ]
        validated = gp.validate_sealed_task_claim_scope(
            self.TASK_ID,
            covered["covered_claim_tokens"],
            digest,
            sealed,
            str(self.repo.resolve()),
        )
        self.assertEqual(validated["claim_scope_sha256"], digest)
        self.assertEqual(validated["claims"], [{"token": "live-base", "observed_status": "released"}])
        lock_tamper = [dict(item) for item in sealed]
        lock_tamper[0]["locks"] = ["repo:file:other.txt"]
        with self.assertRaisesRegex(HarnessError, "digest does not match"):
            gp.validate_sealed_task_claim_scope(
                self.TASK_ID, covered["covered_claim_tokens"], digest, lock_tamper, str(self.repo.resolve())
            )
        foreign_token = [dict(item) for item in sealed]
        foreign_token[0]["task_id"] = "other"
        with self.assertRaisesRegex(HarnessError, "foreign task claim"):
            gp.validate_sealed_task_claim_scope(
                self.TASK_ID, covered["covered_claim_tokens"], digest, foreign_token, str(self.repo.resolve())
            )
        unknown_status = [dict(item) for item in sealed]
        unknown_status[0]["status"] = "unknown"
        with self.assertRaisesRegex(HarnessError, "unsupported status"):
            gp.validate_sealed_task_claim_scope(
                self.TASK_ID, covered["covered_claim_tokens"], digest, unknown_status, str(self.repo.resolve())
            )
        claims.append(
            {
                "task_id": "foreign",
                "token": "foreign-token",
                "owner": "foreign-owner",
                "status": "active",
                "worktree": "foreign-worktree",
                "locks": ["repo:tree:src"],
            }
        )
        claims.append({"task_id": self.TASK_ID, "status": "released", "locks": ["repo:tree:src"]})
        self.assertEqual(gp.task_mutation_snapshot_claim_coverage(snapshot, claims)["claim_scope_sha256"], digest)
        tampered = [dict(item) for item in claims]
        tampered[2]["owner"] = "owner-b"
        self.assertNotEqual(gp.task_mutation_snapshot_claim_coverage(snapshot, tampered)["claim_scope_sha256"], digest)
        duplicate = [dict(item) for item in claims]
        duplicate.append(
            {
                "task_id": self.TASK_ID,
                "token": "live-base",
                "owner": "owner-c",
                "status": "blocked",
                "worktree": str(self.repo.resolve()),
                "locks": ["repo:file:other.txt"],
            }
        )
        with self.assertRaisesRegex(HarnessError, "duplicate live task claim token"):
            gp.task_mutation_snapshot_claim_coverage(snapshot, duplicate)
        invalid = [dict(item) for item in claims]
        invalid[2]["locks"] = "repo:file:base.txt"
        with self.assertRaisesRegex(HarnessError, "locks must be a non-empty list"):
            gp.task_mutation_snapshot_claim_coverage(snapshot, invalid)
        wrong_worktree = [dict(item) for item in claims]
        wrong_worktree[2]["worktree"] = "not-the-snapshot-worktree"
        with self.assertRaisesRegex(HarnessError, "worktree differs"):
            gp.task_mutation_snapshot_claim_coverage(snapshot, wrong_worktree)
        snapshot["paths"][0]["absent"] = True
        with self.assertRaisesRegex(HarnessError, "unexpected metadata"):
            gp.task_mutation_snapshot_claim_coverage(snapshot, claims)

    def test_persisted_snapshot_scope_rejects_self_consistent_uncovered_path(self) -> None:
        """A digest over one covered token cannot hide a second uncovered path."""

        (self.repo / "base.txt").write_bytes(b"drift\n")
        (self.repo / "uncovered.txt").write_bytes(b"new\n")
        snapshot = gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)
        claim = {
            "task_id": self.TASK_ID,
            "token": "base-only",
            "owner": "owner-a",
            "status": "active",
            "worktree": str(self.repo.resolve()),
            "locks": ["repo:file:base.txt"],
        }
        self_consistent = gp.task_mutation_snapshot_claim_coverage(snapshot, [claim])
        self.assertFalse(self_consistent["covered"])
        self.assertEqual(self_consistent["covered_claim_tokens"], ["base-only"])

        with self.assertRaisesRegex(HarnessError, "uncovered paths"):
            gp.validate_task_mutation_snapshot_claim_scope(
                snapshot,
                self_consistent["covered_claim_tokens"],
                self_consistent["claim_scope_sha256"],
                [claim],
                sealed=False,
            )

        claim["status"] = "released"
        with self.assertRaisesRegex(HarnessError, "uncovered paths"):
            gp.validate_task_mutation_snapshot_claim_scope(
                snapshot,
                self_consistent["covered_claim_tokens"],
                self_consistent["claim_scope_sha256"],
                [claim],
                sealed=True,
            )

    def test_full_live_claim_authority_binds_clean_claim_set(self) -> None:
        worktree = str(self.repo.resolve())
        claim = {
            "task_id": self.TASK_ID,
            "token": "source-a",
            "owner": "owner-a",
            "status": "active",
            "worktree": worktree,
            "locks": ["repo:tree:src"],
        }
        authority = gp.capture_task_live_claim_authority(
            self.TASK_ID, [claim], worktree
        )
        self.assertEqual(authority["claim_tokens"], ["source-a"])
        self.assertEqual(
            gp.validate_task_claim_authority(
                authority, [claim], sealed=False
            ),
            authority,
        )

        added = [
            claim,
            {
                "task_id": self.TASK_ID,
                "token": "source-b",
                "owner": "owner-b",
                "status": "active",
                "worktree": worktree,
                "locks": ["repo:file:base.txt"],
            },
        ]
        with self.assertRaisesRegex(HarnessError, "complete live claim scope"):
            gp.validate_task_claim_authority(
                authority, added, sealed=False
            )
        lock_drift = [{**claim, "locks": ["repo:file:base.txt"]}]
        with self.assertRaisesRegex(HarnessError, "complete live claim scope"):
            gp.validate_task_claim_authority(
                authority, lock_drift, sealed=False
            )
        for label, drift in (
            ("owner", [{**claim, "owner": "owner-b"}]),
            ("status", [{**claim, "status": "blocked"}]),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    HarnessError, "complete live claim scope"
                ):
                    gp.validate_task_claim_authority(
                        authority, drift, sealed=False
                    )
        wrong_worktree = [{**claim, "worktree": str(self.repo / "other")}]
        with self.assertRaisesRegex(HarnessError, "worktree differs"):
            gp.validate_task_claim_authority(
                authority, wrong_worktree, sealed=False
            )

        released = [{**claim, "status": "released"}]
        self.assertEqual(
            gp.validate_task_claim_authority(
                authority, released, sealed=True
            ),
            authority,
        )
        with self.assertRaisesRegex(HarnessError, "missing|scope"):
            gp.validate_task_claim_authority(
                authority, released, sealed=False
            )

    def test_rejects_symlink(self) -> None:
        target = self.repo / "target.txt"
        target.write_bytes(b"target\n")
        (self.repo / "base.txt").unlink()
        try:
            os.symlink(target, self.repo / "base.txt")
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(HarnessError, "symlink or reparse"):
            gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)

    def test_rejects_non_utf8_and_output_bound(self) -> None:
        with self.assertRaisesRegex(HarnessError, "not valid UTF-8"):
            gp.task_mutation_claim_coverage(self.TASK_ID, [b"bad-\xff"], [])
        with self.assertRaisesRegex(HarnessError, "cannot be claimed"):
            gp._claimable_utf8_paths([b"cannot:claim.txt"])
        (self.repo / "base.txt").write_bytes(b"bounded\n")
        with mock.patch.object(gp, "MAX_GIT_STATUS_BYTES", 2):
            with self.assertRaisesRegex(HarnessError, "byte bound"):
                gp.task_mutation_snapshot(self.TASK_ID, self.repo, self.baseline)


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
