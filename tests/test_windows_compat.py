#!/usr/bin/env python3
"""Native Windows portability and durability-boundary tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.pilot import PilotError, initialize_kit  # noqa: E402


CLI_MODULE = "aoi_orgware.cli"


@unittest.skipUnless(os.name == "nt", "native Windows-specific behavior")
class NativeWindowsCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.credential_temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env["AOI_ROOT"] = str(self.root)
        self.env["PYTHONPATH"] = str(SRC)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["AOI_CHIEF_CREDENTIAL_HOME"] = str(
            Path(self.credential_temp.name) / "aoi-chief-credentials"
        )
        subprocess.run(
            ["git", "init", "-b", "main", str(self.root)],
            check=True,
            text=True,
            capture_output=True,
        )
        (self.root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=AOI Test",
                "-c",
                "user.email=aoi@test.invalid",
                "commit",
                "-m",
                "initial",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        self.cli("init", "--project-name", "Native Windows Test")
        acquired = json.loads(
            self.cli(
                "chief-acquire",
                "--session-id",
                "native-windows-test-chief",
                "--json",
            ).stdout
        )
        self.env["AOI_CHIEF_SESSION_ID"] = "native-windows-test-chief"
        self.env["AOI_CHIEF_EPOCH"] = str(acquired["authority"]["epoch"])
        self.env["AOI_CHIEF_CREDENTIAL_FILE"] = acquired["credential_file"]

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.credential_temp.cleanup()

    def cli(self, *args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(args)}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        return result

    def test_native_import_version_help_and_doctor_acl_boundary(self) -> None:
        version = self.cli("--version")
        self.assertIn("AOI", version.stdout)
        self.assertIn("governed multi-agent", self.cli("--help").stdout)
        doctor = json.loads(self.cli("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"])
        self.assertEqual(doctor["platform"]["lock_domain"], "windows-msvcrt-v1")
        self.assertTrue(
            any("windows_acl_unverified" in item for item in doctor["warnings"])
        )

    def test_dpapi_credential_rejects_non_ascii_plaintext_without_traceback(self) -> None:
        protected = h._windows_dpapi_transform(b"\xff", protect=True)
        encoded = base64.b64encode(protected).decode("ascii")
        with self.assertRaisesRegex(
            h.HarnessError, "Chief credential DPAPI payload is malformed"
        ):
            h._decode_chief_secret("dpapi-current-user-v1", encoded)

    def test_ntfs_short_alias_is_canonicalized_without_link_false_positive(self) -> None:
        import ctypes

        buffer = ctypes.create_unicode_buffer(32_768)
        length = ctypes.windll.kernel32.GetShortPathNameW(
            str(self.root.resolve()), buffer, len(buffer)
        )
        candidates = []
        if length and length < len(buffer):
            candidates.append(Path(buffer.value))
        candidates.extend((Path(r"C:\PROGRA~1"), Path(r"C:\PROGRA~2")))
        short_root = next(
            (
                candidate
                for candidate in candidates
                if candidate.exists()
                and candidate.absolute() != candidate.resolve()
            ),
            None,
        )
        if short_root is None:
            self.skipTest("no distinct NTFS short-path spelling is available")

        metadata = short_root.lstat()
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        self.assertFalse(getattr(metadata, "st_file_attributes", 0) & reparse_flag)
        self.assertEqual(
            h.canonicalize_no_link_traversal(short_root, "test alias"),
            short_root.resolve(),
        )
        self.assertEqual(h.discover_root(short_root), short_root.resolve())
        if short_root.resolve() == self.root.resolve():
            self.assertEqual(h.get_paths(short_root).root, self.root.resolve())

    def test_explicit_root_junction_is_still_rejected(self) -> None:
        junction = self.root.parent / f"{self.root.name}-root-junction"
        try:
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(self.root)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation unavailable: {created.stderr}")
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                h.get_paths(junction)
        finally:
            if junction.exists():
                os.rmdir(junction)

    def test_managed_task_junction_rejects_read_write_and_dot_bypass(self) -> None:
        task_id = "managed-junction-boundary"
        self.cli(
            "init-task",
            "--task-id",
            task_id,
            "--title",
            "Managed junction boundary",
            "--objective",
            "Prove dynamic state descendants reject junction traversal",
            "--owner",
            "windows-test",
            "--completion-boundary",
            "Read and write paths fail before crossing the junction",
        )
        paths = h.get_paths(self.root)
        task_path = paths.tasks / task_id
        outside = self.root.parent / f"{self.root.name}-managed-task-target"
        task_path.rename(outside)
        junction = task_path
        try:
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation unavailable: {created.stderr}")
            status = self.cli("status", "--task", task_id, "--json", ok=False)
            self.assertIn("symlinks or junctions", status.stderr)
            escaped = junction / "packets" / "escaped.md"
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                h.atomic_write_text(escaped, "must not escape\n")
            self.assertFalse((outside / "packets" / "escaped.md").exists())
            disguised = (
                paths.tasks
                / "missing"
                / ".."
                / task_id
                / "packets"
                / "escaped.md"
            )
            with self.assertRaisesRegex(h.HarnessError, "parent traversal"):
                h.canonicalize_no_link_traversal(disguised, "disguised task path")
        finally:
            if junction.exists():
                os.rmdir(junction)
            if outside.exists():
                outside.rename(task_path)

    def test_pilot_nested_junction_is_rejected_before_external_write(self) -> None:
        kit = self.root / "pilot-kit-junction"
        outside = self.root.parent / f"{self.root.name}-pilot-target"
        kit.mkdir()
        outside.mkdir()
        junction = kit / "sample_project"
        try:
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation unavailable: {created.stderr}")
            with self.assertRaisesRegex(PilotError, "symlinks or junctions"):
                initialize_kit(
                    kit,
                    force=True,
                    allow_unverified_windows_acl=True,
                    authorized_project_root=self.root,
                )
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            if junction.exists():
                os.rmdir(junction)
            if outside.exists():
                outside.rmdir()

    def test_open_reader_replace_retry_and_timeout_preserve_old_state(self) -> None:
        target = self.root / "replace.json"
        target.write_text("old\n", encoding="utf-8")
        reader = target.open("rb")
        closer = threading.Thread(target=lambda: (time.sleep(0.2), reader.close()))
        closer.start()
        h.atomic_write_text(target, "new\n")
        closer.join(timeout=5)
        self.assertEqual(target.read_text(encoding="utf-8"), "new\n")

        target.write_text("stable\n", encoding="utf-8")
        reader = target.open("rb")
        original_timeout = h.WINDOWS_REPLACE_RETRY_SECONDS
        h.WINDOWS_REPLACE_RETRY_SECONDS = 0.1
        try:
            with self.assertRaisesRegex(h.HarnessError, "atomic replace remained blocked"):
                h.atomic_write_text(target, "must-not-commit\n")
        finally:
            h.WINDOWS_REPLACE_RETRY_SECONDS = original_timeout
            reader.close()
        self.assertEqual(target.read_text(encoding="utf-8"), "stable\n")

    def test_native_host_baseline_uses_real_drive_path(self) -> None:
        target = self.root / "host-baseline.txt"
        target.write_bytes(b"native baseline\n")
        lock = f"host:file:{target.resolve().as_posix()}"
        paths = h.get_paths(self.root)
        baseline = h.baselines_for_locks(paths, [lock])
        canonical = h.normalize_lock(lock)
        self.assertTrue(baseline[canonical]["exists"])
        self.assertEqual(
            baseline[canonical]["sha256"],
            hashlib.sha256(b"native baseline\n").hexdigest(),
        )

    def test_ntfs_short_name_claim_aliases_fail_closed(self) -> None:
        program_files = Path(
            os.environ.get("ProgramFiles", "C:/Program Files")
        ).resolve()
        short_program_files = Path(program_files.anchor) / "PROGRA~1"
        if (
            not short_program_files.is_dir()
            or short_program_files.resolve() != program_files
        ):
            self.skipTest("this Windows volume does not expose the PROGRA~1 alias")

        paths = h.get_paths(self.root)
        long_host_lock = f"host:tree:{program_files.as_posix()}"
        short_host_lock = h.normalize_lock(
            f"host:tree:{short_program_files.as_posix()}"
        )
        accepted_host = self.cli("check-locks", "--lock", long_host_lock, "--json")
        self.assertTrue(json.loads(accepted_host.stdout)["ok"])

        rejected_host = self.cli(
            "check-locks",
            "--lock",
            f"host:tree:{short_program_files.as_posix()}",
            "--json",
            ok=False,
        )
        self.assertEqual(rejected_host.returncode, 2, rejected_host.stderr)
        self.assertRegex(
            rejected_host.stderr,
            "canonical long spelling|NTFS 8.3-style",
        )

        long_repo_directory = self.root / "Long Directory"
        long_repo_directory.mkdir()
        accepted_repo = self.cli(
            "check-locks", "--lock", "repo:tree:Long Directory", "--json"
        )
        self.assertTrue(json.loads(accepted_repo.stdout)["ok"])
        canonical_tilde_directory = self.root / "CANON~1"
        canonical_tilde_directory.mkdir()
        accepted_canonical_tilde = self.cli(
            "check-locks", "--lock", "repo:tree:CANON~1", "--json"
        )
        self.assertTrue(json.loads(accepted_canonical_tilde.stdout)["ok"])
        rejected_repo = self.cli(
            "check-locks",
            "--lock",
            "repo:tree:LONGDI~1",
            "--json",
            ok=False,
        )
        self.assertEqual(rejected_repo.returncode, 2, rejected_repo.stderr)
        self.assertRegex(
            rejected_repo.stderr,
            "canonical long spelling|NTFS 8.3-style",
        )

        self.cli(
            "init-task",
            "--task-id",
            "short-alias-claim",
            "--title",
            "Short alias claim rejection",
            "--objective",
            "Prove claim authority rejects a second NTFS spelling",
            "--owner",
            "native-windows-test",
            "--completion-boundary",
            "No claim artifact may be published",
        )
        self.cli(
            "approve-plan",
            "--task",
            "short-alias-claim",
            "--note",
            "The canonical long-spelling boundary is explicit",
        )
        rejected_claim = self.cli(
            "claim",
            "--task",
            "short-alias-claim",
            "--token",
            "short-alias-claim-token",
            "--owner",
            "native-windows-test",
            "--kind",
            "HOST",
            "--lock",
            f"host:tree:{short_program_files.as_posix()}",
            "--intent",
            "Attempt a duplicate physical lock identity",
            "--validation",
            "The short spelling must fail before publication",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertEqual(rejected_claim.returncode, 2, rejected_claim.stderr)
        self.assertRegex(
            rejected_claim.stderr,
            "canonical long spelling|NTFS 8.3-style",
        )
        self.assertFalse(
            (paths.claims_active / "short-alias-claim-token.json").exists()
        )

        h.atomic_write_json(
            paths.claims_active / "legacy-short-lock.json",
            {
                "schema_version": h.SCHEMA_VERSION,
                "legacy": False,
                "source": "structured",
                "token": "legacy-short-lock",
                "task_id": "short-alias-claim",
                "owner": "legacy-test",
                "kind": "HOST",
                "locks": [short_host_lock],
                "status": "active",
                "worktree": str(self.root.resolve()),
            },
        )
        blocked_by_legacy_alias = self.cli(
            "check-locks", "--lock", long_host_lock, "--json", ok=False
        )
        self.assertEqual(
            blocked_by_legacy_alias.returncode, 2, blocked_by_legacy_alias.stderr
        )
        self.assertRegex(
            blocked_by_legacy_alias.stderr,
            "canonical long spelling|NTFS 8.3-style",
        )

        state = h.load_task(paths, "short-alias-claim")
        state["claims"].append("legacy-short-lock")
        h.bump_task(state)
        h.write_task(paths, state)
        state_path = paths.tasks / "short-alias-claim" / "state.json"
        checkpoint_path = paths.tasks / "short-alias-claim" / "checkpoint.md"
        before_checkpoint_state = state_path.read_bytes()
        before_checkpoint = checkpoint_path.read_bytes()
        rejected_checkpoint = self.cli(
            "checkpoint",
            "--task",
            "short-alias-claim",
            "--next-action",
            "Audit and stale the historical short-name claim",
            ok=False,
        )
        self.assertEqual(
            rejected_checkpoint.returncode, 2, rejected_checkpoint.stderr
        )
        self.assertIn("non-canonical lock authority", rejected_checkpoint.stderr)
        self.assertEqual(state_path.read_bytes(), before_checkpoint_state)
        self.assertEqual(checkpoint_path.read_bytes(), before_checkpoint)
        unhealthy = self.cli("doctor", "--json", ok=False)
        self.assertEqual(unhealthy.returncode, 1, unhealthy.stderr)
        unhealthy_payload = json.loads(unhealthy.stdout)
        self.assertTrue(
            any(
                "claim legacy-short-lock lock authority" in error
                for error in unhealthy_payload["errors"]
            ),
            unhealthy_payload,
        )

        refused_done = self.cli(
            "release-claim",
            "--token",
            "legacy-short-lock",
            "--status",
            "done",
            "--reason",
            "The historical alias cannot be revalidated as canonical",
            ok=False,
        )
        self.assertEqual(refused_done.returncode, 2, refused_done.stderr)
        self.assertIn("--status stale", refused_done.stderr)
        self.cli(
            "release-claim",
            "--token",
            "legacy-short-lock",
            "--status",
            "stale",
            "--reason",
            "Explicitly archive the historical short-name authority after audit",
        )
        archived = h.load_json(paths.claims_archive / "legacy-short-lock.json")
        self.assertIn("canonical long spelling", archived["stale_lock_authority_error"])
        self.assertTrue(archived["baseline_changed"][short_host_lock])
        recovered = json.loads(self.cli("doctor", "--json").stdout)
        self.assertFalse(recovered["errors"], recovered)
        self.assertTrue(
            any(
                "claim legacy-short-lock lock authority" in warning
                for warning in recovered["warnings"]
            ),
            recovered,
        )

    def test_existing_custom_short_lock_spelling_is_rejected_not_rewritten(
        self,
    ) -> None:
        paths = h.get_paths(self.root)
        canonical_root = self.root.resolve()

        def resolve_custom_alias(path: Path, label: str) -> Path:
            candidate = Path(path)
            if candidate.name.casefold() == "custom":
                return candidate.parent / "Long Directory"
            return candidate.resolve(strict=False)

        with mock.patch.object(
            h,
            "canonicalize_no_link_traversal",
            side_effect=resolve_custom_alias,
        ):
            with self.assertRaisesRegex(
                h.HarnessError,
                "must use canonical long spelling.*repo:tree:long directory",
            ):
                h.validate_lock_identity(
                    paths,
                    "repo:tree:CUSTOM",
                    repo_root=canonical_root,
                )

            h.atomic_write_json(
                paths.claims_active / "custom-short-held.json",
                {
                    "schema_version": h.SCHEMA_VERSION,
                    "legacy": False,
                    "source": "structured",
                    "token": "custom-short-held",
                    "task_id": "custom-short-held",
                    "owner": "legacy-test",
                    "kind": "REPO",
                    "locks": ["repo:tree:CUSTOM"],
                    "status": "active",
                    "worktree": str(canonical_root),
                },
            )
            with self.assertRaisesRegex(
                h.HarnessError,
                "claim custom-short-held has non-canonical lock authority",
            ):
                h.find_conflicts(
                    paths,
                    ["repo:tree:Long Directory"],
                    repo_root=canonical_root,
                )

        h.atomic_write_json(
            paths.claims_active / "invalid-worktree-claim.json",
            {
                "schema_version": h.SCHEMA_VERSION,
                "legacy": False,
                "source": "structured",
                "token": "invalid-worktree-claim",
                "task_id": "invalid-worktree-claim",
                "owner": "tamper-test",
                "kind": "REPO",
                "locks": ["repo:file:tracked.txt"],
                "status": "active",
                "worktree": [],
            },
        )
        with self.assertRaisesRegex(
            h.HarnessError,
            "claim invalid-worktree-claim worktree must be a path string",
        ):
            h.find_conflicts(
                paths,
                ["repo:file:tracked.txt"],
                repo_root=canonical_root,
            )

    def test_repo_lock_case_alias_cannot_issue_a_second_claim(self) -> None:
        target = self.root / "CaseTarget.txt"
        target.write_text("one NTFS identity\n", encoding="utf-8")
        self.assertEqual(
            h.normalize_lock("repo:file:CaseTarget.txt"),
            h.normalize_lock("repo:file:casetarget.txt"),
        )

        for task_id in ("case-a", "case-b"):
            self.cli(
                "init-task",
                "--task-id",
                task_id,
                "--title",
                f"Task {task_id}",
                "--objective",
                "Exercise case-insensitive repo ownership",
                "--owner",
                task_id,
                "--completion-boundary",
                "Only one spelling may own the NTFS file",
            )
            self.cli(
                "approve-plan",
                "--task",
                task_id,
                "--note",
                "The exact case-alias ownership boundary is recorded",
            )

        self.cli(
            "claim",
            "--task",
            "case-a",
            "--token",
            "case-claim-a",
            "--owner",
            "case-a",
            "--kind",
            "TEST",
            "--lock",
            "repo:file:CaseTarget.txt",
            "--intent",
            "Reserve the mixed-case file spelling",
            "--validation",
            "Reject a second claim using alternate casing",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        rejected = self.cli(
            "claim",
            "--task",
            "case-b",
            "--token",
            "case-claim-b",
            "--owner",
            "case-b",
            "--kind",
            "TEST",
            "--lock",
            "repo:file:casetarget.txt",
            "--intent",
            "Attempt an alternate-case claim",
            "--validation",
            "The existing claim must conflict",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("claim conflict", rejected.stderr)

    def test_git_merge_lock_case_alias_cannot_issue_a_second_claim(self) -> None:
        self.assertEqual(
            h.normalize_lock("git:merge:Feature"),
            h.normalize_lock("git:merge:feature"),
        )
        for task_id in ("branch-a", "branch-b"):
            self.cli(
                "init-task",
                "--task-id",
                task_id,
                "--title",
                f"Task {task_id}",
                "--objective",
                "Exercise case-insensitive branch ownership",
                "--owner",
                task_id,
                "--completion-boundary",
                "Only one branch spelling may own merge authority",
            )
            self.cli(
                "approve-plan",
                "--task",
                task_id,
                "--note",
                "The exact branch-alias ownership boundary is recorded",
            )

        self.cli(
            "claim",
            "--task",
            "branch-a",
            "--token",
            "branch-claim-a",
            "--owner",
            "branch-a",
            "--kind",
            "GIT",
            "--lock",
            "git:merge:Feature",
            "--intent",
            "Reserve the mixed-case branch spelling",
            "--validation",
            "Reject a second claim using alternate casing",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        rejected = self.cli(
            "claim",
            "--task",
            "branch-b",
            "--token",
            "branch-claim-b",
            "--owner",
            "branch-b",
            "--kind",
            "GIT",
            "--lock",
            "git:merge:feature",
            "--intent",
            "Attempt an alternate-case branch claim",
            "--validation",
            "The existing branch claim must conflict",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("claim conflict", rejected.stderr)

    def test_win32_path_aliases_and_device_names_fail_before_claim(self) -> None:
        self.cli(
            "init-task",
            "--task-id",
            "win32-aliases",
            "--title",
            "Reject Win32 path aliases",
            "--objective",
            "Prevent alternate Win32 spellings from bypassing ownership",
            "--owner",
            "windows-review",
            "--completion-boundary",
            "Every unsafe spelling is rejected before claim persistence",
        )
        self.cli(
            "approve-plan",
            "--task",
            "win32-aliases",
            "--note",
            "Exercise Win32 normalization and namespace aliases",
        )
        unsafe_locks = {
            "trailing-dot": "repo:file:tracked.txt.",
            "trailing-space": "repo:file:tracked.txt ",
            "repo-ads": "repo:file:tracked.txt::$DATA",
            "reserved-device": "repo:file:aux.txt",
            "host-trailing-dot": f"host:file:{self.root.as_posix()}/tracked.txt.",
            "host-trailing-space": f"host:file:{self.root.as_posix()}/tracked.txt ",
            "host-ads": f"host:file:{self.root.as_posix()}/tracked.txt::$DATA",
        }
        for suffix, lock in unsafe_locks.items():
            token = f"win32-alias-{suffix}"
            rejected = self.cli(
                "claim",
                "--task",
                "win32-aliases",
                "--token",
                token,
                "--owner",
                "windows-review",
                "--kind",
                "TEST",
                "--lock",
                lock,
                "--intent",
                "Attempt an unsafe Win32 path spelling",
                "--validation",
                "Normalization must fail before a claim artifact is written",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                ok=False,
            )
            self.assertEqual(rejected.returncode, 2, suffix)
            self.assertFalse(
                (h.get_paths(self.root).claims_active / f"{token}.json").exists(),
                suffix,
            )

    def test_repo_junction_traversal_is_rejected(self) -> None:
        outside = self.root.parent / f"{self.root.name}-junction-target"
        outside.mkdir()
        (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
        junction = self.root / "repo-link"
        try:
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation unavailable: {created.stderr}")
            with self.assertRaisesRegex(h.HarnessError, "symlinks? or junctions?"):
                h.baselines_for_locks(
                    h.get_paths(self.root), ["repo:file:repo-link/secret.txt"]
                )
            with self.assertRaisesRegex(h.HarnessError, "symlinks? or junctions?"):
                h.baselines_for_locks(
                    h.get_paths(self.root), ["repo:tree:repo-link"]
                )
        finally:
            if junction.exists():
                os.rmdir(junction)
            if (outside / "secret.txt").exists():
                (outside / "secret.txt").unlink()
            if outside.exists():
                outside.rmdir()

    def test_state_lock_is_released_when_holder_crashes(self) -> None:
        ready = self.root / "lock-holder-ready"
        code = """
import os
import sys
from pathlib import Path
from aoi_orgware import harnesslib as h

paths = h.get_paths(Path(sys.argv[1]))
with h.state_lock(paths):
    Path(sys.argv[2]).write_text("ready\\n", encoding="utf-8")
    os._exit(7)
"""
        holder = subprocess.Popen(
            [sys.executable, "-c", code, str(self.root), str(ready)],
            cwd=self.root,
            env=self.env,
        )
        deadline = time.monotonic() + 5
        while (
            not ready.exists()
            and holder.poll() is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        self.assertTrue(ready.exists(), "lock holder did not enter its critical section")
        self.assertEqual(holder.wait(timeout=5), 7)
        with h.state_lock(h.get_paths(self.root)):
            pass

    def test_untagged_nonempty_state_requires_posix_migration(self) -> None:
        h.get_paths(self.root).platform.unlink()
        rejected = self.cli("status", "--json", ok=False)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("untagged pre-v0.1.2", rejected.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
