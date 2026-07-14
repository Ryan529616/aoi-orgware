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
        lock = f"host:file:{target.as_posix()}"
        paths = h.get_paths(self.root)
        baseline = h.baselines_for_locks(paths, [lock])
        canonical = h.normalize_lock(lock)
        self.assertTrue(baseline[canonical]["exists"])
        self.assertEqual(
            baseline[canonical]["sha256"],
            hashlib.sha256(b"native baseline\n").hexdigest(),
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
            with self.assertRaisesRegex(h.HarnessError, "symlink or junction"):
                h.baselines_for_locks(
                    h.get_paths(self.root), ["repo:file:repo-link/secret.txt"]
                )
            with self.assertRaisesRegex(h.HarnessError, "symlink or junction"):
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
