#!/usr/bin/env python3
"""Doctor and recovery policy for AOI atomic-publication residues."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from tests.harness_case import CLI_MODULE, HarnessTestCase  # noqa: E402
from tests.test_crash_consistency import AtomicCrashController  # noqa: E402


class AtomicTemporaryRecoveryTests(AtomicCrashController, HarnessTestCase):
    def interrupted_prefix(
        self, name: str
    ) -> tuple[Path, h.HarnessPaths, dict[str, str]]:
        root = Path(self.backup_temp.name) / f"prelink-{name}"
        root.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(root)],
            check=True,
            text=True,
            capture_output=True,
        )
        (root / "aoi.toml").write_text(
            cli_impl.default_config_text(f"Pre-link {name}"), encoding="utf-8"
        )
        paths = h.get_paths(root)
        paths.harness.mkdir()
        self.assertTrue(h._create_platform_marker(paths.platform))
        h.ensure_layout(paths)
        self.assertFalse(paths.lock.exists())
        self.assertFalse(paths.chief_authority.exists())

        environment = self.env.copy()
        environment["AOI_ROOT"] = str(root)
        environment["AOI_CHIEF_CREDENTIAL_HOME"] = str(
            Path(self.backup_temp.name) / f"credentials-{name}"
        )
        for variable in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(variable, None)
        return root, paths, environment

    def run_prefix_cli(
        self,
        root: Path,
        environment: dict[str, str],
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *arguments],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

    def leave_state_lock_prelink_temporary(
        self,
        paths: h.HarnessPaths,
        payload: bytes,
        *,
        operation: str = "create",
        target: Path | None = None,
    ) -> Path:
        descriptor, temporary = h._open_atomic_temporary(
            target or paths.lock, operation
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary

    def leave_unpublished_temporary(
        self, target: Path, payload: bytes, *, operation: str = "write"
    ) -> Path:
        descriptor, temporary = h._open_atomic_temporary(target, operation)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary

    def leave_v1_unpublished_temporary(
        self, target: Path, payload: bytes, *, operation: str = "write"
    ) -> Path:
        temporary = target.parent / (
            f".aoi-tmp-v1.{operation}.{h._atomic_target_name_sha256(target)}."
            f"{'0' * 32}.tmp"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary

    def fresh_project(
        self, name: str
    ) -> tuple[Path, h.HarnessPaths, dict[str, str]]:
        root = Path(self.backup_temp.name) / name
        root.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(root)],
            check=True,
            text=True,
            capture_output=True,
        )
        (root / "aoi.toml").write_text(
            cli_impl.default_config_text(f"Strict bootstrap {name}"),
            encoding="utf-8",
        )
        paths = h.get_paths(root)
        environment = self.env.copy()
        environment["AOI_ROOT"] = str(root)
        environment["AOI_CHIEF_CREDENTIAL_HOME"] = str(
            Path(self.backup_temp.name) / f"credentials-{name}"
        )
        for variable in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(variable, None)
        return root, paths, environment

    def complete_prefix(
        self, name: str
    ) -> tuple[Path, h.HarnessPaths, dict[str, str]]:
        root, _paths, environment = self.fresh_project(name)
        (root / "aoi.toml").unlink()
        initialized = self.run_prefix_cli(
            root,
            environment,
            "init",
            "--project-name",
            f"Strict complete {name}",
            "--json",
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        paths = h.get_paths(root)
        h.require_complete_layout(paths)
        self.assertFalse(os.path.lexists(paths.chief_authority))
        self.assertFalse(
            os.path.lexists(Path(environment["AOI_CHIEF_CREDENTIAL_HOME"]))
        )
        return root, paths, environment

    def recovery_snapshot(
        self, root: Path, environment: dict[str, str]
    ) -> tuple[object, object]:
        def capture(path: Path) -> object:
            if not os.path.lexists(path):
                return ("missing",)
            metadata = path.lstat()
            common = (
                int(metadata.st_dev),
                int(metadata.st_ino),
                stat.S_IMODE(metadata.st_mode),
                int(metadata.st_nlink),
                int(metadata.st_size),
            )
            if h._path_is_link_like(path):
                try:
                    target = os.readlink(path)
                except OSError:
                    target = "<unreadable-link>"
                return ("link", *common, target)
            if stat.S_ISDIR(metadata.st_mode):
                return (
                    "directory",
                    *common,
                    tuple(
                        (child.name, capture(child))
                        for child in sorted(path.iterdir(), key=lambda item: item.name)
                    ),
                )
            if stat.S_ISREG(metadata.st_mode):
                return ("file", *common, path.read_bytes())
            return ("special", stat.S_IFMT(metadata.st_mode), *common)

        project = tuple(
            (entry.name, capture(entry))
            for entry in sorted(root.iterdir(), key=lambda item: item.name)
            if entry.name != ".git"
        )
        credential_home = capture(
            Path(environment["AOI_CHIEF_CREDENTIAL_HOME"])
        )
        return project, credential_home

    def assert_chief_bootstrap_refused_without_mutation(
        self,
        root: Path,
        paths: h.HarnessPaths,
        environment: dict[str, str],
        *,
        session_id: str,
        expected_fragment: str,
    ) -> None:
        before = self.recovery_snapshot(root, environment)
        rejected = self.run_prefix_cli(
            root,
            environment,
            "chief-acquire",
            "--session-id",
            session_id,
            "--json",
        )
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        self.assertNotIn("Traceback", rejected.stderr)
        self.assertIn(expected_fragment, rejected.stderr)
        self.assertEqual(self.recovery_snapshot(root, environment), before)
        self.assertFalse(paths.chief_authority.is_file())
        self.assertFalse(
            os.path.lexists(Path(environment["AOI_CHIEF_CREDENTIAL_HOME"]))
        )

    def test_missing_and_empty_lock_matrix_is_cross_platform_fail_closed(
        self,
    ) -> None:
        cases: list[
            tuple[str, Path, h.HarnessPaths, dict[str, str], str]
        ] = []

        root, paths, environment = self.complete_prefix("complete-missing")
        paths.lock.unlink()
        cases.append(("complete-missing", root, paths, environment, "manual recovery"))

        root, paths, environment = self.complete_prefix("complete-empty")
        paths.lock.write_bytes(b"")
        cases.append(("complete-empty", root, paths, environment, "manual recovery"))

        root, paths, environment = self.fresh_project("minimal-missing")
        cases.append(("minimal-missing", root, paths, environment, "manual recovery"))

        root, paths, environment = self.interrupted_prefix("structural-missing")
        cases.append(("structural-missing", root, paths, environment, "manual recovery"))

        for name, root, paths, environment, expected in cases:
            with self.subTest(shape=name):
                self.assert_chief_bootstrap_refused_without_mutation(
                    root,
                    paths,
                    environment,
                    session_id=f"strict-{name}",
                    expected_fragment=expected,
                )

    def test_non_regular_state_lock_is_cross_platform_fail_closed(self) -> None:
        root, paths, environment = self.complete_prefix("lock-directory")
        paths.lock.unlink()
        paths.lock.mkdir()

        self.assert_chief_bootstrap_refused_without_mutation(
            root,
            paths,
            environment,
            session_id="strict-lock-directory",
            expected_fragment="manual recovery",
        )

    def test_hardlinked_state_lock_is_cross_platform_fail_closed(self) -> None:
        root, paths, environment = self.complete_prefix("lock-hardlink")
        alias = root / "state-lock-hardlink-alias"
        os.link(paths.lock, alias)
        self.assertEqual(paths.lock.stat().st_nlink, 2)
        self.assertTrue(os.path.samefile(paths.lock, alias))

        self.assert_chief_bootstrap_refused_without_mutation(
            root,
            paths,
            environment,
            session_id="strict-lock-hardlink",
            expected_fragment="manual recovery",
        )
        self.assertEqual(paths.lock.stat().st_nlink, 2)
        self.assertTrue(os.path.samefile(paths.lock, alias))

    def test_recovery_and_doctor_never_repair_a_state_lock_alias(self) -> None:
        root, paths, environment = self.complete_prefix("lock-alias-dead-routing")
        alias = root / "state-lock-alias-dead-routing"
        os.link(paths.lock, alias)
        before = self.recovery_snapshot(root, environment)

        recovery = self.run_prefix_cli(
            root,
            environment,
            "recover-temporaries",
            "--json",
        )
        self.assertEqual(recovery.returncode, 2, recovery.stderr)
        self.assertNotIn("Traceback", recovery.stderr)
        self.assertNotIn("state_lock_alias_repaired", recovery.stdout)
        self.assertEqual(self.recovery_snapshot(root, environment), before)

        doctor = self.run_prefix_cli(root, environment, "doctor", "--json")
        self.assertIn(doctor.returncode, {1, 2}, doctor.stderr)
        self.assertNotIn("Traceback", doctor.stderr)
        self.assertNotIn("state_lock_alias_repaired", doctor.stdout)
        self.assertEqual(self.recovery_snapshot(root, environment), before)
        self.assertEqual(paths.lock.stat().st_nlink, 2)
        self.assertTrue(os.path.samefile(paths.lock, alias))

    def test_nul_and_empty_hardlink_alias_matrix_is_fail_closed(self) -> None:
        for label, payload in (("nul-alias", b"\0"), ("empty-alias", b"")):
            with self.subTest(shape=label):
                root, paths, environment = self.complete_prefix(label)
                paths.lock.unlink()
                descriptor, temporary = h._open_atomic_temporary(
                    paths.lock, "create"
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.link(temporary, paths.lock, follow_symlinks=False)
                self.assertEqual(paths.lock.stat().st_nlink, 2)
                self.assertTrue(os.path.samefile(temporary, paths.lock))

                self.assert_chief_bootstrap_refused_without_mutation(
                    root,
                    paths,
                    environment,
                    session_id=f"strict-{label}",
                    expected_fragment="manual recovery",
                )
                self.assertTrue(temporary.exists())
                self.assertEqual(paths.lock.stat().st_nlink, 2)
                self.assertTrue(os.path.samefile(temporary, paths.lock))

    @unittest.skipIf(os.name == "nt", "POSIX symlink and mode boundaries")
    def test_posix_symlink_and_wrong_mode_matrix_is_fail_closed(self) -> None:
        root, paths, environment = self.complete_prefix("lock-symlink")
        outside = root / "outside-state-lock"
        outside.write_bytes(b"\0")
        outside.chmod(0o600)
        paths.lock.unlink()
        paths.lock.symlink_to(outside)
        self.assert_chief_bootstrap_refused_without_mutation(
            root,
            paths,
            environment,
            session_id="strict-lock-symlink",
            expected_fragment="manual recovery",
        )

        root, paths, environment = self.complete_prefix("lock-public-mode")
        paths.lock.chmod(0o644)
        self.assert_chief_bootstrap_refused_without_mutation(
            root,
            paths,
            environment,
            session_id="strict-lock-public-mode",
            expected_fragment="permissions are not private",
        )

    def make_dangling_authority_link(self, paths: h.HarnessPaths) -> None:
        try:
            paths.chief_authority.symlink_to("missing-chief-authority.json")
            return
        except OSError:
            if os.name != "nt":
                raise
        target = paths.harness / "missing-chief-authority-target"
        target.mkdir()
        linked = subprocess.run(
            [
                "cmd",
                "/c",
                "mklink",
                "/J",
                str(paths.chief_authority),
                str(target),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(linked.returncode, 0, linked.stderr or linked.stdout)
        target.rmdir()

    def test_ready_nul_with_dangling_authority_is_fail_closed(self) -> None:
        root, paths, environment = self.complete_prefix("dangling-authority")
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        self.make_dangling_authority_link(paths)
        self.assertTrue(h._path_is_link_like(paths.chief_authority))

        self.assert_chief_bootstrap_refused_without_mutation(
            root,
            paths,
            environment,
            session_id="strict-dangling-authority",
            expected_fragment="regular non-linked file",
        )

    def test_canonical_nul_complete_layout_can_acquire_chief(self) -> None:
        root, paths, environment = self.complete_prefix("complete-ready-nul")
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        self.assertEqual(paths.lock.stat().st_nlink, 1)

        acquired = self.run_prefix_cli(
            root,
            environment,
            "chief-acquire",
            "--session-id",
            "complete-ready-chief",
            "--json",
        )

        self.assertEqual(acquired.returncode, 0, acquired.stderr)
        payload = json.loads(acquired.stdout)
        self.assertEqual(payload["authority"]["session_id"], "complete-ready-chief")
        self.assertTrue(paths.chief_authority.is_file())
        self.assertTrue(Path(payload["credential_file"]).is_file())

    def test_ready_nul_config_drift_before_lock_acquisition_is_fail_closed(
        self,
    ) -> None:
        root, paths, environment = self.interrupted_prefix("ready-nul-config-race")
        h.atomic_create_bytes(paths.lock, b"\0")
        before = self.recovery_snapshot(root, environment)
        config_before = paths.config.read_text(encoding="utf-8")
        config_after = config_before.replace(
            'state_dir = ".aoi"', 'state_dir = ".aoi-raced"'
        ).replace(
            'high_risk_paths = [".aoi/",',
            'high_risk_paths = [".aoi-raced/",',
        )
        self.assertNotEqual(config_after, config_before)
        listener, acquisition = self.start_observed_worker(
            destination=paths.lock,
            stage="before_acquire",
            mode="cli",
            env=environment,
            cwd=root,
            command=[
                "chief-acquire",
                "--session-id",
                "ready-nul-config-race-chief",
                "--json",
            ],
        )
        connection = None
        try:
            connection, event = self.await_event(listener, acquisition)
            self.assertEqual(event["operation"], "state_lock")
            self.assertEqual(event["stage"], "before_acquire")
            paths.config.write_text(config_after, encoding="utf-8")
            connection.sendall(b"G")
            connection.close()
            connection = None
            stdout, stderr = acquisition.communicate(timeout=15)
        finally:
            listener.close()
            if connection is not None:
                connection.close()
            if acquisition.poll() is None:
                acquisition.kill()
                acquisition.communicate(timeout=5)

        self.assertEqual(
            acquisition.returncode,
            2,
            stderr.decode("utf-8", "replace"),
        )
        self.assertEqual(stdout, b"")
        self.assertIn(b"aoi.toml changed", stderr)
        self.assertEqual(paths.config.read_text(encoding="utf-8"), config_after)
        self.assertFalse(paths.chief_authority.exists())
        self.assertFalse(
            os.path.lexists(Path(environment["AOI_CHIEF_CREDENTIAL_HOME"]))
        )
        self.assertFalse((root / ".aoi-raced").exists())
        paths.config.write_text(config_before, encoding="utf-8")
        self.assertEqual(self.recovery_snapshot(root, environment), before)

    def test_ready_nul_interrupted_prefix_can_acquire_then_authenticated_init(
        self,
    ) -> None:
        root, paths, environment = self.interrupted_prefix("ready-nul")
        h.atomic_create_bytes(paths.lock, b"\0")
        temporary = self.leave_state_lock_prelink_temporary(paths, b"\0")
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        self.assertEqual(paths.lock.stat().st_nlink, 1)
        self.assertEqual(temporary.read_bytes(), b"\0")
        self.assertEqual(temporary.stat().st_nlink, 1)
        self.assertFalse(paths.chief_authority.exists())

        acquired = self.run_prefix_cli(
            root,
            environment,
            "chief-acquire",
            "--session-id",
            "interrupted-ready-chief",
            "--json",
        )

        self.assertEqual(acquired.returncode, 0, acquired.stderr)
        acquisition = json.loads(acquired.stdout)
        self.assertEqual(
            acquisition["authority"]["session_id"], "interrupted-ready-chief"
        )
        self.assertTrue(
            temporary.exists(),
            "Chief bootstrap must leave an inert pre-link temporary untouched",
        )
        unauthenticated = self.run_prefix_cli(
            root,
            environment,
            "recover-temporaries",
            "--json",
        )
        self.assertEqual(unauthenticated.returncode, 2, unauthenticated.stderr)
        self.assertIn(
            "Chief session id and epoch are required", unauthenticated.stderr
        )
        self.assertTrue(temporary.exists())

        authenticated = environment.copy()
        authenticated["AOI_CHIEF_SESSION_ID"] = "interrupted-ready-chief"
        authenticated["AOI_CHIEF_EPOCH"] = str(
            acquisition["authority"]["epoch"]
        )
        authenticated["AOI_CHIEF_CREDENTIAL_FILE"] = acquisition[
            "credential_file"
        ]
        recovered = self.run_prefix_cli(
            root,
            authenticated,
            "recover-temporaries",
            "--json",
        )
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        recovery = json.loads(recovered.stdout)
        self.assertEqual(len(recovery["recovered"]), 1)
        self.assertEqual(recovery["recovered"][0]["path"], temporary.name)
        self.assertFalse(temporary.exists())
        initialized = self.run_prefix_cli(
            root,
            authenticated,
            "init",
            "--json",
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        h.require_complete_layout(h.get_paths(root))

    def test_v1_ready_nul_interrupted_prefix_can_still_acquire_chief(self) -> None:
        root, paths, environment = self.interrupted_prefix("ready-nul-v1")
        h.atomic_create_bytes(paths.lock, b"\0")
        temporary = self.leave_v1_unpublished_temporary(
            paths.lock, b"\0", operation="create"
        )

        acquired = self.run_prefix_cli(
            root,
            environment,
            "chief-acquire",
            "--session-id",
            "interrupted-ready-v1-chief",
            "--json",
        )

        self.assertEqual(acquired.returncode, 0, acquired.stderr)
        authority = json.loads(acquired.stdout)["authority"]
        self.assertEqual(authority["session_id"], "interrupted-ready-v1-chief")
        self.assertTrue(
            temporary.exists(),
            "Chief bootstrap must leave the historical pre-link residue inert",
        )
        self.assertEqual(temporary.read_bytes(), b"\0")
        self.assertEqual(temporary.stat().st_nlink, 1)

    def checkpoint_command(self, task_id: str) -> list[str]:
        return [
            "checkpoint",
            "--task",
            task_id,
            "--fact",
            "Temporary recovery test boundary",
            "--next-action",
            "Recover only the exact interrupted checkpoint temporary",
            "--json",
        ]

    def test_doctor_waits_for_writer_then_reports_and_recovery_converges(self) -> None:
        task_id = "temporary-recovery"
        self.init_task(task_id)
        paths = h.get_paths(self.root)
        checkpoint_path = h.task_dir(paths, task_id) / "checkpoint.md"
        listener, writer = self.start_observed_worker(
            destination=checkpoint_path,
            stage="temp_fsynced",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.checkpoint_command(task_id),
        )
        connection = None
        doctor = None
        try:
            connection, _event = self.await_event(listener, writer)
            doctor = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "doctor",
                    "--task",
                    task_id,
                    "--json",
                ],
                cwd=self.root,
                env=self.env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            self.assertIsNone(
                doctor.poll(),
                "doctor returned while a cooperative writer still held the state lock",
            )
            writer.kill()
            writer.communicate(timeout=10)
            doctor_stdout, doctor_stderr = doctor.communicate(timeout=15)
            self.assertEqual(doctor.returncode, 1, doctor_stderr)
            doctor_payload = json.loads(doctor_stdout)
            self.assertFalse(doctor_payload["ok"])
            self.assertEqual(len(doctor_payload["temporary_files"]), 1)
            self.assertEqual(
                doctor_payload["temporary_files"][0]["classification"],
                "unpublished",
            )
            temporary_path = (
                paths.harness / doctor_payload["temporary_files"][0]["path"]
            )
            self.assertTrue(temporary_path.exists())
        finally:
            listener.close()
            if connection is not None:
                connection.close()
            if writer.poll() is None:
                writer.kill()
                writer.communicate(timeout=5)
            if doctor is not None and doctor.poll() is None:
                doctor.kill()
                doctor.communicate(timeout=5)

        unauthenticated = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            unauthenticated.pop(name, None)
        recovered = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "recover-temporaries",
                "--json",
            ],
            cwd=self.root,
            env=unauthenticated,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(recovered.returncode, 2, recovered.stderr)
        self.assertIn("Chief session id and epoch are required", recovered.stderr)
        self.assertTrue(temporary_path.exists())

        recovered_payload = json.loads(
            self.cli("recover-temporaries", "--json").stdout
        )
        self.assertEqual(len(recovered_payload["recovered"]), 1)
        self.assertEqual(recovered_payload["remaining"], [])
        self.assertFalse(temporary_path.exists())
        clean = json.loads(self.cli("doctor", "--task", task_id, "--json").stdout)
        self.assertTrue(clean["ok"], clean)
        self.assertEqual(clean["temporary_files"], [])

        repeated = json.loads(
            self.cli("recover-temporaries", "--json").stdout
        )
        self.assertEqual(repeated["recovered"], [])

    def test_ordinary_write_exception_removes_the_named_temporary(self) -> None:
        target = self.root / ".aoi" / "ordinary-write.json"
        target.write_bytes(b"old\n")
        real_fdopen = os.fdopen

        class FailingWriter:
            def __init__(self, handle: object) -> None:
                self.handle = handle

            def __enter__(self) -> "FailingWriter":
                self.handle.__enter__()
                return self

            def __exit__(self, *args: object) -> object:
                return self.handle.__exit__(*args)

            def write(self, _payload: bytes) -> int:
                raise OSError("injected write failure")

        def failing_fdopen(descriptor: int, *args: object, **kwargs: object) -> object:
            return FailingWriter(real_fdopen(descriptor, *args, **kwargs))

        with mock.patch.object(h.os, "fdopen", side_effect=failing_fdopen):
            with self.assertRaisesRegex(OSError, "injected write failure"):
                h.atomic_write_bytes(target, b"new\n")

        self.assertEqual(target.read_bytes(), b"old\n")
        self.assertEqual(
            [
                path
                for path in target.parent.iterdir()
                if h.ATOMIC_TEMP_NAME_RE.fullmatch(path.name)
            ],
            [],
        )

    def test_v1_unpublished_temporary_remains_recoverable(self) -> None:
        paths = h.get_paths(self.root)
        temporary = self.leave_v1_unpublished_temporary(
            paths.index, b"historical v1 residue\n"
        )

        recovered = json.loads(self.cli("recover-temporaries", "--json").stdout)

        self.assertEqual([item["path"] for item in recovered["recovered"]], [temporary.name])
        self.assertFalse(temporary.exists())

    def test_v1_published_create_alias_remains_recoverable(self) -> None:
        paths = h.get_paths(self.root)
        target = paths.tasks / "historical-create.json"
        temporary = self.leave_v1_unpublished_temporary(
            target, b"historical v1 publication\n", operation="create"
        )
        os.link(temporary, target, follow_symlinks=False)

        recovered = json.loads(self.cli("recover-temporaries", "--json").stdout)

        self.assertEqual(
            recovered["recovered"],
            [
                {
                    "path": f"tasks/{temporary.name}",
                    "operation": "create",
                    "target_name_sha256": h._atomic_target_name_sha256(target),
                    "classification": "published_create_alias",
                    "recoverable": True,
                    "target": "tasks/historical-create.json",
                }
            ],
        )
        self.assertFalse(temporary.exists())
        self.assertEqual(target.read_bytes(), b"historical v1 publication\n")

    def test_v2_published_create_alias_reports_canonical_hex_digest(self) -> None:
        paths = h.get_paths(self.root)
        target = paths.tasks / "current-create.json"
        temporary = self.leave_unpublished_temporary(
            target, b"current v2 publication\n", operation="create"
        )
        self.assertIsNotNone(h.ATOMIC_TEMP_V2_NAME_RE.fullmatch(temporary.name))
        os.link(temporary, target, follow_symlinks=False)

        recovered = json.loads(self.cli("recover-temporaries", "--json").stdout)

        record = recovered["recovered"]
        self.assertEqual(len(record), 1)
        self.assertEqual(record[0]["target_name_sha256"], h._atomic_target_name_sha256(target))
        self.assertRegex(record[0]["target_name_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(record[0]["classification"], "published_create_alias")
        self.assertFalse(temporary.exists())
        self.assertEqual(target.read_bytes(), b"current v2 publication\n")

    def test_v2_parser_rejects_noncanonical_base64url_digest(self) -> None:
        temporary = h._atomic_temporary_basename(self.root / "INDEX.md", "write")
        parsed = h._parse_atomic_temporary_name(temporary)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        prefix, _operation, digest, _target_sha256, nonce = parsed
        self.assertEqual(prefix, "v2")
        for replacement in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":
            if replacement == digest[-1]:
                continue
            malformed = f".aoi-v2-w.{digest[:-1]}{replacement}.{nonce}"
            if h._parse_atomic_temporary_name(malformed) is None:
                break
        else:
            self.fail("could not construct a noncanonical v2 base64url digest")
        self.assertIsNotNone(h.ATOMIC_TEMP_V2_NAME_RE.fullmatch(malformed))
        self.assertIsNone(h._parse_atomic_temporary_name(malformed))

    @unittest.skipUnless(os.name == "nt", "native Windows path budget regression")
    def test_v2_atomic_temporaries_fit_a_native_windows_deep_path(self) -> None:
        parent = Path(self.backup_temp.name)
        probe = h._atomic_temporary_basename(parent / "written.json", "write")
        while len(str(parent / probe)) < 245:
            candidate = parent / f"deep-{len(parent.parts):02d}-segment"
            if len(str(candidate / probe)) > 250:
                break
            parent = candidate
        parent.mkdir(parents=True)
        create_target = parent / "created.json"
        write_target = parent / "written.json"
        write_target.write_bytes(b"old\n")
        observed: list[h._AtomicIOEvent] = []

        with h._observe_atomic_io(observed.append):
            h.atomic_create_bytes(create_target, b"created\n")
            h.atomic_write_bytes(write_target, b"written\n")

        temporaries = [
            event.temporary
            for event in observed
            if event.stage == "temp_fsynced" and event.temporary is not None
        ]
        self.assertEqual(len(temporaries), 2)
        for temporary in temporaries:
            assert temporary is not None
            self.assertIsNotNone(h.ATOMIC_TEMP_V2_NAME_RE.fullmatch(temporary.name))
            self.assertLessEqual(len(str(temporary)), 250)
        self.assertGreater(
            len(
                str(
                    parent
                    / (
                        f".aoi-tmp-v1.write."
                        f"{h._atomic_target_name_sha256(write_target)}."
                        f"{'0' * 32}.tmp"
                    )
                )
            ),
            259,
        )
        self.assertEqual(create_target.read_bytes(), b"created\n")
        self.assertEqual(write_target.read_bytes(), b"written\n")

    @unittest.skipUnless(os.name == "nt", "native Windows path budget regression")
    def test_v2_deep_path_residues_scan_and_recover(self) -> None:
        paths = h.get_paths(self.root)
        parent = paths.tasks
        probe = h._atomic_temporary_basename(parent / "pending.json", "write")
        while len(str(parent / probe)) < 245:
            candidate = parent / f"deep-recovery-{len(parent.parts):02d}"
            if len(str(candidate / probe)) > 250:
                break
            parent = candidate
        parent.mkdir(parents=True)
        write_target = parent / "pending.json"
        create_target = parent / "published.json"
        unpublished = self.leave_unpublished_temporary(
            write_target, b"unpublished\n"
        )
        published_alias = self.leave_unpublished_temporary(
            create_target, b"published\n", operation="create"
        )
        os.link(published_alias, create_target, follow_symlinks=False)
        for temporary in (unpublished, published_alias):
            self.assertIsNotNone(h.ATOMIC_TEMP_V2_NAME_RE.fullmatch(temporary.name))
            self.assertLessEqual(len(str(temporary)), 250)

        recovered = json.loads(self.cli("recover-temporaries", "--json").stdout)

        expected = {
            unpublished.relative_to(paths.harness).as_posix(),
            published_alias.relative_to(paths.harness).as_posix(),
        }
        self.assertEqual(
            {item["path"] for item in recovered["recovered"]}, expected
        )
        self.assertFalse(unpublished.exists())
        self.assertFalse(published_alias.exists())
        self.assertEqual(create_target.read_bytes(), b"published\n")

    def test_ambiguous_reserved_entry_causes_zero_deletions(self) -> None:
        paths = h.get_paths(self.root)
        valid = self.leave_unpublished_temporary(paths.index, b"future index\n")
        malformed = paths.harness / ".aoi-tmp-v1.write.not-valid.tmp"
        malformed.write_bytes(b"ambiguous\n")

        rejected = self.cli("recover-temporaries", "--json", ok=False)

        self.assertIn("no files were removed", rejected.stderr)
        self.assertTrue(valid.exists())
        self.assertTrue(malformed.exists())

    def test_legacy_shaped_directory_is_a_doctor_error_not_a_warning(self) -> None:
        paths = h.get_paths(self.root)
        legacy_directory = paths.harness / ".legacy.tmp-abc"
        legacy_directory.mkdir()

        doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        self.assertNotIn("Traceback", doctor.stderr)
        payload = json.loads(doctor.stdout)
        self.assertFalse(payload["ok"])
        record = next(
            item
            for item in payload["temporary_files"]
            if item["path"] == legacy_directory.name
        )
        self.assertEqual(record["classification"], "legacy_ambiguous")
        self.assertTrue(
            any("ambiguous AOI temporary" in error for error in payload["errors"]),
            payload,
        )

    def test_recovery_process_kill_is_idempotently_resumable(self) -> None:
        paths = h.get_paths(self.root)
        temporaries = sorted(
            [
                self.leave_unpublished_temporary(
                    paths.harness / "recovery-a.json", b"first\n"
                ),
                self.leave_unpublished_temporary(
                    paths.harness / "recovery-b.json", b"second\n"
                ),
            ]
        )

        self.kill_at_boundary(
            destination=temporaries[0],
            stage="unlinked",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=["recover-temporaries", "--json"],
        )

        self.assertFalse(temporaries[0].exists())
        self.assertTrue(temporaries[1].exists())
        resumed = json.loads(
            self.cli("recover-temporaries", "--json").stdout
        )
        self.assertEqual(len(resumed["recovered"]), 1)
        self.assertFalse(temporaries[1].exists())

    def test_hardlinked_write_temporary_is_ambiguous_and_not_removed(self) -> None:
        paths = h.get_paths(self.root)
        temporary = self.leave_v1_unpublished_temporary(paths.index, b"future index\n")
        alias = paths.harness / "untrusted-hardlink-copy"
        os.link(temporary, alias)

        rejected = self.cli("recover-temporaries", "--json", ok=False)

        self.assertIn("ambiguous", rejected.stderr)
        self.assertTrue(temporary.exists())
        self.assertTrue(alias.exists())

    def test_platform_domain_mismatch_fails_before_recovery_mutation(self) -> None:
        paths = h.get_paths(self.root)
        temporary = self.leave_unpublished_temporary(paths.index, b"future index\n")
        marker = json.loads(paths.platform.read_text(encoding="utf-8"))
        marker["lock_domain"] = (
            "posix-flock-v1"
            if h.runtime_lock_domain() == "windows-msvcrt-v1"
            else "windows-msvcrt-v1"
        )
        paths.platform.write_text(
            json.dumps(marker, indent=2) + "\n", encoding="utf-8"
        )

        rejected = self.cli("recover-temporaries", "--json", ok=False)

        self.assertIn("lock domain", rejected.stderr)
        self.assertTrue(temporary.exists())

    def test_config_race_before_lock_acquisition_causes_zero_recovery(self) -> None:
        paths = h.get_paths(self.root)
        temporary = self.leave_unpublished_temporary(paths.index, b"future index\n")
        listener, recovery = self.start_observed_worker(
            destination=paths.lock,
            stage="before_acquire",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=["recover-temporaries", "--json"],
        )
        connection = None
        try:
            connection, event = self.await_event(listener, recovery)
            self.assertEqual(event["operation"], "state_lock")
            self.assertEqual(event["stage"], "before_acquire")
            config_before = paths.config.read_text(encoding="utf-8")
            config_after = config_before.replace(
                'state_dir = ".aoi"', 'state_dir = ".aoi-raced"'
            ).replace(
                'high_risk_paths = [".aoi/",',
                'high_risk_paths = [".aoi-raced/",',
            )
            self.assertNotEqual(config_after, config_before)
            paths.config.write_text(config_after, encoding="utf-8")
            connection.sendall(b"G")
            stdout, stderr = recovery.communicate(timeout=15)
        finally:
            listener.close()
            if connection is not None:
                connection.close()
            if recovery.poll() is None:
                recovery.kill()
                recovery.communicate(timeout=5)

        self.assertEqual(recovery.returncode, 2, stderr.decode("utf-8", "replace"))
        self.assertEqual(stdout, b"")
        self.assertIn(b"aoi.toml changed while acquiring", stderr)
        self.assertTrue(temporary.exists())
        self.assertFalse((self.root / ".aoi-raced").exists())



if __name__ == "__main__":
    unittest.main(verbosity=2)
