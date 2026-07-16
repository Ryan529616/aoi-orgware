#!/usr/bin/env python3
"""Fail-closed tests for first-init ``aoi.toml`` publication residue."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.harness_case import CLI_MODULE  # noqa: E402
from tests.test_crash_consistency import AtomicCrashController  # noqa: E402


class ConfigAliasRecoveryTests(AtomicCrashController, unittest.TestCase):
    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, str]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        root = base / "project"
        root.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(root)],
            check=True,
            text=True,
            capture_output=True,
        )
        env = os.environ.copy()
        env.update(
            {
                "AOI_ROOT": str(root),
                "PYTHONPATH": str(SRC),
                "PYTHONDONTWRITEBYTECODE": "1",
                "AOI_CHIEF_CREDENTIAL_HOME": str(base / "credentials"),
                "HOME": str(base / "home"),
                "CODEX_HOME": str(base / "codex-home"),
                "XDG_CONFIG_HOME": str(base / "xdg"),
            }
        )
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            env.pop(name, None)
        return temporary, root, env

    def run_cli(
        self,
        root: Path,
        env: dict[str, str],
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *arguments],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

    def leave_config_create_alias(self, root: Path, payload: bytes) -> tuple[Path, Path]:
        target = root / "aoi.toml"
        descriptor, alias = h._open_atomic_temporary(target, "create")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(alias, target, follow_symlinks=False)
        return target, alias

    def alias_snapshot(
        self, target: Path, alias: Path
    ) -> tuple[bytes, tuple[int, int, int, int, int, int], tuple[int, int, int, int, int, int]]:
        payload = target.read_bytes()

        def stable_stat(path: Path) -> tuple[int, int, int, int, int, int]:
            metadata = path.lstat()
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
            )

        return payload, stable_stat(target), stable_stat(alias)

    def assert_alias_unchanged(
        self,
        target: Path,
        alias: Path,
        before: tuple[
            bytes,
            tuple[int, int, int, int, int, int],
            tuple[int, int, int, int, int, int],
        ],
    ) -> None:
        self.assertTrue(target.is_file())
        self.assertTrue(alias.is_file())
        self.assertTrue(os.path.samefile(target, alias))
        self.assertEqual(self.alias_snapshot(target, alias), before)
        self.assertEqual(target.stat().st_nlink, 2)

    def assert_no_governance_artifacts(
        self, root: Path, env: dict[str, str]
    ) -> None:
        self.assertFalse(os.path.lexists(root / ".aoi"))
        self.assertFalse(
            os.path.lexists(Path(env["AOI_CHIEF_CREDENTIAL_HOME"]))
        )

    def test_all_commands_refuse_root_config_hardlink_without_mutation(self) -> None:
        cases = (
            ("chief-acquire", "--session-id", "alias-chief", "--json"),
            ("init", "--project-name", "Existing Alias", "--json"),
            ("recover-temporaries", "--json"),
        )
        for index, arguments in enumerate(cases):
            with self.subTest(arguments=arguments):
                _temporary, root, env = self.make_project()
                payload = default_config_text(f"Alias Residue {index}").encode("utf-8")
                target, alias = self.leave_config_create_alias(root, payload)
                before = self.alias_snapshot(target, alias)

                rejected = self.run_cli(root, env, *arguments)

                self.assertEqual(
                    rejected.returncode,
                    2,
                    f"stdout={rejected.stdout!r}\nstderr={rejected.stderr!r}",
                )
                self.assert_alias_unchanged(target, alias, before)
                self.assert_no_governance_artifacts(root, env)

    @unittest.skipIf(os.name == "nt", "POSIX hard-link publication protocol")
    def test_linked_init_kill_is_preserved_and_chief_acquire_fails_closed(
        self,
    ) -> None:
        _temporary, root, env = self.make_project()
        target = root / "aoi.toml"
        listener, initializer = self.start_observed_worker(
            destination=target,
            stage="linked",
            mode="cli",
            env=env,
            cwd=root,
            command=["init", "--project-name", "Config Crash", "--json"],
        )
        connection: socket.socket | None = None
        try:
            connection, event = self.await_event(listener, initializer)
            alias = Path(event["temporary"])
            initializer.kill()
            initializer.communicate(timeout=10)
            self.assertNotEqual(initializer.returncode, 0)
        finally:
            listener.close()
            if connection is not None:
                connection.close()
            if initializer.poll() is None:
                initializer.kill()
                initializer.communicate(timeout=5)

        before = self.alias_snapshot(target, alias)
        rejected = self.run_cli(
            root,
            env,
            "chief-acquire",
            "--session-id",
            "config-crash-chief",
            "--json",
        )

        self.assertEqual(
            rejected.returncode,
            2,
            f"stdout={rejected.stdout!r}\nstderr={rejected.stderr!r}",
        )
        self.assert_alias_unchanged(target, alias, before)
        self.assert_no_governance_artifacts(root, env)

    def test_prelink_config_temp_is_non_stranding_but_remains_manual_root_residue(
        self,
    ) -> None:
        _temporary, root, env = self.make_project()
        target = root / "aoi.toml"
        listener, initializer = self.start_observed_worker(
            destination=target,
            stage="temp_fsynced",
            mode="cli",
            env=env,
            cwd=root,
            command=["init", "--project-name", "Prelink Crash", "--json"],
        )
        connection: socket.socket | None = None
        try:
            connection, event = self.await_event(listener, initializer)
            residue = Path(event["temporary"])
            self.assertFalse(target.exists())
            self.assertTrue(residue.is_file())
            self.assertEqual(residue.stat().st_nlink, 1)
            self.assertIsNotNone(h.ATOMIC_TEMP_NAME_RE.fullmatch(residue.name))
            initializer.kill()
            initializer.communicate(timeout=10)
        finally:
            listener.close()
            if connection is not None:
                connection.close()
            if initializer.poll() is None:
                initializer.kill()
                initializer.communicate(timeout=5)

        resumed = self.run_cli(
            root,
            env,
            "init",
            "--project-name",
            "Prelink Crash",
            "--json",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertTrue(residue.exists())
        self.assertEqual(residue.read_bytes(), target.read_bytes())

        acquired = self.run_cli(
            root,
            env,
            "chief-acquire",
            "--session-id",
            "prelink-chief",
            "--json",
        )
        self.assertEqual(acquired.returncode, 0, acquired.stderr)
        self.assertTrue(residue.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
