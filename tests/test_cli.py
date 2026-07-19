#!/usr/bin/env python3
"""Unit and integration tests for dependency-free AOI orgware."""

from __future__ import annotations

import argparse
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import __version__ as AOI_VERSION  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import codex_install_provenance as codex_install_provenance_impl  # noqa: E402
from aoi_orgware import evidence_artifacts as evidence_artifacts_impl  # noqa: E402
from aoi_orgware import git_plumbing as git_plumbing_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import integrity_records as integrity_records_impl  # noqa: E402
from aoi_orgware import semantic_events as semantic_events_impl  # noqa: E402


CLI_MODULE = "aoi_orgware.cli"
HOOK_MODULE = "aoi_orgware.codex_hook"

from tests.harness_case import HarnessTestCase  # noqa: E402
from tests.test_commands_codex_onboarding import (  # noqa: E402
    fake_local_provenance_receipt,
)


class AtomicPrimitiveTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX fchmod allocation path")
    def test_atomic_temporary_fchmod_failure_closes_and_unlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "state.json"
            descriptors: list[int] = []
            real_open = os.open

            def capture_open(*args: object, **kwargs: object) -> int:
                descriptor = real_open(*args, **kwargs)
                descriptors.append(descriptor)
                return descriptor

            with mock.patch.object(h.os, "open", side_effect=capture_open), mock.patch.object(
                h.os, "fchmod", side_effect=OSError("injected fchmod failure")
            ):
                with self.assertRaisesRegex(OSError, "injected fchmod failure"):
                    h._open_atomic_temporary(destination, "write")

            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
            self.assertEqual(list(root.iterdir()), [])

    def test_atomic_create_publishes_complete_bytes_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "atomic" / "blob.bin"
            payload = b"complete immutable payload\n"
            observed: list[tuple[bool, bytes]] = []
            publish_name = "rename" if os.name == "nt" else "link"
            real_publish = getattr(os, publish_name)

            def inspect_then_publish(
                source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                **kwargs: object,
            ) -> None:
                observed.append((Path(target).exists(), Path(source).read_bytes()))
                real_publish(source, target, **kwargs)

            with mock.patch.object(
                h.os, publish_name, side_effect=inspect_then_publish
            ), mock.patch.object(
                h.os, "chmod", side_effect=AssertionError("path chmod is forbidden")
            ):
                h.atomic_create_bytes(destination, payload)

            self.assertEqual(observed, [(False, payload)])
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(
                [
                    path.name
                    for path in destination.parent.iterdir()
                    if h.ATOMIC_TEMP_NAME_RE.fullmatch(path.name)
                ],
                [],
            )

            before = destination.read_bytes()
            with self.assertRaises(h.HarnessError):
                h.atomic_create_bytes(destination, b"replacement must fail\n")
            self.assertEqual(destination.read_bytes(), before)

    def test_recovery_tar_replay_uses_one_shared_aggregate_budget(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            member = tarfile.TarInfo("release/evidence.bin")
            member.size = 1
            handle.addfile(member, io.BytesIO(b"x"))
        archive_data = archive.getvalue()
        budget = {
            "decompressed_bytes": 0,
            "member_count": 0,
            "declared_bytes": 0,
            "extracted_bytes": 0,
        }
        with mock.patch.object(
            cli_impl,
            "BOUND_ARTIFACT_TOTAL_MAX_BYTES",
            len(archive_data) + 1,
        ):
            self.assertEqual(
                cli_impl.read_recovery_tar_member(
                    archive_data,
                    "release/evidence.bin",
                    budget=budget,
                ),
                b"x",
            )
            with self.assertRaisesRegex(
                h.HarnessError, "aggregate decompressed budget"
            ):
                cli_impl.read_recovery_tar_member(
                    archive_data,
                    "release/evidence.bin",
                    budget=budget,
                )
        malformed_gzip = (
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\xff" * 20
        )
        with self.assertRaisesRegex(h.HarnessError, "recovery archive is invalid"):
            cli_impl.read_recovery_tar_member(malformed_gzip, "release/evidence.bin")

    @unittest.skipIf(os.name == "nt", "POSIX symlink boundary; junction is tested natively")
    def test_managed_reads_and_writes_reject_descendant_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            managed = root / "managed"
            outside = root / "outside"
            managed.mkdir()
            outside.mkdir()
            link = managed / "task"
            link.symlink_to(outside, target_is_directory=True)
            destination = link / "state.json"
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                h.atomic_write_bytes(destination, b"{}\n")
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                h.atomic_create_bytes(destination, b"{}\n")
            self.assertEqual(list(outside.iterdir()), [])

            (outside / "state.json").write_text('{"outside": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                h.load_json(destination)
            disguised = managed / "missing" / ".." / "task" / "state.json"
            with self.assertRaisesRegex(h.HarnessError, "parent traversal"):
                h.canonicalize_no_link_traversal(disguised, "disguised state")
            linked_parent = link / ".." / "managed" / "state.json"
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                h.canonicalize_no_link_traversal(linked_parent, "linked parent state")


class ChiefAuthorityTests(HarnessTestCase):
    def filesystem_snapshot(self, root: Path) -> dict[str, tuple[object, ...]]:
        """Capture identities, modes, link targets, and bytes without following links."""

        if not os.path.lexists(root):
            return {".": ("missing",)}
        snapshot: dict[str, tuple[object, ...]] = {}
        pending = [root]
        while pending:
            current = pending.pop()
            metadata = current.lstat()
            relative = "." if current == root else current.relative_to(root).as_posix()
            identity = (
                int(metadata.st_dev),
                int(metadata.st_ino),
                int(metadata.st_nlink),
                stat.S_IMODE(metadata.st_mode),
            )
            if h._path_is_link_like(current):
                try:
                    target = os.readlink(current)
                except OSError:
                    target = "<unreadable-reparse-target>"
                snapshot[relative] = ("link", *identity, target)
            elif stat.S_ISDIR(metadata.st_mode):
                snapshot[relative] = ("directory", *identity)
                pending.extend(sorted(current.iterdir(), reverse=True))
            elif stat.S_ISREG(metadata.st_mode):
                snapshot[relative] = ("file", *identity, current.read_bytes())
            else:
                snapshot[relative] = ("other", *identity)
        return snapshot

    def new_bootstrap_fixture(
        self, name: str
    ) -> tuple[Path, h.HarnessPaths, dict[str, str], Path]:
        root = Path(self.backup_temp.name) / f"bootstrap-{name}"
        root.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(root)],
            check=True,
            text=True,
            capture_output=True,
        )
        (root / "aoi.toml").write_text(
            cli_impl.default_config_text(f"Bootstrap {name}"), encoding="utf-8"
        )
        credential_home = Path(self.backup_temp.name) / f"credentials-{name}"
        environment = self.env.copy()
        environment["AOI_ROOT"] = str(root)
        environment["AOI_CHIEF_CREDENTIAL_HOME"] = str(credential_home)
        for variable in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(variable, None)
        return root, h.get_paths(root), environment, credential_home

    def write_bootstrap_platform_marker(self, paths: h.HarnessPaths) -> None:
        paths.harness.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            paths.harness.chmod(0o700)
        marker = {
            "schema_version": h.PLATFORM_MARKER_SCHEMA_VERSION,
            "lock_domain": h.runtime_lock_domain(),
            "lock_backend": h.platform_capabilities()["lock_backend"],
            "created_at": h.now_iso(),
        }
        paths.platform.write_text(
            json.dumps(marker, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            paths.platform.chmod(0o600)

    def write_bootstrap_lock(
        self, paths: h.HarnessPaths, payload: bytes = b"\0"
    ) -> None:
        paths.harness.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            paths.harness.chmod(0o700)
        paths.lock.write_bytes(payload)
        if os.name != "nt":
            paths.lock.chmod(0o600)

    def assert_canonical_bootstrap_lock(self, paths: h.HarnessPaths) -> None:
        metadata = paths.lock.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(int(metadata.st_nlink), 1)
        self.assertFalse(h._path_is_link_like(paths.lock))
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)

    def assert_chief_acquire_rejected_without_mutation(
        self,
        paths: h.HarnessPaths,
        environment: dict[str, str],
        credential_home: Path,
        *,
        session_id: str,
        manual_recovery: bool = True,
        authority_absent: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        before_config = self.filesystem_snapshot(paths.config)
        before_state = self.filesystem_snapshot(paths.harness)
        before_credentials = self.filesystem_snapshot(credential_home)
        rejected = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "chief-acquire",
                "--session-id",
                session_id,
                "--json",
            ],
            cwd=paths.root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        self.assertNotIn("Traceback", rejected.stderr)
        if manual_recovery:
            self.assertIn("offline/manual recovery", rejected.stderr)
        self.assertEqual(self.filesystem_snapshot(paths.config), before_config)
        self.assertEqual(self.filesystem_snapshot(paths.harness), before_state)
        self.assertEqual(
            self.filesystem_snapshot(credential_home), before_credentials
        )
        if authority_absent:
            self.assertFalse(os.path.lexists(paths.chief_authority))
        return rejected

    def managed_state_bytes(self) -> dict[str, bytes]:
        state = self.root / ".aoi"
        return {
            path.relative_to(state).as_posix(): path.read_bytes()
            for path in sorted(state.rglob("*"))
            if path.is_file() and path.name != ".state.lock"
        }

    def load_credential_token(
        self, session_id: str, epoch: int, credential_file: str
    ) -> str:
        paths = h.get_paths(self.root)
        with h.state_lock(paths, create_layout=False):
            token, loaded_path = h.load_chief_credential(
                paths,
                session_id=session_id,
                epoch=epoch,
                credential_file=Path(credential_file),
            )
        self.assertEqual(loaded_path, Path(credential_file))
        return token

    def test_epoch_lifecycle_stale_writer_and_secret_non_disclosure(self) -> None:
        old_token = self.load_credential_token(
            "harness-test-chief", self.chief_epoch, self.chief_credential_file
        )
        credential_path = Path(self.chief_credential_file)
        credential_bytes = credential_path.read_bytes()
        credential_payload = json.loads(credential_bytes)
        if os.name == "nt":
            self.assertEqual(
                credential_payload["secret_scheme"], "dpapi-current-user-v1"
            )
            self.assertNotIn(old_token.encode("ascii"), credential_bytes)
        else:
            self.assertEqual(
                credential_payload["secret_scheme"], "plain-posix-mode-v1"
            )
            self.assertEqual(stat.S_IMODE(credential_path.stat().st_mode), 0o600)
            credential_root = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])
            for directory in (
                credential_root,
                credential_path.parent.parent,
                credential_path.parent,
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

        credential_alias = Path(self.backup_temp.name) / "credential-hardlink.json"
        before = self.managed_state_bytes()
        os.link(credential_path, credential_alias)
        try:
            rejected = self.cli("render-index", ok=False)
            self.assertIn("private regular", rejected.stderr)
            self.assertEqual(self.managed_state_bytes(), before)
        finally:
            credential_alias.unlink(missing_ok=True)
        if os.name != "nt":
            credential_path.chmod(0o644)
            try:
                rejected = self.cli("render-index", ok=False)
                self.assertIn("permissions are not private", rejected.stderr)
                self.assertEqual(self.managed_state_bytes(), before)
            finally:
                credential_path.chmod(0o600)
            credential_path.parent.chmod(0o755)
            try:
                rejected = self.cli("render-index", ok=False)
                self.assertIn("permissions are not private", rejected.stderr)
                self.assertEqual(self.managed_state_bytes(), before)
            finally:
                credential_path.parent.chmod(0o700)

        renewed = json.loads(self.cli("chief-renew", "--json").stdout)
        self.assertEqual(renewed["authority"]["epoch"], self.chief_epoch)
        self.assertEqual(renewed["authority"]["renewal_count"], 1)

        released = json.loads(
            self.cli(
                "chief-release", "--reason", "rotate Chief test fixture", "--json"
            ).stdout
        )
        self.assertEqual(released["authority"]["status"], "inactive")
        self.assertEqual(released["authority"]["epoch"], self.chief_epoch)
        self.assertTrue(released["credential_cleanup"]["removed"])
        self.assertFalse(Path(self.chief_credential_file).exists())

        acquisition = self.cli(
            "chief-acquire", "--session-id", "replacement-chief", "--json"
        )
        acquired = json.loads(acquisition.stdout)
        self.assertNotIn("chief_token", acquired)
        new_epoch = int(acquired["authority"]["epoch"])
        self.assertEqual(new_epoch, self.chief_epoch + 1)
        new_file = acquired["credential_file"]
        new_token = self.load_credential_token(
            "replacement-chief", new_epoch, new_file
        )
        self.assertNotIn(new_token, acquisition.stdout)
        self.env["AOI_CHIEF_SESSION_ID"] = "replacement-chief"
        self.env["AOI_CHIEF_EPOCH"] = str(new_epoch)
        self.env["AOI_CHIEF_CREDENTIAL_FILE"] = new_file

        before = self.managed_state_bytes()
        rejected = self.cli(
            "init-task",
            "--task-id",
            "stale-chief-write",
            "--title",
            "Stale Chief must fail",
            "--objective",
            "Prove stale epoch fencing",
            "--owner",
            "stale",
            "--completion-boundary",
            "No state mutation",
            "--chief-session-id",
            "harness-test-chief",
            "--chief-epoch",
            str(self.chief_epoch),
            "--chief-token",
            old_token,
            ok=False,
        )
        self.assertNotIn(old_token, rejected.stderr)
        self.assertEqual(self.managed_state_bytes(), before)

        for path in (self.root / ".aoi").rglob("*"):
            if path.is_file():
                self.assertNotIn(new_token.encode("ascii"), path.read_bytes(), path)
        status = self.cli("status", "--json").stdout
        doctor = self.cli("doctor", "--json").stdout
        self.assertNotIn(new_token, status)
        self.assertNotIn(new_token, doctor)
        backup = json.loads(self.cli("backup-state", "--json").stdout)
        with tarfile.open(backup["archive"], mode="r:gz") as archive:
            for member in archive.getmembers():
                handle = archive.extractfile(member)
                self.assertIsNotNone(handle)
                assert handle is not None
                self.assertNotIn(new_token.encode("ascii"), handle.read(), member.name)

    def test_expired_and_live_takeover_require_cas_and_force(self) -> None:
        paths = h.get_paths(self.root)
        current = dt.datetime.now(dt.timezone.utc)
        renewed_at = current - dt.timedelta(minutes=2)
        expires_at = current - dt.timedelta(minutes=1)

        def iso(value: dt.datetime) -> str:
            return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

        with h.state_lock(paths, create_layout=False):
            authority = h.load_chief_authority(paths)
            authority["issued_at"] = iso(renewed_at)
            authority["renewed_at"] = iso(renewed_at)
            authority["expires_at"] = iso(expires_at)
            authority["updated_at"] = iso(renewed_at)
            authority["audit_tail"][-1]["at"] = iso(renewed_at)
            h.validate_chief_authority_record(paths, authority)
            h.atomic_write_json(paths.chief_authority, authority)

        expired_renew = self.cli("chief-renew", ok=False)
        self.assertIn("expired", expired_renew.stderr)
        before = paths.chief_authority.read_bytes()
        wrong_cas = self.cli(
            "chief-takeover",
            "--session-id",
            "takeover-chief",
            "--expected-epoch",
            str(self.chief_epoch + 9),
            "--reason",
            "exercise expected epoch CAS",
            ok=False,
        )
        self.assertIn("CAS failed", wrong_cas.stderr)
        self.assertEqual(paths.chief_authority.read_bytes(), before)

        takeover = json.loads(
            self.cli(
                "chief-takeover",
                "--session-id",
                "takeover-chief",
                "--expected-epoch",
                str(self.chief_epoch),
                "--reason",
                "recover expired Chief lease",
                "--json",
            ).stdout
        )
        takeover_epoch = int(takeover["authority"]["epoch"])
        self.assertEqual(takeover_epoch, self.chief_epoch + 1)
        live_rejected = self.cli(
            "chief-takeover",
            "--session-id",
            "forced-chief",
            "--expected-epoch",
            str(takeover_epoch),
            "--reason",
            "test live takeover acknowledgement",
            ok=False,
        )
        self.assertIn("--force-live", live_rejected.stderr)
        forced = json.loads(
            self.cli(
                "chief-takeover",
                "--session-id",
                "forced-chief",
                "--expected-epoch",
                str(takeover_epoch),
                "--reason",
                "explicitly replace live test lease",
                "--force-live",
                "--json",
            ).stdout
        )
        self.assertEqual(forced["authority"]["epoch"], takeover_epoch + 1)
        record = h.load_chief_authority(paths)
        self.assertTrue(record["audit_tail"][-1]["forced_live"])

    def test_two_concurrent_acquires_have_exactly_one_winner(self) -> None:
        self.cli("chief-release", "--reason", "prepare acquisition race")
        race_env = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            race_env.pop(name, None)
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "chief-acquire",
                    "--session-id",
                    session_id,
                    "--json",
                ],
                cwd=self.root,
                env=race_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for session_id in ("race-chief-a", "race-chief-b")
        ]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            results.append((process.returncode, stdout, stderr))
        self.assertEqual(sorted(result[0] for result in results), [0, 2])
        winner = next(json.loads(stdout) for code, stdout, _ in results if code == 0)
        self.assertNotIn("chief_token", winner)
        status = json.loads(self.cli("chief-status", "--json").stdout)
        self.assertEqual(status["session_id"], winner["authority"]["session_id"])

    def test_authority_and_lock_path_tampering_fail_closed(self) -> None:
        paths = h.get_paths(self.root)
        alias = Path(self.backup_temp.name) / "authority-hardlink.json"
        os.link(paths.chief_authority, alias)
        rejected = self.cli("status", "--json", ok=False)
        self.assertIn("private regular", rejected.stderr)
        self.assertFalse((paths.tasks / "tamper-write").exists())
        alias.unlink()

        lock_alias = Path(self.backup_temp.name) / "state-lock-hardlink"
        before = self.managed_state_bytes()
        os.link(paths.lock, lock_alias)
        try:
            lock_rejected = self.cli(
                "init-task",
                "--task-id",
                "hardlinked-lock-write",
                "--title",
                "Hardlinked lock must fail",
                "--objective",
                "Reject ambiguous lock identity",
                "--owner",
                "test",
                "--completion-boundary",
                "No state mutation",
                ok=False,
            )
            self.assertIn("private regular", lock_rejected.stderr)
            self.assertEqual(self.managed_state_bytes(), before)
            self.assertFalse((paths.tasks / "hardlinked-lock-write").exists())
        finally:
            lock_alias.unlink(missing_ok=True)

        payload = json.loads(paths.chief_authority.read_text(encoding="utf-8"))
        payload["unexpected"] = True
        paths.chief_authority.write_text(json.dumps(payload), encoding="utf-8")
        malformed = self.cli(
            "init-task",
            "--task-id",
            "tamper-write",
            "--title",
            "Malformed authority",
            "--objective",
            "Fail closed",
            "--owner",
            "test",
            "--completion-boundary",
            "No write",
            ok=False,
        )
        self.assertIn("unsupported field set", malformed.stderr)
        self.assertFalse((paths.tasks / "tamper-write").exists())

    def test_state_lock_is_exact_path_reentrant_and_other_threads_block(self) -> None:
        paths = h.get_paths(self.root)
        with h.state_lock(paths, create_layout=False):
            with h.state_lock(paths, create_layout=False):
                pass

        entered = threading.Event()

        def contender() -> None:
            with h.state_lock(paths, create_layout=False):
                entered.set()

        with h.state_lock(paths, create_layout=False):
            thread = threading.Thread(target=contender, daemon=True)
            thread.start()
            time.sleep(0.1)
            self.assertFalse(entered.is_set())
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(entered.is_set())

        if os.name != "nt":
            displaced = paths.lock.with_name(".state.lock.displaced")
            with h.state_lock(paths, create_layout=False):
                os.replace(paths.lock, displaced)
                h.atomic_create_bytes(paths.lock, b"\0")
                try:
                    with self.assertRaisesRegex(
                        h.HarnessError, "lock path changed while the lock was held"
                    ):
                        h._require_chief_lock(paths)
                finally:
                    paths.lock.unlink(missing_ok=True)
                    os.replace(displaced, paths.lock)

    def test_registered_command_classification_defaults_to_fenced(self) -> None:
        parser = cli_impl.build_parser({})
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        commands = set(subparsers.choices)
        explicit = (
            cli_impl.CHIEF_AUTHORITY_CONTROL_COMMANDS
            | cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS
            | cli_impl.CHIEF_PROJECT_PERMIT_CONSUMER_COMMANDS
            | cli_impl.CHIEF_STANDALONE_COMMANDS
            | {"init"}
        )
        self.assertTrue(explicit <= commands)
        for command in commands - explicit:
            self.assertTrue(
                cli_impl.command_requires_chief(command, initialized=True), command
            )
        self.assertFalse(cli_impl.command_requires_chief("init", initialized=False))
        self.assertTrue(cli_impl.command_requires_chief("init", initialized=True))
        self.assertTrue(
            cli_impl.command_requires_chief("future-mutator", initialized=True)
        )
        self.assertFalse(
            cli_impl.command_requires_chief("permit-consume", initialized=True)
        )
        self.assertTrue(
            cli_impl.command_requires_chief("permit-issue", initialized=True)
        )
        self.assertNotIn(
            "permit-consume", cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS
        )
        for command in (
            "cohort-round-preview",
            "cohort-round-prepare",
            "cohort-show",
        ):
            self.assertIn(command, cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS)
            self.assertFalse(
                cli_impl.command_requires_chief(command, initialized=True), command
            )
        for command in cli_impl.CHIEF_STANDALONE_WRITER_COMMANDS:
            self.assertTrue(
                cli_impl.command_requires_chief(command, initialized=True), command
            )

    def test_unauthorized_command_does_not_repair_layout_or_lock_mode(self) -> None:
        paths = h.get_paths(self.root)
        shutil.rmtree(paths.sessions)
        unauthorized_env = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            unauthorized_env.pop(name, None)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "init-task",
                "--task-id",
                "no-layout-repair",
                "--title",
                "No layout repair",
                "--objective",
                "Fail before handler side effects",
                "--owner",
                "unauthorized",
                "--completion-boundary",
                "Missing layout remains missing",
            ],
            cwd=self.root,
            env=unauthorized_env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(paths.sessions.exists())
        self.assertFalse((paths.tasks / "no-layout-repair").exists())

        if os.name != "nt":
            paths.sessions.mkdir(mode=0o700)
            paths.lock.chmod(0o666)
            mode_result = subprocess.run(
                [sys.executable, "-m", CLI_MODULE, "render-index"],
                cwd=self.root,
                env=unauthorized_env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(mode_result.returncode, 2, mode_result.stderr)
            self.assertIn("permissions are not private", mode_result.stderr)
            self.assertEqual(paths.lock.stat().st_mode & 0o777, 0o666)

    def test_missing_config_cannot_rebootstrap_existing_state(self) -> None:
        paths = h.get_paths(self.root)
        before = self.managed_state_bytes()
        paths.config.unlink()
        env = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            env.pop(name, None)
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "init", "--project-name", "Bypass"],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("aoi.toml is missing", result.stderr)
        self.assertFalse(paths.config.exists())
        self.assertEqual(self.managed_state_bytes(), before)

    def test_authority_validator_rejects_naive_time_and_invalid_audit_semantics(self) -> None:
        paths = h.get_paths(self.root)
        record = h.load_chief_authority(paths)
        naive = copy.deepcopy(record)
        naive["expires_at"] = "2099-01-01T00:00:00"
        with self.assertRaisesRegex(h.HarnessError, "timezone-aware"):
            h.validate_chief_authority_record(paths, naive)
        invalid_force = copy.deepcopy(record)
        invalid_force["audit_tail"][-1]["forced_live"] = True
        with self.assertRaisesRegex(h.HarnessError, "only a Chief takeover"):
            h.validate_chief_authority_record(paths, invalid_force)
        invalid_ttl = copy.deepcopy(record)
        renewed_at = dt.datetime.fromisoformat(
            invalid_ttl["renewed_at"].replace("Z", "+00:00")
        )
        invalid_ttl["expires_at"] = h._chief_iso(
            renewed_at + dt.timedelta(seconds=h.CHIEF_MAX_TTL_SECONDS + 1)
        )
        with self.assertRaisesRegex(h.HarnessError, "TTL bounds"):
            h.validate_chief_authority_record(paths, invalid_ttl)
        invalid_status = copy.deepcopy(record)
        invalid_status["status"] = []
        with self.assertRaisesRegex(h.HarnessError, "status is invalid"):
            h.validate_chief_authority_record(paths, invalid_status)
        invalid_sequence = copy.deepcopy(record)
        invalid_sequence["audit_tail"][-1]["seq"] = True
        with self.assertRaisesRegex(h.HarnessError, "sequence/action"):
            h.validate_chief_authority_record(paths, invalid_sequence)
        with h.state_lock(paths, create_layout=False):
            with self.assertRaisesRegex(h.HarnessError, "must be a boolean"):
                h.takeover_chief_authority(
                    paths,
                    session_id="invalid-force-chief",
                    expected_epoch=self.chief_epoch,
                    reason="reject truthy non-boolean force",
                    force_live="yes",  # type: ignore[arg-type]
                    credential_home=Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"]),
                )

    def test_authority_validator_rejects_impossible_epoch_history_metadata(self) -> None:
        paths = h.get_paths(self.root)
        record = h.load_chief_authority(paths)

        takeover_genesis = copy.deepcopy(record)
        takeover_genesis["audit_tail"][0]["action"] = "takeover"
        takeover_genesis["audit_tail"][0]["previous_session_id"] = "prior-chief"
        takeover_genesis["audit_tail"][0]["forced_live"] = True
        with self.assertRaisesRegex(h.HarnessError, "must begin with acquire"):
            h.validate_chief_authority_record(paths, takeover_genesis)

        early_issue = copy.deepcopy(record)
        origin_time = dt.datetime.fromisoformat(
            early_issue["audit_tail"][0]["at"].replace("Z", "+00:00")
        )
        early_issue["issued_at"] = h._chief_iso(
            origin_time - dt.timedelta(seconds=1)
        )
        with self.assertRaisesRegex(h.HarnessError, "current epoch origin"):
            h.validate_chief_authority_record(paths, early_issue)

        fractional_ttl = copy.deepcopy(record)
        renewed_at = dt.datetime.fromisoformat(
            fractional_ttl["renewed_at"].replace("Z", "+00:00")
        )
        fractional_ttl["expires_at"] = h._chief_iso(
            renewed_at
            + dt.timedelta(seconds=h.CHIEF_MIN_TTL_SECONDS, microseconds=1)
        )
        with self.assertRaisesRegex(h.HarnessError, "TTL bounds"):
            h.validate_chief_authority_record(paths, fractional_ttl)

        self.cli("chief-renew")
        renewed = h.load_chief_authority(paths)
        inflated_count = copy.deepcopy(renewed)
        inflated_count["renewal_count"] = 99
        with self.assertRaisesRegex(h.HarnessError, "visible epoch history"):
            h.validate_chief_authority_record(paths, inflated_count)

        truncated = copy.deepcopy(renewed)
        truncated["audit_tail"] = truncated["audit_tail"][1:]
        truncated["omitted_transition_count"] = 1
        truncated["renewal_count"] = 0
        with self.assertRaisesRegex(h.HarnessError, "below its visible epoch history"):
            h.validate_chief_authority_record(paths, truncated)

    def test_bounded_clock_skew_is_clamped_but_real_rollback_fails(self) -> None:
        paths = h.get_paths(self.root)
        token = self.load_credential_token(
            "harness-test-chief", self.chief_epoch, self.chief_credential_file
        )
        record = h.load_chief_authority(paths)
        renewed_at = dt.datetime.fromisoformat(
            record["renewed_at"].replace("Z", "+00:00")
        )
        with h.state_lock(paths, create_layout=False):
            accepted = h.require_chief_authority(
                paths,
                session_id="harness-test-chief",
                epoch=self.chief_epoch,
                token=token,
                now=renewed_at - dt.timedelta(milliseconds=500),
            )
            self.assertEqual(accepted, record)
            with self.assertRaisesRegex(
                h.HarnessError, "system clock precedes the Chief lease renewal time"
            ):
                h.require_chief_authority(
                    paths,
                    session_id="harness-test-chief",
                    epoch=self.chief_epoch,
                    token=token,
                    now=renewed_at
                    - dt.timedelta(
                        seconds=h.CHIEF_CLOCK_SKEW_TOLERANCE_SECONDS + 1
                    ),
                )

    def test_credential_candidate_is_removed_if_authority_commit_fails(self) -> None:
        self.cli("chief-release", "--reason", "prepare authority fault injection")
        paths = h.get_paths(self.root)
        before = paths.chief_authority.read_bytes()
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])
        with h.state_lock(paths, create_layout=False):
            with mock.patch.object(
                h,
                "_write_chief_authority",
                side_effect=h.HarnessError("injected authority write failure"),
            ):
                with self.assertRaisesRegex(h.HarnessError, "injected"):
                    h.acquire_chief_authority(
                        paths,
                        session_id="fault-injected-chief",
                        credential_home=credential_home,
                    )
        self.assertEqual(paths.chief_authority.read_bytes(), before)
        remaining = [path for path in credential_home.rglob("*.json") if path.is_file()]
        self.assertEqual(remaining, [])

    def test_credential_candidate_is_removed_after_ambiguous_create_failure(
        self,
    ) -> None:
        self.cli("chief-release", "--reason", "prepare credential create fault")
        paths = h.get_paths(self.root)
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])
        real_create = h.atomic_create_bytes

        def publish_then_fail(destination: Path, payload: bytes) -> None:
            real_create(destination, payload)
            raise h.HarnessError("injected post-create durability failure")

        with h.state_lock(paths, create_layout=False):
            with mock.patch.object(h, "atomic_create_bytes", publish_then_fail):
                with self.assertRaisesRegex(h.HarnessError, "post-create"):
                    h.acquire_chief_authority(
                        paths,
                        session_id="credential-create-fault-chief",
                        credential_home=credential_home,
                    )
        remaining = [path for path in credential_home.rglob("*.json") if path.is_file()]
        self.assertEqual(remaining, [])
        self.assertEqual(h.load_chief_authority(paths)["status"], "inactive")

    def test_published_authority_keeps_credential_if_durability_reports_failure(
        self,
    ) -> None:
        self.cli("chief-release", "--reason", "prepare post-publication failure")
        paths = h.get_paths(self.root)
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])
        real_write = h._write_chief_authority

        def publish_then_fail(target: h.HarnessPaths, record: dict[str, object]) -> None:
            real_write(target, record)
            raise h.HarnessError("injected post-publication durability failure")

        with h.state_lock(paths, create_layout=False):
            with mock.patch.object(h, "_write_chief_authority", publish_then_fail):
                with self.assertRaisesRegex(h.HarnessError, "post-publication"):
                    h.acquire_chief_authority(
                        paths,
                        session_id="published-fault-chief",
                        credential_home=credential_home,
                    )
            authority = h.load_chief_authority(paths)
            credentials = [
                path for path in credential_home.rglob("*.json") if path.is_file()
            ]
            self.assertEqual(len(credentials), 1)
            token, loaded_path = h.load_chief_credential(
                paths,
                session_id="published-fault-chief",
                epoch=int(authority["epoch"]),
                credential_file=credentials[0],
            )
            self.assertEqual(loaded_path, credentials[0].resolve())
            h.require_chief_authority(
                paths,
                session_id="published-fault-chief",
                epoch=int(authority["epoch"]),
                token=token,
            )

    def test_locked_reload_and_bootstrap_init_fail_on_config_races(self) -> None:
        paths = h.get_paths(self.root)
        before = self.managed_state_bytes()
        parser = cli_impl.build_parser({})
        args = parser.parse_args(["init"])
        args._aoi_initialized_at_dispatch = False
        with self.assertRaisesRegex(h.HarnessError, "appeared after unauthenticated"):
            cli_impl.cmd_init(args, paths)
        self.assertEqual(self.managed_state_bytes(), before)

        config_bytes = paths.config.read_bytes()
        paths.config.unlink()
        try:
            with h.state_lock(paths, create_layout=False):
                with self.assertRaisesRegex(h.HarnessError, "aoi.toml disappeared"):
                    cli_impl._reload_locked_paths(paths)
        finally:
            h.atomic_create_bytes(paths.config, config_bytes)

    def test_credential_home_rejects_dangerous_roots_and_never_chmods_existing(
        self,
    ) -> None:
        paths = h.get_paths(self.root)
        with self.assertRaisesRegex(h.HarnessError, "filesystem root"):
            h._chief_credential_root(paths, Path(paths.root.anchor))
        with self.assertRaisesRegex(h.HarnessError, "project repository"):
            h._chief_credential_root(paths, paths.root.parent)
        with self.assertRaisesRegex(h.HarnessError, "user home"):
            h._chief_credential_root(paths, Path.home())

        existing = Path(self.backup_temp.name) / "existing-private-directory"
        existing.mkdir()
        if os.name != "nt":
            existing.chmod(0o700)
        with mock.patch.object(h, "_chmod_private") as chmod_private:
            self.assertEqual(
                h._ensure_private_credential_directory(existing), existing.resolve()
            )
        chmod_private.assert_not_called()

        unavailable = Path(self.backup_temp.name) / "unavailable-credential-directory"
        with mock.patch.object(
            Path, "mkdir", side_effect=PermissionError("injected permission denial")
        ):
            with self.assertRaisesRegex(
                h.HarnessError, "cannot create Chief credential directory"
            ):
                h._ensure_private_credential_directory(unavailable)
        if os.name != "nt":
            unsafe_ancestor = Path(self.backup_temp.name) / "unsafe-ancestor"
            unsafe_ancestor.mkdir()
            unsafe_ancestor.chmod(0o777)
            with self.assertRaisesRegex(h.HarnessError, "group/world-writable"):
                h._chief_credential_root(paths, unsafe_ancestor / "credentials")

            trusted_parent = Path(self.backup_temp.name) / "umask-zero-parent"
            nested_private = trusted_parent / "first" / "second"
            previous_umask = os.umask(0)
            try:
                h._ensure_private_credential_directory(nested_private)
            finally:
                os.umask(previous_umask)
            for directory in (
                trusted_parent,
                trusted_parent / "first",
                nested_private,
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

            if os.geteuid() != 0:
                with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
                    with self.assertRaisesRegex(h.HarnessError, "untrusted owner"):
                        h._validate_credential_ancestor_chain(
                            Path(self.backup_temp.name) / "foreign-owner-probe"
                        )

    def test_authority_audit_tail_rolls_over_without_breaking_sequence(self) -> None:
        paths = h.get_paths(self.root)
        token = self.load_credential_token(
            "harness-test-chief", self.chief_epoch, self.chief_credential_file
        )
        renewals = h.CHIEF_AUDIT_TAIL_MAX + 5
        base = dt.datetime.now(dt.timezone.utc)
        with h.state_lock(paths, create_layout=False):
            record = h.load_chief_authority(paths)
            for offset in range(renewals):
                record = h.renew_chief_authority(
                    paths,
                    session_id="harness-test-chief",
                    epoch=self.chief_epoch,
                    token=token,
                    now=base + dt.timedelta(microseconds=offset + 1),
                )
        self.assertEqual(len(record["audit_tail"]), h.CHIEF_AUDIT_TAIL_MAX)
        self.assertEqual(record["transition_seq"], renewals + 1)
        self.assertEqual(
            record["omitted_transition_count"],
            record["transition_seq"] - h.CHIEF_AUDIT_TAIL_MAX,
        )
        self.assertEqual(
            record["audit_tail"][0]["seq"],
            record["omitted_transition_count"] + 1,
        )
        self.assertEqual(record["audit_tail"][-1]["seq"], record["transition_seq"])
        self.assertEqual(h.load_chief_authority(paths), record)

    def test_token_environment_is_removed_before_child_processes(self) -> None:
        marker = "A" * 43
        with mock.patch.dict(
            os.environ,
            {
                "AOI_CHIEF_SESSION_ID": "scrub-test",
                "AOI_CHIEF_EPOCH": "7",
                "AOI_CHIEF_TOKEN": marker,
                "AOI_CHIEF_CREDENTIAL_FILE": "C:/private/example.json",
            },
            clear=False,
        ):
            defaults = cli_impl._take_chief_environment_defaults()
            self.assertEqual(defaults["token"], marker)
            for name in (
                "AOI_CHIEF_SESSION_ID",
                "AOI_CHIEF_EPOCH",
                "AOI_CHIEF_TOKEN",
                "AOI_CHIEF_CREDENTIAL_FILE",
            ):
                self.assertNotIn(name, os.environ)
            child = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os; print(os.environ.get('AOI_CHIEF_TOKEN', 'absent'))",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(child.stdout.strip(), "absent")

    def test_authenticated_init_requires_exact_digest_to_replace_custom_policy(self) -> None:
        paths = h.get_paths(self.root)
        custom = b"# locally customized policy\n"
        paths.harness.joinpath("POLICY.md").write_bytes(custom)
        doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        self.assertIn("differs from the packaged contract", doctor.stdout)
        rejected = self.cli("init", ok=False)
        digest = hashlib.sha256(custom).hexdigest()
        self.assertIn(digest, rejected.stderr)
        self.assertEqual(paths.harness.joinpath("POLICY.md").read_bytes(), custom)
        updated = json.loads(
            self.cli(
                "init",
                "--replace-policy-sha256",
                digest,
                "--json",
            ).stdout
        )
        self.assertTrue(updated["policy_updated"])
        self.assertEqual(
            paths.harness.joinpath("POLICY.md").read_bytes(),
            (SRC / "aoi_orgware" / "resources" / "policy.md").read_bytes(),
        )

    def test_authenticated_init_auto_upgrades_exact_v013_managed_policy(self) -> None:
        paths = h.get_paths(self.root)
        legacy_bytes = (HERE / "fixtures" / "policy-v0.1.3.md").read_bytes()
        legacy_digest = hashlib.sha256(legacy_bytes).hexdigest()
        self.assertEqual(
            legacy_digest,
            "76f116580d535ec33ca19da1e53ec3c3d35c107b05768a55d5ee654f477a3c85",
        )
        self.assertIn(legacy_digest, cli_impl.KNOWN_MANAGED_POLICY_SHA256)

        paths.harness.joinpath("POLICY.md").write_bytes(legacy_bytes)
        updated = json.loads(self.cli("init", "--json").stdout)
        self.assertTrue(updated["policy_updated"])
        self.assertEqual(
            paths.harness.joinpath("POLICY.md").read_bytes(),
            (SRC / "aoi_orgware" / "resources" / "policy.md").read_bytes(),
        )

    def test_v021_policy_digest_remains_an_exact_managed_upgrade_source(self) -> None:
        self.assertIn(
            "eb03c009470e9bd27b521de6116b6206bfc0abf9785d0b1a1fe31416054a083f",
            cli_impl.KNOWN_MANAGED_POLICY_SHA256,
        )

    def unauthenticated_environment(self) -> dict[str, str]:
        environment = self.env.copy()
        for variable in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(variable, None)
        return environment

    def test_chief_acquire_refuses_complete_missing_lock_without_mutation(self) -> None:
        self.cli("chief-release", "--reason", "prepare missing-lock refusal")
        paths = h.get_paths(self.root)
        paths.chief_authority.unlink()
        paths.lock.unlink()
        h.require_complete_layout(paths, include_lock=False)
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])

        self.assert_chief_acquire_rejected_without_mutation(
            paths,
            self.unauthenticated_environment(),
            credential_home,
            session_id="missing-lock-chief",
        )

    def test_chief_acquire_refuses_complete_empty_lock_without_mutation(self) -> None:
        self.cli("chief-release", "--reason", "prepare empty-lock refusal")
        paths = h.get_paths(self.root)
        paths.chief_authority.unlink()
        paths.lock.write_bytes(b"")
        h.require_complete_layout(paths)
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])

        self.assert_chief_acquire_rejected_without_mutation(
            paths,
            self.unauthenticated_environment(),
            credential_home,
            session_id="empty-lock-chief",
        )
        self.assertEqual(paths.lock.read_bytes(), b"")

    def test_chief_acquire_accepts_complete_canonical_nul_lock(self) -> None:
        self.cli("chief-release", "--reason", "prepare canonical-lock acquisition")
        paths = h.get_paths(self.root)
        paths.chief_authority.unlink()
        self.assert_canonical_bootstrap_lock(paths)
        h.require_complete_layout(paths)

        acquired = json.loads(
            self.cli(
                "chief-acquire",
                "--session-id",
                "canonical-lock-chief",
                "--json",
            ).stdout
        )

        self.assertEqual(acquired["authority"]["session_id"], "canonical-lock-chief")
        self.assert_canonical_bootstrap_lock(paths)
        self.assertTrue(paths.chief_authority.is_file())
        self.assertTrue(Path(acquired["credential_file"]).is_file())
        h.require_complete_layout(paths)

    def test_chief_acquire_refuses_noncanonical_interrupted_prefixes_without_mutation(
        self,
    ) -> None:
        for case in ("config-only", "minimal", "structural"):
            with self.subTest(case=case):
                _root, paths, environment, credential_home = (
                    self.new_bootstrap_fixture(case)
                )
                if case == "minimal":
                    paths.harness.mkdir()
                    if os.name != "nt":
                        paths.harness.chmod(0o700)
                elif case == "structural":
                    self.write_bootstrap_platform_marker(paths)
                    for directory in (
                        paths.claims,
                        paths.tasks,
                        paths.claims_active,
                        paths.claims_archive,
                        paths.sessions,
                        paths.templates,
                    ):
                        directory.mkdir(parents=True, exist_ok=True)
                        if os.name != "nt":
                            directory.chmod(0o700)
                    self.write_bootstrap_lock(paths, b"")

                self.assert_chief_acquire_rejected_without_mutation(
                    paths,
                    environment,
                    credential_home,
                    session_id=f"refused-{case}-chief",
                )

    def test_chief_acquire_accepts_exact_existing_nul_interrupted_prefix(self) -> None:
        _root, paths, environment, _credential_home = self.new_bootstrap_fixture(
            "exact-nul-prefix"
        )
        self.write_bootstrap_platform_marker(paths)
        self.write_bootstrap_lock(paths)
        self.assert_canonical_bootstrap_lock(paths)
        before_config = paths.config.read_bytes()

        acquired_process = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "chief-acquire",
                "--session-id",
                "exact-nul-prefix-chief",
                "--json",
            ],
            cwd=paths.root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(acquired_process.returncode, 0, acquired_process.stderr)
        acquired = json.loads(acquired_process.stdout)
        self.assertEqual(
            acquired["authority"]["session_id"], "exact-nul-prefix-chief"
        )
        self.assertEqual(paths.config.read_bytes(), before_config)
        self.assert_canonical_bootstrap_lock(paths)
        self.assertTrue(paths.chief_authority.is_file())
        self.assertTrue(Path(acquired["credential_file"]).is_file())
        self.assertFalse(paths.index.exists())
        self.assertFalse((paths.harness / "POLICY.md").exists())
        self.assertFalse(paths.claims.exists())

    def test_chief_lock_bootstrap_rejects_invalid_sentinels_without_mutation(
        self,
    ) -> None:
        self.cli("chief-release", "--reason", "prepare invalid sentinel refusal")
        paths = h.get_paths(self.root)
        paths.chief_authority.unlink()
        for payload in (b"x", b"\0x"):
            with self.subTest(payload=payload):
                paths.lock.write_bytes(payload)
                before = self.filesystem_snapshot(paths.harness)
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "offline/manual recovery|payload changed during lock acquisition",
                ):
                    h.bootstrap_chief_state_lock(paths)
                self.assertEqual(self.filesystem_snapshot(paths.harness), before)
                self.assertFalse(os.path.lexists(paths.chief_authority))

    def test_chief_acquire_refuses_dangling_authority_with_canonical_nul_lock(
        self,
    ) -> None:
        self.cli("chief-release", "--reason", "prepare dangling-authority refusal")
        paths = h.get_paths(self.root)
        paths.chief_authority.unlink()
        self.assert_canonical_bootstrap_lock(paths)
        if os.name == "nt":
            target = paths.harness / "missing-chief-authority-target"
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(paths.chief_authority), str(target)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(
                    "dangling Chief-authority junction unavailable: "
                    + (created.stderr.strip() or created.stdout.strip())
                )
        else:
            paths.chief_authority.symlink_to("missing-chief-authority.json")
        self.assertTrue(h._path_is_link_like(paths.chief_authority))
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])
        try:
            rejected = self.assert_chief_acquire_rejected_without_mutation(
                paths,
                self.unauthenticated_environment(),
                credential_home,
                session_id="dangling-authority-chief",
                manual_recovery=False,
                authority_absent=False,
            )
            self.assertRegex(rejected.stderr, "regular non-linked|symlink|junction")
            self.assertTrue(h._path_is_link_like(paths.chief_authority))
            self.assert_canonical_bootstrap_lock(paths)
        finally:
            if os.name == "nt":
                os.rmdir(paths.chief_authority)
            else:
                paths.chief_authority.unlink()

    def test_interrupted_init_preserves_future_platform_marker(self) -> None:
        _root, paths, _environment, _credential_home = self.new_bootstrap_fixture(
            "future-marker"
        )
        future_payload = (
            json.dumps(
                {
                    "schema_version": h.PLATFORM_MARKER_SCHEMA_VERSION + 1,
                    "lock_domain": h.runtime_lock_domain(),
                    "lock_backend": "future-backend",
                    "created_at": h.now_iso(),
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        paths.harness.mkdir()
        if os.name != "nt":
            paths.harness.chmod(0o700)
        paths.platform.write_bytes(future_payload)
        if os.name != "nt":
            paths.platform.chmod(0o600)
        self.write_bootstrap_lock(paths)
        before = self.filesystem_snapshot(paths.harness)

        with self.assertRaisesRegex(h.HarnessError, "unsupported AOI platform marker"):
            h.bootstrap_chief_state_lock(paths)

        self.assertEqual(self.filesystem_snapshot(paths.harness), before)

    def test_first_init_reloads_config_and_refuses_racing_authority(self) -> None:
        def new_root(name: str) -> tuple[Path, dict[str, str]]:
            root = Path(self.backup_temp.name) / name
            root.mkdir()
            subprocess.run(
                ["git", "init", "-b", "main", str(root)],
                check=True,
                text=True,
                capture_output=True,
            )
            environment = os.environ.copy()
            environment["AOI_ROOT"] = str(root)
            environment["PYTHONPATH"] = str(SRC)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
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
            return root, environment

        config_root, config_environment = new_root("first-init-config-race")
        real_state_lock = cli_impl.state_lock
        config_swapped = False

        @contextlib.contextmanager
        def swap_config_then_lock(
            paths: h.HarnessPaths, *, create_layout: bool = True
        ) -> object:
            nonlocal config_swapped
            if not config_swapped:
                paths.config.write_text(
                    cli_impl.default_config_text("Racing Config"), encoding="utf-8"
                )
                config_swapped = True
            with real_state_lock(paths, create_layout=create_layout):
                yield

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, config_environment, clear=True), mock.patch.object(
            cli_impl, "state_lock", swap_config_then_lock
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            result = cli_impl.main(["init", "--project-name", "Original Config"])
        self.assertEqual(result, 2)
        self.assertIn("aoi.toml changed", stderr.getvalue())
        self.assertFalse((config_root / ".aoi" / "POLICY.md").exists())

        authority_root, authority_environment = new_root("first-init-authority-race")
        authority_inserted = False

        @contextlib.contextmanager
        def acquire_authority_then_lock(
            paths: h.HarnessPaths, *, create_layout: bool = True
        ) -> object:
            nonlocal authority_inserted
            if not authority_inserted:
                # The racing Chief must now arrive through the only automatic
                # bootstrap state: an existing canonical NUL interrupted prefix.
                self.write_bootstrap_platform_marker(paths)
                self.write_bootstrap_lock(paths)
                acquired = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        CLI_MODULE,
                        "chief-acquire",
                        "--session-id",
                        "racing-first-chief",
                    ],
                    cwd=authority_root,
                    env=authority_environment,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
                self.assertEqual(acquired.returncode, 0, acquired.stderr)
                authority_inserted = True
            with real_state_lock(paths, create_layout=create_layout):
                yield

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, authority_environment, clear=True), mock.patch.object(
            cli_impl, "state_lock", acquire_authority_then_lock
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            result = cli_impl.main(["init", "--project-name", "Authority Race"])
        self.assertEqual(result, 2)
        self.assertIn("Chief authority appeared", stderr.getvalue())
        authority_paths = h.get_paths(authority_root)
        self.assertTrue(authority_paths.chief_authority.is_file())
        self.assertFalse((authority_paths.harness / "POLICY.md").exists())
        self.assertFalse(authority_paths.index.exists())

    def test_chief_acquire_refuses_incomplete_missing_lock_without_mutation(self) -> None:
        self.cli("chief-release", "--reason", "prepare incomplete-lock refusal")
        paths = h.get_paths(self.root)
        paths.chief_authority.unlink()
        paths.lock.unlink()
        shutil.rmtree(paths.sessions)
        credential_home = Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"])

        self.assert_chief_acquire_rejected_without_mutation(
            paths,
            self.unauthenticated_environment(),
            credential_home,
            session_id="incomplete-missing-lock-chief",
        )
        self.assertFalse(paths.lock.exists())
        self.assertFalse(paths.sessions.exists())

    def test_default_credential_home_uses_platform_user_state_location(self) -> None:
        paths = h.get_paths(self.root)
        state_home = Path(self.backup_temp.name) / "default-user-state"
        environment = os.environ.copy()
        environment.pop("AOI_CHIEF_CREDENTIAL_HOME", None)
        if os.name == "nt":
            environment["LOCALAPPDATA"] = str(state_home)
            expected = state_home / "AOI" / "credentials" / "v1"
        else:
            environment["XDG_STATE_HOME"] = str(state_home)
            expected = state_home / "aoi" / "credentials" / "v1"
        with mock.patch.dict(os.environ, environment, clear=True):
            actual = h._chief_credential_root(paths)
        self.assertEqual(actual, expected.resolve())

        if os.name == "nt":
            environment["LOCALAPPDATA"] = "relative-user-state"
            relative_label = "LOCALAPPDATA must be an absolute path"
        else:
            environment["XDG_STATE_HOME"] = "relative-user-state"
            relative_label = "XDG_STATE_HOME must be an absolute path"
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(h.HarnessError, relative_label):
                h._chief_credential_root(paths)

    def test_pilot_writers_cannot_bypass_project_fence_or_managed_state(self) -> None:
        paths = h.get_paths(self.root)
        before = paths.chief_authority.read_bytes()
        unauthorized = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            unauthorized.pop(name, None)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "pilot-summary",
                "--record",
                str(self.root / "missing-record.json"),
                "--output",
                str(paths.chief_authority),
                "--force",
            ],
            cwd=self.root,
            env=unauthorized,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Chief session id and epoch are required", result.stderr)
        self.assertEqual(paths.chief_authority.read_bytes(), before)

        init_args = ["pilot-init", "--output", str(paths.harness), "--force"]
        if os.name == "nt":
            init_args.append("--allow-unverified-windows-acl")
        rejected = self.cli(*init_args, ok=False)
        self.assertIn("may not enter AOI managed state", rejected.stderr)
        self.assertEqual(paths.chief_authority.read_bytes(), before)

        root_args = ["pilot-init", "--output", str(paths.root), "--force"]
        if os.name == "nt":
            root_args.append("--allow-unverified-windows-acl")
        rejected = self.cli(*root_args, ok=False)
        self.assertIn("may not replace an initialized AOI project root", rejected.stderr)

        parent = Path(self.backup_temp.name) / "pilot-parent-with-nested-project"
        nested = parent / "sample_project"
        nested.mkdir(parents=True)
        subprocess.run(
            ["git", "init", "-b", "main", str(nested)],
            check=True,
            text=True,
            capture_output=True,
        )
        nested_env = unauthorized.copy()
        nested_env["AOI_ROOT"] = str(nested)
        nested_init = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "init", "--project-name", "Nested Pilot"],
            cwd=nested,
            env=nested_env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(nested_init.returncode, 0, nested_init.stderr)
        sentinel = nested / "README.md"
        sentinel.write_text("nested AOI sentinel\n", encoding="utf-8")

        nested_bypass = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "pilot-init",
                "--output",
                str(parent),
                "--force",
                *(
                    ["--allow-unverified-windows-acl"]
                    if os.name == "nt"
                    else []
                ),
            ],
            cwd=self.root,
            env=unauthorized,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(nested_bypass.returncode, 2, nested_bypass.stderr)
        self.assertIn("Chief session id and epoch are required", nested_bypass.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "nested AOI sentinel\n")

        with self.assertRaisesRegex(cli_impl.PilotError, "active Chief credential"):
            cli_impl.initialize_kit(
                parent,
                force=True,
                allow_unverified_windows_acl=os.name == "nt",
                authorized_project_root=self.root,
            )
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "nested AOI sentinel\n")

        config_bytes = paths.config.read_bytes()
        paths.config.unlink()
        try:
            with self.assertRaisesRegex(
                cli_impl.PilotError, "aoi.toml is missing"
            ):
                cli_impl.initialize_kit(
                    paths.harness,
                    force=True,
                    allow_unverified_windows_acl=os.name == "nt",
                    authorized_project_root=self.root,
                )
        finally:
            paths.config.write_bytes(config_bytes)
        self.assertEqual(paths.chief_authority.read_bytes(), before)

    def test_pilot_nested_projects_are_all_discovered_and_refused(self) -> None:
        nested = self.root / "nested-aoi-project"
        nested.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(nested)],
            check=True,
            text=True,
            capture_output=True,
        )
        environment = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(name, None)
        environment["AOI_ROOT"] = str(nested)
        initialized = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "init", "--project-name", "Nested AOI"],
            cwd=nested,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        projects = cli_impl._pilot_output_projects(
            nested / "pilot-summary.json", kit_destinations=False
        )
        self.assertEqual(
            {item.root for item in projects},
            {self.root.resolve(), nested.resolve()},
        )
        rejected = self.cli(
            "pilot-summary",
            "--record",
            str(nested / "missing-record.json"),
            "--output",
            str(nested / "pilot-summary.json"),
            ok=False,
        )
        self.assertIn("overlaps multiple initialized AOI projects", rejected.stderr)

        sentinel = nested / "README.md"
        sentinel.write_text("nested orphan sentinel\n", encoding="utf-8")
        (nested / "aoi.toml").unlink()
        with self.assertRaisesRegex(cli_impl.PilotError, "aoi.toml is missing"):
            cli_impl.initialize_kit(
                nested,
                force=True,
                allow_unverified_windows_acl=os.name == "nt",
                authorized_project_root=self.root,
            )
        self.assertEqual(
            sentinel.read_text(encoding="utf-8"), "nested orphan sentinel\n"
        )


class LockTests(HarnessTestCase):
    def test_initialized_policy_matches_canonical_packaged_resource(self) -> None:
        canonical = (REPO / "docs" / "POLICY.md").read_bytes()
        packaged = (SRC / "aoi_orgware" / "resources" / "policy.md").read_bytes()
        initialized = (self.root / ".aoi" / "POLICY.md").read_bytes()
        self.assertEqual(packaged, canonical)
        self.assertEqual(initialized, canonical)
        text = initialized.decode("utf-8")
        self.assertIn("packet-input-recover-from-tar", text)
        self.assertIn("verification-supersession-seal", text)

    @unittest.skipIf(os.name == "nt", "POSIX fork/flock inheritance boundary")
    def test_forked_child_cannot_reenter_or_unlock_parent_state_lock(self) -> None:
        import fcntl
        import select

        paths = h.get_paths(self.root)
        read_fd, write_fd = os.pipe()
        child_mode = False
        child_pid = -1
        with h.state_lock(paths, create_layout=False):
            child_pid = os.fork()
            if child_pid == 0:
                child_mode = True
                os.close(read_fd)
                try:
                    with h.state_lock(paths, create_layout=False):
                        pass
                except h.HarnessError:
                    os.write(write_fd, b"R")
                else:
                    os.write(write_fd, b"F")
            else:
                os.close(write_fd)
                observed = b""
                deadline = time.monotonic() + 5
                while len(observed) < 2:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        os.kill(child_pid, 9)
                        os.waitpid(child_pid, 0)
                        self.fail("forked lock child did not report before timeout")
                    ready, _write_ready, _errors = select.select(
                        [read_fd], [], [], remaining
                    )
                    if not ready:
                        continue
                    chunk = os.read(read_fd, 2 - len(observed))
                    if not chunk:
                        break
                    observed += chunk
                _waited, status = os.waitpid(child_pid, 0)
                os.close(read_fd)
                self.assertEqual(status, 0)
                self.assertEqual(observed, b"RL")

        if child_mode:
            result = b"L"
            try:
                with paths.lock.open("rb") as contender:
                    try:
                        fcntl.flock(
                            contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                    except BlockingIOError:
                        pass
                    else:
                        result = b"U"
                        fcntl.flock(contender.fileno(), fcntl.LOCK_UN)
                os.write(write_fd, result)
            finally:
                os.close(write_fd)
                os._exit(0)

    def test_overlap_matrix_and_path_escape(self) -> None:
        self.assertTrue(
            h.locks_overlap("repo:file:rtl/a.sv", "repo:tree:rtl")
        )
        self.assertTrue(
            h.locks_overlap("repo:tree:rtl/adfp", "repo:tree:rtl")
        )
        self.assertFalse(
            h.locks_overlap("repo:file:rtl/a.sv", "repo:file:rtl/b.sv")
        )
        self.assertFalse(
            h.locks_overlap("repo:file:rtl/a.sv", "external:file:/tmp/rtl/a.sv")
        )
        self.assertTrue(h.locks_overlap("contract:foo", "contract:foo"))
        self.assertFalse(h.locks_overlap("contract:foo", "contract:bar"))
        with self.assertRaises(h.HarnessError):
            h.normalize_lock("repo:file:../escape")
        with self.assertRaises(h.HarnessError):
            h.normalize_lock("external:tree:relative/path")
        with self.assertRaisesRegex(h.HarnessError, "double-slash root"):
            h.normalize_lock("external:file://tmp/alias")
        with self.assertRaises(h.HarnessError):
            h.normalize_lock("repo:tree:rtl/*")
        locks, _ = h.legacy_scope_locks(
            h.get_paths(self.root), "legacy `scripts/*model_top*` scope"
        )
        self.assertEqual(locks, ["repo:tree:scripts"])

    def test_external_double_slash_alias_cannot_issue_a_second_claim(self) -> None:
        self.init_task("external-alias-a")
        self.init_task("external-alias-b")
        self.cli(
            "claim",
            "--task",
            "external-alias-a",
            "--token",
            "external-alias-claim-a",
            "--owner",
            "a",
            "--kind",
            "EXTERNAL",
            "--lock",
            "external:file:/tmp/aoi-lock-alias",
            "--intent",
            "Reserve one canonical external file",
            "--validation",
            "A double-slash spelling must not bypass ownership",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
        )
        rejected = self.cli(
            "claim",
            "--task",
            "external-alias-b",
            "--token",
            "external-alias-claim-b",
            "--owner",
            "b",
            "--kind",
            "EXTERNAL",
            "--lock",
            "external:file://tmp/aoi-lock-alias",
            "--intent",
            "Attempt an alternate spelling of the reserved file",
            "--validation",
            "Normalization must reject the alias",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("double-slash root", rejected.stderr)
        self.assertFalse(
            (h.get_paths(self.root).claims_active / "external-alias-claim-b.json").exists()
        )

    def test_state_tree_is_pinned_to_one_runtime_lock_domain(self) -> None:
        paths = h.get_paths(self.root)
        marker = json.loads(paths.platform.read_text(encoding="utf-8"))
        self.assertEqual(marker["lock_domain"], h.runtime_lock_domain())
        marker["lock_domain"] = (
            "posix-flock-v1"
            if h.runtime_lock_domain() == "windows-msvcrt-v1"
            else "windows-msvcrt-v1"
        )
        paths.platform.write_text(json.dumps(marker), encoding="utf-8")
        rejected = self.cli(
            "init-task",
            "--task-id",
            "wrong-lock-domain",
            "--title",
            "Must fail before mutation",
            "--objective",
            "Reject a writer from the wrong lock domain",
            "--owner",
            "test-root",
            "--completion-boundary",
            "No task state is created",
            ok=False,
        )
        self.assertIn("lock domain", rejected.stderr)
        self.assertFalse((paths.tasks / "wrong-lock-domain").exists())

    @unittest.skipIf(os.name == "nt", "symlink creation is not guaranteed on Windows")
    def test_repo_file_baseline_rejects_final_and_parent_symlinks(self) -> None:
        self.init_task("repo-symlink")
        outside = Path(self.backup_temp.name) / "outside.txt"
        outside.write_text("outside authority\n", encoding="utf-8")
        (self.root / "leak.txt").symlink_to(outside)
        rejected = self.cli(
            "claim",
            "--task",
            "repo-symlink",
            "--token",
            "repo-symlink-final",
            "--owner",
            "root",
            "--kind",
            "CODE",
            "--lock",
            "repo:file:leak.txt",
            "--intent",
            "Attempt a final-component symlink baseline",
            "--validation",
            "Claim must reject the symlink",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("may not traverse a symlink", rejected.stderr)

        outside_dir = Path(self.backup_temp.name) / "outside-dir"
        outside_dir.mkdir()
        (outside_dir / "target.txt").write_text("outside parent\n", encoding="utf-8")
        (self.root / "linked-dir").symlink_to(outside_dir, target_is_directory=True)
        parent_rejected = self.cli(
            "claim",
            "--task",
            "repo-symlink",
            "--token",
            "repo-symlink-parent",
            "--owner",
            "root",
            "--kind",
            "CODE",
            "--lock",
            "repo:file:linked-dir/target.txt",
            "--intent",
            "Attempt a parent-component symlink baseline",
            "--validation",
            "Claim must reject the parent symlink",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("may not traverse a symlink", parent_rejected.stderr)

        tree_rejected = self.cli(
            "claim",
            "--task",
            "repo-symlink",
            "--token",
            "repo-symlink-tree",
            "--owner",
            "root",
            "--kind",
            "CODE",
            "--lock",
            "repo:tree:linked-dir",
            "--intent",
            "Attempt a tree claim through a symlink",
            "--validation",
            "Tree claims must reject link traversal too",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("may not traverse a symlink", tree_rejected.stderr)

    def test_repo_file_baseline_rejects_hardlinked_targets(self) -> None:
        self.init_task("repo-hardlink")
        source = self.root / "hardlink-source.txt"
        alias = self.root / "hardlink-alias.txt"
        source.write_text("one filesystem identity\n", encoding="utf-8")
        os.link(source, alias)

        for token, relative_path in (
            ("repo-hardlink-source", source.name),
            ("repo-hardlink-alias", alias.name),
        ):
            rejected = self.cli(
                "claim",
                "--task",
                "repo-hardlink",
                "--token",
                token,
                "--owner",
                "root",
                "--kind",
                "CODE",
                "--lock",
                f"repo:file:{relative_path}",
                "--intent",
                "Attempt to reserve one spelling of a hard-linked file",
                "--validation",
                "Hard-linked targets must fail closed",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                ok=False,
            )
            self.assertIn("must not be hard-linked", rejected.stderr)
            self.assertFalse(
                (h.get_paths(self.root).claims_active / f"{token}.json").exists()
            )

    def test_repo_tree_baseline_rejects_nested_identity_aliases(self) -> None:
        self.init_task("repo-tree-identities")
        first = self.root / "tree-one"
        second = self.root / "tree-two"
        first.mkdir()
        second.mkdir()
        source = first / "source.txt"
        source.write_text("shared inode\n", encoding="utf-8")
        os.link(source, second / "alias.txt")

        hardlink_rejected = self.cli(
            "claim",
            "--task",
            "repo-tree-identities",
            "--token",
            "repo-tree-hardlink",
            "--owner",
            "root",
            "--kind",
            "CODE",
            "--lock",
            "repo:tree:tree-one",
            "--intent",
            "Attempt to reserve a tree containing a hard-linked file",
            "--validation",
            "Tree identity audit must fail closed",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("may not contain a hard-linked file", hardlink_rejected.stderr)

        if os.name != "nt":
            clean_tree = self.root / "tree-with-link"
            clean_tree.mkdir()
            (clean_tree / "nested-link").symlink_to(source)
            symlink_rejected = self.cli(
                "claim",
                "--task",
                "repo-tree-identities",
                "--token",
                "repo-tree-symlink",
                "--owner",
                "root",
                "--kind",
                "CODE",
                "--lock",
                "repo:tree:tree-with-link",
                "--intent",
                "Attempt to reserve a tree containing a symlink",
                "--validation",
                "Nested links must fail closed",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                ok=False,
            )
            self.assertIn("may not contain a symlink", symlink_rejected.stderr)

    def test_expired_and_blocked_claims_still_reserve(self) -> None:
        self.init_task("task-a")
        self.init_task("task-b")
        self.cli(
            "claim",
            "--task",
            "task-a",
            "--token",
            "claim-a",
            "--owner",
            "a",
            "--kind",
            "RTL",
            "--lock",
            "repo:tree:rtl/adfp",
            "--intent",
            "own tree",
            "--validation",
            "test",
            "--expires-at",
            "2000-01-01T00:00:00+00:00",
        )
        conflict = self.cli(
            "claim",
            "--task",
            "task-b",
            "--token",
            "claim-b",
            "--owner",
            "b",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:rtl/adfp/a.sv",
            "--intent",
            "conflict",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("claim-a", conflict.stderr)
        self.cli(
            "set-claim-status",
            "--token",
            "claim-a",
            "--status",
            "blocked",
            "--reason",
            "waiting on evidence",
        )
        blocked = self.cli(
            "claim",
            "--task",
            "task-b",
            "--token",
            "claim-b",
            "--owner",
            "b",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:rtl/adfp/a.sv",
            "--intent",
            "still conflicts",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("blocked", blocked.stderr)
        self.cli(
            "release-claim",
            "--token",
            "claim-a",
            "--status",
            "stale",
            "--reason",
            "explicitly audited in test",
        )
        self.cli(
            "claim",
            "--task",
            "task-b",
            "--token",
            "claim-b",
            "--owner",
            "b",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:rtl/adfp/a.sv",
            "--intent",
            "now available",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
        )

    def test_exact_file_claim_records_sha256_baseline(self) -> None:
        source = self.root / "rtl" / "adfp" / "unit.sv"
        source.parent.mkdir(parents=True)
        source.write_text("module unit; endmodule\n", encoding="utf-8")
        self.init_task("baseline-task")
        self.cli(
            "claim",
            "--task",
            "baseline-task",
            "--token",
            "baseline-claim",
            "--owner",
            "root",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:rtl/adfp/unit.sv",
            "--intent",
            "baseline test",
            "--validation",
            "hash",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        claim = json.loads(
            (
                self.root
                / ".aoi"
                / "claims"
                / "active"
                / "baseline-claim.json"
            ).read_text(encoding="utf-8")
        )
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(
            claim["baselines"]["repo:file:rtl/adfp/unit.sv"]["sha256"], expected
        )

    def test_host_lock_canonicalization_overlap_and_baseline(self) -> None:
        self.assertEqual(
            h.normalize_lock("host:file:d:/workspace/project/Hook.JSON"),
            "host:file:D:/workspace/project/hook.json",
        )
        self.assertTrue(
            h.locks_overlap(
                "host:tree:D:/workspace/project",
                "host:file:d:/workspace/project/.codex/hooks.json",
            )
        )
        for invalid in (
            "host:file:relative/path",
            "host:file://server/share/file",
            "host:file:D:/a/../b",
            "host:file:D:/a/file:stream",
            "host:file:D:\\a\\b",
        ):
            with self.assertRaises(h.HarnessError):
                h.normalize_lock(invalid)

        host_file = (
            self.root / "native-host" / "hook.json"
            if os.name == "nt"
            else self.root / "host-mount" / "d" / "workspace" / "project" / "hook.json"
        )
        host_file.parent.mkdir(parents=True)
        host_file.write_text("v1\n", encoding="utf-8")
        lock = (
            h.normalize_lock(f"host:file:{host_file.resolve().as_posix()}")
            if os.name == "nt"
            else "host:file:D:/workspace/project/hook.json"
        )
        self.init_task("host-baseline")
        self.cli(
            "claim",
            "--task",
            "host-baseline",
            "--token",
            "host-baseline-claim",
            "--owner",
            "root",
            "--kind",
            "HOST",
            "--lock",
            lock,
            "--intent",
            "protect relay file",
            "--validation",
            "hash before and after",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        claim_path = (
            self.root
            / ".aoi"
            / "claims"
            / "active"
            / "host-baseline-claim.json"
        )
        claim = json.loads(claim_path.read_text(encoding="utf-8"))
        self.assertEqual(
            claim["baselines"][lock]["sha256"],
            hashlib.sha256(host_file.read_bytes()).hexdigest(),
        )
        host_file.write_text("v2\n", encoding="utf-8")
        result = self.cli(
            "release-claim",
            "--token",
            "host-baseline-claim",
            "--status",
            "done",
            "--reason",
            "host baseline test complete",
            "--json",
        )
        self.assertTrue(json.loads(result.stdout)["baseline_changed"][lock])

        if os.name != "nt":
            symlink = host_file.parent / "link.json"
            symlink.symlink_to(host_file)
            self.init_task("host-symlink")
            rejected = self.cli(
                "claim",
                "--task",
                "host-symlink",
                "--token",
                "host-symlink-claim",
                "--owner",
                "root",
                "--kind",
                "HOST",
                "--lock",
                "host:file:D:/workspace/project/link.json",
                "--intent",
                "reject symlink",
                "--validation",
                "must fail closed",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                ok=False,
            )
            self.assertIn("symlink", rejected.stderr)

    def test_ntfs_short_name_lock_spelling_fails_closed(self) -> None:
        paths = h.get_paths(self.root)
        for lock in (
            "host:tree:C:/PROGRA~1",
            "host:file:C:/Users/RUNNER~1/file.txt",
            "host:file:C:/TEMP/LONGFI~1.TXT",
            "host:tree:C:/TEMP/ÉCLAI~1",
            "host:file:C:/TEMP/RÉSUMÉ~2.DAT",
            "host:file:C:/TEMP/FOO~BA~1.TXT",
            "host:tree:C:/TEMP/~LONGF~1",
        ):
            with self.subTest(lock=lock):
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "canonical long spelling|NTFS 8.3-style",
                ):
                    h.validate_lock_identity(paths, lock, repo_root=self.root)

        external_lock = (
            f"{h.EXTERNAL_LOCK_NAMESPACE}:tree:/tmp/RUNNER~1"
        )
        self.assertEqual(h.normalize_lock(external_lock), external_lock)
        if os.name == "nt":
            with self.assertRaisesRegex(
                h.HarnessError,
                "canonical long spelling|NTFS 8.3-style",
            ):
                h.validate_lock_identity(
                    paths,
                    "repo:tree:RUNNER~1",
                    repo_root=self.root,
                )
        else:
            self.assertEqual(
                h.validate_lock_identity(
                    paths,
                    "repo:tree:RUNNER~1",
                    repo_root=self.root,
                ),
                "repo:tree:RUNNER~1",
            )
            self.assertEqual(
                h.validate_lock_identity(
                    paths,
                    "repo:tree:MixedCase",
                    repo_root=self.root,
                ),
                "repo:tree:MixedCase",
            )
            self.assertEqual(
                h.validate_lock_identity(
                    paths,
                    "git:merge:MixedCase",
                    repo_root=self.root,
                ),
                "git:merge:MixedCase",
            )
            host_mount = self.root / "host-mount"
            mounted_repo = host_mount / "c" / "workspace"
            mounted_repo.mkdir(parents=True)
            with mock.patch.dict(
                os.environ,
                {"AOI_HOST_MOUNT_ROOT": str(host_mount)},
            ):
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "repo lock URI contains an unresolved NTFS 8.3-style",
                ):
                    h.validate_lock_identity(
                        paths,
                        "repo:tree:RUNNER~1",
                        repo_root=mounted_repo,
                    )
                self.assertEqual(
                    h.validate_lock_identity(
                        paths,
                        "repo:tree:Program Files",
                        repo_root=mounted_repo,
                    ),
                    "repo:tree:program files",
                )
                self.assertEqual(
                    h.validate_lock_identity(
                        paths,
                        "git:merge:Feature/CaseAlias",
                        repo_root=mounted_repo,
                    ),
                    "git:merge:feature/casealias",
                )
                mounted_high_risk = h.validate_lock_identity(
                    paths,
                    "repo:file:.AOI/claims/forged.json",
                    repo_root=mounted_repo,
                )
                self.assertEqual(
                    mounted_high_risk,
                    "repo:file:.aoi/claims/forged.json",
                )
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "mini task may not own high-risk path",
                ):
                    cli_impl.validate_mini_locks([mounted_high_risk])
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "persisted lock URI must use.*canonical Windows-mount identity",
                ):
                    h.validate_persisted_lock_identity(
                        paths,
                        "git:merge:Feature/CaseAlias",
                        repo_root=mounted_repo,
                    )
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "persisted lock URI must use.*canonical Windows-mount identity",
                ):
                    h.validate_persisted_lock_identity(
                        paths,
                        "repo:tree:Program Files",
                        repo_root=mounted_repo,
                    )
                with self.assertRaisesRegex(
                    h.HarnessError,
                    "claim mounted-case-alias has non-canonical lock authority",
                ):
                    h.validate_claim_lock_identities(
                        paths,
                        {
                            "legacy": True,
                            "token": "mounted-case-alias",
                            "worktree": str(mounted_repo),
                            "locks": ["repo:tree:Program Files"],
                        },
                    )
                packet_state = {
                    "task_id": "mounted-packet",
                    "worktree": str(mounted_repo),
                }
                packet = {
                    "packet_id": "mounted-case-packet",
                    "status": "ready",
                    "locks": ["repo:tree:Program Files"],
                }
                self.assertRegex(
                    "\n".join(
                        cli_impl.packet_lock_integrity_errors(
                            paths,
                            packet_state,
                            packet,
                        )
                    ),
                    "persisted lock URI must use.*canonical Windows-mount identity",
                )
                packet["locks"] = ["repo:tree:program files"]
                self.assertEqual(
                    cli_impl.packet_lock_integrity_errors(
                        paths,
                        packet_state,
                        packet,
                    ),
                    [],
                )
        for canonical_tilde_name in ("A B~1", "A~1.X.Y", "A~1.💥"):
            lock = f"host:tree:C:/TEMP/{canonical_tilde_name}"
            self.assertEqual(
                h.validate_lock_identity(paths, lock, repo_root=self.root),
                h.normalize_lock(lock),
            )

    def test_repo_lock_colon_typo_is_rejected_with_separator_hint(self) -> None:
        # ARISE defect: `repo:file:rtl/adfp/tests:test_x.py` carried a ':'-for-'/'
        # typo, was accepted with a null baseline, and silently never matched its
        # correctly spelled twin so mutual exclusion never fired.
        for typo in (
            "repo:file:rtl/adfp/tests:test_dense_weight_cache.py",
            "external:file:/srv/data:cache.bin",
        ):
            with self.subTest(typo=typo):
                with self.assertRaisesRegex(
                    h.HarnessError, r"may not contain ':'.*use '/'"
                ):
                    h.normalize_lock(typo)
        self.init_task("colon-typo")
        rejected = self.cli(
            "claim",
            "--task",
            "colon-typo",
            "--token",
            "colon-typo-claim",
            "--owner",
            "root",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:rtl/adfp/tests:test_dense_weight_cache.py",
            "--intent",
            "reproduce the ARISE colon typo",
            "--validation",
            "must be rejected structurally",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("may not contain ':'", rejected.stderr)
        self.assertIn(
            "rtl/adfp/tests:test_dense_weight_cache.py", rejected.stderr
        )

    def test_persisted_malformed_lock_degrades_instead_of_bricking_reads(self) -> None:
        # Tightened admission rules must not make a pre-existing state tree
        # unreadable: ARISE's claims/archive really contains the colon-typo
        # lock, and one such record previously aborted status/doctor entirely.
        self.init_task("legacy-colon")
        typo_lock = "repo:file:rtl/adfp/tests:test_dense_weight_cache.py"
        # Use the task's own recorded worktree spelling: on CI runners the
        # temp root has an NTFS 8.3 alias, and claim/task worktrees must
        # match exactly.
        task_state = json.loads(
            (self.root / ".aoi" / "tasks" / "legacy-colon" / "state.json").read_text(
                encoding="utf-8"
            )
        )
        claim = {
            "schema_version": 1,
            "legacy": False,
            "source": "structured",
            "token": "legacy-colon-claim",
            "task_id": "legacy-colon",
            "owner": "codex-root",
            "kind": "RTL",
            "locks": [typo_lock],
            "intent": "reproduce the ARISE archive record",
            "validation": "read paths must degrade",
            "status": "released",
            "created_at": "2026-07-15T07:16:46+08:00",
            "updated_at": "2026-07-16T13:54:28+08:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "worktree": task_state["worktree"],
            "baselines": [{"lock": typo_lock, "exists": False, "sha256": None}],
        }
        archive = self.root / ".aoi" / "claims" / "archive"
        archive.mkdir(parents=True, exist_ok=True)
        (archive / "legacy-colon-claim.json").write_text(
            json.dumps(claim, indent=1), encoding="utf-8"
        )
        status = json.loads(self.cli("status", "--json").stdout)
        loaded = [
            item
            for item in status["structured_claims"]
            if item["token"] == "legacy-colon-claim"
        ]
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["locks"], [])

        def run_doctor() -> tuple[int, dict]:
            result = subprocess.run(
                [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
                cwd=self.root,
                env=self.env,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            return result.returncode, json.loads(result.stdout)

        returncode, doctor = run_doctor()
        self.assertTrue(
            any(
                "malformed lock excluded from mutual exclusion" in warning
                and "legacy-colon-claim" in warning
                for warning in doctor["warnings"]
            ),
            doctor["warnings"],
        )
        # A still-reserving claim with a malformed lock is the live fail-open
        # hazard and must be a doctor ERROR, not a warning.
        claim["status"] = "active"
        claim["token"] = "legacy-colon-active"
        active_dir = self.root / ".aoi" / "claims" / "active"
        active_dir.mkdir(parents=True, exist_ok=True)
        (active_dir / "legacy-colon-active.json").write_text(
            json.dumps(claim, indent=1), encoding="utf-8"
        )
        returncode, doctor = run_doctor()
        self.assertEqual(returncode, 1, doctor)
        self.assertTrue(
            any(
                "malformed lock excluded from mutual exclusion" in error
                and "legacy-colon-active" in error
                for error in doctor["errors"]
            ),
            doctor["errors"],
        )
        # Review finding: the reserving claim's true pre-tightening scope is
        # unknowable, so every NEW acquire fails closed until it is released.
        blocked = self.cli(
            "claim",
            "--task",
            "legacy-colon",
            "--token",
            "unrelated-new-claim",
            "--owner",
            "root",
            "--kind",
            "DOC",
            "--lock",
            "repo:file:notes/unrelated.md",
            "--intent",
            "unrelated doc edit",
            "--validation",
            "content check",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("malformed lock of unknown scope", blocked.stderr)

    def test_host_lock_drive_colon_allowed_but_second_colon_rejected(self) -> None:
        self.assertEqual(
            h.normalize_lock("host:file:C:/Users/x/file.py"),
            "host:file:C:/users/x/file.py",
        )
        with self.assertRaises(h.HarnessError):
            h.normalize_lock("host:file:C:/Users/x:y.py")


class LifecycleTests(HarnessTestCase):
    def test_plan_approval_gates_claims(self) -> None:
        self.cli(
            "init-task",
            "--task-id",
            "plan-task",
            "--title",
            "Plan gate task",
            "--objective",
            "Verify claims require an approved immutable plan",
            "--owner",
            "root",
            "--completion-boundary",
            "Plan gate behavior is proven",
        )
        claim_args = [
            "claim",
            "--task",
            "plan-task",
            "--token",
            "plan-claim",
            "--owner",
            "root",
            "--kind",
            "DOC",
            "--lock",
            "repo:file:notes/plan.md",
            "--intent",
            "plan gate",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        ]
        blocked = self.cli(*claim_args, ok=False)
        self.assertIn("approve the task plan", blocked.stderr)
        self.cli(
            "approve-plan",
            "--task",
            "plan-task",
            "--note",
            "Generated plan has concrete lifecycle and verification sections",
        )
        self.cli(*claim_args, "--allow-nonexistent")

    def test_oversized_checkpoint_and_close_roll_back_state(self) -> None:
        self.init_task("rollback-task")
        self.cli(
            "checkpoint",
            "--task",
            "rollback-task",
            "--next-action",
            "Record verification",
        )
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "rollback-task"
            / "state.json"
        )
        checkpoint_path = state_path.parent / "checkpoint.md"
        before_state = state_path.read_bytes()
        before_checkpoint = checkpoint_path.read_bytes()
        self.cli_in_process(
            "checkpoint",
            "--task",
            "rollback-task",
            "--fact",
            "x" * 36000,
            "--next-action",
            "Should fail",
            ok=False,
        )
        self.assertEqual(state_path.read_bytes(), before_state)
        self.assertEqual(checkpoint_path.read_bytes(), before_checkpoint)

        self.add_passing_verification("rollback-task")
        self.cli(
            "set-delivery",
            "--task",
            "rollback-task",
            "--mode",
            "none",
            "--detail",
            "no kept files",
        )
        self.cli(
            "checkpoint",
            "--task",
            "rollback-task",
            "--next-action",
            "Close task",
        )
        before_state = state_path.read_bytes()
        before_checkpoint = checkpoint_path.read_bytes()
        self.cli_in_process(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "rollback-task",
            "--summary",
            "x" * 36000,
            ok=False,
        )
        self.assertEqual(state_path.read_bytes(), before_state)
        self.assertEqual(checkpoint_path.read_bytes(), before_checkpoint)
        self.assertEqual(json.loads(before_state)["status"], "active")

    def test_small_checkpoint_preserves_full_render_bytes(self) -> None:
        self.init_task("small-checkpoint")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "small-checkpoint"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        paths = h.get_paths(self.root)
        full = h.render_checkpoint(paths, state)
        _, prepared, digest = h.prepare_checkpoint(paths, state)
        self.assertEqual(prepared, full)
        self.assertEqual(
            digest,
            hashlib.sha256(full.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn("Terminal-detail fallback", prepared)

    def test_compact_claim_references_bind_canonical_lock_set_and_record(self) -> None:
        paths = h.get_paths(self.root)
        locks = [
            "repo:file:scripts/verify/z.py",
            "contract:example-z",
            "repo:file:scripts/verify/a.py",
        ]
        active = {
            "token": "claim-reference",
            "status": "active",
            "locks": locks,
        }
        reordered = {**active, "locks": list(reversed(locks))}
        changed = {**active, "locks": [*locks, "repo:file:extra.py"]}

        rendered = h._compact_claim_reference(paths, active)
        self.assertEqual(
            rendered,
            h._compact_claim_reference(paths, reordered),
        )
        self.assertNotEqual(
            rendered,
            h._compact_claim_reference(paths, changed),
        )
        canonical = json.dumps(
            sorted(locks),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertIn(f"locks={len(locks)}", rendered)
        self.assertIn(
            f"lock_set_sha256={hashlib.sha256(canonical).hexdigest()}",
            rendered,
        )
        self.assertIn(
            "record=claims/active/claim-reference.json",
            rendered,
        )
        released = h._compact_claim_reference(
            paths,
            {**active, "status": "released"},
        )
        self.assertIn(
            "record=claims/archive/claim-reference.json",
            released,
        )

    def test_large_terminal_claim_history_uses_digest_and_recent_tail(self) -> None:
        self.init_task("large-claim-history")
        paths = h.get_paths(self.root)
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "large-claim-history"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        task_worktree = str(h.validated_state_worktree(paths, state))
        terminal_claims = []
        terminal_count = h.COMPACT_CLAIM_HISTORY_THRESHOLD + 4
        terminal_statuses = ("done", "released", "stale")
        for index in range(terminal_count):
            token = f"terminal-claim-{index:02d}"
            status = terminal_statuses[index % len(terminal_statuses)]
            claim = {
                "schema_version": h.SCHEMA_VERSION,
                "legacy": False,
                "source": "structured",
                "token": token,
                "task_id": "large-claim-history",
                "owner": "test-root",
                "kind": "code",
                "locks": [f"repo:file:scripts/verify/{token}.py"],
                "intent": f"terminal history fixture {index}",
                "validation": "deterministic compact history",
                "status": status,
                "created_at": "2026-07-12T00:00:00+00:00",
                "updated_at": f"2026-07-12T00:00:{index:02d}+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "worktree": task_worktree,
                "baselines": {},
            }
            h.atomic_write_json(paths.claims_archive / f"{token}.json", claim)
            state["claims"].append(token)
            terminal_claims.append(claim)

        active_claim = {
            "schema_version": h.SCHEMA_VERSION,
            "legacy": False,
            "source": "structured",
            "token": "active-claim",
            "task_id": "large-claim-history",
            "owner": "test-root",
            "kind": "code",
            "locks": ["repo:file:scripts/verify/active-claim.py"],
            "intent": "active fixture",
            "validation": "remain individually represented",
            "status": "active",
            "created_at": "2026-07-12T00:01:00+00:00",
            "updated_at": "2026-07-12T00:01:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "worktree": task_worktree,
            "baselines": {},
        }
        h.atomic_write_json(paths.claims_active / "active-claim.json", active_claim)
        state["claims"].append("active-claim")

        before = json.dumps(state, sort_keys=True)
        rendered = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        canonical = json.dumps(
            sorted(terminal_claims, key=lambda claim: claim["token"]),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        status_counts = {
            status: sum(claim["status"] == status for claim in terminal_claims)
            for status in terminal_statuses
        }
        counts = ",".join(
            f"{status}={status_counts[status]}" for status in sorted(status_counts)
        )
        self.assertIn(
            f"Terminal claim history: count={terminal_count}; "
            f"status_counts={counts}; "
            f"history_sha256={hashlib.sha256(canonical).hexdigest()}; "
            "task_record=tasks/large-claim-history/state.json#claims; "
            "claim_records=claims/archive",
            rendered,
        )
        self.assertIn(
            f"Terminal-detail fallback for claims: total={terminal_count + 1}; "
            f"full_detail=1; compact_detail={terminal_count}",
            rendered,
        )
        self.assertNotIn("terminal-claim-00 [done]", rendered)
        for index in range(
            terminal_count - h.COMPACT_CLAIM_RECENT_TAIL,
            terminal_count,
        ):
            self.assertIn(f"terminal-claim-{index:02d}[", rendered)
            self.assertIn("=sha256:", rendered)
        self.assertIn(
            "active-claim [active]: "
            "repo:file:scripts/verify/active-claim.py",
            rendered,
        )
        self.assertEqual(before, json.dumps(state, sort_keys=True))

        first_path = paths.claims_archive / "terminal-claim-00.json"
        changed = json.loads(first_path.read_text(encoding="utf-8"))
        changed["intent"] = "changed terminal claim content"
        h.atomic_write_json(first_path, changed)
        changed_rendered = h.render_checkpoint(
            paths,
            state,
            compact_terminal_detail=True,
        )
        self.assertNotEqual(rendered, changed_rendered)

        below_threshold = json.loads(json.dumps(state))
        retained_terminal_count = h.COMPACT_CLAIM_HISTORY_THRESHOLD - 1
        below_threshold["claims"] = [
            *state["claims"][:retained_terminal_count],
            "active-claim",
        ]
        for token in state["claims"][retained_terminal_count:-1]:
            (paths.claims_archive / f"{token}.json").unlink()
        below_rendered = h.render_checkpoint(
            paths,
            below_threshold,
            compact_terminal_detail=True,
        )
        self.assertNotIn("Terminal claim history:", below_rendered)
        self.assertIn("terminal-claim-00 [done]", below_rendered)

    def test_compact_packet_result_keeps_relative_path_visible(self) -> None:
        self.init_task("relative-packet-result")
        paths = h.get_paths(self.root)
        raw_result = (
            ".aoi/tasks/relative-packet-result/results/relative-reader.md"
        )
        digest = "a" * 64
        packet = {
            "packet_id": "relative-reader",
            "result_path": raw_result,
            "result_sha256": digest,
        }
        with mock.patch.object(Path, "cwd", return_value=self.root):
            reference = h._compact_packet_result_reference(
                paths,
                {"task_id": "relative-packet-result"},
                packet,
            )
        self.assertEqual(reference, f"{raw_result}@{digest[:12]}")

    def test_terminal_history_uses_bounded_deterministic_projection(self) -> None:
        self.init_task("compact-checkpoint")
        active_locks = [
            f"repo:file:scripts/verify/active-claim-{index}-{'a' * 80}.py"
            for index in range(6)
        ]
        released_locks = [
            f"repo:file:scripts/verify/released-claim-{index}-{'r' * 80}.py"
            for index in range(4)
        ]
        for token, locks in (
            ("active-compact-claim", active_locks),
            ("released-compact-claim", released_locks),
        ):
            claim_args = [
                "claim",
                "--task",
                "compact-checkpoint",
                "--token",
                token,
                "--owner",
                "test-root",
                "--kind",
                "CODE",
                "--intent",
                "exercise compact claim projection",
                "--validation",
                "deterministic checkpoint rendering",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
            ]
            for lock in locks:
                claim_args.extend(["--lock", lock])
            self.cli(*claim_args, "--allow-nonexistent")
        self.cli(
            "release-claim",
            "--token",
            "released-compact-claim",
            "--status",
            "released",
            "--reason",
            "terminal compact-render fixture",
        )
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "compact-checkpoint"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["next_action"] = "Inspect the deterministic compact checkpoint"
        for index in range(12):
            state["verification"].append(
                {
                    "integrity_version": 1,
                    "category": "unit_test",
                    "status": "pass",
                    "evidence": f"terminal-verification-{index}-" + "e" * 80,
                    "command": f"terminal-command-{index}-" + "c" * 500,
                    "boundary": f"terminal-boundary-{index}-" + "b" * 80,
                    "run_id": "",
                    "recorded_at": "2026-07-12T00:00:00+00:00",
                }
            )
        state["verification"].append(
            {
                "integrity_version": 1,
                "category": "unit_test",
                "status": "pending",
                "evidence": "ACTIVE-VERIFICATION-EVIDENCE",
                "command": "ACTIVE-VERIFICATION-COMMAND",
                "boundary": "ACTIVE-VERIFICATION-BOUNDARY",
                "run_id": "",
                "recorded_at": "2026-07-12T00:00:00+00:00",
            }
        )
        for index in range(8):
            state["jobs"].append(
                {
                    "run_id": f"terminal-job-{index}",
                    "status": "pass",
                    "host": "eda",
                    "tool": "VCS",
                    "log": f"/runs/terminal-job-{index}/simv.log",
                    "pid": "",
                    "tmux": "",
                    "stop_condition": "s" * 300,
                    "source_sha": "a" * 64,
                    "source_scope": "q" * 300,
                    "evidence": "terminal-job-verbose-" + "j" * 300,
                }
            )
        state["jobs"].append(
            {
                "run_id": "active-job",
                "status": "running",
                "host": "eda",
                "tool": "VCS",
                "log": "/runs/active-job/simv.log",
                "pid": "1234",
                "tmux": "ACTIVE-JOB-TMUX",
                "stop_condition": "ACTIVE-JOB-STOP",
                "source_sha": "b" * 64,
                "source_scope": "ACTIVE-JOB-SCOPE",
                "evidence": "ACTIVE-JOB-EVIDENCE",
            }
        )
        task_results = state_path.parent / "results"
        for index in range(8):
            state["packets"].append(
                {
                    "packet_id": f"terminal-packet-{index}",
                    "status": "done",
                    "agent_role": "reviewer",
                    "model_tier": "expert",
                    "agent_id": f"agent-{index}",
                    "result_path": str(
                        task_results / f"terminal-packet-{index}.md"
                    ),
                    "result_sha256": f"{index + 1:x}" * 64,
                    "summary": "terminal-packet-verbose-" + "p" * 500,
                }
            )
        state["packets"].append(
            {
                "packet_id": "active-packet",
                "status": "dispatched",
                "agent_role": "reviewer",
                "model_tier": "expert",
                "agent_id": "ACTIVE-PACKET-AGENT",
                "result_path": "",
                "summary": "ACTIVE-PACKET-SUMMARY",
            }
        )
        before = json.dumps(state, sort_keys=True)
        paths = h.get_paths(self.root)
        full = h.render_checkpoint(paths, state)
        self.assertGreater(
            len(full.encode("utf-8")), h.CHECKPOINT_COMPACT_THRESHOLD_BYTES
        )

        _, prepared, digest = h.prepare_checkpoint(paths, state)
        _, repeated, repeated_digest = h.prepare_checkpoint(paths, state)
        self.assertLessEqual(
            len(prepared.encode("utf-8")), h.CHECKPOINT_MAX_BYTES
        )
        self.assertEqual(prepared, repeated)
        self.assertEqual(digest, repeated_digest)
        self.assertEqual(before, json.dumps(state, sort_keys=True))
        self.assertIn(
            "Terminal-detail fallback for verification: total=13; "
            "full_detail=1; compact_detail=12",
            prepared,
        )
        self.assertIn(
            "Terminal-detail fallback for jobs: total=9; "
            "full_detail=1; compact_detail=8",
            prepared,
        )
        self.assertIn(
            "Terminal-detail fallback for packets: total=9; "
            "full_detail=1; compact_detail=8",
            prepared,
        )
        self.assertIn("complete records remain in state.json", prepared)
        for index in range(12):
            self.assertIn(f"terminal-verification-{index}-", prepared)
            self.assertNotIn(f"terminal-command-{index}-", prepared)
        for index in range(8):
            self.assertIn(f"terminal-packet-{index} [done]", prepared)
            self.assertIn(
                f"result=sha256:{(f'{index + 1:x}' * 64)[:12]}",
                prepared,
            )
        self.assertIn(
            "Terminal job history: count=8; status_counts=pass=8;",
            prepared,
        )
        self.assertNotIn("terminal-job-0 [pass]", prepared)
        for index in range(8 - h.COMPACT_JOB_RECENT_TAIL, 8):
            self.assertIn(f"terminal-job-{index}[pass]=sha256:", prepared)
        self.assertNotIn(str(task_results), prepared)
        self.assertIn("ACTIVE-VERIFICATION-COMMAND", prepared)
        self.assertIn("ACTIVE-JOB-EVIDENCE", prepared)
        self.assertIn("ACTIVE-PACKET-SUMMARY", prepared)
        for lock in (*active_locks, *released_locks):
            self.assertIn(lock, full)
        for lock in active_locks:
            self.assertIn(lock, prepared)
        for lock in released_locks:
            self.assertNotIn(lock, prepared)
        self.assertIn("active-compact-claim [active]: ", prepared)
        released_canonical = json.dumps(
            sorted(released_locks),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertIn(
            f"released-compact-claim [released]: locks={len(released_locks)}; "
            "lock_set_sha256="
            f"{hashlib.sha256(released_canonical).hexdigest()}; "
            "record=claims/archive/released-compact-claim.json",
            prepared,
        )

    def test_large_established_fact_history_keeps_recent_verbatim_tail(self) -> None:
        self.init_task("large-fact-history")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "large-fact-history"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        fact_count = h.COMPACT_FACT_HISTORY_THRESHOLD + 4
        state["facts"] = [
            f"established-fact-{index}-" + chr(97 + index % 26) * 40
            for index in range(fact_count)
        ]
        paths = h.get_paths(self.root)
        before = json.dumps(state, sort_keys=True)
        full = h.render_checkpoint(paths, state)
        rendered = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        canonical = json.dumps(
            state["facts"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertIn(
            f"Established fact history: count={fact_count}; "
            f"history_sha256={hashlib.sha256(canonical).hexdigest()}; "
            "record=tasks/large-fact-history/state.json#facts; "
            f"recent_verbatim={h.COMPACT_FACT_RECENT_TAIL}",
            rendered,
        )
        self.assertIn("established-fact-0-", full)
        self.assertNotIn("established-fact-0-", rendered)
        for index in range(fact_count - h.COMPACT_FACT_RECENT_TAIL, fact_count):
            self.assertIn(f"established-fact-{index}-", rendered)
        self.assertEqual(before, json.dumps(state, sort_keys=True))

        changed = json.loads(json.dumps(state))
        changed["facts"][0] = "changed-established-fact"
        self.assertNotEqual(
            rendered,
            h.render_checkpoint(paths, changed, compact_terminal_detail=True),
        )

        below = json.loads(json.dumps(state))
        below["facts"] = state["facts"][: h.COMPACT_FACT_HISTORY_THRESHOLD - 1]
        below_rendered = h.render_checkpoint(
            paths,
            below,
            compact_terminal_detail=True,
        )
        self.assertNotIn("Established fact history:", below_rendered)
        self.assertIn("established-fact-0-", below_rendered)

    def test_large_terminal_verification_history_is_digest_bound(self) -> None:
        self.init_task("large-verification-history")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "large-verification-history"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        terminal_count = h.COMPACT_VERIFICATION_HISTORY_THRESHOLD + 4
        for index in range(terminal_count):
            state["verification"].append(
                {
                    "integrity_version": 1,
                    "category": "unit_test",
                    "status": "pass" if index % 2 == 0 else "fail",
                    "evidence": f"verification-evidence-{index}",
                    "command": f"verification-command-{index}",
                    "boundary": f"verification-boundary-{index}",
                    "run_id": "",
                    "recorded_at": f"2026-07-12T00:00:{index:02d}+00:00",
                }
            )
        state["verification"].append(
            {
                "integrity_version": 1,
                "category": "integration_test",
                "status": "pending",
                "evidence": "ACTIVE-VERIFICATION-EVIDENCE",
                "command": "ACTIVE-VERIFICATION-COMMAND",
                "boundary": "ACTIVE-VERIFICATION-BOUNDARY",
                "run_id": "",
                "recorded_at": "2026-07-12T00:01:00+00:00",
            }
        )
        paths = h.get_paths(self.root)
        before = json.dumps(state, sort_keys=True)
        rendered = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        terminal = state["verification"][:-1]
        canonical = json.dumps(
            terminal,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        pass_count = sum(item["status"] == "pass" for item in terminal)
        fail_count = sum(item["status"] == "fail" for item in terminal)
        self.assertIn(
            f"Terminal verification history: count={terminal_count}; "
            f"status_counts=fail={fail_count},pass={pass_count}; "
            f"history_sha256={hashlib.sha256(canonical).hexdigest()}; ",
            rendered,
        )
        self.assertIn(
            "record=tasks/large-verification-history/state.json#verification",
            rendered,
        )
        self.assertNotIn("verification-evidence-0", rendered)
        for index in range(
            terminal_count - h.COMPACT_VERIFICATION_RECENT_TAIL,
            terminal_count,
        ):
            self.assertIn(f"#{index + 1}:unit_test[", rendered)
        self.assertIn("ACTIVE-VERIFICATION-COMMAND", rendered)
        self.assertEqual(before, json.dumps(state, sort_keys=True))

        changed = json.loads(json.dumps(state))
        changed["verification"][0]["boundary"] = "changed-boundary"
        self.assertNotEqual(
            rendered,
            h.render_checkpoint(paths, changed, compact_terminal_detail=True),
        )

        below = json.loads(json.dumps(state))
        below["verification"] = [
            *terminal[: h.COMPACT_VERIFICATION_HISTORY_THRESHOLD - 1],
            state["verification"][-1],
        ]
        below_rendered = h.render_checkpoint(
            paths,
            below,
            compact_terminal_detail=True,
        )
        self.assertNotIn("Terminal verification history:", below_rendered)
        self.assertIn("verification-evidence-0", below_rendered)

    def test_large_terminal_job_history_is_digest_bound(self) -> None:
        self.init_task("large-job-history")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "large-job-history"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        terminal_count = h.COMPACT_JOB_HISTORY_THRESHOLD + 4
        for index in range(terminal_count):
            state["jobs"].append(
                {
                    "run_id": f"terminal-job-{index}",
                    "status": "pass" if index % 2 == 0 else "fail",
                    "host": "eda",
                    "tool": "VCS",
                    "log": f"/runs/terminal-job-{index}/simv.log",
                    "pid": "",
                    "tmux": "",
                    "stop_condition": f"terminal-stop-{index}",
                    "source_sha": "a" * 64,
                    "source_scope": f"terminal-scope-{index}",
                    "evidence": f"terminal-evidence-{index}",
                }
            )
        state["jobs"].append(
            {
                "run_id": "active-job",
                "status": "running",
                "host": "eda",
                "tool": "VCS",
                "log": "/runs/active-job/simv.log",
                "pid": "1234",
                "tmux": "ACTIVE-JOB-TMUX",
                "stop_condition": "ACTIVE-JOB-STOP",
                "source_sha": "b" * 64,
                "source_scope": "ACTIVE-JOB-SCOPE",
                "evidence": "ACTIVE-JOB-EVIDENCE",
            }
        )
        paths = h.get_paths(self.root)
        before = json.dumps(state, sort_keys=True)
        rendered = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        terminal = state["jobs"][:-1]
        canonical = json.dumps(
            terminal,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        pass_count = sum(item["status"] == "pass" for item in terminal)
        fail_count = sum(item["status"] == "fail" for item in terminal)
        self.assertIn(
            f"Terminal job history: count={terminal_count}; "
            f"status_counts=fail={fail_count},pass={pass_count}; "
            f"history_sha256={hashlib.sha256(canonical).hexdigest()}; ",
            rendered,
        )
        self.assertIn("record=tasks/large-job-history/state.json#jobs", rendered)
        self.assertNotIn("terminal-job-0 [pass]", rendered)
        for index in range(
            terminal_count - h.COMPACT_JOB_RECENT_TAIL,
            terminal_count,
        ):
            status = "pass" if index % 2 == 0 else "fail"
            self.assertIn(f"terminal-job-{index}[{status}]=sha256:", rendered)
        self.assertIn("ACTIVE-JOB-EVIDENCE", rendered)
        self.assertEqual(before, json.dumps(state, sort_keys=True))

        changed = json.loads(json.dumps(state))
        changed["jobs"][0]["evidence"] = "changed-evidence"
        self.assertNotEqual(
            rendered,
            h.render_checkpoint(paths, changed, compact_terminal_detail=True),
        )

        below = json.loads(json.dumps(state))
        below["jobs"] = [
            *terminal[: h.COMPACT_JOB_HISTORY_THRESHOLD - 1],
            state["jobs"][-1],
        ]
        below_rendered = h.render_checkpoint(
            paths,
            below,
            compact_terminal_detail=True,
        )
        self.assertNotIn("Terminal job history:", below_rendered)
        self.assertIn("terminal-job-0 [pass]", below_rendered)

    def test_large_terminal_packet_history_uses_digest_and_recent_tail(self) -> None:
        self.init_task("large-packet-history")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "large-packet-history"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        results = state_path.parent / "results"
        for index in range(h.COMPACT_PACKET_HISTORY_THRESHOLD + 4):
            state["packets"].append(
                {
                    "packet_id": f"terminal-packet-{index}",
                    "status": "done",
                    "agent_role": "reviewer",
                    "model_tier": "expert",
                    "agent_id": f"agent-{index}",
                    "result_path": str(results / f"terminal-packet-{index}.md"),
                    "result_sha256": hashlib.sha256(
                        f"terminal-packet-{index}".encode("utf-8")
                    ).hexdigest(),
                    "summary": f"summary-{index}",
                }
            )
        state["packets"].append(
            {
                "packet_id": "active-packet",
                "status": "dispatched",
                "agent_role": "reviewer",
                "model_tier": "expert",
                "agent_id": "active-agent",
                "result_path": "",
                "summary": "ACTIVE-PACKET-SUMMARY",
            }
        )
        paths = h.get_paths(self.root)
        before = json.dumps(state, sort_keys=True)
        rendered = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        terminal = state["packets"][:-1]
        canonical = json.dumps(
            terminal,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertIn(
            f"Terminal packet history: count={len(terminal)}; "
            f"status_counts=done={len(terminal)}; "
            f"history_sha256={hashlib.sha256(canonical).hexdigest()}; "
            "record=tasks/large-packet-history/state.json#packets",
            rendered,
        )
        self.assertNotIn("terminal-packet-0 [done]", rendered)
        for index in range(len(terminal) - h.COMPACT_PACKET_RECENT_TAIL, len(terminal)):
            self.assertIn(f"terminal-packet-{index}[done]=sha256:", rendered)
        self.assertIn("ACTIVE-PACKET-SUMMARY", rendered)
        self.assertEqual(before, json.dumps(state, sort_keys=True))

        changed = json.loads(json.dumps(state))
        changed["packets"][0]["summary"] = "changed-summary"
        changed_rendered = h.render_checkpoint(
            paths,
            changed,
            compact_terminal_detail=True,
        )
        self.assertNotEqual(rendered, changed_rendered)

        below_threshold = json.loads(json.dumps(state))
        below_threshold["packets"] = [
            *terminal[: h.COMPACT_PACKET_HISTORY_THRESHOLD - 1],
            state["packets"][-1],
        ]
        below_rendered = h.render_checkpoint(
            paths,
            below_threshold,
            compact_terminal_detail=True,
        )
        self.assertNotIn("Terminal packet history:", below_rendered)
        self.assertIn("terminal-packet-0 [done]", below_rendered)

    def test_compact_fallback_allows_required_active_detail_above_target(self) -> None:
        self.init_task("active-checkpoint-above-target")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "active-checkpoint-above-target"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        active_detail = "ACTIVE-DETAIL-" + "x" * 18000
        state["jobs"].append(
            {
                "run_id": "active-above-target-job",
                "status": "running",
                "host": "eda",
                "tool": "VCS",
                "log": "/runs/active-above-target-job/simv.log",
                "pid": "1234",
                "tmux": "active-above-target",
                "stop_condition": active_detail,
                "source_sha": "c" * 64,
                "source_scope": "current source",
                "evidence": "still running",
            }
        )
        paths = h.get_paths(self.root)
        compact = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        compact_bytes = len(compact.encode("utf-8"))
        self.assertGreater(compact_bytes, h.CHECKPOINT_COMPACT_THRESHOLD_BYTES)
        self.assertLessEqual(compact_bytes, h.CHECKPOINT_MAX_BYTES)

        _, prepared, _ = h.prepare_checkpoint(paths, state)

        self.assertEqual(prepared, compact)
        self.assertIn(active_detail, prepared)

    def test_compact_fallback_never_truncates_oversized_active_detail(self) -> None:
        self.init_task("active-oversized-checkpoint")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "active-oversized-checkpoint"
            / "state.json"
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["jobs"].append(
            {
                "run_id": "active-oversized-job",
                "status": "running",
                "host": "eda",
                "tool": "VCS",
                "log": "/runs/active-oversized-job/simv.log",
                "pid": "1234",
                "tmux": "active-oversized",
                "stop_condition": "ACTIVE-DETAIL-" + "x" * 36000,
                "source_sha": "c" * 64,
                "source_scope": "current source",
                "evidence": "still running",
            }
        )
        with self.assertRaisesRegex(
            h.HarnessError, "checkpoint exceeds 32 KiB hard ceiling"
        ):
            h.prepare_checkpoint(h.get_paths(self.root), state)

    def test_compact_fallback_never_hides_oversized_active_claim_locks(self) -> None:
        self.init_task("active-claim-oversized-checkpoint")
        claim_args = [
            "claim",
            "--task",
            "active-claim-oversized-checkpoint",
            "--token",
            "active-oversized-claim",
            "--owner",
            "test-root",
            "--kind",
            "CODE",
            "--intent",
            "prove active lock visibility is fail-closed",
            "--validation",
            "checkpoint must reject rather than hide active locks",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        ]
        locks = [
            f"repo:file:scripts/verify/active-lock-{index:03d}-{'x' * 80}.py"
            for index in range(280)
        ]
        for lock in locks:
            claim_args.extend(["--lock", lock])
        self.cli_in_process(*claim_args, "--allow-nonexistent")
        paths = h.get_paths(self.root)
        state = h.load_task(paths, "active-claim-oversized-checkpoint")
        compact = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        for lock in locks:
            self.assertIn(lock, compact)
        with self.assertRaisesRegex(
            h.HarnessError, "checkpoint exceeds 32 KiB hard ceiling"
        ):
            h.prepare_checkpoint(paths, state)

    def test_close_gate_requires_claim_release_checkpoint_and_delivery(self) -> None:
        self.init_task("close-task")
        self.cli(
            "claim",
            "--task",
            "close-task",
            "--token",
            "close-claim",
            "--owner",
            "root",
            "--kind",
            "DOC",
            "--lock",
            "repo:file:notes/result.md",
            "--intent",
            "write result",
            "--validation",
            "content check",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
        )
        self.add_passing_verification("close-task")
        self.cli(
            "set-delivery",
            "--task",
            "close-task",
            "--mode",
            "none",
            "--detail",
            "test task has no tracked delivery",
        )
        self.cli(
            "checkpoint",
            "--task",
            "close-task",
            "--next-action",
            "Release the claim and close",
        )
        failed = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "close-task",
            "--summary",
            "done",
            ok=False,
        )
        self.assertIn("non-terminal claims", failed.stderr)
        self.cli(
            "release-claim",
            "--token",
            "close-claim",
            "--status",
            "done",
            "--reason",
            "test mutation complete",
        )
        stale = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "close-task",
            "--summary",
            "done",
            ok=False,
        )
        self.assertIn("checkpoint is stale", stale.stderr)
        self.cli(
            "checkpoint",
            "--task",
            "close-task",
            "--next-action",
            "Close the task",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "close-task",
            "--summary",
            "All lifecycle gates passed",
        )
        state = json.loads(
            (
                self.root
                / ".aoi"
                / "tasks"
                / "close-task"
                / "state.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(state["status"], "done")
        self.assertFalse(state["checkpoint_required"])
        self.assertEqual(state["revision"], state["checkpoint_revision"])

    def test_close_gate_rejects_empty_and_pending_verification(self) -> None:
        self.init_task("close-empty-verification")
        self.cli(
            "set-delivery",
            "--task",
            "close-empty-verification",
            "--mode",
            "none",
            "--detail",
            "No tracked delivery is expected for this gate test",
        )
        self.cli(
            "checkpoint",
            "--task",
            "close-empty-verification",
            "--next-action",
            "Prove empty verification blocks close",
        )
        empty = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "close-empty-verification",
            "--summary",
            "must remain open",
            ok=False,
        )
        self.assertIn("no verification/evidence record", empty.stderr)
        self.assertEqual(
            h.load_task(h.get_paths(self.root), "close-empty-verification")["status"],
            "active",
        )

        self.init_task("close-pending-verification")
        self.cli(
            "add-verification",
            "--task",
            "close-pending-verification",
            "--category",
            "unit_test",
            "--status",
            "pending",
            "--evidence",
            "The bounded test command has not completed yet",
            "--command",
            "python3 -m unittest pending-case",
            "--boundary",
            "Only the named pending close-gate behavior",
        )
        self.cli(
            "set-delivery",
            "--task",
            "close-pending-verification",
            "--mode",
            "none",
            "--detail",
            "No tracked delivery is expected for this gate test",
        )
        self.cli(
            "checkpoint",
            "--task",
            "close-pending-verification",
            "--next-action",
            "Prove pending verification blocks close",
        )
        pending = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "close-pending-verification",
            "--summary",
            "must remain open",
            ok=False,
        )
        self.assertIn("at least one passing, close-qualifying verification", pending.stderr)
        self.assertIn("unaccounted verification: unit_test", pending.stderr)
        self.assertEqual(
            h.load_task(h.get_paths(self.root), "close-pending-verification")["status"],
            "active",
        )

    def test_malformed_task_list_fields_fail_as_harness_errors(self) -> None:
        self.init_task("malformed-list-state")
        paths = h.get_paths(self.root)
        state_path = h.task_state_path(paths, "malformed-list-state")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["verification"] = "oops"
        h.atomic_write_json(state_path, state)
        rejected = self.cli(
            "checkpoint",
            "--task",
            "malformed-list-state",
            "--next-action",
            "must not render malformed state",
            ok=False,
        )
        self.assertIn("task field 'verification' must be a list", rejected.stderr)

        valid = {
            "schema_version": 1,
            "profile_id": "default",
            "config_sha256": "0" * 64,
            "task_id": "shape-check",
            "status": "active",
            "phase": "planning",
            "profile": "full",
            "revision": 1,
            "checkpoint_revision": 0,
        }
        for field in sorted(h.TASK_STRING_LIST_FIELDS | h.TASK_OBJECT_LIST_FIELDS):
            with self.subTest(field=field):
                malformed = dict(valid)
                malformed[field] = "not-a-list"
                with self.assertRaisesRegex(h.HarnessError, "must be a list"):
                    h.validate_task_state(malformed)

    def test_cancel_requires_needs_user_disposition(self) -> None:
        self.init_task("cancel-needs-user")
        self.cli(
            "set-delivery",
            "--task",
            "cancel-needs-user",
            "--mode",
            "none",
            "--detail",
            "Cancellation test has no tracked delivery",
        )
        paths = h.get_paths(self.root)
        state = h.load_task(paths, "cancel-needs-user")
        state["needs_user_escalations"] = [
            {
                "integrity_version": 1,
                "escalation_id": "budget-choice",
                "status": "needs_user",
                "category": "cost_budget",
            }
        ]
        h.bump_task(state)
        h.write_task(paths, state)
        blocked = self.cli(
            "cancel-task",
            "--task",
            "cancel-needs-user",
            "--reason",
            "Do not hide an unresolved user-owned budget choice",
            ok=False,
        )
        self.assertIn("unresolved needs-user escalations: budget-choice", blocked.stderr)
        self.assertEqual(h.load_task(paths, "cancel-needs-user")["status"], "active")

        state = h.load_task(paths, "cancel-needs-user")
        state["needs_user_escalations"][0]["status"] = "resolved"
        state["needs_user_escalations"][0]["user_disposition"] = {
            "decision": "Cancel the entire task",
            "evidence": "Explicit test-user disposition",
        }
        h.bump_task(state)
        h.write_task(paths, state)
        self.cli(
            "cancel-task",
            "--task",
            "cancel-needs-user",
            "--reason",
            "User disposition explicitly selected cancellation",
        )
        self.assertEqual(h.load_task(paths, "cancel-needs-user")["status"], "cancelled")

    def test_orphan_active_claim_blocks_close(self) -> None:
        self.init_task("orphan-task")
        self.add_passing_verification("orphan-task")
        self.cli(
            "set-delivery",
            "--task",
            "orphan-task",
            "--mode",
            "none",
            "--detail",
            "no files changed",
        )
        self.cli(
            "checkpoint",
            "--task",
            "orphan-task",
            "--next-action",
            "Close",
        )
        paths = h.get_paths(self.root)
        h.ensure_layout(paths)
        task_worktree = str(
            h.validated_state_worktree(paths, h.load_task(paths, "orphan-task"))
        )
        h.atomic_write_json(
            paths.claims_active / "orphan-claim.json",
            {
                "schema_version": 1,
                "legacy": False,
                "source": "structured",
                "token": "orphan-claim",
                "task_id": "orphan-task",
                "owner": "crash",
                "kind": "DOC",
                "locks": ["repo:file:notes/orphan.md"],
                "intent": "simulate crash",
                "validation": "close gate",
                "status": "active",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "worktree": task_worktree,
                "baselines": {},
            },
        )
        state_path = paths.tasks / "orphan-task" / "state.json"
        checkpoint_path = paths.tasks / "orphan-task" / "checkpoint.md"
        before_state = state_path.read_bytes()
        before_checkpoint = checkpoint_path.read_bytes()
        rejected_checkpoint = self.cli(
            "checkpoint",
            "--task",
            "orphan-task",
            "--next-action",
            "Do not omit the crash-orphaned authority",
            ok=False,
        )
        self.assertIn("orphan claim orphan-claim", rejected_checkpoint.stderr)
        self.assertEqual(state_path.read_bytes(), before_state)
        self.assertEqual(checkpoint_path.read_bytes(), before_checkpoint)
        scoped_doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "doctor",
                "--task",
                "orphan-task",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(scoped_doctor.returncode, 1, scoped_doctor.stderr)
        self.assertIn("active/archive orphan claim orphan-claim", scoped_doctor.stdout)
        failed = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "orphan-task",
            "--summary",
            "must not close",
            ok=False,
        )
        self.assertIn("orphan claims", failed.stderr)

    def test_packet_routing_locks_results_and_close_gate(self) -> None:
        self.init_task("packet-task")
        base = [
            "create-packet",
            "--task",
            "packet-task",
            "--packet-id",
            "review",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect source",
            "--scope",
            "Read-only inspection",
            "--deliverable",
            "Bounded result",
            "--validation",
            "Cross-check",
        ]
        invalid = self.cli(*base, "--lock", "repo:file:../escape", ok=False)
        self.assertIn("escapes", invalid.stderr)
        unowned = self.cli(
            *base,
            "--lock",
            "repo:file:rtl/a.sv",
            "--packet-mode",
            "bounded_mutation",
            ok=False,
        )
        self.assertIn("not fully covered", unowned.stderr)
        self.cli(*base)
        self.add_passing_verification("packet-task")
        self.cli(
            "set-delivery",
            "--task",
            "packet-task",
            "--mode",
            "none",
            "--detail",
            "read-only task",
        )
        self.cli(
            "checkpoint",
            "--task",
            "packet-task",
            "--next-action",
            "Collect packet",
        )
        unfinished = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "packet-task",
            "--summary",
            "not yet",
            ok=False,
        )
        self.assertIn("unfinished delegation packets", unfinished.stderr)
        invalid_transition = self.cli(
            "packet-update",
            "--task",
            "packet-task",
            "--packet-id",
            "review",
            "--status",
            "done",
            "--summary",
            "Source inspection complete",
            "--evidence",
            "result cites exact source paths",
            ok=False,
        )
        self.assertIn("invalid packet transition", invalid_transition.stderr)
        self.dispatch_packet(
            "packet-task",
            "review",
            "agent-1",
            "--actual-role",
            "explorer",
            "--actual-model-tier",
            "standard",
            "--routing-evidence",
            "test dispatcher exposed exact custom role and tier",
        )
        self.cli(
            "packet-update",
            "--task",
            "packet-task",
            "--packet-id",
            "review",
            "--status",
            "done",
            "--summary",
            "Source inspection complete",
            "--evidence",
            "result cites exact source paths",
        )
        self.cli(
            "checkpoint",
            "--task",
            "packet-task",
            "--next-action",
            "Close",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "packet-task",
            "--summary",
            "Read-only packet and passing verification complete",
        )

    def test_unknown_external_job_blocks_close_and_terminal_needs_evidence(self) -> None:
        self.init_task("eda-task")
        receipt, receipt_sha = self.write_source_receipt("source-receipt.json")
        self.cli(
            "claim",
            "--task",
            "eda-task",
            "--token",
            "eda-claim",
            "--owner",
            "root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/aoi-example-run",
            "--intent",
            "bounded EDA test",
            "--validation",
            "job gate",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli(
            "job-start",
            "--task",
            "eda-task",
            "--run-id",
            "run-1",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/aoi-example-run",
            "--status",
            "queued",
            "--log",
            "/tmp/aoi-example-run/driver.log",
            "--stop-condition",
            "PASS or first fatal",
            "--source-sha",
            receipt_sha,
            "--source-manifest",
            str(receipt),
            "--tool-path",
            "/tools/vcs",
            "--tool-version",
            "VCS-test",
            "--command",
            "timeout 1m run.sh",
        )
        self.cli(
            "job-update",
            "--task",
            "eda-task",
            "--run-id",
            "run-1",
            "--status",
            "running",
            "--evidence",
            "isolated test process launched",
            "--pid",
            "12345",
        )
        missing_exit = self.cli(
            "job-update",
            "--task",
            "eda-task",
            "--run-id",
            "run-1",
            "--status",
            "pass",
            "--evidence",
            "/tmp/aoi-example-run/driver.log",
            ok=False,
        )
        self.assertIn("exit-code", missing_exit.stderr)
        self.cli(
            "job-update",
            "--task",
            "eda-task",
            "--run-id",
            "run-1",
            "--status",
            "unknown",
            "--evidence",
            "host became unreachable; termination unproven",
        )
        blocked_release = self.cli(
            "release-claim",
            "--token",
            "eda-claim",
            "--status",
            "done",
            "--reason",
            "test lock no longer mutates output",
            ok=False,
        )
        self.assertIn("active work depends", blocked_release.stderr)
        self.add_passing_verification(
            "eda-task", evidence="job lifecycle test recorded terminal evidence"
        )
        self.cli(
            "set-delivery",
            "--task",
            "eda-task",
            "--mode",
            "none",
            "--detail",
            "no kept files",
        )
        self.cli(
            "checkpoint",
            "--task",
            "eda-task",
            "--next-action",
            "Resolve unknown job",
        )
        unresolved = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "eda-task",
            "--summary",
            "must not close",
            ok=False,
        )
        self.assertIn("unresolved queued/running/unknown jobs", unresolved.stderr)
        terminal_log, terminal_log_sha = self.write_terminal_log(
            "aoi-example-run-driver.log"
        )
        self.cli(
            "job-update",
            "--task",
            "eda-task",
            "--run-id",
            "run-1",
            "--status",
            "pass",
            "--evidence",
            "/tmp/aoi-example-run/driver.log exit=0 PASS",
            "--exit-code",
            "0",
            "--terminal-log-artifact",
            str(terminal_log),
            "--terminal-log-sha256",
            terminal_log_sha,
        )
        self.cli(
            "release-claim",
            "--token",
            "eda-claim",
            "--status",
            "done",
            "--reason",
            "terminal job evidence permits output-lock release",
        )
        self.cli(
            "checkpoint",
            "--task",
            "eda-task",
            "--next-action",
            "Close",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "eda-task",
            "--summary",
            "EDA lifecycle gate verified",
        )

    def test_packet_completion_rejects_result_as_own_evidence(self) -> None:
        self.init_task("evidence-gate")
        self.cli(
            "create-packet",
            "--task",
            "evidence-gate",
            "--packet-id",
            "review",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect source",
            "--scope",
            "Read-only inspection",
            "--deliverable",
            "Bounded result",
            "--validation",
            "Cross-check",
        )
        self.dispatch_packet(
            "evidence-gate",
            "review",
            "agent-1",
            "--actual-role",
            "explorer",
            "--actual-model-tier",
            "standard",
            "--routing-evidence",
            "test dispatcher exposed exact custom role and tier",
        )
        own_result = (
            self.root / ".aoi" / "tasks" / "evidence-gate" / "results" / "review.md"
        )
        rejected = self.cli(
            "packet-update",
            "--task",
            "evidence-gate",
            "--packet-id",
            "review",
            "--status",
            "done",
            "--summary",
            "Source inspection complete",
            "--evidence",
            str(own_result),
            ok=False,
        )
        self.assertIn("its own result file", rejected.stderr)
        # A single external primary artifact reference (alongside the self-ref)
        # satisfies the gate and stamps evidence_gate_version.
        self.cli(
            "packet-update",
            "--task",
            "evidence-gate",
            "--packet-id",
            "review",
            "--status",
            "done",
            "--summary",
            "Source inspection complete",
            "--evidence",
            str(own_result),
            "--evidence",
            "/runs/vcs/driver.log lines 12-88",
        )
        state = json.loads(
            (self.root / ".aoi" / "tasks" / "evidence-gate" / "state.json").read_text(
                encoding="utf-8"
            )
        )
        packet = next(p for p in state["packets"] if p["packet_id"] == "review")
        self.assertEqual(packet["evidence_gate_version"], 1)

    def test_job_start_records_observed_launch_and_flags_retroactive(self) -> None:
        self.init_task("job-lag")
        receipt, receipt_sha = self.write_source_receipt("lag-receipt.json")
        self.cli(
            "claim",
            "--task",
            "job-lag",
            "--token",
            "job-lag-claim",
            "--owner",
            "root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/aoi-lag",
            "--intent",
            "bounded lag test",
            "--validation",
            "job gate",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )

        def start(run_id: str, *extra: str, ok: bool = True):
            work_root = f"/tmp/aoi-lag/{run_id}"
            return self.cli(
                "job-start",
                "--task",
                "job-lag",
                "--run-id",
                run_id,
                "--host",
                "eda",
                "--tool",
                "VCS",
                "--work-root",
                work_root,
                "--status",
                "queued",
                "--log",
                f"{work_root}/driver.log",
                "--stop-condition",
                "PASS or first fatal",
                "--source-sha",
                receipt_sha,
                "--source-manifest",
                str(receipt),
                "--tool-path",
                "/tools/vcs",
                "--tool-version",
                "VCS-test",
                "--command",
                "timeout 1m run.sh",
                "--json",
                *extra,
                ok=ok,
            )

        def stop(run_id: str) -> None:
            # Implicit single-execution allows one active chain; retire each job
            # before starting the next so this stays a per-job timing test.
            self.cli(
                "job-update",
                "--task",
                "job-lag",
                "--run-id",
                run_id,
                "--status",
                "stopped",
                "--evidence",
                "isolated harness retired the queued job",
                "--exit-code",
                "1",
            )

        now = dt.datetime.now().astimezone()
        observed_recent = (now - dt.timedelta(seconds=30)).isoformat()
        observed_old = (now - dt.timedelta(minutes=10)).isoformat()
        observed_future = (now + dt.timedelta(minutes=5)).isoformat()

        recent = json.loads(
            start("run-recent", "--observed-start-at", observed_recent).stdout
        )
        self.assertIn("observed_start_at", recent)
        self.assertGreater(recent["registration_lag_seconds"], 0)
        self.assertLess(recent["registration_lag_seconds"], 120)
        self.assertNotIn("retroactive_reason", recent)
        stop("run-recent")

        missing_reason = start(
            "run-old-noreason", "--observed-start-at", observed_old, ok=False
        )
        self.assertIn("--retroactive-reason", missing_reason.stderr)

        old = json.loads(
            start(
                "run-old",
                "--observed-start-at",
                observed_old,
                "--retroactive-reason",
                "tmux launch physically preceded AOI job registration",
            ).stdout
        )
        self.assertGreater(old["registration_lag_seconds"], 120)
        self.assertEqual(
            old["retroactive_reason"],
            "tmux launch physically preceded AOI job registration",
        )
        stop("run-old")

        future = start("run-future", "--observed-start-at", observed_future, ok=False)
        self.assertIn("future", future.stderr)

        legacy = json.loads(start("run-legacy").stdout)
        self.assertIn("registered_at", legacy)
        self.assertNotIn("registration_lag_seconds", legacy)
        self.assertNotIn("observed_start_at", legacy)
        stop("run-legacy")

        summary = json.loads(
            self.cli("status", "--task", "job-lag", "--json").stdout
        )
        self.assertGreater(summary["max_job_registration_lag_seconds"], 120)

    def test_legacy_import_quarantines_expired_active_and_conflicts(self) -> None:
        legacy = self.root / "LEGACY_CONTROL.md"
        original = (
            r"""# Legacy

### Active Claims

| token | owner | kind | scope | intent | validation | started | expires | status |
|---|---|---|---|---|---|---|---|---|
| old-active | old | SCRIPT | `scripts/foo.py` | old A \| B task | `rg "x|y"` check | 2020-01-01 CST | 2020-01-02 CST | active |
| old-done | old | SCRIPT | `scripts/bar.py` | done task | pass | 2020-01-01 CST | 2020-01-02 CST | done |

## Next section
"""
        )
        legacy.write_text(original, encoding="utf-8")
        before = hashlib.sha256(legacy.read_bytes()).hexdigest()
        self.cli("import-legacy")
        self.assertEqual(hashlib.sha256(legacy.read_bytes()).hexdigest(), before)
        pending = list(
            (self.root / ".aoi" / "claims" / "legacy_pending").glob(
                "*.json"
            )
        )
        self.assertEqual(len(pending), 1)
        claim = json.loads(pending[0].read_text(encoding="utf-8"))
        self.assertEqual(claim["token"], "old-active")
        self.assertEqual(claim["legacy_classification"], "expired_unverified")
        self.assertIn("A | B", claim["intent"])
        self.init_task("new-task")
        conflict = self.cli(
            "claim",
            "--task",
            "new-task",
            "--token",
            "new-claim",
            "--owner",
            "root",
            "--kind",
            "SCRIPT",
            "--lock",
            "repo:file:scripts/foo.py",
            "--intent",
            "must conflict",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("old-active", conflict.stderr)

    def test_legacy_adoption_is_explicit_and_cannot_shrink_scope(self) -> None:
        legacy = self.root / "LEGACY_CONTROL.md"
        legacy.write_text(
            """# Legacy

### Active Claims

| token | owner | kind | scope | intent | validation | started | expires | status |
|---|---|---|---|---|---|---|---|---|
| old-adopt | old | SCRIPT | `scripts/**` | old task | old check | 2020-01-01 CST | 2020-01-02 CST | active |

## End
""",
            encoding="utf-8",
        )
        self.cli("import-legacy")
        self.init_task("adopter")
        common = [
            "claim",
            "--task",
            "adopter",
            "--token",
            "old-adopt",
            "--owner",
            "new-root",
            "--kind",
            "SCRIPT",
            "--intent",
            "explicit migration",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        ]
        collision = self.cli(*common, "--lock", "repo:tree:scripts", ok=False)
        self.assertIn("explicit", collision.stderr)
        shrink = self.cli(
            *common,
            "--lock",
            "repo:file:scripts/new.py",
            "--adopt-legacy",
            "--adoption-evidence",
            "owner and process audit",
            ok=False,
        )
        self.assertIn("uncovered", shrink.stderr)
        self.cli(
            *common,
            "--lock",
            "repo:tree:scripts",
            "--adopt-legacy",
            "--adoption-evidence",
            "owner, source, and live job audit proves transfer",
        )
        self.assertFalse(h.legacy_pending_path(h.get_paths(self.root), "old-adopt").exists())

    def test_malformed_legacy_row_fails_loudly(self) -> None:
        legacy = self.root / "LEGACY_CONTROL.md"
        legacy.write_text(
            """# Legacy

### Active Claims

| token | owner | kind | scope | intent | validation | started | expires | status |
|---|---|---|---|---|---|---|---|---|
| malformed | old | SCRIPT | `scripts/a.py` | A | B unescaped | check | 2020-01-01 CST | 2020-01-02 CST | active |

## End
""",
            encoding="utf-8",
        )
        failed = self.cli("import-legacy", ok=False)
        self.assertIn("malformed rows", failed.stderr)
        self.assertFalse(
            any(
                (self.root / ".aoi" / "claims" / "legacy_pending").glob(
                    "*.json"
                )
            )
        )

    def test_planned_repo_file_requires_allow_nonexistent(self) -> None:
        self.init_task("planned-task")
        (self.root / "notes").mkdir()
        base = [
            "claim",
            "--task",
            "planned-task",
            "--token",
            "planned-claim",
            "--owner",
            "root",
            "--kind",
            "DOC",
            "--lock",
            "repo:file:notes/plan.md",
            "--intent",
            "reserve a not-yet-created planned file",
            "--validation",
            "planned admission",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        ]
        rejected = self.cli(*base, ok=False)
        self.assertIn("planned file", rejected.stderr)
        self.assertIn("--allow-nonexistent", rejected.stderr)
        self.assertFalse(
            (h.get_paths(self.root).claims_active / "planned-claim.json").exists()
        )
        self.cli(*base, "--allow-nonexistent")
        claim = json.loads(
            (
                h.get_paths(self.root).claims_active / "planned-claim.json"
            ).read_text(encoding="utf-8")
        )
        baseline = claim["baselines"]["repo:file:notes/plan.md"]
        self.assertFalse(baseline["exists"])
        self.assertIsNone(baseline["sha256"])
        self.assertTrue(baseline["planned"])

    def test_missing_parent_repo_file_names_the_absent_parent(self) -> None:
        self.init_task("typo-parent-task")
        base = [
            "claim",
            "--task",
            "typo-parent-task",
            "--token",
            "typo-parent-claim",
            "--owner",
            "root",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:rtl/adfp/tests/test_missing.py",
            "--intent",
            "a directory misspelling leaves both target and parent missing",
            "--validation",
            "must name the absent parent, not offer the planned-file flag alone",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        ]
        rejected = self.cli(*base, ok=False)
        self.assertIn("parent directory", rejected.stderr)
        self.assertIn("path typo", rejected.stderr)
        self.assertNotIn("(planned file)", rejected.stderr)
        # The same flag still admits an explicitly planned deep target.
        self.cli(*base, "--allow-nonexistent")

    def test_mini_rejects_planned_or_missing_targets(self) -> None:
        rejected = self.cli(
            "start-mini",
            "--task-id",
            "mini-missing",
            "--title",
            "Mini with an absent target",
            "--objective",
            "A mini task may not reserve planned or missing files",
            "--owner",
            "root",
            "--completion-boundary",
            "Rejected atomically before any state is written",
            "--session-id",
            "mini-missing-session",
            "--token",
            "mini-missing-claim",
            "--lock",
            "repo:file:notes/mini.md",
            "--intent",
            "planned mini edit",
            "--validation",
            "must reject",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("mini task", rejected.stderr)
        self.assertIn("--allow-nonexistent", rejected.stderr)
        self.assertFalse(
            h.task_state_path(h.get_paths(self.root), "mini-missing").exists()
        )
        self.assertFalse(
            h.session_path(
                h.get_paths(self.root), "mini-missing-session"
            ).exists()
        )


class HardeningTests(HarnessTestCase):
    def test_legacy_brace_duplicate_and_code_spans_fail_closed(self) -> None:
        legacy = self.root / "LEGACY_CONTROL.md"
        legacy.write_text(
            """# Legacy

### Active Claims

| token | owner | kind | scope | intent | validation | started | expires | status |
|---|---|---|---|---|---|---|---|---|
| brace | old | CODE | `scripts/unrelated.py`, `src/modules/{a,b}.py` | own both | inspect | now | 2099-01-01T00:00:00+00:00 | active |

## End
""",
            encoding="utf-8",
        )
        self.cli("import-legacy")
        pending = list(
            (self.root / ".aoi" / "claims" / "legacy_pending").glob(
                "*.json"
            )
        )
        claim = json.loads(pending[0].read_text(encoding="utf-8"))
        self.assertIn("repo:tree:src/modules", claim["locks"])
        self.assertEqual(claim["scope_parse_warnings"], [])

        check = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "check-locks",
                "--lock",
                "repo:file:src/modules/a.py",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(check.returncode, 1, check.stderr)
        self.assertIn("brace", check.stdout)
        self.init_task("brace-new")
        direct = self.cli(
            "claim",
            "--task",
            "brace-new",
            "--token",
            "brace-new-claim",
            "--owner",
            "new",
            "--kind",
            "CODE",
            "--lock",
            "repo:file:src/modules/b.py",
            "--intent",
            "must conflict",
            "--validation",
            "legacy overlap",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("claim conflict", direct.stderr)

        before_pending = {
            path.name: path.read_bytes() for path in pending
        }
        legacy.write_text(
            """# Legacy

### Active Claims

| token | owner | kind | scope | intent | validation | started | expires | status |
|---|---|---|---|---|---|---|---|---|
| dup | old | SCRIPT | `scripts/a.py` | first | inspect | now | 2099-01-01T00:00:00+00:00 | active |
| dup | old | SCRIPT | `scripts/b.py` | second | inspect | now | 2099-01-01T00:00:00+00:00 | active |

## End
""",
            encoding="utf-8",
        )
        duplicate = self.cli("import-legacy", ok=False)
        self.assertIn("duplicate non-terminal token", duplicate.stderr)
        self.assertEqual(
            {path.name: path.read_bytes() for path in pending}, before_pending
        )

        cells = h.split_markdown_row(
            "| a | b | ``rg '`x|y`'`` | d | e | f | g | h | i |"
        )
        self.assertEqual(len(cells), 9)
        self.assertEqual(cells[2], "``rg '`x|y`'``")
        with self.assertRaises(h.HarnessError):
            h.split_markdown_row("| a | `unterminated | c | d | e | f | g | h | i |")

    def test_partial_legacy_ambiguity_blocks_check_and_direct_claim(self) -> None:
        legacy = self.root / "LEGACY_CONTROL.md"
        legacy.write_text(
            """# Legacy

### Active Claims

| token | owner | kind | scope | intent | validation | started | expires | status |
|---|---|---|---|---|---|---|---|---|
| partial | old | SCRIPT | `scripts/unrelated.py`, `mystery_root/path.bin` | partial scope | inspect | now | 2099-01-01T00:00:00+00:00 | active |

## End
""",
            encoding="utf-8",
        )
        self.cli("import-legacy")
        check = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "check-locks",
                "--lock",
                "repo:file:docs/new.md",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        payload = json.loads(check.stdout)
        self.assertEqual(check.returncode, 1, check.stderr)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["ambiguous_legacy_rows"][0]["token"], "partial")
        self.init_task("partial-new")
        direct = self.cli(
            "claim",
            "--task",
            "partial-new",
            "--token",
            "partial-new-claim",
            "--owner",
            "new",
            "--kind",
            "DOC",
            "--lock",
            "repo:file:docs/new.md",
            "--intent",
            "must not bypass ambiguity",
            "--validation",
            "named ambiguity is blocking",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("unresolved ambiguous legacy scope", direct.stderr)

    def test_dispatched_packet_prevents_claim_release(self) -> None:
        self.init_task("packet-lock-task")
        self.cli(
            "claim",
            "--task",
            "packet-lock-task",
            "--token",
            "packet-lock-claim",
            "--owner",
            "root",
            "--kind",
            "SCRIPT",
            "--lock",
            "repo:file:scripts/a.py",
            "--intent",
            "delegate bounded file",
            "--validation",
            "packet owns the same file",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
        )
        packet = self.cli(
            "create-packet",
            "--task",
            "packet-lock-task",
            "--packet-id",
            "writer",
            "--agent-role",
            "worker",
            "--model-tier",
            "advanced",
            "--objective",
            "Inspect the claimed script",
            "--scope",
            "Only scripts/a.py",
            "--lock",
            "repo:file:scripts/a.py",
            "--packet-mode",
            "bounded_mutation",
            "--deliverable",
            "Bounded report",
            "--validation",
            "Cite the exact file",
        )
        self.dispatch_packet("packet-lock-task", "writer", "agent-writer")
        blocked = self.cli(
            "release-claim",
            "--token",
            "packet-lock-claim",
            "--status",
            "done",
            "--reason",
            "must remain reserved",
            ok=False,
        )
        self.assertIn("packet writer requires", blocked.stderr)
        self.cli(
            "packet-update",
            "--task",
            "packet-lock-task",
            "--packet-id",
            "writer",
            "--status",
            "done",
            "--summary",
            "Bounded inspection finished",
            "--evidence",
            "Exact source path and observation recorded",
        )
        self.cli(
            "release-claim",
            "--token",
            "packet-lock-claim",
            "--status",
            "done",
            "--reason",
            "terminal packet result is integrity-protected",
        )

    def test_source_receipt_and_job_transition_integrity(self) -> None:
        self.init_task("receipt-task")
        self.cli(
            "claim",
            "--task",
            "receipt-task",
            "--token",
            "receipt-claim",
            "--owner",
            "root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/receipt-run",
            "--intent",
            "test source receipt integrity",
            "--validation",
            "job state remains transactional",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        base = [
            "job-start",
            "--task",
            "receipt-task",
            "--run-id",
            "receipt-run",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/receipt-run",
            "--status",
            "queued",
            "--log",
            "/tmp/receipt-run/driver.log",
            "--stop-condition",
            "PASS or first fatal",
            "--tool-path",
            "/tools/vcs",
            "--tool-version",
            "VCS-test",
            "--command",
            "timeout 1m run.sh",
        ]
        state_path = (
            self.root / ".aoi" / "tasks" / "receipt-task" / "state.json"
        )
        before = state_path.read_bytes()
        self.cli(
            *base,
            "--source-sha",
            "a" * 64,
            "--source-manifest",
            str(self.root / "missing-receipt.json"),
            ok=False,
        )
        self.assertEqual(state_path.read_bytes(), before)

        invalid = self.root / "invalid-receipt.json"
        invalid.write_text("{}\n", encoding="utf-8")
        invalid_sha = hashlib.sha256(invalid.read_bytes()).hexdigest()
        self.cli(
            *base,
            "--source-sha",
            invalid_sha,
            "--source-manifest",
            str(invalid),
            ok=False,
        )
        self.assertEqual(state_path.read_bytes(), before)

        receipt, receipt_sha = self.write_source_receipt("valid-receipt.json")
        self.cli(
            *base,
            "--source-sha",
            "c" * 64,
            "--source-manifest",
            str(receipt),
            ok=False,
        )
        self.assertEqual(state_path.read_bytes(), before)
        self.cli(
            *base,
            "--source-sha",
            receipt_sha,
            "--source-manifest",
            str(receipt),
        )
        running_without_identity = self.cli(
            "job-update",
            "--task",
            "receipt-task",
            "--run-id",
            "receipt-run",
            "--status",
            "running",
            "--evidence",
            "launch command returned successfully",
            ok=False,
        )
        self.assertIn("pid or tmux", running_without_identity.stderr)
        self.cli(
            "job-update",
            "--task",
            "receipt-task",
            "--run-id",
            "receipt-run",
            "--status",
            "running",
            "--evidence",
            "isolated process launched under test pid",
            "--pid",
            "4242",
        )
        nonzero_pass = self.cli(
            "job-update",
            "--task",
            "receipt-task",
            "--run-id",
            "receipt-run",
            "--status",
            "pass",
            "--evidence",
            "synthetic PASS marker with nonzero exit",
            "--exit-code",
            "7",
            ok=False,
        )
        self.assertIn("requires exit code 0", nonzero_pass.stderr)
        terminal_log, terminal_log_sha = self.write_terminal_log(
            "receipt-run-driver.log"
        )
        self.cli(
            "job-update",
            "--task",
            "receipt-task",
            "--run-id",
            "receipt-run",
            "--status",
            "pass",
            "--evidence",
            "driver.log records PASS and process exit 0",
            "--exit-code",
            "0",
            "--terminal-log-artifact",
            str(terminal_log),
            "--terminal-log-sha256",
            terminal_log_sha,
        )
        job = h.load_json(
            self.root / ".aoi" / "tasks" / "receipt-task" / "state.json"
        )["jobs"][0]
        self.assertEqual(job["terminal_artifact_status"], "preserved")
        terminal_manifest = h.load_json(Path(job["terminal_manifest_path"]))
        self.assertEqual(
            Path(terminal_manifest["artifact"]["capture_source"]),
            terminal_log.resolve(),
        )
        self.assertEqual(
            terminal_manifest["artifact"]["sha256"], terminal_log_sha
        )

    def test_packet_result_tamper_blocks_close_and_doctor(self) -> None:
        self.init_task("packet-tamper")
        self.cli(
            "create-packet",
            "--task",
            "packet-tamper",
            "--packet-id",
            "reader",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Read bounded state",
            "--scope",
            "Read only",
            "--deliverable",
            "Result artifact",
            "--validation",
            "Physical SHA is checked",
        )
        self.dispatch_packet("packet-tamper", "reader", "reader-agent")
        self.cli(
            "packet-update",
            "--task",
            "packet-tamper",
            "--packet-id",
            "reader",
            "--status",
            "done",
            "--summary",
            "Reader returned a bounded result",
            "--evidence",
            "Canonical result artifact was written",
        )
        self.add_passing_verification("packet-tamper")
        self.cli(
            "set-delivery",
            "--task",
            "packet-tamper",
            "--mode",
            "none",
            "--detail",
            "read-only isolated test",
        )
        self.cli(
            "checkpoint",
            "--task",
            "packet-tamper",
            "--next-action",
            "Close only if result integrity holds",
        )
        result_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "packet-tamper"
            / "results"
            / "reader.md"
        )
        result_path.write_text("tampered\n", encoding="utf-8")
        close = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "packet-tamper",
            "--summary",
            "must not close",
            ok=False,
        )
        self.assertIn("result SHA-256 mismatch", close.stderr)
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
        self.assertFalse(json.loads(doctor.stdout)["ok"])

    def test_post_close_packet_result_tamper_is_doctor_error(self) -> None:
        self.init_task("post-close-tamper")
        self.cli(
            "create-packet",
            "--task",
            "post-close-tamper",
            "--packet-id",
            "reader",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Produce an integrity-protected result",
            "--scope",
            "Read only",
            "--deliverable",
            "Canonical result",
            "--validation",
            "Doctor checks it after close",
        )
        self.dispatch_packet("post-close-tamper", "reader", "reader-agent")
        self.cli(
            "packet-update",
            "--task",
            "post-close-tamper",
            "--packet-id",
            "reader",
            "--status",
            "done",
            "--summary",
            "Reader completed the bounded assignment",
            "--evidence",
            "Canonical result exists before task close",
        )
        self.add_passing_verification("post-close-tamper")
        self.cli(
            "set-delivery",
            "--task",
            "post-close-tamper",
            "--mode",
            "none",
            "--detail",
            "read-only isolated task",
        )
        self.cli(
            "checkpoint",
            "--task",
            "post-close-tamper",
            "--next-action",
            "Close the intact task",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "post-close-tamper",
            "--summary",
            "Task closed with intact packet result",
        )
        result_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "post-close-tamper"
            / "results"
            / "reader.md"
        )
        result_path.write_text("modified after close\n", encoding="utf-8")
        doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        payload = json.loads(doctor.stdout)
        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        self.assertFalse(payload["ok"])
        self.assertTrue(
            any("terminal task post-close-tamper" in item for item in payload["errors"]),
            payload,
        )

    def test_pushed_delivery_requires_exact_remote_ref(self) -> None:
        self.init_task("push-task")
        tracked = self.root / ".harness-test-root"
        tracked.write_text("test root\nnew delivery\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", ".harness-test-root"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "delivery"],
            check=True,
            text=True,
            capture_output=True,
        )
        commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        missing_remote = self.cli(
            "set-delivery",
            "--task",
            "push-task",
            "--mode",
            "pushed",
            "--detail",
            "must prove remote",
            "--commit",
            commit,
            ok=False,
        )
        self.assertIn("requires --remote", missing_remote.stderr)

        bare = self.root / "origin.git"
        subprocess.run(
            ["git", "init", "--bare", str(bare)],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "remote", "add", "origin", str(bare)],
            check=True,
        )
        not_pushed = self.cli(
            "set-delivery",
            "--task",
            "push-task",
            "--mode",
            "pushed",
            "--detail",
            "local object is insufficient",
            "--commit",
            commit,
            "--remote",
            "origin",
            "--remote-ref",
            "refs/heads/main",
            ok=False,
        )
        self.assertIn("could not verify pushed remote ref", not_pushed.stderr)
        subprocess.run(
            ["git", "-C", str(self.root), "push", "origin", "main:refs/heads/main"],
            check=True,
            text=True,
            capture_output=True,
        )
        result = self.cli(
            "set-delivery",
            "--task",
            "push-task",
            "--mode",
            "pushed",
            "--detail",
            "exact remote main tip verified",
            "--commit",
            commit,
            "--remote",
            "origin",
            "--remote-ref",
            "refs/heads/main",
            "--json",
        )
        self.assertEqual(json.loads(result.stdout)["remote_sha"], commit)

    def test_terminal_delivery_accepts_only_synced_descendant_branch(self) -> None:
        task_id = "terminal-delivery-lineage"
        self.init_task(task_id)
        tracked = self.root / ".harness-test-root"
        tracked.write_text("test root\ndelivery base\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", ".harness-test-root"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "delivery base"],
            check=True,
            text=True,
            capture_output=True,
        )
        base_commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        bare = self.root / "origin.git"
        subprocess.run(
            ["git", "init", "--bare", str(bare)],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "remote", "add", "origin", str(bare)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "push", "origin", "main:refs/heads/main"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "pushed",
            "--detail",
            "base delivery",
            "--commit",
            base_commit,
            "--remote",
            "origin",
            "--remote-ref",
            "refs/heads/main",
        )
        self.add_passing_verification(task_id)
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Close after delivery validation",
        )

        tracked.write_text("test root\ndelivery base\nactive drift\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", ".harness-test-root"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "active drift"],
            check=True,
            text=True,
            capture_output=True,
        )
        active_commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(self.root), "push", "origin", "main:refs/heads/main"],
            check=True,
            text=True,
            capture_output=True,
        )
        active_drift = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            task_id,
            "--summary",
            "must not close against stale delivery",
            ok=False,
        )
        self.assertIn("is not the task worktree HEAD", active_drift.stderr)

        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "pushed",
            "--detail",
            "refreshed exact active delivery",
            "--commit",
            active_commit,
            "--remote",
            "origin",
            "--remote-ref",
            "refs/heads/main",
        )
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Close the task",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            task_id,
            "--summary",
            "Exact active delivery closed",
        )

        tracked.write_text(
            "test root\ndelivery base\nactive drift\nterminal descendant\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(self.root), "add", ".harness-test-root"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "terminal descendant"],
            check=True,
            text=True,
            capture_output=True,
        )
        terminal_head = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(self.root), "push", "origin", "main:refs/heads/main"],
            check=True,
            text=True,
            capture_output=True,
        )
        descendant = self.cli("doctor", "--task", task_id, "--json")
        descendant_payload = json.loads(descendant.stdout)
        self.assertTrue(descendant_payload["ok"])
        self.assertEqual(descendant_payload["errors"], [])

        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "push",
                "--force",
                "origin",
                f"{base_commit}:refs/heads/main",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        rewound = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(rewound.returncode, 1, rewound.stderr)
        self.assertIn("not the terminal task worktree HEAD", rewound.stdout)
        self.assertNotEqual(base_commit, terminal_head)

    def test_non_git_worktree_is_rejected_without_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.env.copy()
            env["AOI_ROOT"] = str(root)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m", CLI_MODULE,
                    "init-task",
                    "--task-id",
                    "not-git",
                    "--title",
                    "No Git",
                    "--objective",
                    "Must reject unknown provenance",
                    "--owner",
                    "root",
                    "--completion-boundary",
                    "No state is created",
                ],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("AOI is not initialized", result.stderr)
            self.assertFalse((root / ".aoi" / "tasks").exists())

    def test_verification_schema_and_inference_close_boundary(self) -> None:
        self.init_task("verification-task")
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "verification-task"
            / "state.json"
        )
        before = state_path.read_bytes()
        unknown = self.cli(
            "add-verification",
            "--task",
            "verification-task",
            "--category",
            "made-up-success-class",
            "--status",
            "pass",
            "--evidence",
            "synthetic success text",
            "--command",
            "true",
            "--boundary",
            "nothing",
            ok=False,
        )
        self.assertIn("invalid choice", unknown.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        generic = self.cli(
            "add-verification",
            "--task",
            "verification-task",
            "--category",
            "unit_test",
            "--status",
            "pass",
            "--evidence",
            "pass",
            "--command",
            "true",
            "--boundary",
            "bounded",
            ok=False,
        )
        self.assertIn("too generic", generic.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        missing_method = self.cli(
            "add-verification",
            "--task",
            "verification-task",
            "--category",
            "unit_test",
            "--status",
            "pass",
            "--evidence",
            "bounded runner artifact reports PASS",
            "--boundary",
            "isolated verification only",
            ok=False,
        )
        self.assertIn("--command", missing_method.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        self.cli(
            "add-verification",
            "--task",
            "verification-task",
            "--category",
            "engineering_inference",
            "--status",
            "pass",
            "--evidence",
            "Source inspection suggests the behavior",
            "--command",
            "manual source inspection",
            "--boundary",
            "Inference only; no executable acceptance",
        )
        self.cli(
            "set-delivery",
            "--task",
            "verification-task",
            "--mode",
            "none",
            "--detail",
            "read-only test",
        )
        self.cli(
            "checkpoint",
            "--task",
            "verification-task",
            "--next-action",
            "Add executable evidence",
        )
        inference_only = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "verification-task",
            "--summary",
            "must not close on inference",
            ok=False,
        )
        self.assertIn("close-qualifying verification", inference_only.stderr)
        self.add_passing_verification("verification-task")
        self.cli(
            "checkpoint",
            "--task",
            "verification-task",
            "--next-action",
            "Close after executable evidence",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "verification-task",
            "--summary",
            "Executable verification satisfied the boundary",
        )

    def test_current_checkpoint_corruption_is_doctor_error(self) -> None:
        self.init_task("checkpoint-integrity")
        self.cli(
            "checkpoint",
            "--task",
            "checkpoint-integrity",
            "--next-action",
            "Keep checkpoint current",
        )
        checkpoint = (
            self.root
            / ".aoi"
            / "tasks"
            / "checkpoint-integrity"
            / "checkpoint.md"
        )
        checkpoint.write_text("corrupt\n", encoding="utf-8")
        doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        payload = json.loads(doctor.stdout)
        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        self.assertTrue(
            any("checkpoint mismatch" in item for item in payload["errors"]), payload
        )

    def test_idempotent_session_bind_reports_actual_checkpoint_state(self) -> None:
        self.init_task("bind-idempotent", session_id="same-session")
        self.cli(
            "checkpoint",
            "--task",
            "bind-idempotent",
            "--next-action",
            "Remain current",
        )
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "bind-idempotent"
            / "state.json"
        )
        before = state_path.read_bytes()
        result = self.cli(
            "bind-session",
            "--task",
            "bind-idempotent",
            "--session-id",
            "same-session",
            "--json",
        )
        payload = json.loads(result.stdout)
        self.assertFalse(payload["checkpoint_required"])
        self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual(payload["revision"], json.loads(before)["revision"])


class ParallelLaneCoordinationTests(HarnessTestCase):
    """Contract tests for lean parallel lanes and root arbitration."""

    def git_commit(self, name: str) -> str:
        marker = self.root / f"authority-{name}.txt"
        marker.write_text(f"{name}\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", marker.name], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", f"authority {name}"],
            check=True,
            text=True,
            capture_output=True,
        )
        return subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

    def task_state(self, task_id: str) -> dict:
        return json.loads(
            (
                self.root
                / ".aoi"
                / "tasks"
                / task_id
                / "state.json"
            ).read_text(encoding="utf-8")
        )

    def test_skill_canary_binding_precedes_wall_clock_order(self) -> None:
        canary_time = "2026-07-14T00:00:00+00:00"
        packet = {
            "packet_id": "candidate",
            "status": "done",
            "result_sha256": "a" * 64,
            "completed_at": "2026-07-13T23:59:59+00:00",
            "lane_id": "rtl",
        }
        state = {"packets": [packet]}
        common = {
            "label": "skill canary",
            "minimum": 1,
            "canary_recorded_at": canary_time,
            "require_after_canary": True,
            "expected_skill_release_id": "skill-v1",
            "expected_skill_version": "1.0.0",
            "expected_canary_event_id": "canary-1",
        }
        with self.assertRaisesRegex(h.HarnessError, "not bound to the exact skill canary"):
            cli_impl._resolve_adoption_work_units(
                state, ["packet:candidate"], **common
            )

        packet.update(
            {
                "skill_release_id": "skill-v1",
                "skill_version": "1.0.0",
                "skill_canary_event_id": "canary-1",
            }
        )
        with self.assertRaisesRegex(h.HarnessError, "does not postdate the bound canary"):
            cli_impl._resolve_adoption_work_units(
                state, ["packet:candidate"], **common
            )

    def lane_state(self, task_id: str, lane_id: str) -> dict:
        lanes = self.task_state(task_id)["lanes"]
        if isinstance(lanes, dict):
            return lanes[lane_id]
        return next(lane for lane in lanes if lane["lane_id"] == lane_id)

    def tree_bytes(self) -> dict[str, bytes]:
        harness_root = self.root / ".aoi"
        return {
            path.relative_to(harness_root).as_posix(): path.read_bytes()
            for path in sorted(harness_root.rglob("*"))
            if path.is_file()
        }

    def create_lane(
        self,
        task_id: str,
        lane_id: str,
        *,
        kind: str,
        role: str,
        authority_commit: str,
        contract_version: str = "cv1",
        generator_version: str | None = "gv1",
        adapter_version: str | None = "av1",
        status: str = "active",
    ) -> dict:
        args = [
            "lane-create",
            "--task",
            task_id,
            "--lane-id",
            lane_id,
            "--kind",
            kind,
            "--status",
            status,
            "--owner",
            f"{lane_id}-agent",
            "--role",
            role,
            "--authority-commit",
            authority_commit,
            "--contract-version",
            contract_version,
            "--next-action",
            f"Advance {lane_id} independently",
        ]
        if generator_version is not None:
            args.extend(["--generator-version", generator_version])
        if adapter_version is not None:
            args.extend(["--adapter-version", adapter_version])
        args.append("--json")
        return json.loads(self.cli(*args).stdout)

    def revise_lane(
        self,
        task_id: str,
        lane_id: str,
        *,
        authority_commit: str,
        change_class: str,
        contract_version: str,
        generator_version: str,
        adapter_version: str,
        coord: str | None = None,
        ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        args = [
            "lane-revise",
            "--task",
            task_id,
            "--lane-id",
            lane_id,
            "--expected-revision",
            "1",
            "--authority-commit",
            authority_commit,
            "--change-class",
            change_class,
            "--contract-version",
            contract_version,
            "--generator-version",
            generator_version,
            "--adapter-version",
            adapter_version,
            "--decision",
            f"Root authorizes bounded {change_class} work in {lane_id}",
            "--session-id",
            self.task_state(task_id)["session_ids"][0],
            "--next-action",
            f"Validate {lane_id} revision",
        ]
        if coord is not None:
            args.extend(["--coord", coord])
        args.append("--json")
        return self.cli(*args, ok=ok)

    def create_selected_packet(
        self,
        task_id: str,
        packet_id: str,
        lane_id: str,
        selection_id: str,
    ) -> None:
        lane = self.lane_state(task_id, lane_id)
        role = str(lane["role"])
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            role,
            "--model-tier",
            cli_impl.ROLE_TIER_MAP[role],
            "--objective",
            f"Inspect the bounded {lane_id} evidence question for {packet_id}",
            "--scope",
            "Read-only specialist review under the exact execution selection",
            "--deliverable",
            "One bounded conclusion with exact source evidence",
            "--validation",
            "The Chief checks the result against the selected lane authority",
            "--lane-id",
            lane_id,
            "--execution-selection-id",
            selection_id,
        )

    def test_single_mode_allows_only_one_active_depth_one_chain(self) -> None:
        task_id = "single-chain-fence"
        self.init_task(task_id, session_id="chief-single-chain")
        commit = self.git_commit(task_id)
        self.create_lane(
            task_id,
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.cli(
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "single-review",
            "--work-unit-id",
            "single-review-work",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "One causal RTL review chain with no parallel specialist execution",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "medium",
            "--shared-context",
            "high",
            "--rationale",
            "Both reviews consume the same evolving RTL context and must be serialized",
            "--falsification-condition",
            "Replace this selection if independent lane authorities are created",
            "--escalation-condition",
            "Escalate if the evidence question crosses a numeric contract boundary",
            "--session-id",
            "chief-single-chain",
        )
        self.create_selected_packet(task_id, "review-one", "rtl", "single-review")
        self.create_selected_packet(task_id, "review-two", "rtl", "single-review")
        self.dispatch_packet(task_id, "review-one", "/root/review-one")
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "review-two",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/review-two",
            ok=False,
        )
        self.assertIn("single execution mode already has", rejected.stderr)
        first = self.task_state(task_id)["packets"][0]
        self.assertEqual(first["dispatch_provenance"], "manual_unverified")
        self.assertNotIn("dispatched_at", first)
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "review-one",
            "--status",
            "done",
            "--summary",
            "The first serialized RTL review completed under its exact selection",
            "--evidence",
            "The result records manual-unverified dispatch provenance and exact lane binding",
        )
        self.dispatch_packet(task_id, "review-two", "/root/review-two")

    def test_task_global_execution_epoch_blocks_implicit_and_cross_selection_parallelism(
        self,
    ) -> None:
        implicit_task = "implicit-single-epoch"
        self.init_task(implicit_task)

        def create_unselected(packet_id: str) -> None:
            self.cli(
                "create-packet",
                "--task",
                implicit_task,
                "--packet-id",
                packet_id,
                "--agent-role",
                "explorer",
                "--model-tier",
                "standard",
                "--objective",
                f"Inspect one bounded implicit-single question for {packet_id}",
                "--scope",
                "Read-only unselected packet",
                "--deliverable",
                "One bounded result",
                "--validation",
                "Chief checks the exact result",
            )

        create_unselected("implicit-one")
        create_unselected("implicit-two")
        self.assertEqual(
            self.task_state(implicit_task)["execution_policy_version"], 2
        )
        self.assertIs(
            self.task_state(implicit_task)["legacy_execution_policy"], False
        )
        self.dispatch_packet(implicit_task, "implicit-one", "/root/implicit-one")
        rejected = self.cli(
            "packet-update",
            "--task",
            implicit_task,
            "--packet-id",
            "implicit-two",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/implicit-two",
            ok=False,
        )
        self.assertIn("implicit single execution already has", rejected.stderr)
        implicit_state_path = (
            self.root / ".aoi" / "tasks" / implicit_task / "state.json"
        )
        downgraded = self.task_state(implicit_task)
        downgraded.pop("execution_policy_version")
        downgraded.pop("task_execution_schema_version")
        implicit_state_path.write_text(
            json.dumps(downgraded, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        downgrade_rejected = self.cli(
            "packet-update",
            "--task",
            implicit_task,
            "--packet-id",
            "implicit-two",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/implicit-two",
            ok=False,
        )
        self.assertIn(
            "native execution-policy task lost or downgraded",
            downgrade_rejected.stderr,
        )
        downgrade_doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", implicit_task, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(downgrade_doctor.returncode, 1, downgrade_doctor.stderr)
        self.assertIn(
            "native execution-policy task lost or downgraded",
            downgrade_doctor.stdout,
        )

        selected_task = "cross-selection-epoch"
        self.init_task(selected_task, session_id="chief-cross-selection")
        commit = self.git_commit(selected_task)
        self.create_lane(
            selected_task,
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )

        def select_single(selection_id: str, work_unit_id: str) -> None:
            self.cli(
                "execution-select",
                "--task",
                selected_task,
                "--selection-id",
                selection_id,
                "--work-unit-id",
                work_unit_id,
                "--mode",
                "single",
                "--lane",
                "rtl",
                "--scope",
                f"One bounded report for {work_unit_id}",
                "--sequential-dependency",
                "high",
                "--tool-density",
                "low",
                "--shared-context",
                "high",
                "--rationale",
                "This work unit is explicitly single-chain",
                "--falsification-condition",
                "Supersede only if distinct specialist lanes are required",
                "--escalation-condition",
                "Escalate if another selection needs concurrent execution",
                "--session-id",
                "chief-cross-selection",
            )

        select_single("single-a", "work-a")
        select_single("single-b", "work-b")
        self.create_selected_packet(selected_task, "report-a", "rtl", "single-a")
        self.create_selected_packet(selected_task, "report-b", "rtl", "single-b")
        self.dispatch_packet(selected_task, "report-a", "/root/report-a")
        rejected = self.cli(
            "packet-update",
            "--task",
            selected_task,
            "--packet-id",
            "report-b",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/report-b",
            ok=False,
        )
        self.assertIn("task-global execution epoch", rejected.stderr)

    def test_legacy_parallel_selection_does_not_require_a_retroactive_v2_brief(self) -> None:
        paths = h.get_paths(self.root)
        selection = {
            "selection_id": "legacy-parallel",
            "mode": "centralized_parallel",
        }
        state = {
            "packets": [
                {
                    "packet_id": "legacy-result",
                    "lane_id": "rtl",
                    "status": "done",
                    "result_sha256": "a" * 64,
                    "execution_selection_id": "legacy-parallel",
                }
            ],
            "execution_briefs": [],
        }
        self.assertIsNone(
            cli_impl._execution_brief_coverage_error(paths, state, selection)
        )
        selection["execution_selection_version"] = 2
        self.assertIn(
            "lacks a Steward result brief",
            cli_impl._execution_brief_coverage_error(paths, state, selection) or "",
        )
        selection.pop("execution_selection_version")
        selection["steward_snapshot"] = {}
        self.assertIn(
            "v2-only fields without a selection version",
            cli_impl._execution_brief_coverage_error(paths, state, selection) or "",
        )

    def test_task_global_execution_epoch_includes_standalone_jobs(self) -> None:
        task_id = "job-execution-epoch"
        self.init_task(task_id, session_id="chief-job-epoch")
        commit = self.git_commit(task_id)
        for lane_id in ("rtl", "numeric"):
            self.create_lane(
                task_id,
                lane_id,
                kind="implementation" if lane_id == "rtl" else "analysis",
                role=(
                    "implementation_specialist"
                    if lane_id == "rtl"
                    else "analysis_specialist"
                ),
                authority_commit=commit,
            )
            self.cli(
                "execution-select",
                "--task",
                task_id,
                "--selection-id",
                f"{lane_id}-single",
                "--work-unit-id",
                f"{lane_id}-work",
                "--mode",
                "single",
                "--lane",
                lane_id,
                "--scope",
                f"One standalone {lane_id} external execution chain",
                "--sequential-dependency",
                "high",
                "--tool-density",
                "high",
                "--shared-context",
                "high",
                "--rationale",
                "The external command is one causal execution chain",
                "--falsification-condition",
                "Stop if another chain already occupies the task epoch",
                "--escalation-condition",
                "Require an explicit parallel topology for concurrent jobs",
                "--session-id",
                "chief-job-epoch",
            )
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "job-epoch-claim",
            "--owner",
            "test-root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/job-epoch-rtl",
            "--lock",
            "external:tree:/tmp/job-epoch-numeric",
            "--intent",
            "Exercise task-global job topology without launching a real tool",
            "--validation",
            "The second queued job must be rejected before state mutation",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        receipt, receipt_sha = self.write_source_receipt("job-epoch-source.json")

        def start_job(run_id: str, lane_id: str, *, ok: bool = True):
            root = f"/tmp/job-epoch-{lane_id}"
            return self.cli(
                "job-start",
                "--task",
                task_id,
                "--run-id",
                run_id,
                "--host",
                "eda",
                "--tool",
                "VCS",
                "--work-root",
                root,
                "--log",
                f"{root}/driver.log",
                "--stop-condition",
                "PASS or first fatal",
                "--source-sha",
                receipt_sha,
                "--source-manifest",
                str(receipt),
                "--tool-path",
                "/tools/vcs",
                "--tool-version",
                "VCS-test",
                "--command",
                "timeout 1m run.sh",
                "--lane-id",
                lane_id,
                "--execution-selection-id",
                f"{lane_id}-single",
                ok=ok,
            )

        start_job("rtl-run", "rtl")
        rejected = start_job("numeric-run", "numeric", ok=False)
        self.assertIn("task-global execution epoch", rejected.stderr)
        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)

    def test_external_job_can_be_owned_by_one_dispatched_packet_chain(self) -> None:
        task_id = "owned-job-chain"
        self.init_task(task_id, session_id="chief-owned-job")
        commit = self.git_commit(task_id)
        self.create_lane(
            task_id,
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.cli(
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "owned-job-single",
            "--work-unit-id",
            "owned-job-work",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "One specialist packet owns one external command lifecycle",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "high",
            "--shared-context",
            "high",
            "--rationale",
            "The job is nested in the already-authorized packet chain",
            "--falsification-condition",
            "Reject if packet and job authorities diverge",
            "--escalation-condition",
            "Stop the job before completing its owner packet",
            "--session-id",
            "chief-owned-job",
        )
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "owned-job-claim",
            "--owner",
            "test-root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/owned-job-chain",
            "--intent",
            "Exercise nested job authority without launching a real tool",
            "--validation",
            "Owner packet cannot finish while its job remains active",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "job-owner",
            "--agent-role",
            "implementation_specialist",
            "--model-tier",
            "expert",
            "--objective",
            "Own one bounded external command lifecycle",
            "--scope",
            "Run only inside the claimed external output tree",
            "--deliverable",
            "Terminal job evidence and one bounded conclusion",
            "--validation",
            "The Chief checks job and packet terminal evidence",
            "--packet-mode",
            "bounded_mutation",
            "--lock",
            "external:tree:/tmp/owned-job-chain",
            "--lane-id",
            "rtl",
            "--execution-selection-id",
            "owned-job-single",
        )
        self.dispatch_packet(task_id, "job-owner", "/root/job-owner")
        receipt, receipt_sha = self.write_source_receipt("owned-job-source.json")
        self.cli(
            "job-start",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/owned-job-chain",
            "--log",
            "/tmp/owned-job-chain/driver.log",
            "--stop-condition",
            "PASS or first fatal",
            "--source-sha",
            receipt_sha,
            "--source-manifest",
            str(receipt),
            "--tool-path",
            "/tools/vcs",
            "--tool-version",
            "VCS-test",
            "--command",
            "timeout 1m run.sh",
            "--lane-id",
            "rtl",
            "--execution-selection-id",
            "owned-job-single",
            "--owner-packet-id",
            "job-owner",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        owner_packet = next(
            packet for packet in state["packets"] if packet["packet_id"] == "job-owner"
        )
        owner_contract = Path(owner_packet["path"])
        owner_contract_bytes = owner_contract.read_bytes()
        owner_contract.write_bytes(owner_contract_bytes + b"\nphysical drift\n")
        drifted_launch = self.cli(
            "job-update",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--status",
            "running",
            "--pid",
            "424242",
            "--evidence",
            "Owner contract drift must be rejected at the launch boundary",
            ok=False,
        )
        self.assertIn("owner packet authority is missing or tampered", drifted_launch.stderr)
        owner_contract.write_bytes(owner_contract_bytes)

        valid_state_bytes = state_path.read_bytes()
        lock_drift = json.loads(valid_state_bytes)
        next(
            packet
            for packet in lock_drift["packets"]
            if packet["packet_id"] == "job-owner"
        )["locks"] = []
        state_path.write_text(
            json.dumps(lock_drift, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        lock_doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(lock_doctor.returncode, 1, lock_doctor.stderr)
        self.assertIn("output paths exceed the owner packet locks", lock_doctor.stdout)
        state_path.write_bytes(valid_state_bytes)

        self.cli(
            "job-update",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--status",
            "running",
            "--pid",
            "424242",
            "--evidence",
            "Physical owner authority and canonical output locks were revalidated",
        )
        blocked = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "job-owner",
            "--status",
            "done",
            "--summary",
            "Owner attempted to finish before its job",
            "--evidence",
            "The active owned job must block this transition",
            ok=False,
        )
        self.assertIn("child work is active", blocked.stderr)
        self.cli(
            "job-update",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--status",
            "stopped",
            "--evidence",
            "The bounded external job was stopped before owner completion",
            "--exit-code",
            "143",
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "job-owner",
            "--status",
            "done",
            "--summary",
            "Owner completed after its nested job became terminal",
            "--evidence",
            "The job lifecycle and owner packet share one exact chain",
        )
        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)

    def test_centralized_parallel_allows_cross_lane_but_not_same_lane_overlap(self) -> None:
        task_id = "centralized-lane-fence"
        self.init_task(task_id, session_id="chief-centralized")
        commit = self.git_commit(task_id)
        for lane_id, kind, role in (
            ("rtl", "implementation", "implementation_specialist"),
            ("numeric", "analysis", "analysis_specialist"),
            ("steward", "coordination_steward", "default"),
        ):
            self.create_lane(
                task_id,
                lane_id,
                kind=kind,
                role=role,
                authority_commit=commit,
            )
        self.cli(
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "parallel-reviews",
            "--work-unit-id",
            "parallel-review-work",
            "--mode",
            "centralized_parallel",
            "--lane",
            "rtl",
            "--lane",
            "numeric",
            "--steward-lane-id",
            "steward",
            "--scope",
            "Independent RTL and numeric reviews reported through one Steward",
            "--sequential-dependency",
            "low",
            "--tool-density",
            "medium",
            "--shared-context",
            "low",
            "--rationale",
            "The two evidence questions have distinct authorities and no direct dependency",
            "--falsification-condition",
            "Switch to hybrid if either specialist requires direct technical exchange",
            "--escalation-condition",
            "Escalate any cross-contract dissent through the Steward and Chief",
            "--session-id",
            "chief-centralized",
        )
        self.create_selected_packet(task_id, "rtl-one", "rtl", "parallel-reviews")
        self.create_selected_packet(task_id, "rtl-two", "rtl", "parallel-reviews")
        self.create_selected_packet(task_id, "numeric-one", "numeric", "parallel-reviews")
        for packet_id in ("rtl-one", "numeric-one"):
            self.dispatch_packet(task_id, packet_id, f"/root/{packet_id}")
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "rtl-two",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/rtl-two",
            ok=False,
        )
        self.assertIn("active depth-one chain in lane rtl", rejected.stderr)
        for packet_id in ("rtl-one", "numeric-one"):
            self.cli(
                "packet-update",
                "--task",
                task_id,
                "--packet-id",
                packet_id,
                "--status",
                "done",
                "--summary",
                f"Completed the independent {packet_id} specialist review",
                "--evidence",
                f"Canonical result for {packet_id} is bound to the parallel selection",
            )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "rtl-two",
            "--status",
            "cancelled",
            "--summary",
            "The redundant same-lane review was cancelled without material work",
        )
        missing_brief = self.cli(
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "after-parallel",
            "--work-unit-id",
            "parallel-review-work",
            "--supersedes-selection-id",
            "parallel-reviews",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "Continue one sequential RTL follow-up after result consolidation",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "medium",
            "--shared-context",
            "high",
            "--rationale",
            "The independent specialist phase ended and one causal follow-up remains",
            "--falsification-condition",
            "Return to parallel only if distinct lane evidence questions reappear",
            "--escalation-condition",
            "Escalate if the follow-up changes the numeric contract boundary",
            "--session-id",
            "chief-centralized",
            ok=False,
        )
        self.assertIn("lacks a Steward result brief", missing_brief.stderr)
        revised_steward_commit = self.git_commit("steward-brief-recorder-revision")
        self.revise_lane(
            task_id,
            "steward",
            authority_commit=revised_steward_commit,
            change_class="same_contract_implementation",
            contract_version="cv1",
            generator_version="gv1",
            adapter_version="av1",
        )
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "parallel-review-steward-synthesis",
            "--agent-role",
            "default",
            "--model-tier",
            "standard",
            "--objective",
            "Synthesize every immutable specialist result for Chief arbitration",
            "--scope",
            "Read-only Steward synthesis after all selected specialist packets are terminal",
            "--deliverable",
            "One bounded synthesis with dissent, blockers, and recommendation",
            "--validation",
            "Chief checks the result against every bound specialist result SHA-256",
            "--lane-id",
            "steward",
            "--steward-synthesis-for-selection-id",
            "parallel-reviews",
        )
        self.dispatch_packet(
            task_id,
            "parallel-review-steward-synthesis",
            "/root/parallel-review-steward-synthesis",
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "parallel-review-steward-synthesis",
            "--status",
            "done",
            "--summary",
            "Steward synthesized the exact RTL, numeric, and cancelled duplicate results",
            "--evidence",
            "The synthesis contract and result bind every specialist result SHA-256",
        )
        late_specialist = self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "late-specialist",
            "--agent-role",
            "implementation_specialist",
            "--model-tier",
            "expert",
            "--objective",
            "Attempt to append specialist evidence after synthesis",
            "--scope",
            "This packet must be rejected because the selected result set is frozen",
            "--deliverable",
            "No packet should be created",
            "--validation",
            "Creation fails before any state mutation",
            "--lane-id",
            "rtl",
            "--execution-selection-id",
            "parallel-reviews",
            ok=False,
        )
        self.assertIn("frozen after Steward synthesis begins", late_specialist.stderr)
        brief_args = [
            "execution-brief-record",
            "--task",
            task_id,
            "--brief-id",
            "parallel-review-brief",
            "--execution-selection-id",
            "parallel-reviews",
            "--steward-lane-id",
            "steward",
            "--steward-packet-id",
            "parallel-review-steward-synthesis",
            "--packet-id",
            "rtl-one",
            "--packet-id",
            "rtl-two",
            "--packet-id",
            "numeric-one",
            "--summary",
            "Steward consolidated the independent RTL and numeric terminal results",
            "--dissent",
            "No unresolved specialist dissent was reported",
            "--blocker",
            "No remaining blocker was reported for this review phase",
            "--recommendation",
            "Chief should continue only the bounded sequential RTL follow-up",
            "--session-id",
            "chief-centralized",
        ]
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        synthesis_state = json.loads(state_path.read_text(encoding="utf-8"))
        synthesis_packet = next(
            packet
            for packet in synthesis_state["packets"]
            if packet["packet_id"] == "parallel-review-steward-synthesis"
        )
        synthesis_result = Path(synthesis_packet["result_path"])
        original_result = synthesis_result.read_bytes()
        before_state = state_path.read_bytes()
        synthesis_result.write_bytes(original_result + b"\nTAMPERED\n")
        rejected_brief = self.cli(*brief_args, ok=False)
        self.assertIn("Steward synthesis evidence is missing or tampered", rejected_brief.stderr)
        self.assertIn("result SHA-256 mismatch", rejected_brief.stderr)
        self.assertEqual(state_path.read_bytes(), before_state)
        synthesis_result.write_bytes(original_result)
        brief = json.loads(
            self.cli(
                *brief_args,
                "--json",
            ).stdout
        )
        self.assertRegex(brief["brief_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(brief["brief_version"], 3)
        self.assertEqual(brief["steward_snapshot"]["revision"], 1)
        self.assertEqual(brief["recording_steward_snapshot"]["revision"], 2)
        self.assertEqual(
            brief["steward_packet_binding"]["steward_execution_snapshot"][
                "revision"
            ],
            2,
        )
        self.cli(
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "after-parallel",
            "--work-unit-id",
            "parallel-review-work",
            "--supersedes-selection-id",
            "parallel-reviews",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "Continue one sequential RTL follow-up after result consolidation",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "medium",
            "--shared-context",
            "high",
            "--rationale",
            "The independent specialist phase ended and one causal follow-up remains",
            "--falsification-condition",
            "Return to parallel only if distinct lane evidence questions reappear",
            "--escalation-condition",
            "Escalate if the follow-up changes the numeric contract boundary",
            "--session-id",
            "chief-centralized",
        )
        selection = self.task_state(task_id)["execution_selections"][0]
        self.assertEqual(selection["execution_selection_version"], 2)
        self.assertEqual(selection["steward_snapshot"]["lane_id"], "steward")
        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)

        active_state = self.task_state(task_id)
        filtered_errors = cli_impl.packet_integrity_errors(
            h.get_paths(self.root),
            active_state,
            packet_ids={"parallel-review-steward-synthesis"},
        )
        self.assertEqual(filtered_errors, [])
        self.assertEqual(
            cli_impl.packet_integrity_errors(
                h.get_paths(self.root),
                active_state,
                packet_ids={"missing-packet"},
            ),
            ["packet integrity filter references unknown packet ids: missing-packet"],
        )
        duplicate_active_state = copy.deepcopy(active_state)
        duplicate_active_state["packets"].append(
            copy.deepcopy(duplicate_active_state["packets"][0])
        )
        duplicate_packet_id = duplicate_active_state["packets"][0]["packet_id"]
        self.assertIn(
            f"duplicate packet id {duplicate_packet_id!r}",
            cli_impl.packet_integrity_errors(
                h.get_paths(self.root), duplicate_active_state
            ),
        )
        self.assertEqual(
            cli_impl.packet_integrity_errors(
                h.get_paths(self.root),
                duplicate_active_state,
                packet_ids={duplicate_packet_id},
            ),
            [
                "packet integrity filter requires exactly one state packet for "
                f"{duplicate_packet_id!r}; found 2"
            ],
        )

        for lane_id in ("rtl", "numeric", "steward"):
            lane = self.lane_state(task_id, lane_id)
            self.cli(
                "lane-set-status",
                "--task",
                task_id,
                "--lane-id",
                lane_id,
                "--expected-revision",
                str(lane["revision"]),
                "--expected-status",
                str(lane["status"]),
                "--status",
                "done",
                "--closure-kind",
                "completed_work",
                "--next-action",
                "No further specialist work remains in this regression",
                "--reason",
                "All selected packets and the Steward synthesis are terminal",
                "--session-id",
                "chief-centralized",
            )
        self.add_passing_verification(task_id)
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "none",
            "--detail",
            "Terminal doctor relational-context regression only",
        )
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Close and verify the terminal Steward synthesis packet",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            task_id,
            "--summary",
            "Closed with intact specialist and Steward synthesis evidence",
        )
        terminal_doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(terminal_doctor["ok"], terminal_doctor)

        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        valid_state_bytes = state_path.read_bytes()
        mixed_duplicate = json.loads(valid_state_bytes)
        legacy_duplicate = copy.deepcopy(mixed_duplicate["packets"][0])
        duplicate_packet_id = legacy_duplicate["packet_id"]
        legacy_duplicate.pop("integrity_version", None)
        legacy_duplicate["packet_purpose"] = "invalid-purpose"
        mixed_duplicate["packets"].append(legacy_duplicate)
        state_path.write_text(
            json.dumps(mixed_duplicate, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        mixed_duplicate_doctor = subprocess.run(
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
            capture_output=True,
            check=False,
        )
        mixed_duplicate_payload = json.loads(mixed_duplicate_doctor.stdout)
        self.assertEqual(
            mixed_duplicate_doctor.returncode, 1, mixed_duplicate_doctor.stderr
        )
        self.assertIn(
            f"terminal task {task_id}: duplicate packet id {duplicate_packet_id!r}",
            mixed_duplicate_payload["errors"],
        )
        self.assertFalse(
            any(
                "invalid packet purpose" in item
                for item in mixed_duplicate_payload["errors"]
            ),
            mixed_duplicate_payload,
        )

        state_path.write_bytes(valid_state_bytes)
        stale_binding = json.loads(valid_state_bytes)
        stale_synthesis = next(
            packet
            for packet in stale_binding["packets"]
            if packet["packet_id"] == "parallel-review-steward-synthesis"
        )
        stale_synthesis["steward_input_bindings"][0]["result_sha256"] = "0" * 64
        state_path.write_text(
            json.dumps(stale_binding, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        stale_binding_doctor = subprocess.run(
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
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            stale_binding_doctor.returncode, 1, stale_binding_doctor.stderr
        )
        self.assertIn(
            "Steward synthesis specialist bindings are stale",
            stale_binding_doctor.stdout,
        )

        state_path.write_bytes(valid_state_bytes)
        downgraded = json.loads(valid_state_bytes)
        downgraded["execution_selections"][0].pop("execution_selection_version")
        downgraded["execution_selections"][0].pop("steward_snapshot")
        state_path.write_text(
            json.dumps(downgraded, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        downgraded_doctor = subprocess.run(
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
            capture_output=True,
            check=False,
        )
        self.assertEqual(downgraded_doctor.returncode, 1, downgraded_doctor.stderr)
        self.assertIn("not sealed as version 2", downgraded_doctor.stdout)

        state_path.write_bytes(valid_state_bytes)
        compounded_downgrade = json.loads(valid_state_bytes)
        compounded_downgrade.pop("task_execution_schema_version")
        compounded_downgrade.pop("execution_policy_version")
        compounded_downgrade["execution_selections"][0].pop(
            "execution_selection_version"
        )
        compounded_downgrade["execution_selections"][0].pop("steward_snapshot")
        state_path.write_text(
            json.dumps(compounded_downgrade, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        compounded_doctor = subprocess.run(
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
            capture_output=True,
            check=False,
        )
        self.assertEqual(compounded_doctor.returncode, 1, compounded_doctor.stderr)
        self.assertIn(
            "native execution-policy task lost or downgraded",
            compounded_doctor.stdout,
        )

        state_path.write_bytes(valid_state_bytes)
        damaged = json.loads(valid_state_bytes)
        damaged["execution_selections"][0]["steward_snapshot"] = "malformed"
        state_path.write_text(
            json.dumps(damaged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        damaged_doctor = subprocess.run(
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
            capture_output=True,
            check=False,
        )
        self.assertEqual(damaged_doctor.returncode, 1, damaged_doctor.stderr)
        self.assertNotIn("Traceback", damaged_doctor.stderr)
        self.assertIn("parallel mode lacks a Steward snapshot", damaged_doctor.stdout)

    def test_lean_parallel_lanes_have_lane_local_actions_and_critical_view(self) -> None:
        self.init_task("lane-critical", session_id="root-session")
        commit = self.git_commit("lane-critical")
        rtl = self.create_lane(
            "lane-critical",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        golden = self.create_lane(
            "lane-critical",
            "golden",
            kind="analysis",
            role="analysis_specialist",
            authority_commit=commit,
        )
        pd = self.create_lane(
            "lane-critical",
            "pd",
            kind="physical",
            role="external_operator",
            authority_commit=commit,
        )
        self.assertEqual(
            {rtl["lane_id"], golden["lane_id"], pd["lane_id"]},
            {"rtl", "golden", "pd"},
        )

        first = self.cli(
            "status", "--task", "lane-critical", "--critical", "--json"
        )
        second = self.cli(
            "status", "--task", "lane-critical", "--critical", "--json"
        )
        self.assertEqual(first.stdout, second.stdout)
        self.assertLessEqual(len(first.stdout.encode("utf-8")), 12 * 1024)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["task_id"], "lane-critical")
        self.assertEqual(payload["root_authority"]["owner"], "test-root")
        self.assertEqual(
            {lane["lane_id"] for lane in payload["lanes"]},
            {"rtl", "golden", "pd"},
        )
        self.assertTrue(
            all(lane["next_action"] for lane in payload["lanes"]), payload
        )
        self.assertIn("full_state", payload)

    def test_dependency_severity_blocks_only_baseline_not_lane_local_work(self) -> None:
        self.init_task("hard-gate", session_id="hard-root")
        initial = self.git_commit("hard-initial")
        self.create_lane(
            "hard-gate",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=initial,
        )
        self.create_lane(
            "hard-gate",
            "pd",
            kind="physical",
            role="external_operator",
            authority_commit=initial,
        )
        self.cli(
            "lane-dependency-add",
            "--task",
            "hard-gate",
            "--dependency-id",
            "rtl-to-pd",
            "--source-lane",
            "rtl",
            "--target-lane",
            "pd",
            "--kind",
            "hard_gate",
            "--reason",
            "PD needs a measured RTL area candidate",
            "--needed-by-gate",
            "rc1",
        )
        revised = self.git_commit("hard-local-work")
        self.revise_lane(
            "hard-gate",
            "rtl",
            authority_commit=revised,
            change_class="same_contract_implementation",
            contract_version="cv1",
            generator_version="gv1",
            adapter_version="av1",
        )
        blocked = self.cli(
            "baseline-freeze",
            "--task",
            "hard-gate",
            "--baseline-id",
            "rc1",
            "--contract-version",
            "cv1",
            "--session-id",
            "hard-root",
            "--decision",
            "Attempt integration while the hard gate is open",
            "--lane",
            "rtl",
            "--lane",
            "pd",
            ok=False,
        )
        self.assertIn("hard", blocked.stderr.lower())

        self.init_task("nonblocking-deps", session_id="soft-root")
        nonblocking_commit = self.git_commit("nonblocking")
        self.create_lane(
            "nonblocking-deps",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=nonblocking_commit,
        )
        self.create_lane(
            "nonblocking-deps",
            "pd",
            kind="physical",
            role="external_operator",
            authority_commit=nonblocking_commit,
        )
        for dep_id, kind in (("soft", "soft_dependency"), ("info", "informational")):
            self.cli(
                "lane-dependency-add",
                "--task",
                "nonblocking-deps",
                "--dependency-id",
                dep_id,
                "--source-lane",
                "rtl",
                "--target-lane",
                "pd",
                "--kind",
                kind,
                "--reason",
                f"{kind} must remain nonblocking",
                "--needed-by-gate",
                "rc-soft",
            )
        frozen = json.loads(
            self.cli(
                "baseline-freeze",
                "--task",
                "nonblocking-deps",
                "--baseline-id",
                "rc-soft",
                "--contract-version",
                "cv1",
                "--session-id",
                "soft-root",
                "--decision",
                "Freeze despite nonblocking dependencies",
                "--lane",
                "rtl",
                "--lane",
                "pd",
                "--json",
            ).stdout
        )
        self.assertEqual(frozen["baseline_id"], "rc-soft")

    def test_coordination_request_does_not_mutate_target_and_root_arbitrates(self) -> None:
        self.init_task("coordination", session_id="coord-root")
        commit = self.git_commit("coordination")
        self.create_lane(
            "coordination",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.create_lane(
            "coordination",
            "pd",
            kind="physical",
            role="external_operator",
            authority_commit=commit,
        )
        no_steward = self.cli(
            "coordination-create",
            "--task",
            "coordination",
            "--request-id",
            "reduce-dff",
            "--source-lane",
            "pd",
            "--target-lane",
            "rtl",
            "--severity",
            "soft_dependency",
            "--request",
            "Reduce DFF use without changing numeric semantics",
            "--outcome",
            "Lower sequential-cell area",
            "--evidence",
            "PD report shows DFF-dominated area",
            "--change-class",
            "same_contract_implementation",
            ok=False,
        )
        self.assertIn("steward", no_steward.stderr.lower())
        self.create_lane(
            "coordination",
            "coord",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        before_target = self.lane_state("coordination", "rtl")
        created = json.loads(
            self.cli(
                "coordination-create",
                "--task",
                "coordination",
                "--request-id",
                "reduce-dff",
                "--source-lane",
                "pd",
                "--target-lane",
                "rtl",
                "--severity",
                "soft_dependency",
                "--request",
                "Reduce DFF use without changing numeric semantics",
                "--outcome",
                "Lower sequential-cell area",
                "--evidence",
                "PD report shows DFF-dominated area",
                "--option",
                "Reuse phase-local registers",
                "--change-class",
                "same_contract_implementation",
                "--json",
            ).stdout
        )
        self.assertEqual(created["version"], 1)
        self.assertEqual(created["steward_lane"], "coord")
        self.assertEqual(self.lane_state("coordination", "rtl"), before_target)

        wrong_actor = self.cli(
            "coordination-update",
            "--task",
            "coordination",
            "--request-id",
            "reduce-dff",
            "--actor-lane",
            "pd",
            "--expected-version",
            "1",
            "--status",
            "acknowledged",
            "--response",
            "Requester cannot acknowledge for RTL",
            ok=False,
        )
        self.assertIn("target", wrong_actor.stderr.lower())
        updated = json.loads(
            self.cli(
                "coordination-update",
                "--task",
                "coordination",
                "--request-id",
                "reduce-dff",
                "--actor-lane",
                "rtl",
                "--expected-version",
                "1",
                "--status",
                "countered",
                "--response",
                "Offer scoreboard reuse with a timing-risk review",
                "--evidence",
                "RTL dependency map",
                "--json",
            ).stdout
        )
        self.assertEqual(updated["version"], 2)
        self.assertEqual(self.lane_state("coordination", "rtl"), before_target)

        stale = self.cli(
            "coordination-arbitrate",
            "--task",
            "coordination",
            "--request-id",
            "reduce-dff",
            "--session-id",
            "coord-root",
            "--expected-version",
            "1",
            "--decision",
            "approved",
            "--rationale",
            "A stale Chief brief must not arbitrate a newer specialist response",
            ok=False,
        )
        self.assertIn("CAS failed", stale.stderr)

        unbound = self.cli(
            "coordination-arbitrate",
            "--task",
            "coordination",
            "--request-id",
            "reduce-dff",
            "--session-id",
            "not-bound",
            "--expected-version",
            "2",
            "--decision",
            "approved",
            "--rationale",
            "Must not impersonate root",
            ok=False,
        )
        self.assertIn("session", unbound.stderr.lower())
        arbitration = json.loads(
            self.cli(
                "coordination-arbitrate",
                "--task",
                "coordination",
                "--request-id",
                "reduce-dff",
                "--session-id",
                "coord-root",
                "--expected-version",
                "2",
                "--decision",
                "approved",
                "--rationale",
                "The area benefit is worth bounded RTL verification",
                "--selected-option",
                "Reuse phase-local registers",
                "--json",
            ).stdout
        )
        self.assertEqual(arbitration["status"], "accepted")
        self.assertEqual(arbitration["root_arbitrations"][-1]["decision"], "approved")
        self.assertEqual(
            arbitration["root_arbitrations"][-1]["root_owner"], "test-root"
        )
        self.assertIn(
            "does not authenticate",
            arbitration["root_arbitrations"][-1]["authority_boundary"],
        )
        self.assertEqual(self.lane_state("coordination", "rtl"), before_target)
        self.create_lane(
            "coordination",
            "coord-backup",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        multiple_stewards = self.cli(
            "coordination-create",
            "--task",
            "coordination",
            "--request-id",
            "second-request",
            "--source-lane",
            "pd",
            "--target-lane",
            "rtl",
            "--severity",
            "informational",
            "--request",
            "Record a second observation",
            "--outcome",
            "Reject ambiguous steward ownership",
            "--evidence",
            "Second PD observation",
            "--change-class",
            "same_contract_implementation",
            ok=False,
        )
        self.assertIn("steward", multiple_stewards.stderr.lower())

    def test_golden_version_rules_fail_closed_and_semantic_change_needs_root(self) -> None:
        self.init_task("golden-policy", session_id="golden-root")
        initial = self.git_commit("golden-initial")
        self.create_lane(
            "golden-policy",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=initial,
        )
        self.create_lane(
            "golden-policy",
            "golden",
            kind="analysis",
            role="analysis_specialist",
            authority_commit=initial,
        )
        self.create_lane(
            "golden-policy",
            "coord",
            kind="coordination_steward",
            role="default",
            authority_commit=initial,
        )
        bugfix = self.git_commit("golden-bugfix")
        rejected = self.revise_lane(
            "golden-policy",
            "rtl",
            authority_commit=bugfix,
            change_class="same_contract_implementation",
            contract_version="cv1",
            generator_version="gv2",
            adapter_version="av1",
            ok=False,
        )
        self.assertIn("generator", rejected.stderr.lower())
        self.assertEqual(self.lane_state("golden-policy", "rtl")["revision"], 1)

        semantic = self.git_commit("golden-semantic")
        missing_root = self.revise_lane(
            "golden-policy",
            "rtl",
            authority_commit=semantic,
            change_class="semantic_change",
            contract_version="cv2",
            generator_version="gv2",
            adapter_version="av1",
            ok=False,
        )
        self.assertTrue(
            "coord" in missing_root.stderr.lower()
            or "arbitr" in missing_root.stderr.lower(),
            missing_root.stderr,
        )
        self_request = self.cli(
            "coordination-create",
            "--task",
            "golden-policy",
            "--request-id",
            "semantic-self",
            "--source-lane",
            "rtl",
            "--target-lane",
            "rtl",
            "--severity",
            "hard_gate",
            "--request",
            "Must not bypass independent golden review",
            "--outcome",
            "Reject self coordination",
            "--evidence",
            "Architecture change proposal",
            "--change-class",
            "semantic_change",
            ok=False,
        )
        self.assertIn("source lane", self_request.stderr.lower())
        self.cli(
            "coordination-create",
            "--task",
            "golden-policy",
            "--request-id",
            "semantic-v2",
            "--source-lane",
            "rtl",
            "--target-lane",
            "golden",
            "--severity",
            "hard_gate",
            "--request",
            "Change numeric semantics and regenerate golden independently",
            "--outcome",
            "Publish contract cv2 with generator gv2",
            "--evidence",
            "Architecture change proposal",
            "--change-class",
            "semantic_change",
        )
        self.cli(
            "coordination-update",
            "--task",
            "golden-policy",
            "--request-id",
            "semantic-v2",
            "--actor-lane",
            "golden",
            "--expected-version",
            "1",
            "--status",
            "acknowledged",
            "--response",
            "Golden lane acknowledges independent regeneration work",
        )
        self.cli(
            "coordination-arbitrate",
            "--task",
            "golden-policy",
            "--request-id",
            "semantic-v2",
            "--session-id",
            "golden-root",
            "--expected-version",
            "2",
            "--decision",
            "approved",
            "--rationale",
            "Root approves explicit contract and generator version changes",
        )
        golden_semantic = self.git_commit("golden-independent-v2")
        golden_revision = json.loads(
            self.revise_lane(
                "golden-policy",
                "golden",
                authority_commit=golden_semantic,
                change_class="semantic_change",
                contract_version="cv2",
                generator_version="gv2",
                adapter_version="av1",
                coord="semantic-v2",
            ).stdout
        )
        self.assertEqual(golden_revision["revision"], 2)
        accepted = json.loads(
            self.revise_lane(
                "golden-policy",
                "rtl",
                authority_commit=semantic,
                change_class="semantic_change",
                contract_version="cv2",
                generator_version="gv2",
                adapter_version="av1",
                coord="semantic-v2",
            ).stdout
        )
        self.assertEqual(accepted["revision"], 2)
        self.assertEqual(accepted["contract_version"], "cv2")
        self.assertEqual(accepted["generator_version"], "gv2")

    def test_baseline_freeze_snapshots_lane_revisions(self) -> None:
        self.init_task("baseline-snapshot", session_id="baseline-root")
        initial = self.git_commit("baseline-initial")
        self.create_lane(
            "baseline-snapshot",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=initial,
        )
        self.create_lane(
            "baseline-snapshot",
            "golden",
            kind="analysis",
            role="analysis_specialist",
            authority_commit=initial,
        )
        frozen = json.loads(
            self.cli(
                "baseline-freeze",
                "--task",
                "baseline-snapshot",
                "--baseline-id",
                "rc1",
                "--contract-version",
                "cv1",
                "--session-id",
                "baseline-root",
                "--decision",
                "Freeze exact RTL and golden lane revisions",
                "--lane",
                "rtl",
                "--lane",
                "golden",
                "--json",
            ).stdout
        )
        self.assertEqual(
            {
                item["lane_id"]: item["revision"]
                for item in frozen["lane_snapshots"]
            },
            {"golden": 1, "rtl": 1},
        )
        next_commit = self.git_commit("baseline-next")
        self.revise_lane(
            "baseline-snapshot",
            "rtl",
            authority_commit=next_commit,
            change_class="same_contract_implementation",
            contract_version="cv1",
            generator_version="gv1",
            adapter_version="av1",
        )
        critical = json.loads(
            self.cli(
                "status",
                "--task",
                "baseline-snapshot",
                "--critical",
                "--json",
            ).stdout
        )
        baseline = critical["baseline"]
        self.assertEqual(baseline["baseline_id"], "rc1")
        self.assertEqual(
            {
                item["lane_id"]: item["revision"]
                for item in baseline["lane_snapshots"]
            },
            {"golden": 1, "rtl": 1},
        )
        current_rtl = next(
            lane for lane in critical["lanes"] if lane["lane_id"] == "rtl"
        )
        self.assertEqual(current_rtl["revision"], 2)

    def test_reconcile_is_deterministic_and_byte_stable(self) -> None:
        self.init_task("reconcile-read-only", session_id="reconcile-root")
        commit = self.git_commit("reconcile")
        self.create_lane(
            "reconcile-read-only",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        before = self.tree_bytes()
        first = self.cli("reconcile", "--task", "reconcile-read-only", "--json")
        middle = self.tree_bytes()
        second = self.cli("reconcile", "--task", "reconcile-read-only", "--json")
        after = self.tree_bytes()
        self.assertEqual(before, middle)
        self.assertEqual(before, after)
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["task_id"], "reconcile-read-only")
        self.assertFalse(payload["mutation_performed"])
        self.assertEqual(payload["reconcile_version"], 1)

    def test_exact_command_packet_is_snapshotted_and_tamper_blocks_dispatch(self) -> None:
        self.init_task("packet-command-authority")
        command = self.root / "exact-command.sh"
        command.write_bytes(
            b"#!/bin/sh\r\nprintf 'bounded command\\n'\r\n\r\n \t"
        )
        command_sha = hashlib.sha256(command.read_bytes()).hexdigest()
        self.cli(
            "claim",
            "--task",
            "packet-command-authority",
            "--token",
            "exact-command-claim",
            "--owner",
            "test-root",
            "--kind",
            "COMMAND",
            "--lock",
            "repo:file:exact-command.sh",
            "--intent",
            "Own the exact command execution authority",
            "--validation",
            "Packet command SHA and lock are both required",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "packet-command-authority"
            / "state.json"
        )
        before = state_path.read_bytes()
        short_sha = self.cli(
            "create-packet",
            "--task",
            "packet-command-authority",
            "--packet-id",
            "bad-command",
            "--agent-role",
            "external_operator",
            "--model-tier",
            "standard",
            "--objective",
            "Run only the exact command",
            "--scope",
            "Bounded command authority test",
            "--deliverable",
            "Terminal evidence",
            "--validation",
            "Exact command identity",
            "--packet-mode",
            "exact_command",
            "--lock",
            "repo:file:exact-command.sh",
            "--command-artifact",
            str(command),
            "--command-sha256",
            command_sha[:12],
            ok=False,
        )
        self.assertIn("64-hex", short_sha.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        command_link = self.root / "exact-command-link.sh"
        try:
            command_link.symlink_to(command)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("native Windows symlink privilege is unavailable")
            raise
        symlink = self.cli(
            "create-packet",
            "--task",
            "packet-command-authority",
            "--packet-id",
            "symlink-command",
            "--agent-role",
            "external_operator",
            "--model-tier",
            "standard",
            "--objective",
            "Must reject symlink authority",
            "--scope",
            "Negative command authority fixture",
            "--deliverable",
            "No packet",
            "--validation",
            "Final-component symlink is rejected",
            "--packet-mode",
            "exact_command",
            "--lock",
            "repo:file:exact-command.sh",
            "--command-artifact",
            str(command_link),
            "--command-sha256",
            command_sha,
            ok=False,
        )
        self.assertIn("symlinks or junctions", symlink.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        created = json.loads(
            self.cli(
                "create-packet",
                "--task",
                "packet-command-authority",
                "--packet-id",
                "exact-command",
                "--agent-role",
                "external_operator",
                "--model-tier",
                "standard",
                "--objective",
                "Run only the exact command",
                "--scope",
                "Bounded command authority test",
                "--deliverable",
                "Terminal evidence",
                "--validation",
                "Exact command identity",
                "--packet-mode",
                "exact_command",
                "--lock",
                "repo:file:exact-command.sh",
                "--command-artifact",
                str(command),
                "--command-sha256",
                command_sha,
                "--json",
            ).stdout
        )
        self.assertEqual(created["packet_id"], "exact-command")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        packet = next(item for item in state["packets"] if item["packet_id"] == "exact-command")
        self.assertEqual(packet["command_source_sha256"], command_sha)
        self.assertEqual(packet["command_supplied_sha256"], command_sha)
        self.assertEqual(
            packet["command_normalization"],
            cli_impl.packet_integrity_impl.EXACT_COMMAND_NORMALIZATION_V1,
        )
        snapshot = Path(packet["command_path"])
        self.assertEqual(
            snapshot.read_bytes(), b"#!/bin/sh\nprintf 'bounded command\\n'\n"
        )
        self.assertEqual(
            packet["command_sha256"], hashlib.sha256(snapshot.read_bytes()).hexdigest()
        )
        snapshot.write_text("tampered\n", encoding="utf-8")
        state_before_dispatch = state_path.read_bytes()
        rejected = self.cli(
            "packet-update",
            "--task",
            "packet-command-authority",
            "--packet-id",
            "exact-command",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/exact-command",
            ok=False,
        )
        self.assertIn("identity mismatch", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), state_before_dispatch)
        doctor_result = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "doctor",
                "--task",
                "packet-command-authority",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(doctor_result.returncode, 1, doctor_result.stderr)
        doctor = json.loads(doctor_result.stdout)
        self.assertTrue(
            any("exact command artifact identity mismatch" in item for item in doctor["errors"]),
            doctor,
        )

    def test_exact_command_tamper_blocks_done_and_reviewer_consumer(self) -> None:
        task_id = "packet-command-consumers"
        self.init_task(task_id)
        command = self.root / "consumer-command.sh"
        command.write_text("#!/bin/sh\nprintf 'bounded command\\n'\n", encoding="utf-8")
        command_sha = hashlib.sha256(command.read_bytes()).hexdigest()
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "consumer-command-claim",
            "--owner",
            "test-root",
            "--kind",
            "COMMAND",
            "--lock",
            "repo:file:consumer-command.sh",
            "--intent",
            "Own the exact command execution authority",
            "--validation",
            "Every transition and consumer revalidates command identity",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"

        def create_exact(packet_id: str, role: str, tier: str) -> Path:
            self.cli(
                "create-packet",
                "--task",
                task_id,
                "--packet-id",
                packet_id,
                "--agent-role",
                role,
                "--model-tier",
                tier,
                "--objective",
                "Use only the exact approved command",
                "--scope",
                "Exact command consumer gate fixture",
                "--deliverable",
                "Integrity-bound terminal result",
                "--validation",
                "Command identity is revalidated",
                "--packet-mode",
                "exact_command",
                "--lock",
                "repo:file:consumer-command.sh",
                "--command-artifact",
                str(command),
                "--command-sha256",
                command_sha,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))
            packet = next(
                item for item in state["packets"] if item["packet_id"] == packet_id
            )
            return Path(packet["command_path"])

        worker_snapshot = create_exact("exact-worker", "external_operator", "standard")
        worker_snapshot_bytes = worker_snapshot.read_bytes()
        self.dispatch_packet(task_id, "exact-worker", "/root/exact-worker")
        worker_snapshot.write_text("tampered after dispatch\n", encoding="utf-8")
        before_done = state_path.read_bytes()
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "exact-worker",
            "--status",
            "done",
            "--summary",
            "This transition must not commit",
            "--evidence",
            "The command snapshot changed after dispatch",
            ok=False,
        )
        self.assertIn("exact command artifact identity mismatch", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before_done)

        worker_snapshot.write_bytes(worker_snapshot_bytes)
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "exact-worker",
            "--status",
            "done",
            "--summary",
            "The exact command remained intact through completion",
            "--evidence",
            "The command snapshot matched its approved SHA-256",
        )

        reviewer_snapshot = create_exact("exact-reviewer", "reviewer", "expert")
        self.dispatch_packet(
            task_id,
            "exact-reviewer",
            "/root/exact-reviewer",
            "--actual-role",
            "reviewer",
            "--actual-model-tier",
            "expert",
            "--routing-evidence",
            "The exact reviewer identity and capability tier were exposed",
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "exact-reviewer",
            "--status",
            "done",
            "--summary",
            "Reviewer completed while command authority was intact",
            "--evidence",
            "The review result was bound to the exact command",
        )
        reviewer_snapshot.write_text("tampered after reviewer completion\n", encoding="utf-8")
        before_consumer = state_path.read_bytes()
        rejected = self.cli(
            "add-verification",
            "--task",
            task_id,
            "--category",
            "independent_review",
            "--status",
            "pass",
            "--evidence",
            "A tampered reviewer command cannot qualify this verification",
            "--command",
            "bounded reviewer command",
            "--boundary",
            "Synthetic reviewer authority gate",
            "--review-packet-id",
            "exact-reviewer",
            ok=False,
        )
        self.assertIn("exact command artifact identity mismatch", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before_consumer)

    def test_packet_schema_version_requires_an_exact_non_boolean_integer(self) -> None:
        task_id = "packet-schema-exact-int"
        self.init_task(task_id)
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "schema-reader",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Read one bounded fixture",
            "--scope",
            "Packet schema type validation",
            "--deliverable",
            "No mutation",
            "--validation",
            "Schema routing fails closed",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        pristine = json.loads(state_path.read_text(encoding="utf-8"))
        for invalid_version in (True, "4"):
            with self.subTest(packet_schema_version=invalid_version):
                damaged = json.loads(json.dumps(pristine))
                packet = damaged["packets"][0]
                packet["packet_schema_version"] = invalid_version
                packet.pop("packet_contract_sha256", None)
                state_path.write_text(
                    json.dumps(damaged, indent=2) + "\n", encoding="utf-8"
                )
                before = state_path.read_bytes()
                rejected = self.cli(
                    "packet-update",
                    "--task",
                    task_id,
                    "--packet-id",
                    "schema-reader",
                    "--status",
                    "dispatched",
                    "--agent-id",
                    "/root/schema-reader",
                    ok=False,
                )
                self.assertIn("schema version is invalid", rejected.stderr)
                self.assertEqual(before, state_path.read_bytes())

    def test_packet_inputs_use_canonical_snapshots_and_dispatch_fences_origin(self) -> None:
        task_id = "packet-input-snapshot"
        self.init_task(task_id)
        source = self.root.parent / f"{self.root.name}-packet-input.txt"
        source.write_text("approved input\n", encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "reader",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect one exact input",
            "--scope",
            "Read-only packet snapshot fixture",
            "--deliverable",
            "Bounded findings",
            "--validation",
            "Origin and snapshot identities are fenced",
            "--input-artifact",
            f"{source}={digest}",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        packet = state["packets"][0]
        artifact = packet["input_artifact_refs"][0]
        snapshot = Path(artifact["path"])
        self.assertEqual(packet["packet_schema_version"], 5)
        self.assertEqual(packet["dispatch_provenance"], "none")
        self.assertEqual(artifact["snapshot_version"], 1)
        self.assertEqual(Path(artifact["source_path"]), source.resolve())
        self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(), digest)
        self.assertIn("artifact-blobs", snapshot.parts)
        contract = Path(packet["path"])
        self.assertEqual(
            hashlib.sha256(contract.read_bytes()).hexdigest(),
            packet["packet_contract_sha256"],
        )
        self.assertIn(str(snapshot), contract.read_text(encoding="utf-8"))

        source.write_text("changed before dispatch\n", encoding="utf-8")
        before = state_path.read_bytes()
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "reader",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/reader",
            ok=False,
        )
        self.assertIn("source changed after snapshot", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before)

        source.write_text("approved input\n", encoding="utf-8")
        self.dispatch_packet(task_id, "reader", "/root/reader")
        source.write_text("legitimate evolution after dispatch\n", encoding="utf-8")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "reader",
            "--status",
            "done",
            "--summary",
            "Reader completed against the immutable task snapshot",
            "--evidence",
            "Canonical snapshot SHA remained exact after source evolution",
        )
        doctor = self.cli("doctor", "--task", task_id, "--json")
        self.assertTrue(json.loads(doctor.stdout)["ok"])

    def test_artifact_blob_ancestor_link_is_rejected_before_write(self) -> None:
        task_id = "artifact-blob-ancestor-link"
        self.init_task(task_id)
        source = self.root / "ancestor-link-source.txt"
        source.write_text("exact artifact bytes\n", encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        task_root = self.root / ".aoi" / "tasks" / task_id
        blob_root = task_root / "results" / "artifact-blobs"
        outside = self.root / "outside-artifact-store"
        outside.mkdir()
        blob_root.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(blob_root), str(outside)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation unavailable: {created.stderr}")
        else:
            blob_root.symlink_to(outside, target_is_directory=True)
        try:
            state_path = task_root / "state.json"
            before = state_path.read_bytes()
            rejected = self.cli(
                "create-packet",
                "--task",
                task_id,
                "--packet-id",
                "linked-input",
                "--agent-role",
                "explorer",
                "--model-tier",
                "standard",
                "--objective",
                "Reject linked artifact store ancestors",
                "--scope",
                "Synthetic linked-ancestor fixture",
                "--deliverable",
                "No packet or external blob",
                "--validation",
                "Managed artifact ancestors remain real directories",
                "--input-artifact",
                f"{source}={digest}",
                ok=False,
            )
            self.assertIn("must be a real directory", rejected.stderr)
            self.assertEqual(state_path.read_bytes(), before)
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            if os.name == "nt" and blob_root.exists():
                os.rmdir(blob_root)
            elif blob_root.is_symlink():
                blob_root.unlink()

    def test_v4_snapshot_tamper_blocks_dispatch_and_remains_doctor_error(self) -> None:
        task_id = "packet-input-tamper"
        self.init_task(task_id)
        source = self.root.parent / f"{self.root.name}-packet-tamper.txt"
        source.write_text("immutable input\n", encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "reader",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Reject a modified snapshot",
            "--scope",
            "Read-only tamper fixture",
            "--deliverable",
            "No accepted dispatch",
            "--validation",
            "Snapshot physical SHA is checked",
            "--input-artifact",
            f"{source}={digest}",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        snapshot = Path(state["packets"][0]["input_artifact_refs"][0]["path"])
        snapshot.write_text("tampered\n", encoding="utf-8")
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "reader",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/reader",
            ok=False,
        )
        self.assertIn("snapshot identity mismatch", rejected.stderr)
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "reader",
            "--status",
            "cancelled",
            "--summary",
            "Cancelled after the immutable snapshot failed integrity",
        )
        doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        payload = json.loads(doctor.stdout)
        self.assertTrue(
            any("snapshot identity mismatch" in item for item in payload["errors"]),
            payload,
        )

    def test_legacy_failed_packet_is_digest_only_but_legacy_done_stays_strict(self) -> None:
        def make_terminal(task_id: str, terminal_status: str) -> tuple[Path, Path]:
            self.init_task(task_id)
            source = self.root.parent / f"{self.root.name}-{task_id}.txt"
            source.write_bytes(b"legacy input\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            self.cli(
                "create-packet",
                "--task",
                task_id,
                "--packet-id",
                "legacy-reader",
                "--agent-role",
                "explorer",
                "--model-tier",
                "standard",
                "--objective",
                "Emulate one schema-v3 live input",
                "--scope",
                "Legacy compatibility fixture",
                "--deliverable",
                "Terminal result",
                "--validation",
                "Status-aware legacy handling",
                "--input-artifact",
                f"{source}={digest}",
            )
            self.dispatch_packet(
                task_id, "legacy-reader", f"/root/{task_id}/legacy-reader"
            )
            terminal_args = [
                "packet-update",
                "--task",
                task_id,
                "--packet-id",
                "legacy-reader",
                "--status",
                terminal_status,
                "--summary",
                "Legacy packet reached its terminal test state",
            ]
            if terminal_status in {"done", "failed"}:
                terminal_args.extend(
                    ["--evidence", "Canonical terminal result was recorded before migration"]
                )
            self.cli(*terminal_args)
            state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            packet = state["packets"][0]
            packet["packet_schema_version"] = 3
            packet.pop("packet_contract_sha256", None)
            packet.pop("input_snapshot_version", None)
            packet["input_artifact_refs"] = [
                {
                    "path": str(source.resolve()),
                    "sha256": digest,
                    "size_bytes": len("legacy input\n".encode("utf-8")),
                }
            ]
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
            source.write_bytes(b"legitimate later source\n")
            return state_path, source

        failed_state_path, failed_source = make_terminal(
            "legacy-failed-input", "failed"
        )
        failed_doctor = self.cli(
            "doctor", "--task", "legacy-failed-input", "--json"
        )
        failed_payload = json.loads(failed_doctor.stdout)
        self.assertFalse(failed_payload["errors"])
        self.assertTrue(
            any("legacy digest-only inputs" in item for item in failed_payload["warnings"]),
            failed_payload,
        )

        failed_state = json.loads(failed_state_path.read_text(encoding="utf-8"))
        failed_packet = failed_state["packets"][0]
        failed_ref = failed_packet["input_artifact_refs"][0]
        failed_digest = failed_ref["sha256"]
        snapshot = (
            self.root
            / ".aoi"
            / "tasks"
            / "legacy-failed-input"
            / "results"
            / "artifact-blobs"
            / failed_digest[:2]
            / failed_digest
        )
        snapshot.write_bytes(b"tampered canonical snapshot\n")
        failed_packet["input_artifact_refs"] = [
            {
                "snapshot_version": 1,
                "source_path": str(failed_source.resolve()),
                "path": str(snapshot.resolve()),
                "sha256": failed_digest,
                "size_bytes": len(b"legacy input\n"),
            }
        ]
        failed_state_path.write_text(
            json.dumps(failed_state, indent=2) + "\n", encoding="utf-8"
        )
        mixed_doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "doctor",
                "--task",
                "legacy-failed-input",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertTrue(
            any(
                "packet legacy-reader input artifact: artifact snapshot identity mismatch"
                in item
                for item in json.loads(mixed_doctor.stdout)["errors"]
            )
        )

        make_terminal("legacy-done-input", "done")
        done_doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "doctor",
                "--task",
                "legacy-done-input",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(done_doctor.returncode, 1, done_doctor.stderr)
        done_payload = json.loads(done_doctor.stdout)
        self.assertTrue(
            any("legacy artifact reference identity mismatch" in item for item in done_payload["errors"]),
            done_payload,
        )

    def test_verification_snapshot_materialize_and_explicit_supersession(self) -> None:
        task_id = "verification-artifact-migration"
        self.init_task(task_id)
        first = self.root.parent / f"{self.root.name}-verification-first.txt"
        second = self.root.parent / f"{self.root.name}-verification-second.txt"
        first.write_text("first evidence\n", encoding="utf-8")
        second.write_text("replacement evidence\n", encoding="utf-8")
        first_sha = hashlib.sha256(first.read_bytes()).hexdigest()
        second_sha = hashlib.sha256(second.read_bytes()).hexdigest()
        for path, digest, evidence in (
            (first, first_sha, "Initial exact static-check evidence was recorded"),
            (second, second_sha, "Later replacement static-check evidence was recorded"),
        ):
            self.cli(
                "add-verification",
                "--task",
                task_id,
                "--category",
                "static_check",
                "--status",
                "pass",
                "--evidence",
                evidence,
                "--command",
                "python -m compileall bounded-fixture",
                "--boundary",
                "Synthetic static artifact identity only",
                "--artifact-ref",
                f"{path}={digest}",
            )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        first_record = state["verification"][0]
        second_record = state["verification"][1]
        self.assertEqual(first_record["artifact_refs"][0]["snapshot_version"], 1)

        # Emulate two historical schema-v1 live refs. The first origin evolves;
        # the second remains exact and can be materialized.
        first_record.pop("artifact_snapshot_version", None)
        first_record["artifact_refs"] = [
            {
                "path": str(first.resolve()),
                "sha256": first_sha,
                "size_bytes": first.stat().st_size,
            }
        ]
        second_record.pop("artifact_snapshot_version", None)
        second_record["artifact_refs"] = [
            {
                "path": str(second.resolve()),
                "sha256": second_sha,
                "size_bytes": second.stat().st_size,
            }
        ]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        second_ref = second_record["artifact_refs"][0]
        second_ref["snapshot_version"] = 2
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        before_unsupported = state_path.read_bytes()
        unsupported = self.cli(
            "materialize-artifacts",
            "--task",
            task_id,
            "--verification-index",
            "2",
            ok=False,
        )
        self.assertIn("unsupported artifact snapshot version", unsupported.stderr)
        self.assertEqual(before_unsupported, state_path.read_bytes())
        second_ref.pop("snapshot_version")
        second_ref["size_bytes"] = second.stat().st_size + 1
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        before_wrong_size = state_path.read_bytes()
        wrong_size = self.cli(
            "materialize-artifacts",
            "--task",
            task_id,
            "--verification-index",
            "2",
            ok=False,
        )
        self.assertIn("not physically valid", wrong_size.stderr)
        self.assertEqual(before_wrong_size, state_path.read_bytes())
        second_ref["size_bytes"] = second.stat().st_size
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        first.write_text("superseded origin evolved\n", encoding="utf-8")
        materialized = json.loads(
            self.cli(
                "materialize-artifacts",
                "--task",
                task_id,
                "--verification-index",
                "2",
                "--json",
            ).stdout
        )
        self.assertEqual(materialized["materialized_refs"], 1)
        state = json.loads(state_path.read_text(encoding="utf-8"))
        first_record, second_record = state["verification"]
        source_record_sha = hashlib.sha256(
            json.dumps(
                first_record,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        replacement_record_sha = hashlib.sha256(
            json.dumps(
                second_record,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.cli(
            "verification-supersede",
            "--task",
            task_id,
            "--verification-index",
            "1",
            "--expected-record-sha256",
            source_record_sha,
            "--replacement-index",
            "2",
            "--replacement-record-sha256",
            replacement_record_sha,
            "--reason",
            "The original live-path artifact was replaced by a later exact passing record",
        )
        migrated = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(migrated["verification"][0]["status"], "skipped")
        self.assertEqual(migrated["verification"][0]["supersession_version"], 2)
        self.assertEqual(
            migrated["verification"][0]["source_record_sha256"], source_record_sha
        )
        self.assertEqual(
            migrated["verification"][1]["artifact_refs"][0]["snapshot_version"], 1
        )
        doctor = self.cli("doctor", "--task", task_id, "--json")
        payload = json.loads(doctor.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(
            any("explicitly superseded" in item for item in payload["warnings"]),
            payload,
        )

    def test_canonical_snapshot_rejects_boolean_size_and_version(self) -> None:
        task_id = "canonical-snapshot-bool-schema"
        self.init_task(task_id)
        artifact = self.root / "one-byte-evidence.bin"
        artifact.write_bytes(b"x")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        self.cli(
            "add-verification",
            "--task",
            task_id,
            "--category",
            "static_check",
            "--status",
            "pass",
            "--evidence",
            "One-byte canonical snapshot schema fixture",
            "--command",
            "bounded schema validation",
            "--boundary",
            "Synthetic snapshot metadata only",
            "--artifact-ref",
            f"{artifact}={digest}",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"

        def run_damaged_doctor() -> dict[str, object]:
            result = subprocess.run(
                [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
                cwd=self.root,
                env=self.env,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            return json.loads(result.stdout)

        state = json.loads(state_path.read_text(encoding="utf-8"))
        ref = state["verification"][0]["artifact_refs"][0]
        ref["size_bytes"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        size_payload = run_damaged_doctor()
        self.assertFalse(size_payload["ok"])
        self.assertTrue(
            any("artifact size is invalid" in item for item in size_payload["errors"]),
            size_payload,
        )
        ref["size_bytes"] = 1
        ref["snapshot_version"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        version_payload = run_damaged_doctor()
        self.assertFalse(version_payload["ok"])
        self.assertTrue(
            any(
                "snapshot version is unsupported" in item
                for item in version_payload["errors"]
            ),
            version_payload,
        )
        ref["snapshot_version"] = 1
        state["verification"][0]["integrity_version"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        integrity_payload = run_damaged_doctor()
        self.assertFalse(integrity_payload["ok"])
        self.assertTrue(
            any(
                "lacks integrity_version=1" in item
                for item in integrity_payload["errors"]
            ),
            integrity_payload,
        )

    def test_legacy_done_packet_input_recovers_from_bound_tar_member(self) -> None:
        task_id = "packet-input-archive-recovery"
        self.init_task(task_id)
        source = self.root / "reviewed-source.txt"
        carrier = self.root / "reviewed-release.tar.gz"
        original = b"x"
        source.write_bytes(original)
        member_name = "release-1.0/reviewed-source.txt"
        with tarfile.open(carrier, mode="w:gz") as archive:
            info = tarfile.TarInfo(member_name)
            info.size = len(original)
            archive.addfile(info, io.BytesIO(original))
        source_sha = hashlib.sha256(original).hexdigest()
        carrier_sha = hashlib.sha256(carrier.read_bytes()).hexdigest()
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "reviewer",
            "--agent-role",
            "reviewer",
            "--model-tier",
            "expert",
            "--objective",
            "Review an exact release archive and its source",
            "--scope",
            "Synthetic release recovery fixture",
            "--deliverable",
            "Exact reviewer result",
            "--validation",
            "Recovered input must remain byte-identical",
            "--input-artifact",
            f"{source}={source_sha}",
            "--input-artifact",
            f"{carrier}={carrier_sha}",
        )
        self.dispatch_packet(task_id, "reviewer", "/root/reviewer")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "reviewer",
            "--status",
            "done",
            "--summary",
            "Reviewer accepted the exact source and release archive",
            "--evidence",
            "The result is bound to both exact input identities",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        packet = state["packets"][0]
        result_sha = packet["result_sha256"]
        packet["packet_schema_version"] = 3
        packet.pop("packet_contract_sha256", None)
        packet.pop("input_snapshot_version", None)
        packet["input_artifact_refs"] = [
            {
                "path": str(source.resolve()),
                "sha256": source_sha,
                "size_bytes": len(original),
            },
            {
                "path": str(carrier.resolve()),
                "sha256": carrier_sha,
                "size_bytes": carrier.stat().st_size,
            },
        ]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        source.write_text("legitimate later source evolution\n", encoding="utf-8")

        packet["input_artifact_refs"][0]["size_bytes"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        before_bool_size = state_path.read_bytes()
        bool_size = self.cli(
            "packet-input-recover-from-tar",
            "--task",
            task_id,
            "--packet-id",
            "reviewer",
            "--input-index",
            "1",
            "--expected-input-sha256",
            source_sha,
            "--carrier-input-index",
            "2",
            "--carrier-sha256",
            carrier_sha,
            "--archive-member",
            member_name,
            "--expected-result-sha256",
            result_sha,
            "--reason",
            "Boolean size metadata must never qualify as a one-byte identity",
            ok=False,
        )
        self.assertIn("legacy packet input identity", bool_size.stderr)
        self.assertEqual(before_bool_size, state_path.read_bytes())
        packet["input_artifact_refs"][0]["size_bytes"] = len(original)
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        before = state_path.read_bytes()
        rejected = self.cli(
            "packet-input-recover-from-tar",
            "--task",
            task_id,
            "--packet-id",
            "reviewer",
            "--input-index",
            "1",
            "--expected-input-sha256",
            "0" * 64,
            "--carrier-input-index",
            "2",
            "--carrier-sha256",
            carrier_sha,
            "--archive-member",
            member_name,
            "--expected-result-sha256",
            result_sha,
            "--reason",
            "Attempted recovery must remain bound to the approved input identity",
            ok=False,
        )
        self.assertIn("approved SHA-256", rejected.stderr)
        self.assertEqual(before, state_path.read_bytes())

        self.cli(
            "packet-input-recover-from-tar",
            "--task",
            task_id,
            "--packet-id",
            "reviewer",
            "--input-index",
            "1",
            "--expected-input-sha256",
            source_sha,
            "--carrier-input-index",
            "2",
            "--carrier-sha256",
            carrier_sha,
            "--archive-member",
            f"  {member_name}  ",
            "--expected-result-sha256",
            result_sha,
            "--reason",
            "The drifted live source is recovered from the exact reviewed release archive",
        )
        recovered = json.loads(state_path.read_text(encoding="utf-8"))
        recovered_ref = recovered["packets"][0]["input_artifact_refs"][0]
        self.assertEqual(recovered_ref["snapshot_version"], 1)
        self.assertEqual(Path(recovered_ref["path"]).read_bytes(), original)
        self.assertEqual(recovered_ref["source_path"], str(source.resolve()))
        self.assertEqual(
            recovered_ref["recovery"]["method"], "packet-bound-tar-member"
        )
        self.assertEqual(recovered_ref["recovery"]["carrier_sha256"], carrier_sha)
        self.assertEqual(recovered_ref["recovery"]["archive_member"], member_name)
        self.assertRegex(recovered_ref["recovery"]["record_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            source.read_text(encoding="utf-8"), "legitimate later source evolution\n"
        )
        recovery_doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(recovery_doctor["ok"], recovery_doctor)

        paths = h.get_paths(self.root)
        legacy_receipt = json.loads(json.dumps(recovered))
        legacy_receipt["packets"][0]["input_artifact_refs"][0]["recovery"].pop(
            "record_sha256"
        )
        self.assertEqual(
            cli_impl.packet_recovery_integrity_errors(paths, legacy_receipt), []
        )
        self.assertTrue(
            any(
                "unsealed legacy receipt" in item
                for item in cli_impl.packet_integrity_warnings(legacy_receipt)
            )
        )
        tamper_cases = {
            "boolean receipt version": ("version", True),
            "wrong method": ("method", "unbound-tar-member"),
            "boolean carrier index": ("carrier_input_index", True),
            "noncanonical member": ("archive_member", f" {member_name}"),
            "wrong packet result": ("packet_result_sha256", "0" * 64),
            "wrong record seal": ("record_sha256", "0" * 64),
        }
        for label, (field, value) in tamper_cases.items():
            damaged = json.loads(json.dumps(recovered))
            damaged["packets"][0]["input_artifact_refs"][0]["recovery"][field] = value
            self.assertTrue(
                cli_impl.packet_recovery_integrity_errors(paths, damaged),
                label,
            )

        migrated = json.loads(
            self.cli("materialize-artifacts", "--task", task_id, "--json").stdout
        )
        self.assertEqual(migrated["materialized_refs"], 1)
        final_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(final_state["packets"][0]["input_snapshot_version"], 1)
        doctor = self.cli("doctor", "--task", task_id, "--json")
        doctor_payload = json.loads(doctor.stdout)
        self.assertTrue(doctor_payload["ok"], doctor_payload)

    def test_legacy_supersession_can_be_sealed_after_materialization(self) -> None:
        task_id = "verification-supersession-seal"
        self.init_task(task_id)
        first = self.root / "supersession-source.txt"
        second = self.root / "supersession-replacement.txt"
        first.write_text("source evidence\n", encoding="utf-8")
        second.write_text("replacement evidence\n", encoding="utf-8")
        for path, evidence in (
            (first, "Initial verification was recorded before replacement"),
            (second, "Later canonical replacement verification was recorded"),
        ):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.cli(
                "add-verification",
                "--task",
                task_id,
                "--category",
                "static_check",
                "--status",
                "pass",
                "--evidence",
                evidence,
                "--command",
                "bounded static verification",
                "--boundary",
                "Synthetic supersession seal fixture only",
                "--artifact-ref",
                f"{path}={digest}",
            )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        source, replacement = state["verification"]
        source_preimage_sha = cli_impl.canonical_record_sha256(source)
        replacement_current_sha = cli_impl.canonical_record_sha256(replacement)
        replacement_legacy = json.loads(json.dumps(replacement))
        replacement_legacy.pop("artifact_snapshot_version", None)
        replacement_legacy["artifact_refs"] = [
            {
                "path": ref["source_path"],
                "sha256": ref["sha256"],
                "size_bytes": ref["size_bytes"],
            }
            for ref in replacement["artifact_refs"]
        ]
        replacement_legacy_sha = cli_impl.canonical_record_sha256(
            replacement_legacy
        )
        source["original_status"] = source["status"]
        source["status"] = "skipped"
        source["superseded_at"] = h.now_iso()
        source["supersession_reason"] = (
            "Legacy supersession was recorded before replacement materialization"
        )
        source["replacement_index"] = 2
        source["replacement_record_sha256"] = replacement_legacy_sha
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        source_current_sha = cli_impl.canonical_record_sha256(source)
        self.cli(
            "verification-supersession-seal",
            "--task",
            task_id,
            "--verification-index",
            "1",
            "--expected-current-record-sha256",
            source_current_sha,
            "--expected-source-record-sha256",
            source_preimage_sha,
            "--replacement-index",
            "2",
            "--expected-replacement-before-materialize-sha256",
            replacement_legacy_sha,
            "--expected-replacement-current-sha256",
            replacement_current_sha,
        )
        sealed = json.loads(state_path.read_text(encoding="utf-8"))
        sealed_source = sealed["verification"][0]
        self.assertEqual(sealed_source["supersession_version"], 2)
        self.assertEqual(sealed_source["source_record_sha256"], source_preimage_sha)
        self.assertEqual(
            sealed_source["replacement_materialization"]["from_record_sha256"],
            replacement_legacy_sha,
        )
        doctor = self.cli("doctor", "--task", task_id, "--json")
        self.assertFalse(
            any(
                "supersession" in item
                for item in json.loads(doctor.stdout)["errors"]
            )
        )
        supersession_tamper_cases = {
            "boolean receipt version": lambda item: item[
                "replacement_materialization"
            ].__setitem__("version", True),
            "wrong receipt method": lambda item: item[
                "replacement_materialization"
            ].__setitem__("method", "unsealed-materialization"),
            "extra receipt field": lambda item: item[
                "replacement_materialization"
            ].__setitem__("extra", "not allowed"),
            "invalid seal time": lambda item: item[
                "replacement_materialization"
            ].__setitem__("sealed_at", "not-a-time"),
            "nontext reason": lambda item: item.__setitem__(
                "supersession_reason", True
            ),
            "invalid superseded time": lambda item: item.__setitem__(
                "superseded_at", True
            ),
        }
        for label, mutate in supersession_tamper_cases.items():
            damaged = json.loads(json.dumps(sealed))
            mutate(damaged["verification"][0])
            self.assertTrue(
                cli_impl.verification_supersession_errors(damaged),
                label,
            )

    def test_legacy_supersession_with_canonical_replacement_can_be_sealed(self) -> None:
        task_id = "verification-supersession-direct-seal"
        self.init_task(task_id)
        first = self.root / "direct-seal-source.txt"
        second = self.root / "direct-seal-replacement.txt"
        first.write_text("source evidence\n", encoding="utf-8")
        second.write_text("canonical replacement evidence\n", encoding="utf-8")
        for path, evidence in (
            (first, "Initial canonical verification before direct seal"),
            (second, "Later canonical replacement before direct seal"),
        ):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.cli(
                "add-verification",
                "--task",
                task_id,
                "--category",
                "static_check",
                "--status",
                "pass",
                "--evidence",
                evidence,
                "--command",
                "bounded static verification",
                "--boundary",
                "Synthetic direct supersession seal fixture only",
                "--artifact-ref",
                f"{path}={digest}",
            )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        source, replacement = state["verification"]
        source_preimage_sha = cli_impl.canonical_record_sha256(source)
        replacement_sha = cli_impl.canonical_record_sha256(replacement)
        source["original_status"] = source["status"]
        source["status"] = "skipped"
        source["superseded_at"] = h.now_iso()
        source["supersession_reason"] = (
            "Legacy supersession already named a canonical replacement"
        )
        source["replacement_index"] = 2
        source["replacement_record_sha256"] = replacement_sha
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        result = json.loads(
            self.cli(
                "verification-supersession-seal",
                "--task",
                task_id,
                "--verification-index",
                "1",
                "--expected-current-record-sha256",
                cli_impl.canonical_record_sha256(source),
                "--expected-source-record-sha256",
                source_preimage_sha,
                "--replacement-index",
                "2",
                "--expected-replacement-before-materialize-sha256",
                replacement_sha,
                "--expected-replacement-current-sha256",
                replacement_sha,
                "--json",
            ).stdout
        )
        self.assertFalse(result["replacement_was_materialized"])
        sealed = json.loads(state_path.read_text(encoding="utf-8"))
        sealed_source = sealed["verification"][0]
        self.assertEqual(sealed_source["supersession_version"], 2)
        self.assertEqual(sealed_source["source_record_sha256"], source_preimage_sha)
        self.assertNotIn("replacement_materialization", sealed_source)
        doctor = self.cli("doctor", "--task", task_id, "--json")
        self.assertTrue(json.loads(doctor.stdout)["ok"], doctor.stdout)

        subprocess.run(
            ["git", "-C", str(self.root), "add", first.name, second.name], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "seal fixture artifacts"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "none",
            "--detail",
            "Synthetic supersession migration has no tracked delivery",
        )
        self.add_passing_verification(task_id)
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Close the canonical supersession fixture",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            task_id,
            "--summary",
            "Canonical supersession fixture completed",
        )
        closed_payload = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(closed_payload["ok"], closed_payload)

        paths = h.get_paths(self.root)
        terminal = h.load_task(paths, task_id)
        terminal_source = terminal["verification"][0]
        terminal_source.pop("supersession_version")
        terminal_source.pop("source_record_sha256")
        terminal_current_sha = cli_impl.canonical_record_sha256(terminal_source)
        cli_impl.commit_checkpoint(paths, terminal)
        seal_cli_args = (
            "verification-supersession-seal",
            "--task",
            task_id,
            "--verification-index",
            "1",
            "--expected-current-record-sha256",
            terminal_current_sha,
            "--expected-source-record-sha256",
            source_preimage_sha,
            "--replacement-index",
            "2",
            "--expected-replacement-before-materialize-sha256",
            replacement_sha,
            "--expected-replacement-current-sha256",
            replacement_sha,
            "--json",
        )
        legacy_doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(legacy_doctor.returncode, 1, legacy_doctor.stderr)
        self.assertNotIn("Traceback", legacy_doctor.stderr)
        legacy_payload = json.loads(legacy_doctor.stdout)
        self.assertFalse(legacy_payload["ok"])
        self.assertTrue(
            any("not sealed as version 2" in item for item in legacy_payload["errors"]),
            legacy_payload,
        )
        self.assertFalse(
            any("invalid replacement index" in item for item in legacy_payload["errors"]),
            legacy_payload,
        )

        checkpoint_path = h.task_dir(paths, task_id) / "checkpoint.md"
        checkpoint_bytes = checkpoint_path.read_bytes()
        checkpoint_path.write_text("damaged terminal checkpoint\n", encoding="utf-8")
        damaged_checkpoint = self.cli(*seal_cli_args, ok=False)
        self.assertIn("current physical checkpoint", damaged_checkpoint.stderr)
        h.atomic_write_bytes(checkpoint_path, checkpoint_bytes)

        seal_args = cli_impl.argparse.Namespace(
            task=task_id,
            verification_index=1,
            expected_current_record_sha256=terminal_current_sha,
            expected_source_record_sha256=source_preimage_sha,
            replacement_index=2,
            expected_replacement_before_materialize_sha256=replacement_sha,
            expected_replacement_current_sha256=replacement_sha,
            json=True,
        )
        with mock.patch.object(
            cli_impl,
            "atomic_write_text",
            side_effect=OSError("injected checkpoint publication interruption"),
        ):
            with self.assertRaisesRegex(OSError, "injected checkpoint"):
                cli_impl.cmd_verification_supersession_seal(seal_args, paths)
        pending = h.load_task(paths, task_id)
        self.assertTrue(pending["checkpoint_required"])
        self.assertIn("terminal_supersession_checkpoint_migration", pending)
        pending_bytes = state_path.read_bytes()
        pending["verification"][0]["supersession_reason"] = (
            "A different but superficially valid supersession reason"
        )
        h.atomic_write_json(state_path, pending)
        damaged_pending = self.cli(*seal_cli_args, ok=False)
        self.assertIn("pending state identity changed", damaged_pending.stderr)
        h.atomic_write_bytes(state_path, pending_bytes)

        resumed = json.loads(self.cli(*seal_cli_args).stdout)
        self.assertTrue(resumed["terminal_migration"])
        self.assertTrue(resumed["resumed"])
        self.assertFalse(resumed["already_sealed"])
        final_payload = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(final_payload["ok"], final_payload)
        replayed = json.loads(self.cli(*seal_cli_args).stdout)
        self.assertTrue(replayed["resumed"])
        self.assertTrue(replayed["already_sealed"])

    def test_multiple_legacy_supersessions_can_be_sealed_one_by_one(self) -> None:
        task_id = "verification-multi-edge-seal"
        self.init_task(task_id)
        artifacts: list[Path] = []
        for index in range(4):
            artifact = self.root / f"multi-edge-{index + 1}.txt"
            artifact.write_text(f"verification edge fixture {index + 1}\n", encoding="utf-8")
            artifacts.append(artifact)
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.cli(
                "add-verification",
                "--task",
                task_id,
                "--category",
                "static_check",
                "--status",
                "pass",
                "--evidence",
                f"Canonical verification record {index + 1} for migration",
                "--command",
                "bounded static verification",
                "--boundary",
                "Synthetic multiple-edge migration fixture",
                "--artifact-ref",
                f"{artifact}={digest}",
            )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        records = state["verification"]
        seal_inputs: list[tuple[int, int, str, str, str]] = []
        for source_number, replacement_number in ((1, 2), (3, 4)):
            source = records[source_number - 1]
            replacement = records[replacement_number - 1]
            source_preimage_sha = cli_impl.canonical_record_sha256(source)
            replacement_sha = cli_impl.canonical_record_sha256(replacement)
            source["original_status"] = source["status"]
            source["status"] = "skipped"
            replacement_time = h.parse_time(str(replacement.get("recorded_at", "")))
            self.assertIsNotNone(replacement_time)
            assert replacement_time is not None
            source["superseded_at"] = (
                replacement_time + dt.timedelta(microseconds=1)
            ).isoformat(timespec="microseconds")
            source["supersession_reason"] = (
                f"Legacy edge {source_number} names canonical replacement {replacement_number}"
            )
            source["replacement_index"] = replacement_number
            source["replacement_record_sha256"] = replacement_sha
            seal_inputs.append(
                (
                    source_number,
                    replacement_number,
                    cli_impl.canonical_record_sha256(source),
                    source_preimage_sha,
                    replacement_sha,
                )
            )
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        for ordinal, (
            source_number,
            replacement_number,
            current_source_sha,
            source_preimage_sha,
            replacement_sha,
        ) in enumerate(seal_inputs, start=1):
            self.cli(
                "verification-supersession-seal",
                "--task",
                task_id,
                "--verification-index",
                str(source_number),
                "--expected-current-record-sha256",
                current_source_sha,
                "--expected-source-record-sha256",
                source_preimage_sha,
                "--replacement-index",
                str(replacement_number),
                "--expected-replacement-before-materialize-sha256",
                replacement_sha,
                "--expected-replacement-current-sha256",
                replacement_sha,
            )
            migrated = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertTrue(
                cli_impl._is_exact_int(
                    migrated["verification"][source_number - 1].get(
                        "supersession_version"
                    ),
                    2,
                )
            )
            if ordinal == 1:
                doctor = subprocess.run(
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
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
                self.assertEqual(doctor.returncode, 1, doctor.stderr)
                self.assertIn("not sealed as version 2", doctor.stdout)

        doctor = self.cli("doctor", "--task", task_id, "--json")
        self.assertTrue(json.loads(doctor.stdout)["ok"], doctor.stdout)
        migrated = json.loads(state_path.read_text(encoding="utf-8"))
        migrated["verification"][0]["supersession_version"] = 2.0
        self.assertTrue(cli_impl.verification_supersession_errors(migrated))

    def test_legacy_supersession_can_seal_to_an_already_superseded_replacement(self) -> None:
        task_id = "verification-chain-seal"
        self.init_task(task_id)
        for index in range(3):
            artifact = self.root / f"chain-edge-{index + 1}.txt"
            artifact.write_text(f"chain verification {index + 1}\n", encoding="utf-8")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.cli(
                "add-verification",
                "--task",
                task_id,
                "--category",
                "static_check",
                "--status",
                "pass",
                "--evidence",
                f"Canonical chain verification record {index + 1}",
                "--command",
                "bounded static verification",
                "--boundary",
                "Synthetic chained supersession migration fixture",
                "--artifact-ref",
                f"{artifact}={digest}",
            )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        source, middle, leaf = state["verification"]
        source_preimage_sha = cli_impl.canonical_record_sha256(source)
        middle_preimage_sha = cli_impl.canonical_record_sha256(middle)
        leaf_sha = cli_impl.canonical_record_sha256(leaf)
        source["original_status"] = source["status"]
        source["status"] = "skipped"
        source["superseded_at"] = h.now_iso()
        source["supersession_reason"] = (
            "Legacy source names a replacement that is later superseded again"
        )
        source["replacement_index"] = 2
        source["replacement_record_sha256"] = middle_preimage_sha
        source_current_sha = cli_impl.canonical_record_sha256(source)
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        self.cli(
            "verification-supersede",
            "--task",
            task_id,
            "--verification-index",
            "2",
            "--expected-record-sha256",
            middle_preimage_sha,
            "--replacement-index",
            "3",
            "--replacement-record-sha256",
            leaf_sha,
            "--reason",
            "The middle verification was replaced by the later canonical leaf",
        )
        chained = json.loads(state_path.read_text(encoding="utf-8"))
        middle_current_sha = cli_impl.canonical_record_sha256(
            chained["verification"][1]
        )
        sealed = json.loads(
            self.cli(
                "verification-supersession-seal",
                "--task",
                task_id,
                "--verification-index",
                "1",
                "--expected-current-record-sha256",
                source_current_sha,
                "--expected-source-record-sha256",
                source_preimage_sha,
                "--replacement-index",
                "2",
                "--expected-replacement-before-materialize-sha256",
                middle_preimage_sha,
                "--expected-replacement-current-sha256",
                middle_current_sha,
                "--json",
            ).stdout
        )
        self.assertFalse(sealed["replacement_was_materialized"])
        doctor = self.cli("doctor", "--task", task_id, "--json")
        self.assertTrue(json.loads(doctor.stdout)["ok"], doctor.stdout)

    def test_materialize_rejects_active_authority_and_global_ref_overflow(self) -> None:
        task_id = "artifact-materialize-bounds"
        self.init_task(task_id)
        source = self.root / "legacy-live-input.txt"
        source.write_text("bounded legacy input\n", encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "active-reader",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Keep active legacy authority immutable",
            "--scope",
            "Synthetic active-packet migration fixture",
            "--deliverable",
            "No authority rewrite",
            "--validation",
            "Materialization must reject active packets",
            "--input-artifact",
            f"{source}={digest}",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        packet = state["packets"][0]
        packet["packet_schema_version"] = 3
        packet.pop("packet_contract_sha256", None)
        packet["input_artifact_refs"] = [
            {
                "path": str(source.resolve()),
                "sha256": digest,
                "size_bytes": source.stat().st_size,
            }
        ]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        before_active = state_path.read_bytes()
        rejected = self.cli("materialize-artifacts", "--task", task_id, ok=False)
        self.assertIn("active legacy packet authority", rejected.stderr)
        self.assertEqual(before_active, state_path.read_bytes())

        self.cli(
            "add-verification",
            "--task",
            task_id,
            "--category",
            "static_check",
            "--status",
            "pass",
            "--evidence",
            "A bounded fixture creates one valid verification record",
            "--command",
            "bounded static check",
            "--boundary",
            "Synthetic materialization-count gate only",
            "--artifact-ref",
            f"{source}={digest}",
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["packets"][0]["status"] = "failed"
        legacy_ref = {
            "path": str(source.resolve()),
            "sha256": digest,
            "size_bytes": source.stat().st_size,
        }
        state["verification"][0].pop("artifact_snapshot_version", None)
        state["verification"][0]["artifact_refs"] = [
            dict(legacy_ref) for _ in range(65)
        ]
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        before_overflow = state_path.read_bytes()
        rejected = self.cli("materialize-artifacts", "--task", task_id, ok=False)
        self.assertIn("limit is 64", rejected.stderr)
        self.assertEqual(before_overflow, state_path.read_bytes())

    def test_steward_distributes_chief_decision_and_tracks_acknowledgement(self) -> None:
        self.init_task("steward-control-plane", session_id="chief-session")
        commit = self.git_commit("steward-control-plane")
        self.create_lane(
            "steward-control-plane",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.create_lane(
            "steward-control-plane",
            "pd",
            kind="physical",
            role="external_operator",
            authority_commit=commit,
        )
        self.create_lane(
            "steward-control-plane",
            "coord",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        self.cli(
            "claim",
            "--task",
            "steward-control-plane",
            "--token",
            "rtl-implementation-claim",
            "--owner",
            "rtl-owner",
            "--kind",
            "RTL",
            "--lock",
            "repo:file:authority-steward-control-plane.txt",
            "--intent",
            "Own the bounded target implementation used by coordination closure",
            "--validation",
            "Independent PD verifier checks the exact baseline and evidence artifact",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli(
            "coordination-create",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--source-lane",
            "pd",
            "--target-lane",
            "rtl",
            "--severity",
            "hard_gate",
            "--request",
            "Reduce sequential-cell area under the matched budget",
            "--outcome",
            "Lower DFF area without changing numeric semantics",
            "--evidence",
            "Matched PD report records excessive sequential-cell area",
        )
        self.cli(
            "coordination-update",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--actor-lane",
            "rtl",
            "--expected-version",
            "1",
            "--status",
            "countered",
            "--response",
            "Reuse phase-local registers with bounded numeric verification",
        )
        arbitrated = json.loads(
            self.cli(
                "coordination-arbitrate",
                "--task",
                "steward-control-plane",
                "--request-id",
                "pd-rtl-area",
                "--session-id",
                "chief-session",
                "--expected-version",
                "2",
                "--decision",
                "approved",
                "--rationale",
                "Chief selects register reuse after comparing area and verification risk",
                "--json",
            ).stdout
        )
        source_directive = next(
            item for item in arbitrated["directives"] if item["target_lane"] == "pd"
        )
        target_directive = next(
            item for item in arbitrated["directives"] if item["target_lane"] == "rtl"
        )
        premature_close = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            "steward-control-plane",
            "--summary",
            "must not close",
            ok=False,
        )
        self.assertIn("unresolved coordination requests", premature_close.stderr)
        self.cli(
            "baseline-freeze",
            "--task",
            "steward-control-plane",
            "--baseline-id",
            "rc-area",
            "--contract-version",
            "cv1",
            "--session-id",
            "chief-session",
            "--decision",
            "Freeze chief-approved PD to RTL coordination baseline",
            "--coord",
            "pd-rtl-area",
        )
        wrong_lane = self.cli(
            "coordination-directive-ack",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--directive-id",
            target_directive["directive_id"],
            "--actor-lane",
            "pd",
            "--evidence",
            "PD cannot acknowledge the RTL directive",
            ok=False,
        )
        self.assertIn("target lane", wrong_lane.stderr)
        self.cli(
            "coordination-directive-ack",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--directive-id",
            source_directive["directive_id"],
            "--actor-lane",
            "pd",
            "--evidence",
            "PD requester acknowledges its verification and remeasurement directive",
        )
        self.cli(
            "coordination-directive-ack",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--directive-id",
            target_directive["directive_id"],
            "--actor-lane",
            "rtl",
            "--evidence",
            "RTL owner acknowledges the chief-approved bounded directive",
        )
        request = next(
            item
            for item in self.task_state("steward-control-plane")["coordination_requests"]
            if item["request_id"] == "pd-rtl-area"
        )
        ack_only = self.cli(
            "coordination-resolve",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--expected-version",
            str(request["version"]),
            "--session-id",
            "chief-session",
            "--evidence",
            "Acknowledgement alone must not be treated as verified implementation closure",
            ok=False,
        )
        self.assertIn("independent verification", ack_only.stderr)
        implementation_artifact = self.root / "rtl-implementation-evidence.json"
        implementation_artifact.write_text(
            '{"implementation":"bounded register reuse","status":"ready for verification"}\n',
            encoding="utf-8",
        )
        implementation_sha = hashlib.sha256(implementation_artifact.read_bytes()).hexdigest()
        implementation = json.loads(
            self.cli(
                "coordination-implementation-submit",
                "--task",
                "steward-control-plane",
                "--request-id",
                "pd-rtl-area",
                "--expected-version",
                str(request["version"]),
                "--actor-lane",
                "rtl",
                "--claim-token",
                "rtl-implementation-claim",
                "--baseline-id",
                "rc-area",
                "--evidence-category",
                "integration_test",
                "--command",
                "python3 verify_register_reuse.py --baseline rc-area",
                "--boundary",
                "Exact rc-area contract and bounded register reuse implementation only",
                "--evidence-artifact",
                str(implementation_artifact),
                "--evidence-sha256",
                implementation_sha,
                "--json",
            ).stdout
        )
        request = next(
            item
            for item in self.task_state("steward-control-plane")["coordination_requests"]
            if item["request_id"] == "pd-rtl-area"
        )
        verification_artifact = self.root / "pd-independent-verification.json"
        verification_artifact.write_text(
            '{"oracle":"integration_test","result":"pass","baseline":"rc-area"}\n',
            encoding="utf-8",
        )
        verification_sha = hashlib.sha256(verification_artifact.read_bytes()).hexdigest()
        verification = json.loads(
            self.cli(
                "coordination-verify",
                "--task",
                "steward-control-plane",
                "--request-id",
                "pd-rtl-area",
                "--expected-version",
                str(request["version"]),
                "--verifier-lane",
                "pd",
                "--category",
                "integration_test",
                "--status",
                "pass",
                "--test-oracle",
                "Matched integration test checks register reuse outcome without semantic regression",
                "--command",
                "python3 independent_pd_rtl_check.py --baseline rc-area",
                "--boundary",
                "Independent PD-to-RTL closure on exact rc-area baseline only",
                "--evidence-artifact",
                str(verification_artifact),
                "--evidence-sha256",
                verification_sha,
                "--json",
            ).stdout
        )
        self.assertEqual(verification["implementation_attempt_id"], implementation["attempt_id"])
        request = next(
            item
            for item in self.task_state("steward-control-plane")["coordination_requests"]
            if item["request_id"] == "pd-rtl-area"
        )
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "steward-control-plane"
            / "state.json"
        )
        verified_state = state_path.read_bytes()
        pd_drift = self.git_commit("pd-post-verification-drift")
        self.revise_lane(
            "steward-control-plane",
            "pd",
            authority_commit=pd_drift,
            change_class="evidence_only",
            contract_version="cv1",
            generator_version="gv1",
            adapter_version="av1",
        )
        stale_verification = self.cli(
            "coordination-resolve",
            "--task",
            "steward-control-plane",
            "--request-id",
            "pd-rtl-area",
            "--expected-version",
            str(request["version"]),
            "--session-id",
            "chief-session",
            "--evidence",
            "A PASS from an older lane authority must not close the request",
            ok=False,
        )
        self.assertIn("lane authority changed", stale_verification.stderr)
        state_path.write_bytes(verified_state)
        resolved = json.loads(
            self.cli(
                "coordination-resolve",
                "--task",
                "steward-control-plane",
                "--request-id",
                "pd-rtl-area",
                "--expected-version",
                str(request["version"]),
                "--session-id",
                "chief-session",
                "--evidence",
                "Directive acknowledged and exact RC baseline linkage recorded",
                "--json",
            ).stdout
        )
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["control_phase"], "resolved")

    def test_reconcile_observations_classify_orphan_without_mutation(self) -> None:
        self.init_task("reconcile-observed")
        commit = self.git_commit("reconcile-observed")
        self.create_lane(
            "reconcile-observed",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.cli(
            "create-packet",
            "--task",
            "reconcile-observed",
            "--packet-id",
            "rtl-owner",
            "--agent-role",
            "implementation_specialist",
            "--model-tier",
            "expert",
            "--objective",
            "Own bounded RTL work",
            "--scope",
            "Read-only lifecycle fixture",
            "--deliverable",
            "Status only",
            "--validation",
            "Observation classification",
            "--lane-id",
            "rtl",
        )
        self.dispatch_packet(
            "reconcile-observed", "rtl-owner", "/root/rtl-owner"
        )
        observations = self.root / "observations.json"
        observations.write_text(
            json.dumps(
                {
                    "observation_version": 1,
                    "packets": {"rtl-owner": {"state": "absent"}},
                    "jobs": {},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        observation_sha = hashlib.sha256(observations.read_bytes()).hexdigest()
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "reconcile-observed"
            / "state.json"
        )
        before = state_path.read_bytes()
        report = json.loads(
            self.cli(
                "reconcile",
                "--task",
                "reconcile-observed",
                "--observations",
                str(observations),
                "--observations-sha",
                observation_sha,
                "--json",
            ).stdout
        )
        self.assertEqual(
            report["lanes"][0]["packets"][0]["classification"], "orphan_candidate"
        )
        self.assertEqual(state_path.read_bytes(), before)

    def test_capacity_planning_requires_chief_and_is_single_use(self) -> None:
        self.init_task("capacity-flow", session_id="chief-capacity")
        commit = self.git_commit("capacity-flow")
        self.create_lane(
            "capacity-flow", "rtl", kind="implementation", role="implementation_specialist", authority_commit=commit
        )
        self.create_lane(
            "capacity-flow",
            "steward",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        self.create_lane(
            "capacity-flow",
            "capacity",
            kind="capacity_planning",
            role="architect",
            authority_commit=commit,
            status="standby",
        )
        inactive = self.cli(
            "capacity-snapshot",
            "--task",
            "capacity-flow",
            "--review-id",
            "inactive-capacity",
            "--capacity-lane-id",
            "capacity",
            "--target-lane-id",
            "rtl",
            "--task-type",
            "pipeline-refactor",
            "--leaf-role",
            "worker",
            "--expected-lane-revision",
            "1",
            ok=False,
        )
        self.assertIn("engaged capacity_planning", inactive.stderr)
        self.cli(
            "lane-set-status",
            "--task",
            "capacity-flow",
            "--lane-id",
            "capacity",
            "--expected-revision",
            "1",
            "--expected-status",
            "standby",
            "--status",
            "active",
            "--next-action",
            "Analyze the exact requested task-type capacity dataset",
            "--reason",
            "Chief activates Capacity Planning only for this bounded review",
            "--session-id",
            "chief-capacity",
        )

        def terminal_packet(
            packet_id: str,
            lane_id: str,
            role: str,
            tier: str,
            task_type: str,
            *extra: str,
        ) -> None:
            self.cli(
                "create-packet",
                "--task",
                "capacity-flow",
                "--packet-id",
                packet_id,
                "--agent-role",
                role,
                "--model-tier",
                tier,
                "--objective",
                f"Produce bounded {task_type} evidence",
                "--scope",
                "Isolated capacity fixture",
                "--deliverable",
                "Canonical terminal result",
                "--validation",
                "Result identity is recorded",
                "--lane-id",
                lane_id,
                "--task-type",
                task_type,
                *extra,
            )
            self.dispatch_packet("capacity-flow", packet_id, f"/root/{packet_id}")
            self.cli(
                "packet-update",
                "--task",
                "capacity-flow",
                "--packet-id",
                packet_id,
                "--status",
                "done",
                "--typed-outcome",
                "accepted",
                "--summary",
                f"Completed bounded {task_type} fixture",
                "--evidence",
                f"Canonical result for {packet_id} records the terminal outcome",
            )

        terminal_packet("rtl-history", "rtl", "worker", "advanced", "pipeline-refactor")
        self.cli(
            "create-packet",
            "--task",
            "capacity-flow",
            "--packet-id",
            "rtl-parent",
            "--agent-role",
            "implementation_specialist",
            "--model-tier",
            "expert",
            "--objective",
            "Own the RTL department assignment",
            "--scope",
            "Depth-one parent only",
            "--deliverable",
            "Delegation control record",
            "--validation",
            "Parent remains dispatched",
            "--lane-id",
            "rtl",
            "--task-type",
            "department-owner",
        )
        review = json.loads(
            self.cli(
                "capacity-snapshot",
                "--task",
                "capacity-flow",
                "--review-id",
                "rtl-refactor-capacity",
                "--capacity-lane-id",
                "capacity",
                "--target-lane-id",
                "rtl",
                "--task-type",
                "pipeline-refactor",
                "--leaf-role",
                "worker",
                "--expected-lane-revision",
                "1",
                "--json",
            ).stdout
        )
        self.assertEqual(review["dataset"]["record_count"], 1)
        capacity_record = json.loads(
            Path(review["dataset"]["path"]).read_text(encoding="utf-8")
        )["records"][0]
        self.assertEqual(capacity_record["token_usage"], "unavailable")
        self.assertEqual(capacity_record["dispatch_provenance"], "manual_unverified")
        self.assertTrue(capacity_record["dispatch_recorded_at"])
        self.assertEqual(capacity_record["subagent_start_observed_at"], "")
        self.assertEqual(capacity_record["orchestration_started_at"], "")
        self.assertEqual(capacity_record["typed_outcome"], "accepted")
        self.assertEqual(
            capacity_record["typed_outcome_provenance"], "operator_declared"
        )
        self.assertTrue(capacity_record["model_quality_eligible"])
        self.assertEqual(review["dataset"]["eligible_record_count"], 1)
        terminal_packet(
            "capacity-analysis",
            "capacity",
            "architect",
            "frontier",
            "capacity-analysis",
            "--capacity-review-source-id",
            "rtl-refactor-capacity",
            "--input-artifact",
            f"{review['dataset']['path']}={review['dataset']['sha256']}",
        )
        review = json.loads(
            self.cli(
                "capacity-recommend",
                "--task",
                "capacity-flow",
                "--review-id",
                "rtl-refactor-capacity",
                "--expected-version",
                str(review["version"]),
                "--source-packet-id",
                "capacity-analysis",
                "--capability-tier",
                "c4_expert",
                "--rationale",
                "Historical refactor evidence shows the routine tier needs repeated escalation",
                "--risk",
                "Only one historical unit exists, so this approval is deliberately single-use",
                "--confidence-boundary",
                "Requested routing is auditable but actual model routing remains unobserved",
                "--min-eligible-records",
                "1",
                "--json",
            ).stdout
        )
        self.assertEqual(
            review["recommendation"]["phase"], "recommendation_only"
        )
        self.assertEqual(
            review["recommendation"]["sample_boundary"],
            {
                "min_eligible_records": 1,
                "eligible_record_count": 1,
                "record_count": 1,
            },
        )
        self.dispatch_packet("capacity-flow", "rtl-parent", "/root/rtl-parent")
        before = self.task_state("capacity-flow")
        unapproved = self.cli(
            "create-packet",
            "--task",
            "capacity-flow",
            "--packet-id",
            "premature-leaf",
            "--agent-role",
            "worker",
            "--model-tier",
            "expert",
            "--objective",
            "Must not bypass Chief",
            "--scope",
            "Negative fixture",
            "--deliverable",
            "No packet",
            "--validation",
            "Rejected before mutation",
            "--lane-id",
            "rtl",
            "--task-type",
            "pipeline-refactor",
            "--delegation-depth",
            "2",
            "--parent-packet-id",
            "rtl-parent",
            "--capability-tier",
            "c4_expert",
            "--capacity-decision-id",
            "rtl-refactor-capacity-chief-1",
            ok=False,
        )
        self.assertIn("does not exist", unapproved.stderr)
        self.assertEqual(before, self.task_state("capacity-flow"))
        self.cli(
            "needs-user-create",
            "--task",
            "capacity-flow",
            "--escalation-id",
            "capacity-budget-choice",
            "--category",
            "cost_budget",
            "--source-lane",
            "rtl",
            "--problem",
            "The user must decide whether the task may increase its reasoning budget",
            "--option",
            "Keep the current bounded reasoning budget",
            "--option",
            "Authorize a separately bounded budget increase",
            "--evidence",
            "The recommendation changes a user-owned resource boundary",
            "--chief-recommendation",
            "Keep the existing budget until the user explicitly changes it",
            "--session-id",
            "chief-capacity",
        )
        needs_user_block = self.cli(
            "capacity-arbitrate",
            "--task",
            "capacity-flow",
            "--review-id",
            "rtl-refactor-capacity",
            "--expected-version",
            str(review["version"]),
            "--session-id",
            "chief-capacity",
            "--decision",
            "approved",
            "--rationale",
            "Capacity arbitration must wait for the user-owned budget decision",
            ok=False,
        )
        self.assertIn("needs-user", needs_user_block.stderr)
        self.cli(
            "needs-user-resolve",
            "--task",
            "capacity-flow",
            "--escalation-id",
            "capacity-budget-choice",
            "--session-id",
            "chief-capacity",
            "--user-decision",
            "Preserve the existing task budget",
            "--user-evidence",
            "The bound Chief session recorded the explicit user disposition",
        )
        review = json.loads(
            self.cli(
                "capacity-arbitrate",
                "--task",
                "capacity-flow",
                "--review-id",
                "rtl-refactor-capacity",
                "--expected-version",
                str(review["version"]),
                "--session-id",
                "chief-capacity",
                "--decision",
                "approved",
                "--rationale",
                "Chief approves one expert-tier leaf trial with the recorded evidence boundary",
                "--json",
            ).stdout
        )
        decision_id = review["chief_decision"]["decision_id"]
        review = json.loads(
            self.cli(
                "capacity-distribute",
                "--task",
                "capacity-flow",
                "--review-id",
                "rtl-refactor-capacity",
                "--expected-version",
                str(review["version"]),
                "--steward-lane-id",
                "steward",
                "--json",
            ).stdout
        )
        review = json.loads(
            self.cli(
                "capacity-ack",
                "--task",
                "capacity-flow",
                "--review-id",
                "rtl-refactor-capacity",
                "--expected-version",
                str(review["version"]),
                "--actor-lane",
                "rtl",
                "--evidence",
                "RTL department acknowledges the exact single-use leaf routing directive",
                "--json",
            ).stdout
        )
        wrong_scope = self.cli(
            "create-packet",
            "--task",
            "capacity-flow",
            "--packet-id",
            "wrong-scope-leaf",
            "--agent-role",
            "worker",
            "--model-tier",
            "expert",
            "--objective",
            "Must not widen the approved task type",
            "--scope",
            "Negative scope fixture",
            "--deliverable",
            "No packet",
            "--validation",
            "Exact scope comparison rejects it",
            "--lane-id",
            "rtl",
            "--task-type",
            "different-refactor",
            "--delegation-depth",
            "2",
            "--parent-packet-id",
            "rtl-parent",
            "--capability-tier",
            "c4_expert",
            "--capacity-decision-id",
            decision_id,
            ok=False,
        )
        self.assertIn("outside packet scope", wrong_scope.stderr)
        dataset_path = Path(review["dataset"]["path"])
        dataset_bytes = dataset_path.read_bytes()
        dataset_path.write_text("tampered\n", encoding="utf-8")
        tampered = self.cli(
            "create-packet",
            "--task",
            "capacity-flow",
            "--packet-id",
            "tampered-dataset-leaf",
            "--agent-role",
            "worker",
            "--model-tier",
            "expert",
            "--objective",
            "Must not consume tampered capacity data",
            "--scope",
            "Negative data fixture",
            "--deliverable",
            "No packet",
            "--validation",
            "Dataset identity rejects it",
            "--lane-id",
            "rtl",
            "--task-type",
            "pipeline-refactor",
            "--delegation-depth",
            "2",
            "--parent-packet-id",
            "rtl-parent",
            "--capability-tier",
            "c4_expert",
            "--capacity-decision-id",
            decision_id,
            ok=False,
        )
        self.assertIn("stale, consumed", tampered.stderr)
        dataset_path.write_bytes(dataset_bytes)
        self.cli(
            "create-packet",
            "--task",
            "capacity-flow",
            "--packet-id",
            "expert-leaf",
            "--agent-role",
            "worker",
            "--model-tier",
            "expert",
            "--objective",
            "Execute one bounded refactor leaf assignment",
            "--scope",
            "No coordination or arbitration authority",
            "--deliverable",
            "Bounded implementation result",
            "--validation",
            "Parent independently reviews the result",
            "--lane-id",
            "rtl",
            "--task-type",
            "pipeline-refactor",
            "--delegation-depth",
            "2",
            "--parent-packet-id",
            "rtl-parent",
            "--capability-tier",
            "c4_expert",
            "--capacity-decision-id",
            decision_id,
        )
        state = self.task_state("capacity-flow")
        leaf = next(item for item in state["packets"] if item["packet_id"] == "expert-leaf")
        self.assertFalse(leaf["routing_verified"] if "routing_verified" in leaf else False)
        self.assertEqual(state["capacity_reviews"][0]["status"], "consumed")
        self.assertEqual(
            state["capacity_reviews"][0]["consumption"]["phase"],
            "recommendation_only",
        )
        expires_at = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        parent_state = self.task_state("capacity-flow")
        self.assertNotIn("/root/rtl-parent", parent_state["session_ids"])
        self.assertIn(
            "/root/rtl-parent", parent_state["subagent_parent_session_ids"]
        )
        with self.assertRaisesRegex(h.HarnessError, "root arbitration"):
            cli_impl.require_root_session(
                h.get_paths(self.root), parent_state, "/root/rtl-parent"
            )
        parent_start = self.hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "/root/rtl-parent",
                "source": "startup",
            }
        )
        self.assertIn(
            "not Chief/root authority",
            parent_start["hookSpecificOutput"]["additionalContext"],
        )
        parent_prompt = self.hook(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "/root/rtl-parent",
            }
        )
        self.assertIn(
            "not Chief/root authority",
            parent_prompt["hookSpecificOutput"]["additionalContext"],
        )
        parent_stop = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "/root/rtl-parent",
                "stop_hook_active": False,
            }
        )
        self.assertTrue(parent_stop["continue"])
        self.cli(
            "packet-arm",
            "--task",
            "capacity-flow",
            "--packet-id",
            "expert-leaf",
            "--parent-session-id",
            "/root/rtl-parent",
            "--expected-agent-type",
            "worker",
            "--expires-at",
            expires_at,
        )
        nested = self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "/root/rtl-parent",
                "turn_id": "depth-two-turn",
                "agent_id": "/root/rtl-parent/expert-leaf",
                "agent_type": "worker",
            }
        )
        self.assertIn(
            "valid pre-armed dispatch",
            nested["hookSpecificOutput"]["additionalContext"],
        )
        leaf = next(
            item
            for item in self.task_state("capacity-flow")["packets"]
            if item["packet_id"] == "expert-leaf"
        )
        self.assertEqual(leaf["dispatch_provenance"], "codex_subagent_start_observed")
        reused = self.cli(
            "create-packet",
            "--task",
            "capacity-flow",
            "--packet-id",
            "expert-leaf-two",
            "--agent-role",
            "worker",
            "--model-tier",
            "expert",
            "--objective",
            "Must not reuse a consumed decision",
            "--scope",
            "Negative fixture",
            "--deliverable",
            "No packet",
            "--validation",
            "Single-use CAS rejects it",
            "--lane-id",
            "rtl",
            "--task-type",
            "pipeline-refactor",
            "--delegation-depth",
            "2",
            "--parent-packet-id",
            "rtl-parent",
            "--capability-tier",
            "c4_expert",
            "--capacity-decision-id",
            decision_id,
            ok=False,
        )
        self.assertIn("stale, consumed", reused.stderr)
        self.cli(
            "lane-set-status",
            "--task",
            "capacity-flow",
            "--lane-id",
            "capacity",
            "--expected-revision",
            "1",
            "--expected-status",
            "active",
            "--status",
            "standby",
            "--next-action",
            "Remain dormant until another Chief-authorized capacity review",
            "--reason",
            "The single-use review was consumed and Capacity Planning has no active work",
            "--session-id",
            "chief-capacity",
        )
        self.assertEqual(self.lane_state("capacity-flow", "capacity")["status"], "standby")

    def test_task_contingent_topology_cross_lane_backfill_and_needs_user(self) -> None:
        self.init_task("topology-governance", session_id="chief-topology")
        commit = self.git_commit("topology-governance")
        self.create_lane(
            "topology-governance", "rtl", kind="implementation", role="implementation_specialist", authority_commit=commit
        )
        self.create_lane(
            "topology-governance",
            "num",
            kind="analysis",
            role="analysis_specialist",
            authority_commit=commit,
        )
        self.create_lane(
            "topology-governance",
            "steward",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        single = json.loads(
            self.cli(
                "execution-select",
                "--task",
                "topology-governance",
                "--selection-id",
                "sequential-root-cause",
                "--work-unit-id",
                "sequential-root-cause-work",
                "--mode",
                "single",
                "--lane",
                "rtl",
                "--scope",
                "One tightly coupled causal chain remains inside the RTL lane",
                "--sequential-dependency",
                "high",
                "--tool-density",
                "medium",
                "--shared-context",
                "high",
                "--rationale",
                "High sequential dependence and shared context make parallel delegation wasteful",
                "--falsification-condition",
                "Switch mode only if two independent evidence questions emerge",
                "--escalation-condition",
                "Escalate when the causal chain crosses the numeric contract boundary",
                "--session-id",
                "chief-topology",
                "--json",
            ).stdout
        )
        self.assertEqual(single["mode"], "single")
        rejected_parallel = self.cli(
            "execution-select",
            "--task",
            "topology-governance",
            "--selection-id",
            "bad-parallel",
            "--work-unit-id",
            "bad-parallel-work",
            "--mode",
            "centralized_parallel",
            "--lane",
            "rtl",
            "--lane",
            "num",
            "--scope",
            "Must reject a high-dependency parallel topology",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "medium",
            "--shared-context",
            "high",
            "--rationale",
            "This negative fixture intentionally violates topology heuristics",
            "--falsification-condition",
            "No falsification because this selection must be rejected",
            "--escalation-condition",
            "Reject before any packet or session can consume the selection",
            "--session-id",
            "chief-topology",
            ok=False,
        )
        self.assertIn("not allowed", rejected_parallel.stderr)
        hybrid = json.loads(
            self.cli(
                "execution-select",
                "--task",
                "topology-governance",
                "--selection-id",
                "rtl-num-hybrid",
                "--work-unit-id",
                "rtl-num-rounding-work",
                "--mode",
                "hybrid",
                "--lane",
                "rtl",
                "--lane",
                "num",
                "--steward-lane-id",
                "steward",
                "--scope",
                "RTL and numeric lanes need bounded direct evidence clarification",
                "--sequential-dependency",
                "medium",
                "--tool-density",
                "high",
                "--shared-context",
                "medium",
                "--rationale",
                "Central authority remains while two specialists exchange exact evidence",
                "--falsification-condition",
                "Return to single mode if the discussion becomes one causal chain",
                "--escalation-condition",
                "Escalate unresolved contract dissent to Chief and then user if goal-owned",
                "--session-id",
                "chief-topology",
                "--json",
            ).stdout
        )
        self.assertEqual(hybrid["mode"], "hybrid")
        self.cli(
            "coordination-create",
            "--task",
            "topology-governance",
            "--request-id",
            "rtl-num-rounding",
            "--source-lane",
            "rtl",
            "--target-lane",
            "num",
            "--severity",
            "hard_gate",
            "--request",
            "Clarify the exact rounding mismatch before changing either implementation",
            "--outcome",
            "Agree on evidence and preserve the existing numeric contract authority",
            "--evidence",
            "RTL and numeric traces disagree at the same bounded layer output",
            "--closure-category",
            "runtime_test",
        )
        self.cli(
            "coordination-update",
            "--task",
            "topology-governance",
            "--request-id",
            "rtl-num-rounding",
            "--actor-lane",
            "num",
            "--expected-version",
            "1",
            "--status",
            "acknowledged",
            "--response",
            "Numeric lane acknowledges the mismatch and requests exact intermediate values",
        )

        self.cli(
            "needs-user-create",
            "--task",
            "topology-governance",
            "--escalation-id",
            "taskwide-goal-choice",
            "--category",
            "goal_change",
            "--source-lane",
            "rtl",
            "--problem",
            "The user must decide whether this task may change its research goal",
            "--option",
            "Keep the current research goal and reject scope expansion",
            "--option",
            "Authorize a separately bounded goal-change task",
            "--evidence",
            "The decision concerns the whole task rather than one coordination request",
            "--chief-recommendation",
            "Keep the current goal until the user explicitly authorizes a new task",
            "--session-id",
            "chief-topology",
        )
        taskwide_blocks = self.cli(
            "coordination-arbitrate",
            "--task",
            "topology-governance",
            "--request-id",
            "rtl-num-rounding",
            "--session-id",
            "chief-topology",
            "--expected-version",
            "2",
            "--decision",
            "approved",
            "--rationale",
            "A task-wide user decision must block every technical arbitration",
            ok=False,
        )
        self.assertIn("needs-user", taskwide_blocks.stderr)
        self.cli(
            "needs-user-resolve",
            "--task",
            "topology-governance",
            "--escalation-id",
            "taskwide-goal-choice",
            "--session-id",
            "chief-topology",
            "--user-decision",
            "Preserve the current research goal",
            "--user-evidence",
            "Explicit user direction recorded by the bound Chief session",
        )

        rtl_refresh = self.git_commit("topology-rtl-refresh")
        self.revise_lane(
            "topology-governance",
            "rtl",
            authority_commit=rtl_refresh,
            change_class="evidence_only",
            contract_version="cv1",
            generator_version="gv1",
            adapter_version="av1",
        )
        stale_selection = self.cli(
            "cross-lane-open",
            "--task",
            "topology-governance",
            "--cross-lane-session-id",
            "stale-selection-session",
            "--execution-selection-id",
            "rtl-num-hybrid",
            "--request-id",
            "rtl-num-rounding",
            "--steward-lane-id",
            "steward",
            "--participant-lane",
            "rtl",
            "--participant-lane",
            "num",
            "--topic",
            "A stale topology selection must not authorize direct technical exchange",
            "--evidence-boundary",
            "Only current lane authority snapshots are valid",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("selection is stale", stale_selection.stderr)
        self.cli(
            "execution-select",
            "--task",
            "topology-governance",
            "--selection-id",
            "rtl-num-hybrid-current",
            "--work-unit-id",
            "rtl-num-rounding-work",
            "--supersedes-selection-id",
            "rtl-num-hybrid",
            "--mode",
            "hybrid",
            "--lane",
            "rtl",
            "--lane",
            "num",
            "--steward-lane-id",
            "steward",
            "--scope",
            "Fresh exact lane authorities for bounded RTL and numeric clarification",
            "--sequential-dependency",
            "medium",
            "--tool-density",
            "high",
            "--shared-context",
            "medium",
            "--rationale",
            "The stale topology record was superseded by a fresh authority snapshot",
            "--falsification-condition",
            "Cancel if either participant authority changes again",
            "--escalation-condition",
            "Escalate unresolved contract dissent to Chief",
            "--session-id",
            "chief-topology",
        )
        unbound_packet = self.cli(
            "create-packet",
            "--task",
            "topology-governance",
            "--packet-id",
            "topology-bound-investigation",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect the exact RTL side of the bounded rounding mismatch",
            "--scope",
            "Read-only investigation under the selected hybrid topology",
            "--deliverable",
            "Bounded evidence and one conclusion",
            "--validation",
            "Packet dispatch remains bound to the selected lane snapshot",
            "--lane-id",
            "rtl",
            ok=False,
        )
        self.assertIn("active execution topology", unbound_packet.stderr)
        self.create_selected_packet(
            "topology-governance",
            "topology-bound-investigation",
            "rtl",
            "rtl-num-hybrid-current",
        )
        self.dispatch_packet(
            "topology-governance",
            "topology-bound-investigation",
            "/root/topology-bound-investigation",
        )
        self.cli(
            "packet-update",
            "--task",
            "topology-governance",
            "--packet-id",
            "topology-bound-investigation",
            "--status",
            "done",
            "--summary",
            "Bounded topology-selected RTL investigation completed",
            "--evidence",
            "Canonical result preserves the exact execution selection identity",
        )
        cross = json.loads(
            self.cli(
                "cross-lane-open",
                "--task",
                "topology-governance",
                "--cross-lane-session-id",
                "rounding-working-session",
                "--execution-selection-id",
                "rtl-num-hybrid-current",
                "--request-id",
                "rtl-num-rounding",
                "--steward-lane-id",
                "steward",
                "--participant-lane",
                "rtl",
                "--participant-lane",
                "num",
                "--topic",
                "Compare exact pre-round and post-round values without changing source",
                "--evidence-boundary",
                "Only the named layer trace and current lane authority snapshots",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                "--json",
            ).stdout
        )
        open_blocks = self.cli(
            "coordination-arbitrate",
            "--task",
            "topology-governance",
            "--request-id",
            "rtl-num-rounding",
            "--session-id",
            "chief-topology",
            "--expected-version",
            "3",
            "--decision",
            "approved",
            "--rationale",
            "Must not arbitrate while direct technical results remain outside the record",
            ok=False,
        )
        self.assertIn("close and backfill", open_blocks.stderr)

        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "topology-governance"
            / "state.json"
        )
        expired_state = json.loads(state_path.read_text(encoding="utf-8"))
        expired_state["cross_lane_sessions"][0]["expires_at"] = (
            "2000-01-01T00:00:00+00:00"
        )
        state_path.write_text(
            json.dumps(expired_state, indent=2) + "\n", encoding="utf-8"
        )
        expired_close = self.cli(
            "cross-lane-close",
            "--task",
            "topology-governance",
            "--cross-lane-session-id",
            "rounding-working-session",
            "--expected-version",
            str(cross["version"]),
            "--steward-lane-id",
            "steward",
            "--conclusion",
            "Expired evidence must not be accepted as a current conclusion",
            "--dissent",
            "No expired-session dissent may be promoted",
            "--blocker",
            "A fresh authority snapshot is required",
            "--evidence",
            "This evidence is intentionally stale",
            ok=False,
        )
        self.assertIn("expired", expired_close.stderr)
        self.cli(
            "cross-lane-cancel",
            "--task",
            "topology-governance",
            "--cross-lane-session-id",
            "rounding-working-session",
            "--expected-version",
            str(cross["version"]),
            "--steward-lane-id",
            "steward",
            "--reason",
            "The session expired before a valid steward backfill was recorded",
        )
        fresh_cross = json.loads(
            self.cli(
                "cross-lane-open",
                "--task",
                "topology-governance",
                "--cross-lane-session-id",
                "rounding-working-session-fresh",
                "--execution-selection-id",
                "rtl-num-hybrid-current",
                "--request-id",
                "rtl-num-rounding",
                "--steward-lane-id",
                "steward",
                "--participant-lane",
                "rtl",
                "--participant-lane",
                "num",
                "--topic",
                "Repeat the exact value comparison against a fresh bounded session",
                "--evidence-boundary",
                "Only current exact trace identities and lane authority snapshots",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                "--json",
            ).stdout
        )
        self.cli(
            "cross-lane-close",
            "--task",
            "topology-governance",
            "--cross-lane-session-id",
            "rounding-working-session-fresh",
            "--expected-version",
            str(fresh_cross["version"]),
            "--steward-lane-id",
            "steward",
            "--conclusion",
            "Both lanes locate the divergence at one contract-bound rounding boundary",
            "--dissent",
            "No unresolved technical dissent remains after exact value comparison",
            "--blocker",
            "User still owns whether the accuracy budget may change",
            "--evidence",
            "Steward backfill cites both exact trace identities and current revisions",
        )
        escalation = json.loads(
            self.cli(
                "needs-user-create",
                "--task",
                "topology-governance",
                "--escalation-id",
                "accuracy-budget-choice",
                "--category",
                "accuracy_budget",
                "--source-lane",
                "rtl",
                "--request-id",
                "rtl-num-rounding",
                "--problem",
                "Resolving the rounding mismatch may change the user-owned accuracy budget",
                "--option",
                "Preserve exact accuracy and accept the current implementation cost",
                "--option",
                "Allow a bounded accuracy delta after a separately approved experiment",
                "--evidence",
                "Cross-lane session isolated the choice but cannot own the research goal",
                "--chief-recommendation",
                "Preserve the current accuracy budget unless the user explicitly authorizes change",
                "--session-id",
                "chief-topology",
                "--json",
            ).stdout
        )
        self.assertEqual(escalation["status"], "needs_user")
        user_blocks = self.cli(
            "coordination-arbitrate",
            "--task",
            "topology-governance",
            "--request-id",
            "rtl-num-rounding",
            "--session-id",
            "chief-topology",
            "--expected-version",
            "6",
            "--decision",
            "approved",
            "--rationale",
            "Chief must not consume a user-owned goal decision",
            ok=False,
        )
        self.assertIn("needs-user", user_blocks.stderr)
        critical = json.loads(
            self.cli(
                "status",
                "--task",
                "topology-governance",
                "--critical",
                "--json",
            ).stdout
        )
        self.assertEqual(critical["needs_user"][0]["escalation_id"], "accuracy-budget-choice")
        wrong_session = self.cli(
            "needs-user-resolve",
            "--task",
            "topology-governance",
            "--escalation-id",
            "accuracy-budget-choice",
            "--session-id",
            "not-bound",
            "--user-decision",
            "Preserve the existing accuracy budget",
            "--user-evidence",
            "Explicit user message in the main Chief-owned session",
            ok=False,
        )
        self.assertIn("session bound", wrong_session.stderr)
        self.cli(
            "needs-user-resolve",
            "--task",
            "topology-governance",
            "--escalation-id",
            "accuracy-budget-choice",
            "--session-id",
            "chief-topology",
            "--user-decision",
            "Preserve the existing accuracy budget and reject semantic drift",
            "--user-evidence",
            "Explicit user direction was received in the main Chief-owned session",
        )
        arbitrated = json.loads(
            self.cli(
                "coordination-arbitrate",
                "--task",
                "topology-governance",
                "--request-id",
                "rtl-num-rounding",
                "--session-id",
                "chief-topology",
                "--expected-version",
                "6",
                "--decision",
                "approved",
                "--rationale",
                "Chief now arbitrates within the preserved user-owned accuracy boundary",
                "--json",
            ).stdout
        )
        self.assertEqual(arbitrated["control_phase"], "decided")
        backfill_events = [
            item["event"]
            for item in self.task_state("topology-governance")["coordination_requests"][0][
                "events"
            ]
        ]
        self.assertIn("cross_lane_results_backfilled", backfill_events)

    def test_selection_supersession_revalidates_sessions_and_queued_jobs(self) -> None:
        self.init_task("topology-transition", session_id="chief-transition")
        commit = self.git_commit("topology-transition")
        self.create_lane(
            "topology-transition",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.create_lane(
            "topology-transition",
            "num",
            kind="analysis",
            role="analysis_specialist",
            authority_commit=commit,
        )
        self.create_lane(
            "topology-transition",
            "steward",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        self.cli(
            "execution-select",
            "--task",
            "topology-transition",
            "--selection-id",
            "transition-hybrid",
            "--work-unit-id",
            "transition-coordination-work",
            "--mode",
            "hybrid",
            "--lane",
            "rtl",
            "--lane",
            "num",
            "--steward-lane-id",
            "steward",
            "--scope",
            "One bounded RTL and numeric clarification",
            "--sequential-dependency",
            "medium",
            "--tool-density",
            "high",
            "--shared-context",
            "medium",
            "--rationale",
            "A controlled hybrid session is required",
            "--falsification-condition",
            "Cancel the session before replacing its topology",
            "--escalation-condition",
            "Escalate unresolved dissent to Chief",
            "--session-id",
            "chief-transition",
        )
        self.cli(
            "coordination-create",
            "--task",
            "topology-transition",
            "--request-id",
            "transition-request",
            "--source-lane",
            "rtl",
            "--target-lane",
            "num",
            "--severity",
            "hard_gate",
            "--request",
            "Compare one exact boundary without private state mutation",
            "--outcome",
            "Backfill one bounded conclusion",
            "--evidence",
            "Both lanes expose exact current authority snapshots",
            "--closure-category",
            "runtime_test",
        )
        self.cli(
            "coordination-update",
            "--task",
            "topology-transition",
            "--request-id",
            "transition-request",
            "--actor-lane",
            "num",
            "--expected-version",
            "1",
            "--status",
            "acknowledged",
            "--response",
            "Numeric lane acknowledges the bounded comparison",
        )
        cross = json.loads(
            self.cli(
                "cross-lane-open",
                "--task",
                "topology-transition",
                "--cross-lane-session-id",
                "transition-cross",
                "--execution-selection-id",
                "transition-hybrid",
                "--request-id",
                "transition-request",
                "--steward-lane-id",
                "steward",
                "--participant-lane",
                "rtl",
                "--participant-lane",
                "num",
                "--topic",
                "Compare exact boundary values",
                "--evidence-boundary",
                "Only current exact lane evidence",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                "--json",
            ).stdout
        )
        blocked_session_supersede = self.cli(
            "execution-select",
            "--task",
            "topology-transition",
            "--selection-id",
            "transition-single",
            "--work-unit-id",
            "transition-coordination-work",
            "--supersedes-selection-id",
            "transition-hybrid",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "Replacement topology must wait for session cancellation",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "medium",
            "--shared-context",
            "high",
            "--rationale",
            "The work became sequential",
            "--falsification-condition",
            "Return to hybrid only after a new authority snapshot",
            "--escalation-condition",
            "Cancel stale direct exchange first",
            "--session-id",
            "chief-transition",
            ok=False,
        )
        self.assertIn("active/unconsumed work", blocked_session_supersede.stderr)

        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "topology-transition"
            / "state.json"
        )
        untampered = state_path.read_bytes()
        tampered = json.loads(untampered)
        prior = next(
            item
            for item in tampered["execution_selections"]
            if item["selection_id"] == "transition-hybrid"
        )
        successor = json.loads(json.dumps(prior))
        successor["selection_id"] = "transition-hybrid-forged-successor"
        successor["status"] = "active"
        successor.pop("superseded_by", None)
        successor.pop("superseded_at", None)
        prior["status"] = "superseded"
        prior["superseded_by"] = successor["selection_id"]
        prior["superseded_at"] = prior["recorded_at"]
        tampered["execution_selections"].append(successor)
        state_path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
        stale_close = self.cli(
            "cross-lane-close",
            "--task",
            "topology-transition",
            "--cross-lane-session-id",
            "transition-cross",
            "--expected-version",
            str(cross["version"]),
            "--steward-lane-id",
            "steward",
            "--conclusion",
            "A superseded topology must not publish a conclusion",
            "--dissent",
            "No stale dissent may be promoted",
            "--blocker",
            "Selection authority is no longer active",
            "--evidence",
            "Intentional negative fixture",
            ok=False,
        )
        self.assertIn("no longer active", stale_close.stderr)
        doctor_result = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "doctor",
                "--task",
                "topology-transition",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(doctor_result.returncode, 1, doctor_result.stderr)
        doctor = json.loads(doctor_result.stdout)
        self.assertTrue(
            any("open cross-lane session" in item for item in doctor["errors"]),
            doctor,
        )
        state_path.write_bytes(untampered)
        self.cli(
            "cross-lane-cancel",
            "--task",
            "topology-transition",
            "--cross-lane-session-id",
            "transition-cross",
            "--expected-version",
            str(cross["version"]),
            "--steward-lane-id",
            "steward",
            "--reason",
            "Cancel before selecting a replacement topology",
        )

        self.cli(
            "execution-select",
            "--task",
            "topology-transition",
            "--selection-id",
            "transition-eda",
            "--work-unit-id",
            "transition-eda-work",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "One queued EDA execution unit",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "high",
            "--shared-context",
            "high",
            "--rationale",
            "The exact command has one causal execution chain",
            "--falsification-condition",
            "Stop before launch if topology authority changes",
            "--escalation-condition",
            "Re-select topology before any launch transition",
            "--session-id",
            "chief-transition",
        )
        self.cli(
            "claim",
            "--task",
            "topology-transition",
            "--token",
            "transition-eda-claim",
            "--owner",
            "test-root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/topology-transition-run",
            "--intent",
            "Test queued job topology revalidation without launching EDA",
            "--validation",
            "Only harness state transitions are exercised",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        receipt, receipt_sha = self.write_source_receipt("transition-source.json")
        self.cli(
            "job-start",
            "--task",
            "topology-transition",
            "--run-id",
            "transition-run",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/topology-transition-run",
            "--status",
            "queued",
            "--log",
            "/tmp/topology-transition-run/driver.log",
            "--stop-condition",
            "PASS or first fatal",
            "--source-sha",
            receipt_sha,
            "--source-manifest",
            str(receipt),
            "--tool-path",
            "/tools/vcs",
            "--tool-version",
            "VCS-test",
            "--command",
            "timeout 1m run.sh",
            "--lane-id",
            "rtl",
            "--execution-selection-id",
            "transition-eda",
        )
        blocked_job_supersede = self.cli(
            "execution-select",
            "--task",
            "topology-transition",
            "--selection-id",
            "transition-eda-replacement",
            "--work-unit-id",
            "transition-eda-work",
            "--supersedes-selection-id",
            "transition-eda",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "Replacement must wait until queued job is terminal",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "high",
            "--shared-context",
            "high",
            "--rationale",
            "No queued command may outlive its topology authority",
            "--falsification-condition",
            "Cancel or finish the queued job first",
            "--escalation-condition",
            "Require a fresh selection before launch",
            "--session-id",
            "chief-transition",
            ok=False,
        )
        self.assertIn("active/unconsumed work", blocked_job_supersede.stderr)

        untampered = state_path.read_bytes()
        tampered = json.loads(untampered)
        prior = next(
            item
            for item in tampered["execution_selections"]
            if item["selection_id"] == "transition-eda"
        )
        successor = json.loads(json.dumps(prior))
        successor["selection_id"] = "transition-eda-forged-successor"
        successor["status"] = "active"
        successor.pop("superseded_by", None)
        successor.pop("superseded_at", None)
        prior["status"] = "superseded"
        prior["superseded_by"] = successor["selection_id"]
        prior["superseded_at"] = prior["recorded_at"]
        tampered["execution_selections"].append(successor)
        state_path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
        stale_launch = self.cli(
            "job-update",
            "--task",
            "topology-transition",
            "--run-id",
            "transition-run",
            "--status",
            "running",
            "--evidence",
            "A stale queued command must not transition to running",
            "--pid",
            "4242",
            ok=False,
        )
        self.assertIn("not active", stale_launch.stderr)
        doctor_result = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "doctor",
                "--task",
                "topology-transition",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(doctor_result.returncode, 1, doctor_result.stderr)
        doctor = json.loads(doctor_result.stdout)
        self.assertTrue(
            any("active job" in item and "non-active" in item for item in doctor["errors"]),
            doctor,
        )
        state_path.write_bytes(untampered)
        self.cli(
            "job-update",
            "--task",
            "topology-transition",
            "--run-id",
            "transition-run",
            "--status",
            "running",
            "--evidence",
            "Current exact topology authority permits the synthetic transition",
            "--pid",
            "4242",
        )
        terminal_log, terminal_log_sha = self.write_terminal_log(
            "topology-transition-run-driver.log"
        )
        self.cli(
            "job-update",
            "--task",
            "topology-transition",
            "--run-id",
            "transition-run",
            "--status",
            "pass",
            "--evidence",
            "Synthetic terminal fixture records PASS and exit 0",
            "--exit-code",
            "0",
            "--terminal-log-artifact",
            str(terminal_log),
            "--terminal-log-sha256",
            terminal_log_sha,
        )

    def test_unknown_job_cannot_pass_without_validated_launch(self) -> None:
        self.init_task("unknown-launch", session_id="chief-unknown-launch")
        commit = self.git_commit("unknown-launch")
        self.create_lane(
            "unknown-launch",
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.cli(
            "execution-select",
            "--task",
            "unknown-launch",
            "--selection-id",
            "unknown-launch-selection",
            "--work-unit-id",
            "unknown-launch-work",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "One exact queued EDA work unit",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "high",
            "--shared-context",
            "high",
            "--rationale",
            "The command has one sequential launch path",
            "--falsification-condition",
            "Re-select if lane authority changes before launch",
            "--escalation-condition",
            "Never infer launch from unknown status",
            "--session-id",
            "chief-unknown-launch",
        )
        self.cli(
            "claim",
            "--task",
            "unknown-launch",
            "--token",
            "unknown-launch-claim",
            "--owner",
            "test-root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/unknown-launch-run",
            "--intent",
            "Exercise launch-authority state only",
            "--validation",
            "No EDA process is launched",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        receipt, receipt_sha = self.write_source_receipt("unknown-launch-source.json")
        self.cli(
            "job-start",
            "--task",
            "unknown-launch",
            "--run-id",
            "unknown-launch-run",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/unknown-launch-run",
            "--status",
            "queued",
            "--log",
            "/tmp/unknown-launch-run/driver.log",
            "--stop-condition",
            "PASS or first fatal",
            "--source-sha",
            receipt_sha,
            "--source-manifest",
            str(receipt),
            "--tool-path",
            "/tools/vcs",
            "--tool-version",
            "VCS-test",
            "--command",
            "timeout 1m run.sh",
            "--lane-id",
            "rtl",
            "--execution-selection-id",
            "unknown-launch-selection",
        )
        self.cli(
            "job-update",
            "--task",
            "unknown-launch",
            "--run-id",
            "unknown-launch-run",
            "--status",
            "unknown",
            "--evidence",
            "No launch identity was ever recorded",
        )
        terminal_log, terminal_log_sha = self.write_terminal_log(
            "unknown-launch-run-driver.log"
        )
        bypass = self.cli(
            "job-update",
            "--task",
            "unknown-launch",
            "--run-id",
            "unknown-launch-run",
            "--status",
            "pass",
            "--evidence",
            "A terminal marker cannot substitute for launch authority",
            "--exit-code",
            "0",
            "--terminal-log-artifact",
            str(terminal_log),
            "--terminal-log-sha256",
            terminal_log_sha,
            ok=False,
        )
        self.assertIn("prior topology/skill-validated running", bypass.stderr)
        job = self.task_state("unknown-launch")["jobs"][0]
        self.assertEqual(job["status"], "unknown")
        self.assertEqual(job["launch_authority_events"], [])
        self.cli(
            "job-update",
            "--task",
            "unknown-launch",
            "--run-id",
            "unknown-launch-run",
            "--status",
            "stopped",
            "--evidence",
            "Unlaunched stale job is explicitly stopped",
            "--exit-code",
            "1",
        )
        self.cli(
            "execution-select",
            "--task",
            "unknown-launch",
            "--selection-id",
            "unknown-launch-selection-current",
            "--work-unit-id",
            "unknown-launch-work",
            "--supersedes-selection-id",
            "unknown-launch-selection",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "Fresh topology after stopping the unlaunched job",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "high",
            "--shared-context",
            "high",
            "--rationale",
            "The stale selection is retired without producing PASS",
            "--falsification-condition",
            "Re-select again on any future authority drift",
            "--escalation-condition",
            "Require a recorded running transition before PASS",
            "--session-id",
            "chief-unknown-launch",
        )

    def test_improvement_pipeline_releases_only_validated_canary_skills(self) -> None:
        self.init_task("improvement-parent", session_id="chief-improvement")
        commit = self.git_commit("improvement-parent")
        self.create_lane(
            "improvement-parent", "rtl", kind="implementation", role="implementation_specialist", authority_commit=commit
        )
        self.create_lane(
            "improvement-parent",
            "steward",
            kind="coordination_steward",
            role="default",
            authority_commit=commit,
        )
        for packet_id in ("pain-one", "pain-two", "pain-three"):
            self.cli(
                "create-packet",
                "--task",
                "improvement-parent",
                "--packet-id",
                packet_id,
                "--agent-role",
                "worker",
                "--model-tier",
                "advanced",
                "--objective",
                "Repeat a manual waveform classification task",
                "--scope",
                "Bounded quality pain fixture",
                "--deliverable",
                "Terminal result",
                "--validation",
                "Result identity is durable",
                "--lane-id",
                "rtl",
                "--task-type",
                "waveform-classification",
            )
            self.dispatch_packet(
                "improvement-parent", packet_id, f"/root/{packet_id}"
            )
            self.cli(
                "packet-update",
                "--task",
                "improvement-parent",
                "--packet-id",
                packet_id,
                "--status",
                "done",
                "--summary",
                "Manual classification completed but consumed repeated review effort",
                "--evidence",
                f"Canonical {packet_id} result records the repeated manual work unit",
            )
        self.cli(
            "add-verification",
            "--task",
            "improvement-parent",
            "--category",
            "integration_test",
            "--status",
            "fail",
            "--evidence",
            "Repeated manual classifier missed an adversarial waveform category",
            "--command",
            "python3 bounded-waveform-check.py",
            "--boundary",
            "Only the recorded manual classification path",
            "--lane-id",
            "rtl",
        )
        request = json.loads(
            self.cli(
                "improvement-create",
                "--task",
                "improvement-parent",
                "--request-id",
                "waveform-skill-gap",
                "--source-lane",
                "rtl",
                "--task-type",
                "waveform-classification",
                "--trigger-class",
                "repeated_pain",
                "--pain-statement",
                "Manual waveform classification is repeated and still misses adversarial categories",
                "--desired-outcome",
                "Create a reusable bounded skill that improves classification quality without bypassing review",
                "--occurrence",
                "packet:pain-one",
                "--occurrence",
                "packet:pain-two",
                "--occurrence",
                "verification:0",
                "--json",
            ).stdout
        )
        request = json.loads(
            self.cli(
                "improvement-brief",
                "--task",
                "improvement-parent",
                "--request-id",
                "waveform-skill-gap",
                "--expected-version",
                str(request["version"]),
                "--steward-lane-id",
                "steward",
                "--option",
                "maintain-current=Keep manual review and accept the measured recurring quality cost",
                "--option",
                "capacity=Use a stronger leaf model without creating a reusable technical asset",
                "--option",
                "skill-automation=Build a versioned waveform classification skill with adversarial validation",
                "--recommendation",
                "A temporary skill project best addresses recurrence while preserving department authority",
                "--evidence-boundary",
                "Three work units establish recurrence but do not yet prove future skill effectiveness",
                "--json",
            ).stdout
        )
        wrong_chief = self.cli(
            "improvement-arbitrate",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--session-id",
            "not-bound",
            "--decision",
            "approved",
            "--selected-option",
            "skill-automation",
            "--rationale",
            "This session must not be allowed to act as Chief",
            ok=False,
        )
        self.assertIn("session bound", wrong_chief.stderr)
        self.cli(
            "needs-user-create",
            "--task",
            "improvement-parent",
            "--escalation-id",
            "skill-investment-choice",
            "--category",
            "user_preference",
            "--source-lane",
            "rtl",
            "--problem",
            "The user owns whether this project should invest in a reusable skill",
            "--option",
            "Continue the current manual workflow",
            "--option",
            "Authorize the bounded temporary skill project",
            "--evidence",
            "The technical brief establishes recurrence but not the user's investment preference",
            "--chief-recommendation",
            "Authorize only the bounded project and retain adoption gates",
            "--session-id",
            "chief-improvement",
        )
        needs_user_block = self.cli(
            "improvement-arbitrate",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--session-id",
            "chief-improvement",
            "--decision",
            "approved",
            "--selected-option",
            "skill-automation",
            "--rationale",
            "Chief cannot consume an unresolved user-owned investment choice",
            ok=False,
        )
        self.assertIn("needs-user", needs_user_block.stderr)
        self.cli(
            "needs-user-resolve",
            "--task",
            "improvement-parent",
            "--escalation-id",
            "skill-investment-choice",
            "--session-id",
            "chief-improvement",
            "--user-decision",
            "Authorize the bounded temporary skill project",
            "--user-evidence",
            "The bound Chief session recorded the explicit user disposition",
        )
        request = json.loads(
            self.cli(
                "improvement-arbitrate",
                "--task",
                "improvement-parent",
                "--request-id",
                "waveform-skill-gap",
                "--expected-version",
                str(request["version"]),
                "--session-id",
                "chief-improvement",
                "--decision",
                "approved",
                "--selected-option",
                "skill-automation",
                "--rationale",
                "Chief selects a temporary skill project after comparing status quo and capacity alternatives",
                "--json",
            ).stdout
        )

        self.init_task("waveform-skill-project")
        self.cli(
            "claim",
            "--task",
            "waveform-skill-project",
            "--token",
            "waveform-skill-claim",
            "--owner",
            "skill-project-root",
            "--kind",
            "SKILL",
            "--lock",
            "contract:waveform-skill-v1",
            "--intent",
            "Build and validate one immutable waveform skill release",
            "--validation",
            "skill-creator checks plus independent and blind forward tests",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        request = json.loads(
            self.cli(
                "improvement-link-project",
                "--task",
                "improvement-parent",
                "--request-id",
                "waveform-skill-gap",
                "--expected-version",
                str(request["version"]),
                "--project-task-id",
                "waveform-skill-project",
                "--json",
            ).stdout
        )
        project_results = (
            self.root
            / ".aoi"
            / "tasks"
            / "waveform-skill-project"
            / "results"
        )
        bundle = project_results / "waveform-skill-v1.bundle.tar.gz"
        skill_payload = (
            b"---\nname: waveform-classifier\ndescription: Bounded waveform classification.\n"
            b"---\n# Waveform classifier\n"
        )
        with tarfile.open(bundle, mode="w:gz") as archive:
            info = tarfile.TarInfo("SKILL.md")
            info.size = len(skill_payload)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(skill_payload))
        bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
        skill_sha = hashlib.sha256(skill_payload).hexdigest()
        validation = project_results / "waveform-skill-v1.validation.json"
        validation.write_text(
            json.dumps(
                {
                    "validation_version": 1,
                    "skill_creator_used": True,
                    "structural_pass": True,
                    "agents_metadata_consistent": True,
                    "bundled_scripts_tested": True,
                    "representative_project_fixtures": ["rtl-wave-a", "rtl-wave-b"],
                    "adversarial_fixtures": ["missing-signal", "stale-log", "false-pass"],
                    "blind_forward_tests": ["fresh-wave-c", "fresh-wave-d"],
                    "independent_review": {
                        "status": "pass",
                        "evidence": "review packet SHA and bounded findings recorded",
                        "review_packet_id": "skill-independent-review",
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        validation_sha = hashlib.sha256(validation.read_bytes()).hexdigest()
        manifest = project_results / "waveform-skill-v1.manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "skill_release_manifest_version": 1,
                    "skill_id": "waveform-classifier",
                    "skill_version": "1.0.0",
                    "maintenance_owner": "rtl-quality-owner",
                    "rollback_plan": "Disable waveform-classifier v1 and restore manual review",
                    "bundle_sha256": bundle_sha,
                    "validation_receipt_sha256": validation_sha,
                    "files": [{"path": "SKILL.md", "sha256": skill_sha}],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        artifact_refs = (
            f"{bundle}={bundle_sha}",
            f"{manifest}={manifest_sha}",
            f"{validation}={validation_sha}",
        )
        self.add_passing_verification(
            "waveform-skill-project",
            category="skill_validation",
            evidence="quick_validate and bundled skill scripts passed this exact candidate",
            command="python3 quick_validate.py waveform-skill",
            boundary="Structural and bounded fixture validation only",
            artifact_refs=artifact_refs,
        )
        unbound_review = self.cli(
            "add-verification",
            "--task",
            "waveform-skill-project",
            "--category",
            "independent_review",
            "--status",
            "pass",
            "--evidence",
            "A generic self-asserted review must not qualify the candidate",
            "--command",
            "python3 review_skill_release.py waveform-skill-v1",
            "--boundary",
            "Independent release-candidate review, not production adoption",
            *[
                value
                for item in artifact_refs
                for value in ("--artifact-ref", item)
            ],
            ok=False,
        )
        self.assertIn("review-packet-id", unbound_review.stderr)
        self.cli(
            "create-packet",
            "--task",
            "waveform-skill-project",
            "--packet-id",
            "skill-independent-review",
            "--agent-role",
            "reviewer",
            "--model-tier",
            "expert",
            "--objective",
            "Independently review the exact immutable waveform skill candidate",
            "--scope",
            "Read-only candidate review with no creator or release authority",
            "--deliverable",
            "Bounded findings and an accept-or-reject recommendation",
            "--validation",
            "Every reviewed artifact SHA matches the release candidate",
            "--input-artifact",
            artifact_refs[0],
            "--input-artifact",
            artifact_refs[1],
            "--input-artifact",
            artifact_refs[2],
        )
        self.dispatch_packet(
            "waveform-skill-project",
            "skill-independent-review",
            "/root/skill-independent-review",
        )
        self.cli(
            "packet-update",
            "--task",
            "waveform-skill-project",
            "--packet-id",
            "skill-independent-review",
            "--status",
            "done",
            "--summary",
            "Independent reviewer accepted the exact candidate within the bounded evidence tier",
            "--evidence",
            "Canonical reviewer result is bound to all three candidate artifact SHA-256 values",
        )
        self.add_passing_verification(
            "waveform-skill-project",
            category="independent_review",
            evidence="Independent reviewer accepted this exact immutable candidate",
            command="python3 review_skill_release.py waveform-skill-v1",
            boundary="Independent release-candidate review, not production adoption",
            artifact_refs=artifact_refs,
            review_packet_id="skill-independent-review",
        )
        release = json.loads(
            self.cli(
                "skill-release-record",
                "--task",
                "improvement-parent",
                "--request-id",
                "waveform-skill-gap",
                "--expected-version",
                str(request["version"]),
                "--release-id",
                "waveform-classifier-v1",
                "--skill-id",
                "waveform-classifier",
                "--skill-version",
                "1.0.0",
                "--maintenance-owner",
                "rtl-quality-owner",
                "--rollback-plan",
                "Disable waveform-classifier v1 and restore manual review",
                "--bundle",
                str(bundle),
                "--bundle-sha256",
                bundle_sha,
                "--manifest",
                str(manifest),
                "--manifest-sha256",
                manifest_sha,
                "--validation-receipt",
                str(validation),
                "--validation-receipt-sha256",
                validation_sha,
                "--json",
            ).stdout
        )
        self.assertEqual(release["status"], "release_candidate")
        request = self.task_state("improvement-parent")["improvement_requests"][0]
        canary = self.root / "canary-start.json"
        canary.write_text(
            json.dumps(
                {
                    "adoption_receipt_version": 1,
                    "request_id": "waveform-skill-gap",
                    "release_id": "waveform-classifier-v1",
                    "skill_version": "1.0.0",
                    "action": "canary",
                    "planned_skill_units": 3,
                    "rollback_plan": "Disable the versioned skill and return tasks to manual review",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        canary_sha = hashlib.sha256(canary.read_bytes()).hexdigest()
        self.cli(
            "skill-adoption-record",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--release-id",
            "waveform-classifier-v1",
            "--action",
            "canary",
            "--session-id",
            "chief-improvement",
            "--evidence-artifact",
            str(canary),
            "--evidence-sha256",
            canary_sha,
            "--rationale",
            "Chief authorizes only a three-unit canary with an explicit rollback path",
        )
        request = self.task_state("improvement-parent")["improvement_requests"][0]
        canary_event_id = self.task_state("improvement-parent")["skill_adoption_events"][-1][
            "event_id"
        ]
        incomplete_binding = self.cli(
            "create-packet",
            "--task",
            "improvement-parent",
            "--packet-id",
            "incomplete-canary-binding",
            "--agent-role",
            "worker",
            "--model-tier",
            "advanced",
            "--objective",
            "Reject a one-sided skill canary declaration",
            "--scope",
            "Bounded negative fixture",
            "--deliverable",
            "No packet is created",
            "--validation",
            "Both immutable skill binding fields are mandatory",
            "--lane-id",
            "rtl",
            "--skill-release-id",
            "waveform-classifier-v1",
            ok=False,
        )
        self.assertIn("requires both", incomplete_binding.stderr)
        for packet_id, bind_skill in (
            ("unrelated-one", False),
            ("unrelated-two", False),
            ("unrelated-three", False),
            ("canary-one", True),
            ("canary-two", True),
            ("canary-three", True),
        ):
            create_args = [
                "create-packet",
                "--task",
                "improvement-parent",
                "--packet-id",
                packet_id,
                "--agent-role",
                "worker",
                "--model-tier",
                "advanced",
                "--objective",
                "Exercise one exact waveform skill canary work unit",
                "--scope",
                "Bounded post-canary quality fixture",
                "--deliverable",
                "Terminal skill-assisted result",
                "--validation",
                "Result identity and completion time are durable",
                "--lane-id",
                "rtl",
                "--task-type",
                "waveform-classification",
            ]
            if bind_skill:
                create_args.extend(
                    [
                        "--skill-release-id",
                        "waveform-classifier-v1",
                        "--skill-canary-event-id",
                        canary_event_id,
                    ]
                )
            self.cli(*create_args)
            self.dispatch_packet(
                "improvement-parent", packet_id, f"/root/{packet_id}"
            )
            self.cli(
                "packet-update",
                "--task",
                "improvement-parent",
                "--packet-id",
                packet_id,
                "--status",
                "done",
                "--summary",
                "Skill-assisted canary classification completed successfully",
                "--evidence",
                f"Canonical {packet_id} result records the post-canary work unit",
            )
        unrelated_adopt = self.root / "unrelated-adopt.json"
        unrelated_adopt.write_text(
            json.dumps(
                {
                    "adoption_receipt_version": 1,
                    "request_id": "waveform-skill-gap",
                    "release_id": "waveform-classifier-v1",
                    "skill_version": "1.0.0",
                    "action": "adopt",
                    "canary_event_id": canary_event_id,
                    "skill_units": 3,
                    "skill_work_units": [
                        "packet:unrelated-one",
                        "packet:unrelated-two",
                        "packet:unrelated-three",
                    ],
                    "baseline_units": 0,
                    "efficiency_claim": False,
                    "success_criteria_met": True,
                    "quality_regressions": 0,
                    "rollback_path_verified": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        unrelated_sha = hashlib.sha256(unrelated_adopt.read_bytes()).hexdigest()
        unrelated_rejected = self.cli(
            "skill-adoption-record",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--release-id",
            "waveform-classifier-v1",
            "--action",
            "adopt",
            "--session-id",
            "chief-improvement",
            "--evidence-artifact",
            str(unrelated_adopt),
            "--evidence-sha256",
            unrelated_sha,
            "--rationale",
            "Generic successful packets must not impersonate skill canary work",
            ok=False,
        )
        self.assertIn("not bound to the exact skill canary", unrelated_rejected.stderr)
        bad_adopt = self.root / "bad-adopt.json"
        bad_adopt.write_text(
            json.dumps(
                {
                    "adoption_receipt_version": 1,
                    "request_id": "waveform-skill-gap",
                    "release_id": "waveform-classifier-v1",
                    "skill_version": "1.0.0",
                    "action": "adopt",
                    "canary_event_id": canary_event_id,
                    "skill_units": 2,
                    "skill_work_units": ["packet:canary-one", "packet:canary-two"],
                    "baseline_units": 3,
                    "baseline_work_units": [
                        "packet:pain-one",
                        "packet:pain-two",
                        "packet:pain-three",
                    ],
                    "efficiency_claim": True,
                    "success_criteria_met": True,
                    "quality_regressions": 0,
                    "rollback_path_verified": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        bad_sha = hashlib.sha256(bad_adopt.read_bytes()).hexdigest()
        rejected = self.cli(
            "skill-adoption-record",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--release-id",
            "waveform-classifier-v1",
            "--action",
            "adopt",
            "--session-id",
            "chief-improvement",
            "--evidence-artifact",
            str(bad_adopt),
            "--evidence-sha256",
            bad_sha,
            "--rationale",
            "Must not adopt with fewer than three canary work units",
            ok=False,
        )
        self.assertIn("skill canary", rejected.stderr)
        self.assertEqual(
            self.task_state("improvement-parent")["improvement_requests"][0]["status"],
            "canary",
        )
        stale_units_adopt = self.root / "stale-units-adopt.json"
        stale_units_adopt.write_text(
            json.dumps(
                {
                    "adoption_receipt_version": 1,
                    "request_id": "waveform-skill-gap",
                    "release_id": "waveform-classifier-v1",
                    "skill_version": "1.0.0",
                    "action": "adopt",
                    "canary_event_id": canary_event_id,
                    "skill_units": 3,
                    "skill_work_units": [
                        "packet:pain-one",
                        "packet:pain-two",
                        "packet:pain-three",
                    ],
                    "baseline_units": 0,
                    "efficiency_claim": False,
                    "success_criteria_met": True,
                    "quality_regressions": 0,
                    "rollback_path_verified": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        stale_units_sha = hashlib.sha256(stale_units_adopt.read_bytes()).hexdigest()
        stale_units_rejected = self.cli(
            "skill-adoption-record",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--release-id",
            "waveform-classifier-v1",
            "--action",
            "adopt",
            "--session-id",
            "chief-improvement",
            "--evidence-artifact",
            str(stale_units_adopt),
            "--evidence-sha256",
            stale_units_sha,
            "--rationale",
            "Pre-canary work units must not be relabeled as skill canary evidence",
            ok=False,
        )
        self.assertIn("not bound to the exact skill canary", stale_units_rejected.stderr)
        good_adopt = self.root / "good-adopt.json"
        good_adopt.write_text(
            json.dumps(
                {
                    "adoption_receipt_version": 1,
                    "request_id": "waveform-skill-gap",
                    "release_id": "waveform-classifier-v1",
                    "skill_version": "1.0.0",
                    "action": "adopt",
                    "canary_event_id": canary_event_id,
                    "skill_units": 3,
                    "skill_work_units": [
                        "packet:canary-one",
                        "packet:canary-two",
                        "packet:canary-three",
                    ],
                    "baseline_units": 3,
                    "baseline_work_units": [
                        "packet:pain-one",
                        "packet:pain-two",
                        "packet:pain-three",
                    ],
                    "efficiency_claim": True,
                    "success_criteria_met": True,
                    "quality_regressions": 0,
                    "rollback_path_verified": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        good_sha = hashlib.sha256(good_adopt.read_bytes()).hexdigest()
        self.cli(
            "skill-adoption-record",
            "--task",
            "improvement-parent",
            "--request-id",
            "waveform-skill-gap",
            "--expected-version",
            str(request["version"]),
            "--release-id",
            "waveform-classifier-v1",
            "--action",
            "adopt",
            "--session-id",
            "chief-improvement",
            "--evidence-artifact",
            str(good_adopt),
            "--evidence-sha256",
            good_sha,
            "--rationale",
            "Chief adopts after three canary and three baseline units meet quality criteria",
        )
        state = self.task_state("improvement-parent")
        self.assertEqual(state["improvement_requests"][0]["status"], "adopted")
        self.assertNotIn("installed_path", state["skill_releases"][0])
        state_path = (
            self.root
            / ".aoi"
            / "tasks"
            / "improvement-parent"
            / "state.json"
        )
        clean_state_bytes = state_path.read_bytes()
        semantic_tamper = json.loads(clean_state_bytes)
        semantic_tamper["skill_adoption_events"][-1]["skill_work_unit_bindings"][0][
            "identity_sha256"
        ] = "0" * 64
        state_path.write_text(
            json.dumps(semantic_tamper, indent=2) + "\n", encoding="utf-8"
        )
        semantic_doctor = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "doctor",
                "--task",
                "improvement-parent",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(semantic_doctor.returncode, 1, semantic_doctor.stderr)
        self.assertTrue(
            any(
                "skill adoption event" in item and "semantic integrity" in item
                for item in json.loads(semantic_doctor.stdout)["errors"]
            )
        )
        state_path.write_bytes(clean_state_bytes)
        Path(state["skill_releases"][0]["bundle_path"]).write_bytes(b"tampered\n")
        doctor = subprocess.run(
            [
                sys.executable,
                "-m", CLI_MODULE,
                "doctor",
                "--task",
                "improvement-parent",
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        self.assertTrue(
            any("skill release" in item for item in json.loads(doctor.stdout)["errors"])
        )


class V5FeatureTests(HarnessTestCase):
    def test_start_mini_six_argument_path_derives_bounded_explicit_defaults(self) -> None:
        (self.root / "docs").mkdir()
        (self.root / "docs" / "small.md").write_text("draft\n", encoding="utf-8")
        objective = "Update one small document and verify its exact content"
        result = json.loads(
            self.cli(
                "start-mini",
                "--task-id",
                "mini-defaults",
                "--objective",
                objective,
                "--owner",
                "root",
                "--session-id",
                "mini-default-session",
                "--lock",
                "repo:file:docs/small.md",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                "--json",
            ).stdout
        )
        state = h.load_task(h.get_paths(self.root), "mini-defaults")
        claim = h.load_claim_file(
            h.claim_path(h.get_paths(self.root), result["claim"], active=True)
        )
        self.assertRegex(result["claim"], r"\Amini-[0-9a-f]{24}\Z")
        self.assertEqual(state["title"], objective)
        self.assertEqual(state["objective"], objective)
        self.assertIn(objective, state["completion_boundary"])
        self.assertEqual(claim["intent"], objective)
        self.assertIn(objective, claim["validation"])

    def test_start_mini_is_atomic_constrained_and_preapproved(self) -> None:
        (self.root / "docs").mkdir()
        (self.root / "docs" / "note.md").write_text("draft\n", encoding="utf-8")
        result = self.cli(
            "start-mini",
            "--task-id",
            "mini-ok",
            "--title",
            "Small local edit",
            "--objective",
            "Exercise constrained mini lifecycle",
            "--owner",
            "root",
            "--completion-boundary",
            "One exact file is verified",
            "--session-id",
            "mini-session",
            "--token",
            "mini-claim",
            "--lock",
            "repo:file:docs/note.md",
            "--intent",
            "small documentation edit",
            "--validation",
            "documentation check",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--json",
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["profile"], "mini")
        self.assertTrue(payload["plan_ready"])
        state = h.load_task(h.get_paths(self.root), "mini-ok")
        self.assertEqual(state["profile"], "mini")
        self.assertEqual(state["claims"], ["mini-claim"])
        self.assertIn("mini-session", state["session_ids"])
        extra = self.cli(
            "claim",
            "--task",
            "mini-ok",
            "--token",
            "mini-extra",
            "--owner",
            "root",
            "--kind",
            "DOC",
            "--lock",
            "repo:file:docs/other.md",
            "--intent",
            "must reject",
            "--validation",
            "test",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("additional claims", extra.stderr)
        packet = self.cli(
            "create-packet",
            "--task",
            "mini-ok",
            "--packet-id",
            "not-allowed",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "reject",
            "--scope",
            "none",
            "--deliverable",
            "none",
            "--validation",
            "none",
            ok=False,
        )
        self.assertIn("mini task", packet.stderr)

        rejected = self.cli(
            "start-mini",
            "--task-id",
            "mini-high-risk",
            "--title",
            "Invalid mini",
            "--objective",
            "Must reject high-risk path",
            "--owner",
            "root",
            "--completion-boundary",
            "Rejected atomically",
            "--session-id",
            "mini-high-risk-session",
            "--token",
            "mini-high-risk-claim",
            "--lock",
            "repo:file:infra/deploy/a.py",
            "--intent",
            "invalid",
            "--validation",
            "none",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            ok=False,
        )
        self.assertIn("high-risk", rejected.stderr)
        self.assertFalse(h.task_state_path(h.get_paths(self.root), "mini-high-risk").exists())
        self.assertFalse(h.session_path(h.get_paths(self.root), "mini-high-risk-session").exists())

    def test_guarded_branch_adoption_records_ancestry_and_claim(self) -> None:
        self.init_task("branch-task")
        self.cli(
            "claim",
            "--task",
            "branch-task",
            "--token",
            "branch-claim",
            "--owner",
            "root",
            "--kind",
            "GIT",
            "--lock",
            "git:merge:feature/next",
            "--intent",
            "adopt planned branch",
            "--validation",
            "ancestry",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli(
            "checkpoint",
            "--task",
            "branch-task",
            "--next-action",
            "Create the claimed branch",
        )
        subprocess.run(
            ["git", "-C", str(self.root), "checkout", "-b", "feature/next"],
            check=True,
            capture_output=True,
            text=True,
        )
        (self.root / "branch-change.txt").write_text("next\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "branch-change.txt"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "branch change"],
            check=True,
            capture_output=True,
            text=True,
        )
        result = self.cli(
            "adopt-current-branch",
            "--task",
            "branch-task",
            "--reason",
            "Plan explicitly created the claimed branch",
            "--json",
        )
        payload = json.loads(result.stdout)
        self.assertTrue(payload["changed"])
        self.assertEqual(payload["new_branch"], "feature/next")
        state = h.load_task(h.get_paths(self.root), "branch-task")
        self.assertEqual(state["branch"], "feature/next")
        self.assertEqual(state["branch_adoptions"][0]["claim_token"], "branch-claim")

    def test_scoped_doctor_ignores_unrelated_task_corruption(self) -> None:
        self.init_task("doctor-a")
        self.init_task("doctor-b")
        plan_b = self.root / ".aoi" / "tasks" / "doctor-b" / "plan.md"
        plan_b.write_text(plan_b.read_text(encoding="utf-8") + "\ncorrupt\n", encoding="utf-8")
        global_result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(global_result.returncode, 1, global_result.stderr)
        self.assertIn("doctor-b", global_result.stdout)
        scoped = self.cli("doctor", "--task", "doctor-a", "--json")
        payload = json.loads(scoped.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scope"], "doctor-a")
        self.assertNotIn("doctor-b", scoped.stdout)

    def test_scoped_doctor_accepts_intentionally_unbound_closed_task(self) -> None:
        task_id = "closed-doctor"
        session_id = "closed-doctor-session"
        self.init_task(task_id, session_id)
        self.add_passing_verification(task_id)
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "none",
            "--detail",
            "lifecycle-only regression has no tracked delivery",
        )
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Close the task",
        )
        self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            task_id,
            "--summary",
            "Closed for scoped doctor regression",
        )

        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        mapping_path = h.session_path(paths, session_id)
        self.assertEqual(state["status"], "done")
        self.assertIn(session_id, state["session_ids"])
        self.assertFalse(mapping_path.exists())

        scoped = self.cli("doctor", "--task", task_id, "--json")
        payload = json.loads(scoped.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["errors"], [])

        h.atomic_write_json(
            mapping_path,
            {
                "session_id": session_id,
                "task_id": task_id,
                "bound_at": "2099-01-01T00:00:00+00:00",
            },
        )
        stale = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(stale.returncode, 1, stale.stderr)
        self.assertIn("remains mapped to closed task", stale.stdout)

        mapping_path.unlink()
        rebound_task_id = "rebound-doctor"
        self.init_task(rebound_task_id, session_id)
        rebound = self.cli("doctor", "--task", task_id, "--json")
        rebound_payload = json.loads(rebound.stdout)
        self.assertTrue(rebound_payload["ok"])
        self.assertEqual(rebound_payload["errors"], [])

        rebound_mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        rebound_mapping["session_id"] = "forged-rebound-session"
        h.atomic_write_json(mapping_path, rebound_mapping)
        forged = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(forged.returncode, 1, forged.stderr)
        self.assertIn("filename/hash mismatch", forged.stdout)

    def test_scoped_doctor_still_rejects_missing_active_session_mapping(self) -> None:
        self.install_hook_layers()
        task_id = "active-doctor"
        session_id = "active-doctor-session"
        self.init_task(task_id, session_id)
        paths = h.get_paths(self.root)
        h.session_path(paths, session_id).unlink()

        scoped = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(scoped.returncode, 1, scoped.stderr)
        payload = json.loads(scoped.stdout)
        self.assertFalse(payload["ok"])
        self.assertTrue(
            any("missing state file" in item for item in payload["errors"]),
            payload["errors"],
        )

    def test_backup_is_deterministic_verified_and_tamper_detected(self) -> None:
        self.install_hook_layers()
        self.init_task("backup-task")
        first = json.loads(self.cli("backup-state", "--json").stdout)
        second = json.loads(self.cli("backup-state", "--json").stdout)
        self.assertTrue(first["verified"])
        self.assertTrue(second["verified"])
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertFalse(first["existing"])
        self.assertTrue(second["existing"])
        verified = json.loads(
            self.cli("verify-backup", "--manifest", first["manifest"], "--json").stdout
        )
        self.assertTrue(verified["verified"])
        sidecar = Path(first["manifest"])
        escaped_payload = json.loads(sidecar.read_text(encoding="utf-8"))
        escaped_payload["archive"] = "../outside.tar.gz"
        escaped_sidecar = sidecar.with_name("escaped.manifest.json")
        escaped_sidecar.write_text(json.dumps(escaped_payload), encoding="utf-8")
        escaped = self.cli(
            "verify-backup", "--manifest", str(escaped_sidecar), ok=False
        )
        self.assertIn("plain filename", escaped.stderr)

        real_destination = Path(self.backup_temp.name) / "real"
        real_destination.mkdir()
        linked_destination = Path(self.backup_temp.name) / "linked"
        try:
            linked_destination.symlink_to(real_destination, target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("native Windows symlink privilege is unavailable")
            raise
        linked = self.cli(
            "backup-state", "--destination", str(linked_destination), ok=False
        )
        self.assertIn("symlink", linked.stderr)

        archive = Path(first["archive"])
        archive.write_bytes(archive.read_bytes() + b"tamper")
        tampered = self.cli(
            "verify-backup", "--manifest", first["manifest"], ok=False
        )
        self.assertIn("SHA-256", tampered.stderr)

    @unittest.skipIf(os.name == "nt", "POSIX symlink boundary; junction coverage is native")
    def test_doctor_rejects_symlinked_codex_config_leaf(self) -> None:
        self.install_hook_layers()
        config = self.root / ".codex" / "config.toml"
        outside = Path(self.backup_temp.name) / "outside-config.toml"
        outside.write_text("[features]\nhooks = true\n", encoding="utf-8")
        config.unlink()
        config.symlink_to(outside)

        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(
            any(
                "invalid TOML" in item and ("symlink" in item or "linked" in item)
                for item in payload["errors"]
            ),
            payload["errors"],
        )

    def test_semantic_v2_task_may_explicitly_adopt_integrity_contract(self) -> None:
        self.cli(
            "init-task",
            "--task-id",
            "semantic-integrity",
            "--title",
            "Semantic integrity genesis",
            "--objective",
            "Permit explicit O8 adoption from the semantic task boundary",
            "--owner",
            "test-root",
            "--completion-boundary",
            "Integrity contract may be adopted before close",
            "--semantic-v2",
            "--semantic-command-id",
            "semantic-integrity-genesis",
        )
        state = h.load_task(h.get_paths(self.root), "semantic-integrity")
        self.assertNotIn("integrity_contract", state)
        doctor = json.loads(
            self.cli("doctor", "--task", "semantic-integrity", "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)
        def semantic_mutation(
            command: str, command_id: str, recorded_at: str, *arguments: str
        ) -> dict[str, object]:
            head = json.loads(
                self.cli("semantic-head", "--task", "semantic-integrity", "--json").stdout
            )
            result = self.cli(
                command,
                "--task",
                "semantic-integrity",
                *arguments,
                "--command-id",
                command_id,
                "--recorded-at",
                recorded_at,
                "--expected-head-sha256",
                str(head["event_sha256"]),
                "--json",
            )
            return json.loads(result.stdout)

        genesis_head = json.loads(
            self.cli("semantic-head", "--task", "semantic-integrity", "--json").stdout
        )["event_sha256"]
        adopt_arguments = (
            "integrity-adopt",
            "--task",
            "semantic-integrity",
            "--command-id",
            "semantic-integrity-adopt",
            "--recorded-at",
            "2099-01-01T00:00:00+00:00",
            "--expected-head-sha256",
            str(genesis_head),
            "--json",
        )
        first_adopt = json.loads(self.cli(*adopt_arguments).stdout)
        self.assertFalse(first_adopt["idempotent_replay"])
        adopted = h.load_task(h.get_paths(self.root), "semantic-integrity")
        self.assertEqual(adopted["integrity_contract"]["mode"], "required_v1")
        adopted_baseline = adopted["integrity_contract"]["baseline_head"]

        # Omitting --baseline-head observes Git HEAD only on first execution.
        # An exact response-loss retry must still succeed after ambient HEAD moves.
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "commit",
                "--allow-empty",
                "-m",
                "advance after integrity adoption",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        replayed_adopt = json.loads(self.cli(*adopt_arguments).stdout)
        self.assertTrue(replayed_adopt["idempotent_replay"])
        self.assertEqual(
            h.load_task(h.get_paths(self.root), "semantic-integrity")["integrity_contract"][
                "baseline_head"
            ],
            adopted_baseline,
        )
        candidate = semantic_mutation(
            "integrity-snapshot",
            "semantic-integrity-candidate",
            "2099-01-01T00:00:01+00:00",
            "--purpose",
            "candidate",
        )
        review_artifact = Path(self.backup_temp.name) / "semantic-integrity-review.json"
        review_artifact.write_bytes(b'{"outcome":"clean"}\n')
        review_digest = hashlib.sha256(review_artifact.read_bytes()).hexdigest()
        blob_root = (
            h.get_paths(self.root).tasks
            / "semantic-integrity"
            / "results"
            / "artifact-blobs"
        )
        blobs_before_reuse = sorted(path for path in blob_root.rglob("*") if path.is_file())
        current_head = json.loads(
            self.cli("semantic-head", "--task", "semantic-integrity", "--json").stdout
        )["event_sha256"]
        reused = self.cli(
            "integrity-review",
            "--task",
            "semantic-integrity",
            "--snapshot-sha256",
            str(candidate["snapshot_sha256"]),
            "--reviewer-agent-id",
            "independent-reviewer",
            "--result-artifact",
            f"{review_artifact}={review_digest}",
            "--outcome",
            "clean",
            "--command-id",
            "semantic-integrity-adopt",
            "--recorded-at",
            "2099-01-01T00:00:02+00:00",
            "--expected-head-sha256",
            str(current_head),
            ok=False,
        )
        self.assertIn("semantic command id already exists", reused.stderr)
        self.assertEqual(
            sorted(path for path in blob_root.rglob("*") if path.is_file()),
            blobs_before_reuse,
        )
        semantic_mutation(
            "integrity-review",
            "semantic-integrity-review",
            "2099-01-01T00:00:02+00:00",
            "--snapshot-sha256",
            str(candidate["snapshot_sha256"]),
            "--reviewer-agent-id",
            "independent-reviewer",
            "--result-artifact",
            f"{review_artifact}={review_digest}",
            "--outcome",
            "clean",
        )
        semantic_mutation(
            "integrity-seal",
            "semantic-integrity-seal",
            "2099-01-01T00:00:03+00:00",
        )
        sealed = h.load_task(h.get_paths(self.root), "semantic-integrity")
        self.assertIsNotNone(sealed["integrity_contract"]["seal"])
        self.assertEqual(sealed["integrity_contract"]["snapshots"][0]["covered_claim_tokens"], [])
        doctor = json.loads(
            self.cli("doctor", "--task", "semantic-integrity", "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)

    def test_doctor_rejects_self_consistent_integrity_snapshot_with_uncovered_path(self) -> None:
        """Persisted snapshot tokens/digest do not waive per-path coverage."""

        task_id = "integrity-uncovered"
        self.init_task(task_id)
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "integrity-base-only",
            "--owner",
            "test-root",
            "--kind",
            "implementation",
            "--lock",
            "repo:file:.harness-test-root",
            "--intent",
            "Cover only the tracked fixture",
            "--validation",
            "doctor detects a deliberately uncovered sibling",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli("integrity-adopt", "--task", task_id)
        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        (self.root / ".harness-test-root").write_text("changed\n", encoding="utf-8")
        (self.root / "uncovered-integrity.txt").write_text("uncovered\n", encoding="utf-8")
        snapshot = git_plumbing_impl.task_mutation_snapshot(
            task_id,
            self.root,
            state["integrity_contract"]["baseline_head"],
        )
        coverage = git_plumbing_impl.task_mutation_snapshot_claim_coverage(
            snapshot,
            h.claims_owned_by_task(paths, task_id),
        )
        self.assertFalse(coverage["covered"])
        artifact = evidence_artifacts_impl.preserve_generated_artifact_blob(
            paths,
            task_id,
            semantic_events_impl.canonical_json_bytes(snapshot),
            label="injected integrity mutation snapshot",
            max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
        )
        record = integrity_records_impl.build_snapshot_record(
            task_id=task_id,
            worktree=snapshot["worktree"],
            baseline_head=snapshot["baseline_head"],
            current_head=snapshot["current_head"],
            artifact=artifact,
            snapshot_sha256=snapshot["snapshot_sha256"],
            claim_scope_sha256=coverage["claim_scope_sha256"],
            covered_claim_tokens=coverage["covered_claim_tokens"],
            purpose="candidate",
            producer_agent_ids=["test-root"],
        )
        state["integrity_contract"] = integrity_records_impl.append_snapshot(
            state["integrity_contract"], record
        )
        h.write_task(paths, state)

        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(
            any("uncovered paths" in item for item in payload["errors"]),
            payload,
        )

    def test_doctor_validates_nonlatest_post_fix_snapshot_bindings(self) -> None:
        """Doctor must validate every persisted snapshot, not just candidate."""

        task_id = "integrity-postfix-binding"
        self.init_task(task_id)
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "integrity-postfix-fixture",
            "--owner",
            "test-root",
            "--kind",
            "implementation",
            "--lock",
            "repo:file:.harness-test-root",
            "--intent",
            "Cover the fixture used for the distinct post-fix snapshot",
            "--validation",
            "doctor validates every snapshot record binding",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli("integrity-adopt", "--task", task_id)
        self.cli("integrity-snapshot", "--task", task_id, "--purpose", "candidate")

        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        (self.root / ".harness-test-root").write_text("post-fix\n", encoding="utf-8")
        snapshot = git_plumbing_impl.task_mutation_snapshot(
            task_id,
            self.root,
            state["integrity_contract"]["baseline_head"],
        )
        coverage = git_plumbing_impl.task_mutation_snapshot_claim_coverage(
            snapshot,
            h.claims_owned_by_task(paths, task_id),
        )
        self.assertTrue(coverage["covered"])
        artifact = evidence_artifacts_impl.preserve_generated_artifact_blob(
            paths,
            task_id,
            semantic_events_impl.canonical_json_bytes(snapshot),
            label="injected post-fix binding snapshot",
            max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
        )
        record = integrity_records_impl.build_snapshot_record(
            task_id=task_id,
            worktree=snapshot["worktree"],
            baseline_head=snapshot["baseline_head"],
            current_head="0" * 40,
            artifact=artifact,
            snapshot_sha256=snapshot["snapshot_sha256"],
            claim_scope_sha256=coverage["claim_scope_sha256"],
            covered_claim_tokens=coverage["covered_claim_tokens"],
            purpose="post_fix",
            producer_agent_ids=["test-root"],
        )
        state["integrity_contract"] = integrity_records_impl.append_snapshot(
            state["integrity_contract"], record
        )
        h.write_task(paths, state)

        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(
            any("current-head binding differs" in item for item in payload["errors"]),
            payload,
        )


class ConfigurationTests(HarnessTestCase):
    def test_custom_profile_drives_state_roles_evidence_and_external_namespace(self) -> None:
        config = self.root / "aoi.toml"
        text = config.read_text(encoding="utf-8")
        text = text.replace('profile_id = "generic-v1"', 'profile_id = "custom-v1"')
        text = text.replace('state_dir = ".aoi"', 'state_dir = ".org-state"')
        text = text.replace(
            'high_risk_paths = [".aoi/",',
            'high_risk_paths = [".org-state/",',
        )
        text = text.replace(
            'departments = ["implementation", "verification", "operations", "steward"]',
            'departments = ["build", "review", "steward"]',
        )
        text = text.replace('worker = "advanced"', 'worker = "economical"')
        text = text.replace(
            'categories = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "hook_smoke", "skill_validation", "doctor", "independent_review", "documentation_check", "historical_terminal_readback", "citation_hygiene_review", "resource_governance", "delivery_check", "engineering_inference"]',
            'categories = ["proof", "engineering_inference"]',
        )
        text = text.replace(
            'close_qualifying = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "hook_smoke", "skill_validation", "doctor", "independent_review", "documentation_check", "citation_hygiene_review", "resource_governance", "delivery_check"]',
            'close_qualifying = ["proof"]',
        )
        text = text.replace(
            'external_lock_namespace = "external"',
            'external_lock_namespace = "vendor"',
        )
        self.cli("chief-release", "--reason", "reset isolated profile fixture")
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
        ):
            self.env.pop(name, None)
        shutil.rmtree(self.root / ".aoi")
        config.unlink()
        candidate = Path(self.backup_temp.name) / "custom-profile.toml"
        candidate.write_text(text, encoding="utf-8")
        self.cli(
            "init",
            "--config",
            str(candidate),
            "--expected-config-sha256",
            hashlib.sha256(candidate.read_bytes()).hexdigest(),
        )
        acquired = json.loads(
            self.cli(
                "chief-acquire",
                "--session-id",
                "custom-profile-chief",
                "--json",
            ).stdout
        )
        self.env["AOI_CHIEF_SESSION_ID"] = "custom-profile-chief"
        self.env["AOI_CHIEF_EPOCH"] = str(acquired["authority"]["epoch"])
        self.env["AOI_CHIEF_CREDENTIAL_FILE"] = acquired["credential_file"]
        self.assertTrue((self.root / ".org-state" / "INDEX.md").is_file())
        self.assertIn("/.org-state/", (self.root / ".gitignore").read_text())
        self.cli(
            "init-task",
            "--task-id",
            "custom-profile",
            "--title",
            "Custom profile",
            "--objective",
            "Exercise configured policy",
            "--owner",
            "root",
            "--completion-boundary",
            "Configured policy is reflected in durable state",
        )
        self.cli(
            "approve-plan",
            "--task",
            "custom-profile",
            "--note",
            "Generated plan has explicit scope and verification",
        )
        self.cli(
            "create-packet",
            "--task",
            "custom-profile",
            "--packet-id",
            "configured-worker",
            "--agent-role",
            "worker",
            "--model-tier",
            "economical",
            "--objective",
            "Read the configured project",
            "--scope",
            "Read-only configuration inspection",
            "--deliverable",
            "A bounded configuration conclusion",
            "--validation",
            "Compare the result with aoi.toml",
            "--json",
        )
        self.cli(
            "add-verification",
            "--task",
            "custom-profile",
            "--category",
            "proof",
            "--status",
            "pass",
            "--evidence",
            "The custom evidence category was accepted",
            "--command",
            "inspect aoi.toml",
            "--boundary",
            "Configuration routing only",
        )
        accepted = self.cli(
            "check-locks", "--lock", "vendor:file:/tmp/output.log", "--json"
        )
        self.assertEqual(
            json.loads(accepted.stdout)["requested_locks"],
            ["vendor:file:/tmp/output.log"],
        )
        rejected = self.cli(
            "check-locks", "--lock", "external:file:/tmp/output.log", ok=False
        )
        self.assertIn("invalid lock URI", rejected.stderr)

        state = json.loads(
            (
                self.root
                / ".org-state"
                / "tasks"
                / "custom-profile"
                / "state.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(state["profile_id"], "custom-v1")
        self.assertEqual(state["packets"][0]["model_tier"], "economical")
        self.assertEqual(
            state["config_sha256"], hashlib.sha256(config.read_bytes()).hexdigest()
        )

    def test_config_drift_blocks_existing_task(self) -> None:
        self.init_task("config-drift")
        config = self.root / "aoi.toml"
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                'profile_id = "generic-v1"', 'profile_id = "generic-v2"'
            ),
            encoding="utf-8",
        )
        result = self.cli("status", "--task", "config-drift", ok=False)
        self.assertIn("profile differs", result.stderr)

    def test_unknown_config_key_fails_closed(self) -> None:
        config = self.root / "aoi.toml"
        config.write_text(
            config.read_text(encoding="utf-8") + "\nunknown_policy = true\n",
            encoding="utf-8",
        )
        result = self.cli("status", ok=False)
        self.assertIn("unknown legacy key", result.stderr)

    def test_dangerous_state_directories_fail_closed(self) -> None:
        config = self.root / "aoi.toml"
        original = config.read_text(encoding="utf-8")
        for unsafe in (".", ".git/aoi"):
            with self.subTest(state_dir=unsafe):
                config.write_text(
                    original.replace('state_dir = ".aoi"', f'state_dir = "{unsafe}"'),
                    encoding="utf-8",
                )
                result = self.cli("status", ok=False)
                self.assertIn("state_dir must be a safe", result.stderr)

    def test_symlinked_root_and_state_fail_closed(self) -> None:
        linked_root = Path(self.backup_temp.name) / "linked-root"
        try:
            linked_root.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("native Windows symlink privilege is unavailable")
            raise
        env = self.env.copy()
        env["AOI_ROOT"] = str(linked_root)
        linked_result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "status"],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(linked_result.returncode, 2, linked_result.stderr)
        self.assertIn("may not traverse symlinks", linked_result.stderr)

        state = self.root / ".aoi"
        shutil.rmtree(state)
        outside = Path(self.backup_temp.name) / "outside-state"
        outside.mkdir()
        state.symlink_to(outside, target_is_directory=True)
        state_result = self.cli("status", ok=False)
        self.assertIn("state directory may not traverse symlinks", state_result.stderr)


class CodexLocalProvenanceDoctorTests(HarnessTestCase):
    def test_doctor_consumes_strict_local_v2_receipt_and_reports_runtime_drift(
        self,
    ) -> None:
        """Doctor must preserve strict v2 loading and surface liveness drift.

        The local receipt fixture is intentionally a fully shaped schema-v2
        receipt.  This test owns the doctor boundary only: the dedicated
        provenance tests exercise the real wheel/RECORD/bundle construction.
        """

        receipt = fake_local_provenance_receipt(self.root, salt="doctor-v2")
        self.assertEqual(
            codex_install_provenance_impl.validate_codex_install_provenance_receipt(
                receipt
            ),
            receipt,
        )
        local_bundle = self.root / "reviewed-local-install.json"
        expected_bundle_sha256 = "b" * 64
        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "validate_codex_local_install_provenance",
            return_value=receipt,
        ):
            initialized = self.cli_in_process(
                "codex-init",
                "--local-artifact-bundle-file",
                str(local_bundle),
                "--expected-local-artifact-bundle-sha256",
                expected_bundle_sha256,
                "--user-skills-root",
                str(self.root / "user-skills"),
                "--json",
            )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        self.assertEqual(
            codex_install_provenance_impl.load_codex_install_provenance_receipt(
                self.root
            ),
            receipt,
        )

        def doctor_with_runtime_verifier(
            *, side_effect: Exception | None = None
        ) -> tuple[int, dict[str, object]]:
            stdout = io.StringIO()
            with (
                mock.patch.dict(os.environ, self.env, clear=True),
                mock.patch("sys.stdout", stdout),
                mock.patch("sys.stderr", new=io.StringIO()),
                mock.patch.object(
                    cli_impl.codex_install_provenance_impl,
                    "verify_runtime_hook_provenance",
                    return_value=receipt if side_effect is None else None,
                    side_effect=side_effect,
                ),
            ):
                returncode = cli_impl.main(["doctor", "--json"])
            return returncode, json.loads(stdout.getvalue())

        accepted_code, accepted = doctor_with_runtime_verifier()
        self.assertEqual(accepted_code, 0, accepted)
        self.assertEqual(accepted["codex_install_provenance"], receipt)

        for drift in (
            "current wheel RECORD differs from provenance receipt",
            "local installation proof differs from provenance receipt",
            "current local installed wheel mapping differs from provenance receipt",
        ):
            with self.subTest(drift=drift):
                code, payload = doctor_with_runtime_verifier(
                    side_effect=codex_install_provenance_impl.CodexInstallProvenanceError(
                        drift
                    )
                )
                self.assertEqual(code, 1, payload)
                self.assertEqual(payload["codex_install_provenance"], receipt)
                self.assertIn(
                    f"Codex install provenance is invalid: {drift}",
                    payload["errors"],
                )


class BytecodeHygieneTests(HarnessTestCase):
    def test_help_and_version_work_outside_an_aoi_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = self.env.copy()
            env.pop("AOI_ROOT", None)
            version = subprocess.run(
                [sys.executable, "-m", CLI_MODULE, "--version"],
                cwd=directory,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout.strip(), f"AOI {AOI_VERSION}")
            help_result = subprocess.run(
                [sys.executable, "-m", CLI_MODULE, "init-task", "--help"],
                cwd=directory,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("--completion-boundary", help_result.stdout)
            hook_help = subprocess.run(
                [sys.executable, "-m", HOOK_MODULE, "--help"],
                cwd=directory,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(hook_help.returncode, 0, hook_help.stderr)
            self.assertIn("--hook-version", hook_help.stdout)

    def test_clean_status_and_hook_leave_no_bytecode(self) -> None:
        clean_root = self.root / "clean-bytecode-root"
        clean_root.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(clean_root)],
            check=True,
            text=True,
            capture_output=True,
        )

        clean_env = self.env.copy()
        clean_env["AOI_ROOT"] = str(clean_root)
        clean_env["PYTHONPATH"] = str(SRC)
        clean_env.pop("PYTHONDONTWRITEBYTECODE", None)
        clean_env.pop("PYTHONPYCACHEPREFIX", None)

        initialized = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "init", "--project-name", "Bytecode Test"],
            cwd=clean_root,
            env=clean_env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)

        status = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "status", "--json"],
            cwd=clean_root,
            env=clean_env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["root"], str(clean_root.resolve()))

        payload = json.dumps(
            {"hook_event_name": "SubagentStart", "agent_type": "worker"}
        ).encode("utf-8")
        hook = subprocess.run(
            [
                sys.executable,
                "-m",
                HOOK_MODULE,
                "--hook-version",
                "6",
            ],
            cwd=clean_root,
            env=clean_env,
            input=payload,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(
            hook.returncode, 0, hook.stderr.decode("utf-8", "replace")
        )
        json.loads(hook.stdout.decode("utf-8"))

        artifacts = sorted(
            path.relative_to(clean_root).as_posix()
            for path in clean_root.rglob("*")
            if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
        )
        self.assertEqual(artifacts, [])


class HookTests(HarnessTestCase):
    def task_state(self, task_id: str) -> dict:
        return json.loads(
            (
                self.root / ".aoi" / "tasks" / task_id / "state.json"
            ).read_text(encoding="utf-8")
        )

    def create_hook_packet(self, task_id: str, packet_id: str) -> None:
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect one bounded source question under an observed dispatch",
            "--scope",
            "Read-only packet with no harness mutation authority",
            "--deliverable",
            "One evidence-backed conclusion and exact inspected paths",
            "--validation",
            "The parent checks the conclusion against the named source paths",
        )

    def test_schema_v5_manual_dispatch_requires_a_prior_arm(self) -> None:
        task_id = "manual-dispatch-arm-gate"
        packet_id = "manual-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            "/root/posthoc-agent",
            ok=False,
        )
        self.assertIn("requires a prior packet-arm", rejected.stderr)
        self.arm_packet(
            task_id,
            packet_id,
            expected_agent_type="explorer",
            parent_session_id="harness-test-chief",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        expired = self.task_state(task_id)
        attempt = expired["packets"][0]["dispatch_attempts"][0]
        attempt["armed_at"] = (
            dt.datetime.now().astimezone() - dt.timedelta(minutes=2)
        ).isoformat()
        attempt["expires_at"] = (
            dt.datetime.now().astimezone() - dt.timedelta(seconds=1)
        ).isoformat()
        attempt["arm_authority_sha256"] = cli_impl._dispatch_attempt_authority_sha256(
            attempt
        )
        state_path.write_text(
            json.dumps(expired, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        stale = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            "/root/stale-manual-agent",
            ok=False,
        )
        self.assertIn("expired before dispatch", stale.stderr)
        stale_doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(stale_doctor.returncode, 1, stale_doctor.stderr)
        self.assertIn("active dispatch attempt 1 is expired", stale_doctor.stdout)
        self.arm_packet(
            task_id,
            packet_id,
            expected_agent_type="explorer",
            parent_session_id="harness-test-chief",
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            "/root/manual-fallback-agent",
            "--manual-unverified-reason",
            "Trusted hooks were unavailable after the exact packet had been pre-armed",
        )
        state = self.task_state(task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["dispatch_provenance"], "manual_unverified")
        self.assertEqual(packet["dispatch_attempts"][0]["status"], "expired")
        self.assertEqual(packet["dispatch_attempts"][1]["status"], "disarmed")
        self.assertEqual(
            cli_impl.packet_integrity_errors(h.get_paths(self.root), state), []
        )

    def test_unrelated_expired_arm_does_not_pollute_incident_attribution(self) -> None:
        task_id = "expired-arm-attribution"
        packet_id = "expired-explorer"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm_packet(
            task_id,
            packet_id,
            expected_agent_type="explorer",
            parent_session_id="harness-test-chief",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        attempt = state["packets"][0]["dispatch_attempts"][0]
        attempt["armed_at"] = (
            dt.datetime.now().astimezone() - dt.timedelta(minutes=2)
        ).isoformat()
        attempt["expires_at"] = (
            dt.datetime.now().astimezone() - dt.timedelta(seconds=1)
        ).isoformat()
        attempt["arm_authority_sha256"] = cli_impl._dispatch_attempt_authority_sha256(
            attempt
        )
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        output = self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "harness-test-chief",
                "turn_id": "unrelated-expired-arm-turn",
                "agent_id": "/root/unarmed-worker",
                "agent_type": "worker",
            }
        )
        self.assertIn("reason=no_matching_arm", output["hookSpecificOutput"]["additionalContext"])
        incident = self.task_state(task_id)["subagent_incidents"][0]
        self.assertEqual(incident["reason_code"], "no_matching_arm")
        self.assertEqual(incident["candidate_packet_ids"], [])

    def test_subagent_start_consumes_one_prearmed_packet_idempotently(self) -> None:
        task_id = "hook-observed-dispatch"
        packet_id = "observed-explorer"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        expires_at = (dt.datetime.now().astimezone() + dt.timedelta(minutes=5)).isoformat()
        armed = json.loads(
            self.cli(
                "packet-arm",
                "--task",
                task_id,
                "--packet-id",
                packet_id,
                "--expected-agent-type",
                "explorer",
                "--expires-at",
                expires_at,
                "--json",
            ).stdout
        )
        self.assertEqual(armed["status"], "armed")
        self.create_hook_packet(task_id, "colliding-explorer")
        collision = self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            "colliding-explorer",
            "--expected-agent-type",
            "explorer",
            "--expires-at",
            expires_at,
            ok=False,
        )
        self.assertIn("parent-session/agent-type slot", collision.stderr)
        event = {
            "hook_event_name": "SubagentStart",
            "session_id": "harness-test-chief",
            "turn_id": "turn-observed-1",
            "agent_id": "/root/observed-explorer",
            "agent_type": "explorer",
            "permission_mode": "default",
        }
        observed = self.hook(event)
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn(packet_id, context)
        self.assertIn("valid pre-armed dispatch", context)
        state = self.task_state(task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        self.assertEqual(
            packet["dispatch_provenance"], "codex_subagent_start_observed"
        )
        self.assertNotIn("dispatched_at", packet)
        self.assertEqual(
            packet["dispatch_attempts"][0]["observation"]["agent_id"],
            "/root/observed-explorer",
        )
        tampered = copy.deepcopy(state)
        tampered["packets"][0]["agent_id"] = "/root/forged-agent"
        self.assertTrue(
            any(
                "packet/observation binding" in error
                for error in cli_impl.packet_integrity_errors(
                    h.get_paths(self.root), tampered
                )
            )
        )
        revision = state["revision"]
        replay = self.hook(event)
        self.assertIn(packet_id, replay["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.task_state(task_id)["revision"], revision)
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        checkpoint_path = self.root / ".aoi" / "tasks" / task_id / "checkpoint.md"
        invalid_authority = copy.deepcopy(state)
        invalid_authority["packets"][0]["locks"] = [
            "host:tree:C:/PROGRA~1"
        ]
        h.atomic_write_json(state_path, invalid_authority)
        before_state = state_path.read_bytes()
        before_checkpoint = checkpoint_path.read_bytes()
        rejected_checkpoint = self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Reject the ambiguous packet authority before handoff",
            ok=False,
        )
        self.assertIn("non-canonical lock authority", rejected_checkpoint.stderr)
        self.assertEqual(state_path.read_bytes(), before_state)
        self.assertEqual(checkpoint_path.read_bytes(), before_checkpoint)
        corrupt_replay = cli_impl.observe_subagent_start(
            h.get_paths(self.root),
            event,
        )
        self.assertEqual(corrupt_replay["status"], "corrupt")
        self.assertEqual(
            corrupt_replay["reason_code"],
            "packet_authority_invalid",
        )
        corrupt_hook = self.hook(event)
        corrupt_context = corrupt_hook["hookSpecificOutput"]["additionalContext"]
        self.assertIn("packet authority", corrupt_context)
        self.assertIn("packet_authority_invalid", corrupt_context)
        h.atomic_write_json(state_path, state)
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "done",
            "--summary",
            "The observed read-only packet returned its bounded conclusion",
            "--evidence",
            "The result is bound to the consumed SubagentStart observation",
        )
        terminal_state = self.task_state(task_id)
        capacity_record = cli_impl._capacity_records(
            terminal_state, "", "general"
        )[0]
        observed_at = terminal_state["packets"][0]["dispatch_attempts"][0][
            "observation"
        ]["observed_at"]
        self.assertEqual(
            capacity_record["dispatch_provenance"],
            "codex_subagent_start_observed",
        )
        self.assertEqual(capacity_record["dispatch_recorded_at"], observed_at)
        self.assertEqual(capacity_record["subagent_start_observed_at"], observed_at)
        self.assertEqual(capacity_record["orchestration_started_at"], "")
        invalid_done = copy.deepcopy(terminal_state)
        invalid_done["packets"][0]["locks"] = ["host:tree:C:/PROGRA~1"]
        h.atomic_write_json(state_path, invalid_done)
        rejected_attestation = self.cli(
            "packet-attest-result",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--evidence",
            "A result SHA cannot repair ambiguous historical packet authority",
            ok=False,
        )
        self.assertIn("done packet authority", rejected_attestation.stderr)
        active_errors = cli_impl.packet_integrity_errors(
            h.get_paths(self.root),
            invalid_done,
        )
        self.assertTrue(
            any("non-canonical lock authority" in item for item in active_errors),
            active_errors,
        )
        cancelled_view = {**invalid_done, "status": "cancelled"}
        cancelled_errors = cli_impl.packet_integrity_errors(
            h.get_paths(self.root),
            cancelled_view,
        )
        self.assertFalse(
            any("non-canonical lock authority" in item for item in cancelled_errors),
            cancelled_errors,
        )
        h.atomic_write_json(state_path, terminal_state)
        second_start = dict(event)
        second_start["turn_id"] = "turn-observed-2"
        second_start["agent_id"] = "/root/unarmed-second-explorer"
        second = self.hook(second_start)
        self.assertIn(
            "without one valid, unique pre-armed packet",
            second["hookSpecificOutput"]["additionalContext"],
        )
        self.assertEqual(
            self.task_state(task_id)["subagent_incidents"][0]["reason_code"],
            "no_matching_arm",
        )

    def test_packet_role_is_distinct_from_codex_transport_agent_type(self) -> None:
        task_id = "hook-role-transport-separation"
        packet_id = "independent-review"
        arm_help = " ".join(self.cli("packet-arm", "--help").stdout.split())
        self.assertIn("Codex transport agent_type", arm_help)
        self.assertIn("independent of the packet's AOI technical role", arm_help)
        self.init_task(task_id, session_id="harness-test-chief")
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            "reviewer",
            "--model-tier",
            "expert",
            "--objective",
            "Review one bounded change without mutation authority",
            "--scope",
            "Read-only source and test review",
            "--deliverable",
            "Independent findings with exact evidence",
            "--validation",
            "Chief checks every finding against the frozen diff",
        )
        self.arm_packet(
            task_id,
            packet_id,
            expected_agent_type="default",
            parent_session_id="harness-test-chief",
        )
        event = {
            "hook_event_name": "SubagentStart",
            "session_id": "harness-test-chief",
            "turn_id": "reviewer-over-default-transport",
            "agent_id": "/root/independent-review",
            "agent_type": "default",
        }

        output = self.hook(event)
        context = output["hookSpecificOutput"]["additionalContext"]
        state = self.task_state(task_id)
        packet = state["packets"][0]
        attempt = packet["dispatch_attempts"][0]

        self.assertIn("valid pre-armed dispatch", context)
        self.assertIn("Codex transport agent_type=default", context)
        self.assertIn("technical role is defined by the packet contract", context)
        self.assertEqual(packet["agent_role"], "reviewer")
        self.assertEqual(attempt["expected_agent_type"], "default")
        self.assertEqual(attempt["observation"]["agent_type"], "default")

    def test_invalid_done_packet_authority_blocks_close_but_allows_task_cancel(
        self,
    ) -> None:
        task_id = "invalid-done-cancel-recovery"
        packet_id = "observed-result"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm_packet(
            task_id,
            packet_id,
            expected_agent_type="explorer",
            parent_session_id="harness-test-chief",
        )
        event = {
            "hook_event_name": "SubagentStart",
            "session_id": "harness-test-chief",
            "turn_id": "invalid-done-cancel-turn",
            "agent_id": "/root/invalid-done-cancel-worker",
            "agent_type": "explorer",
            "permission_mode": "default",
        }
        self.assertIn(
            "valid pre-armed dispatch",
            self.hook(event)["hookSpecificOutput"]["additionalContext"],
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "done",
            "--summary",
            "The bounded inspection completed before legacy authority was audited",
            "--evidence",
            "The result file and observed dispatch are intact",
        )
        self.add_passing_verification(task_id)
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "none",
            "--detail",
            "Cancellation recovery publishes no code delivery",
        )
        paths = h.get_paths(self.root)
        state_path = paths.tasks / task_id / "state.json"
        tampered = h.load_task(paths, task_id)
        tampered["packets"][0]["packet_mode"] = "bounded_mutation"
        tampered["packets"][0]["locks"] = ["host:tree:C:/PROGRA~1"]
        h.atomic_write_json(state_path, tampered)
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Cancel rather than accept ambiguous done authority",
        )
        rejected_close = self.cli(
            "close-task",
            "--outcome",
            "achieved",
            "--task",
            task_id,
            "--summary",
            "Ambiguous packet authority cannot support achieved closure",
            ok=False,
        )
        self.assertIn("non-canonical lock authority", rejected_close.stderr)
        self.cli(
            "cancel-task",
            "--task",
            task_id,
            "--reason",
            "Archive the invalid historical result without accepting it",
        )
        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertEqual(doctor["errors"], [])
        self.assertTrue(
            any("non-canonical lock authority" in item for item in doctor["warnings"]),
            doctor,
        )

    def test_legacy_task_packet_creation_and_manual_upgrade_set_dispatch_version(self) -> None:
        task_id = "hook-progressive-dispatch-migration"
        packet_id = "legacy-ready-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        state.pop("dispatch_model_version", None)
        state.pop("subagent_incidents", None)
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        self.create_hook_packet(task_id, packet_id)
        state = self.task_state(task_id)
        self.assertEqual(state["dispatch_model_version"], 1)
        self.assertEqual(state["subagent_incidents"], [])

        packet = state["packets"][0]
        packet["packet_schema_version"] = 4
        packet.pop("dispatch_version", None)
        packet.pop("dispatch_provenance", None)
        packet.pop("dispatch_attempts", None)
        state.pop("dispatch_model_version", None)
        state.pop("subagent_incidents", None)
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        downgraded = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            "/root/forged-legacy-packet",
            ok=False,
        )
        self.assertIn("native-v5 contract was downgraded", downgraded.stderr)
        downgraded_doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(downgraded_doctor.returncode, 1, downgraded_doctor.stderr)
        self.assertIn("native-v5 contract was downgraded", downgraded_doctor.stdout)

        state = self.task_state(task_id)
        packet = state["packets"][0]
        contract_path = Path(packet["path"])
        native_block = (
            "\n## AOI dispatch authority\n\n"
            f"{cli_impl.NATIVE_V5_PACKET_CONTRACT_MARKER}\n"
        ).encode("utf-8")
        legacy_contract = contract_path.read_bytes().replace(native_block, b"")
        self.assertNotEqual(legacy_contract, contract_path.read_bytes())
        contract_path.write_bytes(legacy_contract)
        packet["packet_contract_sha256"] = hashlib.sha256(legacy_contract).hexdigest()
        packet.pop("dispatch_schema_origin", None)
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        forged_migration = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            "/root/forged-policy-v2-migration",
            ok=False,
        )
        self.assertIn(
            "schema-v4 migration is forbidden for a native execution-policy task",
            forged_migration.stderr,
        )

        state = self.task_state(task_id)
        state.pop("task_execution_schema_version")
        state.pop("execution_policy_version")
        state["legacy_execution_policy"] = True
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            "/root/manual-legacy-packet",
        )
        migrated = self.task_state(task_id)
        self.assertEqual(migrated["dispatch_model_version"], 1)
        self.assertEqual(migrated["subagent_incidents"], [])
        self.assertEqual(migrated["packets"][0]["packet_schema_version"], 5)
        self.assertEqual(
            migrated["packets"][0]["dispatch_schema_origin"],
            "legacy_v4_migration",
        )
        self.assertEqual(
            cli_impl.subagent_incident_integrity_errors(migrated), []
        )

    def test_hook_keeps_committed_dispatch_context_when_index_refresh_fails(self) -> None:
        task_id = "hook-index-post-commit"
        packet_id = "index-safe-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        expires_at = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--expected-agent-type",
            "explorer",
            "--expires-at",
            expires_at,
        )
        event = {
            "hook_event_name": "SubagentStart",
            "session_id": "harness-test-chief",
            "turn_id": "index-failure-turn",
            "agent_id": "/root/index-safe-packet",
            "agent_type": "explorer",
        }
        with mock.patch.object(
            cli_impl,
            "write_index",
            side_effect=h.HarnessError("unrelated task prevents index rendering"),
        ):
            outcome = cli_impl.observe_subagent_start(h.get_paths(self.root), event)
        self.assertEqual(outcome["status"], "authorized")
        self.assertTrue(outcome["index_refresh_deferred"])
        packet = self.task_state(task_id)["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        self.assertEqual(packet["agent_id"], "/root/index-safe-packet")

    def test_unarmed_subagent_start_records_and_accounts_incident(self) -> None:
        task_id = "hook-unmanaged-dispatch"
        self.init_task(task_id, session_id="harness-test-chief")
        event = {
            "hook_event_name": "SubagentStart",
            "session_id": "harness-test-chief",
            "turn_id": "turn-unmanaged-1",
            "agent_id": "/root/unmanaged-worker",
            "agent_type": "worker",
        }
        output = self.hook(event)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("without one valid, unique pre-armed packet", context)
        state = self.task_state(task_id)
        self.assertEqual(len(state["subagent_incidents"]), 1)
        incident = state["subagent_incidents"][0]
        self.assertEqual(incident["reason_code"], "no_matching_arm")
        self.assertEqual(incident["status"], "open")
        blocked_cancel = self.cli(
            "cancel-task",
            "--task",
            task_id,
            "--reason",
            "An open spawn incident must block cancellation",
            ok=False,
        )
        self.assertIn("unaccounted sub-agent spawn incidents", blocked_cancel.stderr)
        revision = state["revision"]
        self.hook(event)
        self.assertEqual(self.task_state(task_id)["revision"], revision)
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Account the exact unmanaged spawn incident before further work",
        )
        open_checkpoint = (
            self.root / ".aoi" / "tasks" / task_id / "checkpoint.md"
        ).read_text(encoding="utf-8")
        self.assertIn(incident["incident_id"], open_checkpoint)
        critical = json.loads(
            self.cli(
                "status", "--task", task_id, "--critical", "--json"
            ).stdout
        )
        self.assertEqual(
            critical["subagent_spawn_incidents"][0]["incident_id"],
            incident["incident_id"],
        )
        doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "doctor",
                "--task",
                task_id,
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(doctor.returncode, 1, doctor.stderr)
        self.assertIn("open sub-agent spawn incident", doctor.stdout)
        self.cli(
            "subagent-incident-account",
            "--task",
            task_id,
            "--incident-id",
            incident["incident_id"],
            "--disposition",
            "no_material_work",
            "--reason",
            "The hook instructed the unarmed agent to stop before project inspection",
            "--evidence",
            "The repeated identical hook event produced no additional task mutation",
            "--session-id",
            "harness-test-chief",
        )
        accounted = self.task_state(task_id)["subagent_incidents"][0]
        self.assertEqual(accounted["status"], "accounted")
        checkpoint = self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Continue only with pre-armed delegation packets",
        )
        self.assertEqual(checkpoint.returncode, 0)
        checkpoint_text = (
            self.root / ".aoi" / "tasks" / task_id / "checkpoint.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Accounted spawn incidents: 1", checkpoint_text)

    def test_concurrent_subagent_starts_consume_one_arm_only(self) -> None:
        task_id = "hook-concurrent-dispatch"
        packet_id = "single-permit"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        expires_at = (dt.datetime.now().astimezone() + dt.timedelta(minutes=5)).isoformat()
        self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--expected-agent-type",
            "explorer",
            "--expires-at",
            expires_at,
        )
        payloads = [
            {
                "hook_event_name": "SubagentStart",
                "session_id": "harness-test-chief",
                "turn_id": f"concurrent-turn-{index}",
                "agent_id": f"/root/concurrent-{index}",
                "agent_type": "explorer",
            }
            for index in (1, 2)
        ]
        barrier = threading.Barrier(3)
        results: list[subprocess.CompletedProcess[bytes]] = []
        result_lock = threading.Lock()

        def invoke(payload: dict) -> None:
            barrier.wait(timeout=10)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        "from aoi_orgware.codex_hook import dispatch, read_input; "
                        "dispatch(read_input(), project_root=Path.cwd())"
                    ),
                ],
                cwd=self.root,
                env=self.env,
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True,
                check=False,
                timeout=20,
            )
            with result_lock:
                results.append(result)

        threads = [threading.Thread(target=invoke, args=(payload,)) for payload in payloads]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.returncode == 0 for result in results))
        contexts = [
            json.loads(result.stdout.decode("utf-8"))["hookSpecificOutput"][
                "additionalContext"
            ]
            for result in results
        ]
        self.assertEqual(sum("valid pre-armed dispatch" in item for item in contexts), 1)
        self.assertEqual(
            sum("without one valid, unique pre-armed packet" in item for item in contexts),
            1,
        )
        state = self.task_state(task_id)
        self.assertEqual(state["packets"][0]["status"], "dispatched")
        self.assertEqual(len(state["subagent_incidents"]), 1)

    def test_closed_task_unbinds_session(self) -> None:
        self.init_task("closed-hook-task", session_id="closed-session")
        self.cli(
            "set-delivery",
            "--task",
            "closed-hook-task",
            "--mode",
            "none",
            "--detail",
            "cancelled test has no delivery",
        )
        self.cli(
            "cancel-task",
            "--task",
            "closed-hook-task",
            "--reason",
            "test cancellation",
        )
        self.assertFalse(
            h.session_path(h.get_paths(self.root), "closed-session").exists()
        )

    def test_session_subagent_and_stop_hooks(self) -> None:
        self.init_task("hook-task", session_id="session-123")
        start = self.hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "session-123",
                "source": "compact",
            },
            bom=True,
        )
        context = start["hookSpecificOutput"]["additionalContext"]
        self.assertIn("hook-task", context)
        self.assertIn("compaction boundary", context)

        subagent = self.hook(
            {"hook_event_name": "SubagentStart", "agent_type": "explorer"}
        )
        subcontext = subagent["hookSpecificOutput"]["additionalContext"]
        self.assertIn("no task mapping", subcontext)
        self.assertIn("Stop without material work", subcontext)

        blocked = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "session-123",
                "stop_hook_active": False,
            }
        )
        self.assertEqual(blocked["decision"], "block")
        self.cli(
            "checkpoint",
            "--task",
            "hook-task",
            "--next-action",
            "Continue hook verification",
        )
        allowed = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "session-123",
                "stop_hook_active": False,
            }
        )
        self.assertTrue(allowed["continue"])
        self.cli(
            "set-phase",
            "--task",
            "hook-task",
            "--phase",
            "verifying",
        )
        loop_guard = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "session-123",
                "stop_hook_active": True,
            }
        )
        self.assertTrue(loop_guard["continue"])

    def test_unbound_corrupt_and_user_prompt_hooks(self) -> None:
        unbound = self.hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "unbound-1",
                "source": "startup",
            }
        )
        self.assertIn(
            "No unambiguous task mapping",
            unbound["hookSpecificOutput"]["additionalContext"],
        )
        prompt = self.hook(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "unbound-1",
                "turn_id": "turn-1",
                "prompt": "diagnose example project",
            }
        )
        self.assertIn(
            "not bound", prompt["hookSpecificOutput"]["additionalContext"]
        )
        self.assertIn(
            "do not add lifecycle boilerplate",
            prompt["hookSpecificOutput"]["additionalContext"],
        )
        allowed = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "unbound-1",
                "stop_hook_active": False,
            }
        )
        self.assertTrue(allowed["continue"])
        loop_guard = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "unbound-1",
                "stop_hook_active": True,
            }
        )
        self.assertTrue(loop_guard["continue"])

        corrupt_id = "corrupt-1"
        corrupt_path = h.session_path(h.get_paths(self.root), corrupt_id)
        corrupt_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt_path.write_bytes(b"{not-json")
        corrupt_blocked = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": corrupt_id,
                "stop_hook_active": False,
            }
        )
        self.assertEqual(corrupt_blocked["decision"], "block")
        self.assertIn("corrupt", corrupt_blocked["reason"])

        self.init_task("backlink-task", session_id="expected-session")
        expected_path = h.session_path(h.get_paths(self.root), "expected-session")
        wrong_mapping = json.loads(expected_path.read_text(encoding="utf-8"))
        wrong_mapping["session_id"] = "wrong-session"
        wrong_path = h.session_path(h.get_paths(self.root), "wrong-session")
        wrong_path.write_text(json.dumps(wrong_mapping), encoding="utf-8")
        backlink_blocked = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": "wrong-session",
                "stop_hook_active": False,
            }
        )
        self.assertEqual(backlink_blocked["decision"], "block")
        self.assertIn("corrupt", backlink_blocked["reason"])


class ConcurrencyTests(HarnessTestCase):
    def claim_command(self, task: str, token: str, lock: str) -> list[str]:
        return [
            sys.executable,
            "-m", CLI_MODULE,
            "claim",
            "--task",
            task,
            "--token",
            token,
            "--owner",
            task,
            "--kind",
            "TEST",
            "--lock",
            lock,
            "--intent",
            "concurrency test",
            "--validation",
            "process race",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        ]

    def run_pair(self, left: list[str], right: list[str]) -> list[subprocess.CompletedProcess[str]]:
        processes = [
            subprocess.Popen(
                command,
                cwd=self.root,
                env=self.env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for command in (left, right)
        ]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            results.append(
                subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            )
        return results

    def test_concurrent_overlapping_and_disjoint_claims(self) -> None:
        # Targets exist so this race exercises mutual exclusion, not the
        # acquire-time existence gate.
        (self.root / "rtl" / "adfp").mkdir(parents=True)
        (self.root / "rtl" / "adfp" / "a.sv").write_text("module a; endmodule\n", encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "one.md").write_text("one\n", encoding="utf-8")
        (self.root / "docs" / "two.md").write_text("two\n", encoding="utf-8")
        self.init_task("race-a")
        self.init_task("race-b")
        overlapping = self.run_pair(
            self.claim_command("race-a", "race-a-claim", "repo:tree:rtl/adfp"),
            self.claim_command("race-b", "race-b-claim", "repo:file:rtl/adfp/a.sv"),
        )
        self.assertEqual(sorted(result.returncode for result in overlapping), [0, 2])
        self.assertFalse(any("Traceback" in result.stderr for result in overlapping))

        self.init_task("race-c")
        disjoint = self.run_pair(
            self.claim_command("race-c", "race-c-one", "repo:file:docs/one.md"),
            self.claim_command("race-c", "race-c-two", "repo:file:docs/two.md"),
        )
        self.assertEqual([result.returncode for result in disjoint], [0, 0])
        state = json.loads(
            (
                self.root
                / ".aoi"
                / "tasks"
                / "race-c"
                / "state.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(set(state["claims"]), {"race-c-one", "race-c-two"})

if __name__ == "__main__":
    unittest.main(verbosity=2)
