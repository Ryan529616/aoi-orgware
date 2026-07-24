#!/usr/bin/env python3
"""Fast contract tests for the extracted git-plumbing boundary."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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


class GitExecutableBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        executable = shutil.which("git")
        if executable is None:
            self.skipTest("git is required")
        self.git = Path(executable).resolve()

    def _binding(self, path: Path | None = None) -> gp.GitExecutableBinding:
        subject = self.git if path is None else path
        return gp.GitExecutableBinding.create(
            subject,
            subject.stat().st_size,
            hashlib.sha256(subject.read_bytes()).hexdigest(),
        )

    def test_binding_uses_exact_git_and_never_hostile_path_shim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(
                [str(self.git), "-C", str(repo), "init", "-q"],
                check=True,
                capture_output=True,
            )
            hostile = root / "hostile"
            hostile.mkdir()
            marker = root / "hostile-started"
            if os.name == "nt":
                shim = hostile / "git.cmd"
                shim.write_text(
                    f"@echo hostile>{marker}\r\n@exit /b 91\r\n",
                    encoding="utf-8",
                )
            else:
                shim = hostile / "git"
                shim.write_text(
                    f"#!/bin/sh\nprintf hostile > {marker!s}\nexit 91\n",
                    encoding="utf-8",
                )
                shim.chmod(0o700)
            commands: list[list[str]] = []
            environments: list[dict[str, str]] = []
            original_popen = subprocess.Popen

            def observed(command: list[str], *args: object, **kwargs: object) -> object:
                commands.append(list(command))
                environments.append(dict(kwargs["env"]))  # type: ignore[arg-type]
                return original_popen(command, *args, **kwargs)

            environment = {
                **os.environ,
                "PATH": str(hostile) + os.pathsep + os.environ.get("PATH", ""),
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(gp.subprocess, "Popen", side_effect=observed),
                gp.use_git_executable_binding(self._binding()),
            ):
                gp._run_git_bytes_bounded(
                    repo,
                    ("status", "--porcelain"),
                    label="bound Git test",
                )

            self.assertFalse(marker.exists())
            self.assertTrue(commands)
            self.assertTrue(environments)
            self.assertTrue(
                all(
                    os.path.normcase(command[0])
                    == os.path.normcase(str(self.git))
                    for command in commands
                )
            )
            for child_environment in environments:
                self.assertNotIn("GIT_DIR", child_environment)
                self.assertNotIn("GIT_WORK_TREE", child_environment)
                self.assertNotIn("GIT_OBJECT_DIRECTORY", child_environment)
                self.assertNotIn("SSH_AUTH_SOCK", child_environment)
                self.assertEqual(child_environment["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(child_environment["GIT_CONFIG_GLOBAL"], os.devnull)
                self.assertEqual(child_environment["GIT_ATTR_NOSYSTEM"], "1")
                self.assertEqual(child_environment["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_binding_ignores_ambient_repository_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repositories = [root / "victim", root / "other"]
            heads: list[str] = []
            for index, repository in enumerate(repositories):
                repository.mkdir()
                for command in (
                    ("init", "-q"),
                    ("config", "user.email", "test@example.invalid"),
                    ("config", "user.name", "AOI test"),
                ):
                    subprocess.run(
                        [str(self.git), "-C", str(repository), *command],
                        check=True,
                        capture_output=True,
                    )
                (repository / "subject.txt").write_text(
                    f"repository-{index}\n",
                    encoding="utf-8",
                )
                subprocess.run(
                    [str(self.git), "-C", str(repository), "add", "subject.txt"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        str(self.git),
                        "-C",
                        str(repository),
                        "commit",
                        "-qm",
                        f"repository {index}",
                    ],
                    check=True,
                    capture_output=True,
                )
                heads.append(
                    subprocess.run(
                        [str(self.git), "-C", str(repository), "rev-parse", "HEAD"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip()
                )

            ambient = {
                **os.environ,
                "GIT_DIR": str(repositories[1] / ".git"),
                "GIT_WORK_TREE": str(repositories[0]),
                "GIT_OBJECT_DIRECTORY": str(repositories[1] / ".git" / "objects"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
            }
            with (
                mock.patch.dict(os.environ, ambient, clear=True),
                gp.use_git_executable_binding(self._binding()),
            ):
                observed = gp.git_metadata(repositories[0])

            self.assertEqual(observed["head_sha"], heads[0])
            self.assertNotEqual(observed["head_sha"], heads[1])

    def test_binding_revalidates_drift_before_every_popen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / f"git-copy{self.git.suffix}"
            shutil.copy2(self.git, copied)
            binding = self._binding(copied)
            with gp.use_git_executable_binding(binding):
                with copied.open("r+b") as handle:
                    first = handle.read(1)
                    handle.seek(0)
                    handle.write(bytes([first[0] ^ 0xFF]))
                with mock.patch.object(
                    gp.subprocess,
                    "Popen",
                    side_effect=AssertionError("drifted Git must not start"),
                ):
                    with self.assertRaisesRegex(
                        HarnessError,
                        "bytes drifted",
                    ):
                        gp._run_git_bytes_bounded(
                            Path(temporary),
                            ("status",),
                            label="drifted Git test",
                        )

    def test_mutation_observation_rejects_local_fsmonitor_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            for command in (
                ("init", "-q"),
                ("config", "user.email", "test@example.invalid"),
                ("config", "user.name", "AOI test"),
                ("config", "core.autocrlf", "false"),
            ):
                subprocess.run(
                    [str(self.git), "-C", str(repository), *command],
                    check=True,
                    capture_output=True,
                )
            subject = repository / "subject.txt"
            subject.write_text("before\n", encoding="utf-8")
            subprocess.run(
                [str(self.git), "-C", str(repository), "add", "subject.txt"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [str(self.git), "-C", str(repository), "commit", "-qm", "baseline"],
                check=True,
                capture_output=True,
            )
            baseline = subprocess.run(
                [str(self.git), "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            marker = root / "fsmonitor-started"
            if os.name == "nt":
                monitor = root / "fsmonitor.cmd"
                monitor.write_text(
                    f"@echo started>{marker}\r\n@echo token\r\n",
                    encoding="utf-8",
                )
            else:
                monitor = root / "fsmonitor"
                monitor.write_text(
                    f"#!/bin/sh\nprintf started > {marker!s}\nprintf 'token\\n'\n",
                    encoding="utf-8",
                )
                monitor.chmod(0o700)
            subprocess.run(
                [
                    str(self.git),
                    "-C",
                    str(repository),
                    "config",
                    "core.fsmonitor",
                    str(monitor),
                ],
                check=True,
                capture_output=True,
            )
            subject.write_text("after\n", encoding="utf-8")

            with (
                gp.use_git_executable_binding(self._binding()),
                self.assertRaisesRegex(HarnessError, "unapproved key"),
            ):
                gp.task_mutation_snapshot(
                    "task-1",
                    repository,
                    baseline,
                )
            self.assertFalse(marker.exists())

    def test_mutation_observation_rejects_executable_local_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(
                [str(self.git), "-C", str(repository), "init", "-q"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    str(self.git),
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    str(self.git),
                    "-C",
                    str(repository),
                    "config",
                    "user.name",
                    "AOI test",
                ],
                check=True,
                capture_output=True,
            )
            subject = repository / "subject.txt"
            subject.write_text("baseline\n", encoding="utf-8")
            subprocess.run(
                [str(self.git), "-C", str(repository), "add", "subject.txt"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [str(self.git), "-C", str(repository), "commit", "-qm", "baseline"],
                check=True,
                capture_output=True,
            )
            for key, value in (
                ("include.path", "../outside.gitconfig"),
                ("filter.evil.process", "must-not-run"),
                ("core.attributesFile", "../outside.attributes"),
                ("core.excludesFile", "../outside.excludes"),
            ):
                with self.subTest(key=key):
                    subprocess.run(
                        [
                            str(self.git),
                            "-C",
                            str(repository),
                            "config",
                            key,
                            value,
                        ],
                        check=True,
                        capture_output=True,
                    )
                    with self.assertRaisesRegex(HarnessError, "unapproved key"):
                        gp.git_observation_authority(repository)
                    subprocess.run(
                        [
                            str(self.git),
                            "-C",
                            str(repository),
                            "config",
                            "--unset-all",
                            key,
                        ],
                        check=True,
                        capture_output=True,
                    )

    def test_binding_contract_rejects_noncanonical_or_hardlinked_file(self) -> None:
        contract = self._binding().contract()
        self.assertEqual(
            gp.GitExecutableBinding.from_contract(contract).contract(),
            contract,
        )
        with self.assertRaisesRegex(HarnessError, "provenance contract"):
            gp.GitExecutableBinding.from_contract(
                {**contract, "path": contract["path"].replace("/", "\\")}
            )
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / f"git-copy{self.git.suffix}"
            linked = Path(temporary) / f"git-hardlink{self.git.suffix}"
            shutil.copy2(self.git, copied)
            os.link(copied, linked)
            with self.assertRaisesRegex(HarnessError, "non-linked"):
                self._binding(copied)


class _BrokenReadPipe:
    def read(self, _size: int = -1) -> bytes:
        raise OSError("injected pipe read failure")

    def close(self) -> None:
        return None


class _LingeringReadPipe:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def read(self, _size: int = -1) -> bytes:
        self.closed.wait()
        return b""

    def close(self) -> None:
        self.closed.set()


class _PipeProcess:
    def __init__(self, stdout: object, stderr: object) -> None:
        self.stdout = stdout
        self.stderr = stderr

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        return None


class GitBoundedRunnerTests(unittest.TestCase):
    def test_pipe_read_error_fails_closed(self) -> None:
        process = _PipeProcess(_BrokenReadPipe(), io.BytesIO())
        with (
            mock.patch.object(gp.subprocess, "Popen", return_value=process),
            self.assertRaisesRegex(HarnessError, "output reader failed"),
        ):
            gp._run_git_command_bytes_bounded(
                ["git", "version"],
                environment={},
                label="reader failure",
            )

    def test_lingering_inherited_pipe_cannot_defeat_timeout(self) -> None:
        process = _PipeProcess(_LingeringReadPipe(), io.BytesIO())
        with (
            mock.patch.object(gp.subprocess, "Popen", return_value=process),
            mock.patch.object(gp, "GIT_READER_JOIN_TIMEOUT_SECONDS", 0.01),
            self.assertRaisesRegex(HarnessError, "output reader failed"),
        ):
            gp._run_git_command_bytes_bounded(
                ["git", "version"],
                environment={},
                label="lingering pipe",
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

    def _mktag(self, *, target: str, target_type: str, tag: str) -> str:
        payload = (
            f"object {target}\n"
            f"type {target_type}\n"
            f"tag {tag}\n"
            "tagger Test User <test@example.invalid> 0 +0000\n"
            "\n"
            "release\n"
        )
        return subprocess.run(
            ["git", "-C", str(self.repo), "mktag"],
            input=payload.encode("ascii"),
            check=True,
            capture_output=True,
        ).stdout.decode("ascii", "strict").strip()

    def test_local_annotated_tag_snapshot_rejects_lightweight_tag(self) -> None:
        self._git("tag", "lightweight-v1", self.baseline)
        with self.assertRaisesRegex(HarnessError, "annotated tag object"):
            gp.local_annotated_tag_snapshot(
                self.repo, "refs/tags/lightweight-v1"
            )

        self._git("tag", "-a", "v1.0.0", "-m", "release", self.baseline)
        snapshot = gp.local_annotated_tag_snapshot(
            self.repo, "refs/tags/v1.0.0"
        )
        self.assertEqual(snapshot["peeled_commit_oid"], self.baseline)
        self.assertNotEqual(snapshot["tag_object_oid"], self.baseline)

    def test_local_annotated_tag_snapshot_normalizes_non_ascii_failure(self) -> None:
        with mock.patch.object(
            gp, "_run_git_bytes_bounded", return_value=b"\xff"
        ):
            with self.assertRaisesRegex(HarnessError, "not ASCII"):
                gp.local_annotated_tag_snapshot(
                    self.repo, "refs/tags/v1.0.0"
                )

    def test_local_annotated_tag_snapshot_rejects_wrong_embedded_name(self) -> None:
        tag_object = self._mktag(
            target=self.baseline,
            target_type="commit",
            tag="another-name",
        )
        self._git("update-ref", "refs/tags/v1.0.0", tag_object)
        with self.assertRaisesRegex(HarnessError, "direct annotated tag object"):
            gp.local_annotated_tag_snapshot(
                self.repo, "refs/tags/v1.0.0"
            )

    def test_local_annotated_tag_snapshot_rejects_tag_of_tag(self) -> None:
        self._git("tag", "-a", "inner", "-m", "inner", self.baseline)
        inner = self._git("rev-parse", "refs/tags/inner").strip()
        outer = self._mktag(
            target=inner,
            target_type="tag",
            tag="v1.0.0",
        )
        self._git("update-ref", "refs/tags/v1.0.0", outer)
        with self.assertRaisesRegex(HarnessError, "direct annotated tag object"):
            gp.local_annotated_tag_snapshot(
                self.repo, "refs/tags/v1.0.0"
            )

    def test_transport_config_audit_removes_only_its_first_synthetic_pins(
        self,
    ) -> None:
        system_config = self.repo / "duplicate-system.gitconfig"
        audit_identity = f"aoi-audit://{'a' * 64}"
        alias = f"aoi-transport://{'b' * 64}"
        self._git(
            "config",
            "--file",
            str(system_config),
            "--add",
            f"url.{audit_identity}.insteadOf",
            alias,
        )
        self._git(
            "config",
            "--file",
            str(system_config),
            "--add",
            f"url.{audit_identity}.pushInsteadOf",
            alias,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"GIT_CONFIG_SYSTEM": str(system_config)},
                clear=False,
            ),
            mock.patch.object(
                gp.secrets,
                "token_hex",
                side_effect=("a" * 64, "b" * 64),
            ),
        ):
            raw = gp._git_transport_config_audit_bytes(
                self.repo,
                label="test Git transport config audit",
            )

        records = [record for record in raw.split(b"\x00") if record]
        self.assertEqual(
            records.count(
                f"url.{audit_identity}.insteadof\n{alias}".encode("ascii")
            ),
            1,
        )
        self.assertEqual(
            records.count(
                f"url.{audit_identity}.pushinsteadof\n{alias}".encode("ascii")
            ),
            1,
        )

    def test_remote_annotated_tag_snapshot_requires_exact_peeled_tag(
        self,
    ) -> None:
        remote = self.repo / "remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(remote)],
            check=True,
            capture_output=True,
        )
        self._git("remote", "add", "origin", str(remote))
        with self.assertRaises(HarnessError):
            gp.remote_annotated_tag_snapshot(
                self.repo, str(remote), "refs/tags/v1.0.0"
            )

        self._git("tag", "-a", "v1.0.0", "-m", "release", self.baseline)
        self._git("push", "-q", "origin", "refs/tags/v1.0.0")
        local = gp.local_annotated_tag_snapshot(
            self.repo, "refs/tags/v1.0.0"
        )
        remote_snapshot = gp.remote_annotated_tag_snapshot(
            self.repo, str(remote), "refs/tags/v1.0.0"
        )
        self.assertEqual(remote_snapshot, local)

        self._git("tag", "lightweight-v2", self.baseline)
        self._git("push", "-q", "origin", "refs/tags/lightweight-v2")
        with self.assertRaisesRegex(
            HarnessError, "lightweight|annotated"
        ):
            gp.remote_annotated_tag_snapshot(
                self.repo, str(remote), "refs/tags/lightweight-v2"
            )

    def test_remote_release_advertisement_uses_one_exact_pinned_query(
        self,
    ) -> None:
        transport = "https://example.invalid/owner/repo.git"
        tag_ref = "refs/tags/v1.0.0"
        raw = (
            f"{self.baseline}\trefs/heads/main\n"
            f"{'b' * 40}\t{tag_ref}\n"
            f"{self.baseline}\t{tag_ref}^{{}}\n"
        ).encode("ascii")
        guard_calls: list[str] = []
        with (
            mock.patch.object(
                gp, "_run_git_bytes_bounded", return_value=raw
            ) as runner,
            mock.patch.object(
                gp,
                "_direct_annotated_tag_metadata",
                return_value={
                    "tag_ref": tag_ref,
                    "tag_object_oid": "b" * 40,
                    "peeled_commit_oid": self.baseline,
                },
            ),
        ):
            snapshot = gp.remote_release_advertisement_snapshot(
                self.repo,
                transport,
                tag_ref,
                tag_state="tag_present",
                before_network=lambda: guard_calls.append("called"),
            )
        self.assertEqual(guard_calls, ["called"])
        self.assertEqual(snapshot["remote_main_oid"], self.baseline)
        self.assertEqual(snapshot["tag_peeled_commit_oid"], self.baseline)
        self.assertEqual(snapshot["tag_object_oid"], "b" * 40)
        self.assertEqual(
            runner.call_args.args[1],
            (
                "ls-remote",
                "--exit-code",
                "--",
                transport,
                "refs/heads/main",
                tag_ref,
                f"{tag_ref}^{{}}",
            ),
        )
        self.assertEqual(
            runner.call_args.kwargs["transport_identity"], transport
        )

    def test_remote_release_advertisement_accepts_sha1_and_sha256(
        self,
    ) -> None:
        tag_ref = "refs/tags/v1.0.0"
        for oid_length in (40, 64):
            with self.subTest(oid_length=oid_length):
                main = "a" * oid_length
                raw = (
                    f"{main}\trefs/heads/main\n"
                    f"{'b' * oid_length}\t{tag_ref}\n"
                    f"{main}\t{tag_ref}^{{}}\n"
                ).encode("ascii")
                snapshot = gp._parse_remote_release_advertisement(
                    raw,
                    push_transport="https://example.invalid/repo.git",
                    tag_ref=tag_ref,
                    tag_state="tag_present",
                )
                self.assertEqual(snapshot["remote_main_oid"], main)
                self.assertEqual(
                    gp.validate_remote_release_advertisement_snapshot(
                        snapshot,
                        expected_tag_state="tag_present",
                        expected_push_transport=(
                            "https://example.invalid/repo.git"
                        ),
                        expected_tag_ref=tag_ref,
                    ),
                    snapshot,
                )

    def test_remote_release_preflight_requires_main_and_tag_absence(
        self,
    ) -> None:
        tag_ref = "refs/tags/v1.0.0"
        main = "a" * 40
        snapshot = gp._parse_remote_release_advertisement(
            f"{main}\trefs/heads/main\n".encode("ascii"),
            push_transport="https://example.invalid/repo.git",
            tag_ref=tag_ref,
            tag_state="tag_absent",
        )
        self.assertEqual(snapshot["remote_main_oid"], main)
        self.assertIsNone(snapshot["tag_object_oid"])
        with self.assertRaisesRegex(HarnessError, "requires.*absent tag"):
            gp._parse_remote_release_advertisement(
                (
                    f"{main}\trefs/heads/main\n"
                    f"{'b' * 40}\t{tag_ref}\n"
                ).encode("ascii"),
                push_transport="https://example.invalid/repo.git",
                tag_ref=tag_ref,
                tag_state="tag_absent",
            )

    def test_remote_release_advertisement_parser_fails_closed(self) -> None:
        tag_ref = "refs/tags/v1.0.0"
        main = "a" * 40
        tag = "b" * 40
        peeled = f"{tag_ref}^{{}}"
        fixtures = {
            "missing": (
                f"{main}\trefs/heads/main\n"
                f"{tag}\t{tag_ref}\n"
            ).encode("ascii"),
            "duplicate": (
                f"{main}\trefs/heads/main\n"
                f"{main}\trefs/heads/main\n"
                f"{tag}\t{tag_ref}\n"
                f"{main}\t{peeled}\n"
            ).encode("ascii"),
            "unexpected": (
                f"{main}\trefs/heads/main\n"
                f"{tag}\t{tag_ref}\n"
                f"{main}\t{peeled}\n"
                f"{main}\trefs/heads/other\n"
            ).encode("ascii"),
            "malformed": (
                f"{main} refs/heads/main\n"
                f"{tag}\t{tag_ref}\n"
                f"{main}\t{peeled}\n"
            ).encode("ascii"),
            "uppercase": (
                f"{'A' * 40}\trefs/heads/main\n"
                f"{tag}\t{tag_ref}\n"
                f"{main}\t{peeled}\n"
            ).encode("ascii"),
            "mixed-object-format": (
                f"{main}\trefs/heads/main\n"
                f"{'b' * 64}\t{tag_ref}\n"
                f"{main}\t{peeled}\n"
            ).encode("ascii"),
            "main-tag-mismatch": (
                f"{main}\trefs/heads/main\n"
                f"{tag}\t{tag_ref}\n"
                f"{'c' * 40}\t{peeled}\n"
            ).encode("ascii"),
        }
        for label, raw in fixtures.items():
            with self.subTest(label=label):
                with self.assertRaises(HarnessError):
                    gp._parse_remote_release_advertisement(
                        raw,
                        push_transport="https://example.invalid/repo.git",
                        tag_ref=tag_ref,
                        tag_state="tag_present",
                    )

    def test_remote_release_advertisement_rejects_stale_correlation(self) -> None:
        snapshot = gp._parse_remote_release_advertisement(
            f"{'a' * 40}\trefs/heads/main\n".encode("ascii"),
            push_transport="https://example.invalid/repo.git",
            tag_ref="refs/tags/v1.0.0",
            tag_state="tag_absent",
        )
        for kwargs, message in (
            (
                {"expected_tag_state": "tag_present"},
                "tag state is stale",
            ),
            (
                {
                    "expected_push_transport": (
                        "https://attacker.invalid/repo.git"
                    )
                },
                "endpoint is stale",
            ),
            (
                {"expected_tag_ref": "refs/tags/v2.0.0"},
                "tag ref is stale",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(HarnessError, message):
                    gp.validate_remote_release_advertisement_snapshot(
                        snapshot, **kwargs
                    )

    def test_remote_tag_snapshot_identity_pin_overrides_local_and_ambient_rewrites(
        self,
    ) -> None:
        exact_root = self.repo / "exact-root"
        alternate_root = self.repo / "alternate-root"
        exact_remote = exact_root / "release.git"
        alternate_remote = alternate_root / "release.git"
        exact_root.mkdir()
        alternate_root.mkdir()
        for remote in (exact_remote, alternate_remote):
            subprocess.run(
                ["git", "init", "--bare", "-q", str(remote)],
                check=True,
                capture_output=True,
            )
        transport = exact_remote.as_posix()
        lower_scope = exact_root.as_posix() + "/"
        alternate_scope = alternate_root.as_posix() + "/"
        self._git("tag", "-a", "v1.0.0", "-m", "release", self.baseline)
        self._git("push", "-q", transport, "refs/tags/v1.0.0")
        expected = gp.local_annotated_tag_snapshot(self.repo, "refs/tags/v1.0.0")

        # A lower-scope local rewrite can redirect both ordinary fetch and push
        # transports to the alternate bare repository.
        self._git(
            "config",
            "--local",
            f"url.{alternate_scope}.insteadOf",
            lower_scope,
        )
        self._git(
            "config",
            "--local",
            f"url.{alternate_scope}.pushInsteadOf",
            lower_scope,
        )
        self._git("tag", "-a", "push-rewrite-probe", "-m", "probe", self.baseline)
        self._git("push", "-q", transport, "refs/tags/push-rewrite-probe")
        alternate_probe = subprocess.run(
            [
                "git",
                "--git-dir",
                str(alternate_remote),
                "show-ref",
                "--verify",
                "refs/tags/push-rewrite-probe",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(alternate_probe.returncode, 0)
        exact_probe = subprocess.run(
            [
                "git",
                "--git-dir",
                str(exact_remote),
                "show-ref",
                "--verify",
                "refs/tags/push-rewrite-probe",
            ],
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(exact_probe.returncode, 0)

        # The release runbook puts one unguessable full alias in the earliest
        # system config scope for the actual create-only tag push.  Even an
        # equal-length local rule must lose the traversal tie to that pin.
        self._git("tag", "-a", "pinned-push-probe", "-m", "probe", self.baseline)
        push_alias = "aoi-transport://runbook-pinned-push-probe"
        push_config = self.repo / "runbook-system.gitconfig"
        self._git(
            "config",
            "--file",
            str(push_config),
            "--add",
            f"url.{transport}.insteadOf",
            push_alias,
        )
        self._git(
            "config",
            "--file",
            str(push_config),
            "--add",
            f"url.{transport}.pushInsteadOf",
            push_alias,
        )
        self._git(
            "config",
            "--local",
            f"url.{alternate_scope}.insteadOf",
            push_alias,
        )
        self._git(
            "config",
            "--local",
            f"url.{alternate_scope}.pushInsteadOf",
            push_alias,
        )
        pinned_push_env = os.environ.copy()
        for name in tuple(pinned_push_env):
            normalized = name.upper()
            if (
                normalized
                in {
                    "GIT_CONFIG_COUNT",
                    "GIT_CONFIG_NOSYSTEM",
                    "GIT_CONFIG_PARAMETERS",
                    "GIT_CONFIG_SYSTEM",
                }
                or normalized.startswith("GIT_CONFIG_KEY_")
                or normalized.startswith("GIT_CONFIG_VALUE_")
            ):
                pinned_push_env.pop(name)
        pinned_push_env["GIT_CONFIG_SYSTEM"] = str(push_config)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "push",
                "-q",
                "--force-with-lease=refs/tags/pinned-push-probe:",
                "--",
                push_alias,
                "refs/tags/pinned-push-probe",
            ],
            env=pinned_push_env,
            check=True,
            capture_output=True,
        )
        pinned_exact_probe = subprocess.run(
            [
                "git",
                "--git-dir",
                str(exact_remote),
                "show-ref",
                "--verify",
                "refs/tags/pinned-push-probe",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(pinned_exact_probe.returncode, 0)
        pinned_alternate_probe = subprocess.run(
            [
                "git",
                "--git-dir",
                str(alternate_remote),
                "show-ref",
                "--verify",
                "refs/tags/pinned-push-probe",
            ],
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(pinned_alternate_probe.returncode, 0)

        # Ambient command-scope config is untrusted input too.  Inject an
        # equal-length local alias rule after the isolated pin exists but
        # immediately before ls-remote starts; the system-scope pin must win.
        with mock.patch.dict(
            os.environ,
            {
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": f"url.{alternate_scope}.insteadOf",
                "GIT_CONFIG_VALUE_0": lower_scope,
                "GIT_CONFIG_KEY_1": f"url.{alternate_scope}.pushInsteadOf",
                "GIT_CONFIG_VALUE_1": lower_scope,
            },
            clear=False,
        ):
            original_popen = subprocess.Popen
            injected_aliases: list[str] = []

            def inject_equal_alias_rule(
                command: object, *args: object, **kwargs: object
            ) -> subprocess.Popen[bytes]:
                words = list(command)  # type: ignore[arg-type]
                if "ls-remote" in words:
                    alias = next(
                        word
                        for word in words
                        if isinstance(word, str)
                        and word.startswith("aoi-transport://")
                    )
                    injected_aliases.append(alias)
                    self._git(
                        "config",
                        "--local",
                        f"url.{alternate_scope}.insteadOf",
                        alias,
                    )
                return original_popen(words, *args, **kwargs)

            with mock.patch.object(
                subprocess, "Popen", side_effect=inject_equal_alias_rule
            ):
                observed = gp.remote_annotated_tag_snapshot(
                    self.repo, transport, "refs/tags/v1.0.0"
                )
        self.assertEqual(observed, expected)
        self.assertEqual(len(injected_aliases), 1)

    def test_release_tag_snapshots_reject_noncanonical_ref_and_destination(
        self,
    ) -> None:
        with self.assertRaisesRegex(HarnessError, "tag ref is invalid"):
            gp.local_annotated_tag_snapshot(self.repo, "v1.0.0")
        with self.assertRaisesRegex(HarnessError, "transport destination"):
            gp.remote_annotated_tag_snapshot(
                self.repo, " bad remote", "refs/tags/v1.0.0"
            )

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

        snapshot = gp.task_mutation_snapshot(
            self.TASK_ID,
            self.repo,
            self.baseline,
            require_standalone_observation_authority=True,
        )

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

    def test_legacy_v2_snapshot_remains_readable(self) -> None:
        (self.repo / "base.txt").write_bytes(b"legacy snapshot\n")
        current = gp.task_mutation_snapshot(
            self.TASK_ID,
            self.repo,
            self.baseline,
            require_standalone_observation_authority=True,
        )
        legacy = dict(current)
        legacy["schema"] = gp.LEGACY_GIT_MUTATION_SNAPSHOT_SCHEMA
        legacy.pop("observation_authority_sha256")
        legacy.pop("snapshot_sha256")
        legacy["snapshot_sha256"] = hashlib.sha256(
            gp._canonical_json_bytes(legacy)
        ).hexdigest()

        task_id, paths = gp.validate_task_mutation_snapshot(legacy)

        self.assertEqual(task_id, self.TASK_ID)
        self.assertEqual(paths, [b"base.txt"])

    def test_default_snapshot_retains_existing_v3_bytes_in_standalone_repo(
        self,
    ) -> None:
        (self.repo / "base.txt").write_bytes(b"authority snapshot\n")

        default = gp.task_mutation_snapshot(
            self.TASK_ID,
            self.repo,
            self.baseline,
        )
        strict = gp.task_mutation_snapshot(
            self.TASK_ID,
            self.repo,
            self.baseline,
            require_standalone_observation_authority=True,
        )

        self.assertEqual(default, strict)
        self.assertEqual(default["schema"], gp.GIT_MUTATION_SNAPSHOT_SCHEMA)
        self.assertRegex(default["observation_authority_sha256"], r"^[0-9a-f]{64}$")

    def test_snapshot_rejects_gitlink_index_entry(self) -> None:
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.baseline},nested-repository",
        )

        with self.assertRaisesRegex(HarnessError, "gitlink"):
            gp.task_mutation_snapshot(
                self.TASK_ID,
                self.repo,
                self.baseline,
            )

    def test_closed_observation_ignores_ambient_git_config(self) -> None:
        (self.repo / "base.txt").write_bytes(b"ambient-independent\n")
        marker = (
            self.repo.parent
            / f"{self.repo.name}-ambient-fsmonitor-started"
        )
        hostile = {
            **os.environ,
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.autocrlf",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": str(marker),
        }
        with mock.patch.dict(os.environ, hostile, clear=True):
            first = gp.task_mutation_snapshot(
                self.TASK_ID,
                self.repo,
                self.baseline,
            )
        clean = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("GIT_")
        }
        with mock.patch.dict(os.environ, clean, clear=True):
            second = gp.task_mutation_snapshot(
                self.TASK_ID,
                self.repo,
                self.baseline,
            )

        self.assertEqual(first, second)
        self.assertFalse(marker.exists())

    def test_observation_authority_rejects_alternate_history_paths(self) -> None:
        for relative, as_directory in (
            ("info/grafts", False),
            ("objects/info/alternates", False),
            ("objects/info/http-alternates", False),
            ("shallow", False),
            ("refs/replace", True),
        ):
            with self.subTest(relative=relative):
                candidate = self.repo / ".git" / Path(relative)
                candidate.parent.mkdir(parents=True, exist_ok=True)
                if as_directory:
                    candidate.mkdir()
                else:
                    candidate.write_text("../outside\n", encoding="utf-8")
                try:
                    with self.assertRaisesRegex(HarnessError, "forbidden"):
                        gp.git_observation_authority(self.repo)
                finally:
                    if as_directory:
                        candidate.rmdir()
                    else:
                        candidate.unlink()

    def test_observation_authority_rejects_real_split_index(self) -> None:
        self._git("update-index", "--split-index")
        shared_indexes = list((self.repo / ".git").glob("sharedindex.*"))
        self.assertTrue(shared_indexes)
        with self.assertRaisesRegex(HarnessError, "split index authority"):
            gp.git_observation_authority(self.repo)

    def test_observation_authority_rejects_worktree_alias(self) -> None:
        alias = self.repo.parent / f"{self.repo.name}-alias"
        linked = False
        try:
            if os.name == "nt":
                completed = subprocess.run(
                    [
                        "cmd",
                        "/c",
                        "mklink",
                        "/J",
                        str(alias),
                        str(self.repo),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode != 0:
                    self.skipTest("Windows junction creation is unavailable")
            else:
                os.symlink(self.repo, alias, target_is_directory=True)
            linked = True
            with self.assertRaisesRegex(HarnessError, "non-reparse directory"):
                gp.git_observation_authority(alias)
        finally:
            if linked:
                if os.name == "nt":
                    alias.rmdir()
                else:
                    alias.unlink()

    def test_observation_authority_rejects_linked_worktree(self) -> None:
        linked = self.repo.parent / f"{self.repo.name}-linked"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        try:
            with self.assertRaisesRegex(HarnessError, r"\.git"):
                gp.git_observation_authority(linked, require_standalone=True)
        finally:
            self._git("worktree", "remove", "--force", str(linked))

    def test_v3_snapshot_supports_linked_worktree_but_bridge_strict_refuses(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-authority-linked"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        try:
            (linked / "base.txt").write_bytes(b"linked mutation\n")
            authority = gp.git_observation_authority(linked)
            self.assertEqual(authority["layout"], "linked_worktree")
            self.assertEqual(
                Path(authority["common_git_dir"]),
                (self.repo / ".git").resolve(),
            )
            snapshot = gp.task_mutation_snapshot(
                self.TASK_ID,
                linked,
                self.baseline,
            )
            self.assertEqual(snapshot["schema"], gp.GIT_MUTATION_SNAPSHOT_SCHEMA)
            self.assertRegex(
                snapshot["observation_authority_sha256"],
                r"^[0-9a-f]{64}$",
            )
            with self.assertRaisesRegex(HarnessError, r"\.git"):
                gp.task_mutation_snapshot(
                    self.TASK_ID,
                    linked,
                    self.baseline,
                    require_standalone_observation_authority=True,
                )
        finally:
            self._git("worktree", "remove", "--force", str(linked))

    def test_linked_worktree_authority_rejects_common_executable_config(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-config-linked"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        try:
            for key, value in (
                ("filter.evil.process", "must-not-run"),
                ("include.path", "../outside.gitconfig"),
                ("includeIf.onbranch:main.path", "../outside.gitconfig"),
                ("extensions.worktreeConfig", "true"),
            ):
                with self.subTest(key=key):
                    self._git("config", key, value)
                    try:
                        with self.assertRaisesRegex(HarnessError, "unapproved key"):
                            gp.task_mutation_snapshot(
                                self.TASK_ID,
                                linked,
                                self.baseline,
                            )
                    finally:
                        self._git("config", "--unset-all", key)
        finally:
            self._git("worktree", "remove", "--force", str(linked))

    def test_linked_worktree_authority_rejects_metadata_tampering(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-metadata-linked"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        git_file = linked / ".git"
        git_file_bytes = git_file.read_bytes()
        git_dir_text = git_file_bytes.decode("utf-8").strip()
        self.assertTrue(git_dir_text.startswith("gitdir: "))
        git_dir = Path(git_dir_text[len("gitdir: ") :])
        commondir = git_dir / "commondir"
        backlink = git_dir / "gitdir"
        commondir_bytes = commondir.read_bytes()
        backlink_bytes = backlink.read_bytes()
        try:
            cases = [
                (commondir, b".\n", "linked-worktree registry"),
                (backlink, str(self.repo / ".git").encode("utf-8") + b"\n", "back-reference"),
            ]
            if os.name != "nt":
                cases.insert(
                    0,
                    (git_file, b"gitdir: missing-authority\n", "resolve"),
                )
            for path, replacement, message in cases:
                with self.subTest(path=path.name):
                    original = path.read_bytes()
                    path.write_bytes(replacement)
                    try:
                        with self.assertRaisesRegex(HarnessError, message):
                            gp.git_observation_authority(linked)
                    finally:
                        path.write_bytes(original)

            hardlink = self.repo.parent / f"{self.repo.name}-metadata-hardlink"
            try:
                os.link(commondir, hardlink)
            except OSError as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")
            try:
                with self.assertRaisesRegex(HarnessError, "non-linked"):
                    gp.git_observation_authority(linked)
            finally:
                hardlink.unlink(missing_ok=True)
        finally:
            if os.name != "nt":
                git_file.write_bytes(git_file_bytes)
            commondir.write_bytes(commondir_bytes)
            backlink.write_bytes(backlink_bytes)
            self._git("worktree", "remove", "--force", str(linked))

    def test_linked_worktree_authority_digest_tracks_allowed_common_config(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-config-drift-linked"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        original = self._git("config", "user.name").strip()
        try:
            before = gp.git_observation_authority(linked)
            self._git("config", "user.name", "AOI authority drift")
            after = gp.git_observation_authority(linked)
            self.assertNotEqual(
                before["authority_sha256"],
                after["authority_sha256"],
            )
        finally:
            self._git("config", "user.name", original)
            self._git("worktree", "remove", "--force", str(linked))

    def test_linked_worktree_authority_rejects_per_worktree_config(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-worktree-config-linked"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        git_file = linked / ".git"
        git_dir_text = git_file.read_text(encoding="utf-8").strip()
        self.assertTrue(git_dir_text.startswith("gitdir: "))
        git_dir = Path(git_dir_text[len("gitdir: ") :])
        config_worktree = git_dir / "config.worktree"
        try:
            config_worktree.write_text(
                "[filter \"evil\"]\n\tprocess = must-not-run\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(HarnessError, "config.worktree"):
                gp.git_observation_authority(linked)
        finally:
            config_worktree.unlink(missing_ok=True)
            self._git("worktree", "remove", "--force", str(linked))

    def test_linked_worktree_authority_rejects_linked_ref_hardlink(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-linked-ref-hardlink"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        git_dir_text = (linked / ".git").read_text(encoding="utf-8").strip()
        self.assertTrue(git_dir_text.startswith("gitdir: "))
        git_dir = Path(git_dir_text[len("gitdir: ") :])
        subject = git_dir / "refs" / "aoi-test-ref"
        hardlink = self.repo.parent / f"{self.repo.name}-linked-ref-hardlink-copy"
        try:
            subject.write_text(self.baseline + "\n", encoding="ascii")
            try:
                os.link(subject, hardlink)
            except OSError as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")
            with self.assertRaisesRegex(HarnessError, "hard-linked"):
                gp.git_observation_authority(linked)
        finally:
            hardlink.unlink(missing_ok=True)
            subject.unlink(missing_ok=True)
            self._git("worktree", "remove", "--force", str(linked))

    def test_linked_worktree_authority_rejects_linked_ref_reparse(
        self,
    ) -> None:
        linked = self.repo.parent / f"{self.repo.name}-linked-ref-reparse"
        outside = self.repo.parent / f"{self.repo.name}-linked-ref-outside"
        self._git(
            "worktree",
            "add",
            "--detach",
            str(linked),
            self.baseline,
        )
        git_dir_text = (linked / ".git").read_text(encoding="utf-8").strip()
        self.assertTrue(git_dir_text.startswith("gitdir: "))
        git_dir = Path(git_dir_text[len("gitdir: ") :])
        subject = git_dir / "refs" / "aoi-test-reparse"
        outside.mkdir()
        created = False
        try:
            if os.name == "nt":
                completed = subprocess.run(
                    [
                        "cmd",
                        "/c",
                        "mklink",
                        "/J",
                        str(subject),
                        str(outside),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if completed.returncode != 0:
                    self.skipTest("Windows junction creation is unavailable")
            else:
                os.symlink(outside, subject, target_is_directory=True)
            created = True
            with self.assertRaisesRegex(HarnessError, "link or reparse"):
                gp.git_observation_authority(linked)
        finally:
            if created:
                if os.name == "nt":
                    subject.rmdir()
                else:
                    subject.unlink()
            outside.rmdir()
            self._git("worktree", "remove", "--force", str(linked))

    def test_observation_authority_rejects_redirected_objects_and_refs(
        self,
    ) -> None:
        for name in ("objects", "refs"):
            with self.subTest(name=name):
                subject = self.repo / ".git" / name
                outside = (
                    self.repo.parent / f"{self.repo.name}-outside-{name}"
                )
                shutil.move(str(subject), str(outside))
                linked = False
                try:
                    if os.name == "nt":
                        completed = subprocess.run(
                            [
                                "cmd",
                                "/c",
                                "mklink",
                                "/J",
                                str(subject),
                                str(outside),
                            ],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=False,
                        )
                        if completed.returncode != 0:
                            self.skipTest(
                                "Windows junction creation is unavailable"
                            )
                    else:
                        os.symlink(outside, subject, target_is_directory=True)
                    linked = True
                    with self.assertRaisesRegex(
                        HarnessError,
                        "non-reparse directory",
                    ):
                        gp.git_observation_authority(self.repo)
                finally:
                    if linked:
                        if os.name == "nt":
                            subject.rmdir()
                        else:
                            subject.unlink()
                    shutil.move(str(outside), str(subject))

    def test_observation_authority_rejects_linked_head_and_index(self) -> None:
        for name in ("HEAD", "index"):
            with self.subTest(name=name):
                subject = self.repo / ".git" / name
                linked = (
                    self.repo.parent / f"{self.repo.name}-hardlinked-{name}"
                )
                try:
                    os.link(subject, linked)
                except OSError as exc:
                    self.skipTest(f"hardlink creation unavailable: {exc}")
                try:
                    with self.assertRaisesRegex(
                        HarnessError,
                        "regular non-linked file",
                    ):
                        gp.git_observation_authority(self.repo)
                finally:
                    linked.unlink()

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
