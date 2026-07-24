#!/usr/bin/env python3
"""CLI and CAS integration tests for exact-source test receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import exact_test_receipts as receipts  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import semantic_store as semantic_store_impl  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class ExactTestReceiptCliTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.task_id = "exact-test-evidence"
        self.cli(
            "init-task",
            "--task-id",
            self.task_id,
            "--title",
            "Task exact-test-evidence",
            "--objective",
            "Exercise exact-test receipt CAS and semantic anchoring",
            "--owner",
            "test-root",
            "--completion-boundary",
            "All requested test evidence is accounted",
            "--semantic-v2",
            "--semantic-command-id",
            "init-exact-test-evidence-v1",
        )
        self.external = Path(self.backup_temp.name) / "exact-test-fixtures"
        self.external.mkdir()

    @property
    def state_path(self) -> Path:
        return (
            self.root
            / ".aoi"
            / "tasks"
            / self.task_id
            / "state.json"
        )

    @property
    def task_dir(self) -> Path:
        return self.state_path.parent

    def _state(self) -> dict[str, object]:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def _matrix(self) -> dict[str, object]:
        return {
            "repository": "owner/repo",
            "ref": "refs/heads/main",
            "event": "push",
            "workflow_ref": "owner/repo/.github/workflows/test.yml@refs/heads/main",
            "job_key": "tests",
            "runner_os": "Windows",
            "runner_arch": "X64",
            "run_id": 17,
            "run_attempt": 2,
            "matrix_gate_id": "windows-py314",
            "matrix": {"os": "windows-latest", "python": "3.14"},
        }

    def _receipt_pair(
        self,
        name: str,
        *,
        accepted: bool = True,
        matrix: dict[str, object] | None = None,
        log: bytes = b"1 passed in 0.01s\n",
        manifest_sha256: str | None = None,
    ) -> tuple[Path, Path, str, str]:
        head = self._git("rev-parse", "--verify", "HEAD")
        tree = self._git("write-tree")
        status_sha = hashlib.sha256(b"").hexdigest()
        with tempfile.TemporaryDirectory(
            prefix="aoi-exact-test-fixture-source-"
        ) as temporary:
            observed_manifest_sha, file_count = receipts._snapshot(
                self.root,
                Path(temporary) / "snapshot",
            )
        manifest_sha = manifest_sha256 or observed_manifest_sha
        argv = ["-q", "tests/test_bounded.py"]
        structured_sha = hashlib.sha256(
            _canonical({"pytest_argv": argv, "protocol": "pytest-arg-vector-v1"})
        ).hexdigest()
        terminal_status = "completed" if accepted else "rejected"
        exit_code = 0 if accepted else 1
        producer_path = (self.external / "producer.py").resolve()
        invoker = (
            {
                "path": str((self.external / "invoker.py").resolve()),
                "sha256": "2" * 64,
            }
            if matrix is not None
            else None
        )
        observation = {
            "head": head,
            "index_tree": tree,
            "status_sha256": status_sha,
            "manifest_sha256": manifest_sha,
        }
        receipt: dict[str, object] = {
            "schema_version": receipts.SCHEMA_VERSION,
            "kind": receipts.RECEIPT_KIND,
            "accepted": accepted,
            "terminal_status": terminal_status,
            "created_at": "2026-07-24T00:00:00.000000Z",
            "producer": {
                "module": {"path": str(producer_path), "sha256": "1" * 64},
                "invoker": invoker,
                "version": receipts.RUNNER_VERSION,
                "structured_invocation_sha256": structured_sha,
            },
            "source": {
                "head": head,
                "index_tree": tree,
                "manifest_sha256": manifest_sha,
                "file_count": file_count,
                "snapshot": True,
            },
            "interpreter": {
                "path": str(Path(sys.executable).resolve()),
                "sha256": "3" * 64,
                "implementation": "CPython",
                "version": sys.version,
            },
            "invocation": {
                "argv": argv,
                "cwd_role": "private_git_blob_snapshot",
                "environment_names": [],
                "environment_sha256": "4" * 64,
            },
            "platform": {
                "domain": "windows",
                "system": "Windows",
                "release": "test",
                "wsl_distro": "",
                "kernel": "",
            },
            "log": {
                "sha256": hashlib.sha256(log).hexdigest(),
                "size": len(log),
                "path_role": "repo_external_combined_log",
            },
            "pytest_exit_code": exit_code,
            "identity_unchanged": True,
            "log_closed": True,
            "publication_atomic": True,
            "github_matrix_identity": matrix,
            "observation": {
                "pre": copy.deepcopy(observation),
                "post": copy.deepcopy(observation),
                "error": None,
            },
        }
        receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
        raw = receipts.canonical_exact_test_receipt_bytes(receipt)
        receipt_path = self.external / f"{name}.json"
        log_path = self.external / f"{name}.log"
        receipt_path.write_bytes(raw)
        log_path.write_bytes(log)
        return (
            receipt_path,
            log_path,
            hashlib.sha256(raw).hexdigest(),
            hashlib.sha256(log).hexdigest(),
        )

    def _args(
        self,
        receipt_path: Path,
        log_path: Path,
        receipt_sha: str,
        log_sha: str,
        *,
        status: str = "pass",
        matrix_required: bool = False,
        semantic_command_id: str | None = None,
        semantic_expected_head: str | None = None,
        semantic_recorded_at: str = "2026-07-24T12:00:00+00:00",
        extra: tuple[str, ...] = (),
    ) -> list[str]:
        if semantic_command_id is None:
            semantic_command_id = f"record-{receipt_path.stem}-v1"
        if semantic_expected_head is None:
            semantic_expected_head = str(
                semantic_store_impl.semantic_head(
                    h.get_paths(self.root), self.task_id
                )["event_sha256"]
            )
        args = [
            "add-verification",
            "--task",
            self.task_id,
            "--category",
            "unit_test",
            "--status",
            status,
            "--evidence",
            "Exact private-snapshot pytest receipt and combined log retained",
            "--command",
            "python -m pytest -q tests/test_bounded.py",
            "--boundary",
            "Only the receipt-bound exact source snapshot and pytest invocation",
            "--exact-test-receipt",
            f"{receipt_path}={receipt_sha}",
            "--exact-test-log",
            f"{log_path}={log_sha}",
            "--semantic-command-id",
            semantic_command_id,
            "--semantic-expected-head-sha256",
            semantic_expected_head,
            "--semantic-recorded-at",
            semantic_recorded_at,
        ]
        if matrix_required:
            args.append("--exact-test-require-github-matrix")
        args.extend(extra)
        return args

    def _blobs(self) -> set[Path]:
        root = self.task_dir / "results" / "artifact-blobs"
        return {path for path in root.rglob("*") if path.is_file()} if root.exists() else set()

    def _integrity_errors(self, state: dict[str, object] | None = None) -> list[str]:
        return cli_impl.verification_integrity_errors(
            h.get_paths(self.root),
            self._state() if state is None else state,
        )

    def test_pass_receipt_is_preserved_and_cross_bound(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair("pass")
        added = json.loads(
            self.cli(
                *self._args(
                    receipt_path,
                    log_path,
                    receipt_sha,
                    log_sha,
                    extra=("--asserts-completion-boundary",),
                ),
                "--json",
            ).stdout
        )

        state = self._state()
        record = state["verification"][0]  # type: ignore[index]
        evidence = record["exact_test_evidence"]  # type: ignore[index]
        self.assertEqual(state["verification_integrity_version"], 2)
        self.assertEqual(record["integrity_version"], 2)  # type: ignore[index]
        self.assertEqual(record["status"], "pass")  # type: ignore[index]
        self.assertEqual(record["recorded_at"], "2026-07-24T12:00:00+00:00")  # type: ignore[index]
        self.assertEqual(state["updated_at"], record["recorded_at"])  # type: ignore[index]
        events = semantic_store_impl.load_semantic_events(
            h.get_paths(self.root), self.task_id
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["event_type"], "verification_added")
        self.assertEqual(events[-1]["recorded_at"], record["recorded_at"])  # type: ignore[index]
        self.assertEqual(
            added["semantic_head_sha256"], events[-1]["event_sha256"]
        )
        self.assertFalse(added["idempotent_replay"])
        self.assertTrue(evidence["accepted"])  # type: ignore[index]
        self.assertEqual(evidence["receipt_file_sha256"], receipt_sha)  # type: ignore[index]
        self.assertEqual(evidence["log_sha256"], log_sha)  # type: ignore[index]
        self.assertEqual(
            evidence["semantic_transition"],  # type: ignore[index]
            {
                "event_type": "verification_added",
                "command_id": "record-pass-v1",
                "expected_head_sha256": events[0]["event_sha256"],
                "recorded_at": "2026-07-24T12:00:00+00:00",
            },
        )
        self.assertEqual(
            (self.task_dir / evidence["receipt_artifact"]["path"]).read_bytes(),  # type: ignore[index]
            receipt_path.read_bytes(),
        )
        self.assertEqual(
            (self.task_dir / evidence["log_artifact"]["path"]).read_bytes(),  # type: ignore[index]
            log_path.read_bytes(),
        )
        self.assertEqual(self._integrity_errors(), [])
        close_errors = cli_impl.close_gate(h.get_paths(self.root), state)
        self.assertFalse(
            any(
                "passing, close-qualifying verification" in error
                for error in close_errors
            ),
            close_errors,
        )

    def test_failed_test_receipt_maps_only_to_fail(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "failed", accepted=False
        )
        before = self.state_path.read_bytes()
        rejected = self.cli(
            *self._args(receipt_path, log_path, receipt_sha, log_sha),
            ok=False,
        )
        self.assertIn("maps to verification status 'fail'", rejected.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self._blobs(), set())

        self.cli(
            *self._args(
                receipt_path,
                log_path,
                receipt_sha,
                log_sha,
                status="fail",
            )
        )
        record = self._state()["verification"][0]  # type: ignore[index]
        self.assertEqual(record["status"], "fail")  # type: ignore[index]
        self.assertFalse(record["exact_test_evidence"]["accepted"])  # type: ignore[index]
        self.assertEqual(self._integrity_errors(), [])

    def test_required_github_matrix_is_bound(self) -> None:
        matrix = self._matrix()
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "matrix", matrix=matrix
        )
        self.cli(
            *self._args(
                receipt_path,
                log_path,
                receipt_sha,
                log_sha,
                matrix_required=True,
            )
        )
        evidence = self._state()["verification"][0]["exact_test_evidence"]  # type: ignore[index]
        self.assertTrue(evidence["github_matrix_required"])  # type: ignore[index]
        self.assertEqual(evidence["github_matrix_identity"], matrix)  # type: ignore[index]
        self.assertEqual(self._integrity_errors(), [])

    def test_pairing_duplicates_matrix_alone_and_wrong_sha_are_pre_cas(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair("pair")
        base = self._args(receipt_path, log_path, receipt_sha, log_sha)
        cases = [
            [
                *base[:-2],
            ],
            [
                *base,
                "--exact-test-receipt",
                f"{receipt_path}={receipt_sha}",
            ],
            [
                "add-verification",
                "--task",
                self.task_id,
                "--category",
                "unit_test",
                "--status",
                "pass",
                "--evidence",
                "GitHub matrix flag without retained exact-test evidence",
                "--command",
                "python -m pytest -q",
                "--boundary",
                "Parser and pre-CAS pairing gate only",
                "--exact-test-require-github-matrix",
            ],
            self._args(receipt_path, log_path, "0" * 64, log_sha),
            self._args(
                Path(receipt_path.name),
                log_path,
                receipt_sha,
                log_sha,
            ),
        ]
        for args in cases:
            before = self.state_path.read_bytes()
            with self.subTest(args=args):
                self.cli(*args, ok=False)
                self.assertEqual(self.state_path.read_bytes(), before)
                self.assertEqual(self._blobs(), set())

    def test_log_mismatch_malformed_receipt_zero_log_and_source_drift_are_pre_cas(
        self,
    ) -> None:
        receipt_path, log_path, receipt_sha, _log_sha = self._receipt_pair("mismatch")
        log_path.write_bytes(b"different retained log\n")
        cases: list[list[str]] = [
            self._args(
                receipt_path,
                log_path,
                receipt_sha,
                hashlib.sha256(log_path.read_bytes()).hexdigest(),
            )
        ]

        malformed = self.external / "malformed.json"
        malformed.write_bytes(b'{"not":"a receipt"}\n')
        cases.append(
            self._args(
                malformed,
                log_path,
                hashlib.sha256(malformed.read_bytes()).hexdigest(),
                hashlib.sha256(log_path.read_bytes()).hexdigest(),
            )
        )

        zero_receipt, zero_log, zero_receipt_sha, zero_log_sha = self._receipt_pair(
            "zero", log=b""
        )
        cases.append(
            self._args(zero_receipt, zero_log, zero_receipt_sha, zero_log_sha)
        )
        for args in cases:
            before = self.state_path.read_bytes()
            with self.subTest(args=args):
                self.cli(*args, ok=False)
                self.assertEqual(self.state_path.read_bytes(), before)
                self.assertEqual(self._blobs(), set())

        drift_receipt, drift_log, drift_receipt_sha, drift_log_sha = self._receipt_pair(
            "drift"
        )
        (self.root / "later.txt").write_text("later source\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "later.txt"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "later source"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        before = self.state_path.read_bytes()
        rejected = self.cli(
            *self._args(
                drift_receipt,
                drift_log,
                drift_receipt_sha,
                drift_log_sha,
            ),
            ok=False,
        )
        self.assertIn("source HEAD differs", rejected.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self._blobs(), set())

    def test_same_head_staged_index_drift_is_rejected_before_cas(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "staged-index-drift"
        )
        original_head = self._git("rev-parse", "--verify", "HEAD")
        (self.root / "staged-later.txt").write_text(
            "staged source drift\n", encoding="utf-8"
        )
        self._git("add", "staged-later.txt")
        self.assertEqual(self._git("rev-parse", "--verify", "HEAD"), original_head)

        before = self.state_path.read_bytes()
        rejected = self.cli(
            *self._args(receipt_path, log_path, receipt_sha, log_sha),
            ok=False,
        )
        self.assertIn("source index tree differs", rejected.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self._blobs(), set())
        self.assertFalse(
            (self.task_dir / "results" / "exact-test-bindings").exists()
        )

    def test_same_head_unstaged_status_drift_is_rejected_before_cas(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "unstaged-status-drift"
        )
        original_head = self._git("rev-parse", "--verify", "HEAD")
        tracked = self.root / ".harness-test-root"
        tracked.write_text(
            tracked.read_text(encoding="utf-8") + "unstaged source drift\n",
            encoding="utf-8",
        )
        self.assertEqual(self._git("rev-parse", "--verify", "HEAD"), original_head)
        self.assertEqual(
            self._git("write-tree"),
            json.loads(receipt_path.read_text(encoding="utf-8"))["source"][
                "index_tree"
            ],
        )

        before = self.state_path.read_bytes()
        rejected = self.cli(
            *self._args(receipt_path, log_path, receipt_sha, log_sha),
            ok=False,
        )
        self.assertIn("source status differs", rejected.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self._blobs(), set())
        self.assertFalse(
            (self.task_dir / "results" / "exact-test-bindings").exists()
        )

    def test_same_head_manifest_drift_is_rejected_before_cas(self) -> None:
        fake_manifest = hashlib.sha256(b"different source manifest").hexdigest()
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "manifest-drift",
            manifest_sha256=fake_manifest,
        )
        before = self.state_path.read_bytes()
        rejected = self.cli(
            *self._args(receipt_path, log_path, receipt_sha, log_sha),
            ok=False,
        )
        self.assertIn("source manifest differs", rejected.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self._blobs(), set())
        self.assertFalse(
            (self.task_dir / "results" / "exact-test-bindings").exists()
        )

    def test_candidate_integrity_failure_leaves_state_unchanged(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair("candidate")
        args = cli_impl.build_parser().parse_args(
            self._args(receipt_path, log_path, receipt_sha, log_sha)
        )
        before = self.state_path.read_bytes()
        with mock.patch.object(
            cli_impl,
            "verification_integrity_errors",
            return_value=["injected candidate rejection"],
        ), mock.patch.object(
            h, "_require_chief_lock"
        ), self.assertRaisesRegex(h.HarnessError, "injected candidate rejection"):
            cli_impl.cmd_add_verification(args, h.get_paths(self.root))
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(self._blobs()), 2)
        self.assertFalse(
            (self.task_dir / "results" / "exact-test-bindings").exists()
        )

    def test_source_drift_during_cas_publication_fails_before_binding(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "source-drift-during-cas"
        )
        command = self._args(receipt_path, log_path, receipt_sha, log_sha)
        before = self.state_path.read_bytes()
        real_observe = cli_impl._require_live_exact_test_source_identity
        observation_count = 0

        def observe_then_drift(
            worktree: Path, receipt: object
        ) -> dict[str, object]:
            nonlocal observation_count
            observation_count += 1
            if observation_count == 2:
                raise h.HarnessError("injected live source drift during CAS")
            return real_observe(worktree, receipt)  # type: ignore[arg-type,return-value]

        with mock.patch.object(
            cli_impl,
            "_require_live_exact_test_source_identity",
            side_effect=observe_then_drift,
        ):
            failed = self.cli_in_process(*command, ok=False)
        self.assertIn("live source drift during CAS", failed.stderr)
        self.assertEqual(observation_count, 2)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(self._blobs()), 2)
        self.assertFalse(
            (self.task_dir / "results" / "exact-test-bindings").exists()
        )
        event_root = semantic_store_impl.semantic_event_directory(
            h.get_paths(self.root), self.task_id
        )
        self.assertEqual(len(list(event_root.glob("*.json"))), 1)

        completed = json.loads(self.cli(*command, "--json").stdout)
        self.assertFalse(completed["idempotent_replay"])
        self.assertEqual(len(self._blobs()), 2)
        self.assertEqual(len(list(event_root.glob("*.json"))), 2)
        self.assertEqual(self._integrity_errors(), [])

    def test_state_publication_failure_leaves_a_fail_closed_binding(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "state-publication"
        )
        command = self._args(receipt_path, log_path, receipt_sha, log_sha)
        before = self.state_path.read_bytes()
        with mock.patch.object(
            semantic_store_impl,
            "repair_semantic_projection",
            side_effect=h.HarnessError(
                "injected semantic projection publication failure"
            ),
        ):
            failed = self.cli_in_process(*command, ok=False)
        self.assertIn("semantic projection publication failure", failed.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        bindings = list(
            (self.task_dir / "results" / "exact-test-bindings").glob("*.json")
        )
        self.assertEqual(len(bindings), 1)
        self.assertTrue(
            any(
                "has no exact v2 verification" in error
                for error in self._integrity_errors()
            )
        )
        replay = json.loads(self.cli(*command, "--json").stdout)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(self._integrity_errors(), [])

    def test_partial_cas_publication_retries_without_state_or_event_drift(
        self,
    ) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "partial-cas"
        )
        command = self._args(receipt_path, log_path, receipt_sha, log_sha)
        before = self.state_path.read_bytes()
        real_preserve = (
            cli_impl.evidence_artifacts_impl.preserve_generated_artifact_blob
        )

        def fail_log_publication(*args: object, **kwargs: object) -> dict[str, object]:
            if kwargs.get("label") == "exact-test combined log":
                raise h.HarnessError("injected exact-test log CAS failure")
            return real_preserve(*args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(
            cli_impl.evidence_artifacts_impl,
            "preserve_generated_artifact_blob",
            side_effect=fail_log_publication,
        ):
            failed = self.cli_in_process(*command, ok=False)
        self.assertIn("log CAS failure", failed.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(self._blobs()), 1)
        self.assertFalse(
            (self.task_dir / "results" / "exact-test-bindings").exists()
        )
        event_root = semantic_store_impl.semantic_event_directory(
            h.get_paths(self.root), self.task_id
        )
        self.assertEqual(len(list(event_root.glob("*.json"))), 1)

        completed = json.loads(self.cli(*command, "--json").stdout)
        self.assertFalse(completed["idempotent_replay"])
        self.assertEqual(len(self._blobs()), 2)
        self.assertEqual(len(list(event_root.glob("*.json"))), 2)
        self.assertEqual(self._integrity_errors(), [])

    def test_index_publication_failure_replays_without_duplicate_event(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "index-crash"
        )
        command = self._args(receipt_path, log_path, receipt_sha, log_sha)
        with mock.patch.object(
            cli_impl,
            "write_index",
            side_effect=h.HarnessError("injected verification index failure"),
        ):
            failed = self.cli_in_process(*command, ok=False)
        self.assertIn("verification index failure", failed.stderr)
        event_root = semantic_store_impl.semantic_event_directory(
            h.get_paths(self.root), self.task_id
        )
        self.assertEqual(len(list(event_root.glob("*.json"))), 2)
        self.assertEqual(self._integrity_errors(), [])

        replayed = json.loads(self.cli(*command, "--json").stdout)
        self.assertTrue(replayed["idempotent_replay"])
        self.assertEqual(len(list(event_root.glob("*.json"))), 2)
        self.assertEqual(self._integrity_errors(), [])

    def test_binding_before_event_crash_retries_exactly_and_blocks_other_orphan(
        self,
    ) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "binding-crash"
        )
        command = self._args(receipt_path, log_path, receipt_sha, log_sha)
        before = self.state_path.read_bytes()
        real_atomic_create = h.atomic_create_bytes

        def fail_event_create(path: Path, data: bytes) -> None:
            candidate = Path(path)
            if "semantic-v2" in candidate.parts and "events" in candidate.parts:
                raise h.HarnessError("injected semantic event publication failure")
            real_atomic_create(candidate, data)

        with mock.patch.object(
            h, "atomic_create_bytes", side_effect=fail_event_create
        ):
            failed = self.cli_in_process(*command, ok=False)
        self.assertIn("semantic event", failed.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        binding_root = self.task_dir / "results" / "exact-test-bindings"
        self.assertEqual(len(list(binding_root.glob("*.json"))), 1)
        event_root = semantic_store_impl.semantic_event_directory(
            h.get_paths(self.root), self.task_id
        )
        self.assertEqual(len(list(event_root.glob("*.json"))), 1)

        other_receipt = receipt_path
        other_log = log_path
        other_receipt_sha = receipt_sha
        other_log_sha = log_sha
        rejected = self.cli(
            *self._args(
                other_receipt,
                other_log,
                other_receipt_sha,
                other_log_sha,
                semantic_command_id="record-different-command-v1",
            ),
            ok=False,
        )
        self.assertIn("has no exact v2 verification", rejected.stderr)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(list(binding_root.glob("*.json"))), 1)
        self.assertEqual(len(list(event_root.glob("*.json"))), 1)

        completed = json.loads(self.cli(*command, "--json").stdout)
        self.assertFalse(completed["idempotent_replay"])
        self.assertEqual(len(list(binding_root.glob("*.json"))), 1)
        self.assertEqual(len(list(event_root.glob("*.json"))), 2)
        replayed = json.loads(self.cli(*command, "--json").stdout)
        self.assertTrue(replayed["idempotent_replay"])
        self.assertEqual(
            replayed["semantic_head_sha256"],
            completed["semantic_head_sha256"],
        )
        self.assertEqual(len(list(event_root.glob("*.json"))), 2)
        self.assertEqual(self._integrity_errors(), [])

    def test_semantic_timestamp_and_legacy_exact_writer_fail_before_cas(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "timestamp"
        )
        cases = [
            self._args(
                receipt_path,
                log_path,
                receipt_sha,
                log_sha,
                semantic_recorded_at="2026-07-24T12:00:00",
            ),
            self._args(
                receipt_path,
                log_path,
                receipt_sha,
                log_sha,
                semantic_recorded_at="not-a-time",
            ),
        ]
        missing = self._args(receipt_path, log_path, receipt_sha, log_sha)
        recorded_at_index = missing.index("--semantic-recorded-at")
        del missing[recorded_at_index : recorded_at_index + 2]
        cases.append(missing)
        for args in cases:
            before = self.state_path.read_bytes()
            with self.subTest(args=args):
                self.cli(*args, ok=False)
                self.assertEqual(self.state_path.read_bytes(), before)
                self.assertEqual(self._blobs(), set())
                self.assertFalse(
                    (self.task_dir / "results" / "exact-test-bindings").exists()
                )

        legacy_task = "legacy-exact-writer"
        self.init_task(legacy_task)
        legacy_args = self._args(receipt_path, log_path, receipt_sha, log_sha)
        legacy_args[legacy_args.index(self.task_id)] = legacy_task
        rejected = self.cli(*legacy_args, ok=False)
        self.assertIn("require a semantic-v2 task", rejected.stderr)
        legacy_results = (
            self.root / ".aoi" / "tasks" / legacy_task / "results"
        )
        self.assertFalse((legacy_results / "artifact-blobs").exists())
        self.assertFalse((legacy_results / "exact-test-bindings").exists())

    def test_semantic_ledger_replays_coordinated_state_and_marker_deletion(
        self,
    ) -> None:
        before = self.state_path.read_bytes()
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "coordinated-delete"
        )
        self.cli(*self._args(receipt_path, log_path, receipt_sha, log_sha))
        state = self._state()
        evidence = state["verification"][0]["exact_test_evidence"]  # type: ignore[index]
        binding_path = (
            self.task_dir
            / "results"
            / "exact-test-bindings"
            / f"{evidence['binding_sha256']}.json"  # type: ignore[index]
        )
        binding_path.unlink()
        self.state_path.write_bytes(before)

        replayed = h.load_task(h.get_paths(self.root), self.task_id)
        self.assertEqual(len(replayed["verification"]), 1)
        self.assertEqual(replayed["verification_integrity_version"], 2)
        errors = cli_impl.verification_integrity_errors(
            h.get_paths(self.root), replayed
        )
        self.assertTrue(
            any("lacks binding ledger entry" in error for error in errors),
            errors,
        )
        doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                "aoi_orgware.cli",
                "doctor",
                "--task",
                self.task_id,
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
        payload = json.loads(doctor.stdout)
        self.assertTrue(
            any("lacks binding ledger entry" in error for error in payload["errors"]),
            payload,
        )

    def test_missing_or_tampered_cas_and_semantic_tamper_fail_integrity(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair("tamper")
        self.cli(
            *self._args(
                receipt_path,
                log_path,
                receipt_sha,
                log_sha,
                extra=("--asserts-completion-boundary",),
            )
        )
        state = self._state()
        evidence = state["verification"][0]["exact_test_evidence"]  # type: ignore[index]
        receipt_blob = self.task_dir / evidence["receipt_artifact"]["path"]  # type: ignore[index]
        log_blob = self.task_dir / evidence["log_artifact"]["path"]  # type: ignore[index]
        binding_blob = (
            self.task_dir
            / "results"
            / "exact-test-bindings"
            / f"{evidence['binding_sha256']}.json"  # type: ignore[index]
        )

        receipt_raw = receipt_blob.read_bytes()
        receipt_blob.unlink()
        self.assertTrue(any("missing" in error for error in self._integrity_errors()))
        receipt_blob.write_bytes(receipt_raw)

        log_blob.write_bytes(b"tampered log\n")
        self.assertTrue(any("tampered" in error for error in self._integrity_errors()))
        log_blob.write_bytes(log_path.read_bytes())

        binding_raw = binding_blob.read_bytes()
        binding_blob.unlink()
        self.assertTrue(
            any(
                "immutable binding" in error or "lacks binding ledger entry" in error
                for error in self._integrity_errors()
            )
        )
        binding_blob.write_bytes(binding_raw)

        semantic = copy.deepcopy(state)
        semantic["verification"][0]["exact_test_evidence"]["source"][  # type: ignore[index]
            "manifest_sha256"
        ] = "f" * 64
        self.assertTrue(
            any("source binding is invalid" in error for error in self._integrity_errors(semantic))
        )
        close_critical_mutations = (
            ("category", "static_check"),
            ("boundary", "Tampered close-critical verification boundary"),
            ("command", "python -m pytest -q tests/tampered.py"),
            ("asserts_completion_boundary", False),
            ("completion_boundary_sha256", "0" * 64),
        )
        for field, value in close_critical_mutations:
            close_semantic = copy.deepcopy(state)
            close_semantic["verification"][0][field] = value  # type: ignore[index]
            with self.subTest(close_critical_field=field):
                self.assertTrue(
                    any(
                        "immutable binding digest is invalid" in error
                        for error in self._integrity_errors(close_semantic)
                    )
                )
        typed_tamper = copy.deepcopy(state)
        typed_tamper["verification"][0]["exact_test_evidence"]["accepted"] = 1  # type: ignore[index]
        self.assertTrue(
            any(
                "accepted binding is invalid" in error
                for error in self._integrity_errors(typed_tamper)
            )
        )
        semantic_transition_tamper = copy.deepcopy(state)
        semantic_transition_tamper["verification"][0]["exact_test_evidence"][  # type: ignore[index]
            "semantic_transition"
        ]["command_id"] = "record-other-command-v1"
        self.assertTrue(
            any(
                "immutable binding digest is invalid" in error
                for error in self._integrity_errors(semantic_transition_tamper)
            )
        )

    def test_superseded_record_uses_original_status_and_legacy_remains_valid(
        self,
    ) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair("superseded")
        self.cli(*self._args(receipt_path, log_path, receipt_sha, log_sha))
        state = self._state()
        record = state["verification"][0]  # type: ignore[index]
        record["status"] = "skipped"  # type: ignore[index]
        record["original_status"] = "pass"  # type: ignore[index]
        record["superseded_at"] = "2026-07-24T01:00:00+00:00"  # type: ignore[index]
        record["supersession_reason"] = (  # type: ignore[index]
            "Replace this exact source verification with a later passing run"
        )
        errors = self._integrity_errors(state)
        self.assertFalse(any("maps to original verification status" in e for e in errors))
        record["original_status"] = "fail"  # type: ignore[index]
        self.assertTrue(
            any(
                "maps to original verification status 'pass'" in error
                for error in self._integrity_errors(state)
            )
        )

        downgraded = self._state()
        downgraded["verification"][0].pop("exact_test_evidence")  # type: ignore[index]
        self.assertTrue(
            any(
                "integrity_version=2 requires exact_test_evidence" in error
                for error in self._integrity_errors(downgraded)
            )
        )
        downgraded["verification"][0] = copy.deepcopy(  # type: ignore[index]
            self._state()["verification"][0]  # type: ignore[index]
        )
        downgraded["verification"][0]["integrity_version"] = 1  # type: ignore[index]
        self.assertTrue(
            any(
                "legacy integrity_version=1 may not contain exact_test_evidence"
                in error
                for error in self._integrity_errors(downgraded)
            )
        )
        downgraded["verification"][0].pop("exact_test_evidence")  # type: ignore[index]
        self.assertTrue(
            any(
                "has no exact v2 verification" in error
                for error in self._integrity_errors(downgraded)
            )
        )
        binding_sha256 = self._state()["verification"][0]["exact_test_evidence"][  # type: ignore[index]
            "binding_sha256"
        ]
        binding_path = (
            self.task_dir
            / "results"
            / "exact-test-bindings"
            / f"{binding_sha256}.json"
        )
        binding_path.unlink()
        self.assertTrue(
            any(
                "verification_integrity_version=2 lacks exact-test provenance"
                in error
                for error in self._integrity_errors(downgraded)
            )
        )

        legacy_record = {
            "integrity_version": 1,
            "artifact_snapshot_version": 1,
            "category": "unit_test",
            "status": "pass",
            "evidence": "Legacy verification remains readable without exact evidence",
            "command": "python -m pytest -q",
            "boundary": "Legacy verification compatibility only",
            "run_id": "",
            "lane_id": "",
            "artifact_refs": [],
            "recorded_at": "2026-07-24T00:00:00+00:00",
        }
        legacy_state = copy.deepcopy(self._state())
        legacy_state["task_id"] = "genuine-legacy-task"
        legacy_state.pop("verification_integrity_version", None)
        legacy_state["verification"] = [legacy_record]
        self.assertEqual(self._integrity_errors(legacy_state), [])

    def test_semantic_exact_supersession_is_event_anchored_and_retryable(
        self,
    ) -> None:
        first_receipt, first_log, first_receipt_sha, first_log_sha = (
            self._receipt_pair("supersede-first")
        )
        self.cli(
            *self._args(
                first_receipt,
                first_log,
                first_receipt_sha,
                first_log_sha,
                semantic_recorded_at="2026-07-24T12:00:00+00:00",
            )
        )
        second_receipt, second_log, second_receipt_sha, second_log_sha = (
            self._receipt_pair(
                "supersede-second", log=b"2 passed in 0.02s\n"
            )
        )
        self.cli(
            *self._args(
                second_receipt,
                second_log,
                second_receipt_sha,
                second_log_sha,
                semantic_recorded_at="2026-07-24T13:00:00+00:00",
            )
        )
        before = self._state()
        source_sha = cli_impl.canonical_record_sha256(
            before["verification"][0]  # type: ignore[index]
        )
        replacement_sha = cli_impl.canonical_record_sha256(
            before["verification"][1]  # type: ignore[index]
        )
        expected_head = str(
            semantic_store_impl.semantic_head(
                h.get_paths(self.root), self.task_id
            )["event_sha256"]
        )
        command = [
            "verification-supersede",
            "--task",
            self.task_id,
            "--verification-index",
            "1",
            "--expected-record-sha256",
            source_sha,
            "--replacement-index",
            "2",
            "--replacement-record-sha256",
            replacement_sha,
            "--reason",
            "The later exact run supersedes the earlier source-identical result",
            "--semantic-command-id",
            "supersede-exact-first-v1",
            "--semantic-expected-head-sha256",
            expected_head,
            "--semantic-recorded-at",
            "2026-07-24T14:00:00+00:00",
            "--json",
        ]
        superseded = json.loads(self.cli(*command).stdout)
        self.assertFalse(superseded["idempotent_replay"])
        state = self._state()
        source = state["verification"][0]  # type: ignore[index]
        self.assertEqual(source["status"], "skipped")  # type: ignore[index]
        self.assertEqual(source["original_status"], "pass")  # type: ignore[index]
        self.assertEqual(
            source["superseded_at"], "2026-07-24T14:00:00+00:00"  # type: ignore[index]
        )
        self.assertEqual(state["updated_at"], source["superseded_at"])  # type: ignore[index]
        events = semantic_store_impl.load_semantic_events(
            h.get_paths(self.root), self.task_id
        )
        self.assertEqual(events[-1]["event_type"], "verification_superseded")
        self.assertEqual(
            events[-1]["event_sha256"], superseded["semantic_head_sha256"]
        )
        self.assertEqual(self._integrity_errors(), [])

        replayed = json.loads(self.cli(*command).stdout)
        self.assertTrue(replayed["idempotent_replay"])
        self.assertEqual(
            replayed["semantic_head_sha256"],
            superseded["semantic_head_sha256"],
        )
        self.assertEqual(
            len(
                semantic_store_impl.load_semantic_events(
                    h.get_paths(self.root), self.task_id
                )
            ),
            len(events),
        )
        self.assertEqual(self._integrity_errors(), [])

    def test_duplicate_binding_claim_and_malformed_task_id_fail_closed(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair("duplicate")
        self.cli(*self._args(receipt_path, log_path, receipt_sha, log_sha))
        state = self._state()
        state["verification"].append(copy.deepcopy(state["verification"][0]))  # type: ignore[union-attr]
        self.assertTrue(
            any(
                "is claimed by verification #1 and verification #2" in error
                for error in self._integrity_errors(state)
            )
        )
        for task_id in ("C:\\outside-ledger", "/outside-ledger", "\x00outside"):
            malformed = self._state()
            malformed["task_id"] = task_id
            with self.subTest(task_id=task_id):
                errors = self._integrity_errors(malformed)
                self.assertTrue(errors)
                self.assertTrue(
                    any(
                        "task id" in error or "task identity" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_noncanonical_binding_ledger_entry_fails_closed(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "noncanonical-ledger"
        )
        self.cli(*self._args(receipt_path, log_path, receipt_sha, log_sha))
        binding_root = self.task_dir / "results" / "exact-test-bindings"
        unexpected = binding_root / "unexpected.txt"
        unexpected.write_text("not a canonical binding\n", encoding="utf-8")
        errors = self._integrity_errors()
        self.assertTrue(
            any("noncanonical entry" in error for error in errors), errors
        )

    def test_symlink_binding_ledger_entry_fails_closed_when_supported(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "symlink-ledger"
        )
        self.cli(*self._args(receipt_path, log_path, receipt_sha, log_sha))
        raw = b'{"linked":"binding"}\n'
        target = self.external / "linked-binding.json"
        target.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        linked = (
            self.task_dir
            / "results"
            / "exact-test-bindings"
            / f"{digest}.json"
        )
        try:
            linked.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        errors = self._integrity_errors()
        self.assertTrue(
            any(
                "regular file" in error
                or "linked" in error
                or "canonical" in error
                or "symlink" in error
                for error in errors
            ),
            errors,
        )

    def test_terminal_doctor_checks_exact_binding_ledger(self) -> None:
        receipt_path, log_path, receipt_sha, log_sha = self._receipt_pair(
            "terminal-doctor"
        )
        self.cli(*self._args(receipt_path, log_path, receipt_sha, log_sha))
        terminal_id = "terminal-exact-test"
        terminal_dir = (
            self.root / ".aoi" / "tasks" / terminal_id
        )
        shutil.copytree(self.task_dir, terminal_dir)
        semantic_root = terminal_dir / "semantic-v2"
        if semantic_root.exists():
            shutil.rmtree(semantic_root)
        state_path = terminal_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state.pop("_semantic", None)
        state["task_id"] = terminal_id
        state["status"] = "done"
        state["phase"] = "closing"
        state["outcome"] = "partial"
        state["closed_at"] = "2026-07-24T13:00:00+00:00"
        state["checkpoint_required"] = False
        state["session_ids"] = []
        state["subagent_parent_session_ids"] = []
        record = state["verification"][0]
        record["exact_test_evidence"].pop("binding_sha256")
        binding_raw, binding_sha256 = (
            cli_impl.verification_integrity_impl.exact_test_binding_bytes(
                terminal_id, 1, record
            )
        )
        record["exact_test_evidence"]["binding_sha256"] = binding_sha256
        binding_root = terminal_dir / "results" / "exact-test-bindings"
        shutil.rmtree(binding_root)
        binding_root.mkdir()
        binding_path = binding_root / f"{binding_sha256}.json"
        binding_path.write_bytes(binding_raw)
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            cli_impl.verification_integrity_errors(
                h.get_paths(self.root), state
            ),
            [],
        )
        binding_path.unlink()

        doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                "aoi_orgware.cli",
                "doctor",
                "--task",
                terminal_id,
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
        payload = json.loads(doctor.stdout)
        self.assertTrue(
            any(
                f"terminal task {terminal_id}" in error
                and "lacks binding ledger entry" in error
                for error in payload["errors"]
            ),
            payload,
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
