#!/usr/bin/env python3
"""Process-termination evidence for AOI's ordered atomic publications."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
WORKER = HERE / "atomic_crash_worker.py"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as semantic_store  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


def atomic_temporaries(directory: Path) -> list[Path]:
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and h.ATOMIC_TEMP_NAME_RE.fullmatch(path.name)
    )


def normalize_index_timestamp(data: bytes) -> bytes:
    lines = data.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(b"Generated: `"):
            lines[index] = b"Generated: `<normalized>`"
            break
    return b"\n".join(lines) + (b"\n" if data.endswith(b"\n") else b"")


class AtomicCrashController:
    def start_observed_worker(
        self,
        *,
        destination: Path,
        stage: str,
        mode: str,
        env: dict[str, str],
        cwd: Path,
        payload: Path | None = None,
        command: list[str] | None = None,
        followup_stage: str | None = None,
    ) -> tuple[socket.socket, subprocess.Popen[bytes]]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.1)
        host, port = listener.getsockname()
        worker_command = [
            sys.executable,
            str(WORKER),
            "--host",
            str(host),
            "--port",
            str(port),
            "--destination",
            str(destination),
            "--stage",
            stage,
        ]
        if followup_stage is not None:
            worker_command.extend(["--followup-stage", followup_stage])
        if payload is not None:
            worker_command.extend(["--payload", str(payload)])
        worker_command.append(mode)
        if command:
            worker_command.extend(["--", *command])
        process = subprocess.Popen(
            worker_command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return listener, process

    def await_event(
        self,
        listener: socket.socket,
        process: subprocess.Popen[bytes],
    ) -> tuple[socket.socket, dict[str, Any]]:
        deadline = time.monotonic() + 10
        while True:
            try:
                connection, _address = listener.accept()
                break
            except TimeoutError:
                if process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=5)
                    self.fail(
                        "atomic worker exited before the requested boundary: "
                        f"rc={process.returncode}\nstdout={stdout!r}\nstderr={stderr!r}"
                    )
                if time.monotonic() >= deadline:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=5)
                    self.fail(
                        "atomic worker did not reach the requested boundary\n"
                        f"stdout={stdout!r}\nstderr={stderr!r}"
                    )
        connection.settimeout(10)
        event_bytes = bytearray()
        while not event_bytes.endswith(b"\n"):
            chunk = connection.recv(1)
            if not chunk:
                self.fail("atomic worker disconnected before reporting its event")
            event_bytes.extend(chunk)
            if len(event_bytes) > 4096:
                self.fail("atomic worker event exceeded the test bound")
        return connection, json.loads(event_bytes)

    def kill_at_boundary(
        self,
        *,
        destination: Path,
        stage: str,
        mode: str,
        env: dict[str, str],
        cwd: Path,
        payload: Path | None = None,
        command: list[str] | None = None,
        followup_stage: str | None = None,
    ) -> tuple[dict[str, Any], subprocess.CompletedProcess[bytes]]:
        listener, process = self.start_observed_worker(
            destination=destination,
            stage=stage,
            mode=mode,
            env=env,
            cwd=cwd,
            payload=payload,
            command=command,
            followup_stage=followup_stage,
        )
        connection: socket.socket | None = None
        try:
            connection, event = self.await_event(listener, process)
            self.assertIsNone(process.poll())
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            return event, subprocess.CompletedProcess(
                process.args, process.returncode, stdout, stderr
            )
        finally:
            listener.close()
            if connection is not None:
                connection.close()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


class AtomicReplaceCrashTests(AtomicCrashController, unittest.TestCase):
    def test_kill_after_temp_fsync_preserves_old_destination_and_complete_temp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "state.json"
            payload_path = root / "next.json"
            old_bytes = b'{"generation": "old", "payload": "complete"}\n'
            new_bytes = b'{"generation": "new", "payload": "complete"}\n'
            destination.write_bytes(old_bytes)
            payload_path.write_bytes(new_bytes)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)

            event, _result = self.kill_at_boundary(
                destination=destination,
                stage="temp_fsynced",
                mode="write",
                env=env,
                cwd=REPO,
                payload=payload_path,
            )

            self.assertEqual(event["operation"], "write")
            self.assertEqual(destination.read_bytes(), old_bytes)
            self.assertEqual(json.loads(destination.read_bytes())["generation"], "old")
            temporaries = atomic_temporaries(root)
            self.assertEqual(len(temporaries), 1)
            self.assertEqual(temporaries[0].read_bytes(), new_bytes)

    def test_kill_after_replace_preserves_complete_new_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "state.json"
            payload_path = root / "next.json"
            old_bytes = b'{"generation": "old", "payload": "complete"}\n'
            new_bytes = b'{"generation": "new", "payload": "complete"}\n'
            destination.write_bytes(old_bytes)
            payload_path.write_bytes(new_bytes)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)

            event, _result = self.kill_at_boundary(
                destination=destination,
                stage="published",
                mode="write",
                env=env,
                cwd=REPO,
                payload=payload_path,
            )

            self.assertEqual(event["operation"], "write")
            self.assertEqual(destination.read_bytes(), new_bytes)
            self.assertEqual(json.loads(destination.read_bytes())["generation"], "new")
            self.assertEqual(atomic_temporaries(root), [])

    def test_concurrent_reader_successes_are_complete_old_or_new_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "state.json"
            payload_path = root / "next.json"
            old_payload = "a" * (512 * 1024)
            new_payload = "b" * (512 * 1024)
            old_bytes = json.dumps(
                {"generation": "old", "payload": old_payload}
            ).encode("utf-8") + b"\n"
            new_bytes = json.dumps(
                {"generation": "new", "payload": new_payload}
            ).encode("utf-8") + b"\n"
            destination.write_bytes(old_bytes)
            payload_path.write_bytes(new_bytes)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)
            listener, process = self.start_observed_worker(
                destination=destination,
                stage="temp_fsynced",
                mode="write",
                env=env,
                cwd=REPO,
                payload=payload_path,
            )
            connection: socket.socket | None = None
            observation_count = 0
            managed_observations: set[str] = set()
            managed_rejection_count = 0
            transient_windows_open_failure_count = 0
            failures: list[BaseException] = []
            stop = threading.Event()
            old_seen = threading.Event()
            new_seen = threading.Event()
            managed_old_seen = threading.Event()
            managed_new_seen = threading.Event()

            def read_generations() -> None:
                nonlocal observation_count
                nonlocal managed_rejection_count
                nonlocal transient_windows_open_failure_count
                while not stop.is_set():
                    try:
                        data = destination.read_bytes()
                    except PermissionError as exc:
                        # Native Windows can briefly reject a new open while
                        # os.replace changes the directory entry.  This is an
                        # availability boundary, not a torn-read result.
                        if os.name == "nt":
                            transient_windows_open_failure_count += 1
                            continue
                        failures.append(exc)
                        return
                    except BaseException as exc:  # captured for the parent assertion
                        failures.append(exc)
                        return
                    try:
                        decoded = json.loads(data)
                    except BaseException as exc:
                        failures.append(exc)
                        return
                    if data == old_bytes:
                        old_seen.set()
                    elif data == new_bytes:
                        new_seen.set()
                    else:
                        failures.append(
                            AssertionError(
                                f"reader returned an unexpected generation: {decoded!r}"
                            )
                        )
                        return
                    observation_count += 1

                    try:
                        managed = h.load_json(destination)
                    except h.HarnessError as exc:
                        message = str(exc)
                        expected_rejection = "changed while being read" in message
                        if os.name == "nt" and "Permission denied" in message:
                            expected_rejection = True
                        if not expected_rejection:
                            failures.append(exc)
                            return
                        managed_rejection_count += 1
                        continue
                    generation = managed.get("generation")
                    payload = managed.get("payload")
                    if (generation, payload) == ("old", old_payload):
                        managed_old_seen.set()
                    elif (generation, payload) == ("new", new_payload):
                        managed_new_seen.set()
                    else:
                        failures.append(
                            AssertionError(
                                "managed reader returned an incomplete generation: "
                                f"{generation!r}"
                            )
                        )
                        return
                    managed_observations.add(str(generation))

            def wait_for_observation(
                event: threading.Event, label: str, timeout: float = 5.0
            ) -> None:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if failures:
                        self.fail(f"reader failed before observing {label}: {failures[0]}")
                    if event.wait(timeout=0.02):
                        return
                if failures:
                    self.fail(f"reader failed before observing {label}: {failures[0]}")
                self.fail(f"reader did not observe {label}")

            reader = threading.Thread(target=read_generations)
            try:
                connection, _event = self.await_event(listener, process)
                reader.start()
                wait_for_observation(old_seen, "old raw JSON")
                wait_for_observation(managed_old_seen, "old managed JSON")
                connection.sendall(b"G")
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
                wait_for_observation(new_seen, "new raw JSON")
                wait_for_observation(managed_new_seen, "new managed JSON")
                self.assertEqual(stdout, b"")
            finally:
                stop.set()
                if reader.ident is not None:
                    reader.join(timeout=5)
                listener.close()
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            self.assertFalse(reader.is_alive())
            self.assertEqual(failures, [])
            self.assertGreater(
                observation_count,
                1,
                f"managed reader rejected {managed_rejection_count} raced opens",
            )
            self.assertIn("old", managed_observations)
            self.assertIn("new", managed_observations)
            if os.name != "nt":
                self.assertEqual(transient_windows_open_failure_count, 0)
            self.assertEqual(destination.read_bytes(), new_bytes)


class CheckpointCrashTests(AtomicCrashController, HarnessTestCase):
    def checkpoint_command(self, task_id: str) -> list[str]:
        return [
            "checkpoint",
            "--task",
            task_id,
            "--fact",
            "Crash matrix fact is committed only with matching state",
            "--next-action",
            "Verify the ordered checkpoint, state, and index publications",
            "--json",
        ]

    def test_kill_after_checkpoint_publish_fails_closed_and_retry_repairs(self) -> None:
        task_id = "checkpoint-publish-crash"
        self.init_task(task_id)
        paths = h.get_paths(self.root)
        state_path = h.task_state_path(paths, task_id)
        checkpoint_path = h.task_dir(paths, task_id) / "checkpoint.md"
        old_state = state_path.read_bytes()
        old_checkpoint = checkpoint_path.read_bytes()
        old_index = paths.index.read_bytes()
        command = self.checkpoint_command(task_id)

        self.kill_at_boundary(
            destination=checkpoint_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=command,
        )

        self.assertEqual(state_path.read_bytes(), old_state)
        self.assertNotEqual(checkpoint_path.read_bytes(), old_checkpoint)
        self.assertEqual(paths.index.read_bytes(), old_index)
        state = h.load_task(paths, task_id)
        checkpoint_ok, reason = h.checkpoint_matches(paths, state)
        self.assertFalse(checkpoint_ok, reason)
        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)
        self.assertTrue(
            any("checkpoint mismatch" in warning for warning in doctor["warnings"]),
            doctor,
        )

        self.cli(*command)

        repaired = h.load_task(paths, task_id)
        self.assertTrue(h.checkpoint_matches(paths, repaired)[0])

    def test_kill_after_state_publish_leaves_only_rebuildable_index_stale(self) -> None:
        task_id = "state-publish-crash"
        self.init_task(task_id)
        paths = h.get_paths(self.root)
        state_path = h.task_state_path(paths, task_id)
        checkpoint_path = h.task_dir(paths, task_id) / "checkpoint.md"
        old_state = state_path.read_bytes()
        old_checkpoint = checkpoint_path.read_bytes()
        old_index = paths.index.read_bytes()

        self.kill_at_boundary(
            destination=state_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.checkpoint_command(task_id),
        )

        self.assertNotEqual(state_path.read_bytes(), old_state)
        self.assertNotEqual(checkpoint_path.read_bytes(), old_checkpoint)
        self.assertEqual(paths.index.read_bytes(), old_index)
        state = h.load_task(paths, task_id)
        self.assertTrue(h.checkpoint_matches(paths, state)[0])
        expected_index = h.render_index(paths).encode("utf-8")
        self.assertNotEqual(
            normalize_index_timestamp(expected_index),
            normalize_index_timestamp(old_index),
        )

        self.cli("render-index")

        self.assertEqual(
            normalize_index_timestamp(paths.index.read_bytes()),
            normalize_index_timestamp(expected_index),
        )


class SemanticGenesisCrashTests(AtomicCrashController, HarnessTestCase):
    TASK_ID = "semantic-genesis-crash"
    COMMAND_ID = "init-semantic-genesis-crash-v1"

    def semantic_command(self) -> list[str]:
        return [
            "init-task",
            "--task-id",
            self.TASK_ID,
            "--title",
            "Semantic genesis crash",
            "--objective",
            "Prove ordered event and projection publication",
            "--owner",
            "test-root",
            "--completion-boundary",
            "Every process-kill boundary recovers at most one semantic head",
            "--semantic-v2",
            "--semantic-command-id",
            self.COMMAND_ID,
            "--json",
        ]

    def event_path(self, paths: h.HarnessPaths) -> Path:
        return semantic_store.semantic_event_directory(
            paths, self.TASK_ID
        ) / semantic.event_filename(1)

    def test_kill_after_event_publish_replays_and_exact_retry_repairs_projection(self) -> None:
        paths = h.get_paths(self.root)
        event_path = self.event_path(paths)
        state_path = h.task_state_path(paths, self.TASK_ID)
        self.kill_at_boundary(
            destination=event_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.semantic_command(),
        )

        self.assertTrue(event_path.is_file())
        self.assertFalse(state_path.exists())
        event_before = event_path.read_bytes()
        replayed = h.load_task(paths, self.TASK_ID)
        self.assertEqual(replayed["task_id"], self.TASK_ID)
        self.assertEqual(
            semantic_store.semantic_projection_status(paths, self.TASK_ID), "missing"
        )

        retried = json.loads(self.cli(*self.semantic_command()).stdout)
        self.assertTrue(retried["idempotent_retry"])
        self.assertTrue(retried["projection_repaired"])
        self.assertEqual(event_path.read_bytes(), event_before)
        self.assertEqual(
            list(semantic_store.semantic_event_directory(paths, self.TASK_ID).glob("*.json")),
            [event_path],
        )
        self.assertEqual(
            semantic_store.semantic_projection_status(paths, self.TASK_ID), "current"
        )

    def test_kill_after_projection_publish_leaves_one_current_head_and_stale_index_only(self) -> None:
        paths = h.get_paths(self.root)
        state_path = h.task_state_path(paths, self.TASK_ID)
        old_index = paths.index.read_bytes()
        self.kill_at_boundary(
            destination=state_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.semantic_command(),
        )

        event_path = self.event_path(paths)
        self.assertTrue(event_path.is_file())
        self.assertTrue(state_path.is_file())
        self.assertEqual(paths.index.read_bytes(), old_index)
        self.assertEqual(
            semantic_store.semantic_projection_status(paths, self.TASK_ID), "current"
        )
        before = event_path.read_bytes()
        retried = json.loads(self.cli(*self.semantic_command()).stdout)
        self.assertTrue(retried["idempotent_retry"])
        self.assertFalse(retried["projection_repaired"])
        self.assertEqual(event_path.read_bytes(), before)
        self.assertNotEqual(paths.index.read_bytes(), old_index)

    def test_kill_after_event_temp_fsync_requires_residue_recovery_then_retries(self) -> None:
        paths = h.get_paths(self.root)
        event_path = self.event_path(paths)
        self.kill_at_boundary(
            destination=event_path,
            stage="temp_fsynced",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.semantic_command(),
        )

        self.assertFalse(event_path.exists())
        event_directory = semantic_store.semantic_event_directory(paths, self.TASK_ID)
        self.assertEqual(len(atomic_temporaries(event_directory)), 1)
        failed = subprocess.run(
            [
                sys.executable,
                "-m",
                "aoi_orgware.cli",
                "doctor",
                "--task",
                self.TASK_ID,
                "--json",
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(failed.returncode, 1, failed)
        self.assertTrue(
            any("unexpected file" in error for error in json.loads(failed.stdout)["errors"]),
            failed.stdout,
        )

        recovered = json.loads(self.cli("recover-temporaries", "--json").stdout)
        self.assertGreaterEqual(len(recovered["recovered"]), 1)
        self.assertEqual(atomic_temporaries(event_directory), [])
        initialized = json.loads(self.cli(*self.semantic_command()).stdout)
        self.assertFalse(initialized["idempotent_retry"])
        self.assertTrue(event_path.is_file())
        self.assertEqual(
            semantic_store.semantic_projection_status(paths, self.TASK_ID), "current"
        )


class SemanticMigrationCrashTests(AtomicCrashController, HarnessTestCase):
    TASK_ID = "semantic-migration-crash"
    COMMAND_ID = "semantic-migration-crash-r1"

    def setUp(self) -> None:
        super().setUp()
        self.init_task(self.TASK_ID)
        self.paths = h.get_paths(self.root)
        self.state_path = h.task_state_path(self.paths, self.TASK_ID)
        self.legacy_bytes = self.state_path.read_bytes()
        self.legacy_sha256 = hashlib.sha256(self.legacy_bytes).hexdigest()

    def migration_command(self) -> list[str]:
        return [
            "semantic-migrate",
            "--task",
            self.TASK_ID,
            "--command-id",
            self.COMMAND_ID,
            "--expected-legacy-state-sha256",
            self.legacy_sha256,
            "--json",
        ]

    def test_kill_after_legacy_snapshot_publish_resumes_without_byte_drift(self) -> None:
        snapshot_path = semantic_store.legacy_snapshot_path(
            self.paths, self.TASK_ID
        )
        event_path = semantic_store.semantic_event_directory(
            self.paths, self.TASK_ID
        ) / semantic.event_filename(1)
        self.kill_at_boundary(
            destination=snapshot_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.migration_command(),
        )

        self.assertEqual(snapshot_path.read_bytes(), self.legacy_bytes)
        self.assertFalse(event_path.exists())
        self.assertEqual(self.state_path.read_bytes(), self.legacy_bytes)
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        self.assertFalse(migrated["idempotent_replay"])
        self.assertTrue(event_path.is_file())
        self.assertEqual(
            semantic_store.semantic_projection_status(self.paths, self.TASK_ID),
            "current",
        )

    def test_kill_after_migration_event_publish_exact_retry_finishes_cutover(self) -> None:
        event_path = semantic_store.semantic_event_directory(
            self.paths, self.TASK_ID
        ) / semantic.event_filename(1)
        receipt_path = semantic_store.migration_receipt_path(
            self.paths, self.TASK_ID
        )
        self.kill_at_boundary(
            destination=event_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.migration_command(),
        )

        self.assertTrue(event_path.is_file())
        self.assertFalse(receipt_path.exists())
        self.assertEqual(self.state_path.read_bytes(), self.legacy_bytes)
        event_before = event_path.read_bytes()
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        self.assertTrue(migrated["idempotent_replay"])
        self.assertEqual(event_path.read_bytes(), event_before)
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(
            semantic_store.semantic_projection_status(self.paths, self.TASK_ID),
            "current",
        )

    def test_kill_after_migration_receipt_publish_exact_retry_finishes_projection(
        self,
    ) -> None:
        receipt_path = semantic_store.migration_receipt_path(
            self.paths, self.TASK_ID
        )
        self.kill_at_boundary(
            destination=receipt_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=self.migration_command(),
        )

        self.assertTrue(receipt_path.is_file())
        self.assertEqual(self.state_path.read_bytes(), self.legacy_bytes)
        receipt_before = receipt_path.read_bytes()
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        self.assertTrue(migrated["idempotent_replay"])
        self.assertEqual(receipt_path.read_bytes(), receipt_before)
        self.assertEqual(
            semantic_store.semantic_projection_status(self.paths, self.TASK_ID),
            "current",
        )

    def test_kill_after_rollback_marker_publish_exact_retry_restores_legacy_bytes(
        self,
    ) -> None:
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        marker_path = (
            h.task_dir(self.paths, self.TASK_ID)
            / semantic_store.SEMANTIC_DIRECTORY_NAME
            / semantic_store.MIGRATION_ROLLBACK_NAME
        )
        rollback_command = [
            "semantic-migration-rollback",
            "--task",
            self.TASK_ID,
            "--command-id",
            "semantic-migration-crash-rollback-r1",
            "--expected-head-sha256",
            migrated["head_event_sha256"],
            "--expected-migration-receipt-sha256",
            migrated["migration_receipt_sha256"],
            "--json",
        ]
        semantic_projection = self.state_path.read_bytes()
        self.assertNotEqual(semantic_projection, self.legacy_bytes)
        self.kill_at_boundary(
            destination=marker_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=rollback_command,
        )

        self.assertTrue(marker_path.is_file())
        self.assertEqual(self.state_path.read_bytes(), semantic_projection)
        rolled_back = json.loads(self.cli(*rollback_command).stdout)
        self.assertTrue(rolled_back["idempotent_replay"])
        self.assertEqual(self.state_path.read_bytes(), self.legacy_bytes)
        self.assertFalse(semantic_store.has_semantic_ledger(self.paths, self.TASK_ID))

    def test_kill_after_rollback_state_publish_requires_completion_receipt(self) -> None:
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        semantic_root = (
            h.task_dir(self.paths, self.TASK_ID)
            / semantic_store.SEMANTIC_DIRECTORY_NAME
        )
        marker_path = semantic_root / semantic_store.MIGRATION_ROLLBACK_NAME
        completion_path = (
            semantic_root / semantic_store.MIGRATION_ROLLBACK_COMPLETION_NAME
        )
        rollback_command = [
            "semantic-migration-rollback",
            "--task",
            self.TASK_ID,
            "--command-id",
            "semantic-migration-crash-rollback-state-r1",
            "--expected-head-sha256",
            migrated["head_event_sha256"],
            "--expected-migration-receipt-sha256",
            migrated["migration_receipt_sha256"],
            "--json",
        ]
        self.kill_at_boundary(
            destination=self.state_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=rollback_command,
        )

        self.assertTrue(marker_path.is_file())
        self.assertFalse(completion_path.exists())
        self.assertEqual(self.state_path.read_bytes(), self.legacy_bytes)
        self.assertTrue(semantic_store.has_semantic_ledger(self.paths, self.TASK_ID))
        rolled_back = json.loads(self.cli(*rollback_command).stdout)
        self.assertTrue(rolled_back["idempotent_replay"])
        self.assertTrue(completion_path.is_file())
        self.assertFalse(semantic_store.has_semantic_ledger(self.paths, self.TASK_ID))

    def test_kill_after_rollback_completion_publish_is_fully_idempotent(self) -> None:
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        completion_path = (
            h.task_dir(self.paths, self.TASK_ID)
            / semantic_store.SEMANTIC_DIRECTORY_NAME
            / semantic_store.MIGRATION_ROLLBACK_COMPLETION_NAME
        )
        rollback_command = [
            "semantic-migration-rollback",
            "--task",
            self.TASK_ID,
            "--command-id",
            "semantic-migration-crash-rollback-complete-r1",
            "--expected-head-sha256",
            migrated["head_event_sha256"],
            "--expected-migration-receipt-sha256",
            migrated["migration_receipt_sha256"],
            "--json",
        ]
        self.kill_at_boundary(
            destination=completion_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=rollback_command,
        )

        self.assertTrue(completion_path.is_file())
        self.assertEqual(self.state_path.read_bytes(), self.legacy_bytes)
        self.assertFalse(semantic_store.has_semantic_ledger(self.paths, self.TASK_ID))
        completion_before = completion_path.read_bytes()
        rolled_back = json.loads(self.cli(*rollback_command).stdout)
        self.assertTrue(rolled_back["idempotent_replay"])
        self.assertEqual(completion_path.read_bytes(), completion_before)

    def test_kill_after_semantic_close_event_publish_exact_retry_finishes_close(
        self,
    ) -> None:
        self.cli(
            "set-delivery",
            "--task",
            self.TASK_ID,
            "--mode",
            "local-only",
            "--detail",
            "Semantic close crash remains local",
        )
        self.cli(
            "checkpoint",
            "--task",
            self.TASK_ID,
            "--next-action",
            "Close through the semantic writer",
        )
        self.legacy_bytes = self.state_path.read_bytes()
        self.legacy_sha256 = hashlib.sha256(self.legacy_bytes).hexdigest()
        migrated = json.loads(self.cli(*self.migration_command()).stdout)
        old_projection = self.state_path.read_bytes()
        close_command = [
            "close-task",
            "--task",
            self.TASK_ID,
            "--summary",
            "Semantic close crash recovery is event-authoritative",
            "--outcome",
            "partial",
            "--boundary-disposition",
            "This test validates only close crash mechanics",
            "--semantic-command-id",
            "semantic-close-crash-r2",
            "--semantic-expected-head-sha256",
            migrated["head_event_sha256"],
            "--json",
        ]
        close_event_path = semantic_store.semantic_event_directory(
            self.paths, self.TASK_ID
        ) / semantic.event_filename(2)
        self.kill_at_boundary(
            destination=close_event_path,
            stage="published",
            mode="cli",
            env=self.env,
            cwd=self.root,
            command=close_command,
        )

        self.assertTrue(close_event_path.is_file())
        self.assertEqual(self.state_path.read_bytes(), old_projection)
        checkpoint_path = h.task_dir(self.paths, self.TASK_ID) / "checkpoint.md"
        checkpoint_before = checkpoint_path.read_bytes()
        self.assertEqual(h.load_task(self.paths, self.TASK_ID)["status"], "done")
        self.assertEqual(
            semantic_store.semantic_projection_status(self.paths, self.TASK_ID),
            "behind",
        )
        event_before = close_event_path.read_bytes()
        closed = json.loads(self.cli(*close_command).stdout)
        self.assertTrue(closed["idempotent_replay"])
        self.assertEqual(close_event_path.read_bytes(), event_before)
        self.assertEqual(
            semantic_store.semantic_projection_status(self.paths, self.TASK_ID),
            "current",
        )
        self.assertNotEqual(checkpoint_path.read_bytes(), checkpoint_before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
