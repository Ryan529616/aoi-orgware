#!/usr/bin/env python3
"""End-to-end contract tests for the constrained ``finish-mini`` fast path."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands.mini_completion import cmd_finish_mini  # noqa: E402

from tests.harness_case import HarnessTestCase  # noqa: E402


class FinishMiniTests(HarnessTestCase):
    def _tracked_target(self, task_id: str) -> tuple[str, Path]:
        relative = f"docs/{task_id}.md"
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("before\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", relative],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", f"fixture {task_id}"],
            check=True,
            text=True,
            capture_output=True,
        )
        return relative, target

    def _start_mini(
        self, task_id: str, *, session_id: str | None = None
    ) -> tuple[str, Path, str, str]:
        relative, target = self._tracked_target(task_id)
        session_id = session_id or f"{task_id}-session"
        token = f"{task_id}-claim"
        lock = f"repo:file:{relative}"
        result = self.cli(
            "start-mini",
            "--task-id",
            task_id,
            "--title",
            f"Finish mini fixture {task_id}",
            "--objective",
            "Exercise the constrained finish-mini lifecycle",
            "--owner",
            "test-root",
            "--completion-boundary",
            "The exact documentation file has bounded passing evidence",
            "--session-id",
            session_id,
            "--token",
            token,
            "--lock",
            lock,
            "--intent",
            "Make one bounded documentation edit",
            "--validation",
            "Run the named documentation check",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--json",
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["task_id"], task_id)
        self.assertEqual(payload["profile"], "mini")
        self.assertEqual(payload["claim"], token)
        self.assertEqual(payload["session_id"], session_id)
        return relative, target, session_id, token

    def _add_qualifying_verification(self, task_id: str) -> None:
        self.add_passing_verification(
            task_id,
            category="documentation_check",
            evidence="Bounded documentation fixture contains the expected text",
            command="python -m unittest tests.test_finish_mini",
            boundary="Only the exact claimed documentation fixture",
        )

    def _finish(
        self,
        task_id: str,
        mode: str,
        *,
        ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.cli(
            "finish-mini",
            "--task",
            task_id,
            "--mode",
            mode,
            "--detail",
            f"finish-mini {mode} delivery for {task_id}",
            "--summary",
            f"finish-mini completed {task_id}",
            "--json",
            ok=ok,
        )

    def _finish_args(self, task_id: str, mode: str) -> argparse.Namespace:
        return argparse.Namespace(
            task=task_id,
            mode=mode,
            detail=f"finish-mini {mode} delivery for {task_id}",
            summary=f"finish-mini completed {task_id}",
            commit=None,
            remote=None,
            remote_ref=None,
            json=True,
        )

    def _services(self):
        task_services = cli_impl._task_lifecycle_cmd_services()
        return cli_impl._mini_completion_services(task_services)

    def _state_bytes(self) -> dict[str, bytes]:
        state_root = self.root / ".aoi"
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in state_root.rglob("*")
            if path.is_file()
        }

    def _assert_active_mini(
        self, task_id: str, session_id: str, token: str
    ) -> None:
        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        self.assertEqual(state["status"], "active")
        self.assertTrue(h.claim_path(paths, token, active=True).is_file())
        self.assertFalse(h.claim_path(paths, token, active=False).exists())
        self.assertTrue(h.session_path(paths, session_id).is_file())

    def _assert_finished(
        self,
        task_id: str,
        session_id: str,
        token: str,
        mode: str,
    ) -> tuple[dict, dict]:
        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        self.assertEqual(state["status"], "done")
        self.assertEqual(state["outcome"], "achieved")
        self.assertEqual(state["delivery"]["mode"], mode)
        self.assertFalse(h.claim_path(paths, token, active=True).exists())
        archived = h.claim_path(paths, token, active=False)
        self.assertTrue(archived.is_file())
        claim = h.load_claim_file(archived)
        self.assertEqual(claim["status"], "done")
        self.assertEqual(h.checkpoint_matches(paths, state), (True, "current"))
        self.assertFalse(h.session_path(paths, session_id).exists())

        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)
        self.assertEqual(doctor["errors"], [])
        return state, claim

    def test_local_only_changed_finishes_and_doctor_is_clean(self) -> None:
        task_id = "mini-local-changed"
        relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        self._add_qualifying_verification(task_id)

        payload = json.loads(self._finish(task_id, "local-only").stdout)
        self.assertEqual(payload["task_id"], task_id)
        self.assertEqual(payload["status"], "done")

        state, claim = self._assert_finished(
            task_id, session_id, token, "local-only"
        )
        lock = f"repo:file:{relative}"
        self.assertIn(relative, state["changed_files"])
        self.assertTrue(claim["baseline_changed"][lock])

        repeated = json.loads(self._finish(task_id, "local-only").stdout)
        self.assertTrue(repeated["idempotent"])
        before = self._state_bytes()
        changed_request = self.cli(
            "finish-mini",
            "--task",
            task_id,
            "--mode",
            "local-only",
            "--detail",
            "a different delivery detail",
            "--summary",
            f"finish-mini completed {task_id}",
            "--json",
            ok=False,
        )
        self.assertIn("different arguments", changed_request.stderr.lower())
        self.assertEqual(self._state_bytes(), before)

    def test_none_unchanged_finishes(self) -> None:
        task_id = "mini-none-unchanged"
        relative, _target, session_id, token = self._start_mini(task_id)
        self._add_qualifying_verification(task_id)

        payload = json.loads(self._finish(task_id, "none").stdout)
        self.assertEqual(payload["task_id"], task_id)
        self.assertEqual(payload["status"], "done")

        state, claim = self._assert_finished(task_id, session_id, token, "none")
        lock = f"repo:file:{relative}"
        self.assertEqual(state["changed_files"], [])
        self.assertFalse(claim["baseline_changed"][lock])

    def test_pushed_changed_requires_and_records_exact_remote_tip(self) -> None:
        task_id = "mini-pushed-changed"
        relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", relative],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "mini pushed change"],
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
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "push", "origin", "main:refs/heads/main"],
            check=True,
            text=True,
            capture_output=True,
        )
        self._add_qualifying_verification(task_id)

        result = self.cli(
            "finish-mini",
            "--task",
            task_id,
            "--mode",
            "pushed",
            "--detail",
            "exact remote main tip verified",
            "--summary",
            f"finish-mini completed {task_id}",
            "--commit",
            commit,
            "--remote",
            "origin",
            "--remote-ref",
            "refs/heads/main",
            "--json",
        )
        self.assertEqual(json.loads(result.stdout)["status"], "done")
        state, claim = self._assert_finished(task_id, session_id, token, "pushed")
        self.assertEqual(state["delivery"]["commit"], commit)
        self.assertEqual(state["delivery"]["remote_sha"], commit)
        self.assertTrue(claim["baseline_changed"][f"repo:file:{relative}"])

    def test_pushed_short_commit_rejects_without_state_mutation(self) -> None:
        task_id = "mini-pushed-short"
        _relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        self._add_qualifying_verification(task_id)
        commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        before = self._state_bytes()

        rejected = self.cli(
            "finish-mini",
            "--task",
            task_id,
            "--mode",
            "pushed",
            "--detail",
            "ambiguous short commit",
            "--summary",
            "must not begin",
            "--commit",
            commit[:7],
            "--remote",
            "origin",
            "--remote-ref",
            "refs/heads/main",
            ok=False,
        )
        self.assertIn("full 40-64 hex", rejected.stderr)
        self.assertEqual(self._state_bytes(), before)
        self._assert_active_mini(task_id, session_id, token)

    def test_retry_after_release_rejects_drift_then_completes_when_restored(
        self,
    ) -> None:
        task_id = "mini-resume-after-release"
        _relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        self._add_qualifying_verification(task_id)
        paths = h.get_paths(self.root)
        services = self._services()

        def interrupt_before_checkpoint(
            _args: argparse.Namespace,
            _paths: h.HarnessPaths,
            *,
            emit_result: bool = True,
        ) -> int:
            raise h.HarnessError("injected interruption after claim release")

        interrupted = replace(services, checkpoint=interrupt_before_checkpoint)
        with self.assertRaisesRegex(h.HarnessError, "injected interruption"):
            with contextlib.redirect_stdout(io.StringIO()):
                cmd_finish_mini(
                    self._finish_args(task_id, "local-only"),
                    paths,
                    services=interrupted,
                )

        partial = h.load_task(paths, task_id)
        self.assertEqual(partial["status"], "active")
        self.assertIn("mini_finish", partial)
        self.assertFalse(h.claim_path(paths, token, active=True).exists())
        self.assertTrue(h.claim_path(paths, token, active=False).is_file())

        target.write_text("drifted after release\n", encoding="utf-8")
        drifted = self._finish(task_id, "local-only", ok=False)
        self.assertIn("drifted after", drifted.stderr.lower())

        target.write_text("after\n", encoding="utf-8")
        payload = json.loads(self._finish(task_id, "local-only").stdout)
        self.assertEqual(payload["status"], "done")
        self._assert_finished(task_id, session_id, token, "local-only")

    def test_done_retry_repairs_session_tail_after_interruption(self) -> None:
        task_id = "mini-resume-terminal-tail"
        _relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        self._add_qualifying_verification(task_id)
        paths = h.get_paths(self.root)
        services = self._services()
        normal_close = services.close_task

        def close_then_interrupt(
            close_args: argparse.Namespace,
            close_paths: h.HarnessPaths,
            *,
            emit_result: bool = True,
        ) -> int:
            with mock.patch.object(
                cli_impl, "unbind_all_sessions_unlocked", lambda *_args: None
            ):
                normal_close(
                    close_args, close_paths, emit_result=emit_result
                )
            raise h.HarnessError("injected interruption before terminal finalizer")

        interrupted = replace(services, close_task=close_then_interrupt)
        with self.assertRaisesRegex(h.HarnessError, "terminal finalizer"):
            with contextlib.redirect_stdout(io.StringIO()):
                cmd_finish_mini(
                    self._finish_args(task_id, "local-only"),
                    paths,
                    services=interrupted,
                )

        self.assertEqual(h.load_task(paths, task_id)["status"], "done")
        self.assertTrue(h.session_path(paths, session_id).is_file())
        retried = json.loads(self._finish(task_id, "local-only").stdout)
        self.assertTrue(retried["idempotent"])
        self._assert_finished(task_id, session_id, token, "local-only")

    def test_done_retry_preserves_session_rebound_to_a_later_task(self) -> None:
        first = "mini-rebound-first"
        _relative, target, session_id, _token = self._start_mini(first)
        target.write_text("after\n", encoding="utf-8")
        self._add_qualifying_verification(first)
        self._finish(first, "local-only")

        second = "mini-rebound-second"
        _second_relative, _second_target, _, _second_token = self._start_mini(
            second, session_id=session_id
        )
        paths = h.get_paths(self.root)
        mapping_path = h.session_path(paths, session_id)
        self.assertEqual(h.load_json(mapping_path)["task_id"], second)

        retried = json.loads(self._finish(first, "local-only").stdout)
        self.assertTrue(retried["idempotent"])
        self.assertEqual(h.load_json(mapping_path)["task_id"], second)

    def test_receipt_tamper_is_a_doctor_error(self) -> None:
        task_id = "mini-receipt-tamper"
        _relative, _target, session_id, token = self._start_mini(task_id)
        self._add_qualifying_verification(task_id)
        self._finish(task_id, "none")
        self._assert_finished(task_id, session_id, token, "none")
        paths = h.get_paths(self.root)
        state_path = h.task_state_path(paths, task_id)
        raw = h.load_json(state_path)
        raw["mini_finish"]["detail"] = "tampered after completion"
        h.atomic_write_json(state_path, raw)

        doctor = subprocess.run(
            [
                sys.executable,
                "-m",
                "aoi_orgware.cli",
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
        self.assertIn("mini finish receipt digest is invalid", doctor.stdout)

    def test_any_job_history_rejects_fast_path_without_new_mutation(self) -> None:
        task_id = "mini-job-history"
        _relative, _target, session_id, token = self._start_mini(task_id)
        self._add_qualifying_verification(task_id)
        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        state["jobs"] = [{"run_id": "historical", "status": "pass"}]
        h.bump_task(state)
        h.write_task(paths, state)
        before = self._state_bytes()

        rejected = self._finish(task_id, "none", ok=False)
        self.assertIn("no packets or jobs", rejected.stderr.lower())
        self.assertEqual(self._state_bytes(), before)
        self._assert_active_mini(task_id, session_id, token)

    def test_none_changed_rejects_without_state_mutation(self) -> None:
        task_id = "mini-none-changed"
        _relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        self._add_qualifying_verification(task_id)
        before = self._state_bytes()

        rejected = self._finish(task_id, "none", ok=False)

        self.assertIn("none", rejected.stderr.lower())
        self.assertIn("changed", rejected.stderr.lower())
        self.assertEqual(self._state_bytes(), before)
        self._assert_active_mini(task_id, session_id, token)

    def test_local_only_unchanged_rejects_without_state_mutation(self) -> None:
        task_id = "mini-local-unchanged"
        _relative, _target, session_id, token = self._start_mini(task_id)
        self._add_qualifying_verification(task_id)
        before = self._state_bytes()

        rejected = self._finish(task_id, "local-only", ok=False)

        self.assertIn("local-only", rejected.stderr.lower())
        self.assertIn("changed", rejected.stderr.lower())
        self.assertEqual(self._state_bytes(), before)
        self._assert_active_mini(task_id, session_id, token)

    def test_full_task_is_rejected_without_state_mutation(self) -> None:
        task_id = "full-finish-rejected"
        session_id = f"{task_id}-session"
        self.init_task(task_id, session_id)
        self._add_qualifying_verification(task_id)
        before = self._state_bytes()

        rejected = self._finish(task_id, "none", ok=False)

        self.assertIn("requires", rejected.stderr.lower())
        self.assertIn("mini task", rejected.stderr.lower())
        self.assertEqual(self._state_bytes(), before)
        paths = h.get_paths(self.root)
        self.assertEqual(h.load_task(paths, task_id)["status"], "active")
        self.assertTrue(h.session_path(paths, session_id).is_file())

    def test_missing_qualifying_verification_is_rejected_without_state_mutation(
        self,
    ) -> None:
        task_id = "mini-missing-verification"
        _relative, target, session_id, token = self._start_mini(task_id)
        target.write_text("after\n", encoding="utf-8")
        before = self._state_bytes()

        rejected = self._finish(task_id, "local-only", ok=False)

        self.assertIn("close-qualifying verification", rejected.stderr.lower())
        self.assertEqual(self._state_bytes(), before)
        self._assert_active_mini(task_id, session_id, token)


if __name__ == "__main__":
    unittest.main()
