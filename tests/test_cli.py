#!/usr/bin/env python3
"""Unit and integration tests for dependency-free AOI orgware."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402


CLI_MODULE = "aoi_orgware.cli"
HOOK_MODULE = "aoi_orgware.codex_hook"


class HarnessTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.backup_temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env["AOI_ROOT"] = str(self.root)
        self.env["PYTHONPATH"] = str(SRC)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["HOME"] = str(self.root / "home")
        self.env["CODEX_HOME"] = str(self.root / "codex-home")
        self.env["XDG_CONFIG_HOME"] = str(self.root / "xdg")
        self.env["TMPDIR"] = str(self.root / "tmp")
        self.env["AOI_HOST_MOUNT_ROOT"] = str(self.root / "host-mount")
        self.env["AOI_BACKUP_ROOT"] = self.backup_temp.name
        (self.root / "tmp").mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(self.root)],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Harness Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "harness@test.invalid"],
            check=True,
        )
        (self.root / ".harness-test-root").write_text("test root\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", ".harness-test-root"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "test root"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.cli("init", "--project-name", "AOI Test Project")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "aoi.toml", ".gitignore"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "initialize AOI"],
            check=True,
            text=True,
            capture_output=True,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.backup_temp.cleanup()

    def cli(self, *args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(args)}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        if not ok:
            if result.returncode == 0:
                self.fail(f"CLI unexpectedly succeeded: {' '.join(args)}")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        return result

    def init_task(self, task_id: str, session_id: str | None = None) -> None:
        args = [
            "init-task",
            "--task-id",
            task_id,
            "--title",
            f"Task {task_id}",
            "--objective",
            "Exercise the harness contract",
            "--owner",
            "test-root",
            "--completion-boundary",
            "All requested test evidence is accounted",
        ]
        if session_id:
            args.extend(["--session-id", session_id])
        self.cli(*args)
        self.cli(
            "approve-plan",
            "--task",
            task_id,
            "--note",
            "Test plan records evidence, exclusions, claims, packets, and verification",
        )

    def add_passing_verification(
        self,
        task_id: str,
        *,
        category: str = "unit_test",
        evidence: str = "test runner reported PASS",
        command: str = "python3 -m unittest bounded-case",
        boundary: str = "Only the named isolated harness behavior",
        artifact_refs: tuple[str, ...] = (),
        review_packet_id: str | None = None,
    ) -> None:
        args = [
            "add-verification",
            "--task",
            task_id,
            "--category",
            category,
            "--status",
            "pass",
            "--evidence",
            evidence,
            "--command",
            command,
            "--boundary",
            boundary,
        ]
        for artifact_ref in artifact_refs:
            args.extend(["--artifact-ref", artifact_ref])
        if review_packet_id:
            args.extend(["--review-packet-id", review_packet_id])
        self.cli(*args)

    def write_source_receipt(
        self,
        name: str,
        *,
        tool_path: str = "/tools/vcs",
        tool_version: str = "VCS-test",
        command: str = "timeout 1m run.sh",
    ) -> tuple[Path, str]:
        receipt = self.root / name
        payload = {
            "receipt_version": 1,
            "source_set_id": name,
            "producer": "isolated harness test",
            "tool": {
                "path": tool_path,
                "version": tool_version,
                "command": command,
            },
            "components": {
                "source": {
                    "status": "included",
                    "files": [{"path": "/src/app/main.py", "sha256": "1" * 64}],
                },
                "runner": {
                    "status": "included",
                    "files": [{"path": "/src/scripts/run.sh", "sha256": "2" * 64}],
                },
                "config": {"status": "not_applicable", "reason": "default config"},
                "dependencies": {"status": "not_applicable", "reason": "none"},
                "other": {"status": "not_applicable", "reason": "none"},
            },
        }
        receipt.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt, hashlib.sha256(receipt.read_bytes()).hexdigest()

    def hook(self, payload: dict, bom: bool = False) -> dict:
        raw = json.dumps(payload).encode("utf-8")
        if bom:
            raw = b"\xef\xbb\xbf" + raw
        result = subprocess.run(
            [sys.executable, "-m", HOOK_MODULE, "--hook-version", "5"],
            cwd=self.root,
            env=self.env,
            input=raw,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout.decode("utf-8"))

    def install_hook_layers(self) -> None:
        config = self.root / "aoi.toml"
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "[hooks.codex]\nenabled = false",
                "[hooks.codex]\nenabled = true",
            ),
            encoding="utf-8",
        )
        hooks: dict[str, list[dict]] = {}
        for event in ("SessionStart", "UserPromptSubmit", "SubagentStart", "Stop"):
            hooks[event] = [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "aoi-codex-hook --hook-version 5",
                            "commandWindows": "wsl aoi-codex-hook --hook-version 5",
                            "timeout": 30,
                        }
                    ]
                }
            ]
        payload = json.dumps({"hooks": hooks}, indent=2) + "\n"
        layer = self.root / ".codex"
        layer.mkdir(parents=True, exist_ok=True)
        (layer / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
        (layer / "hooks.json").write_text(payload, encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "aoi.toml", ".codex"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", "enable AOI hook fixture"],
            check=True,
            capture_output=True,
            text=True,
        )


class LockTests(HarnessTestCase):
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
        with self.assertRaises(h.HarnessError):
            h.normalize_lock("repo:tree:rtl/*")
        locks, _ = h.legacy_scope_locks(
            h.get_paths(self.root), "legacy `scripts/*model_top*` scope"
        )
        self.assertEqual(locks, ["repo:tree:scripts"])

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

        host_file = self.root / "host-mount" / "d" / "workspace" / "project" / "hook.json"
        host_file.parent.mkdir(parents=True)
        host_file.write_text("v1\n", encoding="utf-8")
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
            "host:file:D:/workspace/project/hook.json",
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
        lock = "host:file:D:/workspace/project/hook.json"
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
        self.cli(*claim_args)

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
        self.cli(
            "checkpoint",
            "--task",
            "rollback-task",
            "--fact",
            "x" * 13000,
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
        self.cli(
            "close-task",
            "--task",
            "rollback-task",
            "--summary",
            "x" * 13000,
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
                "worktree": str(self.root),
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
            "worktree": str(self.root),
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
        below_threshold["claims"] = [
            *state["claims"][: h.COMPACT_CLAIM_HISTORY_THRESHOLD - 1],
            "active-claim",
        ]
        below_rendered = h.render_checkpoint(
            paths,
            below_threshold,
            compact_terminal_detail=True,
        )
        self.assertNotIn("Terminal claim history:", below_rendered)
        self.assertIn("terminal-claim-00 [done]", below_rendered)

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
            self.cli(*claim_args)
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
        self.assertGreater(len(full.encode("utf-8")), h.CHECKPOINT_MAX_BYTES)

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
                "stop_condition": "ACTIVE-DETAIL-" + "x" * 13000,
                "source_sha": "c" * 64,
                "source_scope": "current source",
                "evidence": "still running",
            }
        )
        with self.assertRaisesRegex(h.HarnessError, "checkpoint exceeds 12 KiB"):
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
            for index in range(130)
        ]
        for lock in locks:
            claim_args.extend(["--lock", lock])
        self.cli(*claim_args)
        paths = h.get_paths(self.root)
        state = h.load_task(paths, "active-claim-oversized-checkpoint")
        compact = h.render_checkpoint(paths, state, compact_terminal_detail=True)
        for lock in locks:
            self.assertIn(lock, compact)
        with self.assertRaisesRegex(h.HarnessError, "checkpoint exceeds 12 KiB"):
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
                "baselines": {},
            },
        )
        failed = self.cli(
            "close-task",
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
        self.cli(
            "packet-update",
            "--task",
            "packet-task",
            "--packet-id",
            "review",
            "--status",
            "dispatched",
            "--agent-id",
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
            "--task",
            "eda-task",
            "--summary",
            "must not close",
            ok=False,
        )
        self.assertIn("unresolved queued/running/unknown jobs", unresolved.stderr)
        terminal_log = Path("/tmp/aoi-example-run/driver.log")
        terminal_log.parent.mkdir(parents=True, exist_ok=True)
        terminal_log.write_text("PASS exit=0\n", encoding="utf-8")
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
            "--task",
            "eda-task",
            "--summary",
            "EDA lifecycle gate verified",
        )

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
        self.cli(
            "packet-update",
            "--task",
            "packet-lock-task",
            "--packet-id",
            "writer",
            "--status",
            "dispatched",
            "--agent-id",
            "agent-writer",
        )
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
        terminal_log = Path("/tmp/receipt-run/driver.log")
        terminal_log.parent.mkdir(parents=True, exist_ok=True)
        terminal_log.write_text("PASS exit=0\n", encoding="utf-8")
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
        self.cli(
            "packet-update",
            "--task",
            "packet-tamper",
            "--packet-id",
            "reader",
            "--status",
            "dispatched",
            "--agent-id",
            "reader-agent",
        )
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
        self.cli(
            "packet-update",
            "--task",
            "post-close-tamper",
            "--packet-id",
            "reader",
            "--status",
            "dispatched",
            "--agent-id",
            "reader-agent",
        )
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
        self.install_hook_layers()
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
        command.write_text("#!/bin/sh\nprintf 'bounded command\\n'\n", encoding="utf-8")
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
        command_link.symlink_to(command)
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
        self.assertIn("non-symlink", symlink.stderr)
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
        self.assertEqual(packet["command_sha256"], command_sha)
        snapshot = Path(packet["command_path"])
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
        self.cli(
            "packet-update",
            "--task",
            "reconcile-observed",
            "--packet-id",
            "rtl-owner",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/rtl-owner",
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
            self.cli(
                "packet-update",
                "--task",
                "capacity-flow",
                "--packet-id",
                packet_id,
                "--status",
                "dispatched",
                "--agent-id",
                f"/root/{packet_id}",
            )
            self.cli(
                "packet-update",
                "--task",
                "capacity-flow",
                "--packet-id",
                packet_id,
                "--status",
                "done",
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
        self.cli(
            "packet-update",
            "--task",
            "capacity-flow",
            "--packet-id",
            "rtl-parent",
            "--status",
            "dispatched",
            "--agent-id",
            "/root/rtl-parent",
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
        self.assertEqual(
            json.loads(Path(review["dataset"]["path"]).read_text(encoding="utf-8"))[
                "records"
            ][0]["token_usage"],
            "unavailable",
        )
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
                "--json",
            ).stdout
        )
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
        self.cli(
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
            "--execution-selection-id",
            "rtl-num-hybrid-current",
        )
        self.cli(
            "packet-update",
            "--task",
            "topology-governance",
            "--packet-id",
            "topology-bound-investigation",
            "--status",
            "dispatched",
            "--agent-id",
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
        terminal_log = Path("/tmp/topology-transition-run/driver.log")
        terminal_log.parent.mkdir(parents=True, exist_ok=True)
        terminal_log.write_text("PASS exit=0\n", encoding="utf-8")
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
        refreshed = self.git_commit("unknown-launch-refreshed")
        self.revise_lane(
            "unknown-launch",
            "rtl",
            authority_commit=refreshed,
            change_class="evidence_only",
            contract_version="cv1",
            generator_version="gv1",
            adapter_version="av1",
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
        terminal_log = Path("/tmp/unknown-launch-run/driver.log")
        terminal_log.parent.mkdir(parents=True, exist_ok=True)
        terminal_log.write_text("PASS exit=0\n", encoding="utf-8")
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
            self.cli(
                "packet-update",
                "--task",
                "improvement-parent",
                "--packet-id",
                packet_id,
                "--status",
                "dispatched",
                "--agent-id",
                f"/root/{packet_id}",
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
        self.cli(
            "packet-update",
            "--task",
            "waveform-skill-project",
            "--packet-id",
            "skill-independent-review",
            "--status",
            "dispatched",
            "--agent-id",
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
            self.cli(
                "packet-update",
                "--task",
                "improvement-parent",
                "--packet-id",
                packet_id,
                "--status",
                "dispatched",
                "--agent-id",
                f"/root/{packet_id}",
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
        self.assertIn("does not postdate the bound canary", stale_units_rejected.stderr)
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
    def test_start_mini_is_atomic_constrained_and_preapproved(self) -> None:
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
        self.install_hook_layers()
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
        self.install_hook_layers()
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
        linked_destination.symlink_to(real_destination, target_is_directory=True)
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


class ConfigurationTests(HarnessTestCase):
    def test_custom_profile_drives_state_roles_evidence_and_external_namespace(self) -> None:
        config = self.root / "aoi.toml"
        text = config.read_text(encoding="utf-8")
        text = text.replace('profile_id = "generic-v1"', 'profile_id = "custom-v1"')
        text = text.replace('state_dir = ".aoi"', 'state_dir = ".org-state"')
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
        config.write_text(text, encoding="utf-8")

        self.cli("init")
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
        linked_root.symlink_to(self.root, target_is_directory=True)
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
            self.assertEqual(version.stdout.strip(), "AOI 0.1.0")
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
                "5",
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
        self.assertIn("root owns task state", subcontext)
        self.assertIn("never paste raw logs", subcontext)

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
