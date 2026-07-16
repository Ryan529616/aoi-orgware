#!/usr/bin/env python3
"""Shared CLI integration-test fixture without importing the full test suite."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402


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
        self.env["AOI_CHIEF_CREDENTIAL_HOME"] = str(
            Path(self.backup_temp.name) / "aoi-chief-credentials"
        )
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
        acquired = json.loads(
            self.cli(
                "chief-acquire",
                "--session-id",
                "harness-test-chief",
                "--json",
            ).stdout
        )
        self.chief_credential_file = acquired["credential_file"]
        self.chief_epoch = int(acquired["authority"]["epoch"])
        self.env["AOI_CHIEF_SESSION_ID"] = "harness-test-chief"
        self.env["AOI_CHIEF_EPOCH"] = str(self.chief_epoch)
        self.env["AOI_CHIEF_CREDENTIAL_FILE"] = self.chief_credential_file
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

    def cli_in_process(
        self, *args: str, ok: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Exercise the full CLI without the Windows CreateProcess argv ceiling."""
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch(
            "sys.stdout", captured_stdout
        ), mock.patch("sys.stderr", captured_stderr):
            returncode = cli_impl.main(list(args))
        result = subprocess.CompletedProcess(
            [sys.executable, "-m", CLI_MODULE, *args],
            returncode,
            captured_stdout.getvalue(),
            captured_stderr.getvalue(),
        )
        if ok and result.returncode != 0:
            self.fail(
                f"in-process CLI failed ({result.returncode})\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        if not ok:
            if result.returncode == 0:
                self.fail("in-process CLI unexpectedly succeeded")
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

    def arm_packet(
        self,
        task_id: str,
        packet_id: str,
        *,
        expected_agent_type: str | None = None,
        parent_session_id: str | None = None,
    ) -> None:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        packet = next(
            item for item in state["packets"] if item["packet_id"] == packet_id
        )
        if int(packet.get("delegation_depth", 1)) == 1:
            if parent_session_id is None:
                suffix = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:16]
                parent_session_id = f"dispatch-parent-{suffix}"
            if parent_session_id not in state.get("session_ids", []):
                self.cli(
                    "bind-session",
                    "--task",
                    task_id,
                    "--session-id",
                    parent_session_id,
                )
        else:
            parent = next(
                item
                for item in state["packets"]
                if item["packet_id"] == packet["parent_packet_id"]
            )
            parent_session_id = str(parent["agent_id"])
        expires_at = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--parent-session-id",
            str(parent_session_id),
            "--expected-agent-type",
            expected_agent_type or str(packet.get("agent_role", "default")),
            "--expires-at",
            expires_at,
        )

    def dispatch_packet(
        self, task_id: str, packet_id: str, agent_id: str, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        self.arm_packet(task_id, packet_id)
        return self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "dispatched",
            "--agent-id",
            agent_id,
            *extra,
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
        asserts_completion_boundary: bool = True,
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
        if asserts_completion_boundary:
            args.append("--asserts-completion-boundary")
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

    def write_terminal_log(
        self, name: str, payload: bytes = b"PASS exit=0\n"
    ) -> tuple[Path, str]:
        terminal_log = self.root / "terminal-log-fixtures" / name
        terminal_log.parent.mkdir(parents=True, exist_ok=True)
        terminal_log.write_bytes(payload)
        return terminal_log, hashlib.sha256(payload).hexdigest()

    def hook(self, payload: dict, bom: bool = False) -> dict:
        raw = json.dumps(payload).encode("utf-8")
        if bom:
            raw = b"\xef\xbb\xbf" + raw
        result = subprocess.run(
            [sys.executable, "-m", HOOK_MODULE, "--hook-version", "6"],
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
                            "command": "aoi-codex-hook --hook-version 6",
                            "commandWindows": "wsl aoi-codex-hook --hook-version 6",
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
