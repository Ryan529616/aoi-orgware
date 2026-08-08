"""AOI-SYNTHETIC-FIXTURE-V1 exact-command ownership regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aoi_orgware import cli as cli_impl
from aoi_orgware import harnesslib as h
from aoi_orgware.legacy_bridge_snapshot_v04 import (
    produce_legacy_bridge_snapshot_v04,
)
from tests.harness_case import HarnessTestCase


class JobStartCommandOwnershipTests(HarnessTestCase):
    def _prepare_exact_owner(
        self,
    ) -> tuple[str, bytes, Path, str, str, str, str]:
        task_id = "job-command-owner"
        packet_id = "job-command-packet"
        work_root = "/tmp/aoi-job-command-owner"
        log = f"{work_root}/driver.log"
        raw_command = b"printf 'intentional terminal failure\\n'\r\nexit 3\r\n\r\n \t"
        command_artifact = self.root / "job-command.sh"
        command_artifact.write_bytes(raw_command)
        self.init_task(task_id)
        self.cli(
            "claim", "--task", task_id, "--token", "job-command-claim",
            "--owner", "test-root", "--kind", "EDA-RUN",
            "--lock", "repo:file:job-command.sh",
            "--lock", f"external:tree:{work_root}",
            "--intent", "Own one exact external command and output tree",
            "--validation", "Canonical packet and job command must match",
            "--expires-at", "2099-01-01T00:00:00+00:00",
        )
        self.cli(
            "create-packet", "--task", task_id, "--packet-id", packet_id,
            "--agent-role", "external_operator", "--model-tier", "standard",
            "--objective", "Run exactly one intentional nonzero command",
            "--scope", "Only the claimed command and output tree",
            "--deliverable", "Terminal log and manifest",
            "--validation", "Exact command identity and terminal receipt",
            "--packet-mode", "exact_command",
            "--lock", "repo:file:job-command.sh",
            "--lock", f"external:tree:{work_root}",
            "--command-artifact", str(command_artifact),
            "--command-sha256", hashlib.sha256(raw_command).hexdigest(),
        )
        self.dispatch_packet(task_id, packet_id, "/home/tester/job-command-agent")
        canonical = cli_impl.packet_integrity_impl.normalize_exact_command_bytes(
            raw_command,
        )
        receipt, receipt_sha = self.write_source_receipt(
            "job-command-source.json",
            command=canonical.decode("utf-8"),
        )
        return task_id, canonical, receipt, receipt_sha, work_root, log, packet_id

    def test_crlf_command_uses_one_packet_job_and_bridge_identity(self) -> None:
        task_id, canonical, receipt, receipt_sha, work_root, log, packet_id = (
            self._prepare_exact_owner()
        )
        self.cli(
            "job-start", "--task", task_id, "--run-id", "run-1",
            "--host", "eda", "--tool", "VCS",
            "--work-root", work_root, "--status", "queued",
            "--log", log, "--stop-condition", "intentional exit 3",
            "--source-sha", receipt_sha, "--source-manifest", str(receipt),
            "--tool-path", "/tools/vcs", "--tool-version", "VCS-test",
            "--owner-packet-id", packet_id,
            "--command", "printf 'intentional terminal failure\\n'\r\nexit 3\r\n\r\n \t",
        )
        paths = h.get_paths(self.root)
        state = json.loads(
            (paths.tasks / task_id / "state.json").read_text(encoding="utf-8"),
        )
        job = next(item for item in state["jobs"] if item["run_id"] == "run-1")
        packet = next(
            item for item in state["packets"] if item["packet_id"] == packet_id
        )
        assert Path(job["command_path"]).read_bytes() == canonical
        assert job["command_sha256"] == packet["command_sha256"]
        assert job["command_size_bytes"] == packet["command_size_bytes"]
        assert job["command_normalization"] == "terminal-whitespace-lf-v1"
        assert cli_impl.job_integrity_errors(paths, state) == []
        produced = produce_legacy_bridge_snapshot_v04(
            paths,
            task_id,
            "company-1",
            1,
            1,
            "a" * 64,
            "0.4.0a4",
            "2026-08-08T00:00:00Z",
        )
        entities = {item.kind: item for item in produced.projection.entities}
        assert entities["job"].parent_bridge_entity_id == entities[
            "packet"
        ].bridge_entity_id
        assert entities["job"].orphan_reason is None

    def test_job_without_owner_packet_fails_before_state_or_command_write(self) -> None:
        task_id, canonical, receipt, receipt_sha, work_root, log, _packet_id = (
            self._prepare_exact_owner()
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        before = state_path.read_bytes()
        rejected = self.cli(
            "job-start", "--task", task_id, "--run-id", "run-missing-owner",
            "--host", "eda", "--tool", "VCS",
            "--work-root", work_root, "--status", "queued",
            "--log", log, "--stop-condition", "intentional exit 3",
            "--source-sha", receipt_sha, "--source-manifest", str(receipt),
            "--tool-path", "/tools/vcs", "--tool-version", "VCS-test",
            "--command", canonical.decode("utf-8"),
            ok=False,
        )
        assert "requires --owner-packet-id" in rejected.stderr
        assert state_path.read_bytes() == before
        assert not (
            self.root / ".aoi" / "tasks" / task_id / "results"
            / "job-command-run-missing-owner.txt"
        ).exists()
