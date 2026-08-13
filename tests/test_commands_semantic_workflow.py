from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from aoi_orgware import cli as cli_impl
from aoi_orgware.ic_rag import ICRagDocumentV1, document_manifest_dict
from aoi_orgware.semantic_events import canonical_json_bytes

from tests.harness_case import HarnessTestCase


STAMP = "2099-01-01T00:00:00+00:00"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def documents() -> tuple[ICRagDocumentV1, ...]:
    result = []
    for index, (kind, authority) in enumerate(
        (
            ("project_graph", "project_design_intent"),
            ("ic_knowledge_base", "reviewed_reference"),
            ("eda_runbook", "operational_guidance"),
        ),
        start=1,
    ):
        text = f"RTL compile runtime evidence from {kind}."
        result.append(
            ICRagDocumentV1(
                source_id=f"source-{index}",
                source_kind=kind,
                authority=authority,
                source_generation_sha256=hashlib.sha256(f"generation-{index}".encode()).hexdigest(),
                freshness="fresh",
                freshness_checked_at="2026-08-11T06:00:00+00:00",
                freshness_evidence_sha256=hashlib.sha256(f"fresh-{index}".encode()).hexdigest(),
                document_id=f"document-{index}",
                locator=f"docs/source-{index}.md",
                content_sha256=hashlib.sha256(text.encode()).hexdigest(),
                content_size_bytes=len(text.encode()),
                text=text,
            )
        )
    return tuple(result)


def request(operation: str, operation_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operation": operation,
        "task_id": "semantic-ic",
        "operation_id": operation_id,
        "payload": payload,
    }


class SemanticWorkflowCommandTests(HarnessTestCase):
    TASK = "semantic-ic"

    def setUp(self) -> None:
        super().setUp()
        self.cli(
            "init-task",
            "--task-id",
            self.TASK,
            "--title",
            "Semantic IC workflow",
            "--objective",
            "Exercise the closed Phase-1 semantic workflow",
            "--owner",
            "test-root",
            "--completion-boundary",
            "Workflow replay remains deterministic",
            "--semantic-v2",
            "--semantic-command-id",
            "semantic-ic-genesis",
            "--json",
        )
        self.manifest = self.root / "ic-rag-manifest.json"
        manifest_bytes = canonical_json_bytes(document_manifest_dict(documents()))
        self.manifest.write_bytes(manifest_bytes)
        self.manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

    def head(self) -> str:
        return json.loads(
            self.cli("semantic-head", "--task", self.TASK, "--json").stdout
        )["event_sha256"]

    def write_request(self, value: dict[str, Any]) -> tuple[Path, str]:
        path = self.root / f"{value['operation_id']}.json"
        data = canonical_json_bytes(value)
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def apply(
        self,
        value: dict[str, Any],
        *,
        expected_head: str | None = None,
        with_rag: bool = False,
        ok: bool = True,
    ):
        path, digest = self.write_request(value)
        args = [
            "semantic-workflow-apply",
            "--task",
            self.TASK,
            "--request",
            str(path),
            "--request-sha256",
            digest,
            "--command-id",
            value["operation_id"],
            "--expected-head-sha256",
            expected_head or self.head(),
            "--recorded-at",
            STAMP,
            "--json",
        ]
        if with_rag:
            args.extend(
                [
                    "--rag-manifest",
                    str(self.manifest),
                    "--rag-manifest-sha256",
                    self.manifest_sha,
                ]
            )
        return self.cli(*args, ok=ok)

    def plan(self) -> dict[str, Any]:
        return request(
            "plan_publish",
            "plan-1",
            {
                "plan_id": "plan-1",
                "plan_sha256": SHA_A,
                "source_manifest_sha256": SHA_B,
                "objective": "Run one tiny compile fixture.",
                "query": "RTL compile runtime evidence",
            },
        )

    def test_apply_exact_retry_and_show_are_event_stable(self) -> None:
        before = self.head()
        first = json.loads(self.apply(self.plan(), expected_head=before, with_rag=True).stdout)
        self.assertFalse(first["idempotent_replay"])
        current = self.head()
        self.assertNotEqual(current, before)
        replay = json.loads(self.apply(self.plan(), expected_head=before, with_rag=True).stdout)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["semantic_head_sha256"], current)
        self.assertEqual(self.head(), current)

        show_env = self.env.copy()
        for key in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
        ):
            show_env.pop(key, None)
        prior = self.env
        self.env = show_env
        try:
            shown = json.loads(
                self.cli("semantic-workflow-show", "--task", self.TASK, "--json").stdout
            )
        finally:
            self.env = prior
        self.assertEqual(shown["semantic_head_sha256"], current)
        self.assertEqual(shown["workflow"]["record_count"], 1)
        self.assertEqual(shown["workflow"]["plan"]["context_receipt"]["audience"], "rtl")
        self.assertIn("semantic-workflow-show", cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS)

    def test_stale_head_divergent_command_and_manifest_mismatch_zero_append(self) -> None:
        before = self.head()
        self.apply(self.plan(), expected_head=before, with_rag=True)
        current = self.head()
        other = self.plan()
        other["operation_id"] = "plan-other"
        rejected = self.apply(other, expected_head=before, with_rag=True, ok=False)
        self.assertIn("expected head", rejected.stderr)
        self.assertEqual(self.head(), current)

        changed = self.plan()
        changed["payload"]["objective"] = "Different objective"
        conflict = self.apply(changed, expected_head=before, with_rag=True, ok=False)
        self.assertIn("different semantics", conflict.stderr)
        self.assertEqual(self.head(), current)

        path, digest = self.write_request(
            request(
                "claim_create",
                "claim-1",
                {
                    "claim_id": "claim-1",
                    "locks": ["external:tree:/tmp/ic-command"],
                    "intent": "Own isolated output.",
                    "validation": "Hash artifacts before review.",
                },
            )
        )
        bad = self.cli(
            "semantic-workflow-apply",
            "--task",
            self.TASK,
            "--request",
            str(path),
            "--request-sha256",
            "0" * 64,
            "--command-id",
            "claim-1",
            "--expected-head-sha256",
            current,
            "--recorded-at",
            STAMP,
            "--json",
            ok=False,
        )
        self.assertIn("SHA-256 mismatch", bad.stderr)
        self.assertNotEqual(digest, "0" * 64)
        self.assertEqual(self.head(), current)

    def test_manifest_is_required_only_for_plan_and_verification(self) -> None:
        missing = self.apply(self.plan(), ok=False)
        self.assertIn("requires --rag-manifest", missing.stderr)
        self.apply(self.plan(), with_rag=True)
        claim = request(
            "claim_create",
            "claim-1",
            {
                "claim_id": "claim-1",
                "locks": ["external:tree:/tmp/ic-command"],
                "intent": "Own isolated output.",
                "validation": "Hash artifacts before review.",
            },
        )
        unexpected = self.apply(claim, with_rag=True, ok=False)
        self.assertIn("does not accept", unexpected.stderr)

    def test_projection_reopen_preserves_single_launch_and_unknown_effect(self) -> None:
        self.apply(self.plan(), with_rag=True)
        self.apply(
            request(
                "claim_create",
                "claim-1",
                {
                    "claim_id": "claim-1",
                    "locks": ["external:tree:/tmp/ic-command"],
                    "intent": "Own isolated output.",
                    "validation": "Hash artifacts before review.",
                },
            )
        )
        command = "printf tiny\n"
        self.apply(
            request(
                "packet_create",
                "packet-rtl-create",
                {
                    "packet_id": "packet-rtl",
                    "role": "rtl",
                    "mode": "exact_command",
                    "parent_packet_id": None,
                    "claim_ids": ["claim-1"],
                    "canonical_command": command,
                    "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
                },
            )
        )
        self.apply(
            request(
                "external_job_queue",
                "job-queue",
                {
                    "job_id": "job-1",
                    "run_id": "run-1",
                    "packet_id": "packet-rtl",
                    "source_sha256": SHA_B,
                    "tool_sha256": SHA_B,
                    "output_lock": "external:tree:/tmp/ic-command/run-1",
                },
            )
        )
        self.apply(
            request("external_job_launch", "job-launch", {"job_id": "job-1"})
        )
        self.apply(
            request(
                "external_job_observe",
                "job-observe",
                {
                    "job_id": "job-1",
                    "stage": "preflight",
                    "stage_status": "inconclusive",
                    "evidence_sha256": SHA_C,
                    "oracle_receipt": None,
                    "terminal_effect": "effect_unknown",
                    "reconcile_id": "reconcile-1",
                },
            )
        )
        head = self.head()
        relaunch = self.apply(
            request("external_job_launch", "job-relaunch", {"job_id": "job-1"}),
            ok=False,
        )
        self.assertIn("single launch", relaunch.stderr)
        self.assertEqual(self.head(), head)
        shown = json.loads(
            self.cli("semantic-workflow-show", "--task", self.TASK, "--json").stdout
        )
        self.assertEqual(shown["workflow"]["external_jobs"][0]["attempt"], 1)
        self.assertEqual(shown["workflow"]["external_jobs"][0]["effect"], "effect_unknown")

    def test_parser_and_semantic_stage_registration_are_explicit(self) -> None:
        self.assertIn("semantic-workflow-apply", cli_impl._SEMANTIC_V2_STAGE1_TARGET_COMMANDS)
        self.assertFalse(
            cli_impl.command_requires_chief("semantic-workflow-show", initialized=True)
        )
        self.assertTrue(
            cli_impl.command_requires_chief("semantic-workflow-apply", initialized=True)
        )
        help_text = " ".join(
            self.cli("semantic-workflow-apply", "--help").stdout.split()
        )
        self.assertIn("--expected-head-sha256", help_text)
        self.assertIn("--rag-manifest-sha256", help_text)


if __name__ == "__main__":
    import unittest

    unittest.main()
