#!/usr/bin/env python3
"""Focused tests for AOI resource envelopes and Codex project configuration."""

from __future__ import annotations

import datetime as dt
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
from aoi_orgware import resource_config as rc  # noqa: E402
from aoi_orgware.config import load_config  # noqa: E402
from aoi_orgware.harnesslib import HarnessError, get_paths  # noqa: E402
from test_cli import HarnessTestCase  # noqa: E402


class ResourceConfigPrimitiveTests(unittest.TestCase):
    def test_safe_read_handles_short_os_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.toml"
            payload = (b"model = 'gpt-test'\n" * 8192) + b"tail = true\n"
            path.write_bytes(payload)
            real_read = os.read

            def short_read(descriptor: int, count: int) -> bytes:
                return real_read(descriptor, min(count, 17))

            with mock.patch.object(rc.os, "read", side_effect=short_read):
                self.assertEqual(rc._safe_read(path, "short-read fixture"), payload)

    def test_apply_rollback_failure_has_a_distinct_recovery_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.toml"
            second = root / "second.toml"
            first.write_bytes(b"before-first\n")
            second.write_bytes(b"before-second\n")
            files = [
                {
                    "relative_path": "first.toml",
                    "path": first,
                    "before": b"before-first\n",
                    "after": b"after-first\n",
                },
                {
                    "relative_path": "second.toml",
                    "path": second,
                    "before": b"before-second\n",
                    "after": b"after-second\n",
                },
            ]
            real_write = rc.atomic_write_bytes
            calls = 0

            def fail_apply_and_rollback(path: Path, payload: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls in {2, 3}:
                    raise OSError(f"injected write failure {calls}")
                real_write(path, payload)

            with mock.patch.object(
                rc, "atomic_write_bytes", side_effect=fail_apply_and_rollback
            ), self.assertRaises(rc.ResourceApplyRollbackError):
                rc.apply_resource_files(files)
            self.assertEqual(first.read_bytes(), b"after-first\n")
            self.assertEqual(second.read_bytes(), b"before-second\n")

    def test_post_publication_write_error_rolls_back_the_failed_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.toml"
            second = root / "second.toml"
            first.write_bytes(b"before-first\n")
            second.write_bytes(b"before-second\n")
            files = [
                {
                    "relative_path": "first.toml",
                    "path": first,
                    "before": b"before-first\n",
                    "after": b"after-first\n",
                },
                {
                    "relative_path": "second.toml",
                    "path": second,
                    "before": b"before-second\n",
                    "after": b"after-second\n",
                },
            ]
            real_write = rc.atomic_write_bytes
            calls = 0

            def fail_after_second_publication(path: Path, payload: bytes) -> None:
                nonlocal calls
                calls += 1
                real_write(path, payload)
                if calls == 2:
                    raise OSError("injected post-publication failure")

            with mock.patch.object(
                rc, "atomic_write_bytes", side_effect=fail_after_second_publication
            ), self.assertRaisesRegex(OSError, "post-publication"):
                rc.apply_resource_files(files)
            self.assertEqual(first.read_bytes(), b"before-first\n")
            self.assertEqual(second.read_bytes(), b"before-second\n")

    def test_failed_explicit_rollback_reapplies_completed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.toml"
            second = root / "second.toml"
            first.write_bytes(b"after-first\n")
            second.write_bytes(b"after-second\n")
            files = [
                {
                    "relative_path": "second.toml",
                    "path": second,
                    "before": b"before-second\n",
                    "after": b"after-second\n",
                },
                {
                    "relative_path": "first.toml",
                    "path": first,
                    "before": b"before-first\n",
                    "after": b"after-first\n",
                },
            ]
            real_write = rc.atomic_write_bytes
            calls = 0

            def fail_second_rollback_write(path: Path, payload: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected rollback write failure")
                real_write(path, payload)

            with mock.patch.object(
                rc, "atomic_write_bytes", side_effect=fail_second_rollback_write
            ), self.assertRaisesRegex(OSError, "rollback write"):
                rc._transition_resource_files(
                    files,
                    source_key="after",
                    target_key="before",
                    action="resource rollback",
                    recovery_error=rc.ResourceRollbackReapplyError,
                )
            self.assertEqual(first.read_bytes(), b"after-first\n")
            self.assertEqual(second.read_bytes(), b"after-second\n")

    def test_override_settings_are_typed_and_target_scoped(self) -> None:
        parsed = rc.parse_override_settings(
            [
                "envelope.max_active_first_level_agents=5",
                "agents.explorer.model=gpt-5.6-terra",
                "agents.explorer.model_reasoning_effort=high",
            ],
            roles={"explorer"},
            target_kind="execution_resource",
        )
        self.assertEqual(parsed["envelope.max_active_first_level_agents"], 5)
        with self.assertRaisesRegex(HarnessError, "not valid for a resource_config"):
            rc.parse_override_settings(
                ["envelope.max_delegation_depth=2"],
                target_kind="resource_config",
            )
        with self.assertRaisesRegex(HarnessError, "static resource_config setting"):
            rc.parse_override_settings(
                ["agents.max_threads=8"],
                target_kind="execution_resource",
            )

    def test_resource_envelope_caps_total_agents_across_both_depths(self) -> None:
        lanes = [
            {"lane_id": "lane-a", "role": "explorer"},
            {"lane_id": "lane-b", "role": "worker"},
        ]
        envelope, digest = cli_impl._build_execution_resource_envelope(
            mode="centralized_parallel",
            lanes=lanes,
            steward=None,
            override_id="",
            override_settings={},
        )
        self.assertEqual(envelope["max_active_first_level_agents"], 2)
        self.assertEqual(envelope["max_active_total_agents"], 4)
        with self.assertRaisesRegex(HarnessError, "unselected role"):
            cli_impl._build_execution_resource_envelope(
                mode="centralized_parallel",
                lanes=lanes,
                steward=None,
                override_id="unrelated-role",
                override_settings={
                    "agents.analysis_specialist.model": "gpt-5.6-sol"
                },
            )
        selection = {
            "selection_id": "selection",
            "mode": "centralized_parallel",
            "lane_snapshots": [
                {"lane_id": "lane-a"},
                {"lane_id": "lane-b"},
            ],
            "steward_snapshot": {},
            "resource_envelope": envelope,
            "resource_envelope_sha256": digest,
        }
        state = {
            "lanes": lanes,
            "override_requests": [],
            "packets": [
                {
                    "packet_id": "parent-a",
                    "status": "dispatched",
                    "delegation_depth": 1,
                    "execution_selection_id": "selection",
                },
                {
                    "packet_id": "parent-b",
                    "status": "dispatched",
                    "delegation_depth": 1,
                    "execution_selection_id": "selection",
                },
                {
                    "packet_id": "child-a",
                    "status": "dispatched",
                    "delegation_depth": 2,
                    "execution_selection_id": "selection",
                },
                {
                    "packet_id": "child-b",
                    "status": "armed",
                    "delegation_depth": 2,
                    "execution_selection_id": "selection",
                },
            ],
        }
        with self.assertRaisesRegex(HarnessError, "no remaining total agent slot"):
            cli_impl._validate_packet_resource_envelope(
                state,
                {
                    "packet_id": "candidate",
                    "agent_role": "explorer",
                    "model_tier": "standard",
                    "delegation_depth": 2,
                    "execution_selection_id": "selection",
                    "resource_envelope_sha256": digest,
                },
                selection,
                enforce_active_limit=True,
            )
        with self.assertRaisesRegex(HarnessError, "selected lane authority"):
            cli_impl._validate_packet_resource_envelope(
                state,
                {
                    "packet_id": "wrong-role",
                    "lane_id": "lane-a",
                    "agent_role": "default",
                    "model_tier": "standard",
                    "delegation_depth": 1,
                    "execution_selection_id": "selection",
                    "resource_envelope_sha256": digest,
                },
                selection,
                enforce_active_limit=False,
            )


class ResourceControlTests(HarnessTestCase):
    def _state(self, task_id: str) -> dict:
        return json.loads(
            (
                self.root / ".aoi" / "tasks" / task_id / "state.json"
            ).read_text(encoding="utf-8")
        )

    def _lane(
        self,
        task_id: str,
        lane_id: str,
        role: str,
        authority_commit: str,
        *,
        kind: str = "implementation",
    ) -> None:
        self.cli(
            "lane-create",
            "--task",
            task_id,
            "--lane-id",
            lane_id,
            "--kind",
            kind,
            "--owner",
            f"{lane_id}-owner",
            "--role",
            role,
            "--authority-commit",
            authority_commit,
            "--contract-version",
            "cv1",
            "--generator-version",
            "gv1",
            "--adapter-version",
            "av1",
            "--next-action",
            f"Advance bounded {lane_id} work",
        )

    def _packet(
        self, task_id: str, packet_id: str, lane_id: str, role: str, tier: str
    ) -> None:
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
            f"Inspect the exact bounded evidence for {lane_id}",
            "--scope",
            "Read-only work under the selected resource envelope",
            "--deliverable",
            "One evidence-backed bounded conclusion",
            "--validation",
            "Chief checks the result against the packet and resource authority",
            "--lane-id",
            lane_id,
            "--execution-selection-id",
            "resource-selection",
        )

    def test_chief_approved_user_override_is_exact_and_consumed_by_selection(self) -> None:
        task_id = "resource-override"
        root_session = "resource-root"
        self.init_task(task_id, root_session)
        head = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        roles = [
            ("lane-a", "explorer", "standard"),
            ("lane-b", "worker", "advanced"),
            ("lane-c", "reviewer", "expert"),
            ("lane-d", "architect", "frontier"),
            ("lane-e", "batch", "economical"),
            ("lane-f", "default", "standard"),
        ]
        for lane_id, role, _tier in roles:
            self._lane(task_id, lane_id, role, head)
        self._lane(
            task_id,
            "steward",
            "reviewer",
            head,
            kind="coordination_steward",
        )
        expires_at = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        ).isoformat()
        selection_args = [
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "resource-selection",
            "--work-unit-id",
            "resource-work",
            "--mode",
            "centralized_parallel",
        ]
        for lane_id, _role, _tier in roles:
            selection_args.extend(["--lane", lane_id])
        selection_args.extend(
            [
                "--steward-lane-id",
                "steward",
                "--scope",
                "Independent read-only evidence passes across six selected lanes",
                "--sequential-dependency",
                "low",
                "--tool-density",
                "low",
                "--shared-context",
                "low",
                "--rationale",
                "Disjoint evidence questions benefit from bounded parallel execution",
                "--falsification-condition",
                "Any same-lane conflict or shared mutable dependency invalidates parallelism",
                "--escalation-condition",
                "Chief reduces the active wave if contention appears",
                "--session-id",
                root_session,
                "--override-id",
                "raise-first-level-cap",
            ]
        )
        preview_args = list(selection_args)
        preview_args[0] = "execution-select-plan"
        preview_args.extend(
            [
                "--proposed-setting",
                "envelope.max_active_first_level_agents=5",
                "--proposed-setting",
                "agents.explorer.model=gpt-5.6-sol",
                "--proposed-setting",
                "agents.explorer.model_reasoning_effort=high",
                "--json",
            ]
        )
        target_contract = json.loads(self.cli(*preview_args).stdout)
        self.cli(
            "override-request",
            "--task",
            task_id,
            "--override-id",
            "raise-first-level-cap",
            "--target-kind",
            "execution_resource",
            "--target-id",
            "resource-selection",
            "--target-contract-sha256",
            target_contract["target_contract_sha256"],
            "--scope",
            "Raise only this six-lane selection from the default four active specialists to five",
            "--setting",
            "envelope.max_active_first_level_agents=5",
            "--setting",
            "agents.explorer.model=gpt-5.6-sol",
            "--setting",
            "agents.explorer.model_reasoning_effort=high",
            "--user-rationale",
            "The user values latency for this independent six-lane evidence pass",
            "--user-evidence",
            "Six selected lanes have disjoint scopes and no same-lane overlap",
            "--chief-assessment",
            "Five concurrent specialists remain below the hard twelve-thread ceiling",
            "--alternative",
            "Keep the default four-agent wave and dispatch the remaining lanes later",
            "--expires-at",
            expires_at,
            "--session-id",
            root_session,
        )
        changed_approval = self.cli(
            "override-arbitrate",
            "--task",
            task_id,
            "--override-id",
            "raise-first-level-cap",
            "--expected-version",
            "1",
            "--decision",
            "approved",
            "--approved-setting",
            "envelope.max_active_first_level_agents=4",
            "--rationale",
            "Chief would prefer a different resource setting",
            "--risk-boundary",
            "The original semantic target contract must not be silently reused",
            "--rollback-condition",
            "Create a new proposal if the setting changes",
            "--compensating-control",
            "Reject contract-changing arbitration",
            "--session-id",
            root_session,
            ok=False,
        )
        self.assertIn("requires a new target contract", changed_approval.stderr)
        self.cli(
            "override-arbitrate",
            "--task",
            task_id,
            "--override-id",
            "raise-first-level-cap",
            "--expected-version",
            "1",
            "--decision",
            "approved",
            "--rationale",
            "Chief accepts one extra independent lane for this exact selection",
            "--risk-boundary",
            "No same-lane overlap and no change to depth, claims, evidence, or provider limits",
            "--rollback-condition",
            "Stop arming new packets if contention or stale topology appears",
            "--compensating-control",
            "Packet arm revalidates the exact envelope and active count",
            "--session-id",
            root_session,
        )
        semantic_reuse = list(selection_args)
        scope_index = semantic_reuse.index("--scope") + 1
        semantic_reuse[scope_index] = (
            "A materially different selection hidden behind the same identifier"
        )
        rejected_reuse = self.cli(*semantic_reuse, ok=False)
        self.assertIn("different canonical contract", rejected_reuse.stderr)
        self.cli(*selection_args)
        state = self._state(task_id)
        override = state["override_requests"][0]
        selection = state["execution_selections"][0]
        self.assertEqual(override["status"], "consumed")
        self.assertEqual(override["version"], 3)
        self.assertEqual(
            selection["resource_envelope"]["max_active_first_level_agents"], 5
        )
        self.assertEqual(
            selection["resource_envelope"]["role_config_overrides"],
            {
                "agents.explorer.model": "gpt-5.6-sol",
                "agents.explorer.model_reasoning_effort": "high",
            },
        )
        self.assertEqual(
            override["consumption"]["resource_envelope_sha256"],
            selection["resource_envelope_sha256"],
        )
        self.assertEqual(cli_impl.override_integrity_errors(state), [])
        self.assertEqual(cli_impl.resource_envelope_integrity_errors(state), [])
        forged = json.loads(json.dumps(state))
        forged_envelope = forged["execution_selections"][0]["resource_envelope"]
        forged_envelope["max_active_first_level_agents"] = 6
        forged_envelope["max_active_total_agents"] = 12
        forged_digest = cli_impl.canonical_record_sha256(forged_envelope)
        forged["execution_selections"][0][
            "resource_envelope_sha256"
        ] = forged_digest
        forged["override_requests"][0]["consumption"][
            "resource_envelope_sha256"
        ] = forged_digest
        forged_errors = cli_impl.resource_envelope_integrity_errors(forged)
        self.assertTrue(forged_errors)
        self.assertTrue(
            any(
                "override consumption binding is invalid" in error
                or "differs from its topology/Chief authority" in error
                or "target contract lost integrity" in error
                for error in forged_errors
            )
        )
        for index, (lane_id, role, tier) in enumerate(roles, start=1):
            self._packet(task_id, f"packet-{index}", lane_id, role, tier)
        packet_state = self._state(task_id)
        tampered_packet = json.loads(json.dumps(packet_state["packets"][0]))
        tampered_packet["resource_envelope_sha256"] = "b" * 64
        self.assertIn(
            "lost its exact resource authority",
            cli_impl.packet_contract_integrity_error(
                get_paths(self.root), packet_state, tampered_packet
            ),
        )
        for index in range(1, 6):
            self.dispatch_packet(
                task_id,
                f"packet-{index}",
                f"agent-{index}",
            )
        rejected = self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            "packet-6",
            "--parent-session-id",
            root_session,
            "--expected-agent-type",
            "default",
            "--expires-at",
            (
                dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
            ).isoformat(),
            ok=False,
        )
        self.assertIn("no remaining first-level agent slot", rejected.stderr)

    def test_project_config_plan_apply_and_rollback_preserve_exact_bytes(self) -> None:
        codex_home = Path(self.env["CODEX_HOME"])
        agents = codex_home / "agents"
        agents.mkdir(parents=True)
        (agents / "explorer.toml").write_text(
            "\n".join(
                [
                    'name = "explorer"',
                    'description = "Read-only repository exploration"',
                    'developer_instructions = "Inspect only the bounded scope."',
                    'model = "gpt-5.6-terra"',
                    'model_reasoning_effort = "medium"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        state = {
            "task_id": "resource-files",
            "plan_sha256": "b" * 64,
            "lanes": [{"status": "active", "role": "explorer"}],
            "packets": [],
            "execution_selections": [],
        }
        with mock.patch.object(rc, "_safe_read", wraps=rc._safe_read) as reads:
            plan, files = rc.build_codex_resource_plan(
                event_id="resource-files-event",
                root=self.root,
                config=load_config(self.root),
                state=state,
                codex_home=codex_home,
                managed_roles=["explorer"],
            )
        user_profile = agents / "explorer.toml"
        self.assertEqual(
            sum(Path(call.args[0]) == user_profile for call in reads.call_args_list),
            1,
        )
        self.assertEqual(plan["resolved"]["max_threads"], 12)
        self.assertEqual(plan["resolved"]["max_depth"], 2)
        self.assertTrue(plan["restart_required"])
        alternate_plan, _alternate_files = rc.build_codex_resource_plan(
            event_id="different-resource-event",
            root=self.root,
            config=load_config(self.root),
            state=state,
            codex_home=codex_home,
            managed_roles=["explorer"],
        )
        self.assertNotEqual(plan["plan_sha256"], alternate_plan["plan_sha256"])
        with mock.patch.object(rc, "RESOURCE_FILE_MAX_COUNT", 1), self.assertRaisesRegex(
            HarnessError, "1-file limit"
        ):
            rc.build_codex_resource_plan(
                event_id="resource-files-event",
                root=self.root,
                config=load_config(self.root),
                state=state,
                codex_home=codex_home,
                managed_roles=["explorer"],
            )
        selected_state = {
            **state,
            "execution_selections": [
                {
                    "status": "active",
                    "selection_id": "selected-work",
                    "resource_envelope": {
                        "max_active_first_level_agents": 2,
                        "max_active_total_agents": 4,
                        "max_delegation_depth": 2,
                        "role_model_tiers": {"explorer": "standard"},
                        "role_config_overrides": {
                            "agents.explorer.model": "gpt-5.6-sol",
                            "agents.explorer.model_reasoning_effort": "high",
                        },
                    },
                    "resource_envelope_sha256": "a" * 64,
                }
            ],
        }
        with self.assertRaisesRegex(HarnessError, "below the selected AOI"):
            rc.build_codex_resource_plan(
                event_id="resource-files-event",
                root=self.root,
                config=load_config(self.root),
                state=selected_state,
                codex_home=codex_home,
                managed_roles=["explorer"],
                platform_max_threads=3,
            )
        selected_plan, _selected_files = rc.build_codex_resource_plan(
            event_id="resource-files-event",
            root=self.root,
            config=load_config(self.root),
            state=selected_state,
            codex_home=codex_home,
            managed_roles=["explorer"],
        )
        self.assertEqual(
            selected_plan["resolved"]["agents"]["explorer"]["model"],
            "gpt-5.6-sol",
        )
        self.assertEqual(
            selected_plan["resolved"]["agents"]["explorer"]
            ["model_reasoning_effort"],
            "high",
        )
        rc.apply_resource_files(files)
        project_config = self.root / ".codex" / "config.toml"
        project_agent = self.root / ".codex" / "agents" / "explorer.toml"
        self.assertIn("max_threads = 12", project_config.read_text(encoding="utf-8"))
        self.assertIn(
            'model_reasoning_effort = "medium"',
            project_agent.read_text(encoding="utf-8"),
        )
        receipt = rc.make_resource_receipt(
            event_id="resource-files-event",
            plan=plan,
            files=files,
            applied_at="2026-07-15T00:00:00+00:00",
            root_session_id="resource-root",
        )
        tampered_receipt = json.loads(json.dumps(receipt))
        tampered_receipt["files"][0]["source_kind"] = "forged"
        with self.assertRaisesRegex(HarnessError, "source identity is invalid"):
            rc.validate_resource_receipt(tampered_receipt)
        applied_agent = project_agent.read_bytes()
        project_config.write_bytes(project_config.read_bytes() + b"# drift\n")
        with self.assertRaisesRegex(HarnessError, "target drifted"):
            rc.rollback_files_from_receipt(root=self.root, receipt=receipt)
        self.assertEqual(project_agent.read_bytes(), applied_agent)
        project_config.write_bytes(files[0]["after"])
        rc.rollback_files_from_receipt(root=self.root, receipt=receipt)
        self.assertFalse(project_config.exists())
        self.assertFalse(project_agent.exists())

    def test_cli_config_override_is_exact_single_use_and_rollbackable(self) -> None:
        task_id = "resource-config-cli"
        root_session = "resource-config-root"
        event_id = "resource-config-event"
        self.init_task(task_id, root_session)
        codex_home = Path(self.env["CODEX_HOME"])
        agents = codex_home / "agents"
        agents.mkdir(parents=True)
        (agents / "explorer.toml").write_text(
            "\n".join(
                [
                    'name = "explorer"',
                    'description = "Read-only repository exploration"',
                    'developer_instructions = "Inspect only the bounded scope."',
                    'model = "gpt-5.6-terra"',
                    'model_reasoning_effort = "medium"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        expires_at = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        ).isoformat()
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "resource-config-files",
            "--owner",
            "resource-config-root",
            "--kind",
            "implementation",
            "--lock",
            "repo:tree:.codex",
            "--intent",
            "Apply and roll back the exact project-scoped Codex resource files",
            "--validation",
            "Receipt hashes bind every before and after byte sequence",
            "--expires-at",
            expires_at,
        )
        draft_plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                event_id,
                "--override-id",
                "resource-config-model",
                "--role",
                "explorer",
                "--proposed-setting",
                "agents.explorer.model=gpt-5.6-sol",
                "--proposed-setting",
                "agents.explorer.model_reasoning_effort=high",
                "--json",
            ).stdout
        )
        self.cli(
            "override-request",
            "--task",
            task_id,
            "--override-id",
            "resource-config-model",
            "--target-kind",
            "resource_config",
            "--target-id",
            event_id,
            "--target-contract-sha256",
            draft_plan["plan_sha256"],
            "--scope",
            "Change only the explorer project profile for the named config event",
            "--setting",
            "agents.explorer.model=gpt-5.6-sol",
            "--setting",
            "agents.explorer.model_reasoning_effort=high",
            "--user-rationale",
            "The user requests deeper repository reasoning for the current ARISE phase",
            "--user-evidence",
            "The explorer owns a bounded cross-module source investigation",
            "--chief-assessment",
            "The stronger profile is justified for this exact project event",
            "--alternative",
            "Keep the existing terra medium explorer profile",
            "--expires-at",
            expires_at,
            "--session-id",
            root_session,
        )
        changed_approval = self.cli(
            "override-arbitrate",
            "--task",
            task_id,
            "--override-id",
            "resource-config-model",
            "--expected-version",
            "1",
            "--decision",
            "approved",
            "--approved-setting",
            "agents.explorer.model=gpt-5.6-terra",
            "--rationale",
            "Chief would prefer a different model request",
            "--risk-boundary",
            "The reviewed config contract must not change in arbitration",
            "--rollback-condition",
            "Create a new config proposal if the model changes",
            "--compensating-control",
            "Reject contract-changing arbitration",
            "--session-id",
            root_session,
            ok=False,
        )
        self.assertIn("requires a new target contract", changed_approval.stderr)
        self.cli(
            "override-arbitrate",
            "--task",
            task_id,
            "--override-id",
            "resource-config-model",
            "--expected-version",
            "1",
            "--decision",
            "approved",
            "--rationale",
            "Chief approves the bounded explorer profile change",
            "--risk-boundary",
            "Configuration does not prove runtime routing and requires a fresh trusted session",
            "--rollback-condition",
            "Restore the exact receipt bytes if the new session is not usable",
            "--compensating-control",
            "Record requested routing as unverified until platform evidence exists",
            "--session-id",
            root_session,
        )
        profile_path = agents / "explorer.toml"
        reviewed_profile = profile_path.read_bytes()
        profile_path.write_bytes(
            reviewed_profile.replace(
                b"Read-only repository exploration",
                b"Changed after Chief review",
            )
        )
        drifted_plan = self.cli(
            "codex-config-plan",
            "--task",
            task_id,
            "--event-id",
            event_id,
            "--override-id",
            "resource-config-model",
            "--role",
            "explorer",
            ok=False,
        )
        self.assertIn("different canonical contract", drifted_plan.stderr)
        profile_path.write_bytes(reviewed_profile)
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                event_id,
                "--override-id",
                "resource-config-model",
                "--role",
                "explorer",
                "--json",
            ).stdout
        )
        self.assertEqual(
            plan["resolved"]["agents"]["explorer"]["model"], "gpt-5.6-sol"
        )
        self.assertEqual(plan["plan_sha256"], draft_plan["plan_sha256"])
        self.cli(
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            event_id,
            "--override-id",
            "resource-config-model",
            "--role",
            "explorer",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            root_session,
        )
        state = self._state(task_id)
        self.assertEqual(state["override_requests"][0]["status"], "consumed")
        self.assertEqual(state["override_requests"][0]["version"], 3)
        self.assertEqual(state["resource_config_events"][0]["status"], "applied")
        self.assertEqual(cli_impl.override_integrity_errors(state), [])
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(get_paths(self.root), state), []
        )
        tampered = json.loads(json.dumps(state))
        tampered["resource_config_events"][0]["resolved"]["agents"]["explorer"][
            "model"
        ] = "gpt-forged"
        self.assertTrue(
            any(
                "receipt binding is invalid" in error
                for error in cli_impl.resource_config_integrity_errors(
                    get_paths(self.root), tampered
                )
            )
        )
        project_agent = self.root / ".codex" / "agents" / "explorer.toml"
        self.assertIn(
            'model = "gpt-5.6-sol"', project_agent.read_text(encoding="utf-8")
        )
        replay = self.cli(
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            event_id,
            "--override-id",
            "resource-config-model",
            "--role",
            "explorer",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            root_session,
            ok=False,
        )
        self.assertIn("event already exists", replay.stderr)
        invalid_reason = self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            event_id,
            "--reason",
            " ",
            "--session-id",
            root_session,
            ok=False,
        )
        self.assertIn("rollback reason", invalid_reason.stderr)
        self.assertTrue(project_agent.exists())
        with mock.patch.object(
            cli_impl,
            "write_task",
            side_effect=HarnessError("injected rollback state write failure"),
        ):
            failed_publish = self.cli_in_process(
                "codex-config-rollback",
                "--task",
                task_id,
                "--event-id",
                event_id,
                "--reason",
                "Exercise exact file re-apply after state publication failure",
                "--session-id",
                root_session,
                ok=False,
            )
        self.assertIn("exact applied bytes were restored", failed_publish.stderr)
        self.assertEqual(self._state(task_id)["resource_config_events"][0]["status"], "applied")
        self.assertIn(
            'model = "gpt-5.6-sol"', project_agent.read_text(encoding="utf-8")
        )
        self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            event_id,
            "--reason",
            "Test exact byte restoration after the governed config event",
            "--session-id",
            root_session,
        )
        state = self._state(task_id)
        self.assertEqual(
            state["resource_config_events"][0]["status"], "rolled_back"
        )
        self.assertEqual(cli_impl.override_integrity_errors(state), [])
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(get_paths(self.root), state), []
        )
        self.assertFalse((self.root / ".codex" / "config.toml").exists())
        self.assertFalse(project_agent.exists())


if __name__ == "__main__":
    unittest.main()
