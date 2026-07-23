from __future__ import annotations

import datetime as dt
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import resource as resource_cmds  # noqa: E402
from aoi_orgware.commands.resource import (  # noqa: E402
    _registration_records_for_write,
)
from aoi_orgware.harnesslib import HarnessError, get_paths, now_iso  # noqa: E402
from aoi_orgware.resource_governance import (  # noqa: E402
    current_applied_resource_event,
)
from aoi_orgware.session_receipts import (  # noqa: E402
    persist_startup_receipt,
    startup_receipt_path,
)
from tests.harness_case import HarnessTestCase  # noqa: E402


class ChiefSessionRegistrationTests(HarnessTestCase):
    def _state(self, task_id: str) -> dict:
        return json.loads(
            (
                self.root / ".aoi" / "tasks" / task_id / "state.json"
            ).read_text(encoding="utf-8")
        )

    def _prepare_applied(
        self,
        *,
        task_id: str,
        event_id: str,
        apply_session: str = "apply-root",
        store_startup: bool = True,
        allow_inapplicable: bool = False,
    ) -> tuple[dict, dict]:
        self.init_task(task_id, apply_session)
        self.cli(
            "bind-session",
            "--task",
            task_id,
            "--session-id",
            "harness-test-chief",
        )
        codex_home = Path(self.env["CODEX_HOME"])
        agents = codex_home / "agents"
        agents.mkdir(parents=True, exist_ok=True)
        (agents / "explorer.toml").write_text(
            "\n".join(
                [
                    'name = "explorer"',
                    'description = "Bounded source exploration"',
                    'developer_instructions = "Inspect only the selected scope."',
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
            f"{event_id}-files",
            "--owner",
            apply_session,
            "--kind",
            "implementation",
            "--lock",
            "repo:tree:.codex",
            "--intent",
            "Apply the exact reviewed Codex resource configuration",
            "--validation",
            "Receipt and live after bytes must remain exact",
            "--expires-at",
            expires_at,
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                event_id,
                "--role",
                "explorer",
                "--json",
            ).stdout
        )
        apply_args = [
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            event_id,
            "--role",
            "explorer",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            apply_session,
        ]
        if allow_inapplicable:
            apply_args.append("--allow-inapplicable")
        self.cli(*apply_args)
        state = self._state(task_id)
        event = next(
            item
            for item in state["resource_config_events"]
            if item["event_id"] == event_id
        )
        paths = get_paths(self.root)
        startup = {}
        if store_startup:
            startup = persist_startup_receipt(
                paths,
                {
                    "schema_version": 2,
                    "hook_protocol_version": 6,
                    "session_id": "harness-test-chief",
                    "source": "startup",
                    "observed_at": now_iso(),
                    "cwd": str(self.root),
                    "project_root": str(self.root),
                    "aoi_config_sha256": paths.project.sha256,
                },
            )
        return event, startup

    def _register(
        self,
        task_id: str,
        event: dict,
        startup: dict,
        *,
        ok: bool = True,
        session_id: str = "harness-test-chief",
    ):
        return self.cli(
            "codex-session-register",
            "--task",
            task_id,
            "--session-id",
            session_id,
            "--event-id",
            event["event_id"],
            "--expected-startup-receipt-sha256",
            startup["startup_receipt_sha256"],
            "--expected-resource-receipt-sha256",
            event["receipt_sha256"],
            "--json",
            ok=ok,
        )

    def _registration_args(
        self, task_id: str, event: dict, startup: dict
    ) -> tuple[str, ...]:
        return (
            "codex-session-register",
            "--task",
            task_id,
            "--session-id",
            "harness-test-chief",
            "--event-id",
            event["event_id"],
            "--expected-startup-receipt-sha256",
            startup["startup_receipt_sha256"],
            "--expected-resource-receipt-sha256",
            event["receipt_sha256"],
            "--json",
        )

    def test_registers_v2_and_same_epoch_renew_replays_byte_identically(self) -> None:
        task_id = "session-register-positive"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-positive"
        )
        result = json.loads(self._register(task_id, event, startup).stdout)
        registration = result["registration"]
        self.assertEqual(registration["registration_schema_version"], 2)
        self.assertEqual(registration["task_id"], task_id)
        self.assertEqual(
            registration["resource_event_applied_snapshot"]["status"], "applied"
        )
        self.assertIsNone(
            registration["resource_event_applied_snapshot"]["rollback"]
        )
        self.assertEqual(
            registration["freshness_verdict"],
            "registered_byte_state_equivalent_only",
        )
        self.assertEqual(registration["config_loaded_verified"], "unavailable")
        self.assertEqual(
            registration["registrar_chief_authority"]["session_id"],
            "harness-test-chief",
        )
        self.assertNotIn("token", json.dumps(registration).lower())
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        before = state_path.read_bytes()
        self.cli("chief-renew", "--ttl-seconds", "3600")
        replay = json.loads(self._register(task_id, event, startup).stdout)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["registration"], registration)
        self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(
                get_paths(self.root), self._state(task_id)
            ),
            [],
        )
        malformed_history = self._state(task_id)
        malformed_history["resource_config_events"][0]["status"] = "rolled_back"
        malformed_history["resource_config_events"][0]["rollback"] = "malformed"
        malformed_errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), malformed_history
        )
        self.assertTrue(
            any("malformed rollback history" in error for error in malformed_errors),
            malformed_errors,
        )
        startup_receipt_path(
            get_paths(self.root), "harness-test-chief"
        ).unlink()
        self.assertTrue(
            any(
                "startup receipt store is invalid" in error
                for error in cli_impl.resource_config_integrity_errors(
                    get_paths(self.root), self._state(task_id)
                )
            )
        )
        replacement = persist_startup_receipt(
            get_paths(self.root),
            {
                "schema_version": 2,
                "hook_protocol_version": 6,
                "session_id": "harness-test-chief",
                "source": "startup",
                "observed_at": now_iso(),
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": get_paths(self.root).project.sha256,
            },
        )
        self.assertNotEqual(replacement, registration["startup_receipt_snapshot"])
        self.assertTrue(
            any(
                "store differs from its sealed snapshot" in error
                for error in cli_impl.resource_config_integrity_errors(
                    get_paths(self.root), self._state(task_id)
                )
            )
        )

    def test_startup_receipt_show_is_read_only_and_does_not_require_chief(self) -> None:
        task_id = "session-receipt-show"
        _event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-receipt-show"
        )
        credential_env = {
            key: self.env.pop(key)
            for key in (
                "AOI_CHIEF_SESSION_ID",
                "AOI_CHIEF_EPOCH",
                "AOI_CHIEF_CREDENTIAL_FILE",
            )
        }
        try:
            shown = json.loads(
                self.cli(
                    "codex-startup-receipt-show",
                    "--session-id",
                    "harness-test-chief",
                    "--json",
                ).stdout
            )
        finally:
            self.env.update(credential_env)
        self.assertEqual(
            shown["startup_receipt_sha256"], startup["startup_receipt_sha256"]
        )
        self.assertEqual(shown["freshness_evidence"], "startup_receipt_only")
        self.assertEqual(shown["config_loaded_verified"], "unavailable")

    def test_live_drift_and_registrar_session_mismatch_are_zero_mutation(self) -> None:
        task_id = "session-register-rejections"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-rejections"
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        before = state_path.read_bytes()
        mismatch = self._register(
            task_id, event, startup, ok=False, session_id="apply-root"
        )
        self.assertIn("registrar Chief session", mismatch.stderr)
        self.assertEqual(state_path.read_bytes(), before)

        config_path = self.root / ".codex" / "config.toml"
        applied = config_path.read_bytes()
        config_path.write_bytes(applied + b"# drift\n")
        drift = self._register(task_id, event, startup, ok=False)
        self.assertIn("target drifted", drift.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        config_path.write_bytes(applied)

    def test_rollback_preserves_history_but_blocks_new_registration_and_replay(self) -> None:
        task_id = "session-register-rollback"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-rollback"
        )
        first = json.loads(self._register(task_id, event, startup).stdout)
        registration = first["registration"]
        self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            event["event_id"],
            "--reason",
            "Exercise rollback-stable historical session registration",
            "--session-id",
            "apply-root",
        )
        state = self._state(task_id)
        self.assertEqual(
            state["resource_session_registrations"][0], registration
        )
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(get_paths(self.root), state), []
        )
        ambiguous = json.loads(json.dumps(state))
        rolled_back = next(
            item
            for item in ambiguous["resource_config_events"]
            if item["event_id"] == event["event_id"]
        )
        rolled_back["rollback"]["recorded_at"] = registration["registered_at"]
        self.assertTrue(
            any(
                "postdates rollback" in error
                for error in cli_impl.resource_config_integrity_errors(
                    get_paths(self.root), ambiguous
                )
            )
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        before = state_path.read_bytes()
        blocked = self._register(task_id, event, startup, ok=False)
        self.assertIn("effective-current applied event", blocked.stderr)
        self.assertEqual(state_path.read_bytes(), before)

    def test_failed_state_publication_leaves_no_registration_and_retry_succeeds(self) -> None:
        task_id = "session-register-write-failure"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-write-failure"
        )
        args = self._registration_args(task_id, event, startup)
        with mock.patch.object(
            cli_impl,
            "write_task",
            side_effect=HarnessError("injected registration state write failure"),
        ):
            failed = self.cli_in_process(*args, ok=False)
        self.assertIn("injected registration state write failure", failed.stderr)
        self.assertEqual(
            self._state(task_id)["resource_session_registrations"], []
        )
        retry = json.loads(self.cli(*args).stdout)
        self.assertFalse(retry["idempotent_replay"])
        self.assertEqual(
            len(self._state(task_id)["resource_session_registrations"]), 1
        )

    def test_published_then_failed_state_write_is_classified_and_replay_recovers(self) -> None:
        task_id = "session-register-published-failure"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-published-failure"
        )
        args = self._registration_args(task_id, event, startup)
        real_write_task = cli_impl.write_task

        def publish_then_fail(paths, state) -> None:
            real_write_task(paths, state)
            raise HarnessError("injected post-publication failure")

        with mock.patch.object(
            cli_impl, "write_task", side_effect=publish_then_fail
        ):
            failed = self.cli_in_process(*args, ok=False)
        self.assertIn("was published but its durability step", failed.stderr)
        self.assertEqual(
            len(self._state(task_id)["resource_session_registrations"]), 1
        )
        replay = json.loads(self.cli(*args).stdout)
        self.assertTrue(replay["idempotent_replay"])

    def test_index_failure_is_repaired_by_idempotent_replay(self) -> None:
        task_id = "session-register-index-recovery"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-index-recovery"
        )
        args = self._registration_args(task_id, event, startup)
        with mock.patch.object(
            cli_impl,
            "write_index",
            side_effect=HarnessError("injected index refresh failure"),
        ):
            failed = self.cli_in_process(*args, ok=False)
        self.assertIn("durable but index refresh failed", failed.stderr)
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        before = state_path.read_bytes()
        real_write_index = cli_impl.write_index
        with mock.patch.object(
            cli_impl, "write_index", wraps=real_write_index
        ) as refreshed:
            replay = json.loads(self.cli_in_process(*args).stdout)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(refreshed.call_count, 1)
        self.assertEqual(state_path.read_bytes(), before)

    def test_concurrent_double_registration_serializes_to_one_record(self) -> None:
        task_id = "session-register-concurrent"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-concurrent"
        )
        args = self._registration_args(task_id, event, startup)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.cli, *args) for _ in range(2)]
            results = [json.loads(future.result().stdout) for future in futures]
        self.assertEqual(
            sorted(item["idempotent_replay"] for item in results), [False, True]
        )
        self.assertEqual(results[0]["registration"], results[1]["registration"])
        self.assertEqual(
            len(self._state(task_id)["resource_session_registrations"]), 1
        )

    def test_effective_current_reverts_to_prior_apply_after_latest_rollback(self) -> None:
        task_id = "session-register-apply-stack"
        first, _startup = self._prepare_applied(
            task_id=task_id, event_id="resource-stack-a"
        )
        first_bytes = (self.root / ".codex" / "config.toml").read_bytes()
        agents = Path(self.env["CODEX_HOME"]) / "agents"
        (agents / "architect.toml").write_text(
            "\n".join(
                [
                    'name = "architect"',
                    'description = "Architecture review"',
                    'developer_instructions = "Review bounded architecture."',
                    'model = "gpt-5.6-sol"',
                    'model_reasoning_effort = "max"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                "resource-stack-b",
                "--role",
                "architect",
                "--json",
            ).stdout
        )
        self.cli(
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            "resource-stack-b",
            "--role",
            "architect",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            "apply-root",
        )
        applied_architect = self.root / ".codex" / "agents" / "architect.toml"
        self.assertTrue(applied_architect.is_file())
        self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            "resource-stack-b",
            "--reason",
            "Restore prior effective resource apply",
            "--session-id",
            "apply-root",
        )
        state = self._state(task_id)
        self.assertEqual(current_applied_resource_event(state)["event_id"], first["event_id"])
        self.assertEqual(
            (self.root / ".codex" / "config.toml").read_bytes(), first_bytes
        )
        self.assertFalse(applied_architect.exists())
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(get_paths(self.root), state), []
        )

    def test_rollback_rejects_shadowed_applied_ancestor_even_when_bytes_match(self) -> None:
        task_id = "session-register-shadowed-rollback"
        first, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-shadowed-a"
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                "resource-shadowed-b",
                "--role",
                "explorer",
                "--json",
            ).stdout
        )
        self.cli(
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            "resource-shadowed-b",
            "--role",
            "explorer",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            "apply-root",
        )
        second = next(
            item
            for item in self._state(task_id)["resource_config_events"]
            if item["event_id"] == "resource-shadowed-b"
        )
        self.assertLess(
            dt.datetime.fromisoformat(startup["observed_at"].replace("Z", "+00:00")),
            dt.datetime.fromisoformat(second["applied_at"].replace("Z", "+00:00")),
        )
        registration = json.loads(
            self._register(task_id, second, startup).stdout
        )["registration"]
        self.assertTrue(registration["startup_resource_state_equivalent"])
        self.assertEqual(
            registration["freshness_verdict"],
            "registered_byte_state_equivalent_only",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        config_path = self.root / ".codex" / "config.toml"
        before_state = state_path.read_bytes()
        before_config = config_path.read_bytes()
        rejected = self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            first["event_id"],
            "--reason",
            "Attempt rollback of a shadowed applied ancestor",
            "--session-id",
            "apply-root",
            ok=False,
        )
        self.assertIn("effective-current apply", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before_state)
        self.assertEqual(config_path.read_bytes(), before_config)

    def test_resource_transition_clock_jitter_is_bounded_and_zero_mutation(self) -> None:
        task_id = "session-register-clock-jitter"
        first, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-clock-a"
        )
        first_at = dt.datetime.fromisoformat(first["applied_at"])
        startup_at = dt.datetime.fromisoformat(
            startup["observed_at"].replace("Z", "+00:00")
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                "resource-clock-b",
                "--role",
                "explorer",
                "--json",
            ).stdout
        )
        with mock.patch.object(
            resource_cmds,
            "now_iso",
            return_value=(first_at - dt.timedelta(seconds=1)).isoformat(
                timespec="microseconds"
            ),
        ), mock.patch.object(resource_cmds.Path, "cwd", return_value=self.root):
            self.cli_in_process(
                "codex-config-apply",
                "--task",
                task_id,
                "--event-id",
                "resource-clock-b",
                "--role",
                "explorer",
                "--expected-plan-sha256",
                plan["plan_sha256"],
                "--session-id",
                "apply-root",
            )
        state = self._state(task_id)
        second = next(
            item
            for item in state["resource_config_events"]
            if item["event_id"] == "resource-clock-b"
        )
        second_at = dt.datetime.fromisoformat(second["applied_at"])
        self.assertEqual(
            second_at,
            max(first_at, startup_at) + dt.timedelta(microseconds=1),
        )

        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        config_path = self.root / ".codex" / "config.toml"
        before_state = state_path.read_bytes()
        before_config = config_path.read_bytes()
        with mock.patch.object(
            resource_cmds,
            "now_iso",
            return_value=(second_at - dt.timedelta(seconds=6)).isoformat(
                timespec="microseconds"
            ),
        ):
            rejected = self.cli_in_process(
                "codex-config-rollback",
                "--task",
                task_id,
                "--event-id",
                "resource-clock-b",
                "--reason",
                "Reject an unbounded backward wall-clock jump",
                "--session-id",
                "apply-root",
                ok=False,
            )
        self.assertIn("precedes the latest resource transition", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before_state)
        self.assertEqual(config_path.read_bytes(), before_config)

        with mock.patch.object(
            resource_cmds,
            "now_iso",
            return_value=(second_at - dt.timedelta(seconds=1)).isoformat(
                timespec="microseconds"
            ),
        ):
            self.cli_in_process(
                "codex-config-rollback",
                "--task",
                task_id,
                "--event-id",
                "resource-clock-b",
                "--reason",
                "Clamp bounded cross-process wall-clock jitter",
                "--session-id",
                "apply-root",
            )
        state = self._state(task_id)
        rolled_back = next(
            item
            for item in state["resource_config_events"]
            if item["event_id"] == "resource-clock-b"
        )
        self.assertEqual(
            dt.datetime.fromisoformat(rolled_back["rollback"]["recorded_at"]),
            second_at + dt.timedelta(microseconds=1),
        )
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(get_paths(self.root), state), []
        )

    def test_resource_apply_is_causally_after_persisted_startup_observation(
        self,
    ) -> None:
        task_id = "session-register-startup-apply-clock"
        _first, startup = self._prepare_applied(
            task_id=task_id,
            event_id="resource-startup-clock-a",
        )
        startup_at = dt.datetime.fromisoformat(
            startup["observed_at"].replace("Z", "+00:00")
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                "resource-startup-clock-b",
                "--role",
                "explorer",
                "--json",
            ).stdout
        )
        with mock.patch.object(
            resource_cmds,
            "now_iso",
            return_value=(startup_at - dt.timedelta(seconds=1)).isoformat(
                timespec="microseconds"
            ),
        ), mock.patch.object(resource_cmds.Path, "cwd", return_value=self.root):
            self.cli_in_process(
                "codex-config-apply",
                "--task",
                task_id,
                "--event-id",
                "resource-startup-clock-b",
                "--role",
                "explorer",
                "--expected-plan-sha256",
                plan["plan_sha256"],
                "--session-id",
                "apply-root",
            )
        second = next(
            item
            for item in self._state(task_id)["resource_config_events"]
            if item["event_id"] == "resource-startup-clock-b"
        )
        self.assertEqual(
            dt.datetime.fromisoformat(second["applied_at"]),
            startup_at + dt.timedelta(microseconds=1),
        )

    def test_startup_bytes_survive_cross_host_clock_skew_and_order_rollback(self) -> None:
        task_id = "session-register-cross-host-clock"
        event, _unused = self._prepare_applied(
            task_id=task_id,
            event_id="resource-cross-host-clock",
            store_startup=False,
        )
        applied_at = dt.datetime.fromisoformat(event["applied_at"])
        paths = get_paths(self.root)
        startup = persist_startup_receipt(
            paths,
            {
                "schema_version": 2,
                "hook_protocol_version": 6,
                "session_id": "harness-test-chief",
                "source": "startup",
                # Simulate a WSL clock behind the Windows apply clock even
                # though SessionStart causally observed the applied bytes.
                "observed_at": (
                    applied_at - dt.timedelta(seconds=1, microseconds=445679)
                ).isoformat(timespec="microseconds"),
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": paths.project.sha256,
            },
        )
        with mock.patch.object(
            resource_cmds,
            "now_iso",
            return_value=(applied_at - dt.timedelta(seconds=1)).isoformat(
                timespec="microseconds"
            ),
        ):
            result = json.loads(
                self.cli_in_process(
                    *self._registration_args(task_id, event, startup)
                ).stdout
            )
        registered_at = dt.datetime.fromisoformat(
            result["registration"]["registered_at"]
        )
        self.assertEqual(registered_at, applied_at + dt.timedelta(microseconds=1))

        with mock.patch.object(
            resource_cmds,
            "now_iso",
            return_value=(applied_at - dt.timedelta(seconds=1)).isoformat(
                timespec="microseconds"
            ),
        ):
            self.cli_in_process(
                "codex-config-rollback",
                "--task",
                task_id,
                "--event-id",
                event["event_id"],
                "--reason",
                "Preserve causal order after cross-host clock skew",
                "--session-id",
                "apply-root",
            )
        state = self._state(task_id)
        rolled_back = state["resource_config_events"][0]
        self.assertEqual(
            dt.datetime.fromisoformat(rolled_back["rollback"]["recorded_at"]),
            registered_at + dt.timedelta(microseconds=1),
        )
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(paths, state), []
        )

    def test_registration_binds_startup_observed_bytes_not_wall_clock(self) -> None:
        task_id = "session-register-startup-effective"
        first, _unused = self._prepare_applied(
            task_id=task_id,
            event_id="resource-startup-a",
            store_startup=False,
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                "resource-startup-b",
                "--role",
                "explorer",
                "--max-threads",
                "11",
                "--json",
            ).stdout
        )
        self.cli(
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            "resource-startup-b",
            "--role",
            "explorer",
            "--max-threads",
            "11",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            "apply-root",
        )
        paths = get_paths(self.root)
        startup = persist_startup_receipt(
            paths,
            {
                "schema_version": 2,
                "hook_protocol_version": 6,
                "session_id": "harness-test-chief",
                "source": "startup",
                "observed_at": now_iso(),
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": paths.project.sha256,
            },
        )
        self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            "resource-startup-b",
            "--reason",
            "Return live resource files to A after the fresh session saw B",
            "--session-id",
            "apply-root",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        before = state_path.read_bytes()
        rejected = self._register(task_id, first, startup, ok=False)
        self.assertIn("did not observe the reviewed resource file", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        first_receipt = json.loads(
            Path(first["receipt_path"]).read_text(encoding="utf-8")
        )
        forged_match = sorted(
            [
                {
                    "relative_path": item["relative_path"],
                    "after_sha256": item["after_sha256"],
                }
                for item in first_receipt["plan"]["files"]
            ],
            key=lambda item: item["relative_path"],
        )
        with mock.patch.object(
            resource_cmds,
            "startup_resource_files_match",
            return_value=forged_match,
        ):
            forged = self.cli_in_process(
                *self._registration_args(task_id, first, startup), ok=False
            )
        self.assertIn("session registration startup authority is invalid", forged.stderr)
        self.assertEqual(state_path.read_bytes(), before)

    def test_registration_allows_prior_event_when_newer_apply_rolled_back_before_startup(self) -> None:
        task_id = "session-register-startup-after-rollback"
        first, _unused = self._prepare_applied(
            task_id=task_id,
            event_id="resource-before-rollback-a",
            store_startup=False,
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                task_id,
                "--event-id",
                "resource-before-rollback-b",
                "--role",
                "explorer",
                "--max-threads",
                "11",
                "--json",
            ).stdout
        )
        self.cli(
            "codex-config-apply",
            "--task",
            task_id,
            "--event-id",
            "resource-before-rollback-b",
            "--role",
            "explorer",
            "--max-threads",
            "11",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            "apply-root",
        )
        self.cli(
            "codex-config-rollback",
            "--task",
            task_id,
            "--event-id",
            "resource-before-rollback-b",
            "--reason",
            "Restore A before the fresh session starts",
            "--session-id",
            "apply-root",
        )
        paths = get_paths(self.root)
        startup = persist_startup_receipt(
            paths,
            {
                "schema_version": 2,
                "hook_protocol_version": 6,
                "session_id": "harness-test-chief",
                "source": "startup",
                "observed_at": now_iso(),
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": paths.project.sha256,
            },
        )
        result = json.loads(self._register(task_id, first, startup).stdout)
        self.assertFalse(result["idempotent_replay"])
        self.assertEqual(result["resource_config_event_id"], first["event_id"])

    def test_malformed_legacy_packet_version_fails_closed_without_adoption(self) -> None:
        state = {"packets": [{"packet_schema_version": "6"}]}
        with self.assertRaisesRegex(HarnessError, "packet schema version is invalid"):
            _registration_records_for_write(state)
        self.assertNotIn("resource_session_registration_schema_version", state)
        self.assertNotIn("resource_session_registrations", state)

    def test_legacy_field_adoption_waits_for_executing_v5_packets_to_drain(self) -> None:
        for status in ("armed", "dispatched"):
            with self.subTest(status=status):
                state = {
                    "packets": [
                        {"packet_schema_version": 5, "status": status}
                    ]
                }
                with self.assertRaisesRegex(HarnessError, "packets to drain"):
                    _registration_records_for_write(state)
                self.assertNotIn(
                    "resource_session_registration_schema_version", state
                )
                self.assertNotIn("resource_session_registrations", state)
        for status in ("ready", "done", "failed", "cancelled"):
            with self.subTest(status=status):
                state = {
                    "packets": [
                        {"packet_schema_version": 5, "status": status}
                    ]
                }
                self.assertEqual(_registration_records_for_write(state), [])
                self.assertEqual(
                    state["resource_session_registration_schema_version"], 2
                )

    def test_unrelated_invalid_registration_blocks_append_without_mutation(self) -> None:
        task_id = "session-register-invalid-ledger"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-invalid-ledger"
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self._state(task_id)
        state["resource_session_registrations"].append(
            {"session_id": "unrelated-bad-record"}
        )
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        before = state_path.read_bytes()
        rejected = self._register(task_id, event, startup, ok=False)
        self.assertIn("registration integrity gate failed", rejected.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual(
            self._state(task_id)["resource_session_registrations"],
            [{"session_id": "unrelated-bad-record"}],
        )

    def test_event_authority_tamper_breaks_receipt_binding_before_registration(self) -> None:
        task_id = "session-register-applicability-tamper"
        event, startup = self._prepare_applied(
            task_id=task_id, event_id="resource-applicability-tamper"
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        baseline = self._state(task_id)
        for field, value in (
            ("applicability_basis", "forged applicability basis"),
            ("execution_selection_id", "forged-selection"),
        ):
            with self.subTest(field=field):
                state = json.loads(json.dumps(baseline))
                stored_event = next(
                    item
                    for item in state["resource_config_events"]
                    if item["event_id"] == event["event_id"]
                )
                stored_event[field] = value
                state_path.write_text(
                    json.dumps(state, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                before = state_path.read_bytes()
                rejected = self._register(task_id, event, startup, ok=False)
                self.assertIn("receipt binding is invalid", rejected.stderr)
                self.assertEqual(state_path.read_bytes(), before)
                self.assertTrue(
                    any(
                        "receipt binding is invalid" in error
                        for error in cli_impl.resource_config_integrity_errors(
                            get_paths(self.root), self._state(task_id)
                        )
                    )
                )

    def test_redundant_allow_inapplicable_flag_does_not_create_false_ack(self) -> None:
        task_id = "session-register-redundant-applicability-ack"
        event, _startup = self._prepare_applied(
            task_id=task_id,
            event_id="resource-redundant-applicability-ack",
            allow_inapplicable=True,
        )
        self.assertEqual(event["config_applicability"], "applicable")
        self.assertFalse(event["inapplicable_acknowledged"])
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(
                get_paths(self.root), self._state(task_id)
            ),
            [],
        )
