from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware._version import __version__  # noqa: E402
from aoi_orgware.harnesslib import (  # noqa: E402
    HarnessError,
    get_paths,
    load_chief_authority,
    now_iso,
)
from aoi_orgware.resource_config import (  # noqa: E402
    make_legacy_resource_config_migration_receipt,
    resource_config_record_sha256,
    resource_plan_sha256,
)
from tests.harness_case import HarnessTestCase  # noqa: E402


class LegacyResourceConfigMigrationTests(HarnessTestCase):
    REASON = (
        "Preserve exact rolled-back pre-applicability history without "
        "inventing an applicability verdict"
    )

    def _state_path(self, task_id: str) -> Path:
        return self.root / ".aoi" / "tasks" / task_id / "state.json"

    def _state(self, task_id: str) -> dict:
        return json.loads(self._state_path(task_id).read_text(encoding="utf-8"))

    def _write_state(self, task_id: str, state: dict) -> None:
        self._state_path(task_id).write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def _prepare_legacy(
        self,
        *,
        task_id: str,
        event_id: str,
        rollback: bool = True,
        legacy: bool = True,
        event_updates: dict | None = None,
        plan_updates: dict | None = None,
    ) -> tuple[dict, dict, Path, bytes]:
        self.init_task(task_id, "harness-test-chief")
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
            "harness-test-chief",
            "--kind",
            "configuration",
            "--lock",
            "repo:tree:.codex",
            "--intent",
            "Apply and roll back one exact resource configuration fixture",
            "--validation",
            "Receipt, migration, and target bytes remain exact",
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
        self.cli(
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
            "harness-test-chief",
        )
        if rollback:
            self.cli(
                "codex-config-rollback",
                "--task",
                task_id,
                "--event-id",
                event_id,
                "--reason",
                "Create exact inert legacy migration fixture history",
                "--session-id",
                "harness-test-chief",
            )

        state = self._state(task_id)
        event = next(
            item
            for item in state["resource_config_events"]
            if item["event_id"] == event_id
        )
        receipt_path = Path(event["receipt_path"])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if legacy:
            for field in (
                "applicability_basis",
                "codex_home",
                "config_applicability",
                "invocation_cwd",
            ):
                receipt["plan"].pop(field, None)
        if plan_updates:
            receipt["plan"].update(plan_updates)
        legacy_plan_sha256 = resource_plan_sha256(receipt["plan"])
        receipt["plan"]["plan_sha256"] = legacy_plan_sha256
        receipt["plan_sha256"] = legacy_plan_sha256
        receipt_bytes = (
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        receipt_path.write_bytes(receipt_bytes)
        event["plan_sha256"] = legacy_plan_sha256
        event["receipt_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
        if legacy:
            for field in (
                "applicability_basis",
                "config_applicability",
                "inapplicable_acknowledged",
            ):
                event.pop(field, None)
        if event_updates:
            event.update(event_updates)
        self._write_state(task_id, state)
        return copy.deepcopy(event), receipt, receipt_path, receipt_bytes

    def _migration_args(self, task_id: str, event: dict) -> tuple[str, ...]:
        return (
            "codex-config-migrate-legacy",
            "--task",
            task_id,
            "--event-id",
            event["event_id"],
            "--expected-event-sha256",
            resource_config_record_sha256(event),
            "--expected-resource-receipt-sha256",
            event["receipt_sha256"],
            "--reason",
            self.REASON,
            "--session-id",
            "harness-test-chief",
            "--json",
        )

    def _target_snapshot(self, receipt: dict) -> dict[str, bytes | None]:
        snapshot: dict[str, bytes | None] = {}
        for item in receipt["files"]:
            target = self.root / item["relative_path"]
            snapshot[item["relative_path"]] = (
                target.read_bytes() if target.exists() else None
            )
        return snapshot

    def test_exact_rolled_back_migration_is_byte_preserving_and_idempotent(
        self,
    ) -> None:
        task_id = "legacy-resource-positive"
        event, receipt, receipt_path, receipt_bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-positive"
        )
        before_targets = self._target_snapshot(receipt)
        initial_errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), self._state(task_id)
        )
        self.assertTrue(
            any("lacks one exact migration" in item for item in initial_errors),
            initial_errors,
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
            preview = json.loads(
                self.cli(
                    "codex-config-migrate-legacy-plan",
                    "--task",
                    task_id,
                    "--event-id",
                    event["event_id"],
                    "--json",
                ).stdout
            )
        finally:
            self.env.update(credential_env)
        self.assertTrue(preview["eligible"])
        self.assertFalse(preview["already_migrated"])
        self.assertEqual(
            preview["legacy_event_sha256"],
            resource_config_record_sha256(event),
        )
        self.assertEqual(
            preview["legacy_resource_receipt_sha256"],
            event["receipt_sha256"],
        )
        self.assertFalse(preview["original_event_rewritten"])
        self.assertFalse(preview["original_receipt_rewritten"])
        self.assertFalse(preview["applicability_inferred"])

        result = json.loads(self.cli(*self._migration_args(task_id, event)).stdout)
        self.assertFalse(result["idempotent_replay"])
        migrated = self._state(task_id)
        self.assertEqual(
            next(
                item
                for item in migrated["resource_config_events"]
                if item["event_id"] == event["event_id"]
            ),
            event,
        )
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        self.assertEqual(self._target_snapshot(receipt), before_targets)
        self.assertEqual(
            cli_impl.resource_config_integrity_errors(
                get_paths(self.root), migrated
            ),
            [],
        )
        self.cli("doctor", "--task", task_id, "--json")

        state_before_retry = self._state_path(task_id).read_bytes()
        replay = json.loads(
            self.cli(*self._migration_args(task_id, event)).stdout
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(self._state_path(task_id).read_bytes(), state_before_retry)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        self.assertEqual(self._target_snapshot(receipt), before_targets)

    def _assert_rejected_shape(
        self,
        *,
        task_id: str,
        rollback: bool,
        event_updates: dict | None = None,
        plan_updates: dict | None = None,
    ) -> None:
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id,
            event_id=f"{task_id}-event",
            rollback=rollback,
            event_updates=event_updates,
            plan_updates=plan_updates,
        )
        before = self._state_path(task_id).read_bytes()
        rejected = self.cli(*self._migration_args(task_id, event), ok=False)
        self.assertIn("receipt binding is invalid", rejected.stderr)
        self.assertEqual(self._state_path(task_id).read_bytes(), before)
        migration_path = (
            self.root
            / ".aoi"
            / "tasks"
            / task_id
            / "results"
            / f"resource-config-legacy-migration-{event['event_id']}.json"
        )
        self.assertFalse(migration_path.exists())

    def test_applied_legacy_shape_is_rejected_without_mutation(self) -> None:
        self._assert_rejected_shape(task_id="legacy-live", rollback=False)

    def test_modern_rolled_back_event_is_not_migration_eligible(self) -> None:
        task_id = "modern-rolled-back"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id,
            event_id="modern-rolled-back-event",
            legacy=False,
        )
        before = self._state_path(task_id).read_bytes()
        rejected = self.cli(*self._migration_args(task_id, event), ok=False)
        self.assertIn(
            "not exact rolled-back pre-applicability history",
            rejected.stderr,
        )
        self.assertEqual(self._state_path(task_id).read_bytes(), before)

    def test_event_null_partial_legacy_shape_is_rejected(self) -> None:
        self._assert_rejected_shape(
            task_id="legacy-event-null",
            rollback=True,
            event_updates={"config_applicability": None},
        )

    def test_plan_null_partial_legacy_shape_is_rejected(self) -> None:
        self._assert_rejected_shape(
            task_id="legacy-plan-null",
            rollback=True,
            plan_updates={"config_applicability": None},
        )

    def test_compare_and_swap_digest_mismatch_is_rejected_without_mutation(
        self,
    ) -> None:
        task_id = "legacy-resource-cas"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-cas"
        )
        before = self._state_path(task_id).read_bytes()
        migration_args = list(self._migration_args(task_id, event))
        for option, message in (
            ("--expected-event-sha256", "event changed after migration review"),
            (
                "--expected-resource-receipt-sha256",
                "receipt changed after migration review",
            ),
        ):
            forged = list(migration_args)
            forged[forged.index(option) + 1] = "0" * 64
            rejected = self.cli(*forged, ok=False)
            self.assertIn(message, rejected.stderr)
            self.assertEqual(self._state_path(task_id).read_bytes(), before)

    def test_unapproved_current_task_plan_is_rejected_without_mutation(self) -> None:
        task_id = "legacy-resource-unapproved"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-unapproved"
        )
        state = self._state(task_id)
        state["plan_approvals"] = []
        self._write_state(task_id, state)
        before = self._state_path(task_id).read_bytes()
        rejected = self.cli(*self._migration_args(task_id, event), ok=False)
        self.assertIn("approval record", rejected.stderr)
        self.assertEqual(self._state_path(task_id).read_bytes(), before)

    def test_migration_tamper_duplicate_unknown_event_and_event_drift_fail(
        self,
    ) -> None:
        task_id = "legacy-resource-tamper"
        event, _receipt, receipt_path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-tamper"
        )
        self.cli(*self._migration_args(task_id, event))
        state = self._state(task_id)
        pristine_state = copy.deepcopy(state)
        migration = state["resource_config_legacy_migrations"][0]
        migration_path = Path(migration["migration_receipt_path"])
        pristine_migration_bytes = migration_path.read_bytes()

        migration_path.write_bytes(pristine_migration_bytes + b" ")
        errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), self._state(task_id)
        )
        self.assertTrue(
            any("migration receipt identity is invalid" in item for item in errors),
            errors,
        )
        migration_path.write_bytes(pristine_migration_bytes)

        duplicate = copy.deepcopy(pristine_state)
        duplicate["resource_config_legacy_migrations"].append(
            copy.deepcopy(migration)
        )
        self._write_state(task_id, duplicate)
        errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), self._state(task_id)
        )
        self.assertTrue(
            any("duplicate legacy resource config migration" in item for item in errors),
            errors,
        )

        unknown = copy.deepcopy(pristine_state)
        unknown["resource_config_legacy_migrations"][0]["event_id"] = (
            "unknown-resource-event"
        )
        self._write_state(task_id, unknown)
        errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), self._state(task_id)
        )
        self.assertTrue(
            any("lacks one exact resource event" in item for item in errors),
            errors,
        )

        drifted = copy.deepcopy(pristine_state)
        drifted["resource_config_events"][0]["rollback"]["reason"] = (
            "Tampered rollback reason"
        )
        self._write_state(task_id, drifted)
        errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), self._state(task_id)
        )
        self.assertTrue(
            any("migration binding is invalid" in item for item in errors),
            errors,
        )

        self._write_state(task_id, pristine_state)
        receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
        errors = cli_impl.resource_config_integrity_errors(
            get_paths(self.root), self._state(task_id)
        )
        self.assertTrue(
            any("receipt identity is invalid" in item for item in errors),
            errors,
        )

    def test_state_write_failure_cleans_new_receipt_and_retry_succeeds(self) -> None:
        task_id = "legacy-resource-write-failure"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-write-failure"
        )
        state_before = self._state_path(task_id).read_bytes()
        migration_path = (
            self.root
            / ".aoi"
            / "tasks"
            / task_id
            / "results"
            / "resource-config-legacy-migration-legacy-write-failure.json"
        )
        with mock.patch.object(
            cli_impl,
            "write_task",
            side_effect=HarnessError("injected migration state write failure"),
        ):
            failed = self.cli_in_process(
                *self._migration_args(task_id, event), ok=False
            )
        self.assertIn("newly created receipt was removed", failed.stderr)
        self.assertEqual(self._state_path(task_id).read_bytes(), state_before)
        self.assertFalse(migration_path.exists())

        result = json.loads(self.cli(*self._migration_args(task_id, event)).stdout)
        self.assertFalse(result["idempotent_replay"])

    def test_index_failure_retains_published_state_and_retry_repairs_index(
        self,
    ) -> None:
        task_id = "legacy-resource-index-failure"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-index-failure"
        )
        with mock.patch.object(
            cli_impl,
            "write_index",
            side_effect=HarnessError("injected migration index failure"),
        ):
            failed = self.cli_in_process(
                *self._migration_args(task_id, event), ok=False
            )
        self.assertIn("migration state was published", failed.stderr)
        published = self._state(task_id)
        self.assertEqual(len(published["resource_config_legacy_migrations"]), 1)
        state_before_retry = self._state_path(task_id).read_bytes()

        replay = json.loads(
            self.cli(*self._migration_args(task_id, event)).stdout
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(self._state_path(task_id).read_bytes(), state_before_retry)

    def test_exact_orphan_receipt_is_adopted(self) -> None:
        task_id = "legacy-resource-orphan"
        event, legacy_receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-orphan"
        )
        paths = get_paths(self.root)
        authority = load_chief_authority(paths)
        orphan = make_legacy_resource_config_migration_receipt(
            task_id=task_id,
            event=copy.deepcopy(event),
            legacy_receipt=legacy_receipt,
            legacy_receipt_sha256=event["receipt_sha256"],
            migration_task_plan_sha256=self._state(task_id)["plan_sha256"],
            reason=self.REASON,
            root_session_id="harness-test-chief",
            chief_session_id="harness-test-chief",
            chief_epoch=authority["epoch"],
            chief_authority_record_sha256=cli_impl.canonical_record_sha256(
                authority
            ),
            migrated_at=now_iso(),
            aoi_version=__version__,
        )
        migration_path = (
            self.root
            / ".aoi"
            / "tasks"
            / task_id
            / "results"
            / "resource-config-legacy-migration-legacy-orphan.json"
        )
        orphan_bytes = (
            json.dumps(orphan, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        migration_path.write_bytes(orphan_bytes)
        adopted = json.loads(
            self.cli(*self._migration_args(task_id, event)).stdout
        )
        self.assertFalse(adopted["idempotent_replay"])
        self.assertEqual(migration_path.read_bytes(), orphan_bytes)

    def test_forged_cross_task_or_cross_event_orphan_is_rejected(self) -> None:
        task_id = "legacy-resource-forged-orphan"
        event, legacy_receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-forged-orphan"
        )
        paths = get_paths(self.root)
        authority = load_chief_authority(paths)
        base_kwargs = {
            "task_id": task_id,
            "event": copy.deepcopy(event),
            "legacy_receipt": legacy_receipt,
            "legacy_receipt_sha256": event["receipt_sha256"],
            "migration_task_plan_sha256": self._state(task_id)["plan_sha256"],
            "reason": self.REASON,
            "root_session_id": "harness-test-chief",
            "chief_session_id": "harness-test-chief",
            "chief_epoch": authority["epoch"],
            "chief_authority_record_sha256": cli_impl.canonical_record_sha256(
                authority
            ),
            "migrated_at": now_iso(),
            "aoi_version": __version__,
        }
        migration_path = (
            self.root
            / ".aoi"
            / "tasks"
            / task_id
            / "results"
            / "resource-config-legacy-migration-legacy-forged-orphan.json"
        )
        for field, value in (
            ("task_id", "different-task"),
            ("event_id", "different-event"),
        ):
            forged = make_legacy_resource_config_migration_receipt(**base_kwargs)
            forged[field] = value
            migration_path.write_text(
                json.dumps(forged, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            before = self._state_path(task_id).read_bytes()
            rejected = self.cli(*self._migration_args(task_id, event), ok=False)
            self.assertIn("migration", rejected.stderr)
            self.assertEqual(self._state_path(task_id).read_bytes(), before)
            migration_path.unlink()

    def test_symlinked_migration_receipt_is_rejected_without_following(self) -> None:
        task_id = "legacy-resource-symlink"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-symlink"
        )
        migration_path = (
            self.root
            / ".aoi"
            / "tasks"
            / task_id
            / "results"
            / "resource-config-legacy-migration-legacy-symlink.json"
        )
        outside = self.root / "outside-migration-receipt.json"
        outside.write_text("{}\n", encoding="utf-8")
        try:
            migration_path.symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        before = self._state_path(task_id).read_bytes()
        rejected = self.cli(*self._migration_args(task_id, event), ok=False)
        self.assertIn("migration receipt path is unsafe", rejected.stderr)
        self.assertEqual(self._state_path(task_id).read_bytes(), before)
        self.assertEqual(outside.read_text(encoding="utf-8"), "{}\n")

    def test_other_root_session_is_rejected(self) -> None:
        task_id = "legacy-resource-session-mismatch"
        event, _receipt, _path, _bytes = self._prepare_legacy(
            task_id=task_id, event_id="legacy-session-mismatch"
        )
        self.cli(
            "bind-session",
            "--task",
            task_id,
            "--session-id",
            "other-root-session",
        )
        args = list(self._migration_args(task_id, event))
        session_index = args.index("--session-id") + 1
        args[session_index] = "other-root-session"
        before = self._state_path(task_id).read_bytes()
        rejected = self.cli(*args, ok=False)
        self.assertIn("current task-bound Chief session", rejected.stderr)
        self.assertEqual(self._state_path(task_id).read_bytes(), before)


if __name__ == "__main__":
    import unittest

    unittest.main()
