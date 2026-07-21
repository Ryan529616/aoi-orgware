"""CLI integration tests for Chief issuance and no-Chief permit consumption."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import dispatch_protocol  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import permit_runtime as runtime  # noqa: E402
from aoi_orgware import routing_authority as authority  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.session_receipts import persist_startup_receipt  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


TASK = "task-1"
CLI_MODULE = "aoi_orgware.cli"
CLOCK_DRIVER = HERE / "permit_cli_clock_driver.py"
CLOCK_ENV = "AOI_TEST_PERMIT_CURRENT_TIME"
_CONTROLLER_SECRET_PREFIXES = ("AOI_CHIEF_", "AOI_CREDENTIAL_")
_CONTROLLER_SECRET_NAMES = {"AOI_BACKUP_ROOT"}

_PACKET_IDS = {
    "packet-cli",
    "packet-cli-race",
    "packet-input",
    "packet-unissued",
}


class PermitCliTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.init_task(TASK, session_id="harness-test-chief")
        self.paths = h.get_paths(self.root)
        self._apply_and_register_resource()
        for packet_id in sorted(_PACKET_IDS):
            self.cli(
                "create-packet",
                "--task",
                TASK,
                "--packet-id",
                packet_id,
                "--agent-role",
                "explorer",
                "--model-tier",
                "standard",
                "--objective",
                f"Exercise standalone permit packet {packet_id}",
                "--scope",
                "Read-only permit CLI fixture",
                "--deliverable",
                "One canonical packet arm result",
                "--validation",
                "Routing, permit, packet, and canonical resource authority agree",
                "--packet-mode",
                "read_only",
            )
        raw = h.task_state_path(self.paths, TASK).read_bytes()
        self.cli(
            "semantic-migrate",
            "--task",
            TASK,
            "--command-id",
            "permit-cli-migrate",
            "--expected-legacy-state-sha256",
            hashlib.sha256(raw).hexdigest(),
            "--json",
        )
        chief = h.load_chief_authority(self.paths)
        assert chief is not None
        self.chief = chief
        self.credential_path = Path(self.chief_credential_file)
        migrated = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        registration = next(
            row
            for row in migrated["resource_session_registrations"]
            if row["session_id"] == "harness-test-chief"
        )
        registered_at = datetime.fromisoformat(
            str(registration["registered_at"]).replace("Z", "+00:00")
        )
        # Preserve the production contract's strict registration-before-arm
        # causal ordering without importing the parent process's wall clock.
        self.now = registered_at + timedelta(microseconds=1)
        self.command = 0

    def _apply_and_register_resource(self) -> None:
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
        self.cli(
            "claim",
            "--task",
            TASK,
            "--token",
            "permit-cli-resource-files",
            "--owner",
            "harness-test-chief",
            "--kind",
            "implementation",
            "--lock",
            "repo:tree:.codex",
            "--intent",
            "Apply exact local Codex resource configuration",
            "--validation",
            "Canonical receipt and local after bytes remain exact",
            "--expires-at",
            self.iso(datetime.now(timezone.utc) + timedelta(hours=1)),
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                TASK,
                "--event-id",
                "permit-cli-resource",
                "--role",
                "explorer",
                "--json",
            ).stdout
        )
        self.cli(
            "codex-config-apply",
            "--task",
            TASK,
            "--event-id",
            "permit-cli-resource",
            "--role",
            "explorer",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            "harness-test-chief",
        )
        startup = persist_startup_receipt(
            self.paths,
            {
                "schema_version": 2,
                "hook_protocol_version": 6,
                "session_id": "harness-test-chief",
                "source": "startup",
                "observed_at": h.now_iso(),
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": self.paths.project.sha256,
            },
        )
        state = h.load_task(self.paths, TASK)
        event = next(
            row
            for row in state["resource_config_events"]
            if row["event_id"] == "permit-cli-resource"
        )
        self.cli(
            "codex-session-register",
            "--task",
            TASK,
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

    def tearDown(self) -> None:
        super().tearDown()

    @staticmethod
    def iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    def cli(
        self,
        *arguments: str,
        env: dict[str, str] | None = None,
        ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *arguments],
            cwd=self.root,
            env=env or self.env,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(arguments)}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        if not ok:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        return result

    def controller_env(self) -> dict[str, str]:
        environment = self.env.copy()
        for name in tuple(environment):
            upper_name = name.upper()
            if upper_name in _CONTROLLER_SECRET_NAMES or upper_name.startswith(
                _CONTROLLER_SECRET_PREFIXES
            ):
                environment.pop(name, None)
        return environment

    def test_controller_environment_cannot_resolve_chief_credential(self) -> None:
        controller = self.controller_env()
        leaked = sorted(
            name
            for name in controller
            if name.upper() in _CONTROLLER_SECRET_NAMES
            or name.upper().startswith(_CONTROLLER_SECRET_PREFIXES)
        )
        self.assertEqual(leaked, [])
        probe = "\n".join(
            [
                "from aoi_orgware import harnesslib as h",
                "paths = h.get_paths()",
                "authority = h.load_chief_authority(paths)",
                "assert authority is not None",
                "try:",
                "    h.load_chief_credential(",
                "        paths,",
                "        session_id=authority['session_id'],",
                "        epoch=authority['epoch'],",
                "    )",
                "except h.HarnessError:",
                "    raise SystemExit(0)",
                "raise SystemExit(3)",
            ]
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=self.root,
            env=controller,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_clocked_consumer_driver_rejects_chief_locator_before_cli(
        self,
    ) -> None:
        transaction = self.transaction(packet_id="packet-input")
        path = self.transaction_file(transaction, "controller-secret-leak.json")
        before = store.semantic_head(self.paths, TASK)
        environment = self.permit_clock_env(path, self.controller_env())
        environment["AOI_CHIEF_CREDENTIAL_HOME"] = self.env[
            "AOI_CHIEF_CREDENTIAL_HOME"
        ]
        result = subprocess.run(
            [
                sys.executable,
                str(CLOCK_DRIVER),
                "permit-consume",
                "--task",
                TASK,
                "--transaction-file",
                str(path),
                "--json",
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("received reusable Chief authority locators", result.stderr)
        self.assertNotIn(environment["AOI_CHIEF_CREDENTIAL_HOME"], result.stderr)
        self.assertEqual(store.semantic_head(self.paths, TASK), before)

    def arm_request(
        self,
        packet_id: str = "packet-cli",
        *,
        registration_override: dict[str, object] | None = None,
        expected_agent_type: str | None = None,
    ) -> dict[str, object]:
        self.command += 1
        state = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        packet = next(row for row in state["packets"] if row["packet_id"] == packet_id)
        event = next(
            row
            for row in state["resource_config_events"]
            if row["event_id"] == "permit-cli-resource"
        )
        registration = registration_override or next(
            row
            for row in state["resource_session_registrations"]
            if row["session_id"] == "harness-test-chief"
        )
        receipt = json.loads(Path(event["receipt_path"]).read_text(encoding="utf-8"))
        packet_authority = {
            "task_id": TASK,
            "packet_id": packet_id,
            "packet_contract_sha256": packet["packet_contract_sha256"],
            "task_plan_sha256": state["plan_sha256"],
            "delegation_depth": packet["delegation_depth"],
            "parent_packet_id": packet["parent_packet_id"],
            "agent_role": packet["agent_role"],
        }
        topology = {
            "delegation_depth": 1,
            "parent_packet_id": "",
            "parent_resource_event_id": "",
            "parent_routing_authority_sha256": "",
        }
        arm = authority.build_arm_authority(
            packet=packet_authority,
            attempt_identity={
                "attempt": 1,
                "arm_id": f"{packet_id}-a1",
                "armed_at": self.iso(self.now),
                "expires_at": self.iso(self.now + timedelta(minutes=14)),
                "expected_agent_type": (
                    expected_agent_type or f"agent-{packet_id}"
                ),
            },
            chief_authority={
                "session_id": self.chief["session_id"],
                "epoch": self.chief["epoch"],
                "authority_sha256": semantic.canonical_sha256(self.chief),
            },
            parent_authority={
                "session_id": "harness-test-chief",
                "mapping_kind": "root",
                "parent_packet_id": "",
                "root_registration_snapshot": registration,
                "parent_authority_preimage": None,
                "parent_dispatch_outcome_preimage": None,
                "inherited_parent_routing_authority_sha256": None,
                "inherited_parent_routing_outcome_sha256": None,
            },
            resource_event_snapshot=event,
            resource_receipt={
                "receipt": receipt,
                "receipt_relative_path": (
                    f"results/resource-config-{event['event_id']}.json"
                ),
                "receipt_file_sha256": event["receipt_sha256"],
            },
            session_registration=registration,
            resource_envelope={
                "snapshot": event["dynamic_envelope"],
                "snapshot_sha256": semantic.canonical_sha256(
                    event["dynamic_envelope"]
                ),
            },
            topology_authority={
                "snapshot": topology,
                "snapshot_sha256": semantic.canonical_sha256(topology),
            },
        )
        arm_sha256 = authority.authority_sha256(arm)
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": TASK,
                "action": "packet.arm",
                "target_ids": [packet_id],
                "parameters": {
                    "packet_id": packet_id,
                    "packet_schema_version": 6,
                    "routing_authority_sha256": arm_sha256,
                },
                "technical_payload_sha256": arm_sha256,
            }
        )
        events = store.load_semantic_events(self.paths, TASK)
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": TASK,
                "expected_semantic_head_sha256": events[-1]["event_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "action": decision["action"],
                "target_ids": decision["target_ids"],
                "parameters": decision["parameters"],
                "expires_at": self.iso(self.now + timedelta(minutes=10)),
                "nonce": f"permit-cli-nonce-{self.command:04d}",
                "chief_authority": {
                    "session_id": self.chief["session_id"],
                    "epoch": self.chief["epoch"],
                },
            }
        )
        return {
            "schema_version": 1,
            "decision": decision,
            "permit": permit,
            "arm": arm,
        }

    def transaction(
        self,
        packet_id: str = "packet-cli",
        *,
        registration_override: dict[str, object] | None = None,
        expected_agent_type: str | None = None,
    ) -> dict[str, object]:
        request = self.arm_request(
            packet_id,
            registration_override=registration_override,
            expected_agent_type=expected_agent_type,
        )
        events = store.load_semantic_events(self.paths, TASK)
        return runtime.prepare_permitted_arm_transaction(
            task_id=TASK,
            event_chain=events,
            decision=request["decision"],
            permit=request["permit"],
            arm=request["arm"],
            command_id=f"permit-cli-{self.command}",
            recorded_at=self.iso(self.now),
        )

    def transaction_file(
        self, transaction: dict[str, object], name: str = "transaction.json"
    ) -> Path:
        path = self.root / name
        path.write_bytes(
            semantic.canonical_json_bytes(
                transaction, max_bytes=runtime.MAX_PERMIT_TRANSACTION_BYTES
            )
        )
        return path

    def issue(self, path: Path) -> dict[str, object]:
        return json.loads(self.permit_cli("permit-issue", path).stdout)

    def permit_clock_env(
        self,
        path: Path,
        env: dict[str, str] | None = None,
    ) -> dict[str, str]:
        transaction = json.loads(path.read_text(encoding="utf-8"))
        planned_at = datetime.fromisoformat(
            str(transaction["recorded_at"]).replace("Z", "+00:00")
        )
        environment = (self.env if env is None else env).copy()
        environment[CLOCK_ENV] = self.iso(planned_at + timedelta(seconds=1))
        return environment

    def permit_cli(
        self,
        command: str,
        path: Path,
        *,
        env: dict[str, str] | None = None,
        ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        self.assertIn(command, {"permit-issue", "permit-consume"})
        result = subprocess.run(
            [
                sys.executable,
                str(CLOCK_DRIVER),
                command,
                "--task",
                TASK,
                "--transaction-file",
                str(path),
                "--json",
            ],
            cwd=self.root,
            env=self.permit_clock_env(path, env),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"clocked CLI failed ({result.returncode}): {command}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        if not ok:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        return result

    def test_packet_arm_prepare_emits_exact_transaction_and_consume_arms_packet(
        self,
    ) -> None:
        request = self.arm_request()
        request_path = self.root / "packet-arm-request.json"
        request_path.write_bytes(
            semantic.canonical_json_bytes(
                request, max_bytes=runtime.MAX_PERMIT_TRANSACTION_BYTES
            )
        )
        command_id = f"permit-cli-{self.command}"
        recorded_at = self.iso(self.now)
        prepared = json.loads(
            self.cli(
                "packet-arm-prepare",
                "--task",
                TASK,
                "--request-file",
                str(request_path),
                "--command-id",
                command_id,
                "--recorded-at",
                recorded_at,
            ).stdout
        )
        expected = runtime.prepare_permitted_arm_transaction(
            task_id=TASK,
            event_chain=store.load_semantic_events(self.paths, TASK),
            decision=request["decision"],
            permit=request["permit"],
            arm=request["arm"],
            command_id=command_id,
            recorded_at=recorded_at,
        )
        self.assertEqual(prepared, expected)

        path = self.transaction_file(prepared, "prepared-arm.json")
        self.issue(path)
        self.permit_cli("permit-consume", path, env=self.controller_env())
        state = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        packet = next(row for row in state["packets"] if row["packet_id"] == "packet-cli")
        self.assertEqual(packet["status"], "armed")
        self.assertEqual(packet["dispatch_provenance"], "none")
        self.assertEqual(len(packet["dispatch_attempts"]), 1)
        attempt = packet["dispatch_attempts"][0]
        self.assertEqual(attempt["arm_id"], "packet-cli-a1")
        self.assertEqual(attempt["status"], "armed")
        self.assertEqual(
            attempt["arm_authority_sha256"],
            dispatch_protocol.dispatch_attempt_authority_sha256(attempt),
        )
        namespace = runtime.permit_namespace_from_projection(state)
        self.assertEqual(len(namespace["consumptions"]), 1)

    def test_packet_arm_prepare_rejects_schema_drift_before_transaction_build(
        self,
    ) -> None:
        for version in (2, True):
            with self.subTest(version=version):
                request = self.arm_request(packet_id="packet-input")
                request["schema_version"] = version
                path = self.root / f"packet-arm-request-{version!s}.json"
                path.write_bytes(
                    semantic.canonical_json_bytes(
                        request, max_bytes=runtime.MAX_PERMIT_TRANSACTION_BYTES
                    )
                )
                result = self.cli(
                    "packet-arm-prepare",
                    "--task",
                    TASK,
                    "--request-file",
                    str(path),
                    "--command-id",
                    f"packet-arm-schema-drift-{version!s}",
                    "--recorded-at",
                    self.iso(self.now),
                    ok=False,
                )
                self.assertIn("packet arm request schema is invalid", result.stderr)

    def test_issue_rechecks_the_canonical_packet_contract(self) -> None:
        transaction = self.transaction(packet_id="packet-input")
        packet = next(
            row
            for row in semantic.projection_domain(
                semantic.replay_events(store.load_semantic_events(self.paths, TASK))
            )["packets"]
            if row["packet_id"] == "packet-input"
        )
        Path(packet["path"]).write_text("tampered\n", encoding="utf-8")
        result = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(self.transaction_file(transaction, "tampered-packet-arm.json")),
            "--json",
            ok=False,
        )
        self.assertIn("packet authority is missing or tampered", result.stderr)
        self.assertFalse(
            runtime.permit_issuance_path(
                self.paths,
                TASK,
                transaction["objects"][2]["payload"]["permit_sha256"],
            ).exists()
        )

    def test_issue_requires_the_canonical_root_session_mapping(self) -> None:
        transaction = self.transaction(packet_id="packet-input")
        h.session_path(self.paths, "harness-test-chief").unlink()
        result = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(self.transaction_file(transaction, "missing-root-session.json")),
            "--json",
            ok=False,
        )
        self.assertRegex(result.stderr, "root arbitration|missing state file")
        self.assertFalse(
            runtime.permit_issuance_path(
                self.paths,
                TASK,
                transaction["objects"][2]["payload"]["permit_sha256"],
            ).exists()
        )

    def test_issue_rejects_a_self_consistent_noncanonical_registration(self) -> None:
        state = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        forged = copy.deepcopy(state["resource_session_registrations"][0])
        forged["registered_at"] = self.iso(self.now - timedelta(microseconds=1))
        forged.pop("registration_sha256")
        forged = authority.seal_session_registration(forged)
        transaction = self.transaction(
            packet_id="packet-input", registration_override=forged
        )
        result = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(self.transaction_file(transaction, "forged-registration.json")),
            "--json",
            ok=False,
        )
        self.assertIn("one exact canonical session registration", result.stderr)

    def test_issue_rechecks_the_canonical_resource_receipt(self) -> None:
        transaction = self.transaction(packet_id="packet-input")
        state = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        event = state["resource_config_events"][0]
        Path(event["receipt_path"]).write_text("tampered\n", encoding="utf-8")
        result = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(self.transaction_file(transaction, "tampered-resource-receipt.json")),
            "--json",
            ok=False,
        )
        self.assertIn("resource authority is invalid", result.stderr)

    def test_no_chief_consume_rechecks_resource_authority_after_issue(self) -> None:
        transaction = self.transaction(packet_id="packet-input")
        path = self.transaction_file(transaction, "consume-resource-drift.json")
        self.issue(path)
        state = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        event = state["resource_config_events"][0]
        Path(event["receipt_path"]).write_text("tampered\n", encoding="utf-8")
        before = store.semantic_head(self.paths, TASK)
        result = self.cli(
            "permit-consume",
            "--task",
            TASK,
            "--transaction-file",
            str(path),
            "--json",
            env=self.controller_env(),
            ok=False,
        )
        self.assertIn("resource authority is invalid", result.stderr)
        self.assertEqual(store.semantic_head(self.paths, TASK), before)

    def test_standalone_arm_rejects_an_exact_parent_slot_collision(self) -> None:
        first = self.transaction(
            packet_id="packet-cli", expected_agent_type="shared-worker"
        )
        first_path = self.transaction_file(first, "first-slot.json")
        self.issue(first_path)
        self.permit_cli("permit-consume", first_path, env=self.controller_env())
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "slot is already armed"):
            self.transaction(
                packet_id="packet-cli-race", expected_agent_type="shared-worker"
            )

    def test_standalone_arm_rejects_a_wildcard_parent_slot_collision(self) -> None:
        first = self.transaction(packet_id="packet-cli", expected_agent_type="*")
        first_path = self.transaction_file(first, "wildcard-slot.json")
        self.issue(first_path)
        self.permit_cli("permit-consume", first_path, env=self.controller_env())
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "slot is already armed"):
            self.transaction(
                packet_id="packet-cli-race", expected_agent_type="another-worker"
            )

    def test_issue_then_consume_without_chief_material_is_exact_and_replayable(
        self,
    ) -> None:
        transaction = self.transaction()
        path = self.transaction_file(transaction)
        issued = self.issue(path)
        issue_text = json.dumps(issued, sort_keys=True)
        with h.state_lock(self.paths, create_layout=False):
            token, _loaded_path = h.load_chief_credential(
                self.paths,
                session_id=self.chief["session_id"],
                epoch=self.chief["epoch"],
                credential_file=self.credential_path,
            )
        for forbidden in (token, str(self.credential_path), str(path)):
            self.assertNotIn(forbidden, issue_text)
        self.assertFalse(issued["idempotent_replay"])

        controller = self.controller_env()
        first = json.loads(
            self.permit_cli("permit-consume", path, env=controller).stdout
        )
        state = semantic.projection_domain(
            semantic.replay_events(store.load_semantic_events(self.paths, TASK))
        )
        packet = next(
            row for row in state["packets"] if row["packet_id"] == "packet-cli"
        )
        Path(packet["path"]).write_text(
            "tampered after committed arm\n", encoding="utf-8"
        )
        second = json.loads(
            self.permit_cli("permit-consume", path, env=controller).stdout
        )
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(first["event_sha256"], second["event_sha256"])
        self.assertNotIn(str(self.credential_path), json.dumps(first, sort_keys=True))
        events = store.load_semantic_events(self.paths, TASK)
        self.assertEqual(
            sum(event["command_id"] == transaction["command_id"] for event in events),
            1,
        )

    def test_no_chief_consume_rejects_an_unissued_transaction(self) -> None:
        transaction = self.transaction(packet_id="packet-unissued")
        path = self.transaction_file(transaction)
        before = store.semantic_head(self.paths, TASK)
        result = self.cli(
            "permit-consume",
            "--task",
            TASK,
            "--transaction-file",
            str(path),
            "--json",
            env=self.controller_env(),
            ok=False,
        )
        self.assertRegex(result.stderr, "durably issued|issuance marker")
        self.assertEqual(store.semantic_head(self.paths, TASK), before)

    def test_issue_requires_chief_and_input_is_exact_canonical_task_local(self) -> None:
        transaction = self.transaction(packet_id="packet-input")
        path = self.transaction_file(transaction)
        missing_chief = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(path),
            "--json",
            env=self.controller_env(),
            ok=False,
        )
        self.assertIn("Chief", missing_chief.stderr)
        self.assertFalse(
            runtime.permit_issuance_path(
                self.paths,
                TASK,
                transaction["objects"][2]["payload"]["permit_sha256"],
            ).exists()
        )

        pretty = self.root / "pretty.json"
        pretty.write_text(json.dumps(transaction, indent=2), encoding="utf-8")
        noncanonical = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(pretty),
            "--json",
            ok=False,
        )
        self.assertIn("canonical JSON", noncanonical.stderr)

        wrong_task = self.cli(
            "permit-issue",
            "--task",
            "other-task",
            "--transaction-file",
            str(path),
            "--json",
            ok=False,
        )
        self.assertIn("another task", wrong_task.stderr)

    def test_two_cli_consumers_publish_one_event(self) -> None:
        transaction = self.transaction(packet_id="packet-cli-race")
        path = self.transaction_file(transaction)
        self.issue(path)
        command = [
            sys.executable,
            str(CLOCK_DRIVER),
            "permit-consume",
            "--task",
            TASK,
            "--transaction-file",
            str(path),
            "--json",
        ]
        controller = self.permit_clock_env(path, self.controller_env())
        processes = [
            subprocess.Popen(
                command,
                cwd=self.root,
                env=controller,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _index in range(2)
        ]
        outputs: list[dict[str, object]] = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr)
            outputs.append(json.loads(stdout))
        self.assertEqual(
            sorted(row["idempotent_replay"] for row in outputs), [False, True]
        )
        events = store.load_semantic_events(self.paths, TASK)
        self.assertEqual(
            sum(event["command_id"] == transaction["command_id"] for event in events),
            1,
        )


if __name__ == "__main__":
    unittest.main()
