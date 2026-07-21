"""Real task composition from semantic migration through Bridge issuance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import codex_transport_contracts as contracts  # noqa: E402
from aoi_orgware import codex_transport_mutation as mutation  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import permit_runtime  # noqa: E402
from aoi_orgware import routing_authority  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.session_receipts import persist_startup_receipt  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


TASK = "task-1"
PACKET = "bridge-packet"
PARENT_SESSION = "harness-test-chief"
_CONTROLLER_SECRET_PREFIXES = ("AOI_CHIEF_", "AOI_CREDENTIAL_")
_CONTROLLER_SECRET_NAMES = {"AOI_BACKUP_ROOT"}


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


class CodexTransportReachabilityTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.bridge_scratch = Path(self.backup_temp.name) / "bridge"
        self.bridge_scratch.mkdir()
        self.env["CODEX_HOME"] = str(self.bridge_scratch / "codex-home")
        config = self.root / "aoi.toml"
        config.write_text(
            config.read_text(encoding="utf-8")
            + '\n[confidentiality]\nmode = "local_files"\n',
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(self.root), "add", "aoi.toml"], check=True
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "commit",
                "-m",
                "enable local files profile",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        self.init_task(TASK, session_id=PARENT_SESSION)
        self.paths = h.get_paths(self.root)
        self._apply_and_register_resource()
        self.cli(
            "create-packet",
            "--task",
            TASK,
            "--packet-id",
            PACKET,
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Issue one governed read-only Codex transport turn",
            "--scope",
            "Read-only disposable scratch task",
            "--deliverable",
            "One terminal transport receipt",
            "--validation",
            "Canonical packet, routing, permit, and launch authority agree",
            "--packet-mode",
            "read_only",
        )

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
        expires_at = _iso(datetime.now(UTC) + timedelta(hours=1))
        self.cli(
            "claim",
            "--task",
            TASK,
            "--token",
            "bridge-resource-files",
            "--owner",
            PARENT_SESSION,
            "--kind",
            "implementation",
            "--lock",
            "repo:tree:.codex",
            "--intent",
            "Apply exact local Codex resource configuration",
            "--validation",
            "Receipt and local after bytes remain exact",
            "--expires-at",
            expires_at,
        )
        plan = json.loads(
            self.cli(
                "codex-config-plan",
                "--task",
                TASK,
                "--event-id",
                "bridge-resource",
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
            "bridge-resource",
            "--role",
            "explorer",
            "--expected-plan-sha256",
            plan["plan_sha256"],
            "--session-id",
            PARENT_SESSION,
        )
        paths = h.get_paths(self.root)
        startup = persist_startup_receipt(
            paths,
            {
                "schema_version": 2,
                "hook_protocol_version": 6,
                "session_id": PARENT_SESSION,
                "source": "startup",
                "observed_at": h.now_iso(),
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": paths.project.sha256,
            },
        )
        state = h.load_task(paths, TASK)
        event = next(
            row
            for row in state["resource_config_events"]
            if row["event_id"] == "bridge-resource"
        )
        self.cli(
            "codex-session-register",
            "--task",
            TASK,
            "--session-id",
            PARENT_SESSION,
            "--event-id",
            event["event_id"],
            "--expected-startup-receipt-sha256",
            startup["startup_receipt_sha256"],
            "--expected-resource-receipt-sha256",
            event["receipt_sha256"],
            "--json",
        )

    def _migrate(self) -> None:
        raw = h.task_state_path(self.paths, TASK).read_bytes()
        self.cli(
            "semantic-migrate",
            "--task",
            TASK,
            "--command-id",
            "bridge-reachability-migrate",
            "--expected-legacy-state-sha256",
            hashlib.sha256(raw).hexdigest(),
            "--json",
        )

    def _arm(self, now: datetime) -> dict[str, object]:
        state = semantic.projection_domain(h.load_task(self.paths, TASK))
        packet = next(row for row in state["packets"] if row["packet_id"] == PACKET)
        event = next(
            row
            for row in state["resource_config_events"]
            if row["event_id"] == "bridge-resource"
        )
        registration = next(
            row
            for row in state["resource_session_registrations"]
            if row["session_id"] == PARENT_SESSION
        )
        receipt_path = Path(event["receipt_path"])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        chief = h.load_chief_authority(self.paths)
        packet_authority = {
            "task_id": TASK,
            "packet_id": PACKET,
            "packet_contract_sha256": packet["packet_contract_sha256"],
            "task_plan_sha256": state["plan_sha256"],
            "delegation_depth": packet["delegation_depth"],
            "parent_packet_id": packet["parent_packet_id"],
            "agent_role": packet["agent_role"],
        }
        envelope = event["dynamic_envelope"]
        topology = {
            "delegation_depth": 1,
            "parent_packet_id": "",
            "parent_resource_event_id": "",
            "parent_routing_authority_sha256": "",
        }
        return routing_authority.build_arm_authority(
            packet=packet_authority,
            attempt_identity={
                "attempt": 1,
                "arm_id": f"{PACKET}-a1",
                "armed_at": _iso(now),
                "expires_at": _iso(now + timedelta(minutes=5)),
                "expected_agent_type": "worker",
            },
            chief_authority={
                "session_id": chief["session_id"],
                "epoch": chief["epoch"],
                "authority_sha256": semantic.canonical_sha256(chief),
            },
            parent_authority={
                "session_id": PARENT_SESSION,
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
                "receipt_relative_path": f"results/resource-config-{event['event_id']}.json",
                "receipt_file_sha256": event["receipt_sha256"],
            },
            session_registration=registration,
            resource_envelope={
                "snapshot": envelope,
                "snapshot_sha256": semantic.canonical_sha256(envelope),
            },
            topology_authority={
                "snapshot": topology,
                "snapshot_sha256": semantic.canonical_sha256(topology),
            },
        )

    def _controller_env(self) -> dict[str, str]:
        environment = self.env.copy()
        for name in tuple(environment):
            upper_name = name.upper()
            if upper_name in _CONTROLLER_SECRET_NAMES or upper_name.startswith(
                _CONTROLLER_SECRET_PREFIXES
            ):
                environment.pop(name, None)
        self.assertFalse(
            any(
                name.upper() in _CONTROLLER_SECRET_NAMES
                or name.upper().startswith(_CONTROLLER_SECRET_PREFIXES)
                for name in environment
            )
        )
        return environment

    def _subprocess(
        self, module: str, arguments: list[str], *, env: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", module, *arguments],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_migrated_ready_packet_reaches_real_bridge_issue(self) -> None:
        self._migrate()
        now = datetime.now(UTC)
        arm = self._arm(now)
        arm_sha256 = routing_authority.authority_sha256(arm)
        events = store.load_semantic_events(self.paths, TASK)
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": TASK,
                "action": "packet.arm",
                "target_ids": [PACKET],
                "parameters": {
                    "packet_id": PACKET,
                    "packet_schema_version": 6,
                    "routing_authority_sha256": arm_sha256,
                },
                "technical_payload_sha256": arm_sha256,
            }
        )
        chief = h.load_chief_authority(self.paths)
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": TASK,
                "expected_semantic_head_sha256": events[-1]["event_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "action": "packet.arm",
                "target_ids": [PACKET],
                "parameters": decision["parameters"],
                "expires_at": _iso(now + timedelta(minutes=4)),
                "nonce": "bridge-arm-reachability-nonce",
                "chief_authority": {
                    "session_id": chief["session_id"],
                    "epoch": chief["epoch"],
                },
            }
        )
        request = {
            "schema_version": 1,
            "decision": decision,
            "permit": permit,
            "arm": arm,
        }
        request_path = self.bridge_scratch / "arm-request.json"
        request_path.write_bytes(
            semantic.canonical_json_bytes(
                request, max_bytes=permit_runtime.MAX_PERMIT_TRANSACTION_BYTES
            )
        )
        prepared = json.loads(
            self.cli(
                "packet-arm-prepare",
                "--task",
                TASK,
                "--request-file",
                str(request_path),
                "--command-id",
                "bridge-packet-arm",
                "--recorded-at",
                _iso(now),
            ).stdout
        )
        transaction_path = self.bridge_scratch / "arm-transaction.json"
        transaction_path.write_bytes(
            semantic.canonical_json_bytes(
                prepared, max_bytes=permit_runtime.MAX_PERMIT_TRANSACTION_BYTES
            )
        )
        self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(transaction_path),
            "--json",
        )
        self._subprocess(
            "aoi_orgware.cli",
            [
                "permit-consume",
                "--task",
                TASK,
                "--transaction-file",
                str(transaction_path),
                "--json",
            ],
            env=self._controller_env(),
        )

        armed_events = store.load_semantic_events(self.paths, TASK)
        armed_state = semantic.projection_domain(semantic.replay_events(armed_events))
        packet = next(row for row in armed_state["packets"] if row["packet_id"] == PACKET)
        self.assertEqual(packet["status"], "armed")
        self.assertEqual(packet["dispatch_attempts"][0]["arm_id"], f"{PACKET}-a1")

        prompt_path = self.bridge_scratch / "prompt.txt"
        prompt_path.write_text("Inspect this disposable task read-only.", encoding="utf-8")
        prompt = prompt_path.read_bytes()
        baseline = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        claims = h.claims_owned_by_task(self.paths, TASK)
        endpoint = mutation.capture_git_endpoint(TASK, self.root, baseline, claims)
        endpoint_path = self.bridge_scratch / "pre-git-endpoint.json"
        endpoint_path.write_bytes(semantic.canonical_json_bytes(endpoint))
        launch_intent = contracts.seal_launch_intent(
            {
                "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V1,
                "task_id": TASK,
                "packet_id": PACKET,
                "routing_binding": {
                    "kind": "standalone",
                    "routing_authority_sha256": arm_sha256,
                    "transport": "codex",
                    "parent_session_id": PARENT_SESSION,
                    "expected_agent_type": "worker",
                },
                "expected_semantic_head_sha256": armed_events[-1]["event_sha256"],
                "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
                "prompt_size_bytes": len(prompt),
                "cwd": self.root.resolve().as_posix(),
                "requested_model": "gpt-5.6-terra",
                "requested_effort": "high",
                "sandbox": "readOnly",
                "approval": "never",
                "runtime_pin": {
                    **contracts.pinned_runtime_binding(),
                    "executable_path": Path(sys.executable).resolve().as_posix(),
                },
                "pre_git_binding": mutation.endpoint_pre_git_binding(endpoint),
            }
        )
        launch_parameters = {
            "launch_id": "launch-1",
            "launch_intent_sha256": launch_intent["intent_sha256"],
            "packet_id": PACKET,
            "routing_binding": launch_intent["routing_binding"],
        }
        launch_decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": TASK,
                "action": "codex.launch",
                "target_ids": ["launch-1"],
                "parameters": launch_parameters,
                "technical_payload_sha256": launch_intent["intent_sha256"],
            }
        )
        launch_permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": TASK,
                "expected_semantic_head_sha256": armed_events[-1]["event_sha256"],
                "decision_sha256": launch_decision["decision_sha256"],
                "action": "codex.launch",
                "target_ids": ["launch-1"],
                "parameters": launch_parameters,
                "expires_at": _iso(now + timedelta(minutes=3)),
                "nonce": "bridge-launch-reachability-nonce",
                "chief_authority": {
                    "session_id": chief["session_id"],
                    "epoch": chief["epoch"],
                },
            }
        )
        paths = {}
        for name, value in (
            ("intent", launch_intent),
            ("decision", launch_decision),
            ("permit", launch_permit),
        ):
            path = self.bridge_scratch / f"launch-{name}.json"
            path.write_bytes(semantic.canonical_json_bytes(value))
            paths[name] = path
        issued = json.loads(
            self._subprocess(
                "aoi_orgware.codex_transport_cli",
                [
                    "--root",
                    str(self.root),
                    "issue",
                    "--task",
                    TASK,
                    "--launch-id",
                    "launch-1",
                    "--intent-file",
                    str(paths["intent"]),
                    "--decision-file",
                    str(paths["decision"]),
                    "--permit-file",
                    str(paths["permit"]),
                    "--pre-git-endpoint-file",
                    str(endpoint_path),
                    "--command-id",
                    "bridge-launch-issue",
                    "--recorded-at",
                    _iso(datetime.now(UTC)),
                    "--chief-session-id",
                    chief["session_id"],
                    "--chief-epoch",
                    str(chief["epoch"]),
                    "--chief-credential-file",
                    self.chief_credential_file,
                    "--json",
                ],
                env=self.env,
            ).stdout
        )
        self.assertEqual(issued["launch_id"], "launch-1")
        self.assertFalse(issued["chief_credential_retained"])


if __name__ == "__main__":
    import unittest

    unittest.main()
