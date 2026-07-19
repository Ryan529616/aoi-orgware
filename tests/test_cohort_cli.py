"""Focused CLI coverage for detached semantic-v2 cohort rounds."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import cohorts  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import permit_runtime as runtime  # noqa: E402
from aoi_orgware import routing_authority as authority  # noqa: E402
from aoi_orgware import routing_persistence as routing  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.test_routing_authority import root_arm  # noqa: E402
from tests.test_routing_persistence import execution_selection_domain  # noqa: E402


TASK = "task-1"
CLI_MODULE = "aoi_orgware.cli"


class CohortCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.credentials = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.credential_home = Path(self.credentials.name) / "credentials"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        (self.root / "aoi.toml").write_text(
            default_config_text("Cohort CLI"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        self.domain = execution_selection_domain()
        with h.state_lock(self.paths, create_layout=True):
            h.task_dir(self.paths, TASK).mkdir(parents=True)
            store.initialize_semantic_task(
                self.paths,
                self.domain,
                command_id="cohort-cli-genesis",
                recorded_at="2026-01-01T00:00:00Z",
                authority_ref="test",
            )
            self.chief, self.credential_path = h.acquire_chief_authority(
                self.paths,
                session_id="session-1",
                ttl_seconds=3600,
                credential_home=self.credential_home,
                now=self.now,
            )
        self.env = os.environ.copy()
        self.env.update(
            {
                "AOI_ROOT": str(self.root),
                "PYTHONPATH": str(SRC),
                "PYTHONDONTWRITEBYTECODE": "1",
                "AOI_CHIEF_SESSION_ID": self.chief["session_id"],
                "AOI_CHIEF_EPOCH": str(self.chief["epoch"]),
                "AOI_CHIEF_CREDENTIAL_FILE": str(self.credential_path),
            }
        )
        self.arms = [
            self._live_arm("packet-route", "explorer"),
            self._live_arm("packet-route-b", "worker"),
        ]
        self.plan = self._cohort_plan()

    def tearDown(self) -> None:
        self.credentials.cleanup()
        self.temp.cleanup()

    @staticmethod
    def iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )

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
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(name, None)
        return environment

    def _live_arm(self, packet_id: str, expected_agent_type: str) -> dict:
        arm = root_arm(
            packet_id,
            expected_agent_type=expected_agent_type,
            execution_selection_id="selection-1",
        )
        arm["attempt_identity"].update(
            {
                "armed_at": self.iso(self.now - timedelta(seconds=30)),
                "expires_at": self.iso(self.now + timedelta(minutes=10)),
            }
        )
        arm["chief_authority"] = {
            "session_id": self.chief["session_id"],
            "epoch": self.chief["epoch"],
            "authority_sha256": semantic.canonical_sha256(self.chief),
        }
        return authority.validate_arm_authority(arm)

    def _cohort_plan(self) -> dict:
        selection = self.domain["execution_selections"][0]
        return cohorts.seal_cohort(
            {
                "schema_version": 1,
                "cohort_id": "cohort-1",
                "packet_schema_version": 6,
                "resource_envelope_sha256": self.arms[0]["resource_envelope"][
                    "snapshot_sha256"
                ],
                "execution_selection_identity_sha256": (
                    cohorts.execution_selection_identity_sha256("selection-1")
                ),
                "execution_selection_target_contract_sha256": selection[
                    "target_contract_sha256"
                ],
                "packet_refs": [
                    {
                        "packet_id": arm["packet_authority"]["packet_id"],
                        "routing_authority_sha256": authority.authority_sha256(arm),
                    }
                    for arm in self.arms
                ],
                "dependencies": {
                    arm["packet_authority"]["packet_id"]: [] for arm in self.arms
                },
                "waves": [[arm["packet_authority"]["packet_id"] for arm in self.arms]],
                "max_concurrency": 2,
                "transport_slots": [
                    {
                        "packet_id": arm["packet_authority"]["packet_id"],
                        "transport": arm["transport_authority"]["transport"],
                        "parent_session_id": arm["parent_authority"]["session_id"],
                        "expected_agent_type": arm["transport_authority"][
                            "expected_agent_type"
                        ],
                    }
                    for arm in self.arms
                ],
                "failure_policy": "continue",
                "cancel_policy": "continue",
            }
        )

    def _request(self, *, include_permit: bool) -> dict:
        request: dict[str, object] = {
            "schema_version": 1,
            "cohort_plan": self.plan,
            "wave_index": 0,
            "arms": self.arms,
        }
        if include_permit:
            events = store.load_semantic_events(self.paths, TASK)
            effect = routing.prepare_cohort_authority_effect(
                self.paths,
                task_id=TASK,
                event_chain=events,
                cohort_plan=self.plan,
                wave_index=0,
                arms=self.arms,
            )
            decision = permits.seal_transition_decision(
                {
                    "schema_version": 1,
                    "task_id": TASK,
                    "action": "cohort.advance",
                    "target_ids": [self.plan["cohort_id"]],
                    "parameters": {
                        "cohort_id": self.plan["cohort_id"],
                        "cohort_sha256": self.plan["cohort_sha256"],
                        "wave_index": 0,
                    },
                    "technical_payload_sha256": effect["selection"]["selection_sha256"],
                }
            )
            request["decision"] = decision
            request["permit"] = permits.seal_transition_permit(
                {
                    "schema_version": 1,
                    "task_id": TASK,
                    "expected_semantic_head_sha256": events[-1]["event_sha256"],
                    "decision_sha256": decision["decision_sha256"],
                    "action": decision["action"],
                    "target_ids": decision["target_ids"],
                    "parameters": decision["parameters"],
                    "expires_at": self.iso(self.now + timedelta(minutes=5)),
                    "nonce": "cohort-cli-nonce-0001",
                    "chief_authority": {
                        "session_id": self.chief["session_id"],
                        "epoch": self.chief["epoch"],
                    },
                }
            )
        return request

    def _write_canonical(self, name: str, value: object, *, maximum: int) -> Path:
        path = self.root / name
        path.write_bytes(semantic.canonical_json_bytes(value, max_bytes=maximum))
        return path

    def test_preview_rejects_noncanonical_and_extra_key_requests_without_launch(self) -> None:
        request = self._request(include_permit=False)
        canonical = self._write_canonical(
            "preview.json", request, maximum=2 * 1024 * 1024
        )
        before = store.semantic_head(self.paths, TASK)
        preview = json.loads(
            self.cli(
                "cohort-round-preview",
                "--task",
                TASK,
                "--request-file",
                str(canonical),
                "--json",
                env=self.controller_env(),
            ).stdout
        )
        self.assertFalse(preview["transport_launch_claimed"])
        self.assertEqual(preview["launch_actor"], "unavailable")
        self.assertEqual(
            {row["status"] for row in preview["packet_states"].values()},
            {"planned"},
        )
        self.assertEqual(store.semantic_head(self.paths, TASK), before)

        pretty = self.root / "preview-pretty.json"
        pretty.write_text(json.dumps(request, indent=2), encoding="utf-8")
        rejected_pretty = self.cli(
            "cohort-round-preview",
            "--task",
            TASK,
            "--request-file",
            str(pretty),
            "--json",
            env=self.controller_env(),
            ok=False,
        )
        self.assertIn("canonical JSON", rejected_pretty.stderr)

        widened = copy.deepcopy(request)
        widened["unexpected"] = "must not be accepted"
        extra = self._write_canonical(
            "preview-extra.json", widened, maximum=2 * 1024 * 1024
        )
        rejected_extra = self.cli(
            "cohort-round-preview",
            "--task",
            TASK,
            "--request-file",
            str(extra),
            "--json",
            env=self.controller_env(),
            ok=False,
        )
        self.assertIn("schema is invalid", rejected_extra.stderr)
        self.assertEqual(store.semantic_head(self.paths, TASK), before)

    def test_prepare_issue_consume_and_show_follow_chief_split_without_launch_claim(self) -> None:
        request = self._request(include_permit=True)
        mismatched = copy.deepcopy(request)
        mismatched["wave_index"] = 1
        mismatched_file = self._write_canonical(
            "prepare-wrong-wave.json", mismatched, maximum=2 * 1024 * 1024
        )
        rejected_wave = self.cli(
            "cohort-round-prepare",
            "--task",
            TASK,
            "--request-file",
            str(mismatched_file),
            "--command-id",
            "cohort-cli-wrong-wave",
            "--recorded-at",
            self.iso(self.now - timedelta(seconds=1)),
            env=self.controller_env(),
            ok=False,
        )
        self.assertIn("wave_index differs", rejected_wave.stderr)

        request_file = self._write_canonical(
            "prepare.json", request, maximum=2 * 1024 * 1024
        )
        prepared = self.cli(
            "cohort-round-prepare",
            "--task",
            TASK,
            "--request-file",
            str(request_file),
            "--command-id",
            "cohort-cli-round-1",
            "--recorded-at",
            self.iso(self.now - timedelta(seconds=1)),
            env=self.controller_env(),
        )
        transaction = json.loads(prepared.stdout)
        canonical_transaction = semantic.canonical_json_bytes(
            transaction, max_bytes=runtime.MAX_COHORT_PERMIT_TRANSACTION_BYTES
        )
        self.assertEqual(prepared.stdout.encode("utf-8"), canonical_transaction)
        self.assertFalse(prepared.stdout.endswith("\n"))
        transaction_file = self.root / "transaction.json"
        transaction_file.write_bytes(canonical_transaction)

        no_chief_issue = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(transaction_file),
            "--json",
            env=self.controller_env(),
            ok=False,
        )
        self.assertIn("Chief", no_chief_issue.stderr)

        issued = json.loads(
            self.cli(
                "permit-issue",
                "--task",
                TASK,
                "--transaction-file",
                str(transaction_file),
                "--json",
            ).stdout
        )
        self.assertFalse(issued["idempotent_replay"])

        consumed = json.loads(
            self.cli(
                "permit-consume",
                "--task",
                TASK,
                "--transaction-file",
                str(transaction_file),
                "--json",
                env=self.controller_env(),
            ).stdout
        )
        self.assertFalse(consumed["idempotent_replay"])
        self.assertEqual(consumed["semantic_head_sha256"], consumed["event_sha256"])

        plan_file = self._write_canonical(
            "cohort.json", self.plan, maximum=2 * 1024 * 1024
        )
        shown = json.loads(
            self.cli(
                "cohort-show",
                "--task",
                TASK,
                "--cohort-file",
                str(plan_file),
                "--json",
                env=self.controller_env(),
            ).stdout
        )
        self.assertFalse(shown["transport_launch_claimed"])
        self.assertFalse(shown["transport_start_observed"])
        self.assertEqual(shown["launch_actor"], "unavailable")
        self.assertEqual(
            {row["status"] for row in shown["packet_states"].values()}, {"armed"}
        )


if __name__ == "__main__":
    unittest.main()
