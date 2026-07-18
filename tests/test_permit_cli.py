"""CLI integration tests for Chief issuance and no-Chief permit consumption."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import permit_runtime as runtime  # noqa: E402
from aoi_orgware import routing_authority as authority  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.test_routing_authority import root_arm  # noqa: E402


TASK = "task-1"
CLI_MODULE = "aoi_orgware.cli"


class PermitCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.credentials = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.credential_home = Path(self.credentials.name) / "credentials"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        (self.root / "aoi.toml").write_text(
            default_config_text("Permit CLI"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        with h.state_lock(self.paths, create_layout=True):
            h.task_dir(self.paths, TASK).mkdir(parents=True)
            store.initialize_semantic_task(
                self.paths,
                {"task_id": TASK, "stage": 0},
                command_id="permit-cli-genesis",
                recorded_at=self.iso(self.now - timedelta(minutes=2)),
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
        self.command = 0

    def tearDown(self) -> None:
        self.credentials.cleanup()
        self.temp.cleanup()

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
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(name, None)
        return environment

    def transaction(self, packet_id: str = "packet-cli") -> dict[str, object]:
        self.command += 1
        arm = root_arm(packet_id)
        arm["attempt_identity"].update(
            {
                "armed_at": self.iso(self.now - timedelta(seconds=30)),
                "expires_at": self.iso(self.now + timedelta(minutes=14)),
            }
        )
        arm["chief_authority"]["authority_sha256"] = semantic.canonical_sha256(
            self.chief
        )
        arm = authority.validate_arm_authority(arm)
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
        return runtime.prepare_permitted_arm_transaction(
            task_id=TASK,
            event_chain=events,
            decision=decision,
            permit=permit,
            arm=arm,
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
        result = self.cli(
            "permit-issue",
            "--task",
            TASK,
            "--transaction-file",
            str(path),
            "--json",
        )
        return json.loads(result.stdout)

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
            self.cli(
                "permit-consume",
                "--task",
                TASK,
                "--transaction-file",
                str(path),
                "--json",
                env=controller,
            ).stdout
        )
        second = json.loads(
            self.cli(
                "permit-consume",
                "--task",
                TASK,
                "--transaction-file",
                str(path),
                "--json",
                env=controller,
            ).stdout
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
            "-m",
            CLI_MODULE,
            "permit-consume",
            "--task",
            TASK,
            "--transaction-file",
            str(path),
            "--json",
        ]
        controller = self.controller_env()
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
