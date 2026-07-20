from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import pytest

from tests.harness_case import HarnessTestCase

from aoi_orgware import cli as cli_impl
from aoi_orgware import external_exports
from aoi_orgware import harnesslib as h


def test_external_destination_rejects_local_or_secret_bearing_uri() -> None:
    for value in (
        "file:///tmp/bundle.age",
        "C:/bundle.age",
        "https://user:secret@example.invalid/upload",
        "https://example.invalid/upload?token=secret",
        "https://example.invalid/upload#attachment",
        "HTTPS://example.invalid/upload",
    ):
        with pytest.raises(external_exports.ExternalExportError):
            external_exports.validate_external_destination(value)
    assert (
        external_exports.validate_external_destination(
            "connector://github/example/private-bundle"
        )
        == "connector://github/example/private-bundle"
    )


class ExternalExportCliTests(HarnessTestCase):
    task_id = "local-export-task"
    export_id = "bundle-export-1"
    destination = "https://example.invalid/private/bundle.age"
    purpose = "User-authorized transfer of the exact encrypted local bundle"

    def setUp(self) -> None:
        super().setUp()
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
        self.init_task(self.task_id)
        self.bundle = self.root / "bundle.age"
        self.bundle.write_bytes(b"encrypted-local-bundle\0v1\n")
        self.content_sha256 = hashlib.sha256(self.bundle.read_bytes()).hexdigest()

    def _expiry(self, minutes: int = 5) -> str:
        return (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def issue(self, *, export_id: str | None = None) -> dict[str, object]:
        result = self.cli(
            "external-export-permit-issue",
            "--task",
            self.task_id,
            "--export-id",
            export_id or self.export_id,
            "--source-file",
            str(self.bundle),
            "--expected-content-sha256",
            self.content_sha256,
            "--destination",
            self.destination,
            "--purpose",
            self.purpose,
            "--expires-at",
            self._expiry(),
            "--json",
        )
        return json.loads(result.stdout)

    def consume(
        self,
        permit_sha256: str,
        *,
        destination: str | None = None,
        purpose: str | None = None,
        ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.cli(
            "external-export-permit-consume",
            "--task",
            self.task_id,
            "--permit-sha256",
            permit_sha256,
            "--source-file",
            str(self.bundle),
            "--destination",
            destination or self.destination,
            "--purpose",
            purpose or self.purpose,
            "--json",
            ok=ok,
        )

    def test_parser_and_chief_fencing_are_explicit(self) -> None:
        parser = cli_impl.build_parser({})
        issue = parser.parse_args(
            [
                "external-export-permit-issue",
                "--task",
                "task-1",
                "--export-id",
                "export-1",
                "--source-file",
                "bundle.age",
                "--expected-content-sha256",
                "1" * 64,
                "--destination",
                self.destination,
                "--purpose",
                self.purpose,
                "--expires-at",
                self._expiry(),
            ]
        )
        self.assertIs(issue.handler, cli_impl.cmd_external_export_permit_issue)
        self.assertTrue(
            cli_impl.command_requires_chief(
                "external-export-permit-issue", initialized=True
            )
        )
        self.assertFalse(
            cli_impl.command_requires_chief(
                "external-export-permit-consume", initialized=True
            )
        )

    def test_issue_consume_and_exact_replay_are_at_most_once(self) -> None:
        issued = self.issue()
        self.assertFalse(issued["idempotent_replay"])
        self.assertFalse(issued["publication_observed"])
        self.assertNotIn("source_file", issued)

        first = json.loads(
            self.consume(str(issued["permit_sha256"])).stdout
        )
        self.assertTrue(first["fresh_consumption"])
        self.assertFalse(first["publication_observed"])
        self.assertEqual(
            first["authorization_status"],
            "fresh_at_most_once_export_authorization",
        )

        replay = json.loads(
            self.consume(str(issued["permit_sha256"])).stdout
        )
        self.assertFalse(replay["fresh_consumption"])
        self.assertEqual(
            replay["authorization_status"],
            "already_consumed_no_export_authority",
        )
        self.assertEqual(first["receipt_sha256"], replay["receipt_sha256"])

    def test_wrong_destination_purpose_content_and_head_drift_fail_closed(self) -> None:
        issued = self.issue()
        wrong_destination = self.consume(
            str(issued["permit_sha256"]),
            destination="https://other.invalid/private/bundle.age",
            ok=False,
        )
        self.assertIn("destination differs", wrong_destination.stderr)
        wrong_purpose = self.consume(
            str(issued["permit_sha256"]), purpose="Another purpose", ok=False
        )
        self.assertIn("purpose differs", wrong_purpose.stderr)

        self.bundle.write_bytes(b"different encrypted bytes\n")
        drift = self.consume(str(issued["permit_sha256"]), ok=False)
        self.assertIn("content_sha256 drifted", drift.stderr)

        self.bundle.write_bytes(b"encrypted-local-bundle\0v1\n")
        self.cli(
            "checkpoint",
            "--task",
            self.task_id,
            "--fact",
            "The export permit was issued but has not been consumed",
            "--risk",
            "The exact task state changed after issuance",
            "--next-action",
            "Issue a new export id if transfer is still intended",
        )
        stale = self.consume(str(issued["permit_sha256"]), ok=False)
        self.assertIn("task state drifted", stale.stderr)

    def test_expiry_and_single_assignment_fail_closed(self) -> None:
        issued = self.issue()
        paths = h.get_paths(self.root)
        with h.state_lock(paths, create_layout=False):
            with self.assertRaisesRegex(
                external_exports.ExternalExportError, "permit is expired"
            ):
                external_exports.consume_external_export_permit(
                    paths,
                    task_id=self.task_id,
                    permit_sha256=str(issued["permit_sha256"]),
                    source_file=self.bundle,
                    destination=self.destination,
                    purpose=self.purpose,
                    current_time=dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(minutes=20),
                )

        self.bundle.write_bytes(b"new encrypted bundle\n")
        different_sha = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        collision = self.cli(
            "external-export-permit-issue",
            "--task",
            self.task_id,
            "--export-id",
            self.export_id,
            "--source-file",
            str(self.bundle),
            "--expected-content-sha256",
            different_sha,
            "--destination",
            self.destination,
            "--purpose",
            self.purpose,
            "--expires-at",
            self._expiry(),
            ok=False,
        )
        self.assertIn("already assigned", collision.stderr)
        intent_files = list(
            (
                self.root
                / ".aoi"
                / "tasks"
                / self.task_id
                / external_exports.EXTERNAL_EXPORT_DIRECTORY
                / "intents"
            ).glob("*.json")
        )
        self.assertEqual(len(intent_files), 1)

    def test_permit_has_no_reusable_chief_credential_and_doctor_is_redacted(self) -> None:
        issued = self.issue()
        self.consume(str(issued["permit_sha256"]))
        permit_path = (
            self.root
            / ".aoi"
            / "tasks"
            / self.task_id
            / external_exports.EXTERNAL_EXPORT_DIRECTORY
            / "permits"
            / f"{issued['permit_sha256']}.json"
        )
        permit = json.loads(permit_path.read_text(encoding="utf-8"))
        serialized = json.dumps(permit, sort_keys=True)
        self.assertNotIn("credential_file", serialized)
        self.assertNotIn("chief_token", serialized)
        self.assertEqual(
            set(permit["chief_authority"]),
            {"session_id", "epoch", "authority_record_sha256"},
        )

        doctor = json.loads(self.cli("doctor", "--json").stdout)
        receipts = doctor["confidentiality"]["receipts"]["external_export"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "consumed")
        self.assertEqual(
            receipts[0]["destination"], "https://example.invalid"
        )
        self.assertFalse(receipts[0]["publication_observed"])
        self.assertNotIn(str(self.bundle), json.dumps(receipts))


if __name__ == "__main__":
    unittest.main()
