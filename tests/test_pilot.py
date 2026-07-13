#!/usr/bin/env python3
"""Closed-alpha pilot kit and result-boundary tests."""

from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import __version__  # noqa: E402
from aoi_orgware.pilot import (  # noqa: E402
    PilotError,
    _private_text_reason,
    initialize_kit,
    load_record,
    summary_csv,
    summary_json,
    summarize_records,
    validate_record,
    write_summary,
)


CLI_MODULE = "aoi_orgware.cli"


def measured(value: int | float, source: str = "provider_export") -> dict[str, object]:
    return {"value": value, "source": source, "missing_reason": ""}


def unavailable(reason: str = "runtime_not_exposed") -> dict[str, object]:
    return {"value": None, "source": "unavailable", "missing_reason": reason}


def record(
    *,
    participant: str = "pilot001",
    variant: str = "single",
    order: int = 1,
    task_id: str = "taskalpha",
    aggregate: bool = True,
) -> dict[str, object]:
    suffix = f"{participant}{variant}{order}"
    aoi = variant == "aoi"
    return {
        "schema_version": 1,
        "protocol_version": "closed-alpha-v1",
        "run_id": f"run{suffix}",
        "participant_id": participant,
        "task_pair_id": "pair001",
        "task_id": task_id,
        "task_order": order,
        "task_kind": "bugfix",
        "variant": variant,
        "run_status": "completed",
        "started_at": "2026-01-01T00:00:00+00:00",
        "ended_at": "2026-01-01T00:10:00+00:00",
        "oracle": {
            "pre_registered": True,
            "oracle_id": f"oracle{task_id}",
            "status": "pass",
        },
        "environment": {
            "runtime_label": "runtime001",
            "model_label": "model001",
            "tool_profile": "tools001",
            "package_sha256": "1" * 64,
            "control_profile_sha256": "2" * 64,
            "baseline_id": f"base{task_id}",
            "time_limit_minutes": 30,
        },
        "metrics": {
            "wall_seconds": 480 if aoi else 600,
            "human_minutes": 1 if aoi else 2,
            "interventions": 0 if aoi else 1,
            "retry_count": 1,
            "rework_count": 0,
            "regressions": 0,
            "baseline_mismatches": 0,
            "contract_mismatches": 0,
            "verification_omissions": 0,
            "unresolved_directives": 0,
        },
        "telemetry": {
            "input_tokens": measured(8000 if aoi else 10000),
            "output_tokens": measured(2500 if aoi else 3000),
            "high_capability_tokens": unavailable(),
            "provider_cost_usd": unavailable(),
        },
        "questionnaire": {
            "workflow_clarity": 4,
            "completion_confidence": 4,
            "cognitive_load": 3,
            "would_use_again": 4,
        },
        "consent": {
            "aggregate": aggregate,
            "share_with_coordinator": True,
        },
    }


class PilotRecordTests(unittest.TestCase):
    def test_valid_record_and_strict_schema(self) -> None:
        payload = record()
        self.assertEqual(validate_record(payload)["variant"], "single")

        unknown = copy.deepcopy(payload)
        unknown["notes"] = "not allowed"
        with self.assertRaisesRegex(PilotError, "unknown fields"):
            validate_record(unknown)

        bad_completion = copy.deepcopy(payload)
        bad_completion["oracle"]["status"] = "fail"
        with self.assertRaisesRegex(PilotError, "completed runs require"):
            validate_record(bad_completion)

        zero_limit = copy.deepcopy(payload)
        zero_limit["environment"]["time_limit_minutes"] = 0
        with self.assertRaisesRegex(PilotError, "must be positive"):
            validate_record(zero_limit)

    def test_missing_telemetry_and_private_text_fail_closed(self) -> None:
        payload = record()
        payload["telemetry"]["input_tokens"] = {
            "value": None,
            "source": "provider_export",
            "missing_reason": "",
        }
        with self.assertRaisesRegex(PilotError, "source='unavailable'"):
            validate_record(payload)

        private = record()
        private["telemetry"]["provider_cost_usd"] = unavailable("C:\\private\\pilot.log")
        with self.assertRaisesRegex(PilotError, "missing_reason must be one of"):
            validate_record(private)

    def test_provider_credentials_and_assignment_leaks_fail_closed(self) -> None:
        provider_values = {
            "github_classic": "ghp_" + "A" * 36,
            "github_oauth": "gho_" + "B" * 36,
            "github_user": "ghu_" + "C" * 36,
            "github_server": "ghs_" + "D" * 36,
            "github_refresh": "ghr_" + "E" * 36,
            "openai_legacy": "sk-" + "F" * 32,
            "openai_project": "sk-proj-" + "G" * 32,
            "anthropic": "sk-ant-api03-" + "H" * 32,
            "aws_long_term": "AKIA" + "J" * 16,
            "aws_temporary": "ASIA" + "K" * 16,
            "slack_bot": "xoxb-" + "L" * 24,
            "slack_app": "xapp-" + "M" * 24,
            "google_api": "AIza" + "N" * 35,
            "google_oauth": "GOCSPX-" + "P" * 24,
            "stripe_webhook": "whsec_" + "T" * 32,
        }
        for label, secret in provider_values.items():
            with self.subTest(label=label):
                payload = record()
                payload["environment"]["runtime_label"] = secret
                with self.assertRaises(PilotError) as caught:
                    validate_record(payload)
                self.assertNotIn(secret, str(caught.exception))

        direct_leaks = (
            "github_pat_" + "Q" * 70,
            "https://hooks.slack.com/services/T000/B000/secretvalue123",
            "Authorization: Bearer " + "R" * 24,
            "AWS_SECRET_ACCESS_KEY=" + "S" * 40,
            "SLACK_SIGNING_SECRET=" + "U" * 32,
            "STRIPE_WEBHOOK_SECRET=whsec_" + "V" * 32,
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        )
        for secret in direct_leaks:
            with self.subTest(secret_kind=secret[:16]):
                self.assertIsNotNone(_private_text_reason(secret))

    def test_credential_boundaries_and_placeholders_avoid_false_positives(self) -> None:
        benign = (
            "flask-api-server-production",
            "risk-sk-benchmark-reference",
            "api_key=",
            "api_key=${OPENAI_API_KEY}",
            "api_key=REDACTED",
            "password=<placeholder>",
        )
        for text in benign:
            with self.subTest(text=text):
                self.assertIsNone(_private_text_reason(text))

    def test_non_finite_numbers_fail_closed(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                payload = record()
                payload["metrics"]["wall_seconds"] = value
                with self.assertRaisesRegex(PilotError, "must be finite"):
                    validate_record(payload)
        huge = record()
        huge["metrics"]["wall_seconds"] = 10**10000
        with self.assertRaisesRegex(PilotError, "finite non-negative"):
            validate_record(huge)
        with self.assertRaises(ValueError):
            summary_json({"invalid": float("nan")})

    def test_summary_is_deidentified_paired_and_reports_missingness(self) -> None:
        single = record(variant="single", order=1, task_id="taskalpha")
        aoi = record(variant="aoi", order=2, task_id="taskbeta")
        summary = summarize_records([aoi, single])

        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["participant_count"], 1)
        self.assertEqual(summary["paired"]["complete_pair_count"], 1)
        self.assertEqual(summary["paired"]["metrics"]["wall_seconds"]["mean"], -120.0)
        self.assertEqual(
            summary["variants"]["single"]["metrics"]["provider_cost_usd"]["missing"],
            1,
        )
        self.assertEqual(
            summary["variants"]["single"]["metrics"]["workflow_clarity"]["mean"],
            4.0,
        )
        rendered = json.dumps(summary, sort_keys=True)
        self.assertNotIn("pilot001", rendered)
        self.assertNotIn("withdraw", rendered)
        self.assertNotIn("withdrawal_code", record()["consent"])

    def test_summary_rejects_consent_duplicates_and_same_task_carryover(self) -> None:
        with self.assertRaisesRegex(PilotError, "lacks coordinator-sharing"):
            summarize_records([record(aggregate=False)])

        no_share = record()
        no_share["consent"]["share_with_coordinator"] = False
        with self.assertRaisesRegex(PilotError, "lacks coordinator-sharing"):
            summarize_records([no_share])

        duplicate = record()
        with self.assertRaisesRegex(PilotError, "duplicate run_id"):
            summarize_records([duplicate, copy.deepcopy(duplicate)])

        single = record(variant="single", order=1, task_id="tasksame")
        aoi = record(variant="aoi", order=2, task_id="tasksame")
        with self.assertRaisesRegex(PilotError, "two different task_id"):
            summarize_records([single, aoi])

    def test_pair_control_drift_is_rejected(self) -> None:
        fields = {
            "runtime_label": "runtime002",
            "model_label": "model002",
            "tool_profile": "tools002",
            "package_sha256": "3" * 64,
            "control_profile_sha256": "4" * 64,
            "time_limit_minutes": 45,
        }
        for field, changed in fields.items():
            with self.subTest(field=field):
                single = record(variant="single", order=1, task_id="taskalpha")
                aoi = record(variant="aoi", order=2, task_id="taskbeta")
                aoi["environment"][field] = changed
                with self.assertRaisesRegex(PilotError, f"environment.{field}"):
                    summarize_records([single, aoi])

    def test_csv_preserves_status_oracle_denominators_and_pairing(self) -> None:
        single = record(variant="single", order=1, task_id="taskalpha")
        aoi = record(variant="aoi", order=2, task_id="taskbeta")
        rendered = summary_csv(summarize_records([single, aoi])).decode("utf-8")
        self.assertIn("metadata,,protocol_version,closed-alpha-v1", rendered)
        self.assertIn(
            "metadata,,analysis_boundary,descriptive_closed_alpha_only", rendered
        )
        self.assertIn("run_status,single,completed,1", rendered)
        self.assertIn("oracle_status,aoi,pass,1", rendered)
        self.assertIn("denominator,aoi,run_count,1", rendered)
        self.assertIn("pairing,,complete_pair_count,1", rendered)
        self.assertIn("pairing,,incomplete_pair_count,0", rendered)


class PilotKitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(SRC)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def cli(self, *args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(args)}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        return result

    def initialize(self, output: Path, *, force: bool = False) -> dict[str, object]:
        return initialize_kit(
            output,
            force=force,
            allow_unverified_windows_acl=os.name == "nt",
        )

    def test_initialize_no_clobber_force_and_manifest(self) -> None:
        kit = self.root / "kit"
        result = self.initialize(kit)
        self.assertTrue(result["created"])
        self.assertEqual(result["file_count"], 14)
        manifest = json.loads((kit / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["aoi_version"], __version__)
        self.assertTrue((kit / "AGENTS.md").is_file())
        self.assertTrue((kit / "sample_project" / "TASK.md").is_file())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(kit.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((kit / "feedback-private.template.md").stat().st_mode),
                0o600,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (kit / "withdrawal-private.template.csv").stat().st_mode
                ),
                0o600,
            )

        readme = kit / "README.md"
        readme.write_text("tester note\n", encoding="utf-8")
        with self.assertRaisesRegex(PilotError, "refusing to overwrite"):
            self.initialize(kit)
        self.assertEqual(readme.read_text(encoding="utf-8"), "tester note\n")

        unknown = kit / "keep-me.txt"
        unknown.write_text("private note\n", encoding="utf-8")
        private_mapping = kit / "withdrawal-private.csv"
        private_mapping.write_text(
            "withdrawal_code,participant_id\nrandomcode,pilot001\n",
            encoding="utf-8",
        )
        self.initialize(kit, force=True)
        self.assertIn("AOI Closed Alpha Kit", readme.read_text(encoding="utf-8"))
        self.assertEqual(unknown.read_text(encoding="utf-8"), "private note\n")
        self.assertIn("randomcode", private_mapping.read_text(encoding="utf-8"))

    def test_template_requires_fill_and_sample_oracle_starts_failing(self) -> None:
        kit = self.root / "kit"
        self.initialize(kit)
        with self.assertRaisesRegex(PilotError, "package_sha256"):
            load_record(kit / "run-record.template.json")

        sample = kit / "sample_project"
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py", "-v"],
            cwd=sample,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stderr)

    def test_standalone_cli_init_validate_and_deterministic_summary(self) -> None:
        init_args = ["pilot-init", "--output", "kit", "--json"]
        if os.name == "nt":
            init_args.append("--allow-unverified-windows-acl")
        init = self.cli(*init_args)
        self.assertTrue(json.loads(init.stdout)["created"])

        records_dir = self.root / "records"
        records_dir.mkdir()
        first = records_dir / "single.json"
        second = records_dir / "aoi.json"
        first.write_text(
            json.dumps(record(variant="single", order=1, task_id="taskalpha")),
            encoding="utf-8",
        )
        second.write_text(
            json.dumps(record(variant="aoi", order=2, task_id="taskbeta")),
            encoding="utf-8",
        )
        validated = self.cli("pilot-validate", "--record", str(first), "--json")
        self.assertTrue(json.loads(validated.stdout)["ok"])

        self.cli(
            "pilot-summary",
            "--record",
            str(first),
            "--record",
            str(second),
            "--output",
            "summary-a.json",
            "--json",
        )
        self.cli(
            "pilot-summary",
            "--record",
            str(second),
            "--record",
            str(first),
            "--output",
            "summary-b.json",
            "--json",
        )
        self.assertEqual(
            (self.root / "summary-a.json").read_bytes(),
            (self.root / "summary-b.json").read_bytes(),
        )

    def test_pilot_help_works_outside_initialized_project(self) -> None:
        result = self.cli("pilot-init", "--help")
        self.assertIn("closed-alpha tester kit", result.stdout)

    @unittest.skipUnless(os.name == "nt", "native Windows ACL boundary")
    def test_native_windows_pilot_requires_explicit_acl_acknowledgement(self) -> None:
        with self.assertRaisesRegex(PilotError, "ACL privacy is not verified"):
            initialize_kit(self.root / "unacknowledged")
        result = initialize_kit(
            self.root / "acknowledged", allow_unverified_windows_acl=True
        )
        self.assertEqual(result["privacy_boundary"], "windows_acl_unverified")

    def test_summary_refuses_directory_even_with_force(self) -> None:
        with self.assertRaisesRegex(PilotError, "is a directory"):
            write_summary(
                [record()],
                self.root,
                output_format="json",
                force=True,
            )


if __name__ == "__main__":
    unittest.main()
