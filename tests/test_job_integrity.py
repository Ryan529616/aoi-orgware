#!/usr/bin/env python3
"""Fast contract tests for the extracted job-integrity boundary."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import job_integrity as ji  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


def _event_authority_sha(event: dict[str, object]) -> str:
    unhashed = dict(event)
    unhashed.pop("authority_sha256", None)
    return hashlib.sha256(
        json.dumps(
            unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


class JobIntegrityPolicyTests(unittest.TestCase):
    def test_policy_is_frozen_and_stores_component_tuples(self) -> None:
        policy = ji.JobIntegrityPolicy(
            receipt_components=("source", "runner"),
            required_receipt_components=("source",),
        )
        self.assertEqual(policy.receipt_components, ("source", "runner"))
        self.assertEqual(policy.required_receipt_components, ("source",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.receipt_components = ("x",)  # type: ignore[misc]

    def test_cli_factory_snapshots_mutable_receipt_globals(self) -> None:
        from aoi_orgware import cli

        original_components = cli.RECEIPT_COMPONENTS
        original_required = cli.REQUIRED_RECEIPT_COMPONENTS
        try:
            snapshot = cli._job_integrity_policy()
            self.assertEqual(snapshot.receipt_components, tuple(original_components))
            self.assertEqual(
                snapshot.required_receipt_components, tuple(original_required)
            )
            cli.RECEIPT_COMPONENTS = ("source",)
            cli.REQUIRED_RECEIPT_COMPONENTS = ("source",)
            rebuilt = cli._job_integrity_policy()
            self.assertEqual(rebuilt.receipt_components, ("source",))
            # The earlier snapshot is frozen and immune to the later mutation.
            self.assertEqual(snapshot.receipt_components, tuple(original_components))
        finally:
            cli.RECEIPT_COMPONENTS = original_components
            cli.REQUIRED_RECEIPT_COMPONENTS = original_required


class ValidateSourceReceiptTests(unittest.TestCase):
    def _write_receipt(self, path: Path, components: dict[str, object]) -> str:
        payload = {
            "receipt_version": 1,
            "source_set_id": "set-1",
            "producer": "producer-1",
            "tool": {"path": "/opt/tool", "version": "1.2.3", "command": "run --x"},
            "components": components,
        }
        data = json.dumps(payload).encode("utf-8")
        path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def test_policy_component_set_is_honored(self) -> None:
        import tempfile

        source_component = {
            "status": "included",
            "files": [{"path": "/abs/src.py", "sha256": "a" * 64}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "receipt.json"
            sha = self._write_receipt(receipt, {"source": source_component})

            minimal = ji.JobIntegrityPolicy(
                receipt_components=("source",),
                required_receipt_components=("source",),
            )
            payload, data = ji.validate_source_receipt(
                receipt,
                sha,
                tool_path="/opt/tool",
                tool_version="1.2.3",
                command="run --x",
                policy=minimal,
            )
            self.assertEqual(payload["source_set_id"], "set-1")
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha)

            # A stricter policy demands components the receipt does not carry.
            strict = ji.JobIntegrityPolicy(
                receipt_components=("source", "runner"),
                required_receipt_components=("source", "runner"),
            )
            with self.assertRaisesRegex(HarnessError, "runner"):
                ji.validate_source_receipt(
                    receipt,
                    sha,
                    tool_path="/opt/tool",
                    tool_version="1.2.3",
                    command="run --x",
                    policy=strict,
                )


class JobLaunchAuthorityRecordTests(unittest.TestCase):
    def test_record_seals_itself_and_binds_selection(self) -> None:
        job = {
            "lane_id": "lane-a",
            "owner_packet_id": "pkt-1",
            "owner_packet_contract_sha256": "c" * 8,
        }
        selection = {
            "selection_id": "sel-1",
            "lane_snapshots": [{"lane_id": "lane-a", "revision": 3}],
        }
        record = ji._job_launch_authority_record(job, selection, {"skill_release_id": "r1"})
        self.assertEqual(record["integrity_version"], 1)
        self.assertEqual(record["execution_selection_id"], "sel-1")
        self.assertEqual(record["lane_id"], "lane-a")
        self.assertEqual(record["lane_snapshot"], {"lane_id": "lane-a", "revision": 3})
        self.assertEqual(record["skill_binding"], {"skill_release_id": "r1"})
        self.assertEqual(record["authority_sha256"], _event_authority_sha(record))

    def test_record_without_selection_is_unbound(self) -> None:
        record = ji._job_launch_authority_record({"lane_id": "lane-a"}, None, None)
        self.assertEqual(record["execution_selection_id"], "")
        self.assertEqual(record["lane_snapshot"], {})
        self.assertEqual(record["skill_binding"], {})


class JobLaunchAuthorityErrorsTests(unittest.TestCase):
    def test_non_v1_short_circuits_without_touching_services(self) -> None:
        def _boom(*args, **kwargs):
            raise AssertionError("skill-canary service must not be called")

        services = ji.JobIntegrityServices(
            validate_skill_canary_work_unit_binding=_boom,
            execution_topology=None,  # type: ignore[arg-type]
        )
        self.assertEqual(
            ji._job_launch_authority_errors(
                {}, {"launch_authority_version": 0}, services=services
            ),
            [],
        )

    def test_injected_skill_binding_result_drives_the_mismatch_error(self) -> None:
        calls: list[tuple[str, str]] = []

        def _binding(state, release_id, canary_event_id, *, require_live_canary):
            calls.append((release_id, canary_event_id))
            return {"skill_release_id": "changed"}

        services = ji.JobIntegrityServices(
            validate_skill_canary_work_unit_binding=_binding,
            execution_topology=None,  # type: ignore[arg-type]
        )
        job = {
            "run_id": "run-1",
            "launch_authority_version": 1,
            "status": "queued",
            "lane_id": "lane-a",
            "execution_selection_id": "",
            "owner_packet_id": "pkt-1",
            "owner_packet_contract_sha256": "sha-1",
            "skill_release_id": "rel-9",
            "skill_canary_event_id": "evt-9",
        }
        event = {
            "integrity_version": 1,
            "lane_id": "lane-a",
            "execution_selection_id": "",
            "owner_packet_id": "pkt-1",
            "owner_packet_contract_sha256": "sha-1",
            "lane_snapshot": {},
            "skill_binding": {},
        }
        event["authority_sha256"] = _event_authority_sha(event)
        job["launch_authority_events"] = [event]

        errors = ji._job_launch_authority_errors({}, job, services=services)
        self.assertEqual(calls, [("rel-9", "evt-9")])
        self.assertEqual(
            errors,
            ["job run-1 launch event 0 skill binding changed"],
        )


class JobRegistrationLagTests(unittest.TestCase):
    """The ARISE ledger hid ~1-minute tmux-before-registration inversions because
    the recorded start time WAS the registration time."""

    REGISTERED = "2026-07-16T10:02:00+00:00"

    def _job(self, **overrides: object) -> dict:
        job = {"run_id": "run-1"}
        job.update(overrides)
        return job

    def test_legacy_job_without_fields_is_untouched(self) -> None:
        self.assertEqual(
            ji._job_registration_lag_errors(self._job(), "run-1"), []
        )

    def test_observed_launch_within_bound_validates(self) -> None:
        job = self._job(
            registered_at=self.REGISTERED,
            observed_start_at="2026-07-16T10:01:30+00:00",
            registration_lag_seconds=30.0,
        )
        self.assertEqual(ji._job_registration_lag_errors(job, "run-1"), [])

    def test_lag_recompute_mismatch_is_detected(self) -> None:
        job = self._job(
            registered_at=self.REGISTERED,
            observed_start_at="2026-07-16T10:01:30+00:00",
            registration_lag_seconds=5.0,
        )
        errors = ji._job_registration_lag_errors(job, "run-1")
        self.assertTrue(any("does not match" in item for item in errors), errors)

    def test_naive_observed_start_is_rejected(self) -> None:
        job = self._job(
            registered_at=self.REGISTERED,
            observed_start_at="2026-07-16T10:01:30",
            registration_lag_seconds=30.0,
        )
        errors = ji._job_registration_lag_errors(job, "run-1")
        self.assertTrue(any("not timezone-aware" in item for item in errors), errors)

    def test_retroactive_lag_requires_reason(self) -> None:
        job = self._job(
            registered_at="2026-07-16T10:05:00+00:00",
            observed_start_at="2026-07-16T10:00:00+00:00",
            registration_lag_seconds=300.0,
        )
        errors = ji._job_registration_lag_errors(job, "run-1")
        self.assertTrue(
            any(
                f"{ji.JOB_REGISTRATION_LAG_LIMIT_SECONDS}s without a retroactive reason"
                in item
                for item in errors
            ),
            errors,
        )

    def test_retroactive_lag_with_reason_validates(self) -> None:
        job = self._job(
            registered_at="2026-07-16T10:05:00+00:00",
            observed_start_at="2026-07-16T10:00:00+00:00",
            registration_lag_seconds=300.0,
            retroactive_reason="tmux launch preceded AOI registration by 5 minutes",
        )
        self.assertEqual(ji._job_registration_lag_errors(job, "run-1"), [])

    def test_observed_after_registration_is_rejected(self) -> None:
        job = self._job(
            registered_at="2026-07-16T10:00:00+00:00",
            observed_start_at="2026-07-16T10:05:00+00:00",
            registration_lag_seconds=-300.0,
        )
        errors = ji._job_registration_lag_errors(job, "run-1")
        self.assertTrue(any("post-dates" in item for item in errors), errors)

    def test_lag_without_observed_start_is_rejected(self) -> None:
        job = self._job(
            registered_at=self.REGISTERED,
            registration_lag_seconds=30.0,
        )
        errors = ji._job_registration_lag_errors(job, "run-1")
        self.assertTrue(
            any("without an observed start" in item for item in errors), errors
        )


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "job_integrity.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "aoi_orgware.cli" for alias in node.names):
                    violations.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"cli", "aoi_orgware.cli"} or any(
                    alias.name == "cli" for alias in node.names
                ):
                    violations.append(f"{path.name}:{node.lineno}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
