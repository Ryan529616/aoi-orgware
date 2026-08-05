"""Focused contract tests for the bounded legacy v0.4 snapshot producer."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from aoi_orgware.company.contracts import canonical_company_json_bytes
from aoi_orgware.company.file_governance import scan_privacy_counts
from aoi_orgware.evidence_artifacts import read_regular_artifact
from aoi_orgware.harnesslib import HarnessError
import aoi_orgware.legacy_bridge_snapshot_v04 as legacy_snapshot
from aoi_orgware.legacy_bridge_snapshot_v04 import (
    LegacyBridgeSnapshotV04Error,
    legacy_bridge_agent_id_v04,
    produce_legacy_bridge_snapshot_v04,
)
from tests.harness_case import HarnessTestCase


def _rooted_agent(*segments: str) -> str:
    """Build one synthetic provider agent identity from explicit segments."""

    return "/".join(("", "root", *segments))


class LegacyBridgeSnapshotV04Tests(unittest.TestCase):
    def _produce(
        self, state: dict[str, object], reads: list[tuple[tuple[int, int], bytes]] | None = None,
        *, semantic: bool = False, claim_error: Exception | None = None,
        raw_a: bytes | None = None, raw_b: bytes | None = None,
    ):
        state = {
            "task_id": "task-1", "profile_id": "profile-1", "config_sha256": "a" * 64,
            **state,
        }
        raw = canonical_company_json_bytes(state)
        raw_a = raw if raw_a is None else raw_a
        raw_b = raw_a if raw_b is None else raw_b
        with (
            mock.patch(
                "aoi_orgware.legacy_bridge_snapshot_v04.state_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch(
                "aoi_orgware.legacy_bridge_snapshot_v04.is_semantic_v2_task",
                return_value=semantic,
            ),
            mock.patch(
                "aoi_orgware.legacy_bridge_snapshot_v04.task_state_path",
                return_value=mock.sentinel.path,
            ),
            mock.patch("aoi_orgware.legacy_bridge_snapshot_v04.validate_task_state"),
            mock.patch(
                "aoi_orgware.legacy_bridge_snapshot_v04.validate_task_claim_references",
                side_effect=claim_error,
            ),
            mock.patch("aoi_orgware.legacy_bridge_snapshot_v04._validate_legacy_integrity"),
            mock.patch(
                "aoi_orgware.legacy_bridge_snapshot_v04._stable_state_read",
                side_effect=reads or [((1, 2), raw_a), ((1, 2), raw_b)],
            ),
        ):
            from aoi_orgware.harnesslib import HarnessPaths

            paths = mock.create_autospec(HarnessPaths, instance=True)
            paths.project.profile_id = "profile-1"
            paths.project.sha256 = "a" * 64
            return produce_legacy_bridge_snapshot_v04(
                paths, "task-1", "company-1", 1, 0, "a" * 64,
                "0.4.0a4", "2026-08-05T00:00:00Z",
            )

    def test_canonical_redacted_snapshot_and_immutable_result(self) -> None:
        result = self._produce({
            "status": "active",
            "packets": [
                {"packet_id": "packet-1", "status": "dispatched", "agent_id": "agent-1", "parent_packet_id": "", "path": "C:/secret-packet"},
                {"packet_id": "packet-missing", "status": "ready", "parent_packet_id": "gone-packet"},
            ],
            "jobs": [
                {"run_id": "job-1", "status": "running", "owner_packet_id": "packet-1", "command": "secret command", "log": "C:/secret.log", "work_root": "C:/secret-root"},
                {"run_id": "job-orphan", "status": "unknown", "owner_packet_id": ""},
            ],
            "needs_user_escalations": [{"escalation_id": "ask-1", "status": "resolved", "problem": "secret prose", "options": ["secret option"], "root_session_id": "secret-session"}],
        })
        document = json.loads(result.snapshot_bytes)
        self.assertEqual(result.snapshot_sha256, hashlib.sha256(result.snapshot_bytes).hexdigest())
        self.assertEqual(result.snapshot_bytes, canonical_company_json_bytes(document))
        self.assertEqual(document["legacy_receipt_quality"], "unavailable")
        self.assertNotIn("secret", result.snapshot_bytes.decode("utf-8"))
        self.assertNotIn("C:/", result.snapshot_bytes.decode("utf-8"))
        unknown_job = next(entity for entity in result.projection.entities if entity.kind == "job" and entity.stated_status == "unknown")
        task = next(entity for entity in result.projection.entities if entity.kind == "task")
        root_packet = next(entity for entity in result.projection.entities if entity.kind == "packet" and entity.stated_status == "dispatched")
        missing_packet = next(entity for entity in result.projection.entities if entity.kind == "packet" and entity.stated_status == "ready")
        agent = next(entity for entity in result.projection.entities if entity.kind == "agent")
        needs_user = next(entity for entity in result.projection.entities if entity.kind == "needs_user")
        self.assertEqual(unknown_job.orphan_reason, "explicit_parent_unavailable")
        self.assertEqual(unknown_job.effect_status, "effect_unknown")
        self.assertIsNone(root_packet.orphan_reason)
        self.assertEqual(root_packet.parent_bridge_entity_id, task.bridge_entity_id)
        self.assertEqual(agent.parent_bridge_entity_id, root_packet.bridge_entity_id)
        self.assertEqual(missing_packet.orphan_reason, "explicit_parent_absent")
        self.assertEqual(needs_user.orphan_reason, "explicit_parent_unavailable")
        self.assertEqual(
            [(entry["kind"], entry["stated_status"], entry["parent_kind"]) for entry in document["entries"]],
            [
                ("task", "active", None), ("packet", "dispatched", "task"),
                ("packet", "ready", "packet"), ("agent", "unknown", "packet"),
                ("job", "running", "packet"), ("job", "unknown", None),
                ("needs_user", "answered", None),
            ],
        )
        with self.assertRaises(AttributeError):
            result.snapshot_sha256 = "b" * 64  # type: ignore[misc]

    def test_needs_user_parent_is_unavailable_and_terminal_statuses_map(self) -> None:
        result = self._produce({
            "status": "cancelled", "packets": [], "jobs": [],
            "needs_user_escalations": [
                {"escalation_id": "answer", "status": "resolved", "source_lane_id": "ignored"},
                {"escalation_id": "expiry", "status": "cancelled", "run_id": "not-a-parent"},
            ],
        })
        entries = {entry["legacy_id"]: entry for entry in json.loads(result.snapshot_bytes)["entries"]}
        self.assertEqual(entries["answer"]["stated_status"], "answered")
        self.assertEqual(entries["expiry"]["stated_status"], "expired")
        self.assertIsNone(entries["answer"]["parent_kind"])
        self.assertIsNone(entries["expiry"]["parent_legacy_id"])

    def test_exact_input_is_deterministic_but_raw_list_order_is_observed(self) -> None:
        common: dict[str, object] = {"status": "active", "jobs": [], "needs_user_escalations": []}
        left = self._produce(dict(common, packets=[
            {"packet_id": "packet-z", "status": "ready", "parent_packet_id": ""},
            {"packet_id": "packet-a", "status": "failed", "parent_packet_id": "packet-z"},
        ]))
        repeat = self._produce(dict(common, packets=[
            {"packet_id": "packet-z", "status": "ready", "parent_packet_id": ""},
            {"packet_id": "packet-a", "status": "failed", "parent_packet_id": "packet-z"},
        ]))
        right = self._produce(dict(common, packets=[
            {"packet_id": "packet-a", "status": "failed", "parent_packet_id": "packet-z"},
            {"packet_id": "packet-z", "status": "ready", "parent_packet_id": ""},
        ]))
        self.assertEqual(left.snapshot_bytes, repeat.snapshot_bytes)
        self.assertEqual(left.snapshot_sha256, repeat.snapshot_sha256)
        self.assertNotEqual(left.snapshot_bytes, right.snapshot_bytes)
        self.assertNotEqual(
            json.loads(left.snapshot_bytes)["legacy_state_sha256"],
            json.loads(right.snapshot_bytes)["legacy_state_sha256"],
        )
        self.assertEqual(
            [(item.kind, item.legacy_identity_digest) for item in left.projection.entities],
            [(item.kind, item.legacy_identity_digest) for item in right.projection.entities],
        )

    def test_explicit_orphans_duplicates_semantic_and_race_fail_typed(self) -> None:
        base: dict[str, object] = {"status": "active", "packets": [], "jobs": [], "needs_user_escalations": []}
        raw_a = canonical_company_json_bytes({
            "task_id": "task-1", "profile_id": "profile-1", "config_sha256": "a" * 64,
            **base,
        })
        raw_b = canonical_company_json_bytes({
            "task_id": "task-1", "profile_id": "profile-1", "config_sha256": "a" * 64,
            **base, "packets": [{"packet_id": "packet-b", "status": "ready"}],
        })
        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "changed"):
            self._produce(base, [((1, 2), raw_a), ((1, 3), raw_b)])
        duplicate = dict(base, packets=[
            {"packet_id": "packet-1", "status": "ready", "parent_packet_id": ""},
            {"packet_id": "packet-1", "status": "ready", "parent_packet_id": ""},
        ])
        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "ambiguous"):
            self._produce(duplicate)
        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "semantic-v2"):
            self._produce(base, semantic=True)
        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "task read failed"):
            self._produce(base, claim_error=HarnessError("claim reference integrity failed"))

    def test_exact_state_parser_rejects_duplicate_utf8_and_nonfinite_json(self) -> None:
        base: dict[str, object] = {"status": "active", "packets": [], "jobs": [], "needs_user_escalations": []}
        invalid = [
            b'{"task_id":"task-1","task_id":"other"}',
            b'\xff',
            b'{"value":NaN}',
            b'{"value":1e999}',
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaisesRegex(
                LegacyBridgeSnapshotV04Error, "task state bytes are invalid"
            ):
                self._produce(base, raw_a=raw, raw_b=raw)

    def test_full_record_digest_changes_for_hidden_job_field(self) -> None:
        common: dict[str, object] = {
            "status": "active", "packets": [], "needs_user_escalations": [],
        }
        left = self._produce(dict(common, jobs=[{
            "run_id": "job-1", "status": "running", "hidden": "first-secret",
        }]))
        right = self._produce(dict(common, jobs=[{
            "run_id": "job-1", "status": "running", "hidden": "second-secret",
        }]))
        left_job = next(item for item in json.loads(left.snapshot_bytes)["entries"] if item["kind"] == "job")
        right_job = next(item for item in json.loads(right.snapshot_bytes)["entries"] if item["kind"] == "job")
        self.assertNotEqual(left_job["source_record_sha256"], right_job["source_record_sha256"])
        self.assertNotIn("first-secret", left.snapshot_bytes.decode("utf-8"))
        self.assertNotIn("second-secret", right.snapshot_bytes.decode("utf-8"))

    def test_pathlike_identifiers_are_typed_and_not_echoed(self) -> None:
        from aoi_orgware.harnesslib import HarnessPaths

        paths = mock.create_autospec(HarnessPaths, instance=True)
        for bad, task_id, company_id in [
            ("C:/unsafe", "C:/unsafe", "company-1"),
            ("../unsafe", "task-1", "../unsafe"),
        ]:
            with self.subTest(argument=bad), self.assertRaises(LegacyBridgeSnapshotV04Error) as raised:
                produce_legacy_bridge_snapshot_v04(
                    paths, task_id, company_id, 1, 0, "a" * 64,
                    "0.4.0a4", "2026-08-05T00:00:00Z",
                )
            self.assertNotIn(bad, str(raised.exception))
        base: dict[str, object] = {"status": "active", "packets": [], "jobs": [], "needs_user_escalations": []}
        invalid_states = [
            dict(base, packets=[{"packet_id": "C:/unsafe", "status": "ready"}]),
            dict(base, packets=[{"packet_id": "packet-1", "status": "ready", "agent_id": "../unsafe"}]),
            dict(base, packets=[{"packet_id": "packet-1", "status": "ready", "agent_id": "C:/unsafe"}]),
            dict(base, packets=[{"packet_id": "packet-1", "status": "ready", "agent_id": _rooted_agent("..", "unsafe")}]),
            dict(base, jobs=[{"run_id": "C:/unsafe", "status": "running"}]),
            dict(base, needs_user_escalations=[{"escalation_id": "../unsafe", "status": "needs_user"}]),
        ]
        for state in invalid_states:
            with self.subTest(state=state), self.assertRaises(LegacyBridgeSnapshotV04Error) as raised:
                self._produce(state)
            self.assertNotIn("unsafe", str(raised.exception))

    def test_rooted_agents_map_to_deterministic_bridge_surrogates(self) -> None:
        raw_a = _rooted_agent("reviewer")
        raw_b = _rooted_agent("team", "reviewer")
        mapped_a = legacy_bridge_agent_id_v04(raw_a)
        mapped_b = legacy_bridge_agent_id_v04(raw_b)
        self.assertEqual(legacy_bridge_agent_id_v04("agent-safe"), "agent-safe")
        self.assertEqual(mapped_a, legacy_bridge_agent_id_v04(raw_a))
        self.assertEqual(
            mapped_a,
            "root@" + hashlib.sha256(
                b"aoi-orgware:legacy-bridge-agent-v04\x00" + raw_a.encode("utf-8")
            ).hexdigest(),
        )
        self.assertRegex(mapped_a, r"root@[0-9a-f]{64}")
        self.assertNotEqual(mapped_a, mapped_b)
        result = self._produce({
            "status": "active", "jobs": [], "needs_user_escalations": [], "packets": [
                {"packet_id": "packet-a", "status": "dispatched", "agent_id": raw_a},
                {"packet_id": "packet-b", "status": "ready", "agent_id": raw_b},
            ],
        })
        snapshot_text = result.snapshot_bytes.decode("utf-8")
        agents = {
            item["legacy_id"]: item
            for item in json.loads(result.snapshot_bytes)["entries"]
            if item["kind"] == "agent"
        }
        self.assertNotIn(raw_a, snapshot_text)
        self.assertNotIn(raw_b, snapshot_text)
        self.assertEqual(agents[mapped_a]["parent_legacy_id"], "packet-a")
        self.assertEqual(agents[mapped_b]["parent_legacy_id"], "packet-b")
        self.assertEqual(len(result.projection.entities), 5)
        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "multiple packets"):
            self._produce({
                "status": "active", "jobs": [], "needs_user_escalations": [], "packets": [
                    {"packet_id": "packet-a", "status": "ready", "agent_id": raw_a},
                    {"packet_id": "packet-b", "status": "ready", "agent_id": raw_a},
                ],
            })

    def test_provider_identity_parser_does_not_relax_privacy_scanning(self) -> None:
        source = Path(legacy_snapshot.__file__).read_bytes()
        fixture = Path(__file__).read_bytes()
        self.assertEqual(
            scan_privacy_counts("src/aoi_orgware/legacy_bridge_snapshot_v04.py", source),
            (),
        )
        self.assertEqual(
            scan_privacy_counts("tests/test_legacy_bridge_snapshot_v04.py", fixture),
            (),
        )
        actual_home_path = (_rooted_agent("private", "work") + "\n").encode("utf-8")
        findings = scan_privacy_counts("docs/runtime-observation.txt", actual_home_path)
        self.assertEqual(
            tuple((finding.rule_id, finding.count) for finding in findings),
            (("posix_user_home", 1),),
        )

    def test_integrity_probe_errors_are_rejected_without_diagnostics(self) -> None:
        from aoi_orgware.harnesslib import HarnessPaths

        paths = mock.create_autospec(HarnessPaths, instance=True)
        state: dict[str, object] = {"status": "active", "packets": [], "jobs": [], "needs_user_escalations": []}
        probes = [
            ("packet_integrity_errors", "missing dispatched agent: C:/secret"),
            ("job_integrity_errors", "missing job integrity: C:/secret"),
            ("portfolio_integrity_errors", "resolved without disposition: C:/secret"),
        ]
        for name, diagnostic in probes:
            with (
                self.subTest(probe=name),
                mock.patch("aoi_orgware.cli.packet_integrity_errors", return_value=[]),
                mock.patch("aoi_orgware.cli.job_integrity_errors", return_value=[]),
                mock.patch("aoi_orgware.cli.portfolio_integrity_errors", return_value=[]),
            ):
                with mock.patch("aoi_orgware.cli." + name, return_value=[diagnostic]):
                    with self.assertRaisesRegex(
                        LegacyBridgeSnapshotV04Error, "legacy task integrity validation failed"
                    ) as raised:
                        legacy_snapshot._validate_legacy_integrity(paths, state)
                self.assertNotIn("C:/secret", str(raised.exception))

    def test_integrity_memory_error_propagates_but_ordinary_error_is_redacted(self) -> None:
        from aoi_orgware.harnesslib import HarnessPaths

        paths = mock.create_autospec(HarnessPaths, instance=True)
        state: dict[str, object] = {"status": "active", "packets": [], "jobs": [], "needs_user_escalations": []}
        with mock.patch("aoi_orgware.cli.packet_integrity_errors", side_effect=MemoryError):
            with self.assertRaises(MemoryError):
                legacy_snapshot._validate_legacy_integrity(paths, state)
        with mock.patch(
            "aoi_orgware.cli.packet_integrity_errors",
            side_effect=RuntimeError("C:/secret ordinary failure"),
        ):
            with self.assertRaisesRegex(
                LegacyBridgeSnapshotV04Error, "legacy task integrity validation failed"
            ) as raised:
                legacy_snapshot._validate_legacy_integrity(paths, state)
        self.assertNotIn("C:/secret", str(raised.exception))

    def test_same_agent_across_packets_fails(self) -> None:
        state: dict[str, object] = {"status": "active", "jobs": [], "needs_user_escalations": [], "packets": [
            {"packet_id": "packet-1", "status": "ready", "agent_id": "agent-1", "parent_packet_id": ""},
            {"packet_id": "packet-1b", "status": "ready", "agent_id": "agent-1", "parent_packet_id": ""},
        ]}
        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "multiple packets"):
            self._produce(state)

    def test_agents_bind_and_digest_their_exact_carrying_packets(self) -> None:
        first = {"packet_id": "packet-a", "status": "dispatched", "agent_id": "agent-a"}
        second = {"packet_id": "packet-b", "status": "ready", "agent_id": "agent-b"}
        result = self._produce({
            "status": "active", "jobs": [], "needs_user_escalations": [],
            "packets": [first, {"packet_id": "packet-z", "status": "ready"}, second],
        })
        agents = {
            item["legacy_id"]: item
            for item in json.loads(result.snapshot_bytes)["entries"]
            if item["kind"] == "agent"
        }
        self.assertEqual(agents["agent-a"]["parent_legacy_id"], "packet-a")
        self.assertEqual(agents["agent-b"]["parent_legacy_id"], "packet-b")
        self.assertEqual(
            agents["agent-a"]["source_record_sha256"],
            hashlib.sha256(canonical_company_json_bytes(first)).hexdigest(),
        )
        self.assertEqual(
            agents["agent-b"]["source_record_sha256"],
            hashlib.sha256(canonical_company_json_bytes(second)).hexdigest(),
        )

    def test_lone_surrogate_source_version_is_typed(self) -> None:
        from aoi_orgware.harnesslib import HarnessPaths

        with self.assertRaisesRegex(LegacyBridgeSnapshotV04Error, "source_version"):
            produce_legacy_bridge_snapshot_v04(
                mock.create_autospec(HarnessPaths, instance=True), "task-1", "company-1",
                1, 0, "a" * 64, "\ud800", "2026-08-05T00:00:00Z",
            )

    def test_public_reader_rejects_nonregular_links_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = os.path.abspath(raw)
            regular = os.path.join(root, "regular.json")
            with open(regular, "wb") as handle:
                handle.write(b"1234")
            with self.assertRaisesRegex(HarnessError, "at most 3"):
                read_regular_artifact(regular, "test", max_bytes=3)
            with self.assertRaisesRegex(HarnessError, "regular"):
                read_regular_artifact(root, "test", max_bytes=8)
            hard = os.path.join(root, "hard.json")
            os.link(regular, hard)
            with self.assertRaisesRegex(HarnessError, "hard-linked"):
                read_regular_artifact(hard, "test", max_bytes=8)
            link = os.path.join(root, "link.json")
            try:
                os.symlink(regular, link)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaisesRegex(HarnessError, "symlinks|non-symlink"):
                    read_regular_artifact(link, "test", max_bytes=8)


class LegacyBridgeSnapshotV04IntegrationTests(HarnessTestCase):
    def test_real_harness_paths_state_lock_and_exact_state_read(self) -> None:
        from aoi_orgware.harnesslib import get_paths

        self.init_task("legacy-snapshot-real", session_id="harness-test-chief")
        result = produce_legacy_bridge_snapshot_v04(
            get_paths(self.root), "legacy-snapshot-real", "company-real", 1, 0,
            "a" * 64, "0.4.0a4", "2026-08-05T00:00:00Z",
        )
        self.assertEqual(result.projection.legacy_state_sha256, hashlib.sha256(
            (self.root / ".aoi" / "tasks" / "legacy-snapshot-real" / "state.json").read_bytes()
        ).hexdigest())


if __name__ == "__main__":
    unittest.main()
