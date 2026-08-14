"""Adversarial generation-rotation tests for Codex hook receipts."""
from __future__ import annotations
import hashlib
import io
import json
import os
import subprocess
import sys
import threading
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))
from aoi_orgware import codex_adapter_contracts as contracts  # noqa: E402
from aoi_orgware import codex_hook  # noqa: E402
from aoi_orgware import codex_hook_receipts as receipts  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.commands import codex_hook_receipt_store as rotation  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes  # noqa: E402
from tests.harness_case import CLI_MODULE, HarnessTestCase  # noqa: E402

def _validated(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("receipt is not an object")
    expected = {"receipt_type", "event_identity", "observation", "receipt_sha256"}
    if set(value) != expected or not isinstance(value["event_identity"], dict):
        raise ValueError("receipt schema is invalid")
    base = {key: value[key] for key in expected - {"receipt_sha256"}}
    if value["receipt_sha256"] != hashlib.sha256(canonical_json_bytes(base)).hexdigest():
        raise ValueError("receipt digest is invalid")
    return json.loads(canonical_json_bytes(value))

class CodexHookReceiptRotationTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.paths = h.get_paths(self.root)
        patch = mock.patch.object(receipts, "_adapter_validator", side_effect=_validated)
        patch.start()
        self.addCleanup(patch.stop)
        self.authority = {
            "session_id": "session-rotation-1",
            "epoch": 1,
            "authority_record_sha256": "a" * 64,
        }
    def receipt(self, key: str, *, receipt_type: str = "post_tool_use") -> dict[str, object]:
        base: dict[str, object] = {
            "receipt_type": receipt_type,
            "event_identity": {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "tool_use_id": key,
                "agent_id": "agent-1",
                "event_id": f"event-{key}",
            },
            "observation": {"status": "observed", "key": key},
        }
        return {
            **base,
            "receipt_sha256": hashlib.sha256(canonical_json_bytes(base)).hexdigest(),
        }
    def apply(self, mode: str, operation_id: str) -> dict[str, object]:
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode=mode, operation_id=operation_id
        )
        return receipts.apply_codex_hook_receipt_rotation(
            self.paths,
            mode=mode,
            operation_id=operation_id,
            expected_preview_sha256=preview["preview_sha256"],
            authority=self.authority,
        )
    def test_full_legacy_adopts_without_changing_bytes_and_new_write_uses_v2(self) -> None:
        first = self.receipt("legacy-1")
        receipts.store_codex_hook_receipt(self.paths, first)
        legacy_path = receipts.codex_hook_receipt_path(self.paths, first)
        before = legacy_path.read_bytes()
        result = self.apply("adopt-v1", "adopt-1")
        self.assertEqual(result["status"], "committed")
        self.assertEqual(legacy_path.read_bytes(), before)
        second = self.receipt("v2-1")
        receipts.store_codex_hook_receipt(self.paths, second)
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        self.assertEqual(report["entry_count"], 1)
        self.assertEqual(report["generations"]["retained_entry_count"], 2)
        active = report["generations"]["active_generation_id"]
        self.assertTrue(
            (receipts.codex_hook_receipts_v2_dir(self.paths) / "generations" / active / "receipts" / f"{receipts.codex_hook_receipt_key(second)}.json").is_file()
        )
        self.assertEqual(receipts.load_codex_hook_receipt(self.paths, first), first)
    def test_cli_readers_are_unfenced_and_apply_is_chief_fenced(self) -> None:
        readers = (
            "codex-hook-receipts-status",
            "codex-hook-receipts-verify",
            "codex-hook-receipts-rotation-preview",
        )
        self.assertTrue(all(name in cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS for name in readers))
        self.assertTrue(all(not cli_impl.command_requires_chief(name, initialized=True) for name in readers))
        self.assertTrue(cli_impl.command_requires_chief("codex-hook-receipts-rotate", initialized=True))
        preview = json.loads(self.cli(
            "codex-hook-receipts-rotation-preview", "--mode", "adopt-v1",
            "--operation-id", "cli-adoption-1", "--json",
        ).stdout)
        unauthorized = self.env.copy()
        for name in ("AOI_CHIEF_SESSION_ID", "AOI_CHIEF_EPOCH", "AOI_CHIEF_CREDENTIAL_FILE", "AOI_CHIEF_TOKEN"):
            unauthorized.pop(name, None)
        denied = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "codex-hook-receipts-rotate",
             "--mode", "adopt-v1", "--operation-id", "cli-adoption-1",
             "--expected-preview-sha256", preview["preview_sha256"], "--json"],
            cwd=self.root, env=unauthorized, text=True, capture_output=True,
            check=False, timeout=20,
        )
        self.assertEqual(denied.returncode, 2)
        self.assertNotIn("Traceback", denied.stderr)
        committed = json.loads(self.cli(
            "codex-hook-receipts-rotate", "--mode", "adopt-v1",
            "--operation-id", "cli-adoption-1", "--expected-preview-sha256",
            preview["preview_sha256"], "--json",
        ).stdout)
        self.assertEqual(committed["status"], "committed")
        verified = json.loads(self.cli("codex-hook-receipts-verify", "--json").stdout)
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["receipt_store"]["generations"]["control_revision"], 1)
    def test_pre_before_rotation_post_after_rotation_and_replay_are_monotonic(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        pre = self.receipt("tool-1", receipt_type="pre_tool_use")
        receipts.store_codex_hook_receipt(self.paths, pre)
        first_control = receipts.inspect_codex_hook_receipt_store(self.paths)["generations"]
        rotation = self.apply("rotate-v2", "rotate-1")
        self.assertEqual(rotation["control_revision"], 2)
        self.assertEqual(
            receipts.load_codex_hook_receipt_by_identity(
                self.paths,
                receipt_type="pre_tool_use",
                event_identity=pre["event_identity"],
            ),
            pre,
        )
        post = self.receipt("tool-1", receipt_type="post_tool_use")
        receipts.store_codex_hook_receipt(self.paths, post)
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        self.assertEqual(report["generations"]["control_revision"], 2)
        self.assertEqual(report["generations"]["retained_entry_count"], 2)
        replay = self.apply("rotate-v2", "rotate-1")
        self.assertEqual(replay["status"], "replayed")
        self.assertEqual(replay["control_sha256"], rotation["control_sha256"])
        self.assertNotEqual(first_control["active_generation_id"], report["generations"]["active_generation_id"])
    def test_applied_replay_requires_exact_mode(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        for correct, wrong, operation_id in (
            ("adopt-v1", "rotate-v2", "adopt-1"),
            ("rotate-v2", "adopt-v1", "rotate-1"),
        ):
            if correct == "rotate-v2":
                self.apply(correct, operation_id)
            preview = receipts.preview_codex_hook_receipt_rotation(self.paths, mode=correct, operation_id=operation_id)
            before = receipts.inspect_codex_hook_receipt_store(self.paths)
            with self.assertRaisesRegex(receipts.CodexHookReceiptError, "replay mode conflicts"):
                receipts.preview_codex_hook_receipt_rotation(self.paths, mode=wrong, operation_id=operation_id)
            with self.assertRaisesRegex(receipts.CodexHookReceiptError, "replay mode conflicts"):
                receipts.apply_codex_hook_receipt_rotation(self.paths, mode=wrong, operation_id=operation_id, expected_preview_sha256=preview["preview_sha256"], authority=self.authority)
            self.assertEqual(receipts.inspect_codex_hook_receipt_store(self.paths), before)
            self.assertEqual(self.apply(correct, operation_id)["status"], "replayed")
    def test_pending_intent_blocks_novel_store_and_exact_apply_resumes(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="rotate-v2", operation_id="rotate-1"
        )
        control = rotation._load_control_locked(self.paths)
        assert control is not None
        expected = rotation._build_control(
            previous=control,
            legacy_inventory=control["legacy_inventory"],
            operation_id="rotate-1",
            mode="rotate-v2",
            preview_sha256=preview["preview_sha256"],
            successor_generation_id=preview["successor_generation_id"],
        )
        intent = rotation._build_intent(
            preview,
            authority=self.authority,
            expected_control_sha256=expected["control_sha256"],
        )
        operation_dir = receipts.codex_hook_receipts_v2_dir(self.paths) / "operations" / "rotate-1"
        operation_dir.mkdir()
        h.atomic_create_bytes(operation_dir / "intent.json", canonical_json_bytes(intent))
        (receipts.codex_hook_receipts_v2_dir(self.paths) / "generations" /
         str(preview["successor_generation_id"])).mkdir()
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "pending"):
            receipts.store_codex_hook_receipt(self.paths, self.receipt("blocked"))
        result = receipts.apply_codex_hook_receipt_rotation(
            self.paths,
            mode="rotate-v2",
            operation_id="rotate-1",
            expected_preview_sha256=preview["preview_sha256"],
            authority={**self.authority, "authority_record_sha256": "b" * 64},
        )
        self.assertEqual(result["status"], "committed")
    def test_adoption_resumes_after_crash_between_operation_dir_and_intent(self) -> None:
        root = rotation._ensure_private_directory(
            receipts.codex_hook_receipts_v2_dir(self.paths),
            "receipt store v2 directory",
        )
        del root
        rotation._ensure_private_directory(
            receipts.codex_hook_receipts_v2_dir(self.paths) / "operations",
            "receipt rotation operations directory",
        )
        rotation._ensure_private_directory(
            receipts.codex_hook_receipts_v2_dir(self.paths) / "generations",
            "receipt generations directory",
        )
        rotation._ensure_private_directory(
            receipts.codex_hook_receipts_v2_dir(self.paths)
            / "operations"
            / "adopt-1",
            "receipt rotation operation directory",
        )
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "pending"):
            receipts.store_codex_hook_receipt(self.paths, self.receipt("blocked"))
        result = self.apply("adopt-v1", "adopt-1")
        self.assertEqual(result["status"], "committed")
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(self.paths)["entry_count"], 0
        )
    def test_v2_rotation_resumes_after_empty_operation_directory(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        operation_dir = (
            receipts.codex_hook_receipts_v2_dir(self.paths)
            / "operations"
            / "rotate-1"
        )
        operation_dir.mkdir(mode=0o700)
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "pending"):
            receipts.store_codex_hook_receipt(self.paths, self.receipt("blocked"))
        result = self.apply("rotate-v2", "rotate-1")
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["control_revision"], 2)
    def test_unexpected_staging_never_commits_new_control(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="rotate-v2", operation_id="rotate-1"
        )
        control_path = receipts.codex_hook_receipts_v2_dir(self.paths) / "control.json"
        original_control = control_path.read_bytes()
        stage_generation = rotation._stage_generation_locked

        def stage_with_unexpected_entry(
            paths: h.HarnessPaths,
            *,
            generation_id: str,
            predecessor_generation_id: str | None,
            location_kind: str,
            operation_id: str,
        ) -> None:
            stage_generation(
                paths,
                generation_id=generation_id,
                predecessor_generation_id=predecessor_generation_id,
                location_kind=location_kind,
                operation_id=operation_id,
            )
            if generation_id == preview["successor_generation_id"]:
                generation_dir = (
                    receipts.codex_hook_receipts_v2_dir(self.paths)
                    / "generations"
                    / str(preview["successor_generation_id"])
                )
                h.atomic_create_bytes(generation_dir / "unexpected.bin", b"x")

        with mock.patch.object(
            rotation,
            "_stage_generation_locked",
            side_effect=stage_with_unexpected_entry,
        ):
            with self.assertRaisesRegex(
                receipts.CodexHookReceiptError, "unexpected entries"
            ):
                receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="rotate-v2",
                    operation_id="rotate-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
        self.assertEqual(control_path.read_bytes(), original_control)

    def test_same_operation_concurrency_has_one_commit_and_one_replay(self) -> None:
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="adopt-v1", operation_id="adopt-1"
        )
        barrier = threading.Barrier(3)

        def apply_once() -> str:
            barrier.wait(timeout=10)
            result = receipts.apply_codex_hook_receipt_rotation(
                self.paths,
                mode="adopt-v1",
                operation_id="adopt-1",
                expected_preview_sha256=preview["preview_sha256"],
                authority=self.authority,
            )
            return str(result["status"])

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(apply_once) for _index in range(2)]
            barrier.wait(timeout=10)
            statuses = sorted(future.result(timeout=30) for future in futures)
        self.assertEqual(statuses, ["committed", "replayed"])
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(self.paths)["generations"][
                "control_revision"
            ],
            1,
        )

    def test_divergent_concurrent_operations_have_one_linear_winner(self) -> None:
        previews = {
            operation_id: receipts.preview_codex_hook_receipt_rotation(
                self.paths, mode="adopt-v1", operation_id=operation_id
            )
            for operation_id in ("adopt-a", "adopt-b")
        }
        barrier = threading.Barrier(3)

        def apply_once(operation_id: str) -> tuple[str, str]:
            barrier.wait(timeout=10)
            try:
                result = receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="adopt-v1",
                    operation_id=operation_id,
                    expected_preview_sha256=previews[operation_id]["preview_sha256"],
                    authority=self.authority,
                )
            except receipts.CodexHookReceiptError as exc:
                return "rejected", str(exc)
            return "committed", str(result["operation_id"])

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(apply_once, operation_id)
                for operation_id in ("adopt-a", "adopt-b")
            ]
            barrier.wait(timeout=10)
            outcomes = [future.result(timeout=30) for future in futures]
        self.assertEqual(sorted(item[0] for item in outcomes), ["committed", "rejected"])
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        self.assertEqual(report["generations"]["control_revision"], 1)
        self.assertEqual(report["generations"]["generation_count"], 2)

    def test_receipt_append_racing_rotation_is_linear_and_never_lost(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="rotate-v2", operation_id="rotate-1"
        )
        value = self.receipt("racing-receipt")
        barrier = threading.Barrier(3)

        def append_once() -> str:
            barrier.wait(timeout=10)
            receipts.store_codex_hook_receipt(self.paths, value)
            return "stored"

        def rotate_once() -> str:
            barrier.wait(timeout=10)
            try:
                result = receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="rotate-v2",
                    operation_id="rotate-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
            except receipts.CodexHookReceiptError:
                return "rejected"
            return str(result["status"])

        with ThreadPoolExecutor(max_workers=2) as pool:
            append_future = pool.submit(append_once)
            rotate_future = pool.submit(rotate_once)
            barrier.wait(timeout=10)
            self.assertEqual(append_future.result(timeout=30), "stored")
            rotation_status = rotate_future.result(timeout=30)
        self.assertIn(rotation_status, {"committed", "rejected"})
        self.assertEqual(receipts.load_codex_hook_receipt(self.paths, value), value)
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        self.assertEqual(report["generations"]["retained_entry_count"], 1)

    def test_generation_retention_limit_rejects_another_rotation(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        for index in range(1, receipts.MAX_CODEX_HOOK_RECEIPT_GENERATIONS - 1):
            self.apply("rotate-v2", f"rotate-{index}")
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        self.assertEqual(
            report["generations"]["generation_count"],
            receipts.MAX_CODEX_HOOK_RECEIPT_GENERATIONS,
        )
        with self.assertRaisesRegex(
            receipts.CodexHookReceiptError, "retention limit"
        ):
            receipts.preview_codex_hook_receipt_rotation(
                self.paths, mode="rotate-v2", operation_id="rotate-over-limit"
            )

    def test_crash_after_adoption_marker_resumes_exact_operation(self) -> None:
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="adopt-v1", operation_id="adopt-1"
        )
        create_metadata = rotation._create_or_verify_metadata

        def create_then_crash(
            path: Path, value: Mapping[str, Any], label: str
        ) -> None:
            create_metadata(path, value, label)
            if label == "receipt store adoption marker":
                raise RuntimeError("simulated crash after adoption marker")

        with mock.patch.object(
            rotation, "_create_or_verify_metadata", side_effect=create_then_crash
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="adopt-v1",
                    operation_id="adopt-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
        result = receipts.apply_codex_hook_receipt_rotation(
            self.paths,
            mode="adopt-v1",
            operation_id="adopt-1",
            expected_preview_sha256=preview["preview_sha256"],
            authority=self.authority,
        )
        self.assertEqual(result["status"], "committed")

    def test_crash_after_generation_metadata_resumes_exact_operation(self) -> None:
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="adopt-v1", operation_id="adopt-1"
        )
        stage_generation = rotation._stage_generation_locked

        def stage_then_crash(
            paths: h.HarnessPaths,
            *,
            generation_id: str,
            predecessor_generation_id: str | None,
            location_kind: str,
            operation_id: str,
        ) -> None:
            stage_generation(
                paths,
                generation_id=generation_id,
                predecessor_generation_id=predecessor_generation_id,
                location_kind=location_kind,
                operation_id=operation_id,
            )
            if generation_id == receipts.CODEX_HOOK_RECEIPTS_V2_LEGACY_GENERATION:
                raise RuntimeError("simulated crash after generation metadata")

        with mock.patch.object(
            rotation, "_stage_generation_locked", side_effect=stage_then_crash
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="adopt-v1",
                    operation_id="adopt-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
        self.assertEqual(
            receipts.apply_codex_hook_receipt_rotation(
                self.paths,
                mode="adopt-v1",
                operation_id="adopt-1",
                expected_preview_sha256=preview["preview_sha256"],
                authority=self.authority,
            )["status"],
            "committed",
        )

    def test_crash_after_generation_seal_resumes_exact_operation(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        receipts.store_codex_hook_receipt(self.paths, self.receipt("source"))
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="rotate-v2", operation_id="rotate-1"
        )
        stage_seal = rotation._stage_seal_locked

        def seal_then_crash(
            paths: h.HarnessPaths,
            *,
            generation_id: str,
            operation_id: str,
            inventory: list[dict[str, Any]],
            summary: Mapping[str, Any],
        ) -> None:
            stage_seal(
                paths,
                generation_id=generation_id,
                operation_id=operation_id,
                inventory=inventory,
                summary=summary,
            )
            raise RuntimeError("simulated crash after generation seal")

        with mock.patch.object(
            rotation, "_stage_seal_locked", side_effect=seal_then_crash
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="rotate-v2",
                    operation_id="rotate-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
        self.assertEqual(
            receipts.apply_codex_hook_receipt_rotation(
                self.paths,
                mode="rotate-v2",
                operation_id="rotate-1",
                expected_preview_sha256=preview["preview_sha256"],
                authority=self.authority,
            )["status"],
            "committed",
        )

    def test_crash_after_empty_successor_resumes_exact_operation(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="rotate-v2", operation_id="rotate-1"
        )
        stage_generation = rotation._stage_generation_locked

        def stage_then_crash(
            paths: h.HarnessPaths,
            *,
            generation_id: str,
            predecessor_generation_id: str | None,
            location_kind: str,
            operation_id: str,
        ) -> None:
            stage_generation(
                paths,
                generation_id=generation_id,
                predecessor_generation_id=predecessor_generation_id,
                location_kind=location_kind,
                operation_id=operation_id,
            )
            if generation_id == preview["successor_generation_id"]:
                raise RuntimeError("simulated crash after empty successor")

        with mock.patch.object(
            rotation, "_stage_generation_locked", side_effect=stage_then_crash
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="rotate-v2",
                    operation_id="rotate-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
        self.assertEqual(
            receipts.apply_codex_hook_receipt_rotation(
                self.paths,
                mode="rotate-v2",
                operation_id="rotate-1",
                expected_preview_sha256=preview["preview_sha256"],
                authority=self.authority,
            )["status"],
            "committed",
        )

    def test_control_commit_response_loss_replays_without_new_generation(self) -> None:
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="adopt-v1", operation_id="adopt-1"
        )
        atomic_write = h.atomic_write_bytes

        def write_then_report_loss(path: Path, payload: bytes) -> None:
            atomic_write(path, payload)
            if path.name == "control.json":
                raise h.HarnessError("simulated response loss")

        with mock.patch.object(h, "atomic_write_bytes", side_effect=write_then_report_loss):
            with self.assertRaisesRegex(
                receipts.CodexHookReceiptError, "cannot commit"
            ):
                receipts.apply_codex_hook_receipt_rotation(
                    self.paths,
                    mode="adopt-v1",
                    operation_id="adopt-1",
                    expected_preview_sha256=preview["preview_sha256"],
                    authority=self.authority,
                )
        result = receipts.apply_codex_hook_receipt_rotation(
            self.paths,
            mode="adopt-v1",
            operation_id="adopt-1",
            expected_preview_sha256=preview["preview_sha256"],
            authority=self.authority,
        )
        self.assertEqual(result["status"], "replayed")
        self.assertEqual(result["control_revision"], 1)

    def test_earlier_operation_replay_returns_its_committed_identity(self) -> None:
        first = self.apply("adopt-v1", "adopt-1")
        second = self.apply("rotate-v2", "rotate-1")
        self.assertNotEqual(first["control_sha256"], second["control_sha256"])
        root = receipts.codex_hook_receipts_v2_dir(self.paths)
        before = {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

        replay = receipts.apply_codex_hook_receipt_rotation(
            self.paths,
            mode="adopt-v1",
            operation_id="adopt-1",
            expected_preview_sha256=first["preview_sha256"],
            authority=self.authority,
        )

        self.assertEqual(replay["status"], "replayed")
        for field in (
            "mode",
            "operation_id",
            "preview_sha256",
            "control_revision",
            "control_sha256",
            "active_generation_id",
            "legacy_inventory",
        ):
            self.assertEqual(replay[field], first[field])
        self.assertEqual(
            before,
            {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            },
        )
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(self.paths)["generations"][
                "control_revision"
            ],
            second["control_revision"],
        )

    @mock.patch.object(receipts, "MAX_CODEX_HOOK_RECEIPT_ENTRIES", 4)
    def test_full_legacy_store_adopts_without_rewriting_receipts(self) -> None:
        originals: dict[Path, bytes] = {}
        for index in range(4):
            value = self.receipt(f"legacy-{index}")
            receipts.store_codex_hook_receipt(self.paths, value)
            path = receipts.codex_hook_receipt_path(self.paths, value)
            originals[path] = path.read_bytes()
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "full"):
            receipts.store_codex_hook_receipt(self.paths, self.receipt("overflow"))
        self.apply("adopt-v1", "adopt-full")
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(self.paths)["generations"][
                "retained_entry_count"
            ],
            4,
        )
        self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_hardlinked_control_fails_closed(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        control_path = receipts.codex_hook_receipts_v2_dir(self.paths) / "control.json"
        os.link(control_path, control_path.with_name("control-copy.json"))
        with self.assertRaisesRegex(
            receipts.CodexHookReceiptError, "regular non-linked"
        ):
            receipts.inspect_codex_hook_receipt_store(self.paths)

    def test_unexpected_v2_root_member_fails_closed(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        h.atomic_create_bytes(
            receipts.codex_hook_receipts_v2_dir(self.paths) / "unexpected.bin", b"x"
        )
        with self.assertRaisesRegex(
            receipts.CodexHookReceiptError, "unexpected entries"
        ):
            receipts.inspect_codex_hook_receipt_store(self.paths)

    def test_sealed_generation_receipt_drift_fails_closed(self) -> None:
        self.apply("adopt-v1", "adopt-1")
        value = self.receipt("sealed")
        receipts.store_codex_hook_receipt(self.paths, value)
        before = receipts.inspect_codex_hook_receipt_store(self.paths)["generations"]
        sealed_generation = before["active_generation_id"]
        self.apply("rotate-v2", "rotate-1")
        divergent = self.receipt("sealed")
        divergent["observation"] = {"status": "tampered"}
        base = {
            key: divergent[key]
            for key in divergent
            if key != "receipt_sha256"
        }
        divergent["receipt_sha256"] = hashlib.sha256(
            canonical_json_bytes(base)
        ).hexdigest()
        path = (
            receipts.codex_hook_receipts_v2_dir(self.paths)
            / "generations"
            / sealed_generation
            / "receipts"
            / f"{receipts.codex_hook_receipt_key(value)}.json"
        )
        path.write_bytes(canonical_json_bytes(divergent))
        with self.assertRaisesRegex(
            receipts.CodexHookReceiptError, "seal does not match"
        ):
            receipts.inspect_codex_hook_receipt_store(self.paths)

    def test_duplicate_identity_across_generations_is_corruption_even_if_equal(self) -> None:
        legacy = self.receipt("duplicate")
        receipts.store_codex_hook_receipt(self.paths, legacy)
        self.apply("adopt-v1", "adopt-1")
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        active = report["generations"]["active_generation_id"]
        destination = receipts.codex_hook_receipts_v2_dir(self.paths) / "generations" / active / "receipts" / f"{receipts.codex_hook_receipt_key(legacy)}.json"
        h.atomic_create_bytes(destination, canonical_json_bytes(legacy))
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "duplicat"):
            receipts.load_codex_hook_receipt(self.paths, legacy)
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "duplicat"):
            receipts.store_codex_hook_receipt(self.paths, self.receipt("unrelated"))

    def test_legacy_drift_after_adoption_fails_closed(self) -> None:
        legacy = self.receipt("legacy")
        receipts.store_codex_hook_receipt(self.paths, legacy)
        self.apply("adopt-v1", "adopt-1")
        extra = self.receipt("old-binary")
        h.atomic_create_bytes(
            receipts.codex_hook_receipt_path(self.paths, extra),
            canonical_json_bytes(extra),
        )
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "drifted"):
            receipts.store_codex_hook_receipt(self.paths, self.receipt("new"))

    def test_invalid_bool_and_divergent_authority_replay_fail_closed(self) -> None:
        preview = receipts.preview_codex_hook_receipt_rotation(
            self.paths, mode="adopt-v1", operation_id="adopt-1"
        )
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "epoch"):
            receipts.apply_codex_hook_receipt_rotation(
                self.paths,
                mode="adopt-v1",
                operation_id="adopt-1",
                expected_preview_sha256=preview["preview_sha256"],
                authority={**self.authority, "epoch": True},
            )
        self.apply("adopt-v1", "adopt-1")
        replay = receipts.apply_codex_hook_receipt_rotation(
            self.paths, mode="adopt-v1", operation_id="adopt-1",
            expected_preview_sha256=preview["preview_sha256"],
            authority={**self.authority, "authority_record_sha256": "b" * 64},
        )
        self.assertEqual(replay["status"], "replayed")
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "conflicts"):
            receipts.apply_codex_hook_receipt_rotation(
                self.paths,
                mode="adopt-v1",
                operation_id="adopt-1",
                expected_preview_sha256=preview["preview_sha256"],
                authority={**self.authority, "epoch": 2},
            )


class CodexHookGenerationCorrelationTests(HarnessTestCase):
    SESSION = "codex-hook-generation-session"
    TASK = "codex-hook-generation-task"

    def call(self, handler: object, payload: dict[str, object]) -> dict[str, object]:
        output = io.StringIO()
        with redirect_stdout(output):
            handler(self.root, payload)  # type: ignore[operator]
        return json.loads(output.getvalue())

    def test_pre_before_rotation_correlates_with_post_in_successor(self) -> None:
        self.init_task(self.TASK, session_id=self.SESSION)
        self.cli(
            "claim", "--task", self.TASK, "--token", "generation-claim",
            "--owner", "test-root", "--kind", "implementation", "--intent",
            "exercise generation correlation", "--validation", "exact target covered",
            "--expires-at", "2099-01-01T00:00:00+00:00", "--allow-nonexistent",
            "--lock", "repo:tree:src",
        )
        payload: dict[str, object] = {
            "session_id": self.SESSION, "turn_id": "turn-1",
            "transcript_path": str(self.root / "rollout.jsonl"), "cwd": str(self.root),
            "hook_event_name": "PreToolUse", "model": "gpt-5.6-terra",
            "permission_mode": "default", "tool_name": "apply_patch",
            "tool_input": {"command": "*** Begin Patch\n*** Add File: src/owned.py\n+x\n*** End Patch"},
            "tool_use_id": "tool-use-1",
        }
        self.assertEqual(self.call(codex_hook.pre_tool_use, payload), {"continue": True})
        paths = h.get_paths(self.root)
        identity = codex_hook._tool_event_identity(payload)
        pre = receipts.load_codex_hook_receipt_by_identity(
            paths, receipt_type=contracts.CODEX_PRETOOL_CLAIM_DECISION_V1,
            event_identity=identity,
        )
        preview = receipts.preview_codex_hook_receipt_rotation(
            paths, mode="adopt-v1", operation_id="hook-adoption-1"
        )
        receipts.apply_codex_hook_receipt_rotation(
            paths, mode="adopt-v1", operation_id="hook-adoption-1",
            expected_preview_sha256=preview["preview_sha256"],
            authority={"session_id": self.SESSION, "epoch": 1,
                       "authority_record_sha256": "a" * 64},
        )
        post_payload = {**payload, "hook_event_name": "PostToolUse",
                        "tool_response": {"content": "applied", "exit_code": 0}}
        self.assertEqual(self.call(codex_hook.post_tool_use, post_payload), {"continue": True})
        post = receipts.load_codex_hook_receipt_by_identity(
            paths, receipt_type=contracts.CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
            event_identity=identity,
        )
        self.assertEqual(post["pre_receipt_sha256"], pre["receipt_sha256"])
        report = receipts.inspect_codex_hook_receipt_store(paths)
        self.assertEqual(report["entry_count"], 1)
        self.assertEqual(report["generations"]["retained_entry_count"], 2)


if __name__ == "__main__":
    import unittest

    unittest.main()
