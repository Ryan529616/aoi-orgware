"""Focused ownership-boundary tests for repository-local AOI offboarding."""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aoi_orgware.commands import offboard
from aoi_orgware import codex_install_provenance as provenance
from aoi_orgware.config import default_config_text
from aoi_orgware.semantic_events import canonical_sha256


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def initialize_aoi(root: Path) -> None:
    """Create the minimum real AOI layout needed for direct apply locking."""

    root.mkdir(parents=True, exist_ok=True)
    (root / "aoi.toml").write_text(
        default_config_text("Offboard Test"), encoding="utf-8"
    )
    paths = offboard.h.get_paths(root)
    with offboard.h.state_lock(paths):
        pass


def strict_local_v2_receipt(root: Path, launcher: Path) -> dict:
    """Make a schema-valid local-install receipt without weakening it to v1."""

    metadata = root / "installed" / "aoi_orgware-1.2.3.dist-info" / "METADATA"
    package = root / "installed" / "aoi_orgware"
    record = metadata.parent / "RECORD"
    wheel = root / "reviewed-store" / "aoi_orgware-1.2.3-py3-none-any.whl"
    direct = metadata.parent / "direct_url.json"
    digest = "a" * 64
    base = {
        "schema_version": 2,
        "install_proof": {
            "kind": "reviewed_local_install_bundle",
            "proof_scope": "exact_local_wheel_install_only",
            "bundle_path": str(root / "reviewed-store" / "local-install-bundle.json"),
            "bundle_sha256": digest,
            "artifact_store_root": str(root / "reviewed-store"),
            "source_commit_oid": "b" * 40,
            "source_tree_oid": "c" * 40,
            "source_manifest_sha256": "d" * 64,
            "rehearsal_report_sha256": "e" * 64,
            "inventory_sha256": "f" * 64,
        },
        "distribution_name": "aoi-orgware",
        "package_version": "1.2.3",
        "installed_metadata_sha256": digest,
        "metadata_path": str(metadata),
        "package_root": str(package),
        "console_entry_point": {
            "name": "aoi",
            "target": "aoi_orgware.cli:main",
            "path": str(root / "bin" / "aoi.exe"),
            "record_sha256": digest,
        },
        "codex_hook_entry_point": {
            "name": "aoi-codex-hook",
            "target": "aoi_orgware.codex_hook:main",
            "path": str(launcher),
            "record_sha256": digest,
        },
        "codex_hook_generated_script": {"path": None, "record_sha256": None},
        "codex_bridge_entry_point": {
            "name": "aoi-codex-bridge",
            "target": "aoi_orgware.codex_transport_cli:main",
            "path": str(root / "bin" / "aoi-codex-bridge.exe"),
            "record_sha256": digest,
        },
        "codex_bridge_generated_script": {"path": None, "record_sha256": None},
        "package_runtime_manifest": {"count": 1, "sha256": digest},
        "hook_protocol_version": 6,
        "install_wheel_artifact": {
            "path": str(wheel),
            "name": wheel.name,
            "size_bytes": 1,
            "sha256": digest,
        },
        "installed_distribution_identity": {
            "name": "aoi-orgware",
            "version": "1.2.3",
            "metadata_sha256": digest,
        },
        "installed_mapping_strength": "direct_url_archive_sha256",
        "installed_mapping_evidence": {
            "direct_url": {
                "path": str(direct),
                "record_sha256": digest,
                "archive_sha256": digest,
                "archive_path": str(wheel),
            }
        },
        "installed_record": {"path": str(record), "sha256": digest},
    }
    receipt = {**base, "provenance_receipt_sha256": canonical_sha256(base)}
    return provenance.validate_codex_install_provenance_receipt(receipt)


class OffboardTests(unittest.TestCase):
    def test_apply_removes_only_owned_wiring_and_preserves_aoi_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / f"{root.name}-offboard-archive").resolve()
            initialize_aoi(root)
            write_json(
                root / ".codex" / "hooks.json",
                {
                    "hooks": {
                        "SessionStart": [
                            {
                                "hooks": [
                                    {"type": "command", "command": "aoi-codex-hook --hook-version 6"},
                                    {"type": "command", "command": "foreign-session-hook"},
                                ]
                            }
                        ],
                        "Stop": [{"hooks": [{"type": "command", "command": "aoi-codex-hook --hook-version 6"}]}],
                    }
                },
            )
            (root / ".codex" / "config.toml").write_text(
                "[features]\nhooks = true\n\n[env]\nAOI_ROOT = 'x'\nFOREIGN_TOKEN = 'keep'\n",
                encoding="utf-8",
            )
            write_json(
                root / ".claude" / "settings.json",
                {
                    "hooks": {
                        "Stop": [
                            {"hooks": [{"type": "command", "command": "aoi-claude-hook --hook-version 1"}]},
                            {"hooks": [{"type": "command", "command": "foreign-claude-hook"}]},
                        ]
                    },
                    "env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker", "KEEP": "yes"},
                },
            )
            write_json(root / ".codex" / "aoi-managed-manifest.json", {"managed_by": "aoi-orgware"})

            preview = offboard.offboard(root, archive_dir=archive)
            self.assertTrue(preview["dry_run"])
            self.assertTrue((root / ".codex" / "hooks.json").exists())
            result = offboard.offboard(root, archive_dir=archive, dry_run=False)

            codex_hooks = json.loads((root / ".codex" / "hooks.json").read_text(encoding="utf-8"))
            self.assertEqual(codex_hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"], "foreign-session-hook")
            self.assertNotIn("Stop", codex_hooks["hooks"])
            config = (root / ".codex" / "config.toml").read_text(encoding="utf-8")
            self.assertIn("hooks = true", config)  # foreign hook still depends on it
            self.assertIn("AOI_ROOT", config)
            self.assertIn("FOREIGN_TOKEN", config)
            claude_settings = json.loads((root / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(
                claude_settings["hooks"]["Stop"][0]["hooks"][0]["command"],
                "foreign-claude-hook",
            )
            self.assertEqual(claude_settings["env"], {"KEEP": "yes"})
            self.assertIn("claude.hooks.Stop", result["removed"])
            self.assertFalse((root / ".codex" / "aoi-managed-manifest.json").exists())
            self.assertTrue(Path(result["receipt_path"]).is_file())
            self.assertTrue(Path(result["receipt_path"]).is_relative_to(archive))

    def test_disable_feature_only_when_aoi_is_the_only_hook_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            write_json(root / ".codex" / "hooks.json", {"hooks": {"Stop": [{"hooks": [{"command": "aoi-codex-hook --hook-version 6"}]}]}})
            (root / ".codex" / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")

            offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertIn("hooks = false", (root / ".codex" / "config.toml").read_text(encoding="utf-8"))
            self.assertNotIn("hooks", json.loads((root / ".codex" / "hooks.json").read_text(encoding="utf-8")))

    def test_noncanonical_or_malformed_configuration_fails_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            original = "[features]\nhooks = true\n[env]\nAOI_ROOT = 'x'\n"
            (root / ".codex").mkdir()
            (root / ".codex" / "config.toml").write_text(original, encoding="utf-8")
            write_json(root / ".codex" / "hooks.json", {"hooks": {"Stop": "not-an-array"}})

            with self.assertRaisesRegex(offboard.OffboardError, "must be an array"):
                offboard.offboard(root, archive_dir=root.parent / "archive")
            self.assertEqual((root / ".codex" / "config.toml").read_text(encoding="utf-8"), original)

    def test_repeated_apply_is_idempotent_and_preserves_unrecognized_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            write_json(root / ".claude" / "settings.json", {"env": {"AOI_ROOT": "x"}})
            write_json(root / ".codex" / "aoi-managed-manifest.json", {"managed_by": "someone-else"})

            first = offboard.offboard(root, archive_dir=archive, dry_run=False)
            digest = hashlib.sha256((root / ".claude" / "settings.json").read_bytes()).hexdigest()
            second = offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertEqual(hashlib.sha256((root / ".claude" / "settings.json").read_bytes()).hexdigest(), digest)
            self.assertEqual(second["backups"], [])
            self.assertEqual(first["removed"], [])
            self.assertTrue((root / ".codex" / "aoi-managed-manifest.json").exists())

    def test_dry_run_reports_active_state_and_apply_refuses_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            write_json(
                root / ".claude" / "settings.json",
                {"env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker", "AOI_KEEP": "yes"}},
            )
            before = (root / ".claude" / "settings.json").read_bytes()
            with mock.patch.object(offboard, "_quiescence_blockers", return_value=["task:active:active"]):
                preview = offboard.offboard(root, archive_dir=archive)
                self.assertEqual(preview["receipt"]["quiescence_blockers"], ["task:active:active"])
                with self.assertRaisesRegex(offboard.OffboardError, "not quiescent"):
                    offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertEqual((root / ".claude" / "settings.json").read_bytes(), before)

    def test_codex_current_local_v2_handler_is_removed_and_foreign_settings_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            launcher = root / "bin" / "aoi-codex-hook.exe"
            launcher.parent.mkdir()
            launcher.write_bytes(b"stub")
            receipt = strict_local_v2_receipt(root, launcher)
            command, command_windows = offboard.codex.build_codex_hook_commands(
                launcher, root, receipt["provenance_receipt_sha256"]
            )
            foreign = "foreign-codex-hook --safe"
            write_json(
                root / ".codex" / "hooks.json",
                {
                    "hooks": {
                        "Stop": [
                            {
                                "hooks": [
                                    {
                                        "command": command,
                                        "commandWindows": command_windows,
                                    }
                                ]
                            },
                            {"hooks": [{"command": foreign}]},
                        ]
                    }
                },
            )
            (root / ".codex" / "config.toml").write_text(
                "[features]\nother = true\n\n[env]\nAOI_KEEP = 'x'\nFOREIGN_TOKEN = 'keep'\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                offboard,
                "load_codex_install_provenance_receipt",
                side_effect=lambda _root: provenance.validate_codex_install_provenance_receipt(receipt),
            ):
                result = offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertIn("codex.hooks.Stop", result["removed"])
            hooks = json.loads((root / ".codex" / "hooks.json").read_text(encoding="utf-8"))
            self.assertEqual(hooks["hooks"]["Stop"][0]["hooks"][0]["command"], foreign)
            config = (root / ".codex" / "config.toml").read_text(encoding="utf-8")
            self.assertIn("other = true", config)
            self.assertIn("AOI_KEEP", config)
            self.assertIn("FOREIGN_TOKEN", config)

    def test_codex_current_route_drift_blocks_offboard_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            launcher = root / "bin" / "aoi-codex-hook.exe"
            launcher.parent.mkdir()
            launcher.write_bytes(b"stub")
            receipt = strict_local_v2_receipt(root, launcher)
            command, command_windows = offboard.codex.build_codex_hook_commands(
                launcher, root, receipt["provenance_receipt_sha256"]
            )
            if command_windows.startswith("wsl.exe "):
                drifted = command_windows.replace(
                    '--distribution "', '--distribution "wrong-', 1
                )
            else:
                drifted = command_windows.replace(
                    receipt["provenance_receipt_sha256"], "b" * 64
                )
            hook_path = root / ".codex" / "hooks.json"
            write_json(
                hook_path,
                {
                    "hooks": {
                        "Stop": [
                            {
                                "hooks": [
                                    {
                                        "command": command,
                                        "commandWindows": drifted,
                                    }
                                ]
                            }
                        ]
                    }
                },
            )
            before = hook_path.read_bytes()
            with mock.patch.object(
                offboard,
                "load_codex_install_provenance_receipt",
                side_effect=lambda _root: provenance.validate_codex_install_provenance_receipt(receipt),
            ):
                with self.assertRaisesRegex(
                    offboard.OffboardError, "partial or route-drifted"
                ):
                    offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertEqual(hook_path.read_bytes(), before)

    def test_codex_current_both_columns_drift_blocks_offboard_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            launcher = root / "bin" / "aoi-codex-hook.exe"
            launcher.parent.mkdir()
            launcher.write_bytes(b"stub")
            receipt = strict_local_v2_receipt(root, launcher)
            command, command_windows = offboard.codex.build_codex_hook_commands(
                launcher, root, receipt["provenance_receipt_sha256"]
            )
            drifted_command = command.replace(
                receipt["provenance_receipt_sha256"], "b" * 64
            )
            drifted_windows = command_windows.replace(
                receipt["provenance_receipt_sha256"], "b" * 64
            )
            hook_path = root / ".codex" / "hooks.json"
            write_json(
                hook_path,
                {
                    "hooks": {
                        "Stop": [
                            {
                                "hooks": [
                                    {
                                        "command": drifted_command,
                                        "commandWindows": drifted_windows,
                                    }
                                ]
                            }
                        ]
                    }
                },
            )
            before = hook_path.read_bytes()
            with mock.patch.object(
                offboard,
                "load_codex_install_provenance_receipt",
                side_effect=lambda _root: provenance.validate_codex_install_provenance_receipt(receipt),
            ):
                with self.assertRaisesRegex(
                    offboard.OffboardError, "partial or route-drifted"
                ):
                    offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertEqual(hook_path.read_bytes(), before)

    def test_codex_malformed_aoi_pairs_block_offboard_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            launcher = root / "bin" / "aoi-codex-hook.exe"
            launcher.parent.mkdir()
            launcher.write_bytes(b"stub")
            receipt = strict_local_v2_receipt(root, launcher)
            command, command_windows = offboard.codex.build_codex_hook_commands(
                launcher, root, receipt["provenance_receipt_sha256"]
            )
            reordered_command = command.replace(
                f'--hook-version 6 --project-root "{root}"',
                f'--project-root "{root}" --hook-version 6',
            )
            reordered_windows = command_windows.replace(
                f'--hook-version 6 --project-root "{root}"',
                f'--project-root "{root}" --hook-version 6',
            )
            pairs = (
                ("reordered", reordered_command, reordered_windows),
                (
                    "shell",
                    f"bash -lc '{command}'",
                    f"bash -lc '{command_windows}'",
                ),
            )
            hook_path = root / ".codex" / "hooks.json"
            for label, candidate_command, candidate_windows in pairs:
                with self.subTest(label=label):
                    write_json(
                        hook_path,
                        {
                            "hooks": {
                                "Stop": [
                                    {
                                        "hooks": [
                                            {
                                                "command": candidate_command,
                                                "commandWindows": candidate_windows,
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                    )
                    before = hook_path.read_bytes()
                    with mock.patch.object(
                        offboard,
                        "load_codex_install_provenance_receipt",
                        side_effect=lambda _root: provenance.validate_codex_install_provenance_receipt(receipt),
                    ):
                        with self.assertRaisesRegex(
                            offboard.OffboardError,
                            "malformed or route-drifted",
                        ):
                            offboard.offboard(
                                root, archive_dir=archive, dry_run=False
                            )
                    self.assertEqual(hook_path.read_bytes(), before)

    def test_codex_current_handler_with_mismatched_receipt_blocks_offboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            launcher = root / "bin" / "aoi-codex-hook.exe"
            launcher.parent.mkdir()
            launcher.write_bytes(b"stub")
            command = offboard.codex.build_codex_hook_command(launcher, root, "a" * 64)
            hook_path = root / ".codex" / "hooks.json"
            write_json(hook_path, {"hooks": {"Stop": [{"hooks": [{"command": command}]}]}})
            before = hook_path.read_bytes()
            receipt = strict_local_v2_receipt(root, launcher)
            with mock.patch.object(
                offboard,
                "load_codex_install_provenance_receipt",
                side_effect=lambda _root: provenance.validate_codex_install_provenance_receipt(receipt),
            ):
                with self.assertRaisesRegex(
                    offboard.OffboardError, "partial or route-drifted"
                ):
                    offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertEqual(hook_path.read_bytes(), before)

    def test_link_like_parent_is_rejected_before_reading_client_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            codex_dir = root / ".codex"
            write_json(codex_dir / "hooks.json", {"hooks": {}})
            original = offboard._is_link_like

            def link_like(path: Path) -> bool:
                return path == codex_dir or original(path)

            with mock.patch.object(offboard, "_is_link_like", side_effect=link_like):
                with self.assertRaisesRegex(offboard.OffboardError, "symlinks, junctions, or reparse points"):
                    offboard.plan_offboard(root, archive_dir=root.parent / "offboard-archive")

    def test_receipt_failure_rolls_back_client_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            write_json(root / ".claude" / "settings.json", {"env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker"}})
            original = (root / ".claude" / "settings.json").read_bytes()
            with mock.patch.object(
                offboard.h, "atomic_create_bytes", side_effect=OSError("receipt unavailable")
            ):
                with self.assertRaisesRegex(offboard.OffboardError, "receipt write failed"):
                    offboard.offboard(root, archive_dir=archive, dry_run=False)
            self.assertEqual((root / ".claude" / "settings.json").read_bytes(), original)

    def test_claude_removes_only_exact_onboarding_entry_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            exact = {"hooks": [{"type": "command", "command": "aoi-claude-hook --hook-version 1"}]}
            write_json(
                root / ".claude" / "settings.json",
                {
                    "hooks": {
                        "Stop": [
                            exact,
                            {"hooks": [{"type": "command", "command": "aoi-claude-hook --hook-version 2"}]},
                            {"hooks": [{"type": "command", "command": "aoi-claude-hook --hook-version 1"}, {"type": "command", "command": "foreign"}]},
                            {"matcher": "NotAgent", **exact},
                        ]
                    }
                },
            )

            result = offboard.offboard(root, archive_dir=archive, dry_run=False)
            entries = json.loads((root / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]["Stop"]
            self.assertEqual(len(entries), 3)
            self.assertIn("claude.hooks.Stop", result["removed"])
            self.assertIn("aoi-claude-hook --hook-version 2", json.dumps(entries))
            self.assertIn("NotAgent", json.dumps(entries))

    def test_same_plan_receipt_is_exact_idempotent_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            write_json(root / ".claude" / "settings.json", {"env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker"}})
            plan = offboard.plan_offboard(root, archive_dir=archive)
            first = offboard.apply_offboard(plan)
            second = offboard.apply_offboard(plan)
            self.assertEqual(first["receipt_path"], second["receipt_path"])
            receipt = json.loads(Path(first["receipt_path"]).read_text(encoding="utf-8"))
            self.assertEqual(receipt["plan_id"], plan["plan_id"])
            self.assertEqual(len(receipt["backups"][0]["after_sha256"]), 64)

    def test_same_archive_for_two_roots_has_distinct_bound_plan_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            archive = (parent / "archive").resolve()
            roots = [parent / "one", parent / "two"]
            receipts = []
            for root in roots:
                initialize_aoi(root)
                write_json(root / ".claude" / "settings.json", {"env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker"}})
                plan = offboard.plan_offboard(root, archive_dir=archive)
                receipts.append(offboard.apply_offboard(plan))
            self.assertNotEqual(receipts[0]["plan_id"], receipts[1]["plan_id"])
            self.assertNotEqual(receipts[0]["receipt_path"], receipts[1]["receipt_path"])

    def test_quiescence_blocks_ready_and_unknown_statuses(self) -> None:
        paths = SimpleNamespace(sessions=Path(tempfile.gettempdir()) / "missing-offboard-sessions")
        state = {
            "task_id": "task",
            "status": "done",
            "packets": [{"packet_id": "ready", "status": "ready"}, {"packet_id": "unknown", "status": "mystery"}],
            "jobs": [{"run_id": "unknown", "status": "mystery"}],
            "session_ids": [],
            "subagent_parent_session_ids": [],
        }
        with mock.patch.object(offboard.h, "load_all_tasks", return_value=[state]), mock.patch.object(
            offboard.h, "reserving_claims", return_value=[]
        ), mock.patch.object(offboard.h, "scan_atomic_temporaries", return_value=[]):
            blockers = offboard._quiescence_blockers_locked(paths)
        self.assertIn("packet:task:ready:ready", blockers)
        self.assertIn("packet:task:unknown:mystery", blockers)
        self.assertIn("job:task:unknown:mystery", blockers)

    def test_direct_apply_serializes_same_plan_until_receipt_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            initialize_aoi(root)
            write_json(root / ".claude" / "settings.json", {"env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker"}})
            plan = offboard.plan_offboard(root, archive_dir=archive)
            paths = SimpleNamespace(root=root, sessions=root / ".aoi" / "sessions")
            gate = threading.Lock()
            acquisitions: list[str] = []

            @contextmanager
            def serialized_state_lock(_paths, *, create_layout=False):
                self.assertFalse(create_layout)
                with gate:
                    acquisitions.append("locked")
                    yield

            outcomes: list[dict] = []
            with mock.patch.object(offboard.h, "get_paths", return_value=paths), mock.patch.object(
                offboard.h, "state_lock", side_effect=serialized_state_lock
            ), mock.patch.object(offboard.h, "load_all_tasks", return_value=[]), mock.patch.object(
                offboard.h, "reserving_claims", return_value=[]
            ), mock.patch.object(offboard.h, "scan_atomic_temporaries", return_value=[]):
                workers = [threading.Thread(target=lambda: outcomes.append(offboard.apply_offboard(plan))) for _ in range(2)]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join()
            self.assertEqual(len(outcomes), 2)
            self.assertEqual(acquisitions, ["locked", "locked"])
            self.assertEqual(outcomes[0]["receipt_path"], outcomes[1]["receipt_path"])

    def test_uninitialized_direct_apply_concurrently_refuses_before_any_archive_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = (root.parent / "offboard-archive").resolve()
            write_json(root / ".claude" / "settings.json", {"env": {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "worker"}})
            before = (root / ".claude" / "settings.json").read_bytes()
            plan = offboard.plan_offboard(root, archive_dir=archive)
            errors: list[Exception] = []

            def attempt() -> None:
                try:
                    offboard.apply_offboard(plan)
                except offboard.OffboardError as exc:
                    errors.append(exc)

            workers = [threading.Thread(target=attempt) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            self.assertEqual(len(errors), 2)
            self.assertFalse((archive / plan["plan_id"] / "receipt.json").exists())
            self.assertEqual((root / ".claude" / "settings.json").read_bytes(), before)
            self.assertIn("initialized AOI state lock", str(errors[0]))


if __name__ == "__main__":
    unittest.main()
