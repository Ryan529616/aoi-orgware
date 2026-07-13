#!/usr/bin/env python3
"""Focused cross-platform tests for the AOI bootstrap inspector."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
INSPECTOR = REPO / "skills" / "aoi-bootstrap" / "scripts" / "inspect_project.py"


def load_inspector_module():
    spec = importlib.util.spec_from_file_location("aoi_bootstrap_inspector", INSPECTOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load inspector module: {INSPECTOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSPECTOR_MODULE = load_inspector_module()


def init_git(root: Path) -> None:
    subprocess.run(
        ["git", "init", "-b", "main", str(root)],
        check=True,
        text=True,
        capture_output=True,
    )


class BootstrapInspectorSignalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        init_git(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, text: str = "fixture\n") -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def inspect(self, *extra: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(INSPECTOR), "--root", str(self.root), *extra],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            self.fail(f"inspector failed ({result.returncode}): {result.stderr}")
        return result

    def tree_paths(self) -> list[str]:
        return sorted(
            path.relative_to(self.root).as_posix() for path in self.root.rglob("*")
        )

    def test_hardware_run_and_eda_signals_are_read_only_and_deterministic(self) -> None:
        self.write("tb/core_tb.sv")
        self.write("tb/helper.sv")
        self.write("dv/dv_top.sv")
        self.write("verification/checker.v")
        self.write("verif/scoreboard.sv")
        self.write("sim/smoke.v")
        self.write("rtl/standalone_tb.sv")
        self.write("rtl/compile.f")
        self.write("rtl/compile.flist")
        self.write("scripts/run/vcs.sh")
        self.write("scripts/run_sim.sh")
        self.write("scripts/run/report.py")
        self.write("constraints/top.sdc")
        self.write("docs/eda/README.md")
        self.write("infra/terraform/main.tf")
        self.write("Makefile")

        before = self.tree_paths()
        first = self.inspect().stdout
        second = self.inspect().stdout
        after = self.tree_paths()

        self.assertEqual(first, second)
        self.assertEqual(before, after)
        inventory = json.loads(first)["inventory"]
        counts = inventory["marker_counts"]

        self.assertEqual(counts["hardware_testbench_markers"], 7)
        self.assertEqual(
            inventory["hardware_testbench_markers"],
            [
                "dv/dv_top.sv",
                "rtl/standalone_tb.sv",
                "sim/smoke.v",
                "tb/core_tb.sv",
                "tb/helper.sv",
                "verif/scoreboard.sv",
                "verification/checker.v",
            ],
        )
        self.assertIn("tb/core_tb.sv", inventory["test_markers"])
        self.assertEqual(counts["hardware_manifest_markers"], 2)
        self.assertEqual(
            inventory["hardware_manifest_markers"],
            ["rtl/compile.f", "rtl/compile.flist"],
        )
        self.assertEqual(counts["manifests"], 1)
        self.assertEqual(
            inventory["run_flow_markers"],
            ["scripts/run/report.py", "scripts/run/vcs.sh", "scripts/run_sim.sh"],
        )
        self.assertEqual(counts["run_flow_markers"], 3)
        self.assertIn("constraints/", inventory["external_system_markers"])
        self.assertIn("constraints/top.sdc", inventory["external_system_markers"])
        self.assertIn("docs/eda/", inventory["external_system_markers"])
        self.assertIn("scripts/run/vcs.sh", inventory["external_system_markers"])
        self.assertEqual(
            counts["external_system_markers"],
            len(inventory["external_system_markers"]),
        )

    def test_fortran_database_and_static_library_are_not_eda_signals(self) -> None:
        self.write("src/solver.f")
        self.write("data/application.db")
        self.write("lib/math.lib")

        inventory = json.loads(self.inspect().stdout)["inventory"]

        self.assertEqual(inventory["marker_counts"]["hardware_manifest_markers"], 0)
        self.assertEqual(inventory["marker_counts"]["external_system_markers"], 0)
        self.assertFalse(inventory["hardware_manifest_markers"])
        self.assertFalse(inventory["external_system_markers"])
        self.assertFalse(inventory["manifests"])

    def test_samples_are_capped_while_counts_remain_complete(self) -> None:
        for index in range(105):
            self.write(f"tb/unit_{index:03}_tb.sv")
            self.write(f"rtl/manifests/list_{index:03}.f")
            self.write(f"scripts/run/run_{index:03}.sh")

        first = self.inspect().stdout
        second = self.inspect().stdout
        self.assertEqual(first, second)
        inventory = json.loads(first)["inventory"]
        counts = inventory["marker_counts"]

        self.assertFalse(inventory["truncated"])
        self.assertEqual(counts["hardware_testbench_markers"], 105)
        self.assertEqual(counts["hardware_manifest_markers"], 105)
        self.assertEqual(counts["run_flow_markers"], 105)
        self.assertEqual(len(inventory["hardware_testbench_markers"]), 100)
        self.assertEqual(len(inventory["hardware_manifest_markers"]), 100)
        self.assertEqual(len(inventory["run_flow_markers"]), 100)

    def test_scan_limit_still_bounds_new_signal_counts(self) -> None:
        for index in range(110):
            self.write(f"scripts/run/run_{index:03}.sh")

        payload = json.loads(self.inspect("--max-files", "100").stdout)
        inventory = payload["inventory"]
        self.assertEqual(inventory["scanned_files"], 100)
        self.assertTrue(inventory["truncated"])
        self.assertEqual(inventory["marker_counts"]["run_flow_markers"], 100)
        self.assertEqual(len(inventory["run_flow_markers"]), 100)
        self.assertTrue(payload["warnings"])

    def test_single_directory_entry_limit_is_hard_and_deterministic(self) -> None:
        for index in range(1_000):
            self.write(f"overflow/item_{index:04}.py")

        first = self.inspect("--max-files", "100").stdout
        second = self.inspect("--max-files", "100").stdout

        self.assertEqual(first, second)
        inventory = json.loads(first)["inventory"]
        self.assertTrue(inventory["truncated"])
        self.assertEqual(inventory["entry_scan_limit"], 1_000)
        self.assertEqual(inventory["directory_entry_limit"], 1_000)
        self.assertEqual(inventory["scanned_files"], 0)
        self.assertFalse(inventory["languages"])
        self.assertEqual(inventory["top_level_directories"], ["overflow"])
        self.assertTrue(any("overflow" in item for item in json.loads(first)["warnings"]))

    def test_directory_probe_never_reads_past_its_limit(self) -> None:
        class EndlessEntries:
            def __init__(self) -> None:
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def __next__(self):
                self.reads += 1
                return SimpleNamespace(name=f"item-{self.reads}")

        entries = EndlessEntries()
        with mock.patch.object(INSPECTOR_MODULE.os, "scandir", return_value=entries):
            names, truncated = INSPECTOR_MODULE._bounded_directory_names(
                Path("unused"), 8
            )

        self.assertTrue(truncated)
        self.assertFalse(names)
        self.assertEqual(entries.reads, 8)

    def test_top_level_reuses_the_bounded_root_scan(self) -> None:
        self.write("src/app.py")
        (self.root / "node_modules").mkdir()

        with mock.patch.object(
            Path, "iterdir", side_effect=AssertionError("unbounded second scan")
        ):
            payload = INSPECTOR_MODULE.inspect(self.root, 100)

        self.assertEqual(
            payload["inventory"]["top_level_directories"],
            ["node_modules", "src"],
        )

    def test_repository_fsmonitor_is_not_executed(self) -> None:
        sentinel = self.root / "fsmonitor-was-executed"
        if os.name == "nt":
            monitor = self.root / "hostile-fsmonitor.cmd"
            monitor.write_text(
                f'@echo invoked>"{sentinel}"\r\n@exit /b 0\r\n',
                encoding="utf-8",
            )
        else:
            monitor = self.root / "hostile-fsmonitor.sh"
            monitor.write_text(
                f'#!/bin/sh\nprintf invoked > "{sentinel}"\nexit 0\n',
                encoding="utf-8",
            )
            monitor.chmod(0o755)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "core.fsmonitor", str(monitor)],
            check=True,
            text=True,
            capture_output=True,
        )

        self.inspect()

        self.assertFalse(
            sentinel.exists(),
            "read-only inspection must not execute repository-configured fsmonitor",
        )

    def test_full_worktree_dirty_status_is_not_probed(self) -> None:
        original_run_git = INSPECTOR_MODULE._run_git
        calls: list[tuple[str, ...]] = []

        def recording_run_git(root: Path, *args: str) -> str:
            calls.append(args)
            return original_run_git(root, *args)

        with mock.patch.object(
            INSPECTOR_MODULE, "_run_git", side_effect=recording_run_git
        ):
            payload = INSPECTOR_MODULE.inspect(self.root, 100)

        self.assertEqual(calls, [("rev-parse", "--show-toplevel")])
        self.assertFalse(payload["git"]["tracked_changes_checked"])
        self.assertIsNone(payload["git"]["tracked_changes"])
        self.assertTrue(
            any("full Git status" in item for item in payload["warnings"])
        )

    @unittest.skipIf(os.name == "nt", "POSIX symlink case; Windows junction is below")
    def test_canonicalizer_rejects_parent_traversal_without_hiding_links(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        link = self.root / "linked"
        link.symlink_to(outside, target_is_directory=True)
        disguised = self.root / "missing" / ".." / "linked" / "file.txt"
        with self.assertRaisesRegex(INSPECTOR_MODULE.InspectError, "parent traversal"):
            INSPECTOR_MODULE._canonicalize_no_link_traversal(
                disguised, "disguised inspector path"
            )
        linked_parent = link / ".." / "repo" / "file.txt"
        with self.assertRaisesRegex(
            INSPECTOR_MODULE.InspectError, "symlinks or junctions"
        ):
            INSPECTOR_MODULE._canonicalize_no_link_traversal(
                linked_parent, "linked parent inspector path"
            )

    @unittest.skipUnless(os.name == "nt", "native Windows reparse metadata")
    def test_lstat_reparse_fallback_and_real_junction_are_link_like(self) -> None:
        class ReparsePath:
            def is_symlink(self) -> bool:
                return False

            def lstat(self) -> SimpleNamespace:
                return SimpleNamespace(
                    st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
                )

        self.assertTrue(INSPECTOR_MODULE._link_like(ReparsePath()))

        with tempfile.TemporaryDirectory() as external_raw:
            external = Path(external_raw)
            (external / "outside_tb.sv").write_text("outside\n", encoding="utf-8")
            junction = self.root / "tb"
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
                text=True,
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation unavailable: {created.stderr}")
            try:
                disguised = self.root / "missing" / ".." / "tb" / "outside_tb.sv"
                with self.assertRaisesRegex(
                    INSPECTOR_MODULE.InspectError, "parent traversal"
                ):
                    INSPECTOR_MODULE._canonicalize_no_link_traversal(
                        disguised, "disguised inspector path"
                    )
                inventory = json.loads(self.inspect().stdout)["inventory"]
                self.assertIn("tb", inventory["skipped_links"])
                self.assertFalse(inventory["hardware_testbench_markers"])
            finally:
                os.rmdir(junction)


if __name__ == "__main__":
    unittest.main(verbosity=2)
