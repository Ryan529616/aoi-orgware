#!/usr/bin/env python3
"""Fail-closed streaming bounds for security-sensitive directory scans."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.commands import task_lifecycle  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402


class _GuardedScandir:
    """Wrap one real scandir and fail if production pulls past its budget."""

    def __init__(self, inner: Any, *, max_pulls: int) -> None:
        self._inner = inner
        self.max_pulls = max_pulls
        self.pulls = 0
        self.closed = False

    def __iter__(self) -> _GuardedScandir:
        return self

    def __next__(self) -> os.DirEntry[str]:
        if self.pulls >= self.max_pulls:
            raise AssertionError("scandir pulled an entry after its fail-closed cap")
        self.pulls += 1
        return next(self._inner)

    def __enter__(self) -> _GuardedScandir:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if not self.closed:
            self._inner.close()
            self.closed = True


class _GuardedScandirFactory:
    def __init__(self, *, max_pulls: int) -> None:
        self._original = os.scandir
        self._max_pulls = max_pulls
        self.opened: list[_GuardedScandir] = []
        self.paths: list[Path] = []

    def __call__(self, path: os.PathLike[str] | str) -> _GuardedScandir:
        guarded = _GuardedScandir(
            self._original(path), max_pulls=self._max_pulls
        )
        self.opened.append(guarded)
        self.paths.append(Path(path))
        return guarded

    def assert_all_closed(self, case: unittest.TestCase) -> None:
        case.assertTrue(self.opened)
        case.assertTrue(all(scanner.closed for scanner in self.opened))


class BoundedScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "aoi.toml").write_text(
            default_config_text("Bounded scan tests"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        with h.state_lock(self.paths, create_layout=True):
            pass

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def leave_unpublished_temporary(self, target: Path, payload: bytes) -> Path:
        descriptor, temporary = h._open_atomic_temporary(target, "write")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary

    def leave_published_create_alias(self, target: Path, payload: bytes) -> Path:
        target.write_bytes(payload)
        if os.name != "nt":
            target.chmod(0o600)
        temporary = target.parent / h._atomic_temporary_basename(target, "create")
        os.link(target, temporary)
        return temporary

    def test_one_entry_probe_stops_and_closes(self) -> None:
        probe = self.root / "probe"
        probe.mkdir()
        (probe / "first").write_bytes(b"1")
        (probe / "second").write_bytes(b"2")
        guarded = _GuardedScandirFactory(max_pulls=1)

        with mock.patch.object(h.os, "scandir", side_effect=guarded):
            self.assertTrue(h.directory_has_any_entry(probe, "probe directory"))

        self.assertEqual([scanner.pulls for scanner in guarded.opened], [1])
        guarded.assert_all_closed(self)

    def test_valid_platform_marker_never_enumerates_state_root(self) -> None:
        with mock.patch.object(
            h.os,
            "scandir",
            side_effect=AssertionError("valid marker must not enumerate state root"),
        ):
            h.preflight_layout(self.paths)
            h._ensure_platform_domain(self.paths)

    def test_pristine_bootstrap_probe_reads_only_one_entry(self) -> None:
        guarded = _GuardedScandirFactory(max_pulls=1)

        with mock.patch.object(h.os, "scandir", side_effect=guarded):
            with self.assertRaisesRegex(h.HarnessError, "state tree already exists"):
                task_lifecycle._require_pristine_bootstrap_state(self.paths)

        self.assertEqual([scanner.pulls for scanner in guarded.opened], [1])
        guarded.assert_all_closed(self)

    def test_tree_identity_cap_fails_before_an_extra_pull(self) -> None:
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "first").write_bytes(b"1")
        (tree / "second").write_bytes(b"2")
        guarded = _GuardedScandirFactory(max_pulls=1)

        with mock.patch.object(h, "TREE_IDENTITY_SCAN_MAX_ENTRIES", 1), mock.patch.object(
            h.os, "scandir", side_effect=guarded
        ):
            with self.assertRaisesRegex(h.HarnessError, "reached.*identity scan limit"):
                h._validate_existing_tree_identity(
                    tree, namespace="repo", raw_path=str(tree)
                )

        self.assertEqual([scanner.pulls for scanner in guarded.opened], [1])
        guarded.assert_all_closed(self)

    def test_interrupted_prefix_cap_fails_before_an_extra_pull(self) -> None:
        guarded = _GuardedScandirFactory(max_pulls=1)

        with mock.patch.object(
            h, "INTERRUPTED_INIT_PREFIX_SCAN_MAX_ENTRIES", 1
        ), mock.patch.object(h.os, "scandir", side_effect=guarded):
            with self.assertRaisesRegex(
                h.HarnessError, "initialization prefix reached.*entry count"
            ):
                h._validate_interrupted_initialization_prefix(
                    self.paths, initialized_lock=True
                )

        self.assertEqual([scanner.pulls for scanner in guarded.opened], [1])
        guarded.assert_all_closed(self)

    def test_recovery_scan_cap_causes_zero_deletions(self) -> None:
        temporary = self.leave_unpublished_temporary(
            self.paths.harness / "residue.json", b"recover me later"
        )
        guarded = _GuardedScandirFactory(max_pulls=1)

        with h.state_lock(self.paths):
            with mock.patch.object(
                h, "ATOMIC_TEMP_SCAN_MAX_ENTRIES", 1
            ), mock.patch.object(h.os, "scandir", side_effect=guarded):
                with self.assertRaisesRegex(
                    h.HarnessError, "temporary scan reached.*entry count"
                ):
                    h.recover_atomic_temporaries(self.paths)

        self.assertTrue(temporary.is_file())
        self.assertEqual(temporary.read_bytes(), b"recover me later")
        self.assertEqual([scanner.pulls for scanner in guarded.opened], [1])
        guarded.assert_all_closed(self)

    def test_recoverable_alias_preflight_is_bounded(self) -> None:
        target = self.paths.tasks / "published.json"
        temporary = self.leave_published_create_alias(target, b"published")
        guarded = _GuardedScandirFactory(max_pulls=1)

        with mock.patch.object(h, "ATOMIC_TEMP_SCAN_MAX_ENTRIES", 1), mock.patch.object(
            h.os, "scandir", side_effect=guarded
        ):
            with self.assertRaisesRegex(
                h.HarnessError, "create-alias preflight reached.*entry limit"
            ):
                h._recoverable_create_alias_for_target(target)

        self.assertTrue(target.is_file())
        self.assertTrue(temporary.is_file())
        self.assertEqual(target.stat().st_nlink, 2)
        self.assertEqual([scanner.pulls for scanner in guarded.opened], [1])
        guarded.assert_all_closed(self)

    def test_temporary_aliases_share_one_directory_index(self) -> None:
        expected_targets: set[Path] = set()
        for index in range(3):
            target = self.paths.tasks / f"published-{index}.json"
            self.leave_published_create_alias(target, f"{index}\n".encode("ascii"))
            expected_targets.add(target)
        guarded = _GuardedScandirFactory(max_pulls=64)

        with h.state_lock(self.paths):
            with mock.patch.object(h.os, "scandir", side_effect=guarded):
                records = h.scan_atomic_temporaries(self.paths)

        published = {
            record.target
            for record in records
            if record.classification == "published_create_alias"
        }
        self.assertEqual(published, expected_targets)
        self.assertEqual(
            sum(path == self.paths.tasks for path in guarded.paths),
            1,
            "one directory scan must classify every create alias in that directory",
        )
        guarded.assert_all_closed(self)


if __name__ == "__main__":
    unittest.main()
