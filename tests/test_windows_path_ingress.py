#!/usr/bin/env python3
"""Native Windows ingress tests for benign short-path aliases."""

from __future__ import annotations

import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest import mock
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(SRC))

from aoi_orgware import codex_hook, confidentiality  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import session_receipts  # noqa: E402
from aoi_orgware import windows_handle_identity as windows_handles  # noqa: E402
from aoi_orgware.commands import release, semantic  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes  # noqa: E402
import release_inventory as inventory  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


@unittest.skipUnless(os.name == "nt", "native Windows-specific behavior")
class WindowsPathIngressTests(HarnessTestCase):
    def _make_junction(self, link: Path, target: Path) -> None:
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest(f"junction creation unavailable: {created.stderr}")

    def _swap_directory_for_junction(
        self, directory: Path, target: Path
    ) -> Path:
        original = directory.with_name(f"{directory.name}-before-junction")
        directory.rename(original)
        self._make_junction(directory, target)
        return original

    @staticmethod
    def _restore_swapped_directory(directory: Path, original: Path) -> None:
        if directory.exists():
            os.rmdir(directory)
        if original.exists():
            original.rename(directory)

    def _short_spelling(self, path: Path) -> Path:
        resolved = path.resolve()
        candidates = (resolved, *resolved.parents)
        probed: list[str] = []
        for candidate in candidates:
            short = self._short_path(candidate)
            probed.append(str(candidate))
            if short is not None:
                return short / resolved.relative_to(candidate)
        for drive in (Path("C:/"), Path("D:/")):
            if drive.exists():
                self._short_path(drive)
                probed.append(str(drive))
        self.skipTest(
            "no distinct NTFS short-path spelling is available for the ingress "
            f"root (probed: {', '.join(probed)})"
        )

    @staticmethod
    def _short_path(path: Path) -> Path | None:
        buffer = ctypes.create_unicode_buffer(32_768)
        length = ctypes.windll.kernel32.GetShortPathNameW(
            str(path), buffer, len(buffer)
        )
        if not length or length >= len(buffer):
            return None
        short = Path(buffer.value)
        if os.path.normcase(str(short)) == os.path.normcase(str(path)):
            return None
        return short

    def test_short_path_ingress_is_canonicalized_after_component_inspection(self) -> None:
        short_root = self._short_spelling(self.root)
        request = self.root / "ingress.json"
        request.write_bytes(canonical_json_bytes({"ingress": "short-path"}))
        short_request = short_root / request.name

        self.hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "windows-short-ingress",
                "source": "startup",
                "cwd": str(short_root),
            }
        )
        stored = session_receipts.load_startup_receipt(
            h.get_paths(self.root), "windows-short-ingress"
        )
        self.assertEqual(stored["cwd"], str(self.root.resolve()))
        self.assertEqual(
            semantic._load_canonical_json_artifact(
                str(short_request), label="Windows short semantic request", maximum=1024
            ),
            {"ingress": "short-path"},
        )
        self.assertEqual(
            release._read_canonical_json(
                str(short_request), label="Windows short release request", maximum=1024
            ),
            {"ingress": "short-path"},
        )
        with mock.patch.object(
            confidentiality,
            "parse_git_push_preflight_receipt_bytes",
            return_value={"parsed": "receipt"},
        ):
            self.assertEqual(
                confidentiality.load_git_push_preflight_receipt(short_request),
                {"parsed": "receipt"},
            )

        dist = self.root / "dist"
        dist.mkdir()
        (dist / "aoi_orgware-0.4.0-py3-none-any.whl").write_bytes(b"wheel")
        (dist / "aoi_orgware-0.4.0.tar.gz").write_bytes(b"sdist")
        captured = inventory.capture(
            short_root / "dist", distribution_name="aoi-orgware", package_version="0.4.0"
        )
        self.assertEqual(len(captured["artifacts"]), 2)

    def test_case_spelling_alias_is_canonicalized(self) -> None:
        canonical_root = self.root / "CaseSpellingIngress"
        canonical_root.mkdir()
        alias_root = canonical_root.with_name(canonical_root.name.casefold())
        request = canonical_root / "request.json"
        request.write_bytes(canonical_json_bytes({"ingress": "case-alias"}))
        alias_request = alias_root / request.name

        self.hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "windows-case-ingress",
                "source": "startup",
                "cwd": str(alias_root),
            }
        )
        stored = session_receipts.load_startup_receipt(
            h.get_paths(self.root), "windows-case-ingress"
        )
        self.assertEqual(stored["cwd"], str(canonical_root.resolve()))
        self.assertEqual(
            semantic._load_canonical_json_artifact(
                str(alias_request), label="case semantic request", maximum=1024
            ),
            {"ingress": "case-alias"},
        )
        self.assertEqual(
            release._read_canonical_json(
                str(alias_request), label="case release request", maximum=1024
            ),
            {"ingress": "case-alias"},
        )
        with mock.patch.object(
            confidentiality,
            "parse_git_push_preflight_receipt_bytes",
            return_value={"parsed": "case-alias"},
        ):
            self.assertEqual(
                confidentiality.load_git_push_preflight_receipt(alias_request),
                {"parsed": "case-alias"},
            )

    def test_short_path_winapi_contract_when_short_names_are_unavailable(self) -> None:
        expected = str(self.root / "TEST~1")

        class _Kernel32:
            @staticmethod
            def GetShortPathNameW(_path: str, buffer: object, _size: int) -> int:
                buffer.value = expected
                return len(expected)

        with mock.patch.object(
            ctypes, "windll", SimpleNamespace(kernel32=_Kernel32()), create=True
        ):
            self.assertEqual(self._short_spelling(self.root), Path(expected))

    def test_junction_ingress_is_rejected_before_read_or_inventory(self) -> None:
        request = self.root / "junction-request.json"
        request.write_bytes(canonical_json_bytes({"ingress": "junction"}))
        junction = self.root.parent / f"{self.root.name}-ingress-junction"
        try:
            self._make_junction(junction, self.root)
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                semantic._load_canonical_json_artifact(
                    str(junction / request.name),
                    label="junction semantic request",
                    maximum=1024,
                )
            with self.assertRaisesRegex(h.HarnessError, "symlinks or junctions"):
                release._read_canonical_json(
                    str(junction / request.name),
                    label="junction release request",
                    maximum=1024,
                )
            with self.assertRaisesRegex(inventory.InventoryError, "link or reparse"):
                inventory._secure_directory(junction, label="junction artifact root")
        finally:
            if junction.exists():
                os.rmdir(junction)

    def test_junction_swap_after_initial_check_is_rejected(self) -> None:
        receipt_dir = self.root / "receipt-parent"
        outside_receipt_dir = self.root / "outside-receipt-parent"
        receipt_dir.mkdir()
        outside_receipt_dir.mkdir()
        receipt = receipt_dir / "receipt.json"
        receipt.write_bytes(b'{"inside":true}')
        (outside_receipt_dir / receipt.name).write_bytes(b'{"outside":true}')
        original_open = os.open
        receipt_original: Path | None = None

        def swap_then_open(*args: object, **kwargs: object) -> int:
            nonlocal receipt_original
            receipt_original = self._swap_directory_for_junction(
                receipt_dir, outside_receipt_dir
            )
            descriptor = original_open(*args, **kwargs)
            self._restore_swapped_directory(receipt_dir, receipt_original)
            receipt_original = None
            return descriptor

        try:
            with (
                mock.patch.object(
                    confidentiality,
                    "parse_git_push_preflight_receipt_bytes",
                    return_value={"outside": "receipt"},
                ),
                mock.patch.object(
                    confidentiality.os, "open", side_effect=swap_then_open
                ),
            ):
                with self.assertRaisesRegex(
                    confidentiality.ConfidentialityError, "symlinks or junctions|changed"
                ):
                    confidentiality.load_git_push_preflight_receipt(receipt)
        finally:
            if receipt_original is not None:
                self._restore_swapped_directory(receipt_dir, receipt_original)

        json_dir = self.root / "json-parent"
        outside_json_dir = self.root / "outside-json-parent"
        json_dir.mkdir()
        outside_json_dir.mkdir()
        request = json_dir / "request.json"
        request.write_bytes(canonical_json_bytes({"ingress": "inside"}))
        (outside_json_dir / request.name).write_bytes(
            canonical_json_bytes({"ingress": "outside"})
        )
        original_path_open = Path.open
        json_original: Path | None = None

        def swap_json_path_open(path: Path, *args: object, **kwargs: object) -> object:
            nonlocal json_original
            if path == request and json_original is None:
                json_original = self._swap_directory_for_junction(
                    json_dir, outside_json_dir
                )
                handle = original_path_open(path, *args, **kwargs)
                self._restore_swapped_directory(json_dir, json_original)
                json_original = None
                return handle
            return original_path_open(path, *args, **kwargs)

        try:
            with mock.patch.object(Path, "open", new=swap_json_path_open):
                with self.assertRaisesRegex(h.HarnessError, "changed while being opened"):
                    semantic._load_canonical_json_artifact(
                        str(request), label="swapped semantic request", maximum=1024
                    )
        finally:
            if json_original is not None:
                self._restore_swapped_directory(json_dir, json_original)

        original_release_open = os.open
        release_original: Path | None = None

        def swap_release_open(path: object, *args: object, **kwargs: object) -> int:
            nonlocal release_original
            if Path(path) == request and release_original is None:
                release_original = self._swap_directory_for_junction(
                    json_dir, outside_json_dir
                )
                descriptor = original_release_open(path, *args, **kwargs)
                self._restore_swapped_directory(json_dir, release_original)
                release_original = None
                return descriptor
            return original_release_open(path, *args, **kwargs)

        try:
            with mock.patch.object(release.os, "open", side_effect=swap_release_open):
                with self.assertRaisesRegex(h.HarnessError, "changed while being opened"):
                    release._read_canonical_json(
                        str(request), label="swapped release request", maximum=1024
                    )
        finally:
            if release_original is not None:
                self._restore_swapped_directory(json_dir, release_original)

        dist = self.root / "dist-parent"
        outside_dist = self.root / "outside-dist-parent"
        dist.mkdir()
        outside_dist.mkdir()
        for directory, payload in ((dist, b"inside"), (outside_dist, b"outside")):
            (directory / "aoi_orgware-0.4.0-py3-none-any.whl").write_bytes(payload)
            (directory / "aoi_orgware-0.4.0.tar.gz").write_bytes(payload)
        dist_original: Path | None = None

        original_file_open = os.open
        swapped_artifact = False

        def swap_read_restore(path: object, *args: object, **kwargs: object) -> int:
            nonlocal dist_original, swapped_artifact
            candidate = Path(path)
            if candidate.parent == dist and not swapped_artifact:
                swapped_artifact = True
                dist_original = self._swap_directory_for_junction(dist, outside_dist)
                descriptor = original_file_open(path, *args, **kwargs)
                self._restore_swapped_directory(dist, dist_original)
                dist_original = None
                return descriptor
            return original_file_open(path, *args, **kwargs)

        try:
            with mock.patch.object(
                inventory.os, "open", side_effect=swap_read_restore
            ):
                with self.assertRaisesRegex(
                    inventory.InventoryError, "outside the stable artifact root|changed"
                ):
                    inventory.capture(
                        dist,
                        distribution_name="aoi-orgware",
                        package_version="0.4.0",
                    )
        finally:
            if dist_original is not None:
                self._restore_swapped_directory(dist, dist_original)

    def test_resolve_time_junction_swap_is_rejected_by_all_ingress_families(
        self,
    ) -> None:
        inside = self.root / "resolve-swap-inside"
        outside = self.root / "resolve-swap-outside"
        inside.mkdir()
        outside.mkdir()
        request = inside / "request.json"
        request.write_bytes(canonical_json_bytes({"source": "inside"}))
        (outside / request.name).write_bytes(
            canonical_json_bytes({"source": "outside"})
        )
        original_resolve = Path.resolve

        def one_resolve_swap(target: Path, swapped_root: Path, outside_root: Path):
            triggered = False

            def resolve(
                candidate: Path, *args: object, **kwargs: object
            ) -> Path:
                nonlocal triggered
                if candidate == target and not triggered:
                    triggered = True
                    original = self._swap_directory_for_junction(
                        swapped_root, outside_root
                    )
                    try:
                        return original_resolve(candidate, *args, **kwargs)
                    finally:
                        self._restore_swapped_directory(swapped_root, original)
                return original_resolve(candidate, *args, **kwargs)

            return resolve

        with mock.patch.object(
            Path,
            "resolve",
            new=one_resolve_swap(request, inside, outside),
        ):
            with self.assertRaisesRegex(h.HarnessError, "changed"):
                semantic._load_canonical_json_artifact(
                    str(request), label="resolve-swapped semantic request", maximum=1024
                )

        with mock.patch.object(
            Path,
            "resolve",
            new=one_resolve_swap(request, inside, outside),
        ):
            with self.assertRaisesRegex(h.HarnessError, "changed"):
                release._read_canonical_json(
                    str(request), label="resolve-swapped release request", maximum=1024
                )

        with mock.patch.object(
            Path,
            "resolve",
            new=one_resolve_swap(request, inside, outside),
        ):
            with self.assertRaisesRegex(
                confidentiality.ConfidentialityError, "changed"
            ):
                confidentiality.load_git_push_preflight_receipt(request)

        with (
            mock.patch.object(
                Path,
                "resolve",
                new=one_resolve_swap(inside, inside, outside),
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            codex_hook.session_start(
                self.root,
                {
                    "hook_event_name": "SessionStart",
                    "session_id": "resolve-swapped-cwd",
                    "source": "startup",
                    "cwd": str(inside),
                },
            )
        hook_output = json.loads(stdout.getvalue())
        self.assertIn(
            codex_hook.STARTUP_RECEIPT_WARNING,
            hook_output["hookSpecificOutput"]["additionalContext"],
        )
        with self.assertRaises(session_receipts.SessionReceiptError):
            session_receipts.load_startup_receipt(
                h.get_paths(self.root), "resolve-swapped-cwd"
            )

        dist = self.root / "resolve-swap-dist"
        outside_dist = self.root / "resolve-swap-dist-outside"
        dist.mkdir()
        outside_dist.mkdir()
        for directory, payload in ((dist, b"inside"), (outside_dist, b"outside")):
            (directory / "aoi_orgware-0.4.0-py3-none-any.whl").write_bytes(payload)
            (directory / "aoi_orgware-0.4.0.tar.gz").write_bytes(payload)
        captured = inventory.capture(
            dist, distribution_name="aoi-orgware", package_version="0.4.0"
        )

        with mock.patch.object(
            Path,
            "resolve",
            new=one_resolve_swap(dist, dist, outside_dist),
        ):
            with self.assertRaisesRegex(inventory.InventoryError, "changed"):
                inventory.capture(
                    dist,
                    distribution_name="aoi-orgware",
                    package_version="0.4.0",
                )

        with mock.patch.object(
            Path,
            "resolve",
            new=one_resolve_swap(dist, dist, outside_dist),
        ):
            with self.assertRaisesRegex(inventory.InventoryError, "changed"):
                inventory.verify(captured, dist)

    def test_capture_rejects_transient_mutation_only_when_watcher_is_enabled(self) -> None:
        dist = self.root / "stable-root"
        dist.mkdir()
        (dist / "aoi_orgware-0.4.0-py3-none-any.whl").write_bytes(b"wheel")
        (dist / "aoi_orgware-0.4.0.tar.gz").write_bytes(b"sdist")
        with mock.patch.object(
            Path,
            "iterdir",
            side_effect=AssertionError("inventory must enumerate the held handle"),
        ):
            captured = inventory.capture(
                dist, distribution_name="aoi-orgware", package_version="0.4.0"
            )
        self.assertEqual(len(captured["artifacts"]), 2)

        (dist / "unexpected-stable-root.txt").write_bytes(b"unexpected")
        with self.assertRaisesRegex(
            inventory.InventoryError, "unsupported distribution artifact"
        ):
            inventory.capture(
                dist, distribution_name="aoi-orgware", package_version="0.4.0"
            )
        (dist / "unexpected-stable-root.txt").unlink()

        original_entries = windows_handles.DirectoryHandle.entries
        original_identity_from_handle = windows_handles._identity_from_handle
        stable_identities: dict[int, windows_handles.WindowsHandleIdentity] = {}
        original_open_directory = inventory.open_directory_identity

        def metadata_identity(handle_value: int) -> windows_handles.WindowsHandleIdentity:
            """Hide directory metadata drift; the watcher must still reject it."""

            identity = original_identity_from_handle(handle_value)
            return stable_identities.get(handle_value, identity)

        def open_and_track(
            path: Path, *, watch_changes: bool = False, enable_watch: bool
        ) -> windows_handles.DirectoryHandle:
            self.assertTrue(watch_changes)
            handle = original_open_directory(path, watch_changes=enable_watch)
            assert handle._handle is not None
            assert handle.identity is not None
            # Freeze the baseline before the transient mutation; reading the
            # identity for the first time afterwards would not hide its drift.
            stable_identities[handle._handle] = handle.identity
            return handle

        def mutate_after_enumeration(
            handle: windows_handles.DirectoryHandle,
        ) -> list[windows_handles.DirectoryEntry]:
            entries = original_entries(handle)
            transient = dist / "unexpected-after-enumeration.txt"
            transient.write_bytes(b"transient")
            transient.unlink()
            return entries

        def capture_with_watch(enable_watch: bool) -> dict[str, object]:
            stable_identities.clear()
            with (
                mock.patch.object(
                    windows_handles.DirectoryHandle,
                    "entries",
                    new=mutate_after_enumeration,
                ),
                mock.patch.object(
                    inventory,
                    "open_directory_identity",
                    new=lambda path, *, watch_changes=False: open_and_track(
                        path, watch_changes=watch_changes, enable_watch=enable_watch
                    ),
                ),
                mock.patch.object(
                    windows_handles,
                    "_identity_from_handle",
                    side_effect=metadata_identity,
                ),
            ):
                return inventory.capture(
                    dist,
                    distribution_name="aoi-orgware",
                    package_version="0.4.0",
                )

        with self.assertRaisesRegex(inventory.InventoryError, "changed while being captured"):
            capture_with_watch(True)
        self.assertEqual(len(capture_with_watch(False)["artifacts"]), 2)

    def test_verify_rejects_transient_mutation_only_when_watcher_is_enabled(self) -> None:
        dist = self.root / "verify-stable-root"
        dist.mkdir()
        (dist / "aoi_orgware-0.4.0-py3-none-any.whl").write_bytes(b"wheel")
        (dist / "aoi_orgware-0.4.0.tar.gz").write_bytes(b"sdist")
        captured = inventory.capture(
            dist, distribution_name="aoi-orgware", package_version="0.4.0"
        )
        original_entries = windows_handles.DirectoryHandle.entries
        original_identity_from_handle = windows_handles._identity_from_handle
        original_open_directory = inventory.open_directory_identity
        stable_identities: dict[int, windows_handles.WindowsHandleIdentity] = {}

        def metadata_identity(handle_value: int) -> windows_handles.WindowsHandleIdentity:
            identity = original_identity_from_handle(handle_value)
            return stable_identities.get(handle_value, identity)

        def open_and_track(
            path: Path, *, watch_changes: bool = False, enable_watch: bool
        ) -> windows_handles.DirectoryHandle:
            self.assertTrue(watch_changes)
            handle = original_open_directory(path, watch_changes=enable_watch)
            assert handle._handle is not None
            assert handle.identity is not None
            stable_identities[handle._handle] = handle.identity
            return handle

        def mutate_after_enumeration(
            handle: windows_handles.DirectoryHandle,
        ) -> list[windows_handles.DirectoryEntry]:
            entries = original_entries(handle)
            transient = dist / "verify-transient-after-enumeration.txt"
            transient.write_bytes(b"transient")
            transient.unlink()
            return entries

        def verify_with_watch(enable_watch: bool) -> None:
            stable_identities.clear()
            with (
                mock.patch.object(
                    windows_handles.DirectoryHandle,
                    "entries",
                    new=mutate_after_enumeration,
                ),
                mock.patch.object(
                    inventory,
                    "open_directory_identity",
                    new=lambda path, *, watch_changes=False: open_and_track(
                        path, watch_changes=watch_changes, enable_watch=enable_watch
                    ),
                ),
                mock.patch.object(
                    windows_handles,
                    "_identity_from_handle",
                    side_effect=metadata_identity,
                ),
            ):
                inventory.verify(captured, dist)

        with self.assertRaisesRegex(inventory.InventoryError, "changed while being verified"):
            verify_with_watch(True)
        verify_with_watch(False)

    def test_change_watch_finalization_drains_before_any_handle_is_closed(self) -> None:
        identity = windows_handles.WindowsHandleIdentity("C:\\watch", 1, 2, 1, 3)
        handle = windows_handles.DirectoryHandle(17, identity)
        handle._change_buffer = ctypes.create_string_buffer(1)
        handle._change_overlapped = ctypes.c_ulong()
        handle._change_event = 18
        handle._change_watch_enabled = True
        order: list[str] = []

        def cancel(*_args: object) -> bool:
            order.append("cancel")
            ctypes.set_last_error(1168)  # ERROR_NOT_FOUND: completion raced.
            return False

        def get_result(*_args: object) -> bool:
            order.append("drain")
            ctypes.set_last_error(995)  # ERROR_OPERATION_ABORTED: clean cancel.
            return False

        kernel32 = SimpleNamespace(
            CancelIoEx=mock.Mock(side_effect=cancel),
            GetOverlappedResult=mock.Mock(side_effect=get_result),
        )

        def current_identity(_handle: int) -> windows_handles.WindowsHandleIdentity:
            order.append("identity")
            return identity

        with (
            mock.patch.object(windows_handles, "_kernel32", return_value=kernel32),
            mock.patch.object(
                windows_handles, "_identity_from_handle", side_effect=current_identity
            ),
            mock.patch.object(
                windows_handles,
                "_close_handle",
                side_effect=lambda value: order.append(f"close:{value}"),
            ),
        ):
            handle.require_unchanged()
            handle.close()

        self.assertEqual(order, ["identity", "cancel", "drain", "close:18", "close:17"])

    def test_change_watch_completion_and_unexpected_cancel_error_drains_before_raise(self) -> None:
        identity = windows_handles.WindowsHandleIdentity("C:\\watch", 1, 2, 1, 3)

        def armed_handle() -> windows_handles.DirectoryHandle:
            handle = windows_handles.DirectoryHandle(17, identity)
            handle._change_buffer = ctypes.create_string_buffer(1)
            handle._change_overlapped = ctypes.c_ulong()
            handle._change_event = 18
            handle._change_watch_enabled = True
            return handle

        def raced_cancel(*_args: object) -> bool:
            ctypes.set_last_error(1168)  # ERROR_NOT_FOUND
            return False

        completed_kernel32 = SimpleNamespace(
            CancelIoEx=mock.Mock(side_effect=raced_cancel),
            GetOverlappedResult=mock.Mock(return_value=True),
        )
        completed = armed_handle()
        with (
            mock.patch.object(
                windows_handles, "_kernel32", return_value=completed_kernel32
            ),
            mock.patch.object(
                windows_handles, "_identity_from_handle", return_value=identity
            ),
            mock.patch.object(windows_handles, "_close_handle"),
        ):
            with self.assertRaisesRegex(OSError, "directory changed"):
                completed.require_unchanged()
        self.assertIsNone(completed._change_event)

        order: list[str] = []

        def unexpected_cancel(*_args: object) -> bool:
            order.append("cancel")
            ctypes.set_last_error(5)  # ERROR_ACCESS_DENIED
            return False

        failed_cancel_kernel32 = SimpleNamespace(
            CancelIoEx=mock.Mock(side_effect=unexpected_cancel),
            GetOverlappedResult=mock.Mock(),
        )
        failed_cancel = armed_handle()

        def drained_failure(*_args: object) -> bool:
            order.append("drain")
            ctypes.set_last_error(995)  # ERROR_OPERATION_ABORTED
            return False

        failed_cancel_kernel32.GetOverlappedResult.side_effect = drained_failure
        with (
            mock.patch.object(
                windows_handles, "_kernel32", return_value=failed_cancel_kernel32
            ),
            mock.patch.object(
                windows_handles,
                "_close_handle",
                side_effect=lambda value: order.append(f"close:{value}"),
            ),
        ):
            with self.assertRaises(OSError):
                failed_cancel.close()
        failed_cancel_kernel32.GetOverlappedResult.assert_called_once()
        self.assertEqual(order, ["cancel", "drain", "close:18", "close:17"])
        self.assertIsNone(failed_cancel._change_event)
        self.assertIsNone(failed_cancel._handle)

    def test_change_watch_boundary_distinguishes_pre_and_post_cancellation_races(self) -> None:
        identity = windows_handles.WindowsHandleIdentity("C:\\watch", 1, 2, 1, 3)

        def armed_handle() -> windows_handles.DirectoryHandle:
            handle = windows_handles.DirectoryHandle(17, identity)
            handle._change_buffer = ctypes.create_string_buffer(1)
            handle._change_overlapped = ctypes.c_ulong()
            handle._change_event = 18
            handle._change_watch_enabled = True
            return handle

        pre_boundary = armed_handle()
        pre_order = ["mutation-before-boundary"]

        def completed_cancel(*_args: object) -> bool:
            pre_order.append("cancel")
            return True

        def completed_result(*_args: object) -> bool:
            pre_order.append("drain")
            return True

        completed_kernel32 = SimpleNamespace(
            CancelIoEx=mock.Mock(side_effect=completed_cancel),
            GetOverlappedResult=mock.Mock(side_effect=completed_result),
        )
        with (
            mock.patch.object(windows_handles, "_kernel32", return_value=completed_kernel32),
            mock.patch.object(windows_handles, "_close_handle"),
        ):
            self.assertTrue(pre_boundary._finalize_change_watch())
        self.assertEqual(pre_order, ["mutation-before-boundary", "cancel", "drain"])

        post_boundary = armed_handle()
        cancellation_boundary = threading.Event()
        mutation_finished = threading.Event()
        order: list[str] = []

        def mutate_after_boundary() -> None:
            self.assertTrue(cancellation_boundary.wait(timeout=1))
            order.append("mutation-after-boundary")
            mutation_finished.set()

        worker = threading.Thread(target=mutate_after_boundary)
        worker.start()

        def cancel(*_args: object) -> bool:
            order.append("cancel")
            cancellation_boundary.set()
            self.assertTrue(mutation_finished.wait(timeout=1))
            return True

        def cancelled_result(*_args: object) -> bool:
            order.append("drain")
            ctypes.set_last_error(995)  # ERROR_OPERATION_ABORTED
            return False

        cancelled_kernel32 = SimpleNamespace(
            CancelIoEx=mock.Mock(side_effect=cancel),
            GetOverlappedResult=mock.Mock(side_effect=cancelled_result),
        )
        with (
            mock.patch.object(windows_handles, "_kernel32", return_value=cancelled_kernel32),
            mock.patch.object(windows_handles, "_close_handle"),
        ):
            self.assertFalse(post_boundary._finalize_change_watch())
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(order, ["cancel", "mutation-after-boundary", "drain"])

    def test_directory_exit_preserves_body_exception_when_cleanup_detects_change(self) -> None:
        identity = windows_handles.WindowsHandleIdentity("C:\\watch", 1, 2, 1, 3)
        handle = windows_handles.DirectoryHandle(17, identity)
        handle._change_buffer = ctypes.create_string_buffer(1)
        handle._change_overlapped = ctypes.c_ulong()
        handle._change_event = 18
        handle._change_watch_enabled = True
        kernel32 = SimpleNamespace(
            CancelIoEx=mock.Mock(return_value=True),
            GetOverlappedResult=mock.Mock(return_value=True),
        )
        with (
            mock.patch.object(windows_handles, "_kernel32", return_value=kernel32),
            mock.patch.object(windows_handles, "_close_handle"),
        ):
            with self.assertRaisesRegex(RuntimeError, "body failure") as raised:
                with handle:
                    raise RuntimeError("body failure")
        self.assertTrue(
            any(
                "Directory cleanup also detected" in note
                for note in raised.exception.__notes__
            )
        )

    def test_directory_close_retains_handle_ownership_until_close_succeeds(self) -> None:
        identity = windows_handles.WindowsHandleIdentity("C:\\watch", 1, 2, 1, 3)
        handle = windows_handles.DirectoryHandle(17, identity)
        attempts: list[int] = []

        def close_once_then_succeed(value: int) -> None:
            attempts.append(value)
            if len(attempts) == 1:
                raise OSError("injected CloseHandle failure")

        with mock.patch.object(
            windows_handles,
            "_close_handle",
            side_effect=close_once_then_succeed,
        ):
            with self.assertRaisesRegex(OSError, "injected CloseHandle failure"):
                handle.close()
            self.assertEqual(handle._handle, 17)
            handle.close()

        self.assertEqual(attempts, [17, 17])
        self.assertIsNone(handle._handle)

    def test_open_directory_watch_arms_before_baseline_and_uses_overlapped_flag_only_when_needed(
        self,
    ) -> None:
        identity = windows_handles.WindowsHandleIdentity("C:\\watch", 1, 2, 1, 3)
        create_file = mock.Mock(return_value=17)
        kernel32 = SimpleNamespace(CreateFileW=create_file)
        order: list[str] = []

        def arm(_handle: windows_handles.DirectoryHandle) -> None:
            order.append("arm")

        def baseline(_value: int) -> windows_handles.WindowsHandleIdentity:
            order.append("identity")
            return identity

        with (
            mock.patch.object(windows_handles, "_kernel32", return_value=kernel32),
            mock.patch.object(windows_handles, "_identity_from_handle", side_effect=baseline),
            mock.patch.object(windows_handles.DirectoryHandle, "begin_change_watch", new=arm),
            mock.patch.object(windows_handles, "_close_handle"),
        ):
            plain = windows_handles.open_directory_identity(Path("C:/plain"))
            watched = windows_handles.open_directory_identity(
                Path("C:/watched"), watch_changes=True
            )
            plain.close()
            watched.close()

        self.assertEqual(create_file.call_args_list[0].args[5], 0x02000000)
        self.assertEqual(create_file.call_args_list[1].args[5], 0x42000000)
        self.assertEqual(order, ["identity", "arm", "identity"])

        already_watched = windows_handles.DirectoryHandle(17, identity)
        already_watched._change_event = 18
        with self.assertRaisesRegex(OSError, "already armed"):
            already_watched.begin_change_watch()
