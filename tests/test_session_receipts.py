#!/usr/bin/env python3
"""Adversarial checks for dispatch-v6 startup receipt persistence."""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import session_receipts as receipts  # noqa: E402
from aoi_orgware.routing_authority import RoutingAuthorityError, seal_startup_receipt  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


class StartupReceiptStoreTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.paths = h.get_paths(self.root)

    def receipt(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 2,
            "hook_protocol_version": 6,
            "session_id": "session-receipt-1",
            "source": "startup",
            "observed_at": "2026-07-18T00:00:00Z",
            "cwd": str(self.root),
            "project_root": str(self.root),
            "aoi_config_sha256": self.paths.project.sha256,
            "observed_resource_files": [],
            "observed_resource_files_sha256": canonical_sha256([]),
        }
        value.update(changes)
        return value

    def legacy_receipt(self, **changes: object) -> dict[str, object]:
        value = self.receipt(**changes)
        value["schema_version"] = 1
        value.pop("observed_resource_files")
        value.pop("observed_resource_files_sha256")
        return {**value, "startup_receipt_sha256": canonical_sha256(value)}

    def unobserved_receipt(self, **changes: object) -> dict[str, object]:
        value = self.receipt(**changes)
        value.pop("observed_resource_files")
        value.pop("observed_resource_files_sha256")
        return value

    def test_full_sha_path_and_canonical_storage_round_trip(self) -> None:
        stored = receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        self.assertTrue(path.is_file())
        self.assertEqual(path.name, f"{receipts.startup_receipt_key('session-receipt-1')}.json")
        self.assertEqual(len(path.stem), 64)
        if os.name == "nt":
            self.assertEqual(
                receipts.startup_receipt_storage_protection(),
                {
                    "content_protection": "windows-dpapi-current-user-v1",
                    "acl_status": "windows-acl-unverified",
                },
            )
            self.assertNotEqual(
                path.read_bytes(),
                canonical_json_bytes(stored, max_bytes=receipts.MAX_STARTUP_RECEIPT_BYTES),
            )
        else:
            self.assertEqual(
                receipts.startup_receipt_storage_protection(),
                {
                    "content_protection": "posix-canonical-plaintext-v1",
                    "acl_status": "not-applicable",
                    "mode_status": "posix-current-user-owner-private-mode",
                },
            )
            self.assertEqual(path.read_bytes(), canonical_json_bytes(stored, max_bytes=receipts.MAX_STARTUP_RECEIPT_BYTES))
        self.assertEqual(receipts.load_startup_receipt(self.paths, "session-receipt-1"), stored)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode) & 0o077, 0)
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(path.parent.stat().st_uid, os.geteuid())

    def test_nonstartup_never_creates_store(self) -> None:
        for source in ("resume", "clear", "compact"):
            with self.subTest(source=source), self.assertRaises(RoutingAuthorityError):
                receipts.store_startup_receipt(self.paths, self.receipt(source=source))
        self.assertFalse(receipts.startup_receipts_dir(self.paths).exists())

    def test_same_identity_replay_is_idempotent_but_changed_identity_is_rejected(self) -> None:
        original = receipts.store_startup_receipt(self.paths, self.receipt())
        self.assertEqual(receipts.store_startup_receipt(self.paths, self.receipt()), original)
        replay = receipts.store_startup_receipt(
            self.paths, self.receipt(observed_at="2026-07-18T00:01:00Z")
        )
        self.assertEqual(replay, original)
        for field, value in (
            ("aoi_config_sha256", "0" * 64),
            ("project_root", str(self.root / "other-root")),
            ("cwd", str(self.root / "other-cwd")),
        ):
            with self.subTest(field=field), self.assertRaises(receipts.SessionReceiptError):
                receipts.store_startup_receipt(self.paths, self.receipt(**{field: value}))
        self.assertEqual(receipts.load_startup_receipt(self.paths, "session-receipt-1"), original)

    def test_legacy_v1_member_is_readable_without_poisoning_new_v2_creation(self) -> None:
        legacy = self.legacy_receipt()
        legacy_path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        with h.state_lock(self.paths, create_layout=False):
            receipts._ensure_receipt_directory(self.paths)
            h.atomic_create_bytes(
                legacy_path,
                receipts._encode_storage_payload(legacy),
            )

        self.assertEqual(
            receipts.load_startup_receipt(self.paths, "session-receipt-1"),
            legacy,
        )
        legacy_raw = legacy_path.read_bytes()
        current = receipts.store_startup_receipt(
            self.paths,
            self.receipt(session_id="session-receipt-2"),
        )
        self.assertEqual(current["schema_version"], 2)
        self.assertEqual(
            sorted(
                item["schema_version"]
                for item in receipts.scan_startup_receipts(self.paths)
            ),
            [1, 2],
        )
        with self.assertRaisesRegex(receipts.SessionReceiptError, "different schema"):
            receipts.store_startup_receipt(self.paths, self.receipt())
        self.assertEqual(legacy_path.read_bytes(), legacy_raw)

    def test_persist_replay_loads_existing_before_snapshot_or_storage_encoding(self) -> None:
        stored = receipts.store_startup_receipt(self.paths, self.receipt())
        with mock.patch.object(
            receipts,
            "snapshot_managed_resource_files",
            side_effect=AssertionError("snapshot must not run on replay"),
        ) as snapshot, mock.patch.object(
            receipts,
            "_encode_storage_payload",
            side_effect=AssertionError("storage encoding must not run on replay"),
        ) as encode:
            replay = receipts.persist_startup_receipt(
                self.paths,
                self.unobserved_receipt(observed_at="2026-07-18T00:05:00Z"),
            )
        self.assertEqual(replay, stored)
        snapshot.assert_not_called()
        encode.assert_not_called()

    def test_tamper_and_oversize_fail_closed(self) -> None:
        receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        path.write_bytes(b'{"forged":true}')
        with self.assertRaises(receipts.SessionReceiptError):
            receipts.load_startup_receipt(self.paths, "session-receipt-1")
        path.write_bytes(b"x" * (receipts.MAX_STARTUP_RECEIPT_FILE_BYTES + 1))
        with self.assertRaisesRegex(receipts.SessionReceiptError, "byte bound"):
            receipts.load_startup_receipt(self.paths, "session-receipt-1")

    def test_permissions_and_hardlink_fail_closed(self) -> None:
        receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        if os.name != "nt":
            path.chmod(0o644)
            with self.assertRaisesRegex(receipts.SessionReceiptError, "private"):
                receipts.load_startup_receipt(self.paths, "session-receipt-1")
            path.chmod(0o600)
        alias = path.with_name("receipt-hardlink-alias")
        os.link(path, alias)
        with self.assertRaisesRegex(receipts.SessionReceiptError, "non-linked"):
            receipts.load_startup_receipt(self.paths, "session-receipt-1")

    @mock.patch.object(receipts, "MAX_STARTUP_RECEIPT_SCAN_ENTRIES", 1)
    def test_scan_and_create_respect_entry_bound_but_replay_at_bound_works(self) -> None:
        receipts.store_startup_receipt(self.paths, self.receipt())
        self.assertEqual(receipts.store_startup_receipt(self.paths, self.receipt())["session_id"], "session-receipt-1")
        second = self.receipt(session_id="session-receipt-2")
        sealed = seal_startup_receipt(second)
        second_path = receipts.startup_receipt_path(self.paths, "session-receipt-2")
        with h.state_lock(self.paths, create_layout=False):
            h.atomic_create_bytes(
                second_path,
                receipts._encode_storage_payload(sealed),
            )
        with self.assertRaisesRegex(receipts.SessionReceiptError, "entry bound"):
            receipts.scan_startup_receipts(self.paths)

        # Restore a one-entry valid store, then prove the store API reserves
        # capacity rather than scanning successfully and overflowing it.
        second_path.unlink()
        with self.assertRaisesRegex(receipts.SessionReceiptError, "entry bound"):
            receipts.store_startup_receipt(self.paths, second)
        self.assertFalse(second_path.exists())

    def test_create_reserves_byte_bound_but_replay_at_bound_works(self) -> None:
        stored = receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        with mock.patch.object(receipts, "MAX_STARTUP_RECEIPT_SCAN_BYTES", path.stat().st_size):
            self.assertEqual(receipts.store_startup_receipt(self.paths, self.receipt()), stored)
            with self.assertRaisesRegex(receipts.SessionReceiptError, "byte bound"):
                receipts.store_startup_receipt(
                    self.paths, self.receipt(session_id="session-receipt-2")
                )
        self.assertFalse(receipts.startup_receipt_path(self.paths, "session-receipt-2").exists())

    def test_scan_rejects_byte_bound_exhaustion(self) -> None:
        receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        with mock.patch.object(receipts, "MAX_STARTUP_RECEIPT_SCAN_BYTES", path.stat().st_size - 1):
            with self.assertRaisesRegex(receipts.SessionReceiptError, "scan reached its byte bound"):
                receipts.scan_startup_receipts(self.paths)

    def test_scan_rejects_an_unmanaged_store_entry(self) -> None:
        receipts.store_startup_receipt(self.paths, self.receipt())
        (receipts.startup_receipts_dir(self.paths) / "unexpected.txt").write_text(
            "not a receipt", encoding="utf-8"
        )
        with self.assertRaisesRegex(receipts.SessionReceiptError, "unexpected entry"):
            receipts.scan_startup_receipts(self.paths)

    def test_symlink_fails_closed_when_supported(self) -> None:
        receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        outside = self.root / "outside-receipt.json"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        with self.assertRaises(h.HarnessError):
            receipts.load_startup_receipt(self.paths, "session-receipt-1")

    def test_store_holds_state_lock_through_atomic_create(self) -> None:
        real_create = h.atomic_create_bytes

        def observed_create(path: Path, payload: bytes) -> None:
            self.assertTrue(h._chief_lock_is_held(self.paths))
            real_create(path, payload)

        with mock.patch.object(h, "atomic_create_bytes", side_effect=observed_create):
            receipts.store_startup_receipt(self.paths, self.receipt())

    def test_idempotent_replay_never_calls_atomic_create(self) -> None:
        original = receipts.store_startup_receipt(self.paths, self.receipt())
        with mock.patch.object(h, "atomic_create_bytes") as create:
            self.assertEqual(receipts.store_startup_receipt(self.paths, self.receipt()), original)
        create.assert_not_called()

    def test_new_create_does_not_hide_noncollision_atomic_error(self) -> None:
        with mock.patch.object(
            h,
            "atomic_create_bytes",
            side_effect=h.HarnessError("simulated atomic create failure"),
        ):
            with self.assertRaisesRegex(h.HarnessError, "simulated atomic create failure"):
                receipts.store_startup_receipt(self.paths, self.receipt())
        self.assertFalse(
            receipts.startup_receipt_path(self.paths, "session-receipt-1").exists()
        )

    def test_concurrent_same_identity_startup_is_one_deterministic_receipt(self) -> None:
        barrier = threading.Barrier(2)

        def create() -> dict[str, object]:
            barrier.wait(timeout=10)
            return receipts.store_startup_receipt(self.paths, self.receipt())

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = list(pool.map(lambda _unused: create(), range(2)))
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        self.assertEqual(first, second)
        self.assertEqual(receipts.load_startup_receipt(self.paths, "session-receipt-1"), first)
        self.assertEqual([item.name for item in receipts.startup_receipts_dir(self.paths).iterdir()], [path.name])

    def test_extra_fields_cannot_persist_credential_material(self) -> None:
        with self.assertRaises(RoutingAuthorityError):
            receipts.store_startup_receipt(
                self.paths, self.receipt(chief_credential_file="must-not-store")
            )
        self.assertFalse(receipts.startup_receipts_dir(self.paths).exists())

    def test_decoded_boundary_receipt_allows_larger_windows_envelope(self) -> None:
        sealed = seal_startup_receipt(self.receipt())
        canonical = canonical_json_bytes(
            sealed, max_bytes=receipts.MAX_STARTUP_RECEIPT_BYTES
        )
        with mock.patch.object(receipts, "MAX_STARTUP_RECEIPT_BYTES", len(canonical)):
            stored = receipts.store_startup_receipt(self.paths, self.receipt())
            path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), receipts.MAX_STARTUP_RECEIPT_FILE_BYTES)
            if os.name == "nt":
                self.assertGreater(len(raw), len(canonical))
            else:
                self.assertEqual(raw, canonical)
            self.assertEqual(receipts.load_startup_receipt(self.paths, "session-receipt-1"), stored)

    @unittest.skipUnless(os.name == "nt", "requires native Windows DPAPI")
    def test_real_512_kib_decoded_dpapi_boundary_fits_file_bound(self) -> None:
        canonical = b"x" * receipts.MAX_STARTUP_RECEIPT_BYTES
        protected = receipts._windows_dpapi_receipt_transform(canonical, protect=True)
        envelope = {
            "schema_version": receipts._WINDOWS_ENVELOPE_VERSION,
            "storage_protection": receipts._WINDOWS_ENVELOPE_PROTECTION,
            "sealed_receipt_dpapi_base64": base64.b64encode(protected).decode("ascii"),
        }
        raw = canonical_json_bytes(
            envelope, max_bytes=receipts.MAX_STARTUP_RECEIPT_FILE_BYTES
        )
        self.assertGreater(len(raw), len(canonical))
        self.assertLessEqual(len(raw), receipts.MAX_STARTUP_RECEIPT_FILE_BYTES)
        self.assertEqual(
            receipts._decode_storage_payload(raw, Path("bounded-envelope.json")),
            canonical,
        )

    def test_wrong_project_config_or_cwd_has_zero_receipt_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            other_root = Path(temporary)
            (other_root / "aoi.toml").write_bytes(self.paths.config.read_bytes())
            other_paths = h.get_paths(other_root)
            with self.assertRaisesRegex(receipts.SessionReceiptError, "project root"):
                receipts.store_startup_receipt(other_paths, self.receipt())
            self.assertFalse(receipts.startup_receipts_dir(other_paths).exists())

        with self.assertRaisesRegex(receipts.SessionReceiptError, "cwd"):
            receipts.store_startup_receipt(
                self.paths, self.receipt(cwd=str(self.root.parent))
            )
        self.assertFalse(receipts.startup_receipts_dir(self.paths).exists())

        with self.assertRaisesRegex(receipts.SessionReceiptError, "canonical"):
            receipts.store_startup_receipt(
                self.paths, self.receipt(cwd=f"{self.root}{os.sep}.")
            )
        self.assertFalse(receipts.startup_receipts_dir(self.paths).exists())

        self.paths.config.write_bytes(self.paths.config.read_bytes() + b"\n")
        with self.assertRaisesRegex(receipts.SessionReceiptError, "configuration SHA"):
            receipts.store_startup_receipt(self.paths, self.receipt())
        self.assertFalse(receipts.startup_receipts_dir(self.paths).exists())

    @unittest.skipUnless(os.name == "nt", "requires native Windows DPAPI and ACLs")
    def test_windows_dpapi_envelope_hides_plaintext_under_everyone_read_acl(self) -> None:
        stored = receipts.store_startup_receipt(self.paths, self.receipt())
        path = receipts.startup_receipt_path(self.paths, "session-receipt-1")
        result = subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(R)"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = path.read_bytes()
        for plaintext in (
            stored["session_id"],
            stored["project_root"],
            stored["cwd"],
            stored["aoi_config_sha256"],
        ):
            self.assertNotIn(str(plaintext).encode("utf-8"), raw)
        envelope = json.loads(raw.decode("utf-8"))
        self.assertEqual(envelope["storage_protection"], "windows-dpapi-current-user-v1")
        self.assertEqual(
            receipts.startup_receipt_storage_protection()["acl_status"],
            "windows-acl-unverified",
        )
        self.assertEqual(receipts.load_startup_receipt(self.paths, "session-receipt-1"), stored)
        encoded = envelope["sealed_receipt_dpapi_base64"]
        envelope["sealed_receipt_dpapi_base64"] = (
            ("A" if encoded[0] != "A" else "B") + encoded[1:]
        )
        path.write_bytes(
            canonical_json_bytes(
                envelope, max_bytes=receipts.MAX_STARTUP_RECEIPT_FILE_BYTES
            )
        )
        with self.assertRaisesRegex(receipts.SessionReceiptError, "startup receipt contents"):
            receipts.load_startup_receipt(self.paths, "session-receipt-1")


if __name__ == "__main__":
    import unittest

    unittest.main()
