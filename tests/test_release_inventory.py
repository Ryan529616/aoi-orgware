"""Tests for exact release distribution inventorying and staging."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import release_inventory as inventory  # noqa: E402


class ReleaseInventoryTests(unittest.TestCase):
    def _dist(self, root: Path) -> Path:
        dist = root / "dist"
        dist.mkdir()
        (dist / "aoi_orgware-0.3.0a2-py3-none-any.whl").write_bytes(b"wheel bytes")
        (dist / "aoi_orgware-0.3.0a2.tar.gz").write_bytes(b"sdist bytes")
        return dist

    def _capture(self, root: Path) -> tuple[Path, dict[str, object]]:
        dist = self._dist(root)
        value = inventory.capture(dist, distribution_name="aoi-orgware", package_version="0.3.0a2")
        path = root / "inventory.json"
        path.write_bytes(inventory._canonical_json(value))
        return dist, value

    def test_capture_is_canonical_exact_and_cli_verify_and_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, value = self._capture(root)
            self.assertEqual([item["name"] for item in value["artifacts"]], sorted(item["name"] for item in value["artifacts"]))
            loaded = inventory.load_inventory(root / "inventory.json")
            inventory.verify(loaded, dist)
            staged = root / "staged"
            receipt = inventory.stage(loaded, dist, staged)
            self.assertEqual(set(item.name for item in staged.iterdir()), set(item["name"] for item in value["artifacts"]))
            self.assertEqual(receipt["inventory_sha256"], value["inventory_sha256"])
            self.assertEqual(inventory.main(["verify", "--inventory", str(root / "inventory.json"), "--root", str(dist)]), 0)
            cli_stage = root / "cli-staged"
            result = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "release_inventory.py"), "stage", "--inventory", str(root / "inventory.json"), "--source-root", str(dist), "--destination-root", str(cli_stage)],
                text=False,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertFalse(result.stdout.endswith(b"\n"))
            self.assertEqual(json.loads(result.stdout)["inventory_sha256"], value["inventory_sha256"])

    def test_capture_rejects_extra_and_unsafe_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = self._dist(root)
            (dist / "unapproved.txt").write_bytes(b"extra")
            with self.assertRaisesRegex(inventory.InventoryError, "unsupported"):
                inventory.capture(dist, distribution_name="aoi-orgware", package_version="0.3.0a2")
            (dist / "unapproved.txt").unlink()
            (dist / "CON.whl").write_bytes(b"reserved")
            with self.assertRaisesRegex(inventory.InventoryError, "Windows-reserved"):
                inventory.capture(dist, distribution_name="aoi-orgware", package_version="0.3.0a2")

    def test_load_rejects_duplicate_and_noncanonical_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, value = self._capture(root)
            path = root / "inventory.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(inventory.InventoryError, "duplicate"):
                inventory.load_inventory(path)
            path.write_bytes(inventory._canonical_json(value) + b"\n")
            with self.assertRaisesRegex(inventory.InventoryError, "canonical"):
                inventory.load_inventory(path)

    def test_verify_rejects_replacement_missing_extra_casefold_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, value = self._capture(root)
            name = value["artifacts"][0]["name"]
            (dist / name).write_bytes(b"replacement")
            with self.assertRaisesRegex(inventory.InventoryError, "size changed|hash"):
                inventory.verify(value, dist)
            (dist / name).unlink()
            with self.assertRaisesRegex(inventory.InventoryError, "missing"):
                inventory.verify(value, dist)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, value = self._capture(root)
            bad = dict(value)
            bad["artifacts"] = [
                {"name": "same.whl", "size_bytes": 1, "sha256": "0" * 64},
                {"name": "SAME.tar.gz", "size_bytes": 1, "sha256": "1" * 64},
            ]
            bad["inventory_sha256"] = hashlib.sha256(
                inventory._canonical_json({key: item for key, item in bad.items() if key != "inventory_sha256"})
            ).hexdigest()
            with self.assertRaisesRegex(inventory.InventoryError, "filename|casefold"):
                inventory.verify(bad, dist)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, value = self._capture(root)
            artifact = dist / value["artifacts"][0]["name"]
            linked = root / "copy.bin"
            try:
                os.link(artifact, linked)
            except OSError as exc:
                self.skipTest(f"hardlinks unavailable: {exc}")
            with self.assertRaisesRegex(inventory.InventoryError, "hard-linked"):
                inventory.verify(value, dist)

    def test_stage_refuses_nonempty_or_existing_destination_and_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, value = self._capture(root)
            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "old").write_bytes(b"old")
            with self.assertRaisesRegex(inventory.InventoryError, "empty"):
                inventory.stage(value, dist, occupied)
            destination = root / "staged"
            receipt = inventory.stage(value, dist, destination)
            self.assertEqual(
                receipt["stage_receipt_sha256"],
                hashlib.sha256(inventory._canonical_json({key: value for key, value in receipt.items() if key != "stage_receipt_sha256"})).hexdigest(),
            )
            with self.assertRaisesRegex(inventory.InventoryError, "empty"):
                inventory.stage(value, dist, destination)

    def test_symlink_and_oversize_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, _ = self._capture(root)
            target = dist / "aoi_orgware-0.3.0a2.tar.gz"
            target.unlink()
            try:
                target.symlink_to(dist / "aoi_orgware-0.3.0a2-py3-none-any.whl")
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(inventory.InventoryError, "link"):
                    inventory.capture(dist, distribution_name="aoi-orgware", package_version="0.3.0a2")
                target.unlink()
            target.write_bytes(b"sdist")
            original = inventory.MAX_ARTIFACT_BYTES
            inventory.MAX_ARTIFACT_BYTES = 3
            try:
                with self.assertRaisesRegex(inventory.InventoryError, "invalid size"):
                    inventory.capture(dist, distribution_name="aoi-orgware", package_version="0.3.0a2")
            finally:
                inventory.MAX_ARTIFACT_BYTES = original

    def test_contract_matches_manifest_names_versions_and_aggregate_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = self._dist(root)
            for distribution_name in ("aoi_orgware", "aoi.orgware"):
                with self.assertRaisesRegex(inventory.InventoryError, "distribution_name"):
                    inventory.capture(
                        dist,
                        distribution_name=distribution_name,
                        package_version="0.3.0a2",
                    )
            for package_version in ("03.0", "v0.3.0", "0.3.0-RC1"):
                with self.assertRaisesRegex(inventory.InventoryError, "package_version"):
                    inventory.capture(
                        dist,
                        distribution_name="aoi-orgware",
                        package_version=package_version,
                    )

            original = inventory.MAX_ARTIFACT_AGGREGATE_BYTES
            inventory.MAX_ARTIFACT_AGGREGATE_BYTES = 20
            try:
                with self.assertRaisesRegex(inventory.InventoryError, "aggregate"):
                    inventory.capture(
                        dist,
                        distribution_name="aoi-orgware",
                        package_version="0.3.0a2",
                    )
            finally:
                inventory.MAX_ARTIFACT_AGGREGATE_BYTES = original

            for artifact in dist.iterdir():
                artifact.rename(artifact.with_name(artifact.name.replace("aoi_orgware-0.3.0a2", "other_pkg-9.9")))
            with self.assertRaisesRegex(inventory.InventoryError, "filename does not match"):
                inventory.capture(
                    dist,
                    distribution_name="aoi-orgware",
                    package_version="0.3.0a2",
                )

    def test_wheel_filename_requires_exact_distribution_version_and_valid_build_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = self._dist(root)
            wheel = dist / "aoi_orgware-0.3.0a2-py3-none-any.whl"
            wheel.rename(dist / "aoi_orgware-0.3.0a2-build-py3-none-any.whl")
            with self.assertRaisesRegex(inventory.InventoryError, "build tag"):
                inventory.capture(
                    dist,
                    distribution_name="aoi-orgware",
                    package_version="0.3.0a2",
                )
            (dist / "aoi_orgware-0.3.0a2-build-py3-none-any.whl").rename(
                dist / "aoi_orgware-0.3.0a2-1build-py3-none-any.whl"
            )
            value = inventory.capture(
                dist,
                distribution_name="aoi-orgware",
                package_version="0.3.0a2",
            )
            self.assertEqual(len(value["artifacts"]), 2)

    def test_artifact_digest_uses_nofollow_descriptor_when_available(self) -> None:
        if not hasattr(inventory.os, "O_NOFOLLOW"):
            self.skipTest("platform has no no-follow descriptor flag")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = self._dist(root)
            original_open = inventory.os.open
            flags: list[int] = []
            def checked_open(*args, **kwargs):
                flags.append(args[1])
                return original_open(*args, **kwargs)
            with mock.patch.object(inventory.os, "open", side_effect=checked_open):
                inventory.capture(
                    dist,
                    distribution_name="aoi-orgware",
                    package_version="0.3.0a2",
                )
            self.assertTrue(flags)
            self.assertTrue(all(flag & inventory.os.O_NOFOLLOW for flag in flags))

    def test_directory_with_linked_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            dist = self._dist(real)
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            with self.assertRaisesRegex(inventory.InventoryError, "traverse a link|alias"):
                inventory.capture(
                    alias / dist.name,
                    distribution_name="aoi-orgware",
                    package_version="0.3.0a2",
                )


if __name__ == "__main__":
    unittest.main()
