"""Release-version consistency tests."""

from __future__ import annotations

import contextlib
import io
import re
import stat
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(REPO / "scripts"))

from aoi_orgware import __version__ as runtime_version  # noqa: E402
from aoi_orgware._version import __version__ as canonical_version  # noqa: E402
import verify_dist as dist_verify  # noqa: E402


PYPROJECT = REPO / "pyproject.toml"
VERSION_PATH = "src/aoi_orgware/_version.py"
CANONICAL_PEP440 = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:(?:a|b|rc)(?:0|[1-9]\d*))?"
    r"(?:\.post(?:0|[1-9]\d*))?"
    r"(?:\.dev(?:0|[1-9]\d*))?\Z"
)


class ReleaseMetadataTests(unittest.TestCase):
    def test_canonical_version_uses_basic_canonical_pep440(self) -> None:
        self.assertIsNotNone(CANONICAL_PEP440.fullmatch(canonical_version))

    def test_pyproject_uses_dynamic_hatch_version_path(self) -> None:
        with PYPROJECT.open("rb") as handle:
            metadata = tomllib.load(handle)

        project = metadata["project"]
        self.assertNotIn("version", project)
        self.assertEqual(project["dynamic"], ["version"])
        self.assertEqual(
            metadata["tool"]["hatch"]["version"]["path"], VERSION_PATH
        )

    def test_runtime_reexports_canonical_version(self) -> None:
        self.assertEqual(runtime_version, canonical_version)

    def test_release_verifier_rejects_windows_drive_members(self) -> None:
        with self.assertRaisesRegex(dist_verify.VerificationError, "unsafe archive"):
            dist_verify._validate_member_names(
                Path("candidate.whl"), ["C:/escape/payload.py"]
            )

    def test_release_verifier_rejects_wheel_and_sdist_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "candidate.whl"
            sdist = root / "candidate.tar.gz"
            with tarfile.open(sdist, "w:gz"):
                pass
            with zipfile.ZipFile(wheel, "w") as archive:
                link = zipfile.ZipInfo("aoi_orgware/link")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "target")
            with self.assertRaisesRegex(
                dist_verify.VerificationError, "symbolic link"
            ):
                dist_verify._validate_archive_contents(wheel, sdist)

            with zipfile.ZipFile(wheel, "w"):
                pass
            with tarfile.open(sdist, "w:gz") as archive:
                link = tarfile.TarInfo("candidate/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "target"
                archive.addfile(link)
            with self.assertRaisesRegex(
                dist_verify.VerificationError, "archive link"
            ):
                dist_verify._validate_archive_contents(wheel, sdist)

    def test_release_verifier_requires_expected_version(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            dist_verify.build_parser().parse_args([])

    def test_release_verifier_rejects_extra_entries_and_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "candidate.whl"
            sdist = root / "candidate.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")
            (root / "unverified.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(
                dist_verify.VerificationError, "unverified entries"
            ):
                dist_verify.verify_dist(root, expected_version="0.3.0a1")

            (root / "unverified.txt").unlink()
            with mock.patch.object(
                dist_verify, "_validate_archive_contents", return_value=None
            ), mock.patch.object(
                dist_verify,
                "_verify_installed_artifact",
                side_effect=["0.3.0a2", "0.3.0a2"],
            ), self.assertRaisesRegex(
                dist_verify.VerificationError, "release expectation"
            ):
                dist_verify.verify_dist(root, expected_version="0.3.0a1")

    def test_workflow_binds_expected_version_and_smokes_windows_artifact(self) -> None:
        workflow = (REPO / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("--expected-version", workflow)
        self.assertIn("package-windows-smoke:", workflow)
        self.assertIn("actions/download-artifact@v4", workflow)

    def test_publish_workflow_consumes_the_dynamic_version_and_shared_verifier(
        self,
    ) -> None:
        workflow = (REPO / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(VERSION_PATH, workflow)
        self.assertIn("project_metadata.get(\"dynamic\")", workflow)
        self.assertIn("scripts/verify_dist.py", workflow)
        self.assertNotIn('["project"]["version"]', workflow)
        self.assertNotIn('Path("src/aoi_orgware/__init__.py")', workflow)


if __name__ == "__main__":
    unittest.main()
