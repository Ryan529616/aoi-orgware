"""Release-version consistency tests."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import re
import stat
import subprocess
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

    def test_release_verifier_requires_bridge_entry_point_and_pinned_resources(self) -> None:
        self.assertIn("aoi-codex-bridge", dist_verify.CONSOLE_SCRIPTS)
        expected = {
            "aoi_orgware/resources/codex_app_server/0.145.0/runtime-pin.json",
            "aoi_orgware/resources/codex_app_server/0.145.0/schema-manifest.json",
            "aoi_orgware/resources/codex_app_server/0.145.0/codex_app_server_protocol.v2.schemas.json",
        }
        self.assertTrue(expected.issubset(dist_verify.REQUIRED_PACKAGE_FILES))

    def test_release_verifier_rejects_self_consistent_runtime_resource_tampering(
        self,
    ) -> None:
        """RECORD cannot substitute for the independently pinned runtime bytes."""

        resource_bytes = {
            member: (SRC / member).read_bytes()
            for member in dist_verify.REQUIRED_PACKAGE_FILES
        }

        def write_sdist(path: Path) -> None:
            with tarfile.open(path, "w:gz") as archive:
                for member, payload in resource_bytes.items():
                    info = tarfile.TarInfo(f"candidate/src/{member}")
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))

        def write_wheel(path: Path, altered_member: str, payload: bytes) -> str:
            members = {
                **resource_bytes,
                altered_member: payload,
                "aoi_orgware-0.4.0a1.dist-info/METADATA": (
                    b"Metadata-Version: 2.1\nName: aoi-orgware\nVersion: 0.4.0a1\n"
                ),
            }
            with zipfile.ZipFile(path, "w") as archive:
                for member, member_bytes in members.items():
                    archive.writestr(member, member_bytes)
                rows = []
                for member, member_bytes in members.items():
                    digest = base64.urlsafe_b64encode(
                        hashlib.sha256(member_bytes).digest()
                    ).rstrip(b"=").decode("ascii")
                    rows.append(f"{member},sha256={digest},{len(member_bytes)}")
                record_member = "aoi_orgware-0.4.0a1.dist-info/RECORD"
                archive.writestr(record_member, "\n".join(rows) + f"\n{record_member},,\n")
            return "\n".join(rows)

        altered_pin = json.loads(resource_bytes[dist_verify.RUNTIME_PIN_MEMBER])
        altered_pin["release_url"] = "https://attacker.invalid/rust-v0.145.0"
        altered_manifest = resource_bytes[dist_verify.SCHEMA_MANIFEST_MEMBER] + b" "
        cases = (
            (
                dist_verify.RUNTIME_PIN_MEMBER,
                json.dumps(altered_pin, sort_keys=True).encode("utf-8"),
                "provenance differs",
            ),
            (
                dist_verify.SCHEMA_MANIFEST_MEMBER,
                altered_manifest,
                "schema-manifest.json digest differs",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "candidate.tar.gz"
            write_sdist(sdist)
            for member, payload, message in cases:
                with self.subTest(member=member):
                    wheel = root / "candidate.whl"
                    record_rows = write_wheel(wheel, member, payload)
                    encoded = base64.urlsafe_b64encode(
                        hashlib.sha256(payload).digest()
                    ).rstrip(b"=").decode("ascii")
                    self.assertIn(f"{member},sha256={encoded},{len(payload)}", record_rows)
                    with self.assertRaisesRegex(dist_verify.VerificationError, message):
                        dist_verify._validate_archive_contents(wheel, sdist)

    def test_release_verifier_requires_installed_runtime_binding_and_digests(
        self,
    ) -> None:
        probe = {
            "runtime_binding": dist_verify.EXPECTED_CODEX_RUNTIME_BINDING,
            "runtime_resources": {
                "runtime_pin": dist_verify.EXPECTED_CODEX_RUNTIME_PIN,
                "runtime_pin_sha256": dist_verify.EXPECTED_RUNTIME_PIN_SHA256,
                "runtime_pin_size": dist_verify.EXPECTED_RUNTIME_PIN_SIZE,
                "schema_manifest_sha256": dist_verify.EXPECTED_SCHEMA_MANIFEST_SHA256,
                "schema_manifest_size": dist_verify.EXPECTED_SCHEMA_MANIFEST_SIZE,
                "combined_schema_sha256": dist_verify.EXPECTED_COMBINED_SCHEMA_SHA256,
                "combined_schema_size": dist_verify.EXPECTED_COMBINED_SCHEMA_SIZE,
            },
        }
        dist_verify._validate_installed_runtime_probe(
            probe, artifact=Path("candidate.whl")
        )
        bad_probe = {
            **probe,
            "runtime_binding": {
                **dist_verify.EXPECTED_CODEX_RUNTIME_BINDING,
                "schema_manifest_sha256": "0" * 64,
            },
        }
        with self.assertRaisesRegex(dist_verify.VerificationError, "runtime binding"):
            dist_verify._validate_installed_runtime_probe(
                bad_probe, artifact=Path("candidate.whl")
            )

    def test_sdist_derived_wheel_runtime_resources_are_checked_before_install(
        self,
    ) -> None:
        resource_bytes = {
            member: (SRC / member).read_bytes()
            for member in dist_verify.RUNTIME_RESOURCE_MEMBERS
        }
        resource_bytes[dist_verify.SCHEMA_MANIFEST_MEMBER] += b" "

        def fake_build(command: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.assertIsInstance(command, list)
            arguments = list(command)  # type: ignore[arg-type]
            output = Path(arguments[arguments.index("--outdir") + 1])
            output.mkdir(parents=True, exist_ok=True)
            wheel = output / "candidate-0.4.0a1-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for member, payload in resource_bytes.items():
                    archive.writestr(member, payload)
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "candidate.tar.gz"
            sdist.write_bytes(b"placeholder")
            source = root / "source-project"
            source.mkdir()
            with (
                mock.patch.object(
                    dist_verify,
                    "_verify_build_backend",
                    return_value=Path(sys.executable),
                ),
                mock.patch.object(dist_verify, "_extract_sdist", return_value=source),
                mock.patch.object(dist_verify, "_run", side_effect=fake_build),
                mock.patch.object(
                    dist_verify,
                    "_verify_installed_artifact",
                    return_value="0.4.0a1",
                ) as installed,
            ):
                with self.assertRaisesRegex(
                    dist_verify.VerificationError,
                    "schema-manifest.json digest differs",
                ):
                    dist_verify._verify_sdist_via_derived_wheel(
                        sdist,
                        build_python=Path(sys.executable),
                        expected_build_version=dist_verify.BUILD_FRONTEND_VERSION,
                        expected_hatchling_version=dist_verify.HATCHLING_VERSION,
                    )
                installed.assert_not_called()

    def test_release_verifier_scrubs_ambient_python_and_pip_configuration(self) -> None:
        with mock.patch.dict(
            dist_verify.os.environ,
            {
                "PIP_INDEX_URL": "https://attacker.invalid/simple",
                "PIP_CONFIG_FILE": "attacker-pip.conf",
                "PYTHONPATH": "attacker-imports",
                "PYTHONHOME": "attacker-home",
                "VIRTUAL_ENV": "attacker-venv",
                "SAFE": "retained",
            },
            clear=True,
        ):
            environment = dist_verify._isolated_environment()
        self.assertEqual(environment["SAFE"], "retained")
        self.assertEqual(environment["PIP_CONFIG_FILE"], dist_verify.os.devnull)
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertTrue(environment["PYTHONNOUSERSITE"] == "1")
        self.assertFalse(any(name.startswith(("PIP_", "PYTHON")) and name not in {"PIP_CONFIG_FILE", "PIP_DISABLE_PIP_VERSION_CHECK", "PIP_NO_INDEX", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"} for name in environment))
        self.assertNotIn("VIRTUAL_ENV", environment)

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
                return_value="0.3.0a2",
            ), mock.patch.object(
                dist_verify,
                "_verify_sdist_via_derived_wheel",
                return_value="0.3.0a2",
            ), self.assertRaisesRegex(
                dist_verify.VerificationError, "release expectation"
            ):
                dist_verify.verify_dist(root, expected_version="0.3.0a1")

    def test_release_verifier_derives_a_wheel_from_the_exact_sdist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "candidate.whl"
            sdist = root / "candidate.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")
            with mock.patch.object(
                dist_verify, "_validate_archive_contents", return_value=None
            ), mock.patch.object(
                dist_verify,
                "_verify_installed_artifact",
                return_value="0.3.0a1",
            ) as installed, mock.patch.object(
                dist_verify,
                "_verify_sdist_via_derived_wheel",
                return_value="0.3.0a1",
            ) as derived:
                dist_verify.verify_dist(root, expected_version="0.3.0a1")

            installed.assert_called_once_with(wheel)
            derived.assert_called_once_with(
                sdist,
                build_python=Path(sys.executable),
                expected_build_version=dist_verify.BUILD_FRONTEND_VERSION,
                expected_hatchling_version=dist_verify.HATCHLING_VERSION,
            )

    def test_release_verifier_rejects_a_mismatched_build_backend(self) -> None:
        probe = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"build": "0.0.0", "hatchling": "1.27.0"}\n',
            stderr="",
        )
        with mock.patch.object(dist_verify, "_run", return_value=probe), self.assertRaisesRegex(
            dist_verify.VerificationError, "build backend versions differ"
        ):
            dist_verify._verify_build_backend(
                Path(sys.executable),
                expected_build_version="1.5.0",
                expected_hatchling_version="1.27.0",
                cwd=REPO,
                env=dist_verify._isolated_environment(),
            )

    def test_sdist_build_preserves_a_symlinked_virtualenv_python(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "candidate.tar.gz"
            sdist.write_bytes(b"placeholder")
            build_python = root / "release-tools-python"
            try:
                build_python.symlink_to(Path(sys.executable).resolve())
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            source_root = root / "source-root"
            source_root.mkdir()
            calls: list[list[str | Path]] = []

            def run_build(command, *, cwd, env, timeout=180):  # type: ignore[no-untyped-def]
                rendered = list(command)
                calls.append(rendered)
                if "-c" in rendered:
                    return subprocess.CompletedProcess(
                        args=rendered,
                        returncode=0,
                        stdout='{"build": "1.5.0", "hatchling": "1.27.0"}\n',
                        stderr="",
                    )
                output = Path(rendered[rendered.index("--outdir") + 1])
                output.mkdir(exist_ok=True)
                (output / "derived.whl").write_bytes(b"wheel")
                return subprocess.CompletedProcess(
                    args=rendered,
                    returncode=0,
                    stdout="",
                    stderr="",
                )

            with mock.patch.object(
                dist_verify, "_extract_sdist", return_value=source_root
            ), mock.patch.object(
                dist_verify, "_verify_installed_artifact", return_value="0.4.0a1"
            ), mock.patch.object(
                dist_verify, "_validate_archived_runtime_resources"
            ) as runtime_validation, mock.patch.object(
                dist_verify, "_run", side_effect=run_build
            ):
                version = dist_verify._verify_sdist_via_derived_wheel(
                    sdist,
                    build_python=build_python,
                    expected_build_version="1.5.0",
                    expected_hatchling_version="1.27.0",
                )

            self.assertEqual(version, "0.4.0a1")
            runtime_validation.assert_called_once()
            build_call = next(command for command in calls if "build" in command)
            self.assertEqual(Path(build_call[0]), build_python.absolute())
            self.assertNotEqual(Path(build_call[0]), Path(sys.executable).resolve())

    def test_release_verifier_rejects_multi_root_sdist_before_building(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdist = root / "candidate.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name in ("first/pyproject.toml", "second/pyproject.toml"):
                    payload = b"[build-system]\n"
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(
                dist_verify.VerificationError, "one top-level source directory"
            ):
                dist_verify._extract_sdist(sdist, root / "extracted")

    def test_workflow_binds_expected_version_and_smokes_windows_artifact(self) -> None:
        workflow = (REPO / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("--expected-version", workflow)
        self.assertIn("package-windows-smoke:", workflow)
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
            workflow,
        )
        self.assertNotIn("actions/download-artifact@v", workflow)
        self.assertGreaterEqual(workflow.count("requirements/release-tools.lock"), 4)
        self.assertEqual(workflow.count("--build-python"), 2)
        self.assertEqual(workflow.count("--expected-build-version 1.5.0"), 2)
        self.assertEqual(workflow.count("--expected-hatchling-version 1.27.0"), 2)

    def test_publish_workflow_consumes_the_dynamic_version_and_shared_verifier(
        self,
    ) -> None:
        workflow = (REPO / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(VERSION_PATH, workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("inputs.intent", workflow)
        self.assertIn("scripts/verify_dist.py", workflow)
        self.assertIn("scripts/release_inventory.py", workflow)
        self.assertIn("scripts/release_rehearsal.py", workflow)
        self.assertIn("scripts/release_pypi_readback.py", workflow)
        self.assertIn('"pytest==8.4.2"', workflow)
        self.assertIn('"hatchling==1.27.0"', workflow)
        self.assertIn("--no-isolation", workflow)
        self.assertIn("--build-python", workflow)
        self.assertNotIn("AOI_CHIEF_", workflow)
        self.assertNotIn("release-promote", workflow)


if __name__ == "__main__":
    unittest.main()
