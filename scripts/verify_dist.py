#!/usr/bin/env python3
"""Verify an AOI wheel plus an sdist-derived wheel from isolated installs."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Sequence


CONSOLE_SCRIPTS = ("aoi", "aoi-codex-hook", "aoi-codex-bridge", "aoi-claude-hook")
BUILD_FRONTEND_VERSION = "1.5.0"
HATCHLING_VERSION = "1.27.0"
REQUIRED_PACKAGE_FILES = (
    "aoi_orgware/__init__.py",
    "aoi_orgware/resources/policy.md",
    "aoi_orgware/resources/codex/SKILL.md",
    "aoi_orgware/resources/claude/SKILL.md",
    "aoi_orgware/resources/pilot/run-record.template.json",
    "aoi_orgware/resources/codex_app_server/0.144.6/runtime-pin.json",
    "aoi_orgware/resources/codex_app_server/0.144.6/schema-manifest.json",
    "aoi_orgware/resources/codex_app_server/0.144.6/codex_app_server_protocol.v2.schemas.json",
)
FORBIDDEN_SDIST_FILES = ("PROVENANCE.md", "IMPORT_MANIFEST.json")
INSTALL_PROBE = r"""
from __future__ import annotations

import importlib.metadata
import importlib.resources
import json
import sys
from pathlib import Path

import aoi_orgware

distribution_version = importlib.metadata.version("aoi-orgware")
if distribution_version != aoi_orgware.__version__:
    raise SystemExit(
        f"metadata version {distribution_version!r} does not match "
        f"package version {aoi_orgware.__version__!r}"
    )

package_path = Path(aoi_orgware.__file__).resolve()
environment_root = Path(sys.prefix).resolve()
if not package_path.is_relative_to(environment_root):
    raise SystemExit(
        f"aoi_orgware loaded outside isolated environment: {package_path}"
    )

resource_root = importlib.resources.files("aoi_orgware.resources")
required_resources = (
    "policy.md",
    "codex/SKILL.md",
    "claude/SKILL.md",
    "pilot/run-record.template.json",
    "codex_app_server/0.144.6/runtime-pin.json",
    "codex_app_server/0.144.6/schema-manifest.json",
    "codex_app_server/0.144.6/codex_app_server_protocol.v2.schemas.json",
)
missing = []
for relative in required_resources:
    resource = resource_root
    for part in relative.split("/"):
        resource = resource.joinpath(part)
    if not resource.is_file():
        missing.append(relative)
if missing:
    raise SystemExit("installed package is missing resources: " + ", ".join(missing))

print(
    json.dumps(
        {
            "package_path": str(package_path),
            "version": distribution_version,
        },
        sort_keys=True,
    )
)
"""


class VerificationError(RuntimeError):
    """A distribution artifact failed a release-blocking check."""


def _run(
    command: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    rendered = [os.fspath(item) for item in command]
    result = subprocess.run(
        rendered,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise VerificationError(
            f"command failed ({result.returncode}): {' '.join(rendered)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _artifact_members(path: Path) -> tuple[str, ...]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return tuple(archive.namelist())
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            return tuple(member.name for member in archive.getmembers())
    raise VerificationError(f"unsupported distribution artifact: {path}")


def _validate_member_names(path: Path, members: Sequence[str]) -> None:
    for member in members:
        portable = member.replace("\\", "/")
        normalized = PurePosixPath(portable)
        if (
            normalized.is_absolute()
            or ".." in normalized.parts
            or re.match(r"^[A-Za-z]:", portable) is not None
        ):
            raise VerificationError(f"unsafe archive member in {path.name}: {member}")


def _has_suffix(members: Sequence[str], suffix: str) -> bool:
    return any(member == suffix or member.endswith(f"/{suffix}") for member in members)


def _validate_archive_contents(wheel: Path, sdist: Path) -> None:
    wheel_members = _artifact_members(wheel)
    sdist_members = _artifact_members(sdist)
    _validate_member_names(wheel, wheel_members)
    _validate_member_names(sdist, sdist_members)

    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            file_type = (member.external_attr >> 16) & 0o170000
            if file_type == stat.S_IFLNK:
                raise VerificationError(
                    f"wheel contains a symbolic link: {member.filename}"
                )
    with tarfile.open(sdist, mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                raise VerificationError(
                    f"sdist contains an archive link: {member.name}"
                )
            if not (member.isdir() or member.isfile()):
                raise VerificationError(
                    f"sdist contains an unsupported archive member: {member.name}"
                )

    for required in REQUIRED_PACKAGE_FILES:
        if required not in wheel_members:
            raise VerificationError(f"wheel is missing required member: {required}")
        sdist_required = f"src/{required}"
        if not _has_suffix(sdist_members, sdist_required):
            raise VerificationError(f"sdist is missing required member: {sdist_required}")

    for forbidden in FORBIDDEN_SDIST_FILES:
        if _has_suffix(sdist_members, forbidden):
            raise VerificationError(f"sdist unexpectedly contains: {forbidden}")


def _venv_executable(environment: Path, name: str) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / f"{name}.exe"
    return environment / "bin" / name


def _isolated_environment() -> dict[str, str]:
    env = os.environ.copy()
    # A release verifier must not inherit a caller's index, configuration,
    # import path, or virtual environment.  Keep this aligned with the PyPI
    # readback installer: only the exact local artifact is permitted.
    for variable in tuple(env):
        if variable.startswith(("PIP_", "PYTHON")) or variable == "VIRTUAL_ENV":
            env.pop(variable, None)
    env.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
        }
    )
    return env


def _verify_installed_artifact(artifact: Path) -> str:
    artifact = artifact.resolve(strict=True)
    if not artifact.is_absolute() or not artifact.is_file():
        raise VerificationError("distribution artifact is not an absolute regular file")
    with tempfile.TemporaryDirectory(prefix="aoi-dist-verify-") as directory:
        root = Path(directory).resolve()
        environment = root / "environment"
        env = _isolated_environment()
        _run([sys.executable, "-m", "venv", environment], cwd=root, env=env)

        python = _venv_executable(environment, "python")
        _run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--isolated",
                "--no-deps",
                "--no-index",
                "--only-binary=:all:",
                "--no-cache-dir",
                artifact.resolve(),
            ],
            cwd=root,
            env=env,
        )
        probe = _run([python, "-I", "-c", INSTALL_PROBE], cwd=root, env=env)
        try:
            installed = json.loads(probe.stdout)
            installed_version = installed["version"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise VerificationError(
                f"{artifact.name} returned an invalid install probe: {probe.stdout!r}"
            ) from exc
        if not isinstance(installed_version, str) or not installed_version:
            raise VerificationError(
                f"{artifact.name} returned an invalid installed version"
            )

        for script_name in CONSOLE_SCRIPTS:
            script = _venv_executable(environment, script_name)
            if not script.is_file():
                raise VerificationError(
                    f"{artifact.name} did not install console script: {script_name}"
                )
            _run([script, "--help"], cwd=root, env=env)
        return installed_version


def _verify_build_backend(
    build_python: Path,
    *,
    expected_build_version: str,
    expected_hatchling_version: str,
    cwd: Path,
    env: dict[str, str],
) -> Path:
    # Keep the requested executable path intact.  POSIX virtual environments
    # normally expose ``bin/python`` as a symlink to the base interpreter;
    # resolving that symlink would escape the venv and probe the wrong
    # environment.  ``is_file`` still follows the link and rejects a missing
    # or non-file target without changing the path used for execution.
    build_python = Path(os.path.abspath(os.fspath(build_python)))
    if not build_python.is_file():
        raise VerificationError("build backend Python is not a regular file")
    probe = _run(
        [
            build_python,
            "-I",
            "-c",
            (
                "import importlib.metadata as metadata, json; "
                "print(json.dumps({'build': metadata.version('build'), "
                "'hatchling': metadata.version('hatchling')}, sort_keys=True))"
            ),
        ],
        cwd=cwd,
        env=env,
    )
    try:
        versions = json.loads(probe.stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            f"build backend returned invalid version probe: {probe.stdout!r}"
        ) from exc
    expected = {
        "build": expected_build_version,
        "hatchling": expected_hatchling_version,
    }
    if versions != expected:
        raise VerificationError(
            "build backend versions differ from the release contract: "
            f"expected {expected!r}, found {versions!r}"
        )
    return build_python


def _extract_sdist(sdist: Path, destination: Path) -> Path:
    with tarfile.open(sdist, mode="r:gz") as archive:
        members = archive.getmembers()
        _validate_member_names(sdist, tuple(member.name for member in members))
        roots = {
            PurePosixPath(member.name.replace("\\", "/")).parts[0]
            for member in members
            if member.name
        }
        if len(roots) != 1:
            raise VerificationError("sdist must contain exactly one top-level source directory")
        for member in members:
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise VerificationError(
                    f"sdist contains an unsafe archive member: {member.name}"
                )
        archive.extractall(destination, members=members)
    source_root = destination / roots.pop()
    if not source_root.is_dir() or not (source_root / "pyproject.toml").is_file():
        raise VerificationError("sdist does not extract to a Python project root")
    return source_root


def _verify_sdist_via_derived_wheel(
    sdist: Path,
    *,
    build_python: Path,
    expected_build_version: str,
    expected_hatchling_version: str,
) -> str:
    sdist = sdist.resolve(strict=True)
    env = _isolated_environment()
    with tempfile.TemporaryDirectory(prefix="aoi-sdist-derive-") as directory:
        root = Path(directory).resolve()
        build_python = _verify_build_backend(
            build_python,
            expected_build_version=expected_build_version,
            expected_hatchling_version=expected_hatchling_version,
            cwd=root,
            env=env,
        )
        source_root = _extract_sdist(sdist, root / "source")
        derived_dir = root / "derived"
        derived_dir.mkdir()
        _run(
            [
                build_python,
                "-I",
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                derived_dir,
                source_root,
            ],
            cwd=root,
            env=env,
        )
        wheels = sorted(derived_dir.glob("*.whl"))
        if len(wheels) != 1:
            raise VerificationError(
                "building the exact sdist must produce exactly one derived wheel; "
                f"found {len(wheels)}"
            )
        return _verify_installed_artifact(wheels[0])


def verify_dist(
    dist_dir: Path,
    *,
    expected_version: str,
    build_python: Path = Path(sys.executable),
    expected_build_version: str = BUILD_FRONTEND_VERSION,
    expected_hatchling_version: str = HATCHLING_VERSION,
) -> None:
    dist_dir = dist_dir.resolve()
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise VerificationError(
            "expected exactly one wheel and one .tar.gz sdist; "
            f"found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)"
        )

    wheel, sdist = wheels[0], sdists[0]
    extra_entries = sorted(
        entry.name for entry in dist_dir.iterdir() if entry not in {wheel, sdist}
    )
    if extra_entries:
        raise VerificationError(
            "distribution directory contains unverified entries: "
            + ", ".join(extra_entries)
        )
    if wheel.stat().st_size == 0 or sdist.stat().st_size == 0:
        raise VerificationError("distribution artifacts must not be empty")

    _validate_archive_contents(wheel, sdist)
    wheel_version = _verify_installed_artifact(wheel)
    sdist_version = _verify_sdist_via_derived_wheel(
        sdist,
        build_python=build_python,
        expected_build_version=expected_build_version,
        expected_hatchling_version=expected_hatchling_version,
    )
    if wheel_version != sdist_version:
        raise VerificationError(
            "wheel and sdist versions differ: "
            f"{wheel_version!r} != {sdist_version!r}"
        )
    if wheel_version != expected_version:
        raise VerificationError(
            "artifact version differs from the release expectation: "
            f"{wheel_version!r} != {expected_version!r}"
        )
    print(
        "verified isolated original-wheel and sdist-derived-wheel installs: "
        f"{wheel.name}, {sdist.name}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=Path("dist"),
        help="directory containing exactly one wheel and one .tar.gz sdist",
    )
    parser.add_argument(
        "--expected-version",
        required=True,
        help="exact PEP 440 version expected from both installed wheels",
    )
    parser.add_argument(
        "--build-python",
        type=Path,
        default=Path(sys.executable),
        help="Python executable in the preinstalled, version-verified build backend environment",
    )
    parser.add_argument(
        "--expected-build-version",
        default=BUILD_FRONTEND_VERSION,
        help="exact build frontend version required in --build-python",
    )
    parser.add_argument(
        "--expected-hatchling-version",
        default=HATCHLING_VERSION,
        help="exact hatchling version required in --build-python",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        verify_dist(
            args.dist_dir,
            expected_version=args.expected_version,
            build_python=args.build_python,
            expected_build_version=args.expected_build_version,
            expected_hatchling_version=args.expected_hatchling_version,
        )
    except (
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
        VerificationError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
