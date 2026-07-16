#!/usr/bin/env python3
"""Verify AOI wheel and sdist artifacts from isolated installations."""

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


CONSOLE_SCRIPTS = ("aoi", "aoi-codex-hook", "aoi-claude-hook")
REQUIRED_PACKAGE_FILES = (
    "aoi_orgware/__init__.py",
    "aoi_orgware/resources/policy.md",
    "aoi_orgware/resources/codex/SKILL.md",
    "aoi_orgware/resources/claude/SKILL.md",
    "aoi_orgware/resources/pilot/run-record.template.json",
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
    for variable in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(variable, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _verify_installed_artifact(artifact: Path) -> str:
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
                "--no-deps",
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


def verify_dist(dist_dir: Path, *, expected_version: str) -> None:
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
    sdist_version = _verify_installed_artifact(sdist)
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
    print(f"verified isolated wheel and sdist installs: {wheel.name}, {sdist.name}")


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
        help="exact PEP 440 version expected from both installed artifacts",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        verify_dist(args.dist_dir, expected_version=args.expected_version)
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
