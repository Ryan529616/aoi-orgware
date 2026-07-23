#!/usr/bin/env python3
"""Verify an AOI wheel plus an sdist-derived wheel from isolated installs."""

from __future__ import annotations

import argparse
import hashlib
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
    "aoi_orgware/resources/codex_app_server/0.145.0/runtime-pin.json",
    "aoi_orgware/resources/codex_app_server/0.145.0/schema-manifest.json",
    "aoi_orgware/resources/codex_app_server/0.145.0/codex_app_server_protocol.v2.schemas.json",
)
FORBIDDEN_SDIST_FILES = ("PROVENANCE.md", "IMPORT_MANIFEST.json")
CODEX_APP_SERVER_RESOURCE_ROOT = (
    "aoi_orgware/resources/codex_app_server/0.145.0"
)
RUNTIME_PIN_MEMBER = f"{CODEX_APP_SERVER_RESOURCE_ROOT}/runtime-pin.json"
SCHEMA_MANIFEST_MEMBER = f"{CODEX_APP_SERVER_RESOURCE_ROOT}/schema-manifest.json"
COMBINED_SCHEMA_MEMBER = (
    f"{CODEX_APP_SERVER_RESOURCE_ROOT}/codex_app_server_protocol.v2.schemas.json"
)
RUNTIME_RESOURCE_MEMBERS = (
    RUNTIME_PIN_MEMBER,
    SCHEMA_MANIFEST_MEMBER,
    COMBINED_SCHEMA_MEMBER,
)
MAX_RUNTIME_RESOURCE_BYTES = 1 * 1024 * 1024
EXPECTED_RUNTIME_PIN_SIZE = 1848
EXPECTED_RUNTIME_PIN_SHA256 = (
    "190519cd4f6d5792b9fdf26373cdb734fb728fbcc31f84470307b5da4c005fdc"
)
EXPECTED_SCHEMA_MANIFEST_SIZE = 36135
EXPECTED_SCHEMA_MANIFEST_SHA256 = (
    "6b8bfa74e475c6c9b46926c46f287f47873d188b13ab3df8db4633602db73262"
)
EXPECTED_COMBINED_SCHEMA_SIZE = 491906
EXPECTED_COMBINED_SCHEMA_SHA256 = (
    "6253fd70273c2f33c42d0b6090eac771580c994b3c6eed4277598de08a5e69ec"
)

# This is intentionally independent from ``aoi_orgware`` source. A release
# verifier must anchor the published runtime provenance rather than trust the
# checkout that invoked it or code contained in a candidate archive.
EXPECTED_CODEX_RUNTIME_PIN = {
    "schema_version": 1,
    "release_tag": "rust-v0.145.0",
    "release_url": "https://github.com/openai/codex/releases/tag/rust-v0.145.0",
    "codex_cli_version": "codex-cli 0.145.0",
    "codex_app_server_version": "codex-app-server 0.145.0",
    "app_server_asset": {
        "name": "codex-app-server-x86_64-pc-windows-msvc.exe.zip",
        "size": 98743440,
        "sha256": "dfc57f87b9bc61d1d4503b7a60fbe5bae5f13a5283234c86a4c0da6c97a12961",
        "url": "https://github.com/openai/codex/releases/download/rust-v0.145.0/codex-app-server-x86_64-pc-windows-msvc.exe.zip",
    },
    "app_server_executable": {
        "name": "codex-app-server-x86_64-pc-windows-msvc.exe",
        "size": 299117872,
        "sha256": "5163c75ed88d460b35b03c8d8f4ef190b3bdd09971d7ac2bd90b48c435f1cf14",
    },
    "schema_generator_asset": {
        "name": "codex-x86_64-pc-windows-msvc.exe.zip",
        "size": 119947181,
        "sha256": "bc6ae808bf5a9cdf113364ac281594d6da76dc103c19129e9d32caed54ec3cda",
        "url": "https://github.com/openai/codex/releases/download/rust-v0.145.0/codex-x86_64-pc-windows-msvc.exe.zip",
    },
    "schema_generator_executable": {
        "name": "codex-x86_64-pc-windows-msvc.exe",
        "size": 359245096,
        "sha256": "83751f15cb6a0a7b97df67752c001e3fe1c20e18ffbfec3ff63567296205eb6c",
    },
    "stable_schema": {
        "generator_arguments": [
            "app-server",
            "generate-json-schema",
            "--out",
            "<fresh-empty-directory>",
        ],
        "experimental": False,
        "file_count": 273,
        "manifest_format": "canonical-json sorted array of path,sha256,size; POSIX relative paths; ASCII; no trailing newline",
        "manifest_size": EXPECTED_SCHEMA_MANIFEST_SIZE,
        "manifest_sha256": EXPECTED_SCHEMA_MANIFEST_SHA256,
        "combined_v2_schema_size": EXPECTED_COMBINED_SCHEMA_SIZE,
        "combined_v2_schema_sha256": EXPECTED_COMBINED_SCHEMA_SHA256,
    },
}
EXPECTED_CODEX_RUNTIME_BINDING = {
    "codex_cli_version": "codex-cli 0.145.0",
    "codex_app_server_version": "codex-app-server 0.145.0",
    "app_server_executable_sha256": "5163c75ed88d460b35b03c8d8f4ef190b3bdd09971d7ac2bd90b48c435f1cf14",
    "executable_size_bytes": 299117872,
    "schema_manifest_sha256": EXPECTED_SCHEMA_MANIFEST_SHA256,
    "combined_v2_schema_sha256": EXPECTED_COMBINED_SCHEMA_SHA256,
}
INSTALL_PROBE = r"""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import sys
from pathlib import Path

import aoi_orgware
from aoi_orgware import codex_transport_contracts

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
    "codex_app_server/0.145.0/runtime-pin.json",
    "codex_app_server/0.145.0/schema-manifest.json",
    "codex_app_server/0.145.0/codex_app_server_protocol.v2.schemas.json",
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

def resource_bytes(relative):
    resource = resource_root
    for part in relative.split("/"):
        resource = resource.joinpath(part)
    return resource.read_bytes()

runtime_pin_bytes = resource_bytes("codex_app_server/0.145.0/runtime-pin.json")
schema_manifest_bytes = resource_bytes("codex_app_server/0.145.0/schema-manifest.json")
combined_schema_bytes = resource_bytes(
    "codex_app_server/0.145.0/codex_app_server_protocol.v2.schemas.json"
)
try:
    runtime_pin = json.loads(runtime_pin_bytes)
    runtime_binding = codex_transport_contracts.pinned_runtime_binding()
except (json.JSONDecodeError, codex_transport_contracts.CodexTransportContractError) as exc:
    raise SystemExit("installed package Codex runtime binding rejected: " + str(exc))

print(
    json.dumps(
        {
            "package_path": str(package_path),
            "runtime_binding": runtime_binding,
            "runtime_resources": {
                "runtime_pin": runtime_pin,
                "runtime_pin_sha256": hashlib.sha256(runtime_pin_bytes).hexdigest(),
                "runtime_pin_size": len(runtime_pin_bytes),
                "schema_manifest_sha256": hashlib.sha256(schema_manifest_bytes).hexdigest(),
                "schema_manifest_size": len(schema_manifest_bytes),
                "combined_schema_sha256": hashlib.sha256(combined_schema_bytes).hexdigest(),
                "combined_schema_size": len(combined_schema_bytes),
            },
            "version": distribution_version,
        },
        sort_keys=True,
    )
)
"""


class VerificationError(RuntimeError):
    """A distribution artifact failed a release-blocking check."""


def _exact_value(actual: object, expected: object) -> bool:
    """Compare JSON values without accepting bool-as-int substitutions."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return set(actual) == set(expected) and all(
            _exact_value(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        return len(actual) == len(expected) and all(
            _exact_value(item, value) for item, value in zip(actual, expected)
        )
    return actual == expected


def _validate_runtime_resource_payload(
    runtime_pin_bytes: bytes,
    schema_manifest_bytes: bytes,
    combined_schema_bytes: bytes,
    *,
    subject: str,
) -> None:
    """Anchor exact 0.145.0 provenance and the two generated-schema digests."""

    if any(
        len(payload) > MAX_RUNTIME_RESOURCE_BYTES
        for payload in (runtime_pin_bytes, schema_manifest_bytes, combined_schema_bytes)
    ):
        raise VerificationError(f"{subject} Codex runtime resource exceeds bound")
    try:
        runtime_pin = json.loads(runtime_pin_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{subject} runtime-pin.json is invalid JSON") from exc
    if not _exact_value(runtime_pin, EXPECTED_CODEX_RUNTIME_PIN):
        raise VerificationError(f"{subject} Codex runtime provenance differs from 0.145.0")
    if (
        len(runtime_pin_bytes) != EXPECTED_RUNTIME_PIN_SIZE
        or hashlib.sha256(runtime_pin_bytes).hexdigest()
        != EXPECTED_RUNTIME_PIN_SHA256
    ):
        raise VerificationError(f"{subject} runtime-pin.json digest differs from 0.145.0")

    expected_digests = (
        (
            "schema-manifest.json",
            schema_manifest_bytes,
            EXPECTED_SCHEMA_MANIFEST_SIZE,
            EXPECTED_SCHEMA_MANIFEST_SHA256,
        ),
        (
            "codex_app_server_protocol.v2.schemas.json",
            combined_schema_bytes,
            EXPECTED_COMBINED_SCHEMA_SIZE,
            EXPECTED_COMBINED_SCHEMA_SHA256,
        ),
    )
    for name, payload, expected_size, expected_sha256 in expected_digests:
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise VerificationError(f"{subject} {name} digest differs from 0.145.0")


def _unique_archive_member(members: Sequence[str], suffix: str, *, subject: str) -> str:
    matches = [member for member in members if member == suffix or member.endswith(f"/{suffix}")]
    if len(matches) != 1:
        raise VerificationError(f"{subject} must contain exactly one {suffix}")
    return matches[0]


def _read_zip_member(archive: zipfile.ZipFile, member: str, *, subject: str) -> bytes:
    info = archive.getinfo(member)
    if info.file_size > MAX_RUNTIME_RESOURCE_BYTES:
        raise VerificationError(f"{subject} Codex runtime resource exceeds bound")
    with archive.open(info, "r") as handle:
        payload = handle.read(MAX_RUNTIME_RESOURCE_BYTES + 1)
    if len(payload) != info.file_size or len(payload) > MAX_RUNTIME_RESOURCE_BYTES:
        raise VerificationError(f"{subject} Codex runtime resource size is invalid")
    return payload


def _read_tar_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, *, subject: str
) -> bytes:
    if not member.isfile() or member.size > MAX_RUNTIME_RESOURCE_BYTES:
        raise VerificationError(f"{subject} Codex runtime resource exceeds bound")
    handle = archive.extractfile(member)
    if handle is None:
        raise VerificationError(f"{subject} cannot read Codex runtime resource")
    payload = handle.read(member.size + 1)
    if len(payload) != member.size:
        raise VerificationError(f"{subject} Codex runtime resource size changed while reading")
    return payload


def _validate_archived_runtime_resources(path: Path) -> None:
    """Validate resources directly from an archive before any build/install code runs."""

    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = tuple(archive.namelist())
            payloads = tuple(
                _read_zip_member(
                    archive,
                    _unique_archive_member(names, member, subject=path.name),
                    subject=path.name,
                )
                for member in RUNTIME_RESOURCE_MEMBERS
            )
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            tar_members = archive.getmembers()
            by_name = {member.name: member for member in tar_members}
            names = tuple(member.name for member in tar_members)
            payloads = tuple(
                _read_tar_member(
                    archive,
                    by_name[_unique_archive_member(names, f"src/{member}", subject=path.name)],
                    subject=path.name,
                )
                for member in RUNTIME_RESOURCE_MEMBERS
            )
    else:
        raise VerificationError(f"unsupported distribution artifact: {path}")
    _validate_runtime_resource_payload(*payloads, subject=path.name)


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
        for zip_member in archive.infolist():
            file_type = (zip_member.external_attr >> 16) & 0o170000
            if file_type == stat.S_IFLNK:
                raise VerificationError(
                    f"wheel contains a symbolic link: {zip_member.filename}"
                )
    with tarfile.open(sdist, mode="r:gz") as archive:
        for tar_member in archive.getmembers():
            if tar_member.issym() or tar_member.islnk():
                raise VerificationError(
                    f"sdist contains an archive link: {tar_member.name}"
                )
            if not (tar_member.isdir() or tar_member.isfile()):
                raise VerificationError(
                    f"sdist contains an unsupported archive member: {tar_member.name}"
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

    _validate_archived_runtime_resources(wheel)
    _validate_archived_runtime_resources(sdist)


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


def _validate_installed_runtime_probe(probe: object, *, artifact: Path) -> None:
    if not isinstance(probe, dict):
        raise VerificationError(f"{artifact.name} returned an invalid install probe")
    if not _exact_value(probe.get("runtime_binding"), EXPECTED_CODEX_RUNTIME_BINDING):
        raise VerificationError(
            f"{artifact.name} installed Codex runtime binding differs from 0.145.0"
        )
    runtime_resources = probe.get("runtime_resources")
    if not isinstance(runtime_resources, dict):
        raise VerificationError(
            f"{artifact.name} returned no installed Codex runtime resource evidence"
        )
    runtime_pin = runtime_resources.get("runtime_pin")
    if not _exact_value(runtime_pin, EXPECTED_CODEX_RUNTIME_PIN):
        raise VerificationError(
            f"{artifact.name} installed Codex runtime provenance differs from 0.145.0"
        )
    expected = {
        "runtime_pin_sha256": EXPECTED_RUNTIME_PIN_SHA256,
        "runtime_pin_size": EXPECTED_RUNTIME_PIN_SIZE,
        "schema_manifest_sha256": EXPECTED_SCHEMA_MANIFEST_SHA256,
        "schema_manifest_size": EXPECTED_SCHEMA_MANIFEST_SIZE,
        "combined_schema_sha256": EXPECTED_COMBINED_SCHEMA_SHA256,
        "combined_schema_size": EXPECTED_COMBINED_SCHEMA_SIZE,
    }
    if not _exact_value(
        {key: runtime_resources.get(key) for key in expected}, expected
    ):
        raise VerificationError(
            f"{artifact.name} installed Codex runtime schema digest differs from 0.145.0"
        )


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
        _validate_installed_runtime_probe(installed, artifact=artifact)

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
        # The sdist is candidate-controlled and may produce a wheel whose code
        # forges its installed probe.  Validate the generated runtime resources
        # directly from the archive before executing or importing that wheel.
        _validate_archived_runtime_resources(wheels[0])
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
