#!/usr/bin/env python3
"""Fail closed when coverage path aliases merge trusted installs incorrectly."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".coveragerc"
CANONICAL_FILE = ROOT / "src" / "aoi_orgware" / "__init__.py"
TEMP_ROOT_ENV = "AOI_COVERAGE_TEMP_ROOT"
COVERAGE_FILE_ENV = "COVERAGE_FILE"
MAX_FRAGMENT_FILES = 4096
MAX_FRAGMENT_BYTES = 64 * 1024 * 1024
MAX_MEASURED_FILES = 4096
MAX_SOURCE_BYTES = 4 * 1024 * 1024
_PYTEST_OWNER = re.compile(r"^pytest-of-[A-Za-z0-9._-]+$")


class CoveragePathMappingError(RuntimeError):
    """The configured aliases did not preserve the trusted measurement boundary."""


def _write_data(
    coverage_data_type: type[Any],
    path: Path,
    measured_file: str,
    lines: set[int],
) -> None:
    data = coverage_data_type(basename=str(path))
    data.add_lines({measured_file: lines})
    data.write()


def _required_temp_root() -> Path:
    raw = os.environ.get(TEMP_ROOT_ENV)
    if not raw:
        raise CoveragePathMappingError(
            f"{TEMP_ROOT_ENV} must name the workflow-owned pytest temp root"
        )
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise CoveragePathMappingError(f"{TEMP_ROOT_ENV} must be absolute")
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        raise CoveragePathMappingError(
            f"{TEMP_ROOT_ENV} does not resolve to an existing directory"
        ) from exc
    if not root.is_dir():
        raise CoveragePathMappingError(f"{TEMP_ROOT_ENV} is not a directory")
    return root


def _parts(raw: str, *, label: str) -> tuple[str, ...]:
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or raw == "/"
        or "\\" in raw
        or "\x00" in raw
    ):
        raise CoveragePathMappingError(f"{label} is not an absolute POSIX path")
    parts = tuple(raw.split("/")[1:])
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CoveragePathMappingError(f"{label} is not lexically canonical")
    return parts


def _classify_posix_measured_path(
    raw: str,
    *,
    repo_root: str,
    temp_root: str,
) -> tuple[str, tuple[str, ...]]:
    measured = _parts(raw, label="measured coverage path")
    repository = _parts(repo_root, label="repository root")
    temporary = _parts(temp_root, label="coverage temp root")
    source_prefix = (*repository, "src", "aoi_orgware")
    if measured[: len(source_prefix)] == source_prefix:
        relative = measured[len(source_prefix) :]
        category = "canonical"
    elif measured[: len(temporary)] == temporary:
        suffix = measured[len(temporary) :]
        if not suffix or not _PYTEST_OWNER.fullmatch(suffix[0]):
            raise CoveragePathMappingError(
                "coverage temp path has an invalid pytest owner segment"
            )
        checkout = (
            suffix[0],
            "pytest-0",
            "test_standalone_gate_runs_from0",
            "checkout",
            "src",
            "aoi_orgware",
        )
        system_site = (
            suffix[0],
            "pytest-0",
            "test_real_system_site_packages0",
            "system-site",
            "lib",
            "python3.13",
            "site-packages",
            "aoi_orgware",
        )
        if suffix[: len(checkout)] == checkout:
            relative = suffix[len(checkout) :]
            category = "checkout"
        elif suffix[: len(system_site)] == system_site:
            relative = suffix[len(system_site) :]
            category = "system_site"
        else:
            raise CoveragePathMappingError(
                "coverage temp path is outside the two exact pytest layouts"
            )
    else:
        raise CoveragePathMappingError(
            "measured coverage path is outside the repository and temp roots"
        )
    if not relative or not relative[-1].endswith(".py"):
        raise CoveragePathMappingError(
            "measured coverage path does not name a Python source file"
        )
    return category, relative


def _verify_raw_path_contract() -> None:
    repo_root = "/work/aoi"
    temp_root = "/runner-temp/aoi-coverage-tests"
    owner = f"{temp_root}/pytest-of-runner/pytest-0"
    trusted = {
        f"{repo_root}/src/aoi_orgware/__init__.py": "canonical",
        (
            f"{owner}/test_standalone_gate_runs_from0/checkout/"
            "src/aoi_orgware/__init__.py"
        ): "checkout",
        (
            f"{owner}/test_real_system_site_packages0/system-site/lib/"
            "python3.13/site-packages/aoi_orgware/__init__.py"
        ): "system_site",
    }
    for measured, expected in trusted.items():
        category, relative = _classify_posix_measured_path(
            measured,
            repo_root=repo_root,
            temp_root=temp_root,
        )
        if category != expected or relative != ("__init__.py",):
            raise CoveragePathMappingError(
                "raw measured path classification changed unexpectedly"
            )
    decoys = (
        "/WORK/aoi/src/aoi_orgware/__init__.py",
        "/RUNNER-TEMP/aoi-coverage-tests/pytest-of-runner/pytest-0/"
        "test_standalone_gate_runs_from0/checkout/src/aoi_orgware/__init__.py",
        f"{temp_root}/pytest-of-runner/PYTEST-0/"
        "test_standalone_gate_runs_from0/checkout/src/aoi_orgware/__init__.py",
        f"{owner}/TEST_STANDALONE_GATE_RUNS_FROM0/"
        "checkout/src/aoi_orgware/__init__.py",
        f"{owner}/test_real_system_site_packages0/system-site/lib/"
        "PYTHON3.13/site-packages/aoi_orgware/__init__.py",
        f"{owner}/test_standalone_gate_runs_from0/checkout/src/"
        "aoi_orgware/../aoi_orgware/__init__.py",
        f"{temp_root}/pytest-of-runner/pytest-9/"
        "test_standalone_gate_runs_from0/checkout/src/aoi_orgware/__init__.py",
        f"{owner}/test_real_system_site_packages0/system-site/lib/"
        "python9.99/site-packages/aoi_orgware/__init__.py",
    )
    for measured in decoys:
        try:
            _classify_posix_measured_path(
                measured,
                repo_root=repo_root,
                temp_root=temp_root,
            )
        except CoveragePathMappingError:
            continue
        raise CoveragePathMappingError(
            "raw measured path classifier accepted a case or lexical decoy"
        )


def _source_digest(path: Path) -> bytes:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_size > MAX_SOURCE_BYTES
    ):
        raise CoveragePathMappingError(
            "measured coverage source is not a bounded regular file"
        )
    with path.open("rb") as handle:
        content = handle.read(MAX_SOURCE_BYTES + 1)
    after = os.lstat(path)
    if (
        len(content) != before.st_size
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise CoveragePathMappingError(
            "measured coverage source changed during verification"
        )
    return sha256(content).digest()


def _verify_fragment_source(
    raw: str,
    *,
    repo_root: Path,
    temp_root: Path,
) -> tuple[str, str]:
    repo_text = repo_root.as_posix()
    temp_text = temp_root.as_posix()
    category, relative = _classify_posix_measured_path(
        raw,
        repo_root=repo_text,
        temp_root=temp_text,
    )
    measured = Path(raw)
    try:
        resolved = measured.resolve(strict=True)
    except OSError as exc:
        raise CoveragePathMappingError(
            "measured coverage source no longer exists"
        ) from exc
    if resolved.as_posix() != raw:
        raise CoveragePathMappingError(
            "measured coverage source is not a canonical no-symlink path"
        )
    canonical = repo_root / "src" / "aoi_orgware"
    for part in relative:
        canonical /= part
    try:
        canonical_resolved = canonical.resolve(strict=True)
    except OSError as exc:
        raise CoveragePathMappingError(
            "measured coverage source has no canonical repository peer"
        ) from exc
    if _source_digest(resolved) != _source_digest(canonical_resolved):
        raise CoveragePathMappingError(
            "measured coverage source bytes differ from the repository source"
        )
    return category, canonical_resolved.as_posix()


def verify_fragments(
    fragment_directory: Path,
) -> tuple[
    tuple[Path, ...],
    dict[str, str],
    dict[Path, tuple[int, int, int]],
]:
    """Reject untrusted raw coverage paths before coverage.py aliases combine."""

    if os.name != "posix":
        raise CoveragePathMappingError(
            "raw coverage fragment verification is supported only by the Ubuntu job"
        )
    temp_root = _required_temp_root()
    repo_root = ROOT.resolve(strict=True)
    expected_directory = repo_root / "covdata"
    try:
        fragments_root = fragment_directory.resolve(strict=True)
    except OSError as exc:
        raise CoveragePathMappingError(
            "coverage fragment directory does not exist"
        ) from exc
    if fragments_root != expected_directory or not fragments_root.is_dir():
        raise CoveragePathMappingError(
            "coverage fragments are outside the exact workflow directory"
        )
    expected_data_file = expected_directory / ".coverage"
    if os.environ.get(COVERAGE_FILE_ENV) != expected_data_file.as_posix():
        raise CoveragePathMappingError(
            "COVERAGE_FILE differs from the exact combine destination"
        )
    try:
        from coverage import CoverageData
    except ImportError as exc:
        raise CoveragePathMappingError(
            "coverage is required before verifying coverage fragments"
        ) from exc

    children = sorted(
        fragments_root.iterdir(),
        key=lambda path: path.name.encode("utf-8"),
    )
    if not 1 <= len(children) <= MAX_FRAGMENT_FILES:
        raise CoveragePathMappingError("coverage fragment count is outside the bound")
    seen: set[str] = set()
    categories: set[str] = set()
    mapped_paths: dict[str, str] = {}
    identities: dict[Path, tuple[int, int, int]] = {}
    for fragment in children:
        before = os.lstat(fragment)
        if (
            not fragment.name.startswith(".coverage.")
            or not stat.S_ISREG(before.st_mode)
            or fragment.is_symlink()
            or before.st_size > MAX_FRAGMENT_BYTES
        ):
            raise CoveragePathMappingError(
                "coverage directory contains an unexpected fragment"
            )
        data = CoverageData(basename=str(fragment))
        data.read()
        for measured in data.measured_files():
            if measured in seen:
                continue
            seen.add(measured)
            if len(seen) > MAX_MEASURED_FILES:
                raise CoveragePathMappingError(
                    "unique measured coverage path count exceeds the bound"
                )
            category, canonical = _verify_fragment_source(
                measured,
                repo_root=repo_root,
                temp_root=temp_root,
            )
            categories.add(category)
            mapped_paths[measured] = canonical
        after = os.lstat(fragment)
        if (
            before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise CoveragePathMappingError(
                "coverage fragment changed during verification"
            )
        identities[fragment] = (after.st_ino, after.st_size, after.st_mtime_ns)
    if categories != {"canonical", "checkout", "system_site"}:
        raise CoveragePathMappingError(
            "coverage fragments do not contain all three required source roots"
        )
    return tuple(children), mapped_paths, identities


def combine_fragments(fragment_directory: Path) -> None:
    """Combine only the exact fragment snapshot that passed raw-path verification."""

    fragments, mapped_paths, identities = verify_fragments(fragment_directory)
    expected_data_file = ROOT.resolve(strict=True) / "covdata" / ".coverage"
    if expected_data_file.exists():
        raise CoveragePathMappingError(
            "combined coverage destination already exists"
        )
    try:
        from coverage import CoverageData
    except ImportError as exc:
        raise CoveragePathMappingError(
            "coverage is required before combining coverage fragments"
        ) from exc

    destination = CoverageData(basename=str(expected_data_file))

    def exact_map(raw: str) -> str:
        try:
            return mapped_paths[raw]
        except KeyError as exc:
            raise CoveragePathMappingError(
                "coverage fragment introduced an unverified measured path"
            ) from exc

    for fragment in fragments:
        source = CoverageData(basename=str(fragment))
        destination.update(source, map_path=exact_map)
        after = os.lstat(fragment)
        if (after.st_ino, after.st_size, after.st_mtime_ns) != identities[fragment]:
            raise CoveragePathMappingError(
                "coverage fragment changed during combine"
            )
    destination.write()
    actual_children = set(fragment_directory.resolve(strict=True).iterdir())
    if actual_children != {*fragments, expected_data_file}:
        raise CoveragePathMappingError(
            "coverage fragment set changed during combine"
        )


def verify() -> None:
    """Combine only exact workflow-owned pytest roots and retain shaped decoys."""

    if not CONFIG.is_file():
        raise CoveragePathMappingError(f"coverage configuration is absent: {CONFIG}")
    temp_root = _required_temp_root()
    _verify_raw_path_contract()
    try:
        from coverage import Coverage, CoverageData
    except ImportError as exc:
        raise CoveragePathMappingError(
            "coverage is required before verifying coverage path mapping"
        ) from exc

    canonical = str(CANONICAL_FILE.resolve())
    # AOI-SYNTHETIC-FIXTURE-V1: no path below is a deployment observation.
    pytest_root = temp_root / "pytest-of-runner"
    trusted_samples = (
        (canonical, {11}),
        (
            str(
                pytest_root
                / "pytest-0"
                / "test_standalone_gate_runs_from0"
                / "checkout"
                / "src"
                / "aoi_orgware"
                / "__init__.py"
            ),
            {12},
        ),
        (
            str(
                pytest_root
                / "pytest-0"
                / "test_real_system_site_packages0"
                / "system-site"
                / "lib"
                / "python3.13"
                / "site-packages"
                / "aoi_orgware"
                / "__init__.py"
            ),
            {13},
        ),
    )
    decoy_samples = (
        (
            str(
                temp_root.parent
                / "aoi-coverage-outside"
                / "checkout"
                / "src"
                / "aoi_orgware"
                / "__init__.py"
            ),
            {91},
        ),
        (
            str(
                pytest_root
                / "pytest-0"
                / "test_unrelated0"
                / "checkout"
                / "src"
                / "aoi_orgware"
                / "__init__.py"
            ),
            {92},
        ),
        (
            str(
                pytest_root
                / "pytest-9"
                / "test_standalone_gate_runs_from0"
                / "checkout"
                / "src"
                / "aoi_orgware"
                / "__init__.py"
            ),
            {93},
        ),
        (
            str(
                pytest_root
                / "pytest-0"
                / "test_real_system_site_packages0"
                / "system-site"
                / "lib"
                / "python9.99"
                / "site-packages"
                / "aoi_orgware"
                / "__init__.py"
            ),
            {94},
        ),
    )
    with TemporaryDirectory(prefix="aoi-coverage-path-") as temporary:
        temporary_path = Path(temporary)
        fragments = temporary_path / "fragments"
        fragments.mkdir()
        for index, (measured_file, lines) in enumerate(trusted_samples, start=1):
            _write_data(
                CoverageData,
                fragments / f".coverage.trusted-{index}",
                measured_file,
                lines,
            )
        for index, (measured_file, lines) in enumerate(decoy_samples, start=1):
            _write_data(
                CoverageData,
                fragments / f".coverage.decoy-{index}",
                measured_file,
                lines,
            )

        combined = Coverage(
            config_file=str(CONFIG),
            data_file=str(temporary_path / ".coverage"),
        )
        combined.combine(data_paths=[str(fragments)], strict=True)
        data = combined.get_data()
        measured_files = set(data.measured_files())

        if canonical not in measured_files:
            raise CoveragePathMappingError(
                "trusted coverage aliases did not produce the canonical measured file"
            )
        if set(data.lines(canonical) or ()) != {11, 12, 13}:
            raise CoveragePathMappingError(
                "trusted coverage aliases did not preserve the exact line union"
            )
        observed_decoys = {
            frozenset(data.lines(measured_file) or ())
            for measured_file in measured_files
            if measured_file != canonical
        }
        expected_decoys = {frozenset(lines) for _, lines in decoy_samples}
        if (
            len(measured_files) != 1 + len(decoy_samples)
            or observed_decoys != expected_decoys
        ):
            raise CoveragePathMappingError(
                "a shaped decoy was merged, lost, or combined with another decoy"
            )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="verify AOI coverage path mapping and raw fragments",
    )
    parser.add_argument(
        "--combine-fragments",
        type=Path,
        help="validate and combine one raw parallel coverage fragment directory",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.combine_fragments is None:
            verify()
        else:
            combine_fragments(arguments.combine_fragments)
    except CoveragePathMappingError as exc:
        print(f"coverage path mapping verification failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"coverage path mapping verification failed unexpectedly: {exc}",
            file=sys.stderr,
        )
        return 1
    print(
        "coverage fragments verified and combined"
        if arguments.combine_fragments is not None
        else "coverage path mapping verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
