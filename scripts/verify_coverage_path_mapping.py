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

_SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from scripts.coverage_fragment_quiescence import (  # noqa: E402
    MAX_COMBINE_ATTEMPTS,
    CoverageFragmentReadError,
    CoveragePathMappingError,
    FragmentIdentity,
    _assert_fragment_snapshot,
    _fragment_identity,
    _FragmentSetChanged,
    _read_stable_fragment_set,
    _snapshot_fragments,
    _validate_coverage_fragment_schema,
)


ROOT = _SCRIPT_ROOT
CONFIG = ROOT / ".coveragerc"
CANONICAL_FILE = ROOT / "src" / "aoi_orgware" / "__init__.py"
TEMP_ROOT_ENV = "AOI_COVERAGE_TEMP_ROOT"
COVERAGE_FILE_ENV = "COVERAGE_FILE"
MAX_MEASURED_FILES = 4096
MAX_SOURCE_BYTES = 4 * 1024 * 1024
_PYTEST_OWNER = re.compile(r"^pytest-of-[A-Za-z0-9._-]+$")


def _close_fragment_data(data: Any) -> None:
    try:
        data.close()
    except MemoryError:
        raise
    except Exception:
        raise CoverageFragmentReadError("coverage_data_close") from None


def _read_fragment_measured_files(
    fragment: Path,
    coverage_data_type: type[Any],
) -> tuple[str, ...]:
    """Classify coverage.py reads without exposing raw fragment or exception text."""

    try:
        _validate_coverage_fragment_schema(fragment)
    except CoveragePathMappingError:
        raise CoverageFragmentReadError("schema_preflight") from None
    try:
        data = coverage_data_type(basename=str(fragment))
    except MemoryError:
        raise
    except Exception:
        raise CoverageFragmentReadError("coverage_data_read") from None
    try:
        data.read()
    except MemoryError:
        raise
    except Exception:
        _close_fragment_data(data)
        raise CoverageFragmentReadError("coverage_data_read") from None
    try:
        measured = tuple(data.measured_files())
    except MemoryError:
        raise
    except Exception:
        _close_fragment_data(data)
        raise CoverageFragmentReadError("measured_files") from None
    _close_fragment_data(data)
    return measured


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
    dict[Path, FragmentIdentity],
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

    children, measured_by_fragment, identities = _read_stable_fragment_set(
        fragments_root,
        lambda fragment: _read_fragment_measured_files(fragment, CoverageData),
    )
    seen: set[str] = set()
    categories: set[str] = set()
    mapped_paths: dict[str, str] = {}
    for fragment in children:
        for measured in measured_by_fragment[fragment]:
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
    _assert_fragment_snapshot(fragments_root, identities)
    if categories != {"canonical", "checkout", "system_site"}:
        raise CoveragePathMappingError(
            "coverage fragments do not contain all three required source roots"
        )
    return tuple(children), mapped_paths, identities


def _combine_fragment_attempt(fragment_directory: Path) -> None:
    fragments, mapped_paths, identities = verify_fragments(fragment_directory)
    fragments_root = fragment_directory.resolve(strict=True)
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

    def exact_map(raw: str) -> str:
        try:
            return mapped_paths[raw]
        except KeyError as exc:
            raise CoveragePathMappingError(
                "coverage fragment introduced an unverified measured path"
            ) from exc

    with TemporaryDirectory(prefix=".aoi-coverage-combine-", dir=ROOT) as temporary:
        staged_data_file = Path(temporary) / ".coverage"
        destination = CoverageData(basename=str(staged_data_file))
        for fragment in fragments:
            if _fragment_identity(fragment) != identities[fragment]:
                raise _FragmentSetChanged("coverage fragment identity changed")
            source = CoverageData(basename=str(fragment))
            try:
                destination.update(source, map_path=exact_map)
            except Exception as exc:
                if _fragment_identity(fragment) != identities[fragment]:
                    raise _FragmentSetChanged(
                        "coverage fragment identity changed during combine"
                    ) from exc
                _assert_fragment_snapshot(fragments_root, identities)
                raise CoveragePathMappingError(
                    "coverage fragment is stably unreadable or invalid during combine"
                ) from exc
            if _fragment_identity(fragment) != identities[fragment]:
                raise _FragmentSetChanged("coverage fragment identity changed")
        _assert_fragment_snapshot(fragments_root, identities)
        destination.write()
        destination.close()
        staged_identity = _fragment_identity(staged_data_file)
        if staged_identity.file_type != stat.S_IFREG or staged_identity.size == 0:
            raise CoveragePathMappingError("combined coverage output is invalid")
        _assert_fragment_snapshot(fragments_root, identities)
        try:
            os.link(staged_data_file, expected_data_file, follow_symlinks=False)
        except FileExistsError as exc:
            raise _FragmentSetChanged(
                "coverage combine destination appeared during publication"
            ) from exc
        except OSError as exc:
            raise CoveragePathMappingError(
                "combined coverage output could not be published"
            ) from exc
        expected = {**identities, expected_data_file: staged_identity}
        try:
            _assert_fragment_snapshot(fragments_root, expected)
        except _FragmentSetChanged:
            if _fragment_identity(expected_data_file) != staged_identity:
                raise CoveragePathMappingError(
                    "combined coverage output identity changed before rollback"
                )
            try:
                expected_data_file.unlink()
            except OSError as exc:
                raise CoveragePathMappingError(
                    "combined coverage output rollback failed"
                ) from exc
            raise


def combine_fragments(fragment_directory: Path) -> None:
    """Combine an exact raw snapshot with bounded retry on cooperative churn."""

    last_change: _FragmentSetChanged | None = None
    for _ in range(MAX_COMBINE_ATTEMPTS):
        try:
            _combine_fragment_attempt(fragment_directory)
            return
        except _FragmentSetChanged as exc:
            last_change = exc
    assert last_change is not None
    raise CoveragePathMappingError(
        "coverage fragments changed during every bounded combine attempt: "
        f"{last_change}"
    ) from last_change


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
