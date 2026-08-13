from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import venv

import pytest

from scripts import coverage_bootstrap_install


_COVERAGE_PRIVATE_SELECTORS = (
    "AOI_COVERAGE_CURRENT_PRODUCER_ID",
    "AOI_COVERAGE_PROCESS_START",
    "AOI_COVERAGE_RUNTIME_PREFIX",
    "AOI_COVERAGE_FILE_BASE",
    "AOI_COVERAGE_METADATA_ROOT",
    "AOI_COVERAGE_TEST_FAMILY_TOKEN",
)


def _site_packages(prefix: Path) -> Path:
    if os.name == "nt":
        return prefix / "Lib" / "site-packages"
    return prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"


def _system_site_child_bootstrap(
    tmp_path: Path, prefix: Path
) -> tuple[dict[str, str], Path | None, Path | None]:
    """Return the exact child environment and an owned bootstrap cleanup pair.

    This mirrors the workflow's private coverage mode without changing the
    non-coverage provenance assertion. The child is intentionally bootstrapped
    only when at least one private AOI selector is present.
    """

    environment = os.environ.copy()
    present_selectors = tuple(
        selector for selector in _COVERAGE_PRIVATE_SELECTORS if selector in environment
    )
    if not present_selectors:
        return environment, None, None
    required = {*_COVERAGE_PRIVATE_SELECTORS, "COVERAGE_FILE"}
    missing = sorted(required.difference(environment))
    if missing:
        pytest.fail(f"coverage child bootstrap environment is incomplete: {missing}")

    coverage = importlib.import_module("coverage")
    if getattr(coverage, "__version__", None) != "7.15.2":
        pytest.fail("coverage bootstrap requires coverage 7.15.2")
    coverage_root = Path(coverage.__file__).resolve().parent.parent
    if coverage_root != Path(sysconfig.get_paths()["purelib"]).resolve():
        pytest.fail("coverage module is not from the runtime purelib")
    if (coverage_root / "aoi_orgware").exists() or any(
        coverage_root.glob("aoi_orgware-*.dist-info")
    ):
        pytest.fail("coverage dependency root could shadow aoi_orgware")

    bootstrap = importlib.import_module("aoi_coverage_bootstrap")
    fork_runtime = importlib.import_module("aoi_coverage_fork_runtime")
    attribution = importlib.import_module("aoi_coverage_fragment_attribution")
    origins = {
        Path(module.__file__).resolve().parent
        for module in (bootstrap, fork_runtime, attribution)
    }
    if len(origins) != 1:
        pytest.fail("coverage startup helpers do not share one exact root")
    startup_root = origins.pop()
    site_root = _site_packages(prefix).resolve()
    receipt_dir = tmp_path / "coverage-bootstrap-receipts"
    receipt_dir.mkdir()
    receipt = receipt_dir / "system-site-child.json"
    coverage_bootstrap_install.install(
        site_root=str(site_root),
        startup_root=str(startup_root),
        dependency_roots=[str(coverage_root)],
        receipt_path=str(receipt),
    )
    environment["AOI_COVERAGE_RUNTIME_PREFIX"] = str(prefix.resolve())
    return environment, receipt, site_root / coverage_bootstrap_install.PTH_NAME


def test_real_system_site_packages_venv_is_rejected(tmp_path: Path) -> None:
    """A real venv with inherited base site-packages is never admissible."""

    repository = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--isolated",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            str(repository),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(wheelhouse.glob("aoi_orgware-*.whl"))
    prefix = tmp_path / "system-site"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(prefix)
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    script = """
import sys
import sysconfig
from pathlib import Path
from aoi_orgware import codex_install_provenance as provenance

provenance._require_dedicated_venv(
    Path(sys.prefix), Path(sysconfig.get_paths()['purelib'])
)
"""
    environment, receipt, bootstrap_target = _system_site_child_bootstrap(tmp_path, prefix)
    try:
        completed = subprocess.run(
            [str(python), "-I", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=environment,
        )
    finally:
        if receipt is not None:
            coverage_bootstrap_install.remove(receipt_path=str(receipt))
            assert bootstrap_target is not None
            assert not bootstrap_target.exists()
            assert receipt.exists()
    assert completed.returncode != 0
    assert "must disable system site packages" in completed.stderr


def test_system_site_child_bootstrap_without_private_selectors_is_noncoverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for selector in _COVERAGE_PRIVATE_SELECTORS:
        monkeypatch.delenv(selector, raising=False)
    environment, receipt, target = _system_site_child_bootstrap(
        tmp_path, tmp_path / "child"
    )
    assert receipt is None
    assert target is None
    assert not any(selector in environment for selector in _COVERAGE_PRIVATE_SELECTORS)


@pytest.mark.parametrize("selector", _COVERAGE_PRIVATE_SELECTORS)
def test_system_site_child_bootstrap_rejects_each_partial_private_selector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, selector: str
) -> None:
    for name in (*_COVERAGE_PRIVATE_SELECTORS, "COVERAGE_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(selector, "test-value")

    with pytest.raises(pytest.fail.Exception, match="environment is incomplete"):
        _system_site_child_bootstrap(tmp_path, tmp_path / "child")
