"""Real interpreter, venv, executable-pth, and fork coverage integration."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.coverage_bootstrap_install as bootstrap_install
import scripts.coverage_fragment_attribution as attribution
import scripts.coverage_fork_runtime as fork_runtime
from scripts.verify_coverage_path_mapping import _validate_coverage_fragment_schema


ROOT = Path(__file__).resolve().parents[1]


def _process_records(metadata: Path) -> dict[str, dict[str, object]]:
    return {
        path.stem: json.loads(path.read_text("ascii"))
        for path in sorted((metadata / "processes").glob("*.json"))
    }


def _run_real_probe(
    tmp_path: Path,
    source: str,
) -> tuple[Path, Path, subprocess.CompletedProcess[str]]:
    coverage = pytest.importorskip("coverage")
    if coverage.__version__ != attribution.EXPECTED_COVERAGE_VERSION:
        pytest.skip("the exact qualified coverage runtime is unavailable")
    import venv

    startup = tmp_path / "startup"
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    receipts = tmp_path / "receipts"
    for directory in (startup, fragments, metadata, receipts):
        directory.mkdir()
    for source_name, target_name in (
        ("coverage_fork_runtime.py", "aoi_coverage_fork_runtime.py"),
        ("coverage_fragment_attribution.py", "aoi_coverage_fragment_attribution.py"),
        ("coverage_sitecustomize.py", "aoi_coverage_bootstrap.py"),
    ):
        shutil.copyfile(ROOT / "scripts" / source_name, startup / target_name)

    prefix = tmp_path / "fork-runtime"
    venv.EnvBuilder(with_pip=False).create(prefix)
    executable = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site_root = Path(
        subprocess.run(
            [str(executable), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    receipt = receipts / "bootstrap.json"
    bootstrap_install.install(
        site_root=str(site_root),
        startup_root=str(startup),
        receipt_path=str(receipt),
        dependency_roots=[str(Path(coverage.__file__).resolve().parent.parent)],
    )
    try:
        config = tmp_path / ".coveragerc"
        config.write_text("[run]\nparallel = true\n", encoding="utf-8")
        probe = tmp_path / "probe.py"
        probe.write_text(textwrap.dedent(source), encoding="utf-8")
        child_env = dict(os.environ)
        # This is a new, receipt-bound collection scope.  The parent process
        # keeps its selectors; only child-local producer/vendor selectors are
        # reset before the child bootstrap installs its own exact values below.
        for name in fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS:
            child_env.pop(name, None)
        base = fragments / ".coverage"
        child_env.update(
            {
                "COVERAGE_FILE": str(base),
                attribution.COVERAGE_CONFIG_ENV: str(config),
                fork_runtime.RUNTIME_PREFIX_ENV: str(prefix.resolve()),
                attribution.COVERAGE_FILE_BASE_ENV: str(base),
                attribution.METADATA_ROOT_ENV: str(metadata),
            }
        )
        completed = subprocess.run(
            [str(executable), "-I", str(probe)],
            cwd=ROOT,
            env=child_env,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return fragments, metadata, completed
    finally:
        bootstrap_install.remove(receipt_path=str(receipt))
        assert not (site_root / bootstrap_install.PTH_NAME).exists()


def test_real_probe_removes_receipt_bound_pth_when_config_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coverage = pytest.importorskip("coverage")
    if coverage.__version__ != attribution.EXPECTED_COVERAGE_VERSION:
        pytest.skip("the exact qualified coverage runtime is unavailable")
    config = tmp_path / ".coveragerc"
    original_write_text = Path.write_text
    removed: list[str] = []
    original_remove = bootstrap_install.remove

    def fail_config_write(path: Path, *args: object, **kwargs: object) -> int:
        if path == config:
            raise OSError("injected config write failure")
        return original_write_text(path, *args, **kwargs)

    def record_receipt_removal(*, receipt_path: object) -> None:
        removed.append(str(receipt_path))
        original_remove(receipt_path=receipt_path)

    monkeypatch.setattr(Path, "write_text", fail_config_write)
    monkeypatch.setattr(bootstrap_install, "remove", record_receipt_removal)
    with pytest.raises(OSError, match="injected config write failure"):
        _run_real_probe(tmp_path, "print('unreachable')")

    prefix = tmp_path / "fork-runtime"
    executable = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site_root = Path(
        subprocess.run(
            [str(executable), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    receipt = tmp_path / "receipts" / "bootstrap.json"
    assert removed == [str(receipt)]
    assert not (site_root / bootstrap_install.PTH_NAME).exists()
    assert bootstrap_install._load_receipt(str(receipt))["target_path"] == str(
        site_root / bootstrap_install.PTH_NAME
    )


@pytest.mark.parametrize(
    ("config", "runtime_prefix", "samefile_error"),
    (
        ("config", "current", False),
        ("", "current", False),
        ("config", None, False),
        ("config", "relative", False),
        ("config", "current", True),
    ),
    ids=(
        "bound-import-failure",
        "bound-empty-config",
        "missing-prefix",
        "malformed-prefix",
        "samefile-error",
    ),
)
def test_sitecustomize_bound_or_invalid_startup_exits_without_measurement(
    tmp_path: Path,
    config: str,
    runtime_prefix: str | None,
    samefile_error: bool,
) -> None:
    site = tmp_path / "site"
    fragments = tmp_path / "covdata"
    site.mkdir()
    fragments.mkdir()
    shutil.copyfile(
        ROOT / "scripts" / "coverage_fork_runtime.py",
        site / "aoi_coverage_fork_runtime.py",
    )
    shutil.copyfile(
        ROOT / "scripts" / "coverage_sitecustomize.py",
        site / "sitecustomize.py",
    )
    if samefile_error:
        startup = site / "sitecustomize.py"
        startup.write_text(
            startup.read_text(encoding="utf-8").replace(
                "return os.path.samefile(configured, runtime_prefix)",
                "raise OSError('synthetic samefile failure')",
                1,
            ),
            encoding="utf-8",
        )
    child_env = dict(os.environ)
    for name in (
        "AOI_COVERAGE_CURRENT_PRODUCER_ID",
        "COVERAGE_PROCESS_CONFIG",
        "COVERAGE_PROCESS_START",
    ):
        child_env.pop(name, None)
    child_env.update(
        {
            "AOI_COVERAGE_PROCESS_START": (
                str(tmp_path / ".coveragerc") if config else config
            ),
            "COVERAGE_FILE": str(fragments / ".coverage"),
            "PYTHONPATH": str(site),
        }
    )
    if runtime_prefix is not None:
        child_env[fork_runtime.RUNTIME_PREFIX_ENV] = (
            str(Path(sys.prefix).resolve())
            if runtime_prefix == "current"
            else runtime_prefix
        )
    completed = subprocess.run(
        [sys.executable, "-c", "value = 1"],
        cwd=tmp_path,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 97
    assert completed.stderr == ""
    assert tuple(fragments.iterdir()) == ()


def test_sitecustomize_partial_private_aoi_state_exits_fail_closed(
    tmp_path: Path,
) -> None:
    site = tmp_path / "site"
    fragments = tmp_path / "covdata"
    site.mkdir()
    fragments.mkdir()
    shutil.copyfile(
        ROOT / "scripts" / "coverage_sitecustomize.py",
        site / "sitecustomize.py",
    )
    child_env = dict(os.environ)
    for name in fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS:
        child_env.pop(name, None)
    child_env.update(
        {
            attribution.COVERAGE_FILE_BASE_ENV: str(fragments / ".coverage"),
            "PYTHONPATH": str(site),
        }
    )
    completed = subprocess.run(
        [sys.executable, "-c", "value = 1"],
        cwd=tmp_path,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 97
    assert completed.stderr == ""
    assert tuple(fragments.iterdir()) == ()


def test_sitecustomize_mismatch_cleanup_failure_exits_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS:
        monkeypatch.delenv(name, raising=False)
    namespace = runpy.run_path(str(ROOT / "scripts" / "coverage_sitecustomize.py"))

    class FailingPop(dict[str, str]):
        def pop(self, key: str, default: object = None) -> str | object:
            if key == "COVERAGE_FILE":
                raise RuntimeError("synthetic cleanup failure")
            return super().pop(key, default)

    environ = FailingPop({"COVERAGE_FILE": "inherited"})
    exits: list[int] = []
    clear = namespace["_clear_out_of_scope_selectors"]
    clear.__globals__["os"] = SimpleNamespace(environ=environ, _exit=exits.append)
    clear()
    assert exits == [97]
    assert "COVERAGE_FILE" in environ


def test_isolated_runtime_without_private_bootstrap_does_not_start_coverage(
    tmp_path: Path,
) -> None:
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    fragments.mkdir()
    metadata.mkdir()
    nested = tmp_path / "nested"
    import venv

    venv.EnvBuilder(with_pip=False).create(nested)
    executable = nested / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    names = fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS
    descendant = (
        "import importlib.util, json, os, sys; "
        "assert 'aoi_coverage_bootstrap' not in sys.modules; "
        "assert importlib.util.find_spec('aoi_coverage_bootstrap') is None; "
        f"print(json.dumps({{name: name in os.environ for name in {names!r}}}))"
    )
    code = (
        "import importlib.util, json, os, subprocess, sys; "
        f"names={names!r}; "
        "assert 'coverage' not in sys.modules and 'aoi_coverage_bootstrap' not in sys.modules; "
        "assert importlib.util.find_spec('aoi_coverage_bootstrap') is None; "
        "assert all(name in os.environ for name in names); "
        f"child=subprocess.run([sys.executable, '-c', {descendant!r}], "
        "check=True, capture_output=True, text=True); "
        "assert all(json.loads(child.stdout).values())"
    )
    child_env = dict(os.environ)
    child_env.update(
        {
            attribution.CURRENT_PRODUCER_ENV: "a" * 64,
            "AOI_COVERAGE_PROCESS_START": str(tmp_path / ".coveragerc"),
            attribution.COVERAGE_CONFIG_ENV: str(tmp_path / ".coveragerc"),
            fork_runtime.RUNTIME_PREFIX_ENV: str(Path(sys.prefix).resolve()),
            attribution.COVERAGE_FILE_BASE_ENV: str(fragments / ".coverage"),
            attribution.METADATA_ROOT_ENV: str(metadata),
            attribution.PYTEST_FAMILY_TOKEN_ENV: "b" * 64,
            "COVERAGE_FILE": str(fragments / ".coverage"),
            "COVERAGE_PROCESS_CONFIG": "serialized-config",
            "COVERAGE_PROCESS_START": "vendor-config",
            "PYTHONPATH": str(ROOT / "src"),
        }
    )
    completed = subprocess.run(
        [str(executable), "-c", code],
        cwd=ROOT,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert tuple(fragments.iterdir()) == ()
    assert tuple(metadata.iterdir()) == ()


def test_executable_pth_starts_exact_unique_module_under_isolated_mode(
    tmp_path: Path,
) -> None:
    coverage = pytest.importorskip("coverage")
    if coverage.__version__ != attribution.EXPECTED_COVERAGE_VERSION:
        pytest.skip("the exact qualified coverage runtime is unavailable")
    import venv

    startup = tmp_path / "startup"
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    receipts = tmp_path / "receipts"
    for directory in (startup, fragments, metadata, receipts):
        directory.mkdir()
    for source_name, target_name in (
        ("coverage_fork_runtime.py", "aoi_coverage_fork_runtime.py"),
        ("coverage_fragment_attribution.py", "aoi_coverage_fragment_attribution.py"),
        ("coverage_sitecustomize.py", "aoi_coverage_bootstrap.py"),
    ):
        shutil.copyfile(ROOT / "scripts" / source_name, startup / target_name)

    prefix = tmp_path / "main-runtime"
    venv.EnvBuilder(with_pip=False).create(prefix)
    executable = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site_root = Path(
        subprocess.run(
            [str(executable), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    dependency_root = Path(coverage.__file__).resolve().parent.parent
    receipt = receipts / "bootstrap.json"
    bootstrap_install.install(
        site_root=str(site_root),
        startup_root=str(startup),
        receipt_path=str(receipt),
        dependency_roots=[str(dependency_root)],
    )
    config = tmp_path / ".coveragerc"
    config.write_text("[run]\nparallel = true\n", encoding="utf-8")
    base = fragments / ".coverage"
    child_env = dict(os.environ)
    for name in fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS:
        child_env.pop(name, None)
    child_env.update(
        {
            attribution.COVERAGE_CONFIG_ENV: str(config),
            fork_runtime.RUNTIME_PREFIX_ENV: str(prefix.resolve()),
            attribution.COVERAGE_FILE_BASE_ENV: str(base),
            attribution.METADATA_ROOT_ENV: str(metadata),
            "COVERAGE_FILE": str(base),
            "PYTHONPATH": str(tmp_path / "ignored-by-isolated-mode"),
        }
    )
    probe = (
        "import json, pathlib, sys; "
        "import aoi_coverage_bootstrap, aoi_coverage_fork_runtime, "
        "aoi_coverage_fragment_attribution, coverage; "
        "mods=(aoi_coverage_bootstrap, aoi_coverage_fork_runtime, "
        "aoi_coverage_fragment_attribution); "
        "print(json.dumps({'origins':[str(pathlib.Path(m.__file__).resolve()) for m in mods], "
        "'active': coverage.Coverage.current() is not None, "
        "'ignored_pythonpath': sys.path.count(str(pathlib.Path(sys.argv[1]).resolve())) == 0}))"
    )
    try:
        completed = subprocess.run(
            [str(executable), "-I", "-c", probe, child_env["PYTHONPATH"]],
            cwd=tmp_path,
            env=child_env,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        observed = json.loads(completed.stdout)
        assert observed == {
            "active": True,
            "ignored_pythonpath": True,
            "origins": [
                str((startup / "aoi_coverage_bootstrap.py").resolve()),
                str((startup / "aoi_coverage_fork_runtime.py").resolve()),
                str((startup / "aoi_coverage_fragment_attribution.py").resolve()),
            ],
        }
        assert tuple(fragments.glob(".coverage.aoi2.*"))
        assert tuple((metadata / "processes").glob("*.json"))
    finally:
        bootstrap_install.remove(receipt_path=str(receipt))
    assert not (site_root / bootstrap_install.PTH_NAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="raw fork is POSIX-only")
def test_real_fork_and_fork_of_fork_have_three_collectors(
    tmp_path: Path,
) -> None:
    fragments, metadata, completed = _run_real_probe(
        tmp_path,
        """
        import os

        def measured(value):
            return value + 1

        child = os.fork()
        if child == 0:
            grandchild = os.fork()
            if grandchild == 0:
                measured(3)
                os._exit(0)
            os.waitpid(grandchild, 0)
            measured(2)
            os._exit(0)
        os.waitpid(child, 0)
        measured(1)
        """,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    records = _process_records(metadata)
    assert len(records) == 3
    root = next(key for key, value in records.items() if value["parent_producer_id"] is None)
    child = next(key for key, value in records.items() if value["parent_producer_id"] == root)
    grandchild = next(
        key for key, value in records.items() if value["parent_producer_id"] == child
    )
    assert records[child]["attribution_scope"] == "fork_child"
    assert records[grandchild]["attribution_scope"] == "fork_child"
    shards = tuple(sorted(fragments.glob(".coverage.*")))
    producers = {
        match.group("producer")
        for shard in shards
        if (match := attribution._FRAGMENT_RE.match(shard.name)) is not None
    }
    assert len(shards) == 3 and producers == set(records)
    for shard in shards:
        _validate_coverage_fragment_schema(shard)


@pytest.mark.skipif(os.name != "posix", reason="raw fork is POSIX-only")
def test_real_fresh_subprocess_and_fork_exec_preserve_lineage(
    tmp_path: Path,
) -> None:
    fragments, metadata, completed = _run_real_probe(
        tmp_path,
        """
        import os
        import subprocess
        import sys

        subprocess.run([sys.executable, "-c", "value = 1"], check=True)
        child = os.fork()
        if child == 0:
            os.execv(sys.executable, [sys.executable, "-c", "value = 2"])
        _, status = os.waitpid(child, 0)
        if status != 0:
            raise SystemExit(5)
        """,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    records = _process_records(metadata)
    assert len(records) == 4
    root = next(key for key, value in records.items() if value["parent_producer_id"] is None)
    children = {
        key: value
        for key, value in records.items()
        if value["parent_producer_id"] == root
    }
    assert {value["attribution_scope"] for value in children.values()} == {
        "fork_child",
        "fresh_interpreter",
    }
    fork_child = next(
        key for key, value in children.items() if value["attribution_scope"] == "fork_child"
    )
    assert any(
        value["parent_producer_id"] == fork_child
        and value["attribution_scope"] == "fresh_interpreter"
        for value in records.values()
    )
    shards = tuple(sorted(fragments.glob(".coverage.*")))
    producers = {
        match.group("producer")
        for shard in shards
        if (match := attribution._FRAGMENT_RE.match(shard.name)) is not None
    }
    assert len(shards) == 3
    assert fork_child not in producers and producers <= set(records)
    for shard in shards:
        _validate_coverage_fragment_schema(shard)
