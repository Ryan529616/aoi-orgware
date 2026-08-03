"""Exactly-once coverage startup and fork-attribution boundaries."""

from __future__ import annotations

import json
import os
import runpy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import scripts.coverage_fragment_attribution as attribution
import scripts.coverage_fork_runtime as fork_runtime
from scripts.verify_coverage_path_mapping import _validate_coverage_fragment_schema


ROOT = Path(__file__).resolve().parents[1]


class _FakeCoverageInstance:
    def __init__(self, owner: type[Any]) -> None:
        self.owner = owner
        self._auto_save = True
        self.saved = False
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True
        if self.owner.current_instance is self:
            self.owner.current_instance = None

    def save(self) -> None:
        self.saved = True


def _fake_coverage() -> tuple[Any, list[tuple[bool, str, _FakeCoverageInstance]]]:
    starts: list[tuple[bool, str, _FakeCoverageInstance]] = []

    class FakeCoverage:
        current_instance: _FakeCoverageInstance | None = None

        @classmethod
        def current(cls) -> _FakeCoverageInstance | None:
            return cls.current_instance

    def process_startup(
        *,
        force: bool = False,
        slug: str = "default",
    ) -> _FakeCoverageInstance:
        instance = _FakeCoverageInstance(FakeCoverage)
        FakeCoverage.current_instance = instance
        process_startup.coverage = instance  # type: ignore[attr-defined]
        starts.append((force, slug, instance))
        return instance

    module = SimpleNamespace(
        Coverage=FakeCoverage,
        __version__=attribution.EXPECTED_COVERAGE_VERSION,
        process_startup=process_startup,
    )
    return module, starts


def test_repo_attribution_uses_the_repo_runtime_module() -> None:
    assert attribution._install_fork_callback is fork_runtime.install_fork_callback


def test_runtime_prefix_requires_existing_exact_directory_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    other = tmp_path / "other"
    runtime.mkdir()
    other.mkdir()
    calls: list[tuple[str, str]] = []
    original_samefile = fork_runtime.os.path.samefile

    def tracked_samefile(left: str, right: str) -> bool:
        calls.append((left, right))
        return original_samefile(left, right)

    monkeypatch.setattr(fork_runtime.os.path, "samefile", tracked_samefile)
    environ = {fork_runtime.RUNTIME_PREFIX_ENV: str(runtime)}
    alias = os.path.join(str(runtime), "..", runtime.name)
    assert alias != str(runtime)
    assert fork_runtime.runtime_prefix_matches(alias, environ)
    assert calls == [(alias, str(runtime))]
    environ[fork_runtime.RUNTIME_PREFIX_ENV] = str(other)
    assert not fork_runtime.runtime_prefix_matches(str(runtime), environ)
    invalid_file = tmp_path / "not-a-directory"
    invalid_file.write_text("synthetic", encoding="utf-8")
    for value in (None, "", "relative", "bad\x00prefix", str(invalid_file), str(tmp_path / "missing")):
        environ = {} if value is None else {fork_runtime.RUNTIME_PREFIX_ENV: value}
        with pytest.raises(fork_runtime.CoverageForkRuntimeError, match="prefix"):
            fork_runtime.runtime_prefix_matches(str(runtime), environ)


def test_workflow_pin_and_scoped_bootstrap_match_the_qualified_runtime() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text("utf-8")
    lock = (ROOT / "requirements" / "coverage-tools-linux.lock").read_text("utf-8")
    assert f"coverage=={fork_runtime.EXPECTED_COVERAGE_VERSION}" in lock
    assert "requirements/coverage-tools-linux.lock" in workflow
    assert "--require-hashes" in workflow
    assert "--no-index" in workflow
    startup_root = "${{ runner.temp }}/aoi-coverage-startup"
    assert workflow.count(f"AOI_COVERAGE_STARTUP_ROOT: {startup_root}") == 2
    assert 'test ! -e "$AOI_COVERAGE_STARTUP_ROOT"' in workflow
    assert 'mkdir -m 700 "$AOI_COVERAGE_STARTUP_ROOT"' in workflow
    assert "PYTHONPATH: src" in workflow
    assert f"PYTHONPATH: {startup_root}:src" not in workflow
    assert "id: coverage_bootstrap" in workflow
    assert "runtime_prefix=\"$(python -I -c 'import sys; print(sys.prefix)')\"" in workflow
    assert "AOI_COVERAGE_RUNTIME_PREFIX: ${{ steps.coverage_bootstrap.outputs.runtime_prefix }}" in workflow
    for source, target in (
        ("coverage_fork_runtime.py", "aoi_coverage_fork_runtime.py"),
        ("coverage_fragment_attribution.py", "aoi_coverage_fragment_attribution.py"),
        ("coverage_sitecustomize.py", "aoi_coverage_bootstrap.py"),
    ):
        installed = f'"$AOI_COVERAGE_STARTUP_ROOT/{target}"'
        assert f"cp scripts/{source} {installed}" in workflow
        assert f"cmp -s scripts/{source} {installed}" in workflow
    install = "python scripts/coverage_bootstrap_install.py install"
    verify = "importlib.import_module(name)"
    remove = "python scripts/coverage_bootstrap_install.py remove"
    suite = "python -m pytest tests/ -q --tb=short"
    combine = "python scripts/verify_coverage_path_mapping.py --combine-fragments covdata"
    assert workflow.index(install) < workflow.index(verify) < workflow.index(suite) < workflow.index(remove) < workflow.index(combine)
    runtime_output = (
        "printf 'runtime_prefix=%s\\n' \"$runtime_prefix\" >> \"$GITHUB_OUTPUT\""
    )
    assert workflow.index(runtime_output) < workflow.index(install)
    assert "if: ${{ always() }}" in workflow
    assert (
        'test -e "$AOI_COVERAGE_BOOTSTRAP_RECEIPT" || '
        'test -L "$AOI_COVERAGE_BOOTSTRAP_RECEIPT"'
    ) in workflow
    assert 'test ! -e "$site_root/aoi_coverage_bootstrap.pth"' in workflow


@pytest.mark.parametrize("vendor_name", fork_runtime.VENDOR_START_ENVIRONMENTS)
def test_runtime_rejects_wrong_version_and_vendor_selector(vendor_name: str) -> None:
    module, _ = _fake_coverage()
    module.__version__ = "0.0.0"
    with pytest.raises(fork_runtime.CoverageForkRuntimeError, match="version"):
        fork_runtime.ensure_not_started(module)
    module.__version__ = fork_runtime.EXPECTED_COVERAGE_VERSION
    environ = {
        fork_runtime.COVERAGE_CONFIG_ENV: "config",
        vendor_name: "vendor-config",
    }
    with pytest.raises(fork_runtime.CoverageForkRuntimeError, match="selector"):
        fork_runtime.start_exact_coverage(
            module,
            environ,
            force=False,
            slug="test",
        )


def test_python_hard_exit_flushes_the_exact_active_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, starts = _fake_coverage()
    active = module.process_startup()
    exits: list[int] = []
    environ = {
        fork_runtime.COVERAGE_CONFIG_ENV: "config",
        fork_runtime.CURRENT_PRODUCER_ENV: "a" * 64,
        "COVERAGE_FILE": "fragment",
        "COVERAGE_PROCESS_CONFIG": "serialized",
        "COVERAGE_PROCESS_START": "vendor-config",
    }
    os_module = SimpleNamespace(environ=environ, _exit=exits.append)
    monkeypatch.setattr(fork_runtime, "_HARD_EXIT_INSTALLED", False)

    fork_runtime.install_hard_exit_flush(module, os_module=os_module)
    installed = os_module._exit
    fork_runtime.install_hard_exit_flush(module, os_module=os_module)

    assert os_module._exit is installed
    os_module._exit(7)
    assert exits == [7]
    assert active is starts[0][2]
    assert active.stopped and active.saved
    assert module.Coverage.current() is None
    assert environ == {}


def test_python_hard_exit_flush_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _ = _fake_coverage()
    active = module.process_startup()
    exits: list[int] = []
    environ = {
        fork_runtime.COVERAGE_CONFIG_ENV: "config",
        fork_runtime.CURRENT_PRODUCER_ENV: "a" * 64,
        "COVERAGE_FILE": "fragment",
    }
    os_module = SimpleNamespace(environ=environ, _exit=exits.append)
    monkeypatch.setattr(fork_runtime, "_HARD_EXIT_INSTALLED", False)

    def fail_save() -> None:
        raise RuntimeError("synthetic save failure")

    active.save = fail_save
    fork_runtime.install_hard_exit_flush(module, os_module=os_module)
    os_module._exit(5)

    assert exits == [97]
    assert active.stopped and not active.saved
    assert environ == {}


def _bind_root_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    fragments.mkdir()
    metadata.mkdir()
    base = fragments / ".coverage"
    monkeypatch.setenv("COVERAGE_FILE", str(base))
    monkeypatch.setenv(attribution.COVERAGE_CONFIG_ENV, str(tmp_path / ".coveragerc"))
    monkeypatch.setenv(attribution.COVERAGE_FILE_BASE_ENV, str(base))
    monkeypatch.setenv(attribution.METADATA_ROOT_ENV, str(metadata))
    monkeypatch.delenv("COVERAGE_PROCESS_CONFIG", raising=False)
    monkeypatch.delenv("COVERAGE_PROCESS_START", raising=False)
    # Record an undo entry even when the selector was initially absent.  The
    # attribution callback publishes these values later in the test; a bare
    # ``delenv(..., raising=False)`` would otherwise have nothing to restore.
    for name in (
        attribution.CURRENT_PRODUCER_ENV,
        attribution.PYTEST_FAMILY_TOKEN_ENV,
    ):
        monkeypatch.setenv(name, "aoi-test-cleanup-sentinel")
        monkeypatch.delenv(name)
    return fragments, metadata


def test_root_environment_binding_restores_late_selector_publication(
    tmp_path: Path,
) -> None:
    names = (
        attribution.CURRENT_PRODUCER_ENV,
        attribution.PYTEST_FAMILY_TOKEN_ENV,
    )
    original = {name: os.environ.get(name) for name in names}
    patch = pytest.MonkeyPatch()
    try:
        _bind_root_environment(tmp_path, patch)
        for name in names:
            os.environ[name] = "b" * 64
    finally:
        patch.undo()
    assert {name: os.environ.get(name) for name in names} == original


def _process_records(metadata: Path) -> dict[str, dict[str, object]]:
    return {
        path.stem: json.loads(path.read_text("ascii"))
        for path in sorted((metadata / "processes").glob("*.json"))
    }


def test_one_callback_restarts_once_per_fork_and_preserves_parent_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, metadata = _bind_root_environment(tmp_path, monkeypatch)
    module, starts = _fake_coverage()
    callbacks: list[Any] = []
    monkeypatch.setattr(fork_runtime, "_FORK_CALLBACK_REGISTERED", False)

    def register_at_fork(*, after_in_child: Any) -> None:
        callbacks.append(after_in_child)

    assert attribution.attempt_subprocess_coverage_attribution(
        coverage_module=module,
        register_at_fork=register_at_fork,
    )
    assert len(callbacks) == 1
    root = os.environ[attribution.CURRENT_PRODUCER_ENV]
    callbacks[0]()
    child = os.environ[attribution.CURRENT_PRODUCER_ENV]
    callbacks[0]()
    grandchild = os.environ[attribution.CURRENT_PRODUCER_ENV]

    assert [(force, slug) for force, slug, _ in starts] == [
        (False, "default"),
        (True, "aoi_fork"),
        (True, "aoi_fork"),
    ]
    assert all(instance.stopped for _, _, instance in starts[:-1])
    assert all(not instance._auto_save for _, _, instance in starts[:-1])
    assert starts[-1][2]._auto_save and not starts[-1][2].stopped
    records = _process_records(metadata)
    assert records[root]["parent_producer_id"] is None
    assert records[child]["parent_producer_id"] == root
    assert records[grandchild]["parent_producer_id"] == child
    assert records[root]["attribution_scope"] == "fresh_interpreter"
    assert records[child]["attribution_scope"] == "fork_child"
    assert records[grandchild]["attribution_scope"] == "fork_child"


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("ordinary"), MemoryError(), SystemExit(2), KeyboardInterrupt()],
)
def test_fork_failure_clears_every_selector_before_hard_exit(
    tmp_path: Path,
    failure: BaseException,
) -> None:
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    fragments.mkdir()
    metadata.mkdir()
    environ = {
        "COVERAGE_FILE": str(fragments / ".coverage"),
        attribution.COVERAGE_CONFIG_ENV: str(tmp_path / ".coveragerc"),
        attribution.COVERAGE_FILE_BASE_ENV: str(fragments / ".coverage"),
        attribution.METADATA_ROOT_ENV: str(metadata),
    }
    root = attribution.prepare_subprocess_coverage_attribution(
        environ=environ,
        token_bytes=lambda size: b"R" * size,
    )
    assert type(root) is str
    environ[fork_runtime.RUNTIME_PREFIX_ENV] = str(tmp_path / "runtime")
    environ[attribution.PYTEST_FAMILY_TOKEN_ENV] = "b" * 64
    environ["COVERAGE_PROCESS_CONFIG"] = "serialized"
    environ["COVERAGE_PROCESS_START"] = str(tmp_path / ".coveragerc")
    module, starts = _fake_coverage()
    module.process_startup()
    exits: list[int] = []

    def fail_prepare(**_kwargs: object) -> None:
        raise failure

    attribution._after_fork_child_attribution(
        coverage_module=module,
        environ=environ,
        prepare=fail_prepare,
        hard_exit=exits.append,
    )
    assert exits == [97]
    assert starts[0][2].stopped and not starts[0][2]._auto_save
    for name in fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS:
        assert name not in environ


def test_cleanup_failure_cannot_bypass_the_hard_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingPop(dict[str, str]):
        def pop(self, key: str, default: object = None) -> str | object:
            if key == "COVERAGE_FILE":
                raise RuntimeError("synthetic cleanup failure")
            return super().pop(key, default)

    environ = FailingPop(
        {
            "COVERAGE_FILE": str(tmp_path / ".coverage"),
            attribution.COVERAGE_CONFIG_ENV: str(tmp_path / ".coveragerc"),
            attribution.CURRENT_PRODUCER_ENV: "a" * 64,
        }
    )
    module, _ = _fake_coverage()
    exits: list[int] = []

    def fail_stop(_module: object) -> None:
        raise RuntimeError("synthetic stop failure")

    monkeypatch.setattr(attribution, "_stop_inherited_coverage", fail_stop)
    attribution._after_fork_child_attribution(
        coverage_module=module,
        environ=environ,
        hard_exit=exits.append,
    )
    assert exits == [97]
    assert "COVERAGE_FILE" in environ
    assert attribution.COVERAGE_CONFIG_ENV not in environ
    assert attribution.CURRENT_PRODUCER_ENV not in environ


def test_startup_cleanup_failure_still_returns_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _ = _fake_coverage()
    module.__version__ = "0.0.0"

    def fail_cleanup(_target: object) -> None:
        raise RuntimeError("synthetic cleanup failure")

    monkeypatch.setattr(attribution, "_disable_inherited_coverage", fail_cleanup)
    assert not attribution.attempt_subprocess_coverage_attribution(
        coverage_module=module,
        environ={},
    )


def test_sitecustomize_cleanup_failure_still_calls_hard_exit(
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

    environ = FailingPop(
        {
            "COVERAGE_FILE": "inherited",
            attribution.COVERAGE_CONFIG_ENV: "config",
        }
    )
    exits: list[int] = []
    hard_fail = namespace["_hard_fail"]
    hard_fail.__globals__["os"] = SimpleNamespace(environ=environ, _exit=exits.append)
    hard_fail()
    assert exits == [97]
    assert "COVERAGE_FILE" in environ
    assert attribution.COVERAGE_CONFIG_ENV not in environ


def test_fork_receipt_requires_an_existing_exact_parent(tmp_path: Path) -> None:
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    fragments.mkdir()
    metadata.mkdir()
    base = fragments / ".coverage"
    environ = {
        "COVERAGE_FILE": str(base),
        attribution.COVERAGE_CONFIG_ENV: str(tmp_path / ".coveragerc"),
        attribution.COVERAGE_FILE_BASE_ENV: str(base),
        attribution.METADATA_ROOT_ENV: str(metadata),
    }
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution.prepare_subprocess_coverage_attribution(
            environ=environ,
            attribution_scope="fork_child",
        )
    environ[attribution.CURRENT_PRODUCER_ENV] = "a" * 64
    environ["COVERAGE_FILE"] = f"{base}.aoi2.{'a' * 64}"
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution.prepare_subprocess_coverage_attribution(
            environ=environ,
            attribution_scope="fork_child",
        )
