"""Repository pytest-hook boundaries for coverage attribution diagnostics."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.coverage_fragment_attribution as attribution
import tests.conftest as repository_hooks


ROOT = Path(__file__).resolve().parents[1]


def _run_hook(item: object) -> None:
    protocol = repository_hooks.pytest_runtest_protocol(item, None)
    next(protocol)
    with pytest.raises(StopIteration):
        next(protocol)


def test_pytest_hook_never_persists_parameter_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = tmp_path / "covmeta"
    metadata.mkdir()
    monkeypatch.setenv(attribution.METADATA_ROOT_ENV, str(metadata))
    tokens: list[str] = []
    for parameter in ("SECRET_ALPHA", "SECRET_BETA"):
        item = SimpleNamespace(
            path=ROOT / "tests" / "test_coverage_attribution_hook.py",
            cls=None,
            originalname=None,
            name=f"test_parameterized[{parameter}]",
        )
        protocol = repository_hooks.pytest_runtest_protocol(item, None)
        next(protocol)
        tokens.append(os.environ[attribution.PYTEST_FAMILY_TOKEN_ENV])
        with pytest.raises(StopIteration):
            next(protocol)
    assert tokens[0] == tokens[1]
    receipts = b"".join(path.read_bytes() for path in (metadata / "families").iterdir())
    assert b"SECRET_ALPHA" not in receipts
    assert b"SECRET_BETA" not in receipts


def test_pytest_hook_is_noop_without_attribution_for_virtual_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(attribution.METADATA_ROOT_ENV, raising=False)
    monkeypatch.setenv(attribution.PYTEST_FAMILY_TOKEN_ENV, "a" * 64)
    _run_hook(SimpleNamespace(path="outside-or-virtual", cls=None, name="test_virtual"))
    assert os.environ[attribution.PYTEST_FAMILY_TOKEN_ENV] == "a" * 64


def test_pytest_hook_metadata_failure_is_fail_open_and_clears_stale_family(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = tmp_path / "covmeta"
    metadata.mkdir()
    monkeypatch.setenv(attribution.METADATA_ROOT_ENV, str(metadata))
    monkeypatch.setenv(attribution.PYTEST_FAMILY_TOKEN_ENV, "b" * 64)

    def unavailable(**_kwargs: object) -> object:
        raise attribution.CoverageFragmentAttributionError("synthetic failure")

    monkeypatch.setattr(attribution, "pytest_family_scope", unavailable)
    _run_hook(
        SimpleNamespace(
            path=ROOT / "tests" / "test_coverage_attribution_hook.py",
            cls=None,
            originalname="test_body",
            name="test_body",
        )
    )
    assert attribution.PYTEST_FAMILY_TOKEN_ENV not in os.environ


def test_pytest_hook_enabled_outside_item_is_fail_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = tmp_path / "covmeta"
    metadata.mkdir()
    monkeypatch.setenv(attribution.METADATA_ROOT_ENV, str(metadata))
    monkeypatch.setenv(attribution.PYTEST_FAMILY_TOKEN_ENV, "c" * 64)
    _run_hook(SimpleNamespace(path=tmp_path / "missing.py", cls=None, name="test_x"))
    assert attribution.PYTEST_FAMILY_TOKEN_ENV not in os.environ


def test_safe_family_scope_preserves_nonordinary_entry_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = tmp_path / "covmeta"
    metadata.mkdir()

    def fatal(**_kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(attribution, "pytest_family_scope", fatal)
    with pytest.raises(MemoryError):
        with attribution.attempt_pytest_family_scope(
            relative_path="tests/test_fatal.py",
            class_name=None,
            function_name="test_fatal",
            environ={attribution.METADATA_ROOT_ENV: str(metadata)},
        ):
            raise AssertionError("unreachable")


def test_safe_family_scope_never_swallows_test_body_exception(tmp_path: Path) -> None:
    metadata = tmp_path / "covmeta"
    metadata.mkdir()
    environ = {attribution.METADATA_ROOT_ENV: str(metadata)}
    with pytest.raises(LookupError, match="test body"):
        with attribution.attempt_pytest_family_scope(
            relative_path="tests/test_body.py",
            class_name=None,
            function_name="test_body",
            environ=environ,
        ):
            raise LookupError("test body")
