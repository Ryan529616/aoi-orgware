"""Static reproducibility contract for the ordinary test workflow."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
TYPECHECK_LOCK = ROOT / "requirements" / "typecheck-tools.lock"
RELEASE_TOOLS_LOCK = ROOT / "requirements" / "release-tools.lock"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(text: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]+:\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"job {name!r} is absent"
    return match.group("body")


def _step(job: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - (?:name|uses):|\Z)",
        job,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"step {name!r} is absent"
    return match.group("body")


def test_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain() -> None:
    unit = _job(_workflow(), "unit")

    assert "timeout-minutes: 45" in unit
    assert "os: [ubuntu-latest, windows-latest]" in unit
    assert all(f'"{version}"' in unit for version in ("3.11", "3.12", "3.13", "3.14"))

    download = _step(unit, "Resolve the hash-locked test-tool wheelhouse")
    assert "python -m pip download" in download
    assert "--require-hashes" in download
    assert "--dest .test-wheelhouse" in download
    assert "requirements/release-tools.lock" in download
    assert "\\\n" not in download
    assert "`\n" not in download

    install = _step(unit, "Install the test toolchain offline")
    assert "python -m pip install" in install
    assert "--no-index" in install
    assert "--find-links .test-wheelhouse" in install
    assert "--require-hashes" in install
    assert "requirements/release-tools.lock" in install
    assert "\\\n" not in install
    assert "`\n" not in install

    package = _step(unit, "Install package")
    assert re.search(
        r"python -m pip install\s+--no-build-isolation\s+--no-deps\s+\.",
        package,
    )

    tests = _step(unit, "Run unit tests")
    assert re.search(
        r"^\s*run:\s*python -m pytest -q tests\s*$", tests, re.MULTILINE
    )
    assert "unittest discover" not in unit
    assert "PYTHONPATH" not in tests

    assert unit.index("Resolve the hash-locked test-tool wheelhouse") < unit.index(
        "Install the test toolchain offline"
    ) < unit.index("Install package") < unit.index("Run unit tests")


def test_typecheck_toolchain_is_exactly_pinned_and_hash_verified() -> None:
    lock = TYPECHECK_LOCK.read_text(encoding="utf-8")
    expected = {
        "ast-serialize==0.6.0",
        "librt==0.13.0",
        "mypy==2.3.0",
        "mypy-extensions==1.1.0",
        "pathspec==1.1.1",
        "typing-extensions==4.16.0",
    }
    assert "--only-binary=:all:" in lock
    assert all(requirement in lock for requirement in expected)
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", lock)) == len(expected)

    typing = _job(_workflow(), "typing")
    assert 'python-version: "3.13"' in typing
    assert "pip download" in typing
    assert "--require-hashes" in typing
    assert "--no-index" in typing
    assert "--find-links .typecheck-wheelhouse" in typing
    assert "requirements/typecheck-tools.lock" in typing
    assert "pip install mypy" not in typing


def test_test_and_docs_workflows_pin_every_third_party_action_to_a_commit() -> None:
    for path in (WORKFLOW, ROOT / ".github" / "workflows" / "docs.yml"):
        workflow = path.read_text(encoding="utf-8")
        refs = re.findall(
            r"^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow, flags=re.MULTILINE
        )
        assert refs, path
        assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs), path


def test_package_jobs_use_the_hash_locked_build_backend_for_sdist_readback() -> None:
    lock = RELEASE_TOOLS_LOCK.read_text(encoding="utf-8")
    assert "build==1.5.0" in lock
    assert "hatchling==1.27.0" in lock
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", lock)) == 11

    workflow = _workflow()
    package = _job(workflow, "package")
    windows = _job(workflow, "package-windows-smoke")
    for section in (package, windows):
        assert "requirements/release-tools.lock" in section
        assert "--require-hashes" in section
        assert "--no-index" in section
        assert "--find-links .release-wheelhouse" in section
        assert "--build-python" in section
        assert "--expected-build-version 1.5.0" in section
        assert "--expected-hatchling-version 1.27.0" in section
    assert ".release-tools/bin/python -m build --no-isolation" in package
    assert ".\\.release-tools\\Scripts\\python.exe" in windows
