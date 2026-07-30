"""Static reproducibility contract for the ordinary test workflow."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
TYPECHECK_LOCK = ROOT / "requirements" / "typecheck-tools.lock"
RELEASE_TOOLS_LOCK = ROOT / "requirements" / "release-tools.lock"
WINDOWS_PRIVATE_TEMP_VERIFIER = (
    "python -c 'import os; from pathlib import Path; "
    "from aoi_orgware.company.service import _verify_windows_private_directory; "
    '_verify_windows_private_directory(Path(os.environ["AOI_PRIVATE_TEST_TEMP"]))\''
)


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


def _checkout_inputs(job: str) -> str:
    match = re.search(
        r"^      - uses: actions/checkout@[0-9a-f]{40}[^\n]*\n"
        r"        with:\n(?P<body>(?:          [^\n]*\n)+)",
        job,
        flags=re.MULTILINE,
    )
    assert match, "actions/checkout inputs are absent"
    return match.group("body")


def _script_lines(step: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in step.splitlines()
        if line.startswith("          ")
        and line.strip()
        and not line.lstrip().startswith("#")
    )


def test_full_suite_jobs_checkout_the_packaged_baseline_history() -> None:
    workflow = _workflow()
    for name in ("unit", "coverage"):
        inputs = _checkout_inputs(_job(workflow, name))
        assert re.search(
            r"^\s*persist-credentials:\s*false\s*$", inputs, re.MULTILINE
        )
        assert re.search(r"^\s*fetch-depth:\s*0\s*$", inputs, re.MULTILINE)


def test_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain() -> None:
    unit = _job(_workflow(), "unit")

    assert "timeout-minutes: 90" in unit
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
    assert all(f"{name}:" not in tests for name in ("TMPDIR", "TEMP", "TMP"))
    assert "unittest discover" not in unit
    assert "PYTHONPATH" not in tests

    assert unit.index("Resolve the hash-locked test-tool wheelhouse") < unit.index(
        "Install the test toolchain offline"
    ) < unit.index("Install package") < unit.index("Run unit tests")


def _assert_unit_matrix_prepares_a_verified_private_test_temp(workflow: str) -> None:
    unit = _job(workflow, "unit")
    posix = _step(unit, "Prepare POSIX test temp")
    windows = _step(unit, "Prepare private Windows test temp")

    assert "if: runner.os != 'Windows'" in posix
    assert 'test -d "$RUNNER_TEMP"' in posix
    assert all(f"printf '{name}=%s" in posix for name in ("TMPDIR", "TEMP", "TMP"))
    assert '"$GITHUB_ENV"' in posix

    assert "if: runner.os == 'Windows'" in windows
    assert "shell: pwsh" in windows
    lines = _script_lines(windows)
    assert lines.count("$drive = [IO.Path]::GetPathRoot($env:RUNNER_TEMP)") == 1
    private_assignments = tuple(
        line for line in lines if re.fullmatch(r"\$private\s*=.*", line)
    )
    assert private_assignments == ("$private = Join-Path $drive 't'",)
    assert "private test temp already exists" in windows
    assert "ReparsePoint" in windows
    assert "System32\\icacls.exe" in windows
    assert "'/inheritance:r'" in windows
    assert "'/grant:r'" in windows
    assert "$currentSid.Value" in windows
    assert "*S-1-5-18:(OI)(CI)F" in windows
    assert "*S-1-5-32-544:(OI)(CI)F" in windows
    assert all(sid not in windows for sid in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545"))
    assert lines.count("& $icacls @arguments") == 1
    assert lines.count(WINDOWS_PRIVATE_TEMP_VERIFIER) == 1
    assert sum("_verify_windows_private_directory" in line for line in lines) == 1
    verifier = lines.index(WINDOWS_PRIVATE_TEMP_VERIFIER)
    assert lines.index("$env:AOI_PRIVATE_TEST_TEMP = $private") < verifier
    publications = tuple(
        f'Add-Content -LiteralPath $env:GITHUB_ENV -Value "{name}=$private"'
        for name in ("TMPDIR", "TEMP", "TMP")
    )
    assert lines[verifier:] == (
        WINDOWS_PRIVATE_TEMP_VERIFIER,
        "if ($LASTEXITCODE -ne 0) {",
        'throw "production ACL verification rejected private test temp"',
        "}",
        *publications,
    )


def test_unit_matrix_prepares_a_verified_private_test_temp() -> None:
    _assert_unit_matrix_prepares_a_verified_private_test_temp(_workflow())


def test_private_temp_contract_rejects_late_override_and_fake_verifier() -> None:
    workflow = _workflow()
    late_override = workflow.replace(
        "$private = Join-Path $drive 't'",
        "$private = Join-Path $drive 't'\n"
        "          $private = $env:RUNNER_TEMP",
        1,
    )
    fake_verifier = workflow.replace(
        WINDOWS_PRIVATE_TEMP_VERIFIER,
        "python -c 'print(\"_verify_windows_private_directory\")'",
        1,
    )
    post_verifier_grant = workflow.replace(
        WINDOWS_PRIVATE_TEMP_VERIFIER,
        WINDOWS_PRIVATE_TEMP_VERIFIER
        + "\n"
        + "          & $icacls $private '/grant' 'Everyone:(OI)(CI)F'",
        1,
    )
    assert late_override != workflow
    assert fake_verifier != workflow
    assert post_verifier_grant != workflow
    for unsafe in (late_override, fake_verifier, post_verifier_grant):
        with pytest.raises(AssertionError):
            _assert_unit_matrix_prepares_a_verified_private_test_temp(unsafe)


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
