"""Static reproducibility contract for the ordinary test workflow."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
TYPECHECK_LOCK = ROOT / "requirements" / "typecheck-tools.lock"
RELEASE_TOOLS_LOCK = ROOT / "requirements" / "release-tools.lock"
COVERAGE_TOOLS_LOCK = ROOT / "requirements" / "coverage-tools-linux.lock"
COVERAGE_TOOLS_LOCK_SHA256 = (
    "4d65a12bb2a6e659ea768839ed147b2626229f1f2f4d091fc2a9aeaef8165f65"
)
WINDOWS_PRIVATE_TEMP_VERIFIER = (
    "python -c 'import os; from pathlib import Path; "
    "from aoi_orgware.company.service import _verify_windows_private_directory; "
    '_verify_windows_private_directory(Path(os.environ["AOI_PRIVATE_TEST_TEMP"]))\''
)
WINDOWS_PRIVATE_TEMP_STEP_SHA256 = (
    "394add889ece766707f918e1b42d55f63bdf14953f2363ccd8c4622a6093faa1"
)
UNIT_JOB_SHA256 = (
    "cd259fe1ffd819c4cd1590daaba5a75b13039964fb0e587da84aae2374e4c6db"
)
WORKFLOW_SHA256 = (
    "c0a6094677725ad08d1585d86f81eae3108f659f86a300eccc5cd29a97ee888e"
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


def _uses_step(job: str, action: str) -> str:
    match = re.search(
        rf"^      - uses: {re.escape(action)}[^\n]*\n"
        r"(?P<body>.*?)(?=^      - (?:name|uses):|\Z)",
        job,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"action step {action!r} is absent"
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


def _step_headers(job: str) -> tuple[str, ...]:
    return tuple(
        match.group("header").strip()
        for match in re.finditer(
            r"^      - (?P<header>[^#\n]+?)(?:\s+#.*)?$",
            job,
            flags=re.MULTILINE,
        )
    )


def test_full_suite_jobs_checkout_the_packaged_baseline_history() -> None:
    workflow = _workflow()
    for name in ("unit", "coverage"):
        inputs = _checkout_inputs(_job(workflow, name))
        assert re.search(
            r"^\s*persist-credentials:\s*false\s*$", inputs, re.MULTILINE
        )
        assert re.search(r"^\s*fetch-depth:\s*0\s*$", inputs, re.MULTILINE)


def _assert_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain(
    workflow: str,
) -> None:
    assert hashlib.sha256(workflow.encode("utf-8")).hexdigest() == WORKFLOW_SHA256
    assert len(
        re.findall(
            r"^(?:jobs|['\"]jobs['\"])\s*:\s*(?:#.*)?$",
            workflow,
            flags=re.MULTILINE,
        )
    ) == 1
    assert len(
        re.findall(
            r"^  (?:unit|['\"]unit['\"])\s*:\s*(?:#.*)?$",
            workflow,
            flags=re.MULTILINE,
        )
    ) == 1
    unit = _job(workflow, "unit")
    assert hashlib.sha256(unit.encode("utf-8")).hexdigest() == UNIT_JOB_SHA256

    assert re.findall(
        r"^    timeout-minutes:\s*(\d+)\s*(?:#.*)?$",
        unit,
        flags=re.MULTILINE,
    ) == ["180"]
    assert re.findall(
        r"^        os:\s*(\[[^]\n]+\])\s*(?:#.*)?$",
        unit,
        flags=re.MULTILINE,
    ) == ["[ubuntu-latest, windows-latest]"]
    assert re.findall(
        r"^        python-version:\s*(\[[^]\n]+\])\s*(?:#.*)?$",
        unit,
        flags=re.MULTILINE,
    ) == ['["3.11", "3.12", "3.13", "3.14"]']
    assert re.findall(
        r"^      fail-fast:\s*(\S+)\s*(?:#.*)?$",
        unit,
        flags=re.MULTILINE,
    ) == ["false"]
    assert re.findall(
        r"^    runs-on:\s*([^#\n]+?)\s*(?:#.*)?$",
        unit,
        flags=re.MULTILINE,
    ) == ["${{ matrix.os }}"]
    assert not re.search(r"^    if\s*:", unit, flags=re.MULTILINE)
    assert re.findall(
        r"^        if:\s*([^#\n]+?)\s*(?:#.*)?$",
        unit,
        flags=re.MULTILINE,
    ) == ["runner.os != 'Windows'", "runner.os == 'Windows'"]
    assert not re.search(
        r"^        (?:include|exclude)\s*:", unit, flags=re.MULTILINE
    )
    assert not re.search(r"^\s+continue-on-error\s*:", unit, flags=re.MULTILINE)
    assert _step_headers(unit) == (
        "uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "name: Resolve the hash-locked test-tool wheelhouse",
        "name: Install the test toolchain offline",
        "name: Install package",
        "name: Smoke installed CLI",
        "name: Prepare POSIX test temp",
        "name: Prepare private Windows test temp",
        "name: Run unit tests",
    )

    setup_python = _uses_step(unit, "actions/setup-python@")
    assert re.findall(
        r"^          python-version:\s*([^#\n]+?)\s*(?:#.*)?$",
        setup_python,
        flags=re.MULTILINE,
    ) == ["${{ matrix.python-version }}"]

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
    assert not re.search(r"^        if\s*:", tests, flags=re.MULTILINE)
    assert re.search(
        r"^\s*run:\s*python -m pytest -q tests\s*$", tests, re.MULTILINE
    )
    assert all(f"{name}:" not in tests for name in ("TMPDIR", "TEMP", "TMP"))
    assert "unittest discover" not in unit
    assert "PYTHONPATH" not in tests

    assert unit.index("Resolve the hash-locked test-tool wheelhouse") < unit.index(
        "Install the test toolchain offline"
    ) < unit.index("Install package") < unit.index("Run unit tests")


def test_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain() -> None:
    _assert_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain(_workflow())


def test_unit_job_contract_rejects_comment_spoofing_and_failure_masking() -> None:
    workflow = _workflow()
    timeout_spoof = workflow.replace(
        "    timeout-minutes: 180",
        "    timeout-minutes: 90  # timeout-minutes: 180",
        1,
    )
    timeout_omission = workflow.replace(
        "    timeout-minutes: 180",
        "    # timeout-minutes: 180",
        1,
    )
    matrix_spoof = workflow.replace(
        '        python-version: ["3.11", "3.12", "3.13", "3.14"]',
        '        python-version: ["3.11", "3.12", "3.13"]  # "3.14"',
        1,
    )
    continue_on_error = workflow.replace(
        "      - name: Run unit tests",
        "      - name: Run unit tests\n        continue-on-error: true",
        1,
    )
    extra_retry = workflow.replace(
        "      - name: Run unit tests",
        "      - name: Retry unit tests\n"
        "        run: python -m pytest -q tests\n"
        "      - name: Run unit tests",
        1,
    )
    job_skip = workflow.replace(
        "    timeout-minutes: 180",
        "    if: false\n    timeout-minutes: 180",
        1,
    )
    step_skip = workflow.replace(
        "      - name: Run unit tests",
        "      - name: Run unit tests\n        if: false",
        1,
    )
    setup_skip = workflow.replace(
        "      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
        " # v6.3.0\n"
        "        with:",
        "      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
        " # v6.3.0\n"
        "        if: false\n"
        "        with:",
        1,
    )
    setup_skip_spaced = workflow.replace(
        "      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
        " # v6.3.0\n"
        "        with:",
        "      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
        " # v6.3.0\n"
        "        if : false\n"
        "        with:",
        1,
    )
    test_shell = workflow.replace(
        "      - name: Run unit tests\n"
        "        env:",
        "      - name: Run unit tests\n"
        '        shell: echo "{0}"\n'
        "        env:",
        1,
    )
    duplicate_unit = (
        workflow
        + "\n  unit :\n"
        + "    if: false\n"
        + "    runs-on: ubuntu-latest\n"
        + "    steps: []\n"
    )
    escaped_duplicate_unit = (
        workflow
        + '\n  "un\\u0069t":\n'
        + "    if: false\n"
        + "    runs-on: ubuntu-latest\n"
        + "    steps: []\n"
    )
    workflow_shell_default = workflow.replace(
        "concurrency:\n",
        "defaults:\n"
        "  run:\n"
        '    shell: echo "{0}"\n'
        "\n"
        "concurrency:\n",
        1,
    )
    fixed_runner = workflow.replace(
        "    runs-on: ${{ matrix.os }}",
        "    runs-on: ubuntu-latest",
        1,
    )
    fixed_python = workflow.replace(
        "          python-version: ${{ matrix.python-version }}",
        '          python-version: "3.11"',
        1,
    )
    excluded_windows = workflow.replace(
        '        python-version: ["3.11", "3.12", "3.13", "3.14"]',
        '        python-version: ["3.11", "3.12", "3.13", "3.14"]\n'
        "        exclude:\n"
        "          - os: windows-latest",
        1,
    )
    fail_fast = workflow.replace(
        "      fail-fast: false",
        "      fail-fast: true",
        1,
    )
    for unsafe in (
        timeout_spoof,
        timeout_omission,
        matrix_spoof,
        continue_on_error,
        extra_retry,
        job_skip,
        step_skip,
        setup_skip,
        setup_skip_spaced,
        test_shell,
        duplicate_unit,
        escaped_duplicate_unit,
        workflow_shell_default,
        fixed_runner,
        fixed_python,
        excluded_windows,
        fail_fast,
    ):
        assert unsafe != workflow
        with pytest.raises(AssertionError):
            _assert_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain(
                unsafe
            )


def _assert_unit_matrix_prepares_a_verified_private_test_temp(workflow: str) -> None:
    unit = _job(workflow, "unit")
    posix = _step(unit, "Prepare POSIX test temp")
    windows = _step(unit, "Prepare private Windows test temp")
    assert (
        hashlib.sha256(windows.encode("utf-8")).hexdigest()
        == WINDOWS_PRIVATE_TEMP_STEP_SHA256
    )

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
    script = "\n".join(lines)
    assert 'throw "private test temp already exists"' in lines
    assert any("ReparsePoint" in line for line in lines)
    assert "$icacls = Join-Path $env:SystemRoot 'System32\\icacls.exe'" in lines
    assert "'/inheritance:r'" in lines
    assert "'/grant:r'" in lines
    assert any("$currentSid.Value" in line for line in lines)
    assert "'*S-1-5-18:(OI)(CI)F'" in lines
    assert "'*S-1-5-32-544:(OI)(CI)F'" in lines
    assert all(
        sid not in script for sid in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
    )
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
    commented_inheritance = workflow.replace(
        "            '/inheritance:r'",
        "            # '/inheritance:r'",
        1,
    )
    post_verifier_override_step = workflow.replace(
        "      - name: Run unit tests",
        "      - name: Restore unsafe runner temp\n"
        "        shell: pwsh\n"
        "        run: Add-Content -LiteralPath $env:GITHUB_ENV "
        '-Value "TEMP=$env:RUNNER_TEMP"\n'
        "      - name: Run unit tests",
        1,
    )
    disabled_windows_step = workflow.replace(
        "        if: runner.os == 'Windows'",
        "        if: runner.os == 'Windows' && false",
        1,
    )
    shadowed_python = workflow.replace(
        "          $drive = [IO.Path]::GetPathRoot($env:RUNNER_TEMP)",
        "          function python { exit 0 }\n"
        "          $drive = [IO.Path]::GetPathRoot($env:RUNNER_TEMP)",
        1,
    )
    shadowed_add_content = workflow.replace(
        "          $drive = [IO.Path]::GetPathRoot($env:RUNNER_TEMP)",
        "          function Add-Content { return }\n"
        "          $drive = [IO.Path]::GetPathRoot($env:RUNNER_TEMP)",
        1,
    )
    assert late_override != workflow
    assert fake_verifier != workflow
    assert post_verifier_grant != workflow
    for unsafe in (
        late_override,
        fake_verifier,
        post_verifier_grant,
        commented_inheritance,
        post_verifier_override_step,
        disabled_windows_step,
        shadowed_python,
        shadowed_add_content,
    ):
        with pytest.raises(AssertionError):
            _assert_unit_matrix_uses_the_hash_locked_offline_pytest_toolchain(
                unsafe
            )
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


def test_coverage_toolchain_is_exactly_pinned_and_installed_offline() -> None:
    lock = COVERAGE_TOOLS_LOCK.read_text(encoding="utf-8")
    assert hashlib.sha256(lock.encode("utf-8")).hexdigest() == COVERAGE_TOOLS_LOCK_SHA256
    expected = {
        "coverage==7.15.2",
        "iniconfig==2.3.0",
        "packaging==26.2",
        "pluggy==1.6.0",
        "pygments==2.20.0",
        "pytest==8.4.2",
    }
    assert "--only-binary=:all:" in lock
    assert all(requirement in lock for requirement in expected)
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", lock)) == len(expected)

    coverage = _job(_workflow(), "coverage")
    assert 'python-version: "3.13"' in coverage
    assert "cache-dependency-path: requirements/coverage-tools-linux.lock" in coverage
    assert "pip download" in coverage
    assert "--require-hashes" in coverage
    assert "--no-index" in coverage
    assert "--find-links .coverage-wheelhouse" in coverage
    assert "requirements/coverage-tools-linux.lock" in coverage
    assert "pip install pytest" not in coverage


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
