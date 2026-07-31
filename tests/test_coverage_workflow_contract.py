"""Static contract for coverage alias verification before the CI measurement run."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from scripts.verify_coverage_path_mapping import (
    CoveragePathMappingError,
    _classify_posix_measured_path,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".coveragerc"
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
VERIFIER = "python scripts/verify_coverage_path_mapping.py"
FRAGMENT_COMBINER = f"{VERIFIER} --combine-fragments covdata"
COVERAGE_JOB_SHA256 = "e744131e63fb71d1a3856ad6a61329f640712466fc8de5a11d98db658069a347"
EXPECTED_CONFIG = """[run]
source = aoi_orgware
parallel = true

[paths]
source =
    src/aoi_orgware
    ${AOI_COVERAGE_TEMP_ROOT?}/pytest-of-*/pytest-0/test_standalone_gate_runs_from0/checkout/src/aoi_orgware
    ${AOI_COVERAGE_TEMP_ROOT?}/pytest-of-*/pytest-0/test_real_system_site_packages0/system-site/lib/python3.13/site-packages/aoi_orgware
"""


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(workflow: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]+:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"job {name!r} is absent"
    return match.group("body")


def _step_headers(job: str) -> tuple[str, ...]:
    return tuple(
        match.group("name")
        for match in re.finditer(
            r"^      - name: (?P<name>[^\n#]+?)(?:\s+#.*)?$",
            job,
            flags=re.MULTILINE,
        )
    )


def _step(job: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - (?:name|uses):|\Z)",
        job,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"step {name!r} is absent"
    return match.group("body")


def _step_block(job: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n.*?(?=^      - (?:name|uses):|\Z)",
        job,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"step {name!r} is absent"
    return match.group(0)


def _assert_coverage_contract(config: str, workflow: str) -> None:
    assert config == EXPECTED_CONFIG
    coverage = _job(workflow, "coverage")
    assert hashlib.sha256(coverage.encode("utf-8")).hexdigest() == COVERAGE_JOB_SHA256
    assert re.findall(
        r"^      AOI_COVERAGE_TEMP_ROOT:\s*([^#\n]+?)\s*(?:#.*)?$",
        coverage,
        flags=re.MULTILINE,
    ) == ["${{ runner.temp }}/aoi-coverage-tests"]
    headers = _step_headers(coverage)
    assert headers == (
        "Install coverage tooling",
        "Verify coverage path mapping",
        "Enable subprocess coverage",
        "Run suite under coverage",
        "Combine and enforce floor",
    )
    assert _step(coverage, "Install coverage tooling").strip() == "run: python -m pip install pytest coverage"
    assert _step(coverage, "Verify coverage path mapping").strip() == (
        "run: |\n"
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n'
        f"          {VERIFIER}"
    )
    startup = _step(coverage, "Enable subprocess coverage")
    assert (
        "printf 'import coverage\\ncoverage.process_startup()\\n' > \"$SITE/sitecustomize.py\""
        in startup
    )
    run = _step(coverage, "Run suite under coverage")
    assert re.findall(
        r"^          TMPDIR:\s*([^#\n]+?)\s*(?:#.*)?$",
        run,
        flags=re.MULTILINE,
    ) == ["${{ env.AOI_COVERAGE_TEMP_ROOT }}"]
    assert "COVERAGE_PROCESS_START: ${{ github.workspace }}/.coveragerc" in run
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in run
    assert "python -m coverage run --parallel-mode -m pytest tests/ -q --tb=short" in run
    combine = _step(coverage, "Combine and enforce floor")
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in combine
    assert (
        "run: |\n"
        f"          {FRAGMENT_COMBINER}\n"
        "          python -m coverage report --fail-under=80"
    ) in combine
    assert "python -m coverage combine" not in combine
    assert "continue-on-error" not in coverage


def test_coverage_path_aliases_and_workflow_are_exactly_bounded() -> None:
    _assert_coverage_contract(CONFIG.read_text(encoding="utf-8"), _workflow())


def test_coverage_contract_rejects_alias_and_workflow_weakening() -> None:
    config = CONFIG.read_text(encoding="utf-8")
    workflow = _workflow()
    missing_strict_root = config.replace(
        "${AOI_COVERAGE_TEMP_ROOT?}",
        "${AOI_COVERAGE_TEMP_ROOT}",
        1,
    )
    broadened_session = config.replace(
        "/pytest-0/",
        "/pytest-*/",
        1,
    )
    broadened_node = config.replace(
        "/test_standalone_gate_runs_from0/checkout/",
        "/*/checkout/",
        1,
    )
    broadened_python = config.replace(
        "/python3.13/site-packages/",
        "/python*/site-packages/",
        1,
    )
    omitted_alias = config.replace(
        "    ${AOI_COVERAGE_TEMP_ROOT?}/pytest-of-*/pytest-0/"
        "test_standalone_gate_runs_from0/checkout/src/aoi_orgware\n",
        "",
    )
    missing_job_root = workflow.replace(
        "    env:\n"
        "      AOI_COVERAGE_TEMP_ROOT: ${{ runner.temp }}/aoi-coverage-tests\n",
        "",
        1,
    )
    wrong_job_root = workflow.replace(
        "${{ runner.temp }}/aoi-coverage-tests",
        "${{ github.workspace }}/aoi-coverage-tests",
        1,
    )
    missing_verifier = workflow.replace(
        "      - name: Verify coverage path mapping\n"
        "        run: |\n"
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n'
        f"          {VERIFIER}\n",
        "",
    )
    verifier_block = _step_block(_job(workflow, "coverage"), "Verify coverage path mapping")
    startup_block = _step_block(_job(workflow, "coverage"), "Enable subprocess coverage")
    reordered_verifier = workflow.replace(
        verifier_block + startup_block,
        startup_block + verifier_block,
        1,
    )
    missing_root_creation = workflow.replace(
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n',
        "",
        1,
    )
    wrong_tmpdir = workflow.replace(
        "          TMPDIR: ${{ env.AOI_COVERAGE_TEMP_ROOT }}",
        "          TMPDIR: ${{ runner.temp }}",
        1,
    )
    missing_fragment_verifier = workflow.replace(
        f"          {FRAGMENT_COMBINER}\n",
        "",
        1,
    )
    late_fragment_verifier = workflow.replace(
        f"          {FRAGMENT_COMBINER}\n"
        "          python -m coverage report --fail-under=80\n",
        "          python -m coverage report --fail-under=80\n"
        f"          {FRAGMENT_COMBINER}\n",
        1,
    )
    missing_startup = workflow.replace(
        "          printf 'import coverage\\ncoverage.process_startup()\\n' > \"$SITE/sitecustomize.py\"\n",
        "          printf 'import coverage\\n' > \"$SITE/sitecustomize.py\"\n",
        1,
    )
    lowered_floor = workflow.replace("--fail-under=80", "--fail-under=79", 1)
    for unsafe_config, unsafe_workflow in (
        (missing_strict_root, workflow),
        (broadened_session, workflow),
        (broadened_node, workflow),
        (broadened_python, workflow),
        (omitted_alias, workflow),
        (config, missing_job_root),
        (config, wrong_job_root),
        (config, missing_verifier),
        (config, reordered_verifier),
        (config, missing_root_creation),
        (config, wrong_tmpdir),
        (config, missing_fragment_verifier),
        (config, late_fragment_verifier),
        (config, missing_startup),
        (config, lowered_floor),
    ):
        assert (unsafe_config, unsafe_workflow) != (config, workflow)
        with pytest.raises(AssertionError):
            _assert_coverage_contract(unsafe_config, unsafe_workflow)


def test_raw_fragment_classifier_is_case_sensitive_and_lexically_exact() -> None:
    repo_root = "/work/aoi"
    temp_root = "/runner-temp/aoi-coverage-tests"
    owner = f"{temp_root}/pytest-of-runner/pytest-0"
    trusted = {
        f"{repo_root}/src/aoi_orgware/company/state.py": "canonical",
        (
            f"{owner}/test_standalone_gate_runs_from0/checkout/"
            "src/aoi_orgware/company/state.py"
        ): "checkout",
        (
            f"{owner}/test_real_system_site_packages0/system-site/lib/"
            "python3.13/site-packages/aoi_orgware/company/state.py"
        ): "system_site",
    }
    for measured, expected in trusted.items():
        category, relative = _classify_posix_measured_path(
            measured,
            repo_root=repo_root,
            temp_root=temp_root,
        )
        assert category == expected
        assert relative == ("company", "state.py")

    decoys = (
        f"{repo_root.upper()}/src/aoi_orgware/company/state.py",
        f"{temp_root.upper()}/pytest-of-runner/pytest-0/"
        "test_standalone_gate_runs_from0/checkout/"
        "src/aoi_orgware/company/state.py",
        f"{temp_root}/pytest-of-runner/PYTEST-0/"
        "test_standalone_gate_runs_from0/checkout/"
        "src/aoi_orgware/company/state.py",
        f"{owner}/TEST_STANDALONE_GATE_RUNS_FROM0/"
        "checkout/src/aoi_orgware/company/state.py",
        f"{owner}/test_real_system_site_packages0/system-site/lib/"
        "PYTHON3.13/site-packages/aoi_orgware/company/state.py",
        f"{owner}/test_standalone_gate_runs_from0/checkout/src/"
        "aoi_orgware/../aoi_orgware/company/state.py",
        f"{temp_root}/pytest-of-runner/pytest-9/"
        "test_standalone_gate_runs_from0/checkout/"
        "src/aoi_orgware/company/state.py",
        f"{owner}/test_real_system_site_packages0/system-site/lib/"
        "python9.99/site-packages/aoi_orgware/company/state.py",
    )
    for measured in decoys:
        with pytest.raises(CoveragePathMappingError):
            _classify_posix_measured_path(
                measured,
                repo_root=repo_root,
                temp_root=temp_root,
            )
