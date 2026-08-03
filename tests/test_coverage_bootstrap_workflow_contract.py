"""Static CI contracts for coverage bootstrap and fragment attribution."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".coveragerc"
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
VERIFIER = "python scripts/verify_coverage_path_mapping.py"
FRAGMENT_COMBINER = f"{VERIFIER} --combine-fragments covdata"
COVERAGE_TEMP_ROOT = "${{ runner.temp }}/aoi-coverage-tests"
COVERAGE_JOB_SHA256 = "2548a4f9597ac5688a22069c7ddc7482a81daae2d38c7efcf7e4d908dfaeefc1"
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


def _temp_root_bindings(text: str) -> list[str]:
    pattern = r"^          AOI_COVERAGE_TEMP_ROOT:\s*([^#\n]+?)\s*(?:#.*)?$"
    return re.findall(pattern, text, flags=re.MULTILINE)


def _assert_temp_root_binding(step: str) -> None:
    assert _temp_root_bindings(step) == [COVERAGE_TEMP_ROOT]


def _assert_coverage_contract(config: str, workflow: str) -> None:
    assert config == EXPECTED_CONFIG
    coverage = _job(workflow, "coverage")
    assert (
        hashlib.sha256(coverage.encode("utf-8")).hexdigest()
        == COVERAGE_JOB_SHA256
    )
    assert not re.search(r"^    env\s*:", coverage, flags=re.MULTILINE)
    assert _temp_root_bindings(coverage) == [COVERAGE_TEMP_ROOT] * 4
    assert coverage.count(COVERAGE_TEMP_ROOT) == 5
    assert "${{ env.AOI_COVERAGE_TEMP_ROOT }}" not in coverage
    headers = _step_headers(coverage)
    assert headers == (
        "Resolve the hash-locked coverage wheelhouse",
        "Install the coverage toolchain offline",
        "Verify coverage path mapping",
        "Install scoped subprocess coverage bootstrap",
        "Verify scoped subprocess coverage bootstrap",
        "Run suite under coverage",
        "Remove scoped subprocess coverage bootstrap",
        "Combine coverage fragments",
        "Enforce coverage floor",
        "Report coverage fragment attribution",
    )
    assert "cache-dependency-path: requirements/coverage-tools-linux.lock" in coverage
    resolve = _step(coverage, "Resolve the hash-locked coverage wheelhouse")
    assert "python -m pip download" in resolve
    assert "--require-hashes" in resolve
    assert "--dest .coverage-wheelhouse" in resolve
    assert "-r requirements/coverage-tools-linux.lock" in resolve
    install = _step(coverage, "Install the coverage toolchain offline")
    assert "python -m pip install" in install
    assert "--no-index" in install
    assert "--find-links .coverage-wheelhouse" in install
    assert "--require-hashes" in install
    assert "-r requirements/coverage-tools-linux.lock" in install
    assert 'coverage.__version__ == "7.15.2"' in install
    assert 'pytest.__version__ == "8.4.2"' in install
    assert _step(coverage, "Verify coverage path mapping").strip() == f"env:\n          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n        run: |\n          mkdir -p \"$AOI_COVERAGE_TEMP_ROOT\"\n          {VERIFIER}"
    startup = _step(coverage, "Install scoped subprocess coverage bootstrap")
    startup_block = _step_block(coverage, "Install scoped subprocess coverage bootstrap")
    assert "site.getsitepackages" not in startup and "id: coverage_bootstrap" in startup_block
    assert "qualified system-site fixture installs its own exact child binding" in startup_block
    assert "python scripts/coverage_bootstrap_install.py install" in startup
    assert "--site-root \"$site_root\"" in startup
    assert "--startup-root \"$AOI_COVERAGE_STARTUP_ROOT\"" in startup
    assert "--receipt \"$AOI_COVERAGE_BOOTSTRAP_RECEIPT\"" in startup
    assert "importlib.util.find_spec" in startup
    assert "aoi_coverage_bootstrap.py" in startup
    assert '"$AOI_COVERAGE_STARTUP_ROOT/sitecustomize.py"' not in startup
    runtime_prefix = "runtime_prefix=\"$(python -I -c 'import sys; print(sys.prefix)')\""
    runtime_output = "printf 'runtime_prefix=%s\\n' \"$runtime_prefix\" >> \"$GITHUB_OUTPUT\""
    assert startup.index(runtime_prefix) < startup.index(runtime_output)
    assert startup.index(runtime_output) < startup.index(
        "coverage_bootstrap_install.py install"
    )
    assert "installed=true" not in startup and "site_root=%s" not in startup
    assert "AOI_COVERAGE_PROCESS_START=" not in startup
    verify = _step(coverage, "Verify scoped subprocess coverage bootstrap")
    assert "python -I -c" in verify and "importlib.import_module" in verify
    assert "AOI_COVERAGE_STARTUP_ROOT: ${{ runner.temp }}/aoi-coverage-startup" in verify
    run = _step(coverage, "Run suite under coverage")
    _assert_temp_root_binding(run)
    assert re.findall(r"^          TMPDIR:\s*([^#\n]+?)\s*(?:#.*)?$", run, flags=re.MULTILINE) == [COVERAGE_TEMP_ROOT]
    assert "AOI_COVERAGE_PROCESS_START: ${{ github.workspace }}/.coveragerc" in run and "AOI_COVERAGE_RUNTIME_PREFIX: ${{ steps.coverage_bootstrap.outputs.runtime_prefix }}" in run and "          COVERAGE_PROCESS_START:" not in run
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in run
    assert "PYTHONPATH: src" in run and "aoi-coverage-startup:src" not in run
    assert "python -m pytest tests/ -q --tb=short" in run and "python -m coverage run" not in run
    cleanup = _step(coverage, "Remove scoped subprocess coverage bootstrap")
    cleanup_block = _step_block(coverage, "Remove scoped subprocess coverage bootstrap")
    assert "if: ${{ always() }}" in cleanup_block
    assert "steps.coverage_bootstrap.outputs" not in cleanup_block
    assert "sysconfig.get_path(\"purelib\")" in cleanup
    assert (
        'test -e "$AOI_COVERAGE_BOOTSTRAP_RECEIPT" || '
        'test -L "$AOI_COVERAGE_BOOTSTRAP_RECEIPT"'
    ) in cleanup
    assert "python scripts/coverage_bootstrap_install.py remove" in cleanup
    assert "--receipt \"$AOI_COVERAGE_BOOTSTRAP_RECEIPT\"" in cleanup
    assert 'test ! -e "$site_root/aoi_coverage_bootstrap.pth"' in cleanup
    assert coverage.index("Run suite under coverage") < coverage.index("Remove scoped subprocess coverage bootstrap") < coverage.index("Combine coverage fragments")
    combine = _step(coverage, "Combine coverage fragments")
    _assert_temp_root_binding(combine)
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in combine
    assert f"run: {FRAGMENT_COMBINER}" in combine
    assert "python -m coverage combine" not in combine
    floor = _step(coverage, "Enforce coverage floor")
    _assert_temp_root_binding(floor)
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in floor
    assert "run: python -m coverage report --fail-under=80" in floor
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
    invalid_job_root = workflow.replace(
        "  coverage:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 120\n"
        "    steps:\n",
        "  coverage:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 120\n"
        f"    env:\n      AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n"
        "    steps:\n",
        1,
    )
    missing_verify_root = workflow.replace(
        f"        env:\n          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n"
        "        run: |\n"
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n',
        "        run: |\n"
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n',
        1,
    )
    wrong_verify_root = workflow.replace(
        f"          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}",
        "          AOI_COVERAGE_TEMP_ROOT: ${{ github.workspace }}/aoi-coverage-tests",
        1,
    )
    missing_combine_root = workflow.replace(
        "      - name: Combine coverage fragments\n"
        "        id: coverage_combine\n"
        "        env:\n"
        f"          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n",
        "      - name: Combine coverage fragments\n"
        "        id: coverage_combine\n"
        "        env:\n",
        1,
    )
    divergent_run_root = workflow.replace(
        f"          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n"
        "          AOI_COVERAGE_FILE_BASE: ${{ github.workspace }}/covdata/.coverage\n"
        "          AOI_COVERAGE_METADATA_ROOT: ${{ runner.temp }}/aoi-coverage-metadata\n"
        '          PYTHONDONTWRITEBYTECODE: "1"\n',
        "          AOI_COVERAGE_TEMP_ROOT: ${{ runner.temp }}/other-coverage-tests\n"
        "          AOI_COVERAGE_FILE_BASE: ${{ github.workspace }}/covdata/.coverage\n"
        "          AOI_COVERAGE_METADATA_ROOT: ${{ runner.temp }}/aoi-coverage-metadata\n"
        '          PYTHONDONTWRITEBYTECODE: "1"\n',
        1,
    )
    missing_verifier = workflow.replace(
        "      - name: Verify coverage path mapping\n"
        "        env:\n"
        f"          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n"
        "        run: |\n"
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n'
        f"          {VERIFIER}\n",
        "",
    )
    verifier_block = _step_block(_job(workflow, "coverage"), "Verify coverage path mapping")
    startup_block = _step_block(
        _job(workflow, "coverage"),
        "Install scoped subprocess coverage bootstrap",
    )
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
        f"          TMPDIR: {COVERAGE_TEMP_ROOT}",
        "          TMPDIR: ${{ runner.temp }}",
        1,
    )
    missing_fragment_verifier = workflow.replace(
        f"        run: {FRAGMENT_COMBINER}\n",
        "        run: true\n",
        1,
    )
    missing_floor = workflow.replace(
        _step_block(_job(workflow, "coverage"), "Enforce coverage floor"), "", 1
    )
    missing_floor_root = workflow.replace(
        "      - name: Enforce coverage floor\n"
        "        env:\n"
        f"          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n",
        "      - name: Enforce coverage floor\n"
        "        env:\n",
        1,
    )
    missing_startup = workflow.replace(
        "          AOI_COVERAGE_RUNTIME_PREFIX: ${{ steps.coverage_bootstrap.outputs.runtime_prefix }}\n",
        "",
        1,
    )
    prefix_emit = "          runtime_prefix=\"$(python -I -c 'import sys; print(sys.prefix)')\"\n"
    late_runtime_prefix = workflow.replace(prefix_emit, "          AOI_COVERAGE_PROCESS_START=${AOI_COVERAGE_PROCESS_START:-active}\n" + prefix_emit, 1)
    missing_bootstrap_install = workflow.replace(
        "          python scripts/coverage_bootstrap_install.py install \\\n"
        "            --site-root \"$site_root\" \\\n"
        "            --startup-root \"$AOI_COVERAGE_STARTUP_ROOT\" \\\n"
        "            --receipt \"$AOI_COVERAGE_BOOTSTRAP_RECEIPT\"\n",
        "",
        1,
    )
    missing_cleanup = workflow.replace(
        _step_block(_job(workflow, "coverage"), "Remove scoped subprocess coverage bootstrap"),
        "",
        1,
    )
    late_runtime_output = workflow.replace(
        "          printf 'runtime_prefix=%s\\n' \"$runtime_prefix\" >> \"$GITHUB_OUTPUT\"\n"
        "          python scripts/coverage_bootstrap_install.py install \\\n",
        "          python scripts/coverage_bootstrap_install.py install \\\n",
        1,
    ).replace(
        "            --receipt \"$AOI_COVERAGE_BOOTSTRAP_RECEIPT\"\n",
        "            --receipt \"$AOI_COVERAGE_BOOTSTRAP_RECEIPT\"\n"
        "          printf 'runtime_prefix=%s\\n' \"$runtime_prefix\" >> \"$GITHUB_OUTPUT\"\n",
        1,
    )
    conditional_cleanup = workflow.replace(
        "        if: ${{ always() }}\n",
        "        if: ${{ always() && steps.coverage_bootstrap.outputs.installed == 'true' }}\n",
        1,
    )
    missing_receipt_guard = workflow.replace(
        '          if test -e "$AOI_COVERAGE_BOOTSTRAP_RECEIPT" || '
        'test -L "$AOI_COVERAGE_BOOTSTRAP_RECEIPT"; then\n',
        "          if false; then\n",
        1,
    )
    unverified_tool_download = workflow.replace(
        "            --require-hashes \\\n"
        "            --dest .coverage-wheelhouse \\\n",
        "            --dest .coverage-wheelhouse \\\n",
        1,
    )
    online_tool_install = workflow.replace(
        "            --no-index \\\n"
        "            --find-links .coverage-wheelhouse \\\n",
        "            --find-links .coverage-wheelhouse \\\n",
        1,
    )
    unverified_tool_install = workflow.replace(
        "            --find-links .coverage-wheelhouse \\\n"
        "            --require-hashes \\\n",
        "            --find-links .coverage-wheelhouse \\\n",
        1,
    )
    floating_pytest = workflow.replace(
        "      - name: Resolve the hash-locked coverage wheelhouse\n",
        "      - name: Install floating coverage tooling\n"
        "        run: python -m pip install pytest coverage\n"
        "      - name: Resolve the hash-locked coverage wheelhouse\n",
        1,
    )
    lowered_floor = workflow.replace("--fail-under=80", "--fail-under=79", 1)
    for unsafe_config, unsafe_workflow in (
        (missing_strict_root, workflow),
        (broadened_session, workflow),
        (broadened_node, workflow),
        (broadened_python, workflow),
        (omitted_alias, workflow),
        (config, invalid_job_root),
        (config, missing_verify_root),
        (config, wrong_verify_root),
        (config, missing_combine_root),
        (config, divergent_run_root),
        (config, missing_verifier),
        (config, reordered_verifier),
        (config, missing_root_creation),
        (config, wrong_tmpdir),
        (config, missing_fragment_verifier),
        (config, missing_floor),
        (config, missing_floor_root),
        (config, missing_startup),
        (config, late_runtime_prefix),
        (config, missing_bootstrap_install),
        (config, missing_cleanup),
        (config, late_runtime_output),
        (config, conditional_cleanup),
        (config, missing_receipt_guard),
        (config, unverified_tool_download),
        (config, online_tool_install),
        (config, unverified_tool_install),
        (config, floating_pytest),
        (config, lowered_floor),
    ):
        assert (unsafe_config, unsafe_workflow) != (config, workflow)
        with pytest.raises(AssertionError):
            _assert_coverage_contract(unsafe_config, unsafe_workflow)


def _coverage_job(workflow: str) -> str:
    match = re.search(
        r"^  coverage:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]+:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match
    return match.group("body")


def _assert_attribution_workflow(workflow: str) -> None:
    job = _coverage_job(workflow)
    markers = (
        "      - name: Install scoped subprocess coverage bootstrap\n",
        "      - name: Verify scoped subprocess coverage bootstrap\n",
        "      - name: Run suite under coverage\n",
        "      - name: Remove scoped subprocess coverage bootstrap\n",
        "      - name: Combine coverage fragments\n",
        "      - name: Enforce coverage floor\n",
        "      - name: Report coverage fragment attribution\n",
    )
    assert all(marker in job for marker in markers)
    startup, verify, suite, cleanup, combine, floor, report = (
        job.index(marker) for marker in markers
    )
    assert startup < verify < suite < cleanup < combine < floor < report
    copies = (
        ("coverage_fork_runtime.py", "aoi_coverage_fork_runtime.py"),
        ("coverage_fragment_attribution.py", "aoi_coverage_fragment_attribution.py"),
        ("coverage_sitecustomize.py", "aoi_coverage_bootstrap.py"),
    )
    for source, target in copies:
        installed = f'"$AOI_COVERAGE_STARTUP_ROOT/{target}"'
        assert f"cp scripts/{source} {installed}" in job
        assert f"cmp -s scripts/{source} {installed}" in job
        # The reviewed helper must be the only producer of each startup file.
        # ``printf`` is still valid for the unrelated GitHub step output.
        assert job.count(installed) == 2
    assert "python scripts/coverage_bootstrap_install.py install" in job
    assert "python scripts/coverage_bootstrap_install.py remove" in job
    assert "        if: ${{ always() }}\n" in job
    assert "steps.coverage_bootstrap.outputs" not in _step_block(
        _coverage_job(workflow),
        "Remove scoped subprocess coverage bootstrap",
    )
    assert (
        'test -e "$AOI_COVERAGE_BOOTSTRAP_RECEIPT" || '
        'test -L "$AOI_COVERAGE_BOOTSTRAP_RECEIPT"'
    ) in job
    assert 'test ! -e "$site_root/aoi_coverage_bootstrap.pth"' in job
    assert "PYTHONPATH: src" in job
    assert "aoi-coverage-startup:src" not in job
    assert job.count(
        "AOI_COVERAGE_FILE_BASE: ${{ github.workspace }}/covdata/.coverage"
    ) == 1
    assert job.count(
        "AOI_COVERAGE_METADATA_ROOT: ${{ runner.temp }}/aoi-coverage-metadata"
    ) == 2
    assert 'umask 077\n          mkdir -p covdata "$AOI_COVERAGE_METADATA_ROOT"' in job
    assert "        id: coverage_combine\n" in job
    assert (
        "        if: ${{ failure() && steps.coverage_combine.outcome == 'failure' }}\n"
    ) in job
    assert (
        "python -m scripts.coverage_fragment_attribution report \\\n"
        '            --fragments-root "${{ github.workspace }}/covdata" \\\n'
        '            --metadata-root "$AOI_COVERAGE_METADATA_ROOT"'
    ) in job
    assert "python scripts/verify_coverage_path_mapping.py --combine-fragments covdata" in job
    assert "python -m coverage report --fail-under=80" in job
    for forbidden in ("continue-on-error", "rm -", "unlink", "delete", "--ignore"):
        assert forbidden not in job


def test_workflow_keeps_attribution_failure_only_and_non_authoritative() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text("utf-8")
    _assert_attribution_workflow(workflow)
    variants = (
        workflow.replace(
            '          cp scripts/coverage_sitecustomize.py "$AOI_COVERAGE_STARTUP_ROOT/aoi_coverage_bootstrap.py"\n',
            "",
            1,
        ),
        workflow.replace(
            '          cmp -s scripts/coverage_sitecustomize.py "$AOI_COVERAGE_STARTUP_ROOT/aoi_coverage_bootstrap.py"\n',
            '          printf "import coverage\\n" > "$AOI_COVERAGE_STARTUP_ROOT/aoi_coverage_bootstrap.py"\n'
            '          cmp -s scripts/coverage_sitecustomize.py "$AOI_COVERAGE_STARTUP_ROOT/aoi_coverage_bootstrap.py"\n',
            1,
        ),
        workflow.replace(
            "      - name: Remove scoped subprocess coverage bootstrap\n",
            "      - name: Missing scoped subprocess coverage bootstrap cleanup\n",
            1,
        ),
        workflow.replace(
            "failure() && steps.coverage_combine.outcome == 'failure'",
            "always()",
            1,
        ),
        workflow.replace(
            "${{ runner.temp }}/aoi-coverage-metadata",
            "${{ github.workspace }}/covmeta",
        ),
        workflow.replace("        id: coverage_combine\n", "        id: other\n", 1),
        workflow.replace(
            "          python -m scripts.coverage_fragment_attribution report",
            "          rm -f covdata/.coverage.bad\n"
            "          python -m scripts.coverage_fragment_attribution report",
            1,
        ),
    )
    for weakened in variants:
        assert weakened != workflow
        with pytest.raises(AssertionError):
            _assert_attribution_workflow(weakened)
