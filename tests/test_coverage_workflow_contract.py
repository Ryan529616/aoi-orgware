"""Static contract for coverage alias verification before the CI measurement run."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.verify_coverage_path_mapping import (
    CoveragePathMappingError,
    FragmentIdentity,
    _classify_posix_measured_path,
    _read_stable_fragment_set,
    _validate_coverage_fragment_schema,
)
import scripts.verify_coverage_path_mapping as coverage_verifier


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".coveragerc"
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
VERIFIER = "python scripts/verify_coverage_path_mapping.py"
FRAGMENT_COMBINER = f"{VERIFIER} --combine-fragments covdata"
COVERAGE_TEMP_ROOT = "${{ runner.temp }}/aoi-coverage-tests"
COVERAGE_JOB_SHA256 = "1fc1fa825555aeb5497d5a944af8fce100ca844630f1afc0d5fddd787bc9d10f"
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
    assert (
        hashlib.sha256(coverage.encode("utf-8")).hexdigest()
        == COVERAGE_JOB_SHA256
    )
    assert not re.search(r"^    env\s*:", coverage, flags=re.MULTILINE)
    assert re.findall(
        r"^          AOI_COVERAGE_TEMP_ROOT:\s*([^#\n]+?)\s*(?:#.*)?$",
        coverage,
        flags=re.MULTILINE,
    ) == [COVERAGE_TEMP_ROOT] * 3
    assert coverage.count(COVERAGE_TEMP_ROOT) == 4
    assert "${{ env.AOI_COVERAGE_TEMP_ROOT }}" not in coverage
    headers = _step_headers(coverage)
    assert headers == (
        "Install coverage tooling",
        "Verify coverage path mapping",
        "Enable subprocess coverage",
        "Run suite under coverage",
        "Combine coverage fragments",
        "Enforce coverage floor",
        "Report coverage fragment attribution",
    )
    assert _step(coverage, "Install coverage tooling").strip() == "run: python -m pip install pytest coverage"
    assert _step(coverage, "Verify coverage path mapping").strip() == (
        "env:\n"
        f"          AOI_COVERAGE_TEMP_ROOT: {COVERAGE_TEMP_ROOT}\n"
        "        run: |\n"
        '          mkdir -p "$AOI_COVERAGE_TEMP_ROOT"\n'
        f"          {VERIFIER}"
    )
    startup = _step(coverage, "Enable subprocess coverage")
    assert 'cp scripts/coverage_fragment_attribution.py "$SITE/aoi_coverage_fragment_attribution.py"' in startup
    assert "attempt_subprocess_coverage_attribution\\n" in startup
    run = _step(coverage, "Run suite under coverage")
    assert re.findall(
        r"^          AOI_COVERAGE_TEMP_ROOT:\s*([^#\n]+?)\s*(?:#.*)?$",
        run,
        flags=re.MULTILINE,
    ) == [COVERAGE_TEMP_ROOT]
    assert re.findall(
        r"^          TMPDIR:\s*([^#\n]+?)\s*(?:#.*)?$",
        run,
        flags=re.MULTILINE,
    ) == [COVERAGE_TEMP_ROOT]
    assert "COVERAGE_PROCESS_START: ${{ github.workspace }}/.coveragerc" in run
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in run
    assert "python -m coverage run --parallel-mode -m pytest tests/ -q --tb=short" in run
    combine = _step(coverage, "Combine coverage fragments")
    assert re.findall(
        r"^          AOI_COVERAGE_TEMP_ROOT:\s*([^#\n]+?)\s*(?:#.*)?$",
        combine,
        flags=re.MULTILINE,
    ) == [COVERAGE_TEMP_ROOT]
    assert "COVERAGE_FILE: ${{ github.workspace }}/covdata/.coverage" in combine
    assert f"run: {FRAGMENT_COMBINER}" in combine
    assert "python -m coverage combine" not in combine
    floor = _step(coverage, "Enforce coverage floor")
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
    missing_startup = workflow.replace(
        "attempt_subprocess_coverage_attribution()\\n",
        "",
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


def _identity(
    inode: int = 1,
    size: int = 10,
    mtime_ns: int = 1,
    file_type: int = stat.S_IFREG,
) -> FragmentIdentity:
    return FragmentIdentity(file_type, inode, size, mtime_ns)


def _snapshot_sequence(*states: dict[Path, FragmentIdentity]):
    values = iter(states)
    last = states[-1]

    def snapshot(_directory: Path) -> dict[Path, FragmentIdentity]:
        nonlocal last
        try:
            last = next(values)
        except StopIteration:
            pass
        return dict(last)

    return snapshot


class _FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now
        self.sleep_calls: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.sleep_calls.append(duration)
        self.now += duration


def test_fragment_reader_accepts_after_exact_stability_interval() -> None:
    left = Path(".coverage.left")
    right = Path(".coverage.right")
    stable = {left: _identity(11), right: _identity(12, 12, 2)}
    clock = _FakeClock()

    fragments, measured, identities = _read_stable_fragment_set(
        Path("fragments"),
        lambda fragment: (f"/{fragment.name}.py",),
        snapshot=_snapshot_sequence(stable, stable, stable, stable),
        stability_interval=0.125,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert fragments == (left, right)
    assert measured == {
        left: ("/.coverage.left.py",),
        right: ("/.coverage.right.py",),
    }
    assert identities == stable
    assert clock.sleep_calls == [0.125]


def test_fragment_reader_uses_constant_full_snapshots_for_many_shards() -> None:
    stable = {Path(f".coverage.{index:04d}"): _identity(index + 1) for index in range(512)}
    snapshots = 0
    clock = _FakeClock()

    def snapshot(_directory: Path) -> dict[Path, FragmentIdentity]:
        nonlocal snapshots
        snapshots += 1
        return dict(stable)

    fragments, _, _ = _read_stable_fragment_set(
        Path("fragments"), lambda _fragment: (), snapshot=snapshot,
        monotonic=clock.monotonic, sleeper=clock.sleep,
    )
    assert len(fragments) == 512
    assert snapshots == 3


def test_fragment_reader_accepts_writer_completion_during_stability_delay() -> None:
    fragment = Path(".coverage.writer")
    publishing = {fragment: _identity(1)}
    complete = {fragment: _identity(2)}
    clock = _FakeClock()
    state = publishing

    def snapshot(_directory: Path) -> dict[Path, FragmentIdentity]:
        return dict(state)

    def sleeper(duration: float) -> None:
        nonlocal state
        clock.sleep(duration)
        state = complete

    fragments, measured, identities = _read_stable_fragment_set(
        Path("fragments"),
        lambda _fragment: ("/trusted.py",),
        snapshot=snapshot,
        stability_interval=0.125,
        monotonic=clock.monotonic,
        sleeper=sleeper,
    )

    assert fragments == (fragment,)
    assert measured == {fragment: ("/trusted.py",)}
    assert identities == complete
    assert clock.sleep_calls == [0.125, 0.125]


@pytest.mark.parametrize(
    ("first", "second"),
    (
        (
            {Path(".coverage.one"): _identity()},
            {
                Path(".coverage.one"): _identity(),
                Path(".coverage.added"): _identity(2),
            },
        ),
        (
            {
                Path(".coverage.one"): _identity(),
                Path(".coverage.removed"): _identity(2),
            },
            {Path(".coverage.one"): _identity()},
        ),
        ({Path(".coverage.one"): _identity(1)}, {Path(".coverage.one"): _identity(2)}),
        (
            {Path(".coverage.one"): _identity(size=10)},
            {Path(".coverage.one"): _identity(size=11)},
        ),
        (
            {Path(".coverage.one"): _identity(mtime_ns=1)},
            {Path(".coverage.one"): _identity(mtime_ns=2)},
        ),
    ),
    ids=("add", "remove", "inode-replacement", "size-mutation", "mtime-mutation"),
)
def test_fragment_reader_rejects_bounded_unstable_set_or_identity(
    first: dict[Path, FragmentIdentity],
    second: dict[Path, FragmentIdentity],
) -> None:
    reader_calls = 0
    clock = _FakeClock()

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal reader_calls
        reader_calls += 1
        return ()

    with pytest.raises(CoveragePathMappingError, match="did not stabilize"):
        _read_stable_fragment_set(
            Path("fragments"),
            reader,
            snapshot=_snapshot_sequence(first, second, first, second, first, second),
            attempts=3, stability_interval=0.01,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    assert reader_calls == 0
    assert clock.sleep_calls == [0.01, 0.01, 0.01]


def test_fragment_reader_rejects_stable_zero_byte_fragment() -> None:
    empty = {Path(".coverage.empty"): _identity(size=0)}
    clock = _FakeClock()

    with pytest.raises(CoveragePathMappingError, match="unexpected or empty"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_snapshot_sequence(empty, empty),
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )


def test_fragment_reader_rejects_stable_non_regular_fragment() -> None:
    invalid = {Path(".coverage.directory"): _identity(file_type=stat.S_IFDIR)}
    clock = _FakeClock()

    with pytest.raises(CoveragePathMappingError, match="unexpected or empty"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_snapshot_sequence(invalid, invalid),
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )


def test_fragment_reader_rejects_stably_invalid_coverage_data() -> None:
    stable = {Path(".coverage.truncated"): _identity()}
    clock = _FakeClock()

    with pytest.raises(CoveragePathMappingError, match="stably unreadable or invalid"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (_ for _ in ()).throw(ValueError("truncated")),
            snapshot=_snapshot_sequence(stable, stable, stable),
            stability_interval=0.125,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    assert clock.sleep_calls == [0.125] * 16


def test_schema_preflight_rejects_missing_schema_without_mutating_bytes(tmp_path: Path) -> None:
    fragment = tmp_path / ".coverage.missing-schema"
    with sqlite3.connect(fragment) as database:
        database.execute("CREATE TABLE unrelated (value INTEGER)")
    before = hashlib.sha256(fragment.read_bytes()).hexdigest()

    with pytest.raises(CoveragePathMappingError, match="schema is missing or invalid"):
        _validate_coverage_fragment_schema(fragment)

    assert hashlib.sha256(fragment.read_bytes()).hexdigest() == before


def test_fragment_reader_retries_transient_parse() -> None:
    fragment = Path(".coverage.retry")
    before = {fragment: _identity(1)}
    recovered = {fragment: _identity(2)}
    reader_calls = 0
    clock = _FakeClock()

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal reader_calls
        reader_calls += 1
        if reader_calls == 1:
            raise ValueError("writer still publishing")
        return ("/trusted.py",)

    fragments, measured, identities = _read_stable_fragment_set(
        Path("fragments"),
        reader,
        snapshot=_snapshot_sequence(
            before, before, recovered, recovered, recovered, recovered,
        ),
        stability_interval=0.01,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert fragments == (fragment,)
    assert measured == {fragment: ("/trusted.py",)}
    assert identities == recovered
    assert reader_calls == 2
    assert clock.sleep_calls == [0.01, 0.01, 0.01]


def test_fragment_reader_retries_identity_change_after_read() -> None:
    fragment = Path(".coverage.post-read")
    first = {fragment: _identity(1)}
    recovered = {fragment: _identity(2)}
    reader_calls = 0
    clock = _FakeClock()

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal reader_calls
        reader_calls += 1
        return ("/trusted.py",)

    fragments, measured, identities = _read_stable_fragment_set(
        Path("fragments"),
        reader,
        snapshot=_snapshot_sequence(
            first, first, recovered, recovered, recovered, recovered,
        ),
        stability_interval=0.01,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert fragments == (fragment,)
    assert measured == {fragment: ("/trusted.py",)}
    assert identities == recovered
    assert reader_calls == 2
    assert clock.sleep_calls == [0.01, 0.01]


def test_fragment_reader_exhausts_continuous_churn() -> None:
    fragment = Path(".coverage.churn")
    clock = _FakeClock()
    snapshots = 0
    reader_calls = 0

    def snapshot(_directory: Path) -> dict[Path, FragmentIdentity]:
        nonlocal snapshots
        snapshots += 1
        return {fragment: _identity(snapshots)}

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal reader_calls
        reader_calls += 1
        return ()

    with pytest.raises(CoveragePathMappingError, match="did not stabilize"):
        _read_stable_fragment_set(
            Path("fragments"),
            reader,
            snapshot=snapshot,
            attempts=3,
            stability_interval=0.01,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    assert reader_calls == 0
    assert clock.sleep_calls == [0.01, 0.01, 0.01]


@pytest.mark.parametrize("interval", (0.0, -0.01, float("nan"), float("inf")))
def test_fragment_reader_rejects_invalid_stability_interval(interval: float) -> None:
    with pytest.raises(CoveragePathMappingError, match="interval is invalid"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_snapshot_sequence({Path(".coverage.one"): _identity()}),
            stability_interval=interval,
        )


def test_fragment_reader_rejects_unbounded_stability_attempts() -> None:
    with pytest.raises(CoveragePathMappingError, match="attempt bound is invalid"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_snapshot_sequence({Path(".coverage.one"): _identity()}),
            attempts=9,
        )


def test_fragment_reader_rejects_backwards_monotonic_clock() -> None:
    times = iter((0.0, 0.001, 0.0))
    stable = {Path(".coverage.one"): _identity()}

    with pytest.raises(CoveragePathMappingError, match="clock moved backwards"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_snapshot_sequence(stable, stable),
            stability_interval=0.01,
            monotonic=lambda: next(times),
            sleeper=lambda _duration: None,
        )


class _FakeCoverageData:
    mutation = None
    mutate_every_attempt = False
    update_errors_remaining = 0
    updates = 0
    def __init__(self, basename: str) -> None:
        self.path = Path(basename)

    def update(self, _source, map_path=None) -> None:
        type(self).updates += 1
        if type(self).mutation is not None and (
            type(self).mutate_every_attempt or type(self).updates == 1
        ):
            type(self).mutation()
        if type(self).update_errors_remaining > 0:
            type(self).update_errors_remaining -= 1
            raise RuntimeError("transient source read failure")
        self.path.write_bytes(b"combined")

    def write(self) -> None:
        pass

    def close(self) -> None:
        pass


def _prepare_fake_combine(monkeypatch, tmp_path: Path):
    root = tmp_path / "repo"
    fragments = root / "covdata"
    fragments.mkdir(parents=True)
    raw = fragments / ".coverage.raw"
    raw.write_bytes(b"raw")
    calls = 0

    def verify(_directory: Path):
        nonlocal calls
        calls += 1
        snapshot = coverage_verifier._snapshot_fragments(fragments)
        return tuple(snapshot), {}, snapshot

    _FakeCoverageData.mutation = None
    _FakeCoverageData.mutate_every_attempt = False
    _FakeCoverageData.update_errors_remaining = 0
    _FakeCoverageData.updates = 0
    monkeypatch.setattr(coverage_verifier, "ROOT", root)
    monkeypatch.setattr(coverage_verifier, "verify_fragments", verify)
    monkeypatch.setitem(sys.modules, "coverage", SimpleNamespace(CoverageData=_FakeCoverageData))
    return fragments, raw, lambda: calls


def test_combine_stages_own_output_outside_frozen_fragment_set(monkeypatch, tmp_path: Path) -> None:
    fragments, raw, calls = _prepare_fake_combine(monkeypatch, tmp_path)
    coverage_verifier.combine_fragments(fragments)
    assert raw.read_bytes() == b"raw"
    assert (fragments / ".coverage").read_bytes() == b"combined"
    assert calls() == 1


def test_combine_retries_one_raw_mutation_then_publishes(monkeypatch, tmp_path: Path) -> None:
    fragments, raw, calls = _prepare_fake_combine(monkeypatch, tmp_path)
    _FakeCoverageData.mutation = lambda: raw.write_bytes(raw.read_bytes() + b"x")
    coverage_verifier.combine_fragments(fragments)
    assert raw.read_bytes() == b"rawx"
    assert (fragments / ".coverage").read_bytes() == b"combined"
    assert calls() == 2


def test_combine_classifies_update_errors_by_raw_identity(monkeypatch, tmp_path: Path) -> None:
    fragments, raw, calls = _prepare_fake_combine(monkeypatch, tmp_path)
    _FakeCoverageData.mutation = lambda: raw.write_bytes(raw.read_bytes() + b"x")
    _FakeCoverageData.update_errors_remaining = 1
    coverage_verifier.combine_fragments(fragments)
    assert calls() == 2
    stable, _, stable_calls = _prepare_fake_combine(monkeypatch, tmp_path / "stable")
    _FakeCoverageData.update_errors_remaining = 1
    with pytest.raises(CoveragePathMappingError, match="stably unreadable"):
        coverage_verifier.combine_fragments(stable)
    assert stable_calls() == 1


def test_combine_retries_one_added_fragment_without_ignoring_it(monkeypatch, tmp_path: Path) -> None:
    fragments, _, calls = _prepare_fake_combine(monkeypatch, tmp_path)
    late = fragments / ".coverage.late"
    _FakeCoverageData.mutation = lambda: late.write_bytes(b"late")
    coverage_verifier.combine_fragments(fragments)
    assert late.exists()
    assert calls() == 2


def test_combine_fails_closed_after_bounded_continuous_mutation(monkeypatch, tmp_path: Path) -> None:
    fragments, raw, calls = _prepare_fake_combine(monkeypatch, tmp_path)
    _FakeCoverageData.mutation = lambda: raw.write_bytes(raw.read_bytes() + b"x")
    _FakeCoverageData.mutate_every_attempt = True
    with pytest.raises(CoveragePathMappingError, match="every bounded combine attempt"):
        coverage_verifier.combine_fragments(fragments)
    assert not (fragments / ".coverage").exists()
    assert calls() == 3
