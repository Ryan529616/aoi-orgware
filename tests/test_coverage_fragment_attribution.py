"""Adversarial tests for failure-only coverage fragment attribution."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import scripts.coverage_fork_runtime as fork_runtime
import scripts.coverage_fragment_attribution as attribution
from scripts.coverage_fragment_quiescence import CoveragePathMappingError
from scripts.verify_coverage_path_mapping import _validate_coverage_fragment_schema


ROOT = Path(__file__).resolve().parents[1]


def _roots(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    fragments = tmp_path / "covdata"
    metadata = tmp_path / "covmeta"
    fragments.mkdir()
    metadata.mkdir()
    environ = {
        attribution.COVERAGE_CONFIG_ENV: str(ROOT / ".coveragerc"),
        attribution.COVERAGE_FILE_BASE_ENV: str(fragments / ".coverage"),
        attribution.METADATA_ROOT_ENV: str(metadata),
    }
    return fragments, metadata, environ


def _bound_producer(
    tmp_path: Path,
    *,
    entropy: bytes = b"\x11" * 32,
) -> tuple[Path, Path, dict[str, str], str, str]:
    fragments, metadata, environ = _roots(tmp_path)
    with attribution.pytest_family_scope(
        relative_path="tests/test_worker_family.py",
        class_name="TestWorker",
        function_name="test_crash_boundary",
        environ=environ,
    ):
        family_token = environ[attribution.PYTEST_FAMILY_TOKEN_ENV]
        producer_id = attribution.prepare_subprocess_coverage_attribution(
            environ=environ,
            token_bytes=lambda size: entropy if size == 32 else b"",
        )
    assert type(producer_id) is str
    return fragments, metadata, environ, family_token, producer_id


def _coverage_schema(path: Path, *, version: int = 7) -> None:
    database = sqlite3.connect(path)
    try:
        with database:
            database.execute("CREATE TABLE coverage_schema (version integer)")
            database.execute("INSERT INTO coverage_schema VALUES (?)", (version,))
    finally:
        database.close()


class _SchemaCoverageData:
    def __init__(self, *, basename: str) -> None:
        self._path = Path(basename)

    def read(self) -> None:
        _validate_coverage_fragment_schema(self._path)

    def measured_files(self) -> tuple[str, ...]:
        return ()

    def close(self) -> None:
        return None


def test_family_scope_is_parameter_free_canonical_and_restores_environment(
    tmp_path: Path,
) -> None:
    _, metadata, environ = _roots(tmp_path)
    prior = "a" * 64
    environ[attribution.PYTEST_FAMILY_TOKEN_ENV] = prior
    with attribution.pytest_family_scope(
        relative_path="tests/company_v05/test_worker.py",
        class_name="TestWorker",
        function_name="test_case",
        environ=environ,
    ):
        token = environ[attribution.PYTEST_FAMILY_TOKEN_ENV]
        assert token != prior
        receipt = (metadata / "families" / f"{token}.json").read_bytes()
        assert b"parameter-secret" not in receipt
        assert receipt.endswith(b"\n")
        assert json.loads(receipt)["family"] == {
            "class_name": "TestWorker",
            "function_name": "test_case",
            "relative_path": "tests/company_v05/test_worker.py",
            "schema_version": 2,
        }
    assert environ[attribution.PYTEST_FAMILY_TOKEN_ENV] == prior


@pytest.mark.parametrize(
    ("relative_path", "class_name", "function_name"),
    [
        ("../tests/test_x.py", None, "test_x"),
        ("tests\\test_x.py", None, "test_x"),
        ("/tests/test_x.py", None, "test_x"),
        ("src/test_x.py", None, "test_x"),
        ("tests/test_x.py", "Test[param-secret]", "test_x"),
        ("tests/test_x.py", None, "test_x[param-secret]"),
        ("tests//test_x.py", None, "test_x"),
        ("tests/./test_x.py", None, "test_x"),
        ("tests/a\nB.py", None, "test_x"),
        ("tests/a\x00B.py", None, "test_x"),
        ("tests/\ud800.py", None, "test_x"),
    ],
)
def test_family_scope_rejects_unbounded_or_parameterized_identity(
    tmp_path: Path,
    relative_path: str,
    class_name: str | None,
    function_name: str,
) -> None:
    _, _, environ = _roots(tmp_path)
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        with attribution.pytest_family_scope(
            relative_path=relative_path,
            class_name=class_name,
            function_name=function_name,
            environ=environ,
        ):
            raise AssertionError("unreachable")


def test_concurrent_family_publication_is_identical_and_atomic(tmp_path: Path) -> None:
    _, metadata, base = _roots(tmp_path)

    def publish(_: int) -> None:
        with attribution.pytest_family_scope(
            relative_path="tests/test_parallel.py",
            class_name=None,
            function_name="test_parallel",
            environ=dict(base),
        ):
            pass

    with ThreadPoolExecutor(max_workers=8) as pool:
        tuple(pool.map(publish, range(32)))
    receipts = tuple((metadata / "families").glob("*.json"))
    temporaries = tuple((metadata / "families").glob(".*.tmp.*"))
    assert len(receipts) == 1
    assert temporaries == ()
    assert attribution._read_record(receipts[0])["schema_version"] == 2


def test_atomic_receipt_never_exposes_partial_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = tmp_path / "receipt.json"
    payload = b'{"schema_version":1}\n'
    real_write = os.write
    calls = 0

    def fail_after_prefix(handle: int, value: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(handle, bytes(value[:1]))
        raise OSError("synthetic interrupted write")

    monkeypatch.setattr(attribution.os, "write", fail_after_prefix)
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution._write_once(final, payload)
    assert not final.exists()
    assert tuple(tmp_path.glob(".*.tmp.*")) == ()


def test_atomic_receipt_never_replaces_existing_bytes(tmp_path: Path) -> None:
    final = tmp_path / "receipt.json"
    first = b'{"schema_version":1}\n'
    second = b'{"schema_version":2}\n'
    assert attribution._write_once(final, first) is True
    assert attribution._write_once(final, second) is False
    assert final.read_bytes() == first


def test_fsync_failure_never_publishes_or_becomes_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, metadata, environ = _roots(tmp_path)

    def fail_fsync(_handle: int) -> None:
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(attribution.os, "fsync", fail_fsync)
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        with attribution.pytest_family_scope(
            relative_path="tests/test_fsync.py",
            class_name=None,
            function_name="test_fsync",
            environ=environ,
        ):
            pass
    families = metadata / "families"
    assert not families.exists() or tuple(families.iterdir()) == ()


def test_startup_binds_only_opaque_ids_and_does_not_query_coverage(tmp_path: Path) -> None:
    _, metadata, environ, family_token, producer_id = _bound_producer(tmp_path)
    assert producer_id == "11" * 32
    assert environ["COVERAGE_FILE"].endswith(f".coverage.aoi2.{producer_id}")
    process = attribution._validated_process_record(metadata, producer_id)
    assert process == {
        "attribution_scope": "fresh_interpreter",
        "family_quality": "cooperative_unverified_pytest_family",
        "family_token": family_token,
        "parent_producer_id": None,
        "producer_id": producer_id,
        "schema_version": 2,
    }
    raw = (metadata / "processes" / f"{producer_id}.json").read_text("ascii")
    for forbidden in ("argv", "cwd", "hostname", "pid", "timestamp", "provider"):
        assert forbidden not in raw
    source = (ROOT / "scripts" / "coverage_fragment_attribution.py").read_text("utf-8")
    startup = source[source.index("def prepare_subprocess_coverage_attribution"):]
    assert "Coverage(" not in startup
    assert ".get_data(" not in startup
    assert ".data_filename(" not in startup


def test_startup_without_coverage_is_a_strict_noop(tmp_path: Path) -> None:
    fragments, metadata, environ = _roots(tmp_path)
    del environ[attribution.COVERAGE_CONFIG_ENV]
    before = dict(environ)
    assert attribution.prepare_subprocess_coverage_attribution(environ=environ) is None
    assert environ == before
    assert tuple(metadata.iterdir()) == ()
    assert tuple(fragments.iterdir()) == ()


def test_safe_startup_wrapper_disables_inherited_coverage_on_any_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeCoverage:
        @classmethod
        def current(cls) -> None:
            return None

    module = type(
        "CoverageAPI",
        (),
        {
            "Coverage": FakeCoverage,
            "__version__": attribution.EXPECTED_COVERAGE_VERSION,
            "process_startup": staticmethod(lambda **_kwargs: None),
        },
    )
    environ = {
        "COVERAGE_FILE": "inherited",
        attribution.COVERAGE_CONFIG_ENV: "private-config",
        "COVERAGE_PROCESS_CONFIG": "config",
        "COVERAGE_PROCESS_START": "start",
        attribution.CURRENT_PRODUCER_ENV: "a" * 64,
    }

    def unavailable(**_kwargs: object) -> None:
        raise attribution.CoverageFragmentAttributionError("synthetic metadata failure")

    monkeypatch.setattr(attribution, "prepare_subprocess_coverage_attribution", unavailable)
    assert attribution.attempt_subprocess_coverage_attribution(
        coverage_module=module,
        environ=environ,
    ) is False
    assert environ == {}


@pytest.mark.parametrize("bad_entropy", [b"", b"x" * 31, b"x" * 33, bytearray(32), True])
def test_startup_rejects_nonexact_entropy(tmp_path: Path, bad_entropy: object) -> None:
    _, metadata, environ = _roots(tmp_path)
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution.prepare_subprocess_coverage_attribution(
            environ=environ,
            token_bytes=lambda _size: bad_entropy,
        )
    assert not (metadata / "processes").exists()
    assert "COVERAGE_FILE" not in environ


def test_startup_preserves_nonordinary_control_flow(tmp_path: Path) -> None:
    _, _, environ = _roots(tmp_path)
    for exception in (MemoryError(), KeyboardInterrupt(), SystemExit(2)):
        def fail(_size: int, *, current: BaseException = exception) -> bytes:
            raise current

        with pytest.raises(type(exception)):
            attribution.prepare_subprocess_coverage_attribution(
                environ=environ,
                token_bytes=fail,
            )


def test_startup_rejects_symlinked_roots(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "meta").mkdir(parents=True)
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    environ = {
        attribution.COVERAGE_CONFIG_ENV: str(ROOT / ".coveragerc"),
        attribution.COVERAGE_FILE_BASE_ENV: str(real / ".coverage"),
        attribution.METADATA_ROOT_ENV: str(link / "meta"),
    }
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution.prepare_subprocess_coverage_attribution(environ=environ)


def test_existing_family_symlink_is_never_accepted_as_idempotent(tmp_path: Path) -> None:
    _, metadata, environ = _roots(tmp_path)
    token, family = attribution._normalized_test_family(
        "tests/test_link.py",
        None,
        "test_link",
    )
    families = metadata / "families"
    families.mkdir()
    real = tmp_path / "real-family.json"
    real.write_bytes(
        attribution._canonical_bytes(
            {"family": family, "family_token": token, "schema_version": 2}
        )
    )
    try:
        (families / f"{token}.json").symlink_to(real)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        with attribution.pytest_family_scope(
            relative_path="tests/test_link.py",
            class_name=None,
            function_name="test_link",
            environ=environ,
        ):
            pass


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":1}\n',
        b'{ "a":1}\n',
        b"\xff\n",
        b"x" * (attribution._MAX_RECEIPT_BYTES + 1),
        b"[1]\n",
        b'{"x":NaN}\n',
    ],
)
def test_receipt_reader_rejects_malformed_noncanonical_or_oversize(
    tmp_path: Path,
    raw: bytes,
) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_bytes(raw)
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution._read_record(receipt)


def test_receipt_validators_reject_bool_schema_versions(tmp_path: Path) -> None:
    _, metadata, _, family_token, producer_id = _bound_producer(tmp_path)
    process_path = metadata / "processes" / f"{producer_id}.json"
    process = attribution._read_record(process_path)
    process["schema_version"] = True
    process_path.write_bytes(attribution._canonical_bytes(process))
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution._validated_process_record(metadata, producer_id)

    family_path = metadata / "families" / f"{family_token}.json"
    family = attribution._read_record(family_path)
    assert type(family["family"]) is dict
    family["family"]["schema_version"] = True  # type: ignore[index]
    family_path.write_bytes(attribution._canonical_bytes(family))
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution._validated_family_record(metadata, family_token)


def test_failure_report_is_sanitized_read_only_and_does_not_weaken_acceptance(
    tmp_path: Path,
) -> None:
    fragments, metadata, _, _, producer_id = _bound_producer(tmp_path)
    known = fragments / f".coverage.aoi2.{producer_id}.host.1.random"
    known.write_bytes(b"truncated")
    missing_id = "22" * 32
    missing = fragments / f".coverage.aoi2.{missing_id}.host.2.random"
    missing.write_bytes(b"")
    unexpected = fragments / "unexpected-member"
    unexpected.write_bytes(b"untrusted")
    valid_without_receipt = fragments / f".coverage.aoi2.{'33' * 32}.host.3.random"
    _coverage_schema(valid_without_receipt)
    before = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in fragments.iterdir()
    }
    with pytest.raises(CoveragePathMappingError):
        _validate_coverage_fragment_schema(known)
    _validate_coverage_fragment_schema(valid_without_receipt)

    output = io.StringIO()
    invalid = attribution.report_invalid_fragment_attribution(
        fragments_root=fragments,
        metadata_root=metadata,
        output=output,
        coverage_data_type=_SchemaCoverageData,
    )
    text = output.getvalue()
    assert invalid == 3
    assert "tests/test_worker_family.py::TestWorker::test_crash_boundary" in text
    assert "producer_quality=cooperative_unverified_pytest_family" in text
    assert "receipt_invalid_or_missing" in text
    assert producer_id not in text
    assert missing_id not in text
    assert str(tmp_path) not in text
    assert "reader_stage=unexpected_member" in text
    assert "invalid_fragments=3" in text
    after = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in fragments.iterdir()
    }
    assert after == before


def test_forged_filename_token_cannot_mint_attribution(tmp_path: Path) -> None:
    fragments, metadata, environ = _roots(tmp_path)
    with attribution.pytest_family_scope(
        relative_path="tests/test_forgery.py",
        class_name=None,
        function_name="test_forgery",
        environ=environ,
    ):
        family_token = environ[attribution.PYTEST_FAMILY_TOKEN_ENV]
    forged = fragments / f".coverage.aoi2.{family_token}.forged"
    forged.write_bytes(b"invalid")
    output = io.StringIO()
    assert attribution.report_invalid_fragment_attribution(
        fragments_root=fragments,
        metadata_root=metadata,
        output=output,
        coverage_data_type=_SchemaCoverageData,
    ) == 1
    assert "receipt_invalid_or_missing" in output.getvalue()
    assert "test_forgery" not in output.getvalue()


@pytest.mark.parametrize("linked_directory", ["processes", "families"])
def test_reporter_rejects_linked_metadata_subdirectories(
    tmp_path: Path,
    linked_directory: str,
) -> None:
    fragments, metadata, _, _, producer_id = _bound_producer(tmp_path)
    fragment = fragments / f".coverage.aoi2.{producer_id}.invalid"
    fragment.write_bytes(b"invalid")
    original = metadata / linked_directory
    outside = tmp_path / f"outside-{linked_directory}"
    original.rename(outside)
    try:
        original.symlink_to(outside, target_is_directory=True)
    except OSError:
        outside.rename(original)
        pytest.skip("directory symlink creation is unavailable")
    before = fragment.read_bytes(), tuple(path.read_bytes() for path in outside.glob("*.json"))
    output = io.StringIO()
    assert attribution.report_invalid_fragment_attribution(
        fragments_root=fragments,
        metadata_root=metadata,
        output=output,
        coverage_data_type=_SchemaCoverageData,
    ) == 1
    assert "receipt_invalid_or_missing" in output.getvalue()
    assert "test_crash_boundary" not in output.getvalue()
    assert before == (
        fragment.read_bytes(),
        tuple(path.read_bytes() for path in outside.glob("*.json")),
    )


def test_reporter_uses_authoritative_fragment_snapshot_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.coverage_fragment_quiescence as quiescence

    fragments, metadata, _ = _roots(tmp_path)

    def outside_bound(_root: Path) -> object:
        raise CoveragePathMappingError("synthetic authoritative bound")

    monkeypatch.setattr(quiescence, "_snapshot_fragments", outside_bound)
    with pytest.raises(attribution.CoverageFragmentAttributionError):
        attribution.report_invalid_fragment_attribution(
            fragments_root=fragments,
            metadata_root=metadata,
            output=io.StringIO(),
            coverage_data_type=_SchemaCoverageData,
        )


def test_diagnostic_unavailability_is_nonmutating_and_never_masks_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing"
    assert attribution.main(
        ["report", "--fragments-root", str(missing), "--metadata-root", str(missing)]
    ) == 0
    assert capsys.readouterr().out == (
        "coverage fragment attribution summary: diagnostic_unavailable\n"
    )


def test_reporter_uses_full_coverage_reader_and_closes_handle(tmp_path: Path) -> None:
    coverage = pytest.importorskip("coverage")
    fragment = tmp_path / ".coverage.schema-only"
    _coverage_schema(fragment)
    assert attribution._fragment_reader_failure_stage(
        fragment,
        coverage.CoverageData,
    ) == "coverage_data_read"
    renamed = tmp_path / ".coverage.renamed"
    fragment.replace(renamed)
    assert renamed.is_file()


def test_workflow_module_reporter_loads_authoritative_reader_without_pythonpath(
    tmp_path: Path,
) -> None:
    pytest.importorskip("coverage")
    fragments, metadata, _ = _roots(tmp_path)
    (fragments / ".coverage.invalid").write_bytes(b"invalid")
    child_env = dict(os.environ)
    child_env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.coverage_fragment_attribution",
            "report",
            "--fragments-root",
            str(fragments),
            "--metadata-root",
            str(metadata),
        ],
        cwd=ROOT,
        env=child_env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "coverage fragment attribution:" in completed.stdout
    assert "reader_stage=schema_preflight" in completed.stdout
    assert "diagnostic_unavailable" not in completed.stdout


def test_startup_attribution_preserves_public_coverage_measurement(tmp_path: Path) -> None:
    pytest.importorskip("coverage")
    probe = tmp_path / "probe.py"
    probe.write_text(
        textwrap.dedent(
            """
            import json
            import pathlib
            import sys

            from coverage import Coverage
            from scripts.coverage_fragment_attribution import (
                COVERAGE_CONFIG_ENV,
                COVERAGE_FILE_BASE_ENV,
                METADATA_ROOT_ENV,
                prepare_subprocess_coverage_attribution,
            )

            root = pathlib.Path(sys.argv[1])
            mode = sys.argv[2]
            data_file = root / f".coverage.{mode}"
            if mode == "attributed":
                metadata = root / "covmeta"
                fragments = root / "covdata"
                metadata.mkdir()
                fragments.mkdir()
                environ = {
                    COVERAGE_CONFIG_ENV: str(root / ".coveragerc"),
                    COVERAGE_FILE_BASE_ENV: str(fragments / ".coverage"),
                    METADATA_ROOT_ENV: str(metadata),
                }
                prepare_subprocess_coverage_attribution(
                    environ=environ,
                    token_bytes=lambda size: b"D" * size,
                )
                data_file = pathlib.Path(environ["COVERAGE_FILE"])
            coverage = Coverage(
                data_file=str(data_file),
                branch=True,
                context="probe",
                config_file=False,
            )
            coverage.start()
            namespace = {}
            exec(
                compile(
                    "def branch(value):\\n    return 1 if value else 0\\nbranch(True)\\n",
                    "aoi_attribution_probe.py",
                    "exec",
                ),
                namespace,
            )
            coverage.stop()
            coverage.save()
            data = coverage.get_data()
            files = sorted(data.measured_files())
            result = {
                "arcs": {name: data.arcs(name) for name in files},
                "contexts": sorted(data.measured_contexts()),
                "contexts_by_lineno": {
                    name: data.contexts_by_lineno(name) for name in files
                },
                "files": files,
                "lines": {name: data.lines(name) for name in files},
            }
            print(json.dumps(result, sort_keys=True))
            """
        ),
        encoding="utf-8",
    )
    child_env = dict(os.environ)
    child_env[attribution.CURRENT_PRODUCER_ENV] = "e" * 64
    child_env[fork_runtime.RUNTIME_PREFIX_ENV] = str(Path(sys.prefix).resolve())
    for name in (
        "COVERAGE_PROCESS_START",
        attribution.COVERAGE_CONFIG_ENV,
        "COVERAGE_FILE",
        attribution.COVERAGE_FILE_BASE_ENV,
        attribution.METADATA_ROOT_ENV,
        attribution.PYTEST_FAMILY_TOKEN_ENV,
        attribution.CURRENT_PRODUCER_ENV,
        fork_runtime.RUNTIME_PREFIX_ENV,
    ):
        child_env.pop(name, None)
    assert attribution.CURRENT_PRODUCER_ENV not in child_env
    assert fork_runtime.RUNTIME_PREFIX_ENV not in child_env
    child_env["PYTHONPATH"] = os.pathsep.join((str(ROOT), str(ROOT / "src")))

    def run(mode: str) -> object:
        completed = subprocess.run(
            [sys.executable, str(probe), str(tmp_path / mode), mode],
            cwd=ROOT,
            env=child_env,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    (tmp_path / "baseline").mkdir()
    (tmp_path / "attributed").mkdir()
    assert run("baseline") == run("attributed")
    assert len(tuple((tmp_path / "attributed" / "covmeta" / "processes").glob("*.json"))) == 1


def test_sitecustomize_receipt_failure_exits_without_coverage_fragment(
    tmp_path: Path,
) -> None:
    pytest.importorskip("coverage")
    site = tmp_path / "site"
    fragments = tmp_path / "covdata"
    temp_root = tmp_path / "runner-temp"
    site.mkdir()
    fragments.mkdir()
    temp_root.mkdir()
    copies = (
        ("coverage_fork_runtime.py", "aoi_coverage_fork_runtime.py"),
        ("coverage_fragment_attribution.py", "aoi_coverage_fragment_attribution.py"),
        ("coverage_sitecustomize.py", "sitecustomize.py"),
    )
    for source, target in copies:
        shutil.copyfile(ROOT / "scripts" / source, site / target)
    child_env = dict(os.environ)
    child_env.update(
        {
            "AOI_COVERAGE_TEMP_ROOT": str(temp_root),
            attribution.COVERAGE_FILE_BASE_ENV: str(fragments / ".coverage"),
            attribution.METADATA_ROOT_ENV: str(tmp_path / "missing-metadata"),
            "COVERAGE_FILE": str(fragments / ".coverage"),
            attribution.COVERAGE_CONFIG_ENV: str(ROOT / ".coveragerc"),
            "PYTHONPATH": os.pathsep.join((str(site), str(ROOT / "src"))),
        }
    )
    child_env.pop(attribution.PYTEST_FAMILY_TOKEN_ENV, None)
    completed = subprocess.run(
        [sys.executable, "-c", "import aoi_orgware.company.contracts"],
        cwd=ROOT,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 97
    assert tuple(fragments.glob(".coverage.*")) == ()
    assert not (tmp_path / "missing-metadata").exists()
