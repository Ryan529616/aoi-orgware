"""Contract tests for the fail-closed coverage provenance combiner."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import base64
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "combine_coverage.py"
SPEC = importlib.util.spec_from_file_location("combine_coverage", SCRIPT)
assert SPEC and SPEC.loader
combine_coverage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = combine_coverage
SPEC.loader.exec_module(combine_coverage)
REAL_VALIDATE_TOOLCHAIN = combine_coverage._validate_toolchain


TEST_TOOLCHAIN = {
    "coverage": "7.15.2",
    "pytest": "9.1.1",
    "lock_sha256": "test-lock",
    "python": "test",
    "records": [],
}


@pytest.fixture
def live_toolchain() -> None:
    """Opt into the actual installed, hash-locked coverage toolchain."""


@pytest.fixture(autouse=True)
def _stable_toolchain(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic provenance fixtures do not need the runner's toolchain."""
    if "live_toolchain" not in request.fixturenames:
        monkeypatch.setattr(combine_coverage, "_validate_toolchain", lambda _lock: TEST_TOOLCHAIN)


def _init_git(root: Path) -> None:
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "coverage@example.invalid"],
        ["git", "config", "user.name", "Coverage Test"],
        ["git", "add", "."],
        ["git", "commit", "-qm", "coverage fixture"],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)


def _tree(root: Path) -> Path:
    package = root / "src" / "aoi_orgware"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "core.py").write_text("def core():\n    return 1\n", encoding="utf-8")
    (package / "sentinel.py").write_text("def sentinel():\n    return 2\n", encoding="utf-8")
    return package


def _copy_tree(source: Path, destination: Path) -> Path:
    target = destination / "aoi_orgware"
    target.parent.mkdir(parents=True)
    shutil.copytree(source, target)
    return target


def _data(path: Path, files: list[Path]) -> None:
    data = combine_coverage.CoverageData(basename=str(path))
    data.add_lines({str(item.absolute()): {1} for item in files})
    data.write()


def _fixture(tmp_path: Path, roots: int = 3) -> tuple[Path, list[Path], Path]:
    canonical = _tree(tmp_path)
    lock = tmp_path / "requirements" / "coverage-tools.lock"
    lock.parent.mkdir()
    shutil.copy2(Path(__file__).resolve().parents[1] / "requirements" / "coverage-tools.lock", lock)
    shutil.copy2(Path(__file__).resolve().parents[1] / ".coveragerc", tmp_path / ".coveragerc")
    (tmp_path / ".gitignore").write_text("covdata/\ncopy-*/\n", encoding="utf-8")
    _init_git(tmp_path)
    copies = [canonical]
    for index in range(1, roots):
        copies.append(_copy_tree(canonical, tmp_path / f"copy-{index}"))
    covdata = tmp_path / "covdata"
    covdata.mkdir()
    for index, root in enumerate(copies):
        _data(covdata / f".coverage.{index}", [root / "core.py"])
    return canonical, copies, covdata


def _combine(tmp_path: Path, canonical: Path, covdata: Path, **kwargs: object) -> dict[str, object]:
    parameters: dict[str, object] = {
        "data_dir": covdata,
        "source_root": canonical,
        "output_file": covdata / ".coverage",
        "receipt_file": covdata / "coverage-provenance.json",
        "lock_path": tmp_path / "requirements" / "coverage-tools.lock",
        "repo_root": tmp_path,
    }
    parameters.update(kwargs)
    return combine_coverage.combine(
        **parameters,
    )


def _published_output(covdata: Path, receipt: dict[str, object]) -> Path:
    return covdata / receipt["run"]["combined_output_filename"]


def test_identical_roots_are_mapped_to_one_canonical_tree(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    receipt = _combine(tmp_path, canonical, covdata)
    payload = receipt["canonical_payload"]
    assert len(payload["roots"]) == 3
    assert payload["git"]["clean"] is True
    combined = combine_coverage.CoverageData(basename=str(_published_output(covdata, receipt)))
    combined.read()
    assert combined.measured_files() == {str((canonical / "core.py").absolute())}
    parsed = json.loads((covdata / "coverage-provenance.json").read_text(encoding="utf-8"))
    assert parsed["canonical_payload"]["combined_measured_files"] == ["core.py"]
    canonical_json = json.dumps(parsed["canonical_payload"], sort_keys=True, separators=(",", ":"))
    assert combine_coverage.hashlib.sha256(canonical_json.encode()).hexdigest() == parsed["canonical_payload_sha256"]
    assert str(tmp_path) not in canonical_json


def test_one_byte_mutation_is_rejected(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    (roots[1] / "core.py").write_text("def core():\n    return 9\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="diverges"):
        _combine(tmp_path, canonical, covdata)


@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_missing_or_extra_source_file_is_rejected(tmp_path: Path, operation: str) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    if operation == "missing":
        (roots[1] / "sentinel.py").unlink()
    else:
        (roots[1] / "extra.py").write_text("EXTRA = True\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="diverges"):
        _combine(tmp_path, canonical, covdata)


def test_unknown_fourth_root_is_rejected(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path, roots=4)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="exactly 3"):
        _combine(tmp_path, canonical, covdata)


def test_symlinked_source_is_rejected(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    target = roots[1] / "core.py"
    target.unlink()
    try:
        target.symlink_to(roots[1] / "sentinel.py")
    except OSError:
        pytest.skip("current Windows policy does not permit test symlinks")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="link|non-linked"):
        _combine(tmp_path, canonical, covdata)


def test_directory_symlinked_source_entry_is_rejected(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    target = tmp_path / "directory-symlink-target"
    target.mkdir()
    link = roots[1] / "linked-directory"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("current Windows policy does not permit directory symlinks")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="directory entry|link|reparse"):
        _combine(tmp_path, canonical, covdata)


def test_namespace_measured_root_is_rejected_before_input_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    data = combine_coverage.CoverageData(basename=str(covdata / ".coverage.1"))
    data.add_lines({r"\\?\C:\aoi_orgware\core.py": {1}})
    data.write()

    def input_staging_must_not_copy(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("measured namespace alias must be rejected before input staging")

    monkeypatch.setattr(combine_coverage.shutil, "copyfile", input_staging_must_not_copy)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="namespace alias"):
        _combine(tmp_path, canonical, covdata)


def test_external_measured_root_with_symlink_ancestor_is_rejected_before_input_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    linked_copy = tmp_path.parent / f"{tmp_path.name}-linked-external-root"
    try:
        linked_copy.symlink_to(roots[1].parent, target_is_directory=True)
    except OSError:
        pytest.skip("current Windows policy does not permit directory symlinks")
    try:
        data = combine_coverage.CoverageData(basename=str(covdata / ".coverage.1"))
        data.add_lines({str(linked_copy / roots[1].name / "core.py"): {1}})
        data.write()

        def input_staging_must_not_copy(*_args: object, **_kwargs: object) -> str:
            raise AssertionError("measured symlink ancestor must be rejected before input staging")

        monkeypatch.setattr(combine_coverage.shutil, "copyfile", input_staging_must_not_copy)
        with pytest.raises(combine_coverage.CoverageProvenanceError, match="symlink|reparse ancestor"):
            _combine(tmp_path, canonical, covdata)
    finally:
        if linked_copy.is_symlink():
            linked_copy.unlink()


def test_enumerated_non_directory_cannot_be_silently_omitted_from_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "aoi_orgware"
    root.mkdir()
    (root / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "not-a-directory").write_text("must not be omitted\n", encoding="utf-8")

    def synthetic_walk(*_args: object, **_kwargs: object) -> object:
        return iter([(str(root), ["not-a-directory"], ["core.py"])])

    monkeypatch.setattr(combine_coverage.os, "walk", synthetic_walk)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="directory entry"):
        combine_coverage._tree_manifest(root)


def test_walk_onerror_is_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _tree(tmp_path)

    def failing_walk(*_args: object, **kwargs: object) -> object:
        def entries() -> object:
            onerror = kwargs["onerror"]
            assert callable(onerror)
            onerror(PermissionError("injected directory access failure"))
            yield None

        return entries()

    monkeypatch.setattr(combine_coverage.os, "walk", failing_walk)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="walk failed"):
        combine_coverage._tree_manifest(root)


def test_listed_directory_disappearance_before_descent_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _tree(tmp_path)
    child = root / "child"
    child.mkdir()

    def synthetic_walk(*_args: object, **_kwargs: object) -> object:
        def entries() -> object:
            yield str(root), ["child"], ["__init__.py", "core.py", "sentinel.py"]
            child.rmdir()

        return entries()

    monkeypatch.setattr(combine_coverage.os, "walk", synthetic_walk)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="was not visited"):
        combine_coverage._tree_manifest(root)


def test_listed_directory_swap_before_descent_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _tree(tmp_path)
    child = root / "child"
    child.mkdir()
    replacement = root / "replacement"

    def synthetic_walk(*_args: object, **_kwargs: object) -> object:
        def entries() -> object:
            yield str(root), ["child"], ["__init__.py", "core.py", "sentinel.py"]
            replacement.mkdir()
            child.rmdir()
            replacement.replace(child)
            yield str(child), [], []

        return entries()

    monkeypatch.setattr(combine_coverage.os, "walk", synthetic_walk)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="changed before descent"):
        combine_coverage._tree_manifest(root)


def test_terminal_directory_identity_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _tree(tmp_path)
    terminal = root / "terminal"
    terminal.mkdir()
    replacement = root / "replacement"

    def synthetic_walk(*_args: object, **_kwargs: object) -> object:
        def entries() -> object:
            yield str(root), ["terminal"], ["__init__.py", "core.py", "sentinel.py"]
            yield str(terminal), [], []
            replacement.mkdir()
            terminal.rmdir()
            replacement.replace(terminal)

        return entries()

    monkeypatch.setattr(combine_coverage.os, "walk", synthetic_walk)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="identity changed"):
        combine_coverage._tree_manifest(root)


def test_source_race_between_pre_and_post_manifest_is_rejected(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)

    def mutate() -> None:
        (roots[2] / "core.py").write_text("def core():\n    return 3\n", encoding="utf-8")

    with pytest.raises(combine_coverage.CoverageProvenanceError, match="changed during combine"):
        _combine(tmp_path, canonical, covdata, between_manifests=mutate)


def test_dirty_unrelated_git_state_is_rejected(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    (tmp_path / "unrelated.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="worktree must be clean"):
        _combine(tmp_path, canonical, covdata)


def test_assume_unchanged_and_arbitrary_lock_are_rejected(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    subprocess.run(["git", "update-index", "--assume-unchanged", "src/aoi_orgware/core.py"], cwd=tmp_path, check=True)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="assume-unchanged"):
        _combine(tmp_path, canonical, covdata)
    subprocess.run(["git", "update-index", "--no-assume-unchanged", "src/aoi_orgware/core.py"], cwd=tmp_path, check=True)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="repository pinned lock"):
        combine_coverage.combine(data_dir=covdata, source_root=canonical, output_file=covdata / ".coverage", receipt_file=covdata / "coverage-provenance.json", lock_path=tmp_path / "other.lock", repo_root=tmp_path)


def test_non_python_package_drift_is_rejected(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    (roots[1] / "package-data.txt").write_text("not allowed\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="diverges"):
        _combine(tmp_path, canonical, covdata)


def test_nested_clean_git_manifest_uses_global_relative_path_order(tmp_path: Path) -> None:
    canonical = _tree(tmp_path)
    nested = canonical / "nested"
    nested.mkdir()
    (nested / "alpha.py").write_text("ALPHA = 1\n", encoding="utf-8")
    (nested / "omega.py").write_text("OMEGA = 1\n", encoding="utf-8")
    _init_git(tmp_path)

    live = combine_coverage._tree_manifest(canonical)
    assert [entry.relative for entry in live] == [
        "__init__.py",
        "core.py",
        "nested",
        "nested/alpha.py",
        "nested/omega.py",
        "sentinel.py",
    ]
    assert combine_coverage._git_worktree_manifest(tmp_path, canonical) == combine_coverage._git_package_manifest(tmp_path)


def test_tree_manifest_includes_stable_nested_and_empty_directories(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    nested = root / "nested"
    nested.mkdir()
    (nested / "alpha.py").write_text("ALPHA = 1\n", encoding="utf-8")
    (root / "empty").mkdir()

    manifest = combine_coverage._tree_manifest(root)
    assert [(entry.relative, entry.kind) for entry in manifest] == [
        ("__init__.py", "file"),
        ("core.py", "file"),
        ("empty", "directory"),
        ("nested", "directory"),
        ("nested/alpha.py", "file"),
        ("sentinel.py", "file"),
    ]
    assert next(entry for entry in manifest if entry.relative == "core.py").sha256 == combine_coverage._sha256(root / "core.py")


def test_extra_empty_live_directory_differs_from_git_tree(tmp_path: Path) -> None:
    canonical, _, _ = _fixture(tmp_path)
    (canonical / "extra-empty").mkdir()
    assert combine_coverage._git_worktree_manifest(tmp_path, canonical) != combine_coverage._git_package_manifest(tmp_path)


def test_input_set_race_is_rejected(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)

    def add_input() -> None:
        _data(covdata / ".coverage.race", [roots[1] / "core.py"])

    with pytest.raises(combine_coverage.CoverageProvenanceError, match="input set changed"):
        _combine(tmp_path, canonical, covdata, between_manifests=add_input)


def test_child_only_sentinel_contribution_survives_canonical_mapping(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    _data(covdata / ".coverage.1", [roots[1] / "sentinel.py"])
    receipt = _combine(tmp_path, canonical, covdata)
    combined = combine_coverage.CoverageData(basename=str(_published_output(covdata, receipt)))
    combined.read()
    assert str((canonical / "sentinel.py").absolute()) in combined.measured_files()
    assert all(str(canonical) in filename for filename in combined.measured_files())


def test_tool_drift_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    monkeypatch.setattr(combine_coverage, "EXPECTED_COVERAGE_VERSION", "0.0.0")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="toolchain drift"):
        REAL_VALIDATE_TOOLCHAIN(tmp_path / "requirements" / "coverage-tools.lock")
    assert not [path for path in covdata.glob(".coverage.*") if len(path.name.rsplit(".", 1)[-1]) == 64]


def test_failure_preserves_existing_unowned_publications(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    output = covdata / ".coverage"
    receipt = covdata / "coverage-provenance.json"
    output.write_bytes(b"old output")
    receipt.write_text("old receipt\n", encoding="utf-8")
    (roots[1] / "core.py").write_text("def core():\n    return 9\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="diverges"):
        _combine(tmp_path, canonical, covdata)
    assert output.read_bytes() == b"old output"
    assert receipt.read_text(encoding="utf-8") == "old receipt\n"


def test_semantic_data_from_all_roots_is_mapped_with_lines_arcs_and_contexts(tmp_path: Path) -> None:
    canonical, roots, covdata = _fixture(tmp_path)
    for index, root in enumerate(roots):
        data = combine_coverage.CoverageData(basename=str(covdata / f".coverage.{index}"))
        data.set_context("shared")
        data.add_arcs({str((root / "core.py").absolute()): {(1, 2)}})
        data.write()
    receipt = _combine(tmp_path, canonical, covdata)
    combined = combine_coverage.CoverageData(basename=str(_published_output(covdata, receipt)))
    combined.read()
    core = str((canonical / "core.py").absolute())
    assert combined.lines(core) == [1, 2]
    assert combined.arcs(core) == [(1, 2)]
    assert combined.contexts_by_lineno(core) == {1: ["shared"], 2: ["shared"]}
    assert receipt["canonical_payload"]["combined_semantic_sha256"]


def test_sitecustomize_binding_is_hashed_and_validated(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    sitecustomize = tmp_path.parent / "coverage-sitecustomize.py"
    sitecustomize.write_text("import coverage\ncoverage.process_startup()\n", encoding="utf-8")
    receipt = _combine(tmp_path, canonical, covdata, sitecustomize=sitecustomize)
    assert receipt["canonical_payload"]["sitecustomize_sha256"] == combine_coverage._sha256(sitecustomize)
    sitecustomize.write_text("pass\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="does not start coverage"):
        _combine(tmp_path, canonical, covdata, sitecustomize=sitecustomize)
    assert _published_output(covdata, receipt).exists()
    assert (covdata / "coverage-provenance.json").exists()


def test_output_alias_to_source_is_rejected_without_mutation(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    source = canonical / "core.py"
    original = source.read_bytes()
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="outside|overlaps|aliases"):
        _combine(tmp_path, canonical, covdata, output_file=source, output_root=covdata)
    assert source.read_bytes() == original


@pytest.mark.parametrize("target", ["output_file", "receipt_file"])
def test_windows_named_stream_on_protected_input_is_rejected_before_mutation(tmp_path: Path, target: str) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    source = canonical / "core.py"
    original = source.read_bytes()
    kwargs: dict[str, object] = {
        target: source.with_name(f"{source.name}:coverage-provenance"),
        "output_root": covdata,
    }

    with pytest.raises(combine_coverage.CoverageProvenanceError, match="named stream"):
        _combine(tmp_path, canonical, covdata, **kwargs)
    assert source.read_bytes() == original
    assert not [path for path in covdata.glob(".coverage.*") if len(path.name.rsplit(".", 1)[-1]) == 64]
    assert not (covdata / "coverage-provenance.json").exists()
    assert not subprocess.run(["git", "status", "--porcelain"], cwd=tmp_path, check=True, capture_output=True, text=True).stdout


@pytest.mark.parametrize("alias", [r"\\?\C:\coverage-output", r"\\.\C:\coverage-output", r"\??\C:\coverage-output"])
def test_windows_namespace_output_root_is_rejected_before_staging(tmp_path: Path, alias: str) -> None:
    canonical, _, covdata = _fixture(tmp_path)

    with pytest.raises(combine_coverage.CoverageProvenanceError, match="namespace alias"):
        _combine(tmp_path, canonical, covdata, output_root=Path(alias))
    assert not [path for path in covdata.glob(".coverage.*") if len(path.name.rsplit(".", 1)[-1]) == 64]
    assert not (covdata / "coverage-provenance.json").exists()


@pytest.mark.parametrize("argument", ["data_dir", "source_root", "lock_path", "repo_root", "sitecustomize"])
@pytest.mark.parametrize("spelling", ["named-stream", "namespace"])
def test_windows_ingress_aliases_are_rejected_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argument: str,
    spelling: str,
) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    lock_path = tmp_path / "requirements" / "coverage-tools.lock"
    if spelling == "namespace":
        alias = Path(r"\\?\C:\aoi-coverage-ingress")
        expected = "namespace alias"
    else:
        aliases = {
            "data_dir": covdata.with_name(f"{covdata.name}:coverage-provenance"),
            "source_root": canonical.with_name(f"{canonical.name}:coverage-provenance"),
            "lock_path": lock_path.with_name(f"{lock_path.name}:coverage-provenance"),
            "repo_root": tmp_path / "repository:coverage-provenance",
            "sitecustomize": tmp_path / "sitecustomize.py:coverage-provenance",
        }
        alias = aliases[argument]
        expected = "named stream"

    def staging_must_not_start(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("Windows alias must be rejected before staging")

    monkeypatch.setattr(combine_coverage.tempfile, "mkdtemp", staging_must_not_start)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match=expected):
        _combine(tmp_path, canonical, covdata, **{argument: alias})
    assert not [path for path in covdata.glob(".coverage.*") if len(path.name.rsplit(".", 1)[-1]) == 64]
    assert not (covdata / "coverage-provenance.json").exists()


@pytest.mark.parametrize("target", ["output_root", "output_file", "receipt_file"])
def test_publication_path_traversal_is_rejected_before_staging_or_mutation(tmp_path: Path, target: str) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    source = canonical / "core.py"
    original = source.read_bytes()
    outside = tmp_path / "outside.json"
    kwargs: dict[str, object] = {}
    if target == "output_root":
        kwargs["output_root"] = covdata / ".." / "src" / "aoi_orgware"
    elif target == "output_file":
        kwargs["output_file"] = covdata / ".." / "outside.json"
    else:
        kwargs["receipt_file"] = covdata / ".." / "outside.json"
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="traversal"):
        _combine(tmp_path, canonical, covdata, **kwargs)
    assert source.read_bytes() == original
    assert not outside.exists()
    assert not [path for path in covdata.glob(".coverage.*") if len(path.name.rsplit(".", 1)[-1]) == 64]
    assert not (covdata / "coverage-provenance.json").exists()
    assert not subprocess.run(["git", "status", "--porcelain"], cwd=tmp_path, check=True, capture_output=True, text=True).stdout


def test_resolved_publication_escape_is_rejected_without_mutation(tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    escaped = covdata / "escape"
    try:
        escaped.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("current Windows policy does not permit test symlinks")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="symlink|reparse"):
        _combine(
            tmp_path,
            canonical,
            covdata,
            output_file=escaped / ".coverage",
            receipt_file=escaped / "coverage-provenance.json",
        )
    assert not list(outside.iterdir())


@pytest.mark.parametrize("mutation", ["source", "lock", "receipt"])
def test_post_validation_mutation_is_rejected_before_publication(tmp_path: Path, mutation: str) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    receipt = covdata / "coverage-provenance.json"

    def mutate() -> None:
        if mutation == "source":
            (canonical / "core.py").write_text("def core():\n    return 9\n", encoding="utf-8")
        elif mutation == "lock":
            (tmp_path / "requirements" / "coverage-tools.lock").write_text("tampered\n", encoding="utf-8")
        else:
            receipt.write_text("attacker receipt\n", encoding="utf-8")

    with pytest.raises(combine_coverage.CoverageProvenanceError):
        _combine(tmp_path, canonical, covdata, before_publication=mutate)
    if mutation == "receipt":
        assert receipt.read_text(encoding="utf-8") == "attacker receipt\n"
    else:
        assert not receipt.exists()


@pytest.mark.parametrize("mutation", ["source", "lock"])
def test_post_output_publication_mutation_preserves_unreceipted_orphan(tmp_path: Path, mutation: str) -> None:
    canonical, _, covdata = _fixture(tmp_path)

    def mutate() -> None:
        if mutation == "source":
            (canonical / "core.py").write_text("def core():\n    return 9\n", encoding="utf-8")
        else:
            (tmp_path / "requirements" / "coverage-tools.lock").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(combine_coverage.CoverageProvenanceError):
        _combine(tmp_path, canonical, covdata, after_output_publication=mutate)
    assert len([path for path in covdata.glob(".coverage.*") if len(path.name.rsplit(".", 1)[-1]) == 64]) == 1
    assert not (covdata / "coverage-provenance.json").exists()


def test_write_failure_does_not_unlink_pathname_swapped_after_o_excl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "published"
    source = tmp_path / "protected-source"
    source.write_text("do not delete\n", encoding="utf-8")

    def fail_after_swap(descriptor: int, _mode: str) -> object:
        class FailingOutput:
            def __enter__(self) -> "FailingOutput":
                return self

            def __exit__(self, *_args: object) -> bool:
                return False

            def write(self, _payload: bytes) -> int:
                os.close(descriptor)
                target.unlink()
                source.replace(target)
                raise OSError("injected write failure")

            def flush(self) -> None:
                raise AssertionError("write must fail first")

            def fileno(self) -> int:
                return descriptor

        return FailingOutput()

    monkeypatch.setattr(combine_coverage.os, "fdopen", fail_after_swap)
    with pytest.raises(OSError, match="injected write failure"):
        combine_coverage._publish_no_replace(target, b"new output", "test publication")
    assert target.read_text(encoding="utf-8") == "do not delete\n"


def test_readback_failure_never_runs_post_close_identity_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    protected = tmp_path.parent / f"{tmp_path.name}-protected-source"
    protected.write_text("do not delete\n", encoding="utf-8")
    original_identity = combine_coverage._identity
    output_identity_calls = 0
    receipt_identity_calls = 0

    def swap_on_obsolete_cleanup(path: Path, label: str) -> tuple[int, int, int, str]:
        nonlocal output_identity_calls, receipt_identity_calls
        identity = original_identity(path, label)
        if label == "combined coverage output":
            output_identity_calls += 1
            if output_identity_calls == 3:
                path.unlink()
                protected.replace(path)
            return identity
        if label == "coverage receipt":
            receipt_identity_calls += 1
            if receipt_identity_calls == 2:
                return (*identity[:3], "0" * 64)
        return identity

    monkeypatch.setattr(combine_coverage, "_identity", swap_on_obsolete_cleanup)
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="readback"):
        _combine(tmp_path, canonical, covdata)

    assert output_identity_calls == 2
    assert protected.read_text(encoding="utf-8") == "do not delete\n"


class _FakeDistribution:
    def __init__(self, root: Path, version: str) -> None:
        self.root = root
        self.version = version
        self.files = [Path("fake-1.0.dist-info/RECORD")]

    def locate_file(self, path: object) -> Path:
        return self.root / str(path)


def _write_fake_record(root: Path, contents: bytes = b"VALUE = 1\n") -> Path:
    module = root / "fake" / "__init__.py"
    module.parent.mkdir(parents=True)
    module.write_bytes(contents)
    dist = root / "fake-1.0.dist-info"
    dist.mkdir()
    digest = base64.urlsafe_b64encode(combine_coverage.hashlib.sha256(contents).digest()).decode().rstrip("=")
    (dist / "RECORD").write_text(
        f"fake/__init__.py,sha256={digest},{len(contents)}\nfake-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    return module


def test_fake_record_and_tool_file_tamper_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _write_fake_record(tmp_path)
    fake = _FakeDistribution(tmp_path, "1.0")
    monkeypatch.setattr(combine_coverage, "distribution", lambda _name: fake)
    validated = combine_coverage._validate_distribution("fake", "1.0", str(module))
    assert validated["record_entries"] == 2
    module.write_text("VALUE = 9\n", encoding="utf-8")
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="payload mismatch"):
        combine_coverage._validate_distribution("fake", "1.0", str(module))


def test_fake_record_missing_hash_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _write_fake_record(tmp_path)
    record = tmp_path / "fake-1.0.dist-info" / "RECORD"
    record.write_text("fake/__init__.py,,10\nfake-1.0.dist-info/RECORD,,\n", encoding="utf-8")
    monkeypatch.setattr(combine_coverage, "distribution", lambda _name: _FakeDistribution(tmp_path, "1.0"))
    with pytest.raises(combine_coverage.CoverageProvenanceError, match="lacks sha256/size"):
        combine_coverage._validate_distribution("fake", "1.0", str(module))


def test_record_generated_bytecode_without_hash_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _write_fake_record(tmp_path)
    cache = tmp_path / "fake" / "__pycache__"
    cache.mkdir()
    (cache / "__init__.cpython-314.pyc").write_bytes(b"generated")
    record = tmp_path / "fake-1.0.dist-info" / "RECORD"
    record.write_text(
        record.read_text(encoding="utf-8") + "fake/__pycache__/__init__.cpython-314.pyc,,\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(combine_coverage, "distribution", lambda _name: _FakeDistribution(tmp_path, "1.0"))
    validated = combine_coverage._validate_distribution("fake", "1.0", str(module))
    assert validated["record_entries"] == 2


def test_live_installed_toolchain_matches_lock_and_validates_wheel_records(live_toolchain: None) -> None:
    validated = REAL_VALIDATE_TOOLCHAIN(
        Path(__file__).resolve().parents[1] / "requirements" / "coverage-tools.lock"
    )
    assert validated["coverage"] == "7.15.2"
    assert validated["pytest"] == "9.1.1"
    assert {row["name"] for row in validated["records"]} == {
        "coverage",
        "colorama",
        "iniconfig",
        "packaging",
        "pluggy",
        "pygments",
        "pytest",
    }


def test_live_installed_toolchain_combines_fixture(live_toolchain: None, tmp_path: Path) -> None:
    canonical, _, covdata = _fixture(tmp_path)
    receipt = _combine(tmp_path, canonical, covdata)
    assert _published_output(covdata, receipt).is_file()


def test_synthetic_below_80_percent_remains_a_coverage_failure(tmp_path: Path) -> None:
    source = tmp_path / "low.py"
    source.write_text("a = 1\nb = 2\nc = 3\nd = 4\n", encoding="utf-8")
    data_file = tmp_path / ".coverage"
    data = combine_coverage.CoverageData(basename=str(data_file))
    data.add_lines({str(source.absolute()): {1}})
    data.write()
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "report", "--fail-under=80"],
        cwd=tmp_path,
        env={**os.environ, "COVERAGE_FILE": str(data_file)},
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
