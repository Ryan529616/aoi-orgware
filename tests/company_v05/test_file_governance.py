"""AOI-SYNTHETIC-FIXTURE-V1 tests for deterministic file governance."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from aoi_orgware.company.file_governance import (
    BASELINE_RESOURCE_PATH,
    SYNTHETIC_FIXTURE_MARKER,
    ActiveWriteRefV1,
    ExactExclusionV1,
    FileGovernanceError,
    FileGovernanceWaiverV1,
    GitBlob,
    GitScopeSnapshot,
    GovernanceReport,
    ImportBoundaryRuleV1,
    PrivacyCount,
    _evaluate_verified_candidate,
    baseline_manifest_bytes,
    build_baseline_manifest,
    load_packaged_baseline,
    logical_line_count,
    normalize_repo_identity,
    normalize_repo_path,
    parse_baseline_manifest,
    scan_privacy_counts,
    snapshot_file,
)
from aoi_orgware.company.file_governance_io import (
    _run_git,
    build_baseline_from_git,
    evaluate_file_governance,
    read_git_commit_scope,
    read_worktree_scope,
    verify_baseline_against_git,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCEPTED_COMMIT = "95c6ba0a364f749d55deb9d46eabb965577360c9"
ACCEPTED_TREE = "c4592610a855009f7eeffa32f5d19477f8c5f084"
OBSERVED_AT = datetime(2026, 7, 28, 15, 0, tzinfo=timezone.utc)
SELF_ONLY = (
    ExactExclusionV1(
        BASELINE_RESOURCE_PATH,
        "generated",
        "self-describing deterministic test baseline",
        True,
    ),
)


def _scope(files: dict[str, bytes]) -> GitScopeSnapshot:
    return GitScopeSnapshot(
        "1" * 40,
        "2" * 40,
        {path: GitBlob("100644", data) for path, data in files.items()},
    )


def _baseline(files: dict[str, bytes]) -> tuple[dict[str, object], bytes]:
    manifest = build_baseline_manifest(_scope(files), exclusions=SELF_ONLY)
    return manifest, baseline_manifest_bytes(manifest)


def _current(
    baseline_wire: bytes,
    files: dict[str, bytes],
) -> dict[str, GitBlob]:
    result = {
        path: GitBlob("100644", data) for path, data in files.items()
    }
    result[BASELINE_RESOURCE_PATH] = GitBlob("100644", baseline_wire)
    return result


def _pure_report(
    manifest: dict[str, object],
    wire: bytes,
    files: dict[str, bytes],
    *,
    waivers: tuple[FileGovernanceWaiverV1, ...] = (),
    known_values: tuple[tuple[str, bytes | str], ...] = (),
) -> GovernanceReport:
    return _evaluate_verified_candidate(
        baseline=manifest,
        current_files=_current(wire, files),
        release="0.5.0a1",
        observed_at=OBSERVED_AT,
        waivers=waivers,
        known_values=known_values,
    )


def _waiver(
    *,
    waiver_id: str = "waiver-1",
    path: str = "src/new.py",
    rule_id: str = "new_file_target_exceeded",
    maximum_lines: int = 900,
    maximum_bytes: int = 100_000,
) -> FileGovernanceWaiverV1:
    return FileGovernanceWaiverV1(
        waiver_id=waiver_id,
        path=path,
        rule_id=rule_id,
        owner="company-core-owner",
        reason="Bounded extraction follow-up is already assigned.",
        expires_at="2026-07-29T00:00:00Z",
        followup="followup-file-split",
        applies_to_release="0.5.0a1",
        max_logical_lines=maximum_lines,
        max_size_bytes=maximum_bytes,
    )


def _git(
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_bytes,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.decode("utf-8").strip()


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "aoi-test@example.invalid")
    _git(root, "config", "user.name", "AOI Test")


def test_path_and_logical_line_contract_is_platform_independent() -> None:
    assert normalize_repo_path("src/a.py") == "src/a.py"
    assert normalize_repo_identity("pyproject.toml") == "pyproject.toml"
    with pytest.raises(FileGovernanceError):
        normalize_repo_path("pyproject.toml")
    for path in (
        r"src\a.py",
        "/src/a.py",
        "C:/src/a.py",
        "src//a.py",
        "src/../a.py",
        "src/con.txt",
        "src/name:stream",
        "src/progra~1/a.py",
        "src/trailing./a.py",
        "src/e\u0301.py",
    ):
        with pytest.raises(FileGovernanceError):
            normalize_repo_path(path)
    assert logical_line_count(b"") == 0
    assert logical_line_count(b"a") == 1
    assert logical_line_count(b"a\n") == 1
    assert logical_line_count(b"a\nb") == 2
    for content in (b"a\rb", b"a\vb", b"a\fb", "a\u2028b".encode()):
        with pytest.raises(FileGovernanceError):
            snapshot_file("src/a.py", GitBlob("100644", content))


def test_manifest_is_canonical_deterministic_and_alias_safe() -> None:
    first = _scope({"tests/z.py": b"z\n", "docs/a.md": b"a\n"})
    second = _scope({"docs/a.md": b"a\n", "tests/z.py": b"z\n"})
    left = build_baseline_manifest(first, exclusions=SELF_ONLY)
    right = build_baseline_manifest(second, exclusions=SELF_ONLY)
    assert baseline_manifest_bytes(left) == baseline_manifest_bytes(right)
    assert parse_baseline_manifest(baseline_manifest_bytes(left)) == left
    assert left["accepted_commit_sha1"] == "1" * 40
    assert left["accepted_tree_sha1"] == "2" * 40
    with pytest.raises(FileGovernanceError, match="duplicate"):
        parse_baseline_manifest(b'{"x":1,"x":2}\n')
    tampered = dict(left)
    tampered["accepted_tree_sha1"] = "3" * 40
    wire = (
        json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )
    with pytest.raises(FileGovernanceError, match="digest"):
        parse_baseline_manifest(wire)
    collision = _scope({"src/A.py": b"a\n", "src/a.py": b"a\n"})
    with pytest.raises(FileGovernanceError, match="collision"):
        build_baseline_manifest(collision, exclusions=SELF_ONLY)


def test_exact_exclusion_does_not_hide_a_resource_subtree() -> None:
    exclusion = ExactExclusionV1(
        "src/generated/schema.json",
        "generated",
        "synthetic generator receipt for one exact schema",
    )
    snapshot = _scope({
        "src/generated/schema.json": b"{}\n",
        "src/generated/hand_authored.py": b"x = 1\n",
    })
    manifest = build_baseline_manifest(
        snapshot,
        exclusions=(exclusion, *SELF_ONLY),
    )
    assert [item["path"] for item in manifest["files"]] == [
        "src/generated/hand_authored.py"
    ]
    assert manifest["totals"]["tracked_file_count"] == 2
    with pytest.raises(FileGovernanceError, match="missing exact"):
        build_baseline_manifest(_scope({}), exclusions=(exclusion, *SELF_ONLY))


def test_self_exclusion_supports_two_baseline_generations() -> None:
    files = {"src/base.py": b"x = 1\n"}
    _manifest_zero, wire_zero = _baseline(files)
    generation_one = build_baseline_manifest(
        _scope({**files, BASELINE_RESOURCE_PATH: wire_zero}),
        exclusions=SELF_ONLY,
    )
    wire_one = baseline_manifest_bytes(generation_one)
    self_entry = generation_one["exact_exclusions"][0]
    assert self_entry["self_unbound"] is True
    assert self_entry["baseline_size_bytes"] == len(wire_zero)
    assert self_entry["baseline_sha256"] is not None
    assert _pure_report(generation_one, wire_one, files).accepted
    stale = _pure_report(generation_one, wire_zero, files)
    assert {item.rule_id for item in stale.errors} == {
        "baseline_identity_mismatch"
    }


def test_privacy_roots_boundaries_and_synthetic_scope() -> None:
    windows_root = ("C:" + "\\Users\\" + "operator-secret").encode()
    posix_root = ("/home/" + "operator-secret").encode()
    license_value = ("27000" + "@" + "license.internal").encode()
    assert scan_privacy_counts("docs/a.md", windows_root) == (
        PrivacyCount("windows_user_home", 1),
    )
    assert scan_privacy_counts("docs/a.md", posix_root) == (
        PrivacyCount("posix_user_home", 1),
    )
    root_home = ("/" + "root/private/service.conf").encode()
    assert scan_privacy_counts("docs/a.md", root_home) == (
        PrivacyCount("posix_user_home", 1),
    )
    assert not scan_privacy_counts("docs/a.md", b"/rooted/a\n/rootless\n")
    assert scan_privacy_counts("docs/a.md", license_value) == (
        PrivacyCount("license_endpoint", 1),
    )
    endpoint_host = b"license" + b".internal"
    endpoint_values = (
        b"9@" + endpoint_host + b" 65535@" + endpoint_host
        + b" 0@" + b"bad" + b" 65536@" + b"bad"
    )
    assert scan_privacy_counts("docs/a.md", endpoint_values) == (
        PrivacyCount("license_endpoint", 2),
    )
    marker = (SYNTHETIC_FIXTURE_MARKER + "\n").encode()
    synthetic = marker + b"C:\\Users\\alice\n27000@license.example\n"
    assert scan_privacy_counts("tests/fixture.txt", synthetic) == ()
    not_synthetic = marker + windows_root + b"\n" + license_value
    counts = scan_privacy_counts("tests/fixture.txt", not_synthetic)
    assert counts == (
        PrivacyCount("license_endpoint", 1),
        PrivacyCount("windows_user_home", 1),
    )
    secret = ("private-" + "deployment-value").encode()
    external = scan_privacy_counts(
        "tests/fixture.txt",
        marker + secret,
        known_values=(("opaque-rule", secret),),
    )
    assert external == (PrivacyCount("known:opaque-rule", 1),)
    rendered = json.dumps([
        {"rule_id": item.rule_id, "count": item.count} for item in external
    ])
    assert secret.decode() not in rendered
    assert "VM GPU VRAM license execution pool" and not scan_privacy_counts(
        "docs/generic.md",
        b"VM GPU VRAM license execution pool\n",
    )


def test_privacy_debt_requires_unchanged_file_or_strict_reduction() -> None:
    old_value = ("C:" + "\\Users\\" + "old-operator").encode()
    replacement = ("C:" + "\\Users\\" + "new-operator").encode()
    manifest, wire = _baseline({"docs/debt.md": old_value + b"\n"})
    assert _pure_report(
        manifest, wire, {"docs/debt.md": old_value + b"\n"}
    ).accepted
    replaced = _pure_report(
        manifest, wire, {"docs/debt.md": replacement + b"\n"}
    )
    assert {item.rule_id for item in replaced.errors} == {
        "privacy_debt_file_changed"
    }
    assert _pure_report(
        manifest, wire, {"docs/debt.md": b"generic policy\n"}
    ).accepted
    copied = _pure_report(
        manifest,
        wire,
        {
            "docs/debt.md": old_value + b"\n",
            "docs/copied.md": old_value + b"\n",
        },
    )
    assert "deployment_value" in {item.rule_id for item in copied.errors}


def test_new_file_target_waiver_is_visible_and_hard_cap_is_absolute() -> None:
    manifest, wire = _baseline({"src/base.py": b"x = 1\n"})
    assert _pure_report(
        manifest, wire, {"src/new.py": b"x\n" * 800}
    ).accepted
    target_miss = _pure_report(
        manifest, wire, {"src/new.py": b"x\n" * 801}
    )
    assert {item.rule_id for item in target_miss.errors} == {
        "new_file_target_exceeded"
    }
    waiver = _waiver()
    waived = _pure_report(
        manifest,
        wire,
        {"src/new.py": b"x\n" * 801},
        waivers=(waiver,),
    )
    assert waived.accepted and not waived.errors
    assert waived.warnings[0].waiver_id == waiver.waiver_id
    assert len(waived.warnings[0].waiver_sha256) == 64
    hard = _pure_report(
        manifest,
        wire,
        {"src/new.py": b"x\n" * 1501},
        waivers=(waiver,),
    )
    assert not hard.accepted
    assert {item.rule_id for item in hard.errors} == {"new_file_hard_limit"}
    with pytest.raises(FileGovernanceError, match="non-waivable"):
        _waiver(rule_id="new_file_hard_limit")


def test_duplicate_and_overlapping_waivers_are_order_independent_errors() -> None:
    manifest, wire = _baseline({"src/base.py": b"x\n"})
    first = _waiver(waiver_id="waiver-a")
    overlap = _waiver(waiver_id="waiver-b")
    current = {"src/new.py": b"x\n" * 801}
    for ordered in ((first, overlap), (overlap, first)):
        with pytest.raises(FileGovernanceError, match="overlapping"):
            _pure_report(manifest, wire, current, waivers=ordered)
    duplicate_id = _waiver(
        waiver_id="waiver-a",
        path="tests/new.py",
    )
    with pytest.raises(FileGovernanceError, match="duplicate"):
        _pure_report(
            manifest,
            wire,
            current,
            waivers=(first, duplicate_id),
        )


def test_current_baseline_resource_must_equal_trusted_baseline_bytes() -> None:
    files = {"src/base.py": b"x\n"}
    manifest, wire = _baseline(files)
    alternate = build_baseline_manifest(
        _scope(files),
        exclusions=(
            ExactExclusionV1(
                BASELINE_RESOURCE_PATH,
                "generated",
                "alternate self-describing deterministic test baseline",
                True,
            ),
        ),
    )
    report = _evaluate_verified_candidate(
        baseline=manifest,
        current_files=_current(baseline_manifest_bytes(alternate), files),
        release="0.5.0a1",
        observed_at=OBSERVED_AT,
    )
    assert not report.accepted
    assert {item.rule_id for item in report.errors} == {
        "baseline_identity_mismatch"
    }


def test_existing_over_target_files_ratchet_lines_and_bytes_separately() -> None:
    base = b"long-line\n" * 801
    manifest, wire = _baseline({"src/large.py": base})
    byte_growth = b"longer-line\n" + b"long-line\n" * 800
    report = _pure_report(
        manifest, wire, {"src/large.py": byte_growth}
    )
    assert {item.rule_id for item in report.errors} == {
        "existing_over_target_byte_growth"
    }
    line_growth = b"\n" * 802
    report = _pure_report(
        manifest, wire, {"src/large.py": line_growth}
    )
    assert {item.rule_id for item in report.errors} == {
        "existing_over_target_line_growth"
    }
    renamed = _pure_report(
        manifest, wire, {"src/renamed.py": b"x\n" * 801}
    )
    assert {item.rule_id for item in renamed.errors} == {
        "new_file_target_exceeded"
    }


def test_reserved_contracts_are_strict_and_repo_wide() -> None:
    rule = ImportBoundaryRuleV1(
        1,
        "company-boundary",
        "aoi_orgware.company",
        ("aoi_orgware.company", "aoi_orgware.harnesslib"),
        True,
    )
    assert rule.forbid_cycles
    with pytest.raises(TypeError):
        ImportBoundaryRuleV1(  # type: ignore[call-arg]
            1,
            "company-boundary",
            "aoi_orgware.company",
            ("aoi_orgware.company",),
            True,
            unexpected=True,
        )
    ref = ActiveWriteRefV1(
        1,
        "file",
        "repo",
        "pyproject.toml",
        "windows-win32-v1",
    )
    assert ref.canonical_identity == "pyproject.toml"
    with pytest.raises(FileGovernanceError):
        ActiveWriteRefV1(
            1,
            "file",
            "repo",
            r"scripts\gate.py",
            "windows-win32-v1",
        )
    assert ActiveWriteRefV1(
        1,
        "serialization_key",
        "company",
        "ledger-writer",
        "opaque-v1",
    ).canonical_identity == "ledger-writer"


def test_ls_tree_reader_ignores_export_ignore_and_verifies_exact_tree(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    (root / "docs").mkdir()
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / ".gitattributes").write_text(
        "docs/hidden.md export-ignore\n",
        encoding="utf-8",
    )
    (root / "docs/hidden.md").write_text("tracked\n", encoding="utf-8")
    (root / "src/a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "tests/test_a.py").write_text("def test_a(): pass\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "baseline")
    commit = _git(root, "rev-parse", "HEAD")
    snapshot = read_git_commit_scope(root, commit)
    assert "docs/hidden.md" in snapshot.files
    manifest = build_baseline_from_git(
        root,
        commit,
        exclusions=SELF_ONLY,
    )
    wire = baseline_manifest_bytes(manifest)
    assert verify_baseline_against_git(root, wire) == manifest
    forged_files = dict(snapshot.files)
    forged_files["src/a.py"] = GitBlob("100644", b"forged = 1\n")
    forged = build_baseline_manifest(
        GitScopeSnapshot(commit, snapshot.tree_sha1, forged_files),
        exclusions=SELF_ONLY,
    )
    with pytest.raises(FileGovernanceError, match="exact Git tree"):
        verify_baseline_against_git(root, baseline_manifest_bytes(forged))
    safe = evaluate_file_governance(
        root,
        baseline=wire,
        current_files=_current(wire, {}),
        release="0.5.0a1",
        observed_at=OBSERVED_AT,
        import_rules=(),
    )
    assert safe.accepted


def test_public_gate_composes_exact_git_and_import_policy(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    source = root / "src/aoi_orgware/company/worker.py"
    source.parent.mkdir(parents=True)
    source.write_text("import aoi_orgware.ledger\n", encoding="utf-8")
    (root / "src/aoi_orgware/ledger.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "baseline")
    commit = _git(root, "rev-parse", "HEAD")
    snapshot = read_git_commit_scope(root, commit)
    manifest = build_baseline_from_git(root, commit, exclusions=SELF_ONLY)
    wire = baseline_manifest_bytes(manifest)
    current = dict(snapshot.files)
    current[BASELINE_RESOURCE_PATH] = GitBlob("100644", wire)
    report = evaluate_file_governance(
        root,
        baseline=wire,
        current_files=current,
        release="0.5.0a1",
        observed_at=OBSERVED_AT,
        import_rules=(
            ImportBoundaryRuleV1(
                1,
                "company-boundary-test",
                "aoi_orgware.company",
                ("aoi_orgware.company",),
                True,
            ),
        ),
    )
    assert not report.accepted
    assert {item.rule_id for item in report.errors} == {
        "import_boundary:company-boundary-test"
    }


def test_ls_tree_rejects_tracked_symlink_mode(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    (root / "tests").mkdir()
    (root / "tests/a.py").write_text("x = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "base")
    oid = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"tests/a.py")
    _git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{oid},tests/link.py",
    )
    _git(root, "commit", "-q", "-m", "link")
    with pytest.raises(FileGovernanceError, match="non-regular"):
        read_git_commit_scope(root, _git(root, "rev-parse", "HEAD"))


def test_worktree_reader_requires_exact_ignored_allowlist(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    for name in ("docs", "src", "tests"):
        (root / name).mkdir()
    (root / ".gitignore").write_text("tests/ignored.py\n", encoding="utf-8")
    (root / "src/a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "tests/test_a.py").write_text("def test_a(): pass\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "base")
    (root / "docs/untracked.md").write_text("candidate\n", encoding="utf-8")
    (root / "tests/ignored.py").write_text("runtime\n", encoding="utf-8")
    with pytest.raises(FileGovernanceError, match="ignored"):
        read_worktree_scope(root)
    files = read_worktree_scope(
        root,
        exact_ignored_allowlist=("tests/ignored.py",),
    )
    assert "docs/untracked.md" in files
    assert "tests/ignored.py" not in files
    with pytest.raises(FileGovernanceError, match="ignored"):
        read_worktree_scope(
            root,
            exact_ignored_allowlist=(
                "tests/ignored.py",
                "tests/not-present.py",
            ),
        )


def test_worktree_reader_rejects_broken_untracked_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    for name in ("docs", "src", "tests"):
        (root / name).mkdir()
    link = root / "src/broken.py"
    try:
        os.symlink(
            root / "missing-target.py",
            link,
            target_is_directory=False,
        )
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")
    assert not link.exists() and os.path.lexists(link)
    with pytest.raises(FileGovernanceError, match="link/reparse"):
        read_worktree_scope(root)


def test_git_reader_streams_to_a_strict_output_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    oid = _git(
        root,
        "hash-object",
        "-w",
        "--stdin",
        input_bytes=b"x" * (1024 * 1024),
    )

    def forbidden_full_capture(*args: object, **kwargs: object) -> object:
        raise AssertionError("subprocess.run would capture unbounded output")

    monkeypatch.setattr(subprocess, "run", forbidden_full_capture)
    with pytest.raises(FileGovernanceError, match="bounded Git observation"):
        _run_git(
            root,
            ("cat-file", "blob", oid),
            timeout=10,
            output_limit=1024,
        )


def test_packaged_baseline_covers_source_docs_tests_and_exact_counts() -> None:
    packaged = load_packaged_baseline()
    assert packaged["accepted_commit_sha1"] == ACCEPTED_COMMIT
    assert packaged["accepted_tree_sha1"] == ACCEPTED_TREE
    assert packaged["totals"] == {
        "excluded_file_count": 2,
        "hand_authored_file_count": 315,
        "hand_authored_logical_lines": 264890,
        "hand_authored_size_bytes": 10829305,
        "legacy_privacy_finding_count": 160,
        "tracked_file_count": 317,
        "tracked_size_bytes": 11357346,
    }
    paths = {item["path"] for item in packaged["files"]}
    assert {
        "docs/v0.5-plan.md",
        "src/aoi_orgware/company/supervisor.py",
        "tests/test_cli.py",
    } <= paths
    wire = (
        REPO_ROOT
        / "src/aoi_orgware/resources/company/file-governance-baseline-v1.json"
    ).read_bytes()
    assert verify_baseline_against_git(REPO_ROOT, wire) == packaged


def test_new_hand_authored_p0_files_meet_the_800_line_target() -> None:
    paths = (
        REPO_ROOT / "src/aoi_orgware/company/file_governance.py",
        REPO_ROOT / "src/aoi_orgware/company/file_governance_io.py",
        REPO_ROOT / "src/aoi_orgware/company/file_governance_process.py",
        REPO_ROOT / "tests/company_v05/test_file_governance_process.py",
        Path(__file__),
    )
    assert {
        path.name: logical_line_count(path.read_bytes()) for path in paths
    } == {
        path.name: logical_line_count(path.read_bytes()) for path in paths
        if logical_line_count(path.read_bytes()) <= 800
    }
