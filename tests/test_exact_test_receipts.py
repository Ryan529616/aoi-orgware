from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

import aoi_orgware.exact_test_receipts as receipts
from aoi_orgware.exact_test_receipts import ExactTestReceiptError, canonical_exact_test_receipt_bytes, parse_exact_test_receipt_bytes, platform_domain, run_clean_commit_source_tree, verify_exact_test_log


def _repo(tmp_path: Path, test_body: str = "def test_ok():\n    assert True\n") -> Path:
    repo = tmp_path / "repo"; (repo / "src" / "demo").mkdir(parents=True); (repo / "tests").mkdir()
    (repo / "src" / "demo" / "__init__.py").write_text("")
    (repo / "tests" / "test_demo.py").write_text(test_body)
    subprocess.run(["git", "init", "-q", str(repo)], check=True); subprocess.run(["git", "-C", str(repo), "add", "."], check=True); subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"], check=True)
    return repo


def test_clean_pass_and_canonical_receipt(tmp_path: Path) -> None:
    repo = _repo(tmp_path); receipt = run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "receipt.json", logs_dir=tmp_path / "logs")
    assert receipt["accepted"] is True
    assert receipt["producer"]["invoker"] is None
    assert parse_exact_test_receipt_bytes((tmp_path / "receipt.json").read_bytes())["receipt_sha256"] == receipt["receipt_sha256"]


@pytest.mark.parametrize(
    "argv",
    [
        ["--pyargs", "demo"],
        ["-p", "external_plugin"],
        ["-pno:terminal"],
        ["--quiet"],
        ["--color=no"],
        ["--maxfail=1"],
        ["-c", "outside.ini"],
        ["--rootdir=.."],
        ["--confcutdir=.."],
        ["--import-mode=append"],
        ["-o", "pythonpath=.."],
        ["--override-ini=pythonpath=.."],
        ["@outside.args"],
        ["@tests/inside.args"],
        ["--"],
        ["../outside.py"],
        ["tests/../../outside.py"],
        ["tests/../tests/test_demo.py"],
        ["--ignore=tests/../tests/test_demo.py"],
        [r"C:\outside.py"],
        ["C:/outside.py"],
        ["C:outside.py"],
        [r"\\server\share\outside.py"],
        [r"\\?\C:\outside.py"],
    ],
)
def test_pytest_argv_rejects_external_collection_surfaces(
    tmp_path: Path, argv: list[str]
) -> None:
    repo = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("def test_unrelated():\n    assert True\n")
    with pytest.raises(ExactTestReceiptError):
        run_clean_commit_source_tree(
            repo=repo,
            pytest_argv=argv,
            receipt_path=tmp_path / "unsafe.json",
            logs_dir=tmp_path / "unsafe-logs",
        )
    assert not (tmp_path / "unsafe.json").exists()


def test_pytest_argv_accepts_only_candidate_target_and_output_format(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    receipt = run_clean_commit_source_tree(
        repo=repo,
        pytest_argv=[
            "-q",
            "--tb=short",
            "tests/test_demo.py::test_ok",
        ],
        receipt_path=tmp_path / "targeted.json",
        logs_dir=tmp_path / "targeted-logs",
    )
    assert receipt["accepted"] is True
    assert receipt["invocation"]["argv"] == [
        "-q",
        "--tb=short",
        "tests/test_demo.py::test_ok",
    ]
    assert receipt["invocation"]["requested_argv"] == receipt["invocation"]["argv"]
    assert receipt["producer"]["version"] == receipts.RUNNER_VERSION
    assert (
        receipt["invocation"]["argument_contract"]
        == receipts.PYTEST_ARGUMENT_CONTRACT
    )
    assert receipt["invocation"]["config"]["sha256"] == receipts._PYTEST_CONFIG_SHA256
    assert receipt["invocation"]["rootdir_role"] == "private_git_blob_snapshot"
    assert receipt["invocation"]["confcutdir_role"] == "private_git_blob_snapshot"


def test_pytest_argv_canonicalizes_directory_and_accepts_contained_ignore(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / "tests" / "test_ignored.py").write_text(
        "def test_ignored():\n    assert False\n"
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "ignored fixture",
        ],
        check=True,
    )
    receipt = run_clean_commit_source_tree(
        repo=repo,
        pytest_argv=[
            "-q",
            "tests/",
            "--ignore=tests/test_ignored.py",
        ],
        receipt_path=tmp_path / "canonical.json",
        logs_dir=tmp_path / "canonical-logs",
    )
    assert receipt["accepted"] is True
    assert receipt["invocation"]["argv"] == [
        "-q",
        "tests",
        "--ignore=tests/test_ignored.py",
    ]
    assert receipt["invocation"]["requested_argv"] == [
        "-q",
        "tests/",
        "--ignore=tests/test_ignored.py",
    ]


def test_pytest_argv_rejects_missing_snapshot_target(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(ExactTestReceiptError, match="unavailable"):
        run_clean_commit_source_tree(
            repo=repo,
            pytest_argv=["-q", "tests/missing.py"],
            receipt_path=tmp_path / "missing.json",
            logs_dir=tmp_path / "missing-logs",
        )


def test_external_pass_cannot_mask_internal_failure(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "def test_internal_failure():\n    assert False\n")
    outside = tmp_path / "outside_pass.py"
    outside.write_text("def test_unrelated_pass():\n    assert True\n")
    with pytest.raises(ExactTestReceiptError):
        run_clean_commit_source_tree(
            repo=repo,
            pytest_argv=[str(outside.resolve())],
            receipt_path=tmp_path / "false-pass.json",
            logs_dir=tmp_path / "false-pass-logs",
        )
    assert not (tmp_path / "false-pass.json").exists()


def test_fixed_config_root_and_environment_ignore_ambient_pytest_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    (repo / "pytest.ini").write_text(
        "[pytest]\naddopts = --pyargs definitely_missing_external_package\n"
    )
    subprocess.run(["git", "-C", str(repo), "add", "pytest.ini"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "hostile candidate config",
        ],
        check=True,
    )
    original_run = receipts.subprocess.run
    original_snapshot = receipts._snapshot
    observed: dict[str, object] = {}

    def snapshot_with_hostile_parent(source: Path, destination: Path) -> tuple[str, int]:
        result = original_snapshot(source, destination)
        if destination.name == "snapshot":
            (destination.parent / "conftest.py").write_text(
                "raise RuntimeError('snapshot parent conftest must not load')\n"
            )
        return result

    def capture_pytest(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[0]
        if (
            isinstance(command, list)
            and len(command) >= 3
            and command[1:3] == ["-m", "pytest"]
        ):
            observed["command"] = list(command)
            observed["env"] = dict(kwargs["env"])
        return original_run(*args, **kwargs)

    monkeypatch.setattr(receipts, "_snapshot", snapshot_with_hostile_parent)
    monkeypatch.setattr(receipts.subprocess, "run", capture_pytest)
    inherited = {
        key: os.environ[key]
        for key in receipts._ENV_ALLOWLIST
        if key in os.environ
    }
    inherited.update(
        {
            "PYTEST_ADDOPTS": "--pyargs external",
            "PYTEST_PLUGINS": "external_plugin",
            "PYTHONHOME": str(tmp_path / "external-home"),
            "PYTHONPATH": str(tmp_path / "external-path"),
            "PYTHONSTARTUP": str(tmp_path / "startup.py"),
        }
    )
    receipt = run_clean_commit_source_tree(
        repo=repo,
        pytest_argv=["-q"],
        receipt_path=tmp_path / "isolated.json",
        logs_dir=tmp_path / "isolated-logs",
        inherited_env=inherited,
    )
    assert receipt["accepted"] is True
    command = observed["command"]
    assert isinstance(command, list)
    assert command[-2:] == ["-q", "tests"]
    assert "-c" in command
    assert any(str(item).startswith("--rootdir=") for item in command)
    assert any(str(item).startswith("--confcutdir=") for item in command)
    child_env = observed["env"]
    assert isinstance(child_env, dict)
    assert child_env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert child_env["PYTHONNOUSERSITE"] == "1"
    assert child_env["PYTHONDONTWRITEBYTECODE"] == "1"
    for forbidden in (
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTHONHOME",
        "PYTHONSTARTUP",
    ):
        assert forbidden not in child_env


@pytest.mark.parametrize("change", ["staged", "untracked", "rename", "newline name"])
def test_dirty_trees_rejected(tmp_path: Path, change: str) -> None:
    repo = _repo(tmp_path)
    if change == "staged": (repo / "tests" / "test_demo.py").write_text("x=1\n"); subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    elif change == "rename": (repo / "tests" / "test_demo.py").rename(repo / "tests" / "renamed.py")
    else:
        if change == "newline name" and sys.platform == "win32":
            pytest.skip("Windows forbids newline filename fixtures")
        (repo / ("odd\nname" if change == "newline name" else "untracked")).write_text("x")
    with pytest.raises(ExactTestReceiptError): run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs")


def test_nonzero_and_secret_env_excluded(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "def test_no():\n    assert False\n")
    receipt = run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs", inherited_env={"SECRET_TOKEN": "never", "PATH": "x"})
    assert not receipt["accepted"] and receipt["pytest_exit_code"] != 0
    assert "SECRET_TOKEN" not in receipt["invocation"]["environment_names"]


def test_tamper_duplicate_extra_nan_and_matrix_tuple(tmp_path: Path) -> None:
    receipt = run_clean_commit_source_tree(repo=_repo(tmp_path), pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs")
    raw = canonical_exact_test_receipt_bytes(receipt)
    with pytest.raises(ExactTestReceiptError): parse_exact_test_receipt_bytes(raw.replace(b'"accepted":true', b'"accepted":true,"accepted":true'))
    with pytest.raises(ExactTestReceiptError): parse_exact_test_receipt_bytes(raw[:-1] + b' ')
    altered = dict(receipt); altered["extra"] = 1
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(altered)
    with pytest.raises(ExactTestReceiptError): parse_exact_test_receipt_bytes(b'{"x":NaN}\n')
    with pytest.raises(ExactTestReceiptError): parse_exact_test_receipt_bytes(raw, require_github_matrix=True)
    log = next((tmp_path / "logs").glob("*.log"))
    verify_exact_test_log(log.resolve(), receipt)
    log.write_bytes(b"tampered")
    with pytest.raises(ExactTestReceiptError): verify_exact_test_log(log.resolve(), receipt)


def test_stable_regular_read_rejects_linked_symlinked_and_changed_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    linked = tmp_path / "linked.log"; linked.write_bytes(b"linked")
    os.link(linked, tmp_path / "linked-alias.log")
    with pytest.raises(ExactTestReceiptError): receipts._stable_regular_read(linked.resolve(), "linked fixture")

    target = tmp_path / "target.log"; target.write_bytes(b"target")
    symlink = tmp_path / "symlink.log"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink fixture unavailable: {exc}")
    with pytest.raises(ExactTestReceiptError): receipts._stable_regular_read(symlink.absolute(), "symlink fixture")

    changing = tmp_path / "changing.log"; changing.write_bytes(b"before")
    original_read = receipts.os.read; changed = False
    def mutate_after_open(descriptor: int, size: int) -> bytes:
        nonlocal changed
        if not changed:
            changed = True; changing.write_bytes(b"after mutation")
        return original_read(descriptor, size)
    monkeypatch.setattr(receipts.os, "read", mutate_after_open)
    with pytest.raises(ExactTestReceiptError): receipts._stable_regular_read(changing.resolve(), "changing fixture")


def test_windows_and_wsl_domains() -> None:
    assert platform_domain(system="Windows", release="x", environ={})["domain"] == "windows"
    assert platform_domain(system="Linux", release="x", environ={"WSL_DISTRO_NAME": "Ubuntu"}, proc_version="Microsoft")["domain"] == "wsl"


@pytest.mark.parametrize("mutation", ["source", "index", "head"])
def test_post_identity_mutation_rejects_terminal_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    repo = _repo(tmp_path)
    original_snapshot = receipts._snapshot
    def mutate_then_snapshot(*args: object, **kwargs: object) -> tuple[str, int]:
        if mutation == "source":
            (repo / "tests" / "test_demo.py").write_text("def test_changed():\n    assert True\n")
        elif mutation == "index":
            (repo / "index-change").write_text("x")
            subprocess.run(["git", "-C", str(repo), "add", "index-change"], check=True)
        else:
            subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-qm", "head-change"], check=True)
        return original_snapshot(*args, **kwargs)
    monkeypatch.setattr(receipts, "_snapshot", mutate_then_snapshot)
    receipt = run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / f"{mutation}.json", logs_dir=tmp_path / "logs")
    assert not receipt["accepted"] and receipt["identity_unchanged"] is False


def test_aba_is_explicitly_only_an_observation_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path); target = repo / "tests" / "test_demo.py"; original = target.read_bytes()
    original_snapshot = receipts._snapshot
    def aba_then_snapshot(*args: object, **kwargs: object) -> tuple[str, int]:
        target.write_text("def test_changed():\n    assert False\n")
        target.write_bytes(original)
        return original_snapshot(*args, **kwargs)
    monkeypatch.setattr(receipts, "_snapshot", aba_then_snapshot)
    receipt = run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "aba.json", logs_dir=tmp_path / "logs")
    assert receipt["accepted"]  # Identity observations cannot prove no ABA mutation.


def test_timeout_and_publication_crash_do_not_claim_acceptance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, "import time\ndef test_wait():\n    time.sleep(2)\n")
    timed_out = run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "timeout.json", logs_dir=tmp_path / "logs", timeout_seconds=0.01)
    assert not timed_out["accepted"] and timed_out["terminal_status"] == "timeout"
    monkeypatch.setattr(receipts, "_atomic_create", lambda *_args: (_ for _ in ()).throw(receipts.ReceiptPublicationError("crash")))
    with pytest.raises(receipts.ReceiptPublicationError):
        run_clean_commit_source_tree(repo=_repo(tmp_path / "two"), pytest_argv=["-q"], receipt_path=tmp_path / "crash.json", logs_dir=tmp_path / "logs2")
    assert not (tmp_path / "crash.json").exists()


def test_symlink_and_gitlink_tree_entries_rejected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    # A Git symlink is represented by mode 120000 even where the host cannot
    # safely create a native symlink.
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", "120000," + "0" * 40 + ",link"], check=False)
    # The zero object is rejected by Git itself; write a real blob instead.
    blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=b"target", stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"120000,{blob},link"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "link"], check=True)
    with pytest.raises(ExactTestReceiptError): run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "link.json", logs_dir=tmp_path / "logs")
    gitlink = _repo(tmp_path / "gitlink")
    head = subprocess.run(["git", "-C", str(gitlink), "rev-parse", "HEAD"], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    subprocess.run(["git", "-C", str(gitlink), "update-index", "--add", "--cacheinfo", f"160000,{head},submodule"], check=True)
    subprocess.run(["git", "-C", str(gitlink), "commit", "-qm", "gitlink"], check=True)
    with pytest.raises(ExactTestReceiptError): run_clean_commit_source_tree(repo=gitlink, pytest_argv=["-q"], receipt_path=tmp_path / "gitlink.json", logs_dir=tmp_path / "logs2")


def test_required_github_matrix_tuple(tmp_path: Path) -> None:
    matrix = {"repository": "owner/repo", "ref": "refs/heads/main", "event": "push", "workflow_ref": "owner/repo/.github/workflows/test.yml@refs/heads/main", "job_key": "tests", "runner_os": "Windows", "runner_arch": "X64", "run_id": 1, "run_attempt": 1, "matrix_gate_id": "windows-py314", "matrix": {"python": "3.14", "os": "windows"}}
    receipt = run_clean_commit_source_tree(repo=_repo(tmp_path), pytest_argv=["-q"], receipt_path=tmp_path / "matrix.json", logs_dir=tmp_path / "logs", github_matrix_identity=matrix, require_github_matrix=True, invoker_path=Path(__file__))
    assert receipt["accepted"] and receipt["github_matrix_identity"] == matrix
    incomplete = dict(matrix); del incomplete["job_key"]
    with pytest.raises(ExactTestReceiptError):
        run_clean_commit_source_tree(repo=_repo(tmp_path / "bad"), pytest_argv=["-q"], receipt_path=tmp_path / "bad.json", logs_dir=tmp_path / "logs2", github_matrix_identity=incomplete, require_github_matrix=True, invoker_path=Path(__file__))


def _reseal(receipt: dict[str, object]) -> dict[str, object]:
    base = dict(receipt); base.pop("receipt_sha256")
    base["receipt_sha256"] = receipts._sha256_bytes(receipts._canonical(base))
    return base


def _reseal_with_v2_invocation(
    receipt: dict[str, object],
    invocation: dict[str, object],
) -> dict[str, object]:
    producer = {
        **receipt["producer"],
        "structured_invocation_sha256": receipts._sha256_bytes(
            receipts._canonical(
                receipts._structured_invocation_payload(
                    invocation,
                    runner_version=receipts.RUNNER_VERSION,
                )
            )
        ),
    }
    return _reseal(
        {
            **receipt,
            "producer": producer,
            "invocation": invocation,
        }
    )


def test_strict_object_lengths_timestamp_and_accepted_predicate(tmp_path: Path) -> None:
    receipt = run_clean_commit_source_tree(repo=_repo(tmp_path), pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs")
    wrong_producer = _reseal({**receipt, "producer": {**receipt["producer"], "structured_invocation_sha256": "0" * 64}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(wrong_producer)


def test_resealed_v2_confinement_tampering_is_rejected(tmp_path: Path) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    original = receipt["invocation"]

    requested_mismatch = copy.deepcopy(original)
    requested_mismatch["requested_argv"] = [
        "-q",
        "tests/test_demo.py",
    ]

    config_drift = copy.deepcopy(original)
    config_drift["config"]["sha256"] = "0" * 64

    root_drift = copy.deepcopy(original)
    root_drift["rootdir_role"] = "external"

    confcut_drift = copy.deepcopy(original)
    confcut_drift["confcutdir_role"] = "external"

    missing_fixed_env = copy.deepcopy(original)
    missing_fixed_env["environment_names"].remove("PYTHONNOUSERSITE")

    for invocation in (
        requested_mismatch,
        config_drift,
        root_drift,
        confcut_drift,
        missing_fixed_env,
    ):
        tampered = _reseal_with_v2_invocation(receipt, invocation)
        with pytest.raises(ExactTestReceiptError):
            canonical_exact_test_receipt_bytes(tampered)


def test_cross_field_identity_is_derived_not_self_asserted(tmp_path: Path) -> None:
    receipt = run_clean_commit_source_tree(repo=_repo(tmp_path), pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs")
    swapped_post = _reseal({**receipt, "observation": {**receipt["observation"], "post": {**receipt["observation"]["post"], "head": "a" * 40}}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(swapped_post)
    mismatched_source = _reseal({**receipt, "source": {**receipt["source"], "manifest_sha256": "b" * 64}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(mismatched_source)
    dirty_pre = _reseal({**receipt, "observation": {**receipt["observation"], "pre": {**receipt["observation"]["pre"], "status_sha256": "c" * 64}}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(dirty_pre)
    other_oid_width = 64 if len(receipt["source"]["head"]) == 40 else 40
    mixed_width = _reseal({**receipt, "source": {**receipt["source"], "index_tree": "b" * other_oid_width}, "observation": {**receipt["observation"], "pre": {**receipt["observation"]["pre"], "index_tree": "b" * other_oid_width}, "post": {**receipt["observation"]["post"], "index_tree": "b" * other_oid_width}}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(mixed_width)
    null_oid = _reseal({**receipt, "source": {**receipt["source"], "head": "0" * len(receipt["source"]["head"])}, "observation": {**receipt["observation"], "pre": {**receipt["observation"]["pre"], "head": "0" * len(receipt["observation"]["pre"]["head"])}, "post": {**receipt["observation"]["post"], "head": "0" * len(receipt["observation"]["post"]["head"])}}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(null_oid)


def test_accepted_schema_requires_snapshot_clean_error_unique_env_and_wrapper(tmp_path: Path) -> None:
    receipt = run_clean_commit_source_tree(repo=_repo(tmp_path), pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs")
    no_snapshot = _reseal({**receipt, "source": {**receipt["source"], "snapshot": False}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(no_snapshot)
    with_error = _reseal({**receipt, "observation": {**receipt["observation"], "error": "unexpected"}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(with_error)
    duplicate_env = _reseal({**receipt, "invocation": {**receipt["invocation"], "environment_names": ["PYTHONHASHSEED", "PYTHONHASHSEED"]}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(duplicate_env)
    matrix_required = _reseal({**receipt, "github_matrix_identity": {"repository": "owner/repo", "ref": "refs/heads/main", "event": "push", "workflow_ref": "owner/repo/.github/workflows/test.yml@refs/heads/main", "job_key": "tests", "runner_os": "Windows", "runner_arch": "X64", "run_id": 1, "run_attempt": 1, "matrix_gate_id": "gate", "matrix": {}}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(matrix_required, require_github_matrix=True)
    wrong_time = _reseal({**receipt, "created_at": "2026-07-24T00:00:00+00:00"})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(wrong_time)
    impossible_time = _reseal({**receipt, "created_at": "2026-99-99T99:99:99.000000Z"})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(impossible_time)
    wrong_sha = _reseal({**receipt, "source": {**receipt["source"], "head": "a" * 41}})
    with pytest.raises(ExactTestReceiptError): canonical_exact_test_receipt_bytes(wrong_sha)


def test_atomic_publication_competition_never_replaces(tmp_path: Path) -> None:
    target = tmp_path / "same-receipt.json"; failures: list[Exception] = []
    def publish(payload: bytes) -> None:
        try: receipts._atomic_create(target, payload)
        except Exception as exc: failures.append(exc)
    left = threading.Thread(target=publish, args=(b"left",)); right = threading.Thread(target=publish, args=(b"right",))
    left.start(); right.start(); left.join(); right.join()
    assert len(failures) == 1
    assert target.read_bytes() in {b"left", b"right"}


@pytest.mark.parametrize("parts", [("C:", "x"), ("CON.txt",), ("name:stream",), ("trailing.",), ("trailing ",), ("safe~1.txt",), ("aux",)])
def test_windows_materialization_path_table_rejects_lossy_names(parts: tuple[str, ...]) -> None:
    with pytest.raises(ExactTestReceiptError): receipts._windows_materialization_key(parts)


def test_snapshot_rejects_windows_case_collision_before_materialization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tree = b"100644 blob " + b"0" * 40 + b"\tA\0" + b"100644 blob " + b"1" * 40 + b"\ta\0"
    monkeypatch.setattr(receipts, "_git", lambda *_args, **_kwargs: tree)
    with pytest.raises(ExactTestReceiptError): receipts._snapshot(tmp_path, tmp_path / "snapshot")


def test_cli_records_actual_invoker_identity_but_not_an_exit_claim(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    script = Path(__file__).parents[1] / "scripts" / "exact_test_receipt.py"
    receipt_path = tmp_path / "cli.json"
    completed = subprocess.run([sys.executable, str(script), "--repo", str(repo), "--receipt", str(receipt_path), "--logs-dir", str(tmp_path / "logs"), "--pytest-arg=-q"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    receipt = parse_exact_test_receipt_bytes(receipt_path.read_bytes())
    assert receipt["producer"]["invoker"]["path"] == str(script.resolve())
    assert "runner_exit_code" not in receipt


@pytest.mark.parametrize("matrix", ['{"x":1,"x":2}', '[]', '[["x",1]]'])
def test_cli_rejects_non_strict_github_matrix_json(tmp_path: Path, matrix: str) -> None:
    repo = _repo(tmp_path)
    script = Path(__file__).parents[1] / "scripts" / "exact_test_receipt.py"
    completed = subprocess.run([sys.executable, str(script), "--repo", str(repo), "--receipt", str(tmp_path / "r.json"), "--logs-dir", str(tmp_path / "logs"), "--pytest-arg=-q", "--github-matrix-json", matrix], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    assert completed.returncode == 2
    assert not (tmp_path / "r.json").exists()
