from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
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
    inherited_env = {"SECRET_TOKEN": "never", "PATH": "x"}
    if platform_domain()["domain"] == "wsl":
        inherited_env.update({key: os.environ[key] for key in receipts._WSL_ENV})
    receipt = run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "r.json", logs_dir=tmp_path / "logs", inherited_env=inherited_env)
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


@pytest.mark.skipif(
    platform_domain()["domain"] != "wsl",
    reason="requires a real WSL child process",
)
def test_wsl_environment_survives_contained_runner_and_nested_routing(
    tmp_path: Path,
) -> None:
    captured_platform = platform_domain()
    distro = os.environ["WSL_DISTRO_NAME"]
    interop = os.environ["WSL_INTEROP"]
    repo = _repo(tmp_path)
    shutil.copytree(
        Path(__file__).parents[1] / "src" / "aoi_orgware",
        repo / "src" / "aoi_orgware",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (repo / "tests" / "test_wsl_routing.py").write_text(
        "from aoi_orgware.commands.codex_onboarding import CodexOnboardingError, build_codex_hook_commands\n"
        "import os\n\n"
        "import platform\n\n"
        "def test_wsl_route_keeps_complete_signals():\n"
        "    assert 'SECRET_TOKEN' not in os.environ\n"
        "    direct, windows = build_codex_hook_commands(\n"
        "        '/opt/aoi/bin/aoi-codex-hook', '/work/project', 'a' * 64,\n"
        "        environment=os.environ, kernel_release=platform.release(),\n"
        "        host_os_name='posix', wsl_user='runner',\n"
        "    )\n"
        "    assert direct.startswith('\\\"/opt/aoi/bin/aoi-codex-hook\\\" ')\n"
        "    expected = 'wsl.exe --distribution \\\"' + os.environ['WSL_DISTRO_NAME'] + '\\\" '\n"
        "    assert windows.startswith(expected)\n"
        "    partial = dict(os.environ)\n"
        "    del partial['WSL_INTEROP']\n"
        "    try:\n"
        "        build_codex_hook_commands(\n"
        "            '/opt/aoi/bin/aoi-codex-hook', '/work/project', 'a' * 64,\n"
        "            environment=partial, kernel_release=platform.release(),\n"
        "            host_os_name='posix', wsl_user='runner',\n"
        "        )\n"
        "    except CodexOnboardingError:\n"
        "        pass\n"
        "    else:\n"
        "        raise AssertionError('partial WSL routing signals were accepted')\n"
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "include routing fixture"],
        check=True,
    )
    receipt = run_clean_commit_source_tree(
        repo=repo,
        pytest_argv=["-q"],
        receipt_path=tmp_path / "wsl.json",
        logs_dir=tmp_path / "wsl-logs",
        inherited_env={
            "PATH": os.environ.get("PATH", ""),
            "SECRET_TOKEN": "never",
            "WSL_DISTRO_NAME": distro,
            "WSL_INTEROP": interop,
        },
    )
    assert receipt["accepted"] is True
    assert receipt["platform"] == captured_platform
    assert receipts._WSL_ENV == set(receipt["invocation"]["environment_names"]) & receipts._WSL_ENV
    assert "SECRET_TOKEN" not in receipt["invocation"]["environment_names"]


def test_explicit_environment_is_not_replaced_by_conflicting_ambient_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = {"PATH": os.environ.get("PATH", ""), "SECRET_TOKEN": "never"}
    observed: list[object] = []
    actual_platform_domain = receipts.platform_domain
    monkeypatch.setenv("WSL_DISTRO_NAME", "ambient-only")
    monkeypatch.setenv("WSL_INTEROP", "/run/WSL/ambient")

    def capture_explicit_platform(*, environ: object) -> dict[str, str]:
        observed.append(environ)
        return actual_platform_domain(
            system="Linux", release="unit-release", environ=environ, proc_version=""
        )

    monkeypatch.setattr(receipts, "platform_domain", capture_explicit_platform)
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "explicit.json",
        logs_dir=tmp_path / "logs",
        inherited_env=explicit,
    )
    assert observed == [explicit]
    assert receipt["platform"] == {
        "domain": "linux",
        "system": "Linux",
        "release": "unit-release",
        "wsl_distro": "",
        "kernel": "",
    }
    assert not (receipts._WSL_ENV & set(receipt["invocation"]["environment_names"]))


@pytest.mark.parametrize(
    "explicit",
    [
        {"PATH": "x"},
        {"PATH": "x", "WSL_DISTRO_NAME": "unit-distro"},
        {"PATH": "x", "WSL_INTEROP": "/run/WSL/unit"},
    ],
)
def test_explicit_wsl_signals_must_be_complete_before_child_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit: dict[str, str]
) -> None:
    child_launches = 0
    original_run = receipts.subprocess.run

    def reject_child_launch(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal child_launches
        command = args[0]
        if isinstance(command, list) and command[1:3] == ["-m", "pytest"]:
            child_launches += 1
            raise AssertionError("WSL correlation must fail before the child launches")
        return original_run(*args, **kwargs)

    monkeypatch.setattr(
        receipts,
        "platform_domain",
        lambda *, environ: {
            "domain": "wsl",
            "system": "Linux",
            "release": "unit-microsoft-release",
            "wsl_distro": environ.get("WSL_DISTRO_NAME", "unit-distro"),
            "kernel": "unit-microsoft-release",
        },
    )
    monkeypatch.setattr(receipts.subprocess, "run", reject_child_launch)
    with pytest.raises(ExactTestReceiptError):
        run_clean_commit_source_tree(
            repo=_repo(tmp_path),
            pytest_argv=["-q"],
            receipt_path=tmp_path / "partial.json",
            logs_dir=tmp_path / "logs",
            inherited_env=explicit,
        )
    assert child_launches == 0


def test_explicit_wsl_distro_mismatch_is_rejected_before_child_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child_launches = 0
    original_run = receipts.subprocess.run

    def reject_child_launch(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal child_launches
        command = args[0]
        if isinstance(command, list) and command[1:3] == ["-m", "pytest"]:
            child_launches += 1
            raise AssertionError("WSL distro mismatch must fail before the child launches")
        return original_run(*args, **kwargs)

    monkeypatch.setattr(
        receipts,
        "platform_domain",
        lambda *, environ: {
            "domain": "wsl",
            "system": "Linux",
            "release": "unit-microsoft-release",
            "wsl_distro": "captured-distro",
            "kernel": "unit-microsoft-release",
        },
    )
    monkeypatch.setattr(receipts.subprocess, "run", reject_child_launch)
    with pytest.raises(ExactTestReceiptError):
        run_clean_commit_source_tree(
            repo=_repo(tmp_path),
            pytest_argv=["-q"],
            receipt_path=tmp_path / "mismatch.json",
            logs_dir=tmp_path / "logs",
            inherited_env={
                "PATH": "x",
                "WSL_DISTRO_NAME": "child-distro",
                "WSL_INTEROP": "/run/WSL/unit",
            },
        )
    assert child_launches == 0


def test_wsl_environment_allowlist_is_bounded_and_hashed() -> None:
    child_env, names, digest = receipts._child_env(
        Path("/snapshot"),
        {
            "PATH": "safe-path",
            "SECRET_TOKEN": "never",
            "WSL_DISTRO_NAME": "Ubuntu",
            "WSL_INTEROP": "/run/WSL/123_interop",
        },
    )
    assert set(names) == set(child_env)
    assert receipts._WSL_ENV.issubset(names)
    assert "SECRET_TOKEN" not in child_env
    assert digest == receipts._sha256_bytes(
        receipts._canonical({"environment": {name: child_env[name] for name in names}})
    )


@pytest.mark.parametrize("distro", ["-unit", "unit/distro", "unit\nname", "unit" + "x" * 128])
def test_wsl_distribution_allowlist_value_is_fail_closed(distro: str) -> None:
    with pytest.raises(ExactTestReceiptError):
        receipts._child_env(
            Path("/snapshot"),
            {"WSL_DISTRO_NAME": distro, "WSL_INTEROP": "/run/WSL/123_interop"},
        )


def test_wsl_receipt_cross_field_constraints_reject_tampering(tmp_path: Path) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    missing_interop = copy.deepcopy(receipt)
    missing_interop["platform"] = {
        "domain": "wsl",
        "system": "Linux",
        "release": "6.6.0-microsoft-standard-WSL2",
        "wsl_distro": "Ubuntu",
        "kernel": "6.6.0-microsoft-standard-WSL2",
    }
    missing_interop["invocation"]["environment_names"] = sorted(
        (set(missing_interop["invocation"]["environment_names"]) | {"WSL_DISTRO_NAME"})
        - {"WSL_INTEROP"}
    )
    missing_interop = _reseal_with_structured_invocation(
        missing_interop,
        missing_interop["invocation"],
    )
    with pytest.raises(ExactTestReceiptError):
        canonical_exact_test_receipt_bytes(missing_interop)

    for platform in (
        {
            "domain": "wsl",
            "system": "Linux",
            "release": "6.6.0-microsoft-standard-WSL2",
            "wsl_distro": "",
            "kernel": "6.6.0-microsoft-standard-WSL2",
        },
        {
            "domain": "wsl",
            "system": "Linux",
            "release": "",
            "wsl_distro": "unit-distro",
            "kernel": "",
        },
        {
            "domain": "wsl",
            "system": "Linux",
            "release": "6.6.0-microsoft-standard-WSL2",
            "wsl_distro": "unit-distro",
            "kernel": "6.6.0-other",
        },
        {
            "domain": "wsl",
            "system": "Windows",
            "release": "6.6.0-microsoft-standard-WSL2",
            "wsl_distro": "unit-distro",
            "kernel": "6.6.0-microsoft-standard-WSL2",
        },
    ):
        incoherent = copy.deepcopy(receipt)
        incoherent["platform"] = platform
        incoherent["invocation"]["environment_names"] = sorted(
            set(incoherent["invocation"]["environment_names"]) | receipts._WSL_ENV
        )
        incoherent = _reseal_with_structured_invocation(incoherent, incoherent["invocation"])
        with pytest.raises(ExactTestReceiptError):
            canonical_exact_test_receipt_bytes(incoherent)

    for wsl_name in receipts._WSL_ENV:
        non_wsl = copy.deepcopy(receipt)
        non_wsl["platform"] = {
            "domain": "linux",
            "system": "Linux",
            "release": "6.6.0-linux",
            "wsl_distro": "",
            "kernel": "",
        }
        non_wsl["invocation"]["environment_names"] = sorted(
            set(non_wsl["invocation"]["environment_names"]) | {wsl_name}
        )
        non_wsl = _reseal_with_structured_invocation(non_wsl, non_wsl["invocation"])
        with pytest.raises(ExactTestReceiptError):
            canonical_exact_test_receipt_bytes(non_wsl)

    legacy = copy.deepcopy(receipt)
    legacy["producer"] = {
        **legacy["producer"],
        "version": receipts.LEGACY_RUNNER_VERSION,
        "structured_invocation_sha256": receipts._sha256_bytes(
            receipts._canonical(
                {
                    "pytest_argv": legacy["invocation"]["argv"],
                    "protocol": "pytest-arg-vector-v1",
                }
            )
        ),
    }
    legacy["invocation"] = {
        "argv": legacy["invocation"]["argv"],
        "cwd_role": legacy["invocation"]["cwd_role"],
        "environment_names": ["PYTHONHASHSEED"],
        "environment_sha256": legacy["invocation"]["environment_sha256"],
    }
    legacy["platform"] = missing_interop["platform"]
    assert canonical_exact_test_receipt_bytes(_reseal(legacy))


@pytest.mark.parametrize("interop", ["relative/socket", "/run/WSL/../socket", "/run/WSL/\x00socket"])
def test_wsl_interop_allowlist_value_is_fail_closed(interop: str) -> None:
    with pytest.raises(ExactTestReceiptError):
        receipts._child_env(
            Path("/snapshot"),
            {"WSL_DISTRO_NAME": "Ubuntu", "WSL_INTEROP": interop},
        )


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
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-qm", "head-change"], check=True)
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
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "link"], check=True)
    with pytest.raises(ExactTestReceiptError): run_clean_commit_source_tree(repo=repo, pytest_argv=["-q"], receipt_path=tmp_path / "link.json", logs_dir=tmp_path / "logs")
    gitlink = _repo(tmp_path / "gitlink")
    head = subprocess.run(["git", "-C", str(gitlink), "rev-parse", "HEAD"], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    subprocess.run(["git", "-C", str(gitlink), "update-index", "--add", "--cacheinfo", f"160000,{head},submodule"], check=True)
    subprocess.run(["git", "-C", str(gitlink), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "gitlink"], check=True)
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


def _reseal_with_structured_invocation(
    receipt: dict[str, object],
    invocation: dict[str, object],
    *,
    runner_version: str = receipts.RUNNER_VERSION,
) -> dict[str, object]:
    producer = {
        **receipt["producer"],
        "version": runner_version,
        "structured_invocation_sha256": receipts._sha256_bytes(
            receipts._canonical(
                receipts._structured_invocation_payload(
                    invocation,
                    runner_version=runner_version,
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


@pytest.mark.parametrize("identity_path", ["/mnt/d/aoi/exact_test_receipts.py", r"D:\aoi\exact_test_receipts.py"])
def test_receipt_identity_paths_are_host_independent(
    tmp_path: Path, identity_path: str
) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    cross_platform = _reseal(
        {
            **receipt,
            "producer": {
                **receipt["producer"],
                "module": {**receipt["producer"]["module"], "path": identity_path},
            },
            "interpreter": {**receipt["interpreter"], "path": identity_path},
        }
    )
    assert canonical_exact_test_receipt_bytes(cross_platform)


@pytest.mark.parametrize("identity_path", ["relative/module.py", "../module.py", r"D:module.py", r"\module.py"])
def test_receipt_identity_paths_reject_relative_or_ambiguous_syntax(identity_path: str) -> None:
    with pytest.raises(ExactTestReceiptError):
        receipts._absolute_path(identity_path, "receipt identity path")


def test_historical_v2_structured_receipts_remain_readable_but_not_current(
    tmp_path: Path,
) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    historical_wsl = copy.deepcopy(receipt)
    historical_wsl["platform"] = {
        "domain": "wsl",
        "system": "Linux",
        "release": "6.6.0-microsoft-standard-WSL2",
        "wsl_distro": "historical-distro",
        "kernel": "6.6.0-microsoft-standard-WSL2",
    }
    historical_wsl["invocation"]["environment_names"] = sorted(
        set(historical_wsl["invocation"]["environment_names"]) - receipts._WSL_ENV
    )
    historical_wsl = _reseal_with_structured_invocation(
        historical_wsl,
        historical_wsl["invocation"],
        runner_version=receipts.PREVIOUS_RUNNER_VERSION,
    )
    historical_wsl_raw = canonical_exact_test_receipt_bytes(historical_wsl)
    assert parse_exact_test_receipt_bytes(historical_wsl_raw) == historical_wsl
    with pytest.raises(ExactTestReceiptError):
        parse_exact_test_receipt_bytes(
            historical_wsl_raw, require_current_protocol=True
        )

    historical_non_wsl = copy.deepcopy(receipt)
    historical_non_wsl["platform"] = {
        "domain": "linux",
        "system": "Linux",
        "release": "historical-release",
        "wsl_distro": "",
        "kernel": "",
    }
    historical_non_wsl["invocation"]["environment_names"] = sorted(
        set(historical_non_wsl["invocation"]["environment_names"]) - receipts._WSL_ENV
    )
    historical_non_wsl = _reseal_with_structured_invocation(
        historical_non_wsl,
        historical_non_wsl["invocation"],
        runner_version=receipts.PREVIOUS_RUNNER_VERSION,
    )
    historical_non_wsl_raw = canonical_exact_test_receipt_bytes(historical_non_wsl)
    assert parse_exact_test_receipt_bytes(historical_non_wsl_raw) == historical_non_wsl


def test_historical_producer_environment_grammars_are_versioned(
    tmp_path: Path,
) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )

    legacy_invocation = {
        "argv": receipt["invocation"]["argv"],
        "cwd_role": receipt["invocation"]["cwd_role"],
        "environment_names": sorted(
            {
                "PYTHONHASHSEED",
                "PYTHONPATH",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                "PYTHONDONTWRITEBYTECODE",
            }
        ),
        "environment_sha256": receipt["invocation"]["environment_sha256"],
    }
    legacy = _reseal_with_structured_invocation(
        receipt,
        legacy_invocation,
        runner_version=receipts.LEGACY_RUNNER_VERSION,
    )
    assert canonical_exact_test_receipt_bytes(legacy)

    v2 = copy.deepcopy(receipt)
    v2["invocation"]["environment_names"] = sorted(
        set(v2["invocation"]["environment_names"]) - receipts._WSL_ENV
    )
    v2 = _reseal_with_structured_invocation(
        v2,
        v2["invocation"],
        runner_version=receipts.PREVIOUS_RUNNER_VERSION,
    )
    assert "PYTHONNOUSERSITE" in v2["invocation"]["environment_names"]
    assert canonical_exact_test_receipt_bytes(v2)


def test_environment_name_grammar_is_frozen_per_runner_version() -> None:
    base = {
        "PATH",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "LANG",
        "LC_ALL",
        "TZ",
    }
    v1_fixed = {
        "PYTHONHASHSEED",
        "PYTHONPATH",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "PYTHONDONTWRITEBYTECODE",
    }
    v2_fixed = v1_fixed | {"PYTHONNOUSERSITE"}
    expected = {
        "1": (
            frozenset(base | v1_fixed),
            frozenset(),
        ),
        "2": (
            frozenset(base | v2_fixed),
            frozenset(v2_fixed),
        ),
        "3": (
            frozenset(base | v2_fixed | {"WSL_DISTRO_NAME", "WSL_INTEROP"}),
            frozenset(v2_fixed),
        ),
    }
    assert {
        version: receipts._environment_name_grammar(version)
        for version in expected
    } == expected
    assert (
        receipts.LEGACY_RUNNER_VERSION,
        receipts.PREVIOUS_RUNNER_VERSION,
        receipts.RUNNER_VERSION,
    ) == ("1", "2", "3")
    assert {
        version: receipts._runner_invocation_contract(version)
        for version in expected
    } == {
        "1": "pytest-arg-vector-v1",
        "2": "pytest-contained-argv-v2",
        "3": "pytest-contained-argv-v2",
    }
    current_allowed, current_required = expected["3"]
    assert receipts._ENV_ALLOWLIST | receipts._PYTEST_FIXED_ENV == current_allowed
    assert receipts._PYTEST_FIXED_ENV == current_required
    with pytest.raises(ExactTestReceiptError):
        receipts._environment_name_grammar("4")
    with pytest.raises(ExactTestReceiptError):
        receipts._runner_invocation_contract("4")


def test_historical_dispatch_does_not_follow_moving_role_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    v2 = copy.deepcopy(receipt)
    v2["invocation"]["environment_names"] = sorted(
        set(v2["invocation"]["environment_names"]) - receipts._WSL_ENV
    )
    v2 = _reseal_with_structured_invocation(
        v2,
        v2["invocation"],
        runner_version="2",
    )
    v3_missing_wsl = copy.deepcopy(receipt)
    v3_missing_wsl["platform"] = {
        "domain": "wsl",
        "system": "Linux",
        "release": "6.6.0-microsoft-standard-WSL2",
        "wsl_distro": "Ubuntu",
        "kernel": "6.6.0-microsoft-standard-WSL2",
    }
    v3_missing_wsl["invocation"]["environment_names"] = sorted(
        set(v3_missing_wsl["invocation"]["environment_names"]) - receipts._WSL_ENV
    )
    v3_missing_wsl = _reseal_with_structured_invocation(
        v3_missing_wsl,
        v3_missing_wsl["invocation"],
        runner_version="3",
    )
    v2_grammar = receipts._environment_name_grammar("2")
    v3_grammar = receipts._environment_name_grammar("3")
    monkeypatch.setattr(receipts, "PREVIOUS_RUNNER_VERSION", "3")
    monkeypatch.setattr(receipts, "RUNNER_VERSION", "4")
    monkeypatch.setattr(
        receipts,
        "PYTEST_ARGUMENT_CONTRACT",
        "pytest-contained-argv-v3",
    )
    assert receipts._environment_name_grammar("2") == v2_grammar
    assert receipts._environment_name_grammar("3") == v3_grammar
    assert (
        receipts._runner_invocation_contract("2")
        == "pytest-contained-argv-v2"
    )
    assert (
        receipts._runner_invocation_contract("3")
        == "pytest-contained-argv-v2"
    )
    assert receipts._structured_invocation_payload(
        receipt["invocation"],
        runner_version="3",
    )["protocol"] == "pytest-contained-argv-v2"
    assert canonical_exact_test_receipt_bytes(v2)
    assert canonical_exact_test_receipt_bytes(receipt)
    with pytest.raises(ExactTestReceiptError):
        canonical_exact_test_receipt_bytes(
            receipt,
            require_current_protocol=True,
        )
    with pytest.raises(ExactTestReceiptError):
        canonical_exact_test_receipt_bytes(v3_missing_wsl)
    with pytest.raises(ExactTestReceiptError):
        receipts._environment_name_grammar("4")


def test_resealed_v1_receipt_rejects_v2_pythonnousersite(
    tmp_path: Path,
) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    legacy_invocation = {
        "argv": receipt["invocation"]["argv"],
        "cwd_role": receipt["invocation"]["cwd_role"],
        "environment_names": sorted(
            {
                "PYTHONHASHSEED",
                "PYTHONNOUSERSITE",
                "PYTHONPATH",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                "PYTHONDONTWRITEBYTECODE",
            }
        ),
        "environment_sha256": receipt["invocation"]["environment_sha256"],
    }
    legacy = _reseal_with_structured_invocation(
        receipt,
        legacy_invocation,
        runner_version=receipts.LEGACY_RUNNER_VERSION,
    )
    with pytest.raises(ExactTestReceiptError):
        canonical_exact_test_receipt_bytes(legacy)


@pytest.mark.parametrize(
    ("runner_version", "wsl_name"),
    [
        (receipts.LEGACY_RUNNER_VERSION, "WSL_DISTRO_NAME"),
        (receipts.LEGACY_RUNNER_VERSION, "WSL_INTEROP"),
        (receipts.PREVIOUS_RUNNER_VERSION, "WSL_DISTRO_NAME"),
        (receipts.PREVIOUS_RUNNER_VERSION, "WSL_INTEROP"),
    ],
)
def test_historical_producers_reject_v3_wsl_environment_names(
    tmp_path: Path,
    runner_version: str,
    wsl_name: str,
) -> None:
    receipt = run_clean_commit_source_tree(
        repo=_repo(tmp_path),
        pytest_argv=["-q"],
        receipt_path=tmp_path / "r.json",
        logs_dir=tmp_path / "logs",
    )
    historical = copy.deepcopy(receipt)
    if runner_version == receipts.LEGACY_RUNNER_VERSION:
        invocation = {
            "argv": historical["invocation"]["argv"],
            "cwd_role": historical["invocation"]["cwd_role"],
            "environment_names": sorted({"PYTHONHASHSEED", wsl_name}),
            "environment_sha256": historical["invocation"]["environment_sha256"],
        }
    else:
        invocation = historical["invocation"]
        invocation["environment_names"] = sorted(
            (set(invocation["environment_names"]) - receipts._WSL_ENV)
            | {wsl_name}
        )
    historical = _reseal_with_structured_invocation(
        historical,
        invocation,
        runner_version=runner_version,
    )
    with pytest.raises(ExactTestReceiptError):
        canonical_exact_test_receipt_bytes(historical)


def test_resealed_current_confinement_tampering_is_rejected(tmp_path: Path) -> None:
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
        tampered = _reseal_with_structured_invocation(receipt, invocation)
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
