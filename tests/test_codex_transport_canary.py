from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest


_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "codex_transport_canary.py"
)
_SPEC = importlib.util.spec_from_file_location("codex_transport_canary", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
canary = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(canary)

SHA_A = "a" * 64
SHA_B = "b" * 64


def _git() -> Path:
    executable = shutil.which("git")
    assert executable is not None
    return Path(executable).resolve()


def _run_git(root: Path, *args: str) -> None:
    subprocess.run(
        [str(_git()), "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _repository(root: Path, mode: str) -> None:
    root.mkdir()
    _run_git(root, "init")
    _run_git(root, "config", "user.email", "canary@example.invalid")
    _run_git(root, "config", "user.name", "AOI Canary")
    (root / canary.ROOT_MARKER).write_text(
        json.dumps(
            {
                "schema_version": canary.ROOT_MARKER_SCHEMA,
                "purpose": "disposable Codex transport canary",
                "mode": mode,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (root / "prompt.txt").write_text("bounded canary prompt\n", encoding="utf-8")
    (root / "workload.txt").write_text("before\n", encoding="utf-8")
    _run_git(root, "add", ".")
    _run_git(root, "commit", "-m", "seed disposable canary")


def _spec(tmp_path: Path, mode: str) -> tuple[Path, dict[str, Any]]:
    root = tmp_path / "scratch"
    _repository(root, mode)
    codex = tmp_path / "codex.exe"
    codex.write_bytes(b"exact pinned fake Codex executable")
    bridge = tmp_path / "aoi-codex-bridge.exe"
    bridge.write_bytes(b"fake bridge entry point")
    runtime_pin = {
        "codex_cli_version": "0.145.0",
        "codex_app_server_version": "0.145.0",
        "app_server_executable_sha256": hashlib.sha256(
            codex.read_bytes()
        ).hexdigest(),
        "schema_manifest_sha256": SHA_A,
        "combined_v2_schema_sha256": "c" * 64,
        "executable_path": str(codex.resolve()),
        "executable_size_bytes": codex.stat().st_size,
    }
    value: dict[str, Any] = {
        "schema_version": canary.SCHEMA_VERSION,
        "mode": mode,
        "aoi_root": str(root.resolve()),
        "task_id": "canary-task",
        "launch_id": "canary-launch",
        "permit_sha256": SHA_B,
        "prompt_file": str((root / "prompt.txt").resolve()),
        "codex_executable": str(codex.resolve()),
        "bridge_executable": str(bridge.resolve()),
        "git_executable": str(_git()),
        "scratch_root": str(root.resolve()),
        "runtime_pin": runtime_pin,
        "timeout_seconds": 30,
        "post_git_endpoint_file": None,
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return spec_path.resolve(), value


def _inspect(spec: dict[str, Any], *, completed: bool) -> dict[str, Any]:
    lifecycle = [
        {
            "classification": "committed",
            "event_type": "reserved",
        }
    ]
    terminal: list[dict[str, Any]] = []
    evidence = "transport_reserved"
    if completed:
        lifecycle.append(
            {
                "classification": "committed",
                "event_type": "completed",
            }
        )
        terminal = [
            {
                "classification": "committed",
                "terminal_state": "completed",
                "evidence_level": "codex_runtime_observed",
            }
        ]
        evidence = "codex_runtime_observed"
    return {
        "task_id": spec["task_id"],
        "launch_id": spec["launch_id"],
        "contract_version": "v2",
        "intent": {
            "cwd": canary._contract_path(Path(spec["scratch_root"])),
            "sandbox": canary._MODES[spec["mode"]],
            "approval": "never",
            "network_access": False,
            "runtime_pin": dict(spec["runtime_pin"]),
        },
        "reservation": {"evidence_level": "transport_reserved"},
        "lifecycle": lifecycle,
        "terminal_receipts": terminal,
        "evidence_level": evidence,
        "task_completion": "not_inferred",
    }


def test_policy_accepts_authenticated_contract_paths_on_native_windows(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    inspected = _inspect(spec, completed=False)

    assert inspected["intent"]["cwd"] == Path(spec["scratch_root"]).as_posix()
    assert (
        inspected["intent"]["runtime_pin"]["executable_path"]
        == Path(spec["codex_executable"]).as_posix()
    )
    canary._validate_policy(spec, inspected, fresh=True)


def test_preflight_is_read_only_and_does_not_start_app_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    calls: list[list[str]] = []

    def fake_bridge(current: dict[str, Any], args: list[str]) -> dict[str, Any]:
        calls.append(args)
        assert args[0] == "inspect"
        return _inspect(current, completed=False)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)
    result = canary.run_canary(spec, execute=False)

    assert result["status"] == "preflight_ready"
    assert result["live_app_server_started"] is False
    assert result["task_completion"] == "not_inferred"
    assert [call[0] for call in calls] == ["inspect"]


def test_read_only_canary_requires_an_exact_unchanged_workload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    completed = False

    def fake_bridge(current: dict[str, Any], args: list[str]) -> dict[str, Any]:
        nonlocal completed
        if args[0] == "run":
            completed = True
            return {"terminal_state": "completed"}
        assert args[0] == "inspect"
        return _inspect(current, completed=completed)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)
    result = canary.run_canary(spec, execute=True)

    assert result["status"] == "completed"
    assert result["evidence_level"] == "codex_runtime_observed"
    assert result["mutation_receipt"] is None
    assert result["pre_git_snapshot"] == result["post_git_snapshot"]


def test_writable_canary_requires_mutation_and_separate_elevation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "workspace_write")
    spec = canary.load_spec(spec_path)
    completed = False
    commands: list[str] = []

    def fake_bridge(current: dict[str, Any], args: list[str]) -> dict[str, Any]:
        nonlocal completed
        commands.append(args[0])
        if args[0] == "run":
            (Path(current["scratch_root"]) / "workload.txt").write_text(
                "after\n", encoding="utf-8"
            )
            completed = True
            return {"terminal_state": "completed"}
        if args[0] == "verify-mutation":
            assert "--sealed-claim-scope" in args
            return {
                "evidence_level": "verified_mutation",
                "mutation_object_sha256": SHA_A,
                "task_completion": "not_inferred",
            }
        assert args[0] == "inspect"
        return _inspect(current, completed=completed)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)
    result = canary.run_canary(spec, execute=True)

    assert commands == ["inspect", "run", "inspect", "verify-mutation"]
    assert result["evidence_level"] == "verified_mutation"
    assert result["pre_git_snapshot"] != result["post_git_snapshot"]
    assert result["task_completion"] == "not_inferred"


def test_canary_rejects_arise_and_remote_connected_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arise_parent = tmp_path / "ARISE"
    arise_parent.mkdir()
    spec_path, raw = _spec(arise_parent, "read_only")
    with pytest.raises(canary.CanaryError, match="ARISE"):
        canary.load_spec(spec_path)

    safe_parent = tmp_path / "safe"
    safe_parent.mkdir()
    safe_spec_path, _safe_raw = _spec(safe_parent, "read_only")
    safe_spec = canary.load_spec(safe_spec_path)
    _run_git(
        Path(safe_spec["scratch_root"]),
        "remote",
        "add",
        "origin",
        "https://example.invalid/repo.git",
    )
    monkeypatch.setattr(
        canary,
        "_bridge_json",
        lambda *_args, **_kwargs: pytest.fail("bridge must not be called"),
    )
    with pytest.raises(canary.CanaryError, match="no Git remotes"):
        canary.run_canary(safe_spec, execute=False)
