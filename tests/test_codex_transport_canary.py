from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest

from aoi_orgware import codex_app_server_stdio as app_server
from aoi_orgware import confidentiality


_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "codex_transport_canary.py"
)
_SPEC = importlib.util.spec_from_file_location("codex_transport_canary", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
canary = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(canary)

SHA_A = "a" * 64
SHA_B = "b" * 64
BRIDGE_BYTES = b"fake bridge entry point"
BRIDGE_SAME_SIZE_DRIFT = b"drifted bridge payload!"
assert len(BRIDGE_SAME_SIZE_DRIFT) == len(BRIDGE_BYTES)


def test_canary_policy_constants_match_runtime_enforcement() -> None:
    assert canary._LOCAL_FILES_MAX_BYTES == app_server.DEFAULT_MAX_LINE_BYTES
    assert canary._LOCAL_FILES_HOME_NAMES == app_server._LOCAL_FILES_HOME_NAMES
    assert canary._LOCAL_FILES_CONFIG == app_server._LOCAL_FILES_CONFIG
    assert (
        canary._LOCAL_FILES_MANAGED_CONFIG
        == app_server._LOCAL_FILES_MANAGED_CONFIG
    )
    assert (
        canary._LOCAL_FILES_THREAD_CONFIG
        == app_server._LOCAL_FILES_THREAD_CONFIG
    )
    assert canary._AOI_SECRET_ENV_PREFIXES == app_server._AOI_SECRET_ENV_PREFIXES
    assert canary._AOI_SECRET_ENV_NAMES == app_server._AOI_SECRET_ENV_NAMES
    assert (
        canary._PUBLISH_CREDENTIAL_NAMES
        == confidentiality._STRONG_PUBLISH_CREDENTIAL_NAMES
    )
    assert (
        canary._PUBLISH_CREDENTIAL_PREFIXES
        == confidentiality._STRONG_PUBLISH_CREDENTIAL_PREFIXES
    )


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
    _run_git(root, "config", "core.autocrlf", "false")
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
    (root / ".aoi").mkdir()
    (root / ".aoi" / "state.json").write_text("{}\n", encoding="utf-8")
    _run_git(root, "add", ".")
    _run_git(root, "commit", "-m", "seed disposable canary")


def _spec(tmp_path: Path, mode: str) -> tuple[Path, dict[str, Any]]:
    root = tmp_path / "scratch"
    _repository(root, mode)
    codex = tmp_path / "codex.exe"
    codex.write_bytes(b"exact pinned fake Codex executable")
    bridge = tmp_path / "aoi-codex-bridge.exe"
    bridge.write_bytes(BRIDGE_BYTES)
    codex_home = tmp_path / "isolated-codex-home"
    codex_home.mkdir()
    (codex_home / "auth.json").write_text(
        '{"tokens":{"openai":"secret-not-for-receipts"}}', encoding="utf-8"
    )
    (codex_home / "config.toml").write_text(
        'web_search = "disabled"\n\n'
        "[features]\napps = false\nremote_plugin = false\nmulti_agent = false\n\n"
        "[apps._default]\nenabled = false\n",
        encoding="utf-8",
    )
    (codex_home / "managed_config.toml").write_text(
        "allow_remote_control = false\nallowed_web_search_modes = []\n\n"
        "[features]\napps = false\nremote_plugin = false\nmulti_agent = false\n",
        encoding="utf-8",
    )
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
        "bridge_executable_sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
        "bridge_executable_size_bytes": bridge.stat().st_size,
        "git_executable": str(_git()),
        "git_executable_sha256": hashlib.sha256(_git().read_bytes()).hexdigest(),
        "git_executable_size_bytes": _git().stat().st_size,
        "scratch_root": str(root.resolve()),
        "codex_home": str(codex_home.resolve()),
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
        "reservation": {
            "classification": "committed",
            "permit_sha256": spec["permit_sha256"],
            "evidence_level": "transport_reserved",
        },
        "issuance": {
            "classification": "committed",
            "permit_sha256": spec["permit_sha256"],
        },
        "lifecycle": lifecycle,
        "terminal_receipts": terminal,
        "evidence_level": evidence,
        "task_completion": "not_inferred",
    }


def _verified_mutation(
    spec: dict[str, Any],
    *paths: str,
) -> dict[str, Any]:
    encoded = sorted(
        base64.b64encode(path.encode("utf-8")).decode("ascii")
        for path in paths
    )
    return {
        "evidence_level": "verified_mutation",
        "mutation_object_sha256": SHA_A,
        "post_endpoint_sha256": SHA_B,
        "post_mutation_paths_b64": encoded,
        "post_mutation_paths_sha256": canary._digest(
            {
                "schema": canary._GIT_MUTATION_PATHS_SCHEMA,
                "paths_b64": encoded,
            }
        ),
        "git_executable": {
            "schema": canary._GIT_EXECUTABLE_BINDING_SCHEMA,
            "path": canary._contract_path(Path(spec["git_executable"])),
            "size_bytes": spec["git_executable_size_bytes"],
            "sha256": spec["git_executable_sha256"],
            "provenance_scope": canary._GIT_EXECUTABLE_PROVENANCE_SCOPE,
        },
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


@pytest.mark.parametrize("section", ["reservation", "issuance"])
def test_policy_rejects_same_task_cross_permit_launch(
    tmp_path: Path,
    section: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    inspected = _inspect(spec, completed=False)
    inspected[section]["permit_sha256"] = SHA_A

    with pytest.raises(
        canary.CanaryError,
        match="not bound to the exact permit",
    ):
        canary._validate_policy(spec, inspected, fresh=True)


def test_v2_spec_is_rejected_after_git_authority_fields_changed(
    tmp_path: Path,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    raw["schema_version"] = "aoi.codex-transport-canary.v2"
    spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")

    with pytest.raises(canary.CanaryError, match="schema_version is unsupported"):
        canary.load_spec(spec_path)


def test_spec_rejects_duplicate_json_object_keys(tmp_path: Path) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    text = spec_path.read_text(encoding="utf-8")
    assert text.endswith("}")
    spec_path.write_text(
        text[:-1] + ', "mode": "read_only"}',
        encoding="utf-8",
    )

    with pytest.raises(canary.CanaryError, match="duplicate object keys"):
        canary.load_spec(spec_path)


@pytest.mark.parametrize(
    ("token", "message"),
    [
        ("NaN", "non-finite JSON number"),
        ("Infinity", "non-finite JSON number"),
        ("1e999", "outside 1..900"),
    ],
)
def test_spec_rejects_nonfinite_timeout(
    tmp_path: Path,
    token: str,
    message: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    text = spec_path.read_text(encoding="utf-8")
    assert '"timeout_seconds": 30' in text
    spec_path.write_text(
        text.replace('"timeout_seconds": 30', f'"timeout_seconds": {token}'),
        encoding="utf-8",
    )

    with pytest.raises(canary.CanaryError, match=message):
        canary.load_spec(spec_path)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_run_process_bounds_output_while_child_is_running(stream: str) -> None:
    script = (
        "import sys\n"
        f"stream = sys.{stream}.buffer\n"
        f"stream.write(b'x' * {canary._MAX_JSON_BYTES + 65536})\n"
        "stream.flush()\n"
    )

    with pytest.raises(
        canary.CanaryError,
        match="output exceeds the bounded canary limit",
    ):
        canary._run_process(
            [sys.executable, "-c", script],
            timeout_seconds=10.0,
        )


def test_codex_home_binding_is_exact_and_auth_safe(tmp_path: Path) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)

    binding = spec["codex_home_policy"]
    inventory = binding["initial_inventory"]
    auth = next(row for row in inventory if row["name"] == "auth.json")
    assert binding["codex_home"] == Path(raw["codex_home"]).as_posix()
    assert set(binding) >= {
        "config_path",
        "config_sha256",
        "managed_config_path",
        "managed_config_sha256",
        "thread_config_sha256",
    }
    assert set(auth) == {"name", "path", "size_bytes", "type"}
    assert "secret-not-for-receipts" not in json.dumps(binding)


@pytest.mark.parametrize("change", ["missing", "extra", "policy_drift"])
def test_codex_home_rejects_inventory_and_policy_drift(
    tmp_path: Path, change: str
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    home = Path(raw["codex_home"])
    if change == "missing":
        (home / "auth.json").unlink()
    elif change == "extra":
        (home / "unexpected.txt").write_text("no", encoding="utf-8")
    else:
        (home / "config.toml").write_text('web_search = "live"\n', encoding="utf-8")

    with pytest.raises(canary.CanaryError, match="codex_home"):
        canary.load_spec(spec_path)


def test_codex_home_rejects_missing_directory_as_canary_error(
    tmp_path: Path,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    raw["codex_home"] = str((tmp_path / "missing-codex-home").resolve())
    spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")

    with pytest.raises(canary.CanaryError, match="codex_home"):
        canary.load_spec(spec_path)


def test_bridge_executable_bytes_are_bound(tmp_path: Path) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    Path(raw["bridge_executable"]).write_bytes(BRIDGE_SAME_SIZE_DRIFT)

    with pytest.raises(canary.CanaryError, match="bridge_executable bytes drifted"):
        canary.load_spec(spec_path)


def test_bridge_revalidates_binary_and_codex_home_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    monkeypatch.setattr(
        canary,
        "_run_process",
        lambda *_args, **_kwargs: pytest.fail("bridge must not start after drift"),
    )
    Path(raw["bridge_executable"]).write_bytes(BRIDGE_SAME_SIZE_DRIFT)
    with pytest.raises(canary.CanaryError, match="bridge_executable bytes drifted"):
        canary._bridge_json(spec, ["inspect"])

    fresh = tmp_path / "fresh"
    fresh.mkdir()
    fresh_spec_path, fresh_raw = _spec(fresh, "read_only")
    fresh_spec = canary.load_spec(fresh_spec_path)
    (Path(fresh_raw["codex_home"]) / "config.toml").write_text(
        'web_search = "live"\n', encoding="utf-8"
    )
    with pytest.raises(canary.CanaryError, match="codex_home"):
        canary._bridge_json(fresh_spec, ["inspect"])

    codex_parent = tmp_path / "codex-drift"
    codex_parent.mkdir()
    codex_spec_path, codex_raw = _spec(codex_parent, "read_only")
    codex_spec = canary.load_spec(codex_spec_path)
    codex_path = Path(codex_raw["codex_executable"])
    with codex_path.open("r+b") as handle:
        first = handle.read(1)
        handle.seek(0)
        handle.write(bytes([first[0] ^ 0xFF]))
    with pytest.raises(canary.CanaryError, match="runtime_pin executable bytes drifted"):
        canary._bridge_json(codex_spec, ["inspect"])


def test_git_executable_load_time_drift_is_rejected(tmp_path: Path) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    copied_git = tmp_path / f"load-time-git{_git().suffix}"
    shutil.copy2(_git(), copied_git)
    raw["git_executable"] = str(copied_git.resolve())
    raw["git_executable_size_bytes"] = copied_git.stat().st_size
    raw["git_executable_sha256"] = hashlib.sha256(
        copied_git.read_bytes()
    ).hexdigest()
    spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    with copied_git.open("r+b") as handle:
        first = handle.read(1)
        handle.seek(0)
        handle.write(bytes([first[0] ^ 0xFF]))

    with pytest.raises(canary.CanaryError, match="git_executable bytes drifted"):
        canary.load_spec(spec_path)


def test_git_executable_bytes_are_bound_and_revalidated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    copied_git = tmp_path / f"copied-git{_git().suffix}"
    shutil.copy2(_git(), copied_git)
    raw["git_executable"] = str(copied_git.resolve())
    raw["git_executable_size_bytes"] = copied_git.stat().st_size
    raw["git_executable_sha256"] = hashlib.sha256(
        copied_git.read_bytes()
    ).hexdigest()
    spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    spec = canary.load_spec(spec_path)
    monkeypatch.setattr(
        canary,
        "_run_process",
        lambda *_args, **_kwargs: pytest.fail("drifted Git must not start"),
    )

    with copied_git.open("r+b") as handle:
        first = handle.read(1)
        handle.seek(0)
        handle.write(bytes([first[0] ^ 0xFF]))

    with pytest.raises(canary.CanaryError, match="git_executable bytes drifted"):
        canary._git(spec, ["status"])


def test_executable_hashing_is_streamed_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    executable_paths = {
        Path(raw["codex_executable"]).resolve(),
        Path(raw["bridge_executable"]).resolve(),
        Path(raw["git_executable"]).resolve(),
    }
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path.resolve() in executable_paths:
            pytest.fail("executable binding must not use Path.read_bytes")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    canary.load_spec(spec_path)

    raw["bridge_executable_size_bytes"] = canary._MAX_EXECUTABLE_BYTES + 1
    spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    with pytest.raises(
        canary.CanaryError,
        match="bridge_executable_size_bytes is invalid",
    ):
        canary.load_spec(spec_path)


def test_stable_streaming_hash_rejects_stat_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"stable bytes")
    original = canary._path_stat_fingerprint
    calls = 0

    def drifted(value: os.stat_result) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        result = original(value)
        if calls == 2:
            return (*result[:-1], result[-1] ^ 1)
        return result

    monkeypatch.setattr(canary, "_path_stat_fingerprint", drifted)
    with pytest.raises(canary.CanaryError, match="changed while hashing"):
        canary._stable_regular_file_sha256(
            subject,
            "subject",
            max_bytes=1024,
        )


def test_git_subprocess_scrubs_ambient_repository_and_config_routing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    seen: dict[str, str] = {}

    def fake_run(
        argv: list[str],
        *,
        environment: dict[str, str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        seen.update(environment)
        return subprocess.CompletedProcess([], 0, b"", b"")

    monkeypatch.setattr(canary, "_run_process", fake_run)
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_EXEC_PATH",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
    ):
        monkeypatch.setenv(name, "must-not-pass")

    canary._git_raw(spec, ["status"])

    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_EXEC_PATH",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
    ):
        assert name not in seen
    assert seen["GIT_CONFIG_NOSYSTEM"] == "1"
    assert seen["GIT_CONFIG_GLOBAL"] == os.devnull
    assert seen["GIT_ATTR_NOSYSTEM"] == "1"
    assert seen["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert seen["GIT_OPTIONAL_LOCKS"] == "0"
    assert seen["GIT_TERMINAL_PROMPT"] == "0"
    assert seen["GCM_INTERACTIVE"] == "Never"


def test_real_git_validation_ignores_ambient_repository_and_config_routing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "outside.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "outside-worktree"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "outside.index"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.https://evil.invalid/.pushInsteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://example.invalid/")

    canary._validate_scratch(spec)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("core.fsmonitor", "must-not-run"),
        ("core.hooksPath", "must-not-run"),
        ("include.path", "../outside.gitconfig"),
        ("filter.exfil.process", "must-not-run"),
        ("diff.exfil.command", "must-not-run"),
        ("merge.exfil.driver", "must-not-run"),
        ("credential.helper", "must-not-run"),
        ("core.sshCommand", "must-not-run"),
    ],
)
def test_unapproved_local_git_authority_is_rejected_before_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    _run_git(Path(spec["scratch_root"]), "config", key, value)
    calls: list[list[str]] = []
    original = canary._git_raw

    def observed(
        current: dict[str, Any],
        args: list[str],
        *,
        allow_codes: set[int] | None = None,
    ) -> bytes:
        calls.append(list(args))
        return original(current, args, allow_codes=allow_codes)

    monkeypatch.setattr(canary, "_git_raw", observed)
    with pytest.raises(
        canary.CanaryError,
        match="unapproved local authority",
    ):
        canary._validate_scratch(spec)

    assert not any("status" in call for call in calls)


def test_allowed_local_git_config_drift_cannot_mix_snapshot_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    root = Path(spec["scratch_root"])
    original = canary._git
    calls = 0

    def drift_after_first_command(
        current: dict[str, Any],
        args: list[str],
        *,
        allow_codes: set[int] | None = None,
    ) -> bytes:
        nonlocal calls
        result = original(current, args, allow_codes=allow_codes)
        calls += 1
        if calls == 1:
            _run_git(root, "config", "core.filemode", "true")
        return result

    monkeypatch.setattr(canary, "_git", drift_after_first_command)
    with pytest.raises(
        canary.CanaryError,
        match="changed during Git snapshot",
    ):
        canary._git_snapshot(spec)


@pytest.mark.parametrize(
    ("relative", "as_directory"),
    [
        ("commondir", False),
        ("gitdir", False),
        ("config.worktree", False),
        ("worktrees", True),
        ("shallow", False),
        ("info/grafts", False),
        ("objects/info/alternates", False),
        ("objects/info/http-alternates", False),
        ("refs/replace", True),
    ],
)
def test_nonconfig_git_repository_authority_is_rejected_before_git_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    as_directory: bool,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    subject = Path(spec["scratch_root"]) / ".git" / Path(relative)
    subject.parent.mkdir(parents=True, exist_ok=True)
    if as_directory:
        subject.mkdir()
    else:
        subject.write_text("../outside.git\n", encoding="utf-8")
    monkeypatch.setattr(
        canary,
        "_run_process",
        lambda *_args, **_kwargs: pytest.fail(
            "Git must not start after repository-authority injection"
        ),
    )

    with pytest.raises(canary.CanaryError, match="forbidden"):
        canary._git(spec, ["status"])


def test_packed_replace_ref_is_rejected_before_git_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    packed_refs = Path(spec["scratch_root"]) / ".git" / "packed-refs"
    packed_refs.write_text(
        f"{'1' * 40} refs/replace/{'2' * 40}\n",
        encoding="ascii",
    )
    monkeypatch.setattr(
        canary,
        "_run_process",
        lambda *_args, **_kwargs: pytest.fail(
            "Git must not start with a packed replace ref"
        ),
    )

    with pytest.raises(canary.CanaryError, match="packed replace refs"):
        canary._git(spec, ["status"])


def test_git_info_authority_drift_cannot_mix_snapshot_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    exclude = Path(spec["scratch_root"]) / ".git" / "info" / "exclude"
    original = canary._git
    calls = 0

    def drift_after_first_command(
        current: dict[str, Any],
        args: list[str],
        *,
        allow_codes: set[int] | None = None,
    ) -> bytes:
        nonlocal calls
        result = original(current, args, allow_codes=allow_codes)
        calls += 1
        if calls == 1:
            exclude.write_text("# changed local exclude authority\n", encoding="utf-8")
        return result

    monkeypatch.setattr(canary, "_git", drift_after_first_command)
    with pytest.raises(
        canary.CanaryError,
        match="authority changed during Git snapshot",
    ):
        canary._git_snapshot(spec)


def test_scratch_marker_is_narrowly_bounded(tmp_path: Path) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    marker = Path(spec["scratch_root"]) / canary.ROOT_MARKER
    marker.write_bytes(b"{" + b" " * canary._ROOT_MARKER_MAX_BYTES + b"}")

    with pytest.raises(canary.CanaryError, match="outside the bounded limit"):
        canary._validate_scratch(spec)


def test_scratch_marker_rejects_duplicate_json_object_keys(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    marker = Path(spec["scratch_root"]) / canary.ROOT_MARKER
    marker.write_text(
        json.dumps(
            {
                "schema_version": canary.ROOT_MARKER_SCHEMA,
                "purpose": "disposable Codex transport canary",
                "mode": "read_only",
            }
        )[:-1]
        + ', "mode": "read_only"}',
        encoding="utf-8",
    )

    with pytest.raises(canary.CanaryError, match="strict UTF-8 JSON"):
        canary._validate_scratch(spec)


def test_scratch_marker_rejects_hardlink(tmp_path: Path) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    marker = Path(spec["scratch_root"]) / canary.ROOT_MARKER
    os.link(marker, tmp_path / "marker-hardlink.json")

    with pytest.raises(canary.CanaryError, match="regular non-linked file"):
        canary._validate_scratch(spec)


def test_scratch_marker_rejects_stat_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    original = canary._path_stat_fingerprint
    calls = 0

    def drifted(value: os.stat_result) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        result = original(value)
        if calls == 2:
            return (*result[:-1], result[-1] ^ 1)
        return result

    monkeypatch.setattr(canary, "_path_stat_fingerprint", drifted)
    with pytest.raises(canary.CanaryError, match="changed while bound"):
        canary._validate_scratch(spec)


@pytest.mark.parametrize(
    "args",
    [
        ["inspect", "--task", "canary-task", "--launch-id", "canary-launch"],
        ["run", "--task", "canary-task", "--permit-sha256", SHA_B],
        ["verify-mutation", "--task", "canary-task", "--launch-id", "canary-launch"],
    ],
)
def test_all_bridge_subprocesses_use_isolated_redacted_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    ambient_home = tmp_path / "ambient-codex-home"
    seen: dict[str, str] = {}

    def fake_run(
        argv: list[str],
        *,
        environment: dict[str, str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        seen.update(environment)
        return subprocess.CompletedProcess([], 0, b"{}", b"")

    monkeypatch.setattr(canary, "_run_process", fake_run)
    monkeypatch.setenv("CODEX_HOME", str(ambient_home))
    monkeypatch.setenv("AOI_CHIEF_CREDENTIAL_FILE", "must-not-pass")
    monkeypatch.setenv("AOI_CREDENTIAL_FILE", "must-not-pass")
    monkeypatch.setenv("AOI_ROOT_TOKEN", "must-not-pass")
    monkeypatch.setenv("AOI_BACKUP_ROOT", "must-not-pass")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-pass")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "must-not-pass")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "must-not-pass")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "must-not-pass")
    monkeypatch.setenv("ACTIONS_RESULTS_URL", "must-not-pass")
    monkeypatch.setenv("TWINE_PASSWORD", "must-not-pass")
    monkeypatch.setenv("GIT_DIR", "must-not-pass")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.fake.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://example.invalid/")
    monkeypatch.setenv("SSH_AUTH_SOCK", "must-not-pass")
    monkeypatch.setenv("PYTHONPATH", "must-not-influence-bridge")
    monkeypatch.setenv("PYTHONHOME", "must-not-influence-bridge")
    monkeypatch.setenv("VIRTUAL_ENV", "must-not-influence-bridge")
    monkeypatch.setenv("OPENAI_API_KEY", "model-auth-must-pass")

    canary._bridge_json(spec, args)

    assert seen["CODEX_HOME"] == Path(raw["codex_home"]).as_posix()
    assert seen["OPENAI_API_KEY"] == "model-auth-must-pass"
    assert seen["PYTHONNOUSERSITE"] == "1"
    assert seen["PYTHONSAFEPATH"] == "1"
    assert "PYTHONPATH" not in seen
    assert "PYTHONHOME" not in seen
    assert "VIRTUAL_ENV" not in seen
    assert "GIT_DIR" not in seen
    assert "GIT_CONFIG_COUNT" not in seen
    assert "GIT_CONFIG_KEY_0" not in seen
    assert "GIT_CONFIG_VALUE_0" not in seen
    assert "SSH_AUTH_SOCK" not in seen
    assert seen["GIT_CONFIG_NOSYSTEM"] == "1"
    assert seen["GIT_CONFIG_GLOBAL"] == os.devnull
    assert seen["GIT_ATTR_NOSYSTEM"] == "1"
    assert seen["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert seen["GIT_OPTIONAL_LOCKS"] == "0"
    assert seen["GIT_TERMINAL_PROMPT"] == "0"
    assert not any(
        name.startswith(canary._AOI_SECRET_ENV_PREFIXES)
        or name == "AOI_BACKUP_ROOT"
        or canary._is_publish_credential_name(name)
        for name in seen
    )


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
    assert result["git_executable"] == {
        "path": canary._contract_path(Path(spec["git_executable"])),
        "size_bytes": spec["git_executable_size_bytes"],
        "sha256": spec["git_executable_sha256"],
    }
    assert result["scratch_root"] == canary._contract_path(
        Path(spec["scratch_root"])
    )
    assert set(result) == {
        "schema_version",
        "mode",
        "task_id",
        "launch_id",
        "permit_sha256",
        "runtime_pin",
        "codex_home_policy",
        "bridge_executable",
        "git_executable",
        "scratch_root",
        "pre_git_snapshot",
        "reserved_inspect_sha256",
        "status",
        "live_app_server_started",
        "task_completion",
    }
    assert [call[0] for call in calls] == ["inspect"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink regression")
def test_workspace_snapshot_rejects_directory_symlink_escape(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("must not be read\n", encoding="utf-8")
    (Path(spec["scratch_root"]) / "escape").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(
        canary.CanaryError,
        match="cannot contain links or reparses",
    ):
        canary._workspace_files(Path(spec["scratch_root"]))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_workspace_snapshot_rejects_windows_junction_escape(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("must not be read\n", encoding="utf-8")
    junction = Path(spec["scratch_root"]) / "junction"
    completed = subprocess.run(
        [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(outside),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        pytest.fail(
            "could not create Windows junction: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    try:
        with pytest.raises(
            canary.CanaryError,
            match="cannot contain links or reparses",
        ):
            canary._workspace_files(Path(spec["scratch_root"]))
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink regression")
def test_git_metadata_binding_rejects_nested_symlink_escape(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    outside = tmp_path / "outside-git-metadata"
    outside.mkdir()
    (outside / "object").write_text("must not be read\n", encoding="utf-8")
    escape = Path(spec["scratch_root"]) / ".git" / "objects" / "escape"
    escape.symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        canary.CanaryError,
        match="cannot contain links or reparses",
    ):
        canary._git_metadata_binding(spec)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_git_metadata_binding_rejects_nested_windows_junction_escape(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    outside = tmp_path / "outside-git-metadata"
    outside.mkdir()
    (outside / "object").write_text("must not be read\n", encoding="utf-8")
    junction = Path(spec["scratch_root"]) / ".git" / "objects" / "escape"
    completed = subprocess.run(
        [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(outside),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        pytest.fail(
            "could not create Windows junction: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    try:
        with pytest.raises(
            canary.CanaryError,
            match="cannot contain links or reparses",
        ):
            canary._git_metadata_binding(spec)
    finally:
        junction.rmdir()


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
    assert set(result) == {
        "schema_version",
        "mode",
        "task_id",
        "launch_id",
        "permit_sha256",
        "runtime_pin",
        "codex_home_policy",
        "bridge_executable",
        "git_executable",
        "scratch_root",
        "pre_git_snapshot",
        "reserved_inspect_sha256",
        "status",
        "live_app_server_started",
        "run_result_sha256",
        "completed_inspect_sha256",
        "post_git_snapshot",
        "mutation_receipt",
        "evidence_level",
        "task_completion",
    }


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
            assert args[args.index("--git-executable") + 1] == str(
                current["git_executable"]
            )
            assert args[args.index("--git-executable-size-bytes") + 1] == str(
                current["git_executable_size_bytes"]
            )
            assert args[args.index("--git-executable-sha256") + 1] == str(
                current["git_executable_sha256"]
            )
            return _verified_mutation(current, "workload.txt")
        assert args[0] == "inspect"
        return _inspect(current, completed=completed)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)
    result = canary.run_canary(spec, execute=True)

    assert commands == ["inspect", "run", "inspect", "verify-mutation"]
    assert result["evidence_level"] == "verified_mutation"
    assert result["pre_git_snapshot"] != result["post_git_snapshot"]
    assert result["task_completion"] == "not_inferred"
    assert set(result) == {
        "schema_version",
        "mode",
        "task_id",
        "launch_id",
        "permit_sha256",
        "runtime_pin",
        "codex_home_policy",
        "bridge_executable",
        "git_executable",
        "scratch_root",
        "pre_git_snapshot",
        "reserved_inspect_sha256",
        "status",
        "live_app_server_started",
        "run_result_sha256",
        "completed_inspect_sha256",
        "post_git_snapshot",
        "mutation_receipt",
        "evidence_level",
        "task_completion",
    }


def test_writable_canary_rejects_git_metadata_only_mutation(
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
            exclude = Path(current["scratch_root"]) / ".git" / "info" / "exclude"
            exclude.write_text("metadata-only-change\n", encoding="utf-8")
            completed = True
            return {"terminal_state": "completed"}
        if args[0] == "verify-mutation":
            pytest.fail("metadata-only mutation must not be elevated")
        assert args[0] == "inspect"
        return _inspect(current, completed=completed)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)

    with pytest.raises(
        canary.CanaryError,
        match="made no workload mutation",
    ):
        canary.run_canary(spec, execute=True)
    assert commands == ["inspect", "run", "inspect"]


def test_writable_canary_rejects_git_authority_change_with_workload_mutation(
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
            root = Path(current["scratch_root"])
            (root / "workload.txt").write_text("after\n", encoding="utf-8")
            (root / ".git" / "info" / "exclude").write_text(
                "authority-change\n",
                encoding="utf-8",
            )
            completed = True
            return {"terminal_state": "completed"}
        if args[0] == "verify-mutation":
            pytest.fail("Git-authority mutation must not be elevated")
        assert args[0] == "inspect"
        return _inspect(current, completed=completed)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)

    with pytest.raises(
        canary.CanaryError,
        match="changed Git repository authority",
    ):
        canary.run_canary(spec, execute=True)
    assert commands == ["inspect", "run", "inspect"]


@pytest.mark.parametrize(
    "tracked_change",
    [False, True],
    ids=["ignored-only", "tracked-plus-ignored"],
)
def test_writable_canary_rejects_workload_paths_omitted_from_git_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracked_change: bool,
) -> None:
    spec_path, _raw = _spec(tmp_path, "workspace_write")
    spec = canary.load_spec(spec_path)
    root = Path(spec["scratch_root"])
    (root / ".git" / "info" / "exclude").write_text(
        "ignored.txt\n",
        encoding="utf-8",
    )
    completed = False

    def fake_bridge(current: dict[str, Any], args: list[str]) -> dict[str, Any]:
        nonlocal completed
        if args[0] == "run":
            root = Path(current["scratch_root"])
            (root / "ignored.txt").write_text("hidden delta\n", encoding="utf-8")
            if tracked_change:
                (root / "workload.txt").write_text(
                    "visible delta\n",
                    encoding="utf-8",
                )
            completed = True
            return {"terminal_state": "completed"}
        if args[0] == "verify-mutation":
            return _verified_mutation(
                current,
                *(("workload.txt",) if tracked_change else ()),
            )
        assert args[0] == "inspect"
        return _inspect(current, completed=completed)

    monkeypatch.setattr(canary, "_bridge_json", fake_bridge)

    with pytest.raises(
        canary.CanaryError,
        match="omits direct workload delta paths",
    ):
        canary.run_canary(spec, execute=True)


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
    with pytest.raises(canary.CanaryError, match="Git remote"):
        canary.run_canary(safe_spec, execute=False)


def test_canary_rejects_whitespace_named_git_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    _run_git(
        Path(spec["scratch_root"]),
        "config",
        "remote. .url",
        "https://example.invalid/repo.git",
    )
    monkeypatch.setattr(
        canary,
        "_bridge_json",
        lambda *_args, **_kwargs: pytest.fail("bridge must not be called"),
    )

    with pytest.raises(canary.CanaryError, match="Git remote"):
        canary.run_canary(spec, execute=False)
