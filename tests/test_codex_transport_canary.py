from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any
import zipfile

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
SOURCE_COMMIT = "c" * 40
SOURCE_TREE = "d" * 40
PACKAGE_VERSION = "0.4.0a4"
CONSOLE_SCRIPTS = {
    "aoi": "aoi_orgware.cli:main",
    "aoi-claude-hook": "aoi_orgware.claude_hook:main",
    "aoi-codex-bridge": "aoi_orgware.codex_transport_cli:main",
    "aoi-codex-hook": "aoi_orgware.codex_hook:main",
}


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
    assert canary._EXPECTED_CONSOLE_SCRIPTS == CONSOLE_SCRIPTS


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


def _record_hash(data: bytes) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(data).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def _record_name(path: Path, site_root: Path) -> str:
    return os.path.relpath(path, site_root).replace(os.sep, "/")


def _minimal_wheel_bytes() -> bytes:
    dist_info = f"aoi_orgware-{PACKAGE_VERSION}.dist-info"
    members = {
        "aoi_orgware/__init__.py": f'__version__ = "{PACKAGE_VERSION}"\n'.encode(),
        "aoi_orgware/codex_transport_cli.py": (
            b"import argparse\n"
            b"def main(argv=None):\n"
            b"    print('{}')\n"
            b"    return 0\n"
        ),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: aoi-orgware\n"
            f"Version: {PACKAGE_VERSION}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: deterministic-test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
        f"{dist_info}/entry_points.txt": (
            "[console_scripts]\n"
            + "".join(
                f"{name} = {target}\n"
                for name, target in CONSOLE_SCRIPTS.items()
            )
        ).encode(),
    }
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, payload in sorted(members.items()):
        writer.writerow([name, f"sha256={_record_hash(payload)}", str(len(payload))])
    writer.writerow([f"{dist_info}/RECORD", "", ""])
    members[f"{dist_info}/RECORD"] = stream.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)
    return output.getvalue()


def _bridge_installation(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any]]:
    prefix = tmp_path / "bridge-venv"
    scripts = prefix / ("Scripts" if os.name == "nt" else "bin")
    python_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_root = (
        prefix / "Lib" / "site-packages"
        if os.name == "nt"
        else prefix / "lib" / python_version / "site-packages"
    )
    package_root = site_root / "aoi_orgware"
    dist_info = site_root / f"aoi_orgware-{PACKAGE_VERSION}.dist-info"
    scripts.mkdir(parents=True)
    package_root.mkdir(parents=True)
    dist_info.mkdir(parents=True)
    base_python = Path(
        getattr(sys, "_base_executable", None) or sys.executable
    ).resolve()
    version = ".".join(str(value) for value in sys.version_info[:3])
    (prefix / "pyvenv.cfg").write_text(
        f"home = {base_python.parent}\n"
        "include-system-site-packages = false\n"
        f"version = {version}\n"
        f"executable = {base_python}\n"
        f"command = {base_python} -m venv {prefix}\n",
        encoding="utf-8",
    )
    launcher_suffix = ".exe" if os.name == "nt" else ""
    launcher_paths: dict[str, Path] = {}
    for name in CONSOLE_SCRIPTS:
        launcher = scripts / f"{name}{launcher_suffix}"
        launcher.write_bytes(
            BRIDGE_BYTES
            if name == "aoi-codex-bridge"
            else f"fake {name} entry point".encode()
        )
        launcher_paths[name] = launcher
    bridge = launcher_paths["aoi-codex-bridge"]
    wheel = tmp_path / f"aoi_orgware-{PACKAGE_VERSION}-py3-none-any.whl"
    wheel.write_bytes(_minimal_wheel_bytes())
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith("/RECORD"):
                continue
            target = site_root / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
    (dist_info / "INSTALLER").write_bytes(b"pip\n")
    (dist_info / "REQUESTED").write_bytes(b"")
    direct_url = {
        "archive_info": {
            "hash": f"sha256={wheel_sha}",
            "hashes": {"sha256": wheel_sha},
        },
        "url": wheel.resolve().as_uri(),
    }
    (dist_info / "direct_url.json").write_text(
        json.dumps(direct_url, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    record_path = dist_info / "RECORD"
    installed_files = sorted(
        [
            *(path for path in package_root.rglob("*") if path.is_file()),
            *(
                path
                for path in dist_info.rglob("*")
                if path.is_file() and path != record_path
            ),
            *launcher_paths.values(),
        ],
        key=lambda path: _record_name(path, site_root),
    )
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for path in installed_files:
        data = path.read_bytes()
        writer.writerow(
            [
                _record_name(path, site_root),
                f"sha256={_record_hash(data)}",
                str(len(data)),
            ]
        )
    writer.writerow([_record_name(record_path, site_root), "", ""])
    record_path.write_text(stream.getvalue(), encoding="utf-8", newline="")

    package_receipt = {
        "schema": canary._PACKAGE_RECEIPT_SCHEMA,
        "head": SOURCE_COMMIT,
        "tree": SOURCE_TREE,
        "version": PACKAGE_VERSION,
        "source_date_epoch": 1,
        "release_tools_lock_sha256": SHA_A,
        "bootstrap_python": sys.executable,
        "build_python": sys.executable,
        "source_clean": True,
        "verify_dist_exit_code": 0,
        "artifacts": [
            {
                "name": wheel.name,
                "size_bytes": wheel.stat().st_size,
                "sha256": wheel_sha,
            }
        ],
        "recorded_at": "2026-07-24T00:00:00Z",
    }
    receipt = tmp_path / "package-receipt.json"
    receipt.write_text(
        json.dumps(package_receipt, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    binding = {
        "package_receipt_file": str(receipt.resolve()),
        "package_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "expected_source_commit_oid": SOURCE_COMMIT,
        "expected_source_tree_oid": SOURCE_TREE,
        "expected_wheel_sha256": wheel_sha,
        "wheel_file": str(wheel.resolve()),
        "site_packages_root": str(site_root.resolve()),
        "distribution_info_root": str(dist_info.resolve()),
    }
    return bridge.resolve(), binding


def _spec(tmp_path: Path, mode: str) -> tuple[Path, dict[str, Any]]:
    root = tmp_path / "scratch"
    _repository(root, mode)
    codex = tmp_path / "codex.exe"
    codex.write_bytes(b"exact pinned fake Codex executable")
    bridge, bridge_install_binding = _bridge_installation(tmp_path)
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
        "bridge_install_binding": bridge_install_binding,
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


def _issued_preflight(spec: dict[str, Any]) -> dict[str, Any]:
    intent = {
        "packet_id": "canary-packet",
        "intent_sha256": SHA_A,
        "cwd": canary._contract_path(Path(spec["scratch_root"])),
        "sandbox": canary._MODES[spec["mode"]],
        "approval": "never",
        "network_access": False,
        "runtime_pin": dict(spec["runtime_pin"]),
    }
    return {
        "task_id": spec["task_id"],
        "launch_id": spec["launch_id"],
        "packet_id": intent["packet_id"],
        "packet_status": "armed",
        "permit_sha256": spec["permit_sha256"],
        "intent": intent,
        "issuance": {
            "task_id": spec["task_id"],
            "launch_id": spec["launch_id"],
            "permit_sha256": spec["permit_sha256"],
            "intent_sha256": intent["intent_sha256"],
            "issuance_sha256": SHA_B,
        },
        "semantic_head_sha256": "e" * 64,
        "status": "issued_unconsumed",
        "evidence_level": "transport_issued",
        "permit_consumed": False,
        "runtime_evidence": "none",
        "confidentiality_warnings": [],
        "task_completion": "not_inferred",
    }


def _run_result(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": spec["task_id"],
        "launch_id": spec["launch_id"],
        "permit_sha256": spec["permit_sha256"],
        "terminal_state": "completed",
        "terminal_receipt_sha256": SHA_A,
        "evidence_level": "codex_runtime_observed",
        "runtime_completed": True,
        "process_start_evidence": "process_started_observed",
        "app_server_start_durably_observed": True,
        "runtime_process_boundary_reached": True,
        "confidentiality_warnings": [],
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
    inspected = _inspect(spec, completed=True)

    assert inspected["intent"]["cwd"] == Path(spec["scratch_root"]).as_posix()
    assert (
        inspected["intent"]["runtime_pin"]["executable_path"]
        == Path(spec["codex_executable"]).as_posix()
    )
    canary._validate_policy(spec, inspected)


@pytest.mark.parametrize("section", ["reservation", "issuance"])
def test_policy_rejects_same_task_cross_permit_launch(
    tmp_path: Path,
    section: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    inspected = _inspect(spec, completed=True)
    inspected[section]["permit_sha256"] = SHA_A

    with pytest.raises(
        canary.CanaryError,
        match="not bound to the exact permit",
    ):
        canary._validate_policy(spec, inspected)


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


def test_bridge_invocation_uses_fixed_installed_module_not_launcher(
    tmp_path: Path,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)

    assert Path(raw["bridge_executable"]).read_bytes() == BRIDGE_BYTES
    assert canary._bridge_json(spec, ["inspect"]) == {}


def test_bridge_invocation_keeps_stdlib_ahead_of_installed_site_root(
    tmp_path: Path,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    site_root = Path(raw["bridge_install_binding"]["site_packages_root"])
    (site_root / "argparse.py").write_text(
        "raise RuntimeError('installed stdlib shadow executed')\n",
        encoding="utf-8",
    )
    spec = canary.load_spec(spec_path)

    assert canary._bridge_json(spec, ["inspect"]) == {}


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


def test_bridge_install_binding_records_exact_package_closure(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    binding = spec["bridge_install_binding"]
    closure = binding["closure"]

    assert closure["source_commit_oid"] == SOURCE_COMMIT
    assert closure["source_tree_oid"] == SOURCE_TREE
    assert closure["wheel_sha256"] == binding["expected_wheel_sha256"]
    assert closure["package_receipt_sha256"] == binding["package_receipt_sha256"]
    assert closure["record_rows"] >= 9
    assert closure["namespace"]["file_count"] >= 9
    assert {
        row["name"]: row["target"] for row in closure["console_scripts"]
    } == CONSOLE_SCRIPTS
    assert len(closure["console_scripts"]) == 4
    assert all(
        Path(row["path"]).is_file() and row["sha256"] and row["size_bytes"] > 0
        for row in closure["console_scripts"]
    )
    assert closure["bridge_runtime_python"]["execution_mode"] == (
        "isolated_no_site_fixed_module"
    )
    assert Path(closure["bridge_runtime_python"]["path"]).is_file()
    assert closure["pyvenv_configuration"][
        "include-system-site-packages"
    ] == "false"
    assert closure["closure_sha256"] == canary._digest(
        {key: value for key, value in closure.items() if key != "closure_sha256"}
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("package", "installed RECORD member bytes drifted"),
        ("package_hardlink", "regular non-linked file"),
        ("unrecorded", "differs from exact RECORD closure"),
        ("record", "installed RECORD"),
        ("direct_url", "installed RECORD member bytes drifted"),
        ("other_launcher", "installed RECORD member bytes drifted"),
        ("wheel", "release wheel bytes drifted"),
        ("receipt", "release package receipt bytes drifted"),
        ("pyvenv", "installed-distribution binding drifted"),
        ("pth", "may not contain a .pth authority path"),
        ("shadow", "AOI import shadow"),
        ("extra_dist", "another AOI distribution"),
    ],
)
def test_bridge_install_binding_rejects_distribution_drift(
    tmp_path: Path,
    change: str,
    message: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    binding = spec["bridge_install_binding"]
    site_root = Path(binding["site_packages_root"])
    dist_info = Path(binding["distribution_info_root"])

    if change == "package":
        target = site_root / "aoi_orgware" / "codex_transport_cli.py"
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == "package_hardlink":
        target = site_root / "aoi_orgware" / "codex_transport_cli.py"
        os.link(target, tmp_path / "installed-package-hardlink.py")
    elif change == "unrecorded":
        (site_root / "aoi_orgware" / "unexpected.py").write_text(
            "not in RECORD\n",
            encoding="utf-8",
        )
    elif change == "record":
        with (dist_info / "RECORD").open("ab") as handle:
            handle.write(b"\n")
    elif change == "direct_url":
        target = dist_info / "direct_url.json"
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == "other_launcher":
        bridge = Path(spec["bridge_executable"])
        suffix = ".exe" if os.name == "nt" else ""
        target = bridge.parent / f"aoi{suffix}"
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == "wheel":
        target = Path(binding["wheel_file"])
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == "receipt":
        target = Path(binding["package_receipt_file"])
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == "pyvenv":
        prefix = Path(spec["bridge_executable"]).parent.parent
        with (prefix / "pyvenv.cfg").open("a", encoding="utf-8") as handle:
            handle.write("prompt = drift\n")
    elif change == "pth":
        (site_root / "authority.pth").write_text(
            "import aoi_orgware\n",
            encoding="utf-8",
        )
    elif change == "shadow":
        (site_root / "aoi_orgware.py").write_text(
            "raise RuntimeError('shadow')\n",
            encoding="utf-8",
        )
    else:
        (site_root / "aoi_orgware-copy.dist-info").mkdir()

    with pytest.raises(canary.CanaryError, match=message):
        canary._revalidate_bridge_binding(spec)


def test_bridge_install_binding_rejects_self_consistent_installed_record_rewrite(
    tmp_path: Path,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    binding = spec["bridge_install_binding"]
    site_root = Path(binding["site_packages_root"])
    target = site_root / "aoi_orgware" / "codex_transport_cli.py"
    target.write_bytes(b"def main():\n    return 1\n")
    record_path = Path(binding["distribution_info_root"]) / "RECORD"
    rows = list(csv.reader(record_path.read_text(encoding="utf-8").splitlines()))
    target_name = _record_name(target, site_root)
    for row in rows:
        if row[0] == target_name:
            payload = target.read_bytes()
            row[1] = f"sha256={_record_hash(payload)}"
            row[2] = str(len(payload))
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    record_path.write_text(stream.getvalue(), encoding="utf-8", newline="")

    with pytest.raises(
        canary.CanaryError,
        match="installed payload differs from exact wheel bytes",
    ):
        canary._revalidate_bridge_binding(spec)


def test_bridge_install_binding_hashes_the_exact_wheel_bytes_it_parses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    original = canary._bounded_regular_bytes

    def substitute_wheel_bytes(
        path: Path,
        label: str,
        **kwargs: Any,
    ) -> bytes:
        if label == "release wheel":
            return b"self-consistent alternate wheel bytes"
        return original(path, label, **kwargs)

    monkeypatch.setattr(canary, "_bounded_regular_bytes", substitute_wheel_bytes)
    with pytest.raises(canary.CanaryError, match="release wheel bytes drifted"):
        canary._revalidate_bridge_binding(spec)


@pytest.mark.parametrize(
    "extra",
    [
        "include-system-site-packages = true\n",
        "home = C:/hostile-runtime\n",
    ],
)
def test_bridge_install_binding_rejects_ambiguous_pyvenv_authority(
    tmp_path: Path,
    extra: str,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    prefix = Path(raw["bridge_executable"]).parent.parent
    with (prefix / "pyvenv.cfg").open("a", encoding="utf-8") as handle:
        handle.write(extra)

    with pytest.raises(
        canary.CanaryError,
        match="pyvenv.cfg is ambiguous or invalid",
    ):
        canary.load_spec(spec_path)


def test_bridge_install_binding_rejects_pyvenv_prefix_superstring(
    tmp_path: Path,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    prefix = Path(raw["bridge_executable"]).parent.parent
    config_path = prefix / "pyvenv.cfg"
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        config.replace(
            f" -m venv {prefix}\n",
            f" -m venv {prefix}-hostile\n",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        canary.CanaryError,
        match="pyvenv.cfg creation command drifted",
    ):
        canary.load_spec(spec_path)


def _rebind_wheel_fixture(
    spec_path: Path,
    raw: dict[str, Any],
    wheel_bytes: bytes,
) -> None:
    binding = raw["bridge_install_binding"]
    wheel_path = Path(binding["wheel_file"])
    wheel_path.write_bytes(wheel_bytes)
    wheel_sha = hashlib.sha256(wheel_bytes).hexdigest()
    receipt_path = Path(binding["package_receipt_file"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["artifacts"] = [
        {"name": wheel_path.name, "size_bytes": len(wheel_bytes), "sha256": wheel_sha}
    ]
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    binding["expected_wheel_sha256"] = wheel_sha
    binding["package_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("duplicate", "duplicate or case-colliding"),
        ("traversal", "wheel member path is invalid"),
        ("symlink", "special"),
    ],
)
def test_bridge_install_binding_rejects_malformed_wheel_members(
    tmp_path: Path,
    kind: str,
    message: str,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_STORED) as archive:
        if kind == "duplicate":
            archive.writestr("aoi_orgware/__init__.py", b"one\n")
            archive.writestr("aoi_orgware/__init__.py", b"two\n")
        elif kind == "traversal":
            archive.writestr("../escape.py", b"escape\n")
        else:
            info = zipfile.ZipInfo("aoi_orgware/linked.py")
            info.external_attr = 0o120777 << 16
            archive.writestr(info, b"target")
    _rebind_wheel_fixture(spec_path, raw, payload.getvalue())

    with pytest.raises(canary.CanaryError, match=message):
        canary.load_spec(spec_path)


@pytest.mark.parametrize(
    "name",
    [
        "sitecustomize.py",
        "sitecustomize.pyc",
        "sitecustomize.pyd",
        "sitecustomize.so",
        "usercustomize.py",
        "usercustomize.pyc",
    ],
)
def test_bridge_install_binding_rejects_startup_injection(
    tmp_path: Path,
    name: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    Path(spec["bridge_install_binding"]["site_packages_root"], name).write_text(
        "raise RuntimeError('startup injection')\n",
        encoding="utf-8",
    )

    with pytest.raises(canary.CanaryError, match="startup injection"):
        canary._revalidate_bridge_binding(spec)


@pytest.mark.parametrize("name", ["sitecustomize", "usercustomize"])
def test_bridge_install_binding_rejects_startup_injection_package(
    tmp_path: Path,
    name: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    Path(spec["bridge_install_binding"]["site_packages_root"], name).mkdir()

    with pytest.raises(canary.CanaryError, match="startup injection"):
        canary._revalidate_bridge_binding(spec)


def test_bridge_install_binding_rejects_linked_ancestor(
    tmp_path: Path,
) -> None:
    spec_path, raw = _spec(tmp_path, "read_only")
    binding = raw["bridge_install_binding"]
    actual_lib = Path(binding["site_packages_root"]).parent
    alias = tmp_path / "linked-lib"
    if os.name == "nt":
        completed = subprocess.run(
            [
                os.environ.get("COMSPEC", "cmd.exe"),
                "/d",
                "/c",
                "mklink",
                "/J",
                str(alias),
                str(actual_lib),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            pytest.skip("Windows junction creation is unavailable")
    else:
        alias.symlink_to(actual_lib, target_is_directory=True)
    try:
        site_alias = alias / "site-packages"
        binding["site_packages_root"] = str(site_alias.absolute())
        binding["distribution_info_root"] = str(
            (
                site_alias
                / Path(binding["distribution_info_root"]).name
            ).absolute()
        )
        spec_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
        with pytest.raises(
            canary.CanaryError,
            match="resolves through a link or reparse boundary",
        ):
            canary.load_spec(spec_path)
    finally:
        if os.name == "nt":
            alias.rmdir()
        else:
            alias.unlink()


def test_bridge_revalidates_installed_package_after_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    package_file = (
        Path(spec["bridge_install_binding"]["site_packages_root"])
        / "aoi_orgware"
        / "codex_transport_cli.py"
    )

    def mutate_during_subprocess(
        *_args: Any,
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        data = package_file.read_bytes()
        package_file.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        return subprocess.CompletedProcess([], 0, b"{}", b"")

    monkeypatch.setattr(canary, "_run_process", mutate_during_subprocess)
    with pytest.raises(
        canary.CanaryError,
        match="installed RECORD member bytes drifted",
    ):
        canary._bridge_json(spec, ["inspect"])


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
    filemode = subprocess.run(
        [str(_git()), "-C", str(root), "config", "--get", "core.filemode"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip().casefold()
    assert filemode in {"true", "false"}
    drifted_filemode = "false" if filemode == "true" else "true"

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
            _run_git(root, "config", "core.filemode", drifted_filemode)
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
        [
            "preflight",
            "--task",
            "canary-task",
            "--permit-sha256",
            SHA_B,
            "--prompt-file",
            "prompt.txt",
        ],
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
    seen_argv: list[str] = []

    def fake_run(
        argv: list[str],
        *,
        environment: dict[str, str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        seen_argv.extend(argv)
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
    monkeypatch.setenv("PYTHONSTARTUP", "must-not-influence-bridge")
    monkeypatch.setenv("VIRTUAL_ENV", "must-not-influence-bridge")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setenv("LD_PRELOAD", "must-not-pass")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "must-not-pass")
    monkeypatch.setenv("NODE_OPTIONS", "must-not-pass")
    monkeypatch.setenv("HTTP_PROXY", "must-not-pass")
    monkeypatch.setenv("HTTPS_PROXY", "must-not-pass")
    monkeypatch.setenv("NO_PROXY", "must-not-pass")
    monkeypatch.setenv("UNRELATED_AMBIENT_AUTHORITY", "must-not-pass")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "ambient-system-root"))
    monkeypatch.setenv("WINDIR", str(tmp_path / "ambient-windir"))

    canary._bridge_json(spec, args)

    runtime_python = spec["bridge_install_binding"]["closure"][
        "bridge_runtime_python"
    ]
    assert seen_argv[:9] == [
        runtime_python["path"],
        "-I",
        "-S",
        "-B",
        "-X",
        "utf8",
        "-c",
        canary._BRIDGE_MODULE_BOOTSTRAP,
        spec["bridge_install_binding"]["site_packages_root"],
    ]
    assert str(raw["bridge_executable"]) not in seen_argv[:1]
    assert seen_argv[9:11] == ["--root", str(spec["aoi_root"])]
    assert seen["CODEX_HOME"] == Path(raw["codex_home"]).as_posix()
    assert seen["HOME"] == seen["CODEX_HOME"]
    assert seen["USERPROFILE"] == seen["CODEX_HOME"]
    assert seen["PYTHONDONTWRITEBYTECODE"] == "1"
    assert seen["PYTHONNOUSERSITE"] == "1"
    assert seen["PYTHONSAFEPATH"] == "1"
    assert seen["PYTHONUTF8"] == "1"
    assert "PYTHONPATH" not in seen
    assert "PYTHONHOME" not in seen
    assert "VIRTUAL_ENV" not in seen
    assert "GIT_DIR" not in seen
    assert "GIT_CONFIG_COUNT" not in seen
    assert "GIT_CONFIG_KEY_0" not in seen
    assert "GIT_CONFIG_VALUE_0" not in seen
    assert "SSH_AUTH_SOCK" not in seen
    for name in (
        "OPENAI_API_KEY",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "NODE_OPTIONS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "UNRELATED_AMBIENT_AUTHORITY",
    ):
        assert name not in seen
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
    expected_keys = {
        "CODEX_HOME",
        "HOME",
        "USERPROFILE",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
        "PYTHONUTF8",
        "LANG",
        "LC_ALL",
        "TEMP",
        "TMP",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ATTR_NOSYSTEM",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
        "GCM_INTERACTIVE",
    }
    if os.name == "nt":
        assert seen["SYSTEMROOT"] != str(tmp_path / "ambient-system-root")
        assert seen["WINDIR"] != str(tmp_path / "ambient-windir")
        expected_keys.update(
            {
                "HOMEDRIVE",
                "HOMEPATH",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
            }
        )
    assert set(seen) == expected_keys


def test_preflight_is_read_only_and_does_not_start_app_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    calls: list[list[str]] = []

    def fake_bridge(current: dict[str, Any], args: list[str]) -> dict[str, Any]:
        calls.append(args)
        assert args[0] == "preflight"
        return _issued_preflight(current)

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
        "bridge_install_binding",
        "git_executable",
        "scratch_root",
        "pre_git_snapshot",
        "issued_preflight_sha256",
        "status",
        "live_app_server_started",
        "task_completion",
    }
    assert [call[0] for call in calls] == ["preflight"]


@pytest.mark.parametrize(
    "mutation",
    ["extra_field", "consumed", "wrong_launch", "network_enabled"],
)
def test_preflight_rejects_noncanonical_or_consumed_issuance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    spec_path, _raw = _spec(tmp_path, "read_only")
    spec = canary.load_spec(spec_path)
    observed = _issued_preflight(spec)
    if mutation == "extra_field":
        observed["unexpected"] = True
        message = "fields differ"
    elif mutation == "consumed":
        observed["permit_consumed"] = True
        message = "unconsumed launch"
    elif mutation == "wrong_launch":
        observed["launch_id"] = "another-launch"
        message = "exact launch"
    else:
        observed["intent"]["network_access"] = True
        message = "intent differs"

    monkeypatch.setattr(
        canary,
        "_bridge_json",
        lambda _spec, args: (
            observed
            if args[0] == "preflight"
            else pytest.fail("preflight failure must not reach another command")
        ),
    )
    with pytest.raises(canary.CanaryError, match=message):
        canary.run_canary(spec, execute=True)


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
        if args[0] == "preflight":
            return _issued_preflight(current)
        if args[0] == "run":
            completed = True
            return _run_result(current)
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
        "bridge_install_binding",
        "git_executable",
        "scratch_root",
        "pre_git_snapshot",
        "issued_preflight_sha256",
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
        if args[0] == "preflight":
            return _issued_preflight(current)
        if args[0] == "run":
            (Path(current["scratch_root"]) / "workload.txt").write_text(
                "after\n", encoding="utf-8"
            )
            completed = True
            return _run_result(current)
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

    assert commands == ["preflight", "run", "inspect", "verify-mutation"]
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
        "bridge_install_binding",
        "git_executable",
        "scratch_root",
        "pre_git_snapshot",
        "issued_preflight_sha256",
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
        if args[0] == "preflight":
            return _issued_preflight(current)
        if args[0] == "run":
            exclude = Path(current["scratch_root"]) / ".git" / "info" / "exclude"
            exclude.write_text("metadata-only-change\n", encoding="utf-8")
            completed = True
            return _run_result(current)
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
    assert commands == ["preflight", "run", "inspect"]


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
        if args[0] == "preflight":
            return _issued_preflight(current)
        if args[0] == "run":
            root = Path(current["scratch_root"])
            (root / "workload.txt").write_text("after\n", encoding="utf-8")
            (root / ".git" / "info" / "exclude").write_text(
                "authority-change\n",
                encoding="utf-8",
            )
            completed = True
            return _run_result(current)
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
    assert commands == ["preflight", "run", "inspect"]


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
        if args[0] == "preflight":
            return _issued_preflight(current)
        if args[0] == "run":
            root = Path(current["scratch_root"])
            (root / "ignored.txt").write_text("hidden delta\n", encoding="utf-8")
            if tracked_change:
                (root / "workload.txt").write_text(
                    "visible delta\n",
                    encoding="utf-8",
                )
            completed = True
            return _run_result(current)
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
