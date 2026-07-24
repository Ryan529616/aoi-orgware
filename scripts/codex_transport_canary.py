"""Run one bounded Codex transport canary in a disposable local repository.

This driver never issues authority.  It consumes an already issued one-shot
transport permit, refuses non-disposable or remotely connected repositories,
and separates read-only runtime evidence from writable Git-mutation evidence.
The default is preflight-only; ``--execute`` is required to start App Server.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "aoi.codex-transport-canary.v1"
ROOT_MARKER = ".aoi-codex-transport-canary.json"
ROOT_MARKER_SCHEMA = "aoi.codex-transport-canary-root.v1"
_MODES = {
    "read_only": "readOnly",
    "workspace_write": "workspaceWrite",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_FILES = 4096
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024


class CanaryError(ValueError):
    """The canary is unsafe, malformed, or did not produce the required evidence."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CanaryError(f"{label} schema is invalid")
    return dict(value)


def _text(value: Any, label: str, *, limit: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise CanaryError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _text(value, label, limit=128)
    if not all(
        char.isascii() and (char.isalnum() or char in "._:-")
        for char in result
    ):
        raise CanaryError(f"{label} is invalid")
    return result


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise CanaryError(f"{label} is not lowercase SHA-256")
    return value


def _absolute_file(value: Any, label: str) -> Path:
    raw = (
        str(value)
        if isinstance(value, os.PathLike)
        else _text(value, label, limit=4096)
    )
    path = Path(raw)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise CanaryError(f"{label} must be an existing absolute regular file")
    return path.resolve()


def _absolute_directory(value: Any, label: str) -> Path:
    raw = _text(value, label, limit=4096)
    path = Path(raw)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise CanaryError(f"{label} must be an existing absolute directory")
    return path.resolve()


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(
        str(right.resolve())
    )


def _contract_path(path: Path) -> str:
    """Return the canonical absolute spelling used by transport contracts."""

    result = path.resolve(strict=True).as_posix()
    if "\\" in result:
        raise CanaryError("could not canonicalize path for transport contract")
    return result


def _under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _runtime_pin(value: Any) -> dict[str, Any]:
    result = _object(
        value,
        {
            "codex_cli_version",
            "codex_app_server_version",
            "app_server_executable_sha256",
            "schema_manifest_sha256",
            "combined_v2_schema_sha256",
            "executable_path",
            "executable_size_bytes",
        },
        "runtime_pin",
    )
    executable = _absolute_file(
        result["executable_path"], "runtime_pin.executable_path"
    )
    size = result["executable_size_bytes"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 1
        or size > 2**63 - 1
    ):
        raise CanaryError("runtime_pin.executable_size_bytes is invalid")
    normalized = {
        "codex_cli_version": _text(
            result["codex_cli_version"],
            "runtime_pin.codex_cli_version",
            limit=128,
        ),
        "codex_app_server_version": _text(
            result["codex_app_server_version"],
            "runtime_pin.codex_app_server_version",
            limit=128,
        ),
        "app_server_executable_sha256": _sha256(
            result["app_server_executable_sha256"],
            "runtime_pin.app_server_executable_sha256",
        ),
        "schema_manifest_sha256": _sha256(
            result["schema_manifest_sha256"],
            "runtime_pin.schema_manifest_sha256",
        ),
        "combined_v2_schema_sha256": _sha256(
            result["combined_v2_schema_sha256"],
            "runtime_pin.combined_v2_schema_sha256",
        ),
        "executable_path": _contract_path(executable),
        "executable_size_bytes": size,
    }
    actual_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    if (
        actual_sha256 != normalized["app_server_executable_sha256"]
        or executable.stat().st_size != normalized["executable_size_bytes"]
    ):
        raise CanaryError("runtime_pin executable bytes drifted")
    return normalized


def load_spec(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise CanaryError("spec must be an existing absolute regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > _MAX_JSON_BYTES:
        raise CanaryError("spec size is invalid")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryError("spec must be strict UTF-8 JSON") from exc
    value = _object(
        parsed,
        {
            "schema_version",
            "mode",
            "aoi_root",
            "task_id",
            "launch_id",
            "permit_sha256",
            "prompt_file",
            "codex_executable",
            "bridge_executable",
            "git_executable",
            "scratch_root",
            "runtime_pin",
            "timeout_seconds",
            "post_git_endpoint_file",
        },
        "spec",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise CanaryError("spec schema_version is unsupported")
    mode = _text(value["mode"], "mode", limit=32)
    if mode not in _MODES:
        raise CanaryError("mode is unsupported")
    scratch_root = _absolute_directory(value["scratch_root"], "scratch_root")
    aoi_root = _absolute_directory(value["aoi_root"], "aoi_root")
    if not _same_path(scratch_root, aoi_root):
        raise CanaryError("aoi_root must equal the disposable scratch_root")
    if any(part.casefold() == "arise" for part in scratch_root.parts):
        raise CanaryError("ARISE may not be used as a transport canary root")
    prompt_file = _absolute_file(value["prompt_file"], "prompt_file")
    if not _under(prompt_file, scratch_root):
        raise CanaryError("prompt_file must remain inside scratch_root")
    runtime_pin = _runtime_pin(value["runtime_pin"])
    codex_executable = _absolute_file(
        value["codex_executable"], "codex_executable"
    )
    if not _same_path(
        codex_executable, Path(runtime_pin["executable_path"])
    ):
        raise CanaryError("codex_executable differs from runtime_pin")
    bridge_executable = _absolute_file(
        value["bridge_executable"], "bridge_executable"
    )
    git_executable = _absolute_file(value["git_executable"], "git_executable")
    timeout_seconds = value["timeout_seconds"]
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds < 1
        or timeout_seconds > 900
    ):
        raise CanaryError("timeout_seconds is outside 1..900")
    post_endpoint = value["post_git_endpoint_file"]
    post_endpoint_path: Path | None = None
    if post_endpoint is not None:
        post_endpoint_path = _absolute_file(
            post_endpoint, "post_git_endpoint_file"
        )
        if not _under(post_endpoint_path, scratch_root):
            raise CanaryError(
                "post_git_endpoint_file must remain inside scratch_root"
            )
    if mode == "read_only" and post_endpoint_path is not None:
        raise CanaryError("read_only canary cannot carry a post Git endpoint")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "aoi_root": aoi_root,
        "task_id": _identifier(value["task_id"], "task_id"),
        "launch_id": _identifier(value["launch_id"], "launch_id"),
        "permit_sha256": _sha256(value["permit_sha256"], "permit_sha256"),
        "prompt_file": prompt_file,
        "codex_executable": codex_executable,
        "bridge_executable": bridge_executable,
        "git_executable": git_executable,
        "scratch_root": scratch_root,
        "runtime_pin": runtime_pin,
        "timeout_seconds": float(timeout_seconds),
        "post_git_endpoint_file": post_endpoint_path,
    }


def _run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    allow_codes: set[int] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    allowed = {0} if allow_codes is None else allow_codes
    try:
        completed = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CanaryError(f"command execution failed: {argv[0]}") from exc
    if len(completed.stdout) > _MAX_JSON_BYTES or len(completed.stderr) > _MAX_JSON_BYTES:
        raise CanaryError("command output exceeds the bounded canary limit")
    if completed.returncode not in allowed:
        stderr = completed.stderr.decode("utf-8", errors="replace")[:1024]
        raise CanaryError(
            f"command failed with status {completed.returncode}: {stderr}"
        )
    return completed


def _git(
    spec: Mapping[str, Any],
    args: Sequence[str],
    *,
    allow_codes: set[int] | None = None,
) -> bytes:
    completed = _run_process(
        [
            str(spec["git_executable"]),
            "-C",
            str(spec["scratch_root"]),
            *args,
        ],
        timeout_seconds=min(float(spec["timeout_seconds"]), 30.0),
        allow_codes=allow_codes,
    )
    return completed.stdout


def _validate_scratch(spec: Mapping[str, Any]) -> None:
    root = Path(spec["scratch_root"])
    marker = _absolute_file(root / ROOT_MARKER, "scratch marker")
    try:
        marker_value = json.loads(marker.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryError("scratch marker must be strict UTF-8 JSON") from exc
    expected_marker = {
        "schema_version": ROOT_MARKER_SCHEMA,
        "purpose": "disposable Codex transport canary",
        "mode": spec["mode"],
    }
    if marker_value != expected_marker:
        raise CanaryError("scratch marker does not exactly authorize this mode")
    top = _git(spec, ["rev-parse", "--show-toplevel"]).decode(
        "utf-8", errors="strict"
    ).strip()
    if not _same_path(Path(top), root):
        raise CanaryError("scratch_root is not the exact Git top level")
    if _git(spec, ["remote"]).strip():
        raise CanaryError("transport canary repository must have no Git remotes")
    rewrites = _git(
        spec,
        [
            "config",
            "--show-origin",
            "--get-regexp",
            r"^url\..*\.(insteadOf|pushInsteadOf)$",
        ],
        allow_codes={0, 1},
    )
    if rewrites.strip():
        raise CanaryError("transport canary repository inherits URL rewrites")
    status = _git(
        spec, ["status", "--porcelain=v2", "--untracked-files=all"]
    )
    if status.strip():
        raise CanaryError("transport canary repository must begin Git-clean")


def _workspace_files(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in {".git", ".aoi"}:
            continue
        if path.is_symlink():
            raise CanaryError("transport canary workload cannot contain links")
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise CanaryError("transport canary workload file is too large")
        total_bytes += size
        if total_bytes > _MAX_TOTAL_BYTES or len(rows) >= _MAX_FILES:
            raise CanaryError("transport canary workload exceeds bounded limits")
        rows.append(
            {
                "path": relative.as_posix(),
                "size_bytes": size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return rows


def _git_snapshot(spec: Mapping[str, Any]) -> dict[str, str]:
    root = Path(spec["scratch_root"])
    head = _git(spec, ["rev-parse", "HEAD"]).decode(
        "ascii", errors="strict"
    ).strip()
    index = _git(spec, ["ls-files", "--stage", "-z"])
    status = _git(
        spec, ["status", "--porcelain=v2", "--untracked-files=all", "-z"]
    )
    files = _workspace_files(root)
    if _GIT_OID.fullmatch(head) is None:
        raise CanaryError("transport canary requires one committed Git HEAD")
    return {
        "head_sha256": hashlib.sha256(head.encode("ascii")).hexdigest(),
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "workload_files_sha256": _digest(files),
    }


def _bridge_json(
    spec: Mapping[str, Any],
    args: Sequence[str],
) -> dict[str, Any]:
    completed = _run_process(
        [
            str(spec["bridge_executable"]),
            "--root",
            str(spec["aoi_root"]),
            *args,
            "--json",
        ],
        timeout_seconds=float(spec["timeout_seconds"]) + 30.0,
    )
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryError("bridge did not return one UTF-8 JSON value") from exc
    if not isinstance(value, Mapping):
        raise CanaryError("bridge JSON result is not an object")
    return dict(value)


def _inspect(spec: Mapping[str, Any]) -> dict[str, Any]:
    return _bridge_json(
        spec,
        [
            "inspect",
            "--task",
            str(spec["task_id"]),
            "--launch-id",
            str(spec["launch_id"]),
        ],
    )


def _validate_policy(
    spec: Mapping[str, Any],
    inspected: Mapping[str, Any],
    *,
    fresh: bool,
) -> None:
    if (
        inspected.get("task_id") != spec["task_id"]
        or inspected.get("launch_id") != spec["launch_id"]
        or inspected.get("contract_version") != "v2"
    ):
        raise CanaryError("inspect result does not identify the exact V2 launch")
    intent = inspected.get("intent")
    if not isinstance(intent, Mapping):
        raise CanaryError("inspect result has no authenticated intent")
    expected_runtime = dict(spec["runtime_pin"])
    if (
        intent.get("cwd") != _contract_path(Path(spec["scratch_root"]))
        or intent.get("sandbox") != _MODES[str(spec["mode"])]
        or intent.get("approval") != "never"
        or intent.get("network_access") is not False
        or intent.get("runtime_pin") != expected_runtime
    ):
        raise CanaryError("inspect intent differs from the canary policy")
    reservation = inspected.get("reservation")
    if not isinstance(reservation, Mapping) or (
        reservation.get("evidence_level") != "transport_reserved"
    ):
        raise CanaryError("inspect reservation is not transport_reserved")
    if inspected.get("task_completion") != "not_inferred":
        raise CanaryError("transport inspect inferred task completion")
    lifecycle = inspected.get("lifecycle")
    if not isinstance(lifecycle, list) or not lifecycle:
        raise CanaryError("transport inspect lifecycle is missing")
    if fresh:
        if (
            len(lifecycle) != 1
            or lifecycle[0].get("event_type") != "reserved"
            or inspected.get("terminal_receipts") != []
            or inspected.get("evidence_level") != "transport_reserved"
        ):
            raise CanaryError("canary launch is not one fresh reservation")
        return
    terminal = inspected.get("terminal_receipts")
    if (
        not isinstance(terminal, list)
        or len(terminal) != 1
        or terminal[0].get("classification") != "committed"
        or terminal[0].get("terminal_state") != "completed"
        or terminal[0].get("evidence_level") != "codex_runtime_observed"
        or inspected.get("evidence_level") != "codex_runtime_observed"
    ):
        raise CanaryError("live canary lacks one committed completed receipt")


def run_canary(spec: Mapping[str, Any], *, execute: bool) -> dict[str, Any]:
    _validate_scratch(spec)
    before = _git_snapshot(spec)
    reserved = _inspect(spec)
    _validate_policy(spec, reserved, fresh=True)
    basis = {
        "schema_version": SCHEMA_VERSION,
        "mode": spec["mode"],
        "task_id": spec["task_id"],
        "launch_id": spec["launch_id"],
        "permit_sha256": spec["permit_sha256"],
        "runtime_pin": spec["runtime_pin"],
        "scratch_root": str(spec["scratch_root"]),
        "pre_git_snapshot": before,
        "reserved_inspect_sha256": _digest(reserved),
    }
    if not execute:
        return {
            **basis,
            "status": "preflight_ready",
            "live_app_server_started": False,
            "task_completion": "not_inferred",
        }
    run_result = _bridge_json(
        spec,
        [
            "run",
            "--task",
            str(spec["task_id"]),
            "--permit-sha256",
            str(spec["permit_sha256"]),
            "--prompt-file",
            str(spec["prompt_file"]),
            "--executable",
            str(spec["codex_executable"]),
            "--timeout-seconds",
            str(spec["timeout_seconds"]),
        ],
    )
    completed = _inspect(spec)
    _validate_policy(spec, completed, fresh=False)
    after = _git_snapshot(spec)
    if spec["mode"] == "read_only":
        if after != before:
            raise CanaryError("read_only canary changed workload Git bytes")
        mutation: dict[str, Any] | None = None
        evidence_level = "codex_runtime_observed"
    else:
        if after == before:
            raise CanaryError("workspace_write canary made no workload mutation")
        verify_args = [
            "verify-mutation",
            "--task",
            str(spec["task_id"]),
            "--launch-id",
            str(spec["launch_id"]),
            "--sealed-claim-scope",
        ]
        endpoint = spec["post_git_endpoint_file"]
        if endpoint is not None:
            verify_args.extend(["--post-git-endpoint-file", str(endpoint)])
        mutation = _bridge_json(spec, verify_args)
        if (
            mutation.get("evidence_level") != "verified_mutation"
            or mutation.get("task_completion") != "not_inferred"
        ):
            raise CanaryError("writable canary was not elevated to verified_mutation")
        evidence_level = "verified_mutation"
    return {
        **basis,
        "status": "completed",
        "live_app_server_started": True,
        "run_result_sha256": _digest(run_result),
        "completed_inspect_sha256": _digest(completed),
        "post_git_snapshot": after,
        "mutation_receipt": mutation,
        "evidence_level": evidence_level,
        "task_completion": "not_inferred",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run one disposable Codex transport canary"
    )
    parser.add_argument("--spec", required=True)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="consume the permit and start App Server; absent means preflight-only",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        spec = load_spec(Path(args.spec))
        result = run_canary(spec, execute=args.execute)
    except (CanaryError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"{result['status']}: {result['mode']} "
            f"launch {result['launch_id']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
