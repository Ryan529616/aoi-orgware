#!/usr/bin/env python3
"""Run one real AOI entrypoint behind an exact state-lock test gate."""

from __future__ import annotations

import argparse
import base64
import io
import json
import socket
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import codex_hook  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402


def _run_hook(payload: bytes) -> int:
    """Invoke the handler dispatcher with a real binary-backed stdin."""

    original_argv = sys.argv
    original_stdin = sys.stdin
    hook_stdin = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
    try:
        sys.stdin = hook_stdin
        codex_hook.dispatch(codex_hook.read_input(), project_root=Path.cwd())
        return 0
    finally:
        sys.argv = original_argv
        sys.stdin = original_stdin
        hook_stdin.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--mode", choices=("cli", "hook"), required=True)
    parser.add_argument(
        "--gate-stage",
        choices=("before_acquire", "acquired"),
        default="before_acquire",
    )
    parser.add_argument("--hook-payload-b64")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command.pop(0)
    if args.mode == "cli" and not command:
        parser.error("CLI mode requires command arguments after --")
    if args.mode == "hook" and (command or args.hook_payload_b64 is None):
        parser.error("hook mode requires --hook-payload-b64 and no command")

    reached_boundary = False

    def wait_at_lock_boundary(event: h._StateLockAcquisitionEvent) -> None:
        nonlocal reached_boundary
        if reached_boundary or event.stage != args.gate_stage:
            return
        reached_boundary = True
        message = {
            "actor": args.actor,
            "stage": event.stage,
            "path": str(event.path),
            "st_dev": event.st_dev,
            "st_ino": event.st_ino,
        }
        with socket.create_connection((args.host, args.port), timeout=10) as gate:
            gate.settimeout(10)
            gate.sendall(json.dumps(message, sort_keys=True).encode("utf-8") + b"\n")
            if gate.recv(1) != b"G":
                raise RuntimeError("state-lock race gate closed without releasing actor")

    with h._observe_state_lock_acquisition(wait_at_lock_boundary):
        if args.mode == "cli":
            return cli_impl.main(command)
        if args.mode == "hook":
            payload = base64.b64decode(args.hook_payload_b64, validate=True)
            return _run_hook(payload)
        raise AssertionError(f"unsupported race worker mode: {args.mode}")


if __name__ == "__main__":
    raise SystemExit(main())
