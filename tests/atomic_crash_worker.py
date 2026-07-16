#!/usr/bin/env python3
"""Block at one private atomic-I/O event so a parent can terminate this process."""

from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path

from aoi_orgware import cli
from aoi_orgware import harnesslib as h


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--followup-stage")
    parser.add_argument("--payload")
    parser.add_argument("mode", choices=["write", "create", "cli"])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    destination = Path(args.destination).resolve()
    requested_stages = {args.stage}
    if args.followup_stage:
        requested_stages.add(args.followup_stage)
    reported: set[tuple[str, str]] = set()

    def report(
        *,
        operation: str,
        stage: str,
        event_destination: Path,
        temporary: Path | None,
        st_dev: int | None = None,
        st_ino: int | None = None,
    ) -> None:
        key = operation, stage
        if (
            event_destination != destination
            or stage not in requested_stages
            or key in reported
        ):
            return
        reported.add(key)
        with socket.create_connection((args.host, args.port), timeout=10) as control:
            control.settimeout(None)
            control.sendall(
                json.dumps(
                    {
                        "operation": operation,
                        "stage": stage,
                        "destination": str(event_destination),
                        "temporary": (
                            str(temporary) if temporary is not None else None
                        ),
                        "st_dev": st_dev,
                        "st_ino": st_ino,
                    },
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
            if control.recv(1) != b"G":
                raise RuntimeError("atomic crash controller closed without release")

    def observe_atomic_io(event: h._AtomicIOEvent) -> None:
        report(
            operation=event.operation,
            stage=event.stage,
            event_destination=event.destination,
            temporary=event.temporary,
        )

    def observe_state_lock(event: h._StateLockAcquisitionEvent) -> None:
        report(
            operation="state_lock",
            stage=event.stage,
            event_destination=event.path,
            temporary=None,
            st_dev=event.st_dev,
            st_ino=event.st_ino,
        )

    with h._observe_atomic_io(observe_atomic_io), h._observe_state_lock_acquisition(
        observe_state_lock
    ):
        if args.mode in {"write", "create"}:
            if not args.payload:
                parser.error(f"{args.mode} mode requires --payload")
            publish = (
                h.atomic_write_bytes
                if args.mode == "write"
                else h.atomic_create_bytes
            )
            publish(destination, Path(args.payload).read_bytes())
            return 0
        command = list(args.command)
        if command[:1] == ["--"]:
            command.pop(0)
        if not command:
            parser.error("cli mode requires a command after --")
        return cli.main(command)


if __name__ == "__main__":
    raise SystemExit(main())
