"""Project-bound client command for observational legacy bridge ingestion."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aoi_orgware.company.legacy_bridge_client import (
    LegacyBridgeClientError,
    LegacyBridgeIngestClientResult,
    run_legacy_bridge_ingest_v04,
)
from aoi_orgware.company.discovery import resolve_bound_company
from aoi_orgware.company.legacy_bridge_job_terminal_client import (
    LegacyBridgeJobTerminalClientError,
    LegacyBridgeJobTerminalClientResult,
    run_legacy_bridge_job_terminal_reconcile,
)
from aoi_orgware.legacy_bridge_job_terminal_v04 import (
    LegacyBridgeJobTerminalV04Error,
    produce_legacy_bridge_job_terminal_evidence_v04,
)
from aoi_orgware.legacy_bridge_snapshot_v04 import produce_legacy_bridge_snapshot_v04

from .company_runtime import CompanyRuntimeCommandError


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]
Runner = Callable[..., LegacyBridgeIngestClientResult]
TerminalRunner = Callable[..., LegacyBridgeJobTerminalClientResult]


class LegacyBridgeRuntimeCommandError(CompanyRuntimeCommandError):
    """One secret-free runtime client failure."""


def cmd_legacy_bridge_ingest_v04(
    args: argparse.Namespace,
    paths: Any,
    *,
    runner: Runner = run_legacy_bridge_ingest_v04,
) -> int:
    """Read one exact v0.4 task and submit it to an already-running owner."""

    root = getattr(paths, "root", None)
    if not isinstance(root, Path):
        raise LegacyBridgeRuntimeCommandError(
            "legacy-bridge ingest-v04 requires one initialized repository",
        )

    def source_loader(
        company_id: str,
        company_incarnation: int,
        lock_domain_generation: int,
        observed_at: str,
    ) -> bytes:
        return produce_legacy_bridge_snapshot_v04(
            paths,
            args.task,
            company_id,
            company_incarnation,
            lock_domain_generation,
            args.legacy_archive_sha256,
            args.source_version,
            observed_at,
        ).snapshot_bytes

    try:
        result = runner(
            root,
            task_id=args.task,
            legacy_archive_sha256=args.legacy_archive_sha256,
            source_version=args.source_version,
            source_loader=source_loader,
            company_id=args.company_id,
            timeout_seconds=args.timeout_seconds,
        )
        payload = result.public_dict()
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except LegacyBridgeClientError as exc:
        raise LegacyBridgeRuntimeCommandError(
            f"legacy-bridge ingest-v04 failed: {exc.code}",
        ) from exc
    except Exception as exc:
        raise LegacyBridgeRuntimeCommandError(
            "legacy-bridge ingest-v04 failed",
        ) from exc
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"effect: {payload['effect']}")
        print(f"gate_decision: {payload['gate_decision']}")
        print(f"gate_reason: {payload['gate_reason']}")
        print(f"attempt_id: {payload['attempt_id']}")
    return result.exit_code


def cmd_legacy_bridge_reconcile_job_terminal_v04(
    args: argparse.Namespace,
    paths: Any,
    *,
    runner: TerminalRunner = run_legacy_bridge_job_terminal_reconcile,
) -> int:
    """Publish one exact failed-job terminal receipt through the Supervisor."""

    root = getattr(paths, "root", None)
    if not isinstance(root, Path):
        raise LegacyBridgeRuntimeCommandError(
            "legacy-bridge reconcile-job-terminal-v04 requires one initialized repository",
        )
    exit_artifact = Path(str(args.process_exit_artifact))
    if not exit_artifact.is_absolute():
        raise LegacyBridgeRuntimeCommandError(
            "--process-exit-artifact must be an absolute path",
        )
    observed_at = datetime.now(timezone.utc).isoformat(
        timespec="microseconds",
    ).replace("+00:00", "Z")
    try:
        target = resolve_bound_company(root, args.company_id)
        manifest = target.manifest
        produced = produce_legacy_bridge_job_terminal_evidence_v04(
            paths,
            args.task,
            args.run_id,
            target.company_id,
            int(manifest["company_incarnation"]),
            int(manifest["lock_domain_generation"]),
            args.legacy_archive_sha256,
            args.source_version,
            observed_at,
            exit_artifact,
            args.process_exit_sha256,
        )
        result = runner(
            root,
            terminal_evidence=produced.evidence,
            terminal_artifacts=dict(produced.artifacts),
            company_id=args.company_id,
            timeout_seconds=args.timeout_seconds,
        )
        payload = result.public_dict()
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except LegacyBridgeJobTerminalClientError as exc:
        raise LegacyBridgeRuntimeCommandError(
            "legacy-bridge reconcile-job-terminal-v04 failed: "
            f"{exc.code} effect={exc.effect} cursor={exc.cursor}",
        ) from exc
    except LegacyBridgeJobTerminalV04Error as exc:
        raise LegacyBridgeRuntimeCommandError(
            f"legacy-bridge reconcile-job-terminal-v04 failed: {exc}",
        ) from exc
    except Exception as exc:
        raise LegacyBridgeRuntimeCommandError(
            "legacy-bridge reconcile-job-terminal-v04 failed",
        ) from exc
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        for field in (
            "effect", "global_sequence", "transaction_id", "terminal_key_id",
            "receipt_id", "idempotent_replay",
        ):
            print(f"{field}: {payload[field]}")
    return 0


def register_legacy_bridge_runtime_commands(
    subparsers: argparse._SubParsersAction[Any],
    *,
    handler: Handler,
    add_json_argument: JsonArgumentRegistrar,
    terminal_handler: Handler = cmd_legacy_bridge_reconcile_job_terminal_v04,
) -> None:
    """Register the no-legacy-lock ``legacy-bridge ingest-v04`` client."""

    bridge = subparsers.add_parser(
        "legacy-bridge",
        help="ingest an exact legacy task into an already-running company",
    )
    actions = bridge.add_subparsers(dest="legacy_bridge_action", required=True)
    ingest = actions.add_parser(
        "ingest-v04",
        help="publish one exact v0.4 task observation without dispatch authority",
    )
    ingest.add_argument("--task", required=True)
    ingest.add_argument("--legacy-archive-sha256", required=True)
    ingest.add_argument("--source-version", required=True)
    ingest.add_argument("--company-id")
    ingest.add_argument("--timeout-seconds", type=float, default=30.0)
    add_json_argument(ingest)
    ingest.set_defaults(handler=handler)
    terminal = actions.add_parser(
        "reconcile-job-terminal-v04",
        help="append one exact failed-job terminal receipt without relaunch",
    )
    terminal.add_argument("--task", required=True)
    terminal.add_argument("--run-id", required=True)
    terminal.add_argument("--legacy-archive-sha256", required=True)
    terminal.add_argument("--source-version", required=True)
    terminal.add_argument("--process-exit-artifact", required=True)
    terminal.add_argument("--process-exit-sha256", required=True)
    terminal.add_argument("--company-id")
    terminal.add_argument("--timeout-seconds", type=float, default=30.0)
    add_json_argument(terminal)
    terminal.set_defaults(handler=terminal_handler)


__all__ = [
    "LegacyBridgeRuntimeCommandError",
    "cmd_legacy_bridge_ingest_v04",
    "cmd_legacy_bridge_reconcile_job_terminal_v04",
    "register_legacy_bridge_runtime_commands",
]
