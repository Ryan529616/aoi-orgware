"""Project-bound client command for observational legacy bridge ingestion."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aoi_orgware.company.legacy_bridge_client import (
    LegacyBridgeClientError,
    LegacyBridgeIngestClientResult,
    run_legacy_bridge_ingest_v04,
)
from aoi_orgware.legacy_bridge_snapshot_v04 import produce_legacy_bridge_snapshot_v04

from .company_runtime import CompanyRuntimeCommandError


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]
Runner = Callable[..., LegacyBridgeIngestClientResult]


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


def register_legacy_bridge_runtime_commands(
    subparsers: argparse._SubParsersAction[Any],
    *,
    handler: Handler,
    add_json_argument: JsonArgumentRegistrar,
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


__all__ = [
    "LegacyBridgeRuntimeCommandError",
    "cmd_legacy_bridge_ingest_v04",
    "register_legacy_bridge_runtime_commands",
]
