from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware import cli
from aoi_orgware.commands import legacy_bridge_runtime
from aoi_orgware.company.legacy_bridge_client import LegacyBridgeIngestClientResult


def _result(
    exit_code: int = 0,
    *,
    capacity_required: bool = False,
) -> LegacyBridgeIngestClientResult:
    return LegacyBridgeIngestClientResult(
        company_id="company-1",
        bridge_scope_id="a" * 64,
        attempt_id="b" * 64,
        source_document_sha256="c" * 64,
        source_matches_current_legacy_state=True,
        effect=(
            "none"
            if capacity_required
            else "committed" if exit_code in {0, 4} else "effect_unknown"
        ),
        gate_decision="blocked" if capacity_required else "satisfied" if exit_code == 0 else "unknown",
        gate_reason=(
            "successor_rollover_required"
            if capacity_required
            else "current_structural_ingest_observed"
            if exit_code == 0
            else "company_state_degraded"
        ),
        cursor=None if capacity_required else 9,
        exit_code=exit_code,
        prepared_receipt_sha256=None if capacity_required else "d" * 64,
        terminal_receipt_sha256=None if capacity_required else "e" * 64,
        reconciliation_receipt_sha256=None,
        capacity_receipt_sha256="f" * 64 if capacity_required else None,
    )


def _argv() -> list[str]:
    return [
        "legacy-bridge",
        "ingest-v04",
        "--task",
        "task-1",
        "--legacy-archive-sha256",
        "a" * 64,
        "--source-version",
        "0.4.0a4",
        "--json",
    ]


def test_parser_dispatches_top_level_legacy_bridge_without_chief_lock() -> None:
    args = cli.build_parser({}).parse_args(_argv())
    assert args._aoi_command == "legacy-bridge"
    assert args.legacy_bridge_action == "ingest-v04"
    assert args.handler is legacy_bridge_runtime.cmd_legacy_bridge_ingest_v04
    assert "legacy-bridge" in cli.CHIEF_PROJECT_READ_ONLY_COMMANDS
    assert not cli.command_requires_chief("legacy-bridge", initialized=True)


def test_parser_requires_exact_source_bindings() -> None:
    parser = cli.build_parser({})
    with pytest.raises(SystemExit):
        parser.parse_args(["legacy-bridge", "ingest-v04", "--task", "task-1"])


def test_command_emits_secret_free_result_and_preserves_exit_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, Any] = {}

    def runner(root: Path, **kwargs: Any) -> LegacyBridgeIngestClientResult:
        observed["root"] = root
        observed.update(kwargs)
        return _result(3)

    args = cli.build_parser({}).parse_args(_argv())
    status = legacy_bridge_runtime.cmd_legacy_bridge_ingest_v04(
        args,
        argparse.Namespace(root=tmp_path),
        runner=runner,
    )
    payload = json.loads(capsys.readouterr().out)

    assert status == 3
    assert payload["effect"] == "effect_unknown"
    assert payload["authority"] == "none"
    assert observed["root"] == tmp_path
    serialized = json.dumps(payload).lower()
    assert "bearer" not in serialized
    assert "token" not in serialized
    assert str(tmp_path).lower() not in serialized


def test_command_redacts_ordinary_runner_failure(tmp_path: Path) -> None:
    secret = "AOI-SYNTHETIC-FIXTURE-V1:private"

    def fail(_root: Path, **_kwargs: Any) -> LegacyBridgeIngestClientResult:
        raise RuntimeError(secret)

    args = cli.build_parser({}).parse_args(_argv())
    with pytest.raises(
        legacy_bridge_runtime.LegacyBridgeRuntimeCommandError,
        match="legacy-bridge ingest-v04 failed$",
    ) as captured:
        legacy_bridge_runtime.cmd_legacy_bridge_ingest_v04(
            args,
            argparse.Namespace(root=tmp_path),
            runner=fail,
        )
    assert secret not in str(captured.value)


def test_command_emits_typed_successor_rollover_without_mutation_claim(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def runner(_root: Path, **_kwargs: Any) -> LegacyBridgeIngestClientResult:
        return _result(4, capacity_required=True)

    args = cli.build_parser({}).parse_args(_argv())
    status = legacy_bridge_runtime.cmd_legacy_bridge_ingest_v04(
        args,
        argparse.Namespace(root=tmp_path),
        runner=runner,
    )
    payload = json.loads(capsys.readouterr().out)

    assert status == 4
    assert payload["effect"] == "none"
    assert payload["gate_decision"] == "blocked"
    assert payload["gate_reason"] == "successor_rollover_required"
    assert payload["prepared_receipt_sha256"] is None
    assert payload["capacity_receipt_sha256"] == "f" * 64


def test_command_preserves_memory_error(tmp_path: Path) -> None:
    def fail(_root: Path, **_kwargs: Any) -> LegacyBridgeIngestClientResult:
        raise MemoryError("synthetic")

    args = cli.build_parser({}).parse_args(_argv())
    with pytest.raises(MemoryError, match="synthetic"):
        legacy_bridge_runtime.cmd_legacy_bridge_ingest_v04(
            args,
            argparse.Namespace(root=tmp_path),
            runner=fail,
        )
