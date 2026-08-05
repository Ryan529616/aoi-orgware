from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from aoi_orgware import cli
from aoi_orgware.commands import company_init
from aoi_orgware.company.legacy_bridge_init import LegacyBridgeCompanyInitResult


def _result() -> LegacyBridgeCompanyInitResult:
    return LegacyBridgeCompanyInitResult(
        action="created",
        company_id="legacy-bridge-" + "a" * 64,
        manifest_sha256="b" * 64,
        state_root="/synthetic/aoi/companies/bridge",
        platform="posix",
        lock_domain="posix",
        chief_carrier_state="unknown",
        departments=("rtl", "dv", "pd"),
        authority_boundary="genesis grants are limited to supervisor/chief company.mutate; bridge init dispatched no work",
    )


def test_company_init_json_output_is_secret_free(capsys: pytest.CaptureFixture[str]) -> None:
    args = argparse.Namespace(mode="legacy-bridge", json=True)
    assert company_init.cmd_company_init(args, argparse.Namespace(root=Path(".")), initializer=lambda _root: _result()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["company_id"].startswith("legacy-bridge-")
    assert payload["chief_carrier"] == {"state": "unknown"}
    assert "token" not in json.dumps(payload).lower()


def test_company_init_parser_requires_exact_mode() -> None:
    parser = cli.build_parser({})
    args = parser.parse_args(["company", "init", "--mode", "legacy-bridge", "--json"])
    assert args._aoi_command == "company"
    assert args.mode == "legacy-bridge"
    with pytest.raises(SystemExit):
        parser.parse_args(["company", "init"])


def test_company_init_parser_dispatches_the_registered_handler(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = cli.build_parser({}).parse_args(
        ["company", "init", "--mode", "legacy-bridge", "--json"],
    )
    assert args.handler is company_init.cmd_company_init
    assert args.handler(args, argparse.Namespace(root=Path(".")), initializer=lambda _root: _result()) == 0
    assert json.loads(capsys.readouterr().out)["action"] == "created"


def test_company_is_project_fenced_not_a_standalone_runtime_command() -> None:
    assert "company" not in cli.CHIEF_STANDALONE_RUNTIME_COMMANDS
    assert "company" not in cli.CHIEF_STANDALONE_COMMANDS
    assert cli.command_requires_chief("company", initialized=True)


def test_company_init_rejects_wrong_mode() -> None:
    with pytest.raises(company_init.CompanyInitCommandError, match="legacy-bridge"):
        company_init.cmd_company_init(argparse.Namespace(mode="other", json=False), Path("."))


def test_company_init_redacts_ordinary_initializer_failure() -> None:
    secret = "AOI-SYNTHETIC-FIXTURE-V1:private-token"

    def fail(_paths: object) -> LegacyBridgeCompanyInitResult:
        raise RuntimeError(secret)

    with pytest.raises(company_init.CompanyInitCommandError) as captured:
        company_init.cmd_company_init(
            argparse.Namespace(mode="legacy-bridge", json=False),
            argparse.Namespace(root=Path(".")),
            initializer=fail,
        )
    assert str(captured.value) == "legacy bridge company init failed"
    assert secret not in str(captured.value)


def test_company_init_preserves_memory_error() -> None:
    def fail(_paths: object) -> LegacyBridgeCompanyInitResult:
        raise MemoryError("synthetic")

    with pytest.raises(MemoryError, match="synthetic"):
        company_init.cmd_company_init(
            argparse.Namespace(mode="legacy-bridge", json=False),
            argparse.Namespace(root=Path(".")),
            initializer=fail,
        )
