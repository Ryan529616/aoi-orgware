from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware import cli as cli_impl
from aoi_orgware.commands.company_runtime import CompanyRuntimeCommandError


def _top_level_commands(parser: argparse.ArgumentParser) -> set[str]:
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    return set(subparsers.choices)


def test_runtime_families_are_registered_and_explicitly_chief_exempt() -> None:
    parser = cli_impl.build_parser({})
    assert {"supervisor", "dashboard"} <= _top_level_commands(parser)
    assert cli_impl.CHIEF_STANDALONE_RUNTIME_COMMANDS == {
        "dashboard",
        "supervisor",
    }
    for command in cli_impl.CHIEF_STANDALONE_RUNTIME_COMMANDS:
        assert command in cli_impl.CHIEF_STANDALONE_COMMANDS
        assert not cli_impl.command_requires_chief(command, initialized=False)
        assert not cli_impl.command_requires_chief(command, initialized=True)

    args = parser.parse_args(
        ["supervisor", "ensure", "--company-id", "company-1", "--json"],
    )
    assert args._aoi_command == "supervisor"
    assert args.supervisor_action == "ensure"
    assert args.company_id == "company-1"
    assert args.json is True
    with pytest.raises(SystemExit):
        parser.parse_args(["supervisor", "status", "--slot-root", "C:/other"])


@pytest.mark.parametrize(
    ("argv", "handler_name"),
    (
        (["supervisor", "ensure"], "cmd_supervisor_ensure"),
        (["supervisor", "status"], "cmd_supervisor_status"),
        (["supervisor", "stop"], "cmd_supervisor_stop"),
        (["dashboard", "url"], "cmd_dashboard_url"),
        (["dashboard", "open"], "cmd_dashboard_open"),
    ),
)
def test_runtime_commands_bypass_v04_layout_and_writer_output_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    handler_name: str,
) -> None:
    observed: list[tuple[str, Any]] = []

    def handler(args: argparse.Namespace, paths: Any) -> int:
        observed.append((str(args._aoi_command), paths))
        return 0

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("legacy project/Chief routing must not run")

    monkeypatch.setattr(cli_impl, handler_name, handler)
    monkeypatch.setattr(cli_impl, "get_paths", forbidden)
    monkeypatch.setattr(cli_impl, "_chief_credential", forbidden)
    monkeypatch.setattr(cli_impl, "_pilot_output_projects", forbidden)
    monkeypatch.chdir(tmp_path)

    assert cli_impl.main(argv) == 0
    assert observed == [(argv[0], None)]


def test_runtime_command_error_is_rendered_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_args: argparse.Namespace, _paths: Any) -> int:
        raise CompanyRuntimeCommandError("repo-bound company is unavailable")

    monkeypatch.setattr(cli_impl, "cmd_dashboard_url", handler)
    monkeypatch.chdir(tmp_path)

    assert cli_impl.main(["dashboard", "url"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "ERROR: repo-bound company is unavailable\n"
