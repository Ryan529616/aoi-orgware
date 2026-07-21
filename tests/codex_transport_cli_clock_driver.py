#!/usr/bin/env python3
"""Tests-only subprocess clock seam for Codex transport issue coverage."""

from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path
import sys
from unittest import mock


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import codex_transport_cli  # noqa: E402


CLOCK_ENV = "AOI_TEST_CODEX_TRANSPORT_CURRENT_TIME"


def _require_issue_command() -> None:
    arguments = sys.argv[1:]
    if arguments[:1] == ["--root"]:
        command = arguments[2] if len(arguments) > 2 else None
    else:
        command = arguments[0] if arguments else None
    if command != "issue":
        raise SystemExit("ERROR: Codex transport clock driver permits only issue")


def _current_time() -> datetime:
    raw = os.environ.pop(CLOCK_ENV, None)
    if not isinstance(raw, str):
        raise SystemExit(f"ERROR: {CLOCK_ENV} is required")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"ERROR: {CLOCK_ENV} is invalid: {exc}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SystemExit(f"ERROR: {CLOCK_ENV} needs a timezone")
    parsed = parsed.astimezone(UTC)
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if raw != canonical:
        raise SystemExit(f"ERROR: {CLOCK_ENV} is not canonical UTC")
    return parsed


def main() -> int:
    _require_issue_command()
    current_time = _current_time()
    with mock.patch.object(codex_transport_cli, "_now", return_value=current_time):
        return codex_transport_cli.main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
