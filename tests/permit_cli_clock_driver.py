#!/usr/bin/env python3
"""Tests-only subprocess clock seam for permit CLI integration coverage."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from unittest import mock


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli  # noqa: E402
from aoi_orgware.commands import semantic as semantic_commands  # noqa: E402


CLOCK_ENV = "AOI_TEST_PERMIT_CURRENT_TIME"
_CONTROLLER_SECRET_PREFIXES = ("AOI_CHIEF_", "AOI_CREDENTIAL_")
_CONTROLLER_SECRET_NAMES = {"AOI_BACKUP_ROOT"}


def _reject_controller_authority() -> None:
    if sys.argv[1:2] != ["permit-consume"]:
        return
    leaked = sorted(
        name
        for name in os.environ
        if name.upper() in _CONTROLLER_SECRET_NAMES
        or name.upper().startswith(_CONTROLLER_SECRET_PREFIXES)
    )
    if leaked:
        raise SystemExit(
            "ERROR: permit-consume test child received reusable Chief "
            "authority locators"
        )


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
    parsed = parsed.astimezone(timezone.utc)
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if raw != canonical:
        raise SystemExit(f"ERROR: {CLOCK_ENV} is not canonical UTC")
    return parsed


def main() -> int:
    _reject_controller_authority()
    current_time = _current_time()
    with mock.patch.object(
        semantic_commands, "datetime", wraps=datetime
    ) as command_clock:
        command_clock.now.return_value = current_time
        return cli.main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
