"""Native filesystem syscall spelling for canonical company paths."""
from __future__ import annotations

import ntpath
import os
from pathlib import Path


def _windows_extended_path(raw: str) -> str:
    """Return one idempotent absolute Win32 extended-path spelling."""

    if raw.startswith("\\\\?\\"):
        return raw
    absolute = ntpath.abspath(raw)
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def native_filesystem_path(path: Path) -> str | Path:
    """Use extended spelling only at a Windows filesystem syscall boundary."""

    if os.name != "nt":
        return path
    return _windows_extended_path(os.fspath(path))


def fsync_directory(path: Path) -> None:
    """Persist one directory entry update where the platform supports it."""

    if os.name == "nt":
        return
    descriptor = os.open(
        native_filesystem_path(path),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
