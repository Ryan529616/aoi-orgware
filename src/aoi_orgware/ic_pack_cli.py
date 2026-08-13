"""Standalone JSON CLI for the package-owned Phase-1 IC Pack."""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
from pathlib import Path
from typing import Sequence

from .ic_pack import (
    ICPackError,
    MAX_REQUEST_BYTES,
    canonical_json_bytes,
    execute_request,
    parse_request_bytes,
    result_to_dict,
)


def _read_request(path: Path) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ICPackError("IC Pack request must be a non-linked regular file")
        with path.open("rb") as handle:
            data = handle.read(MAX_REQUEST_BYTES + 1)
        after = path.lstat()
    except ICPackError:
        raise
    except OSError as exc:
        raise ICPackError("IC Pack request is unreadable") from exc
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if len(data) > MAX_REQUEST_BYTES or any(
        getattr(before, key) != getattr(after, key) for key in identity
    ):
        raise ICPackError("IC Pack request changed during bounded read")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aoi-ic-pack",
        description="Run the fixed AOI synthetic IC Pack exactly once.",
        allow_abbrev=False,
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--request-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = _read_request(args.request)
        if hashlib.sha256(data).hexdigest() != args.request_sha256:
            raise ICPackError("IC Pack request file digest differs")
        request = parse_request_bytes(data)
        result = execute_request(request, args.request_sha256)
        sys.stdout.buffer.write(canonical_json_bytes(result_to_dict(result)) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except ICPackError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
