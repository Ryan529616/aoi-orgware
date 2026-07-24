"""Canonicalize and compare exact Codex App Server generated JSON schemas.

Codex 0.145.0 can emit semantically identical JSON objects in different key
orders.  Raw-byte hashes are therefore not a reproducible generator identity.
This tool rejects duplicate keys/non-finite numbers, canonicalizes each JSON
file, builds a sorted canonical manifest, and can require two independent
generator outputs to agree before writing package resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence


EXPECTED_FILE_COUNT = 273
EXPECTED_MANIFEST_SIZE = 36091
EXPECTED_MANIFEST_SHA256 = (
    "c05875501c6e9a6778cc4afc5488cdb87aae539217121ebbb5c8dd14c79bc025"
)
EXPECTED_COMBINED_SIZE = 269688
EXPECTED_COMBINED_SHA256 = (
    "27f8d983f19d8e1a5548d52176de0a460fb05aaf2a72110f913c6f4af2bd4f27"
)
COMBINED_V2_PATH = "codex_app_server_protocol.v2.schemas.json"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


class SchemaRefreshError(ValueError):
    """Generated schemas are unsafe, malformed, or semantically inconsistent."""


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaRefreshError(f"generated schema repeats key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SchemaRefreshError(f"generated schema contains non-finite number {value}")


def canonical_json_bytes(raw: bytes, *, label: str) -> bytes:
    """Return deterministic semantic bytes for one strict UTF-8 JSON value."""

    if not raw or len(raw) > MAX_FILE_BYTES:
        raise SchemaRefreshError(f"{label} size is invalid")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_duplicate_rejector,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise SchemaRefreshError(f"{label} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise SchemaRefreshError(f"{label} is not strict JSON") from exc
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _schema_paths(root: Path) -> list[Path]:
    if (
        not root.is_absolute()
        or not root.is_dir()
        or _is_link_or_reparse(root)
    ):
        raise SchemaRefreshError(
            "schema directory must be an existing absolute non-link, "
            "non-reparse directory"
        )
    paths: list[Path] = []
    for current, directories, files in os.walk(root):
        current_path = Path(current)
        for name in directories:
            if _is_link_or_reparse(current_path / name):
                raise SchemaRefreshError(
                    "schema directory contains a linked or reparse directory"
                )
        for name in files:
            path = current_path / name
            if _is_link_or_reparse(path) or not path.is_file():
                raise SchemaRefreshError("schema directory contains a non-regular file")
            if path.suffix != ".json":
                raise SchemaRefreshError("schema directory contains a non-JSON file")
            paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def canonicalize_schema_directory(
    root: Path,
    *,
    expected_file_count: int = EXPECTED_FILE_COUNT,
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Return canonical manifest, canonical combined-v2 schema, and summary."""

    if not root.is_absolute() or _is_link_or_reparse(root):
        raise SchemaRefreshError(
            "schema directory must be an existing absolute non-link, "
            "non-reparse directory"
        )
    root = root.resolve()
    paths = _schema_paths(root)
    if len(paths) != expected_file_count:
        raise SchemaRefreshError(
            f"schema file count {len(paths)} differs from {expected_file_count}"
        )
    entries: list[dict[str, Any]] = []
    combined: bytes | None = None
    total_raw_bytes = 0
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if (
            relative.startswith("/")
            or "\\" in relative
            or "//" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise SchemaRefreshError("schema path is not a safe POSIX relative path")
        raw = path.read_bytes()
        total_raw_bytes += len(raw)
        if total_raw_bytes > MAX_TOTAL_BYTES:
            raise SchemaRefreshError("schema directory exceeds the total byte bound")
        canonical = canonical_json_bytes(raw, label=relative)
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(canonical).hexdigest(),
                "size": len(canonical),
            }
        )
        if relative == COMBINED_V2_PATH:
            combined = canonical
    if combined is None:
        raise SchemaRefreshError("schema directory lacks the combined v2 schema")
    manifest = json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    summary = {
        "file_count": len(entries),
        "manifest_size": len(manifest),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "combined_v2_schema_size": len(combined),
        "combined_v2_schema_sha256": hashlib.sha256(combined).hexdigest(),
    }
    return manifest, combined, summary


def compare_schema_directories(
    first: Path,
    second: Path,
    *,
    expected_file_count: int = EXPECTED_FILE_COUNT,
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Require two independent outputs to have identical canonical semantics."""

    first_result = canonicalize_schema_directory(
        first, expected_file_count=expected_file_count
    )
    second_result = canonicalize_schema_directory(
        second, expected_file_count=expected_file_count
    )
    if first_result != second_result:
        raise SchemaRefreshError(
            "independent generated schema directories differ semantically"
        )
    return first_result


def _require_expected(summary: dict[str, Any]) -> None:
    expected = {
        "file_count": EXPECTED_FILE_COUNT,
        "manifest_size": EXPECTED_MANIFEST_SIZE,
        "manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "combined_v2_schema_size": EXPECTED_COMBINED_SIZE,
        "combined_v2_schema_sha256": EXPECTED_COMBINED_SHA256,
    }
    if summary != expected:
        raise SchemaRefreshError("canonical schema identities differ from Codex 0.145.0")


def _write_atomic(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or not path.parent.is_dir():
        raise SchemaRefreshError("output path must be absolute with an existing parent")
    if path.is_symlink():
        raise SchemaRefreshError("output path must not be a link")
    temporary = path.with_name(f".{path.name}.aoi-schema-refresh.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise SchemaRefreshError("schema refresh temporary path already exists")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Canonicalize two Codex generated-schema directories"
    )
    parser.add_argument("--first", required=True)
    parser.add_argument("--second", required=True)
    parser.add_argument("--manifest-out")
    parser.add_argument("--combined-out")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        first = Path(args.first)
        second = Path(args.second)
        if not first.is_absolute() or not second.is_absolute():
            raise SchemaRefreshError("schema input paths must be absolute")
        manifest, combined, summary = compare_schema_directories(first, second)
        _require_expected(summary)
        outputs = (args.manifest_out, args.combined_out)
        if (outputs[0] is None) != (outputs[1] is None):
            raise SchemaRefreshError("both output paths must be supplied together")
        if outputs[0] is not None:
            _write_atomic(Path(outputs[0]), manifest)
            _write_atomic(Path(outputs[1]), combined)
        result = {
            **summary,
            "first": str(first.resolve()),
            "second": str(second.resolve()),
            "outputs_written": outputs[0] is not None,
        }
    except (OSError, SchemaRefreshError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"canonical schemas match: {result['file_count']} files, "
            f"{result['manifest_sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
