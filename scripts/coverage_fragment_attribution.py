"""Test-only provenance for coverage.py fragments.

The existing verifier remains authoritative and fail-closed.  This diagnostic
helper assigns opaque producer prefixes.  One version-pinned AOI fork hook
replaces inherited measurement with exactly one child collector; coverage.py's
recursive ``patch=fork`` hook is deliberately absent.

The fork guarantee is limited to Python runtimes that execute registered
``os.register_at_fork`` callbacks and Python-level ``os._exit``.  Raw
third-party C forks and direct C ``_exit`` calls remain unavailable.

The receipt correlation is cooperative and diagnostic, not authenticated.
Another process running as the same user can mint self-consistent filenames and
receipts, so a matched pytest family remains explicitly unverified.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Iterator, MutableMapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, TextIO

_fork_runtime = importlib.import_module(
    "scripts.coverage_fork_runtime"
    if __package__ == "scripts"
    else "aoi_coverage_fork_runtime"
)
COVERAGE_CONFIG_ENV = _fork_runtime.COVERAGE_CONFIG_ENV
EXPECTED_COVERAGE_VERSION = _fork_runtime.EXPECTED_COVERAGE_VERSION
_VENDOR_COVERAGE_START_ENVIRONMENTS = _fork_runtime.VENDOR_START_ENVIRONMENTS
_ensure_coverage_not_started = _fork_runtime.ensure_not_started
_install_fork_callback = _fork_runtime.install_fork_callback
_start_exact_coverage = _fork_runtime.start_exact_coverage
_stop_inherited_coverage = _fork_runtime.stop_inherited_coverage


ATTRIBUTION_SCHEMA_VERSION = 2
COVERAGE_FILE_BASE_ENV = "AOI_COVERAGE_FILE_BASE"
METADATA_ROOT_ENV = "AOI_COVERAGE_METADATA_ROOT"
PYTEST_FAMILY_TOKEN_ENV = "AOI_COVERAGE_TEST_FAMILY_TOKEN"
CURRENT_PRODUCER_ENV = "AOI_COVERAGE_CURRENT_PRODUCER_ID"
_PRODUCER_PREFIX = ".aoi2."
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.-]+\Z")
_FRAGMENT_RE = re.compile(r"^\.coverage\.aoi2\.(?P<producer>[0-9a-f]{64})(?:\.|\Z)")
_MAX_RECEIPT_BYTES = 4096
_ATTRIBUTION_SCOPES = frozenset({"fork_child", "fresh_interpreter"})


class CoverageFragmentAttributionError(RuntimeError):
    """Raised when test-only attribution cannot remain bounded and exact."""


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _write_all(handle: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(handle, view)
        if written <= 0:
            raise CoverageFragmentAttributionError("attribution receipt write made no progress")
        view = view[written:]


def _write_once(path: Path, payload: bytes) -> bool:
    """Atomically publish ``payload`` without replacing an existing receipt."""

    if len(payload) > _MAX_RECEIPT_BYTES:
        raise CoverageFragmentAttributionError("attribution receipt exceeds byte bound")
    try:
        temporary = path.with_name(f".{path.name}.tmp.{secrets.token_hex(16)}")
    except (OSError, ValueError) as exc:
        raise CoverageFragmentAttributionError("cannot prepare attribution receipt") from exc
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    handle: int | None = None
    try:
        handle = os.open(temporary, flags, 0o600)
        _write_all(handle, payload)
        os.fsync(handle)
        os.close(handle)
        handle = None
        try:
            os.link(temporary, path)
        except FileExistsError:
            return False
        return True
    except MemoryError:
        raise
    except CoverageFragmentAttributionError:
        raise
    except (OSError, ValueError) as exc:
        raise CoverageFragmentAttributionError("cannot publish attribution receipt") from exc
    finally:
        if handle is not None:
            try:
                os.close(handle)
            except OSError:
                raise CoverageFragmentAttributionError(
                    "cannot close attribution receipt"
                ) from None
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            raise CoverageFragmentAttributionError(
                "cannot remove attribution receipt temporary"
            ) from None


def _existing_private_directory(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise CoverageFragmentAttributionError(f"{label} must be absolute")
    if ".." in path.parts:
        raise CoverageFragmentAttributionError(f"{label} is not canonical")
    try:
        parts = path.parts
        current = Path(parts[0])
        info = current.lstat()
        for part in parts[1:]:
            current /= part
            info = current.lstat()
            reparse = getattr(info, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
            )
            if stat.S_ISLNK(info.st_mode) or reparse:
                raise CoverageFragmentAttributionError(
                    f"{label} must not traverse a link or reparse point"
                )
            if current != path and not stat.S_ISDIR(info.st_mode):
                raise CoverageFragmentAttributionError(
                    f"{label} has a non-directory ancestor"
                )
        resolved = path.resolve(strict=True)
        resolved_info = resolved.lstat()
    except CoverageFragmentAttributionError:
        raise
    except (OSError, RuntimeError) as exc:
        raise CoverageFragmentAttributionError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise CoverageFragmentAttributionError(f"{label} must be a real directory")
    if (info.st_dev, info.st_ino) != (resolved_info.st_dev, resolved_info.st_ino):
        raise CoverageFragmentAttributionError(f"{label} identity is unstable")
    return resolved


def _metadata_subdirectory(root: Path, name: str) -> Path:
    child = root / name
    try:
        child.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise CoverageFragmentAttributionError("cannot create attribution directory") from exc
    return _existing_private_directory(child, label="attribution directory")


def _metadata_root(environ: MutableMapping[str, str]) -> Path | None:
    raw = environ.get(METADATA_ROOT_ENV)
    if raw is None:
        return None
    if type(raw) is not str or not raw or "\x00" in raw:
        raise CoverageFragmentAttributionError("attribution metadata root is invalid")
    return _existing_private_directory(Path(raw), label="attribution metadata root")


def _normalized_test_family(
    relative_path: str,
    class_name: str | None,
    function_name: str,
) -> tuple[str, dict[str, object]]:
    if type(relative_path) is not str or "\\" in relative_path:
        raise CoverageFragmentAttributionError("pytest family path is invalid")
    try:
        encoded_path = relative_path.encode("utf-8")
    except UnicodeError as exc:
        raise CoverageFragmentAttributionError("pytest family path is invalid") from exc
    pure = PurePosixPath(relative_path)
    if (
        pure.is_absolute()
        or not pure.parts
        or pure.parts[0] != "tests"
        or any(part in {"", ".", ".."} for part in pure.parts)
        or relative_path != pure.as_posix()
        or any(_PATH_SEGMENT_RE.fullmatch(part) is None for part in pure.parts)
        or len(encoded_path) > 512
    ):
        raise CoverageFragmentAttributionError("pytest family path is invalid")
    if type(function_name) is not str or _IDENTIFIER_RE.fullmatch(function_name) is None:
        raise CoverageFragmentAttributionError("pytest function family is invalid")
    if class_name is not None and (
        type(class_name) is not str or _IDENTIFIER_RE.fullmatch(class_name) is None
    ):
        raise CoverageFragmentAttributionError("pytest class family is invalid")
    family: dict[str, object] = {
        "class_name": class_name,
        "function_name": function_name,
        "relative_path": pure.as_posix(),
        "schema_version": ATTRIBUTION_SCHEMA_VERSION,
    }
    token = hashlib.sha256(
        b"aoi.coverage.pytest-family.v1\x00" + _canonical_bytes(family)
    ).hexdigest()
    return token, family


def _publish_family(root: Path, token: str, family: dict[str, object]) -> None:
    record = {
        "family": family,
        "family_token": token,
        "schema_version": ATTRIBUTION_SCHEMA_VERSION,
    }
    payload = _canonical_bytes(record)
    path = _metadata_subdirectory(root, "families") / f"{token}.json"
    if not _write_once(path, payload):
        try:
            existing = _read_record(path)
        except CoverageFragmentAttributionError as exc:
            raise CoverageFragmentAttributionError(
                "cannot read existing family receipt"
            ) from exc
        if _canonical_bytes(existing) != payload:
            raise CoverageFragmentAttributionError("pytest family token collision") from None


@contextmanager
def pytest_family_scope(
    *,
    relative_path: str,
    class_name: str | None,
    function_name: str,
    environ: MutableMapping[str, str] | None = None,
) -> Iterator[None]:
    """Bind one parameter-free pytest family token for child interpreter startup."""

    target = os.environ if environ is None else environ
    root = _metadata_root(target)
    if root is None:
        yield
        return
    token, family = _normalized_test_family(relative_path, class_name, function_name)
    _publish_family(root, token, family)
    sentinel = object()
    previous: str | object = target.get(PYTEST_FAMILY_TOKEN_ENV, sentinel)
    target[PYTEST_FAMILY_TOKEN_ENV] = token
    try:
        yield
    finally:
        if previous is sentinel:
            target.pop(PYTEST_FAMILY_TOKEN_ENV, None)
        else:
            target[PYTEST_FAMILY_TOKEN_ENV] = previous  # type: ignore[assignment]


@contextmanager
def attempt_pytest_family_scope(
    *,
    relative_path: str,
    class_name: str | None,
    function_name: str,
    environ: MutableMapping[str, str] | None = None,
) -> Iterator[None]:
    """Attempt test-only family metadata without suppressing the test body."""

    target = os.environ if environ is None else environ
    try:
        target.pop(PYTEST_FAMILY_TOKEN_ENV, None)
        scope = pytest_family_scope(
            relative_path=relative_path,
            class_name=class_name,
            function_name=function_name,
            environ=target,
        )
        scope.__enter__()
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception:
        try:
            target.pop(PYTEST_FAMILY_TOKEN_ENV, None)
        except (KeyboardInterrupt, MemoryError, SystemExit):
            raise
        except Exception:
            pass
        yield
        return
    try:
        yield
    finally:
        try:
            scope.__exit__(None, None, None)
        except (KeyboardInterrupt, MemoryError, SystemExit):
            raise
        except Exception:
            try:
                target.pop(PYTEST_FAMILY_TOKEN_ENV, None)
            except (KeyboardInterrupt, MemoryError, SystemExit):
                raise
            except Exception:
                pass


def prepare_subprocess_coverage_attribution(
    *,
    environ: MutableMapping[str, str] | None = None,
    token_bytes: Any = secrets.token_bytes,
    attribution_scope: str = "fresh_interpreter",
) -> str | None:
    """Prepare one fresh interpreter before ``coverage.process_startup``.

    The returned opaque producer id is diagnostic only.  No coverage.py object
    is created or queried here, so measurement buffers and fragment acceptance
    are unaffected.
    """

    target = os.environ if environ is None else environ
    config_raw = target.get(COVERAGE_CONFIG_ENV)
    if config_raw is None:
        return None
    if (
        type(config_raw) is not str
        or not config_raw
        or "\x00" in config_raw
        or not Path(config_raw).is_absolute()
    ):
        raise CoverageFragmentAttributionError("coverage config binding is invalid")
    if any(name in target for name in _VENDOR_COVERAGE_START_ENVIRONMENTS):
        raise CoverageFragmentAttributionError("coverage started before attribution")
    if type(attribution_scope) is not str or attribution_scope not in _ATTRIBUTION_SCOPES:
        raise CoverageFragmentAttributionError("coverage attribution scope is invalid")
    root = _metadata_root(target)
    if root is None:
        raise CoverageFragmentAttributionError("coverage attribution metadata is required")
    base_raw = target.get(COVERAGE_FILE_BASE_ENV)
    if type(base_raw) is not str or not base_raw or "\x00" in base_raw:
        raise CoverageFragmentAttributionError("coverage file base is invalid")
    base = Path(base_raw)
    if not base.is_absolute() or base.name != ".coverage":
        raise CoverageFragmentAttributionError("coverage file base must name absolute .coverage")
    base_parent = _existing_private_directory(base.parent, label="coverage data directory")
    base = base_parent / base.name
    parent_producer_id = target.get(CURRENT_PRODUCER_ENV)
    if parent_producer_id is not None and (
        type(parent_producer_id) is not str
        or _HEX64_RE.fullmatch(parent_producer_id) is None
    ):
        raise CoverageFragmentAttributionError("parent producer identity is invalid")
    if attribution_scope == "fork_child" and parent_producer_id is None:
        raise CoverageFragmentAttributionError("fork child parent identity is required")
    if parent_producer_id is not None:
        _validated_process_record(root, parent_producer_id)
    inherited_file = target.get("COVERAGE_FILE")
    expected_inherited = (
        str(base)
        if parent_producer_id is None
        else f"{base}{_PRODUCER_PREFIX}{parent_producer_id}"
    )
    if inherited_file is not None and inherited_file != expected_inherited:
        raise CoverageFragmentAttributionError("parent coverage file binding differs")
    try:
        entropy = token_bytes(32)
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception as exc:
        raise CoverageFragmentAttributionError("cannot generate producer identity") from exc
    if type(entropy) is not bytes or len(entropy) != 32:
        raise CoverageFragmentAttributionError("producer entropy is invalid")
    producer_id = entropy.hex()
    family_token = target.get(PYTEST_FAMILY_TOKEN_ENV)
    if family_token is not None and (
        type(family_token) is not str or _HEX64_RE.fullmatch(family_token) is None
    ):
        raise CoverageFragmentAttributionError("pytest family token is invalid")
    record: dict[str, object] = {
        "attribution_scope": attribution_scope,
        "family_quality": (
            "cooperative_unverified_pytest_family"
            if family_token is not None
            else "unattributed"
        ),
        "family_token": family_token,
        "parent_producer_id": parent_producer_id,
        "producer_id": producer_id,
        "schema_version": ATTRIBUTION_SCHEMA_VERSION,
    }
    if not _write_once(
        _metadata_subdirectory(root, "processes") / f"{producer_id}.json",
        _canonical_bytes(record),
    ):
        raise CoverageFragmentAttributionError("producer identity collision")
    target["COVERAGE_FILE"] = f"{base}{_PRODUCER_PREFIX}{producer_id}"
    target[CURRENT_PRODUCER_ENV] = producer_id
    return producer_id


def _disable_inherited_coverage(target: MutableMapping[str, str]) -> None:
    """Remove every inherited switch that could write under a parent identity."""

    for name in _fork_runtime.COVERAGE_SELECTOR_ENVIRONMENTS:
        try:
            target.pop(name, None)
        except BaseException:
            pass


def _after_fork_child_attribution(
    *,
    coverage_module: Any,
    environ: MutableMapping[str, str] | None = None,
    prepare: Any = prepare_subprocess_coverage_attribution,
    hard_exit: Any = os._exit,
) -> None:
    """Replace inherited measurement with one child-owned collector."""

    target = os.environ if environ is None else environ
    try:
        _stop_inherited_coverage(coverage_module)
        producer_id = prepare(
            environ=target,
            attribution_scope="fork_child",
        )
        if producer_id is None:
            raise CoverageFragmentAttributionError("fork attribution is disabled")
        _start_exact_coverage(
            coverage_module,
            target,
            force=True,
            slug="aoi_fork",
        )
        return
    except BaseException:
        try:
            _disable_inherited_coverage(target)
        finally:
            hard_exit(97)


def attempt_subprocess_coverage_attribution(
    *,
    coverage_module: Any,
    environ: MutableMapping[str, str] | None = None,
    register_at_fork: Any | None = None,
) -> bool:
    """Start one collector; a ``False`` result requires immediate ``os._exit``."""

    target = os.environ if environ is None else environ
    try:
        _ensure_coverage_not_started(coverage_module)
        producer_id = prepare_subprocess_coverage_attribution(environ=target)
        if producer_id is None:
            return False
        _start_exact_coverage(
            coverage_module,
            target,
            force=False,
            slug="aoi_startup",
        )
        def child_callback() -> None:
            _after_fork_child_attribution(coverage_module=coverage_module)

        _install_fork_callback(child_callback, register_at_fork)
        return True
    except BaseException:
        try:
            _disable_inherited_coverage(target)
        except BaseException:
            pass
        return False


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise CoverageFragmentAttributionError("attribution JSON keys are invalid")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise CoverageFragmentAttributionError("attribution JSON constants are invalid")


def _read_bounded_bytes(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(_MAX_RECEIPT_BYTES + 1)


def _read_record(path: Path) -> dict[str, object]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise CoverageFragmentAttributionError("attribution receipt is not a regular file")
        if info.st_size < 2 or info.st_size > _MAX_RECEIPT_BYTES:
            raise CoverageFragmentAttributionError("attribution receipt size is invalid")
        raw = _read_bounded_bytes(path)
        if len(raw) != info.st_size:
            raise CoverageFragmentAttributionError("attribution receipt identity changed")
        value = json.loads(
            raw,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_json_constant,
        )
        if type(value) is not dict:
            raise CoverageFragmentAttributionError("attribution receipt shape is invalid")
        canonical = _canonical_bytes(value)
    except MemoryError:
        raise
    except CoverageFragmentAttributionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CoverageFragmentAttributionError("attribution receipt is invalid") from exc
    if canonical != raw:
        raise CoverageFragmentAttributionError("attribution receipt is not canonical")
    return value


def _validated_process_record(root: Path, producer_id: str) -> dict[str, object]:
    processes = _existing_private_directory(
        root / "processes", label="attribution processes directory"
    )
    value = _read_record(processes / f"{producer_id}.json")
    if set(value) != {
        "attribution_scope",
        "family_quality",
        "family_token",
        "parent_producer_id",
        "producer_id",
        "schema_version",
    }:
        raise CoverageFragmentAttributionError("process receipt shape is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != ATTRIBUTION_SCHEMA_VERSION
    ):
        raise CoverageFragmentAttributionError("process receipt version is invalid")
    if value["producer_id"] != producer_id:
        raise CoverageFragmentAttributionError("process receipt identity differs")
    if value["attribution_scope"] not in _ATTRIBUTION_SCOPES:
        raise CoverageFragmentAttributionError("process attribution scope is invalid")
    parent_producer_id = value["parent_producer_id"]
    if parent_producer_id is not None and (
        type(parent_producer_id) is not str
        or _HEX64_RE.fullmatch(parent_producer_id) is None
        or parent_producer_id == producer_id
    ):
        raise CoverageFragmentAttributionError("parent producer binding is invalid")
    if value["attribution_scope"] == "fork_child" and parent_producer_id is None:
        raise CoverageFragmentAttributionError("fork child parent binding is absent")
    family_token = value["family_token"]
    quality = value["family_quality"]
    if family_token is None:
        if quality != "unattributed":
            raise CoverageFragmentAttributionError("process family quality is inconsistent")
    elif (
        type(family_token) is not str
        or _HEX64_RE.fullmatch(family_token) is None
        or quality != "cooperative_unverified_pytest_family"
    ):
        raise CoverageFragmentAttributionError("process family binding is invalid")
    return value


def _validated_family_record(root: Path, family_token: str) -> str:
    families = _existing_private_directory(
        root / "families", label="attribution families directory"
    )
    value = _read_record(families / f"{family_token}.json")
    if set(value) != {"family", "family_token", "schema_version"}:
        raise CoverageFragmentAttributionError("family receipt shape is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != ATTRIBUTION_SCHEMA_VERSION
        or value["family_token"] != family_token
    ):
        raise CoverageFragmentAttributionError("family receipt identity differs")
    family = value["family"]
    if type(family) is not dict or set(family) != {
        "class_name",
        "function_name",
        "relative_path",
        "schema_version",
    }:
        raise CoverageFragmentAttributionError("family payload shape is invalid")
    if type(family["schema_version"]) is not int:
        raise CoverageFragmentAttributionError("family payload version is invalid")
    token, normalized = _normalized_test_family(
        family["relative_path"],  # type: ignore[arg-type]
        family["class_name"],  # type: ignore[arg-type]
        family["function_name"],  # type: ignore[arg-type]
    )
    if token != family_token or _canonical_bytes(family) != _canonical_bytes(normalized):
        raise CoverageFragmentAttributionError("family receipt digest differs")
    parts = [normalized["relative_path"]]
    if normalized["class_name"] is not None:
        parts.append(normalized["class_name"])
    parts.append(normalized["function_name"])
    return "::".join(str(part) for part in parts)


def _fragment_reader_failure_stage(
    fragment: Path,
    coverage_data_type: type[Any] | None,
) -> str | None:
    try:
        from scripts.verify_coverage_path_mapping import (
            CoverageFragmentReadError,
            _read_fragment_measured_files,
        )
        if coverage_data_type is None:
            from coverage import CoverageData
            coverage_data_type = CoverageData
    except (AttributeError, ImportError, TypeError) as exc:
        raise CoverageFragmentAttributionError(
            "coverage fragment reader is unavailable"
        ) from exc
    try:
        _read_fragment_measured_files(fragment, coverage_data_type)
    except MemoryError:
        raise
    except CoverageFragmentReadError as exc:
        return exc.stage
    return None


def _bounded_fragment_children(fragment_directory: Path) -> tuple[Path, ...]:
    try:
        from scripts.coverage_fragment_quiescence import (
            CoveragePathMappingError,
            _snapshot_fragments,
        )
    except (AttributeError, ImportError, TypeError) as exc:
        raise CoverageFragmentAttributionError(
            "coverage fragment snapshot helper is unavailable"
        ) from exc
    try:
        return tuple(_snapshot_fragments(fragment_directory))
    except MemoryError:
        raise
    except CoveragePathMappingError as exc:
        raise CoverageFragmentAttributionError(
            "coverage fragment set is outside the authoritative bound"
        ) from exc


def _fragment_basename_sha256(fragment: Path) -> str:
    try:
        from scripts.coverage_fragment_quiescence import (
            CoveragePathMappingError,
            _fragment_name_bytes,
        )
    except (AttributeError, ImportError, TypeError) as exc:
        raise CoverageFragmentAttributionError(
            "coverage fragment name helper is unavailable"
        ) from exc
    try:
        return hashlib.sha256(_fragment_name_bytes(fragment)).hexdigest()
    except MemoryError:
        raise
    except CoveragePathMappingError as exc:
        raise CoverageFragmentAttributionError(
            "coverage fragment basename is outside the authoritative bound"
        ) from exc


def _diagnostic_for_fragment(
    fragment: Path,
    metadata_root: Path,
    *,
    reader_stage: str,
) -> str:
    name_digest = _fragment_basename_sha256(fragment)
    match = _FRAGMENT_RE.match(fragment.name)
    if match is None:
        return (
            "coverage fragment attribution: "
            f"fragment_basename_sha256={name_digest}, producer_quality=unavailable, "
            f"test_family=unavailable, scope=unavailable, reader_stage={reader_stage}"
        )
    producer_id = match.group("producer")
    try:
        process = _validated_process_record(metadata_root, producer_id)
        parent_producer_id = process["parent_producer_id"]
        if type(parent_producer_id) is str:
            _validated_process_record(metadata_root, parent_producer_id)
        family_token = process["family_token"]
        family = (
            _validated_family_record(metadata_root, family_token)
            if type(family_token) is str
            else "unavailable"
        )
        quality = process["family_quality"]
        scope = process["attribution_scope"]
    except MemoryError:
        raise
    except CoverageFragmentAttributionError:
        family = "unavailable"
        parent_producer_id = "unavailable"
        quality = "receipt_invalid_or_missing"
        scope = "unavailable"
    return (
        "coverage fragment attribution: "
        f"fragment_basename_sha256={name_digest}, producer_quality={quality}, "
        f"test_family={family}, scope={scope}, "
        f"parent_producer_id={parent_producer_id}, reader_stage={reader_stage}"
    )


def report_invalid_fragment_attribution(
    *,
    fragments_root: Path,
    metadata_root: Path,
    output: TextIO = sys.stdout,
    coverage_data_type: type[Any] | None = None,
) -> int:
    """Report sanitized provenance for invalid fragments without mutating them."""

    fragments = _existing_private_directory(fragments_root, label="coverage fragments root")
    metadata = _existing_private_directory(metadata_root, label="attribution metadata root")
    children = _bounded_fragment_children(fragments)
    invalid = 0
    for child in children:
        stage: str | None
        if not child.name.startswith(".coverage."):
            stage = "unexpected_member"
        else:
            stage = _fragment_reader_failure_stage(child, coverage_data_type)
        if stage is None:
            continue
        invalid += 1
        print(
            _diagnostic_for_fragment(child, metadata, reader_stage=stage),
            file=output,
        )
    print(f"coverage fragment attribution summary: invalid_fragments={invalid}", file=output)
    return invalid


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    report = subcommands.add_parser("report", help="report failure-only fragment attribution")
    report.add_argument("--fragments-root", required=True, type=Path)
    report.add_argument("--metadata-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "report":
        try:
            report_invalid_fragment_attribution(
                fragments_root=args.fragments_root,
                metadata_root=args.metadata_root,
            )
        except MemoryError:
            raise
        except CoverageFragmentAttributionError:
            print(
                "coverage fragment attribution summary: diagnostic_unavailable",
                file=sys.stdout,
            )
        return 0
    raise AssertionError("unreachable attribution command")


if __name__ == "__main__":
    raise SystemExit(main())
