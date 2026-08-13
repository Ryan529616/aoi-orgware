"""Fail-closed startup for AOI's pinned test-only coverage collector."""

from __future__ import annotations

import os
import sys


_SELECTORS = (
    "AOI_COVERAGE_CURRENT_PRODUCER_ID",
    "AOI_COVERAGE_PROCESS_START",
    "AOI_COVERAGE_RUNTIME_PREFIX",
    "AOI_COVERAGE_FILE_BASE",
    "AOI_COVERAGE_METADATA_ROOT",
    "AOI_COVERAGE_TEST_FAMILY_TOKEN",
    "COVERAGE_FILE",
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_PROCESS_START",
)
_PRIVATE_AOI_SELECTORS = tuple(
    name for name in _SELECTORS if name.startswith("AOI_COVERAGE_")
)


def _hard_fail() -> None:
    try:
        for name in _SELECTORS:
            try:
                os.environ.pop(name, None)
            except BaseException:
                pass
    finally:
        os._exit(97)


def _runtime_prefix_matches() -> bool:
    configured = os.environ.get("AOI_COVERAGE_RUNTIME_PREFIX")
    runtime_prefix = sys.prefix
    if (
        type(configured) is not str
        or type(runtime_prefix) is not str
        or not configured
        or not runtime_prefix
        or "\x00" in configured
        or "\x00" in runtime_prefix
        or not os.path.isabs(configured)
        or not os.path.isabs(runtime_prefix)
    ):
        raise RuntimeError("coverage runtime prefix binding is invalid")
    if not os.path.isdir(configured) or not os.path.isdir(runtime_prefix):
        raise RuntimeError("coverage runtime prefix is unavailable")
    return os.path.samefile(configured, runtime_prefix)


def _clear_out_of_scope_selectors() -> None:
    try:
        for name in _SELECTORS:
            os.environ.pop(name, None)
    except BaseException:
        _hard_fail()


if any(name in os.environ for name in _PRIVATE_AOI_SELECTORS):
    try:
        if not _runtime_prefix_matches():
            _clear_out_of_scope_selectors()
        else:
            import coverage
            from aoi_coverage_fragment_attribution import (
                attempt_subprocess_coverage_attribution,
            )
            from aoi_coverage_fork_runtime import install_hard_exit_flush

            if not attempt_subprocess_coverage_attribution(coverage_module=coverage):
                _hard_fail()
            install_hard_exit_flush(coverage)
    except BaseException:
        _hard_fail()
