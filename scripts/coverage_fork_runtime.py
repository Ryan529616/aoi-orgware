"""Version-qualified coverage.py lifecycle for AOI's test-only fork hook."""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from typing import Any


COVERAGE_CONFIG_ENV = "AOI_COVERAGE_PROCESS_START"
CURRENT_PRODUCER_ENV = "AOI_COVERAGE_CURRENT_PRODUCER_ID"
RUNTIME_PREFIX_ENV = "AOI_COVERAGE_RUNTIME_PREFIX"
EXPECTED_COVERAGE_VERSION = "7.15.2"
VENDOR_START_ENVIRONMENTS = (
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_PROCESS_START",
)
COVERAGE_SELECTOR_ENVIRONMENTS = (
    COVERAGE_CONFIG_ENV,
    CURRENT_PRODUCER_ENV,
    RUNTIME_PREFIX_ENV,
    "AOI_COVERAGE_FILE_BASE",
    "AOI_COVERAGE_METADATA_ROOT",
    "AOI_COVERAGE_TEST_FAMILY_TOKEN",
    "COVERAGE_FILE",
    *VENDOR_START_ENVIRONMENTS,
)
_FORK_CALLBACK_REGISTERED = False
_HARD_EXIT_INSTALLED = False


class CoverageForkRuntimeError(RuntimeError):
    """Raised when the pinned collector lifecycle cannot remain exact."""


def runtime_prefix_matches(
    runtime_prefix: str,
    target: MutableMapping[str, str],
) -> bool:
    """Return whether this interpreter is the workflow-bound runtime exactly."""

    configured = target.get(RUNTIME_PREFIX_ENV)
    if (
        type(runtime_prefix) is not str
        or type(configured) is not str
        or not runtime_prefix
        or not configured
        or "\x00" in runtime_prefix
        or "\x00" in configured
        or not os.path.isabs(runtime_prefix)
        or not os.path.isabs(configured)
    ):
        raise CoverageForkRuntimeError("coverage runtime prefix binding is invalid")
    try:
        if not os.path.isdir(runtime_prefix) or not os.path.isdir(configured):
            raise CoverageForkRuntimeError("coverage runtime prefix is unavailable")
        return os.path.samefile(runtime_prefix, configured)
    except CoverageForkRuntimeError:
        raise
    except OSError as error:
        raise CoverageForkRuntimeError("coverage runtime prefix cannot be verified") from error


def coverage_api(coverage_module: Any) -> tuple[Any, Any]:
    if getattr(coverage_module, "__version__", None) != EXPECTED_COVERAGE_VERSION:
        raise CoverageForkRuntimeError("coverage runtime version is unqualified")
    startup = getattr(coverage_module, "process_startup", None)
    coverage_type = getattr(coverage_module, "Coverage", None)
    current = getattr(coverage_type, "current", None)
    if not callable(startup) or not callable(current):
        raise CoverageForkRuntimeError("coverage runtime API is unavailable")
    return startup, current


def ensure_not_started(coverage_module: Any) -> None:
    _, current = coverage_api(coverage_module)
    if current() is not None:
        raise CoverageForkRuntimeError("coverage was already started")


def stop_inherited_coverage(coverage_module: Any) -> None:
    startup, current = coverage_api(coverage_module)
    inherited = getattr(startup, "coverage", None)
    if inherited is None or current() is not inherited:
        raise CoverageForkRuntimeError("inherited coverage owner is ambiguous")
    if type(getattr(inherited, "_auto_save", None)) is not bool:
        raise CoverageForkRuntimeError("coverage autosave contract differs")
    inherited._auto_save = False
    inherited.stop()
    if current() is not None:
        raise CoverageForkRuntimeError("inherited coverage did not stop")


def start_exact_coverage(
    coverage_module: Any,
    target: MutableMapping[str, str],
    *,
    force: bool,
    slug: str,
) -> None:
    startup, current = coverage_api(coverage_module)
    config = target.get(COVERAGE_CONFIG_ENV)
    if type(config) is not str or any(
        name in target for name in VENDOR_START_ENVIRONMENTS
    ):
        raise CoverageForkRuntimeError("coverage startup selector differs")
    target["COVERAGE_PROCESS_START"] = config
    try:
        started = startup(force=force, slug=slug) if force else startup()
    finally:
        target.pop("COVERAGE_PROCESS_START", None)
    if started is None or current() is not started:
        raise CoverageForkRuntimeError("coverage startup identity differs")


def _clear_exit_selectors(target: MutableMapping[str, str]) -> None:
    for name in COVERAGE_SELECTOR_ENVIRONMENTS:
        try:
            target.pop(name, None)
        except BaseException:
            pass


def _flush_then_exit(
    coverage_module: Any,
    code: int,
    *,
    target: MutableMapping[str, str],
    hard_exit: Any,
) -> None:
    exit_code = code
    try:
        startup, current = coverage_api(coverage_module)
        active = current()
        if active is None or active is not getattr(startup, "coverage", None):
            raise CoverageForkRuntimeError("coverage hard-exit owner is ambiguous")
        stop = getattr(active, "stop", None)
        save = getattr(active, "save", None)
        if not callable(stop) or not callable(save):
            raise CoverageForkRuntimeError("coverage hard-exit flush is unavailable")
        stop()
        save()
    except BaseException:
        exit_code = 97
    finally:
        _clear_exit_selectors(target)
        hard_exit(exit_code)


def install_hard_exit_flush(
    coverage_module: Any,
    *,
    os_module: Any = os,
) -> None:
    """Flush Python-level ``os._exit`` without running general atexit hooks."""

    global _HARD_EXIT_INSTALLED
    if _HARD_EXIT_INSTALLED:
        return
    original = getattr(os_module, "_exit", None)
    target = getattr(os_module, "environ", None)
    if not callable(original) or not isinstance(target, MutableMapping):
        raise CoverageForkRuntimeError("hard-exit runtime is unavailable")

    def coverage_hard_exit(code: int) -> None:
        _flush_then_exit(
            coverage_module,
            code,
            target=target,
            hard_exit=original,
        )

    os_module._exit = coverage_hard_exit
    _HARD_EXIT_INSTALLED = True


def install_fork_callback(
    child_callback: Any,
    register_at_fork: Any | None = None,
) -> None:
    global _FORK_CALLBACK_REGISTERED
    if _FORK_CALLBACK_REGISTERED:
        return
    register = (
        getattr(os, "register_at_fork", None)
        if register_at_fork is None
        else register_at_fork
    )
    if register is None:
        if os.name == "posix":
            raise CoverageForkRuntimeError("fork attribution is unavailable")
        return
    register(after_in_child=child_callback)
    _FORK_CALLBACK_REGISTERED = True
