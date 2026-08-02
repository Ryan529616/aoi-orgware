"""Repository-wide pytest hooks for bounded test-only diagnostics."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

import pytest

from scripts.coverage_fragment_attribution import (
    METADATA_ROOT_ENV,
    PYTEST_FAMILY_TOKEN_ENV,
    attempt_pytest_family_scope as coverage_family_scope,
)


_ROOT = Path(__file__).resolve().parents[1]


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item: Any, nextitem: Any) -> Iterator[None]:
    """Expose only a parameter-free, repo-relative family to fresh children."""

    del nextitem
    if METADATA_ROOT_ENV not in os.environ:
        yield
        return
    try:
        relative = Path(str(item.path)).resolve(strict=True).relative_to(_ROOT).as_posix()
        class_name = item.cls.__name__ if item.cls is not None else None
        function_name = getattr(item, "originalname", None)
        if function_name is None:
            function_name = item.name.split("[", 1)[0]
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception:
        os.environ.pop(PYTEST_FAMILY_TOKEN_ENV, None)
        yield
        return
    with coverage_family_scope(
        relative_path=relative,
        class_name=class_name,
        function_name=function_name,
    ):
        yield
