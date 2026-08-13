"""Focused adversarial tests for terminal pushed-delivery lineage."""
from __future__ import annotations

from pathlib import Path
from unittest import mock

from aoi_orgware import delivery_lineage
from aoi_orgware.harnesslib import HarnessError


WORKTREE = Path("C:/bounded/worktree")
EXPECTED = "a" * 40
ACTUAL = "b" * 40


def _error(*, allow_descendant: bool) -> str:
    return delivery_lineage.remote_tip_error(
        WORKTREE,
        EXPECTED,
        ACTUAL,
        "origin",
        "refs/heads/main",
        "terminal task worktree HEAD",
        allow_descendant,
    )


def test_exact_tip_needs_no_ancestry_query() -> None:
    with mock.patch.object(delivery_lineage, "git_is_ancestor") as ancestry:
        assert delivery_lineage.remote_tip_error(
            WORKTREE,
            EXPECTED,
            EXPECTED,
            "origin",
            "refs/heads/main",
            "delivery commit",
            False,
        ) == ""
    ancestry.assert_not_called()


def test_terminal_descendant_is_accepted() -> None:
    with mock.patch.object(delivery_lineage, "git_is_ancestor", return_value=True):
        assert _error(allow_descendant=True) == ""


def test_rewind_or_divergent_tip_is_rejected() -> None:
    with mock.patch.object(delivery_lineage, "git_is_ancestor", return_value=False):
        assert _error(allow_descendant=True) == (
            f"remote origin refs/heads/main points to {ACTUAL}, not the "
            f"terminal task worktree HEAD {EXPECTED}"
        )


def test_active_delivery_never_queries_or_accepts_descendant() -> None:
    with mock.patch.object(delivery_lineage, "git_is_ancestor") as ancestry:
        assert _error(allow_descendant=False)
    ancestry.assert_not_called()


def test_unknown_remote_object_fails_closed() -> None:
    with mock.patch.object(
        delivery_lineage,
        "git_is_ancestor",
        side_effect=HarnessError("remote tip object is unavailable"),
    ):
        assert _error(allow_descendant=True) == (
            "cannot verify terminal pushed-delivery remote ancestry: "
            "remote tip object is unavailable"
        )
