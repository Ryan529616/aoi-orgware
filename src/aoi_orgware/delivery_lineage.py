"""Fail-closed lineage checks for terminal pushed-delivery refs."""
from __future__ import annotations

from pathlib import Path

from .git_plumbing import git_is_ancestor
from .harnesslib import HarnessError


def remote_tip_error(
    worktree: Path,
    expected_tip: str,
    actual_tip: str,
    remote: str,
    remote_ref: str,
    expected_label: str,
    allow_descendant: bool,
) -> str:
    """Return an integrity error unless the observed tip preserves lineage."""

    if actual_tip == expected_tip:
        return ""
    if allow_descendant:
        try:
            if git_is_ancestor(worktree, expected_tip, actual_tip):
                return ""
        except HarnessError as exc:
            return "cannot verify terminal pushed-delivery remote ancestry: " + str(exc)
    return (
        f"remote {remote} {remote_ref} points to {actual_tip}, "
        f"not the {expected_label} {expected_tip}"
    )


__all__ = ["remote_tip_error"]
