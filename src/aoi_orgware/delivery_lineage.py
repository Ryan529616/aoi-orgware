"""Fail-closed lineage checks for terminal pushed-delivery refs."""
from __future__ import annotations

from pathlib import Path

from typing import Any

from .git_plumbing import git_is_ancestor, state_worktree, worktree_integrity_errors
from .harnesslib import HarnessError, HarnessPaths


def delivery_worktree_lineage_errors(
    paths: HarnessPaths, state: dict[str, Any], commit: str
) -> tuple[list[str], dict[str, str] | None, bool]:
    """Validate active exactness or terminal descendant lineage."""

    terminal = state.get("status") in {"done", "cancelled"}
    errors, current = worktree_integrity_errors(paths, state)
    if current is None:
        return errors, None, terminal
    recorded_branch = state.get("branch")
    if terminal and isinstance(recorded_branch, str) and recorded_branch:
        branch_error = (
            f"task branch changed from {recorded_branch!r} "
            f"to {current['branch']!r}"
        )
        if current["branch"] != recorded_branch:
            if errors.count(branch_error) != 1:
                errors.append("terminal branch transition validation is inconsistent")
            else:
                errors.remove(branch_error)
    elif terminal:
        errors.append("task branch is missing or invalid")
    if not terminal and current["head_sha"] != commit:
        errors.append(
            f"pushed delivery commit {commit} is not the task worktree HEAD "
            f"{current['head_sha']}"
        )
        return errors, current, terminal
    if not terminal:
        return errors, current, terminal
    try:
        contains_delivery = git_is_ancestor(
            state_worktree(paths, state), commit, current["head_sha"]
        )
    except HarnessError as exc:
        errors.append(str(exc))
    else:
        if not contains_delivery:
            errors.append(
                f"pushed delivery commit {commit} is not an ancestor of the "
                f"terminal task worktree HEAD {current['head_sha']}"
            )
    return errors, current, terminal


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


__all__ = ["delivery_worktree_lineage_errors", "remote_tip_error"]
