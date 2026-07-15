"""Git worktree metadata, ancestry, and legacy-claim scope checks.

The CLI stays the composition root and remains the canonical source for
``require_full_commit``/``require_text`` (see :mod:`aoi_orgware.state_lookup`);
this module keeps small private duplicates of those two pure helpers so its
own git-facing functions are self-contained without importing the CLI. This
module imports only sibling packages (:mod:`aoi_orgware.harnesslib`) and
never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    load_claim_file,
    validated_state_worktree,
)


COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_full_commit(value: str, label: str) -> str:
    commit = require_text(value, label).lower()
    if not FULL_COMMIT_RE.fullmatch(commit):
        raise HarnessError(f"{label} must be a full 40-64 hex commit id")
    return commit


def git_metadata(worktree: Path) -> dict[str, str]:
    resolved = worktree.resolve()
    if not resolved.is_dir():
        raise HarnessError(f"worktree does not exist: {resolved}")

    def run(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(resolved), *arguments],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessError(f"Git metadata command failed: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise HarnessError(
                f"Git metadata command failed ({' '.join(arguments)}): {detail or 'unknown error'}"
            )
        return result.stdout.strip()

    top = run("rev-parse", "--show-toplevel")
    if Path(top).resolve() != resolved:
        raise HarnessError(
            f"--worktree must be the Git worktree root, got {resolved} (root is {top})"
        )
    head_sha = run("rev-parse", "HEAD").lower()
    if not FULL_COMMIT_RE.fullmatch(head_sha):
        raise HarnessError(f"Git worktree has no valid HEAD commit: {head_sha!r}")
    branch = run("branch", "--show-current") or "detached"
    return {
        "worktree": str(resolved),
        "branch": branch,
        "head_sha": head_sha,
    }


def git_is_ancestor(worktree: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(worktree), "merge-base", "--is-ancestor", ancestor, descendant],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode not in {0, 1}:
        detail = (result.stderr or result.stdout).strip()
        raise HarnessError(f"Git ancestry check failed: {detail or result.returncode}")
    return result.returncode == 0


def resolve_task_commit(state: dict[str, Any], value: str, label: str) -> str:
    requested = require_full_commit(value, label)
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(Path(state.get("worktree", "")).resolve()),
                "rev-parse",
                f"{requested}^{{commit}}",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"could not resolve {label}: {exc}") from exc
    resolved = result.stdout.strip().lower()
    if result.returncode != 0 or not FULL_COMMIT_RE.fullmatch(resolved):
        raise HarnessError(f"{label} is not a commit in the task worktree")
    if resolved != requested:
        raise HarnessError(f"{label} must name the exact full commit, got {resolved}")
    return resolved


def state_worktree(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    return validated_state_worktree(paths, state)


def worktree_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> tuple[list[str], dict[str, str] | None]:
    try:
        current = git_metadata(state_worktree(paths, state))
    except HarnessError as exc:
        return [str(exc)], None
    errors: list[str] = []
    if current["worktree"] != str(state.get("worktree", "")):
        errors.append(
            f"recorded worktree {state.get('worktree')!r} differs from {current['worktree']!r}"
        )
    if current["branch"] != state.get("branch"):
        errors.append(
            f"task branch changed from {state.get('branch')!r} to {current['branch']!r}"
        )
    if not FULL_COMMIT_RE.fullmatch(str(state.get("head_sha", ""))):
        errors.append("task starting HEAD is missing or invalid")
    return errors, current


def legacy_ambiguities(
    paths: HarnessPaths, *, ignore_token: str | None = None
) -> list[dict[str, Any]]:
    ambiguous: list[dict[str, Any]] = []
    for pending in sorted(paths.legacy_pending.glob("*.json")):
        claim = load_claim_file(pending)
        if claim.get("token") == ignore_token:
            continue
        if claim.get("scope_parse_warnings"):
            ambiguous.append(
                {
                    "token": claim.get("token"),
                    "owner": claim.get("owner"),
                    "raw_scope": claim.get("raw_scope"),
                    "warnings": claim.get("scope_parse_warnings"),
                    "locks": claim.get("locks", []),
                    "source_file": claim.get("source_file"),
                    "source_line": claim.get("source_line"),
                    "pending_file": str(pending),
                }
            )
    return ambiguous


def remote_ref_tip(worktree: Path, remote: str, remote_ref: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", remote):
        raise HarnessError(f"invalid Git remote name: {remote!r}")
    if not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", remote_ref) or ".." in remote_ref:
        raise HarnessError(f"--remote-ref must be a full refs/heads/... ref: {remote_ref!r}")
    try:
        result = subprocess.run(
            ["git", "-C", str(worktree), "ls-remote", "--exit-code", remote, remote_ref],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"could not verify pushed remote ref: {exc}") from exc
    if result.returncode != 0:
        raise HarnessError(
            "could not verify pushed remote ref: "
            + ((result.stderr or result.stdout).strip() or "ref not found")
        )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError(f"expected exactly one remote ref result, got {len(lines)}")
    tip = lines[0].split()[0].lower()
    if not FULL_COMMIT_RE.fullmatch(tip):
        raise HarnessError(f"remote ref returned invalid commit id: {tip!r}")
    return tip


__all__ = [
    "COMMIT_RE",
    "FULL_COMMIT_RE",
    "git_is_ancestor",
    "git_metadata",
    "legacy_ambiguities",
    "remote_ref_tip",
    "resolve_task_commit",
    "state_worktree",
    "worktree_integrity_errors",
]
