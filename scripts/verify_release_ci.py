#!/usr/bin/env python3
"""Fail-closed validation of exact-commit GitHub Actions run evidence.

The release workflow owns network access and writes the bounded API responses
to runner-temporary files. This verifier is deliberately offline so its
correlation logic can be falsified without GitHub credentials or network I/O.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, NoReturn


EXPECTED_REPOSITORY = "Ryan529616/aoi-orgware"
EXPECTED_BRANCH = "main"
EXPECTED_WORKFLOWS = frozenset(
    {
        ".github/workflows/docs.yml",
        ".github/workflows/test.yml",
    }
)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_RUNS_PER_WORKFLOW = 100
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")


class VerificationError(ValueError):
    """The supplied workflow-run evidence cannot authorize publication."""


def _fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"GitHub response contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _read_response(path_text: str) -> tuple[Mapping[str, Any], str]:
    path = Path(path_text)
    if not path.is_absolute():
        _fail("workflow response path must be absolute")
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            _fail("workflow response must be a regular non-link file")
        if before.st_size > MAX_RESPONSE_BYTES:
            _fail("workflow response exceeds byte bound")
        raw = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        _fail(f"cannot read workflow response: {exc}")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(raw) != before.st_size:
        _fail("workflow response changed while being read")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"workflow response is not strict UTF-8 JSON: {exc}")
    return _mapping(parsed, "GitHub response root"), hashlib.sha256(raw).hexdigest()


def _parse_workflows(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        workflow, separator, response_path = value.partition("=")
        if not separator or not workflow or not response_path:
            _fail("--workflow must be WORKFLOW_PATH=ABSOLUTE_RESPONSE_PATH")
        if workflow in parsed:
            _fail(f"duplicate workflow response binding: {workflow}")
        parsed[workflow] = response_path
    if set(parsed) != EXPECTED_WORKFLOWS:
        _fail(
            "workflow response bindings must be exactly "
            + ", ".join(sorted(EXPECTED_WORKFLOWS))
        )
    return parsed


def _validate_runs(
    document: Mapping[str, Any],
    *,
    workflow_path: str,
    repository: str,
    commit: str,
    branch: str,
    response_sha256: str,
    global_run_ids: set[int],
) -> dict[str, Any]:
    total_count = document.get("total_count")
    if (
        isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count < 0
    ):
        _fail(f"{workflow_path} total_count must be a non-negative integer")
    runs = document.get("workflow_runs")
    if not isinstance(runs, list):
        _fail(f"{workflow_path} workflow_runs must be a list")
    if total_count != len(runs):
        _fail(f"{workflow_path} response is truncated or count-mismatched")
    if not runs:
        _fail(f"{workflow_path} has no successful exact-commit push run")
    if len(runs) > MAX_RUNS_PER_WORKFLOW:
        _fail(f"{workflow_path} exceeds workflow-run bound")

    accepted: list[dict[str, int]] = []
    local_run_ids: set[int] = set()
    for index, raw_run in enumerate(runs):
        label = f"{workflow_path} workflow_runs[{index}]"
        run = _mapping(raw_run, label)
        run_id = _positive_int(run.get("id"), f"{label}.id")
        workflow_id = _positive_int(run.get("workflow_id"), f"{label}.workflow_id")
        attempt = _positive_int(run.get("run_attempt"), f"{label}.run_attempt")
        if run_id in local_run_ids or run_id in global_run_ids:
            _fail(f"duplicate workflow run id: {run_id}")
        local_run_ids.add(run_id)

        expected_strings = {
            "head_sha": commit,
            "head_branch": branch,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "path": workflow_path,
        }
        for field, expected in expected_strings.items():
            actual = _string(run.get(field), f"{label}.{field}")
            if actual != expected:
                _fail(f"{label}.{field} does not match exact release evidence")

        observed_repository = _mapping(
            run.get("repository"), f"{label}.repository"
        )
        head_repository = _mapping(
            run.get("head_repository"), f"{label}.head_repository"
        )
        for nested_label, nested in (
            ("repository", observed_repository),
            ("head_repository", head_repository),
        ):
            if (
                _string(nested.get("full_name"), f"{label}.{nested_label}.full_name")
                != repository
            ):
                _fail(f"{label}.{nested_label} is not the canonical repository")
        accepted.append(
            {
                "run_id": run_id,
                "run_attempt": attempt,
                "workflow_id": workflow_id,
            }
        )

    global_run_ids.update(local_run_ids)
    accepted.sort(key=lambda item: (item["run_id"], item["run_attempt"]))
    return {
        "path": workflow_path,
        "response_sha256": response_sha256,
        "runs": accepted,
    }


def verify(
    *,
    repository: str,
    commit: str,
    branch: str,
    workflow_responses: Mapping[str, str],
) -> dict[str, Any]:
    if repository != EXPECTED_REPOSITORY:
        _fail("repository is not the canonical release repository")
    if branch != EXPECTED_BRANCH:
        _fail("branch is not the canonical release branch")
    if _SHA1.fullmatch(commit) is None:
        _fail("commit must be one full lowercase Git SHA-1")
    if set(workflow_responses) != EXPECTED_WORKFLOWS:
        _fail("workflow response set is incomplete or unexpected")

    global_run_ids: set[int] = set()
    workflows: list[dict[str, Any]] = []
    for workflow_path in sorted(workflow_responses):
        document, response_sha256 = _read_response(
            workflow_responses[workflow_path]
        )
        workflows.append(
            _validate_runs(
                document,
                workflow_path=workflow_path,
                repository=repository,
                commit=commit,
                branch=branch,
                response_sha256=response_sha256,
                global_run_ids=global_run_ids,
            )
        )
    base = {
        "schema_version": 1,
        "kind": "exact_release_ci_gate",
        "repository": repository,
        "commit": commit,
        "branch": branch,
        "event": "push",
        "workflows": workflows,
    }
    canonical = json.dumps(
        base,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        **base,
        "receipt_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify exact successful test/docs GitHub Actions responses."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument(
        "--workflow",
        action="append",
        default=[],
        help="WORKFLOW_PATH=ABSOLUTE_RESPONSE_PATH; repeat for test and docs",
    )
    args = parser.parse_args(argv)
    try:
        receipt = verify(
            repository=args.repository,
            commit=args.commit,
            branch=args.branch,
            workflow_responses=_parse_workflows(args.workflow),
        )
    except VerificationError as exc:
        print(f"verify_release_ci: {exc}", file=sys.stderr)
        return 2
    raw = (
        json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(raw.decode("utf-8"))
        sys.stdout.flush()
    else:
        stream.write(raw)
        stream.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
