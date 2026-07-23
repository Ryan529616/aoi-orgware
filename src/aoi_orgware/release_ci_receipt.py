"""Strict validation for content-addressed exact-release-CI receipts."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any, NoReturn


EXPECTED_REPOSITORY = "Ryan529616/aoi-orgware"
EXPECTED_BRANCH = "main"
EXPECTED_WORKFLOWS = (
    ".github/workflows/docs.yml",
    ".github/workflows/test.yml",
)
MAX_EXACT_CI_RECEIPT_BYTES = 256 * 1024
MAX_RUNS_PER_WORKFLOW = 100
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ReleaseCIReceiptError(ValueError):
    """An exact-CI receipt is malformed, tampered, or wrongly correlated."""


def _fail(message: str) -> NoReturn:
    raise ReleaseCIReceiptError(message)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase SHA-256")
    return value


def _canonical_base_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"exact-CI receipt is not canonical JSON data: {exc}")


def validate_exact_ci_receipt(
    value: Mapping[str, Any],
    *,
    expected_repository: str = EXPECTED_REPOSITORY,
    expected_commit: str | None = None,
    expected_branch: str = EXPECTED_BRANCH,
) -> dict[str, Any]:
    """Validate one receipt without trusting its caller-provided summary."""

    expected_keys = {
        "schema_version",
        "kind",
        "repository",
        "commit",
        "branch",
        "event",
        "workflows",
        "receipt_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        _fail("exact-CI receipt schema is invalid")
    commit = value.get("commit")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("kind") != "exact_release_ci_gate"
        or value.get("repository") != expected_repository
        or value.get("branch") != expected_branch
        or value.get("event") != "push"
        or not isinstance(commit, str)
        or _SHA1.fullmatch(commit) is None
        or (expected_commit is not None and commit != expected_commit)
    ):
        _fail("exact-CI receipt identity is invalid")

    workflows = value.get("workflows")
    if not isinstance(workflows, list) or len(workflows) != len(EXPECTED_WORKFLOWS):
        _fail("exact-CI receipt workflow set is invalid")
    observed_paths: list[str] = []
    observed_run_ids: set[int] = set()
    for workflow_index, raw_workflow in enumerate(workflows):
        label = f"exact-CI workflow {workflow_index + 1}"
        if not isinstance(raw_workflow, Mapping) or set(raw_workflow) != {
            "path",
            "response_sha256",
            "runs",
        }:
            _fail(f"{label} schema is invalid")
        path = raw_workflow.get("path")
        if not isinstance(path, str):
            _fail(f"{label} path is invalid")
        observed_paths.append(path)
        _sha256(raw_workflow.get("response_sha256"), f"{label} response SHA-256")
        runs = raw_workflow.get("runs")
        if (
            not isinstance(runs, list)
            or not runs
            or len(runs) > MAX_RUNS_PER_WORKFLOW
        ):
            _fail(f"{label} run set is invalid")
        normalized_runs: list[tuple[int, int, int]] = []
        for run_index, raw_run in enumerate(runs):
            run_label = f"{label} run {run_index + 1}"
            if not isinstance(raw_run, Mapping) or set(raw_run) != {
                "run_id",
                "run_attempt",
                "workflow_id",
            }:
                _fail(f"{run_label} schema is invalid")
            run_id = _positive_int(raw_run.get("run_id"), f"{run_label} id")
            run_attempt = _positive_int(
                raw_run.get("run_attempt"), f"{run_label} attempt"
            )
            workflow_id = _positive_int(
                raw_run.get("workflow_id"), f"{run_label} workflow id"
            )
            if run_id in observed_run_ids:
                _fail("exact-CI receipt contains a duplicate workflow run id")
            observed_run_ids.add(run_id)
            normalized_runs.append((run_id, run_attempt, workflow_id))
        if normalized_runs != sorted(normalized_runs):
            _fail(f"{label} runs are noncanonical")
    if observed_paths != list(EXPECTED_WORKFLOWS):
        _fail("exact-CI receipt workflow paths are incomplete or noncanonical")

    claimed = _sha256(value.get("receipt_sha256"), "exact-CI receipt digest")
    base = dict(value)
    del base["receipt_sha256"]
    expected_digest = hashlib.sha256(_canonical_base_bytes(base)).hexdigest()
    if claimed != expected_digest:
        _fail("exact-CI receipt digest is invalid")
    return dict(value)


def canonical_exact_ci_receipt_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the one portable artifact encoding: canonical UTF-8 plus LF."""

    validated = validate_exact_ci_receipt(value)
    raw = _canonical_base_bytes(validated) + b"\n"
    if len(raw) > MAX_EXACT_CI_RECEIPT_BYTES:
        _fail("exact-CI receipt exceeds its byte bound")
    return raw


def parse_exact_ci_receipt_bytes(raw: bytes) -> dict[str, Any]:
    """Reject duplicate keys, noncanonical JSON, CRLF, and trailing data."""

    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_EXACT_CI_RECEIPT_BYTES
    ):
        _fail("exact-CI receipt bytes are empty or exceed their bound")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail(f"exact-CI receipt contains duplicate JSON key: {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"exact-CI receipt is not strict UTF-8 JSON: {exc}")
    if not isinstance(parsed, Mapping):
        _fail("exact-CI receipt root must be an object")
    validated = validate_exact_ci_receipt(parsed)
    if raw != _canonical_base_bytes(validated) + b"\n":
        _fail("exact-CI receipt bytes are not canonical LF-terminated JSON")
    return validated


__all__ = [
    "EXPECTED_BRANCH",
    "EXPECTED_REPOSITORY",
    "EXPECTED_WORKFLOWS",
    "MAX_EXACT_CI_RECEIPT_BYTES",
    "ReleaseCIReceiptError",
    "canonical_exact_ci_receipt_bytes",
    "parse_exact_ci_receipt_bytes",
    "validate_exact_ci_receipt",
]
