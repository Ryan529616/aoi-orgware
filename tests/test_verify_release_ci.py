"""Falsification tests for the offline exact-release-CI verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from aoi_orgware import release_ci_receipt


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_release_ci.py"
REPOSITORY = "Ryan529616/aoi-orgware"
COMMIT = "a" * 40
WORKFLOWS = (
    ".github/workflows/docs.yml",
    ".github/workflows/test.yml",
)


def _run_record(
    workflow: str, run_id: int, *, attempt: int = 1
) -> dict[str, object]:
    return {
        "id": run_id,
        "workflow_id": 300_000_000 + run_id,
        "run_attempt": attempt,
        "head_sha": COMMIT,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "path": workflow,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }


def _documents() -> dict[str, dict[str, object]]:
    return {
        workflow: {
            "total_count": 1,
            "workflow_runs": [_run_record(workflow, index + 1)],
        }
        for index, workflow in enumerate(WORKFLOWS)
    }


def _invoke(
    tmp_path: Path,
    documents: dict[str, object],
    *,
    raw_overrides: dict[str, str] | None = None,
    repository: str = REPOSITORY,
    commit: str = COMMIT,
    branch: str = "main",
    workflow_order: tuple[str, ...] = WORKFLOWS,
    binary: bool = False,
) -> subprocess.CompletedProcess[Any]:
    args = [
        sys.executable,
        "-I",
        str(SCRIPT),
        "--repository",
        repository,
        "--commit",
        commit,
        "--branch",
        branch,
    ]
    for index, workflow in enumerate(workflow_order):
        response = (tmp_path / f"response-{index}.json").resolve()
        if raw_overrides and workflow in raw_overrides:
            response.write_text(raw_overrides[workflow], encoding="utf-8")
        else:
            response.write_text(
                json.dumps(documents[workflow], sort_keys=True),
                encoding="utf-8",
            )
        args.extend(["--workflow", f"{workflow}={response}"])
    return subprocess.run(
        args, text=not binary, capture_output=True, check=False
    )


def test_accepts_multiple_successful_exact_main_push_reruns(
    tmp_path: Path,
) -> None:
    documents = _documents()
    test_document = documents[".github/workflows/test.yml"]
    test_document["workflow_runs"] = [
        _run_record(".github/workflows/test.yml", 2, attempt=1),
        _run_record(".github/workflows/test.yml", 3, attempt=2),
    ]
    test_document["total_count"] = 2
    completed = _invoke(tmp_path, documents, binary=True)
    assert completed.returncode == 0, completed.stderr
    assert isinstance(completed.stdout, bytes)
    assert completed.stdout.endswith(b"\n")
    assert not completed.stdout.endswith(b"\r\n")
    receipt = release_ci_receipt.parse_exact_ci_receipt_bytes(completed.stdout)
    assert (
        release_ci_receipt.canonical_exact_ci_receipt_bytes(receipt)
        == completed.stdout
    )
    assert receipt["kind"] == "exact_release_ci_gate"
    assert receipt["commit"] == COMMIT
    assert [item["path"] for item in receipt["workflows"]] == list(WORKFLOWS)
    base = {
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    }
    canonical = json.dumps(
        base, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert receipt["receipt_sha256"] == hashlib.sha256(canonical).hexdigest()


def test_receipt_parser_rejects_crlf_and_duplicate_keys(tmp_path: Path) -> None:
    completed = _invoke(tmp_path, _documents(), binary=True)
    assert completed.returncode == 0, completed.stderr
    assert isinstance(completed.stdout, bytes)
    raw = completed.stdout
    with pytest.raises(
        release_ci_receipt.ReleaseCIReceiptError, match="canonical LF-terminated"
    ):
        release_ci_receipt.parse_exact_ci_receipt_bytes(raw[:-1] + b"\r\n")
    with pytest.raises(
        release_ci_receipt.ReleaseCIReceiptError, match="duplicate JSON key"
    ):
        release_ci_receipt.parse_exact_ci_receipt_bytes(
            raw[:-2] + b',"schema_version":1}\n'
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("head_sha", "b" * 40),
        ("head_sha", "short"),
        ("head_branch", "release"),
        ("event", "workflow_dispatch"),
        ("event", "pull_request"),
        ("status", "in_progress"),
        ("status", "queued"),
        ("conclusion", "failure"),
        ("conclusion", "cancelled"),
        ("conclusion", None),
        ("path", ".github/workflows/docs.yml"),
        ("workflow_id", 0),
        ("run_attempt", False),
    ],
)
def test_rejects_wrong_or_malformed_run_correlation(
    tmp_path: Path, field: str, value: object
) -> None:
    documents = _documents()
    runs = documents[".github/workflows/test.yml"]["workflow_runs"]
    assert isinstance(runs, list)
    run = runs[0]
    assert isinstance(run, dict)
    run[field] = value
    completed = _invoke(tmp_path, documents)
    assert completed.returncode == 2
    assert "verify_release_ci:" in completed.stderr


@pytest.mark.parametrize("nested", ["repository", "head_repository"])
def test_rejects_wrong_repository_correlation(
    tmp_path: Path, nested: str
) -> None:
    documents = _documents()
    runs = documents[".github/workflows/test.yml"]["workflow_runs"]
    assert isinstance(runs, list)
    run = runs[0]
    assert isinstance(run, dict)
    run[nested] = {"full_name": "attacker/fork"}
    completed = _invoke(tmp_path, documents)
    assert completed.returncode == 2
    assert "canonical repository" in completed.stderr


def test_rejects_empty_or_count_mismatched_response(tmp_path: Path) -> None:
    documents = _documents()
    documents[".github/workflows/test.yml"] = {
        "total_count": 0,
        "workflow_runs": [],
    }
    empty = _invoke(tmp_path, documents)
    assert empty.returncode == 2
    assert "no successful exact-commit push run" in empty.stderr

    documents = _documents()
    documents[".github/workflows/test.yml"]["total_count"] = 2
    mismatch = _invoke(tmp_path, documents)
    assert mismatch.returncode == 2
    assert "truncated or count-mismatched" in mismatch.stderr


def test_rejects_duplicate_run_id_within_or_across_workflows(
    tmp_path: Path,
) -> None:
    documents = _documents()
    test_document = documents[".github/workflows/test.yml"]
    test_document["workflow_runs"] = [
        _run_record(".github/workflows/test.yml", 2),
        _run_record(".github/workflows/test.yml", 2),
    ]
    test_document["total_count"] = 2
    within = _invoke(tmp_path, documents)
    assert within.returncode == 2
    assert "duplicate workflow run id" in within.stderr

    documents = _documents()
    runs = documents[".github/workflows/test.yml"]["workflow_runs"]
    assert isinstance(runs, list)
    run = runs[0]
    assert isinstance(run, dict)
    run["id"] = 1
    across = _invoke(tmp_path, documents)
    assert across.returncode == 2
    assert "duplicate workflow run id" in across.stderr


def test_rejects_duplicate_json_key_and_non_object_root(tmp_path: Path) -> None:
    documents = _documents()
    duplicate = _invoke(
        tmp_path,
        documents,
        raw_overrides={
            ".github/workflows/test.yml": (
                '{"total_count":1,"total_count":1,"workflow_runs":[]}'
            )
        },
    )
    assert duplicate.returncode == 2
    assert "duplicate JSON key" in duplicate.stderr

    non_object = _invoke(
        tmp_path,
        documents,
        raw_overrides={".github/workflows/test.yml": "[]"},
    )
    assert non_object.returncode == 2
    assert "response root must be an object" in non_object.stderr


def test_rejects_noncanonical_invocation_and_incomplete_workflow_set(
    tmp_path: Path,
) -> None:
    documents = _documents()
    assert _invoke(
        tmp_path, documents, repository="attacker/fork"
    ).returncode == 2
    assert _invoke(tmp_path, documents, commit="A" * 40).returncode == 2
    assert _invoke(tmp_path, documents, branch="release").returncode == 2
    incomplete = _invoke(
        tmp_path,
        documents,
        workflow_order=(".github/workflows/test.yml",),
    )
    assert incomplete.returncode == 2
    assert "exactly" in incomplete.stderr
