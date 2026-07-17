"""Evidence-bounded codebase-memory receipt validation for AOI.

This module never starts codebase-memory, indexes a repository, or watches a
filesystem.  It validates an immutable provider receipt and, only when an
explicit AOI freshness profile is recorded, compares that receipt with the
current repository and provider artifacts.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, cast

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    canonicalize_no_link_traversal,
    task_dir,
)


RECEIPT_SCHEMA = "codebase-memory-arise-receipt/v1"
SOURCE_MANIFEST_SCHEMA = "codebase-memory-indexed-source-manifest/v1"
SUPPORTED_TOOL_VERSIONS = {"codebase-memory-mcp 0.9.0"}
FRESHNESS_PROFILES = {"receipt-only", "codebase-memory-git-v1"}
QUERY_EVIDENCE_CATEGORY = "engineering_inference"
PROVIDER_HEALTH_EVIDENCE_CATEGORY = "system_evidence"
STEWARD_AUTHORITY_BOUNDARY = (
    "Steward validates and summarizes provider health/freshness only; "
    "this binding is not a technical PASS"
)
STEWARD_BINDING_FIELDS = {
    "provider",
    "receipt_id",
    "receipt_sha256",
    "source_set_id",
    "requirement",
    "freshness_profile",
    "provider_health",
    "freshness",
    "health_findings",
    "freshness_findings",
    "query_evidence_category",
    "close_qualifying",
    "technical_verdict_authority",
    "authority_boundary",
}
RECEIPT_MAX_BYTES = 4 * 1024 * 1024
MANIFEST_MAX_FILES = 20_000
MANIFEST_MAX_DECLARED_BYTES = 8 * 1024 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 30
EXPECTED_EVIDENCE_CLASS = (
    "system_evidence_for_provider_health; "
    "engineering_inference_for_graph_results"
)
REQUIRED_COMPARISONS = {
    "project.head_sha",
    "project.branch",
    "project.indexed_scope_status_sha256",
    "source_manifest.source_set_id",
    "discovery_inputs.files[*].sha256",
    "tool.binary.sha256",
}
RECEIPT_RECORD_FIELDS = {
    "integrity_version",
    "record_version",
    "receipt_id",
    "provider",
    "requirement",
    "freshness_profile",
    "supersedes_receipt_id",
    "recorded_by_session_id",
    "source_path",
    "receipt_path",
    "receipt_sha256",
    "receipt_size_bytes",
    "receipt_schema",
    "project_name",
    "project_root",
    "branch",
    "head_sha",
    "indexed_scope",
    "source_set_id",
    "tool_version",
    "tool_binary_sha256",
    "graph_artifact_sha256",
    "store_db_sha256",
    "indexed_file_count",
    "nodes",
    "edges",
    "skipped_count",
    "degraded",
    "query_evidence_category",
    "close_qualifying",
    "provider_health_evidence_category",
    "technical_verdict_authority",
    "refresh_authority",
    "recorded_at",
    "record_sha256",
}


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise HarnessError(f"{label} must be an array")
    return value


def _text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise HarnessError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise HarnessError(f"{label} may not be empty")
    return value


def _sha256(value: Any, label: str) -> str:
    digest = _text(value, label).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise HarnessError(f"{label} must be a full SHA-256")
    return digest


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HarnessError(f"{label} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum:
        comparator = "positive" if positive else "non-negative"
        raise HarnessError(f"{label} must be {comparator}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise HarnessError(f"{label} must be true or false")
    return value


def _timestamp(value: Any, label: str) -> str:
    raw = _text(value, label)
    try:
        parsed = dt.datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError as exc:
        raise HarnessError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HarnessError(f"{label} must include a timezone")
    return raw


def _relative_path(value: Any, label: str) -> str:
    raw = _text(value, label)
    path = PurePosixPath(raw)
    if (
        "\\" in raw
        or path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise HarnessError(f"{label} must be a canonical project-relative POSIX path")
    return raw


def _absolute_path(value: Any, label: str) -> str:
    raw = _text(value, label)
    if not Path(raw).expanduser().is_absolute():
        raise HarnessError(f"{label} must be absolute")
    return raw


def _file_record(
    value: Any,
    label: str,
    *,
    relative: bool = False,
    allow_zero: bool = False,
) -> dict[str, Any]:
    record = _object(value, label)
    path = (
        _relative_path(record.get("path"), f"{label}.path")
        if relative
        else _absolute_path(record.get("path"), f"{label}.path")
    )
    size = _integer(record.get("size_bytes"), f"{label}.size_bytes")
    if not allow_zero and size == 0:
        raise HarnessError(f"{label}.size_bytes must be positive")
    digest = _sha256(record.get("sha256"), f"{label}.sha256")
    return {"path": path, "size_bytes": size, "sha256": digest}


def validate_receipt_payload(payload: Any) -> dict[str, Any]:
    """Validate the supported receipt schema and return the original object."""

    receipt = _object(payload, "codebase-memory receipt")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise HarnessError(
            f"codebase-memory receipt schema must be {RECEIPT_SCHEMA!r}"
        )
    _timestamp(receipt.get("created_at"), "codebase-memory receipt.created_at")
    if receipt.get("evidence_class") != EXPECTED_EVIDENCE_CLASS:
        raise HarnessError(
            "codebase-memory receipt must separate provider health from "
            "engineering_inference graph results"
        )

    project = _object(receipt.get("project"), "codebase-memory receipt.project")
    project_name = _text(project.get("name"), "codebase-memory receipt.project.name")
    project_root = _absolute_path(
        project.get("root"), "codebase-memory receipt.project.root"
    )
    _text(project.get("branch"), "codebase-memory receipt.project.branch")
    head_sha = _text(project.get("head_sha"), "codebase-memory receipt.project.head_sha")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head_sha):
        raise HarnessError("codebase-memory receipt.project.head_sha is invalid")
    _sha256(
        project.get("worktree_status_sha256"),
        "codebase-memory receipt.project.worktree_status_sha256",
    )
    _integer(
        project.get("worktree_status_entry_count"),
        "codebase-memory receipt.project.worktree_status_entry_count",
    )
    indexed_scope = _relative_path(
        project.get("indexed_scope"),
        "codebase-memory receipt.project.indexed_scope",
    )
    if (
        len(PurePosixPath(indexed_scope).parts) != 1
        or indexed_scope.startswith(":")
        or any(character in indexed_scope for character in "*?[]")
    ):
        raise HarnessError(
            "codebase-memory indexed scope must be one literal top-level directory"
        )
    _sha256(
        project.get("indexed_scope_status_sha256"),
        "codebase-memory receipt.project.indexed_scope_status_sha256",
    )
    _integer(
        project.get("indexed_scope_status_entry_count"),
        "codebase-memory receipt.project.indexed_scope_status_entry_count",
    )

    tool = _object(receipt.get("tool"), "codebase-memory receipt.tool")
    tool_version = _text(tool.get("version"), "codebase-memory receipt.tool.version")
    if tool_version not in SUPPORTED_TOOL_VERSIONS:
        raise HarnessError(
            "unsupported codebase-memory tool version: " + tool_version
        )
    _file_record(tool.get("binary"), "codebase-memory receipt.tool.binary")
    release = _text(
        tool.get("official_release"),
        "codebase-memory receipt.tool.official_release",
    )
    if not release.endswith("/releases/tag/v0.9.0"):
        raise HarnessError("codebase-memory receipt official release is not v0.9.0")
    _sha256(
        tool.get("release_archive_sha256"),
        "codebase-memory receipt.tool.release_archive_sha256",
    )

    runtime = _object(receipt.get("runtime"), "codebase-memory receipt.runtime")
    _absolute_path(runtime.get("cache_dir"), "codebase-memory receipt.runtime.cache_dir")
    allowed_root = _absolute_path(
        runtime.get("allowed_root"),
        "codebase-memory receipt.runtime.allowed_root",
    )
    if allowed_root != project_root:
        raise HarnessError("codebase-memory allowed_root differs from project.root")
    _integer(
        runtime.get("memory_budget_mb"),
        "codebase-memory receipt.runtime.memory_budget_mb",
        positive=True,
    )
    if _boolean(runtime.get("auto_index"), "codebase-memory receipt.runtime.auto_index"):
        raise HarnessError("codebase-memory Phase 1 requires auto_index=false")
    if _boolean(runtime.get("auto_watch"), "codebase-memory receipt.runtime.auto_watch"):
        raise HarnessError("codebase-memory Phase 1 requires auto_watch=false")
    _integer(
        runtime.get("auto_index_limit"),
        "codebase-memory receipt.runtime.auto_index_limit",
        positive=True,
    )
    index_command = _text(
        runtime.get("index_command"),
        "codebase-memory receipt.runtime.index_command",
    )
    if "index_repository" not in index_command:
        raise HarnessError("codebase-memory receipt lacks the exact refresh command")

    index = _object(receipt.get("index"), "codebase-memory receipt.index")
    _text(index.get("status"), "codebase-memory receipt.index.status")
    _integer(index.get("nodes"), "codebase-memory receipt.index.nodes")
    _integer(index.get("edges"), "codebase-memory receipt.index.edges")
    indexed_file_count = _integer(
        index.get("indexed_file_count"),
        "codebase-memory receipt.index.indexed_file_count",
    )
    _integer(
        index.get("skipped_count_observed"),
        "codebase-memory receipt.index.skipped_count_observed",
    )
    _boolean(
        index.get("degraded_observed"),
        "codebase-memory receipt.index.degraded_observed",
    )
    _file_record(index.get("store_db"), "codebase-memory receipt.index.store_db")
    _timestamp(
        index.get("store_db_mtime"),
        "codebase-memory receipt.index.store_db_mtime",
    )
    _file_record(index.get("config_db"), "codebase-memory receipt.index.config_db")
    _file_record(
        index.get("repo_artifact"), "codebase-memory receipt.index.repo_artifact"
    )
    _timestamp(
        index.get("repo_artifact_mtime"),
        "codebase-memory receipt.index.repo_artifact_mtime",
    )

    manifest = _object(
        receipt.get("source_manifest"), "codebase-memory receipt.source_manifest"
    )
    source_set_id = _sha256(
        manifest.get("source_set_id"),
        "codebase-memory receipt.source_manifest.source_set_id",
    )
    if manifest.get("schema") != SOURCE_MANIFEST_SCHEMA:
        raise HarnessError("unsupported codebase-memory source manifest schema")
    if manifest.get("project") != project_name or manifest.get("root") != project_root:
        raise HarnessError("codebase-memory source manifest project/root mismatch")
    files = _array(
        manifest.get("files"), "codebase-memory receipt.source_manifest.files"
    )
    if not files or len(files) > MANIFEST_MAX_FILES:
        raise HarnessError(
            f"codebase-memory source manifest must contain 1-{MANIFEST_MAX_FILES} files"
        )
    normalized_files: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    declared_bytes = 0
    for index_value, item in enumerate(files):
        record = _file_record(
            item,
            f"codebase-memory receipt.source_manifest.files[{index_value}]",
            relative=True,
            allow_zero=True,
        )
        if record["path"] in seen_paths:
            raise HarnessError(
                f"codebase-memory source manifest duplicates {record['path']!r}"
            )
        seen_paths.add(record["path"])
        declared_bytes += int(record["size_bytes"])
        if declared_bytes > MANIFEST_MAX_DECLARED_BYTES:
            raise HarnessError("codebase-memory source manifest declared size is excessive")
        normalized_files.append(record)
    if normalized_files != sorted(normalized_files, key=lambda item: item["path"]):
        raise HarnessError("codebase-memory source manifest files must be path-sorted")
    if indexed_file_count != len(normalized_files):
        raise HarnessError("codebase-memory indexed file count differs from manifest")
    manifest_preimage = {
        "schema": SOURCE_MANIFEST_SCHEMA,
        "project": project_name,
        "root": project_root,
        "files": normalized_files,
    }
    if canonical_json_sha256(manifest_preimage) != source_set_id:
        raise HarnessError("codebase-memory source_set_id does not match its manifest")

    discovery = _object(
        receipt.get("discovery_inputs"), "codebase-memory receipt.discovery_inputs"
    )
    _text(
        discovery.get("precedence_note"),
        "codebase-memory receipt.discovery_inputs.precedence_note",
    )
    discovery_files = _array(
        discovery.get("files"),
        "codebase-memory receipt.discovery_inputs.files",
    )
    discovery_paths: set[str] = set()
    for index_value, item in enumerate(discovery_files):
        record = _file_record(
            item,
            f"codebase-memory receipt.discovery_inputs.files[{index_value}]",
            relative=True,
            allow_zero=True,
        )
        if record["path"] in discovery_paths:
            raise HarnessError(
                f"codebase-memory discovery inputs duplicate {record['path']!r}"
            )
        discovery_paths.add(record["path"])
    if ".cbmignore" not in discovery_paths or ".git/info/exclude" not in discovery_paths:
        raise HarnessError("codebase-memory discovery inputs lack required ignore sources")
    for index_value, item in enumerate(
        _array(
            discovery.get("global_excludes"),
            "codebase-memory receipt.discovery_inputs.global_excludes",
        )
    ):
        label = f"codebase-memory receipt.discovery_inputs.global_excludes[{index_value}]"
        record = _object(item, label)
        _absolute_path(record.get("path"), f"{label}.path")
        if record.get("present") is False:
            if set(record) != {"path", "present"}:
                raise HarnessError(f"{label} absent record has unexpected fields")
        else:
            _file_record(record, label, allow_zero=True)

    client_configs = _object(
        receipt.get("client_configs"), "codebase-memory receipt.client_configs"
    )
    _file_record(
        client_configs.get("codex"), "codebase-memory receipt.client_configs.codex"
    )
    _file_record(
        client_configs.get("claude"), "codebase-memory receipt.client_configs.claude"
    )
    disabled_tools = _array(
        client_configs.get("codex_disabled_tools"),
        "codebase-memory receipt.client_configs.codex_disabled_tools",
    )
    if "index_repository" not in disabled_tools:
        raise HarnessError(
            "codebase-memory query client must disable index_repository in Phase 1"
        )

    freshness = _object(receipt.get("freshness"), "codebase-memory receipt.freshness")
    _integer(
        freshness.get("detect_changes_changed_count"),
        "codebase-memory receipt.freshness.detect_changes_changed_count",
    )
    if _boolean(
        freshness.get("detect_changes_is_authoritative_for_graph_freshness"),
        "codebase-memory receipt.freshness.detect_changes_is_authoritative_for_graph_freshness",
    ):
        raise HarnessError("detect_changes may not be authoritative for dirty-worktree freshness")
    _text(freshness.get("reason"), "codebase-memory receipt.freshness.reason")
    _text(
        freshness.get("worktree_status_note"),
        "codebase-memory receipt.freshness.worktree_status_note",
    )
    comparisons = {
        _text(item, "codebase-memory receipt.freshness.required_comparison entry")
        for item in _array(
            freshness.get("required_comparison"),
            "codebase-memory receipt.freshness.required_comparison",
        )
    }
    if not REQUIRED_COMPARISONS <= comparisons:
        missing = ", ".join(sorted(REQUIRED_COMPARISONS - comparisons))
        raise HarnessError(f"codebase-memory receipt lacks freshness comparisons: {missing}")

    boundary = _object(
        receipt.get("evidence_boundary"),
        "codebase-memory receipt.evidence_boundary",
    )
    _text(
        boundary.get("provider_health"),
        "codebase-memory receipt.evidence_boundary.provider_health",
    )
    graph_boundary = _text(
        boundary.get("graph_results"),
        "codebase-memory receipt.evidence_boundary.graph_results",
    ).lower()
    required_boundary_terms = {
        "engineering inference",
        "compile",
        "runtime",
        "numeric",
        "synthesis",
        "physical",
        "signoff",
    }
    if not all(term in graph_boundary for term in required_boundary_terms):
        raise HarnessError("codebase-memory graph evidence boundary is incomplete")
    scope_prefix = indexed_scope + "/"
    outside_scope = [
        item["path"]
        for item in normalized_files
        if not item["path"].startswith(scope_prefix)
    ]
    if outside_scope:
        # The adapter intentionally supports one literal top-level scope.  This
        # prevents a receipt from binding an unrelated status hash while hiding
        # out-of-scope files later in the sorted manifest.
        raise HarnessError(
            "codebase-memory indexed scope does not cover every manifest file: "
            + ", ".join(outside_scope[:8])
        )
    return receipt


def parse_receipt_bytes(data: bytes) -> dict[str, Any]:
    if not data or len(data) > RECEIPT_MAX_BYTES or b"\x00" in data:
        raise HarnessError(
            f"codebase-memory receipt must be non-empty UTF-8 JSON under {RECEIPT_MAX_BYTES} bytes"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"codebase-memory receipt is not valid UTF-8 JSON: {exc}") from exc
    return validate_receipt_payload(payload)


def receipt_summary(payload: dict[str, Any]) -> dict[str, Any]:
    project = payload["project"]
    tool = payload["tool"]
    index = payload["index"]
    manifest = payload["source_manifest"]
    return {
        "provider": "codebase-memory",
        "receipt_schema": payload["schema"],
        "project_name": project["name"],
        "project_root": project["root"],
        "branch": project["branch"],
        "head_sha": project["head_sha"].lower(),
        "indexed_scope": project["indexed_scope"],
        "source_set_id": manifest["source_set_id"],
        "tool_version": tool["version"],
        "tool_binary_sha256": tool["binary"]["sha256"],
        "graph_artifact_sha256": index["repo_artifact"]["sha256"],
        "store_db_sha256": index["store_db"]["sha256"],
        "indexed_file_count": index["indexed_file_count"],
        "nodes": index["nodes"],
        "edges": index["edges"],
        "skipped_count": index["skipped_count_observed"],
        "degraded": index["degraded_observed"],
        "query_evidence_category": QUERY_EVIDENCE_CATEGORY,
        "close_qualifying": False,
    }


def receipt_record_preimage(record: dict[str, Any]) -> dict[str, Any]:
    preimage = dict(record)
    preimage.pop("record_sha256", None)
    return preimage


def make_receipt_record(
    *,
    receipt_id: str,
    snapshot: dict[str, Any],
    payload: dict[str, Any],
    requirement: str,
    freshness_profile: str,
    supersedes_receipt_id: str,
    recorded_by_session_id: str,
    recorded_at: str,
) -> dict[str, Any]:
    if requirement not in {"optional", "required"}:
        raise HarnessError("codebase-memory receipt requirement is invalid")
    if freshness_profile not in FRESHNESS_PROFILES:
        raise HarnessError("unsupported codebase-memory freshness profile")
    record = {
        "integrity_version": 1,
        "record_version": 1,
        "receipt_id": receipt_id,
        "provider": "codebase-memory",
        "requirement": requirement,
        "freshness_profile": freshness_profile,
        "supersedes_receipt_id": supersedes_receipt_id,
        "recorded_by_session_id": recorded_by_session_id,
        "source_path": snapshot["source_path"],
        "receipt_path": snapshot["path"],
        "receipt_sha256": snapshot["sha256"],
        "receipt_size_bytes": snapshot["size_bytes"],
        **receipt_summary(payload),
        "provider_health_evidence_category": PROVIDER_HEALTH_EVIDENCE_CATEGORY,
        "technical_verdict_authority": "none",
        "refresh_authority": "external_unverified",
        "recorded_at": recorded_at,
    }
    record["record_sha256"] = canonical_json_sha256(receipt_record_preimage(record))
    return record


def validate_receipt_record(
    paths: HarnessPaths,
    state: dict[str, Any],
    record: Any,
) -> dict[str, Any]:
    value = _object(record, "codebase-memory receipt record")
    if set(value) != RECEIPT_RECORD_FIELDS:
        raise HarnessError("codebase-memory receipt record fields are invalid")
    if value.get("integrity_version") != 1 or value.get("record_version") != 1:
        raise HarnessError("codebase-memory receipt record version is invalid")
    receipt_id = _text(value.get("receipt_id"), "codebase-memory receipt id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", receipt_id):
        raise HarnessError("codebase-memory receipt id is invalid")
    if value.get("provider") != "codebase-memory":
        raise HarnessError("codebase-memory receipt record provider changed")
    if value.get("requirement") not in {"optional", "required"}:
        raise HarnessError("codebase-memory receipt record requirement is invalid")
    if value.get("freshness_profile") not in FRESHNESS_PROFILES:
        raise HarnessError("codebase-memory receipt record freshness profile is invalid")
    supersedes = value.get("supersedes_receipt_id")
    if not isinstance(supersedes, str):
        raise HarnessError("codebase-memory supersession id must be a string")
    expected_path = (
        task_dir(paths, state["task_id"])
        / "results"
        / f"codebase-memory-receipt-{receipt_id}.json"
    )
    if Path(str(value.get("receipt_path", ""))) != expected_path:
        raise HarnessError("codebase-memory receipt snapshot path is not canonical")
    if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("receipt_sha256", ""))):
        raise HarnessError("codebase-memory receipt snapshot SHA-256 is invalid")
    size = value.get("receipt_size_bytes")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= RECEIPT_MAX_BYTES:
        raise HarnessError("codebase-memory receipt snapshot size is invalid")
    source_path = Path(str(value.get("source_path", "")))
    if not source_path.is_absolute():
        raise HarnessError("codebase-memory receipt source path is not absolute")
    actual_size, actual_sha, data = _stable_regular_identity(
        expected_path,
        "codebase-memory receipt snapshot",
        max_bytes=RECEIPT_MAX_BYTES,
        capture=True,
    )
    if actual_size != size or actual_sha != value["receipt_sha256"]:
        raise HarnessError("codebase-memory receipt snapshot identity mismatch")
    assert data is not None
    payload = parse_receipt_bytes(data)
    expected_summary = receipt_summary(payload)
    for key, expected in expected_summary.items():
        if value.get(key) != expected:
            raise HarnessError(f"codebase-memory receipt record summary changed: {key}")
    if value.get("provider_health_evidence_category") != PROVIDER_HEALTH_EVIDENCE_CATEGORY:
        raise HarnessError("codebase-memory provider health evidence category changed")
    _text(
        value.get("recorded_by_session_id"),
        "codebase-memory receipt record.recorded_by_session_id",
    )
    if value.get("technical_verdict_authority") != "none":
        raise HarnessError("codebase-memory receipt gained technical verdict authority")
    if value.get("refresh_authority") != "external_unverified":
        raise HarnessError("codebase-memory imported receipt gained refresh authority")
    _timestamp(value.get("recorded_at"), "codebase-memory receipt record.recorded_at")
    if value.get("record_sha256") != canonical_json_sha256(
        receipt_record_preimage(value)
    ):
        raise HarnessError("codebase-memory receipt record integrity mismatch")
    return payload


def active_receipt_records(state: dict[str, Any]) -> list[dict[str, Any]]:
    records = [
        record
        for record in state.get("context_provider_receipts", [])
        if isinstance(record, dict)
    ]
    superseded = {
        str(record.get("supersedes_receipt_id", ""))
        for record in records
        if record.get("supersedes_receipt_id")
    }
    return [record for record in records if str(record.get("receipt_id", "")) not in superseded]


def receipt_chain_errors(state: dict[str, Any]) -> list[str]:
    records = state.get("context_provider_receipts", [])
    ids = [str(record.get("receipt_id", "")) for record in records if isinstance(record, dict)]
    errors: list[str] = []
    if any(not isinstance(record, dict) for record in records):
        errors.append("codebase-memory receipt chain contains a malformed entry")
    if len(ids) != len(set(ids)):
        errors.append("codebase-memory receipt ids are duplicated")
    known: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        receipt_id = str(record.get("receipt_id", ""))
        supersedes = str(record.get("supersedes_receipt_id", ""))
        if supersedes:
            if supersedes not in known:
                errors.append(
                    f"codebase-memory receipt {receipt_id} supersedes a missing or non-prior receipt"
                )
            if supersedes == receipt_id:
                errors.append(f"codebase-memory receipt {receipt_id} supersedes itself")
        known.add(receipt_id)
    active = active_receipt_records(state)
    if len(active) > 1:
        errors.append("codebase-memory has more than one active receipt")
    return errors


def _git(root: Path, arguments: list[str], *, raw: bool = False) -> bytes | str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"Git freshness probe failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise HarnessError(f"Git freshness probe failed: {detail or completed.returncode}")
    return completed.stdout if raw else completed.stdout.decode("utf-8", "replace").strip()


def _stable_regular_identity(
    path: Path,
    label: str,
    *,
    max_bytes: int | None = None,
    capture: bool = False,
) -> tuple[int, str, bytes | None]:
    """Hash one pinned regular file without following a replacement link."""

    canonical = canonicalize_no_link_traversal(path, label)
    try:
        before = os.lstat(canonical)
    except OSError as exc:
        raise HarnessError(f"{label} is missing or unreadable: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise HarnessError(f"{label} must be a regular non-symlink file")
    if before.st_nlink != 1:
        raise HarnessError(f"{label} must not be hard-linked")
    if max_bytes is not None and (before.st_size <= 0 or before.st_size > max_bytes):
        raise HarnessError(f"{label} is outside its allowed size bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(canonical, flags)
    except OSError as exc:
        raise HarnessError(f"{label} could not be opened safely: {exc}") from exc
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise HarnessError(f"{label} changed while it was being opened")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(canonical)
    except OSError as exc:
        raise HarnessError(f"{label} changed while it was hashed: {exc}") from exc
    if (
        finished.st_dev != opened.st_dev
        or finished.st_ino != opened.st_ino
        or finished.st_size != opened.st_size
        or getattr(finished, "st_mtime_ns", None)
        != getattr(opened, "st_mtime_ns", None)
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
    ):
        raise HarnessError(f"{label} changed while it was hashed")
    return int(after.st_size), digest.hexdigest(), b"".join(chunks) if capture else None


def _compare_live_file(
    path: Path,
    expected: dict[str, Any],
    label: str,
    findings: list[dict[str, str]],
) -> None:
    try:
        size, digest, _data = _stable_regular_identity(path, label)
    except HarnessError as exc:
        findings.append({"code": "unavailable", "detail": str(exc)})
        return
    if size != expected["size_bytes"] or digest != expected["sha256"]:
        findings.append(
            {
                "code": "mismatch",
                "detail": f"{label} no longer matches the indexed receipt",
            }
        )


def evaluate_live_receipt(
    payload: dict[str, Any],
    *,
    freshness_profile: str,
    project_root: str,
) -> dict[str, Any]:
    """Return provider health and freshness without invoking the provider."""

    if freshness_profile not in FRESHNESS_PROFILES:
        raise HarnessError("unsupported codebase-memory freshness profile")
    project = payload["project"]
    index = payload["index"]
    health_findings: list[dict[str, str]] = []
    freshness_findings: list[dict[str, str]] = []
    diagnostics: list[dict[str, str]] = []

    if index["status"] != "ready":
        health_findings.append(
            {"code": "index_not_ready", "detail": f"receipt index status is {index['status']!r}"}
        )
    if index["degraded_observed"]:
        health_findings.append(
            {"code": "degraded", "detail": "receipt reports degraded indexing"}
        )
    if index["skipped_count_observed"]:
        health_findings.append(
            {
                "code": "skipped_files",
                "detail": f"receipt reports {index['skipped_count_observed']} skipped files",
            }
        )

    root = Path(project_root).expanduser()
    if not root.is_absolute() or str(root) != project["root"]:
        freshness_findings.append(
            {
                "code": "root_mismatch",
                "detail": "recorded project root differs from receipt project.root",
            }
        )
    try:
        canonical_root = canonicalize_no_link_traversal(root, "codebase-memory project root")
        if not canonical_root.is_dir():
            raise HarnessError("codebase-memory project root is not a directory")
    except (HarnessError, OSError) as exc:
        return {
            "provider": "codebase-memory",
            "provider_health": "unavailable",
            "freshness": "unverifiable",
            "freshness_profile": freshness_profile,
            "health_findings": [
                {"code": "project_unavailable", "detail": str(exc)}
            ],
            "freshness_findings": freshness_findings,
            "diagnostics": diagnostics,
            "query_evidence_category": QUERY_EVIDENCE_CATEGORY,
            "close_qualifying": False,
        }

    for label, record in (
        ("codebase-memory tool binary", payload["tool"]["binary"]),
        ("codebase-memory graph artifact", index["repo_artifact"]),
        ("codebase-memory store database", index["store_db"]),
        ("codebase-memory config database", index["config_db"]),
        ("codebase-memory Codex client config", payload["client_configs"]["codex"]),
        ("codebase-memory Claude client config", payload["client_configs"]["claude"]),
    ):
        before = len(health_findings)
        _compare_live_file(Path(record["path"]), record, label, health_findings)
        for finding in health_findings[before:]:
            if finding["code"] == "mismatch":
                finding["code"] = "provider_identity_mismatch"

    if freshness_profile == "receipt-only":
        freshness_findings.append(
            {
                "code": "profile_unverifiable",
                "detail": (
                    "receipt does not self-describe the canonical Git/status hashing "
                    "algorithm; record codebase-memory-git-v1 explicitly to verify freshness"
                ),
            }
        )
    else:
        try:
            branch = str(_git(canonical_root, ["branch", "--show-current"]))
            head = str(_git(canonical_root, ["rev-parse", "HEAD"])).lower()
            whole_status = bytes(
                cast(
                    bytes,
                    _git(
                        canonical_root,
                        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
                        raw=True,
                    ),
                )
            )
            scope_status = bytes(
                cast(
                    bytes,
                    _git(
                        canonical_root,
                        [
                            "status",
                            "--porcelain=v1",
                            "-z",
                            "--untracked-files=all",
                            "--",
                            project["indexed_scope"],
                        ],
                        raw=True,
                    ),
                )
            )
        except HarnessError as exc:
            freshness_findings.append({"code": "git_unavailable", "detail": str(exc)})
        else:
            if branch != project["branch"]:
                freshness_findings.append(
                    {"code": "branch_mismatch", "detail": "Git branch differs from receipt"}
                )
            if head != project["head_sha"].lower():
                freshness_findings.append(
                    {"code": "head_mismatch", "detail": "Git HEAD differs from receipt"}
                )
            if hashlib.sha256(scope_status).hexdigest() != project[
                "indexed_scope_status_sha256"
            ]:
                freshness_findings.append(
                    {
                        "code": "indexed_scope_status_mismatch",
                        "detail": "indexed-scope Git status differs from receipt",
                    }
                )
            whole_digest = hashlib.sha256(whole_status).hexdigest()
            if whole_digest != project["worktree_status_sha256"]:
                diagnostics.append(
                    {
                        "code": "whole_worktree_changed",
                        "detail": (
                            "whole-worktree status differs outside or inside the indexed "
                            "scope; this diagnostic alone does not make the graph stale"
                        ),
                    }
                )

        for item in payload["source_manifest"]["files"]:
            _compare_live_file(
                canonical_root / PurePosixPath(item["path"]),
                item,
                f"indexed source {item['path']}",
                freshness_findings,
            )
        for item in payload["discovery_inputs"]["files"]:
            _compare_live_file(
                canonical_root / PurePosixPath(item["path"]),
                item,
                f"discovery input {item['path']}",
                freshness_findings,
            )
        for item in payload["discovery_inputs"]["global_excludes"]:
            path = Path(item["path"])
            if item.get("present") is False:
                if path.exists():
                    freshness_findings.append(
                        {
                            "code": "global_exclude_appeared",
                            "detail": f"global Git exclude appeared: {path}",
                        }
                    )
            else:
                _compare_live_file(
                    path,
                    item,
                    f"global discovery input {path}",
                    freshness_findings,
                )

    unavailable_health = any(
        item["code"] == "unavailable" for item in health_findings
    )
    provider_health = (
        "unavailable"
        if unavailable_health
        else "degraded"
        if health_findings
        else "healthy"
    )
    if freshness_profile == "receipt-only" or any(
        item["code"] in {"git_unavailable", "unavailable"}
        for item in freshness_findings
    ):
        freshness = "unverifiable"
    elif freshness_findings:
        freshness = "stale"
    else:
        freshness = "fresh"
    return {
        "provider": "codebase-memory",
        "provider_health": provider_health,
        "freshness": freshness,
        "freshness_profile": freshness_profile,
        "health_findings": health_findings,
        "freshness_findings": freshness_findings,
        "diagnostics": diagnostics,
        "query_evidence_category": QUERY_EVIDENCE_CATEGORY,
        "close_qualifying": False,
    }


def steward_binding(record: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Build the bounded provider-health section of a Steward brief."""

    return {
        "provider": "codebase-memory",
        "receipt_id": record["receipt_id"],
        "receipt_sha256": record["receipt_sha256"],
        "source_set_id": record["source_set_id"],
        "requirement": record["requirement"],
        "freshness_profile": record["freshness_profile"],
        "provider_health": report["provider_health"],
        "freshness": report["freshness"],
        "health_findings": report["health_findings"],
        "freshness_findings": report["freshness_findings"],
        "query_evidence_category": QUERY_EVIDENCE_CATEGORY,
        "close_qualifying": False,
        "technical_verdict_authority": "none",
        "authority_boundary": STEWARD_AUTHORITY_BOUNDARY,
    }


def _validate_steward_findings(value: Any, label: str) -> None:
    findings = _array(value, label)
    for index, finding in enumerate(findings):
        item = _object(finding, f"{label}[{index}]")
        if set(item) != {"code", "detail"}:
            raise HarnessError(f"{label}[{index}] fields are invalid")
        _text(item.get("code"), f"{label}[{index}].code")
        _text(item.get("detail"), f"{label}[{index}].detail")


def validate_steward_binding(
    record: dict[str, Any], binding: Any
) -> dict[str, Any]:
    """Validate one brief binding against its exact receipt authority."""

    value = _object(binding, "codebase-memory Steward binding")
    if set(value) != STEWARD_BINDING_FIELDS:
        raise HarnessError("codebase-memory Steward binding fields are invalid")
    expected = {
        "provider": "codebase-memory",
        "receipt_id": record.get("receipt_id"),
        "receipt_sha256": record.get("receipt_sha256"),
        "source_set_id": record.get("source_set_id"),
        "requirement": record.get("requirement"),
        "freshness_profile": record.get("freshness_profile"),
        "query_evidence_category": QUERY_EVIDENCE_CATEGORY,
        "close_qualifying": False,
        "technical_verdict_authority": "none",
        "authority_boundary": STEWARD_AUTHORITY_BOUNDARY,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise HarnessError("codebase-memory Steward binding authority changed")
    if value.get("provider_health") not in {"healthy", "degraded", "unavailable"}:
        raise HarnessError("codebase-memory Steward provider health is invalid")
    if value.get("freshness") not in {"fresh", "stale", "unverifiable"}:
        raise HarnessError("codebase-memory Steward freshness is invalid")
    _validate_steward_findings(
        value.get("health_findings"), "codebase-memory Steward health findings"
    )
    _validate_steward_findings(
        value.get("freshness_findings"),
        "codebase-memory Steward freshness findings",
    )
    return value


def validate_steward_binding_set(
    state: dict[str, Any], bindings: Any
) -> list[dict[str, Any]]:
    """Require a brief to bind exactly the currently active receipt set."""

    chain_errors = receipt_chain_errors(state)
    if chain_errors:
        raise HarnessError("codebase-memory receipt chain is invalid: " + "; ".join(chain_errors))
    values = _array(bindings, "codebase-memory Steward bindings")
    active = active_receipt_records(state)
    expected_ids = [str(record.get("receipt_id", "")) for record in active]
    actual_ids = [
        str(binding.get("receipt_id", "")) if isinstance(binding, dict) else ""
        for binding in values
    ]
    if actual_ids != expected_ids:
        raise HarnessError(
            "codebase-memory Steward bindings do not match the active receipt set"
        )
    return [
        validate_steward_binding(record, binding)
        for record, binding in zip(active, values, strict=True)
    ]
