#!/usr/bin/env python3
"""Receipt, doctor, Steward-boundary, and navigation A/B tests."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import codebase_memory as cbm  # noqa: E402
from aoi_orgware import codebase_memory_benchmark as bench  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


CLI_MODULE = "aoi_orgware.cli"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, display_path: str | None = None) -> dict[str, object]:
    return {
        "path": display_path or str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def git(root: Path, *arguments: str, raw: bool = False) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout if raw else result.stdout.decode("utf-8").strip()


def build_receipt(base: Path) -> tuple[Path, dict[str, object], Path]:
    root = base / "context-project"
    root.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "-b", "main", str(root)],
        check=True,
        capture_output=True,
    )
    git(root, "config", "user.name", "Context Test")
    git(root, "config", "user.email", "context@test.invalid")
    (root / "rtl").mkdir()
    (root / "rtl" / "top.sv").write_text(
        "module top(input logic clk); endmodule\n", encoding="utf-8"
    )
    (root / ".cbmignore").write_text("!rtl/**\n", encoding="utf-8")
    (root / ".gitignore").write_text(".codebase-memory/\n", encoding="utf-8")
    (root / ".git" / "info" / "exclude").write_text(
        ".aoi/\n", encoding="utf-8"
    )
    git(root, "add", "rtl/top.sv", ".cbmignore", ".gitignore")
    git(root, "commit", "-m", "context baseline")

    graph_dir = root / ".codebase-memory"
    graph_dir.mkdir()
    graph_artifact = graph_dir / "graph.db.zst"
    graph_artifact.write_bytes(b"graph-artifact-v1\n")
    provider = base / "provider"
    provider.mkdir()
    binary = provider / "codebase-memory-mcp"
    binary.write_bytes(b"codebase-memory-mcp-v0.9.0\n")
    store_db = provider / "context.db"
    store_db.write_bytes(b"store-db-v1\n")
    config_db = provider / "_config.db"
    config_db.write_bytes(b"config-db-v1\n")
    codex_config = provider / "codex.toml"
    codex_config.write_text("disabled_tools = [\"index_repository\"]\n", encoding="utf-8")
    claude_config = provider / "claude.json"
    claude_config.write_text("{}\n", encoding="utf-8")

    indexed_files = [file_record(root / "rtl" / "top.sv", "rtl/top.sv")]
    manifest_payload = {
        "schema": cbm.SOURCE_MANIFEST_SCHEMA,
        "project": "fixture",
        "root": str(root),
        "files": indexed_files,
    }
    source_set_id = cbm.canonical_json_sha256(manifest_payload)
    whole_status = git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        raw=True,
    )
    scope_status = git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        "rtl",
        raw=True,
    )
    assert isinstance(whole_status, bytes)
    assert isinstance(scope_status, bytes)
    now = dt.datetime.now(tz=dt.timezone.utc).isoformat()
    receipt: dict[str, object] = {
        "schema": cbm.RECEIPT_SCHEMA,
        "created_at": now,
        "evidence_class": cbm.EXPECTED_EVIDENCE_CLASS,
        "project": {
            "name": "fixture",
            "root": str(root),
            "branch": git(root, "branch", "--show-current"),
            "head_sha": git(root, "rev-parse", "HEAD"),
            "worktree_status_sha256": hashlib.sha256(whole_status).hexdigest(),
            "worktree_status_entry_count": len(
                [item for item in whole_status.split(b"\0") if item]
            ),
            "indexed_scope": "rtl",
            "indexed_scope_status_sha256": hashlib.sha256(scope_status).hexdigest(),
            "indexed_scope_status_entry_count": len(
                [item for item in scope_status.split(b"\0") if item]
            ),
        },
        "tool": {
            "version": "codebase-memory-mcp 0.9.0",
            "binary": file_record(binary),
            "official_release": (
                "https://github.com/DeusData/codebase-memory-mcp/releases/tag/v0.9.0"
            ),
            "release_archive_sha256": "a" * 64,
        },
        "runtime": {
            "cache_dir": str(provider),
            "allowed_root": str(root),
            "memory_budget_mb": 4096,
            "auto_index": False,
            "auto_watch": False,
            "auto_index_limit": 50_000,
            "index_command": (
                f"env CBM_ALLOWED_ROOT={root} {binary} cli index_repository "
                f"--repo-path {root} --name fixture --mode full --persistence true"
            ),
        },
        "index": {
            "status": "ready",
            "nodes": 2,
            "edges": 1,
            "indexed_file_count": 1,
            "skipped_count_observed": 0,
            "degraded_observed": False,
            "store_db": file_record(store_db),
            "store_db_mtime": now,
            "config_db": file_record(config_db),
            "repo_artifact": file_record(graph_artifact),
            "repo_artifact_mtime": now,
        },
        "source_manifest": {
            "source_set_id": source_set_id,
            **manifest_payload,
        },
        "discovery_inputs": {
            "precedence_note": (
                ".git/info/exclude and Git ignore rules apply before .cbmignore"
            ),
            "files": [
                file_record(root / ".cbmignore", ".cbmignore"),
                file_record(root / ".git" / "info" / "exclude", ".git/info/exclude"),
                file_record(root / ".gitignore", ".gitignore"),
            ],
            "global_excludes": [
                {"path": str(base / "absent-global-ignore"), "present": False}
            ],
        },
        "client_configs": {
            "codex": file_record(codex_config),
            "claude": file_record(claude_config),
            "codex_disabled_tools": ["index_repository"],
        },
        "freshness": {
            "detect_changes_changed_count": 0,
            "detect_changes_is_authoritative_for_graph_freshness": False,
            "reason": "Git changes are not a graph-snapshot comparison.",
            "worktree_status_note": (
                "Whole status is diagnostic; indexed scope and manifest are authoritative."
            ),
            "required_comparison": sorted(cbm.REQUIRED_COMPARISONS),
        },
        "evidence_boundary": {
            "provider_health": "Checksums and index metadata establish provider health only.",
            "graph_results": (
                "Navigation and engineering inference only; never compile, runtime, "
                "numeric, synthesis, physical, or signoff evidence."
            ),
        },
    }
    receipt_path = base / "receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return receipt_path, receipt, root


def measured(value: int | float, source: str) -> dict[str, object]:
    return {"value": value, "source": source, "missing_reason": ""}


def unavailable(reason: str) -> dict[str, object]:
    return {"value": None, "source": "unavailable", "missing_reason": reason}


def benchmark_record(
    variant: str,
    *,
    receipt_sha256: str,
    source_set_id: str,
    run_id: str,
) -> dict[str, object]:
    baseline = variant == "rg_open"
    graph_metric = unavailable("not_applicable") if baseline else measured(1, "tool_trace")
    graph_zero = unavailable("not_applicable") if baseline else measured(0, "tool_trace")
    started = "2026-07-14T00:00:00+00:00"
    ended = "2026-07-14T00:00:01+00:00"
    return {
        "schema_version": 1,
        "protocol_version": bench.PROTOCOL_VERSION,
        "analysis_boundary": bench.ANALYSIS_BOUNDARY,
        "evidence_class": bench.EVIDENCE_CLASS,
        "run_id": run_id,
        "case_pair_id": "pair-001",
        "case_id": "case-001",
        "case_order": 1,
        "variant": variant,
        "run_status": "completed",
        "started_at": started,
        "ended_at": ended,
        "controls": {
            "runtime_label": "test-runtime",
            "model_label": "test-model",
            "shared_control_profile_sha256": "1" * 64,
            "variant_tool_profile_sha256": ("2" if baseline else "3") * 64,
            "benchmark_package_sha256": "4" * 64,
            "corpus_sha256": "5" * 64,
            "oracle_manifest_sha256": "6" * 64,
            "assignment_sha256": "7" * 64,
            "provider_receipt_sha256": receipt_sha256,
            "source_set_id": source_set_id,
            "time_limit_seconds": 300,
        },
        "freshness": {
            "profile": "codebase-memory-git-v1",
            "status": "fresh",
            "checked_at": started,
            "validator_version": "AOI test",
            "check_artifact_sha256": "8" * 64,
            "mismatch_count": 0,
        },
        "navigation_oracle": {
            "pre_registered": True,
            "oracle_id": "oracle-001",
            "status": "matched",
        },
        "trace": {
            "sha256": "9" * 64,
            "event_count": 3,
            "graph_query_calls": 0 if baseline else 1,
            "rg_calls": 1 if baseline else 0,
            "open_calls": 1,
            "mutating_provider_calls": 0,
        },
        "metrics": {
            "time_to_first_relevant_ms": measured(
                800 if baseline else 400, "runner_monotonic"
            ),
            "time_to_final_answer_ms": measured(
                1000 if baseline else 600, "runner_monotonic"
            ),
            "wrong_paths_before_first_relevant": measured(
                1 if baseline else 0, "tool_trace"
            ),
            "first_relevant_rank": measured(2 if baseline else 1, "navigation_oracle"),
            "checked_graph_results": graph_metric,
            "stale_graph_results": graph_zero,
            "uncheckable_graph_results": graph_zero,
            "fallback_episodes": graph_zero,
            "fallback_tool_calls": graph_zero,
            "input_tokens": unavailable("provider_not_exposed"),
            "output_tokens": unavailable("provider_not_exposed"),
            "provider_cost_usd": unavailable("provider_not_exposed"),
        },
    }


class ReceiptUnitTests(unittest.TestCase):
    def test_explicit_profile_verifies_and_detects_staleness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path, receipt, root = build_receipt(Path(directory))
            parsed = cbm.parse_receipt_bytes(receipt_path.read_bytes())
            self.assertEqual(parsed["source_manifest"]["source_set_id"], receipt["source_manifest"]["source_set_id"])
            receipt_only = cbm.evaluate_live_receipt(
                parsed,
                freshness_profile="receipt-only",
                project_root=str(root),
            )
            self.assertEqual(receipt_only["freshness"], "unverifiable")
            live = cbm.evaluate_live_receipt(
                parsed,
                freshness_profile="codebase-memory-git-v1",
                project_root=str(root),
            )
            self.assertEqual(live["provider_health"], "healthy")
            self.assertEqual(live["freshness"], "fresh")
            codex_config = Path(receipt["client_configs"]["codex"]["path"])
            original_config = codex_config.read_bytes()
            codex_config.write_text("disabled_tools = []\n", encoding="utf-8")
            config_drift = cbm.evaluate_live_receipt(
                parsed,
                freshness_profile="codebase-memory-git-v1",
                project_root=str(root),
            )
            self.assertEqual(config_drift["provider_health"], "degraded")
            self.assertEqual(config_drift["freshness"], "fresh")
            self.assertTrue(
                any(
                    item["code"] == "provider_identity_mismatch"
                    and "Codex client config" in item["detail"]
                    for item in config_drift["health_findings"]
                )
            )
            codex_config.write_bytes(original_config)
            (root / "rtl" / "top.sv").write_text("module changed; endmodule\n", encoding="utf-8")
            stale = cbm.evaluate_live_receipt(
                parsed,
                freshness_profile="codebase-memory-git-v1",
                project_root=str(root),
            )
            self.assertEqual(stale["freshness"], "stale")
            self.assertTrue(
                any(item["code"] == "indexed_scope_status_mismatch" for item in stale["freshness_findings"])
            )

    def test_receipt_rejects_unsafe_automation_and_evidence_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _path, receipt, root = build_receipt(Path(directory))
            watched = copy.deepcopy(receipt)
            watched["runtime"]["auto_watch"] = True
            with self.assertRaisesRegex(HarnessError, "auto_watch=false"):
                cbm.validate_receipt_payload(watched)
            promoted = copy.deepcopy(receipt)
            promoted["evidence_class"] = "system_evidence"
            with self.assertRaisesRegex(HarnessError, "separate provider health"):
                cbm.validate_receipt_payload(promoted)
            damaged = copy.deepcopy(receipt)
            damaged["source_manifest"]["source_set_id"] = "f" * 64
            with self.assertRaisesRegex(HarnessError, "source_set_id"):
                cbm.validate_receipt_payload(damaged)

            (root / "tb").mkdir()
            (root / "tb" / "outside.sv").write_text(
                "module outside; endmodule\n", encoding="utf-8"
            )
            outside_scope = copy.deepcopy(receipt)
            outside_scope["source_manifest"]["files"].append(
                file_record(root / "tb" / "outside.sv", "tb/outside.sv")
            )
            outside_scope["source_manifest"]["files"].sort(
                key=lambda item: item["path"]
            )
            outside_scope["index"]["indexed_file_count"] = 2
            outside_scope["source_manifest"]["source_set_id"] = (
                cbm.canonical_json_sha256(
                    {
                        "schema": cbm.SOURCE_MANIFEST_SCHEMA,
                        "project": "fixture",
                        "root": str(root),
                        "files": outside_scope["source_manifest"]["files"],
                    }
                )
            )
            with self.assertRaisesRegex(HarnessError, "every manifest file"):
                cbm.validate_receipt_payload(outside_scope)

    def test_steward_binding_is_exact_and_tracks_the_active_receipt(self) -> None:
        record = {
            "receipt_id": "fixture-v1",
            "receipt_sha256": "a" * 64,
            "source_set_id": "b" * 64,
            "requirement": "optional",
            "freshness_profile": "codebase-memory-git-v1",
            "supersedes_receipt_id": "",
        }
        report = {
            "provider_health": "healthy",
            "freshness": "fresh",
            "health_findings": [],
            "freshness_findings": [],
        }
        binding = cbm.steward_binding(record, report)
        self.assertEqual(binding["technical_verdict_authority"], "none")
        cbm.validate_steward_binding_set(
            {"context_provider_receipts": [record]}, [binding]
        )
        missing_authority = copy.deepcopy(binding)
        missing_authority.pop("technical_verdict_authority")
        with self.assertRaisesRegex(HarnessError, "fields are invalid"):
            cbm.validate_steward_binding_set(
                {"context_provider_receipts": [record]}, [missing_authority]
            )
        replacement = {
            **record,
            "receipt_id": "fixture-v2",
            "receipt_sha256": "c" * 64,
            "source_set_id": "d" * 64,
            "supersedes_receipt_id": "fixture-v1",
        }
        with self.assertRaisesRegex(HarnessError, "active receipt set"):
            cbm.validate_steward_binding_set(
                {"context_provider_receipts": [record, replacement]}, [binding]
            )


class BenchmarkUnitTests(unittest.TestCase):
    def test_strict_pair_summary_is_navigation_inference_only(self) -> None:
        baseline = benchmark_record(
            "rg_open", receipt_sha256="a" * 64, source_set_id="b" * 64, run_id="run-a"
        )
        graph = benchmark_record(
            "codebase_memory_assisted",
            receipt_sha256="a" * 64,
            source_set_id="b" * 64,
            run_id="run-b",
        )
        summary = bench.summarize_records(
            [graph, baseline], generated_at="2026-07-14T01:00:00+00:00"
        )
        self.assertEqual(summary["evidence_class"], "engineering_inference")
        self.assertFalse(summary["close_qualifying"])
        self.assertEqual(summary["pair_count"], 1)
        self.assertEqual(
            summary["paired_differences"]["time_to_final_answer_ms"][
                "graph_minus_rg_open_mean"
            ],
            -400.0,
        )
        self.assertEqual(
            summary["graph_diagnostics"]["stale_graph_result_count"]["value"],
            0.0,
        )

    def test_benchmark_rejects_graph_mutation_nonfresh_query_and_fake_missing_zero(self) -> None:
        baseline = benchmark_record(
            "rg_open", receipt_sha256="a" * 64, source_set_id="b" * 64, run_id="run-a"
        )
        baseline["trace"]["graph_query_calls"] = 1
        with self.assertRaisesRegex(HarnessError, "baseline may not query"):
            bench.validate_record(baseline)
        graph = benchmark_record(
            "codebase_memory_assisted",
            receipt_sha256="a" * 64,
            source_set_id="b" * 64,
            run_id="run-b",
        )
        graph["freshness"]["status"] = "stale"
        graph["freshness"]["mismatch_count"] = 1
        with self.assertRaisesRegex(HarnessError, "fail open"):
            bench.validate_record(graph)
        graph = benchmark_record(
            "codebase_memory_assisted",
            receipt_sha256="a" * 64,
            source_set_id="b" * 64,
            run_id="run-c",
        )
        graph["metrics"]["input_tokens"] = {
            "value": 0,
            "source": "unavailable",
            "missing_reason": "provider_not_exposed",
        }
        with self.assertRaisesRegex(HarnessError, "measured values"):
            bench.validate_record(graph)

    def test_benchmark_rejects_impossible_trace_and_fail_open_claims(self) -> None:
        graph = benchmark_record(
            "codebase_memory_assisted",
            receipt_sha256="a" * 64,
            source_set_id="b" * 64,
            run_id="run-impossible",
        )
        graph["freshness"]["status"] = "stale"
        graph["freshness"]["mismatch_count"] = 1
        graph["trace"].update(
            {
                "event_count": 0,
                "graph_query_calls": 0,
                "rg_calls": 0,
                "open_calls": 0,
            }
        )
        for name in (
            "checked_graph_results",
            "stale_graph_results",
            "uncheckable_graph_results",
            "fallback_episodes",
            "fallback_tool_calls",
        ):
            graph["metrics"][name] = measured(0, "tool_trace")
        with self.assertRaisesRegex(HarnessError, "fail-open fallback"):
            bench.validate_record(graph)

        latency = benchmark_record(
            "codebase_memory_assisted",
            receipt_sha256="a" * 64,
            source_set_id="b" * 64,
            run_id="run-latency",
        )
        latency["metrics"]["time_to_first_relevant_ms"] = measured(
            900, "runner_monotonic"
        )
        latency["metrics"]["time_to_final_answer_ms"] = measured(
            800, "runner_monotonic"
        )
        with self.assertRaisesRegex(HarnessError, "precedes first-relevant"):
            bench.validate_record(latency)

        trace = benchmark_record(
            "codebase_memory_assisted",
            receipt_sha256="a" * 64,
            source_set_id="b" * 64,
            run_id="run-trace",
        )
        trace["trace"]["event_count"] = 1
        with self.assertRaisesRegex(HarnessError, "below its recorded tool calls"):
            bench.validate_record(trace)


class CliIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.backup = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "aoi-project"
        self.root.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            {
                "AOI_ROOT": str(self.root),
                "PYTHONPATH": str(SRC),
                "PYTHONDONTWRITEBYTECODE": "1",
                "HOME": str(self.base / "home"),
                "XDG_CONFIG_HOME": str(self.base / "xdg"),
                "AOI_BACKUP_ROOT": self.backup.name,
                "AOI_CHIEF_CREDENTIAL_HOME": str(Path(self.backup.name) / "credentials"),
            }
        )
        subprocess.run(
            ["git", "init", "-b", "main", str(self.root)],
            check=True,
            capture_output=True,
        )
        git(self.root, "config", "user.name", "AOI Test")
        git(self.root, "config", "user.email", "aoi@test.invalid")
        (self.root / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        git(self.root, "add", "tracked.txt")
        git(self.root, "commit", "-m", "baseline")
        self.cli("init", "--project-name", "Context Integration Test")
        authority = json.loads(
            self.cli("chief-acquire", "--session-id", "chief-test", "--json").stdout
        )
        self.env["AOI_CHIEF_SESSION_ID"] = "chief-test"
        self.env["AOI_CHIEF_EPOCH"] = str(authority["authority"]["epoch"])
        self.env["AOI_CHIEF_CREDENTIAL_FILE"] = authority["credential_file"]
        git(self.root, "add", "aoi.toml", ".gitignore")
        git(self.root, "commit", "-m", "initialize AOI")
        self.cli(
            "init-task",
            "--task-id",
            "context-task",
            "--title",
            "Context task",
            "--objective",
            "Exercise context receipt integration",
            "--owner",
            "chief-test",
            "--completion-boundary",
            "Receipt and benchmark behavior is verified",
            "--session-id",
            "root-session",
        )
        self.cli(
            "approve-plan",
            "--task",
            "context-task",
            "--note",
            "Plan covers receipt, freshness, benchmark, doctor, and evidence boundaries",
        )
        self.receipt_path, self.receipt, self.context_root = build_receipt(
            self.base / "fixture"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.backup.cleanup()

    def cli(self, *arguments: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *arguments],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(arguments)}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        if not ok and result.returncode == 0:
            self.fail(f"CLI unexpectedly succeeded: {' '.join(arguments)}")
        return result

    def record_receipt(self, *, requirement: str = "optional") -> dict[str, object]:
        result = self.cli(
            "context-receipt-record",
            "--task",
            "context-task",
            "--provider",
            "codebase-memory",
            "--receipt-id",
            "fixture-v1",
            "--receipt",
            str(self.receipt_path),
            "--receipt-sha256",
            sha256_file(self.receipt_path),
            "--requirement",
            requirement,
            "--freshness-profile",
            "codebase-memory-git-v1",
            "--session-id",
            "root-session",
            "--json",
        )
        return json.loads(result.stdout)

    def test_optional_stale_is_warning_and_snapshot_tamper_is_error(self) -> None:
        recorded = self.record_receipt()
        self.assertEqual(recorded["provider_report"]["freshness"], "fresh")
        state_path = self.root / ".aoi" / "tasks" / "context-task" / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["verification"], [])
        self.assertFalse(state["context_provider_receipts"][0]["close_qualifying"])
        (self.context_root / "rtl" / "top.sv").write_text(
            "module stale; endmodule\n", encoding="utf-8"
        )
        doctor = json.loads(
            self.cli("doctor", "--task", "context-task", "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)
        self.assertEqual(doctor["context_providers"][0]["freshness"], "stale")
        self.assertTrue(any("freshness=stale" in item for item in doctor["warnings"]))
        snapshot = Path(state["context_provider_receipts"][0]["receipt_path"])
        snapshot.write_text("{}\n", encoding="utf-8")
        tampered = self.cli(
            "doctor", "--task", "context-task", "--json", ok=False
        )
        payload = json.loads(tampered.stdout)
        self.assertFalse(payload["ok"])
        self.assertTrue(any("snapshot identity" in item for item in payload["errors"]))

    def test_required_stale_blocks_doctor_and_receipt_only_required_is_rejected(self) -> None:
        rejected = self.cli(
            "context-receipt-record",
            "--task",
            "context-task",
            "--provider",
            "codebase-memory",
            "--receipt-id",
            "bad-required",
            "--receipt",
            str(self.receipt_path),
            "--receipt-sha256",
            sha256_file(self.receipt_path),
            "--requirement",
            "required",
            "--freshness-profile",
            "receipt-only",
            "--session-id",
            "root-session",
            ok=False,
        )
        self.assertIn("freshness profile", rejected.stderr)
        self.record_receipt(requirement="required")
        (self.context_root / "rtl" / "top.sv").write_text(
            "module stale_required; endmodule\n", encoding="utf-8"
        )
        doctor = self.cli("doctor", "--task", "context-task", "--json", ok=False)
        payload = json.loads(doctor.stdout)
        self.assertFalse(payload["ok"])
        self.assertTrue(any("freshness=stale" in item for item in payload["errors"]))

    def test_navigation_benchmark_is_bound_but_never_close_qualifying(self) -> None:
        recorded = self.record_receipt()
        receipt_record = recorded["record"]
        records_dir = self.base / "records"
        records_dir.mkdir()
        sources: list[Path] = []
        for variant, run_id in (("rg_open", "run-a"), ("codebase_memory_assisted", "run-b")):
            payload = benchmark_record(
                variant,
                receipt_sha256=receipt_record["receipt_sha256"],
                source_set_id=receipt_record["source_set_id"],
                run_id=run_id,
            )
            source = records_dir / f"{variant}.json"
            source.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            sources.append(source)
        arguments = [
            "codebase-memory-benchmark-record",
            "--task",
            "context-task",
            "--benchmark-id",
            "navigation-v1",
            "--receipt-id",
            "fixture-v1",
        ]
        for source in sources:
            arguments.extend(["--record", str(source)])
        for source in sources:
            arguments.extend(["--record-sha256", sha256_file(source)])
        arguments.extend(["--session-id", "root-session", "--json"])
        result = json.loads(self.cli(*arguments).stdout)
        self.assertEqual(result["summary"]["pair_count"], 1)
        self.assertEqual(result["summary"]["evidence_class"], "engineering_inference")
        self.assertFalse(result["benchmark"]["close_qualifying"])
        doctor = json.loads(
            self.cli("doctor", "--task", "context-task", "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)
        self.assertEqual(len(doctor["context_provider_benchmarks"]), 1)


if __name__ == "__main__":
    unittest.main()
