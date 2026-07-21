from __future__ import annotations

import copy
from datetime import UTC, datetime
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware import codex_transport_mutation as mutation
from aoi_orgware import git_plumbing as git
from aoi_orgware import harnesslib as h
from aoi_orgware.config import default_config_text


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _run(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _correlation(thread: str | None = None, turn: str | None = None) -> dict[str, str | None]:
    return {"thread_id": thread, "turn_id": turn, "item_id": None}


def _event(intent_sha: str, reservation_sha: str, records: list[dict[str, object]], event_type: str, state: str, correlation: dict[str, str | None]) -> list[dict[str, object]]:
    sequence = len(records) + 1
    pending = event_type.endswith("_pending")
    response_observed = event_type in {
        "initialized",
        "thread_started",
        "turn_started",
        "interrupt_observed",
    }
    wire_observed = response_observed or event_type in {
        "process_started",
        "item_started",
        "item_completed",
        "completed",
        "interrupted",
    }
    raw: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
        "event_id": f"event-{sequence}", "sequence": sequence,
        "prev_event_sha256": contracts.ZERO_SHA256 if not records else records[-1]["event_sha256"],
        "launch_intent_sha256": intent_sha, "reservation_sha256": reservation_sha,
        "event_type": event_type, "state": state,
        "wire_method": contracts._EVENT_WIRE_METHOD[event_type],
        "wire_event_sha256": SHA_A if wire_observed else None,
        "payload_size_bytes": 0 if event_type == "reserved" else 41,
        "item_type": None, "status": contracts._EVENT_WIRE_STATUS[event_type],
        "request_id": f"request-{sequence}" if pending else None,
        "request_bytes_sha256": SHA_B if pending else None,
        "response_sha256": SHA_A if response_observed else None,
        "fault_kind": None,
        "fault_evidence_sha256": None,
        "fault_evidence_size_bytes": None,
        "correlation": correlation,
    }
    return contracts.append_transport_journal_event(records, contracts.seal_journal_event(raw))


class MutationFixture:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _run(self.root, "init")
        _run(self.root, "config", "user.email", "test@example.invalid")
        _run(self.root, "config", "user.name", "AOI Test")
        (self.root / ".gitignore").write_text(".aoi/\n", encoding="utf-8")
        (self.root / "aoi.toml").write_text(default_config_text("Mutation test"), encoding="utf-8")
        (self.root / "src").mkdir()
        (self.root / "src" / "tracked.txt").write_text("before\n", encoding="utf-8")
        (self.root / "src" / "delete.txt").write_text("delete me\n", encoding="utf-8")
        _run(self.root, "add", ".gitignore", "aoi.toml", "src/tracked.txt", "src/delete.txt")
        _run(self.root, "commit", "-m", "baseline")
        self.paths = h.get_paths(self.root)
        with h.state_lock(self.paths, create_layout=True):
            h.task_dir(self.paths, "task-1").mkdir(parents=True)
        self.baseline = _run(self.root, "rev-parse", "HEAD")
        self.claims: list[dict[str, Any]] = [{
            "task_id": "task-1", "token": "task-source", "owner": "root", "status": "active",
            "worktree": str(self.root.resolve()), "locks": ["repo:tree:src"],
        }]

    def close(self) -> None:
        self.tmp.cleanup()

    def endpoint(self) -> dict[str, Any]:
        return mutation.capture_git_endpoint("task-1", self.root, self.baseline, self.claims)

    def intent_and_runtime(self, pre: dict[str, Any], *, pre_binding: dict[str, str] | None = None) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
        pin = {**contracts.pinned_runtime_binding(), "executable_path": "C:/AOI/codex-app-server.exe"}
        intent = contracts.seal_launch_intent({
            "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V1, "task_id": "task-1", "packet_id": "packet-1",
            "routing_binding": {"kind": "cohort", "cohort_id": "cohort-1", "cohort_sha256": SHA_A, "wave_index": 0, "transport_slot_sha256": SHA_B, "routing_authority_sha256": SHA_C, "transport": "codex", "parent_session_id": "chief-1", "expected_agent_type": "worker"},
            "expected_semantic_head_sha256": SHA_A, "prompt_sha256": SHA_B, "prompt_size_bytes": 1,
            "cwd": self.root.resolve().as_posix(), "requested_model": "gpt-5.6-terra", "requested_effort": "high",
            "sandbox": "workspaceWrite", "approval": "never", "runtime_pin": pin,
            "pre_git_binding": pre_binding or mutation.endpoint_pre_git_binding(pre),
        })
        reservation = contracts.seal_reservation({
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1, "reservation_id": "reserve-1",
            "launch_intent_sha256": intent["intent_sha256"], "permit_sha256": SHA_C, "runtime_pin": pin,
            "state": "reserved", "correlation": _correlation(),
        })
        records: list[dict[str, object]] = []
        for event_type, state, corr in (
            ("reserved", "reserved", _correlation()), ("process_start_pending", "reserved", _correlation()),
            ("process_started", "reserved", _correlation()), ("initialize_send_pending", "reserved", _correlation()),
            ("initialized", "reserved", _correlation()), ("thread_start_send_pending", "reserved", _correlation()),
            ("thread_started", "thread_started", _correlation("thread-1")),
            ("turn_start_send_pending", "thread_started", _correlation("thread-1")),
            ("turn_started", "turn_started", _correlation("thread-1", "turn-1")),
            ("completed", "completed", _correlation("thread-1", "turn-1")),
        ):
            records = _event(intent["intent_sha256"], reservation["reservation_sha256"], records, event_type, state, corr)
        terminal = contracts.seal_terminal_receipt({
            "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
            "reservation_sha256": reservation["reservation_sha256"], "journal_head_sha256": records[-1]["event_sha256"],
            "terminal_state": "completed", "correlation": _correlation("thread-1", "turn-1"),
            "evidence_level": "codex_runtime_observed", "mutation_verification": {"status": "unavailable", "object_sha256": None},
        })
        return intent, reservation, records, terminal


@pytest.fixture()
def fixture() -> Any:
    value = MutationFixture()
    try:
        yield value
    finally:
        value.close()


def test_materializes_exact_endpoints_and_never_claims_task_completion(fixture: MutationFixture) -> None:
    pre = fixture.endpoint()
    intent, reservation, journal, terminal = fixture.intent_and_runtime(pre)
    (fixture.root / "src" / "tracked.txt").write_text("after\n", encoding="utf-8")
    (fixture.root / "src" / "untracked.txt").write_text("new\n", encoding="utf-8")
    (fixture.root / "src" / "delete.txt").unlink()
    _run(fixture.root, "mv", "src/tracked.txt", "src/renamed.txt")
    post = fixture.endpoint()
    paths = {entry["path_b64"] for entry in post["snapshot"]["paths"]}
    assert paths
    with h.state_lock(fixture.paths, create_layout=False):
        result = mutation.materialize_verified_mutation(
            fixture.paths, task_id="task-1", intent=intent, reservation=reservation, journal=journal,
            runtime_terminal_receipt=terminal, pre_endpoint=pre, post_endpoint=post, claims=fixture.claims,
        )
        checked = mutation.validate_materialized_mutation(
            fixture.paths, task_id="task-1", semantic_object=result["semantic_object"],
            verified_terminal_receipt=result["verified_terminal_receipt"], intent=intent, reservation=reservation,
            journal=journal, claims=fixture.claims,
        )
    assert result["verified_terminal_receipt"]["evidence_level"] == "verified_mutation"
    assert result["task_completion"] == checked["task_completion"] == "not_inferred"


def test_rejects_after_image_claim_and_source_binding_mismatches(fixture: MutationFixture) -> None:
    pre = fixture.endpoint()
    intent, reservation, journal, terminal = fixture.intent_and_runtime(pre)
    (fixture.root / "src" / "tracked.txt").write_text("after\n", encoding="utf-8")
    post = fixture.endpoint()
    bad_claims = copy.deepcopy(fixture.claims)
    bad_claims[0]["locks"] = ["repo:file:other.txt"]
    with pytest.raises(
        mutation.CodexTransportMutationError,
        match="uncovered|claim coverage|claim authority",
    ):
        mutation.validate_git_endpoint(post, bad_claims, sealed_claim_scope=False)
    bad_binding = dict(mutation.endpoint_pre_git_binding(pre))
    bad_binding["git_tree_sha256"] = SHA_A
    bad_intent, bad_reservation, bad_journal, bad_terminal = fixture.intent_and_runtime(pre, pre_binding=bad_binding)
    with h.state_lock(fixture.paths, create_layout=False):
        with pytest.raises(mutation.CodexTransportMutationError, match="pre Git endpoint"):
            mutation.materialize_verified_mutation(
                fixture.paths, task_id="task-1", intent=bad_intent, reservation=bad_reservation, journal=bad_journal,
                runtime_terminal_receipt=bad_terminal, pre_endpoint=pre, post_endpoint=post, claims=fixture.claims,
            )


def test_clean_endpoint_binds_complete_live_claim_authority(
    fixture: MutationFixture,
) -> None:
    before = fixture.endpoint()
    legacy_base = {
        "schema": mutation.LEGACY_GIT_ENDPOINT_SCHEMA,
        "task_id": before["task_id"],
        "snapshot": before["snapshot"],
        "tree": before["tree"],
        "claim_coverage": before["claim_coverage"],
    }
    legacy = {
        **legacy_base,
        "endpoint_sha256": mutation._sha(
            mutation._canonical(legacy_base, "legacy Git endpoint")
        ),
    }
    with pytest.raises(
        mutation.CodexTransportMutationError,
        match="legacy Git endpoint lacks complete live claim authority",
    ):
        mutation.validate_git_endpoint(
            legacy, fixture.claims, sealed_claim_scope=False
        )
    added = [
        *fixture.claims,
        {
            "task_id": "task-1",
            "token": "second-source",
            "owner": "root",
            "status": "active",
            "worktree": str(fixture.root.resolve()),
            "locks": ["repo:file:src/tracked.txt"],
        },
    ]
    after_add = mutation.capture_git_endpoint(
        "task-1", fixture.root, fixture.baseline, added
    )
    assert before["snapshot"] == after_add["snapshot"]
    assert before["claim_coverage"] == after_add["claim_coverage"]
    assert before["claim_authority"] != after_add["claim_authority"]
    assert before["endpoint_sha256"] != after_add["endpoint_sha256"]
    assert (
        mutation.endpoint_pre_git_binding(before)["claim_coverage_sha256"]
        != mutation.endpoint_pre_git_binding(after_add)[
            "claim_coverage_sha256"
        ]
    )
    with pytest.raises(
        mutation.CodexTransportMutationError,
        match="complete live claim scope",
    ):
        mutation.validate_git_endpoint(
            before, added, sealed_claim_scope=False
        )

    lock_drift = copy.deepcopy(fixture.claims)
    lock_drift[0]["locks"] = ["repo:file:src/tracked.txt"]
    with pytest.raises(
        mutation.CodexTransportMutationError,
        match="complete live claim scope",
    ):
        mutation.validate_git_endpoint(
            before, lock_drift, sealed_claim_scope=False
        )
    with pytest.raises(
        mutation.CodexTransportMutationError,
        match="complete live claim scope",
    ):
        mutation.validate_git_endpoint(before, [], sealed_claim_scope=False)


def test_rejects_tree_digest_that_does_not_match_live_snapshot_head(fixture: MutationFixture) -> None:
    endpoint = fixture.endpoint()
    forged = copy.deepcopy(endpoint)
    forged["tree"]["tree"] = "f" * 40
    tree_base = {key: forged["tree"][key] for key in ("schema", "head", "tree")}
    forged["tree"]["tree_sha256"] = mutation._sha(mutation._canonical(tree_base, "Git tree"))
    endpoint_base = {
        "schema": mutation.GIT_ENDPOINT_SCHEMA,
        "task_id": forged["task_id"],
        "snapshot": forged["snapshot"],
        "tree": forged["tree"],
        "claim_coverage": forged["claim_coverage"],
        "claim_authority": forged["claim_authority"],
    }
    forged["endpoint_sha256"] = mutation._sha(mutation._canonical(endpoint_base, "Git endpoint"))
    with pytest.raises(mutation.CodexTransportMutationError, match="live snapshot HEAD tree"):
        mutation.validate_git_endpoint(forged, fixture.claims, sealed_claim_scope=False)


def test_rejects_post_endpoint_drift_before_cas_publication(fixture: MutationFixture) -> None:
    pre = fixture.endpoint()
    intent, reservation, journal, terminal = fixture.intent_and_runtime(pre)
    (fixture.root / "src" / "tracked.txt").write_text("first after image\n", encoding="utf-8")
    post = fixture.endpoint()
    (fixture.root / "src" / "tracked.txt").write_text("drifted after image\n", encoding="utf-8")
    with h.state_lock(fixture.paths, create_layout=False):
        with pytest.raises(mutation.CodexTransportMutationError, match="post Git endpoint drifted"):
            mutation.materialize_verified_mutation(
                fixture.paths, task_id="task-1", intent=intent, reservation=reservation, journal=journal,
                runtime_terminal_receipt=terminal, pre_endpoint=pre, post_endpoint=post, claims=fixture.claims,
            )


class _FakePopen:
    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        return None


def test_git_tree_lookup_bounds_stdout_and_stderr(fixture: MutationFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mutation, "MAX_GIT_TREE_OUTPUT_BYTES", 4)
    monkeypatch.setattr(git, "MAX_GIT_COMMAND_STDERR_BYTES", 4)
    monkeypatch.setattr(git.subprocess, "Popen", lambda *_args, **_kwargs: _FakePopen(b"12345", b""))
    with pytest.raises(mutation.CodexTransportMutationError, match="output exceeds"):
        mutation._git_tree(fixture.root, fixture.baseline)
    monkeypatch.setattr(git.subprocess, "Popen", lambda *_args, **_kwargs: _FakePopen(b"1234", b"12345"))
    with pytest.raises(mutation.CodexTransportMutationError, match="output exceeds"):
        mutation._git_tree(fixture.root, fixture.baseline)


def test_rejects_wrong_runtime_correlation_and_tampered_cas(fixture: MutationFixture) -> None:
    pre = fixture.endpoint()
    intent, reservation, journal, terminal = fixture.intent_and_runtime(pre)
    post = fixture.endpoint()
    with h.state_lock(fixture.paths, create_layout=False):
        wrong_terminal = contracts.seal_terminal_receipt({
            "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
            "reservation_sha256": reservation["reservation_sha256"], "journal_head_sha256": journal[-1]["event_sha256"],
            "terminal_state": "completed", "correlation": _correlation("wrong-thread", "turn-1"),
            "evidence_level": "codex_runtime_observed", "mutation_verification": {"status": "unavailable", "object_sha256": None},
        })
        with pytest.raises(mutation.CodexTransportMutationError, match="correlation|runtime evidence"):
            mutation.materialize_verified_mutation(
                fixture.paths, task_id="task-1", intent=intent, reservation=reservation, journal=journal,
                runtime_terminal_receipt=wrong_terminal, pre_endpoint=pre, post_endpoint=post, claims=fixture.claims,
            )
        result = mutation.materialize_verified_mutation(
            fixture.paths, task_id="task-1", intent=intent, reservation=reservation, journal=journal,
            runtime_terminal_receipt=terminal, pre_endpoint=pre, post_endpoint=post, claims=fixture.claims,
        )
        payload = result["mutation_verification"]
        target = mutation.artifacts.artifact_blob_path(fixture.paths, "task-1", payload["post_git_tree"]["cas_sha256"])
        target.write_bytes(b"tampered")
        with pytest.raises(mutation.CodexTransportMutationError, match="tampered|cannot materialize"):
            mutation.validate_materialized_mutation(
                fixture.paths, task_id="task-1", semantic_object=result["semantic_object"],
                verified_terminal_receipt=result["verified_terminal_receipt"], intent=intent, reservation=reservation,
                journal=journal, claims=fixture.claims,
            )


def test_sealed_endpoint_scope_allows_terminal_claim_status_only_with_exact_scope(fixture: MutationFixture) -> None:
    (fixture.root / "src" / "tracked.txt").write_text("sealed endpoint\n", encoding="utf-8")
    pre = fixture.endpoint()
    released = copy.deepcopy(fixture.claims)
    released[0]["status"] = "released"
    assert mutation.validate_git_endpoint(pre, released, sealed_claim_scope=True)["endpoint_sha256"] == pre["endpoint_sha256"]
    released[0]["locks"] = ["repo:file:other.txt"]
    with pytest.raises(mutation.CodexTransportMutationError, match="coverage|scope"):
        mutation.validate_git_endpoint(pre, released, sealed_claim_scope=True)


def test_symlink_and_case_only_falsification_when_supported(fixture: MutationFixture) -> None:
    target = fixture.root / "src" / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    link = fixture.root / "src" / "link.txt"
    try:
        os.symlink(target.name, link)
    except (OSError, NotImplementedError):
        pytest.skip("host does not permit symlink fixtures")
    with pytest.raises(mutation.CodexTransportMutationError, match="symlink|cannot capture"):
        fixture.endpoint()
    link.unlink()


def test_case_only_rename_and_bounded_endpoint_records(fixture: MutationFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    _run(fixture.root, "config", "core.ignorecase", "false")
    renamed = subprocess.run(
        ["git", "-C", str(fixture.root), "mv", "src/tracked.txt", "src/TRACKED.txt"],
        capture_output=True, text=True, check=False,
    )
    if renamed.returncode:
        pytest.skip("host filesystem does not permit case-only rename fixtures")
    assert fixture.endpoint()["snapshot"]["mutation_paths_b64"]
    monkeypatch.setattr(mutation, "MAX_MUTATION_RECORD_BYTES", 1)
    with pytest.raises(mutation.CodexTransportMutationError, match="bounded"):
        fixture.endpoint()
