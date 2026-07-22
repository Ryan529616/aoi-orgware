from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any, Mapping

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_cli as bridge
from aoi_orgware import cli as core_cli
from aoi_orgware import confidentiality
from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware import codex_transport_mutation as mutation
from aoi_orgware import codex_transport_runtime as runtime
from aoi_orgware import evidence_artifacts
from aoi_orgware import harnesslib as h
from aoi_orgware import semantic_events as semantic
from aoi_orgware import semantic_store as store
from aoi_orgware import transition_permits as permits
from aoi_orgware.codex_app_server_stdio import (
    AppServerError,
    ProcessJournalEntry,
    RequestJournalEntry,
    RequestPhase,
    ResponseSchemaViolation,
    RuntimeDisconnected,
    RuntimeEvent,
    TurnObservation,
)
from aoi_orgware.config import default_config_text


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _launch_authority(intent: Mapping[str, Any]) -> dict[str, Any]:
    return contracts.seal_launch_authority(
        {
            "contract_type": contracts.CODEX_LAUNCH_AUTHORITY_V1,
            "task_id": "task-1",
            "packet_id": "packet-1",
            "packet_contract_sha256": SHA_B,
            "attempt_number": 1,
            "arm_id": "packet-1-a1",
            "armed_at": "2026-07-19T23:59:00Z",
            "expires_at": "2099-07-21T00:00:00Z",
            "dispatch_attempt_authority_sha256": SHA_C,
            "chief_authority_sha256": SHA_D,
            "parent_session_id": "chief-1",
            "expected_agent_type": "worker",
            "routing_binding": intent["routing_binding"],
            "expected_semantic_head_sha256": intent[
                "expected_semantic_head_sha256"
            ],
            "launch_intent_sha256": intent["intent_sha256"],
        }
    )


def _task_domain() -> dict[str, Any]:
    return {
        "task_id": "task-1",
        "stage": 0,
        "revision": 1,
        "updated_at": "2026-07-19T23:59:00Z",
        "checkpoint_required": False,
        "packets": [
            {
                "packet_id": "packet-1",
                "packet_contract_sha256": SHA_B,
                "status": "armed",
                "dispatch_provenance": "none",
                "dispatch_attempts": [
                    {
                        "attempt": 1,
                        "arm_id": "packet-1-a1",
                        "status": "armed",
                        "armed_at": "2026-07-19T23:59:00Z",
                        "expires_at": "2099-07-21T00:00:00Z",
                        "arm_authority_sha256": SHA_C,
                        "authority_sha256": SHA_D,
                        "parent_session_id": "chief-1",
                        "expected_agent_type": "worker",
                        "observation": None,
                        "closed_at": "",
                        "reason": "",
                    }
                ],
            }
        ],
    }


_FIXTURE_CLAIMS_BY_ROOT: dict[str, list[dict[str, Any]]] = {}


@pytest.fixture(autouse=True)
def _stub_canonical_launch_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    _FIXTURE_CLAIMS_BY_ROOT.clear()
    monkeypatch.setattr(
        runtime.launch_authority,
        "require_canonical_launch_authority",
        lambda *args, **kwargs: _launch_authority(kwargs["intent"]),
    )
    monkeypatch.setattr(
        h,
        "claims_owned_by_task",
        lambda paths, task_id: [
            dict(claim)
            for claim in _FIXTURE_CLAIMS_BY_ROOT.get(
                str(paths.root.resolve()), []
            )
            if claim["task_id"] == task_id
        ],
    )


@dataclass
class BridgeFixture:
    root: Path
    paths: h.HarnessPaths
    chief: dict[str, Any]
    credential_path: Path
    prompt_path: Path
    intent_path: Path
    decision_path: Path
    permit_path: Path
    permit_sha256: str
    worktree: Path
    claims: list[dict[str, Any]]
    pre_endpoint_path: Path
    sandbox: str


def _additional_claim(value: BridgeFixture) -> dict[str, Any]:
    return {
        "task_id": "task-1",
        "token": "bridge-second-source",
        "owner": "/root",
        "status": "active",
        "worktree": str(value.worktree.resolve()),
        "locks": ["repo:file:src/tracked.txt"],
    }


def _rewrite_as_legacy_null_cas_marker(value: BridgeFixture) -> dict[str, Any]:
    marker_path = runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    )
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["pre_git_endpoint_cas_sha256"] = None
    base = {key: item for key, item in marker.items() if key != "issuance_sha256"}
    marker["issuance_sha256"] = semantic.canonical_sha256(
        base, max_bytes=runtime.MAX_ISSUANCE_BYTES
    )
    marker_path.write_bytes(
        semantic.canonical_json_bytes(
            marker, max_bytes=runtime.MAX_ISSUANCE_BYTES
        )
    )
    return runtime.inspect_codex_launch_issuance(
        value.paths,
        task_id="task-1",
        permit_sha256=value.permit_sha256,
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(dict(value), sort_keys=True), encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _fixture(
    tmp_path: Path,
    *,
    sandbox: str = "readOnly",
    local_files: bool = False,
) -> BridgeFixture:
    root = tmp_path / "project"
    root.mkdir()
    config_text = default_config_text("Codex transport bridge")
    if local_files:
        config_text += '\n[confidentiality]\nmode = "local_files"\n'
    (root / "aoi.toml").write_text(config_text, encoding="utf-8")
    worktree = root / "scratch"
    worktree.mkdir()
    _git(worktree, "init")
    _git(worktree, "config", "user.email", "test@example.invalid")
    _git(worktree, "config", "user.name", "AOI Test")
    (worktree / "src").mkdir()
    (worktree / "src" / "tracked.txt").write_text("before\n", encoding="utf-8")
    _git(worktree, "add", "src/tracked.txt")
    _git(worktree, "commit", "-m", "baseline")
    baseline = _git(worktree, "rev-parse", "HEAD")
    claims: list[dict[str, Any]] = [
        {
            "task_id": "task-1",
            "token": "bridge-source",
            "owner": "/root",
            "status": "active",
            "worktree": str(worktree.resolve()),
            "locks": ["repo:tree:src"],
        }
    ]
    pre_endpoint = mutation.capture_git_endpoint(
        "task-1", worktree, baseline, claims
    )
    paths = h.get_paths(root)
    _FIXTURE_CLAIMS_BY_ROOT[str(paths.root.resolve())] = claims
    with h.state_lock(paths, create_layout=True):
        h.task_dir(paths, "task-1").mkdir(parents=True)
        store.initialize_semantic_task(
            paths,
            _task_domain(),
            command_id="bridge-genesis",
            recorded_at="2026-07-20T00:00:00Z",
            authority_ref="test",
        )
        chief, credential_path = h.acquire_chief_authority(
            paths,
            session_id="chief-1",
            ttl_seconds=3600,
            credential_home=tmp_path / "credentials",
            now=datetime.now(UTC),
        )
    events = store.load_semantic_events(paths, "task-1")
    head = str(events[-1]["event_sha256"])
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("hello", encoding="utf-8")
    prompt = prompt_path.read_bytes()
    pin = {
        **contracts.pinned_runtime_binding(),
        "executable_path": Path(sys.executable).resolve().as_posix(),
    }
    intent = contracts.seal_launch_intent(
        {
            "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V1,
            "task_id": "task-1",
            "packet_id": "packet-1",
            "routing_binding": {
                "kind": "cohort",
                "cohort_id": "cohort-1",
                "cohort_sha256": SHA_A,
                "wave_index": 0,
                "transport_slot_sha256": SHA_B,
                "routing_authority_sha256": SHA_C,
                "transport": "codex",
                "parent_session_id": "chief-1",
                "expected_agent_type": "worker",
            },
            "expected_semantic_head_sha256": head,
            "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
            "prompt_size_bytes": len(prompt),
            "cwd": worktree.resolve().as_posix(),
            "requested_model": "gpt-5.6-terra",
            "requested_effort": "high",
            "sandbox": sandbox,
            "approval": "never",
            "runtime_pin": pin,
            "pre_git_binding": mutation.endpoint_pre_git_binding(pre_endpoint),
        }
    )
    parameters = {
        "launch_id": "launch-1",
        "launch_intent_sha256": intent["intent_sha256"],
        "packet_id": "packet-1",
        "routing_binding": intent["routing_binding"],
    }
    decision = permits.seal_transition_decision(
        {
            "schema_version": 1,
            "task_id": "task-1",
            "action": "codex.launch",
            "target_ids": ["launch-1"],
            "parameters": parameters,
            "technical_payload_sha256": intent["intent_sha256"],
        }
    )
    permit = permits.seal_transition_permit(
        {
            "schema_version": 1,
            "task_id": "task-1",
            "expected_semantic_head_sha256": head,
            "decision_sha256": decision["decision_sha256"],
            "action": "codex.launch",
            "target_ids": ["launch-1"],
            "parameters": parameters,
            "expires_at": "2099-07-21T00:00:00Z",
            "nonce": "nonce-bridge-0001",
            "chief_authority": {
                "session_id": chief["session_id"],
                "epoch": chief["epoch"],
            },
        }
    )
    intent_path = tmp_path / "intent.json"
    decision_path = tmp_path / "decision.json"
    permit_path = tmp_path / "permit.json"
    pre_endpoint_path = tmp_path / "pre-endpoint.json"
    _write_json(intent_path, intent)
    _write_json(decision_path, decision)
    _write_json(permit_path, permit)
    _write_json(pre_endpoint_path, pre_endpoint)
    return BridgeFixture(
        root,
        paths,
        chief,
        credential_path,
        prompt_path,
        intent_path,
        decision_path,
        permit_path,
        str(permit["permit_sha256"]),
        worktree,
        claims,
        pre_endpoint_path,
        sandbox,
    )


def _issue_args(value: BridgeFixture) -> list[str]:
    result = [
        "--root",
        str(value.root),
        "issue",
        "--task",
        "task-1",
        "--launch-id",
        "launch-1",
        "--intent-file",
        str(value.intent_path),
        "--decision-file",
        str(value.decision_path),
        "--permit-file",
        str(value.permit_path),
        "--command-id",
        "reserve-launch-1",
        "--recorded-at",
        "2026-07-20T00:01:00Z",
        "--chief-session-id",
        value.chief["session_id"],
        "--chief-epoch",
        str(value.chief["epoch"]),
        "--chief-credential-file",
        str(value.credential_path),
        "--json",
    ]
    result.extend(
        ["--pre-git-endpoint-file", str(value.pre_endpoint_path)]
    )
    return result


def _runtime_event(method: str, params: Mapping[str, Any]) -> RuntimeEvent:
    raw = json.dumps(
        {"method": method, "params": dict(params)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return RuntimeEvent(method, dict(params), hashlib.sha256(raw).hexdigest(), raw)


class FakeAdapter:
    def __init__(self, mode: str = "completed") -> None:
        self.mode = mode
        self.on_process_start_pending: Any = None
        self.on_process_started: Any = None
        self.on_send_pending: Any = None
        self.on_response: Any = None
        self.on_rejected_response: Any = None
        self.on_rejected_notification: Any = None
        self.request_count: dict[str, int] = {}
        self._next_id = 1
        self.reroute_event: RuntimeEvent | None = None

    @staticmethod
    def _process(phase: str, pid: int | None) -> ProcessJournalEntry:
        raw = json.dumps(
            {"phase": phase, "pid": pid}, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return ProcessJournalEntry(phase, raw, hashlib.sha256(raw).hexdigest(), pid)

    def start(self) -> None:
        self.on_process_start_pending(self._process("process_start_pending", None))
        self.on_process_started(self._process("process_started", 42))

    def _request(self, method: str, result: Mapping[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self.request_count[method] = self.request_count.get(method, 0) + 1
        request = json.dumps(
            {"id": request_id, "method": method, "params": {}},
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        self.on_send_pending(
            RequestJournalEntry(
                request_id,
                method,
                RequestPhase.SEND_PENDING,
                request,
                hashlib.sha256(request).hexdigest(),
            )
        )
        if self.mode == "thread_start_loss" and method == "thread/start":
            raise RuntimeDisconnected("thread/start response lost")
        if self.mode == "model_list_schema_error" and method == "model/list":
            rejected = json.dumps(
                {"id": request_id, "result": {"invalid": True}},
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            entry = RequestJournalEntry(
                request_id,
                method,
                RequestPhase.RESPONSE_RECEIVED,
                rejected,
                hashlib.sha256(rejected).hexdigest(),
            )
            self.on_rejected_response(entry)
            raise ResponseSchemaViolation(
                "pinned model/list response schema validation failed",
                method=method,
                evidence_sha256=entry.sha256,
                evidence_size_bytes=len(rejected),
            )
        response = json.dumps(
            {"id": request_id, "result": dict(result)},
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        self.on_response(
            RequestJournalEntry(
                request_id,
                method,
                RequestPhase.RESPONSE_RECEIVED,
                response,
                hashlib.sha256(response).hexdigest(),
            )
        )
        return dict(result)

    def initialize(self) -> dict[str, Any]:
        return self._request("initialize", {"capabilities": {}})

    def verify_model_from_intent(self, *, intent: object) -> dict[str, Any]:
        return self._request(
            "model/list",
            {
                "data": [
                    {
                        "model": "gpt-5.6-terra",
                        "supportedReasoningEfforts": [
                            {"reasoningEffort": "high"}
                        ],
                    }
                ],
                "nextCursor": None,
            },
        )

    def start_thread_from_intent(self, *, intent: object) -> str:
        result = self._request("thread/start", {"thread": {"id": "thread-1"}})
        return str(result["thread"]["id"])

    def start_turn_from_intent(
        self, *, thread_id: str, prompt: str, intent: object
    ) -> str:
        result = self._request(
            "turn/start", {"turn": {"id": "turn-1", "status": "inProgress"}}
        )
        return str(result["turn"]["id"])

    def interrupt_turn(self, *, thread_id: str, turn_id: str) -> dict[str, Any]:
        return self._request("turn/interrupt", {})

    def observe_turn(
        self, *, thread_id: str, turn_id: str, timeout_seconds: float
    ) -> TurnObservation:
        if self.mode == "model_rerouted":
            self.reroute_event = _runtime_event(
                "model/rerouted",
                {
                    "fromModel": "gpt-5.6-terra",
                    "reason": "highRiskCyberActivity",
                    "threadId": thread_id,
                    "toModel": "reroute-secret-model",
                    "turnId": turn_id,
                },
            )
            completed = _runtime_event(
                "turn/completed",
                {
                    "threadId": thread_id,
                    "turn": {"id": turn_id, "status": "completed"},
                },
            )
            return TurnObservation(
                thread_id, turn_id, "completed", (self.reroute_event, completed)
            )
        item = {"id": "item-1", "type": "agentMessage", "text": "not persisted"}
        status = (
            "interrupted" if self.request_count.get("turn/interrupt") else "completed"
        )
        events = (
            _runtime_event(
                "item/started",
                {"threadId": thread_id, "turnId": turn_id, "item": item},
            ),
            _runtime_event(
                "item/completed",
                {"threadId": thread_id, "turnId": turn_id, "item": item},
            ),
            _runtime_event(
                "turn/completed",
                {"threadId": thread_id, "turn": {"id": turn_id, "status": status}},
            ),
        )
        return TurnObservation(thread_id, turn_id, status, events)

    def synchronize_reader_boundary(self, *, timeout_seconds: float) -> None:
        return None

    def seal_reader_for_terminal_commit(self, *, timeout_seconds: float) -> None:
        return None

    def close(self) -> None:
        return None


class CallbackWrappingAdapter(FakeAdapter):
    """Match the production adapter's callback failure boundary."""

    def start(self) -> None:
        try:
            self.on_process_start_pending(
                self._process("process_start_pending", None)
            )
        except Exception as exc:
            raise AppServerError(
                "process_start_pending journal callback failed; process was not started"
            ) from exc
        self.on_process_started(self._process("process_started", 42))


class StartedCallbackWrappingAdapter(FakeAdapter):
    """Model Popen success followed by durable started-callback failure."""

    def __init__(self) -> None:
        super().__init__()
        self.physically_started = False

    def start(self) -> None:
        self.on_process_start_pending(self._process("process_start_pending", None))
        self.physically_started = True
        try:
            self.on_process_started(self._process("process_started", 42))
        except Exception as exc:
            raise AppServerError(
                "process_started journal callback failed; process was terminated"
            ) from exc


def _run_args(value: BridgeFixture, prompt: Path, *extra: str) -> list[str]:
    return [
        "--root",
        str(value.root),
        "run",
        "--task",
        "task-1",
        "--permit-sha256",
        value.permit_sha256,
        "--prompt-file",
        str(prompt),
        "--json",
        *extra,
    ]


def test_cli_issue_run_inspect_and_no_resend(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    first_issue = json.loads(capsys.readouterr().out)
    assert first_issue["chief_credential_retained"] is False
    assert first_issue["idempotent_replay"] is False
    assert bridge.main(_issue_args(value)) == 0
    second_issue = json.loads(capsys.readouterr().out)
    assert second_issue["idempotent_replay"] is True

    created: list[FakeAdapter] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        adapter = FakeAdapter()
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    wrong = tmp_path / "wrong-prompt.txt"
    wrong.write_text("different", encoding="utf-8")
    assert bridge.main(_run_args(value, wrong)) == 2
    assert "do not match" in capsys.readouterr().err
    assert created == []

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    completed = json.loads(capsys.readouterr().out)
    assert completed["terminal_state"] == "completed"
    assert completed["evidence_level"] == "codex_runtime_observed"
    assert completed["task_completion"] == "not_inferred"
    assert completed["app_server_start_durably_observed"] is True
    assert completed["runtime_process_boundary_reached"] is True
    assert completed["process_start_evidence"] == "process_started_observed"
    assert len(created) == 1

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["terminal_receipt_sha256"] == completed["terminal_receipt_sha256"]
    assert replay["app_server_start_durably_observed"] is False
    assert replay["runtime_process_boundary_reached"] is False
    assert replay["process_start_evidence"] == "not_started"
    assert len(created) == 1

    assert bridge.main(
        [
            "--root",
            str(value.root),
            "inspect",
            "--task",
            "task-1",
            "--launch-id",
            "launch-1",
            "--json",
        ]
    ) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["terminal_receipt_sha256"] == completed["terminal_receipt_sha256"]
    assert inspected["pending_journal_event_sha256"] is None
    assert inspected["pending_terminal_receipt_sha256"] is None


def test_cli_thread_start_loss_is_launch_unknown_and_never_resent(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[FakeAdapter] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        adapter = FakeAdapter("thread_start_loss")
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["terminal_state"] == "launch_unknown"
    assert created[0].request_count["thread/start"] == 1

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["terminal_state"] == "launch_unknown"
    assert second["app_server_start_durably_observed"] is False
    assert second["runtime_process_boundary_reached"] is False
    assert len(created) == 1


def test_cli_rejected_response_bytes_are_verified_in_task_local_cas(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[FakeAdapter] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        adapter = FakeAdapter("model_list_schema_error")
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "failed"
    assert created[0].request_count == {"initialize": 1, "model/list": 1}

    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    terminal = launch["journal"][-1]
    assert terminal["fault_kind"] == "ResponseSchemaViolation"
    digest = terminal["fault_evidence_sha256"]
    blob = evidence_artifacts.artifact_blob_path(
        value.paths, "task-1", digest
    ).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest
    assert len(blob) == terminal["fault_evidence_size_bytes"]
    assert json.loads(blob)["result"] == {"invalid": True}


def test_cli_model_reroute_is_failed_with_exact_task_local_cas_and_no_resend(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[FakeAdapter] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        adapter = FakeAdapter("model_rerouted")
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["terminal_state"] == "failed"
    assert first["runtime_completed"] is False
    assert len(created) == 1
    assert created[0].reroute_event is not None

    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert "completed" not in [row["event_type"] for row in launch["journal"]]
    terminal = launch["journal"][-1]
    assert terminal["event_type"] == "failed"
    assert terminal["wire_method"] == "model/rerouted"
    assert terminal["fault_kind"] == "ModelReroutedViolation"
    digest = terminal["fault_evidence_sha256"]
    blob = evidence_artifacts.artifact_blob_path(
        value.paths, "task-1", digest
    ).read_bytes()
    assert blob == created[0].reroute_event.wire_bytes
    assert hashlib.sha256(blob).hexdigest() == digest
    assert len(blob) == terminal["fault_evidence_size_bytes"]

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["terminal_state"] == "failed"
    assert replay["runtime_completed"] is False
    assert replay["terminal_receipt_sha256"] == first["terminal_receipt_sha256"]
    assert replay["app_server_start_durably_observed"] is False
    assert len(created) == 1


def test_cli_local_files_profile_requires_adapter_process_policy(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, local_files=True)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    observed_kwargs: list[dict[str, object]] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        observed_kwargs.append(dict(kwargs))
        return FakeAdapter()

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "completed"
    intent = json.loads(value.intent_path.read_text(encoding="utf-8"))
    assert observed_kwargs == [
        {
            "cwd": str(intent["cwd"]),
            "require_local_files_policy": True,
        }
    ]


def test_cli_interrupt_persists_response_then_turn_terminal(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[FakeAdapter] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        adapter = FakeAdapter()
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(
        _run_args(value, value.prompt_path, "--interrupt-after-start")
    ) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "interrupted"
    assert created[0].request_count["turn/interrupt"] == 1
    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    event_types = [row["event_type"] for row in launch["journal"]]
    assert "interrupt_observed" in event_types
    assert event_types[-1] == "interrupted"


def test_cli_workspace_write_recaptures_pre_endpoint_before_issuance(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, sandbox="workspaceWrite")
    monkeypatch.setattr(
        bridge.h, "claims_owned_by_task", lambda _paths, _task: value.claims
    )
    # The endpoint file was captured before this local edit.  A valid old
    # endpoint must not be preserved or bound to a new permit.
    (value.worktree / "src" / "tracked.txt").write_text(
        "changed before issue\n", encoding="utf-8"
    )

    assert bridge.main(_issue_args(value)) == 2
    assert "drifted before permit issuance" in capsys.readouterr().err
    assert not bridge._launch_is_committed(
        store.load_semantic_events(value.paths, "task-1"), "launch-1"
    )


def test_cli_read_only_recaptures_pre_endpoint_before_issuance(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    monkeypatch.setattr(
        bridge.h, "claims_owned_by_task", lambda _paths, _task: value.claims
    )
    (value.worktree / "src" / "tracked.txt").write_text(
        "read-only drift before issue\n", encoding="utf-8"
    )

    assert bridge.main(_issue_args(value)) == 2
    assert "drifted before permit issuance" in capsys.readouterr().err
    assert not bridge._launch_is_committed(
        store.load_semantic_events(value.paths, "task-1"), "launch-1"
    )


def test_cli_read_only_rejects_full_claim_drift_before_issuance(
    tmp_path: Path, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    value.claims.append(_additional_claim(value))

    assert bridge.main(_issue_args(value)) == 2
    assert "complete live claim scope" in capsys.readouterr().err
    assert not runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    ).exists()


def test_cli_read_only_issue_requires_pre_git_endpoint_file(
    tmp_path: Path, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    missing_pre = _issue_args(value)
    pre_index = missing_pre.index("--pre-git-endpoint-file")
    del missing_pre[pre_index : pre_index + 2]

    assert bridge.main(missing_pre) == 2
    assert (
        "readOnly issuance requires --pre-git-endpoint-file"
        in capsys.readouterr().err
    )
    assert not runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    ).exists()


def test_cli_legacy_read_only_null_cas_marker_cannot_reserve_or_start(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    marker = _rewrite_as_legacy_null_cas_marker(value)
    assert marker["pre_git_endpoint_cas_sha256"] is None
    created: list[FakeAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: created.append(FakeAdapter()) or created[-1],
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 2
    assert "lacks its preserved pre Git endpoint" in capsys.readouterr().err
    assert created == []
    assert not bridge._launch_is_committed(
        store.load_semantic_events(value.paths, "task-1"), "launch-1"
    )


def test_cli_legacy_reserved_read_only_null_cas_marker_cannot_start(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    with h.state_lock(value.paths, create_layout=False):
        reserved = bridge._load_or_reserve(
            value.paths,
            task_id="task-1",
            permit_sha256=value.permit_sha256,
            now=bridge._now(),
        )
    assert [row["event_type"] for row in reserved["journal"]] == [
        "reserved"
    ]
    marker = _rewrite_as_legacy_null_cas_marker(value)
    assert marker["pre_git_endpoint_cas_sha256"] is None
    created: list[CallbackWrappingAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: (
            created.append(CallbackWrappingAdapter()) or created[-1]
        ),
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "failed"
    assert result["process_start_evidence"] == "not_started"
    assert result["app_server_start_durably_observed"] is False
    assert len(created) == 1


def test_cli_workspace_write_rechecks_source_after_issue_before_reserve(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, sandbox="workspaceWrite")
    monkeypatch.setattr(
        bridge.h, "claims_owned_by_task", lambda _paths, _task: value.claims
    )
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    (value.worktree / "src" / "tracked.txt").write_text(
        "drift after issue\n", encoding="utf-8"
    )
    created: list[FakeAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: created.append(FakeAdapter()) or created[-1],
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 2
    assert "drifted after issuance" in capsys.readouterr().err
    assert created == []
    assert not bridge._launch_is_committed(
        store.load_semantic_events(value.paths, "task-1"), "launch-1"
    )


def test_cli_read_only_rechecks_source_after_issue_before_reserve(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    monkeypatch.setattr(
        bridge.h, "claims_owned_by_task", lambda _paths, _task: value.claims
    )
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    (value.worktree / "src" / "tracked.txt").write_text(
        "read-only drift after issue\n", encoding="utf-8"
    )
    created: list[FakeAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: created.append(FakeAdapter()) or created[-1],
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 2
    assert "drifted after issuance" in capsys.readouterr().err
    assert created == []
    assert not bridge._launch_is_committed(
        store.load_semantic_events(value.paths, "task-1"), "launch-1"
    )


def test_cli_read_only_rechecks_full_claim_scope_before_reserve(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    value.claims.append(_additional_claim(value))
    created: list[FakeAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: created.append(FakeAdapter()) or created[-1],
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 2
    assert "complete live claim scope" in capsys.readouterr().err
    assert created == []
    assert not bridge._launch_is_committed(
        store.load_semantic_events(value.paths, "task-1"), "launch-1"
    )


def test_cli_read_only_rechecks_source_at_process_pending(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    monkeypatch.setattr(
        bridge.h, "claims_owned_by_task", lambda _paths, _task: value.claims
    )
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()

    class DriftBeforePendingAdapter(CallbackWrappingAdapter):
        def start(self) -> None:
            (value.worktree / "src" / "tracked.txt").write_text(
                "read-only drift at process pending\n", encoding="utf-8"
            )
            super().start()

    created: list[DriftBeforePendingAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: (
            created.append(DriftBeforePendingAdapter()) or created[-1]
        ),
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "failed"
    assert result["process_start_evidence"] == "not_started"
    assert result["app_server_start_durably_observed"] is False
    assert len(created) == 1
    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert [row["event_type"] for row in launch["journal"]] == [
        "reserved",
        "failed",
    ]


def test_cli_read_only_rechecks_full_claim_scope_at_process_pending(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()

    class ClaimDriftBeforePendingAdapter(CallbackWrappingAdapter):
        def start(self) -> None:
            value.claims.append(_additional_claim(value))
            super().start()

    created: list[ClaimDriftBeforePendingAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: (
            created.append(ClaimDriftBeforePendingAdapter()) or created[-1]
        ),
    )

    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "failed"
    assert result["process_start_evidence"] == "not_started"
    assert result["app_server_start_durably_observed"] is False
    assert len(created) == 1
    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert [row["event_type"] for row in launch["journal"]] == [
        "reserved",
        "failed",
    ]


def test_cli_expiry_crossing_before_pending_prevents_process_start(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    moments = iter(
        [
            datetime(2026, 7, 20, 0, 1, tzinfo=UTC),
            datetime(2100, 7, 20, 0, 1, tzinfo=UTC),
        ]
    )
    monkeypatch.setattr(bridge, "_now", lambda: next(moments))
    created: list[CallbackWrappingAdapter] = []

    def factory(*args: object, **kwargs: object) -> CallbackWrappingAdapter:
        adapter = CallbackWrappingAdapter()
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "failed"
    assert result["process_start_evidence"] == "not_started"
    assert result["app_server_start_durably_observed"] is False
    assert result["runtime_process_boundary_reached"] is False
    assert len(created) == 1
    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert [row["event_type"] for row in launch["journal"]] == [
        "reserved",
        "failed",
    ]


def test_cli_never_infers_physical_start_from_pending_only_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[StartedCallbackWrappingAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: created.append(StartedCallbackWrappingAdapter())
        or created[-1],
    )
    original_record = runtime.record_milestone

    def fail_started(*args: Any, **kwargs: Any) -> dict[str, Any]:
        milestone = kwargs.get("milestone")
        if isinstance(milestone, Mapping) and milestone.get("event_type") == "process_started":
            raise runtime.CodexTransportRuntimeError(
                "injected process_started persistence failure"
            )
        return original_record(*args, **kwargs)

    monkeypatch.setattr(runtime, "record_milestone", fail_started)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert created[0].physically_started is True
    assert result["terminal_state"] == "launch_unknown"
    assert result["process_start_evidence"] == "process_start_pending_only"
    assert result["app_server_start_durably_observed"] is False
    assert result["runtime_process_boundary_reached"] is True


def test_cli_exact_executable_override_is_checked_before_adapter(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[FakeAdapter] = []
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: created.append(FakeAdapter()) or created[-1],
    )
    assert bridge.main(
        _run_args(
            value,
            value.prompt_path,
            "--executable",
            (tmp_path / "other-codex-app-server").resolve().as_posix(),
        )
    ) == 2
    assert "differs from the sealed exact executable" in capsys.readouterr().err
    assert created == []


def test_local_files_bridge_blocks_confirmed_synced_state_root_before_issue(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, local_files=True)
    monkeypatch.setenv("ONEDRIVE", str(value.root))
    assert bridge.main(_issue_args(value)) == 2
    assert "AOI artifact/CAS root" in capsys.readouterr().err
    assert not runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    ).exists()


def test_local_files_bridge_blocks_mapped_state_root_before_issue(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, local_files=True)
    state_dir = value.paths.harness.resolve()
    monkeypatch.setattr(
        confidentiality,
        "_windows_volume_kind",
        lambda path: "network_path" if path.resolve(strict=False) == state_dir else None,
    )
    assert bridge.main(_issue_args(value)) == 2
    error = capsys.readouterr().err
    assert "AOI artifact/CAS root" in error
    assert "confirmed network storage" in error
    assert not runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    ).exists()


def test_local_files_bridge_blocks_unverified_workspace_cwd_before_issue(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, sandbox="workspaceWrite", local_files=True)
    worktree = value.worktree.resolve()
    monkeypatch.setattr(
        confidentiality,
        "_windows_volume_kind",
        lambda path: (
            "unverified_local_path"
            if path.resolve(strict=False) == worktree
            else None
        ),
    )
    assert bridge.main(_issue_args(value)) == 2
    error = capsys.readouterr().err
    assert "workspaceWrite cwd" in error
    assert "locality is unverified" in error
    assert not runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    ).exists()


def test_local_files_bridge_blocks_generic_reparse_state_root_before_issue(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, local_files=True)
    state_dir = value.paths.harness.resolve()
    monkeypatch.setattr(
        confidentiality,
        "_path_has_windows_reparse_attribute",
        lambda path: path.resolve(strict=False) == state_dir,
    )
    assert bridge.main(_issue_args(value)) == 2
    error = capsys.readouterr().err
    assert "AOI artifact/CAS root" in error
    assert "link/reparse point" in error
    assert not runtime._issuance_path(
        value.paths, "task-1", value.permit_sha256
    ).exists()


def test_concurrent_run_uses_one_controller_and_one_process_owner(
    tmp_path: Path, monkeypatch: Any
) -> None:
    value = _fixture(tmp_path)
    issue_args = bridge._parser().parse_args(_issue_args(value))
    bridge._issue(issue_args)
    entered = threading.Event()
    release = threading.Event()
    created: list[FakeAdapter] = []

    class BlockingAdapter(FakeAdapter):
        def start(self) -> None:
            self.on_process_start_pending(
                self._process("process_start_pending", None)
            )
            entered.set()
            assert release.wait(timeout=10)
            self.on_process_started(self._process("process_started", 42))

    def factory(*args: object, **kwargs: object) -> BlockingAdapter:
        adapter = BlockingAdapter()
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    run_args = bridge._parser().parse_args(_run_args(value, value.prompt_path))
    results: list[dict[str, Any]] = []
    failures: list[BaseException] = []

    def invoke() -> None:
        try:
            results.append(bridge._run(run_args))
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    first = threading.Thread(target=invoke)
    second = threading.Thread(target=invoke)
    first.start()
    assert entered.wait(timeout=10)
    second.start()
    assert second.is_alive()
    release.set()
    first.join(timeout=20)
    second.join(timeout=20)
    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert len(created) == 1
    assert len(results) == 2
    assert sorted(
        result["app_server_start_durably_observed"] for result in results
    ) == [False, True]
    assert len({result["terminal_receipt_sha256"] for result in results}) == 1


def test_core_packet_update_cannot_cancel_nonterminal_bridge_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _fixture(tmp_path)
    bridge._issue(bridge._parser().parse_args(_issue_args(value)))
    with h.state_lock(value.paths, create_layout=False):
        launch = bridge._load_or_reserve(
            value.paths,
            task_id="task-1",
            permit_sha256=value.permit_sha256,
            now=datetime(2026, 7, 20, 0, 1, tzinfo=UTC),
    )
    assert launch["journal"][-1]["event_type"] == "reserved"
    state = semantic.replay_events(store.load_semantic_events(value.paths, "task-1"))
    monkeypatch.setattr(core_cli, "load_task", lambda _paths, _task: state)
    monkeypatch.setattr(
        core_cli, "require_open_task", lambda _state, _operation: None
    )
    args = core_cli.build_parser().parse_args(
        [
            "packet-update",
            "--task",
            "task-1",
            "--packet-id",
            "packet-1",
            "--status",
            "cancelled",
            "--summary",
            "attempt generic cancellation",
        ]
    )
    with pytest.raises(h.HarnessError, match="launch is nonterminal"):
        core_cli.cmd_packet_update(args, value.paths)


@pytest.mark.parametrize(
    ("launch_state", "packet_status"),
    [
        ("completed", "done"),
        ("failed", "failed"),
        ("interrupted", "cancelled"),
    ],
)
def test_core_transport_terminal_packet_mapping_accepts_only_exact_status(
    launch_state: str, packet_status: str
) -> None:
    core_cli._require_codex_transport_packet_terminal_status(
        launch_state, packet_status
    )
    for wrong in {"done", "failed", "cancelled"} - {packet_status}:
        with pytest.raises(h.HarnessError, match="requires packet status"):
            core_cli._require_codex_transport_packet_terminal_status(
                launch_state, wrong
            )


@pytest.mark.parametrize("launch_state", ["launch_unknown", "runtime_unknown"])
@pytest.mark.parametrize("packet_status", ["done", "failed", "cancelled"])
def test_core_transport_unknown_never_becomes_terminal_packet(
    launch_state: str, packet_status: str
) -> None:
    with pytest.raises(h.HarnessError, match="reconcile the exact launch"):
        core_cli._require_codex_transport_packet_terminal_status(
            launch_state, packet_status
        )


def test_nonissuance_commands_scrub_reusable_authority_from_controller_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()

    commands = [
        _run_args(value, tmp_path / "missing-prompt.txt"),
        [
            "--root",
            str(value.root),
            "inspect",
            "--task",
            "task-1",
            "--launch-id",
            "launch-1",
            "--json",
        ],
        [
            "--root",
            str(value.root),
            "verify-mutation",
            "--task",
            "task-1",
            "--launch-id",
            "launch-1",
            "--json",
        ],
    ]
    secret_names = (
        "AOI_CHIEF_SESSION_ID",
        "AOI_CHIEF_EPOCH",
        "AOI_CHIEF_TOKEN",
        "AOI_CHIEF_CREDENTIAL_FILE",
        "GITHUB_PAT",
        "AZURE_DEVOPS_EXT_PAT",
        "DOCKER_AUTH_CONFIG",
    )
    for command in commands:
        for name in secret_names:
            monkeypatch.setenv(name, "must-not-survive")
        bridge.main(command)
        captured = capsys.readouterr()
        assert "must-not-survive" not in captured.out + captured.err
        assert not any(name in os.environ for name in secret_names)


def test_cli_read_only_runtime_cannot_be_elevated_to_verified_mutation(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path)
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    monkeypatch.setattr(
        bridge,
        "CodexAppServerStdio",
        lambda *args, **kwargs: FakeAdapter(),
    )
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    runtime_result = json.loads(capsys.readouterr().out)
    assert runtime_result["evidence_level"] == "codex_runtime_observed"

    assert bridge.main(
        [
            "--root",
            str(value.root),
            "verify-mutation",
            "--task",
            "task-1",
            "--launch-id",
            "launch-1",
            "--json",
        ]
    ) == 2
    assert "requires a workspaceWrite launch" in capsys.readouterr().err
    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert launch["terminal_receipt"]["evidence_level"] == (
        "codex_runtime_observed"
    )
    assert launch["verified_terminal_receipt"] is None


def test_cli_workspace_write_elevation_is_separate_committed_evidence(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    value = _fixture(tmp_path, sandbox="workspaceWrite")
    monkeypatch.setattr(
        bridge.h, "claims_owned_by_task", lambda _paths, _task: value.claims
    )
    missing_pre = _issue_args(value)
    pre_index = missing_pre.index("--pre-git-endpoint-file")
    del missing_pre[pre_index : pre_index + 2]
    assert bridge.main(missing_pre) == 2
    assert "requires --pre-git-endpoint-file" in capsys.readouterr().err
    assert bridge.main(_issue_args(value)) == 0
    capsys.readouterr()
    created: list[FakeAdapter] = []

    def factory(*args: object, **kwargs: object) -> FakeAdapter:
        adapter = FakeAdapter()
        created.append(adapter)
        return adapter

    monkeypatch.setattr(bridge, "CodexAppServerStdio", factory)
    assert bridge.main(_run_args(value, value.prompt_path)) == 0
    runtime_result = json.loads(capsys.readouterr().out)
    assert runtime_result["evidence_level"] == "codex_runtime_observed"

    (value.worktree / "src" / "tracked.txt").write_text(
        "after\n", encoding="utf-8"
    )
    verify_args = [
        "--root",
        str(value.root),
        "verify-mutation",
        "--task",
        "task-1",
        "--launch-id",
        "launch-1",
        "--pre-git-endpoint-file",
        str(value.pre_endpoint_path),
        "--json",
    ]
    original_append = mutation.store.append_semantic_transition

    def crash_before_verification_event(*args: object, **kwargs: object) -> object:
        raise store.SemanticStoreError("simulated mutation publication crash")

    monkeypatch.setattr(
        mutation.store, "append_semantic_transition", crash_before_verification_event
    )
    assert bridge.main(verify_args) == 2
    assert "publication crash" in capsys.readouterr().err
    pending_launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert pending_launch["terminal_receipt"]["evidence_level"] == "codex_runtime_observed"
    assert pending_launch["pending_verified_terminal_receipt"]["evidence_level"] == "verified_mutation"

    monkeypatch.setattr(mutation.store, "append_semantic_transition", original_append)
    assert bridge.main(verify_args) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["evidence_level"] == "verified_mutation"
    assert verified["task_completion"] == "not_inferred"
    assert verified["idempotent_replay"] is False

    # Once committed, later worktree drift cannot rewrite the sealed elevation;
    # inspection/retry returns the existing exact binding without recapture.
    (value.worktree / "src" / "tracked.txt").write_text(
        "later drift\n", encoding="utf-8"
    )
    assert bridge.main(verify_args) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["idempotent_replay"] is True
    assert replay["verified_terminal_receipt_sha256"] == verified[
        "verified_terminal_receipt_sha256"
    ]
    launch = runtime.load_codex_transport_launch(
        value.paths,
        "task-1",
        "launch-1",
        store.load_semantic_events(value.paths, "task-1"),
    )
    assert launch["terminal_receipt"]["evidence_level"] == "codex_runtime_observed"
    assert launch["verified_terminal_receipt"]["evidence_level"] == "verified_mutation"
    assert launch["task_completion"] == "not_inferred"
