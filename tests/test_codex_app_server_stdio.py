from __future__ import annotations

import json
import hashlib
import sys
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware import codex_app_server_stdio as stdio
from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware.codex_app_server_stdio import (
    AppServerError,
    CodexAppServerStdio,
    ProcessJournalEntry,
    ProtocolViolation,
    RequestJournalEntry,
    RequestPhase,
    ResponseSchemaViolation,
    RuntimeEvent,
    RuntimeDisconnected,
    RuntimePin,
    SealedLaunchIntent,
    ServerRequestDenied,
    scrub_aoi_secret_env,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


_FAKE_SERVER = r'''
import json
import os
import platform
import sys

scenario = os.environ.get("FAKE_SCENARIO", "normal")
if scenario == "stderr_flood":
    sys.stderr.write('{"level":"WARN","message":"plugin catalog"}' + "x" * 8192)
    sys.stderr.flush()

def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def read():
    line = sys.stdin.readline()
    if not line:
        raise SystemExit(0)
    return json.loads(line)

def response(request, result):
    send({"id": request["id"], "result": result})

init = read()
assert "jsonrpc" not in init
if scenario == "malformed":
    sys.stdout.write('{"id":1,"result":{},"result":{}}\n')
    sys.stdout.flush()
    raise SystemExit(0)
if scenario == "oversize":
    sys.stdout.write("x" * 4096 + "\n")
    sys.stdout.flush()
    raise SystemExit(0)
if scenario == "jsonrpc_envelope":
    send({"jsonrpc":"2.0","id":init["id"],"result":{}})
    raise SystemExit(0)
if scenario == "error_not_object":
    send({"id":init["id"],"error":"bad"})
    raise SystemExit(0)
if scenario == "error_bad_code":
    send({"id":init["id"],"error":{"code":True,"message":"bad"}})
    raise SystemExit(0)
if scenario == "error_bad_message":
    send({"id":init["id"],"error":{"code":-32000,"message":7}})
    raise SystemExit(0)
initialize_result = {
    "codexHome": os.path.abspath(os.environ.get("CODEX_HOME", os.getcwd())),
    "platformFamily": "windows" if os.name == "nt" else "unix",
    "platformOs": platform.system().lower(),
    "userAgent": "fake-codex-app-server/0.144.6",
    "secret_present": "AOI_CHIEF_CREDENTIAL_FILE" in os.environ,
    "publication_secret_present": "GITHUB_TOKEN" in os.environ,
}
if scenario == "invalid_initialize_response":
    initialize_result.pop("userAgent")
response(init, initialize_result)
assert read() == {"method":"initialized"}
send({"method":"remoteControl/status/changed","params":{"status":"ready"}})
if scenario == "flood":
    for _ in range(128):
        send({"method":"warning","params":{"message":"flood"}})

thread = read()
assert "jsonrpc" not in thread
if scenario == "eof_thread":
    raise SystemExit(0)
if scenario == "wrong_response":
    send({"id":999,"result":{}})
    raise SystemExit(0)
if scenario == "error_response":
    send({"id":thread["id"],"error":{"code":-32000,"message":"no"}})
    raise SystemExit(0)
thread_value = {
    "cliVersion": "0.144.6",
    "createdAt": 1,
    "cwd": thread["params"]["cwd"],
    "ephemeral": True,
    "id": "thread-1",
    "modelProvider": "openai",
    "preview": "",
    "sessionId": "session-1",
    "source": "appServer",
    "status": {"type":"idle"},
    "turns": [],
    "updatedAt": 1,
}
sandbox_type = "readOnly" if thread["params"]["sandbox"] == "read-only" else "workspaceWrite"
sandbox = {"type":sandbox_type,"networkAccess":False}
if sandbox_type == "workspaceWrite":
    sandbox["writableRoots"] = [thread["params"]["cwd"]]
thread_result = {
    "approvalPolicy": thread["params"]["approvalPolicy"],
    "approvalsReviewer": "user",
    "cwd": thread["params"]["cwd"],
    "model": thread["params"]["model"],
    "modelProvider": "openai",
    "sandbox": sandbox,
    "thread": thread_value,
}
if scenario == "invalid_thread_response":
    thread_result.pop("approvalsReviewer")
if scenario == "thread_context_drift":
    thread_result["model"] = "other-model"
send({"method":"thread/started","params":{"thread":thread_value}})
response(thread, thread_result)
if scenario == "auxiliary_notifications":
    send({"method":"thread/status/changed","params":{"threadId":"thread-1","status":"active"}})

turn = read()
assert "jsonrpc" not in turn
if scenario == "server_request":
    send({"id":55,"method":"tool/requestUserInput","params":{}})
    raise SystemExit(0)
if scenario == "bad_notification":
    send({"method":"unknown/event","params":{}})
    raise SystemExit(0)
turn_value = {"id":"turn-1","items":[],"status":"inProgress"}
if scenario == "wrong_correlation":
    send({"method":"turn/started","params":{"threadId":"other","turn":turn_value}})
else:
    send({"method":"turn/started","params":{"threadId":"thread-1","turn":turn_value}})
if scenario == "auxiliary_wrong_thread":
    send({"method":"thread/status/changed","params":{"threadId":"other","status":"active"}})
if scenario == "auxiliary_wrong_turn":
    send({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"other","itemId":"item-1","delta":"wrong turn"}})
if scenario == "auxiliary_item_without_turn":
    send({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","itemId":"item-1","delta":"missing turn"}})
turn_result = {"turn":turn_value}
if scenario == "invalid_turn_response":
    turn_result = {"turn":{"id":"turn-1","status":"inProgress"}}
if scenario == "turn_status_drift":
    turn_result = {"turn":{"id":"turn-1","items":[],"status":"completed"}}
response(turn, turn_result)
if scenario == "auxiliary_notifications":
    send({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":"not persisted by AOI"}})
    send({"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":{"totalTokens":1}}})
if scenario == "interrupt_active":
    interrupt = read()
    assert "jsonrpc" not in interrupt
    response(interrupt, {})
    send({"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","items":[],"status":"interrupted"}}})
    raise SystemExit(0)
if scenario == "midstream_eof":
    send({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":2,"item":{"id":"item-1","type":"agentMessage","text":"partial"}}})
    raise SystemExit(0)
item = {"id":"item-1","type":"agentMessage","text":"ok"}
started = {"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":2,"item":item}}
completed = {"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","completedAtMs":3,"item":item}}
if scenario == "invalid_item_notification":
    started["params"].pop("startedAtMs")
send(started)
if scenario == "duplicate_conflict":
    item["text"] = "different"
    send({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","item":item}})
elif scenario == "duplicate_exact":
    send(started)
send(completed)
send({"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","items":[item],"status":"completed"}}})
if scenario == "interrupt":
    interrupt = read()
    assert "jsonrpc" not in interrupt
    response(interrupt, {})
'''


@pytest.fixture
def fake_server(tmp_path: Path) -> Path:
    script = tmp_path / "fake_app_server.py"
    script.write_text(_FAKE_SERVER, encoding="utf-8")
    return script


def _fake_runtime_pin(
    *,
    executable_sha256: str | None = None,
    executable_size_bytes: int | None = None,
    app_server_version: str = "fake-app-server 0.144.6",
) -> RuntimePin:
    executable = Path(sys.executable).resolve()
    binding = contracts.pinned_runtime_binding()
    return RuntimePin(
        codex_cli_version=str(binding["codex_cli_version"]),
        executable_sha256=executable_sha256 or hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_size_bytes=(
            executable.stat().st_size
            if executable_size_bytes is None
            else executable_size_bytes
        ),
        app_server_version=app_server_version,
        schema_manifest_sha256=str(binding["schema_manifest_sha256"]),
        combined_v2_schema_sha256=str(binding["combined_v2_schema_sha256"]),
    )


def _client(fake_server: Path, tmp_path: Path, scenario: str = "normal", **kwargs: Any) -> CodexAppServerStdio:
    env = {"FAKE_SCENARIO": scenario, "AOI_CHIEF_CREDENTIAL_FILE": "must-not-leak", "GITHUB_TOKEN": "must-not-leak", "SAFE_VALUE": "yes"}
    runtime_pin = kwargs.pop(
        "runtime_pin",
        _fake_runtime_pin(),
    )
    return CodexAppServerStdio(
        Path(sys.executable).resolve(),
        cwd=tmp_path,
        environment=env,
        max_line_bytes=1024,
        runtime_pin=runtime_pin,  # type: ignore[arg-type]
        _test_launch_args=("-u", str(fake_server)),
        _test_version_args=("-c", "print('fake-app-server 0.144.6')"),
        **kwargs,
    )


def _intent_payload(
    tmp_path: Path,
    *,
    sandbox: str = "readOnly",
    prompt: str = "hello",
    executable: Path | None = None,
) -> dict[str, object]:
    prompt_bytes = prompt.encode("utf-8")
    return {
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
        "expected_semantic_head_sha256": SHA_D,
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "prompt_size_bytes": len(prompt_bytes),
        "cwd": tmp_path.resolve().as_posix(),
        "requested_model": "gpt-5.6",
        "requested_effort": "medium",
        "sandbox": sandbox,
        "approval": "never",
        "runtime_pin": {
            **contracts.pinned_runtime_binding(),
            "executable_path": (executable or Path(sys.executable)).resolve().as_posix(),
        },
        "pre_git_binding": {
            "git_head_sha256": SHA_A,
            "git_tree_sha256": SHA_B,
            "git_status_sha256": SHA_C,
            "claim_coverage_sha256": SHA_D,
        },
    }


def _intent(
    tmp_path: Path,
    *,
    sandbox: str = "readOnly",
    prompt: str = "hello",
    executable: Path | None = None,
) -> SealedLaunchIntent:
    sealed = contracts.seal_launch_intent(
        _intent_payload(
            tmp_path,
            sandbox=sandbox,
            prompt=prompt,
            executable=executable,
        )
    )
    return SealedLaunchIntent.from_sealed_mapping(
        sealed, expected_sha256=str(sealed["intent_sha256"])
    )


def _initialized_client(fake_server: Path, tmp_path: Path, scenario: str = "normal", **kwargs: Any) -> CodexAppServerStdio:
    client = _client(fake_server, tmp_path, scenario, **kwargs)
    client.start()
    initialized = client.initialize()
    assert initialized["secret_present"] is False
    assert initialized["publication_secret_present"] is False
    return client


def test_default_launch_is_exact_standalone_stdio_and_scrubs_secret_env(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    client = CodexAppServerStdio(executable, cwd=tmp_path)
    assert client.argv == (str(executable), "--listen", "stdio://")
    scrubbed = scrub_aoi_secret_env({"AOI_CHIEF_EPOCH": "secret", "aoi_chief_credential_file": "secret", "GITHUB_TOKEN": "secret", "GITHUB_PAT": "secret", "AZURE_DEVOPS_EXT_PAT": "secret", "DOCKER_AUTH_CONFIG": "secret", "TWINE_PASSWORD": "secret", "OPENAI_API_KEY": "model-control", "SAFE": "1"})
    assert scrubbed == {"OPENAI_API_KEY": "model-control", "SAFE": "1"}


def test_constructor_rejects_symlinked_executable(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("creating a symlink is not a portable unprivileged Windows test")
    executable_link = tmp_path / "codex-app-server-link"
    executable_link.symlink_to(Path(sys.executable).resolve())
    with pytest.raises(ValueError, match="must not be a symlink"):
        CodexAppServerStdio(executable_link, cwd=tmp_path)


def test_pinned_notification_and_item_allowlists_match_generated_schema() -> None:
    root = (
        Path(contracts.__file__).resolve().parent
        / "resources"
        / "codex_app_server"
        / "0.144.6"
    )
    schema = json.loads(
        (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    )
    notification_methods = {
        entry["properties"]["method"]["enum"][0]
        for entry in schema["definitions"]["ServerNotification"]["oneOf"]
    }
    item_types = {
        entry["properties"]["type"]["enum"][0]
        for entry in schema["definitions"]["ThreadItem"]["oneOf"]
    }
    assert stdio._NOTIFICATION_METHODS == notification_methods
    assert stdio._ITEM_TYPES == item_types
    assert stdio._THREAD_START_RESPONSE_REQUIRED == frozenset(
        schema["definitions"]["ThreadStartResponse"]["required"]
    )
    assert stdio._THREAD_REQUIRED == frozenset(
        schema["definitions"]["Thread"]["required"]
    )
    assert stdio._TURN_REQUIRED == frozenset(
        schema["definitions"]["Turn"]["required"]
    )
    item_required = {
        variant["properties"]["type"]["enum"][0]: frozenset(
            variant["required"]
        )
        for variant in schema["definitions"]["ThreadItem"]["oneOf"]
    }
    assert stdio._THREAD_ITEM_REQUIRED_FIELDS == item_required
    assert stdio._INITIALIZE_RESPONSE_REQUIRED == frozenset(
        {"codexHome", "platformFamily", "platformOs", "userAgent"}
    )


def test_pinned_rpc_envelopes_do_not_define_jsonrpc_member() -> None:
    root = (
        Path(contracts.__file__).resolve().parent
        / "resources"
        / "codex_app_server"
        / "0.144.6"
    )
    schema = json.loads(
        (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    )
    for definition in ("ClientRequest", "ServerNotification"):
        for variant in schema["definitions"][definition]["oneOf"]:
            assert "jsonrpc" not in variant["properties"]
            assert "jsonrpc" not in variant["required"]
    manifest = {
        entry["path"]: entry["sha256"]
        for entry in json.loads((root / "schema-manifest.json").read_bytes())
    }
    assert manifest["ClientNotification.json"] == (
        "a30b3041578845b11add3d07d5a63cd3a12d5d126e87b8c591862b4aeb68d97c"
    )
    assert manifest["v1/InitializeResponse.json"] == (
        "86dcd236d0576a82c85b933586dc45731260eab1b6edb3447b03f790277322b1"
    )
    assert manifest["JSONRPCResponse.json"] == (
        "94ecf5e81bdbc2af858afad0044b95c7fb4decf77d7fd7d6321324dad79eef57"
    )


def test_lifecycle_buffers_event_before_response_and_records_aggregate(fake_server: Path, tmp_path: Path) -> None:
    pending: list[RequestJournalEntry] = []
    process_entries: list[ProcessJournalEntry] = []
    client = _initialized_client(
        fake_server,
        tmp_path,
        on_process_start_pending=process_entries.append,
        on_process_started=process_entries.append,
        on_send_pending=pending.append,
    )
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(thread_id=thread_id, prompt="hello", intent=intent)
        observation = client.observe_turn(thread_id=thread_id, turn_id=turn_id, timeout_seconds=3)
        assert observation.terminal_status == "completed"
        assert [event.method for event in observation.events][-1] == "turn/completed"
        assert all(event.wire_bytes.endswith(b"\n") for event in observation.events)
        assert all(
            hashlib.sha256(event.wire_bytes).hexdigest() == event.sha256
            for event in observation.events
        )
        assert all(
            "jsonrpc" not in json.loads(event.wire_bytes)
            for event in observation.events
        )
        assert client.event_count == 6  # remote, thread, turn, item start/completed, terminal
        assert len(client.event_digest) == 64
        assert len(client.stderr_digest) == 64
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.RESPONSE_RECEIVED
        assert [entry.phase for entry in process_entries] == [
            "process_start_pending",
            "process_started",
        ]
        assert process_entries[0].pid is None
        assert isinstance(process_entries[1].pid, int)
        assert len(process_entries[0].sha256) == 64
        sent = {
            entry.method: json.loads(entry.wire_bytes)["params"]
            for entry in pending
            if entry.method in {"thread/start", "turn/start"}
        }
        assert all(
            "jsonrpc" not in json.loads(entry.wire_bytes) for entry in pending
        )
        assert sent["thread/start"] == {
            "cwd": tmp_path.resolve().as_posix(),
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "serviceName": "aoi-orgware",
            "ephemeral": True,
            "model": "gpt-5.6",
        }
        assert sent["turn/start"]["sandboxPolicy"] == {
            "type": "readOnly",
            "networkAccess": False,
        }
        assert sent["turn/start"]["cwd"] == tmp_path.resolve().as_posix()
        assert sent["turn/start"]["effort"] == "medium"
    finally:
        client.close()


def test_pinned_auxiliary_notifications_do_not_break_lifecycle(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path, "auxiliary_notifications")
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )
        observation = client.observe_turn(
            thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
        )
        assert observation.terminal_status == "completed"
        assert "item/agentMessage/delta" in {
            event.method for event in observation.events
        }
        assert "thread/tokenUsage/updated" in {
            event.method for event in observation.events
        }
    finally:
        client.close()


def test_wrong_response_id_fails_closed(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path, "wrong_response")
    try:
        with pytest.raises(ProtocolViolation):
            client.start_thread_from_intent(intent=_intent(tmp_path))
    finally:
        client.close()


@pytest.mark.parametrize("scenario", ["bad_notification", "wrong_correlation"])
def test_wrong_notification_method_or_correlation_fails_closed(fake_server: Path, tmp_path: Path, scenario: str) -> None:
    client = _initialized_client(fake_server, tmp_path, scenario)
    try:
        intent = _intent(tmp_path)
        assert client.start_thread_from_intent(intent=intent) == "thread-1"
        with pytest.raises(ProtocolViolation):
            client.start_turn_from_intent(thread_id="thread-1", prompt="hello", intent=intent)
    finally:
        client.close()


@pytest.mark.parametrize(
    "scenario",
    [
        "auxiliary_wrong_thread",
        "auxiliary_wrong_turn",
        "auxiliary_item_without_turn",
    ],
)
def test_scoped_auxiliary_notification_correlation_fails_closed(
    fake_server: Path, tmp_path: Path, scenario: str
) -> None:
    client = _initialized_client(fake_server, tmp_path, scenario)
    try:
        intent = _intent(tmp_path)
        assert client.start_thread_from_intent(intent=intent) == "thread-1"
        with pytest.raises(ProtocolViolation, match="auxiliary"):
            client.start_turn_from_intent(
                thread_id="thread-1", prompt="hello", intent=intent
            )
    finally:
        client.close()


def test_auxiliary_event_identity_binds_explicit_correlation_ids() -> None:
    def event(params: dict[str, object]) -> RuntimeEvent:
        return RuntimeEvent("item/agentMessage/delta", params, "a" * 64, b"wire")

    first = stdio._event_identity(
        event(
            {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "itemId": "item-1",
                "delta": "first",
            }
        )
    )
    changed_thread = stdio._event_identity(
        event(
            {
                "threadId": "thread-2",
                "turnId": "turn-1",
                "itemId": "item-1",
                "delta": "first",
            }
        )
    )
    assert first[0] == "item/agentMessage/delta"
    assert "thread=thread-1;turn=turn-1;item=item-1;payload=" in first[1]
    assert first != changed_thread


@pytest.mark.parametrize("scenario", ["malformed", "oversize"])
def test_malformed_duplicate_key_or_oversize_stdout_fails_closed(fake_server: Path, tmp_path: Path, scenario: str) -> None:
    client = _client(fake_server, tmp_path, scenario)
    client.start()
    try:
        with pytest.raises(ProtocolViolation):
            client.initialize()
    finally:
        client.close()


def test_jsonrpc_tagged_envelope_is_rejected_against_pinned_framing(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _client(fake_server, tmp_path, "jsonrpc_envelope")
    client.start()
    try:
        with pytest.raises(ProtocolViolation, match="must not contain jsonrpc"):
            client.initialize()
    finally:
        client.close()


@pytest.mark.parametrize(
    "scenario", ["error_not_object", "error_bad_code", "error_bad_message"]
)
def test_malformed_error_envelope_is_rejected_before_response_observation(
    fake_server: Path, tmp_path: Path, scenario: str
) -> None:
    responses: list[RequestJournalEntry] = []
    client = _client(fake_server, tmp_path, scenario, on_response=responses.append)
    client.start()
    try:
        with pytest.raises(ProtocolViolation, match="response error"):
            client.initialize()
        assert responses == []
    finally:
        client.close()


def test_initialize_success_response_is_schema_validated_before_observation(
    fake_server: Path, tmp_path: Path
) -> None:
    responses: list[RequestJournalEntry] = []
    client = _client(
        fake_server,
        tmp_path,
        "invalid_initialize_response",
        on_response=responses.append,
    )
    client.start()
    try:
        with pytest.raises(ResponseSchemaViolation, match="pinned initialize") as caught:
            client.initialize()
        assert responses == []
        assert len(caught.value.evidence_sha256) == 64
        assert caught.value.evidence_size_bytes > 0
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


@pytest.mark.parametrize(
    "scenario", ["invalid_thread_response", "thread_context_drift"]
)
def test_thread_success_response_schema_and_intent_drift_fail_before_observation(
    fake_server: Path, tmp_path: Path, scenario: str
) -> None:
    client = _initialized_client(fake_server, tmp_path, scenario)
    responses: list[RequestJournalEntry] = []
    client.on_response = responses.append
    try:
        with pytest.raises(ResponseSchemaViolation, match="pinned thread/start"):
            client.start_thread_from_intent(intent=_intent(tmp_path))
        assert responses == []
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


@pytest.mark.parametrize(
    "scenario", ["invalid_turn_response", "turn_status_drift"]
)
def test_turn_success_response_schema_fails_before_observation(
    fake_server: Path, tmp_path: Path, scenario: str
) -> None:
    client = _initialized_client(fake_server, tmp_path, scenario)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        responses: list[RequestJournalEntry] = []
        client.on_response = responses.append
        with pytest.raises(ResponseSchemaViolation, match="pinned turn/start"):
            client.start_turn_from_intent(
                thread_id=thread_id, prompt="hello", intent=intent
            )
        assert responses == []
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


def test_thread_response_eof_preserves_send_pending_ambiguity(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path, "eof_thread")
    try:
        with pytest.raises(RuntimeDisconnected):
            client.start_thread_from_intent(intent=_intent(tmp_path))
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


def test_server_user_input_request_is_fail_closed(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path, "server_request")
    try:
        intent = _intent(tmp_path)
        assert client.start_thread_from_intent(intent=intent) == "thread-1"
        with pytest.raises(ServerRequestDenied):
            client.start_turn_from_intent(thread_id="thread-1", prompt="hello", intent=intent)
    finally:
        client.close()


def test_midstream_eof_and_duplicate_event_variants(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path, "midstream_eof")
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(thread_id=thread_id, prompt="hello", intent=intent)
        with pytest.raises(RuntimeDisconnected):
            client.observe_turn(thread_id=thread_id, turn_id=turn_id, timeout_seconds=3)
    finally:
        client.close()

    exact = _initialized_client(fake_server, tmp_path, "duplicate_exact")
    try:
        intent = _intent(tmp_path)
        thread_id = exact.start_thread_from_intent(intent=intent)
        turn_id = exact.start_turn_from_intent(thread_id=thread_id, prompt="hello", intent=intent)
        assert exact.observe_turn(thread_id=thread_id, turn_id=turn_id, timeout_seconds=3).terminal_status == "completed"
    finally:
        exact.close()

    conflicting = _initialized_client(fake_server, tmp_path, "duplicate_conflict")
    try:
        intent = _intent(tmp_path)
        thread_id = conflicting.start_thread_from_intent(intent=intent)
        turn_id = conflicting.start_turn_from_intent(thread_id=thread_id, prompt="hello", intent=intent)
        with pytest.raises(ProtocolViolation, match="conflicting duplicate"):
            conflicting.observe_turn(thread_id=thread_id, turn_id=turn_id, timeout_seconds=3)
    finally:
        conflicting.close()


def test_lifecycle_notification_required_fields_follow_pinned_schema(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path, "invalid_item_notification")
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        with pytest.raises(ProtocolViolation, match="startedAtMs"):
            turn_id = client.start_turn_from_intent(
                thread_id=thread_id, prompt="hello", intent=intent
            )
            client.observe_turn(
                thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
            )
    finally:
        client.close()


def test_interrupt_is_correlated_only_while_turn_is_active(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path, "interrupt_active")
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(thread_id=thread_id, prompt="hello", intent=intent)
        assert client.interrupt_turn(thread_id=thread_id, turn_id=turn_id) == {}
        assert client.observe_turn(thread_id=thread_id, turn_id=turn_id, timeout_seconds=3).terminal_status == "interrupted"
        with pytest.raises(AppServerError, match="active MVP turn"):
            client.interrupt_turn(thread_id=thread_id, turn_id=turn_id)
    finally:
        client.close()


def test_send_pending_callback_precedes_write_and_response_callback_precedes_error(fake_server: Path, tmp_path: Path) -> None:
    pending: list[RequestJournalEntry] = []

    def reject_before_write(entry: RequestJournalEntry) -> None:
        pending.append(entry)
        raise RuntimeError("journal unavailable")

    client = _client(fake_server, tmp_path, on_send_pending=reject_before_write)
    client.start()
    try:
        with pytest.raises(AppServerError, match="request was not written"):
            client.initialize()
        assert len(pending) == 1
        assert client.last_receipt is not None and client.last_receipt.phase is RequestPhase.BEFORE_SEND
    finally:
        client.close()

    responses: list[RequestJournalEntry] = []
    error_client = _initialized_client(fake_server, tmp_path, "error_response")
    error_client.on_response = responses.append
    try:
        with pytest.raises(AppServerError, match="error response"):
            error_client.start_thread_from_intent(intent=_intent(tmp_path))
        assert len(responses) == 1
        assert b'"error"' in responses[0].wire_bytes
        assert len(responses[0].sha256) == 64
    finally:
        error_client.close()


def test_process_callbacks_bracket_every_child_process_and_fail_closed(
    fake_server: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pending: list[ProcessJournalEntry] = []
    version_probe_called = False

    original_run = stdio.subprocess.run

    def observed_run(*args: Any, **kwargs: Any) -> Any:
        nonlocal version_probe_called
        version_probe_called = True
        return original_run(*args, **kwargs)

    monkeypatch.setattr(stdio.subprocess, "run", observed_run)

    def reject_before_popen(entry: ProcessJournalEntry) -> None:
        pending.append(entry)
        raise RuntimeError("journal unavailable")

    before = _client(
        fake_server,
        tmp_path,
        on_process_start_pending=reject_before_popen,
    )
    with pytest.raises(AppServerError, match="process was not started"):
        before.start()
    assert len(pending) == 1
    assert pending[0].phase == "process_start_pending"
    assert pending[0].pid is None
    assert version_probe_called is False

    started: list[ProcessJournalEntry] = []

    def reject_after_popen(entry: ProcessJournalEntry) -> None:
        started.append(entry)
        raise RuntimeError("journal unavailable")

    after = _client(
        fake_server,
        tmp_path,
        on_process_started=reject_after_popen,
    )
    with pytest.raises(AppServerError, match="process was terminated"):
        after.start()
    assert len(started) == 1
    assert started[0].phase == "process_started"
    assert isinstance(started[0].pid, int)
    after.close()


def test_runtime_pin_version_and_intent_validation_fail_closed(fake_server: Path, tmp_path: Path) -> None:
    bad_hash = _client(
        fake_server,
        tmp_path,
        runtime_pin=_fake_runtime_pin(executable_sha256="0" * 64),
    )
    with pytest.raises(AppServerError, match="SHA-256"):
        bad_hash.start()
    bad_size = _client(
        fake_server,
        tmp_path,
        runtime_pin=_fake_runtime_pin(executable_size_bytes=1),
    )
    with pytest.raises(AppServerError, match="size"):
        bad_size.start()
    bad_version = _client(
        fake_server,
        tmp_path,
        runtime_pin=_fake_runtime_pin(app_server_version="different"),
    )
    with pytest.raises(AppServerError, match="--version"):
        bad_version.start()
    tampered = contracts.seal_launch_intent(_intent_payload(tmp_path))
    tampered["prompt_size_bytes"] = 1
    with pytest.raises(ProtocolViolation, match="intent_sha256"):
        SealedLaunchIntent.from_sealed_mapping(tampered)


def test_prompt_executable_and_cwd_must_match_sealed_intent(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        with pytest.raises(ProtocolViolation, match="prompt bytes"):
            client.start_turn_from_intent(thread_id=thread_id, prompt="different", intent=intent)
    finally:
        client.close()

    wrong_executable = _initialized_client(fake_server, tmp_path)
    try:
        with pytest.raises(ProtocolViolation, match="executable path"):
            wrong_executable.start_thread_from_intent(
                intent=_intent(tmp_path, executable=tmp_path / "other-app-server.exe")
            )
    finally:
        wrong_executable.close()

    other_cwd = tmp_path / "other-cwd"
    other_cwd.mkdir()
    wrong_cwd = _initialized_client(fake_server, tmp_path)
    try:
        with pytest.raises(ProtocolViolation, match="cwd"):
            wrong_cwd.start_thread_from_intent(intent=_intent(other_cwd))
    finally:
        wrong_cwd.close()


def test_workspace_write_policy_is_exact_and_network_closed(fake_server: Path, tmp_path: Path) -> None:
    pending: list[RequestJournalEntry] = []
    client = _initialized_client(fake_server, tmp_path, on_send_pending=pending.append)
    try:
        intent = _intent(tmp_path, sandbox="workspaceWrite")
        thread_id = client.start_thread_from_intent(intent=intent)
        client.start_turn_from_intent(thread_id=thread_id, prompt="hello", intent=intent)
        sent = {
            entry.method: json.loads(entry.wire_bytes)["params"]
            for entry in pending
            if entry.method in {"thread/start", "turn/start"}
        }
        assert sent["thread/start"]["sandbox"] == "workspace-write"
        assert sent["turn/start"]["sandboxPolicy"] == {
            "type": "workspaceWrite",
            "networkAccess": False,
            "writableRoots": [tmp_path.resolve().as_posix()],
            "excludeSlashTmp": True,
            "excludeTmpdirEnvVar": True,
        }
    finally:
        client.close()


def test_cardinality_flood_and_stderr_metadata_are_bounded(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        assert client.start_thread_from_intent(intent=intent) == "thread-1"
        with pytest.raises(AppServerError, match="one thread/start"):
            client.start_thread_from_intent(intent=intent)
        assert client.start_turn_from_intent(thread_id="thread-1", prompt="hello", intent=intent) == "turn-1"
        with pytest.raises(AppServerError, match="one turn/start"):
            client.start_turn_from_intent(thread_id="thread-1", prompt="again", intent=intent)
    finally:
        client.close()

    flooded = _client(fake_server, tmp_path, "flood", max_queue_messages=2)
    flooded.start()
    try:
        assert flooded.initialize()["secret_present"] is False
        with pytest.raises(ProtocolViolation, match="queue/backpressure"):
            flooded.start_thread_from_intent(intent=_intent(tmp_path))
    finally:
        flooded.close()

    stderr_client = _initialized_client(fake_server, tmp_path, "stderr_flood", max_stderr_bytes=32)
    stderr_client.close()
    metadata = stderr_client.runtime_metadata
    assert metadata["stderr_total_bytes"] > 32
    assert metadata["stderr_truncated"] is True
    assert len(str(metadata["stderr_sha256"])) == 64
