from __future__ import annotations

import io
import json
import hashlib
import math
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, NoReturn, cast

import pytest

from aoi_orgware import codex_app_server_stdio as stdio
from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware.company.codex_adapter import (
    ThreadTokenUsageUpdated,
    parse_codex_notification,
)
from aoi_orgware.codex_app_server_stdio import (
    AppServerError,
    AppServerLaunchSpec,
    AppServerResponseError,
    ClientNotificationJournalEntry,
    ClientNotificationPhase,
    CodexAppServerStdio,
    ProcessJournalEntry,
    ProtocolViolation,
    RequestJournalEntry,
    RequestPhase,
    ModelCatalogViolation,
    ModelReroutedViolation,
    ResponsePolicyViolation,
    ResponseSchemaViolation,
    RejectedNotificationWire,
    RuntimeEvent,
    RuntimeDisconnected,
    RuntimePin,
    SealedLaunchIntent,
    ServerRequestDenied,
    VersionProbeJournalEntry,
    scrub_aoi_secret_env,
)
from aoi_orgware.codex_transport_controller import CodexTransportController


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


_FAKE_SERVER = r'''
import json
import os
import platform
import sys
import time

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
    "userAgent": "fake-codex-app-server/0.145.0",
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

model_list = read()
assert model_list["method"] == "model/list"
assert model_list["params"] == {"includeHidden":True,"limit":100}
model_row = {
    "defaultReasoningEffort": "medium",
    "description": "fake model",
    "displayName": "GPT-5.6-Terra",
    "hidden": False,
    "id": "gpt-5.6-terra",
    "isDefault": True,
    "model": "gpt-5.6-terra",
    "supportedReasoningEfforts": [
        {"description":"Medium","reasoningEffort":"medium"},
        {"description":"High","reasoningEffort":"high"},
    ],
}
model_result = {"data":[model_row],"nextCursor":None}
if scenario == "invalid_model_response":
    model_row.pop("supportedReasoningEfforts")
if scenario == "model_missing":
    model_row["model"] = "gpt-5.6-sol"
if scenario == "model_hidden":
    model_row["hidden"] = True
if scenario == "model_duplicate":
    model_result["data"].append(dict(model_row))
if scenario == "model_effort_missing":
    model_row["supportedReasoningEfforts"] = [
        {"description":"High","reasoningEffort":"high"}
    ]
if scenario == "model_paginated":
    model_result["nextCursor"] = "more"
if scenario == "eof_model":
    raise SystemExit(0)
response(model_list, model_result)

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
    "cliVersion": "0.145.0",
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
reroute = {
    "method":"model/rerouted",
    "params":{
        "fromModel":"gpt-5.6-terra",
        "reason":"highRiskCyberActivity",
        "threadId":"thread-1",
        "toModel":"reroute-secret-model",
        "turnId":"turn-1",
    },
}
if scenario == "model_rerouted_buffered":
    send(reroute)
if scenario == "model_rerouted_nonobject_buffered":
    send({"method":"model/rerouted","params":"payload-secret"})
response(turn, turn_result)
if scenario == "model_rerouted_live":
    send(reroute)
    send({"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","items":[],"status":"completed"}}})
    raise SystemExit(0)
if scenario == "auxiliary_notifications":
    send({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":"not persisted by AOI"}})
    token_vector = {"inputTokens":1,"cachedInputTokens":0,"outputTokens":2,"reasoningOutputTokens":0,"totalTokens":3}
    send({"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","turnId":"turn-1","tokenUsage":{"total":token_vector,"last":token_vector}}})
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
if scenario == "model_rerouted_after_stdin_eof":
    assert sys.stdin.readline() == ""
    send(reroute)
    raise SystemExit(0)
if scenario == "nonzero_after_completion":
    raise SystemExit(7)
if scenario == "hang_after_stdin_eof":
    assert sys.stdin.readline() == ""
    time.sleep(30)
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
    app_server_version: str = "fake-app-server 0.145.0",
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
    env = dict(
        kwargs.pop(
            "environment",
            {
                "AOI_CHIEF_CREDENTIAL_FILE": "must-not-leak",
                "GITHUB_TOKEN": "must-not-leak",
                "SAFE_VALUE": "yes",
            },
        )
    )
    env["FAKE_SCENARIO"] = scenario
    runtime_pin = kwargs.pop(
        "runtime_pin",
        _fake_runtime_pin(),
    )
    max_line_bytes = int(kwargs.pop("max_line_bytes", 1024))
    version_args = cast(
        tuple[str, ...],
        kwargs.pop(
            "_test_version_args",
            ("-c", "print('fake-app-server 0.145.0')"),
        ),
    )
    return CodexAppServerStdio(
        Path(sys.executable).resolve(),
        cwd=tmp_path,
        environment=env,
        max_line_bytes=max_line_bytes,
        runtime_pin=runtime_pin,  # type: ignore[arg-type]
        _test_launch_args=("-u", str(fake_server)),
        _test_version_args=version_args,
        **kwargs,
    )


def _write_local_files_codex_home(path: Path) -> None:
    path.mkdir()
    (path / "auth.json").write_text("{}\n", encoding="utf-8")
    (path / "config.toml").write_text(
        'web_search = "disabled"\n'
        "[features]\n"
        "apps = false\n"
        "remote_plugin = false\n"
        "multi_agent = false\n"
        "[apps._default]\n"
        "enabled = false\n",
        encoding="utf-8",
    )
    (path / "managed_config.toml").write_text(
        "allow_remote_control = false\n"
        "allowed_web_search_modes = []\n"
        "[features]\n"
        "apps = false\n"
        "remote_plugin = false\n"
        "multi_agent = false\n",
        encoding="utf-8",
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
        "requested_model": "gpt-5.6-terra",
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


def _version_probe_controller(
    tmp_path: Path,
) -> tuple[CodexTransportController, list[dict[str, Any]]]:
    intent = contracts.seal_launch_intent(_intent_payload(tmp_path))
    reservation = contracts.seal_reservation(
        {
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1,
            "reservation_id": "version-probe-boundary",
            "launch_intent_sha256": intent["intent_sha256"],
            "permit_sha256": SHA_C,
            "runtime_pin": intent["runtime_pin"],
            "state": "reserved",
            "correlation": {
                "thread_id": None,
                "turn_id": None,
                "item_id": None,
            },
        }
    )
    reserved = contracts.seal_journal_event(
        {
            "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
            "event_id": "version-probe-boundary:1:reserved",
            "sequence": 1,
            "prev_event_sha256": contracts.ZERO_SHA256,
            "launch_intent_sha256": intent["intent_sha256"],
            "reservation_sha256": reservation["reservation_sha256"],
            "event_type": "reserved",
            "state": "reserved",
            "wire_method": "aoi/reservation",
            "wire_event_sha256": None,
            "payload_size_bytes": 0,
            "item_type": None,
            "status": "observed",
            "request_id": None,
            "request_bytes_sha256": None,
            "response_sha256": None,
            "fault_kind": None,
            "fault_evidence_sha256": None,
            "fault_evidence_size_bytes": None,
            "correlation": {
                "thread_id": None,
                "turn_id": None,
                "item_id": None,
            },
        }
    )
    durable = [reserved]

    def persist(event: Mapping[str, Any]) -> list[dict[str, Any]]:
        durable[:] = contracts.append_transport_journal_event(durable, event)
        return list(durable)

    controller = CodexTransportController(
        intent=intent,
        reservation=reservation,
        journal=durable,
        persist_milestone=persist,
        publish_terminal=lambda receipt: dict(receipt),
        persist_fault_evidence=lambda data, _label: {
            "path": "local-cas",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        },
    )
    return controller, durable


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
    assert client.argv == (
        str(executable),
        "--strict-config",
        "--config",
        'web_search="disabled"',
        "--config",
        "features.apps=false",
        "--config",
        "features.remote_plugin=false",
        "--config",
        "features.multi_agent=false",
        "--config",
        "apps._default.enabled=false",
        "--listen",
        "stdio://",
    )
    scrubbed = scrub_aoi_secret_env({"AOI_CHIEF_EPOCH": "secret", "aoi_chief_credential_file": "secret", "GITHUB_TOKEN": "secret", "GITHUB_PAT": "secret", "AZURE_DEVOPS_EXT_PAT": "secret", "DOCKER_AUTH_CONFIG": "secret", "TWINE_PASSWORD": "secret", "OPENAI_API_KEY": "model-control", "SAFE": "1"})
    assert scrubbed == {"OPENAI_API_KEY": "model-control", "SAFE": "1"}


def test_local_files_codex_home_policy_is_bound_before_process_start(
    fake_server: Path, tmp_path: Path
) -> None:
    codex_home = tmp_path / "isolated-codex-home"
    _write_local_files_codex_home(codex_home)
    entries: list[ProcessJournalEntry] = []
    client = _client(
        fake_server,
        tmp_path,
        environment={"CODEX_HOME": str(codex_home)},
        max_line_bytes=4096,
        require_local_files_policy=True,
        on_process_start_pending=entries.append,
        on_process_started=entries.append,
    )
    client.start()
    try:
        initialized = client.initialize()
        assert Path(initialized["codexHome"]).resolve() == codex_home.resolve()
        assert len(entries) == 2
        pending = json.loads(entries[0].payload_bytes)
        binding = pending["local_files_policy"]
        assert binding["mode"] == "local_files"
        assert Path(binding["codex_home"]).resolve() == codex_home.resolve()
        assert len(binding["config_sha256"]) == 64
        assert len(binding["managed_config_sha256"]) == 64
        assert len(binding["thread_config_sha256"]) == 64
        auth = next(
            row for row in binding["initial_inventory"] if row["name"] == "auth.json"
        )
        assert "sha256" not in auth
    finally:
        client.close()


@pytest.mark.parametrize("fault", ["extra", "config", "managed"])
def test_local_files_codex_home_policy_drift_fails_before_process(
    fake_server: Path, tmp_path: Path, fault: str
) -> None:
    codex_home = tmp_path / f"isolated-{fault}"
    _write_local_files_codex_home(codex_home)
    if fault == "extra":
        (codex_home / "plugins").mkdir()
    elif fault == "config":
        (codex_home / "config.toml").write_text(
            'web_search = "live"\n', encoding="utf-8"
        )
    else:
        (codex_home / "managed_config.toml").write_text(
            "allow_remote_control = true\n", encoding="utf-8"
        )
    pending: list[ProcessJournalEntry] = []
    client = _client(
        fake_server,
        tmp_path,
        environment={"CODEX_HOME": str(codex_home)},
        require_local_files_policy=True,
        on_process_start_pending=pending.append,
    )
    with pytest.raises(AppServerError, match="local_files"):
        client.start()
    assert pending == []


def test_local_files_policy_is_rechecked_after_version_probe_before_popen(
    fake_server: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_home = tmp_path / "isolated-toctou"
    _write_local_files_codex_home(codex_home)
    pending: list[ProcessJournalEntry] = []
    client = _client(
        fake_server,
        tmp_path,
        environment={"CODEX_HOME": str(codex_home)},
        require_local_files_policy=True,
        on_process_start_pending=pending.append,
        max_line_bytes=4096,
    )

    def mutate_after_pending() -> None:
        (codex_home / "managed_config.toml").write_text(
            "allow_remote_control = true\n", encoding="utf-8"
        )

    monkeypatch.setattr(client, "_verify_runtime_version", mutate_after_pending)
    with pytest.raises(AppServerError, match="local_files"):
        client.start()
    assert pending == []


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
        / "0.145.0"
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
    assert stdio._MODEL_LIST_RESPONSE_REQUIRED == frozenset(
        schema["definitions"]["ModelListResponse"]["required"]
    )
    assert stdio._MODEL_REQUIRED == frozenset(
        schema["definitions"]["Model"]["required"]
    )
    assert stdio._REASONING_EFFORT_OPTION_REQUIRED == frozenset(
        schema["definitions"]["ReasoningEffortOption"]["required"]
    )


def test_pinned_rpc_envelopes_do_not_define_jsonrpc_member() -> None:
    root = (
        Path(contracts.__file__).resolve().parent
        / "resources"
        / "codex_app_server"
        / "0.145.0"
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
            "model": "gpt-5.6-terra",
            "config": {
                "web_search": "disabled",
                "features": {
                    "apps": False,
                    "remote_plugin": False,
                    "multi_agent": False,
                },
                "apps": {"_default": {"enabled": False}},
            },
        }
        assert sent["turn/start"]["sandboxPolicy"] == {
            "type": "readOnly",
            "networkAccess": False,
        }
        assert sent["turn/start"]["cwd"] == tmp_path.resolve().as_posix()
        assert sent["turn/start"]["effort"] == "medium"
    finally:
        client.close()


def test_transport_neutral_launch_spec_uses_the_legacy_adapter_flow(
    fake_server: Path, tmp_path: Path
) -> None:
    prompt = "hello"
    spec = AppServerLaunchSpec(
        cwd=tmp_path.resolve().as_posix(),
        model="gpt-5.6-terra",
        effort="medium",
        sandbox="readOnly",
        prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        prompt_size_bytes=len(prompt.encode("utf-8")),
        executable_path=Path(sys.executable).resolve().as_posix(),
    )
    client = _initialized_client(fake_server, tmp_path)
    try:
        thread_id = client.start_thread_from_intent(intent=spec)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt=prompt, intent=spec
        )
        assert client.observe_turn(
            thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
        ).terminal_status == "completed"
    finally:
        client.close()


def test_observe_turn_event_callback_receives_accepted_exact_wire_bytes(
    fake_server: Path, tmp_path: Path
) -> None:
    accepted: list[RuntimeEvent] = []
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )
        observation = client.observe_turn(
            thread_id=thread_id,
            turn_id=turn_id,
            timeout_seconds=3,
            on_event=accepted.append,
        )
        assert accepted == list(observation.events)
        assert [event.wire_bytes for event in accepted] == [
            event.wire_bytes for event in observation.events
        ]
        assert all(
            hashlib.sha256(event.wire_bytes).hexdigest() == event.sha256
            for event in accepted
        )
    finally:
        client.close()


def test_observe_turn_rejects_before_event_callback() -> None:
    invalid_events = (
        RuntimeEvent(
            "turn/started",
            {"threadId": "other", "turn": {"id": "turn-1", "items": [], "status": "inProgress"}},
            "a" * 64,
            b'{"method":"turn/started"}\n',
        ),
        RuntimeEvent(
            "item/started",
            {"threadId": "thread-1", "turnId": "turn-1", "item": {"id": "item-1", "type": "agentMessage", "text": "ok"}},
            "b" * 64,
            b'{"method":"item/started"}\n',
        ),
    )
    for event in invalid_events:
        client = object.__new__(CodexAppServerStdio)
        client._notifications = [event]
        accepted: list[RuntimeEvent] = []
        with pytest.raises(ProtocolViolation):
            client.observe_turn(
                thread_id="thread-1",
                turn_id="turn-1",
                timeout_seconds=1,
                on_event=accepted.append,
            )
        assert accepted == []


def test_observe_turn_event_callback_failure_fails_closed(fake_server: Path, tmp_path: Path) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )

        def fail_callback(_event: RuntimeEvent) -> None:
            raise RuntimeError("callback-secret")

        with pytest.raises(AppServerError, match="event callback failed") as caught:
            client.observe_turn(
                thread_id=thread_id,
                turn_id=turn_id,
                timeout_seconds=3,
                on_event=fail_callback,
            )
        assert "callback-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert client._turn_terminal is False
        assert client._terminal_stream_phase.value == "aborted"
        assert type(client._reader_error) is AppServerError
        assert str(client._reader_error) == "observe_turn event callback failed"
        with pytest.raises(AppServerError, match="event callback failed"):
            client.observe_turn(
                thread_id=thread_id,
                turn_id=turn_id,
                timeout_seconds=3,
            )
        with pytest.raises(RuntimeDisconnected, match="not eligible for a clean seal"):
            client.seal_reader_for_terminal_commit(timeout_seconds=3)
    finally:
        client.close()


def test_observe_turn_base_exception_callback_failure_fails_closed(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )

        def interrupt_callback(_event: RuntimeEvent) -> None:
            raise KeyboardInterrupt("callback-secret")

        with pytest.raises(AppServerError, match="event callback failed") as caught:
            client.observe_turn(
                thread_id=thread_id,
                turn_id=turn_id,
                timeout_seconds=3,
                on_event=interrupt_callback,
            )
        assert "callback-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert client._turn_terminal is False
        assert client._terminal_stream_phase.value == "aborted"
        with pytest.raises(AppServerError, match="event callback failed"):
            client.observe_turn(
                thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
            )
        with pytest.raises(RuntimeDisconnected, match="not eligible for a clean seal"):
            client.seal_reader_for_terminal_commit(timeout_seconds=3)
    finally:
        client.close()


@pytest.mark.parametrize("late_method", ["turn/started", "turn/completed"])
def test_observe_turn_late_callback_aborts_terminal_eligibility(
    fake_server: Path, tmp_path: Path, late_method: str
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    callbacks: list[str] = []
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )

        def late_callback(event: RuntimeEvent) -> None:
            callbacks.append(event.method)
            if event.method == late_method:
                time.sleep(0.08)

        with pytest.raises(
            RuntimeDisconnected, match="turn observation deadline expired"
        ):
            client.observe_turn(
                thread_id=thread_id,
                turn_id=turn_id,
                timeout_seconds=0.02,
                on_event=late_callback,
            )

        assert late_method in callbacks
        assert client._turn_terminal is False
        assert client._terminal_stream_phase.value == "aborted"
        with pytest.raises(RuntimeDisconnected, match="not eligible for a clean seal"):
            client.seal_reader_for_terminal_commit(timeout_seconds=3)
    finally:
        client.close()


def test_observe_and_terminal_seal_serialize_callback_abort(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    observer_errors: list[BaseException] = []
    seal_errors: list[BaseException] = []
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )

        def fail_after_barrier(_event: RuntimeEvent) -> None:
            callback_entered.set()
            assert release_callback.wait(timeout=3)
            raise RuntimeError("callback-secret")

        def observe() -> None:
            try:
                client.observe_turn(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    timeout_seconds=3,
                    on_event=fail_after_barrier,
                )
            except BaseException as exc:
                observer_errors.append(exc)

        def seal() -> None:
            try:
                client.seal_reader_for_terminal_commit(timeout_seconds=3)
            except BaseException as exc:
                seal_errors.append(exc)

        observer = threading.Thread(target=observe)
        observer.start()
        assert callback_entered.wait(timeout=2)
        sealer = threading.Thread(target=seal)
        sealer.start()
        time.sleep(0.1)
        assert client._terminal_stream_phase.value == "open"
        assert sealer.is_alive()

        release_callback.set()
        observer.join(timeout=3)
        sealer.join(timeout=3)

        assert not observer.is_alive()
        assert not sealer.is_alive()
        assert len(observer_errors) == 1
        assert isinstance(observer_errors[0], AppServerError)
        assert len(seal_errors) == 1
        assert isinstance(seal_errors[0], RuntimeDisconnected)
        assert client._terminal_stream_phase.value == "aborted"
        assert client._turn_terminal is False
    finally:
        client.close()


def test_lifecycle_serialization_timeout_aborts_stalled_callback(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    observer_errors: list[BaseException] = []
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )

        def stall_callback(_event: RuntimeEvent) -> None:
            callback_entered.set()
            assert release_callback.wait(timeout=3)

        def observe() -> None:
            try:
                client.observe_turn(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    timeout_seconds=3,
                    on_event=stall_callback,
                )
            except BaseException as exc:
                observer_errors.append(exc)

        observer = threading.Thread(target=observe)
        observer.start()
        assert callback_entered.wait(timeout=2)

        started = time.monotonic()
        with pytest.raises(RuntimeDisconnected, match="lifecycle serialization"):
            client.observe_turn(
                thread_id=thread_id, turn_id=turn_id, timeout_seconds=0.1
            )
        assert time.monotonic() - started < 0.5

        started = time.monotonic()
        with pytest.raises(RuntimeDisconnected, match="lifecycle serialization"):
            client.seal_reader_for_terminal_commit(timeout_seconds=0.1)
        assert time.monotonic() - started < 0.5
        assert client._terminal_stream_phase.value == "aborted"
        assert client._turn_terminal is False

        release_callback.set()
        observer.join(timeout=3)
        assert not observer.is_alive()
        assert len(observer_errors) == 1
        assert isinstance(observer_errors[0], RuntimeDisconnected)
        assert client._terminal_stream_phase.value == "aborted"
    finally:
        client.close()


@pytest.mark.parametrize("abort_mode", ["contender", "reentrant"])
def test_global_abort_preserves_later_buffered_events_after_callback(
    abort_mode: str,
) -> None:
    client = object.__new__(CodexAppServerStdio)
    first = RuntimeEvent(
        "item/started",
        {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "startedAtMs": 1,
            "item": {"id": "item-1", "type": "agentMessage", "text": "first"},
        },
        "a" * 64,
        b"first\n",
    )
    later = RuntimeEvent(
        "item/started",
        {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "startedAtMs": 2,
            "item": {"id": "item-2", "type": "agentMessage", "text": "later"},
        },
        "b" * 64,
        b"later\n",
    )
    client._notifications = [first, later]
    client._turn_lifecycle_lock = threading.Lock()
    client._reader_condition = threading.Condition()
    client._terminal_stream_phase = stdio._TerminalStreamPhase.OPEN
    client._turn_terminal = False
    client._reader_error = None
    client._event_callback_failed = False
    callbacks: list[RuntimeEvent] = []

    if abort_mode == "reentrant":

        def callback(event: RuntimeEvent) -> None:
            callbacks.append(event)
            with pytest.raises(RuntimeDisconnected, match="lifecycle serialization"):
                client.observe_turn(
                    thread_id="thread-1", turn_id="turn-1", timeout_seconds=0.01
                )

        with pytest.raises(RuntimeDisconnected, match="not eligible after terminal stream transition"):
            client.observe_turn(
                thread_id="thread-1",
                turn_id="turn-1",
                timeout_seconds=1,
                on_event=callback,
            )
    else:
        callback_entered = threading.Event()
        release_callback = threading.Event()
        observer_errors: list[BaseException] = []

        def callback(event: RuntimeEvent) -> None:
            callbacks.append(event)
            callback_entered.set()
            assert release_callback.wait(timeout=3)

        def observe() -> None:
            try:
                client.observe_turn(
                    thread_id="thread-1",
                    turn_id="turn-1",
                    timeout_seconds=1,
                    on_event=callback,
                )
            except BaseException as exc:
                observer_errors.append(exc)

        observer = threading.Thread(target=observe)
        observer.start()
        assert callback_entered.wait(timeout=1)
        with pytest.raises(RuntimeDisconnected, match="lifecycle serialization"):
            client.observe_turn(thread_id="thread-1", turn_id="turn-1", timeout_seconds=0.01)
        release_callback.set()
        observer.join(timeout=1)
        assert not observer.is_alive()
        assert len(observer_errors) == 1
        assert isinstance(observer_errors[0], RuntimeDisconnected)

    assert callbacks == [first]
    assert client._notifications == [later]
    assert client._terminal_stream_phase.value == "aborted"


def test_global_abort_preserves_live_event_waiting_in_next_incoming() -> None:
    entered_get = threading.Event()
    release_event = threading.Event()
    params: dict[str, Any] = {
        "threadId": "thread-1",
        "turnId": "turn-1",
        "startedAtMs": 1,
        "item": {"id": "item-1", "type": "agentMessage", "text": "live"},
    }
    message = {
        "method": "item/started",
        "params": params,
    }
    raw = b'{"method":"item/started"}\n'

    class IncomingAfterAbort:
        def get(self, *, timeout: float) -> tuple[str, object]:
            entered_get.set()
            assert release_event.wait(timeout=3)
            return ("notification", (message, raw))

    client = object.__new__(CodexAppServerStdio)
    client._notifications = []
    client._turn_lifecycle_lock = threading.Lock()
    client._reader_condition = threading.Condition()
    client._terminal_stream_phase = stdio._TerminalStreamPhase.OPEN
    client._turn_terminal = False
    client._reader_error = None
    client._event_callback_failed = False
    client._reroute_persistence_inflight = 0
    client._incoming = IncomingAfterAbort()  # type: ignore[assignment]
    client._seen_events = {}
    client.max_events = 8
    callbacks: list[RuntimeEvent] = []
    observer_errors: list[BaseException] = []

    def observe() -> None:
        try:
            client.observe_turn(
                thread_id="thread-1",
                turn_id="turn-1",
                timeout_seconds=1,
                on_event=callbacks.append,
            )
        except BaseException as exc:
            observer_errors.append(exc)

    observer = threading.Thread(target=observe)
    observer.start()
    assert entered_get.wait(timeout=1)
    with pytest.raises(RuntimeDisconnected, match="lifecycle serialization"):
        client.observe_turn(thread_id="thread-1", turn_id="turn-1", timeout_seconds=0.01)
    release_event.set()
    observer.join(timeout=1)

    assert not observer.is_alive()
    assert len(observer_errors) == 1
    assert isinstance(observer_errors[0], RuntimeDisconnected)
    assert callbacks == []
    assert client._notifications == [
        RuntimeEvent("item/started", params, hashlib.sha256(raw).hexdigest(), raw)
    ]
    assert client._terminal_stream_phase.value == "aborted"


@pytest.mark.parametrize(
    "timeout_seconds",
    [math.nan, math.inf, -math.inf, 0.0, -1.0, True, "1", threading.TIMEOUT_MAX * 2, 10**10000],
    ids=[
        "nan",
        "positive-infinity",
        "negative-infinity",
        "zero",
        "negative",
        "bool",
        "non-numeric",
        "over-timeout-max",
        "conversion-overflow",
    ],
)
@pytest.mark.parametrize("operation", ["observe", "seal"])
def test_public_lifecycle_timeouts_reject_invalid_or_unwaitable_before_lock(
    timeout_seconds: object, operation: str
) -> None:
    class LockMustNotRun:
        def acquire(self, *args: object, **kwargs: object) -> bool:
            raise AssertionError("platform lifecycle lock was called")

        def release(self) -> None:
            raise AssertionError("platform lifecycle lock was released")

    client = object.__new__(CodexAppServerStdio)
    client._turn_lifecycle_lock = LockMustNotRun()  # type: ignore[assignment]
    client._terminal_stream_phase = stdio._TerminalStreamPhase.OPEN
    client._turn_terminal = False
    client._reader_error = None
    with pytest.raises(ValueError, match="finite positive number"):
        if operation == "observe":
            client.observe_turn(
                thread_id="thread-1", turn_id="turn-1", timeout_seconds=timeout_seconds  # type: ignore[arg-type]
            )
        else:
            client.seal_reader_for_terminal_commit(timeout_seconds=timeout_seconds)  # type: ignore[arg-type]
    assert client._terminal_stream_phase is stdio._TerminalStreamPhase.OPEN
    assert client._turn_terminal is False
    assert client._reader_error is None


def test_concurrent_observers_cannot_accept_after_terminal_observation(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    observations: list[object] = []
    observer_errors: list[BaseException] = []
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )

        def pause_first_callback(_event: RuntimeEvent) -> None:
            if not callback_entered.is_set():
                callback_entered.set()
                assert release_callback.wait(timeout=3)

        def first_observer() -> None:
            observations.append(
                client.observe_turn(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    timeout_seconds=3,
                    on_event=pause_first_callback,
                )
            )

        def second_observer() -> None:
            try:
                client.observe_turn(
                    thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
                )
            except BaseException as exc:
                observer_errors.append(exc)

        first = threading.Thread(target=first_observer)
        first.start()
        assert callback_entered.wait(timeout=2)
        second = threading.Thread(target=second_observer)
        second.start()
        time.sleep(0.1)
        assert second.is_alive()

        release_callback.set()
        first.join(timeout=3)
        second.join(timeout=3)

        assert not first.is_alive()
        assert not second.is_alive()
        assert len(observations) == 1
        assert len(observer_errors) == 1
        assert isinstance(observer_errors[0], AppServerError)
        assert "after terminal completion" in str(observer_errors[0])
        assert client._turn_terminal is True
    finally:
        client.close()


@pytest.mark.parametrize("reroute_first", [False, True])
def test_callback_abort_preserves_reroute_evidence_precedence(
    fake_server: Path, tmp_path: Path, reroute_first: bool
) -> None:
    client = _client(fake_server, tmp_path)
    client._model_intent = _intent(tmp_path)
    persisted: list[bytes] = []
    def persist_rejected(
        observed: RuntimeEvent | RejectedNotificationWire,
    ) -> dict[str, object]:
        persisted.append(observed.wire_bytes)
        return {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }

    def fail_callback(_event: RuntimeEvent) -> None:
        raise RuntimeError("callback-secret")

    client.on_rejected_notification = persist_rejected
    raw = (
        b'{"method":"item/started","params":{"threadId":"thread-1",'
        b'"turnId":"turn-1","startedAtMs":2,"item":{"id":"item-1",'
        b'"type":"agentMessage","text":"ok"}}}\n'
    )
    client._notifications.append(
        RuntimeEvent(
            "item/started",
            {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "startedAtMs": 2,
                "item": {"id": "item-1", "type": "agentMessage", "text": "ok"},
            },
            hashlib.sha256(raw).hexdigest(),
            raw,
        )
    )
    reroute, reroute_raw = _reroute_wire()

    if reroute_first:
        client._classify_incoming(reroute, reroute_raw)

    with pytest.raises(AppServerError, match="event callback failed"):
        client.observe_turn(
            thread_id="thread-1",
            turn_id="turn-1",
            timeout_seconds=1,
            on_event=fail_callback,
        )

    if not reroute_first:
        client._classify_incoming(reroute, reroute_raw)

    assert persisted == [reroute_raw]
    assert isinstance(client._reader_error, ModelReroutedViolation)
    assert client._reader_error.evidence_sha256 == hashlib.sha256(reroute_raw).hexdigest()
    assert client._reader_error.evidence_size_bytes == len(reroute_raw)
    assert client._event_callback_failed is True
    assert client._terminal_stream_phase.value == "aborted"
    with pytest.raises(ModelReroutedViolation) as caught:
        client.observe_turn(thread_id="thread-1", turn_id="turn-1", timeout_seconds=1)
    assert caught.value.evidence_sha256 == hashlib.sha256(reroute_raw).hexdigest()
    assert caught.value.evidence_size_bytes == len(reroute_raw)


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_runtime_event_json_payload_bytes_is_company_parser_outer_framing_equivalent(
    line_ending: bytes,
) -> None:
    payload = (
        b'{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1",'
        b'"turnId":"turn-1","tokenUsage":{"total":{"inputTokens":1,'
        b'"cachedInputTokens":0,"outputTokens":2,"reasoningOutputTokens":0,'
        b'"totalTokens":3},"last":{"inputTokens":1,"cachedInputTokens":0,'
        b'"outputTokens":2,"reasoningOutputTokens":0,"totalTokens":3}}}}'
    )
    wire = payload + line_ending
    event = RuntimeEvent(
        "thread/tokenUsage/updated",
        {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "tokenUsage": {
                "total": {
                    "inputTokens": 1,
                    "cachedInputTokens": 0,
                    "outputTokens": 2,
                    "reasoningOutputTokens": 0,
                    "totalTokens": 3,
                },
                "last": {
                    "inputTokens": 1,
                    "cachedInputTokens": 0,
                    "outputTokens": 2,
                    "reasoningOutputTokens": 0,
                    "totalTokens": 3,
                },
            },
        },
        hashlib.sha256(wire).hexdigest(),
        wire,
    )
    assert event.json_payload_bytes == payload
    parsed = parse_codex_notification(event.json_payload_bytes)
    assert isinstance(parsed, ThreadTokenUsageUpdated)
    assert parsed.total.total_tokens == 3


@pytest.mark.parametrize(
    "payload",
    [
        b' {"method":"warning","params":{}}',
        b'{"method":"warning","params":{}} ',
        b'{"method":"warning","params":{},"extra":true}',
        b'{"method":"warning","method":"warning","params":{}}',
    ],
    ids=("leading-whitespace", "trailing-whitespace", "extra-envelope", "duplicate-key"),
)
@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_runtime_event_json_payload_bytes_rejects_non_parser_equivalent_outer_framing(
    payload: bytes, line_ending: bytes
) -> None:
    wire = payload + line_ending
    event = RuntimeEvent(
        "warning",
        {},
        hashlib.sha256(wire).hexdigest(),
        wire,
    )
    with pytest.raises(ProtocolViolation):
        _ = event.json_payload_bytes


def test_pinned_auxiliary_notifications_do_not_break_lifecycle(fake_server: Path, tmp_path: Path) -> None:
    accepted: list[RuntimeEvent] = []
    client = _initialized_client(fake_server, tmp_path, "auxiliary_notifications")
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )
        observation = client.observe_turn(
            thread_id=thread_id,
            turn_id=turn_id,
            timeout_seconds=3,
            on_event=accepted.append,
        )
        assert observation.terminal_status == "completed"
        assert "item/agentMessage/delta" in {
            event.method for event in observation.events
        }
        assert "thread/tokenUsage/updated" in {
            event.method for event in observation.events
        }
        token_events = [
            event for event in accepted if event.method == "thread/tokenUsage/updated"
        ]
        assert len(token_events) == 1
        assert token_events[0].wire_bytes == next(
            event.wire_bytes
            for event in observation.events
            if event.method == "thread/tokenUsage/updated"
        )
        assert json.loads(token_events[0].wire_bytes)["params"] == {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "tokenUsage": {
                "total": {
                    "inputTokens": 1,
                    "cachedInputTokens": 0,
                    "outputTokens": 2,
                    "reasoningOutputTokens": 0,
                    "totalTokens": 3,
                },
                "last": {
                    "inputTokens": 1,
                    "cachedInputTokens": 0,
                    "outputTokens": 2,
                    "reasoningOutputTokens": 0,
                    "totalTokens": 3,
                },
            },
        }
        token_event = token_events[0]
        assert token_event.wire_bytes.endswith(b"\n")
        assert hashlib.sha256(token_event.wire_bytes).hexdigest() == token_event.sha256
        expected_payload = token_event.wire_bytes.removesuffix(b"\n").removesuffix(b"\r")
        assert token_event.json_payload_bytes == expected_payload
        assert hashlib.sha256(token_event.json_payload_bytes).hexdigest() != token_event.sha256
        parsed = parse_codex_notification(token_event.json_payload_bytes)
        assert isinstance(parsed, ThreadTokenUsageUpdated)
        assert parsed.total.total_tokens == 3
        assert parsed.last.total_tokens == 3
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


@pytest.mark.parametrize(
    "changes",
    [
        {"fromModel": None},
        {"toModel": None},
        {"reason": None},
        {"fromModel": "wrong-model"},
        {"toModel": ""},
        {"reason": "unsupported-reason"},
        {"threadId": "wrong-thread"},
        {"turnId": "wrong-turn"},
        {"threadId": 7},
        {"turnId": []},
        {"fromModel": 7},
        {"toModel": {}},
        {"reason": 7},
        {},
    ],
)
def test_model_rerouted_always_fails_closed_after_exact_evidence(
    fake_server: Path,
    tmp_path: Path,
    changes: dict[str, object | None],
) -> None:
    params: dict[str, object] = {
        "fromModel": "gpt-5.6-terra",
        "reason": "highRiskCyberActivity",
        "threadId": "thread-1",
        "toModel": "reroute-secret-model",
        "turnId": "turn-1",
    }
    for key, value in changes.items():
        if value is None:
            params.pop(key)
        else:
            params[key] = value
    raw = json.dumps(
        {"method": "model/rerouted", "params": params},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    event = RuntimeEvent(
        "model/rerouted", params, hashlib.sha256(raw).hexdigest(), raw
    )
    persisted: list[RuntimeEvent] = []
    client = _client(fake_server, tmp_path)
    client._model_intent = _intent(tmp_path)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed)
        or {
            "path": "local-cas",
            "sha256": observed.sha256,
            "size_bytes": len(observed.wire_bytes),
        }
    )

    with pytest.raises(
        ModelReroutedViolation,
        match="App Server model reroute violates sealed AOI policy",
    ) as caught:
        client._validate_event(
            event, thread_id="thread-1", turn_id="turn-1"
        )

    assert persisted == [event]
    assert persisted[0].wire_bytes == raw
    assert caught.value.method == "model/rerouted"
    assert caught.value.reason_code == "model_rerouted"
    assert caught.value.evidence_sha256 == hashlib.sha256(raw).hexdigest()
    assert caught.value.evidence_size_bytes == len(raw)
    assert "reroute-secret-model" not in str(caught.value)
    assert "wrong-model" not in str(caught.value)


@pytest.mark.parametrize(
    ("scenario", "failure_point"),
    [
        ("model_rerouted_buffered", "start"),
        ("model_rerouted_live", "start_or_observe"),
    ],
)
def test_model_rerouted_buffered_or_live_preempts_queued_completion(
    fake_server: Path,
    tmp_path: Path,
    scenario: str,
    failure_point: str,
) -> None:
    persisted: list[RuntimeEvent | RejectedNotificationWire] = []
    client = _initialized_client(fake_server, tmp_path, scenario)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed)
        or {
            "path": "local-cas",
            "sha256": observed.sha256,
            "size_bytes": len(observed.wire_bytes),
        }
    )
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        if failure_point == "start":
            with pytest.raises(ModelReroutedViolation):
                client.start_turn_from_intent(
                    thread_id=thread_id, prompt="hello", intent=intent
                )
        else:
            try:
                turn_id = client.start_turn_from_intent(
                    thread_id=thread_id, prompt="hello", intent=intent
                )
            except ModelReroutedViolation:
                pass
            else:
                with pytest.raises(ModelReroutedViolation):
                    client.observe_turn(
                        thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
                    )
        assert len(persisted) == 1
        assert b'"method":"model/rerouted"' in persisted[0].wire_bytes
        assert b"reroute-secret-model" in persisted[0].wire_bytes
        assert client._turn_terminal is False
    finally:
        client.close()


def test_terminal_stream_seal_requires_natural_exit_and_full_reader_join(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )
        observation = client.observe_turn(
            thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
        )

        client.seal_reader_for_terminal_commit(timeout_seconds=3)
        client.seal_reader_for_terminal_commit(timeout_seconds=3)

        assert observation.terminal_status == "completed"
        assert client._terminal_stream_phase.value == "sealed"
        assert client._stdout_reader_done is True
        assert client._stderr_reader_done is True
        assert client._reroute_persistence_inflight == 0
        assert client._process is None
        assert client._stdout_thread is not None
        assert client._stdout_thread.is_alive() is False
        assert client._stderr_thread is not None
        assert client._stderr_thread.is_alive() is False
    finally:
        client.close()


def test_terminal_stream_seal_drains_reroute_emitted_after_stdin_eof(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[RuntimeEvent | RejectedNotificationWire] = []
    client = _initialized_client(
        fake_server, tmp_path, "model_rerouted_after_stdin_eof"
    )
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed)
        or {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
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

        with pytest.raises(ModelReroutedViolation) as caught:
            client.seal_reader_for_terminal_commit(timeout_seconds=3)

        assert len(persisted) == 1
        assert caught.value.evidence_sha256 == hashlib.sha256(
            persisted[0].wire_bytes
        ).hexdigest()
        assert client._terminal_stream_phase.value == "aborted"
        assert client._stdout_reader_done is True
        assert client._process is None
    finally:
        client.close()


_TERMINAL_SEAL_LATE_QUEUE_CASES: list[tuple[str, Any]] = [
    (
        "notification",
        (
            {"method": "warning", "params": {"message": "late"}},
            b'{"method":"warning","params":{"message":"late"}}\n',
        ),
    ),
    (
        "notification",
        (
            {
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {"id": "turn-1", "items": [], "status": "failed"},
                },
            },
            b'{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","items":[],"status":"failed"}}}\n',
        ),
    ),
    ("response", ({"id": 99, "result": {}}, b'{"id":99,"result":{}}\n')),
    ("server_request", {"id": 99, "method": "tool/requestUserInput", "params": {}}),
    ("eof", None),
]


@pytest.mark.parametrize(
    ("kind", "payload"),
    _TERMINAL_SEAL_LATE_QUEUE_CASES,
    ids=("late-notification", "conflicting-terminal", "late-response", "late-request", "duplicate-eof"),
)
def test_terminal_stream_seal_rejects_every_late_or_duplicate_queue_entry(
    fake_server: Path, tmp_path: Path, kind: str, payload: Any
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )
        assert client.observe_turn(
            thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
        ).terminal_status == "completed"
        client._incoming.put_nowait((kind, payload))

        with pytest.raises(RuntimeDisconnected, match="late protocol data or invalid EOF"):
            client.seal_reader_for_terminal_commit(timeout_seconds=3)

        assert client._terminal_stream_phase.value == "aborted"
        assert client._turn_terminal is False
    finally:
        client.close()


def test_terminal_stream_seal_rejects_buffered_ordinary_notification(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path)
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        turn_id = client.start_turn_from_intent(
            thread_id=thread_id, prompt="hello", intent=intent
        )
        assert client.observe_turn(
            thread_id=thread_id, turn_id=turn_id, timeout_seconds=3
        ).terminal_status == "completed"
        raw = b'{"method":"warning","params":{"message":"buffered"}}\n'
        client._notifications.append(
            RuntimeEvent(
                "warning",
                {"message": "buffered"},
                hashlib.sha256(raw).hexdigest(),
                raw,
            )
        )

        with pytest.raises(RuntimeDisconnected, match="late protocol data or invalid EOF"):
            client.seal_reader_for_terminal_commit(timeout_seconds=3)

        assert client._terminal_stream_phase.value == "aborted"
        assert client._turn_terminal is False
    finally:
        client.close()


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("nonzero_after_completion", "exited nonzero"),
        ("hang_after_stdin_eof", "did not exit naturally"),
    ],
)
def test_terminal_stream_seal_never_accepts_nonzero_or_forced_shutdown(
    fake_server: Path, tmp_path: Path, scenario: str, message: str
) -> None:
    client = _initialized_client(fake_server, tmp_path, scenario)
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

        with pytest.raises(RuntimeDisconnected, match=message):
            client.seal_reader_for_terminal_commit(timeout_seconds=0.2)

        assert client._terminal_stream_phase.value == "aborted"
        assert client._process is None
        if scenario == "hang_after_stdin_eof":
            assert client._forced_shutdown is True
        with pytest.raises(RuntimeDisconnected, match="not eligible"):
            client.seal_reader_for_terminal_commit(timeout_seconds=0.2)
    finally:
        client.close()


def test_model_rerouted_nonobject_params_persist_before_classification(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[RuntimeEvent | RejectedNotificationWire] = []
    client = _initialized_client(
        fake_server, tmp_path, "model_rerouted_nonobject_buffered"
    )
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed)
        or {
            "path": "local-cas",
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        with pytest.raises(ModelReroutedViolation) as caught:
            client.start_turn_from_intent(
                thread_id=thread_id, prompt="hello", intent=intent
            )
        assert len(persisted) == 1
        assert isinstance(persisted[0], RejectedNotificationWire)
        assert b'"params":"payload-secret"' in persisted[0].wire_bytes
        assert caught.value.evidence_sha256 == hashlib.sha256(
            persisted[0].wire_bytes
        ).hexdigest()
        assert caught.value.evidence_size_bytes == len(persisted[0].wire_bytes)
        assert "payload-secret" not in str(caught.value)
        assert client._turn_terminal is False
    finally:
        client.close()


def _reroute_wire(to_model: str = "reroute-secret-model") -> tuple[dict[str, Any], bytes]:
    message = {
        "method": "model/rerouted",
        "params": {
            "fromModel": "gpt-5.6-terra",
            "reason": "highRiskCyberActivity",
            "threadId": "thread-1",
            "toModel": to_model,
            "turnId": "turn-1",
        },
    }
    raw = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
    return message, raw


def test_model_rerouted_reader_persists_before_queued_completion(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[RuntimeEvent | RejectedNotificationWire] = []
    client = _client(fake_server, tmp_path)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed)
        or {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
    completed = {
        "method": "turn/completed",
        "params": {
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "items": [], "status": "completed"},
        },
    }
    completed_raw = (
        json.dumps(completed, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    client._incoming.put_nowait(("notification", (completed, completed_raw)))
    reroute, reroute_raw = _reroute_wire()
    client._enqueue(client._classify_incoming(reroute, reroute_raw))

    assert [entry.wire_bytes for entry in persisted] == [reroute_raw]
    assert isinstance(client._reader_error, ModelReroutedViolation)
    with pytest.raises(ModelReroutedViolation) as caught:
        client._next_notification(time.monotonic() + 1)
    assert caught.value.evidence_sha256 == hashlib.sha256(reroute_raw).hexdigest()
    assert client._turn_terminal is False


def test_model_rerouted_reader_fault_cannot_overtake_exact_evidence(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[bytes] = []
    client = _client(fake_server, tmp_path)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed.wire_bytes)
        or {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
    reroute, raw = _reroute_wire()
    client._enqueue(client._classify_incoming(reroute, raw))
    retained = client._retain_reader_error(ProtocolViolation("later reader fault"))

    assert persisted == [raw]
    assert isinstance(retained, ModelReroutedViolation)
    with pytest.raises(ModelReroutedViolation):
        client._next_incoming(time.monotonic() + 1)


def test_model_rerouted_reader_persists_even_when_main_queue_is_full(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[bytes] = []
    client = _client(fake_server, tmp_path, max_queue_messages=1)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed.wire_bytes)
        or {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
    client._incoming.put_nowait(("notification", ({"method": "warning"}, b"{}\n")))
    reroute, raw = _reroute_wire()
    client._enqueue(client._classify_incoming(reroute, raw))

    assert persisted == [raw]
    assert client._incoming.qsize() == 1
    assert isinstance(client._reader_error, ModelReroutedViolation)


def test_model_rerouted_reader_persists_each_recognized_duplicate(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[bytes] = []
    client = _client(fake_server, tmp_path)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed.wire_bytes)
        or {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
    first, first_raw = _reroute_wire("reroute-secret-model-1")
    second, second_raw = _reroute_wire("reroute-secret-model-2")

    client._classify_incoming(first, first_raw)
    client._classify_incoming(second, second_raw)

    assert persisted == [first_raw, second_raw]
    assert isinstance(client._reader_error, ModelReroutedViolation)


@pytest.mark.parametrize("callback_mode", ["success", "raises", "diverges"])
def test_model_rerouted_inflight_callback_blocks_terminal_completion(
    fake_server: Path,
    tmp_path: Path,
    callback_mode: str,
) -> None:
    callback_entered = threading.Event()
    release_callback = threading.Event()
    observer_done = threading.Event()
    persisted: list[bytes] = []
    classifier_errors: list[BaseException] = []
    observer_errors: list[BaseException] = []
    observations: list[object] = []
    client = _client(fake_server, tmp_path)

    def callback(
        observed: RuntimeEvent | RejectedNotificationWire,
    ) -> dict[str, object]:
        callback_entered.set()
        assert release_callback.wait(timeout=3)
        if callback_mode == "raises":
            raise RuntimeError("payload-secret")
        persisted.append(observed.wire_bytes)
        if callback_mode == "diverges":
            return {"sha256": "0" * 64, "size_bytes": len(observed.wire_bytes)}
        return {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }

    client.on_rejected_notification = callback
    completed = {
        "method": "turn/completed",
        "params": {
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "items": [], "status": "completed"},
        },
    }
    completed_raw = json.dumps(
        completed, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    client._notifications.append(
        RuntimeEvent(
            "turn/completed",
            completed["params"],
            hashlib.sha256(completed_raw).hexdigest(),
            completed_raw,
        )
    )
    reroute, reroute_raw = _reroute_wire()

    def classify() -> None:
        try:
            client._classify_incoming(reroute, reroute_raw)
        except BaseException as exc:
            classifier_errors.append(exc)

    def observe() -> None:
        try:
            observations.append(
                client.observe_turn(
                    thread_id="thread-1",
                    turn_id="turn-1",
                    timeout_seconds=3,
                )
            )
        except BaseException as exc:
            observer_errors.append(exc)
        finally:
            observer_done.set()

    classifier = threading.Thread(target=classify)
    classifier.start()
    assert callback_entered.wait(timeout=2)
    observer = threading.Thread(target=observe)
    observer.start()

    assert not observer_done.wait(timeout=0.1)
    assert client._turn_terminal is False
    assert observations == []

    release_callback.set()
    classifier.join(timeout=3)
    observer.join(timeout=3)
    assert not classifier.is_alive()
    assert not observer.is_alive()
    assert observations == []
    assert len(observer_errors) == 1
    assert "payload-secret" not in str(observer_errors[0])
    assert client._turn_terminal is False
    assert client._reroute_persistence_inflight == 0
    if callback_mode == "success":
        assert classifier_errors == []
        assert persisted == [reroute_raw]
        assert isinstance(observer_errors[0], ModelReroutedViolation)
    else:
        assert len(classifier_errors) == 1
        assert isinstance(classifier_errors[0], AppServerError)
        assert isinstance(observer_errors[0], AppServerError)


def test_stdout_reader_persists_duplicate_reroutes_despite_full_main_queue(
    fake_server: Path, tmp_path: Path
) -> None:
    persisted: list[bytes] = []
    client = _client(fake_server, tmp_path, max_queue_messages=1)
    client.on_rejected_notification = lambda observed: (
        persisted.append(observed.wire_bytes)
        or {
            "sha256": hashlib.sha256(observed.wire_bytes).hexdigest(),
            "size_bytes": len(observed.wire_bytes),
        }
    )
    ordinary = json.dumps(
        {
            "method": "thread/status/changed",
            "params": {"threadId": "thread-1", "status": "active"},
        },
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    first, first_raw = _reroute_wire("reroute-secret-model-1")
    second, second_raw = _reroute_wire("reroute-secret-model-2")
    assert first != second
    client._process = SimpleNamespace(
        stdout=io.BytesIO(ordinary + first_raw + second_raw)
    )  # type: ignore[assignment]

    reader = threading.Thread(target=client._stdout_reader)
    reader.start()
    reader.join(timeout=3)
    client._process = None

    assert not reader.is_alive()
    assert persisted == [first_raw, second_raw]
    assert client._incoming.qsize() == 1
    assert isinstance(client._reader_error, ModelReroutedViolation)
    assert client._reroute_persistence_inflight == 0


@pytest.mark.parametrize("callback_mode", ["missing", "raises"])
def test_model_rerouted_requires_successful_evidence_callback(
    fake_server: Path,
    tmp_path: Path,
    callback_mode: str,
) -> None:
    client = _initialized_client(
        fake_server, tmp_path, "model_rerouted_nonobject_buffered"
    )
    if callback_mode == "raises":
        def fail_callback(
            _entry: RuntimeEvent | RejectedNotificationWire,
        ) -> dict[str, object]:
            raise RuntimeError("payload-secret")

        client.on_rejected_notification = fail_callback
    try:
        intent = _intent(tmp_path)
        thread_id = client.start_thread_from_intent(intent=intent)
        expected = "required" if callback_mode == "missing" else "callback failed"
        with pytest.raises(AppServerError, match=expected) as caught:
            client.start_turn_from_intent(
                thread_id=thread_id, prompt="hello", intent=intent
            )
        assert "payload-secret" not in str(caught.value)
        assert client._turn_terminal is False
    finally:
        client.close()


def test_model_rerouted_evidence_sink_must_return_exact_digest_and_size(
    fake_server: Path, tmp_path: Path
) -> None:
    params = {
        "fromModel": "gpt-5.6-terra",
        "reason": "highRiskCyberActivity",
        "threadId": "thread-1",
        "toModel": "other",
        "turnId": "turn-1",
    }
    raw = json.dumps(
        {"method": "model/rerouted", "params": params},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    event = RuntimeEvent(
        "model/rerouted", params, hashlib.sha256(raw).hexdigest(), raw
    )
    client = _client(fake_server, tmp_path)
    client._model_intent = _intent(tmp_path)
    client.on_rejected_notification = lambda _event: {
        "sha256": "0" * 64,
        "size_bytes": len(raw),
    }
    with pytest.raises(AppServerError, match="divergent bytes"):
        client._validate_event(event, thread_id="thread-1", turn_id="turn-1")

    client.on_rejected_notification = lambda _event: {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw) + 1,
    }
    with pytest.raises(AppServerError, match="divergent bytes"):
        client._validate_event(event, thread_id="thread-1", turn_id="turn-1")


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
    ("scenario", "error_type"),
    [
        ("invalid_model_response", ResponseSchemaViolation),
        ("model_missing", ModelCatalogViolation),
        ("model_hidden", ModelCatalogViolation),
        ("model_duplicate", ModelCatalogViolation),
        ("model_effort_missing", ModelCatalogViolation),
        ("model_paginated", ModelCatalogViolation),
    ],
)
def test_model_list_schema_and_exact_catalog_policy_fail_closed_with_local_evidence(
    fake_server: Path,
    tmp_path: Path,
    scenario: str,
    error_type: type[Exception],
) -> None:
    rejected: list[RequestJournalEntry] = []

    def persist_rejected(entry: RequestJournalEntry) -> dict[str, object]:
        rejected.append(entry)
        return {
            "path": "local-cas",
            "sha256": entry.sha256,
            "size_bytes": len(entry.wire_bytes),
        }

    client = _initialized_client(fake_server, tmp_path, scenario)
    client.on_rejected_response = persist_rejected
    responses: list[RequestJournalEntry] = []
    client.on_response = responses.append
    try:
        with pytest.raises(error_type, match="pinned model/list") as caught:
            client.verify_model_from_intent(intent=_intent(tmp_path))
        assert responses == []
        assert len(rejected) == 1
        assert caught.value.evidence_sha256 == rejected[0].sha256
        assert caught.value.evidence_size_bytes == len(rejected[0].wire_bytes)
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


def test_model_list_response_loss_remains_send_pending_without_retry(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path, "eof_model")
    try:
        intent = _intent(tmp_path)
        with pytest.raises(RuntimeDisconnected):
            client.verify_model_from_intent(intent=intent)
        assert client.last_receipt is not None
        assert client.last_receipt.method == "model/list"
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


def test_rejected_response_evidence_sink_must_return_exact_digest_and_size(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _initialized_client(fake_server, tmp_path, "invalid_model_response")
    client.on_rejected_response = lambda entry: {
        "path": "wrong-local-cas",
        "sha256": "0" * 64,
        "size_bytes": len(entry.wire_bytes),
    }
    try:
        with pytest.raises(AppServerError, match="divergent bytes"):
            client.verify_model_from_intent(intent=_intent(tmp_path))
        assert client.last_receipt is not None
        assert client.last_receipt.phase is RequestPhase.SEND_PENDING
    finally:
        client.close()


def test_thread_response_policy_drift_is_distinct_from_generated_schema_drift(
    fake_server: Path, tmp_path: Path
) -> None:
    rejected: list[RequestJournalEntry] = []
    client = _initialized_client(fake_server, tmp_path, "thread_context_drift")
    client.on_rejected_response = lambda entry: (
        rejected.append(entry)
        or {
            "path": "local-cas",
            "sha256": entry.sha256,
            "size_bytes": len(entry.wire_bytes),
        }
    )
    try:
        with pytest.raises(ResponsePolicyViolation, match="sealed AOI policy"):
            client.start_thread_from_intent(intent=_intent(tmp_path))
        assert len(rejected) == 1
        assert rejected[0].method == "thread/start"
    finally:
        client.close()


@pytest.mark.parametrize(
    "scenario", ["invalid_thread_response", "thread_context_drift"]
)
def test_thread_success_response_schema_and_intent_drift_fail_before_observation(
    fake_server: Path, tmp_path: Path, scenario: str
) -> None:
    client = _initialized_client(fake_server, tmp_path, scenario)
    try:
        intent = _intent(tmp_path)
        client.verify_model_from_intent(intent=intent)
        responses: list[RequestJournalEntry] = []
        client.on_response = responses.append
        with pytest.raises(ResponseSchemaViolation, match="pinned thread/start"):
            client.start_thread_from_intent(intent=intent)
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


def test_send_pending_precedes_write_and_error_response_uses_rejected_sink(
    fake_server: Path, tmp_path: Path
) -> None:
    pending: list[RequestJournalEntry] = []

    def reject_before_write(entry: RequestJournalEntry) -> None:
        pending.append(entry)
        raise RuntimeError("journal unavailable")

    client = _client(fake_server, tmp_path, on_send_pending=reject_before_write)
    client.start()
    try:
        with pytest.raises(AppServerError, match="request was not written"):
            client.initialize()
        with pytest.raises(AppServerError, match="initialize may be called only once"):
            client.initialize()
        assert len(pending) == 1
        assert client.last_receipt is not None and client.last_receipt.phase is RequestPhase.BEFORE_SEND
    finally:
        client.close()

    responses: list[RequestJournalEntry] = []
    rejected: list[RequestJournalEntry] = []
    error_client = _initialized_client(fake_server, tmp_path, "error_response")
    try:
        intent = _intent(tmp_path)
        error_client.verify_model_from_intent(intent=intent)
        error_client.on_response = responses.append
        error_client.on_rejected_response = lambda entry: (
            rejected.append(entry)
            or {
                "sha256": entry.sha256,
                "size_bytes": len(entry.wire_bytes),
            }
        )
        with pytest.raises(AppServerResponseError, match="correlated error response") as caught:
            error_client.start_thread_from_intent(intent=intent)
        assert responses == []
        assert len(rejected) == 1
        assert b'"error"' in rejected[0].wire_bytes
        assert caught.value.evidence_sha256 == rejected[0].sha256
        assert caught.value.evidence_size_bytes == len(rejected[0].wire_bytes)
        assert "no" not in str(caught.value)
    finally:
        error_client.close()


def test_initialized_notification_is_journaled_before_and_after_the_exact_write(
    fake_server: Path, tmp_path: Path
) -> None:
    order: list[tuple[str, object]] = []
    client = _client(
        fake_server,
        tmp_path,
        on_send_pending=lambda entry: order.append(("request", entry)),
        on_client_notification_send_pending=lambda entry: order.append(
            ("notification_pending", entry)
        ),
        on_client_notification_written=lambda entry: order.append(
            ("notification_written", entry)
        ),
    )
    client.start()
    try:
        client.initialize()
        assert [kind for kind, _entry in order] == [
            "request",
            "notification_pending",
            "notification_written",
        ]
        pending = order[1][1]
        written = order[2][1]
        assert isinstance(pending, ClientNotificationJournalEntry)
        assert isinstance(written, ClientNotificationJournalEntry)
        assert pending.phase is ClientNotificationPhase.SEND_PENDING
        assert written.phase is ClientNotificationPhase.WRITE_COMPLETED
        assert pending.method == written.method == "initialized"
        assert pending.wire_bytes == written.wire_bytes == b'{"method":"initialized"}\n'
        assert pending.sha256 == written.sha256 == hashlib.sha256(
            pending.wire_bytes
        ).hexdigest()
    finally:
        client.close()


def test_initialized_notification_pre_callback_failure_writes_no_notification_bytes(
    fake_server: Path, tmp_path: Path
) -> None:
    class RecordingStdin:
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.flushes = 0

        def write(self, payload: bytes) -> None:
            self.writes.append(payload)

        def flush(self) -> None:
            self.flushes += 1

    entries: list[ClientNotificationJournalEntry] = []
    failure = KeyboardInterrupt("pending-callback-secret")

    def reject_pending(entry: ClientNotificationJournalEntry) -> None:
        entries.append(entry)
        raise failure

    client = _client(
        fake_server,
        tmp_path,
        on_client_notification_send_pending=reject_pending,
    )
    client.start()
    actual_process = client._process
    assert actual_process is not None
    recording_stdin = RecordingStdin()
    client._process = cast(subprocess.Popen[bytes], SimpleNamespace(stdin=recording_stdin))
    try:
        with pytest.raises(AppServerError, match="notification was not written") as caught:
            client._send_notification("initialized")
        assert "pending-callback-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert len(entries) == 1
        assert entries[0].phase is ClientNotificationPhase.SEND_PENDING
        assert recording_stdin.writes == []
        assert recording_stdin.flushes == 0
    finally:
        client._process = actual_process
        client.close()


def test_initialize_post_write_callback_failure_is_one_shot_and_never_resends(
    fake_server: Path, tmp_path: Path
) -> None:
    requests: list[RequestJournalEntry] = []
    notifications: list[ClientNotificationJournalEntry] = []
    failure = ValueError("written-callback-secret")

    def reject_written(entry: ClientNotificationJournalEntry) -> None:
        notifications.append(entry)
        raise failure

    client = _client(
        fake_server,
        tmp_path,
        on_send_pending=requests.append,
        on_client_notification_send_pending=notifications.append,
        on_client_notification_written=reject_written,
    )
    client.start()
    try:
        with pytest.raises(AppServerError, match="notification may have been written") as caught:
            client.initialize()
        assert "written-callback-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        with pytest.raises(AppServerError, match="initialize may be called only once"):
            client.initialize()
        assert [entry.method for entry in requests] == ["initialize"]
        assert [entry.phase for entry in notifications] == [
            ClientNotificationPhase.SEND_PENDING,
            ClientNotificationPhase.WRITE_COMPLETED,
        ]
        assert notifications[0].wire_bytes == notifications[1].wire_bytes
        assert notifications[0].sha256 == notifications[1].sha256
    finally:
        client.close()


def test_initialize_write_failure_is_one_shot_and_never_resends(
    fake_server: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingStdin:
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.flushes = 0

        def write(self, payload: bytes) -> None:
            self.writes.append(payload)
            raise OSError("injected notification write failure")

        def flush(self) -> None:
            self.flushes += 1

    request_methods: list[str] = []

    def successful_initialize_request(
        method: str, params: dict[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        request_methods.append(method)
        assert params["clientInfo"] == {"name": "aoi-orgware", "version": "0.4"}
        assert "validate_result" in kwargs
        return {"model": "gpt-5.6"}

    client = _client(fake_server, tmp_path)
    failing_stdin = FailingStdin()
    client._process = cast(subprocess.Popen[bytes], SimpleNamespace(stdin=failing_stdin))
    monkeypatch.setattr(client, "request", successful_initialize_request)

    with pytest.raises(RuntimeDisconnected, match="notification may have been written") as caught:
        client.initialize()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    with pytest.raises(AppServerError, match="initialize may be called only once"):
        client.initialize()

    assert request_methods == ["initialize"]
    assert failing_stdin.writes == [b'{"method":"initialized"}\n']
    assert failing_stdin.flushes == 0


def test_initialize_short_or_invalid_notification_write_is_ambiguous_and_never_resends(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ShortWritingStdin:
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.flushes = 0

        def write(self, payload: bytes) -> object:
            self.writes.append(payload)
            return write_result

        def flush(self) -> None:
            self.flushes += 1

    for write_result in (0, 5, 24, None, "write-result-secret"):
        request_methods: list[str] = []

        def successful_initialize_request(
            method: str, _params: dict[str, Any], **_kwargs: Any
        ) -> dict[str, Any]:
            request_methods.append(method)
            return {"model": "gpt-5.6"}

        notifications: list[ClientNotificationJournalEntry] = []
        client = _client(
            fake_server,
            tmp_path,
            on_client_notification_send_pending=notifications.append,
            on_client_notification_written=notifications.append,
        )
        stdin = ShortWritingStdin()
        client._process = cast(subprocess.Popen[bytes], SimpleNamespace(stdin=stdin))
        monkeypatch.setattr(client, "request", successful_initialize_request)

        with pytest.raises(RuntimeDisconnected, match="notification may have been written") as caught:
            client.initialize()
        assert "write-result-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        with pytest.raises(AppServerError, match="initialize may be called only once"):
            client.initialize()
        assert request_methods == ["initialize"]
        assert stdin.writes == [b'{"method":"initialized"}\n']
        assert stdin.flushes == 0
        assert [entry.phase for entry in notifications] == [ClientNotificationPhase.SEND_PENDING]


def test_initialize_notification_io_value_error_is_redacted_and_never_resends(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for operation in ("write", "flush"):
        class ValueErrorStdin:
            def __init__(self) -> None:
                self.writes: list[bytes] = []
                self.flushes = 0

            def write(self, payload: bytes) -> int:
                self.writes.append(payload)
                if operation == "write":
                    raise ValueError("write-io-secret")
                return len(payload)

            def flush(self) -> None:
                self.flushes += 1
                if operation == "flush":
                    raise ValueError("flush-io-secret")

        request_methods: list[str] = []

        def successful_initialize_request(
            method: str, _params: dict[str, Any], **_kwargs: Any
        ) -> dict[str, Any]:
            request_methods.append(method)
            return {"model": "gpt-5.6"}

        notifications: list[ClientNotificationJournalEntry] = []
        client = _client(
            fake_server,
            tmp_path,
            on_client_notification_send_pending=notifications.append,
            on_client_notification_written=notifications.append,
        )
        stdin = ValueErrorStdin()
        client._process = cast(subprocess.Popen[bytes], SimpleNamespace(stdin=stdin))
        monkeypatch.setattr(client, "request", successful_initialize_request)

        with pytest.raises(RuntimeDisconnected, match="notification may have been written") as caught:
            client.initialize()
        assert "io-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        with pytest.raises(AppServerError, match="initialize may be called only once"):
            client.initialize()
        assert request_methods == ["initialize"]
        assert stdin.writes == [b'{"method":"initialized"}\n']
        assert stdin.flushes == (0 if operation == "write" else 1)
        assert [entry.phase for entry in notifications] == [ClientNotificationPhase.SEND_PENDING]


def test_initialize_first_attempt_consumption_is_atomic_without_deadlock(
    fake_server: Path, tmp_path: Path
) -> None:
    requests: list[RequestJournalEntry] = []
    notifications: list[ClientNotificationJournalEntry] = []
    client = _client(
        fake_server,
        tmp_path,
        on_send_pending=requests.append,
        on_client_notification_send_pending=notifications.append,
        on_client_notification_written=notifications.append,
    )
    client.start()
    barrier = threading.Barrier(3)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()

    def call_initialize() -> None:
        barrier.wait(timeout=2)
        try:
            client.initialize()
        except AppServerError as exc:
            outcome = str(exc)
        else:
            outcome = "success"
        with outcomes_lock:
            outcomes.append(outcome)

    first = threading.Thread(target=call_initialize)
    second = threading.Thread(target=call_initialize)
    first.start()
    second.start()
    try:
        barrier.wait(timeout=2)
        first.join(timeout=3)
        second.join(timeout=3)
        assert first.is_alive() is False
        assert second.is_alive() is False
        assert sorted(outcomes) == ["initialize may be called only once", "success"]
        assert [entry.method for entry in requests] == ["initialize"]
        assert [entry.phase for entry in notifications] == [
            ClientNotificationPhase.SEND_PENDING,
            ClientNotificationPhase.WRITE_COMPLETED,
        ]
    finally:
        client.close()


def test_version_probe_and_process_callbacks_are_separate_exact_effects(
    fake_server: Path, tmp_path: Path
) -> None:
    order: list[str] = []
    probes: list[VersionProbeJournalEntry] = []
    processes: list[ProcessJournalEntry] = []
    version_probe_called = False

    def record_probe(entry: VersionProbeJournalEntry) -> None:
        order.append(entry.phase)
        probes.append(entry)

    def record_process(entry: ProcessJournalEntry) -> None:
        order.append(entry.phase)
        processes.append(entry)

    client = _client(
        fake_server,
        tmp_path,
        on_version_probe_pending=record_probe,
        on_version_probe_observed=record_probe,
        on_process_start_pending=record_process,
        on_process_started=record_process,
    )
    original_capture = client._capture_version_probe_output

    def observed_capture(*args: Any, **kwargs: Any) -> tuple[bytes, bytes, int]:
        nonlocal version_probe_called
        version_probe_called = True
        return original_capture(*args, **kwargs)

    client._capture_version_probe_output = observed_capture  # type: ignore[method-assign]
    client.start()
    try:
        assert version_probe_called is True
        assert order == [
            "version_probe_pending",
            "version_probe_observed",
            "process_start_pending",
            "process_started",
        ]
        assert len(probes) == 2
        pending, observed = probes
        assert pending.argv == observed.argv == (
            str(Path(sys.executable).resolve()),
            "-c",
            "print('fake-app-server 0.145.0')",
        )
        assert json.loads(pending.payload_bytes) == {
            "argv": list(pending.argv),
            "phase": "version_probe_pending",
        }
        assert pending.stdout_bytes is None
        assert pending.stderr_bytes is None
        assert pending.returncode is None
        assert observed.stdout_bytes is not None
        assert observed.stdout_bytes.rstrip(b"\r\n") == b"fake-app-server 0.145.0"
        assert observed.stderr_bytes == b""
        assert observed.returncode == 0
        assert json.loads(observed.payload_bytes) == {
            "argv": list(observed.argv),
            "phase": "version_probe_observed",
            "returncode": 0,
            "stderr_hex": "",
            "stdout_hex": observed.stdout_bytes.hex(),
        }
        assert [entry.phase for entry in processes] == [
            "process_start_pending",
            "process_started",
        ]
        assert json.loads(processes[0].payload_bytes)["argv"] == list(client.argv)
        assert processes[0].pid is None
        assert isinstance(processes[1].pid, int)
    finally:
        client.close()


def test_version_probe_capture_drains_both_pipes_with_exact_aggregate_bound(
    fake_server: Path, tmp_path: Path
) -> None:
    stdout_size = 70_000
    stderr_size = 70_000
    script = (
        "import sys\n"
        f"sys.stdout.buffer.write(b'a' * {stdout_size})\n"
        "sys.stdout.buffer.flush()\n"
        f"sys.stderr.buffer.write(b'b' * {stderr_size})\n"
        "sys.stderr.buffer.flush()\n"
    )
    client = _client(
        fake_server,
        tmp_path,
        max_line_bytes=300_000,
        _test_version_args=("-u", "-c", script),
    )

    stdout_bytes, stderr_bytes, returncode = (
        client._capture_version_probe_output()
    )

    assert stdout_bytes == b"a" * stdout_size
    assert stderr_bytes == b"b" * stderr_size
    assert returncode == 0
    assert client._version_probe_process is None
    assert client._version_probe_threads == ()


@pytest.mark.parametrize("distribution", ["stdout", "stderr", "split"])
@pytest.mark.parametrize("over_budget", [False, True])
def test_version_probe_capture_uses_one_combined_raw_byte_budget(
    fake_server: Path,
    tmp_path: Path,
    distribution: str,
    over_budget: bool,
) -> None:
    script = (
        "import os,sys\n"
        "stdout_size=int(os.environ['SAFE_STDOUT_SIZE'])\n"
        "stderr_size=int(os.environ['SAFE_STDERR_SIZE'])\n"
        "sys.stdout.buffer.write(b'v' + b'a' * (stdout_size - 1))\n"
        "sys.stdout.buffer.flush()\n"
        "sys.stderr.buffer.write(b'b' * stderr_size)\n"
        "sys.stderr.buffer.flush()\n"
    )
    planner = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        environment={"SAFE_STDOUT_SIZE": "1", "SAFE_STDERR_SIZE": "0"},
        _test_version_args=("-u", "-c", script),
    )
    raw_budget = planner._version_probe_raw_capture_budget()
    planner.close()
    total_size = raw_budget + int(over_budget)
    if distribution == "stdout":
        stdout_size, stderr_size = total_size, 0
    elif distribution == "stderr":
        stdout_size, stderr_size = 1, total_size - 1
    else:
        stdout_size = 1 + ((total_size - 1) // 2)
        stderr_size = total_size - stdout_size
    client = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        environment={
            "SAFE_STDOUT_SIZE": str(stdout_size),
            "SAFE_STDERR_SIZE": str(stderr_size),
        },
        _test_version_args=("-u", "-c", script),
    )
    assert client._version_probe_raw_capture_budget() == raw_budget
    if not over_budget:
        stdout_bytes, stderr_bytes, returncode = (
            client._capture_version_probe_output()
        )
        assert (len(stdout_bytes), len(stderr_bytes), returncode) == (
            stdout_size,
            stderr_size,
            0,
        )
    else:
        with pytest.raises(AppServerError, match="bounded version probe"):
            client._capture_version_probe_output()
    assert client._version_probe_process is None
    assert client._version_probe_threads == ()


def test_version_probe_overflow_after_pending_ack_is_not_retried(
    fake_server: Path, tmp_path: Path
) -> None:
    script = (
        "import sys\n"
        "sys.stdout.write('fake-app-server 0.145.0\\n')\n"
        "sys.stdout.flush()\n"
        "sys.stderr.buffer.write(b'x' * 8192)\n"
        "sys.stderr.buffer.flush()\n"
    )
    client = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        _test_version_args=("-u", "-c", script),
    )

    with pytest.raises(AppServerError, match="could not execute"):
        client.start()

    assert client._version_probe_effect_phase.value == "effect_pending"
    assert client._version_probe_process is None
    assert client._version_probe_threads == ()
    with pytest.raises(AppServerError, match="retry is forbidden"):
        client.start()


@pytest.mark.parametrize("distribution", ["stdout", "stderr", "split"])
def test_version_probe_capture_budget_closes_controller_observed_journal(
    fake_server: Path,
    tmp_path: Path,
    distribution: str,
) -> None:
    script = (
        "import os,sys\n"
        "stdout_size=int(os.environ['SAFE_STDOUT_SIZE'])\n"
        "stderr_size=int(os.environ['SAFE_STDERR_SIZE'])\n"
        "sys.stdout.buffer.write(b'v' + b'a' * (stdout_size - 1))\n"
        "sys.stdout.buffer.flush()\n"
        "sys.stderr.buffer.write(b'b' * stderr_size)\n"
        "sys.stderr.buffer.flush()\n"
    )
    planner = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        environment={"SAFE_STDOUT_SIZE": "1", "SAFE_STDERR_SIZE": "0"},
        _test_version_args=("-u", "-c", script),
    )
    raw_budget = planner._version_probe_raw_capture_budget()
    planner.close()

    for over_budget in (False, True):
        total_size = raw_budget + int(over_budget)
        if distribution == "stdout":
            stdout_size, stderr_size = total_size, 0
        elif distribution == "stderr":
            stdout_size, stderr_size = 1, total_size - 1
        else:
            stdout_size = 1 + ((total_size - 1) // 2)
            stderr_size = total_size - stdout_size
        expected_version = "v" + ("a" * (stdout_size - 1))
        controller, durable = _version_probe_controller(tmp_path)
        client = _client(
            fake_server,
            tmp_path,
            max_line_bytes=1024,
            environment={
                "SAFE_STDOUT_SIZE": str(stdout_size),
                "SAFE_STDERR_SIZE": str(stderr_size),
            },
            runtime_pin=_fake_runtime_pin(app_server_version=expected_version),
            _test_version_args=("-u", "-c", script),
            on_version_probe_pending=controller._on_version_probe_pending,
            on_version_probe_observed=controller._on_version_probe_observed,
        )
        try:
            if over_budget:
                with pytest.raises(AppServerError, match="bounded version probe"):
                    client._verify_runtime_version()
                assert client._version_probe_effect_phase.value == "effect_pending"
                assert [row["event_type"] for row in durable] == [
                    "reserved",
                    "version_probe_pending",
                ]
            else:
                client._verify_runtime_version()
                assert client._version_probe_effect_phase.value == "observed"
                assert [row["event_type"] for row in durable] == [
                    "reserved",
                    "version_probe_pending",
                    "version_probe_observed",
                ]
                observed_size = int(durable[-1]["payload_size_bytes"])
                assert observed_size <= client.max_line_bytes
        finally:
            client.close()


def test_version_probe_capture_budget_reserves_worst_case_returncode_and_argv(
    fake_server: Path, tmp_path: Path
) -> None:
    client = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        _test_version_args=("--version", "--long-argument"),
    )
    raw_budget = client._version_probe_raw_capture_budget()
    for returncode in (-2_147_483_648, 4_294_967_295):
        accepted = client._version_probe_journal_entry(
            "version_probe_observed",
            stdout_bytes=b"a" * raw_budget,
            stderr_bytes=b"",
            returncode=returncode,
        )
        assert len(accepted.payload_bytes) <= client.max_line_bytes
    with pytest.raises(AppServerError, match="journal entry exceeds"):
        client._version_probe_journal_entry(
            "version_probe_observed",
            stdout_bytes=b"a" * (raw_budget + 1),
            stderr_bytes=b"",
            returncode=-2_147_483_648,
        )


def test_version_probe_pending_callback_cannot_mutate_frozen_effect_plan(
    fake_server: Path, tmp_path: Path
) -> None:
    controller, durable = _version_probe_controller(tmp_path)
    pending_entries: list[VersionProbeJournalEntry] = []
    observed_entries: list[VersionProbeJournalEntry] = []
    client: CodexAppServerStdio

    def persist_then_mutate(entry: VersionProbeJournalEntry) -> None:
        controller._on_version_probe_pending(entry)
        pending_entries.append(entry)
        client.max_line_bytes = 128
        client._version_args = ("-c", "raise SystemExit(37)")

    def persist_observed(entry: VersionProbeJournalEntry) -> None:
        controller._on_version_probe_observed(entry)
        observed_entries.append(entry)

    client = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        on_version_probe_pending=persist_then_mutate,
        on_version_probe_observed=persist_observed,
    )

    client._verify_runtime_version()

    assert [row["event_type"] for row in durable] == [
        "reserved",
        "version_probe_pending",
        "version_probe_observed",
    ]
    assert len(pending_entries) == len(observed_entries) == 1
    assert pending_entries[0].argv == observed_entries[0].argv
    assert pending_entries[0].argv != (
        str(client.executable),
        *client._version_args,
    )
    assert len(observed_entries[0].payload_bytes) > client.max_line_bytes
    assert len(observed_entries[0].payload_bytes) <= 1024
    assert client._version_probe_effect_phase.value == "observed"


def test_version_probe_observed_journal_reuses_plan_after_capture_mutation(
    fake_server: Path, tmp_path: Path
) -> None:
    controller, durable = _version_probe_controller(tmp_path)
    entries: list[VersionProbeJournalEntry] = []

    def persist(entry: VersionProbeJournalEntry) -> None:
        entries.append(entry)
        if entry.phase == "version_probe_pending":
            controller._on_version_probe_pending(entry)
        else:
            controller._on_version_probe_observed(entry)

    client = _client(
        fake_server,
        tmp_path,
        max_line_bytes=1024,
        on_version_probe_pending=persist,
        on_version_probe_observed=persist,
    )
    original_capture = client._capture_version_probe_output

    def capture_then_mutate(
        *args: Any, **kwargs: Any
    ) -> tuple[bytes, bytes, int]:
        result = original_capture(*args, **kwargs)
        client.max_line_bytes = 128
        client._version_args = ("-c", "raise SystemExit(38)")
        return result

    client._capture_version_probe_output = capture_then_mutate  # type: ignore[method-assign]

    client._verify_runtime_version()

    assert [entry.phase for entry in entries] == [
        "version_probe_pending",
        "version_probe_observed",
    ]
    assert entries[0].argv == entries[1].argv
    assert len(entries[1].payload_bytes) > client.max_line_bytes
    assert [row["event_type"] for row in durable] == [
        "reserved",
        "version_probe_pending",
        "version_probe_observed",
    ]
    assert client._version_probe_effect_phase.value == "observed"


def test_version_probe_timeout_kills_and_reaps_owned_direct_child(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(stdio, "_VERSION_PROBE_TIMEOUT_SECONDS", 0.2)
    script = "import time; time.sleep(30)\n"
    client = _client(
        fake_server,
        tmp_path,
        _test_version_args=("-u", "-c", script),
    )
    started = time.monotonic()

    with pytest.raises(AppServerError, match="could not execute"):
        client.start()

    assert time.monotonic() - started < 3
    assert client._version_probe_effect_phase.value == "effect_pending"
    assert client._version_probe_process is None
    assert client._version_probe_threads == ()
    with pytest.raises(AppServerError, match="retry is forbidden"):
        client.start()


def test_version_probe_second_reader_start_failure_cleans_first_reader_and_child(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(
        fake_server,
        tmp_path,
        _test_version_args=("-u", "-c", "import time; time.sleep(30)\n"),
    )
    original_start = threading.Thread.start
    starts = 0

    def fail_second_start(thread: threading.Thread) -> None:
        nonlocal starts
        starts += 1
        if starts == 2:
            raise RuntimeError("synthetic second reader start failure")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_second_start)
    with pytest.raises(AppServerError, match="bounded version probe"):
        client._capture_version_probe_output()

    assert starts == 2
    assert client._version_probe_process is None
    assert client._version_probe_threads == ()


def test_version_probe_baseexception_during_poll_still_cleans_owned_child(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = subprocess.Popen
    child: subprocess.Popen[bytes] | None = None

    class InterruptingPoll:
        def __init__(self, process: subprocess.Popen[bytes]) -> None:
            self._process = process
            self.stdout = process.stdout
            self.stderr = process.stderr

        def poll(self) -> int | None:
            raise KeyboardInterrupt("synthetic poll interrupt")

        def kill(self) -> None:
            self._process.kill()

        def wait(self, timeout: float | None = None) -> int:
            return self._process.wait(timeout=timeout)

    def interrupting_popen(*args: Any, **kwargs: Any) -> InterruptingPoll:
        nonlocal child
        child = real_popen(*args, **kwargs)
        return InterruptingPoll(child)

    monkeypatch.setattr(stdio.subprocess, "Popen", interrupting_popen)
    client = _client(
        fake_server,
        tmp_path,
        _test_version_args=("-u", "-c", "import time; time.sleep(30)\n"),
    )

    with pytest.raises(KeyboardInterrupt, match="synthetic poll interrupt"):
        client._capture_version_probe_output()

    assert child is not None
    assert child.poll() is not None
    assert client._version_probe_process is None
    assert client._version_probe_threads == ()


def test_version_probe_unconfirmed_cleanup_retains_separate_process_handle(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnconfirmableProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()

        def poll(self) -> int | None:
            raise OSError("synthetic poll failure")

        def kill(self) -> None:
            raise OSError("synthetic kill failure")

        def wait(self, timeout: float | None = None) -> int:
            raise OSError("synthetic wait failure")

    process = UnconfirmableProcess()
    monkeypatch.setattr(stdio.subprocess, "Popen", lambda *args, **kwargs: process)
    client = _client(fake_server, tmp_path)

    with pytest.raises(AppServerError, match="cleanup is unconfirmed"):
        client._capture_version_probe_output()

    assert client._version_probe_process is process
    assert client._version_probe_threads == ()


def test_version_probe_pending_callback_prevents_the_probe_without_consuming_start(
    fake_server: Path, tmp_path: Path
) -> None:
    called = False
    entries: list[VersionProbeJournalEntry] = []

    def reject_pending(entry: VersionProbeJournalEntry) -> None:
        entries.append(entry)
        raise KeyboardInterrupt("pending-callback-secret")

    client = _client(
        fake_server,
        tmp_path,
        on_version_probe_pending=reject_pending,
    )
    original_capture = client._capture_version_probe_output

    def observed_capture(*args: Any, **kwargs: Any) -> tuple[bytes, bytes, int]:
        nonlocal called
        called = True
        return original_capture(*args, **kwargs)

    client._capture_version_probe_output = observed_capture  # type: ignore[method-assign]
    with pytest.raises(AppServerError, match="probe was not executed") as caught:
        client.start()
    assert "pending-callback-secret" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert called is False
    assert client._process is None
    assert [entry.phase for entry in entries] == ["version_probe_pending"]
    client.on_version_probe_pending = None
    client.start()
    client.close()


def test_version_probe_observed_callback_preserves_unknown_effect_without_retry(
    fake_server: Path, tmp_path: Path
) -> None:
    calls = 0
    entries: list[VersionProbeJournalEntry] = []

    def reject_observed(entry: VersionProbeJournalEntry) -> None:
        entries.append(entry)
        raise SystemExit("observed-callback-secret")

    client = _client(
        fake_server,
        tmp_path,
        on_version_probe_observed=reject_observed,
    )
    original_capture = client._capture_version_probe_output

    def observed_capture(*args: Any, **kwargs: Any) -> tuple[bytes, bytes, int]:
        nonlocal calls
        calls += 1
        return original_capture(*args, **kwargs)

    client._capture_version_probe_output = observed_capture  # type: ignore[method-assign]
    with pytest.raises(AppServerError, match="effect is unknown") as caught:
        client.start()
    assert "observed-callback-secret" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert calls == 1
    assert client._process is None
    assert [entry.phase for entry in entries] == ["version_probe_observed"]
    with pytest.raises(AppServerError, match="retry is forbidden"):
        client.start()
    assert calls == 1


@pytest.mark.parametrize(
    "raised",
    [
        OSError("injected version probe launch failure"),
        subprocess.TimeoutExpired(["codex", "--version"], timeout=10),
    ],
)
def test_version_probe_run_failure_is_non_retryable_after_pending_ack(
    fake_server: Path,
    tmp_path: Path,
    raised: BaseException,
) -> None:
    calls = 0

    def fail_capture(*_args: Any, **_kwargs: Any) -> NoReturn:
        nonlocal calls
        calls += 1
        raise raised

    client = _client(fake_server, tmp_path)
    client._capture_version_probe_output = fail_capture  # type: ignore[method-assign]
    with pytest.raises(AppServerError, match="could not execute"):
        client.start()
    assert calls == 1
    with pytest.raises(AppServerError, match="retry is forbidden"):
        client.start()
    assert calls == 1


@pytest.mark.parametrize("later_failure", ["process_pending", "popen"])
def test_observed_version_probe_is_not_resent_after_later_start_failure(
    fake_server: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    later_failure: str,
) -> None:
    calls = 0
    kwargs: dict[str, Any] = {}
    if later_failure == "process_pending":
        def reject_process_pending(_entry: ProcessJournalEntry) -> None:
            raise RuntimeError("process pending journal unavailable")

        kwargs["on_process_start_pending"] = reject_process_pending
    else:
        def reject_popen(*_args: Any, **_kwargs: Any) -> NoReturn:
            raise OSError("injected Popen failure")

        def install_popen_failure(_entry: VersionProbeJournalEntry) -> None:
            monkeypatch.setattr(stdio.subprocess, "Popen", reject_popen)

        kwargs["on_version_probe_observed"] = install_popen_failure
    client = _client(fake_server, tmp_path, **kwargs)
    original_capture = client._capture_version_probe_output

    def observed_capture(*args: Any, **kwargs: Any) -> tuple[bytes, bytes, int]:
        nonlocal calls
        calls += 1
        return original_capture(*args, **kwargs)

    client._capture_version_probe_output = observed_capture  # type: ignore[method-assign]
    with pytest.raises(AppServerError, match="process was not started|could not start"):
        client.start()
    assert calls == 1
    assert client._process is None
    with pytest.raises(AppServerError, match="retry is forbidden"):
        client.start()
    assert calls == 1


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit])
def test_process_started_baseexception_runs_cleanup_without_claiming_clean_exit(
    fake_server: Path, tmp_path: Path, failure_type: type[BaseException]
) -> None:
    def interrupt_after_popen(_entry: ProcessJournalEntry) -> None:
        raise failure_type("process-callback-secret")

    client = _client(
        fake_server,
        tmp_path,
        on_process_started=interrupt_after_popen,
    )
    with pytest.raises(AppServerError, match="process exited during cleanup") as caught:
        client.start()
    assert "process-callback-secret" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert client._process is None


def test_process_started_callback_preserves_unconfirmed_exit_when_cleanup_cannot_prove_it(
    fake_server: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process: subprocess.Popen[bytes] | None = None

    def refuse_cleanup(_entry: ProcessJournalEntry) -> None:
        nonlocal process
        process = client._process
        assert process is not None

        def fail_cleanup(*_args: Any, **_kwargs: Any) -> NoReturn:
            raise OSError("injected cleanup failure")

        monkeypatch.setattr(process, "poll", fail_cleanup)
        monkeypatch.setattr(process, "terminate", fail_cleanup)
        monkeypatch.setattr(process, "kill", fail_cleanup)
        monkeypatch.setattr(process, "wait", fail_cleanup)
        raise KeyboardInterrupt("process-callback-secret")

    client = _client(fake_server, tmp_path, on_process_started=refuse_cleanup)
    try:
        with pytest.raises(AppServerError, match="exit is unconfirmed") as caught:
            client.start()
        assert "process-callback-secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert process is not None
        assert client._process is process
    finally:
        monkeypatch.undo()
        client.close()


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
    with pytest.raises(AppServerError, match="retry is forbidden"):
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
