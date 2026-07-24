from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import cast

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware.semantic_events import canonical_json_bytes


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def correlation(thread: str | None = None, turn: str | None = None, item: str | None = None) -> dict[str, str | None]:
    return {"thread_id": thread, "turn_id": turn, "item_id": item}


def runtime_pin(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        **contracts.pinned_runtime_binding(),
        "executable_path": "C:/tools/codex-app-server.exe",
    }
    value.update(changes)
    return value


def runtime_pin_v2(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        **contracts.pinned_runtime_binding_v2(),
        "executable_path": "C:/tools/codex-app-server.exe",
    }
    value.update(changes)
    return value


def intent(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
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
        "expected_semantic_head_sha256": SHA_A,
        "prompt_sha256": SHA_B,
        "prompt_size_bytes": 41,
        "cwd": "C:/scratch/repo",
        "requested_model": "gpt-5.6-terra",
        "requested_effort": "high",
        "sandbox": "workspaceWrite",
        "approval": "never",
        "runtime_pin": runtime_pin(),
        "pre_git_binding": {
            "git_head_sha256": SHA_A,
            "git_tree_sha256": SHA_B,
            "git_status_sha256": SHA_C,
            "claim_coverage_sha256": SHA_D,
        },
    }
    value.update(changes)
    return value


def reservation(intent_sha: str, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1,
        "reservation_id": "reservation-1",
        "launch_intent_sha256": intent_sha,
        "permit_sha256": SHA_C,
        "runtime_pin": runtime_pin(),
        "state": "reserved",
        "correlation": correlation(),
    }
    value.update(changes)
    return value


def event(
    intent_sha: str,
    reservation_sha: str,
    *,
    event_id: str,
    sequence: int,
    prev: str,
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
    **changes: object,
) -> dict[str, object]:
    pending = event_type.endswith("_pending")
    unknown = event_type == "launch_unknown"
    method = str(changes.get("wire_method", contracts._EVENT_WIRE_METHOD[event_type]))
    response_observed = event_type in {
        "initialized",
        "model_list_observed",
        "thread_started",
        "turn_started",
        "interrupt_observed",
    } or (event_type == "failed" and method not in {"process/exited", "turn/completed"})
    wire_observed = response_observed or event_type in {
        "process_started",
        "item_started",
        "item_completed",
        "completed",
        "interrupted",
    } or (event_type == "failed" and method == "turn/completed")
    fault_observed = event_type in {"launch_unknown", "runtime_unknown"} or (
        event_type == "failed" and method == "process/exited"
    )
    value: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V1,
        "event_id": event_id,
        "sequence": sequence,
        "prev_event_sha256": prev,
        "launch_intent_sha256": intent_sha,
        "reservation_sha256": reservation_sha,
        "event_type": event_type,
        "state": state,
        "wire_method": method,
        "wire_event_sha256": SHA_A if wire_observed else None,
        "payload_size_bytes": 0 if event_type == "reserved" else 42,
        "item_type": "agent_message" if event_type in {"item_started", "item_completed"} else None,
        "status": contracts._EVENT_WIRE_STATUS[event_type],
        "request_id": f"request-{sequence}" if pending or unknown else None,
        "request_bytes_sha256": SHA_B if pending or unknown else None,
        "response_sha256": SHA_A if response_observed else None,
        "fault_kind": "RuntimeDisconnected" if fault_observed else None,
        "fault_evidence_sha256": SHA_D if fault_observed else None,
        "fault_evidence_size_bytes": 42 if fault_observed else None,
        "correlation": runtime,
    }
    value.update(changes)
    return value


def append(
    records: list[dict[str, object]],
    intent_sha: str,
    reservation_sha: str,
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
    **changes: object,
) -> list[dict[str, object]]:
    sequence = len(records) + 1
    raw = event(
        intent_sha,
        reservation_sha,
        event_id=f"event-{sequence}",
        sequence=sequence,
        prev=contracts.ZERO_SHA256 if not records else records[-1]["event_sha256"],
        event_type=event_type,
        state=state,
        runtime=runtime,
        **changes,
    )
    return contracts.append_transport_journal_event(records, contracts.seal_journal_event(raw))


def v2_material() -> tuple[dict[str, object], dict[str, object]]:
    raw_intent = intent(
        contract_type=contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V2,
        network_access=False,
        runtime_pin=runtime_pin_v2(),
    )
    sealed_intent = contracts.seal_launch_intent(raw_intent)
    sealed_reservation = contracts.seal_reservation(
        {
            **reservation(sealed_intent["intent_sha256"]),
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V2,
            "runtime_pin": runtime_pin_v2(),
            "evidence_level": "transport_reserved",
        }
    )
    return sealed_intent, sealed_reservation


def v2_request_witness(
    sealed_intent: dict[str, object],
    sealed_reservation: dict[str, object],
    *,
    method: str,
    request_id: str,
    request_sha256: str = SHA_B,
    runtime: dict[str, str | None] | None = None,
    **changes: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "launch_intent_sha256": sealed_intent["intent_sha256"],
        "permit_sha256": sealed_reservation["permit_sha256"],
        "expected_semantic_head_sha256": sealed_intent[
            "expected_semantic_head_sha256"
        ],
        "request_id": request_id,
        "wire_method": method,
        "request_envelope_sha256": request_sha256,
        "request_size_bytes": 42,
        "prompt_sha256": sealed_intent["prompt_sha256"],
        "prompt_size_bytes": sealed_intent["prompt_size_bytes"],
        "cwd": sealed_intent["cwd"],
        "requested_model": sealed_intent["requested_model"],
        "requested_effort": sealed_intent["requested_effort"],
        "approval": sealed_intent["approval"],
        "sandbox": sealed_intent["sandbox"],
        "network_access": False,
        "runtime_pin": sealed_intent["runtime_pin"],
        "thread_start_config": (
            contracts._THREAD_START_CONFIG if method == "thread/start" else None
        ),
        "correlation": correlation() if runtime is None else runtime,
    }
    value.update(changes)
    return contracts.seal_request_witness(value)


def append_v2(
    records: list[dict[str, object]],
    sealed_intent: dict[str, object],
    sealed_reservation: dict[str, object],
    event_type: str,
    state: str,
    runtime: dict[str, str | None],
    **changes: object,
) -> list[dict[str, object]]:
    sequence = len(records) + 1
    raw = event(
        str(sealed_intent["intent_sha256"]),
        str(sealed_reservation["reservation_sha256"]),
        event_id=f"v2-event-{sequence}",
        sequence=sequence,
        prev=contracts.ZERO_SHA256 if not records else str(records[-1]["event_sha256"]),
        event_type=event_type,
        state=state,
        runtime=runtime,
        **changes,
    )
    raw["contract_type"] = contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V2
    request_bound = event_type.endswith("_pending") or event_type == "launch_unknown"
    raw["request_witness"] = (
        v2_request_witness(
            sealed_intent,
            sealed_reservation,
            method=str(raw["wire_method"]),
            request_id=str(raw["request_id"]),
            request_sha256=str(raw["request_bytes_sha256"]),
            runtime=runtime,
        )
        if request_bound
        else None
    )
    return contracts.append_transport_journal_event(
        records, contracts.seal_journal_event(raw)
    )


def to_turn_started() -> tuple[str, str, list[dict[str, object]]]:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(reservation(sealed_intent["intent_sha256"]))
    records: list[dict[str, object]] = []
    for event_type, state, runtime in (
        ("reserved", "reserved", correlation()),
        ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()),
        ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()),
        ("thread_start_send_pending", "reserved", correlation()),
        ("thread_started", "thread_started", correlation("thread-1")),
        ("turn_start_send_pending", "thread_started", correlation("thread-1")),
        ("turn_started", "turn_started", correlation("thread-1", "turn-1")),
    ):
        records = append(records, sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], event_type, state, runtime)
    return sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], records


def test_packaged_runtime_pin_and_strict_manifest_guards() -> None:
    legacy = contracts.pinned_runtime_binding()
    pin = contracts.pinned_runtime_binding_v2()
    assert pin["app_server_executable_sha256"] == "5163c75ed88d460b35b03c8d8f4ef190b3bdd09971d7ac2bd90b48c435f1cf14"
    assert pin["executable_size_bytes"] == 299117872
    assert legacy["schema_manifest_sha256"] == (
        "6b8bfa74e475c6c9b46926c46f287f47873d188b13ab3df8db4633602db73262"
    )
    assert pin["schema_manifest_sha256"] == (
        "c05875501c6e9a6778cc4afc5488cdb87aae539217121ebbb5c8dd14c79bc025"
    )
    assert pin["combined_v2_schema_sha256"] == (
        "27f8d983f19d8e1a5548d52176de0a460fb05aaf2a72110f913c6f4af2bd4f27"
    )
    root = Path(contracts.__file__).resolve().parent / "resources" / "codex_app_server" / "0.145.0"
    pin_bytes = (root / "runtime-pin.json").read_bytes()
    manifest = json.loads((root / "schema-manifest.json").read_bytes())
    combined = (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    bad = copy.deepcopy(manifest)
    bad[0]["path"] = "../schema.json"
    with pytest.raises(contracts.CodexTransportContractError):
        contracts._validate_packaged_runtime_payload(pin_bytes, canonical_json_bytes(bad), combined)
    reordered = list(reversed(manifest))
    with pytest.raises(contracts.CodexTransportContractError):
        contracts._validate_packaged_runtime_payload(pin_bytes, canonical_json_bytes(reordered), combined)


def _replace_pin_field(pin: dict[str, object], path: tuple[str | int, ...], value: object) -> None:
    target: object = pin
    for part in path[:-1]:
        if isinstance(part, str):
            assert isinstance(target, dict)
            target = target[part]
        else:
            assert isinstance(target, list)
            target = target[part]
    if isinstance(path[-1], str):
        assert isinstance(target, dict)
        target[path[-1]] = value
    else:
        assert isinstance(target, list)
        target[path[-1]] = value


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("schema_version",), 1),
        (("release_tag",), "rust-v0.145.0-forged"),
        (("release_url",), "https://example.invalid/release"),
        (("codex_cli_version",), "codex-cli 0.145.0-forged"),
        (("codex_app_server_version",), "codex-app-server 0.145.0-forged"),
        (("app_server_asset", "name"), "forged-app-server.zip"),
        (("app_server_asset", "size"), 1),
        (("app_server_asset", "sha256"), SHA_A),
        (("app_server_asset", "url"), "https://example.invalid/app.zip"),
        (("app_server_executable", "name"), "forged-app-server.exe"),
        (("app_server_executable", "size"), 1),
        (("app_server_executable", "sha256"), SHA_A),
        (("schema_generator_asset", "name"), "forged-codex.zip"),
        (("schema_generator_asset", "size"), 1),
        (("schema_generator_asset", "sha256"), SHA_A),
        (("schema_generator_asset", "url"), "https://example.invalid/codex.zip"),
        (("schema_generator_executable", "name"), "forged-codex.exe"),
        (("schema_generator_executable", "size"), 1),
        (("schema_generator_executable", "sha256"), SHA_A),
        (("stable_schema", "generator_arguments"), ["forged"]),
        (("stable_schema", "experimental"), True),
        (("stable_schema", "file_count"), 1),
        (("stable_schema", "canonicalization"), "forged"),
        (("stable_schema", "manifest_format"), "forged"),
        (("stable_schema", "manifest_size"), 1),
        (("stable_schema", "manifest_sha256"), SHA_A),
        (("stable_schema", "combined_v2_schema_size"), 1),
        (("stable_schema", "combined_v2_schema_sha256"), SHA_A),
    ),
)
def test_packaged_runtime_pin_rejects_every_pinned_field_mutation(
    path: tuple[str | int, ...], replacement: object
) -> None:
    root = Path(contracts.__file__).resolve().parent / "resources" / "codex_app_server" / "0.145.0"
    pin = json.loads((root / "runtime-pin.json").read_bytes())
    manifest = (root / "schema-manifest.json").read_bytes()
    combined = (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    _replace_pin_field(pin, path, replacement)
    with pytest.raises(contracts.CodexTransportContractError, match="stable contract"):
        contracts._validate_packaged_runtime_payload(
            canonical_json_bytes(pin), manifest, combined
        )


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("schema_version",), True),
        (("app_server_asset", "size"), True),
        (("stable_schema", "experimental"), 0),
        (("stable_schema", "generator_arguments"), "app-server"),
    ),
)
def test_packaged_runtime_pin_rejects_equal_but_wrong_scalar_or_container_types(
    path: tuple[str | int, ...], replacement: object
) -> None:
    root = Path(contracts.__file__).resolve().parent / "resources" / "codex_app_server" / "0.145.0"
    pin = json.loads((root / "runtime-pin.json").read_bytes())
    manifest = (root / "schema-manifest.json").read_bytes()
    combined = (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    _replace_pin_field(pin, path, replacement)
    with pytest.raises(contracts.CodexTransportContractError, match="stable contract"):
        contracts._validate_packaged_runtime_payload(
            canonical_json_bytes(pin), manifest, combined
        )


def test_packaged_runtime_pin_rejects_duplicate_json_keys() -> None:
    root = Path(contracts.__file__).resolve().parent / "resources" / "codex_app_server" / "0.145.0"
    pin = (root / "runtime-pin.json").read_bytes()
    manifest = (root / "schema-manifest.json").read_bytes()
    combined = (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    duplicate = pin.replace(
        b'{\n  "schema_version": 2,',
        b'{\n  "schema_version": 2,\n  "schema_version": 2,',
        1,
    )
    assert duplicate != pin
    with pytest.raises(contracts.CodexTransportContractError, match="duplicate key"):
        contracts._validate_packaged_runtime_payload(duplicate, manifest, combined)


def test_packaged_combined_schema_rejects_duplicate_order_and_semantic_drift() -> None:
    root = Path(contracts.__file__).resolve().parent / "resources" / "codex_app_server" / "0.145.0"
    pin = (root / "runtime-pin.json").read_bytes()
    manifest = (root / "schema-manifest.json").read_bytes()
    combined = (root / "codex_app_server_protocol.v2.schemas.json").read_bytes()
    with pytest.raises(contracts.CodexTransportContractError, match="duplicate key"):
        contracts._validate_packaged_runtime_payload(
            pin, manifest, b'{"value":1,"value":1}'
        )
    parsed = json.loads(combined)
    reordered = json.dumps(parsed, indent=2, sort_keys=False).encode("utf-8")
    assert json.loads(reordered) == parsed
    assert reordered != combined
    with pytest.raises(
        contracts.CodexTransportContractError, match="not canonical JSON"
    ):
        contracts._validate_packaged_runtime_payload(pin, manifest, reordered)
    changed = copy.deepcopy(parsed)
    changed["title"] = "semantic drift"
    with pytest.raises(
        contracts.CodexTransportContractError, match="digest drifted"
    ):
        contracts._validate_packaged_runtime_payload(
            pin, manifest, canonical_json_bytes(changed)
        )


def test_v1_raw_runtime_pin_is_readable_but_v2_requires_semantic_pin() -> None:
    legacy = contracts.seal_launch_intent(intent())
    assert contracts.validate_launch_intent(legacy) == legacy
    raw_v2 = intent(
        contract_type=contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V2,
        network_access=False,
    )
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="canonical-semantic V2",
    ):
        contracts.seal_launch_intent(raw_v2)
    sealed_v2, sealed_reservation = v2_material()
    assert sealed_v2["runtime_pin"]["schema_manifest_sha256"] == (
        "c05875501c6e9a6778cc4afc5488cdb87aae539217121ebbb5c8dd14c79bc025"
    )
    assert sealed_reservation["runtime_pin"] == sealed_v2["runtime_pin"]


def test_packaged_runtime_resource_reader_is_bounded(tmp_path: Path) -> None:
    resource = tmp_path / "resource.bin"
    resource.write_bytes(b"1234")
    with pytest.raises(contracts.CodexTransportContractError, match="byte bound"):
        contracts._read_bounded_packaged_resource(
            resource, maximum_bytes=3, label="test resource"
        )


@pytest.mark.parametrize(
    "change",
    (
        {"cwd": "C:\\\\scratch\\repo"},
        {"approval": "on-request"},
        {"sandbox": "workspace-write"},
        {"requested_model": "unbounded-model"},
        {"prompt_size_bytes": 0},
        {"runtime_pin": runtime_pin(executable_path="relative/path")},
        {"routing_binding": {"kind": "cohort", "cohort_id": "c"}},
    ),
)
def test_launch_intent_falsification_guards(change: dict[str, object]) -> None:
    with pytest.raises(contracts.CodexTransportContractError):
        contracts.seal_launch_intent(intent(**change))


def test_launch_intent_accepts_standalone_and_zero_based_cohort_routing() -> None:
    cohort = contracts.seal_launch_intent(intent())
    assert cohort["routing_binding"]["wave_index"] == 0
    standalone_binding = {
        "kind": "standalone",
        "routing_authority_sha256": SHA_C,
        "transport": "codex",
        "parent_session_id": "chief-1",
        "expected_agent_type": "worker",
    }
    standalone = contracts.seal_launch_intent(
        intent(routing_binding=standalone_binding)
    )
    assert standalone["routing_binding"] == standalone_binding


def test_launch_intent_rejects_legacy_fallback_model_name() -> None:
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="requested_model is not an approved bounded model",
    ):
        contracts.seal_launch_intent(intent(requested_model="gpt-5.6"))


def test_model_list_preflight_is_ordered_and_failure_is_known_before_thread_start() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(
        reservation(sealed_intent["intent_sha256"])
    )
    intent_sha = str(sealed_intent["intent_sha256"])
    reservation_sha = str(sealed_reservation["reservation_sha256"])
    records: list[dict[str, object]] = []
    for event_type in (
        "reserved",
        "process_start_pending",
        "process_started",
        "initialize_send_pending",
        "initialized",
        "model_list_send_pending",
        "model_list_observed",
    ):
        records = append(
            records,
            intent_sha,
            reservation_sha,
            event_type,
            "reserved",
            correlation(),
        )
    state = contracts.validate_transport_journal(records)
    assert state.state == "reserved"
    assert state.last_event_type == "model_list_observed"
    assert append(
        records,
        intent_sha,
        reservation_sha,
        "thread_start_send_pending",
        "reserved",
        correlation(),
    )[-1]["wire_method"] == "thread/start"

    pending = records[:-1]
    assert pending[-1]["event_type"] == "model_list_send_pending"
    failed = append(
        pending,
        intent_sha,
        reservation_sha,
        "failed",
        "failed",
        correlation(),
        wire_method="model/list",
        wire_event_sha256=None,
        response_sha256=None,
        fault_kind="ModelCatalogViolation",
        fault_evidence_sha256=SHA_D,
        fault_evidence_size_bytes=42,
    )
    assert contracts.validate_transport_journal(failed).state == "failed"
    with pytest.raises(contracts.CodexTransportContractError):
        append(
            pending,
            intent_sha,
            reservation_sha,
            "launch_unknown",
            "launch_unknown",
            correlation(),
            wire_method="model/list",
        )


def test_model_rerouted_typed_failed_event_is_terminal() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "failed",
        "failed",
        correlation("thread-1", "turn-1"),
        wire_method="model/rerouted",
        wire_event_sha256=None,
        response_sha256=None,
        fault_kind="ModelReroutedViolation",
        fault_evidence_sha256=SHA_D,
        fault_evidence_size_bytes=42,
    )
    state = contracts.validate_transport_journal(records)
    assert state.state == "failed"
    assert records[-1]["wire_method"] == "model/rerouted"
    assert records[-1]["fault_kind"] == "ModelReroutedViolation"

    with pytest.raises(contracts.CodexTransportContractError, match="terminal"):
        append(
            records,
            intent_sha,
            reservation_sha,
            "completed",
            "completed",
            correlation("thread-1", "turn-1"),
        )


def test_launch_reservation_is_exactly_bound_to_intent_and_pin() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed = contracts.seal_reservation(reservation(sealed_intent["intent_sha256"]))
    assert contracts.validate_reservation_against_intent(sealed, sealed_intent) == sealed
    mismatched = contracts.seal_reservation(reservation(SHA_A))
    with pytest.raises(contracts.CodexTransportContractError, match="does not bind"):
        contracts.validate_reservation_against_intent(mismatched, sealed_intent)
    with pytest.raises(contracts.CodexTransportContractError):
        contracts.seal_reservation(reservation(sealed_intent["intent_sha256"], runtime_pin=runtime_pin(executable_size_bytes=1)))


def test_full_crash_safe_milestone_journal_and_wire_falsification() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    assert contracts.validate_transport_journal(records).state == "turn_started"
    raw = event(intent_sha, reservation_sha, event_id="raw", sequence=10, prev=records[-1]["event_sha256"], event_type="item_started", state="turn_started", runtime=correlation("thread-1", "turn-1", "item-1"))
    raw["assistant_text"] = "must never be a receipt field"
    with pytest.raises(contracts.CodexTransportContractError, match="schema"):
        contracts.seal_journal_event(raw)
    bad_pending = event(intent_sha, reservation_sha, event_id="bad", sequence=10, prev=records[-1]["event_sha256"], event_type="interrupt_send_pending", state="turn_started", runtime=correlation("thread-1", "turn-1"), response_sha256=SHA_A)
    with pytest.raises(contracts.CodexTransportContractError, match="send-pending"):
        contracts.seal_journal_event(bad_pending)
    bad_wire = event(intent_sha, reservation_sha, event_id="bad-2", sequence=10, prev=records[-1]["event_sha256"], event_type="completed", state="completed", runtime=correlation("thread-1", "turn-1"), wire_method="thread/start")
    with pytest.raises(contracts.CodexTransportContractError, match="wire metadata"):
        contracts.seal_journal_event(bad_wire)
    mislabeled_fault = event(
        intent_sha,
        reservation_sha,
        event_id="bad-3",
        sequence=10,
        prev=records[-1]["event_sha256"],
        event_type="failed",
        state="failed",
        runtime=correlation("thread-1", "turn-1"),
        fault_kind=None,
        fault_evidence_sha256=None,
        fault_evidence_size_bytes=None,
        wire_event_sha256=SHA_A,
        response_sha256=SHA_A,
    )
    with pytest.raises(contracts.CodexTransportContractError, match="evidence"):
        contracts.seal_journal_event(mislabeled_fault)


def test_thread_and_turn_start_response_loss_are_terminal_and_non_retryable() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(reservation(sealed_intent["intent_sha256"]))
    records: list[dict[str, object]] = []
    for event_type, state, runtime in (
        ("reserved", "reserved", correlation()), ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()), ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()), ("thread_start_send_pending", "reserved", correlation()),
    ):
        records = append(records, sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], event_type, state, runtime)
    pending = records[-1]
    unknown = event(sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], event_id="unknown", sequence=7, prev=pending["event_sha256"], event_type="launch_unknown", state="launch_unknown", runtime=correlation(), request_id=pending["request_id"], request_bytes_sha256=pending["request_bytes_sha256"])
    records = contracts.append_transport_journal_event(records, contracts.seal_journal_event(unknown))
    assert contracts.validate_transport_journal(records).state == "launch_unknown"
    with pytest.raises(contracts.CodexTransportContractError, match="terminal"):
        append(records, sealed_intent["intent_sha256"], sealed_reservation["reservation_sha256"], "thread_started", "thread_started", correlation("retry"))

    intent_sha, reservation_sha, active = to_turn_started()
    # A lost turn/start response is represented by rebuilding only through its pending request.
    active = active[:-1]
    pending = active[-1]
    unknown = event(intent_sha, reservation_sha, event_id="turn-unknown", sequence=9, prev=pending["event_sha256"], event_type="launch_unknown", state="launch_unknown", runtime=correlation("thread-1"), request_id=pending["request_id"], request_bytes_sha256=pending["request_bytes_sha256"], wire_method="turn/start")
    active = contracts.append_transport_journal_event(active, contracts.seal_journal_event(unknown))
    assert contracts.validate_transport_journal(active).correlation == correlation("thread-1")
    turn_unknown_receipt = contracts.seal_terminal_receipt(
        terminal(
            reservation_sha,
            active[-1]["event_sha256"],
            terminal_state="launch_unknown",
            correlation=correlation("thread-1"),
        )
    )
    assert contracts.validate_terminal_receipt_against_journal(
        turn_unknown_receipt, active
    )["correlation"] == correlation("thread-1")


def test_interrupt_response_remains_nonterminal_until_turn_completed() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupt_send_pending",
        "turn_started",
        correlation("thread-1", "turn-1"),
    )
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupt_observed",
        "turn_started",
        correlation("thread-1", "turn-1"),
    )
    observed = contracts.validate_transport_journal(records)
    assert observed.state == "turn_started"
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupted",
        "interrupted",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(records).state == "interrupted"


def test_process_start_crash_is_launch_unknown_not_a_known_failure() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(
        reservation(sealed_intent["intent_sha256"])
    )
    records: list[dict[str, object]] = []
    records = append(
        records,
        sealed_intent["intent_sha256"],
        sealed_reservation["reservation_sha256"],
        "reserved",
        "reserved",
        correlation(),
    )
    records = append(
        records,
        sealed_intent["intent_sha256"],
        sealed_reservation["reservation_sha256"],
        "process_start_pending",
        "reserved",
        correlation(),
    )
    pending = records[-1]
    unknown = event(
        sealed_intent["intent_sha256"],
        sealed_reservation["reservation_sha256"],
        event_id="process-unknown",
        sequence=3,
        prev=pending["event_sha256"],
        event_type="launch_unknown",
        state="launch_unknown",
        runtime=correlation(),
        request_id=pending["request_id"],
        request_bytes_sha256=pending["request_bytes_sha256"],
        wire_method="process/start",
    )
    records = contracts.append_transport_journal_event(
        records, contracts.seal_journal_event(unknown)
    )
    receipt = contracts.seal_terminal_receipt(
        terminal(
            sealed_reservation["reservation_sha256"],
            records[-1]["event_sha256"],
            terminal_state="launch_unknown",
            correlation=correlation(),
        )
    )
    assert contracts.validate_terminal_receipt_against_journal(
        receipt, records
    )["terminal_state"] == "launch_unknown"


def test_failures_and_disconnect_preserve_only_known_correlation() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    disconnected = append(records, intent_sha, reservation_sha, "runtime_unknown", "runtime_unknown", correlation("thread-1", "turn-1"))
    assert contracts.validate_transport_journal(disconnected).state == "runtime_unknown"
    with pytest.raises(contracts.CodexTransportContractError, match="preserve"):
        append(records, intent_sha, reservation_sha, "runtime_unknown", "runtime_unknown", correlation("thread-1"))
    before_thread = records[:2]
    failed = append(before_thread, intent_sha, reservation_sha, "failed", "failed", correlation())
    assert contracts.validate_transport_journal(failed).state == "failed"
    before_turn = records[:-1]
    failed = append(before_turn, intent_sha, reservation_sha, "failed", "failed", correlation("thread-1"))
    assert contracts.validate_transport_journal(failed).correlation == correlation("thread-1")
    turn_failed = append(
        records,
        intent_sha,
        reservation_sha,
        "failed",
        "failed",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(turn_failed).state == "failed"
    turn_interrupted = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupted",
        "interrupted",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(turn_interrupted).state == "interrupted"


def test_item_interrupt_and_correlation_falsification() -> None:
    intent_sha, reservation_sha, records = to_turn_started()
    with pytest.raises(contracts.CodexTransportContractError, match="correlation changed"):
        append(records, intent_sha, reservation_sha, "item_started", "turn_started", correlation("other", "turn-1", "item-1"))
    records = append(records, intent_sha, reservation_sha, "item_started", "turn_started", correlation("thread-1", "turn-1", "item-1"))
    with pytest.raises(contracts.CodexTransportContractError, match="duplicates item_id"):
        append(records, intent_sha, reservation_sha, "item_started", "turn_started", correlation("thread-1", "turn-1", "item-1"))
    records = append(records, intent_sha, reservation_sha, "item_completed", "turn_started", correlation("thread-1", "turn-1", "item-1"))
    records = append(records, intent_sha, reservation_sha, "interrupt_send_pending", "turn_started", correlation("thread-1", "turn-1"))
    records = append(records, intent_sha, reservation_sha, "interrupt_observed", "turn_started", correlation("thread-1", "turn-1"))
    assert contracts.validate_transport_journal(records).state == "turn_started"
    records = append(
        records,
        intent_sha,
        reservation_sha,
        "interrupted",
        "interrupted",
        correlation("thread-1", "turn-1"),
        wire_method="turn/completed",
    )
    assert contracts.validate_transport_journal(records).state == "interrupted"


@pytest.mark.parametrize("terminal_state", ("completed", "failed", "interrupted"))
def test_terminal_states_reject_outstanding_lifecycle_items(
    terminal_state: str,
) -> None:
    intent_sha, reservation_sha, journal = to_turn_started()
    journal = append(
        journal,
        intent_sha,
        reservation_sha,
        "item_started",
        "turn_started",
        correlation("thread-1", "turn-1", "item-1"),
    )
    terminal_correlation = (
        correlation("thread-1", "turn-1", "item-1")
        if terminal_state == "failed"
        else correlation("thread-1", "turn-1")
    )
    raw_terminal = event(
        intent_sha,
        reservation_sha,
        event_id="outstanding-terminal",
        sequence=len(journal) + 1,
        prev=cast(str, journal[-1]["event_sha256"]),
        event_type=terminal_state,
        state=terminal_state,
        runtime=terminal_correlation,
    )
    invalid_journal = [*journal, contracts.seal_journal_event(raw_terminal)]
    with pytest.raises(contracts.CodexTransportContractError, match="lifecycle item started"):
        contracts.validate_transport_journal(invalid_journal)
    receipt = contracts.seal_terminal_receipt(
        terminal(
            reservation_sha,
            cast(str, invalid_journal[-1]["event_sha256"]),
            terminal_state=terminal_state,
            correlation=terminal_correlation,
        )
    )
    with pytest.raises(contracts.CodexTransportContractError, match="lifecycle item started"):
        contracts.validate_terminal_receipt_against_journal(receipt, invalid_journal)


def test_runtime_unknown_preserves_an_outstanding_lifecycle_item_as_evidence() -> None:
    intent_sha, reservation_sha, journal = to_turn_started()
    outstanding = correlation("thread-1", "turn-1", "item-1")
    journal = append(
        journal,
        intent_sha,
        reservation_sha,
        "item_started",
        "turn_started",
        outstanding,
    )
    journal = append(
        journal,
        intent_sha,
        reservation_sha,
        "runtime_unknown",
        "runtime_unknown",
        outstanding,
    )
    assert contracts.validate_transport_journal(journal).correlation == outstanding
    receipt = contracts.seal_terminal_receipt(
        terminal(
            reservation_sha,
            cast(str, journal[-1]["event_sha256"]),
            terminal_state="runtime_unknown",
            correlation=outstanding,
        )
    )
    assert contracts.validate_terminal_receipt_against_journal(receipt, journal) == receipt


def terminal(reservation_sha: str, head_sha: str, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
        "reservation_sha256": reservation_sha,
        "journal_head_sha256": head_sha,
        "terminal_state": "completed",
        "correlation": correlation("thread-1", "turn-1"),
        "evidence_level": "codex_runtime_observed",
        "mutation_verification": {"status": "unavailable", "object_sha256": None},
    }
    value.update(changes)
    return value


def test_terminal_and_mutation_evidence_are_structural_not_promotion() -> None:
    intent_sha, reservation_sha, journal = to_turn_started()
    journal = append(journal, intent_sha, reservation_sha, "completed", "completed", correlation("thread-1", "turn-1"))
    observed = contracts.seal_terminal_receipt(terminal(reservation_sha, journal[-1]["event_sha256"]))
    assert contracts.validate_terminal_receipt_against_journal(observed, journal) == observed
    payload = {
        "contract_type": "codex_mutation_verification_v1",
        "launch_intent_sha256": intent_sha,
        "reservation_sha256": reservation_sha,
        "journal_head_sha256": journal[-1]["event_sha256"],
        "pre_git_snapshot": {"cas_sha256": SHA_A, "content_type": "git_snapshot"},
        "post_git_snapshot": {"cas_sha256": SHA_B, "content_type": "git_snapshot"},
        "claim_coverage": {"cas_sha256": SHA_C, "content_type": "claim_coverage"},
        "pre_git_tree": {"cas_sha256": SHA_D, "content_type": "git_tree"},
        "post_git_tree": {"cas_sha256": SHA_D, "content_type": "git_tree"},
    }
    assert contracts.validate_mutation_verification_payload(payload)["pre_git_tree"] == payload["post_git_tree"]
    v2_payload = {
        **payload,
        "contract_type": "codex_mutation_verification_v2",
        "git_executable": {
            "cas_sha256": SHA_A,
            "content_type": "git_executable_binding",
        },
    }
    assert (
        contracts.validate_mutation_verification_payload(v2_payload)[
            "git_executable"
        ]
        == v2_payload["git_executable"]
    )
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="schema is invalid",
    ):
        contracts.validate_mutation_verification_payload(
            {**payload, "contract_type": "codex_mutation_verification_v2"}
        )
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="schema is invalid",
    ):
        contracts.validate_mutation_verification_payload(
            {
                **payload,
                "git_executable": {
                    "cas_sha256": SHA_A,
                    "content_type": "git_executable_binding",
                },
            }
        )
    verified = contracts.seal_terminal_receipt(terminal(reservation_sha, journal[-1]["event_sha256"], evidence_level="verified_mutation", mutation_verification={"status": "referenced", "object_sha256": SHA_A}))
    assert verified["evidence_level"] == "verified_mutation"
    with pytest.raises(contracts.CodexTransportContractError, match="cannot assert"):
        contracts.seal_terminal_receipt(terminal(reservation_sha, journal[-1]["event_sha256"], mutation_verification={"status": "referenced", "object_sha256": SHA_A}))


def test_pure_v2_chain_binds_policy_and_keeps_reserved_below_runtime_evidence() -> None:
    sealed_intent, sealed_reservation = v2_material()
    assert sealed_reservation["evidence_level"] == "transport_reserved"
    journal: list[dict[str, object]] = []
    sequence = (
        ("reserved", "reserved", correlation()),
        ("process_start_pending", "reserved", correlation()),
        ("process_started", "reserved", correlation()),
        ("initialize_send_pending", "reserved", correlation()),
        ("initialized", "reserved", correlation()),
        ("model_list_send_pending", "reserved", correlation()),
        ("model_list_observed", "reserved", correlation()),
        ("thread_start_send_pending", "reserved", correlation()),
        ("thread_started", "thread_started", correlation("thread-1")),
        ("turn_start_send_pending", "thread_started", correlation("thread-1")),
        ("turn_started", "turn_started", correlation("thread-1", "turn-1")),
        ("item_started", "turn_started", correlation("thread-1", "turn-1", "item-1")),
        ("item_completed", "turn_started", correlation("thread-1", "turn-1", "item-1")),
        ("completed", "completed", correlation("thread-1", "turn-1")),
    )
    for event_type, state, runtime in sequence:
        journal = append_v2(
            journal,
            sealed_intent,
            sealed_reservation,
            event_type,
            state,
            runtime,
        )
    terminal = contracts.seal_terminal_receipt(
        {
            "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V2,
            "reservation_sha256": sealed_reservation["reservation_sha256"],
            "journal_head_sha256": journal[-1]["event_sha256"],
            "terminal_state": "completed",
            "correlation": correlation("thread-1", "turn-1"),
            "evidence_level": "codex_runtime_observed",
            "mutation_verification": {"status": "unavailable", "object_sha256": None},
        }
    )
    assert contracts.validate_terminal_receipt_against_journal(
        terminal, journal
    )["terminal_state"] == "completed"
    assert sealed_intent["intent_sha256"] == (
        "824af41759763410205a47404880d4fc7178f10fd3294d5c87122a00a81bdb01"
    )
    assert sealed_reservation["reservation_sha256"] == (
        "cf4c61046b307516578dc986cbc1e4aa285fd364f2071f3577df6e1423c6e0bd"
    )
    assert [row["event_sha256"] for row in journal] == [
        "24908cf5c57564065c18adbea1481c82a680e9a2b014f402243266f90ff43786",
        "31ba57bd1f30fa4239f9b7f2885e4a6b0c71f4290a3ddfc1ebc0fc044339dd8b",
        "4c4c3786d2330349017c9dff1b4144659bf63669559ab05fe21cef60466890ed",
        "4524d66e80ba299adaa7159060a9fcbcbaa48ac347062911d75147eff73348d5",
        "d90af37d80a6673f8d4369d9ce85aaa490877ab69fc4512da0a5320ce273935e",
        "6dee4f58a0515219cf8567876255786206d8ddaf4e347ea330fa249900bbb8b3",
        "153a293e9d6adbbe7a02396b05ea02732ec992541a276e09894bf118a450d335",
        "9f1e47ba2d071213b6df5e32cb2e6796485bf6fd9b9aa7d9359ebe152f20b0f8",
        "a3d17805ca7147545e0c4980ec2fbc02f6fb8900abf8023fe8ad2a0790824a75",
        "0dfc7f851da5bc9d4b7dac4fbd4a0f54bce77d522bceb1b3718ff7c3643ca8cd",
        "17bd876faa83521b82398c5c5261c8c44730ea0abdebae2b6b2c441a62f8bf35",
        "15cf646477d193ceefdc070b51851477c713627b58db3f46b92725e34838559f",
        "c43a962bab3f5fc898807be84e0c2c4ffc18df269b7d2d18453e531b4ed2c2c7",
        "99e02850ae7e9578f32f1211d3077b1434a9048cf63dcb719a329968621a63ba",
    ]
    assert terminal["receipt_sha256"] == (
        "993fb163afb7641a56117a1935236736ff3703147e09ddeb4719e023b3670b9e"
    )
    witnesses = [
        row["request_witness"]
        for row in journal
        if row.get("request_witness") is not None
    ]
    assert witnesses
    assert [
        cast(dict[str, object], witness)["witness_sha256"]
        for witness in witnesses
    ] == [
        "6af357bdf68945b163eab2d2303e09660075c1bd2ac0e811174dab51631befcd",
        "ea94cdfa8221f14c6510820ff40daf300a4440af1ac9d84c7bc1d877818e4592",
        "db8588ddd165478f34ffe9e457573d2c696d7503daff6823b9363a9e84d93cd9",
        "39c850b1dff662ebcce9eb7daf360089b1bec20e39dd7bf069aa609791ac27d6",
        "2c4b8628b01c3f71fc5715208dc311e6f3ba1558adc557bc8aa88b1d75163654",
    ]
    assert all(
        contracts.validate_request_witness_against_launch(
            cast(dict[str, object], witness),
            sealed_intent,
            sealed_reservation,
        )
        for witness in witnesses
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("permit_sha256", SHA_D),
        ("expected_semantic_head_sha256", SHA_D),
        ("prompt_sha256", SHA_D),
        ("prompt_size_bytes", 99),
        ("cwd", "C:/scratch/other"),
        ("requested_model", "gpt-5.4"),
        ("requested_effort", "low"),
        ("sandbox", "readOnly"),
        ("runtime_pin", {**runtime_pin_v2(), "schema_manifest_sha256": SHA_D}),
    ),
)
def test_v2_request_witness_policy_drift_fails_against_launch(
    field: str, replacement: object
) -> None:
    sealed_intent, sealed_reservation = v2_material()
    witness = v2_request_witness(
        sealed_intent,
        sealed_reservation,
        method="turn/start",
        request_id="request-1",
        runtime=correlation("thread-1"),
        **{field: replacement},
    )
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="differs from immutable launch policy",
    ):
        contracts.validate_request_witness_against_launch(
            witness, sealed_intent, sealed_reservation
        )


def test_v2_network_and_thread_config_drift_fail_closed() -> None:
    raw_intent = intent(
        contract_type=contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V2,
        network_access=True,
        runtime_pin=runtime_pin_v2(),
    )
    with pytest.raises(contracts.CodexTransportContractError, match="must be false"):
        contracts.seal_launch_intent(raw_intent)
    sealed_intent, sealed_reservation = v2_material()
    with pytest.raises(
        contracts.CodexTransportContractError, match="closed allowlist"
    ):
        v2_request_witness(
            sealed_intent,
            sealed_reservation,
            method="thread/start",
            request_id="request-1",
            thread_start_config={"unsealed": True},
        )
    with pytest.raises(
        contracts.CodexTransportContractError,
        match="sandbox/approval policy is invalid",
    ):
        v2_request_witness(
            sealed_intent,
            sealed_reservation,
            method="turn/start",
            request_id="request-1",
            approval="on-request",
        )


def test_journal_rejects_mixed_v1_v2_events() -> None:
    sealed_intent = contracts.seal_launch_intent(intent())
    sealed_reservation = contracts.seal_reservation(
        reservation(str(sealed_intent["intent_sha256"]))
    )
    v1 = contracts.seal_journal_event(
        event(
            str(sealed_intent["intent_sha256"]),
            str(sealed_reservation["reservation_sha256"]),
            event_id="v1-reserved",
            sequence=1,
            prev=contracts.ZERO_SHA256,
            event_type="reserved",
            state="reserved",
            runtime=correlation(),
        )
    )
    raw = event(
        str(sealed_intent["intent_sha256"]),
        str(sealed_reservation["reservation_sha256"]),
        event_id="v2-pending",
        sequence=2,
        prev=str(v1["event_sha256"]),
        event_type="process_start_pending",
        state="reserved",
        runtime=correlation(),
    )
    raw["contract_type"] = contracts.CODEX_TRANSPORT_JOURNAL_EVENT_V2
    raw["request_witness"] = contracts.seal_request_witness(
        {
            "schema_version": 1,
            "launch_intent_sha256": sealed_intent["intent_sha256"],
            "permit_sha256": sealed_reservation["permit_sha256"],
            "expected_semantic_head_sha256": sealed_intent["expected_semantic_head_sha256"],
            "request_id": raw["request_id"],
            "wire_method": "process/start",
            "request_envelope_sha256": raw["request_bytes_sha256"],
            "request_size_bytes": raw["payload_size_bytes"],
            "prompt_sha256": sealed_intent["prompt_sha256"],
            "prompt_size_bytes": sealed_intent["prompt_size_bytes"],
            "cwd": sealed_intent["cwd"],
            "requested_model": sealed_intent["requested_model"],
            "requested_effort": sealed_intent["requested_effort"],
            "approval": sealed_intent["approval"],
            "sandbox": sealed_intent["sandbox"],
            "network_access": False,
            "runtime_pin": sealed_intent["runtime_pin"],
            "thread_start_config": None,
            "correlation": correlation(),
        }
    )
    v2 = contracts.seal_journal_event(raw)
    with pytest.raises(contracts.CodexTransportContractError, match="cannot mix"):
        contracts.validate_transport_journal([v1, v2])
