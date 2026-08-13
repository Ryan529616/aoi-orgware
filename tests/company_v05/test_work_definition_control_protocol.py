from __future__ import annotations

import base64
import copy
from pathlib import Path
import sys
from typing import Any

import pytest

from aoi_orgware.company.contracts import company_contract_sha256
from aoi_orgware.company.work_definition_control_protocol import (
    WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA,
    WORK_DEFINITION_REGISTER_SCHEMA,
    WorkDefinitionControlProtocolError,
    parse_work_definition_enforcement_activate,
    parse_work_definition_register,
)


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_work_definition_registration import (  # type: ignore[import-not-found]
    _chief_fence,
    _initialize,
    _work_bundle,
)


def _register_request(tmp_path: Path) -> dict[str, object]:
    supervisor = _initialize(tmp_path)
    task, packet, context, prompt = _work_bundle(supervisor)
    return {
        "schema_version": WORK_DEFINITION_REGISTER_SCHEMA,
        "service_instance_id": "service-1",
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        **_chief_fence(supervisor),
        "transaction_id": "register-tx-1",
        "command_id": "register-command-1",
        "task_revision": task,
        "work_packet": packet,
        "context_manifest": context,
        "prompt_base64": base64.b64encode(prompt).decode("ascii"),
    }


def _enforcement_request() -> dict[str, object]:
    return {
        "schema_version": WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA,
        "service_instance_id": "service-1",
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        "chief_id": "chief-1",
        "carrier_id": "carrier-1",
        "term": 1,
        "epoch": 1,
        "chief_execution_id": "chief-execution-1",
        "transaction_id": "enforcement-tx-1",
        "command_id": "enforcement-command-1",
    }


def _rehash(item: dict[str, Any], field: str) -> None:
    item[field] = company_contract_sha256({
        key: value for key, value in item.items() if key != field
    })


def test_register_round_trips_canonical_bytes_and_enforcement_is_separate(
    tmp_path: Path,
) -> None:
    request = _register_request(tmp_path)
    command = parse_work_definition_register(request)
    assert command.prompt_bytes == base64.b64decode(str(request["prompt_base64"]))
    assert command.as_dict() == request

    enforcement = _enforcement_request()
    assert parse_work_definition_enforcement_activate(enforcement).as_dict() == enforcement


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("term", True, "invalid_term"),
        ("epoch", 0, "invalid_epoch"),
        ("company_incarnation", False, "invalid_company_incarnation"),
        ("manifest_sha256", "A" * 64, "invalid_manifest_sha256"),
        ("chief_id", "bad id", "invalid_chief_id"),
        ("transaction_id", "bad id", "invalid_transaction_id"),
    ],
)
def test_protocol_rejects_invalid_fencing_scalars(
    tmp_path: Path,
    field: str,
    value: object,
    code: str,
) -> None:
    request = _register_request(tmp_path)
    request[field] = value
    with pytest.raises(WorkDefinitionControlProtocolError, match=f"^{code}$"):
        parse_work_definition_register(request)


@pytest.mark.parametrize("dropped", ["task_revision", "prompt_base64"])
def test_register_rejects_missing_or_extra_keys(tmp_path: Path, dropped: str) -> None:
    request = _register_request(tmp_path)
    request.pop(dropped)
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_request_fields$"):
        parse_work_definition_register(request)
    request = _register_request(tmp_path / "extra")
    request["client_timestamp"] = "2026-07-28T00:00:00Z"
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_request_fields$"):
        parse_work_definition_register(request)


@pytest.mark.parametrize(
    ("prompt", "code"),
    [
        ("not-base64", "invalid_prompt_base64"),
        (base64.b64encode(b"\xff").decode("ascii"), "invalid_prompt_utf8"),
        (base64.b64encode(b"prompt\x00text").decode("ascii"), "invalid_prompt_utf8"),
    ],
)
def test_register_rejects_noncanonical_or_invalid_prompt(
    tmp_path: Path,
    prompt: str,
    code: str,
) -> None:
    request = _register_request(tmp_path)
    request["prompt_base64"] = prompt
    with pytest.raises(WorkDefinitionControlProtocolError, match=f"^{code}$"):
        parse_work_definition_register(request)


def test_register_rejects_oversize_prompt(tmp_path: Path) -> None:
    request = _register_request(tmp_path)
    request["prompt_base64"] = base64.b64encode(b"x" * (256 * 1024 + 1)).decode(
        "ascii",
    )
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_prompt_base64$"):
        parse_work_definition_register(request)


@pytest.mark.parametrize(
    ("document", "field", "value", "code"),
    [
        ("task_revision", "task_sha256", "A" * 64, "invalid_task_revision"),
        ("work_packet", "packet_sha256", "A" * 64, "invalid_work_packet"),
        ("context_manifest", "document_type", "wrong", "invalid_context_manifest"),
    ],
)
def test_register_rejects_invalid_embedded_contracts(
    tmp_path: Path,
    document: str,
    field: str,
    value: object,
    code: str,
) -> None:
    request = _register_request(tmp_path)
    document_value = copy.deepcopy(request[document])
    assert isinstance(document_value, dict)
    document_value[field] = value
    request[document] = document_value
    with pytest.raises(WorkDefinitionControlProtocolError, match=f"^{code}$"):
        parse_work_definition_register(request)


@pytest.mark.parametrize("field", ["sha256", "size_bytes", "media_type", "availability"])
def test_register_matches_prompt_to_work_packet_reference(
    tmp_path: Path,
    field: str,
) -> None:
    request = _register_request(tmp_path)
    packet = copy.deepcopy(request["work_packet"])
    assert isinstance(packet, dict)
    reference = packet["prompt_ref"]
    assert isinstance(reference, dict)
    values: dict[str, object] = {
        "sha256": "0" * 64,
        "size_bytes": 999,
        "media_type": "text/plain",
        "availability": "unknown",
    }
    reference[field] = values[field]
    _rehash(packet, "packet_sha256")
    request["work_packet"] = packet
    expected = "prompt_ref_mismatch" if field in {"sha256", "size_bytes"} else "invalid_work_packet"
    with pytest.raises(WorkDefinitionControlProtocolError, match=f"^{expected}$"):
        parse_work_definition_register(request)


def test_register_rejects_bundle_and_company_mismatch(tmp_path: Path) -> None:
    request = _register_request(tmp_path)
    task = copy.deepcopy(request["task_revision"])
    assert isinstance(task, dict)
    task["company_id"] = "company-other"
    _rehash(task, "task_sha256")
    request["task_revision"] = task
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_company_binding$"):
        parse_work_definition_register(request)


def test_enforcement_rejects_client_timestamp_missing_and_bool() -> None:
    request = _enforcement_request()
    request["activated_at"] = "2026-07-28T00:00:00Z"
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_request_fields$"):
        parse_work_definition_enforcement_activate(request)

    request = _enforcement_request()
    request.pop("command_id")
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_request_fields$"):
        parse_work_definition_enforcement_activate(request)

    request = _enforcement_request()
    request["lock_domain_generation"] = True
    with pytest.raises(WorkDefinitionControlProtocolError, match="^invalid_lock_domain_generation$"):
        parse_work_definition_enforcement_activate(request)
