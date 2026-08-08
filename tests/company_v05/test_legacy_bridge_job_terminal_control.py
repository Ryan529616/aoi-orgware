from __future__ import annotations

import copy
from contextlib import contextmanager
from http import HTTPStatus
import json
import os
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.legacy_bridge_job_terminal_protocol import (
    LegacyBridgeJobTerminalProtocolError,
    build_legacy_bridge_job_terminal_command,
    decode_legacy_bridge_job_terminal_result,
    parse_legacy_bridge_job_terminal_reconcile,
)
from aoi_orgware.company.legacy_bridge_service_control import (
    LEGACY_BRIDGE_JOB_TERMINAL_ROUTE,
)
from aoi_orgware.company.service import stop_service
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_company_service import (
    _await_status,
    _descriptor,
    _foreground_process,
)
from tests.company_v05.test_legacy_bridge_job_terminal import (
    _terminal_evidence,
)
from tests.company_v05.test_supervisor import manifest


def _command(
    descriptor: dict[str, Any],
    evidence: dict[str, Any],
    artifacts: tuple[tuple[str, bytes], ...],
):
    company = descriptor["company"]
    return build_legacy_bridge_job_terminal_command(
        service_instance_id=descriptor["service_instance_id"],
        company_id=company["company_id"],
        company_incarnation=company["company_incarnation"],
        lock_domain_generation=company["lock_domain_generation"],
        manifest_sha256=company["manifest_sha256"],
        terminal_evidence=evidence,
        terminal_artifacts=dict(artifacts),
    )


def _post(
    descriptor: dict[str, Any],
    payload: dict[str, Any],
    *,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    request = Request(
        descriptor["control_url"] + LEGACY_BRIDGE_JOB_TERMINAL_ROUTE,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": (
                "Bearer "
                + (descriptor["bearer_token"] if token is None else token)
            ),
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5.0) as response:  # noqa: S310
            value = json.loads(response.read())
            assert type(value) is dict
            return int(response.status), value
    except HTTPError as exc:
        value = json.loads(exc.read())
        assert type(value) is dict
        return int(exc.code), value


@contextmanager
def _running_terminal_service(
    tmp_path: Path,
) -> Iterator[
    tuple[
        Path,
        dict[str, Any],
        dict[str, Any],
        tuple[tuple[str, bytes], ...],
    ]
]:
    slot = tmp_path / "company"
    runtime = tmp_path / "runtime"
    with CompanySupervisor.initialize(
        slot,
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    ) as supervisor:
        evidence, artifacts = _terminal_evidence(supervisor)
    process = _foreground_process(slot, runtime)
    try:
        _await_status(slot, runtime, process)
        yield slot, _descriptor(slot, runtime), evidence, artifacts
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
        process.wait(timeout=10.0)


def test_protocol_binds_all_artifact_bytes_and_rejects_mutation(tmp_path: Path) -> None:
    with CompanySupervisor.initialize(
        tmp_path / "company",
        manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-08-06T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    ) as supervisor:
        evidence, artifacts = _terminal_evidence(supervisor)
    descriptor = {
        "service_instance_id": "service-1",
        "company": {
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "manifest_sha256": "b" * 64,
        },
    }
    command = _command(descriptor, evidence, artifacts)
    assert parse_legacy_bridge_job_terminal_reconcile(command.as_dict()) == command
    missing = command.as_dict()
    missing["artifact_payloads"].pop()
    with pytest.raises(LegacyBridgeJobTerminalProtocolError):
        parse_legacy_bridge_job_terminal_reconcile(missing)
    duplicate = command.as_dict()
    duplicate["artifact_payloads"][1]["role"] = "command"
    with pytest.raises(LegacyBridgeJobTerminalProtocolError):
        parse_legacy_bridge_job_terminal_reconcile(duplicate)
    changed = command.as_dict()
    changed["artifact_payloads"][0]["data_base64"] = "ZXhpdCA0Cg=="
    with pytest.raises(
        LegacyBridgeJobTerminalProtocolError,
        match="artifact_payload_binding_mismatch",
    ):
        parse_legacy_bridge_job_terminal_reconcile(changed)
    with pytest.raises(
        LegacyBridgeJobTerminalProtocolError,
        match="invalid_terminal_command_input",
    ):
        build_legacy_bridge_job_terminal_command(
            service_instance_id="service-1",
            company_id="company-1",
            company_incarnation=1,
            lock_domain_generation=1,
            manifest_sha256="b" * 64,
            terminal_evidence=evidence,
            terminal_artifacts={"command": True},  # type: ignore[dict-item]
        )


def test_live_authenticated_terminal_reconcile_and_exact_replay(
    tmp_path: Path,
) -> None:
    with _running_terminal_service(tmp_path) as (
        slot,
        descriptor,
        evidence,
        artifacts,
    ):
        command = _command(descriptor, evidence, artifacts)
        status, value = _post(descriptor, command.as_dict())
        assert status == HTTPStatus.OK
        result = decode_legacy_bridge_job_terminal_result(value, command=command)
        assert result.effect == "committed"
        assert result.idempotent_replay is False
        for field, replacement in (
            ("terminal_key_id", "e" * 64),
            ("receipt_id", "f" * 64),
            ("transaction_id", "forged-transaction"),
            ("command_id", "forged-command"),
            ("global_sequence", 0),
        ):
            forged = copy.deepcopy(value)
            forged[field] = replacement
            with pytest.raises(
                LegacyBridgeJobTerminalProtocolError,
                match="terminal_result_binding_mismatch|invalid_global_sequence",
            ):
                decode_legacy_bridge_job_terminal_result(
                    forged,
                    command=command,
                )
        coordinated = copy.deepcopy(value)
        coordinated["receipt_id"] = "f" * 64
        coordinated["transaction_id"] = (
            f"legacy-terminal-transaction-{'f' * 64}"
        )
        coordinated["command_id"] = f"legacy-terminal-command-{'f' * 64}"
        with pytest.raises(
            LegacyBridgeJobTerminalProtocolError,
            match="terminal_result_binding_mismatch",
        ):
            decode_legacy_bridge_job_terminal_result(
                coordinated,
                command=command,
            )
        stale_digest = command._replace(
            terminal_evidence=copy.deepcopy(command.terminal_evidence),
        )
        stale_digest.terminal_evidence["owner_packet_contract_sha256"] = "f" * 64
        with pytest.raises(
            LegacyBridgeJobTerminalProtocolError,
            match="terminal_result_binding_mismatch",
        ):
            decode_legacy_bridge_job_terminal_result(
                value,
                command=stale_digest,
            )
        replay_status, replay_value = _post(descriptor, command.as_dict())
        assert replay_status == HTTPStatus.OK
        replay = decode_legacy_bridge_job_terminal_result(
            replay_value, command=command,
        )
        assert replay.global_sequence == result.global_sequence
        assert replay.receipt_id == result.receipt_id
        assert replay.idempotent_replay is True
        assert _post(descriptor, command.as_dict(), token="wrong") == (
            HTTPStatus.FORBIDDEN,
            {"error": "forbidden"},
        )
        browser_post = Request(
            descriptor["dashboard_url"] + "/api/v1/snapshot",
            data=b"{}",
            method="POST",
        )
        with pytest.raises(HTTPError) as rejected:
            urlopen(browser_post, timeout=3.0)  # noqa: S310
        assert rejected.value.code == HTTPStatus.METHOD_NOT_ALLOWED
    with CompanySupervisor.open(slot) as reopened:
        assert reopened.heads().global_head.global_sequence == result.global_sequence


def test_live_binding_and_divergent_second_receipt_are_zero_append(
    tmp_path: Path,
) -> None:
    with _running_terminal_service(tmp_path) as (
        slot,
        descriptor,
        evidence,
        artifacts,
    ):
        command = _command(descriptor, evidence, artifacts)
        foreign_descriptor = copy.deepcopy(descriptor)
        foreign_descriptor["company"]["company_id"] = "another-company"
        foreign_evidence = copy.deepcopy(evidence)
        foreign_evidence["company_id"] = "another-company"
        foreign = _command(
            foreign_descriptor, foreign_evidence, artifacts,
        )
        assert _post(descriptor, foreign.as_dict()) == (
            HTTPStatus.CONFLICT,
            {"error": "service_binding_mismatch"},
        )
        first_status, first_value = _post(descriptor, command.as_dict())
        assert first_status == HTTPStatus.OK
        before = decode_legacy_bridge_job_terminal_result(
            first_value, command=command,
        ).global_sequence
        divergent = copy.deepcopy(evidence)
        divergent["owner_packet_contract_sha256"] = "f" * 64
        second = _command(descriptor, divergent, artifacts)
        status, value = _post(descriptor, second.as_dict())
        assert (status, value) == (
            HTTPStatus.CONFLICT,
            {"error": "legacy_bridge_job_terminal_rejected"},
        )
        with pytest.raises(
            LegacyBridgeJobTerminalProtocolError,
            match="terminal_result_binding_mismatch",
        ):
            decode_legacy_bridge_job_terminal_result(
                first_value,
                command=second,
            )
    with CompanySupervisor.open(slot) as readback:
        assert readback.heads().global_head.global_sequence == before
