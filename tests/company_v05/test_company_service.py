from __future__ import annotations

import base64
from contextlib import nullcontext
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from aoi_orgware.company.contracts import COMPANY_MANIFEST_V1
from aoi_orgware.company.ledger import (
    LedgerAppendResult,
    LedgerTransactionRecord,
)
from aoi_orgware.company.process_lock import CompanyProcessLockBusyError
import aoi_orgware.company.service as service_module
from aoi_orgware.company.service import (
    SERVICE_DESCRIPTOR_SCHEMA,
    TELEMETRY_CAPABILITY_SCHEMA,
    TELEMETRY_INGEST_SCHEMA,
    TELEMETRY_INGEST_RESULT_SCHEMA,
    CompanyServiceError,
    CompanyServiceOperationError,
    CompanyServiceUnavailableError,
    ensure_service,
    ingest_service_telemetry,
    run_service_foreground,
    runtime_descriptor_path,
    service_status,
    stop_service,
)
from aoi_orgware.company.state import CompanyProjectionDegradedError
import aoi_orgware.company.supervisor as supervisor_module
from aoi_orgware.company.supervisor import (
    CompanySupervisor,
    CompanyTelemetryIngestError,
)


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"


def _manifest() -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-service-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def _slot(tmp_path: Path) -> Path:
    slot = tmp_path / "state" / "companies" / "company-service-1"
    with CompanySupervisor.initialize(
        slot,
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
    ):
        pass
    return slot


def _await_status(
    slot: Path,
    runtime: Path,
    process: subprocess.Popen[bytes],
) -> dict[str, Any]:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        value = service_status(slot, runtime_root=runtime, timeout_seconds=0.3)
        if value["state"] == "running":
            return value
        if process.poll() is not None:
            _stdout, stderr = process.communicate(timeout=1.0)
            raise AssertionError(f"foreground service exited: {stderr.decode('utf-8', 'replace')}")
        time.sleep(0.05)
    raise AssertionError("foreground service did not become ready")


def _foreground_process(slot: Path, runtime: Path) -> subprocess.Popen[bytes]:
    source = Path(__file__).resolve().parents[2] / "src"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source)
    code = (
        "from aoi_orgware.company.service import run_service_foreground; "
        f"raise SystemExit(run_service_foreground({str(slot)!r}, runtime_root={str(runtime)!r}))"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )


def _get_json(url: str, *, token: str | None = None, method: str = "GET") -> tuple[int, dict[str, Any]]:
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    request = Request(url, headers=headers, method=method)
    with urlopen(request, timeout=2.0) as response:  # noqa: S310 - exact loopback descriptor endpoint
        return int(response.status), json.loads(response.read())


def _descriptor(slot: Path, runtime: Path) -> dict[str, Any]:
    value = json.loads(
        runtime_descriptor_path(slot, runtime_root=runtime).read_text(
            encoding="utf-8",
        ),
    )
    assert isinstance(value, dict)
    return value


def _raw_control_request(
    control_url: str,
    *,
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes = b"",
) -> tuple[int, dict[str, Any]]:
    """Issue an exact loopback request, including deliberately duplicate headers."""

    parsed = urlsplit(control_url)
    assert parsed.scheme == "http"
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port is not None
    request_headers = [("Host", parsed.netloc), *headers]
    if not any(name.lower() == "content-length" for name, _value in request_headers):
        request_headers.append(("Content-Length", str(len(body))))
    request = b"\r\n".join(
        [
            f"{method} {path} HTTP/1.1".encode("ascii"),
            *(f"{name}: {value}".encode("ascii") for name, value in request_headers),
            b"",
            body,
        ],
    )
    response = bytearray()
    with socket.create_connection(("127.0.0.1", parsed.port), timeout=2.0) as connection:
        connection.settimeout(2.0)
        connection.sendall(request)
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    status_line, _separator, raw_body = bytes(response).partition(b"\r\n")
    assert status_line.startswith(b"HTTP/")
    status = int(status_line.split()[1])
    _headers, _separator, raw_body = raw_body.partition(b"\r\n\r\n")
    value = json.loads(raw_body)
    assert isinstance(value, dict)
    return status, value


def _telemetry_request_payload(
    descriptor: dict[str, Any],
    *,
    source_class: str = "codex_app_server",
) -> dict[str, Any]:
    company = descriptor["company"]
    raw = b'{"method":"thread/tokenUsage/updated","params":{}}'
    return {
        "schema_version": TELEMETRY_INGEST_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "provider": "codex" if source_class == "codex_app_server" else "claude",
        "source_class": source_class,
        "adapter_instance_id": "adversarial-adapter-1",
        "adapter_event_id": "adversarial-event-1",
        "intake_sequence": 1,
        "transaction_id": "adversarial-transaction-1",
        "command_id": "adversarial-command-1",
        "received_at": "2026-07-27T00:01:00Z",
        "raw_base64": base64.b64encode(raw).decode("ascii"),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _telemetry_operation_result(
    *,
    service_instance_id: str = "service-expected",
    cursor: object = 1,
) -> dict[str, Any]:
    return {
        "schema_version": TELEMETRY_INGEST_RESULT_SCHEMA,
        "service_instance_id": service_instance_id,
        "company_id": "company-service-1",
        "cursor": cursor,
        "result": {
            "receipt_id": "receipt-result-binding",
            "provider": "codex",
            "parse_outcome": "normalized",
            "normalized_kind": "thread_status_changed",
            "dispatch_join_state": "none",
            "lifecycle_coverage_revision_id":
                "coverage-result-binding",
            "usage_coverage_revision_id": "",
            "usage_sample_id": None,
            "transaction_id": "tx-result-binding",
            "command_id": "cmd-result-binding",
            "global_sequence": cursor,
            "idempotent_replay": False,
        },
    }


def test_foreground_service_discovers_dashboard_and_stops_without_pid_kill(tmp_path: Path) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    process = _foreground_process(slot, runtime)
    try:
        service = _await_status(slot, runtime, process)
        descriptor = service["descriptor"]
        assert descriptor["schema_version"] == SERVICE_DESCRIPTOR_SCHEMA
        assert descriptor["slot_path"] == str(slot.resolve())
        assert descriptor["company"]["company_id"] == "company-service-1"
        assert "bearer_token" not in descriptor
        assert "telemetry_capabilities" not in descriptor
        private_descriptor = _descriptor(slot, runtime)
        assert len(private_descriptor["bearer_token"]) == 64
        capabilities = private_descriptor["telemetry_capabilities"]
        assert set(capabilities) == {
            "codex_app_server",
            "claude_hook",
            "otel",
        }
        capability_values = [
            json.loads(Path(path).read_text(encoding="utf-8"))
            for path in capabilities.values()
        ]
        assert {
            value["source_class"]
            for value in capability_values
        } == set(capabilities)
        assert all(
            value["schema_version"] == TELEMETRY_CAPABILITY_SCHEMA
            and len(value["bearer_token"]) == 64
            and "telemetry_capabilities" not in value
            for value in capability_values
        )
        status, dashboard = _get_json(descriptor["dashboard_url"] + "api/v1/meta")
        assert status == 200
        assert dashboard["company_id"] == "company-service-1"
        status, control = _get_json(
            descriptor["control_url"] + "/status",
            token=private_descriptor["bearer_token"],
        )
        assert status == 200
        assert control["state"] == "running"
        with pytest.raises(HTTPError) as forbidden:
            _get_json(descriptor["control_url"] + "/status", token="0" * 64)
        assert forbidden.value.code == 403
        with pytest.raises(HTTPError) as rejected:
            _get_json(descriptor["dashboard_url"], method="POST")
        assert rejected.value.code == 405
        stopped = stop_service(slot, runtime_root=runtime)
        assert stopped["state"] == "stopping"
        assert process.wait(timeout=10.0) == 0
        assert not runtime_descriptor_path(slot, runtime_root=runtime).exists()
        assert all(
            not Path(path).exists()
            for path in capabilities.values()
        )
    finally:
        if process.poll() is None:
            # Test cleanup does not assert product behavior; the test has
            # already verified graceful authenticated shutdown above.
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


def test_control_http_rejects_cross_capability_and_malformed_telemetry_without_ledger_effect(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    process = _foreground_process(slot, runtime)
    try:
        running = _await_status(slot, runtime, process)
        descriptor = _descriptor(slot, runtime)
        control_url = descriptor["control_url"]
        admin_token = descriptor["bearer_token"]
        capabilities = descriptor["telemetry_capabilities"]
        codex_capability = json.loads(
            Path(capabilities["codex_app_server"]).read_text(
                encoding="utf-8",
            ),
        )
        claude_capability = json.loads(
            Path(capabilities["claude_hook"]).read_text(
                encoding="utf-8",
            ),
        )
        codex_token = codex_capability["bearer_token"]
        claude_token = claude_capability["bearer_token"]
        codex_payload = _telemetry_request_payload(descriptor)
        claude_payload = _telemetry_request_payload(
            descriptor,
            source_class="claude_hook",
        )
        codex_body = json.dumps(codex_payload, separators=(",", ":")).encode()
        claude_body = json.dumps(claude_payload, separators=(",", ":")).encode()
        _status, initial = _get_json(
            control_url + "/status",
            token=admin_token,
        )
        deadline = time.monotonic() + 3.0
        while initial["cursor"] is None and time.monotonic() < deadline:
            time.sleep(0.01)
            _status, initial = _get_json(
                control_url + "/status",
                token=admin_token,
            )
        initial_cursor = initial["cursor"]
        assert isinstance(initial_cursor, int)

        requests = [
            (
                "admin bearer cannot ingest telemetry",
                "/control/v1/telemetry/codex",
                [("Authorization", f"Bearer {admin_token}"), ("Content-Type", "application/json")],
                codex_body,
                403,
            ),
            (
                "telemetry token cannot read admin status",
                "/status",
                [("Authorization", f"Bearer {codex_token}")],
                b"",
                403,
            ),
            (
                "telemetry token cannot stop service",
                "/stop",
                [("Authorization", f"Bearer {codex_token}")],
                b"",
                403,
            ),
            (
                "claude token cannot use codex route",
                "/control/v1/telemetry/codex",
                [("Authorization", f"Bearer {claude_token}"), ("Content-Type", "application/json")],
                codex_body,
                403,
            ),
            (
                "codex token cannot use claude route",
                "/control/v1/telemetry/claude-hook",
                [("Authorization", f"Bearer {codex_token}"), ("Content-Type", "application/json")],
                claude_body,
                403,
            ),
            (
                "body source cannot differ from authenticated route",
                "/control/v1/telemetry/codex",
                [("Authorization", f"Bearer {codex_token}"), ("Content-Type", "application/json")],
                claude_body,
                403,
            ),
            (
                "duplicate JSON key",
                "/control/v1/telemetry/codex",
                [("Authorization", f"Bearer {codex_token}"), ("Content-Type", "application/json")],
                codex_body[:-1] + b',"source_class":"codex_app_server"}',
                400,
            ),
            (
                "unknown telemetry field",
                "/control/v1/telemetry/codex",
                [("Authorization", f"Bearer {codex_token}"), ("Content-Type", "application/json")],
                json.dumps({**codex_payload, "unexpected": True}, separators=(",", ":")).encode(),
                400,
            ),
            (
                "non-JSON content type",
                "/control/v1/telemetry/codex",
                [("Authorization", f"Bearer {codex_token}"), ("Content-Type", "text/plain")],
                codex_body,
                415,
            ),
            (
                "transfer encoding is forbidden",
                "/control/v1/telemetry/codex",
                [
                    ("Authorization", f"Bearer {codex_token}"),
                    ("Content-Type", "application/json"),
                    ("Transfer-Encoding", "identity"),
                ],
                codex_body,
                400,
            ),
            (
                "content encoding is forbidden",
                "/control/v1/telemetry/codex",
                [
                    ("Authorization", f"Bearer {codex_token}"),
                    ("Content-Type", "application/json"),
                    ("Content-Encoding", "identity"),
                ],
                codex_body,
                400,
            ),
            (
                "duplicate content length",
                "/control/v1/telemetry/codex",
                [
                    ("Authorization", f"Bearer {codex_token}"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(codex_body))),
                    ("Content-Length", str(len(codex_body))),
                ],
                codex_body,
                400,
            ),
            (
                "unbounded content length integer",
                "/control/v1/telemetry/codex",
                [
                    ("Authorization", f"Bearer {codex_token}"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", "9" * 5000),
                ],
                b"",
                400,
            ),
        ]
        for label, path, headers, body, expected_status in requests:
            status, response = _raw_control_request(
                control_url,
                method="POST" if path != "/status" else "GET",
                path=path,
                headers=headers,
                body=body,
            )
            assert status == expected_status, (label, response)
            _status, status_payload = _get_json(
                control_url + "/status",
                token=admin_token,
            )
            assert status_payload["cursor"] == initial_cursor, label

        assert service_status(slot, runtime_root=runtime)["state"] == "running"
        assert running["descriptor"]["service_instance_id"] == descriptor["service_instance_id"]
        stop_service(slot, runtime_root=runtime)
        assert process.wait(timeout=10.0) == 0
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


def test_resident_owner_ingests_telemetry_idempotently_and_refreshes_dashboard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    process = _foreground_process(slot, runtime)
    try:
        running = _await_status(slot, runtime, process)
        private_descriptor = _descriptor(slot, runtime)
        codex_capability_path = private_descriptor[
            "telemetry_capabilities"
        ]["codex_app_server"]
        claude_capability_path = private_descriptor[
            "telemetry_capabilities"
        ]["claude_hook"]
        def reject_admin_descriptor(
            *_args: object,
            **_kwargs: object,
        ) -> None:
            raise AssertionError(
                "adapter ingest must not read admin descriptor",
            )

        raw = json.dumps(
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "thread-service-1",
                    "turnId": "turn-service-1",
                    "tokenUsage": {
                        "total": {
                            "inputTokens": 20,
                            "cachedInputTokens": 4,
                            "outputTokens": 10,
                            "reasoningOutputTokens": 8,
                            "totalTokens": 42,
                        },
                        "last": {
                            "inputTokens": 20,
                            "cachedInputTokens": 4,
                            "outputTokens": 10,
                            "reasoningOutputTokens": 8,
                            "totalTokens": 42,
                        },
                    },
                },
            },
            separators=(",", ":"),
        ).encode()
        with pytest.raises(
            CompanyServiceError,
            match="invalid binding",
        ):
            ingest_service_telemetry(
                slot,
                raw,
                capability_path=claude_capability_path,
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-wrong-capability",
                adapter_event_id="event-wrong-capability",
                intake_sequence=1,
                transaction_id="tx-wrong-capability",
                command_id="cmd-wrong-capability",
                received_at="2026-07-27T00:00:30Z",
                runtime_root=runtime,
            )
        with monkeypatch.context() as context:
            context.setattr(
                service_module,
                "_read_descriptor",
                reject_admin_descriptor,
            )
            first = ingest_service_telemetry(
                slot,
                raw,
                capability_path=codex_capability_path,
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-service-1",
                adapter_event_id="event-service-1",
                intake_sequence=1,
                transaction_id="tx-service-telemetry-1",
                command_id="cmd-service-telemetry-1",
                received_at="2026-07-27T00:01:00Z",
                runtime_root=runtime,
            )
        assert first["schema_version"] == TELEMETRY_INGEST_RESULT_SCHEMA
        assert first["service_instance_id"] == (
            running["descriptor"]["service_instance_id"]
        )
        assert first["result"]["provider"] == "codex"
        assert first["result"]["usage_sample_id"]
        assert first["result"]["idempotent_replay"] is False

        status, usage = _get_json(
            running["descriptor"]["dashboard_url"] + "api/v1/usage",
        )
        assert status == 200
        assert [
            sample["sample_id"]
            for sample in usage["data"]["counter_samples"]
        ] == [first["result"]["usage_sample_id"]]
        status, evidence = _get_json(
            running["descriptor"]["dashboard_url"] + "api/v1/evidence",
        )
        assert status == 200
        assert [
            receipt["receipt_id"]
            for receipt in evidence["data"]["provider_telemetry_receipts"]
        ] == [first["result"]["receipt_id"]]

        replay = ingest_service_telemetry(
            slot,
            raw,
            capability_path=codex_capability_path,
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-service-1",
            adapter_event_id="event-service-1",
            intake_sequence=1,
            transaction_id="tx-service-telemetry-1",
            command_id="cmd-service-telemetry-1",
            received_at="2026-07-27T00:01:00Z",
            runtime_root=runtime,
        )
        assert replay["cursor"] == first["cursor"]
        assert replay["result"]["idempotent_replay"] is True

        with pytest.raises(CompanyServiceOperationError) as conflict:
            ingest_service_telemetry(
                slot,
                raw + b" ",
                capability_path=codex_capability_path,
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-service-1",
                adapter_event_id="event-service-1",
                intake_sequence=1,
                transaction_id="tx-service-telemetry-1",
                command_id="cmd-service-telemetry-1",
                received_at="2026-07-27T00:01:00Z",
                runtime_root=runtime,
            )
        assert conflict.value.status == 409
        assert conflict.value.code == "telemetry_conflict"

        claude_raw = json.dumps(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "claude-parent",
                "prompt_id": "prompt-service-1",
                "agent_id": "claude-child",
                "agent_type": "general-purpose",
            },
            separators=(",", ":"),
        ).encode()
        claude = ingest_service_telemetry(
            slot,
            claude_raw,
            capability_path=claude_capability_path,
            provider="claude",
            source_class="claude_hook",
            adapter_instance_id="adapter-claude-1",
            adapter_event_id="event-claude-1",
            intake_sequence=1,
            transaction_id="tx-service-claude-1",
            command_id="cmd-service-claude-1",
            received_at="2026-07-27T00:02:00Z",
            runtime_root=runtime,
        )
        assert claude["result"]["provider"] == "claude"
        assert claude["result"]["usage_sample_id"] is None
        assert claude["cursor"] > first["cursor"]

        stop_service(slot, runtime_root=runtime)
        assert process.wait(timeout=10.0) == 0
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


def test_committed_telemetry_refresh_failure_reports_effect_and_reconciles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    service = service_module._ResidentService(
        slot.resolve(),
        runtime.resolve(),
        0.01,
    )
    failures: list[BaseException] = []

    def run() -> None:
        try:
            service.run()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            running = service_status(
                slot,
                runtime_root=runtime,
                timeout_seconds=0.3,
            )
            if running["state"] == "running":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("resident service did not become ready")

        descriptor = _descriptor(slot, runtime)
        capability_path = descriptor["telemetry_capabilities"][
            "codex_app_server"
        ]
        supervisor = service._supervisor
        assert supervisor is not None
        cache = supervisor._dashboard_cache
        assert cache is not None
        original_refresh = cache.refresh
        baseline = _get_json(
            descriptor["dashboard_url"] + "api/v1/meta",
        )[1]["cursor"]
        assert isinstance(baseline, int)
        failure_injected = False

        def fail_first_post_commit_refresh() -> int:
            nonlocal failure_injected
            current = supervisor.heads().global_head.global_sequence
            if current > baseline and not failure_injected:
                failure_injected = True
                raise RuntimeError("injected post-commit refresh failure")
            return original_refresh()

        monkeypatch.setattr(
            cache,
            "refresh",
            fail_first_post_commit_refresh,
        )
        raw = json.dumps(
            {
                "method": "thread/status/changed",
                "params": {
                    "threadId": "thread-refresh-effect",
                    "status": {"type": "idle"},
                },
            },
            separators=(",", ":"),
        ).encode()
        with pytest.raises(CompanyServiceOperationError) as committed:
            ingest_service_telemetry(
                slot,
                raw,
                capability_path=capability_path,
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-refresh-effect",
                adapter_event_id="event-refresh-effect",
                intake_sequence=1,
                transaction_id="tx-refresh-effect",
                command_id="cmd-refresh-effect",
                received_at="2026-07-27T00:01:00Z",
                runtime_root=runtime,
            )
        assert committed.value.status == 500
        assert (
            committed.value.code
            == "committed_dashboard_refresh_failed"
        )
        assert committed.value.effect == "committed"
        assert committed.value.cursor == baseline + 1
        assert failure_injected

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            meta = _get_json(
                descriptor["dashboard_url"] + "api/v1/meta",
            )[1]
            if meta["cursor"] == committed.value.cursor:
                break
            time.sleep(0.01)
        else:
            raise AssertionError(
                "periodic Dashboard refresh did not reconcile commit",
            )

        replay = ingest_service_telemetry(
            slot,
            raw,
            capability_path=capability_path,
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-refresh-effect",
            adapter_event_id="event-refresh-effect",
            intake_sequence=1,
            transaction_id="tx-refresh-effect",
            command_id="cmd-refresh-effect",
            received_at="2026-07-27T00:01:00Z",
            runtime_root=runtime,
        )
        assert replay["cursor"] == committed.value.cursor
        assert replay["result"]["idempotent_replay"] is True
        stop_service(slot, runtime_root=runtime)
        thread.join(timeout=10.0)
        assert not thread.is_alive()
        assert failures == []
    finally:
        if thread.is_alive():
            try:
                stop_service(slot, runtime_root=runtime)
            except CompanyServiceUnavailableError:
                service.request_stop()
            thread.join(timeout=10.0)


def test_client_timeout_after_enqueue_is_effect_unknown_and_exact_retry_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    service = service_module._ResidentService(
        slot.resolve(),
        runtime.resolve(),
        0.01,
    )
    failures: list[BaseException] = []
    original_execute = service._execute_telemetry
    first_execution = True

    def delayed_first_execution(
        pending: service_module._PendingTelemetryIngest,
    ) -> None:
        nonlocal first_execution
        if first_execution:
            first_execution = False
            time.sleep(0.2)
        original_execute(pending)

    monkeypatch.setattr(
        service,
        "_execute_telemetry",
        delayed_first_execution,
    )

    def run() -> None:
        try:
            service.run()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            running = service_status(
                slot,
                runtime_root=runtime,
                timeout_seconds=0.3,
            )
            if running["state"] == "running":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("resident service did not become ready")

        descriptor = _descriptor(slot, runtime)
        capability_path = descriptor["telemetry_capabilities"][
            "codex_app_server"
        ]
        baseline = _get_json(
            descriptor["dashboard_url"] + "api/v1/meta",
        )[1]["cursor"]
        assert isinstance(baseline, int)
        raw = json.dumps(
            {
                "method": "thread/status/changed",
                "params": {
                    "threadId": "thread-client-timeout",
                    "status": {"type": "idle"},
                },
            },
            separators=(",", ":"),
        ).encode()

        with pytest.raises(CompanyServiceOperationError) as unknown:
            ingest_service_telemetry(
                slot,
                raw,
                capability_path=capability_path,
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-client-timeout",
                adapter_event_id="event-client-timeout",
                intake_sequence=1,
                transaction_id="tx-client-timeout",
                command_id="cmd-client-timeout",
                received_at="2026-07-27T00:01:00Z",
                runtime_root=runtime,
                timeout_seconds=0.05,
            )
        assert unknown.value.status == 504
        assert unknown.value.code == "effect_unknown"
        assert unknown.value.effect == "effect_unknown"
        assert unknown.value.cursor is None

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            meta = _get_json(
                descriptor["dashboard_url"] + "api/v1/meta",
            )[1]
            if meta["cursor"] == baseline + 1:
                break
            time.sleep(0.01)
        else:
            raise AssertionError(
                "owner thread did not publish the late committed result",
            )

        replay = ingest_service_telemetry(
            slot,
            raw,
            capability_path=capability_path,
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-client-timeout",
            adapter_event_id="event-client-timeout",
            intake_sequence=1,
            transaction_id="tx-client-timeout",
            command_id="cmd-client-timeout",
            received_at="2026-07-27T00:01:00Z",
            runtime_root=runtime,
        )
        assert replay["cursor"] == baseline + 1
        assert replay["result"]["idempotent_replay"] is True

        stop_service(slot, runtime_root=runtime)
        thread.join(timeout=10.0)
        assert not thread.is_alive()
        assert failures == []
    finally:
        if thread.is_alive():
            try:
                stop_service(slot, runtime_root=runtime)
            except CompanyServiceUnavailableError:
                service.request_stop()
            thread.join(timeout=10.0)


@pytest.mark.parametrize(
    "raw_response",
    (
        b"x" * (service_module._MAX_DESCRIPTOR_BYTES + 1),
        b"{",
        b'{"schema_version":"wrong"}',
        (
            b'{"schema_version":"wrong",'
            b'"schema_version":"aoi.company.telemetry-ingest-result.v1"}'
        ),
    ),
)
def test_untrusted_success_response_is_effect_unknown(
    monkeypatch: pytest.MonkeyPatch,
    raw_response: bytes,
) -> None:
    class FakeResponse:
        status = 200

        def read(self, _limit: int) -> bytes:
            return raw_response

    def fake_open(
        _request: Request,
        *,
        timeout_seconds: float,
    ) -> Any:
        del timeout_seconds
        return nullcontext(FakeResponse())

    monkeypatch.setattr(service_module, "_open_local", fake_open)
    with pytest.raises(CompanyServiceOperationError) as unknown:
        service_module._control_operation_request(
            {"control_url": "http://127.0.0.1:1"},
            path="/control/v1/telemetry/codex",
            token="a" * 64,
            payload={},
            timeout_seconds=0.1,
        )
    assert unknown.value.status == 502
    assert unknown.value.code == "effect_unknown"
    assert unknown.value.effect == "effect_unknown"
    assert unknown.value.cursor is None


@pytest.mark.parametrize(
    "error_body",
    (
        {"error": "unknown_code"},
        {"error": "x", "effect": "garbage"},
        {
            "error": "committed_dashboard_refresh_failed",
            "effect": "committed",
        },
        {
            "error": "committed_dashboard_refresh_failed",
            "effect": "committed",
            "cursor": True,
        },
    ),
)
def test_untrusted_http_error_cannot_clear_effect_unknown(
    monkeypatch: pytest.MonkeyPatch,
    error_body: dict[str, Any],
) -> None:
    raw = json.dumps(error_body, separators=(",", ":")).encode()

    def fake_open(
        request: Request,
        *,
        timeout_seconds: float,
    ) -> Any:
        del timeout_seconds
        raise HTTPError(
            request.full_url,
            500,
            "injected",
            Message(),
            io.BytesIO(raw),
        )

    monkeypatch.setattr(service_module, "_open_local", fake_open)
    with pytest.raises(CompanyServiceOperationError) as unknown:
        service_module._control_operation_request(
            {"control_url": "http://127.0.0.1:1"},
            path="/control/v1/telemetry/codex",
            token="a" * 64,
            payload={},
            timeout_seconds=0.1,
        )
    assert unknown.value.status == 500
    assert unknown.value.code == error_body["error"]
    assert unknown.value.effect == "effect_unknown"
    assert unknown.value.cursor is None


def test_allowlisted_pre_enqueue_http_error_has_known_no_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b'{"error":"service_binding_mismatch"}'

    def fake_open(
        request: Request,
        *,
        timeout_seconds: float,
    ) -> Any:
        del timeout_seconds
        raise HTTPError(
            request.full_url,
            409,
            "injected",
            Message(),
            io.BytesIO(raw),
        )

    monkeypatch.setattr(service_module, "_open_local", fake_open)
    with pytest.raises(CompanyServiceOperationError) as rejected:
        service_module._control_operation_request(
            {"control_url": "http://127.0.0.1:1"},
            path="/control/v1/telemetry/codex",
            token="a" * 64,
            payload={},
            timeout_seconds=0.1,
        )
    assert rejected.value.status == 409
    assert rejected.value.code == "service_binding_mismatch"
    assert rejected.value.effect is None
    assert rejected.value.cursor is None


@pytest.mark.parametrize(
    ("status", "raw"),
    (
        (500, b'{"error":"service_binding_mismatch"}'),
        (
            409,
            b'{"error":"service_binding_mismatch","extra":true}',
        ),
        (
            409,
            (
                b'{"error":"other",'
                b'"error":"service_binding_mismatch"}'
            ),
        ),
    ),
)
def test_malformed_allowlisted_error_remains_effect_unknown(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    raw: bytes,
) -> None:
    def fake_open(
        request: Request,
        *,
        timeout_seconds: float,
    ) -> Any:
        del timeout_seconds
        raise HTTPError(
            request.full_url,
            status,
            "injected",
            Message(),
            io.BytesIO(raw),
        )

    monkeypatch.setattr(service_module, "_open_local", fake_open)
    with pytest.raises(CompanyServiceOperationError) as unknown:
        service_module._control_operation_request(
            {"control_url": "http://127.0.0.1:1"},
            path="/control/v1/telemetry/codex",
            token="a" * 64,
            payload={},
            timeout_seconds=0.1,
        )
    assert unknown.value.status == status
    assert unknown.value.effect == "effect_unknown"
    assert unknown.value.cursor is None


@pytest.mark.parametrize(
    ("service_instance_id", "cursor", "corruption"),
    (
        ("service-other", 1, "none"),
        ("service-expected", True, "none"),
        ("service-expected", 0, "none"),
        ("service-expected", -1, "none"),
        ("service-expected", 1, "empty_result"),
        ("service-expected", 1, "extra_top"),
        ("service-expected", 1, "extra_result"),
    ),
)
def test_untrusted_operation_result_binding_is_effect_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service_instance_id: str,
    cursor: object,
    corruption: str,
) -> None:
    slot = _slot(tmp_path)
    capability = {
        "service_instance_id": "service-expected",
        "control_url": "http://127.0.0.1:1",
        "bearer_token": "a" * 64,
        "company": {
            "company_id": "company-service-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "manifest_sha256": "a" * 64,
        },
    }

    def fake_capability(
        *_args: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        return capability

    def fake_operation(
        *_args: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        value = _telemetry_operation_result(
            service_instance_id=service_instance_id,
            cursor=cursor,
        )
        if corruption == "empty_result":
            value["result"] = {}
        elif corruption == "extra_top":
            value["extra"] = True
        elif corruption == "extra_result":
            value["result"]["extra"] = True
        return value

    monkeypatch.setattr(
        service_module,
        "_read_telemetry_capability",
        fake_capability,
    )
    monkeypatch.setattr(
        service_module,
        "_control_operation_request",
        fake_operation,
    )
    with pytest.raises(CompanyServiceOperationError) as unknown:
        ingest_service_telemetry(
            slot,
            b"{}",
            capability_path=tmp_path / "unused-capability.json",
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-result-binding",
            adapter_event_id="event-result-binding",
            intake_sequence=1,
            transaction_id="tx-result-binding",
            command_id="cmd-result-binding",
            received_at="2026-07-27T00:01:00Z",
            runtime_root=tmp_path / "runtime",
        )
    assert unknown.value.status == 502
    assert unknown.value.code == "effect_unknown"
    assert unknown.value.effect == "effect_unknown"
    assert unknown.value.cursor is None


def test_projection_degraded_reports_known_committed_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    service = service_module._ResidentService(
        slot.resolve(),
        (tmp_path / "runtime").resolve(),
        0.01,
    )
    company = {
        "company_id": "company-service-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        "pointer_sha256": "b" * 64,
    }
    descriptor = {
        "service_instance_id": service.service_instance_id,
        "company": company,
    }
    command = service_module._telemetry_ingest_command(
        _telemetry_request_payload(descriptor),
    )
    pending = service_module._PendingTelemetryIngest(command)
    record = LedgerTransactionRecord(
        global_sequence=2,
        request={},
        receipt={},
        events=(),
        reservations=(),
    )
    result = LedgerAppendResult(
        receipt={},
        idempotent_replay=False,
        record=record,
    )
    supervisor = CompanySupervisor.open(slot)

    def fail_after_commit(*_args: Any, **_kwargs: Any) -> Any:
        raise CompanyProjectionDegradedError(result)

    monkeypatch.setattr(
        supervisor,
        "ingest_codex_telemetry",
        fail_after_commit,
    )
    service._supervisor = supervisor
    try:
        service._execute_telemetry(pending)
    finally:
        supervisor.close()
    assert pending.done.is_set()
    assert pending.response is None
    assert pending.error_status == 500
    assert pending.error_code == "committed_projection_degraded"
    assert pending.error_effect == "committed"
    assert pending.error_cursor == 2
    assert service.status_payload()["cursor"] == 2


def test_post_commit_result_conversion_fault_is_effect_unknown_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    service = service_module._ResidentService(
        slot.resolve(),
        runtime.resolve(),
        0.01,
    )
    failures: list[BaseException] = []

    def run() -> None:
        try:
            service.run()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            running = service_status(
                slot,
                runtime_root=runtime,
                timeout_seconds=0.3,
            )
            if running["state"] == "running":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("resident service did not become ready")

        descriptor = _descriptor(slot, runtime)
        capability_path = descriptor["telemetry_capabilities"][
            "codex_app_server"
        ]
        baseline = _get_json(
            descriptor["dashboard_url"] + "api/v1/meta",
        )[1]["cursor"]
        assert isinstance(baseline, int)
        original_result = supervisor_module._telemetry_result_from_record

        def fail_result_conversion(
            *_args: Any,
            **_kwargs: Any,
        ) -> Any:
            raise CompanyTelemetryIngestError(
                "injected post-commit conversion fault",
            )

        monkeypatch.setattr(
            supervisor_module,
            "_telemetry_result_from_record",
            fail_result_conversion,
        )
        raw = json.dumps(
            {
                "method": "thread/status/changed",
                "params": {
                    "threadId": "thread-result-conversion",
                    "status": {"type": "idle"},
                },
            },
            separators=(",", ":"),
        ).encode()
        with pytest.raises(CompanyServiceOperationError) as unknown:
            ingest_service_telemetry(
                slot,
                raw,
                capability_path=capability_path,
                provider="codex",
                source_class="codex_app_server",
                adapter_instance_id="adapter-result-conversion",
                adapter_event_id="event-result-conversion",
                intake_sequence=1,
                transaction_id="tx-result-conversion",
                command_id="cmd-result-conversion",
                received_at="2026-07-27T00:01:00Z",
                runtime_root=runtime,
            )
        assert unknown.value.status == 409
        assert unknown.value.code == "telemetry_conflict"
        assert unknown.value.effect == "effect_unknown"
        assert unknown.value.cursor is None

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            meta = _get_json(
                descriptor["dashboard_url"] + "api/v1/meta",
            )[1]
            if meta["cursor"] == baseline + 1:
                break
            time.sleep(0.01)
        else:
            raise AssertionError(
                "post-commit conversion fault did not retain commit",
            )

        monkeypatch.setattr(
            supervisor_module,
            "_telemetry_result_from_record",
            original_result,
        )
        replay = ingest_service_telemetry(
            slot,
            raw,
            capability_path=capability_path,
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-result-conversion",
            adapter_event_id="event-result-conversion",
            intake_sequence=1,
            transaction_id="tx-result-conversion",
            command_id="cmd-result-conversion",
            received_at="2026-07-27T00:01:00Z",
            runtime_root=runtime,
        )
        assert replay["cursor"] == baseline + 1
        assert replay["result"]["idempotent_replay"] is True

        stop_service(slot, runtime_root=runtime)
        thread.join(timeout=10.0)
        assert not thread.is_alive()
        assert failures == []
    finally:
        if thread.is_alive():
            try:
                stop_service(slot, runtime_root=runtime)
            except CompanyServiceUnavailableError:
                service.request_stop()
            thread.join(timeout=10.0)


def test_bounded_owner_queue_reports_busy_then_stop_without_execution(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    service = service_module._ResidentService(
        slot.resolve(),
        (tmp_path / "runtime").resolve(),
        0.01,
    )
    company = {
        "company_id": "company-service-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        "pointer_sha256": "b" * 64,
    }
    service._company_binding = dict(company)
    descriptor = {
        "service_instance_id": service.service_instance_id,
        "company": company,
    }
    command = service_module._telemetry_ingest_command(
        _telemetry_request_payload(descriptor),
    )
    for _index in range(service_module._MAX_CONTROL_QUEUE):
        service._operations.put_nowait(None)

    with pytest.raises(service_module._ControlRequestError) as busy:
        service.submit_telemetry(command)
    assert busy.value.status == 503
    assert busy.value.code == "ingest_busy"
    assert busy.value.effect is None
    assert service._supervisor is None

    service.request_stop()
    with pytest.raises(service_module._ControlRequestError) as stopping:
        service.submit_telemetry(command)
    assert stopping.value.status == 503
    assert stopping.value.code == "service_stopping"
    assert stopping.value.effect is None
    assert service._operations.qsize() == service_module._MAX_CONTROL_QUEUE
    assert service._supervisor is None


def test_shutdown_and_enqueue_are_serialized_without_orphan_pending(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    service = service_module._ResidentService(
        slot.resolve(),
        (tmp_path / "runtime").resolve(),
        0.01,
    )
    company = {
        "company_id": "company-service-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "manifest_sha256": "a" * 64,
        "pointer_sha256": "b" * 64,
    }
    service._company_binding = dict(company)
    descriptor = {
        "service_instance_id": service.service_instance_id,
        "company": company,
    }
    command = service_module._telemetry_ingest_command(
        _telemetry_request_payload(descriptor),
    )
    enqueue_entered = threading.Event()
    allow_enqueue = threading.Event()

    class BarrierQueue(
        queue.Queue[
            service_module._PendingTelemetryIngest | None
        ],
    ):
        def put_nowait(
            self,
            item: service_module._PendingTelemetryIngest | None,
        ) -> None:
            if isinstance(
                item,
                service_module._PendingTelemetryIngest,
            ):
                enqueue_entered.set()
                assert allow_enqueue.wait(timeout=5.0)
            super().put_nowait(item)

    service._operations = BarrierQueue(
        maxsize=service_module._MAX_CONTROL_QUEUE,
    )
    outcome: list[BaseException | dict[str, Any]] = []

    def submit() -> None:
        try:
            outcome.append(service.submit_telemetry(command))
        except BaseException as exc:
            outcome.append(exc)

    submit_thread = threading.Thread(target=submit)
    submit_thread.start()
    assert enqueue_entered.wait(timeout=5.0)
    stop_thread = threading.Thread(
        target=service._stop_and_fail_pending_operations,
    )
    stop_thread.start()
    time.sleep(0.05)
    assert stop_thread.is_alive()
    allow_enqueue.set()
    submit_thread.join(timeout=5.0)
    stop_thread.join(timeout=5.0)

    assert not submit_thread.is_alive()
    assert not stop_thread.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], service_module._ControlRequestError)
    assert outcome[0].status == 503
    assert outcome[0].code == "service_stopping"
    assert outcome[0].effect is None
    assert service._operations.empty()
    assert service._supervisor is None


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows ACL enforcement is platform-specific",
)
def test_windows_runtime_root_with_broad_allow_ace_is_rejected(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "unsafe-runtime"
    runtime.mkdir()
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    icacls = system_root / "System32" / "icacls.exe"
    grant = subprocess.run(
        [
            str(icacls),
            str(runtime),
            "/grant",
            "*S-1-5-11:(OI)(CI)(RX)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10.0,
        check=False,
    )
    assert grant.returncode == 0, grant.stderr.decode(
        "utf-8",
        "replace",
    )
    resolved = runtime.resolve(strict=True)
    service_module._WINDOWS_PRIVATE_DIRECTORIES.pop(resolved, None)
    try:
        with pytest.raises(
            CompanyServiceError,
            match="grants access outside",
        ):
            service_module._mkdir_private(runtime)
        assert resolved not in service_module._WINDOWS_PRIVATE_DIRECTORIES
    finally:
        revoke = subprocess.run(
            [
                str(icacls),
                str(runtime),
                "/remove:g",
                "*S-1-5-11",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
            check=False,
        )
        assert revoke.returncode == 0, revoke.stderr.decode(
            "utf-8",
            "replace",
        )


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows ACL enforcement is platform-specific",
)
def test_windows_runtime_acl_cache_is_bound_to_directory_identity(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "replaced-runtime"
    service_module._mkdir_private(runtime)
    resolved = runtime.resolve(strict=True)
    original_identity = service_module._windows_directory_identity(
        resolved,
    )
    assert (
        service_module._WINDOWS_PRIVATE_DIRECTORIES[resolved]
        == original_identity
    )

    runtime.rmdir()
    runtime.mkdir()
    replacement_identity = service_module._windows_directory_identity(
        resolved,
    )
    assert replacement_identity != original_identity
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    icacls = system_root / "System32" / "icacls.exe"
    grant = subprocess.run(
        [
            str(icacls),
            str(runtime),
            "/grant",
            "*S-1-5-11:(OI)(CI)(RX)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10.0,
        check=False,
    )
    assert grant.returncode == 0, grant.stderr.decode(
        "utf-8",
        "replace",
    )
    try:
        with pytest.raises(
            CompanyServiceError,
            match="grants access outside",
        ):
            service_module._mkdir_private(runtime)
        assert (
            service_module._WINDOWS_PRIVATE_DIRECTORIES[resolved]
            == original_identity
        )
    finally:
        revoke = subprocess.run(
            [
                str(icacls),
                str(runtime),
                "/remove:g",
                "*S-1-5-11",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
            check=False,
        )
        service_module._WINDOWS_PRIVATE_DIRECTORIES.pop(
            resolved,
            None,
        )
        assert revoke.returncode == 0, revoke.stderr.decode(
            "utf-8",
            "replace",
        )


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows ACL enforcement is platform-specific",
)
def test_windows_acl_probe_uses_absolute_system_powershell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    expected = (
        system_root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    observed: list[list[str]] = []

    def fake_run(
        command: list[str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(command)
        value = {
            "current_user_sid": "S-1-5-21-1",
            "owner_sid": "S-1-5-21-1",
            "rules": [],
        }
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(value).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    service_module._verify_windows_private_directory(tmp_path)
    assert observed
    assert observed[0][0] == str(expected)
    assert Path(observed[0][0]).is_absolute()


def test_stale_descriptor_is_replaced_only_by_lock_owning_foreground_service(tmp_path: Path) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    descriptor_path = runtime_descriptor_path(slot, runtime_root=runtime)
    descriptor_path.parent.mkdir(parents=True)
    descriptor_path.write_text("{}", encoding="utf-8")
    process = _foreground_process(slot, runtime)
    try:
        service = _await_status(slot, runtime, process)
        assert service["descriptor"]["service_instance_id"]
        assert json.loads(descriptor_path.read_text(encoding="utf-8"))["schema_version"] == SERVICE_DESCRIPTOR_SCHEMA
        stop_service(slot, runtime_root=runtime)
        assert process.wait(timeout=10.0) == 0
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


def test_live_company_lock_prevents_foreground_service_takeover(tmp_path: Path) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    owner = CompanySupervisor.open(slot)
    try:
        with pytest.raises(CompanyServiceUnavailableError, match="live unknown writer"):
            run_service_foreground(slot, runtime_root=runtime, refresh_seconds=0.01)
        assert not runtime_descriptor_path(slot, runtime_root=runtime).exists()
    finally:
        owner.close()


def test_ensure_uses_exact_isolated_child_command_and_returns_existing_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    calls: list[tuple[list[str], dict[str, Any]]] = []
    statuses = iter((
        {"state": "unavailable", "reason": "descriptor_absent"},
        {"state": "running", "descriptor": {"service_instance_id": "instance"}},
    ))

    def fake_status(*_args: object, **_kwargs: object) -> dict[str, Any]:
        return next(statuses)

    class FakeChild:
        def poll(self) -> int | None:
            return None

    def fake_popen(command: list[str], **kwargs: Any) -> FakeChild:
        calls.append((command, kwargs))
        return FakeChild()

    monkeypatch.setattr(service_module, "service_status", fake_status)
    monkeypatch.setattr("aoi_orgware.company.service.subprocess.Popen", fake_popen)
    result = ensure_service(slot, runtime_root=runtime, timeout_seconds=1.0)
    assert result["state"] == "running"
    assert calls[0][0] == [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "aoi_orgware.company.service",
        "--slot-root",
        str(slot.resolve()),
        "--runtime-root",
        str(runtime),
    ]
    assert calls[0][1]["stdin"] is subprocess.DEVNULL


@pytest.mark.parametrize("value", (float("nan"), float("inf"), 0.0, 301.0))
def test_service_timeouts_reject_nonfinite_or_unbounded_values(
    tmp_path: Path,
    value: float,
) -> None:
    slot = _slot(tmp_path)
    with pytest.raises(service_module.CompanyServiceError):
        service_status(slot, timeout_seconds=value)
    with pytest.raises(service_module.CompanyServiceError):
        ensure_service(slot, timeout_seconds=value)


def test_foreground_service_rejects_inferred_or_unknown_dashboard_environment(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    with pytest.raises(
        CompanyServiceError,
        match="Dashboard environment kind is invalid",
    ):
        run_service_foreground(
            slot,
            dashboard_environment_kind="company-name-looks-synthetic",
        )


def test_expected_manifest_fences_discovery_to_service_race(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    with pytest.raises(
        CompanyServiceUnavailableError,
        match="manifest changed after discovery",
    ):
        run_service_foreground(
            slot,
            runtime_root=runtime,
            refresh_seconds=0.01,
            expected_manifest_sha256="f" * 64,
        )
    assert not runtime_descriptor_path(slot, runtime_root=runtime).exists()
    with CompanySupervisor.open(slot):
        pass


def test_ensure_rejects_running_service_with_another_manifest(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    process = _foreground_process(slot, runtime)
    try:
        running = _await_status(slot, runtime, process)
        actual = running["descriptor"]["company"]["manifest_sha256"]
        assert actual != "f" * 64
        with pytest.raises(
            CompanyServiceUnavailableError,
            match="manifest differs from discovery",
        ):
            ensure_service(
                slot,
                runtime_root=runtime,
                expected_manifest_sha256="f" * 64,
            )
        assert service_status(slot, runtime_root=runtime)["state"] == "running"
        stop_service(slot, runtime_root=runtime)
        assert process.wait(timeout=10.0) == 0
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


def test_stop_rejects_running_service_with_another_manifest(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    process = _foreground_process(slot, runtime)
    try:
        running = _await_status(slot, runtime, process)
        actual = running["descriptor"]["company"]["manifest_sha256"]
        assert actual != "f" * 64
        with pytest.raises(
            CompanyServiceUnavailableError,
            match="manifest differs from discovery",
        ):
            stop_service(
                slot,
                runtime_root=runtime,
                expected_manifest_sha256="f" * 64,
            )
        assert service_status(slot, runtime_root=runtime)["state"] == "running"
        stop_service(
            slot,
            runtime_root=runtime,
            expected_manifest_sha256=actual,
        )
        assert process.wait(timeout=10.0) == 0
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("control_url", "https://attacker.invalid/control"),
        ("control_url", "http://localhost:1234"),
        ("control_url", "http://127.0.0.1:1234/control"),
        ("control_url", "http://127.0.0.1:1234?next=outside"),
        ("dashboard_url", "http://127.0.0.1:1234"),
        ("dashboard_url", "http://user@127.0.0.1:1234/"),
    ),
)
def test_status_rejects_noncanonical_descriptor_urls_without_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    path = runtime_descriptor_path(slot, runtime_root=runtime)
    path.parent.mkdir(parents=True)
    descriptor = {
        "schema_version": SERVICE_DESCRIPTOR_SCHEMA,
        "slot_sha256": service_module._slot_sha256(slot.resolve()),
        "slot_path": str(slot.resolve()),
        "company": {
            "company_id": "company-service-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "manifest_sha256": "a" * 64,
            "pointer_sha256": "b" * 64,
        },
        "pid": 123,
        "service_instance_id": "00000000-0000-4000-8000-000000000001",
        "dashboard_url": "http://127.0.0.1:1234/",
        "control_url": "http://127.0.0.1:1235",
        "bearer_token": "c" * 64,
        "telemetry_capabilities": {
            "codex_app_server": str(
                path.parent / "cap-codex.json",
            ),
            "claude_hook": str(
                path.parent / "cap-claude.json",
            ),
            "otel": str(
                path.parent / "cap-otel.json",
            ),
        },
    }
    descriptor[field] = value
    path.write_text(json.dumps(descriptor), encoding="utf-8")
    requested = False

    def forbidden_request(*_args: object, **_kwargs: object) -> object:
        nonlocal requested
        requested = True
        raise AssertionError("invalid descriptor must not cause a request")

    monkeypatch.setattr(service_module, "_open_local", forbidden_request)
    status = service_status(slot, runtime_root=runtime)
    assert status["state"] == "unavailable"
    assert "loopback" in str(status["reason"]) or "canonical" in str(status["reason"])
    assert not requested


def test_service_status_preserves_stopping_and_redacts_control_secret(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    process = _foreground_process(slot, runtime)
    try:
        running = _await_status(slot, runtime, process)
        private_descriptor = _descriptor(slot, runtime)
        _get_json(
            private_descriptor["control_url"] + "/stop",
            token=private_descriptor["bearer_token"],
            method="POST",
        )
        stopping = service_status(
            slot,
            runtime_root=runtime,
            timeout_seconds=0.3,
        )
        assert stopping["state"] in {"stopping", "unavailable"}
        if stopping["state"] == "stopping":
            assert "bearer_token" not in stopping["descriptor"]
            assert (
                "telemetry_capabilities"
                not in stopping["descriptor"]
            )
        assert process.wait(timeout=10.0) == 0
        assert running["descriptor"]["service_instance_id"]
    finally:
        if process.poll() is None:
            stop_service(slot, runtime_root=runtime)
            process.wait(timeout=10.0)


def test_malformed_descriptor_cannot_skip_supervisor_shutdown(
    tmp_path: Path,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    service = service_module._ResidentService(
        slot.resolve(),
        runtime.resolve(),
        0.01,
    )
    failures: list[BaseException] = []

    def run() -> None:
        try:
            service.run()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not runtime_descriptor_path(
        slot,
        runtime_root=runtime,
    ).is_file():
        time.sleep(0.02)
    path = runtime_descriptor_path(slot, runtime_root=runtime)
    assert path.is_file()
    path.write_text("{", encoding="utf-8")
    service.request_stop()
    thread.join(timeout=10.0)
    assert not thread.is_alive()
    assert failures == []
    with CompanySupervisor.open(slot):
        pass


def test_descriptor_remains_stopping_until_company_lock_is_released(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = _slot(tmp_path)
    runtime = tmp_path / "runtime"
    service = service_module._ResidentService(
        slot.resolve(),
        runtime.resolve(),
        0.01,
    )
    close_entered = threading.Event()
    allow_close = threading.Event()
    original_close = CompanySupervisor.close

    def blocking_close(supervisor: CompanySupervisor) -> None:
        close_entered.set()
        assert allow_close.wait(timeout=10.0)
        original_close(supervisor)

    monkeypatch.setattr(CompanySupervisor, "close", blocking_close)
    failures: list[BaseException] = []

    def run() -> None:
        try:
            service.run()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    path = runtime_descriptor_path(slot, runtime_root=runtime)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not path.is_file():
        time.sleep(0.02)
    assert path.is_file()
    service.request_stop()
    assert close_entered.wait(timeout=10.0)
    assert path.is_file()
    status = service_status(slot, runtime_root=runtime, timeout_seconds=0.3)
    assert status["state"] == "stopping"
    with pytest.raises(CompanyProcessLockBusyError):
        CompanySupervisor.open(slot, lock_timeout_seconds=0.01)
    allow_close.set()
    thread.join(timeout=10.0)
    assert not thread.is_alive()
    assert failures == []
    assert not path.exists()
    with CompanySupervisor.open(slot):
        pass
