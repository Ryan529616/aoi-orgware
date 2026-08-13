from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company import service as service_module
from aoi_orgware.company.service import CompanyServiceError
import tests.company_v05.test_company_service as service_tests


def test_windows_acl_probe_uses_one_bounded_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[float] = []

    def succeed(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(kwargs["timeout"])
        payload = {
            "current_user_sid": "S-1-5-21-1",
            "owner_sid": "S-1-5-21-1",
            "rules": [],
        }
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", succeed)
    service_module._verify_windows_private_directory(tmp_path)
    assert observed == [service_module._WINDOWS_ACL_PROBE_TIMEOUT_SECONDS]


def test_windows_acl_probe_uses_bounded_timeout_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[float] = []

    def timeout(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(
        CompanyServiceError,
        match="cannot verify private Windows runtime ACL",
    ) as caught:
        service_module._verify_windows_private_directory(tmp_path)

    assert observed == [service_module._WINDOWS_ACL_PROBE_TIMEOUT_SECONDS]
    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)


def test_default_service_readiness_outlives_acl_probe_and_accepts_slow_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        service_module._SERVICE_READINESS_TIMEOUT_SECONDS
        > service_module._WINDOWS_ACL_PROBE_TIMEOUT_SECONDS + 4.0
    )
    clock = 0.0
    spawned: list[list[str]] = []

    class RunningChild:
        def poll(self) -> None:
            return None

    def monotonic() -> float:
        return clock

    def sleep(seconds: float) -> None:
        nonlocal clock
        clock += max(seconds, 1.0)

    def status(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        if clock <= service_module._WINDOWS_ACL_PROBE_TIMEOUT_SECONDS + 4.0:
            return {"state": "unavailable", "reason": "descriptor_absent"}
        return {"state": "running", "descriptor": {}, "status": {}}

    def popen(command: list[str], **_kwargs: Any) -> RunningChild:
        spawned.append(command)
        return RunningChild()

    monkeypatch.setattr(service_module.time, "monotonic", monotonic)
    monkeypatch.setattr(service_module.time, "sleep", sleep)
    monkeypatch.setattr(service_module, "service_status", status)
    monkeypatch.setattr(service_module.subprocess, "Popen", popen)

    result = service_module.ensure_service(tmp_path / "company")

    assert result["state"] == "running"
    assert (
        service_module._WINDOWS_ACL_PROBE_TIMEOUT_SECONDS + 4.0
        < clock
        < service_module._SERVICE_READINESS_TIMEOUT_SECONDS
    )
    assert len(spawned) == 1


def test_await_status_timeout_terminates_only_exact_child_and_preserves_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExactChild:
        returncode: int | None = None
        terminated = False
        killed = False

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True
            self.returncode = 137

        def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
            assert timeout == 10.0
            if not self.killed:
                raise subprocess.TimeoutExpired("exact-child", timeout)
            return b"", b"slow private-directory verification"

    moments = iter((0.0, 0.0, 61.0))
    child = ExactChild()
    monkeypatch.setattr(service_tests.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(service_tests.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        service_tests,
        "service_status",
        lambda *_args, **_kwargs: {
            "state": "unavailable",
            "reason": "descriptor_absent",
        },
    )

    with pytest.raises(AssertionError) as caught:
        service_tests._await_status(
            tmp_path / "slot",
            tmp_path / "runtime",
            child,  # type: ignore[arg-type]
        )

    assert child.terminated is True
    assert child.killed is True
    assert "descriptor_absent" in str(caught.value)
    assert "slow private-directory verification" in str(caught.value)


def test_await_status_cleanup_race_preserves_primary_readiness_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RacedChild:
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            raise ProcessLookupError("child exited during terminate")

        def kill(self) -> None:
            raise ProcessLookupError("child already exited")

        def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
            assert timeout == 10.0
            return b"", b""

    moments = iter((0.0, 0.0, 61.0))
    monkeypatch.setattr(service_tests.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(service_tests.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        service_tests,
        "service_status",
        lambda *_args, **_kwargs: {
            "state": "unavailable",
            "reason": "descriptor_absent",
        },
    )

    with pytest.raises(AssertionError) as caught:
        service_tests._await_status(
            tmp_path / "slot",
            tmp_path / "runtime",
            RacedChild(),  # type: ignore[arg-type]
        )

    assert "descriptor_absent" in str(caught.value)
    assert "child exited during terminate" in str(caught.value)
