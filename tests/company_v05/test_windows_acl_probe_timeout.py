from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company import service as service_module
from aoi_orgware.company.service import CompanyServiceError


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
    assert observed == [30.0]


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

    assert observed == [30.0]
    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)
