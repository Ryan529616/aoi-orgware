from __future__ import annotations

import sys
import time

import pytest

from aoi_orgware.company import identity as identity_module


def test_bounded_output_overflow_kills_a_still_live_synthetic_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity_module, "_MAX_GIT_OUTPUT_BYTES", 64)
    real_popen = identity_module.subprocess.Popen
    observed_processes = []

    def observe_popen(*args: object, **kwargs: object):
        process = real_popen(*args, **kwargs)
        observed_processes.append(process)
        return process

    monkeypatch.setattr(identity_module.subprocess, "Popen", observe_popen)
    started = time.monotonic()
    try:
        with pytest.raises(identity_module.CompanyIdentityError, match="output exceeds bound"):
            identity_module._run_bounded_command(
                [
                    sys.executable,
                    "-S",
                    "-c",
                    "import os,time;os.write(1,b'x'*65);time.sleep(60)",
                ],
                label="run live bounded-output canary",
                timeout_seconds=30,
            )
        assert time.monotonic() - started < 10
        assert len(observed_processes) == 1
        assert observed_processes[0].poll() is not None
    finally:
        for process in observed_processes:
            if process.poll() is None:
                process.kill()
                process.wait()
