from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

from tests.provenance_subprocess import run_python_checked


def test_failure_retains_raw_streams_without_copying_them_into_error(
    tmp_path: Path,
) -> None:
    secret = "PROVENANCE_HELPER_SECRET_SENTINEL"
    stdout = secret.encode("ascii") + b"\xff-out"
    stderr = secret.encode("ascii") + b"\xfe-err"
    evidence_root = tmp_path / "evidence"

    with pytest.raises(AssertionError) as captured:
        run_python_checked(
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; "
                f"sys.stdout.buffer.write({stdout!r}); "
                f"sys.stderr.buffer.write({stderr!r}); "
                "raise SystemExit(7)"
            ),
            cache_root=tmp_path / "cache",
            evidence_root=evidence_root,
            label="failed-child",
        )

    message = str(captured.value)
    prefix = "isolated Python subprocess failed: "
    assert message.startswith(prefix)
    assert secret not in message
    receipt = json.loads(message.removeprefix(prefix))
    assert receipt["returncode"] == 7
    assert "stdout_tail" not in receipt
    assert "stderr_tail" not in receipt
    assert secret not in (evidence_root / "failed-child.json").read_text(
        encoding="utf-8"
    )
    for role, expected in (("stdout", stdout), ("stderr", stderr)):
        assert (evidence_root / f"failed-child.{role}.log").read_bytes() == expected
        assert receipt[role]["size_bytes"] == len(expected)
        assert receipt[role]["sha256"] == hashlib.sha256(expected).hexdigest()


def test_success_replacement_decodes_non_utf8_streams(tmp_path: Path) -> None:
    stdout = b"\xff-out"
    stderr = b"\xfe-err"
    evidence_root = tmp_path / "evidence"

    completed = run_python_checked(
        sys.executable,
        "-I",
        "-c",
        (
            "import sys; "
            f"sys.stdout.buffer.write({stdout!r}); "
            f"sys.stderr.buffer.write({stderr!r})"
        ),
        cache_root=tmp_path / "cache",
        evidence_root=evidence_root,
        label="successful-child",
    )

    assert completed.returncode == 0
    assert completed.stdout == "\ufffd-out"
    assert completed.stderr == "\ufffd-err"
    assert (evidence_root / "successful-child.stdout.log").read_bytes() == stdout
    assert (evidence_root / "successful-child.stderr.log").read_bytes() == stderr
