from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aoi_orgware import ic_pack
from aoi_orgware.ic_pack import canonical_json_bytes, request_bytes
from aoi_orgware.ic_pack_cli import build_parser, main
from aoi_orgware.ic_pack_worker import derive_worker_receipt

from tests.test_ic_pack import make_request


def test_parser_is_closed() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["--request", "request.json", "--request-sha256", "a" * 64]
    )
    assert args.request == Path("request.json")
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--request",
                "request.json",
                "--request-sha256",
                "a" * 64,
                "--shell",
                "arbitrary",
            ]
        )


def test_cli_runs_once_and_replays_json_without_second_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    request = make_request(tmp_path / "run")
    data = request_bytes(request)
    digest = hashlib.sha256(data).hexdigest()
    path = tmp_path / "request.json"
    path.write_bytes(data)
    calls: list[str] = []

    def worker(worker_data: bytes) -> tuple[int, bytes, bytes]:
        parsed = ic_pack.parse_request_bytes(worker_data)
        calls.append(parsed.run_id)
        return 0, canonical_json_bytes(derive_worker_receipt(parsed)), b""

    monkeypatch.setattr(ic_pack, "_default_launcher", worker)
    argv = ["--request", str(path), "--request-sha256", digest]
    assert main(argv) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(argv) == 0
    second = json.loads(capsys.readouterr().out)
    assert calls == ["run-1"]
    assert first["schema_version"] == 2
    assert first["terminal_effect"] == "completed"
    assert first["worker_exit_code"] == 0
    assert first["worker_receipt_validation"] == "accepted"
    assert first["idempotent_replay"] is False
    assert second["idempotent_replay"] is True
    assert second["terminal_receipt_sha256"] == first["terminal_receipt_sha256"]
    assert [item["stage"] for item in second["stages"]] == [
        "preflight",
        "compile",
        "elaboration",
        "runtime",
        "numeric",
    ]


def test_cli_digest_mismatch_is_typed_and_has_no_launch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = make_request(tmp_path / "run")
    path = tmp_path / "request.json"
    path.write_bytes(request_bytes(request))
    assert main(["--request", str(path), "--request-sha256", "a" * 64]) == 2
    assert "request file digest differs" in capsys.readouterr().err
    assert not Path(request.output_root).exists()


def test_cli_rejects_noncanonical_request_before_launch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = make_request(tmp_path / "run")
    path = tmp_path / "request.json"
    data = json.dumps(ic_pack.request_to_dict(request), indent=2).encode()
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    assert main(["--request", str(path), "--request-sha256", digest]) == 2
    assert "canonical" in capsys.readouterr().err
    assert not Path(request.output_root).exists()


@pytest.mark.parametrize(
    "field",
    (
        "terminal_effect",
        "worker_receipt_validation",
        "worker_receipt_validation_reason",
    ),
)
def test_cli_terminal_container_tampering_is_typed_and_does_not_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    field: str,
) -> None:
    request = make_request(tmp_path / field)
    data = request_bytes(request)
    digest = hashlib.sha256(data).hexdigest()
    path = tmp_path / "request.json"
    path.write_bytes(data)
    calls: list[str] = []

    def worker(worker_data: bytes) -> tuple[int, bytes, bytes]:
        parsed = ic_pack.parse_request_bytes(worker_data)
        calls.append(parsed.run_id)
        return 0, canonical_json_bytes(derive_worker_receipt(parsed)), b""

    monkeypatch.setattr(ic_pack, "_default_launcher", worker)
    argv = ["--request", str(path), "--request-sha256", digest]
    assert main(argv) == 0
    capsys.readouterr()
    terminal = Path(request.output_root) / "terminal-receipt.json"
    value = json.loads(terminal.read_text(encoding="utf-8"))
    value[field] = []
    preimage = {key: item for key, item in value.items() if key != "receipt_sha256"}
    value["receipt_sha256"] = hashlib.sha256(
        canonical_json_bytes(preimage)
    ).hexdigest()
    terminal.write_bytes(canonical_json_bytes(value))

    assert main(argv) == 2
    assert "is invalid" in capsys.readouterr().err
    assert calls == ["run-1"]
