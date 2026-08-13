from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.ic_pack import (
    AUTHORITY_BOUNDARY,
    ICPackError,
    ICPackRequestV1,
    PACK_MODE,
    canonical_json_bytes,
    execute_request,
    fixture_manifest_dict,
    fixture_manifest_sha256,
    parse_request_bytes,
    request_bytes,
    request_to_dict,
    result_to_dict,
    synthetic_tool_sha256,
)
from aoi_orgware.ic_pack_worker import derive_worker_receipt
from aoi_orgware.ic_pack_terminal import (
    ICPackTerminalError,
    build_terminal_receipt,
    validate_terminal_receipt,
)


def make_request(root: Path, **changes: Any) -> ICPackRequestV1:
    value: dict[str, Any] = {
        "schema_version": 1,
        "mode": PACK_MODE,
        "task_id": "ic-pack-task",
        "job_id": "job-1",
        "run_id": "run-1",
        "rtl_packet_id": "packet-rtl",
        "dv_packet_id": "packet-dv",
        "source_manifest_sha256": fixture_manifest_sha256(),
        "tool_sha256": synthetic_tool_sha256(),
        "output_root": str(root),
    }
    value.update(changes)
    return parse_request_bytes(canonical_json_bytes(value))


def good_launcher(calls: list[str]):
    def launch(data: bytes) -> tuple[int, bytes, bytes]:
        request = parse_request_bytes(data)
        calls.append(request.run_id)
        return 0, canonical_json_bytes(derive_worker_receipt(request)), b""

    return launch


def reseal_receipt(value: dict[str, Any]) -> None:
    preimage = {key: item for key, item in value.items() if key != "receipt_sha256"}
    value["receipt_sha256"] = hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()


@pytest.mark.parametrize(
    ("field", "malformed"),
    (
        ("terminal_effect", []),
        ("terminal_effect", {}),
        ("worker_receipt_validation", []),
        ("worker_receipt_validation", {}),
        ("worker_receipt_validation_reason", []),
        ("worker_receipt_validation_reason", {}),
    ),
)
def test_terminal_enum_containers_are_typed_rejections(
    field: str, malformed: object
) -> None:
    request_digest = hashlib.sha256(b"request").hexdigest()
    receipt = build_terminal_receipt(
        launch_id="launch-1",
        request_sha256=request_digest,
        worker_exit_code=0,
        stdout=b"",
        stderr=b"",
        validation="accepted",
        validation_reason="accepted",
        worker_receipt={},
    )
    receipt[field] = malformed
    reseal_receipt(receipt)
    with pytest.raises(ICPackTerminalError, match="invalid"):
        validate_terminal_receipt(
            receipt, launch_id="launch-1", request_sha256=request_digest
        )


def test_fixture_manifest_request_and_worker_receipt_are_exact(tmp_path: Path) -> None:
    manifest = fixture_manifest_dict()
    assert manifest["fixture_id"] == "aoi_tiny_sv_v1"
    assert [item["path"] for item in manifest["files"]] == [
        "resources/ic_pack/tiny_vcs/tiny_tb.sv",
        "resources/ic_pack/tiny_vcs/tiny_top.sv",
    ]
    request = make_request(tmp_path / "run")
    data = request_bytes(request)
    assert parse_request_bytes(data) == request
    assert request_to_dict(request)["source_manifest_sha256"] == fixture_manifest_sha256()
    worker = derive_worker_receipt(request)
    assert [item["stage"] for item in worker["stages"]] == [
        "preflight",
        "compile",
        "elaboration",
        "runtime",
        "numeric",
    ]
    assert worker["authority_boundary"] == AUTHORITY_BOUNDARY
    assert "not_vcs_compile" in worker["stages"][1]["evidence_classification"]
    assert "not_hdl_runtime" in worker["stages"][3]["evidence_classification"]


def test_single_launch_terminal_replay_and_immutability(tmp_path: Path) -> None:
    request = make_request(tmp_path / "run")
    digest = hashlib.sha256(request_bytes(request)).hexdigest()
    calls: list[str] = []
    first = execute_request(request, digest, launcher=good_launcher(calls))
    second = execute_request(request, digest, launcher=good_launcher(calls))
    assert calls == ["run-1"]
    assert first.terminal_effect == second.terminal_effect == "completed"
    assert first.worker_exit_code == second.worker_exit_code == 0
    assert first.worker_receipt_validation == "accepted"
    assert first.worker_receipt_validation_reason == "accepted"
    assert first.idempotent_replay is False
    assert second.idempotent_replay is True
    assert len(first.stages) == 5
    assert first.oracle_receipt is not None
    assert first.oracle_receipt.mismatch_count == 0
    assert first.terminal_receipt_sha256 == second.terminal_receipt_sha256
    assert not hasattr(first, "__dict__")
    assert not hasattr(first.stages[0], "__dict__")
    assert not hasattr(first.oracle_receipt, "__dict__")
    assert (Path(request.output_root) / "launch-receipt.json").is_file()
    assert (Path(request.output_root) / "terminal-receipt.json").is_file()
    terminal = json.loads(
        (Path(request.output_root) / "terminal-receipt.json").read_text(encoding="utf-8")
    )
    assert terminal["schema_version"] == 2
    assert terminal["worker_exit_code"] == 0
    assert result_to_dict(second)["authority_boundary"] == AUTHORITY_BOUNDARY


def test_effect_unknown_never_relaunches_or_accepts_divergent_request(tmp_path: Path) -> None:
    request = make_request(tmp_path / "run")
    digest = hashlib.sha256(request_bytes(request)).hexdigest()
    calls: list[str] = []

    def uncertain(data: bytes) -> tuple[int, bytes, bytes]:
        calls.append(hashlib.sha256(data).hexdigest())
        raise TimeoutError("synthetic lost terminal")

    first = execute_request(request, digest, launcher=uncertain)
    second = execute_request(request, digest, launcher=uncertain)
    assert calls == [digest]
    assert first.terminal_effect == second.terminal_effect == "effect_unknown"
    assert first.worker_exit_code is second.worker_exit_code is None
    assert first.worker_receipt_validation == "not_attempted"
    assert first.worker_receipt_validation_reason == "terminal_unavailable"
    assert first.idempotent_replay is False
    assert second.idempotent_replay is True
    assert not (Path(request.output_root) / "terminal-receipt.json").exists()
    divergent = make_request(Path(request.output_root), job_id="job-2")
    divergent_digest = hashlib.sha256(request_bytes(divergent)).hexdigest()
    with pytest.raises(ICPackError, match="launch receipt differs"):
        execute_request(divergent, divergent_digest, launcher=uncertain)
    assert calls == [digest]


def test_known_worker_exit_is_terminal_and_replay_safe(tmp_path: Path) -> None:
    request = make_request(tmp_path / "run")
    digest = hashlib.sha256(request_bytes(request)).hexdigest()
    calls = 0

    def failed(_: bytes) -> tuple[int, bytes, bytes]:
        nonlocal calls
        calls += 1
        return 7, b"", b"synthetic worker failure"

    first = execute_request(request, digest, launcher=failed)
    second = execute_request(request, digest, launcher=failed)
    assert calls == 1
    assert first.terminal_effect == second.terminal_effect == "failed_known"
    assert first.worker_exit_code == second.worker_exit_code == 7
    assert first.worker_receipt_validation == "not_attempted"
    assert first.worker_receipt_validation_reason == "worker_exit_nonzero"
    assert first.coverage == "degraded"
    assert second.idempotent_replay is True


def test_request_boundary_rejects_noncanonical_duplicate_huge_and_bool(tmp_path: Path) -> None:
    request = make_request(tmp_path / "run")
    value = request_to_dict(request)
    pretty = json.dumps(value, indent=2).encode()
    with pytest.raises(ICPackError, match="canonical"):
        parse_request_bytes(pretty)
    duplicate = request_bytes(request).replace(
        b'"schema_version":1,', b'"schema_version":1,"schema_version":1,', 1
    )
    with pytest.raises(ICPackError, match="duplicates"):
        parse_request_bytes(duplicate)
    value["schema_version"] = True
    with pytest.raises(ICPackError, match="schema_version"):
        parse_request_bytes(canonical_json_bytes(value))
    huge = b'{"schema_version":' + b"9" * 5000 + b"}"
    with pytest.raises(ICPackError, match="invalid JSON"):
        parse_request_bytes(huge)
    value = request_to_dict(request)
    value["source_manifest_sha256"] = "a" * 64
    with pytest.raises(ICPackError, match="source manifest"):
        parse_request_bytes(canonical_json_bytes(value))
    forged = request._replace(source_manifest_sha256="a" * 64)
    with pytest.raises(ICPackError, match="source manifest"):
        execute_request(forged, hashlib.sha256(request_bytes(forged)).hexdigest())


def test_receipt_tampering_and_unowned_output_fail_closed(tmp_path: Path) -> None:
    request = make_request(tmp_path / "run")
    digest = hashlib.sha256(request_bytes(request)).hexdigest()
    execute_request(request, digest, launcher=good_launcher([]))
    terminal = Path(request.output_root) / "terminal-receipt.json"
    value = json.loads(terminal.read_text(encoding="utf-8"))
    value["worker_exit_code"] = True
    reseal_receipt(value)
    terminal.write_bytes(canonical_json_bytes(value))
    with pytest.raises(ICPackError, match="terminal receipt"):
        execute_request(request, digest, launcher=good_launcher([]))
    other = make_request(tmp_path / "unowned")
    Path(other.output_root).mkdir()
    (Path(other.output_root) / "foreign.txt").write_text("foreign", encoding="utf-8")
    with pytest.raises(ICPackError, match="unowned"):
        execute_request(other, hashlib.sha256(request_bytes(other)).hexdigest())


@pytest.mark.parametrize(
    "field",
    (
        "terminal_effect",
        "worker_receipt_validation",
        "worker_receipt_validation_reason",
    ),
)
def test_terminal_replay_container_tampering_is_typed_and_does_not_relaunch(
    tmp_path: Path, field: str
) -> None:
    request = make_request(tmp_path / field)
    digest = hashlib.sha256(request_bytes(request)).hexdigest()
    calls: list[str] = []
    execute_request(request, digest, launcher=good_launcher(calls))
    terminal = Path(request.output_root) / "terminal-receipt.json"
    value = json.loads(terminal.read_text(encoding="utf-8"))
    value[field] = []
    reseal_receipt(value)
    terminal.write_bytes(canonical_json_bytes(value))
    with pytest.raises(ICPackError, match="invalid"):
        execute_request(request, digest, launcher=good_launcher(calls))
    assert calls == ["run-1"]


@pytest.mark.parametrize(
    "forgery",
    ("stage_digest", "worker_schema_bool", "oracle_schema_bool", "oracle_count_bool"),
)
def test_resealed_worker_forgery_is_failed_known(
    tmp_path: Path, forgery: str
) -> None:
    request = make_request(tmp_path / forgery)
    digest = hashlib.sha256(request_bytes(request)).hexdigest()
    calls = 0

    def forged_launcher(data: bytes) -> tuple[int, bytes, bytes]:
        nonlocal calls
        calls += 1
        worker_request = parse_request_bytes(data)
        worker = derive_worker_receipt(worker_request)
        if forgery == "stage_digest":
            worker["stages"][1]["evidence_sha256"] = "a" * 64
        elif forgery == "worker_schema_bool":
            worker["schema_version"] = True
        elif forgery == "oracle_schema_bool":
            worker["oracle_receipt"]["schema_version"] = True
            reseal_receipt(worker["oracle_receipt"])
        else:
            worker["oracle_receipt"]["mismatch_count"] = False
            reseal_receipt(worker["oracle_receipt"])
        reseal_receipt(worker)
        return 0, canonical_json_bytes(worker), b""

    result = execute_request(request, digest, launcher=forged_launcher)
    replay = execute_request(request, digest, launcher=forged_launcher)
    assert calls == 1
    assert result.terminal_effect == "failed_known"
    assert result.worker_exit_code == replay.worker_exit_code == 0
    assert result.worker_receipt_validation == "rejected"
    assert result.worker_receipt_validation_reason == "invalid_worker_receipt"
    assert result.stages == ()
    assert result.oracle_receipt is None


def test_resealed_bool_launch_receipt_is_rejected(tmp_path: Path) -> None:
    request = make_request(tmp_path / "launch-bool")
    digest = hashlib.sha256(request_bytes(request)).hexdigest()

    def uncertain(_: bytes) -> tuple[int, bytes, bytes]:
        raise TimeoutError("synthetic lost terminal")

    first = execute_request(request, digest, launcher=uncertain)
    assert first.terminal_effect == "effect_unknown"
    launch_path = Path(request.output_root) / "launch-receipt.json"
    launch = json.loads(launch_path.read_text(encoding="utf-8"))
    launch["schema_version"] = True
    reseal_receipt(launch)
    launch_path.write_bytes(canonical_json_bytes(launch))
    with pytest.raises(ICPackError, match="launch receipt differs"):
        execute_request(request, digest, launcher=uncertain)
