"""Isolated, replay-safe IC Pack harness for the Phase-1 synthetic canary.

The pack owns a fixed package fixture and a package-owned worker command.  It
does not accept arbitrary shell, modify a repository, or claim VCS/EDA truth.
An acquired launch without a sealed terminal is permanently effect-unknown;
replay never launches it again.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from importlib import resources
from pathlib import Path
from typing import Any, NamedTuple, cast

from . import harnesslib as h
from .ic_pack_terminal import (
    ICPackTerminalError,
    build_terminal_receipt,
    validate_terminal_receipt,
)


REQUEST_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 2
MAX_REQUEST_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
WORKER_TIMEOUT_SECONDS = 30
PACK_MODE = "synthetic_vcs_fixture_v1"
AUTHORITY_BOUNDARY = "synthetic_contract_only_not_vcs_eda_arise_or_signoff"
ORACLE_AUTHORITY = "caller_supplied_digest_bound_not_ledger_or_eda_authority"
FIXTURE_ID = "aoi_tiny_sv_v1"
FIXTURE_FILES = ("tiny_tb.sv", "tiny_top.sv")

_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
_SHA_CHARS = frozenset("0123456789abcdef")
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "task_id",
        "job_id",
        "run_id",
        "rtl_packet_id",
        "dv_packet_id",
        "source_manifest_sha256",
        "tool_sha256",
        "output_root",
    }
)
_LAUNCH_FIELDS = frozenset(
    {
        "schema_version",
        "launch_id",
        "request_sha256",
        "job_id",
        "run_id",
        "status",
        "receipt_sha256",
    }
)
_WORKER_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "task_id",
        "job_id",
        "run_id",
        "rtl_packet_id",
        "dv_packet_id",
        "command_sha256",
        "source_manifest_sha256",
        "tool_sha256",
        "stages",
        "oracle_receipt",
        "authority_boundary",
        "receipt_sha256",
    }
)
_STAGE_FIELDS = frozenset(
    {"stage", "status", "evidence_sha256", "evidence_classification"}
)
_ORACLE_FIELDS = frozenset(
    {
        "schema_version",
        "oracle_id",
        "job_id",
        "run_id",
        "rtl_packet_id",
        "dv_packet_id",
        "source_sha256",
        "tool_sha256",
        "command_sha256",
        "numeric_evidence_sha256",
        "outcome",
        "mismatch_count",
        "authority",
        "receipt_sha256",
    }
)
_STAGES = ("preflight", "compile", "elaboration", "runtime", "numeric")
_CLASSIFICATIONS = {
    "preflight": "synthetic_fixture_inventory_check",
    "compile": "synthetic_source_contract_not_vcs_compile",
    "elaboration": "synthetic_hierarchy_contract_not_vcs_elaboration",
    "runtime": "synthetic_python_model_not_hdl_runtime",
    "numeric": "synthetic_exact_oracle_not_arise_numeric",
}


class ICPackError(ValueError):
    """Typed fail-closed error for IC Pack inputs and durable receipts."""


class ICPackRequestV1(NamedTuple):
    mode: str
    task_id: str
    job_id: str
    run_id: str
    rtl_packet_id: str
    dv_packet_id: str
    command_sha256: str
    source_manifest_sha256: str
    tool_sha256: str
    output_root: str


class ICPackStageReceiptV1(NamedTuple):
    stage: str
    status: str
    evidence_sha256: str
    evidence_classification: str


class ICPackOracleReceiptV1(NamedTuple):
    oracle_id: str
    job_id: str
    run_id: str
    rtl_packet_id: str
    dv_packet_id: str
    source_sha256: str
    tool_sha256: str
    command_sha256: str
    numeric_evidence_sha256: str
    outcome: str
    mismatch_count: int
    authority: str
    receipt_sha256: str


class ICPackRunResultV2(NamedTuple):
    request_sha256: str
    launch_id: str
    job_id: str
    run_id: str
    terminal_effect: str
    worker_exit_code: int | None
    worker_receipt_validation: str
    worker_receipt_validation_reason: str
    coverage: str
    idempotent_replay: bool
    stages: tuple[ICPackStageReceiptV1, ...]
    oracle_receipt: ICPackOracleReceiptV1 | None
    terminal_receipt_sha256: str | None
    authority_boundary: str


WorkerLauncher = Callable[[bytes], tuple[int, bytes, bytes]]


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ICPackError("IC Pack value is not canonical JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _SHA_CHARS for char in value)
    ):
        raise ICPackError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value[0] not in _ID_CHARS - frozenset("._-")
        or any(char not in _ID_CHARS for char in value)
    ):
        raise ICPackError(f"{label} must be a lowercase portable identifier")
    return value


def _exact_fields(value: Mapping[str, Any], fields: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != fields:
        raise ICPackError(
            f"{label} fields are invalid: missing={sorted(fields - actual)}, "
            f"unexpected={sorted(actual - fields)}"
        )


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ICPackError(f"IC Pack JSON duplicates key {key!r}")
        value[key] = item
    return value


def _parse_canonical_json(data: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if not data or len(data) > maximum:
        raise ICPackError(f"{label} size is invalid")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=lambda raw: (_ for _ in ()).throw(
                ICPackError(f"{label} contains non-finite number {raw}")
            ),
        )
    except ICPackError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ICPackError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != data:
        raise ICPackError(f"{label} must be a canonical JSON object")
    return value


def _package_bytes(relative: str) -> bytes:
    try:
        data = resources.files("aoi_orgware").joinpath(relative).read_bytes()
    except (FileNotFoundError, OSError, TypeError) as exc:
        raise ICPackError(f"packaged IC fixture is unavailable: {relative}") from exc
    if not data or len(data) > MAX_REQUEST_BYTES:
        raise ICPackError(f"packaged IC fixture size is invalid: {relative}")
    return data


def fixture_manifest_dict() -> dict[str, Any]:
    files = []
    for name in FIXTURE_FILES:
        relative = f"resources/ic_pack/tiny_vcs/{name}"
        data = _package_bytes(relative)
        files.append(
            {"path": relative, "sha256": _sha256_bytes(data), "size_bytes": len(data)}
        )
    return {"schema_version": 1, "fixture_id": FIXTURE_ID, "files": files}


def fixture_manifest_sha256() -> str:
    return _sha256_bytes(canonical_json_bytes(fixture_manifest_dict()))


def synthetic_tool_sha256() -> str:
    return _sha256_bytes(_package_bytes("ic_pack_worker.py"))


def request_to_dict(request: ICPackRequestV1) -> dict[str, Any]:
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "mode": request.mode,
        "task_id": request.task_id,
        "job_id": request.job_id,
        "run_id": request.run_id,
        "rtl_packet_id": request.rtl_packet_id,
        "dv_packet_id": request.dv_packet_id,
        "source_manifest_sha256": request.source_manifest_sha256,
        "tool_sha256": request.tool_sha256,
        "output_root": request.output_root,
    }


def request_bytes(request: ICPackRequestV1) -> bytes:
    return canonical_json_bytes(request_to_dict(request))


def canonical_command(data: bytes) -> str:
    digest = _sha256_bytes(data)
    return f"aoi-ic-pack --request request.json --request-sha256 {digest}\n"


def canonical_command_sha256(data: bytes) -> str:
    return _sha256_bytes(canonical_command(data).encode("utf-8"))


def parse_request_bytes(data: bytes) -> ICPackRequestV1:
    value = _parse_canonical_json(data, maximum=MAX_REQUEST_BYTES, label="IC Pack request")
    _exact_fields(value, _REQUEST_FIELDS, "IC Pack request")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ICPackError("IC Pack request schema_version is unsupported")
    if value["mode"] != PACK_MODE:
        raise ICPackError("IC Pack mode is unsupported")
    output_root = value["output_root"]
    if not isinstance(output_root, str) or not output_root or len(output_root) > 4096:
        raise ICPackError("IC Pack output_root must be an absolute path")
    try:
        output_root.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ICPackError("IC Pack output_root must be valid UTF-8") from exc
    if not Path(output_root).is_absolute():
        raise ICPackError("IC Pack output_root must be an absolute path")
    request = ICPackRequestV1(
        mode=PACK_MODE,
        task_id=_identifier(value["task_id"], "task_id"),
        job_id=_identifier(value["job_id"], "job_id"),
        run_id=_identifier(value["run_id"], "run_id"),
        rtl_packet_id=_identifier(value["rtl_packet_id"], "rtl_packet_id"),
        dv_packet_id=_identifier(value["dv_packet_id"], "dv_packet_id"),
        command_sha256=canonical_command_sha256(data),
        source_manifest_sha256=_sha256(
            value["source_manifest_sha256"], "source_manifest_sha256"
        ),
        tool_sha256=_sha256(value["tool_sha256"], "tool_sha256"),
        output_root=output_root,
    )
    if request.source_manifest_sha256 != fixture_manifest_sha256():
        raise ICPackError("IC Pack source manifest differs from packaged fixture")
    if request.tool_sha256 != synthetic_tool_sha256():
        raise ICPackError("IC Pack tool digest differs from packaged worker")
    return request


def oracle_receipt_dict(
    request: ICPackRequestV1, numeric_evidence_sha256: str
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "oracle_id": f"{request.run_id}-oracle",
        "job_id": request.job_id,
        "run_id": request.run_id,
        "rtl_packet_id": request.rtl_packet_id,
        "dv_packet_id": request.dv_packet_id,
        "source_sha256": request.source_manifest_sha256,
        "tool_sha256": request.tool_sha256,
        "command_sha256": request.command_sha256,
        "numeric_evidence_sha256": _sha256(
            numeric_evidence_sha256, "numeric_evidence_sha256"
        ),
        "outcome": "pass",
        "mismatch_count": 0,
        "authority": ORACLE_AUTHORITY,
    }
    return {**value, "receipt_sha256": _sha256_bytes(canonical_json_bytes(value))}


def _receipt_digest(value: Mapping[str, Any]) -> str:
    preimage = {key: item for key, item in value.items() if key != "receipt_sha256"}
    return _sha256_bytes(canonical_json_bytes(preimage))


def _stable_read(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ICPackError(f"{label} must be a non-linked regular file")
        with path.open("rb") as handle:
            data = handle.read(maximum + 1)
        after = path.lstat()
    except ICPackError:
        raise
    except OSError as exc:
        raise ICPackError(f"cannot read {label}") from exc
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if len(data) > maximum or any(getattr(before, key) != getattr(after, key) for key in identity):
        raise ICPackError(f"{label} changed during bounded read")
    return data


def _launch_receipt(request: ICPackRequestV1, request_sha256: str) -> dict[str, Any]:
    launch_id = _sha256_bytes(b"AOI-IC-PACK-LAUNCH-V1\0" + request_sha256.encode())
    value = {
        "schema_version": 1,
        "launch_id": launch_id,
        "request_sha256": request_sha256,
        "job_id": request.job_id,
        "run_id": request.run_id,
        "status": "launch_acquired",
    }
    return {**value, "receipt_sha256": _sha256_bytes(canonical_json_bytes(value))}


def _validate_launch(value: Any, expected: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ICPackError("launch receipt must be an object")
    _exact_fields(value, _LAUNCH_FIELDS, "launch receipt")
    if (
        canonical_json_bytes(value) != canonical_json_bytes(expected)
        or _receipt_digest(value) != value["receipt_sha256"]
    ):
        raise ICPackError("launch receipt differs from request identity")
    return value


def _stage_receipt(value: Any, expected_stage: str) -> ICPackStageReceiptV1:
    if not isinstance(value, dict):
        raise ICPackError("worker stage receipt must be an object")
    _exact_fields(value, _STAGE_FIELDS, "worker stage receipt")
    if (
        value["stage"] != expected_stage
        or value["status"] != "pass"
        or value["evidence_classification"] != _CLASSIFICATIONS[expected_stage]
    ):
        raise ICPackError("worker stage receipt overstates or differs from synthetic truth")
    return ICPackStageReceiptV1(
        stage=expected_stage,
        status="pass",
        evidence_sha256=_sha256(value["evidence_sha256"], "stage evidence_sha256"),
        evidence_classification=value["evidence_classification"],
    )


def _oracle_receipt(
    value: Any, request: ICPackRequestV1, numeric_evidence_sha256: str
) -> ICPackOracleReceiptV1:
    if not isinstance(value, dict):
        raise ICPackError("worker oracle receipt must be an object")
    _exact_fields(value, _ORACLE_FIELDS, "worker oracle receipt")
    expected = oracle_receipt_dict(request, numeric_evidence_sha256)
    if (
        canonical_json_bytes(value) != canonical_json_bytes(expected)
        or _receipt_digest(value) != value["receipt_sha256"]
    ):
        raise ICPackError("worker oracle receipt differs from request and numeric evidence")
    return ICPackOracleReceiptV1(
        oracle_id=value["oracle_id"],
        job_id=value["job_id"],
        run_id=value["run_id"],
        rtl_packet_id=value["rtl_packet_id"],
        dv_packet_id=value["dv_packet_id"],
        source_sha256=value["source_sha256"],
        tool_sha256=value["tool_sha256"],
        command_sha256=value["command_sha256"],
        numeric_evidence_sha256=value["numeric_evidence_sha256"],
        outcome="pass",
        mismatch_count=0,
        authority=ORACLE_AUTHORITY,
        receipt_sha256=value["receipt_sha256"],
    )


def _validate_worker(
    value: Any, request: ICPackRequestV1
) -> tuple[tuple[ICPackStageReceiptV1, ...], ICPackOracleReceiptV1]:
    if not isinstance(value, dict):
        raise ICPackError("worker receipt must be an object")
    _exact_fields(value, _WORKER_FIELDS, "worker receipt")
    from .ic_pack_worker import derive_worker_receipt

    expected_receipt = derive_worker_receipt(request)
    if canonical_json_bytes(value) != canonical_json_bytes(expected_receipt):
        raise ICPackError("worker receipt differs from deterministic packaged fixture")
    expected_identity = {
        "schema_version": 1,
        "mode": request.mode,
        "task_id": request.task_id,
        "job_id": request.job_id,
        "run_id": request.run_id,
        "rtl_packet_id": request.rtl_packet_id,
        "dv_packet_id": request.dv_packet_id,
        "command_sha256": request.command_sha256,
        "source_manifest_sha256": request.source_manifest_sha256,
        "tool_sha256": request.tool_sha256,
        "authority_boundary": AUTHORITY_BOUNDARY,
    }
    if any(value[key] != item for key, item in expected_identity.items()):
        raise ICPackError("worker receipt identity differs from request")
    stages_value = value["stages"]
    if not isinstance(stages_value, list) or len(stages_value) != len(_STAGES):
        raise ICPackError("worker receipt stage inventory is incomplete")
    stages = tuple(
        _stage_receipt(item, stage) for item, stage in zip(stages_value, _STAGES, strict=True)
    )
    oracle = _oracle_receipt(value["oracle_receipt"], request, stages[-1].evidence_sha256)
    if _sha256(value["receipt_sha256"], "worker receipt digest") != _receipt_digest(value):
        raise ICPackError("worker receipt digest differs")
    return stages, oracle


def _validate_terminal(
    value: Any, launch: Mapping[str, Any], request: ICPackRequestV1
) -> tuple[dict[str, Any], tuple[ICPackStageReceiptV1, ...], ICPackOracleReceiptV1 | None]:
    try:
        validation = validate_terminal_receipt(
            value,
            launch_id=cast(str, launch["launch_id"]),
            request_sha256=cast(str, launch["request_sha256"]),
        )
    except ICPackTerminalError as exc:
        raise ICPackError(str(exc)) from exc
    terminal = cast(dict[str, Any], value)
    if validation == "accepted":
        stages, oracle = _validate_worker(terminal["worker_receipt"], request)
    else:
        stages, oracle = (), None
    return terminal, stages, oracle


def _result(
    request: ICPackRequestV1,
    request_sha256: str,
    launch: Mapping[str, Any],
    *,
    effect: str,
    replay: bool,
    stages: tuple[ICPackStageReceiptV1, ...] = (),
    oracle: ICPackOracleReceiptV1 | None = None,
    terminal_sha256: str | None = None,
    worker_exit_code: int | None = None,
    validation: str = "not_attempted",
    validation_reason: str = "terminal_unavailable",
) -> ICPackRunResultV2:
    return ICPackRunResultV2(
        request_sha256=request_sha256,
        launch_id=cast(str, launch["launch_id"]),
        job_id=request.job_id,
        run_id=request.run_id,
        terminal_effect=effect,
        worker_exit_code=worker_exit_code,
        worker_receipt_validation=validation,
        worker_receipt_validation_reason=validation_reason,
        coverage="synthetic_complete" if effect == "completed" else "degraded",
        idempotent_replay=replay,
        stages=stages,
        oracle_receipt=oracle,
        terminal_receipt_sha256=terminal_sha256,
        authority_boundary=AUTHORITY_BOUNDARY,
    )


def _default_launcher(data: bytes) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "aoi_orgware.ic_pack_worker"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=WORKER_TIMEOUT_SECONDS,
    )
    return completed.returncode, completed.stdout, completed.stderr


def execute_request(
    request: ICPackRequestV1,
    request_sha256: str,
    *,
    launcher: WorkerLauncher | None = None,
) -> ICPackRunResultV2:
    """Acquire at most one launch and return deterministic terminal/unknown truth."""

    data = request_bytes(request)
    if parse_request_bytes(data) != request:
        raise ICPackError("request object differs from canonical validated request")
    if _sha256(request_sha256, "request_sha256") != _sha256_bytes(data):
        raise ICPackError("request digest differs from canonical request")
    if request.command_sha256 != canonical_command_sha256(data):
        raise ICPackError("request command identity differs from canonical IC Pack command")
    try:
        root = h.canonicalize_no_link_traversal(Path(request.output_root), "IC Pack output root")
        if root.exists():
            h.validate_existing_regular_directory(root, "IC Pack output root")
        else:
            root.mkdir(parents=False, exist_ok=False)
        root = h.canonicalize_no_link_traversal(root, "IC Pack output root")
    except (h.HarnessError, OSError) as exc:
        raise ICPackError(f"IC Pack output root is unavailable: {exc}") from exc
    allowed = {"launch-receipt.json", "terminal-receipt.json"}
    try:
        names = {item.name for item in root.iterdir()}
    except OSError as exc:
        raise ICPackError("cannot inventory IC Pack output root") from exc
    if not names <= allowed:
        raise ICPackError("IC Pack output root contains unowned files")
    launch_path = root / "launch-receipt.json"
    terminal_path = root / "terminal-receipt.json"
    expected_launch = _launch_receipt(request, request_sha256)
    created = False
    if launch_path.exists():
        launch = _validate_launch(
            _parse_canonical_json(
                _stable_read(launch_path, maximum=MAX_RECEIPT_BYTES, label="launch receipt"),
                maximum=MAX_RECEIPT_BYTES,
                label="launch receipt",
            ),
            expected_launch,
        )
    else:
        try:
            h.atomic_create_bytes(launch_path, canonical_json_bytes(expected_launch))
            created = True
            launch = expected_launch
        except h.HarnessError:
            launch = _validate_launch(
                _parse_canonical_json(
                    _stable_read(launch_path, maximum=MAX_RECEIPT_BYTES, label="launch receipt"),
                    maximum=MAX_RECEIPT_BYTES,
                    label="launch receipt",
                ),
                expected_launch,
            )
    if terminal_path.exists():
        terminal, stages, oracle = _validate_terminal(
            _parse_canonical_json(
                _stable_read(terminal_path, maximum=MAX_RECEIPT_BYTES, label="terminal receipt"),
                maximum=MAX_RECEIPT_BYTES,
                label="terminal receipt",
            ),
            launch,
            request,
        )
        return _result(
            request,
            request_sha256,
            launch,
            effect=terminal["terminal_effect"],
            replay=True,
            stages=stages,
            oracle=oracle,
            terminal_sha256=terminal["receipt_sha256"],
            worker_exit_code=terminal["worker_exit_code"],
            validation=terminal["worker_receipt_validation"],
            validation_reason=terminal["worker_receipt_validation_reason"],
        )
    if not created:
        return _result(
            request, request_sha256, launch, effect="effect_unknown", replay=True
        )
    try:
        returncode, stdout, stderr = (launcher or _default_launcher)(data)
        if (
            isinstance(returncode, bool)
            or not isinstance(returncode, int)
            or not isinstance(stdout, bytes)
            or not isinstance(stderr, bytes)
            or len(stdout) > MAX_RECEIPT_BYTES
            or len(stderr) > MAX_RECEIPT_BYTES
        ):
            raise ICPackError("IC Pack worker result is invalid or oversized")
    except Exception:
        return _result(
            request, request_sha256, launch, effect="effect_unknown", replay=False
        )
    worker_value: dict[str, Any] | None = None
    validation, validation_reason = "not_attempted", "worker_exit_nonzero"
    if returncode == 0:
        try:
            worker_value = _parse_canonical_json(
                stdout, maximum=MAX_RECEIPT_BYTES, label="worker receipt"
            )
            stages, oracle = _validate_worker(worker_value, request)
            validation, validation_reason = "accepted", "accepted"
        except ICPackError:
            worker_value, stages, oracle = None, (), None
            validation, validation_reason = "rejected", "invalid_worker_receipt"
    else:
        stages, oracle = (), None
    terminal = build_terminal_receipt(
        launch_id=cast(str, launch["launch_id"]),
        request_sha256=cast(str, launch["request_sha256"]),
        worker_exit_code=returncode,
        stdout=stdout,
        stderr=stderr,
        validation=validation,
        validation_reason=validation_reason,
        worker_receipt=worker_value,
    )
    try:
        h.atomic_create_bytes(terminal_path, canonical_json_bytes(terminal))
    except h.HarnessError:
        return _result(
            request, request_sha256, launch, effect="effect_unknown", replay=False
        )
    return _result(
        request,
        request_sha256,
        launch,
        effect=terminal["terminal_effect"],
        replay=False,
        stages=stages,
        oracle=oracle,
        terminal_sha256=terminal["receipt_sha256"],
        worker_exit_code=terminal["worker_exit_code"],
        validation=terminal["worker_receipt_validation"],
        validation_reason=terminal["worker_receipt_validation_reason"],
    )


def stage_to_dict(value: ICPackStageReceiptV1) -> dict[str, Any]:
    return {
        "stage": value.stage,
        "status": value.status,
        "evidence_sha256": value.evidence_sha256,
        "evidence_classification": value.evidence_classification,
    }


def oracle_to_dict(value: ICPackOracleReceiptV1) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "oracle_id": value.oracle_id,
        "job_id": value.job_id,
        "run_id": value.run_id,
        "rtl_packet_id": value.rtl_packet_id,
        "dv_packet_id": value.dv_packet_id,
        "source_sha256": value.source_sha256,
        "tool_sha256": value.tool_sha256,
        "command_sha256": value.command_sha256,
        "numeric_evidence_sha256": value.numeric_evidence_sha256,
        "outcome": value.outcome,
        "mismatch_count": value.mismatch_count,
        "authority": value.authority,
        "receipt_sha256": value.receipt_sha256,
    }


def result_to_dict(value: ICPackRunResultV2) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "request_sha256": value.request_sha256,
        "launch_id": value.launch_id,
        "job_id": value.job_id,
        "run_id": value.run_id,
        "terminal_effect": value.terminal_effect,
        "worker_exit_code": value.worker_exit_code,
        "worker_receipt_validation": value.worker_receipt_validation,
        "worker_receipt_validation_reason": value.worker_receipt_validation_reason,
        "coverage": value.coverage,
        "idempotent_replay": value.idempotent_replay,
        "stages": [stage_to_dict(item) for item in value.stages],
        "oracle_receipt": (
            None if value.oracle_receipt is None else oracle_to_dict(value.oracle_receipt)
        ),
        "terminal_receipt_sha256": value.terminal_receipt_sha256,
        "authority_boundary": value.authority_boundary,
    }


__all__ = [
    "AUTHORITY_BOUNDARY",
    "ICPackError",
    "ICPackOracleReceiptV1",
    "ICPackRequestV1",
    "ICPackRunResultV2",
    "ICPackStageReceiptV1",
    "PACK_MODE",
    "canonical_command",
    "canonical_command_sha256",
    "canonical_json_bytes",
    "execute_request",
    "fixture_manifest_dict",
    "fixture_manifest_sha256",
    "oracle_receipt_dict",
    "oracle_to_dict",
    "parse_request_bytes",
    "request_bytes",
    "request_to_dict",
    "result_to_dict",
    "stage_to_dict",
    "synthetic_tool_sha256",
]
