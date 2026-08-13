"""Package-owned deterministic worker for the synthetic IC Pack fixture."""

from __future__ import annotations

import hashlib
import sys
from importlib import resources
from typing import Any

from .ic_pack import (
    AUTHORITY_BOUNDARY,
    ICPackError,
    ICPackRequestV1,
    MAX_REQUEST_BYTES,
    canonical_json_bytes,
    fixture_manifest_dict,
    oracle_receipt_dict,
    parse_request_bytes,
    request_to_dict,
)


_CLASSIFICATIONS = {
    "preflight": "synthetic_fixture_inventory_check",
    "compile": "synthetic_source_contract_not_vcs_compile",
    "elaboration": "synthetic_hierarchy_contract_not_vcs_elaboration",
    "runtime": "synthetic_python_model_not_hdl_runtime",
    "numeric": "synthetic_exact_oracle_not_arise_numeric",
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fixture(name: str) -> bytes:
    try:
        return resources.files("aoi_orgware").joinpath(
            "resources", "ic_pack", "tiny_vcs", name
        ).read_bytes()
    except (FileNotFoundError, OSError, TypeError) as exc:
        raise ICPackError(f"packaged synthetic fixture is missing: {name}") from exc


def _stage(stage: str, evidence: dict[str, Any]) -> dict[str, Any]:
    preimage = {
        "schema_version": 1,
        "stage": stage,
        "status": "pass",
        "evidence_classification": _CLASSIFICATIONS[stage],
        "evidence": evidence,
    }
    return {
        "stage": stage,
        "status": "pass",
        "evidence_sha256": _sha256(canonical_json_bytes(preimage)),
        "evidence_classification": _CLASSIFICATIONS[stage],
    }


def derive_worker_receipt(request: ICPackRequestV1) -> dict[str, Any]:
    """Derive five distinct synthetic axes without invoking VCS or HDL runtime."""

    if parse_request_bytes(canonical_json_bytes(request_to_dict(request))) != request:
        raise ICPackError("worker request object is not canonical and validated")
    top = _fixture("tiny_top.sv")
    testbench = _fixture("tiny_tb.sv")
    if b"module tiny_top" not in top or b"assign y" not in top:
        raise ICPackError("synthetic top contract is malformed")
    if b"module tiny_tb" not in testbench or b"tiny_top dut" not in testbench:
        raise ICPackError("synthetic hierarchy contract is malformed")
    left, right, expected = 7, 11, 18
    actual = (left + right) & 0x1FF
    stages = [
        _stage(
            "preflight",
            {
                "fixture_manifest": fixture_manifest_dict(),
                "source_manifest_sha256": request.source_manifest_sha256,
            },
        ),
        _stage(
            "compile",
            {
                "top_sha256": _sha256(top),
                "testbench_sha256": _sha256(testbench),
                "check": "package_bytes_and_required_tokens_only",
            },
        ),
        _stage(
            "elaboration",
            {
                "top_module": "tiny_top",
                "testbench_module": "tiny_tb",
                "instance": "dut",
                "check": "static_token_relationship_only",
            },
        ),
        _stage(
            "runtime",
            {
                "model": "python_unsigned_8bit_add_to_9bit",
                "left": left,
                "right": right,
                "actual": actual,
                "check": "not_hdl_runtime",
            },
        ),
        _stage(
            "numeric",
            {
                "expected": expected,
                "actual": actual,
                "mismatch_count": int(actual != expected),
                "check": "synthetic_exact_oracle",
            },
        ),
    ]
    if actual != expected:
        raise ICPackError("synthetic numeric fixture unexpectedly diverged")
    oracle = oracle_receipt_dict(request, stages[-1]["evidence_sha256"])
    value = {
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
        "stages": stages,
        "oracle_receipt": oracle,
        "authority_boundary": AUTHORITY_BOUNDARY,
    }
    return {**value, "receipt_sha256": _sha256(canonical_json_bytes(value))}


def main() -> int:
    try:
        data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        request = parse_request_bytes(data)
        sys.stdout.buffer.write(canonical_json_bytes(derive_worker_receipt(request)))
        sys.stdout.buffer.flush()
        return 0
    except ICPackError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["derive_worker_receipt", "main"]
