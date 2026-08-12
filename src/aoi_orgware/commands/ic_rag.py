"""Read-only IC RAG query command registration and execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from ..evidence_artifacts import COMMAND_ARTIFACT_MAX_BYTES, read_regular_artifact
from ..harnesslib import HarnessError
from ..ic_rag import (
    AUDIENCE_VALUES,
    PHASE_VALUES,
    ICRagError,
    derive_ic_rag_context,
    parse_document_manifest_bytes,
    receipt_to_dict,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"ic_rag_query"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    receipt = payload["receipt"]
    print(f"receipt_sha256: {receipt['receipt_sha256']}")
    print(f"result_quality: {receipt['result_quality']}")
    print(f"technical_verdict_authority: {receipt['technical_verdict_authority']}")
    print(f"hit_count: {len(receipt['hits'])}")


def cmd_ic_rag_query(args: argparse.Namespace, _paths: Any) -> int:
    expected_sha = str(args.manifest_sha256).strip().lower()
    if not _SHA256_RE.fullmatch(expected_sha):
        raise HarnessError("IC RAG manifest SHA-256 must be full lowercase hex")
    _source, data = read_regular_artifact(
        args.manifest,
        "IC RAG document manifest",
        max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
        require_utf8=True,
    )
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        raise HarnessError(
            f"IC RAG manifest SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
        )
    try:
        documents = parse_document_manifest_bytes(data)
        receipt = derive_ic_rag_context(
            query=args.query,
            phase=args.phase,
            audience=args.audience,
            documents=documents,
            max_hits=args.max_hits,
            max_hits_per_kind=args.max_hits_per_kind,
            max_excerpt_bytes=args.max_excerpt_bytes,
        )
    except ICRagError as exc:
        raise HarnessError(str(exc)) from exc
    _emit(
        {
            "manifest_sha256": actual_sha,
            "receipt": receipt_to_dict(receipt),
        },
        bool(args.json),
    )
    return 0


def register_ic_rag_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the read-only project-first IC RAG command family."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "IC RAG command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )
    parser = subparsers.add_parser(
        "ic-rag-query",
        help="derive bounded project-first IC engineering context",
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--phase", choices=sorted(PHASE_VALUES), required=True)
    parser.add_argument("--audience", choices=sorted(AUDIENCE_VALUES), required=True)
    parser.add_argument("--max-hits", type=int, default=6)
    parser.add_argument("--max-hits-per-kind", type=int, default=2)
    parser.add_argument("--max-excerpt-bytes", type=int, default=768)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["ic_rag_query"])


__all__ = ["cmd_ic_rag_query", "register_ic_rag_commands"]
