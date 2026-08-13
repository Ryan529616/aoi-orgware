#!/usr/bin/env python3
"""CLI boundary tests for project-first IC RAG."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli, ic_rag  # noqa: E402
from aoi_orgware.commands.ic_rag import (  # noqa: E402
    cmd_ic_rag_query,
    register_ic_rag_commands,
)
from aoi_orgware.harnesslib import HarnessError  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes  # noqa: E402


def one_document() -> ic_rag.ICRagDocumentV1:
    text = "ARISE dense K owner and VCS runtime boundary."
    data = text.encode("utf-8")
    return ic_rag.ICRagDocumentV1(
        source_id="arise-project-graph",
        source_kind="project_graph",
        authority="project_design_intent",
        source_generation_sha256=hashlib.sha256(b"graph-generation").hexdigest(),
        freshness="fresh",
        freshness_checked_at="2026-08-11T00:00:00Z",
        freshness_evidence_sha256=hashlib.sha256(b"freshness").hexdigest(),
        document_id="dense-k-owner",
        locator="architecture/dense-k.md",
        content_sha256=hashlib.sha256(data).hexdigest(),
        content_size_bytes=len(data),
        text=text,
    )


def command_args(path: Path, digest: str, *, as_json: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        manifest=str(path),
        manifest_sha256=digest,
        query="dense K runtime",
        phase="planning",
        audience="rtl",
        max_hits=6,
        max_hits_per_kind=2,
        max_excerpt_bytes=768,
        json=as_json,
    )


class ICRagCommandTests(unittest.TestCase):
    def write_manifest(self, root: Path) -> tuple[Path, bytes]:
        data = canonical_json_bytes(
            ic_rag.document_manifest_dict((one_document(),)),
            max_bytes=ic_rag.MAX_MANIFEST_BYTES,
        )
        path = root / "ic-rag-manifest.json"
        path.write_bytes(data)
        return path, data

    def test_json_command_output_binds_manifest_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path, data = self.write_manifest(Path(raw))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = cmd_ic_rag_query(
                    command_args(path, hashlib.sha256(data).hexdigest()), None
                )
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["manifest_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(payload["receipt"]["hits"][0]["source_kind"], "project_graph")
        self.assertEqual(payload["receipt"]["technical_verdict_authority"], "none")

    def test_text_output_does_not_claim_engineering_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path, data = self.write_manifest(Path(raw))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                cmd_ic_rag_query(
                    command_args(path, hashlib.sha256(data).hexdigest(), as_json=False),
                    None,
                )
        self.assertIn("result_quality: bounded_lexical_candidate", output.getvalue())
        self.assertIn("technical_verdict_authority: none", output.getvalue())

    def test_manifest_hash_mismatch_fails_before_parse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path, _data = self.write_manifest(Path(raw))
            with self.assertRaisesRegex(HarnessError, "SHA-256 mismatch"):
                cmd_ic_rag_query(command_args(path, "0" * 64), None)

    def test_noncanonical_manifest_is_typed_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "manifest.json"
            path.write_text(
                json.dumps(ic_rag.document_manifest_dict((one_document(),)), indent=2),
                encoding="utf-8",
            )
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(HarnessError, "not canonical"):
                cmd_ic_rag_query(command_args(path, digest), None)

    def test_parser_registers_exact_read_only_command(self) -> None:
        parser = cli.build_parser(
            {"session_id": None, "epoch": None, "token": None, "credential_file": None}
        )
        args = parser.parse_args(
            [
                "ic-rag-query",
                "--manifest",
                "manifest.json",
                "--manifest-sha256",
                "a" * 64,
                "--query",
                "dense K",
                "--phase",
                "independent_review",
                "--audience",
                "dv",
                "--json",
            ]
        )
        self.assertEqual(args._aoi_command, "ic-rag-query")
        self.assertIs(args.handler, cmd_ic_rag_query)
        self.assertEqual(args.phase, "independent_review")
        self.assertEqual(args.audience, "dv")
        self.assertIn("ic-rag-query", cli.CHIEF_PROJECT_READ_ONLY_COMMANDS)
        self.assertFalse(cli.command_requires_chief("ic-rag-query", initialized=True))

    def test_registrar_rejects_missing_or_extra_handler(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()

        def add_json(target: argparse.ArgumentParser) -> None:
            target.add_argument("--json", action="store_true")

        with self.assertRaisesRegex(ValueError, "missing"):
            register_ic_rag_commands(sub, handlers={}, add_json_argument=add_json)
        with self.assertRaisesRegex(ValueError, "unexpected"):
            register_ic_rag_commands(
                sub,
                handlers={"ic_rag_query": cmd_ic_rag_query, "extra": cmd_ic_rag_query},
                add_json_argument=add_json,
            )


if __name__ == "__main__":
    unittest.main()
