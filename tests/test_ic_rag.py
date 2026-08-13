#!/usr/bin/env python3
"""Adversarial tests for deterministic project-first IC RAG."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import ic_rag  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes  # noqa: E402


def document(
    *,
    source_id: str,
    source_kind: str,
    document_id: str,
    locator: str,
    text: str,
    freshness: str = "fresh",
    generation: str | None = None,
) -> ic_rag.ICRagDocumentV1:
    data = text.encode("utf-8")
    return ic_rag.ICRagDocumentV1(
        source_id=source_id,
        source_kind=source_kind,
        authority=ic_rag.SOURCE_AUTHORITY[source_kind],
        source_generation_sha256=generation or hashlib.sha256(source_id.encode()).hexdigest(),
        freshness=freshness,
        freshness_checked_at="2026-08-11T00:00:00+00:00",
        freshness_evidence_sha256=hashlib.sha256(
            (source_id + ":freshness").encode()
        ).hexdigest(),
        document_id=document_id,
        locator=locator,
        content_sha256=hashlib.sha256(data).hexdigest(),
        content_size_bytes=len(data),
        text=text,
    )


def fixture_documents() -> tuple[ic_rag.ICRagDocumentV1, ...]:
    return (
        document(
            source_id="eda-vcs-runbook",
            source_kind="eda_runbook",
            document_id="vcs-stages",
            locator="vcs/stages.md",
            text="VCS compile and elaboration are separate from runtime and numeric checks.",
        ),
        document(
            source_id="digital-ic-kb",
            source_kind="ic_knowledge_base",
            document_id="handshake",
            locator="rtl/ready-valid.md",
            text="Ready valid handshakes require stable payload under backpressure.",
        ),
        document(
            source_id="arise-project-graph",
            source_kind="project_graph",
            document_id="dense-k-owner",
            locator="architecture/dense-k.md",
            text="Dense K demand is owned by arise_vit_model_top and feeds QKV chunk1.",
        ),
        document(
            source_id="arise-project-graph",
            source_kind="project_graph",
            document_id="qkv-dataflow",
            locator="architecture/qkv.md",
            text="QKV chunk1 follows the project graph dataflow and explicit owner edges.",
        ),
    )


class ICRagTests(unittest.TestCase):
    def derive(self, documents: tuple[ic_rag.ICRagDocumentV1, ...] | None = None):
        return ic_rag.derive_ic_rag_context(
            query="QKV chunk1 runtime",
            phase="planning",
            audience="rtl",
            documents=documents or fixture_documents(),
        )

    def test_project_first_order_and_truth_boundary(self) -> None:
        receipt = self.derive()
        self.assertEqual(
            [hit.source_kind for hit in receipt.hits],
            ["project_graph", "eda_runbook", "project_graph"],
        )
        self.assertEqual(receipt.result_quality, "bounded_lexical_candidate")
        self.assertEqual(receipt.technical_verdict_authority, "none")
        self.assertEqual(
            receipt.project_fact_precedence,
            "repository_source_and_runtime_receipts",
        )
        self.assertFalse(receipt.close_qualifying)

    def test_every_hit_retains_source_digest_freshness_and_authority(self) -> None:
        receipt = self.derive()
        for hit in receipt.hits:
            self.assertRegex(hit.content_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(hit.source_generation_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(hit.freshness_evidence_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(hit.authority, ic_rag.SOURCE_AUTHORITY[hit.source_kind])
            self.assertIn(hit.freshness, ic_rag.FRESHNESS_VALUES)

    def test_input_permutation_is_byte_identical(self) -> None:
        values = fixture_documents()
        first = self.derive(values)
        second = self.derive(tuple(reversed(values)))
        self.assertEqual(first, second)
        self.assertEqual(
            canonical_json_bytes(ic_rag.receipt_to_dict(first)),
            canonical_json_bytes(ic_rag.receipt_to_dict(second)),
        )

    def test_exact_duplicate_identity_rejects(self) -> None:
        values = fixture_documents()
        with self.assertRaisesRegex(ic_rag.ICRagError, "identity is duplicated"):
            self.derive(values + (values[-1],))

    def test_source_evidence_disagreement_rejects(self) -> None:
        values = list(fixture_documents())
        values[-1] = values[-1]._replace(freshness="stale")
        with self.assertRaisesRegex(ic_rag.ICRagError, "disagree on source evidence"):
            self.derive(tuple(values))

    def test_project_graph_is_required(self) -> None:
        values = tuple(
            item for item in fixture_documents() if item.source_kind != "project_graph"
        )
        with self.assertRaisesRegex(ic_rag.ICRagError, "requires at least one"):
            self.derive(values)

    def test_fixed_authority_cannot_be_promoted(self) -> None:
        values = list(fixture_documents())
        values[-1] = values[-1]._replace(authority="runtime_truth")
        with self.assertRaisesRegex(ic_rag.ICRagError, "fixed source authority"):
            self.derive(tuple(values))

    def test_stale_and_unknown_are_preserved_not_hidden(self) -> None:
        graph = document(
            source_id="arise-project-graph",
            source_kind="project_graph",
            document_id="dense-k",
            locator="architecture/dense-k.md",
            text="dense K owner",
            freshness="stale",
        )
        kb = document(
            source_id="digital-ic-kb",
            source_kind="ic_knowledge_base",
            document_id="dense-k",
            locator="concepts/dense-k.md",
            text="dense K reference",
            freshness="unknown",
        )
        receipt = ic_rag.derive_ic_rag_context(
            query="dense K",
            phase="independent_review",
            audience="dv",
            documents=(kb, graph),
        )
        self.assertEqual([hit.freshness for hit in receipt.hits], ["stale", "unknown"])
        self.assertEqual(receipt.phase, "independent_review")
        self.assertEqual(receipt.audience, "dv")

    def test_missing_supplemental_sources_are_explicit(self) -> None:
        graph = fixture_documents()[-1]
        receipt = self.derive((graph,))
        self.assertEqual(
            receipt.missing_source_kinds,
            ("ic_knowledge_base", "eda_runbook"),
        )

    def test_unmatched_terms_and_empty_hits_are_explicit(self) -> None:
        receipt = ic_rag.derive_ic_rag_context(
            query="nonexistent-token",
            phase="planning",
            audience="chief",
            documents=fixture_documents(),
        )
        self.assertEqual(receipt.hits, ())
        self.assertEqual(receipt.unmatched_query_terms, ("nonexistent-token",))

    def test_max_hits_per_kind_keeps_supplemental_context_bounded(self) -> None:
        receipt = ic_rag.derive_ic_rag_context(
            query="QKV chunk1 runtime",
            phase="planning",
            audience="rtl",
            documents=fixture_documents(),
            max_hits=3,
            max_hits_per_kind=1,
        )
        self.assertEqual(
            [hit.source_kind for hit in receipt.hits],
            ["project_graph", "eda_runbook"],
        )

    def test_matching_supplemental_source_is_not_starved_by_project_hits(self) -> None:
        values = fixture_documents() + (
            document(
                source_id="digital-ic-kb",
                source_kind="ic_knowledge_base",
                document_id="qkv-runtime",
                locator="rtl/qkv-runtime.md",
                text="QKV chunk1 runtime reference.",
            ),
        )
        receipt = ic_rag.derive_ic_rag_context(
            query="QKV chunk1 runtime",
            phase="planning",
            audience="rtl",
            documents=values,
            max_hits=2,
            max_hits_per_kind=2,
        )
        self.assertEqual(
            [hit.source_kind for hit in receipt.hits],
            ["project_graph", "ic_knowledge_base"],
        )

    def test_bool_is_not_an_integer_limit(self) -> None:
        with self.assertRaisesRegex(ic_rag.ICRagError, "exact integer"):
            ic_rag.derive_ic_rag_context(
                query="QKV",
                phase="planning",
                audience="rtl",
                documents=fixture_documents(),
                max_hits=True,
            )

    def test_public_values_are_deeply_immutable(self) -> None:
        receipt = self.derive()
        self.assertFalse(hasattr(receipt, "__dict__"))
        self.assertFalse(hasattr(receipt.hits[0], "__dict__"))
        with self.assertRaises(AttributeError):
            receipt.hits[0].freshness = "fresh"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            receipt.hits[0].matched_terms[0] = "forged"  # type: ignore[index]

    def test_receipt_rederivation_rejects_semantic_forgery(self) -> None:
        receipt = self.derive()
        forged = receipt._replace(technical_verdict_authority="authoritative")
        with self.assertRaisesRegex(ic_rag.ICRagError, "differs"):
            ic_rag.validate_ic_rag_receipt(forged, documents=fixture_documents())

    def test_receipt_rederivation_accepts_exact_witness(self) -> None:
        receipt = self.derive()
        self.assertIs(
            ic_rag.validate_ic_rag_receipt(receipt, documents=fixture_documents()),
            receipt,
        )

    def test_manifest_canonical_roundtrip(self) -> None:
        payload = ic_rag.document_manifest_dict(fixture_documents())
        data = canonical_json_bytes(payload, max_bytes=ic_rag.MAX_MANIFEST_BYTES)
        parsed = ic_rag.parse_document_manifest_bytes(data)
        self.assertEqual(parsed, ic_rag.validate_documents(fixture_documents()))

    def test_manifest_rejects_duplicate_key_and_alternate_serialization(self) -> None:
        with self.assertRaisesRegex(ic_rag.ICRagError, "duplicate key"):
            ic_rag.parse_document_manifest_bytes(
                b'{"schema_version":1,"schema_version":1,"documents":[]}'
            )
        payload = ic_rag.document_manifest_dict(fixture_documents())
        noncanonical = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        with self.assertRaisesRegex(ic_rag.ICRagError, "not canonical"):
            ic_rag.parse_document_manifest_bytes(noncanonical)

    def test_manifest_rejects_deep_json_with_typed_error(self) -> None:
        data = b'{"documents":' + (b"[" * 1100) + b"0" + (b"]" * 1100)
        data += b',"schema_version":1}'
        with self.assertRaises(ic_rag.ICRagError):
            ic_rag.parse_document_manifest_bytes(data)

    def test_manifest_rejects_oversized_integer_with_typed_error(self) -> None:
        data = b'{"documents":[],"schema_version":' + (b"9" * 5000) + b"}"
        with self.assertRaises(ic_rag.ICRagError):
            ic_rag.parse_document_manifest_bytes(data)

    def test_unicode_equivalent_query_matches_and_surrogate_is_typed(self) -> None:
        value = document(
            source_id="arise-project-graph",
            source_kind="project_graph",
            document_id="unicode-term",
            locator="architecture/unicode.md",
            text="The cafe\u0301 dataflow is project-owned.",
        )
        receipt = ic_rag.derive_ic_rag_context(
            query="caf\u00e9",
            phase="planning",
            audience="rtl",
            documents=(value,),
        )
        self.assertEqual(len(receipt.hits), 1)
        with self.assertRaisesRegex(ic_rag.ICRagError, "valid UTF-8"):
            ic_rag.derive_ic_rag_context(
                query="dense \ud800 K",
                phase="planning",
                audience="rtl",
                documents=(value,),
            )

    def test_content_hash_size_and_locator_are_exact(self) -> None:
        value = fixture_documents()[-1]
        with self.assertRaisesRegex(ic_rag.ICRagError, "differs from UTF-8 bytes"):
            self.derive((value._replace(content_size_bytes=value.content_size_bytes + 1),))
        with self.assertRaisesRegex(ic_rag.ICRagError, "differs from text bytes"):
            self.derive((value._replace(content_sha256="0" * 64),))
        with self.assertRaisesRegex(ic_rag.ICRagError, "portable relative POSIX"):
            self.derive((value._replace(locator="C:\\secret\\graph.md"),))


if __name__ == "__main__":
    unittest.main()
