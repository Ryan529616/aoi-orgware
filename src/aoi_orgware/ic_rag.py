"""Deterministic project-first context retrieval for IC engineering work.

The module deliberately consumes caller-selected canonical document records.
It does not crawl a repository, open a provider, or grant engineering
authority.  Retrieval results are bounded navigation candidates whose source,
content, generation, freshness, and authority declarations remain visible.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any, NamedTuple

from .semantic_events import SemanticEventError, canonical_json_bytes


MANIFEST_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_DOCUMENTS = 256
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_QUERY_CHARACTERS = 512
MAX_HITS = 12
MAX_HITS_PER_KIND = 4
MIN_EXCERPT_BYTES = 64
MAX_EXCERPT_BYTES = 4096

SOURCE_ORDER = ("project_graph", "ic_knowledge_base", "eda_runbook")
SOURCE_AUTHORITY = {
    "project_graph": "project_design_intent",
    "ic_knowledge_base": "reviewed_reference",
    "eda_runbook": "operational_guidance",
}
FRESHNESS_VALUES = frozenset({"fresh", "stale", "unknown"})
PHASE_VALUES = frozenset({"planning", "independent_review"})
AUDIENCE_VALUES = frozenset({"chief", "rtl", "dv", "pd"})

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TOKEN_RE = re.compile(r"[^\W_]+(?:[_./:$-][^\W_]+)*|[_a-zA-Z][\w.$:/-]*", re.UNICODE)


class ICRagError(ValueError):
    """Typed fail-closed boundary for IC RAG inputs and receipts."""


class ICRagDocumentV1(NamedTuple):
    source_id: str
    source_kind: str
    authority: str
    source_generation_sha256: str
    freshness: str
    freshness_checked_at: str
    freshness_evidence_sha256: str
    document_id: str
    locator: str
    content_sha256: str
    content_size_bytes: int
    text: str


class ICRagHitV1(NamedTuple):
    rank: int
    source_id: str
    source_kind: str
    authority: str
    source_generation_sha256: str
    freshness: str
    freshness_checked_at: str
    freshness_evidence_sha256: str
    document_id: str
    locator: str
    content_sha256: str
    content_size_bytes: int
    matched_terms: tuple[str, ...]
    excerpt: str


class ICRagReceiptV1(NamedTuple):
    schema_version: int
    retrieval_method: str
    phase: str
    audience: str
    query: str
    query_sha256: str
    document_set_sha256: str
    source_order: tuple[str, ...]
    present_source_kinds: tuple[str, ...]
    missing_source_kinds: tuple[str, ...]
    unmatched_query_terms: tuple[str, ...]
    max_hits: int
    max_hits_per_kind: int
    max_excerpt_bytes: int
    result_quality: str
    technical_verdict_authority: str
    project_fact_precedence: str
    close_qualifying: bool
    hits: tuple[ICRagHitV1, ...]
    receipt_sha256: str


class _DuplicateKeyError(ValueError):
    pass


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError(key)
        value[key] = item
    return value


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value.keys())
    if actual != expected:
        raise ICRagError(
            f"{label} fields are invalid: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ICRagError(f"{label} must be a string")
    if not value.strip() or len(value) > maximum:
        raise ICRagError(f"{label} must be non-empty and at most {maximum} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ICRagError(f"{label} must be valid UTF-8 text") from exc
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, maximum=128)
    if not _ID_RE.fullmatch(text):
        raise ICRagError(f"{label} must be a lowercase portable identifier")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ICRagError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _exact_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ICRagError(f"{label} must be an exact integer")
    if value < minimum or value > maximum:
        raise ICRagError(f"{label} must be between {minimum} and {maximum}")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, maximum=64)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ICRagError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ICRagError(f"{label} must include an explicit timezone")
    return text


def _relative_locator(value: Any, label: str) -> str:
    text = _text(value, label, maximum=512)
    if "\\" in text or ":" in text:
        raise ICRagError(f"{label} must use a portable relative POSIX path")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ICRagError(f"{label} must be a canonical relative POSIX path")
    if path.as_posix() != text:
        raise ICRagError(f"{label} is non-canonical")
    return text


def _document_dict(document: ICRagDocumentV1) -> dict[str, Any]:
    return {
        "authority": document.authority,
        "content_sha256": document.content_sha256,
        "content_size_bytes": document.content_size_bytes,
        "document_id": document.document_id,
        "freshness": document.freshness,
        "freshness_checked_at": document.freshness_checked_at,
        "freshness_evidence_sha256": document.freshness_evidence_sha256,
        "locator": document.locator,
        "source_generation_sha256": document.source_generation_sha256,
        "source_id": document.source_id,
        "source_kind": document.source_kind,
        "text": document.text,
    }


def _hit_dict(hit: ICRagHitV1) -> dict[str, Any]:
    return {
        "authority": hit.authority,
        "content_sha256": hit.content_sha256,
        "content_size_bytes": hit.content_size_bytes,
        "document_id": hit.document_id,
        "excerpt": hit.excerpt,
        "freshness": hit.freshness,
        "freshness_checked_at": hit.freshness_checked_at,
        "freshness_evidence_sha256": hit.freshness_evidence_sha256,
        "locator": hit.locator,
        "matched_terms": list(hit.matched_terms),
        "rank": hit.rank,
        "source_generation_sha256": hit.source_generation_sha256,
        "source_id": hit.source_id,
        "source_kind": hit.source_kind,
    }


def receipt_to_dict(receipt: ICRagReceiptV1) -> dict[str, Any]:
    """Return the canonical portable representation of one immutable receipt."""

    if type(receipt) is not ICRagReceiptV1:
        raise ICRagError("IC RAG receipt must have exact ICRagReceiptV1 type")
    return {
        "audience": receipt.audience,
        "close_qualifying": receipt.close_qualifying,
        "document_set_sha256": receipt.document_set_sha256,
        "hits": [_hit_dict(hit) for hit in receipt.hits],
        "max_excerpt_bytes": receipt.max_excerpt_bytes,
        "max_hits": receipt.max_hits,
        "max_hits_per_kind": receipt.max_hits_per_kind,
        "missing_source_kinds": list(receipt.missing_source_kinds),
        "phase": receipt.phase,
        "present_source_kinds": list(receipt.present_source_kinds),
        "project_fact_precedence": receipt.project_fact_precedence,
        "query": receipt.query,
        "query_sha256": receipt.query_sha256,
        "receipt_sha256": receipt.receipt_sha256,
        "result_quality": receipt.result_quality,
        "retrieval_method": receipt.retrieval_method,
        "schema_version": receipt.schema_version,
        "source_order": list(receipt.source_order),
        "technical_verdict_authority": receipt.technical_verdict_authority,
        "unmatched_query_terms": list(receipt.unmatched_query_terms),
    }


def _receipt_preimage(receipt: ICRagReceiptV1) -> dict[str, Any]:
    value = receipt_to_dict(receipt)
    del value["receipt_sha256"]
    return value


def _validate_document(value: Any, index: int) -> ICRagDocumentV1:
    label = f"documents[{index}]"
    if not isinstance(value, dict):
        raise ICRagError(f"{label} must be an object")
    _exact_fields(
        value,
        frozenset(
            {
                "source_id",
                "source_kind",
                "authority",
                "source_generation_sha256",
                "freshness",
                "freshness_checked_at",
                "freshness_evidence_sha256",
                "document_id",
                "locator",
                "content_sha256",
                "content_size_bytes",
                "text",
            }
        ),
        label,
    )
    source_kind = _text(value["source_kind"], f"{label}.source_kind", maximum=32)
    if source_kind not in SOURCE_ORDER:
        raise ICRagError(f"{label}.source_kind is unsupported")
    authority = _text(value["authority"], f"{label}.authority", maximum=64)
    if authority != SOURCE_AUTHORITY[source_kind]:
        raise ICRagError(f"{label}.authority differs from the fixed source authority")
    freshness = _text(value["freshness"], f"{label}.freshness", maximum=16)
    if freshness not in FRESHNESS_VALUES:
        raise ICRagError(f"{label}.freshness is unsupported")
    text = _text(value["text"], f"{label}.text", maximum=MAX_DOCUMENT_BYTES)
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ICRagError(f"{label}.text is not valid UTF-8 text") from exc
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ICRagError(f"{label}.text exceeds the byte bound")
    content_size = _exact_int(
        value["content_size_bytes"],
        f"{label}.content_size_bytes",
        minimum=1,
        maximum=MAX_DOCUMENT_BYTES,
    )
    if content_size != len(encoded):
        raise ICRagError(f"{label}.content_size_bytes differs from UTF-8 bytes")
    content_sha = _sha256(value["content_sha256"], f"{label}.content_sha256")
    if content_sha != hashlib.sha256(encoded).hexdigest():
        raise ICRagError(f"{label}.content_sha256 differs from text bytes")
    return ICRagDocumentV1(
        source_id=_identifier(value["source_id"], f"{label}.source_id"),
        source_kind=source_kind,
        authority=authority,
        source_generation_sha256=_sha256(
            value["source_generation_sha256"], f"{label}.source_generation_sha256"
        ),
        freshness=freshness,
        freshness_checked_at=_timestamp(
            value["freshness_checked_at"], f"{label}.freshness_checked_at"
        ),
        freshness_evidence_sha256=_sha256(
            value["freshness_evidence_sha256"],
            f"{label}.freshness_evidence_sha256",
        ),
        document_id=_identifier(value["document_id"], f"{label}.document_id"),
        locator=_relative_locator(value["locator"], f"{label}.locator"),
        content_sha256=content_sha,
        content_size_bytes=content_size,
        text=text,
    )


def _sorted_documents(documents: Sequence[ICRagDocumentV1]) -> tuple[ICRagDocumentV1, ...]:
    return tuple(
        sorted(
            documents,
            key=lambda item: (
                SOURCE_ORDER.index(item.source_kind),
                item.source_id,
                item.document_id,
                item.locator.casefold(),
                item.content_sha256,
            ),
        )
    )


def validate_documents(documents: Sequence[ICRagDocumentV1]) -> tuple[ICRagDocumentV1, ...]:
    """Validate immutable documents and return their canonical order."""

    if isinstance(documents, (str, bytes)) or not isinstance(documents, Sequence):
        raise ICRagError("IC RAG documents must be a bounded sequence")
    if not documents or len(documents) > MAX_DOCUMENTS:
        raise ICRagError(f"IC RAG documents must contain 1..{MAX_DOCUMENTS} records")
    checked: list[ICRagDocumentV1] = []
    identities: set[tuple[str, str]] = set()
    source_rows: dict[str, tuple[str, str, str, str, str]] = {}
    for index, item in enumerate(documents):
        if type(item) is not ICRagDocumentV1:
            raise ICRagError(f"documents[{index}] must have exact ICRagDocumentV1 type")
        validated = _validate_document(_document_dict(item), index)
        identity = (validated.source_id, validated.document_id)
        if identity in identities:
            raise ICRagError("IC RAG document identity is duplicated")
        identities.add(identity)
        source_row = (
            validated.source_kind,
            validated.authority,
            validated.source_generation_sha256,
            validated.freshness,
            validated.freshness_checked_at + ":" + validated.freshness_evidence_sha256,
        )
        prior = source_rows.setdefault(validated.source_id, source_row)
        if prior != source_row:
            raise ICRagError("documents for one source_id disagree on source evidence")
        checked.append(validated)
    if not any(item.source_kind == "project_graph" for item in checked):
        raise ICRagError("project-first retrieval requires at least one project_graph document")
    return _sorted_documents(checked)


def parse_document_manifest_bytes(data: bytes) -> tuple[ICRagDocumentV1, ...]:
    """Parse exact canonical JSON bytes into immutable document records."""

    if not isinstance(data, bytes) or not data or len(data) > MAX_MANIFEST_BYTES:
        raise ICRagError("IC RAG manifest must be non-empty bounded bytes")
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_object)
    except _DuplicateKeyError as exc:
        raise ICRagError(f"IC RAG manifest contains duplicate key {exc.args[0]!r}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ICRagError("IC RAG manifest is not bounded UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ICRagError("IC RAG manifest must be an object")
    _exact_fields(payload, frozenset({"schema_version", "documents"}), "manifest")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise ICRagError("IC RAG manifest schema_version must be exact integer 1")
    values = payload["documents"]
    if not isinstance(values, list) or not values or len(values) > MAX_DOCUMENTS:
        raise ICRagError(f"IC RAG manifest documents must contain 1..{MAX_DOCUMENTS} items")
    documents = tuple(_validate_document(item, index) for index, item in enumerate(values))
    documents = validate_documents(documents)
    try:
        canonical = canonical_json_bytes(payload, max_bytes=MAX_MANIFEST_BYTES)
    except SemanticEventError as exc:
        raise ICRagError("IC RAG manifest exceeds canonical JSON bounds") from exc
    if data != canonical:
        raise ICRagError("IC RAG manifest bytes are not canonical JSON")
    return documents


def document_manifest_dict(documents: Sequence[ICRagDocumentV1]) -> dict[str, Any]:
    checked = validate_documents(documents)
    return {
        "documents": [_document_dict(item) for item in checked],
        "schema_version": MANIFEST_SCHEMA_VERSION,
    }


def _query_terms(query: str) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for match in _TOKEN_RE.finditer(unicodedata.normalize("NFC", query).casefold()):
        term = match.group(0)
        if len(term) < 2 or term in seen:
            continue
        seen.add(term)
        values.append(term)
    if not values:
        raise ICRagError("IC RAG query has no searchable terms")
    return tuple(values)


def _truncate_utf8(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", errors="ignore").rstrip()


def _excerpt(document: ICRagDocumentV1, terms: tuple[str, ...], maximum: int) -> str:
    normalized = unicodedata.normalize("NFC", " ".join(document.text.split()))
    folded = normalized.casefold()
    positions = [folded.find(term) for term in terms if folded.find(term) >= 0]
    anchor = min(positions) if positions else 0
    start = max(0, anchor - maximum // 3)
    return _truncate_utf8(normalized[start:], maximum)


def _document_set_sha256(documents: tuple[ICRagDocumentV1, ...]) -> str:
    try:
        encoded = canonical_json_bytes(
            document_manifest_dict(documents), max_bytes=MAX_MANIFEST_BYTES
        )
    except SemanticEventError as exc:
        raise ICRagError("IC RAG document set exceeds canonical JSON bounds") from exc
    return hashlib.sha256(encoded).hexdigest()


def derive_ic_rag_context(
    *,
    query: str,
    phase: str,
    audience: str,
    documents: Sequence[ICRagDocumentV1],
    max_hits: int = 6,
    max_hits_per_kind: int = 2,
    max_excerpt_bytes: int = 768,
) -> ICRagReceiptV1:
    """Derive a deterministic, bounded, project-first navigation receipt."""

    query = _text(query, "IC RAG query", maximum=MAX_QUERY_CHARACTERS).strip()
    if phase not in PHASE_VALUES:
        raise ICRagError("IC RAG phase is unsupported")
    if audience not in AUDIENCE_VALUES:
        raise ICRagError("IC RAG audience is unsupported")
    max_hits = _exact_int(max_hits, "max_hits", minimum=1, maximum=MAX_HITS)
    max_hits_per_kind = _exact_int(
        max_hits_per_kind,
        "max_hits_per_kind",
        minimum=1,
        maximum=MAX_HITS_PER_KIND,
    )
    max_excerpt_bytes = _exact_int(
        max_excerpt_bytes,
        "max_excerpt_bytes",
        minimum=MIN_EXCERPT_BYTES,
        maximum=MAX_EXCERPT_BYTES,
    )
    checked = validate_documents(documents)
    terms = _query_terms(query)
    phrase = unicodedata.normalize("NFC", " ".join(query.casefold().split()))
    candidates: dict[str, list[tuple[int, int, ICRagDocumentV1, tuple[str, ...]]]] = {
        kind: [] for kind in SOURCE_ORDER
    }
    observed_terms: set[str] = set()
    for document in checked:
        haystack = unicodedata.normalize(
            "NFC", document.locator + "\n" + document.text
        ).casefold()
        matched = tuple(term for term in terms if term in haystack)
        if not matched:
            continue
        observed_terms.update(matched)
        candidates[document.source_kind].append(
            (1 if phrase in haystack else 0, len(matched), document, matched)
        )
    ordered_candidates: dict[
        str, list[tuple[int, int, ICRagDocumentV1, tuple[str, ...]]]
    ] = {}
    for kind in SOURCE_ORDER:
        ordered_candidates[kind] = sorted(
            candidates[kind],
            key=lambda item: (
                -item[0],
                -item[1],
                item[2].source_id,
                item[2].locator.casefold(),
                item[2].document_id,
                item[2].content_sha256,
            ),
        )
    selected: list[tuple[ICRagDocumentV1, tuple[str, ...]]] = []
    for tier_index in range(max_hits_per_kind):
        for kind in SOURCE_ORDER:
            ordered = ordered_candidates[kind]
            if tier_index >= len(ordered):
                continue
            _phrase_score, _term_score, document, matched = ordered[tier_index]
            selected.append((document, matched))
            if len(selected) >= max_hits:
                break
        if len(selected) >= max_hits:
            break
    hits = tuple(
        ICRagHitV1(
            rank=index,
            source_id=document.source_id,
            source_kind=document.source_kind,
            authority=document.authority,
            source_generation_sha256=document.source_generation_sha256,
            freshness=document.freshness,
            freshness_checked_at=document.freshness_checked_at,
            freshness_evidence_sha256=document.freshness_evidence_sha256,
            document_id=document.document_id,
            locator=document.locator,
            content_sha256=document.content_sha256,
            content_size_bytes=document.content_size_bytes,
            matched_terms=matched,
            excerpt=_excerpt(document, matched, max_excerpt_bytes),
        )
        for index, (document, matched) in enumerate(selected, start=1)
    )
    present = tuple(kind for kind in SOURCE_ORDER if any(d.source_kind == kind for d in checked))
    missing = tuple(kind for kind in SOURCE_ORDER if kind not in present)
    receipt = ICRagReceiptV1(
        schema_version=RECEIPT_SCHEMA_VERSION,
        retrieval_method="deterministic_lexical_v1",
        phase=phase,
        audience=audience,
        query=query,
        query_sha256=hashlib.sha256(query.encode("utf-8")).hexdigest(),
        document_set_sha256=_document_set_sha256(checked),
        source_order=SOURCE_ORDER,
        present_source_kinds=present,
        missing_source_kinds=missing,
        unmatched_query_terms=tuple(term for term in terms if term not in observed_terms),
        max_hits=max_hits,
        max_hits_per_kind=max_hits_per_kind,
        max_excerpt_bytes=max_excerpt_bytes,
        result_quality="bounded_lexical_candidate",
        technical_verdict_authority="none",
        project_fact_precedence="repository_source_and_runtime_receipts",
        close_qualifying=False,
        hits=hits,
        receipt_sha256="0" * 64,
    )
    try:
        digest = hashlib.sha256(canonical_json_bytes(_receipt_preimage(receipt))).hexdigest()
    except SemanticEventError as exc:
        raise ICRagError("IC RAG receipt exceeds canonical JSON bounds") from exc
    return receipt._replace(receipt_sha256=digest)


def validate_ic_rag_receipt(
    receipt: ICRagReceiptV1,
    *,
    documents: Sequence[ICRagDocumentV1],
) -> ICRagReceiptV1:
    """Re-derive and exact-compare one semantic receipt against its witnesses."""

    if type(receipt) is not ICRagReceiptV1:
        raise ICRagError("IC RAG receipt must have exact ICRagReceiptV1 type")
    if any(type(hit) is not ICRagHitV1 for hit in receipt.hits):
        raise ICRagError("IC RAG receipt hits must have exact ICRagHitV1 type")
    expected = derive_ic_rag_context(
        query=receipt.query,
        phase=receipt.phase,
        audience=receipt.audience,
        documents=documents,
        max_hits=receipt.max_hits,
        max_hits_per_kind=receipt.max_hits_per_kind,
        max_excerpt_bytes=receipt.max_excerpt_bytes,
    )
    if receipt != expected:
        raise ICRagError("IC RAG receipt differs from deterministic witness derivation")
    return receipt


__all__ = [
    "AUDIENCE_VALUES",
    "FRESHNESS_VALUES",
    "ICRagDocumentV1",
    "ICRagError",
    "ICRagHitV1",
    "ICRagReceiptV1",
    "PHASE_VALUES",
    "SOURCE_AUTHORITY",
    "SOURCE_ORDER",
    "derive_ic_rag_context",
    "document_manifest_dict",
    "parse_document_manifest_bytes",
    "receipt_to_dict",
    "validate_documents",
    "validate_ic_rag_receipt",
]
