"""Pure, fail-closed reviewer-independence and finding-chain contracts.

This is intentionally a schema-only boundary: close/doctor callers may pass
their task projection to these functions, but this module neither reads state
nor infers identities from legacy prose.  New records must carry explicit
agent identities and sealed SHA-256 bindings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


REVIEW_INTEGRITY_VERSION = 1
MAX_REVIEW_INTEGRITY_ITEMS = 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_FINDING_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CHAIN_FIELDS = frozenset(
    {
        "review_integrity_version",
        "finding_id",
        "candidate_snapshot_sha256",
        "mutation_snapshot_sha256",
        "fix_result_sha256",
        "reviewer_agent_id",
        "verification_sha256",
    }
)
_REVIEW_RESULT_FIELDS = frozenset(
    {
        "review_integrity_version",
        "reviewer_agent_id",
        "producer_agent_ids",
        "candidate_snapshot_sha256",
        "mutation_snapshot_sha256",
        "review_result_sha256",
        "outcome",
        "finding_ids",
    }
)


class ReviewIntegrityError(ValueError):
    """A fail-closed review-integrity contract violation."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        values = (errors,) if isinstance(errors, str) else tuple(errors)
        self.errors = tuple(str(value) for value in values)
        super().__init__("review integrity failed: " + "; ".join(self.errors))


def _bounded_records(value: Iterable[Any], label: str) -> list[Any]:
    records: list[Any] = []
    for index, item in enumerate(value, start=1):
        if index > MAX_REVIEW_INTEGRITY_ITEMS:
            raise ReviewIntegrityError(
                f"{label} exceeds {MAX_REVIEW_INTEGRITY_ITEMS} records"
            )
        records.append(item)
    return records


def _bounded_values(value: Any, label: str) -> list[Any]:
    """Materialize one JSON-array-like field without accepting text or maps."""

    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise ReviewIntegrityError(f"{label} must be an array")
    try:
        return _bounded_records(value, label)
    except TypeError as exc:
        raise ReviewIntegrityError(f"{label} must be an array") from exc


def _agent_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ReviewIntegrityError(f"{label} lacks an explicit agent_id")
    if len(value) > 256:
        raise ReviewIntegrityError(f"{label} agent_id exceeds 256 characters")
    return value


def _finding_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _FINDING_ID_RE.fullmatch(value):
        raise ReviewIntegrityError(f"{label} has an invalid finding_id")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ReviewIntegrityError(f"{label} has an invalid SHA-256")
    return value


def _packet_is_reviewer(packet: Mapping[str, Any], label: str) -> bool:
    roles = {
        value
        for value in (packet.get("agent_role"), packet.get("actual_role"))
        if isinstance(value, str) and value.strip()
    }
    if "reviewer" in roles and len(roles) > 1:
        raise ReviewIntegrityError(f"{label} has conflicting reviewer roles")
    return roles == {"reviewer"}


def producer_identity_set(
    *,
    task_owner: Any,
    candidate_packets: Iterable[Mapping[str, Any]] = (),
    result_packets: Iterable[Mapping[str, Any]] = (),
    mutations: Iterable[Mapping[str, Any]] = (),
) -> frozenset[str]:
    """Return every explicit producer identity, rejecting legacy omissions.

    Every candidate/result packet is a producer regardless of its role label;
    otherwise relabeling a producer as ``reviewer`` could manufacture false
    independence. Mutation records use the unambiguous ``actor_agent_id``
    field rather than a prose actor label.
    """

    identities = {_agent_id(task_owner, "task owner")}
    for collection_name, collection in (
        ("candidate packet", candidate_packets),
        ("result packet", result_packets),
    ):
        for index, packet in enumerate(_bounded_records(collection, collection_name), 1):
            label = f"{collection_name} #{index}"
            if not isinstance(packet, Mapping):
                raise ReviewIntegrityError(f"{label} is not a record")
            _packet_is_reviewer(packet, label)
            identities.add(_agent_id(packet.get("agent_id"), label))
    for index, mutation in enumerate(_bounded_records(mutations, "mutation"), 1):
        label = f"mutation #{index}"
        if not isinstance(mutation, Mapping):
            raise ReviewIntegrityError(f"{label} is not a record")
        identities.add(_agent_id(mutation.get("actor_agent_id"), label))
    return frozenset(identities)


def validate_reviewer_identity(
    reviewer_agent_id: Any, producer_agent_ids: Iterable[str]
) -> str:
    """Require a named reviewer independent from every producer identity."""

    reviewer = _agent_id(reviewer_agent_id, "reviewer")
    producers = frozenset(producer_agent_ids)
    if reviewer in producers:
        raise ReviewIntegrityError(
            f"reviewer agent_id {reviewer!r} is a producer identity (self-review)"
        )
    return reviewer


def build_finding_fix_verification_chain(
    *,
    finding_id: Any,
    candidate_snapshot_sha256: Any,
    mutation_snapshot_sha256: Any,
    fix_result_sha256: Any,
    reviewer_agent_id: Any,
    verification_sha256: Any,
) -> dict[str, str | int]:
    """Build the one canonical, JSON-ready binding for a resolved finding."""

    return {
        "review_integrity_version": REVIEW_INTEGRITY_VERSION,
        "finding_id": _finding_id(finding_id, "chain"),
        "candidate_snapshot_sha256": _sha256(
            candidate_snapshot_sha256, "chain candidate snapshot"
        ),
        "mutation_snapshot_sha256": _sha256(
            mutation_snapshot_sha256, "chain mutation snapshot"
        ),
        "fix_result_sha256": _sha256(fix_result_sha256, "chain fix result"),
        "reviewer_agent_id": _agent_id(reviewer_agent_id, "chain reviewer"),
        "verification_sha256": _sha256(
            verification_sha256, "chain verification"
        ),
    }


def build_review_result(
    *,
    reviewer_agent_id: Any,
    producer_agent_ids: Iterable[str],
    candidate_snapshot_sha256: Any,
    mutation_snapshot_sha256: Any,
    review_result_sha256: Any,
    outcome: Any,
    finding_ids: Iterable[Any],
) -> dict[str, Any]:
    """Build the mandatory review attestation, including a clean review."""

    producers = sorted(
        {
            _agent_id(item, "review producer")
            for item in _bounded_values(producer_agent_ids, "review result producer_agent_ids")
        }
    )
    reviewer = validate_reviewer_identity(reviewer_agent_id, producers)
    if outcome not in {"clean", "findings_resolved"}:
        raise ReviewIntegrityError("review result outcome is invalid")
    findings = [
        _finding_id(item, "review result")
        for item in _bounded_values(finding_ids, "review result finding_ids")
    ]
    if findings != sorted(set(findings)):
        raise ReviewIntegrityError("review result finding_ids must be sorted and unique")
    if outcome == "clean" and findings:
        raise ReviewIntegrityError("clean review result may not name findings")
    if outcome == "findings_resolved" and not findings:
        raise ReviewIntegrityError("findings_resolved review result requires findings")
    return {
        "review_integrity_version": REVIEW_INTEGRITY_VERSION,
        "reviewer_agent_id": reviewer,
        "producer_agent_ids": producers,
        "candidate_snapshot_sha256": _sha256(
            candidate_snapshot_sha256, "review result candidate snapshot"
        ),
        "mutation_snapshot_sha256": _sha256(
            mutation_snapshot_sha256, "review result mutation snapshot"
        ),
        "review_result_sha256": _sha256(
            review_result_sha256, "review result artifact"
        ),
        "outcome": outcome,
        "finding_ids": findings,
    }


def validate_review_result(
    value: Mapping[str, Any], *, expected_producer_agent_ids: Iterable[str]
) -> dict[str, Any]:
    """Validate one exact mandatory review result against live producers."""

    if not isinstance(value, Mapping) or set(value) != _REVIEW_RESULT_FIELDS:
        raise ReviewIntegrityError("review result schema is invalid")
    if value.get("review_integrity_version") != REVIEW_INTEGRITY_VERSION:
        raise ReviewIntegrityError("review result version is invalid")
    if not isinstance(value.get("producer_agent_ids"), list):
        raise ReviewIntegrityError("review result producer_agent_ids must be an array")
    if not isinstance(value.get("finding_ids"), list):
        raise ReviewIntegrityError("review result finding_ids must be an array")
    expected = sorted(
        {
            _agent_id(item, "expected review producer")
            for item in _bounded_values(
                expected_producer_agent_ids, "expected review producer_agent_ids"
            )
        }
    )
    rebuilt = build_review_result(
        reviewer_agent_id=value.get("reviewer_agent_id"),
        producer_agent_ids=value["producer_agent_ids"],
        candidate_snapshot_sha256=value.get("candidate_snapshot_sha256"),
        mutation_snapshot_sha256=value.get("mutation_snapshot_sha256"),
        review_result_sha256=value.get("review_result_sha256"),
        outcome=value.get("outcome"),
        finding_ids=value["finding_ids"],
    )
    if rebuilt["producer_agent_ids"] != expected:
        raise ReviewIntegrityError("review result producer set is stale or incomplete")
    return rebuilt


def _records_by_finding(
    records: Iterable[Mapping[str, Any]], kind: str, errors: list[str]
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    try:
        bounded = _bounded_records(records, kind)
    except ReviewIntegrityError as exc:
        errors.extend(exc.errors)
        return indexed
    for index, record in enumerate(bounded, 1):
        label = f"{kind} #{index}"
        if not isinstance(record, Mapping):
            errors.append(f"{label} is not a record")
            continue
        try:
            finding_id = _finding_id(record.get("finding_id"), label)
        except ReviewIntegrityError as exc:
            errors.extend(exc.errors)
            continue
        if finding_id in indexed:
            errors.append(f"duplicate {kind} for finding_id {finding_id!r}")
            continue
        indexed[finding_id] = record
    return indexed


def review_integrity_errors(
    *,
    task_owner: Any,
    candidate_packets: Iterable[Mapping[str, Any]],
    result_packets: Iterable[Mapping[str, Any]],
    mutations: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]],
    fix_results: Iterable[Mapping[str, Any]],
    verifications: Iterable[Mapping[str, Any]],
    chains: Iterable[Mapping[str, Any]],
    review_result: Mapping[str, Any] | None = None,
) -> list[str]:
    """Return deterministic errors for the complete finding-to-fix graph.

    ``findings`` bind ``finding_id`` to ``candidate_snapshot_sha256``;
    ``mutations`` bind the candidate to a mutation snapshot and actor;
    ``fix_results`` bind that snapshot to a result; and ``verifications`` bind
    the result to an independent reviewer and verification digest.  Each input
    set must contain exactly one record for every finding, as must ``chains``.
    """

    errors: list[str] = []
    # Materialize once: callers may supply generators, and mutation records are
    # intentionally consumed both for producer identities and finding links.
    try:
        candidate_packets = _bounded_records(candidate_packets, "candidate packet")
        result_packets = _bounded_records(result_packets, "result packet")
        mutations = _bounded_records(mutations, "mutation")
        findings = _bounded_records(findings, "finding")
        fix_results = _bounded_records(fix_results, "fix result")
        verifications = _bounded_records(verifications, "verification")
        chains = _bounded_records(chains, "review chain")
    except ReviewIntegrityError as exc:
        return sorted(exc.errors)
    try:
        producers = producer_identity_set(
            task_owner=task_owner,
            candidate_packets=candidate_packets,
            result_packets=result_packets,
            mutations=mutations,
        )
    except ReviewIntegrityError as exc:
        errors.extend(exc.errors)
        producers = frozenset()

    validated_review: dict[str, Any] | None = None
    if review_result is None:
        errors.append("mandatory review result is missing")
    else:
        try:
            validated_review = validate_review_result(
                review_result, expected_producer_agent_ids=producers
            )
        except ReviewIntegrityError as exc:
            errors.extend(exc.errors)
            validated_review = None

    finding_by_id = _records_by_finding(findings, "finding", errors)
    mutation_by_id = _records_by_finding(mutations, "mutation", errors)
    fix_by_id = _records_by_finding(fix_results, "fix result", errors)
    verification_by_id = _records_by_finding(verifications, "verification", errors)
    chain_by_id = _records_by_finding(chains, "review chain", errors)
    expected_ids = set(finding_by_id)
    if validated_review is not None:
        if validated_review["finding_ids"] != sorted(expected_ids):
            errors.append("review result finding set differs from the finding graph")
        if expected_ids:
            candidate_digests = {
                record.get("candidate_snapshot_sha256")
                for record in finding_by_id.values()
            }
            mutation_digests = {
                record.get("mutation_snapshot_sha256")
                for record in mutation_by_id.values()
            }
            if candidate_digests != {validated_review["candidate_snapshot_sha256"]}:
                errors.append("review result candidate snapshot differs from findings")
            if mutation_digests != {validated_review["mutation_snapshot_sha256"]}:
                errors.append("review result mutation snapshot differs from mutations")
            verification_reviewers = {
                record.get("reviewer_agent_id")
                for finding_id, record in verification_by_id.items()
                if finding_id in expected_ids
            }
            if verification_reviewers != {validated_review["reviewer_agent_id"]}:
                errors.append(
                    "review result reviewer identity differs from verifications"
                )
    for kind, indexed in (
        ("mutation", mutation_by_id),
        ("fix result", fix_by_id),
        ("verification", verification_by_id),
        ("review chain", chain_by_id),
    ):
        missing = sorted(expected_ids - set(indexed))
        extra = sorted(set(indexed) - expected_ids)
        if missing:
            errors.append(f"missing {kind} records for finding_ids: {', '.join(missing)}")
        if extra:
            errors.append(f"extra {kind} records for finding_ids: {', '.join(extra)}")

    for finding_id in sorted(expected_ids):
        finding = finding_by_id[finding_id]
        mutation = mutation_by_id.get(finding_id)
        fix = fix_by_id.get(finding_id)
        verification = verification_by_id.get(finding_id)
        chain = chain_by_id.get(finding_id)
        try:
            candidate_sha = _sha256(
                finding.get("candidate_snapshot_sha256"), f"finding {finding_id}"
            )
            finding_reviewer = _agent_id(
                finding.get("reviewer_agent_id"), f"finding {finding_id} reviewer"
            )
            validate_reviewer_identity(finding_reviewer, producers)
        except ReviewIntegrityError as exc:
            errors.extend(exc.errors)
            candidate_sha = None
        if mutation is not None:
            try:
                if candidate_sha != _sha256(
                    mutation.get("candidate_snapshot_sha256"),
                    f"mutation {finding_id} candidate snapshot",
                ):
                    errors.append(f"finding {finding_id} candidate snapshot binding is tampered")
                _sha256(
                    mutation.get("mutation_snapshot_sha256"),
                    f"mutation {finding_id} snapshot",
                )
                _agent_id(mutation.get("actor_agent_id"), f"mutation {finding_id}")
            except ReviewIntegrityError as exc:
                errors.extend(exc.errors)
        if mutation is not None and fix is not None:
            try:
                if _sha256(
                    mutation.get("mutation_snapshot_sha256"),
                    f"mutation {finding_id} snapshot",
                ) != _sha256(
                    fix.get("mutation_snapshot_sha256"),
                    f"fix result {finding_id} mutation snapshot",
                ):
                    errors.append(f"finding {finding_id} mutation snapshot binding is tampered")
                _sha256(fix.get("fix_result_sha256"), f"fix result {finding_id}")
            except ReviewIntegrityError as exc:
                errors.extend(exc.errors)
        if fix is not None and verification is not None:
            try:
                if _sha256(fix.get("fix_result_sha256"), f"fix result {finding_id}") != _sha256(
                    verification.get("fix_result_sha256"),
                    f"verification {finding_id} fix result",
                ):
                    errors.append(f"finding {finding_id} fix result binding is tampered")
                validate_reviewer_identity(
                    verification.get("reviewer_agent_id"), producers
                )
                _sha256(
                    verification.get("verification_sha256"),
                    f"verification {finding_id}",
                )
            except ReviewIntegrityError as exc:
                errors.extend(exc.errors)
        if (
            chain is not None
            and mutation is not None
            and fix is not None
            and verification is not None
            and candidate_sha is not None
        ):
            try:
                expected = build_finding_fix_verification_chain(
                    finding_id=finding_id,
                    candidate_snapshot_sha256=candidate_sha,
                    mutation_snapshot_sha256=mutation.get("mutation_snapshot_sha256"),
                    fix_result_sha256=fix.get("fix_result_sha256"),
                    reviewer_agent_id=verification.get("reviewer_agent_id"),
                    verification_sha256=verification.get("verification_sha256"),
                )
                if set(chain) != _CHAIN_FIELDS or chain != expected:
                    errors.append(f"review chain for finding {finding_id} is tampered")
                validate_reviewer_identity(chain.get("reviewer_agent_id"), producers)
            except ReviewIntegrityError as exc:
                errors.extend(exc.errors)
    return sorted(set(errors))


def validate_review_integrity(**kwargs: Any) -> None:
    """Raise :class:`ReviewIntegrityError` when the pure graph is invalid."""

    errors = review_integrity_errors(**kwargs)
    if errors:
        raise ReviewIntegrityError(errors)


__all__ = [
    "MAX_REVIEW_INTEGRITY_ITEMS",
    "REVIEW_INTEGRITY_VERSION",
    "ReviewIntegrityError",
    "build_finding_fix_verification_chain",
    "build_review_result",
    "producer_identity_set",
    "review_integrity_errors",
    "validate_review_integrity",
    "validate_review_result",
    "validate_reviewer_identity",
]
