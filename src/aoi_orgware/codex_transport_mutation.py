"""Git/claim materialization for the optional Codex transport bridge.

The App Server can only report runtime lifecycle.  This module is the separate
Chief-side evidence boundary that may create a *new* ``verified_mutation``
terminal receipt after exact Git and claim-endpoint evidence has been preserved
in task-local CAS.  It never launches Codex, infers task completion, or treats
an endpoint claim as continuous authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import codex_transport_contracts as contracts
from . import codex_transport_runtime as runtime
from . import evidence_artifacts as artifacts
from . import git_plumbing as git
from . import harnesslib as h
from . import semantic_events as semantic
from . import semantic_objects as objects
from . import semantic_store as store
from .harnesslib import HarnessError, HarnessPaths


LEGACY_GIT_ENDPOINT_SCHEMA = "aoi.codex-transport.git-endpoint.v1"
GIT_ENDPOINT_SCHEMA = "aoi.codex-transport.git-endpoint.v2"
GIT_TREE_SCHEMA = "aoi.codex-transport.git-tree.v1"
CLAIM_ENDPOINT_SCHEMA = "aoi.codex-transport.claim-endpoints.v2"
MAX_MUTATION_RECORD_BYTES = 8 * 1024 * 1024
# ``rev-parse <commit>^{tree}`` is tiny by contract.  Keep a separate narrow
# cap rather than allowing a malformed executable on PATH to consume the
# general Git-command budget.
MAX_GIT_TREE_OUTPUT_BYTES = 1024
CODEX_MUTATION_NAMESPACE_KEY = "codex_verified_mutations_v1"
CODEX_MUTATION_NAMESPACE_VERSION = 1
MAX_VERIFIED_MUTATIONS = 128
_SHA256 = re.compile(r"[0-9a-f]{64}")


class CodexTransportMutationError(HarnessError):
    """Mutation evidence is malformed, mismatched, or cannot be materialized."""


def _fail(message: str, exc: BaseException | None = None) -> CodexTransportMutationError:
    return CodexTransportMutationError(message) if exc is None else CodexTransportMutationError(f"{message}: {exc}")


def _canonical(value: Mapping[str, Any], label: str) -> bytes:
    try:
        return semantic.canonical_json_bytes(value, max_bytes=MAX_MUTATION_RECORD_BYTES)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail(f"{label} is not bounded canonical JSON", exc) from exc


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise CodexTransportMutationError(f"{label} is not lowercase SHA-256")
    return value


def _mutation_namespace(value: Any) -> dict[str, Any]:
    if value is None:
        return {"schema_version": CODEX_MUTATION_NAMESPACE_VERSION, "launches": {}}
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "launches"}:
        raise CodexTransportMutationError("verified mutation namespace schema is invalid")
    if value["schema_version"] != CODEX_MUTATION_NAMESPACE_VERSION:
        raise CodexTransportMutationError("verified mutation namespace version is invalid")
    launches = value["launches"]
    if not isinstance(launches, Mapping) or len(launches) > MAX_VERIFIED_MUTATIONS:
        raise CodexTransportMutationError("verified mutation namespace launch index is invalid")
    checked: dict[str, dict[str, str]] = {}
    for launch_id, row in launches.items():
        if (
            not isinstance(launch_id, str)
            or not launch_id
            or not isinstance(row, Mapping)
            or set(row)
            != {
                "launch_id",
                "mutation_object_sha256",
                "verified_receipt_sha256",
                "journal_head_sha256",
            }
            or row["launch_id"] != launch_id
        ):
            raise CodexTransportMutationError(
                "verified mutation launch row schema is invalid"
            )
        checked[launch_id] = {
            "launch_id": launch_id,
            "mutation_object_sha256": _sha_text(
                str(row["mutation_object_sha256"]),
                "verified mutation object SHA-256",
            ),
            "verified_receipt_sha256": _sha_text(
                str(row["verified_receipt_sha256"]),
                "verified mutation receipt SHA-256",
            ),
            "journal_head_sha256": _sha_text(
                str(row["journal_head_sha256"]),
                "verified mutation journal head SHA-256",
            ),
        }
    return {
        "schema_version": CODEX_MUTATION_NAMESPACE_VERSION,
        "launches": {key: checked[key] for key in sorted(checked)},
    }


def _worktree_for_intent(snapshot: Mapping[str, Any], intent: Mapping[str, Any]) -> None:
    try:
        observed = Path(str(snapshot["worktree"])).resolve().as_posix()
    except (KeyError, OSError) as exc:
        raise _fail("Git endpoint worktree is invalid", exc) from exc
    if observed != intent["cwd"]:
        raise CodexTransportMutationError("Git endpoint worktree does not match launch intent cwd")


def _git_tree(worktree: Path, head: str) -> dict[str, str]:
    """Resolve one exact commit's tree object through Git's bounded runner."""

    try:
        raw = git._run_git_bytes_bounded(
            worktree,
            ("rev-parse", f"{head}^{{tree}}"),
            label="Git tree lookup",
            stdout_limit=MAX_GIT_TREE_OUTPUT_BYTES,
        )
    except HarnessError as exc:
        raise _fail("Git tree lookup failed", exc) from exc
    try:
        tree = raw.decode("ascii", "strict").strip().lower()
    except UnicodeDecodeError as exc:
        raise _fail("Git tree lookup returned non-ASCII bytes", exc) from exc
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", tree):
        raise CodexTransportMutationError("Git tree lookup returned no valid tree object")
    base = {"schema": GIT_TREE_SCHEMA, "head": head, "tree": tree}
    return {**base, "tree_sha256": _sha(_canonical(base, "Git tree"))}


def _validate_tree(value: Mapping[str, Any], snapshot: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"schema", "head", "tree", "tree_sha256"}:
        raise CodexTransportMutationError("Git tree record schema is invalid")
    head = value.get("head")
    tree = value.get("tree")
    if head != snapshot.get("current_head") or not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", tree):
        raise CodexTransportMutationError("Git tree record does not bind the snapshot HEAD")
    checked_head = str(head)
    checked_tree = str(tree)
    base = {"schema": GIT_TREE_SCHEMA, "head": checked_head, "tree": checked_tree}
    if value.get("schema") != GIT_TREE_SCHEMA or value.get("tree_sha256") != _sha(_canonical(base, "Git tree")):
        raise CodexTransportMutationError("Git tree record digest is invalid")
    # A self-consistent caller-supplied digest is not source evidence.  Resolve
    # the *recorded snapshot HEAD* in its recorded worktree and require its
    # actual Git tree object.  This intentionally does not assert current
    # worktree HEAD still equals a historical pre-image: that pre-image is a
    # Chief-captured fact and a turn may legitimately have changed it.
    try:
        worktree = Path(str(snapshot["worktree"])).resolve()
    except (KeyError, OSError) as exc:
        raise _fail("Git tree snapshot worktree is invalid", exc) from exc
    observed = _git_tree(worktree, checked_head)
    if observed["tree"] != checked_tree:
        raise CodexTransportMutationError("Git tree record does not match the live snapshot HEAD tree object")
    return {**base, "tree_sha256": str(value["tree_sha256"])}


def _claim_binding_digest(
    coverage: Mapping[str, Any], authority: Mapping[str, Any]
) -> str:
    return _sha(
        _canonical(
            {
                "claim_coverage": dict(coverage),
                "claim_authority_sha256": authority[
                    "claim_authority_sha256"
                ],
            },
            "claim coverage and authority",
        )
    )


def _endpoint_base(
    snapshot: Mapping[str, Any],
    tree: Mapping[str, Any],
    coverage: Mapping[str, Any],
    claim_authority: Mapping[str, Any],
) -> dict[str, Any]:
    task_id, _paths = git.validate_task_mutation_snapshot(snapshot)
    checked_tree = _validate_tree(tree, snapshot)
    if not isinstance(coverage, Mapping) or coverage.get("task_id") != task_id or coverage.get("covered") is not True:
        raise CodexTransportMutationError("Git endpoint claim coverage is missing or uncovered")
    tokens = coverage.get("covered_claim_tokens")
    digest = coverage.get("claim_scope_sha256")
    if not isinstance(tokens, list) or tokens != sorted(set(tokens)) or any(not isinstance(token, str) for token in tokens):
        raise CodexTransportMutationError("Git endpoint covered claim tokens are not canonical")
    _sha_text(str(digest), "Git endpoint claim scope SHA-256")
    checked_authority = git.validate_task_claim_authority_record(
        claim_authority
    )
    if (
        checked_authority["task_id"] != task_id
        or checked_authority["worktree"] != snapshot["worktree"]
        or not checked_authority["claim_tokens"]
    ):
        raise CodexTransportMutationError(
            "Git endpoint full claim authority is missing or mismatched"
        )
    return {
        "schema": GIT_ENDPOINT_SCHEMA,
        "task_id": task_id,
        "snapshot": dict(snapshot),
        "tree": checked_tree,
        "claim_coverage": dict(coverage),
        "claim_authority": checked_authority,
    }


def capture_git_endpoint(
    task_id: str,
    worktree: Path,
    baseline_head: str,
    claims: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Capture one bounded source/claim endpoint before or after a runtime turn."""

    try:
        snapshot = git.task_mutation_snapshot(task_id, worktree, baseline_head)
        coverage = git.task_mutation_snapshot_claim_coverage(snapshot, claims)
        claim_authority = git.capture_task_live_claim_authority(
            task_id, claims, str(snapshot["worktree"])
        )
        base = _endpoint_base(
            snapshot,
            _git_tree(Path(snapshot["worktree"]), snapshot["current_head"]),
            coverage,
            claim_authority,
        )
        return {**base, "endpoint_sha256": _sha(_canonical(base, "Git endpoint"))}
    except (HarnessError, KeyError, OSError, TypeError) as exc:
        raise _fail("cannot capture Git mutation endpoint", exc) from exc


def validate_git_endpoint(
    endpoint: Mapping[str, Any],
    claims: Sequence[Mapping[str, Any]],
    *,
    sealed_claim_scope: bool,
) -> dict[str, Any]:
    """Revalidate an endpoint's exact snapshot and its recorded claim relation.

    ``sealed_claim_scope`` accepts a normal later claim terminal transition, but
    still recomputes coverage against exactly the sealed token set.  It never
    asserts the claims were held for any time between endpoints.
    """

    if (
        isinstance(endpoint, Mapping)
        and endpoint.get("schema") == LEGACY_GIT_ENDPOINT_SCHEMA
    ):
        raise CodexTransportMutationError(
            "legacy Git endpoint lacks complete live claim authority"
        )
    if not isinstance(endpoint, Mapping) or set(endpoint) != {
        "schema", "task_id", "snapshot", "tree", "claim_coverage",
        "claim_authority", "endpoint_sha256"
    }:
        raise CodexTransportMutationError("Git endpoint schema is invalid")
    try:
        checked_authority = git.validate_task_claim_authority(
            endpoint["claim_authority"],
            claims,
            sealed=sealed_claim_scope,
        )
        base = _endpoint_base(
            endpoint["snapshot"],
            endpoint["tree"],
            endpoint["claim_coverage"],
            checked_authority,
        )
        if endpoint["schema"] != GIT_ENDPOINT_SCHEMA or endpoint["task_id"] != base["task_id"]:
            raise CodexTransportMutationError("Git endpoint identity is invalid")
        if endpoint["endpoint_sha256"] != _sha(_canonical(base, "Git endpoint")):
            raise CodexTransportMutationError("Git endpoint digest is invalid")
        coverage = endpoint["claim_coverage"]
        rebuilt = git.validate_task_mutation_snapshot_claim_scope(
            endpoint["snapshot"], coverage["covered_claim_tokens"], coverage["claim_scope_sha256"], claims,
            sealed=sealed_claim_scope,
        )
        # ``covered_claims[*].observed_status`` is deliberately diagnostic:
        # a released claim can still be checked by its sealed immutable scope.
        # It must not make a formerly exact endpoint appear to claim continuous
        # authority.  All path, lock, token, and scope-digest fields remain exact.
        rebuilt_stable = {key: value for key, value in rebuilt.items() if key != "covered_claims"}
        recorded_stable = {key: value for key, value in coverage.items() if key != "covered_claims"}
        if _canonical(rebuilt_stable, "rebuilt claim coverage") != _canonical(recorded_stable, "recorded claim coverage"):
            raise CodexTransportMutationError("Git endpoint claim coverage no longer matches its exact snapshot")
        return {**base, "endpoint_sha256": str(endpoint["endpoint_sha256"])}
    except (HarnessError, KeyError, TypeError) as exc:
        raise _fail("Git endpoint validation failed", exc) from exc


def endpoint_pre_git_binding(endpoint: Mapping[str, Any]) -> dict[str, str]:
    """Return the exact intent pre-image binding for a validated pre endpoint."""

    if not isinstance(endpoint, Mapping):
        raise CodexTransportMutationError("Git endpoint must be an object")
    base = _endpoint_base(
        endpoint["snapshot"],
        endpoint["tree"],
        endpoint["claim_coverage"],
        endpoint["claim_authority"],
    )
    snapshot = base["snapshot"]
    return {
        "git_head_sha256": _sha(str(snapshot["current_head"]).encode("ascii")),
        "git_tree_sha256": _sha(str(base["tree"]["tree"]).encode("ascii")),
        "git_status_sha256": str(snapshot["snapshot_sha256"]),
        "claim_coverage_sha256": _claim_binding_digest(
            base["claim_coverage"], base["claim_authority"]
        ),
    }


def _persist_json(paths: HarnessPaths, task_id: str, value: Mapping[str, Any], label: str) -> dict[str, Any]:
    try:
        return artifacts.preserve_generated_artifact_blob(
            paths, task_id, _canonical(value, label), label=label, max_bytes=MAX_MUTATION_RECORD_BYTES
        )
    except HarnessError as exc:
        raise _fail(f"cannot persist {label}", exc) from exc


def _read_json(paths: HarnessPaths, task_id: str, digest: str, label: str) -> dict[str, Any]:
    _sha_text(digest, f"{label} CAS SHA-256")
    path = artifacts.artifact_blob_path(paths, task_id, digest)
    try:
        _path, raw = artifacts.read_regular_artifact(path, label, max_bytes=MAX_MUTATION_RECORD_BYTES)
        if _sha(raw) != digest:
            raise CodexTransportMutationError(f"{label} CAS bytes are missing or tampered")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or _canonical(value, label) != raw:
            raise CodexTransportMutationError(f"{label} CAS bytes are not canonical")
        return value
    except (HarnessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail(f"cannot materialize {label}", exc) from exc


def preserve_git_endpoint(
    paths: HarnessPaths,
    *,
    task_id: str,
    endpoint: Mapping[str, Any],
    claims: Sequence[Mapping[str, Any]],
    sealed_claim_scope: bool = False,
) -> dict[str, Any]:
    """Validate and preserve one exact endpoint in task-local content storage."""

    checked = validate_git_endpoint(
        endpoint, claims, sealed_claim_scope=sealed_claim_scope
    )
    return _persist_json(paths, task_id, checked, "pre Git endpoint")


def load_preserved_git_endpoint(
    paths: HarnessPaths,
    *,
    task_id: str,
    cas_sha256: str,
    claims: Sequence[Mapping[str, Any]],
    sealed_claim_scope: bool = False,
) -> dict[str, Any]:
    """Read back and fully validate a Chief-bound endpoint CAS object."""

    value = _read_json(paths, task_id, cas_sha256, "pre Git endpoint")
    return validate_git_endpoint(
        value, claims, sealed_claim_scope=sealed_claim_scope
    )


def materialize_verified_mutation(
    paths: HarnessPaths,
    *,
    task_id: str,
    intent: Mapping[str, Any],
    reservation: Mapping[str, Any],
    journal: Sequence[Mapping[str, Any]],
    runtime_terminal_receipt: Mapping[str, Any],
    pre_endpoint: Mapping[str, Any],
    post_endpoint: Mapping[str, Any],
    claims: Sequence[Mapping[str, Any]],
    sealed_claim_scope: bool = False,
) -> dict[str, Any]:
    """Persist evidence and create a verified receipt only after all checks pass.

    The caller must hold the normal Chief/state lock before object publication.
    No reusable Chief credential is accepted or retained here.

    ``pre_endpoint`` must be created directly by :func:`capture_git_endpoint`
    at the Chief-side launch boundary; it is historical evidence and must not
    be re-captured after the runtime turn.  In contrast, this function captures
    ``post_endpoint`` again immediately before CAS publication and rejects any
    after-image drift.
    """

    try:
        checked_intent = contracts.validate_launch_intent(intent)
        if checked_intent["sandbox"] != "workspaceWrite":
            raise CodexTransportMutationError(
                "verified mutation requires a workspaceWrite launch intent"
            )
        checked_reservation = contracts.validate_reservation_against_intent(reservation, checked_intent)
        checked_runtime = contracts.validate_terminal_receipt_against_journal(runtime_terminal_receipt, journal)
        if checked_runtime["terminal_state"] != "completed" or checked_runtime["evidence_level"] != "codex_runtime_observed":
            raise CodexTransportMutationError("only a completed runtime-observed terminal receipt may be elevated")
        pre = validate_git_endpoint(pre_endpoint, claims, sealed_claim_scope=sealed_claim_scope)
        post = validate_git_endpoint(post_endpoint, claims, sealed_claim_scope=sealed_claim_scope)
        _worktree_for_intent(pre["snapshot"], checked_intent)
        _worktree_for_intent(post["snapshot"], checked_intent)
        if endpoint_pre_git_binding(pre) != checked_intent["pre_git_binding"]:
            raise CodexTransportMutationError("pre Git endpoint does not match launch intent source/tree binding")
        # The supplied post endpoint may have been valid at capture time but
        # become stale before its bytes reach CAS.  Re-capture exactly once at
        # publication time, using the sealed baseline and task-local claims;
        # no attempted recovery or merge is safe here.
        recaptured_post = capture_git_endpoint(
            task_id,
            Path(str(post["snapshot"]["worktree"])),
            str(post["snapshot"]["baseline_head"]),
            claims,
        )
        if _canonical(recaptured_post, "recaptured post Git endpoint") != _canonical(post, "supplied post Git endpoint"):
            raise CodexTransportMutationError("post Git endpoint drifted before CAS publication")
        journal_state = contracts.validate_transport_journal(journal)
        if checked_runtime["journal_head_sha256"] != journal_state.head_sha256:
            raise CodexTransportMutationError("terminal receipt does not bind the supplied journal")
        claim_endpoints = {
            "schema": CLAIM_ENDPOINT_SCHEMA,
            "task_id": task_id,
            "pre_endpoint_sha256": pre["endpoint_sha256"],
            "post_endpoint_sha256": post["endpoint_sha256"],
            "pre_claim_coverage": pre["claim_coverage"],
            "post_claim_coverage": post["claim_coverage"],
            "pre_claim_authority": pre["claim_authority"],
            "post_claim_authority": post["claim_authority"],
        }
        if task_id != checked_intent["task_id"] or pre["task_id"] != task_id or post["task_id"] != task_id:
            raise CodexTransportMutationError("mutation evidence task identity does not match launch intent")
        pre_snapshot_ref = _persist_json(paths, task_id, pre["snapshot"], "pre Git snapshot")
        post_snapshot_ref = _persist_json(paths, task_id, post["snapshot"], "post Git snapshot")
        coverage_ref = _persist_json(paths, task_id, claim_endpoints, "claim endpoint coverage")
        pre_tree_ref = _persist_json(paths, task_id, pre["tree"], "pre Git tree")
        post_tree_ref = _persist_json(paths, task_id, post["tree"], "post Git tree")
        payload = contracts.validate_mutation_verification_payload({
            "contract_type": "codex_mutation_verification_v1",
            "launch_intent_sha256": checked_intent["intent_sha256"],
            "reservation_sha256": checked_reservation["reservation_sha256"],
            "journal_head_sha256": journal_state.head_sha256,
            "pre_git_snapshot": {"cas_sha256": pre_snapshot_ref["sha256"], "content_type": "git_snapshot"},
            "post_git_snapshot": {"cas_sha256": post_snapshot_ref["sha256"], "content_type": "git_snapshot"},
            "claim_coverage": {"cas_sha256": coverage_ref["sha256"], "content_type": "claim_coverage"},
            "pre_git_tree": {"cas_sha256": pre_tree_ref["sha256"], "content_type": "git_tree"},
            "post_git_tree": {"cas_sha256": post_tree_ref["sha256"], "content_type": "git_tree"},
        })
        wrapped = objects.create_semantic_object(
            object_type="codex_mutation_verification", task_id=task_id,
            object_identity=f"{checked_intent['intent_sha256']}:{journal_state.head_sha256}", payload=payload,
        )
        objects.publish_semantic_object(paths, wrapped)
        verified = contracts.seal_terminal_receipt({
            **{key: checked_runtime[key] for key in (
                "contract_type", "reservation_sha256", "journal_head_sha256", "terminal_state", "correlation"
            )},
            "evidence_level": "verified_mutation",
            "mutation_verification": {"status": "referenced", "object_sha256": wrapped["object_sha256"]},
        })
        return {
            "mutation_verification": payload,
            "semantic_object": wrapped,
            "verified_terminal_receipt": verified,
            "task_completion": "not_inferred",
        }
    except (HarnessError, contracts.CodexTransportContractError, objects.SemanticObjectError, KeyError, TypeError) as exc:
        raise _fail("cannot materialize verified Codex mutation", exc) from exc


def validate_materialized_mutation(
    paths: HarnessPaths,
    *,
    task_id: str,
    semantic_object: Mapping[str, Any],
    verified_terminal_receipt: Mapping[str, Any],
    intent: Mapping[str, Any],
    reservation: Mapping[str, Any],
    journal: Sequence[Mapping[str, Any]],
    claims: Sequence[Mapping[str, Any]],
    sealed_claim_scope: bool = False,
) -> dict[str, Any]:
    """Read CAS bytes back and falsify any drift before accepting promotion."""

    try:
        wrapped = objects.validate_semantic_object(semantic_object)
        if wrapped["object_type"] != "codex_mutation_verification" or wrapped["task_id"] != task_id:
            raise CodexTransportMutationError("mutation verification object identity is invalid")
        payload = contracts.validate_mutation_verification_payload(wrapped["payload"])
        checked_intent = contracts.validate_launch_intent(intent)
        checked_reservation = contracts.validate_reservation_against_intent(reservation, checked_intent)
        state = contracts.validate_transport_journal(journal)
        verified = contracts.validate_terminal_receipt_against_journal(verified_terminal_receipt, journal)
        if (
            verified["evidence_level"] != "verified_mutation"
            or verified["mutation_verification"]["object_sha256"] != wrapped["object_sha256"]
            or verified["reservation_sha256"] != checked_reservation["reservation_sha256"]
            or payload["launch_intent_sha256"] != checked_intent["intent_sha256"]
            or payload["reservation_sha256"] != checked_reservation["reservation_sha256"]
            or payload["journal_head_sha256"] != state.head_sha256
        ):
            raise CodexTransportMutationError("verified mutation receipt is not correlated to exact runtime evidence")
        pre_snapshot = _read_json(paths, task_id, payload["pre_git_snapshot"]["cas_sha256"], "pre Git snapshot")
        post_snapshot = _read_json(paths, task_id, payload["post_git_snapshot"]["cas_sha256"], "post Git snapshot")
        pre_tree = _read_json(paths, task_id, payload["pre_git_tree"]["cas_sha256"], "pre Git tree")
        post_tree = _read_json(paths, task_id, payload["post_git_tree"]["cas_sha256"], "post Git tree")
        coverage = _read_json(paths, task_id, payload["claim_coverage"]["cas_sha256"], "claim endpoint coverage")
        if not isinstance(coverage, dict) or set(coverage) != {
            "schema", "task_id", "pre_endpoint_sha256", "post_endpoint_sha256",
            "pre_claim_coverage", "post_claim_coverage", "pre_claim_authority",
            "post_claim_authority"
        } or coverage.get("schema") != CLAIM_ENDPOINT_SCHEMA or coverage.get("task_id") != task_id:
            raise CodexTransportMutationError("claim endpoint coverage record is invalid")
        pre_base = _endpoint_base(
            pre_snapshot,
            pre_tree,
            coverage["pre_claim_coverage"],
            coverage["pre_claim_authority"],
        )
        pre = {
            **pre_base,
            "endpoint_sha256": _sha(_canonical(pre_base, "Git endpoint")),
        }
        post_base = _endpoint_base(
            post_snapshot,
            post_tree,
            coverage["post_claim_coverage"],
            coverage["post_claim_authority"],
        )
        post = {
            **post_base,
            "endpoint_sha256": _sha(_canonical(post_base, "Git endpoint")),
        }
        if pre["endpoint_sha256"] != coverage["pre_endpoint_sha256"] or post["endpoint_sha256"] != coverage["post_endpoint_sha256"]:
            raise CodexTransportMutationError("claim endpoint coverage hashes do not bind CAS endpoints")
        validate_git_endpoint(pre, claims, sealed_claim_scope=sealed_claim_scope)
        validate_git_endpoint(post, claims, sealed_claim_scope=sealed_claim_scope)
        _worktree_for_intent(pre_snapshot, checked_intent)
        _worktree_for_intent(post_snapshot, checked_intent)
        if endpoint_pre_git_binding(pre) != checked_intent["pre_git_binding"]:
            raise CodexTransportMutationError("materialized pre Git endpoint does not match launch intent")
        return {"object_sha256": wrapped["object_sha256"], "task_completion": "not_inferred"}
    except (HarnessError, contracts.CodexTransportContractError, objects.SemanticObjectError, KeyError, TypeError) as exc:
        raise _fail("materialized Codex mutation validation failed", exc) from exc


def inspect_verified_mutation_commit(
    paths: HarnessPaths,
    *,
    task_id: str,
    launch_id: str,
    event_chain: Sequence[Mapping[str, Any]],
    claims: Sequence[Mapping[str, Any]],
    sealed_claim_scope: bool = False,
) -> dict[str, Any]:
    """Inspect one binding-backed mutation elevation without inferring completion."""

    try:
        launch = runtime.load_codex_transport_launch(
            paths, task_id, launch_id, event_chain
        )
        report = objects.inspect_semantic_objects(paths, task_id, event_chain)
        bindings = [
            item
            for item in report["bindings"]
            if item["binding_kind"] == "codex_mutation_verification"
            and item["binding_key"] == launch_id
            and item["classification"] in {"pending", "committed"}
        ]
        if not bindings:
            return {
                "status": "absent",
                "task_id": task_id,
                "launch_id": launch_id,
                "task_completion": "not_inferred",
            }
        if len(bindings) != 1:
            raise CodexTransportMutationError(
                "mutation verification binding is ambiguous"
            )
        binding = bindings[0]
        if binding["classification"] == "pending":
            return {
                "status": "pending",
                "task_id": task_id,
                "launch_id": launch_id,
                "binding_sha256": binding["binding_sha256"],
                "task_completion": "not_inferred",
            }
        by_sha = {item["object_sha256"]: item for item in report["objects"]}
        referenced = [by_sha[digest] for digest in binding["object_sha256s"]]
        mutation_objects = [
            item for item in referenced
            if item["object_type"] == "codex_mutation_verification"
        ]
        verified_receipts = [
            item for item in referenced
            if item["object_type"] == "codex_transport_receipt"
            and item["payload"].get("receipt_kind") == "terminal"
            and item["payload"]["receipt"].get("evidence_level") == "verified_mutation"
        ]
        if len(mutation_objects) != 1 or len(verified_receipts) != 1:
            raise CodexTransportMutationError(
                "mutation verification binding does not name exact evidence objects"
            )
        mutation_object = {
            key: mutation_objects[0][key]
            for key in (
                "schema_version",
                "object_type",
                "task_id",
                "object_identity",
                "payload",
                "payload_sha256",
                "object_sha256",
            )
        }
        verified_receipt = verified_receipts[0]["payload"]["receipt"]
        if launch["verified_terminal_receipt"] != verified_receipt:
            raise CodexTransportMutationError(
                "runtime inspection and mutation binding disagree on verified receipt"
            )
        validated = validate_materialized_mutation(
            paths,
            task_id=task_id,
            semantic_object=mutation_object,
            verified_terminal_receipt=verified_receipt,
            intent=launch["intent"],
            reservation=launch["reservation"],
            journal=launch["journal"],
            claims=claims,
            sealed_claim_scope=sealed_claim_scope,
        )
        projected = semantic.projection_domain(semantic.replay_events(event_chain))
        namespace = _mutation_namespace(projected.get(CODEX_MUTATION_NAMESPACE_KEY))
        row = namespace["launches"].get(launch_id)
        expected_row = {
            "launch_id": launch_id,
            "mutation_object_sha256": mutation_object["object_sha256"],
            "verified_receipt_sha256": verified_receipt["receipt_sha256"],
            "journal_head_sha256": verified_receipt["journal_head_sha256"],
        }
        if row != expected_row:
            raise CodexTransportMutationError(
                "verified mutation projection row differs from committed objects"
            )
        return {
            "status": "committed",
            "task_id": task_id,
            "launch_id": launch_id,
            "binding_sha256": binding["binding_sha256"],
            "semantic_object": mutation_object,
            "verified_terminal_receipt": verified_receipt,
            "object_sha256": validated["object_sha256"],
            "task_completion": "not_inferred",
        }
    except CodexTransportMutationError:
        raise
    except (
        HarnessError,
        contracts.CodexTransportContractError,
        objects.SemanticObjectError,
        runtime.CodexTransportRuntimeError,
        KeyError,
        TypeError,
    ) as exc:
        raise _fail("cannot inspect verified Codex mutation", exc) from exc


def commit_verified_mutation(
    paths: HarnessPaths,
    *,
    task_id: str,
    launch_id: str,
    event_chain: Sequence[Mapping[str, Any]],
    pre_endpoint: Mapping[str, Any],
    post_endpoint: Mapping[str, Any],
    claims: Sequence[Mapping[str, Any]],
    sealed_claim_scope: bool = False,
) -> dict[str, Any]:
    """CAS, bind, and semantically commit one verified-mutation elevation.

    The runtime-observed receipt remains the transport row's terminal fact.
    This separate no-op semantic transition binds the stronger mutation object
    and its derived verified receipt without changing task state or claiming
    task completion.
    """

    h._require_chief_lock(paths)
    try:
        records, _state, _head = runtime._live_records(
            paths, task_id, event_chain
        )
        existing = inspect_verified_mutation_commit(
            paths,
            task_id=task_id,
            launch_id=launch_id,
            event_chain=records,
            claims=claims,
            sealed_claim_scope=sealed_claim_scope,
        )
        if existing["status"] == "committed":
            return {**existing, "idempotent_replay": True}
        launch = runtime.load_codex_transport_launch(
            paths, task_id, launch_id, records
        )
        runtime_receipt = launch["terminal_receipt"]
        if runtime_receipt is None:
            raise CodexTransportMutationError(
                "mutation verification requires a committed runtime terminal receipt"
            )
        materialized = materialize_verified_mutation(
            paths,
            task_id=task_id,
            intent=launch["intent"],
            reservation=launch["reservation"],
            journal=launch["journal"],
            runtime_terminal_receipt=runtime_receipt,
            pre_endpoint=pre_endpoint,
            post_endpoint=post_endpoint,
            claims=claims,
            sealed_claim_scope=sealed_claim_scope,
        )
        verified_receipt = materialized["verified_terminal_receipt"]
        receipt_object = objects.create_semantic_object(
            object_type="codex_transport_receipt",
            task_id=task_id,
            object_identity=f"{launch_id}:verified:{verified_receipt['receipt_sha256']}",
            payload={"receipt_kind": "terminal", "receipt": verified_receipt},
        )
        objects.publish_semantic_object(paths, receipt_object)
        content_sha256 = semantic.canonical_sha256(
            {
                "mutation_object_sha256": materialized["semantic_object"]["object_sha256"],
                "verified_receipt_sha256": verified_receipt["receipt_sha256"],
            }
        )
        marker = runtime._read_marker(
            paths, task_id, launch["reservation"]["permit_sha256"]
        )
        command_id, recorded_at = runtime._derived_transition_identity(
            marker,
            ordinal=len(launch["journal"]) + 2,
            kind="mutation",
            content_sha256=content_sha256,
        )
        base_records, base_state, base_head = runtime._transition_base(
            records, command_id
        )
        domain = semantic.projection_domain(base_state)
        namespace = _mutation_namespace(domain.get(CODEX_MUTATION_NAMESPACE_KEY))
        if launch_id in namespace["launches"]:
            raise CodexTransportMutationError(
                "verified mutation launch already exists in retry base"
            )
        if len(namespace["launches"]) >= MAX_VERIFIED_MUTATIONS:
            raise CodexTransportMutationError(
                "verified mutation namespace reached its launch bound"
            )
        namespace["launches"][launch_id] = {
            "launch_id": launch_id,
            "mutation_object_sha256": materialized["semantic_object"]["object_sha256"],
            "verified_receipt_sha256": verified_receipt["receipt_sha256"],
            "journal_head_sha256": verified_receipt["journal_head_sha256"],
        }
        domain[CODEX_MUTATION_NAMESPACE_KEY] = _mutation_namespace(namespace)
        planned = semantic.create_transition_event(
            base_records[-1],
            base_state,
            domain,
            event_type="codex_transport_verified_mutation",
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=f"codex-transport:{launch_id}",
        )
        binding = objects.create_semantic_binding(
            binding_kind="codex_mutation_verification",
            task_id=task_id,
            binding_key=launch_id,
            expected_semantic_head_sha256=base_head,
            planned_event_sha256=planned["event_sha256"],
            result_projection_sha256=semantic.canonical_sha256(domain),
            object_sha256s=sorted(
                [
                    materialized["semantic_object"]["object_sha256"],
                    receipt_object["object_sha256"],
                ]
            ),
        )
        objects.publish_semantic_binding(paths, binding, records)
        result = store.append_semantic_transition(
            paths,
            task_id,
            domain,
            event_type="codex_transport_verified_mutation",
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=f"codex-transport:{launch_id}",
            expected_head_sha256=base_head,
        )
        committed = inspect_verified_mutation_commit(
            paths,
            task_id=task_id,
            launch_id=launch_id,
            event_chain=store.load_semantic_events(paths, task_id),
            claims=claims,
            sealed_claim_scope=sealed_claim_scope,
        )
        if committed["status"] != "committed":
            raise CodexTransportMutationError(
                "mutation verification semantic commit is not observable"
            )
        return {
            **committed,
            "semantic_event_sha256": result.event["event_sha256"],
            "idempotent_replay": result.idempotent_replay,
        }
    except CodexTransportMutationError:
        raise
    except (
        HarnessError,
        contracts.CodexTransportContractError,
        objects.SemanticObjectError,
        store.SemanticStoreError,
        runtime.CodexTransportRuntimeError,
        semantic.SemanticEventError,
        KeyError,
        TypeError,
    ) as exc:
        raise _fail("cannot commit verified Codex mutation", exc) from exc


__all__ = [
    "CLAIM_ENDPOINT_SCHEMA", "CODEX_MUTATION_NAMESPACE_KEY", "CODEX_MUTATION_NAMESPACE_VERSION",
    "GIT_ENDPOINT_SCHEMA", "GIT_TREE_SCHEMA", "LEGACY_GIT_ENDPOINT_SCHEMA",
    "MAX_GIT_TREE_OUTPUT_BYTES", "MAX_MUTATION_RECORD_BYTES",
    "CodexTransportMutationError", "capture_git_endpoint", "commit_verified_mutation",
    "endpoint_pre_git_binding", "inspect_verified_mutation_commit",
    "load_preserved_git_endpoint", "materialize_verified_mutation",
    "preserve_git_endpoint", "validate_git_endpoint", "validate_materialized_mutation",
]
