"""Standalone preflight for a persisted publication-policy snapshot.

The gate does not read AOI configuration, AOI state, or protected origins.
Callers supply the exact snapshot and subjects; the current working directory
is only the explicit filesystem root used to inventory those subjects and
canonicalize a destination.  Snapshot freshness is checked at the local
generation/promotion boundary, because a remote clean checkout may correctly
lack a local-only protected origin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable, Mapping, NoReturn, Sequence

from . import publication_subjects
from .confidentiality import ConfidentialityError, canonical_publication_destination
from .publication_policy import (
    PublicationPolicyError,
    load_publication_policy_snapshot,
    validate_publication_policy_snapshot,
)


_ACTIONS = frozenset(
    {
        "remote_ci", "release_publish", "package_publish",
        "artifact_upload", "attachment_publish", "connector_publish",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REPARSE_POINT = 0x0400
_MAX_RECEIPT_BYTES = 32 * 1024 * 1024


class PublicationGateError(ValueError):
    """The requested publication is not authorized by its snapshot."""


def _fail(message: str) -> NoReturn:
    raise PublicationGateError(message)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _root(value: Path | str) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _fail("project root is invalid")
    root = Path(os.path.abspath(raw))
    try:
        metadata = root.lstat()
    except OSError as exc:
        _fail(f"cannot inspect project root: {exc}")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        _fail("project root must be a non-link directory")
    return root


def _checked_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if snapshot is None:
        _fail("policy snapshot is required")
    try:
        return validate_publication_policy_snapshot(snapshot)
    except PublicationPolicyError as exc:
        _fail(str(exc))


def _canonical_destination(destination: str, root: Path) -> str:
    try:
        return canonical_publication_destination(destination, root)
    except ConfidentialityError as exc:
        _fail(str(exc))


def _validate_action(action: Any, remote: Any) -> tuple[str, str]:
    if not isinstance(action, str) or action not in _ACTIONS:
        _fail("publication action is invalid")
    if remote is None:
        return action, ""
    if not isinstance(remote, str) or _REMOTE.fullmatch(remote) is None:
        _fail("publication remote is invalid")
    return action, remote


def _validate_inventory(inventory: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"containers", "subjects", "manifest_sha256"}
    if not isinstance(inventory, Mapping) or set(inventory) != expected:
        _fail("publication inventory schema is invalid")
    containers = inventory["containers"]
    subjects = inventory["subjects"]
    digest = inventory["manifest_sha256"]
    if not isinstance(containers, list) or not isinstance(subjects, list):
        _fail("publication inventory rows are invalid")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        _fail("publication inventory digest is invalid")
    for index, row in enumerate(containers):
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256", "size_bytes"}:
            _fail(f"publication inventory container {index} schema is invalid")
        if (
            not isinstance(row["path"], str)
            or not row["path"]
            or "\\" in row["path"]
            or not isinstance(row["sha256"], str)
            or _SHA256.fullmatch(row["sha256"]) is None
            or type(row["size_bytes"]) is not int
            or row["size_bytes"] < 0
        ):
            _fail(f"publication inventory container {index} is invalid")
    for index, row in enumerate(subjects):
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
            _fail(f"publication inventory subject {index} schema is invalid")
        if (
            not isinstance(row["path"], str)
            or not row["path"]
            or "\\" in row["path"]
            or not isinstance(row["sha256"], str)
            or _SHA256.fullmatch(row["sha256"]) is None
        ):
            _fail(f"publication inventory subject {index} is invalid")
    sorted_containers = sorted(
        (dict(row) for row in containers), key=lambda row: (row["path"].casefold(), row["path"])
    )
    sorted_subjects = sorted(
        (dict(row) for row in subjects),
        key=lambda row: (row["path"].casefold(), row["path"], row["sha256"]),
    )
    if containers != sorted_containers or subjects != sorted_subjects:
        _fail("publication inventory is not normalized")
    if len({(row["path"].casefold(), row["sha256"]) for row in subjects}) != len(subjects):
        _fail("publication inventory has duplicate subjects")
    observed = hashlib.sha256(
        _canonical_bytes({"containers": containers, "subjects": subjects})
    ).hexdigest()
    if observed != digest:
        _fail("publication inventory digest is invalid")
    return {"containers": [dict(row) for row in containers], "subjects": [dict(row) for row in subjects], "manifest_sha256": digest}


def _exposures(
    snapshot: Mapping[str, Any],
    inventory: Mapping[str, Any],
    destination: str,
) -> list[dict[str, str]]:
    digest_rules: dict[str, list[dict[str, Any]]] = {}
    for row in snapshot["protected_content"]:
        digest_rules.setdefault(row["sha256"], []).append(
            next(rule for rule in snapshot["protected_rules"] if rule["path"] == row["rule_path"])
        )
    exposures: list[dict[str, str]] = []
    for subject in inventory["subjects"]:
        matching: dict[str, dict[str, Any]] = {}
        for rule in snapshot["protected_rules"]:
            path = rule["path"].casefold()
            candidate = subject["path"].casefold()
            if candidate == path or (rule["kind"] == "tree" and candidate.startswith(path + "/")):
                matching[rule["path"]] = rule
        for rule in digest_rules.get(subject["sha256"], []):
            matching[rule["path"]] = rule
        for rule_path in sorted(matching, key=lambda item: (item.casefold(), item)):
            rule = matching[rule_path]
            allowed = (
                destination.startswith("file:")
                if rule["policy"] == "local_only"
                # home_remote_only is a Git repository policy.  Its only
                # authorization boundary is the full outgoing-commit
                # confidentiality-git-push-preflight, not this archive/file
                # publication gate.  Caller-supplied --remote metadata must
                # never turn a package, Actions artifact, attachment, or
                # connector upload into a repository push.
                else False
            )
            if not allowed:
                _fail(
                    f"publication would expose protected {rule['kind']} {rule['path']!r} outside its configured policy"
                )
            exposures.append(
                {
                    "subject_path": subject["path"],
                    "subject_sha256": subject["sha256"],
                    "rule_path": rule["path"],
                    "rule_policy": rule["policy"],
                }
            )
    return exposures


def preflight_publication_snapshot(
    *,
    snapshot: Mapping[str, Any],
    root: Path | str,
    action: str,
    destination: str,
    subjects: Iterable[Path | str],
    remote: str | None = None,
) -> dict[str, Any]:
    """Inventory subjects and return an allowed receipt bound to one snapshot."""

    checked_snapshot = _checked_snapshot(snapshot)
    checked_root = _root(root)
    checked_action, checked_remote = _validate_action(action, remote)
    checked_destination = _canonical_destination(destination, checked_root)
    try:
        inventory = _validate_inventory(
            publication_subjects.inventory_publication_subjects(checked_root, subjects)
        )
    except publication_subjects.PublicationSubjectError as exc:
        _fail(str(exc))
    exposures = _exposures(
        checked_snapshot, inventory, checked_destination
    )
    base: dict[str, Any] = {
        "schema_version": 1,
        "policy_snapshot_sha256": checked_snapshot["snapshot_sha256"],
        "action": checked_action,
        "remote": checked_remote,
        "destination": checked_destination,
        "inventory": inventory,
        "protected_exposures": exposures,
        "decision": "allowed",
    }
    return {**base, "receipt_sha256": _digest(base)}


def validate_publication_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the receipt's exact schema and content self-digest."""

    expected = {
        "schema_version", "policy_snapshot_sha256", "action", "remote", "destination",
        "inventory", "protected_exposures", "decision", "receipt_sha256",
    }
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != expected
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 1
    ):
        _fail("publication receipt schema is invalid")
    if (
        not isinstance(receipt.get("policy_snapshot_sha256"), str)
        or _SHA256.fullmatch(receipt["policy_snapshot_sha256"]) is None
        or not isinstance(receipt.get("action"), str)
        or receipt["action"] not in _ACTIONS
        or not isinstance(receipt.get("remote"), str)
        or (receipt["remote"] and _REMOTE.fullmatch(receipt["remote"]) is None)
        or not isinstance(receipt.get("destination"), str)
        or not receipt["destination"]
        or receipt.get("decision") != "allowed"
    ):
        _fail("publication receipt identity is invalid")
    inventory = _validate_inventory(receipt["inventory"])
    exposures = receipt["protected_exposures"]
    if not isinstance(exposures, list):
        _fail("publication receipt exposures are invalid")
    normalized: list[dict[str, str]] = []
    for index, row in enumerate(exposures):
        if not isinstance(row, Mapping) or set(row) != {"subject_path", "subject_sha256", "rule_path", "rule_policy"}:
            _fail(f"publication receipt exposure {index} schema is invalid")
        if (
            not all(isinstance(row[key], str) and row[key] for key in row)
            or _SHA256.fullmatch(row["subject_sha256"]) is None
            or row["rule_policy"] not in {"local_only", "home_remote_only"}
        ):
            _fail(f"publication receipt exposure {index} is invalid")
        normalized.append(dict(row))
    if exposures != sorted(normalized, key=lambda row: (row["subject_path"].casefold(), row["subject_path"], row["subject_sha256"], row["rule_path"].casefold(), row["rule_path"])):
        _fail("publication receipt exposures are not normalized")
    base = {key: receipt[key] for key in expected - {"receipt_sha256"}}
    if not isinstance(receipt.get("receipt_sha256"), str) or receipt["receipt_sha256"] != _digest(base):
        _fail("publication receipt self-digest is invalid")
    return {**base, "inventory": inventory, "protected_exposures": normalized, "receipt_sha256": receipt["receipt_sha256"]}


def _load_json_receipt(path: Path | str) -> dict[str, Any]:
    source = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = source.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            _fail("receipt file must be a regular non-link, non-hardlink file")
        if metadata.st_size < 1 or metadata.st_size > _MAX_RECEIPT_BYTES:
            _fail("receipt file has an invalid size")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
                or opened.st_mtime_ns != metadata.st_mtime_ns
                or opened.st_nlink != metadata.st_nlink
            ):
                _fail("receipt file changed while opening")
            raw = handle.read(_MAX_RECEIPT_BYTES + 1)
            finished = os.fstat(handle.fileno())
        after = source.lstat()
        if (
            len(raw) != metadata.st_size
            or finished.st_dev != metadata.st_dev
            or finished.st_ino != metadata.st_ino
            or finished.st_size != metadata.st_size
            or finished.st_mtime_ns != metadata.st_mtime_ns
            or finished.st_nlink != metadata.st_nlink
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_nlink != metadata.st_nlink
        ):
            _fail("receipt file changed while being read")
    except PublicationGateError:
        raise
    except OSError as exc:
        _fail(f"cannot read receipt file: {exc}")
    try:
        checked = validate_publication_receipt(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"receipt file is not strict JSON: {exc}")
    if raw != _canonical_bytes(checked) + b"\n":
        _fail("receipt file is not canonical JSON")
    return checked


def verify_publication_receipt(
    *,
    snapshot: Mapping[str, Any],
    receipt: Mapping[str, Any],
    root: Path | str,
    action: str,
    destination: str,
    subjects: Iterable[Path | str],
    remote: str | None = None,
) -> dict[str, Any]:
    """Recompute a receipt and require exact equality with the supplied one."""

    supplied = validate_publication_receipt(receipt)
    expected = preflight_publication_snapshot(
        snapshot=snapshot, root=root, action=action, destination=destination,
        subjects=subjects, remote=remote,
    )
    if supplied != expected:
        _fail("publication receipt does not match the exact recomputed receipt")
    return expected


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m aoi_orgware.publication_gate")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--policy-snapshot", required=True)
        command.add_argument("--expected-snapshot-sha256", required=True)
        command.add_argument("--action", required=True)
        command.add_argument("--destination", required=True)
        command.add_argument("--remote")
        command.add_argument("--subject", action="append", required=True)
        command.add_argument("--json", action="store_true")
        if name == "verify":
            command.add_argument("--receipt", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        snapshot = load_publication_policy_snapshot(args.policy_snapshot)
        if (
            not isinstance(args.expected_snapshot_sha256, str)
            or _SHA256.fullmatch(args.expected_snapshot_sha256) is None
            or snapshot["snapshot_sha256"] != args.expected_snapshot_sha256
        ):
            _fail("policy snapshot does not match the caller's trusted expected digest")
        kwargs = {
            "snapshot": snapshot, "root": Path.cwd(), "action": args.action,
            "destination": args.destination, "subjects": args.subject, "remote": args.remote,
        }
        if args.command == "preflight":
            result = preflight_publication_snapshot(**kwargs)
        else:
            result = verify_publication_receipt(
                **kwargs, receipt=_load_json_receipt(args.receipt)
            )
    except (PublicationGateError, PublicationPolicyError) as exc:
        print(f"publication gate: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    else:
        print(result["receipt_sha256"])
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess
    raise SystemExit(main())


__all__ = [
    "PublicationGateError",
    "preflight_publication_snapshot",
    "validate_publication_receipt",
    "verify_publication_receipt",
]
