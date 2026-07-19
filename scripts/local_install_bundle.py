#!/usr/bin/env python3
"""Create and verify a reviewed local-install bundle without publication actions."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from aoi_orgware import local_install_proof as proof  # noqa: E402


def _write_create_only(path: Path, value: Mapping[str, Any]) -> None:
    data = proof._canonical(dict(value))
    path = Path(os.path.abspath(path))
    if path.exists() or path.is_symlink():
        raise proof.LocalInstallProofError("create-only output already exists")
    parent = path.parent
    if not parent.exists():
        existing = parent
        while not existing.exists():
            if existing.parent == existing:
                raise proof.LocalInstallProofError("output path has no existing parent")
            existing = existing.parent
        proof._secure_directory(existing, "output ancestor")
        parent.mkdir(parents=True, exist_ok=True)
    proof._secure_directory(parent, "output parent")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _read(path: Path, label: str) -> dict[str, Any]:
    return proof._read_json(path, label, canonical=True)[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source_manifest = commands.add_parser("source-manifest")
    source_manifest.add_argument("--source-root", required=True, type=Path); source_manifest.add_argument("--output", required=True, type=Path)
    rehearsal = commands.add_parser("rehearsal-report")
    rehearsal.add_argument("--source-root", required=True, type=Path); rehearsal.add_argument("--store-root", required=True, type=Path)
    rehearsal.add_argument("--inventory", required=True); rehearsal.add_argument("--source-manifest", default="evidence/source-file-manifest.json"); rehearsal.add_argument("--tool-lock", default="requirements/release-tools.lock")
    rehearsal.add_argument("--producer-test-summary", required=True); rehearsal.add_argument("--output", required=True, type=Path)
    subject = commands.add_parser("subject")
    subject.add_argument("--source-root", required=True, type=Path); subject.add_argument("--store-root", required=True, type=Path)
    subject.add_argument("--inventory", required=True); subject.add_argument("--rehearsal", required=True)
    subject.add_argument("--source-manifest", default="evidence/source-file-manifest.json"); subject.add_argument("--tool-lock", default="requirements/release-tools.lock")
    subject.add_argument("--output", required=True, type=Path)
    review = commands.add_parser("review")
    review.add_argument("--subject-file", required=True, type=Path); review.add_argument("--reviewer", required=True); review.add_argument("--reviewed-at", required=True)
    review.add_argument("--outcome", required=True, choices=("PASS", "FAIL")); review.add_argument("--clean", action="store_true"); review.add_argument("--limitation", action="append", required=True)
    review.add_argument("--output", required=True, type=Path)
    seal = commands.add_parser("seal")
    seal.add_argument("--source-root", required=True, type=Path); seal.add_argument("--store-root", required=True, type=Path)
    seal.add_argument("--subject-file", required=True, type=Path); seal.add_argument("--review-file", required=True, type=Path); seal.add_argument("--sealed-at", required=True); seal.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle-file", required=True, type=Path); verify.add_argument("--expected-sha256", required=True); verify.add_argument("--source-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "source-manifest":
            result = proof.create_source_manifest(args.source_root); _write_create_only(args.output, result)
        elif args.command == "rehearsal-report":
            result = proof.create_rehearsal_report(source_root=args.source_root, store_root=args.store_root, inventory_path=args.inventory, source_manifest_path=args.source_manifest, tool_lock_path=args.tool_lock, producer_test_summary=args.producer_test_summary); _write_create_only(args.output, result)
        elif args.command == "subject":
            result = proof.create_subject(source_root=args.source_root, store_root=args.store_root, inventory_path=args.inventory, rehearsal_path=args.rehearsal, source_manifest_path=args.source_manifest, tool_lock_path=args.tool_lock); _write_create_only(args.output, result)
        elif args.command == "review":
            result = proof.create_review_assertion(subject=_read(args.subject_file, "subject file"), reviewer=args.reviewer, reviewed_at=args.reviewed_at, outcome=args.outcome, clean=args.clean, limitations=args.limitation); _write_create_only(args.output, result)
        elif args.command == "seal":
            result = proof.seal_bundle(source_root=args.source_root, store_root=args.store_root, subject=_read(args.subject_file, "subject file"), review_assertion=_read(args.review_file, "review file"), sealed_at=args.sealed_at); _write_create_only(args.output, result)
        else:
            loaded = proof.load_local_install_bundle(args.bundle_file, args.expected_sha256, verify_store=True)
            result = proof.verify_bundle(source_root=args.source_root, store_root=Path(loaded["subject"]["artifact_store_root"]), bundle=loaded, expected_sha256=args.expected_sha256) if args.source_root else {"ok": True, "kind": loaded["kind"], "proof_scope": loaded["proof_scope"], "bundle_sha256": loaded["bundle_sha256"], "subject_sha256": loaded["subject"]["subject_sha256"]}
        sys.stdout.buffer.write(proof._canonical(result) + b"\n")
    except (OSError, proof.LocalInstallProofError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
