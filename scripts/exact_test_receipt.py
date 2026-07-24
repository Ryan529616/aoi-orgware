#!/usr/bin/env python3
"""Run pytest from a clean Git snapshot and publish an exact-test receipt."""
from __future__ import annotations
import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import sys

# Keep the checked-out helper directly runnable without depending on an
# editable install.  The subprocess still receives only the snapshot's src.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from aoi_orgware.exact_test_receipts import ExactTestReceiptError, ReceiptPublicationError, run_clean_commit_source_tree


def _strict_json_object(raw: str) -> Mapping[str, object]:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ExactTestReceiptError(f"GitHub matrix JSON has duplicate key: {key}")
            result[key] = value
        return result
    try:
        parsed = json.loads(raw, object_pairs_hook=no_duplicates, parse_constant=lambda value: (_ for _ in ()).throw(ExactTestReceiptError(f"GitHub matrix JSON has forbidden constant: {value}")))
    except json.JSONDecodeError as exc:
        raise ExactTestReceiptError(f"GitHub matrix JSON is invalid: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise ExactTestReceiptError("GitHub matrix JSON must be one object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--logs-dir", required=True, type=Path)
    parser.add_argument("--pytest-arg", action="append", default=[], help="One literal pytest argument; repeat, never a shell command (use --pytest-arg=-q for option values)")
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--github-matrix-json")
    parser.add_argument("--require-github-matrix", action="store_true")
    args = parser.parse_args(argv)
    try:
        matrix = _strict_json_object(args.github_matrix_json) if args.github_matrix_json else None
        receipt = run_clean_commit_source_tree(repo=args.repo, pytest_argv=args.pytest_arg, receipt_path=args.receipt, logs_dir=args.logs_dir, timeout_seconds=args.timeout_seconds, github_matrix_identity=matrix, require_github_matrix=args.require_github_matrix, invoker_path=Path(__file__))
    except (ExactTestReceiptError, ReceiptPublicationError, json.JSONDecodeError) as exc:
        print(f"exact_test_receipt: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
