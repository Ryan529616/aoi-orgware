"""Parser registration for verification-record and legacy-recovery commands.

Handlers are injected by the CLI composition root.  This module therefore
defines command syntax without importing the monolithic CLI or verification
state-machine handlers.  ``VERIFICATION_CATEGORIES`` is a per-project mutable
CLI global (reassignable by ``apply_project_config``), so it arrives only via
the injected ``ParserVocabulary`` snapshot; ``VERIFICATION_STATUSES`` is a
static ``harnesslib`` constant and is imported directly.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import Any

from ..harnesslib import VERIFICATION_STATUSES


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "reconcile",
        "add_verification",
        "materialize_artifacts",
        "packet_input_recover_from_tar",
        "verification_supersede",
        "verification_supersession_seal",
    }
)


def register_verification_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the verification-record command family on one subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "verification command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("reconcile")
    parser.add_argument("--task", required=True)
    parser.add_argument("--observations")
    parser.add_argument("--observations-sha")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["reconcile"])

    parser = subparsers.add_parser("add-verification")
    parser.add_argument("--task", required=True)
    parser.add_argument(
        "--category", choices=sorted(vocab.verification_categories), required=True
    )
    parser.add_argument(
        "--status", choices=sorted(VERIFICATION_STATUSES), required=True
    )
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--lane-id")
    parser.add_argument("--artifact-ref", action="append", default=[])
    parser.add_argument(
        "--exact-test-receipt",
        action="append",
        default=[],
        metavar="ABSOLUTE-PATH=SHA256",
        help=(
            "bind exactly one canonical exact-test receipt; requires one "
            "--exact-test-log"
        ),
    )
    parser.add_argument(
        "--exact-test-log",
        action="append",
        default=[],
        metavar="ABSOLUTE-PATH=SHA256",
        help=(
            "bind exactly one separately retained exact-test combined log; "
            "requires one --exact-test-receipt"
        ),
    )
    parser.add_argument(
        "--exact-test-require-github-matrix",
        action="store_true",
        help=(
            "require the exact-test receipt to contain its complete GitHub "
            "matrix identity"
        ),
    )
    parser.add_argument(
        "--semantic-command-id",
        help=(
            "stable idempotency key required when recording exact-test "
            "evidence on a semantic-v2 task"
        ),
    )
    parser.add_argument(
        "--semantic-expected-head-sha256",
        help=(
            "exact semantic ledger head required when recording exact-test "
            "evidence on a semantic-v2 task"
        ),
    )
    parser.add_argument(
        "--semantic-recorded-at",
        help=(
            "caller-stable timezone-aware event time required for crash-safe "
            "semantic exact-test retry"
        ),
    )
    parser.add_argument("--review-packet-id")
    parser.add_argument(
        "--asserts-completion-boundary",
        action="store_true",
        help=(
            "declare that this passing verification covers the task's "
            "registered completion boundary itself (required once for an "
            "achieved close)"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["add_verification"])

    parser = subparsers.add_parser(
        "materialize-artifacts",
        help="snapshot still-valid legacy packet and verification artifacts",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument(
        "--verification-index", type=int, action="append", default=[]
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["materialize_artifacts"])

    parser = subparsers.add_parser(
        "packet-input-recover-from-tar",
        help="recover one drifted legacy done-packet input from a bound tar member",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--packet-id", required=True)
    parser.add_argument("--input-index", type=int, required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    parser.add_argument("--carrier-input-index", type=int, required=True)
    parser.add_argument("--carrier-sha256", required=True)
    parser.add_argument("--archive-member", required=True)
    parser.add_argument("--expected-result-sha256", required=True)
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["packet_input_recover_from_tar"])

    parser = subparsers.add_parser(
        "verification-supersede",
        help="retire one exact legacy verification in favor of a later valid pass",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--verification-index", type=int, required=True)
    parser.add_argument("--expected-record-sha256", required=True)
    parser.add_argument("--replacement-index", type=int, required=True)
    parser.add_argument("--replacement-record-sha256", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--semantic-command-id",
        help="stable idempotency key required for semantic-v2 supersession",
    )
    parser.add_argument(
        "--semantic-expected-head-sha256",
        help="exact semantic ledger head required for semantic-v2 supersession",
    )
    parser.add_argument(
        "--semantic-recorded-at",
        help="caller-stable timezone-aware semantic-v2 supersession time",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["verification_supersede"])

    parser = subparsers.add_parser(
        "verification-supersession-seal",
        help="seal a legacy supersession against its exact canonical replacement",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--verification-index", type=int, required=True)
    parser.add_argument("--expected-current-record-sha256", required=True)
    parser.add_argument("--expected-source-record-sha256", required=True)
    parser.add_argument("--replacement-index", type=int, required=True)
    parser.add_argument(
        "--expected-replacement-before-materialize-sha256", required=True
    )
    parser.add_argument("--expected-replacement-current-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["verification_supersession_seal"])


__all__ = ["register_verification_commands"]
