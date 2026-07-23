"""CLI boundary for selective confidentiality and exact export permits."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Callable

from .. import confidentiality as confidentiality_policy
from .. import external_exports
from .. import harnesslib as h
from .. import publication_policy


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        import json

        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
        return
    print(payload)


def cmd_external_export_permit_issue(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    authority = getattr(args, "_aoi_chief_authority", None)
    if not isinstance(authority, dict):
        raise h.HarnessError(
            "external export permit issuance requires validated Chief authority"
        )
    result = external_exports.issue_external_export_permit(
        paths,
        task_id=args.task,
        export_id=args.export_id,
        source_file=Path(args.source_file),
        expected_content_sha256=args.expected_content_sha256,
        destination=args.destination,
        purpose=args.purpose,
        expires_at=args.expires_at,
        chief_authority=authority,
        current_time=datetime.now(timezone.utc),
    )
    _emit(result, args.json)
    return 0


def cmd_external_export_permit_consume(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    with h.state_lock(paths, create_layout=False):
        if not paths.config.is_file():
            raise h.HarnessError(
                "aoi.toml disappeared while acquiring the external-export state lock"
            )
        current = h.get_paths(paths.root)
        if (
            current.project.sha256 != paths.project.sha256
            or current.harness != paths.harness
            or current.lock != paths.lock
        ):
            raise h.HarnessError(
                "aoi.toml changed while acquiring the external-export state lock"
            )
        result = external_exports.consume_external_export_permit(
            current,
            task_id=args.task,
            permit_sha256=args.permit_sha256,
            source_file=Path(args.source_file),
            destination=args.destination,
            purpose=args.purpose,
            current_time=datetime.now(timezone.utc),
        )
    _emit(result, args.json)
    return 0


def cmd_confidentiality_git_push_preflight(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    root = paths.root
    if args.task:
        state = h.load_task(paths, args.task)
        root = h.validated_state_worktree(paths, state)
    snapshot_path = root / "release" / "publication-policy.json"
    if snapshot_path.is_file():
        try:
            snapshot = publication_policy.load_publication_policy_snapshot(
                snapshot_path
            )
            publication_policy.require_current_publication_policy_snapshot(
                root,
                paths.project.confidentiality,
                paths.project.sha256,
                snapshot,
            )
        except publication_policy.PublicationPolicyError as exc:
            raise h.HarnessError(str(exc)) from exc
    result = confidentiality_policy.preflight_git_push(
        root=root,
        policy=paths.project.confidentiality,
        config_sha256=paths.project.sha256,
        remote=args.remote,
        destination=args.destination,
        updates=args.update,
    )
    _emit(result, args.json)
    return 0


def cmd_confidentiality_policy_snapshot(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    """Emit the canonical tracked publication snapshot from live local authority."""

    del args
    snapshot = publication_policy.build_publication_policy_snapshot(
        paths.root,
        paths.project.confidentiality,
        paths.project.sha256,
    )
    sys.stdout.buffer.write(
        publication_policy.canonical_publication_policy_snapshot_bytes(snapshot)
    )
    return 0


def cmd_confidentiality_publication_preflight(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    result = confidentiality_policy.preflight_publication_paths(
        root=paths.root,
        policy=paths.project.confidentiality,
        config_sha256=paths.project.sha256,
        action=args.action,
        destination=args.destination,
        subject_paths=args.subject,
        remote=args.remote,
    )
    if args.json:
        sys.stdout.buffer.write(
            json.dumps(
                result,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )
    else:
        _emit(result, False)
    return 0


def register_confidentiality_commands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    handlers: dict[str, Callable[..., int]],
    add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    git_preflight = sub.add_parser(
        "confidentiality-git-push-preflight",
        help=(
            "inspect an exact outgoing Git update before push and deny protected "
            "files/trees sent outside their configured repository"
        ),
    )
    git_preflight.add_argument("--remote", required=True)
    git_preflight.add_argument("--destination", required=True)
    git_preflight.add_argument(
        "--task",
        help=(
            "inspect the recorded isolated worktree for this task while retaining "
            "the canonical AOI policy/config binding"
        ),
    )
    git_preflight.add_argument(
        "--update",
        action="append",
        nargs=4,
        required=True,
        metavar=("LOCAL_REF", "LOCAL_SHA", "REMOTE_REF", "REMOTE_SHA"),
        help=(
            "one exact pre-push update tuple; repeat for every ref update and "
            "use the all-zero object id for a missing side"
        ),
    )
    add_json_argument(git_preflight)
    git_preflight.set_defaults(
        handler=handlers["confidentiality_git_push_preflight"]
    )

    snapshot = sub.add_parser(
        "confidentiality-policy-snapshot",
        help=(
            "emit the canonical release publication snapshot from the current "
            "selective protected-file policy and exact local content identities"
        ),
    )
    snapshot.set_defaults(handler=handlers["confidentiality_policy_snapshot"])

    publication_preflight = sub.add_parser(
        "confidentiality-publication-preflight",
        help=(
            "inventory exact files/archive members and deny protected bytes sent "
            "outside their configured destination"
        ),
    )
    publication_preflight.add_argument(
        "--action",
        required=True,
        choices=(
            "remote_ci",
            "release_publish",
            "package_publish",
            "artifact_upload",
            "attachment_publish",
            "connector_publish",
        ),
    )
    publication_preflight.add_argument("--destination", required=True)
    publication_preflight.add_argument("--remote")
    publication_preflight.add_argument(
        "--subject",
        action="append",
        required=True,
        help="regular file or directory to inventory; repeat for every input",
    )
    add_json_argument(publication_preflight)
    publication_preflight.set_defaults(
        handler=handlers["confidentiality_publication_preflight"]
    )

    issue = sub.add_parser(
        "external-export-permit-issue",
        help=(
            "Chief-issue one local-only permit for an exact file, destination, "
            "purpose, and expiry"
        ),
    )
    issue.add_argument("--task", required=True)
    issue.add_argument("--export-id", required=True)
    issue.add_argument("--source-file", required=True)
    issue.add_argument("--expected-content-sha256", required=True)
    issue.add_argument("--destination", required=True)
    issue.add_argument("--purpose", required=True)
    issue.add_argument("--expires-at", required=True)
    add_json_argument(issue)
    issue.set_defaults(handler=handlers["external_export_permit_issue"])

    consume = sub.add_parser(
        "external-export-permit-consume",
        help=(
            "spend one exact permit before export; only fresh_consumption=true "
            "authorizes the caller to act"
        ),
    )
    consume.add_argument("--task", required=True)
    consume.add_argument("--permit-sha256", required=True)
    consume.add_argument("--source-file", required=True)
    consume.add_argument("--destination", required=True)
    consume.add_argument("--purpose", required=True)
    add_json_argument(consume)
    consume.set_defaults(handler=handlers["external_export_permit_consume"])


__all__ = [
    "cmd_confidentiality_git_push_preflight",
    "cmd_confidentiality_policy_snapshot",
    "cmd_confidentiality_publication_preflight",
    "cmd_external_export_permit_consume",
    "cmd_external_export_permit_issue",
    "register_confidentiality_commands",
]
