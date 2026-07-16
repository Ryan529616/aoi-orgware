"""Narrow recovery for AOI-owned atomic-publication temporary files."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    get_paths,
    preflight_layout,
    recover_atomic_temporaries,
    scan_atomic_temporaries,
    state_lock,
)


Handler = Callable[[argparse.Namespace, HarnessPaths], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]
ChiefAuthorizer = Callable[[argparse.Namespace, HarnessPaths], None]
LockedPathReloader = Callable[[HarnessPaths], HarnessPaths]


@dataclass(frozen=True)
class TemporaryRecoveryServices:
    """Composition-root policy required before managed-state recovery."""

    authorize_chief: ChiefAuthorizer
    reload_locked_paths: LockedPathReloader


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def cmd_recover_temporaries(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: TemporaryRecoveryServices,
) -> int:
    """Chief-fence recovery after strict canonical-lock preflight."""

    preflight_layout(paths, allow_recoverable_nonlock_aliases=True)
    current = get_paths(paths.root)
    if (
        current.project.sha256 != paths.project.sha256
        or current.harness != paths.harness
        or current.lock != paths.lock
    ):
        raise HarnessError("aoi.toml changed before temporary recovery")
    paths = current
    preflight_layout(paths, allow_recoverable_nonlock_aliases=True)
    with state_lock(
        paths,
        create_layout=False,
        allow_recoverable_nonlock_aliases=True,
    ):
        paths = services.reload_locked_paths(paths)
        before = scan_atomic_temporaries(paths)
        recovered = []
        if before:
            services.authorize_chief(args, paths)
            recovered = recover_atomic_temporaries(paths, before)
        remaining = scan_atomic_temporaries(paths)
        if remaining:
            raise HarnessError(
                "temporary recovery did not converge under the project state lock"
            )
        payload = {
            "ok": True,
            "authority_boundary": (
                "every state-tree residue deletion requires the current Chief credential; "
                "linked state locks require explicit offline/manual recovery"
            ),
            "recovered": [record.as_dict(paths) for record in recovered],
            "remaining": [],
        }
    emit(payload, args.json)
    return 0


def register_temporary_recovery_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    expected = {"recover_temporaries"}
    missing = sorted(expected - handlers.keys())
    unexpected = sorted(handlers.keys() - expected)
    if missing or unexpected:
        raise ValueError(
            "temporary recovery handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )
    parser = subparsers.add_parser(
        "recover-temporaries",
        help="remove only exact AOI atomic-publication residues under the state lock",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["recover_temporaries"])
