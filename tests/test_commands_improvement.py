#!/usr/bin/env python3
"""Relocation contract for the improvement/skill command family (Wave D5).

The ``improvement-*`` and ``skill-*`` command bodies moved from the monolithic
``cli`` into :mod:`aoi_orgware.commands.improvement`.  ``improvement-create``,
``improvement-arbitrate``, ``improvement-link-project``, ``skill-release-record``
and ``skill-adoption-record`` carry a frozen :class:`ImprovementCmdServices`
injected from the composition root; ``improvement-brief`` depends on no
composition-root concern and stays a bare ``(args, paths)`` handler (a pure
verbatim move).

Like the capacity family, no improvement body is fault-injected via
``mock.patch.object(cli, ...)``: the suite's ``write_task``/``write_index``/
``state_lock`` patches drive only init/chief-acquire/observe_subagent_start/
codex-config-rollback, never an ``improvement-*``/``skill-*`` command.  The only
coupling to ``cli`` is that the six threaded helpers (``require_plan_ready``,
``require_root_session``, ``read_regular_artifact``, ``_records_fingerprint``,
``_require_done_reviewer_packet``, ``_skill_release_semantic_integrity_errors``)
remain defined in ``cli`` -- shared with the capacity/packet/portfolio wiring and
other command families -- and are injected here as direct-bound services.  These
tests pin that contract so a future regression that moves the helpers or swaps
the wiring is caught.
"""

from __future__ import annotations

import ast
import argparse
import dataclasses
import functools
import sys
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import improvement as improvement_cmds  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "improvement.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "aoi_orgware.cli" for alias in node.names):
                    violations.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"cli", "aoi_orgware.cli"} or any(
                    alias.name == "cli" for alias in node.names
                ):
                    violations.append(f"{path.name}:{node.lineno}")
        self.assertEqual(violations, [])


class RelocationContractTests(unittest.TestCase):
    RELOCATED = (
        "cmd_improvement_create",
        "cmd_improvement_brief",
        "cmd_improvement_arbitrate",
        "cmd_improvement_link_project",
        "cmd_skill_release_record",
        "cmd_skill_adoption_record",
    )
    SERVICE_WIRED = {
        "improvement-create": "cmd_improvement_create",
        "improvement-arbitrate": "cmd_improvement_arbitrate",
        "improvement-link-project": "cmd_improvement_link_project",
        "skill-release-record": "cmd_skill_release_record",
        "skill-adoption-record": "cmd_skill_adoption_record",
    }
    BARE_WIRED = {
        "improvement-brief": "cmd_improvement_brief",
    }

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(improvement_cmds, name),
                f"cli re-export {name} is not the relocated object",
            )

    def _choices(self) -> dict[str, object]:
        parser = cli_impl.build_parser()
        subactions = [
            a
            for a in parser._actions  # noqa: SLF001
            if a.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        return subactions[0].choices

    def test_build_parser_wires_service_bodies_as_partials(self) -> None:
        choices = self._choices()
        for command, body_name in self.SERVICE_WIRED.items():
            body = getattr(improvement_cmds, body_name)
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"],
                improvement_cmds.ImprovementCmdServices,
            )

    def test_build_parser_wires_serviceless_bodies_as_bare_handlers(self) -> None:
        choices = self._choices()
        for command, body_name in self.BARE_WIRED.items():
            body = getattr(improvement_cmds, body_name)
            handler = choices[command].get_default("handler")
            self.assertIs(handler, body)
            self.assertNotIsInstance(handler, functools.partial)

    def test_module_leaf_helpers_are_module_local(self) -> None:
        # emit/require_text/require_evidence_detail are pure leaf helpers
        # redeclared inside the command module; the relocated bodies must bind the
        # module-local copies, never reach back into cli.
        self.assertIsNot(improvement_cmds.emit, cli_impl.emit)
        self.assertIsNot(improvement_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(
            improvement_cmds.require_evidence_detail,
            cli_impl.require_evidence_detail,
        )


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._improvement_cmd_services()
        self.assertIsInstance(services, improvement_cmds.ImprovementCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.require_plan_ready = None  # type: ignore[misc]

    def test_direct_bound_callables_are_the_cli_resident_objects(self) -> None:
        # Every service field is direct-bound to the CLI-resident object (no name
        # is fault-injected via mock.patch.object(cli, ...), so no late binding).
        services = cli_impl._improvement_cmd_services()
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.require_root_session, cli_impl.require_root_session)
        self.assertIs(services.read_regular_artifact, cli_impl.read_regular_artifact)

    def test_shared_helpers_stay_in_cli_single_source(self) -> None:
        # _records_fingerprint / _require_done_reviewer_packet /
        # _skill_release_semantic_integrity_errors are shared with the
        # capacity/packet/portfolio wiring and other command families, so cli
        # remains their single source of truth; the services inject the same
        # objects rather than redefining them.
        services = cli_impl._improvement_cmd_services()
        self.assertIs(services.records_fingerprint, cli_impl._records_fingerprint)
        self.assertIs(
            services.require_done_reviewer_packet,
            cli_impl._require_done_reviewer_packet,
        )
        self.assertIs(
            services.skill_release_semantic_integrity_errors,
            cli_impl._skill_release_semantic_integrity_errors,
        )


class NewReleaseIdentityTests(unittest.TestCase):
    def test_new_skill_release_reviewer_uses_shared_identity_contract(self) -> None:
        for reviewer in (
            "/root/reviewer",
            "operator@example.invalid",
            "/" + "a" * 511,
        ):
            with self.subTest(reviewer=reviewer):
                self.assertEqual(
                    improvement_cmds._new_release_reviewer_agent_id(reviewer),
                    reviewer,
                )

        for reviewer in (
            "legacy reviewer",
            "reviewer+identity",
            "審查者",
            "/" + "a" * 512,
            ["/root/reviewer"],
        ):
            with self.subTest(reviewer=reviewer), self.assertRaisesRegex(
                HarnessError, "create a new reviewer packet"
            ):
                improvement_cmds._new_release_reviewer_agent_id(reviewer)

    def test_invalid_release_metadata_fails_before_snapshot_capability(self) -> None:
        base = {
            "release_id": "release-1",
            "skill_id": "skill-1",
            "bundle_sha256": "a" * 64,
            "skill_version": "0.4.0",
            "maintenance_owner": "operator@example.invalid",
            "rollback_plan": "Restore the exact previously adopted skill bundle bytes",
        }
        invalid_cases = (
            {"skill_version": ""},
            {"maintenance_owner": ""},
            {"rollback_plan": "short"},
        )
        for changes in invalid_cases:
            args = argparse.Namespace(**{**base, **changes})
            with self.subTest(changes=changes), mock.patch.object(
                improvement_cmds, "state_lock"
            ) as lock, self.assertRaises(HarnessError):
                improvement_cmds.cmd_skill_release_record(
                    args,
                    mock.sentinel.paths,
                    services=cli_impl._improvement_cmd_services(),
                )
            lock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
