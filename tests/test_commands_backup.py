#!/usr/bin/env python3
"""Relocation contract for the backup command family (Wave D1).

The ``backup-state``/``verify-backup`` command bodies and their archive helpers
moved from the monolithic ``cli`` into :mod:`aoi_orgware.commands.backup`.  This
family carries *zero* fault-injected services, so the load-bearing proof of the
relocation is object identity: the composition root must wire the *relocated*
callables (a future regression that leaves a stale copy behind in ``cli`` is
caught here), and the keep-list ``cmd_doctor`` must resolve the relocated
``_check_json_file`` through the module-global import.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import backup as backup_cmds  # noqa: E402


class BackupRelocationContractTests(unittest.TestCase):
    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        self.assertIs(cli_impl.cmd_backup_state, backup_cmds.cmd_backup_state)
        self.assertIs(cli_impl.cmd_verify_backup, backup_cmds.cmd_verify_backup)
        self.assertIs(cli_impl.verify_backup, backup_cmds.verify_backup)
        self.assertIs(cli_impl._check_json_file, backup_cmds._check_json_file)

    def test_build_parser_wires_relocated_backup_handlers(self) -> None:
        parser = cli_impl.build_parser()
        subactions = [
            a
            for a in parser._actions  # noqa: SLF001
            if a.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        choices = subactions[0].choices
        self.assertIs(
            choices["backup-state"].get_default("handler"),
            backup_cmds.cmd_backup_state,
        )
        self.assertIs(
            choices["verify-backup"].get_default("handler"),
            backup_cmds.cmd_verify_backup,
        )

    def test_backup_module_leaf_helpers_are_module_local(self) -> None:
        # emit/require_text are redeclared inside the command module (keep-list
        # leaf helpers stay in cli too); the relocated bodies must bind the
        # module-local copies, never reach back into cli.
        self.assertIsNot(backup_cmds.emit, cli_impl.emit)
        self.assertIsNot(backup_cmds.require_text, cli_impl.require_text)


if __name__ == "__main__":
    unittest.main()
