#!/usr/bin/env python3
"""Parser contract for the extracted temporary-recovery command."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware.commands.temporary_recovery import (
    register_temporary_recovery_commands,
)


class TemporaryRecoveryCommandRegistryTests(unittest.TestCase):
    def parser(self, handlers: dict[str, object]) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        register_temporary_recovery_commands(
            subparsers,
            handlers=handlers,
            add_json_argument=lambda item: item.add_argument(
                "--json", action="store_true"
            ),
        )
        return parser

    def test_registry_injects_handler_and_accepts_json(self) -> None:
        handler = object()
        args = self.parser({"recover_temporaries": handler}).parse_args(
            ["recover-temporaries", "--json"]
        )
        self.assertIs(args.handler, handler)
        self.assertTrue(args.json)

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        with self.assertRaisesRegex(ValueError, "temporary recovery handler map"):
            self.parser({})
        with self.assertRaisesRegex(ValueError, "temporary recovery handler map"):
            self.parser({"recover_temporaries": object(), "extra": object()})


if __name__ == "__main__":
    unittest.main(verbosity=2)
