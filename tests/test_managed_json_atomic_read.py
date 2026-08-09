"""AOI-SYNTHETIC-FIXTURE-V1 managed JSON atomic-read race tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aoi_orgware import harnesslib as h


class ManagedJsonAtomicReadTests(unittest.TestCase):
    def _assert_link_count_failure(self, link_count: int, message: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = (Path(directory) / "state.json").resolve()
            destination.write_text("{}\n", encoding="utf-8")
            metadata = destination.lstat()
            observed = mock.Mock(st_mode=metadata.st_mode, st_nlink=link_count)
            with (
                mock.patch.object(
                    h,
                    "canonicalize_no_link_traversal",
                    return_value=destination,
                ),
                mock.patch.object(Path, "lstat", return_value=observed),
                self.assertRaisesRegex(h.HarnessError, message),
            ):
                h.load_json(destination)

    def test_zero_link_metadata_is_a_raced_read(self) -> None:
        self._assert_link_count_failure(0, "changed while being read")

    def test_stable_hard_link_metadata_remains_rejected(self) -> None:
        self._assert_link_count_failure(2, "must be a private regular file")


if __name__ == "__main__":
    unittest.main()
