from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

from aoi_orgware import codex_install_provenance as provenance


def _record_with_hashless_row(
    tmp_path: Path, candidate: Path
) -> tuple[Path, Path]:
    site_root = tmp_path / "prefix" / "site-packages"
    dist_info = site_root / "aoi_orgware-1.2.3.dist-info"
    dist_info.mkdir(parents=True)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"bytecode")
    relative = os.path.relpath(candidate, site_root).replace("\\", "/")
    (dist_info / "RECORD").write_text(f"{relative},,\n", encoding="utf-8")
    return dist_info, site_root


def test_hashless_record_row_outside_site_packages_fails_typed(
    tmp_path: Path,
) -> None:
    tag = sys.implementation.cache_tag
    assert isinstance(tag, str) and tag
    candidate = tmp_path / "external-cache" / "__pycache__" / f"module.{tag}.pyc"
    dist_info, site_root = _record_with_hashless_row(tmp_path, candidate)

    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="hashless entry lies outside site-packages",
    ):
        provenance._record(dist_info, site_root)


def test_hashless_canonical_cache_inside_site_packages_remains_admissible(
    tmp_path: Path,
) -> None:
    tag = sys.implementation.cache_tag
    assert isinstance(tag, str) and tag
    candidate = (
        tmp_path
        / "prefix"
        / "site-packages"
        / "aoi_orgware"
        / "__pycache__"
        / f"module.{tag}.pyc"
    )
    dist_info, site_root = _record_with_hashless_row(tmp_path, candidate)

    assert provenance._record(dist_info, site_root) == {}
