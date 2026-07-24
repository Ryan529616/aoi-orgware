from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest


_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "refresh_codex_app_server_schema.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "refresh_codex_app_server_schema", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
refresh = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(refresh)


def _bundle(
    root: Path,
    *,
    reverse_order: bool = False,
    changed: bool = False,
) -> None:
    root.mkdir()
    (root / "v2").mkdir()
    if reverse_order:
        combined = b'{"definitions":{"B":{"type":"string"},"A":{"type":"object"}},"title":"v2"}'
        leaf = b'{"required":["value"],"properties":{"value":{"type":"integer"}},"type":"object"}'
    else:
        combined = b'{"title":"v2","definitions":{"A":{"type":"object"},"B":{"type":"string"}}}'
        leaf = b'{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}'
    if changed:
        leaf = leaf.replace(b'"integer"', b'"string"')
    (root / refresh.COMBINED_V2_PATH).write_bytes(combined)
    (root / "v2" / "Leaf.json").write_bytes(leaf)


def test_independent_key_order_drift_has_one_canonical_identity(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _bundle(first)
    _bundle(second, reverse_order=True)

    first_result = refresh.canonicalize_schema_directory(
        first.resolve(), expected_file_count=2
    )
    second_result = refresh.canonicalize_schema_directory(
        second.resolve(), expected_file_count=2
    )

    assert first_result == second_result
    manifest, combined, summary = first_result
    assert json.loads(manifest) == [
        {
            "path": refresh.COMBINED_V2_PATH,
            "sha256": summary["combined_v2_schema_sha256"],
            "size": summary["combined_v2_schema_size"],
        },
        {
            "path": "v2/Leaf.json",
            "sha256": json.loads(manifest)[1]["sha256"],
            "size": json.loads(manifest)[1]["size"],
        },
    ]
    assert combined == (
        b'{"definitions":{"A":{"type":"object"},"B":{"type":"string"}},'
        b'"title":"v2"}'
    )


def test_semantic_drift_between_generator_runs_fails_closed(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _bundle(first)
    _bundle(second, reverse_order=True, changed=True)

    with pytest.raises(refresh.SchemaRefreshError, match="semantically"):
        refresh.compare_schema_directories(
            first.resolve(), second.resolve(), expected_file_count=2
        )


def test_linked_input_root_is_rejected_before_resolution(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    _bundle(target)
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    assert linked.is_symlink()
    with pytest.raises(refresh.SchemaRefreshError, match="non-link"):
        refresh.canonicalize_schema_directory(linked, expected_file_count=2)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_native_windows_junction_root_is_rejected_before_resolution(
    tmp_path: Path,
) -> None:
    target = tmp_path / "junction-target"
    _bundle(target)
    junction = tmp_path / "junction-root"
    completed = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(target),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        pytest.skip(
            "could not create a bounded native Windows junction: "
            + completed.stderr.decode(errors="replace")
        )
    try:
        assert refresh._is_link_or_reparse(junction)
        with pytest.raises(refresh.SchemaRefreshError, match="non-reparse"):
            refresh.canonicalize_schema_directory(
                junction, expected_file_count=2
            )
    finally:
        os.rmdir(junction)


@pytest.mark.parametrize(
    "raw",
    (
        b'{"type":"object","type":"object"}',
        b'{"value":NaN}',
        b"\xff",
    ),
)
def test_duplicate_nonfinite_and_non_utf8_json_are_rejected(raw: bytes) -> None:
    with pytest.raises(refresh.SchemaRefreshError):
        refresh.canonical_json_bytes(raw, label="bad.json")


def test_output_pair_is_atomic_and_requires_exact_expected_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _bundle(first)
    _bundle(second, reverse_order=True)
    manifest = tmp_path / "manifest.json"
    combined = tmp_path / "combined.json"
    monkeypatch.setattr(refresh, "EXPECTED_FILE_COUNT", 2)
    generated = refresh.canonicalize_schema_directory(
        first.resolve(), expected_file_count=2
    )
    monkeypatch.setattr(refresh, "EXPECTED_MANIFEST_SIZE", len(generated[0]))
    monkeypatch.setattr(
        refresh,
        "EXPECTED_MANIFEST_SHA256",
        generated[2]["manifest_sha256"],
    )
    monkeypatch.setattr(refresh, "EXPECTED_COMBINED_SIZE", len(generated[1]))
    monkeypatch.setattr(
        refresh,
        "EXPECTED_COMBINED_SHA256",
        generated[2]["combined_v2_schema_sha256"],
    )
    monkeypatch.setattr(
        refresh,
        "compare_schema_directories",
        lambda _first, _second: generated,
    )

    status = refresh.main(
        [
            "--first",
            str(first.resolve()),
            "--second",
            str(second.resolve()),
            "--manifest-out",
            str(manifest.resolve()),
            "--combined-out",
            str(combined.resolve()),
            "--json",
        ]
    )

    assert status == 0
    assert manifest.read_bytes() == generated[0]
    assert combined.read_bytes() == generated[1]
