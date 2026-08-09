"""Exact provenance and file-governance exclusions for Company OS assets."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Literal


FROZEN_V8_RECEIPT_SHA256 = (
    "3beba7750581c45e6e22213a04ea45771e0b43a0e2679cb6c200392d5b5063f0"
)
_RESOURCE_ROOT = "src/aoi_orgware/resources/dashboard_company_os/"
_MANIFEST_PATH = _RESOURCE_ROOT + "asset-manifest.json"
_SAFE_ASSET = re.compile(r"^(?:assets/[A-Za-z0-9._-]+|favicon\.svg|index\.html)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_ASSETS = 256
ExclusionKind = Literal["generated", "runtime", "vendor"]


class DashboardAssetGovernanceError(ValueError):
    """The package-bound Company OS asset inventory is not trustworthy."""


@dataclass(frozen=True, slots=True)
class ExactExclusionSpec:
    path: str
    kind: ExclusionKind
    reason: str
    self_unbound: bool = False


_BASE_SPECS = (
    ExactExclusionSpec(
        "src/aoi_orgware/resources/codex_app_server/0.145.0/"
        "codex_app_server_protocol.v2.schemas.json",
        "generated",
        "provider-generated protocol schema pinned by runtime receipt",
    ),
    ExactExclusionSpec(
        "src/aoi_orgware/resources/codex_app_server/0.145.0/schema-manifest.json",
        "generated",
        "provider-generated protocol member manifest",
    ),
    ExactExclusionSpec(
        "src/aoi_orgware/resources/company/file-governance-baseline-v1.json",
        "generated",
        "self-describing deterministic file-governance baseline",
        True,
    ),
)
_PINNED_SPECS: tuple[tuple[str, str, ExclusionKind, str], ...] = (
    (
        "frontend/company-os/package-lock.json",
        "df623b833af123a668f185e35e4782d863ce9979eaffa50d287396eeab8120ec",
        "generated",
        "reviewed npm lock after Company OS toolchain security qualification",
    ),
    (
        "frontend/company-os/src/styles.css",
        "3e901d658698a70cbe6bd26b4d4e6485f8da9bad786b2564e960cbeff2f2b24c",
        "vendor",
        "immutable visual stylesheet from frozen Company OS V8 contract",
    ),
)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DashboardAssetGovernanceError("duplicate asset manifest key")
        result[key] = value
    return result


def _manifest_files(data: bytes) -> tuple[tuple[str, int, str], ...]:
    if len(data) > _MAX_MANIFEST_BYTES:
        raise DashboardAssetGovernanceError("asset manifest exceeds byte bound")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DashboardAssetGovernanceError("asset manifest is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "frozen_v8_receipt_sha256", "files"
    }:
        raise DashboardAssetGovernanceError("asset manifest keys do not match")
    if (
        value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
        or value["frozen_v8_receipt_sha256"] != FROZEN_V8_RECEIPT_SHA256
        or not isinstance(value["files"], list)
        or not 1 <= len(value["files"]) <= _MAX_ASSETS
    ):
        raise DashboardAssetGovernanceError("asset manifest identity is invalid")
    result: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    for raw in value["files"]:
        if not isinstance(raw, dict) or set(raw) != {
            "path", "size_bytes", "sha256", "content_type"
        }:
            raise DashboardAssetGovernanceError("asset record keys do not match")
        path, size, digest = raw["path"], raw["size_bytes"], raw["sha256"]
        if (
            not isinstance(path, str)
            or not _SAFE_ASSET.fullmatch(path)
            or path.casefold() in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(digest, str)
            or not _HEX64.fullmatch(digest)
            or not isinstance(raw["content_type"], str)
        ):
            raise DashboardAssetGovernanceError("asset record is invalid")
        seen.add(path.casefold())
        result.append((path, size, digest))
    ordered = tuple(sorted(result, key=lambda item: item[0].encode("utf-8")))
    if tuple(result) != ordered:
        raise DashboardAssetGovernanceError("asset records are not ordinal-sorted")
    return ordered


def exact_exclusion_specs(
    files: Mapping[str, bytes] | None = None,
) -> tuple[ExactExclusionSpec, ...]:
    """Return base rules plus exact V8 vendor and generated-file inventory."""

    if files is None or _MANIFEST_PATH not in files:
        return _BASE_SPECS
    for path, expected, _kind, _reason in _PINNED_SPECS:
        data = files.get(path)
        if data is None or sha256(data).hexdigest() != expected:
            raise DashboardAssetGovernanceError(
                "pinned Company OS provenance differs"
            )
    generated = _manifest_files(files[_MANIFEST_PATH])
    expected_generated = {_MANIFEST_PATH}
    specs = [*_BASE_SPECS]
    for path, size, digest in generated:
        full_path = _RESOURCE_ROOT + path
        data = files.get(full_path)
        if data is None or len(data) != size or sha256(data).hexdigest() != digest:
            raise DashboardAssetGovernanceError("generated asset identity differs")
        expected_generated.add(full_path)
        specs.append(ExactExclusionSpec(
            full_path,
            "generated",
            "package-bound Company OS asset in frozen manifest",
        ))
    actual_generated = {path for path in files if path.startswith(_RESOURCE_ROOT)}
    if actual_generated != expected_generated:
        raise DashboardAssetGovernanceError(
            "generated Company OS subtree differs from exact manifest inventory"
        )
    specs.append(ExactExclusionSpec(
        _MANIFEST_PATH,
        "generated",
        "package-bound Company OS asset manifest",
    ))
    specs.extend(
        ExactExclusionSpec(path, kind, reason)
        for path, _digest, kind, reason in _PINNED_SPECS
    )
    return tuple(sorted(specs, key=lambda item: item.path.encode("utf-8")))


__all__ = [
    "DashboardAssetGovernanceError",
    "ExactExclusionSpec",
    "FROZEN_V8_RECEIPT_SHA256",
    "exact_exclusion_specs",
]
