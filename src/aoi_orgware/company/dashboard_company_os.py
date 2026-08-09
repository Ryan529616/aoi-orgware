"""Hash-bound packaged assets for the read-only Company OS shell."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from http import HTTPStatus
import importlib.resources
import json
import re
from typing import NamedTuple, Protocol


_MANIFEST_NAME = "asset-manifest.json"
_MANIFEST_SHA256 = (
    "204b26730a466e85c1f9f467eda9786db3c0d2e3ad45aaf2fe34bb0b4fbf9c15"
)
_FROZEN_V8_RECEIPT_SHA256 = (
    "3beba7750581c45e6e22213a04ea45771e0b43a0e2679cb6c200392d5b5063f0"
)
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_ASSET_BYTES = 2 * 1024 * 1024
_MAX_ASSETS = 256
_SAFE_PART = re.compile(r"^[A-Za-z0-9._-]+$")
_CONTENT_TYPES = frozenset(
    {
        "text/html; charset=utf-8",
        "text/javascript; charset=utf-8",
        "text/css; charset=utf-8",
        "image/svg+xml",
        "font/woff",
        "font/woff2",
    },
)


class CompanyOsAssetError(RuntimeError):
    """A packaged Company OS asset cannot be trusted or read safely."""


class CompanyOsAssetNotFound(CompanyOsAssetError):
    """A request does not name one manifested Company OS asset."""


class CompanyOsAsset(NamedTuple):
    payload: bytes
    content_type: str


class _DashboardAssetWriter(Protocol):
    def _write_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        *,
        content_type: str,
    ) -> None: ...

    def _error(
        self,
        status: HTTPStatus,
        code: str,
        detail: str,
    ) -> None: ...


class _ManifestEntry(NamedTuple):
    path: str
    size_bytes: int
    sha256: str
    content_type: str


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _safe_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise CompanyOsAssetError(f"{label} is invalid")
    if (
        value.startswith("/")
        or "\\" in value
        or "%" in value
        or "?" in value
        or "#" in value
    ):
        raise CompanyOsAssetError(f"{label} is unsafe")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or _SAFE_PART.fullmatch(part) is None for part in parts):
        raise CompanyOsAssetError(f"{label} is unsafe")
    return value


def _manifest_entries() -> dict[str, _ManifestEntry]:
    resource = importlib.resources.files("aoi_orgware.resources").joinpath(
        "dashboard_company_os",
        _MANIFEST_NAME,
    )
    try:
        raw = resource.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise CompanyOsAssetError("installed package is missing the Company OS manifest") from exc
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise CompanyOsAssetError("Company OS manifest size is invalid")
    if hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA256:
        raise CompanyOsAssetError("Company OS manifest digest differs from packaged code")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CompanyOsAssetError("Company OS manifest is not valid JSON") from exc
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "frozen_v8_receipt_sha256",
        "files",
    }:
        raise CompanyOsAssetError("Company OS manifest fields are invalid")
    if _canonical_json(value) != raw:
        raise CompanyOsAssetError("Company OS manifest is not canonical")
    if value["schema_version"] != 1:
        raise CompanyOsAssetError("Company OS manifest schema is unsupported")
    if value["frozen_v8_receipt_sha256"] != _FROZEN_V8_RECEIPT_SHA256:
        raise CompanyOsAssetError("Company OS frozen source receipt differs")
    files = value["files"]
    if (
        not isinstance(files, Sequence)
        or isinstance(files, (str, bytes, bytearray))
        or not files
        or len(files) > _MAX_ASSETS
    ):
        raise CompanyOsAssetError("Company OS manifest file inventory is invalid")
    result: dict[str, _ManifestEntry] = {}
    previous = ""
    for index, item in enumerate(files):
        if not isinstance(item, Mapping) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
            "content_type",
        }:
            raise CompanyOsAssetError("Company OS manifest entry fields are invalid")
        path = _safe_path(item["path"], label=f"Company OS manifest path {index}")
        if path <= previous or path in result:
            raise CompanyOsAssetError("Company OS manifest paths are not strictly ordered")
        previous = path
        size = item["size_bytes"]
        digest = item["sha256"]
        content_type = item["content_type"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or size > _MAX_ASSET_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or content_type not in _CONTENT_TYPES
        ):
            raise CompanyOsAssetError("Company OS manifest entry metadata is invalid")
        result[path] = _ManifestEntry(path, size, digest, str(content_type))
    if "index.html" not in result:
        raise CompanyOsAssetError("Company OS manifest does not name index.html")
    return result


def company_os_asset(path: str) -> CompanyOsAsset:
    """Read one allowlisted asset and verify its bytes from the same resource."""

    try:
        safe = _safe_path(path, label="Company OS request path")
    except CompanyOsAssetError as exc:
        raise CompanyOsAssetNotFound("Company OS asset is not allowlisted") from exc
    entries = _manifest_entries()
    entry = entries.get(safe)
    if entry is None:
        raise CompanyOsAssetNotFound("Company OS asset is not allowlisted")
    resource = importlib.resources.files("aoi_orgware.resources").joinpath(
        "dashboard_company_os",
        *safe.split("/"),
    )
    try:
        payload = resource.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise CompanyOsAssetError("installed package is missing a manifested Company OS asset") from exc
    if len(payload) != entry.size_bytes or hashlib.sha256(payload).hexdigest() != entry.sha256:
        raise CompanyOsAssetError("Company OS asset bytes differ from the packaged manifest")
    return CompanyOsAsset(payload, entry.content_type)


def legacy_console_html() -> bytes:
    resource = importlib.resources.files("aoi_orgware.resources").joinpath(
        "dashboard", "index.html"
    )
    try:
        payload = resource.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise CompanyOsAssetError(
            "installed package is missing the Command Center asset"
        ) from exc
    if not payload or len(payload) > 1024 * 1024:
        raise CompanyOsAssetError("Command Center asset size is invalid")
    return payload


def serve_company_os(writer: _DashboardAssetWriter, path: str) -> bool:
    if path in {"/company-os", "/company-os/", "/company-os/index.html"}:
        asset_path = "index.html"
    elif path.startswith("/company-os/"):
        asset_path = path.removeprefix("/company-os/")
    else:
        return False
    try:
        asset = company_os_asset(asset_path)
    except CompanyOsAssetNotFound:
        writer._error(
            HTTPStatus.NOT_FOUND,
            "not_found",
            "unknown read-only Company OS asset",
        )
        return True
    except CompanyOsAssetError:
        writer._error(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "company_os_asset_integrity_failed",
            "installed Company OS assets failed integrity validation",
        )
        return True
    writer._write_bytes(HTTPStatus.OK, asset.payload, content_type=asset.content_type)
    return True


def company_os_manifest_sha256() -> str:
    """Expose the code-bound manifest identity for package/readback tests."""

    return _MANIFEST_SHA256
