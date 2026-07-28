"""Deterministic, observation-only file governance for AOI v0.5."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from importlib import resources
import json
import re
from typing import Any, Literal
import unicodedata
FILE_GOVERNANCE_BASELINE_V1 = "FileGovernanceBaselineV1"
BASELINE_RESOURCE_PATH = (
    "src/aoi_orgware/resources/company/file-governance-baseline-v1.json"
)
BASELINE_RESOURCE_PARTS = (
    "resources",
    "company",
    "file-governance-baseline-v1.json",
)
SCOPE_ROOTS = ("docs", "src", "tests")
NEW_FILE_TARGET_LOGICAL_LINES = 800
NEW_FILE_HARD_LOGICAL_LINES = 1500
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SCOPE_BYTES = 128 * 1024 * 1024
SYNTHETIC_FIXTURE_MARKER = "AOI-SYNTHETIC-FIXTURE-V1"

FileCategory = Literal["documentation", "source", "test"]
ExclusionKind = Literal["generated", "runtime", "vendor"]
WriteRefKind = Literal["file", "tree", "output_namespace", "serialization_key"]
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RELEASE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:(?:a|b|rc)(?:0|[1-9][0-9]*))?$"
)
_WINDOWS_RESERVED = frozenset(
    {"aux", "con", "nul", "prn", *(f"com{i}" for i in range(1, 10)),
     *(f"lpt{i}" for i in range(1, 10))}
)
_WINDOWS_HOME = re.compile(
    r"(?i)(?<![A-Za-z0-9])[A-Za-z]:(?:[\\/]+)Users"
    r"(?:[\\/]+)(?P<user>[A-Za-z0-9._-]+)"
    r"(?:(?:[\\/]+)[^\s'\"`<>|]+)*"
)
_POSIX_HOME = re.compile(
    r"(?<![A-Za-z0-9])(?:/(?:home|Users)/(?P<user>[A-Za-z0-9._-]+)|/" r"root(?![A-Za-z0-9._-]))"
    r"(?:/[^\s'\"`<>]+)*"
)
_LICENSE_ENDPOINT = re.compile(
    r"(?<![A-Za-z0-9])(?P<port>[0-9]{1,5})@"
    r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)"
)
_SYNTHETIC_USERS = frozenset({"alice", "bob", "example", "tester", "test-user"})
_WAIVABLE = frozenset(
    {
        "existing_over_target_byte_growth",
        "existing_over_target_line_growth",
        "new_file_target_exceeded",
    }
)
_FILES_KEYS = {
    "category", "content_sha256", "git_mode", "logical_lines", "path",
    "privacy_counts", "size_bytes",
}
_EXCLUSION_KEYS = {
    "self_unbound", "baseline_sha256", "baseline_size_bytes",
    "git_mode", "kind", "path", "reason",
}
class FileGovernanceError(ValueError):
    """A baseline or candidate cannot be interpreted safely."""

@dataclass(frozen=True, slots=True)
class GitBlob:
    mode: Literal["100644", "100755"]
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.mode not in {"100644", "100755"}:
            raise FileGovernanceError("tracked entry must be a regular Git blob")
        if not isinstance(self.data, bytes) or len(self.data) > MAX_FILE_BYTES:
            raise FileGovernanceError("tracked blob exceeds the byte contract")

@dataclass(frozen=True, slots=True)
class GitScopeSnapshot:
    commit_sha1: str
    tree_sha1: str
    files: Mapping[str, GitBlob] = field(repr=False)

@dataclass(frozen=True, slots=True, order=True)
class PrivacyCount:
    rule_id: str
    count: int

@dataclass(frozen=True, slots=True)
class FileSnapshot:
    path: str
    category: FileCategory
    git_mode: str
    size_bytes: int
    logical_lines: int
    content_sha256: str
    privacy_counts: tuple[PrivacyCount, ...]

@dataclass(frozen=True, slots=True)
class ExactExclusionV1:
    """One exact generated/vendor/runtime file, never a prefix or glob."""

    path: str
    kind: ExclusionKind
    reason: str
    self_unbound: bool = False

    def __post_init__(self) -> None:
        path = normalize_repo_path(self.path)
        object.__setattr__(self, "path", path)
        if self.kind not in {"generated", "runtime", "vendor"}:
            raise FileGovernanceError("invalid exact exclusion kind")
        _text_bound(self.reason, "exclusion reason", 12, 512)
        if self.self_unbound and path != BASELINE_RESOURCE_PATH:
            raise FileGovernanceError("only the baseline resource may be self-unbound")

@dataclass(frozen=True, slots=True)
class FileGovernanceWaiverV1:
    """One exact rule/path exception bounded to one release and two maxima."""

    waiver_id: str
    path: str
    rule_id: str
    owner: str
    reason: str
    expires_at: str
    followup: str
    applies_to_release: str
    max_logical_lines: int
    max_size_bytes: int

    def __post_init__(self) -> None:
        _identifier(self.waiver_id, "waiver id")
        object.__setattr__(self, "path", normalize_repo_path(self.path))
        if self.rule_id not in _WAIVABLE:
            raise FileGovernanceError("waiver names a non-waivable rule")
        _text_bound(self.owner, "waiver owner", 2, 128)
        _text_bound(self.reason, "waiver reason", 12, 512)
        _text_bound(self.followup, "waiver followup", 4, 256)
        _parse_utc(self.expires_at)
        if not _RELEASE.fullmatch(self.applies_to_release):
            raise FileGovernanceError("waiver must name exactly one release")
        _plain_int(self.max_logical_lines, "waiver line maximum", minimum=1)
        _plain_int(self.max_size_bytes, "waiver byte maximum", minimum=1)

    def permits(
        self, finding: GovernanceFinding, *, release: str,
        observed_at: datetime, snapshot: FileSnapshot,
    ) -> bool:
        return (
            finding.path == self.path and finding.rule_id == self.rule_id
            and release == self.applies_to_release
            and observed_at < _parse_utc(self.expires_at)
            and snapshot.logical_lines <= self.max_logical_lines
            and snapshot.size_bytes <= self.max_size_bytes
        )

@dataclass(frozen=True, slots=True)
class ImportBoundaryRuleV1:
    """Reserved contract only; no AST gate is claimed in this slice."""

    schema_version: Literal[1]
    rule_id: str
    source_prefix: str
    allowed_import_prefixes: tuple[str, ...]
    forbid_cycles: bool

    def __post_init__(self) -> None:
        if self.schema_version != 1 or not isinstance(self.forbid_cycles, bool):
            raise FileGovernanceError("invalid import-boundary version/flag")
        _identifier(self.rule_id, "import-boundary rule id")
        _module_prefix(self.source_prefix)
        if (
            not self.allowed_import_prefixes
            or tuple(sorted(set(self.allowed_import_prefixes)))
            != self.allowed_import_prefixes
        ):
            raise FileGovernanceError("import prefixes must be sorted and unique")
        for prefix in self.allowed_import_prefixes:
            _module_prefix(prefix)

@dataclass(frozen=True, slots=True)
class ActiveWriteRefV1:
    """Reserved contract only; no dispatch overlap decision is made here."""

    schema_version: Literal[1]
    kind: WriteRefKind
    namespace: str
    canonical_identity: str
    filesystem_semantics: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise FileGovernanceError("invalid write-reference version")
        _identifier(self.namespace, "write-reference namespace")
        if self.kind in {"file", "tree"}:
            identity = normalize_repo_identity(self.canonical_identity)
            if self.filesystem_semantics not in {
                "posix-v1", "windows-win32-v1",
                "wsl-windows-drive-mount-v1",
            }:
                raise FileGovernanceError("invalid filesystem semantics")
        elif self.kind in {"output_namespace", "serialization_key"}:
            identity = _identifier(self.canonical_identity, "opaque identity")
            if self.filesystem_semantics != "opaque-v1":
                raise FileGovernanceError("opaque reference requires opaque-v1")
        else:
            raise FileGovernanceError("invalid write-reference kind")
        object.__setattr__(self, "canonical_identity", identity)

@dataclass(frozen=True, slots=True, order=True)
class GovernanceFinding:
    severity: Literal["error", "warning"]
    rule_id: str
    path: str
    evidence_sha256: str
    waiver_id: str = ""
    waiver_sha256: str = ""

@dataclass(frozen=True, slots=True)
class GovernanceReport:
    accepted: bool
    baseline_commit_sha1: str
    baseline_tree_sha1: str
    scanned_file_count: int
    scanned_size_bytes: int
    errors: tuple[GovernanceFinding, ...]
    warnings: tuple[GovernanceFinding, ...]
def _text_bound(value: Any, label: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise FileGovernanceError(f"{label} has invalid length")
    if any(ord(char) < 0x20 for char in value):
        raise FileGovernanceError(f"{label} contains a control character")
    return value

def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise FileGovernanceError(f"invalid {label}")
    return value

def _module_prefix(value: Any) -> str:
    if not isinstance(value, str) or any(
        not part.isidentifier() for part in value.split(".")
    ):
        raise FileGovernanceError("invalid module prefix")
    return value

def _plain_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise FileGovernanceError(f"{label} must be an integer >= {minimum}")
    return value

def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FileGovernanceError("timestamp must use UTC Z form")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FileGovernanceError("invalid UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise FileGovernanceError("timestamp must use UTC")
    return parsed

def normalize_repo_identity(raw: str) -> str:
    """Validate one repo-wide canonical NFC POSIX identity."""
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise FileGovernanceError("repository path must use POSIX separators")
    if raw.startswith("/") or raw.endswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise FileGovernanceError("repository path must be relative")
    if unicodedata.normalize("NFC", raw) != raw:
        raise FileGovernanceError("repository path must already be NFC")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise FileGovernanceError("repository path contains an unsafe segment")
    for part in parts:
        if (
            ":" in part or part.endswith((" ", "."))
            or any(ord(char) < 0x20 or char in '<>"|?*' for char in part)
            or re.fullmatch(r"[^.]+~[0-9]+(?:\.[^.]+)?", part)
            or unicodedata.normalize("NFKC", part.split(".", 1)[0]).casefold()
            in _WINDOWS_RESERVED
        ):
            raise FileGovernanceError("repository path is not cross-platform safe")
    return raw
def normalize_repo_path(raw: str) -> str:
    """Validate a governed src/docs/tests path."""
    path = normalize_repo_identity(raw)
    if path.split("/", 1)[0] not in SCOPE_ROOTS:
        raise FileGovernanceError("repository path is outside governed roots")
    return path

def _ordinal(values: Iterable[str]) -> list[str]:
    return sorted(values, key=lambda item: item.encode("utf-8"))

def _reject_aliases(paths: Iterable[str]) -> None:
    seen: set[str] = set()
    folded: dict[str, str] = {}
    for path in paths:
        if path in seen:
            raise FileGovernanceError("duplicate repository path")
        seen.add(path)
        prior = folded.setdefault(path.casefold(), path)
        if prior != path:
            raise FileGovernanceError("case-folding repository path collision")

def file_category(path: str) -> FileCategory:
    root = normalize_repo_path(path).split("/", 1)[0]
    return {"docs": "documentation", "src": "source", "tests": "test"}[root]  # type: ignore[return-value]
def logical_line_count(data: bytes) -> int:
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)

def _strict_text(data: bytes, path: str) -> str:
    if len(data) > MAX_FILE_BYTES:
        raise FileGovernanceError(f"{path} exceeds the file byte bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FileGovernanceError(f"{path} is not strict UTF-8") from exc
    if any(char in text for char in ("\x00", "\r", "\v", "\f", "\x85", "\u2028", "\u2029")):
        raise FileGovernanceError(f"{path} contains a non-canonical separator")
    return text

def _synthetic(path: str, text: str) -> bool:
    marked = any(
        SYNTHETIC_FIXTURE_MARKER in line for line in text.splitlines()[:5]
    )
    return marked and (
        path.startswith("tests/")
        or "/fixtures/" in f"/{path}/"
        or "/sample_project/" in f"/{path}/"
    )

def _synthetic_match(rule: str, match: re.Match[str]) -> bool:
    if rule in {"windows_user_home", "posix_user_home"}:
        return (match.groupdict().get("user") or "").casefold() in _SYNTHETIC_USERS
    host = match.group("host").casefold()
    return host == "localhost" or host.endswith((".example", ".invalid"))

def scan_privacy_counts(
    path: str, data: bytes,
    *, known_values: Sequence[tuple[str, bytes | str]] = (),
) -> tuple[PrivacyCount, ...]:
    """Return counts only; secret values and fingerprints are never returned."""

    path = normalize_repo_path(path)
    text = _strict_text(data, path)
    counts: Counter[str] = Counter()
    synthetic = _synthetic(path, text)
    for rule, pattern in (
        ("windows_user_home", _WINDOWS_HOME),
        ("posix_user_home", _POSIX_HOME),
        ("license_endpoint", _LICENSE_ENDPOINT),
    ):
        counts[rule] += sum(
            1 for match in pattern.finditer(text)
            if (rule != "license_endpoint" or 1 <= int(match.group("port")) <= 65535) and not (synthetic and _synthetic_match(rule, match))
        )
    seen_ids: set[str] = set()
    for opaque_id, secret in known_values:
        _identifier(opaque_id, "known-value rule id")
        if opaque_id in seen_ids:
            raise FileGovernanceError("duplicate known-value rule id")
        seen_ids.add(opaque_id)
        raw = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not isinstance(raw, bytes) or len(raw) < 4:
            raise FileGovernanceError("known value is invalid")
        count = data.count(raw)
        if count:
            counts[f"known:{opaque_id}"] += count
    return tuple(
        PrivacyCount(rule, count)
        for rule, count in sorted(counts.items())
        if count > 0
    )
def snapshot_file(
    path: str, blob: GitBlob,
    *, known_values: Sequence[tuple[str, bytes | str]] = (),
) -> FileSnapshot:
    path = normalize_repo_path(path)
    _strict_text(blob.data, path)
    return FileSnapshot(
        path, file_category(path), blob.mode, len(blob.data),
        logical_line_count(blob.data), sha256(blob.data).hexdigest(),
        scan_privacy_counts(path, blob.data, known_values=known_values),
    )

def default_exact_exclusions() -> tuple[ExactExclusionV1, ...]:
    base = "src/aoi_orgware/resources/codex_app_server/0.145.0/"
    return (
        ExactExclusionV1(
            base + "codex_app_server_protocol.v2.schemas.json", "generated",
            "provider-generated protocol schema pinned by runtime receipt",
        ),
        ExactExclusionV1(
            base + "schema-manifest.json", "generated",
            "provider-generated protocol member manifest",
        ),
        ExactExclusionV1(
            BASELINE_RESOURCE_PATH, "generated",
            "self-describing deterministic file-governance baseline", True,
        ),
    )

def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
def build_baseline_manifest(
    snapshot: GitScopeSnapshot,
    *, exclusions: Sequence[ExactExclusionV1] | None = None,
) -> dict[str, Any]:
    if not _HEX40.fullmatch(snapshot.commit_sha1) or not _HEX40.fullmatch(
        snapshot.tree_sha1
    ):
        raise FileGovernanceError("Git commit/tree identity is invalid")
    files = {normalize_repo_path(path): blob for path, blob in snapshot.files.items()}
    if len(files) != len(snapshot.files):
        raise FileGovernanceError("duplicate normalized Git path")
    _reject_aliases(files)
    excluded: list[dict[str, Any]] = []
    for rule in sorted(
        exclusions or default_exact_exclusions(),
        key=lambda item: item.path.encode("utf-8"),
    ):
        blob = files.pop(rule.path, None)
        if blob is None and not rule.self_unbound:
            raise FileGovernanceError(f"missing exact exclusion: {rule.path}")
        excluded.append({
            "self_unbound": rule.self_unbound,
            "baseline_sha256": None if blob is None else sha256(blob.data).hexdigest(),
            "baseline_size_bytes": None if blob is None else len(blob.data),
            "git_mode": None if blob is None else blob.mode,
            "kind": rule.kind, "path": rule.path, "reason": rule.reason,
        })
    entries: list[dict[str, Any]] = []
    for path in _ordinal(files):
        item = snapshot_file(path, files[path])
        entries.append({
            "category": item.category, "content_sha256": item.content_sha256,
            "git_mode": item.git_mode, "logical_lines": item.logical_lines,
            "path": item.path,
            "privacy_counts": [
                {"count": count.count, "rule_id": count.rule_id}
                for count in item.privacy_counts
            ],
            "size_bytes": item.size_bytes,
        })
    body: dict[str, Any] = {
        "accepted_commit_sha1": snapshot.commit_sha1,
        "accepted_tree_sha1": snapshot.tree_sha1,
        "contract": FILE_GOVERNANCE_BASELINE_V1,
        "exact_exclusions": excluded, "files": entries,
        "limits": {
            "new_file_hard_logical_lines": NEW_FILE_HARD_LOGICAL_LINES,
            "new_file_target_logical_lines": NEW_FILE_TARGET_LOGICAL_LINES,
        },
        "schema_version": 1, "scope_roots": list(SCOPE_ROOTS),
        "totals": {
            "excluded_file_count": sum(x["baseline_sha256"] is not None for x in excluded),
            "hand_authored_file_count": len(entries),
            "hand_authored_logical_lines": sum(x["logical_lines"] for x in entries),
            "hand_authored_size_bytes": sum(x["size_bytes"] for x in entries),
            "legacy_privacy_finding_count": sum(
                sum(x["count"] for x in item["privacy_counts"]) for item in entries
            ),
            "tracked_file_count": len(snapshot.files),
            "tracked_size_bytes": sum(len(blob.data) for blob in snapshot.files.values()),
        },
    }
    body["manifest_sha256"] = sha256(_canonical(body)).hexdigest()
    return body

def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FileGovernanceError("duplicate baseline JSON key")
        result[key] = value
    return result

def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise FileGovernanceError(f"{label} keys do not match the contract")
def validate_baseline_manifest(raw: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(raw)
    _exact_keys(value, {
        "accepted_commit_sha1", "accepted_tree_sha1", "contract",
        "exact_exclusions", "files", "limits", "manifest_sha256",
        "schema_version", "scope_roots", "totals",
    }, "baseline")
    if (
        value["contract"] != FILE_GOVERNANCE_BASELINE_V1
        or value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
        or not isinstance(value["accepted_commit_sha1"], str)
        or not _HEX40.fullmatch(value["accepted_commit_sha1"])
        or not isinstance(value["accepted_tree_sha1"], str)
        or not _HEX40.fullmatch(value["accepted_tree_sha1"])
        or value["scope_roots"] != list(SCOPE_ROOTS)
    ):
        raise FileGovernanceError("invalid baseline identity")
    if value["limits"] != {
        "new_file_hard_logical_lines": NEW_FILE_HARD_LOGICAL_LINES,
        "new_file_target_logical_lines": NEW_FILE_TARGET_LOGICAL_LINES,
    }:
        raise FileGovernanceError("baseline limits differ from runtime policy")
    exclusions, files = value["exact_exclusions"], value["files"]
    if not isinstance(exclusions, list) or not isinstance(files, list):
        raise FileGovernanceError("baseline collections must be arrays")
    paths: list[str] = []
    for item in exclusions:
        if not isinstance(item, dict):
            raise FileGovernanceError("invalid exact exclusion")
        _exact_keys(item, _EXCLUSION_KEYS, "exact exclusion")
        rule = ExactExclusionV1(
            item["path"], item["kind"], item["reason"],
            item["self_unbound"],
        )
        if not isinstance(item["self_unbound"], bool):
            raise FileGovernanceError("invalid exclusion self-binding flag")
        identity = tuple(item[key] for key in (
            "baseline_sha256", "baseline_size_bytes", "git_mode",
        ))
        if any(value is None for value in identity) != all(
            value is None for value in identity
        ):
            raise FileGovernanceError("excluded blob identity is partial")
        if identity[0] is None:
            if not rule.self_unbound:
                raise FileGovernanceError("required exclusion is absent")
        elif (
            not isinstance(item["baseline_sha256"], str)
            or not _HEX64.fullmatch(item["baseline_sha256"])
            or item["git_mode"] not in {"100644", "100755"}
        ):
            raise FileGovernanceError("invalid excluded blob identity")
        if item["baseline_size_bytes"] is not None:
            _plain_int(item["baseline_size_bytes"], "excluded size")
        paths.append(rule.path)
    for item in files:
        if not isinstance(item, dict):
            raise FileGovernanceError("invalid file entry")
        _exact_keys(item, _FILES_KEYS, "file entry")
        path = normalize_repo_path(item["path"])
        if (
            item["category"] != file_category(path)
            or item["git_mode"] not in {"100644", "100755"}
            or not isinstance(item["content_sha256"], str)
            or not _HEX64.fullmatch(item["content_sha256"])
        ):
            raise FileGovernanceError("invalid file identity")
        _plain_int(item["logical_lines"], "logical lines")
        _plain_int(item["size_bytes"], "file size")
        privacy = item["privacy_counts"]
        if not isinstance(privacy, list):
            raise FileGovernanceError("privacy counts must be an array")
        prior_rule = ""
        for count in privacy:
            if not isinstance(count, dict) or set(count) != {"count", "rule_id"}:
                raise FileGovernanceError("invalid privacy count")
            rule_id = _identifier(count["rule_id"], "privacy rule id")
            _plain_int(count["count"], "privacy count", minimum=1)
            if rule_id <= prior_rule:
                raise FileGovernanceError("privacy counts are not sorted")
            prior_rule = rule_id
        paths.append(path)
    if [x["path"] for x in exclusions] != _ordinal(x["path"] for x in exclusions):
        raise FileGovernanceError("exact exclusions are not ordinal-sorted")
    if [x["path"] for x in files] != _ordinal(x["path"] for x in files):
        raise FileGovernanceError("file entries are not ordinal-sorted")
    _reject_aliases(paths)
    totals = {
        "excluded_file_count": sum(x["baseline_sha256"] is not None for x in exclusions),
        "hand_authored_file_count": len(files),
        "hand_authored_logical_lines": sum(x["logical_lines"] for x in files),
        "hand_authored_size_bytes": sum(x["size_bytes"] for x in files),
        "legacy_privacy_finding_count": sum(
            sum(x["count"] for x in item["privacy_counts"]) for item in files
        ),
        "tracked_file_count": len(files) + sum(
            x["baseline_sha256"] is not None for x in exclusions
        ),
        "tracked_size_bytes": sum(x["size_bytes"] for x in files) + sum(
            x["baseline_size_bytes"] or 0 for x in exclusions
        ),
    }
    if value["totals"] != totals:
        raise FileGovernanceError("baseline totals are inconsistent")
    digest = value["manifest_sha256"]
    body = dict(value)
    body.pop("manifest_sha256")
    if (
        not isinstance(digest, str) or not _HEX64.fullmatch(digest)
        or digest != sha256(_canonical(body)).hexdigest()
    ):
        raise FileGovernanceError("baseline self digest mismatch")
    return value
def baseline_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return _canonical(validate_baseline_manifest(manifest)) + b"\n"
def parse_baseline_manifest(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FileGovernanceError("invalid baseline JSON") from exc
    if not isinstance(value, dict):
        raise FileGovernanceError("baseline JSON must be an object")
    checked = validate_baseline_manifest(value)
    if data != _canonical(checked) + b"\n":
        raise FileGovernanceError("baseline bytes are not canonical")
    return checked
def _finding(
    severity: Literal["error", "warning"], rule: str, path: str,
    *facts: str | int,
) -> GovernanceFinding:
    digest = sha256(
        "\0".join((path, rule, *(str(item) for item in facts))).encode("utf-8")
    ).hexdigest()
    return GovernanceFinding(severity, rule, path, digest)

def _evaluate_verified_candidate(
    *, baseline: Mapping[str, Any], current_files: Mapping[str, GitBlob],
    release: str, observed_at: datetime,
    waivers: Sequence[FileGovernanceWaiverV1] = (),
    known_values: Sequence[tuple[str, bytes | str]] = (),
) -> GovernanceReport:
    """Apply the accepted-tree growth and privacy-debt ratchets."""

    checked = validate_baseline_manifest(baseline)
    if observed_at.tzinfo != timezone.utc or not _RELEASE.fullmatch(release):
        raise FileGovernanceError("observation time/release is invalid")
    waiver_ids: set[str] = set()
    waiver_authorities: set[tuple[str, str, str]] = set()
    for waiver in waivers:
        if not isinstance(waiver, FileGovernanceWaiverV1):
            raise FileGovernanceError("invalid waiver object")
        authority = (waiver.path, waiver.rule_id, waiver.applies_to_release)
        if waiver.waiver_id in waiver_ids or authority in waiver_authorities:
            raise FileGovernanceError("duplicate or overlapping waiver authority")
        waiver_ids.add(waiver.waiver_id)
        waiver_authorities.add(authority)
    current = {normalize_repo_path(path): blob for path, blob in current_files.items()}
    if len(current) != len(current_files):
        raise FileGovernanceError("duplicate normalized candidate path")
    _reject_aliases(current)
    prior_files = {item["path"]: item for item in checked["files"]}
    exclusions = {item["path"]: item for item in checked["exact_exclusions"]}
    errors: list[tuple[GovernanceFinding, FileSnapshot | None]] = []
    for path, rule in exclusions.items():
        blob = current.pop(path, None)
        if blob is None:
            errors.append((_finding("error", "excluded_file_missing", path), None))
        elif rule["self_unbound"]:
            parsed = parse_baseline_manifest(blob.data)
            if (
                blob.mode != "100644"
                or blob.data != baseline_manifest_bytes(checked)
                or parsed["accepted_commit_sha1"] != checked["accepted_commit_sha1"]
                or parsed["accepted_tree_sha1"] != checked["accepted_tree_sha1"]
            ):
                errors.append((_finding("error", "baseline_identity_mismatch", path), None))
        elif (
            blob.mode != rule["git_mode"]
            or len(blob.data) != rule["baseline_size_bytes"]
            or sha256(blob.data).hexdigest() != rule["baseline_sha256"]
        ):
            errors.append((_finding("error", "excluded_file_changed", path), None))
    for path in _ordinal(current):
        snapshot = snapshot_file(path, current[path], known_values=known_values)
        prior = prior_files.get(path)
        if prior is None:
            if snapshot.logical_lines > NEW_FILE_HARD_LOGICAL_LINES:
                errors.append((_finding(
                    "error", "new_file_hard_limit", path, snapshot.logical_lines
                ), snapshot))
            elif snapshot.logical_lines > NEW_FILE_TARGET_LOGICAL_LINES:
                errors.append((_finding(
                    "error", "new_file_target_exceeded", path, snapshot.logical_lines
                ), snapshot))
            prior_privacy: dict[str, int] = {}
        else:
            prior_lines, prior_size = prior["logical_lines"], prior["size_bytes"]
            if prior["git_mode"] != snapshot.git_mode:
                errors.append((_finding("error", "git_mode_changed", path), snapshot))
            if prior_lines > NEW_FILE_TARGET_LOGICAL_LINES:
                if snapshot.logical_lines > prior_lines:
                    errors.append((_finding(
                        "error", "existing_over_target_line_growth", path,
                        prior_lines, snapshot.logical_lines,
                    ), snapshot))
                if snapshot.size_bytes > prior_size:
                    errors.append((_finding(
                        "error", "existing_over_target_byte_growth", path,
                        prior_size, snapshot.size_bytes,
                    ), snapshot))
            elif snapshot.logical_lines > NEW_FILE_HARD_LOGICAL_LINES:
                errors.append((_finding(
                    "error", "existing_file_hard_limit", path,
                    prior_lines, snapshot.logical_lines,
                ), snapshot))
            prior_privacy = {
                item["rule_id"]: item["count"] for item in prior["privacy_counts"]
            }
        current_privacy = {
            item.rule_id: item.count for item in snapshot.privacy_counts
        }
        known_hits = {key: value for key, value in current_privacy.items()
                      if key.startswith("known:")}
        if known_hits:
            errors.append((_finding(
                "error", "deployment_value", path,
                *[f"{key}:{value}" for key, value in sorted(known_hits.items())],
            ), snapshot))
        built_current = {k: v for k, v in current_privacy.items()
                         if not k.startswith("known:")}
        if prior is None or not prior_privacy:
            if built_current:
                errors.append((_finding(
                    "error", "deployment_value", path,
                    *[f"{key}:{value}" for key, value in sorted(built_current.items())],
                ), snapshot))
        elif snapshot.content_sha256 != prior["content_sha256"]:
            strictly_less = (
                sum(built_current.values()) < sum(prior_privacy.values())
                and all(built_current.get(key, 0) <= value
                        for key, value in prior_privacy.items())
                and not (set(built_current) - set(prior_privacy))
            )
            if not strictly_less:
                errors.append((_finding(
                    "error", "privacy_debt_file_changed", path,
                    sum(prior_privacy.values()), sum(built_current.values()),
                ), snapshot))
    retained: list[GovernanceFinding] = []
    waived_findings: list[GovernanceFinding] = []
    for finding, candidate_snapshot in errors:
        matching_waiver = next((
            waiver for waiver in waivers
            if candidate_snapshot is not None and waiver.permits(
                finding, release=release, observed_at=observed_at,
                snapshot=candidate_snapshot,
            )
        ), None)
        if matching_waiver is None:
            retained.append(finding)
        else:
            waiver_body = {
                "applies_to_release": matching_waiver.applies_to_release,
                "expires_at": matching_waiver.expires_at,
                "followup": matching_waiver.followup,
                "max_logical_lines": matching_waiver.max_logical_lines,
                "max_size_bytes": matching_waiver.max_size_bytes,
                "owner": matching_waiver.owner,
                "path": matching_waiver.path,
                "reason": matching_waiver.reason,
                "rule_id": matching_waiver.rule_id,
                "waiver_id": matching_waiver.waiver_id,
            }
            waived_findings.append(GovernanceFinding(
                "warning", finding.rule_id, finding.path,
                finding.evidence_sha256, matching_waiver.waiver_id,
                sha256(_canonical(waiver_body)).hexdigest(),
            ))
    retained.sort()
    waived_findings.sort()
    return GovernanceReport(
        not retained, checked["accepted_commit_sha1"], checked["accepted_tree_sha1"],
        len(current_files), sum(len(blob.data) for blob in current_files.values()),
        tuple(retained), tuple(waived_findings),
    )

def load_packaged_baseline() -> dict[str, Any]:
    resource = resources.files("aoi_orgware").joinpath(*BASELINE_RESOURCE_PARTS)
    return parse_baseline_manifest(resource.read_bytes())
__all__ = [
    "ActiveWriteRefV1", "BASELINE_RESOURCE_PATH", "ExactExclusionV1",
    "FILE_GOVERNANCE_BASELINE_V1", "FileGovernanceError",
    "FileGovernanceWaiverV1", "FileSnapshot", "GitBlob", "GitScopeSnapshot",
    "GovernanceFinding", "GovernanceReport", "ImportBoundaryRuleV1",
    "NEW_FILE_HARD_LOGICAL_LINES", "NEW_FILE_TARGET_LOGICAL_LINES",
    "PrivacyCount", "SCOPE_ROOTS", "SYNTHETIC_FIXTURE_MARKER",
    "baseline_manifest_bytes", "build_baseline_manifest",
    "default_exact_exclusions", "file_category",
    "load_packaged_baseline", "logical_line_count", "normalize_repo_path",
    "normalize_repo_identity", "parse_baseline_manifest",
    "scan_privacy_counts", "snapshot_file", "validate_baseline_manifest",
]
