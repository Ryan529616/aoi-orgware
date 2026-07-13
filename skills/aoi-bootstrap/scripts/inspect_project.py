#!/usr/bin/env python3
"""Deterministically inventory a Git repository for AOI bootstrap drafting.

This script reads names and filesystem metadata only. It does not infer an
organization, read source contents, or mutate the repository.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath


SCHEMA_VERSION = 1
DEFAULT_MAX_FILES = 20_000
MAX_REPORTED_PATHS = 100
MAX_DIRECTORY_ENTRIES = 4_096
MAX_CONFIG_BYTES = 256 * 1024
MAX_MARKER_BYTES = 64 * 1024
LOCK_DOMAINS = {"posix-flock-v1", "windows-msvcrt-v1"}
WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)

IGNORED_DIRECTORIES = {
    ".git",
    ".aoi",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}

LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".go": "go",
    ".h": "c-cpp-header",
    ".hpp": "c-cpp-header",
    ".html": "html",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".m": "objective-c",
    ".md": "markdown",
    ".php": "php",
    ".ps1": "powershell",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "shell",
    ".sv": "systemverilog",
    ".svh": "systemverilog",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".v": "verilog",
    ".vhd": "vhdl",
    ".vhdl": "vhdl",
    ".vue": "vue",
}

MANIFEST_NAMES = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.toml",
    "cmakelists.txt",
    "composer.json",
    "dockerfile",
    "gemfile",
    "go.mod",
    "makefile",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
}

DOCUMENTATION_NAMES = {
    "agents.md",
    "changelog.md",
    "contributing.md",
    "readme.md",
    "security.md",
}

RISK_SEGMENTS = {
    ".codex",
    ".github",
    "auth",
    "credentials",
    "deploy",
    "deployment",
    "infra",
    "infrastructure",
    "keys",
    "migrations",
    "production",
    "secrets",
    "security",
}

EXTERNAL_SEGMENTS = {
    ".github",
    "deploy",
    "deployment",
    "docker",
    "helm",
    "infra",
    "infrastructure",
    "k8s",
    "kubernetes",
    "terraform",
}

HDL_SUFFIXES = {".sv", ".svh", ".v", ".vh"}
HARDWARE_TEST_DIRECTORIES = {
    "dv",
    "sim",
    "testbench",
    "testbenches",
    "tb",
    "verif",
    "verification",
}
HARDWARE_CONTEXT_DIRECTORIES = HARDWARE_TEST_DIRECTORIES | {"rtl"}
EDA_FLOW_DIRECTORY_NAMES = {
    "apr",
    "constraints",
    "dc-rm",
    "dft",
    "eda",
    "fc-rm",
    "formal",
    "gls",
    "physical-design",
    "pnr",
    "rtl2gds",
    "rtla-rm",
    "sta",
    "synthesis",
    "synopsys",
}
EDA_FLOW_DIRECTORY_PREFIXES = ("dc-rm-", "fc-rm-", "rtla-rm-")
EDA_TOOL_TOKENS = {
    "apr",
    "dc",
    "eda",
    "fc",
    "formality",
    "gls",
    "icc2",
    "mc2",
    "pnr",
    "primetime",
    "rtl2gds",
    "rtla",
    "spyglass",
    "sta",
    "synth",
    "synthesis",
    "tmax",
    "vcs",
    "verdi",
}
EDA_TOOL_SCRIPT_SUFFIXES = {".py", ".ps1", ".sh", ".tcl"}
EDA_ARTIFACT_SUFFIXES = {
    ".def",
    ".gds",
    ".gdsii",
    ".lef",
    ".saif",
    ".sdc",
    ".sdf",
    ".spef",
    ".upf",
    ".xdc",
}
AMBIGUOUS_EDA_ARTIFACT_SUFFIXES = {".db", ".lib"}


class InspectError(RuntimeError):
    pass


def _link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction is not None and is_junction():
            return True
        if os.name != "nt":
            return False
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attributes & reparse_flag)
    except OSError:
        # An entry whose link metadata cannot be inspected is unsafe to traverse.
        return True


def _is_hardware_testbench(
    parts: tuple[str, ...], name: str, suffix: str
) -> bool:
    if suffix not in HDL_SUFFIXES:
        return False
    stem = name[: -len(suffix)] if suffix else name
    return bool(set(parts[:-1]) & HARDWARE_TEST_DIRECTORIES) or stem.endswith(
        "_tb"
    ) or stem.startswith("tb_")


def _is_hardware_manifest(parts: tuple[str, ...], suffix: str) -> bool:
    if suffix == ".flist":
        return True
    if suffix != ".f":
        return False
    parents = set(parts[:-1])
    return bool(parents & HARDWARE_CONTEXT_DIRECTORIES) or any(
        _is_eda_flow_directory(part) for part in parents
    )


def _is_run_flow(parts: tuple[str, ...], name: str, suffix: str) -> bool:
    if any(
        parts[index : index + 2] in (("scripts", "run"), ("scripts", "runs"))
        for index in range(max(0, len(parts) - 1))
    ):
        return True
    if "scripts" not in parts[:-1] or suffix not in EDA_TOOL_SCRIPT_SUFFIXES:
        return False
    tokens = set(re.split(r"[^a-z0-9]+", name.casefold()))
    return "run" in tokens and bool(
        tokens & (EDA_TOOL_TOKENS | {"compile", "flow", "regress", "regression", "sim", "simulation"})
    )


def _is_eda_flow_directory(name: str) -> bool:
    normalized = name.casefold().replace("_", "-")
    if normalized in EDA_FLOW_DIRECTORY_NAMES:
        return True
    if normalized.startswith(EDA_FLOW_DIRECTORY_PREFIXES):
        return True
    tokens = set(re.split(r"[^a-z0-9]+", normalized))
    return bool(tokens & {"eda", "mc2", "rtl2gds", "synopsys"})


def _is_eda_tool_flow_file(
    parts: tuple[str, ...], name: str, suffix: str, hardware_manifest: bool
) -> bool:
    if hardware_manifest or suffix in EDA_ARTIFACT_SUFFIXES:
        return True
    if suffix in AMBIGUOUS_EDA_ARTIFACT_SUFFIXES:
        parents = set(parts[:-1])
        return bool(parents & HARDWARE_CONTEXT_DIRECTORIES) or any(
            _is_eda_flow_directory(part) for part in parents
        )
    tokens = set(re.split(r"[^a-z0-9]+", name.casefold()))
    if suffix in EDA_TOOL_SCRIPT_SUFFIXES and tokens & EDA_TOOL_TOKENS:
        return True
    return False


def _run_git(root: Path, *args: str) -> str:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        result = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "submodule.recurse=false",
                "-C",
                str(root),
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InspectError(f"cannot execute Git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Git rejected the repository"
        raise InspectError(detail)
    return result.stdout.strip()


def _append_bounded(items: list[str], value: str) -> None:
    if len(items) < MAX_REPORTED_PATHS and value not in items:
        items.append(value)


def _bounded_directory_names(path: Path, limit: int) -> tuple[list[str], bool]:
    """Return sorted names without reading more than ``limit`` entries.

    Reaching the limit is treated conservatively as truncation, even when the
    directory might contain exactly that many entries.  In that case no names
    are returned, so output never depends on filesystem enumeration order.
    """

    if limit <= 0:
        return [], True
    names: list[str] = []
    with os.scandir(path) as entries:
        for _index in range(limit):
            try:
                entry = next(entries)
            except StopIteration:
                return sorted(names), False
            names.append(entry.name)
    return [], True


def _safe_state_dir(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise InspectError("state_dir is not a safe project-relative POSIX path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or not posix.parts
        or str(posix) != value
    ):
        raise InspectError("state_dir is not a safe project-relative POSIX path")
    for part in posix.parts:
        folded = part.casefold()
        if (
            folded in {".", "..", ".git"}
            or folded.split(".", 1)[0] in WINDOWS_RESERVED
            or part.endswith((" ", "."))
            or any(character in WINDOWS_FORBIDDEN for character in part)
            or any(ord(character) < 32 for character in part)
        ):
            raise InspectError("state_dir is not a safe project-relative POSIX path")
    return value


def _existing_state_dir(root: Path, warnings: list[str]) -> tuple[str, str]:
    config = root / "aoi.toml"
    if not os.path.lexists(config):
        return ".aoi", "absent"
    if _link_like(config) or not config.is_file():
        warnings.append("existing aoi.toml is linked or not a regular file; it was not read")
        return ".aoi", "invalid"
    try:
        size = config.stat().st_size
        if not 0 < size <= MAX_CONFIG_BYTES:
            raise InspectError("existing aoi.toml is empty or exceeds the inspection limit")
        payload = tomllib.loads(config.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise InspectError("existing aoi.toml does not contain a table")
        return _safe_state_dir(payload.get("state_dir")), "parsed"
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, InspectError) as exc:
        warnings.append(f"existing aoi.toml could not be safely inspected: {exc}")
        return ".aoi", "invalid"


def _path_traverses_link(root: Path, relative: str) -> bool:
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if not os.path.lexists(current):
            return False
        if _link_like(current):
            return True
    return False


def inspect(root_arg: Path, max_files: int) -> dict[str, object]:
    lexical = root_arg.expanduser().absolute()
    if _link_like(lexical):
        raise InspectError(f"repository root may not be a symlink or junction: {lexical}")
    if not lexical.is_dir():
        raise InspectError(f"repository root is not a directory: {lexical}")
    root = lexical.resolve()
    if lexical != root:
        raise InspectError("repository root may not traverse symlinks or junctions")
    git_root = Path(_run_git(root, "rev-parse", "--show-toplevel")).resolve()
    if git_root != root:
        raise InspectError(f"--root must name the exact Git worktree root: {git_root}")

    language_counts: Counter[str] = Counter()
    manifests: list[str] = []
    documentation: list[str] = []
    tests: list[str] = []
    hardware_testbenches: list[str] = []
    hardware_manifests: list[str] = []
    run_flows: list[str] = []
    risk_markers: list[str] = []
    external_markers: list[str] = []
    skipped_links: list[str] = []
    filesystem_errors: list[str] = []
    manifest_roots: set[str] = set()
    scanned = 0
    scanned_entries = 0
    max_entries = max(1_000, max_files * 4)
    truncated = False
    warnings: list[str] = []
    marker_counts: Counter[str] = Counter()
    configured_state_dir, config_status = _existing_state_dir(root, warnings)
    state_parts = PurePosixPath(configured_state_dir).parts
    state_top_level = state_parts[0] if len(state_parts) == 1 else None

    def record_walk_error(error: OSError, directory: Path) -> None:
        value = error.filename or str(directory)
        try:
            value = Path(value).resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            value = "unresolved path"
        _append_bounded(filesystem_errors, f"could not inspect {value}: {error.strerror}")

    stop_walk = False
    truncated_directory: str | None = None
    top_level: list[str] = []
    pending_directories = [root]
    while pending_directories and not stop_walk:
        current_path = pending_directories.pop()
        remaining_entries = max_entries - scanned_entries
        directory_entry_limit = min(MAX_DIRECTORY_ENTRIES, remaining_entries)
        try:
            entry_names, directory_truncated = _bounded_directory_names(
                current_path, directory_entry_limit
            )
        except OSError as exc:
            record_walk_error(exc, current_path)
            continue
        if directory_truncated:
            truncated = True
            truncated_directory = (
                "."
                if current_path == root
                else current_path.relative_to(root).as_posix()
            )
            break

        safe_directories: list[str] = []
        files: list[str] = []
        for name in entry_names:
            scanned_entries += 1
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            if _link_like(child):
                _append_bounded(skipped_links, relative)
                continue
            try:
                child_is_directory = child.is_dir()
                child_is_file = child.is_file()
            except OSError as exc:
                record_walk_error(exc, child)
                continue
            if not child_is_directory:
                if child_is_file:
                    files.append(name)
                continue
            if (
                current_path == root
                and name != ".git"
                and name != state_top_level
                and len(top_level) < MAX_REPORTED_PATHS
            ):
                top_level.append(name)
            if name.lower() in IGNORED_DIRECTORIES:
                continue
            if relative == configured_state_dir:
                continue
            safe_directories.append(name)
            relative_parts = tuple(
                item.casefold() for item in PurePosixPath(relative).parts
            )
            lowered_parts = set(relative_parts)
            if lowered_parts & RISK_SEGMENTS:
                _append_bounded(risk_markers, relative + "/")
            if lowered_parts & EXTERNAL_SEGMENTS or _is_eda_flow_directory(name):
                marker_counts["external_system_markers"] += 1
                _append_bounded(external_markers, relative + "/")

        for name in files:
            if scanned >= max_files:
                truncated = True
                stop_walk = True
                break
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            scanned += 1
            suffix = path.suffix.lower()
            if suffix in LANGUAGES:
                language_counts[LANGUAGES[suffix]] += 1
            lowered_name = name.lower()
            relative_parts = tuple(
                item.casefold() for item in PurePosixPath(relative).parts
            )
            lowered_parts = set(relative_parts)
            hardware_manifest = _is_hardware_manifest(relative_parts, suffix)
            hardware_testbench = _is_hardware_testbench(
                relative_parts, lowered_name, suffix
            )
            run_flow = _is_run_flow(relative_parts, lowered_name, suffix)
            if lowered_name in MANIFEST_NAMES or suffix == ".sln":
                marker_counts["manifests"] += 1
                _append_bounded(manifests, relative)
                parent = PurePosixPath(relative).parent.parts
                manifest_roots.add(parent[0].lower() if parent else ".")
            if hardware_manifest:
                marker_counts["hardware_manifest_markers"] += 1
                _append_bounded(hardware_manifests, relative)
            if lowered_name in DOCUMENTATION_NAMES:
                _append_bounded(documentation, relative)
            if (
                "test" in lowered_parts
                or "tests" in lowered_parts
                or "spec" in lowered_parts
                or lowered_name.startswith("test_")
                or lowered_name.endswith("_test.py")
                or lowered_name.endswith(".test.js")
                or lowered_name.endswith(".test.ts")
                or hardware_testbench
            ):
                marker_counts["test_markers"] += 1
                _append_bounded(tests, relative)
            if hardware_testbench:
                marker_counts["hardware_testbench_markers"] += 1
                _append_bounded(hardware_testbenches, relative)
            if run_flow:
                marker_counts["run_flow_markers"] += 1
                _append_bounded(run_flows, relative)
            if lowered_parts & RISK_SEGMENTS:
                _append_bounded(risk_markers, relative)
            if (
                lowered_parts & EXTERNAL_SEGMENTS
                or lowered_name.startswith("dockerfile")
                or suffix in {".tf", ".tfvars"}
                or _is_eda_tool_flow_file(
                    relative_parts, lowered_name, suffix, hardware_manifest
                )
            ):
                marker_counts["external_system_markers"] += 1
                _append_bounded(external_markers, relative)
        if not stop_walk:
            pending_directories.extend(
                current_path / name for name in reversed(safe_directories)
            )

    aoi_state = root / configured_state_dir
    platform_marker = aoi_state / "platform.json"
    lock_domain = None
    state_linked = _path_traverses_link(root, configured_state_dir)
    state_exists = not state_linked and aoi_state.is_dir()
    if state_linked:
        warnings.append("configured AOI state path traverses a link; state was not read")
    elif platform_marker.is_file() and not _link_like(platform_marker):
        try:
            if not 0 < platform_marker.stat().st_size <= MAX_MARKER_BYTES:
                raise ValueError("marker is empty or too large")
            payload = json.loads(platform_marker.read_text(encoding="utf-8"))
            value = payload.get("lock_domain") if isinstance(payload, dict) else None
            if (
                not isinstance(payload, dict)
                or payload.get("schema_version") != 1
                or value not in LOCK_DOMAINS
            ):
                raise ValueError("marker schema or lock domain is invalid")
            lock_domain = value
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            lock_domain = "invalid-marker"
            warnings.append("AOI platform marker is invalid and was not trusted")

    top_level.sort()
    monorepo_signals: list[str] = []
    non_root_manifests = sorted(item for item in manifest_roots if item != ".")
    if len(non_root_manifests) >= 2:
        monorepo_signals.append("build manifests appear under multiple top-level directories")
    for marker in ("pnpm-workspace.yaml", "lerna.json", "nx.json"):
        if (root / marker).is_file():
            monorepo_signals.append(f"workspace marker present: {marker}")

    if truncated:
        warnings.append(
            f"repository scan stopped at the {max_files}-file or {max_entries}-entry limit"
        )
    if truncated_directory is not None:
        warnings.append(
            "repository scan skipped an over-limit directory without sampling it: "
            f"{truncated_directory} (limit {min(MAX_DIRECTORY_ENTRIES, max_entries)})"
        )
    if skipped_links:
        warnings.append("linked filesystem entries were skipped and not traversed")
    if filesystem_errors:
        warnings.append("some filesystem entries could not be inspected")
    if os.path.lexists(root / "aoi.toml"):
        warnings.append("aoi.toml already exists; bootstrap must not overwrite it")
    if os.path.lexists(aoi_state):
        warnings.append(
            f"AOI state at {configured_state_dir} already exists; preserve its lock domain"
        )
    warnings.append(
        "tracked-worktree change status was not probed because a full Git status "
        "is outside the bounded inventory"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "project_name": root.name,
        "git": {
            "exact_worktree_root": True,
            "tracked_changes_checked": False,
            "tracked_changes": None,
        },
        "aoi": {
            "config_exists": os.path.lexists(root / "aoi.toml"),
            "config_status": config_status,
            "state_dir": configured_state_dir,
            "state_exists": state_exists,
            "state_linked": state_linked,
            "lock_domain": lock_domain,
        },
        "inventory": {
            "scanned_files": scanned,
            "scan_limit": max_files,
            "entry_scan_limit": max_entries,
            "directory_entry_limit": min(MAX_DIRECTORY_ENTRIES, max_entries),
            "truncated": truncated,
            "languages": [
                {"id": key, "files": language_counts[key]}
                for key in sorted(language_counts)
            ],
            "manifests": sorted(manifests),
            "test_markers": sorted(tests),
            "hardware_testbench_markers": sorted(hardware_testbenches),
            "hardware_manifest_markers": sorted(hardware_manifests),
            "run_flow_markers": sorted(run_flows),
            "documentation_markers": sorted(documentation),
            "risk_markers": sorted(risk_markers),
            "external_system_markers": sorted(external_markers),
            "marker_counts": {
                key: marker_counts[key]
                for key in (
                    "manifests",
                    "test_markers",
                    "hardware_testbench_markers",
                    "hardware_manifest_markers",
                    "run_flow_markers",
                    "external_system_markers",
                )
            },
            "top_level_directories": top_level,
            "monorepo_signals": monorepo_signals,
            "skipped_links": sorted(skipped_links),
            "filesystem_errors": sorted(filesystem_errors),
        },
        "warnings": warnings,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only repository inventory for AOI bootstrap drafting"
    )
    parser.add_argument("--root", default=".", help="exact Git worktree root")
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help="bounded number of regular files to inventory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 100 <= args.max_files <= 100_000:
        print("ERROR: --max-files must be between 100 and 100000", file=sys.stderr)
        return 2
    try:
        payload = inspect(Path(args.root), args.max_files)
    except InspectError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
