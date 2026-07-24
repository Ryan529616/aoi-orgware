"""Portable, fail-closed receipts for tests run from a Git blob snapshot.

This is intentionally a cooperative evidence primitive, not an attestation
system.  In particular, a same-user process can replace Git, Python, or this
runner before it starts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform as _platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from typing import Any, NoReturn


SCHEMA_VERSION = 1
RECEIPT_KIND = "aoi.clean_commit_source_tree_exact_test_receipt.v1"
RUNNER_VERSION = "1"
MAX_RECEIPT_BYTES = 512 * 1024
EMPTY_GIT_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z")
_ENV_ALLOWLIST = frozenset(
    {"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL", "TZ"}
)
_WINDOWS_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL", *(f"COM{number}" for number in range(1, 10)), *(f"LPT{number}" for number in range(1, 10))})


class ExactTestReceiptError(ValueError):
    """The requested run or receipt is not safe to accept."""


class ReceiptPublicationError(ExactTestReceiptError):
    """A terminal receipt could not be published atomically."""


def _fail(message: str) -> NoReturn:
    raise ExactTestReceiptError(message)


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"receipt is not canonical JSON data: {exc}")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_stable_regular_read(path, "file"))


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _check_path_components(path: Path, label: str) -> None:
    """Reject an extant symlink/reparse component before opening a path."""
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            _fail(f"cannot inspect {label} component: {exc}")
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            _fail(f"{label} has a symlink or reparse component")


def _stable_regular_read(path: Path, label: str) -> bytes:
    if not path.is_absolute():
        _fail(f"{label} path must be absolute")
    _check_path_components(path, label)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(before) or before.st_nlink != 1:
            _fail(f"{label} must be a single-link regular non-reparse file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            raw = b"".join(iter(lambda: os.read(descriptor, 1024 * 1024), b""))
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError as exc:
        _fail(f"cannot safely read {label}: {exc}")
    # Windows can report creation/change metadata differently through a file
    # descriptor than through the pathname, so use the stable identity fields
    # common to both APIs rather than comparing ctime.
    before_id = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    opened_id = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink)
    after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)
    if before_id != opened_id or before_id != after_id or len(raw) != before.st_size:
        _fail(f"{label} changed while being read")
    return raw


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _absolute_path(value: object, label: str) -> str:
    text = _string(value, label)
    if not Path(text).is_absolute() and not PureWindowsPath(text).is_absolute():
        _fail(f"{label} must be absolute")
    return text


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase SHA-256")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer at least {minimum}")
    return value


def _exact(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} schema is invalid")
    return value


def validate_exact_test_receipt(value: Mapping[str, Any], *, require_github_matrix: bool = False) -> dict[str, Any]:
    """Validate the complete typed schema and its self digest."""
    keys = {
        "schema_version", "kind", "accepted", "terminal_status", "created_at", "producer",
        "source", "interpreter", "invocation", "platform", "log", "pytest_exit_code",
        "identity_unchanged", "log_closed", "publication_atomic",
        "github_matrix_identity", "observation", "receipt_sha256",
    }
    item = _exact(value, keys, "exact test receipt")
    if item["schema_version"] != SCHEMA_VERSION or item["kind"] != RECEIPT_KIND:
        _fail("receipt version or kind is invalid")
    if type(item["accepted"]) is not bool or type(item["identity_unchanged"]) is not bool or type(item["log_closed"]) is not bool or type(item["publication_atomic"]) is not bool:
        _fail("receipt booleans are invalid")
    if item["terminal_status"] not in {"completed", "rejected", "timeout", "runner_error"}:
        _fail("receipt terminal status is invalid")
    _string(item["created_at"], "receipt created_at")
    if not isinstance(item["created_at"], str) or _RFC3339_UTC.fullmatch(item["created_at"]) is None:
        _fail("receipt created_at must be RFC3339 UTC with microseconds")
    try:
        datetime.strptime(item["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _fail("receipt created_at is not a real RFC3339 timestamp")
    producer = _exact(item["producer"], {"module", "invoker", "version", "structured_invocation_sha256"}, "producer")
    bound = _exact(producer["module"], {"path", "sha256"}, "producer module")
    _absolute_path(bound["path"], "producer module path"); _sha256(bound["sha256"], "producer module SHA-256")
    if producer["invoker"] is not None:
        invoker = _exact(producer["invoker"], {"path", "sha256"}, "producer invoker")
        _absolute_path(invoker["path"], "producer invoker path"); _sha256(invoker["sha256"], "producer invoker SHA-256")
    if producer["version"] != RUNNER_VERSION: _fail("producer version is invalid")
    _sha256(producer["structured_invocation_sha256"], "producer structured invocation SHA-256")
    source = _exact(item["source"], {"head", "index_tree", "manifest_sha256", "file_count", "snapshot"}, "source")
    if not isinstance(source["head"], str) or _GIT_OBJECT.fullmatch(source["head"]) is None: _fail("source HEAD is invalid")
    if not isinstance(source["index_tree"], str) or _GIT_OBJECT.fullmatch(source["index_tree"]) is None: _fail("source index tree is invalid")
    if source["head"] == "0" * len(source["head"]) or source["index_tree"] == "0" * len(source["index_tree"]): _fail("source Git identity is null")
    _sha256(source["manifest_sha256"], "source manifest SHA-256"); _int(source["file_count"], "source file_count")
    if type(source["snapshot"]) is not bool: _fail("source snapshot flag is invalid")
    interpreter = _exact(item["interpreter"], {"path", "sha256", "implementation", "version"}, "interpreter")
    _absolute_path(interpreter["path"], "interpreter path"); _sha256(interpreter["sha256"], "interpreter SHA-256")
    _string(interpreter["implementation"], "interpreter implementation"); _string(interpreter["version"], "interpreter version")
    invocation = _exact(item["invocation"], {"argv", "cwd_role", "environment_names", "environment_sha256"}, "invocation")
    if not isinstance(invocation["argv"], list) or not all(isinstance(x, str) for x in invocation["argv"]): _fail("pytest argv is invalid")
    if invocation["cwd_role"] != "private_git_blob_snapshot": _fail("pytest cwd role is invalid")
    if not isinstance(invocation["environment_names"], list) or invocation["environment_names"] != sorted(invocation["environment_names"]) or len(invocation["environment_names"]) != len(set(invocation["environment_names"])) or any(x not in _ENV_ALLOWLIST | {"PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONHASHSEED"} for x in invocation["environment_names"]): _fail("environment names are invalid")
    _sha256(invocation["environment_sha256"], "environment SHA-256")
    if producer["structured_invocation_sha256"] != _sha256_bytes(
        _canonical({"pytest_argv": invocation["argv"], "protocol": "pytest-arg-vector-v1"})
    ):
        _fail("runner structured invocation does not bind pytest argv")
    domain = _exact(item["platform"], {"domain", "system", "release", "wsl_distro", "kernel"}, "platform")
    if domain["domain"] not in {"windows", "wsl", "linux"}: _fail("platform domain is invalid")
    for key in ("system", "release", "wsl_distro", "kernel"):
        if not isinstance(domain[key], str): _fail(f"platform {key} is invalid")
    log = _exact(item["log"], {"sha256", "size", "path_role"}, "log")
    _sha256(log["sha256"], "log SHA-256"); _int(log["size"], "log size")
    if log["path_role"] != "repo_external_combined_log": _fail("log path role is invalid")
    for key in ("pytest_exit_code",):
        if isinstance(item[key], bool) or not isinstance(item[key], int): _fail(f"{key} is invalid")
    matrix = item["github_matrix_identity"]
    if matrix is not None:
        matrix = _exact(matrix, {"repository", "ref", "event", "workflow_ref", "job_key", "runner_os", "runner_arch", "run_id", "run_attempt", "matrix_gate_id", "matrix"}, "GitHub matrix identity")
        for key in ("repository", "ref", "event", "workflow_ref", "job_key", "runner_os", "runner_arch", "matrix_gate_id"):
            _string(matrix[key], f"GitHub matrix {key}")
        _int(matrix["run_id"], "GitHub matrix run id", minimum=1); _int(matrix["run_attempt"], "GitHub matrix run attempt", minimum=1)
        if not isinstance(matrix["matrix"], Mapping): _fail("GitHub matrix tuple is invalid")
        for key, val in matrix["matrix"].items():
            if not isinstance(key, str) or not isinstance(val, str): _fail("GitHub matrix tuple is invalid")
    elif require_github_matrix:
        _fail("GitHub matrix identity is required")
    observation = _exact(item["observation"], {"pre", "post", "error"}, "observation")
    observed_identities: dict[str, Mapping[str, Any]] = {}
    for phase in ("pre", "post"):
        observed = _exact(observation[phase], {"head", "index_tree", "status_sha256", "manifest_sha256"}, f"observation {phase}")
        if not isinstance(observed["head"], str) or _GIT_OBJECT.fullmatch(observed["head"]) is None: _fail(f"observation {phase} HEAD is invalid")
        if not isinstance(observed["index_tree"], str) or _GIT_OBJECT.fullmatch(observed["index_tree"]) is None: _fail(f"observation {phase} index tree is invalid")
        if observed["head"] == "0" * len(observed["head"]) or observed["index_tree"] == "0" * len(observed["index_tree"]): _fail(f"observation {phase} Git identity is null")
        _sha256(observed["status_sha256"], f"observation {phase} status SHA-256")
        _sha256(observed["manifest_sha256"], f"observation {phase} manifest SHA-256")
        observed_identities[phase] = observed
    pre = observed_identities["pre"]
    post = observed_identities["post"]
    if pre["status_sha256"] != EMPTY_GIT_STATUS_SHA256:
        _fail("source-tree pre-status is not canonical clean porcelain output")
    if (source["head"], source["index_tree"], source["manifest_sha256"]) != (pre["head"], pre["index_tree"], pre["manifest_sha256"]):
        _fail("source identity does not match pre-observation")
    oid_widths = {
        len(source["head"]), len(source["index_tree"]),
        len(pre["head"]), len(pre["index_tree"]),
        len(post["head"]), len(post["index_tree"]),
    }
    if oid_widths not in ({40}, {64}):
        _fail("receipt mixes Git object identifier widths")
    identity_is_unchanged = all(pre[field] == post[field] for field in ("head", "index_tree", "manifest_sha256", "status_sha256"))
    if item["identity_unchanged"] != identity_is_unchanged:
        _fail("receipt identity_unchanged is not derived from observations")
    if observation["error"] is not None and not isinstance(observation["error"], str): _fail("observation error is invalid")
    accepted = item["accepted"]
    if accepted != (item["pytest_exit_code"] == 0 and item["identity_unchanged"] and item["log_closed"] and item["publication_atomic"] and item["terminal_status"] == "completed"):
        _fail("receipt accepted predicate is invalid")
    if accepted and (source["snapshot"] is not True or observation["error"] is not None):
        _fail("accepted receipt has an invalid snapshot or error observation")
    if require_github_matrix and producer["invoker"] is None:
        _fail("accepted required-GitHub receipt lacks an actual wrapper identity")
    claimed = _sha256(item["receipt_sha256"], "receipt SHA-256")
    base = dict(item); del base["receipt_sha256"]
    if claimed != _sha256_bytes(_canonical(base)): _fail("receipt self digest is invalid")
    return dict(item)


def canonical_exact_test_receipt_bytes(value: Mapping[str, Any], *, require_github_matrix: bool = False) -> bytes:
    checked = validate_exact_test_receipt(value, require_github_matrix=require_github_matrix)
    raw = _canonical(checked) + b"\n"
    if len(raw) > MAX_RECEIPT_BYTES: _fail("receipt exceeds byte bound")
    return raw


def parse_exact_test_receipt_bytes(raw: bytes, *, require_github_matrix: bool = False) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RECEIPT_BYTES: _fail("receipt bytes are empty or exceed their bound")
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result: _fail(f"receipt contains duplicate JSON key: {key}")
            result[key] = item
        return result
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=lambda x: (_fail(f"receipt has forbidden JSON constant: {x}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"receipt is not strict UTF-8 JSON: {exc}")
    checked = validate_exact_test_receipt(parsed, require_github_matrix=require_github_matrix)
    if raw != _canonical(checked) + b"\n": _fail("receipt bytes are not canonical LF JSON")
    return checked


def verify_exact_test_log(path: Path, receipt: Mapping[str, Any]) -> None:
    """Fail closed when a separately retained combined log was changed.

    The receipt deliberately records a path *role*, not a local machine path;
    the caller supplies the retained external log and this function binds it
    back through the recorded byte count and digest.
    """
    checked = validate_exact_test_receipt(receipt)
    raw = _stable_regular_read(path, "combined log")
    if len(raw) != checked["log"]["size"] or _sha256_bytes(raw) != checked["log"]["sha256"]:
        _fail("combined log digest does not match receipt")


def _git(repo: Path, args: Sequence[str], *, binary: bool = False) -> bytes:
    try:
        return subprocess.run(["git", "-C", os.fspath(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        _fail(f"Git command failed: {exc}")


def _inside(child: Path, parent: Path) -> bool:
    try: child.resolve(strict=False).relative_to(parent.resolve(strict=False)); return True
    except ValueError: return False


def _external_absolute(path: Path, repo: Path, label: str) -> Path:
    if not path.is_absolute(): _fail(f"{label} must be an absolute path")
    if _inside(path, repo): _fail(f"{label} must be outside repository")
    return path.resolve(strict=False)


def _status(repo: Path) -> dict[str, Any]:
    head = _git(repo, ["rev-parse", "--verify", "HEAD"]).decode("ascii").strip()
    index_tree = _git(repo, ["write-tree"]).decode("ascii").strip()
    status = _git(repo, ["status", "--porcelain=v2", "-z", "--untracked-files=all"])
    if _GIT_OBJECT.fullmatch(head) is None or _GIT_OBJECT.fullmatch(index_tree) is None: _fail("Git identity is malformed")
    return {"head": head, "index_tree": index_tree, "status_sha256": _sha256_bytes(status), "clean": not status}


def _windows_materialization_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    """Reject Git paths with no lossless ordinary-Windows-file mapping."""
    normalized: list[str] = []
    for component in parts:
        if (
            not component
            or component in {".", ".."}
            or ":" in component
            or component[-1:] in {".", " "}
            or any(character in '<>"\\|?*' or ord(character) < 32 for character in component)
            or re.search(r"~[0-9](?:\.|$)", component, flags=re.IGNORECASE) is not None
            or len(component.encode("utf-16-le")) > 480
        ):
            _fail("Git tree path is not safely materializable on Windows")
        device = component.rstrip(" .").split(".", 1)[0].rstrip(" ").upper()
        if device in _WINDOWS_RESERVED:
            _fail("Git tree path uses a reserved Windows device name")
        normalized.append(unicodedata.normalize("NFKC", component).casefold())
    return tuple(normalized)


def _snapshot(repo: Path, destination: Path) -> tuple[str, int]:
    raw = _git(repo, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"])
    entries: list[tuple[str, str, str, str]] = []
    windows_paths: set[tuple[str, ...]] = set()
    for record in raw.split(b"\0"):
        if not record: continue
        try: header, raw_path = record.split(b"\t", 1); mode, kind, object_id = header.decode("ascii").split(" ", 2); name = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError): _fail("Git tree entry is malformed or non-UTF-8")
        pure = PurePosixPath(name)
        if not name or "\\" in name or pure.is_absolute() or any(p in {"", ".", ".."} for p in pure.parts): _fail("Git tree path is unsafe")
        windows_key = _windows_materialization_key(pure.parts)
        if windows_key in windows_paths:
            _fail("Git tree paths collide under Windows case or alias rules")
        windows_paths.add(windows_key)
        if kind != "blob" or mode not in {"100644", "100755"}: _fail("Git tree contains symlink, gitlink, or unsupported mode")
        entries.append((name, mode, kind, object_id))
    if entries != sorted(entries): _fail("Git tree is noncanonical")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest: list[dict[str, str]] = []
    for name, mode, _kind, object_id in entries:
        target = destination.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _inside(target, destination) is False or target.exists() or target.is_symlink(): _fail("snapshot path is unsafe")
        content = _git(repo, ["cat-file", "blob", object_id])
        with target.open("xb") as stream: stream.write(content)
        if mode == "100755": target.chmod(0o700)
        manifest.append({"path": name, "mode": mode, "blob": object_id, "sha256": _sha256_bytes(content)})
    return _sha256_bytes(_canonical({"files": manifest})), len(entries)


def platform_domain(*, system: str | None = None, release: str | None = None, environ: Mapping[str, str] | None = None, proc_version: str | None = None) -> dict[str, str]:
    environ = os.environ if environ is None else environ
    system = _platform.system() if system is None else system
    release = _platform.release() if release is None else release
    if proc_version is None and system == "Linux":
        try: proc_version = Path("/proc/version").read_text(encoding="utf-8", errors="replace")
        except OSError: proc_version = ""
    is_wsl = system == "Linux" and ("microsoft" in (proc_version or "").lower() or "WSL_DISTRO_NAME" in environ)
    return {"domain": "windows" if system == "Windows" else "wsl" if is_wsl else "linux", "system": system, "release": release, "wsl_distro": environ.get("WSL_DISTRO_NAME", "") if is_wsl else "", "kernel": release if is_wsl else ""}


def _child_env(snapshot: Path, inherited: Mapping[str, str]) -> tuple[dict[str, str], list[str], str]:
    env = {key: inherited[key] for key in sorted(_ENV_ALLOWLIST) if key in inherited}
    env.update({"PYTHONPATH": os.fspath(snapshot / "src"), "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONHASHSEED": "0"})
    names = sorted(env)
    return env, names, _sha256_bytes(_canonical({"environment": {key: env[key] for key in names}}))


def _producer_identity(pytest_argv: Sequence[str], invoker_path: Path | None) -> dict[str, Any]:
    module = Path(__file__).resolve()
    return {
        "module": {"path": os.fspath(module), "sha256": _sha256_file(module)},
        # None means direct API use.  A supplied invoker is an identity of the
        # caller observed by the core, never a claim about that process' exit.
        "invoker": None if invoker_path is None else {"path": os.fspath(invoker_path.resolve(strict=True)), "sha256": _sha256_file(invoker_path.resolve(strict=True))},
        "version": RUNNER_VERSION,
        "structured_invocation_sha256": _sha256_bytes(
            _canonical({"pytest_argv": list(pytest_argv), "protocol": "pytest-arg-vector-v1"})
        ),
    }


def _interpreter_identity() -> dict[str, str]:
    path = Path(sys.executable).resolve()
    return {"path": os.fspath(path), "sha256": _sha256_file(path), "implementation": _platform.python_implementation(), "version": sys.version}


def _atomic_create(path: Path, raw: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink(): raise ReceiptPublicationError("receipt target already exists")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        # Hard-link publication is an atomic no-replace create on the same
        # filesystem.  Unlike os.replace it cannot overwrite a concurrent
        # receipt target.  The temp is deliberately in the destination parent.
        os.link(temporary, path)
    except OSError as exc:
        raise ReceiptPublicationError(f"cannot publish receipt: {exc}") from exc
    finally:
        try: temporary.unlink(missing_ok=True)
        except OSError: pass


def run_clean_commit_source_tree(*, repo: Path, pytest_argv: Sequence[str], receipt_path: Path, logs_dir: Path, timeout_seconds: float | None = None, github_matrix_identity: Mapping[str, Any] | None = None, require_github_matrix: bool = False, inherited_env: Mapping[str, str] | None = None, invoker_path: Path | None = None) -> dict[str, Any]:
    """Run structured pytest arguments against a private snapshot and publish one receipt."""
    repo = repo.resolve(strict=True); receipt_path = _external_absolute(receipt_path, repo, "receipt path"); logs_dir = _external_absolute(logs_dir, repo, "logs directory")
    if not pytest_argv or any(not isinstance(item, str) or "\0" in item for item in pytest_argv): _fail("pytest argv must be a non-empty string vector")
    inherited_env = os.environ if inherited_env is None else inherited_env
    pre = _status(repo)
    if not pre["clean"]: _fail("repository HEAD/index/tree is not clean")
    scratch = Path(tempfile.mkdtemp(prefix="aoi-exact-test-"))
    log_path = logs_dir / f"exact-test-{uuid.uuid4().hex}.log"
    result_code, terminal, error = -1, "runner_error", None
    try:
        snapshot = scratch / "snapshot"; manifest, count = _snapshot(repo, snapshot)
        env, env_names, env_sha = _child_env(snapshot, inherited_env)
        # Preserve the venv launcher spelling.  Resolving a POSIX venv's
        # ``bin/python`` symlink to the base interpreter discards the venv
        # package context and can run a different pytest environment.
        command = [sys.executable, "-m", "pytest", *pytest_argv]
        try:
            completed = subprocess.run(command, cwd=snapshot, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout_seconds, check=False)
            result_code = completed.returncode; log = completed.stdout; terminal = "completed" if result_code == 0 else "rejected"
        except subprocess.TimeoutExpired as exc:
            result_code = -1; log = (exc.stdout or b"") + (exc.stderr or b""); terminal = "timeout"; error = "pytest timeout"
        logs_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        with log_path.open("xb") as stream: stream.write(log); stream.flush(); os.fsync(stream.fileno())
        post = _status(repo)
        post_manifest, _post_count = _snapshot(repo, scratch / "post-manifest")
        unchanged = pre["head"] == post["head"] and pre["index_tree"] == post["index_tree"] and manifest == post_manifest and post["clean"]
        if not unchanged and terminal == "completed": terminal = "rejected"; error = "repository identity changed during run"
        log_closed = _sha256_file(log_path) == _sha256_bytes(log) and log_path.stat().st_size == len(log)
        base: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "kind": RECEIPT_KIND, "accepted": False, "terminal_status": terminal, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "producer": _producer_identity(pytest_argv, invoker_path), "source": {"head": pre["head"], "index_tree": pre["index_tree"], "manifest_sha256": manifest, "file_count": count, "snapshot": True}, "interpreter": _interpreter_identity(), "invocation": {"argv": list(pytest_argv), "cwd_role": "private_git_blob_snapshot", "environment_names": env_names, "environment_sha256": env_sha}, "platform": platform_domain(), "log": {"sha256": _sha256_bytes(log), "size": len(log), "path_role": "repo_external_combined_log"}, "pytest_exit_code": result_code, "identity_unchanged": unchanged, "log_closed": log_closed, "publication_atomic": True, "github_matrix_identity": dict(github_matrix_identity) if github_matrix_identity is not None else None, "observation": {"pre": {**{key: pre[key] for key in ("head", "index_tree", "status_sha256")}, "manifest_sha256": manifest}, "post": {**{key: post[key] for key in ("head", "index_tree", "status_sha256")}, "manifest_sha256": post_manifest}, "error": error}}
        base["accepted"] = result_code == 0 and unchanged and log_closed and terminal == "completed"
        base["receipt_sha256"] = _sha256_bytes(_canonical(base))
        raw = canonical_exact_test_receipt_bytes(base, require_github_matrix=require_github_matrix)
        _atomic_create(receipt_path, raw)
        return base
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


__all__ = ["ExactTestReceiptError", "ReceiptPublicationError", "canonical_exact_test_receipt_bytes", "parse_exact_test_receipt_bytes", "platform_domain", "run_clean_commit_source_tree", "validate_exact_test_receipt", "verify_exact_test_log"]
