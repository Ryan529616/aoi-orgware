from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import venv


def run_python_checked(
    python: Path | str,
    *arguments: str,
    cache_root: Path,
    evidence_root: Path,
    label: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one Python child with bytecode isolated and exact output retained."""

    cache_root.mkdir(parents=True, exist_ok=True)
    evidence_root.mkdir(parents=True, exist_ok=True)
    argv = [
        str(python),
        "-B",
        "-X",
        f"pycache_prefix={cache_root}",
        *arguments,
    ]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPYCACHEPREFIX"] = str(cache_root)
    raw = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        cwd=cwd,
        env=environment,
    )
    stdout = bytes(raw.stdout)
    stderr = bytes(raw.stderr)
    stdout_path = evidence_root / f"{label}.stdout.log"
    stderr_path = evidence_root / f"{label}.stderr.log"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    displayed_argv = list(argv)
    if "-c" in displayed_argv:
        script_index = displayed_argv.index("-c") + 1
        script_bytes = displayed_argv[script_index].encode("utf-8")
        displayed_argv[script_index] = (
            "<inline-python "
            f"size_bytes={len(script_bytes)} "
            f"sha256={hashlib.sha256(script_bytes).hexdigest()}>"
        )
    receipt = {
        "schema_version": 1,
        "label": label,
        "argv": displayed_argv,
        "returncode": raw.returncode,
        "stdout": {
            "path": str(stdout_path),
            "size_bytes": len(stdout),
            "sha256": hashlib.sha256(stdout).hexdigest(),
        },
        "stderr": {
            "path": str(stderr_path),
            "size_bytes": len(stderr),
            "sha256": hashlib.sha256(stderr).hexdigest(),
        },
    }
    (evidence_root / f"{label}.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    if raw.returncode != 0:
        raise AssertionError(
            "isolated Python subprocess failed: "
            + json.dumps(receipt, sort_keys=True)
        )
    return subprocess.CompletedProcess(
        argv,
        raw.returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def create_pth_clean_pip_venv(prefix: Path) -> Path:
    """Create the dedicated AOI tool venv used by provenance-qualified installs."""

    venv.EnvBuilder(with_pip=True).create(prefix)
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    evidence_root = prefix.parent / "child-evidence"
    run_python_checked(
        python,
        "-m",
        "pip",
        "uninstall",
        "--yes",
        "setuptools",
        cache_root=prefix.parent / "python-cache" / "venv-uninstall-setuptools",
        evidence_root=evidence_root,
        label="venv-uninstall-setuptools",
    )
    probe = run_python_checked(
        python,
        "-I",
        "-c",
        (
            "import json, pathlib, sysconfig; "
            "root=pathlib.Path(sysconfig.get_paths()['purelib']); "
            "bad=[p.name for p in root.glob('*.pth') "
            "if any(line.strip().startswith(('import ', 'import\\t')) "
            "for line in p.read_text(encoding='utf-8').splitlines())]; "
            "print(json.dumps(sorted(bad)))"
        ),
        cache_root=prefix.parent / "python-cache" / "venv-pth-probe",
        evidence_root=evidence_root,
        label="venv-pth-probe",
    )
    assert json.loads(probe.stdout) == []
    return python
