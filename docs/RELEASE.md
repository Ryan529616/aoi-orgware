# Release runbook (PyPI)

AOI ships as a pure-stdlib package with a `hatchling` backend and no runtime
dependencies, so a release is a build + verify + upload. The upload step is the
only one that needs your credentials; everything before it is reproducible and
non-credentialed.

Prior local release dry-runs (v0.1.2-alpha, v0.2.1) already produced clean
wheels and sdists with recorded SHA-256 and byte-identity checks; this runbook
generalizes that flow.

## 0. Preconditions

- CI is green on the release commit for the full matrix (Windows + Linux,
  Python 3.11/3.12). Confirm the historically-flaky Windows path-canonicalization
  job passes.
- `version` in `pyproject.toml` is the version you intend to publish, and
  `CHANGELOG.md` has a section for it.
- **Name availability:** confirm `aoi-orgware` is free (or already owned by you)
  on <https://pypi.org/project/aoi-orgware/>. This is a network/credential check
  only you can do.

## 1. Clean build

Run from the repository root in a disposable environment:

```bash
python -m venv .release-env
. .release-env/bin/activate      # PowerShell: .\.release-env\Scripts\Activate.ps1
python -m pip install --upgrade build twine
rm -rf dist
python -m build
```

This produces `dist/aoi_orgware-<version>-py3-none-any.whl` and
`dist/aoi_orgware-<version>.tar.gz`.

## 2. Metadata + long-description check

```bash
python -m twine check dist/*
```

`twine check` validates that the README renders as the PyPI long description.
The README currently opens with a Mermaid diagram, which PyPI does not render;
`twine check` will still pass (Mermaid degrades to a fenced code block), but
consider a static fallback image if the raw fence looks poor on the project page.

## 3. Fresh-install smoke test (both platforms if possible)

```bash
python -m venv .smoke-env
. .smoke-env/bin/activate
python -m pip install dist/aoi_orgware-<version>-py3-none-any.whl
aoi --version
aoi --help | grep -E "codex-init|claude-init|init|doctor"   # entry points resolve
aoi codex-init --help
aoi claude-init --help
# Confirm both hook entry points are installed:
aoi-codex-hook --hook-version 6 < /dev/null || true
aoi-claude-hook --hook-version 1 < /dev/null || true
```

Both `aoi-codex-hook` and `aoi-claude-hook` must resolve as console scripts.

## 4. Upload (your credentialed step)

```bash
python -m twine upload dist/*
```

Use a PyPI API token (recommended) or your account credentials. After upload,
verify a clean one-line install from PyPI itself:

```bash
pipx install aoi-orgware      # or: uv tool install aoi-orgware
aoi --version
```

## 5. Tag and release

```bash
git tag v<version>
git push origin v<version>
```

Publish a GitHub Release for the tag, pasting the matching `CHANGELOG.md`
section and attaching the `dist/` artifacts and their SHA-256 sums.

## Notes

- The sdist intentionally excludes `PROVENANCE.md` and `IMPORT_MANIFEST.json`;
  confirm they are absent from the built `.tar.gz` before uploading.
- Nothing in this flow installs or trusts hooks in a user environment. Project
  wiring through `aoi codex-init` or `aoi claude-init` is a separate, explicit
  action. Codex hook definitions still require exact review/trust via `/hooks`.
