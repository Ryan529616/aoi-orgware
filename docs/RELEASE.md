# Release runbook (PyPI)

AOI ships as a pure-stdlib package with a `hatchling` backend and no runtime
dependencies. Public releases use GitHub Actions and PyPI Trusted Publishing:
the release workflow requests a short-lived OIDC credential and never stores a
long-lived PyPI token in the repository, GitHub secrets, local files, or logs.

Prior local dry-runs (v0.1.2-alpha, v0.2.1) produced clean wheels and sdists
with recorded SHA-256 and byte-identity checks. This runbook keeps those local
checks and adds an independently rebuilt, tag-bound PyPI publication path.

## 0. Preconditions

- The release worktree is clean and local `main`, `origin/main`, and the
  intended release commit resolve to one exact SHA.
- `version` in `pyproject.toml`, `aoi_orgware.__version__`, the CLI version
  test, `CHANGELOG.md`, and versioned public documentation all agree.
- CI is green on the release commit for the complete Windows/Linux and Python
  3.11/3.12 matrix, including Windows path canonicalization.
- The intended tag and PyPI version do not already exist. PyPI distributions
  are immutable and must never be overwritten.
- `.github/workflows/publish.yml` is present on the default branch with
  immutable action SHAs and least-privilege job permissions.

## 1. Clean local build and verification

Build from the exact release commit in a disposable, repo-external worktree and
environment. Keep build tools out of the source root so a local `build/`
directory cannot shadow the PyPA `build` package.

```bash
python -m venv <release-root>/build-env
<release-root>/build-env/bin/python -m pip install \
  "build==1.5.0" "twine==6.2.0"
<release-root>/build-env/bin/python -m build \
  --sdist --wheel --outdir <release-root>/dist
<release-root>/build-env/bin/python -m twine check --strict \
  <release-root>/dist/*
```

PowerShell uses `<release-root>\build-env\Scripts\python.exe`. Build twice
from the same exact commit with `SOURCE_DATE_EPOCH` set to that commit's Unix
timestamp (`git show -s --format=%ct <release-sha>`), then compare SHA-256
values. The expected set is:

```text
aoi_orgware-<version>-py3-none-any.whl
aoi_orgware-<version>.tar.gz
```

Inspect both archives. They must contain the package metadata and README, and
must not contain `PROVENANCE.md` or `IMPORT_MANIFEST.json`.

Run the complete local test suite and a fresh wheel-install smoke test:

```bash
python -m pytest -q
python -m unittest discover -s tests -v

python -m venv <release-root>/smoke-env
<release-root>/smoke-env/bin/python -m pip install \
  --no-deps <release-root>/dist/aoi_orgware-<version>-py3-none-any.whl
<release-root>/smoke-env/bin/aoi --version
<release-root>/smoke-env/bin/aoi --help
<release-root>/smoke-env/bin/aoi codex-init --help
<release-root>/smoke-env/bin/aoi claude-init --help
<release-root>/smoke-env/bin/aoi-codex-hook --help
<release-root>/smoke-env/bin/aoi-claude-hook --help
```

## 2. One-time Trusted Publishing setup

Create a GitHub environment named exactly `pypi`. Restrict deployment branches
and tags to the release-tag policy (currently `v*`). If more than one trusted
maintainer exists, add a required reviewer; do not enable a self-review rule
that leaves a single-maintainer project unable to publish.

For the first PyPI release, register a pending GitHub publisher at
<https://pypi.org/manage/account/publishing/>:

| Field | Value |
|---|---|
| PyPI project name | `aoi-orgware` |
| Owner | `Ryan529616` |
| Repository | `aoi-orgware` |
| Workflow filename | `publish.yml` |
| Environment | `pypi` |

The pending publisher does not reserve the project name. On the first successful
OIDC upload it creates the project and becomes a normal Trusted Publisher.

## 3. Tag, GitHub Release, and PyPI publication

After the exact release commit is pushed and its CI is green:

```bash
git tag -a v<version> -m "AOI v<version> alpha"
git push origin v<version>
```

Create the GitHub prerelease for that tag using the matching
`CHANGELOG.md` section. Publishing the release (including publishing a draft)
triggers `publish.yml`. Its build job:

1. checks out the release tag without persisting credentials;
2. verifies project, tag, and source versions;
3. runs the complete unit suite;
4. builds and strictly checks the wheel and sdist;
5. verifies archive exclusions and a fresh install; and
6. uploads the verified distributions as a workflow artifact.

The separate publish job receives only `id-token: write`, downloads that
same-run artifact, and uploads it through PyPI Trusted Publishing with PEP 740
attestations. It does not check out or execute repository code.

## 4. Post-publication readback

- Confirm the release workflow completed successfully.
- Read the PyPI JSON/simple index and verify version, filenames, SHA-256 values,
  project URLs, Python requirement, and attestations.
- Install `aoi-orgware==<version>` from PyPI in a new environment and repeat
  the CLI/onboarding/hook smoke checks.
- Download the workflow artifact, compute `SHA256SUMS.txt`, and attach the
  exact published wheel, sdist, and checksum file to the GitHub Release.
- Verify local tag, remote tag (including the peeled annotated-tag commit),
  GitHub Release target, `origin/main`, and the package metadata all identify
  the intended release.

Nothing in this flow installs or trusts hooks in a user environment. Project
wiring through `aoi codex-init` or `aoi claude-init` is a separate,
explicit action. Codex hook definitions still require exact review and trust
through `/hooks`.
