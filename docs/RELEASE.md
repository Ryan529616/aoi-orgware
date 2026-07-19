# Release runbook (PyPI)

AOI ships as a pure-stdlib package with a `hatchling` backend and no runtime
dependencies. Public releases use GitHub Actions and PyPI Trusted Publishing:
the release workflow builds and verifies one wheel/sdist pair, passes those
exact artifacts to a separate publication job, and requests a short-lived OIDC
credential. It does not store a long-lived PyPI token in the repository, GitHub
secrets, local files, or logs.

The 0.2.1 and 0.2.2 changelog headings are internal milestones, not published
releases. Do not manufacture retroactive tags for them.

## 0. Preconditions

- The release worktree is clean and local `main`, `origin/main`, and the
  intended release commit resolve to one exact SHA.
- `src/aoi_orgware/_version.py` contains the PEP 440 version to publish.
  `pyproject.toml`, runtime imports, CLI output, and release validation consume
  that source dynamically; do not add a second literal version.
- `CHANGELOG.md` has a matching section and the intended tag is exactly
  `v<version>` (for example, `v0.3.0a1`).
- CI is green on the release commit for Linux and Windows with Python 3.11,
  3.12, 3.13, and 3.14, including the installed-artifact jobs.
- The intended tag, GitHub Release, and PyPI version do not already exist. PyPI
  distributions are immutable and must never be overwritten.
- `.github/workflows/publish.yml` is present on the default branch with
  immutable action SHAs and least-privilege job permissions.

## 1. Clean local build and verification

Build from the exact release commit in a disposable, repo-external worktree and
environment. Keep build tools out of the source root so a local `build/`
directory cannot shadow the PyPA `build` package.

```bash
python -m pip download --isolated --require-hashes --only-binary=:all: \
  --dest <release-root>/release-tool-wheelhouse \
  -r requirements/release-tools.lock
python -m venv <release-root>/build-env
<release-root>/build-env/bin/python -I -m pip install --isolated --no-index \
  --find-links <release-root>/release-tool-wheelhouse --require-hashes \
  -r requirements/release-tools.lock
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
<release-root>/build-env/bin/python -I -m build --no-isolation \
  --sdist --wheel --outdir <release-root>/dist
<release-root>/build-env/bin/python -I scripts/verify_dist.py \
  --dist-dir <release-root>/dist --expected-version <version> \
  --build-python <release-root>/build-env/bin/python \
  --expected-build-version 1.5.0 --expected-hatchling-version 1.27.0
```

PowerShell uses `<release-root>\build-env\Scripts\python.exe`. The expected
artifact set is:

```text
aoi_orgware-<version>-py3-none-any.whl
aoi_orgware-<version>.tar.gz
```

`requirements/release-tools.lock` is the canonical hash-pinned release
toolchain. Download its wheels first, verify every hash, then install from that
wheelhouse with networking disabled; the producer receipt records the lock
SHA-256 and the exact name, version, and artifact SHA-256 for all eleven locked
distributions. Before `-I -m pytest` runs the O7 modules, install the exact
inventory-selected built wheel; no ambient install or replacement rebuild may
substitute for it.

`scripts/verify_dist.py` installs the wheel and sdist independently in fresh
environments, checks packaged resources and exact metadata/runtime versions,
and confirms all three entry points complete a `--help` smoke from outside the
source tree. The sdist path first builds its derived wheel with the verified
backend and then runs the same offline installed-artifact smoke; passing a
prebuilt wheel alone is insufficient. This verifies the built artifacts; it
does not by itself establish byte-reproducibility across independently resolved
build toolchains.

## 2. Confirm the evidence chain

```bash
git diff --exit-code
git diff --cached --exit-code
git status --porcelain=v1                # must produce no output
git rev-parse HEAD
```

Record the release SHA, version, and local wheel/sdist checksums. Do not import
`aoi_orgware` or run an ambient `aoi` executable as version evidence from a
src-layout checkout; either may resolve an unrelated installed version.

## 3. One-time Trusted Publishing setup

Create a GitHub environment named exactly `pypi`. Restrict deployments to the
release-tag policy (currently `v*`). If more than one trusted maintainer exists,
add a required reviewer; do not enable a self-review rule that leaves a
single-maintainer project unable to publish.

Register the GitHub publisher on PyPI with these values:

| Field | Value |
|---|---|
| PyPI project name | `aoi-orgware` |
| Owner | `Ryan529616` |
| Repository | `aoi-orgware` |
| Workflow filename | `publish.yml` |
| Environment | `pypi` |

## 4. Tag, verify CI, and publish the GitHub Release

After the exact release commit is pushed:

```bash
git tag -a v<version> -m "AOI v<version> alpha"
git push origin v<version>
```

Wait for the tag's test workflow to pass and verify that its `headSha` equals
the peeled tag commit. Then create and publish the matching GitHub prerelease.
The publication workflow is deliberately manual; the GitHub Release event does
not trigger it. Dispatch the workflow only after those checks, with the exact
tag and explicit publish intent:

```bash
gh workflow run publish.yml --ref main -f tag=v<version> -f intent=publish
```

Verify that the resulting run checked out the peeled tag commit before treating
any producer or publication evidence as belonging to that release.

The release workflow:

1. checks out the release tag without persisting credentials;
2. verifies the project name, tag, dynamic version source, and Hatch binding;
3. creates and verifies the hash-pinned, offline release-tool wheelhouse;
4. builds and strictly checks one wheel and one sdist;
5. installs the exact inventory-selected wheel before `-I` O7 tests and runs
   `scripts/verify_dist.py` against both artifacts;
6. records the eleven-distribution toolchain receipt and the producer evidence;
7. uploads the verified pair as a same-run workflow artifact; and
8. passes only those bytes to the OIDC publication job.

The publication job receives only `id-token: write`; it does not check out or
execute repository code.

### Exact staged upload contract

The upload input is not merely the workflow artifact name. The Linux producer
creates the wheel/sdist inventory and producer receipt, then stages exactly the
two distribution files with that inventory, release manifest, and producer
receipt. The upload job downloads that closed stage and revalidates before
upload: canonical JSON and self-digests; exactly one wheel and one sdist;
filename, size, and SHA-256 for each staged byte; manifest-to-inventory
equality; and the complete Linux producer chain (producer receipt → Linux
inventory → manifest producer binding). Missing or extra staged files, a
replaced artifact, or any chain mismatch stops publication. Trusted Publishing
then receives only the revalidated `dist/` pair.

This contract describes the required workflow, not a claim that a GitHub
Actions run has completed. In particular, local build/rehearsal evidence does
not establish a Linux producer result, staged-upload revalidation, PyPI
publication, or post-publication readback.

## 5. Post-publication readback

- Confirm the release workflow completed successfully.
- Read the PyPI JSON/simple index and verify version, filenames, SHA-256 values,
  project URLs, Python requirement, and attestations.
- Install `aoi-orgware==<version>` from PyPI in a new environment and repeat
  the CLI/onboarding/hook smoke checks.
- Download the workflow artifact, compute `SHA256SUMS.txt`, and attach the exact
  published wheel, sdist, and checksum file to the GitHub Release.
- Verify local tag, remote tag (including the peeled annotated-tag commit),
  GitHub Release target, `origin/main`, package metadata, and recorded checksums
  all identify the same release.

PyPI's integrity/attestation response is retained as **presence-only**
provenance bound to the expected artifact and trusted-publisher identity. It is
not a cryptographic verification of the attestation, not proof of the local
wheel bytes used by an installer, and not a substitute for the exact PyPI file
SHA-256 and isolated install checks.

Nothing in this flow installs or trusts hooks in a user environment. Project
wiring through `aoi codex-init` or `aoi claude-init` is a separate, explicit
action. Codex hook definitions still require exact review and trust through
`/hooks`.
