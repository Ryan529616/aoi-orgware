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
- `aoi.toml` has been reviewed. An empty `confidentiality.protected` set permits
  the normal AOI release. If any rule exists, every workflow artifact, package,
  and GitHub Release asset must pass the exact member-level publication
  preflight for its real destination.
- `release/publication-policy.json` exactly matches the canonical output of
  `aoi confidentiality-policy-snapshot` for the reviewed local config and
  protected origins, and the workflow's independent expected-digest pin matches
  it. Raw `aoi.toml` is never a remote workflow input.

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
and confirms all four entry points complete a `--help` smoke from outside the
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
the peeled tag commit. Do not create or populate the GitHub Release by hand.
The publication workflow is deliberately manually dispatched; it creates or
reconciles the exact GitHub prerelease, independently reads it back, and only
then permits PyPI publication. Dispatch it only after the tag checks, with the
exact tag and explicit publish intent:

```bash
gh workflow run publish.yml --ref main -f tag=v<version> -f intent=publish
```

Verify that the resulting run checked out the peeled tag commit before treating
any producer or publication evidence as belonging to that release. The
workflow also requires its dispatch `GITHUB_SHA` (the `--ref main` workflow
bytes) to equal that same peeled commit, so dispatch after `main` advances is
rejected instead of running different workflow bytes against the tag.

The release workflow:

1. checks out the release tag without persisting credentials;
2. verifies the project name, tag, dynamic version source, and Hatch binding;
3. creates and verifies the hash-pinned, offline release-tool wheelhouse;
4. builds and strictly checks one wheel and one sdist;
5. installs the exact inventory-selected wheel before `-I` O7 tests and runs
   `scripts/verify_dist.py` against both artifacts;
6. records the eleven-distribution toolchain receipt, the exact annotated tag
   object-to-commit/tree binding, and the producer evidence;
7. inventories each exact upload directory/file, including wheel/ZIP and
   gzip-tar members, and requires an allowed destination-bound confidentiality
   preflight before every GitHub Actions artifact upload;
8. preserves a package-publication preflight bound to the exact staged wheel
   and sdist container hashes;
9. uses a non-OIDC verification job, checked out at the producer's exact peeled
   commit, to revalidate the closed stage and seal a minimal publication
   envelope containing the two distributions and their package-publication
   receipt; and
10. seals a separate GitHub Release envelope containing the same wheel/sdist,
    deterministic `SHA256SUMS.txt`, an exact `release_publish` preflight, and a
    non-recursive Actions-artifact receipt;
11. gives one no-checkout job `contents: write` only, makes it rebind the remote
    annotated tag object to the exact peeled commit, creates or resumes a
    non-public draft, reconciles and downloads only the three expected assets,
    verifies their SHA-256 values, then publishes the complete draft as a
    prerelease in the final mutation;
12. gives a separate `contents: read` job the exact commit and envelope artifact
    ID, makes it formally verify both publication receipts, independently read
    back the tag, deterministic Release marker, state, asset set, sizes, and
    downloaded hashes, and persist a gated content-addressed readback candidate;
    and
13. permits the PyPI OIDC job to start only after that GitHub Release readback
    job succeeds.

The GitHub Release writer receives only `contents: write`: it has no checkout
and executes no repository code. A new or partially staged Release remains a
draft while assets are uploaded. A rerun may fill an absent expected draft
asset only after a complete first pass verifies every existing asset, a stable
Release state, and the exact remote tag object/peeled commit; unexpected names
or conflicting bytes fail closed. A published but incomplete Release is never
mutated automatically. Only a complete, stable, hash-verified draft is changed
to `draft=false`, after which the published prerelease is read back again. The
writer discovers drafts through an authenticated fully paginated listing; an
API or transport failure is never classified as absence. Its deterministic
draft marker binds the repository, tag object, commit, filenames, sizes,
hashes, policy, and deterministic preflight digests. The run-local Actions ZIP
digest remains provenance but is deliberately excluded from cross-run draft
identity because archive metadata may change on a content-equivalent rerun.
Every delete, upload, and
publish mutation rechecks that marker, exact Release ID, draft state, and tag
binding. Only an expected zero-byte `starter` asset left by a failed upload may
be deleted automatically, and only while that exact Release remains a draft.
The PyPI OIDC publication job receives only `id-token: write`: it also has no
checkout, does not execute repository Python, and downloads only the sealed
artifact ID.
After its environment approval, workflow-owned code uses the public GitHub API
and asset URLs to recheck the exact tag, deterministic Release marker, state,
asset set, and hashes immediately before publication without receiving
repository credentials.

The same job reads the public PyPI version and Integrity API before upload. An
absent version stages both files; a crash-left partial version may stage only
the missing file after every existing file has matching size, downloaded hash,
and presence-only trusted-publisher provenance. Conflicting or unexpected
files fail closed. The publisher action is never given `skip-existing`; an
ambiguous action outcome is followed by a bounded exact remote reconciliation,
and the job succeeds only when both filenames, bytes, and trusted-publisher
provenance are present. No reusable GitHub or PyPI credential is stored by AOI.

### Exact staged upload contract

The upload input is not merely the workflow artifact name. The Linux producer
creates the wheel/sdist inventory and producer receipt, then stages exactly the
two distribution files with that inventory, release manifest, producer
receipt, tracked `release/publication-policy.json`, and PyPI
destination/member preflight. The upload job downloads that
closed stage and revalidates before
upload: canonical JSON and self-digests; exactly one wheel and one sdist;
filename, size, and SHA-256 for each staged byte; manifest-to-inventory
equality; and the complete Linux producer chain (producer receipt → Linux
inventory → manifest producer binding). It also verifies the preflight action,
PyPI destination, decision, receipt digest, expected snapshot SHA-256, and exact equality between its two
container rows and the inventory's filename/size/SHA-256 pair. Missing or extra staged files, a
replaced artifact, or any chain mismatch stops publication. The sealed envelope
retains the exact package-publication receipt as evidence; Trusted Publishing
then receives only the revalidated `dist/` pair.

Each Actions upload receipt is a non-recursive sidecar: create it outside the
payload subject, copy it into the uploaded envelope, move it outside again at
the receiver, recompute the payload receipt exactly, then restore it. A receipt
must never appear as a zero-byte or completed member of its own inventory.

This contract describes the required workflow, not a claim that a GitHub
Actions run has completed. In particular, local build/rehearsal evidence does
not establish a Linux producer result, staged-upload revalidation, PyPI
publication, or post-publication readback.

## 5. Post-publication readback

- Confirm the release workflow completed successfully, including the
  `verify-github-release` job before `publish-pypi`.
- Download the gated `github-release-readback-candidate` Actions artifact and
  verify its receipt against the exact release commit's policy snapshot.
- Read the PyPI JSON/simple index and verify version, filenames, SHA-256 values,
  project URLs, Python requirement, and attestations.
- Install `aoi-orgware==<version>` from PyPI in a new environment and repeat
  the CLI/onboarding/hook smoke checks.
- Verify the local tag, remote annotated-tag object and peeled commit, Release
  `tag_name`, `origin/main`, package metadata, and recorded checksums all
  identify the same release. For an already-existing tag, GitHub's
  `target_commitish` field is recorded as an observation only and may remain a
  branch name; the exact `tag_name -> annotated tag object -> peeled commit`
  chain is the authoritative source binding.

The workflow's GitHub Release envelope performs the standalone snapshot gate
over the three files before the writer can receive them. That preflight binds
exact containers and archive-member identities but is not, by itself, proof
that GitHub accepted or retained the upload. The separate remote API/download
readback and its gated candidate supply that observation. Local operators must
not substitute an unreceipted manual asset upload for this chain.

PyPI's integrity/attestation response is retained as **presence-only**
provenance bound to the expected artifact and trusted-publisher identity. It is
not a cryptographic verification of the attestation, not proof of the local
wheel bytes used by an installer, and not a substitute for the exact PyPI file
SHA-256 and isolated install checks.

Nothing in this flow installs or trusts hooks in a user environment. Project
wiring through `aoi codex-init` or `aoi claude-init` is a separate, explicit
action. Codex hook definitions still require exact review and trust through
`/hooks`.
