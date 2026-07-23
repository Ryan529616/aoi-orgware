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

- The release worktree is clean and local `main`, the canonical GitHub
  `main`, and the intended release commit resolve to one exact peeled SHA.
- `src/aoi_orgware/_version.py` contains the PEP 440 version to publish.
  `pyproject.toml`, runtime imports, CLI output, and release validation consume
  that source dynamically; do not add a second literal version.
- `CHANGELOG.md` has a matching section and the intended tag is exactly
  `v<version>` (for example, `v0.3.0a1`).
- The canonical `test.yml` main-push run is completed and successful on the
  exact release commit for Linux and Windows with Python 3.11, 3.12, 3.13,
  and 3.14, including the installed-artifact jobs. The main-only `docs.yml`
  push run is completed and successful at that same SHA. Record both run IDs;
  a tag-push test is supplementary and cannot replace either main-push
  observation.
- The separate local fresh-ext4 WSL full-suite gate passed on the exact commit.
  GitHub-hosted Ubuntu is Linux CI evidence, not WSL evidence.
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
- Every provenance-governed AOI install uses a dedicated venv without
  `--system-site-packages`. Remove Setuptools before installing AOI; executable
  `.pth` files, including Python 3.11 venvs' `distutils-precedence.pth`, remain
  inadmissible rather than allowlisted.

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

## 4. Verify exact main-push CI, tag, and publish

Push the sealed exact release commit to `main`, then wait for the canonical
`test.yml` and main-only `docs.yml` push runs. Fetch both observations through
an authenticated GitHub API client and run the offline verifier. It binds the
canonical repository, `main`, `event=push`, completed/success state, exact
workflow path, and exact commit. Preserve its canonical UTF-8/LF receipt through
a passing `delivery_check` verification so AOI copies the exact bytes into the
task CAS before any release tag is created. Both this exact-CI artifact and the
later release-tag preflight artifact must be canonical task-CAS snapshots
(`snapshot_version = 1`); legacy live artifact references are historical
compatibility inputs only and are rejected by the release route.

The following POSIX-shell sketch shows the binding. On native Windows, capture
native stdout with a byte-preserving process redirect; do not pass these
canonical receipts through a text cmdlet that can change encoding or newlines.

```bash
repo=Ryan529616/aoi-orgware
commit="$(git rev-parse HEAD)"
test_json="$PWD/exact-main-test-runs.json"
docs_json="$PWD/exact-main-docs-runs.json"
ci_receipt="$PWD/exact-main-ci-receipt.json"

gh api -H "X-GitHub-Api-Version: 2026-03-10" \
  "repos/$repo/actions/workflows/test.yml/runs?head_sha=$commit&branch=main&event=push&status=success&per_page=100" \
  > "$test_json"
gh api -H "X-GitHub-Api-Version: 2026-03-10" \
  "repos/$repo/actions/workflows/docs.yml/runs?head_sha=$commit&branch=main&event=push&status=success&per_page=100" \
  > "$docs_json"
python -I scripts/verify_release_ci.py \
  --repository "$repo" --commit "$commit" --branch main \
  --workflow ".github/workflows/test.yml=$test_json" \
  --workflow ".github/workflows/docs.yml=$docs_json" \
  > "$ci_receipt"
ci_sha256="$(sha256sum "$ci_receipt" | awk '{print $1}')"
aoi add-verification --task <release-task> \
  --category delivery_check --status pass \
  --evidence "Authenticated exact-main test/docs receipt passed" \
  --command "scripts/verify_release_ci.py for $commit" \
  --boundary "Exact canonical main-push CI observation; not tag delivery or publication" \
  --artifact-ref "$ci_receipt=$ci_sha256"
```

Record the resulting verification index. Only then create the unused annotated
tag and build a composite preflight that re-reads that exact CAS artifact,
current approved plan, local tag object/peeled commit, effective push
destination, current remote absence, and destination-aware confidentiality
decision:

Before either release-tag command performs remote inspection, audit URL rewrite
configuration. Any configured Git `insteadOf` or `pushInsteadOf` rewrite makes
the exact release-tag route fail closed before network observation or push,
even when the current confidentiality profile has no protected subjects. Do
not try to reinterpret the effective endpoint or work around this guard: stop,
review/remove the rewrite under the applicable Git config scope, then rerun the
complete preflight.

The release helpers repeat this guard immediately next to every Git network
subprocess. The guard enumerates the same normalized config authority as that
subprocess: ambient command-count, parameter, no-system, and system-file
selectors are scrubbed; the discovered ordinary system config is included;
and the temporary endpoint pins themselves are removed from the guard result.
Thus `GIT_CONFIG_NOSYSTEM=1` cannot hide a system rewrite from the guard and
then expose it to the network helper.

The helpers generate an unguessable full transport alias and map it once to the
exact raw transport from a temporary system-scope config entry that is read
before global, repository, worktree, and command scopes. Git therefore selects
that full alias match even if an equal-length rewrite is inserted in a later
scope after the guard; later rules for the raw URL are not applied recursively.
Thus an ambient rewrite observed before the network boundary is a failure
before network access. A rewrite that appears in the remaining post-guard race
cannot redirect the already pinned subprocess away from the exact endpoint;
the post-call recheck still rejects the receipt if it sees drift. This is not,
and must not be described as, an atomic lock over Git configuration.

```bash
git config --show-origin --get-regexp '^url\..*\.(insteadOf|pushInsteadOf)$'
# Any output is a stop condition: do not run release-tag-push-preflight,
# release-tag-push-verify, remote readback, or git push until it is resolved.
```

```bash
tag=v<version>
destination=https://github.com/Ryan529616/aoi-orgware.git
tag_preflight="$PWD/$tag-push-preflight.json"
git tag -a "$tag" -m "AOI $tag alpha"
aoi release-tag-push-preflight --task <release-task> \
  --verification-index <exact-ci-verification-index> \
  --artifact-sha256 "$ci_sha256" \
  --tag "$tag" --remote github --destination "$destination" \
  > "$tag_preflight"
tag_preflight_sha256="$(sha256sum "$tag_preflight" | awk '{print $1}')"
aoi add-verification --task <release-task> \
  --category delivery_check --status pass \
  --evidence "Exact CI, plan, annotated tag, destination, and confidentiality gate bound" \
  --command "aoi release-tag-push-preflight for $tag" \
  --boundary "Cooperative pre-push authorization; not remote delivery" \
  --artifact-ref "$tag_preflight=$tag_preflight_sha256"
```

Record that second verification index. Immediately before the push, rerun the
same preflight in CAS-backed recheck mode. That mode must reopen the named
current passing verification and its content-addressed artifact, repeat the
plan/config/HEAD/tag/remote-absence checks, and emit bytes only when the stored
receipt and freshly rebuilt receipt are identical. Read the exact tag object,
tag ref, and credential-free raw push transport from those verified bytes; do
not push the mutable local tag ref, the canonical destination identity, or a
remote name. The empty force-with-lease is create-only: a competing tag
creation fails without replacement.

```bash
tag_preflight_recheck="$PWD/$tag-push-preflight-recheck.json"
aoi release-tag-push-preflight --task <release-task> \
  --verification-index <exact-ci-verification-index> \
  --artifact-sha256 "$ci_sha256" \
  --tag "$tag" --remote github --destination "$destination" \
  --recorded-preflight-verification-index <tag-preflight-verification-index> \
  --recorded-preflight-artifact-sha256 "$tag_preflight_sha256" \
  > "$tag_preflight_recheck"
test "$(sha256sum "$tag_preflight" | awk '{print $1}')" = \
  "$tag_preflight_sha256" || exit 1
test "$(sha256sum "$tag_preflight_recheck" | awk '{print $1}')" = \
  "$tag_preflight_sha256" || exit 1
cmp --silent "$tag_preflight" "$tag_preflight_recheck" || exit 1
tag_object_oid="$(python -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["tag_object_oid"])' "$tag_preflight_recheck")"
tag_ref="$(python -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["tag_ref"])' "$tag_preflight_recheck")"
push_transport="$(python -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["push_transport"])' "$tag_preflight_recheck")"
transport_alias="aoi-transport://$(python -I -c 'import secrets; print(secrets.token_hex(32))')"
transport_system_config="$(mktemp)"
cleanup_transport_config() { rm -f -- "$transport_system_config"; }
trap cleanup_transport_config EXIT HUP INT TERM
git config --file "$transport_system_config" --add \
  "url.${push_transport}.insteadOf" "$transport_alias"
git config --file "$transport_system_config" --add \
  "url.${push_transport}.pushInsteadOf" "$transport_alias"
existing_system_config="$(GIT_EDITOR=echo git config --system --edit)"
if test -f "$existing_system_config"; then
  git config --file "$transport_system_config" --add \
    include.path "$existing_system_config"
fi
chmod 600 "$transport_system_config"
env -u GIT_CONFIG_NOSYSTEM -u GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_COUNT=0 \
  GIT_CONFIG_SYSTEM="$transport_system_config" \
  git push --porcelain \
  --force-with-lease="$tag_ref:" \
  -- \
  "$transport_alias" \
  "$tag_object_oid:$tag_ref"
cleanup_transport_config
trap - EXIT HUP INT TERM

tag_delivery="$PWD/$tag-push-delivery.json"
aoi release-tag-push-verify --task <release-task> \
  --preflight-verification-index <tag-preflight-verification-index> \
  --preflight-artifact-sha256 "$tag_preflight_sha256" \
  --tag "$tag" --expected-commit "$commit" \
  --remote github --destination "$destination" \
  > "$tag_delivery"
tag_delivery_sha256="$(sha256sum "$tag_delivery" | awk '{print $1}')"
aoi add-verification --task <release-task> \
  --category delivery_check --status pass \
  --evidence "Remote annotated tag object and peeled commit matched preflight" \
  --command "aoi release-tag-push-verify for $tag" \
  --boundary "Authenticated remote tag readback; not GitHub Release, PyPI, or task completion" \
  --artifact-ref "$tag_delivery=$tag_delivery_sha256"
```

Do not retry an ambiguous push blindly. Run the readback command first: if the
exact object arrived, it reconciles the outcome; if it did not, rerun the full
preflight and byte comparison before considering another create-only push. A
known successful push must be read back as the same remote annotated tag object
and peeled commit. The delivery receipt also binds the exact task-CAS
verification index, verification-record SHA-256, artifact SHA-256, and
preflight receipt SHA-256 used for that readback.

The two `release-tag-*` commands are read-only consumers of current AOI state;
only the Chief-fenced `add-verification` calls mutate task state. The composite
preflight is a cooperative gate, not system DLP. A missing, lightweight,
already-existing, changed, or wrongly peeled tag; stale/superseded verification;
noncanonical receipt; plan/config/head/policy drift; split fetch/push endpoint
confusion; a tag object whose embedded name differs from the ref; a tag-of-tag;
protected-content destination mismatch; any `insteadOf`/`pushInsteadOf` URL
rewrite observed before the network boundary; raw-transport drift detected by
the post-call recheck; a missing, tampered, legacy-live, or non-current recorded
preflight CAS edge; or remote readback mismatch fails closed. The exact-identity
pin limits the residual post-guard race to the receipt-bound endpoint; it does
not atomically lock Git configuration. Public release-tag receipt validation
independently checks the embedded confidentiality
preflight's exact schema and canonical self-digest, in addition to the outer
receipt digest; a merely matching embedded digest field is insufficient.

The tag push may start another test run. If present, verify that its `headSha`
equals the peeled tag commit, but treat it only as supplementary evidence.
`docs.yml` intentionally runs on `main` pushes, not tag pushes. Do not create or
populate the GitHub Release by hand. The publication workflow is deliberately
manually dispatched; it independently re-verifies the required exact-main-push
test/docs observations, creates or reconciles the exact GitHub prerelease,
reads it back, and only then permits PyPI publication. Dispatch it with the
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
   receipt;
10. seals a separate GitHub Release envelope containing the same wheel/sdist,
    deterministic `SHA256SUMS.txt`, an exact `release_publish` preflight, and a
    non-recursive Actions-artifact receipt;
11. gives a separate read-only job only `actions: read` and `contents: read`,
    makes it query the canonical `test.yml` and `docs.yml` main-push runs, and
    fails closed unless both bind the exact peeled release commit, repository,
    workflow path, event, completed state, and successful conclusion;
12. gives one no-checkout job `contents: write` only, makes it rebind the remote
    annotated tag object to the exact peeled commit, creates or resumes a
    non-public draft, reconciles and downloads only the three expected assets,
    verifies their SHA-256 values, then publishes the complete draft as a
    prerelease in the final mutation;
13. gives a separate `contents: read` job the exact commit and envelope artifact
    ID, makes it formally verify both publication receipts, independently read
    back the tag, deterministic Release marker, state, asset set, sizes, and
    downloaded hashes, and persist a gated content-addressed readback candidate;
    and
14. permits the PyPI OIDC job to start only after that GitHub Release readback
    job succeeds.

The exact-CI verifier is a dependency of the first GitHub Release writer.
Failed, unknown, truncated, ambiguous, or wrongly correlated API evidence
therefore stops draft creation, asset mutation, publication, and all downstream
PyPI work. Earlier producer artifacts remain preflighted workflow evidence;
they are not a GitHub Release or PyPI publication.

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
  the CLI/onboarding/hook smoke checks. Use a dedicated venv and remove
  Setuptools before the AOI install so executable `.pth` remains fail-closed.
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

## 6. Chief promotion and downstream handoff

Workflow success and public visibility do not promote a release in AOI
semantic state. Download and locally verify these short-retention Actions
artifacts immediately:

- `release-observation-candidate`, containing the canonical
  `observation-result.json`;
- `github-release-readback-candidate`, containing the independently verified
  GitHub Release observation; and
- `pypi-readback-candidate`, containing the post-PyPI candidate whose exact
  `promotion_receipt` binds the observed distribution pair.

Extract the `promotion_receipt` as canonical JSON without changing its bytes or
fields, obtain the active task's current semantic head, and invoke the installed
AOI console launcher with current Chief authority:

```text
aoi release-promote \
  --task <task-id> \
  --observation-result-file <canonical-observation-result.json> \
  --promotion-receipt-file <canonical-promotion-receipt.json> \
  --command-id <unique-command-id> \
  --recorded-at <canonical-UTC-timestamp> \
  --expected-semantic-head-sha256 <current-semantic-head>
```

Capture the command's exact canonical stdout as `promotion-bundle.json`,
validate its `bundle_sha256`, and preserve both locally. `release-promote`
records already observed evidence; it neither uploads files nor publishes a
release, and no workflow receives reusable Chief credentials.

Only that content-addressed public promotion route may authorize downstream
release onboarding:

```text
aoi codex-init \
  --project-name <project-name> \
  --promotion-bundle-file <promotion-bundle.json> \
  --expected-promotion-bundle-sha256 <bundle-sha256> \
  --json
```

Back up downstream AOI state first, install the exact PyPI wheel in a new
side-by-side AOI-only venv, and retain rollback assets. A reviewed local-install
bundle is a separate unpublished proof scope and cannot substitute for this
public promotion bundle.

Nothing in this flow installs or trusts hooks in a user environment. Project
wiring through `aoi codex-init` or `aoi claude-init` is a separate, explicit
action. Codex hook definitions still require exact review and trust through
`/hooks`.
