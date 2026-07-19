# AOI v0.4 quickstart

This guide is for the reviewed alpha `aoi-orgware==0.4.0a1`. Do not substitute
an unpinned package, a different wheel, or a newer build. The package install,
Codex hook trust, provider routing, and reviewer identity are separate claims.

There are two deliberately separate proof routes:

- A public **release-promotion bundle** has tag, release, and PyPI publication
  semantics; use `--promotion-bundle-file` and
  `--expected-promotion-bundle-sha256`.
- A **reviewed_local_install_bundle** has
  `proof_scope=exact_local_wheel_install_only`; it is not published and is not
  a release or promotion. Use `--local-artifact-bundle-file` and
  `--expected-local-artifact-bundle-sha256`.

This checkpoint uses the local route. `codex-init` requires exactly one
complete pair. A half pair, both pairs, or neither pair fails before mutation.

## 1. Install one verified wheel in an isolated environment

Obtain the exact wheel and its SHA-256 from the reviewed local-install bundle.
Keep the bundle, wheel, and isolated tool environment outside the repository
being governed. The example below uses PowerShell; replace placeholders with
reviewed absolute paths and lowercase digests.

```powershell
$aoiToolRoot = Join-Path $env:LOCALAPPDATA 'AOI\venvs\0.4.0a1'
python -m venv $aoiToolRoot
$aoiPython = (Resolve-Path (Join-Path $aoiToolRoot 'Scripts\python.exe')).Path
$aoiWheel = (Resolve-Path 'C:\reviewed-local-install\aoi_orgware-0.4.0a1-py3-none-any.whl').Path
$expectedWheelSha256 = '<reviewed-wheel-sha256>'
$actualWheelSha256 = (Get-FileHash -Algorithm SHA256 $aoiWheel).Hash.ToLowerInvariant()
if ($actualWheelSha256 -ne $expectedWheelSha256) { throw 'wheel SHA-256 mismatch' }

& $aoiPython -m pip install --isolated --no-index --no-deps $aoiWheel
$aoiLauncher = (Resolve-Path (Join-Path $aoiToolRoot 'Scripts\aoi.exe')).Path
& $aoiPython -m pip show aoi-orgware
& $aoiLauncher --version
```

The installed package version must be exactly `0.4.0a1`. The wheel filename is
not sufficient evidence: compare its full SHA-256 before installation. Keep the
tool environment outside the governed repository so it cannot pollute Git
mutation snapshots or claim coverage.

## 2. Initialize Codex with the reviewed local-install proof

Run this from the Git repository to govern. The bundle expected SHA is the
caller's trust anchor: use the canonical digest recorded in the bundle's
`bundle_sha256` field, not the raw JSON file SHA-256, and do not infer it from
installed metadata. Use the exact installed `aoi.exe` launcher: provenance
validates its `sys.argv[0]` identity.

```powershell
& $aoiLauncher codex-init `
  --project-name 'My Project' `
  --local-artifact-bundle-file 'C:\reviewed-local-install\reviewed-local-install-bundle.json' `
  --expected-local-artifact-bundle-sha256 '<approved-local-install-bundle-sha256>' `
  --json
```

On Linux/WSL, create a repo-external venv and install the same exact local
wheel without index or dependencies, then invoke its console script directly:

```bash
AOI_TOOL_ROOT="$HOME/.local/share/aoi/venvs/0.4.0a1"
python3 -m venv "$AOI_TOOL_ROOT"
"$AOI_TOOL_ROOT/bin/python" -m pip install --isolated --no-index --no-deps \
  /absolute/reviewed-local-install/aoi_orgware-0.4.0a1-py3-none-any.whl
"$AOI_TOOL_ROOT/bin/aoi" codex-init \
  --project-name 'My Project' \
  --local-artifact-bundle-file /absolute/reviewed-local-install/reviewed-local-install-bundle.json \
  --expected-local-artifact-bundle-sha256 '<approved-local-install-bundle-sha256>' \
  --json
```

The local receipt/runtime binds the expected bundle SHA, a canonical external
store, clean commit/tree and full tracked-source manifest, artifact inventory
and rehearsal, the exact wheel path/SHA, PEP 610 `direct_url` archive path/SHA,
and installed `RECORD` plus runtime bytes. A manual reviewer remains a
cooperative assertion; the expected bundle SHA is the caller trust anchor. It
does not establish a tag, GitHub Release, PyPI publication, or live Codex
`/hooks` trust. The clean source identity is reviewed context; this local
bundle does not independently attest that the wheel was built from that source,
which builder toolchain ran, or that the caller-supplied test summary executed.

### Public release-promotion route

Use this only when a reviewed public release-promotion bundle exists. Replace
the two local-proof flags above with this complete pair; do not combine routes:

```powershell
& $aoiLauncher codex-init `
  --project-name 'My Project' `
  --promotion-bundle-file 'C:\approved-release\promotion-bundle.json' `
  --expected-promotion-bundle-sha256 '<approved-promotion-bundle-sha256>' `
  --json
```

On Linux/WSL, use the same public pair with the installed
`<venv>/bin/aoi codex-init ...` launcher. Never use `python -m` as a substitute
for either route: the provenance receipt validates the launcher identity.

Then inspect the exact absolute AOI hook definition and provenance digest in
Codex's `/hooks` UI and make the trust decision there. Hook installation is
not runtime trust, and `aoi doctor --json` is only a structural check; neither
proves that Codex executed or trusted a hook. If the MCP registry is unavailable
for a requested integration, record that integration as **uncovered** rather
than assuming the hook or registry path ran.

## 3. Run one mini task

`start-mini` is only for a low-risk change to one through three exact files.
It has six required flags: `--task-id`, `--objective`, `--owner`,
`--session-id`, `--lock`, and `--expires-at`. The following example supplies
all six; the remaining fields make the evidence and finish boundary explicit.

```powershell
$expiresAt = (Get-Date).ToUniversalTime().AddHours(2).ToString('o')
& $aoiLauncher start-mini `
  --task-id docs-v04-quickstart `
  --objective 'Update the approved quickstart text' `
  --owner 'operator@example.invalid' `
  --session-id '<current-codex-session-id>' `
  --lock 'repo:file:docs/quickstart.md' `
  --expires-at $expiresAt `
  --validation 'Review rendered Markdown links and command paths' `
  --json

# Make and validate the claimed change, then close through the mini finish path.
& $aoiLauncher finish-mini `
  --task docs-v04-quickstart `
  --mode local-only `
  --detail 'Reviewed the claimed Markdown file and its local links' `
  --summary 'Quickstart updated and basic link checks completed' `
  --json

& $aoiLauncher status
& $aoiLauncher status --json
```

`aoi status` is the concise operator view; `aoi status --json` remains the
machine contract. A manually entered reviewer identity is a cooperative
assertion, not independent authentication. Do not represent it as proof that a
different person, model, or runtime performed the review.

## 4. Adopt integrity for an eligible material task

`required_v1` is a one-time choice for an eligible task, not a field that every
semantic-v2 task receives at genesis. Make the decision before the final review
and while the task's claims are still live. The material-task sequence is
`integrity-adopt`, `integrity-snapshot`, `integrity-review`, optional
`integrity-fix` plus a post-fix snapshot and `integrity-verify`, then
`integrity-seal`; `integrity-show` is read-only.

The candidate snapshot compares every task-local Git mutation path with the
live claim scope. Seal recaptures the worktree and requires byte identity with
the latest candidate and its exact live claim tokens. Only then may the normal
claim-release/terminal task close sequence proceed. A latest-candidate review
is mandatory; any retry must match the recorded semantic intent exactly rather
than creating a fresh snapshot. Reviewer IDs are cooperative and must differ
from recorded producer IDs; they do not authenticate an independent human or
runtime.

## 5. Offboard without deleting evidence

Offboarding first performs a dry run. Choose an absolute archive directory
outside the repository. Apply only after the preview is correct and AOI state
is quiescent.

```powershell
& $aoiLauncher offboard `
  --archive-dir 'C:\aoi-archives\my-project-offboard' `
  --json

& $aoiLauncher offboard `
  --apply `
  --archive-dir 'C:\aoi-archives\my-project-offboard' `
  --json
```

`offboard --apply` removes only recognizable AOI-owned client wiring, preserves
foreign settings, and leaves `.aoi` as an inert archive by default. It refuses
to apply when it cannot prove the state is quiescent; it does not silently
delete task or evidence history.
