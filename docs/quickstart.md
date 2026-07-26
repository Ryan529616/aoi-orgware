# ARISE Operational Alpha quickstart

This guide targets the unpublished Operational Alpha candidate
`aoi-orgware==0.4.0a4`, not a complete v0.5 release. Current schema-v3 hooks
may be created only from one reviewed local-v2 exact-wheel proof:
`reviewed_local_install_bundle` with
`proof_scope=exact_local_wheel_install_only`. It is neither published nor a
release/promotion. Public schema-v1 receipts remain readable and can take their
historical upgrade path, but cannot newly enable current hooks; the public
current-hook route is deferred. Do not substitute an unpinned package, a
different wheel, source presence, a tag, workflow success, or PyPI visibility.
The package install, Codex hook trust, provider routing, and reviewer identity
are separate claims.

## 1. Install one verified wheel in an isolated environment

Obtain the exact wheel and its SHA-256 from the reviewed local-install bundle.
Keep the bundle, wheel, and isolated tool environment outside the repository
being governed. The example below uses PowerShell; replace placeholders with
reviewed absolute paths and lowercase digests.

```powershell
$aoiToolRoot = Join-Path $env:LOCALAPPDATA 'AOI\venvs\0.4.0a4'
python -m venv $aoiToolRoot
$aoiPython = (Resolve-Path (Join-Path $aoiToolRoot 'Scripts\python.exe')).Path
# Python 3.11 may seed executable distutils-precedence.pth. AOI has no
# Setuptools runtime dependency and provenance intentionally rejects that file.
& $aoiPython -m pip uninstall --yes setuptools
$aoiWheel = (Resolve-Path 'C:\reviewed-local-install\aoi_orgware-0.4.0a4-py3-none-any.whl').Path
$expectedWheelSha256 = '<reviewed-wheel-sha256>'
$actualWheelSha256 = (Get-FileHash -Algorithm SHA256 $aoiWheel).Hash.ToLowerInvariant()
if ($actualWheelSha256 -ne $expectedWheelSha256) { throw 'wheel SHA-256 mismatch' }

& $aoiPython -m pip install --isolated --no-index --no-deps $aoiWheel
$aoiLauncher = (Resolve-Path (Join-Path $aoiToolRoot 'Scripts\aoi.exe')).Path
& $aoiPython -m pip show aoi-orgware
& $aoiLauncher --version
```

The installed package version must be exactly `0.4.0a4`. The wheel filename is
not sufficient evidence: compare its full SHA-256 before installation. Keep the
tool environment outside the governed repository so it cannot pollute Git
mutation snapshots or claim coverage. The environment must be dedicated to AOI:
do not create it with `--system-site-packages` or add unrelated development
tools. AOI rejects every executable `.pth`; reinstalling Setuptools or another
such file makes onboarding and runtime hooks fail closed until the environment
is cleaned and requalified.

## 2. Initialize Codex with the reviewed local-install proof

Run this from the Git repository to govern. The bundle expected SHA is the
caller's trust anchor: use the canonical digest recorded in the bundle's
`bundle_sha256` field, not the raw JSON file SHA-256, and do not infer it from
installed metadata. Use the exact installed `aoi.exe` launcher: provenance
validates its `sys.argv[0]` identity. Local-v2 launcher/bridge records are
historical or diagnostic evidence only; they do not establish schema-v3
active-hook authority. The Bridge has its own launch/receipt boundary.

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
AOI_TOOL_ROOT="$HOME/.local/share/aoi/venvs/0.4.0a4"
python3 -m venv "$AOI_TOOL_ROOT"
"$AOI_TOOL_ROOT/bin/python" -m pip uninstall --yes setuptools
"$AOI_TOOL_ROOT/bin/python" -m pip install --isolated --no-index --no-deps \
  /absolute/reviewed-local-install/aoi_orgware-0.4.0a4-py3-none-any.whl
"$AOI_TOOL_ROOT/bin/aoi" codex-init \
  --project-name 'My Project' \
  --local-artifact-bundle-file /absolute/reviewed-local-install/reviewed-local-install-bundle.json \
  --expected-local-artifact-bundle-sha256 '<approved-local-install-bundle-sha256>' \
  --json
```

When run from a canonical WSL session, `codex-init` does not render a legacy
Linux launcher into `commandWindows`. It requires consistent Microsoft-kernel,
`WSL_DISTRO_NAME`, absolute `WSL_INTEROP`, recorded absolute Python/runtime/root,
and passwd-user signals, then writes an exact pair:

- `command` directly invokes the recorded absolute Linux venv Python as
  `-I -B -m aoi_orgware.codex_hook` with the project root and provenance digest;
- `commandWindows` uses only
  `wsl.exe --distribution <distro> --user <user> --cd <root> --exec <python>
  -I -B -m aoi_orgware.codex_hook`
  followed by those same exact hook arguments.

AOI does not accept a shell prefix or arbitrary Windows command override.
Partial WSL signals, a native-Windows `\\wsl$`/`\\wsl.localhost` onboarding
root, a relative inner hook, mismatched `--cd`/`--project-root`, or altered
distro/user/root/digest fails closed. Run onboarding inside the target WSL
distribution; do not hand-edit `.codex/hooks.json`. A proof-changing reinstall
can rotate an existing current handler only if both of its commands exactly
match the pair reconstructed from the persisted validated provenance receipt;
partial old/new pairs, cross-bound identities, malformed AOI references, and
unbound current-shaped drift are rejected. The hook pair is written before the
replacement receipt so an interrupted receipt write is fail-closed and
resumable by rerunning the same command.

The malformed-reference check is deliberately bounded: it examines direct
tokens and one known-shell operand, and fails closed for recognizable AOI hook
signatures after tokenizer quote failure or CMD caret removal. It is not a
general shell parser or DLP boundary; do not treat arbitrary same-user shell
execution as governed by this detector.

The local receipt/runtime binds the expected bundle SHA, a canonical external
store, clean commit/tree and full tracked-source manifest, artifact inventory
and rehearsal, the exact wheel path/SHA, PEP 610 `direct_url` archive path/SHA,
and installed `RECORD` plus runtime bytes. A manual reviewer remains a
cooperative assertion. The tracked-source manifest includes safe dotfiles such
as `.gitignore` and paths under `.github/`; traversal and noncanonical paths
remain invalid. The
expected bundle SHA is the caller trust anchor. It
does not establish a tag, GitHub Release, PyPI publication, or live Codex
`/hooks` trust. The clean source identity is reviewed context; this local
bundle does not independently attest that the wheel was built from that source,
which builder toolchain ran, or that the caller-supplied test summary executed.

The public current-hook route is intentionally unavailable in this candidate.
Do not use a public schema-v1 receipt, promotion bundle, console/bridge launcher
record, or historical `aoi-codex-hook` entry point as a substitute for the
reviewed local-v2 proof and schema-v3 Python-module binding above.

Then inspect the exact absolute AOI hook definition and provenance digest in
Codex's `/hooks` UI and make the trust decision there. Hook installation is
not runtime trust, and `aoi doctor --json` is only a structural check; neither
proves that Codex executed or trusted a hook. If the MCP registry is unavailable
for a requested integration, record that integration as **uncovered** rather
than assuming the hook or registry path ran.

`codex-init` also installs the AOI-distribution Codex client adapter at
`$HOME/.agents/skills/aoi/SKILL.md`. It is not a governance rule source or a
mutation authority: the installed CLI/runtime/ledger and the repository's
`aoi.toml`, managed `POLICY.md`, and instructions remain authoritative. The
schema-v3 receipt binds the adapter to the installed package version and
`RECORD`; doctor reports `not_configured`, `exact`, `missing`, `drifted`,
`uninspectable`, or `legacy_unbound`. Do not copy or edit the skill to repair
those states. Instead, inspect the actual user-scope file digest and,
under the same reviewed distribution/proof, rerun provenance-qualified
`aoi codex-init`; a differing file requires its reviewed
`--replace-user-skill-sha256` acknowledgement. Reinstalling a wheel alone does
not repair a user-scope file. This guide makes no equivalent Claude or
all-provider binding claim.

With hooks disabled, missing, drifted, or user-path-uninspectable adapter state
is warning/status only and does not block `doctor`. Corrupt receipt/schema,
package/`RECORD`, or exact-wheel provenance remains blocking even then. Once
AOI `main` enters, the hook rechecks its Python invocation/resolved hash/prefix/
cache tag, exact module and argv prefix; it is cooperative post-import drift
detection, not protection from interpreter, site/import, same-user, or
pre-import tampering.

For a WSL-governed project used by Windows Codex, also exercise the installed
`commandWindows` from Windows against a disposable project and confirm a new
adapter receipt appears in that same WSL `.aoi` state tree. This is separate
from `/hooks` trust and from the App Server Transport Bridge canary.

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

### Optional: repair exact rolled-back pre-applicability history

If `doctor` reports a legacy resource receipt binding error after an unchanged
pre-applicability event has been rolled back, use
`codex-config-migrate-legacy-plan` to obtain its exact event/receipt digests,
then run Chief-fenced `codex-config-migrate-legacy` with those expected values.
The migration preserves the original bytes and records no inferred
applicability. Applied/current or partially upgraded history is ineligible.
See [Resource control](resource_control.md#migrate-rolled-back-pre-applicability-history)
for the complete command, receipt, recovery, and idempotency contract.

## 4. Adopt or upgrade integrity for an eligible material task

New eligible tasks use `integrity-adopt` to create `required_v2` directly from
an exact baseline head:

```powershell
& $aoiLauncher integrity-adopt `
  --task <task-id> `
  --baseline-head <exact-baseline-head> `
  --json
```

`required_v1` is frozen, read-only compatibility for existing contracts: its
validator, candidate-only seal, and sealed contracts remain unchanged. Do not
attempt to migrate or reinterpret a sealed v1 task. Any unsealed, valid v1
contract—including one with an empty record set—moves to `required_v2` through
the explicit command with the expected canonical v1 digest:

```powershell
& $aoiLauncher integrity-upgrade-v2 `
  --task <task-id> `
  --expected-v1-contract-sha256 <canonical-v1-contract-sha256> `
  --json
```

The upgrade receipt retains the canonical v1 CAS artifact and every existing
finding obligation; it does not silently reinterpret v1 evidence. New v2 work
uses record SHA as the attempt handle. Snapshot content SHA may repeat when the
Git bytes repeat, but the returned snapshot record SHA and `integrity_seq` are
unique.

Each `--result-artifact`, `--fix-artifact`, and `--verification-artifact` value
uses the exact grammar `<absolute-path>=<sha256>`; the path must exist and the
digest must be its declared SHA-256.

```powershell
# Capture one exact candidate attempt and record its finding review.
& $aoiLauncher integrity-snapshot --task <task-id> --purpose candidate --json
& $aoiLauncher integrity-review `
  --task <task-id> `
  --snapshot-record-sha256 <candidate-snapshot-record-sha256> `
  --reviewer-agent-id <independent-reviewer-agent-id> `
  --result-artifact <absolute-path>=<sha256> `
  --outcome findings `
  --finding-id <finding-id> `
  --json

# For each finding, capture a post-fix attempt, bind the fix, and reverify it.
& $aoiLauncher integrity-snapshot --task <task-id> --purpose post_fix --json
& $aoiLauncher integrity-fix `
  --task <task-id> `
  --finding-id <finding-id> `
  --post-fix-snapshot-record-sha256 <post-fix-snapshot-record-sha256> `
  --fix-artifact <absolute-path>=<sha256> `
  --json
& $aoiLauncher integrity-verify `
  --task <task-id> `
  --finding-id <finding-id> `
  --fix-record-sha256 <fix-record-sha256> `
  --verification-snapshot-record-sha256 <terminal-snapshot-record-sha256> `
  --reviewer-agent-id <independent-reviewer-agent-id> `
  --verification-artifact <absolute-path>=<sha256> `
  --outcome pass `
  --json

# The exact terminal attempt then receives its final clean review.
& $aoiLauncher integrity-review `
  --task <task-id> `
  --snapshot-record-sha256 <terminal-snapshot-record-sha256> `
  --reviewer-agent-id <independent-reviewer-agent-id> `
  --result-artifact <absolute-path>=<sha256> `
  --outcome clean `
  --json

& $aoiLauncher integrity-seal `
  --task <task-id> `
  --json
```

Review may iterate and record more findings. Before `integrity-seal`, the exact
terminal attempt must receive the final clean review. Its review basis must list
the current `PASS` verification for every prior finding's latest fix on that
same attempt. Seal then recaptures the worktree and requires byte and live-claim
scope identity with that exact terminal record. Retries preserve the recorded
semantic intent rather than creating a fresh attempt. Reviewer IDs are
cooperative and must differ from recorded producer IDs; they do not authenticate
an independent human or runtime.

## 5. Protect selected files from the wrong publication destination

Use this profile when Codex may see project context but user-selected files or
trees must either remain local or go only to their home repository:

```toml
[confidentiality]
mode = "local_files"
model_context = "allowed"
git_push = "deny"
remote_ci = "deny"
artifact_upload = "deny"
external_export = "permit_required"
local_cas = true
protected = [
  { path = "private/design.bin", kind = "file", policy = "home_remote_only", home_remote = "origin", home_destination = "https://github.com/example/chip.git" },
  { path = "eda/private", kind = "tree", policy = "local_only" },
]
```

Omit `protected`, or set it to `[]`, to classify nothing. That preserves normal
repository updates, remote CI, GitHub Release, and package publication; the
profile name alone is not a whole-repository ban. Local
branch/status/diff/commit and local evidence are always allowed.

If the repository uses clean remote release jobs, generate and review its
tracked policy projection locally:

```powershell
aoi confidentiality-policy-snapshot > publication-policy.new.json
# Compare exact bytes, then replace release/publication-policy.json only after review.
```

The generator verifies current protected origins. Remote jobs receive the
canonical snapshot and a separately pinned expected digest, not raw `aoi.toml`
or the local-only origins.

Before an AOI-managed push from a project with protected rules, create an exact
UTF-8 preflight receipt for every ref update:

```powershell
aoi confidentiality-git-push-preflight `
  --task <task-id> `
  --remote origin `
  --destination https://github.com/example/chip.git `
  --update refs/heads/main <local-commit> refs/heads/main <remote-commit-or-40-zeroes> `
  --json > protected-push-preflight.json

git push origin <local-commit>:refs/heads/main

aoi set-delivery --task <task-id> --mode pushed `
  --detail "exact protected-content preflight" `
  --commit <local-commit> --remote origin --remote-ref refs/heads/main `
  --confidentiality-preflight-file protected-push-preflight.json --json
```

Use `--task` whenever the delivery comes from a recorded isolated worktree. It
selects that task's validated worktree for Git inspection while retaining the
authoritative AOI root's config and policy digest. It may be omitted only when
the authoritative AOI root itself is the pushed worktree.

The preflight read-checks every remote ref's exact old OID and scans the exact
outgoing commits, including protected files later deleted or copied under
another path. Current protected bytes also enter the Git-blob identity set even
when their configured path has never been tracked, so an exact copy committed
elsewhere remains classified. It binds the config, destination, Git blob
identities, and content SHA-256 values. `set-delivery` revalidates the receipt
and preserves its canonical bytes in task-local CAS; deleting the operator's
temporary JSON does not erase the governed evidence. It permits a `home_remote_only`
subject only at its exact home remote/destination and denies a `local_only`
subject externally. Rewrites and ambiguous LFS routing fail closed. Other
publication actions inventory the exact input files and archive members whenever
protected rules exist:

```powershell
aoi confidentiality-publication-preflight `
  --action package_publish `
  --destination https://pypi.org/project/example `
  --subject <exact-wheel-path> `
  --subject <exact-sdist-path> `
  --json > package-publication-preflight.json
```

This local live-config command does not authorize a Git push. In clean CI use
`python -m aoi_orgware.publication_gate` with the tracked snapshot and its
reviewed `--expected-snapshot-sha256`. A caller-supplied `--remote` cannot make
an artifact/package upload eligible for `home_remote_only`.

The receipt binds every outer container SHA-256 and a bounded manifest of
regular wheel/ZIP/gzip-tar members. Exact copied bytes or protected member paths
are denied at other destinations; unrelated package bytes remain publishable.
A missing configured protected file/tree fails closed because AOI cannot recover
an untracked origin after deletion. Restore it or explicitly revise the reviewed
rule before retrying. An approved local-only exception uses the one-shot export-permit
commands. Its receipt proves authorization/consumption, not an observed upload.

Run `aoi doctor --json` before governed work. External remotes, workflow files,
credential helpers, and known publish-credential names are reported as
inventory/warnings unless AOI proves a protected-content contradiction.
Credential matching is finite and cannot prove that no unlisted secret exists.
A Windows mapped drive is denied as network storage. Missing drive metadata,
SUBST aliases, and link/reparse traversal are labelled unverified and, when
protected rules exist, also block a confirmed-local state/launch gate. An empty
protected list does not activate that gate. Do not treat this mode as an air gap:
model context is allowed. An ungoverned same-user Git or upload command remains
outside this cooperative AOI boundary.


## 6. Optional one-turn Codex bridge

Most users should let an AOI-aware agent prepare the sealed intent, decision,
permit, and prompt. The transport is intentionally separate from ordinary
`aoi` lifecycle commands:

```powershell
aoi-codex-bridge --root <project> issue `
  --task <task-id> --launch-id <launch-id> `
  --intent-file <sealed-intent.json> `
  --decision-file <sealed-decision.json> `
  --permit-file <sealed-permit.json> `
  --pre-git-endpoint-file <exact-pre-git-endpoint.json> `
  --command-id <stable-command-id> `
  --recorded-at <timezone-aware-time> `
  --chief-session-id <chief-session> --chief-epoch <epoch> `
  --chief-credential-file <absolute-external-credential-file> --json

aoi-codex-bridge --root <project> run `
  --task <task-id> --permit-sha256 <permit-sha256> `
  --prompt-file <exact-utf8-prompt-file> --json
```

`run` deliberately has no Chief credential option. Every `readOnly` and
`workspaceWrite` issuance requires `--pre-git-endpoint-file`; AOI re-captures
that exact Git/tree/status/claim endpoint under the issue lock, again before
reservation, and again at process-pending. The endpoint separately binds the
complete canonical live task-claim authority, even when Git status has no
mutation paths. A historical marker with no endpoint CAS, or a legacy endpoint
without that complete authority, is readable for inspection but cannot start.
Only `workspaceWrite` may later use
`verify-mutation` to record the post-image and elevate the evidence. A completed
turn is not task completion. If `inspect` reports `launch_unknown`, do not rerun
the launch; reconcile the task evidence instead.

The bridge consumes the packet arm atomically and does not fabricate a
`SubagentStart` identity. It uses one per-launch OS lock, checks the earlier
permit/arm expiry and exact packet ownership at `process_start_pending`. That
milestone precedes and authorizes both the exact-binary version probe and the
App Server Popen; the bridge never restarts after it becomes durable. When
`local_files` has protected rules, known sync/network AOI state roots and writable cwd paths are
rejected before Popen, as are mapped Windows drives and paths whose Windows
volume/reparse locality cannot be confirmed. `reservation_effective_at` is a Chief-planned semantic
time, not measured wall-clock consumption.

## 7. Offboard without deleting evidence

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
