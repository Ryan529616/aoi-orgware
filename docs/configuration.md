# Configuration

`aoi init` writes a strict `aoi.toml`. Unknown top-level keys and malformed
values fail closed. A candidate can be validated without loading or changing
the installed project configuration:

Phase 1 context-provider receipts are task-local records, not project
configuration. Do not add an unversioned `[integrations.codebase_memory]` table:
the schema rejects it. This keeps codebase-memory optional and fail-open while
receipt/doctor/benchmark behavior is evaluated. A future mandatory integration
would require an explicit configuration-schema migration.

```bash
# Run from the target Git repository root.
aoi config-check --file /path/to/candidate-aoi.toml --json
aoi init --config /path/to/candidate-aoi.toml \
  --expected-config-sha256 <approved-config-sha256> --json
```

`config-check` is read-only. `init --config` requires
`--expected-config-sha256`, preserves the candidate's exact bytes, refuses to
overwrite a different `aoi.toml`, and checks an existing state tree's
Windows/WSL lock domain, managed-path identity, and the project `.gitignore`
before writing the config. A review workflow must bind approval to
`config_sha256` and revalidate that digest immediately before init; apply fails
if the candidate changes after approval.

The normal first init of a pristine state location is the sole unauthenticated
lifecycle write. Any later `aoi init` is Chief-fenced. Interrupted bootstrap
objects follow the fail-closed rules below; AOI does not repair them before
authentication. Authenticated init may replace an exact known managed
predecessor policy automatically. An unrecognized or locally customized policy
requires `--replace-policy-sha256` with its reviewed current digest.

```toml
schema_version = 1
profile_id = "generic-v1"
state_dir = ".aoi"

[project]
name = "Example Project"

[organization]
departments = ["implementation", "verification", "operations", "steward"]

[roles]
architect = "frontier"
analysis_specialist = "frontier"
implementation_specialist = "expert"
reviewer = "expert"
external_systems_expert = "expert"
worker = "advanced"
explorer = "standard"
external_operator = "standard"
default = "standard"
batch = "economical"

[evidence]
categories = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "hook_smoke", "skill_validation", "doctor", "independent_review", "documentation_check", "historical_terminal_readback", "citation_hygiene_review", "resource_governance", "delivery_check", "engineering_inference"]
close_qualifying = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "hook_smoke", "skill_validation", "doctor", "independent_review", "documentation_check", "citation_hygiene_review", "resource_governance", "delivery_check"]

[receipts]
components = ["source", "runner", "config", "dependencies", "other"]
required = ["source", "runner"]

[policy]
high_risk_paths = [".aoi/", "infra/", "security/", "deploy/"]
external_lock_namespace = "external"

[hooks.codex]
enabled = false

[legacy]
enabled = false
```

## Semantics

- `profile_id`: human-readable governance profile version.
- `state_dir`: canonical project-relative POSIX path for private state. AOI also
  rejects Windows drive/UNC semantics, `.git` at any depth, non-canonical path
  spellings, Win32 reserved names, and any resolved path outside the repo.
- `departments`: valid organizational vocabulary for project reporting.
- `roles`: packet role to one of the model-agnostic tiers `frontier`, `expert`,
  `advanced`, `standard`, or `economical`. Provider/model names are invalid.
- `evidence.categories`: accepted evidence labels.
- `evidence.close_qualifying`: subset allowed to support achieved closure;
  inference and historical terminal readback cannot qualify.
- `receipts`: exact source-receipt component contract for external jobs.
- `high_risk_paths`: canonical project-relative paths rejected by the mini-task
  convenience flow. The configured `state_dir` must be covered by one entry.
  At least one entry must cover the configured `state_dir`.
- `external_lock_namespace`: prefix for external file/tree locks.
- `hooks.codex.enabled`: opt-in declaration. Plain `aoi init` does not install
  or trust hooks. Explicit `aoi codex-init` enables the declaration, merges
  protocol-v6 project hooks, enables Codex's stable hook feature, and installs
  the generic AOI skill at Codex user scope (`$HOME/.agents/skills`); the user
  must still review the exact commands through Codex `/hooks`. Project-specific
  instructions remain in the repository. Without hook trust, arm the exact
  packet first and
  then use explicit manual-unverified packet dispatch before that short-lived
  arm expires. AOI revalidates the same authority snapshot at consumption.
  Installer command ownership requires a direct current AOI entry point or the
  documented structured WSL launcher; substring matches are never sufficient.
- `aoi claude-init`: merges Claude lifecycle hooks into the repository's
  `.claude/settings.json`, but installs the generic AOI skill only at Claude
  user scope (`$HOME/.claude/skills`). It never creates the generic skill under
  the project. A differing user skill is replaced only after its exact reviewed
  SHA-256 is supplied. The pre-spawn gate validates the full live arm authority,
  not only the parent-session and agent-type slot.
- `legacy.enabled`: enables compatibility-ledger import and reporting.

The full default file is available at `examples/aoi.toml`.

## Confidentiality profile

The default is `mode = "standard"`. IC/EDA projects that allow model context
but prohibit project-file publication use the exact strict profile:

```toml
[confidentiality]
mode = "local_files"
model_context = "allowed"
git_push = "deny"
remote_ci = "deny"
artifact_upload = "deny"
external_export = "permit_required"
local_cas = true
```

For `local_files`, all seven values are one closed contract; permissive or
unknown combinations are rejected. Local Git operations remain allowed.
AOI-managed push/LFS upload, remote CI, release/package publication, artifact
upload, and connector/attachment publication are denied. External export is
available only through an exact Chief one-shot permit, and AOI records
authorization/consumption without claiming that it uploaded the bytes.

`doctor` classifies external remotes and rewrites, LFS endpoints, workflow
files, synchronized/network artifact roots, known publish credential
names/helpers, and push/export receipts. Credential matching is a finite
known-name detector and cannot prove that an unlisted secret is absent.
Confirmed contradictions fail. On Windows, drive letters are checked with
`GetDriveTypeW` and DOS-device alias inspection. Mapped drives fail as network
storage; missing roots, metadata failures, SUBST aliases, and link/reparse
traversal are labelled unverified and fail the confirmed-local gate. `file:` URI
paths are strictly percent-decoded before classification, and generic Windows
reparse attributes are checked beyond symlink/junction helpers. Both lexical
and resolved drives are classified, and malformed URLs are reported as redacted
invalid destinations instead of aborting doctor. The
optional Codex bridge
rechecks the artifact/CAS root at issue, pre-reserve, and process-pending, and
also checks a `workspaceWrite` cwd. Its child sandbox requests
`networkAccess=false`; the model-service control channel is not represented
as arbitrary workload network permission.

This profile does not claim that a model provider cannot receive prompt or
context. Use a future offline/self-hosted profile for that different threat
model. Promotion under `local_files` selects complete local Windows/WSL,
applicable authorized EDA, independent review, integrity seal, install smoke,
and encrypted local bundle evidence; remote-main CI/publication is forbidden,
not missing.

## Codex v0.4 adapter boundary

`codex-init` records the exact resolved AOI hook launcher and installed-package
provenance before it wires repository-local hooks. It accepts exactly one
complete source-proof pair: the public release-promotion pair
(`--promotion-bundle-file` / `--expected-promotion-bundle-sha256`) or the
separate local pair (`--local-artifact-bundle-file` /
`--expected-local-artifact-bundle-sha256`). Half a pair, both pairs, or neither
fails before mutation.

A public promotion receipt keeps its tag/release/PyPI semantics. A local
`reviewed_local_install_bundle` instead has
`proof_scope=exact_local_wheel_install_only`: it is not a promotion or release.
Its v2 receipt/runtime binds caller-supplied bundle SHA, canonical external
store, clean commit/tree and complete tracked-source manifest, inventory and
rehearsal, exact wheel path/SHA, PEP 610 `direct_url` archive path/SHA, and
installed `RECORD` plus runtime bytes. The exact installed console launcher is
part of that check; do not invoke `codex-init` through a module entry point.
Manual reviewer identity remains cooperative, while the expected bundle SHA is
the caller trust anchor. That value is the canonical digest recorded in the
bundle's `bundle_sha256` field, not the raw JSON file SHA-256. The clean source
identity is reviewed context: the local bundle does not independently attest
source-to-wheel derivation, builder-toolchain execution, or execution of its
caller-supplied test summary.

Both routes bind package version, installed metadata, generated console/hook
scripts, and a bounded non-cache runtime-package manifest checked against
wheel `RECORD`. Pip-generated, hashless `__pycache__/*.pyc` files are excluded;
other files under `__pycache__` are rejected. At hook execution, AOI's
provenance validator revalidates the persisted receipt, invoked launcher, and
covered installed package bytes, and `doctor` reports drift. Any internal
`PreToolUse` failure produces the fixed deny response (fail-closed); only
non-`PreToolUse` lifecycle adapters are fail-open. This cooperative hook is not
a pre-import or OS security boundary.
`RECORD` verifies covered installed payloads; it proves the original wheel
archive only when the stronger matching archive-digest evidence is available.

The adapter correlates a PreToolUse and PostToolUse pair by exactly
`(session_id, turn_id, tool_use_id)`. `agent_id` and `event_id` may be retained
as observations but are not a substitute correlation key. The PreToolUse record
contains the parser, input digest, canonical target list, session mapping,
claim-snapshot digest, coverage (`covered`, `unclaimed`, or `uncovered`), and
allow/deny decision. Provider, runtime profile, and sandbox remain
`unavailable`. The PostToolUse record names the pre-receipt, input/response
digests, targets, and completion observation. It may claim a mutation effect
only from a distinct paired before/after SHA-256 observation; it never prevents
or rolls back a mutation.

Hook receipts are stored as bounded, canonical, create-only state records. A
divergent replay for one event identity, corrupted/linked record, or exhausted
64 KiB-per-record / 1,024-record / 16 MiB aggregate budget is an error: AOI
does not evict old evidence or silently continue with partial accounting. Only
supported parseable paths can be cooperatively gated. An unavailable MCP
registry, unsupported tool, or ambiguous target is `uncovered`, never treated
as a covered integration.

The v0.4 integrity surface makes new `integrity-adopt` contracts `required_v2`.
`required_v1` remains frozen and read-only for compatibility. Any unsealed valid
v1 contract, including a valid empty record set, may make the explicit
`integrity-upgrade-v2` transition with its expected canonical v1-contract
digest; sealed v1 contracts remain v1.
`required_v2` uses one ordered `integrity_seq` ledger: content SHA
may repeat for identical snapshots, while record SHA identifies each distinct
attempt and every graph edge. The migration receipt retains the canonical v1
CAS source and all pre-existing finding obligations, which remain validated by
the v1 reader; it is not a silent reinterpretation.

For v2 seal, every prior finding's latest fix must have an independent `PASS`
verification on the exact terminal snapshot attempt, and the final clean review
must name that exact verification basis. Reviewer identities must not equal
producer identities, but this is a cooperative identity rule, not authentication
or a same-user security boundary. Offboarding likewise changes only AOI-owned
client wiring after preimage-drift checks and an archive/receipt; it preserves
the AOI state as an inert archive unless the user takes a separate explicit
action.

## Interrupted publication and initialization

Root configuration and the state lock have separate fail-closed boundaries:

- For `chief-acquire` and recovery, root `aoi.toml` must already be one normal
  non-linked configuration file. A post-link alias blocks normal loading and
  remains unchanged for explicit offline/manual audit and recovery. A pre-link
  temporary is not repaired and is outside `.aoi/` scanning, but does not block
  the identical `init`; it remains manual root residue for audit and cleanup.
- Automatic `chief-acquire` accepts only an existing canonical `.state.lock`
  that is one private regular non-linked file containing exactly one NUL byte.
  After taking that platform lock, AOI reloads the same configuration binding
  and accepts only a complete layout or the exact existing-NUL interrupted-init
  prefix before publishing first-Chief authority.
- A missing or empty state lock, any state-lock alias, or any other linked or
  ambiguous bootstrap object is rejected with zero automatic bootstrap mutation
  on POSIX and Windows. AOI currently has no ownership ledger: it does not create
  a lock, upgrade empty to NUL, unlink an alias, or attempt automatic bootstrap
  rollback.
- Bounded exact pre-link state-lock temporaries may remain inert in an otherwise
  exact existing-NUL interrupted prefix. They are not consumed before Chief
  authentication. After valid first-Chief acquisition, the current Chief can
  run `recover-temporaries`.

`recover-temporaries` requires the normal canonical NUL state lock. Every
configured state-tree temporary deletion requires an under-lock config reload
and current-Chief validation. A malformed, legacy, or ambiguous entry blocks
all ordinary deletion. Repo-external credential temporaries,
published-but-orphaned credentials, obsolete takeover credentials, and custom
credential roots are also outside this command. Stale credential tuples cannot
authorize current authority, but their secret-at-rest cleanup is a separate
follow-up.

## Change discipline

Tasks bind both `profile_id` and the file's SHA-256. Change configuration only
when no active task depends on the previous digest. Chief authority does not
bind one config digest, so a reviewed same-`state_dir` change does not strand
lease recovery; each fenced command reloads the config while holding the state
lock. Changing `state_dir` is a separate state migration and must not be
simulated by swapping `aoi.toml` under a live lease.

On an existing project, `aoi codex-init` is Chief-fenced and changes only the
false-to-true Codex hook flag. It refuses the change while any active or blocked
task binds the current digest. It does not rewrite model, reasoning, approval,
sandbox, provider, notification, MCP, plugin, or global Codex settings.
The separate user-scope skill write is preflighted before project mutation and
refuses a differing existing skill without its reviewed SHA-256. After a
successful fresh init or strict existing-NUL Chief acquisition, onboarding
reacquires the project state lock, rechecks that no competing Chief or task
appeared, and retains the lock across the remaining policy and client-file
writes.
Both client onboarding commands preflight existing client files, atomically
replace only changed destinations, and are idempotently resumable by rerunning
the same command if a later destination fails. When an interrupted first run
already published `aoi.toml`, acquire/export the project Chief credential before
rerunning only if the strict canonical-NUL bootstrap boundary above is met;
otherwise perform offline/manual recovery first. They are intentionally not one
distributed filesystem transaction.

Initialization is resumable and non-clobbering, but it is not a distributed
multi-file transaction. `chief-acquire` can resume only a complete layout or
exact interrupted prefix that already has the private non-linked canonical NUL
state lock. Missing, empty, or aliased locks and all root-config aliases remain
unchanged and require offline/manual recovery. After a valid first-Chief
acquisition, use that credential to rerun the same digest-bound
`aoi init --config ...` command. If the interruption happened later while
creating templates or the index, acquire or use the project Chief credential
and rerun the same command. Never substitute a different candidate.
