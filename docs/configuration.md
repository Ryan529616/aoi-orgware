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

The first init of a pristine state location is the sole unauthenticated
lifecycle write. Any later `aoi init` is Chief-fenced. Authenticated init may
replace the exact known v0.1.3 managed policy automatically; an unrecognized or
locally customized policy requires `--replace-policy-sha256` with its reviewed
current digest.

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
- `aoi claude-init`: merges Claude lifecycle hooks into the repository's
  `.claude/settings.json`, but installs the generic AOI skill only at Claude
  user scope (`$HOME/.claude/skills`). It never creates the generic skill under
  the project. A differing user skill is replaced only after its exact reviewed
  SHA-256 is supplied.
- `legacy.enabled`: enables compatibility-ledger import and reporting.

The full default file is available at `examples/aoi.toml`.

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
refuses a differing existing skill without its reviewed SHA-256.

Initialization is resumable and non-clobbering, but it is not a distributed
multi-file transaction. If the first process stops after publishing `aoi.toml`
but before initializing the state lock, `chief-acquire` accepts only the exact
structural prefix (no authority, lifecycle payload, managed resource, or unknown
entry), repairs the platform/lock, and acquires the first Chief. Use that
credential to rerun the same digest-bound `aoi init --config ...` command. If
the interruption happened later while creating templates or the index, acquire
or use the project Chief credential and rerun the same command. Never substitute
a different candidate.
