# Configuration

`aoi init` writes a strict `aoi.toml`. Unknown top-level keys and malformed
values fail closed. A candidate can be validated without loading or changing
the installed project configuration:

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
categories = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "doctor", "independent_review", "documentation_check", "historical_terminal_readback", "resource_governance", "delivery_check", "engineering_inference"]
close_qualifying = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "doctor", "independent_review", "documentation_check", "resource_governance", "delivery_check"]

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
- `hooks.codex.enabled`: opt-in declaration; it does not install hooks.
- `legacy.enabled`: enables compatibility-ledger import and reporting.

The full default file is available at `examples/aoi.toml`.

## Change discipline

Tasks bind both `profile_id` and the file's SHA-256. Change configuration only
when no active task depends on the previous digest. v0.1 intentionally has no
automatic migration command.

Initialization is idempotent and non-clobbering, but it is not a distributed
multi-file transaction. If the process is interrupted while creating templates
or the index, rerun the same `aoi init --config ...` command; do not substitute a
different candidate.
