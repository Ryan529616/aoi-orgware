# Configuration

`aoi init` writes a strict `aoi.toml`. Unknown top-level keys and malformed
values fail closed.

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
categories = ["unit_test", "integration_test", "documentation_check", "engineering_inference"]
close_qualifying = ["unit_test", "integration_test", "documentation_check"]

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
- `state_dir`: safe project-relative POSIX path for private state.
- `departments`: valid organizational vocabulary for project reporting.
- `roles`: packet role to model-agnostic capability-tier mapping.
- `evidence.categories`: accepted evidence labels.
- `evidence.close_qualifying`: subset allowed to support achieved closure.
- `receipts`: exact source-receipt component contract for external jobs.
- `high_risk_paths`: paths rejected by the mini-task convenience flow.
- `external_lock_namespace`: prefix for external file/tree locks.
- `hooks.codex.enabled`: opt-in declaration; it does not install hooks.
- `legacy.enabled`: enables compatibility-ledger import and reporting.

The full default file is available at `examples/aoi.toml`.

## Change discipline

Tasks bind both `profile_id` and the file's SHA-256. Change configuration only
when no active task depends on the previous digest. v0.1 intentionally has no
automatic migration command.
