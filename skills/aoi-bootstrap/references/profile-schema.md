# AOI profile schema

AOI v0.1.2 accepts strict TOML schema version 1. Unknown top-level or table keys
fail closed. Generate a complete candidate; do not rely on omitted defaults.

```toml
schema_version = 1
profile_id = "generic-v1"
state_dir = ".aoi"

[project]
name = "Example Project"

[organization]
departments = ["implementation", "verification", "steward"]

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

## Field invariants

- `schema_version` is exactly `1`.
- `profile_id` is a simple 1-128 character identifier using letters, digits,
  `.`, `_`, or `-` after the first alphanumeric character.
- `state_dir` is a non-empty project-relative POSIX path. It must not be
  absolute, contain `..` or backslashes, or live under `.git`. Its exact path or
  an ancestor directory must be covered by `policy.high_risk_paths`.
- `project.name` is a trimmed printable string of 1-128 characters.
- `organization.departments` is a non-empty list of unique names.
- `roles` is a non-empty mapping from role names to model-agnostic capability
  tiers. Tier values are exactly `frontier`, `expert`, `advanced`, `standard`,
  or `economical`; provider and model names are invalid. Preserve the standard
  roles unless the repository has a documented reason to add a role.
- `evidence.close_qualifying` is a subset of `evidence.categories`.
  `engineering_inference` and `historical_terminal_readback` must not qualify
  closure.
- `receipts.required` is a subset of `receipts.components`.
- `policy.external_lock_namespace` matches `[a-z][a-z0-9_-]{1,31}`.
- Every `policy.high_risk_paths` entry is a canonical project-relative POSIX
  path or directory prefix; absolute, drive-qualified, and traversal spellings
  are invalid. A custom `state_dir` must be absent or empty before
  initialization and covered by this list.
- At least one `policy.high_risk_paths` entry covers the configured `state_dir`.
- Both boolean opt-ins must be explicit `true` or `false` values.

Tasks bind both `profile_id` and the SHA-256 of `aoi.toml`. Do not replace a
profile while active tasks depend on the previous digest.

## Capability tiers

Tier names are contracts, not provider or model names:

- `frontier`: architecture, arbitration, high-risk cross-domain reasoning.
- `expert`: domain-specialist implementation, verification, or review.
- `advanced`: bounded implementation with a clear contract.
- `standard`: exploration, coordination support, routine external operation.
- `economical`: deterministic extraction, classification, or formatting.

The runtime may map tiers to concrete models later. Bootstrap must not encode a
provider-specific model name as organizational policy.
