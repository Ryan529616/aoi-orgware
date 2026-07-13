---
name: aoi-bootstrap
description: Inspect an existing Git repository and turn the user's project requirements into a conservative, reviewable AOI organization profile. Use when the user asks to initialize AOI, create or review aoi.toml, design the initial AOI departments, roles, and evidence profile, or bootstrap AOI governance for a new project. Do not use for ordinary task or lane execution or to install hooks without an explicit request.
---

# AOI Bootstrap

Bootstrap AOI through a gated workflow:

`inspect -> draft -> validate -> preview -> approve -> apply -> doctor`

Keep the target repository unchanged during inspection, drafting, validation,
and preview. A candidate may be written only to an external scratch path. Never
apply it until the user explicitly approves the exact candidate SHA-256.

## 1. Inspect

Confirm that the requested root is the exact root of an existing Git worktree.
Read the repository's `AGENTS.md`, `README.md`, current runbooks, and existing
`aoi.toml` when present. Then run:

```text
python <skill-directory>/scripts/inspect_project.py --root <repository-root>
```

Treat the JSON as inventory, not as authority. It intentionally does not read
source contents or infer the organization.

Treat `truncated`, filesystem errors, linked entries, an unreadable/invalid
state marker, or `git.tracked_changes_checked = false` as incomplete evidence.
The bounded inspector intentionally does not run a full-worktree `git status`.
Resolve the affected boundary or present it as an explicit unknown before
drafting.

Stop without writing when any of these are true:

- the path is not the exact Git worktree root;
- the root or candidate configuration is a symlink or junction;
- `aoi.toml` already exists and the user has not explicitly requested a review
  or interrupted-initialization recovery;
- AOI state already exists without the same valid installed profile, is linked,
  or records a different Windows/WSL lock domain;
- the user's goal, risk tolerance, or project boundary is materially unclear.

## 2. Draft

Read [profile-schema.md](references/profile-schema.md) and
[organization-heuristics.md](references/organization-heuristics.md). Combine:

- the user's stated goal and constraints;
- repository evidence from inspection and current docs;
- the smallest useful set of stable specialist lanes;
- model-agnostic capability tiers and evidence gates.

Write a candidate TOML to a scratch path outside the target repository.
Keep `hooks.codex.enabled = false` and `legacy.enabled = false` unless the user
explicitly requests otherwise. Do not create agents or tasks during bootstrap.
If `state_dir` is customized, require that path to be absent or empty and include
the exact directory prefix in `policy.high_risk_paths`.

Record each non-obvious choice as an assumption. The user retains ownership of
project goals, budget, risk acceptance, irreversible actions, and hook trust.

## 3. Validate

Validate the candidate before presenting or applying it:

Run this command with the repository root as the process working directory:

```text
aoi config-check --file <candidate.toml> --json
```

Treat any validation error as fail-closed. Do not weaken the schema or remove a
required gate merely to make the candidate pass. Save the returned
`config_sha256`; it is the identity of the candidate under review.

## 4. Preview and approve

Show a bounded preview containing:

- project name, profile ID, and state directory;
- the exact candidate TOML (or exact diff for review-only mode) and SHA-256;
- departments and role-to-capability mappings;
- close-qualifying evidence and required receipt components;
- high-risk paths and external lock namespace;
- exact files that `aoi init` will create;
- warnings, assumptions, and any requested hook or legacy opt-in;
- the exact apply command.

Ask only the minimum questions needed to resolve material choices. Do not treat
silence, a prior general request, or approval of the plan as approval to write.
Approval must name the exact `config_sha256`. When `aoi.toml` already exists,
remain in review-only mode unless the user explicitly requests recovery from an
interrupted initialization. Recovery may enter the apply step only when the
candidate bytes exactly match the installed file, the selected state directory
and lock domain are unchanged and valid, and the user approves that exact
digest again.

## 5. Apply

After explicit approval, initialize using the validated candidate:

Immediately rerun `config-check` and stop if its digest differs from the approved
`config_sha256`. Then initialize using that unchanged candidate:

Run this command with the repository root as the process working directory:

```text
aoi init --config <candidate.toml> \
  --expected-config-sha256 <approved-config-sha256> --json
```

Never overwrite an existing different `aoi.toml`. Never alternate native
Windows and WSL writers against the same AOI state tree. Enabling Codex hooks is
a separate user-reviewed action; the configuration flag alone does not install
or trust hooks. Require the init result's `config_sha256` and the installed
`aoi.toml` digest to equal the approved digest.

For an explicitly approved interrupted-initialization recovery, use the
installed `aoi.toml` as the candidate and the same digest-gated command. This
may repair missing AOI-managed directories, templates, policy, index, or
`.gitignore` entry. Refuse recovery if the installed config differs, its state
path is linked or unsafe, or its platform lock domain does not match the current
writer.

## 6. Verify

Run this command with the repository root as the process working directory:

```text
aoi doctor --json
```

Report the actual config digest, state path, lock domain, doctor result, files
created, and remaining warnings. On native Windows, report private-state ACL
verification as unverified unless it was independently checked. A doctor PASS
proves structural consistency only; it does not prove that the profile is the
right organization or that hooks are installed or trusted.

## Safety boundaries

- AOI is an alpha governance layer, not a security boundary.
- Chief authority means formal technical arbitration, not every reversible local
  implementation choice.
- Steward is the system-of-record and coordination role, not a technical
  decision-maker or information black box.
- Use task-contingent execution topologies; do not route every request through
  every department.
- Acknowledgement is not verification. Closure still requires qualifying,
  baseline-bound evidence.
- Do not claim AOI is faster or better without a comparison on the user's own
  workload.
