---
name: aoi
description: Govern material engineering work in any AOI-configured repository through the installed AOI CLI. Use when AOI hooks report an active project, before edits or external actions, and when planning, claiming, delegating, verifying, checkpointing, delivering, or closing AOI tasks.
---

# Govern work with AOI

This is a user-scope, cross-project skill. Project-specific paths, architecture,
tool flows, evidence requirements, and exclusions belong in that project's
`AGENTS.md`, `aoi.toml`, and current source/docs—not in this skill.

AOI is a cooperative procedural guardrail for authority, exact claims, evidence,
checkpoints, jobs, and bounded delegation. It is not a filesystem sandbox.

## Client-adapter authority boundary

This skill is only a `client_adapter_only` guide shipped inside the same exact
AOI distribution as the CLI/runtime. It does not define or grant governance
authority. The installed CLI/runtime, ledger, `aoi.toml`, `.aoi/POLICY.md`, and
repository instructions remain authoritative when this prose disagrees with
them. `aoi doctor` must report the package-bound Codex client skill as `exact`
before relying on it for governed work; a missing, drifted, uninspectable, or
legacy-unbound skill must not be treated as current policy.

For this unpublished ARISE Operational Alpha candidate (not a complete v0.5
release), current schema-v3 hooks can be created only from reviewed local-v2
exact-wheel proof. Public schema-v1 receipts are readable and historically
upgradable, but cannot newly enable current hooks; the public current-hook route
is deferred. With hooks disabled, missing, drifted, or user-path-uninspectable
adapter status is warning/status only and does not block `doctor`; corrupt
receipt/schema/package/wheel provenance remains blocking. The skill never turns
any of those states into governance authority.

The user-scope install is a transitional compatibility surface for this release.
A repository-scoped skill or stable bootstrap contract is future work; do not
interpret this layout as the final multi-repository/company architecture.

## Establish the project and executable

1. Find the exact Git worktree root.
2. Read every applicable `AGENTS.md`.
3. Read `aoi.toml`, `.aoi/POLICY.md`, and the short `.aoi/INDEX.md` when
   present.
4. Run `aoi --version`, `aoi status --json`, and `aoi chief-status --json`.
5. For current schema-v3 hooks, inspect the recorded absolute venv Python
   command `-I -B -m aoi_orgware.codex_hook` and use its sibling absolute `aoi`
   CLI for read-only checks. The pip `aoi-codex-hook` launcher is v1/v2
   historical/diagnostic only; do not promote its local-v2 console/bridge
   evidence into current-hook authority.

Read-only explanation and inspection need no AOI task. Before a material edit,
external launch, evidence write, process stop, merge, or other state change,
resume or create exactly one task.

If a project still documents an older project-local harness/wrapper, do not use
it automatically. Prefer the installed AOI CLI; treat the wrapper as a
migration/history surface unless the project explicitly proves it remains the
authoritative interface.

## Chief and session fencing

Only one root session may own lifecycle mutations. If a hook supplies a valid
session/task mapping, resume it:

```bash
aoi resume --session-id <session-id> --json
```

Treat a corrupt mapping or broken backlink as a real fault. Never invent a
session ID when hooks were not trusted or did not run.

Before the first write, confirm the active Chief belongs to this exact session.
Use the non-secret identity returned by AOI:

```bash
export AOI_CHIEF_SESSION_ID=<session-id>
export AOI_CHIEF_EPOCH=<epoch>
export AOI_CHIEF_CREDENTIAL_FILE=<repo-external-owner-only-path>
```

Never print, copy, commit, or checkpoint credential contents. If another session
owns a live lease, remain read-only. Do not take over merely because a lease is
inconvenient or expired; require a real handoff/migration decision and the
expected epoch. Never force a live takeover without explicit authority.

## Start or resume a task

For new material work, initialize on the intended branch and exact worktree:

```bash
aoi init-task \
  --task-id <id> \
  --title "<title>" \
  --objective "<why>" \
  --owner <root-owner> \
  --completion-boundary "<concrete done condition>" \
  --session-id <hook-session-id>
```

Write `.aoi/tasks/<id>/plan.md`, remove placeholders, and state scope,
exclusions, claims, evidence gates, delivery, and stop conditions. Approve the
exact plan bytes before claims or work:

```bash
aoi approve-plan --task <id> \
  --note "Scope, exclusions, evidence, and verification are explicit"
```

Use `start-mini` only for one-to-three low-risk exact files. Never use mini mode
for RTL, EDA, hooks, AOI state/config, high-risk contracts, jobs, or runtime,
numeric, physical, or signoff evidence.

## Claim before mutation

Check conflicts, then claim exact files or exact external output roots:

```bash
aoi check-locks --lock repo:file:path/to/file --json

aoi claim \
  --task <id> \
  --token <unique-token> \
  --owner <root-owner> \
  --kind implementation \
  --lock repo:file:path/to/file \
  --intent "<bounded change and reason>" \
  --validation "<exact check>" \
  --expires-at <tz-aware-timestamp>
```

Prefer exact-file locks. Use `repo:`, `host:`, `eda:`, `contract:`, and
`git:merge:` identities exactly as AOI defines them. Expiry never releases a
claim. Do not work around structured or partially parsed legacy conflicts.

Use separate worktrees whenever another active session might edit the same
repository. AOI coordinates cooperative writers but cannot stop a
non-cooperating process; never let two sessions write the same physical file.

## Bounded delegation

Root owns task state, plan, claims, packets, checkpoint, arbitration, and final
delivery. Before any governed sub-agent starts, create and arm one exact packet:

```bash
aoi create-packet \
  --task <id> \
  --packet-id <packet-id> \
  --agent-role <role> \
  --model-tier <tier> \
  --objective "<one bounded question>" \
  --scope "<exact read/write scope>" \
  --deliverable "<conclusion, evidence paths, risks, next action>" \
  --validation "<root verification>"

aoi packet-arm \
  --task <id> \
  --packet-id <packet-id> \
  --expected-agent-type <type> \
  --expires-at <within-15-minutes>
```

Codex `SubagentStart` is post-start observation, not a pre-spawn security
boundary. An unarmed child must stop without material work. Record actual
routing only when the platform exposes it. Use one sequential lane for shared
write surfaces; parallelize only independently verifiable scopes.

## Evidence and external jobs

Record only checks that actually ran:

```bash
aoi add-verification \
  --task <id> \
  --category <category> \
  --status <pass|fail|blocked|skipped> \
  --evidence "<bounded observation>" \
  --command "<exact command>" \
  --boundary "<what this proves and does not prove>"
```

Keep compile acceptance, runtime result, synthesis anchor, proxy/trace evidence,
exploratory physical evidence, and engineering inference distinct. Never
promote weaker evidence into a stronger claim.

## Closure honesty

AOI requires the terminal outcome to be explicit. A verification may use
`--asserts-completion-boundary` only when that exact passing,
close-qualifying check actually covers the task's registered completion
boundary; do not add it to a partial, proxy, compile-only, or narrower check.

```bash
aoi add-verification \
  --task <id> \
  --category <close-qualifying-category> \
  --status pass \
  --evidence "<observed result>" \
  --command "<exact command>" \
  --boundary "<why this covers the registered completion boundary>" \
  --asserts-completion-boundary

aoi close-task \
  --task <id> \
  --summary "<result>" \
  --outcome achieved
```

Use `--outcome partial`, `scope_changed`, or `superseded` when the registered
boundary was not achieved, and supply `--boundary-disposition` explaining
where the unmet scope went. An achieved close with recorded blockers also
requires `--blockers-disposition`; the flag accounts for blockers but does not
turn an unmet boundary into achievement.

Change title, objective, or completion boundary only with `retarget-task`, then
re-approve the exact updated plan. If packets or jobs already ran under the
superseded plan, `approve-plan` requires `--coverage-note` stating which work
that earlier plan governed.

Before an external job, claim its source/runner/output/log surfaces and create
the exact source receipt required by project policy. Record queued, running,
and terminal transitions with concrete PID/log/exit evidence. A
queued/running/unknown job blocks close and release of its owning output claim.

## Checkpoint, delivery, and close

Checkpoint after material facts, edits, phase changes, long-job launch, review,
and before returning to the user:

```bash
aoi checkpoint \
  --task <id> \
  --fact "<established fact>" \
  --changed-file <path> \
  --risk "<remaining bounded risk>" \
  --next-action "<one exact next action>"
```

Before achieved close:

1. Account for every verification, packet, claim, and job.
2. Record delivery as pushed, local-only, blocked, or none.
3. Release claims with truthful terminal reasons.
4. Checkpoint again.
5. Run `close-task --outcome achieved` only when the completion boundary is
   achieved and a qualifying PASS explicitly recorded with
   `--asserts-completion-boundary` exists; otherwise use the truthful
   non-achieved outcome and required boundary disposition, or block/cancel.
6. Run task-local doctor during work and global doctor for final migration/audit.

Never sweep unrelated dirty files into a commit. Report the real state, exact
changes, verification boundary, remaining risks, active jobs, delivery, and
whether hook trust still needs user review.

## AOI upgrades

Treat an AOI version change as a migration, not an in-place package refresh:

1. Checkpoint or finish active work and stop every AOI writer.
2. Preserve an exact `backup-state` artifact and current `aoi.toml` digest.
3. Install the reviewed wheel into a new versioned environment.
4. Use the new absolute CLI for read-only `status`, `doctor`, and
   `chief-status` preflight.
5. Handoff Chief authority without overlapping turns.
6. Run authenticated `aoi init` for any reviewed policy migration.
7. Regenerate client hooks, review exact Codex hooks through `/hooks`, and
   verify representative task/checkpoint/doctor flows.
8. Keep the backup and old environment until rollback is proven.

Never switch a live state tree while older AOI processes or an active Chief turn
remain.
