---
name: aoi
description: Operate under AOI governance in this repository. Use when an AOI Codex lifecycle hook says AOI is active, before material governed edits or external actions, when creating/claiming/verifying/closing an AOI task, or before spawning a governed sub-agent.
---

# Operating under AOI in Codex

AOI is a cooperative procedural guardrail for durable authority, claims,
evidence, checkpoints, and bounded delegation. It is not a filesystem sandbox.
Follow the hook context and the repository's `.aoi/POLICY.md`; do not treat the
hook itself as proof that a task is valid or complete.

## Bind material work to one task

Read-only explanation and inspection do not require a task. Before a material
edit, external launch, or other state change, use the SessionStart context to
resume or initialize exactly one task and bind the current Codex session:

```bash
aoi status
aoi resume --task <task-id>
# Or initialize a new task, then:
aoi bind-session --task <task-id> --session-id <session-id>
```

If the hook reports a corrupt mapping, stop material work and run `aoi doctor`.
Never reuse a closed task for new work.

## Governed task loop

```bash
aoi init-task --task-id <id> --title "<title>" --objective "<why>" \
  --owner root --completion-boundary "<concrete done condition>"
$EDITOR .aoi/tasks/<id>/plan.md
aoi approve-plan --task <id> --note "Scope and verification are explicit"

aoi claim --task <id> --token <claim-id> --owner root --kind implementation \
  --lock repo:file:path/to/file --intent "<what and why>" \
  --validation "<how it will be checked>" --expires-at <tz-aware-timestamp>

# Perform the bounded work and record evidence that was actually observed.
aoi add-verification --task <id> --category <category> --status pass \
  --evidence "<bounded observation>" --command "<command actually run>" \
  --boundary "<what this proves and does not prove>"

aoi set-delivery --task <id> --mode local-only --detail "<location>"
aoi release-claim --token <claim-id> --status done --reason "<done>"
aoi checkpoint --task <id> --next-action "Close the task"
aoi close-task --task <id> --summary "<result>"
```

For a low-risk one-to-three-file change, `aoi start-mini` can create the task,
approved plan, session binding, and exact-file claim together.

## Evidence boundary

An acknowledgement, static reading, compilation, or model inference is not a
runtime pass unless the declared boundary says so. Never claim a check ran when
it did not. Record exact artifacts and distinguish compile acceptance, runtime
results, external-system evidence, and engineering inference.

## Arm before spawning a governed sub-agent

Codex `SubagentStart` hooks observe a start after it has occurred; they are not
a pre-spawn security boundary. Always create and arm an exact packet first:

```bash
aoi create-packet --task <id> --packet-id <packet-id> \
  --agent-role explorer --model-tier standard \
  --objective "<one bounded question>" --scope "<exact read/write scope>" \
  --deliverable "<conclusion, evidence paths, risks, next action>" \
  --validation "<how root will verify it>"
aoi packet-arm --task <id> --packet-id <packet-id> \
  --expected-agent-type <codex-agent-type> --expires-at <within-15-minutes>
# Spawn exactly one matching Codex sub-agent now.
```

The SubagentStart hook consumes the arm and injects the packet contract. An
unarmed start becomes an accountable incident and the child must stop without
material work. The root session alone owns AOI lifecycle state, claims, plan,
checkpoint, and final completion.

## Before ending a turn

The Stop hook may block a stale checkpoint. Before stopping on active material
work, persist the real state:

```bash
aoi checkpoint --task <id> --next-action "<one exact next action>"
```

Include changed files, verified evidence, unresolved risks, and the next action.
On resume or compaction, reconstruct from the checkpoint and current files, not
from conversational memory.

## Boundaries

- Chief authority is formal technical arbitration, not every reversible choice.
- Chief credentials are repo-external secrets; never copy their value or path
  into tracked files, AOI state, logs, packets, or checkpoints.
- Respect exact-file claims. AOI does not prevent a non-cooperating process from
  writing the same file, so use separate worktrees or explicit ownership when
  another session is active.
- AOI is alpha. Do not claim it is faster or better without a controlled
  comparison on this repository's workload.
