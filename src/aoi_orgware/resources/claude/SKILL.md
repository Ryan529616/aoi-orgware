---
name: aoi
description: Operate under AOI governance in this repository. Use whenever an AOI SessionStart/UserPromptSubmit hook says "AOI is active" for this project, when a task must be created/claimed/verified/closed, or before dispatching a governed sub-agent. AOI records authority, ownership, evidence, and closure so parallel agents do not overwrite each other or close work without proof.
---

# Operating under AOI

This project is governed by **AOI** (Agent Organization Infrastructure). AOI is a
cooperative, fail-open procedural guardrail — not a sandbox. It keeps parallel
agent work from overwriting ownership, losing decisions, or being closed without
evidence. Work *with* it: the fastest path is to follow the loop below, not to
route around the hooks.

The hooks will tell you the current state. Read what they say each turn.

## First: bind this session to a task

On session start the hook prints one of:

- **"AOI is active … No unambiguous task mapping exists for this session."** —
  the repo is governed but this chat is not yet bound to a task. Before any
  material edit, either resume an existing task or create one, then bind:

  ```bash
  aoi status                      # see existing tasks
  aoi resume --task <task-id>     # if continuing one
  # …or create a new one (see the loop below), then:
  aoi bind-session --task <task-id> --session-id <this-session-id>
  ```

- **"This session is bound to task <id> …"** — run `aoi resume --task <id>` and
  reconstruct from the task checkpoint and current files, not from memory.

Read-only answers (explaining code, summarizing) do **not** require a task. Only
bind before material mutation or an external action.

## The governed task loop

```bash
# 1. Create a task and make its plan explicit.
aoi init-task --task-id <id> --title "<title>" --objective "<why>" \
  --owner root --completion-boundary "<what 'done' concretely means>"
$EDITOR .aoi/tasks/<id>/plan.md
aoi approve-plan --task <id> --note "Scope and verification are explicit"

# 2. Claim the EXACT write scope before you mutate anything.
aoi claim --task <id> --token <id>-claim --owner root --kind implementation \
  --lock repo:file:path/to/file --intent "<what/why>" \
  --validation "<how it will be checked>" --expires-at <tz-aware-timestamp>

# 3. Do the work, then record real evidence (see "Evidence" below).

# 4. Account for delivery, release the claim, checkpoint, and close.
aoi set-delivery --task <id> --mode local-only --detail "<where the change lives>"
aoi release-claim --token <id>-claim --status done --reason "<done>"
aoi checkpoint --task <id> --next-action "Close the task"
aoi close-task --task <id> --summary "<result>"
```

For a small, low-risk, one-to-three-file edit, `aoi start-mini` creates the task,
approved plan, session binding, and exact-file claim in one step.

If a command is refused ("cannot close", "claim conflict", …), that is the
guardrail working. Read the message; it names exactly what is missing or who
already owns the scope. Fix that, don't force past it.

## Evidence: an acknowledgement is not proof

AOI will not let a task close on your say-so. Closure needs a real, qualifying
verification bound to the current baseline. Record it honestly:

```bash
aoi add-verification --task <id> --category <category> --status pass \
  --evidence "<what was actually observed>" --command "<command you ran>" \
  --boundary "<exactly what this proves and does not prove>"
```

Never claim a test passed that you did not run. Never label exploratory reading
or a code-graph guess as close-qualifying evidence.

## Dispatching a governed sub-agent — arm first

When the hook governs sub-agents (default: `general-purpose`), a spawn with **no
pre-armed packet is denied at `PreToolUse` before the sub-agent exists**. That is
why an ungoverned probe stops with "no task mapping / no armed packet". To
dispatch one correctly:

```bash
aoi create-packet --task <id> --packet-id <pid> --agent-role explorer \
  --model-tier standard --objective "<one bounded question>" \
  --scope "<read-only, exact sources>" \
  --deliverable "<conclusion + exact evidence paths + risks + one next action>" \
  --validation "<how the root will check it>"
aoi packet-arm --task <id> --packet-id <pid> --expected-agent-type general-purpose \
  --expires-at <timestamp within 15 minutes>
# Now spawn exactly one matching general-purpose sub-agent, and pass a model
# inside the packet's tier — see below.
```

**Pass a tier-matched `model` when you spawn.** `PreToolUse` reads the `Agent`
tool's `model` and denies a governed dispatch whose model is absent (omitting it
would inherit *your* model — the cost leak the tier exists to prevent) or outside
the packet tier's families. The shipped default table:

| `--model-tier` | Pass a model in family |
|---|---|
| `frontier` | `opus` |
| `expert` | `opus` or `sonnet` |
| `advanced` | `sonnet` |
| `standard` | `sonnet` or `haiku` |
| `economical` | `haiku` |

So an `--model-tier standard` packet must be spawned with a `sonnet` or `haiku`
model; spawning it on `opus`, or with no model, is denied before the sub-agent
exists. Matching is by family substring, so both the alias and a fully qualified
id (`claude-sonnet-5`) count. Override the table with `AOI_CLAUDE_TIER_MODELS`
(JSON). The session's top-price model is in no tier by default: a packet that
truly needs it is an escalation, not a routine dispatch.

The sub-agent stays inside its packet, returns a bounded conclusion, and never
mutates AOI state. **Ambient** agent types (Explore, workflow helpers) are not
governed — their output is engineering inference for you, never packet evidence.

## Before you stop

The Stop hook blocks if the task has a stale semantic checkpoint. Before ending a
turn on an active task:

```bash
aoi checkpoint --task <id> --next-action "<one exact next action>"
```

Summarize material facts, changed files, the evidence boundary, and open risks in
the checkpoint — so the next session (or a resume/compaction boundary) can rebuild
from it rather than from conversational memory.

## Boundaries

- The **root** (this main session) owns AOI state, claims, plan, checkpoint, and
  final completion. Sub-agents and ambient tooling do not mutate `.aoi/`.
- Chief authority is formal technical arbitration, not every reversible local
  choice. Chief credentials are repo-external secrets: never copy their token,
  credential file, or path into state, logs, checkpoints, or artifacts.
- AOI is alpha. Do not claim it is faster or better than a simpler topology
  without a comparison on this repo's own workload.
