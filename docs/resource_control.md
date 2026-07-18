# ARISE-first Codex resource control

AOI uses two different resource layers. They must not be confused:

1. Project `.codex` files are static platform ceilings and role defaults for a
   future trusted Codex session.
2. An execution selection carries a smaller dynamic AOI envelope that is
   enforced when packets are created, armed, and dispatched.

Writing configuration does not hot-reload the current session. It also does
not prove the provider's actual model route, token usage, price, or available
capacity.

## Default selection envelope

`execution-select` now derives and SHA-seals one resource envelope:

- `single`: one active first-level agent;
- `centralized_parallel` or `hybrid`: the selected specialist-lane count, with
  a default soft cap of four and a hard ceiling of twelve;
- total active agents across both depths: twice the first-level wave by
  default, never above twelve and never below the first-level limit;
- delegation depth: at most two;
- depth two: still restricted to `batch`, `explorer`, or `worker`, one active
  child per dispatched parent, with one exact acknowledged Capacity Planning
  decision;
- depth-one role/model tier: still validated against the project AOI role map.

A depth-one packet must also match the exact role of its selected lane. A
globally valid role cannot be substituted into a different selected lane.

Every packet created under that selection records the exact envelope SHA-256.
`packet-arm`, trusted hook consumption, manual dispatch registration, doctor,
and close gates recompute the binding. Ready packets may be prepared in
advance; only armed or dispatched first-level packets consume the dynamic
active-agent limit.

Selections created by an older AOI version remain legacy-compatible and do not
gain retroactive resource authority. Supersede their topology to opt into the
new envelope.

## User and Chief override

An override is a proposal, not an instruction. The direct User/Chief discussion
is recorded with the User's rationale/evidence, the Chief's preliminary
assessment, alternatives, expiry, and an exact future target. Only the Chief
can approve the exact settings, risk boundary, rollback condition, and
compensating controls.

Phase 1 treats the SHA-bound proposal as exact accept/reject authority. If the
Chief wants different settings, reject it, generate a new plan/contract, and
submit a new override request; arbitration cannot silently rewrite the target.

The following proposes raising one future selection from the default four
active first-level agents to five:

```bash
aoi execution-select-plan \
  --task <task-id> \
  --selection-id <future-selection-id> \
  --work-unit-id <work-unit-id> \
  --mode centralized_parallel \
  --lane <lane-a> --lane <lane-b> --lane <lane-c> \
  --lane <lane-d> --lane <lane-e> \
  --steward-lane-id <steward-lane> \
  --scope "Only this exact independent selected work unit" \
  --sequential-dependency low \
  --tool-density low \
  --shared-context low \
  --rationale "Why this topology is appropriate" \
  --falsification-condition "What invalidates this topology" \
  --escalation-condition "When the Chief must reduce or stop it" \
  --session-id <task-bound-root-session> \
  --override-id <override-id> \
  --proposed-setting envelope.max_active_first_level_agents=5 \
  --json

aoi override-request \
  --task <task-id> \
  --override-id <override-id> \
  --target-kind execution_resource \
  --target-id <future-selection-id> \
  --target-contract-sha256 <execution-select-plan-target-contract-sha256> \
  --scope "Only this independent selected work unit" \
  --setting envelope.max_active_first_level_agents=5 \
  --user-rationale "Why the extra concurrency is worth it" \
  --user-evidence "Why the lanes are independent" \
  --chief-assessment "Preliminary technical assessment" \
  --alternative "Keep the default four-agent wave" \
  --expires-at <future-timezone-aware-timestamp> \
  --session-id <task-bound-root-session>

aoi override-arbitrate \
  --task <task-id> \
  --override-id <override-id> \
  --expected-version 1 \
  --decision approved \
  --rationale "Why the Chief accepts this bounded exception" \
  --risk-boundary "What this approval does not waive" \
  --rollback-condition "When to stop using the exception" \
  --compensating-control "How the added risk is contained" \
  --session-id <task-bound-root-session>
```

Pass `--override-id <override-id>` to the exact matching
`execution-select`. That transaction consumes the approval and records the
resulting envelope and target-contract digests. The plan preimage binds the
task plan, work unit, supersession, mode, sorted lane authority snapshots,
Steward snapshot, scope, task characteristics, rationale, falsification and
escalation conditions, and proposed resource envelope. A replay, changed
semantic field, stale lane snapshot, different target id, expired approval, or
changed version fails closed.

Supported `execution_resource` settings are:

- `envelope.max_active_first_level_agents`;
- `envelope.max_active_total_agents`;
- `envelope.max_delegation_depth`;
- `agents.<role>.model`;
- `agents.<role>.model_reasoning_effort`.

Role model/reasoning settings become requested project configuration for that
selection. They still require the `.codex` apply step and a fresh trusted Codex
session before they can affect routing.

The Chief may reject the proposal. An approved but unused proposal can be
revoked with its current `--expected-version`. The following guardrails are
never overridden: Chief lease, task-bound root session, approved plan, claim
coverage, dispatch-before-work, packet/result integrity, evidence strength,
project trust/sandbox/provider limits, the twelve-thread ceiling, and depth
two.

## Plan and apply project Codex files

AOI only writes project-scoped files. It never edits the user's
`~/.codex/config.toml` or `~/.codex/agents/*.toml`. Existing project role files
are the first source; otherwise the corresponding user role file is copied as a
template. Required `name`, `description`, and `developer_instructions` fields
are preserved while `model` and `model_reasoning_effort` are patched.

Claim the exact project scope before apply:

```bash
aoi claim \
  --task <task-id> \
  --token <claim-token> \
  --owner <owner> \
  --kind configuration \
  --lock repo:tree:.codex \
  --intent "Apply the reviewed Codex resource profile" \
  --validation "Verify plan, receipt, fresh-session smoke, and rollback" \
  --expires-at <future-timezone-aware-timestamp>
```

Use one event id for plan and apply:

```bash
aoi codex-config-plan \
  --task <task-id> \
  --event-id <event-id> \
  --execution-selection-id <selection-id> \
  --role explorer \
  --json

aoi codex-config-apply \
  --task <task-id> \
  --event-id <event-id> \
  --execution-selection-id <selection-id> \
  --role explorer \
  --expected-plan-sha256 <reviewed-plan-sha256> \
  --session-id <task-bound-root-session> \
  --json
```

The event id and current approved task-plan SHA are part of the plan digest, so
a reviewed digest for event A cannot authorize event B or a different task
plan.

The normal project ceiling is `max_threads = 12` and `max_depth = 2`; the
selection envelope enforces the smaller active wave. A `resource_config`
override may approve exact `agents.max_threads`, `agents.max_depth`, or
role-model/reasoning settings for one event. Its `--target-id` must equal that
event id, and both plan and apply must name the override. Before requesting
that override, create its exact contract with `codex-config-plan` plus the
future `--override-id` and one or more `--proposed-setting`; pass the returned
`plan_sha256` as `override-request --target-contract-sha256`. After Chief
approval, the ordinary plan/apply path recomputes and must exactly match it.

Apply writes a task-local JSON receipt before changing project files. The
receipt binds every before/after byte sequence, file hash, plan hash, root
session, event, override, and the full reviewed plan preimage. After apply,
start a fresh Codex session inside the task worktree. Do not report routing as
verified merely because the files exist.

## Fresh-session registration

The startup hook stores a task-independent schema-v2 sealed receipt. Under the
project state lock it records the SHA-256 identities of
`.codex/config.toml` and managed `.codex/agents/*.toml` files. Inspect only its
validated metadata and obtain the compare-and-register SHA without a Chief
credential:

```bash
aoi codex-startup-receipt-show \
  --session-id <fresh-session-id> \
  --json
```

Bind that fresh session to the task and make the same session the active Chief
before registering it. Use the startup SHA above and `receipt_sha256` returned
by `codex-config-apply`:

```bash
aoi codex-session-register \
  --task <task-id> \
  --session-id <fresh-session-id> \
  --event-id <event-id> \
  --expected-startup-receipt-sha256 <startup-sha256> \
  --expected-resource-receipt-sha256 <resource-receipt-sha256> \
  --json
```

Each managed file is read twice and its descriptor and final pathname metadata
must remain stable. This detects ordinary concurrent mutation/replacement, but
is not an OS-atomic snapshot against a hostile same-account writer deliberately
evading metadata and repeated-read checks. Such writers are outside the
cooperative lock guarantee.

Registration succeeds only when every reviewed plan after-image occurs in that
sealed startup observation, the target event is still the unique
effective-current apply, it matches the current approved task plan and exact
receipt/applicability/selection authority, and all managed files still equal
the receipt's after-bytes. Independent host/process timestamps are not used as
causal proof. The complete existing registration ledger, strict apply/rollback
replay, and persisted startup store must also validate. A same-epoch Chief
renewal may replay the identical record; a different event, session, epoch,
receipt, or historical authority is a conflict. Identical managed bytes from
two different events are deliberately indistinguishable at startup; the
selected event must be current at registration, but AOI does not claim startup
occurred after that exact event. The result is only
`registered_byte_state_equivalent_only`: the hook observed equivalent bytes,
but it does not prove that Codex loaded them or that the provider honored the
requested model/profile/sandbox.

Schema-v1 startup receipts remain readable as hash-verified history so they do
not poison the bounded store. They cannot satisfy v2 registration and are never
silently upgraded; creating v2 for the same session id is an explicit conflict,
while unrelated new v2 sessions continue normally.

## Rollback

Rollback requires the same live task, Chief/root authority, claim coverage, an
unchanged receipt and unchanged applied file bytes. The event must also be the
unique effective-current apply; shadowed ancestors cannot be rolled back out of
order even when their bytes happen to match:

```bash
aoi codex-config-rollback \
  --task <task-id> \
  --event-id <event-id> \
  --reason "Fresh-session validation did not meet the approved boundary" \
  --session-id <task-bound-root-session>
```

AOI restores the exact previous bytes or removes files that did not previously
exist. Drift after apply blocks rollback rather than overwriting unrelated
changes. All targets are preflighted before the first rollback mutation. If a
mid-rollback write fails, AOI attempts to restore the exact applied state; if
task-state publication fails after file rollback, AOI probes publication and,
when the old applied state is still authoritative, reapplies the exact receipt
bytes. Ambiguous or doubly failed recovery retains the receipt and fails
closed. After rolling back the latest apply, the newest remaining non-rollback
apply becomes current and its exact after-bytes are revalidated. Apply and
rollback writers share a strict timezone-aware replay: transition instants are
unique, apply order follows the append ledger, and rollback is LIFO. Up to five
seconds of cross-process clock jitter is serialized after the latest causal
resource/registration record; a larger backward jump fails before any target
file is changed.

## Claude model-tier dispatch gate

On the Claude host the tier ledger has one enforcement point Codex lacks:
`PreToolUse` receives the `Agent` tool's input — including the requested
`model` — before the sub-agent exists. The hook denies a governed dispatch
whose model is absent (omission inherits the Chief session's model, which is
exactly the cost leak the tier exists to prevent) or outside the armed
packet's tier. Depth-two helper spawns are capped at the parent packet's
tier.

The tier→family table matches case-insensitive substrings, so `sonnet`
covers both the alias and a fully qualified model id:

| Tier | Default allowed families |
|---|---|
| `frontier` | `opus` |
| `expert` | `opus`, `sonnet` |
| `advanced` | `sonnet` |
| `standard` | `sonnet`, `haiku` |
| `economical` | `haiku` |

The session's own top-price model is deliberately in no tier: the Chief
session is the only place for it, and a packet that needs it is an
escalation, not a dispatch. Override the table with
`AOI_CLAUDE_TIER_MODELS`, a JSON object mapping tier names to family lists,
e.g. `{"standard": ["opus"]}`; tiers absent from the override fall outside
the gate.

Boundary: this checks the dispatch *request* the runtime received, not the
routing it later performs, and Workflow-orchestrated spawns bypass
`PreToolUse` entirely (`SubagentStart` still observes them). It is a
cooperative guardrail on the one hook that fires before spawn.

## Claude claim-write gate (opt-in)

The claim ledger records who owns which files, but by default nothing stops a
sub-agent from writing a file it never claimed — AOI is a cooperative
guardrail, not an OS sandbox. On the Claude host, though, `PreToolUse` fires
before `Write`/`Edit` too, so the ledger can be enforced on the tools a
*cooperating* agent actually uses.

Set `AOI_CLAUDE_CLAIM_WRITE_GATE`:

| Value | Behavior on a `Write`/`Edit`/`MultiEdit`/`NotebookEdit` |
|---|---|
| unset / `off` | No gating (default; exact pass-through) |
| `warn` | Allow, but announce a write outside the session's live claims |
| `deny` | Block a write outside the session's live claims before it lands |

The check applies only to a session bound to a task, compares the target
against that task's reserving `repo:file:` and `repo:tree:` claims, and passes
through writes outside the repo (temp/external output) and under `.aoi/` (Chief
manages AOI state through the CLI, not file claims). `Bash` is never gated —
its command cannot be resolved to a target, and a false deny there would break
the session.

Boundary: this gates the cooperative tool path only. A non-cooperating process
under the same OS account, or a write routed through `Bash`, is not stopped.
It upgrades the claim ledger from a record to a pre-write gate on Claude; it is
not a sandbox.

## Current evidence boundary

This controller is policy-based, not cost-optimizing. AOI can select a role,
request the role's configured model/reasoning effort, cap concurrency/depth,
and preserve the decision/receipt. It cannot currently read authoritative
per-spawn token usage or price, prove provider routing, or calculate the
cheapest sufficient model. Those fields must remain unavailable until an
independent provider receipt exists.
