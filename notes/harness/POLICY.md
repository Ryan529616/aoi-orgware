# ARISE Harness Policy

This directory is the authoritative low-token coordination layer for **new**
ARISE work. The historical `notes/SESSION_CONTROL.md` remains an immutable
compatibility ledger until each non-terminal row is explicitly audited.

## Required lifecycle

For any task that will edit files, launch or stop EDA work, write evidence, or
merge changes, the root agent must:

1. inspect `AGENTS.md`, this policy, `notes/harness/INDEX.md`, and the relevant
   current docs/source/logs;
2. create or resume one structured task;
3. write and approve a bounded plan/completion boundary before claim,
   delegation, edits, or EDA launch; approval stores the plan SHA-256;
4. acquire explicit non-overlapping locks;
5. delegate independent, read-only or disjoint packets only;
6. checkpoint after every material phase change and before returning;
7. account for verification and active jobs, then release claims before close.

Read-only inspection needs no claim. An expired claim still reserves its scope
until its owner or an explicit audit marks it `released`, `done`, or `stale`.
Pure read-only reporting also needs no task: an unbound `Stop` is allowed and
`UserPromptSubmit` supplies only a reminder. Missing session mapping is
`unbound`; malformed JSON, a missing task, or a broken task/session backlink is
`corrupt` and blocks `Stop` until repaired.

`start-mini` is the atomic convenience path for one-to-three exact low-risk
`repo:file:` or `host:file:` edits. It creates the task, approved plan, binding,
and claim together. Mini tasks reject RTL/EDA/hook/high-risk paths, packets,
jobs, additional claims, and runtime/numeric/EDA/physical/resource evidence.
Any broader or uncertain change uses the full lifecycle.

## Machine state

Task status is one of `active`, `blocked`, `done`, or `cancelled`. It is separate
from task phase: `planning`, `gathering`, `diagnosing`, `implementing`,
`waiting_eda`, `verifying`, `reviewing`, or `closing`.

Claim status is one of `active`, `blocked`, `done`, `released`, or `stale`.
Both `active` and `blocked` reserve locks. Expiry produces a warning only.

Locks use exact URIs:

- `repo:file:<relative-path>`
- `repo:tree:<relative-path>`
- `host:file:<canonical-Windows-drive-path>`
- `host:tree:<canonical-Windows-drive-path>`
- `eda:file:<absolute-path>`
- `eda:tree:<absolute-path>`
- `contract:<slug>`
- `git:merge:<branch>`

File/tree ancestry conflicts are rejected. `..` path traversal is rejected.
Exact repo-file locks record a SHA-256 baseline because active RTL can be
untracked and therefore cannot safely rely on Git `HEAD` alone.
Exact host-file locks also record a baseline through the configured WSL mount.
Host paths must be drive-absolute, use `/`, contain no glob, `..`, alternate
data-stream syntax, UNC prefix, or backslash, and are compared case-insensitively.
These locks coordinate cooperative agents; they cannot prevent an unrelated
Windows process from editing the file.

Every task also records its exact Git worktree, branch, and starting HEAD. Task
initialization fails outside an exact Git worktree root or before the repository
has a valid HEAD commit.
Repo-file baselines are measured in that task worktree, not implicitly in the
canonical coordination root. Structured locks reject glob syntax. Use
`check-locks` before mutation and `inspect-legacy` for a named ambiguous row.
Initialize after switching to the intended branch. If that was impossible,
`adopt-current-branch` requires a current pre-adoption checkpoint, no active
jobs or pushed delivery, the recorded starting HEAD as an ancestor of current
HEAD, and exactly one reserving claim covering `git:merge:<actual-branch>`.

## Root and sub-agent contract

Only the root agent writes task state, plans, checkpoints, claims, packets, or
the generated index. Root is the sole user-facing chief, final technical
arbitrator, priority owner, and release authority; it continues architecture,
trade-off, integration, and roadmap reasoning while delegated work runs.
Sub-agents receive one bounded packet and return:

- conclusion;
- evidence and exact artifact paths;
- files inspected or changed;
- verification performed;
- unresolved risks and recommended next action.

Sub-agents must not claim completion, edit shared harness state, or paste raw
logs. Use the least expensive sufficient role: Luna/batch for mechanical scans,
Terra/medium for exploration and routine execution, and Sol/high or max only for
architecture, difficult numeric/RTL diagnosis, or final review. `max_threads=12`
is a ceiling, not a target; normally keep 2–4 useful first-level lanes. Depth may
reach two only when a first-level specialist delegates one bounded `batch`,
`explorer`, or `worker` leaf packet. A depth-two agent cannot spawn or coordinate
further agents, arbitrate, edit harness state, or report to the user.

With the normal RTL, numeric/verification, and PD/EDA specialist departments,
one `default` coordination steward is the single official specialist-to-chief
control plane. Specialists submit exact evidence, blockers, dissent, and
coordination needs through it. The steward checks commit/contract/artifact/
baseline identity, prepares bounded chief briefs, persists root decisions as
directives, and tracks acknowledgements. It is read-mostly and cannot decide a
technical option, declare PASS, release claims, freeze a baseline, set priority,
or change engineering source. Root may inspect or question any raw evidence,
but decision-relevant results return to the steward system of record.

Choose the execution topology for each request instead of forcing every task
through every department:

- `single`: one lane for sequential causal work or dense shared context;
- `centralized_parallel`: at least two independently verifiable lanes with the
  steward as aggregator;
- `hybrid`: central control plus one bounded, direct technical working session.

Hybrid lateral communication is not private authority. The steward opens it
against exact lane revisions and a named coordination request, sets an expiry
and evidence boundary, prohibits source/contract mutation, then backfills the
conclusion, dissent, blockers, and raw evidence links before arbitration.
Each topology selection is also bound to one exact work-unit ID. Any new packet
or EDA job while a selection is active must name an active selection containing
its lane; dispatch revalidates every selected lane snapshot. A new selection for
the same work unit must explicitly supersede the previous active selection.
Supersession is rejected until bound ready/dispatched packets and
queued/running/unknown jobs are terminal, open hybrid sessions are cancelled,
and closed backfill is arbitrated. Hybrid close and every queued-to-running job
transition revalidate that the exact selection remains active and current.

Decision granularity is explicit. Reversible lane-local choices that do not
change a contract or cross-lane state remain local. Baseline, interface,
architecture, semantic, PPA-target, and cross-lane choices are formal technical
decisions reserved to root. Goal/accuracy/budget changes, irreversible actions,
unresolved high-confidence dissent, or preference questions create a
`needs_user` record and block the linked arbitration and close gate until the
bound root session records the user's disposition. Open task-level
`needs_user` records also block Capacity Planning and Improvement Pipeline
arbitration.

Directive acknowledgement means received, not implemented or verified. Before
a coordination request reaches `resolved`, the implementing lane must submit
claim-bound evidence and a different lane must independently verify the latest
implementation against the exact baseline and closure oracle. The verification
record binds verifier revision, evidence category, command, boundary, artifact
SHA, and implementation ID. Weak evidence cannot satisfy a stronger closure
category.

Capacity Planning is an on-demand/standby analysis packet, not an autonomous
scheduler. It consumes only steward-verified task-type, routing, outcome, retry,
latency, intervention, and token/cost data; unavailable telemetry remains
unavailable. It may recommend a model-agnostic capability tier only for a named
depth-two lane/task-type/leaf-role combination. Root must approve or reject;
the steward records/distributes the decision. Never auto-tune, change first-level
or chief routing, pin model brands, or treat a requested tier as proof of actual
runtime routing.

The Improvement Pipeline is a temporary project path, not a standing R&D lane.
For ordinary recurrence, `improvement-create` requires at least three durable
occurrences across at least two work-unit kinds; a critical single incident may
enter review only for explicit Chief arbitration. `improvement-brief` must let
the steward compare `maintain-current`, `capacity`, and `skill-automation`
rather than assuming every pain point deserves a new skill. A Chief-approved
skill option links to a separate full harness task with its own current plan and
reserving claim. The project follows `skill-creator`; release requires structural
validation, consistent agent metadata, executed bundled scripts, at least two
representative ARISE fixtures, three adversarial fixtures, two fresh blind
forward tests, and independent review. The immutable release bundle, manifest,
and validation receipt are SHA-bound before canary. Independent review is valid
only when its verification record names a completed `reviewer` packet bound to
all candidate artifact SHA values and preserves the reviewer agent/result
identity. Adoption requires at least three distinct successful post-canary work
unit references, and any efficiency claim also requires three distinct
successful pre-canary baseline references; self-reported counts alone are not
accepted. A post-canary unit qualifies only when its packet/job record
structurally binds the exact release ID, skill version, and canary event;
free-text claims of skill use do not qualify. Zero recorded quality regressions
and a verified rollback path remain
mandatory. Skills
are shared technical assets only: they cannot install themselves, modify routing
policy, or bypass claims, packets, EDA ownership, golden independence, evidence
tiers, steward records, or Chief release authority.

Role/tier pairs are validated against the personal agent map. Packet locks must
be fully covered by the task's reserving claims. Packet transitions are
`ready -> dispatched|cancelled` and `dispatched -> done|failed|cancelled`; the
agent ID is immutable after dispatch. The root records a bounded terminal result
at its canonical path with a physical SHA-256. Missing or modified results block
doctor/close. `ready` or `dispatched` packets also prevent release of the last
claim covering their locks. Packet metadata requests a model but cannot by
itself prove the spawn used it, so routing is marked verified only when matching
actual role/tier and concrete routing evidence are supplied.

## Checkpoints and context

The checkpoint is a semantic reconstruction aid, not a transcript. Keep it
under roughly 12 KiB and include revision, objective, claims, established facts,
decisions, rejected paths, changed files, evidence boundary, active jobs,
blockers/risks, and one exact next action. Raw logs belong under `build/` or the
remote run directory.

Checkpoint rendering first preserves the full historical detail byte-for-byte.
Only when that projection exceeds 12 KiB may the renderer fall back to a
deterministic terminal-detail projection: every terminal verification, job, and
packet remains represented by a traceable compact line and explicit counts,
while pending verification, queued/running/unknown jobs, ready/dispatched
packets, semantic facts/decisions/files/risks, delivery, and next action remain
full. Complete records remain authoritative in `state.json`; close and doctor
continue to validate that full state. If semantic or active detail alone still
exceeds the limit, checkpoint creation fails without changing state or the
previous checkpoint.

Before a long run, phase transition, expected compaction, or user-facing return,
run the checkpoint command. On resume or after compaction, read the task-bound
checkpoint instead of replaying the full conversation or legacy ledger.

Checkpoint state is valid only when revision and stored SHA-256 match the
physical `checkpoint.md`. Commands render/size-check first, atomically write the
checkpoint, and only then commit state; a partial failure therefore remains
stale rather than falsely current/done.

Project command hooks are trusted executable policy. `SessionStart` restores a
thread, `UserPromptSubmit` reasserts the binding contract each turn,
`SubagentStart` injects the packet contract, and `Stop` checks a session-bound
physical checkpoint once without looping. Any semantic edit to
`scripts/harness/codex_hook.py` must also increment its supported hook version
and the fixed `--hook-version` argument in both project `hooks.json` files, so
Codex invalidates the old definition trust and asks for explicit review again.
Hooks are procedural guardrails, not a security boundary: protocol mismatch and
unexpected exceptions deliberately fail open to avoid bricking Codex. Corrupt
session state is an expected validation result and therefore fails closed at
`Stop`. After a hook version change, the user must review the new definitions
through `/hooks` before automatic protection can be claimed.

`doctor --task <task-id>` validates only that task, its referenced claims and
session mappings, plus shared hook/config invariants. It intentionally ignores
unrelated task corruption and the legacy ledger. Run global `doctor` for close,
full-state maintenance, and legacy audit.

`backup-state` writes a deterministic allowlisted archive of harness state,
scripts, project/relay hook configuration, project policy, and the personal
skill. It fsyncs and publishes the SHA-bound sidecar last; `verify-backup`
rechecks archive, manifest, member paths, sizes, and hashes. Destinations must
remain under the configured Windows-side backup root and cannot traverse a
symlink. This is same-host recovery, not off-host disaster recovery.

## EDA evidence

Every long EDA job record must identify host, tool, run ID, work root, status,
log path, PID and/or tmux session when available, stop condition, and source
SHA. Distinguish compile acceptance, runtime pass/fail, synthesis anchor,
proxy/evaluator/trace evidence, exploratory physical evidence, and engineering
inference. Never promote one level into another.

Before launch, the task must own both remote work-root and log locks and record
the job as queued. `job-start` accepts only `queued`; transition to `running`
requires a PID or tmux identity and revalidates the active topology/lane
snapshot plus any live skill-canary binding. The successful transition writes
an integrity-protected launch-authority event. A PASS terminal update requires
at least one such event; `queued -> unknown -> pass` is forbidden. Its source
receipt must already exist locally,
match the supplied physical SHA-256, and use receipt schema version 1. The
receipt records `source_set_id`, producer, the exact tool path/version/command,
and `rtl`, `tb`, `sram`, `runner`, `golden`, and `overlay` components. Every
component is either `included` with absolute paths and SHA-256 values, or
`not_applicable` with a reason; `rtl` and `runner` must be included. The harness
snapshots the exact receipt into the task results and revalidates it at
doctor/close. `unknown` is unresolved and blocks close; `pass`, `fail`, and
`stopped` require terminal evidence and an exit code. A pass must match the
job's recorded success exit code (zero unless explicitly configured).
Start from `templates/source_receipt.example.json`; do not weaken or omit its
component accounting.

## Close gate

A task cannot close while it owns non-terminal/orphan claims, has
queued/running/unknown jobs, has unfinished packets, contains unaccounted
verification, lacks a current approved plan/completion boundary, or has a stale
or physically mismatched checkpoint. Verification uses an allowlisted evidence
class and requires a concrete command/method, artifact or bounded observation,
and evidence boundary. Engineering inference alone never satisfies achieved
close. `close-task` means achieved and requires a qualifying pass. Use
`block-task` for resumable blockers and `cancel-task` only after
claims/jobs/packets/delivery are accounted. `blocked` delivery cannot be closed
as achieved. A `pushed` delivery requires the exact worktree HEAD plus a named
remote and full `refs/heads/...` ref whose live tip equals the commit;
local-object existence is not push proof.

## Legacy quarantine

`import-legacy` reads but never rewrites `notes/SESSION_CONTROL.md`. Non-terminal
legacy rows are mirrored under `claims/legacy_pending/`; expired rows are marked
`expired_unverified`, not silently released. Parseable legacy paths continue to
participate in overlap checks. A partially unparsed non-terminal row is a named
blocking ambiguity even when another part of that row produced a valid lock;
`claim` cannot bypass the check. Duplicate non-terminal tokens fail import
before pending state changes.

Same-token migration is never implicit: explicit adoption evidence is required,
and new locks must fully cover every parsed legacy lock. Escaped pipes and pipes
inside variable-length Markdown code spans are parsed; unclosed spans and other
malformed rows fail import loudly. Legacy star, bracket, and brace globs are
conservatively promoted to their non-glob parent tree.
