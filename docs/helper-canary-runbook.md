# Codex helper-budget live canary — operator runbook

AOI must never claim that depth-two helper budgets "work" on a Codex
transport from code inspection. Whether the SubagentStart hook payload of a
nested spawn carries the DIRECT parent's session id (required for helper
association, `dispatch_protocol.observe_subagent_start`) or only the root
session id is an empirical property of the installed Codex version and hook
protocol. This runbook probes it live and records a typed
`transport_probes` verdict in task state.

The unit suite (`tests/test_helper_canary.py`) proves the AOI-side logic for
every payload shape; only the LIVE probe below proves the transport.

## Preconditions

- An initialized AOI project with `[hooks.codex] enabled = true` and the
  codex hooks installed (`aoi codex-init`), protocol v6.
- An open task with an approved plan, a bound root session, and a Chief
  lease.
- A real Codex session started at the project root (the transport under
  test).

## Probe procedure

1. Record the window start (timezone-aware ISO-8601):

   ```bash
   date --iso-8601=seconds   # keep this value; the canary only counts
                             # observations at or after it
   ```

2. Create and arm one depth-one parent packet with a helper budget of 1
   (budget is only settable at `create-packet` time):

   ```bash
   aoi create-packet --task <task> --packet-id canary-parent \
     --agent-role worker --model-tier advanced --helper-spawn-budget 1 \
     --objective "Live helper transport canary" \
     --scope "read-only; spawn exactly two trivial nested helpers" \
     --deliverable "two nested helper attempts, no material work" \
     --validation "transport probe verdict recorded"
   aoi packet-arm --task <task> --packet-id canary-parent \
     --parent-session-id <root-session-id> --expected-agent-type <type> \
     --expires-at <now+15min>
   ```

3. In the live Codex session, dispatch exactly one sub-agent matching the
   arm, and instruct it to spawn TWO trivial nested helpers (e.g. "spawn a
   sub-agent that reports the current date, twice"). The first nested spawn
   exercises the budget slot; the second exercises the over-budget path.

4. After both nested spawns returned (or visibly failed to), evaluate:

   ```bash
   aoi codex-helper-canary --task <task> --probe-id live-canary-1 \
     --parent-packet-id canary-parent --window-start <step-1 value> \
     --session-id <root-session-id> --json
   ```

## Reading the verdict

- `supported` — the transport reported the depth-one agent's own session id
  for the nested spawn; exactly one helper slot was consumed and the second
  spawn produced a `helper_budget_exhausted` incident. Helper budgets are
  usable on this transport.
- `supported_budget_enforced` — direct-parent linkage resolved but the
  budget gate refused (`no_helper_budget` / `helper_budget_exhausted`).
  Seen when probing a budget-0 parent: linkage works, budgets enforce.
- `unsupported_root_parent_only` — nested spawns arrived keyed to the ROOT
  session id and became unmanaged-start incidents while the parent consumed
  no slot. **Helper budgets do not deliver nested helpers on this
  transport**; do not raise packet budgets expecting fan-out, and account
  the incidents explicitly.
- `unknown` — nothing observable happened in the window; the probe proves
  nothing. Re-run with a fresh window; check that the hooks fired at all
  (`aoi doctor`).

## Boundaries

- One probe id is single-use; keep probes in state as the durable evidence
  trail for any later claim about helper capability.
- The verdict binds to the Codex build and hook protocol version that
  produced the observations; re-probe after upgrading Codex.
- A `supported` verdict is NOT a model-routing verification and never sets
  `routing_verified`; it only certifies parent association and budget
  accounting.
