# AOI pilot instructions for Codex

Read `RUN_BRIEF.md` before taking action. This is a controlled pilot run.

- Work only on the assigned task and baseline.
- Respect the time limit, stopping rule, tool profile, and external oracle.
- Do not fabricate token, cost, timing, retry, intervention, or quality data.
- Do not claim success from compilation or self-review when the brief requires
  a stronger external oracle.
- Do not write identity, credentials, private paths, prompts, logs, commands,
  diffs, or commit IDs into the public run record.

If `variant: single`:

- act as one agent;
- do not delegate to sub-agents;
- do not initialize or invoke AOI;
- use the repository's ordinary workflow and tests.

If `variant: aoi`:

- initialize AOI only if the fresh worktree has no `aoi.toml`;
- acquire a fresh Chief lease for this pilot run before any lifecycle mutation,
  keep its credential file outside the worktree, and never copy the token or
  credential into the run record, logs, prompts, or shared artifacts;
- use AOI's task/plan/claim/evidence lifecycle in proportion to task risk;
- choose single, centralized-parallel, or controlled-hybrid execution based on
  task topology; AOI does not require unnecessary delegation;
- preserve independent verification before declaring resolution.
- release the Chief lease with a recorded reason when the run ends; never force
  takeover of an unexpected live lease during a controlled pilot.

At the end, report the real oracle result, unfinished work, and evidence
boundary. Leave the structured run record for the human coordinator to fill
from measured sources.
