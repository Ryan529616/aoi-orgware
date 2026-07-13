# Architecture

AOI separates organization policy from agent execution. It can sit above Codex,
an Agents SDK application, a custom supervisor, or a human-operated workflow.

## Planes

| Plane | Responsibility | Authority |
|---|---|---|
| Goal | objectives, risk, budget, irreversible choices | user |
| Decision | architecture, contracts, cross-lane trade-offs | Chief |
| Control | versions, evidence index, directives, acknowledgements | Steward |
| Execution | bounded implementation and investigation | specialist lanes |
| Improvement | capability analysis and reusable-skill lifecycle | Chief-approved projects |

## Durable objects

- `Task`: objective, plan digest, worktree identity, configuration digest, phase
- `Claim`: cooperative ownership over exact project/host/external/contract scope
- `Checkpoint`: bounded semantic reconstruction of current state
- `Lane`: owner, role, revision, authority commit, contract, next action
- `Packet`: delegated objective, scope, route request, evidence, terminal result
- `External job`: exact command, source receipt, owner, log, terminal evidence
- `Coordination request`: cross-lane question, Chief decision, directives,
  acknowledgements, implementation evidence, independent verification
- `Capacity review`: observed demand and single-use routing recommendation
- `Improvement request`: observed pain through qualified skill adoption or reject
- `Needs-user escalation`: explicit boundary that AI authority cannot cross

AOI stores project configuration in tracked `aoi.toml`. Operational state lives
under the configured private state directory (default `.aoi/`) and is ignored by
Git. Backups are deterministic, hash-verified snapshots of configuration and
state, not substitutes for source control.

## Configuration binding

Task records include the exact configuration SHA-256. This prevents a task from
being interpreted under a different role map, evidence vocabulary, receipt
contract, or risk policy after it starts.

## State safety

- Project root is an explicit `AOI_ROOT`, an explicit library argument, or the
  nearest `aoi.toml`/Git root.
- Explicit roots do not walk upward into a parent project.
- filesystem root, the user's home directory, symlinked explicit roots, path
  traversal, and malformed lock URIs fail closed.
- state writes are atomic and serialized with a POSIX file lock.
- generated state is private (`0700` directories, `0600` files where supported).

## Integrations

The core has no provider dependency. Optional `aoi-codex-hook` integration only
translates Codex lifecycle events into checkpoint reminders and guardrails.
Other runtimes should integrate through the CLI or the JSON state contract
without bypassing AOI authority rules.

## Known v0.1 boundaries

- POSIX/WSL only because the state lock uses `fcntl`.
- One cooperative root writer; no distributed transaction service.
- Capability tiers are policy labels, not calibrated cross-provider scores.
- Legacy import exists for the originating harness but is disabled by default.
- No proof yet that AOI's added process pays for itself on every workload.
