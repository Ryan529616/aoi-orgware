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

## Bootstrap boundary

The optional `aoi-bootstrap` skill is an inference and onboarding layer, not a
new authority plane. It may inspect repository structure and propose departments,
capability tiers, evidence gates, and risk paths. Its output remains an
untrusted candidate until:

1. the strict CLI validates the complete TOML outside project state;
2. the user reviews assumptions and the exact write preview;
3. the user explicitly approves application;
4. `aoi init --config` applies the exact validated bytes without clobbering;
5. `aoi doctor` verifies the resulting state and lock domain.

This keeps natural-language interpretation outside the deterministic state
transition boundary. The skill never creates always-running agents, installs
hooks, chooses a provider-specific model, or changes user-owned goals and risk
decisions.

## State safety

- Project root is an explicit `AOI_ROOT`, an explicit library argument, or the
  nearest `aoi.toml`/Git root.
- Explicit roots do not walk upward into a parent project.
- filesystem root, the user's home directory, explicit roots crossing real
  symlink/reparse components, path traversal, and malformed lock URIs fail
  closed; benign Windows 8.3 aliases are canonicalized after component checks.
- configured state paths are validated under both POSIX and Windows path
  semantics and must resolve inside the project root;
- state writes use same-directory replacement after flushing the new file;
- writers are serialized with `fcntl.flock` on POSIX/WSL or a one-byte
  `msvcrt` lock on native Windows;
- immutable packet/verification blobs are completed and flushed before atomic
  no-replace publication, and every managed ancestor is checked for links;
- `.aoi/platform.json` permanently binds the tree to one lock domain so
  alternating WSL/native writers fail closed;
- existing repo/host tree claims receive a bounded recursive identity audit;
  nested links, hard-linked files, special nodes, and oversized scans fail
  closed before ownership is recorded;
- generated state is private (`0700` directories, `0600` files where
  supported). Native Windows ACL equivalence is reported as unverified.

## Integrations

The core has no provider dependency. Optional `aoi-codex-hook` integration only
translates Codex lifecycle events into checkpoint reminders and guardrails.
Other runtimes should integrate through the CLI or the JSON state contract
without bypassing AOI authority rules.

## Known v0.1 boundaries

- One state tree may be written from POSIX/WSL or native Windows, not both.
- Native Windows support is limited to ordinary local filesystems; UNC/network
  shares and case-sensitive NTFS are unsupported. Project-file and Git-branch
  locks therefore use case-insensitive canonical identities in that domain.
- Native Windows provides atomic visibility and flushed file contents, but AOI
  cannot claim POSIX-equivalent parent-directory metadata durability or private
  ACL enforcement through the Python standard library.
- Nonexistent planned trees have no filesystem identity to inspect and retain
  only AOI's cooperative lexical reservation until a later claim/release audit.
- One cooperative root writer; the state lock covers one CLI transaction, not
  a cross-command Chief lease or stale-turn fencing credential. Overlapping
  Chief turns remain prohibited until the planned v0.2 fencing architecture.
- Initialization is resumable and non-clobbering, but its multiple filesystem
  writes are not one atomic transaction; rerun the same profile after an
  interruption.
- Capability tiers are policy labels, not calibrated cross-provider scores.
- Legacy import exists for the originating harness but is disabled by default.
- No proof yet that AOI's added process pays for itself on every workload.
