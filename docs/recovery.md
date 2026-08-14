# Recovery and interrupted bootstrap

Operational reference for AOI's recovery boundaries. This is runbook detail; the
project README carries only the summary. The authoritative semantics are in the
[operating policy](POLICY.md).

## Recover across sessions

Tasks bind the Git worktree, branch, configuration digest, plan, claims,
decisions, dissent, verification, and a bounded semantic checkpoint. A resumed
session reconstructs from the checkpoint and current repository state instead
of relying on conversational memory.

## Recover interrupted atomic publication

AOI deliberately does not auto-repair bootstrap publication. `chief-acquire`
accepts only an existing canonical `.state.lock` that is one private regular
non-linked file containing exactly one NUL byte. After taking that platform
lock, it reloads the same configuration and accepts either a complete layout or
the exact existing-NUL interrupted-init prefix before publishing first-Chief
authority. The returned credential can then authorize the identical `init`
retry.

A missing or empty state lock, any state-lock alias, any root `aoi.toml` alias,
or any other linked/ambiguous bootstrap object is rejected without automatically
mutating those objects on either POSIX or Windows. These blocking states require
explicit offline/manual audit and recovery; AOI does not guess ownership or
rollback another writer's inode. A root config temporary left before link
publication is non-stranding—the identical `init` can still proceed—but it is
outside `.aoi/` scanning and remains manual root residue for audit and cleanup.

## Clearing state-tree residue after a crash

After a writer process terminates, the current Chief can explicitly remove
eligible state-tree temporaries and then re-audit the state tree:

```bash
aoi recover-temporaries --json
aoi doctor --json
```

The command accepts no target path and requires the normal canonical NUL state
lock. Every state-tree residue deletion occurs only after an under-lock
`aoi.toml` reload and current-Chief validation. Any malformed, ambiguous, or
legacy entry prevents all ordinary deletion. A create alias at
`chief-authority.json` is not a bootstrap exception and may require manual
repair because it blocks authority validation.

Repo-external Chief credential temporaries, published-but-orphaned credentials,
obsolete credential files, and custom credential roots are not scanned by
`recover-temporaries`. Stale credentials cannot authorize a current authority
tuple, but secret-at-rest cleanup remains a separate follow-up.

This bounded cleanup addresses process-crash residue; it is not evidence of
power-loss durability or automatic bootstrap repair.

## Resume an interrupted hook-receipt generation rotation

Do not delete, move, rewrite, compact, or copy receipts out of the managed
store to clear a full-capacity error. First quiesce every hook writer and pin
the repository to one reviewed v2-capable AOI runtime. Then inspect and verify
the existing bytes:

```bash
aoi codex-hook-receipts-status --json
aoi codex-hook-receipts-verify --json
aoi codex-hook-receipts-rotation-preview \
  --mode adopt-v1 \
  --operation-id <approved-operation-id> \
  --json
```

The preview is read-only. A current Chief may apply only that exact preview:

```bash
aoi codex-hook-receipts-rotate \
  --mode adopt-v1 \
  --operation-id <approved-operation-id> \
  --expected-preview-sha256 <preview-sha256> \
  --json
```

Use `--mode rotate-v2` for a later active-generation rotation. If the command
is interrupted before the atomic control commit, ordinary receipt writes remain
denied and the same mode, operation ID, preview SHA-256, and Chief-bound intent
must be resumed. Do not choose a replacement operation. If the caller loses the
response after control publication, the exact command replays the committed
result without another generation. A different operation, authority, preview,
legacy inventory, or active inventory fails closed.
Renewing the same logical Chief keeps its session ID and epoch, so the durable
intent remains resumable; a takeover or different epoch is different authority.

After apply or exact replay, run both read-only verification and `doctor`.
Doctor reports active capacity separately from retained generation totals. A
sealed-manifest mismatch, duplicate identity, pending operation, legacy drift,
missing generation, link, or unexpected member remains an error and requires
an evidence-preserving audit; it is never auto-repaired. This procedure proves
bounded process-crash/reopen recovery only, not filesystem power-loss behavior.
