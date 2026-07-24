# Recovery and interrupted bootstrap

Operational reference for AOI's recovery boundaries. This is runbook detail; the
project README carries only the summary. The authoritative semantics are in the
[operating policy](POLICY.md).

## Recover across sessions

Tasks bind the Git worktree, branch, configuration digest, plan, claims,
decisions, dissent, verification, and a bounded semantic checkpoint. A resumed
session reconstructs from the checkpoint and current repository state instead
of relying on conversational memory.

If the checkpoint contains an `Established fact history`, `Decision history`,
or `Rejected path history` marker, its recent entries are only a convenience
tail. Read the exact referenced `state.json` field and encode the complete list
as `json-list-utf8-v1`: preserve list order, emit a JSON array with comma/colon
separators and no insignificant whitespace, emit UTF-8 non-ASCII code points
directly, and leave `/` unescaped. Encode quote as `\"`, backslash as `\\`,
backspace as `\b`, tab as `\t`, LF as `\n`, form feed as `\f`, and CR as `\r`;
encode every other U+0000--U+001F control as a lowercase `\u00xx` escape.
Verify the marker's SHA-256 before reconstructing omitted history. `aoi doctor
--task <id> --json` independently checks the marker and retained tail against
current state through the fixed `AOI-CHECKPOINT-HISTORY-V1` machine block
before free-form task text. Marker-looking lines inside objectives or history
entries have no authority.

## Recover an over-limit historical checkpoint

An older long-lived task may have complete state whose first compact checkpoint
projection exceeds 32 KiB. Stop cooperative writers, preserve an exact
repo-external backup, and upgrade through the reviewed AOI installation route
before retrying the ordinary command:

```bash
aoi checkpoint --task <id> --next-action "<same exact next action>" --json
aoi doctor --task <id> --json
```

The fixed runtime may use the digest-bound stage-two projection for append-only
fact, decision, and rejected-path history. It does not mutate or delete that
history. Optional recent tails shrink before required detail can cross the
ceiling. A failed retry leaves both state and the previous checkpoint unchanged.
If the marker-only retry still exceeds the ceiling, required active authority
is itself too large; do not hand-edit state or raise the limit ad hoc. Reduce
that authority only through truthful lifecycle operations or split future work
into a separately governed task.

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
