# Security and trust model

AOI is a cooperative governance layer, not a sandbox.

- Claims do not prevent unrelated processes from editing files.
- Codex hooks are optional, fail-open procedural guardrails.
- AOI does not authenticate a human or model identity; actor fields are
  auditable workflow assertions supplied by the controlling process.
- A session binding proves association with a task, not that the caller is the
  Chief or is authorized to exercise Chief authority. Enforce identity and
  authorization outside AOI when the controlling processes are not mutually
  trusted.
- External commands and generated skills can execute with the invoking user's
  permissions. Review them before execution and use OS-level isolation where
  appropriate.
- `.aoi/` may contain task details, command lines, paths, evidence references,
  and session identifiers. AOI creates it as private state where the platform
  supports permissions and adds it to `.gitignore`; do not publish it.
- Native Windows does not let AOI prove a `0700`/`0600`-equivalent DACL through
  the Python standard library. `doctor` reports this as an unverified ACL
  boundary, and private pilot files require explicit acknowledgement.
- A state tree is permanently tagged for either POSIX/WSL `flock` or native
  Windows `msvcrt` locking. Never alternate or concurrently write the same
  `.aoi/` tree from both environments. UNC/network shares and case-sensitive
  NTFS are outside the supported native-Windows boundary.
- Existing repo/host tree claims are recursively checked for filesystem
  aliases. AOI rejects nested symlinks, junctions, hard-linked files, special
  nodes, and trees beyond the bounded scan limit. This fail-closed audit runs
  when claims are issued and released; it cannot prevent unrelated processes
  from changing a tree between those checkpoints.
- `aoi.toml` is trusted project policy. Tasks bind its SHA-256 and fail closed
  on drift, but the file itself must still be code-reviewed.
- Closed-alpha records are not execution traces. Do not put `.aoi/`, prompts,
  diffs, absolute paths, commands, logs, commit IDs, credentials, identity, or
  private project details in them. `aoi pilot-validate` rejects common leakage
  patterns, including several common provider credentials, but it is a
  versioned denylist rather than a complete secret scanner and cannot prove
  anonymity; human review is still required.
- Pilot free-text feedback and withdrawal linkage are private by default.
  Coordinator-sharing and aggregate consent are separate permissions. Closed-
  alpha individual run records are never public; respect withdrawal before the
  announced analysis freeze.

AOI refuses filesystem root, the user's home directory, symlinked explicit
roots, unsafe state directories, traversal in structured locks, and unknown
configuration keys. These checks reduce accidental damage; they do not defend
against a malicious process running under the same OS account.

When the public GitHub repository is available, report vulnerabilities through
GitHub's private vulnerability reporting feature. Do not include real secrets,
private task state, or exploit payloads in a public issue.
