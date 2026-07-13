# Security and trust model

AOI is a cooperative governance layer, not a sandbox.

- Claims do not prevent unrelated processes from editing files.
- Codex hooks are optional, fail-open procedural guardrails.
- AOI does not authenticate a human or model identity; actor fields are
  auditable workflow assertions supplied by the controlling process.
- External commands and generated skills can execute with the invoking user's
  permissions. Review them before execution and use OS-level isolation where
  appropriate.
- `.aoi/` may contain task details, command lines, paths, evidence references,
  and session identifiers. AOI creates it as private state where the platform
  supports permissions and adds it to `.gitignore`; do not publish it.
- `aoi.toml` is trusted project policy. Tasks bind its SHA-256 and fail closed
  on drift, but the file itself must still be code-reviewed.

AOI refuses filesystem root, the user's home directory, symlinked explicit
roots, unsafe state directories, traversal in structured locks, and unknown
configuration keys. These checks reduce accidental damage; they do not defend
against a malicious process running under the same OS account.

When the public GitHub repository is available, report vulnerabilities through
GitHub's private vulnerability reporting feature. Do not include real secrets,
private task state, or exploit payloads in a public issue.
