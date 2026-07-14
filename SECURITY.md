# Security and trust model

AOI is a cooperative governance layer, not a sandbox.

- Claims do not prevent unrelated processes from editing files.
- Codex hooks are optional procedural guardrails. Protocol v6 may consume one
  pre-authorized packet arm or append a task-local unmanaged-start incident;
  every other hook failure remains fail-open.
- `SubagentStart` runs after Codex creates the agent. AOI can attest that an arm
  predated its observation and can instruct an unarmed agent to stop, but it
  cannot claim that the hook prevented or terminated the spawn.
- A schema-v5 manual fallback also requires a prior arm. This prevents normal
  post-hoc ready-to-dispatched registration; expiry, Chief epoch, plan, packet,
  topology, lane/Steward, and skill authority are revalidated at consumption.
  Native-v5 packet contracts also carry an origin marker so state-only schema
  downgrade cannot invoke the v4 migration exception, and native policy-v2
  tasks carry an independent non-legacy provenance bit. These remain cooperative
  state evidence and cannot prove when an external runtime actually began work.
- AOI does not authenticate a human or model identity; actor fields are
  auditable workflow assertions supplied by the controlling process.
- A Chief lease fences cooperative AOI CLI mutations by session assertion,
  monotonic epoch, high-entropy token digest, and expiry. It does not
  authenticate a human/model identity or prevent direct source, Git, EDA, or
  state writes. Enforce identity and authorization outside AOI when controlling
  processes are not mutually trusted.
- Chief plaintext tokens are never stored in shared AOI state or printed by
  acquire/takeover. They live in a repo-external user credential store. POSIX
  validates owner-only credential directories/files and safe ancestors; native
  Windows encrypts the token with CurrentUser DPAPI. A process under the same OS
  account may still use that account's credential, so this is not a sandbox.
- `AOI_CHIEF_TOKEN` and `--chief-token` are deprecated compatibility inputs.
  AOI removes Chief environment values before child processes, but command-line
  arguments, shell history, transcripts, crash dumps, and same-user process
  inspection remain exposure paths. Prefer the credential-file reference.
- Live takeover is break-glass cooperation, not authentication. It requires
  expected-epoch CAS, `--force-live`, and a non-empty audit reason; protect the
  invoking OS account and review the transition log.
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
- WSL requires a native filesystem or a mount that reliably exposes POSIX mode
  metadata. A metadata-less DrvFs mount will normally fail AOI's private-mode
  checks; this is deliberate fail-closed behavior, not permission emulation.
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
- Standalone pilot writers scan every destination before writing. A destination
  inside an initialized AOI project requires that exact project's Chief lease;
  project roots, managed state, and multi-project write sets are refused even
  with `--force`. AOI also recognizes an orphan managed-state tree when
  `aoi.toml` is missing, revalidates the target immediately before each
  publication, and uses atomic no-replace publication unless `--force` was
  explicit. These are cooperative path checks, not an OS transaction against a
  hostile same-user process.

AOI refuses filesystem root, the user's home directory, symlinked explicit
roots, dangerous credential/output roots, unsafe state directories, traversal
in structured locks, and unknown configuration keys. These checks reduce
accidental damage; they do not defend against a malicious process running under
the same OS account.

When the public GitHub repository is available, report vulnerabilities through
GitHub's private vulnerability reporting feature. Do not include real secrets,
private task state, or exploit payloads in a public issue.
