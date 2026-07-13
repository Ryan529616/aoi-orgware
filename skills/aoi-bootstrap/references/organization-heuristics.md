# Organization drafting heuristics

Draft the smallest organization justified by current evidence. Departments are
stable responsibility and reporting lanes; they are not always-running agents.

## Logical control plane

Every AOI profile has two logical responsibilities even when only one agent is
active:

- **Chief/root** owns formal technical arbitration, architecture, priorities,
  and user-facing synthesis.
- **Steward** validates versions and contracts, maintains the system-of-record,
  assembles bounded briefs, distributes directives, and records acknowledgement
  and verification. Steward does not decide which technical position is right.

Keep a `steward` department in the initial profile unless the project uses a
clearly documented equivalent name. Chief/root is an authority role, not a
department that must appear in `organization.departments`.

## Specialist lanes

Create a lane only when the repository or user requirements show a stable
boundary with distinct evidence, tools, or failure modes. Prefer one to four
specialist lanes at bootstrap.

- A small single-runtime codebase usually needs `implementation`,
  `verification`, and `steward`.
- Add `operations` only when deployment, infrastructure, remote runners, or
  external systems are genuinely in scope.
- A multi-domain project may replace generic implementation with named lanes
  such as `frontend`, `backend`, `security`, or `numeric`, but avoid mirroring
  every directory as a department.
- Do not add Capacity Planning or Improvement/R&D as always-running execution
  departments. Treat them as periodic governance reviews and temporary projects
  until workload data justifies persistent responsibility.

## Execution topology

The organization can be stable while per-task execution changes:

- `single`: one lane for tightly coupled or sequential work;
- `centralized_parallel`: independent evidence gathering across lanes;
- `hybrid`: controlled cross-lane working session with conclusions and dissent
  written back to the system-of-record.

Direct specialist discussion may improve technical bandwidth, but it may not
privately mutate baselines, decisions, claims, or directives.

## Evidence and closure

Select evidence categories that the project can actually produce. Keep evidence
levels distinct: static checks, compile acceptance, runtime tests, external
runtime, system evidence, and engineering inference are not interchangeable.

An implementation claim is not completion. AOI closure should follow:

`implemented -> evidence submitted -> independently verified -> resolved`

Use an independent reviewer for high-risk or cross-domain work. Preserve
dissent and raw evidence pointers so a bounded steward summary cannot erase a
material conflict.

## Policy defaults

- Keep `.aoi/` high risk.
- If `state_dir` is customized, keep that exact directory high risk and require
  it to be absent or empty before initialization.
- Add deployment, infrastructure, migrations, security, credentials, or other
  irreversible surfaces only when repo evidence supports them.
- Require source and runner receipts for external execution; add config or
  dependencies when reproducibility depends on them.
- Keep hooks and legacy compatibility disabled by default.
- Use `.aoi` as the state directory unless the user approves a different path.

## Questions that require the user

Ask before finalizing when the answer changes:

- project goal or completion criteria;
- repo boundary in a monorepo;
- acceptable token/time budget;
- irreversible or external actions;
- risk tolerance and required human approvals;
- hook installation or trust;
- migration from existing AOI state.

Do not ask about choices that current repository evidence already answers and
that remain reversible within one lane.
