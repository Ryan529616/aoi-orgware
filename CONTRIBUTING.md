# Contributing to AOI

AOI is an alpha-stage, pure-stdlib Python package. Contributions are welcome,
with two non-negotiables: evidence discipline and additive state schemas.

## Ground rules

- **Evidence over claims.** A change that touches governance behavior needs a
  test that pins the behavior adversarially (try to defeat your own gate).
  Never label a test you did not run as passing.
- **Additive-only state.** Live projects carry `.aoi/` state produced by older
  versions. New fields must be optional; readers must tolerate their absence.
  Schema-set validations must accept both the legacy and the new shape.
- **Fail closed, stay fail-open at the hooks.** CLI gates refuse on ambiguity;
  lifecycle hooks must never block a user's session on a harness defect.
- **No new runtime dependencies.** The package is deliberately stdlib-only.

## Development setup

```bash
git clone https://github.com/Ryan529616/aoi-orgware
cd aoi-orgware
python -m pytest tests/ -q        # no install needed; tests insert src/
```

Python 3.11+ and git are required. The suite is subprocess-heavy and takes
~15 minutes; scope your loop with a single test file first, e.g.
`python -m pytest tests/test_dispatch_protocol.py -q`.

## Architecture constraints (enforced by tests)

- New `aoi` subcommands live in `src/aoi_orgware/commands/<family>.py` with a
  `register_*_commands` function and a frozen `*CmdServices` dataclass;
  `tests/test_architecture_boundaries.py` rejects new `cmd_*` definitions in
  `cli.py` and any `commands/` module importing `cli`.
- `docs/POLICY.md` must stay byte-identical to
  `src/aoi_orgware/resources/policy.md` (test-pinned).
- Windows and POSIX are both first-class; path handling goes through the
  helpers in `harnesslib.py`.

## Pull requests

- Base on current `main`; keep one logical change per PR.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- CI (Linux + Windows, Python 3.11–3.13, installed-artifact jobs) must be
  green.
- Security-sensitive reports: see `SECURITY.md` — do not open a public issue.
