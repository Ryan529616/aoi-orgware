## What & why

<!-- One logical change. Link the issue if one exists. -->

## Evidence

- [ ] Tests added/updated that adversarially pin the new behavior
- [ ] `python -m pytest tests/ -q` green locally (state OS + Python)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] State schema changes are additive-only (legacy `.aoi/` state stays valid)
- [ ] No new runtime dependencies

## Boundaries

<!-- What this change does NOT cover; known residual risks. -->
