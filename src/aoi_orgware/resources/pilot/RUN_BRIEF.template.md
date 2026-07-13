# Measured run brief

- variant: `<single|aoi>`
- participant_id: `<opaque-id>`
- task_pair_id: `<opaque-pair-id>`
- task_order: `<1|2>`
- task_id: `<opaque-task-id>`
- baseline_id: `<opaque-baseline-id>`
- oracle_id: `<opaque-oracle-id>`
- time_limit_minutes: `<integer>`
- runtime_label: `<opaque-runtime-label>`
- model_label: `<opaque-model-label>`
- tool_profile: `<opaque-tool-profile>`
- package_sha256: `<exact-wheel-sha256>`
- control_profile_sha256: `<sha256-of-context-dependencies-stop-and-intervention-policy>`

## Task

`<bounded task specification>`

## Stop condition

`<fixed condition shared across variants>`

## External oracle

`<private exact oracle instruction; remove sensitive paths before sharing>`
