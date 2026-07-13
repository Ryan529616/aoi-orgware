# Sub-agent packet — {{PACKET_ID}}

- Parent task: `{{TASK_ID}}`
- Role / model tier: `{{AGENT_ROLE}}` / `{{MODEL_TIER}}`
- Objective: {{OBJECTIVE}}
- Scope: {{SCOPE}}
- Locks owned by root: {{LOCKS}}
- Deliverable: {{DELIVERABLE}}
- Verification: {{VALIDATION}}

## Required context

{{READ_FIRST}}

## Contract

Stay inside scope. Do not write harness state, claim completion, launch an
unrequested long job, or paste raw logs. Return conclusion, evidence paths,
files touched, checks run, risks, and one recommended next action.
