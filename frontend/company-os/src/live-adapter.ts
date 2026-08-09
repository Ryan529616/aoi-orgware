import type {
  CoverageStatusV1,
  DashboardAttentionV1,
  DashboardNodeV1,
  DashboardSnapshotV1,
  EffectStatusV1,
  EngineeringStatusV1,
  NodeStatus,
  RuntimeStatusV1
} from "./contracts";

export class CompanySnapshotError extends Error {}

type JsonRecord = Record<string, unknown>;

const ENGINEERING = new Set<EngineeringStatusV1>([
  "active",
  "idle",
  "waiting",
  "blocked",
  "completed",
  "cancelled",
  "unknown"
]);
const RUNTIME = new Set<RuntimeStatusV1>([
  "running",
  "telemetry_silent",
  "confirmed_lost",
  "stopped",
  "unknown"
]);
const COVERAGE = new Set<CoverageStatusV1>(["complete", "degraded", "unknown"]);
const EFFECT = new Set<EffectStatusV1>([
  "none",
  "failed_known",
  "effect_unknown",
  "unknown"
]);

function fail(message: string): never {
  throw new CompanySnapshotError(message);
}

function record(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value as JsonRecord;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  return value;
}

function optionalText(value: unknown, label: string): string | null {
  if (value === null || value === undefined) return null;
  return text(value, label);
}

function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function enumValue<T extends string>(
  value: unknown,
  values: ReadonlySet<T>,
  label: string
): T {
  if (typeof value !== "string" || !values.has(value as T)) {
    fail(`${label} has an unsupported value`);
  }
  return value as T;
}

function observationReason(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const item = record(value, "execution.observation");
  return optionalText(item.reason, "execution.observation.reason");
}

function displayStatus(
  engineering: EngineeringStatusV1,
  needsUser: boolean
): NodeStatus {
  if (needsUser) return "needs_user";
  return engineering;
}

function frozenNode(value: DashboardNodeV1): DashboardNodeV1 {
  return Object.freeze(value);
}

function chiefNode(companyId: string, company: JsonRecord): DashboardNodeV1 {
  const chief = record(company.chief ?? {}, "snapshot.data.company.chief");
  const term = chief.term === null || chief.term === undefined
    ? null
    : record(chief.term, "snapshot.data.company.chief.term");
  const chiefId = term ? optionalText(term.chief_id, "chief.term.chief_id") : null;
  const organizationStatus = term
    ? optionalText(term.state, "chief.term.state")
    : null;
  return frozenNode({
    id: chiefId ? `chief:${chiefId}` : `company:${companyId}:chief`,
    parentId: null,
    name: "Logical Chief",
    role: "chief",
    objective: "Company authority anchor; runtime state is not inferred.",
    kind: "chief",
    status: "unknown",
    engineeringStatus: "unknown",
    runtimeStatus: "unknown",
    coverageStatus: "unknown",
    effectStatus: "unknown",
    organizationStatus,
    department: null,
    provider: null,
    model: null,
    reason: chiefId ? null : "chief_term_unavailable",
    evidenceClass: null,
    usageTokens: null,
    projectionSource: chiefId ? "company_chief_term" : "ui_company_anchor",
    orphanReason: null
  });
}

function departmentNodes(
  departmentsValue: unknown,
  chiefId: string
): DashboardNodeV1[] {
  const seen = new Set<string>();
  return array(departmentsValue, "snapshot.data.departments").map((value, index) => {
    const item = record(value, `snapshot.data.departments[${index}]`);
    const departmentId = text(item.department_id, `departments[${index}].department_id`);
    const id = `department:${departmentId}`;
    if (seen.has(id)) fail(`duplicate department identity: ${departmentId}`);
    seen.add(id);
    const lifecycle = optionalText(
      item.lifecycle_state ?? item.status,
      `departments[${index}].lifecycle_state`
    );
    const reason = optionalText(
      item.lifecycle_reason,
      `departments[${index}].lifecycle_reason`
    );
    return frozenNode({
      id,
      parentId: chiefId,
      name: departmentId.toUpperCase(),
      role: "department",
      objective: "Durable department identity; activity is shown on execution nodes.",
      kind: "department",
      status: "unknown",
      engineeringStatus: "unknown",
      runtimeStatus: "unknown",
      coverageStatus: "unknown",
      effectStatus: "unknown",
      organizationStatus: lifecycle,
      department: departmentId,
      provider: null,
      model: null,
      reason,
      evidenceClass: null,
      usageTokens: null,
      projectionSource: "department_identity",
      orphanReason: null
    });
  });
}

function executionNode(value: unknown, label: string): DashboardNodeV1 {
  const item = record(value, label);
  const id = text(item.execution_id, `${label}.execution_id`);
  const engineering = enumValue(
    item.engineering_status,
    ENGINEERING,
    `${label}.engineering_status`
  );
  const runtime = enumValue(
    item.runtime_status,
    RUNTIME,
    `${label}.runtime_status`
  );
  const coverage = item.coverage_status === undefined
    ? "unknown"
    : enumValue(item.coverage_status, COVERAGE, `${label}.coverage_status`);
  const effect = item.effect_status === undefined
    ? "unknown"
    : enumValue(item.effect_status, EFFECT, `${label}.effect_status`);
  const rawKind = text(item.execution_kind, `${label}.execution_kind`);
  const orphanReason = optionalText(item.orphan_reason, `${label}.orphan_reason`);
  const waitReason = optionalText(item.wait_reason, `${label}.wait_reason`);
  const needsUser = item.needs_user === true || (
    Array.isArray(item.attention_overlays) && item.attention_overlays.includes("needs_user")
  );
  const childrenCount = item.descendant_count;
  if (
    childrenCount !== undefined && childrenCount !== null &&
    (typeof childrenCount !== "number" || !Number.isSafeInteger(childrenCount) || childrenCount < 0)
  ) {
    fail(`${label}.descendant_count is invalid`);
  }
  return frozenNode({
    id,
    parentId: optionalText(item.parent_execution_id, `${label}.parent_execution_id`),
    name: optionalText(item.display_name, `${label}.display_name`) ?? id,
    role: optionalText(item.role, `${label}.role`) ?? rawKind,
    objective: optionalText(item.objective, `${label}.objective`) ?? "No bounded objective projected.",
    kind: rawKind.endsWith("job") || rawKind === "job" ? "job" : "execution",
    status: displayStatus(engineering, needsUser),
    engineeringStatus: engineering,
    runtimeStatus: runtime,
    coverageStatus: coverage,
    effectStatus: effect,
    organizationStatus: null,
    department: optionalText(item.department_id, `${label}.department_id`),
    provider: optionalText(item.provider, `${label}.provider`),
    model: optionalText(item.model, `${label}.model`),
    reason: orphanReason ?? waitReason ?? observationReason(item.observation),
    evidenceClass: null,
    usageTokens: null,
    projectionSource: optionalText(item.projection_source, `${label}.projection_source`) ?? "execution_node",
    orphanReason,
    ...(typeof childrenCount === "number" ? { childrenCount } : {})
  });
}

function executionNodes(executionValue: unknown): DashboardNodeV1[] {
  const execution = record(executionValue, "snapshot.data.execution");
  const primary = array(execution.nodes, "snapshot.data.execution.nodes");
  const orphanValues = array(execution.orphans ?? [], "snapshot.data.execution.orphans");
  const byId = new Map<string, DashboardNodeV1>();
  primary.forEach((value, index) => {
    const node = executionNode(value, `execution.nodes[${index}]`);
    if (byId.has(node.id)) fail(`duplicate execution identity: ${node.id}`);
    byId.set(node.id, node);
  });
  orphanValues.forEach((value, index) => {
    const orphan = executionNode(value, `execution.orphans[${index}]`);
    const current = byId.get(orphan.id);
    if (current) {
      byId.set(orphan.id, frozenNode({
        ...current,
        orphanReason: orphan.orphanReason,
        reason: orphan.orphanReason ?? current.reason,
        projectionSource: orphan.projectionSource
      }));
    } else {
      byId.set(orphan.id, orphan);
    }
  });
  return [...byId.values()].sort((left, right) => left.id.localeCompare(right.id));
}

function severity(value: unknown, label: string): DashboardAttentionV1["severity"] {
  if (value === "critical" || value === "warning" || value === "info") return value;
  fail(`${label} has an unsupported severity`);
}

function attentionKind(category: string): DashboardAttentionV1["kind"] {
  if (category.includes("effect")) return "effect";
  if (category.includes("orphan")) return "orphan";
  if (category.includes("coverage")) return "coverage";
  if (category.includes("needs_user")) return "needs_user";
  if (category.includes("block") || category.includes("failed")) return "blocked";
  return "unknown";
}

function attentionItems(alertsValue: unknown, warnings: string[]): DashboardAttentionV1[] {
  const result: DashboardAttentionV1[] = [];
  const alerts = record(alertsValue ?? {}, "snapshot.data.alerts");
  array(alerts.alerts ?? [], "snapshot.data.alerts.alerts").forEach((value, index) => {
    const item = record(value, `alerts[${index}]`);
    if (item.state !== undefined && item.state !== "open") return;
    const id = text(item.alert_id, `alerts[${index}].alert_id`);
    const category = optionalText(item.category, `alerts[${index}].category`) ?? "unknown";
    const reason = optionalText(item.orphan_reason ?? item.reason, `alerts[${index}].reason`);
    result.push(Object.freeze({
      id,
      nodeId: optionalText(item.execution_id, `alerts[${index}].execution_id`),
      severity: severity(item.severity ?? "warning", `alerts[${index}].severity`),
      kind: attentionKind(category),
      title: category.replaceAll("_", " "),
      detail: reason ?? "Open company attention has no bounded detail."
    }));
  });
  array(alerts.needs_user ?? [], "snapshot.data.alerts.needs_user").forEach((value, index) => {
    const item = record(value, `needs_user[${index}]`);
    if (item.state !== undefined && !["open", "needs_user", "pending"].includes(String(item.state))) return;
    const id = text(item.item_id, `needs_user[${index}].item_id`);
    const detail = optionalText(
      item.question_summary ?? item.question_summary_reason ?? item.reason,
      `needs_user[${index}].detail`
    );
    result.push(Object.freeze({
      id: `needs-user:${id}`,
      nodeId: optionalText(
        item.execution_id ?? item.origin_execution_id,
        `needs_user[${index}].execution_id`
      ),
      severity: "warning",
      kind: "needs_user",
      title: "Needs user",
      detail: detail ?? "A managed item requires user input."
    }));
  });
  [...new Set(warnings)].sort().forEach((warning, index) => {
    result.push(Object.freeze({
      id: `snapshot-warning:${index}`,
      nodeId: null,
      severity: "warning",
      kind: "coverage",
      title: "Snapshot degraded",
      detail: warning
    }));
  });
  if (new Set(result.map((item) => item.id)).size !== result.length) {
    fail("snapshot attention identities are not unique");
  }
  return result.sort((left, right) => left.id.localeCompare(right.id));
}

export function adaptCompanySnapshot(
  value: unknown,
  mode: DashboardSnapshotV1["mode"]
): DashboardSnapshotV1 {
  const envelope = record(value, "snapshot");
  if (envelope.schema_version !== 1) fail("snapshot.schema_version must be 1");
  const companyId = text(envelope.company_id, "snapshot.company_id");
  const cursor = integer(envelope.cursor, "snapshot.cursor");
  const generatedAt = text(envelope.generated_at, "snapshot.generated_at");
  const completeness = enumValue(
    envelope.completeness,
    new Set<DashboardSnapshotV1["completeness"]>(["complete", "partial", "unknown"]),
    "snapshot.completeness"
  );
  const warnings = array(envelope.warnings, "snapshot.warnings").map((item, index) =>
    text(item, `snapshot.warnings[${index}]`)
  );
  const data = record(envelope.data, "snapshot.data");
  const company = record(data.company, "snapshot.data.company");
  const chief = chiefNode(companyId, company);
  const nodes = [
    chief,
    ...departmentNodes(data.departments ?? [], chief.id),
    ...executionNodes(data.execution)
  ];
  if (new Set(nodes.map((node) => node.id)).size !== nodes.length) {
    fail("snapshot node identities are not unique");
  }
  return Object.freeze({
    schemaVersion: 1,
    companyId,
    companyName: companyId,
    cursor,
    generatedAt,
    completeness,
    mode,
    nodes: Object.freeze(nodes) as unknown as DashboardNodeV1[],
    attention: Object.freeze(attentionItems(data.alerts, warnings)) as unknown as DashboardAttentionV1[]
  });
}
