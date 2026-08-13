import type {
  DashboardAttentionV1,
  DashboardNodeV1,
  DashboardSnapshotV1,
  NodeStatus
} from "./contracts";

const departments = [
  ["rtl", "RTL Systems", "Hardware architecture and synthesizable implementation"],
  ["dv", "Design Verification", "Independent verification and adversarial coverage"],
  ["pd", "Physical Design", "Synthesis, timing, implementation and signoff evidence"],
  ["platform", "Platform", "Provider runtime, ledger and durable orchestration"],
  ["research", "Research", "Methods, experiments and claim-to-evidence alignment"]
] as const;

const work = [
  "Provider lifecycle projection",
  "Execution identity audit",
  "Token telemetry correlation",
  "Dashboard read model",
  "History reconstruction",
  "Artifact lineage review",
  "Path identity verification",
  "Runtime replay invariants",
  "External job observation",
  "Coverage gap analysis",
  "Checkpoint consistency",
  "Model routing validation"
];

const statuses: NodeStatus[] = [
  "active",
  "active",
  "waiting",
  "completed",
  "idle",
  "unknown",
  "blocked",
  "needs_user",
  "cancelled"
];

function seeded(index: number): number {
  const value = Math.sin(index * 91.173 + 17.77) * 43758.5453;
  return value - Math.floor(value);
}

function executionStatus(index: number, cursor: number): NodeStatus {
  return statuses[(index * 5 + cursor) % statuses.length];
}

function makeNodes(cursor: number, count: number): DashboardNodeV1[] {
  const nodes: DashboardNodeV1[] = [
    {
      id: "org:chief",
      parentId: null,
      name: "Aster",
      role: "Chief",
      objective: "Coordinate an evidence-bounded AI engineering company",
      kind: "chief",
      status: "active",
      engineeringStatus: "active",
      runtimeStatus: "running",
      coverageStatus: "complete",
      effectStatus: "none",
      organizationStatus: "active",
      department: null,
      provider: "openai",
      model: "gpt-5.6-sol",
      reason: null,
      evidenceClass: "system_evidence",
      usageTokens: 184920,
      projectionSource: "test_fixture",
      orphanReason: null
    }
  ];

  departments.forEach(([id, name, objective], index) => {
    nodes.push({
      id: `org:${id}`,
      parentId: "org:chief",
      name,
      role: "Department",
      objective,
      kind: "department",
      status: index === 3 ? "active" : index === 2 ? "waiting" : "idle",
      engineeringStatus:
        index === 3 ? "active" : index === 2 ? "waiting" : "idle",
      runtimeStatus: index === 3 ? "running" : "unknown",
      coverageStatus: "complete",
      effectStatus: "none",
      organizationStatus: index === 2 ? "parked" : "active",
      department: id,
      provider: null,
      model: null,
      reason: index === 3 ? null : "durable department without active carrier",
      evidenceClass: "system_evidence",
      usageTokens: null,
      projectionSource: "test_fixture",
      orphanReason: null
    });
  });

  const boundedCount = Math.max(18, Math.min(count, 500));
  for (let index = 0; index < boundedCount - departments.length - 1; index += 1) {
    const department = departments[index % departments.length];
    const status = executionStatus(index, cursor);
    const parent =
      index < departments.length * 2
        ? `org:${department[0]}`
        : `exec:${String(index % (departments.length * 2)).padStart(3, "0")}`;
    nodes.push({
      id: `exec:${String(index).padStart(3, "0")}`,
      parentId: parent,
      name: `${work[index % work.length]} ${String(Math.floor(index / work.length) + 1).padStart(2, "0")}`,
      role: index % 7 === 0 ? "Reviewer" : index % 5 === 0 ? "Explorer" : "Engineer",
      objective: work[index % work.length],
      kind: index % 11 === 0 ? "job" : "execution",
      status,
      engineeringStatus:
        status === "completed"
          ? "completed"
          : status === "cancelled"
            ? "cancelled"
            : status === "blocked" || status === "needs_user"
              ? "blocked"
              : status === "waiting"
                ? "waiting"
                : status === "idle"
                  ? "idle"
                  : status === "active"
                    ? "active"
                    : "unknown",
      runtimeStatus:
        status === "cancelled" || status === "completed"
          ? "stopped"
          : status === "unknown"
            ? "unknown"
          : status === "idle"
              ? "unknown"
              : status === "active"
                ? "running"
                : "telemetry_silent",
      coverageStatus: status === "unknown" ? "degraded" : "complete",
      effectStatus: status === "blocked" ? "effect_unknown" : "none",
      organizationStatus: null,
      department: department[0],
      provider: status === "idle" ? null : index % 3 === 0 ? "openai" : "codex",
      model: status === "idle" ? null : index % 3 === 0 ? "gpt-5.6-sol" : "gpt-5.6-terra",
      reason:
        status === "blocked"
          ? "waiting for an exact upstream receipt"
          : status === "needs_user"
            ? "user disposition required"
            : status === "unknown"
              ? "provider observation is incomplete"
              : status === "cancelled"
                ? "execution was cancelled before completion"
              : null,
      evidenceClass:
        status === "completed"
          ? "runtime"
          : status === "cancelled"
            ? "runtime"
          : status === "unknown"
            ? "engineering_inference"
            : "compile_acceptance",
      usageTokens: status === "idle" ? null : Math.round(1800 + seeded(index) * 42000),
      projectionSource: "test_fixture",
      orphanReason: null
    });
  }
  return nodes;
}

function makeAttention(nodes: DashboardNodeV1[]): DashboardAttentionV1[] {
  const candidates = nodes.filter((node) =>
    ["blocked", "needs_user", "unknown"].includes(node.status)
  );
  return candidates.slice(0, 9).map((node, index) => ({
    id: `attention:${index}`,
    nodeId: node.id,
    severity:
      node.status === "blocked" ? "critical" : node.status === "needs_user" ? "warning" : "info",
    kind:
      node.status === "needs_user"
        ? "needs_user"
        : node.status === "blocked"
          ? "blocked"
          : "unknown",
    title:
      node.status === "needs_user"
        ? "User decision required"
        : node.status === "blocked"
          ? "Execution blocked"
          : "Observation incomplete",
    detail: `${node.name} · ${node.reason ?? "No bounded reason is available."}`
  }));
}

export function makeFixtureSnapshot(cursor = 42, count = 72): DashboardSnapshotV1 {
  const nodes = makeNodes(cursor, count);
  return {
    schemaVersion: 1,
    companyId: "fixture:aoi-company-os",
    companyName: "AOI Systems Company",
    cursor,
    generatedAt: new Date(Date.UTC(2026, 6, 28, 6, cursor % 60, 0)).toISOString(),
    completeness: cursor % 5 === 0 ? "partial" : "complete",
    mode: cursor === 42 ? "live" : "historical",
    nodes,
    attention: makeAttention(nodes)
  };
}

export const fixtureHistory = [36, 38, 40, 41, 42].map((cursor) =>
  makeFixtureSnapshot(cursor, 72)
);
