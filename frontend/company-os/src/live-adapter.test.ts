import { describe, expect, it } from "vitest";
import { adaptCompanySnapshot, CompanySnapshotError } from "./live-adapter";

function rawSnapshot() {
  return {
    schema_version: 1,
    company_id: "company-live",
    cursor: 9,
    generated_at: "2026-08-09T00:00:00Z",
    completeness: "partial",
    warnings: ["provider_adapters_not_yet_connected"],
    data: {
      company: {
        chief: { term: { chief_id: "chief-1", state: "active" } }
      },
      departments: [
        {
          department_id: "rtl",
          lifecycle_state: "parked",
          lifecycle_reason: "department_parked"
        }
      ],
      execution: {
        nodes: [
          {
            execution_id: "exec-agent",
            parent_execution_id: null,
            execution_kind: "agent",
            display_name: "RTL worker",
            role: "worker",
            objective: "Inspect one exact source cut",
            engineering_status: "active",
            runtime_status: "telemetry_silent",
            department_id: "rtl",
            provider: "codex",
            model: null,
            wait_reason: null,
            observation: { state: "unknown", reason: "provider_signal_missing" },
            projection_source: "execution_node_v1",
            evidence_ids: ["evidence-a", "evidence-b"],
            usage_cursor: 44
          },
          {
            execution_id: "legacy-job",
            parent_execution_id: "exec-agent",
            execution_kind: "legacy_job",
            display_name: "Legacy job",
            role: "legacy_job",
            objective: null,
            engineering_status: "blocked",
            runtime_status: "stopped",
            coverage_status: "degraded",
            effect_status: "failed_known",
            department_id: null,
            provider: "unknown",
            model: null,
            orphan_reason: null,
            observation: {
              state: "known",
              reason: "registered_job_process_nonzero_exit_reconciled"
            },
            projection_source: "legacy_bridge_terminal_receipt"
          }
        ],
        orphans: [
          {
            execution_id: "legacy-job",
            parent_execution_id: "exec-agent",
            execution_kind: "legacy_job",
            display_name: "Legacy job",
            role: "legacy_job",
            objective: null,
            engineering_status: "blocked",
            runtime_status: "stopped",
            coverage_status: "degraded",
            effect_status: "failed_known",
            department_id: null,
            provider: "unknown",
            model: null,
            orphan_reason: "packet_parent_unjoined",
            observation: {
              state: "known",
              reason: "registered_job_process_nonzero_exit_reconciled"
            },
            projection_source: "legacy_bridge_terminal_receipt"
          }
        ]
      },
      alerts: {
        alerts: [
          {
            alert_id: "alert-effect",
            execution_id: "legacy-job",
            state: "open",
            severity: "critical",
            category: "effect_unknown",
            reason: "manual_reconciliation_required"
          }
        ],
        needs_user: [
          {
            item_id: "question-1",
            state: "open",
            origin_execution_id: "exec-agent",
            question_summary: "Choose a bounded disposition"
          }
        ]
      },
      usage: {
        counting_semantics: "non_additive_cumulative",
        counter_samples: [{ total_token_vector: { total: 999_999 } }]
      },
      evidence: {
        records: [{ evidence_id: "evidence-a", class: "runtime" }]
      },
      jobs: []
    }
  };
}

describe("production snapshot adapter", () => {
  it("preserves raw truth axes and never invents usage or evidence reduction", () => {
    const snapshot = adaptCompanySnapshot(rawSnapshot(), "live");
    expect(snapshot.mode).toBe("live");
    expect(snapshot.nodes.map((node) => node.id)).toEqual([
      "chief:chief-1",
      "department:rtl",
      "exec-agent",
      "legacy-job"
    ]);
    const agent = snapshot.nodes.find((node) => node.id === "exec-agent")!;
    expect(agent.engineeringStatus).toBe("active");
    expect(agent.runtimeStatus).toBe("telemetry_silent");
    expect(agent.coverageStatus).toBe("unknown");
    expect(agent.effectStatus).toBe("unknown");
    expect(agent.usageTokens).toBeNull();
    expect(agent.evidenceClass).toBeNull();
    const job = snapshot.nodes.find((node) => node.id === "legacy-job")!;
    expect([
      job.engineeringStatus,
      job.runtimeStatus,
      job.coverageStatus,
      job.effectStatus,
      job.orphanReason
    ]).toEqual(["blocked", "stopped", "degraded", "failed_known", "packet_parent_unjoined"]);
    expect(snapshot.attention.map((item) => item.kind)).toEqual([
      "effect",
      "needs_user",
      "coverage"
    ]);
  });

  it("keeps cancelled engineering distinct from stopped runtime", () => {
    const value = rawSnapshot();
    const node = value.data.execution.nodes[0];
    node.engineering_status = "cancelled";
    node.runtime_status = "stopped";
    const projected = adaptCompanySnapshot(value, "historical").nodes.find(
      (candidate) => candidate.id === "exec-agent"
    )!;
    expect(projected.status).toBe("cancelled");
    expect(projected.engineeringStatus).toBe("cancelled");
    expect(projected.runtimeStatus).toBe("stopped");
  });

  it("rejects duplicate identity, unsupported raw status and bool cursor", () => {
    const duplicate = rawSnapshot();
    duplicate.data.execution.nodes.push({ ...duplicate.data.execution.nodes[0] });
    expect(() => adaptCompanySnapshot(duplicate, "live")).toThrow(CompanySnapshotError);

    const status = rawSnapshot();
    status.data.execution.nodes[0].runtime_status = "terminated";
    expect(() => adaptCompanySnapshot(status, "live")).toThrow(
      "runtime_status has an unsupported value"
    );

    const cursor = rawSnapshot();
    (cursor as unknown as { cursor: unknown }).cursor = true;
    expect(() => adaptCompanySnapshot(cursor, "live")).toThrow(
      "snapshot.cursor must be a non-negative safe integer"
    );
  });

  it("deduplicates and ordinally stabilizes snapshot warning attention", () => {
    const value = rawSnapshot();
    value.warnings = ["zeta", "alpha", "zeta", "alpha"];
    const projected = adaptCompanySnapshot(value, "live");
    const warnings = projected.attention.filter((item) => item.title === "Snapshot degraded");
    expect(warnings.map((item) => [item.id, item.detail])).toEqual([
      ["snapshot-warning:0", "alpha"],
      ["snapshot-warning:1", "zeta"]
    ]);

    const duplicateAlert = rawSnapshot();
    duplicateAlert.data.alerts.alerts.push({ ...duplicateAlert.data.alerts.alerts[0] });
    expect(() => adaptCompanySnapshot(duplicateAlert, "live")).toThrow(
      "snapshot attention identities are not unique"
    );
  });
});
