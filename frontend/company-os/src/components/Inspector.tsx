import { useEffect, useRef, useState } from "react";
import type { DashboardNodeV1, DashboardSnapshotV1 } from "../contracts";
import { Icon } from "./Icon";
import { useResizablePanel } from "./ResizablePanel";

const tabs = ["Overview", "Activity", "Usage", "Artifacts", "Evidence", "Raw"] as const;
type Tab = (typeof tabs)[number];

interface InspectorProps {
  node: DashboardNodeV1 | null;
  snapshot: DashboardSnapshotV1;
  onClose: () => void;
}

export function Inspector({ node, snapshot, onClose }: InspectorProps) {
  const [tab, setTab] = useState<Tab>("Overview");
  const closeRef = useRef<HTMLButtonElement>(null);
  const resize = useResizablePanel({
    id: "inspector",
    anchor: "top-left",
    baseWidth: 480,
    baseHeight: 900,
    minWidth: 390,
    minHeight: 420,
    maxWidth: 980
  });

  useEffect(() => {
    if (node) {
      setTab("Overview");
      closeRef.current?.focus({ preventScroll: true });
    }
  }, [node]);

  useEffect(() => {
    if (!node) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    globalThis.addEventListener("keydown", escape);
    return () => globalThis.removeEventListener("keydown", escape);
  }, [node, onClose]);

  if (!node) return null;
  return (
    <aside
      ref={resize.panelRef}
      style={resize.panelStyle}
      className={`inspector glass-panel ${resize.panelClassName}`}
      aria-label="Node inspector"
    >
      <header className="inspector-header">
        <div>
          <span className="panel-kicker">NODE INSPECTOR</span>
          <h2>{node.name}</h2>
          <p>{node.role}</p>
        </div>
        <button ref={closeRef} type="button" className="icon-button" onClick={onClose}>
          <Icon name="close" />
          <span className="sr-only">Close inspector</span>
        </button>
      </header>

      <div className="inspector-state">
        <span className={`state-pill state-${node.status}`}>{node.status.replace("_", " ")}</span>
        <span>eng {node.engineeringStatus}</span>
        <span>run {node.runtimeStatus}</span>
        <span>cov {node.coverageStatus}</span>
        <span>effect {node.effectStatus}</span>
      </div>

      <div className="inspector-tabs" role="tablist" aria-label="Node detail">
        {tabs.map((value) => (
          <button
            type="button"
            role="tab"
            aria-selected={tab === value}
            key={value}
            onClick={() => setTab(value)}
          >
            {value}
          </button>
        ))}
      </div>

      <div className="inspector-body" role="tabpanel">
        {tab === "Overview" ? (
          <>
            <InspectorSection label="Objective">{node.objective}</InspectorSection>
            <InspectorSection label="Identity">
              <CopyRow label="Immutable ID" value={node.id} />
              <CopyRow label="Parent" value={node.parentId ?? "root"} />
              <CopyRow label="Department" value={node.department ?? "company"} />
            </InspectorSection>
            <InspectorSection label="Runtime">
              <Definition label="Provider" value={node.provider ?? "unavailable"} />
              <Definition label="Model" value={node.model ?? "unavailable"} />
              <Definition label="Organization" value={node.organizationStatus ?? "unavailable"} />
              <Definition label="Coverage" value={node.coverageStatus} />
              <Definition label="Effect" value={node.effectStatus} />
              <Definition label="Projection" value={node.projectionSource} />
              <Definition label="Orphan" value={node.orphanReason ?? "no explicit orphan"} />
              <Definition label="Reason" value={node.reason ?? "No bounded reason recorded"} />
            </InspectorSection>
          </>
        ) : null}
        {tab === "Activity" ? (
          <Timeline node={node} cursor={snapshot.cursor} />
        ) : null}
        {tab === "Usage" ? (
          <InspectorSection label="Raw provider usage">
            <div className="usage-orb">
              <strong>{node.usageTokens?.toLocaleString() ?? "Unavailable"}</strong>
              <span>observed tokens</span>
            </div>
            <p className="bounded-copy">
              Raw cumulative counters are intentionally not reduced to a node total,
              cost, quota or remaining budget.
            </p>
          </InspectorSection>
        ) : null}
        {tab === "Artifacts" ? (
          <EmptyDetail
            title="Artifact metadata"
            detail="Artifact joins are unavailable in this first live adapter."
          />
        ) : null}
        {tab === "Evidence" ? (
          <InspectorSection label="Evidence boundary">
            <Definition label="Class" value={node.evidenceClass ?? "unknown"} />
            <Definition
              label="Scope"
              value="No evidence class is selected from a potentially multi-class join."
            />
          </InspectorSection>
        ) : null}
        {tab === "Raw" ? (
          <pre className="raw-json">{JSON.stringify(node, null, 2)}</pre>
        ) : null}
      </div>
      <footer className="inspector-footer">
        {snapshot.mode.toUpperCase()} · CURSOR {snapshot.cursor} · {snapshot.companyId}
      </footer>
      {resize.handle}
    </aside>
  );
}

function InspectorSection({
  label,
  children
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <section className="inspector-section">
      <h3>{label}</h3>
      {typeof children === "string" ? <p>{children}</p> : children}
    </section>
  );
}

function CopyRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="copy-row">
      <div>
        <span>{label}</span>
        <code>{value}</code>
      </div>
      <button
        type="button"
        className="icon-button compact"
        onClick={() => {
          void navigator.clipboard?.writeText(value);
          setCopied(true);
          globalThis.setTimeout(() => setCopied(false), 1200);
        }}
      >
        <Icon name="copy" />
        <span className="sr-only">{copied ? "Copied" : `Copy ${label}`}</span>
      </button>
    </div>
  );
}

function Definition({ label, value }: { label: string; value: string }) {
  return (
    <div className="definition-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Timeline({ node, cursor }: { node: DashboardNodeV1; cursor: number }) {
  return (
    <ol className="timeline">
      {[0, 1, 2].map((offset) => (
        <li key={offset}>
          <span className="timeline-dot" />
          <div>
            <strong>
              {offset === 0 ? "Current projection" : offset === 1 ? "Observation joined" : "Work admitted"}
            </strong>
            <p>
              Cursor {Math.max(1, cursor - offset)} · {node.runtimeStatus}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

function EmptyDetail({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-detail">
      <Icon name="layers" />
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}
