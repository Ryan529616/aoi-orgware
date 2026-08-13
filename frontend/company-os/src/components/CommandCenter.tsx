import { useEffect, useMemo, useRef, useState } from "react";
import type {
  DashboardNodeV1,
  DashboardProfileV1,
  DashboardSnapshotV1,
  ViewTransform
} from "../contracts";
import { readCompanyOsPreferences } from "../company-os-preferences";
import { useVisualActivity } from "../visual-activity";
import { AttentionStack } from "./AttentionStack";
import { CommandPalette, type PaletteCommand } from "./CommandPalette";
import { Dock } from "./Dock";
import { GraphCanvas } from "./GraphCanvas";
import { HistoryOverlay } from "./HistoryOverlay";
import { Icon } from "./Icon";
import { Inspector } from "./Inspector";
import { VisualLayer } from "./VisualLayer";

interface CommandCenterProps {
  profile: DashboardProfileV1;
  snapshot: DashboardSnapshotV1;
  historyCursors: number[];
  liveCursor: number;
  connection: "connecting" | "live" | "historical" | "degraded";
  onCursorChange: (cursor: number | null) => void;
  onApplyProfile: (profile: DashboardProfileV1) => void;
}

function defaultTransform(): ViewTransform {
  const width = globalThis.innerWidth || 2560;
  const height = globalThis.innerHeight || 1440;
  const scale = width < 1400 || height < 800 ? 0.46 : height < 1050 ? 0.52 : 0.68;
  return { x: 0, y: 22, scale };
}

export function CommandCenter({
  profile,
  snapshot,
  historyCursors,
  liveCursor,
  connection,
  onCursorChange,
  onApplyProfile
}: CommandCenterProps) {
  const [selectedId, setSelectedId] = useState<string | null>("org:chief");
  const [transform, setTransform] = useState<ViewTransform>(defaultTransform);
  const [search, setSearch] = useState("");
  const [attentionExpanded, setAttentionExpanded] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [resetPositionsVersion, setResetPositionsVersion] = useState(0);
  const [pinnedNodeCount, setPinnedNodeCount] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const companyOsPreferences = useMemo(
    () => readCompanyOsPreferences(profile),
    [profile]
  );
  const visualActivity = useVisualActivity(
    companyOsPreferences.resourcePolicy.pauseWhenUnfocused,
    companyOsPreferences.resourcePolicy.pauseWhenAutomated
  );

  const selected = useMemo(
    () => snapshot.nodes.find((node) => node.id === selectedId) ?? null,
    [selectedId, snapshot.nodes]
  );
  const counts = useMemo(() => {
    const value = {
      active: 0,
      blocked: 0,
      needsUser: 0,
      observed: 0
    };
    snapshot.nodes.forEach((node) => {
      if (node.status === "active") value.active += 1;
      if (node.status === "blocked") value.blocked += 1;
      if (node.status === "needs_user") value.needsUser += 1;
      if (node.runtimeStatus === "running") {
        value.observed += 1;
      }
    });
    return value;
  }, [snapshot.nodes]);

  useEffect(() => {
    if (selectedId && !snapshot.nodes.some((node) => node.id === selectedId)) {
      setSelectedId(null);
    }
  }, [selectedId, snapshot.nodes]);

  useEffect(() => {
    const hotkeys = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
      if (event.key === "/" && !(event.target instanceof HTMLInputElement)) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    globalThis.addEventListener("keydown", hotkeys);
    return () => globalThis.removeEventListener("keydown", hotkeys);
  }, []);

  const selectById = (nodeId: string) => {
    const node = snapshot.nodes.find((candidate) => candidate.id === nodeId);
    if (node) setSelectedId(node.id);
  };

  const cycleTheme = () => {
    const next =
      profile.colorMode === "auto"
        ? "dark"
        : profile.colorMode === "dark"
          ? "light"
          : "auto";
    onApplyProfile({ ...profile, colorMode: next });
  };

  const restoreDefaultGraphLayout = () => {
    setTransform(defaultTransform());
    setResetPositionsVersion((version) => version + 1);
  };

  const commands: PaletteCommand[] = [
    {
      id: "focus",
      label: "Center Command Core",
      detail: "Reset pan and semantic zoom.",
      keywords: "graph chief reset view",
      run: () => setTransform(defaultTransform())
    },
    {
      id: "restore-graph",
      label: "Restore default graph layout",
      detail: "Clear all dragged node positions and restore the default view.",
      keywords: "graph nodes reset restore default pinned collision",
      run: restoreDefaultGraphLayout
    },
    {
      id: "history",
      label: "Open projection history",
      detail: "Move the complete view to a bounded company cursor.",
      keywords: "cursor timeline live",
      run: () => setHistoryOpen(true)
    },
    {
      id: "gpu-off",
      label: "Disable Visual Engine",
      detail: "Dispose all Canvas/WebGPU resources.",
      keywords: "gpu off motion particles",
      run: () =>
        onApplyProfile({
          ...profile,
          visualEngine: { ...profile.visualEngine, preset: "off", particles: 0 }
        })
    },
    {
      id: "gpu-ultra",
      label: "Enable Ultra Visual Engine",
      detail: "Use one million particles and high-performance adapter hint.",
      keywords: "gpu ultra cinematic million",
      run: () =>
        onApplyProfile({
          ...profile,
          visualEngine: {
            ...profile.visualEngine,
            preset: "ultra",
            particles: 1_000_000,
            renderScale: 1.5,
            bloom: 1.15,
            depthOfField: 0.9,
            highPerformanceHint: true
          }
        })
    }
  ];

  return (
    <main
      className={`company-os ${
        visualActivity.paused ? "is-visual-paused" : ""
      }`}
      data-visual-activity={visualActivity.paused ? "paused" : "running"}
    >
      <VisualLayer
        settings={profile.visualEngine}
        paused={visualActivity.paused}
        pauseReason={visualActivity.reason}
      />
      <div className="grid-field" aria-hidden="true" />
      <GraphCanvas
        snapshot={snapshot}
        selectedId={selectedId}
        onSelect={(node) => setSelectedId(node.id)}
        transform={transform}
        setTransform={setTransform}
        search={search}
        semanticEffects={profile.visualEngine.semanticEffects}
        graphPreferences={companyOsPreferences.graph}
        profileId={profile.id}
        resetPositionsVersion={resetPositionsVersion}
        onPinnedCountChange={setPinnedNodeCount}
        visualStyle={companyOsPreferences.appearance.style}
      />

      <header className="company-hud glass-panel">
        <div className="brand-mark">
          <span className="brand-orbit">
            <i />
          </span>
          <div>
            <span>AOI // COMPANY OS</span>
            <strong>{snapshot.companyName}</strong>
          </div>
        </div>
        <div className="company-status">
          <span className={`connection-dot completeness-${snapshot.completeness}`} />
          <div>
            <strong>
              {snapshot.mode === "historical" ? "HISTORICAL PROJECTION" : "LIVE COMPANY"}
            </strong>
            <small>
              Cursor {snapshot.cursor} · {snapshot.completeness} ·{" "}
              {new Date(snapshot.generatedAt).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit"
              })}
            </small>
          </div>
        </div>
      </header>

      <div className="search-hud glass-panel">
        <Icon name="search" />
        <input
          ref={searchRef}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search company, node, ID, provider…"
          aria-label="Search company graph"
        />
        {search ? (
          <button type="button" onClick={() => setSearch("")}>
            <Icon name="close" />
            <span className="sr-only">Clear search</span>
          </button>
        ) : (
          <kbd>/</kbd>
        )}
      </div>

      <section className="metric-hud glass-panel" aria-label="Company summary">
        <Metric label="Active" value={counts.active} tone="cyan" />
        <Metric label="Blocked" value={counts.blocked} tone="red" />
        <Metric label="Needs user" value={counts.needsUser} tone="amber" />
        <Metric label="Observed" value={counts.observed} tone="violet" />
      </section>

      <AttentionStack
        attention={snapshot.attention}
        expanded={attentionExpanded}
        onToggle={() => setAttentionExpanded((expanded) => !expanded)}
        onSelect={selectById}
      />

      <div className="fixture-boundary">
        <span />
        READ-ONLY PROJECTION · {connection.toUpperCase()} · NO BROWSER MUTATION AUTHORITY
      </div>

      <Inspector node={selected} snapshot={snapshot} onClose={() => setSelectedId(null)} />

      {historyOpen ? (
        <HistoryOverlay
          cursors={historyCursors}
          liveCursor={liveCursor}
          activeCursor={snapshot.cursor}
          onSelect={onCursorChange}
          onClose={() => setHistoryOpen(false)}
        />
      ) : null}

      <Dock
        colorMode={profile.colorMode}
        gpuPreset={profile.visualEngine.preset}
        gpuPaused={visualActivity.paused}
        historyOpen={historyOpen}
        graphLayoutModified={pinnedNodeCount > 0}
        onOpenCommand={() => setPaletteOpen(true)}
        onToggleHistory={() => setHistoryOpen((open) => !open)}
        onResetView={() => setTransform(defaultTransform)}
        onRestoreGraph={restoreDefaultGraphLayout}
        onToggleTheme={cycleTheme}
      />

      {paletteOpen ? (
        <CommandPalette commands={commands} onClose={() => setPaletteOpen(false)} />
      ) : null}
    </main>
  );
}

function Metric({
  label,
  value,
  tone
}: {
  label: string;
  value: number;
  tone: string;
}) {
  return (
    <div className={`metric-item tone-${tone}`}>
      <span>{label}</span>
      <strong>{String(value).padStart(2, "0")}</strong>
    </div>
  );
}
