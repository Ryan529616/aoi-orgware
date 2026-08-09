import type { ColorMode, GpuPreset } from "../contracts";
import { Icon } from "./Icon";

interface DockProps {
  colorMode: ColorMode;
  gpuPreset: GpuPreset;
  gpuPaused: boolean;
  historyOpen: boolean;
  graphLayoutModified: boolean;
  onOpenCommand: () => void;
  onToggleHistory: () => void;
  onResetView: () => void;
  onRestoreGraph: () => void;
  onToggleTheme: () => void;
}

export function Dock({
  colorMode,
  gpuPreset,
  gpuPaused,
  historyOpen,
  graphLayoutModified,
  onOpenCommand,
  onToggleHistory,
  onResetView,
  onRestoreGraph,
  onToggleTheme
}: DockProps) {
  return (
    <nav className="floating-dock glass-panel" aria-label="Company OS">
      <DockButton label="Command palette" onClick={onOpenCommand}>
        <Icon name="command" />
      </DockButton>
      <span className="dock-divider" />
      <DockButton label="Center command core" onClick={onResetView}>
        <Icon name="focus" />
      </DockButton>
      <DockButton
        label="Reset graph layout"
        active={graphLayoutModified}
        onClick={onRestoreGraph}
      >
        <Icon name="reset" />
      </DockButton>
      <DockButton
        label="History"
        active={historyOpen}
        onClick={onToggleHistory}
      >
        <Icon name="history" />
      </DockButton>
      <DockButton label={`Color mode: ${colorMode}`} onClick={onToggleTheme}>
        <Icon name={colorMode === "light" ? "sun" : "moon"} />
      </DockButton>
      <span className="dock-divider" />
      <div
        className={`dock-engine engine-${gpuPreset} ${gpuPaused ? "is-paused" : ""}`}
        aria-label={`Visual engine ${gpuPreset}${gpuPaused ? ", paused by resource policy" : ""}`}
      >
        <span />
        <strong>{gpuPaused ? `${gpuPreset} · paused` : gpuPreset}</strong>
      </div>
    </nav>
  );
}

function DockButton({
  label,
  active,
  onClick,
  children
}: {
  label: string;
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      className={`dock-button ${active ? "is-active" : ""}`}
      onClick={onClick}
    >
      {children}
      <span>{label}</span>
    </button>
  );
}
