import { Icon } from "./Icon";
import { useResizablePanel } from "./ResizablePanel";

interface HistoryOverlayProps {
  cursors: number[];
  liveCursor: number;
  activeCursor: number;
  onSelect: (cursor: number | null) => void;
  onClose: () => void;
}

export function HistoryOverlay({
  cursors,
  liveCursor,
  activeCursor,
  onSelect,
  onClose
}: HistoryOverlayProps) {
  const resize = useResizablePanel({
    id: "history",
    anchor: "top-right",
    baseWidth: 1200,
    baseHeight: 180,
    minWidth: 720,
    minHeight: 150,
    maxHeight: 460
  });
  return (
    <section
      ref={resize.panelRef}
      style={resize.panelStyle}
      className={`history-overlay glass-panel ${resize.panelClassName}`}
      aria-label="History cursor"
    >
      <header>
        <div>
          <span className="panel-kicker">PROJECTION TIME</span>
          <h2>Company history</h2>
        </div>
        <button type="button" className="icon-button compact" onClick={onClose}>
          <Icon name="close" />
          <span className="sr-only">Close history</span>
        </button>
      </header>
      <div className="history-track">
        <span className="history-rail" />
        {cursors.map((cursor) => (
          <button
            type="button"
            key={cursor}
            className={cursor === activeCursor ? "is-active" : ""}
            onClick={() => onSelect(cursor === liveCursor ? null : cursor)}
          >
            <span />
            <strong>{cursor}</strong>
            <small>
              {cursor === liveCursor ? "LIVE" : "HISTORICAL"}
            </small>
          </button>
        ))}
      </div>
      <footer>
        <span>Cursor-bound view</span>
        <button
          type="button"
          onClick={() => onSelect(null)}
        >
          Return to latest
        </button>
      </footer>
      {resize.handle}
    </section>
  );
}
