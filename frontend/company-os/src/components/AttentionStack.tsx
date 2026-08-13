import type { DashboardAttentionV1 } from "../contracts";
import { Icon } from "./Icon";
import { useResizablePanel } from "./ResizablePanel";

interface AttentionStackProps {
  attention: DashboardAttentionV1[];
  expanded: boolean;
  onToggle: () => void;
  onSelect: (nodeId: string) => void;
}

export function AttentionStack({
  attention,
  expanded,
  onToggle,
  onSelect
}: AttentionStackProps) {
  const visible = expanded ? attention : attention.slice(0, 3);
  const resize = useResizablePanel({
    id: "attention",
    anchor: "bottom-left",
    baseWidth: 420,
    baseHeight: 270,
    minWidth: 350,
    minHeight: 190,
    maxWidth: 760,
    maxHeight: 760
  });
  return (
    <section
      ref={resize.panelRef}
      style={resize.panelStyle}
      className={`attention-stack ${expanded ? "is-expanded" : ""} ${resize.panelClassName}`}
    >
      <button type="button" className="attention-heading" onClick={onToggle}>
        <span className="attention-symbol">
          <Icon name="alert" />
        </span>
        <span>
          <strong>Attention</strong>
          <small>{attention.length} items require inspection</small>
        </span>
        <span className="attention-count">{attention.length}</span>
      </button>
      <div className="attention-items">
        {visible.map((item) => (
          <button
            type="button"
            key={item.id}
            className={`attention-item severity-${item.severity}`}
            disabled={!item.nodeId}
            onClick={() => item.nodeId && onSelect(item.nodeId)}
          >
            <span className="attention-line" />
            <span>
              <strong>{item.title}</strong>
              <small>{item.detail}</small>
            </span>
          </button>
        ))}
      </div>
      {attention.length > 3 ? (
        <button type="button" className="attention-more" onClick={onToggle}>
          {expanded ? "Collapse attention" : `View all ${attention.length}`}
        </button>
      ) : null}
      {resize.handle}
    </section>
  );
}
