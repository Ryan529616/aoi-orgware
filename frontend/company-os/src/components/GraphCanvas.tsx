import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type PointerEvent as ReactPointerEvent,
  type SetStateAction,
  type WheelEvent
} from "react";
import type {
  CompanyOsGraphPreferencesV1,
  CompanyOsVisualStyle
} from "../company-os-preferences";
import type {
  DashboardNodeV1,
  DashboardSnapshotV1,
  ViewTransform
} from "../contracts";
import {
  applyPinnedPositions,
  edgePath,
  radialLayout,
  resolveNodeCollisions,
  semanticNodes,
  type PositionedNode
} from "../graph-layout";
import {
  clearPinnedNodePositions,
  readPinnedNodePositions,
  writePinnedNodePositions
} from "../graph-position-store";

interface GraphCanvasProps {
  snapshot: DashboardSnapshotV1;
  selectedId: string | null;
  onSelect: (node: DashboardNodeV1) => void;
  transform: ViewTransform;
  setTransform: Dispatch<SetStateAction<ViewTransform>>;
  search: string;
  semanticEffects: boolean;
  graphPreferences: CompanyOsGraphPreferencesV1;
  profileId: string;
  resetPositionsVersion: number;
  onPinnedCountChange: (count: number) => void;
  visualStyle: CompanyOsVisualStyle;
}

export function GraphCanvas({
  snapshot,
  selectedId,
  onSelect,
  transform,
  setTransform,
  search,
  semanticEffects,
  graphPreferences,
  profileId,
  resetPositionsVersion,
  onPinnedCountChange,
  visualStyle
}: GraphCanvasProps) {
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    originX: number;
    originY: number;
  } | null>(null);
  const nodeDragRef = useRef<{
    pointerId: number;
    nodeId: string;
    startX: number;
    startY: number;
    originX: number;
    originY: number;
    latestX: number;
    latestY: number;
    moved: boolean;
  } | null>(null);
  const suppressClickRef = useRef<string | null>(null);
  const resetVersionRef = useRef(resetPositionsVersion);
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [pinned, setPinned] = useState(() =>
    readPinnedNodePositions(snapshot.companyId, profileId)
  );
  const pinnedRef = useRef(pinned);
  pinnedRef.current = pinned;
  const pinnedCount = Object.keys(pinned).length;
  const resetPinnedPositions = useCallback(() => {
    clearPinnedNodePositions(snapshot.companyId, profileId);
    pinnedRef.current = {};
    setPinned({});
  }, [profileId, snapshot.companyId]);
  const visible = useMemo(
    () => semanticNodes(snapshot.nodes, transform, search),
    [snapshot.nodes, transform, search]
  );
  const automaticLayout = useMemo(
    () => radialLayout(visible, graphPreferences),
    [graphPreferences, visible]
  );
  const baseLayout = useMemo(
    () => applyPinnedPositions(automaticLayout, pinned),
    [automaticLayout, pinned]
  );
  const collisionResult = useMemo(
    () =>
      resolveNodeCollisions(
        baseLayout,
        new Set(Object.keys(pinned)),
        graphPreferences
      ),
    [baseLayout, graphPreferences, pinned]
  );
  const layout = collisionResult.layout;
  const realVisibleCount = visible.filter((node) => node.kind !== "aggregate").length;
  const hiddenCount = snapshot.nodes.length - realVisibleCount;

  useEffect(() => {
    const next = readPinnedNodePositions(snapshot.companyId, profileId);
    pinnedRef.current = next;
    setPinned(next);
  }, [profileId, snapshot.companyId]);

  useEffect(() => {
    onPinnedCountChange(pinnedCount);
  }, [onPinnedCountChange, pinnedCount]);

  useEffect(() => {
    if (resetVersionRef.current === resetPositionsVersion) return;
    resetVersionRef.current = resetPositionsVersion;
    resetPinnedPositions();
  }, [resetPinnedPositions, resetPositionsVersion]);

  const handleWheel = useCallback(
    (event: WheelEvent<HTMLDivElement>) => {
      event.preventDefault();
      const factor = event.deltaY > 0 ? 0.9 : 1.1;
      setTransform((current) => ({
        ...current,
        scale: Math.max(0.42, Math.min(2.4, current.scale * factor))
      }));
    },
    [setTransform]
  );

  const handlePointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("[data-graph-node]")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: transform.x,
      originY: transform.y
    };
  };

  const handlePointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    setTransform((current) => ({
      ...current,
      x: drag.originX + event.clientX - drag.startX,
      y: drag.originY + event.clientY - drag.startY
    }));
  };

  const handlePointerUp = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (dragRef.current?.pointerId === event.pointerId) dragRef.current = null;
  };

  const startNodeDrag = (
    event: ReactPointerEvent<HTMLButtonElement>,
    item: PositionedNode
  ) => {
    if (!graphPreferences.draggableNodes || event.button !== 0) return;
    event.stopPropagation();
    event.currentTarget.setPointerCapture(event.pointerId);
    setDraggingNodeId(item.node.id);
    nodeDragRef.current = {
      pointerId: event.pointerId,
      nodeId: item.node.id,
      startX: event.clientX,
      startY: event.clientY,
      originX: item.x,
      originY: item.y,
      latestX: item.x,
      latestY: item.y,
      moved: false
    };
  };

  const moveNode = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const drag = nodeDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    event.stopPropagation();
    const deltaX = (event.clientX - drag.startX) / Math.max(0.01, transform.scale);
    const deltaY = (event.clientY - drag.startY) / Math.max(0.01, transform.scale);
    drag.latestX = Math.round(drag.originX + deltaX);
    drag.latestY = Math.round(drag.originY + deltaY);
    drag.moved ||= Math.hypot(deltaX, deltaY) > 4;
    const next = {
      ...pinnedRef.current,
      [drag.nodeId]: { x: drag.latestX, y: drag.latestY }
    };
    pinnedRef.current = next;
    setPinned(next);
  };

  const endNodeDrag = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const drag = nodeDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    event.stopPropagation();
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    if (drag.moved) {
      suppressClickRef.current = drag.nodeId;
      writePinnedNodePositions(
        snapshot.companyId,
        profileId,
        pinnedRef.current
      );
    }
    nodeDragRef.current = null;
    setDraggingNodeId(null);
  };

  const restoreNode = (
    event: React.MouseEvent<HTMLButtonElement>,
    nodeId: string
  ) => {
    if (!graphPreferences.draggableNodes || !pinnedRef.current[nodeId]) return;
    event.preventDefault();
    event.stopPropagation();
    const next = { ...pinnedRef.current };
    delete next[nodeId];
    pinnedRef.current = next;
    setPinned(next);
    writePinnedNodePositions(snapshot.companyId, profileId, next);
  };

  return (
    <div
      className="graph-canvas"
      aria-label="Company organization and execution graph"
      onWheel={handleWheel}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerCancel={handlePointerUp}
    >
      <div
        className="graph-world"
        style={{
          transform: `translate(calc(-50% + ${transform.x}px), calc(-50% + ${transform.y}px)) scale(${transform.scale})`
        }}
      >
        <svg
          className="graph-edges"
          viewBox="-1100 -800 2200 1600"
          preserveAspectRatio="none"
        >
          <defs>
            <filter id="edge-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {layout.edges.map((edge) => (
            <g
              key={edge.id}
              className={`graph-edge edge-${edge.target.node.status} ${
                semanticEffects ? "edge-semantic" : ""
              }`}
            >
              <path
                className="edge-base"
                d={edgePath(edge, visualStyle === "pcb-blue" ? "circuit" : "curve")}
              />
              {semanticEffects &&
              ["active", "blocked", "needs_user", "unknown"].includes(
                edge.target.node.status
              ) ? (
                <path
                  className="edge-flow"
                  d={edgePath(
                    edge,
                    visualStyle === "pcb-blue" ? "circuit" : "curve"
                  )}
                />
              ) : null}
            </g>
          ))}
        </svg>

        {layout.nodes.map((item) => {
          const { node, x, y } = item;
          const nodeIsPinned = Boolean(pinned[node.id]);
          const nodeIsDisplaced = collisionResult.displacedNodeIds.has(node.id);
          return (
          <button
            type="button"
            key={node.id}
            data-graph-node={node.id}
            data-engineering-status={node.engineeringStatus}
            data-runtime-status={node.runtimeStatus}
            data-coverage-status={node.coverageStatus}
            data-effect-status={node.effectStatus}
            className={`graph-node node-${node.kind} status-${node.status} ${
              selectedId === node.id ? "is-selected" : ""
            } ${graphPreferences.draggableNodes ? "is-draggable" : ""} ${
              nodeIsPinned ? "is-position-pinned" : ""
            } ${draggingNodeId === node.id ? "is-dragging" : ""} ${
              nodeIsDisplaced ? "is-collision-displaced" : ""
            }`}
            style={{ left: `calc(50% + ${x}px)`, top: `calc(50% + ${y}px)` }}
            onPointerDown={(event) => startNodeDrag(event, item)}
            onPointerMove={moveNode}
            onPointerUp={endNodeDrag}
            onPointerCancel={endNodeDrag}
            onDoubleClick={(event) => restoreNode(event, node.id)}
            onClick={() => {
              if (suppressClickRef.current === node.id) {
                suppressClickRef.current = null;
                return;
              }
              if (node.kind === "aggregate") {
                setTransform((current) => ({ ...current, scale: 0.88 }));
              } else {
                onSelect(node);
              }
            }}
            aria-label={`${node.name}, ${node.role}, engineering ${node.engineeringStatus}, runtime ${node.runtimeStatus}, coverage ${node.coverageStatus}, effect ${node.effectStatus}`}
            aria-description={
              graphPreferences.draggableNodes
                ? "Drag to reposition and push colliding nodes away. Double-click to restore automatic layout."
                : undefined
            }
          >
            <span className="node-halo" />
            <span className="node-status-dot" />
            <span className="node-eyebrow">
              {node.kind === "chief" ? "COMMAND CORE" : node.role.toUpperCase()}
            </span>
            <strong>{node.name}</strong>
            <span className="node-objective">{node.objective}</span>
            <span className="node-meta">
              <span>eng {node.engineeringStatus}</span>
              <span>run {node.runtimeStatus}</span>
            </span>
            <span className="node-truth-axes">
              <span>cov {node.coverageStatus}</span>
              <span>effect {node.effectStatus}</span>
            </span>
          </button>
          );
        })}
      </div>

      <div className="zoom-readout" aria-live="polite">
        <span>{Math.round(transform.scale * 100)}%</span>
        <span>{realVisibleCount} live nodes</span>
        {hiddenCount > 0 ? <span>{hiddenCount} collapsed</span> : null}
        {pinnedCount > 0 ? (
          <span>{pinnedCount} pinned</span>
        ) : null}
        {draggingNodeId && collisionResult.collisionCount > 0 ? (
          <span>{collisionResult.collisionCount} collisions resolved</span>
        ) : null}
        {pinnedCount > 0 ? (
          <button
            type="button"
            className="graph-reset-positions"
            onPointerDown={(event) => event.stopPropagation()}
            onClick={resetPinnedPositions}
          >
            Restore auto layout
          </button>
        ) : null}
      </div>
    </div>
  );
}
