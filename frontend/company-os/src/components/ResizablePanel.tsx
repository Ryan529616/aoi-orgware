import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, KeyboardEvent, PointerEvent, RefObject } from "react";

export type ResizeAnchor = "top-left" | "top-right" | "bottom-left" | "bottom-right";

export interface PanelSize {
  width: number;
  height: number;
}

interface ResizablePanelOptions {
  id: string;
  anchor: ResizeAnchor;
  baseWidth: number;
  baseHeight: number;
  minWidth: number;
  minHeight: number;
  maxWidth?: number;
  maxHeight?: number;
  defaultTextScale?: number;
  compactTextScale?: number;
  maxTextScale?: number;
}

interface ResizablePanelResult {
  panelRef: RefObject<HTMLElement | null>;
  panelStyle: CSSProperties;
  panelClassName: string;
  handle: React.ReactNode;
}

const STORAGE_KEY = "aoi.dashboard.panel-layout.v1";

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

export function derivePanelTextScale(
  size: PanelSize | null,
  baseSize: PanelSize,
  defaultScale = 1.1,
  maxScale = 1.5
): number {
  if (!size) return defaultScale;
  const areaRatio = (size.width * size.height) / (baseSize.width * baseSize.height);
  return clamp(defaultScale * Math.sqrt(areaRatio), defaultScale, maxScale);
}

export function resizePanelFromDelta(
  start: PanelSize,
  deltaX: number,
  deltaY: number,
  anchor: ResizeAnchor,
  bounds: {
    minWidth: number;
    minHeight: number;
    maxWidth: number;
    maxHeight: number;
  }
): PanelSize {
  const horizontal = anchor.includes("left") ? -deltaX : deltaX;
  const vertical = anchor.includes("top") ? -deltaY : deltaY;
  return {
    width: Math.round(clamp(start.width + horizontal, bounds.minWidth, bounds.maxWidth)),
    height: Math.round(
      clamp(start.height + vertical, bounds.minHeight, bounds.maxHeight)
    )
  };
}

export function useResizablePanel(options: ResizablePanelOptions): ResizablePanelResult {
  const panelRef = useRef<HTMLElement | null>(null);
  const [size, setSize] = useState<PanelSize | null>(() => {
    const stored = readPanelSize(options.id);
    return stored ? clampPanelSize(stored, resolveBounds(options)) : null;
  });
  const [resizing, setResizing] = useState(false);
  const [viewport, setViewport] = useState(() => ({
    width: globalThis.innerWidth || options.baseWidth,
    height: globalThis.innerHeight || options.baseHeight
  }));
  const compactViewport =
    viewport.width < 1500 || viewport.height < 800;
  const defaultScale = compactViewport
    ? (options.compactTextScale ?? 1)
    : (options.defaultTextScale ?? 1.1);
  const scale = derivePanelTextScale(
    size,
    { width: options.baseWidth, height: options.baseHeight },
    defaultScale,
    options.maxTextScale
  );
  const panelStyle = useMemo(
    () =>
      ({
        ...(size ? { width: size.width, height: size.height } : {}),
        "--panel-ui-scale": scale.toFixed(3)
      }) as CSSProperties,
    [scale, size]
  );

  const bounds = () => resolveBounds(options);

  useEffect(() => {
    const keepInsideViewport = () => {
      setViewport({
        width: globalThis.innerWidth || options.baseWidth,
        height: globalThis.innerHeight || options.baseHeight
      });
      setSize((current) =>
        current ? clampPanelSize(current, resolveBounds(options)) : current
      );
    };
    globalThis.addEventListener("resize", keepInsideViewport);
    return () => globalThis.removeEventListener("resize", keepInsideViewport);
  }, [
    options.baseHeight,
    options.baseWidth,
    options.maxHeight,
    options.maxWidth,
    options.minHeight,
    options.minWidth
  ]);

  const commit = (next: PanelSize) => {
    setSize(next);
    writePanelSize(options.id, next);
  };

  const beginResize = (event: PointerEvent<HTMLButtonElement>) => {
    if (event.button !== 0) return;
    const panel = panelRef.current;
    if (!panel) return;
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.focus({ preventScroll: true });
    const startRect = panel.getBoundingClientRect();
    const start = { width: startRect.width, height: startRect.height };
    const origin = { x: event.clientX, y: event.clientY };
    let latest = start;
    let moved = false;

    const move = (moveEvent: globalThis.PointerEvent) => {
      if (
        !moved &&
        Math.hypot(moveEvent.clientX - origin.x, moveEvent.clientY - origin.y) < 2
      ) {
        return;
      }
      if (!moved) {
        moved = true;
        setResizing(true);
        document.body.classList.add("is-resizing-panel");
      }
      latest = resizePanelFromDelta(
        start,
        moveEvent.clientX - origin.x,
        moveEvent.clientY - origin.y,
        options.anchor,
        bounds()
      );
      setSize(latest);
    };
    const end = () => {
      globalThis.removeEventListener("pointermove", move);
      globalThis.removeEventListener("pointerup", end);
      globalThis.removeEventListener("pointercancel", end);
      if (moved) {
        document.body.classList.remove("is-resizing-panel");
        setResizing(false);
        commit(latest);
      }
    };
    globalThis.addEventListener("pointermove", move);
    globalThis.addEventListener("pointerup", end, { once: true });
    globalThis.addEventListener("pointercancel", end, { once: true });
  };

  const keyboardResize = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const rect = panelRef.current?.getBoundingClientRect();
    const current = size ?? {
      width: rect?.width ?? options.baseWidth,
      height: rect?.height ?? options.baseHeight
    };
    const step = event.shiftKey ? 40 : 16;
    const next = {
      width:
        current.width +
        (event.key === "ArrowRight" ? step : event.key === "ArrowLeft" ? -step : 0),
      height:
        current.height +
        (event.key === "ArrowDown" ? step : event.key === "ArrowUp" ? -step : 0)
    };
    commit(clampPanelSize(next, bounds()));
  };

  const reset = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setSize(null);
    removePanelSize(options.id);
  };

  const currentLabel = size
    ? `${Math.round(size.width)} × ${Math.round(size.height)} · ${scale.toFixed(2)}× text`
    : `Default · ${scale.toFixed(2)}× text`;

  return {
    panelRef,
    panelStyle,
    panelClassName: `resizable-panel ${size ? "has-custom-panel-size" : ""} ${
      resizing ? "is-resizing" : ""
    }`,
    handle: (
      <button
        type="button"
        className={`panel-resize-handle resize-${options.anchor}`}
        aria-label={`Resize ${options.id} panel. Arrow keys adjust size. Double-click resets.`}
        title="Drag to resize · Double-click to reset"
        onPointerDown={beginResize}
        onDoubleClick={reset}
        onKeyDown={keyboardResize}
      >
        <i aria-hidden="true" />
        <span>{currentLabel}</span>
      </button>
    )
  };
}

function resolveBounds(options: ResizablePanelOptions) {
  return {
    minWidth: options.minWidth,
    minHeight: options.minHeight,
    maxWidth: Math.max(
      options.minWidth,
      Math.min(options.maxWidth ?? Number.POSITIVE_INFINITY, innerWidth - 24)
    ),
    maxHeight: Math.max(
      options.minHeight,
      Math.min(options.maxHeight ?? Number.POSITIVE_INFINITY, innerHeight - 24)
    )
  };
}

function clampPanelSize(
  size: PanelSize,
  bounds: ReturnType<typeof resolveBounds>
): PanelSize {
  return {
    width: Math.round(clamp(size.width, bounds.minWidth, bounds.maxWidth)),
    height: Math.round(clamp(size.height, bounds.minHeight, bounds.maxHeight))
  };
}

function readPanelLayout(): Record<string, PanelSize> {
  try {
    const source = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (!source) return {};
    const parsed: unknown = JSON.parse(source);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, PanelSize>)
      : {};
  } catch {
    return {};
  }
}

function readPanelSize(id: string): PanelSize | null {
  const value = readPanelLayout()[id];
  return value &&
    Number.isFinite(value.width) &&
    Number.isFinite(value.height) &&
    value.width > 0 &&
    value.height > 0
    ? value
    : null;
}

function writePanelSize(id: string, size: PanelSize): void {
  const layout = readPanelLayout();
  layout[id] = size;
  globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(layout));
}

function removePanelSize(id: string): void {
  const layout = readPanelLayout();
  delete layout[id];
  globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(layout));
}
