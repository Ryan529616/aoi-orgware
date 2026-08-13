import { useEffect, useRef, useState } from "react";
import type { VisualEngineSettingsV1 } from "../contracts";
import type { VisualActivityReason } from "../visual-activity";
import {
  createVisualEngine,
  type VisualEngineHandle,
  type VisualEngineStats
} from "../visual-engine";

const initialStats: VisualEngineStats = {
  renderer: "off",
  activity: "off",
  fps: 0,
  frameTime: 0,
  drawCalls: 0,
  particles: 0,
  renderScale: 0
};

interface VisualLayerProps {
  settings: VisualEngineSettingsV1;
  paused: boolean;
  pauseReason: VisualActivityReason;
}

export function VisualLayer({ settings, paused, pauseReason }: VisualLayerProps) {
  const [stats, setStats] = useState(initialStats);
  const [reason, setReason] = useState<string | null>(null);
  const [forceWebGL, setForceWebGL] = useState(false);
  const engineKey = JSON.stringify([forceWebGL, settings]);

  return (
    <div
      className={`visual-layer visual-${settings.preset}`}
      data-renderer-request={forceWebGL ? "webgl2" : "auto"}
      data-visual-activity={paused ? "paused" : "running"}
      aria-hidden="true"
    >
      <EngineCanvas
        key={engineKey}
        settings={settings}
        paused={paused}
        forceWebGL={forceWebGL}
        onStart={() => setReason(null)}
        onStats={setStats}
        onUnavailable={setReason}
        onDeviceLost={(value) => {
          setReason(`${value}. Rebuilding with WebGL2.`);
          setForceWebGL(true);
        }}
      />
      {settings.decorativeEffects && settings.preset !== "off" ? (
        <>
          <div className="volumetric-haze haze-a" />
          <div className="volumetric-haze haze-b" />
          <div className="scan-plane" />
        </>
      ) : null}
      {settings.devHud ? (
        <div className="dev-hud" aria-hidden="false">
          <strong>VISUAL ENGINE</strong>
          <span>{stats.renderer.toUpperCase()}</span>
          <span>STATE</span>
          <span>
            {paused ? `PAUSED · ${pauseReason.toUpperCase()}` : stats.activity.toUpperCase()}
          </span>
          <span>{stats.fps} FPS</span>
          <span>{stats.frameTime} MS</span>
          <span>{stats.drawCalls} DRAWS</span>
          <span>{stats.particles.toLocaleString()} PARTICLES</span>
          <span>{stats.renderScale.toFixed(2)}× SCALE</span>
          {reason ? <span className="hud-error">{reason}</span> : null}
        </div>
      ) : null}
    </div>
  );
}

interface EngineCanvasProps {
  settings: VisualEngineSettingsV1;
  paused: boolean;
  forceWebGL: boolean;
  onStart: () => void;
  onStats: (stats: VisualEngineStats) => void;
  onUnavailable: (reason: string) => void;
  onDeviceLost: (reason: string) => void;
}

function EngineCanvas({
  settings,
  paused,
  forceWebGL,
  onStart,
  onStats,
  onUnavailable,
  onDeviceLost
}: EngineCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const engineRef = useRef<VisualEngineHandle | null>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let cancelled = false;
    onStart();
    void createVisualEngine(canvas, settings, {
      onStats: (value) => {
        if (!cancelled) onStats(value);
      },
      onUnavailable: (value) => {
        if (!cancelled) onUnavailable(value);
      },
      onDeviceLost: (value) => {
        if (!cancelled) onDeviceLost(value);
      },
      forceWebGL
    }).then((engine) => {
      if (cancelled) {
        engine.dispose();
      } else {
        engineRef.current = engine;
        engine.setPaused(pausedRef.current);
      }
    });
    return () => {
      cancelled = true;
      engineRef.current?.dispose();
      engineRef.current = null;
    };
  }, [settings, forceWebGL]);

  useEffect(() => {
    engineRef.current?.setPaused(paused);
  }, [paused]);

  useEffect(() => {
    const handleMove = (event: PointerEvent) => {
      const x = (event.clientX / Math.max(1, innerWidth) - 0.5) * 2;
      const y = (event.clientY / Math.max(1, innerHeight) - 0.5) * 2;
      engineRef.current?.setPointer(x, y);
    };
    globalThis.addEventListener("pointermove", handleMove, { passive: true });
    return () => globalThis.removeEventListener("pointermove", handleMove);
  }, []);

  return <canvas ref={canvasRef} />;
}
