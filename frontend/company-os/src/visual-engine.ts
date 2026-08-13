import type { VisualEngineSettingsV1 } from "./contracts";

export type RendererKind = "off" | "canvas2d" | "webgpu" | "webgl2" | "unavailable";

export interface VisualEngineStats {
  renderer: RendererKind;
  activity: "off" | "running" | "paused";
  fps: number;
  frameTime: number;
  drawCalls: number;
  particles: number;
  renderScale: number;
}

export interface VisualEngineHandle {
  dispose: () => void;
  setPointer: (x: number, y: number) => void;
  setPaused: (paused: boolean) => void;
}

interface EngineHooks {
  onStats: (stats: VisualEngineStats) => void;
  onUnavailable: (reason: string) => void;
  onDeviceLost?: (reason: string) => void;
  forceWebGL?: boolean;
}

const OFF_STATS: VisualEngineStats = {
  renderer: "off",
  activity: "off",
  fps: 0,
  frameTime: 0,
  drawCalls: 0,
  particles: 0,
  renderScale: 0
};

export async function createVisualEngine(
  canvas: HTMLCanvasElement,
  settings: VisualEngineSettingsV1,
  hooks: EngineHooks
): Promise<VisualEngineHandle> {
  if (settings.preset === "off" || settings.particles === 0) {
    hooks.onStats(OFF_STATS);
    const context = canvas.getContext("2d");
    context?.clearRect(0, 0, canvas.width, canvas.height);
    canvas.width = 1;
    canvas.height = 1;
    return {
      dispose: () => undefined,
      setPointer: () => undefined,
      setPaused: () => undefined
    };
  }

  if (settings.preset === "eco" || settings.preset === "balanced") {
    return createCanvasEngine(canvas, settings, hooks);
  }

  const query = new URLSearchParams(globalThis.location?.search ?? "");
  if (
    query.get("simulateDeviceLoss") === "1" &&
    query.get("renderer") !== "webgl2" &&
    hooks.forceWebGL !== true
  ) {
    const timer = globalThis.setTimeout(() => {
      hooks.onDeviceLost?.(
        "WebGPU device lost: deterministic renderer-abstraction test trigger"
      );
    }, 250);
    return {
      dispose: () => {
        globalThis.clearTimeout(timer);
        canvas.width = 1;
        canvas.height = 1;
      },
      setPointer: () => undefined,
      setPaused: () => undefined
    };
  }

  try {
    return await createThreeEngine(canvas, settings, hooks);
  } catch (error) {
    const threeFailure = error instanceof Error ? error.message : String(error);
    hooks.onUnavailable(threeFailure);
    return createCanvasEngine(canvas, settings, {
      ...hooks,
      onUnavailable: (canvasFailure) => {
        hooks.onUnavailable(`${threeFailure}; fallback failed: ${canvasFailure}`);
      }
    });
  }
}

function createCanvasEngine(
  canvas: HTMLCanvasElement,
  settings: VisualEngineSettingsV1,
  hooks: EngineHooks
): VisualEngineHandle {
  const context = canvas.getContext("2d", { alpha: true });
  if (!context) {
    hooks.onUnavailable("Canvas2D context is unavailable");
    hooks.onStats({ ...OFF_STATS, renderer: "unavailable" });
    return {
      dispose: () => undefined,
      setPointer: () => undefined,
      setPaused: () => undefined
    };
  }

  const budget = Math.min(settings.particles, 70_000);
  const points = new Float32Array(budget * 4);
  let seed = 0x51f15e;
  const random = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0x1_0000_0000;
  };
  for (let index = 0; index < budget; index += 1) {
    const offset = index * 4;
    points[offset] = random();
    points[offset + 1] = random();
    points[offset + 2] = 0.15 + random() * 0.85;
    points[offset + 3] = random() * Math.PI * 2;
  }

  let pointerX = 0;
  let pointerY = 0;
  let disposed = false;
  let paused = false;
  let frame = 0;
  let previous = performance.now();
  let sampledAt = previous;
  let sampledFrames = 0;
  let raf = 0;
  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    const ratio = Math.min(devicePixelRatio * settings.renderScale, 2);
    canvas.width = Math.max(1, Math.floor(rect.width * ratio));
    canvas.height = Math.max(1, Math.floor(rect.height * ratio));
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  };
  resize();
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(canvas);

  const render = (now: number) => {
    if (disposed) return;
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    context.clearRect(0, 0, width, height);
    context.globalCompositeOperation = "lighter";
    const time = now * 0.00005;
    const shown = Math.min(budget, settings.preset === "eco" ? 4_000 : 40_000);
    for (let index = 0; index < shown; index += 1) {
      const offset = index * 4;
      const depth = points[offset + 2];
      const phase = points[offset + 3] + time * (0.4 + depth);
      const x =
        ((points[offset] + time * depth) % 1) * width +
        Math.sin(phase) * 24 +
        pointerX * depth * 8;
      const y =
        points[offset + 1] * height +
        Math.cos(phase * 0.7) * 26 +
        pointerY * depth * 8;
      const alpha = 0.08 + depth * 0.3;
      context.fillStyle =
        index % 9 === 0
          ? `rgba(139,92,246,${alpha})`
          : `rgba(34,211,238,${alpha})`;
      context.fillRect(x, y, depth > 0.7 ? 1.5 : 1, depth > 0.7 ? 1.5 : 1);
    }
    context.globalCompositeOperation = "source-over";

    frame += 1;
    sampledFrames += 1;
    if (now - sampledAt >= 500) {
      hooks.onStats({
        renderer: "canvas2d",
        activity: "running",
        fps: Math.round((sampledFrames * 1000) / (now - sampledAt)),
        frameTime: Number(((now - previous) || 0).toFixed(2)),
        drawCalls: 1,
        particles: shown,
        renderScale: settings.renderScale
      });
      sampledAt = now;
      sampledFrames = 0;
    }
    previous = now;
    if (!paused) raf = requestAnimationFrame(render);
  };
  raf = requestAnimationFrame(render);

  return {
    dispose: () => {
      disposed = true;
      cancelAnimationFrame(raf);
      resizeObserver.disconnect();
      context.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = 1;
      canvas.height = 1;
    },
    setPointer: (x, y) => {
      pointerX = x;
      pointerY = y;
    },
    setPaused: (nextPaused) => {
      if (disposed || paused === nextPaused) return;
      paused = nextPaused;
      if (paused) {
        cancelAnimationFrame(raf);
        hooks.onStats({
          renderer: "canvas2d",
          activity: "paused",
          fps: 0,
          frameTime: 0,
          drawCalls: 0,
          particles: Math.min(
            budget,
            settings.preset === "eco" ? 4_000 : 40_000
          ),
          renderScale: settings.renderScale
        });
      } else {
        previous = performance.now();
        sampledAt = previous;
        sampledFrames = 0;
        raf = requestAnimationFrame(render);
      }
    }
  };
}

async function createThreeEngine(
  canvas: HTMLCanvasElement,
  settings: VisualEngineSettingsV1,
  hooks: EngineHooks
): Promise<VisualEngineHandle> {
  const THREE = await import("three/webgpu");
  const forceWebGL =
    hooks.forceWebGL === true ||
    new URLSearchParams(globalThis.location?.search ?? "").get("renderer") === "webgl2";
  const renderer = new THREE.WebGPURenderer({
    canvas,
    alpha: true,
    antialias: settings.preset === "ultra",
    forceWebGL,
    powerPreference: settings.highPerformanceHint ? "high-performance" : "default"
  } as ConstructorParameters<typeof THREE.WebGPURenderer>[0]);
  renderer.setClearColor(0x000000, 0);
  await renderer.init();
  const defaultDeviceLost = renderer.onDeviceLost.bind(renderer);
  renderer.onDeviceLost = (info) => {
    if (info.reason !== "test") defaultDeviceLost(info);
    hooks.onDeviceLost?.(`${info.api} device lost: ${info.message}`);
  };
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x050710, 0.006);
  const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 200);
  camera.position.set(0, 0, 34);

  const particleCount = Math.max(1, Math.min(settings.particles, 2_000_000));
  const positions = new Float32Array(particleCount * 3);
  const colors = new Float32Array(particleCount * 3);
  let state = 0xc0ffee;
  const random = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };

  for (let index = 0; index < particleCount; index += 1) {
    const offset = index * 3;
    const radius = 4 + Math.pow(random(), 0.58) * 45;
    const angle = random() * Math.PI * 2;
    const band = (random() - 0.5) * 16;
    positions[offset] = Math.cos(angle) * radius;
    positions[offset + 1] = Math.sin(angle) * radius * 0.62 + band;
    positions[offset + 2] = (random() - 0.5) * 36;
    const violet = index % 13 === 0 || random() > 0.93;
    colors[offset] = violet ? 0.55 : 0.05;
    colors[offset + 1] = violet ? 0.22 : 0.76;
    colors[offset + 2] = violet ? 1 : 0.98;
  }

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  const material = new THREE.PointsMaterial({
    size: settings.preset === "ultra" ? 0.032 : 0.046,
    sizeAttenuation: true,
    transparent: true,
    opacity: Math.min(0.28, 0.12 + settings.bloom * 0.08),
    vertexColors: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false
  });
  const cloud = new THREE.Points(geometry, material);
  scene.add(cloud);

  const coreGeometry = new THREE.RingGeometry(5.4, 5.46, 192);
  const coreMaterial = new THREE.MeshBasicMaterial({
    color: 0x8b5cf6,
    transparent: true,
    opacity: 0.22 + settings.bloom * 0.09,
    blending: THREE.AdditiveBlending,
    side: THREE.DoubleSide,
    depthWrite: false
  });
  const coreRing = new THREE.Mesh(coreGeometry, coreMaterial);
  scene.add(coreRing);

  const flowGeometry = new THREE.TorusGeometry(10.4, 0.022, 8, 256);
  const flowMaterial = new THREE.MeshBasicMaterial({
    color: 0x22d3ee,
    transparent: true,
    opacity: 0.22,
    blending: THREE.AdditiveBlending,
    depthWrite: false
  });
  const flowRing = new THREE.Mesh(flowGeometry, flowMaterial);
  flowRing.scale.y = 0.62;
  scene.add(flowRing);

  let disposed = false;
  let paused = false;
  let pointerX = 0;
  let pointerY = 0;
  let sampledAt = performance.now();
  let sampledFrames = 0;
  let lastFrame = sampledAt;
  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    const ratio = Math.min(devicePixelRatio * settings.renderScale, 3);
    renderer.setPixelRatio(ratio);
    renderer.setSize(Math.max(1, rect.width), Math.max(1, rect.height), false);
    camera.aspect = Math.max(0.1, rect.width / Math.max(1, rect.height));
    camera.updateProjectionMatrix();
  };
  resize();
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(canvas);

  const backendName = forceWebGL || !("gpu" in navigator) ? "webgl2" : "webgpu";
  const render = (now: number) => {
    if (disposed) return;
    const seconds = now * 0.001;
    cloud.rotation.z = seconds * 0.007;
    cloud.rotation.x = Math.sin(seconds * 0.07) * 0.035;
    flowRing.rotation.z = -seconds * 0.025;
    coreRing.scale.setScalar(1 + Math.sin(seconds * 0.8) * 0.018);
    camera.position.x += (pointerX * 2.2 - camera.position.x) * 0.018;
    camera.position.y += (-pointerY * 1.6 - camera.position.y) * 0.018;
    camera.lookAt(0, 0, 0);
    renderer.render(scene, camera);

    sampledFrames += 1;
    if (now - sampledAt >= 500) {
      hooks.onStats({
        renderer: backendName,
        activity: "running",
        fps: Math.round((sampledFrames * 1000) / (now - sampledAt)),
        frameTime: Number((now - lastFrame).toFixed(2)),
        drawCalls: 3,
        particles: particleCount,
        renderScale: settings.renderScale
      });
      sampledAt = now;
      sampledFrames = 0;
    }
    lastFrame = now;
  };
  renderer.setAnimationLoop(render);

  return {
    dispose: () => {
      disposed = true;
      resizeObserver.disconnect();
      renderer.setAnimationLoop(null);
      scene.remove(cloud, coreRing, flowRing);
      geometry.dispose();
      material.dispose();
      coreGeometry.dispose();
      coreMaterial.dispose();
      flowGeometry.dispose();
      flowMaterial.dispose();
      renderer.dispose();
      canvas.width = 1;
      canvas.height = 1;
      hooks.onStats(OFF_STATS);
    },
    setPointer: (x, y) => {
      pointerX = x;
      pointerY = y;
    },
    setPaused: (nextPaused) => {
      if (disposed || paused === nextPaused) return;
      paused = nextPaused;
      if (paused) {
        renderer.setAnimationLoop(null);
        hooks.onStats({
          renderer: backendName,
          activity: "paused",
          fps: 0,
          frameTime: 0,
          drawCalls: 0,
          particles: particleCount,
          renderScale: settings.renderScale
        });
      } else {
        sampledAt = performance.now();
        lastFrame = sampledAt;
        sampledFrames = 0;
        renderer.setAnimationLoop(render);
      }
    }
  };
}
