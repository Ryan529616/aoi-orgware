import { describe, expect, it } from "vitest";
import { makeFixtureSnapshot } from "./fixtures";
import {
  applyPinnedPositions,
  edgePath,
  nodeCollisionHalfSize,
  radialLayout,
  resolveNodeCollisions,
  semanticNodes
} from "./graph-layout";
import { defaultCompanyOsPreferences } from "./company-os-preferences";

describe("Company OS semantic graph", () => {
  const snapshot = makeFixtureSnapshot(42, 72);

  it("auto-expands attention states and separately aggregates quiet/waiting/cancelled work", () => {
    const visible = semanticNodes(snapshot.nodes, { x: 0, y: 0, scale: 0.68 }, "");
    const real = visible.filter((node) => node.kind !== "aggregate");
    const aggregates = visible.filter((node) => node.kind === "aggregate");

    expect(
      snapshot.nodes
        .filter((node) => ["active", "blocked", "needs_user", "unknown"].includes(node.status))
        .every((node) => real.some((candidate) => candidate.id === node.id))
    ).toBe(true);
    expect(aggregates.some((node) => node.status === "idle")).toBe(true);
    expect(aggregates.some((node) => node.status === "waiting")).toBe(true);
    expect(
      aggregates.some(
        (node) =>
          node.status === "cancelled" &&
          node.objective.includes("cancellation is not completion")
      )
    ).toBe(true);
    expect(real.length).toBeLessThan(snapshot.nodes.length);
  });

  it("preserves cancellation as distinct engineering and runtime truth", () => {
    const cancelled = snapshot.nodes.find((node) => node.status === "cancelled");
    expect(cancelled).toMatchObject({
      status: "cancelled",
      engineeringStatus: "cancelled",
      runtimeStatus: "stopped"
    });
    expect(cancelled?.status).not.toBe("completed");
    expect(cancelled?.status).not.toBe("idle");
    expect(cancelled?.status).not.toBe("unknown");
  });

  it("shows the exact original node set above the semantic threshold", () => {
    expect(semanticNodes(snapshot.nodes, { x: 0, y: 0, scale: 0.9 }, "")).toEqual(
      snapshot.nodes
    );
  });

  it("searches provider/model fields and retains ancestry", () => {
    const visible = semanticNodes(snapshot.nodes, { x: 0, y: 0, scale: 0.68 }, "gpt-5.6-sol");
    expect(visible.some((node) => node.id === "org:chief")).toBe(true);
    expect(visible.every((node) => node.kind !== "aggregate")).toBe(true);
  });

  it("lays out the 500-node functional fixture deterministically", () => {
    const nodes = makeFixtureSnapshot(42, 500).nodes;
    const first = radialLayout(nodes);
    const second = radialLayout(nodes);
    expect(first.nodes).toEqual(second.nodes);
    expect(first.nodes).toHaveLength(500);
    expect(first.edges.length).toBeGreaterThan(490);
  });

  it("responds deterministically to density, repulsion and link length", () => {
    const nodes = makeFixtureSnapshot(42, 72).nodes;
    const compact = radialLayout(nodes, {
      ...defaultCompanyOsPreferences.graph,
      density: 1.8,
      linkLength: 120,
      repulsion: 0
    });
    const spacious = radialLayout(nodes, {
      ...defaultCompanyOsPreferences.graph,
      density: 0.6,
      linkLength: 320,
      repulsion: 1400
    });
    const extent = (layout: typeof compact) =>
      Math.max(...layout.nodes.map((node) => Math.hypot(node.x, node.y)));
    expect(extent(spacious)).toBeGreaterThan(extent(compact) * 2);
    expect(radialLayout(nodes, defaultCompanyOsPreferences.graph)).toEqual(
      radialLayout(nodes, defaultCompanyOsPreferences.graph)
    );
  });

  it("packs the automatic layout without rectangular node overlap", () => {
    const nodes = makeFixtureSnapshot(42, 72).nodes;
    const visible = semanticNodes(nodes, { x: 0, y: 0, scale: 0.68 }, "");
    const layout = radialLayout(visible);
    const overlaps = layout.nodes.flatMap((left, leftIndex) =>
      layout.nodes.slice(leftIndex + 1).flatMap((right) => {
        const leftSize = nodeCollisionHalfSize(left);
        const rightSize = nodeCollisionHalfSize(right);
        return (
          Math.abs(right.x - left.x) <
              leftSize.width + rightSize.width &&
          Math.abs(right.y - left.y) <
            leftSize.height + rightSize.height
        )
          ? [`${left.node.id}|${right.node.id}`]
          : [];
      })
    );
    expect(overlaps).toEqual([]);
  });

  it("moves pinned nodes and keeps their edge endpoints synchronized", () => {
    const layout = radialLayout(makeFixtureSnapshot(42, 72).nodes);
    const target = layout.edges[0].target.node.id;
    const pinned = applyPinnedPositions(layout, {
      [target]: { x: 777, y: -333 }
    });
    const node = pinned.nodes.find((candidate) => candidate.node.id === target);
    const edge = pinned.edges.find((candidate) => candidate.target.node.id === target);
    expect(node).toMatchObject({ x: 777, y: -333 });
    expect(edge?.target).toBe(node);
  });

  it("pushes a colliding node away from a fixed dragged node", () => {
    const layout = radialLayout(makeFixtureSnapshot(42, 18).nodes);
    const edge = layout.edges[0];
    const overlapped = applyPinnedPositions(layout, {
      [edge.target.node.id]: {
        x: edge.source.x + 2,
        y: edge.source.y + 2
      }
    });
    const fixed = new Set([edge.source.node.id]);
    const result = resolveNodeCollisions(
      overlapped,
      fixed,
      defaultCompanyOsPreferences.graph
    );
    const source = result.layout.nodes.find(
      (item) => item.node.id === edge.source.node.id
    )!;
    const target = result.layout.nodes.find(
      (item) => item.node.id === edge.target.node.id
    )!;
    const resolvedEdge = result.layout.edges.find(
      (item) => item.id === edge.id
    )!;

    expect(result.collisionCount).toBeGreaterThan(0);
    const sourceSize = nodeCollisionHalfSize(source);
    const targetSize = nodeCollisionHalfSize(target);
    expect(
      Math.abs(target.x - source.x) >= sourceSize.width + targetSize.width - 2 ||
        Math.abs(target.y - source.y) >= sourceSize.height + targetSize.height - 2
    ).toBe(true);
    expect(result.displacedNodeIds.has(edge.target.node.id)).toBe(true);
    expect(resolvedEdge.source).toBe(source);
    expect(resolvedEdge.target).toBe(target);
  });

  it("resolves collisions deterministically and honors the off switch", () => {
    const layout = radialLayout(makeFixtureSnapshot(42, 18).nodes);
    const targetIds = layout.nodes.slice(1, 4).map((item) => item.node.id);
    const overlapped = applyPinnedPositions(
      layout,
      Object.fromEntries(targetIds.map((id) => [id, { x: 20, y: -20 }]))
    );
    const fixed = new Set([targetIds[0]]);
    const first = resolveNodeCollisions(
      overlapped,
      fixed,
      defaultCompanyOsPreferences.graph
    );
    const second = resolveNodeCollisions(
      overlapped,
      fixed,
      defaultCompanyOsPreferences.graph
    );
    const off = resolveNodeCollisions(overlapped, fixed, {
      ...defaultCompanyOsPreferences.graph,
      collisionEnabled: false
    });

    expect(first.layout).toEqual(second.layout);
    expect(first.collisionCount).toBe(second.collisionCount);
    expect(first.displacedNodeIds).toEqual(second.displacedNodeIds);
    expect(off.layout).toBe(overlapped);
    expect(off.collisionCount).toBe(0);
  });

  it("keeps the automatic layout stable until a user-pinned node seeds collision response", () => {
    const layout = radialLayout(makeFixtureSnapshot(42, 72).nodes);
    const result = resolveNodeCollisions(
      layout,
      new Set(),
      defaultCompanyOsPreferences.graph
    );
    expect(result.layout).toBe(layout);
    expect(result.displacedNodeIds.size).toBe(0);
    expect(result.collisionCount).toBe(0);
  });

  it("bounds collision propagation around a pinned node and never moves the Chief", () => {
    const layout = radialLayout(makeFixtureSnapshot(42, 72).nodes);
    const chief = layout.nodes.find((item) => item.node.kind === "chief")!;
    const target = layout.nodes.find((item) => item.node.id === "exec:000")!;
    const neighbor = layout.nodes.find((item) => item.node.id === "exec:001")!;
    const pinned = applyPinnedPositions(layout, {
      [target.node.id]: { x: neighbor.x, y: neighbor.y }
    });
    const result = resolveNodeCollisions(
      pinned,
      new Set([target.node.id]),
      defaultCompanyOsPreferences.graph
    );
    const resolvedChief = result.layout.nodes.find(
      (item) => item.node.id === chief.node.id
    )!;
    const maximumDelta = Math.max(
      ...result.layout.nodes.map((item) => {
        const anchor = pinned.nodes.find(
          (candidate) => candidate.node.id === item.node.id
        )!;
        return Math.hypot(item.x - anchor.x, item.y - anchor.y);
      })
    );

    expect(resolvedChief).toMatchObject({ x: chief.x, y: chief.y });
    expect(result.displacedNodeIds.size).toBeGreaterThan(0);
    expect(result.displacedNodeIds.size).toBeLessThan(18);
    expect(maximumDelta).toBeLessThanOrEqual(256.01);
  });

  it("renders PCB routing as an orthogonal circuit trace", () => {
    const edge = radialLayout(makeFixtureSnapshot(42, 72).nodes).edges[0];
    const path = edgePath(edge, "circuit");
    expect(path.startsWith("M ")).toBe(true);
    expect(path.split(" L ")).toHaveLength(4);
    expect(path).not.toContain(" C ");
  });
});
