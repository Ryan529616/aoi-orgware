import type { DashboardNodeV1, ViewTransform } from "./contracts";
import {
  defaultCompanyOsPreferences,
  type CompanyOsGraphPreferencesV1
} from "./company-os-preferences";

export interface PositionedNode {
  node: DashboardNodeV1;
  x: number;
  y: number;
  depth: number;
  angle: number;
}

export interface PositionedEdge {
  id: string;
  source: PositionedNode;
  target: PositionedNode;
}

export interface NodePosition {
  x: number;
  y: number;
}

export type PinnedNodePositions = Record<string, NodePosition>;

export interface CollisionResolution {
  layout: ReturnType<typeof radialLayout>;
  displacedNodeIds: Set<string>;
  collisionCount: number;
}

export interface NodeCollisionHalfSize {
  width: number;
  height: number;
}

const ALWAYS_VISIBLE = new Set(["active", "blocked", "needs_user", "unknown"]);

export function semanticNodes(
  nodes: DashboardNodeV1[],
  transform: ViewTransform,
  search: string
): DashboardNodeV1[] {
  const normalized = search.trim().toLowerCase();
  if (normalized) {
    const matches = new Set(
      nodes
        .filter((node) =>
          [
            node.name,
            node.id,
            node.role,
            node.objective,
            node.department,
            node.status,
            node.provider,
            node.model,
            node.evidenceClass
          ]
            .filter(Boolean)
            .some((value) => String(value).toLowerCase().includes(normalized))
        )
        .map((node) => node.id)
    );
    nodes.forEach((node) => {
      if (matches.has(node.id)) {
        let parent = node.parentId;
        while (parent) {
          matches.add(parent);
          parent = nodes.find((candidate) => candidate.id === parent)?.parentId ?? null;
        }
      }
    });
    return nodes.filter((node) => matches.has(node.id));
  }

  if (transform.scale >= 0.82) return nodes;
  const visible = nodes.filter(
    (node) =>
      node.kind === "chief" ||
      node.kind === "department" ||
      ALWAYS_VISIBLE.has(node.status)
  );
  const collapsedByDepartment = new Map<
    string,
    {
      quiet: DashboardNodeV1[];
      waiting: DashboardNodeV1[];
      cancelled: DashboardNodeV1[];
    }
  >();
  nodes.forEach((node) => {
    if (visible.includes(node) || !node.department) return;
    const collapsed = collapsedByDepartment.get(node.department) ?? {
      quiet: [],
      waiting: [],
      cancelled: []
    };
    if (["idle", "completed"].includes(node.status)) collapsed.quiet.push(node);
    if (node.status === "waiting") collapsed.waiting.push(node);
    if (node.status === "cancelled") collapsed.cancelled.push(node);
    collapsedByDepartment.set(node.department, collapsed);
  });
  collapsedByDepartment.forEach((collapsed, department) => {
    const parent = nodes.find(
      (node) => node.kind === "department" && node.department === department
    );
    if (!parent) return;
    (
      [
        {
          key: "quiet",
          members: collapsed.quiet,
          status: "idle" as const,
          label: "quiet",
          objective: "Idle and completed executions collapsed at this zoom"
        },
        {
          key: "waiting",
          members: collapsed.waiting,
          status: "waiting" as const,
          label: "waiting",
          objective: "Waiting executions collapsed at this zoom"
        },
        {
          key: "cancelled",
          members: collapsed.cancelled,
          status: "cancelled" as const,
          label: "cancelled",
          objective:
            "Cancelled executions collapsed at this zoom; cancellation is not completion"
        }
      ] as const
    ).forEach((aggregate) => {
      if (aggregate.members.length === 0) return;
      visible.push({
        id: `ui:aggregate:${aggregate.key}:${parent.id}`,
        parentId: parent.id,
        name: `${aggregate.members.length} ${aggregate.label} execution${
          aggregate.members.length === 1 ? "" : "s"
        }`,
        role: "Aggregate",
        objective: aggregate.objective,
        kind: "aggregate",
        status: aggregate.status,
        engineeringStatus: "unknown",
        runtimeStatus: "unknown",
        coverageStatus: "unknown",
        effectStatus: "unknown",
        organizationStatus: null,
        department,
        provider: null,
        model: null,
        reason: "Semantic zoom aggregate",
        evidenceClass: null,
        usageTokens: null,
        projectionSource: "ui_semantic_aggregate",
        orphanReason: null,
        childrenCount: aggregate.members.length
      });
    });
  });
  return visible;
}

export function radialLayout(
  nodes: DashboardNodeV1[],
  tuning: CompanyOsGraphPreferencesV1 = defaultCompanyOsPreferences.graph
): {
  nodes: PositionedNode[];
  edges: PositionedEdge[];
} {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const children = new Map<string, DashboardNodeV1[]>();
  nodes.forEach((node) => {
    if (!node.parentId || !byId.has(node.parentId)) return;
    const group = children.get(node.parentId) ?? [];
    group.push(node);
    children.set(node.parentId, group);
  });
  children.forEach((group) => group.sort((a, b) => a.id.localeCompare(b.id)));

  const roots = nodes.filter((node) => !node.parentId || !byId.has(node.parentId));
  const depthOf = (node: DashboardNodeV1) => {
    let depth = 0;
    let parent = node.parentId;
    const visited = new Set<string>();
    while (parent && byId.has(parent) && !visited.has(parent) && depth < 8) {
      visited.add(parent);
      depth += 1;
      parent = byId.get(parent)?.parentId ?? null;
    }
    return depth;
  };

  const departmentNodes = nodes.filter((node) => node.kind === "department");
  const departmentAngle = new Map<string, number>();
  departmentNodes.forEach((node, index) => {
    departmentAngle.set(node.id, -Math.PI / 2 + (index / departmentNodes.length) * Math.PI * 2);
  });

  const rootDepartment = (node: DashboardNodeV1): string | null => {
    let current: DashboardNodeV1 | undefined = node;
    const visited = new Set<string>();
    while (current && !visited.has(current.id)) {
      visited.add(current.id);
      if (current.kind === "department") return current.id;
      current = current.parentId ? byId.get(current.parentId) : undefined;
    }
    return null;
  };

  const departmentMembers = new Map<string, DashboardNodeV1[]>();
  nodes.forEach((node) => {
    const department = rootDepartment(node);
    if (!department || node.kind === "department") return;
    const group = departmentMembers.get(department) ?? [];
    group.push(node);
    departmentMembers.set(department, group);
  });
  departmentMembers.forEach((group) => group.sort((a, b) => a.id.localeCompare(b.id)));

  const densityScale = 1 / Math.sqrt(tuning.density);
  const positioned: PositionedNode[] = nodes.map((node, rootIndex) => {
    const depth = depthOf(node);
    if (node.kind === "chief" || roots.includes(node)) {
      return { node, x: 0, y: 0, depth: 0, angle: 0 };
    }
    if (node.kind === "department") {
      const angle = departmentAngle.get(node.id) ?? 0;
      return {
        node,
        x: Math.cos(angle) * tuning.linkLength * 1.63 * densityScale,
        y:
          Math.sin(angle) *
          tuning.linkLength *
          1.63 *
          densityScale *
          0.78,
        depth,
        angle
      };
    }
    const department = rootDepartment(node);
    const base = department ? (departmentAngle.get(department) ?? 0) : rootIndex * 0.7;
    const members = department ? (departmentMembers.get(department) ?? []) : nodes;
    const index = Math.max(0, members.findIndex((candidate) => candidate.id === node.id));
    const lane = (index % 3) - 1;
    const ring = Math.floor(index / 3);
    const angle =
      base +
      lane * 0.34 * densityScale +
      (ring % 2 === 0 ? -0.045 : 0.045);
    const radius =
      tuning.linkLength *
      (2.92 + ring * 0.82 + Math.max(0, depth - 2)) *
      densityScale;
    return {
      node,
      x: Math.cos(angle) * radius,
      y: Math.sin(angle) * radius * 0.72,
      depth,
      angle
    };
  });

  relaxOverlaps(positioned, tuning);

  const positionById = new Map(positioned.map((item) => [item.node.id, item]));
  const edges = positioned.flatMap((target) => {
    if (!target.node.parentId) return [];
    const source = positionById.get(target.node.parentId);
    if (!source) return [];
    return [{ id: `${source.node.id}->${target.node.id}`, source, target }];
  });
  return { nodes: positioned, edges };
}

export function applyPinnedPositions(
  layout: ReturnType<typeof radialLayout>,
  pinned: PinnedNodePositions
): ReturnType<typeof radialLayout> {
  const nodes = layout.nodes.map((item) => {
    const position = pinned[item.node.id];
    return position ? { ...item, x: position.x, y: position.y } : item;
  });
  const byId = new Map(nodes.map((item) => [item.node.id, item]));
  const edges = layout.edges.map((edge) => ({
    ...edge,
    source: byId.get(edge.source.node.id) ?? edge.source,
    target: byId.get(edge.target.node.id) ?? edge.target
  }));
  return { nodes, edges };
}

export function resolveNodeCollisions(
  layout: ReturnType<typeof radialLayout>,
  fixedNodeIds: ReadonlySet<string>,
  tuning: CompanyOsGraphPreferencesV1
): CollisionResolution {
  if (
    !tuning.collisionEnabled ||
    layout.nodes.length < 2 ||
    fixedNodeIds.size === 0
  ) {
    return {
      layout,
      displacedNodeIds: new Set<string>(),
      collisionCount: 0
    };
  }

  const nodes = layout.nodes.map((item) => ({ ...item }));
  const anchors = new Map(
    nodes.map((item) => [item.node.id, { x: item.x, y: item.y }])
  );
  const displacedNodeIds = new Set<string>();
  const resolvedPairs = new Set<string>();
  const influenceDepth = new Map<string, number>();
  fixedNodeIds.forEach((nodeId) => {
    if (anchors.has(nodeId)) influenceDepth.set(nodeId, 0);
  });
  const cellSize = 320;
  const iterations = nodes.length > 250 ? 7 : 10;
  const maximumCascadeDepth = nodes.length > 250 ? 1 : 2;
  const response = 0.22 + tuning.collisionStrength * 0.18;
  const gap = 10 + tuning.collisionStrength * 8;
  const maximumDisplacement = 130 + tuning.collisionStrength * 140;

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    let movedThisIteration = false;
    const cells = new Map<string, number[]>();
    nodes.forEach((item, index) => {
      const cellX = Math.floor(item.x / cellSize);
      const cellY = Math.floor(item.y / cellSize);
      const key = `${cellX}:${cellY}`;
      const members = cells.get(key) ?? [];
      members.push(index);
      cells.set(key, members);
    });

    nodes.forEach((left, leftIndex) => {
      const cellX = Math.floor(left.x / cellSize);
      const cellY = Math.floor(left.y / cellSize);
      for (let offsetY = -1; offsetY <= 1; offsetY += 1) {
        for (let offsetX = -1; offsetX <= 1; offsetX += 1) {
          const members = cells.get(`${cellX + offsetX}:${cellY + offsetY}`) ?? [];
          members.forEach((rightIndex) => {
            if (rightIndex <= leftIndex) return;
            const right = nodes[rightIndex];
            const leftDepth = influenceDepth.get(left.node.id);
            const rightDepth = influenceDepth.get(right.node.id);
            if (leftDepth === undefined && rightDepth === undefined) return;
            if (
              leftDepth === undefined &&
              (rightDepth ?? maximumCascadeDepth) >= maximumCascadeDepth
            ) {
              return;
            }
            if (
              rightDepth === undefined &&
              (leftDepth ?? maximumCascadeDepth) >= maximumCascadeDepth
            ) {
              return;
            }

            const separation = collisionSeparation(left, right, gap);
            if (!separation) return;
            const leftPriority = collisionPriority(
              left,
              fixedNodeIds,
              leftDepth !== undefined
            );
            const rightPriority = collisionPriority(
              right,
              fixedNodeIds,
              rightDepth !== undefined
            );
            if (leftPriority === rightPriority && leftPriority >= 2) return;

            const pairKey =
              left.node.id < right.node.id
                ? `${left.node.id}|${right.node.id}`
                : `${right.node.id}|${left.node.id}`;
            const push = separation.penetration * response;
            const leftShare =
              leftPriority > rightPriority
                ? 0
                : leftPriority < rightPriority
                  ? 1
                  : 0.5;
            const rightShare =
              rightPriority > leftPriority
                ? 0
                : rightPriority < leftPriority
                  ? 1
                  : 0.5;
            const leftMoved = moveWithinAnchor(
              left,
              -separation.x * push * leftShare,
              -separation.y * push * leftShare,
              anchors,
              maximumDisplacement
            );
            const rightMoved = moveWithinAnchor(
              right,
              separation.x * push * rightShare,
              separation.y * push * rightShare,
              anchors,
              maximumDisplacement
            );
            if (!leftMoved && !rightMoved) return;

            resolvedPairs.add(pairKey);
            movedThisIteration = true;
            if (leftMoved) {
              displacedNodeIds.add(left.node.id);
              if (leftDepth === undefined && rightDepth !== undefined) {
                influenceDepth.set(left.node.id, rightDepth + 1);
              }
            }
            if (rightMoved) {
              displacedNodeIds.add(right.node.id);
              if (rightDepth === undefined && leftDepth !== undefined) {
                influenceDepth.set(right.node.id, leftDepth + 1);
              }
            }
          });
        }
      }
    });
    if (!movedThisIteration) break;
  }

  displacedNodeIds.forEach((nodeId) => {
    const item = nodes.find((candidate) => candidate.node.id === nodeId);
    const anchor = anchors.get(nodeId);
    if (!item || !anchor || Math.hypot(item.x - anchor.x, item.y - anchor.y) >= 0.5) {
      return;
    }
    displacedNodeIds.delete(nodeId);
  });

  return {
    layout: rebuildEdges(layout, nodes),
    displacedNodeIds,
    collisionCount: resolvedPairs.size
  };
}

function relaxOverlaps(
  nodes: PositionedNode[],
  tuning: CompanyOsGraphPreferencesV1
): void {
  if (tuning.repulsion <= 0 || nodes.length < 2) return;
  const strength = tuning.repulsion / 720;
  const iterations = nodes.length > 250 ? 12 : nodes.length > 100 ? 24 : 42;
  const response = 0.42 + Math.min(1.8, strength) * 0.08;
  const gap = 6 + Math.min(12, strength * 6);

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
      const left = nodes[leftIndex];
      for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
        const right = nodes[rightIndex];
        const separation = collisionSeparation(left, right, gap);
        if (!separation) continue;
        const push = separation.penetration * response;
        const leftFixed = left.node.kind === "chief";
        const rightFixed = right.node.kind === "chief";
        const divisor = leftFixed || rightFixed ? 1 : 2;
        if (!leftFixed) {
          left.x -= (separation.x * push) / divisor;
          left.y -= (separation.y * push) / divisor;
        }
        if (!rightFixed) {
          right.x += (separation.x * push) / divisor;
          right.y += (separation.y * push) / divisor;
        }
      }
    }
  }
  packNearestOpenPosition(nodes, gap);
}

export function nodeCollisionHalfSize(
  item: PositionedNode
): NodeCollisionHalfSize {
  if (item.node.kind === "chief") return { width: 135, height: 71 };
  if (item.node.kind === "department") return { width: 110, height: 53 };
  if (item.node.kind === "aggregate") return { width: 84, height: 32 };
  return { width: 98, height: 46 };
}

function collisionSeparation(
  left: PositionedNode,
  right: PositionedNode,
  gap: number
): { x: number; y: number; penetration: number } | null {
  const leftSize = nodeCollisionHalfSize(left);
  const rightSize = nodeCollisionHalfSize(right);
  const dx = right.x - left.x;
  const dy = right.y - left.y;
  const desiredX = leftSize.width + rightSize.width + gap;
  const desiredY = leftSize.height + rightSize.height + gap;
  const overlapX = desiredX - Math.abs(dx);
  const overlapY = desiredY - Math.abs(dy);
  if (overlapX <= 0 || overlapY <= 0) return null;

  const angle = deterministicPairAngle(left.node.id, right.node.id);
  if (overlapX / desiredX <= overlapY / desiredY) {
    return {
      x: dx === 0 ? (Math.cos(angle) >= 0 ? 1 : -1) : Math.sign(dx),
      y: 0,
      penetration: overlapX
    };
  }
  return {
    x: 0,
    y: dy === 0 ? (Math.sin(angle) >= 0 ? 1 : -1) : Math.sign(dy),
    penetration: overlapY
  };
}

function collisionPriority(
  item: PositionedNode,
  fixedNodeIds: ReadonlySet<string>,
  influenced: boolean
): number {
  if (item.node.kind === "chief") return 3;
  if (fixedNodeIds.has(item.node.id)) return 2;
  return influenced ? 1 : 0;
}

function moveWithinAnchor(
  item: PositionedNode,
  deltaX: number,
  deltaY: number,
  anchors: ReadonlyMap<string, NodePosition>,
  maximumDisplacement: number
): boolean {
  if (Math.abs(deltaX) < 0.001 && Math.abs(deltaY) < 0.001) return false;
  const anchor = anchors.get(item.node.id);
  if (!anchor) return false;
  const previousX = item.x;
  const previousY = item.y;
  item.x += deltaX;
  item.y += deltaY;
  const distance = Math.hypot(item.x - anchor.x, item.y - anchor.y);
  if (distance > maximumDisplacement) {
    const scale = maximumDisplacement / distance;
    item.x = anchor.x + (item.x - anchor.x) * scale;
    item.y = anchor.y + (item.y - anchor.y) * scale;
  }
  return Math.hypot(item.x - previousX, item.y - previousY) >= 0.001;
}

function packNearestOpenPosition(nodes: PositionedNode[], gap: number): void {
  const placed: PositionedNode[] = [];
  nodes.forEach((item) => {
    const overlaps = () =>
      placed.some((candidate) => collisionSeparation(candidate, item, gap));
    if (overlaps()) {
      const originX = item.x;
      const originY = item.y;
      for (let attempt = 1; attempt <= 4096; attempt += 1) {
        const radius = 12 + Math.sqrt(attempt) * 18;
        const angle = item.angle + attempt * 2.399963229728653;
        item.x = originX + Math.cos(angle) * radius;
        item.y = originY + Math.sin(angle) * radius * 0.8;
        if (!overlaps()) break;
      }
    }
    placed.push(item);
  });
}

function rebuildEdges(
  sourceLayout: ReturnType<typeof radialLayout>,
  nodes: PositionedNode[]
): ReturnType<typeof radialLayout> {
  const byId = new Map(nodes.map((item) => [item.node.id, item]));
  const edges = sourceLayout.edges.map((edge) => ({
    ...edge,
    source: byId.get(edge.source.node.id) ?? edge.source,
    target: byId.get(edge.target.node.id) ?? edge.target
  }));
  return { nodes, edges };
}

function deterministicPairAngle(leftId: string, rightId: string): number {
  let hash = 2166136261;
  for (const character of `${leftId}|${rightId}`) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return ((hash >>> 0) / 0xffffffff) * Math.PI * 2;
}

export function edgePath(
  edge: PositionedEdge,
  routing: "curve" | "circuit" = "curve"
): string {
  const { source, target } = edge;
  if (routing === "circuit") {
    const deltaX = target.x - source.x;
    const deltaY = target.y - source.y;
    if (Math.abs(deltaX) >= Math.abs(deltaY)) {
      const midX = source.x + deltaX / 2;
      return `M ${source.x} ${source.y} L ${midX} ${source.y} L ${midX} ${target.y} L ${target.x} ${target.y}`;
    }
    const midY = source.y + deltaY / 2;
    return `M ${source.x} ${source.y} L ${source.x} ${midY} L ${target.x} ${midY} L ${target.x} ${target.y}`;
  }
  const midX = (source.x + target.x) / 2;
  const midY = (source.y + target.y) / 2;
  const curvature = 0.18;
  const controlA = {
    x: source.x + (midX - source.x) * (1 + curvature),
    y: source.y + (midY - source.y) * (1 + curvature)
  };
  const controlB = {
    x: target.x + (midX - target.x) * (1 + curvature),
    y: target.y + (midY - target.y) * (1 + curvature)
  };
  return `M ${source.x} ${source.y} C ${controlA.x} ${controlA.y}, ${controlB.x} ${controlB.y}, ${target.x} ${target.y}`;
}
