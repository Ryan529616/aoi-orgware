import type { DashboardProfileV1 } from "./contracts";

export const COMPANY_OS_PREFERENCES_KEY = "builtin.company_os@1.0.0";

export type CompanyOsVisualStyle = "precision-futurism" | "pcb-blue";

export interface CompanyOsGraphPreferencesV1 {
  repulsion: number;
  density: number;
  linkLength: number;
  draggableNodes: boolean;
  collisionEnabled: boolean;
  collisionStrength: number;
}

export interface CompanyOsResourcePolicyV1 {
  pauseWhenUnfocused: boolean;
  pauseWhenAutomated: boolean;
}

export interface CompanyOsPreferencesV1 {
  schemaVersion: 1;
  appearance: {
    style: CompanyOsVisualStyle;
  };
  graph: CompanyOsGraphPreferencesV1;
  resourcePolicy: CompanyOsResourcePolicyV1;
}

export const defaultCompanyOsPreferences: CompanyOsPreferencesV1 = {
  schemaVersion: 1,
  appearance: {
    style: "precision-futurism"
  },
  graph: {
    repulsion: 720,
    density: 1,
    linkLength: 190,
    draggableNodes: true,
    collisionEnabled: true,
    collisionStrength: 0.9
  },
  resourcePolicy: {
    pauseWhenUnfocused: true,
    pauseWhenAutomated: true
  }
};

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function finite(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export function readCompanyOsPreferences(
  profile: DashboardProfileV1
): CompanyOsPreferencesV1 {
  const raw = profile.plugins[COMPANY_OS_PREFERENCES_KEY];
  const root = isRecord(raw) ? raw : {};
  const graph = isRecord(root.graph) ? root.graph : {};
  const appearance = isRecord(root.appearance) ? root.appearance : {};
  const resourcePolicy = isRecord(root.resourcePolicy) ? root.resourcePolicy : {};
  return {
    schemaVersion: 1,
    appearance: {
      style:
        appearance.style === "pcb-blue"
          ? "pcb-blue"
          : defaultCompanyOsPreferences.appearance.style
    },
    graph: {
      repulsion: clamp(
        finite(graph.repulsion, defaultCompanyOsPreferences.graph.repulsion),
        0,
        1600
      ),
      density: clamp(
        finite(graph.density, defaultCompanyOsPreferences.graph.density),
        0.5,
        2
      ),
      linkLength: clamp(
        finite(graph.linkLength, defaultCompanyOsPreferences.graph.linkLength),
        100,
        360
      ),
      draggableNodes:
        typeof graph.draggableNodes === "boolean"
          ? graph.draggableNodes
          : defaultCompanyOsPreferences.graph.draggableNodes,
      collisionEnabled:
        typeof graph.collisionEnabled === "boolean"
          ? graph.collisionEnabled
          : defaultCompanyOsPreferences.graph.collisionEnabled,
      collisionStrength: clamp(
        finite(
          graph.collisionStrength,
          defaultCompanyOsPreferences.graph.collisionStrength
        ),
        0.25,
        1.25
      )
    },
    resourcePolicy: {
      pauseWhenUnfocused:
        typeof resourcePolicy.pauseWhenUnfocused === "boolean"
          ? resourcePolicy.pauseWhenUnfocused
          : defaultCompanyOsPreferences.resourcePolicy.pauseWhenUnfocused,
      pauseWhenAutomated:
        typeof resourcePolicy.pauseWhenAutomated === "boolean"
          ? resourcePolicy.pauseWhenAutomated
          : defaultCompanyOsPreferences.resourcePolicy.pauseWhenAutomated
    }
  };
}

export function writeCompanyOsPreferences(
  profile: DashboardProfileV1,
  preferences: CompanyOsPreferencesV1
): DashboardProfileV1 {
  return {
    ...profile,
    plugins: {
      ...profile.plugins,
      [COMPANY_OS_PREFERENCES_KEY]: structuredClone(preferences)
    }
  };
}
