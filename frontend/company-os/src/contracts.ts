export type NodeStatus =
  | "active"
  | "blocked"
  | "needs_user"
  | "waiting"
  | "unknown"
  | "idle"
  | "completed"
  | "cancelled";

export type EngineeringStatusV1 =
  | "active"
  | "idle"
  | "waiting"
  | "blocked"
  | "completed"
  | "cancelled"
  | "unknown";

export type RuntimeStatusV1 =
  | "running"
  | "telemetry_silent"
  | "confirmed_lost"
  | "stopped"
  | "unknown";

export type CoverageStatusV1 = "complete" | "degraded" | "unknown";
export type EffectStatusV1 =
  | "none"
  | "failed_known"
  | "effect_unknown"
  | "unknown";

export type NodeKind = "chief" | "department" | "execution" | "job" | "aggregate";
export type ColorMode = "auto" | "light" | "dark";
export type GpuPreset = "off" | "eco" | "balanced" | "cinematic" | "ultra";
export type PluginSelectorV1 = `${string}@${string}`;

export interface DashboardNodeV1 {
  id: string;
  parentId: string | null;
  name: string;
  role: string;
  objective: string;
  kind: NodeKind;
  status: NodeStatus;
  engineeringStatus: EngineeringStatusV1;
  runtimeStatus: RuntimeStatusV1;
  coverageStatus: CoverageStatusV1;
  effectStatus: EffectStatusV1;
  organizationStatus: string | null;
  department: string | null;
  provider: string | null;
  model: string | null;
  reason: string | null;
  evidenceClass: string | null;
  usageTokens: number | null;
  projectionSource: string;
  orphanReason: string | null;
  childrenCount?: number;
}

export interface DashboardAttentionV1 {
  id: string;
  nodeId: string | null;
  severity: "critical" | "warning" | "info";
  kind: "blocked" | "needs_user" | "unknown" | "coverage" | "effect" | "orphan";
  title: string;
  detail: string;
}

export interface DashboardSnapshotV1 {
  schemaVersion: 1;
  companyId: string;
  companyName: string;
  cursor: number;
  generatedAt: string;
  completeness: "complete" | "partial" | "unknown";
  mode: "live" | "historical";
  nodes: DashboardNodeV1[];
  attention: DashboardAttentionV1[];
}

export interface FontFaceV1 {
  family: string;
  src: string;
  weight?: string;
  style?: string;
}

export interface RegionBaseV1 {
  id: string;
  className?: string;
  visible?: boolean;
}

export interface GridRegionV1 extends RegionBaseV1 {
  kind: "grid";
  columns: number;
  gap?: number;
  children: RegionV1[];
}

export interface CanvasItemV1 {
  region: RegionV1;
  x: number;
  y: number;
  width: number;
  height: number;
  z?: number;
}

export interface CanvasRegionV1 extends RegionBaseV1 {
  kind: "canvas";
  width: number;
  height: number;
  items: CanvasItemV1[];
}

export interface SplitRegionV1 extends RegionBaseV1 {
  kind: "split";
  direction: "horizontal" | "vertical";
  ratio: number;
  first: RegionV1;
  second: RegionV1;
}

export interface TabsRegionV1 extends RegionBaseV1 {
  kind: "tabs";
  activeTab?: string;
  tabs: Array<{ id: string; label: string; region: RegionV1 }>;
}

export interface WidgetRegionV1 extends RegionBaseV1 {
  kind: "widget";
  widget: string;
  plugin?: PluginSelectorV1;
  props?: Record<string, unknown>;
}

export type RegionV1 =
  | GridRegionV1
  | CanvasRegionV1
  | SplitRegionV1
  | TabsRegionV1
  | WidgetRegionV1;

export interface VisualEngineSettingsV1 {
  preset: GpuPreset;
  particles: number;
  renderScale: number;
  bloom: number;
  depthOfField: number;
  fpsTarget: number;
  semanticEffects: boolean;
  decorativeEffects: boolean;
  highPerformanceHint: boolean;
  devHud: boolean;
}

export interface DashboardProfileV1 {
  schemaVersion: 1;
  id: string;
  name: string;
  template: string;
  colorMode: ColorMode;
  locale: "en";
  shell: { plugin: PluginSelectorV1 | null };
  layout: RegionV1;
  visualEngine: VisualEngineSettingsV1;
  typography: {
    sans: string;
    mono: string;
    fontFaces: FontFaceV1[];
  };
  customCss: string;
  plugins: Partial<Record<PluginSelectorV1, unknown>>;
}

export interface DashboardPluginManifestV1 {
  schemaVersion: 1;
  id: string;
  version: string;
  name: string;
  frontend: {
    entry: string;
    styles?: string[];
    exports: Array<"shell" | "widget" | "page" | "theme">;
  };
  pythonExtension?: PythonExtensionRefV1;
}

export interface PythonExtensionRefV1 {
  protocol: "http" | "https" | "ws" | "wss";
  endpoint: string;
  responsibility: "user_managed";
}

export interface DashboardActiveStateV1 {
  global_profile_id: string | null;
  company_bindings: Record<string, string>;
}

export interface DashboardConfigStateV1 {
  profiles: DashboardProfileV1[];
  active: DashboardActiveStateV1;
}

export interface DashboardConfigEnvelopeV1 {
  schema_version: 1;
  revision: number;
  etag: string;
  data: DashboardConfigStateV1;
}

export interface DashboardConfigBootstrapV1 extends DashboardConfigEnvelopeV1 {
  csrf_token: string;
  csrf_expires_at: string;
  session_expires_at: string;
}

export type DashboardProfileResolutionSourceV1 =
  | "company_binding"
  | "global"
  | "unconfigured";

export interface DashboardProfileResolutionV1 {
  source: DashboardProfileResolutionSourceV1;
  profile_id: string | null;
  profile: DashboardProfileV1 | null;
}

export type DashboardActiveMutationV1 =
  | {
      schema_version: 1;
      action: "set_global";
      profile_id: string | null;
    }
  | {
      schema_version: 1;
      action: "bind_company";
      company_id: string;
      profile_id: string;
    }
  | {
      schema_version: 1;
      action: "unbind_company";
      company_id: string;
    };

export interface DashboardPluginRegistryEntryV1 {
  source: "packaged_builtin";
  selector: PluginSelectorV1;
  id: string;
  version: string;
  package_receipt_sha256: string;
  manifest_url: string;
  asset_base_url: string;
  members: DashboardPackagedPluginMemberV1[];
}

export interface DashboardPackagedPluginMemberV1 {
  path: string;
  size_bytes: number;
  sha256: string;
  kind:
    | "manifest"
    | "module"
    | "stylesheet"
    | "asset"
    | "font"
    | "wasm"
    | "worker";
}

export interface DashboardPluginRegistryV1 {
  schema_version: 1;
  plugins: DashboardPluginRegistryEntryV1[];
}

export type DashboardEffectNoneErrorCodeV1 =
  | "invalid_request"
  | "invalid_json"
  | "invalid_path_segment"
  | "body_too_large"
  | "request_auth_failed"
  | "misdirected_request"
  | "method_not_allowed"
  | "precondition_required"
  | "revision_conflict"
  | "profile_not_found"
  | "company_binding_not_found"
  | "profile_in_use"
  | "limit_exceeded"
  | "config_busy"
  | "config_corrupt"
  | "internal_error";

export type DashboardEffectUnknownErrorCodeV1 =
  | "mutation_effect_unknown"
  | "durability_unknown";

interface DashboardErrorFieldsV1 {
  message: string;
  request_id: string;
}

export type DashboardErrorV1 =
  | (DashboardErrorFieldsV1 & {
      code: DashboardEffectNoneErrorCodeV1;
      effect: "none";
    })
  | (DashboardErrorFieldsV1 & {
      code: DashboardEffectUnknownErrorCodeV1;
      effect: "unknown";
    });

export interface DashboardErrorEnvelopeV1 {
  schema_version: 1;
  error: DashboardErrorV1;
}

export interface DashboardPluginContextV1 {
  apiBaseUrl: string;
  profile: DashboardProfileV1;
  snapshot: DashboardSnapshotV1;
  navigate: (route: string) => void;
  openInspector: (nodeId: string) => void;
}

export interface DashboardPluginModuleV1 {
  mount: (container: HTMLElement, context: DashboardPluginContextV1) => void | Promise<void>;
  unmount: () => void | Promise<void>;
}

export interface ViewTransform {
  x: number;
  y: number;
  scale: number;
}
