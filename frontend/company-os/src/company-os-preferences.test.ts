import { describe, expect, it } from "vitest";
import type { DashboardProfileV1 } from "./contracts";
import {
  COMPANY_OS_PREFERENCES_KEY,
  defaultCompanyOsPreferences,
  readCompanyOsPreferences,
  writeCompanyOsPreferences
} from "./company-os-preferences";

function profile(): DashboardProfileV1 {
  return {
    schemaVersion: 1,
    id: "test-profile",
    name: "Test",
    template: "test",
    colorMode: "auto",
    locale: "en",
    shell: { plugin: null },
    layout: { id: "root", kind: "widget", widget: "test" },
    visualEngine: {
      preset: "off",
      particles: 0,
      renderScale: 1,
      bloom: 0,
      depthOfField: 0,
      fpsTarget: 30,
      semanticEffects: false,
      decorativeEffects: false,
      highPerformanceHint: false,
      devHud: false
    },
    typography: { sans: "sans", mono: "mono", fontFaces: [] },
    customCss: "",
    plugins: {}
  };
}

describe("Company OS namespaced preferences", () => {
  it("uses static-safe defaults when no preference exists", () => {
    expect(readCompanyOsPreferences(profile())).toEqual(defaultCompanyOsPreferences);
  });

  it("clamps graph values and preserves unrelated opaque data", () => {
    const value = profile();
    value.plugins = {
      "other.plugin@1.0.0": { retained: true },
      [COMPANY_OS_PREFERENCES_KEY]: {
        appearance: { style: "pcb-blue" },
        graph: {
          repulsion: 9999,
          density: -1,
          linkLength: 40,
          draggableNodes: false,
          collisionEnabled: false,
          collisionStrength: 9
        },
        resourcePolicy: {
          pauseWhenUnfocused: false,
          pauseWhenAutomated: false
        }
      }
    };
    expect(readCompanyOsPreferences(value)).toEqual({
      schemaVersion: 1,
      appearance: { style: "pcb-blue" },
      graph: {
        repulsion: 1600,
        density: 0.5,
        linkLength: 100,
        draggableNodes: false,
        collisionEnabled: false,
        collisionStrength: 1.25
      },
      resourcePolicy: {
        pauseWhenUnfocused: false,
        pauseWhenAutomated: false
      }
    });
    const written = writeCompanyOsPreferences(value, defaultCompanyOsPreferences);
    expect(written.plugins["other.plugin@1.0.0"]).toEqual({ retained: true });
  });
});
