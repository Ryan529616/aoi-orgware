import { describe, expect, it } from "vitest";
import { deriveVisualActivity } from "./visual-activity";

describe("Company OS visual activity policy", () => {
  it("pauses when the window loses focus", () => {
    expect(deriveVisualActivity(true, "visible", false)).toEqual({
      paused: true,
      reason: "unfocused"
    });
  });

  it("pauses when the tab is hidden", () => {
    expect(deriveVisualActivity(true, "hidden", true)).toEqual({
      paused: true,
      reason: "hidden"
    });
  });

  it("honors an explicit continue-in-background override", () => {
    expect(deriveVisualActivity(false, "hidden", false)).toEqual({
      paused: false,
      reason: "active"
    });
  });

  it("pauses automated browsers unless a visual run is explicit", () => {
    expect(
      deriveVisualActivity(true, "visible", true, {
        automated: true,
        pauseWhenAutomated: true
      })
    ).toEqual({ paused: true, reason: "automation" });
    expect(
      deriveVisualActivity(true, "visible", true, {
        automated: true,
        pauseWhenAutomated: true,
        allowAutomatedVisuals: true
      })
    ).toEqual({ paused: false, reason: "active" });
  });

  it("always pauses a suspended page lifecycle", () => {
    expect(
      deriveVisualActivity(false, "visible", true, {
        lifecycleSuspended: true
      })
    ).toEqual({ paused: true, reason: "suspended" });
  });
});
