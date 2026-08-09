import { describe, expect, it } from "vitest";
import { derivePanelTextScale, resizePanelFromDelta } from "./ResizablePanel";

describe("resizable dashboard panels", () => {
  it("grows a top-left anchored inspector against its fixed right/bottom edges", () => {
    expect(
      resizePanelFromDelta(
        { width: 480, height: 720 },
        -120,
        -80,
        "top-left",
        { minWidth: 380, minHeight: 420, maxWidth: 900, maxHeight: 1200 }
      )
    ).toEqual({ width: 600, height: 800 });
  });

  it("clamps panel dimensions to viewport-safe bounds", () => {
    expect(
      resizePanelFromDelta(
        { width: 700, height: 500 },
        1000,
        1000,
        "bottom-right",
        { minWidth: 520, minHeight: 320, maxWidth: 900, maxHeight: 700 }
      )
    ).toEqual({ width: 900, height: 700 });
  });

  it("increases text with panel area without shrinking below the readable default", () => {
    expect(
      derivePanelTextScale(
        { width: 720, height: 900 },
        { width: 480, height: 720 },
        1.1,
        1.5
      )
    ).toBeGreaterThan(1.1);
    expect(
      derivePanelTextScale(
        { width: 320, height: 400 },
        { width: 480, height: 720 },
        1.1,
        1.5
      )
    ).toBe(1.1);
  });
});
