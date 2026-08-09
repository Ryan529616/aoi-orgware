import { useEffect, useState } from "react";

export type VisualActivityReason =
  | "active"
  | "unfocused"
  | "hidden"
  | "automation"
  | "suspended";

export interface VisualActivityState {
  paused: boolean;
  reason: VisualActivityReason;
}

export interface VisualActivityOptions {
  automated?: boolean;
  pauseWhenAutomated?: boolean;
  allowAutomatedVisuals?: boolean;
  lifecycleSuspended?: boolean;
}

export function deriveVisualActivity(
  pauseWhenUnfocused: boolean,
  visibilityState: DocumentVisibilityState,
  hasFocus: boolean,
  options: VisualActivityOptions = {}
): VisualActivityState {
  if (options.lifecycleSuspended) return { paused: true, reason: "suspended" };
  if (
    options.automated &&
    options.pauseWhenAutomated !== false &&
    !options.allowAutomatedVisuals
  ) {
    return { paused: true, reason: "automation" };
  }
  if (!pauseWhenUnfocused) return { paused: false, reason: "active" };
  if (visibilityState !== "visible") return { paused: true, reason: "hidden" };
  if (!hasFocus) return { paused: true, reason: "unfocused" };
  return { paused: false, reason: "active" };
}

function readActivity(
  pauseWhenUnfocused: boolean,
  pauseWhenAutomated: boolean,
  lifecycleSuspended = false
): VisualActivityState {
  return deriveVisualActivity(
    pauseWhenUnfocused,
    document.visibilityState,
    document.hasFocus(),
    {
      automated: navigator.webdriver,
      pauseWhenAutomated,
      allowAutomatedVisuals:
        new URLSearchParams(globalThis.location?.search ?? "").get(
          "automationVisuals"
        ) === "1",
      lifecycleSuspended
    }
  );
}

export function useVisualActivity(
  pauseWhenUnfocused: boolean,
  pauseWhenAutomated: boolean
): VisualActivityState {
  const [activity, setActivity] = useState(() =>
    readActivity(pauseWhenUnfocused, pauseWhenAutomated)
  );

  useEffect(() => {
    let lifecycleSuspended = false;
    const update = () =>
      setActivity(
        readActivity(
          pauseWhenUnfocused,
          pauseWhenAutomated,
          lifecycleSuspended
        )
      );
    const suspend = () => {
      lifecycleSuspended = true;
      update();
    };
    const resume = () => {
      lifecycleSuspended = false;
      update();
    };
    update();
    document.addEventListener("visibilitychange", update);
    document.addEventListener("freeze", suspend);
    document.addEventListener("resume", resume);
    globalThis.addEventListener("focus", update);
    globalThis.addEventListener("blur", update);
    globalThis.addEventListener("pagehide", suspend);
    globalThis.addEventListener("pageshow", resume);
    return () => {
      document.removeEventListener("visibilitychange", update);
      document.removeEventListener("freeze", suspend);
      document.removeEventListener("resume", resume);
      globalThis.removeEventListener("focus", update);
      globalThis.removeEventListener("blur", update);
      globalThis.removeEventListener("pagehide", suspend);
      globalThis.removeEventListener("pageshow", resume);
    };
  }, [pauseWhenAutomated, pauseWhenUnfocused]);

  return activity;
}
