import { useCallback, useEffect, useMemo, useState } from "react";
import type { DashboardProfileV1, DashboardSnapshotV1 } from "./contracts";
import { COMPANY_OS_PREFERENCES_KEY, defaultCompanyOsPreferences } from "./company-os-preferences";
import { CommandCenter } from "./components/CommandCenter";
import {
  CompanyClientError,
  createLatestSnapshotLoader,
  fetchCompanySnapshot,
  fetchHistoryCursors,
  requestedHistoricalCursor,
  subscribeCompanyEvents
} from "./live-client";

const STATIC_PROFILE: DashboardProfileV1 = {
  schemaVersion: 1,
  id: "builtin.company-os-live",
  name: "Company OS Live",
  template: "production-read-only",
  colorMode: "auto",
  locale: "en",
  shell: { plugin: null },
  layout: {
    id: "company-os-live",
    kind: "widget",
    widget: "builtin.company-command-center"
  },
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
  typography: {
    sans: "Space Grotesk",
    mono: "JetBrains Mono",
    fontFaces: []
  },
  customCss: "",
  plugins: {
    [COMPANY_OS_PREFERENCES_KEY]: defaultCompanyOsPreferences
  }
};

type ConnectionState = "connecting" | "live" | "historical" | "degraded";

function replaceCursor(cursor?: number): void {
  const url = new URL(globalThis.location.href);
  if (cursor === undefined) url.searchParams.delete("cursor");
  else url.searchParams.set("cursor", String(cursor));
  globalThis.history.replaceState(null, "", url);
}

export default function App() {
  const [profile, setProfile] = useState<DashboardProfileV1>(STATIC_PROFILE);
  const [snapshot, setSnapshot] = useState<DashboardSnapshotV1 | null>(null);
  const [historyCursors, setHistoryCursors] = useState<number[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [failure, setFailure] = useState<string | null>(null);

  const loadOne = useCallback(async (cursor?: number) => {
    try {
      const next = await fetchCompanySnapshot(cursor);
      setSnapshot(next);
      setFailure(null);
      setConnection(next.mode === "live" ? "live" : "historical");
      replaceCursor(cursor);
      if (next.mode === "live") {
        try {
          setHistoryCursors(await fetchHistoryCursors(next.cursor));
        } catch {
          setHistoryCursors([next.cursor]);
        }
      } else {
        setHistoryCursors((current) =>
          [...new Set([...current, next.cursor])].sort((left, right) => left - right)
        );
      }
    } catch (error) {
      setConnection("degraded");
      setFailure(error instanceof Error ? error.message : "Company snapshot failed");
    }
  }, []);
  const load = useMemo(() => createLatestSnapshotLoader(loadOne), [loadOne]);

  useEffect(() => {
    try {
      void load(requestedHistoricalCursor(globalThis.location.search));
    } catch (error) {
      setConnection("degraded");
      setFailure(error instanceof Error ? error.message : "URL cursor is invalid");
    }
  }, [load]);

  useEffect(() => {
    if (!snapshot || snapshot.mode !== "live" || typeof EventSource === "undefined") return;
    return subscribeCompanyEvents(snapshot.cursor, {
      onCursor: (cursor) => {
        if (cursor > snapshot.cursor) void load();
      },
      onReset: () => {
        setConnection("connecting");
        void load();
      },
      onOpen: () => setConnection("live"),
      onError: () => {
        setConnection("degraded");
        setFailure("Company event stream closed; refreshing current truth.");
        void load();
      },
      onProtocolError: (error) => {
        setConnection("degraded");
        setFailure(error instanceof CompanyClientError ? error.message : "SSE cursor failed");
      }
    });
  }, [load, snapshot]);

  useEffect(() => {
    const query = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
    const apply = () => {
      const theme = profile.colorMode === "auto"
        ? (query?.matches ? "dark" : "light")
        : profile.colorMode;
      document.documentElement.dataset.theme = theme;
      document.documentElement.dataset.motion = "off";
      document.documentElement.dataset.visualStyle = "precision-futurism";
    };
    apply();
    query?.addEventListener("change", apply);
    return () => query?.removeEventListener("change", apply);
  }, [profile.colorMode]);

  if (!snapshot) {
    return (
      <main className="shell-failure">
        <div className="failure-orb" aria-hidden="true">!</div>
        <span>READ-ONLY COMPANY SNAPSHOT</span>
        <h1>{failure ? "Company OS could not load truth." : "Connecting to Supervisor…"}</h1>
        <p>{failure ?? "Waiting for the first package-local snapshot."}</p>
        {failure ? <button type="button" onClick={() => void load()}>Retry read</button> : null}
        <a href="/">Open conservative Console</a>
      </main>
    );
  }

  return (
    <>
      {failure ? (
        <div className="live-truth-warning" role="status">
          <strong>Live refresh degraded.</strong> {failure} The last cursor remains visible.
        </div>
      ) : null}
      <CommandCenter
        profile={profile}
        snapshot={snapshot}
        historyCursors={historyCursors}
        liveCursor={historyCursors.at(-1) ?? snapshot.cursor}
        connection={connection}
        onCursorChange={(cursor) => void load(cursor ?? undefined)}
        onApplyProfile={setProfile}
      />
    </>
  );
}
