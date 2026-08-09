import { describe, expect, it, vi } from "vitest";
import {
  type CompanyEventSourceLike,
  CompanyClientError,
  createLatestSnapshotLoader,
  eventCursor,
  fetchCompanySnapshot,
  fetchHistoryCursors,
  requestedHistoricalCursor,
  subscribeCompanyEvents
} from "./live-client";

function snapshot(cursor = 7) {
  return {
    schema_version: 1,
    company_id: "company-1",
    cursor,
    generated_at: "2026-08-09T00:00:00Z",
    completeness: "complete",
    warnings: [],
    data: {
      company: { chief: { term: null } },
      departments: [],
      execution: { nodes: [], orphans: [] },
      alerts: { alerts: [], needs_user: [] }
    }
  };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

describe("live Company OS client", () => {
  it("coalesces overlapping reads and preserves the latest requested cursor", async () => {
    let releaseFirst!: () => void;
    const first = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const calls: Array<number | undefined> = [];
    const load = createLatestSnapshotLoader(async (cursor) => {
      calls.push(cursor);
      if (calls.length === 1) await first;
    });
    const running = load(4);
    expect(load(5)).toBe(running);
    expect(load()).toBe(running);
    expect(calls).toEqual([4]);
    releaseFirst();
    await running;
    expect(calls).toEqual([4, undefined]);
  });

  it("closes stale streams and requests one bounded current reset", () => {
    class FakeSource implements CompanyEventSourceLike {
      readonly listeners = new Map<string, EventListener>();
      closeCount = 0;
      addEventListener(type: string, listener: EventListener): void {
        this.listeners.set(type, listener);
      }
      close(): void {
        this.closeCount += 1;
      }
      emit(type: string, event: Event): void {
        this.listeners.get(type)?.(event);
      }
    }
    const source = new FakeSource();
    const onReset = vi.fn();
    const onCursor = vi.fn();
    const unsubscribe = subscribeCompanyEvents(9, {
      onCursor,
      onReset,
      onOpen: vi.fn(),
      onError: vi.fn(),
      onProtocolError: vi.fn()
    }, (url) => {
      expect(url).toBe("/api/v1/events?cursor=9");
      return source;
    });
    source.emit("company", { lastEventId: "10" } as MessageEvent<string>);
    expect(onCursor).toHaveBeenCalledWith(10);
    source.emit("reset_required", new Event("reset_required"));
    source.emit("reset_required", new Event("reset_required"));
    expect(onReset).toHaveBeenCalledTimes(1);
    expect(source.closeCount).toBe(1);
    unsubscribe();
    expect(source.closeCount).toBe(1);
  });

  it("uses the current snapshot route for live and exact cursor route for history", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
      json(snapshot(String(input).includes("cursor=4") ? 4 : 7))
    );
    expect((await fetchCompanySnapshot(undefined, fetchImpl)).mode).toBe("live");
    expect((await fetchCompanySnapshot(4, fetchImpl)).mode).toBe("historical");
    expect(fetchImpl.mock.calls.map(([input]) => String(input))).toEqual([
      "/api/v1/snapshot",
      "/api/v1/snapshot?cursor=4"
    ]);
    for (const [, init] of fetchImpl.mock.calls) {
      expect(init).toMatchObject({ method: "GET", cache: "no-store" });
    }
  });

  it("derives only exact history cursors without fabricating snapshots", async () => {
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => json({
      schema_version: 1,
      company_id: "company-1",
      cursor: 12,
      generated_at: "2026-08-09T00:00:00Z",
      completeness: "complete",
      warnings: [],
      data: {
        after_cursor: 0,
        transactions: [
          { cursor: 10, transaction_id: "tx-10", events: [] },
          { cursor: 11, transaction_id: "tx-11", events: [] },
          { cursor: 12, transaction_id: "tx-12", events: [] }
        ]
      }
    }));
    expect(await fetchHistoryCursors(12, fetchImpl)).toEqual([10, 11, 12]);
    expect(String(fetchImpl.mock.calls[0][0])).toBe("/api/v1/history?cursor=0");
  });

  it("rejects malformed URL and SSE cursor identities", () => {
    expect(requestedHistoricalCursor("")).toBeUndefined();
    expect(requestedHistoricalCursor("?cursor=19")).toBe(19);
    expect(() => requestedHistoricalCursor("?cursor=1&cursor=2")).toThrow(
      CompanyClientError
    );
    expect(() => requestedHistoricalCursor("?cursor=true")).toThrow(
      CompanyClientError
    );
    expect(eventCursor({ lastEventId: "21" } as MessageEvent<string>)).toBe(21);
    expect(() => eventCursor({ lastEventId: "" } as MessageEvent<string>)).toThrow(
      CompanyClientError
    );
  });

  it("fails closed on non-JSON and error responses", async () => {
    await expect(fetchCompanySnapshot(undefined, async () => new Response("no", {
      status: 200,
      headers: { "Content-Type": "text/plain" }
    }))).rejects.toThrow("non-JSON");
    await expect(fetchCompanySnapshot(undefined, async () => json({}, 503))).rejects.toThrow(
      "HTTP 503"
    );
  });
});
