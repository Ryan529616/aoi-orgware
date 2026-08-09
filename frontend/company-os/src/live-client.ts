import type { DashboardSnapshotV1 } from "./contracts";
import { adaptCompanySnapshot, CompanySnapshotError } from "./live-adapter";

export class CompanyClientError extends Error {}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface CompanyEventSourceLike {
  addEventListener(type: string, listener: EventListener): void;
  close(): void;
}

export interface CompanyEventCallbacks {
  onCursor(cursor: number): void;
  onReset(): void;
  onOpen(): void;
  onError(): void;
  onProtocolError(error: CompanyClientError): void;
}

interface SnapshotLoadRequest {
  cursor?: number;
}

export function createLatestSnapshotLoader(
  loadOne: (cursor?: number) => Promise<void>
): (cursor?: number) => Promise<void> {
  let active: Promise<void> | null = null;
  let queued: SnapshotLoadRequest | null = null;

  return (cursor?: number): Promise<void> => {
    if (active !== null) {
      queued = { cursor };
      return active;
    }
    const drain = async (): Promise<void> => {
      let request: SnapshotLoadRequest | null = { cursor };
      while (request !== null) {
        queued = null;
        await loadOne(request.cursor);
        request = queued;
      }
    };
    active = drain().finally(() => {
      active = null;
    });
    return active;
  };
}

export function subscribeCompanyEvents(
  cursor: number,
  callbacks: CompanyEventCallbacks,
  factory: (url: string) => CompanyEventSourceLike = (url) => new EventSource(url)
): () => void {
  if (!Number.isSafeInteger(cursor) || cursor < 0) {
    throw new CompanyClientError("SSE start cursor is invalid");
  }
  const source = factory(`/api/v1/events?cursor=${cursor}`);
  let closed = false;
  const close = (): boolean => {
    if (closed) return false;
    closed = true;
    source.close();
    return true;
  };
  source.addEventListener("company", ((raw: Event) => {
    if (closed) return;
    try {
      callbacks.onCursor(eventCursor(raw as MessageEvent<string>));
    } catch (error) {
      close();
      callbacks.onProtocolError(
        error instanceof CompanyClientError
          ? error
          : new CompanyClientError("SSE cursor failed", { cause: error })
      );
    }
  }) as EventListener);
  source.addEventListener("reset_required", (() => {
    if (close()) callbacks.onReset();
  }) as EventListener);
  source.addEventListener("open", (() => {
    if (!closed) callbacks.onOpen();
  }) as EventListener);
  source.addEventListener("error", (() => {
    if (close()) callbacks.onError();
  }) as EventListener);
  return () => {
    close();
  };
}

function snapshotUrl(cursor?: number): string {
  if (cursor === undefined) return "/api/v1/snapshot";
  if (!Number.isSafeInteger(cursor) || cursor < 0) {
    throw new CompanyClientError("historical cursor must be a non-negative safe integer");
  }
  return `/api/v1/snapshot?cursor=${cursor}`;
}

async function responseJson(response: Response, label: string): Promise<unknown> {
  if (!response.ok) {
    throw new CompanyClientError(`${label} failed with HTTP ${response.status}`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new CompanyClientError(`${label} returned a non-JSON response`);
  }
  try {
    return await response.json();
  } catch (error) {
    throw new CompanyClientError(`${label} returned invalid JSON`, { cause: error });
  }
}

export async function fetchCompanySnapshot(
  cursor?: number,
  fetchImpl: FetchLike = globalThis.fetch.bind(globalThis)
): Promise<DashboardSnapshotV1> {
  const response = await fetchImpl(snapshotUrl(cursor), {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  const raw = await responseJson(response, "company snapshot");
  try {
    return adaptCompanySnapshot(raw, cursor === undefined ? "live" : "historical");
  } catch (error) {
    if (error instanceof CompanySnapshotError) {
      throw new CompanyClientError(`company snapshot contract rejected: ${error.message}`, {
        cause: error
      });
    }
    throw error;
  }
}

export async function fetchHistoryCursors(
  headCursor: number,
  fetchImpl: FetchLike = globalThis.fetch.bind(globalThis)
): Promise<number[]> {
  if (!Number.isSafeInteger(headCursor) || headCursor < 0) {
    throw new CompanyClientError("history head cursor is invalid");
  }
  const lowerBound = Math.max(0, headCursor - 255);
  const response = await fetchImpl(`/api/v1/history?cursor=${lowerBound}`, {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  const raw = await responseJson(response, "company history");
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CompanyClientError("company history envelope is invalid");
  }
  const data = (raw as Record<string, unknown>).data;
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new CompanyClientError("company history data is invalid");
  }
  const transactions = (data as Record<string, unknown>).transactions;
  if (!Array.isArray(transactions)) {
    throw new CompanyClientError("company history transactions are invalid");
  }
  const cursors = new Set<number>([headCursor]);
  transactions.forEach((value, index) => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new CompanyClientError(`company history transaction ${index} is invalid`);
    }
    const cursor = (value as Record<string, unknown>).cursor;
    if (typeof cursor !== "number" || !Number.isSafeInteger(cursor) || cursor <= lowerBound) {
      throw new CompanyClientError(`company history transaction ${index} has an invalid cursor`);
    }
    cursors.add(cursor);
  });
  return [...cursors].sort((left, right) => left - right);
}

export function requestedHistoricalCursor(search: string): number | undefined {
  const values = new URLSearchParams(search).getAll("cursor");
  if (values.length === 0) return undefined;
  if (values.length !== 1 || !/^\d+$/.test(values[0])) {
    throw new CompanyClientError("URL cursor must be one non-negative integer");
  }
  const cursor = Number(values[0]);
  if (!Number.isSafeInteger(cursor)) {
    throw new CompanyClientError("URL cursor exceeds the safe integer range");
  }
  return cursor;
}

export function eventCursor(event: MessageEvent<string>): number {
  if (!/^\d+$/.test(event.lastEventId)) {
    throw new CompanyClientError("SSE event has an invalid cursor identity");
  }
  const cursor = Number(event.lastEventId);
  if (!Number.isSafeInteger(cursor)) {
    throw new CompanyClientError("SSE cursor exceeds the safe integer range");
  }
  return cursor;
}
