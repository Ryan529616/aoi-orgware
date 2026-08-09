import type { PinnedNodePositions } from "./graph-layout";

const STORAGE_KEY = "aoi.dashboard.graph-positions.v1";

function scope(companyId: string, profileId: string): string {
  return `${companyId}::${profileId}`;
}

function readAll(): Record<string, PinnedNodePositions> {
  try {
    const source = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (!source) return {};
    const parsed: unknown = JSON.parse(source);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, PinnedNodePositions>)
      : {};
  } catch {
    return {};
  }
}

export function readPinnedNodePositions(
  companyId: string,
  profileId: string
): PinnedNodePositions {
  const raw = readAll()[scope(companyId, profileId)] ?? {};
  return Object.fromEntries(
    Object.entries(raw).filter(
      ([, position]) =>
        position &&
        Number.isFinite(position.x) &&
        Number.isFinite(position.y) &&
        Math.abs(position.x) <= 10_000 &&
        Math.abs(position.y) <= 10_000
    )
  );
}

export function writePinnedNodePositions(
  companyId: string,
  profileId: string,
  positions: PinnedNodePositions
): void {
  const all = readAll();
  all[scope(companyId, profileId)] = positions;
  globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(all));
}

export function clearPinnedNodePositions(
  companyId: string,
  profileId: string
): void {
  const all = readAll();
  delete all[scope(companyId, profileId)];
  globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(all));
}
