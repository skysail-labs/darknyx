/**
 * Public system endpoints — `GET /system/status` (liveness / degraded-mode)
 * and `GET /time` (server slot + unix ms). Both are unauthenticated.
 *
 * `/time` is the anchor for GTT order expiry: feed its result straight into
 * `gttExpirySlot` (see `orders/builders.ts`) so a wall-clock expiry converts to
 * an `expiry_slot` without the client running its own Solana RPC.
 */

/** Wire shape of `GET /system/status` (mirrors `darknyx_tee::api::system::SystemStatus`). */
export interface SystemStatus {
  /** `true` when any market is paused or global matching/settlement readiness is down. */
  degraded: boolean;
  /** `true` when at least one configured market can still trade. */
  matcher_running: boolean;
  settle_enabled: boolean;
  oracle_configured: boolean;
  current_slot: number;
  version: string;
}

/** Wire shape of `GET /time` (mirrors `darknyx_tee::api::system::ServerTime`). */
export interface ServerTime {
  slot: number;
  /** Server unix time, milliseconds. */
  unix_ms: number;
}

/** Fetch the engine's liveness / degraded-mode snapshot. */
export async function fetchSystemStatus(
  baseUrl: string,
  opts: { fetchImpl?: typeof fetch } = {},
): Promise<SystemStatus> {
  const f = opts.fetchImpl ?? fetch;
  const res = await f(new URL("/system/status", baseUrl).toString());
  if (!res.ok)
    throw new Error(`/system/status ${res.status}: ${await res.text()}`);
  return (await res.json()) as SystemStatus;
}

/** Fetch the server's current slot + unix time (the GTT conversion anchor). */
export async function fetchServerTime(
  baseUrl: string,
  opts: { fetchImpl?: typeof fetch } = {},
): Promise<ServerTime> {
  const f = opts.fetchImpl ?? fetch;
  const res = await f(new URL("/time", baseUrl).toString());
  if (!res.ok) throw new Error(`/time ${res.status}: ${await res.text()}`);
  return (await res.json()) as ServerTime;
}
