/**
 * TeeReadClient — authenticated GETs for the TEE's read-only surface.
 *
 * These endpoints aren't part of the trade loop, but a strategy running on the
 * daemon wants them: account snapshot, instrument/market metadata, a batch's
 * settlement progress, node health/clock, and the transparency (reserves /
 * governance) view. The daemon exposes them via its control API so the strategy
 * reads everything through one local surface. Responses are passed through as
 * parsed JSON (`unknown`) — the daemon stays decoupled from the exact shapes,
 * which the TEE can evolve.
 */

export interface TeeReadOptions {
  gatewayUrl: string;
  token: string;
  /** REQUIRED — the CVM transport; see `OrderClientOptions.fetchImpl`. */
  fetchImpl: typeof fetch;
}

export interface TeeInstrument {
  symbol: string;
  base_mint: string;
  quote_mint: string;
  tick_size: string;
  min_order_size: string;
  /** Current market-local readiness for new place/modify/match operations. */
  trading_enabled: boolean;
  oracle: {
    type: "pyth_pull_v2" | "pyth_push_v2";
    pubkey: string;
    source: "pyth-router-quorum-v1" | "pyth-solana-push-v1";
    account?: string;
    publish_time_ms: number | null;
    age_ms: number | null;
    max_age_ms: number | null;
  };
}

/** The subset of `GET /orders/{id}` the reconciler reads. */
export interface TeeOrderStatus {
  order_id: string;
  /** Server-side lifecycle phase — the authority after a gap. */
  status?: string;
  filled_amount?: string | number;
  [k: string]: unknown;
}

export class TeeReadClient {
  constructor(private readonly opts: TeeReadOptions) {}

  private async get(path: string): Promise<unknown> {
    const f = this.opts.fetchImpl;
    const res = await f(new URL(path, this.opts.gatewayUrl).toString(), {
      headers: { authorization: `Bearer ${this.opts.token}` },
    });
    if (!res.ok) throw new Error(`${path} → ${res.status}`);
    return res.json();
  }

  /** `GET /account` — this account's open orders + snapshot. */
  account(): Promise<unknown> {
    return this.get("/account");
  }
  /** `GET /instruments` — tradable markets + their mints/tick/min-size. */
  instruments(): Promise<TeeInstrument[]> {
    return this.get("/instruments") as Promise<TeeInstrument[]>;
  }
  /** `GET /instruments/{symbol}` — one market. */
  instrument(symbol: string): Promise<TeeInstrument> {
    return this.get(
      `/instruments/${encodeURIComponent(symbol)}`,
    ) as Promise<TeeInstrument>;
  }
  /**
   * `GET /orders/{orderId}` — one order's authoritative server-side state.
   *
   * The reconciliation path's source of truth for phase (SW-11): after a stream
   * gap or a restart the daemon's local phase can be arbitrarily stale, and the
   * `orders` channel is a notifier, not a durable log.
   *
   * `null` when the order is unknown to the CVM — either it never landed or it
   * has aged out of the server's retention. Distinguished from a transport
   * failure, which throws, so a caller can tell "gone" from "cannot tell".
   */
  async order(orderId: string): Promise<TeeOrderStatus | null> {
    const f = this.opts.fetchImpl;
    const path = `/orders/${encodeURIComponent(orderId)}`;
    const res = await f(new URL(path, this.opts.gatewayUrl).toString(), {
      headers: { authorization: `Bearer ${this.opts.token}` },
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`${path} → ${res.status}`);
    return (await res.json()) as TeeOrderStatus;
  }

  /** `GET /settlement/status/{batchId}` — a settle batch's per-job progress. */
  settlementStatus(batchId: string | number): Promise<unknown> {
    // Encoded like its `instrument` sibling. `control-api.ts` feeds this an
    // arbitrary caller-controlled path segment (SW-20).
    return this.get(
      `/settlement/status/${encodeURIComponent(String(batchId))}`,
    );
  }
  /** `GET /system/status` — node health. */
  systemStatus(): Promise<unknown> {
    return this.get("/system/status");
  }
  /** `GET /time` — the TEE's clock/slot. */
  serverTime(): Promise<unknown> {
    return this.get("/time");
  }
  /** `GET /transparency` — reserves (outstanding vs vault balance) + identity. */
  transparency(): Promise<unknown> {
    return this.get("/transparency");
  }
}
