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
  fetchImpl?: typeof fetch;
}

export interface TeeInstrument {
  symbol: string;
  base_mint: string;
  quote_mint: string;
  tick_size: string;
  min_order_size: string;
  oracle: {
    type: "pyth_pull_v2";
    pubkey: string;
  };
}

export class TeeReadClient {
  constructor(private readonly opts: TeeReadOptions) {}

  private async get(path: string): Promise<unknown> {
    const f = this.opts.fetchImpl ?? fetch;
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
  /** `GET /settlement/status/{batchId}` — a settle batch's per-job progress. */
  settlementStatus(batchId: string | number): Promise<unknown> {
    return this.get(`/settlement/status/${batchId}`);
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
