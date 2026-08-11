interface BrokerResponse {
  access_token?: unknown;
  expires_in?: unknown;
}

export interface SessionBrokerOptions {
  venueId: string;
  endpoint?: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
  origin?: string;
  timeoutMs?: number;
}

/**
 * Exchanges an opaque venue id for a short-lived bearer token through the
 * trusted application origin. Long-lived CVM credentials stay server-side.
 */
export class SameOriginSessionBroker {
  readonly #venueId: string;
  readonly #endpoint: URL;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #timeoutMs: number;
  #token = "";
  #refreshAtMs = 0;
  #inFlight: Promise<string> | null = null;
  #generation = 0;

  constructor(options: SessionBrokerOptions) {
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(options.venueId)) {
      throw new Error("venueId must be an opaque 1-64 character identifier");
    }
    const origin =
      options.origin ??
      (typeof location === "undefined" ? undefined : location.origin);
    if (!origin)
      throw new Error("session broker requires an application origin");
    const endpoint = new URL(
      options.endpoint ?? "/api/darknyx/session",
      origin,
    );
    if (endpoint.origin !== new URL(origin).origin) {
      throw new Error("session broker endpoint must be same-origin");
    }
    this.#venueId = options.venueId;
    this.#endpoint = endpoint;
    this.#fetch = options.fetchImpl ?? fetch;
    this.#now = options.now ?? Date.now;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new Error("session broker timeout must be a positive number");
    }
  }

  async establish(): Promise<void> {
    const endpoint = new URL(
      `${this.#endpoint.pathname}/start`,
      this.#endpoint,
    );
    const response = await this.#fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-darknyx-client": "browser-v1",
      },
      body: JSON.stringify({ venue_id: this.#venueId }),
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    if (response.status !== 204) {
      throw new Error(`session bootstrap refused access (${response.status})`);
    }
  }

  async token(): Promise<string> {
    if (this.#token && this.#now() < this.#refreshAtMs) return this.#token;
    if (this.#inFlight) return this.#inFlight;
    const generation = this.#generation;
    const refresh = this.#refresh(generation);
    this.#inFlight = refresh;
    try {
      return await refresh;
    } finally {
      if (this.#inFlight === refresh) this.#inFlight = null;
    }
  }

  invalidate(): void {
    this.#generation += 1;
    this.#token = "";
    this.#refreshAtMs = 0;
    this.#inFlight = null;
  }

  async #refresh(generation: number): Promise<string> {
    const response = await this.#fetch(this.#endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-darknyx-client": "browser-v1",
      },
      body: JSON.stringify({ venue_id: this.#venueId }),
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`session broker refused access (${response.status})`);
    }
    const body = (await response.json()) as BrokerResponse;
    if (
      typeof body.access_token !== "string" ||
      body.access_token.length < 32 ||
      body.access_token.length > 16_384 ||
      typeof body.expires_in !== "number" ||
      !Number.isSafeInteger(body.expires_in) ||
      body.expires_in < 30 ||
      body.expires_in > 3_600
    ) {
      throw new Error("session broker returned a malformed token envelope");
    }
    if (generation !== this.#generation) {
      throw new Error("session token refresh was invalidated");
    }
    this.#token = body.access_token;
    // Refresh after 80% of the advertised lifetime; a reconnect never races
    // the last few seconds of a token.
    this.#refreshAtMs = this.#now() + body.expires_in * 800;
    return this.#token;
  }
}
