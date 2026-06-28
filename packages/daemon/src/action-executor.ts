/**
 * DaemonActionExecutor — the (only) CVM/SDK-aware seam of the lifecycle engine.
 *
 * The reducer (`order-lifecycle.ts`) emits intents; the engine
 * (`lifecycle-engine.ts`) hands them here; this turns them into real effects
 * and resolves with the follow-up event the engine folds back in:
 *
 *   - **top-up** → the SDK `buildAnchorTopUp` produces the *signed* request body
 *     (the daemon never re-implements that crypto), then an injected
 *     {@link AnchorTopUpPoster} `POST`s it to `/orders/{id}/anchors`. Resolves
 *     `topup-confirmed`.
 *   - **merge** → delegated to an injected {@link MergeRunner} (the on-chain
 *     VALID_MERGE consolidation, which selects residual change notes + submits
 *     the vault `merge` tx — wired in a later slice since it needs devnet).
 *     Resolves `merge-confirmed` with the count actually consumed.
 *
 * Key material + note selection are injected ({@link KeyProvider},
 * {@link MergeRunner}) so this stays pure orchestration + unit-testable with
 * fakes. On any failure it throws — the engine catches it and converts to the
 * matching `*-failed` event (clearing the in-flight latch).
 */

import { buildAnchorTopUp, NyxApiError, type AnchorTopUpBody } from "@nyx/sdk";

import type { ManagedOrder } from "./types.js";
import type { ActionExecutor } from "./lifecycle-engine.js";
import type { LifecycleAction, LifecycleEvent } from "./order-lifecycle.js";

type TopupAction = Extract<LifecycleAction, { type: "topup" }>;
type MergeAction = Extract<LifecycleAction, { type: "merge" }>;

/** Per-order signing material — derived from the keystore, never logged. */
export interface OrderKeys {
  /** 64-byte master seed (anchor inner_hashes derive from it + the order id). */
  masterSeed: Uint8Array;
  /** BN254 spending key (Fr-safe; nullifiers hash it). */
  spendingKey: bigint;
  /** 32-byte trading-key pubkey the order was placed under. */
  tradingKeyPubkey: Uint8Array;
  /** Ed25519 signer over a 32-byte digest with that trading key. */
  sign: (digest: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

/** Supplies the signing material for a managed order. */
export interface KeyProvider {
  keysForOrder(order: ManagedOrder): Promise<OrderKeys> | OrderKeys;
}

/** Transport for `POST /orders/{id}/anchors`. Resolves on success, throws otherwise. */
export interface AnchorTopUpPoster {
  post(orderIdHex: string, body: AnchorTopUpBody): Promise<void>;
}

/** Consolidates up to `noteCount` residual change notes for an order on-chain
 *  (VALID_MERGE). Resolves with the number actually merged. */
export interface MergeRunner {
  run(order: ManagedOrder, noteCount: number): Promise<number>;
}

export interface ActionExecutorDeps {
  keys: KeyProvider;
  anchors: AnchorTopUpPoster;
  merge: MergeRunner;
}

/** A 16-byte order id as a Uint8Array (validates the hex length). */
function orderIdBytes(orderIdHex: string): Uint8Array {
  const b = Uint8Array.from(Buffer.from(orderIdHex, "hex"));
  if (b.length !== 16) {
    throw new Error(
      `order id must be 16 bytes, got ${b.length} (${orderIdHex})`,
    );
  }
  return b;
}

export class DaemonActionExecutor implements ActionExecutor {
  constructor(private readonly deps: ActionExecutorDeps) {}

  async topup(
    order: ManagedOrder,
    action: TopupAction,
  ): Promise<LifecycleEvent> {
    const keys = await this.deps.keys.keysForOrder(order);
    // The SDK builds + signs the canonical body (parity-tested vs. Rust). We
    // only choose the index range + nonce the reducer told us to use.
    const body = await buildAnchorTopUp({
      masterSeed: keys.masterSeed,
      spendingKey: keys.spendingKey,
      orderId: orderIdBytes(order.orderId),
      startIndex: action.startIndex,
      topupNonce: BigInt(action.nonce),
      tradingKey: keys.tradingKeyPubkey,
      sign: keys.sign,
      count: action.count,
    });
    await this.deps.anchors.post(order.orderId, body);
    return { type: "topup-confirmed", count: action.count };
  }

  async merge(
    order: ManagedOrder,
    action: MergeAction,
  ): Promise<LifecycleEvent> {
    const consumed = await this.deps.merge.run(order, action.noteCount);
    return { type: "merge-confirmed", consumed };
  }
}

/** Options for {@link HttpAnchorTopUpPoster}. */
export interface HttpAnchorTopUpPosterOptions {
  /** Gateway origin, e.g. `https://<app>-8080.dstack-…`. */
  baseUrl: string;
  /** Bearer token from `POST /auth/token`. */
  token: string;
  fetchImpl?: typeof fetch;
}

/**
 * `fetch`-based {@link AnchorTopUpPoster}. Mirrors the SDK order-client's error
 * decoding so a non-2xx surfaces as a {@link NyxApiError} (with the
 * `x-request-id` correlation header), which the engine treats as a topup
 * failure.
 */
export class HttpAnchorTopUpPoster implements AnchorTopUpPoster {
  constructor(private readonly opts: HttpAnchorTopUpPosterOptions) {}

  async post(orderIdHex: string, body: AnchorTopUpBody): Promise<void> {
    const f = this.opts.fetchImpl ?? fetch;
    const res = await f(
      new URL(`/orders/${orderIdHex}/anchors`, this.opts.baseUrl).toString(),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.opts.token}`,
        },
        body: JSON.stringify(body),
      },
    );
    if (res.ok) return;
    const requestId = res.headers.get("x-request-id") ?? undefined;
    let code = res.status;
    let message = res.statusText;
    try {
      const errBody = (await res.json()) as {
        code?: number;
        message?: string;
      };
      if (typeof errBody.code === "number") code = errBody.code;
      if (typeof errBody.message === "string") message = errBody.message;
    } catch {
      // non-JSON error body — keep the status text
    }
    throw new NyxApiError(code, message, res.status, requestId);
  }
}
