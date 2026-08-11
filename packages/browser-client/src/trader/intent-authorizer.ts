import type { TraderIntentDraft } from "@darknyx/client-core";
import type {
  AuthorizedIntentEnvelope,
  IntentAuthorizationPort,
  IntentReservation,
} from "@darknyx/client-core/internal";
import type { CancelOrderRequest } from "@darknyx/sdk/browser-orders";

import {
  requestVaultInternal,
  type BrowserVault,
} from "../custody/browser-vault.js";
import type { BrowserInventory } from "../inventory/browser-inventory.js";

const ORDER_ID = /^[0-9a-f]{32}$/;
const HEX32 = /^[0-9a-f]{64}$/;

interface WorkerAuthorization {
  body: Uint8Array;
  clientOrderId: string;
}

export interface BrowserIntentAuthorizerOptions {
  vault: BrowserVault;
  inventory: BrowserInventory;
  /** Exact 32-byte hex boot session bound by the verified TDX quote. */
  bootSessionId: string;
  now?: () => number;
}

/** Typed order authorization whose signing key never leaves the custody Worker. */
export class BrowserIntentAuthorizer implements IntentAuthorizationPort {
  readonly #vault: BrowserVault;
  readonly #inventory: BrowserInventory;
  readonly #bootSessionId: string;
  readonly #now: () => number;

  constructor(options: BrowserIntentAuthorizerOptions) {
    if (!HEX32.test(options.bootSessionId)) {
      throw new Error("boot session id must be lowercase 32-byte hex");
    }
    this.#vault = options.vault;
    this.#inventory = options.inventory;
    this.#bootSessionId = options.bootSessionId;
    this.#now = options.now ?? Date.now;
  }

  async authorizeIntent(
    draft: TraderIntentDraft,
    reservation: IntentReservation,
  ): Promise<AuthorizedIntentEnvelope> {
    const reserved = await this.#inventory.resolveReservedProof(
      reservation.reservationId,
      reservation.proof,
    );
    // Persist before deriving. A failed attempt burns an index, which is safe;
    // reusing one after a crash would repeat an order id and trading key.
    const tradingIndex = await this.#inventory.allocateOrderIndex();
    const authorized = await requestVaultInternal<WorkerAuthorization>(
      this.#vault,
      "authorizeIntent",
      {
        draft,
        note: reserved.note,
        proof: reserved.proof,
        sessionId: this.#bootSessionId,
        orderIndex: tradingIndex,
      },
    );
    if (
      !(authorized.body instanceof Uint8Array) ||
      authorized.body.length === 0 ||
      authorized.body.length > 16_384 ||
      !ORDER_ID.test(authorized.clientOrderId)
    ) {
      throw new Error("vault returned malformed authorized order bytes");
    }
    const now = this.#now();
    await this.#inventory.bindReservationToOrder({
      orderId: authorized.clientOrderId,
      reservationId: reservation.reservationId,
      noteCommitment: reserved.note.commitment,
      tradingIndex,
      marketSymbol: draft.marketSymbol,
      side: draft.side,
      baseAmountAtoms: draft.baseAmountAtoms,
      limitPriceTicks: draft.limitPriceTicks,
      kind: "submitting",
      createdAtMs: now,
      updatedAtMs: now,
    });
    return {
      body: authorized.body,
      clientOrderId: authorized.clientOrderId,
    };
  }

  async authorizeCancel(orderId: string): Promise<CancelOrderRequest> {
    if (!ORDER_ID.test(orderId)) throw new Error("invalid browser order id");
    const order = await this.#inventory.order(orderId);
    if (!order) throw new Error("unknown browser order");
    return requestVaultInternal<CancelOrderRequest>(
      this.#vault,
      "authorizeCancel",
      {
        orderId,
        tradingIndex: order.tradingIndex,
        cancelNonce: "1",
        sessionId: this.#bootSessionId,
      },
    );
  }
}
