import {
  IntentValidationError,
  validateIntentDraft,
} from "./intent-validation.js";
import type {
  BalanceView,
  ProofReadinessView,
  SubmitIntentResult,
  TraderClientPort,
  TraderIntentDraft,
} from "./types.js";

declare const reservationBrand: unique symbol;
declare const proofBrand: unique symbol;

export type ReservationId = string & { readonly [reservationBrand]: true };
export type ReadyProofHandle = string & { readonly [proofBrand]: true };

const OPAQUE_ID = /^[A-Za-z0-9:_-]{1,128}$/;

export function reservationId(value: string): ReservationId {
  if (!OPAQUE_ID.test(value)) throw new Error("invalid reservation ID");
  return value as ReservationId;
}

export function readyProofHandle(value: string): ReadyProofHandle {
  if (!OPAQUE_ID.test(value)) throw new Error("invalid ready-proof handle");
  return value as ReadyProofHandle;
}

export interface IntentReservation {
  reservationId: ReservationId;
  proof: ReadyProofHandle;
}

export type ReservationOutcome =
  | { status: "ready"; reservation: IntentReservation }
  | { status: "not_ready"; retryAfterMs?: number };

export interface InventoryIntentPort {
  listBalances(): Promise<readonly BalanceView[]>;
  proofReadiness(): Promise<ProofReadinessView>;
  /** Read/cache/reserve only. This method must never synchronously prove. */
  reserveReadyIntent(draft: TraderIntentDraft): Promise<ReservationOutcome>;
  releaseReservation(reservationId: ReservationId): Promise<void>;
}

export interface AuthorizedIntentEnvelope {
  /** Canonical request bytes, proof and scoped signature; never exposed to UI. */
  body: Uint8Array;
  clientOrderId: string;
}

export interface IntentAuthorizationPort {
  /** Typed intent authorization only; never a generic sign(bytes) capability. */
  authorizeIntent(
    draft: TraderIntentDraft,
    reservation: IntentReservation,
  ): Promise<AuthorizedIntentEnvelope>;
}

export type TransportSubmissionOutcome =
  | { status: "accepted"; orderId: string }
  | { status: "rejected" }
  | { status: "ambiguous"; orderId?: string };

export interface IntentTransportPort {
  submitAuthorized(
    envelope: AuthorizedIntentEnvelope,
  ): Promise<TransportSubmissionOutcome>;
}

export interface IntentCoordinatorDependencies {
  inventory: InventoryIntentPort;
  authorization: IntentAuthorizationPort;
  transport: IntentTransportPort;
}

async function releaseReservation(
  inventory: InventoryIntentPort,
  reservationId: ReservationId,
): Promise<boolean> {
  try {
    await inventory.releaseReservation(reservationId);
    return true;
  } catch {
    // Fail closed: a failed local release keeps collateral reserved and asks
    // reconciliation to resolve it. Reuse here could double-allocate a note.
    return false;
  }
}

export function createIntentCoordinator({
  inventory,
  authorization,
  transport,
}: IntentCoordinatorDependencies): TraderClientPort {
  return Object.freeze({
    balances: () => inventory.listBalances(),
    proofReadiness: () => inventory.proofReadiness(),
    async submitIntent(
      rawDraft: TraderIntentDraft,
    ): Promise<SubmitIntentResult> {
      let draft: TraderIntentDraft;
      try {
        draft = validateIntentDraft(rawDraft);
      } catch (error) {
        if (error instanceof IntentValidationError) {
          return {
            status: "rejected",
            code: "INVALID_INTENT",
            retryable: false,
          };
        }
        throw error;
      }

      let reserved: ReservationOutcome;
      try {
        reserved = await inventory.reserveReadyIntent(draft);
      } catch {
        return { status: "pending", reason: "INVENTORY_UNAVAILABLE" };
      }
      if (reserved.status === "not_ready") {
        return {
          status: "pending",
          reason: "PROOF_NOT_READY",
          ...(reserved.retryAfterMs === undefined
            ? {}
            : { retryAfterMs: reserved.retryAfterMs }),
        };
      }

      let authorized: AuthorizedIntentEnvelope;
      try {
        authorized = await authorization.authorizeIntent(
          draft,
          reserved.reservation,
        );
      } catch {
        const released = await releaseReservation(
          inventory,
          reserved.reservation.reservationId,
        );
        return released
          ? {
              status: "rejected",
              code: "AUTHORIZATION_FAILED",
              retryable: true,
            }
          : {
              status: "pending",
              reason: "LOCAL_RECONCILIATION_REQUIRED",
            };
      }

      let outcome: TransportSubmissionOutcome;
      try {
        outcome = await transport.submitAuthorized(authorized);
      } catch {
        // Once transport begins, an exception is ambiguous. Keep collateral
        // reserved until stream/chain reconciliation proves non-acceptance.
        return {
          status: "pending",
          reason: "TRANSPORT_AMBIGUOUS",
          orderId: authorized.clientOrderId,
        };
      }

      if (outcome.status === "accepted") {
        return { status: "accepted", orderId: outcome.orderId };
      }
      if (outcome.status === "ambiguous") {
        return {
          status: "pending",
          reason: "TRANSPORT_AMBIGUOUS",
          orderId: outcome.orderId ?? authorized.clientOrderId,
        };
      }
      const released = await releaseReservation(
        inventory,
        reserved.reservation.reservationId,
      );
      return released
        ? { status: "rejected", code: "VENUE_REJECTED", retryable: false }
        : {
            status: "pending",
            reason: "LOCAL_RECONCILIATION_REQUIRED",
          };
    },
  });
}
