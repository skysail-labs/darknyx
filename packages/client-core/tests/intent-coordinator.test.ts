import { describe, expect, it, vi } from "vitest";

import {
  createIntentCoordinator,
  type IntentAuthorizationPort,
  type IntentCoordinatorDependencies,
  type IntentReservation,
  type IntentTransportPort,
  type InventoryIntentPort,
  readyProofHandle,
  reservationId,
} from "../src/internal.js";
import type { TraderClientPort, TraderIntentDraft } from "../src/index.js";

const draft: TraderIntentDraft = {
  protocolVersion: 1,
  marketSymbol: "SOL-USDC",
  side: "bid",
  baseAmountAtoms: "1000000000",
  limitPriceTicks: "15000",
  attributes: { future_attribute: { enabled: true } },
};

const reservation: IntentReservation = {
  reservationId: reservationId("reservation-1"),
  proof: readyProofHandle("proof-1"),
};

function dependencies(
  reservationOutcome: Awaited<
    ReturnType<InventoryIntentPort["reserveReadyIntent"]>
  > = {
    status: "ready",
    reservation,
  },
): IntentCoordinatorDependencies & {
  inventory: InventoryIntentPort & {
    reserveReadyIntent: ReturnType<typeof vi.fn>;
    releaseReservation: ReturnType<typeof vi.fn>;
  };
  authorization: IntentAuthorizationPort & {
    authorizeIntent: ReturnType<typeof vi.fn>;
  };
  transport: IntentTransportPort & {
    submitAuthorized: ReturnType<typeof vi.fn>;
  };
} {
  return {
    inventory: {
      listBalances: vi.fn(async () => []),
      proofReadiness: vi.fn(async () => ({ ready: 1, proving: 0, stale: 0 })),
      reserveReadyIntent: vi.fn(async () => reservationOutcome),
      releaseReservation: vi.fn(async () => undefined),
    },
    authorization: {
      authorizeIntent: vi.fn(async () => ({
        body: new Uint8Array([1, 2, 3]),
        clientOrderId: "client-order-1",
      })),
    },
    transport: {
      submitAuthorized: vi.fn(async () => ({
        status: "accepted" as const,
        orderId: "order-1",
      })),
    },
  };
}

describe("intent coordinator", () => {
  it("submits only a ready, reserved, typed authorization", async () => {
    const deps = dependencies();
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "accepted",
      orderId: "order-1",
    });
    expect(deps.inventory.reserveReadyIntent).toHaveBeenCalledOnce();
    expect(deps.authorization.authorizeIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        attributes: { future_attribute: { enabled: true } },
      }),
      reservation,
    );
    expect(deps.transport.submitAuthorized).toHaveBeenCalledOnce();
    expect(deps.inventory.releaseReservation).not.toHaveBeenCalled();
  });

  it("does not authorize or send when no proof is ready", async () => {
    const deps = dependencies({ status: "not_ready", retryAfterMs: 250 });
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "pending",
      reason: "PROOF_NOT_READY",
      retryAfterMs: 250,
    });
    expect(deps.authorization.authorizeIntent).not.toHaveBeenCalled();
    expect(deps.transport.submitAuthorized).not.toHaveBeenCalled();
  });

  it("sanitizes inventory failures before they reach page UI", async () => {
    const deps = dependencies();
    deps.inventory.reserveReadyIntent.mockRejectedValueOnce(
      new Error("private note database path"),
    );
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "pending",
      reason: "INVENTORY_UNAVAILABLE",
    });
    expect(deps.authorization.authorizeIntent).not.toHaveBeenCalled();
  });

  it("releases a reservation after local authorization failure", async () => {
    const deps = dependencies();
    deps.authorization.authorizeIntent.mockRejectedValueOnce(
      new Error("secret internal detail"),
    );
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "rejected",
      code: "AUTHORIZATION_FAILED",
      retryable: true,
    });
    expect(deps.inventory.releaseReservation).toHaveBeenCalledWith(
      reservation.reservationId,
    );
  });

  it("keeps collateral reserved after an ambiguous transport failure", async () => {
    const deps = dependencies();
    deps.transport.submitAuthorized.mockRejectedValueOnce(
      new Error("connection reset"),
    );
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "pending",
      reason: "TRANSPORT_AMBIGUOUS",
      orderId: "client-order-1",
    });
    expect(deps.inventory.releaseReservation).not.toHaveBeenCalled();
  });

  it("keeps collateral reserved for an explicit ambiguous outcome", async () => {
    const deps = dependencies();
    deps.transport.submitAuthorized.mockResolvedValueOnce({
      status: "ambiguous",
      orderId: "venue-order-1",
    });
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "pending",
      reason: "TRANSPORT_AMBIGUOUS",
      orderId: "venue-order-1",
    });
    expect(deps.inventory.releaseReservation).not.toHaveBeenCalled();
  });

  it("releases only a definitively rejected submission", async () => {
    const deps = dependencies();
    deps.transport.submitAuthorized.mockResolvedValueOnce({
      status: "rejected",
    });
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "rejected",
      code: "VENUE_REJECTED",
      retryable: false,
    });
    expect(deps.inventory.releaseReservation).toHaveBeenCalledWith(
      reservation.reservationId,
    );
  });

  it("fails closed when a reservation cannot be released", async () => {
    const deps = dependencies();
    deps.transport.submitAuthorized.mockResolvedValueOnce({
      status: "rejected",
    });
    deps.inventory.releaseReservation.mockRejectedValueOnce(
      new Error("database busy"),
    );
    const client = createIntentCoordinator(deps);

    await expect(client.submitIntent(draft)).resolves.toEqual({
      status: "pending",
      reason: "LOCAL_RECONCILIATION_REQUIRED",
    });
  });

  it("rejects invalid drafts before touching inventory", async () => {
    const deps = dependencies();
    const client = createIntentCoordinator(deps);

    await expect(
      client.submitIntent({ ...draft, baseAmountAtoms: "01" }),
    ).resolves.toEqual({
      status: "rejected",
      code: "INVALID_INTENT",
      retryable: false,
    });
    expect(deps.inventory.reserveReadyIntent).not.toHaveBeenCalled();
  });
});

// Compile-time security boundary: the UI-facing port cannot request arbitrary
// signing, proving, seed export, witness access, or decrypted note records.
function assertPublicBoundary(client: TraderClientPort): void {
  if (false) {
    // @ts-expect-error no generic signing capability crosses into page UI
    void client.sign(new Uint8Array());
    // @ts-expect-error the intent plane cannot synchronously invoke a prover
    void client.prove({});
    // @ts-expect-error raw seed export is intentionally absent
    void client.exportSeed();
    // @ts-expect-error decrypted note records are intentionally absent
    void client.notes();
  }
}
void assertPublicBoundary;
