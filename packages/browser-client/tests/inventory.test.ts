import {
  bn254ToBE32,
  deriveNoteUseTag,
  noteCommitmentFromBytes,
  noteCommitmentV2,
  type StoredNote,
} from "@darknyx/sdk/browser-inventory-crypto";
import { describe, expect, it, vi } from "vitest";

import {
  BrowserInventory,
  InMemoryInventoryStore,
  type BrowserMarketInventoryConfig,
  type FinalizedRootRing,
  type RecoveryReport,
} from "../src/internal.js";

const mint = (byte: number) => new Uint8Array(32).fill(byte);
const mintHex = (byte: number) => byte.toString(16).padStart(2, "0").repeat(32);
const root = (byte: number) => byte.toString(16).padStart(2, "0").repeat(32);
const proof = () => new Uint8Array(256).fill(0x77);

const market: BrowserMarketInventoryConfig = {
  symbol: "SOL-USDC",
  baseMintHex: mintHex(0xb1),
  quoteMintHex: mintHex(0x9e),
  priceScale: 100n,
  feeRateBps: 100n,
};

async function note(
  tokenMint: Uint8Array,
  amount: bigint,
  innerHash: bigint,
  leafIndex: bigint,
): Promise<StoredNote> {
  const candidate = {
    tokenMint,
    amount,
    ownerCommitment: 31n,
    innerHash,
  };
  const commitment = await noteCommitmentV2(candidate);
  return {
    ...candidate,
    commitment: Array.from(commitment, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join(""),
    leafIndex,
    treeId: 0,
  };
}

const report = (notes: StoredNote[]): RecoveryReport => ({
  fullScan: true,
  notes,
  recovered: { deposits: notes.length, trade: 0, change: 0, merges: 0 },
  unresolvedSettlements: 0,
  unresolvedMerges: 0,
});

const ring = (...acceptedRoots: string[]): FinalizedRootRing => ({
  treeId: 0,
  finalizedSlot: 1_000,
  acceptedRoots,
});

function ids(...values: string[]): () => string {
  let index = 0;
  return () => values[index++] ?? `fallback-${index}`;
}

describe("browser inventory plane", () => {
  it("rejects an invalid persisted order lifecycle kind", async () => {
    await expect(
      BrowserInventory.create({
        store: {
          load: async () =>
            ({
              format: "darknyx-browser-inventory",
              version: 3,
              notes: [],
              proofs: [],
              reservations: [],
              roots: [],
              nextOrderIndex: 1,
              orders: [
                {
                  orderId: "ab".repeat(16),
                  reservationId: "reservation-a",
                  noteCommitment: "cd".repeat(32),
                  tradingIndex: 0,
                  nextCancelNonce: "1",
                  marketSymbol: "SOL-USDC",
                  side: "bid",
                  baseAmountAtoms: "1",
                  limitPriceTicks: "1",
                  kind: "corrupted",
                  createdAtMs: 1,
                  updatedAtMs: 1,
                },
              ],
            }) as never,
          save: async () => undefined,
          clear: async () => undefined,
        },
        markets: [market],
        circuitVersion: "valid-input-v3",
        provingKeyVersion: "pk-1",
      }),
    ).rejects.toThrow(/lifecycle kind/);
  });

  it("persists the HD order index before reuse is possible", async () => {
    const store = new InMemoryInventoryStore();
    const first = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    await expect(first.allocateOrderIndex()).resolves.toBe(0);
    const reloaded = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    await expect(reloaded.allocateOrderIndex()).resolves.toBe(1);
  });

  it("exposes a locally created deposit as soon as its transaction is confirmed", async () => {
    const store = new InMemoryInventoryStore();
    const inventory = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const deposited = await note(mint(0x9e), 250n, 39n, 7n);

    await inventory.recordConfirmedDeposit({
      ...deposited,
      treeId: 0,
      leafIndex: 7n,
    });
    await inventory.recordConfirmedDeposit({
      ...deposited,
      treeId: 0,
      leafIndex: 7n,
    });
    await expect(
      inventory.recordConfirmedDeposit({
        ...deposited,
        amount: deposited.amount + 1n,
        treeId: 0,
        leafIndex: 7n,
      }),
    ).rejects.toThrow(/does not match its commitment/);

    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "250",
        reservedAtoms: "0",
        pendingSettlementAtoms: "0",
      },
    ]);
    const reloaded = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    await expect(reloaded.listBalances()).resolves.toEqual(
      await inventory.listBalances(),
    );
  });

  it("atomically replaces confirmed merge inputs with their output note", async () => {
    const store = new InMemoryInventoryStore();
    const inventory = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("merge-a", "merge-b"),
    });
    const first = await note(mint(0x9e), 70n, 51n, 7n);
    const second = await note(mint(0x9e), 30n, 52n, 8n);
    await inventory.recover(report([first, second]), async () => false);
    const held = await inventory.reserveAccountMerge(market.quoteMintHex);
    expect(held).toHaveLength(2);
    const output = await note(mint(0x9e), 100n, 53n, 9n);

    await inventory.recordConfirmedMerge(
      held.map(({ note: heldNote }) => heldNote.commitment),
      { ...output, treeId: 0, leafIndex: 9n },
    );

    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "100",
        reservedAtoms: "0",
        pendingSettlementAtoms: "0",
      },
    ]);
    await expect(
      inventory.noteLayout(market.quoteMintHex),
    ).resolves.toMatchObject({
      totalNotes: 1,
      spendableNotes: 1,
    });
    const reloaded = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    await expect(reloaded.listBalances()).resolves.toEqual(
      await inventory.listBalances(),
    );
  });

  it("rejects a confirmed merge that changes mint or value", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("merge-a", "merge-b"),
    });
    const first = await note(mint(0x9e), 70n, 71n, 20n);
    const second = await note(mint(0x9e), 30n, 72n, 21n);
    await inventory.recover(report([first, second]), async () => false);
    const held = await inventory.reserveAccountMerge(market.quoteMintHex);
    const inputs = held.map(({ note: heldNote }) => heldNote.commitment);
    const wrongValue = await note(mint(0x9e), 101n, 73n, 22n);
    await expect(
      inventory.recordConfirmedMerge(inputs, {
        ...wrongValue,
        treeId: 0,
        leafIndex: 22n,
      }),
    ).rejects.toThrow(/does not conserve value/);

    const wrongMint = await note(mint(0xb1), 100n, 74n, 23n);
    await expect(
      inventory.recordConfirmedMerge(inputs, {
        ...wrongMint,
        treeId: 0,
        leafIndex: 23n,
      }),
    ).rejects.toThrow(/must use one mint/);
  });

  it("reports the same lowest mergeable shard that consolidation selects", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const notes = await Promise.all([
      note(mint(0x9e), 10n, 81n, 30n),
      note(mint(0x9e), 11n, 82n, 31n),
      note(mint(0x9e), 12n, 83n, 32n),
      note(mint(0x9e), 13n, 84n, 33n),
      note(mint(0x9e), 14n, 85n, 34n),
      note(mint(0x9e), 15n, 86n, 35n),
    ]);
    notes[0]!.treeId = 0;
    notes[1]!.treeId = 0;
    for (const candidate of notes.slice(2)) candidate.treeId = 3;
    await inventory.recover(report(notes), async () => false);

    await expect(
      inventory.noteLayout(market.quoteMintHex),
    ).resolves.toMatchObject({ mergeableNotes: 2, preferredTreeId: 0 });
    const selected = await inventory.reserveAccountMerge(market.quoteMintHex);
    expect(selected).toHaveLength(2);
    expect(selected.every(({ note: held }) => held.treeId === 0)).toBe(true);
  });

  it("rolls back the entire merge transition when durable storage fails", async () => {
    const backing = new InMemoryInventoryStore();
    let rejectSave = false;
    const inventory = await BrowserInventory.create({
      store: {
        load: () => backing.load(),
        save: async (snapshot) => {
          if (rejectSave) throw new Error("durable save failed");
          await backing.save(snapshot);
        },
        clear: () => backing.clear(),
      },
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("merge-a", "merge-b"),
    });
    const first = await note(mint(0x9e), 70n, 61n, 10n);
    const second = await note(mint(0x9e), 30n, 62n, 11n);
    await inventory.recover(report([first, second]), async () => false);
    const held = await inventory.reserveAccountMerge(market.quoteMintHex);
    const output = await note(mint(0x9e), 100n, 63n, 12n);
    rejectSave = true;

    await expect(
      inventory.recordConfirmedMerge(
        held.map(({ note: heldNote }) => heldNote.commitment),
        { ...output, treeId: 0, leafIndex: 12n },
      ),
    ).rejects.toThrow("durable save failed");
    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "100",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("rolls an account reservation back when durable persistence fails", async () => {
    const backing = new InMemoryInventoryStore();
    let rejectSave = false;
    const inventory = await BrowserInventory.create({
      store: {
        load: () => backing.load(),
        save: async (snapshot) => {
          if (rejectSave) throw new Error("durable save failed");
          await backing.save(snapshot);
        },
        clear: () => backing.clear(),
      },
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("account-reservation"),
    });
    const spendable = await note(mint(0x9e), 500n, 41n, 2n);
    await inventory.recover(report([spendable]), async () => false);
    rejectSave = true;

    await expect(
      inventory.reserveAccountExact(market.quoteMintHex, 500n),
    ).rejects.toThrow("durable save failed");
    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "500",
        reservedAtoms: "0",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("revalidates recovered openings and chain consumption before exposing balances", async () => {
    const store = new InMemoryInventoryStore();
    const inventory = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const spendable = await note(mint(0x9e), 500n, 41n, 2n);
    const consumed = await note(mint(0xb1), 70n, 42n, 3n);
    const checked: string[] = [];

    await inventory.recover(report([spendable, consumed]), async (tag) => {
      checked.push(tag);
      return checked.length === 2;
    });

    expect(checked).toHaveLength(2);
    expect(await inventory.listBalances()).toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "500",
        reservedAtoms: "0",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("rejects recovered notes without an exact shard or governed mint", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const missingTree = await note(mint(0x9e), 5n, 45n, 4n);
    delete missingTree.treeId;
    await expect(
      inventory.recover(report([missingTree]), async () => false),
    ).rejects.toThrow(/tree id/);

    const unsupported = await note(mint(0x55), 5n, 46n, 5n);
    await expect(
      inventory.recover(report([unsupported]), async () => false),
    ).rejects.toThrow(/not served/);
  });

  it("persists one reservation per note and refuses double allocation after reload", async () => {
    const store = new InMemoryInventoryStore();
    const first = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-a", "reservation-a"),
    });
    const collateral = await note(mint(0x9e), 103n, 51n, 4n);
    await first.recover(report([collateral]), async () => false);
    await first.synchronizeFinalizedRoots([ring(root(1))]);
    await first.cacheReadyProof(collateral.commitment, root(1), proof());
    const draft = {
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid" as const,
      baseAmountAtoms: "100",
      limitPriceTicks: "101",
      attributes: {},
    };

    await expect(first.reserveReadyIntent(draft)).resolves.toMatchObject({
      status: "ready",
    });
    const reloaded = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    await expect(reloaded.reserveReadyIntent(draft)).resolves.toEqual({
      status: "not_ready",
      retryAfterMs: 250,
    });
    expect(await reloaded.listBalances()).toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "103",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("releases a stale venue reservation only after chain recovery leaves the note reusable", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-stale", "reservation-stale"),
      now: () => 900,
    });
    const collateral = await note(mint(0x9e), 2_000n, 49n, 4n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    const orderId = "aa".repeat(16);
    await inventory.allocateOrderIndex();
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: collateral.commitment,
      tradingIndex: 0,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "open",
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    // A regular recovery preserves the durable reservation until the venue's
    // authenticated open-order snapshot has also been consulted.
    await inventory.recover(report([collateral]), async () => false);
    await inventory.reconcileVenueOpenOrders([]);

    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "2000",
        reservedAtoms: "0",
        pendingSettlementAtoms: "0",
      },
    ]);
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "closed",
      reason: expect.stringContaining("Closed while"),
      updatedAtMs: 900,
    });
  });

  it("preserves collateral for an order still present in the venue snapshot", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-live", "reservation-live"),
    });
    const collateral = await note(mint(0x9e), 2_000n, 50n, 5n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    const orderId = "bb".repeat(16);
    await inventory.allocateOrderIndex();
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: collateral.commitment,
      tradingIndex: 0,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "open",
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    await inventory.recover(report([collateral]), async () => false);
    await inventory.reconcileVenueOpenOrders([orderId]);

    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "2000",
        pendingSettlementAtoms: "0",
      },
    ]);
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "open",
    });
  });

  it("does not let an older venue snapshot close a newer accepted order", async () => {
    let now = 100;
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-race", "reservation-race"),
      now: () => now,
    });
    const collateral = await note(mint(0x9e), 2_000n, 55n, 15n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    await inventory.allocateOrderIndex();
    const orderId = "dd".repeat(16);
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: collateral.commitment,
      tradingIndex: 0,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "submitting",
      createdAtMs: now,
      updatedAtMs: now,
    });

    // The request producing this empty snapshot starts first. The placement
    // acknowledgement updates the local order while that request is in flight.
    const snapshotStartedAtMs = 110;
    now = 120;
    await inventory.updateOrder(orderId, { kind: "open" });
    await inventory.reconcileVenueOpenOrders([], { snapshotStartedAtMs });

    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "open",
      updatedAtMs: 120,
    });
    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "2000",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("repairs a falsely closed order when the venue still reports it open", async () => {
    let now = 200;
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-repair", "reservation-repair"),
      now: () => now,
    });
    const collateral = await note(mint(0x9e), 2_000n, 57n, 16n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    await inventory.allocateOrderIndex();
    const orderId = "ee".repeat(16);
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: collateral.commitment,
      tradingIndex: 0,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "open",
      createdAtMs: now,
      updatedAtMs: now,
    });
    now = 300;
    await inventory.reconcileVenueOpenOrders([]);
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "closed",
    });

    now = 400;
    await inventory.reconcileVenueOpenOrders([orderId]);
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "open",
      updatedAtMs: 400,
    });
    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "2000",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("does not let an older venue snapshot revive a newer closed order", async () => {
    let now = 500;
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-revival-race", "reservation-revival-race"),
      now: () => now,
    });
    const collateral = await note(mint(0x9e), 2_000n, 91n, 40n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    await inventory.allocateOrderIndex();
    const orderId = "fa".repeat(16);
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: collateral.commitment,
      tradingIndex: 0,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "open",
      createdAtMs: now,
      updatedAtMs: now,
    });
    await inventory.reconcileVenueOpenOrders([]);
    const snapshotStartedAtMs = 550;
    now = 600;
    await inventory.updateOrder(orderId, {
      kind: "closed",
      reason: "cancel confirmed",
    });

    await inventory.reconcileVenueOpenOrders([orderId], {
      snapshotStartedAtMs,
    });
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "closed",
      reason: "cancel confirmed",
      updatedAtMs: 600,
    });
    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "2000",
        reservedAtoms: "0",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("does not release collateral for an offline-closed order whose on-chain lock remains", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-locked", "reservation-locked"),
    });
    const collateral = await note(mint(0x9e), 2_000n, 56n, 6n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    const orderId = "cc".repeat(16);
    await inventory.allocateOrderIndex();
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: collateral.commitment,
      tradingIndex: 0,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "pending_settlement",
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    await inventory.recover(
      report([collateral]),
      async () => false,
      async () => true,
    );
    await inventory.reconcileVenueOpenOrders([]);

    await expect(inventory.listBalances()).resolves.toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "2000",
        pendingSettlementAtoms: "0",
      },
    ]);
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      kind: "closed",
      reason: expect.stringContaining("keeps collateral unavailable"),
    });
  });

  it("reconciles a missed partial-fill continuation chain from finalized outputs", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("proof-chain", "reservation-chain"),
      now: () => 500,
    });
    const input = await note(mint(0x9e), 1_000n, 52n, 10n);
    await inventory.recover(report([input]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    const proofHandle = await inventory.cacheReadyProof(
      input.commitment,
      root(1),
      proof(),
    );
    const reserved = await inventory.reserveReadyIntent({
      protocolVersion: 1,
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      attributes: {},
    });
    if (reserved.status !== "ready") throw new Error("expected reservation");
    const orderId = "ab".repeat(16);
    const tradingIndex = await inventory.allocateOrderIndex();
    await inventory.bindReservationToOrder({
      orderId,
      reservationId: reserved.reservation.reservationId,
      noteCommitment: input.commitment,
      tradingIndex,
      nextCancelNonce: "1",
      marketSymbol: "SOL-USDC",
      side: "bid",
      baseAmountAtoms: "100",
      limitPriceTicks: "100",
      kind: "open",
      createdAtMs: 1,
      updatedAtMs: 1,
    });
    expect(reserved.reservation.proof).toBe(proofHandle);
    await expect(inventory.allocateCancelNonce(orderId)).resolves.toBe("1");
    await expect(inventory.allocateCancelNonce(orderId)).resolves.toBe("2");
    await expect(inventory.order(orderId)).resolves.toMatchObject({
      nextCancelNonce: "3",
    });

    const trade = await note(mint(0xb1), 40n, 53n, 11n);
    trade.orderId = orderId;
    trade.consumedCommitment = input.commitment;
    const continuation = await note(mint(0x9e), 600n, 54n, 12n);
    continuation.orderId = orderId;
    continuation.consumedCommitment = input.commitment;
    const inputTag = Array.from(
      await deriveNoteUseTag(
        noteCommitmentFromBytes(
          Uint8Array.from(input.commitment.match(/../g) ?? [], (byte) =>
            Number.parseInt(byte, 16),
          ),
        ),
        bn254ToBE32(input.innerHash),
      ),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
    await inventory.recover(
      report([input, trade, continuation]),
      async (tag) => tag === inputTag,
      async (_tag, _tree) => false,
    );
    expect(await inventory.order(orderId)).toMatchObject({
      kind: "partially_filled",
      noteCommitment: continuation.commitment,
    });

    const finalTrade = await note(mint(0xb1), 60n, 55n, 13n);
    finalTrade.orderId = orderId;
    finalTrade.consumedCommitment = continuation.commitment;
    const consumedTags = new Set<string>();
    for (const consumed of [input, continuation]) {
      consumedTags.add(
        Array.from(
          await deriveNoteUseTag(
            noteCommitmentFromBytes(
              Uint8Array.from(consumed.commitment.match(/../g) ?? [], (byte) =>
                Number.parseInt(byte, 16),
              ),
            ),
            bn254ToBE32(consumed.innerHash),
          ),
          (byte) => byte.toString(16).padStart(2, "0"),
        ).join(""),
      );
    }
    await inventory.recover(
      report([input, trade, continuation, finalTrade]),
      async (tag) => consumedTags.has(tag),
    );
    expect(await inventory.order(orderId)).toMatchObject({
      kind: "fully_filled",
      noteCommitment: continuation.commitment,
    });
  });

  it("refreshes an ageing accepted-root proof before eviction and stales evicted roots", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      refreshAtRootPosition: 1,
      randomId: ids("old", "new"),
    });
    const collateral = await note(mint(0x9e), 500n, 61n, 5n);
    await inventory.recover(report([collateral]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    await inventory.cacheReadyProof(collateral.commitment, root(1), proof());
    await inventory.synchronizeFinalizedRoots([ring(root(2), root(1))]);
    const producer = vi.fn(async () => ({ proofBytes: proof() }));

    await expect(inventory.refreshExpiringProofs(producer)).resolves.toBe(1);
    expect(producer).toHaveBeenCalledWith(
      expect.objectContaining({ root: root(2), treeId: 0 }),
    );
    expect(await inventory.proofReadiness()).toEqual({
      ready: 2,
      proving: 0,
      stale: 0,
    });

    await inventory.synchronizeFinalizedRoots([
      {
        ...ring(root(3)),
        finalizedSlot: 1_001,
      },
    ]);
    expect(await inventory.proofReadiness()).toEqual({
      ready: 0,
      proving: 0,
      stale: 2,
    });
  });

  it("does not mutate inventory when owned recovery outputs are unresolved", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const incomplete = report([await note(mint(0x9e), 10n, 71n, 6n)]);
    incomplete.unresolvedSettlements = 1;
    await expect(
      inventory.recover(incomplete, async () => false),
    ).rejects.toThrow(/unresolved owned outputs/);
    expect(await inventory.listBalances()).toEqual([]);
  });

  it("keeps recovered notes unavailable until their leaf index is resolved", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const unresolvedLeaf = await note(mint(0x9e), 10n, 72n, 6n);
    delete unresolvedLeaf.leafIndex;
    await inventory.recover(report([unresolvedLeaf]), async () => false);
    expect(await inventory.listBalances()).toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "10",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("keeps an unconsumed recovered note unavailable while its NoteLock exists", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const relocked = await note(mint(0x9e), 250n, 75n, 9n);
    await inventory.recover(
      report([relocked]),
      async () => false,
      async () => true,
    );
    expect(await inventory.listBalances()).toEqual([
      {
        mint: market.quoteMintHex,
        spendableAtoms: "0",
        reservedAtoms: "250",
        pendingSettlementAtoms: "0",
      },
    ]);
  });

  it("durably reserves exact withdrawals and same-shard merge inputs", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("withdraw", "merge-a", "merge-b"),
    });
    const exact = await note(mint(0x9e), 50n, 76n, 14n);
    const mergeA = await note(mint(0xb1), 10n, 77n, 15n);
    const mergeB = await note(mint(0xb1), 20n, 78n, 16n);
    await inventory.recover(report([exact, mergeA, mergeB]), async () => false);
    const withdrawal = await inventory.reserveAccountExact(
      market.quoteMintHex,
      50n,
    );
    expect(withdrawal?.note.commitment).toBe(exact.commitment);
    expect(
      await inventory.reserveAccountExact(market.quoteMintHex, 50n),
    ).toBeNull();
    const merge = await inventory.reserveAccountMerge(market.baseMintHex);
    expect(merge.map(({ note: held }) => held.commitment)).toEqual([
      mergeA.commitment,
      mergeB.commitment,
    ]);
    expect(await inventory.listBalances()).toEqual(
      [
        {
          mint: market.quoteMintHex,
          spendableAtoms: "0",
          reservedAtoms: "50",
          pendingSettlementAtoms: "0",
        },
        {
          mint: market.baseMintHex,
          spendableAtoms: "0",
          reservedAtoms: "30",
          pendingSettlementAtoms: "0",
        },
      ].sort((left, right) => left.mint.localeCompare(right.mint)),
    );
  });

  it("clears every proving marker after one refresh fails", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    const first = await note(mint(0x9e), 10n, 73n, 7n);
    const second = await note(mint(0x9e), 20n, 74n, 8n);
    await inventory.recover(report([first, second]), async () => false);
    await inventory.synchronizeFinalizedRoots([ring(root(1))]);
    const producer = vi
      .fn()
      .mockRejectedValueOnce(new Error("proof failed"))
      .mockResolvedValueOnce({ proofBytes: proof() });

    await expect(inventory.refreshExpiringProofs(producer)).rejects.toThrow(
      /proof failed/,
    );
    expect(producer).toHaveBeenCalledTimes(2);
    expect(await inventory.proofReadiness()).toEqual({
      ready: 1,
      proving: 0,
      stale: 0,
    });
  });

  it("rejects a finalized snapshot rollback", async () => {
    const inventory = await BrowserInventory.create({
      store: new InMemoryInventoryStore(),
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
    });
    await inventory.synchronizeFinalizedRoots([
      { ...ring(root(1)), finalizedSlot: 9 },
    ]);
    await expect(
      inventory.synchronizeFinalizedRoots([
        { ...ring(root(2)), finalizedSlot: 8 },
      ]),
    ).rejects.toThrow(/moved backwards/);
  });

  it("invalidates cached proofs when circuit or proving-key versions change", async () => {
    const store = new InMemoryInventoryStore();
    const original = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v3",
      provingKeyVersion: "pk-1",
      randomId: ids("versioned-proof"),
    });
    const collateral = await note(mint(0x9e), 500n, 81n, 7n);
    await original.recover(report([collateral]), async () => false);
    await original.synchronizeFinalizedRoots([ring(root(1))]);
    await original.cacheReadyProof(collateral.commitment, root(1), proof());

    const upgraded = await BrowserInventory.create({
      store,
      markets: [market],
      circuitVersion: "valid-input-v4",
      provingKeyVersion: "pk-2",
    });
    expect(await upgraded.proofReadiness()).toEqual({
      ready: 0,
      proving: 0,
      stale: 1,
    });
  });
});
