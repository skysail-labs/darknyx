import {
  bn254ToBE32,
  deriveNoteUseTag,
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
              version: 2,
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
        Uint8Array.from(input.commitment.match(/../g) ?? [], (byte) =>
          Number.parseInt(byte, 16),
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
            Uint8Array.from(consumed.commitment.match(/../g) ?? [], (byte) =>
              Number.parseInt(byte, 16),
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
