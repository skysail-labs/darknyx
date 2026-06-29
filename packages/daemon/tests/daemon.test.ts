/**
 * Daemon wiring tests — the assembled object with all I/O faked (no CVM).
 * Real Keystore + :memory: store + real engine; fake prover/placer/fetch/streams.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PublicKey } from "@solana/web3.js";

import { Daemon, type DaemonEvent } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import type { DaemonConfig } from "../src/config.js";
import type { OrderPlacer } from "../src/order-placer.js";
import {
  limitPolicy,
  OrderSide,
  type PlaceOrderResponse,
  type StoredNote,
  type ValidInputProver,
} from "@nyx/sdk";

function keystore(): Keystore {
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) masterSeed[i] = (i * 13 + 5) & 0xff;
  const id: AccountIdentity = {
    masterSeed,
    ownerBlinding: 0xabcn,
    r0: 1n,
    r1: 2n,
    r2: 3n,
    rootKeyPubkey: new Uint8Array(32).fill(4),
  };
  return new Keystore(id);
}

const config = (): DaemonConfig => ({
  gatewayUrl: "https://gw",
  gatewayWsUrl: "wss://gw",
  token: "tok",
  rpcUrl: "https://rpc",
  dbPath: ":memory:",
  controlPort: 0,
  keystorePath: "x",
  thresholds: DEFAULT_THRESHOLDS,
  programId: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
});

const note: StoredNote = {
  commitment: "aa".repeat(32),
  tokenMint: new Uint8Array(32).fill(9),
  amount: 1_000_000n,
  ownerCommitment: 12345n,
  innerHash: 7n,
  leafIndex: 0n,
};

const fakeProver: ValidInputProver = async (p) => ({
  proofBytes: new Uint8Array(256).fill(1),
  merkleRoot: p.witness.merkleRoot,
});

function fakeFetch(): typeof fetch {
  return vi.fn(async () => {
    const body = {
      leaf_index: 0,
      merkle_root: "bb".repeat(32),
      siblings: Array.from({ length: 20 }, (_, i) =>
        i.toString(16).padStart(2, "0").repeat(32),
      ),
    };
    return new Response(JSON.stringify(body), { status: 200 });
  }) as unknown as typeof fetch;
}

const ACCEPT: PlaceOrderResponse = {
  order_id: "x",
  status: "accepted",
  arrival_slot: 7,
};

/** Capture the injected stream options so tests can push frames. */
function capture<T>() {
  const cap: { opts?: T; closed: boolean } = { closed: false };
  const fn = (opts: T) => {
    cap.opts = opts;
    return {
      close() {
        cap.closed = true;
      },
    };
  };
  return { cap, fn };
}

let store: DaemonStore;
let placer: OrderPlacer & { placed: unknown[]; cancelled: string[] };

beforeEach(() => {
  store = new DaemonStore(":memory:");
  placer = {
    placed: [],
    cancelled: [],
    place: vi.fn(async (o: unknown) => {
      placer.placed.push(o);
      return ACCEPT;
    }),
    cancel: vi.fn(async (id: string) => {
      placer.cancelled.push(id);
      return { order_id: id, status: "cancelled" };
    }),
    modify: vi.fn(),
    close: vi.fn(),
  } as never;
});
afterEach(() => store.close());

function mkDaemon(
  extra: Partial<Parameters<typeof Daemon.prototype.constructor>[0]> = {},
) {
  return new Daemon({
    config: config(),
    keystore: keystore(),
    store,
    prover: fakeProver,
    placer,
    fetchImpl: fakeFetch(),
    subscribeFills: capture().fn as never,
    subscribeOrders: capture().fn as never,
    verifyAttestation: false, // attestation covered in attestation.test.ts
    ...extra,
  });
}

describe("Daemon — placeOrder", () => {
  it("builds, places, and moves the order to open; emits an order event", async () => {
    const daemon = mkDaemon();
    const events: DaemonEvent[] = [];
    daemon.subscribe((e) => events.push(e));

    const { orderId, arrivalSlot } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n }),
        amount: 500n,
      },
      note,
    );

    expect(arrivalSlot).toBe(7);
    expect(placer.placed).toHaveLength(1);
    expect(store.getOrder(orderId)!.phase).toBe("open");
    expect(events.some((e) => e.type === "order")).toBe(true);
  });

  it("allocates a fresh HD seed index per order", async () => {
    const daemon = mkDaemon();
    const intent = {
      symbol: "SOL-USDC",
      side: OrderSide.Bid,
      policy: limitPolicy({ priceLimit: 100n }),
      amount: 500n,
    };
    const a = await daemon.placeOrder(intent, note);
    const b = await daemon.placeOrder(intent, note);
    expect(a.orderId).not.toBe(b.orderId);
    const idxs = daemon.listOrders().map((o) => o.seedIndex);
    expect(new Set(idxs).size).toBe(2);
  });
});

describe("Daemon — cancelOrder", () => {
  it("signs + sends a cancel and drives the order to cancelled", async () => {
    const daemon = mkDaemon();
    const { orderId } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n }),
        amount: 500n,
      },
      note,
    );
    await daemon.cancelOrder(orderId);
    expect(placer.cancelled).toContain(orderId);
    expect(store.getOrder(orderId)!.phase).toBe("cancelled");
  });

  it("rejects an unknown order", async () => {
    const daemon = mkDaemon();
    await expect(daemon.cancelOrder("ab".repeat(8))).rejects.toThrow(
      /unknown order/,
    );
  });
});

describe("Daemon — balances + streams", () => {
  it("aggregates unspent notes per mint", () => {
    const daemon = mkDaemon();
    store.put(note);
    store.put({ ...note, commitment: "bb".repeat(32), amount: 5n });
    store.put({
      ...note,
      commitment: "cc".repeat(32),
      tokenMint: new Uint8Array(32).fill(2),
      amount: 3n,
    });
    const balances = daemon.balances();
    const byMint = Object.fromEntries(balances.map((b) => [b.mint, b]));
    expect(byMint["09".repeat(32)].amount).toBe("1000005");
    expect(byMint["09".repeat(32)].notes).toBe(2);
    expect(byMint["02".repeat(32)].amount).toBe("3");
  });

  it("start() opens both streams; stop() closes the placer", async () => {
    const fills = capture();
    const orders = capture();
    const daemon = mkDaemon({
      subscribeFills: fills.fn as never,
      subscribeOrders: orders.fn as never,
    });
    await daemon.start();
    expect(fills.cap.opts).toBeDefined();
    expect(orders.cap.opts).toBeDefined();
    daemon.stop();
    expect((placer.close as ReturnType<typeof vi.fn>).mock.calls.length).toBe(
      1,
    );
  });
});

describe("Daemon — collateral selection + pruning", () => {
  const MINT = new Uint8Array(32).fill(9);
  const spendable = (commitment: string, amount: bigint): StoredNote => ({
    commitment,
    tokenMint: MINT,
    amount,
    ownerCommitment: 12345n,
    innerHash: 7n,
    leafIndex: 0n,
  });
  const intent = {
    symbol: "SOL-USDC",
    side: OrderSide.Bid,
    policy: limitPolicy({ priceLimit: 100n }),
    amount: 500n,
  };

  const BIG = "1a".repeat(32);
  const MID = "2b".repeat(32);
  const COLL = "3c".repeat(32);

  it("selectNote best-fits a spendable note of the mint", () => {
    const daemon = mkDaemon();
    store.put(spendable(BIG, 1000n));
    store.put(spendable(MID, 500n));
    expect(daemon.selectNote({ mint: MINT, minAmount: 300n })?.commitment).toBe(
      MID,
    );
  });

  it("excludes a note already locked by a resting order", async () => {
    const daemon = mkDaemon();
    const n = spendable(BIG, 1000n);
    store.put(n);
    // place an order spending it → it becomes locked (order open)
    await daemon.placeOrder(intent, n);
    expect(daemon.selectNote({ mint: MINT, minAmount: 1n })).toBeUndefined();
  });

  it("prunes the collateral note once a fill consumes it", async () => {
    const daemon = mkDaemon();
    const n = spendable(COLL, 1000n);
    store.put(n);
    const { orderId } = await daemon.placeOrder(intent, n);
    expect(store.get(COLL)).toBeDefined(); // still there while resting

    // a fill consumes anchor 0 → the collateral note is rotated/spent
    await (
      daemon as unknown as {
        engine: { dispatch: (id: string, e: unknown) => Promise<unknown> };
      }
    ).engine.dispatch(orderId, {
      type: "fill",
      anchorIndex: 0,
      producedChangeNote: true,
    });
    expect(store.get(COLL)).toBeUndefined(); // pruned
  });
});

describe("Daemon — deposit", () => {
  const MINT = new Uint8Array(32).fill(9);

  it("calls the deposit fn, stores the minted note, returns it", async () => {
    const depositFn = vi.fn(
      async (params: { tokenMint: Uint8Array; amount: bigint }) => ({
        signature: "depsig",
        leafIndex: 42n,
        noteCommitment: new Uint8Array(32).fill(0xcd),
        notePlaintext: {
          tokenMint: params.tokenMint,
          amount: params.amount,
          ownerCommitment: 7n,
          innerHash: 8n,
        },
      }),
    );
    const daemon = mkDaemon({
      depositFn: depositFn as never,
      depositor: PublicKey.default,
    });

    const out = await daemon.deposit({
      tokenMint: MINT,
      amount: 1000n,
      depositorTokenAccount: PublicKey.default,
    });

    expect(depositFn).toHaveBeenCalledOnce();
    expect(
      typeof (depositFn.mock.calls[0][0] as { depositIndex: bigint })
        .depositIndex,
    ).toBe("bigint");
    expect(out.leafIndex).toBe(42n);
    const stored = store.get(out.commitment)!;
    expect(stored.amount).toBe(1000n);
    expect(stored.leafIndex).toBe(42n); // spendable immediately
  });

  it("throws when deposit isn't configured", async () => {
    const daemon = mkDaemon(); // no depositFn
    await expect(
      daemon.deposit({
        tokenMint: MINT,
        amount: 1n,
        depositorTokenAccount: PublicKey.default,
      }),
    ).rejects.toThrow(/deposit not configured/);
  });
});

describe("Daemon — note-lifecycle hygiene (rolling residual)", () => {
  const MINT = new Uint8Array(32).fill(9);
  const OID = "ab".repeat(8);
  const change = (commitment: string, anchorIndex: number): StoredNote => ({
    commitment,
    tokenMint: MINT,
    amount: 100n,
    ownerCommitment: 9n,
    innerHash: 7n,
    orderId: OID,
    anchorIndex,
    leafIndex: BigInt(anchorIndex),
  });
  const openMgr = (orderId: string): ManagedOrder => ({
    orderId,
    seedIndex: 0,
    side: "bid",
    priceRaw: 1n,
    sizeRaw: 1n,
    phase: "open",
    anchorPoolSize: 10,
    anchorsConsumed: 0,
    topupNonce: 0,
    topupInFlight: false,
    mergeInFlight: false,
    pendingChangeNotes: 0,
    createdAt: 0,
    updatedAt: 0,
  });

  it("selectNote excludes an open order's re-locked rolling residual", () => {
    const daemon = mkDaemon();
    store.putOrder(openMgr(OID));
    store.put(change("res", 0)); // the open order's rolling residual
    // locked while the order is open → not selectable
    expect(daemon.selectNote({ mint: MINT, minAmount: 1n })).toBeUndefined();
  });

  it("a continuation fill prunes the order's prior residuals (keeps the latest)", async () => {
    const c = capture<{ onFill?: (n: StoredNote) => void }>();
    const daemon = mkDaemon({ subscribeFills: c.fn as never });
    store.putOrder(openMgr(OID));
    await daemon.start();
    // the SDK stores each memo's note before onFill; simulate that + drive onFill.
    store.put(change("c0", 0));
    store.put(change("c1", 1));
    store.put(change("c2", 2));
    c.cap.opts!.onFill!(change("c2", 2));
    expect(store.get("c0")).toBeUndefined(); // superseded → pruned
    expect(store.get("c1")).toBeUndefined();
    expect(store.get("c2")).toBeDefined(); // latest kept
    daemon.stop();
  });
});
