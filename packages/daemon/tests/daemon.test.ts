/**
 * Daemon wiring tests — the assembled object with all I/O faked (no CVM).
 * Real Keystore + :memory: store + real engine; fake prover/placer/fetch/streams.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RootVerifier, DepositParams } from "@darknyx/sdk";
import { PublicKey } from "@solana/web3.js";

import { Daemon, type DaemonEvent, type DaemonDeps } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import type { DaemonConfig } from "../src/config.js";
import type { OrderPlacer } from "../src/order-placer.js";
import type { ManagedOrder } from "../src/types.js";
import { MemoryOrderSequence } from "../src/order-sequence.js";
import {
  limitPolicy,
  OrderSide,
  type PlaceOrderResponse,
  type StoredNote,
  type ValidInputProver,
} from "@darknyx/sdk";

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

class CountingKeystore extends Keystore {
  derivations = 0;

  protected override tradingKeypair(index: number) {
    this.derivations += 1;
    return super.tradingKeypair(index);
  }
}

function countingKeystore(): CountingKeystore {
  const base = keystore();
  return new CountingKeystore({
    masterSeed: base.masterSeed,
    ownerBlinding: base.ownerBlinding,
    r0: 1n,
    r1: 2n,
    r2: 3n,
    rootKeyPubkey: new Uint8Array(32).fill(4),
  });
}

const config = (): DaemonConfig => ({
  gatewayUrl: "https://gw",
  // Legacy path: predates T-03P and exercises the gateway-terminated
  // transport. Stated rather than defaulted.
  transportMode: "gateway-terminated" as const,
  gatewayWsUrl: "wss://gw",
  token: "tok",
  rpcUrl: "https://rpc",
  dbPath: ":memory:",
  controlPort: 0,
  keystorePath: "x",
  orderSequencePath: "x.order-sequence",
  // Required by DaemonConfig. The fixture predates these fields and nothing
  // caught the omission, because test files were never typechecked.
  // `verifyAttestation: false` in mkDaemon() is what actually disables the
  // attestation path here; these just satisfy the config shape.
  attestationStrict: false,
  attestOnchainCheck: false,
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
  return vi.fn(async (input: string | URL | Request) => {
    const url = new URL(
      typeof input === "string" || input instanceof URL ? input : input.url,
    );
    if (url.pathname === "/info") {
      return new Response(
        JSON.stringify({
          app_id: "app_test",
          compose_hash: "11".repeat(32),
          tee_pubkey: PublicKey.default.toBase58(),
          tee_pubkeys: [PublicKey.default.toBase58()],
          boot_session_id: "5a".repeat(32),
        }),
        { status: 200 },
      );
    }
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

function mkDaemon(extra: Partial<DaemonDeps> = {}) {
  return new Daemon({
    config: config(),
    keystore: keystore(),
    store,
    orderSequence: new MemoryOrderSequence(),
    prover: fakeProver,
    placer,
    fetchImpl: fakeFetch(),
    subscribeFills: capture().fn as never,
    subscribeOrders: capture().fn as never,
    verifyAttestation: false, // attestation covered in attestation.test.ts
    verifyRoot: false, // on-chain root gate has dedicated SDK/daemon tests
    // These suites stand up no CVM and no RPC; boot reconciliation (SW-11) has
    // its own coverage in reconcile.test.ts.
    reconcileOnStart: false,
    ...extra,
  });
}

async function readyDaemon(extra: Partial<DaemonDeps> = {}): Promise<Daemon> {
  const daemon = mkDaemon(extra);
  await daemon.start();
  return daemon;
}

describe("Daemon — placeOrder", () => {
  it("builds, places, and moves the order to open; emits an order event", async () => {
    const daemon = await readyDaemon();
    const events: DaemonEvent[] = [];
    daemon.subscribe((e) => events.push(e));

    const { orderId, arrivalSlot } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
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
    const daemon = await readyDaemon();
    const intent = {
      symbol: "SOL-USDC",
      side: OrderSide.Bid,
      policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
      amount: 500n,
    };
    const a = await daemon.placeOrder(intent, note);
    const b = await daemon.placeOrder(intent, note);
    expect(a.orderId).not.toBe(b.orderId);
    const idxs = daemon.listOrders().map((o) => o.seedIndex);
    expect(new Set(idxs).size).toBe(2);
  });

  it("burns a reserved index when placement fails", async () => {
    const orderSequence = new MemoryOrderSequence();
    const daemon = await readyDaemon({ orderSequence });
    (placer.place as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("gateway unavailable"),
    );
    const intent = {
      symbol: "SOL-USDC",
      side: OrderSide.Bid,
      policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
      amount: 500n,
    };
    await expect(daemon.placeOrder(intent, note)).rejects.toThrow(
      /gateway unavailable/,
    );
    expect(orderSequence.nextIndex).toBe(1);

    await daemon.placeOrder(intent, note);
    expect(daemon.listOrders().at(-1)?.seedIndex).toBe(1);
  });

  it("runs the root-ring verifier before proving a placement", async () => {
    const verifyRoot = vi.fn<RootVerifier>(async () => {});
    const daemon = await readyDaemon({ verifyRoot });
    await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
        amount: 500n,
      },
      note,
    );
    expect(verifyRoot).toHaveBeenCalledOnce();
    expect(Buffer.from(verifyRoot.mock.calls[0][0])).toEqual(
      Buffer.from(new Uint8Array(32).fill(0xbb)),
    );
  });
});

describe("Daemon — cancelOrder", () => {
  it("derives one keypair for placement and one for cancellation", async () => {
    const ks = countingKeystore();
    const daemon = await readyDaemon({ keystore: ks });
    const { orderId } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
        amount: 500n,
      },
      note,
    );
    expect(ks.derivations).toBe(1);
    await daemon.cancelOrder(orderId);
    expect(ks.derivations).toBe(2);
  });

  it("signs + sends a cancel and drives the order to cancelled", async () => {
    const daemon = await readyDaemon();
    const { orderId } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
        amount: 500n,
      },
      note,
    );
    await daemon.cancelOrder(orderId);
    expect(placer.cancelled).toContain(orderId);
    expect(store.getOrder(orderId)!.phase).toBe("cancelled");
  });

  it("rejects an unknown order", async () => {
    const daemon = await readyDaemon();
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

  it("start() shares one multiplexed session across both channels", async () => {
    const fills = capture();
    const orders = capture();
    const daemon = mkDaemon({
      subscribeFills: fills.fn as never,
      subscribeOrders: orders.fn as never,
    });
    await daemon.start();
    expect(fills.cap.opts).toBeDefined();
    expect(orders.cap.opts).toBeDefined();
    expect((fills.cap.opts as { streamClient?: unknown }).streamClient).toBe(
      (orders.cap.opts as { streamClient?: unknown }).streamClient,
    );
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
    policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
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
    const daemon = await readyDaemon();
    const n = spendable(BIG, 1000n);
    store.put(n);
    // place an order spending it → it becomes locked (order open)
    await daemon.placeOrder(intent, n);
    expect(daemon.selectNote({ mint: MINT, minAmount: 1n })).toBeUndefined();
  });

  it("prunes the collateral note once a fill consumes it", async () => {
    const daemon = await readyDaemon();
    const n = spendable(COLL, 1000n);
    store.put(n);
    const { orderId } = await daemon.placeOrder(intent, n);
    expect(store.get(COLL)).toBeDefined(); // still there while resting

    // a fill consumes and rotates the collateral note
    await (
      daemon as unknown as {
        engine: { dispatch: (id: string, e: unknown) => Promise<unknown> };
      }
    ).engine.dispatch(orderId, {
      type: "fill",
      producedChangeNote: true,
    });
    expect(store.get(COLL)).toBeUndefined(); // pruned
  });
});

describe("Daemon — deposit", () => {
  const MINT = new Uint8Array(32).fill(9);

  it("calls the deposit fn, stores the minted note, returns it", async () => {
    // Typed with the REAL DepositParams, not a two-field structural stand-in.
    // With the narrow inline type, `mock.calls[0][0]` did not carry
    // `depositIndex`, and the assertion below had to cast to reach it — a cast
    // that quietly asserted nothing about what the daemon actually passed.
    const depositFn = vi.fn(async (params: DepositParams) => ({
      signature: "depsig",
      leafIndex: 42n,
      noteCommitment: new Uint8Array(32).fill(0xcd),
      notePlaintext: {
        tokenMint: params.tokenMint,
        amount: params.amount,
        ownerCommitment: 7n,
        innerHash: 8n,
      },
    }));
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
    expect(typeof depositFn.mock.calls[0][0].depositIndex).toBe("bigint");
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
  const change = (
    commitment: string,
    consumedCommitment: string,
  ): StoredNote => ({
    commitment,
    tokenMint: MINT,
    amount: 100n,
    ownerCommitment: 9n,
    innerHash: 7n,
    orderId: OID,
    consumedCommitment,
  });
  const openMgr = (orderId: string): ManagedOrder => ({
    orderId,
    seedIndex: 0,
    // Required by ManagedOrder since isolated market books landed.
    symbol: "SOL-USDC",
    side: "bid",
    priceRaw: 1n,
    sizeRaw: 1n,
    phase: "open",
    mergeInFlight: false,
    pendingChangeNotes: 0,
    createdAt: 0,
    updatedAt: 0,
  });

  it("selectNote excludes an open order's re-locked rolling residual", () => {
    const daemon = mkDaemon();
    store.putOrder(openMgr(OID));
    store.put(change("res", "input")); // the open order's rolling residual
    // locked while the order is open → not selectable
    expect(daemon.selectNote({ mint: MINT, minAmount: 1n })).toBeUndefined();
  });

  it("a continuation fill prunes the order's prior residuals (keeps the latest)", async () => {
    const c = capture<{ onFill?: (n: StoredNote) => void }>();
    const daemon = mkDaemon({ subscribeFills: c.fn as never });
    store.putOrder(openMgr(OID));
    await daemon.start();
    // the SDK stores each memo's note before onFill; simulate that + drive onFill.
    store.put(change("c0", "input"));
    c.cap.opts!.onFill!(change("c0", "input"));
    store.put(change("c1", "c0"));
    c.cap.opts!.onFill!(change("c1", "c0"));
    store.put(change("c2", "c1"));
    c.cap.opts!.onFill!(change("c2", "c1"));
    expect(store.get("c0")).toBeUndefined();
    expect(store.get("c1")).toBeUndefined();
    expect(store.get("c2")).toBeDefined(); // latest kept
    daemon.stop();
  });
});

describe("daemon wiring", () => {
  it("a fills resync triggers reconciliation and pauses placement", async () => {
    // The signal existed and both listeners forwarded it; the daemon simply
    // never passed a handler, so it was discarded at the top of the stack.
    // Driving the real seam proves the wiring rather than inspecting source.
    const fills = capture<{ onResync?: (r: string) => void }>();
    const daemon = mkDaemon({ subscribeFills: fills.fn as never });
    await daemon.start();

    const events: DaemonEvent[] = [];
    daemon.subscribe((e) => events.push(e));

    expect(
      fills.cap.opts?.onResync,
      "the daemon must hand down onResync",
    ).toBeTypeOf("function");

    // Fire the 1011 signal the SDK raises on a buffer overrun.
    fills.cap.opts!.onResync!("buffer overrun");

    // Placement is refused while state is being re-derived — silent drift is
    // the failure mode this exists to end.
    await expect(
      daemon.placeOrder(
        {
          symbol: "SOL-USDC",
          side: OrderSide.Bid,
          policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
          amount: 500n,
        },
        note,
      ),
    ).rejects.toThrow(/reconcil/i);

    // And the operator hears about it.
    expect(
      events.some(
        (e) =>
          e.type === "error" &&
          e.context === "reconcile" &&
          /reconciling/i.test(e.message),
      ),
      "the operator must hear about it — silent drift is the failure mode this ends",
    ).toBe(true);

    daemon.stop();
  });
  it("a failing reconcile never produces an unhandled rejection", async () => {
    // The listener callbacks are synchronous and cannot await, so `onResync`
    // discards the promise. If `reconcileNow` could reject, that becomes an
    // unhandled rejection — which Node turns into process exit by default,
    // crashing the daemon in exactly the situation the feature exists to
    // survive. (This harness has no CVM behind it, so the reconcile below
    // genuinely fails; that is the point.)
    //
    // It also cost a CI run: `vitest` reported "178 passed" while exiting 1 on
    // the unhandled rejection, and a grep for the pass count hid it.
    const fills = capture<{ onResync?: (r: string) => void }>();
    const daemon = mkDaemon({ subscribeFills: fills.fn as never });
    await daemon.start();

    const rejections: unknown[] = [];
    const onUnhandled = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onUnhandled);
    try {
      fills.cap.opts!.onResync!("buffer overrun");
      // Give the discarded promise a turn to settle and the rejection a turn
      // to reach the loop.
      await new Promise((r) => setTimeout(r, 50));
      // Asserted while the listener is still attached, so a late rejection
      // cannot slip through after it is detached.
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }

    // ...and the failure is still reported, not swallowed.
    const result = await daemon.reconcileNow("direct");
    expect(result.errors.length).toBeGreaterThan(0);

    daemon.stop();
  });
  it("a failed reconcile keeps placement paused until a clean one runs", async () => {
    // A failed reconcile means local state is UNVERIFIED, not merely stale.
    // Resuming placement then risks spending collateral the chain has already
    // consumed, so the pause must outlive the attempt that failed.
    const daemon = mkDaemon();
    await daemon.start();

    const result = await daemon.reconcileNow("gap");
    expect(result.errors.length).toBeGreaterThan(0);

    // The transient `reconciling` flag has cleared…
    expect(daemon.getTrustStatus().reconciling).toBe(false);
    // …but the failure latch has not.
    expect(daemon.getTrustStatus().reconcileFailureReason).toBeTruthy();
    expect(daemon.getTrustStatus().tradingEnabled).toBe(false);
    await expect(
      daemon.placeOrder(
        {
          symbol: "SOL-USDC",
          side: OrderSide.Bid,
          policy: limitPolicy({ priceLimit: 100n, expirySlot: 10_000n }),
          amount: 500n,
        },
        note,
      ),
    ).rejects.toThrow(/unverified/);

    daemon.stop();
  });

  it("a re-entrant call during the opening emit shares the one run", async () => {
    // The body's first act is a synchronous `emitError`. If `reconcileInFlight`
    // were assigned only after the IIFE was created, a subscriber that
    // re-entered here would have seen `null` and started a SECOND chain scan —
    // the duplication the sharing exists to prevent.
    const daemon = mkDaemon();
    await daemon.start();

    let reentrant: Promise<unknown> | null = null;
    daemon.subscribe((e) => {
      if (e.type === "error" && e.context === "reconcile" && !reentrant) {
        reentrant = daemon.reconcileNow("re-entrant");
      }
    });

    const first = await daemon.reconcileNow("gap");
    expect(reentrant, "the emit must have re-entered").not.toBeNull();
    expect(await reentrant).toBe(first);

    daemon.stop();
  });
});
