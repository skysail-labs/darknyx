/**
 * Order-submission surface: the inclusion-proof fetch, the
 * prove→build orchestrator (with a stub prover), and the `/v1/stream`
 * client driven by an injected socket.
 */

import { describe, it, expect } from "vitest";
import nacl from "tweetnacl";

import {
  fetchInclusionProof,
  pathIndicesFromLeafIndex,
  proveAndBuildOrder,
  type ValidInputProver,
} from "../src/zk/valid-input-prover.js";
import {
  TradingClient,
  type SendableWebSocketLike,
} from "../src/orders/trading-ws-client.js";
import { DarknyxApiError } from "../src/orders/order-client.js";
import type { PlaceOrderRequest } from "../src/orders/build-order.js";
import { limitPolicy } from "../src/orders/builders.js";
import { OrderSide } from "../src/orders/canonical.js";
import { isTerminalUpdate } from "../src/orders/orders-ws-client.js";
import { noteCommitmentV2, ownerCommitment } from "../src/utxo/note.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const flushMicrotasks = async () => {
  for (let i = 0; i < 4; i += 1) await Promise.resolve();
};

describe("order settlement lifecycle", () => {
  it("keeps pending_settlement live and makes settlement_failed terminal", () => {
    expect(
      isTerminalUpdate({
        order_id: "01".repeat(16),
        kind: "pending_settlement",
        lock_expiry_slot: 500,
      }),
    ).toBe(false);
    expect(
      isTerminalUpdate({
        order_id: "01".repeat(16),
        kind: "settlement_failed",
        reason: "reverted",
        lock_expiry_slot: 500,
      }),
    ).toBe(true);
  });
});

describe("inclusion proof fetch", () => {
  it("parses the witness and derives path bits from the leaf index", async () => {
    const siblings = Array.from(
      { length: 20 },
      (_, i) => "0".repeat(63) + ((i % 9) + 1).toString(16),
    );
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          note_commitment: "ab",
          leaf_index: 5,
          merkle_root: "dd".repeat(32),
          siblings,
        }),
        { status: 200 },
      )) as unknown as typeof fetch;

    const w = await fetchInclusionProof(
      { baseUrl: "https://x", token: "t", fetchImpl },
      "ab",
    );
    expect(w.leafIndex).toBe(5);
    expect(w.siblings).toHaveLength(20);
    expect(hex(w.merkleRoot)).toBe("dd".repeat(32));
    // 5 = 0b101 → bits [1,0,1,0,0,...]
    expect(w.pathIndices.slice(0, 4)).toEqual([1, 0, 1, 0]);
  });

  it("derives path indices little-endian by level", () => {
    expect(pathIndicesFromLeafIndex(0b1011, 5)).toEqual([1, 1, 0, 1, 0]);
  });
});

describe("proveAndBuildOrder", () => {
  it("fetches the witness, proves (stub), and assembles a signed order", async () => {
    const spendingKey = 7n;
    const blinding = 3n;
    const innerHash = 0x55n;
    const amount = 1_000n;
    const tokenMint = new Uint8Array(32).fill(9);
    const owner = await ownerCommitment(spendingKey, blinding);
    const commitment = await noteCommitmentV2({
      tokenMint,
      amount,
      ownerCommitment: owner,
      innerHash,
    });

    const kp = nacl.sign.keyPair();

    // Stub prover: echoes back a fixed proof + the witness root.
    const prover: ValidInputProver = async (p) => ({
      proofBytes: new Uint8Array(256).fill(1),
      merkleRoot: p.witness.merkleRoot,
    });

    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          note_commitment: hex(commitment),
          leaf_index: 2,
          merkle_root: "ee".repeat(32),
          siblings: Array.from({ length: 20 }, () => "0".repeat(63) + "1"),
        }),
        { status: 200 },
      )) as unknown as typeof fetch;

    const body = await proveAndBuildOrder({
      baseUrl: "https://x",
      token: "t",
      prover,
      ownerCommitmentBlinding: blinding,
      tokenMint,
      fetchImpl,
      masterSeed: new Uint8Array(64).fill(5),
      spendingKey,
      ownerCommitment: owner,
      tradingKey: kp.publicKey,
      sign: (d) => nacl.sign.detached(d, kp.secretKey),
      note: { commitment, innerHash, amount },
      symbol: "SOL-USDC",
      side: OrderSide.Ask,
      policy: limitPolicy({ priceLimit: 100n, expirySlot: 5_500n }),
      amount,
      orderId: new Uint8Array(16).fill(2),
      sessionId: new Uint8Array(32).fill(0x66),
    });

    expect(body.merkle_root).toBe("ee".repeat(32));
    expect(body.valid_input_proof).toBe("01".repeat(256));
    expect(body.note_commitment).toBe(hex(commitment));
    expect(body.session_id).toBe("66".repeat(32));
  });
});

// A controllable fake socket for the send-client tests.
class FakeSocket implements SendableWebSocketLike {
  listeners: Record<string, ((ev?: unknown) => void)[]> = {};
  sent: string[] = [];
  // `any` callback param: a single mock signature can't satisfy the interface's
  // four typed addEventListener overloads otherwise (callback contravariance).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  addEventListener(type: string, cb: (ev: any) => void): void {
    (this.listeners[type] ||= []).push(cb as (ev?: unknown) => void);
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(): void {
    this.fire("close", { code: 1000 });
  }
  fire(type: string, ev?: unknown): void {
    (this.listeners[type] ?? []).forEach((cb) => cb(ev));
  }
  lastFrame(): { op: string; request_id: string; [k: string]: unknown } {
    return JSON.parse(this.sent[this.sent.length - 1]);
  }
}

describe("TradingClient (/v1/stream session)", () => {
  async function connected(): Promise<{
    client: TradingClient;
    sock: FakeSocket;
  }> {
    const sock = new FakeSocket();
    const client = new TradingClient({
      gatewayWsUrl: "wss://x",
      token: "t",
      autoReconnect: false,
      webSocketFactory: () => sock,
    });
    const p = client.connect();
    sock.fire("open");
    await flushMicrotasks();
    const login = sock.lastFrame();
    expect(login).toMatchObject({ op: "login", token: "t" });
    sock.fire("message", {
      data: JSON.stringify({
        op: "login",
        seq: 1,
        request_id: login.request_id,
        account_id: "acct",
      }),
    });
    await p;
    return { client, sock };
  }

  it("correlates a place reply to its request_id", async () => {
    const { client, sock } = await connected();
    const placeP = client.place({
      symbol: "SOL-USDC",
    } as unknown as PlaceOrderRequest);
    await flushMicrotasks();
    const frame = sock.lastFrame();
    expect(frame.op).toBe("order.place");
    sock.fire("message", {
      data: JSON.stringify({
        op: "order.place",
        seq: 2,
        request_id: frame.request_id,
        result: { order_id: "ab", status: "accepted", arrival_slot: 5 },
      }),
    });
    const res = await placeP;
    expect(res.order_id).toBe("ab");
  });

  it("rejects with DarknyxApiError on an error frame", async () => {
    const { client, sock } = await connected();
    const cancelP = client.cancel("ab", {
      trading_key: "00",
      cancel_nonce: "1",
      // Required since S-07: a cancel signature is scoped to a boot session.
      // The test body omitted it and nothing caught that, because test files
      // were never typechecked.
      session_id: "00".repeat(32),
      trading_key_signature: "00",
    });
    await flushMicrotasks();
    const frame = sock.lastFrame();
    sock.fire("message", {
      data: JSON.stringify({
        op: "error",
        seq: 2,
        request_id: frame.request_id,
        code: 1103,
        message: "not owner",
      }),
    });
    await expect(cancelP).rejects.toBeInstanceOf(DarknyxApiError);
    await cancelP.catch((e: DarknyxApiError) => expect(e.code).toBe(1103));
  });

  it("fails in-flight requests when the socket closes", async () => {
    const { client, sock } = await connected();
    const p = client.ping();
    await flushMicrotasks();
    sock.fire("close", { code: 1006 });
    await expect(p).rejects.toThrow(/closed/);
  });

  it("keeps the bearer token out of the URL and refreshes in-band", async () => {
    const sock = new FakeSocket();
    const urls: string[] = [];
    const tokens = ["initial", "refreshed"];
    const client = new TradingClient({
      gatewayWsUrl: "wss://x/",
      token: "unused",
      tokenProvider: async () => tokens.shift() ?? "refreshed",
      autoReconnect: false,
      webSocketFactory: (url) => {
        urls.push(url);
        return sock;
      },
    });
    const connected = client.connect();
    sock.fire("open");
    await flushMicrotasks();
    const login = sock.lastFrame();
    expect(urls).toEqual(["wss://x/v1/stream"]);
    expect(urls[0]).not.toContain("initial");
    sock.fire("message", {
      data: JSON.stringify({
        op: "login",
        seq: 1,
        request_id: login.request_id,
        account_id: "acct",
      }),
    });
    await connected;

    sock.fire("message", {
      data: JSON.stringify({ op: "auth_expired", seq: 2, expires_at: 100 }),
    });
    await flushMicrotasks();
    const refresh = sock.lastFrame();
    expect(refresh).toMatchObject({ op: "login", token: "refreshed" });
    sock.fire("message", {
      data: JSON.stringify({
        op: "login",
        seq: 3,
        request_id: refresh.request_id,
        account_id: "acct",
      }),
    });
    client.close();
  });

  it("closes for resync on a connection-global sequence gap", async () => {
    const resync: string[] = [];
    const { client, sock } = await connected();
    client.subscribeChannel("fills", () => undefined, {
      onResync: (reason) => resync.push(reason),
    });
    sock.fire("message", {
      data: JSON.stringify({ op: "pong", seq: 4 }),
    });
    expect(resync[0]).toContain("expected 2, received 4");
    client.close();
  });

  it("reconnects, logs in with cancel-on-disconnect, and resubscribes", async () => {
    const sockets: FakeSocket[] = [];
    const client = new TradingClient({
      gatewayWsUrl: "wss://x",
      token: "t",
      cancelOnDisconnect: true,
      reconnectDelayMs: 0,
      webSocketFactory: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
    });
    const sub = client.subscribeChannel("fills", () => undefined);
    const ready = client.connect();
    const first = sockets[0];
    first.fire("open");
    await flushMicrotasks();
    const firstLogin = first.lastFrame();
    expect(firstLogin).toMatchObject({
      op: "login",
      cancel_on_disconnect: true,
    });
    first.fire("message", {
      data: JSON.stringify({
        op: "login",
        seq: 1,
        request_id: firstLogin.request_id,
        account_id: "acct",
      }),
    });
    await ready;
    expect(first.sent.map((raw) => JSON.parse(raw).op)).toContain("subscribe");

    first.fire("close", { code: 1006, reason: "network loss" });
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(sockets).toHaveLength(2);
    const second = sockets[1];
    second.fire("open");
    await flushMicrotasks();
    const secondLogin = second.lastFrame();
    expect(secondLogin).toMatchObject({
      op: "login",
      cancel_on_disconnect: true,
    });
    second.fire("message", {
      data: JSON.stringify({
        op: "login",
        seq: 1,
        request_id: secondLogin.request_id,
        account_id: "acct",
      }),
    });
    await flushMicrotasks();
    expect(second.sent.map((raw) => JSON.parse(raw).op)).toContain("subscribe");
    sub.close();
    client.close();
  });
});
