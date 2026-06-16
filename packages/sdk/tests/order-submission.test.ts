/**
 * Order-submission surface (Phase 5 / D2): the inclusion-proof fetch, the
 * prove→build orchestrator (with a stub prover), and the `/ws/trading`
 * send-client driven by an injected socket.
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
import {
  NyxApiError,
  type PlaceOrderRequest,
} from "../src/orders/order-client.js";
import { limitPolicy } from "../src/orders/builders.js";
import { OrderSide } from "../src/orders/canonical.js";
import { noteCommitmentV2, ownerCommitment } from "../src/utxo/note.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

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
    const userCommitment = new Uint8Array(32); // top byte 0 = Fr-safe

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
      userCommitment,
      tradingKey: kp.publicKey,
      sign: (d) => nacl.sign.detached(d, kp.secretKey),
      note: { commitment, innerHash, amount },
      symbol: "SOL-USDC",
      side: OrderSide.Ask,
      policy: limitPolicy({ priceLimit: 100n }),
      amount,
      orderId: new Uint8Array(16).fill(2),
    });

    expect(body.merkle_root).toBe("ee".repeat(32));
    expect(body.valid_input_proof).toBe("01".repeat(256));
    expect(body.note_commitment).toBe(hex(commitment));
    expect(body.anchors).toHaveLength(10);
  });
});

// A controllable fake socket for the send-client tests.
class FakeSocket implements SendableWebSocketLike {
  listeners: Record<string, ((ev?: unknown) => void)[]> = {};
  sent: string[] = [];
  addEventListener(type: string, cb: (ev?: unknown) => void): void {
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

describe("TradingClient (/ws/trading send-client)", () => {
  async function connected(): Promise<{
    client: TradingClient;
    sock: FakeSocket;
  }> {
    const sock = new FakeSocket();
    const client = new TradingClient({
      gatewayWsUrl: "wss://x",
      token: "t",
      webSocketFactory: () => sock,
    });
    const p = client.connect();
    sock.fire("open");
    await p;
    return { client, sock };
  }

  it("correlates a place reply to its request_id", async () => {
    const { client, sock } = await connected();
    const placeP = client.place({
      symbol: "SOL-USDC",
    } as unknown as PlaceOrderRequest);
    const frame = sock.lastFrame();
    expect(frame.op).toBe("order.place");
    sock.fire("message", {
      data: JSON.stringify({
        op: "order.place",
        seq: 1,
        request_id: frame.request_id,
        result: { order_id: "ab", status: "accepted", arrival_slot: 5 },
      }),
    });
    const res = await placeP;
    expect(res.order_id).toBe("ab");
  });

  it("rejects with NyxApiError on an error frame", async () => {
    const { client, sock } = await connected();
    const cancelP = client.cancel("ab", {
      trading_key: "00",
      cancel_nonce: 1,
      trading_key_signature: "00",
    });
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
    await expect(cancelP).rejects.toBeInstanceOf(NyxApiError);
    await cancelP.catch((e: NyxApiError) => expect(e.code).toBe(1103));
  });

  it("fails in-flight requests when the socket closes", async () => {
    const { client, sock } = await connected();
    const p = client.ping();
    sock.fire("close", { code: 1006 });
    await expect(p).rejects.toThrow(/closed/);
  });
});
