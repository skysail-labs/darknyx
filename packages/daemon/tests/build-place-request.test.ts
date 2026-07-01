/**
 * buildPlaceRequest tests — the proving + body-build wiring, no live CVM.
 *
 * Injects a fake VALID_INPUT prover + a fake `/tree/inclusion` fetch, so the
 * test exercises the REAL keystore signing + SDK buildOrder (anchor pool,
 * canonical digest) without snarkjs or a gateway, and asserts the produced
 * `POST /orders` body is keyed to the right order id + trading key.
 */

import { describe, expect, it, vi } from "vitest";

import { buildPlaceRequest } from "../src/build-place-request.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import {
  deriveOrderId,
  limitPolicy,
  OrderSide,
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

const note: StoredNote = {
  commitment: "aa".repeat(32),
  tokenMint: new Uint8Array(32).fill(9),
  amount: 1_000_000n,
  ownerCommitment: 12345n,
  innerHash: 7n,
  leafIndex: 0n,
};

/** Fake `/tree/inclusion` response (20-level path). */
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

/** Fake prover — returns canned proof bytes + the witness's root. */
const fakeProver: ValidInputProver = async (params) => ({
  proofBytes: new Uint8Array(256).fill(1),
  merkleRoot: params.witness.merkleRoot,
});

describe("buildPlaceRequest", () => {
  it("assembles a signed body keyed to the HD order id + trading key", async () => {
    const ks = keystore();
    const seedIndex = 4;

    const { request, orderId } = await buildPlaceRequest({
      keystore: ks,
      note,
      seedIndex,
      intent: {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n }),
        amount: 500n,
      },
      gatewayUrl: "https://gw.example",
      token: "tok",
      prover: fakeProver,
      fetchImpl: fakeFetch(),
    });

    const expectId = deriveOrderId(ks.masterSeed, seedIndex);
    expect(Buffer.from(orderId)).toEqual(Buffer.from(expectId));
    expect(request.order_id).toBe(Buffer.from(expectId).toString("hex"));
    expect(request.trading_key).toBe(
      Buffer.from(ks.tradingPublicKey(seedIndex)).toString("hex"),
    );
    expect(request.side).toBe("bid");
    expect(request.note_commitment).toBe(note.commitment);
    // VALID_INPUT proof = 256 bytes (512 hex chars)
    expect(request.valid_input_proof).toHaveLength(512);
    // the deterministic anchor pool rides along
    expect(request.anchors).toHaveLength(10);
    // signed with a non-empty trading-key signature
    expect(request.trading_key_signature).toMatch(/^[0-9a-f]{128}$/);
  });

  it("derives different order ids for different seed indices", async () => {
    const ks = keystore();
    const common = {
      keystore: ks,
      note,
      intent: {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n }),
        amount: 500n,
      },
      gatewayUrl: "https://gw",
      token: "t",
      prover: fakeProver,
      fetchImpl: fakeFetch(),
    };
    const a = await buildPlaceRequest({ ...common, seedIndex: 0 });
    const b = await buildPlaceRequest({ ...common, seedIndex: 1 });
    expect(a.request.order_id).not.toBe(b.request.order_id);
    expect(a.request.trading_key).not.toBe(b.request.trading_key);
  });
});
