/**
 * buildOrder assembly + signature parity.
 *
 * buildOrder signs the v3 canonical digest, which is itself pinned to the Rust
 * matcher by `order-canonical-parity.test.ts` — so this test guards that
 * buildOrder (a) maps every wire field correctly and (b) signs the EXACT digest
 * a verifier recomputes. A regression in the assembly (wrong field, wrong
 * digest inputs, wrong viewing key or session id) breaks the signature check here before
 * it ever reaches the enclave.
 */

import { describe, it, expect } from "vitest";
import nacl from "tweetnacl";

import { buildOrder } from "../src/orders/build-order.js";
import { limitPolicy } from "../src/orders/builders.js";
import { OrderSide, orderCanonicalDigest } from "../src/orders/canonical.js";
import { noteCommitmentV2, ownerCommitment } from "../src/utxo/note.js";
import { deriveViewingEncKeypair } from "../src/keys/key-generators.js";

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("buildOrder", () => {
  it("assembles a signed POST /orders body and signs the canonical digest", async () => {
    // Fixed, reproducible inputs.
    const masterSeed = new Uint8Array(64).map((_, i) => i + 1);
    const spendingKey = 12_345_678_901_234_567_890n;
    const blinding = 99n;
    const innerHash = 0x1234n;
    const amount = 10_000_000n;
    const tokenMint = new Uint8Array(32).fill(7);

    const ownerCommit = await ownerCommitment(spendingKey, blinding);
    const note = {
      commitment: await noteCommitmentV2({
        tokenMint,
        amount,
        ownerCommitment: ownerCommit,
        innerHash,
      }),
      innerHash,
      amount,
    };
    const userCommitment = (() => {
      const v = new Uint8Array(32).fill(0x33);
      v[0] = 0; // BN254 Fr-safe top byte
      return v;
    })();
    const orderId = new Uint8Array(16);
    orderId[0] = 0xaa;
    orderId[15] = 1;

    const kp = nacl.sign.keyPair();
    const policy = limitPolicy({ priceLimit: 150_000_000n });
    const sessionId = new Uint8Array(32).fill(0x66);

    const body = await buildOrder({
      masterSeed,
      spendingKey,
      ownerCommitment: ownerCommit,
      userCommitment,
      tradingKey: kp.publicKey,
      sign: (d) => nacl.sign.detached(d, kp.secretKey),
      note,
      validInput: {
        proofBytes: new Uint8Array(256),
        merkleRoot: new Uint8Array(32).fill(0xdd),
      },
      symbol: "SOL-USDC",
      side: OrderSide.Bid,
      policy,
      amount,
      orderId,
      sessionId,
    });

    // ── Field mapping ──
    expect(body.side).toBe("bid");
    expect(body.order_type).toBe("limit");
    expect(body.amount).toBe(10_000_000);
    expect(body.price_limit).toBe(150_000_000);
    expect(body.min_fill_size).toBe(0);
    expect(body.arrival_nonce).toBe(1);
    expect(body.order_id).toBe(toHex(orderId));
    expect(body.note_commitment).toBe(toHex(note.commitment));
    expect(body.user_commitment).toBe(toHex(userCommitment));
    expect(body.trading_key).toBe(toHex(kp.publicKey));
    expect(body.merkle_root).toBe("dd".repeat(32));
    expect(body.valid_input_proof).toBe("00".repeat(256));
    expect(body.collateral_amount).toBe(10_000_000);
    expect(body.session_id).toBe(toHex(sessionId));
    // Recovery on by default: viewing_pubkey is the seed-derived X25519 key.
    // It is bound into the signed canonical body.
    expect(body.viewing_pubkey).toBe(
      toHex(deriveViewingEncKeypair(masterSeed).publicKey),
    );

    // ── Signature parity: verify against the INDEPENDENTLY recomputed digest ──
    const viewingPubkey = deriveViewingEncKeypair(masterSeed).publicKey;
    const digest = orderCanonicalDigest({
      symbol: new TextEncoder().encode("SOL-USDC"),
      side: OrderSide.Bid,
      orderType: policy.orderType,
      amount,
      priceLimit: policy.priceLimit,
      minFillSize: policy.minFillSize,
      expirySlot: policy.expirySlot,
      orderId,
      noteCommitment: note.commitment,
      userCommitment,
      arrivalNonce: 1n,
      viewingPubkey,
      sessionId,
    });
    const sig = fromHex(body.trading_key_signature);
    expect(nacl.sign.detached.verify(digest, sig, kp.publicKey)).toBe(true);

    // A tampered digest must NOT verify (sanity on the guard itself).
    const tampered = digest.slice();
    tampered[0] ^= 0xff;
    expect(nacl.sign.detached.verify(tampered, sig, kp.publicKey)).toBe(false);
  });

  it("rejects an over-2^53 amount (JSON number precision boundary)", async () => {
    const kp = nacl.sign.keyPair();
    await expect(
      buildOrder({
        masterSeed: new Uint8Array(64),
        spendingKey: 1n,
        ownerCommitment: 1n,
        userCommitment: new Uint8Array(32),
        tradingKey: kp.publicKey,
        sign: (d) => nacl.sign.detached(d, kp.secretKey),
        note: {
          commitment: new Uint8Array(32),
          innerHash: 1n,
          amount: 2n ** 60n,
        },
        validInput: {
          proofBytes: new Uint8Array(256),
          merkleRoot: new Uint8Array(32),
        },
        symbol: "X",
        side: OrderSide.Ask,
        policy: limitPolicy({ priceLimit: 1n }),
        amount: 2n ** 60n,
        orderId: new Uint8Array(16).fill(1),
        sessionId: new Uint8Array(32).fill(0x66),
      }),
    ).rejects.toThrow(/2\^53/);
  });
});
