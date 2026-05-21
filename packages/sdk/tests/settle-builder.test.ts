/**
 * Phase-5 — `tee_forced_settle` SDK builder.
 *
 * Verifies that:
 *   1. `canonicalPayloadHash` is deterministic + byte-identical to the
 *      Rust fixture used by `programs/vault/src/instructions/tee_forced_settle.rs`.
 *   2. The Ed25519 precompile ix layout matches what the on-chain
 *      `verify_tee_signature` decoder expects.
 *   3. `buildSettleIx` produces the correct accounts list and includes
 *      the expected vault PDAs.
 *   4. `serializePayload` byte-length matches the on-chain Borsh struct.
 *
 * All tests are pure TypeScript — no RPC / LiteSVM required.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Keypair, PublicKey, SYSVAR_INSTRUCTIONS_PUBKEY } from "@solana/web3.js";

import {
  ED25519_PROGRAM_ID,
  RELOCK_ORDER_ID_NONE,
  ZERO_COMMITMENT,
  buildEd25519VerifyIx,
  buildSettleIx,
  canonicalPayloadHash,
  exactFillPayload,
  serializePayload,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";

const PROGRAM_ID = new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

function filled(len: number, v: number): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(v);
  return b;
}

describe("Phase 5 — settle-builder: canonicalPayloadHash", () => {
  it("[hash_deterministic] identical payloads hash to the same 32 bytes", () => {
    const p = exactFillPayload({
      matchId: filled(16, 0x11),
      noteAcommitment: filled(32, 0xA1),
      noteBcommitment: filled(32, 0xB1),
      noteCcommitment: filled(32, 0xC1),
      noteDcommitment: filled(32, 0xD1),
      nullifierA: filled(32, 0xEA),
      nullifierB: filled(32, 0xEB),
      orderIdA: filled(16, 0x01),
      orderIdB: filled(16, 0x02),
      baseAmount: 100n,
      quoteAmount: 5_000n,
    });
    const h1 = canonicalPayloadHash(p);
    const h2 = canonicalPayloadHash(p);
    expect(h1).toEqual(h2);
    expect(h1.length).toBe(32);
  });

  it("[hash_field_sensitive] any field change flips the hash", () => {
    const base = exactFillPayload({
      matchId: filled(16, 0x11),
      noteAcommitment: filled(32, 0xA1),
      noteBcommitment: filled(32, 0xB1),
      noteCcommitment: filled(32, 0xC1),
      noteDcommitment: filled(32, 0xD1),
      nullifierA: filled(32, 0xEA),
      nullifierB: filled(32, 0xEB),
      orderIdA: filled(16, 0x01),
      orderIdB: filled(16, 0x02),
      baseAmount: 100n,
      quoteAmount: 5_000n,
    });
    const h = canonicalPayloadHash(base);
    const h2 = canonicalPayloadHash({ ...base, baseAmount: 101n });
    expect(h2).not.toEqual(h);
  });

  it("[hash_rust_fixture] matches the Rust-side canonical hash for a fixed input", () => {
    // The Rust canonical_payload_hash is `hashv([tag, fields...])` which is
    // equivalent to sha256(tag || concat(fields)) — the TS impl uses this
    // exact form, so we verify it byte-for-byte against an in-process
    // recompute that independently reproduces the update order.
    const p = exactFillPayload({
      matchId: filled(16, 0x11),
      noteAcommitment: filled(32, 0xA1),
      noteBcommitment: filled(32, 0xB1),
      noteCcommitment: filled(32, 0xC1),
      noteDcommitment: filled(32, 0xD1),
      nullifierA: filled(32, 0xEA),
      nullifierB: filled(32, 0xEB),
      orderIdA: filled(16, 0x01),
      orderIdB: filled(16, 0x02),
      baseAmount: 100n,
      quoteAmount: 5_000n,
    });
    const want = new Uint8Array(
      createHash("sha256")
        .update(Buffer.from("nyx-match-v5"))
        .update(p.matchId)
        .update(p.noteAcommitment)
        .update(p.noteBcommitment)
        .update(p.noteCcommitment)
        .update(p.noteDcommitment)
        .update(p.noteEcommitment)
        .update(p.noteFcommitment)
        .update(p.noteFeeCommitment)
        .update(p.nullifierA)
        .update(p.nullifierB)
        .update(p.orderIdA)
        .update(p.orderIdB)
        .update(u64LE(p.baseAmount))
        .update(u64LE(p.quoteAmount))
        .update(u64LE(p.buyerChangeAmt))
        .update(u64LE(p.sellerChangeAmt))
        .update(u64LE(p.buyerFeeAmt))
        .update(u64LE(p.sellerFeeAmt))
        .update(p.buyerRelockOrderId)
        .update(u64LE(p.buyerRelockExpiry))
        .update(p.sellerRelockOrderId)
        .update(u64LE(p.sellerRelockExpiry))
        .update(u64LE(p.clearingPrice))
        .update(u64LE(p.batchSlot))
        .digest(),
    );
    expect(canonicalPayloadHash(p)).toEqual(want);
  });
});

describe("Phase 5 — settle-builder: Ed25519 precompile ix", () => {
  it("[precompile_layout] header fields point at inline pubkey/sig/msg", () => {
    const tee = Keypair.generate();
    const msg = new Uint8Array(32).fill(0xBE);
    const sig = new Uint8Array(64).fill(0xFF);
    const ix = buildEd25519VerifyIx({
      teePubkey: tee.publicKey.toBytes(),
      signature: sig,
      message: msg,
    });
    expect(ix.programId.toBase58()).toBe(ED25519_PROGRAM_ID.toBase58());
    expect(ix.keys.length).toBe(0);

    const d = new Uint8Array(ix.data);
    expect(d[0]).toBe(1); // num_signatures
    expect(d[1]).toBe(0); // padding
    const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
    const sigOff = dv.getUint16(2, true);
    const sigIx = dv.getUint16(4, true);
    const pkOff = dv.getUint16(6, true);
    const pkIx = dv.getUint16(8, true);
    const msgOff = dv.getUint16(10, true);
    const msgLen = dv.getUint16(12, true);
    const msgIx = dv.getUint16(14, true);
    expect(sigIx).toBe(0xFFFF);
    expect(pkIx).toBe(0xFFFF);
    expect(msgIx).toBe(0xFFFF);
    expect(pkOff).toBe(16);
    expect(sigOff).toBe(16 + 32);
    expect(msgOff).toBe(16 + 32 + 64);
    expect(msgLen).toBe(msg.length);
    // Inline bytes
    expect(d.slice(pkOff, pkOff + 32)).toEqual(tee.publicKey.toBytes());
    expect(d.slice(sigOff, sigOff + 64)).toEqual(sig);
    expect(d.slice(msgOff, msgOff + msgLen)).toEqual(msg);
  });

  it("[precompile_rejects_wrong_sig_length] throws when sig length != 64", () => {
    expect(() =>
      buildEd25519VerifyIx({
        teePubkey: new Uint8Array(32),
        signature: new Uint8Array(32), // wrong
        message: new Uint8Array(32),
      }),
    ).toThrow(/64 bytes/);
  });
});

describe("Phase 5 — settle-builder: buildSettleIx", () => {
  it("[settle_accounts_layout] account ordering matches TeeForcedSettle struct", () => {
    const tee = Keypair.generate();
    const payload = exactFillPayload({
      matchId: filled(16, 0x11),
      noteAcommitment: filled(32, 0xA1),
      noteBcommitment: filled(32, 0xB1),
      noteCcommitment: filled(32, 0xC1),
      noteDcommitment: filled(32, 0xD1),
      nullifierA: filled(32, 0xEA),
      nullifierB: filled(32, 0xEB),
      orderIdA: filled(16, 0x01),
      orderIdB: filled(16, 0x02),
      baseAmount: 100n,
      quoteAmount: 5_000n,
    });
    const ix = buildSettleIx({
      programId: PROGRAM_ID,
      teeAuthority: tee.publicKey,
      payload,
      quoteMint: new PublicKey(filled(32, 0xC0)),
      baseMint: new PublicKey(filled(32, 0xC1)),
      // v3.1: priceCommitment derives the ValidPriceMarker PDA. The unit
      // tests don't exercise the marker; a fixed sentinel keeps the
      // expected account list deterministic.
      priceCommitment: filled(32, 0xC2),
    });

    expect(ix.programId.toBase58()).toBe(PROGRAM_ID.toBase58());
    // v3.1: 12 base accounts + ValidCreateMarker + ValidPriceMarker = 14.
    expect(ix.keys.length).toBe(14);
    expect(ix.keys[0].pubkey.toBase58()).toBe(tee.publicKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[10].pubkey.toBase58()).toBe(
      SYSVAR_INSTRUCTIONS_PUBKEY.toBase58(),
    );
    // tee_authority + all PDAs (2..9) + sysvar + marker + system = 13.
  });

  it("[settle_anchor_discriminator_present] data starts with sha256('global:tee_forced_settle')[..8]", () => {
    const tee = Keypair.generate();
    const payload = exactFillPayload({
      matchId: filled(16, 0),
      noteAcommitment: filled(32, 1),
      noteBcommitment: filled(32, 2),
      noteCcommitment: filled(32, 3),
      noteDcommitment: filled(32, 4),
      nullifierA: filled(32, 5),
      nullifierB: filled(32, 6),
      orderIdA: filled(16, 7),
      orderIdB: filled(16, 8),
      baseAmount: 0n,
      quoteAmount: 0n,
    });
    const ix = buildSettleIx({
      programId: PROGRAM_ID,
      teeAuthority: tee.publicKey,
      payload,
      quoteMint: new PublicKey(filled(32, 0xC0)),
      baseMint: new PublicKey(filled(32, 0xC1)),
      // v3.1: priceCommitment derives the ValidPriceMarker PDA. The unit
      // tests don't exercise the marker; a fixed sentinel keeps the
      // expected account list deterministic.
      priceCommitment: filled(32, 0xC2),
    });
    const expectedDisc = new Uint8Array(
      createHash("sha256").update("global:tee_forced_settle").digest(),
    ).slice(0, 8);
    expect(new Uint8Array(ix.data).slice(0, 8)).toEqual(expectedDisc);
  });

  it("[settle_payload_serialization_size] data length matches Borsh struct size", () => {
    const tee = Keypair.generate();
    const payload = exactFillPayload({
      matchId: filled(16, 0),
      noteAcommitment: filled(32, 1),
      noteBcommitment: filled(32, 2),
      noteCcommitment: filled(32, 3),
      noteDcommitment: filled(32, 4),
      nullifierA: filled(32, 5),
      nullifierB: filled(32, 6),
      orderIdA: filled(16, 7),
      orderIdB: filled(16, 8),
      baseAmount: 0n,
      quoteAmount: 0n,
    });
    const ix = buildSettleIx({
      programId: PROGRAM_ID,
      teeAuthority: tee.publicKey,
      payload,
      quoteMint: new PublicKey(filled(32, 0xC0)),
      baseMint: new PublicKey(filled(32, 0xC1)),
      // v3.1: priceCommitment derives the ValidPriceMarker PDA. The unit
      // tests don't exercise the marker; a fixed sentinel keeps the
      // expected account list deterministic.
      priceCommitment: filled(32, 0xC2),
    });
    // v3.1 payload (priceProof + priceCommitment factored out into the
    // preceding verify_valid_price ix):
    //   9 * 32  (noteA..noteF + nullA + nullB + noteFee)
    //   5 * 16  (matchId + oidA + oidB + buyerRelockOid + sellerRelockOid)
    //  10 *  8  (base, quote, buyerChange, sellerChange, buyerFee, sellerFee,
    //            buyerRelockExpiry, sellerRelockExpiry, price, batchSlot)
    //  = 288 + 80 + 80 = 448.
    // Plus 8-byte Anchor discriminator = 456 total in ix.data.
    const payloadBytes = serializePayload(payload);
    expect(payloadBytes.length).toBe(32 * 9 + 16 * 5 + 8 * 10);
    expect(payloadBytes.length).toBe(448);
    expect(ix.data.length).toBe(8 + payloadBytes.length);
  });

  it("[exact_fill_defaults] zero change, zero fee, no relock", () => {
    const p = exactFillPayload({
      matchId: filled(16, 0),
      noteAcommitment: filled(32, 0),
      noteBcommitment: filled(32, 0),
      noteCcommitment: filled(32, 0),
      noteDcommitment: filled(32, 0),
      nullifierA: filled(32, 0),
      nullifierB: filled(32, 0),
      orderIdA: filled(16, 1),
      orderIdB: filled(16, 2),
      baseAmount: 100n,
      quoteAmount: 5_000n,
    });
    expect(p.buyerChangeAmt).toBe(0n);
    expect(p.sellerChangeAmt).toBe(0n);
    expect(p.buyerFeeAmt).toBe(0n);
    expect(p.sellerFeeAmt).toBe(0n);
    expect(p.noteEcommitment).toEqual(ZERO_COMMITMENT);
    expect(p.noteFcommitment).toEqual(ZERO_COMMITMENT);
    expect(p.noteFeeCommitment).toEqual(ZERO_COMMITMENT);
    expect(p.buyerRelockOrderId).toEqual(RELOCK_ORDER_ID_NONE);
    expect(p.sellerRelockOrderId).toEqual(RELOCK_ORDER_ID_NONE);
  });
});

describe("Phase 5 — settle-builder: cross-environment parity", () => {
  /**
   * Byte-for-byte parity with
   * `programs/vault/src/instructions/tee_forced_settle.rs::tests::canonical_payload_hash_fixed_vector`.
   * If this diverges, TEE-signed MatchResultPayloads will be rejected by
   * the on-chain verifier in every settlement — drop EVERYTHING and
   * find the divergence.
   */
  it("[hash_cross_env_parity] identical fixed-input hash in TS and Rust", () => {
    const p = exactFillPayload({
      matchId: filled(16, 0x11),
      noteAcommitment: filled(32, 0xA1),
      noteBcommitment: filled(32, 0xB1),
      noteCcommitment: filled(32, 0xC1),
      noteDcommitment: filled(32, 0xD1),
      nullifierA: filled(32, 0xEA),
      nullifierB: filled(32, 0xEB),
      orderIdA: filled(16, 0x01),
      orderIdB: filled(16, 0x02),
      baseAmount: 100n,
      quoteAmount: 5_000n,
      // Match the Rust `canonical_payload_hash_fixed_vector` test (in
      // programs/vault/src/instructions/tee_forced_settle.rs), which uses
      // clearing_price = 0 + batch_slot = 0. Without this override
      // exactFillPayload's v3.1 auto-derive would set clearingPrice =
      // 5000/100 = 50 and the hashes would diverge.
      clearingPrice: 0n,
      batchSlot: 0n,
    });
    const expected = new Uint8Array([
      0x03, 0x88, 0xE8, 0x01, 0x83, 0x01, 0x59, 0x29, 0x83, 0xB8, 0x6C, 0xBC, 0x2F, 0xB7,
      0x96, 0x76, 0x57, 0x6C, 0x04, 0xC1, 0xA4, 0xB8, 0xAD, 0x79, 0x26, 0x15, 0xCA, 0x63,
      0xFC, 0xE7, 0x1F, 0x92,
    ]);
    expect(canonicalPayloadHash(p)).toEqual(expected);
  });
});

describe("Phase 5 — settle-builder: partial-fill + fee variants", () => {
  it("[partial_fill_variant] hash differs from exact-fill variant", () => {
    const exact = exactFillPayload({
      matchId: filled(16, 0x22),
      noteAcommitment: filled(32, 0xA2),
      noteBcommitment: filled(32, 0xB2),
      noteCcommitment: filled(32, 0xC2),
      noteDcommitment: filled(32, 0xD2),
      nullifierA: filled(32, 0xEC),
      nullifierB: filled(32, 0xED),
      orderIdA: filled(16, 3),
      orderIdB: filled(16, 4),
      baseAmount: 10n,
      quoteAmount: 50n,
    });
    const partial: MatchResultPayload = {
      ...exact,
      buyerChangeAmt: 50n,
      noteEcommitment: filled(32, 0xE2),
    };
    const h1 = canonicalPayloadHash(exact);
    const h2 = canonicalPayloadHash(partial);
    expect(h1).not.toEqual(h2);
  });

  it("[fee_flush_variant] note_fee_commitment flips the hash", () => {
    const base = exactFillPayload({
      matchId: filled(16, 0x33),
      noteAcommitment: filled(32, 0xA3),
      noteBcommitment: filled(32, 0xB3),
      noteCcommitment: filled(32, 0xC3),
      noteDcommitment: filled(32, 0xD3),
      nullifierA: filled(32, 0xEE),
      nullifierB: filled(32, 0xEF),
      orderIdA: filled(16, 5),
      orderIdB: filled(16, 6),
      baseAmount: 100n,
      quoteAmount: 100n,
    });
    const withFee: MatchResultPayload = {
      ...base,
      buyerFeeAmt: 3n,
      sellerFeeAmt: 1n,
      noteFeeCommitment: filled(32, 0x88),
    };
    expect(canonicalPayloadHash(withFee)).not.toEqual(canonicalPayloadHash(base));
  });
});

function u64LE(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}
