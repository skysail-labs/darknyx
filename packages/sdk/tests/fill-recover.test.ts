/**
 * Change-amount recovery (Proposal B), B.4 — client decrypt + self-verify from
 * the on-chain ciphertext alone (no FillMemo).
 *
 * Synthesizes an `IndexerFill` exactly as the indexer would surface one (an
 * encrypted change_amount + the on-chain change-note commitment), then asserts
 * `recoverChangeFromChain` decrypts it and self-verifies the spendable opening —
 * for BOTH a final change note (`derive_inner`) and a continuation note (anchor
 * `inner_hash`) — and rejects a wrong key / tampered ciphertext / wrong amount.
 */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import {
  deriveViewingEncKeypair,
  deriveInnerHash,
  bn254ToBE32,
} from "../src/keys/key-generators.js";
import { encryptChangeAmount } from "../src/keys/fill-encryption.js";
import {
  deriveChangeInner,
  CHANGE_ROLE_BUYER,
  CHANGE_ROLE_SELLER,
} from "../src/utxo/change-note.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { recoverChangeFromChain } from "../src/fills/recover.js";
import type { IndexerFill } from "../src/fills/history.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const be32ToBig = (b: Uint8Array) => {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
};

const SEED = new Uint8Array(64).fill(0x07);
const OWNER = 0x1234_5678n;
const QUOTE_MINT = new Uint8Array(32).fill(0x9e);
const BASE_MINT = new Uint8Array(32).fill(0xb1);
const ORDER_ID = new Uint8Array(16).fill(0xab);

function matchIdHex(mid: bigint): string {
  const b = new Uint8Array(16);
  new DataView(b.buffer).setBigUint64(8, mid, true); // low 8 bytes at [8,16), LE
  return hex(b);
}

/** Build the IndexerFill the indexer would serve for a change note with the
 *  given (innerHash, amount, side), encrypting the amount to SEED's viewing key. */
async function makeFill(opts: {
  side: "buyer" | "seller";
  innerHash: bigint;
  amount: bigint;
  matchId: bigint;
  recipientPub?: Uint8Array; // override (defaults to SEED's viewing pubkey)
}): Promise<IndexerFill> {
  const tokenMint = opts.side === "buyer" ? QUOTE_MINT : BASE_MINT;
  const commitment = await noteCommitmentV2({
    tokenMint,
    amount: opts.amount,
    ownerCommitment: OWNER,
    innerHash: opts.innerHash,
  });
  const recipient =
    opts.recipientPub ?? deriveViewingEncKeypair(SEED).publicKey;
  const ephSecret = crypto.randomBytes(32);
  const ephPub = nacl.scalarMult.base(ephSecret);
  const nonce = crypto.randomBytes(12);
  const changeEnc = encryptChangeAmount(
    ephSecret,
    recipient,
    opts.amount,
    nonce,
  );
  return {
    orderId: hex(ORDER_ID),
    side: opts.side,
    matchId: matchIdHex(opts.matchId),
    signature: "00",
    isPartialFill: true,
    changeNoteCommitment: hex(commitment),
    batchSlot: "1",
    ephemeralPubkey: hex(ephPub),
    changeEnc: hex(changeEnc),
  };
}

const params = {
  masterSeed: SEED,
  ownerCommitment: OWNER,
  baseMint: BASE_MINT,
  quoteMint: QUOTE_MINT,
};

describe("recoverChangeFromChain (B.4)", () => {
  it("recovers a FINAL change note (derive_inner)", async () => {
    const innerHash = be32ToBig(deriveChangeInner(42n, CHANGE_ROLE_BUYER));
    const fill = await makeFill({
      side: "buyer",
      innerHash,
      amount: 250n,
      matchId: 42n,
    });

    const note = await recoverChangeFromChain(fill, params);
    expect(note).not.toBeNull();
    expect(note!.amount).toBe(250n);
    expect(note!.innerHash).toBe(innerHash);
    expect(note!.anchorIndex).toBeUndefined();
    expect(note!.commitment).toBe(fill.changeNoteCommitment);
    expect(hex(note!.tokenMint)).toBe(hex(QUOTE_MINT));
  });

  it("compares commitments as bytes and returns canonical hex", async () => {
    const innerHash = be32ToBig(deriveChangeInner(42n, CHANGE_ROLE_BUYER));
    const fill = await makeFill({
      side: "buyer",
      innerHash,
      amount: 250n,
      matchId: 42n,
    });
    const canonical = fill.changeNoteCommitment!;
    fill.changeNoteCommitment = canonical.toUpperCase();

    const note = await recoverChangeFromChain(fill, params);
    expect(note).not.toBeNull();
    expect(note!.commitment).toBe(canonical);
  });

  it("recovers a CONTINUATION note (anchor inner_hash) + its anchor index", async () => {
    const innerHash = deriveInnerHash(SEED, ORDER_ID, 3);
    const fill = await makeFill({
      side: "seller",
      innerHash,
      amount: 777n,
      matchId: 9n,
    });

    const note = await recoverChangeFromChain(fill, params);
    expect(note).not.toBeNull();
    expect(note!.amount).toBe(777n);
    expect(note!.innerHash).toBe(innerHash);
    expect(note!.anchorIndex).toBe(3);
    expect(hex(note!.tokenMint)).toBe(hex(BASE_MINT));
  });

  it("returns null for a wrong viewing key (not ours)", async () => {
    const innerHash = be32ToBig(deriveChangeInner(42n, CHANGE_ROLE_BUYER));
    // Encrypt to a DIFFERENT recipient than SEED's viewing key.
    const stranger = deriveViewingEncKeypair(
      new Uint8Array(64).fill(0x99),
    ).publicKey;
    const fill = await makeFill({
      side: "buyer",
      innerHash,
      amount: 250n,
      matchId: 42n,
      recipientPub: stranger,
    });
    expect(await recoverChangeFromChain(fill, params)).toBeNull();
  });

  it("returns null for a tampered ciphertext", async () => {
    const innerHash = be32ToBig(deriveChangeInner(42n, CHANGE_ROLE_BUYER));
    const fill = await makeFill({
      side: "buyer",
      innerHash,
      amount: 250n,
      matchId: 42n,
    });
    const bytes = Uint8Array.from(Buffer.from(fill.changeEnc!, "hex"));
    bytes[bytes.length - 1] ^= 0x01; // flip a tag byte
    fill.changeEnc = hex(bytes);
    expect(await recoverChangeFromChain(fill, params)).toBeNull();
  });

  it("returns null when the decrypted amount doesn't match the on-chain commitment", async () => {
    // Decryptable, but the commitment was built for a DIFFERENT amount → the
    // self-verify (Vuln-4) recomputes no candidate and rejects.
    const innerHash = be32ToBig(deriveChangeInner(42n, CHANGE_ROLE_BUYER));
    const fill = await makeFill({
      side: "buyer",
      innerHash,
      amount: 250n,
      matchId: 42n,
    });
    // Re-point the commitment at amount 999 (same inner) — decrypt yields 250.
    const wrongCommitment = await noteCommitmentV2({
      tokenMint: QUOTE_MINT,
      amount: 999n,
      ownerCommitment: OWNER,
      innerHash,
    });
    fill.changeNoteCommitment = hex(wrongCommitment);
    expect(await recoverChangeFromChain(fill, params)).toBeNull();
  });

  it("returns null for an exact fill (no ciphertext)", async () => {
    const exact: IndexerFill = {
      orderId: hex(ORDER_ID),
      side: "buyer",
      matchId: matchIdHex(1n),
      signature: "00",
      isPartialFill: false,
      changeNoteCommitment: null,
      batchSlot: "1",
      ephemeralPubkey: null,
      changeEnc: null,
    };
    expect(await recoverChangeFromChain(exact, params)).toBeNull();
  });
});

describe("deriveChangeInner KAT", () => {
  it("matches the cross-language spec value for (42, CHANGE_ROLE_BUYER)", () => {
    // Same vector as tests/change-note-inner-parity.test.ts (the matcher port).
    expect(hex(deriveChangeInner(42n, CHANGE_ROLE_BUYER))).toBe(
      "0003e743eb441d6b6f5363d7ad169cf3b8dd6621303ed9d47cb14ddf05de286b",
    );
  });

  it("is Fr-safe + role/match separated", () => {
    const a = deriveChangeInner(42n, CHANGE_ROLE_BUYER);
    expect(a[0]).toBe(0);
    expect(a[1] & 0xf0).toBe(0);
    expect(hex(a)).not.toBe(hex(deriveChangeInner(42n, CHANGE_ROLE_SELLER)));
    expect(hex(a)).not.toBe(hex(deriveChangeInner(43n, CHANGE_ROLE_BUYER)));
  });
});
