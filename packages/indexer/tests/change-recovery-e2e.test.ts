/**
 * Change-amount recovery — CLIENT-SIDE end-to-end (Proposals A + B).
 *
 * Stitches the whole user-side journey together with the REAL SDK + indexer
 * functions, no live CVM, proving the cross-package byte agreement
 * (settle-builder ENCODE → indexer DECODE → SDK RECOVER):
 *
 *   A   seed       = seedFromWalletSignature(walletSig)              (deterministic, recoverable)
 *   B.1 viewing kp = deriveViewingEncKeypair(seed)                   (the order's viewing_pubkey)
 *   B.3 (TEE sim)  = encryptChangeAmount(eph, viewing.pub, amount)   (the on-chain ciphertext)
 *   B.5a payload   = MatchResultPayload{ note_e, fill_recovery } → serializePayload → settle ix data
 *   B.4 indexer    = decodeSettleIxData → IndexerFill{ ephemeralPubkey, changeEnc }
 *   B.4 client     = recoverChangeFromChain → spendable note (decrypt + Vuln-4 self-verify)
 *
 * Covers both a FINAL change note (derive_inner) and a CONTINUATION note (anchor
 * inner_hash) — the two inner_hash shapes the recoverer must handle.
 */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import {
  seedFromWalletSignature,
  deriveViewingEncKeypair,
  deriveInnerHash,
} from "../../sdk/src/keys/key-generators.js";
import {
  deriveChangeInner,
  CHANGE_ROLE_BUYER,
  CHANGE_ROLE_SELLER,
} from "../../sdk/src/utxo/change-note.js";
import { noteCommitmentV2 } from "../../sdk/src/utxo/note.js";
import { encryptChangeAmount } from "../../sdk/src/keys/fill-encryption.js";
import {
  serializePayload,
  exactFillPayload,
  type MatchResultPayload,
} from "../../sdk/src/settlement/settle-builder.js";
import { recoverChangeFromChain } from "../../sdk/src/fills/recover.js";
import { decodeSettleIxData, SETTLE_DISCRIMINATOR } from "../src/decode.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const be32ToBig = (b: Uint8Array) => {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
};

// Deterministic seed from a (fake) wallet signature — Proposal A.
const SEED = seedFromWalletSignature(new Uint8Array(64).fill(0x42));
const VIEWING = deriveViewingEncKeypair(SEED);
const OWNER = 0x1234_5678n;
const QUOTE_MINT = fill(32, 0x9e);
const BASE_MINT = fill(32, 0xb1);
const ORDER_ID = fill(16, 0xab);

/** 16-byte match_id field: the u64 lives in the low 8 bytes, LE (as assemble.rs packs it). */
function matchIdBytes(mid: bigint): Uint8Array {
  const b = new Uint8Array(16);
  new DataView(b.buffer).setBigUint64(8, mid, true);
  return b;
}

/** Pack the TEE's FillCiphertext into the 128-byte fill_recovery field:
 *  eph(32) ‖ buyer_enc(36) ‖ seller_enc(36) ‖ pad(24). Mirrors
 *  `FillCiphertext::to_payload_bytes` in nyx-tee. */
function packRecovery(eph: Uint8Array, buyerEnc: Uint8Array, sellerEnc: Uint8Array): Uint8Array {
  const out = new Uint8Array(128);
  out.set(eph, 0);
  out.set(buyerEnc, 32);
  out.set(sellerEnc, 68);
  return out;
}

/** Wrap a payload as a `tee_forced_settle_batched` ix data blob:
 *  disc(8) ‖ tree_id(1) ‖ payload ‖ match_index(1) ‖ siblings(128). */
function ixData(p: MatchResultPayload): Uint8Array {
  const body = serializePayload(p);
  const out = new Uint8Array(8 + 1 + body.length + 1 + 128);
  out.set(SETTLE_DISCRIMINATOR, 0);
  out[8] = 0; // tree_id
  out.set(body, 9);
  return out; // match_index + siblings left zero (the decoder ignores them)
}

/** Simulate the TEE encrypting `amount` to a recipient, returning the 36-byte blob
 *  + the shared ephemeral pubkey (one ephemeral per fill). */
function teeEncrypt(recipientPub: Uint8Array, amount: bigint): { ephPub: Uint8Array; blob: Uint8Array } {
  const ephSecret = crypto.randomBytes(32);
  const ephPub = nacl.scalarMult.base(ephSecret);
  const blob = encryptChangeAmount(ephSecret, recipientPub, amount, crypto.randomBytes(12));
  return { ephPub, blob };
}

const recoverParams = {
  masterSeed: SEED,
  ownerCommitment: OWNER,
  baseMint: BASE_MINT,
  quoteMint: QUOTE_MINT,
};

/** Build the settle ix for a one-sided buyer change of `amount` under `inner`. */
async function buyerChangeIx(inner: bigint, amount: bigint, matchId: bigint): Promise<Uint8Array> {
  const commitment = await noteCommitmentV2({
    tokenMint: QUOTE_MINT,
    amount,
    ownerCommitment: OWNER,
    innerHash: inner,
  });
  const { ephPub, blob } = teeEncrypt(VIEWING.publicKey, amount);
  const payload = exactFillPayload({
    matchId: matchIdBytes(matchId),
    noteAcommitment: fill(32, 0xa1),
    noteBcommitment: fill(32, 0xb1),
    noteCcommitment: fill(32, 0xc1),
    noteDcommitment: fill(32, 0xd1),
    nullifierA: fill(32, 0xea),
    nullifierB: fill(32, 0xeb),
    orderIdA: ORDER_ID,
    orderIdB: fill(16, 0xcd),
  });
  payload.noteEcommitment = commitment; // buyer change note
  payload.fillRecovery = packRecovery(ephPub, blob, new Uint8Array(36)); // seller exact
  return ixData(payload);
}

describe("change-amount recovery — client-side e2e", () => {
  it("seed → viewing key → the recipient the TEE encrypts to (A → B.1)", () => {
    // The order's viewing_pubkey (what intake carries + the TEE encrypts to) is
    // exactly the seed-derived key the recovering client regenerates.
    expect(hex(VIEWING.publicKey)).toBe(hex(deriveViewingEncKeypair(SEED).publicKey));
    expect(VIEWING.publicKey.length).toBe(32);
  });

  it("recovers a FINAL change note end-to-end (encode → decode → recover)", async () => {
    const matchId = 42n;
    const inner = be32ToBig(deriveChangeInner(matchId, CHANGE_ROLE_BUYER));
    const data = await buyerChangeIx(inner, 250n, matchId);

    // Indexer decodes the ix → surfaces the ciphertext opaquely.
    const fills = decodeSettleIxData(data)!;
    expect(fills).toHaveLength(2);
    const buyer = fills.find((f) => f.side === "buyer")!;
    expect(buyer.ephemeralPubkey).not.toBeNull();
    expect(buyer.changeEnc).not.toBeNull();
    // Seller had no change → its blob is zeroed → null.
    const seller = fills.find((f) => f.side === "seller")!;
    expect(seller.changeEnc).toBeNull();

    // Client recovers the spendable note from the chain alone.
    const note = await recoverChangeFromChain(buyer, recoverParams);
    expect(note).not.toBeNull();
    expect(note!.amount).toBe(250n);
    expect(note!.innerHash).toBe(inner);
    expect(note!.anchorIndex).toBeUndefined();
    expect(note!.commitment).toBe(buyer.changeNoteCommitment);
  });

  it("recovers a CONTINUATION note + its anchor index end-to-end", async () => {
    const matchId = 9n;
    const k = 4;
    const inner = deriveInnerHash(SEED, ORDER_ID, k); // anchor inner_hash
    const data = await buyerChangeIx(inner, 777n, matchId);

    const buyer = decodeSettleIxData(data)!.find((f) => f.side === "buyer")!;
    const note = await recoverChangeFromChain(buyer, recoverParams);
    expect(note).not.toBeNull();
    expect(note!.amount).toBe(777n);
    expect(note!.innerHash).toBe(inner);
    expect(note!.anchorIndex).toBe(k);
  });

  it("a different wallet's seed cannot recover the note (isolation)", async () => {
    const matchId = 7n;
    const inner = be32ToBig(deriveChangeInner(matchId, CHANGE_ROLE_BUYER));
    const data = await buyerChangeIx(inner, 250n, matchId);
    const buyer = decodeSettleIxData(data)!.find((f) => f.side === "buyer")!;

    const stranger = {
      ...recoverParams,
      masterSeed: seedFromWalletSignature(new Uint8Array(64).fill(0x99)),
    };
    expect(await recoverChangeFromChain(buyer, stranger)).toBeNull();
  });

  it("a seller-side continuation recovers symmetrically (base mint)", async () => {
    // Seller change (base-denominated): note_f + the seller-side ciphertext slot.
    const matchId = 11n;
    const amount = 333n;
    const inner = be32ToBig(deriveChangeInner(matchId, CHANGE_ROLE_SELLER));
    const commitment = await noteCommitmentV2({
      tokenMint: BASE_MINT,
      amount,
      ownerCommitment: OWNER,
      innerHash: inner,
    });
    const { ephPub, blob } = teeEncrypt(VIEWING.publicKey, amount);
    const payload = exactFillPayload({
      matchId: matchIdBytes(matchId),
      noteAcommitment: fill(32, 0xa1),
      noteBcommitment: fill(32, 0xb1),
      noteCcommitment: fill(32, 0xc1),
      noteDcommitment: fill(32, 0xd1),
      nullifierA: fill(32, 0xea),
      nullifierB: fill(32, 0xeb),
      orderIdA: fill(16, 0xcd),
      orderIdB: ORDER_ID, // the seller order
    });
    payload.noteFcommitment = commitment;
    payload.fillRecovery = packRecovery(ephPub, new Uint8Array(36), blob); // buyer exact

    const seller = decodeSettleIxData(ixData(payload))!.find((f) => f.side === "seller")!;
    expect(seller.changeEnc).toBe(hex(blob));
    const note = await recoverChangeFromChain(seller, recoverParams);
    expect(note!.amount).toBe(333n);
    expect(hex(note!.tokenMint)).toBe(hex(BASE_MINT));
  });
});
