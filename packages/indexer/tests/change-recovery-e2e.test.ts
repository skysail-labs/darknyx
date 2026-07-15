/**
 * Change-amount recovery — CLIENT-SIDE end-to-end (Proposal B).
 *
 * Stitches the whole user-side journey together with the REAL SDK + indexer
 * functions, no live CVM, proving the cross-package byte agreement
 * (settle-builder ENCODE → indexer DECODE → SDK RECOVER):
 *
 *   seed           = securely stored CSPRNG output                    (backed up encrypted)
 *   B.1 viewing kp = deriveViewingEncKeypair(seed)                   (the order's viewing_pubkey)
 *   B.3 (TEE sim)  = encryptChangeAmount(eph, viewing.pub, amount)   (the on-chain ciphertext)
 *   B.5a payload   = MatchResultPayload{ note_e, fill_recovery } → serializePayload → settle ix data
 *   B.4 indexer    = decodeSettleIxData → IndexerFill{ ephemeralPubkey, changeEnc }
 *   B.4 client     = recoverChangeFromChain → spendable note (decrypt + Vuln-4 self-verify)
 *
 * The output inner is derived from the consumed input opening exactly as in
 * VALID_MATCH_BATCH v3; no settlement-id or anchor probing is involved.
 */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import {
  deriveViewingEncKeypair,
  bn254ToBE32,
} from "../../sdk/src/keys/key-generators.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
} from "../../sdk/src/utxo/match-output.js";
import { noteCommitmentV2 } from "../../sdk/src/utxo/note.js";
import type { StoredNote } from "../../sdk/src/utxo/note-store.js";
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

// Deterministic stand-in for a securely stored 64-byte CSPRNG seed.
const SEED = new Uint8Array(64).fill(0x42);
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
function packRecovery(
  eph: Uint8Array,
  buyerEnc: Uint8Array,
  sellerEnc: Uint8Array,
): Uint8Array {
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
function teeEncrypt(
  recipientPub: Uint8Array,
  amount: bigint,
): { ephPub: Uint8Array; blob: Uint8Array } {
  const ephSecret = crypto.randomBytes(32);
  const ephPub = nacl.scalarMult.base(ephSecret);
  const blob = encryptChangeAmount(
    ephSecret,
    recipientPub,
    amount,
    crypto.randomBytes(12),
  );
  return { ephPub, blob };
}

const recoverParams = (candidateInputs: StoredNote[]) => ({
  masterSeed: SEED,
  candidateInputs,
  baseMint: BASE_MINT,
  quoteMint: QUOTE_MINT,
});

async function inputNote(side: "buyer" | "seller", innerHash: bigint) {
  const tokenMint = side === "buyer" ? QUOTE_MINT : BASE_MINT;
  const amount = 2_000n;
  const commitment = await noteCommitmentV2({
    tokenMint,
    amount,
    ownerCommitment: OWNER,
    innerHash,
  });
  return {
    commitment: hex(commitment),
    tokenMint,
    amount,
    ownerCommitment: OWNER,
    innerHash,
    leafIndex: 0n,
  } satisfies StoredNote;
}

/** Build the settle ix for a one-sided buyer change of `amount` under `inner`. */
async function buyerChangeIx(
  input: StoredNote,
  amount: bigint,
  matchId: bigint,
): Promise<Uint8Array> {
  const inner = be32ToBig(
    await deriveMatchOutputInner(
      bn254ToBE32(input.innerHash),
      MATCH_ROLE_CHANGE_BUYER,
    ),
  );
  const commitment = await noteCommitmentV2({
    tokenMint: QUOTE_MINT,
    amount,
    ownerCommitment: OWNER,
    innerHash: inner,
  });
  const { ephPub, blob } = teeEncrypt(VIEWING.publicKey, amount);
  const payload = exactFillPayload({
    matchId: matchIdBytes(matchId),
    noteAcommitment: Uint8Array.from(Buffer.from(input.commitment, "hex")),
    noteBcommitment: fill(32, 0xb1),
    noteCcommitment: fill(32, 0xc1),
    noteDcommitment: fill(32, 0xd1),
    orderIdA: ORDER_ID,
    orderIdB: fill(16, 0xcd),
  });
  payload.noteEcommitment = commitment; // buyer change note
  payload.fillRecovery = packRecovery(ephPub, blob, new Uint8Array(36)); // seller exact
  return ixData(payload);
}

describe("change-amount recovery — client-side e2e", () => {
  it("seed → viewing key → the recipient the TEE encrypts to (B.1)", () => {
    // The order's viewing_pubkey (what intake carries + the TEE encrypts to) is
    // exactly the seed-derived key the recovering client regenerates.
    expect(hex(VIEWING.publicKey)).toBe(
      hex(deriveViewingEncKeypair(SEED).publicKey),
    );
    expect(VIEWING.publicKey.length).toBe(32);
  });

  it("recovers an input-derived change note end-to-end", async () => {
    const matchId = 42n;
    const input = await inputNote("buyer", 0x1234n);
    const data = await buyerChangeIx(input, 250n, matchId);

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
    const note = await recoverChangeFromChain(buyer, recoverParams([input]));
    expect(note).not.toBeNull();
    expect(note!.amount).toBe(250n);
    expect(note!.consumedCommitment).toBe(input.commitment);
    expect(note!.commitment).toBe(buyer.changeNoteCommitment);
  });

  it("recovers a second continuation from the first recovered opening", async () => {
    const matchId = 9n;
    const input = await inputNote("buyer", 0x2222n);
    const firstData = await buyerChangeIx(input, 777n, matchId);
    const firstFill = decodeSettleIxData(firstData)!.find(
      (f) => f.side === "buyer",
    )!;
    const first = await recoverChangeFromChain(
      firstFill,
      recoverParams([input]),
    );
    expect(first).not.toBeNull();

    const data = await buyerChangeIx(first!, 555n, matchId + 1n);

    const buyer = decodeSettleIxData(data)!.find((f) => f.side === "buyer")!;
    const note = await recoverChangeFromChain(
      buyer,
      recoverParams([input, first!]),
    );
    expect(note).not.toBeNull();
    expect(note!.amount).toBe(555n);
    expect(note!.consumedCommitment).toBe(first!.commitment);
  });

  it("a different account seed cannot recover the note (isolation)", async () => {
    const matchId = 7n;
    const input = await inputNote("buyer", 0x3333n);
    const data = await buyerChangeIx(input, 250n, matchId);
    const buyer = decodeSettleIxData(data)!.find((f) => f.side === "buyer")!;

    const stranger = {
      ...recoverParams([input]),
      masterSeed: new Uint8Array(64).fill(0x99),
    };
    expect(await recoverChangeFromChain(buyer, stranger)).toBeNull();
  });

  it("a seller-side continuation recovers symmetrically (base mint)", async () => {
    // Seller change (base-denominated): note_f + the seller-side ciphertext slot.
    const matchId = 11n;
    const amount = 333n;
    const input = await inputNote("seller", 0x4444n);
    const inner = be32ToBig(
      await deriveMatchOutputInner(
        bn254ToBE32(input.innerHash),
        MATCH_ROLE_CHANGE_SELLER,
      ),
    );
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
      noteBcommitment: Uint8Array.from(Buffer.from(input.commitment, "hex")),
      noteCcommitment: fill(32, 0xc1),
      noteDcommitment: fill(32, 0xd1),
      orderIdA: fill(16, 0xcd),
      orderIdB: ORDER_ID, // the seller order
    });
    payload.noteFcommitment = commitment;
    payload.fillRecovery = packRecovery(ephPub, new Uint8Array(36), blob); // buyer exact

    const seller = decodeSettleIxData(ixData(payload))!.find(
      (f) => f.side === "seller",
    )!;
    expect(seller.changeEnc).toBe(hex(blob));
    const note = await recoverChangeFromChain(seller, recoverParams([input]));
    expect(note!.amount).toBe(333n);
    expect(hex(note!.tokenMint)).toBe(hex(BASE_MINT));
  });
});
