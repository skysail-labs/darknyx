/**
 * Recover a change note's spendable opening from the PERMANENT ON-CHAIN
 * ciphertext (change-amount recovery, Proposal B) — no FillMemo required.
 *
 * The amount-privacy revamp left a fill's `change_amount` only in the live
 * live fills-channel memo + a TTL log that a CVM redeploy wipes. The settle ix now also
 * carries the amount ENCRYPTED to the order owner's X25519 viewing key
 * (`fill_recovery`), which the indexer surfaces opaquely as
 * `IndexerFill.{ephemeralPubkey, changeEnc}`. This module turns that back into a
 * spendable note on any device that has the seed.
 *
 * Two checks, in order:
 *   1. Decrypt `changeEnc` with `deriveViewingEncKeypair(seed)`. A wrong key or a
 *      tampered ciphertext fails the AEAD tag → `null` (not ours / corrupt).
 *   2. Self-verify (Vuln-4): the decrypted amount must recompute the on-chain
 *      `changeNoteCommitment` under the correct `inner_hash`. We don't know a
 *      priori whether the note was a FINAL change note (`derive_inner(match_id,
 *      role)`) or a CONTINUATION (one of the order's anchor `inner_hash`es), so
 *      we try the final case then probe the anchor pool; the match also recovers
 *      the spendable `inner_hash`. A decrypted amount that recomputes NO known
 *      commitment is rejected (a misbehaving TEE that encrypted a wrong amount).
 */

import {
  deriveViewingEncKeypair,
  deriveInnerHash,
} from "../keys/key-generators.js";
import { decryptChangeAmount } from "../keys/fill-encryption.js";
import {
  deriveChangeInner,
  CHANGE_ROLE_BUYER,
  CHANGE_ROLE_SELLER,
} from "../utxo/change-note.js";
import { noteCommitmentV2 } from "../utxo/note.js";
import type { StoredNote } from "../utxo/note-store.js";
import type { IndexerFill } from "./history.js";

export interface RecoverParams {
  masterSeed: Uint8Array;
  /** The order's note owner commitment (`Poseidon2(spending_key, r_owner)`). */
  ownerCommitment: bigint;
  /** 32-byte base + quote mints. Buyer change is quote-denominated; seller base. */
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  /** Anchor-pool indices to probe for a CONTINUATION note (the initial 10 plus
   *  any top-ups). Default 64. */
  anchorProbeLimit?: number;
}

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function fromHexExact(value: string, bytes: number): Uint8Array | null {
  if (value.length !== bytes * 2 || !/^[0-9a-fA-F]+$/.test(value)) {
    return null;
  }
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function be32ToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

/** Extract the u64 `match_id` from the 16-byte payload field (low 8 bytes, LE). */
function matchIdU64(matchIdHex: string): bigint {
  const b = fromHex(matchIdHex);
  if (b.length !== 16)
    throw new Error(`matchId must be 16 bytes; got ${b.length}`);
  return new DataView(b.buffer, b.byteOffset, 16).getBigUint64(8, true);
}

/**
 * Attempt to recover the spendable change note for one located fill. Returns the
 * `StoredNote` on success, or `null` if the fill carries no ciphertext, isn't
 * ours, or doesn't self-verify.
 */
export async function recoverChangeFromChain(
  fill: IndexerFill,
  params: RecoverParams,
): Promise<StoredNote | null> {
  if (!fill.changeNoteCommitment || !fill.ephemeralPubkey || !fill.changeEnc) {
    return null; // exact fill / no recovery ciphertext.
  }

  // (1) Decrypt — AEAD tag failure ⇒ not our key, or tampered.
  const { secretKey } = deriveViewingEncKeypair(params.masterSeed);
  const amount = decryptChangeAmount(
    secretKey,
    fromHex(fill.ephemeralPubkey),
    fromHex(fill.changeEnc),
  );
  if (amount === null) return null;

  const tokenMint = fill.side === "buyer" ? params.quoteMint : params.baseMint;
  const role = fill.side === "buyer" ? CHANGE_ROLE_BUYER : CHANGE_ROLE_SELLER;
  const targetBytes = fromHexExact(fill.changeNoteCommitment, 32);
  if (!targetBytes) return null;
  const target = toHex(targetBytes);

  const recomputes = async (innerHash: bigint): Promise<boolean> => {
    const c = await noteCommitmentV2({
      tokenMint,
      amount,
      ownerCommitment: params.ownerCommitment,
      innerHash,
    });
    return Buffer.compare(Buffer.from(c), Buffer.from(targetBytes)) === 0;
  };

  const note = (innerHash: bigint, anchorIndex?: number): StoredNote => ({
    commitment: target,
    tokenMint,
    amount,
    ownerCommitment: params.ownerCommitment,
    innerHash,
    orderId: fill.orderId,
    anchorIndex,
  });

  // (2a) FINAL change note: inner_hash = derive_inner(match_id, role).
  const finalInner = be32ToBig(
    deriveChangeInner(matchIdU64(fill.matchId), role),
  );
  if (await recomputes(finalInner)) return note(finalInner);

  // (2b) CONTINUATION note: inner_hash is one of the order's anchor inner_hashes.
  const probe = params.anchorProbeLimit ?? 64;
  const orderId = fromHex(fill.orderId);
  for (let i = 0; i < probe; i++) {
    const inner = deriveInnerHash(params.masterSeed, orderId, i);
    if (await recomputes(inner)) return note(inner, i);
  }

  // Decrypted but self-verify failed under every candidate — reject.
  return null;
}
