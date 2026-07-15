/**
 * Change/trade note `inner_hash` derivation — SDK port of the matcher's
 * `darkpool_matcher::change_note::derive_inner` (and the on-chain
 * `tee_forced_settle`/assembler use of it).
 *
 * This SHA-based helper pins the legacy pure-matcher's provisional commitment
 * construction. The live VALID_MATCH_BATCH v3 settlement instead uses
 * `utxo/match-output.ts::deriveMatchOutputInner`, derived from the consumed
 * input inner, for every final and continuing output.
 *
 *   inner_hash = SHA-256("nyx-change-inner" ‖ match_id_u64_le ‖ role) , Fr-safe
 *                masked (byte 0 = 0, byte 1 high-nibble cleared).
 *
 * Byte-identical to the matcher; pinned by the cross-language KAT in
 * `tests/change-note-inner-parity.test.ts` (and the SDK test alongside it).
 */

import { createHash } from "node:crypto";

/** Role tags — must match `darkpool_matcher::change_note` + on-chain constants. */
export const CHANGE_ROLE_BUYER = 0xb1; // note_e (buyer's quote-side change)
export const CHANGE_ROLE_SELLER = 0x5e; // note_f (seller's base-side change)

/**
 * Derive the `inner_hash` (32-byte BE, Fr-safe) for a final change note of the
 * given `matchId` + `role`.
 */
export function deriveChangeInner(matchId: bigint, role: number): Uint8Array {
  if (matchId < 0n || matchId > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`matchId must be a u64; got ${matchId}`);
  }
  if (!Number.isInteger(role) || role < 0 || role > 0xff) {
    throw new Error(`role must be a u8; got ${role}`);
  }
  const h = createHash("sha256");
  h.update(Buffer.from("nyx-change-inner"));
  const mid = new Uint8Array(8);
  new DataView(mid.buffer).setBigUint64(0, matchId, true); // little-endian
  h.update(mid);
  h.update(new Uint8Array([role]));
  const d = new Uint8Array(h.digest());
  d[0] = 0; // Fr-safe: clear the top byte …
  d[1] &= 0x0f; // … and the high nibble of byte 1.
  return d;
}
