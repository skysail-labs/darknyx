/**
 * The public note-consumption handle (TS mirror of
 * `crates/darkpool-crypto/src/note_use.rs`).
 *
 * `note_commitment` used to be both the Merkle-leaf identity of a note AND the
 * public handle every consumption path keyed on. Because the same 32 bytes
 * appeared at deposit, lock, settle and withdraw, an observer reconstructed a
 * note's whole lineage by string-matching. The commitment now appears exactly
 * once — when the note is created as a leaf — and everything downstream
 * references this tag.
 *
 * ## Why the commitment is an input
 *
 * The commitment is what binds a note's fields:
 * `C = Poseidon6(2, mint_lo, mint_hi, amount, owner_commitment, inner_hash)`.
 * A tag over `inner_hash` alone would leave the amount unbound at settle, where
 * the input commitment is only a private witness — a prover could pair a real
 * lock with an inflated amount. Feeding `C` in restores the binding.
 *
 * ## Why it is unlinkable
 *
 * An observer holds the commitment (it is a public leaf) but not `inner_hash`,
 * which is private to the owner and the enclave.
 *
 * Byte-identical to the Rust side; pinned by `note-use-tag-parity.test.ts`.
 */

import { poseidonHashBytesBE } from "./note.js";
import {
  noteUseTagFromBytes,
  type NoteCommitment,
  type NoteUseTag,
} from "./note-identity.js";

/**
 * Domain tag. Note 26 is NOT free — it is `DOMAIN_MERGE_INNER`. In use: 1, 2, 3,
 * 5, 10..14, 22..28. Retired: 20, 21.
 */
export const DOMAIN_NOTE_USE = 29n;

function be32ToBigInt(value: Uint8Array, label: string): bigint {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

/** `Poseidon3(29, note_commitment, inner_hash)`. */
export async function deriveNoteUseTag(
  noteCommitment: NoteCommitment,
  innerHash: Uint8Array,
): Promise<NoteUseTag> {
  return noteUseTagFromBytes(
    await poseidonHashBytesBE([
      DOMAIN_NOTE_USE,
      be32ToBigInt(noteCommitment, "noteCommitment"),
      be32ToBigInt(innerHash, "innerHash"),
    ]),
  );
}
