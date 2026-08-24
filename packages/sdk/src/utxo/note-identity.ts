/**
 * Semantic 32-byte note identities.
 *
 * Commitments and use tags have the same wire representation, but belong to
 * different PDA namespaces. The brands disappear at runtime and do not alter
 * Borsh/JSON bytes; checked constructors are the only raw-byte entry points.
 */

import { BN254_R } from "../keys/key-generators.js";

declare const noteCommitmentBrand: unique symbol;
declare const noteUseTagBrand: unique symbol;

export type NoteCommitment = Uint8Array & {
  readonly [noteCommitmentBrand]: "NoteCommitment";
};

export type NoteUseTag = Uint8Array & {
  readonly [noteUseTagBrand]: "NoteUseTag";
};

function checkedFieldBytes(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  let scalar = 0n;
  for (const byte of value) scalar = (scalar << 8n) | BigInt(byte);
  if (scalar >= BN254_R) {
    throw new Error(`${label} must be a canonical BN254 field element`);
  }
  return new Uint8Array(value);
}

/** Check raw Merkle-leaf/wire bytes before entering commitment-typed code. */
export function noteCommitmentFromBytes(value: Uint8Array): NoteCommitment {
  return checkedFieldBytes(value, "note commitment") as NoteCommitment;
}

/** Check raw instruction/API bytes before entering use-tag-typed code. */
export function noteUseTagFromBytes(value: Uint8Array): NoteUseTag {
  return checkedFieldBytes(value, "note-use tag") as NoteUseTag;
}

/** Explicitly cross back to the raw wire representation without copying. */
export function noteCommitmentToBytes(value: NoteCommitment): Uint8Array {
  return value;
}

/** Explicitly cross back to the raw wire representation without copying. */
export function noteUseTagToBytes(value: NoteUseTag): Uint8Array {
  return value;
}
