/**
 * Race-proof leaf-index recovery for tree-appending instructions (deposit,
 * merge).
 *
 * The on-chain program appends a note at the CURRENT `leaf_count` and emits the
 * index it used in the instruction's Anchor event (`NoteCreated.leaf_index` /
 * `NoteMerged.leaf_index`). Reading `leaf_count` from the SDK *before* sending
 * only predicts the index, and a concurrent append (the TEE settles constantly)
 * makes that prediction wrong — the stored note then can't build a valid
 * inclusion proof. The event is emitted by the transaction itself, so parsing it
 * from the CONFIRMED tx yields the exact index that tx used, immune to
 * concurrent appends.
 *
 * `leafIndexFromLogs` is a pure function over `meta.logMessages` so it can be
 * unit-tested with a synthetic log line (mirrors `indexer/src/watcher.ts`'s
 * `extractFills`).
 *
 * Both decoders below are scoped to the vault program via
 * `programEventPayloads` — `Program data:` is not a vault-private channel, and
 * a decoder that only prefix-matches it will read any program's events. See
 * `idl/log-scope.ts` for why that matters more in the enclave than it does
 * here, and why it is closed in both.
 */

import type {
  Connection,
  PublicKey,
  TransactionSignature,
} from "@solana/web3.js";

import { programEventPayloads } from "../idl/log-scope.js";

/** The vault program, however the caller happens to hold it. */
export type ProgramIdLike = PublicKey | string;
type TransactionReader = Pick<Connection, "getTransaction">;

const base58 = (id: ProgramIdLike): string =>
  typeof id === "string" ? id : id.toBase58();

/** Anchor event discriminator: `sha256("event:<Name>")[..8]`. */
// Anchor event discriminators are protocol constants. Keeping the precomputed
// bytes here makes the confirmed-transaction readers browser-safe; importing
// `node:crypto` from this module would otherwise pull a Node builtin into the
// production browser bundle.
const NOTE_CREATED_DISC = new Uint8Array([
  173, 155, 50, 250, 162, 108, 244, 218,
]);
const NOTE_MERGED_DISC = new Uint8Array([
  217, 47, 249, 180, 165, 103, 225, 209,
]);

// Byte offset of the `leaf_index` u64 within the event BODY (after the 8-byte
// discriminator). Must match the on-chain event field order:
//   NoteCreated: tree_id(1) ‖ leaf_index(8) ‖ commitment(32) ‖ …
//   NoteMerged:  tree_id(1) ‖ output_commitment(32) ‖ token_mint(32) ‖ k(1) ‖ leaf_index(8) ‖ …
const NOTE_CREATED_LEAF_OFFSET = 1;
const NOTE_MERGED_LEAF_OFFSET = 1 + 32 + 32 + 1; // 66

function readU64LE(bytes: Uint8Array, offset: number): bigint {
  return new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).getBigUint64(offset, true);
}

/** A `NoteCreated` event's shard + position: which tree the deposit landed in
 *  and the leaf index within it. Both are needed to build a per-shard witness
 *  under tree-sharding. */
export interface NoteCreatedLeaf {
  treeId: number;
  leafIndex: bigint;
}

/** The complete identity-bearing portion of a `NoteMerged` event. */
export interface NoteMergedLeaf {
  treeId: number;
  outputCommitment: Uint8Array;
  tokenMint: Uint8Array;
  k: number;
  leafIndex: bigint;
}

/**
 * Pure: scan one transaction's `logMessages` for the `NoteCreated` event and
 * return its `(tree_id, leaf_index)`, or `null` if absent. The event body is
 * `tree_id(u8) ‖ leaf_index(u64) ‖ commitment(32) ‖ …` after the 8-byte disc.
 */
export function noteCreatedFromLogs(
  logs: string[],
  programId: ProgramIdLike,
): NoteCreatedLeaf | null {
  for (const bytes of programEventPayloads(logs, base58(programId))) {
    if (bytes.length < 8 + 1 + 8) continue;
    let matches = true;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== NOTE_CREATED_DISC[i]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    return {
      treeId: bytes[8],
      leafIndex: readU64LE(bytes, 8 + NOTE_CREATED_LEAF_OFFSET),
    };
  }
  return null;
}

/**
 * Pure: scan one transaction's `logMessages` for the named event and return its
 * `leaf_index`, or `null` if no matching event log is present.
 */
export function leafIndexFromLogs(
  logs: string[],
  disc: Uint8Array,
  leafOffset: number,
  programId: ProgramIdLike,
): bigint | null {
  for (const bytes of programEventPayloads(logs, base58(programId))) {
    if (bytes.length < 8 + leafOffset + 8) continue;
    let matches = true;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== disc[i]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    return readU64LE(bytes, 8 + leafOffset);
  }
  return null;
}

/**
 * Pure: decode the output identity and exact tree position from a vault-emitted
 * `NoteMerged` event. Callers must compare these fields with the locally proved
 * merge before committing their private inventory transition.
 */
export function noteMergedFromLogs(
  logs: string[],
  programId: ProgramIdLike,
): NoteMergedLeaf | null {
  for (const bytes of programEventPayloads(logs, base58(programId))) {
    if (bytes.length < 8 + NOTE_MERGED_LEAF_OFFSET + 8) continue;
    let matches = true;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== NOTE_MERGED_DISC[i]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    return {
      treeId: bytes[8],
      outputCommitment: bytes.slice(9, 41),
      tokenMint: bytes.slice(41, 73),
      k: bytes[73],
      leafIndex: readU64LE(bytes, 8 + NOTE_MERGED_LEAF_OFFSET),
    };
  }
  return null;
}

async function fetchLeafIndex(
  conn: TransactionReader,
  signature: TransactionSignature,
  disc: Uint8Array,
  leafOffset: number,
  eventName: string,
  programId: ProgramIdLike,
): Promise<bigint> {
  const tx = await conn.getTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  if (!tx) {
    throw new Error(
      `leaf-index: getTransaction returned null for ${signature} (not yet confirmed?)`,
    );
  }
  const idx = leafIndexFromLogs(
    tx.meta?.logMessages ?? [],
    disc,
    leafOffset,
    programId,
  );
  if (idx === null) {
    throw new Error(
      `leaf-index: no vault-emitted ${eventName} event found in tx ${signature}`,
    );
  }
  return idx;
}

/** Read the actual leaf index a confirmed `deposit` tx appended its note at. */
export function readNoteCreatedLeafIndex(
  conn: TransactionReader,
  signature: TransactionSignature,
  programId: ProgramIdLike,
): Promise<bigint> {
  return fetchLeafIndex(
    conn,
    signature,
    NOTE_CREATED_DISC,
    NOTE_CREATED_LEAF_OFFSET,
    "NoteCreated",
    programId,
  );
}

/** Read both the shard (`tree_id`) and the leaf index a confirmed `deposit` tx
 *  appended its note at — the pair needed to build a per-shard inclusion proof. */
export async function readNoteCreated(
  conn: TransactionReader,
  signature: TransactionSignature,
  programId: ProgramIdLike,
): Promise<NoteCreatedLeaf> {
  const tx = await conn.getTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  if (!tx) {
    throw new Error(
      `leaf-index: getTransaction returned null for ${signature} (not yet confirmed?)`,
    );
  }
  const found = noteCreatedFromLogs(tx.meta?.logMessages ?? [], programId);
  if (found === null) {
    throw new Error(
      `leaf-index: no vault-emitted NoteCreated event found in tx ${signature}`,
    );
  }
  return found;
}

/** Read the actual leaf index a confirmed `merge` tx appended its output note at. */
export function readNoteMergedLeafIndex(
  conn: TransactionReader,
  signature: TransactionSignature,
  programId: ProgramIdLike,
): Promise<bigint> {
  return fetchLeafIndex(
    conn,
    signature,
    NOTE_MERGED_DISC,
    NOTE_MERGED_LEAF_OFFSET,
    "NoteMerged",
    programId,
  );
}

/** Read and authenticate the merged output identity from its confirmed tx. */
export async function readNoteMerged(
  conn: TransactionReader,
  signature: TransactionSignature,
  programId: ProgramIdLike,
): Promise<NoteMergedLeaf> {
  const tx = await conn.getTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  if (!tx) {
    throw new Error(
      `leaf-index: getTransaction returned null for ${signature} (not yet confirmed?)`,
    );
  }
  const found = noteMergedFromLogs(tx.meta?.logMessages ?? [], programId);
  if (found === null) {
    throw new Error(
      `leaf-index: no vault-emitted NoteMerged event found in tx ${signature}`,
    );
  }
  return found;
}
