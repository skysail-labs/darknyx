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
 */

import { createHash } from "node:crypto";
import type { Connection, TransactionSignature } from "@solana/web3.js";

/** Anchor event discriminator: `sha256("event:<Name>")[..8]`. */
function eventDiscriminator(name: string): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(`event:${name}`).digest().subarray(0, 8),
  );
}

const NOTE_CREATED_DISC = eventDiscriminator("NoteCreated");
const NOTE_MERGED_DISC = eventDiscriminator("NoteMerged");

// Byte offset of the `leaf_index` u64 within the event BODY (after the 8-byte
// discriminator). Must match the on-chain event field order:
//   NoteCreated: tree_id(1) ‖ leaf_index(8) ‖ commitment(32) ‖ …
//   NoteMerged:  tree_id(1) ‖ output_commitment(32) ‖ token_mint(32) ‖ k(1) ‖ leaf_index(8) ‖ …
const NOTE_CREATED_LEAF_OFFSET = 1;
const NOTE_MERGED_LEAF_OFFSET = 1 + 32 + 32 + 1; // 66

const PROGRAM_DATA_PREFIX = "Program data: ";

/** A `NoteCreated` event's shard + position: which tree the deposit landed in
 *  and the leaf index within it. Both are needed to build a per-shard witness
 *  under tree-sharding. */
export interface NoteCreatedLeaf {
  treeId: number;
  leafIndex: bigint;
}

/**
 * Pure: scan one transaction's `logMessages` for the `NoteCreated` event and
 * return its `(tree_id, leaf_index)`, or `null` if absent. The event body is
 * `tree_id(u8) ‖ leaf_index(u64) ‖ commitment(32) ‖ …` after the 8-byte disc.
 */
export function noteCreatedFromLogs(logs: string[]): NoteCreatedLeaf | null {
  for (const line of logs) {
    if (!line.startsWith(PROGRAM_DATA_PREFIX)) continue;
    let bytes: Buffer;
    try {
      bytes = Buffer.from(
        line.slice(PROGRAM_DATA_PREFIX.length).trim(),
        "base64",
      );
    } catch {
      continue;
    }
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
      leafIndex: bytes.readBigUInt64LE(8 + NOTE_CREATED_LEAF_OFFSET),
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
): bigint | null {
  for (const line of logs) {
    if (!line.startsWith(PROGRAM_DATA_PREFIX)) continue;
    let bytes: Buffer;
    try {
      bytes = Buffer.from(
        line.slice(PROGRAM_DATA_PREFIX.length).trim(),
        "base64",
      );
    } catch {
      continue;
    }
    if (bytes.length < 8 + leafOffset + 8) continue;
    let matches = true;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== disc[i]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    return bytes.readBigUInt64LE(8 + leafOffset);
  }
  return null;
}

async function fetchLeafIndex(
  conn: Connection,
  signature: TransactionSignature,
  disc: Uint8Array,
  leafOffset: number,
  eventName: string,
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
  const idx = leafIndexFromLogs(tx.meta?.logMessages ?? [], disc, leafOffset);
  if (idx === null) {
    throw new Error(
      `leaf-index: no ${eventName} event found in tx ${signature}`,
    );
  }
  return idx;
}

/** Read the actual leaf index a confirmed `deposit` tx appended its note at. */
export function readNoteCreatedLeafIndex(
  conn: Connection,
  signature: TransactionSignature,
): Promise<bigint> {
  return fetchLeafIndex(
    conn,
    signature,
    NOTE_CREATED_DISC,
    NOTE_CREATED_LEAF_OFFSET,
    "NoteCreated",
  );
}

/** Read both the shard (`tree_id`) and the leaf index a confirmed `deposit` tx
 *  appended its note at — the pair needed to build a per-shard inclusion proof. */
export async function readNoteCreated(
  conn: Connection,
  signature: TransactionSignature,
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
  const found = noteCreatedFromLogs(tx.meta?.logMessages ?? []);
  if (found === null) {
    throw new Error(
      `leaf-index: no NoteCreated event found in tx ${signature}`,
    );
  }
  return found;
}

/** Read the actual leaf index a confirmed `merge` tx appended its output note at. */
export function readNoteMergedLeafIndex(
  conn: Connection,
  signature: TransactionSignature,
): Promise<bigint> {
  return fetchLeafIndex(
    conn,
    signature,
    NOTE_MERGED_DISC,
    NOTE_MERGED_LEAF_OFFSET,
    "NoteMerged",
  );
}
