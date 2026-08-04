/**
 * Seed-plus-chain disaster recovery for every user-owned note class.
 *
 * A scan supplies successful vault transactions (instruction bytes + Anchor
 * event logs). Deposits are recognized by the seed-derived owner commitment;
 * settlements decrypt recovery-v3 tuples and derive trade/change outputs from
 * the exact consumed opening; merges derive their output from recovered input
 * commitments. A fixed-point pass handles same-slot or scan-order inversions.
 */

import type { Connection } from "@solana/web3.js";
import { PublicKey } from "@solana/web3.js";
import { createHash } from "node:crypto";
import { anchorDiscriminator } from "../idl/vault-client.js";
import {
  bn254ToBE32,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
  deriveNoteSecret,
} from "../keys/key-generators.js";
import { deriveMergeOutputInnerHash } from "../utxo/merge.js";
import { deriveDepositInnerHash } from "../utxo/deposit-inner.js";
import { noteCommitmentV2, ownerCommitment } from "../utxo/note.js";
import { deriveNoteUseTag } from "../utxo/note-use.js";
import type { StoredNote } from "../utxo/note-store.js";
import {
  decodeSettleFills,
  decodeTradeSettledLeaves,
  makeConnectionScan,
  type RawSettleTx,
  type ChainScan,
} from "./chain-history.js";
import { recoverFillFromChain } from "./recover.js";

const DEPOSIT_DISC = anchorDiscriminator("deposit");
const MERGE_DISC = anchorDiscriminator("merge");
const NOTE_CREATED_DISC = eventDiscriminator("NoteCreated");
const NOTE_MERGED_DISC = eventDiscriminator("NoteMerged");
const PROGRAM_DATA_PREFIX = "Program data: ";

function eventDiscriminator(name: string): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(`event:${name}`).digest().subarray(0, 8),
  );
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const same = (a: Uint8Array, b: Uint8Array): boolean =>
  Buffer.from(a).equals(Buffer.from(b));
const isZero = (b: Uint8Array): boolean => b.every((x) => x === 0);
const ZERO32_BYTES = new Uint8Array(32);

/** Parse a 32-byte hex string, or `null` if it is not exactly that. */
function fromHex(value: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) return null;
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function be32ToBig(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

function hasDisc(bytes: Uint8Array, disc: Uint8Array): boolean {
  return bytes.length >= 8 && same(bytes.subarray(0, 8), disc);
}

function eventBodies(
  logs: readonly string[],
  discriminator: Uint8Array,
): Buffer[] {
  const out: Buffer[] = [];
  for (const line of logs) {
    if (!line.startsWith(PROGRAM_DATA_PREFIX)) continue;
    let bytes: Buffer;
    try {
      bytes = Buffer.from(line.slice(PROGRAM_DATA_PREFIX.length).trim(), "base64");
    } catch {
      continue;
    }
    if (hasDisc(bytes, discriminator)) out.push(bytes.subarray(8));
  }
  return out;
}

export interface DepositRecoveryRecord {
  treeId: number;
  leafIndex: bigint;
  commitment: Uint8Array;
  tokenMint: Uint8Array;
  amount: bigint;
  recoveryNonce: Uint8Array;
}

/** Decode seed-independent deposit data + its matching NoteCreated event. */
export function decodeDeposits(tx: RawSettleTx): DepositRecoveryRecord[] {
  const events = eventBodies(tx.logMessages ?? [], NOTE_CREATED_DISC)
    .filter((body) => body.length >= 1 + 8 + 32 + 32 + 8)
    .map((body) => ({
      treeId: body[0],
      leafIndex: body.readBigUInt64LE(1),
      commitment: Uint8Array.from(body.subarray(9, 41)),
      tokenMint: Uint8Array.from(body.subarray(41, 73)),
      amount: body.readBigUInt64LE(73),
    }));
  const out: DepositRecoveryRecord[] = [];
  for (const data of tx.ixDatas) {
    if (!hasDisc(data, DEPOSIT_DISC) || data.length < 337) continue;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const treeId = data[8];
    const amount = view.getBigUint64(9, true);
    const commitment = data.subarray(17, 49);
    const recoveryNonce = data.subarray(49, 81);
    const event = events.find(
      (candidate) =>
        candidate.treeId === treeId &&
        candidate.amount === amount &&
        same(candidate.commitment, commitment),
    );
    if (!event) continue;
    out.push({
      ...event,
      recoveryNonce: Uint8Array.from(recoveryNonce),
    });
  }
  return out;
}

export interface MergeRecoveryRecord {
  treeId: number;
  leafIndex: bigint;
  /**
   * The K input slots as they appear on the wire: note-use TAGS, zero for pad
   * slots. Recovery must invert these against notes it already holds — the
   * commitments the merge consumed are not on chain anywhere.
   */
  inputUseTags: Uint8Array[];
  outputCommitment: Uint8Array;
  tokenMint: Uint8Array;
}

/** Decode merge input handles + exact output leaf position. */
export function decodeMerges(tx: RawSettleTx): MergeRecoveryRecord[] {
  const events = eventBodies(tx.logMessages ?? [], NOTE_MERGED_DISC)
    .filter((body) => body.length >= 1 + 32 + 32 + 1 + 8)
    .map((body) => ({
      treeId: body[0],
      outputCommitment: Uint8Array.from(body.subarray(1, 33)),
      tokenMint: Uint8Array.from(body.subarray(33, 65)),
      leafIndex: body.readBigUInt64LE(66),
    }));
  const out: MergeRecoveryRecord[] = [];
  for (const data of tx.ixDatas) {
    if (!hasDisc(data, MERGE_DISC) || data.length < 13) continue;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const treeId = data[8];
    const k = view.getUint32(9, true);
    if (k !== 2 && k !== 4) continue;
    const tagsEnd = 13 + k * 32;
    if (data.length < tagsEnd + 64) continue;
    const inputUseTags = Array.from({ length: k }, (_, index) =>
      Uint8Array.from(data.subarray(13 + index * 32, 13 + (index + 1) * 32)),
    );
    const outputCommitment = Uint8Array.from(
      data.subarray(tagsEnd, tagsEnd + 32),
    );
    const tokenMint = Uint8Array.from(
      data.subarray(tagsEnd + 32, tagsEnd + 64),
    );
    const event = events.find(
      (candidate) =>
        candidate.treeId === treeId &&
        same(candidate.outputCommitment, outputCommitment) &&
        same(candidate.tokenMint, tokenMint),
    );
    if (event) out.push({ ...event, inputUseTags });
  }
  return out;
}

export interface ColdRecoveryOptions {
  connection: Connection;
  programId: PublicKey;
  masterSeed: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  /** Optional non-standard identity override. Canonical wallets derive this
   * value from the seed and need no extra recovery secret. */
  ownerCommitmentBlinding?: bigint;
  sinceSlot?: number;
  scan?: ChainScan;
}

export interface ColdRecoveryResult {
  /** Every verified opening, including already-consumed ancestors. */
  notes: StoredNote[];
  recovered: {
    deposits: number;
    trade: number;
    change: number;
    merges: number;
  };
  /** Valid chain actions whose prerequisites were not recoverable. */
  unresolvedSettlements: number;
  unresolvedMerges: number;
}

/** Recover deposit, trade, change, and merge openings from seed + chain only. */
export async function recoverNotesFromChain(
  opts: ColdRecoveryOptions,
): Promise<ColdRecoveryResult> {
  const scan = opts.scan ?? makeConnectionScan(opts.connection, opts.programId);
  const txs = (await scan({ sinceSlot: opts.sinceSlot })).sort(
    (a, b) => a.slot - b.slot,
  );
  const owner = await ownerCommitment(
    deriveSpendingKey(opts.masterSeed),
    opts.ownerCommitmentBlinding ??
      deriveOwnerCommitmentBlinding(opts.masterSeed),
  );
  const ownerBytes = bn254ToBE32(owner);
  const notes = new Map<string, StoredNote>();
  const recovered = { deposits: 0, trade: 0, change: 0, merges: 0 };

  const deposits = txs.flatMap(decodeDeposits);
  for (const deposit of deposits) {
    // Re-derive the per-note secret from seed + the PUBLIC nonce recorded in
    // the deposit instruction. This is the whole reason the secret is keyed on
    // the nonce rather than a counter: cold recovery needs no persisted state.
    const innerBytes = await deriveDepositInnerHash(
      ownerBytes,
      deposit.recoveryNonce,
      bn254ToBE32(deriveNoteSecret(opts.masterSeed, deposit.recoveryNonce)),
    );
    const innerHash = be32ToBig(innerBytes);
    const commitment = await noteCommitmentV2({
      tokenMint: deposit.tokenMint,
      amount: deposit.amount,
      ownerCommitment: owner,
      innerHash,
    });
    if (!same(commitment, deposit.commitment)) continue;
    const key = hex(commitment);
    if (!notes.has(key)) recovered.deposits += 1;
    notes.set(key, {
      commitment: key,
      tokenMint: deposit.tokenMint,
      amount: deposit.amount,
      ownerCommitment: owner,
      innerHash,
      leafIndex: deposit.leafIndex,
      treeId: deposit.treeId,
    });
  }

  const settlements = txs.flatMap((tx) => {
    const leaves = decodeTradeSettledLeaves(tx.logMessages ?? [], opts.programId);
    return tx.ixDatas.flatMap((data) => {
      const initial = decodeSettleFills(data, tx.signature, tx.slot);
      if (!initial) return [];
      const event = leaves.get(initial[0].matchId);
      return decodeSettleFills(data, tx.signature, tx.slot, event) ?? [];
    });
  });
  const merges = txs.flatMap(decodeMerges);

  /**
   * Invert the tag namespace: `tag -> the held note that produces it`.
   *
   * A merge instruction publishes only handles, so recovery cannot look a
   * consumed note up by commitment any more. It has to walk the notes it has
   * already reconstructed, derive each one's tag, and match. Rebuilt at the top
   * of every fixed-point pass because `notes` grows as settlements resolve, and
   * a merge whose input was itself a trade output is only resolvable once that
   * output exists.
   */
  const buildTagIndex = async (): Promise<Map<string, StoredNote>> => {
    const index = new Map<string, StoredNote>();
    for (const note of notes.values()) {
      const commitment = fromHex(note.commitment);
      if (!commitment) continue;
      const tag = await deriveNoteUseTag(
        commitment,
        bn254ToBE32(note.innerHash),
      );
      index.set(hex(tag), note);
    }
    return index;
  };

  // Output derivations form a commitment DAG. Iterate to a fixed point so RPC
  // scan ordering within a slot cannot strand a merge/continuation chain.
  let progressed = true;
  while (progressed) {
    progressed = false;
    const tagIndex = await buildTagIndex();
    for (const fill of settlements) {
      if (notes.has(fill.tradeNoteCommitment)) continue;
      const result = await recoverFillFromChain(fill, {
        masterSeed: opts.masterSeed,
        candidateInputs: notes.values(),
        baseMint: opts.baseMint,
        quoteMint: opts.quoteMint,
      });
      if (!result) continue;
      notes.set(result.trade.commitment, result.trade);
      recovered.trade += 1;
      if (result.change && !notes.has(result.change.commitment)) {
        notes.set(result.change.commitment, result.change);
        recovered.change += 1;
      }
      progressed = true;
    }
    for (const merge of merges) {
      const outputHex = hex(merge.outputCommitment);
      if (notes.has(outputHex)) continue;
      // `null` marks a genuine pad slot; a MISSING active slot means we do not
      // hold that note yet, which defers this merge to a later pass rather than
      // dropping it.
      const slots: (StoredNote | null)[] = [];
      let unresolved = false;
      for (const tag of merge.inputUseTags) {
        if (isZero(tag)) {
          slots.push(null);
          continue;
        }
        const note = tagIndex.get(hex(tag));
        if (!note) {
          unresolved = true;
          break;
        }
        slots.push(note);
      }
      if (unresolved) continue;
      const resolved = slots.filter((slot): slot is StoredNote => slot !== null);
      if (resolved.length === 0) continue;
      if (
        resolved.some(
          (note) =>
            note.ownerCommitment !== owner ||
            !same(note.tokenMint, merge.tokenMint),
        )
      ) {
        continue;
      }
      const amount = resolved.reduce((sum, note) => sum + note.amount, 0n);
      // The circuit derives the output inner over input COMMITMENTS (they stay
      // private witnesses there), so rebuild that vector in slot order from the
      // notes the tags resolved to — zero for the pad slots.
      const inputCommitments = slots.map((slot) =>
        slot === null ? ZERO32_BYTES : (fromHex(slot.commitment) ?? ZERO32_BYTES),
      );
      const innerHash = await deriveMergeOutputInnerHash(inputCommitments);
      const commitment = await noteCommitmentV2({
        tokenMint: merge.tokenMint,
        amount,
        ownerCommitment: owner,
        innerHash,
      });
      if (!same(commitment, merge.outputCommitment)) continue;
      notes.set(outputHex, {
        commitment: outputHex,
        tokenMint: merge.tokenMint,
        amount,
        ownerCommitment: owner,
        innerHash,
        leafIndex: merge.leafIndex,
        treeId: merge.treeId,
      });
      recovered.merges += 1;
      progressed = true;
    }
  }

  const finalTagIndex = await buildTagIndex();
  return {
    notes: [...notes.values()],
    recovered,
    // "Unresolved" means: we hold the input but failed to reconstruct the
    // output — a real gap. A settlement or merge whose input we never held is
    // someone else's and is not counted. Both now test membership through the
    // tag index rather than by commitment lookup.
    unresolvedSettlements: settlements.filter(
      (fill) =>
        finalTagIndex.has(fill.inputNoteUseTag.toLowerCase()) &&
        !notes.has(fill.tradeNoteCommitment),
    ).length,
    unresolvedMerges: merges.filter(
      (merge) =>
        merge.inputUseTags
          .filter((tag) => !isZero(tag))
          .every((tag) => finalTagIndex.has(hex(tag))) &&
        !notes.has(hex(merge.outputCommitment)),
    ).length,
  };
}
