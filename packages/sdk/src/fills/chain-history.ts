/**
 * Direct-chain fills rediscovery — the indexer-FREE backfill path.
 *
 * `backfillHistory` (`./history.ts`) locates an account's change-note fills by
 * querying the off-TEE `packages/indexer` by HD-derived order id. That indexer
 * is OPTIONAL infrastructure (see `packages/indexer/README.md`): post
 * amount-privacy + on-chain change-amount recovery (Proposal B) the durable
 * source of truth is the CHAIN, and a client can rediscover its own fills
 * without any indexer at all — by scanning the vault program's settle txs and
 * decoding the same `MatchResultPayload` the indexer decodes.
 *
 * This module is that scan. It returns the SAME `BackfillResult` shape as
 * `backfillHistory`, so it's a drop-in alternative (`startFillsSync` picks one).
 *
 * COST TRADEOFF: this walks `getSignaturesForAddress` + `getTransaction` over the
 * program's history (O(all settles)), whereas the indexer serves a pre-built
 * by-order_id index (O(my order ids)). Fine for a light/stateless client over
 * shallow history; at deep mainnet volume, stand up the indexer instead. Bound
 * the scan with `sinceSlot` whenever you have a cursor.
 *
 * BYTE-LAYOUT CONTRACT: the payload offsets below mirror
 * `settlement/settle-builder.ts::serializePayload` (the encoder) AND
 * `packages/indexer/src/decode.ts` (the indexer's decoder). `chain-history.test.ts`
 * round-trips against the encoder so the three can't drift.
 */

import {
  Connection,
  PublicKey,
  MessageV0,
  type VersionedTransactionResponse,
} from "@solana/web3.js";
import { anchorDiscriminator } from "../idl/vault-client.js";
import { deriveOrderId } from "../keys/key-generators.js";
import type { IndexerFill, BackfillResult } from "./history.js";

/** `sha256("global:tee_forced_settle_batched")[..8]`. */
const SETTLE_DISCRIMINATOR = anchorDiscriminator("tee_forced_settle_batched");

/** Borsh `MatchResultPayload` length (v9, 488 B). Mirrors decode.ts::PAYLOAD_LEN. */
const PAYLOAD_LEN = 488;
/** ix data = disc(8) ‖ tree_id(u8) ‖ payload(488) ‖ match_index(1) ‖ siblings(128).
 *  The payload starts AFTER the discriminator AND the leading `tree_id` byte. */
const PAYLOAD_OFFSET = 8 + 1;
/** `fill_recovery` bundle starts at 360 within the payload:
 *  eph(32) ‖ buyer_enc(36) ‖ seller_enc(36) ‖ pad(24). */
const FILL_RECOVERY_OFFSET = 360;

const ZERO32 = "0".repeat(64);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const isZero = (b: Uint8Array) => b.every((x) => x === 0);
const hexOrNull = (b: Uint8Array) => (isZero(b) ? null : hex(b));

/**
 * Decode one vault instruction's raw data into its two fill rows (buyer + seller),
 * or `null` for any non-settle ix. Identical field selection to the indexer's
 * `decodeSettleIxData` → `payloadToFills`, but stamped with `signature`.
 */
export function decodeSettleFills(
  ixData: Uint8Array,
  signature: string,
): IndexerFill[] | null {
  if (ixData.length < PAYLOAD_OFFSET + PAYLOAD_LEN) return null;
  for (let i = 0; i < 8; i++) {
    if (ixData[i] !== SETTLE_DISCRIMINATOR[i]) return null;
  }
  const p = ixData.subarray(PAYLOAD_OFFSET, PAYLOAD_OFFSET + PAYLOAD_LEN);
  const v = new DataView(p.buffer, p.byteOffset, p.byteLength);

  const matchId = hex(p.subarray(0, 16));
  // Six 32-byte note commitments precede the order ids in payload v9.
  const noteE = hex(p.subarray(144, 176)); // buyer change ([0;32] = exact fill)
  const noteF = hex(p.subarray(176, 208)); // seller change
  const orderIdA = hex(p.subarray(208, 224)); // buyer
  const orderIdB = hex(p.subarray(224, 240)); // seller
  const batchSlot = v.getBigUint64(352, true).toString();

  const r = FILL_RECOVERY_OFFSET;
  const eph = hexOrNull(p.subarray(r, r + 32));
  const buyerEnc = hexOrNull(p.subarray(r + 32, r + 68));
  const sellerEnc = hexOrNull(p.subarray(r + 68, r + 104));

  const buyerExact = noteE === ZERO32;
  const sellerExact = noteF === ZERO32;
  return [
    {
      orderId: orderIdA,
      side: "buyer",
      matchId,
      signature,
      isPartialFill: !buyerExact,
      changeNoteCommitment: buyerExact ? null : noteE,
      batchSlot,
      ephemeralPubkey: eph,
      changeEnc: buyerEnc,
    },
    {
      orderId: orderIdB,
      side: "seller",
      matchId,
      signature,
      isPartialFill: !sellerExact,
      changeNoteCommitment: sellerExact ? null : noteF,
      batchSlot,
      ephemeralPubkey: eph,
      changeEnc: sellerEnc,
    },
  ];
}

/** One scanned settle tx trimmed to what the decoder needs. */
export interface RawSettleTx {
  signature: string;
  slot: number;
  /** Raw data of every vault-program top-level ix in the tx. */
  ixDatas: Uint8Array[];
}

/** Injectable settle-tx scanner (defaults to a `Connection` walk; tests mock it). */
export type ChainScan = (opts: {
  sinceSlot?: number;
}) => Promise<RawSettleTx[]>;

/** Pull the vault program's top-level ix data out of a v0 tx.
 *  Settle txs are always v0 (they load ALTs — CLAUDE.md §6); legacy messages
 *  carry no settle ix here, so they're skipped. Program ids are ALWAYS static
 *  account keys (a program id can never come from an ALT), so no table lookup. */
function extractVaultIxDatas(
  tx: VersionedTransactionResponse,
  programId: PublicKey,
): Uint8Array[] {
  const message = tx.transaction.message;
  if (!(message instanceof MessageV0)) return [];
  const keys = message.staticAccountKeys;
  const out: Uint8Array[] = [];
  for (const ci of message.compiledInstructions) {
    const pid = keys[ci.programIdIndex];
    if (pid && pid.equals(programId)) out.push(Uint8Array.from(ci.data));
  }
  return out;
}

/** Build the default `Connection`-backed scanner for `programId`. */
export function makeConnectionScan(
  conn: Connection,
  programId: PublicKey,
): ChainScan {
  return async ({ sinceSlot }) => {
    const out: RawSettleTx[] = [];
    let before: string | undefined;
    for (;;) {
      // Newest-first, up to 1000 signatures per page.
      const sigs = await conn.getSignaturesForAddress(programId, {
        before,
        limit: 1000,
      });
      if (sigs.length === 0) break;
      for (const s of sigs) {
        if (s.err) continue; // reverted tx — no settle applied.
        // Signatures are newest→oldest, so the first one below the floor means
        // every remaining one is too — stop the whole scan.
        if (sinceSlot !== undefined && s.slot < sinceSlot) return out;
        const tx = await conn.getTransaction(s.signature, {
          commitment: "confirmed",
          maxSupportedTransactionVersion: 0,
        });
        if (!tx) continue;
        const ixDatas = extractVaultIxDatas(tx, programId);
        if (ixDatas.length > 0) {
          out.push({ signature: s.signature, slot: tx.slot, ixDatas });
        }
      }
      before = sigs[sigs.length - 1].signature;
      if (sigs.length < 1000) break; // last page.
    }
    return out;
  };
}

export interface ChainBackfillOptions {
  connection: Connection;
  programId: PublicKey;
  masterSeed: Uint8Array;
  /** Stop gap-scanning after this many consecutive empty order ids. Default 5. */
  gapLimit?: number;
  /** Only consider settles at/after this slot (incremental backfill). */
  sinceSlot?: number;
  /** Override the scanner (tests inject synthetic settle txs). */
  scan?: ChainScan;
}

/**
 * Rediscover an account's change-note fills straight from the chain — no indexer.
 * Scans the vault program's settle history, decodes each `MatchResultPayload`,
 * then HD-gap-scans `deriveOrderId(seed, 0..)` against the decoded set (same
 * gap-limit stop as `backfillHistory`). Returns the identical `BackfillResult`,
 * so callers treat it as a drop-in for the indexer path.
 */
export async function backfillHistoryFromChain(
  opts: ChainBackfillOptions,
): Promise<BackfillResult> {
  const scan = opts.scan ?? makeConnectionScan(opts.connection, opts.programId);
  const txs = await scan({ sinceSlot: opts.sinceSlot });

  // Index the decoded fills by order id (one client-side pass over history).
  const byOrder = new Map<string, IndexerFill[]>();
  for (const tx of txs) {
    for (const ixData of tx.ixDatas) {
      const fills = decodeSettleFills(ixData, tx.signature);
      if (!fills) continue;
      for (const f of fills) {
        const arr = byOrder.get(f.orderId);
        if (arr) arr.push(f);
        else byOrder.set(f.orderId, [f]);
      }
    }
  }

  // HD gap-scan — identical semantics to backfillHistory (just a map, not HTTP).
  const gapLimit = opts.gapLimit ?? 5;
  const located: IndexerFill[] = [];
  let consecutiveEmpty = 0;
  let n = 0;
  let highestUsedIndex = -1;
  let cursorSlot = opts.sinceSlot ?? 0;

  while (consecutiveEmpty < gapLimit) {
    const orderId = hex(deriveOrderId(opts.masterSeed, n));
    const fills = byOrder.get(orderId) ?? [];
    if (fills.length === 0) {
      consecutiveEmpty += 1;
    } else {
      consecutiveEmpty = 0;
      highestUsedIndex = n;
      for (const fill of fills) {
        // Guard a malformed batchSlot from poisoning the cursor (NaN via Math.max).
        const slot = Number(fill.batchSlot);
        if (Number.isFinite(slot)) cursorSlot = Math.max(cursorSlot, slot);
        if (fill.changeNoteCommitment) located.push(fill);
      }
    }
    n += 1;
  }
  return { located, highestUsedIndex, cursorSlot };
}
