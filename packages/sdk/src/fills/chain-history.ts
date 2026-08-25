/**
 * Direct-chain fills rediscovery — the indexer-FREE backfill path.
 *
 * `backfillHistory` (`./history.ts`) locates an account's fills by
 * querying the off-TEE `packages/indexer` by HD-derived order id. That indexer
 * is OPTIONAL infrastructure (see `packages/indexer/README.md`): post
 * amount-privacy + on-chain output recovery the durable
 * source of truth is the CHAIN, and a client can rediscover its own fills
 * without any indexer at all — by scanning the vault program's settle txs and
 * decoding the same `MatchResultPayload` the indexer decodes.
 *
 * This module is that scan. It returns the SAME `BackfillResult` shape as
 * `backfillHistory`, so it's a drop-in alternative (`startFillsSync` picks one).
 *
 * COST TRADEOFF: this walks `getSignaturesForAddress` + batched
 * `getTransactions` over the
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
import { sha256 } from "@noble/hashes/sha2";
import { anchorDiscriminator } from "../idl/vault-client.js";
import { programEventPayloads } from "../idl/log-scope.js";
import { deriveOrderId } from "../keys/key-generators.js";
import type { IndexerFill, BackfillResult } from "./history.js";
import { slotToNumber } from "../types/slot.js";

/** `sha256("global:tee_forced_settle_batched")[..8]`. */
const SETTLE_DISCRIMINATOR = anchorDiscriminator("tee_forced_settle_batched");
const TRADE_SETTLED_DISCRIMINATOR = new Uint8Array(
  sha256(new TextEncoder().encode("event:TradeSettled")).slice(0, 8),
);

/** Borsh `MatchResultPayload` length (v11, 552 B). Mirrors decode.ts::PAYLOAD_LEN. */
const PAYLOAD_LEN = 552;
/** ix data = disc(8) ‖ tree_id(u8) ‖ payload(552) ‖ match_index(1) ‖ siblings(128).
 *  The payload starts AFTER the discriminator AND the leading `tree_id` byte. */
const PAYLOAD_OFFSET = 8 + 1;
/** `fill_recovery` v3 starts at 424 within the v11 payload (the two appended
 *  relock tags pushed it 64 bytes later):
 *  eph(32) ‖ buyer_enc(44) ‖ seller_enc(44) ‖ "DNYXREC3". */
const FILL_RECOVERY_OFFSET = 424;
const RECOVERY_V3_TRAILER = new TextEncoder().encode("DNYXREC3");

const ZERO32 = "0".repeat(64);
const hex = (b: Uint8Array) =>
  Array.from(b, (byte) => byte.toString(16).padStart(2, "0")).join("");
const isZero = (b: Uint8Array) => b.every((x) => x === 0);
const hexOrNull = (b: Uint8Array) => (isZero(b) ? null : hex(b));
const same = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((value, index) => value === b[index]);
const NO_LEAF = 0xffff_ffff_ffff_ffffn;

export interface TradeSettledLeaves {
  matchId: string;
  tradeBuyer: bigint;
  tradeSeller: bigint;
  changeBuyer: bigint | null;
  changeSeller: bigint | null;
}

export interface SettlementFeeCommitments {
  base: Uint8Array;
  quote: Uint8Array;
}

/** Decode the two observer-visible protocol fee commitments from Tx D. */
export function decodeSettleFeeCommitments(
  ixData: Uint8Array,
): SettlementFeeCommitments | null {
  if (ixData.length < PAYLOAD_OFFSET + PAYLOAD_LEN) return null;
  if (!same(ixData.subarray(0, 8), SETTLE_DISCRIMINATOR)) return null;
  const payload = ixData.subarray(PAYLOAD_OFFSET, PAYLOAD_OFFSET + PAYLOAD_LEN);
  return {
    base: Uint8Array.from(payload.subarray(240, 272)),
    quote: Uint8Array.from(payload.subarray(272, 304)),
  };
}

/**
 * Decode every vault-emitted Anchor `TradeSettled` event in a transaction's
 * logs.
 *
 * Scoped to `programId`: `Program data:` is `sol_log_data`, callable by any
 * program, so an unscoped scan reads whatever else the transaction invoked.
 * This function feeds `cold-recovery.ts` — the path a user runs *after* losing
 * local state — off `getSignaturesForAddress(programId)`, which returns
 * transactions that merely REFERENCE the vault. `extractVaultIxDatas` below
 * already scopes the instruction half by program id; this is the log half.
 */
export function decodeTradeSettledLeaves(
  logs: readonly string[],
  programId: PublicKey | string,
): Map<string, TradeSettledLeaves> {
  const out = new Map<string, TradeSettledLeaves>();
  const vault =
    typeof programId === "string" ? programId : programId.toBase58();
  for (const bytes of programEventPayloads(logs, vault)) {
    if (bytes.length < 8 + 1 + 16 + 6 * 8) continue;
    if (!same(bytes.subarray(0, 8), TRADE_SETTLED_DISCRIMINATOR)) {
      continue;
    }
    const matchId = hex(bytes.subarray(9, 25));
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const leaf = (offset: number): bigint => view.getBigUint64(offset, true);
    const change = (value: bigint): bigint | null =>
      value === NO_LEAF ? null : value;
    out.set(matchId, {
      matchId,
      tradeBuyer: leaf(25),
      tradeSeller: leaf(33),
      changeBuyer: change(leaf(41)),
      changeSeller: change(leaf(49)),
    });
  }
  return out;
}

/**
 * Decode one vault instruction's raw data into its two fill rows (buyer + seller),
 * or `null` for any non-settle ix. Identical field selection to the indexer's
 * `decodeSettleIxData` → `payloadToFills`, but stamped with `signature`.
 */
export function decodeSettleFills(
  ixData: Uint8Array,
  signature: string,
  slot = 0,
  leaves?: TradeSettledLeaves,
): IndexerFill[] | null {
  if (ixData.length < PAYLOAD_OFFSET + PAYLOAD_LEN) return null;
  for (let i = 0; i < 8; i++) {
    if (ixData[i] !== SETTLE_DISCRIMINATOR[i]) return null;
  }
  const p = ixData.subarray(PAYLOAD_OFFSET, PAYLOAD_OFFSET + PAYLOAD_LEN);
  const v = new DataView(p.buffer, p.byteOffset, p.byteLength);

  const matchId = hex(p.subarray(0, 16));
  // Six 32-byte note fields precede the order ids. In v11 the first two are
  // input note-use TAGS, not commitments — they will not match any Merkle leaf,
  // which is the whole point. The last four remain output commitments.
  const tagA = hex(p.subarray(16, 48)); // buyer input handle (quote)
  const tagB = hex(p.subarray(48, 80)); // seller input handle (base)
  const noteC = hex(p.subarray(80, 112)); // buyer trade output (base)
  const noteD = hex(p.subarray(112, 144)); // seller trade output (quote)
  const noteE = hex(p.subarray(144, 176)); // buyer change ([0;32] = exact fill)
  const noteF = hex(p.subarray(176, 208)); // seller change
  const orderIdA = hex(p.subarray(208, 224)); // buyer
  const orderIdB = hex(p.subarray(224, 240)); // seller
  const batchSlot = v.getBigUint64(416, true).toString();

  const r = FILL_RECOVERY_OFFSET;
  const recoveryV3 = same(p.subarray(r + 120, r + 128), RECOVERY_V3_TRAILER);
  const eph = recoveryV3 ? hexOrNull(p.subarray(r, r + 32)) : null;
  const buyerEnc = recoveryV3 ? hexOrNull(p.subarray(r + 32, r + 76)) : null;
  const sellerEnc = recoveryV3 ? hexOrNull(p.subarray(r + 76, r + 120)) : null;

  const buyerExact = noteE === ZERO32;
  const sellerExact = noteF === ZERO32;
  return [
    {
      orderId: orderIdA,
      side: "buyer",
      matchId,
      signature,
      slot,
      inputNoteUseTag: tagA,
      tradeNoteCommitment: noteC,
      isPartialFill: !buyerExact,
      changeNoteCommitment: buyerExact ? null : noteE,
      batchSlot,
      ephemeralPubkey: eph,
      outputEnc: buyerEnc,
      tradeLeafIndex: leaves?.tradeBuyer.toString() ?? null,
      changeLeafIndex: leaves?.changeBuyer?.toString() ?? null,
    },
    {
      orderId: orderIdB,
      side: "seller",
      matchId,
      signature,
      slot,
      inputNoteUseTag: tagB,
      tradeNoteCommitment: noteD,
      isPartialFill: !sellerExact,
      changeNoteCommitment: sellerExact ? null : noteF,
      batchSlot,
      ephemeralPubkey: eph,
      outputEnc: sellerEnc,
      tradeLeafIndex: leaves?.tradeSeller.toString() ?? null,
      changeLeafIndex: leaves?.changeSeller?.toString() ?? null,
    },
  ];
}

/** One scanned settle tx trimmed to what the decoder needs. */
export interface RawSettleTx {
  signature: string;
  slot: number;
  /** Raw data of every vault-program top-level ix in the tx. */
  ixDatas: Uint8Array[];
  /** Anchor event logs used to recover exact output leaf positions. */
  logMessages?: string[];
}

/** Injectable settle-tx scanner (defaults to a `Connection` walk; tests mock it). */
export type ChainScan = (opts: {
  sinceSlot?: number;
}) => Promise<RawSettleTx[]>;

/** Pull the vault program's top-level ix data out of a v0 or legacy tx.
 * Program ids are always static account keys, so no ALT lookup is needed. The
 * legacy branch is required by deposit/merge cold recovery. */
function extractVaultIxDatas(
  tx: VersionedTransactionResponse,
  programId: PublicKey,
): Uint8Array[] {
  const message = tx.transaction.message;
  const keys =
    message instanceof MessageV0
      ? message.staticAccountKeys
      : message.accountKeys;
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
      const sigs = await conn.getSignaturesForAddress(
        programId,
        { before, limit: 1000 },
        "finalized",
      );
      if (sigs.length === 0) break;
      const relevant: typeof sigs = [];
      let reachedFloor = false;
      for (const s of sigs) {
        // Signatures are newest→oldest, so the first one below the floor means
        // every remaining one is too — stop the whole scan.
        if (sinceSlot !== undefined && s.slot < sinceSlot) {
          reachedFloor = true;
          break;
        }
        if (!s.err) relevant.push(s); // reverted tx — no settle applied.
      }
      // The standalone trader host accepts at most 50 allowlisted JSON-RPC
      // requests in one authenticated batch. Fetching one transaction per
      // round trip made a fresh browser vault scan thousands of historical
      // program signatures serially and guaranteed a startup timeout.
      for (let offset = 0; offset < relevant.length; offset += 50) {
        const batch = relevant.slice(offset, offset + 50);
        const transactions = await conn.getTransactions(
          batch.map((signature) => signature.signature),
          { commitment: "finalized", maxSupportedTransactionVersion: 0 },
        );
        for (let index = 0; index < batch.length; index++) {
          const tx = transactions[index];
          if (!tx) continue;
          const ixDatas = extractVaultIxDatas(tx, programId);
          if (ixDatas.length > 0) {
            out.push({
              signature: batch[index].signature,
              slot: slotToNumber(tx.slot),
              ixDatas,
              logMessages: tx.meta?.logMessages ?? [],
            });
          }
        }
      }
      if (reachedFloor) return out;
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
 * Rediscover an account's fills straight from finalized chain history — no indexer.
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
    const leavesByMatch = decodeTradeSettledLeaves(
      tx.logMessages ?? [],
      opts.programId,
    );
    for (const ixData of tx.ixDatas) {
      const rawFills = decodeSettleFills(ixData, tx.signature, tx.slot);
      const fillLeaves = rawFills?.[0]
        ? leavesByMatch.get(rawFills[0].matchId)
        : undefined;
      const fills = fillLeaves
        ? decodeSettleFills(ixData, tx.signature, tx.slot, fillLeaves)
        : rawFills;
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
        if (Number.isSafeInteger(fill.slot) && fill.slot >= 0) {
          cursorSlot = Math.max(cursorSlot, fill.slot);
        }
        located.push(fill);
      }
    }
    n += 1;
  }
  return { located, highestUsedIndex, cursorSlot };
}
