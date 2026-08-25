import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";

import {
  anchorDiscriminator,
  computeSettlementBatchLeaf,
  computeSettlementBatchRoot,
  decodeTradeSettled,
  decryptProtocolFeeRecovery,
  deriveFeeKeyBinding,
  deriveMatchFeeInner,
  MATCH_ROLE_FEE_BASE,
  MATCH_ROLE_FEE_QUOTE,
  noteCommitmentV2,
  programEventPayloads,
  type MatchResultPayload,
  U64_MAX,
} from "@darknyx/sdk";
import type {
  FeeKeyProvider,
  FeeRecoveryResult,
  FinalizedVaultTransaction,
  MarketResolver,
  RecoveredFeeNote,
  UnresolvedFeeRecord,
} from "./types.js";

const VERIFY_DISC = anchorDiscriminator("verify_match_batch");
const SETTLE_DISC = anchorDiscriminator("tee_forced_settle_batched");
const CONFIG_DISC = anchorDiscriminator("set_protocol_config");
const TRADE_SETTLED_DISC = createHash("sha256")
  .update("event:TradeSettled")
  .digest()
  .subarray(0, 8);
const VERIFY_DATA_LEN = 8 + 32 + 256 + 8 + 272;
const PAYLOAD_LEN = 552;
const SETTLE_DATA_LEN = 8 + 1 + PAYLOAD_LEN + 1 + 4 * 32;
const ZERO32 = new Uint8Array(32);

const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

function hasDisc(data: Uint8Array, disc: Uint8Array): boolean {
  return data.length >= 8 && same(data.subarray(0, 8), disc);
}

function u64le(data: Uint8Array, offset: number): bigint {
  return new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getBigUint64(offset, true);
}

function bytesToBigIntBE(value: Uint8Array): bigint {
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

function decodePayload(data: Uint8Array): MatchResultPayload {
  if (data.length !== PAYLOAD_LEN)
    throw new Error("settlement payload length mismatch");
  return {
    matchId: data.slice(0, 16),
    noteAuseTag: data.slice(16, 48),
    noteBuseTag: data.slice(48, 80),
    noteCcommitment: data.slice(80, 112),
    noteDcommitment: data.slice(112, 144),
    noteEcommitment: data.slice(144, 176),
    noteFcommitment: data.slice(176, 208),
    orderIdA: data.slice(208, 224),
    orderIdB: data.slice(224, 240),
    noteFeeBaseCommitment: data.slice(240, 272),
    noteFeeQuoteCommitment: data.slice(272, 304),
    buyerRelockOrderId: data.slice(304, 320),
    buyerRelockExpiry: u64le(data, 320),
    sellerRelockOrderId: data.slice(328, 344),
    sellerRelockExpiry: u64le(data, 344),
    noteEuseTag: data.slice(352, 384),
    noteFuseTag: data.slice(384, 416),
    batchSlot: u64le(data, 416),
    fillRecovery: data.slice(424, 552),
  };
}

interface ProtocolConfigSnapshot {
  ownerCommitment: Uint8Array;
  feeKeyBinding: Uint8Array;
  feeKeyEpoch: bigint;
}

function decodeProtocolConfig(data: Uint8Array): ProtocolConfigSnapshot | null {
  if (!hasDisc(data, CONFIG_DISC) || data.length !== 8 + 32 + 2 + 32 + 8) {
    return null;
  }
  return {
    ownerCommitment: data.slice(8, 40),
    feeKeyBinding: data.slice(42, 74),
    feeKeyEpoch: u64le(data, 74),
  };
}

interface VerifyRecord {
  order: number;
  signature: string;
  slot: number;
  root: Uint8Array;
  epoch: bigint;
  ciphertext: Uint8Array;
  marketAddress: string;
  protocol: ProtocolConfigSnapshot | null;
}

interface SettleRecord {
  order: number;
  signature: string;
  slot: number;
  root: Uint8Array;
  matchIndex: number;
  treeId: number;
  payload: MatchResultPayload;
  feeBaseLeaf: bigint;
  feeQuoteLeaf: bigint;
}

function tradeEvents(
  tx: FinalizedVaultTransaction,
  programId: string,
): Map<string, ReturnType<typeof decodeTradeSettled>> {
  const out = new Map<string, ReturnType<typeof decodeTradeSettled>>();
  for (const encoded of programEventPayloads(tx.logMessages, programId)) {
    if (
      encoded.length !== 8 + 99 ||
      !same(encoded.subarray(0, 8), TRADE_SETTLED_DISC)
    ) {
      continue;
    }
    const event = decodeTradeSettled(encoded.subarray(8));
    out.set(hex(event.matchId), event);
  }
  return out;
}

async function decodeSettle(
  tx: FinalizedVaultTransaction,
  order: number,
  data: Uint8Array,
  events: Map<string, ReturnType<typeof decodeTradeSettled>>,
): Promise<SettleRecord> {
  if (data.length !== SETTLE_DATA_LEN)
    throw new Error("settlement wire length mismatch");
  const treeId = data[8];
  const payload = decodePayload(data.subarray(9, 9 + PAYLOAD_LEN));
  const matchIndex = data[9 + PAYLOAD_LEN];
  if (payload.batchSlot !== BigInt(matchIndex)) {
    throw new Error("settlement payload slot does not match its proof index");
  }
  const siblings = Array.from({ length: 4 }, (_, index) =>
    data.slice(
      9 + PAYLOAD_LEN + 1 + index * 32,
      9 + PAYLOAD_LEN + 1 + (index + 1) * 32,
    ),
  );
  const leaf = await computeSettlementBatchLeaf(payload);
  const root = await computeSettlementBatchRoot({ leaf, matchIndex, siblings });
  const event = events.get(hex(payload.matchId));
  if (!event || event.treeId !== treeId) {
    throw new Error(
      "finalized settlement is missing its scoped TradeSettled event",
    );
  }
  return {
    order,
    signature: tx.signature,
    slot: tx.slot,
    root,
    matchIndex,
    treeId,
    payload,
    feeBaseLeaf: event.noteFeeBaseLeaf,
    feeQuoteLeaf: event.noteFeeQuoteLeaf,
  };
}

function unresolved(
  target: UnresolvedFeeRecord[],
  record: Omit<UnresolvedFeeRecord, "reason">,
  reason: UnresolvedFeeRecord["reason"],
): void {
  target.push({ ...record, reason });
}

/**
 * Recover every finalized protocol fee opening. Any cryptographic/configuration
 * gap is returned explicitly; callers must treat a nonempty `unresolved` list
 * as an operational failure rather than silently accepting a partial balance.
 */
export async function recoverProtocolFees(params: {
  transactions: readonly FinalizedVaultTransaction[];
  programId: string;
  keyForEpoch: FeeKeyProvider;
  resolveMarket: MarketResolver;
}): Promise<FeeRecoveryResult> {
  const transactions = [...params.transactions].sort((a, b) => a.slot - b.slot);
  const verifies: VerifyRecord[] = [];
  const settles: SettleRecord[] = [];
  const issues: UnresolvedFeeRecord[] = [];
  let protocol: ProtocolConfigSnapshot | null = null;

  for (const [order, tx] of transactions.entries()) {
    const events = tradeEvents(tx, params.programId);
    for (const instruction of tx.instructions) {
      if (instruction.programId !== params.programId) continue;
      const next = decodeProtocolConfig(instruction.data);
      if (next) {
        protocol = next;
        continue;
      }
      if (hasDisc(instruction.data, VERIFY_DISC)) {
        if (
          instruction.data.length !== VERIFY_DATA_LEN ||
          instruction.accounts.length < 3
        ) {
          unresolved(
            issues,
            { signature: tx.signature, slot: tx.slot },
            "invalid_recovery_ciphertext",
          );
          continue;
        }
        verifies.push({
          order,
          signature: tx.signature,
          slot: tx.slot,
          root: instruction.data.slice(8, 40),
          epoch: u64le(instruction.data, 8 + 32 + 256),
          ciphertext: instruction.data.slice(8 + 32 + 256 + 8),
          marketAddress: instruction.accounts[2],
          protocol: protocol
            ? {
                ...protocol,
                ownerCommitment: protocol.ownerCommitment.slice(),
                feeKeyBinding: protocol.feeKeyBinding.slice(),
              }
            : null,
        });
        continue;
      }
      if (hasDisc(instruction.data, SETTLE_DISC)) {
        try {
          settles.push(await decodeSettle(tx, order, instruction.data, events));
        } catch (error) {
          unresolved(
            issues,
            { signature: tx.signature, slot: tx.slot },
            (error as Error).message.includes("TradeSettled")
              ? "missing_settlement_event"
              : "invalid_settlement_binding",
          );
        }
      }
    }
  }

  const settlesByRoot = new Map<string, SettleRecord[]>();
  for (const settle of settles) {
    const rows = settlesByRoot.get(hex(settle.root));
    if (rows) rows.push(settle);
    else settlesByRoot.set(hex(settle.root), [settle]);
  }
  const verifiesByRoot = new Map<string, VerifyRecord[]>();
  for (const verify of verifies) {
    const rows = verifiesByRoot.get(hex(verify.root));
    if (rows) rows.push(verify);
    else verifiesByRoot.set(hex(verify.root), [verify]);
  }
  const nextVerifyOrder = new Map<VerifyRecord, number>();
  for (const rows of verifiesByRoot.values()) {
    rows.sort((a, b) => a.order - b.order);
    for (let index = 0; index + 1 < rows.length; index += 1) {
      nextVerifyOrder.set(rows[index], rows[index + 1].order);
    }
  }
  const settlesForVerify = new Map<VerifyRecord, SettleRecord[]>();
  const pairedSettles = new Set<SettleRecord>();
  for (const verify of verifies) {
    const nextOrder = nextVerifyOrder.get(verify);
    const assigned = (settlesByRoot.get(hex(verify.root)) ?? []).filter(
      (settle) =>
        settle.order > verify.order &&
        (nextOrder === undefined || settle.order < nextOrder),
    );
    settlesForVerify.set(verify, assigned);
    for (const settle of assigned) pairedSettles.add(settle);
  }

  const notes: RecoveredFeeNote[] = [];
  let skippedUnsettledSlots = 0;
  for (const verify of verifies) {
    const context = {
      signature: verify.signature,
      slot: verify.slot,
      epoch: verify.epoch,
      batchRoot: verify.root,
    };
    if (!verify.protocol) {
      unresolved(issues, context, "missing_protocol_config");
      continue;
    }
    if (verify.protocol.feeKeyEpoch !== verify.epoch) {
      unresolved(issues, context, "epoch_mismatch");
      continue;
    }
    const key = params.keyForEpoch(verify.epoch);
    if (!key) {
      unresolved(issues, context, "missing_epoch_key");
      continue;
    }
    const derivedBinding = await deriveFeeKeyBinding(key.key);
    if (
      key.epoch !== verify.epoch ||
      !same(key.binding, derivedBinding) ||
      !same(derivedBinding, verify.protocol.feeKeyBinding)
    ) {
      unresolved(issues, context, "fee_key_binding_mismatch");
      continue;
    }
    let market;
    try {
      market = await params.resolveMarket(verify.marketAddress);
      if (
        hex(market.address) !==
        hex(new PublicKey(verify.marketAddress).toBytes())
      ) {
        throw new Error("market resolver returned a different account");
      }
    } catch {
      unresolved(issues, context, "market_config_unavailable");
      continue;
    }
    let amounts;
    try {
      amounts = decryptProtocolFeeRecovery({
        epochKey: key.key,
        epoch: verify.epoch,
        batchRoot: verify.root,
        market: market.address,
        baseMint: market.baseMint,
        quoteMint: market.quoteMint,
        ciphertext: verify.ciphertext,
      });
    } catch {
      unresolved(issues, context, "invalid_recovery_ciphertext");
      continue;
    }
    const finalized = settlesForVerify.get(verify) ?? [];
    const settledSlots = new Set(finalized.map((item) => item.matchIndex));
    skippedUnsettledSlots += amounts.filter(
      (amount, index) =>
        (amount.base > 0n || amount.quote > 0n) && !settledSlots.has(index),
    ).length;

    for (const settle of finalized) {
      const amount = amounts[settle.matchIndex];
      const eventContext = {
        signature: settle.signature,
        slot: settle.slot,
        epoch: verify.epoch,
        batchRoot: verify.root,
        matchIndex: settle.matchIndex,
      };
      const sides = [
        {
          side: "base" as const,
          amount: amount.base,
          useTag: settle.payload.noteBuseTag,
          role: MATCH_ROLE_FEE_BASE,
          mint: market.baseMint,
          commitment: settle.payload.noteFeeBaseCommitment,
          leafIndex: settle.feeBaseLeaf,
        },
        {
          side: "quote" as const,
          amount: amount.quote,
          useTag: settle.payload.noteAuseTag,
          role: MATCH_ROLE_FEE_QUOTE,
          mint: market.quoteMint,
          commitment: settle.payload.noteFeeQuoteCommitment,
          leafIndex: settle.feeQuoteLeaf,
        },
      ];
      for (const side of sides) {
        if (side.amount === 0n) {
          if (!same(side.commitment, ZERO32) || side.leafIndex !== U64_MAX) {
            unresolved(issues, eventContext, "commitment_mismatch");
          }
          continue;
        }
        if (side.leafIndex === U64_MAX) {
          unresolved(issues, eventContext, "missing_settlement_event");
          continue;
        }
        let innerHash: Uint8Array;
        let expected: Uint8Array;
        try {
          innerHash = await deriveMatchFeeInner(
            key.key,
            side.useTag,
            side.role,
          );
          expected = await noteCommitmentV2({
            tokenMint: side.mint,
            amount: side.amount,
            ownerCommitment: bytesToBigIntBE(verify.protocol.ownerCommitment),
            innerHash: bytesToBigIntBE(innerHash),
          });
        } catch {
          unresolved(issues, eventContext, "commitment_mismatch");
          continue;
        }
        if (!same(expected, side.commitment)) {
          unresolved(issues, eventContext, "commitment_mismatch");
          continue;
        }
        notes.push({
          epoch: verify.epoch,
          batchRoot: verify.root.slice(),
          verifySignature: verify.signature,
          settleSignature: settle.signature,
          matchIndex: settle.matchIndex,
          side: side.side,
          tokenMint: side.mint.slice(),
          amount: side.amount,
          ownerCommitment: verify.protocol.ownerCommitment.slice(),
          innerHash,
          commitment: side.commitment.slice(),
          treeId: settle.treeId,
          leafIndex: side.leafIndex,
        });
      }
    }
  }

  for (const settle of settles) {
    if (!pairedSettles.has(settle)) {
      unresolved(
        issues,
        {
          signature: settle.signature,
          slot: settle.slot,
          batchRoot: settle.root,
          matchIndex: settle.matchIndex,
        },
        "missing_verify_record",
      );
    }
  }

  return { notes, unresolved: issues, skippedUnsettledSlots };
}
