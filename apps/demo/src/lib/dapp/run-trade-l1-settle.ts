import {
  buildLockNoteInstruction,
  buildSettleIx,
  buildEd25519VerifyIx,
  canonicalPayloadHash,
  decodeBatchResults,
  deriveSpendingKey,
  noteCommitment,
  nullifier,
  vaultConfigPda,
  RELOCK_ORDER_ID_NONE,
  ZERO_COMMITMENT,
  type MatchResultPayload,
} from "@nyx/sdk";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";
import nacl from "tweetnacl";

import { actorSeed } from "@/lib/dapp/persona-client";
import {
  be32ToBigInt,
  deriveBlinding,
  deriveNonce,
  matchIdToPayloadBytes,
  TRADE_ROLE_BUYER,
  TRADE_ROLE_SELLER,
} from "@/lib/dapp/change-note-derive";
import { collectVaultLeavesOrdered } from "@/lib/dapp/vault-leaf-history";
import { MerkleShadow } from "@/lib/dapp/merkle-shadow";

function isZero32(b: Uint8Array): boolean {
  return b.every((x) => x === 0);
}

function isRelockNone(id: Uint8Array): boolean {
  return id.length === 16 && id.every((x) => x === 0);
}

export interface TradeL1SettleContext {
  l1: Connection;
  vaultProgramId: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  meProgramId: PublicKey;
  market: PublicKey;
  batchPda: PublicKey;
  tee: Keypair;
  maker: Keypair;
  /** Phantom-derived master seed (for user spending key + nullifier). */
  userMasterSeed: Uint8Array;
  userQuoteNoteCommitment: Uint8Array;
  userOrderId: Uint8Array;
  userExpirySlot: bigint;
  makerNoteCommitment: Uint8Array;
  makerOrderId: Uint8Array;
  makerExpirySlot: bigint;
}

export interface TradeL1SettleResult {
  lockSettleSignatures: { label: string; signature: string; cluster: "l1" }[];
  buyerBaseNote: {
    matchId: string;
    leafIndex: string;
    amount: string;
    nonce: string;
    blindingR: string;
    commitmentHex: string;
    tokenMintBase58: string;
    vaultLeafCountAfter: string;
  };
}

export async function runTradeL1Settle(
  ctx: TradeL1SettleContext,
): Promise<TradeL1SettleResult> {
  const {
    l1,
    vaultProgramId,
    baseMint,
    quoteMint,
    batchPda,
    tee,
    maker,
    userMasterSeed,
  } = ctx;

  const brAcct = await l1.getAccountInfo(batchPda, "confirmed");
  if (!brAcct?.data) throw new Error("BatchResults account missing on L1");
  const brView = decodeBatchResults(brAcct.data);

  // Search the ring buffer for THIS run's match (the BatchResults ring is keyed
  // by next_match_id so prior runs may occupy lower indices). Compare against
  // the user's quote note commitment + maker's note commitment.
  const userQuoteBuf = Buffer.from(ctx.userQuoteNoteCommitment);
  const makerNoteBuf = Buffer.from(ctx.makerNoteCommitment);
  const mr = brView.results.find(
    (r) =>
      r.status === 1 &&
      Buffer.from(r.noteBuyer).equals(userQuoteBuf) &&
      Buffer.from(r.noteSeller).equals(makerNoteBuf),
  );
  if (!mr) {
    const cb = brView.lastCircuitBreakerTripped;
    const twap = brView.lastPythTwap;
    const lastP = brView.lastClearingPrice;
    const lastN = brView.lastMatchCount;
    const writeCursor = brView.writeCursor;
    const hint = cb
      ? `Circuit breaker tripped (last clearing price ${lastP} deviated > circuit_breaker_bps from oracle TWAP ${twap}). ` +
        "Set NEXT_PUBLIC_DEMO_EXCHANGE_QUOTE_PER_BASE close to the mock-oracle TWAP (default 100) so the clearing price stays within the 5% band."
      : `last_match_count=${lastN}, last_clearing_price=${lastP}, twap=${twap}, write_cursor=${writeCursor}. ` +
        "run_batch may not have crossed any orders for this market — check that maker submit_order succeeded and prices crossed.";
    throw new Error(`No FILLED MatchResult for this run. ${hint}`);
  }

  if (mr.buyerFeeAmt !== 0n || mr.sellerFeeAmt !== 0n) {
    // counter-and-match runs ensureZeroProtocolFee before submit_order, so
    // the vault should have fee_rate_bps=0 at match time. Hitting this path
    // means the auto-zero raced this match (e.g. concurrent dapp run).
    throw new Error(
      "Demo L1 settle + BASE withdraw currently requires zero protocol fees on the match " +
        `(buyer_fee=${mr.buyerFeeAmt}, seller_fee=${mr.sellerFeeAmt}). The dapp's pre-flight should have ` +
        "auto-zeroed vault.fee_rate_bps before run_batch — try the trade flow again from step 4.",
    );
  }

  const [vaultPda] = vaultConfigPda(vaultProgramId);
  const vcPre = await l1.getAccountInfo(vaultPda, "confirmed");
  if (!vcPre?.data) throw new Error("vault_config missing");
  const leafBeforeSettle = new DataView(
    vcPre.data.buffer,
    vcPre.data.byteOffset + 104,
    8,
  ).getBigUint64(0, true);

  const userSpending = deriveSpendingKey(userMasterSeed);
  const makerSeed = actorSeed("maker", maker);
  const makerSpending = deriveSpendingKey(makerSeed);

  const nullA = await nullifier(userSpending, mr.noteBuyer);
  const nullB = await nullifier(makerSpending, mr.noteSeller);

  const ucBuyer = be32ToBigInt(mr.userCommitmentBuyer);
  const ucSeller = be32ToBigInt(mr.userCommitmentSeller);

  const nonceC = deriveNonce(mr.matchId, TRADE_ROLE_BUYER);
  const blindC = deriveBlinding(mr.matchId, TRADE_ROLE_BUYER);
  const noteCcommitment = await noteCommitment({
    tokenMint: baseMint.toBytes(),
    amount: mr.baseAmt,
    ownerCommitment: ucBuyer,
    nonce: be32ToBigInt(nonceC),
    blindingR: be32ToBigInt(blindC),
  });

  const nonceD = deriveNonce(mr.matchId, TRADE_ROLE_SELLER);
  const blindD = deriveBlinding(mr.matchId, TRADE_ROLE_SELLER);
  const noteDcommitment = await noteCommitment({
    tokenMint: quoteMint.toBytes(),
    amount: mr.quoteAmt,
    ownerCommitment: ucSeller,
    nonce: be32ToBigInt(nonceD),
    blindingR: be32ToBigInt(blindD),
  });

  const noteE = isZero32(mr.noteEcommitment)
    ? ZERO_COMMITMENT
    : mr.noteEcommitment;
  const noteF = isZero32(mr.noteFcommitment)
    ? ZERO_COMMITMENT
    : mr.noteFcommitment;

  const payload: MatchResultPayload = {
    matchId: matchIdToPayloadBytes(mr.matchId),
    noteAcommitment: mr.noteBuyer,
    noteBcommitment: mr.noteSeller,
    noteCcommitment: noteCcommitment,
    noteDcommitment: noteDcommitment,
    noteEcommitment: noteE,
    noteFcommitment: noteF,
    nullifierA: nullA,
    nullifierB: nullB,
    orderIdA: ctx.userOrderId,
    orderIdB: ctx.makerOrderId,
    baseAmount: mr.baseAmt,
    quoteAmount: mr.quoteAmt,
    buyerChangeAmt: mr.buyerChangeAmt,
    sellerChangeAmt: mr.sellerChangeAmt,
    buyerFeeAmt: mr.buyerFeeAmt,
    sellerFeeAmt: mr.sellerFeeAmt,
    noteFeeCommitment: ZERO_COMMITMENT,
    buyerRelockOrderId: isRelockNone(mr.buyerRelockOrderId)
      ? RELOCK_ORDER_ID_NONE
      : mr.buyerRelockOrderId,
    buyerRelockExpiry: mr.buyerRelockExpiry,
    sellerRelockOrderId: isRelockNone(mr.sellerRelockOrderId)
      ? RELOCK_ORDER_ID_NONE
      : mr.sellerRelockOrderId,
    sellerRelockExpiry: mr.sellerRelockExpiry,
    clearingPrice: mr.price,
    batchSlot: mr.batchSlot,
  };

  const msg = canonicalPayloadHash(payload);
  const sigTee = nacl.sign.detached(msg, tee.secretKey);

  const lockTx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
    buildLockNoteInstruction({
      programId: vaultProgramId,
      teeAuthority: tee.publicKey,
      noteCommitment: mr.noteBuyer,
      orderId: ctx.userOrderId,
      expirySlot: ctx.userExpirySlot,
      amount: mr.buyerNoteValue,
    }),
    buildLockNoteInstruction({
      programId: vaultProgramId,
      teeAuthority: tee.publicKey,
      noteCommitment: mr.noteSeller,
      orderId: ctx.makerOrderId,
      expirySlot: ctx.makerExpirySlot,
      amount: mr.sellerNoteValue,
    }),
  );
  const lockSig = await sendAndConfirmTransaction(l1, lockTx, [tee], {
    commitment: "confirmed",
  });

  const settleTx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    buildEd25519VerifyIx({
      teePubkey: tee.publicKey.toBytes(),
      signature: sigTee,
      message: msg,
    }),
    buildSettleIx({
      programId: vaultProgramId,
      teeAuthority: tee.publicKey,
      payload,
    }),
  );
  const settleSig = await sendAndConfirmTransaction(l1, settleTx, [tee], {
    commitment: "confirmed",
  });

  const vcPost = await l1.getAccountInfo(vaultPda, "confirmed");
  if (!vcPost?.data) throw new Error("vault_config missing after settle");
  const leafAfter = new DataView(
    vcPost.data.buffer,
    vcPost.data.byteOffset + 104,
    8,
  ).getBigUint64(0, true);

  // Best-effort post-settle replay: walk RPC history, build a shadow tree,
  // and check the leaf at `leafBeforeSettle` matches our derived note_c. We
  // do NOT throw on mismatch here — `lock_note` + `tee_forced_settle` have
  // already landed on L1 by this point, and the canonical validation lives
  // in `trade-withdraw-prepare` (which the user hits explicitly when they
  // press the withdraw button). Throwing here would only orphan the trade
  // metadata the UI needs to drive the withdraw step.
  const cHex = Buffer.from(noteCcommitment).toString("hex");
  try {
    const leaves = await collectVaultLeavesOrdered(
      l1,
      vaultProgramId,
      Number(leafAfter),
      {
        maxSignatures: 2000,
      },
    );
    const shadow = await MerkleShadow.create();
    for (const leaf of leaves) {
      await shadow.append(leaf);
    }
    const noteCLeaf = Number(leafBeforeSettle);
    const w = await shadow.witness(noteCLeaf);
    const onChainRoot = vcPost.data.subarray(112, 144);
    if (Buffer.compare(Buffer.from(w.root), Buffer.from(onChainRoot)) !== 0) {
      console.warn(
        "[run-trade-l1-settle] shadow Merkle root != vault current_root — RPC leaf replay may be incomplete. " +
          "Trade is settled on-chain; trade-withdraw-prepare will revalidate when the user presses Withdraw.",
      );
    }
    const leafBytes = leaves[noteCLeaf];
    if (
      leafBytes &&
      Buffer.compare(Buffer.from(leafBytes), Buffer.from(noteCcommitment)) !== 0
    ) {
      console.warn(
        "[run-trade-l1-settle] replayed leaf at note_c index does not match derived note_c commitment.",
      );
    }
  } catch (e) {
    console.warn(
      "[run-trade-l1-settle] post-settle Merkle replay skipped:",
      e instanceof Error ? e.message : String(e),
    );
  }

  const out: TradeL1SettleResult = {
    lockSettleSignatures: [
      { label: "lock_note ×2 (L1)", signature: lockSig, cluster: "l1" },
      {
        label: "Ed25519 + tee_forced_settle (L1)",
        signature: settleSig,
        cluster: "l1",
      },
    ],
    buyerBaseNote: {
      matchId: mr.matchId.toString(),
      leafIndex: leafBeforeSettle.toString(),
      amount: mr.baseAmt.toString(),
      nonce: be32ToBigInt(nonceC).toString(),
      blindingR: be32ToBigInt(blindC).toString(),
      commitmentHex: cHex,
      tokenMintBase58: baseMint.toBase58(),
      vaultLeafCountAfter: leafAfter.toString(),
    },
  };
  return out;
}
