import { randomBytes } from "node:crypto";

import {
  batchResultsPda,
  bn254ToBE32,
  buildDelegatePendingOrderInstruction,
  buildInitPendingOrderSlotInstruction,
  buildRunBatchInstruction,
  buildSubmitOrderInstruction,
  deriveTradingKeyAtOffset,
  getDepositFunction,
  pendingOrderPda,
} from "@nyx/sdk";
import {
  buildUndelegateMarketInstruction,
  waitForL1AccountChange,
} from "@nyx/sdk/dist/idl/er-client.js";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";
import bs58 from "bs58";
import { NextResponse } from "next/server";
import nacl from "tweetnacl";

import {
  getDemoConnections,
  loadDemoE2eConfig,
  loadDemoKeyring,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import { ensureMarketDelegatedOnL1 } from "@/lib/dapp/ensure-market-delegated";
import { ensureZeroProtocolFee } from "@/lib/dapp/ensure-zero-fee";
import { makePersonaDarkPoolClient } from "@/lib/dapp/persona-client";
import { topUpSol } from "@/lib/dapp/top-up-sol";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";
import { runTradeL1Settle } from "@/lib/dapp/run-trade-l1-settle";

export const runtime = "nodejs";

const DELEGATION_PROGRAM_ID = new PublicKey(
  "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh",
);

/** Mirrors on-chain `MAX_PENDING_SLOTS_PER_USER` in pending_order.rs. */
const MAX_PENDING_SLOTS_PER_USER = 4;
const PENDING_ORDER_STATUS_OFFSET = 8 + 32 + 32;
const PENDING_STATUS_EMPTY = 0;
const PENDING_STATUS_MATCHED = 2;
const PENDING_STATUS_EXPIRED = 3;
const PENDING_STATUS_CANCELLED = 4;

function isReusablePendingOrderStatus(status: number): boolean {
  return (
    status === PENDING_STATUS_EMPTY ||
    status === PENDING_STATUS_MATCHED ||
    status === PENDING_STATUS_EXPIRED ||
    status === PENDING_STATUS_CANCELLED
  );
}

interface SlotPick {
  slotIdx: number;
  /** True if account doesn't exist yet; init+delegate is required. */
  needsInit: boolean;
}

/**
 * Pick a usable maker slot under the on-chain `[0, MAX_PENDING_SLOTS_PER_USER)` cap.
 *
 * Once a slot is delegated to MagicBlock, the L1 view of its `status` is frozen at
 * the post-init snapshot — the live status (Pending after a previous
 * `submit_order`, Matched after a successful `run_batch`, …) lives on the ER.
 * Reusing a slot that looks terminal on L1 but is still `Pending` on the ER would land
 * a `MatchingError::SlotAlreadyOccupied (0x1793)` from the program's
 * `submit_order` reusability check.
 */
async function chooseFreshSlot(
  l1: import("@solana/web3.js").Connection,
  er: import("@solana/web3.js").Connection,
  meProgramId: PublicKey,
  market: PublicKey,
  tradingKey: PublicKey,
): Promise<SlotPick> {
  let firstReusable: number | null = null;
  for (let idx = 0; idx < MAX_PENDING_SLOTS_PER_USER; idx++) {
    const [pda] = pendingOrderPda(meProgramId, market, tradingKey, idx);
    const l1info = await l1.getAccountInfo(pda, "confirmed");
    if (!l1info) return { slotIdx: idx, needsInit: true };
    if (firstReusable != null) continue;
    const isDelegated = l1info.owner.equals(DELEGATION_PROGRAM_ID);
    let data: Buffer | Uint8Array | null = null;
    if (isDelegated) {
      // L1 view is stale once delegated — only the ER reflects live status.
      const erInfo = await er.getAccountInfo(pda, "confirmed");
      data = erInfo?.data ?? null;
    } else {
      data = l1info.data;
    }
    if (
      data &&
      data.length > PENDING_ORDER_STATUS_OFFSET &&
      isReusablePendingOrderStatus(data[PENDING_ORDER_STATUS_OFFSET] ?? -1)
    ) {
      firstReusable = idx;
    }
  }
  if (firstReusable != null)
    return { slotIdx: firstReusable, needsInit: false };
  throw new Error(
    `Maker has all ${MAX_PENDING_SLOTS_PER_USER} pending-order slots with live orders. ` +
      "Wait for outstanding maker orders to clear or rotate the demo maker keypair.",
  );
}

export async function POST(req: Request) {
  const signatures: {
    label: string;
    signature: string;
    cluster: "l1" | "er";
  }[] = [];
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      tradingSecretKeyBase58?: string;
      userSlotIdx?: number;
      userSide?: number;
      userAmount?: string;
      userPriceLimit?: string;
      userNoteAmount?: string;
      userNoteCommitmentHex?: string;
      userOwnerCommitmentHex?: string;
      userOrderIdHex?: string;
      userExpirySlot?: string;
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.tradingSecretKeyBase58 ||
      body.userSlotIdx === undefined ||
      body.userSide === undefined ||
      !body.userAmount ||
      !body.userPriceLimit ||
      !body.userNoteAmount ||
      !body.userNoteCommitmentHex ||
      !body.userOwnerCommitmentHex ||
      !body.userOrderIdHex ||
      body.userExpirySlot == null
    ) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "missing counter-and-match fields (need userOrderIdHex + userExpirySlot for L1 settle)",
        },
        { status: 400 },
      );
    }

    const { seed } = verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );
    const userTrading = Keypair.fromSecretKey(
      bs58.decode(body.tradingSecretKeyBase58),
    );
    const expectedSeed = deriveTradingKeyAtOffset(seed, 0n).secretKey;
    const expected = Keypair.fromSecretKey(
      nacl.sign.keyPair.fromSeed(expectedSeed).secretKey,
    );
    if (!expected.publicKey.equals(userTrading.publicKey)) {
      return NextResponse.json(
        { ok: false, error: "trading key mismatch" },
        { status: 400 },
      );
    }

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1, er, erRpcUrl } = getDemoConnections(cfg);
    const programs = parseDemoPrograms(cfg);
    const { admin, funder, tee, maker } = loadDemoKeyring(repoRoot);

    await ensureMarketDelegatedOnL1(
      l1,
      programs.meProgramId,
      programs.market,
      funder,
    );
    await topUpSol(l1, funder, maker.publicKey);
    await topUpSol(l1, funder, admin.publicKey);

    // The demo's L1 settle path emits a MatchResultPayload with no fee note,
    // and the user's quote deposit is sized to exactly the bid notional, so
    // any non-zero `vault_config.fee_rate_bps` would (a) underflow run_batch's
    // conservation check (`note.amount - notional - fee` -> ConservationViolation
    // 0x178d) and (b) be rejected by tee_forced_settle. setup-devnet defaults
    // to 30 bps for production parity; transparently reset to 0 here.
    //
    // Surface it on the receipt as a neutral "fees set to zero for this demo"
    // line — we don't want to advertise the 30 → 0 reduction, but the on-chain
    // signature is worth keeping visible so anyone auditing on the explorer
    // can confirm vault_config.fee_rate_bps actually flipped.
    const feeOutcome = await ensureZeroProtocolFee(
      l1,
      programs.vaultProgramId,
      admin,
    );
    if (feeOutcome.zeroed && feeOutcome.signature) {
      signatures.push({
        label: "protocol fees set to 0 for this demo",
        signature: feeOutcome.signature,
        cluster: "l1",
      });
    }

    const makerBaseAta = await getAssociatedTokenAddress(
      programs.baseMint,
      maker.publicKey,
    );
    const makerQuoteAta = await getAssociatedTokenAddress(
      programs.quoteMint,
      maker.publicKey,
    );

    const mintUi = Math.min(
      Number(process.env.DEMO_COUNTERPARTY_MINT_UI ?? `${200 * 1e9}`),
      Number.MAX_SAFE_INTEGER,
    );

    const mintSig = await sendAndConfirmTransaction(
      l1,
      new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey,
          makerBaseAta,
          maker.publicKey,
          programs.baseMint,
        ),
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey,
          makerQuoteAta,
          maker.publicKey,
          programs.quoteMint,
        ),
        createMintToInstruction(
          programs.baseMint,
          makerBaseAta,
          admin.publicKey,
          mintUi,
        ),
        createMintToInstruction(
          programs.quoteMint,
          makerQuoteAta,
          admin.publicKey,
          mintUi,
        ),
      ),
      [admin],
      { commitment: "confirmed" },
    );
    signatures.push({
      label: "counterparty mint",
      signature: mintSig,
      cluster: "l1",
    });

    const makerClient = makePersonaDarkPoolClient(
      l1,
      erRpcUrl,
      programs.vaultProgramId,
      programs.meProgramId,
      maker,
      "maker",
    );
    const makerDeposit = getDepositFunction({ client: makerClient });
    const depNonce = BigInt(Date.now()) + 888_888n;

    const userBidsBase = body.userSide === 0;
    const depMint = userBidsBase ? programs.baseMint : programs.quoteMint;
    const depAta = userBidsBase ? makerBaseAta : makerQuoteAta;
    // Default to 100 — matches the setup-devnet mock-oracle TWAP so the
    // clearing price falls inside the 5% circuit-breaker band.
    const quotePerBase = BigInt(
      process.env.DEMO_EXCHANGE_QUOTE_PER_BASE ?? "100",
    );
    const depAmount = userBidsBase
      ? BigInt(body.userAmount) * 3n
      : BigInt(body.userAmount) * quotePerBase * 3n;

    const makerReceipt = await makerDeposit({
      depositor: maker.publicKey,
      tokenMint: depMint.toBytes(),
      amount: depAmount,
      depositorTokenAccount: depAta,
      nonce: depNonce,
    });
    signatures.push({
      label: "counterparty deposit",
      signature: makerReceipt.signature,
      cluster: "l1",
    });

    const makerPick = await chooseFreshSlot(
      l1,
      er,
      programs.meProgramId,
      programs.market,
      maker.publicKey,
    );
    const makerSlot = makerPick.slotIdx;

    const [slotPda] = pendingOrderPda(
      programs.meProgramId,
      programs.market,
      maker.publicKey,
      makerSlot,
    );
    let info = await l1.getAccountInfo(slotPda, "confirmed");
    if (!info && makerPick.needsInit) {
      const s = await sendAndConfirmTransaction(
        l1,
        new Transaction().add(
          buildInitPendingOrderSlotInstruction({
            programId: programs.meProgramId,
            tradingKey: maker.publicKey,
            market: programs.market,
            slotIdx: makerSlot,
          }),
        ),
        [maker],
        { commitment: "confirmed" },
      );
      signatures.push({
        label: "maker init slot",
        signature: s,
        cluster: "l1",
      });
      info = await l1.getAccountInfo(slotPda, "confirmed");
    }
    if (!info) throw new Error("maker slot missing");
    if (!info.owner.equals(DELEGATION_PROGRAM_ID)) {
      const s2 = await sendAndConfirmTransaction(
        l1,
        new Transaction().add(
          buildDelegatePendingOrderInstruction({
            programId: programs.meProgramId,
            payer: funder.publicKey,
            tradingKey: maker.publicKey,
            market: programs.market,
            slotIdx: makerSlot,
          }),
        ),
        [funder, maker],
        { commitment: "confirmed" },
      );
      signatures.push({
        label: "maker delegate slot",
        signature: s2,
        cluster: "l1",
      });
    }

    const makerSide = body.userSide === 0 ? 1 : 0;
    const makerAmount = BigInt(body.userAmount);
    const makerPrice = BigInt(body.userPriceLimit);
    const now = await l1.getSlot("confirmed");
    const expiry = BigInt(now) + 500n;
    const orderId = randomBytes(16);
    if (orderId.every((b) => b === 0)) orderId[0] = 1;

    const makerOwnerCommitBytes = bn254ToBE32(
      makerReceipt.notePlaintext.ownerCommitment,
    );

    const { ix: makerIx } = buildSubmitOrderInstruction({
      programId: programs.meProgramId,
      tradingKey: maker.publicKey,
      market: programs.market,
      slotIdx: makerSlot,
      side: makerSide,
      amount: makerAmount,
      priceLimit: makerPrice,
      noteAmount: depAmount,
      expirySlot: expiry,
      orderId,
      noteCommitment: makerReceipt.noteCommitment,
      userCommitment: makerOwnerCommitBytes,
    });

    const erSig = await sendAndConfirmTransaction(
      er,
      new Transaction().add(makerIx),
      [maker],
      {
        commitment: "confirmed",
      },
    );
    signatures.push({
      label: "counterparty submit_order (PER)",
      signature: erSig,
      cluster: "er",
    });

    const [userPda] = pendingOrderPda(
      programs.meProgramId,
      programs.market,
      userTrading.publicKey,
      body.userSlotIdx,
    );
    const [makerPda] = pendingOrderPda(
      programs.meProgramId,
      programs.market,
      maker.publicKey,
      makerSlot,
    );

    const [batchPda] = batchResultsPda(programs.meProgramId, programs.market);
    const preBatch = await l1.getAccountInfo(batchPda, "confirmed");
    const preHex = preBatch ? Buffer.from(preBatch.data).toString("hex") : null;

    const runSig = await sendAndConfirmTransaction(
      er,
      new Transaction().add(
        buildRunBatchInstruction({
          programId: programs.meProgramId,
          vaultProgramId: programs.vaultProgramId,
          teeAuthority: tee.publicKey,
          market: programs.market,
          pythAccount: programs.pythAccount,
          pendingOrderPdas: [userPda, makerPda],
        }),
      ),
      [tee],
      { commitment: "confirmed" },
    );
    signatures.push({ label: "run_batch", signature: runSig, cluster: "er" });

    const undSig = await sendAndConfirmTransaction(
      er,
      new Transaction().add(
        buildUndelegateMarketInstruction({
          programId: programs.meProgramId,
          payer: funder.publicKey,
          market: programs.market,
        }),
      ),
      [funder],
      { commitment: "confirmed" },
    );
    signatures.push({
      label: "undelegate_market",
      signature: undSig,
      cluster: "er",
    });

    await waitForL1AccountChange(l1, batchPda, preHex, {
      timeoutMs: 90_000,
      intervalMs: 1000,
    });

    const userOrderBytes = Buffer.from(
      body.userOrderIdHex.replace(/^0x/, ""),
      "hex",
    );
    if (userOrderBytes.length !== 16) {
      return NextResponse.json(
        { ok: false, error: "userOrderIdHex must be 32 hex chars (16 bytes)" },
        { status: 400 },
      );
    }

    const userNoteBuyer = Buffer.from(
      body.userNoteCommitmentHex.replace(/^0x/, ""),
      "hex",
    );
    if (userNoteBuyer.length !== 32) {
      return NextResponse.json(
        { ok: false, error: "bad userNoteCommitmentHex" },
        { status: 400 },
      );
    }

    const settleOutcome = await runTradeL1Settle({
      l1,
      vaultProgramId: programs.vaultProgramId,
      baseMint: programs.baseMint,
      quoteMint: programs.quoteMint,
      meProgramId: programs.meProgramId,
      market: programs.market,
      batchPda,
      tee,
      maker,
      userMasterSeed: seed,
      userQuoteNoteCommitment: userNoteBuyer,
      userOrderId: new Uint8Array(userOrderBytes),
      userExpirySlot: BigInt(body.userExpirySlot),
      makerNoteCommitment: makerReceipt.noteCommitment,
      makerOrderId: new Uint8Array(orderId),
      makerExpirySlot: expiry,
    });
    signatures.push(...settleOutcome.lockSettleSignatures);

    return NextResponse.json({
      ok: true,
      message:
        "Counterparty matched, batch executed, market committed, L1 settle complete.",
      signatures,
      maker: {
        slotIdx: makerSlot,
        orderIdHex: Buffer.from(orderId).toString("hex"),
        noteCommitmentHex: Buffer.from(makerReceipt.noteCommitment).toString(
          "hex",
        ),
      },
      tradeWithdrawBuyerBase: settleOutcome.buyerBaseNote,
    });
  } catch (e) {
    return NextResponse.json(
      {
        ok: false,
        error: e instanceof Error ? e.message : String(e),
        signatures,
      },
      { status: 500 },
    );
  }
}
