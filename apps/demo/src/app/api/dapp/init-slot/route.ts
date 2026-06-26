import {
  buildDelegatePendingOrderInstruction,
  buildInitPendingOrderSlotInstruction,
  deriveTradingKeyAtOffset,
  pendingOrderPda,
} from "@nyx/sdk";
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
import { topUpSol } from "@/lib/dapp/top-up-sol";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

const DELEGATION_PROGRAM_ID = new PublicKey(
  "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh",
);

/** Mirrors on-chain `MAX_PENDING_SLOTS_PER_USER` in pending_order.rs. */
const MAX_PENDING_SLOTS_PER_USER = 4;

/** Byte layout for PendingOrder.status (after 8B disc + 32 trading_key + 32 market). */
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
 * Pick a usable slot under the on-chain `[0, MAX_PENDING_SLOTS_PER_USER)` cap.
 * Preference order:
 *   1. first slot whose PDA doesn't exist (fresh init+delegate)
 *   2. first existing slot in any terminal reusable state
 *      (Empty / Matched / Expired / Cancelled) — re-use as-is
 *   3. otherwise: throw with a clear message (all 4 slots are still occupied)
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
    const data = isDelegated
      ? ((await er.getAccountInfo(pda, "confirmed"))?.data ?? null)
      : l1info.data;
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
    `All ${MAX_PENDING_SLOTS_PER_USER} pending-order slots for this trading key still have live Pending orders. ` +
      "Wait for an outstanding order to settle or use a fresh wallet for the demo.",
  );
}

async function ensureSlotDelegated(
  l1: import("@solana/web3.js").Connection,
  meProgramId: PublicKey,
  market: PublicKey,
  funder: Keypair,
  trading: Keypair,
  slotIdx: number,
  needsInit: boolean,
): Promise<void> {
  const [slotPda] = pendingOrderPda(
    meProgramId,
    market,
    trading.publicKey,
    slotIdx,
  );
  let info = await l1.getAccountInfo(slotPda, "confirmed");
  if (!info && needsInit) {
    await sendAndConfirmTransaction(
      l1,
      new Transaction().add(
        buildInitPendingOrderSlotInstruction({
          programId: meProgramId,
          tradingKey: trading.publicKey,
          market,
          slotIdx,
        }),
      ),
      [trading],
      { commitment: "confirmed" },
    );
    info = await l1.getAccountInfo(slotPda, "confirmed");
  }
  if (!info) throw new Error("pending order slot missing after init");
  if (info.owner.equals(DELEGATION_PROGRAM_ID)) return;
  await sendAndConfirmTransaction(
    l1,
    new Transaction().add(
      buildDelegatePendingOrderInstruction({
        programId: meProgramId,
        payer: funder.publicKey,
        tradingKey: trading.publicKey,
        market,
        slotIdx,
      }),
    ),
    [funder, trading],
    { commitment: "confirmed" },
  );
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      tradingSecretKeyBase58?: string;
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.tradingSecretKeyBase58
    ) {
      return NextResponse.json(
        { ok: false, error: "missing session fields" },
        { status: 400 },
      );
    }
    const { seed } = verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );
    const trading = Keypair.fromSecretKey(
      bs58.decode(body.tradingSecretKeyBase58),
    );
    const expectedSeed = deriveTradingKeyAtOffset(seed, 0n).secretKey;
    const expected = Keypair.fromSecretKey(
      nacl.sign.keyPair.fromSeed(expectedSeed).secretKey,
    );
    if (!expected.publicKey.equals(trading.publicKey)) {
      return NextResponse.json(
        {
          ok: false,
          error: "trading key does not match Phantom-derived session",
        },
        { status: 400 },
      );
    }

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1, er } = getDemoConnections(cfg);
    const { meProgramId, market } = parseDemoPrograms(cfg);
    const { funder } = loadDemoKeyring(repoRoot);

    await ensureMarketDelegatedOnL1(l1, meProgramId, market, funder);

    const pick = await chooseFreshSlot(
      l1,
      er,
      meProgramId,
      market,
      trading.publicKey,
    );
    await topUpSol(l1, funder, trading.publicKey);
    await ensureSlotDelegated(
      l1,
      meProgramId,
      market,
      funder,
      trading,
      pick.slotIdx,
      pick.needsInit,
    );

    return NextResponse.json({
      ok: true,
      slotIdx: pick.slotIdx,
      reusedExisting: !pick.needsInit,
      tradingPubkey: trading.publicKey.toBase58(),
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
