import {
  buildSubmitOrderInstruction,
  deriveTradingKeyAtOffset,
} from "@nyx/sdk";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import { NextResponse } from "next/server";
import nacl from "tweetnacl";

import {
  getDemoConnections,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import { instructionToJson } from "@/lib/dapp/ix-json";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(h, "hex"));
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      tradingSecretKeyBase58?: string;
      slotIdx?: number;
      side?: number;
      amount?: string;
      priceLimit?: string;
      noteAmount?: string;
      expirySlot?: string;
      noteCommitmentHex?: string;
      userOwnerCommitmentHex?: string;
      orderIdHex?: string;
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.tradingSecretKeyBase58 ||
      body.slotIdx === undefined ||
      body.side === undefined ||
      !body.amount ||
      !body.priceLimit ||
      !body.noteAmount ||
      !body.noteCommitmentHex ||
      !body.userOwnerCommitmentHex ||
      !body.orderIdHex
    ) {
      return NextResponse.json(
        { ok: false, error: "missing required fields" },
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
        { ok: false, error: "trading key mismatch" },
        { status: 400 },
      );
    }

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    getDemoConnections(cfg);
    const { meProgramId, market } = parseDemoPrograms(cfg);

    const orderId = hexToBytes(body.orderIdHex);
    if (orderId.length !== 16) {
      return NextResponse.json(
        { ok: false, error: "orderIdHex must be 16 bytes (32 hex chars)" },
        { status: 400 },
      );
    }

    const expirySlot =
      body.expirySlot != null ? BigInt(body.expirySlot) : BigInt(0);
    if (expirySlot === 0n) {
      return NextResponse.json(
        { ok: false, error: "expirySlot required (use current slot + buffer)" },
        { status: 400 },
      );
    }

    const { ix, pendingOrderPda } = buildSubmitOrderInstruction({
      programId: meProgramId,
      tradingKey: trading.publicKey,
      market,
      slotIdx: body.slotIdx,
      side: body.side,
      amount: BigInt(body.amount),
      priceLimit: BigInt(body.priceLimit),
      noteAmount: BigInt(body.noteAmount),
      expirySlot,
      orderId,
      noteCommitment: hexToBytes(body.noteCommitmentHex),
      userCommitment: hexToBytes(body.userOwnerCommitmentHex),
    });

    return NextResponse.json({
      ok: true,
      instruction: instructionToJson(ix),
      pendingOrderPda: pendingOrderPda.toBase58(),
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
