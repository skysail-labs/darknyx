import {
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import {
  PublicKey,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";
import { NextResponse } from "next/server";

import {
  getDemoConnections,
  loadDemoAdminKeypair,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      baseAmount?: string;
      quoteAmount?: string;
    };
    if (!body.phantomSignatureBase58 || !body.ownerPubkeyBase58) {
      return NextResponse.json(
        { ok: false, error: "missing session fields" },
        { status: 400 },
      );
    }
    verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );

    const baseAmt = BigInt(
      body.baseAmount ?? process.env.DEMO_USER_AIRDROP_BASE ?? "1000000000",
    );
    const quoteAmt = BigInt(
      body.quoteAmount ?? process.env.DEMO_USER_AIRDROP_QUOTE ?? "1000000000",
    );

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1 } = getDemoConnections(cfg);
    const { baseMint, quoteMint } = parseDemoPrograms(cfg);
    const admin = loadDemoAdminKeypair(repoRoot);
    const owner = new PublicKey(body.ownerPubkeyBase58);

    const baseAta = await getAssociatedTokenAddress(baseMint, owner);
    const quoteAta = await getAssociatedTokenAddress(quoteMint, owner);

    const sig = await sendAndConfirmTransaction(
      l1,
      new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey,
          baseAta,
          owner,
          baseMint,
        ),
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey,
          quoteAta,
          owner,
          quoteMint,
        ),
        createMintToInstruction(
          baseMint,
          baseAta,
          admin.publicKey,
          Number(baseAmt),
        ),
        createMintToInstruction(
          quoteMint,
          quoteAta,
          admin.publicKey,
          Number(quoteAmt),
        ),
      ),
      [admin],
      { commitment: "confirmed" },
    );

    return NextResponse.json({
      ok: true,
      signature: sig,
      baseAta: baseAta.toBase58(),
      quoteAta: quoteAta.toBase58(),
      baseAmount: baseAmt.toString(),
      quoteAmount: quoteAmt.toString(),
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
